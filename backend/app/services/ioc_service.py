"""Coordinate OTX collection and durable storage, one provider job at a time.

Worker -> run_one_due_job -> PostgreSQL job -> collector -> repository.
API GET -> stored evidence only. API POST -> queue only; never hold an HTTP
request open while downloading OTX. Redis is intentionally unnecessary here:
PostgreSQL owns evidence, jobs, cooldowns, and the cross-process advisory lock.

The session lock is held on a dedicated borrowed connection while collecting.
No database transaction is kept open during provider HTTP requests. Other
requests continue using the remaining connections in the existing shared pool.


FILE GUIDE
----------
WHAT THIS FILE DOES
Coordinate one due OTX job and expose safe operations to the API.

WHY IT EXISTS
Collection, provider cooldown, transaction outcomes, and queue requests need one policy owner.

WHO CALLS OR IMPORTS IT
ioc_worker calls run_one_due_job; app.api.ioc calls the read/queue functions.

WHAT IT CALLS OR IMPORTS
Calls ioc_repository for durable state and app.collectors.otx for network collection.

ROLE IN THE ARCHITECTURE
Application orchestration layer between routes, worker, collector, and storage.
"""
import asyncio
import hashlib
from datetime import datetime, timedelta, timezone

from app.config import (
    OTX_API_KEY, OTX_ENABLED, OTX_REFRESH_HOURS, OTX_RETRY_SECONDS,
    OTX_JOB_DELAY_SECONDS, OTX_MANUAL_COOLDOWN_SECONDS,
)
from app.collectors.otx import (
    normalize_cve_id, fetch_otx_cve_iocs, OTXAuthenticationError,
    OTXConfigurationError, OTXRetryLaterError, OTXNotFoundError,
    OTXResponseError, OTXProviderUnavailableError,
)
from app.models.ioc_api import IOCProviderStatus, IOCQueueResult
from app.storage import ioc_repository as repository
from app.storage.postgres import db_connection

OTX_LOCK_ID = 73419022


class IOCDisabledError(RuntimeError):
    """A queue request requires this optional feature and its key to be enabled."""


async def run_one_due_job() -> str:
    """Run at most one due CVE, returning an operational outcome for the worker.

    Every API process may start a worker, but only the advisory-lock owner can
    collect. Persisted next_allowed_at governs all processes using this DB.
    A new API key clears an authentication cooldown, not a provider rate limit.
    Cancelled/crashed attempts are recovered after the next lock acquisition.
    

    Function detail: Called by ioc_worker on each tick. It seeds KEVs, claims a provider-
      wide advisory lock, honors durable cooldowns, stores one result or failure, and
      releases the lock. The provider call happens outside a database transaction.
    """
    async with db_connection() as connection:
        locked = await connection.fetchval("SELECT pg_try_advisory_lock($1)", OTX_LOCK_ID)
        if not locked:
            return "another_worker"
        try:
            await repository.seed_jobs(connection)
            await repository.recover_interrupted_jobs(connection)
            await connection.execute("UPDATE otx_provider_state SET heartbeat_at=NOW() WHERE id=1")
            if not OTX_ENABLED or not OTX_API_KEY:
                return "disabled_or_missing_key"

            fingerprint = hashlib.sha256(OTX_API_KEY.encode("utf-8")).hexdigest()
            await connection.execute("""
                UPDATE otx_provider_state SET
                    next_allowed_at=CASE WHEN blocked_kind='authentication' AND
                        key_fingerprint IS DISTINCT FROM $1 THEN NOW() ELSE next_allowed_at END,
                    key_fingerprint=$1 WHERE id=1
            """, fingerprint)
            allowed = await connection.fetchval(
                "SELECT next_allowed_at<=NOW() FROM otx_provider_state WHERE id=1"
            )
            if not allowed:
                return "provider_cooldown"
            job = await repository.start_next_job(connection)
            if job is None:
                return "idle"
            cve_id, run_id = job
            error_message = None
            blocked_kind = None
            deferred = False
            retry_at = datetime.now(timezone.utc) + timedelta(seconds=OTX_RETRY_SECONDS)
            provider_retry_at = datetime.now(timezone.utc) + timedelta(seconds=OTX_JOB_DELAY_SECONDS)
            try:
                result = await fetch_otx_cve_iocs(cve_id, include_context=False)
                await repository.save_result(
                    connection, run_id, result, OTX_REFRESH_HOURS * 3600, OTX_RETRY_SECONDS
                )
                outcome = "complete" if result.complete else "partial"
                # Space jobs from completion, not from their start time.
                provider_retry_at = datetime.now(timezone.utc) + timedelta(seconds=OTX_JOB_DELAY_SECONDS)
            except OTXRetryLaterError as exc:
                error_message = "OTX requested a cooldown; this lookup will be retried."
                deferred, blocked_kind = True, "cooldown"
                retry_at = provider_retry_at = max(
                    exc.retry_at, datetime.now(timezone.utc) + timedelta(seconds=OTX_JOB_DELAY_SECONDS)
                )
                outcome = "deferred"
            except OTXAuthenticationError:
                error_message = "OTX rejected authentication. Update the API key and restart the backend."
                blocked_kind = "authentication"
                retry_at = provider_retry_at = datetime.now(timezone.utc) + timedelta(seconds=OTX_RETRY_SECONDS)
                outcome = "failed"
            except OTXConfigurationError:
                error_message = "OTX configuration is invalid. Check the server URL and API key."
                blocked_kind = "configuration"
                retry_at = provider_retry_at = datetime.now(timezone.utc) + timedelta(seconds=OTX_RETRY_SECONDS)
                outcome = "failed"
            except (OTXNotFoundError, OTXResponseError, OTXProviderUnavailableError) as exc:
                error_message = str(exc)[:1000]
                retry_at = datetime.now(timezone.utc) + timedelta(seconds=OTX_RETRY_SECONDS)
                outcome = "failed"
            except asyncio.CancelledError:
                # Keep the running row for recovery; never record an empty success.
                raise
            except Exception:
                error_message = "Collection or database write failed; previous evidence was preserved."
                retry_at = datetime.now(timezone.utc) + timedelta(seconds=OTX_RETRY_SECONDS)
                outcome = "failed"

            if blocked_kind is None:
                # Failed ordinary requests can run for minutes too. Always
                # pace from completion, not the timestamp before collection.
                provider_retry_at = datetime.now(timezone.utc) + timedelta(seconds=OTX_JOB_DELAY_SECONDS)
            # A rate-limited attempt and its provider-wide cooldown commit
            # together. Restarting between these writes cannot lose the pause.
            async with connection.transaction():
                if error_message is not None:
                    await repository.record_failure(connection, cve_id, run_id, error_message, retry_at, deferred)
                await connection.execute("""
                    UPDATE otx_provider_state SET next_allowed_at=$1,last_error=$2,
                        blocked_kind=$3,heartbeat_at=NOW() WHERE id=1
                """, provider_retry_at, error_message, blocked_kind)
            return outcome
        finally:
            # Explicit release while the same session still owns the lock.
            # If the connection dies, PostgreSQL releases its session lock.
            if not connection.is_closed():
                await connection.execute("SELECT pg_advisory_unlock($1)", OTX_LOCK_ID)


async def get_ioc_status() -> IOCProviderStatus:
    """Expose coverage and health without provider credentials or internal hashes.

    Function detail: Called by the API status route. It combines configured flags with
      repository counts without returning the secret key.
    """
    counts = await repository.get_status_counts()
    return IOCProviderStatus(enabled=OTX_ENABLED, configured=bool(OTX_API_KEY), **counts)


async def get_stored_iocs(cve_id: str, limit: int, offset: int, include_history: bool):
    """Validate the CVE and read PostgreSQL; this path never invokes the collector.

    Function detail: Called by the API detail route. It validates the CVE and delegates to
      PostgreSQL; a page view never makes an OTX request.
    """
    return await repository.get_page(normalize_cve_id(cve_id), limit, offset, include_history)


async def get_ioc_runs(cve_id: str, limit: int):
    """Read recent attempt outcomes so failures cannot look like empty intelligence.

    Function detail: Called by the API run-history route. It validates the CVE before
      returning recent persisted attempt outcomes.
    """
    return await repository.get_runs(normalize_cve_id(cve_id), limit)


async def request_ioc_refresh(cve_id: str) -> IOCQueueResult:
    """Queue a manual refresh and return immediately; repeated clicks coalesce.

    Function detail: Called by the API POST route. It requires the enabled feature and key,
      then lets the repository coalesce/throttle a manual request.
    """
    if not OTX_ENABLED or not OTX_API_KEY:
        raise IOCDisabledError("Enable OTX and configure its API key before queuing refreshes.")
    normalized = normalize_cve_id(cve_id)
    queued, state = await repository.queue_refresh(normalized, OTX_MANUAL_COOLDOWN_SECONDS)
    return IOCQueueResult(cve_id=normalized,queued=queued,state=state,message=(
        "Refresh queued. The worker will honor provider cooldowns."
        if queued else "Already running or recently requested; the existing schedule is retained."
    ))
