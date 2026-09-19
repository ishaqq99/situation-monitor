"""Orchestrate KEV-centered NVD enrichment.

FILE ROLE
---------
This is the business-process layer for NVD. It decides *which* KEVs need NVD
work and coordinates the collector, repository, Redis lock/status, and request
pacing. It deliberately does not contain raw HTTP parsing or SQL.

ARCHITECTURE POSITION
---------------------
Scheduled worker / FastAPI manual refresh
                |
                v
          this service
      /        |        \
Redis lock   NVD collector   PostgreSQL repository

READ PATH
---------
React -> FastAPI -> get_stored_nvd_cve()/get_stored_nvd_history()
                  -> PostgreSQL only

REFRESH PATH
------------
1. Acquire Redis lock.
2. Enforce short cooldown.
3. Confirm KEV catalog exists.
4. Select a bounded batch of missing/stale KEVs from PostgreSQL.
5. Request each CVE from NVD sequentially with deliberate pacing.
6. Store current state; repository records CVSS history when it changed.
7. Publish batch summary in Redis.

WHY BATCHES
-----------
The first NVD backfill may contain well over a thousand KEVs. Processing every
CVE inside one HTTP request would make manual refreshes take too long and would
make cancellation/recovery difficult. A bounded batch lets the worker resume
incrementally and keeps API calls predictable.
"""

import asyncio
import logging
from datetime import datetime, timedelta, timezone

import httpx

from app.collectors.nvd import NVDResponseError, fetch_nvd_cve, normalize_cve_id
from app.config import (
    NVD_BATCH_SIZE,
    NVD_REQUEST_DELAY_SECONDS,
    NVD_RETRY_INTERVAL_SECONDS,
    NVD_STALE_AFTER_HOURS,
)
from app.models.nvd import NVDCVE, NVDCVSSChange, NVDFeedStatus, NVDRefreshResult
from app.storage import nvd_cache as cache
from app.storage.nvd_repository import (
    count_kev_entries,
    count_nvd_cves,
    count_nvd_refresh_candidates,
    get_kev_cve_ids_needing_nvd,
    get_nvd_cve_by_cve,
    get_nvd_cvss_history,
    upsert_nvd_cve,
)


logger = logging.getLogger(__name__)
NVD_REFRESH_TIMEOUT_SECONDS = 300


class NVDRefreshInProgressError(Exception):
    """Another API process or worker already owns the NVD refresh lease."""


class NVDCatalogNotReadyError(Exception):
    """KEV must populate PostgreSQL before NVD can enrich it."""


class NVDRefreshCooldownError(Exception):
    """A successful NVD batch completed too recently."""

    def __init__(self, retry_after: int):
        self.retry_after = retry_after
        super().__init__(
            f"NVD was refreshed recently. Try again in {retry_after} seconds."
        )


class NVDProviderRateLimitError(Exception):
    """NVD asked the client to stop sending requests temporarily."""

    def __init__(self, retry_after: int):
        self.retry_after = retry_after
        super().__init__(
            f"NVD rate limit reached. Retry in about {retry_after} seconds."
        )


def _stale_before(now: datetime | None = None) -> datetime:
    """Return the fetched-at cutoff used to select stale NVD rows."""

    current = now or datetime.now(timezone.utc)
    return current - timedelta(hours=NVD_STALE_AFTER_HOURS)


def _retry_after_from_response(response: httpx.Response) -> int:
    """Use NVD's Retry-After header when valid, otherwise our safe retry delay."""

    value = response.headers.get("Retry-After")
    if value:
        try:
            return max(1, int(value))
        except ValueError:
            pass
    return NVD_RETRY_INTERVAL_SECONDS


async def get_stored_nvd_cve(cve_id: str) -> NVDCVE | None:
    """Normalize one CVE ID and read its current NVD data from PostgreSQL."""

    cleaned_id = normalize_cve_id(cve_id)
    return await get_nvd_cve_by_cve(cleaned_id)


async def get_stored_nvd_history(
    cve_id: str,
    limit: int = 20,
) -> list[NVDCVSSChange]:
    """Read newest-first CVSS change history without contacting NVD."""

    cleaned_id = normalize_cve_id(cve_id)
    return await get_nvd_cvss_history(cleaned_id, limit)


async def get_nvd_status() -> NVDFeedStatus:
    """Combine durable NVD/KEV counts with temporary Redis refresh metadata."""

    cutoff = _stale_before()
    total_stored, total_kev, pending = await asyncio.gather(
        count_nvd_cves(),
        count_kev_entries(),
        count_nvd_refresh_candidates(cutoff),
    )
    return await cache.get_nvd_feed_status(
        total_stored_cves=total_stored,
        total_kev_cves=total_kev,
        pending_count=pending,
    )


async def refresh_nvd_data() -> NVDRefreshResult:
    """Enrich one bounded batch of missing/stale KEVs from NVD.

    Return value
    ------------
    The result counts only this batch and also reports how many candidates are
    still pending afterward. The worker uses ``remaining_count`` to decide
    whether it should continue backfilling soon or return to its idle cadence.

    Failure handling
    ----------------
    - Redis lock/cooldown errors stop the batch before provider requests.
    - A provider 429 stops the batch immediately so we do not keep hammering
      NVD after it has asked us to slow down.
    - Individual network, HTTP (non-429), or malformed-response failures are
      counted and the batch continues to other CVEs.
    - PostgreSQL failures propagate because continuing when durable writes are
      broken would only create misleading success counts.
    - Previously stored NVD rows remain available after any refresh failure.
    """

    token = await cache.acquire_nvd_refresh_lock()
    if token is None:
        raise NVDRefreshInProgressError("An NVD refresh is already running")

    try:
        async with asyncio.timeout(NVD_REFRESH_TIMEOUT_SECONDS):
            remaining_cooldown = await cache.get_nvd_refresh_cooldown_remaining()
            if remaining_cooldown:
                raise NVDRefreshCooldownError(remaining_cooldown)

            if not await count_kev_entries():
                raise NVDCatalogNotReadyError(
                    "KEV data is not ready yet. Refresh KEV first; NVD will retry automatically."
                )

            cutoff = _stale_before()
            cve_ids = await get_kev_cve_ids_needing_nvd(
                stale_before=cutoff,
                limit=NVD_BATCH_SIZE,
            )

            stored_count = 0
            unavailable_count = 0
            failed_count = 0

            for index, cve_id in enumerate(cve_ids):
                try:
                    record = await fetch_nvd_cve(cve_id)
                    if record is None:
                        unavailable_count += 1
                    else:
                        await upsert_nvd_cve(record)
                        stored_count += 1

                except httpx.HTTPStatusError as exc:
                    if exc.response.status_code == 429:
                        raise NVDProviderRateLimitError(
                            _retry_after_from_response(exc.response)
                        ) from exc

                    failed_count += 1
                    logger.warning(
                        "NVD HTTP failure for %s: status=%s",
                        cve_id,
                        exc.response.status_code,
                    )

                except (httpx.RequestError, NVDResponseError, ValueError) as exc:
                    failed_count += 1
                    logger.warning(
                        "NVD provider/validation failure for %s: %s",
                        cve_id,
                        exc,
                    )

                # NVD recommends sequential, paced requests. Do not sleep after
                # the final item because there is no next provider call to pace.
                if index < len(cve_ids) - 1:
                    await asyncio.sleep(NVD_REQUEST_DELAY_SECONDS)

            pending = await count_nvd_refresh_candidates(cutoff)
            result = NVDRefreshResult(
                requested_count=len(cve_ids),
                stored_count=stored_count,
                unavailable_count=unavailable_count,
                failed_count=failed_count,
                remaining_count=pending,
                refreshed_at=datetime.now(timezone.utc),
            )
            await cache.publish_nvd_refresh(result)
            return result

    except NVDProviderRateLimitError:
        try:
            await cache.publish_nvd_failure(
                "NVD rate-limited the last refresh. Stored data remains available; "
                "the worker will retry later."
            )
        except Exception:
            logger.exception("Could not record NVD rate-limit status")
        raise
    except (NVDRefreshCooldownError, NVDCatalogNotReadyError):
        raise
    except Exception:
        try:
            await cache.publish_nvd_failure(
                "The last NVD refresh failed. Stored NVD data remains available; "
                "the worker will retry."
            )
        except Exception:
            logger.exception("Could not record NVD failure status")
        raise
    finally:
        try:
            await cache.release_nvd_refresh_lock(token)
        except Exception:
            # The Redis lease expires automatically. Preserve the original error.
            logger.exception("Could not release NVD refresh lock")
