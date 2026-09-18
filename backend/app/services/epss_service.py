"""Coordinate FIRST collection, PostgreSQL storage, and Redis state."""

import asyncio
import logging
from datetime import datetime, timezone

from app.collectors.epss import fetch_epss_scores, normalize_cve_id
from app.models.epss import EPSSFeedStatus, EPSSRefreshResult, EPSSScore
from app.storage import epss_cache as cache
from app.storage.epss_repository import (
    count_epss_scores,
    count_kev_entries,
    get_epss_score_by_cve,
    get_kev_cve_ids_needing_epss,
    upsert_epss_scores,
)


logger = logging.getLogger(__name__)
EPSS_REFRESH_TIMEOUT_SECONDS = 240


class EPSSRefreshInProgressError(Exception):
    """Another API process or worker already owns the refresh lease."""


class EPSSCatalogNotReadyError(Exception):
    """KEV must populate the local database before EPSS can enrich it."""


class EPSSRefreshCooldownError(Exception):
    """A successful refresh occurred too recently."""

    def __init__(self, retry_after: int):
        self.retry_after = retry_after
        super().__init__(
            f"EPSS was refreshed recently. Try again in {retry_after} seconds."
        )


async def get_stored_epss_score(cve_id: str) -> EPSSScore | None:
    """Normalize one CVE ID and read its current local score."""
    cleaned_id = normalize_cve_id(cve_id)
    return await get_epss_score_by_cve(cleaned_id)


async def get_epss_status() -> EPSSFeedStatus:
    """Combine durable score count with temporary Redis refresh state."""
    total = await count_epss_scores()
    return await cache.get_epss_feed_status(total)


async def refresh_epss_data() -> EPSSRefreshResult:
    """Refresh missing or stale scores for the local CISA KEV catalog."""
    token = await cache.acquire_epss_refresh_lock()
    if token is None:
        raise EPSSRefreshInProgressError("An EPSS refresh is already running")

    try:
        async with asyncio.timeout(EPSS_REFRESH_TIMEOUT_SECONDS):
            remaining = await cache.get_epss_refresh_cooldown_remaining()
            if remaining:
                raise EPSSRefreshCooldownError(remaining)

            if not await count_kev_entries():
                raise EPSSCatalogNotReadyError(
                    "KEV data is not ready yet. Refresh KEV first; EPSS will retry automatically."
                )

            # Scores older than today's UTC date are refresh candidates. We
            # select the candidate set once so a provider still publishing
            # yesterday's date cannot create an endless refresh loop.
            today_utc = datetime.now(timezone.utc).date()
            cve_ids = await get_kev_cve_ids_needing_epss(
                minimum_score_date=today_utc,
            )

            scores = await fetch_epss_scores(cve_ids)
            stored_count = await upsert_epss_scores(scores)
            result = EPSSRefreshResult(
                requested_count=len(cve_ids),
                stored_count=stored_count,
                unavailable_count=len(cve_ids) - len(scores),
                refreshed_at=datetime.now(timezone.utc),
            )
            await cache.publish_epss_refresh(result)
            return result
    except (EPSSRefreshCooldownError, EPSSCatalogNotReadyError):
        raise
    except Exception:
        try:
            await cache.publish_epss_failure(
                "The last EPSS refresh failed. Stored scores remain available; the worker will retry."
            )
        except Exception:
            logger.exception("Could not record EPSS failure status")
        raise
    finally:
        try:
            await cache.release_epss_refresh_lock(token)
        except Exception:
            # The lease expires automatically. Preserve any original failure.
            logger.exception("Could not release EPSS refresh lock")
