"""Coordinate KEV behavior for HTTP routes and the scheduled worker.

PostgreSQL is the durable source; Redis accelerates reads and coordinates
refreshes across API processes. Ordinary GET requests never download CISA.
"""
import asyncio
import logging
from datetime import datetime, timezone

from app.collectors.cisa_kev import fetch_kev_catalog
from app.models.kev import KEVEntry, KEVFeedStatus, KEVRefreshResult
from app.storage import kev_cache as cache
from app.storage.kev_repository import (
    get_kev_entry_by_cve, get_latest_kev_entries,
    search_kev_entries, upsert_kev_entries,
)

logger = logging.getLogger(__name__)
KEV_CACHE_SIZE = 50
# Leave time for cancellation and lock cleanup before the Redis lease expires.
KEV_REFRESH_TIMEOUT_SECONDS = 240


class KEVRefreshInProgressError(Exception):
    """Another process already owns the refresh lease."""


class KEVRefreshCooldownError(Exception):
    def __init__(self, retry_after: int):
        self.retry_after = retry_after
        super().__init__(f"KEV was refreshed recently. Try again in {retry_after} seconds.")


async def refresh_kev_data() -> KEVRefreshResult:
    """Lock, check cooldown, download, commit PostgreSQL, then publish cache.

A Redis outage fails refresh closed: ingestion must not proceed without its
cross-process lock. Reads can still fall back to PostgreSQL. A failed cache
publication leaves durable rows intact and does not record refresh success.
"""
    token = await cache.acquire_kev_refresh_lock()
    if token is None:
        raise KEVRefreshInProgressError("A KEV refresh is already running")
    try:
        async with asyncio.timeout(KEV_REFRESH_TIMEOUT_SECONDS):
            remaining = await cache.get_refresh_cooldown_remaining()
            if remaining:
                raise KEVRefreshCooldownError(remaining)
            catalog = await fetch_kev_catalog()
            if not catalog.vulnerabilities or catalog.total_count != len(catalog.vulnerabilities):
                raise ValueError("CISA returned an empty or inconsistent catalog")
            stored_count = await upsert_kev_entries(catalog.vulnerabilities)
            # Read through the same ordering used by cache-miss requests.
            latest = await get_latest_kev_entries(KEV_CACHE_SIZE)
            refreshed_at = datetime.now(timezone.utc)
            await cache.publish_kev_refresh(latest, refreshed_at)
            return KEVRefreshResult(
                fetched_count=len(catalog.vulnerabilities), stored_count=stored_count,
                cached_count=len(latest), refreshed_at=refreshed_at,
            )
    finally:
        try:
            await cache.release_kev_refresh_lock(token)
        except Exception:
            # Preserve the original failure; the lease still expires automatically.
            logger.exception("Could not release KEV refresh lock")


async def get_latest_kev(limit: int = 20) -> list[KEVEntry]:
    """Serve cached rows, or durable rows when Redis is empty/unavailable.

Cache misses do not write a snapshot back: that could race with a concurrent
refresh and overwrite its newer cache. Only successful refreshes publish it.
"""
    try:
        entries = await cache.get_cached_kev_entries()
        if entries:
            return entries[:limit]
    except Exception:
        logger.warning("KEV cache unavailable; reading PostgreSQL", exc_info=True)
    return await get_latest_kev_entries(limit)


async def get_kev_status() -> KEVFeedStatus:
    """Return one Redis snapshot of last success, lock state, and cache size."""
    return await cache.get_kev_feed_status()


async def search_kev(search_term: str, limit: int = 50) -> list[KEVEntry]:
    cleaned_term = search_term.strip()
    return await search_kev_entries(cleaned_term, limit) if cleaned_term else []


async def get_kev_details(cve_id: str) -> KEVEntry | None:
    return await get_kev_entry_by_cve(cve_id)
