"""Scheduled KEV ingestion using the same protected service as manual refresh.

Run immediately at startup so a fresh database populates without a manual
click. Redis locking and cooldown coordinate workers in multiple API processes.
"""
import asyncio
import logging
from app.config import KEV_REFRESH_INTERVAL_SECONDS
from app.services.kev_service import (
    KEVRefreshCooldownError, KEVRefreshInProgressError, refresh_kev_data,
)

logger = logging.getLogger(__name__)


async def run_kev_worker(stop_event: asyncio.Event) -> None:
    while not stop_event.is_set():
        try:
            result = await refresh_kev_data()
            logger.info("Automatic KEV refresh complete: %s fetched", result.fetched_count)
        except (KEVRefreshInProgressError, KEVRefreshCooldownError):
            logger.info("Automatic KEV refresh skipped: running or recently refreshed")
        except Exception:
            # An upstream/storage failure must not permanently kill the scheduler.
            logger.exception("Automatic KEV refresh failed")
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=KEV_REFRESH_INTERVAL_SECONDS)
        except TimeoutError:
            pass
