"""Scheduled EPSS refresh worker."""

import asyncio
import logging

from app.config import (
    EPSS_REFRESH_INTERVAL_SECONDS, EPSS_STARTUP_DELAY_SECONDS,
    EPSS_RETRY_INTERVAL_SECONDS,
)
from app.services.epss_service import (
    EPSSRefreshCooldownError,
    EPSSRefreshInProgressError,
    EPSSCatalogNotReadyError,
    refresh_epss_data,
)


logger = logging.getLogger(__name__)


async def run_epss_worker(stop_event: asyncio.Event) -> None:
    """Refresh after KEV startup ingestion, then repeat once per interval."""
    try:
        await asyncio.wait_for(
            stop_event.wait(),
            timeout=EPSS_STARTUP_DELAY_SECONDS,
        )
        return
    except TimeoutError:
        pass

    while not stop_event.is_set():
        delay = EPSS_REFRESH_INTERVAL_SECONDS
        try:
            result = await refresh_epss_data()
            logger.info(
                "Automatic EPSS refresh complete: %s requested, %s stored",
                result.requested_count,
                result.stored_count,
            )
        except EPSSRefreshCooldownError as exc:
            delay = max(1, exc.retry_after)
        except (EPSSRefreshInProgressError, EPSSCatalogNotReadyError):
            delay = EPSS_RETRY_INTERVAL_SECONDS
            logger.info("Automatic EPSS refresh skipped: running or recently refreshed")
        except Exception:
            # A temporary FIRST/storage failure must not kill the scheduler.
            logger.exception("Automatic EPSS refresh failed")
            delay = EPSS_RETRY_INTERVAL_SECONDS

        try:
            await asyncio.wait_for(
                stop_event.wait(),
                timeout=delay,
            )
        except TimeoutError:
            pass
