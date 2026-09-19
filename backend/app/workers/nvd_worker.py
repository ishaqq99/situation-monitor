"""Scheduled NVD enrichment worker for the local CISA KEV catalog.

FILE ROLE
---------
This module decides *when* NVD enrichment should run. It does not choose CVEs,
call NVD directly, or write SQL; ``nvd_service.refresh_nvd_data`` owns that
business process.

SCHEDULING POLICY
-----------------
- Wait briefly after FastAPI startup so KEV can populate a new database first.
- Process one bounded NVD batch.
- If candidates remain, wait a short backlog interval and process another batch.
- If fully caught up, sleep for the longer idle interval and check again later.
- Temporary failures use the retry interval rather than killing the worker.

This makes first-time backfill resumable and keeps normal steady-state work
lightweight.
"""

import asyncio
import logging

from app.config import (
    NVD_BACKLOG_RETRY_INTERVAL_SECONDS,
    NVD_IDLE_CHECK_INTERVAL_SECONDS,
    NVD_RETRY_INTERVAL_SECONDS,
    NVD_STARTUP_DELAY_SECONDS,
)
from app.services.nvd_service import (
    NVDCatalogNotReadyError,
    NVDProviderRateLimitError,
    NVDRefreshCooldownError,
    NVDRefreshInProgressError,
    refresh_nvd_data,
)


logger = logging.getLogger(__name__)


async def run_nvd_worker(stop_event: asyncio.Event) -> None:
    """Run protected NVD batches until application shutdown."""

    try:
        await asyncio.wait_for(
            stop_event.wait(),
            timeout=NVD_STARTUP_DELAY_SECONDS,
        )
        return
    except TimeoutError:
        pass

    while not stop_event.is_set():
        delay = NVD_IDLE_CHECK_INTERVAL_SECONDS

        try:
            result = await refresh_nvd_data()
            logger.info(
                "Automatic NVD refresh complete: %s requested, %s stored, %s remaining",
                result.requested_count,
                result.stored_count,
                result.remaining_count,
            )

            if result.remaining_count > 0:
                if result.stored_count > 0:
                    # Normal first-time/stale backlog: keep making progress.
                    delay = NVD_BACKLOG_RETRY_INTERVAL_SECONDS
                elif result.failed_count > 0:
                    # Provider/network failures deserve a moderate retry.
                    delay = NVD_RETRY_INTERVAL_SECONDS
                else:
                    # No progress and no transient failure usually means the
                    # remaining CVEs are currently unavailable from NVD. Avoid
                    # repeatedly querying the same IDs in a tight loop.
                    delay = NVD_IDLE_CHECK_INTERVAL_SECONDS

        except NVDRefreshCooldownError as exc:
            delay = max(1, exc.retry_after)

        except NVDProviderRateLimitError as exc:
            delay = max(NVD_RETRY_INTERVAL_SECONDS, exc.retry_after)
            logger.warning("Automatic NVD refresh rate-limited; retrying later")

        except (NVDRefreshInProgressError, NVDCatalogNotReadyError):
            delay = NVD_RETRY_INTERVAL_SECONDS
            logger.info("Automatic NVD refresh skipped: running or KEV not ready")

        except Exception:
            # Provider/storage failures must not permanently kill the scheduler.
            delay = NVD_RETRY_INTERVAL_SECONDS
            logger.exception("Automatic NVD refresh failed")

        try:
            await asyncio.wait_for(stop_event.wait(), timeout=delay)
        except TimeoutError:
            pass
