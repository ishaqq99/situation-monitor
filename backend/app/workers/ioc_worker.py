"""Background OTX clock: ask the service to process one due job each tick.

All scheduling state is durable in PostgreSQL. This loop neither chooses CVEs
nor downloads provider data itself. Failures are logged without killing the
worker; cancellation propagates so FastAPI can shut down its shared pool.


FILE GUIDE
----------
WHAT THIS FILE DOES
Wake periodically and ask the service to run at most one due CVE job.

WHY IT EXISTS
The browser should not wait for slow provider pages; recurring work needs a background loop.

WHO CALLS OR IMPORTS IT
app.main.lifespan creates and later cancels this worker task.

WHAT IT CALLS OR IMPORTS
Calls ioc_service.run_one_due_job, which owns all scheduling and collection policy.

ROLE IN THE ARCHITECTURE
Background clock, not a second queue or data store.
"""
import asyncio
import logging
from app.config import OTX_WORKER_POLL_SECONDS
from app.services.ioc_service import run_one_due_job

logger = logging.getLogger(__name__)


async def run_ioc_worker(stop_event: asyncio.Event) -> None:
    """Process bounded jobs until shutdown; waiting is interruptible by the event.

    Function detail: Called by app.main.lifespan. It keeps polling until shutdown, logs
      recoverable errors, and allows cancellation so database cleanup can finish.
    """
    while not stop_event.is_set():
        try:
            outcome = await run_one_due_job()
            if outcome in {"complete", "partial", "failed", "deferred"}:
                logger.info("OTX background attempt: %s", outcome)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            # Do not log request headers, API keys, or entire provider payloads.
            logger.error("OTX worker could not complete its tick (%s)", type(exc).__name__)
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=OTX_WORKER_POLL_SECONDS)
        except TimeoutError:
            pass
