"""
Situation Monitor FastAPI application entry point.

Why this file exists
--------------------
This module creates the FastAPI application, connects the major backend pieces,
starts shared resources and background workers during application startup, and
shuts those resources down cleanly when the API stops.

Where this file sits in the architecture
----------------------------------------
Browser / React frontend
        |
        v
FastAPI application (this file)
        |
        +--> KEV API router  --> KEV service / repository / cache
        |
        +--> EPSS API router --> EPSS service / repository / cache
        |
        +--> NVD API router  --> NVD service / repository / cache
        |
        +--> PostgreSQL shared connection pool
        |
        +--> Redis shared client
        |
        +--> KEV background worker
        |
        +--> EPSS background worker
        |
        +--> NVD background worker

Who imports/calls this file
---------------------------
Uvicorn imports ``app.main:app`` when you run:

    uvicorn app.main:app --reload

FastAPI then invokes ``lifespan()`` automatically when the application starts
and stops.

What this file deliberately does NOT do
---------------------------------------
- It does not fetch CISA KEV data itself.
- It does not fetch EPSS data itself.
- It does not contain PostgreSQL query logic.
- It does not create Redis connections directly for every request.
- It does not fetch NVD data itself; the NVD collector/service own that work.

Those responsibilities stay in their own collectors, services, storage modules,
and workers so this entry point remains small and predictable.
"""

import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.epss import router as epss_router
from app.api.kev import router as kev_router
from app.api.nvd import router as nvd_router
from app.config import CORS_ORIGINS
from app.storage.postgres import (
    check_database_connection,
    close_database_pool,
    initialize_database,
    initialize_pool,
)
from app.storage.redis import check_redis_connection, close_redis_client
from app.workers.epss_worker import run_epss_worker
from app.workers.kev_worker import run_kev_worker
from app.workers.nvd_worker import run_nvd_worker


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Manage shared application resources and background workers.

    Inputs
    ------
    app:
        The FastAPI application instance. FastAPI supplies this automatically.

    Returns
    -------
    This is an async context manager rather than a normal return-based function.
    Code before ``yield`` runs during startup. Code after ``yield`` runs during
    shutdown.

    What happens during startup
    ---------------------------
    1. Create the shared PostgreSQL connection pool.
    2. Initialize database tables/indexes required by the existing application.
    3. Start the KEV background worker.
    4. Start the EPSS background worker.
    5. Start the NVD background worker.
    6. Yield control so FastAPI can begin serving requests.

    What happens during shutdown
    ----------------------------
    1. Signal workers that shutdown has started.
    2. Cancel any still-running worker tasks.
    3. Wait for their cancellation results so shutdown is orderly.
    4. Close the shared Redis client.
    5. Close the PostgreSQL connection pool.

    Failure handling
    ----------------
    If startup fails before ``yield``, FastAPI will not begin serving requests.
    The ``finally`` block still attempts to close resources that may already
    have been created. Worker cancellation uses ``return_exceptions=True`` so
    one worker's cancellation does not prevent the others from being cleaned up.
    """

    # All background workers receive the same event so they have one shared
    # shutdown signal. Each worker can inspect the event while sleeping or
    # between refresh cycles.
    stop_event = asyncio.Event()

    # Keep the tasks in a list so every started worker can be cancelled and
    # awaited during shutdown. The list starts empty in case startup fails
    # before the workers are created.
    workers: list[asyncio.Task] = []

    try:
        # Create one shared PostgreSQL pool for the application instead of
        # opening a brand-new database connection for every API operation.
        await initialize_pool()

        # Ensure the current KEV/EPSS/NVD database objects exist before workers or
        # API routes begin depending on them.
        await initialize_database()

        # Start the existing background refresh loops. EPSS already contains
        # its own startup-delay behavior so KEV can populate a new database
        # first; that timing remains owned by the worker rather than this file.
        workers = [
            asyncio.create_task(run_kev_worker(stop_event), name="kev-worker"),
            asyncio.create_task(run_epss_worker(stop_event), name="epss-worker"),
            asyncio.create_task(run_nvd_worker(stop_event), name="nvd-worker"),
        ]

        # FastAPI serves requests while execution is paused here.
        yield

    finally:
        # Tell cooperative worker loops that application shutdown has started.
        stop_event.set()

        # Cancel any worker still blocked in a sleep/network operation so the
        # process does not hang while Uvicorn is trying to stop.
        for worker in workers:
            worker.cancel()

        # Await cancelled tasks so Python can finish their cleanup code.
        if workers:
            await asyncio.gather(*workers, return_exceptions=True)

        # Redis is closed before PostgreSQL simply because both are independent
        # shared resources; the nested finally guarantees the database pool is
        # still closed even if Redis cleanup raises unexpectedly.
        try:
            await close_redis_client()
        finally:
            await close_database_pool()


# The application object imported by Uvicorn through ``app.main:app``.
app = FastAPI(
    title="Situation Monitor API",
    version="0.3.0",
    lifespan=lifespan,
)


# Allow the React/Vite frontend origins configured in app.config to call the
# backend API. The current application only needs GET and POST requests.
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


# Register the existing feature routers. Keeping route definitions in their own
# modules prevents this application entry point from becoming a large API file.
app.include_router(kev_router)
app.include_router(epss_router)
app.include_router(nvd_router)


@app.get("/")
def root():
    """
    Return lightweight API identity/version information.

    Called by
    ---------
    Any client requesting ``GET /``.

    Important behavior
    ------------------
    This endpoint intentionally does not contact PostgreSQL or Redis. It only
    proves that the FastAPI process itself is reachable.
    """

    return {
        "service": "Situation Monitor API",
        "version": "0.3.0",
    }


@app.get("/api/health")
async def health_check():
    """
    Check whether PostgreSQL and Redis are reachable through shared helpers.

    Called by
    ---------
    Monitoring, manual browser/API checks, or any client requesting
    ``GET /api/health``.

    What it calls
    -------------
    - ``check_database_connection()``
    - ``check_redis_connection()``

    Both checks run concurrently with ``asyncio.gather`` so the endpoint does
    not unnecessarily wait for one dependency check to finish before starting
    the other.

    Return value
    ------------
    ``status`` is ``healthy`` only when both dependencies are reachable.
    Otherwise the API remains readable and reports ``degraded`` along with the
    individual dependency state.
    """

    database, redis = await asyncio.gather(
        check_database_connection(),
        check_redis_connection(),
    )

    return {
        "status": "healthy" if database and redis else "degraded",
        "api": True,
        "database": "healthy" if database else "unhealthy",
        "redis": "healthy" if redis else "unhealthy",
    }
