<<<<<<< Updated upstream
from pathlib import Path
import os
=======
"""FastAPI application lifecycle, routing, CORS, and health checks."""

import asyncio
from contextlib import asynccontextmanager
>>>>>>> Stashed changes

import asyncpg
import redis.asyncio as redis

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

<<<<<<< Updated upstream

# Find the root of our project.
PROJECT_ROOT = Path(__file__).resolve().parents[2]

# Load variables from the root .env file.
load_dotenv(PROJECT_ROOT / ".env")


DATABASE_URL = os.getenv("DATABASE_URL")
REDIS_URL = os.getenv("REDIS_URL")
=======
from app.api.epss import router as epss_router
from app.api.kev import router as kev_router
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


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Open shared resources, run workers, and close everything cleanly."""
    stop_event = asyncio.Event()
    workers: list[asyncio.Task] = []

    try:
        await initialize_pool()
        await initialize_database()

        # Both workers use the same stop signal. EPSS waits briefly before its
        # first refresh so the immediate KEV worker can populate a new database.
        workers = [
            asyncio.create_task(run_kev_worker(stop_event), name="kev-worker"),
            asyncio.create_task(run_epss_worker(stop_event), name="epss-worker"),
        ]
        yield
    finally:
        stop_event.set()
        for worker in workers:
            worker.cancel()
        if workers:
            await asyncio.gather(*workers, return_exceptions=True)

        try:
            await close_redis_client()
        finally:
            await close_database_pool()
>>>>>>> Stashed changes


app = FastAPI(
    title="Situation Monitor API",
<<<<<<< Updated upstream
    description="Backend API for the real-time situational awareness platform.",
    version="0.1.0",
=======
    version="0.2.0",
    lifespan=lifespan,
>>>>>>> Stashed changes
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

<<<<<<< Updated upstream

@app.get("/")
def root():
    return {
        "service": "Situation Monitor API",
        "version": "0.1.0",
    }
=======
app.include_router(kev_router)
app.include_router(epss_router)


@app.get("/")
def root():
    return {"service": "Situation Monitor API", "version": "0.2.0"}
>>>>>>> Stashed changes


@app.get("/api/health")
async def health_check():
<<<<<<< Updated upstream
    database_status = "unhealthy"
    redis_status = "unhealthy"

    # Test PostgreSQL.
    try:
        connection = await asyncpg.connect(DATABASE_URL)

        await connection.execute("SELECT 1")

        await connection.close()

        database_status = "healthy"

    except Exception:
        database_status = "unhealthy"


    # Test Redis.
    try:
        redis_client = redis.from_url(REDIS_URL)

        await redis_client.ping()

        await redis_client.aclose()

        redis_status = "healthy"

    except Exception:
        redis_status = "unhealthy"


    return {
        "status": "healthy",
        "api": True,
        "database": database_status,
        "redis": redis_status,
    }
=======
    """Report dependency degradation while keeping a readable response."""
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
>>>>>>> Stashed changes
