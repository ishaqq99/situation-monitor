from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.kev import router as kev_router
from app.storage.kev_cache import check_redis_connection
from app.storage.postgres import (
    check_database_connection,
    initialize_database,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Run startup work before FastAPI begins serving requests.
    """

    await initialize_database()

    yield


app = FastAPI(
    title="Situation Monitor API",
    description="Backend API for the real-time situational awareness platform.",
    version="0.1.0",
    lifespan=lifespan,
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(kev_router)


@app.get("/")
def root():
    """
    Simple application identity endpoint.
    """

    return {
        "service": "Situation Monitor API",
        "version": "0.1.0",
    }


@app.get("/api/health")
async def health_check():
    """
    Check FastAPI, PostgreSQL, and Redis health.
    """

    database_healthy = await check_database_connection()
    redis_healthy = await check_redis_connection()

    return {
        "status": (
            "healthy"
            if database_healthy and redis_healthy
            else "degraded"
        ),
        "api": True,
        "database": (
            "healthy"
            if database_healthy
            else "unhealthy"
        ),
        "redis": (
            "healthy"
            if redis_healthy
            else "unhealthy"
        ),
    }