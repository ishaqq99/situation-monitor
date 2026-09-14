from pathlib import Path
import os

import asyncpg
import redis.asyncio as redis

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware


# Find the root of our project.
PROJECT_ROOT = Path(__file__).resolve().parents[2]

# Load variables from the root .env file.
load_dotenv(PROJECT_ROOT / ".env")


DATABASE_URL = os.getenv("DATABASE_URL")
REDIS_URL = os.getenv("REDIS_URL")


app = FastAPI(
    title="Situation Monitor API",
    description="Backend API for the real-time situational awareness platform.",
    version="0.1.0",
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


@app.get("/")
def root():
    return {
        "service": "Situation Monitor API",
        "version": "0.1.0",
    }


@app.get("/api/health")
async def health_check():
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