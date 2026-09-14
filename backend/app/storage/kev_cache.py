import json
import os
from pathlib import Path

import redis.asyncio as redis
from dotenv import load_dotenv

from app.models.kev import KEVEntry


PROJECT_ROOT = Path(__file__).resolve().parents[3]
load_dotenv(PROJECT_ROOT / ".env")

REDIS_URL = os.getenv("REDIS_URL")

KEV_CACHE_KEY = "kev:latest"


def create_redis_client():
    """
    Build a Redis client using REDIS_URL from .env.
    """

    if not REDIS_URL:
        raise RuntimeError("REDIS_URL is not configured")

    return redis.from_url(
        REDIS_URL,
        decode_responses=True,
    )


async def cache_kev_entries(entries: list[KEVEntry]) -> None:
    """
    Serialize the latest KEV entries to JSON and store them in Redis.
    """

    payload = json.dumps(
        [
            entry.model_dump(mode="json")
            for entry in entries
        ]
    )

    client = create_redis_client()

    try:
        await client.set(KEV_CACHE_KEY, payload)

    finally:
        await client.aclose()


async def get_cached_kev_entries() -> list[KEVEntry]:
    """
    Read the current KEV cache from Redis.
    """

    client = create_redis_client()

    try:
        payload = await client.get(KEV_CACHE_KEY)

    finally:
        await client.aclose()

    if not payload:
        return []

    raw_entries = json.loads(payload)

    return [
        KEVEntry.model_validate(item)
        for item in raw_entries
    ]


async def check_redis_connection() -> bool:
    """
    Test whether Redis is reachable.
    """

    client = None

    try:
        client = create_redis_client()
        await client.ping()
        return True

    except Exception:
        return False

    finally:
        if client is not None:
            await client.aclose()