"""Shared Redis client lifecycle for every Situation Monitor feature."""

import redis.asyncio as redis_async

from app.config import REDIS_URL


_client: redis_async.Redis | None = None


def create_redis_client() -> redis_async.Redis:
    """Create one pooled client lazily and reuse it across KEV and EPSS."""
    global _client
    if not REDIS_URL:
        raise RuntimeError("REDIS_URL is not configured")
    if _client is None:
        _client = redis_async.from_url(
            REDIS_URL,
            decode_responses=True,
            socket_connect_timeout=5,
            socket_timeout=5,
            max_connections=20,
        )
    return _client


async def close_redis_client() -> None:
    """Close Redis connections once during FastAPI shutdown."""
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None


async def check_redis_connection() -> bool:
    """Return a Boolean suitable for the platform health endpoint."""
    try:
        return bool(await create_redis_client().ping())
    except Exception:
        return False
