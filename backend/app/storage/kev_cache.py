"""Redis cache and cross-process refresh coordination for CISA KEV."""

import json
import math
from datetime import datetime, timezone
from uuid import uuid4

from app.config import KEV_REFRESH_INTERVAL_SECONDS
from app.models.kev import KEVEntry, KEVFeedStatus
from app.storage.redis import create_redis_client


KEV_CACHE_KEY = "kev:latest"
KEV_REFRESH_LOCK_KEY = "kev:refresh_lock"
KEV_LAST_REFRESH_KEY = "kev:last_refresh"
KEV_REFRESH_LOCK_TTL_SECONDS = 300
KEV_REFRESH_COOLDOWN_SECONDS = 60
KEV_CACHE_TTL_SECONDS = max(3_600, KEV_REFRESH_INTERVAL_SECONDS * 2)


def _decode_entries(payload: str | None) -> list[KEVEntry]:
    """Turn cached JSON back into validated KEV models."""
    if not payload:
        return []
    return [KEVEntry.model_validate(item) for item in json.loads(payload)]


async def get_cached_kev_entries() -> list[KEVEntry]:
    return _decode_entries(await create_redis_client().get(KEV_CACHE_KEY))


async def publish_kev_refresh(
    entries: list[KEVEntry],
    refreshed_at: datetime,
) -> None:
    """Publish entries and the success timestamp in one Redis transaction."""
    payload = json.dumps([entry.model_dump(mode="json") for entry in entries])
    async with create_redis_client().pipeline(transaction=True) as pipeline:
        pipeline.set(KEV_CACHE_KEY, payload, ex=KEV_CACHE_TTL_SECONDS)
        pipeline.set(KEV_LAST_REFRESH_KEY, refreshed_at.isoformat())
        await pipeline.execute()


async def acquire_kev_refresh_lock() -> str | None:
    """Grant one process an expiring refresh lease and return its token."""
    token = uuid4().hex
    acquired = await create_redis_client().set(
        KEV_REFRESH_LOCK_KEY,
        token,
        nx=True,
        ex=KEV_REFRESH_LOCK_TTL_SECONDS,
    )
    return token if acquired else None


async def release_kev_refresh_lock(token: str) -> None:
    """Release only the lease still owned by the supplied token."""
    await create_redis_client().eval(
        "if redis.call('get', KEYS[1]) == ARGV[1] then "
        "return redis.call('del', KEYS[1]) else return 0 end",
        1,
        KEV_REFRESH_LOCK_KEY,
        token,
    )


async def get_refresh_cooldown_remaining() -> int:
    value = await create_redis_client().get(KEV_LAST_REFRESH_KEY)
    if not value:
        return 0

    last_refresh = datetime.fromisoformat(value)
    if last_refresh.tzinfo is None:
        last_refresh = last_refresh.replace(tzinfo=timezone.utc)

    elapsed = (datetime.now(timezone.utc) - last_refresh).total_seconds()
    return max(0, math.ceil(KEV_REFRESH_COOLDOWN_SECONDS - elapsed))


async def get_kev_feed_status() -> KEVFeedStatus:
    """Read cache, timestamp, and lock as one consistent Redis snapshot."""
    payload, timestamp, lock = await create_redis_client().mget(
        KEV_CACHE_KEY,
        KEV_LAST_REFRESH_KEY,
        KEV_REFRESH_LOCK_KEY,
    )
    return KEVFeedStatus(
        cached_entries=len(_decode_entries(payload)),
        last_refreshed_at=timestamp,
        refresh_in_progress=lock is not None,
    )
