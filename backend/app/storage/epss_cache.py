"""Redis refresh locking and status metadata for EPSS.

PostgreSQL stores scores permanently. Redis only coordinates refresh jobs and
records their latest successful summary, so losing Redis does not lose scores.
"""

import json
import math
from datetime import datetime, timezone
from uuid import uuid4

from app.models.epss import EPSSFeedStatus, EPSSRefreshResult
from app.storage.redis import create_redis_client


EPSS_REFRESH_LOCK_KEY = "epss:refresh_lock"
EPSS_LAST_REFRESH_KEY = "epss:last_refresh"
EPSS_LAST_RESULT_KEY = "epss:last_result"
EPSS_LAST_ERROR_KEY = "epss:last_error"
EPSS_REFRESH_LOCK_TTL_SECONDS = 300
EPSS_REFRESH_COOLDOWN_SECONDS = 300


async def acquire_epss_refresh_lock() -> str | None:
    """Acquire a unique, expiring refresh lease using Redis SET NX."""
    token = uuid4().hex
    acquired = await create_redis_client().set(
        EPSS_REFRESH_LOCK_KEY,
        token,
        nx=True,
        ex=EPSS_REFRESH_LOCK_TTL_SECONDS,
    )
    return token if acquired else None


async def release_epss_refresh_lock(token: str) -> None:
    """Release the lock only when this process still owns it."""
    await create_redis_client().eval(
        "if redis.call('get', KEYS[1]) == ARGV[1] then "
        "return redis.call('del', KEYS[1]) else return 0 end",
        1,
        EPSS_REFRESH_LOCK_KEY,
        token,
    )


async def get_epss_refresh_cooldown_remaining() -> int:
    """Return seconds remaining before another manual refresh may begin."""
    value = await create_redis_client().get(EPSS_LAST_REFRESH_KEY)
    if not value:
        return 0

    last_refresh = datetime.fromisoformat(value)
    if last_refresh.tzinfo is None:
        last_refresh = last_refresh.replace(tzinfo=timezone.utc)

    elapsed = (datetime.now(timezone.utc) - last_refresh).total_seconds()
    return max(0, math.ceil(EPSS_REFRESH_COOLDOWN_SECONDS - elapsed))


async def publish_epss_refresh(result: EPSSRefreshResult) -> None:
    """Publish the successful timestamp and result atomically."""
    async with create_redis_client().pipeline(transaction=True) as pipeline:
        pipeline.set(EPSS_LAST_REFRESH_KEY, result.refreshed_at.isoformat())
        pipeline.set(EPSS_LAST_RESULT_KEY, result.model_dump_json())
        pipeline.delete(EPSS_LAST_ERROR_KEY)
        await pipeline.execute()


async def publish_epss_failure(message: str) -> None:
    """Record a safe error summary without replacing the last success time."""
    await create_redis_client().set(EPSS_LAST_ERROR_KEY, message)


async def get_epss_feed_status(total_stored_scores: int) -> EPSSFeedStatus:
    """Read lock and last-success metadata in one Redis round trip."""
    timestamp, result_json, lock, last_error = await create_redis_client().mget(
        EPSS_LAST_REFRESH_KEY,
        EPSS_LAST_RESULT_KEY,
        EPSS_REFRESH_LOCK_KEY,
        EPSS_LAST_ERROR_KEY,
    )

    counts = {
        "requested_count": 0,
        "stored_count": 0,
        "unavailable_count": 0,
    }
    if result_json:
        result = json.loads(result_json)
        counts = {
            "requested_count": int(result.get("requested_count", 0)),
            "stored_count": int(result.get("stored_count", 0)),
            "unavailable_count": int(result.get("unavailable_count", 0)),
        }

    return EPSSFeedStatus(
        last_refreshed_at=timestamp,
        refresh_in_progress=lock is not None,
        total_stored_scores=total_stored_scores,
        last_error=last_error,
        **counts,
    )
