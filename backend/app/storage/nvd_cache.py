"""Redis coordination and status metadata for NVD enrichment.

FILE ROLE
---------
PostgreSQL stores NVD vulnerability data permanently. Redis does not store the
NVD records themselves; it only coordinates refresh jobs and exposes lightweight
operational status to the API/UI.

ARCHITECTURE POSITION
---------------------
NVD service <-> this module <-> Redis
NVD status API -> service -> this module

WHAT THIS FILE OWNS
-------------------
- A cross-process refresh lock so manual and scheduled NVD jobs cannot overlap.
- A short cooldown after a successful batch.
- The last successful batch summary.
- A safe last-error message.

FAILURE MODEL
-------------
If Redis is lost, stored NVD data remains safe in PostgreSQL. Refreshes fail
closed because running an uncoordinated multi-request job is less safe than
waiting for Redis to recover.
"""

import json
import math
from datetime import datetime, timezone
from uuid import uuid4

from app.models.nvd import NVDFeedStatus, NVDRefreshResult
from app.storage.redis import create_redis_client


NVD_REFRESH_LOCK_KEY = "nvd:refresh_lock"
NVD_LAST_REFRESH_KEY = "nvd:last_refresh"
NVD_LAST_RESULT_KEY = "nvd:last_result"
NVD_LAST_ERROR_KEY = "nvd:last_error"

# A bounded batch is capped by the service timeout at five minutes. Give the
# lease one extra minute so another process cannot start just before cleanup.
NVD_REFRESH_LOCK_TTL_SECONDS = 360
NVD_REFRESH_COOLDOWN_SECONDS = 30


async def acquire_nvd_refresh_lock() -> str | None:
    """Acquire a unique, expiring NVD refresh lease using Redis SET NX."""

    token = uuid4().hex
    acquired = await create_redis_client().set(
        NVD_REFRESH_LOCK_KEY,
        token,
        nx=True,
        ex=NVD_REFRESH_LOCK_TTL_SECONDS,
    )
    return token if acquired else None


async def release_nvd_refresh_lock(token: str) -> None:
    """Release the lease only when the supplied token still owns it."""

    await create_redis_client().eval(
        "if redis.call('get', KEYS[1]) == ARGV[1] then "
        "return redis.call('del', KEYS[1]) else return 0 end",
        1,
        NVD_REFRESH_LOCK_KEY,
        token,
    )


async def get_nvd_refresh_cooldown_remaining() -> int:
    """Return seconds remaining before another refresh batch may start."""

    value = await create_redis_client().get(NVD_LAST_REFRESH_KEY)
    if not value:
        return 0

    last_refresh = datetime.fromisoformat(value)
    if last_refresh.tzinfo is None:
        last_refresh = last_refresh.replace(tzinfo=timezone.utc)

    elapsed = (datetime.now(timezone.utc) - last_refresh).total_seconds()
    return max(0, math.ceil(NVD_REFRESH_COOLDOWN_SECONDS - elapsed))


async def publish_nvd_refresh(result: NVDRefreshResult) -> None:
    """Publish a successful bounded-batch summary atomically."""

    async with create_redis_client().pipeline(transaction=True) as pipeline:
        pipeline.set(NVD_LAST_REFRESH_KEY, result.refreshed_at.isoformat())
        pipeline.set(NVD_LAST_RESULT_KEY, result.model_dump_json())
        pipeline.delete(NVD_LAST_ERROR_KEY)
        await pipeline.execute()


async def publish_nvd_failure(message: str) -> None:
    """Record a safe failure summary without overwriting the last success."""

    await create_redis_client().set(NVD_LAST_ERROR_KEY, message)


async def get_nvd_feed_status(
    *,
    total_stored_cves: int,
    total_kev_cves: int,
    pending_count: int,
) -> NVDFeedStatus:
    """Combine Redis refresh metadata with durable PostgreSQL counts."""

    timestamp, result_json, lock, last_error = await create_redis_client().mget(
        NVD_LAST_REFRESH_KEY,
        NVD_LAST_RESULT_KEY,
        NVD_REFRESH_LOCK_KEY,
        NVD_LAST_ERROR_KEY,
    )

    counts = {
        "requested_count": 0,
        "stored_count": 0,
        "unavailable_count": 0,
        "failed_count": 0,
        "remaining_count": pending_count,
    }
    if result_json:
        result = json.loads(result_json)
        counts = {
            "requested_count": int(result.get("requested_count", 0)),
            "stored_count": int(result.get("stored_count", 0)),
            "unavailable_count": int(result.get("unavailable_count", 0)),
            "failed_count": int(result.get("failed_count", 0)),
            "remaining_count": int(result.get("remaining_count", pending_count)),
        }

    return NVDFeedStatus(
        last_refreshed_at=timestamp,
        refresh_in_progress=lock is not None,
        total_stored_cves=total_stored_cves,
        total_kev_cves=total_kev_cves,
        pending_count=pending_count,
        last_error=last_error,
        **counts,
    )
