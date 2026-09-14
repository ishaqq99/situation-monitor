
from app.collectors.cisa_kev import fetch_kev_catalog
from app.models.kev import KEVEntry, KEVRefreshResult
from app.storage.kev_cache import (
    cache_kev_entries,
    get_cached_kev_entries,
)
from app.storage.kev_repository import (
    get_latest_kev_entries,
    upsert_kev_entries,
)


KEV_CACHE_SIZE = 50


async def refresh_kev_data() -> KEVRefreshResult:
    """
    Run the complete Day 3 ingestion pipeline:
    CISA -> normalize -> PostgreSQL -> Redis.
    """

    catalog = await fetch_kev_catalog()

    stored_count = await upsert_kev_entries(
        catalog.vulnerabilities
    )

    latest_entries = catalog.vulnerabilities[:KEV_CACHE_SIZE]

    await cache_kev_entries(latest_entries)

    return KEVRefreshResult(
        fetched_count=len(catalog.vulnerabilities),
        stored_count=stored_count,
        cached_count=len(latest_entries),
    )


async def get_latest_kev(limit: int = 20) -> list[KEVEntry]:
    """
    Return latest KEVs using cache-aside behavior.

    Read order:
    1. Redis
    2. PostgreSQL
    3. CISA only if both local stores are empty
    """

    cached_entries = await get_cached_kev_entries()

    if cached_entries:
        return cached_entries[:limit]

    database_entries = await get_latest_kev_entries(
        limit=KEV_CACHE_SIZE
    )

    if database_entries:
        await cache_kev_entries(database_entries)
        return database_entries[:limit]

    await refresh_kev_data()

    cached_entries = await get_cached_kev_entries()

    return cached_entries[:limit]
