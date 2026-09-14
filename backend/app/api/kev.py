from fastapi import APIRouter, HTTPException, Query

from app.models.kev import KEVEntry, KEVRefreshResult
from app.services.kev_service import (
    get_latest_kev,
    refresh_kev_data,
)


# This creates the router object that main.py imports.
router = APIRouter(
    prefix="/api/kev",
    tags=["CISA KEV"],
)


@router.get("", response_model=list[KEVEntry])
async def get_kev_entries(
    limit: int = Query(default=20, ge=1, le=50)
):
    """
    Return current/latest KEVs.
    The service layer checks Redis first, then PostgreSQL.
    """

    try:
        return await get_latest_kev(limit)

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail="Unable to retrieve stored KEV data",
        ) from exc


@router.post(
    "/refresh",
    response_model=KEVRefreshResult,
)
async def refresh_kev_catalog():
    """
    Fetch the current CISA KEV catalog and update
    PostgreSQL and Redis.
    """

    try:
        return await refresh_kev_data()

    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail="Unable to refresh CISA KEV data",
        ) from exc