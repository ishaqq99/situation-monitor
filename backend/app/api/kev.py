"""HTTP boundary for all five KEV endpoints.

The service owns ingestion and storage decisions. This module validates HTTP
inputs, declares response contracts, and maps failures to safe HTTP errors.
"""
import logging
from fastapi import APIRouter, HTTPException, Query
from app.models.kev import KEVEntry, KEVFeedStatus, KEVRefreshResult
from app.services.kev_service import (
    KEVRefreshCooldownError, KEVRefreshInProgressError,
    get_kev_details, get_kev_status, get_latest_kev, refresh_kev_data, search_kev,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/kev", tags=["CISA KEV"])


@router.get("", response_model=list[KEVEntry])
async def get_kev_entries(limit: int = Query(default=20, ge=1, le=50)):
    try:
        return await get_latest_kev(limit)
    except Exception as exc:
        logger.exception("Unable to read KEV data")
        raise HTTPException(503, "Unable to retrieve stored KEV data") from exc


@router.get("/status", response_model=KEVFeedStatus)
async def get_feed_status():
    try:
        return await get_kev_status()
    except Exception as exc:
        logger.exception("Unable to read KEV status")
        raise HTTPException(503, "KEV status is temporarily unavailable") from exc


@router.post("/refresh", response_model=KEVRefreshResult)
async def refresh_kev_catalog():
    try:
        return await refresh_kev_data()
    except KEVRefreshInProgressError as exc:
        raise HTTPException(409, str(exc)) from exc
    except KEVRefreshCooldownError as exc:
        raise HTTPException(429, str(exc), headers={"Retry-After": str(exc.retry_after)}) from exc
    except TimeoutError as exc:
        logger.exception("KEV refresh timed out")
        raise HTTPException(504, "KEV refresh timed out; please retry later") from exc
    except Exception as exc:
        logger.exception("KEV refresh failed")
        raise HTTPException(502, "Unable to refresh CISA KEV data") from exc


# Static routes precede /{cve_id}, so 'status' and 'search' are never CVE IDs.
@router.get("/search", response_model=list[KEVEntry])
async def search_kev_catalog(
    q: str = Query(min_length=1, max_length=100),
    limit: int = Query(default=50, ge=1, le=100),
):
    try:
        return await search_kev(q, limit)
    except Exception as exc:
        logger.exception("KEV search failed")
        raise HTTPException(503, "Unable to search KEV data") from exc


@router.get("/{cve_id}", response_model=KEVEntry)
async def get_single_kev(cve_id: str):
    try:
        entry = await get_kev_details(cve_id)
    except Exception as exc:
        logger.exception("KEV detail lookup failed")
        raise HTTPException(503, "Unable to retrieve CVE details") from exc
    if entry is None:
        raise HTTPException(404, f"{cve_id.upper()} was not found in the CISA KEV catalog")
    return entry
