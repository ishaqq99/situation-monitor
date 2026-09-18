"""FastAPI routes for stored EPSS scores, status, and manual refresh."""

import logging

import asyncpg
import httpx
from fastapi import APIRouter, HTTPException
from redis.exceptions import RedisError

from app.collectors.epss import EPSSResponseError
from app.models.epss import EPSSFeedStatus, EPSSRefreshResult, EPSSScore
from app.services.epss_service import (
    EPSSRefreshCooldownError,
    EPSSRefreshInProgressError,
    EPSSCatalogNotReadyError,
    get_epss_status,
    get_stored_epss_score,
    refresh_epss_data,
)


logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/epss", tags=["FIRST EPSS"])


@router.get("/status", response_model=EPSSFeedStatus)
async def get_feed_status():
    try:
        return await get_epss_status()
    except Exception as exc:
        logger.exception("Unable to read EPSS status")
        raise HTTPException(503, "EPSS status is temporarily unavailable") from exc


@router.post("/refresh", response_model=EPSSRefreshResult)
async def refresh_epss_scores():
    try:
        return await refresh_epss_data()
    except EPSSRefreshInProgressError as exc:
        raise HTTPException(409, str(exc)) from exc
    except EPSSCatalogNotReadyError as exc:
        raise HTTPException(409, str(exc)) from exc
    except EPSSRefreshCooldownError as exc:
        raise HTTPException(
            429,
            str(exc),
            headers={"Retry-After": str(exc.retry_after)},
        ) from exc
    except (TimeoutError, httpx.TimeoutException) as exc:
        logger.exception("EPSS refresh timed out")
        raise HTTPException(504, "EPSS refresh timed out; please retry later") from exc
    except (httpx.HTTPError, EPSSResponseError) as exc:
        logger.exception("FIRST EPSS request failed")
        raise HTTPException(502, "Unable to retrieve EPSS data from FIRST") from exc
    except (asyncpg.PostgresError, RedisError, OSError) as exc:
        logger.exception("EPSS database operation failed")
        raise HTTPException(503, "EPSS storage is temporarily unavailable") from exc
    except Exception as exc:
        logger.exception("EPSS refresh failed")
        raise HTTPException(500, "EPSS refresh failed") from exc


# Static routes appear above this dynamic route so "status" and "refresh"
# cannot be interpreted as CVE identifiers.
@router.get("/{cve_id}", response_model=EPSSScore)
async def get_single_epss_score(cve_id: str):
    try:
        score = await get_stored_epss_score(cve_id)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    except asyncpg.PostgresError as exc:
        logger.exception("EPSS lookup failed")
        raise HTTPException(503, "EPSS storage is temporarily unavailable") from exc
    except Exception as exc:
        logger.exception("EPSS stored-score lookup failed")
        raise HTTPException(503, "EPSS storage is temporarily unavailable") from exc

    if score is None:
        raise HTTPException(404, f"No stored EPSS score exists for {cve_id.upper()}")
    return score
