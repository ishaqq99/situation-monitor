"""FastAPI routes for stored NVD enrichment, CVSS history, and refresh status.

FILE ROLE
---------
This module is the HTTP boundary for NVD. Routes translate HTTP requests into
service calls and map predictable failures to safe HTTP status codes.

IMPORTANT READ BEHAVIOR
-----------------------
``GET /api/nvd/{cve_id}`` and the history endpoint read PostgreSQL only. Opening
a CVE in React never makes the browser wait for a live NVD request.
"""

import logging

import asyncpg
import httpx
from fastapi import APIRouter, HTTPException, Query
from redis.exceptions import RedisError

from app.collectors.nvd import NVDResponseError
from app.models.nvd import NVDCVE, NVDCVSSChange, NVDFeedStatus, NVDRefreshResult
from app.services.nvd_service import (
    NVDCatalogNotReadyError,
    NVDProviderRateLimitError,
    NVDRefreshCooldownError,
    NVDRefreshInProgressError,
    get_nvd_status,
    get_stored_nvd_cve,
    get_stored_nvd_history,
    refresh_nvd_data,
)


logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/nvd", tags=["NVD Enrichment"])


@router.get("/status", response_model=NVDFeedStatus)
async def get_feed_status():
    """Return durable coverage counts plus Redis refresh state."""

    try:
        return await get_nvd_status()
    except Exception as exc:
        logger.exception("Unable to read NVD status")
        raise HTTPException(503, "NVD status is temporarily unavailable") from exc


@router.post("/refresh", response_model=NVDRefreshResult)
async def refresh_nvd_enrichment():
    """Process one protected, rate-paced NVD enrichment batch."""

    try:
        return await refresh_nvd_data()
    except NVDRefreshInProgressError as exc:
        raise HTTPException(409, str(exc)) from exc
    except NVDCatalogNotReadyError as exc:
        raise HTTPException(409, str(exc)) from exc
    except NVDRefreshCooldownError as exc:
        raise HTTPException(
            429,
            str(exc),
            headers={"Retry-After": str(exc.retry_after)},
        ) from exc
    except NVDProviderRateLimitError as exc:
        raise HTTPException(
            429,
            str(exc),
            headers={"Retry-After": str(exc.retry_after)},
        ) from exc
    except (TimeoutError, httpx.TimeoutException) as exc:
        logger.exception("NVD refresh timed out")
        raise HTTPException(504, "NVD refresh timed out; please retry later") from exc
    except (httpx.HTTPError, NVDResponseError) as exc:
        logger.exception("NVD provider request failed")
        raise HTTPException(502, "Unable to retrieve NVD data") from exc
    except (asyncpg.PostgresError, RedisError, OSError) as exc:
        logger.exception("NVD storage/coordination operation failed")
        raise HTTPException(503, "NVD storage is temporarily unavailable") from exc
    except Exception as exc:
        logger.exception("NVD refresh failed")
        raise HTTPException(500, "NVD refresh failed") from exc


# This route is declared before /{cve_id} so FastAPI never interprets the word
# "history" as part of a different static path.
@router.get("/{cve_id}/history", response_model=list[NVDCVSSChange])
async def get_cvss_history(
    cve_id: str,
    limit: int = Query(default=20, ge=1, le=100),
):
    """Return newest-first selected-CVSS changes for one stored CVE."""

    try:
        return await get_stored_nvd_history(cve_id, limit)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    except asyncpg.PostgresError as exc:
        logger.exception("NVD history lookup failed")
        raise HTTPException(503, "NVD storage is temporarily unavailable") from exc
    except Exception as exc:
        logger.exception("NVD history lookup failed")
        raise HTTPException(503, "NVD storage is temporarily unavailable") from exc


@router.get("/{cve_id}", response_model=NVDCVE)
async def get_single_nvd_cve(cve_id: str):
    """Return current locally stored NVD enrichment for one CVE."""

    try:
        record = await get_stored_nvd_cve(cve_id)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    except asyncpg.PostgresError as exc:
        logger.exception("NVD lookup failed")
        raise HTTPException(503, "NVD storage is temporarily unavailable") from exc
    except Exception as exc:
        logger.exception("NVD stored-record lookup failed")
        raise HTTPException(503, "NVD storage is temporarily unavailable") from exc

    if record is None:
        raise HTTPException(404, f"No stored NVD enrichment exists for {cve_id.upper()}")
    return record
