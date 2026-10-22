"""FastAPI boundary for OTX V1: stored reads and asynchronous refresh requests.

GET routes do not contact OTX. POST returns 202 after queueing; the worker owns
the expensive collection. Static /status comes before /{cve_id}. Limit/offset
validation keeps each browser response bounded. This follows the application's
existing local-development access model; expose it publicly only with auth.


FILE GUIDE
----------
WHAT THIS FILE DOES
Offer stored OTX status, CVE evidence, run history, and a refresh queue endpoint.

WHY IT EXISTS
HTTP validation and response codes should stay separate from provider/database policy.

WHO CALLS OR IMPORTS IT
app.main registers this router; frontend/src/api/ioc.ts calls its routes.

WHAT IT CALLS OR IMPORTS
Calls app.services.ioc_service and returns app.models.ioc_api response objects.

ROLE IN THE ARCHITECTURE
FastAPI transport boundary; GET never performs a provider lookup.
"""
from fastapi import APIRouter, HTTPException, Query
from pydantic import ValidationError
from app.models.ioc_api import IOCPage, IOCProviderStatus, IOCQueueResult, IOCRun
from app.services.ioc_service import (
    get_ioc_status, get_stored_iocs, get_ioc_runs, request_ioc_refresh, IOCDisabledError,
)

router = APIRouter(prefix="/api/ioc", tags=["AlienVault OTX"])


def as_http_error(exc: Exception) -> HTTPException:
    """Map known input/not-found errors; hide database and provider internals.

    Function detail: Called by route exception handlers. Input errors become 400, absent
      KEVs become 404, and unsafe internal details become a generic 503.
    """
    if isinstance(exc, ValidationError):
        return HTTPException(503, "Stored OTX data could not be validated.")
    if isinstance(exc, ValueError):
        return HTTPException(400, "Enter a valid CVE identifier.")
    if isinstance(exc, LookupError):
        return HTTPException(404, "CVE is not in the local KEV catalog.")
    return HTTPException(503, "Stored OTX data is temporarily unavailable.")


@router.get("/status", response_model=IOCProviderStatus)
async def status():
    """Read global enabled/configured state, job coverage, and provider cooldown.

    Function detail: Called by IocStatusPanel through GET /api/ioc/status. It asks the
      service for persisted coverage and never contacts OTX.
    """
    try:
        return await get_ioc_status()
    except Exception as exc:
        raise as_http_error(exc) from exc


@router.get("/public/{cve_id}")
async def public_details(cve_id: str, limit: int = Query(25, ge=1, le=100),
                         offset: int = Query(0, ge=0, le=1_000_000),
                         include_history: bool = False):
    """Return evidence without queue, job, or provider-configuration fields.

    Public Nginx permits this read route but blocks the operator IOC routes.
    It uses the same stored-data service, then narrows the result before HTTP.
    """
    try:
        page = await get_stored_iocs(cve_id, limit, offset, include_history)
        return {
            "cve_id": page.cve_id,
            "total": page.total,
            "limit": page.limit,
            "offset": page.offset,
            "include_history": page.include_history,
            "observations": page.observations,
            # Keep the existing frontend contract, with no operational content.
            "job": None,
            "assessments": [],
            "assessment_total": 0,
        }
    except Exception as exc:
        raise as_http_error(exc) from exc


@router.get("/{cve_id}", response_model=IOCPage)
async def details(cve_id: str, limit: int = Query(25, ge=1, le=100),
                  offset: int = Query(0, ge=0, le=1_000_000), include_history: bool = False):
    """Read one observation page, local job state, and a pulse-assessment preview.

    Function detail: Called when a KEV detail opens or refreshes its view. Query bounds
      protect the browser and database from unbounded pages.
    """
    try:
        return await get_stored_iocs(cve_id, limit, offset, include_history)
    except Exception as exc:
        raise as_http_error(exc) from exc


@router.get("/{cve_id}/runs", response_model=list[IOCRun])
async def runs(cve_id: str, limit: int = Query(10, ge=1, le=50)):
    """Return recent refresh outcomes, including failures and partial attempts.

    Function detail: Called by IocPanel to distinguish a genuine empty result from a failed
      attempt. Returns stored history only.
    """
    try:
        return await get_ioc_runs(cve_id, limit)
    except Exception as exc:
        raise as_http_error(exc) from exc


@router.post("/{cve_id}/refresh", response_model=IOCQueueResult, status_code=202)
async def refresh(cve_id: str):
    """Enqueue/coalesce a refresh; a 202 means accepted, not collected already.

    Function detail: Called by the IocPanel button. It queues work and immediately returns
      HTTP 202; the background worker collects later.
    """
    try:
        return await request_ioc_refresh(cve_id)
    except IOCDisabledError as exc:
        raise HTTPException(503, "Enable OTX and configure its API key before requesting refreshes.") from exc
    except Exception as exc:
        raise as_http_error(exc) from exc
