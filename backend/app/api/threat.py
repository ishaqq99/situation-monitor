"""Public, read-only threat summary route.

FastAPI imports this router from app.main. It calls the service, which reads a
cached Cloudflare Radar snapshot. The route neither triggers a manual refresh
nor exposes a provider credential or internal worker status.
"""

import logging

from fastapi import APIRouter, HTTPException

from app.services.threat_service import ThreatFeedUnavailable, get_threat_snapshot


router = APIRouter(prefix="/api/threat", tags=["Threat overview"])
logger = logging.getLogger(__name__)


@router.get("/overview")
async def threat_overview() -> dict:
    """Return a recent country summary for the globe and nearby ranked list."""
    try:
        return await get_threat_snapshot()
    except ThreatFeedUnavailable as exc:
        raise HTTPException(503, "Threat overview is temporarily unavailable") from exc
    except Exception as exc:
        logger.exception("Threat overview storage or provider failure")
        raise HTTPException(503, "Threat overview is temporarily unavailable") from exc
