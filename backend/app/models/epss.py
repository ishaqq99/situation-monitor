"""Pydantic models shared by the EPSS collector, storage, API, and frontend.

FILE ROLE
---------
This file defines the validated shapes used by every EPSS layer. It does not
perform HTTP requests, run SQL, or schedule background work.

DATA FLOW
---------
FIRST response -> EPSSScore -> PostgreSQL -> FastAPI -> React
"""

from datetime import date, datetime

from pydantic import BaseModel, Field


class EPSSScore(BaseModel):
    """One CVE's EPSS probability and percentile for a particular day."""

    cve_id: str = Field(pattern=r"^CVE-[0-9]{4}-[0-9]{4,}$")
    epss_score: float = Field(ge=0.0, le=1.0, allow_inf_nan=False)
    percentile: float = Field(ge=0.0, le=1.0, allow_inf_nan=False)
    score_date: date


class EPSSRefreshResult(BaseModel):
    """Summary of one successful scheduled or manual EPSS refresh."""

    requested_count: int = Field(ge=0)
    stored_count: int = Field(ge=0)
    unavailable_count: int = Field(ge=0)
    refreshed_at: datetime


class EPSSFeedStatus(BaseModel):
    """Operational state displayed by the dashboard."""

    last_refreshed_at: datetime | None = None
    refresh_in_progress: bool
    requested_count: int = Field(default=0, ge=0)
    stored_count: int = Field(default=0, ge=0)
    unavailable_count: int = Field(default=0, ge=0)
    total_stored_scores: int = Field(default=0, ge=0)
    last_error: str | None = None
