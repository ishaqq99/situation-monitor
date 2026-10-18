"""Explicit HTTP response contracts for stored OTX evidence and queue status.

Collector models describe downloaded intelligence. These models additionally
describe local refresh state, database observation times, and pagination.
React's types/ioc.ts mirrors these fields; no provider key is part of a response.


FILE GUIDE
----------
WHAT THIS FILE DOES
Specify the JSON structures returned by the stored IOC API.

WHY IT EXISTS
Local job status and historical observation timestamps differ from raw provider data.

WHO CALLS OR IMPORTS IT
app.api.ioc declares these response models; repository and service create instances.

WHAT IT CALLS OR IMPORTS
Embeds selected app.models.ioc evidence; frontend/src/types/ioc.ts mirrors the fields.

ROLE IN THE ARCHITECTURE
HTTP contract layer; it does not perform collection or persistence.
"""
from datetime import datetime
from typing import Literal
from pydantic import BaseModel, Field
from app.models.ioc import IOCObservation, SourceRecordAssessment


class IOCJob(BaseModel):
    """One CVE's schedule. A null last_success_at means no complete check yet.

    summary describes the last result that reached storage. A later failed
    attempt changes state/last_error while retaining that result and evidence.
    """
    cve_id: str
    state: str
    next_check_at: datetime
    last_attempt_at: datetime | None = None
    last_success_at: datetime | None = None
    last_error: str | None = None
    summary: dict | None = None


class IOCProviderStatus(BaseModel):
    """Global coverage plus provider pacing. configured means a key is present,
    not that OTX has verified it. ever_completed is lifetime coverage, not a
    claim that all those CVEs are currently fresh or have any indicators.
    """
    enabled: bool
    configured: bool
    collection_scope: str = "focused_only"
    total_kevs: int
    scheduled_kevs: int
    ever_completed: int
    due_jobs: int
    running_jobs: int
    failed_or_partial: int
    stored_observations: int
    next_allowed_at: datetime | None = None
    heartbeat_at: datetime | None = None
    last_error: str | None = None


class StoredIOC(BaseModel):
    """An observation plus local first/last retrieval times and scope presence.
    These local times are not the first/last time an attacker used the IOC.
    """
    observation: IOCObservation
    first_seen_at: datetime
    last_seen_at: datetime
    absent_since: datetime | None = None
    lifecycle: Literal["active", "inactive", "expired", "unknown", "not_in_latest_scope"]


class IOCPage(BaseModel):
    """One bounded observation page and a preview of report-selection decisions.
    total counts source observations, so the same IOC in two reports counts twice.
    """
    cve_id: str
    job: IOCJob | None
    total: int
    limit: int
    offset: int
    include_history: bool
    observations: list[StoredIOC] = Field(default_factory=list)
    assessments: list[SourceRecordAssessment] = Field(default_factory=list)
    assessment_total: int = 0


class IOCQueueResult(BaseModel):
    """Acceptance/coalescing result. queued=True does not mean collection finished."""
    cve_id: str
    queued: bool
    state: str
    message: str


class IOCRun(BaseModel):
    """Recent attempt summary, preserving failed and partial attempts as well."""
    run_id: str
    started_at: datetime
    finished_at: datetime | None = None
    outcome: str
    summary: dict | None = None
    error: str | None = None
