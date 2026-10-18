"""Validated models shared by every NVD layer in Situation Monitor.

FILE ROLE
---------
This module defines the stable application contracts for NVD enrichment. The
collector converts raw NVD JSON into these models; PostgreSQL stores equivalent
fields; FastAPI returns the same shapes; React mirrors them with TypeScript.

ARCHITECTURE POSITION
---------------------
NVD API -> app.collectors.nvd -> models in this file -> repository/service
                                                -> FastAPI -> React

WHAT THIS FILE OWNS
-------------------
- The current selected CVSS assessment for one CVE.
- The current normalized NVD record for one KEV CVE.
- The result/status objects used by scheduled and manual NVD refreshes.
- CVSS change-history objects used to explain how an NVD assessment changed.

WHAT THIS FILE DOES NOT DO
--------------------------
- It does not call NVD.
- It does not execute SQL.
- It does not use Redis.
- It does not decide when a refresh should run.

WHY HISTORY IS A SEPARATE MODEL
-------------------------------
``NVDCVE`` represents the newest known state. ``NVDCVSSChange`` represents a
past transition such as 9.8 -> 7.5. Keeping current state and history separate
lets normal CVE detail reads stay fast while still preserving analyst context.
"""

from datetime import datetime, timezone

from pydantic import BaseModel, Field, field_validator


def normalize_nvd_timestamp(value: datetime) -> datetime:
    """Return one NVD timestamp as an offset-aware UTC datetime.

    Why this function exists
    ------------------------
    NVD CVE API responses can contain date strings without a timezone suffix.
    Pydantic parses those strings as offset-naive ``datetime`` objects, whereas
    PostgreSQL TIMESTAMPTZ values returned by asyncpg are offset-aware. Python
    cannot compare the two kinds directly.

    Our NVD integration interprets an offset-less NVD date as UTC. A date that
    already has an offset is converted to the equivalent UTC instant instead
    of simply replacing its timezone. This function does no database I/O.

    Called by
    ---------
    ``NVDCVE._timestamps_in_utc`` validates incoming and stored model values.
    ``app.storage.nvd_repository.upsert_nvd_cve`` also uses it defensively when
    comparing a row from a database created with an older timestamp schema.
    """

    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


class NVDCVSSMetric(BaseModel):
    """One normalized CVSS assessment selected for display and storage.

    Inputs
    ------
    Values come from one NVD metric entry, for example ``cvssMetricV40`` or
    ``cvssMetricV31``.

    Important fields
    ----------------
    ``source`` and ``metric_type`` are preserved because the selected score may
    be authored by NVD or another organization. Situation Monitor must not
    present two different assessors' numbers as if they were the same score.

    Missing values
    --------------
    Exploitability and impact subscores are optional because not every CVSS
    version/provider supplies them in the same way.
    """

    cvss_version: str = Field(min_length=1)
    base_score: float = Field(ge=0.0, le=10.0, allow_inf_nan=False)
    base_severity: str | None = None
    vector_string: str = Field(min_length=1)
    source: str | None = None
    metric_type: str | None = None
    exploitability_score: float | None = Field(
        default=None,
        ge=0.0,
        allow_inf_nan=False,
    )
    impact_score: float | None = Field(
        default=None,
        ge=0.0,
        allow_inf_nan=False,
    )


class NVDCVE(BaseModel):
    """Current normalized NVD enrichment for one locally tracked KEV CVE.

    Data represented
    ----------------
    - CVE identity and NVD lifecycle timestamps.
    - Human-readable description.
    - Preferred current CVSS assessment, when one exists.
    - CWE identifiers.
    - Vulnerable CPE criteria.
    - Reference URLs.
    - ``fetched_at``: when Situation Monitor observed this NVD state.

    ``cvss`` is optional intentionally. A valid NVD CVE may temporarily have no
    usable CVSS assessment. Missing CVSS must remain ``None`` rather than being
    misrepresented as a score of 0.0.
    """

    cve_id: str = Field(pattern=r"^CVE-[0-9]{4}-[0-9]{4,}$")
    source_identifier: str | None = None
    published_at: datetime
    last_modified_at: datetime
    vuln_status: str | None = None
    description: str | None = None
    cvss: NVDCVSSMetric | None = None
    cwes: list[str] = Field(default_factory=list)
    affected_cpes: list[str] = Field(default_factory=list)
    reference_urls: list[str] = Field(default_factory=list)
    fetched_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    @field_validator("published_at", "last_modified_at", "fetched_at")
    @classmethod
    def _timestamps_in_utc(cls, value: datetime) -> datetime:
        """Normalize all NVD lifecycle dates before service/storage use.

        The collector constructs this model from NVD JSON. The repository also
        constructs it when reading an asyncpg row. Keeping this rule in the
        shared model prevents either path from creating a naive/aware pair.
        """

        return normalize_nvd_timestamp(value)


class NVDCVSSChange(BaseModel):
    """One observed transition between two selected CVSS assessments.

    Example
    -------
    A CVE previously stored with CVSS 3.1 score 9.8 is later returned by NVD
    with score 7.5. The current row becomes 7.5 and this history object records
    the old/new assessments plus when Situation Monitor observed the change.

    Either side may be ``None``. That supports cases where CVSS is newly added
    to a CVE or disappears from the selected provider state.
    """

    cve_id: str = Field(pattern=r"^CVE-[0-9]{4}-[0-9]{4,}$")
    observed_at: datetime
    nvd_last_modified_at: datetime
    previous_cvss: NVDCVSSMetric | None = None
    current_cvss: NVDCVSSMetric | None = None


class NVDRefreshResult(BaseModel):
    """Summary of one bounded NVD enrichment batch.

    A refresh intentionally processes a configurable batch rather than every
    KEV in one request cycle. This keeps manual requests bounded and lets the
    background worker gradually complete a large first-time backfill without
    violating NVD request limits.
    """

    requested_count: int = Field(ge=0)
    stored_count: int = Field(ge=0)
    unavailable_count: int = Field(ge=0)
    failed_count: int = Field(ge=0)
    remaining_count: int = Field(ge=0)
    refreshed_at: datetime


class NVDFeedStatus(BaseModel):
    """Operational status shown by the dashboard's NVD status panel."""

    last_refreshed_at: datetime | None = None
    refresh_in_progress: bool
    requested_count: int = Field(default=0, ge=0)
    stored_count: int = Field(default=0, ge=0)
    unavailable_count: int = Field(default=0, ge=0)
    failed_count: int = Field(default=0, ge=0)
    remaining_count: int = Field(default=0, ge=0)
    total_stored_cves: int = Field(default=0, ge=0)
    total_kev_cves: int = Field(default=0, ge=0)
    pending_count: int = Field(default=0, ge=0)
    last_error: str | None = None
