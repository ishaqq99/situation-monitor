"""Provider-neutral IOC models for Situation Monitor.

FILE ROLE
---------
This module defines the common data contracts used by IOC intelligence
collectors. AlienVault OTX is the first provider, but the models are designed
for future ThreatFox, GreyNoise, and other feeds so the rest of the application
does not need a provider-specific schema.

ARCHITECTURE POSITION
---------------------
External threat-intel provider
    -> provider collector (for example ``app.collectors.otx``)
    -> models in this file
    -> IOC service / PostgreSQL repository / FastAPI / React

WHAT THIS FILE OWNS
-------------------
- Canonical IOC types such as IPv4, domain, URL, and SHA256.
- A normalized indicator value.
- The strength/meaning of a CVE-to-IOC relationship.
- One source observation preserving provenance for that relationship.
- One source enrichment result for a requested CVE.

WHY RELATIONSHIP TYPE MATTERS
-----------------------------
Threat-intelligence providers do not all mean the same thing when an IOC and a
CVE appear together. For example, an OTX pulse can contain several CVEs plus a
large list of IPs/hashes/domains. That proves the IOC and CVE share the same
source record, but it does NOT prove the IOC directly exploited that CVE.

Situation Monitor therefore keeps the relationship explicit rather than
silently converting every source match into a strong CVE -> IOC assertion.

CURRENT RELATIONSHIP LEVELS
---------------------------
``pulse_context``
    IOC appears in a broader source record/pulse that OTX associated with the
    requested CVE. This is contextual evidence only.

``cve_associated``
    Reserved for a source that explicitly associates the IOC with the CVE.
    OTX pulse indicators are NOT promoted to this level in Stage 1.3.

``observed_exploitation``
    Reserved for a provider that explicitly reports observed exploitation
    activity involving the IOC and CVE, such as a future GreyNoise connector
    when the provider data supports that statement.

OLD CVE BEHAVIOR
----------------
Nothing in these models limits CVE age. A five-year-old CVE can receive a new
IOC observation today. The IOC scheduler gives every local KEV a recurring
job, without filtering on its publication year or KEV addition date.


FILE GUIDE
----------
WHAT THIS FILE DOES
Define validated, provider-neutral CVE/indicator/report evidence objects.

WHY IT EXISTS
The collector and storage layer need the same precise meaning for each field.

WHO CALLS OR IMPORTS IT
The OTX collector builds these objects; service, repository, and tests consume them.

WHAT IT CALLS OR IMPORTS
Pydantic validates values and serializes them for storage and HTTP responses.

ROLE IN THE ARCHITECTURE
Data-contract layer; it performs no network or database I/O.
"""

from datetime import datetime, timezone
from enum import StrEnum

from pydantic import BaseModel, Field


class IOCType(StrEnum):
    """Canonical IOC types understood by Situation Monitor."""

    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    HOSTNAME = "hostname"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"


class IOCRelationshipType(StrEnum):
    """Describe what a provider actually proved about an IOC and a CVE.

    The values are intentionally semantic rather than provider-specific. Future
    collectors can therefore reuse them without teaching PostgreSQL, the API,
    or the frontend special meanings for every threat-intelligence vendor.
    """

    PULSE_CONTEXT = "pulse_context"
    CVE_ASSOCIATED = "cve_associated"
    OBSERVED_EXPLOITATION = "observed_exploitation"


class SourceRecordRelevance(StrEnum):
    """Conservative review category for a source record, not IOC confidence.

    A focused report still provides *contextual* indicators. Neither a focused
    title nor a single-CVE report proves that its indicators exploited a CVE.
    """

    FOCUSED_CONTEXT = "focused_context"
    BROAD_CONTEXT = "broad_context"
    REVIEW_REQUIRED = "review_required"


class SourceRecordAssessment(BaseModel):
    """Audit-friendly assessment of one OTX pulse before indicator collection.

    The collector returns assessments even when it deliberately skips a broad
    pulse. This prevents a filtered lookup from masquerading as 'zero IOCs at
    the provider'. A successful scoped fetch and a full-provider fetch are
    different operations, recorded in ``CVEIOCEnrichment.collection_scope``.

    ``indicator_count`` counts normalized observations downloaded from this
    record; ``None`` means its indicator endpoint was not fetched or failed.
    This number is not a count of confirmed CVE exploitation indicators.
    """

    source_record_id: str = Field(min_length=1, max_length=200)
    source_record_name: str | None = Field(default=None, max_length=1_000)
    source_record_url: str | None = Field(default=None, max_length=4_096)
    source_record_cve_ids: list[str] = Field(default_factory=list)
    relevance: SourceRecordRelevance
    reason_code: str = Field(min_length=1, max_length=100)
    reason: str = Field(min_length=1, max_length=1_000)
    selected_for_collection: bool = False
    fetched: bool = False
    indicator_count: int | None = Field(default=None, ge=0)


class IOCIndicator(BaseModel):
    """One normalized unique observable such as an IP, domain, URL, or hash.

    ``value`` is the canonical form intended for storage deduplication. Domains
    and hashes are normalized to lower case by collectors; URLs keep their
    path/query casing because rewriting those components can change meaning.
    """

    value: str = Field(min_length=1, max_length=4_096)
    indicator_type: IOCType


class IOCObservation(BaseModel):
    """One provider observation connecting an IOC to CVE-related intelligence.

    ``cve_id``
        The CVE Situation Monitor requested or is correlating.

    ``relationship_type``
        Tells analysts how strong the CVE-to-IOC relationship actually is. An
        OTX pulse-derived IOC is ``pulse_context`` because the pulse may contain
        multiple CVEs and many unrelated/contextual indicators.

    ``source_record_cve_ids``
        CVEs referenced by the source record as far as the collector can safely
        determine. For OTX this includes the requested CVE plus CVEs found in
        pulse metadata. It describes the PULSE context, not a claim that every
        IOC in that pulse belongs directly to every listed CVE.

    Provider timestamps describe the source record, not necessarily the first
    or last time the IOC was malicious on the Internet. ``fetched_at`` is when
    Situation Monitor retrieved the evidence.
    """

    cve_id: str = Field(pattern=r"^CVE-[0-9]{4}-[0-9]{4,}$")
    indicator: IOCIndicator

    relationship_type: IOCRelationshipType
    # Pulse-level relevance is separate from the actual IOC/CVE relationship.
    # Focused context must NOT be mistaken for explicit exploitation evidence.
    source_record_relevance: SourceRecordRelevance = SourceRecordRelevance.REVIEW_REQUIRED
    source_record_cve_ids: list[str] = Field(default_factory=list)

    source: str = Field(min_length=1, max_length=100)
    source_record_id: str = Field(min_length=1, max_length=200)
    source_record_name: str | None = Field(default=None, max_length=1_000)
    source_record_url: str | None = Field(default=None, max_length=4_096)
    source_author: str | None = Field(default=None, max_length=500)
    source_tlp: str | None = Field(default=None, max_length=50)

    source_created_at: datetime | None = None
    source_modified_at: datetime | None = None
    active: bool | None = None
    # OTX's indicator expiration is provider metadata, not an attack timestamp.
    # Missing/unparseable expiration stays unknown. Storage also tracks when
    # Situation Monitor first/last observed this source relationship.
    expires_at: datetime | None = None

    reference_urls: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)

    fetched_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


class CVEIOCEnrichment(BaseModel):
    """Normalized IOC enrichment returned for one CVE from one provider.

    ``complete`` is explicit because a provider may return partial intelligence.
    A partial result can still be useful, but storage and automation must not
    treat it as a complete refresh or as proof that no additional IOCs exist.
    """

    cve_id: str = Field(pattern=r"^CVE-[0-9]{4}-[0-9]{4,}$")
    source: str = Field(min_length=1, max_length=100)

    # 'focused_only' downloads only conservative, title-focused OTX pulses.
    # 'all_pulses' is an explicit exploratory mode; neither mode publishes IOCs.
    collection_scope: str = Field(default="all_pulses", min_length=1)
    source_record_count_reported: int = Field(default=0, ge=0)
    source_record_count_processed: int = Field(default=0, ge=0)
    source_record_count_skipped: int = Field(default=0, ge=0)
    source_record_assessments: list[SourceRecordAssessment] = Field(default_factory=list)
    observation_count: int = Field(default=0, ge=0)
    unique_indicator_count: int = Field(default=0, ge=0)

    complete: bool = True
    warnings: list[str] = Field(default_factory=list)
    observations: list[IOCObservation] = Field(default_factory=list)

    fetched_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
