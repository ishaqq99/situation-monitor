from datetime import date, datetime

from pydantic import BaseModel, Field


class KEVEntry(BaseModel):
    """
    One normalized CISA Known Exploited Vulnerability.
    """

    cve_id: str
    vendor_project: str
    product: str
    vulnerability_name: str
    date_added: date
    due_date: date
    short_description: str
    required_action: str
    known_ransomware_campaign_use: str = "Unknown"
    notes: str = ""
    cwes: list[str] = Field(default_factory=list)


class KEVCatalog(BaseModel):
    """
    Full normalized catalog returned by the CISA collector.
    """

    catalog_version: str
    date_released: str
    total_count: int
    vulnerabilities: list[KEVEntry]


class KEVRefreshResult(BaseModel):
    """
    Summary returned after a successful CISA refresh.
    """

    fetched_count: int
    stored_count: int
    cached_count: int
    refreshed_at: datetime


class KEVFeedStatus(BaseModel):
    """
    Small feed-status object used by React.
    """

    last_refreshed_at: datetime | None = None
    refresh_in_progress: bool
    cached_entries: int