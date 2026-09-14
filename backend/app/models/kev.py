from datetime import date

from pydantic import BaseModel, Field


class KEVEntry(BaseModel):
    """
    One normalized KEV vulnerability.
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
    Represents the complete normalized CISA KEV catalog.
    """

    catalog_version: str
    date_released: str
    total_count: int

    vulnerabilities: list[KEVEntry]


class KEVRefreshResult(BaseModel):
    """
    Represents the result of refreshing CISA data
    into PostgreSQL and Redis.
    """

    fetched_count: int
    stored_count: int
    cached_count: int