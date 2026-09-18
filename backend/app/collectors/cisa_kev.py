import httpx

from app.models.kev import KEVCatalog, KEVEntry


CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

CISA_KEV_FALLBACK_URL = (
    "https://raw.githubusercontent.com/"
    "cisagov/kev-data/develop/"
    "known_exploited_vulnerabilities.json"
)


async def download_kev_data(url: str) -> dict:
    """Download raw KEV JSON from the provided URL."""

    headers = {
        "User-Agent": "Situation-Monitor/0.1"
    }

    async with httpx.AsyncClient(
        timeout=30.0,
        follow_redirects=True,
        headers=headers,
    ) as client:
        response = await client.get(url)
        response.raise_for_status()
        return response.json()


def normalize_kev_catalog(raw_data: dict) -> KEVCatalog:
    """Validate the whole feed before any storage writes are permitted."""
    vulnerabilities: list[KEVEntry] = []

    for item in raw_data["vulnerabilities"]:
        vulnerability = KEVEntry(
            cve_id=item["cveID"].strip().upper(),
            vendor_project=item["vendorProject"],
            product=item["product"],
            vulnerability_name=item["vulnerabilityName"],
            date_added=item["dateAdded"],
            due_date=item["dueDate"],
            short_description=item["shortDescription"],
            required_action=item["requiredAction"],
            known_ransomware_campaign_use=item.get(
                "knownRansomwareCampaignUse",
                "Unknown",
            ),
            notes=item.get("notes", ""),
            cwes=item.get("cwes", []),
        )

        vulnerabilities.append(vulnerability)

    vulnerabilities.sort(
        key=lambda vulnerability: (vulnerability.date_added, vulnerability.cve_id),
        reverse=True,
    )

    catalog = KEVCatalog(
        catalog_version=raw_data["catalogVersion"],
        date_released=raw_data["dateReleased"],
        total_count=raw_data["count"],
        vulnerabilities=vulnerabilities,
    )
    identifiers = {entry.cve_id for entry in vulnerabilities}
    if not vulnerabilities or catalog.total_count != len(vulnerabilities):
        raise ValueError("CISA catalog count is empty or inconsistent")
    if len(identifiers) != len(vulnerabilities):
        raise ValueError("CISA catalog contains duplicate CVE IDs")
    return catalog


async def fetch_kev_catalog() -> KEVCatalog:
    """Try CISA first and its official mirror if downloading or validation fails."""
    try:
        return normalize_kev_catalog(await download_kev_data(CISA_KEV_URL))
    except (httpx.HTTPError, ValueError, KeyError, TypeError, AttributeError):
        return normalize_kev_catalog(await download_kev_data(CISA_KEV_FALLBACK_URL))
