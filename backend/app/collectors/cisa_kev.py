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


async def fetch_kev_catalog() -> KEVCatalog:
    """Fetch CISA KEV and normalize it into our data model."""

    try:
        raw_data = await download_kev_data(CISA_KEV_URL)
    except (httpx.HTTPError, ValueError):
        raw_data = await download_kev_data(CISA_KEV_FALLBACK_URL)

    vulnerabilities: list[KEVEntry] = []

    for item in raw_data["vulnerabilities"]:
        vulnerability = KEVEntry(
            cve_id=item["cveID"],
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
        key=lambda vulnerability: vulnerability.date_added,
        reverse=True,
    )

    return KEVCatalog(
        catalog_version=raw_data["catalogVersion"],
        date_released=raw_data["dateReleased"],
        total_count=raw_data["count"],
        vulnerabilities=vulnerabilities,
    )