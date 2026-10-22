"""Read a country-level threat summary from Cloudflare Radar.

ROLE
----
The public dashboard calls our FastAPI route, which calls this service. This
service owns the Cloudflare token, validates the provider response, and caches
one snapshot in Redis. Browsers never receive the token or contact Radar.

The data describes the *share of Cloudflare-mitigated HTTP requests by source
IP country* in the last day. It is not a count of attacks, an attacker home
location, or evidence linked to any particular CVE. Country coordinates are
added separately by the frontend solely to place summary markers on its map.
"""

import asyncio
import json
import logging
import math
import os
from datetime import datetime, timezone

import httpx

from app.storage.redis import create_redis_client


logger = logging.getLogger(__name__)
RADAR_URL = "https://api.cloudflare.com/client/v4/radar/attacks/layer7/top/locations/origin"
FRESH_KEY = "threat:radar:origin:1d:fresh"
STALE_KEY = "threat:radar:origin:1d:stale"
FRESH_SECONDS = 1800  # At most one provider request per 30 minutes per API process.
STALE_SECONDS = 86400  # Show the last real snapshot if Radar briefly fails.
_fetch_lock = asyncio.Lock()


class ThreatFeedUnavailable(Exception):
    """Raised when there is no usable current or previously cached snapshot."""


def _normalize(body: dict) -> dict:
    """Check the Radar response and keep only fields used by the public UI.

    Called by ``get_threat_snapshot`` after a successful HTTP response. The
    narrow output prevents the frontend from depending on provider internals
    and rejects malformed or out-of-range percentage values.
    """
    if body.get("success") is not True:
        raise ValueError("Radar reported an unsuccessful response")
    result = body["result"]
    meta = result["meta"]
    if meta.get("normalization") != "PERCENTAGE":
        raise ValueError("Unexpected Radar normalization")
    date_range = meta["dateRange"][0]
    rows = result["top_0"]
    if not isinstance(rows, list):
        raise ValueError("Radar country list is missing")

    countries = []
    for row in rows[:20]:
        code = row.get("originCountryAlpha2")
        name = row.get("originCountryName")
        value = float(row["value"])
        if (not isinstance(code, str) or len(code) != 2
                or not code.isalpha() or not isinstance(name, str)
                or not math.isfinite(value) or not 0 <= value <= 100):
            continue
        countries.append({
            "country_code": code.upper(),
            "country_name": name[:100],
            "percentage": value,
            "rank": int(row["rank"]),
        })

    return {
        "source": "Cloudflare Radar",
        "metric": "Share of mitigated HTTP requests by source IP country",
        "window_start": date_range["startTime"],
        "window_end": date_range["endTime"],
        "source_updated_at": meta.get("lastUpdated"),
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "stale": False,
        "countries": countries,
    }


async def get_threat_snapshot() -> dict:
    """Return a Redis-cached snapshot, fetching Radar only when it expires.

    Called by the GET-only threat route. The lock coalesces simultaneous
    requests in this API process. A second, longer-lived Redis copy lets the
    public page show dated real data during a temporary provider failure.
    """
    token = os.getenv("RADAR_API_TOKEN", "").strip()
    if not token:
        raise ThreatFeedUnavailable("Radar is not configured")

    cache = create_redis_client()
    cached = await cache.get(FRESH_KEY)
    if cached:
        return json.loads(cached)

    async with _fetch_lock:
        cached = await cache.get(FRESH_KEY)
        if cached:
            return json.loads(cached)
        try:
            async with httpx.AsyncClient(timeout=12.0) as client:
                response = await client.get(
                    RADAR_URL,
                    params={"dateRange": "1d", "limit": 20, "format": "JSON"},
                    headers={"Authorization": f"Bearer {token}"},
                )
                response.raise_for_status()
            snapshot = _normalize(response.json())
            serialized = json.dumps(snapshot)
            await cache.set(FRESH_KEY, serialized, ex=FRESH_SECONDS)
            await cache.set(STALE_KEY, serialized, ex=STALE_SECONDS)
            return snapshot
        except (httpx.HTTPError, ValueError, KeyError, TypeError, IndexError) as exc:
            # Do not put a provider error or token into the public response.
            logger.warning("Cloudflare Radar fetch failed: %s", type(exc).__name__)
            old = await cache.get(STALE_KEY)
            if old:
                return {**json.loads(old), "stale": True}
            raise ThreatFeedUnavailable("No Radar snapshot is available") from exc
