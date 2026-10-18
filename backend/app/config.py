"""Validated environment settings shared by API, storage, collectors, and workers.

FILE ROLE
---------
All long-lived tuning values are read here once when the backend starts. That
keeps environment parsing out of collectors/services and gives one obvious
place to document refresh cadence and request pacing.

NVD NOTES
---------
NVD enrichment is intentionally KEV-centered. The worker processes a bounded
batch of KEVs that are missing NVD data or whose stored NVD record has become
stale. ``NVD_API_KEY`` is optional, but an API key allows a much faster initial
backfill. Request pacing remains sequential even when a key is configured.


FILE GUIDE
----------
WHAT THIS FILE DOES
Read and validate environment settings for KEV, EPSS, NVD, and OTX.

WHY IT EXISTS
One settings module prevents collectors and workers from parsing the same values differently.

WHO CALLS OR IMPORTS IT
Backend routes, services, collectors, and workers import its constants.

WHAT IT CALLS OR IMPORTS
Reads process environment and the existing private root .env through dotenv.

ROLE IN THE ARCHITECTURE
Configuration boundary; it neither contacts providers nor stores data.
"""

import os
import math
from pathlib import Path

from dotenv import load_dotenv


# backend/app/config.py -> backend/app -> backend -> project root
load_dotenv(Path(__file__).resolve().parents[2] / ".env")


def positive_int(name: str, default: int) -> int:
    """Read a positive integer setting and fail early on invalid values.

    Function detail: Called while this module loads. Returns a strictly positive integer or
      raises ValueError before any worker starts.
    """
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError as exc:
        raise ValueError(f"{name} must be a positive integer") from exc
    if value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


def positive_float(name: str, default: float) -> float:
    """Read a positive floating-point setting and fail early on invalid values.

    Function detail: Called for pacing/deadline settings. Rejects zero, negative, and non-
      finite values so retry calculations remain meaningful.
    """
    try:
        value = float(os.getenv(name, str(default)))
    except ValueError as exc:
        raise ValueError(f"{name} must be a positive number") from exc
    if not math.isfinite(value) or value <= 0:
        raise ValueError(f"{name} must be a positive finite number")
    return value


DATABASE_URL = os.getenv("DATABASE_URL", "")
REDIS_URL = os.getenv("REDIS_URL", "")

# CISA changes less often, but the inexpensive feed check runs every 30 minutes.
KEV_REFRESH_INTERVAL_SECONDS = positive_int(
    "KEV_REFRESH_INTERVAL_SECONDS",
    1_800,
)

# FIRST publishes EPSS scores daily. If KEV is still empty or collection fails,
# retry sooner rather than recording an empty success and waiting a full day.
EPSS_REFRESH_INTERVAL_SECONDS = positive_int(
    "EPSS_REFRESH_INTERVAL_SECONDS",
    86_400,
)
EPSS_STARTUP_DELAY_SECONDS = positive_int(
    "EPSS_STARTUP_DELAY_SECONDS",
    60,
)
EPSS_RETRY_INTERVAL_SECONDS = positive_int(
    "EPSS_RETRY_INTERVAL_SECONDS",
    300,
)

# NVD is used only to enrich CVEs already present in CISA KEV. A bounded batch
# prevents one manual refresh from becoming an hours-long request.
NVD_API_KEY = os.getenv("NVD_API_KEY", "").strip()
NVD_BATCH_SIZE = positive_int("NVD_BATCH_SIZE", 25)

# Current NVD data is rechecked weekly by default. This is frequent enough to
# detect meaningful CVSS reassessments without querying every KEV every day.
NVD_STALE_AFTER_HOURS = positive_int("NVD_STALE_AFTER_HOURS", 168)

# NVD starts after KEV/EPSS have had time to initialize. While a backlog exists,
# the worker keeps processing another bounded batch after a short pause. When
# caught up, it only checks periodically for new/stale candidates.
NVD_STARTUP_DELAY_SECONDS = positive_int("NVD_STARTUP_DELAY_SECONDS", 120)
NVD_BACKLOG_RETRY_INTERVAL_SECONDS = positive_int(
    "NVD_BACKLOG_RETRY_INTERVAL_SECONDS",
    60,
)
NVD_IDLE_CHECK_INTERVAL_SECONDS = positive_int(
    "NVD_IDLE_CHECK_INTERVAL_SECONDS",
    3_600,
)
NVD_RETRY_INTERVAL_SECONDS = positive_int(
    "NVD_RETRY_INTERVAL_SECONDS",
    300,
)

# NVD documents different request limits for public and API-key traffic. We
# still send requests sequentially. Without a key, ~6.5 seconds stays below the
# public 5-per-30-second limit. With a key, the default is much faster while
# remaining below the documented keyed limit. The value is configurable so the
# project can be tuned later without code changes.
_default_nvd_delay = 0.75 if NVD_API_KEY else 6.5
NVD_REQUEST_DELAY_SECONDS = positive_float(
    "NVD_REQUEST_DELAY_SECONDS",
    _default_nvd_delay,
)

CORS_ORIGINS = [
    origin.strip()
    for origin in os.getenv(
        "CORS_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173,"
        "http://localhost:4173,http://127.0.0.1:4173",
    ).split(",")
    if origin.strip()
]

# IOC-CVE Stage 1 uses AlienVault OTX as the direct CVE -> pulse -> IOC source.
# The API key is free but required for predictable authenticated access. OTX is
# deliberately kept separate from future ThreatFox/GreyNoise configuration so
# each source can have its own rate limits and trust policy.
OTX_API_KEY = os.getenv("OTX_API_KEY", "").strip()
OTX_SERVER = os.getenv("OTX_SERVER", "https://otx.alienvault.com").strip().rstrip("/")
if not OTX_SERVER.startswith(("https://", "http://")):
    raise ValueError("OTX_SERVER must start with http:// or https://")



# OTX V1 SETTINGS
# The optional feature is enabled explicitly after its files/schema are ready.
# A missing key keeps its worker idle while existing KEV/EPSS/NVD continue.
def environment_bool(name: str, default: bool = False) -> bool:
    """Parse an explicit boolean instead of treating the string 'false' as true.

    Function detail: Called when defining feature flags. Accepts explicit true/false
      spellings; an invalid value fails startup instead of silently enabling OTX.
    """
    value = os.getenv(name, "true" if default else "false").strip().lower()
    if value not in {"true", "false", "1", "0"}:
        raise ValueError(f"{name} must be true or false")
    return value in {"true", "1"}


OTX_ENABLED = environment_bool("OTX_ENABLED")
OTX_REFRESH_HOURS = positive_int("OTX_REFRESH_HOURS", 24)
OTX_WORKER_POLL_SECONDS = positive_int("OTX_WORKER_POLL_SECONDS", 15)
OTX_REQUEST_DELAY_SECONDS = positive_float("OTX_REQUEST_DELAY_SECONDS", 1.0)
OTX_JOB_DELAY_SECONDS = positive_int("OTX_JOB_DELAY_SECONDS", 15)
OTX_RETRY_SECONDS = positive_int("OTX_RETRY_SECONDS", 3_600)
OTX_MANUAL_COOLDOWN_SECONDS = positive_int("OTX_MANUAL_COOLDOWN_SECONDS", 900)
