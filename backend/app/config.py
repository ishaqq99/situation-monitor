"""Validated environment settings shared by API, storage, and workers."""

import os
from pathlib import Path

from dotenv import load_dotenv


# backend/app/config.py -> backend/app -> backend -> project root
load_dotenv(Path(__file__).resolve().parents[2] / ".env")


def positive_int(name: str, default: int) -> int:
    """Read a positive integer setting and fail early on invalid values."""
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError as exc:
        raise ValueError(f"{name} must be a positive integer") from exc
    if value <= 0:
        raise ValueError(f"{name} must be a positive integer")
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

CORS_ORIGINS = [
    origin.strip()
    for origin in os.getenv(
        "CORS_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173,"
        "http://localhost:4173,http://127.0.0.1:4173",
    ).split(",")
    if origin.strip()
]
