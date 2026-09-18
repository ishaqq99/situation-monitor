"""Retrieve and validate current EPSS scores from FIRST.

The public API supports small comma-separated CVE batches. Situation Monitor
uses those batches because it enriches only the local CISA KEV catalog; it does
not download the complete global EPSS dataset.

This module owns external HTTP behavior and response parsing. It does not know
about PostgreSQL, Redis, FastAPI routes, or background scheduling.
"""

import asyncio
import re
from collections.abc import Iterable

import httpx
from pydantic import ValidationError

from app.models.epss import EPSSScore


EPSS_API_URL = "https://api.first.org/data/v1/epss"
CVE_PATTERN = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")

# FIRST limits the cve query string to 2,000 characters. One hundred normal
# CVE identifiers remain safely below that limit and match the API's normal
# response size. The character check below provides a second safety boundary.
EPSS_BATCH_SIZE = 100
EPSS_MAX_CVE_PARAMETER_LENGTH = 1_900


class EPSSResponseError(RuntimeError):
    """FIRST responded, but its response could not be used safely."""


def normalize_cve_id(cve_id: str) -> str:
    """Trim, uppercase, and validate a CVE identifier before network use."""
    cleaned_id = cve_id.strip().upper()
    if CVE_PATTERN.fullmatch(cleaned_id) is None:
        raise ValueError("Enter a CVE ID such as CVE-2021-44228.")
    if len(cleaned_id) > EPSS_MAX_CVE_PARAMETER_LENGTH:
        raise ValueError("CVE ID exceeds the provider's query length limit.")
    return cleaned_id


def normalize_cve_ids(cve_ids: Iterable[str]) -> list[str]:
    """Normalize identifiers while preserving order and removing duplicates."""
    normalized: list[str] = []
    seen: set[str] = set()

    for cve_id in cve_ids:
        cleaned_id = normalize_cve_id(cve_id)
        if cleaned_id not in seen:
            seen.add(cleaned_id)
            normalized.append(cleaned_id)

    return normalized


def _build_batches(cve_ids: list[str]) -> list[list[str]]:
    """Split identifiers by both item count and query-string length."""
    batches: list[list[str]] = []
    current: list[str] = []

    for cve_id in cve_ids:
        candidate = ",".join([*current, cve_id])
        if current and (
            len(current) >= EPSS_BATCH_SIZE
            or len(candidate) > EPSS_MAX_CVE_PARAMETER_LENGTH
        ):
            batches.append(current)
            current = [cve_id]
        else:
            current.append(cve_id)

    if current:
        batches.append(current)

    return batches


def parse_epss_batch_response(
    payload: object,
    requested_cves: set[str],
) -> list[EPSSScore]:
    """Validate one FIRST response and return normalized score models.

    FIRST may omit a requested CVE when no score exists. That is a successful
    response with missing data, not a fabricated zero score.
    """
    if not isinstance(payload, dict):
        raise EPSSResponseError("FIRST returned an unexpected response format.")
    if payload.get("status") != "OK":
        raise EPSSResponseError("FIRST did not report a successful EPSS response.")

    records = payload.get("data")
    if not isinstance(records, list):
        raise EPSSResponseError("FIRST's response did not contain a valid data list.")
    total = payload.get("total")
    if total is not None and str(total) != str(len(records)):
        raise EPSSResponseError("FIRST returned a truncated or inconsistent batch.")

    scores: list[EPSSScore] = []
    returned_cves: set[str] = set()

    for record in records:
        if not isinstance(record, dict):
            raise EPSSResponseError("FIRST returned an invalid EPSS record.")
        try:
            score = EPSSScore(
                cve_id=record["cve"],
                epss_score=record["epss"],
                percentile=record["percentile"],
                score_date=record["date"],
            )
        except (KeyError, ValidationError) as exc:
            raise EPSSResponseError(
                "FIRST returned incomplete or invalid score data."
            ) from exc

        if score.cve_id not in requested_cves:
            raise EPSSResponseError("FIRST returned a score for an unrequested CVE.")
        if score.cve_id in returned_cves:
            raise EPSSResponseError("FIRST returned a duplicate EPSS record.")

        returned_cves.add(score.cve_id)
        scores.append(score)

    return scores


def parse_epss_response(payload: object, requested_cve: str) -> EPSSScore | None:
    """Compatibility helper for callers that request exactly one CVE."""
    scores = parse_epss_batch_response(payload, {requested_cve})
    if len(scores) > 1:
        raise EPSSResponseError("FIRST returned multiple records for one CVE.")
    return scores[0] if scores else None


async def fetch_epss_scores(cve_ids: Iterable[str]) -> list[EPSSScore]:
    """Fetch a small CVE population using efficient sequential API batches."""
    normalized_ids = normalize_cve_ids(cve_ids)
    if not normalized_ids:
        return []

    timeout = httpx.Timeout(15.0, connect=5.0)
    all_scores: list[EPSSScore] = []

    # The outer deadline bounds the complete refresh. Batches are sequential,
    # which avoids creating a request burst against FIRST's public service.
    async with asyncio.timeout(180):
        async with httpx.AsyncClient(
            timeout=timeout,
            headers={
                "Accept": "application/json",
                "User-Agent": "Situation-Monitor/0.1",
            },
        ) as client:
            for batch in _build_batches(normalized_ids):
                response = await client.get(
                    EPSS_API_URL,
                    params={"cve": ",".join(batch), "limit": len(batch)},
                )
                response.raise_for_status()
                try:
                    payload = response.json()
                except ValueError as exc:
                    raise EPSSResponseError("FIRST returned invalid JSON.") from exc

                all_scores.extend(
                    parse_epss_batch_response(payload, requested_cves=set(batch))
                )

    return all_scores


async def fetch_epss_score(cve_id: str) -> EPSSScore | None:
    """Fetch one CVE while reusing the same validated batch implementation."""
    cleaned_id = normalize_cve_id(cve_id)
    scores = await fetch_epss_scores([cleaned_id])
    return scores[0] if scores else None
