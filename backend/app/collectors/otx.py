"""AlienVault OTX CVE -> IOC enrichment for Situation Monitor.

FILE ROLE
---------
This is the first provider collector in the IOC-CVE intelligence feature. Given
one CVE ID, it asks OTX which public pulses are related to that CVE, downloads
the indicators (including inactive ones) from those pulses, validates the indicator values, and
returns provider-neutral models from ``app.models.ioc``.

ARCHITECTURE POSITION
---------------------
check_ioc.py / app.services.ioc_service
    -> fetch_otx_cve_iocs()
    -> OTX CVE general endpoint
    -> OTX pulse-indicator endpoints
    -> CVEIOCEnrichment

WHAT THIS FILE OWNS
-------------------
- OTX HTTP behavior, authentication header, timeout, and pagination.
- CVE input validation before network use.
- Translation from OTX indicator names into Situation Monitor IOC types.
- Safe normalization/validation of IPs, domains/hostnames, URLs, and hashes.
- Preserving OTX pulse provenance for every CVE -> IOC observation.
- Recording skipped broad/ambiguous pulses instead of silently discarding them.
- Passing pulse metadata to the pure relevance classifier before heavy calls.

WHAT THIS FILE DOES NOT DO
--------------------------
- It does not write PostgreSQL or Redis.
- It does not schedule daily enrichment.
- It does not exclude old KEVs; the IOC job scheduler revisits every KEV.
- It does not assign a Situation Monitor trust score to community intelligence.

IMPORTANT TRUST BOUNDARY
------------------------
An OTX pulse is community threat intelligence. OTX's CVE lookup tells us that a
pulse is related to the requested CVE, while the pulse-indicator endpoint gives
us the indicators contained in that broader pulse. A pulse can mention several
CVEs, so an indicator from that pulse must NOT automatically be described as a
direct IOC for the requested CVE.

Stage 1.3 keeps every OTX pulse-derived observation as ``pulse_context`` and
also assesses each pulse BEFORE downloading its entire indicator list. The
normal collector only downloads conservatively focused pulses; skipped pulses
remain visible in the assessment list for review. An analyst can opt in to
``include_context=True`` for a fuller exploratory view. Neither mode approves
anything for a detection or changes its CVE relationship strength.

OLD CVE REACTIVATION
--------------------
This collector accepts any syntactically valid CVE regardless of age. The IOC
worker schedules every local KEV, so newly published report context can be
discovered for a five-year-old CVE during a later refresh.


FILE GUIDE
----------
WHAT THIS FILE DOES
Download bounded OTX pulse context for one CVE and normalize its indicators.

WHY IT EXISTS
Provider protocol, pagination, safety limits, and normalization belong outside routes and SQL.

WHO CALLS OR IMPORTS IT
ioc_service.run_one_due_job and the optional check_ioc.py diagnostic call fetch_otx_cve_iocs.

WHAT IT CALLS OR IMPORTS
Calls official OTX HTTPS endpoints through HTTPX and creates app.models.ioc objects.

ROLE IN THE ARCHITECTURE
External-data adapter; it never writes to PostgreSQL or Redis.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

import httpx
from pydantic import ValidationError

from app.config import OTX_API_KEY, OTX_SERVER, OTX_REQUEST_DELAY_SECONDS
from app.models.ioc import (
    CVEIOCEnrichment,
    IOCIndicator,
    IOCObservation,
    IOCRelationshipType,
    IOCType,
    SourceRecordAssessment,
)
from app.services.ioc_evidence import assess_otx_pulse


CVE_PATTERN = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")
# OTX pulse tags sometimes remove the normal CVE hyphens, for example
# ``cve20260300 cve``. This pattern intentionally accepts normal and compact
# forms so the pulse context can show which CVEs the source record references.
PULSE_CVE_PATTERN = re.compile(
    r"\bcve[\s:_-]*([0-9]{4})[\s:_-]*([0-9]{4,})\b",
    re.IGNORECASE,
)
HEX_PATTERNS = {
    IOCType.MD5: re.compile(r"^[0-9a-fA-F]{32}$"),
    IOCType.SHA1: re.compile(r"^[0-9a-fA-F]{40}$"),
    IOCType.SHA256: re.compile(r"^[0-9a-fA-F]{64}$"),
}

OTX_SOURCE_NAME = "AlienVault OTX"

# OTX pulse responses can be substantially larger than the initial CVE lookup.
# Stage 1 originally used a 30-second read timeout and requested up to 1,000
# indicators per page. In practice, CVEs that actually have related pulses are
# exactly the ones that trigger the heavier pulse-indicator path, so large pages
# could time out while zero-pulse CVEs appeared healthy. Smaller pages plus
# retries make the collector much more reliable without changing the data model.
OTX_TIMEOUT = httpx.Timeout(connect=10.0, read=60.0, write=30.0, pool=10.0)
OTX_PULSE_PAGE_LIMIT = 250
OTX_MAX_ATTEMPTS = 5
OTX_RETRYABLE_STATUS_CODES = {500, 502, 503, 504}
OTX_BACKOFF_SECONDS = (1.0, 2.0, 4.0, 8.0)

OTX_TYPE_MAP = {
    "IPv4": IOCType.IPV4,
    "IPv6": IOCType.IPV6,
    "domain": IOCType.DOMAIN,
    "hostname": IOCType.HOSTNAME,
    "URL": IOCType.URL,
    "FileHash-MD5": IOCType.MD5,
    "FileHash-SHA1": IOCType.SHA1,
    "FileHash-SHA256": IOCType.SHA256,
}


class OTXConfigurationError(RuntimeError):
    """Required local OTX configuration is missing or invalid."""


class OTXResponseError(RuntimeError):
    """OTX responded, but the response could not be trusted or normalized."""


class OTXAuthenticationError(RuntimeError):
    """OTX rejected the configured API key."""


class OTXNotFoundError(RuntimeError):
    """The requested OTX resource does not exist."""


class OTXProviderUnavailableError(RuntimeError):
    """OTX could not complete a request after retrying transient failures.

    This is intentionally different from a successful lookup with zero IOCs.
    Future automation must leave this CVE eligible for retry rather than storing
    the provider failure as an authoritative "no intelligence found" result.
    """


# Collection budgets protect the caller even when every page has a new URL.
# These are collector limits, not OTX quota claims. Hitting one is never success.
OTX_ORIGIN = "https://otx.alienvault.com"
OTX_TOTAL_TIMEOUT_SECONDS = 180.0
OTX_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
OTX_MAX_TOTAL_BYTES = 16 * 1024 * 1024
OTX_MAX_PULSE_METADATA = 500
OTX_MAX_SELECTED_PULSES = 25
OTX_MAX_PAGES_PER_PULSE = 20
OTX_MAX_TOTAL_PAGES = 80
OTX_MAX_TOTAL_RECORDS = 10_000
OTX_MAX_INLINE_RETRY_SECONDS = 10.0


class OTXCollectionLimitError(OTXResponseError):
    """Collection exceeded its size/page budget; absence cannot be inferred."""


class OTXRetryLaterError(OTXProviderUnavailableError):
    """Stop the entire lookup and expose a cooldown to the IOC service.

    The manual checker prints retry_at. The IOC service persists it in the
    provider-state row, preventing every worker from calling OTX before expiry.
    This exception intentionally does not return a successful empty result.
    """

    def __init__(self, message: str, retry_after_seconds: float):
        """Create a provider cooldown exception carrying the next allowed UTC time; the service persists this deadline before trying another job."""
        super().__init__(message)
        self.retry_after_seconds = retry_after_seconds
        self.retry_at = datetime.now(timezone.utc) + timedelta(seconds=retry_after_seconds)


@dataclass
class _LookupBudget:
    """Mutable counters shared by all requests in ONE CVE lookup, not globally."""

    remaining_bytes: int = OTX_MAX_TOTAL_BYTES
    remaining_pages: int = OTX_MAX_TOTAL_PAGES
    remaining_records: int = OTX_MAX_TOTAL_RECORDS


def normalize_cve_id(cve_id: str) -> str:
    """Normalize and validate a CVE identifier before it reaches OTX.

    Parameters
    ----------
    cve_id:
        User/service supplied CVE such as ``" cve-2021-44228 "``.

    Returns
    -------
    str
        Uppercase, whitespace-trimmed CVE ID.

    Raises
    ------
    ValueError
        If the value is not a syntactically valid CVE identifier.
    

    Function detail: The service, routes, and manual checker use this before a CVE enters a
      provider URL or database lookup.
    """

    cleaned = cve_id.strip().upper()
    if CVE_PATTERN.fullmatch(cleaned) is None:
        raise ValueError("Enter a CVE ID such as CVE-2021-44228.")
    return cleaned


def _parse_datetime(value: object) -> datetime | None:
    """Parse provider timestamps while preserving the meaning 'not supplied'.

    Function detail: Called for provider-created, modified, and expiration fields. Missing
      or invalid dates remain unknown instead of becoming fabricated timestamps.
    """

    if not isinstance(value, str) or not value.strip():
        return None

    candidate = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _deduplicate_strings(values: object) -> list[str]:
    """Keep unique non-empty strings in source order.

    Function detail: Called for report tags/references. Preserving first-seen order makes
      evidence display stable.
    """

    if not isinstance(values, list):
        return []

    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        if not isinstance(value, str):
            continue
        cleaned = value.strip()
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            result.append(cleaned)
    return result


def _extract_pulse_cve_ids(
    pulse: dict[str, Any],
    requested_cve: str,
) -> list[str]:
    """Return CVEs referenced by an OTX pulse without implying IOC ownership.

    Why this exists
    ---------------
    The OTX CVE endpoint can return a pulse containing multiple CVEs and many
    indicators. We preserve those CVE references as SOURCE-RECORD CONTEXT so a
    future analyst can see that the pulse was broader than the requested CVE.

    The requested CVE is always included because OTX itself returned this pulse
    from that CVE's ``general`` lookup. Additional CVEs are extracted only from
    pulse metadata we received (tags, name, description, and references).

    This function does NOT say that every IOC in the pulse is directly linked
    to every CVE in this list. That semantic distinction is carried separately
    by ``IOCRelationshipType.PULSE_CONTEXT``.
    

    Function detail: Called while assessing report relevance. A CVE mention links a report
      to the CVE; it does not prove each indicator was used to exploit it.
    """

    ordered: list[str] = [requested_cve]
    seen: set[str] = {requested_cve}

    text_values: list[str] = []

    tags = pulse.get("tags")
    if isinstance(tags, list):
        text_values.extend(item for item in tags if isinstance(item, str))

    for field_name in ("name", "description"):
        value = pulse.get(field_name)
        if isinstance(value, str):
            text_values.append(value)

    references = pulse.get("references")
    if isinstance(references, list):
        text_values.extend(item for item in references if isinstance(item, str))

    for text in text_values:
        for match in PULSE_CVE_PATTERN.finditer(text):
            cve = f"CVE-{match.group(1)}-{match.group(2)}"
            if cve not in seen:
                seen.add(cve)
                ordered.append(cve)

    return ordered


def _normalize_dns_name(value: str) -> str | None:
    """Normalize a domain/hostname and reject values unsafe for IOC matching.

    Function detail: Called by normalize_otx_indicator. Rejects malformed hostnames before
      they become stored observables.
    """

    candidate = value.strip().rstrip(".").lower()
    if not candidate or len(candidate) > 253:
        return None

    # OTX domain/hostname indicators should be DNS names rather than URLs,
    # wildcard patterns, paths, or IP literals. IDNA encoding validates Unicode
    # labels and gives us a stable ASCII form for later deduplication.
    if any(character in candidate for character in ("/", "*", " ")):
        return None

    try:
        ascii_name = candidate.encode("idna").decode("ascii")
    except UnicodeError:
        return None

    labels = ascii_name.split(".")
    if len(labels) < 2:
        return None
    for label in labels:
        if not label or len(label) > 63:
            return None
        if label.startswith("-") or label.endswith("-"):
            return None
        if re.fullmatch(r"[a-z0-9-]+", label) is None:
            return None

    # If the provider mislabeled a bare IP as a DNS name, discard it rather
    # than creating two canonical identities for the same observable.
    try:
        ipaddress.ip_address(ascii_name)
    except ValueError:
        return ascii_name
    return None


def _normalize_url(value: str) -> str | None:
    """Validate a network URL without rewriting path/query semantics.

    Function detail: Called by normalize_otx_indicator. Validating an observable URL never
      opens it; the URL remains plain text in the UI.
    """

    candidate = value.strip()
    if not candidate or len(candidate) > 4_096:
        return None

    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return None

    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return None

    # Preserve path/query case. Reject credentials, invalid ports, and control
    # characters, but never resolve or visit an indicator URL.
    try:
        _ = parsed.port
    except ValueError:
        return None
    if parsed.username is not None or parsed.password is not None:
        return None
    if any(ord(char) < 32 or ord(char) == 127 for char in candidate):
        return None
    return candidate


def normalize_otx_indicator(raw_type: object, raw_value: object) -> IOCIndicator | None:
    """Convert one OTX indicator into the provider-neutral IOC model.

    Unsupported indicator types are deliberately ignored. Stage 1 focuses on
    observables that later map cleanly into SIEM/threat-intel workflows: IPs,
    DNS names, URLs, and common cryptographic hashes.
    

    Function detail: Called for each provider indicator. Returns None for unsupported or
      invalid types and an IOCIndicator for accepted types.
    """

    if not isinstance(raw_type, str) or not isinstance(raw_value, str):
        return None

    indicator_type = OTX_TYPE_MAP.get(raw_type)
    if indicator_type is None:
        return None

    candidate = raw_value.strip()
    if not candidate:
        return None

    if indicator_type in {IOCType.IPV4, IOCType.IPV6}:
        try:
            parsed_ip = ipaddress.ip_address(candidate)
        except ValueError:
            return None
        if indicator_type is IOCType.IPV4 and parsed_ip.version != 4:
            return None
        if indicator_type is IOCType.IPV6 and parsed_ip.version != 6:
            return None
        normalized_value = parsed_ip.compressed.lower()

    elif indicator_type in {IOCType.DOMAIN, IOCType.HOSTNAME}:
        normalized_value = _normalize_dns_name(candidate)
        if normalized_value is None:
            return None

    elif indicator_type is IOCType.URL:
        normalized_value = _normalize_url(candidate)
        if normalized_value is None:
            return None

    else:
        pattern = HEX_PATTERNS[indicator_type]
        if pattern.fullmatch(candidate) is None:
            return None
        normalized_value = candidate.lower()

    return IOCIndicator(value=normalized_value, indicator_type=indicator_type)


def _parse_pulses(payload: object, requested_cve: str) -> tuple[int, list[dict[str, Any]]]:
    """Validate the OTX CVE general response and return related pulse metadata.

    Function detail: Called after the CVE lookup response. Validates metadata and reports
      counts so truncated results cannot be mistaken for a complete empty lookup.
    """

    if not isinstance(payload, dict):
        raise OTXResponseError("OTX returned an unexpected CVE response format.")

    returned_indicator = payload.get("indicator")
    if not isinstance(returned_indicator, str):
        raise OTXResponseError("OTX CVE response is missing its indicator identity.")
    if returned_indicator.strip().upper() != requested_cve:
        raise OTXResponseError("OTX returned data for a different CVE.")

    pulse_info = payload.get("pulse_info")
    if not isinstance(pulse_info, dict):
        raise OTXResponseError("OTX CVE data did not contain pulse information.")

    count = pulse_info.get("count")
    if type(count) is not int or count < 0:
        raise OTXResponseError("OTX returned an invalid related-pulse count.")

    pulses = pulse_info.get("pulses")
    if not isinstance(pulses, list):
        raise OTXResponseError("OTX returned an invalid related-pulse list.")

    if len(pulses) > OTX_MAX_PULSE_METADATA:
        raise OTXCollectionLimitError("OTX returned too many pulse metadata records.")

    normalized_pulses: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for pulse in pulses:
        if not isinstance(pulse, dict):
            raise OTXResponseError("OTX returned malformed pulse metadata.")
        # A single enormous reference/tag list would otherwise be copied into
        # every observation. Reject oversized metadata explicitly, never trim
        # it silently and claim complete coverage.
        if len(json.dumps(pulse, ensure_ascii=False).encode("utf-8")) > 32_768:
            raise OTXCollectionLimitError("OTX pulse metadata exceeded 32 KiB.")
        pulse_id = pulse.get("id")
        if not isinstance(pulse_id, str) or not re.fullmatch(r"[0-9a-fA-F]{24}", pulse_id):
            raise OTXResponseError("OTX returned a pulse without a valid ID.")
        if pulse_id in seen_ids:
            continue
        seen_ids.add(pulse_id)
        normalized_pulses.append(pulse)

    return count, normalized_pulses


def _observation_from_otx(
    *,
    cve_id: str,
    pulse: dict[str, Any],
    raw_indicator: object,
    fetched_at: datetime,
    assessment: SourceRecordAssessment | None = None,
) -> IOCObservation | None:
    """Create one source observation from OTX pulse + indicator metadata.

    Function detail: Called for a selected pulse's indicators. Attaches report ID,
      relevance, source timestamps, and provider active/expiration state to each normalized
      observable.
    """

    if not isinstance(raw_indicator, dict):
        return None

    indicator = normalize_otx_indicator(
        raw_indicator.get("type"),
        raw_indicator.get("indicator"),
    )
    if indicator is None:
        return None

    pulse_id = str(pulse["id"])
    author = pulse.get("author")
    author_name: str | None = None
    if isinstance(author, dict):
        username = author.get("username")
        if isinstance(username, str) and username.strip():
            author_name = username.strip()

    pulse_name = pulse.get("name")
    if not isinstance(pulse_name, str) or not pulse_name.strip():
        pulse_name = None
    else:
        pulse_name = pulse_name.strip()

    tlp = pulse.get("TLP", pulse.get("tlp"))
    if not isinstance(tlp, str) or not tlp.strip():
        tlp = None
    else:
        tlp = tlp.strip().lower()

    is_active = raw_indicator.get("is_active")
    if isinstance(is_active, bool):
        active: bool | None = is_active
    elif isinstance(is_active, int) and is_active in {0, 1}:
        active = bool(is_active)
    else:
        active = None

    return IOCObservation(
        cve_id=cve_id,
        indicator=indicator,
        # OTX proves that the IOC and CVE occur in the same related pulse. It
        # does not prove an indicator-level CVE association, especially when a
        # pulse references several CVEs. Keep this contextual by default.
        relationship_type=IOCRelationshipType.PULSE_CONTEXT,
        source_record_relevance=(assessment.relevance if assessment else "review_required"),
        source_record_cve_ids=(
            assessment.source_record_cve_ids
            if assessment else _extract_pulse_cve_ids(pulse, cve_id)
        ),
        source=OTX_SOURCE_NAME,
        source_record_id=pulse_id,
        source_record_name=pulse_name,
        source_record_url=f"{OTX_SERVER.rstrip('/')}/pulse/{pulse_id}",
        source_author=author_name,
        source_tlp=tlp,
        source_created_at=_parse_datetime(pulse.get("created")),
        source_modified_at=_parse_datetime(pulse.get("modified")),
        active=active,
        expires_at=_parse_datetime(raw_indicator.get("expiration")),
        reference_urls=_deduplicate_strings(pulse.get("references")),
        tags=_deduplicate_strings(pulse.get("tags")),
        fetched_at=fetched_at,
    )


def _validate_otx_url(url: str, *, expected_path: str | None = None) -> str:
    """Allow credentials only to the official HTTPS origin and known API paths.

    Provider-supplied pagination is untrusted. Host, port, credentials, path,
    and fragments are checked BEFORE HTTPX sees the URL. No redirect is used.
    An exact pulse path also prevents a next link from changing to another CVE
    or pulse. Indicator/reference URLs are metadata and are never fetched.
    

    Function detail: Called before every HTTP request, including provider-supplied next
      links. It rejects host/path changes so the API key cannot be sent to arbitrary
      destinations.
    """
    if not isinstance(url, str) or len(url) > 4096:
        raise OTXResponseError("Invalid OTX request URL.")
    if any(ord(char) <= 32 or ord(char) == 127 or char == "\\" for char in url):
        raise OTXResponseError("OTX request URL contains forbidden characters.")
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise OTXResponseError("Invalid OTX request URL.") from exc
    if (parsed.scheme != "https" or parsed.hostname != "otx.alienvault.com"
            or port not in (None, 443) or parsed.username is not None
            or parsed.password is not None or parsed.fragment):
        raise OTXResponseError("OTX requests must stay on the official HTTPS origin.")
    path = parsed.path
    if expected_path is not None:
        valid_path = path.rstrip("/") == expected_path.rstrip("/")
    else:
        valid_path = re.fullmatch(
            r"/api/v1/(?:indicators/cve/CVE-[0-9]{4}-[0-9]{4,}/general|"
            r"pulses/[0-9a-fA-F]{24}/indicators)/?", path
        ) is not None
    if not valid_path:
        raise OTXResponseError("OTX returned a request path outside the expected endpoint.")
    return url


def _validate_server() -> None:
    """Reject insecure/custom OTX_SERVER values before attaching the API key.

    The shared config file is left intact. Strict provider validation happens
    only when OTX is called, so this patch needs no KEV/EPSS/NVD config rewrite.
    Tests replace the HTTP transport, never the authenticated destination.
    

    Function detail: Called before collection. Only the official HTTPS OTX server can
      receive the configured API key.
    """
    if OTX_SERVER.rstrip("/") not in (OTX_ORIGIN, OTX_ORIGIN + ":443"):
        raise OTXConfigurationError(
            "OTX_SERVER must be https://otx.alienvault.com (optional :443)."
        )


def _retry_after_seconds(value: str | None) -> float | None:
    """Read Retry-After as integer seconds or an HTTP date without shortening it.

    Missing/malformed values use the caller's normal fallback. Impossibly
    large numeric waits fail explicitly rather than overflow or retry early.
    HTTP dates are evaluated in UTC using the local machine's clock.
    

    Function detail: Called for 429/503 handling. Returns a provider-directed wait, or None
      when the header is absent or unusable.
    """
    if value is None:
        return None
    value = value.strip()
    if value.isascii() and value.isdigit():
        if len(value) > 9:
            raise OTXResponseError("OTX returned an unsupported Retry-After duration.")
        return float(value)
    try:
        when = parsedate_to_datetime(value)
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        return max(0.0, (when - datetime.now(timezone.utc)).total_seconds())
    except (TypeError, ValueError, OverflowError):
        return None


async def _get_response(
    client: httpx.AsyncClient,
    url: str,
    *,
    params: dict[str, object] | None = None,
    budget: _LookupBudget | None = None,
) -> httpx.Response:
    """Stream one response under byte limits and always close its connection.

    We request identity encoding and reject unexpected compression BEFORE
    reading, so a compressed bomb cannot expand inside the HTTP decoder. Error
    bodies are never needed for classification and are not read into memory.
    The returned response is detached from its closed network stream.
    

    Function detail: Called by _request_json. Streams bounded bytes and closes the response
      even when decoding or limit checks fail.
    """
    _validate_otx_url(url)
    # Pace EVERY HTTP attempt, including pagination/retries. The worker also
    # spaces whole CVE jobs. These are local pacing settings, not a quota claim.
    if OTX_REQUEST_DELAY_SECONDS > 0:
        await asyncio.sleep(OTX_REQUEST_DELAY_SECONDS)
    async with client.stream("GET", url, params=params, follow_redirects=False) as response:
        body = bytearray()
        if 200 <= response.status_code < 300:
            if response.headers.get("Content-Encoding", "identity").lower() != "identity":
                raise OTXResponseError("OTX returned unexpected compressed content.")
            async for chunk in response.aiter_bytes(chunk_size=16_384):
                if len(body) + len(chunk) > OTX_MAX_RESPONSE_BYTES:
                    raise OTXCollectionLimitError("OTX response exceeded the 2 MiB byte limit.")
                if budget is not None:
                    budget.remaining_bytes -= len(chunk)
                    if budget.remaining_bytes < 0:
                        raise OTXCollectionLimitError("OTX lookup exceeded its total byte budget.")
                body.extend(chunk)
        # The bytes above are already decoded by HTTPX. Do not forward an
        # encoding header that would cause the detached response to decode twice.
        headers = dict(response.headers)
        headers.pop("content-encoding", None)
        headers.pop("content-length", None)
        return httpx.Response(
            response.status_code, headers=headers, content=bytes(body), request=response.request
        )


async def _request_json(
    client: httpx.AsyncClient,
    url: str,
    *,
    params: dict[str, object] | None = None,
    context: str = "OTX request",
    budget: _LookupBudget | None = None,
) -> dict[str, Any]:
    """Retry transient transport/5xx failures; defer cooldowns; validate JSON.

    429 always stops this lookup. A long Retry-After on 5xx also stops it.
    Short server-directed waits are honored in full, never truncated. Sleeping
    happens after the response is closed and is covered by the total deadline.
    Authentication, redirects, 404, malformed payloads, and limits are separate
    errors. The IOC service catches OTXRetryLaterError before its base class.
    

    Function detail: Called for each CVE/pulse page. It applies per-request pacing and an
      overall budget, then returns validated JSON or a specific retry/failure exception.
    """
    for attempt in range(OTX_MAX_ATTEMPTS):
        backoff = OTX_BACKOFF_SECONDS[min(attempt, len(OTX_BACKOFF_SECONDS) - 1)]
        try:
            response = await _get_response(client, url, params=params, budget=budget)
        except (httpx.TimeoutException, httpx.NetworkError, httpx.RemoteProtocolError) as exc:
            if attempt + 1 == OTX_MAX_ATTEMPTS:
                raise OTXProviderUnavailableError(
                    f"{context} failed after {OTX_MAX_ATTEMPTS} attempts ({type(exc).__name__})."
                ) from exc
            await asyncio.sleep(backoff)
            continue

        status = response.status_code
        if status in (401, 403):
            raise OTXAuthenticationError("OTX rejected the configured API key.")
        if status == 404:
            raise OTXNotFoundError(f"{context}: OTX returned HTTP 404; result is unknown.")
        if 300 <= status < 400:
            raise OTXResponseError(f"{context}: redirects are not accepted.")
        if status == 429 or status in OTX_RETRYABLE_STATUS_CODES:
            server_wait = _retry_after_seconds(response.headers.get("Retry-After"))
            delay = max(server_wait if server_wait is not None else backoff, backoff)
            if status == 429:
                raise OTXRetryLaterError(
                    f"{context}: OTX rate limit reached; lookup stopped.",
                    server_wait if server_wait is not None else 60.0,
                )
            if server_wait is not None and (
                delay > OTX_MAX_INLINE_RETRY_SECONDS or attempt + 1 == OTX_MAX_ATTEMPTS
            ):
                raise OTXRetryLaterError(f"{context}: OTX requested a later retry.", delay)
            if attempt + 1 == OTX_MAX_ATTEMPTS:
                raise OTXProviderUnavailableError(
                    f"{context} failed after {OTX_MAX_ATTEMPTS} attempts (HTTP {status})."
                )
            await asyncio.sleep(delay)
            continue
        response.raise_for_status()
        try:
            payload = json.loads(response.content)
        except (ValueError, RecursionError) as exc:
            raise OTXResponseError(f"{context} returned invalid JSON.") from exc
        if not isinstance(payload, dict):
            raise OTXResponseError(f"{context} returned an unexpected JSON shape.")
        return payload
    raise OTXProviderUnavailableError(f"{context} could not be completed.")


def _next_page_url(current_url: str, next_page: object, pulse_id: str) -> str | None:
    """Resolve pagination on the same pulse endpoint and keep page sizes bounded.

    Relative links are resolved against the current page, not the site root.
    Do not check membership in a set before checking type: a dict/list is an
    invalid link and should raise our readable error, not Python's TypeError.
    

    Function detail: Called by pulse pagination. It validates every next link and reapplies
      bounded page size plus inactive-indicator inclusion.
    """
    if next_page is None or next_page == "":
        return None
    if not isinstance(next_page, str):
        raise OTXResponseError("OTX returned an invalid pagination link.")
    if any(ord(char) <= 32 or char == "\\" for char in next_page):
        raise OTXResponseError("OTX returned an invalid pagination link.")
    resolved = urljoin(current_url, next_page)
    _validate_otx_url(resolved, expected_path=f"/api/v1/pulses/{pulse_id}/indicators")
    parsed = urlsplit(resolved)
    query = parse_qsl(parsed.query, keep_blank_values=True)
    query = [(key, value) for key, value in query if key not in {"limit", "include_inactive"}]
    query.extend([("limit", str(OTX_PULSE_PAGE_LIMIT)), ("include_inactive", "1")])
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query), ""))


async def _fetch_pulse_indicators(
    client: httpx.AsyncClient,
    pulse_id: str,
    *,
    budget: _LookupBudget | None = None,
) -> list[dict[str, Any]]:
    """Read a complete lifecycle-inclusive indicator snapshot of one pulse within budgets.

    A partially downloaded pulse is not returned as a complete snapshot.
    On failure the caller retains observations from OTHER completed pulses
    and marks this pulse unfetched. Missing pagination metadata is an error.
    

    Function detail: Called only for selected reports. It returns a complete pulse snapshot
      or an explicit partial/failure condition; it never silently drops failed pages.
    """
    budget = budget if budget is not None else _LookupBudget()
    url = _next_page_url(
        OTX_ORIGIN, f"/api/v1/pulses/{pulse_id}/indicators", pulse_id
    )
    indicators: list[dict[str, Any]] = []
    visited: set[str] = set()
    pages = 0
    while url is not None:
        if url in visited:
            raise OTXResponseError("OTX returned a cyclic pagination link.")
        if pages >= OTX_MAX_PAGES_PER_PULSE or budget.remaining_pages <= 0:
            raise OTXCollectionLimitError("OTX indicator pagination exceeded its page budget.")
        visited.add(url)
        pages += 1
        budget.remaining_pages -= 1
        payload = await _request_json(
            client, url, context=f"OTX pulse {pulse_id} page {pages}", budget=budget
        )
        results = payload.get("results")
        if not isinstance(results, list) or any(not isinstance(item, dict) for item in results):
            raise OTXResponseError("OTX pulse data did not contain valid indicator records.")
        if len(results) > OTX_PULSE_PAGE_LIMIT or len(results) > budget.remaining_records:
            raise OTXCollectionLimitError("OTX indicators exceeded the record budget.")
        budget.remaining_records -= len(results)
        indicators.extend(results)
        if "next" not in payload:
            raise OTXResponseError("OTX indicator response is missing pagination metadata.")
        url = _next_page_url(url, payload["next"], pulse_id)
        # Yield even with an in-memory test transport; timeout/cancellation
        # must be observable during a long run of very fast pages.
        await asyncio.sleep(0)
    return indicators


async def _collect_cve(
    normalized_cve: str, effective_api_key: str, include_context: bool
) -> CVEIOCEnrichment:
    """Coordinate one scoped collection while retaining source-level evidence.

    All pulse metadata is assessed first. A cap leaves selected-but-unfetched
    assessments visible; those are different from intentional scope skips.
    Unavailable/disappeared pulses produce a partial result. Cooldowns, bad
    credentials, and malformed responses abort; callers must not save them as
    empty successes. Completed pulses may be returned when a budget is reached.
    

    Function detail: Called by the public fetch function. It first assesses all report
      metadata, then downloads selected report indicators within count/time budgets.
    """
    fetched_at = datetime.now(timezone.utc)
    budget = _LookupBudget()
    headers = {
        "Accept": "application/json", "Accept-Encoding": "identity",
        "User-Agent": "Situation-Monitor/0.1", "X-OTX-API-KEY": effective_api_key,
    }
    async with httpx.AsyncClient(
        timeout=OTX_TIMEOUT, follow_redirects=False, headers=headers
    ) as client:
        payload = await _request_json(
            client, f"{OTX_ORIGIN}/api/v1/indicators/cve/{normalized_cve}/general",
            context=f"OTX CVE lookup for {normalized_cve}", budget=budget,
        )
        # In particular, HTTP 404 reaches the caller as OTXNotFoundError.
        reported_count, pulses = _parse_pulses(payload, normalized_cve)
        warnings: list[str] = []
        complete = reported_count == len(pulses)
        if not complete:
            warnings.append(
                f"OTX reported {reported_count} pulses but returned {len(pulses)} metadata records."
            )
        assessments: list[SourceRecordAssessment] = []
        for pulse in pulses:
            title = pulse.get("name")
            title = title.strip() if isinstance(title, str) and title.strip() else None
            title_cves = list(dict.fromkeys(
                f"CVE-{match.group(1)}-{match.group(2)}"
                for match in PULSE_CVE_PATTERN.finditer(title or "")
            ))
            assessment = assess_otx_pulse(
                requested_cve=normalized_cve, pulse_id=pulse["id"], title=title,
                pulse_url=f"{OTX_ORIGIN}/pulse/{pulse['id']}",
                source_record_cve_ids=_extract_pulse_cve_ids(pulse, normalized_cve),
                title_cve_ids=title_cves,
            )
            if include_context:
                assessment.selected_for_collection = True
            assessments.append(assessment)

        observations: list[IOCObservation] = []
        seen: set[tuple[str, str, str]] = set()
        attempted = 0
        for pulse, assessment in zip(pulses, assessments):
            if not assessment.selected_for_collection:
                continue
            if attempted >= OTX_MAX_SELECTED_PULSES:
                complete = False
                warnings.append(f"Selected pulses exceeded the {OTX_MAX_SELECTED_PULSES}-pulse collection limit.")
                break
            attempted += 1
            try:
                raw_indicators = await _fetch_pulse_indicators(client, pulse["id"], budget=budget)
            except OTXRetryLaterError:
                # Provider-wide cooldown: do NOT proceed to the next pulse.
                raise
            except OTXCollectionLimitError as exc:
                complete = False
                warnings.append(str(exc))
                break
            except (OTXNotFoundError, OTXProviderUnavailableError) as exc:
                complete = False
                warnings.append(str(exc))
                continue
            assessment.fetched = True
            assessment.indicator_count = 0
            invalid_supported = 0
            for raw_indicator in raw_indicators:
                observation = _observation_from_otx(
                    cve_id=normalized_cve, pulse=pulse, raw_indicator=raw_indicator,
                    fetched_at=fetched_at, assessment=assessment,
                )
                if observation is None:
                    raw_type = raw_indicator.get("type")
                    # Unknown *string* types are outside our supported scope.
                    # Broken records or invalid values of supported types mean
                    # data was lost; expose that instead of claiming completeness.
                    if not isinstance(raw_type, str) or raw_type in OTX_TYPE_MAP:
                        invalid_supported += 1
                    continue
                identity = (observation.source_record_id,
                            observation.indicator.indicator_type.value,
                            observation.indicator.value)
                if identity in seen:
                    continue
                seen.add(identity)
                observations.append(observation)
                assessment.indicator_count += 1
            if invalid_supported:
                complete = False
                warnings.append(
                    f"Pulse {pulse['id']} contained {invalid_supported} invalid supported IOC records."
                )
            await asyncio.sleep(0)

    unique = {(item.indicator.indicator_type, item.indicator.value) for item in observations}
    return CVEIOCEnrichment(
        cve_id=normalized_cve, source=OTX_SOURCE_NAME,
        collection_scope="all_pulses" if include_context else "focused_only",
        source_record_count_reported=reported_count,
        source_record_count_processed=sum(item.fetched for item in assessments),
        source_record_count_skipped=sum(not item.selected_for_collection for item in assessments),
        source_record_assessments=assessments, observation_count=len(observations),
        unique_indicator_count=len(unique), complete=complete, warnings=warnings,
        observations=observations, fetched_at=fetched_at,
    )


async def fetch_otx_cve_iocs(
    cve_id: str, *, api_key: str | None = None, include_context: bool = False
) -> CVEIOCEnrichment:
    """Public collector entry point used by check_ioc.py and the IOC service.

    1. Validate input/config before network use. Old CVEs are accepted.
    2. Apply a deadline to the ENTIRE lookup, including retries and page reads.
    3. Return the existing Stage 1.3 models without changing their meaning.

    complete=True means the chosen scope was collected, not that every OTX
    indicator is related to exploitation of this CVE. All observations remain
    pulse_context. A timeout aborts this run; no empty result is returned and
    callers must keep previously stored data. External cancellation propagates.
    

    Function detail: Called by the service and manual checker. It is the sole public
      collector operation and returns normalized evidence with complete/partial status.
    """
    normalized_cve = normalize_cve_id(cve_id)
    effective_api_key = (api_key if api_key is not None else OTX_API_KEY).strip()
    if not effective_api_key:
        raise OTXConfigurationError("OTX_API_KEY is required in your local .env file.")
    _validate_server()
    try:
        async with asyncio.timeout(OTX_TOTAL_TIMEOUT_SECONDS):
            return await _collect_cve(normalized_cve, effective_api_key, include_context)
    except TimeoutError as exc:
        raise OTXProviderUnavailableError(
            "OTX lookup exceeded its total time budget; no complete snapshot is available."
        ) from exc
    except ValidationError as exc:
        # Provider metadata violating our model is a provider response problem,
        # not bad user input. Avoid printing raw provider payloads in the CLI.
        raise OTXResponseError("OTX metadata failed the IOC model's validation.") from exc
