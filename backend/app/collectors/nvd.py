"""Fetch and normalize one CVE from the NVD CVE API 2.0.

FILE ROLE
---------
This is Situation Monitor's provider-facing NVD layer. It knows how to talk to
NVD and how to translate NVD's nested JSON into the stable Pydantic models in
``app.models.nvd``.

ARCHITECTURE POSITION
---------------------
Stage 1:
    terminal/check_nvd.py -> fetch_nvd_cve() -> NVD -> parse_nvd_cve_response()
        -> NVDCVE

Future stages:
    NVD service/worker -> fetch_nvd_cve() -> NVDCVE -> PostgreSQL

WHO CALLS THIS FILE
-------------------
- Stage 1: ``backend/check_nvd.py``.
- Unit tests: ``backend/tests/test_nvd.py``.
- Later: the NVD service will call this collector only for CVE IDs selected
  from the local KEV catalog.

WHAT THIS FILE CALLS
--------------------
- ``httpx`` for the external HTTPS request.
- Pydantic models from ``app.models.nvd`` for application-level validation.

WHAT THIS FILE DOES NOT DO
--------------------------
- It does not query the local KEV database. The future service layer will
  decide which KEV CVEs need enrichment.
- It does not write PostgreSQL or Redis.
- It does not schedule refreshes.
- It does not expose FastAPI routes.

CVSS SELECTION POLICY
---------------------
NVD can return several metrics for the same CVE and they may come from NVD or
another source. Situation Monitor needs one clear current metric for its first
UI, while still preserving the source/type that produced it.

The selector therefore:
1. Prefers the newest supported CVSS version: 4.0, then 3.1, 3.0, then 2.0.
2. Within one version, prefers an ``nvd@nist.gov`` assessment when available.
3. Otherwise prefers a metric marked ``Primary``.
4. Otherwise uses the first valid metric returned for that version.

A CVE with no usable CVSS metric is still a valid NVD result. Its ``cvss``
field is ``None``.
"""

import re
from collections.abc import Iterable

import httpx
from pydantic import ValidationError

from app.config import NVD_API_KEY
from app.models.nvd import NVDCVE, NVDCVSSMetric


NVD_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_PATTERN = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")
CWE_PATTERN = re.compile(r"CWE-[0-9]+")

# Each request is still a targeted CVE lookup. Automated pacing between
# requests is owned by the service layer; this provider layer owns HTTP headers,
# timeout behavior, and response normalization.
NVD_REQUEST_TIMEOUT_SECONDS = 30.0

# The API currently exposes metrics under these keys. The order expresses the
# application's preference for newer CVSS standards when more than one exists.
CVSS_METRIC_GROUPS = (
    "cvssMetricV40",
    "cvssMetricV31",
    "cvssMetricV30",
    "cvssMetricV2",
)


class NVDResponseError(RuntimeError):
    """NVD responded, but the response could not be trusted or normalized."""


def normalize_cve_id(cve_id: str) -> str:
    """Normalize and validate a CVE ID before it is sent to NVD.

    Parameters
    ----------
    cve_id:
        User/service supplied identifier, for example ``" cve-2021-44228 "``.

    Returns
    -------
    str
        Uppercase, whitespace-trimmed identifier such as ``CVE-2021-44228``.

    Raises
    ------
    ValueError
        If the identifier does not match the public CVE identifier format.

    Called by
    ---------
    ``fetch_nvd_cve()`` and ``parse_nvd_cve_response()``. The second call is
    intentional defensive validation: parsing should remain safe even when it
    is tested or reused without the network function.
    """

    cleaned_id = cve_id.strip().upper()
    if CVE_PATTERN.fullmatch(cleaned_id) is None:
        raise ValueError("Enter a CVE ID such as CVE-2021-44228.")
    return cleaned_id


def _english_description(descriptions: object) -> str | None:
    """Return the preferred English description without inventing text.

    NVD normally supplies a list of language/value objects. We prefer ``en``;
    if English is absent, the first non-empty textual description is retained
    so the CVE can still be useful. Invalid entries are ignored rather than
    crashing an otherwise valid CVE record.
    """

    if not isinstance(descriptions, list):
        return None

    fallback: str | None = None
    for item in descriptions:
        if not isinstance(item, dict):
            continue
        value = item.get("value")
        if not isinstance(value, str) or not value.strip():
            continue
        cleaned_value = value.strip()
        if fallback is None:
            fallback = cleaned_value
        if item.get("lang") == "en":
            return cleaned_value

    return fallback


def _deduplicate(values: Iterable[str]) -> list[str]:
    """Preserve provider order while removing duplicate non-empty strings."""

    unique: list[str] = []
    seen: set[str] = set()

    for value in values:
        if value and value not in seen:
            seen.add(value)
            unique.append(value)

    return unique


def _extract_cwes(weaknesses: object) -> list[str]:
    """Extract normalized CWE identifiers from NVD weakness descriptions.

    NVD weakness entries can come from several sources and may repeat the same
    CWE. Only values shaped like ``CWE-79`` or ``CWE-787`` are retained. Text
    such as ``NVD-CWE-noinfo`` is deliberately excluded from this ID list.
    """

    if not isinstance(weaknesses, list):
        return []

    values: list[str] = []
    for weakness in weaknesses:
        if not isinstance(weakness, dict):
            continue
        descriptions = weakness.get("description")
        if not isinstance(descriptions, list):
            continue
        for description in descriptions:
            if not isinstance(description, dict):
                continue
            value = description.get("value")
            if isinstance(value, str):
                cleaned_value = value.strip().upper()
                if CWE_PATTERN.fullmatch(cleaned_value):
                    values.append(cleaned_value)

    return _deduplicate(values)


def _walk_configuration_node(node: object) -> list[str]:
    """Recursively collect vulnerable CPE criteria from one configuration node.

    NVD configuration trees may include CPEs that describe vulnerable software
    and other CPEs used only as environmental/platform constraints. For the
    first Situation Monitor model we retain entries explicitly marked
    ``vulnerable: true`` so the field means "affected CPE" rather than "every
    CPE mentioned in the applicability expression".
    """

    if not isinstance(node, dict):
        return []

    results: list[str] = []

    cpe_matches = node.get("cpeMatch")
    if isinstance(cpe_matches, list):
        for match in cpe_matches:
            if not isinstance(match, dict) or match.get("vulnerable") is not True:
                continue
            criteria = match.get("criteria")
            if isinstance(criteria, str) and criteria.strip():
                results.append(criteria.strip())

    # Keeping this recursive makes the parser tolerant of nested configuration
    # trees without requiring storage/UI code to understand that structure.
    child_nodes = node.get("nodes")
    if isinstance(child_nodes, list):
        for child in child_nodes:
            results.extend(_walk_configuration_node(child))

    return results


def _extract_affected_cpes(configurations: object) -> list[str]:
    """Return unique vulnerable CPE criteria from all NVD configurations."""

    if not isinstance(configurations, list):
        return []

    values: list[str] = []
    for configuration in configurations:
        if not isinstance(configuration, dict):
            continue

        # API 2.0 commonly places applicability nodes inside each configuration.
        nodes = configuration.get("nodes")
        if isinstance(nodes, list):
            for node in nodes:
                values.extend(_walk_configuration_node(node))

        # This also handles a configuration object that itself carries cpeMatch.
        values.extend(_walk_configuration_node(configuration))

    return _deduplicate(values)


def _extract_reference_urls(references: object) -> list[str]:
    """Return unique non-empty reference URLs in provider order."""

    if not isinstance(references, list):
        return []

    values: list[str] = []
    for reference in references:
        if not isinstance(reference, dict):
            continue
        url = reference.get("url")
        if isinstance(url, str) and url.strip():
            values.append(url.strip())

    return _deduplicate(values)


def _normalize_optional_score(value: object) -> float | None:
    """Convert an optional numeric subscore while rejecting non-finite values.

    The Pydantic model performs the final bounds/finite validation. Returning
    ``None`` here means the provider did not supply the subscore, not that its
    value is zero.
    """

    if value is None:
        return None
    return float(value)


def _parse_cvss_candidate(candidate: object) -> NVDCVSSMetric | None:
    """Normalize one raw NVD metric candidate.

    Invalid individual candidates are ignored so that one malformed secondary
    metric does not hide another valid metric for the same CVE. Structural
    corruption of the overall response is handled by the higher-level parser.
    """

    if not isinstance(candidate, dict):
        return None

    cvss_data = candidate.get("cvssData")
    if not isinstance(cvss_data, dict):
        return None

    try:
        version = str(cvss_data["version"]).strip()
        vector = str(cvss_data["vectorString"]).strip()
        base_score = float(cvss_data["baseScore"])

        # Newer CVSS versions normally expose baseSeverity inside cvssData.
        # CVSS v2 payloads may instead place severity on the metric wrapper.
        severity = cvss_data.get("baseSeverity", candidate.get("baseSeverity"))
        if severity is not None:
            severity = str(severity).strip().upper() or None

        source = candidate.get("source")
        if source is not None:
            source = str(source).strip() or None

        metric_type = candidate.get("type")
        if metric_type is not None:
            metric_type = str(metric_type).strip() or None

        return NVDCVSSMetric(
            cvss_version=version,
            base_score=base_score,
            base_severity=severity,
            vector_string=vector,
            source=source,
            metric_type=metric_type,
            exploitability_score=_normalize_optional_score(
                candidate.get("exploitabilityScore")
            ),
            impact_score=_normalize_optional_score(candidate.get("impactScore")),
        )
    except (KeyError, TypeError, ValueError, ValidationError):
        return None


def _metric_preference(metric: NVDCVSSMetric) -> tuple[int, int]:
    """Rank metrics within the same CVSS version.

    The first tuple item prefers NVD's own assessment. The second prefers a
    provider metric marked Primary. ``max()`` can therefore choose the most
    useful candidate while the original list order breaks any remaining tie.
    """

    source = (metric.source or "").lower()
    metric_type = (metric.metric_type or "").lower()
    return (
        1 if source == "nvd@nist.gov" else 0,
        1 if metric_type == "primary" else 0,
    )


def select_preferred_cvss(metrics: object) -> NVDCVSSMetric | None:
    """Select one preferred valid CVSS metric from NVD's metrics object.

    Parameters
    ----------
    metrics:
        Raw ``cve.metrics`` value from the NVD API.

    Returns
    -------
    NVDCVSSMetric | None
        The selected normalized metric, or ``None`` when no usable metric is
        available. Missing CVSS is valid data and must not become ``0.0``.

    Important logic
    ---------------
    Metric groups are checked in modern-version order (4.0 -> 3.1 -> 3.0 ->
    2.0). As soon as a group contains at least one valid candidate, the best
    candidate in that group is returned.
    """

    if metrics is None:
        return None
    if not isinstance(metrics, dict):
        raise NVDResponseError("NVD returned an invalid metrics object.")

    for group_name in CVSS_METRIC_GROUPS:
        raw_candidates = metrics.get(group_name)
        if not isinstance(raw_candidates, list) or not raw_candidates:
            continue

        candidates = [
            metric
            for raw_candidate in raw_candidates
            if (metric := _parse_cvss_candidate(raw_candidate)) is not None
        ]
        if candidates:
            return max(candidates, key=_metric_preference)

    return None


def parse_nvd_cve_response(payload: object, requested_cve: str) -> NVDCVE | None:
    """Validate a targeted NVD response and normalize the requested CVE.

    Parameters
    ----------
    payload:
        Python object produced from the NVD JSON response.
    requested_cve:
        CVE identifier that Situation Monitor asked NVD to return.

    Returns
    -------
    NVDCVE | None
        A validated record when NVD has the CVE, or ``None`` when NVD reports
        zero results for that exact identifier.

    Raises
    ------
    NVDResponseError
        If NVD returns an unexpected shape, more than one record for a targeted
        lookup, a different CVE ID, or data that cannot form a trusted model.

    Why the returned ID is checked
    -----------------------------
    A targeted enrichment job must never accidentally save data for the wrong
    CVE. The parser therefore verifies the returned identifier even though the
    request itself used NVD's ``cveId`` parameter.
    """

    normalized_request = normalize_cve_id(requested_cve)

    if not isinstance(payload, dict):
        raise NVDResponseError("NVD returned an unexpected response format.")

    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        raise NVDResponseError("NVD response did not contain a vulnerability list.")

    total_results = payload.get("totalResults")
    if not isinstance(total_results, int):
        raise NVDResponseError("NVD response did not contain a valid result count.")
    if total_results != len(vulnerabilities):
        raise NVDResponseError("NVD returned an inconsistent targeted result count.")
    if total_results == 0:
        return None
    if total_results != 1:
        raise NVDResponseError("A targeted NVD CVE lookup returned multiple records.")

    wrapper = vulnerabilities[0]
    if not isinstance(wrapper, dict):
        raise NVDResponseError("NVD returned an invalid vulnerability wrapper.")

    raw_cve = wrapper.get("cve")
    if not isinstance(raw_cve, dict):
        raise NVDResponseError("NVD returned an invalid CVE record.")

    returned_id = raw_cve.get("id")
    if not isinstance(returned_id, str):
        raise NVDResponseError("NVD CVE record did not contain an identifier.")

    try:
        normalized_returned_id = normalize_cve_id(returned_id)
    except ValueError as exc:
        raise NVDResponseError("NVD returned an invalid CVE identifier.") from exc

    if normalized_returned_id != normalized_request:
        raise NVDResponseError("NVD returned a different CVE than requested.")

    try:
        return NVDCVE(
            cve_id=normalized_returned_id,
            source_identifier=raw_cve.get("sourceIdentifier"),
            published_at=raw_cve["published"],
            last_modified_at=raw_cve["lastModified"],
            vuln_status=raw_cve.get("vulnStatus"),
            description=_english_description(raw_cve.get("descriptions")),
            cvss=select_preferred_cvss(raw_cve.get("metrics")),
            cwes=_extract_cwes(raw_cve.get("weaknesses")),
            affected_cpes=_extract_affected_cpes(raw_cve.get("configurations")),
            reference_urls=_extract_reference_urls(raw_cve.get("references")),
        )
    except (KeyError, TypeError, ValueError, ValidationError) as exc:
        raise NVDResponseError("NVD returned an invalid CVE data record.") from exc


def _request_headers() -> dict[str, str]:
    """Build provider headers without exposing the API key to other layers.

    NVD accepts an optional ``apiKey`` request header. The key is read once by
    ``app.config`` from the project root ``.env`` file. The header is omitted
    entirely when no key is configured, so Stage 1/manual lookups still work
    with public NVD access.
    """

    headers = {"User-Agent": "Situation-Monitor/0.1"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    return headers


async def fetch_nvd_cve(cve_id: str) -> NVDCVE | None:
    """Fetch one targeted CVE from NVD and return the normalized model.

    Parameters
    ----------
    cve_id:
        CVE to enrich. Automated callers supply only IDs selected from the
        local KEV catalog. Manual check scripts may supply an ID directly.

    Returns
    -------
    NVDCVE | None
        Normalized NVD data, or ``None`` when NVD reports zero results.

    External calls
    --------------
    Sends one HTTPS GET request to the NVD CVE API 2.0 using the ``cveId``
    parameter. If ``NVD_API_KEY`` is configured, it is sent in NVD's ``apiKey``
    header. Request spacing across multiple CVEs is deliberately handled by
    ``nvd_service.py`` so this collector remains responsible for one request.

    Failure behavior
    ----------------
    ``httpx`` HTTP/network exceptions propagate to the service/API boundary.
    That lets the service distinguish provider rate limiting from individual
    CVE parse failures. Invalid JSON becomes ``NVDResponseError`` because NVD
    responded but did not provide usable application data.
    """

    normalized_cve = normalize_cve_id(cve_id)

    async with httpx.AsyncClient(
        timeout=NVD_REQUEST_TIMEOUT_SECONDS,
        follow_redirects=True,
        headers=_request_headers(),
    ) as client:
        response = await client.get(
            NVD_CVE_API_URL,
            params={"cveId": normalized_cve},
        )
        response.raise_for_status()

        try:
            payload = response.json()
        except ValueError as exc:
            raise NVDResponseError("NVD returned invalid JSON.") from exc

    return parse_nvd_cve_response(payload, normalized_cve)
