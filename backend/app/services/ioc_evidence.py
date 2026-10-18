"""Conservative source-record relevance review for IOC-CVE intelligence.

FILE ROLE
---------
This module decides which OTX pulse *records* are focused enough to download
in the Stage 1.3 default CVE lookup. It is deliberately a small, deterministic
policy that can be tested without HTTP, a database, Redis, or a UI.

ARCHITECTURE POSITION
---------------------
app.collectors.otx.fetch_otx_cve_iocs()
    -> discovers OTX pulses through the CVE general endpoint
    -> extracts CVE IDs from each pulse's metadata/title
    -> assess_otx_pulse() in this file
    -> fetches indicators only for selected pulses (unless the analyst opts in
       to exploratory collection of all contextual pulses)
    -> returns SourceRecordAssessment and IOCObservation models

WHAT THIS FILE OWNS
-------------------
- A conservative, documented decision based on explicit CVE strings in a
  pulse title and CVEs referenced elsewhere in the pulse metadata.
- A human-readable reason and stable reason code for later auditing/UI.

WHAT IT DOES NOT DO
-------------------
- It does not decide whether an IP/hash is malicious.
- It does not assign a numerical confidence or exploitation probability.
- It does not change IOC relationship_type to cve_associated.
- It does not approve or publish IOCs to Google SecOps.
- It does not request any external URL or store data.

WHY TITLE-BASED FILTERING IS CONSERVATIVE
-----------------------------------------
OTX returns whole-pulse indicator lists, including broad campaign collections.
A pulse with many CVEs, or a title about a different CVE, should not silently
populate the requested CVE's primary IOC view. An exact CVE in the title AND
no other CVE in available pulse metadata is necessary for 'focused_context'.
This is a *collection scope*, not validation of each indicator. Focused pulses
remain pulse_context and are not automatically detection-ready.

An interesting report whose title omits the literal CVE can land in
review_required and will be skipped by default. The analyst can explicitly
request --include-context to inspect its IOCs; later, manual review or a
provider with indicator-level evidence can establish a stronger relationship.
"""

from __future__ import annotations

from app.models.ioc import SourceRecordAssessment, SourceRecordRelevance


def assess_otx_pulse(
    *,
    requested_cve: str,
    pulse_id: str,
    title: str | None,
    pulse_url: str,
    source_record_cve_ids: list[str],
    title_cve_ids: list[str],
) -> SourceRecordAssessment:
    """Classify one OTX pulse using only its already-received metadata.

    Inputs
    ------
    requested_cve:
        Validated CVE that the collector queried.
    pulse_id, title, pulse_url:
        OTX provenance used in the terminal now and in database/UI later.
    source_record_cve_ids:
        CVEs OTX/our parser associates with the broader pulse. This includes
        the requested CVE because OTX returned the pulse for that query.
    title_cve_ids:
        CVEs literally found in the pulse's title (not tags or references).

    Returns
    -------
    SourceRecordAssessment:
        A classification and an explicit collection decision. It says nothing
        about the trustworthiness of individual indicators in the pulse.
    """

    title_set = set(title_cve_ids)
    context_set = set(source_record_cve_ids)
    other_cves = sorted(context_set - {requested_cve})

    if title_set - {requested_cve}:
        relevance = SourceRecordRelevance.BROAD_CONTEXT
        reason_code = "title_mentions_other_cve"
        reason = (
            "Pulse title mentions a CVE other than the requested one; its "
            "indicators must not be assigned to this CVE by default."
        )
    elif other_cves:
        relevance = SourceRecordRelevance.BROAD_CONTEXT
        reason_code = "multiple_cves_in_pulse"
        reason = (
            f"Pulse metadata references {len(context_set)} CVEs; its indicators "
            "are broader campaign/report context."
        )
    elif requested_cve in title_set:
        relevance = SourceRecordRelevance.FOCUSED_CONTEXT
        reason_code = "title_matches_single_cve"
        reason = (
            "The requested CVE is explicitly named in the pulse title and "
            "no other CVEs were found in available pulse metadata. Indicators "
            "remain contextual, not confirmed exploitation IOCs."
        )
    else:
        relevance = SourceRecordRelevance.REVIEW_REQUIRED
        reason_code = "no_explicit_title_match"
        reason = (
            "OTX related this pulse to the CVE, but its title does not "
            "explicitly identify that CVE. Review before collecting all of "
            "its indicators for the CVE-specific view."
        )

    return SourceRecordAssessment(
        source_record_id=pulse_id,
        source_record_name=title,
        source_record_url=pulse_url,
        source_record_cve_ids=source_record_cve_ids,
        relevance=relevance,
        reason_code=reason_code,
        reason=reason,
        selected_for_collection=(
            relevance is SourceRecordRelevance.FOCUSED_CONTEXT
        ),
    )
