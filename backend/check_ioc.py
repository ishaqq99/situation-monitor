"""Manual OTX CVE-IOC evidence and scoped-collection test (compatible with OTX V1).

FILE ROLE
---------
This is the developer/analyst command-line entry point for testing OTX
collection without a database, Redis, FastAPI, or React. It prints explicit
source-record decisions so a 2,500-IOC bulk pulse never silently becomes a
2,500-IOC list for one CVE.

ARCHITECTURE AND CALL FLOW
--------------------------
PowerShell (backend directory)
    -> python check_ioc.py CVE-2026-0300
    -> main()
    -> app.collectors.otx.fetch_otx_cve_iocs()
    -> OTX CVE endpoint + conservative pulse relevance assessment
    -> only focused pulse-indicator pages by default
    -> CVEIOCEnrichment models
    -> this file prints counts, skipped-pulse reasons and a short IOC preview

This file does NOT query PostgreSQL or Redis, classify individual IOC
maliciousness, assign a confidence score, or publish anything to Google SecOps.
The future publisher must be a separate policy-controlled component.

COMMANDS
--------
python check_ioc.py CVE-2026-0300
    Default conservative scope. Broad/ambiguous pulse metadata is displayed,
    but its entire indicator list is not downloaded.

python check_ioc.py CVE-2026-0300 --include-context
    Select every returned OTX pulse, subject to collection limits. All
    indicators remain pulse_context, and this is exploratory output only.

python check_ioc.py CVE-2026-0300 --limit 50 --pulse-limit 25
    Adjust visible IOC and pulse preview sizes without changing collection.

python check_ioc.py CVE-2026-0300 --json
    Also print the complete normalized result. Large responses can be verbose.


FILE GUIDE
----------
WHAT THIS FILE DOES
Let a developer inspect one OTX CVE lookup and its report-selection decisions.

WHY IT EXISTS
A manual diagnostic makes collector behavior understandable without starting the app.

WHO CALLS OR IMPORTS IT
A developer runs this file directly from the backend directory.

WHAT IT CALLS OR IMPORTS
Calls app.collectors.otx; does not call the worker, database, or Redis.

ROLE IN THE ARCHITECTURE
Diagnostic entry point, not the automatic production refresh path.
"""

import argparse
import asyncio
from collections import Counter, defaultdict

import httpx

from app.collectors.otx import (
    OTXAuthenticationError,
    OTXConfigurationError,
    OTXProviderUnavailableError,
    OTXNotFoundError,
    OTXRetryLaterError,
    OTXResponseError,
    fetch_otx_cve_iocs,
)


async def main(
    cve_id: str,
    *,
    include_context: bool = False,
    show_json: bool = False,
    limit: int = 20,
    pulse_limit: int = 20,
) -> int:
    """Run one lookup and explain both the fetched and intentionally skipped data.

    Inputs
    ------
    cve_id: User-requested CVE; all years are allowed.
    include_context: Opt in to fetching broad/ambiguous pulse indicators.
    show_json: Print the complete Pydantic result after the summary.
    limit/pulse_limit: Display-only limits; do not modify data collection.

    Returns
    -------
    0 on a complete lookup for the selected scope (even if no IOCs found),
    1 if the initial lookup failed, or 2 if selected pulse fetches were partial.
    Intentionally skipped pulses are *not* provider failures; collection_scope
    explicitly records that they were not fetched.
    """

    try:
        result = await fetch_otx_cve_iocs(
            cve_id,
            include_context=include_context,
        )
    except ValueError as exc:
        print(f"Invalid input: {exc}")
        return 1
    except OTXConfigurationError as exc:
        print(f"Configuration error: {exc}")
        return 1
    except OTXAuthenticationError as exc:
        print(f"Authentication error: {exc}")
        return 1
    except OTXNotFoundError as exc:
        print(f"OTX resource unavailable: {exc}")
        print("A 404 is not a verified empty IOC result.")
        return 1
    except OTXRetryLaterError as exc:
        print(f"OTX lookup deferred: {exc}")
        print(f"Retry no earlier than: {exc.retry_at.isoformat()} (UTC)")
        print("This checker does not schedule or perform that later retry.")
        return 1
    except OTXProviderUnavailableError as exc:
        print(f"OTX temporarily unavailable: {exc}")
        print("Provider failure is not proof that this CVE has zero IOCs.")
        return 1
    except OTXResponseError as exc:
        print(f"Invalid OTX response: {exc}")
        return 1
    except httpx.HTTPStatusError as exc:
        print(f"OTX returned HTTP {exc.response.status_code}.")
        return 1
    except httpx.RequestError as exc:
        print(f"Unable to communicate with OTX: {type(exc).__name__}")
        return 1

    print(f"\nCVE:                     {result.cve_id}")
    print(f"Source:                  {result.source}")
    print(f"Collection scope:        {result.collection_scope}")
    print(f"Related pulses reported: {result.source_record_count_reported}")
    print(f"Pulses fetched:          {result.source_record_count_processed}")
    print(f"Pulses skipped by scope: {result.source_record_count_skipped}")
    print(f"IOC observations fetched:{result.observation_count:>5}")
    print(f"Unique indicators fetched:{result.unique_indicator_count:>4}")
    print(f"Scope fetch complete:    {'yes' if result.complete else 'no'}")
    print("Relationship:            pulse_context (NOT direct-CVE evidence)")
    print("SecOps publishing:       not implemented / none approved")

    # Assessments preserve metadata for records whose indicator payloads were
    # deliberately skipped. '0 fetched' is therefore not confused with
    # 'the provider has 0 IOCs'.
    counts = Counter(item.relevance.value for item in result.source_record_assessments)
    if counts:
        print("\nOTX pulse relevance (metadata assessment, not IOC confidence):")
        for label, count in sorted(counts.items()):
            print(f"  {label:<20} {count}")

    if result.source_record_assessments:
        print(f"\nPulse decisions (showing up to {pulse_limit}):")
        for assessment in result.source_record_assessments[:pulse_limit]:
            status = (
                "fetched" if assessment.fetched else
                "selected but not completed" if assessment.selected_for_collection else
                "skipped by scope"
            )
            print(f"  - {assessment.source_record_name or 'Unnamed OTX pulse'}")
            print(f"    ID: {assessment.source_record_id}")
            print(f"    Relevance: {assessment.relevance.value} | {status}")
            print(f"    Reason: {assessment.reason_code}: {assessment.reason}")
            print(f"    Pulse CVEs: {', '.join(assessment.source_record_cve_ids)}")
            if assessment.indicator_count is not None:
                print(f"    Supported IOC observations fetched: {assessment.indicator_count}")
        hidden = len(result.source_record_assessments) - min(
            len(result.source_record_assessments), pulse_limit
        )
        if hidden:
            print(f"  ... {hidden} more pulse assessments not printed")

    if result.warnings:
        print("\nProvider warnings (selected lookups may need retry):")
        for warning in result.warnings:
            print(f"  - {warning}")

    unique_iocs: dict[tuple[str, str], list] = defaultdict(list)
    for observation in result.observations:
        identity = (
            observation.indicator.indicator_type.value,
            observation.indicator.value,
        )
        unique_iocs[identity].append(observation)

    if unique_iocs:
        print("\nUnique indicator types in selected scope:")
        for indicator_type, count in sorted(
            Counter(indicator_type for indicator_type, _ in unique_iocs).items()
        ):
            print(f"  {indicator_type:<10} {count}")

        print(f"\nIOC preview (up to {limit} unique indicators):")
        for indicator_type, value in sorted(unique_iocs)[:limit]:
            print(
                f"  [{indicator_type}] {value} "
                f"(OTX pulse observations: {len(unique_iocs[(indicator_type, value)])})"
            )
        hidden = len(unique_iocs) - min(len(unique_iocs), limit)
        if hidden:
            print(f"  ... {hidden} more indicators not printed")
    elif not result.complete:
        print("\nCollection is incomplete; an empty preview does not mean zero IOCs exist.")
    elif result.source_record_count_skipped:
        print(
            "\nNo supported indicators were fetched from the selected scope. "
            "Other OTX pulses were intentionally skipped; their indicator "
            "contents are UNKNOWN, not zero. Use --include-context for "
            "manual investigation."
        )
    else:
        print("\nNo supported IOC observations found in the selected pulse scope.")

    if show_json:
        print("\nComplete normalized result:")
        print(result.model_dump_json(indent=2))

    return 0 if result.complete else 2


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Conservatively assess OTX pulse context related to one CVE."
    )
    parser.add_argument("cve_id", help="For example: CVE-2026-0300")
    parser.add_argument(
        "--include-context",
        action="store_true",
        help="Fetch broad/ambiguous pulse indicators too (manual exploration only).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print all normalized results including skipped pulse assessments.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="How many unique IOC values to display (default: 20).",
    )
    parser.add_argument(
        "--pulse-limit",
        type=int,
        default=20,
        help="How many pulse assessments to display (default: 20).",
    )
    arguments = parser.parse_args()
    if arguments.limit < 0 or arguments.pulse_limit < 0:
        parser.error("--limit and --pulse-limit must be zero or greater")

    raise SystemExit(
        asyncio.run(
            main(
                arguments.cve_id,
                include_context=arguments.include_context,
                show_json=arguments.json,
                limit=arguments.limit,
                pulse_limit=arguments.pulse_limit,
            )
        )
    )
