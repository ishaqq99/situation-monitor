"""Manual EPSS lookup before connecting the feature to the dashboard.

RUN FROM YOUR BACKEND DIRECTORY
------------------------------
python check_epss.py CVE-2021-44228

WHO CALLS WHAT
--------------
Terminal -> argparse -> asyncio.run(main()) -> fetch_epss_score()
    -> FIRST -> EPSSScore -> readable terminal output

This script needs internet access and the project's Python dependencies.
It does not use FastAPI, React, PostgreSQL, or Redis.
"""

import argparse
import asyncio

import httpx

from app.collectors.epss import EPSSResponseError, fetch_epss_score


async def main(cve_id: str) -> int:
    """Print a lookup result and return a process exit code.

    0 means the lookup completed, including a successful empty result.
    1 means the request failed or the input/response was invalid.
    """
    try:
        score = await fetch_epss_score(cve_id)
    except ValueError as exc:
        print(f"Invalid input: {exc}")
        return 1
    except EPSSResponseError as exc:
        print(f"Invalid API response: {exc}")
        return 1
    except httpx.HTTPStatusError as exc:
        print(f"FIRST returned HTTP {exc.response.status_code}.")
        return 1
    except httpx.RequestError as exc:
        print(f"Unable to communicate with FIRST: {type(exc).__name__}")
        return 1
    except TimeoutError:
        print("The EPSS lookup exceeded its time limit.")
        return 1

    if score is None:
        # Do not display '0%' when the actual state is 'not available'.
        print(f"No EPSS score is available for {cve_id.strip().upper()}.")
        return 0

    print()
    print(f"CVE:              {score.cve_id}")
    print(f"Score date:       {score.score_date}")

    # Percentage formatting converts 0.12 into '12.00%'.
    print(f"EPSS probability: {score.epss_score:.2%}")
    print(f"Percentile rank:  {score.percentile * 100:.2f} / 100")
    print()
    print("Normalized application data:")

    # JSON serialization converts the Python date back to an ISO string.
    # The raw probability is retained, even if display rounding shows 0.00%.
    print(score.model_dump_json(indent=2))
    return 0


if __name__ == "__main__":
    # This block runs only when executed directly, not when imported.
    parser = argparse.ArgumentParser(description="Look up one CVE's EPSS score.")
    parser.add_argument("cve_id", help="For example: CVE-2021-44228")
    arguments = parser.parse_args()

    # A standalone script starts its own event loop. FastAPI will supply
    # one later when the collector is called from an asynchronous route.
    raise SystemExit(asyncio.run(main(arguments.cve_id)))
