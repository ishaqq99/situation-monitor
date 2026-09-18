"""Manual end-to-end EPSS storage check.

RUN FROM THE BACKEND DIRECTORY
------------------------------
python check_epss_storage.py CVE-2021-44228

Unlike check_epss.py, this script requires PostgreSQL. The selected CVE must
already exist in kev_entries because epss_scores is an enrichment table with a
foreign key to the local CISA KEV catalog.

FLOW
----
input -> FIRST collector -> EPSSScore -> repository upsert -> repository read
"""

import argparse
import asyncio

import asyncpg
import httpx

from app.collectors.epss import EPSSResponseError, fetch_epss_score
from app.storage.epss_repository import (
    get_epss_score_by_cve,
    upsert_epss_score,
)
from app.storage.postgres import (
    close_database_pool,
    initialize_database,
    initialize_pool,
)


async def main(cve_id: str) -> int:
    """Fetch, store, and read back one score; return a process exit code."""
    try:
        # A standalone script must perform the startup normally handled by
        # FastAPI's lifespan function.
        await initialize_pool()
        await initialize_database()

        score = await fetch_epss_score(cve_id)

        if score is None:
            print(f"FIRST has no EPSS score for {cve_id.strip().upper()}.")
            return 0

        stored_score = await upsert_epss_score(score)
        retrieved_score = await get_epss_score_by_cve(stored_score.cve_id)

        if retrieved_score is None:
            print("The score was stored but could not be read back.")
            return 1

        print()
        print("EPSS score stored successfully")
        print()
        print(retrieved_score.model_dump_json(indent=2))
        return 0

    except ValueError as exc:
        print(f"Invalid input: {exc}")
        return 1
    except EPSSResponseError as exc:
        print(f"Invalid FIRST response: {exc}")
        return 1
    except httpx.HTTPStatusError as exc:
        print(f"FIRST returned HTTP {exc.response.status_code}.")
        return 1
    except httpx.RequestError as exc:
        print(f"Unable to communicate with FIRST: {type(exc).__name__}")
        return 1
    except asyncpg.ForeignKeyViolationError:
        print("This CVE is not stored in the local CISA KEV table.")
        print("Choose a CVE currently displayed in your KEV dashboard.")
        return 1
    except asyncpg.PostgresError as exc:
        print(f"PostgreSQL error: {type(exc).__name__}")
        return 1
    except TimeoutError:
        print("The operation exceeded its time limit.")
        return 1
    finally:
        # Safe even if pool initialization failed: close_database_pool() simply
        # returns when no pool exists.
        await close_database_pool()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Fetch and store EPSS for one locally stored KEV CVE."
    )
    parser.add_argument(
        "cve_id",
        help="A CVE currently stored in the local CISA KEV catalog.",
    )
    arguments = parser.parse_args()
    raise SystemExit(asyncio.run(main(arguments.cve_id)))

