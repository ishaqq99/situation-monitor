"""PostgreSQL connection pooling and schema initialization.

FILE ROLE
---------
This file owns the shared asyncpg connection pool and creates the PostgreSQL
schema used by the Situation Monitor vulnerability-intelligence features.

The current schema has three source-specific tables:
- ``kev_entries`` for CISA KEV data;
- ``epss_scores`` for the newest FIRST EPSS value for each KEV;
- ``nvd_cves`` for the newest normalized NVD enrichment for each KEV.

Keeping provider data in separate tables preserves source ownership while the
shared CVE identifier lets the service/API layer correlate the records later.

ARCHITECTURE POSITION
---------------------
FastAPI lifespan
-> initialize_pool()
-> initialize_database()
-> repositories borrow connections through db_connection()
-> background workers / API requests use repositories
-> close_database_pool() during application shutdown

Standalone developer checks such as ``check_nvd_storage.py`` call the same
startup functions because FastAPI is not running to do it for them.

WHAT THIS FILE OWNS
-------------------
- Creation and lifetime of the shared asyncpg pool.
- Safe connection borrowing through ``db_connection()``.
- Idempotent table/index creation for KEV, EPSS, and NVD current-state data.
- A small health-check query used by the API health endpoint.

WHAT THIS FILE DOES NOT DO
--------------------------
- It does not contact CISA, FIRST, or NVD.
- It does not perform provider-specific row conversion; repositories own that.
- It does not decide which CVEs need enrichment or schedule background work.
- It does not expose FastAPI routes.

SHUTDOWN ORDER
--------------
FastAPI lifespan
-> stop background workers
-> close_database_pool()
"""

import asyncio
from contextlib import asynccontextmanager

import asyncpg

from app.config import DATABASE_URL


# The pool is initialized during FastAPI startup. Keeping one shared pool is
# cheaper and more reliable than opening a new TCP connection for every query.
_pool: asyncpg.Pool | None = None


async def initialize_pool() -> None:
    """Create the application's shared PostgreSQL connection pool.

    Inputs
    ------
    No parameters. ``DATABASE_URL`` comes from ``app.config``.

    Returns
    -------
    None

    Important logic
    ---------------
    ``min_size=1`` keeps one connection ready.
    ``max_size=10`` bounds concurrent database connections.
    ``timeout=5`` bounds connection acquisition/creation.
    ``command_timeout=30`` bounds normal SQL commands.

    Called by
    ---------
    FastAPI lifespan during startup and standalone storage-check scripts.

    Failure behavior
    ----------------
    Missing configuration raises ``RuntimeError``. Connection failures from
    asyncpg propagate to the caller so startup/check scripts can report them.
    """

    global _pool

    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not configured")

    # Startup code may be called again during tests or development reloads.
    # Do not replace a pool that is already active.
    if _pool is None:
        _pool = await asyncpg.create_pool(
            DATABASE_URL,
            min_size=1,
            max_size=10,
            timeout=5,
            command_timeout=30,
        )


async def close_database_pool() -> None:
    """Close all pooled connections during application shutdown.

    A five-second deadline prevents shutdown from hanging indefinitely. If a
    graceful close times out, ``terminate()`` closes remaining connections.

    This function is intentionally safe when no pool exists so callers can put
    it in ``finally`` blocks even when startup failed partway through.
    """

    global _pool

    if _pool is None:
        return

    pool = _pool
    _pool = None

    try:
        await asyncio.wait_for(pool.close(), timeout=5)
    except TimeoutError:
        pool.terminate()


@asynccontextmanager
async def db_connection():
    """Borrow one pooled connection and return it automatically afterward.

    Usage
    -----
    ``async with db_connection() as connection:``
        ``rows = await connection.fetch("SELECT ...")``

    Repositories call this function for all normal SQL work. The connection is
    returned to the pool even when a query raises an exception.
    """

    if _pool is None:
        raise RuntimeError("Database pool has not been initialized")

    async with _pool.acquire(timeout=5) as connection:
        yield connection


async def initialize_database() -> None:
    """Create/upgrade current KEV, EPSS, and NVD storage tables.

    KEV ownership
    -------------
    ``kev_entries`` is the local catalog of vulnerabilities that CISA says are
    known to be exploited.

    EPSS ownership
    --------------
    ``epss_scores`` stores the newest FIRST score known for each local KEV.
    Its CVE ID is a foreign key to ``kev_entries`` so Situation Monitor does
    not become a general EPSS mirror.

    NVD ownership
    -------------
    ``nvd_cves`` stores the newest normalized NVD enrichment for each local
    KEV. It is also a foreign-key enrichment table because the project's V1
    scope is intentionally KEV-centered rather than a full NVD mirror.

    ``nvd_cvss_history`` stores only meaningful selected-CVSS transitions. It
    is append-only from the application perspective: normal NVD refreshes update
    the current ``nvd_cves`` row and append a history row only when the selected
    CVSS assessment actually changes.

    Safety
    ------
    ``CREATE TABLE IF NOT EXISTS`` and ``ADD COLUMN IF NOT EXISTS`` make this
    safe to run repeatedly during normal application startup. Existing KEV and
    EPSS data is preserved.
    """

    async with db_connection() as connection:
        await connection.execute(
            """
            CREATE TABLE IF NOT EXISTS kev_entries (
                cve_id TEXT PRIMARY KEY,
                vendor_project TEXT NOT NULL,
                product TEXT NOT NULL,
                vulnerability_name TEXT NOT NULL,
                date_added DATE NOT NULL,
                due_date DATE NOT NULL,
                short_description TEXT NOT NULL,
                required_action TEXT NOT NULL,
                known_ransomware_campaign_use TEXT NOT NULL,
                notes TEXT NOT NULL DEFAULT '',
                cwes JSONB NOT NULL DEFAULT '[]'::jsonb,
                first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );

            -- Idempotent additions support databases created by older project
            -- versions. Running these statements again is safe.
            ALTER TABLE kev_entries
            ADD COLUMN IF NOT EXISTS notes TEXT NOT NULL DEFAULT '';

            ALTER TABLE kev_entries
            ADD COLUMN IF NOT EXISTS cwes JSONB NOT NULL DEFAULT '[]'::jsonb;

            ALTER TABLE kev_entries
            ADD COLUMN IF NOT EXISTS first_seen_at
            TIMESTAMPTZ NOT NULL DEFAULT NOW();

            ALTER TABLE kev_entries
            ADD COLUMN IF NOT EXISTS last_seen_at
            TIMESTAMPTZ NOT NULL DEFAULT NOW();

            CREATE INDEX IF NOT EXISTS idx_kev_entries_date_added
            ON kev_entries (date_added DESC);


            CREATE TABLE IF NOT EXISTS epss_scores (
                -- One current score per CVE.
                cve_id TEXT PRIMARY KEY,

                -- FIRST publishes score and percentile on a 0-to-1 scale.
                -- Database CHECK constraints protect the table even if a
                -- future caller bypasses Pydantic validation.
                epss_score DOUBLE PRECISION NOT NULL
                    CHECK (epss_score >= 0.0 AND epss_score <= 1.0),

                percentile DOUBLE PRECISION NOT NULL
                    CHECK (percentile >= 0.0 AND percentile <= 1.0),

                -- Date associated with the score published by FIRST.
                score_date DATE NOT NULL,

                -- Time Situation Monitor stored the response.
                fetched_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

                CONSTRAINT fk_epss_kev_cve
                    FOREIGN KEY (cve_id)
                    REFERENCES kev_entries (cve_id)
                    ON DELETE CASCADE
            );

            -- Supports future sorting by highest probability.
            CREATE INDEX IF NOT EXISTS idx_epss_scores_score
            ON epss_scores (epss_score DESC);

            -- Supports finding scores older than the desired refresh date.
            CREATE INDEX IF NOT EXISTS idx_epss_scores_date
            ON epss_scores (score_date);


            CREATE TABLE IF NOT EXISTS nvd_cves (
                -- One current NVD enrichment record per locally stored KEV.
                cve_id TEXT PRIMARY KEY,

                -- Source/lifecycle fields come directly from the normalized
                -- NVDCVE model produced by app.collectors.nvd.
                source_identifier TEXT,
                published_at TIMESTAMPTZ NOT NULL,
                last_modified_at TIMESTAMPTZ NOT NULL,
                vuln_status TEXT,
                description TEXT,

                -- Selected current CVSS assessment. These fields are nullable
                -- because a valid NVD CVE may temporarily have no usable CVSS.
                cvss_version TEXT,
                cvss_base_score DOUBLE PRECISION
                    CHECK (
                        cvss_base_score IS NULL
                        OR (cvss_base_score >= 0.0 AND cvss_base_score <= 10.0)
                    ),
                cvss_base_severity TEXT,
                cvss_vector_string TEXT,
                cvss_source TEXT,
                cvss_metric_type TEXT,
                cvss_exploitability_score DOUBLE PRECISION
                    CHECK (
                        cvss_exploitability_score IS NULL
                        OR cvss_exploitability_score >= 0.0
                    ),
                cvss_impact_score DOUBLE PRECISION
                    CHECK (
                        cvss_impact_score IS NULL
                        OR cvss_impact_score >= 0.0
                    ),

                -- Provider arrays are stored as JSONB so the normalized lists
                -- remain queryable without flattening them into extra tables
                -- during this early stage.
                cwes JSONB NOT NULL DEFAULT '[]'::jsonb,
                affected_cpes JSONB NOT NULL DEFAULT '[]'::jsonb,
                reference_urls JSONB NOT NULL DEFAULT '[]'::jsonb,

                -- Time the collector fetched this particular normalized view.
                fetched_at TIMESTAMPTZ NOT NULL,

                -- Enforces the project's chosen scope: NVD is enrichment for
                -- KEVs, not a mirror of every CVE published by NVD.
                CONSTRAINT fk_nvd_kev_cve
                    FOREIGN KEY (cve_id)
                    REFERENCES kev_entries (cve_id)
                    ON DELETE CASCADE,

                -- If CVSS exists, the three fields required by NVDCVSSMetric
                -- must exist together. If no CVSS exists, all three are null.
                CONSTRAINT chk_nvd_cvss_core_fields
                    CHECK (
                        (
                            cvss_version IS NULL
                            AND cvss_base_score IS NULL
                            AND cvss_vector_string IS NULL
                        )
                        OR
                        (
                            cvss_version IS NOT NULL
                            AND cvss_base_score IS NOT NULL
                            AND cvss_vector_string IS NOT NULL
                        )
                    )
            );

            -- Useful later when the refresh service searches for stale NVD
            -- records or the UI sorts KEVs by technical severity.
            CREATE INDEX IF NOT EXISTS idx_nvd_cves_last_modified
            ON nvd_cves (last_modified_at);

            CREATE INDEX IF NOT EXISTS idx_nvd_cves_cvss_score
            ON nvd_cves (cvss_base_score DESC);


            CREATE TABLE IF NOT EXISTS nvd_cvss_history (
                -- Surrogate key keeps multiple legitimate changes for one CVE.
                id BIGSERIAL PRIMARY KEY,

                cve_id TEXT NOT NULL,

                -- Time Situation Monitor observed the transition and the NVD
                -- last-modified timestamp associated with the incoming record.
                observed_at TIMESTAMPTZ NOT NULL,
                nvd_last_modified_at TIMESTAMPTZ NOT NULL,

                -- Previous selected CVSS assessment. Every field is nullable
                -- so history can represent a CVE that previously had no CVSS.
                previous_cvss_version TEXT,
                previous_base_score DOUBLE PRECISION,
                previous_base_severity TEXT,
                previous_vector_string TEXT,
                previous_source TEXT,
                previous_metric_type TEXT,
                previous_exploitability_score DOUBLE PRECISION,
                previous_impact_score DOUBLE PRECISION,

                -- New selected CVSS assessment. Nullable for the inverse case:
                -- a provider revision that no longer exposes a usable metric.
                current_cvss_version TEXT,
                current_base_score DOUBLE PRECISION,
                current_base_severity TEXT,
                current_vector_string TEXT,
                current_source TEXT,
                current_metric_type TEXT,
                current_exploitability_score DOUBLE PRECISION,
                current_impact_score DOUBLE PRECISION,

                CONSTRAINT fk_nvd_cvss_history_cve
                    FOREIGN KEY (cve_id)
                    REFERENCES nvd_cves (cve_id)
                    ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_nvd_cvss_history_cve_time
            ON nvd_cvss_history (cve_id, observed_at DESC);
            """
        )


async def check_database_connection() -> bool:
    """Return whether PostgreSQL accepts a simple query through the pool.

    The health endpoint needs a Boolean result, so database exceptions are
    intentionally converted to ``False`` here rather than being exposed as an
    HTTP traceback.
    """

    try:
        async with db_connection() as connection:
            await connection.execute("SELECT 1")
        return True
    except Exception:
        return False
