"""PostgreSQL connection pooling and schema initialization.

FILE ROLE
---------
This file owns the shared asyncpg connection pool and creates the tables used
by the CISA KEV and FIRST EPSS features.

Repositories borrow connections through db_connection(). They do not create
or close long-lived connections themselves.

STARTUP ORDER
-------------
FastAPI lifespan
    -> initialize_pool()
    -> initialize_database()
    -> serve requests

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

    min_size=1 keeps one connection ready.
    max_size=10 bounds concurrent database connections.
    timeout=5 bounds connection acquisition/creation.
    command_timeout=30 bounds normal SQL commands.
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

    A five-second deadline prevents shutdown from hanging indefinitely. If
    graceful close times out, terminate the remaining pool connections.
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
    """Borrow one connection and return it automatically after the query.

    Usage:

        async with db_connection() as connection:
            rows = await connection.fetch("SELECT ...")

    The connection returns to the pool even when the query raises an error.
    """
    if _pool is None:
        raise RuntimeError("Database pool has not been initialized")

    async with _pool.acquire(timeout=5) as connection:
        yield connection


async def initialize_database() -> None:
    """Create or upgrade the KEV schema and create the EPSS storage table.

    epss_scores stores the newest EPSS value known for each locally stored KEV.
    cve_id is both its primary key and a foreign key to kev_entries.

    Consequently:
    - one CVE has at most one current EPSS row;
    - EPSS enrichment is stored only for CVEs in the local KEV catalog;
    - deleting a KEV row also deletes its EPSS row.
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
            """
        )


async def check_database_connection() -> bool:
    """Return whether PostgreSQL accepts a simple query through the pool.

    The health endpoint needs a Boolean result, so database exceptions are
    intentionally converted to False here.
    """
    try:
        async with db_connection() as connection:
            await connection.execute("SELECT 1")
        return True
    except Exception:
        return False

