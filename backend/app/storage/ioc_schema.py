"""Add durable OTX jobs, source evidence, lifecycle state, and run summaries.

Called by FastAPI after the existing KEV schema is initialized. All DDL is
additive and repeatable. This module uses the existing PostgreSQL pool; it does
not create a second pool or touch Redis. Each table has a documented purpose.


FILE GUIDE
----------
WHAT THIS FILE DOES
Create the additive PostgreSQL tables and indexes for OTX jobs and evidence.

WHY IT EXISTS
Durable jobs, provenance, and cooldowns must survive API restarts.

WHO CALLS OR IMPORTS IT
app.main.lifespan calls initialize_ioc_schema after the existing KEV schema exists.

WHAT IT CALLS OR IMPORTS
Uses app.storage.postgres's existing shared connection pool.

ROLE IN THE ARCHITECTURE
Schema/migration boundary; it never downloads provider data.
"""

from app.storage.postgres import db_connection


IOC_SCHEMA_SQL = """
-- One provider-wide row persists cooldowns through Uvicorn/process restarts.
CREATE TABLE IF NOT EXISTS otx_provider_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    next_allowed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    heartbeat_at TIMESTAMPTZ,
    last_error TEXT,
    blocked_kind TEXT,
    key_fingerprint TEXT
);
INSERT INTO otx_provider_state(id) VALUES (1) ON CONFLICT DO NOTHING;

-- One recurring job for EVERY local KEV, without a CVE-age predicate.
CREATE TABLE IF NOT EXISTS otx_jobs (
    cve_id TEXT PRIMARY KEY REFERENCES kev_entries(cve_id) ON DELETE CASCADE,
    state TEXT NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending','running','complete','partial','failed','deferred')),
    next_check_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_attempt_at TIMESTAMPTZ,
    last_success_at TIMESTAMPTZ,
    last_manual_at TIMESTAMPTZ,
    last_error TEXT,
    run_id UUID,
    summary JSONB,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS otx_jobs_due_idx ON otx_jobs(next_check_at, cve_id);

-- Audit summaries distinguish empty success, failure, partial, and cooldown.
CREATE TABLE IF NOT EXISTS otx_runs (
    run_id UUID PRIMARY KEY,
    cve_id TEXT NOT NULL REFERENCES kev_entries(cve_id) ON DELETE CASCADE,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at TIMESTAMPTZ,
    outcome TEXT NOT NULL DEFAULT 'running',
    summary JSONB,
    error TEXT
);
CREATE INDEX IF NOT EXISTS otx_runs_cve_idx ON otx_runs(cve_id, started_at DESC);

-- SHA-256 keys avoid PostgreSQL's B-tree entry-size limit for long URLs.
-- The original value/type remain available; hashes are never displayed as IOCs.
CREATE TABLE IF NOT EXISTS otx_indicators (
    indicator_key CHAR(64) PRIMARY KEY,
    indicator_type TEXT NOT NULL,
    value TEXT NOT NULL,
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL
);

-- Shared pulse metadata is stored once rather than repeated per indicator.
CREATE TABLE IF NOT EXISTS otx_reports (
    pulse_id TEXT PRIMARY KEY,
    metadata JSONB NOT NULL,
    checked_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS otx_cve_reports (
    cve_id TEXT NOT NULL REFERENCES kev_entries(cve_id) ON DELETE CASCADE,
    pulse_id TEXT NOT NULL REFERENCES otx_reports(pulse_id),
    assessment JSONB NOT NULL,
    checked_at TIMESTAMPTZ NOT NULL,
    in_latest_metadata BOOLEAN NOT NULL DEFAULT TRUE,
    PRIMARY KEY (cve_id, pulse_id)
);

-- Presence is source/scope-specific. Missing on a failed or partial refresh
-- must NEVER be interpreted as removal. Historical rows are retained.
CREATE TABLE IF NOT EXISTS otx_observations (
    cve_id TEXT NOT NULL REFERENCES kev_entries(cve_id) ON DELETE CASCADE,
    pulse_id TEXT NOT NULL REFERENCES otx_reports(pulse_id),
    indicator_key CHAR(64) NOT NULL REFERENCES otx_indicators(indicator_key),
    evidence JSONB NOT NULL,
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    absent_since TIMESTAMPTZ,
    PRIMARY KEY (cve_id, pulse_id, indicator_key)
);
CREATE INDEX IF NOT EXISTS otx_observations_current_idx
    ON otx_observations(cve_id, last_seen_at DESC) WHERE absent_since IS NULL;
"""


async def initialize_ioc_schema() -> None:
    """Apply the additive schema atomically through the existing shared pool.

    Function detail: Called once per FastAPI startup after KEV initialization. A
      transaction and advisory lock serialize additive DDL across multiple app processes.
    """
    async with db_connection() as connection:
        async with connection.transaction():
            # Serialize this DDL across multiple Uvicorn processes at startup.
            await connection.execute("SELECT pg_advisory_xact_lock(73419021)")
            await connection.execute(IOC_SCHEMA_SQL)
