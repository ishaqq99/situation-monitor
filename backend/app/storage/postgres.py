import os
from pathlib import Path

import asyncpg
from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parents[3]
load_dotenv(PROJECT_ROOT / ".env")

DATABASE_URL = os.getenv("DATABASE_URL")


async def open_db_connection() -> asyncpg.Connection:
    """
    Open and return one PostgreSQL connection.
    """

    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not configured")

    return await asyncpg.connect(DATABASE_URL)


async def initialize_database() -> None:
    """
    Create the KEV table and index if they do not already exist.
    """

    connection = await open_db_connection()

    try:
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

            CREATE INDEX IF NOT EXISTS idx_kev_entries_date_added
            ON kev_entries (date_added DESC);
            """
        )

    finally:
        await connection.close()


async def check_database_connection() -> bool:
    """
    Test whether PostgreSQL is reachable.
    """

    connection = None

    try:
        connection = await open_db_connection()
        await connection.execute("SELECT 1")
        return True

    except Exception:
        return False

    finally:
        if connection is not None:
            await connection.close()