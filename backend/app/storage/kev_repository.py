"""PostgreSQL boundary for KEV ingestion, latest records, search, and details.

Routes call the service; the service calls this module. SQL and asyncpg row
conversion stay here so callers only handle validated KEVEntry objects.
"""
import json
from app.models.kev import KEVEntry
from app.storage.postgres import db_connection

COLUMNS = """cve_id, vendor_project, product, vulnerability_name, date_added,
    due_date, short_description, required_action,
    known_ransomware_campaign_use, notes, cwes"""


def _row_to_kev_entry(row) -> KEVEntry:
    """Decode asyncpg's JSONB representation before Pydantic validation."""
    values = dict(row)
    if isinstance(values["cwes"], str):
        values["cwes"] = json.loads(values["cwes"])
    return KEVEntry.model_validate(values)


async def upsert_kev_entries(entries: list[KEVEntry]) -> int:
    """Persist a complete batch atomically; preserve each CVE's first_seen_at.

An upstream correction replaces mutable fields. A failed batch rolls back
rather than leaving PostgreSQL with a partially refreshed catalog.
"""
    if not entries:
        return 0
    rows = [(
        e.cve_id, e.vendor_project, e.product, e.vulnerability_name,
        e.date_added, e.due_date, e.short_description, e.required_action,
        e.known_ransomware_campaign_use, e.notes, json.dumps(e.cwes),
    ) for e in entries]
    async with db_connection() as connection:
        async with connection.transaction():
            await connection.executemany(f"""
                INSERT INTO kev_entries ({COLUMNS})
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb)
                ON CONFLICT (cve_id) DO UPDATE SET
                    vendor_project = EXCLUDED.vendor_project,
                    product = EXCLUDED.product,
                    vulnerability_name = EXCLUDED.vulnerability_name,
                    date_added = EXCLUDED.date_added,
                    due_date = EXCLUDED.due_date,
                    short_description = EXCLUDED.short_description,
                    required_action = EXCLUDED.required_action,
                    known_ransomware_campaign_use = EXCLUDED.known_ransomware_campaign_use,
                    notes = EXCLUDED.notes,
                    cwes = EXCLUDED.cwes,
                    last_seen_at = NOW()
            """, rows)
    return len(rows)


async def get_latest_kev_entries(limit: int = 50) -> list[KEVEntry]:
    """Read newest records with deterministic ordering for same-day additions."""
    async with db_connection() as connection:
        rows = await connection.fetch(f"""
            SELECT {COLUMNS} FROM kev_entries
            ORDER BY date_added DESC, cve_id DESC LIMIT $1
        """, limit)
    return [_row_to_kev_entry(row) for row in rows]


async def search_kev_entries(search_term: str, limit: int = 50) -> list[KEVEntry]:
    """Search stored records; treat percent and underscore as literal input."""
    escaped = search_term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    async with db_connection() as connection:
        rows = await connection.fetch(f"""
            SELECT {COLUMNS} FROM kev_entries
            WHERE cve_id ILIKE $1 OR vendor_project ILIKE $1
                OR product ILIKE $1 OR vulnerability_name ILIKE $1
                OR short_description ILIKE $1
            ORDER BY date_added DESC, cve_id DESC LIMIT $2
        """, f"%{escaped}%", limit)
    return [_row_to_kev_entry(row) for row in rows]


async def get_kev_entry_by_cve(cve_id: str) -> KEVEntry | None:
    """Normalize the lookup value, allowing PostgreSQL to use its primary key."""
    async with db_connection() as connection:
        row = await connection.fetchrow(
            f"SELECT {COLUMNS} FROM kev_entries WHERE cve_id = $1",
            cve_id.strip().upper(),
        )
    return _row_to_kev_entry(row) if row is not None else None
