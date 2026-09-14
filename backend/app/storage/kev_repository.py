import json

from app.models.kev import KEVEntry
from app.storage.postgres import open_db_connection


async def upsert_kev_entries(entries: list[KEVEntry]) -> int:
    """
    Insert new CVEs and update existing CVEs in PostgreSQL.
    """

    if not entries:
        return 0

    query = """
        INSERT INTO kev_entries (
            cve_id,
            vendor_project,
            product,
            vulnerability_name,
            date_added,
            due_date,
            short_description,
            required_action,
            known_ransomware_campaign_use,
            notes,
            cwes
        )
        VALUES (
            $1, $2, $3, $4, $5, $6,
            $7, $8, $9, $10, $11::jsonb
        )

        ON CONFLICT (cve_id)
        DO UPDATE SET
            vendor_project = EXCLUDED.vendor_project,
            product = EXCLUDED.product,
            vulnerability_name = EXCLUDED.vulnerability_name,
            date_added = EXCLUDED.date_added,
            due_date = EXCLUDED.due_date,
            short_description = EXCLUDED.short_description,
            required_action = EXCLUDED.required_action,
            known_ransomware_campaign_use =
                EXCLUDED.known_ransomware_campaign_use,
            notes = EXCLUDED.notes,
            cwes = EXCLUDED.cwes,
            last_seen_at = NOW();
    """

    records = [
        (
            entry.cve_id,
            entry.vendor_project,
            entry.product,
            entry.vulnerability_name,
            entry.date_added,
            entry.due_date,
            entry.short_description,
            entry.required_action,
            entry.known_ransomware_campaign_use,
            entry.notes,
            json.dumps(entry.cwes),
        )
        for entry in entries
    ]

    connection = await open_db_connection()

    try:
        async with connection.transaction():
            await connection.executemany(query, records)

    finally:
        await connection.close()

    return len(records)


async def get_latest_kev_entries(limit: int = 50) -> list[KEVEntry]:
    """
    Read the newest KEV entries from PostgreSQL.
    """

    query = """
        SELECT
            cve_id,
            vendor_project,
            product,
            vulnerability_name,
            date_added,
            due_date,
            short_description,
            required_action,
            known_ransomware_campaign_use,
            notes,
            cwes
        FROM kev_entries
        ORDER BY date_added DESC, cve_id DESC
        LIMIT $1;
    """

    connection = await open_db_connection()

    try:
        rows = await connection.fetch(query, limit)

    finally:
        await connection.close()

    entries: list[KEVEntry] = []

    for row in rows:
        cwes = row["cwes"]

        if isinstance(cwes, str):
            cwes = json.loads(cwes)

        entries.append(
            KEVEntry(
                cve_id=row["cve_id"],
                vendor_project=row["vendor_project"],
                product=row["product"],
                vulnerability_name=row["vulnerability_name"],
                date_added=row["date_added"],
                due_date=row["due_date"],
                short_description=row["short_description"],
                required_action=row["required_action"],
                known_ransomware_campaign_use=(
                    row["known_ransomware_campaign_use"]
                ),
                notes=row["notes"],
                cwes=cwes,
            )
        )

    return entries