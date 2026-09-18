"""PostgreSQL repository for current EPSS scores.

The service calls this module; this module calls PostgreSQL. It never contacts
FIRST, starts workers, uses Redis, or creates HTTP responses.
"""

from datetime import date

from app.models.epss import EPSSScore
from app.storage.postgres import db_connection


def _row_to_epss_score(row) -> EPSSScore:
    """Convert an asyncpg Record into the shared application model."""
    return EPSSScore(
        cve_id=row["cve_id"],
        epss_score=row["epss_score"],
        percentile=row["percentile"],
        score_date=row["score_date"],
    )


UPSERT_SQL = """
    INSERT INTO epss_scores (
        cve_id, epss_score, percentile, score_date, fetched_at
    )
    VALUES ($1, $2, $3, $4, NOW())
    ON CONFLICT (cve_id)
    DO UPDATE SET
        epss_score = EXCLUDED.epss_score,
        percentile = EXCLUDED.percentile,
        score_date = EXCLUDED.score_date,
        fetched_at = NOW()
    WHERE epss_scores.score_date <= EXCLUDED.score_date
"""


async def upsert_epss_score(score: EPSSScore) -> EPSSScore:
    """Store one score and return the newest value retained by PostgreSQL."""
    async with db_connection() as connection:
        row = await connection.fetchrow(
            UPSERT_SQL
            + """
            RETURNING cve_id, epss_score, percentile, score_date
            """,
            score.cve_id,
            score.epss_score,
            score.percentile,
            score.score_date,
        )

        # An older incoming date is intentionally rejected by the conflict
        # condition, so RETURNING may produce no row. Return the newer row.
        if row is None:
            row = await connection.fetchrow(
                """
                SELECT cve_id, epss_score, percentile, score_date
                FROM epss_scores
                WHERE cve_id = $1
                """,
                score.cve_id,
            )

    if row is None:
        raise RuntimeError("EPSS score could not be stored or retrieved")
    return _row_to_epss_score(row)


async def upsert_epss_scores(scores: list[EPSSScore]) -> int:
    """Store one validated batch in a transaction.

    If one row fails, the whole batch rolls back. This prevents a partially
    applied FIRST response from looking like a complete refresh.
    """
    if not scores:
        return 0

    rows = [
        (score.cve_id, score.epss_score, score.percentile, score.score_date)
        for score in scores
    ]

    async with db_connection() as connection:
        async with connection.transaction():
            await connection.executemany(UPSERT_SQL, rows)

    return len(rows)


async def get_epss_score_by_cve(cve_id: str) -> EPSSScore | None:
    """Read one current score from PostgreSQL without contacting FIRST."""
    async with db_connection() as connection:
        row = await connection.fetchrow(
            """
            SELECT cve_id, epss_score, percentile, score_date
            FROM epss_scores
            WHERE cve_id = $1
            """,
            cve_id,
        )
    return _row_to_epss_score(row) if row is not None else None


async def count_epss_scores() -> int:
    """Return the number of KEV CVEs currently enriched with EPSS."""
    async with db_connection() as connection:
        return int(await connection.fetchval("SELECT COUNT(*) FROM epss_scores"))


async def count_kev_entries() -> int:
    """Distinguish a brand-new KEV database from fully up-to-date scores."""
    async with db_connection() as connection:
        return int(await connection.fetchval("SELECT COUNT(*) FROM kev_entries"))


async def get_kev_cve_ids_needing_epss(
    minimum_score_date: date,
    limit: int | None = None,
) -> list[str]:
    """Find missing/old scores; no default cap that can starve older KEVs.

    The service selects this set once. FIRST requests are then split into small
    batches, so absent upstream scores never trap a repeated LIMIT query.
    """
    async with db_connection() as connection:
        rows = await connection.fetch(
            """
            SELECT kev.cve_id
            FROM kev_entries AS kev
            LEFT JOIN epss_scores AS epss ON epss.cve_id = kev.cve_id
            WHERE epss.cve_id IS NULL OR epss.score_date < $1
            ORDER BY kev.date_added DESC, kev.cve_id DESC
            LIMIT $2
            """,
            minimum_score_date,
            limit,
        )
    return [row["cve_id"] for row in rows]
