"""PostgreSQL repository for current NVD enrichment and CVSS history.

FILE ROLE
---------
This module is the database boundary for NVD. It converts validated ``NVDCVE``
models to PostgreSQL rows, reconstructs models from rows, finds KEVs that need
NVD work, and records meaningful CVSS changes.

ARCHITECTURE POSITION
---------------------
NVD service -> collector -> NVDCVE -> this repository -> PostgreSQL
FastAPI GET -> NVD service -> this repository -> PostgreSQL

WHAT THIS FILE OWNS
-------------------
- Current NVD row insert/update behavior.
- Protection against an older NVD revision overwriting a newer one.
- CVSS change-history insertion inside the same database transaction.
- Queries that select missing/stale KEVs for automated enrichment.
- Current-record counts and CVSS history reads.

WHAT THIS FILE DOES NOT DO
--------------------------
- It does not call NVD.
- It does not use Redis.
- It does not sleep between provider requests.
- It does not decide refresh cadence; config/service/worker own that policy.

CURRENT VS HISTORY
------------------
``nvd_cves`` contains one current row per KEV. ``nvd_cvss_history`` receives a
new row only when the selected CVSS assessment changes. Re-fetching an unchanged
9.8 score updates ``fetched_at`` but does not create noisy history.
"""

import json
from datetime import datetime

from app.models.nvd import NVDCVE, NVDCVSSChange, NVDCVSSMetric
from app.storage.postgres import db_connection


NVD_COLUMNS = """cve_id, source_identifier, published_at, last_modified_at,
    vuln_status, description, cvss_version, cvss_base_score,
    cvss_base_severity, cvss_vector_string, cvss_source, cvss_metric_type,
    cvss_exploitability_score, cvss_impact_score, cwes, affected_cpes,
    reference_urls, fetched_at"""


UPSERT_NVD_SQL = f"""
    INSERT INTO nvd_cves ({NVD_COLUMNS})
    VALUES (
        $1, $2, $3, $4, $5, $6, $7, $8, $9,
        $10, $11, $12, $13, $14,
        $15::jsonb, $16::jsonb, $17::jsonb, $18
    )
    ON CONFLICT (cve_id)
    DO UPDATE SET
        source_identifier = EXCLUDED.source_identifier,
        published_at = EXCLUDED.published_at,
        last_modified_at = EXCLUDED.last_modified_at,
        vuln_status = EXCLUDED.vuln_status,
        description = EXCLUDED.description,
        cvss_version = EXCLUDED.cvss_version,
        cvss_base_score = EXCLUDED.cvss_base_score,
        cvss_base_severity = EXCLUDED.cvss_base_severity,
        cvss_vector_string = EXCLUDED.cvss_vector_string,
        cvss_source = EXCLUDED.cvss_source,
        cvss_metric_type = EXCLUDED.cvss_metric_type,
        cvss_exploitability_score = EXCLUDED.cvss_exploitability_score,
        cvss_impact_score = EXCLUDED.cvss_impact_score,
        cwes = EXCLUDED.cwes,
        affected_cpes = EXCLUDED.affected_cpes,
        reference_urls = EXCLUDED.reference_urls,
        fetched_at = EXCLUDED.fetched_at
    WHERE nvd_cves.last_modified_at <= EXCLUDED.last_modified_at
    RETURNING {NVD_COLUMNS}
"""


HISTORY_COLUMNS = """cve_id, observed_at, nvd_last_modified_at,
    previous_cvss_version, previous_base_score, previous_base_severity,
    previous_vector_string, previous_source, previous_metric_type,
    previous_exploitability_score, previous_impact_score,
    current_cvss_version, current_base_score, current_base_severity,
    current_vector_string, current_source, current_metric_type,
    current_exploitability_score, current_impact_score"""


def _decode_json_list(value: object) -> list[str]:
    """Normalize asyncpg JSONB output into a Python list of strings."""

    decoded = json.loads(value) if isinstance(value, str) else value
    if not isinstance(decoded, list):
        raise RuntimeError("Expected PostgreSQL JSONB array for NVD list field")
    return [str(item) for item in decoded]


def _metric_from_values(
    *,
    version: object,
    base_score: object,
    severity: object,
    vector: object,
    source: object,
    metric_type: object,
    exploitability: object,
    impact: object,
) -> NVDCVSSMetric | None:
    """Build one CVSS model from flattened SQL fields, or return ``None``."""

    if version is None:
        return None

    return NVDCVSSMetric(
        cvss_version=str(version),
        base_score=float(base_score),
        base_severity=str(severity) if severity is not None else None,
        vector_string=str(vector),
        source=str(source) if source is not None else None,
        metric_type=str(metric_type) if metric_type is not None else None,
        exploitability_score=(
            float(exploitability) if exploitability is not None else None
        ),
        impact_score=float(impact) if impact is not None else None,
    )


def _row_cvss(row) -> NVDCVSSMetric | None:
    """Extract the selected CVSS assessment from one current NVD row."""

    return _metric_from_values(
        version=row["cvss_version"],
        base_score=row["cvss_base_score"],
        severity=row["cvss_base_severity"],
        vector=row["cvss_vector_string"],
        source=row["cvss_source"],
        metric_type=row["cvss_metric_type"],
        exploitability=row["cvss_exploitability_score"],
        impact=row["cvss_impact_score"],
    )


def _row_to_nvd_cve(row) -> NVDCVE:
    """Convert one asyncpg row into the shared normalized NVD model."""

    return NVDCVE(
        cve_id=row["cve_id"],
        source_identifier=row["source_identifier"],
        published_at=row["published_at"],
        last_modified_at=row["last_modified_at"],
        vuln_status=row["vuln_status"],
        description=row["description"],
        cvss=_row_cvss(row),
        cwes=_decode_json_list(row["cwes"]),
        affected_cpes=_decode_json_list(row["affected_cpes"]),
        reference_urls=_decode_json_list(row["reference_urls"]),
        fetched_at=row["fetched_at"],
    )


def _history_row_to_change(row) -> NVDCVSSChange:
    """Convert one history row into an API/application history model."""

    previous = _metric_from_values(
        version=row["previous_cvss_version"],
        base_score=row["previous_base_score"],
        severity=row["previous_base_severity"],
        vector=row["previous_vector_string"],
        source=row["previous_source"],
        metric_type=row["previous_metric_type"],
        exploitability=row["previous_exploitability_score"],
        impact=row["previous_impact_score"],
    )
    current = _metric_from_values(
        version=row["current_cvss_version"],
        base_score=row["current_base_score"],
        severity=row["current_base_severity"],
        vector=row["current_vector_string"],
        source=row["current_source"],
        metric_type=row["current_metric_type"],
        exploitability=row["current_exploitability_score"],
        impact=row["current_impact_score"],
    )

    return NVDCVSSChange(
        cve_id=row["cve_id"],
        observed_at=row["observed_at"],
        nvd_last_modified_at=row["nvd_last_modified_at"],
        previous_cvss=previous,
        current_cvss=current,
    )


def _nvd_parameters(record: NVDCVE) -> tuple[object, ...]:
    """Flatten one ``NVDCVE`` into ordered SQL parameters for the upsert."""

    cvss = record.cvss
    return (
        record.cve_id,
        record.source_identifier,
        record.published_at,
        record.last_modified_at,
        record.vuln_status,
        record.description,
        cvss.cvss_version if cvss else None,
        cvss.base_score if cvss else None,
        cvss.base_severity if cvss else None,
        cvss.vector_string if cvss else None,
        cvss.source if cvss else None,
        cvss.metric_type if cvss else None,
        cvss.exploitability_score if cvss else None,
        cvss.impact_score if cvss else None,
        json.dumps(record.cwes),
        json.dumps(record.affected_cpes),
        json.dumps(record.reference_urls),
        record.fetched_at,
    )


def _cvss_signature(metric: NVDCVSSMetric | None) -> tuple[object, ...] | None:
    """Return fields that define whether the selected CVSS assessment changed."""

    if metric is None:
        return None
    return (
        metric.cvss_version,
        metric.base_score,
        metric.base_severity,
        metric.vector_string,
        metric.source,
        metric.metric_type,
        metric.exploitability_score,
        metric.impact_score,
    )


def _history_parameters(
    cve_id: str,
    observed_at: datetime,
    nvd_last_modified_at: datetime,
    previous: NVDCVSSMetric | None,
    current: NVDCVSSMetric | None,
) -> tuple[object, ...]:
    """Flatten one old/new CVSS transition for ``nvd_cvss_history``."""

    def values(metric: NVDCVSSMetric | None) -> tuple[object, ...]:
        if metric is None:
            return (None, None, None, None, None, None, None, None)
        return (
            metric.cvss_version,
            metric.base_score,
            metric.base_severity,
            metric.vector_string,
            metric.source,
            metric.metric_type,
            metric.exploitability_score,
            metric.impact_score,
        )

    return (
        cve_id,
        observed_at,
        nvd_last_modified_at,
        *values(previous),
        *values(current),
    )


async def upsert_nvd_cve(record: NVDCVE) -> NVDCVE:
    """Store one current NVD record and append history if CVSS changed.

    Inputs
    ------
    record:
        Fully validated NVD data produced by the collector.

    Returns
    -------
    NVDCVE
        The newest row PostgreSQL retained. If an older NVD revision is passed
        in, the existing newer row is returned unchanged.

    Important logic
    ---------------
    The current-row read, optional history insert, and current-row upsert happen
    in one PostgreSQL transaction. This prevents a successful current update
    from being separated from its CVSS change-history record.
    """

    async with db_connection() as connection:
        async with connection.transaction():
            existing = await connection.fetchrow(
                f"""
                SELECT {NVD_COLUMNS}
                FROM nvd_cves
                WHERE cve_id = $1
                FOR UPDATE
                """,
                record.cve_id,
            )

            # Never let an older provider revision replace a newer NVD state.
            if (
                existing is not None
                and existing["last_modified_at"] > record.last_modified_at
            ):
                return _row_to_nvd_cve(existing)

            if existing is not None:
                previous_cvss = _row_cvss(existing)
                if _cvss_signature(previous_cvss) != _cvss_signature(record.cvss):
                    await connection.execute(
                        f"""
                        INSERT INTO nvd_cvss_history ({HISTORY_COLUMNS})
                        VALUES (
                            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,
                            $12,$13,$14,$15,$16,$17,$18,$19
                        )
                        """,
                        *_history_parameters(
                            record.cve_id,
                            record.fetched_at,
                            record.last_modified_at,
                            previous_cvss,
                            record.cvss,
                        ),
                    )

            row = await connection.fetchrow(
                UPSERT_NVD_SQL,
                *_nvd_parameters(record),
            )

            # This can occur only if another path supplied an older revision
            # between the first check and the upsert. Read the retained row.
            if row is None:
                row = await connection.fetchrow(
                    f"""
                    SELECT {NVD_COLUMNS}
                    FROM nvd_cves
                    WHERE cve_id = $1
                    """,
                    record.cve_id,
                )

    if row is None:
        raise RuntimeError("NVD record could not be stored or retrieved")
    return _row_to_nvd_cve(row)


async def get_nvd_cve_by_cve(cve_id: str) -> NVDCVE | None:
    """Read one current NVD enrichment from PostgreSQL without calling NVD."""

    async with db_connection() as connection:
        row = await connection.fetchrow(
            f"""
            SELECT {NVD_COLUMNS}
            FROM nvd_cves
            WHERE cve_id = $1
            """,
            cve_id.strip().upper(),
        )

    return _row_to_nvd_cve(row) if row is not None else None


async def get_nvd_cvss_history(
    cve_id: str,
    limit: int = 20,
) -> list[NVDCVSSChange]:
    """Return newest-first CVSS transitions for one CVE."""

    async with db_connection() as connection:
        rows = await connection.fetch(
            f"""
            SELECT {HISTORY_COLUMNS}
            FROM nvd_cvss_history
            WHERE cve_id = $1
            ORDER BY observed_at DESC, id DESC
            LIMIT $2
            """,
            cve_id.strip().upper(),
            limit,
        )

    return [_history_row_to_change(row) for row in rows]


async def get_kev_cve_ids_needing_nvd(
    stale_before: datetime,
    limit: int,
) -> list[str]:
    """Return newest KEVs whose NVD data is missing or stale.

    Missing records are prioritized before stale records. Within those groups,
    newer KEV additions are processed first so the dashboard gains useful NVD
    context for the most recent CISA additions early in a large first backfill.
    """

    async with db_connection() as connection:
        rows = await connection.fetch(
            """
            SELECT k.cve_id
            FROM kev_entries AS k
            LEFT JOIN nvd_cves AS n ON n.cve_id = k.cve_id
            WHERE n.cve_id IS NULL OR n.fetched_at < $1
            ORDER BY
                (n.cve_id IS NULL) DESC,
                k.date_added DESC,
                n.fetched_at ASC NULLS FIRST,
                k.cve_id DESC
            LIMIT $2
            """,
            stale_before,
            limit,
        )

    return [str(row["cve_id"]) for row in rows]


async def count_nvd_refresh_candidates(stale_before: datetime) -> int:
    """Count KEVs whose NVD data is missing or older than the freshness policy."""

    async with db_connection() as connection:
        return int(
            await connection.fetchval(
                """
                SELECT COUNT(*)
                FROM kev_entries AS k
                LEFT JOIN nvd_cves AS n ON n.cve_id = k.cve_id
                WHERE n.cve_id IS NULL OR n.fetched_at < $1
                """,
                stale_before,
            )
        )


async def count_nvd_cves() -> int:
    """Return how many KEV CVEs currently have stored NVD enrichment."""

    async with db_connection() as connection:
        return int(await connection.fetchval("SELECT COUNT(*) FROM nvd_cves"))


async def count_kev_entries() -> int:
    """Return the number of KEVs available for NVD enrichment."""

    async with db_connection() as connection:
        return int(await connection.fetchval("SELECT COUNT(*) FROM kev_entries"))
