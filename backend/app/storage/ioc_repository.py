"""PostgreSQL boundary for OTX V1: jobs, run history, reports, and observations.

The collector never calls this file. The service passes a normalized result
here after collection. Reads never call OTX. SQL parameters carry all user/
provider values; indicator/reference strings are never executed or visited.

Refresh safety: a failed transaction preserves the previous data. Only a
complete focused snapshot can mark old observations absent from that scope.
Partial refreshes can add positive evidence but cannot prove absence. Source
rows remain available as history; no IOC deletion or SIEM publication occurs.


FILE GUIDE
----------
WHAT THIS FILE DOES
Store OTX results and jobs, then serve bounded stored-data reads.

WHY IT EXISTS
Only this module should know the IOC table layout and SQL transaction rules.

WHO CALLS OR IMPORTS IT
app.services.ioc_service calls its scheduling, write, and read functions.

WHAT IT CALLS OR IMPORTS
Uses app.storage.postgres and the app.models.ioc / ioc_api contracts.

ROLE IN THE ARCHITECTURE
Persistence boundary; GET reads never contact OTX.
"""

import hashlib
import json
from datetime import datetime, timezone
from uuid import UUID, uuid4

from app.models.ioc import CVEIOCEnrichment, IOCObservation, SourceRecordAssessment
from app.models.ioc_api import IOCJob, IOCPage, IOCRun, StoredIOC
from app.storage.postgres import db_connection


def indicator_key(indicator_type: str, value: str) -> str:
    """Stable identity over canonical type/value; keeps long URLs out of indexes.

    Function detail: Called when saving an indicator. Hashing the complete normalized type
      and value gives a short index key while keeping the original observable text in the
      table.
    """
    return hashlib.sha256(f"{indicator_type}\0{value}".encode("utf-8")).hexdigest()


def decode_json(value):
    """asyncpg normally returns JSONB as text; also accept decoded test values.

    Function detail: Called after asyncpg reads JSONB. Production drivers often return a
      JSON string; tests may supply a decoded object.
    """
    return json.loads(value) if isinstance(value, str) else value


def lifecycle(observation: IOCObservation, absent_since: datetime | None) -> str:
    """Explain source state without equating active with malicious or confirmed.

    Function detail: Called while building API pages. Source absence, expiration, and OTX
      active state are presented separately from evidence strength.
    """
    if absent_since is not None:
        return "not_in_latest_scope"
    if observation.expires_at and observation.expires_at <= datetime.now(timezone.utc):
        return "expired"
    if observation.active is False:
        return "inactive"
    return "active" if observation.active is True else "unknown"


async def seed_jobs(connection) -> None:
    """Give every stored KEV a recurring job, including CVEs from earlier years.

    Existing due times are retained. Restarting the API therefore does not
    restart the entire backfill or erase a saved provider cooldown.
    

    Function detail: Called on each worker pass under the provider lock. INSERT ON CONFLICT
      adds newly ingested KEVs without resetting existing schedules.
    """
    await connection.execute("""
        INSERT INTO otx_jobs(cve_id)
        SELECT cve_id FROM kev_entries WHERE TRUE ON CONFLICT DO NOTHING
    """)


async def recover_interrupted_jobs(connection) -> None:
    """Recover abandoned running jobs after acquiring the provider advisory lock.

    Call ONLY while owning the session lock. With no other worker holding it,
    a leftover running row is from a crashed/cancelled previous process. Its
    old evidence stays intact and its abandoned attempt remains in history.
    

    Function detail: Called only by the lock owner. It marks abandoned attempts interrupted
      and returns their jobs to pending without deleting prior evidence.
    """
    async with connection.transaction():
        await connection.execute("""
            UPDATE otx_runs SET outcome='interrupted', finished_at=NOW(),
                error='Previous worker stopped before completing this lookup.'
            WHERE outcome='running'
        """)
        await connection.execute("""
            UPDATE otx_jobs SET state='pending', next_check_at=NOW(), run_id=NULL,
                last_error='Previous worker stopped; lookup will be retried.', updated_at=NOW()
            WHERE state='running'
        """)


async def start_next_job(connection) -> tuple[str, UUID] | None:
    """Atomically claim one due CVE and create its durable attempt record.

    Manual requests are prioritized, while normal jobs are oldest-due first.
    PostgreSQL scheduling survives restart; there is no in-memory-only queue.
    The caller must hold the provider session lock for the whole operation.
    

    Function detail: Called by the service after cooldown checks. Row locking claims one
      due CVE and creates a run ID atomically; manual requests take priority.
    """
    async with connection.transaction():
        cve_id = await connection.fetchval("""
            SELECT cve_id FROM otx_jobs WHERE next_check_at <= NOW() AND state <> 'running'
            ORDER BY (last_manual_at IS NOT NULL AND
                (last_attempt_at IS NULL OR last_manual_at > last_attempt_at)) DESC,
                next_check_at, cve_id
            LIMIT 1 FOR UPDATE SKIP LOCKED
        """)
        if cve_id is None:
            return None
        run_id = uuid4()
        await connection.execute("INSERT INTO otx_runs(run_id,cve_id) VALUES($1,$2)", run_id, cve_id)
        await connection.execute("""
            UPDATE otx_jobs SET state='running',run_id=$2,last_attempt_at=NOW(),
                last_error=NULL,updated_at=NOW() WHERE cve_id=$1
        """, cve_id, run_id)
        return cve_id, run_id


async def save_result(connection, run_id: UUID, result: CVEIOCEnrichment,
                      refresh_seconds: int, retry_seconds: int) -> None:
    """Commit evidence and job completion together; never delete old evidence.

    Shared report metadata avoids storing long references once per indicator.
    Indicators are deduplicated globally; observations remain per CVE/report.
    complete=False preserves last_success_at and uses the retry interval.
    The run token prevents a superseded attempt from replacing newer results.
    

    Function detail: Called by the service after a normalized collector result. One
      transaction upserts provenance and observations, updates the run/job, and rolls back
      on any error. Only a complete focused result may mark prior scoped observations
      absent.
    """
    if result.collection_scope != "focused_only":
        raise ValueError("Automated storage accepts focused_only scope.")
    if any(item.cve_id != result.cve_id for item in result.observations):
        raise ValueError("Observation belongs to a different CVE.")
    summary = result.model_dump(mode="json", exclude={"observations", "source_record_assessments"})
    report_fields = {
        "source_record_name", "source_record_url", "source_author", "source_tlp",
        "source_created_at", "source_modified_at", "reference_urls", "tags",
    }
    reports = {
        a.source_record_id: {"source_record_name": a.source_record_name,
                             "source_record_url": a.source_record_url}
        for a in result.source_record_assessments
    }
    indicators, observations = {}, {}
    for item in result.observations:
        serialized = item.model_dump(mode="json")
        reports[item.source_record_id] = {key: serialized[key] for key in report_fields}
        key = indicator_key(item.indicator.indicator_type.value, item.indicator.value)
        indicators[key] = (key, item.indicator.indicator_type.value, item.indicator.value, result.fetched_at)
        evidence = {name: value for name, value in serialized.items() if name not in
                    report_fields | {"cve_id", "source", "indicator", "source_record_id", "fetched_at"}}
        observations[(item.source_record_id, key)] = (
            result.cve_id, item.source_record_id, key, json.dumps(evidence), result.fetched_at,
        )

    async with connection.transaction():
        current = await connection.fetchval(
            "SELECT run_id FROM otx_jobs WHERE cve_id=$1 FOR UPDATE", result.cve_id
        )
        if current != run_id:
            raise RuntimeError("This IOC attempt no longer owns the job.")
        if reports:
            await connection.executemany("""
                INSERT INTO otx_reports(pulse_id,metadata,checked_at) VALUES($1,$2::jsonb,$3)
                ON CONFLICT(pulse_id) DO UPDATE SET
                    metadata=otx_reports.metadata || EXCLUDED.metadata,checked_at=EXCLUDED.checked_at
                WHERE otx_reports.checked_at <= EXCLUDED.checked_at
            """, [(key, json.dumps(metadata), result.fetched_at) for key, metadata in reports.items()])
        if result.complete:
            await connection.execute("UPDATE otx_cve_reports SET in_latest_metadata=FALSE WHERE cve_id=$1", result.cve_id)
            await connection.execute("""
                UPDATE otx_observations SET absent_since=COALESCE(absent_since,$2)
                WHERE cve_id=$1
            """, result.cve_id, result.fetched_at)
        if result.source_record_assessments:
            await connection.executemany("""
                INSERT INTO otx_cve_reports(cve_id,pulse_id,assessment,checked_at,in_latest_metadata)
                VALUES($1,$2,$3::jsonb,$4,TRUE)
                ON CONFLICT(cve_id,pulse_id) DO UPDATE SET assessment=EXCLUDED.assessment,
                    checked_at=EXCLUDED.checked_at,in_latest_metadata=TRUE
            """, [(result.cve_id, a.source_record_id, a.model_dump_json(), result.fetched_at)
                  for a in result.source_record_assessments])
        if indicators:
            # An astronomically unlikely hash collision is rejected instead of
            # silently combining different indicator identities.
            await connection.executemany("""
                INSERT INTO otx_indicators(indicator_key,indicator_type,value,first_seen_at,last_seen_at)
                VALUES($1,$2,$3,$4,$4) ON CONFLICT(indicator_key) DO UPDATE
                SET last_seen_at=EXCLUDED.last_seen_at
            """, list(indicators.values()))
            saved = await connection.fetch("""
                SELECT indicator_key,indicator_type,value FROM otx_indicators
                WHERE indicator_key=ANY($1::text[])
            """, list(indicators))
            for row in saved:
                candidate = indicators[row["indicator_key"]]
                if (row["indicator_type"], row["value"]) != candidate[1:3]:
                    raise RuntimeError("IOC identity collision; transaction rolled back.")
            await connection.executemany("""
                INSERT INTO otx_observations(cve_id,pulse_id,indicator_key,evidence,first_seen_at,last_seen_at)
                VALUES($1,$2,$3,$4::jsonb,$5,$5)
                ON CONFLICT(cve_id,pulse_id,indicator_key) DO UPDATE SET
                    evidence=EXCLUDED.evidence,last_seen_at=EXCLUDED.last_seen_at,absent_since=NULL
            """, list(observations.values()))
        state = "complete" if result.complete else "partial"
        delay = refresh_seconds if result.complete else retry_seconds
        await connection.execute("""
            UPDATE otx_runs SET outcome=$2,summary=$3::jsonb,finished_at=NOW() WHERE run_id=$1
        """, run_id, state, json.dumps(summary))
        await connection.execute("""
            UPDATE otx_jobs SET state=$2,summary=$3::jsonb,
                last_success_at=CASE WHEN $4 THEN NOW() ELSE last_success_at END,
                next_check_at=NOW()+make_interval(secs=>$5),last_error=NULL,updated_at=NOW()
            WHERE cve_id=$1 AND run_id=$6
        """, result.cve_id, state, json.dumps(summary), result.complete, float(delay), run_id)


async def record_failure(connection, cve_id: str, run_id: UUID, message: str,
                         retry_at: datetime, deferred: bool = False) -> None:
    """Record a failed attempt without touching stored indicators or last success.

    Function detail: Called after a provider or storage error. It changes the run/job retry
      state but deliberately leaves last_success_at and existing observations alone.
    """
    state = "deferred" if deferred else "failed"
    async with connection.transaction():
        await connection.execute("""
            UPDATE otx_runs SET outcome=$2,error=$3,finished_at=NOW() WHERE run_id=$1
        """, run_id, state, message[:1000])
        await connection.execute("""
            UPDATE otx_jobs SET state=$3,last_error=$4,next_check_at=$5,updated_at=NOW()
            WHERE cve_id=$1 AND run_id=$2
        """, cve_id, run_id, state, message[:1000], retry_at)


async def queue_refresh(cve_id: str, cooldown_seconds: int) -> tuple[bool, str]:
    """Coalesce repeated requests and throttle manual refreshes inside PostgreSQL.

    This only makes the CVE eligible for its worker; provider-wide cooldowns
    still apply. Row locking makes concurrent button clicks idempotent.
    

    Function detail: Called by request_ioc_refresh. A KEV check, row lock, and cooldown
      inside one transaction prevent repeat clicks from creating duplicate work.
    """
    async with db_connection() as connection:
        async with connection.transaction():
            if not await connection.fetchval("SELECT EXISTS(SELECT 1 FROM kev_entries WHERE cve_id=$1)", cve_id):
                raise LookupError("CVE is not in the local KEV catalog.")
            await connection.execute("INSERT INTO otx_jobs(cve_id) VALUES($1) ON CONFLICT DO NOTHING", cve_id)
            row = await connection.fetchrow("SELECT * FROM otx_jobs WHERE cve_id=$1 FOR UPDATE", cve_id)
            if row["state"] == "running":
                return False, "running"
            now = datetime.now(timezone.utc)
            if row["last_manual_at"] and (now - row["last_manual_at"]).total_seconds() < cooldown_seconds:
                return False, row["state"]
            await connection.execute("""
                UPDATE otx_jobs SET state='pending',next_check_at=NOW(),last_manual_at=NOW(),
                    updated_at=NOW() WHERE cve_id=$1
            """, cve_id)
            return True, "pending"


async def require_kev(connection, cve_id: str) -> None:
    """Distinguish an unknown KEV from a known KEV awaiting IOC collection.

    Function detail: Called by stored-data reads. Raises LookupError for a CVE outside the
      local KEV catalog so the API can return 404.
    """
    if not await connection.fetchval("SELECT EXISTS(SELECT 1 FROM kev_entries WHERE cve_id=$1)", cve_id):
        raise LookupError("CVE is not in the local KEV catalog.")


async def get_page(cve_id: str, limit: int, offset: int, include_history: bool) -> IOCPage:
    """Read one consistent page of stored evidence; never trigger live enrichment.

    Function detail: Called by GET /api/ioc/{cve_id}. A repeatable-read snapshot joins
      observations to indicator/report metadata, paginates rows, and includes limited
      assessment context.
    """
    async with db_connection() as connection:
        async with connection.transaction(isolation="repeatable_read", readonly=True):
            await require_kev(connection, cve_id)
            row = await connection.fetchrow("SELECT * FROM otx_jobs WHERE cve_id=$1", cve_id)
            job = None
            if row:
                fields = dict(row)
                fields["summary"] = decode_json(fields["summary"])
                job = IOCJob.model_validate(fields)
            total = await connection.fetchval("""
                SELECT count(*) FROM otx_observations WHERE cve_id=$1 AND ($2 OR absent_since IS NULL)
            """, cve_id, include_history)
            rows = await connection.fetch("""
                SELECT o.*,i.indicator_type,i.value,r.metadata FROM otx_observations o
                JOIN otx_indicators i USING(indicator_key) JOIN otx_reports r USING(pulse_id)
                WHERE o.cve_id=$1 AND ($2 OR o.absent_since IS NULL)
                ORDER BY o.last_seen_at DESC,o.pulse_id,o.indicator_key LIMIT $3 OFFSET $4
            """, cve_id, include_history, limit, offset)
            # Show up to 50 latest-assessed pulse decisions; the count exposes
            # truncation rather than implying the preview contains everything.
            assessments = await connection.fetch("""
                SELECT assessment FROM otx_cve_reports WHERE cve_id=$1 AND in_latest_metadata
                ORDER BY checked_at DESC,pulse_id LIMIT 50
            """, cve_id)
            assessment_total = await connection.fetchval("""
                SELECT count(*) FROM otx_cve_reports WHERE cve_id=$1 AND in_latest_metadata
            """, cve_id)
    observations = []
    for item in rows:
        observation = IOCObservation.model_validate({
            **decode_json(item["metadata"]), **decode_json(item["evidence"]),
            "cve_id": cve_id, "source": "AlienVault OTX", "source_record_id": item["pulse_id"],
            "indicator": {"indicator_type": item["indicator_type"], "value": item["value"]},
            "fetched_at": item["last_seen_at"],
        })
        observations.append(StoredIOC(
            observation=observation, first_seen_at=item["first_seen_at"],
            last_seen_at=item["last_seen_at"], absent_since=item["absent_since"],
            lifecycle=lifecycle(observation, item["absent_since"]),
        ))
    return IOCPage(cve_id=cve_id,job=job,total=total,limit=limit,offset=offset,
                   include_history=include_history,observations=observations,
                   assessments=[SourceRecordAssessment.model_validate(decode_json(a["assessment"])) for a in assessments],
                   assessment_total=assessment_total)


async def get_runs(cve_id: str, limit: int) -> list[IOCRun]:
    """Return recent attempt summaries, including failures and genuine empty successes.

    Function detail: Called by GET /api/ioc/{cve_id}/runs. It returns bounded persisted
      outcomes, including failures and empty successes.
    """
    async with db_connection() as connection:
        await require_kev(connection, cve_id)
        rows = await connection.fetch("""
            SELECT * FROM otx_runs WHERE cve_id=$1 ORDER BY started_at DESC LIMIT $2
        """, cve_id, limit)
    return [IOCRun(run_id=str(row["run_id"]),started_at=row["started_at"],finished_at=row["finished_at"],
                   outcome=row["outcome"],summary=decode_json(row["summary"]),error=row["error"]) for row in rows]


async def get_status_counts() -> dict:
    """Aggregate coverage and persisted provider state without exposing the key hash.

    Function detail: Called by the status service. SQL summarizes KEV coverage, due/running
      work, stored observations, and provider cooldown without scanning provider data.
    """
    async with db_connection() as connection:
        row = await connection.fetchrow("""
            SELECT (SELECT count(*) FROM kev_entries) AS total_kevs,
                count(*) AS scheduled_kevs,
                count(*) FILTER(WHERE last_success_at IS NOT NULL) AS ever_completed,
                count(*) FILTER(WHERE next_check_at<=NOW() AND state<>'running') AS due_jobs,
                count(*) FILTER(WHERE state='running') AS running_jobs,
                count(*) FILTER(WHERE state IN ('failed','partial','deferred')) AS failed_or_partial,
                (SELECT count(*) FROM otx_observations) AS stored_observations FROM otx_jobs
        """)
        provider = await connection.fetchrow("""
            SELECT next_allowed_at,heartbeat_at,last_error FROM otx_provider_state WHERE id=1
        """)
    return {**dict(row), **dict(provider)}
