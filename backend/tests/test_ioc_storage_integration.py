"""Opt-in real PostgreSQL checks in a temporary, rolled-back schema.

Set OTX_INTEGRATION_TESTS=1 and DATABASE_URL to run. No live OTX calls or Redis
operations occur. Existing application tables are not read/written: each test
sets an isolated search_path and rolls back its schema/data in finally cleanup.
The account needs CREATE SCHEMA permission. Never enable against production.


FILE GUIDE
----------
WHAT THIS FILE DOES
Exercise the real OTX schema and SQL in an isolated PostgreSQL schema.

WHY IT EXISTS
Mocked repository tests cannot prove SQL syntax, constraints, or transaction behavior.

WHO CALLS OR IMPORTS IT
unittest runs this file only when OTX_INTEGRATION_TESTS=1 is set explicitly.

WHAT IT CALLS OR IMPORTS
Calls IOC schema/repository through asyncpg and rolls back its temporary schema.

ROLE IN THE ARCHITECTURE
Opt-in database integration tests; never contacts live OTX.
"""
import os
import unittest
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from uuid import uuid4
from unittest.mock import patch

import asyncpg
from app.config import DATABASE_URL
from app.models.ioc import CVEIOCEnrichment, IOCObservation, IOCIndicator, SourceRecordAssessment
from app.storage.ioc_schema import IOC_SCHEMA_SQL
from app.storage import ioc_repository as repository

CVE = "CVE-2017-0144"
PULSE = "a" * 24


def collected(*, complete=True, empty=False):
    """Build a realistic focused result; empty success has explicit zero counts."""
    assessment = SourceRecordAssessment(source_record_id=PULSE,source_record_name=f"Report on {CVE}",
        source_record_url=f"https://otx.alienvault.com/pulse/{PULSE}",source_record_cve_ids=[CVE],
        relevance="focused_context",reason_code="title_matches_single_cve",reason="Single-CVE title.",
        selected_for_collection=True,fetched=True,indicator_count=1)
    entry = IOCObservation(cve_id=CVE,indicator=IOCIndicator(indicator_type="ipv4",value="192.0.2.1"),
        relationship_type="pulse_context",source_record_relevance="focused_context",
        source_record_cve_ids=[CVE],source="AlienVault OTX",source_record_id=PULSE,
        source_record_name=f"Report on {CVE}",source_record_url=f"https://otx.alienvault.com/pulse/{PULSE}",
        active=True)
    return CVEIOCEnrichment(cve_id=CVE,source="AlienVault OTX",collection_scope="focused_only",
        complete=complete,source_record_count_reported=0 if empty else 1,
        source_record_count_processed=0 if empty else 1,
        source_record_assessments=[] if empty else [assessment],
        observation_count=0 if empty else 1,unique_indicator_count=0 if empty else 1,
        observations=[] if empty else [entry])


@unittest.skipUnless(os.getenv("OTX_INTEGRATION_TESTS") == "1", "Opt-in isolated PostgreSQL test")
class IOCStorageIntegration(unittest.IsolatedAsyncioTestCase):
    """Group cases that check real PostgreSQL constraints and lifecycle updates behave as intended."""
    async def asyncSetUp(self):
        """Prepare asynchronous test fixtures before each case."""
        self.connection = await asyncpg.connect(DATABASE_URL,timeout=5,command_timeout=30)
        self.transaction = self.connection.transaction(isolation="repeatable_read")
        await self.transaction.start()
        self.addAsyncCleanup(self.cleanup_database)
        schema = "otx_test_" + uuid4().hex  # Internal hex identifier, never user SQL.
        await self.connection.execute(f'CREATE SCHEMA "{schema}"')
        await self.connection.execute(f'SET LOCAL search_path TO "{schema}"')
        await self.connection.execute("CREATE TABLE kev_entries(cve_id TEXT PRIMARY KEY)")
        await self.connection.execute("INSERT INTO kev_entries VALUES($1)", CVE)
        await self.connection.execute(IOC_SCHEMA_SQL)
        await self.connection.execute(IOC_SCHEMA_SQL)  # Repeatable startup.

        @asynccontextmanager
        async def isolated_connection():
            """Give repository functions an isolated PostgreSQL connection and search path."""
            yield self.connection
        self.connection_patch = patch.object(repository,"db_connection",isolated_connection)
        self.connection_patch.start()
        self.addCleanup(self.connection_patch.stop)
        await repository.seed_jobs(self.connection)

    async def cleanup_database(self):
        """Roll back and remove the test-only PostgreSQL schema after a case."""
        try:
            await self.transaction.rollback()
        finally:
            await self.connection.close()

    async def save(self, data):
        """Start a controlled attempt for this CVE and call the real SQL writer."""
        await self.connection.execute("UPDATE otx_jobs SET next_check_at=NOW(),state='pending' WHERE cve_id=$1", CVE)
        job = await repository.start_next_job(self.connection)
        self.assertEqual(job[0], CVE)
        await repository.save_result(self.connection,job[1],data,86400,3600)
        return job[1]

    async def test_old_and_new_kevs_both_receive_jobs(self):
        """Verify old and new kevs both receive jobs. This checks that real PostgreSQL constraints and lifecycle updates behave as intended."""
        await self.connection.execute("INSERT INTO kev_entries VALUES('CVE-2026-12345')")
        await repository.seed_jobs(self.connection)
        await repository.seed_jobs(self.connection)
        self.assertEqual(await self.connection.fetchval("SELECT count(*) FROM otx_jobs"),2)

    async def test_repeat_refresh_deduplicates_and_preserves_first_seen(self):
        """Verify repeat refresh deduplicates and preserves first seen. This checks that real PostgreSQL constraints and lifecycle updates behave as intended."""
        await self.save(collected())
        first = await repository.get_page(CVE,25,0,False)
        await self.save(collected())
        second = await repository.get_page(CVE,25,0,False)
        self.assertEqual(second.total,1)
        self.assertEqual(second.observations[0].first_seen_at,first.observations[0].first_seen_at)
        self.assertEqual(second.observations[0].observation.relationship_type,"pulse_context")
        self.assertEqual(len(await repository.get_runs(CVE,10)),2)

    async def test_partial_empty_preserves_existing_observations_and_last_success(self):
        """Verify partial empty preserves existing observations and last success. This checks that real PostgreSQL constraints and lifecycle updates behave as intended."""
        await self.save(collected())
        original = await repository.get_page(CVE,25,0,False)
        await self.save(collected(complete=False,empty=True))
        partial = await repository.get_page(CVE,25,0,False)
        self.assertEqual(partial.total,1)
        self.assertIsNone(partial.observations[0].absent_since)
        self.assertEqual(partial.job.last_success_at,original.job.last_success_at)
        self.assertEqual(partial.job.state,"partial")

    async def test_complete_empty_marks_absent_but_preserves_history(self):
        """Verify complete empty marks absent but preserves history. This checks that real PostgreSQL constraints and lifecycle updates behave as intended."""
        await self.save(collected())
        await self.save(collected(empty=True))
        self.assertEqual((await repository.get_page(CVE,25,0,False)).total,0)
        history = await repository.get_page(CVE,25,0,True)
        self.assertEqual(history.total,1)
        self.assertEqual(history.observations[0].lifecycle,"not_in_latest_scope")

    async def test_failed_attempt_preserves_successful_evidence(self):
        """Verify failed attempt preserves successful evidence. This checks that real PostgreSQL constraints and lifecycle updates behave as intended."""
        await self.save(collected())
        await self.connection.execute("UPDATE otx_jobs SET next_check_at=NOW()")
        cve, run_id = await repository.start_next_job(self.connection)
        await repository.record_failure(self.connection,cve,run_id,"Provider unavailable",datetime.now(timezone.utc))
        page = await repository.get_page(CVE,25,0,False)
        self.assertEqual(page.total,1)
        self.assertIsNotNone(page.job.last_success_at)
        self.assertEqual(page.job.state,"failed")

    async def test_repeated_manual_queue_requests_coalesce(self):
        """Verify repeated manual queue requests coalesce. This checks that real PostgreSQL constraints and lifecycle updates behave as intended."""
        first = await repository.queue_refresh(CVE,900)
        second = await repository.queue_refresh(CVE,900)
        self.assertTrue(first[0])
        self.assertFalse(second[0])

    async def test_superseded_run_cannot_overwrite_evidence(self):
        """Verify superseded run cannot overwrite evidence. This checks that real PostgreSQL constraints and lifecycle updates behave as intended."""
        await self.save(collected())
        with self.assertRaises(RuntimeError):
            await repository.save_result(self.connection,uuid4(),collected(empty=True),86400,3600)
        self.assertEqual((await repository.get_page(CVE,25,0,False)).total,1)

    async def test_interrupted_job_is_recovered_without_removing_data(self):
        """Verify interrupted job is recovered without removing data. This checks that real PostgreSQL constraints and lifecycle updates behave as intended."""
        await self.save(collected())
        await self.connection.execute("UPDATE otx_jobs SET next_check_at=NOW()")
        await repository.start_next_job(self.connection)
        await repository.recover_interrupted_jobs(self.connection)
        page = await repository.get_page(CVE,25,0,False)
        self.assertEqual(page.total,1)
        self.assertEqual(page.job.state,"pending")
