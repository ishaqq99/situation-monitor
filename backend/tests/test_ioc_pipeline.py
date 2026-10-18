"""Offline tests for OTX storage policy, job orchestration, and HTTP boundaries.

No database, Redis, or live provider is contacted. The service tests substitute
the repository/connection at their boundary, then verify observable decisions:
no collector on GET, cooldown persistence, preservation on failure, and scope.
Real SQL behavior has a separate opt-in PostgreSQL integration test file.


FILE GUIDE
----------
WHAT THIS FILE DOES
Check OTX scheduling, write policy, and API behavior without external services.

WHY IT EXISTS
Service and route guarantees should be testable before connecting to a real database.

WHO CALLS OR IMPORTS IT
unittest discovers this file during the offline IOC test command.

WHAT IT CALLS OR IMPORTS
Mocks the repository/provider boundaries and calls service/API functions.

ROLE IN THE ARCHITECTURE
Offline orchestration tests; real SQL has a separate integration suite.
"""
import asyncio
import unittest
from contextlib import asynccontextmanager, ExitStack
from datetime import datetime, timedelta, timezone
from uuid import uuid4
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
from fastapi import FastAPI
from app.api import ioc as api
from app.collectors import otx
from app.models.ioc import CVEIOCEnrichment, IOCIndicator, IOCObservation, IOCRelationshipType
from app.models.ioc_api import IOCPage, IOCProviderStatus, IOCQueueResult
from app.services import ioc_service as service
from app.storage import ioc_repository as repository

CVE = "CVE-2017-0144"
REAL_SAVE_RESULT = repository.save_result


def result():
    """Build one normalized collection result for service/storage assertions."""
    return CVEIOCEnrichment(cve_id=CVE, source="AlienVault OTX", collection_scope="focused_only")


def observation(**fields):
    """Build one normalized IOC observation for lifecycle and storage checks."""
    values = dict(cve_id=CVE, indicator=IOCIndicator(indicator_type="ipv4",value="192.0.2.1"),
                  relationship_type=IOCRelationshipType.PULSE_CONTEXT, source="AlienVault OTX",
                  source_record_id="a"*24)
    return IOCObservation(**(values | fields))


class StoragePolicyTests(unittest.TestCase):
    """Group cases that check service, route, and storage policies remain correct offline."""
    def test_indicator_identity_covers_type_and_entire_long_value(self):
        """Verify indicator identity covers type and entire long value. This checks that service, route, and storage policies remain correct offline."""
        first = repository.indicator_key("url", "https://example.com/" + "a" * 3900)
        self.assertEqual(len(first), 64)
        self.assertNotEqual(first, repository.indicator_key("url", "https://example.com/" + "a" * 3899 + "b"))
        self.assertNotEqual(repository.indicator_key("domain", "example.com"), repository.indicator_key("hostname", "example.com"))

    def test_lifecycle_is_separate_from_evidence_strength(self):
        """Verify lifecycle is separate from evidence strength. This checks that service, route, and storage policies remain correct offline."""
        now = datetime.now(timezone.utc)
        cases = [(observation(active=True), None, "active"),
                 (observation(active=False), None, "inactive"),
                 (observation(), None, "unknown"),
                 (observation(active=True,expires_at=now-timedelta(days=1)), None, "expired"),
                 (observation(active=True), now, "not_in_latest_scope")]
        for entry, absent, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(repository.lifecycle(entry, absent), expected)
                self.assertEqual(entry.relationship_type, IOCRelationshipType.PULSE_CONTEXT)

    def test_expiration_is_normalized_from_provider_metadata(self):
        """Verify expiration is normalized from provider metadata. This checks that service, route, and storage policies remain correct offline."""
        entry = otx._observation_from_otx(cve_id=CVE, pulse={"id":"a"*24},
            raw_indicator={"type":"IPv4","indicator":"192.0.2.1","is_active":0,
                           "expiration":"2020-01-01T00:00:00Z"}, fetched_at=datetime.now(timezone.utc))
        self.assertFalse(entry.active)
        self.assertEqual(entry.expires_at.year, 2020)


class ServiceTests(unittest.IsolatedAsyncioTestCase):
    """Group cases that check service, route, and storage policies remain correct offline."""
    def setUp(self):
        """Prepare mocks and settings shared by the tests in this class."""
        self.connection = MagicMock()
        self.connection.fetchval = AsyncMock(side_effect=[True, True])
        self.connection.execute = AsyncMock()
        self.connection.is_closed.return_value = False
        self.connection.transaction.return_value.__aenter__ = AsyncMock()
        self.connection.transaction.return_value.__aexit__ = AsyncMock(return_value=False)
        self.run_id = uuid4()

        @asynccontextmanager
        async def connection_context():
            """Replace the shared-pool context manager with a controlled in-memory test connection."""
            yield self.connection

        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(service, "db_connection", connection_context))
        self.stack.enter_context(patch.object(service, "OTX_ENABLED", True))
        self.stack.enter_context(patch.object(service, "OTX_API_KEY", "test-key"))
        for name in ("seed_jobs", "recover_interrupted_jobs", "record_failure", "save_result"):
            self.stack.enter_context(patch.object(repository, name, AsyncMock()))
        self.stack.enter_context(patch.object(repository, "start_next_job", AsyncMock(return_value=(CVE,self.run_id))))
        self.collect = self.stack.enter_context(patch.object(service, "fetch_otx_cve_iocs", AsyncMock(return_value=result())))

    async def test_complete_empty_response_is_saved_as_success(self):
        """Verify complete empty response is saved as success. This checks that service, route, and storage policies remain correct offline."""
        self.assertEqual(await service.run_one_due_job(), "complete")
        self.collect.assert_awaited_once_with(CVE, include_context=False)
        repository.save_result.assert_awaited_once()
        repository.record_failure.assert_not_awaited()

    async def test_404_does_not_overwrite_stored_evidence(self):
        """Verify 404 does not overwrite stored evidence. This checks that service, route, and storage policies remain correct offline."""
        self.collect.side_effect = otx.OTXNotFoundError("404 is unknown")
        self.assertEqual(await service.run_one_due_job(), "failed")
        repository.save_result.assert_not_awaited()
        repository.record_failure.assert_awaited_once()

    async def test_provider_cooldown_prevents_collection(self):
        """Verify provider cooldown prevents collection. This checks that service, route, and storage policies remain correct offline."""
        self.connection.fetchval.side_effect = [True, False]
        self.assertEqual(await service.run_one_due_job(), "provider_cooldown")
        self.collect.assert_not_awaited()
        repository.start_next_job.assert_not_awaited()

    async def test_advisory_lock_loser_does_not_claim_work(self):
        """Verify advisory lock loser does not claim work. This checks that service, route, and storage policies remain correct offline."""
        self.connection.fetchval.side_effect = [False]
        self.assertEqual(await service.run_one_due_job(), "another_worker")
        self.collect.assert_not_awaited()
        repository.start_next_job.assert_not_awaited()

    async def test_rate_limit_persists_deadline_and_stops(self):
        """Verify rate limit persists deadline and stops. This checks that service, route, and storage policies remain correct offline."""
        failure = otx.OTXRetryLaterError("cooldown", 120)
        self.collect.side_effect = failure
        self.assertEqual(await service.run_one_due_job(), "deferred")
        calls = [call for call in self.connection.execute.await_args_list
                 if "next_allowed_at=$1" in call.args[0]]
        self.assertEqual(len(calls), 1)
        self.assertGreaterEqual(calls[0].args[1], failure.retry_at)
        self.assertTrue(repository.record_failure.await_args.args[-1])
        repository.save_result.assert_not_awaited()

    async def test_partial_result_is_stored_without_becoming_complete(self):
        """Verify partial result is stored without becoming complete. This checks that service, route, and storage policies remain correct offline."""
        self.collect.return_value = result().model_copy(update={"complete":False})
        self.assertEqual(await service.run_one_due_job(), "partial")
        self.assertFalse(repository.save_result.await_args.args[2].complete)

    async def test_cancel_propagates_and_unlocks(self):
        """Verify cancel propagates and unlocks. This checks that service, route, and storage policies remain correct offline."""
        self.collect.side_effect = asyncio.CancelledError
        with self.assertRaises(asyncio.CancelledError):
            await service.run_one_due_job()
        self.assertIn("pg_advisory_unlock", self.connection.execute.await_args.args[0])
        repository.record_failure.assert_not_awaited()

    async def test_disabled_feature_keeps_jobs_but_does_not_collect(self):
        """Verify disabled feature keeps jobs but does not collect. This checks that service, route, and storage policies remain correct offline."""
        with patch.object(service, "OTX_ENABLED", False):
            self.assertEqual(await service.run_one_due_job(), "disabled_or_missing_key")
        repository.seed_jobs.assert_awaited_once()
        self.collect.assert_not_awaited()

    async def test_reading_a_cve_never_calls_collector(self):
        """Verify reading a cve never calls collector. This checks that service, route, and storage policies remain correct offline."""
        page = IOCPage(cve_id=CVE,job=None,total=0,limit=25,offset=0,include_history=False)
        with patch.object(repository, "get_page", AsyncMock(return_value=page)) as read:
            self.assertEqual(await service.get_stored_iocs(CVE.lower(),25,0,False), page)
        read.assert_awaited_once_with(CVE,25,0,False)
        self.collect.assert_not_awaited()

    async def test_manual_refresh_only_enqueues(self):
        """Verify manual refresh only enqueues. This checks that service, route, and storage policies remain correct offline."""
        with patch.object(repository, "queue_refresh", AsyncMock(return_value=(True,"pending"))):
            self.assertTrue((await service.request_ioc_refresh(CVE)).queued)
        self.collect.assert_not_awaited()

    async def test_storage_rejects_exploratory_scope_before_sql(self):
        """Verify storage rejects exploratory scope before sql. This checks that service, route, and storage policies remain correct offline."""
        value = result().model_copy(update={"collection_scope":"all_pulses"})
        # Bypass the service-test mock and assert the repository rejects this
        # incompatible scope before making any database mutation.
        with self.assertRaises(ValueError):
            await REAL_SAVE_RESULT(self.connection, self.run_id, value, 86400, 3600)
        self.connection.execute.assert_not_awaited()

    async def test_failed_job_pacing_is_measured_from_completion(self):
        """Verify failed job pacing is measured from completion. This checks that service, route, and storage policies remain correct offline."""
        self.collect.side_effect = otx.OTXProviderUnavailableError("temporary failure")
        with patch.object(service,"OTX_JOB_DELAY_SECONDS",60):
            before = datetime.now(timezone.utc)
            self.assertEqual(await service.run_one_due_job(),"failed")
        calls = [call for call in self.connection.execute.await_args_list
                 if "next_allowed_at=$1" in call.args[0]]
        self.assertGreaterEqual(calls[0].args[1],before+timedelta(seconds=60))

    async def test_each_transport_attempt_is_paced(self):
        """Verify each transport attempt is paced. This checks that service, route, and storage policies remain correct offline."""
        async with httpx.AsyncClient(transport=httpx.MockTransport(
            lambda request: httpx.Response(200,json={"ok":True})
        ),trust_env=False) as client:
            with patch.object(otx,"OTX_REQUEST_DELAY_SECONDS",1.25), patch.object(
                otx.asyncio,"sleep",AsyncMock()
            ) as sleep:
                value = await otx._request_json(client,
                    f"https://otx.alienvault.com/api/v1/indicators/cve/{CVE}/general")
        self.assertTrue(value["ok"])
        sleep.assert_awaited_once_with(1.25)


class HttpRouteTests(unittest.IsolatedAsyncioTestCase):
    """Group cases that check service, route, and storage policies remain correct offline."""
    async def asyncSetUp(self):
        """Prepare asynchronous test fixtures before each case."""
        app = FastAPI()
        app.include_router(api.router)
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url="http://test")

    async def asyncTearDown(self):
        """Release asynchronous test fixtures after each case."""
        await self.client.aclose()

    async def test_stored_details_and_status_contracts(self):
        """Verify stored details and status contracts. This checks that service, route, and storage policies remain correct offline."""
        page = IOCPage(cve_id=CVE,job=None,total=0,limit=25,offset=0,include_history=False)
        status = IOCProviderStatus(enabled=True,configured=True,total_kevs=1,scheduled_kevs=1,
            ever_completed=0,due_jobs=1,running_jobs=0,failed_or_partial=0,stored_observations=0)
        with patch.object(api,"get_stored_iocs",AsyncMock(return_value=page)), patch.object(
            api,"get_ioc_status",AsyncMock(return_value=status)):
            self.assertEqual((await self.client.get(f"/api/ioc/{CVE}")).json()["total"],0)
            self.assertEqual((await self.client.get("/api/ioc/status")).json()["due_jobs"],1)

    async def test_invalid_pagination_rejected(self):
        """Verify invalid pagination rejected. This checks that service, route, and storage policies remain correct offline."""
        with patch.object(api,"get_stored_iocs",AsyncMock()) as read:
            self.assertEqual((await self.client.get(f"/api/ioc/{CVE}?limit=9999")).status_code,422)
            self.assertEqual((await self.client.get(f"/api/ioc/{CVE}?offset=-1")).status_code,422)
        read.assert_not_awaited()

    async def test_unknown_kev_is_not_an_empty_success(self):
        """Verify unknown kev is not an empty success. This checks that service, route, and storage policies remain correct offline."""
        with patch.object(api,"get_stored_iocs",AsyncMock(side_effect=LookupError("missing"))):
            self.assertEqual((await self.client.get(f"/api/ioc/{CVE}")).status_code,404)

    async def test_refresh_returns_accepted_not_completed(self):
        """Verify refresh returns accepted not completed. This checks that service, route, and storage policies remain correct offline."""
        value = IOCQueueResult(cve_id=CVE,queued=True,state="pending",message="Queued")
        with patch.object(api,"request_ioc_refresh",AsyncMock(return_value=value)):
            response = await self.client.post(f"/api/ioc/{CVE}/refresh")
        self.assertEqual(response.status_code,202)
        self.assertEqual(response.json()["state"],"pending")
