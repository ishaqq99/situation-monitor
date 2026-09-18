"""Unit and HTTP-contract tests for the completed EPSS feature."""

import unittest
import asyncio
from contextlib import ExitStack
from datetime import date, datetime, timezone
from unittest.mock import AsyncMock, patch

import httpx
from fastapi import FastAPI

from app.api import epss as api
from app.collectors.epss import (
    EPSSResponseError,
    normalize_cve_id,
    normalize_cve_ids,
    parse_epss_batch_response,
)
from app.models.epss import EPSSRefreshResult, EPSSScore
from app.services import epss_service as service
from app.collectors import epss as collector


SCORE = EPSSScore(
    cve_id="CVE-2021-44228",
    epss_score=0.94,
    percentile=0.99,
    score_date=date(2026, 9, 17),
)

REFRESH_RESULT = EPSSRefreshResult(
    requested_count=1,
    stored_count=1,
    unavailable_count=0,
    refreshed_at=datetime(2026, 9, 17, tzinfo=timezone.utc),
)


class CollectorParsing(unittest.TestCase):
    def test_normalization_and_duplicate_removal(self):
        self.assertEqual(normalize_cve_id(" cve-2021-44228 "), "CVE-2021-44228")
        self.assertEqual(
            normalize_cve_ids(["CVE-2021-44228", " cve-2021-44228 "]),
            ["CVE-2021-44228"],
        )

    def test_invalid_identifier_is_rejected(self):
        with self.assertRaises(ValueError):
            normalize_cve_id("not-a-cve")

    def test_valid_batch_response(self):
        payload = {
            "status": "OK",
            "data": [
                {
                    "cve": "CVE-2021-44228",
                    "epss": "0.94",
                    "percentile": "0.99",
                    "date": "2026-09-17",
                }
            ],
        }
        self.assertEqual(
            parse_epss_batch_response(payload, {"CVE-2021-44228"}),
            [SCORE],
        )

    def test_unrequested_cve_is_rejected(self):
        payload = {
            "status": "OK",
            "data": [
                {
                    "cve": "CVE-2025-11111",
                    "epss": "0.10",
                    "percentile": "0.50",
                    "date": "2026-09-17",
                }
            ],
        }
        with self.assertRaises(EPSSResponseError):
            parse_epss_batch_response(payload, {"CVE-2021-44228"})


class ServiceRefresh(unittest.IsolatedAsyncioTestCase):
    async def test_refresh_connects_collector_repository_and_status(self):
        with (
            patch.object(
                service.cache,
                "acquire_epss_refresh_lock",
                AsyncMock(return_value="owner"),
            ),
            patch.object(
                service.cache,
                "release_epss_refresh_lock",
                AsyncMock(),
            ) as release,
            patch.object(
                service.cache,
                "get_epss_refresh_cooldown_remaining",
                AsyncMock(return_value=0),
            ),
            patch.object(
                service,
                "count_kev_entries",
                AsyncMock(return_value=1),
            ),
            patch.object(
                service,
                "get_kev_cve_ids_needing_epss",
                AsyncMock(return_value=[SCORE.cve_id]),
            ),
            patch.object(
                service,
                "fetch_epss_scores",
                AsyncMock(return_value=[SCORE]),
            ) as fetch,
            patch.object(
                service,
                "upsert_epss_scores",
                AsyncMock(return_value=1),
            ) as upsert,
            patch.object(
                service.cache,
                "publish_epss_refresh",
                AsyncMock(),
            ) as publish,
        ):
            result = await service.refresh_epss_data()

        self.assertEqual(result.requested_count, 1)
        self.assertEqual(result.stored_count, 1)
        fetch.assert_awaited_once_with([SCORE.cve_id])
        upsert.assert_awaited_once_with([SCORE])
        publish.assert_awaited_once()
        release.assert_awaited_once_with("owner")

    async def test_lock_contention_stops_before_collection(self):
        with patch.object(
            service.cache,
            "acquire_epss_refresh_lock",
            AsyncMock(return_value=None),
        ), patch.object(service, "fetch_epss_scores", AsyncMock()) as fetch:
            with self.assertRaises(service.EPSSRefreshInProgressError):
                await service.refresh_epss_data()
        fetch.assert_not_awaited()


class ApiTestCase(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        application = FastAPI()
        application.include_router(api.router)
        self.client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=application),
            base_url="http://test",
        )

    async def asyncTearDown(self):
        await self.client.aclose()


class ApiContracts(ApiTestCase):
    async def test_stored_score_contract(self):
        with patch.object(
            api,
            "get_stored_epss_score",
            AsyncMock(return_value=SCORE),
        ):
            response = await self.client.get("/api/epss/CVE-2021-44228")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["epss_score"], 0.94)

    async def test_missing_score_returns_404(self):
        with patch.object(
            api,
            "get_stored_epss_score",
            AsyncMock(return_value=None),
        ):
            response = await self.client.get("/api/epss/CVE-2021-44228")
        self.assertEqual(response.status_code, 404)

    async def test_refresh_contract(self):
        with patch.object(
            api,
            "refresh_epss_data",
            AsyncMock(return_value=REFRESH_RESULT),
        ):
            response = await self.client.post("/api/epss/refresh")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["stored_count"], 1)


class FailureSafety(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        def mock(obj, name, **kwargs):
            return self.stack.enter_context(patch.object(obj, name, AsyncMock(**kwargs)))
        self.lock = mock(service.cache, "acquire_epss_refresh_lock", return_value="owner")
        self.release = mock(service.cache, "release_epss_refresh_lock")
        self.cooldown = mock(service.cache, "get_epss_refresh_cooldown_remaining", return_value=0)
        self.catalog = mock(service, "count_kev_entries", return_value=1)
        self.pending = mock(service, "get_kev_cve_ids_needing_epss", return_value=[SCORE.cve_id])
        self.fetch = mock(service, "fetch_epss_scores", return_value=[SCORE])
        self.upsert = mock(service, "upsert_epss_scores", return_value=1)
        self.publish = mock(service.cache, "publish_epss_refresh")
        self.failed = mock(service.cache, "publish_epss_failure")

    async def test_empty_catalog_is_not_a_successful_daily_refresh(self):
        self.catalog.return_value = 0
        with self.assertRaises(service.EPSSCatalogNotReadyError):
            await service.refresh_epss_data()
        self.publish.assert_not_awaited()
        self.fetch.assert_not_awaited()
        self.release.assert_awaited_once_with("owner")

    async def test_timeout_preserves_success_and_releases_lock(self):
        self.fetch.side_effect = TimeoutError()
        with self.assertRaises(TimeoutError):
            await service.refresh_epss_data()
        self.upsert.assert_not_awaited()
        self.publish.assert_not_awaited()
        self.failed.assert_awaited_once()
        self.release.assert_awaited_once_with("owner")

    async def test_cancellation_releases_lock_without_recording_success(self):
        self.fetch.side_effect = asyncio.CancelledError()
        with self.assertRaises(asyncio.CancelledError):
            await service.refresh_epss_data()
        self.publish.assert_not_awaited()
        self.release.assert_awaited_once_with("owner")

    async def test_missing_provider_score_does_not_repeat_candidates(self):
        self.fetch.return_value = []
        self.upsert.return_value = 0
        result = await service.refresh_epss_data()
        self.assertEqual(result.unavailable_count, 1)
        self.pending.assert_awaited_once()

    async def test_cooldown_does_not_call_provider(self):
        self.cooldown.return_value = 100
        with self.assertRaises(service.EPSSRefreshCooldownError):
            await service.refresh_epss_data()
        self.fetch.assert_not_awaited()
        self.failed.assert_not_awaited()
        self.release.assert_awaited_once_with("owner")

    async def test_redis_failure_blocks_unlocked_ingestion(self):
        self.lock.side_effect = ConnectionError()
        with self.assertRaises(ConnectionError):
            await service.refresh_epss_data()
        self.fetch.assert_not_awaited()

    async def test_read_normalizes_and_does_not_download(self):
        with patch.object(service, "get_epss_score_by_cve", AsyncMock(return_value=SCORE)) as read:
            self.assertEqual(await service.get_stored_epss_score(" cve-2021-44228 "), SCORE)
        read.assert_awaited_once_with(SCORE.cve_id)
        self.fetch.assert_not_awaited()


class BatchCollection(unittest.IsolatedAsyncioTestCase):
    async def test_multiple_batches_are_fully_consumed(self):
        identifiers = [f"CVE-2025-{number:04d}" for number in range(250)]
        requests = []
        def response_for(request):
            batch = request.url.params["cve"].split(",")
            requests.append(batch)
            return httpx.Response(200, json={"status": "OK", "total": len(batch), "data": [
                {"cve": cve, "epss": "0.5", "percentile": "0.8", "date": "2026-09-17"}
                for cve in batch
            ]})
        client = httpx.AsyncClient(transport=httpx.MockTransport(response_for))
        with patch.object(collector.httpx, "AsyncClient", return_value=client):
            scores = await collector.fetch_epss_scores(identifiers)
        self.assertEqual([score.cve_id for score in scores], identifiers)
        self.assertEqual([len(batch) for batch in requests], [100, 100, 50])

    def test_invalid_and_truncated_responses_are_rejected(self):
        valid = {"cve": SCORE.cve_id, "epss": "0.5", "percentile": "0.8", "date": "2026-09-17"}
        for payload in [
            {}, {"status": "ERROR", "data": []},
            {"status": "OK", "data": [valid, valid]},
            {"status": "OK", "total": 2, "data": [valid]},
            {"status": "OK", "data": [dict(valid, epss="NaN")]},
            {"status": "OK", "data": [dict(valid, percentile="2")]},
        ]:
            with self.subTest(payload=payload), self.assertRaises(EPSSResponseError):
                parse_epss_batch_response(payload, {SCORE.cve_id})


class WorkerRecovery(unittest.IsolatedAsyncioTestCase):
    async def test_failure_retries_before_daily_interval(self):
        from app.workers import epss_worker as worker
        stop = asyncio.Event()
        attempts = 0
        async def refresh():
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise service.EPSSCatalogNotReadyError()
            stop.set()
            return REFRESH_RESULT
        with patch.object(worker, "EPSS_STARTUP_DELAY_SECONDS", 0.001), patch.object(
            worker, "EPSS_RETRY_INTERVAL_SECONDS", 0.001,
        ), patch.object(worker, "refresh_epss_data", refresh):
            await asyncio.wait_for(worker.run_epss_worker(stop), 1)
        self.assertEqual(attempts, 2)


class ErrorContracts(ApiTestCase):
    async def test_refresh_error_codes_and_safe_messages(self):
        from redis.exceptions import ConnectionError as RedisConnectionError
        cases = [
            (service.EPSSRefreshCooldownError(42), 429),
            (service.EPSSCatalogNotReadyError("Waiting for KEV"), 409),
            (httpx.ReadTimeout("private info"), 504),
            (EPSSResponseError("private info"), 502),
            (RedisConnectionError("private info"), 503),
        ]
        for error, status in cases:
            with self.subTest(status=status), patch.object(api, "refresh_epss_data", AsyncMock(side_effect=error)):
                response = await self.client.post("/api/epss/refresh")
            self.assertEqual(response.status_code, status)
            self.assertNotIn("private info", response.text)
            if status == 429:
                self.assertEqual(response.headers["Retry-After"], "42")

    async def test_invalid_cve_and_database_unavailable(self):
        invalid = await self.client.get("/api/epss/invalid")
        self.assertEqual(invalid.status_code, 422)
        with patch.object(api, "get_stored_epss_score", AsyncMock(side_effect=RuntimeError("secret"))):
            response = await self.client.get(f"/api/epss/{SCORE.cve_id}")
        self.assertEqual(response.status_code, 503)
        self.assertNotIn("secret", response.text)


if __name__ == "__main__":
    unittest.main()
