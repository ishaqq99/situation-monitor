"""Regression tests for the KEV import graph, HTTP contracts, and refresh safety.

External calls are mocked; these tests do not contact CISA or mutate local data.
Run from backend: python -B -m unittest discover -s tests -v


FILE GUIDE
----------
WHAT THIS FILE DOES
Retain KEV route, worker, and app-lifespan regression checks after adding OTX.

WHY IT EXISTS
Registering a new worker must not break existing KEV startup or refresh behavior.

WHO CALLS OR IMPORTS IT
unittest discovers this file with the existing backend tests.

WHAT IT CALLS OR IMPORTS
Mocks external services and checks the app entry point and existing KEV modules.

ROLE IN THE ARCHITECTURE
Existing-feature regression tests updated for the added IOC worker/schema.
"""
import asyncio
import importlib
import unittest
from contextlib import ExitStack
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import httpx
from app.main import app
from app.models.kev import KEVEntry, KEVCatalog, KEVFeedStatus, KEVRefreshResult
from app.services import kev_service as service
from app.storage import kev_cache as cache
from app.storage.kev_repository import _row_to_kev_entry
from app.collectors import cisa_kev as collector
from app.config import positive_int

ENTRY = KEVEntry(
    cve_id="CVE-2025-12345", vendor_project="Example", product="Widget",
    vulnerability_name="Example vulnerability", date_added="2025-01-01",
    due_date="2025-02-01", short_description="Description", required_action="Patch",
    cwes=["CWE-79"],
)
NOW = datetime.now(timezone.utc)
RESULT = KEVRefreshResult(fetched_count=1, stored_count=1, cached_count=1, refreshed_at=NOW)
CATALOG = KEVCatalog(catalog_version="1", date_released="2025-01-01", total_count=1, vulnerabilities=[ENTRY])


class Contracts(unittest.IsolatedAsyncioTestCase):
    """Group cases that check existing KEV behavior survives the new IOC integration."""
    async def asyncSetUp(self):
        # ASGITransport deliberately omits lifespan: startup is tested separately.
        """Prepare asynchronous test fixtures before each case."""
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")

    async def asyncTearDown(self):
        """Release asynchronous test fixtures after each case."""
        await self.client.aclose()

    async def test_all_five_routes_and_json_shapes(self):
        """Verify all five routes and json shapes. This checks that existing KEV behavior survives the new IOC integration."""
        status = KEVFeedStatus(last_refreshed_at=NOW, refresh_in_progress=False, cached_entries=1)
        cases = [
            ("GET", "/api/kev?limit=10", "get_latest_kev", [ENTRY], list),
            ("GET", "/api/kev/status", "get_kev_status", status, dict),
            ("POST", "/api/kev/refresh", "refresh_kev_data", RESULT, dict),
            ("GET", "/api/kev/search?q=Example", "search_kev", [ENTRY], list),
            ("GET", "/api/kev/CVE-2025-12345", "get_kev_details", ENTRY, dict),
        ]
        for method, path, name, result, shape in cases:
            with self.subTest(path=path), patch(f"app.api.kev.{name}", AsyncMock(return_value=result)):
                response = await self.client.request(method, path)
                self.assertEqual(response.status_code, 200, response.text)
                self.assertIsInstance(response.json(), shape)
                if path.endswith("refresh"):
                    self.assertIn("refreshed_at", response.json())
                if "CVE-" in path:
                    self.assertEqual(response.json()["date_added"], "2025-01-01")

    async def test_validation_and_not_found(self):
        """Verify validation and not found. This checks that existing KEV behavior survives the new IOC integration."""
        for path in ["/api/kev?limit=0", "/api/kev?limit=51", "/api/kev/search?q=", "/api/kev/search?q=" + "x" * 101]:
            response = await self.client.get(path)
            self.assertEqual(response.status_code, 422)
        with patch("app.api.kev.get_kev_details", AsyncMock(return_value=None)):
            self.assertEqual((await self.client.get("/api/kev/CVE-1900-0000")).status_code, 404)

    async def test_refresh_errors_and_retry_after(self):
        """Verify refresh errors and retry after. This checks that existing KEV behavior survives the new IOC integration."""
        for error, code in [(service.KEVRefreshInProgressError("Running"), 409),
                            (service.KEVRefreshCooldownError(42), 429),
                            (TimeoutError(), 504), (RuntimeError("private database detail"), 502)]:
            with patch("app.api.kev.refresh_kev_data", AsyncMock(side_effect=error)):
                response = await self.client.post("/api/kev/refresh")
                self.assertEqual(response.status_code, code)
                self.assertNotIn("private database detail", response.text)
                if code == 429:
                    self.assertEqual(response.headers["Retry-After"], "42")

    async def test_status_unavailable_is_independent_of_latest(self):
        """Verify status unavailable is independent of latest. This checks that existing KEV behavior survives the new IOC integration."""
        with patch("app.api.kev.get_kev_status", AsyncMock(side_effect=RuntimeError())), patch(
            "app.api.kev.get_latest_kev", AsyncMock(return_value=[ENTRY]),
        ):
            self.assertEqual((await self.client.get("/api/kev/status")).status_code, 503)
            self.assertEqual((await self.client.get("/api/kev")).status_code, 200)

    async def test_health_contract(self):
        """Verify health contract. This checks that existing KEV behavior survives the new IOC integration."""
        with patch("app.main.check_database_connection", AsyncMock(return_value=True)), patch(
            "app.main.check_redis_connection", AsyncMock(return_value=False),
        ):
            body = (await self.client.get("/api/health")).json()
            self.assertEqual(body, {"api": True, "status": "degraded", "database": "healthy", "redis": "unhealthy"})


class RefreshBehavior(unittest.IsolatedAsyncioTestCase):
    """Group cases that check existing KEV behavior survives the new IOC integration."""
    def setUp(self):
        """Prepare mocks and settings shared by the tests in this class."""
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.lock = self.stack.enter_context(patch.object(cache, "acquire_kev_refresh_lock", AsyncMock(return_value="owner-a")))
        self.release = self.stack.enter_context(patch.object(cache, "release_kev_refresh_lock", AsyncMock()))
        self.cooldown = self.stack.enter_context(patch.object(cache, "get_refresh_cooldown_remaining", AsyncMock(return_value=0)))
        self.download = self.stack.enter_context(patch.object(service, "fetch_kev_catalog", AsyncMock(return_value=CATALOG)))
        self.upsert = self.stack.enter_context(patch.object(service, "upsert_kev_entries", AsyncMock(return_value=1)))
        self.latest = self.stack.enter_context(patch.object(service, "get_latest_kev_entries", AsyncMock(return_value=[ENTRY])))
        self.publish = self.stack.enter_context(patch.object(cache, "publish_kev_refresh", AsyncMock()))

    async def test_success_includes_timestamp_and_releases_owner(self):
        """Verify success includes timestamp and releases owner. This checks that existing KEV behavior survives the new IOC integration."""
        result = await service.refresh_kev_data()
        self.assertEqual(result.stored_count, 1)
        self.assertIsNotNone(result.refreshed_at.tzinfo)
        self.publish.assert_awaited_once_with([ENTRY], result.refreshed_at)
        self.release.assert_awaited_once_with("owner-a")

    async def test_lock_contention_does_not_download_or_release_other_owner(self):
        """Verify lock contention does not download or release other owner. This checks that existing KEV behavior survives the new IOC integration."""
        self.lock.return_value = None
        with self.assertRaises(service.KEVRefreshInProgressError):
            await service.refresh_kev_data()
        self.download.assert_not_awaited()
        self.release.assert_not_awaited()

    async def test_cooldown_checked_under_lock(self):
        """Verify cooldown checked under lock. This checks that existing KEV behavior survives the new IOC integration."""
        self.cooldown.return_value = 20
        with self.assertRaises(service.KEVRefreshCooldownError):
            await service.refresh_kev_data()
        self.download.assert_not_awaited()
        self.release.assert_awaited_once_with("owner-a")

    async def test_database_failure_does_not_publish_success(self):
        """Verify database failure does not publish success. This checks that existing KEV behavior survives the new IOC integration."""
        self.upsert.side_effect = RuntimeError("DB unavailable")
        with self.assertRaises(RuntimeError):
            await service.refresh_kev_data()
        self.publish.assert_not_awaited()
        self.release.assert_awaited_once()

    async def test_download_failure_releases_lock(self):
        """Verify download failure releases lock. This checks that existing KEV behavior survives the new IOC integration."""
        self.download.side_effect = ValueError("Invalid catalog")
        with self.assertRaises(ValueError):
            await service.refresh_kev_data()
        self.upsert.assert_not_awaited()
        self.release.assert_awaited_once()

    async def test_redis_failure_prevents_unlocked_ingestion(self):
        """Verify redis failure prevents unlocked ingestion. This checks that existing KEV behavior survives the new IOC integration."""
        self.lock.side_effect = ConnectionError("Redis unavailable")
        with self.assertRaises(ConnectionError):
            await service.refresh_kev_data()
        self.download.assert_not_awaited()

    async def test_cancellation_releases_lock(self):
        """Verify cancellation releases lock. This checks that existing KEV behavior survives the new IOC integration."""
        self.download.side_effect = asyncio.CancelledError()
        with self.assertRaises(asyncio.CancelledError):
            await service.refresh_kev_data()
        self.release.assert_awaited_once_with("owner-a")

    async def test_read_falls_back_when_cache_is_unavailable(self):
        """Verify read falls back when cache is unavailable. This checks that existing KEV behavior survives the new IOC integration."""
        with patch.object(cache, "get_cached_kev_entries", AsyncMock(side_effect=ConnectionError())):
            self.assertEqual(await service.get_latest_kev(10), [ENTRY])
        self.download.assert_not_awaited()

    async def test_empty_cache_reads_db_without_download(self):
        """Verify empty cache reads db without download. This checks that existing KEV behavior survives the new IOC integration."""
        with patch.object(cache, "get_cached_kev_entries", AsyncMock(return_value=[])):
            self.assertEqual(await service.get_latest_kev(10), [ENTRY])
        self.download.assert_not_awaited()

    async def test_cache_hit_does_not_query_db(self):
        """Verify cache hit does not query db. This checks that existing KEV behavior survives the new IOC integration."""
        with patch.object(cache, "get_cached_kev_entries", AsyncMock(return_value=[ENTRY])):
            self.assertEqual(await service.get_latest_kev(1), [ENTRY])
        self.latest.assert_not_awaited()


class Normalization(unittest.TestCase):
    """Group cases that check existing KEV behavior survives the new IOC integration."""
    def test_complete_import_graph(self):
        """Verify complete import graph. This checks that existing KEV behavior survives the new IOC integration."""
        for module in ["app.main", "app.api.kev", "app.services.kev_service", "app.workers.kev_worker"]:
            importlib.import_module(module)

    def test_jsonb_row_conversion(self):
        """Verify jsonb row conversion. This checks that existing KEV behavior survives the new IOC integration."""
        row = ENTRY.model_dump()
        row["cwes"] = '["CWE-79"]'
        self.assertEqual(_row_to_kev_entry(row), ENTRY)

    def test_invalid_interval_is_rejected(self):
        """Verify invalid interval is rejected. This checks that existing KEV behavior survives the new IOC integration."""
        for value in ["0", "-1", "abc"]:
            with patch.dict("os.environ", {"TEST_INTERVAL": value}):
                with self.assertRaises(ValueError):
                    positive_int("TEST_INTERVAL", 1800)

    def test_empty_catalog_rejected(self):
        """Verify empty catalog rejected. This checks that existing KEV behavior survives the new IOC integration."""
        with self.assertRaises(ValueError):
            collector.normalize_kev_catalog({"vulnerabilities": [], "catalogVersion": "1", "dateReleased": "today", "count": 0})


class CollectorFallback(unittest.IsolatedAsyncioTestCase):
    """Group cases that check existing KEV behavior survives the new IOC integration."""
    async def test_invalid_primary_uses_mirror(self):
        """Verify invalid primary uses mirror. This checks that existing KEV behavior survives the new IOC integration."""
        with patch.object(collector, "download_kev_data", AsyncMock(side_effect=[{}, {"mirror": True}])) as download, patch.object(
            collector, "normalize_kev_catalog", side_effect=[KeyError("vulnerabilities"), CATALOG],
        ):
            self.assertEqual(await collector.fetch_kev_catalog(), CATALOG)
            self.assertEqual(download.await_args_list[1].args, (collector.CISA_KEV_FALLBACK_URL,))


class WorkerLifecycle(unittest.IsolatedAsyncioTestCase):
    """Group cases that check existing KEV behavior survives the new IOC integration."""
    async def test_worker_refreshes_immediately_and_stops(self):
        """Verify worker refreshes immediately and stops. This checks that existing KEV behavior survives the new IOC integration."""
        worker = importlib.import_module("app.workers.kev_worker")
        stop = asyncio.Event()
        async def refresh():
            """Provide a short fake KEV refresh operation for lifecycle assertions."""
            stop.set()
            return RESULT
        with patch.object(worker, "refresh_kev_data", AsyncMock(side_effect=refresh)) as run:
            await asyncio.wait_for(worker.run_kev_worker(stop), timeout=1)
            run.assert_awaited_once()

    async def test_lifespan_initializes_and_closes_resources(self):
        """Verify lifespan initializes and closes resources. This checks that existing KEV behavior survives the new IOC integration."""
        main = importlib.import_module("app.main")
        async def worker(stop):
            """Provide a controllable background worker for lifespan assertions."""
            await stop.wait()
        with ExitStack() as stack:
            initialize = stack.enter_context(patch.object(main, "initialize_pool", AsyncMock()))
            schema = stack.enter_context(patch.object(main, "initialize_database", AsyncMock()))
            # Startup now initializes the additive IOC schema too. Mock that
            # boundary so this remains an offline lifecycle test.
            ioc_schema = stack.enter_context(patch.object(main, "initialize_ioc_schema", AsyncMock()))
            close_db = stack.enter_context(patch.object(main, "close_database_pool", AsyncMock()))
            close_cache = stack.enter_context(patch.object(main, "close_redis_client", AsyncMock()))
            # Every worker is controlled here: test task startup/shutdown,
            # not provider calls, database access, or refresh policies.
            worker_mocks = [stack.enter_context(patch.object(main, name, AsyncMock(side_effect=worker)))
                            for name in ("run_kev_worker", "run_epss_worker", "run_nvd_worker", "run_ioc_worker")]
            async with main.lifespan(app):
                initialize.assert_awaited_once()
                schema.assert_awaited_once()
                ioc_schema.assert_awaited_once()
                await asyncio.sleep(0)
                for mock in worker_mocks:
                    mock.assert_awaited_once()
            close_cache.assert_awaited_once()
            close_db.assert_awaited_once()


if __name__ == "__main__":
    unittest.main()
