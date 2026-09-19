"""Unit/API tests for automated NVD enrichment orchestration.

TEST SCOPE
----------
These tests do not contact live NVD, PostgreSQL, or Redis. They verify that the
service connects candidate selection -> collector -> repository -> status, that
locking/rate-limit safety works, and that FastAPI exposes stable NVD contracts.

Real PostgreSQL behavior remains covered by test_nvd_storage_integration.py.
"""

import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import httpx
from fastapi import FastAPI

from app.api import nvd as api
from app.models.nvd import (
    NVDCVE,
    NVDCVSSChange,
    NVDCVSSMetric,
    NVDRefreshResult,
)
from app.services import nvd_service as service


NOW = datetime(2026, 9, 19, tzinfo=timezone.utc)
CVE_ID = "CVE-2021-44228"

METRIC = NVDCVSSMetric(
    cvss_version="3.1",
    base_score=9.8,
    base_severity="CRITICAL",
    vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    source="nvd@nist.gov",
    metric_type="Primary",
    exploitability_score=3.9,
    impact_score=5.9,
)

RECORD = NVDCVE(
    cve_id=CVE_ID,
    source_identifier="cve@mitre.org",
    published_at=NOW - timedelta(days=30),
    last_modified_at=NOW - timedelta(days=1),
    vuln_status="Analyzed",
    description="Test NVD record",
    cvss=METRIC,
    cwes=["CWE-502"],
    affected_cpes=[],
    reference_urls=["https://example.test/advisory"],
    fetched_at=NOW,
)

CHANGE = NVDCVSSChange(
    cve_id=CVE_ID,
    observed_at=NOW,
    nvd_last_modified_at=NOW - timedelta(days=1),
    previous_cvss=METRIC.model_copy(update={"base_score": 9.0}),
    current_cvss=METRIC,
)

REFRESH_RESULT = NVDRefreshResult(
    requested_count=1,
    stored_count=1,
    unavailable_count=0,
    failed_count=0,
    remaining_count=10,
    refreshed_at=NOW,
)


class ServiceRefresh(unittest.IsolatedAsyncioTestCase):
    async def test_refresh_connects_candidates_collector_storage_and_status(self):
        with (
            patch.object(
                service.cache,
                "acquire_nvd_refresh_lock",
                AsyncMock(return_value="owner"),
            ),
            patch.object(
                service.cache,
                "release_nvd_refresh_lock",
                AsyncMock(),
            ) as release,
            patch.object(
                service.cache,
                "get_nvd_refresh_cooldown_remaining",
                AsyncMock(return_value=0),
            ),
            patch.object(
                service,
                "count_kev_entries",
                AsyncMock(return_value=2),
            ),
            patch.object(
                service,
                "get_kev_cve_ids_needing_nvd",
                AsyncMock(return_value=[CVE_ID, "CVE-2025-12345"]),
            ) as candidates,
            patch.object(
                service,
                "fetch_nvd_cve",
                AsyncMock(side_effect=[RECORD, None]),
            ) as fetch,
            patch.object(
                service,
                "upsert_nvd_cve",
                AsyncMock(return_value=RECORD),
            ) as upsert,
            patch.object(
                service,
                "count_nvd_refresh_candidates",
                AsyncMock(return_value=0),
            ),
            patch.object(
                service.cache,
                "publish_nvd_refresh",
                AsyncMock(),
            ) as publish,
            patch.object(service.asyncio, "sleep", AsyncMock()) as sleep,
        ):
            result = await service.refresh_nvd_data()

        self.assertEqual(result.requested_count, 2)
        self.assertEqual(result.stored_count, 1)
        self.assertEqual(result.unavailable_count, 1)
        self.assertEqual(result.failed_count, 0)
        self.assertEqual(result.remaining_count, 0)
        candidates.assert_awaited_once()
        self.assertEqual(fetch.await_count, 2)
        upsert.assert_awaited_once_with(RECORD)
        sleep.assert_awaited_once()
        publish.assert_awaited_once()
        release.assert_awaited_once_with("owner")

    async def test_lock_contention_stops_before_collection(self):
        with (
            patch.object(
                service.cache,
                "acquire_nvd_refresh_lock",
                AsyncMock(return_value=None),
            ),
            patch.object(service, "fetch_nvd_cve", AsyncMock()) as fetch,
        ):
            with self.assertRaises(service.NVDRefreshInProgressError):
                await service.refresh_nvd_data()

        fetch.assert_not_awaited()

    async def test_provider_rate_limit_stops_batch_and_releases_lock(self):
        request = httpx.Request("GET", "https://services.nvd.nist.gov/test")
        response = httpx.Response(429, request=request, headers={"Retry-After": "45"})
        rate_error = httpx.HTTPStatusError(
            "rate limited",
            request=request,
            response=response,
        )

        with (
            patch.object(
                service.cache,
                "acquire_nvd_refresh_lock",
                AsyncMock(return_value="owner"),
            ),
            patch.object(
                service.cache,
                "release_nvd_refresh_lock",
                AsyncMock(),
            ) as release,
            patch.object(
                service.cache,
                "get_nvd_refresh_cooldown_remaining",
                AsyncMock(return_value=0),
            ),
            patch.object(service, "count_kev_entries", AsyncMock(return_value=1)),
            patch.object(
                service,
                "get_kev_cve_ids_needing_nvd",
                AsyncMock(return_value=[CVE_ID]),
            ),
            patch.object(
                service,
                "fetch_nvd_cve",
                AsyncMock(side_effect=rate_error),
            ),
            patch.object(
                service.cache,
                "publish_nvd_failure",
                AsyncMock(),
            ),
        ):
            with self.assertRaises(service.NVDProviderRateLimitError) as caught:
                await service.refresh_nvd_data()

        self.assertEqual(caught.exception.retry_after, 45)
        release.assert_awaited_once_with("owner")


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
    async def test_stored_nvd_contract(self):
        with patch.object(
            api,
            "get_stored_nvd_cve",
            AsyncMock(return_value=RECORD),
        ):
            response = await self.client.get(f"/api/nvd/{CVE_ID}")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["cvss"]["base_score"], 9.8)

    async def test_missing_nvd_returns_404(self):
        with patch.object(
            api,
            "get_stored_nvd_cve",
            AsyncMock(return_value=None),
        ):
            response = await self.client.get(f"/api/nvd/{CVE_ID}")

        self.assertEqual(response.status_code, 404)

    async def test_history_contract(self):
        with patch.object(
            api,
            "get_stored_nvd_history",
            AsyncMock(return_value=[CHANGE]),
        ):
            response = await self.client.get(f"/api/nvd/{CVE_ID}/history")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()[0]["previous_cvss"]["base_score"], 9.0)
        self.assertEqual(response.json()[0]["current_cvss"]["base_score"], 9.8)

    async def test_refresh_contract(self):
        with patch.object(
            api,
            "refresh_nvd_data",
            AsyncMock(return_value=REFRESH_RESULT),
        ):
            response = await self.client.post("/api/nvd/refresh")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["remaining_count"], 10)


if __name__ == "__main__":
    unittest.main()
