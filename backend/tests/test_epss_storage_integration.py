"""Opt-in EPSS tests using real PostgreSQL/Redis and a mocked FIRST response.

All SQL changes roll back in a unique schema. Redis keys have a random prefix
and are deleted in finally. The normal catalog/cache is never modified.
"""
import os
import unittest
from contextlib import asynccontextmanager, ExitStack
from datetime import date
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import asyncpg
import httpx
import redis.asyncio as redis

from app.config import DATABASE_URL, REDIS_URL
from app.main import app
from app.storage import postgres, kev_repository, epss_repository, epss_cache
from app.services import epss_service
from app.models.epss import EPSSScore
from test_kev import ENTRY


@unittest.skipUnless(os.getenv("KEV_INTEGRATION_TESTS") == "1", "Opt-in storage test")
class EPSSStorageIntegration(unittest.IsolatedAsyncioTestCase):
    async def test_real_storage_locking_and_http(self):
        connection = await asyncpg.connect(DATABASE_URL, timeout=5, command_timeout=30)
        client = redis.from_url(REDIS_URL, decode_responses=True, socket_timeout=5,
                                socket_connect_timeout=5)
        transaction = connection.transaction()
        await transaction.start()
        prefix = "epss-test:" + uuid4().hex
        names = ["EPSS_REFRESH_LOCK_KEY", "EPSS_LAST_REFRESH_KEY",
                 "EPSS_LAST_RESULT_KEY", "EPSS_LAST_ERROR_KEY"]
        keys = [prefix + ":" + name for name in names]

        @asynccontextmanager
        async def isolated_connection():
            yield connection

        try:
            schema = "epss_" + uuid4().hex
            await connection.execute(f'CREATE SCHEMA "{schema}"')
            await connection.execute(f'SET LOCAL search_path TO "{schema}"')
            with ExitStack() as stack:
                for module in (postgres, kev_repository, epss_repository):
                    stack.enter_context(patch.object(module, "db_connection", isolated_connection))
                stack.enter_context(patch.object(epss_cache, "create_redis_client", return_value=client))
                for name, key in zip(names, keys):
                    stack.enter_context(patch.object(epss_cache, name, key))
                await postgres.initialize_database()
                await kev_repository.upsert_kev_entries([ENTRY])
                score = EPSSScore(cve_id=ENTRY.cve_id, epss_score=0.8,
                                  percentile=0.9, score_date=date.today())
                stack.enter_context(patch.object(epss_service, "fetch_epss_scores",
                                                 AsyncMock(return_value=[score])))
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as http:
                    self.assertEqual((await http.get(f"/api/epss/{ENTRY.cve_id}")).status_code, 404)
                    result = await http.post("/api/epss/refresh")
                    self.assertEqual(result.status_code, 200, result.text)
                    self.assertEqual(result.json()["stored_count"], 1)
                    status = (await http.get("/api/epss/status")).json()
                    self.assertEqual(status["total_stored_scores"], 1)
                    self.assertFalse(status["refresh_in_progress"])
                    self.assertEqual((await http.get(f"/api/epss/{ENTRY.cve_id.lower()}")).json()["epss_score"], 0.8)
                    self.assertEqual((await http.post("/api/epss/refresh")).status_code, 429)
                old = score.model_copy(update={"score_date": date(2020, 1, 1), "epss_score": 0.1})
                self.assertEqual(await epss_repository.upsert_epss_score(old), score)
                self.assertEqual(await epss_repository.get_kev_cve_ids_needing_epss(date.today()), [])

                # A failed batch must roll back even its earlier valid update.
                updated = score.model_copy(update={"epss_score": 0.6})
                unknown = score.model_copy(update={"cve_id": "CVE-2025-99999"})
                with self.assertRaises(asyncpg.ForeignKeyViolationError):
                    await epss_repository.upsert_epss_scores([updated, unknown])
                self.assertEqual(await epss_repository.get_epss_score_by_cve(ENTRY.cve_id), score)

                owner = await epss_cache.acquire_epss_refresh_lock()
                self.assertIsNone(await epss_cache.acquire_epss_refresh_lock())
                await client.set(keys[0], "successor", ex=300)
                await epss_cache.release_epss_refresh_lock(owner)
                self.assertEqual(await client.get(keys[0]), "successor")
                await epss_cache.release_epss_refresh_lock("successor")
                await epss_cache.publish_epss_failure("Example upstream failure")
                status = await epss_service.get_epss_status()
                self.assertIsNotNone(status.last_refreshed_at)
                self.assertEqual(status.last_error, "Example upstream failure")
        finally:
            try:
                await client.delete(*keys)
                await client.aclose()
            finally:
                await transaction.rollback()
                await connection.close()
