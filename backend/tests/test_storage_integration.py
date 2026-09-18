"""Opt-in tests against local PostgreSQL and Redis, without changing catalog data.

Set KEV_INTEGRATION_TESTS=1 to run. SQL stays in a rolled-back transaction with
an isolated schema. Redis keys use a random test prefix and are cleaned up.
"""
import os
import unittest
from contextlib import asynccontextmanager, ExitStack
from uuid import uuid4
from unittest.mock import AsyncMock, patch

import asyncpg
import httpx
import redis.asyncio as redis
from app.config import DATABASE_URL, REDIS_URL
from app.main import app
from app.storage import postgres, kev_repository as repository, kev_cache as cache
from app.services import kev_service as service
from test_kev import ENTRY, CATALOG


@unittest.skipUnless(os.getenv("KEV_INTEGRATION_TESTS") == "1", "Opt-in local storage test")
class StorageIntegration(unittest.IsolatedAsyncioTestCase):
    async def test_real_storage_and_all_http_routes(self):
        connection = await asyncpg.connect(DATABASE_URL, timeout=5, command_timeout=30)
        client = redis.from_url(REDIS_URL, decode_responses=True, socket_timeout=5, socket_connect_timeout=5)
        transaction = connection.transaction()
        await transaction.start()
        prefix = "kev-test:" + uuid4().hex
        keys = [prefix + suffix for suffix in (":latest", ":last_refresh", ":lock")]

        @asynccontextmanager
        async def isolated_connection():
            yield connection

        try:
            # Schema name is generated internally from hex digits, not user input.
            schema = "kev_test_" + uuid4().hex
            await connection.execute(f'CREATE SCHEMA "{schema}"')
            await connection.execute(f'SET LOCAL search_path TO "{schema}"')
            with ExitStack() as stack:
                stack.enter_context(patch.object(postgres, "db_connection", isolated_connection))
                stack.enter_context(patch.object(repository, "db_connection", isolated_connection))
                stack.enter_context(patch.object(cache, "create_redis_client", return_value=client))
                for name, value in zip(["KEV_CACHE_KEY", "KEV_LAST_REFRESH_KEY", "KEV_REFRESH_LOCK_KEY"], keys):
                    stack.enter_context(patch.object(cache, name, value))
                stack.enter_context(patch.object(service, "fetch_kev_catalog", AsyncMock(return_value=CATALOG)))
                await postgres.initialize_database()
                await postgres.initialize_database()  # Startup DDL is repeatable.

                # Ownership-aware release must not remove a successor's lease.
                owner = await cache.acquire_kev_refresh_lock()
                self.assertIsNotNone(owner)
                self.assertIsNone(await cache.acquire_kev_refresh_lock())
                await client.set(keys[2], "successor", ex=300)
                await cache.release_kev_refresh_lock(owner)
                self.assertEqual(await client.get(keys[2]), "successor")
                await cache.release_kev_refresh_lock("successor")
                self.assertIsNone(await client.get(keys[2]))

                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as http:
                    response = await http.post("/api/kev/refresh")
                    self.assertEqual(response.status_code, 200, response.text)
                    self.assertEqual(response.json()["stored_count"], 1)
                    self.assertGreater(await client.ttl(keys[0]), 0)
                    self.assertEqual((await http.get("/api/kev/status")).json()["cached_entries"], 1)
                    self.assertEqual((await http.get("/api/kev")).json()[0]["cve_id"], ENTRY.cve_id)
                    self.assertEqual(len((await http.get("/api/kev/search?q=example")).json()), 1)
                    self.assertEqual((await http.get("/api/kev/" + ENTRY.cve_id.lower())).status_code, 200)
                    self.assertEqual((await http.post("/api/kev/refresh")).status_code, 429)
                    self.assertIsNone(await client.get(keys[2]))
                    # Cache loss must still serve durable rows without a download.
                    await client.delete(keys[0])
                    self.assertEqual(len((await http.get("/api/kev")).json()), 1)

                first_seen = await connection.fetchval("SELECT first_seen_at FROM kev_entries")
                changed = ENTRY.model_copy(update={"product": "100%_Widget", "cwes": ["CWE-89"]})
                await repository.upsert_kev_entries([changed])
                self.assertEqual(await repository.get_kev_entry_by_cve(ENTRY.cve_id), changed)
                self.assertEqual(await connection.fetchval("SELECT first_seen_at FROM kev_entries"), first_seen)
                self.assertEqual(len(await repository.search_kev_entries("%_")), 1)
                self.assertEqual(await repository.search_kev_entries("not-present%"), [])

                # One invalid record must roll back the earlier valid insert too.
                good = ENTRY.model_copy(update={"cve_id": "CVE-2025-22222"})
                bad = ENTRY.model_copy(update={"cve_id": "CVE-2025-33333", "product": None})
                with self.assertRaises(asyncpg.NotNullViolationError):
                    await repository.upsert_kev_entries([good, bad])
                self.assertEqual(await connection.fetchval("SELECT count(*) FROM kev_entries"), 1)
        finally:
            try:
                await client.delete(*keys)
                await client.aclose()
            finally:
                await transaction.rollback()
                await connection.close()
