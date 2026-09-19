"""Opt-in NVD repository/history tests using a real PostgreSQL database.

PURPOSE
-------
Stage 1 unit tests validate NVD parsing without external dependencies. These
integration tests validate the completed NVD schema/repository against a real
PostgreSQL instance while keeping normal Situation Monitor tables untouched.

ISOLATION
---------
The test starts a transaction, creates a random temporary schema, redirects the
production repository modules to that connection, and rolls everything back in
``finally``.

RUNNING THE TEST
----------------
PowerShell from backend/:\n
    $env:NVD_INTEGRATION_TESTS="1"\n
    python -m unittest discover -s tests -p "test_nvd_storage_integration.py" -v\n
    Remove-Item Env:NVD_INTEGRATION_TESTS\n
WHAT IT VERIFIES
----------------
- initialize_database() creates NVD current/history tables.
- KEV-scoped NVD data stores and round-trips correctly.
- Meaningful selected-CVSS changes append history.
- Re-fetching the same CVSS does not append duplicate history.
- Older NVD revisions cannot overwrite newer current data.
- Missing/stale candidate selection works.
- The KEV foreign key rejects arbitrary non-KEV NVD rows.
"""

import os
import unittest
from contextlib import asynccontextmanager, ExitStack
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from uuid import uuid4

import asyncpg

from app.config import DATABASE_URL
from app.models.nvd import NVDCVE, NVDCVSSMetric
from app.storage import kev_repository, nvd_repository, postgres
from test_kev import ENTRY


@unittest.skipUnless(
    os.getenv("NVD_INTEGRATION_TESTS") == "1",
    "Opt-in NVD PostgreSQL integration test",
)
class NVDStorageIntegration(unittest.IsolatedAsyncioTestCase):
    async def test_real_nvd_storage_history_candidates_and_scope(self):
        connection = await asyncpg.connect(
            DATABASE_URL,
            timeout=5,
            command_timeout=30,
        )
        transaction = connection.transaction()
        await transaction.start()

        @asynccontextmanager
        async def isolated_connection():
            yield connection

        try:
            schema = "nvd_" + uuid4().hex
            await connection.execute(f'CREATE SCHEMA "{schema}"')
            await connection.execute(f'SET LOCAL search_path TO "{schema}"')

            with ExitStack() as stack:
                for module in (postgres, kev_repository, nvd_repository):
                    stack.enter_context(
                        patch.object(module, "db_connection", isolated_connection)
                    )

                await postgres.initialize_database()
                await kev_repository.upsert_kev_entries([ENTRY])

                now = datetime.now(timezone.utc)
                metric = NVDCVSSMetric(
                    cvss_version="3.1",
                    base_score=9.8,
                    base_severity="CRITICAL",
                    vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    source="nvd@nist.gov",
                    metric_type="Primary",
                    exploitability_score=3.9,
                    impact_score=5.9,
                )
                record = NVDCVE(
                    cve_id=ENTRY.cve_id,
                    source_identifier="example@nvd.test",
                    published_at=now - timedelta(days=30),
                    last_modified_at=now,
                    vuln_status="Analyzed",
                    description="Integration-test NVD record.",
                    cvss=metric,
                    cwes=["CWE-787"],
                    affected_cpes=["cpe:2.3:a:example:product:*:*:*:*:*:*:*:*"],
                    reference_urls=["https://example.test/advisory"],
                    fetched_at=now,
                )

                stored = await nvd_repository.upsert_nvd_cve(record)
                self.assertEqual(stored, record)
                self.assertEqual(
                    await nvd_repository.get_nvd_cve_by_cve(ENTRY.cve_id.lower()),
                    record,
                )
                self.assertEqual(await nvd_repository.count_nvd_cves(), 1)
                self.assertEqual(
                    await nvd_repository.count_nvd_refresh_candidates(
                        now - timedelta(days=7)
                    ),
                    0,
                )
                self.assertEqual(
                    await nvd_repository.get_nvd_cvss_history(ENTRY.cve_id),
                    [],
                )

                # A newer NVD revision with a different selected CVSS value
                # updates current state and appends exactly one history row.
                changed = record.model_copy(
                    update={
                        "last_modified_at": now + timedelta(hours=1),
                        "fetched_at": now + timedelta(hours=1),
                        "cvss": metric.model_copy(
                            update={
                                "base_score": 7.5,
                                "base_severity": "HIGH",
                            }
                        ),
                    }
                )
                retained = await nvd_repository.upsert_nvd_cve(changed)
                self.assertEqual(retained, changed)

                history = await nvd_repository.get_nvd_cvss_history(ENTRY.cve_id)
                self.assertEqual(len(history), 1)
                self.assertEqual(history[0].previous_cvss.base_score, 9.8)
                self.assertEqual(history[0].current_cvss.base_score, 7.5)

                # Re-fetching the exact same selected CVSS only refreshes the
                # current row timestamp; it must not add duplicate history.
                same_metric_refresh = changed.model_copy(
                    update={"fetched_at": now + timedelta(hours=2)}
                )
                await nvd_repository.upsert_nvd_cve(same_metric_refresh)
                self.assertEqual(
                    len(await nvd_repository.get_nvd_cvss_history(ENTRY.cve_id)),
                    1,
                )

                # An older NVD provider revision must not overwrite newer state.
                older = changed.model_copy(
                    update={
                        "last_modified_at": now - timedelta(days=1),
                        "description": "Older provider state",
                        "cvss": metric.model_copy(update={"base_score": 4.0}),
                    }
                )
                retained = await nvd_repository.upsert_nvd_cve(older)
                self.assertEqual(retained.cvss.base_score, 7.5)
                self.assertEqual(
                    len(await nvd_repository.get_nvd_cvss_history(ENTRY.cve_id)),
                    1,
                )

                # A cutoff later than the stored fetched_at makes the row stale
                # and therefore a refresh candidate.
                candidates = await nvd_repository.get_kev_cve_ids_needing_nvd(
                    stale_before=now + timedelta(days=1),
                    limit=10,
                )
                self.assertEqual(candidates, [ENTRY.cve_id])

                # The project's V1 scope is KEV-centered. PostgreSQL rejects
                # NVD enrichment for a CVE absent from kev_entries.
                unknown = record.model_copy(update={"cve_id": "CVE-2099-99999"})
                with self.assertRaises(asyncpg.ForeignKeyViolationError):
                    await nvd_repository.upsert_nvd_cve(unknown)

        finally:
            await transaction.rollback()
            await connection.close()
