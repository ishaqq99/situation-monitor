"""Regression tests for mixed NVD and PostgreSQL timestamp representations.

Why this file exists
--------------------
The NVD CVE API can omit a timezone suffix from ``published`` and
``lastModified``. PostgreSQL TIMESTAMPTZ rows are returned as aware datetimes.
The original repository compared them directly and both manual and automatic
refreshes crashed. These tests exercise the model contract and repository
comparison without contacting NVD, PostgreSQL, Redis, or the browser.

Who runs it
-----------
``python -m unittest discover -s tests -p "test_nvd*.py" -v`` discovers it.
"""

import unittest
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

from app.models.nvd import NVDCVE, normalize_nvd_timestamp
from app.storage import nvd_repository


CVE_ID = "CVE-2021-44228"


def make_record(last_modified: str = "2026-09-28T12:00:00.000") -> NVDCVE:
    """Build an NVD model from the offset-less date strings in provider JSON."""

    return NVDCVE(
        cve_id=CVE_ID,
        published_at="2021-12-10T10:15:09.143",
        last_modified_at=last_modified,
        description="Test NVD record",
    )


def make_row(last_modified: datetime) -> dict:
    """Build the fields the repository selects from one PostgreSQL NVD row."""

    return {
        "cve_id": CVE_ID,
        "source_identifier": None,
        "published_at": datetime(2021, 12, 10, tzinfo=timezone.utc),
        "last_modified_at": last_modified,
        "vuln_status": None,
        "description": "Stored NVD record",
        "cvss_version": None,
        "cvss_base_score": None,
        "cvss_base_severity": None,
        "cvss_vector_string": None,
        "cvss_source": None,
        "cvss_metric_type": None,
        "cvss_exploitability_score": None,
        "cvss_impact_score": None,
        "cwes": "[]",
        "affected_cpes": "[]",
        "reference_urls": "[]",
        "fetched_at": datetime(2026, 9, 28, tzinfo=timezone.utc),
    }


class TimestampModelTests(unittest.TestCase):
    """Check the shared model before data reaches the repository."""

    def test_offsetless_provider_dates_become_aware_utc(self):
        """NVD's common offset-less strings must be safe for TIMESTAMPTZ use."""

        record = make_record()
        self.assertEqual(record.published_at.utcoffset(), timedelta(0))
        self.assertEqual(record.last_modified_at.utcoffset(), timedelta(0))
        self.assertEqual(record.fetched_at.utcoffset(), timedelta(0))

    def test_explicit_offset_is_converted_not_relabelled(self):
        """A genuine +02:00 instant should move two hours when shown as UTC."""

        record = make_record("2026-09-28T14:00:00+02:00")
        self.assertEqual(record.last_modified_at, datetime(2026, 9, 28, 12, tzinfo=timezone.utc))

    def test_helper_handles_legacy_naive_datetime(self):
        """An old row or test fixture with no offset can still be compared."""

        naive = datetime(2026, 9, 28, 13)
        self.assertEqual(normalize_nvd_timestamp(naive).utcoffset(), timedelta(0))


class RepositoryComparisonTests(unittest.IsolatedAsyncioTestCase):
    """Check that newer stored NVD revisions are retained without the TypeError."""

    async def test_aware_stored_revision_beats_older_offsetless_provider_record(self):
        """The exact logged aware/naive comparison must no longer crash."""

        row = make_row(datetime(2026, 9, 28, 13, tzinfo=timezone.utc))
        connection = type("FakeConnection", (), {})()
        connection.fetchrow = AsyncMock(return_value=row)
        connection.execute = AsyncMock()

        @asynccontextmanager
        async def transaction():
            yield

        @asynccontextmanager
        async def database():
            yield connection

        connection.transaction = transaction
        with patch.object(nvd_repository, "db_connection", database):
            saved = await nvd_repository.upsert_nvd_cve(make_record())

        self.assertEqual(saved.last_modified_at, row["last_modified_at"])
        connection.fetchrow.assert_awaited_once()
        connection.execute.assert_not_awaited()

    async def test_legacy_naive_stored_revision_can_be_compared(self):
        """The repository defensively normalizes an older naive database row."""

        row = make_row(datetime(2026, 9, 28, 13))
        connection = type("FakeConnection", (), {})()
        connection.fetchrow = AsyncMock(return_value=row)

        @asynccontextmanager
        async def transaction():
            yield

        @asynccontextmanager
        async def database():
            yield connection

        connection.transaction = transaction
        with patch.object(nvd_repository, "db_connection", database):
            saved = await nvd_repository.upsert_nvd_cve(make_record())

        self.assertEqual(saved.last_modified_at, datetime(2026, 9, 28, 13, tzinfo=timezone.utc))
        connection.fetchrow.assert_awaited_once()

    async def test_newer_provider_revision_reaches_upsert_with_aware_dates(self):
        """The fix must preserve normal writes, not only the stale-row shortcut."""

        old = make_row(datetime(2026, 9, 28, 11, tzinfo=timezone.utc))
        new = make_row(datetime(2026, 9, 28, 12, tzinfo=timezone.utc))
        connection = type("FakeConnection", (), {})()
        connection.fetchrow = AsyncMock(side_effect=[old, new])
        connection.execute = AsyncMock()

        @asynccontextmanager
        async def transaction():
            yield

        @asynccontextmanager
        async def database():
            yield connection

        connection.transaction = transaction
        with patch.object(nvd_repository, "db_connection", database):
            saved = await nvd_repository.upsert_nvd_cve(make_record())

        self.assertEqual(saved.last_modified_at, new["last_modified_at"])
        self.assertEqual(connection.fetchrow.await_count, 2)
        upsert_args = connection.fetchrow.await_args_list[1].args
        self.assertEqual(upsert_args[3].utcoffset(), timedelta(0))  # published_at
        self.assertEqual(upsert_args[4].utcoffset(), timedelta(0))  # last_modified_at


if __name__ == "__main__":
    unittest.main()
