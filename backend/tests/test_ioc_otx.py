"""Stage 1.3 tests for OTX-CVE collection, evidence scope, and reliability.

ARCHITECTURE AND PURPOSE
------------------------
The tests run via `python -m unittest tests.test_ioc_otx -v`. They mock only
OTX network interactions, run all existing normalization/retry tests, and
verify that default collection avoids broad pulse indicator dumps while
preserving pulse assessments for later analyst review. They don't need an OTX
key, PostgreSQL, Redis, or Google SecOps and never send network requests.


FILE GUIDE
----------
WHAT THIS FILE DOES
Check basic OTX parsing, normalization, report relevance, retries, and partial results.

WHY IT EXISTS
Provider data can be ambiguous; these tests protect the collector's evidence semantics.

WHO CALLS OR IMPORTS IT
unittest discovers this file during the offline IOC test command.

WHAT IT CALLS OR IMPORTS
Calls app.collectors.otx with mocked HTTP responses; never contacts live OTX.

ROLE IN THE ARCHITECTURE
Collector regression tests; no PostgreSQL or Redis required.
"""

import unittest

import httpx
from unittest.mock import AsyncMock, patch

from app.collectors import otx
from app.models.ioc import IOCRelationshipType, IOCType, SourceRecordRelevance


PULSE_A = {
    "id": "aaaaaaaaaaaaaaaaaaaaaaaa",
    "name": "Example CVE-2021-44228 campaign",
    "created": "2026-09-01T10:00:00.000000",
    "modified": "2026-09-02T10:00:00.000000",
    "tags": ["CVE-2021-44228", "example"],
    "references": ["https://research.example/report"],
    "TLP": "white",
    "author": {"username": "research-team"},
}

PULSE_B = {
    "id": "bbbbbbbbbbbbbbbbbbbbbbbb",
    "name": "Second source record",
    "created": "2026-09-03T10:00:00Z",
    "modified": "2026-09-03T11:00:00Z",
    "tags": [],
    "references": [],
    "TLP": "green",
    "author": {"username": "another-team"},
}



PULSE_MULTI_CVE = {
    "id": "cccccccccccccccccccccccc",
    "name": "Multi-CVE threat report",
    "description": "Campaign context also mentions CVE_2026_1340.",
    "created": "2026-09-04T10:00:00Z",
    "modified": "2026-09-04T11:00:00Z",
    "tags": [
        "cve20260300 cve",
        "CVE-2026-1281",
        "yara",
    ],
    "references": [
        "https://research.example/CVE-2026-1731/report",
    ],
    "TLP": "white",
    "author": {"username": "context-researcher"},
}


def general_payload(*pulses, count=None):
    """Build a small CVE lookup response so each test can vary one provider field."""
    return {
        "indicator": "CVE-2021-44228",
        "type_title": "CVE",
        "pulse_info": {
            "count": len(pulses) if count is None else count,
            "pulses": list(pulses),
            "references": [],
        },
    }


# PURE VALIDATION TESTS
# These call the collector's normalization helpers directly. They check values
# before any network request, including old CVEs, supported IOC types, invalid
# indicators, mismatched CVE responses, and CVEs found in report metadata.
class NormalizationTests(unittest.TestCase):
    """Group cases that check the collector preserves source meaning and reports incomplete work."""
    def test_cve_normalization_accepts_old_cve(self):
        # Age is deliberately irrelevant: historical CVEs can be reactivated by
        # new threat intelligence years after original disclosure.
        """Verify cve normalization accepts old cve. This checks that the collector preserves source meaning and reports incomplete work."""
        self.assertEqual(
            otx.normalize_cve_id(" cve-2017-0144 "),
            "CVE-2017-0144",
        )

    def test_invalid_cve_is_rejected_before_network_use(self):
        """Verify invalid cve is rejected before network use. This checks that the collector preserves source meaning and reports incomplete work."""
        with self.assertRaises(ValueError):
            otx.normalize_cve_id("2021-44228")

    def test_supported_ioc_types_are_normalized(self):
        """Verify supported ioc types are normalized. This checks that the collector preserves source meaning and reports incomplete work."""
        cases = [
            ("IPv4", "192.0.2.10", IOCType.IPV4, "192.0.2.10"),
            ("IPv6", "2001:0db8::1", IOCType.IPV6, "2001:db8::1"),
            ("domain", "Example.COM.", IOCType.DOMAIN, "example.com"),
            ("hostname", "C2.Example.COM", IOCType.HOSTNAME, "c2.example.com"),
            ("URL", "https://example.com/CaseSensitive", IOCType.URL, "https://example.com/CaseSensitive"),
            ("FileHash-MD5", "A" * 32, IOCType.MD5, "a" * 32),
            ("FileHash-SHA1", "B" * 40, IOCType.SHA1, "b" * 40),
            ("FileHash-SHA256", "C" * 64, IOCType.SHA256, "c" * 64),
        ]

        for raw_type, raw_value, expected_type, expected_value in cases:
            with self.subTest(raw_type=raw_type):
                indicator = otx.normalize_otx_indicator(raw_type, raw_value)
                self.assertIsNotNone(indicator)
                self.assertEqual(indicator.indicator_type, expected_type)
                self.assertEqual(indicator.value, expected_value)

    def test_unsupported_or_invalid_ioc_is_ignored(self):
        """Verify unsupported or invalid ioc is ignored. This checks that the collector preserves source meaning and reports incomplete work."""
        self.assertIsNone(otx.normalize_otx_indicator("email", "a@example.com"))
        self.assertIsNone(otx.normalize_otx_indicator("IPv4", "999.1.1.1"))
        self.assertIsNone(otx.normalize_otx_indicator("domain", "https://example.com"))
        self.assertIsNone(otx.normalize_otx_indicator("FileHash-SHA256", "not-a-hash"))

    def test_mismatched_cve_response_is_rejected(self):
        """Verify mismatched cve response is rejected. This checks that the collector preserves source meaning and reports incomplete work."""
        payload = general_payload(PULSE_A)
        payload["indicator"] = "CVE-2024-0001"
        with self.assertRaises(otx.OTXResponseError):
            otx._parse_pulses(payload, "CVE-2021-44228")


    def test_otx_compact_and_standard_cve_tags_are_extracted_as_pulse_context(self):
        """Verify otx compact and standard cve tags are extracted as pulse context. This checks that the collector preserves source meaning and reports incomplete work."""
        cves = otx._extract_pulse_cve_ids(
            PULSE_MULTI_CVE,
            "CVE-2026-0300",
        )

        self.assertEqual(
            cves,
            [
                "CVE-2026-0300",
                "CVE-2026-1281",
                "CVE-2026-1340",
                "CVE-2026-1731",
            ],
        )

    def test_requested_cve_is_kept_even_when_pulse_tags_do_not_repeat_it(self):
        """Verify requested cve is kept even when pulse tags do not repeat it. This checks that the collector preserves source meaning and reports incomplete work."""
        cves = otx._extract_pulse_cve_ids(PULSE_B, "CVE-2021-44228")
        self.assertEqual(cves, ["CVE-2021-44228"])



# COLLECTION/PROVENANCE TESTS
# Each test gets its own event loop. AsyncMock replaces provider operations so
# the real orchestration and data models can run without external traffic.
# Assert both counts and evidence: one IOC in two reports must remain two
# observations, while duplicates inside one report must not inflate its count.
class FetchBehaviorTests(unittest.IsolatedAsyncioTestCase):
    """Group cases that check the collector preserves source meaning and reports incomplete work."""
    async def test_otx_pulse_ioc_is_contextual_even_when_requested_by_cve(self):
        """Verify otx pulse ioc is contextual even when requested by cve. This checks that the collector preserves source meaning and reports incomplete work."""
        raw_indicator = {
            "type": "IPv4",
            "indicator": "192.0.2.99",
            "is_active": 1,
        }

        payload = general_payload(PULSE_MULTI_CVE)

        with patch.object(
            otx,
            "_request_json",
            AsyncMock(return_value=payload),
        ), patch.object(
            otx,
            "_fetch_pulse_indicators",
            AsyncMock(return_value=[raw_indicator]),
        ):
            result = await otx.fetch_otx_cve_iocs(
                "CVE-2021-44228",
                api_key="test-key",
                include_context=True,
            )

        observation = result.observations[0]
        self.assertEqual(
            observation.relationship_type,
            IOCRelationshipType.PULSE_CONTEXT,
        )
        self.assertIn("CVE-2021-44228", observation.source_record_cve_ids)
        self.assertIn("CVE-2026-0300", observation.source_record_cve_ids)
        self.assertIn("CVE-2026-1281", observation.source_record_cve_ids)

    async def test_same_ioc_in_two_pulses_preserves_two_observations(self):
        """Verify same ioc in two pulses preserves two observations. This checks that the collector preserves source meaning and reports incomplete work."""
        raw_indicator = {
            "type": "IPv4",
            "indicator": "192.0.2.55",
            "is_active": 1,
        }

        with patch.object(
            otx,
            "_request_json",
            AsyncMock(return_value=general_payload(PULSE_A, PULSE_B)),
        ), patch.object(
            otx,
            "_fetch_pulse_indicators",
            AsyncMock(side_effect=[[raw_indicator], [raw_indicator]]),
        ):
            result = await otx.fetch_otx_cve_iocs(
                "CVE-2021-44228",
                api_key="test-key",
                include_context=True,
            )

        self.assertTrue(result.complete)
        self.assertEqual(result.source_record_count_processed, 2)
        self.assertEqual(result.observation_count, 2)
        self.assertEqual(result.unique_indicator_count, 1)
        self.assertEqual(
            {item.source_record_id for item in result.observations},
            {PULSE_A["id"], PULSE_B["id"]},
        )

    async def test_duplicate_ioc_within_same_pulse_is_deduplicated(self):
        """Verify duplicate ioc within same pulse is deduplicated. This checks that the collector preserves source meaning and reports incomplete work."""
        duplicate = {
            "type": "domain",
            "indicator": "Example.COM",
            "is_active": 1,
        }

        with patch.object(
            otx,
            "_request_json",
            AsyncMock(return_value=general_payload(PULSE_A)),
        ), patch.object(
            otx,
            "_fetch_pulse_indicators",
            AsyncMock(return_value=[duplicate, duplicate]),
        ):
            result = await otx.fetch_otx_cve_iocs(
                "CVE-2021-44228",
                api_key="test-key",
            )

        self.assertEqual(result.observation_count, 1)
        self.assertEqual(result.unique_indicator_count, 1)

    async def test_no_pulses_is_successful_empty_intelligence(self):
        """Verify no pulses is successful empty intelligence. This checks that the collector preserves source meaning and reports incomplete work."""
        with patch.object(
            otx,
            "_request_json",
            AsyncMock(return_value=general_payload()),
        ):
            result = await otx.fetch_otx_cve_iocs(
                "CVE-2021-44228",
                api_key="test-key",
            )

        self.assertTrue(result.complete)
        self.assertEqual(result.observation_count, 0)
        self.assertEqual(result.unique_indicator_count, 0)

    async def test_reported_pulse_count_mismatch_is_marked_partial(self):
        """Verify reported pulse count mismatch is marked partial. This checks that the collector preserves source meaning and reports incomplete work."""
        with patch.object(
            otx,
            "_request_json",
            AsyncMock(return_value=general_payload(PULSE_A, count=3)),
        ), patch.object(
            otx,
            "_fetch_pulse_indicators",
            AsyncMock(return_value=[]),
        ):
            result = await otx.fetch_otx_cve_iocs(
                "CVE-2021-44228",
                api_key="test-key",
            )

        self.assertFalse(result.complete)
        self.assertEqual(result.source_record_count_reported, 3)
        self.assertEqual(result.source_record_count_processed, 1)
        self.assertTrue(result.warnings)

    async def test_missing_api_key_fails_before_provider_call(self):
        """Verify missing api key fails before provider call. This checks that the collector preserves source meaning and reports incomplete work."""
        with patch.object(otx, "_request_json", AsyncMock()) as request:
            with self.assertRaises(otx.OTXConfigurationError):
                await otx.fetch_otx_cve_iocs(
                    "CVE-2021-44228",
                    api_key="",
                )
        request.assert_not_awaited()


# RETRIES AND PARTIAL RESULTS
# _get_response is the bounded streaming boundary. Mocking it lets these tests
# simulate a gateway failure or timeout followed by a successful response.
# The separate safety test file exercises actual HTTPX MockTransport behavior.
# A failed pulse must not hide usable observations from another completed pulse.
class RetryAndPartialResultTests(unittest.IsolatedAsyncioTestCase):
    """Group cases that check the collector preserves source meaning and reports incomplete work."""
    async def test_request_json_retries_502_then_succeeds(self):
        """Verify request json retries 502 then succeeds. This checks that the collector preserves source meaning and reports incomplete work."""
        request = httpx.Request("GET", "https://otx.example/api")
        response_502 = httpx.Response(502, request=request)
        response_200 = httpx.Response(200, request=request, json={"ok": True})

        client = AsyncMock()
        get_response = AsyncMock(side_effect=[response_502, response_200])

        with (patch.object(otx, "_get_response", get_response), patch.object(otx.asyncio, "sleep", AsyncMock()) as sleep):
            result = await otx._request_json(
                client,
                "https://otx.example/api",
                context="unit-test request",
            )

        self.assertEqual(result, {"ok": True})
        self.assertEqual(get_response.await_count, 2)
        sleep.assert_awaited_once()

    async def test_request_json_retries_read_timeout_then_succeeds(self):
        """Verify request json retries read timeout then succeeds. This checks that the collector preserves source meaning and reports incomplete work."""
        request = httpx.Request("GET", "https://otx.example/api")
        response_200 = httpx.Response(200, request=request, json={"ok": True})

        client = AsyncMock()
        get_response = AsyncMock(
            side_effect=[httpx.ReadTimeout("slow provider", request=request), response_200]
        )

        with (patch.object(otx, "_get_response", get_response), patch.object(otx.asyncio, "sleep", AsyncMock()) as sleep):
            result = await otx._request_json(
                client,
                "https://otx.example/api",
                context="unit-test request",
            )

        self.assertEqual(result, {"ok": True})
        self.assertEqual(get_response.await_count, 2)
        sleep.assert_awaited_once()

    async def test_one_failed_pulse_returns_partial_data_from_other_pulses(self):
        """Verify one failed pulse returns partial data from other pulses. This checks that the collector preserves source meaning and reports incomplete work."""
        raw_indicator = {
            "type": "IPv4",
            "indicator": "192.0.2.77",
            "is_active": 1,
        }

        with patch.object(
            otx,
            "_request_json",
            AsyncMock(return_value=general_payload(PULSE_A, PULSE_B)),
        ), patch.object(
            otx,
            "_fetch_pulse_indicators",
            AsyncMock(
                side_effect=[
                    otx.OTXProviderUnavailableError("pulse A remained unavailable"),
                    [raw_indicator],
                ]
            ),
        ):
            result = await otx.fetch_otx_cve_iocs(
                "CVE-2021-44228",
                api_key="test-key",
                include_context=True,
            )

        self.assertFalse(result.complete)
        self.assertEqual(result.source_record_count_processed, 1)
        self.assertEqual(result.observation_count, 1)
        self.assertEqual(result.unique_indicator_count, 1)
        self.assertTrue(any("pulse A remained unavailable" in item for item in result.warnings))


# SCOPE AND EVIDENCE RULES
# The default mode fetches focused reports only. Explicit exploratory mode may
# fetch broad reports too, but must not upgrade pulse_context into proven CVE
# exploitation evidence. Deliberately skipped and failed requests are distinct.
class ScopeAndEvidenceClassificationTests(unittest.IsolatedAsyncioTestCase):
    """Prove broad OTX reports do not pollute a CVE's default IOC scope."""

    async def test_default_downloads_focused_and_skips_bulk_and_ambiguous(self):
        # OTX's CVE lookup returns every pulse, but downloading the giant bulk
        # indicator list is unnecessary and misleading in the normal CVE view.
        """Verify default downloads focused and skips bulk and ambiguous. This checks that the collector preserves source meaning and reports incomplete work."""
        focused = dict(PULSE_A)
        bulk = dict(PULSE_MULTI_CVE)
        ambiguous = dict(PULSE_B)
        item = {"type": "IPv4", "indicator": "192.0.2.44", "is_active": 1}

        with patch.object(
            otx,
            "_request_json",
            AsyncMock(return_value=general_payload(focused, bulk, ambiguous)),
        ), patch.object(
            otx,
            "_fetch_pulse_indicators",
            AsyncMock(return_value=[item]),
        ) as fetch:
            result = await otx.fetch_otx_cve_iocs("CVE-2021-44228", api_key="test-key")

        self.assertEqual(fetch.await_count, 1)
        self.assertEqual(fetch.await_args.args[1], focused["id"])
        self.assertTrue(result.complete)
        self.assertEqual(result.collection_scope, "focused_only")
        self.assertEqual(result.source_record_count_reported, 3)
        self.assertEqual(result.source_record_count_processed, 1)
        self.assertEqual(result.source_record_count_skipped, 2)
        self.assertEqual(result.unique_indicator_count, 1)
        self.assertEqual(
            [a.relevance for a in result.source_record_assessments],
            [
                SourceRecordRelevance.FOCUSED_CONTEXT,
                SourceRecordRelevance.BROAD_CONTEXT,
                SourceRecordRelevance.REVIEW_REQUIRED,
            ],
        )
        self.assertEqual(result.observations[0].relationship_type, IOCRelationshipType.PULSE_CONTEXT)
        self.assertEqual(
            result.observations[0].source_record_relevance,
            SourceRecordRelevance.FOCUSED_CONTEXT,
        )

    async def test_include_context_fetches_broad_without_promoting_relationship(self):
        """Verify include context fetches broad without promoting relationship. This checks that the collector preserves source meaning and reports incomplete work."""
        indicator = {"type": "domain", "indicator": "research.example", "is_active": True}
        with patch.object(
            otx,
            "_request_json",
            AsyncMock(return_value=general_payload(PULSE_A, PULSE_MULTI_CVE)),
        ), patch.object(
            otx,
            "_fetch_pulse_indicators",
            AsyncMock(side_effect=[[indicator], [indicator]]),
        ) as fetch:
            result = await otx.fetch_otx_cve_iocs(
                "CVE-2021-44228", api_key="test-key", include_context=True
            )

        self.assertEqual(fetch.await_count, 2)
        self.assertTrue(result.complete)
        self.assertEqual(result.collection_scope, "all_pulses")
        self.assertEqual(result.source_record_count_skipped, 0)
        self.assertEqual(result.observation_count, 2)
        self.assertEqual(result.unique_indicator_count, 1)
        self.assertEqual(
            {item.relationship_type for item in result.observations},
            {IOCRelationshipType.PULSE_CONTEXT},
        )
        self.assertEqual(
            result.source_record_assessments[1].relevance,
            SourceRecordRelevance.BROAD_CONTEXT,
        )
        self.assertTrue(result.source_record_assessments[1].fetched)

    async def test_title_about_other_cve_is_not_fetched_by_default(self):
        """Verify title about other cve is not fetched by default. This checks that the collector preserves source meaning and reports incomplete work."""
        off_target = dict(PULSE_B)
        off_target["name"] = "Exploitation of CVE-2026-35616 at a different vendor"
        off_target["tags"] = ["CVE-2021-44228"]

        with patch.object(
            otx, "_request_json", AsyncMock(return_value=general_payload(off_target))
        ), patch.object(otx, "_fetch_pulse_indicators", AsyncMock()) as fetch:
            result = await otx.fetch_otx_cve_iocs("CVE-2021-44228", api_key="test-key")

        fetch.assert_not_awaited()
        self.assertTrue(result.complete)
        self.assertEqual(result.unique_indicator_count, 0)
        self.assertEqual(result.source_record_count_skipped, 1)
        self.assertEqual(result.source_record_assessments[0].reason_code, "title_mentions_other_cve")
        self.assertIsNone(result.source_record_assessments[0].indicator_count)

    async def test_tag_only_match_is_review_required_not_auto_fetched(self):
        """Verify tag only match is review required not auto fetched. This checks that the collector preserves source meaning and reports incomplete work."""
        only_tag = dict(PULSE_B)
        only_tag["tags"] = ["cve202144228 cve"]
        with patch.object(
            otx, "_request_json", AsyncMock(return_value=general_payload(only_tag))
        ), patch.object(otx, "_fetch_pulse_indicators", AsyncMock()) as fetch:
            result = await otx.fetch_otx_cve_iocs("CVE-2021-44228", api_key="test-key")

        fetch.assert_not_awaited()
        self.assertEqual(result.source_record_assessments[0].relevance,
                         SourceRecordRelevance.REVIEW_REQUIRED)
        self.assertEqual(result.source_record_count_skipped, 1)

    async def test_selected_pulse_failure_is_partial_not_intentional_skip(self):
        """Verify selected pulse failure is partial not intentional skip. This checks that the collector preserves source meaning and reports incomplete work."""
        with patch.object(
            otx, "_request_json", AsyncMock(return_value=general_payload(PULSE_A))
        ), patch.object(
            otx, "_fetch_pulse_indicators", AsyncMock(side_effect=otx.OTXProviderUnavailableError("bad gateway"))
        ):
            result = await otx.fetch_otx_cve_iocs("CVE-2021-44228", api_key="test-key")

        self.assertFalse(result.complete)
        self.assertEqual(result.source_record_count_skipped, 0)
        self.assertEqual(result.source_record_count_processed, 0)
        self.assertTrue(result.source_record_assessments[0].selected_for_collection)
        self.assertFalse(result.source_record_assessments[0].fetched)
        self.assertIsNone(result.source_record_assessments[0].indicator_count)
        self.assertTrue(any("bad gateway" in warning for warning in result.warnings))

    async def test_single_cve_title_is_still_only_pulse_context(self):
        """Verify single cve title is still only pulse context. This checks that the collector preserves source meaning and reports incomplete work."""
        entry = {"type": "FileHash-SHA256", "indicator": "a" * 64, "is_active": True}
        with patch.object(
            otx, "_request_json", AsyncMock(return_value=general_payload(PULSE_A))
        ), patch.object(otx, "_fetch_pulse_indicators", AsyncMock(return_value=[entry])):
            result = await otx.fetch_otx_cve_iocs("CVE-2021-44228", api_key="test-key")

        self.assertEqual(result.unique_indicator_count, 1)
        self.assertEqual(result.observations[0].relationship_type, IOCRelationshipType.PULSE_CONTEXT)
        self.assertEqual(result.observations[0].source_record_relevance,
                         SourceRecordRelevance.FOCUSED_CONTEXT)
        self.assertEqual(result.source_record_assessments[0].indicator_count, 1)


if __name__ == "__main__":
    unittest.main()
