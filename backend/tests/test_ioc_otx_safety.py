"""Stage 1.3 regression tests using local responses, never the live OTX API.

Run from backend using the command in INSTALL.md. HTTPX MockTransport exercises
the actual HTTP adapter without sockets. All keys, hosts, and indicators here
are test data. No PostgreSQL, Redis, frontend, or OTX account is needed.


FILE GUIDE
----------
WHAT THIS FILE DOES
Check destination validation, response limits, pagination, pacing, and error outcomes.

WHY IT EXISTS
A threat-intelligence provider can return malformed or dangerous links and large payloads.

WHO CALLS OR IMPORTS IT
unittest discovers this file during the offline IOC test command.

WHAT IT CALLS OR IMPORTS
Uses HTTPX MockTransport to exercise app.collectors.otx without network sockets.

ROLE IN THE ARCHITECTURE
Collector safety and reliability tests.
"""

import asyncio
import io
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from unittest.mock import AsyncMock, patch

import httpx

from app.collectors import otx
import check_ioc


CVE = "CVE-2021-44228"
GENERAL = f"https://otx.alienvault.com/api/v1/indicators/cve/{CVE}/general"
PULSE_ID = "a" * 24
PULSE_PATH = f"/api/v1/pulses/{PULSE_ID}/indicators"
PULSE_URL = "https://otx.alienvault.com" + PULSE_PATH
PULSE = {"id": PULSE_ID, "name": f"Research on {CVE}", "tags": [CVE]}
INDICATOR = {"type": "IPv4", "indicator": "192.0.2.10", "is_active": True}


def general(*pulses):
    """Build a valid provider response; omissions must be explicit in tests."""
    return {"indicator": CVE, "pulse_info": {"count": len(pulses), "pulses": list(pulses)}}


class TrackedStream(httpx.AsyncByteStream):
    """Small chunked stream that lets tests prove early failures close it."""

    def __init__(self, chunks):
        """Record the mock response-stream state used to check cleanup."""
        self.chunks = chunks
        self.closed = False
        self.read = False

    async def __aiter__(self):
        """Yield mock response chunks as an asynchronous stream."""
        self.read = True
        for chunk in self.chunks:
            yield chunk

    async def aclose(self):
        """Mark the mock response stream closed so the test can assert cleanup."""
        self.closed = True


# INPUT/RESPONSE VALIDATION
# Reject missing metadata, boolean counts, unsafe next links, and malformed
# indicator URLs. Also verify that Retry-After accepts numeric and date forms.
# These assertions target the false-empty and unsafe-destination regressions.
class ResponseValidationTests(unittest.TestCase):
    """Group cases that check untrusted provider responses stay within safety and resource limits."""
    def test_missing_or_invalid_pulse_metadata_is_not_empty_success(self):
        """Verify missing or invalid pulse metadata is not empty success. This checks that untrusted provider responses stay within safety and resource limits."""
        invalid = [
            {}, {"indicator": CVE}, {"indicator": CVE, "pulse_info": {}},
            {"indicator": CVE, "pulse_info": {"count": 0}},
            {"indicator": CVE, "pulse_info": {"pulses": []}},
            {"indicator": CVE, "pulse_info": {"count": True, "pulses": []}},
            {"indicator": CVE, "pulse_info": {"count": -1, "pulses": []}},
            {"pulse_info": {"count": 0, "pulses": []}},
        ]
        for payload in invalid:
            with self.subTest(payload=payload), self.assertRaises(otx.OTXResponseError):
                otx._parse_pulses(payload, CVE)
        self.assertEqual(otx._parse_pulses(general(), CVE), (0, []))

    def test_pulse_metadata_count_is_bounded(self):
        """Verify pulse metadata count is bounded. This checks that untrusted provider responses stay within safety and resource limits."""
        with patch.object(otx, "OTX_MAX_PULSE_METADATA", 1):
            with self.assertRaises(otx.OTXCollectionLimitError):
                otx._parse_pulses(general(PULSE, dict(PULSE, id="b" * 24)), CVE)

    def test_next_link_stays_on_same_origin_and_pulse(self):
        """Verify next link stays on same origin and pulse. This checks that untrusted provider responses stay within safety and resource limits."""
        bad_links = [
            "https://attacker.example" + PULSE_PATH,
            "//attacker.example" + PULSE_PATH,
            "http://otx.alienvault.com" + PULSE_PATH,
            "https://otx.alienvault.com:444" + PULSE_PATH,
            "https://user:password@otx.alienvault.com" + PULSE_PATH,
            "/api/v1/pulses/" + "b" * 24 + "/indicators",
            GENERAL, "/api/v1/../private", PULSE_URL + "#fragment",
            "\n" + PULSE_URL, {}, [], 7,
        ]
        for link in bad_links:
            with self.subTest(link=link), self.assertRaises(otx.OTXResponseError):
                otx._next_page_url(PULSE_URL, link, PULSE_ID)

    def test_relative_next_retains_endpoint_and_bounded_page_settings(self):
        """Verify relative next retains endpoint and bounded page settings. This checks that untrusted provider responses stay within safety and resource limits."""
        url = otx._next_page_url(PULSE_URL, "?page=2&limit=99999&include_inactive=1", PULSE_ID)
        parsed = httpx.URL(url)
        self.assertEqual(parsed.path, PULSE_PATH)
        self.assertEqual(parsed.params["page"], "2")
        self.assertEqual(parsed.params["limit"], "250")
        self.assertEqual(parsed.params["include_inactive"], "1")
        self.assertIsNone(otx._next_page_url(PULSE_URL, None, PULSE_ID))

    def test_retry_after_numeric_and_http_date(self):
        """Verify retry after numeric and http date. This checks that untrusted provider responses stay within safety and resource limits."""
        self.assertEqual(otx._retry_after_seconds("120"), 120)
        future = datetime.now(timezone.utc) + timedelta(seconds=125)
        seconds = otx._retry_after_seconds(format_datetime(future, usegmt=True))
        self.assertGreater(seconds, 120)
        self.assertLessEqual(seconds, 125)
        self.assertIsNone(otx._retry_after_seconds("invalid"))
        self.assertIsNone(otx._retry_after_seconds(None))

    def test_indicator_url_validation_never_visits_observable(self):
        """Verify indicator url validation never visits observable. This checks that untrusted provider responses stay within safety and resource limits."""
        for value in ["https://user:pass@example.com/x", "https://example.com:bad/x",
                      "https://example.com/x\ny"]:
            with self.subTest(value=value):
                self.assertIsNone(otx.normalize_otx_indicator("URL", value))


# HTTP BOUNDARY
# MockTransport handles requests entirely in memory, but the production HTTP
# adapter still runs. Recording requests proves that redirects/unsafe URLs do
# not cause a second request. TrackedStream proves failures close the response
# and unexpected compressed content is rejected before its body is consumed.
class HTTPBoundaryTests(unittest.IsolatedAsyncioTestCase):
    """Group cases that check untrusted provider responses stay within safety and resource limits."""
    def setUp(self):
        # Pacing is covered by the pipeline tests; in-memory transports need
        # no real waiting. Keep retry sleeps observable for their own tests.
        """Prepare mocks and settings shared by the tests in this class."""
        pacing = patch.object(otx, "OTX_REQUEST_DELAY_SECONDS", 0)
        pacing.start()
        self.addCleanup(pacing.stop)

    async def test_redirect_not_followed_even_if_client_allows_redirects(self):
        """Verify redirect not followed even if client allows redirects. This checks that untrusted provider responses stay within safety and resource limits."""
        requests = []

        def respond(request):
            """Return the chosen local HTTP response for this test's request."""
            requests.append(request)
            return httpx.Response(302, headers={"Location": "https://attacker.example/collect"})

        async with httpx.AsyncClient(transport=httpx.MockTransport(respond),
                                     follow_redirects=True, trust_env=False,
                                     headers={"X-OTX-API-KEY": "test-key"}) as client:
            with self.assertRaises(otx.OTXResponseError):
                await otx._request_json(client, GENERAL)
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0].url.host, "otx.alienvault.com")

    async def test_untrusted_url_rejected_before_transport(self):
        """Verify untrusted url rejected before transport. This checks that untrusted provider responses stay within safety and resource limits."""
        requests = []
        def respond(request):
            """Return the chosen local HTTP response for this test's request."""
            requests.append(request)
            return httpx.Response(200, json={})
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond), trust_env=False) as client:
            with self.assertRaises(otx.OTXResponseError):
                await otx._request_json(client, "https://attacker.example/api")
        self.assertEqual(requests, [])

    async def test_authentication_and_missing_resource_are_distinct(self):
        """Verify authentication and missing resource are distinct. This checks that untrusted provider responses stay within safety and resource limits."""
        for status, exception in [(401, otx.OTXAuthenticationError),
                                  (403, otx.OTXAuthenticationError),
                                  (404, otx.OTXNotFoundError)]:
            with self.subTest(status=status):
                async with httpx.AsyncClient(
                    transport=httpx.MockTransport(lambda request: httpx.Response(status)),
                    trust_env=False,
                ) as client:
                    with self.assertRaises(exception):
                        await otx._request_json(client, GENERAL)

    async def test_rate_limit_defers_without_early_retry(self):
        """Verify rate limit defers without early retry. This checks that untrusted provider responses stay within safety and resource limits."""
        requests = []
        def respond(request):
            """Return the chosen local HTTP response for this test's request."""
            requests.append(request)
            return httpx.Response(429, headers={"Retry-After": "120"})
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond), trust_env=False) as client:
            with patch.object(otx.asyncio, "sleep", AsyncMock()) as sleep:
                with self.assertRaises(otx.OTXRetryLaterError) as caught:
                    await otx._request_json(client, GENERAL)
        self.assertEqual(caught.exception.retry_after_seconds, 120)
        self.assertEqual(len(requests), 1)
        sleep.assert_not_awaited()

    async def test_long_503_wait_also_defers_without_truncation(self):
        """Verify long 503 wait also defers without truncation. This checks that untrusted provider responses stay within safety and resource limits."""
        async with httpx.AsyncClient(transport=httpx.MockTransport(
            lambda request: httpx.Response(503, headers={"Retry-After": "300"})
        ), trust_env=False) as client:
            with self.assertRaises(otx.OTXRetryLaterError) as caught:
                await otx._request_json(client, GENERAL)
        self.assertEqual(caught.exception.retry_after_seconds, 300)

    async def test_short_503_retry_after_is_honored(self):
        """Verify short 503 retry after is honored. This checks that untrusted provider responses stay within safety and resource limits."""
        responses = iter([httpx.Response(503, headers={"Retry-After": "7"}),
                          httpx.Response(200, json={"ok": True})])
        async with httpx.AsyncClient(transport=httpx.MockTransport(
            lambda request: next(responses)
        ), trust_env=False) as client:
            with patch.object(otx.asyncio, "sleep", AsyncMock()) as sleep:
                self.assertEqual(await otx._request_json(client, GENERAL), {"ok": True})
        sleep.assert_awaited_once_with(7.0)

    async def test_response_limit_closes_stream(self):
        """Verify response limit closes stream. This checks that untrusted provider responses stay within safety and resource limits."""
        stream = TrackedStream([b"{" + b" " * 64 + b"}"])
        async with httpx.AsyncClient(transport=httpx.MockTransport(
            lambda request: httpx.Response(200, stream=stream)
        ), trust_env=False) as client:
            with patch.object(otx, "OTX_MAX_RESPONSE_BYTES", 32):
                with self.assertRaises(otx.OTXCollectionLimitError):
                    await otx._request_json(client, GENERAL)
        self.assertTrue(stream.closed)

    async def test_compressed_response_rejected_before_reading(self):
        """Verify compressed response rejected before reading. This checks that untrusted provider responses stay within safety and resource limits."""
        stream = TrackedStream([b"untrusted-compressed-bytes"])
        async with httpx.AsyncClient(transport=httpx.MockTransport(
            lambda request: httpx.Response(200, headers={"Content-Encoding": "gzip"}, stream=stream)
        ), trust_env=False) as client:
            with self.assertRaises(otx.OTXResponseError):
                await otx._request_json(client, GENERAL)
        self.assertFalse(stream.read)
        self.assertTrue(stream.closed)

    async def test_total_response_byte_budget_is_shared(self):
        """Verify total response byte budget is shared. This checks that untrusted provider responses stay within safety and resource limits."""
        async with httpx.AsyncClient(transport=httpx.MockTransport(
            lambda request: httpx.Response(200, content=b"{}")
        ), trust_env=False) as client:
            budget = otx._LookupBudget(remaining_bytes=3)
            self.assertEqual(await otx._request_json(client, GENERAL, budget=budget), {})
            with self.assertRaises(otx.OTXCollectionLimitError):
                await otx._request_json(client, GENERAL, budget=budget)

    async def test_malformed_json_and_wrong_shape_fail(self):
        """Verify malformed json and wrong shape fail. This checks that untrusted provider responses stay within safety and resource limits."""
        for body in (b"<html>Error</html>", b"[]"):
            with self.subTest(body=body):
                async with httpx.AsyncClient(transport=httpx.MockTransport(
                    lambda request: httpx.Response(200, content=body)
                ), trust_env=False) as client:
                    with self.assertRaises(otx.OTXResponseError):
                        await otx._request_json(client, GENERAL)


# PAGINATION AND WORK LIMITS
# Cover ordinary two-page collection as well as cycles, cross-origin next URLs,
# missing next fields, ever-changing page URLs, and raw-record limits. Limits
# apply before normalization because even unsupported records cost resources.
class PaginationTests(unittest.IsolatedAsyncioTestCase):
    """Group cases that check untrusted provider responses stay within safety and resource limits."""
    def setUp(self):
        """Prepare mocks and settings shared by the tests in this class."""
        pacing = patch.object(otx, "OTX_REQUEST_DELAY_SECONDS", 0)
        pacing.start()
        self.addCleanup(pacing.stop)

    async def test_real_page_flow_collects_two_pages(self):
        """Verify real page flow collects two pages. This checks that untrusted provider responses stay within safety and resource limits."""
        requests = []
        def respond(request):
            """Return the chosen local HTTP response for this test's request."""
            requests.append(request)
            return httpx.Response(200, json={
                "results": [INDICATOR],
                "next": "?page=2" if request.url.params.get("page") is None else None,
            })
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond), trust_env=False) as client:
            rows = await otx._fetch_pulse_indicators(client, PULSE_ID)
        self.assertEqual(len(rows), 2)
        self.assertEqual(len(requests), 2)
        self.assertTrue(all(request.url.params["limit"] == "250" for request in requests))

    async def test_unsafe_next_is_not_requested(self):
        """Verify unsafe next is not requested. This checks that untrusted provider responses stay within safety and resource limits."""
        requests = []
        def respond(request):
            """Return the chosen local HTTP response for this test's request."""
            requests.append(request)
            return httpx.Response(200, json={"results": [], "next": "https://attacker.example/"})
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond), trust_env=False) as client:
            with self.assertRaises(otx.OTXResponseError):
                await otx._fetch_pulse_indicators(client, PULSE_ID)
        self.assertEqual(len(requests), 1)

    async def test_missing_next_is_not_silently_complete(self):
        """Verify missing next is not silently complete. This checks that untrusted provider responses stay within safety and resource limits."""
        with patch.object(otx, "_request_json", AsyncMock(return_value={"results": []})):
            with self.assertRaises(otx.OTXResponseError):
                await otx._fetch_pulse_indicators(AsyncMock(), PULSE_ID)

    async def test_cyclic_next_stops(self):
        """Verify cyclic next stops. This checks that untrusted provider responses stay within safety and resource limits."""
        with patch.object(otx, "_request_json", AsyncMock(return_value={
            "results": [], "next": PULSE_URL
        })) as request:
            with self.assertRaises(otx.OTXResponseError):
                await otx._fetch_pulse_indicators(AsyncMock(), PULSE_ID)
        self.assertEqual(request.await_count, 1)

    async def test_unique_next_urls_still_hit_page_limit(self):
        """Verify unique next urls still hit page limit. This checks that untrusted provider responses stay within safety and resource limits."""
        with patch.object(otx, "OTX_MAX_PAGES_PER_PULSE", 1), patch.object(
            otx, "_request_json", AsyncMock(return_value={"results": [], "next": "?page=2"})
        ) as request:
            with self.assertRaises(otx.OTXCollectionLimitError):
                await otx._fetch_pulse_indicators(AsyncMock(), PULSE_ID)
        self.assertEqual(request.await_count, 1)

    async def test_raw_record_budget_applies_before_normalization(self):
        # Even unsupported/malformed observable values consume work budget.
        """Verify raw record budget applies before normalization. This checks that untrusted provider responses stay within safety and resource limits."""
        with patch.object(otx, "_request_json", AsyncMock(return_value={
            "results": [{"type": "unsupported"}], "next": None
        })):
            with self.assertRaises(otx.OTXCollectionLimitError):
                await otx._fetch_pulse_indicators(
                    AsyncMock(), PULSE_ID, budget=otx._LookupBudget(remaining_records=0)
                )


# WHOLE-LOOKUP BEHAVIOR AND USER MESSAGES
# Verify the public entry point preserves failures, cancels at its deadline,
# honors external cancellation, and stops all remaining pulses on a cooldown.
# Partial results must retain completed source evidence and show unfinished
# assessments. CLI tests capture printed text and assert the exit status.
class LookupAndCheckerTests(unittest.IsolatedAsyncioTestCase):
    """Group cases that check untrusted provider responses stay within safety and resource limits."""
    async def test_initial_404_is_not_an_empty_result(self):
        """Verify initial 404 is not an empty result. This checks that untrusted provider responses stay within safety and resource limits."""
        with patch.object(otx, "_request_json", AsyncMock(side_effect=otx.OTXNotFoundError("404"))):
            with self.assertRaises(otx.OTXNotFoundError):
                await otx.fetch_otx_cve_iocs(CVE, api_key="test-key")

    async def test_lookup_deadline_cancels_wait(self):
        # Use a real awaitable, never patch asyncio.sleep in this timeout test.
        """Verify lookup deadline cancels wait. This checks that untrusted provider responses stay within safety and resource limits."""
        finished = False
        async def blocked(*args):
            """Hold the mocked provider request until the test cancels it."""
            nonlocal finished
            try:
                await asyncio.Event().wait()
            finally:
                finished = True
        with patch.object(otx, "OTX_TOTAL_TIMEOUT_SECONDS", 0.02), patch.object(
            otx, "_collect_cve", blocked
        ):
            with self.assertRaises(otx.OTXProviderUnavailableError):
                await otx.fetch_otx_cve_iocs(CVE, api_key="test-key")
        self.assertTrue(finished)

    async def test_external_cancellation_is_preserved(self):
        """Verify external cancellation is preserved. This checks that untrusted provider responses stay within safety and resource limits."""
        with patch.object(otx, "_collect_cve", AsyncMock(side_effect=asyncio.CancelledError)):
            with self.assertRaises(asyncio.CancelledError):
                await otx.fetch_otx_cve_iocs(CVE, api_key="test-key")

    async def test_custom_or_insecure_server_rejected_before_request(self):
        """Verify custom or insecure server rejected before request. This checks that untrusted provider responses stay within safety and resource limits."""
        for server in ("http://otx.alienvault.com", "https://attacker.example",
                       "https://otx.alienvault.com/private"):
            with self.subTest(server=server), patch.object(otx, "OTX_SERVER", server), patch.object(
                otx, "_request_json", AsyncMock()
            ) as request:
                with self.assertRaises(otx.OTXConfigurationError):
                    await otx.fetch_otx_cve_iocs(CVE, api_key="test-key")
                request.assert_not_awaited()

    async def test_rate_limit_does_not_continue_to_second_pulse(self):
        """Verify rate limit does not continue to second pulse. This checks that untrusted provider responses stay within safety and resource limits."""
        with patch.object(otx, "_request_json", AsyncMock(return_value=general(
            PULSE, dict(PULSE, id="b" * 24)
        ))), patch.object(otx, "_fetch_pulse_indicators", AsyncMock(
            side_effect=otx.OTXRetryLaterError("rate limited", 120)
        )) as fetch:
            with self.assertRaises(otx.OTXRetryLaterError):
                await otx.fetch_otx_cve_iocs(CVE, api_key="test-key")
        self.assertEqual(fetch.await_count, 1)

    async def test_pulse_cap_is_partial_and_preserves_unfetched_assessment(self):
        """Verify pulse cap is partial and preserves unfetched assessment. This checks that untrusted provider responses stay within safety and resource limits."""
        with patch.object(otx, "OTX_MAX_SELECTED_PULSES", 1), patch.object(
            otx, "_request_json", AsyncMock(return_value=general(PULSE, dict(PULSE, id="b" * 24)))
        ), patch.object(otx, "_fetch_pulse_indicators", AsyncMock(return_value=[INDICATOR])) as fetch:
            result = await otx.fetch_otx_cve_iocs(CVE, api_key="test-key")
        self.assertEqual(fetch.await_count, 1)
        self.assertFalse(result.complete)
        self.assertEqual(result.source_record_count_skipped, 0)
        self.assertEqual(result.source_record_count_processed, 1)
        self.assertEqual(len(result.source_record_assessments), 2)
        self.assertTrue(result.source_record_assessments[1].selected_for_collection)
        self.assertFalse(result.source_record_assessments[1].fetched)

    async def test_completed_pulse_survives_later_collection_limit(self):
        """Verify completed pulse survives later collection limit. This checks that untrusted provider responses stay within safety and resource limits."""
        with patch.object(otx, "_request_json", AsyncMock(return_value=general(
            PULSE, dict(PULSE, id="b" * 24)
        ))), patch.object(otx, "_fetch_pulse_indicators", AsyncMock(side_effect=[
            [INDICATOR], otx.OTXCollectionLimitError("page budget")
        ])):
            result = await otx.fetch_otx_cve_iocs(CVE, api_key="test-key")
        self.assertFalse(result.complete)
        self.assertEqual(result.observation_count, 1)
        self.assertEqual(result.source_record_count_processed, 1)

    async def test_checker_handles_not_found_and_retry_deadline(self):
        """Verify checker handles not found and retry deadline. This checks that untrusted provider responses stay within safety and resource limits."""
        for exception, message in [
            (otx.OTXNotFoundError("404"), "not a verified empty"),
            (otx.OTXRetryLaterError("slow down", 120), "Retry no earlier than"),
        ]:
            output = io.StringIO()
            with patch.object(check_ioc, "fetch_otx_cve_iocs", AsyncMock(side_effect=exception)):
                with redirect_stdout(output):
                    self.assertEqual(await check_ioc.main(CVE), 1)
            self.assertIn(message, output.getvalue())

    async def test_invalid_supported_indicator_marks_collection_partial(self):
        """Verify invalid supported indicator marks collection partial. This checks that untrusted provider responses stay within safety and resource limits."""
        with patch.object(otx, "_request_json", AsyncMock(return_value=general(PULSE))), patch.object(
            otx, "_fetch_pulse_indicators", AsyncMock(return_value=[
                INDICATOR, {"type": "IPv4", "indicator": "999.1.1.1"}
            ])
        ):
            result = await otx.fetch_otx_cve_iocs(CVE, api_key="test-key")
        self.assertFalse(result.complete)
        self.assertEqual(result.observation_count, 1)
        self.assertTrue(any("invalid supported" in message for message in result.warnings))

    async def test_unsupported_type_is_intentionally_outside_scope(self):
        """Verify unsupported type is intentionally outside scope. This checks that untrusted provider responses stay within safety and resource limits."""
        with patch.object(otx, "_request_json", AsyncMock(return_value=general(PULSE))), patch.object(
            otx, "_fetch_pulse_indicators", AsyncMock(return_value=[
                {"type": "email", "indicator": "analyst@example.com"}
            ])
        ):
            result = await otx.fetch_otx_cve_iocs(CVE, api_key="test-key")
        self.assertTrue(result.complete)
        self.assertEqual(result.observation_count, 0)


if __name__ == "__main__":
    unittest.main()
