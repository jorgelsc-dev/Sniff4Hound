from __future__ import annotations

import io
import re
import unittest
from datetime import datetime, timedelta
from contextlib import redirect_stdout
from unittest.mock import patch

from sniff4hound import access_log
from sniff4hound.utils import utc_now

# 2026-08-26T14:27:24+00:00 HTTP/1.1 GET /x ref=- loc=- 200
LINE_RE = re.compile(
    r"^(?P<time>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}) "
    r"(?P<protocol>HTTP/\S+) (?P<method>\S+) (?P<target>\S+) "
    r"ref=(?P<referer>\S*) loc=(?P<location>\S*) (?P<status>\d{3})$"
)

AUTH_FAIL_RE = re.compile(
    r"^(?P<time>\S+) SECURITY AUTH-FAIL (?P<protocol>HTTP/\S+) (?P<method>\S+) (?P<target>\S+) "
    r"client=(?P<client>\S+) reason=(?P<reason>\S+) retry_after=(?P<retry>\d+)s (?P<status>\d{3})$"
)


class _FakeRequest:
    def __init__(self, method="GET", path="/api/runtime/", query_string="", headers=None, client=("127.0.0.1", 51234)):
        self.method = method
        self.path = path
        self.query_string = query_string
        self.headers = headers if headers is not None else {"user-agent": "curl/8.5.0"}
        self.client = client


class _FakeResponse:
    def __init__(self, status=200, body=b"{}", headers=None):
        self.status = status
        self.body = body
        self.headers = headers or {}


def _capture(fn, *args, **kwargs) -> str:
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        fn(*args, **kwargs)
    return buffer.getvalue().strip()


class AccessLogFormatTests(unittest.TestCase):
    def setUp(self):
        # Colour codes would break the strict field parsing below, and the
        # tests must not depend on whether stdout happens to be a TTY.
        patcher = patch.object(access_log, "ACCESS_LOG_COLOR", "never")
        patcher.start()
        self.addCleanup(patcher.stop)
        enabled = patch.object(access_log, "ACCESS_LOG_ENABLED", True)
        enabled.start()
        self.addCleanup(enabled.stop)

    def test_emits_the_compact_line(self):
        line = _capture(
            access_log.log_response,
            _FakeRequest(headers={"referer": "http://host/soc"}),
            _FakeResponse(200, b"x" * 512),
            0.0,
        )
        match = LINE_RE.match(line)
        self.assertIsNotNone(match, f"unexpected shape: {line!r}")
        self.assertEqual(match.group("protocol"), "HTTP/1.1")
        self.assertEqual(match.group("method"), "GET")
        self.assertEqual(match.group("target"), "/api/runtime/")
        self.assertEqual(match.group("referer"), "http://host/soc")
        self.assertEqual(match.group("status"), "200")

    def test_reports_the_response_location_header(self):
        line = _capture(
            access_log.log_response,
            _FakeRequest(),
            _FakeResponse(302, b"", headers={"Location": "/dashboard"}),
            0.0,
        )
        match = LINE_RE.match(line)
        self.assertIsNotNone(match, line)
        self.assertEqual(match.group("location"), "/dashboard")
        self.assertEqual(match.group("status"), "302")

    def test_query_string_is_part_of_the_target(self):
        line = _capture(
            access_log.log_response,
            _FakeRequest(path="/api/ports/", query_string="since=1h&limit=50"),
            _FakeResponse(200, b""),
            0.0,
        )
        self.assertIn("GET /api/ports/?since=1h&limit=50 ", line)

    def test_missing_referer_and_location_become_a_dash(self):
        line = _capture(access_log.log_response, _FakeRequest(headers={}), _FakeResponse(404, b"nope"), 0.0)
        match = LINE_RE.match(line)
        self.assertIsNotNone(match, line)
        self.assertEqual(match.group("referer"), "-")
        self.assertEqual(match.group("location"), "-")
        self.assertEqual(match.group("status"), "404")

    def test_a_hostile_referer_cannot_forge_extra_fields(self):
        # Fields are space-separated, so a Referer full of spaces would
        # otherwise render as extra columns and let a remote client forge the
        # status a log parser reads back. The value must survive as one field.
        line = _capture(
            access_log.log_response,
            _FakeRequest(headers={"referer": "evil loc=/admin 200"}),
            _FakeResponse(403, b""),
            0.0,
        )
        match = LINE_RE.match(line)
        self.assertIsNotNone(match, f"injected referer broke the line: {line!r}")
        self.assertEqual(match.group("status"), "403", "forged status won")
        self.assertEqual(match.group("location"), "-", "forged Location won")
        self.assertNotIn(" ", match.group("referer"))

    def test_newlines_in_a_header_cannot_fake_a_second_entry(self):
        line = _capture(
            access_log.log_response,
            _FakeRequest(headers={"referer": "a\r\n2026-01-01 00:00:00 HTTP/1.1 GET /fake ref=- loc=- 200"}),
            _FakeResponse(403, b""),
            0.0,
        )
        self.assertEqual(len(line.splitlines()), 1, line)
        self.assertTrue(line.endswith("403"), line)

    def test_websocket_handshake_logs_as_status_101(self):
        line = _capture(access_log.log_websocket_open, _FakeRequest(path="/ws/", query_string="since=1h"))
        match = LINE_RE.match(line)
        self.assertIsNotNone(match, line)
        self.assertEqual(match.group("status"), "101")
        self.assertEqual(match.group("target"), "/ws/?since=1h")

    def test_timestamps_are_utc(self):
        # The access lines used to carry local wall-clock time while every
        # stored `created_at` was UTC, so a log line and the events it
        # produced could not be correlated without knowing the operator's
        # timezone.
        line = _capture(access_log.log_response, _FakeRequest(), _FakeResponse(200, b""), 0.0)
        stamp = LINE_RE.match(line).group("time")
        self.assertEqual(datetime.fromisoformat(stamp).utcoffset(), timedelta(0))
        # Byte-for-byte the same shape utils.utc_now() writes into every
        # `created_at`, so the two correlate as plain strings.
        self.assertEqual(len(stamp), len(utc_now()))



    def test_websocket_close_reports_the_close_code(self):
        line = _capture(access_log.log_websocket_close, _FakeRequest(path="/ws/"), 4401, 0.0)
        self.assertIn("WS CLOSE /ws/", line)
        self.assertTrue(line.endswith("close=4401"), line)

    def test_disabled_logging_prints_nothing(self):
        with patch.object(access_log, "ACCESS_LOG_ENABLED", False):
            self.assertEqual(_capture(access_log.log_response, _FakeRequest(), _FakeResponse(), 0.0), "")
            self.assertEqual(_capture(access_log.log_websocket_open, _FakeRequest()), "")

    def test_logging_never_raises_on_a_malformed_request(self):
        class Broken:
            @property
            def headers(self):
                raise RuntimeError("boom")

        # Must not propagate: access logging can never be allowed to take
        # down the request it is describing.
        self.assertEqual(_capture(access_log.log_response, Broken(), _FakeResponse(), 0.0), "")

    def test_status_is_colorized_only_when_enabled(self):
        with patch.object(access_log, "ACCESS_LOG_COLOR", "always"):
            line = _capture(access_log.log_response, _FakeRequest(), _FakeResponse(500, b""), 0.0)
        self.assertIn("\033[", line)
        with patch.object(access_log, "ACCESS_LOG_COLOR", "never"):
            line = _capture(access_log.log_response, _FakeRequest(), _FakeResponse(500, b""), 0.0)
        self.assertNotIn("\033[", line)



class AccessLogRedactionTests(unittest.TestCase):
    """The frontend passes the live security code in the WebSocket handshake
    query string, so an unredacted access line printed the working
    credential to the console on every single reconnect."""

    def setUp(self):
        for attribute, value in (("ACCESS_LOG_COLOR", "never"), ("ACCESS_LOG_ENABLED", True)):
            patcher = patch.object(access_log, attribute, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_security_code_never_reaches_the_line(self):
        secret = "Ab3xZ9qP"
        for key in ("code", "security_code", "access_token", "token", "auth"):
            with self.subTest(key=key):
                line = _capture(
                    access_log.log_websocket_open,
                    _FakeRequest(path="/ws/", query_string=f"{key}={secret}"),
                )
                self.assertNotIn(secret, line, f"{key} leaked the live token")
                self.assertIn(f"{key}=REDACTED", line)

    def test_other_query_parameters_survive_untouched(self):
        line = _capture(
            access_log.log_response,
            _FakeRequest(path="/api/ports/", query_string="since=1h&token=SEKRIT&limit=50"),
            _FakeResponse(200, b""),
            0.0,
        )
        self.assertIn("since=1h", line)
        self.assertIn("limit=50", line)
        self.assertNotIn("SEKRIT", line)

    def test_a_token_in_the_referer_is_redacted_too(self):
        for key in ("code", "security_code"):
            with self.subTest(key=key):
                line = _capture(
                    access_log.log_response,
                    _FakeRequest(headers={"referer": f"http://host/dashboard?{key}=Ab3xZ9qP"}),
                    _FakeResponse(200, b""),
                    0.0,
                )
                self.assertNotIn("Ab3xZ9qP", line)
                self.assertIn(f"{key}=REDACTED", line)


class AccessLogAuthFailureTests(unittest.TestCase):
    """Every 401 used to be silent, so a guessing loop against the security
    code left no trace at all in the operator's console."""

    def setUp(self):
        for attribute, value in (("ACCESS_LOG_COLOR", "never"), ("ACCESS_LOG_ENABLED", True)):
            patcher = patch.object(access_log, attribute, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_records_the_source_address_and_reason(self):
        line = _capture(
            access_log.log_auth_failure,
            _FakeRequest(path="/api/dashboard/"),
            client="203.0.113.7",
            reason="invalid_token",
            status=401,
            retry_after=0.0,
        )
        match = AUTH_FAIL_RE.match(line)
        self.assertIsNotNone(match, f"unexpected shape: {line!r}")
        self.assertEqual(match.group("client"), "203.0.113.7")
        self.assertEqual(match.group("reason"), "invalid_token")
        self.assertEqual(match.group("status"), "401")

    def test_reports_the_applied_lockout(self):
        line = _capture(
            access_log.log_auth_failure,
            _FakeRequest(path="/api/dashboard/"),
            client="203.0.113.7",
            reason="rate_limited",
            status=429,
            retry_after=20.0,
        )
        match = AUTH_FAIL_RE.match(line)
        self.assertIsNotNone(match, line)
        self.assertEqual(match.group("retry"), "20")
        self.assertEqual(match.group("status"), "429")

    def test_the_attempted_token_is_not_logged(self):
        line = _capture(
            access_log.log_auth_failure,
            _FakeRequest(path="/ws/", query_string="security_code=GuEsS123"),
            client="203.0.113.7",
        )
        self.assertNotIn("GuEsS123", line)

    def test_disabled_logging_prints_nothing(self):
        with patch.object(access_log, "ACCESS_LOG_ENABLED", False):
            self.assertEqual(_capture(access_log.log_auth_failure, _FakeRequest(), client="1.2.3.4"), "")

if __name__ == "__main__":
    unittest.main()
