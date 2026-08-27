"""API-level tests for the auth guard, the export endpoints and the IPC
token handling.

- M-01: a 401 is now counted and logged; enough of them turn into a 429.
- M-03: `/api/export/*` serves IOC-shaped rows as CSV or JSON, inside the
  existing auth guard.
- A-02: the capture IPC token never appears on the child's command line.
"""

from __future__ import annotations

import csv
import importlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from wsbuilder import Request

from sniff4hound.store import SniffStore


def _close_app_store(module):
    store = getattr(module, "store", None)
    if store is None:
        return
    try:
        store.close()
    except Exception:
        pass


def _reload_app_stack(require_auth: str = "1"):
    previous = os.environ.get("SNIFF4HOUND_REQUIRE_AUTH")
    os.environ["SNIFF4HOUND_REQUIRE_AUTH"] = require_auth
    try:
        import sniff4hound.app as app_module
        import sniff4hound.auth as auth_module

        _close_app_store(sys.modules.get("sniff4hound.app"))
        auth_module = importlib.reload(auth_module)
        app_module = importlib.reload(app_module)
        return auth_module, app_module
    finally:
        if previous is None:
            os.environ.pop("SNIFF4HOUND_REQUIRE_AUTH", None)
        else:
            os.environ["SNIFF4HOUND_REQUIRE_AUTH"] = previous


def _request(path, *, query="", headers=None, client=("203.0.113.10", 4444), method="GET"):
    return Request(method, path, query, dict(headers or {}), b"", client)


class AuthGuardHardeningTests(unittest.TestCase):
    """Failed authentication is counted, logged and eventually refused."""

    def setUp(self):
        self.auth, self.app = _reload_app_stack("1")
        self.auth._SESSION_TOKEN = "Ab12Cd34"
        self.auth.RATE_LIMITER.reset()
        self.addCleanup(self.auth.RATE_LIMITER.reset)

    def _dispatch(self, **kwargs):
        return self.app.app.dispatch(_request("/api/hello", **kwargs))

    def test_a_rejected_request_is_written_to_the_security_log(self):
        with patch.object(self.app.access_log, "log_auth_failure") as logged:
            response = self._dispatch(headers={"x-security-code": "wrong"})
        self.assertEqual(response.status, 401)
        self.assertTrue(logged.called, "a 401 must leave a trace")
        self.assertEqual(logged.call_args.kwargs.get("client"), "203.0.113.10")
        self.assertEqual(logged.call_args.kwargs.get("reason"), "invalid_token")

    def test_repeated_failures_are_eventually_rate_limited(self):
        statuses = [
            self._dispatch(headers={"x-security-code": f"guess{index}"}).status
            for index in range(self.auth.AUTH_FAILURE_THRESHOLD + 3)
        ]
        self.assertEqual(statuses[0], 401)
        self.assertIn(429, statuses, "a guessing loop must eventually be refused")
        limited = self._dispatch(headers={"x-security-code": "guess-again"})
        self.assertEqual(limited.status, 429)
        self.assertIn("Retry-After", dict(limited.headers))
        payload = json.loads(limited.body.decode("utf-8"))
        self.assertEqual(payload["code"], "auth_rate_limited")

    def test_a_lockout_is_scoped_to_the_offending_source(self):
        for index in range(self.auth.AUTH_FAILURE_THRESHOLD + 1):
            self._dispatch(headers={"x-security-code": f"guess{index}"})
        self.assertEqual(self._dispatch(headers={"x-security-code": "x"}).status, 429)
        other = self.app.app.dispatch(
            _request("/api/hello", headers={"x-security-code": "Ab12Cd34"}, client=("198.51.100.5", 5555))
        )
        self.assertEqual(other.status, 200)

    def test_a_successful_login_clears_the_counter(self):
        for index in range(self.auth.AUTH_FAILURE_THRESHOLD - 1):
            self._dispatch(headers={"x-security-code": f"guess{index}"})
        self.assertEqual(self._dispatch(headers={"x-security-code": "Ab12Cd34"}).status, 200)
        self.assertEqual(self._dispatch(headers={"x-security-code": "nope"}).status, 401)

    def test_the_session_endpoint_shares_the_limiter(self):
        # /api/auth/session is the one route the guard skips, which makes it
        # the only free "is this code right?" oracle if it is not limited.
        for index in range(self.auth.AUTH_FAILURE_THRESHOLD + 1):
            self.app.app.dispatch(_request("/api/auth/session", headers={"x-security-code": f"g{index}"}))
        response = self.app.app.dispatch(_request("/api/hello", headers={"x-security-code": "Ab12Cd34"}))
        self.assertEqual(response.status, 429)

    def test_an_unauthenticated_session_probe_is_not_counted(self):
        # The SPA calls /api/auth/session with no token at all on every load;
        # that is not a failed attempt and must never trip the limiter.
        for _ in range(self.auth.AUTH_FAILURE_THRESHOLD + 5):
            self.app.app.dispatch(_request("/api/auth/session"))
        self.assertEqual(self._dispatch(headers={"x-security-code": "Ab12Cd34"}).status, 200)


class ExportEndpointTests(unittest.TestCase):
    """M-03: IOC export, inside the auth guard."""

    def setUp(self):
        self.auth, self.app = _reload_app_stack("1")
        self.auth._SESSION_TOKEN = "Ab12Cd34"
        self.auth.RATE_LIMITER.reset()
        self.addCleanup(self.auth.RATE_LIMITER.reset)
        self.headers = {"x-security-code": "Ab12Cd34"}

    def _dispatch(self, path, query="", headers=None):
        return self.app.app.dispatch(
            _request(path, query=query, headers=self.headers if headers is None else headers)
        )

    def test_export_requires_authentication(self):
        response = self._dispatch("/api/export/alerts", headers={})
        self.assertEqual(response.status, 401)

    def test_every_dataset_answers_json(self):
        for dataset in ("alerts", "endpoints", "flows", "domains"):
            with self.subTest(dataset=dataset):
                response = self._dispatch(f"/api/export/{dataset}")
                self.assertEqual(response.status, 200)
                payload = json.loads(response.body.decode("utf-8"))
                self.assertEqual(payload["dataset"], dataset)
                self.assertIsInstance(payload["rows"], list)
                self.assertTrue(payload["fields"])

    def test_csv_carries_the_header_row_and_a_download_name(self):
        response = self._dispatch("/api/export/domains", query="format=csv")
        self.assertEqual(response.status, 200)
        headers = {str(key).lower(): value for key, value in dict(response.headers).items()}
        self.assertIn("text/csv", headers.get("content-type", ""))
        self.assertIn("attachment", headers.get("content-disposition", ""))
        body = response.body.decode("utf-8") if isinstance(response.body, bytes) else str(response.body)
        first_row = next(csv.reader(io.StringIO(body)))
        self.assertEqual(first_row[0], "domain")

    def test_an_unknown_format_is_a_clean_400(self):
        response = self._dispatch("/api/export/alerts", query="format=pdf")
        self.assertEqual(response.status, 400)
        payload = json.loads(response.body.decode("utf-8"))
        self.assertEqual(payload["code"], "invalid_request")

    def test_the_index_lists_datasets_and_columns(self):
        payload = json.loads(self._dispatch("/api/export/").body.decode("utf-8"))
        self.assertEqual(set(payload["datasets"]), {"alerts", "endpoints", "flows", "domains"})
        self.assertEqual(set(payload["formats"]), {"csv", "json"})
        self.assertIn("severity", payload["fields"]["alerts"])


class ExportContentTests(unittest.TestCase):
    """The exported rows carry the IOC fields an analyst needs, built from
    the store's own listings."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.store = SniffStore(Path(self._tmp.name) / "export.db")
        self.addCleanup(self.store.close)

    def _record_packet(self, **overrides):
        from sniff4hound.sniffer import build_base_packet
        from sniff4hound.utils import utc_now

        packet = build_base_packet(utc_now(), "eth0", b"\x00" * 64, b"\x00" * 40)
        packet.update(
            {
                "src_ip": "203.0.113.9",
                "dst_ip": "198.51.100.4",
                "src_port": 51234,
                "dst_port": 22,
                "proto": "tcp",
                "direction": "outbound",
            }
        )
        packet.update(overrides)
        return self.store.register_packet(packet)

    def test_alert_rows_carry_rule_severity_and_first_last_seen(self):
        from sniff4hound import export

        self._record_packet(
            tags=[{"key": "monitor", "value": "SSH brute force", "severity": "high"}],
        )
        payload = export.build_export(self.store, "alerts", limit=100)
        self.assertEqual(payload["count"], 1)
        row = payload["rows"][0]
        self.assertEqual(row["rule"], "SSH brute force")
        self.assertEqual(row["severity"], "high")
        self.assertEqual(row["src_ip"], "203.0.113.9")
        self.assertEqual(row["dst_port"], 22)
        self.assertTrue(row["first_seen"])
        self.assertTrue(row["last_seen"])

    def test_repeated_hits_collapse_into_one_indicator(self):
        from sniff4hound import export

        for _ in range(3):
            self._record_packet(tags=[{"key": "monitor", "value": "Port scan", "severity": "medium"}])
        payload = export.build_export(self.store, "alerts", limit=100)
        self.assertEqual(payload["count"], 1)
        self.assertEqual(payload["rows"][0]["hit_count"], 3)

    def test_domain_rows_come_from_the_domain_catalog(self):
        from sniff4hound import export

        self.store.record_domain(name="evil.example", source="dns", ip="203.0.113.9", port=53, proto="udp")
        payload = export.build_export(self.store, "domains", limit=100)
        self.assertEqual([row["domain"] for row in payload["rows"]], ["evil.example"])
        self.assertEqual(payload["rows"][0]["source"], "dns")

    def test_csv_quoting_survives_a_hostile_value(self):
        from sniff4hound import export

        rows = [{"domain": 'a,b"c\nd', "source": "dns"}]
        text = export.rows_to_csv(("domain", "source"), rows)
        parsed = list(csv.DictReader(io.StringIO(text)))
        self.assertEqual(parsed[0]["domain"], 'a,b"c\nd')
        self.assertEqual(parsed[0]["source"], "dns")

    def test_an_unknown_dataset_raises_value_error(self):
        from sniff4hound import export

        with self.assertRaises(ValueError):
            export.build_export(self.store, "everything")


class CaptureIpcTokenTests(unittest.TestCase):
    """A-02: /proc/<pid>/cmdline is world-readable, so the shared IPC secret
    must never travel as a `sudo env KEY=VALUE` argument."""

    def test_the_token_is_not_on_the_capture_child_command_line(self):
        import sniff4hound.manage as manage

        token = "f" * 64
        with patch.dict(os.environ, {"SNIFF4HOUND_IPC_TOKEN": token}, clear=False):
            command = manage._build_capture_relaunch_command("/tmp/x.sock", "/tmp/x.token", 1000)
        joined = " ".join(command)
        self.assertNotIn(token, joined)
        self.assertIn("SNIFF4HOUND_IPC_TOKEN_FILE=/tmp/x.token", command)
        self.assertFalse(any(entry.startswith("SNIFF4HOUND_IPC_TOKEN=") for entry in command))

    def test_the_jwt_secret_is_not_forwarded_either(self):
        import sniff4hound.manage as manage

        with patch.dict(os.environ, {"SNIFF4HOUND_JWT_SECRET": "s" * 64}, clear=False):
            command = manage._build_capture_relaunch_command("/tmp/x.sock", "/tmp/x.token", 1000)
        self.assertFalse(any(entry.startswith("SNIFF4HOUND_JWT_SECRET=") for entry in command))

    def test_capture_service_self_elevation_also_keeps_it_off_argv(self):
        import sniff4hound.capture_service as capture_service

        token = "e" * 64
        with patch.dict(os.environ, {"SNIFF4HOUND_IPC_TOKEN": token}, clear=False):
            os.environ.pop("SNIFF4HOUND_IPC_TOKEN_FILE", None)
            try:
                command = capture_service._build_admin_relaunch_command()
                token_file = os.environ.get("SNIFF4HOUND_IPC_TOKEN_FILE", "")
                self.assertTrue(token_file)
                self.addCleanup(capture_service._discard_ephemeral_token_file, token_file)
                self.assertNotIn(token, " ".join(command))
                self.assertIn(f"SNIFF4HOUND_IPC_TOKEN_FILE={token_file}", command)
            finally:
                os.environ.pop("SNIFF4HOUND_IPC_TOKEN_FILE", None)
                os.environ.pop("SNIFF4HOUND_IPC_TOKEN_FILE_EPHEMERAL", None)

    def test_the_token_file_is_private_and_round_trips(self):
        from sniff4hound import settings

        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "nested" / "ipc.token"
            self.assertTrue(settings.write_ipc_token_file(path, "a" * 64))
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(settings.read_ipc_token_file(str(path)), "a" * 64)
            with patch.dict(os.environ, {"SNIFF4HOUND_IPC_TOKEN_FILE": str(path)}, clear=False):
                self.assertEqual(settings.resolve_ipc_token(), "a" * 64)

    def test_a_missing_token_file_falls_back_to_the_environment(self):
        from sniff4hound import settings

        with patch.dict(
            os.environ,
            {"SNIFF4HOUND_IPC_TOKEN_FILE": "/nonexistent/ipc.token", "SNIFF4HOUND_IPC_TOKEN": "b" * 64},
            clear=False,
        ):
            self.assertEqual(settings.resolve_ipc_token(), "b" * 64)


if __name__ == "__main__":
    unittest.main()
