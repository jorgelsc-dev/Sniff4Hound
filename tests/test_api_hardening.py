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


def _reload_app_stack(test_case, require_auth: str = "1"):
    """Reload sniff4hound.app/.auth with SNIFF4HOUND_REQUIRE_AUTH pinned to
    require_auth for the duration of test_case. Reloading is process-global
    (it replaces sys.modules["sniff4hound.app"] etc.), so without undoing it
    afterwards the module would stay in this test's auth state for every
    later test in the process - including ones in a different file that
    never touch this env var, which only surfaces once something shards or
    reorders the suite. test_case.addCleanup reloads back to the prior env
    value once this test is done, regardless of how it exits."""
    previous = os.environ.get("SNIFF4HOUND_REQUIRE_AUTH")

    def _restore():
        if previous is None:
            os.environ.pop("SNIFF4HOUND_REQUIRE_AUTH", None)
        else:
            os.environ["SNIFF4HOUND_REQUIRE_AUTH"] = previous
        import sniff4hound.app as app_module
        import sniff4hound.auth as auth_module

        _close_app_store(sys.modules.get("sniff4hound.app"))
        importlib.reload(auth_module)
        importlib.reload(app_module)

    test_case.addCleanup(_restore)

    os.environ["SNIFF4HOUND_REQUIRE_AUTH"] = require_auth
    import sniff4hound.app as app_module
    import sniff4hound.auth as auth_module

    _close_app_store(sys.modules.get("sniff4hound.app"))
    auth_module = importlib.reload(auth_module)
    app_module = importlib.reload(app_module)
    return auth_module, app_module


def _request(path, *, query="", headers=None, client=("203.0.113.10", 4444), method="GET", body=b""):
    if isinstance(body, str):
        body = body.encode("utf-8")
    return Request(method, path, query, dict(headers or {}), body, client)


class AuthGuardHardeningTests(unittest.TestCase):
    """Failed authentication is counted, logged and eventually refused."""

    def setUp(self):
        self.auth, self.app = _reload_app_stack(self, "1")
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

    def test_cross_origin_state_change_is_rejected_after_auth(self):
        response = self.app.app.dispatch(
            _request(
                "/api/echo",
                method="POST",
                headers={
                    "x-security-code": "Ab12Cd34",
                    "host": "127.0.0.1:45678",
                    "origin": "http://evil.example",
                },
                body="{}",
            )
        )
        self.assertEqual(response.status, 403)
        payload = json.loads(response.body.decode("utf-8"))
        self.assertEqual(payload["code"], "bad_origin")

    def test_same_origin_state_change_is_allowed(self):
        response = self.app.app.dispatch(
            _request(
                "/api/echo",
                method="POST",
                headers={
                    "x-security-code": "Ab12Cd34",
                    "host": "127.0.0.1:45678",
                    "origin": "http://127.0.0.1:45678",
                },
                body="hello",
            )
        )
        self.assertEqual(response.status, 200)

    def test_forwarded_host_alone_cannot_satisfy_the_origin_guard(self):
        """X-Forwarded-Host used to outrank Host, which let the same caller
        supply both halves of the same-origin comparison: send Origin: evil and
        X-Forwarded-Host: evil and the guard agreed with itself. Only a proxy
        we are told to trust may speak for the host now."""
        response = self.app.app.dispatch(
            _request(
                "/api/echo",
                method="POST",
                headers={
                    "x-security-code": "Ab12Cd34",
                    "host": "127.0.0.1:45678",
                    "x-forwarded-host": "evil.example",
                    "origin": "http://evil.example",
                },
                body="{}",
            )
        )
        self.assertEqual(response.status, 403)
        payload = json.loads(response.body.decode("utf-8"))
        self.assertEqual(payload["code"], "bad_origin")

    def test_forwarded_host_is_honoured_when_a_proxy_is_trusted(self):
        """The opt-out has to actually work, or a real reverse-proxy
        deployment has no way back."""
        with patch.object(self.app, "TRUST_FORWARDED_HEADERS", True):
            response = self.app.app.dispatch(
                _request(
                    "/api/echo",
                    method="POST",
                    headers={
                        "x-security-code": "Ab12Cd34",
                        "host": "127.0.0.1:45678",
                        "x-forwarded-host": "sensor.example",
                        "origin": "http://sensor.example",
                    },
                    body="hello",
                )
            )
        self.assertEqual(response.status, 200)

    def _set_desktop_mode(self, value):
        previous = os.environ.get("SNIFF4HOUND_DESKTOP")

        def _restore():
            if previous is None:
                os.environ.pop("SNIFF4HOUND_DESKTOP", None)
            else:
                os.environ["SNIFF4HOUND_DESKTOP"] = previous

        self.addCleanup(_restore)
        if value is None:
            os.environ.pop("SNIFF4HOUND_DESKTOP", None)
        else:
            os.environ["SNIFF4HOUND_DESKTOP"] = value

    def test_null_origin_from_the_bundled_desktop_shell_is_allowed(self):
        # Older local-file desktop builds reported the opaque origin
        # literally as "null" - the one legitimate non-same-origin caller
        # once the backend stops serving any page of its own.
        # _desktop_mode_enabled() reads the env var live (it isn't a
        # module-level constant like REQUIRE_AUTH), so no module reload is
        # needed here, unlike _reload_app_stack above.
        self._set_desktop_mode("1")
        response = self.app.app.dispatch(
            _request(
                "/api/echo",
                method="POST",
                headers={
                    "x-security-code": "Ab12Cd34",
                    "host": "127.0.0.1:45678",
                    "origin": "null",
                },
                body="{}",
            )
        )
        self.assertEqual(response.status, 200)

    def test_app_shell_origin_from_the_bundled_desktop_shell_is_allowed(self):
        self._set_desktop_mode("1")
        response = self.app.app.dispatch(
            _request(
                "/api/echo",
                method="POST",
                headers={
                    "x-security-code": "Ab12Cd34",
                    "host": "127.0.0.1:45678",
                    "origin": "app://shell",
                },
                body="{}",
            )
        )
        self.assertEqual(response.status, 200)

    def test_null_origin_is_still_rejected_outside_desktop_mode(self):
        # A plain server/CLI deployment (no Electron shell involved) keeps
        # today's exact behavior - "null" is not a magic bypass in general,
        # only for a backend actually launched to serve the desktop shell.
        self._set_desktop_mode(None)
        response = self.app.app.dispatch(
            _request(
                "/api/echo",
                method="POST",
                headers={
                    "x-security-code": "Ab12Cd34",
                    "host": "127.0.0.1:45678",
                    "origin": "null",
                },
                body="{}",
            )
        )
        self.assertEqual(response.status, 403)
        payload = json.loads(response.body.decode("utf-8"))
        self.assertEqual(payload["code"], "bad_origin")

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

    def test_websocket_ticket_is_one_time_and_replaces_query_security_code(self):
        issued = self.app.app.dispatch(
            _request("/api/ws/ticket", method="POST", headers={"x-security-code": "Ab12Cd34"})
        )
        self.assertEqual(issued.status, 200)
        ticket = json.loads(issued.body.decode("utf-8"))["ticket"]

        first = _request("/ws/", query=f"ws_ticket={ticket}")
        self.assertIsNone(self.app._guard_websocket_auth(first))

        replay = _request("/ws/", query=f"ws_ticket={ticket}")
        self.assertEqual(self.app._guard_websocket_auth(replay).status, 401)

        old_style = _request("/ws/", query="security_code=Ab12Cd34")
        self.assertEqual(self.app._guard_websocket_auth(old_style).status, 401)


class ExportEndpointTests(unittest.TestCase):
    """M-03: IOC export, inside the auth guard."""

    def setUp(self):
        self.auth, self.app = _reload_app_stack(self, "1")
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

    def test_captured_secret_preview_is_redacted_before_storage(self):
        row = self._record_packet(
            payload_text="Authorization: Bearer very-secret-token password=hunter2",
            banner_text="redis://user:supersecret@example.internal",
        )
        text = f"{row.get('payload_text')} {row.get('banner_text')}"
        self.assertIn("[REDACTED]", text)
        self.assertNotIn("very-secret-token", text)
        self.assertNotIn("hunter2", text)
        self.assertNotIn("supersecret", text)
        payload = self.store.list_payloads(limit=1)[0]
        self.assertIn("[REDACTED]", payload["response_plain"])
        self.assertNotIn("very-secret-token", payload["response_plain"])
        self.assertNotIn("hunter2", payload["response_plain"])
        self.assertNotIn("supersecret", payload["response_plain"])

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


class ApiInputCoercionTests(unittest.TestCase):
    """Client JSON should mean what it says, even when it comes from forms or
    scripts that send booleans as strings."""

    def setUp(self):
        self.auth, self.app = _reload_app_stack(self, "0")

    def _store_with_captured_favicon(self, tmp_dir):
        replacement_store = SniffStore(Path(tmp_dir) / "api.db")
        icon = b"\x00\x00\x01\x00\x01\x00\x10\x10\x00\x00\x01\x00"
        http_response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: image/vnd.microsoft.icon\r\n"
            b"Content-Length: 12\r\n"
            b"\r\n"
            + icon
        )
        replacement_store.register_packet(
            {
                "proto": "tcp",
                "src_ip": "198.51.100.10",
                "dst_ip": "10.0.0.5",
                "src_port": 80,
                "dst_port": 51321,
                "summary": "HTTP favicon response",
                "payload_text": "HTTP/1.1 200 OK\r\nContent-Type: image/vnd.microsoft.icon",
                "payload_hex": http_response.hex(),
                "banner_text": "HTTP/1.1 200 OK\r\nContent-Type: image/vnd.microsoft.icon",
                "http_path": "/favicon.ico",
                "http_host": "example.test",
                "raw_packet": b"",
            }
        )
        return replacement_store, icon

    def _store_with_captured_svg_favicon(self, tmp_dir):
        """A favicon body is whatever the watched host chose to send, so this
        is the hostile case: a valid SVG that carries a script."""
        replacement_store = SniffStore(Path(tmp_dir) / "svg.db")
        icon = b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'
        http_response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: image/svg+xml\r\n"
            b"Content-Length: " + str(len(icon)).encode("ascii") + b"\r\n"
            b"\r\n"
            + icon
        )
        replacement_store.register_packet(
            {
                "proto": "tcp",
                "src_ip": "198.51.100.11",
                "dst_ip": "10.0.0.5",
                "src_port": 80,
                "dst_port": 51322,
                "summary": "HTTP favicon response",
                "payload_text": "HTTP/1.1 200 OK\r\nContent-Type: image/svg+xml",
                "payload_hex": http_response.hex(),
                "banner_text": "HTTP/1.1 200 OK\r\nContent-Type: image/svg+xml",
                "http_path": "/favicon.svg",
                "http_host": "example.test",
                "raw_packet": b"",
            }
        )
        return replacement_store, icon

    def test_svg_favicon_is_served_as_a_download_not_as_a_live_document(self):
        """Serving a captured SVG inline runs its <script> in this backend's
        own origin, where the API - and the security code in the query string
        that fetched it - are readable. Raster icons stay inline; a scriptable
        document does not."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            forensic = patch("sniff4hound.store.STORE_RAW_PACKET_BYTES", True)
            forensic.start()
            self.addCleanup(forensic.stop)
            replacement_store, icon = self._store_with_captured_svg_favicon(tmp_dir)
            try:
                with patch.object(self.app, "store", replacement_store):
                    rows = json.loads(
                        self.app.app.dispatch(_request("/favicons/")).body.decode("utf-8")
                    )
                self.assertEqual(rows[0]["mime_type"], "image/svg+xml")

                with patch.object(self.app, "store", replacement_store):
                    response = self.app.app.dispatch(_request(
                        "/favicons/raw/",
                        query=f"id={rows[0]['id']}",
                    ))

                self.assertEqual(response.status, 200)
                # The bytes are still served - this is a forensic tool - but
                # never as something the browser will render and execute.
                self.assertEqual(response.body, icon)
                self.assertEqual(response.headers.get("Content-Type"), "application/octet-stream")
                self.assertTrue(
                    response.headers.get("Content-Disposition", "").startswith("attachment;"),
                    response.headers.get("Content-Disposition"),
                )
                self.assertEqual(response.headers.get("Content-Security-Policy"), "default-src 'none'; sandbox")
                self.assertEqual(response.headers.get("X-Content-Type-Options"), "nosniff")
            finally:
                replacement_store.close()

    def test_raster_favicon_stays_inline_but_is_sandboxed(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            forensic = patch("sniff4hound.store.STORE_RAW_PACKET_BYTES", True)
            forensic.start()
            self.addCleanup(forensic.stop)
            replacement_store, icon = self._store_with_captured_favicon(tmp_dir)
            try:
                with patch.object(self.app, "store", replacement_store):
                    rows = json.loads(
                        self.app.app.dispatch(_request("/favicons/")).body.decode("utf-8")
                    )
                    response = self.app.app.dispatch(_request(
                        "/favicons/raw/",
                        query=f"id={rows[0]['id']}",
                    ))

                self.assertEqual(response.body, icon)
                self.assertEqual(response.headers.get("Content-Type"), "image/x-icon")
                self.assertTrue(
                    response.headers.get("Content-Disposition", "").startswith("inline;"),
                    response.headers.get("Content-Disposition"),
                )
                self.assertEqual(response.headers.get("Content-Security-Policy"), "default-src 'none'; sandbox")
            finally:
                replacement_store.close()

    def test_file_catalog_endpoints_accept_root_arrays(self):
        class FakeStore:
            def __init__(self):
                self.filename = ""
                self.rows = None

            def read_catalog_file(self, _filename):
                return []

            def write_catalog_file(self, filename, rows):
                self.filename = filename
                self.rows = rows

        fake = FakeStore()
        body = json.dumps([{"id": "home", "label": "Home lab"}, "skip-me", {"id": "corp"}])
        with patch.object(self.app, "store", fake):
            response = self.app.app.dispatch(_request(
                "/api/catalog/file/ip-presets",
                method="POST",
                body=body,
            ))

        self.assertEqual(response.status, 200)
        payload = json.loads(response.body.decode("utf-8"))
        self.assertEqual(payload["count"], 2)
        self.assertEqual(payload["ignored"], 1)
        self.assertEqual(fake.filename, "ip_presets.json")
        self.assertEqual([row["id"] for row in fake.rows], ["home", "corp"])

    def test_bool_like_strings_are_not_all_truthy_for_toggles(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            replacement_store = SniffStore(Path(tmp_dir) / "api.db")
            self.addCleanup(replacement_store.close)
            entry = replacement_store.create_blacklist_entry("ip", "exact", "203.0.113.55")
            with patch.object(self.app, "store", replacement_store):
                response = self.app.app.dispatch(_request(
                    "/api/blacklist/toggle",
                    method="POST",
                    body=json.dumps({"id": entry["id"], "enabled": "false"}),
                ))

            self.assertEqual(response.status, 200)
            payload = json.loads(response.body.decode("utf-8"))
            self.assertFalse(payload["enabled"])
            self.assertFalse(replacement_store.get_blacklist_entry(entry["id"])["enabled"])

    def test_false_clean_results_string_does_not_delete_related_rows(self):
        class FakeStore:
            def __init__(self):
                self.deleted = None

            def delete_session(self, session_id):
                self.deleted = session_id

        fake = FakeStore()
        with patch.object(self.app, "store", fake), patch.object(self.app, "_clear_packets_for_session") as clear:
            response = self.app.app.dispatch(_request(
                "/target/",
                method="DELETE",
                body=json.dumps({"id": 42, "clean_results": "false"}),
            ))

        self.assertEqual(response.status, 200)
        self.assertEqual(fake.deleted, 42)
        clear.assert_not_called()

    def test_port_action_endpoint_updates_captured_packet_state(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            replacement_store = SniffStore(Path(tmp_dir) / "api.db")
            self.addCleanup(replacement_store.close)
            packet = replacement_store.register_packet(
                {
                    "proto": "tcp",
                    "src_ip": "10.0.0.5",
                    "dst_ip": "10.0.0.10",
                    "src_port": 51234,
                    "dst_port": 443,
                    "summary": "TLS probe",
                    "payload_text": "",
                    "payload_hex": "",
                    "raw_packet": b"",
                }
            )
            with patch.object(self.app, "store", replacement_store):
                response = self.app.app.dispatch(_request(
                    "/port/action/",
                    method="POST",
                    body=json.dumps({"id": packet["id"], "action": "stop"}),
                ))

            self.assertEqual(response.status, 200)
            payload = json.loads(response.body.decode("utf-8"))
            self.assertEqual(payload["state"], "filtered")
            self.assertEqual(payload["scan_state"], "stopped")

    def test_runtime_engines_accept_bool_like_strings(self):
        class FakeRuntime:
            mode = "sniffer"

            def __init__(self):
                self.selection = None

            def set_engines(self, selection):
                self.selection = selection
                return {"mode": self.mode, "selection": selection}

        fake = FakeRuntime()
        with patch.object(self.app, "runtime", fake):
            response = self.app.app.dispatch(_request(
                "/api/runtime/",
                method="POST",
                body=json.dumps({"engines": {"sniffer": "false", "honeypot": "1"}}),
            ))

        self.assertEqual(response.status, 200)
        self.assertEqual(fake.selection, {"sniffer": False, "honeypot": True})

    def test_invalid_boolean_values_are_clean_400s(self):
        response = self.app.app.dispatch(_request(
            "/api/runtime/",
            method="POST",
            body=json.dumps({"engines": {"sniffer": "maybe"}}),
        ))
        self.assertEqual(response.status, 400)
        payload = json.loads(response.body.decode("utf-8"))
        self.assertEqual(payload["code"], "invalid_request")
        self.assertIn("engines.sniffer", payload["message"])

    def test_favicon_endpoints_extract_and_serve_captured_http_icons(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            forensic = patch("sniff4hound.store.STORE_RAW_PACKET_BYTES", True)
            forensic.start()
            self.addCleanup(forensic.stop)
            replacement_store, icon = self._store_with_captured_favicon(tmp_dir)
            try:
                with patch.object(self.app, "store", replacement_store):
                    response = self.app.app.dispatch(_request("/favicons/"))

                self.assertEqual(response.status, 200)
                rows = json.loads(response.body.decode("utf-8"))
                self.assertEqual(len(rows), 1)
                self.assertNotIn("_body", rows[0])
                self.assertEqual(rows[0]["mime_type"], "image/x-icon")
                self.assertEqual(rows[0]["size"], len(icon))
                self.assertEqual(rows[0]["ip"], "198.51.100.10")
                self.assertEqual(rows[0]["port"], 80)
                self.assertEqual(rows[0]["icon_url"], "http://example.test/favicon.ico")

                with patch.object(self.app, "store", replacement_store):
                    raw_response = self.app.app.dispatch(_request(
                        "/favicons/raw/",
                        query=f"id={rows[0]['id']}",
                    ))

                self.assertEqual(raw_response.status, 200)
                self.assertEqual(raw_response.body, icon)
                self.assertEqual(raw_response.headers.get("Content-Type"), "image/x-icon")
            finally:
                replacement_store.close()

    def test_favicon_raw_accepts_query_security_code_for_image_tags(self):
        self.auth, self.app = _reload_app_stack(self, "1")
        self.auth._SESSION_TOKEN = "Ab12Cd34"
        self.auth.RATE_LIMITER.reset()
        self.addCleanup(self.auth.RATE_LIMITER.reset)
        with tempfile.TemporaryDirectory() as tmp_dir:
            forensic = patch("sniff4hound.store.STORE_RAW_PACKET_BYTES", True)
            forensic.start()
            self.addCleanup(forensic.stop)
            replacement_store, icon = self._store_with_captured_favicon(tmp_dir)
            try:
                payload_id = replacement_store.list_payloads(limit=1)[0]["id"]
                with patch.object(self.app, "store", replacement_store):
                    response = self.app.app.dispatch(_request(
                        "/favicons/raw/",
                        query=f"id={payload_id}&security_code=Ab12Cd34",
                    ))

                self.assertEqual(response.status, 200)
                self.assertEqual(response.body, icon)
            finally:
                replacement_store.close()


class CaptureIpcTokenTests(unittest.TestCase):
    """A-02: /proc/<pid>/cmdline is world-readable, so the shared IPC secret
    must never travel as a `sudo env KEY=VALUE` / `pkexec env KEY=VALUE`
    argument - including on the whole-process self-elevation re-exec that
    replaced the old capture-child-only relaunch."""

    def test_the_desktop_security_code_is_not_printed_to_stdout(self):
        """The ready line is printed, and the same stdout is the journal when
        the app starts from its .desktop entry. Only the path to a 0600 file
        may travel there - never the code itself."""
        import io
        from contextlib import redirect_stdout

        from sniff4hound import manage

        with tempfile.TemporaryDirectory() as tmp_dir:
            code_path = str(Path(tmp_dir) / "desktop-code.secret")
            buffer = io.StringIO()
            with patch.object(manage, "resolve_desktop_code_path", return_value=code_path), \
                 patch("sniff4hound.auth.REQUIRE_AUTH", True), \
                 patch("sniff4hound.auth.get_security_code", return_value="Ab12Cd34"), \
                 redirect_stdout(buffer):
                manage._emit_desktop_ready("127.0.0.1", 45678)

            printed = buffer.getvalue()
            self.assertIn(manage.DESKTOP_READY_PREFIX, printed)
            self.assertNotIn("Ab12Cd34", printed)

            payload = json.loads(printed.split(manage.DESKTOP_READY_PREFIX, 1)[1])
            self.assertNotIn("security_code", payload)
            self.assertEqual(payload["security_code_file"], code_path)
            self.assertTrue(payload["auth_required"])

            # The file carries the code, and only the operator can read it.
            self.assertEqual(Path(code_path).read_text(encoding="utf-8"), "Ab12Cd34")
            self.assertEqual(os.stat(code_path).st_mode & 0o777, 0o600)

    def test_no_code_file_is_written_when_auth_is_disabled(self):
        import io
        from contextlib import redirect_stdout

        from sniff4hound import manage

        with tempfile.TemporaryDirectory() as tmp_dir:
            code_path = str(Path(tmp_dir) / "desktop-code.secret")
            buffer = io.StringIO()
            with patch.object(manage, "resolve_desktop_code_path", return_value=code_path), \
                 patch("sniff4hound.auth.REQUIRE_AUTH", False), \
                 redirect_stdout(buffer):
                manage._emit_desktop_ready("127.0.0.1", 45678)

            payload = json.loads(buffer.getvalue().split(manage.DESKTOP_READY_PREFIX, 1)[1])
            self.assertEqual(payload["security_code_file"], "")
            self.assertFalse(Path(code_path).exists())

    def test_the_desktop_code_path_is_forwarded_across_the_elevation(self):
        """pkexec drops XDG_RUNTIME_DIR, so the backend's own default lands
        under root's runtime directory once it re-execs - somewhere the
        unprivileged Electron process may not be able to read. The desktop
        app pins the path instead, and that assignment has to survive the
        re-exec or the shell never gets its code."""
        from sniff4hound import manage, settings

        chosen = "/home/operator/.config/Sniff4Hound/desktop-code.secret"
        with patch.dict(os.environ, {"SNIFF4HOUND_DESKTOP_CODE_FILE": chosen}, clear=False):
            reloaded = importlib.reload(settings)
            self.addCleanup(importlib.reload, settings)
            self.assertEqual(reloaded.resolve_desktop_code_path(45678), chosen)

            # The path is not a secret, so unlike the IPC token it may ride
            # the command line - but it must actually be carried over.
            assignments = manage._self_elevate_env_assignments(1000)
        self.assertIn(f"SNIFF4HOUND_DESKTOP_CODE_FILE={chosen}", assignments)
        self.assertNotIn("SNIFF4HOUND_DESKTOP_CODE_FILE", manage.CAPTURE_ENV_DENYLIST)

    def test_the_token_is_not_on_the_self_elevate_command_line(self):
        import sniff4hound.manage as manage

        token = "f" * 64
        with patch.dict(
            os.environ, {"SNIFF4HOUND_IPC_TOKEN": token, "SNIFF4HOUND_IPC_TOKEN_FILE": "/tmp/x.token"}, clear=False
        ):
            command = manage._build_self_elevate_command(1000)
        joined = " ".join(command)
        self.assertNotIn(token, joined)
        self.assertIn("SNIFF4HOUND_IPC_TOKEN_FILE=/tmp/x.token", command)
        self.assertFalse(any(entry.startswith("SNIFF4HOUND_IPC_TOKEN=") for entry in command))

    def test_the_jwt_secret_is_not_forwarded_either(self):
        import sniff4hound.manage as manage

        with patch.dict(os.environ, {"SNIFF4HOUND_JWT_SECRET": "s" * 64}, clear=False):
            command = manage._build_self_elevate_command(1000)
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


class CaptureServiceUnavailableTests(unittest.TestCase):
    """Every engine control runs in the privileged capture process over IPC.
    When that link is down, the failure used to reach the operator as a bare
    500 "Internal Server Error" on the Sniffer/Honeypot toggle - which says
    nothing about which half is broken and looks identical to a crash in the
    API itself."""

    def setUp(self):
        _, self.app = _reload_app_stack(self, "0")

    def _post_runtime(self, body):
        return self.app.app.dispatch(
            _request("/api/runtime/", method="POST", body=json.dumps(body))
        )

    def test_a_dropped_capture_link_answers_503_with_a_reason(self):
        from sniff4hound.ipc import IpcDisconnected

        with patch.object(
            self.app.runtime,
            "start",
            side_effect=IpcDisconnected("Not connected to the capture service"),
        ):
            response = self._post_runtime({"engine": "honeypot", "action": "start"})

        self.assertEqual(response.status, 503)
        payload = json.loads(response.body.decode("utf-8"))
        self.assertEqual(payload["code"], "capture_unavailable")
        self.assertIn("capture service", payload["message"].lower())
        # The underlying reason survives: without it the operator cannot tell
        # a stalled capture process from a rejected token.
        self.assertIn("Not connected to the capture service", payload["message"])

    def test_a_stalled_capture_call_answers_503_not_500(self):
        from sniff4hound.ipc import IpcError

        with patch.object(self.app.runtime, "stop", side_effect=IpcError("IPC call timed out")):
            response = self._post_runtime({"engine": "sniffer", "action": "stop"})

        self.assertEqual(response.status, 503)
        self.assertIn("IPC call timed out", json.loads(response.body.decode("utf-8"))["message"])

    def test_a_validation_error_is_still_a_400(self):
        """The new 503 branch must not swallow the existing ValueError -> 400
        mapping: "mode, engine or interface is required" is a client mistake,
        not an unavailable backend."""
        response = self._post_runtime({})
        self.assertEqual(response.status, 400)
        self.assertEqual(json.loads(response.body.decode("utf-8"))["code"], "invalid_request")


if __name__ == "__main__":
    unittest.main()
