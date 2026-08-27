from __future__ import annotations

import errno
import os
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
import json
import importlib
import io
from contextlib import redirect_stdout, redirect_stderr
from unittest.mock import patch

import sniff4hound
from sniff4hound import versioning
from sniff4hound.store import SniffStore
from wsbuilder import Request, Response


def _close_app_store(module):
    store = getattr(module, "store", None)
    if store is None:
        return
    try:
        store.close()
    except Exception:
        pass


def _reload_auth_stack(require_auth: str = "1"):
    previous = os.environ.get("SNIFF4HOUND_REQUIRE_AUTH")
    os.environ["SNIFF4HOUND_REQUIRE_AUTH"] = require_auth
    try:
        import sniff4hound.auth as auth_module
        import sniff4hound.app as app_module

        _close_app_store(sys.modules.get("sniff4hound.app"))
        auth_module = importlib.reload(auth_module)
        app_module = importlib.reload(app_module)
        return auth_module, app_module
    finally:
        if previous is None:
            os.environ.pop("SNIFF4HOUND_REQUIRE_AUTH", None)
        else:
            os.environ["SNIFF4HOUND_REQUIRE_AUTH"] = previous


def _reload_runtime_stack(require_auth: str = "1"):
    previous = os.environ.get("SNIFF4HOUND_REQUIRE_AUTH")
    os.environ["SNIFF4HOUND_REQUIRE_AUTH"] = require_auth
    try:
        import sniff4hound.settings as settings_module
        import sniff4hound.auth as auth_module
        import sniff4hound.app as app_module

        _close_app_store(sys.modules.get("sniff4hound.app"))
        settings_module = importlib.reload(settings_module)
        auth_module = importlib.reload(auth_module)
        app_module = importlib.reload(app_module)
        return settings_module, auth_module, app_module
    finally:
        if previous is None:
            os.environ.pop("SNIFF4HOUND_REQUIRE_AUTH", None)
        else:
            os.environ["SNIFF4HOUND_REQUIRE_AUTH"] = previous


class _InProcessIpcClient:
    """Test double standing in for `sniff4hound.ipc.IpcClient`: routes
    `RuntimeControllerClient` calls straight to a real `RuntimeController`
    in the same process/thread, skipping the Unix socket entirely, while
    keeping the real `Sniffer`/`HoneypotEngine`/`RuntimeController` logic
    under test - mirrors how the capture process actually dispatches these
    calls (see `capture_service.py`)."""

    def __init__(self, controller):
        self._controller = controller

    def call(self, method, **kwargs):
        return getattr(self._controller, method)(**kwargs)


class _FakeCaptureProcess:
    """Stands in for the `subprocess.Popen` handle `manage.main()` keeps
    for the spawned capture child, so tests can exercise the surrounding
    orchestration without actually spawning/sudo-elevating a process."""

    def __init__(self, wait_effects=None):
        self.returncode = None
        self.terminate_calls = 0
        self.kill_calls = 0
        self._wait_effects = list(wait_effects or [])

    def poll(self):
        return self.returncode

    def terminate(self):
        self.terminate_calls += 1

    def wait(self, timeout=None):
        if self._wait_effects:
            effect = self._wait_effects.pop(0)
            if isinstance(effect, BaseException):
                raise effect
        self.returncode = 0
        return self.returncode

    def kill(self):
        self.kill_calls += 1
        self.returncode = -9


def _install_fake_capture_runtime(app_module, *, capture_auto_start=False):
    from unittest.mock import MagicMock

    from sniff4hound.honeypot import HoneypotEngine
    from sniff4hound.runtime_controller import RuntimeController
    from sniff4hound.sniffer import Sniffer

    sniffer = Sniffer(app_module.store, MagicMock(), interfaces=())
    honeypot = HoneypotEngine(app_module.store, MagicMock())
    controller = RuntimeController(
        store=app_module.store,
        sniffer=sniffer,
        honeypot=honeypot,
        hub=MagicMock(),
        capture_auto_start=capture_auto_start,
    )
    app_module.runtime._ipc_client = _InProcessIpcClient(controller)
    return controller, sniffer, honeypot


class SmokeTests(unittest.TestCase):
    def test_version(self):
        project_root = Path(__file__).resolve().parents[1]
        self.assertEqual(sniff4hound.__version__, versioning.read_project_version(project_root))
        self.assertRegex(sniff4hound.__version__, r"^\d+\.\d+\.\d+$")

    def test_versioning_is_stable_for_same_release_window(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            package_dir = root / "sniff4hound"
            package_dir.mkdir()

            (root / "pyproject.toml").write_text(
                '[project]\nname = "sniff4hound"\nversion = "0.1.0"\n',
                encoding="utf-8",
            )
            (package_dir / "__init__.py").write_text(
                '"""Sniff4Hound package."""\n\n__version__ = "0.1.0"\n',
                encoding="utf-8",
            )
            (root / "README.md").write_text("seed\n", encoding="utf-8")

            subprocess.run(["git", "init"], cwd=root, check=True, capture_output=True, text=True)
            subprocess.run(["git", "config", "user.email", "tests@example.com"], cwd=root, check=True, capture_output=True, text=True)
            subprocess.run(["git", "config", "user.name", "Sniff4Hound Tests"], cwd=root, check=True, capture_output=True, text=True)
            subprocess.run(
                ["git", "add", "pyproject.toml", "sniff4hound/__init__.py", "README.md"],
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(["git", "commit", "-m", "chore: seed release"], cwd=root, check=True, capture_output=True, text=True)
            subprocess.run(["git", "tag", "main-deb-1.1-seed000"], cwd=root, check=True, capture_output=True, text=True)

            (root / "README.md").write_text("seed\npatch\n", encoding="utf-8")
            subprocess.run(["git", "add", "README.md"], cwd=root, check=True, capture_output=True, text=True)
            subprocess.run(["git", "commit", "-m", "fix: keep release numbering stable"], cwd=root, check=True, capture_output=True, text=True)

            first = versioning.resolve_version(root)
            applied = versioning.apply_resolved_version(root)
            second = versioning.resolve_version(root)

            self.assertEqual(first.base_version, "0.1.0")
            self.assertEqual(first.next_version, "0.1.1")
            self.assertEqual(applied.current_version, "0.1.1")
            self.assertEqual(versioning.read_project_version(root), "0.1.1")
            self.assertEqual(second.next_version, "0.1.1")

    def test_store_initializes_and_summaries_work(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "sniff4hound.db"
            store = SniffStore(db_path)
            try:
                counts = store.summary_counts()
                self.assertIn("sessions", counts)
                self.assertIn("packets", counts)
                self.assertIn("unique_hosts", counts)
                self.assertGreaterEqual(counts["rulesets"], 1)
            finally:
                store.close()

    def test_map_snapshot_geolocates_public_hosts_and_keeps_multicast_out_of_public_points(self):
        class FakeGeoResolver:
            def describe_source(self):
                return "country-db-zoneinfo"

            def lookup(self, ip):
                if ip == "72.249.55.101":
                    return {
                        "country_code": "US",
                        "country": "United States",
                        "lat": 39.78373,
                        "lon": -100.445882,
                        "precision": "country",
                    }
                return {}

            def close(self):
                return None

        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "sniff4hound.db"
            store = SniffStore(db_path)
            try:
                store._geoip_resolver = FakeGeoResolver()
                store.register_packet(
                    {
                        "session_id": 1,
                        "proto": "udp",
                        "src_ip": "72.249.55.101",
                        "dst_ip": "224.0.0.251",
                        "src_port": 5353,
                        "dst_port": 5353,
                        "length": 128,
                        "summary": "mDNS sample",
                    }
                )

                snapshot = store.map_snapshot(limit=50)

                self.assertEqual(snapshot["summary"]["public_hosts"], 1)
                self.assertEqual(snapshot["summary"]["private_hosts"], 1)
                self.assertEqual(snapshot["summary"]["unmapped_public_hosts"], 0)
                self.assertEqual(snapshot["geoip"]["source"], "country-db-zoneinfo")
                self.assertEqual(snapshot["geoip"]["resolved_public_hosts"], 1)
                self.assertEqual(snapshot["geoip"]["total_public_hosts"], 1)
                self.assertEqual(len(snapshot["public_points"]), 1)
                self.assertEqual(snapshot["public_points"][0]["ip"], "72.249.55.101")
                self.assertEqual(snapshot["public_points"][0]["country_code"], "US")
                self.assertAlmostEqual(snapshot["public_points"][0]["lat"], 39.78373)
                self.assertAlmostEqual(snapshot["public_points"][0]["lon"], -100.445882)
                self.assertEqual(snapshot["private_hosts"][0]["ip"], "224.0.0.251")
                self.assertEqual(snapshot["private_hosts"][0]["scope"], "multicast")
            finally:
                store.close()

    def test_rulesets_list_survives_tuple_rows(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "sniff4hound.db"
            store = SniffStore(db_path)
            try:
                store._conn.row_factory = None
                rows = store.list_rulesets()
                self.assertGreaterEqual(len(rows), 1)
                self.assertIn("id", rows[0])
                self.assertIn("match", rows[0])
            finally:
                store.close()

    def test_rulesets_list_tolerates_invalid_utf8_description(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "sniff4hound.db"
            store = SniffStore(db_path)
            try:
                now = "2026-06-11T00:00:00.000Z"
                store._conn.execute(
                    """
                    INSERT INTO rulesets
                    (id, name, description, enabled, priority, source, match_json, action_json, created_at, updated_at)
                    VALUES (?, ?, CAST(X'FF7754AABB' AS TEXT), ?, ?, ?, ?, ?, ?, ?)
                    """,
                    ("legacy-bad", "Legacy Bad", 1, 999, "custom", "{}", "{}", now, now),
                )
                store._conn.commit()

                rows = store.list_rulesets()
                row = next(item for item in rows if item["id"] == "legacy-bad")
                self.assertIsInstance(row["description"], str)
                self.assertIn("\ufffd", row["description"])
            finally:
                store.close()

    def test_raw_packet_is_json_safe(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "sniff4hound.db"
            store = SniffStore(db_path)
            try:
                packet = {
                    "session_id": 1,
                    "proto": "tcp",
                    "src_ip": "192.0.2.10",
                    "dst_ip": "198.51.100.20",
                    "src_port": 12345,
                    "dst_port": 80,
                    "payload_text": "GET / HTTP/1.1",
                    "payload_hex": "474554202f20485454502f312e31",
                    "summary": "HTTP request",
                    "raw_packet": b"\x00\x01\x02\x03",
                }
                row = store.register_packet(packet)
                self.assertIsInstance(row["raw_packet"], str)
                json.dumps(store.dashboard_snapshot())
                json.dumps(store.analytics_snapshot())
            finally:
                store.close()

    def test_app_import_uses_configured_database(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "runtime.db"
            previous = os.environ.get("SNIFF4HOUND_DB_PATH")
            os.environ["SNIFF4HOUND_DB_PATH"] = str(db_path)
            try:
                import sniff4hound.settings as settings_module
                import sniff4hound.app as app_module

                importlib.reload(settings_module)
                app_module = importlib.reload(app_module)

                self.assertTrue(hasattr(app_module, "app"))
                self.assertTrue(db_path.exists())
                app_module.store.close()
            finally:
                if previous is None:
                    os.environ.pop("SNIFF4HOUND_DB_PATH", None)
                else:
                    os.environ["SNIFF4HOUND_DB_PATH"] = previous

    def test_frontend_build_is_served(self):
        import sniff4hound.app as app_module

        response = app_module.root(None)

        payload = response.body if isinstance(response.body, (bytes, bytearray)) else response.status
        body = payload.decode("utf-8") if isinstance(payload, (bytes, bytearray)) else str(payload)
        self.assertIn('<div id="app"></div>', body)
        self.assertIn('/assets/index-', body)
        self.assertIn('type="module"', body)

    def test_http_send_guard_suppresses_broken_pipe_noise(self):
        import sniff4hound.app as app_module

        class BrokenPipeConn:
            def sendall(self, _data):
                raise BrokenPipeError(errno.EPIPE, "Broken pipe")

        output = io.StringIO()
        with redirect_stdout(output):
            app_module._guarded_send_http_response(BrokenPipeConn(), Response.text("ok"))

        self.assertEqual(output.getvalue(), "")

    def test_http_send_guard_keeps_non_disconnect_errors_visible(self):
        import sniff4hound.app as app_module

        class ExplodingConn:
            def sendall(self, _data):
                raise RuntimeError("boom")

        output = io.StringIO()
        with redirect_stdout(output):
            app_module._guarded_send_http_response(ExplodingConn(), Response.text("ok"))

        self.assertIn("[http] send error 200: boom", output.getvalue())

    def test_session_token_is_eight_characters(self):
        import sniff4hound.auth as auth_module

        previous_token = auth_module._SESSION_TOKEN
        try:
            auth_module._SESSION_TOKEN = None
            token = auth_module.initialize_session_token()
            self.assertEqual(len(token), auth_module.SESSION_TOKEN_LENGTH)
            self.assertRegex(token, r"^[A-Za-z0-9]{8}$")
        finally:
            auth_module._SESSION_TOKEN = previous_token

    def test_auth_session_endpoint_reports_auth_requirement(self):
        _auth_module, app_module = _reload_auth_stack("1")

        request = Request("GET", "/api/auth/session", "", {}, b"", ("127.0.0.1", 0))
        response = app_module.app.dispatch(request)
        payload = json.loads(response.body.decode("utf-8"))

        self.assertEqual(response.status, 200)
        self.assertTrue(payload["require_auth"])
        self.assertFalse(payload["authenticated"])
        self.assertEqual(payload["message"], "Security code required")
        self.assertEqual(payload["security_code_length"], 8)

    def test_api_routes_return_401_without_token(self):
        _auth_module, app_module = _reload_auth_stack("1")

        request = Request("GET", "/api/hello", "", {}, b"", ("127.0.0.1", 0))
        response = app_module.app.dispatch(request)
        payload = json.loads(response.body.decode("utf-8"))

        self.assertEqual(response.status, 401)
        self.assertEqual(payload["code"], "auth_required")

    def test_api_routes_accept_valid_token(self):
        auth_module, app_module = _reload_auth_stack("1")

        previous_token = auth_module._SESSION_TOKEN
        try:
            auth_module._SESSION_TOKEN = "Ab12Cd34"
            request = Request(
                "GET",
                "/api/hello",
                "",
                {"authorization": "Bearer Ab12Cd34"},
                b"",
                ("127.0.0.1", 0),
            )
            response = app_module.app.dispatch(request)
            payload = json.loads(response.body.decode("utf-8"))
        finally:
            auth_module._SESSION_TOKEN = previous_token

        self.assertEqual(response.status, 200)
        self.assertEqual(payload["status"], "ok")

    def test_api_routes_accept_valid_security_code_header(self):
        auth_module, app_module = _reload_auth_stack("1")

        previous_token = auth_module._SESSION_TOKEN
        try:
            auth_module._SESSION_TOKEN = "Ab12Cd34"
            request = Request(
                "GET",
                "/api/hello",
                "",
                {"x-security-code": "Ab12Cd34"},
                b"",
                ("127.0.0.1", 0),
            )
            response = app_module.app.dispatch(request)
            payload = json.loads(response.body.decode("utf-8"))
        finally:
            auth_module._SESSION_TOKEN = previous_token

        self.assertEqual(response.status, 200)
        self.assertEqual(payload["status"], "ok")

    def test_websocket_auth_accepts_valid_query_token(self):
        auth_module, app_module = _reload_auth_stack("1")

        previous_token = auth_module._SESSION_TOKEN
        try:
            auth_module._SESSION_TOKEN = "Ab12Cd34"
            request = Request(
                "GET",
                "/ws/",
                "security_code=Ab12Cd34",
                {"upgrade": "websocket"},
                b"",
                ("127.0.0.1", 0),
            )
            is_authenticated, payload = app_module._authenticate_request(request, allow_query=True)
        finally:
            auth_module._SESSION_TOKEN = previous_token

        self.assertTrue(is_authenticated)
        self.assertIsNotNone(payload)

    def test_api_routes_reject_query_string_security_code(self):
        auth_module, app_module = _reload_auth_stack("1")

        previous_token = auth_module._SESSION_TOKEN
        try:
            auth_module._SESSION_TOKEN = "Ab12Cd34"
            request = Request(
                "GET",
                "/api/hello",
                "security_code=Ab12Cd34",
                {},
                b"",
                ("127.0.0.1", 0),
            )
            response = app_module.app.dispatch(request)
            payload = json.loads(response.body.decode("utf-8"))
        finally:
            auth_module._SESSION_TOKEN = previous_token

        self.assertEqual(response.status, 401)
        self.assertEqual(payload["code"], "auth_required")

    def test_deb_launcher_resolves_vendor_package_outside_repo(self):
        launcher_source = Path(__file__).resolve().parents[1] / "scripts" / "deb_launcher.py"

        with tempfile.TemporaryDirectory() as tmp_dir:
            install_root = Path(tmp_dir)
            vendor_package = install_root / "vendor" / "sniff4hound"
            vendor_package.mkdir(parents=True)

            (install_root / "launcher.py").write_text(launcher_source.read_text(encoding="utf-8"), encoding="utf-8")
            (vendor_package / "__init__.py").write_text('SENTINEL = "ok"\n', encoding="utf-8")
            (vendor_package / "manage.py").write_text(
                'from . import SENTINEL\nprint(SENTINEL)\n',
                encoding="utf-8",
            )

            response = subprocess.run(
                [sys.executable, str(install_root / "launcher.py")],
                cwd="/tmp",
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertEqual(response.returncode, 0, response.stderr)
        self.assertEqual(response.stdout.strip(), "ok")

    def test_runtime_api_exposes_and_updates_sniffer_interfaces(self):
        _auth_module, app_module = _reload_auth_stack("0")
        self.addCleanup(app_module.store.close)
        _controller, sniffer, _honeypot = _install_fake_capture_runtime(app_module)

        with patch.object(sniffer, "list_available_interfaces", return_value=["eth0", "wlan0"]):
            app_module.runtime.set_sniffer_interfaces([])

            get_request = Request("GET", "/api/runtime/", "", {}, b"", ("127.0.0.1", 0))
            get_response = app_module.app.dispatch(get_request)
            get_payload = json.loads(get_response.body.decode("utf-8"))

            self.assertEqual(get_response.status, 200)
            self.assertEqual(get_payload["sniffer"]["available_interfaces"], ["eth0", "wlan0"])
            self.assertEqual(get_payload["sniffer"]["selected_interface"], "")
            self.assertEqual(get_payload["sniffer"]["selected_interfaces"], [])

            post_request = Request(
                "POST",
                "/api/runtime/",
                "",
                {"content-type": "application/json"},
                json.dumps({"interfaces": ["wlan0", "eth0", "wlan0"]}).encode("utf-8"),
                ("127.0.0.1", 0),
            )
            post_response = app_module.app.dispatch(post_request)
            post_payload = json.loads(post_response.body.decode("utf-8"))

            self.assertEqual(post_response.status, 200)
            self.assertEqual(post_payload["sniffer"]["selected_interface"], "")
            self.assertEqual(post_payload["sniffer"]["selected_interfaces"], ["wlan0", "eth0"])

    def test_monitors_toggle_endpoint_disables_a_builtin_monitor(self):
        _auth_module, app_module = _reload_auth_stack("0")
        self.addCleanup(app_module.store.close)

        request = Request(
            "POST",
            "/api/monitors/toggle",
            "",
            {"content-type": "application/json"},
            json.dumps({"id": "builtin-credentials", "enabled": False}).encode("utf-8"),
            ("127.0.0.1", 0),
        )
        response = app_module.app.dispatch(request)
        payload = json.loads(response.body.decode("utf-8"))

        self.assertEqual(response.status, 200)
        self.assertEqual(payload["id"], "builtin-credentials")
        self.assertFalse(payload["enabled"])

    def test_monitors_toggle_endpoint_requires_id_and_enabled(self):
        # A plain `raise ValueError(...)` from a route handler is caught by
        # the auth guard's `except ValueError` arm and answered as a 400
        # carrying the validation message, rather than escaping to
        # wsbuilder's dispatch() and becoming an opaque 500. This is the
        # convention for every "<param> is required" check in the handlers.
        _auth_module, app_module = _reload_auth_stack("0")
        self.addCleanup(app_module.store.close)

        missing_id = Request(
            "POST",
            "/api/monitors/toggle",
            "",
            {"content-type": "application/json"},
            json.dumps({"enabled": True}).encode("utf-8"),
            ("127.0.0.1", 0),
        )
        self.assertEqual(app_module.app.dispatch(missing_id).status, 400)

        missing_enabled = Request(
            "POST",
            "/api/monitors/toggle",
            "",
            {"content-type": "application/json"},
            json.dumps({"id": "builtin-credentials"}).encode("utf-8"),
            ("127.0.0.1", 0),
        )
        self.assertEqual(app_module.app.dispatch(missing_enabled).status, 400)

    def test_runtime_api_supports_start_and_stop_actions(self):
        _auth_module, app_module = _reload_auth_stack("0")
        self.addCleanup(app_module.store.close)

        with patch.object(app_module.runtime, "set_mode", return_value={"mode": "honeypot"}) as set_mode_mock, patch.object(
            app_module.runtime, "start", return_value={"mode": "honeypot", "active": {"running": True}}
        ) as start_mock:
            start_request = Request(
                "POST",
                "/api/runtime/",
                "",
                {"content-type": "application/json"},
                json.dumps({"mode": "honeypot", "action": "start"}).encode("utf-8"),
                ("127.0.0.1", 0),
            )
            start_response = app_module.app.dispatch(start_request)
            start_payload = json.loads(start_response.body.decode("utf-8"))

            self.assertEqual(start_response.status, 200)
            self.assertEqual(start_payload["mode"], "honeypot")
            set_mode_mock.assert_called_once_with("honeypot")
            start_mock.assert_called_once()

        with patch.object(app_module.runtime, "stop", return_value={"mode": "sniffer", "active": {"running": False}}) as stop_mock:
            stop_request = Request(
                "POST",
                "/api/runtime/",
                "",
                {"content-type": "application/json"},
                json.dumps({"mode": "sniffer", "action": "stop"}).encode("utf-8"),
                ("127.0.0.1", 0),
            )
            stop_response = app_module.app.dispatch(stop_request)
            stop_payload = json.loads(stop_response.body.decode("utf-8"))

            self.assertEqual(stop_response.status, 200)
            self.assertFalse(stop_payload["active"]["running"])
            stop_mock.assert_called_once()

    def test_runtime_api_start_explicitly_starts_engine_when_auto_start_is_disabled(self):
        previous_auto_start = os.environ.get("SNIFF4HOUND_CAPTURE_AUTO_START")
        os.environ["SNIFF4HOUND_CAPTURE_AUTO_START"] = "0"
        try:
            _settings_module, _auth_module, app_module = _reload_runtime_stack("0")
            self.addCleanup(app_module.store.close)
            _controller, sniffer, _honeypot = _install_fake_capture_runtime(
                app_module, capture_auto_start=app_module.CAPTURE_AUTO_START
            )

            sniffer_state = {"running": False}

            def fake_sniffer_snapshot():
                return {
                    "running": bool(sniffer_state["running"]),
                    "capture_state": "running" if sniffer_state["running"] else "idle",
                    "interfaces": ["eth0"],
                    "available_interfaces": ["eth0"],
                    "selected_interfaces": [],
                    "selected_interface": "",
                    "errors": {},
                    "packets_seen": 0,
                    "packets_total_bytes": 0,
                    "started_at": "2026-08-09T16:05:00Z" if sniffer_state["running"] else "",
                    "last_packet_at": "",
                    "active_threads": 1 if sniffer_state["running"] else 0,
                }

            def fake_sniffer_start():
                sniffer_state["running"] = True
                return fake_sniffer_snapshot()

            with patch.object(sniffer, "snapshot", side_effect=fake_sniffer_snapshot), patch.object(
                sniffer, "start", side_effect=fake_sniffer_start
            ) as start_mock:
                start_request = Request(
                    "POST",
                    "/api/runtime/",
                    "",
                    {"content-type": "application/json"},
                    json.dumps({"mode": "sniffer", "action": "start"}).encode("utf-8"),
                    ("127.0.0.1", 0),
                )
                start_response = app_module.app.dispatch(start_request)
                start_payload = json.loads(start_response.body.decode("utf-8"))

            self.assertEqual(start_response.status, 200)
            self.assertEqual(start_payload["mode"], "sniffer")
            self.assertTrue(start_payload["active"]["running"])
            self.assertEqual(start_payload["active"]["capture_state"], "running")
            start_mock.assert_called_once()
        finally:
            if previous_auto_start is None:
                os.environ.pop("SNIFF4HOUND_CAPTURE_AUTO_START", None)
            else:
                os.environ["SNIFF4HOUND_CAPTURE_AUTO_START"] = previous_auto_start

    def test_websocket_route_enables_keepalive(self):
        _auth_module, app_module = _reload_auth_stack("0")
        self.addCleanup(app_module.store.close)

        route = app_module.app.ws_routes["/ws/"]

        self.assertGreater(route["keepalive_interval"], 0.0)
        self.assertGreater(route["pong_timeout"], 0.0)
        self.assertEqual(route["ping_payload"], b"sniff4hound")

    def test_manage_candidate_ports_scan_requested_block(self):
        import sniff4hound.manage as manage_module

        candidates = manage_module._candidate_ports(45678)

        self.assertEqual(
            candidates[:10],
            (45678, 45670, 45671, 45672, 45673, 45674, 45675, 45676, 45677, 45679),
        )
        self.assertEqual(len(candidates), manage_module.FALLBACK_PORT_SCAN_SIZE)
        self.assertIn(45769, candidates)

    def test_settings_default_port_ignores_generic_port_env(self):
        import sniff4hound.settings as settings_module

        with patch.dict(os.environ, {"PORT": "12345"}, clear=False):
            os.environ.pop("SNIFF4HOUND_PORT", None)
            settings_module = importlib.reload(settings_module)
            self.assertEqual(settings_module.PORT, 45678)

        with patch.dict(os.environ, {"SNIFF4HOUND_PORT": "45679", "PORT": "12345"}, clear=False):
            settings_module = importlib.reload(settings_module)
            self.assertEqual(settings_module.PORT, 45679)

        importlib.reload(settings_module)

    def test_relative_db_path_resolves_under_the_data_dir(self):
        # A relative SNIFF4HOUND_DB_PATH used to resolve against the process
        # cwd, so the same install grew a separate database in every
        # directory it was ever launched from - that is how a 46 MB
        # Sniff4Hound.db ended up inside frontend/.
        import sniff4hound.settings as settings_module

        with tempfile.TemporaryDirectory() as tmp_dir:
            with patch.dict(
                os.environ,
                {"SNIFF4HOUND_DATA_DIR": tmp_dir, "SNIFF4HOUND_DB_PATH": "Sniff4Hound.db"},
                clear=False,
            ):
                settings_module = importlib.reload(settings_module)
                self.assertEqual(settings_module.DB_PATH, str(Path(tmp_dir) / "Sniff4Hound.db"))

            absolute = str(Path(tmp_dir) / "elsewhere" / "custom.db")
            with patch.dict(
                os.environ,
                {"SNIFF4HOUND_DATA_DIR": tmp_dir, "SNIFF4HOUND_DB_PATH": absolute},
                clear=False,
            ):
                settings_module = importlib.reload(settings_module)
                self.assertEqual(settings_module.DB_PATH, absolute)

        importlib.reload(settings_module)

    def test_manage_main_creates_web_store_before_spawning_capture_child(self):
        # Both processes open the same SQLite file; whichever one creates
        # it first owns it on disk, and a root-owned DB is unwritable by
        # the (unprivileged) web process afterwards. `from .app import ...`
        # (which constructs sniff4hound.app's SniffStore as this process's
        # own user) must therefore run before `_spawn_capture_child()` -
        # regression test for the exact ordering, since by the time any
        # test runs `sniff4hound.app` is already cached in sys.modules and a
        # functional/mock-based check can't observe the real race.
        import inspect

        import sniff4hound.manage as manage_module

        source = inspect.getsource(manage_module.main)
        import_index = source.index("from .app import")
        spawn_index = source.index("_spawn_capture_child(")
        self.assertLess(
            import_index,
            spawn_index,
            "sniff4hound.app must be imported (constructing its SniffStore) "
            "before the privileged capture child is spawned",
        )

    def test_manage_capture_child_does_not_inherit_the_console_stdin(self):
        # Since sudo 1.9.14 `use_pty` is the default, so sudo puts the capture
        # child on its own pty and relays our terminal into it for the whole
        # session. With stdin inherited, sudo's relay and the console's
        # input() are two readers racing on one tty and keystrokes go to
        # whichever reads first - typing "/help" came out as "[note] p".
        import sniff4hound.manage as manage_module

        with patch.object(manage_module.shutil, "which", return_value="/usr/bin/sudo"), patch.object(
            manage_module, "_open_capture_log", return_value=None
        ), patch.object(manage_module.subprocess, "Popen") as popen:
            manage_module._spawn_capture_child("/tmp/x.sock", "tok")

        self.assertEqual(popen.call_args.kwargs.get("stdin"), subprocess.DEVNULL)

    def test_manage_capture_relaunch_command_forwards_pythonpath(self):
        # The Debian package only makes `sniff4hound` importable via
        # PYTHONPATH pointing at its vendored copy (scripts/deb_wrapper.sh) -
        # `sudo env ...` does not inherit it on its own, so it must be
        # forwarded explicitly or the privileged child can't import the
        # package at all.
        import sniff4hound.manage as manage_module

        with patch.dict(os.environ, {"PYTHONPATH": "/usr/lib/sniff4hound/vendor"}, clear=False):
            command = manage_module._build_capture_relaunch_command("/tmp/x.sock", "tok", 1000)
        self.assertIn("PYTHONPATH=/usr/lib/sniff4hound/vendor", command)

        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("PYTHONPATH", None)
            command = manage_module._build_capture_relaunch_command("/tmp/x.sock", "tok", 1000)
        self.assertFalse(any(entry.startswith("PYTHONPATH=") for entry in command))

    def test_manage_capture_relaunch_command_forwards_data_dir(self):
        # Every SNIFF4HOUND_* var present in os.environ is forwarded verbatim
        # to the sudo-relaunched capture child. Pin this for
        # SNIFF4HOUND_DATA_DIR specifically (main() sets it via
        # os.environ.setdefault() before spawning, see the test below) - a
        # future refactor to an allowlist could easily forget it and
        # silently reintroduce the two-databases bug this fixes.
        import sniff4hound.manage as manage_module

        with patch.dict(
            os.environ, {"SNIFF4HOUND_DATA_DIR": "/home/example/.local/share/sniff4hound"}, clear=False
        ):
            command = manage_module._build_capture_relaunch_command("/tmp/x.sock", "tok", 1000)
        self.assertIn("SNIFF4HOUND_DATA_DIR=/home/example/.local/share/sniff4hound", command)

    def test_manage_main_pins_data_dir_before_spawning_capture_child(self):
        # Regression test: the capture child is relaunched via `sudo`,
        # which resets HOME to root's home by default. DATA_DIR (and so
        # DB_PATH, honeypot log/db/certs - see settings.py/honeypot.py)
        # defaults to Path.home()/.local/share/sniff4hound, so without
        # pinning SNIFF4HOUND_DATA_DIR explicitly before spawning, the
        # unprivileged web process and the privileged capture child would
        # silently compute two different paths - captured traffic would be
        # persisted somewhere the web process never reads from, and every
        # table/catalog view would stay empty despite live capture (and
        # notifications) working fine over the IPC/WebSocket path.
        import sniff4hound.app as app_module
        import sniff4hound.manage as manage_module
        from sniff4hound.settings import DATA_DIR

        fake_process = _FakeCaptureProcess()
        observed = {}

        def _capture_spawn(ipc_socket, ipc_token):
            observed["data_dir"] = os.environ.get("SNIFF4HOUND_DATA_DIR")
            return fake_process

        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SNIFF4HOUND_DATA_DIR", None)
            with patch.object(manage_module, "HOST", "127.0.0.1"), patch.object(
                manage_module, "PORT", 45678
            ), patch.object(
                manage_module, "_select_listen_port", return_value=45678
            ), patch.object(
                manage_module, "_spawn_capture_child", side_effect=_capture_spawn
            ), patch.object(
                manage_module, "_stop_capture_child"
            ), patch.object(
                manage_module, "_print_startup_banner"
            ), patch.object(
                app_module, "connect_capture_service", return_value=True
            ), patch.object(
                app_module, "bootstrap_capture"
            ), patch.object(
                app_module, "shutdown_capture"
            ), patch.object(
                app_module.app, "run", side_effect=KeyboardInterrupt
            ):
                manage_module.main()

        self.assertEqual(observed.get("data_dir"), str(DATA_DIR))

    def test_manage_refuses_to_spawn_capture_child_without_sudo(self):
        # manage.py (the web process) never elevates itself anymore - it
        # only needs `sudo` to spawn the privileged capture child. Actual
        # "capture always requires root, no bypass" policy now lives in
        # capture_service.py (see tests/test_capture_service.py).
        import sniff4hound.manage as manage_module

        output = io.StringIO()
        with patch.object(manage_module.shutil, "which", return_value=None), redirect_stderr(output):
            result = manage_module._spawn_capture_child("/tmp/sniff4hound-test.sock", "test-token")

        self.assertIsNone(result)
        self.assertIn("requires root", output.getvalue())

    def test_manage_restore_tty_attrs_undoes_raw_mode_left_by_sudo_prompt(self):
        # sudo's password/fingerprint (PAM) prompt for the capture child
        # commonly leaves the shared controlling terminal without ONLCR -
        # "\n" then stops returning the cursor to column 0, so every
        # subsequent printed line drifts further right than the last,
        # staircasing the startup banner. Exercise the actual termios
        # syscalls against a real pty to prove the fix undoes exactly that.
        import pty
        import termios as termios_module

        import sniff4hound.manage as manage_module

        if manage_module.termios is None:
            self.skipTest("termios is not available on this platform")

        master_fd, slave_fd = pty.openpty()
        self.addCleanup(os.close, master_fd)
        self.addCleanup(os.close, slave_fd)

        class _FakeStdin:
            def isatty(self):
                return True

            def fileno(self):
                return slave_fd

        with patch.object(manage_module.sys, "stdin", _FakeStdin()):
            original = manage_module._snapshot_tty_attrs()
            self.assertIsNotNone(original)

            mutated = termios_module.tcgetattr(slave_fd)
            mutated[1] &= ~termios_module.ONLCR  # oflag: disable NL->CRNL
            termios_module.tcsetattr(slave_fd, termios_module.TCSANOW, mutated)
            self.assertFalse(termios_module.tcgetattr(slave_fd)[1] & termios_module.ONLCR)

            manage_module._restore_tty_attrs(original)

        restored = termios_module.tcgetattr(slave_fd)
        self.assertTrue(restored[1] & termios_module.ONLCR)
        self.assertEqual(restored, original)

    def test_manage_spawn_capture_child_does_not_inherit_the_terminal(self):
        # The capture child's stdout/stderr must never be the same terminal
        # this process writes its own banner/console to - two processes
        # line-buffer-flushing to the same tty concurrently interleaves
        # their output into a garbled/staircased mess.
        import sniff4hound.manage as manage_module

        with tempfile.TemporaryDirectory() as tmp_dir:
            ipc_socket = str(Path(tmp_dir) / "run" / "capture-45678.sock")
            captured_kwargs = {}

            def _fake_popen(command, **kwargs):
                captured_kwargs.update(kwargs)
                return _FakeCaptureProcess()

            with patch.object(manage_module.shutil, "which", return_value="/usr/bin/sudo"), patch.object(
                manage_module.subprocess, "Popen", side_effect=_fake_popen
            ):
                result = manage_module._spawn_capture_child(ipc_socket, "test-token")

            self.assertIsNotNone(result)
            self.assertIsNot(captured_kwargs.get("stdout"), None)
            self.assertIsNot(captured_kwargs.get("stderr"), None)
            self.assertTrue(manage_module._capture_log_path(ipc_socket).parent.is_dir())
            self.assertTrue(manage_module._capture_log_path(ipc_socket).exists())

    def test_manage_stop_capture_child_survives_normal_termination(self):
        import sniff4hound.manage as manage_module

        process = _FakeCaptureProcess()
        manage_module._stop_capture_child(process)

        self.assertEqual(process.terminate_calls, 1)
        self.assertEqual(process.kill_calls, 0)

    def test_manage_stop_capture_child_escalates_to_kill_on_timeout(self):
        import sniff4hound.manage as manage_module

        process = _FakeCaptureProcess(wait_effects=[subprocess.TimeoutExpired(cmd="sudo", timeout=5)])
        manage_module._stop_capture_child(process)

        self.assertEqual(process.terminate_calls, 1)
        self.assertEqual(process.kill_calls, 1)

    def test_manage_stop_capture_child_survives_repeated_ctrl_c_and_still_kills(self):
        # Real-world trigger: `sudo` is blocked on a fingerprint/password
        # prompt for the capture child, and the user hits Ctrl+C again
        # while manage.py is waiting for it to exit during shutdown. A
        # second KeyboardInterrupt here must not escape as an uncaught
        # traceback, and the child must still end up killed rather than
        # left running as an orphaned privileged process.
        process = _FakeCaptureProcess(wait_effects=[KeyboardInterrupt(), KeyboardInterrupt()])
        import sniff4hound.manage as manage_module

        output = io.StringIO()
        with redirect_stderr(output):
            manage_module._stop_capture_child(process)  # must not raise

        self.assertEqual(process.terminate_calls, 1)
        self.assertEqual(process.kill_calls, 1)
        self.assertIn("Still stopping", output.getvalue())

    def test_manage_console_autocomplete_and_aliases(self):
        import sniff4hound.manage as manage_module

        self.assertEqual(manage_module._resolve_console_command("/stats"), "/status")
        self.assertIn(
            "/stats",
            manage_module._build_console_completion_candidates("/st", "/st", 0),
        )
        self.assertEqual(
            manage_module._build_console_completion_candidates("/mode s", "s", len("/mode ")),
            ["sniffer"],
        )

    def test_manage_console_alias_executes_status_command(self):
        import sniff4hound.manage as manage_module

        class DummyRuntime:
            def snapshot(self):
                return {
                    "mode": "sniffer",
                    "active": {
                        "running": True,
                        "packets_seen": 12,
                    },
                }

        class DummyHub:
            def list_clients(self):
                return [{"id": 1}, {"id": 2}]

        output = io.StringIO()
        with redirect_stdout(output):
            manage_module._handle_console_line(
                "/stats",
                host="127.0.0.1",
                port=45678,
                runtime=DummyRuntime(),
                hub=DummyHub(),
                append_chat_message=lambda *args, **kwargs: {},
            )

        self.assertIn("[status] mode=sniffer", output.getvalue())
        self.assertIn("ws_clients=2", output.getvalue())

    def test_manage_quit_command_requests_single_shutdown(self):
        import sniff4hound.manage as manage_module

        # /quit now lives in sniff4hound.console, so that is where the shutdown
        # call has to be intercepted: patching the manage-level name would let
        # the real one through and actually SIGINT the test runner.
        import sniff4hound.console as console_module

        output = io.StringIO()
        with patch.object(console_module, "request_process_shutdown", return_value=True) as shutdown_mock, redirect_stdout(output):
            manage_module._handle_console_line(
                "/quit",
                host="127.0.0.1",
                port=45678,
                runtime=object(),
                hub=object(),
                append_chat_message=lambda *args, **kwargs: {},
            )

        shutdown_mock.assert_called_once_with()
        self.assertIn("Stopping Sniff4Hound", output.getvalue())

    def test_manage_stop_interactive_console_closes_input_and_joins_thread(self):
        import sniff4hound.manage as manage_module

        class DummyThread:
            def __init__(self):
                self.join_called = False

            def is_alive(self):
                return True

            def join(self, timeout=None):
                self.join_called = True
                self.timeout = timeout

        class DummyInput:
            def __init__(self):
                self.closed = False

            def close(self):
                self.closed = True

        thread = DummyThread()
        input_stream = DummyInput()

        manage_module._stop_interactive_console(thread, input_stream=input_stream, join_timeout=0.25)

        self.assertTrue(input_stream.closed)
        self.assertTrue(thread.join_called)
        self.assertEqual(thread.timeout, 0.25)

    def test_manage_stop_interactive_console_ignores_keyboard_interrupt_during_join(self):
        import sniff4hound.manage as manage_module

        class DummyThread:
            def is_alive(self):
                return True

            def join(self, timeout=None):
                raise KeyboardInterrupt

        class DummyInput:
            closed = False

            def close(self):
                self.closed = True

        input_stream = DummyInput()
        manage_module._stop_interactive_console(DummyThread(), input_stream=input_stream, join_timeout=0.25)
        self.assertTrue(input_stream.closed)

    def test_manage_startup_banner_uses_hound_icon_and_link_line(self):
        import sniff4hound.manage as manage_module
        import sniff4hound.auth as auth_module

        output = io.StringIO()
        with patch.object(auth_module, "get_session_token", return_value="Ab12Cd34"), patch.object(
            auth_module, "REQUIRE_AUTH", True
        ), redirect_stdout(output):
            manage_module._print_startup_banner("127.0.0.1", 45678)

        banner = output.getvalue()
        self.assertIn(f"🐕 SNIFF4HOUND v{sniff4hound.__version__}", banner)
        self.assertIn("Link: http://127.0.0.1:45678/", banner)
        self.assertNotIn("Dashboard:", banner)
        self.assertNotIn("URL:", banner)

    def test_manage_selects_fallback_port_when_requested_port_is_occupied(self):
        import sniff4hound.manage as manage_module

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            host, port = sock.getsockname()
            selected = manage_module._select_listen_port(host, port)

        self.assertIsNotNone(selected)
        self.assertIn(selected, manage_module._candidate_ports(port))
        self.assertNotEqual(selected, port)

    def test_manage_main_uses_fallback_port(self):
        import sniff4hound.app as app_module
        import sniff4hound.manage as manage_module

        fake_process = _FakeCaptureProcess()

        with patch.object(manage_module, "HOST", "127.0.0.1"), patch.object(
            manage_module, "PORT", 45678
        ), patch.object(
            manage_module, "_select_listen_port", return_value=45670
        ), patch.object(
            manage_module, "_spawn_capture_child", return_value=fake_process
        ) as spawn_mock, patch.object(
            manage_module, "_stop_capture_child"
        ) as stop_mock, patch.object(
            manage_module, "_print_port_fallback_notice"
        ) as notice_mock, patch.object(
            manage_module, "_print_startup_banner"
        ) as banner_mock, patch.object(
            app_module, "connect_capture_service", return_value=True
        ), patch.object(
            app_module, "bootstrap_capture"
        ), patch.object(
            app_module, "shutdown_capture"
        ), patch.object(
            app_module.app, "run", side_effect=KeyboardInterrupt
        ) as run_mock:
            exit_code = manage_module.main()

        self.assertEqual(exit_code, 0)
        spawn_mock.assert_called_once()
        stop_mock.assert_called_once_with(fake_process)
        notice_mock.assert_called_once_with(45678, 45670)
        banner_mock.assert_called_once_with("127.0.0.1", 45670)
        run_mock.assert_called_once_with("127.0.0.1", 45670)

    def test_manage_exits_cleanly_when_no_fallback_port_is_available(self):
        import sniff4hound.manage as manage_module

        with patch.object(manage_module, "HOST", "127.0.0.1"), patch.object(
            manage_module, "PORT", 45678
        ), patch.object(
            manage_module, "_select_listen_port", return_value=None
        ), patch.object(
            manage_module, "_print_address_in_use_error"
        ) as error_mock, patch.object(
            manage_module, "_print_startup_banner"
        ) as banner_mock:
            exit_code = manage_module.main()

        self.assertEqual(exit_code, 1)
        error_mock.assert_called_once_with("127.0.0.1", 45678)
        banner_mock.assert_not_called()

    def test_app_shutdown_endpoint_requests_graceful_process_shutdown(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "traffic.db"
            previous_db = os.environ.get("SNIFF4HOUND_DB_PATH")
            previous_auth = os.environ.get("SNIFF4HOUND_REQUIRE_AUTH")
            os.environ["SNIFF4HOUND_DB_PATH"] = str(db_path)
            os.environ["SNIFF4HOUND_REQUIRE_AUTH"] = "0"
            try:
                _settings_module, _auth_module, app_module = _reload_runtime_stack("0")

                request = Request(
                    "POST",
                    "/api/app/shutdown",
                    "",
                    {"content-type": "application/json"},
                    json.dumps({"delay": 0.35}).encode("utf-8"),
                    ("127.0.0.1", 0),
                )

                with patch.object(app_module, "request_process_shutdown", return_value=True) as shutdown_mock:
                    response = app_module.app.dispatch(request)
                payload = json.loads(response.body.decode("utf-8"))

                self.assertEqual(response.status, 200)
                self.assertTrue(payload["shutdown_requested"])
                self.assertTrue(payload["shutdown_pending"])
                self.assertEqual(payload["delay_seconds"], 0.35)
                shutdown_mock.assert_called_once_with(delay=0.35)
                app_module.store.close()
            finally:
                if previous_db is None:
                    os.environ.pop("SNIFF4HOUND_DB_PATH", None)
                else:
                    os.environ["SNIFF4HOUND_DB_PATH"] = previous_db
                if previous_auth is None:
                    os.environ.pop("SNIFF4HOUND_REQUIRE_AUTH", None)
                else:
                    os.environ["SNIFF4HOUND_REQUIRE_AUTH"] = previous_auth

    def test_static_file_response_uses_body(self):
        import sniff4hound.app as app_module

        with tempfile.TemporaryDirectory() as tmp_dir:
            file_path = Path(tmp_dir) / "asset.txt"
            file_path.write_text("static payload", encoding="utf-8")

            response = app_module._static_file_response(file_path)
            self.assertIsNotNone(response)
            self.assertEqual(response.status, 200)
            self.assertEqual(response.body, b"static payload")
            self.assertEqual(response.headers.get("Content-Type"), "text/plain")

    def test_frontend_dist_resolution_prefers_packaged_assets(self):
        import sniff4hound.app as app_module

        with tempfile.TemporaryDirectory() as tmp_dir:
            base = Path(tmp_dir)
            packaged_dist = base / "site-packages" / "sniff4hound" / "_frontend_dist"
            packaged_dist.mkdir(parents=True)
            (packaged_dist / "index.html").write_text("packaged build", encoding="utf-8")

            previous_source = app_module.SOURCE_FRONTEND_DIST_DIR
            previous_package = app_module.PACKAGE_FRONTEND_DIST_DIR
            previous_override = os.environ.pop("SNIFF4HOUND_FRONTEND_DIST", None)
            try:
                app_module.SOURCE_FRONTEND_DIST_DIR = base / "missing" / "frontend" / "dist"
                app_module.PACKAGE_FRONTEND_DIST_DIR = packaged_dist

                resolved = app_module._resolve_frontend_dist_dir()
                self.assertEqual(resolved, packaged_dist)
            finally:
                app_module.SOURCE_FRONTEND_DIST_DIR = previous_source
                app_module.PACKAGE_FRONTEND_DIST_DIR = previous_package
                if previous_override is not None:
                    os.environ["SNIFF4HOUND_FRONTEND_DIST"] = previous_override

    def test_ports_endpoint_exposes_rich_packet_context(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "traffic.db"
            previous_db = os.environ.get("SNIFF4HOUND_DB_PATH")
            previous_auth = os.environ.get("SNIFF4HOUND_REQUIRE_AUTH")
            os.environ["SNIFF4HOUND_DB_PATH"] = str(db_path)
            os.environ["SNIFF4HOUND_REQUIRE_AUTH"] = "0"
            try:
                _settings_module, _auth_module, app_module = _reload_runtime_stack("0")

                app_module.store.register_packet(
                    {
                        "session_id": 7,
                        "interface": "eth0",
                        "direction": "outbound",
                        "proto": "tcp",
                        "src_ip": "192.0.2.10",
                        "dst_ip": "198.51.100.20",
                        "src_port": 54321,
                        "dst_port": 443,
                        "summary": "TLS handshake",
                        "payload_text": "GET / HTTP/1.1",
                        "banner_text": "HTTP request",
                        "tags": [{"key": "service", "value": "https"}],
                        "rule_hits": [{"rule_id": "tls", "label": "TLS"}],
                    }
                )

                request = Request("GET", "/ports/", "proto=tcp&mode=sniffer", {}, b"", ("127.0.0.1", 0))
                response = app_module.app.dispatch(request)
                payload = json.loads(response.body.decode("utf-8"))

                self.assertEqual(response.status, 200)
                self.assertEqual(len(payload), 1)
                self.assertEqual(payload[0]["interface"], "eth0")
                self.assertEqual(payload[0]["src_ip"], "192.0.2.10")
                self.assertEqual(payload[0]["dst_ip"], "198.51.100.20")
                self.assertEqual(payload[0]["src_port"], 54321)
                self.assertEqual(payload[0]["dst_port"], 443)
                self.assertEqual(payload[0]["payload_text"], "GET / HTTP/1.1")
                self.assertEqual(payload[0]["banner_text"], "HTTP request")
                self.assertEqual(payload[0]["tags"][0]["value"], "https")
                self.assertEqual(payload[0]["rule_hits"][0]["label"], "TLS")
                app_module.store.close()
            finally:
                if previous_db is None:
                    os.environ.pop("SNIFF4HOUND_DB_PATH", None)
                else:
                    os.environ["SNIFF4HOUND_DB_PATH"] = previous_db
                if previous_auth is None:
                    os.environ.pop("SNIFF4HOUND_REQUIRE_AUTH", None)
                else:
                    os.environ["SNIFF4HOUND_REQUIRE_AUTH"] = previous_auth

    def test_soc_analysis_endpoint_returns_iterative_triage(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "traffic.db"
            previous_db = os.environ.get("SNIFF4HOUND_DB_PATH")
            previous_auth = os.environ.get("SNIFF4HOUND_REQUIRE_AUTH")
            os.environ["SNIFF4HOUND_DB_PATH"] = str(db_path)
            os.environ["SNIFF4HOUND_REQUIRE_AUTH"] = "0"
            try:
                _settings_module, _auth_module, app_module = _reload_runtime_stack("0")

                app_module.store.register_packet(
                    {
                        "session_id": 21,
                        "interface": "eth0",
                        "direction": "unknown",
                        "proto": "tcp",
                        "src_ip": "127.0.0.1",
                        "dst_ip": "127.0.0.1",
                        "src_port": 45670,
                        "dst_port": 45670,
                        "summary": "Loopback packet",
                        "payload_text": "{\"type\":\"telemetry\",\"packet\":1}",
                        "banner_text": "",
                        "tags": [{"key": "role", "value": "loopback"}],
                    }
                )
                app_module.store.register_packet(
                    {
                        "session_id": 22,
                        "interface": "eth0",
                        "direction": "outbound",
                        "proto": "udp",
                        "src_ip": "72.249.55.101",
                        "dst_ip": "192.168.88.250",
                        "src_port": 443,
                        "dst_port": 51820,
                        "summary": "Tunnel packet",
                        "payload_text": "GET / HTTP/1.1",
                        "banner_text": "HTTP request",
                        "tags": [{"key": "service", "value": "vpn"}],
                    }
                )

                request = Request("GET", "/api/soc/analysis/", "cycles=4&limit=500", {}, b"", ("127.0.0.1", 0))
                response = app_module.app.dispatch(request)
                payload = json.loads(response.body.decode("utf-8"))

                self.assertEqual(response.status, 200)
                self.assertIn("soc_summary", payload)
                self.assertEqual(len(payload["cycles"]), 4)
                self.assertGreaterEqual(payload["soc_summary"]["findings_total"], 1)
                self.assertGreaterEqual(len(payload["findings"]), 1)
                self.assertGreaterEqual(len(payload["questions"]), 1)
            finally:
                try:
                    app_module.store.close()
                except NameError:
                    pass
                if previous_db is None:
                    os.environ.pop("SNIFF4HOUND_DB_PATH", None)
                else:
                    os.environ["SNIFF4HOUND_DB_PATH"] = previous_db
                if previous_auth is None:
                    os.environ.pop("SNIFF4HOUND_REQUIRE_AUTH", None)
                else:
                    os.environ["SNIFF4HOUND_REQUIRE_AUTH"] = previous_auth

    def test_banners_endpoint_filters_honeypot_mode_and_keeps_packet_context(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "traffic.db"
            previous_db = os.environ.get("SNIFF4HOUND_DB_PATH")
            previous_auth = os.environ.get("SNIFF4HOUND_REQUIRE_AUTH")
            os.environ["SNIFF4HOUND_DB_PATH"] = str(db_path)
            os.environ["SNIFF4HOUND_REQUIRE_AUTH"] = "0"
            try:
                _settings_module, _auth_module, app_module = _reload_runtime_stack("0")

                app_module.store.register_packet(
                    {
                        "session_id": 11,
                        "interface": "eth0",
                        "direction": "outbound",
                        "proto": "tcp",
                        "src_ip": "192.0.2.15",
                        "dst_ip": "198.51.100.21",
                        "src_port": 50000,
                        "dst_port": 80,
                        "summary": "HTTP request",
                        "payload_text": "GET / HTTP/1.1",
                        "banner_text": "HTTP request",
                    }
                )
                app_module.store.register_packet(
                    {
                        "session_id": 12,
                        "interface": "honeypot:53",
                        "direction": "inbound",
                        "proto": "udp",
                        "src_ip": "203.0.113.50",
                        "dst_ip": "127.0.0.1",
                        "src_port": 53535,
                        "dst_port": 53,
                        "summary": "DNS message",
                        "payload_text": "query example.com",
                        "banner_text": "DNS message",
                        "tags": [{"key": "mode", "value": "honeypot"}],
                    }
                )

                request = Request("GET", "/banners/", "mode=honeypot", {}, b"", ("127.0.0.1", 0))
                response = app_module.app.dispatch(request)
                payload = json.loads(response.body.decode("utf-8"))

                self.assertEqual(response.status, 200)
                self.assertEqual(len(payload), 1)
                self.assertEqual(payload[0]["interface"], "honeypot:53")
                self.assertEqual(payload[0]["direction"], "inbound")
                self.assertEqual(payload[0]["src_ip"], "203.0.113.50")
                self.assertEqual(payload[0]["dst_ip"], "127.0.0.1")
                self.assertEqual(payload[0]["response_plain"], "DNS message")
                self.assertEqual(payload[0]["tags"][0]["value"], "honeypot")
                app_module.store.close()
            finally:
                if previous_db is None:
                    os.environ.pop("SNIFF4HOUND_DB_PATH", None)
                else:
                    os.environ["SNIFF4HOUND_DB_PATH"] = previous_db
                if previous_auth is None:
                    os.environ.pop("SNIFF4HOUND_REQUIRE_AUTH", None)
                else:
                    os.environ["SNIFF4HOUND_REQUIRE_AUTH"] = previous_auth
