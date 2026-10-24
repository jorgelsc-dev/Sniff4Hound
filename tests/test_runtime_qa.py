"""Regressions observed against the real desktop and remote sensors."""
from __future__ import annotations

import importlib
import json
import os
import socket
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from wsbuilder import Request

from sniff4hound import log_setup, mobile_stream
from sniff4hound.sniffer import Sniffer
from sniff4hound.store import SniffStore
from sniff4hound.utils import service_endpoint
from tests.test_intel import _build_dns_query, _build_dns_response


def frame(src=50000, dst=22, *, udp=False, flags=2, payload=b"", ipv6=False, vlan=False):
    body = struct.pack("!HHHH", src, dst, 8 + len(payload), 0) if udp else struct.pack("!HHIIBBHHH", src, dst, 0, 0, 80, flags, 1024, 0, 0)
    body += payload
    proto = 17 if udp else 6
    if ipv6:
        ip = struct.pack("!IHBB16s16s", 6 << 28, len(body), proto, 64,
                         socket.inet_pton(socket.AF_INET6, "2001:db8::1"), socket.inet_pton(socket.AF_INET6, "2001:db8::2"))
    else:
        ip = struct.pack("!BBHHHBBH4s4s", 69, 0, 20 + len(body), 0, 0, 64, proto, 0,
                         socket.inet_aton("192.0.2.1"), socket.inet_aton("192.0.2.2"))
    ethernet = b"\x00" * 12 + (b"\x81\x00\x00\x01\x86\xdd" if vlan and ipv6 else b"\x81\x00\x00\x01\x08\x00" if vlan else b"\x86\xdd" if ipv6 else b"\x08\x00")
    return ethernet + ip + body


class RuntimeQaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.store = SniffStore(Path(cls.tmp.name) / "qa.db")

    @classmethod
    def tearDownClass(cls):
        cls.store.close()
        cls.tmp.cleanup()

    def setUp(self):
        self.sniffer = Sniffer(self.store, MagicMock())
        self.sniffer.dashboard_port = 45671

    def test_own_udp_and_tcp_are_dropped_before_parser_and_queue(self):
        for udp in (False, True):
            for incoming in (False, True):
                for ipv6, vlan in ((False, False), (False, True), (True, False), (True, True)):
                    with self.subTest(udp=udp, incoming=incoming, ipv6=ipv6, vlan=vlan):
                        self.sniffer._stop_event.clear()
                        data = frame(45671 if incoming else 50000, 50000 if incoming else 45671, udp=udp, ipv6=ipv6, vlan=vlan)
                        sock = MagicMock()
                        def receive(_size):
                            self.sniffer._stop_event.set()
                            return data, None
                        sock.recvfrom.side_effect = receive
                        with patch("sniff4hound.sniffer.socket.socket", return_value=sock), patch.object(self.sniffer, "parse_packet") as parse, patch.object(self.sniffer, "_enqueue_packet") as enqueue:
                            self.sniffer._capture_worker("lo")
                        parse.assert_not_called()
                        enqueue.assert_not_called()

    def test_fallback_port_filters_only_the_selected_port(self):
        self.assertTrue(self.sniffer._is_own_dashboard_frame(frame(dst=45671, udp=True)))
        self.assertFalse(self.sniffer._is_own_dashboard_frame(frame(dst=45678, udp=True)))
        with patch.dict(os.environ, {"SNIFF4HOUND_BOUND_PORT": "45672"}):
            other = Sniffer(self.store, MagicMock())
        self.assertEqual(other.dashboard_port, 45672)

    def test_tcp_states_and_empty_banners_follow_flags(self):
        for flags, state in ((2, "filtered"), (18, "open"), (20, "closed"), (16, "unknown")):
            for port in (22, 25, 445, 3389):
                with self.subTest(flags=flags, port=port):
                    row = self.sniffer.parse_packet(frame(dst=port, flags=flags))
                    self.assertEqual(row["payload_len"], 0)
                    self.assertEqual(row["state"], state)
                    self.assertEqual(row["banner_text"], "")
                    self.assertNotIn("session", row["summary"])
        row = self.sniffer.parse_packet(frame(payload=b"SSH-2.0-fixture\r\n", flags=24))
        self.assertEqual(row["payload_len"], len(b"SSH-2.0-fixture\r\n"))

    def test_dns_server_endpoint_is_not_the_client_port(self):
        for src, dst, data in ((50000, 53, _build_dns_query()), (53, 50000, _build_dns_response())):
            row = self.sniffer.parse_packet(frame(src, dst, udp=True, payload=data))
            self.assertEqual(row["payload_len"], len(data))
            self.assertEqual(service_endpoint(row)[1], 53)
            with patch.object(self.store, "record_domain") as record:
                self.sniffer._record_intel(row)
            self.assertEqual(record.call_args.kwargs["port"], 53)
        self.assertEqual(service_endpoint({"proto": "arp", "src_port": 0, "dst_port": 0}), ("", 0))

    def test_investigation_attributes_only_server_transport_services(self):
        rows = [self.sniffer.parse_packet(frame(dst=3389, flags=2)),
                self.sniffer.parse_packet(frame(53, 50000, udp=True, payload=_build_dns_response()))]
        for row in rows:
            self.store.register_packet(row)
        client = self.store.ip_intel("192.0.2.2")["host"]["transport"]["services"]
        self.assertNotIn(50000, [row["port"] for row in client])
        server = self.store.ip_intel("192.0.2.1")["host"]["transport"]["services"]
        self.assertEqual([(row["port"], row["state"]) for row in server if row["proto"] == "dns"], [(53, "open")])

    def test_monitors_page_is_small_searchable_and_has_separate_details(self):
        page = self.store.monitor_page(limit=2, offset=0)
        next_page = self.store.monitor_page(limit=2, offset=2)
        self.assertGreater(page["total_available"], 1000)
        self.assertEqual(len(page["items"]), 2)
        self.assertTrue({row["id"] for row in page["items"]}.isdisjoint(row["id"] for row in next_page["items"]))
        for row in page["items"]:
            self.assertNotIn("match", row)
            self.assertNotIn("match_json", row)
            self.assertIn("match", self.store.get_monitor(row["id"]))
        row = page["items"][0]
        filtered = self.store.monitor_page(q=row["id"], enabled=row["enabled"])
        self.assertIn(row["id"], [item["id"] for item in filtered["items"]])
        self.assertLess(len(json.dumps(page)), 10000)

    def test_listener_catalog_is_paged_with_aggregate_counts(self):
        page = self.store.honeypot_listener_page(limit=3, enabled=True)
        self.assertEqual(len(page["items"]), 3)
        self.assertTrue(all(row["enabled"] for row in page["items"]))
        self.assertGreater(page["stats"]["total"], len(page["items"]))
        self.assertTrue(all("tcp/22" in row["id"] or "tcp/22" in row["label"] for row in self.store.honeypot_listener_page(q="tcp/22")["items"]))

    def test_packet_trace_requires_explicit_opt_in_even_at_debug_level(self):
        with patch.dict(os.environ, {"SNIFF4HOUND_TRACE_PACKETS": "0"}), patch("sniff4hound.sniffer.LOGGER") as logger:
            self.sniffer._trace_packet({}, "received")
            logger.debug.assert_not_called()
        with patch.dict(os.environ, {"SNIFF4HOUND_TRACE_PACKETS": "1"}), patch("sniff4hound.sniffer.LOGGER") as logger:
            self.sniffer._trace_packet({}, "received")
            logger.debug.assert_called_once()

    def test_root_log_owner_uses_operator_uid_and_gid(self):
        with patch.dict(os.environ, {"SNIFF4HOUND_INVOKING_UID": "1000", "SNIFF4HOUND_INVOKING_GID": "1001"}), patch("os.geteuid", return_value=0):
            self.assertEqual(log_setup.invoking_owner(), (1000, 1001))
        self.assertEqual(log_setup.LOG_DEFAULTS["level"], "INFO")

    def test_new_log_and_rotated_log_are_returned_to_operator_after_creation(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "logs" / "web.ndjson"
            handed_back = []
            def chown(target, uid, gid):
                if Path(target).exists():
                    handed_back.append((Path(target), uid, gid))
            with patch("os.chown", side_effect=chown):
                sink = log_setup.RotatingNDJSONSink(path, max_bytes=1, backups=1, retention_days=0, owner=(1000, 1001))
                sink.write({"message": "first"})
                self.assertIn((path, 1000, 1001), handed_back)
                handed_back.clear()
                sink.write({"message": "second"})
                self.assertIn((path, 1000, 1001), handed_back)

    def test_startup_banner_and_port_notices_flush_without_tty(self):
        from sniff4hound import manage
        with patch("builtins.print") as output:
            manage._print_startup_banner("localhost", 45671)
            manage._print_port_fallback_notice(45678, 45671)
            manage._print_address_in_use_error("localhost", 45678)
        self.assertTrue(all(call.kwargs.get("flush") for call in output.call_args_list))

    def test_mobile_interfaces_prefer_active_default_route(self):
        def ioctl(_fd, request, packed):
            name = packed.split(b"\0", 1)[0].decode()
            if request == 0x8913:
                return b"\0" * 16 + struct.pack("H", 0 if name.startswith("br-") else 1) + b"\0" * 238
            return b"\0" * 20 + socket.inet_aton("127.0.0.1" if name == "lo" else "192.0.2.1") + b"\0" * 232
        with patch.object(socket, "if_nameindex", return_value=[(1, "br-test"), (2, "eth0"), (3, "wlan0"), (4, "lo")]), patch.object(mobile_stream.fcntl, "ioctl", side_effect=ioctl), patch.object(mobile_stream, "_default_route_interface", return_value="wlan0"):
            rows = mobile_stream.discover_interfaces()
        self.assertEqual(rows[0].name, "wlan0")
        self.assertEqual(rows[-1].name, "br-test")
        self.assertTrue(rows[0].default_route)


class RuntimeQaApiTests(unittest.TestCase):
    def setUp(self):
        self.app = importlib.import_module("sniff4hound.app")
        self.auth = importlib.import_module("sniff4hound.auth")
        self.patches = [patch.object(self.app, "REQUIRE_AUTH", True), patch.object(self.auth, "REQUIRE_AUTH", True), patch.object(self.auth, "_SESSION_TOKEN", "Ab12Cd34")]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)
        self.auth.RATE_LIMITER.reset()
        self.addCleanup(self.auth.RATE_LIMITER.reset)

    def request(self, path, query="", code="Ab12Cd34", method="GET"):
        return self.app.app.dispatch(Request(method, path, query, {"x-security-code": code, "origin": "app://shell"}, b"{}", ("127.0.0.1", 1234)))

    def test_public_app_helpers_remain_available_to_legacy_views(self):
        from sniff4hound import settings, utils, views
        self.assertEqual(self.app.HOST, settings.HOST)
        self.assertIs(self.app.json_dumps, utils.json_dumps)
        self.assertIs(self.app.normalize_text, utils.normalize_text)
        self.assertIs(views.normalize_text, utils.normalize_text)
        self.assertTrue(callable(self.app.ensure_data_dir))

    def test_remote_sensor_accepts_authenticated_shell_and_ws_ticket(self):
        with patch.dict(os.environ, {"SNIFF4HOUND_DESKTOP": "0"}):
            self.assertEqual(self.request("/api/echo", method="POST").status, 200)
            self.assertEqual(self.request("/api/ws/ticket", method="POST").status, 200)
            self.assertEqual(self.request("/api/echo", code="wrong", method="POST").status, 401)

    def test_correct_code_remains_usable_after_local_lockout(self):
        for _ in range(self.auth.AUTH_FAILURE_THRESHOLD + 2):
            self.request("/api/hello", code="wrong")
        self.assertEqual(self.request("/api/hello", code="wrong").status, 429)
        self.assertEqual(self.request("/api/hello").status, 200)

    def test_invalid_domain_and_unknown_monitor_return_400(self):
        for domain in ("%00%ff", "bad%00name.com", "name..example", "-bad.example"):
            self.assertEqual(self.request("/api/domain/intel/", "domain=" + domain).status, 400)
        self.assertEqual(self.request("/api/monitors/packets/", "monitor_id=abc").status, 400)

    def test_catalog_api_caps_page_size_and_does_not_ship_match(self):
        response = self.request("/api/monitors/", "limit=2&metadata=1")
        data = json.loads(response.body)
        self.assertEqual(len(data["items"]), 2)
        self.assertNotIn("match", data["items"][0])
        self.assertEqual(self.request("/api/monitors/", "enabled=maybe").status, 400)

    def test_monitor_stats_is_a_small_summary_for_settings(self):
        response = self.request("/api/monitors/stats")
        self.assertEqual(response.status, 200)
        data = json.loads(response.body)
        self.assertEqual(set(data), {"total", "enabled", "builtin", "custom"})
        self.assertGreater(data["total"], 1000)
        self.assertLess(len(response.body), 1024)

    def test_monitor_list_and_detail_keep_catalog_loading_under_demand(self):
        page = json.loads(self.request("/api/monitors/", "limit=2&metadata=1").body)
        self.assertEqual(len(page["items"]), 2)
        self.assertTrue(all("match" not in row and "match_json" not in row for row in page["items"]))
        detail = json.loads(self.request(
            "/api/monitors/", "id=" + page["items"][0]["id"]
        ).body)
        self.assertIn("match", detail)
        self.assertIn("action", detail)
