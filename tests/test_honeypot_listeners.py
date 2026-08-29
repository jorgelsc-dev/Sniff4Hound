from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from sniff4hound.honeypot import (
    HoneypotEngine,
    TCP_BANNERS,
    UDP_BANNERS,
    _build_rdp_connection_confirm,
    _build_rtsp_response,
    _build_sip_response,
    _build_smb2_negotiate_response,
)
from sniff4hound.honeypot_ports import DEFAULT_ENABLED_PORTS
from sniff4hound.store import SniffStore


def _free_high_port() -> int:
    """Pick a free ephemeral port so listener tests don't need root and
    don't collide with anything else on the box."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class TestSeedingDoesNotImportHeavyHoneypotModule(unittest.TestCase):
    """Regression test for a real bug: SniffStore's honeypot_listeners
    seeding used to do `from .honeypot import COMMON_PORTS`, which pulls in
    honeypot.py's module-level side effects (it opens a RotatingFileHandler
    for honeypot.log as soon as it's imported). That module had previously
    only ever been imported by the privileged capture process (root, so
    permission issues on a pre-existing honeypot.log were masked) - once
    the unprivileged web process started constructing SniffStore before
    the privileged process even starts, importing honeypot.py from there
    could crash the whole app on `PermissionError` if an older honeypot.log
    in the current directory happened to be root-owned. Run in a real
    subprocess so sys.modules isn't polluted by whatever other tests in
    this session have already imported."""

    def test_constructing_a_store_never_imports_sniff4hound_honeypot(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            script = (
                "import sys\n"
                "from pathlib import Path\n"
                "from sniff4hound.store import SniffStore\n"
                f"store = SniffStore(Path({tmp_dir!r}) / 'test.db')\n"
                "store.list_honeypot_listeners()\n"
                "store.close()\n"
                "assert 'sniff4hound.honeypot' not in sys.modules, "
                "'constructing SniffStore must not import sniff4hound.honeypot'\n"
                "print('OK')\n"
            )
            repo_root = str(Path(__file__).resolve().parents[1])
            env = {**os.environ, "PYTHONPATH": repo_root}
            result = subprocess.run(
                [sys.executable, "-c", script],
                cwd=tmp_dir,
                env=env,
                capture_output=True,
                text=True,
                timeout=30,
            )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("OK", result.stdout)

    def test_honeypot_ports_module_is_importable_standalone(self):
        repo_root = str(Path(__file__).resolve().parents[1])
        env = {**os.environ, "PYTHONPATH": repo_root}
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "from sniff4hound.honeypot_ports import COMMON_PORTS; "
                "print(len(COMMON_PORTS['tcp']), len(COMMON_PORTS['udp']))",
            ],
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        tcp_count, udp_count = (int(item) for item in result.stdout.strip().split())
        self.assertGreaterEqual(tcp_count + udp_count, 10000)


class TestHoneypotListenerStore(unittest.TestCase):
    """Store-layer CRUD for honeypot_listeners: create is allowed, enable/
    disable is allowed, edit/delete deliberately don't exist at all."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test.db"
        self.store = SniffStore(self.db_path)

    def tearDown(self):
        self.store.close()
        self.temp_dir.cleanup()

    def test_builtin_listeners_are_seeded_on_init(self):
        listeners = self.store.list_honeypot_listeners()
        self.assertGreaterEqual(len(listeners), 10000)
        self.assertTrue(all(item["source"] == "builtin" for item in listeners))
        ids = {item["id"] for item in listeners}
        enabled_ids = {item["id"] for item in listeners if item["enabled"]}
        expected_enabled = {
            f"{proto}/{port}"
            for proto, ports in DEFAULT_ENABLED_PORTS.items()
            for port in ports
        }
        self.assertEqual(enabled_ids, expected_enabled)
        self.assertTrue(all(str(item.get("label") or "").strip() for item in listeners))
        self.assertIn("tcp/22", ids)  # SSH is always in COMMON_PORTS
        self.assertIn("tcp/502", ids)  # Modbus/OT
        self.assertIn("tcp/6443", ids)  # Kubernetes API
        self.assertIn("tcp/27018", ids)  # MongoDB alternate
        self.assertIn("udp/623", ids)  # IPMI
        self.assertIn("udp/47808", ids)  # BACnet/IP
        self.assertFalse(self.store.get_honeypot_listener("tcp/4999")["enabled"])
        self.assertFalse(self.store.get_honeypot_listener("udp/4999")["enabled"])

    def test_create_custom_listener(self):
        listener = self.store.create_honeypot_listener("tcp", 65000, label="Fake SSH #2")
        self.assertEqual(listener["id"], "tcp/65000")
        self.assertEqual(listener["source"], "custom")
        self.assertTrue(listener["enabled"])
        self.assertEqual(listener["label"], "Fake SSH #2")
        self.assertIn(listener["id"], {item["id"] for item in self.store.list_honeypot_listeners()})

    def test_create_duplicate_listener_raises(self):
        self.store.create_honeypot_listener("tcp", 65000)
        with self.assertRaises(ValueError):
            self.store.create_honeypot_listener("tcp", 65000)

    def test_create_listener_rejects_bad_proto(self):
        with self.assertRaises(ValueError):
            self.store.create_honeypot_listener("icmp", 8022)

    def test_create_listener_rejects_out_of_range_port(self):
        with self.assertRaises(ValueError):
            self.store.create_honeypot_listener("tcp", 70000)

    def test_set_enabled_works_on_builtin_and_custom(self):
        self.store.set_honeypot_listener_enabled("tcp/22", False)
        self.assertFalse(self.store.get_honeypot_listener("tcp/22")["enabled"])

        custom = self.store.create_honeypot_listener("udp", 9999)
        self.store.set_honeypot_listener_enabled(custom["id"], False)
        self.assertFalse(self.store.get_honeypot_listener(custom["id"])["enabled"])

    def test_set_enabled_unknown_id_raises(self):
        with self.assertRaises(ValueError):
            self.store.set_honeypot_listener_enabled("tcp/999999", True)

    def test_no_edit_or_delete_methods_exist(self):
        # Enforced at the storage layer, not just the API - there should be
        # no code path capable of changing proto/port or removing a row.
        self.assertFalse(hasattr(self.store, "delete_honeypot_listener"))
        self.assertFalse(hasattr(self.store, "update_honeypot_listener"))
        self.assertFalse(hasattr(self.store, "edit_honeypot_listener"))


class TestHoneypotEnginePerListenerControl(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test.db"
        self.store = SniffStore(self.db_path)
        # Disable every seeded builtin listener so start() only spins up
        # what each test explicitly creates - keeps this fast and avoids
        # needing root for the low builtin ports.
        with self.store._lock:
            self.store._conn.execute("UPDATE honeypot_listeners SET enabled = 0")
            self.store._conn.commit()
        self.engine = HoneypotEngine(self.store, MagicMock())

    def tearDown(self):
        try:
            self.engine.stop()
        except Exception:
            pass
        self.store.close()
        self.temp_dir.cleanup()

    def test_create_listener_before_start_joins_the_roster(self):
        port = _free_high_port()
        self.engine.create_listener("tcp", port, label="test")
        snapshot = self.engine.start()
        try:
            listeners = {item["id"]: item for item in snapshot["listeners"]}
            self.assertIn(f"tcp/{port}", listeners)
            self.assertTrue(listeners[f"tcp/{port}"]["enabled"])
        finally:
            self.engine.stop()

    def test_create_listener_while_running_starts_immediately(self):
        self.engine.start()
        try:
            port = _free_high_port()
            snapshot = self.engine.create_listener("tcp", port)
            time.sleep(0.1)
            listener_id = f"tcp/{port}"
            listeners = {item["id"]: item for item in snapshot["listeners"]}
            self.assertTrue(listeners[listener_id]["running"])
        finally:
            self.engine.stop()

    def test_stopping_one_listener_leaves_another_running(self):
        self.engine.start()
        try:
            port_a = _free_high_port()
            port_b = _free_high_port()
            self.engine.create_listener("tcp", port_a)
            self.engine.create_listener("tcp", port_b)
            time.sleep(0.1)

            snapshot = self.engine.set_listener_enabled(f"tcp/{port_a}", False)
            listeners = {item["id"]: item for item in snapshot["listeners"]}

            self.assertFalse(listeners[f"tcp/{port_a}"]["running"])
            self.assertFalse(listeners[f"tcp/{port_a}"]["enabled"])
            self.assertTrue(listeners[f"tcp/{port_b}"]["running"])
            self.assertTrue(listeners[f"tcp/{port_b}"]["enabled"])
        finally:
            self.engine.stop()

    def test_re_enabling_a_stopped_listener_restarts_it(self):
        self.engine.start()
        try:
            port = _free_high_port()
            listener_id = f"tcp/{port}"
            self.engine.create_listener("tcp", port)
            time.sleep(0.1)
            self.engine.set_listener_enabled(listener_id, False)
            snapshot = self.engine.set_listener_enabled(listener_id, True)
            time.sleep(0.1)
            listeners = {item["id"]: item for item in snapshot["listeners"]}
            self.assertTrue(listeners[listener_id]["enabled"])
        finally:
            self.engine.stop()

    def test_stop_engine_stops_every_listener(self):
        self.engine.start()
        port = _free_high_port()
        self.engine.create_listener("tcp", port)
        time.sleep(0.1)
        self.engine.stop()
        snapshot = self.engine.snapshot()
        self.assertFalse(snapshot["running"])
        self.assertTrue(all(not item["running"] for item in snapshot["listeners"]))

    def test_disabled_listener_does_not_start_with_the_engine(self):
        port = _free_high_port()
        self.engine.create_listener("tcp", port)
        self.store.set_honeypot_listener_enabled(f"tcp/{port}", False)
        snapshot = self.engine.start()
        try:
            listeners = {item["id"]: item for item in snapshot["listeners"]}
            self.assertFalse(listeners[f"tcp/{port}"]["running"])
        finally:
            self.engine.stop()


class TestHoneypotPacketNotificationTags(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test.db"
        self.store = SniffStore(self.db_path)
        self.engine = HoneypotEngine(self.store, MagicMock())

    def tearDown(self):
        self.store.close()
        self.temp_dir.cleanup()

    def test_build_packet_carries_a_critical_monitor_tag(self):
        # "honeypot" is expected and correct in this packet's own internal
        # metadata (interface/tags/summary) - that's the Sniff4Hound
        # operator's own dashboard data, never transmitted to the connecting
        # client. The actual stealth requirement (nothing sent back over the
        # wire may reveal the listener's true nature) is covered separately
        # by TestHoneypotStealthBanners below, against the real banner bytes.
        packet = self.engine._build_packet(
            protocol="tcp", port=22, addr=("203.0.113.5", 51234), data=b"SSH-2.0-test\r\n"
        )
        tag_map = {tag["key"]: tag for tag in packet["tags"]}
        self.assertIn("monitor", tag_map)
        self.assertIn("monitor_id", tag_map)
        self.assertEqual(packet["interface"], "honeypot:22")
        self.assertEqual(tag_map["monitor"]["severity"], "critical")
        self.assertEqual(tag_map["monitor"]["value"], "Honeypot hit")
        self.assertEqual(tag_map["monitor_id"]["value"], "builtin-honeypot-hit")
        self.assertEqual(tag_map["mode"]["value"], "honeypot")


class TestHoneypotStealthBanners(unittest.TestCase):
    def assertNoMarkerLeak(self, payload):
        if isinstance(payload, str):
            payload = payload.encode("utf-8", errors="replace")
        lowered = bytes(payload).lower()
        self.assertNotIn(b"honeypot", lowered)
        self.assertNotIn(b"sniff4hound", lowered)

    def test_static_banners_do_not_reveal_the_listener_role(self):
        for payload in list(TCP_BANNERS.values()) + list(UDP_BANNERS.values()):
            with self.subTest(payload=payload):
                self.assertNoMarkerLeak(payload)

    def test_dynamic_sip_and_rtsp_responses_do_not_reveal_the_listener_role(self):
        responses = [
            _build_sip_response(b"OPTIONS sip:service@example.net SIP/2.0\r\n\r\n", ("203.0.113.8", 5060)),
            _build_rtsp_response("OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n"),
            _build_smb2_negotiate_response(),
            _build_rdp_connection_confirm(),
        ]
        for response in responses:
            with self.subTest(response=response):
                self.assertNoMarkerLeak(response)


class TestSmb2NegotiateResponse(unittest.TestCase):
    """Byte-level structural checks for the SMB2 NEGOTIATE_RESPONSE mock -
    see _build_smb2_negotiate_response's docstring for the field layout this
    pins down. A malformed response here is worse than the honest generic
    fallback it replaced, so these checks matter."""

    def setUp(self):
        self.response = _build_smb2_negotiate_response()
        netbios_len = int.from_bytes(self.response[0:4], "big")
        self.assertEqual(netbios_len, len(self.response) - 4)
        self.message = self.response[4:]
        self.body = self.message[64:]

    def test_smb2_protocol_id_and_header_shape(self):
        self.assertEqual(self.message[:4], b"\xfeSMB")
        self.assertEqual(int.from_bytes(self.message[4:6], "little"), 64)  # header StructureSize
        self.assertEqual(int.from_bytes(self.message[12:14], "little"), 0)  # Command = NEGOTIATE

    def test_negotiate_response_body_fields(self):
        self.assertEqual(int.from_bytes(self.body[0:2], "little"), 65)  # body StructureSize
        self.assertEqual(int.from_bytes(self.body[4:6], "little"), 0x0202)  # DialectRevision = 2.0.2
        sec_offset = int.from_bytes(self.body[56:58], "little")
        sec_len = int.from_bytes(self.body[58:60], "little")
        self.assertEqual(sec_offset, 128)  # 64-byte header + 64-byte body
        self.assertEqual(sec_len, 0)


class TestRdpConnectionConfirm(unittest.TestCase):
    """Byte-level structural checks for the X.224 Connection Confirm mock -
    see _build_rdp_connection_confirm's docstring for the field layout."""

    def setUp(self):
        self.response = _build_rdp_connection_confirm()

    def test_tpkt_header_length_matches_actual_size(self):
        self.assertEqual(self.response[0:2], b"\x03\x00")
        tpkt_length = int.from_bytes(self.response[2:4], "big")
        self.assertEqual(tpkt_length, len(self.response))

    def test_x224_connection_confirm_and_negotiate_response(self):
        length_indicator = self.response[4]
        self.assertEqual(length_indicator, len(self.response) - 5)
        self.assertEqual(self.response[5], 0xD0)  # CC CDT
        self.assertEqual(self.response[11], 0x02)  # RDP_NEG_RSP type
        neg_length = int.from_bytes(self.response[13:15], "little")
        self.assertEqual(neg_length, 8)
        selected_protocol = int.from_bytes(self.response[15:19], "little")
        self.assertEqual(selected_protocol, 0)  # PROTOCOL_RDP


if __name__ == "__main__":
    unittest.main()
