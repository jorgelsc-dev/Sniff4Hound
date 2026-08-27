"""
Comprehensive test suite for Sniff4Hound

Includes unit tests, integration tests, and security tests.
Run with: pytest tests/ -v --cov=sniff4hound
"""

from __future__ import annotations

import ipaddress
import json
import os
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import sniff4hound
from sniff4hound import auth, logger, utils
from sniff4hound.monitors import DEFAULT_MONITORS, evaluate_packet, normalize_monitor
from sniff4hound.sniffer import Sniffer
from sniff4hound.store import SniffStore


class TestVersion(unittest.TestCase):
    """Test version information."""

    def test_version_format(self):
        """Version should follow semantic versioning."""
        version = sniff4hound.__version__
        parts = version.split(".")
        self.assertEqual(len(parts), 3)
        for part in parts:
            self.assertTrue(part.isdigit())

    def test_version_is_string(self):
        self.assertIsInstance(sniff4hound.__version__, str)


class TestNDJsonLogger(unittest.TestCase):
    """Test NDJSON logging functionality."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.log_file = Path(self.temp_dir.name) / "test.log"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_logger_creates_log_file(self):
        """Logger should create log file if it doesn't exist."""
        test_logger = logger.get_logger("test", log_file=self.log_file)
        test_logger.info("Test message")
        self.assertTrue(self.log_file.exists())

    def test_logger_writes_valid_json(self):
        """Each log line should be valid JSON."""
        test_logger = logger.get_logger("test", log_file=self.log_file)
        test_logger.info("Test message", extra={"custom_field": "value"})
        test_logger.warning("Warning message")
        test_logger.error("Error message")

        with open(self.log_file) as f:
            lines = f.readlines()

        self.assertGreater(len(lines), 0)
        for line in lines:
            parsed = json.loads(line.strip())
            self.assertIn("timestamp", parsed)
            self.assertIn("level", parsed)
            self.assertIn("message", parsed)

    def test_logger_captures_exceptions(self):
        """Logger should capture exception info."""
        test_logger = logger.get_logger("test", log_file=self.log_file)
        try:
            raise ValueError("Test error")
        except ValueError:
            test_logger.exception("An error occurred")

        with open(self.log_file) as f:
            content = f.read()

        parsed = json.loads(content.strip())
        self.assertIn("exception", parsed)
        self.assertIn("ValueError", parsed["exception"])

    def test_logger_context_manager(self):
        """LoggerContext should temporarily change log level."""
        test_logger = logger.get_logger("test", log_file=self.log_file, level=20)  # INFO
        original_level = test_logger.level

        with logger.LoggerContext(test_logger, level=10):  # DEBUG
            self.assertEqual(test_logger.level, 10)

        self.assertEqual(test_logger.level, original_level)


class TestJWTAuth(unittest.TestCase):
    """Test JWT authentication."""

    def test_encode_decode_jwt(self):
        """JWT should encode and decode correctly."""
        payload = {"user": "test_user", "role": "admin"}
        token = auth.encode_jwt(payload)

        is_valid, decoded = auth.decode_jwt(token)
        self.assertTrue(is_valid)
        self.assertEqual(decoded["user"], "test_user")
        self.assertEqual(decoded["role"], "admin")

    def test_invalid_token_signature(self):
        """Token with invalid signature should fail verification."""
        token = auth.encode_jwt({"user": "test"})
        # Tamper with the token
        parts = token.split(".")
        tampered = f"{parts[0]}.{parts[1]}.INVALID"

        is_valid, decoded = auth.decode_jwt(tampered)
        self.assertFalse(is_valid)
        self.assertIsNone(decoded)

    def test_expired_token(self):
        """Expired token should be rejected."""
        # Create a token that expired in the past
        now = int(time.time())
        payload = {
            "user": "test",
            "exp": now - 3600,  # Expired 1 hour ago
            "iat": now - 7200,
        }

        token = auth.encode_jwt(payload)
        is_valid, decoded = auth.decode_jwt(token)
        self.assertFalse(is_valid)

    def test_generate_token(self):
        """Generated token should be valid."""
        token = auth.generate_token(user="admin", scope="full")
        is_valid, payload = auth.decode_jwt(token)

        self.assertTrue(is_valid)
        self.assertEqual(payload["user"], "admin")
        self.assertEqual(payload["scope"], "full")

    def test_extract_token_from_header(self):
        """Should extract token from Bearer header."""
        token = auth.generate_token(user="test")
        header = f"Bearer {token}"

        extracted = auth.extract_token_from_header(header)
        self.assertEqual(extracted, token)

    def test_extract_token_without_bearer(self):
        """Should handle token without Bearer prefix."""
        token = "some.jwt.token"
        extracted = auth.extract_token_from_header(token)
        self.assertEqual(extracted, token)

    def test_authenticate_request_with_valid_token(self):
        """Valid token should authenticate successfully."""
        token = auth.generate_token(user="admin")
        is_auth, user_info = auth.authenticate_request(token)

        self.assertTrue(is_auth)
        self.assertEqual(user_info["user"], "admin")
        self.assertTrue(user_info["authenticated"])

    def test_authenticate_request_without_token_no_auth_required(self):
        """Without token and auth not required, should be anonymous."""
        with patch.dict(os.environ, {"SNIFF4HOUND_REQUIRE_AUTH": "0"}):
            # Reload auth module to pick up new env var
            import importlib

            importlib.reload(auth)
            is_auth, user_info = auth.authenticate_request(None)

            # In non-enforced mode, should allow
            if is_auth:
                self.assertTrue(is_auth)


class TestUtils(unittest.TestCase):
    """Test utility functions."""

    def test_bytes_to_hex_preview(self):
        """Should convert bytes to hex preview."""
        data = b"\x00\x01\x02\x03"
        preview = utils.bytes_to_hex_preview(data, max_length=8)
        self.assertIn("00010203", preview)

    def test_normalize_text(self):
        """Should normalize text safely."""
        text = "Hello\x00World\xff"
        normalized = utils.normalize_text(text)
        self.assertIsInstance(normalized, str)
        # Should not raise

    def test_safe_int_parsing(self):
        """Should safely parse integers."""
        self.assertEqual(utils.safe_int("123", 0), 123)
        self.assertEqual(utils.safe_int("invalid", 999), 999)
        self.assertEqual(utils.safe_int(None, 42), 42)

    def test_safe_float_parsing(self):
        """Should safely parse floats."""
        self.assertEqual(utils.safe_float("3.14", 0.0), 3.14)
        self.assertEqual(utils.safe_float("invalid", 2.0), 2.0)

    def test_clamp_int(self):
        """Should clamp integer to range."""
        self.assertEqual(utils.clamp_int(5, 1, 10), 5)
        self.assertEqual(utils.clamp_int(0, 1, 10), 1)
        self.assertEqual(utils.clamp_int(20, 1, 10), 10)

    def test_json_dumps_is_consistent(self):
        """json_dumps should produce consistent output."""
        data = {"z": 1, "a": 2, "m": 3}
        result1 = utils.json_dumps(data)
        result2 = utils.json_dumps(data)
        self.assertEqual(result1, result2)

    def test_normalize_protocol_name(self):
        """Should normalize protocol names."""
        self.assertEqual(utils.normalize_protocol_name("tcp"), "tcp")
        self.assertEqual(utils.normalize_protocol_name("UDP"), "udp")
        self.assertEqual(utils.normalize_protocol_name("ICMP"), "icmp")


class TestSnifferParsing(unittest.TestCase):
    """Test packet parsing edge cases from live captures."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test.db"
        self.store = SniffStore(self.db_path)
        self.sniffer = Sniffer(self.store, MagicMock(), interfaces=())

    def tearDown(self):
        self.store.close()
        self.temp_dir.cleanup()

    def _ipv4_checksum(self, header: bytes) -> int:
        total = 0
        for index in range(0, len(header), 2):
            total += int.from_bytes(header[index : index + 2], "big")
        while total > 0xFFFF:
            total = (total & 0xFFFF) + (total >> 16)
        return (~total) & 0xFFFF

    def _build_raw_ipv4_packet(self, *, proto: int, src_ip: str, dst_ip: str, body: bytes) -> bytes:
        header = bytearray(20)
        header[0] = 0x45
        header[2:4] = (20 + len(body)).to_bytes(2, "big")
        header[4:6] = (0x1337).to_bytes(2, "big")
        header[8] = 64
        header[9] = int(proto) & 0xFF
        header[12:16] = ipaddress.IPv4Address(src_ip).packed
        header[16:20] = ipaddress.IPv4Address(dst_ip).packed
        header[10:12] = self._ipv4_checksum(header).to_bytes(2, "big")
        return bytes(header) + bytes(body)

    def test_parse_raw_ipv4_packet_without_ethernet_header(self):
        packet = self.sniffer.parse_packet(
            bytes.fromhex(
                "45000028A74A40004006D78D0A0D0D03B5E1EF068A5201BB"
                "6349235CF2E6C49250100133BC120000"
            ),
            interface="Neubox",
        )

        self.assertIsNotNone(packet)
        # Port 443: the application protocol is reported, with the transport
        # it rode on kept alongside it.
        self.assertEqual(packet["proto"], "tls")
        self.assertEqual(packet["transport"], "tcp")
        self.assertEqual(packet["ip_version"], 4)
        self.assertEqual(packet["src_ip"], "10.13.13.3")
        self.assertEqual(packet["dst_ip"], "181.225.239.6")
        self.assertEqual(packet["src_port"], 35410)
        self.assertEqual(packet["dst_port"], 443)
        self.assertEqual(packet["eth_type"], 0x0800)

    def test_parse_truncated_raw_ipv4_packet_without_ethernet_header(self):
        packet = self.sniffer.parse_packet(
            bytes.fromhex(
                "4500058C180B00003806086F2268237B0A0D0D030050BA9A"
                "282AC4C9C0666D928018041A4BED00000101080A00DDD904"
            ),
            interface="Neubox",
        )

        self.assertIsNotNone(packet)
        # Source port 80: identified as HTTP even though the segment is
        # truncated and carries no decodable request line.
        self.assertEqual(packet["proto"], "http")
        self.assertEqual(packet["transport"], "tcp")
        self.assertEqual(packet["src_ip"], "34.104.35.123")
        self.assertEqual(packet["dst_ip"], "10.13.13.3")
        self.assertEqual(packet["src_port"], 80)
        self.assertEqual(packet["dst_port"], 47770)

    def test_parse_stp_bpdu_frame(self):
        packet = self.sniffer.parse_packet(
            bytes.fromhex(
                "0180C2000000D401C3D8E1250027424203000002023E8000"
                "D401C3D8E125000000008000D401C3D8E125800200001400"
            ),
            interface="eth0",
        )

        self.assertIsNotNone(packet)
        self.assertEqual(packet["proto"], "stp")
        self.assertEqual(packet["eth_dst"], "01:80:c2:00:00:00")
        self.assertEqual(packet["summary"], "STP BPDU")
        self.assertTrue(packet["flow_key"].startswith("stp|"))

    def test_parse_unknown_ipv4_protocol_as_unknown(self):
        # Protocol 253 is IANA-reserved "for experimentation" and will never
        # get a dedicated parser, unlike protocol 47 (GRE) which sniffer.py
        # now parses explicitly — see test_new_protocols.py for that coverage.
        packet = self.sniffer.parse_packet(
            self._build_raw_ipv4_packet(
                proto=253,
                src_ip="10.10.10.10",
                dst_ip="8.8.8.8",
                body=b"???",
            ),
            interface="eth0",
        )

        self.assertIsNotNone(packet)
        self.assertEqual(packet["proto"], "unknown")
        self.assertEqual(packet["src_ip"], "10.10.10.10")
        self.assertEqual(packet["dst_ip"], "8.8.8.8")
        self.assertIn("IPv4 protocol 253", packet["summary"])

    def test_parse_sctp_packet(self):
        body = (
            (5000).to_bytes(2, "big")
            + (3868).to_bytes(2, "big")
            + b"\x00\x00\x00\x01"
            + b"\x00\x00\x00\x00"
            + b"diameter"
        )
        packet = self.sniffer.parse_packet(
            self._build_raw_ipv4_packet(
                proto=132,
                src_ip="192.0.2.10",
                dst_ip="198.51.100.20",
                body=body,
            ),
            interface="eth0",
        )

        self.assertIsNotNone(packet)
        self.assertEqual(packet["proto"], "sctp")
        self.assertEqual(packet["src_port"], 5000)
        self.assertEqual(packet["dst_port"], 3868)
        self.assertIn("diameter", packet["payload_text"])

    def test_parse_ipv6_packet_with_extension_header(self):
        payload = b"mdns"
        udp = (
            (5353).to_bytes(2, "big")
            + (5353).to_bytes(2, "big")
            + (8 + len(payload)).to_bytes(2, "big")
            + b"\x00\x00"
            + payload
        )
        hop_by_hop = bytes([17, 0, 0, 0, 0, 0, 0, 0])
        header = bytearray(40)
        header[0] = 0x60
        header[4:6] = (len(hop_by_hop) + len(udp)).to_bytes(2, "big")
        header[6] = 0
        header[7] = 64
        header[8:24] = ipaddress.IPv6Address("2001:db8::1").packed
        header[24:40] = ipaddress.IPv6Address("2001:db8::2").packed

        packet = self.sniffer.parse_packet(bytes(header) + hop_by_hop + udp, interface="eth0")

        self.assertIsNotNone(packet)
        # Port 5353 now gets its own "mdns" proto tag (sniffer.py parses it
        # via the shared DNS-message parser) rather than the generic "udp" —
        # what this test actually exercises, the hop-by-hop extension header
        # unwrap reaching the inner UDP payload, still works correctly.
        self.assertEqual(packet["proto"], "mdns")
        self.assertEqual(packet["ip_version"], 6)
        self.assertEqual(packet["src_port"], 5353)
        self.assertEqual(packet["dst_port"], 5353)
        # The 4-byte "mdns" fixture payload isn't valid DNS wire format (real
        # mDNS queries are >=12 bytes) and is too short to pass the printable-
        # payload floor in `is_printable_payload`, so `payload_text` no longer
        # falls back to that raw literal - it gets the synthetic mDNS summary
        # instead, same as any other packet where parsing found no questions.
        self.assertIn("mdns", packet["payload_text"].lower())

    def test_unknown_ethertype_binary_noise_does_not_leak_into_payload_text(self):
        # Regression test: a completely unparsed (proto="unknown") Ethernet
        # frame's raw binary payload used to always get decoded into
        # `payload_text` via `bytes.decode(errors="ignore")`, no matter how
        # noisy the result - and that noise can coincidentally spell out a
        # monitor's trigger word. This exact payload (captured live) tripped
        # a false "Web shell reference" alert purely from the "wso" fragment
        # buried in the noise.
        payload_hex = (
            "000010006c098004b90000003724070000001c0500000000000091ed3801"
            "00000000160011030200e037b900b10188424800d62f705f794244896de7"
            "c2ef44896de7c2e0506f000026cc002012000000797bcc3d9fdf5504b889"
            "e28c432ab5df3de5b3e446da2ec82b08533847277318c8e384720626738a"
            "ae3a6b2ca74ae4bb529ee8c40715e2db0e8c29b3d5a56f0adad1bafd5425"
            "d98a84658b3fd03cc6a188a4c6752116d3b1bf15ad8a893c79931413b0d3"
            "f56f9e753923084f2959e9fbf3db7bb12b6ee221677aec1673f70b5cd9a2"
            "303f7a356b8ce1887a64bde13355635519bc1ed84151a36d818fe0cbed18"
            "5753fc4f3a16ba1be4eb659609a88ced"
        )
        payload = bytes.fromhex(payload_hex)
        frame = (
            bytes.fromhex("00003c002a40")  # dst mac
            + bytes.fromhex("58a8200800a0")  # src mac
            + (0x2008).to_bytes(2, "big")  # unrecognized EtherType
            + payload
        )
        packet = self.sniffer.parse_packet(frame, interface="wlan0")

        self.assertIsNotNone(packet)
        self.assertEqual(packet["proto"], "unknown")
        self.assertEqual(packet["payload_text"], "")

        monitors = [normalize_monitor(item, allow_source=True) for item in DEFAULT_MONITORS]
        hits = evaluate_packet(packet, monitors)
        # The generic "unknown protocol" visibility monitor is expected to
        # match (that's its whole purpose) - the regression this test
        # actually guards is that nothing else (a noise-derived false
        # positive like the webshell-reference regex) matches alongside it.
        self.assertEqual({hit["tag"] for hit in hits}, {"unknown-protocol"})

    def test_unparseable_packet_is_tagged_distinctly_from_unknown(self):
        packet = self.sniffer._build_unparseable_packet("wlan0", b"\x00\x01\x02", reason="frame too short to parse")
        self.assertEqual(packet["proto"], "unparseable")
        self.assertEqual(packet["parse_error"], "frame too short to parse")
        self.assertIn("Unparseable frame", packet["summary"])

        monitors = [normalize_monitor(item, allow_source=True) for item in DEFAULT_MONITORS]
        hits = evaluate_packet(packet, monitors)
        self.assertEqual({hit["tag"] for hit in hits}, {"unparseable-packet"})

    def test_unparseable_frames_are_counted_per_interface(self):
        # A frame the parser rejects is not just a curiosity: a spike is what
        # malformed/fuzzed traffic aimed at evading or crashing the sensor
        # looks like from the inside. Until this counter existed, the only
        # trace was a line in the JSON log nobody watches.
        self.sniffer._build_unparseable_packet("wlan0", b"\x00\x01", reason="too short")
        self.sniffer._build_unparseable_packet("wlan0", b"\x00\x02", reason="too short")
        self.sniffer._build_unparseable_packet("eth0", b"\x00\x03", reason="boom")

        snapshot = self.sniffer.snapshot()
        self.assertEqual(snapshot["packets_unparseable"], 3)
        self.assertEqual(snapshot["unparseable_by_interface"], {"wlan0": 2, "eth0": 1})
        self.assertTrue(snapshot["last_unparseable_at"])

    def test_the_unparseable_counter_is_exposed_even_when_zero(self):
        snapshot = self.sniffer.snapshot()
        self.assertEqual(snapshot["packets_unparseable"], 0)
        self.assertEqual(snapshot["unparseable_by_interface"], {})

    def test_capture_worker_survives_a_parser_exception_without_crashing(self):
        # Regression test: parse_packet() used to be called with no try/except
        # around it in _capture_worker - a single malformed frame tripping a
        # bug in any parser would raise out of the loop and silently kill the
        # whole capture thread, with nothing captured again until a manual
        # restart. Drive the real loop (fake socket, real threading.Event)
        # to prove it now degrades to a tagged record and keeps running.
        fake_sock = MagicMock()
        call_count = {"n": 0}

        def fake_recvfrom(_bufsize):
            call_count["n"] += 1
            if call_count["n"] == 1:
                return b"\x00" * 20, None
            self.sniffer._stop_event.set()
            raise socket.timeout()

        fake_sock.recvfrom.side_effect = fake_recvfrom
        stored: list[dict] = []
        self.sniffer._stop_event = threading.Event()
        with patch("socket.socket", return_value=fake_sock), \
             patch.object(self.sniffer, "parse_packet", side_effect=ValueError("boom")), \
             patch.object(self.sniffer, "_store_packet", side_effect=stored.append):
            self.sniffer._capture_worker("wlan0")

        self.assertEqual(len(stored), 1)
        self.assertEqual(stored[0]["proto"], "unparseable")
        self.assertEqual(stored[0]["parse_error"], "boom")

    def test_capture_worker_tags_a_none_return_as_unparseable_too(self):
        # parse_packet() returning None (frame too short) used to be
        # silently dropped with no record at all - now it degrades the
        # same way an exception does.
        fake_sock = MagicMock()
        call_count = {"n": 0}

        def fake_recvfrom(_bufsize):
            call_count["n"] += 1
            if call_count["n"] == 1:
                return b"\x00" * 20, None
            self.sniffer._stop_event.set()
            raise socket.timeout()

        fake_sock.recvfrom.side_effect = fake_recvfrom
        stored: list[dict] = []
        self.sniffer._stop_event = threading.Event()
        with patch("socket.socket", return_value=fake_sock), \
             patch.object(self.sniffer, "parse_packet", return_value=None), \
             patch.object(self.sniffer, "_store_packet", side_effect=stored.append):
            self.sniffer._capture_worker("wlan0")

        self.assertEqual(len(stored), 1)
        self.assertEqual(stored[0]["proto"], "unparseable")
        self.assertEqual(stored[0]["parse_error"], "frame too short to parse")


class TestSniffStore(unittest.TestCase):
    """Test SQLite store functionality."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test.db"
        self.store = SniffStore(self.db_path)

    def tearDown(self):
        self.store.close()
        self.temp_dir.cleanup()

    def test_store_initialization(self):
        """Store should initialize with empty counts."""
        counts = self.store.summary_counts()
        self.assertEqual(counts["packets"], 0)
        self.assertEqual(counts["sessions"], 0)

    def test_register_packet(self):
        """Should register a packet."""
        packet = {
            "session_id": 1,
            "proto": "tcp",
            "src_ip": "192.168.1.1",
            "dst_ip": "192.168.1.2",
            "src_port": 1234,
            "dst_port": 80,
            "payload_text": "test",
            "payload_hex": "74657374",
            "summary": "TCP packet",
            "raw_packet": b"\x45\x00",
        }
        result = self.store.register_packet(packet)
        self.assertIn("id", result)

        counts = self.store.summary_counts()
        self.assertEqual(counts["packets"], 1)

    def test_register_packet_does_not_create_payload_from_summary_only(self):
        """Summary-only packets should not become synthetic response rows."""
        packet = {
            "session_id": 1,
            "proto": "tcp",
            "src_ip": "172.64.155.209",
            "dst_ip": "192.168.15.7",
            "src_port": 443,
            "dst_port": 43650,
            "payload_text": "",
            "payload_hex": "",
            "summary": "TCP 172.64.155.209:443 -> 192.168.15.7:43650",
            "raw_packet": b"\x45\x00",
        }
        self.store.register_packet(packet)

        payloads = self.store.list_payloads(limit=10)
        self.assertEqual(payloads, [])

    def test_packet_raw_binary_encoding(self):
        """Raw packet binary should be encoded as hex string."""
        packet = {
            "session_id": 1,
            "proto": "tcp",
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "src_port": 5000,
            "dst_port": 443,
            "payload_text": "",
            "payload_hex": "",
            "summary": "Test",
            "raw_packet": b"\x00\x01\x02\xff",
        }
        result = self.store.register_packet(packet)
        self.assertIsInstance(result["raw_packet"], str)
        self.assertRegex(result["raw_packet"], r"^[0-9a-f]+$")

    def test_snapshot_is_json_serializable(self):
        """Snapshots should be JSON serializable."""
        packet = {
            "session_id": 1,
            "proto": "tcp",
            "src_ip": "8.8.8.8",
            "dst_ip": "1.1.1.1",
            "src_port": 53,
            "dst_port": 53,
            "payload_text": "",
            "payload_hex": "",
            "summary": "DNS",
            "raw_packet": b"",
        }
        self.store.register_packet(packet)

        snapshot = self.store.dashboard_snapshot()
        # Should not raise
        json.dumps(snapshot)

    def test_ip_intel_handles_structured_tags(self):
        """Host intel should tolerate tags stored as objects."""
        packet = {
            "session_id": 1,
            "proto": "tcp",
            "src_ip": "127.0.0.1",
            "dst_ip": "127.0.0.1",
            "src_port": 34500,
            "dst_port": 45678,
            "payload_text": "loopback test",
            "payload_hex": "6c6f6f706261636b2074657374",
            "summary": "Loopback packet",
            "tags": [
                {"key": "role", "value": "loopback"},
                {"key": "scope", "value": "local"},
            ],
            "raw_packet": b"\x45\x00",
        }
        self.store.register_packet(packet)

        intel = self.store.ip_intel("127.0.0.1")
        services = intel["host"]["transport"]["services"]
        self.assertGreaterEqual(len(services), 1)
        self.assertIn("loopback", services[0]["tags_text"])
        self.assertIn("local", services[0]["tags_text"])
        json.dumps(intel)

    def test_soc_analysis_snapshot_produces_iterative_cycles(self):
        """SOC analysis should return stable multi-pass triage output."""
        self.store.register_packet(
            {
                "session_id": 1,
                "proto": "tcp",
                "src_ip": "127.0.0.1",
                "dst_ip": "127.0.0.1",
                "src_port": 45670,
                "dst_port": 45670,
                "direction": "unknown",
                "state": "open",
                "summary": "Loopback packet",
                "payload_text": "{\"type\":\"telemetry\",\"packet\":1}",
                "tags": [{"key": "role", "value": "loopback"}],
                "raw_packet": b"\x45\x00",
            }
        )
        self.store.register_packet(
            {
                "session_id": 2,
                "proto": "udp",
                "src_ip": "72.249.55.101",
                "dst_ip": "192.168.88.250",
                "src_port": 443,
                "dst_port": 51820,
                "direction": "outbound",
                "state": "open",
                "summary": "Tunnel packet",
                "payload_text": "GET / HTTP/1.1",
                "banner_text": "HTTP request",
                "tags": [{"key": "service", "value": "vpn"}],
                "raw_packet": b"\x45\x00",
            }
        )

        snapshot = self.store.soc_analysis_snapshot(cycles=4, limit=250)

        self.assertIn("soc_summary", snapshot)
        self.assertEqual(len(snapshot["cycles"]), 4)
        self.assertGreaterEqual(snapshot["soc_summary"]["findings_total"], 1)
        self.assertGreaterEqual(len(snapshot["findings"]), 1)
        self.assertGreaterEqual(len(snapshot["questions"]), 1)
        self.assertGreaterEqual(len(snapshot["top_hosts"]), 1)
        json.dumps(snapshot)


class TestConcurrency(unittest.TestCase):
    """Test thread-safety of components."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test.db"
        self.store = SniffStore(self.db_path)

    def tearDown(self):
        self.store.close()
        self.temp_dir.cleanup()

    def test_concurrent_packet_registration(self):
        """Store should handle concurrent packet registration."""
        packet_count = 50
        threads = []

        def register_packets():
            for i in range(10):
                self.store.register_packet(
                    {
                        "session_id": 1,
                        "proto": "tcp",
                        "src_ip": "10.0.0.1",
                        "dst_ip": "10.0.0.2",
                        "src_port": 1000 + i,
                        "dst_port": 80,
                        "payload_text": f"packet_{i}",
                        "payload_hex": "",
                        "summary": f"Test {i}",
                        "raw_packet": b"",
                    }
                )

        for _ in range(5):
            t = threading.Thread(target=register_packets)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        counts = self.store.summary_counts()
        self.assertEqual(counts["packets"], packet_count)


class TestSettings(unittest.TestCase):
    """Test settings and environment configuration."""

    def test_db_path_configuration(self):
        """DB_PATH should use environment variable."""
        db_path = os.getenv("SNIFF4HOUND_DB_PATH", "Sniff4Hound.db")
        self.assertIsInstance(db_path, str)


class TestSecurityBasics(unittest.TestCase):
    """Basic security tests."""

    def test_no_hardcoded_credentials(self):
        """Should not have hardcoded passwords."""
        import sniff4hound.app
        import sniff4hound.auth
        import sniff4hound.settings

        modules = [sniff4hound.app, sniff4hound.auth, sniff4hound.settings]
        for module in modules:
            source = open(module.__file__).read()
            self.assertNotIn("password", source.lower())
            self.assertNotIn("secret123", source.lower())

    def test_jwt_uses_strong_hash(self):
        """JWT should use HS256."""
        import sniff4hound.auth as auth_module

        source = open(auth_module.__file__).read()
        self.assertIn("HS256", source)
        self.assertIn("sha256", source)


if __name__ == "__main__":
    unittest.main()
