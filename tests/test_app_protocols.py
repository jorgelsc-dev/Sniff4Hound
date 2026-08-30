"""Application-layer protocol identification and the transport it rides on.

Naming the application protocol in `packet["proto"]` is what lets the
Protocols view offer a slice per real protocol instead of one giant "tcp"
bucket. The risk it introduces is that every rule written against
protocols:["tcp"]/["udp"] stops matching - which had already silently
happened to the builtin SNMP rule before `transport` existed. These tests
pin both halves: the classification, and the fact that transport-scoped
rules keep firing through it.
"""

from __future__ import annotations

import struct
import unittest

from sniff4hound.app_protocols import classify_tcp, classify_udp
from sniff4hound.monitors import load_builtin_monitors
from sniff4hound.rulesets import rule_matches_packet
from sniff4hound.utils import KNOWN_PROTOCOLS


class ClassificationTests(unittest.TestCase):
    def test_signature_wins_over_the_port(self):
        # SSH on 2222 and HTTP on 8080 are recognised from their bytes, not
        # from a port table that would have to enumerate every alternative.
        self.assertEqual(classify_tcp(50000, 31337, b"SSH-2.0-OpenSSH_9.6"), "ssh")
        self.assertEqual(classify_tcp(50000, 8080, b"GET /index.html HTTP/1.1\r\n"), "http")
        self.assertEqual(classify_tcp(50000, 9999, b"\x16\x03\x01\x00\x50"), "tls")

    def test_port_is_the_fallback_when_no_signature_matches(self):
        self.assertEqual(classify_tcp(50000, 22, b""), "ssh")
        self.assertEqual(classify_udp(50000, 123, b"\x1b" + b"\x00" * 47), "ntp")
        self.assertEqual(classify_udp(50000, 53, b"\x00\x01"), "dns")

    def test_destination_port_is_preferred_over_the_source(self):
        # A client->server segment names the service it is addressing, not
        # whatever service happens to share its ephemeral source port.
        self.assertEqual(classify_tcp(80, 3306, b""), "mysql")

    def test_unrecognised_traffic_is_left_unnamed(self):
        self.assertEqual(classify_tcp(40000, 40001, b"\x00\x01\x02"), "")
        self.assertEqual(classify_udp(40000, 40001, b"\x00\x01\x02"), "")

    def test_ssdp_and_sip_are_not_mistaken_for_http(self):
        # Both use HTTP-shaped request lines, so ordering matters.
        self.assertEqual(classify_udp(50000, 1900, b"M-SEARCH * HTTP/1.1\r\n"), "ssdp")
        self.assertEqual(classify_udp(50000, 5060, b"INVITE sip:a@b SIP/2.0\r\n"), "sip")

    def test_every_classified_name_has_a_protocols_entry(self):
        # app.py builds /protocols/<name> straight off KNOWN_PROTOCOLS, so a
        # name the classifier can emit but the tuple lacks would 404 on
        # refresh.
        known = set(KNOWN_PROTOCOLS)
        for name in ("http", "tls", "ssh", "dns", "quic", "ssdp", "sip", "smb", "lldp", "ospf"):
            self.assertIn(name, known, f"{name} is classifiable but missing from KNOWN_PROTOCOLS")

    def test_known_protocols_has_no_duplicates(self):
        self.assertEqual(len(KNOWN_PROTOCOLS), len(set(KNOWN_PROTOCOLS)))

    def test_every_protocol_the_frontend_can_route_to_is_known(self):
        """The SPA validates /protocols/<name> against its own catalog.

        A protocol the backend can emit but the frontend has no entry for is
        unreachable by URL - selectedProtocol falls back to the first entry
        and quietly loads the wrong slice, which is exactly what an 8-entry
        fallback list used to do to every application protocol.
        """
        import re
        from pathlib import Path

        catalog = Path(__file__).resolve().parents[1] / "frontend" / "src" / "utils" / "protocolCatalog.js"
        source = catalog.read_text(encoding="utf-8")
        # Entries look like:  key: ["layer", "icon", "Label", "description"],
        declared = set(re.findall(r'^\s{2}"?([a-z0-9-]+)"?:\s*\[', source, re.MULTILINE))
        missing = sorted(set(KNOWN_PROTOCOLS) - declared)
        self.assertEqual(missing, [], f"no frontend card for: {missing}")


class TransportScopedRuleTests(unittest.TestCase):
    def setUp(self):
        self.monitors = load_builtin_monitors()
        # builtin-insecure-snmp and builtin-unknown-protocol default to
        # opt-in (protocol-visibility monitors, not threat signatures) -
        # these tests are about whether the transport-scoping match logic
        # is correct, not about default-enabled policy, so force them on
        # rather than letting `enabled: False` short-circuit the match
        # before the transport logic under test ever runs.
        for monitor in self.monitors:
            if monitor["id"] in ("builtin-insecure-snmp", "builtin-unknown-protocol"):
                monitor["enabled"] = True

    def _monitor(self, monitor_id):
        return next(m for m in self.monitors if m["id"] == monitor_id)

    def test_udp_scoped_rule_still_fires_once_the_protocol_is_named(self):
        # Regression: builtin-insecure-snmp matches protocols:["udp"] while
        # _parse_snmp reports proto="snmp", so before `transport` existed
        # this rule could never fire on real captured traffic.
        packet = {
            "proto": "snmp", "transport": "udp", "src_port": 40000, "dst_port": 161,
            "length": 80, "payload_hex": "30", "payload_text": "", "summary": "",
        }
        self.assertTrue(rule_matches_packet(self._monitor("builtin-insecure-snmp"), packet))

    def test_missing_transport_is_not_treated_as_unknown(self):
        # normalize_protocol_name("") returns "unknown", so reusing it for
        # transport would make every transport-less packet match
        # protocols:["unknown"].
        packet = {
            "proto": "tcp", "transport": "", "src_port": 51234, "dst_port": 443,
            "length": 60, "payload_hex": "", "payload_text": "", "summary": "",
        }
        self.assertFalse(rule_matches_packet(self._monitor("builtin-unknown-protocol"), packet))

    def test_named_protocol_still_matches_its_own_name(self):
        packet = {
            "proto": "tls", "transport": "tcp", "src_port": 50000, "dst_port": 443,
            "length": 200, "payload_hex": "160301", "payload_text": "", "summary": "",
        }
        rule = {"match": {"protocols": ["tls"]}, "action": {}}
        self.assertTrue(rule_matches_packet(rule, packet))


class SnifferIntegrationTests(unittest.TestCase):
    """The classification has to survive the real parse path, not just the
    helper functions."""

    def setUp(self):
        import os
        import tempfile

        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        # No env var: SniffStore takes its path explicitly. Setting
        # SNIFF4HOUND_DATA_DIR here and not restoring it leaves later module
        # reloads pointing at a directory this cleanup has already deleted,
        # which surfaces as "sqlite3.OperationalError: disk I/O error" in
        # whichever unrelated test happens to run next.
        from sniff4hound.sniffer import Sniffer
        from sniff4hound.store import SniffStore

        class _Hub:
            def broadcast(self, *args, **kwargs):
                pass

        store = SniffStore(os.path.join(self._tmp.name, "proto.db"))
        self.addCleanup(store.close)
        self.sniffer = Sniffer(store, _Hub())

    def _ethernet(self, eth_type: int, payload: bytes) -> bytes:
        return bytes.fromhex("aabbccddeeff") + bytes.fromhex("112233445566") + struct.pack("!H", eth_type) + payload

    def test_lldp_frame_is_named(self):
        packet = self.sniffer.parse_packet(self._ethernet(0x88CC, b"\x02\x07\x04" + bytes(20)), interface="eth0")
        self.assertEqual(packet["proto"], "lldp")

    def test_eapol_frame_is_named(self):
        packet = self.sniffer.parse_packet(self._ethernet(0x888E, b"\x01\x01\x00\x00"), interface="eth0")
        self.assertEqual(packet["proto"], "eapol")

    def test_ospf_over_ipv4_is_named(self):
        header = bytes([0x45, 0, 0, 40, 0, 0, 0, 0, 64, 89, 0, 0]) + bytes([10, 0, 0, 1]) + bytes([224, 0, 0, 5])
        packet = self.sniffer.parse_packet(self._ethernet(0x0800, header + b"\x02\x01" + bytes(18)), interface="eth0")
        self.assertEqual(packet["proto"], "ospf")

    def test_tls_over_tcp_records_both_layers(self):
        tcp = bytearray(20)
        struct.pack_into("!HH", tcp, 0, 50000, 443)
        tcp[12] = 5 << 4
        header = bytes([0x45, 0, 0, 60, 0, 0, 0, 0, 64, 6, 0, 0]) + bytes([10, 0, 0, 1]) + bytes([1, 1, 1, 1])
        frame = self._ethernet(0x0800, header + bytes(tcp) + b"\x16\x03\x01\x00\x50")
        packet = self.sniffer.parse_packet(frame, interface="eth0")
        self.assertEqual(packet["proto"], "tls")
        self.assertEqual(packet["transport"], "tcp")


if __name__ == "__main__":
    unittest.main()
