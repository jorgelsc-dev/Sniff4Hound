from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from sniff4hound.anomaly import (
    AnomalyEngine,
    ArpSpoofDetector,
    BruteForceLoginDetector,
    DnsQueryFloodDetector,
    IcmpFloodDetector,
    SynFloodDetector,
)
from sniff4hound.monitors import DEFAULT_MONITORS, normalize_monitor
from sniff4hound.sniffer import Sniffer, build_base_packet
from sniff4hound.store import SniffStore


def _monitors():
    return [normalize_monitor(item, allow_source=True) for item in DEFAULT_MONITORS]


class TestArpSpoofDetector(unittest.TestCase):
    def test_first_sighting_establishes_baseline(self):
        detector = ArpSpoofDetector()
        hit = detector.evaluate({"proto": "arp", "arp_opcode": 2, "src_ip": "10.0.0.5", "eth_src": "aa:aa:aa:aa:aa:aa"})
        self.assertIsNone(hit)

    def test_conflicting_mac_flags(self):
        detector = ArpSpoofDetector()
        detector.evaluate({"proto": "arp", "arp_opcode": 2, "src_ip": "10.0.0.5", "eth_src": "aa:aa:aa:aa:aa:aa"})
        hit = detector.evaluate({"proto": "arp", "arp_opcode": 2, "src_ip": "10.0.0.5", "eth_src": "bb:bb:bb:bb:bb:bb"})
        self.assertIsNotNone(hit)
        self.assertIn("10.0.0.5", hit["detail"])

    def test_ignores_non_arp_and_requests(self):
        detector = ArpSpoofDetector()
        self.assertIsNone(detector.evaluate({"proto": "tcp"}))
        self.assertIsNone(detector.evaluate({"proto": "arp", "arp_opcode": 1, "src_ip": "10.0.0.5", "eth_src": "aa:aa:aa:aa:aa:aa"}))

    def test_same_mac_is_not_a_conflict(self):
        detector = ArpSpoofDetector()
        pkt = {"proto": "arp", "arp_opcode": 2, "src_ip": "10.0.0.5", "eth_src": "aa:aa:aa:aa:aa:aa"}
        detector.evaluate(pkt)
        self.assertIsNone(detector.evaluate(pkt))

    def test_first_alert_fires_even_on_a_freshly_booted_monotonic_clock(self):
        # Regression test: `time.monotonic()` is relative to an arbitrary
        # reference point (often process/system start on Linux), not
        # guaranteed to already exceed the cooldown window - a short-lived
        # CI runner can have it return a value smaller than
        # ARP_SPOOF_COOLDOWN_SECONDS. Comparing against a `0.0` sentinel for
        # "never alerted" used to suppress the very first, legitimate alert.
        with patch("sniff4hound.anomaly.time.monotonic", return_value=2.5):
            detector = ArpSpoofDetector()
            detector.evaluate({"proto": "arp", "arp_opcode": 2, "src_ip": "10.0.0.5", "eth_src": "aa:aa:aa:aa:aa:aa"})
            hit = detector.evaluate({"proto": "arp", "arp_opcode": 2, "src_ip": "10.0.0.5", "eth_src": "bb:bb:bb:bb:bb:bb"})
        self.assertIsNotNone(hit)


class TestIcmpFloodDetector(unittest.TestCase):
    def test_fires_once_threshold_crossed(self):
        detector = IcmpFloodDetector()
        detector._threshold = 5
        hits = [detector.evaluate({"proto": "icmp", "src_ip": "9.9.9.9"}) for _ in range(5)]
        self.assertTrue(any(hits))
        self.assertEqual(sum(1 for hit in hits if hit), 1)

    def test_ignores_non_icmp(self):
        detector = IcmpFloodDetector()
        self.assertIsNone(detector.evaluate({"proto": "tcp", "src_ip": "9.9.9.9"}))


class TestSynFloodDetector(unittest.TestCase):
    def test_fires_once_threshold_crossed(self):
        detector = SynFloodDetector()
        detector._threshold = 5
        pkt = {"proto": "tcp", "tcp_flags": "SYN", "src_ip": "9.9.9.9"}
        hits = [detector.evaluate(pkt) for _ in range(5)]
        self.assertTrue(any(hits))
        self.assertEqual(sum(1 for hit in hits if hit), 1)

    def test_ignores_syn_ack(self):
        detector = SynFloodDetector()
        detector._threshold = 2
        pkt = {"proto": "tcp", "tcp_flags": "SYN,ACK", "src_ip": "9.9.9.9"}
        self.assertIsNone(detector.evaluate(pkt))
        self.assertIsNone(detector.evaluate(pkt))

    def test_ignores_non_tcp(self):
        detector = SynFloodDetector()
        self.assertIsNone(detector.evaluate({"proto": "udp", "tcp_flags": "SYN", "src_ip": "9.9.9.9"}))


class TestBruteForceLoginDetector(unittest.TestCase):
    def test_fires_once_threshold_crossed_on_login_port(self):
        detector = BruteForceLoginDetector()
        detector._threshold = 4
        pkt = {"proto": "tcp", "tcp_flags": "SYN", "src_ip": "10.0.0.5", "dst_ip": "10.0.0.1", "dst_port": 22}
        hits = [detector.evaluate(pkt) for _ in range(4)]
        self.assertTrue(any(hits))
        self.assertIn("10.0.0.5", hits[-1]["detail"])

    def test_ignores_non_login_port(self):
        detector = BruteForceLoginDetector()
        detector._threshold = 2
        pkt = {"proto": "tcp", "tcp_flags": "SYN", "src_ip": "10.0.0.5", "dst_ip": "10.0.0.1", "dst_port": 8080}
        self.assertIsNone(detector.evaluate(pkt))
        self.assertIsNone(detector.evaluate(pkt))

    def test_ignores_established_connections(self):
        detector = BruteForceLoginDetector()
        detector._threshold = 2
        pkt = {"proto": "tcp", "tcp_flags": "ACK", "src_ip": "10.0.0.5", "dst_ip": "10.0.0.1", "dst_port": 22}
        self.assertIsNone(detector.evaluate(pkt))
        self.assertIsNone(detector.evaluate(pkt))

    def test_first_alert_fires_even_on_a_freshly_booted_monotonic_clock(self):
        # See the matching regression test on TestArpSpoofDetector for why.
        with patch("sniff4hound.anomaly.time.monotonic", return_value=2.5):
            detector = BruteForceLoginDetector()
            detector._threshold = 3
            pkt = {"proto": "tcp", "tcp_flags": "SYN", "src_ip": "10.0.0.5", "dst_ip": "10.0.0.1", "dst_port": 22}
            hits = [detector.evaluate(pkt) for _ in range(3)]
        self.assertTrue(any(hits))


class TestDnsQueryFloodDetector(unittest.TestCase):
    def test_fires_once_threshold_crossed(self):
        detector = DnsQueryFloodDetector()
        detector._threshold = 5
        pkt = {"proto": "udp", "dst_port": 53, "src_ip": "10.0.0.5"}
        hits = [detector.evaluate(pkt) for _ in range(5)]
        self.assertTrue(any(hits))

    def test_ignores_non_dns_port(self):
        detector = DnsQueryFloodDetector()
        self.assertIsNone(detector.evaluate({"proto": "udp", "dst_port": 123, "src_ip": "10.0.0.5"}))


class TestAnomalyEngine(unittest.TestCase):
    def test_disabled_stateful_monitor_is_not_evaluated(self):
        engine = AnomalyEngine()
        monitors = _monitors()
        for monitor in monitors:
            if monitor["id"] == "builtin-arp-spoof":
                monitor["enabled"] = False
        engine.evaluate({"proto": "arp", "arp_opcode": 2, "src_ip": "1.1.1.1", "eth_src": "aa:aa:aa:aa:aa:aa"}, monitors)
        hits = engine.evaluate({"proto": "arp", "arp_opcode": 2, "src_ip": "1.1.1.1", "eth_src": "bb:bb:bb:bb:bb:bb"}, monitors)
        self.assertEqual(hits, [])

    def test_missing_monitor_definition_is_skipped(self):
        engine = AnomalyEngine()
        hits = engine.evaluate({"proto": "arp", "arp_opcode": 2, "src_ip": "1.1.1.1", "eth_src": "aa:aa:aa:aa:aa:aa"}, [])
        self.assertEqual(hits, [])

    def test_hit_shape_matches_evaluate_packet_output(self):
        engine = AnomalyEngine()
        monitors = _monitors()
        engine.evaluate({"proto": "arp", "arp_opcode": 2, "src_ip": "1.1.1.1", "eth_src": "aa:aa:aa:aa:aa:aa"}, monitors)
        hits = engine.evaluate({"proto": "arp", "arp_opcode": 2, "src_ip": "1.1.1.1", "eth_src": "bb:bb:bb:bb:bb:bb"}, monitors)
        self.assertEqual(len(hits), 1)
        hit = hits[0]
        for key in ("monitor_id", "monitor_name", "tag", "label", "severity"):
            self.assertIn(key, hit)
        self.assertEqual(hit["monitor_id"], "builtin-arp-spoof")
        self.assertEqual(hit["severity"], "critical")


class TestSnifferAnomalyIntegration(unittest.TestCase):
    """Verifies the Sniffer._store_packet restructuring: anomaly hits must
    persist a packet even when the declarative monitor filter is on and no
    declarative monitor matched — this is the regression test for the
    "anomaly detectors must run unconditionally" fix."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test.db"
        self.store = SniffStore(self.db_path)
        self.sniffer = Sniffer(self.store, MagicMock(), interfaces=())

    def tearDown(self):
        self.store.close()
        self.temp_dir.cleanup()

    def _arp_packet(self, ip: str, mac: str) -> dict:
        packet = build_base_packet("now", "test0", b"\x00" * 28, b"\x00" * 28, eth_src=mac, eth_dst="ff:ff:ff:ff:ff:ff", eth_type=0x0806)
        packet.update(
            {
                "proto": "arp",
                "arp_opcode": 2,
                "src_ip": ip,
                "dst_ip": "10.0.0.1",
                "ip_version": 0,
                "flow_key": f"arp:{ip}",
                "summary": f"ARP {ip}",
            }
        )
        return packet

    def test_arp_conflict_persists_despite_filter_enabled(self):
        self.assertTrue(self.store.get_monitor_filter_enabled())
        self.sniffer._store_packet(self._arp_packet("10.0.0.5", "aa:aa:aa:aa:aa:aa"))
        self.sniffer._store_packet(self._arp_packet("10.0.0.5", "bb:bb:bb:bb:bb:bb"))
        matched = self.store.list_packets_by_monitor("builtin-arp-spoof")
        self.assertTrue(matched, "expected the second, conflicting ARP packet to be tagged and persisted")


if __name__ == "__main__":
    unittest.main()
