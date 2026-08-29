from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from sniff4hound.sniffer import Sniffer
from sniff4hound.store import SniffStore
from sniff4hound.utils import DETECTION_IP_SCOPES, detection_ip_scope, utc_now


class DetectionIpScopeTests(unittest.TestCase):
    def test_classifies_loopback_separately_from_private(self):
        self.assertEqual(detection_ip_scope("127.0.0.1"), "loopback")
        self.assertEqual(detection_ip_scope("::1"), "loopback")
        self.assertEqual(detection_ip_scope("10.0.0.5"), "private")
        self.assertEqual(detection_ip_scope("192.168.1.1"), "private")

    def test_classifies_rfc1918_ranges_a_prefix_check_would_miss(self):
        for address in ("172.20.3.4", "169.254.1.1", "100.64.0.1"):
            self.assertEqual(detection_ip_scope(address), "private", address)

    def test_classifies_routable_addresses_as_public(self):
        self.assertEqual(detection_ip_scope("8.8.8.8"), "public")
        self.assertEqual(detection_ip_scope("2606:4700::1"), "public")

    def test_unparseable_input_is_unknown(self):
        for value in ("", None, "not-an-ip", "999.1.1.1"):
            self.assertEqual(detection_ip_scope(value), "unknown", repr(value))


class DetectionScopeStoreTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.store = SniffStore(Path(self._tmp.name) / "scopes.db")
        self.addCleanup(self.store.close)

    def test_default_excludes_nothing(self):
        self.assertEqual(self.store.get_detection_exclude_scopes(), [])

    def test_round_trips_and_normalizes(self):
        self.assertEqual(self.store.set_detection_exclude_scopes(["PRIVATE", " loopback "]), ["loopback", "private"])
        self.assertEqual(self.store.get_detection_exclude_scopes(), ["loopback", "private"])

    def test_accepts_a_comma_separated_string(self):
        self.assertEqual(self.store.set_detection_exclude_scopes("public,loopback"), ["loopback", "public"])

    def test_clearing_restores_full_detection(self):
        self.store.set_detection_exclude_scopes(["public"])
        self.assertEqual(self.store.set_detection_exclude_scopes([]), [])

    def test_rejects_an_unknown_scope(self):
        with self.assertRaises(ValueError) as ctx:
            self.store.set_detection_exclude_scopes(["banana"])
        self.assertIn("banana", str(ctx.exception))
        # A rejected write must not partially apply.
        self.assertEqual(self.store.get_detection_exclude_scopes(), [])

    def test_every_advertised_scope_is_accepted(self):
        for scope in DETECTION_IP_SCOPES:
            self.assertEqual(self.store.set_detection_exclude_scopes([scope]), [scope])


class DetectionMuteTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.store = SniffStore(Path(self._tmp.name) / "mute.db")
        self.addCleanup(self.store.close)
        self.sniffer = Sniffer(self.store, MagicMock(), interfaces=[])

    def _mute(self, scopes, src, dst):
        self.sniffer._detection_exclude_scopes = frozenset(scopes)
        return self.sniffer._detection_muted({"src_ip": src, "dst_ip": dst})

    def test_nothing_is_muted_by_default(self):
        self.assertFalse(self._mute([], "127.0.0.1", "127.0.0.1"))
        self.assertFalse(self._mute([], "8.8.8.8", "1.1.1.1"))

    def test_loopback_only_mutes_loopback(self):
        self.assertTrue(self._mute(["loopback"], "127.0.0.1", "127.0.0.1"))
        self.assertFalse(self._mute(["loopback"], "10.0.0.1", "10.0.0.2"))

    def test_private_mutes_lan_to_lan(self):
        self.assertTrue(self._mute(["private"], "10.0.0.1", "192.168.1.5"))

    def test_private_does_not_mute_traffic_leaving_the_lan(self):
        # The whole point: a private host reaching a public address is exactly
        # what an analyst still wants flagged.
        self.assertFalse(self._mute(["private"], "10.0.0.1", "8.8.8.8"))
        self.assertFalse(self._mute(["private"], "8.8.8.8", "10.0.0.1"))

    def test_public_mutes_only_fully_external_traffic(self):
        self.assertTrue(self._mute(["public"], "8.8.8.8", "1.1.1.1"))
        self.assertFalse(self._mute(["public"], "8.8.8.8", "10.0.0.1"))

    def test_combined_scopes_mute_each_side_independently(self):
        self.assertTrue(self._mute(["loopback", "private"], "127.0.0.1", "10.0.0.1"))
        self.assertFalse(self._mute(["loopback", "private"], "10.0.0.1", "8.8.8.8"))

    def test_unclassifiable_endpoints_never_mute(self):
        # ARP and other L2-only frames carry no IP; they must keep detecting.
        for scopes in (["loopback"], ["private"], ["public"], list(DETECTION_IP_SCOPES)):
            self.assertFalse(self._mute(scopes, "", ""), scopes)
            self.assertFalse(self._mute(scopes, "10.0.0.1", ""), scopes)


class ExcludedTrafficPipelineTests(unittest.TestCase):
    """End-to-end: an excluded scope must mute detection without hiding capture."""

    def _sniffer(self, scopes, *, store_only_detected=True):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        store = SniffStore(Path(tmp.name) / "pipeline.db")
        self.addCleanup(store.close)
        store.set_detection_exclude_scopes(scopes)
        store.set_monitor_filter_enabled(store_only_detected)
        sniffer = Sniffer(store, MagicMock(), interfaces=[])
        sniffer._get_monitor_context()  # prime the cache off the store
        return sniffer, store

    def _packet(self, src, dst):
        stamp = utc_now()
        return {
            "src_ip": src, "dst_ip": dst, "proto": "tcp", "dst_port": 80, "src_port": 5555,
            "interface": "lo", "length": 120, "payload_len": 60,
            "created_at": stamp, "updated_at": stamp,
            # Deliberately hits the cleartext-credentials rules.
            "payload_text": "GET /login?user=admin&password=hunter2 HTTP/1.1",
            "summary": "", "banner_text": "", "tags": [], "flow_key": "x",
        }

    def _stored(self, store):
        return {f"{row['src_ip']}->{row['dst_ip']}" for row in store.list_packets(limit=200)}

    def test_excluded_traffic_is_not_tagged_by_rulesets(self):
        # Regression: classify_packet() ran before the scope check, so muted
        # traffic still came out with rule or monitor detections.
        sniffer, _store = self._sniffer(["loopback", "private"])
        packet = self._packet("10.0.0.5", "192.168.1.9")
        sniffer._store_packet(packet)
        tag_keys = {tag.get("key") for tag in packet.get("tags", []) if isinstance(tag, dict)}
        self.assertNotIn("rule", tag_keys)
        self.assertNotIn("monitor", tag_keys)
        self.assertEqual(packet.get("monitor_hits") or [], [])

    def test_excluded_traffic_is_stored_without_detection_tags(self):
        sniffer, store = self._sniffer(["loopback", "private"])
        for src, dst in (("127.0.0.1", "127.0.0.1"), ("10.0.0.5", "192.168.1.9")):
            sniffer._store_packet(self._packet(src, dst))
        self.assertEqual(self._stored(store), {"127.0.0.1->127.0.0.1", "10.0.0.5->192.168.1.9"})
        for row in store.list_packets(limit=200):
            tag_keys = {tag.get("key") for tag in row.get("tags", []) if isinstance(tag, dict)}
            self.assertNotIn("rule", tag_keys)
            self.assertNotIn("monitor", tag_keys)

    def test_excluded_traffic_is_stored_without_detection_even_when_storing_everything(self):
        sniffer, store = self._sniffer(["loopback", "private"], store_only_detected=False)
        for src, dst in (("127.0.0.1", "127.0.0.1"), ("10.0.0.5", "192.168.1.9")):
            sniffer._store_packet(self._packet(src, dst))
        self.assertEqual(self._stored(store), {"127.0.0.1->127.0.0.1", "10.0.0.5->192.168.1.9"})

    def test_traffic_leaving_the_lan_is_still_analysed_and_stored(self):
        sniffer, store = self._sniffer(["loopback", "private"])
        packet = self._packet("10.0.0.5", "8.8.8.8")
        sniffer._store_packet(packet)
        self.assertTrue(packet.get("monitor_hits"), "outbound traffic lost its detections")
        self.assertIn("10.0.0.5->8.8.8.8", self._stored(store))

    def test_nothing_is_dropped_without_an_exclusion(self):
        sniffer, store = self._sniffer([])
        packet = self._packet("127.0.0.1", "127.0.0.1")
        sniffer._store_packet(packet)
        self.assertTrue(packet.get("tags"), "loopback lost its tags with no exclusion set")
        self.assertIn("127.0.0.1->127.0.0.1", self._stored(store))

    def test_excluded_traffic_still_counts_toward_seen_totals(self):
        # The frame did cross the wire; hiding it from the counters would make
        # the capture stats misreport link volume.
        sniffer, _store = self._sniffer(["loopback"])
        before = sniffer.state.packets_seen
        stored_before = sniffer.state.packets_stored
        sniffer._store_packet(self._packet("127.0.0.1", "127.0.0.1"))
        self.assertEqual(sniffer.state.packets_seen, before + 1)
        self.assertEqual(sniffer.state.packets_stored, stored_before + 1)


if __name__ == "__main__":
    unittest.main()
