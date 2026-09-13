from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sniff4hound.monitors import evaluate_packet
from sniff4hound.sniffer import Sniffer
from sniff4hound.store import SniffStore


def _packet(**overrides) -> dict:
    base = {
        "proto": "tcp",
        "src_ip": "10.0.0.5",
        "dst_ip": "10.0.0.1",
        "src_port": 51234,
        "dst_port": 80,
        "summary": "",
        "payload_text": "",
        "eth_src": "",
        "eth_dst": "",
    }
    base.update(overrides)
    return base


class _Hub:
    def __init__(self):
        self.events = []

    def broadcast(self, event):
        self.events.append(event)


class TestBlacklistEntries(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.store = SniffStore(Path(self.temp_dir.name) / "test.db")

    def tearDown(self):
        self.store.close()
        self.temp_dir.cleanup()

    def test_create_rejects_unknown_category(self):
        with self.assertRaises(ValueError):
            self.store.create_blacklist_entry("mac", "exact", "aa:bb:cc:dd:ee:ff")

    def test_create_rejects_invalid_regex(self):
        with self.assertRaises(ValueError):
            self.store.create_blacklist_entry("path", "regex", "(unterminated")

    def test_create_rejects_redos_risk_regex(self):
        with self.assertRaises(ValueError):
            self.store.create_blacklist_entry("domain", "regex", r"(a+)+$")

    def test_create_rejects_empty_value(self):
        with self.assertRaises(ValueError):
            self.store.create_blacklist_entry("ip", "exact", "   ")

    def test_create_rejects_invalid_exact_port(self):
        with self.assertRaises(ValueError):
            self.store.create_blacklist_entry("port", "exact", "70000")

    def test_create_mirrors_a_monitor(self):
        entry = self.store.create_blacklist_entry("ip", "exact", "203.0.113.5", label="Known bad actor")
        monitor = self.store.get_monitor(entry["id"])
        self.assertIsNotNone(monitor)
        self.assertEqual(monitor["source"], "blacklist")
        self.assertTrue(monitor["enabled"])
        self.assertEqual(monitor["action"]["severity"], "critical")

    def test_exact_match_is_word_boundary_anchored_not_substring(self):
        # A naive `payload_contains` substring match on "1.2.3.4" would also
        # false-positive against an unrelated IP like "21.2.3.45" that merely
        # contains those digits - the word-boundary regex form must not.
        entry = self.store.create_blacklist_entry("ip", "exact", "1.2.3.4")
        monitor = self.store.get_monitor(entry["id"])
        unrelated = _packet(src_ip="21.2.3.45", dst_ip="10.0.0.1")
        self.assertEqual(evaluate_packet(unrelated, [monitor]), [])
        matching = _packet(src_ip="1.2.3.4", dst_ip="10.0.0.1")
        hits = evaluate_packet(matching, [monitor])
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["monitor_id"], entry["id"])

    def test_regex_match_uses_pattern_verbatim(self):
        entry = self.store.create_blacklist_entry("domain", "regex", r"evil-[a-z]+\.example\.com")
        monitor = self.store.get_monitor(entry["id"])
        hit_packet = _packet(summary="connecting to evil-xyz.example.com")
        self.assertEqual(len(evaluate_packet(hit_packet, [monitor])), 1)
        miss_packet = _packet(summary="connecting to good.example.com")
        self.assertEqual(evaluate_packet(miss_packet, [monitor]), [])

    def test_exact_path_match_handles_leading_slash(self):
        entry = self.store.create_blacklist_entry("path", "exact", "/wp-admin/setup-config.php")
        monitor = self.store.get_monitor(entry["id"])
        hit_packet = _packet(http_path="/wp-admin/setup-config.php")
        self.assertEqual(len(evaluate_packet(hit_packet, [monitor])), 1)
        miss_packet = _packet(http_path="/not-wp-admin/setup-config.php")
        self.assertEqual(evaluate_packet(miss_packet, [monitor]), [])

    def test_exact_port_match_uses_transport_ports(self):
        entry = self.store.create_blacklist_entry("port", "exact", "3389")
        monitor = self.store.get_monitor(entry["id"])
        hit_packet = _packet(dst_port=3389)
        self.assertEqual(len(evaluate_packet(hit_packet, [monitor])), 1)
        miss_packet = _packet(dst_port=3390)
        self.assertEqual(evaluate_packet(miss_packet, [monitor]), [])

    def test_exact_protocol_match_uses_proto_and_transport(self):
        entry = self.store.create_blacklist_entry("protocol", "exact", "HTTP")
        monitor = self.store.get_monitor(entry["id"])
        hit_packet = _packet(proto="http", transport="tcp")
        self.assertEqual(len(evaluate_packet(hit_packet, [monitor])), 1)
        transport_hit_packet = _packet(proto="tls", transport="http")
        self.assertEqual(len(evaluate_packet(transport_hit_packet, [monitor])), 1)
        miss_packet = _packet(proto="dns", transport="udp")
        self.assertEqual(evaluate_packet(miss_packet, [monitor]), [])

    def test_regex_port_and_protocol_entries_match_direct_fields(self):
        port_entry = self.store.create_blacklist_entry("port", "regex", r"^33\d{2}$")
        protocol_entry = self.store.create_blacklist_entry("protocol", "regex", r"^ht")
        port_monitor = self.store.get_monitor(port_entry["id"])
        protocol_monitor = self.store.get_monitor(protocol_entry["id"])
        self.assertEqual(len(evaluate_packet(_packet(dst_port=3389), [port_monitor])), 1)
        self.assertEqual(len(evaluate_packet(_packet(proto="http"), [protocol_monitor])), 1)

    def test_disable_disables_the_mirrored_monitor(self):
        entry = self.store.create_blacklist_entry("path", "exact", "/wp-admin/setup-config.php")
        self.store.set_blacklist_entry_enabled(entry["id"], False)
        monitor = self.store.get_monitor(entry["id"])
        self.assertFalse(monitor["enabled"])
        updated_entry = self.store.get_blacklist_entry(entry["id"])
        self.assertFalse(updated_entry["enabled"])

    def test_delete_removes_both_entry_and_monitor(self):
        entry = self.store.create_blacklist_entry("ip", "exact", "198.51.100.9")
        self.store.delete_blacklist_entry(entry["id"])
        self.assertIsNone(self.store.get_blacklist_entry(entry["id"]))
        self.assertIsNone(self.store.get_monitor(entry["id"]))

    def test_delete_unknown_id_raises(self):
        with self.assertRaises(ValueError):
            self.store.delete_blacklist_entry("blacklist-ip-does-not-exist")

    def test_list_filters_by_category(self):
        self.store.create_blacklist_entry("ip", "exact", "203.0.113.1")
        self.store.create_blacklist_entry("domain", "exact", "evil.example.com")
        ip_entries = self.store.list_blacklist_entries("ip")
        self.assertEqual(len(ip_entries), 1)
        self.assertEqual(ip_entries[0]["category"], "ip")
        all_entries = self.store.list_blacklist_entries()
        self.assertEqual(len(all_entries), 2)


class TestWhitelistEntries(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.store = SniffStore(Path(self.temp_dir.name) / "test.db")

    def tearDown(self):
        self.store.close()
        self.temp_dir.cleanup()

    def test_create_rejects_unknown_category(self):
        with self.assertRaises(ValueError):
            self.store.create_whitelist_entry("mac", "exact", "aa:bb:cc:dd:ee:ff")

    def test_create_rejects_invalid_regex(self):
        with self.assertRaises(ValueError):
            self.store.create_whitelist_entry("domain", "regex", "(unterminated")

    def test_create_rejects_redos_risk_regex(self):
        with self.assertRaises(ValueError):
            self.store.create_whitelist_entry("domain", "regex", r"(a+)+$")

    def test_create_rejects_empty_value(self):
        with self.assertRaises(ValueError):
            self.store.create_whitelist_entry("ip", "exact", "   ")

    def test_create_rejects_invalid_exact_port(self):
        with self.assertRaises(ValueError):
            self.store.create_whitelist_entry("port", "exact", "ssh")

    def test_create_toggle_delete_and_filter(self):
        ip_entry = self.store.create_whitelist_entry("ip", "exact", "203.0.113.8")
        self.store.create_whitelist_entry("domain", "exact", "trusted.example.com")
        self.assertEqual(len(self.store.list_whitelist_entries("ip")), 1)
        self.assertEqual(len(self.store.list_whitelist_entries()), 2)

        disabled = self.store.set_whitelist_entry_enabled(ip_entry["id"], False)
        self.assertFalse(disabled["enabled"])

        self.store.delete_whitelist_entry(ip_entry["id"])
        self.assertIsNone(self.store.get_whitelist_entry(ip_entry["id"]))

    def test_whitelisted_ip_traffic_is_not_persisted_at_all(self):
        # Whitelisting an IP is a deliberate "stop tracking this host"
        # action (unlike a mute/exclusion scope, which still stores traffic
        # untagged for capture visibility - see ExcludedTrafficPipelineTests
        # in test_detection_scopes.py): once whitelisted, its traffic is
        # dropped outright, same as clean/undetected traffic.
        self.store.create_whitelist_entry("ip", "exact", "10.0.0.5")
        sniffer = Sniffer(self.store, _Hub(), interfaces=())
        sniffer._monitor_cache = [
            {
                "id": "always-hit",
                "name": "Always hit",
                "enabled": True,
                "mode": "rule",
                "match": {"ports": [80]},
                "action": {"tag": "always-hit", "label": "Always hit", "severity": "critical"},
            }
        ]
        sniffer._whitelist_cache = self.store.list_whitelist_entries()
        sniffer._monitor_filter_enabled = True
        sniffer._monitor_cache_at = 999999999.0
        sniffer._store_packet(_packet(src_ip="10.0.0.5", dst_port=80))

        self.assertEqual(self.store.list_packets(limit=10), [])
        self.assertEqual(self.store.list_tags(limit=20), [])

    def test_whitelist_port_and_protocol_suppress_persistence(self):
        sniffer = Sniffer(self.store, _Hub(), interfaces=())
        sniffer._monitor_cache = [
            {
                "id": "always-hit",
                "name": "Always hit",
                "enabled": True,
                "mode": "rule",
                "match": {"ports": [80]},
                "action": {"tag": "always-hit", "label": "Always hit", "severity": "critical"},
            }
        ]
        sniffer._monitor_filter_enabled = True
        sniffer._monitor_cache_at = 999999999.0

        self.store.create_whitelist_entry("port", "exact", "80")
        sniffer._whitelist_cache = self.store.list_whitelist_entries()
        sniffer._store_packet(_packet(dst_port=80))
        self.assertEqual(self.store.list_packets(limit=20), [])

        self.store.create_whitelist_entry("protocol", "exact", "http")
        sniffer._whitelist_cache = self.store.list_whitelist_entries()
        sniffer._store_packet(_packet(proto="http", transport="tcp", dst_port=80))
        self.assertEqual(self.store.list_packets(limit=40), [])

    def test_purge_ip_data_removes_only_that_ips_rows(self):
        target = self.store.register_packet(
            _packet(src_ip="10.0.0.5", dst_ip="10.0.0.1", tags=[{"key": "monitor", "value": "hit"}])
        )
        other = self.store.register_packet(_packet(src_ip="10.0.0.9", dst_ip="10.0.0.1"))
        self.store.record_domain(name="evil.example", ip="10.0.0.5")
        self.store.record_domain(name="fine.example", ip="10.0.0.9")
        self.store.record_path(path="/x", ip="10.0.0.5")
        self.store.record_path(path="/y", ip="10.0.0.9")

        result = self.store.purge_ip_data("10.0.0.5")

        self.assertEqual(result["packets"], 1)
        self.assertEqual(result["domains"], 1)
        self.assertEqual(result["paths"], 1)
        remaining_ids = {row["id"] for row in self.store.list_packets(limit=20)}
        self.assertEqual(remaining_ids, {other["id"]})
        self.assertEqual([row["name"] for row in self.store.list_domains(limit=20)], ["fine.example"])
        self.assertEqual([row["path"] for row in self.store.list_paths(limit=20)], ["/y"])
        self.assertEqual(self.store.list_tags(limit=20), [])


class TestWhitelistIpEndpoint(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.store = SniffStore(Path(self.temp_dir.name) / "test.db")

    def tearDown(self):
        self.store.close()
        self.temp_dir.cleanup()

    def _call(self, body):
        from wsbuilder import Request
        from sniff4hound import app as module

        request = Request("POST", "/api/whitelist/ip", "", {}, json.dumps(body).encode(), ("127.0.0.1", 0))
        with patch.object(module, "store", self.store):
            return module.whitelist_ip(request)

    def test_without_confirm_reports_count_and_does_not_delete(self):
        self.store.register_packet(_packet(src_ip="10.0.0.5", dst_ip="10.0.0.1"))
        self.store.register_packet(_packet(src_ip="10.0.0.5", dst_ip="10.0.0.2"))

        payload = self._call({"ip": "10.0.0.5"})

        self.assertEqual(payload["status"], "confirm_required")
        self.assertEqual(payload["packets"], 2)
        self.assertEqual(self.store.list_whitelist_entries("ip"), [])
        self.assertEqual(len(self.store.list_packets(limit=10)), 2)

    def test_with_confirm_whitelists_and_purges(self):
        self.store.register_packet(_packet(src_ip="10.0.0.5", dst_ip="10.0.0.1"))
        self.store.register_packet(_packet(src_ip="10.0.0.9", dst_ip="10.0.0.1"))

        payload = self._call({"ip": "10.0.0.5", "confirm": True})

        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["purged"]["packets"], 1)
        entries = self.store.list_whitelist_entries("ip")
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["value"], "10.0.0.5")
        remaining = self.store.list_packets(limit=10)
        self.assertEqual(len(remaining), 1)
        self.assertEqual(remaining[0]["src_ip"], "10.0.0.9")

    def test_missing_ip_is_rejected(self):
        with self.assertRaises(ValueError):
            self._call({})


if __name__ == "__main__":
    unittest.main()
