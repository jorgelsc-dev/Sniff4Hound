"""Regression tests for FAQA.md findings (Blue Team deep-audit pass).

Each test class is named after the finding it locks in, so a future
regression shows up against the same identifier the audit used. These run
against a temporary SQLite database via SniffStore, never the operator's
live database.
"""

from __future__ import annotations

import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from sniff4hound.export import build_export
from sniff4hound.sniffer import Sniffer
from sniff4hound.store import SniffStore
from sniff4hound.utils import utc_since


def _packet(**overrides) -> dict:
    packet = {
        "src_ip": "10.0.0.10",
        "dst_ip": "192.0.2.9",
        "src_port": 52000,
        "dst_port": 80,
        "proto": "tcp",
        "length": 60,
        "payload_len": 0,
    }
    packet.update(overrides)
    return packet


class StoreRegressionTestCase(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(prefix="s4h-faqa-")
        self.db_path = Path(self.temp_dir.name) / "test.db"
        self.store = SniffStore(self.db_path)

    def tearDown(self):
        self.store.close()
        self.temp_dir.cleanup()


class Finding118IpIntelExactIdentityTests(StoreRegressionTestCase):
    """1.18 - ip_intel() must not mix a queried IP with an unrelated IP that
    merely shares it as a text prefix (old `search=` used LIKE '%ip%')."""

    def test_ip_prefix_is_not_treated_as_a_match(self):
        self.store.register_packet(_packet(src_ip="10.0.0.10", dst_ip="192.0.2.9"))
        result = self.store.ip_intel("10.0.0.1")
        self.assertEqual(result["summary"]["packets"], 0)
        self.assertEqual(result["evidence"]["packets"]["total_available"], 0)

    def test_exact_match_is_still_found(self):
        self.store.register_packet(_packet(src_ip="10.0.0.10", dst_ip="192.0.2.9"))
        result = self.store.ip_intel("10.0.0.10")
        self.assertEqual(result["summary"]["packets"], 1)

    def test_matches_either_direction(self):
        self.store.register_packet(_packet(src_ip="10.0.0.10", dst_ip="192.0.2.9"))
        as_dst = self.store.ip_intel("192.0.2.9")
        self.assertEqual(as_dst["summary"]["packets"], 1)

    def test_ip_mentioned_only_in_summary_text_is_not_counted_as_a_packet(self):
        # A packet between two other hosts whose free-text summary happens to
        # mention the target IP must not read as "this host communicated".
        self.store.register_packet(
            _packet(src_ip="203.0.113.1", dst_ip="203.0.113.2", summary="proxy for 10.0.0.10 seen upstream")
        )
        result = self.store.ip_intel("10.0.0.10")
        self.assertEqual(result["summary"]["packets"], 0)

    def test_rejects_invalid_ip(self):
        with self.assertRaises(ValueError):
            self.store.ip_intel("not-an-ip")

    def test_rejects_empty_ip(self):
        with self.assertRaises(ValueError):
            self.store.ip_intel("")


class Finding119EvidenceSurvivesNoiseTests(StoreRegressionTestCase):
    """1.19 - evidence for the investigated host must not disappear because
    unrelated recent rows pushed it out of a pre-filter LIMIT."""

    def test_payload_for_target_host_survives_255_unrelated_payloads(self):
        target = self.store.register_packet(
            _packet(src_ip="10.0.0.10", dst_ip="192.0.2.9", payload_text="target payload")
        )
        self.assertTrue(target.get("id"))
        for _ in range(255):
            self.store.register_packet(
                _packet(src_ip="198.51.100.5", dst_ip="198.51.100.6", payload_text="unrelated noise")
            )
        result = self.store.ip_intel("10.0.0.10")
        self.assertEqual(result["summary"]["payloads"], 1)
        self.assertEqual(result["evidence"]["payloads"]["returned"], 1)
        self.assertEqual(result["evidence"]["payloads"]["total_available"], 1)
        self.assertFalse(result["evidence"]["payloads"]["truncated"])

    def test_summary_reports_total_not_page_size(self):
        for _ in range(260):
            self.store.register_packet(_packet(src_ip="10.0.0.10", dst_ip="192.0.2.9"))
        result = self.store.ip_intel("10.0.0.10")
        self.assertEqual(result["summary"]["packets"], 260)
        self.assertEqual(result["evidence"]["packets"]["returned"], 250)
        self.assertEqual(result["evidence"]["packets"]["total_available"], 260)
        self.assertTrue(result["evidence"]["packets"]["truncated"])


class Finding129DomainStructuredMatchTests(StoreRegressionTestCase):
    """1.29 - domain investigation must use the structured domain/http_host
    columns, not a free-text substring search that both misses structured
    evidence and picks up incidental text mentions."""

    def test_finds_packet_only_present_in_structured_domain_field(self):
        self.store.register_packet(
            _packet(
                src_ip="10.0.0.5",
                dst_ip="93.184.216.34",
                domain="needle.example",
                domain_source="dns",
                summary="DNS query",
            )
        )
        result = self.store.domain_intel("needle.example")
        self.assertEqual(result["summary"]["packets"], 1)

    def test_incidental_text_mention_is_not_a_match(self):
        self.store.register_packet(
            _packet(
                src_ip="203.0.113.1",
                dst_ip="203.0.113.2",
                domain="unrelated.example",
                payload_text="user visited needle.example via proxy",
            )
        )
        result = self.store.domain_intel("needle.example")
        self.assertEqual(result["summary"]["packets"], 0)

    def test_case_and_trailing_dot_are_normalized(self):
        self.store.register_packet(_packet(domain="needle.example", domain_source="dns"))
        result = self.store.domain_intel("Needle.Example.")
        self.assertEqual(result["summary"]["packets"], 1)

    def test_exact_mode_excludes_subdomains_by_default(self):
        self.store.register_packet(_packet(domain="api.needle.example", domain_source="dns"))
        result = self.store.domain_intel("needle.example")
        self.assertEqual(result["summary"]["packets"], 0)

    def test_subdomain_mode_includes_subdomains(self):
        self.store.register_packet(_packet(domain="api.needle.example", domain_source="dns"))
        result = self.store.domain_intel("needle.example", mode="subdomain")
        self.assertEqual(result["summary"]["packets"], 1)

    def test_matches_http_host_ignoring_port(self):
        self.store.register_packet(
            _packet(http_host="needle.example:8080", http_method="get", http_path="/", domain="")
        )
        result = self.store.domain_intel("needle.example")
        self.assertEqual(result["summary"]["packets"], 1)

    def test_rejects_empty_domain(self):
        with self.assertRaises(ValueError):
            self.store.domain_intel("")


class Finding117AiPacketsSinceFilterTests(StoreRegressionTestCase):
    """1.17 - the AI packet feed must filter by time in SQL so a short
    dashboard window cannot surface rows scored outside it."""

    def test_since_in_the_future_excludes_rows_just_inserted(self):
        self.store.register_packet(_packet())
        future_cutoff = utc_since(-3600)  # one hour from now
        rows = self.store.list_ai_packets(since=future_cutoff)
        self.assertEqual(rows, [])

    def test_since_in_the_past_still_includes_rows(self):
        self.store.register_packet(_packet())
        past_cutoff = utc_since(3600)  # one hour ago
        rows = self.store.list_ai_packets(since=past_cutoff)
        self.assertEqual(len(rows), 1)

    def test_no_since_behaves_as_before(self):
        self.store.register_packet(_packet())
        rows = self.store.list_ai_packets()
        self.assertEqual(len(rows), 1)


class Finding121ExportAlertsScopeTests(StoreRegressionTestCase):
    """1.21 - exporting alerts for one target must not include alerts for a
    different, unrelated host."""

    def _register_alert(self, *, src_ip, dst_ip, monitor="Port scan", severity="high"):
        packet = self.store.register_packet(
            _packet(
                src_ip=src_ip,
                dst_ip=dst_ip,
                tags=[{"key": "monitor", "value": monitor, "severity": severity}],
            )
        )
        return packet

    def test_export_search_excludes_other_hosts_alerts(self):
        self._register_alert(src_ip="192.0.2.1", dst_ip="192.0.2.2")
        self._register_alert(src_ip="203.0.113.1", dst_ip="203.0.113.2")
        payload = build_export(self.store, "alerts", search="203.0.113.250")
        self.assertEqual(payload["rows"], [])

    def test_export_search_includes_only_matching_host(self):
        self._register_alert(src_ip="192.0.2.1", dst_ip="192.0.2.2")
        self._register_alert(src_ip="203.0.113.1", dst_ip="203.0.113.2")
        payload = build_export(self.store, "alerts", search="192.0.2.1")
        ips = {(row["src_ip"], row["dst_ip"]) for row in payload["rows"]}
        self.assertEqual(ips, {("192.0.2.1", "192.0.2.2")})

    def test_export_reports_total_available_and_truncated(self):
        for index in range(3):
            self._register_alert(src_ip="192.0.2.1", dst_ip=f"192.0.2.{10 + index}")
        payload = build_export(self.store, "alerts", limit=1)
        self.assertIn("total_available", payload)
        self.assertIn("truncated", payload)
        self.assertGreaterEqual(payload["total_available"], 3)
        self.assertTrue(payload["truncated"])


class Finding115ListEntryDuplicatesTests(StoreRegressionTestCase):
    """1.15 - whitelist/blacklist entries must not accumulate duplicate
    (category, match_type, value) rows, and pre-existing duplicates from
    before this constraint existed must merge, not just get stuck."""

    def test_create_whitelist_entry_rejects_exact_duplicate(self):
        self.store.create_whitelist_entry("ip", "exact", "10.0.0.5", label="first")
        with self.assertRaises(ValueError):
            self.store.create_whitelist_entry("ip", "exact", "10.0.0.5", label="second")
        self.assertEqual(len(self.store.list_whitelist_entries()), 1)

    def test_create_blacklist_entry_rejects_exact_duplicate(self):
        self.store.create_blacklist_entry("domain", "exact", "evil.example", label="first")
        with self.assertRaises(ValueError):
            self.store.create_blacklist_entry("domain", "exact", "evil.example", label="second")
        self.assertEqual(len(self.store.list_blacklist_entries()), 1)

    def test_different_category_or_match_type_is_not_a_duplicate(self):
        self.store.create_whitelist_entry("ip", "exact", "10.0.0.5", label="a")
        self.store.create_whitelist_entry("domain", "exact", "10.0.0.5", label="b")  # different category
        self.assertEqual(len(self.store.list_whitelist_entries()), 2)

    def test_migration_merges_pre_existing_duplicate_whitelist_entries(self):
        # Simulate a database from before the unique index existed: drop it
        # first (a fresh test store already has it from _create_schema()),
        # then insert two rows create_whitelist_entry() would now refuse.
        now = "2026-01-01T00:00:00+00:00"
        later = "2026-01-01T00:05:00+00:00"
        with self.store._lock:
            self.store._conn.execute("DROP INDEX IF EXISTS idx_whitelist_unique_entry")
            self.store._conn.execute(
                "INSERT INTO whitelist_entries (id, category, match_type, value, label, enabled, created_at, updated_at) "
                "VALUES ('whitelist-ip-a', 'ip', 'exact', '10.0.0.5', 'internal scanner', 1, ?, ?)",
                (now, now),
            )
            self.store._conn.execute(
                "INSERT INTO whitelist_entries (id, category, match_type, value, label, enabled, created_at, updated_at) "
                "VALUES ('whitelist-ip-b', 'ip', 'exact', '10.0.0.5', '', 1, ?, ?)",
                (later, later),
            )
            self.store._conn.commit()
        self.assertEqual(len(self.store.list_whitelist_entries()), 2)

        self.store._create_schema()  # re-run migrations, as __init__ does on every open

        rows = self.store.list_whitelist_entries()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["id"], "whitelist-ip-a")  # earliest created_at kept
        self.assertEqual(rows[0]["label"], "internal scanner")

    def test_unique_index_exists_after_migration(self):
        indexes = {
            row["name"]
            for row in self.store._conn.execute("PRAGMA index_list(whitelist_entries)")
        }
        self.assertIn("idx_whitelist_unique_entry", indexes)


class Finding124AiTrainingWorkerLifecycleTests(StoreRegressionTestCase):
    """1.24 - the AI training worker must be a thread `stop()` actually
    signals and joins, not an un-tracked `while True` daemon that outlives
    every stop()/restart() cycle (and, per 1.5, the most likely source of
    writes racing a test's TemporaryDirectory cleanup)."""

    def setUp(self):
        super().setUp()
        self.sniffer = Sniffer(self.store, MagicMock(), interfaces=())

    def _wait_until(self, predicate, *, timeout=2.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return True
            time.sleep(0.02)
        return predicate()

    def test_worker_processes_queued_feedback_and_stop_joins_it(self):
        saved = self.store.register_packet(_packet(raw_packet=b"\x01\x02\x03\x04" * 16))
        self.sniffer._enqueue_ai_training(saved["id"], "malicious", 0.9, "test")
        self.assertTrue(
            self._wait_until(lambda: self.sniffer.ai_training_stats()["processed"] == 1),
            "training worker never processed the queued example",
        )
        worker = self.sniffer._ai_training_thread
        self.assertIsNotNone(worker)
        self.sniffer.stop()
        self.assertFalse(worker.is_alive(), "stop() must join the AI training worker thread")

    def test_repeated_start_stop_leaves_no_training_worker_threads_alive(self):
        for _ in range(5):
            saved = self.store.register_packet(_packet(raw_packet=b"\x01\x02\x03\x04" * 16))
            self.sniffer._enqueue_ai_training(saved["id"], "benign", 0.4, "test")
            self._wait_until(lambda: self.sniffer.ai_training_stats()["processed"] >= 1)
            self.sniffer.stop()
        self.assertFalse(
            any(thread.name == "sniff4hound-ai-training" and thread.is_alive() for thread in threading.enumerate()),
            "an AI training worker thread survived stop()",
        )

    def test_full_queue_is_counted_as_dropped_not_silently_lost(self):
        # Pretend a worker is already running so _enqueue_ai_training only
        # exercises the put_nowait()/queue.Full path, not thread startup -
        # keeps this deterministic instead of racing a real consumer thread.
        self.sniffer._ai_training_thread_started = True
        while not self.sniffer._ai_training_queue.full():
            self.sniffer._ai_training_queue.put_nowait((0, "benign", 0.1, "probe"))
        self.sniffer._enqueue_ai_training(0, "benign", 0.1, "probe-over-capacity")
        self.assertEqual(self.sniffer.ai_training_stats()["dropped"], 1)


if __name__ == "__main__":
    unittest.main()
