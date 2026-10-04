"""Packet cache, pipeline settings and the sniffer's capture -> jobs hand-off."""

from __future__ import annotations

import os
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch

from sniff4hound.packet_pipeline import (
    PACKET_CACHE_LIMIT_DEFAULT,
    PACKET_CACHE_LIMIT_MAX,
    PACKET_CACHE_LIMIT_MIN,
    PACKET_JOBS_DEFAULT,
    PACKET_JOBS_MAX,
    PacketCache,
    coerce_pipeline_settings,
)
from sniff4hound.sniffer import Sniffer
from sniff4hound.store import SniffStore


class PacketCacheTests(unittest.TestCase):
    def test_full_cache_evicts_oldest_and_counts_it(self):
        cache = PacketCache(limit=3)
        for number in range(5):
            self.assertTrue(cache.put(number))
        self.assertEqual(len(cache), 3)
        self.assertEqual(cache.dropped, 2)
        self.assertEqual(cache.accepted, 5)
        # The retained window is the newest packets, oldest first.
        self.assertEqual([cache.get(0) for _ in range(3)], [2, 3, 4])

    def test_get_times_out_empty(self):
        cache = PacketCache(limit=3)
        self.assertIsNone(cache.get(timeout=0.01))

    def test_shrinking_limit_evicts_immediately(self):
        cache = PacketCache(limit=5)
        for number in range(5):
            cache.put(number)
        cache.set_limit(2)
        self.assertEqual(cache.limit, 2)
        self.assertEqual(len(cache), 2)
        self.assertEqual(cache.dropped, 3)
        self.assertEqual([cache.get(0), cache.get(0)], [3, 4])

    def test_close_discards_waiting_items_and_refuses_new_ones(self):
        cache = PacketCache(limit=5)
        cache.put("a")
        cache.close()
        self.assertTrue(cache.closed)
        self.assertFalse(cache.put("b"))
        self.assertIsNone(cache.get(timeout=0.01))

    def test_blocked_consumer_wakes_on_put(self):
        cache = PacketCache(limit=5)
        received = []
        consumer = threading.Thread(target=lambda: received.append(cache.get(timeout=2)))
        consumer.start()
        cache.put("packet")
        consumer.join(timeout=2)
        self.assertEqual(received, ["packet"])


class PipelineSettingsValidationTests(unittest.TestCase):
    def test_accepts_partial_valid_values(self):
        self.assertEqual(
            coerce_pipeline_settings({"cache_limit": "5000", "jobs": 4, "persist_mode": "ALL"}),
            {"cache_limit": 5000, "jobs": 4, "persist_mode": "all"},
        )

    def test_rejects_out_of_range_and_wrong_types(self):
        bad = [
            {"cache_limit": PACKET_CACHE_LIMIT_MIN - 1},
            {"cache_limit": PACKET_CACHE_LIMIT_MAX + 1},
            {"jobs": 0},
            {"jobs": PACKET_JOBS_MAX + 1},
            {"jobs": True},
            {"jobs": "many"},
            {"persist_mode": "some"},
        ]
        for values in bad:
            with self.subTest(values=values), self.assertRaises(ValueError):
                coerce_pipeline_settings(values)

    def test_rejects_non_object_payload(self):
        with self.assertRaises(ValueError):
            coerce_pipeline_settings([1, 2])


class PipelineStoreConfigTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.store = SniffStore(os.path.join(self._tmp.name, "pipeline.db"))
        self.addCleanup(self.store.close)

    def test_defaults_when_never_set(self):
        self.assertEqual(
            self.store.get_packet_pipeline_config(),
            {"cache_limit": PACKET_CACHE_LIMIT_DEFAULT, "jobs": PACKET_JOBS_DEFAULT, "persist_mode": "alerts"},
        )

    def test_round_trip_keeps_untouched_fields(self):
        saved = self.store.set_packet_pipeline_config({"jobs": 6})
        self.assertEqual(saved["jobs"], 6)
        self.assertEqual(saved["cache_limit"], PACKET_CACHE_LIMIT_DEFAULT)
        saved = self.store.set_packet_pipeline_config({"cache_limit": 40000, "persist_mode": "all"})
        self.assertEqual(saved, {"cache_limit": 40000, "jobs": 6, "persist_mode": "all"})

    def test_invalid_update_is_rejected_and_nothing_is_written(self):
        self.store.set_packet_pipeline_config({"jobs": 3})
        with self.assertRaises(ValueError):
            self.store.set_packet_pipeline_config({"jobs": 3, "cache_limit": 1})
        self.assertEqual(self.store.get_packet_pipeline_config()["jobs"], 3)


class CaptureHandOffTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.store = SniffStore(os.path.join(self._tmp.name, "handoff.db"))
        self.addCleanup(self.store.close)
        self.sniffer = Sniffer(self.store, hub=None)

    def test_without_running_pipeline_packets_are_evaluated_inline(self):
        seen = []
        self.sniffer._store_packet = seen.append
        self.sniffer._enqueue_packet({"id": 1})
        self.assertEqual(seen, [{"id": 1}])

    def test_running_pipeline_queues_and_jobs_process_packets(self):
        processed = []
        done = threading.Event()

        def fake_store(packet):
            processed.append(packet["n"])
            if len(processed) == 3:
                done.set()

        self.sniffer._store_packet = fake_store
        self.sniffer._packet_cache = PacketCache(limit=10)
        job = threading.Thread(target=self.sniffer._pipeline_worker, args=(self.sniffer._packet_cache,), daemon=True)
        job.start()
        for number in range(3):
            self.sniffer._enqueue_packet({"n": number})
        self.assertTrue(done.wait(timeout=2))
        self.sniffer._packet_cache.close()
        job.join(timeout=2)
        self.assertEqual(processed, [0, 1, 2])
        self.assertFalse(job.is_alive())

    def test_snapshot_reports_pipeline_state(self):
        self.store.set_packet_pipeline_config({"cache_limit": 2000, "persist_mode": "all"})
        self.sniffer._pipeline_persist_all = True
        self.sniffer._packet_cache = PacketCache(limit=2000)
        self.sniffer._packet_cache.put({"n": 1})
        info = self.sniffer._pipeline_snapshot()
        self.assertEqual(info["cache_limit"], 2000)
        self.assertEqual(info["cache_depth"], 1)
        self.assertEqual(info["persist_mode"], "all")


class PipelineCountersTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.store = SniffStore(os.path.join(self._tmp.name, "counters.db"))
        self.addCleanup(self.store.close)
        self.sniffer = Sniffer(self.store, hub=None)

    def test_reset_zeroes_cache_and_job_counters_but_keeps_waiting_packets(self):
        cache = PacketCache(limit=2)
        for number in range(4):
            cache.put(number)
        self.sniffer._packet_cache = cache
        self.sniffer._count_pipeline("processed", 5)
        self.sniffer._count_pipeline("persisted", 2)
        self.sniffer._count_pipeline("errors")
        before = self.sniffer._pipeline_snapshot()
        self.assertEqual((before["cache_dropped"], before["cache_peak"], before["processed"]), (2, 2, 5))
        self.assertEqual(before["skipped"], 3)

        after = self.sniffer.reset_pipeline_counters()
        self.assertEqual(
            (after["cache_accepted"], after["cache_dropped"], after["cache_peak"]),
            (0, 0, 2),
        )
        self.assertEqual((after["processed"], after["persisted"], after["skipped"], after["errors"]), (0, 0, 0, 0))
        self.assertEqual(after["cache_depth"], 2)
        self.assertTrue(after["since"])

    def test_pipeline_worker_counts_processed_and_errors(self):
        cache = PacketCache(limit=10)
        calls = []

        def flaky(packet):
            calls.append(packet)
            if packet == "bad":
                raise RuntimeError("boom")

        self.sniffer._store_packet = flaky
        for item in ("ok", "bad", "ok2"):
            cache.put(item)
        worker = threading.Thread(target=self.sniffer._pipeline_worker, args=(cache,), daemon=True)
        worker.start()
        deadline = threading.Event()
        for _ in range(100):
            info = self.sniffer._pipeline_snapshot()
            if info["processed"] + info["errors"] == 3:
                break
            deadline.wait(0.02)
        cache.close()
        worker.join(timeout=2)
        self.assertEqual((info["processed"], info["errors"]), (2, 1))


class WriteBatchTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.store = SniffStore(os.path.join(self._tmp.name, "batch.db"))
        self.addCleanup(self.store.close)
        self.sniffer = Sniffer(self.store, hub=None)
        raw = bytes.fromhex("45000028A74A40004006D78D0A0D0D03B5E1EF068A5201BB6349235CF2E6C49250100133BC120000")
        self.packet = self.sniffer.parse_packet(raw, interface="wlan0")

    def _count(self):
        return self.store._fetchone("SELECT COUNT(*) AS n FROM packets")["n"]

    def test_batch_commits_all_packets_together(self):
        with self.store.write_batch():
            for _ in range(5):
                self.store.register_packet(dict(self.packet), allow_raw_retention=False)
            self.assertEqual(self._count(), 5)
        self.assertEqual(self._count(), 5)

    def test_register_packets_lands_the_whole_list_and_returns_one_row_each(self):
        outcomes = self.store.register_packets([(dict(self.packet), False) for _ in range(4)])
        self.assertEqual(len(outcomes), 4)
        self.assertTrue(all(isinstance(row, dict) and row.get("id") for row in outcomes))
        self.assertEqual(self._count(), 4)

    def test_failed_packet_inside_batch_is_undone_alone(self):
        original = self.store._write_packet_rows
        calls = {"n": 0}

        def flaky(*args, **kwargs):
            calls["n"] += 1
            if calls["n"] == 2:
                # Simulate a failure after the packet row was already inserted.
                original(*args, **kwargs)
                raise sqlite3.OperationalError("disk I/O error")
            return original(*args, **kwargs)

        with patch.object(self.store, "_write_packet_rows", side_effect=flaky):
            with self.store.write_batch():
                for _ in range(3):
                    try:
                        self.store.register_packet(dict(self.packet), allow_raw_retention=False)
                    except sqlite3.OperationalError:
                        pass
        # Three attempts, one failed: two packets land, the failed one leaves no row.
        self.assertEqual(self._count(), 2)

    def test_exception_outside_savepoints_rolls_the_whole_batch_back(self):
        with self.assertRaises(RuntimeError):
            with self.store.write_batch():
                self.store.register_packet(dict(self.packet), allow_raw_retention=False)
                raise RuntimeError("batch aborted")
        self.assertEqual(self._count(), 0)

    def test_job_counts_write_errors_separately_from_evaluation_errors(self):
        calls = {"n": 0}

        def store_packet(packet):
            calls["n"] += 1
            if calls["n"] == 1:
                raise sqlite3.OperationalError("database is locked")
            if calls["n"] == 2:
                raise ValueError("bad frame")

        self.sniffer._store_packet = store_packet
        self.sniffer._process_batch([{"n": 1}, {"n": 2}, {"n": 3}])
        info = self.sniffer._pipeline_snapshot()
        self.assertEqual((info["write_errors"], info["errors"], info["processed"]), (1, 1, 1))

    def test_store_lock_is_free_between_packets_of_a_batch(self):
        # The store connection is shared with the API. A batch that held the
        # store lock across its evaluation parked every API request behind it.
        seen = []

        def probe_lock():
            if self.store._lock.acquire(timeout=1):
                self.store._lock.release()
                seen.append(True)
            else:
                seen.append(False)

        def store_packet(packet):
            probe = threading.Thread(target=probe_lock)
            probe.start()
            probe.join(timeout=2)

        self.sniffer._store_packet = store_packet
        self.sniffer._process_batch([{"n": 1}, {"n": 2}, {"n": 3}])
        self.assertEqual(seen, [True, True, True])
        self.assertEqual(self.sniffer._pipeline_snapshot()["processed"], 3)


class RetentionPolicyTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.store = SniffStore(os.path.join(self._tmp.name, "retention.db"))
        self.addCleanup(self.store.close)

    def test_defaults_come_from_the_environment_values(self):
        policy = self.store.get_retention_config()
        self.assertEqual(policy["retention_max_packets"], policy["defaults"]["retention_max_packets"])
        self.assertEqual(policy["table_limits"]["tags"], policy["retention_max_packets"] * 2)
        self.assertEqual(policy["overridden"], [])

    def test_base_change_moves_tables_without_an_override(self):
        policy = self.store.set_retention_config({"retention_max_packets": 5000})
        self.assertEqual(policy["table_limits"]["packets"], 5000)
        self.assertEqual(policy["table_limits"]["tags"], 10000)

    def test_table_override_wins_over_the_base_and_null_clears_it(self):
        policy = self.store.set_retention_config({"table_limits": {"packets": 7000}})
        self.assertEqual(policy["table_limits"]["packets"], 7000)
        self.assertIn("limit_packets", policy["overridden"])
        policy = self.store.set_retention_config({"table_limits": {"packets": None}})
        self.assertEqual(policy["table_limits"]["packets"], policy["retention_max_packets"])
        self.assertNotIn("limit_packets", policy["overridden"])

    def test_invalid_field_rejects_the_whole_update(self):
        before = self.store.get_retention_config()
        with self.assertRaises(ValueError):
            self.store.set_retention_config({"retention_days": 3, "retention_interval_seconds": 1})
        self.assertEqual(self.store.get_retention_config()["retention_days"], before["retention_days"])

    def test_rejects_unknown_tables_and_bools(self):
        with self.assertRaises(ValueError):
            self.store.set_retention_config({"table_limits": {"users": 10}})
        with self.assertRaises(ValueError):
            self.store.set_retention_config({"retention_days": True})

    def test_sweep_trims_to_the_configured_limit(self):
        self.store.set_retention_config({"table_limits": {"sessions": 100}})
        for _ in range(150):
            self.store.create_session({"network": "10.0.0.0/8", "type": "all", "proto": "all", "port_mode": "preset"})
        self.store.enforce_retention()
        count = self.store._fetchone("SELECT COUNT(*) AS n FROM sessions")["n"]
        self.assertLessEqual(count, 100)


if __name__ == "__main__":
    unittest.main()
