"""CPU, RAM and storage limits: validation, trip, resume and counters."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sniff4hound import resource_guard
from sniff4hound.resource_guard import ResourceGuard, coerce_limit_settings
from sniff4hound.store import SniffStore


class FakeSniffer:
    def __init__(self):
        self.starts = 0
        self.stops = 0

    def start(self):
        self.starts += 1

    def stop(self):
        self.stops += 1


class LimitValidationTests(unittest.TestCase):
    def test_accepts_partial_values(self):
        self.assertEqual(coerce_limit_settings({"ram_mb": "512", "resume_percent": 70}),
                         {"ram_mb": 512, "resume_percent": 70})

    def test_rejects_out_of_range_null_and_bools(self):
        for values in ({"cpu_percent": 101}, {"resume_percent": 5}, {"ram_mb": None},
                       {"storage_mb": True}, {"sample_seconds": 0}):
            with self.subTest(values=values), self.assertRaises(ValueError):
                coerce_limit_settings(values)


class GuardTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.store = SniffStore(os.path.join(self._tmp.name, "limits.db"))
        self.addCleanup(self.store.close)
        self.sniffer = FakeSniffer()
        self.guard = ResourceGuard(self.store, self.sniffer, log_dir=Path(self._tmp.name))

    def _measure(self, *, cpu=0.0, ram=0.0, storage=0.0):
        return patch.object(self.guard, "measure", return_value={
            "cpu_percent": cpu, "ram_mb": ram, "storage_mb": storage})

    def test_one_sample_over_the_limit_does_not_trip(self):
        self.store.set_limit_config({"ram_mb": 100})
        with self._measure(ram=500):
            self.guard.sample()
        self.assertEqual(self.sniffer.stops, 0)

    def test_two_samples_over_the_limit_stop_capture_and_record_a_trip(self):
        self.store.set_limit_config({"ram_mb": 100})
        with self._measure(ram=500):
            self.guard.sample()
            state = self.guard.sample()
        self.assertEqual(self.sniffer.stops, 1)
        self.assertTrue(state["paused"])
        self.assertEqual(state["reason"], "ram")
        self.assertEqual(state["counters"]["trips"], 1)
        self.assertEqual(state["counters"]["by_kind"]["ram"], 1)

    def test_resumes_automatically_once_back_under_the_threshold(self):
        self.store.set_limit_config({"ram_mb": 100, "resume_percent": 80, "cooldown_seconds": 0})
        with self._measure(ram=500):
            self.guard.sample()
            self.guard.sample()
        with self._measure(ram=85):      # 85 >= 80% of 100: still too close, stay paused
            self.guard.sample()
        self.assertEqual(self.sniffer.starts, 0)
        with self._measure(ram=40):
            state = self.guard.sample()
        self.assertEqual(self.sniffer.starts, 1)
        self.assertFalse(state["paused"])
        self.assertGreaterEqual(state["counters"]["paused_seconds"], 0.0)

    def test_no_resume_before_the_cooldown_even_when_below_threshold(self):
        self.store.set_limit_config({"ram_mb": 100, "cooldown_seconds": 300})
        with self._measure(ram=500):
            self.guard.sample()
            self.guard.sample()
        with self._measure(ram=10):
            self.guard.sample()
        self.assertEqual(self.sniffer.starts, 0)
        self.guard._paused_since -= 301
        with self._measure(ram=10):
            self.guard.sample()
        self.assertEqual(self.sniffer.starts, 1)

    def test_disabled_limits_never_trip(self):
        with self._measure(cpu=99, ram=10**6, storage=10**6):
            for _ in range(5):
                self.guard.sample()
        self.assertEqual(self.sniffer.stops, 0)

    def test_storage_limit_is_checked_too(self):
        self.store.set_limit_config({"storage_mb": 10})
        with self._measure(storage=50):
            self.guard.sample()
            state = self.guard.sample()
        self.assertEqual(state["reason"], "storage")

    def test_reset_zeroes_counters_but_keeps_limits(self):
        self.store.set_limit_config({"cpu_percent": 50})
        with self._measure(cpu=90):
            self.guard.sample()
            self.guard.sample()
        state = self.guard.reset_counters()
        self.assertEqual(state["counters"]["trips"], 0)
        self.assertEqual(self.store.get_limit_config()["cpu_percent"], 50)

    def test_a_pause_left_by_a_previous_process_is_cleared_on_start(self):
        state = self.store.get_limit_state()
        state.update({"paused": True, "reason": "storage"})
        self.store.set_limit_state(state)
        self.guard.start()
        self.guard.stop()
        cleared = self.store.get_limit_state()
        self.assertFalse(cleared["paused"])
        self.assertEqual(cleared["reason"], "")
        self.assertEqual(self.sniffer.starts, 0)

    def test_measure_reports_process_numbers(self):
        values = self.guard.measure()
        self.assertGreaterEqual(values["ram_mb"], 0.0)
        self.assertGreaterEqual(values["storage_mb"], 0.0)
        self.assertGreaterEqual(values["cpu_percent"], 0.0)


if __name__ == "__main__":
    unittest.main()
