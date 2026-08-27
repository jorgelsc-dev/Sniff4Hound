"""Sniffer and honeypot as independent engines.

The runtime used to guarantee exactly one active engine: starting the
honeypot stopped the sniffer, and switching mode stopped whatever was
running. Both write into the same store - the honeypot under its
`honeypot:<port>` pseudo-interfaces - so running them together was a policy,
not a technical limit. These tests pin all four combinations, and pin that
the single-engine calls existing callers already send keep behaving exactly
as they did.
"""

from __future__ import annotations

import unittest

from sniff4hound.runtime_controller import RuntimeController


class _FakeEngine:
    def __init__(self, name):
        self.name = name
        self.running = False
        self.starts = 0
        self.stops = 0

    def start(self):
        self.running = True
        self.starts += 1

    def stop(self):
        self.running = False
        self.stops += 1

    def restart(self):
        self.stop()
        self.start()

    def snapshot(self):
        return {"running": self.running, "selected_interfaces": [], "errors": {}}

    def set_interfaces(self, interfaces):
        return list(interfaces or [])


class _FakeStore:
    def __init__(self):
        self.config = {}

    def set_runtime_config(self, key, value):
        self.config[key] = value

    def get_runtime_config(self, key, default=""):
        return self.config.get(key, default)


class _FakeHub:
    def __init__(self):
        self.messages = []

    def broadcast(self, payload):
        self.messages.append(payload)


class ConcurrentEngineTests(unittest.TestCase):
    def setUp(self):
        self.sniffer = _FakeEngine("sniffer")
        self.honeypot = _FakeEngine("honeypot")
        self.hub = _FakeHub()
        self.runtime = RuntimeController(
            store=_FakeStore(),
            sniffer=self.sniffer,
            honeypot=self.honeypot,
            hub=self.hub,
            capture_auto_start=False,
        )

    def _running(self):
        return set(self.runtime.snapshot()["running_engines"])

    # --- the four combinations ------------------------------------------
    def test_neither_engine_runs_by_default(self):
        self.assertEqual(self._running(), set())
        self.assertFalse(self.runtime.snapshot()["concurrent"])

    def test_only_the_sniffer(self):
        self.runtime.start("sniffer")
        self.assertEqual(self._running(), {"sniffer"})

    def test_only_the_honeypot(self):
        self.runtime.start("honeypot")
        self.assertEqual(self._running(), {"honeypot"})

    def test_both_at_once(self):
        self.runtime.start("sniffer")
        self.runtime.start("honeypot")
        self.assertEqual(self._running(), {"sniffer", "honeypot"})
        self.assertTrue(self.runtime.snapshot()["concurrent"])

    def test_starting_one_never_stops_the_other(self):
        self.runtime.start("sniffer")
        self.runtime.start("honeypot")
        self.assertEqual(self.sniffer.stops, 0, "the sniffer was stopped by starting the honeypot")

    def test_stopping_one_leaves_the_other_running(self):
        self.runtime.start("sniffer")
        self.runtime.start("honeypot")
        self.runtime.stop("honeypot")
        self.assertEqual(self._running(), {"sniffer"})

    # --- set_engines ------------------------------------------------------
    def test_set_engines_brings_the_running_set_to_exactly_what_was_asked(self):
        self.runtime.set_engines({"sniffer": True, "honeypot": True})
        self.assertEqual(self._running(), {"sniffer", "honeypot"})
        self.runtime.set_engines({"sniffer": False, "honeypot": True})
        self.assertEqual(self._running(), {"honeypot"})
        self.runtime.set_engines({"sniffer": False, "honeypot": False})
        self.assertEqual(self._running(), set())

    def test_set_engines_accepts_a_list(self):
        self.runtime.set_engines(["honeypot"])
        self.assertEqual(self._running(), {"honeypot"})

    def test_set_engines_does_not_restart_an_already_running_engine(self):
        self.runtime.set_engines({"sniffer": True})
        self.runtime.set_engines({"sniffer": True})
        self.assertEqual(self.sniffer.starts, 1, "an already-running engine was restarted")

    def test_start_all_starts_both(self):
        self.runtime.start("all")
        self.assertEqual(self._running(), {"sniffer", "honeypot"})

    # --- backward compatibility ------------------------------------------
    def test_unqualified_start_acts_on_the_focused_mode(self):
        self.runtime.set_mode("honeypot")
        self.runtime.start()
        self.assertEqual(self._running(), {"honeypot"})

    def test_switching_mode_no_longer_stops_the_running_engine(self):
        # The old behaviour silently killed capture when an operator merely
        # looked at the other engine's controls.
        self.runtime.start("sniffer")
        self.runtime.set_mode("honeypot")
        self.assertIn("sniffer", self._running())

    def test_mode_still_selects_what_active_describes(self):
        self.runtime.start("honeypot")
        self.runtime.set_mode("honeypot")
        snapshot = self.runtime.snapshot()
        self.assertEqual(snapshot["mode"], "honeypot")
        self.assertTrue(snapshot["active"]["running"])

    def test_snapshot_keeps_its_existing_keys(self):
        snapshot = self.runtime.snapshot()
        for key in ("mode", "supported_modes", "auto_start", "active", "sniffer", "honeypot"):
            self.assertIn(key, snapshot)

    def test_every_change_is_broadcast(self):
        before = len(self.hub.messages)
        self.runtime.start("sniffer")
        self.assertGreater(len(self.hub.messages), before)
        self.assertEqual(self.hub.messages[-1]["type"], "runtime_mode")


if __name__ == "__main__":
    unittest.main()
