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

import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

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

    def test_set_engines_accepts_bool_like_strings(self):
        self.runtime.set_engines({"sniffer": "true", "honeypot": "false"})
        self.assertEqual(self._running(), {"sniffer"})

    def test_set_engines_rejects_ambiguous_strings(self):
        with self.assertRaises(ValueError):
            self.runtime.set_engines({"sniffer": "maybe"})

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


class EngineTogglesOverRealIpcTests(unittest.TestCase):
    """The reported failure, end to end: toggling one engine made the other
    engine's toggle fail.

    The pieces the fakes above stand in for are what actually broke - the real
    `HoneypotEngine` (whose stop() joins a thread per enabled listener) behind
    the real IPC transport (which used to run every request inline on its read
    loop, so a slow call meant the next frame was not even read until it
    finished). This wires the genuine articles together and drives them the way
    the UI does.
    """

    def setUp(self):
        from sniff4hound.honeypot import HoneypotEngine
        from sniff4hound.ipc import IpcClient, IpcEventSink, IpcServer, generate_ipc_token
        from sniff4hound.sniffer import Sniffer
        from sniff4hound.store import SniffStore

        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.store = SniffStore(Path(self.temp_dir.name) / "test.db")
        self.addCleanup(self.store.close)
        with self.store._lock:
            self.store._conn.execute("UPDATE honeypot_listeners SET enabled = 0")
            self.store._conn.execute(
                "UPDATE honeypot_listeners SET enabled = 1 WHERE id IN"
                " (SELECT id FROM honeypot_listeners LIMIT 150)"
            )
            self.store._conn.commit()

        # Real listeners, no real sockets: binding 150 ports (many below 1024)
        # would need root, and what is under test is the control path, not the
        # bind. The sleep makes each listener slow to wind down, which is what
        # made honeypot stop() long enough to starve the transport.
        def _slow_listen(_self, _port, _handler, *, udp=False, stop_event):
            stop_event.wait(timeout=30)
            time.sleep(0.01)

        patcher = patch.object(HoneypotEngine, "_listen", _slow_listen)
        patcher.start()
        self.addCleanup(patcher.stop)

        socket_path = str(Path(self.temp_dir.name) / "capture.sock")
        token = generate_ipc_token()
        self.server = IpcServer(socket_path, token)
        sink = IpcEventSink(self.server)
        # "lo" only: a raw AF_PACKET socket needs root, so the capture threads
        # will record a permission error - irrelevant here, and it keeps the
        # sniffer from touching every interface on the machine.
        self.sniffer = Sniffer(self.store, sink, interfaces=("lo",))
        self.honeypot = HoneypotEngine(self.store, sink, bind_host="127.0.0.1")
        self.addCleanup(self.honeypot.stop)
        self.addCleanup(self.sniffer.stop)
        controller = RuntimeController(
            store=self.store,
            sniffer=self.sniffer,
            honeypot=self.honeypot,
            hub=sink,
            capture_auto_start=False,
        )
        self.server.methods.update(
            {
                "start": controller.start,
                "stop": controller.stop,
                "set_engines": controller.set_engines,
                "snapshot": controller.snapshot,
            }
        )
        self.server.start()
        self.addCleanup(self.server.stop)

        self.client = IpcClient(socket_path, token, connect_timeout=5, call_timeout=10)
        self.client.connect()
        self.addCleanup(self.client.close)

    def test_stopping_the_honeypot_does_not_fail_the_sniffer_toggle(self):
        self.client.call("start", engine="honeypot")
        self.client.call("start", engine="sniffer")

        results: dict[str, object] = {}
        barrier = threading.Barrier(2)

        def toggle(name, method, engine):
            barrier.wait(timeout=5)
            try:
                results[name] = self.client.call(method, engine=engine)
            except Exception as exc:
                results[name] = f"{type(exc).__name__}: {exc}"

        threads = [
            threading.Thread(target=toggle, args=("stop honeypot", "stop", "honeypot")),
            threading.Thread(target=toggle, args=("start sniffer", "start", "sniffer")),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)

        for name, result in results.items():
            self.assertIsInstance(result, dict, msg=f"{name} failed: {result}")
        self.assertEqual(len(results), 2)
        self.assertIn("sniffer", self.client.call("snapshot")["running_engines"])

    def test_both_engines_still_reachable_after_the_capture_link_drops(self):
        """A dropped link used to be permanent: every later engine control
        answered "Internal Server Error" until the app was restarted."""
        self.client.call("set_engines", selection={"sniffer": True, "honeypot": False})
        self.assertIn("sniffer", self.client.call("snapshot")["running_engines"])

        # Same shape as the capture process being restarted underneath us.
        with self.client._connect_lock:
            sock = self.client._sock
        sock.close()
        self.client._connected.clear()

        snapshot = self.client.call("snapshot")
        self.assertIn("sniffer", snapshot["running_engines"])
        self.assertIsInstance(self.client.call("start", engine="honeypot"), dict)


if __name__ == "__main__":
    unittest.main()
