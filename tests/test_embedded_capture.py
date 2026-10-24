"""The capture engines running inside the web process.

`manage.main()` runs everything as one elevated process, so the engines are
built in place instead of behind a socket in a child process. These tests cover
that in-process runtime and how `app.py` picks between it and the IPC client.
"""

import importlib
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from wsbuilder import Request

from sniff4hound.embedded_capture import EmbeddedCapture, EventSink
from sniff4hound.runtime_controller import RuntimeController
from sniff4hound.settings import capture_embedded


def _wait_until(predicate, *, timeout=5.0, interval=0.02) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return bool(predicate())


class EventSinkTests(unittest.TestCase):
    def test_events_are_delivered_in_order_off_the_calling_thread(self):
        seen, threads = [], set()

        def deliver(payload):
            seen.append(payload["n"])
            threads.add(threading.current_thread().name)

        sink = EventSink(deliver)
        self.addCleanup(sink.close)
        for n in range(50):
            sink.broadcast({"n": n})

        self.assertTrue(_wait_until(lambda: len(seen) == 50))
        self.assertEqual(seen, list(range(50)))
        self.assertEqual(threads, {"sniff4hound-capture-events"}, "delivery ran on a capture thread")

    def test_a_slow_listener_never_blocks_the_engines_and_overflow_is_counted(self):
        gate = threading.Event()
        delivered = []

        def deliver(payload):
            gate.wait(5)
            delivered.append(payload)

        sink = EventSink(deliver, maxsize=10)
        self.addCleanup(sink.close)
        started = time.monotonic()
        for n in range(100):
            sink.broadcast({"n": n})  # must return at once even though nothing is being consumed
        self.assertLess(time.monotonic() - started, 1.0, "broadcast waited for the consumer")
        self.assertGreater(sink.dropped, 0)
        gate.set()
        self.assertTrue(_wait_until(lambda: len(delivered) > 0))

    def test_a_listener_that_raises_does_not_end_the_stream(self):
        seen = []

        def deliver(payload):
            if payload["n"] == 1:
                raise RuntimeError("one bad client")
            seen.append(payload["n"])

        sink = EventSink(deliver)
        self.addCleanup(sink.close)
        for n in range(4):
            sink.broadcast({"n": n})
        self.assertTrue(_wait_until(lambda: seen == [0, 2, 3]), seen)

    def test_closing_delivers_what_is_queued_first(self):
        seen = []
        sink = EventSink(lambda payload: (time.sleep(0.01), seen.append(payload["n"])))
        for n in range(10):
            sink.broadcast({"n": n})
        sink.close()
        self.assertEqual(seen, list(range(10)))


class EmbeddedCaptureTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.events = []
        self.capture = EmbeddedCapture(
            self.events.append, db_path=Path(self._tmp.name) / "embedded.db", interfaces=("lo",), auto_start=False
        )
        self.addCleanup(self.capture.close)

    def test_it_is_a_real_runtime_controller_with_nothing_running(self):
        self.assertIsInstance(self.capture.runtime, RuntimeController)
        snapshot = self.capture.runtime.snapshot()
        self.assertEqual(snapshot["running_engines"], [])
        self.assertIn(snapshot["mode"], ("sniffer", "honeypot"))

    def test_engine_events_reach_the_web_side_without_a_socket(self):
        self.capture.runtime.set_mode("honeypot")
        self.assertTrue(
            _wait_until(lambda: any(event.get("type") == "runtime_mode" for event in self.events)),
            "the mode change never came out of the in-process hub",
        )

    def test_the_listener_catalogue_answers_in_process(self):
        rows = {row["id"]: row for row in self.capture.runtime.list_honeypot_listeners()}
        self.assertGreaterEqual(len(rows), 10000)
        self.assertTrue(rows["tcp/22"]["can_enable"])
        self.assertFalse(rows["tcp/2"]["can_enable"])

    def test_a_refused_listener_is_a_plain_value_error_not_an_ipc_outage(self):
        with self.assertRaises(ValueError) as caught:
            self.capture.runtime.create_honeypot_listener("tcp", 22, "ssh")
        self.assertIn("privileged ports", str(caught.exception))

    def test_it_writes_through_a_connection_of_its_own(self):
        from sniff4hound.store import SniffStore

        other = SniffStore(Path(self._tmp.name) / "embedded.db")
        self.addCleanup(other.close)
        self.assertIsNot(self.capture.store._conn, other._conn)

    def test_closing_stops_every_thread_and_can_be_repeated(self):
        guard_thread = self.capture.guard._thread
        events_thread = self.capture.events._thread
        self.assertTrue(guard_thread.is_alive() and events_thread.is_alive())

        self.capture.close()

        self.assertTrue(_wait_until(lambda: not events_thread.is_alive()))
        self.assertTrue(_wait_until(lambda: not guard_thread.is_alive()))
        self.capture.close()  # a second shutdown path (signal, then finally) must be harmless


def _reload_app(test_case, *, embedded: bool):
    """Reload sniff4hound.app with the capture mode pinned for one test and put
    it back afterwards (a reload replaces sys.modules["sniff4hound.app"] for every
    later test in the process)."""
    names = ("SNIFF4HOUND_CAPTURE_EMBEDDED", "SNIFF4HOUND_REQUIRE_AUTH")
    previous = {name: os.environ.get(name) for name in names}

    def _close(module):
        if module is None:
            return
        try:
            shutdown = getattr(module, "shutdown_capture", None)
            if shutdown is not None and getattr(module, "embedded_capture", None) is not None:
                shutdown()
            else:
                module.store.close()
        except Exception:
            pass

    def _restore():
        _close(sys.modules.get("sniff4hound.app"))
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        import sniff4hound.settings as settings_module
        importlib.reload(settings_module)
        importlib.reload(sys.modules["sniff4hound.auth"])
        importlib.reload(sys.modules["sniff4hound.app"])

    test_case.addCleanup(_restore)
    os.environ["SNIFF4HOUND_REQUIRE_AUTH"] = "0"
    if embedded:
        os.environ["SNIFF4HOUND_CAPTURE_EMBEDDED"] = "1"
    else:
        os.environ.pop("SNIFF4HOUND_CAPTURE_EMBEDDED", None)
    import sniff4hound.app as app_module
    import sniff4hound.auth as auth_module
    import sniff4hound.settings as settings_module

    _close(sys.modules.get("sniff4hound.app"))
    importlib.reload(settings_module)
    importlib.reload(auth_module)
    return importlib.reload(app_module)


class AppCaptureModeTests(unittest.TestCase):
    def _get(self, app_module, path, *, method="GET", body=None):
        request = Request(method, path, "", {"host": "127.0.0.1:45678"}, json.dumps(body).encode() if body else b"", ("127.0.0.1", 40000))
        return app_module.app.dispatch(request)

    def test_the_capture_mode_is_read_when_asked(self):
        previous = os.environ.get("SNIFF4HOUND_CAPTURE_EMBEDDED")
        self.addCleanup(lambda: os.environ.pop("SNIFF4HOUND_CAPTURE_EMBEDDED", None) if previous is None
                        else os.environ.__setitem__("SNIFF4HOUND_CAPTURE_EMBEDDED", previous))
        os.environ.pop("SNIFF4HOUND_CAPTURE_EMBEDDED", None)
        self.assertFalse(capture_embedded(), "the split is the default for anything but the combined entry point")
        os.environ["SNIFF4HOUND_CAPTURE_EMBEDDED"] = "1"
        self.assertTrue(capture_embedded())
        os.environ["SNIFF4HOUND_CAPTURE_EMBEDDED"] = "0"
        self.assertFalse(capture_embedded())

    def test_the_unprivileged_web_entry_point_is_always_the_split(self):
        from unittest.mock import patch

        from sniff4hound import manage

        previous = os.environ.get("SNIFF4HOUND_CAPTURE_EMBEDDED")
        self.addCleanup(lambda: os.environ.pop("SNIFF4HOUND_CAPTURE_EMBEDDED", None) if previous is None
                        else os.environ.__setitem__("SNIFF4HOUND_CAPTURE_EMBEDDED", previous))
        os.environ["SNIFF4HOUND_CAPTURE_EMBEDDED"] = "1"
        # It stops at once on a busy port, after it has decided how the engines run.
        with patch.object(manage, "_running_as_root", return_value=False), \
                patch.object(manage, "_select_listen_port", return_value=None), \
                patch.object(manage, "_print_address_in_use_error"):
            self.assertEqual(manage.main_web(), 1)
        self.assertEqual(os.environ["SNIFF4HOUND_CAPTURE_EMBEDDED"], "0",
                         "sniff4hound-web would have tried to run the engines without privileges")

    def test_without_the_flag_the_web_process_still_talks_to_a_capture_process(self):
        module = _reload_app(self, embedded=False)
        self.assertIsNotNone(module.ipc_client)
        self.assertIsNone(module.embedded_capture)
        self.assertEqual(type(module.runtime).__name__, "RuntimeControllerClient")

    def test_with_the_flag_the_engines_run_in_the_web_process(self):
        module = _reload_app(self, embedded=True)
        self.assertIsNone(module.ipc_client)
        self.assertIsInstance(module.runtime, RuntimeController)
        self.assertTrue(module.connect_capture_service(), "there is nothing to connect to, and that is not a failure")

        runtime_response = self._get(module, "/api/runtime/")
        self.assertEqual(runtime_response.status, 200)
        self.assertIn("mode", json.loads(runtime_response.body.decode("utf-8")))

    def test_a_refused_listener_is_a_400_with_the_reason_in_embedded_mode_too(self):
        module = _reload_app(self, embedded=True)
        response = self._get(module, "/api/honeypot/listeners/", method="POST", body={"proto": "tcp", "port": 22, "label": "x"})
        self.assertEqual(response.status, 400)
        payload = json.loads(response.body.decode("utf-8"))
        self.assertEqual(payload["code"], "invalid_request")
        self.assertIn("privileged ports", payload["message"])

    def test_shutting_down_closes_the_embedded_engines_and_is_repeatable(self):
        module = _reload_app(self, embedded=True)
        capture = module.embedded_capture
        self.assertFalse(capture._closed)
        module.shutdown_capture()
        self.assertTrue(capture._closed)
        module.shutdown_capture()


class ManageMainWiringTests(unittest.TestCase):
    """What `manage.main()` starts, and does not, in each capture mode."""

    def _run_main(self, mode):
        import contextlib
        from unittest.mock import MagicMock, patch

        import sniff4hound.app as app_module
        from sniff4hound import manage

        env = self.enterContext(patch.dict(os.environ))
        env.pop("SNIFF4HOUND_CAPTURE_EMBEDDED", None) if mode is None else env.update(SNIFF4HOUND_CAPTURE_EMBEDDED=mode)
        for leftover in ("SNIFF4HOUND_IPC_SOCKET", "SNIFF4HOUND_IPC_TOKEN_FILE", "SNIFF4HOUND_IPC_OWNER_UID"):
            env.pop(leftover, None)

        child = MagicMock()
        child.poll.return_value = None
        mocks = {}
        with contextlib.ExitStack() as stack:
            def patched(target, name, **kwargs):
                mocks[name] = stack.enter_context(patch.object(target, name, **kwargs))

            patched(manage, "HOST", new="127.0.0.1")
            patched(manage, "PORT", new=45678)
            patched(manage, "_ensure_running_as_root", return_value=True)
            patched(manage, "_select_listen_port", return_value=45678)
            patched(manage, "_spawn_capture_child", return_value=child)
            patched(manage, "_stop_capture_child")
            patched(manage, "_remove_ipc_token_file")
            patched(manage, "_clear_stale_capture_socket")
            patched(manage, "_capture_start_lock", side_effect=lambda *_: contextlib.nullcontext())
            patched(manage, "write_ipc_token_file", return_value=True)
            patched(manage, "CaptureSupervisor")
            patched(manage, "_print_startup_banner")
            patched(app_module, "connect_capture_service", return_value=True)
            patched(app_module, "bootstrap_capture")
            patched(app_module.runtime, "set_dashboard_port")
            patched(app_module, "shutdown_capture")
            stack.enter_context(patch.object(app_module.app, "run", side_effect=KeyboardInterrupt))
            exit_code = manage.main()
        return exit_code, mocks, dict(os.environ)

    def test_by_default_everything_runs_in_this_one_process(self):
        exit_code, mocks, env = self._run_main(None)

        self.assertEqual(exit_code, 0)
        self.assertEqual(env["SNIFF4HOUND_CAPTURE_EMBEDDED"], "1", "the app module reads this when it is imported")
        for name in ("_spawn_capture_child", "CaptureSupervisor", "write_ipc_token_file", "_capture_start_lock",
                     "_clear_stale_capture_socket", "_stop_capture_child", "_remove_ipc_token_file"):
            mocks[name].assert_not_called()
        for name in ("SNIFF4HOUND_IPC_SOCKET", "SNIFF4HOUND_IPC_TOKEN_FILE", "SNIFF4HOUND_IPC_OWNER_UID"):
            self.assertNotIn(name, env, "there is no capture process to hand a socket or token to")
        mocks["bootstrap_capture"].assert_called_once()
        mocks["set_dashboard_port"].assert_called_once_with(45678)
        mocks["shutdown_capture"].assert_called_once()

    def test_the_flag_set_to_zero_brings_back_the_separate_capture_process(self):
        exit_code, mocks, env = self._run_main("0")

        self.assertEqual(exit_code, 0)
        mocks["_spawn_capture_child"].assert_called_once()
        mocks["CaptureSupervisor"].assert_called_once()
        mocks["CaptureSupervisor"].return_value.start.assert_called_once()
        mocks["CaptureSupervisor"].return_value.stop.assert_called_once()
        mocks["_stop_capture_child"].assert_called_once()
        self.assertIn("SNIFF4HOUND_IPC_SOCKET", env)


if __name__ == "__main__":
    unittest.main()
