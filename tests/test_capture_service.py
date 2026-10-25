from __future__ import annotations

import importlib
import io
import os
import socket
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import MagicMock, patch

from sniff4hound.store import SniffStore


class FakeEngine:
    """Stands in for `Sniffer`/`HoneypotEngine` - just enough surface for
    `RuntimeController` (start/stop/restart/snapshot/set_interfaces), no
    raw sockets involved."""

    def __init__(self, name: str):
        self.name = name
        self.running = False
        self.selected_interfaces: list[str] = []

    def start(self):
        self.running = True

    def stop(self):
        self.running = False

    def restart(self):
        self.stop()
        self.start()

    def snapshot(self):
        return {
            "engine": self.name,
            "running": self.running,
            "selected_interfaces": list(self.selected_interfaces),
        }

    def set_interfaces(self, interfaces):
        self.selected_interfaces = list(interfaces or [])


class RuntimeControllerTests(unittest.TestCase):
    def setUp(self):
        self._tmp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp_dir.cleanup)
        self.store = SniffStore(Path(self._tmp_dir.name) / "capture.db")
        self.addCleanup(self.store.close)
        self.sniffer = FakeEngine("sniffer")
        self.honeypot = FakeEngine("honeypot")
        self.hub = MagicMock()

    def _controller(self, **kwargs):
        from sniff4hound.runtime_controller import RuntimeController

        params = {
            "store": self.store,
            "sniffer": self.sniffer,
            "honeypot": self.honeypot,
            "hub": self.hub,
            "capture_auto_start": False,
        }
        params.update(kwargs)
        controller = RuntimeController(**params)
        # Keep the post-restart verification window short in tests.
        controller._interface_verify_seconds = 0.05
        return controller

    def test_interface_verification_environment_is_finite_and_bounded(self):
        from sniff4hound.runtime_controller import _configured_interface_verify_seconds

        for raw, expected in (("0", 0.0), ("0.25", 0.25), ("-1", 0.0), ("99", 5.0),
                              ("invalid", 0.5), ("", 0.5), ("nan", 0.5), ("inf", 0.5), ("-inf", 0.5)):
            with self.subTest(raw=raw), patch.dict(os.environ, {"SNIFF4HOUND_INTERFACE_VERIFY_SECONDS": raw}):
                self.assertEqual(_configured_interface_verify_seconds(), expected)

    def test_zero_verification_window_checks_once_without_sleeping(self):
        controller = self._controller()
        controller._interface_verify_seconds = 0
        with patch("sniff4hound.runtime_controller.time.sleep") as sleep:
            controller._restart_sniffer_verified()
            sleep.assert_not_called()
        self.assertTrue(self.sniffer.running)

    def test_defaults_to_sniffer_mode_and_persists_it(self):
        previous = os.environ.pop("SNIFF4HOUND_RUNTIME_MODE", None)
        try:
            import sniff4hound.settings as settings_module
            import sniff4hound.runtime_controller as runtime_controller_module

            importlib.reload(settings_module)
            runtime_controller_module = importlib.reload(runtime_controller_module)

            controller = runtime_controller_module.RuntimeController(
                store=self.store,
                sniffer=self.sniffer,
                honeypot=self.honeypot,
                hub=self.hub,
                capture_auto_start=False,
            )
            self.assertEqual(controller.mode, "sniffer")
            self.assertEqual(self.store.get_runtime_config("runtime_mode", ""), "sniffer")
        finally:
            if previous is not None:
                os.environ["SNIFF4HOUND_RUNTIME_MODE"] = previous

    def test_current_engine_switches_with_mode(self):
        controller = self._controller()
        self.assertIs(controller.current_engine(), self.sniffer)

        controller.set_mode("honeypot")
        self.assertIs(controller.current_engine(), self.honeypot)
        self.assertEqual(controller.mode, "honeypot")

    def test_set_mode_no_longer_stops_the_running_engine(self):
        """Switching the focused mode must not kill capture.

        The engines are independent now - any of the four combinations is
        valid - so `mode` only selects which engine the unqualified controls
        act on. Stopping one is an explicit stop("sniffer"), never a side
        effect of looking at the other engine's controls.
        """
        controller = self._controller()
        controller.start()
        self.assertTrue(self.sniffer.running)

        controller.set_mode("honeypot")
        self.assertTrue(self.sniffer.running)
        self.assertFalse(self.honeypot.running)

    def test_engines_run_independently(self):
        controller = self._controller()
        controller.start("sniffer")
        controller.start("honeypot")
        self.assertTrue(self.sniffer.running)
        self.assertTrue(self.honeypot.running)

        controller.stop("honeypot")
        self.assertTrue(self.sniffer.running)
        self.assertFalse(self.honeypot.running)

    def test_start_stop_broadcast_runtime_mode_events(self):
        controller = self._controller()
        controller.start()
        controller.stop()

        broadcast_types = [call.args[0]["type"] for call in self.hub.broadcast.call_args_list]
        self.assertEqual(broadcast_types, ["runtime_mode", "runtime_mode"])

    def test_set_sniffer_interfaces_persists_and_restarts_when_running(self):
        controller = self._controller()
        controller.mode = "sniffer"
        controller.start()

        controller.set_sniffer_interfaces(["eth0", "wlan0"])

        self.assertEqual(self.sniffer.selected_interfaces, ["eth0", "wlan0"])
        self.assertEqual(
            self.store.get_runtime_config("sniffer_interfaces", ""),
            '["eth0", "wlan0"]',
        )
        self.assertTrue(self.sniffer.running)

    def test_interfaces_restart_the_live_sniffer_with_either_focus(self):
        controller = self._controller()
        for focus in ("sniffer", "honeypot"):
            for concurrent in (False, True):
                with self.subTest(focus=focus, concurrent=concurrent):
                    controller.mode = focus
                    self.sniffer.running = True
                    self.honeypot.running = concurrent
                    self.sniffer.set_interfaces(["fixture-old"])
                    live = ["fixture-old"]

                    def restart():
                        live[:] = self.sniffer.selected_interfaces

                    with patch.object(self.sniffer, "restart", side_effect=restart) as restarted:
                        snapshot = controller.set_sniffer_interfaces(["fixture-new"])
                        restarted.assert_called_once_with()
                        self.assertEqual(live, ["fixture-new"])
                        self.assertEqual(snapshot["sniffer"]["interface_update"]["status"], "applied")
                        controller.set_sniffer_interfaces(["fixture-new"])
                        restarted.assert_called_once_with()
                    self.assertEqual(self.honeypot.running, concurrent)

    def test_stopped_sniffer_only_saves_interfaces(self):
        controller = self._controller()
        controller.mode = "honeypot"
        with patch.object(self.sniffer, "restart") as restarted:
            snapshot = controller.set_sniffer_interfaces(["fixture-new"])
            restarted.assert_not_called()
        self.assertFalse(snapshot["sniffer"]["running"])
        self.assertEqual(snapshot["sniffer"]["interface_update"]["status"], "saved")
        self.assertEqual(self.store.get_runtime_config("sniffer_interfaces"), '["fixture-new"]')

    def test_failed_restart_restores_selection_and_broadcasts_failure(self):
        controller = self._controller()
        controller.set_sniffer_interfaces(["fixture-old"])
        controller.start("all")
        controller.mode = "honeypot"
        for raises in (True, False):
            with self.subTest(raises=raises):
                self.sniffer.running = True

                def fail():
                    self.sniffer.running = False
                    if raises:
                        raise RuntimeError("fixture restart failure")

                calls = []

                def restart():
                    calls.append(list(self.sniffer.selected_interfaces))
                    if len(calls) == 1:
                        fail()
                    else:
                        self.sniffer.running = True

                with patch.object(self.sniffer, "restart", side_effect=restart):
                    with self.assertRaises(RuntimeError):
                        controller.set_sniffer_interfaces(["fixture-new"])
                # The rollback restarted capture on the previous selection.
                self.assertEqual(calls, [["fixture-new"], ["fixture-old"]])
                snapshot = controller.snapshot()
                self.assertTrue(snapshot["sniffer"]["running"])
                self.assertEqual(snapshot["sniffer"]["selected_interfaces"], ["fixture-old"])
                self.assertEqual(snapshot["sniffer"]["interface_update"]["status"], "rolled_back")
                self.assertEqual(snapshot["sniffer"]["interface_update"]["restored_interfaces"], ["fixture-old"])
                self.assertEqual(snapshot["sniffer"]["interface_update"]["requested_interfaces"], ["fixture-new"])
                self.assertEqual(self.hub.broadcast.call_args.args[0]["runtime"], snapshot)
                self.assertEqual(self.store.get_runtime_config("sniffer_interfaces"), '["fixture-old"]')
                self.assertTrue(self.honeypot.running)


    def test_failed_rollback_is_reported_and_broadcast(self):
        controller = self._controller()
        controller.set_sniffer_interfaces(["fixture-old"])
        controller.start("sniffer")

        def fail():
            self.sniffer.running = False
            raise RuntimeError("fixture restart failure")

        with patch.object(self.sniffer, "restart", side_effect=fail) as restarted:
            with self.assertRaises(RuntimeError):
                controller.set_sniffer_interfaces(["fixture-new"])
        self.assertEqual(restarted.call_count, 2)
        snapshot = controller.snapshot()
        update = snapshot["sniffer"]["interface_update"]
        self.assertEqual(update["status"], "rollback_failed")
        self.assertIn("fixture restart failure", update["rollback_error"])
        self.assertFalse(snapshot["sniffer"]["running"])
        self.assertEqual(snapshot["sniffer"]["selected_interfaces"], ["fixture-old"])
        self.assertEqual(self.hub.broadcast.call_args.args[0]["runtime"], snapshot)

    def test_asynchronous_worker_failure_is_not_reported_applied(self):
        controller = self._controller()
        controller._interface_verify_seconds = 0.3
        controller.set_sniffer_interfaces(["fixture-old"])
        controller.start("sniffer")
        errors = {}
        base_snapshot = self.sniffer.snapshot

        def snapshot():
            state = base_snapshot()
            if errors:
                state.update(capture_state="blocked", errors=dict(errors))
            else:
                state.update(capture_state="running" if state["running"] else "idle", errors={})
            return state

        def restart():
            errors.clear()
            self.sniffer.running = True
            if self.sniffer.selected_interfaces == ["fixture-new"]:
                # start() returned fine; the worker fails a moment later.
                def worker_fails():
                    errors["fixture-new"] = "no such device"
                    self.sniffer.running = False

                threading.Timer(0.05, worker_fails).start()

        with patch.object(self.sniffer, "snapshot", side_effect=snapshot), \
                patch.object(self.sniffer, "restart", side_effect=restart):
            with self.assertRaises(RuntimeError) as raised:
                controller.set_sniffer_interfaces(["fixture-new"])
            result = controller.snapshot()
        self.assertIn("no such device", str(raised.exception))
        update = result["sniffer"]["interface_update"]
        self.assertNotEqual(update["status"], "applied")
        self.assertEqual(update["status"], "rolled_back")
        self.assertTrue(result["sniffer"]["running"])
        self.assertEqual(result["sniffer"]["selected_interfaces"], ["fixture-old"])
        self.assertEqual(self.store.get_runtime_config("sniffer_interfaces"), '["fixture-old"]')

    def test_selection_restore_failure_is_broadcast_as_rollback_failed(self):
        controller = self._controller()
        controller.set_sniffer_interfaces(["fixture-old"])
        controller.start("sniffer")
        original_set = self.sniffer.set_interfaces

        def select(interfaces):
            if list(interfaces) == ["fixture-old"]:
                raise ValueError("old interface disappeared")
            original_set(interfaces)

        with patch.object(self.sniffer, "set_interfaces", side_effect=select), \
                patch.object(self.sniffer, "restart", side_effect=RuntimeError("restart failed")):
            with self.assertRaisesRegex(RuntimeError, "restart failed"):
                controller.set_sniffer_interfaces(["fixture-new"])
        update = controller.snapshot()["sniffer"]["interface_update"]
        self.assertEqual(update["status"], "rollback_failed")
        self.assertEqual(update["rollback_error"], "old interface disappeared")
        self.assertEqual(update["restored_interfaces"], [])
        self.assertEqual(self.hub.broadcast.call_args.args[0]["runtime"], controller.snapshot())

    def test_real_capture_worker_readiness_and_delayed_bind_failure(self):
        from sniff4hound.sniffer import Sniffer

        sniffer = Sniffer(self.store, self.hub, interfaces=("fixture-old", "fixture-new"))
        controller = self._controller(sniffer=sniffer)
        controller._interface_verify_seconds = 0.15

        class CaptureSocket:
            def setsockopt(self, *_args):
                pass

            def settimeout(self, _timeout):
                pass

            def bind(self, address):
                if address[0] == "fixture-new":
                    time.sleep(0.04)
                    raise OSError("fixture bind failed")

            def recvfrom(self, _size):
                sniffer._stop_event.wait(0.01)
                raise socket.timeout()

            def close(self):
                pass

        def warning(_sock, interface):
            sniffer._set_error(interface, "promiscuous mode unavailable: fixture warning")

        with patch("sniff4hound.sniffer.socket.socket", side_effect=lambda *_a: CaptureSocket()), \
                patch("sniff4hound.sniffer.CAPTURE_PROMISCUOUS", True), \
                patch.object(sniffer, "_enable_promiscuous", side_effect=warning):
            try:
                controller.set_sniffer_interfaces(["fixture-old"])
                controller.start("sniffer")
                # A warning about optional promiscuous mode must not reject a
                # bound, working capture, nor may a historical receive error.
                controller._restart_sniffer_verified()
                self.assertEqual(sniffer.snapshot()["ready_interfaces"], ["fixture-old"])
                self.assertIn("fixture-old", sniffer.snapshot()["errors"])
                with self.assertRaisesRegex(RuntimeError, "fixture bind failed"):
                    controller.set_sniffer_interfaces(["fixture-new"])
                snapshot = controller.snapshot()["sniffer"]
                self.assertTrue(snapshot["running"])
                self.assertEqual(snapshot["ready_interfaces"], ["fixture-old"])
                self.assertEqual(snapshot["interface_update"]["status"], "rolled_back")
                self.assertEqual(snapshot["startup_errors"], {})
            finally:
                sniffer.stop()

    def test_stale_worker_exiting_after_restart_keeps_new_worker_ready(self):
        from sniff4hound.sniffer import Sniffer

        sniffer = Sniffer(self.store, self.hub, interfaces=("fixture-old",))
        bound = threading.Event()
        release = threading.Event()

        def bind_then_wait():
            # Stands in for the new worker after its bind succeeded.
            with sniffer._state_lock:
                sniffer._capture_ready["fixture-old"] = threading.current_thread()
            bound.set()
            release.wait(3)
            sniffer._mark_capture_worker_stopped("fixture-old")

        new_worker = threading.Thread(target=bind_then_wait, daemon=True)
        new_worker.start()
        try:
            self.assertTrue(bound.wait(3))
            # A worker from before the restart, on the same interface, exits
            # late: it must not erase the new worker's readiness.
            stale = threading.Thread(target=sniffer._mark_capture_worker_stopped, args=("fixture-old",))
            stale.start()
            stale.join(3)
            self.assertEqual(sniffer.snapshot()["ready_interfaces"], ["fixture-old"])
        finally:
            release.set()
            new_worker.join(3)
        # The owning worker still clears its own readiness when it stops.
        self.assertEqual(sniffer.snapshot()["ready_interfaces"], [])

    def test_live_worker_that_never_binds_is_not_reported_applied(self):
        controller = self._controller()
        controller.start("sniffer")
        base_snapshot = self.sniffer.snapshot

        def snapshot():
            return {**base_snapshot(), "interfaces": ["fixture-new"],
                    "active_threads": 1, "ready_interfaces": [], "startup_errors": {}}

        with patch.object(self.sniffer, "snapshot", side_effect=snapshot):
            with self.assertRaisesRegex(RuntimeError, "startup did not finish"):
                controller.set_sniffer_interfaces(["fixture-new"])
        self.assertEqual(controller.snapshot()["sniffer"]["interface_update"]["status"], "rollback_failed")

    def test_late_ipc_mutation_uses_production_resync_hook(self):
        from sniff4hound.capture_service import _resync_after_slow_mutation
        from sniff4hound.ipc import IpcClient, IpcError, IpcEventSink, IpcServer

        release = threading.Event()
        path = str(Path(self._tmp_dir.name) / "late.sock")
        server = IpcServer(path, "fixture-token")
        controller = self._controller(hub=IpcEventSink(server))

        def mutate():
            release.wait(3)
            self.sniffer.running = True
            raise RuntimeError("fixture error after mutation")

        server.methods["start"] = mutate
        server.on_slow_dispatch = lambda method, elapsed: _resync_after_slow_mutation(controller, method, elapsed)
        events = []
        client = IpcClient(path, "fixture-token", on_event=events.append, call_timeout=0.05)
        server.start()
        try:
            client.connect()
            with self.assertRaisesRegex(IpcError, "timed out"):
                client.call("start")
            self.assertEqual(client._pending, {})
            release.set()
            deadline = time.monotonic() + 2
            while not events and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertEqual(events[0]["type"], "runtime_mode")
            self.assertTrue(events[0]["runtime"]["sniffer"]["running"])
        finally:
            release.set()
            client.close()
            server.stop()


class CaptureServiceAdminPolicyTests(unittest.TestCase):
    """Capture always requires root - no bypass, ported from what used to
    be manage.py's policy tests before capture moved to its own process."""

    def test_refuses_to_start_without_admin_and_without_sudo(self):
        import sniff4hound.capture_service as capture_service_module

        output = io.StringIO()
        with patch.object(capture_service_module, "_is_running_as_admin", return_value=False), patch.object(
            capture_service_module.shutil, "which", return_value=None
        ), redirect_stderr(output):
            result = capture_service_module._ensure_admin_privileges()

        self.assertFalse(result)
        self.assertIn("requires root", output.getvalue())
        self.assertIn("will not start", output.getvalue())

    def test_proceeds_when_already_admin(self):
        import sniff4hound.capture_service as capture_service_module

        with patch.object(capture_service_module, "_is_running_as_admin", return_value=True):
            self.assertTrue(capture_service_module._ensure_admin_privileges())


class FakeCaptureProcess:
    """Stands in for the `subprocess.Popen` handle `manage.main()` keeps for
    the privileged capture child. Spawning the real thing needs root, which
    a test run does not have."""

    def __init__(self, returncode=None):
        self.returncode = returncode

    def poll(self):
        return self.returncode

    def die(self, returncode=-9):
        self.returncode = returncode


class CaptureSupervisorTests(unittest.TestCase):
    """The capture child used to be spawned once and never looked at again:
    `app.run()` blocks until shutdown, so a child lost mid-session (crash,
    OOM-kill, external `kill -9`) left the web process serving HTTP while
    every engine control failed for the rest of the run.

    These drive `CaptureSupervisor.check_once()` directly - one supervision
    tick, no thread, no real process - so the restart/give-up decisions are
    covered without root.
    """

    def setUp(self):
        self.clock = 1000.0
        self.logs: list[str] = []
        self.spawned: list[tuple[str, str]] = []
        self.written: list[tuple[str, str]] = []
        self.removed: list[str] = []
        self.shutdown = False
        self.reconnected = 0
        self.spawn_results: list = []

    def _supervisor(self, process, **kwargs):
        import sniff4hound.manage as manage_module

        def _spawn(ipc_socket, ipc_token_file):
            self.spawned.append((ipc_socket, ipc_token_file))
            if self.spawn_results:
                return self.spawn_results.pop(0)
            return FakeCaptureProcess()

        def _write_token(path, token):
            self.written.append((str(path), token))
            return True

        def _reconnect():
            self.reconnected += 1
            return True

        params = {
            "process": process,
            "ipc_socket": "/run/sniff4hound/capture-8080.sock",
            "ipc_token_file": "/run/sniff4hound/capture-8080.token",
            "ipc_token": "a" * 64,
            "spawn": _spawn,
            "reconnect": _reconnect,
            "write_token": _write_token,
            "remove_token": self.removed.append,
            "shutdown_requested": lambda: self.shutdown,
            "monotonic": lambda: self.clock,
            "log": self.logs.append,
        }
        params.update(kwargs)
        return manage_module.CaptureSupervisor(**params)

    def test_a_live_child_is_left_alone(self):
        supervisor = self._supervisor(FakeCaptureProcess())

        self.assertTrue(supervisor.check_once())
        self.assertEqual(self.spawned, [])
        self.assertEqual(self.logs, [])

    def test_unexpected_exit_rewrites_the_token_and_respawns(self):
        dead = FakeCaptureProcess(returncode=-9)
        supervisor = self._supervisor(dead)

        self.assertTrue(supervisor.check_once())

        # The token file is deleted once the first child authenticates, and a
        # child that finds none generates its own - leaving this process's
        # IpcClient holding a secret the new child would reject.
        self.assertEqual(
            self.written,
            [("/run/sniff4hound/capture-8080.token", "a" * 64)],
        )
        self.assertEqual(
            self.spawned,
            [("/run/sniff4hound/capture-8080.sock", "/run/sniff4hound/capture-8080.token")],
        )
        self.assertIsNot(supervisor.process, dead)
        self.assertIsNone(supervisor.process.poll())
        # IpcClient.call() reconnects on demand, but only when something
        # calls it - nothing polls. Reconnecting eagerly is what brings the
        # reader thread, and so the packet/stats event stream, back on an
        # untouched dashboard.
        self.assertEqual(self.reconnected, 1)
        # And the secret goes back off disk afterwards, as at startup.
        self.assertEqual(self.removed, ["/run/sniff4hound/capture-8080.token"])
        self.assertIn("restarting it (1/3)", self.logs[0])

    def test_exit_during_shutdown_is_not_a_crash(self):
        self.shutdown = True
        supervisor = self._supervisor(FakeCaptureProcess(returncode=0))

        self.assertFalse(supervisor.check_once())
        self.assertEqual(self.spawned, [])
        self.assertEqual(self.written, [])
        self.assertEqual(self.logs, [])

    def test_stop_ends_supervision_without_respawning(self):
        # Ctrl+C does not go through request_process_shutdown(), so main()'s
        # finally block stops the supervisor explicitly before terminating
        # the child. A tick racing that must not respawn as root on the way
        # out.
        supervisor = self._supervisor(FakeCaptureProcess(returncode=0))
        supervisor.stop()

        self.assertFalse(supervisor.check_once())
        self.assertEqual(self.spawned, [])

    def test_restarts_are_bounded_within_the_window(self):
        process = FakeCaptureProcess(returncode=1)
        supervisor = self._supervisor(process)
        self.spawn_results = [process, process, process]

        for expected in (1, 2, 3):
            self.clock += 1.0
            self.assertTrue(supervisor.check_once())
            self.assertIn(f"restarting it ({expected}/3)", self.logs[-1])

        # Fourth death inside the same minute: a child that crashes this fast
        # is broken, and retrying forever would re-prompt for privileges on
        # every attempt.
        self.clock += 1.0
        self.assertFalse(supervisor.check_once())
        self.assertEqual(len(self.spawned), 3)
        self.assertIn("giving up on restarting it", self.logs[-1])
        self.assertIn("died 3 times in the last 60s", self.logs[-1])

    def test_restart_budget_recovers_after_the_window_passes(self):
        process = FakeCaptureProcess(returncode=1)
        supervisor = self._supervisor(process)
        self.spawn_results = [process] * 6

        # Six crashes spread well over a minute apart is an unlucky session,
        # not a crash loop - each one still gets a restart.
        for _ in range(6):
            self.clock += 61.0
            self.assertTrue(supervisor.check_once())
            self.assertIn("restarting it (1/3)", self.logs[-1])

        self.assertEqual(len(self.spawned), 6)

    def test_gives_up_when_the_token_file_cannot_be_rewritten(self):
        supervisor = self._supervisor(
            FakeCaptureProcess(returncode=-9),
            write_token=lambda path, token: False,
        )

        # Spawning anyway would start a child that mints its own token, and a
        # token mismatch is permanent: IpcClient latches `_auth_failed` on the
        # first rejection and raises from every later connect(), so it would
        # wedge the link for the rest of the run - including across a later
        # restart that would otherwise have recovered.
        self.assertFalse(supervisor.check_once())
        self.assertEqual(self.spawned, [])
        self.assertIn("Could not rewrite the capture IPC token file", self.logs[-1])

    def test_a_failed_spawn_retries_on_the_next_tick(self):
        dead = FakeCaptureProcess(returncode=-9)
        supervisor = self._supervisor(dead)
        replacement = FakeCaptureProcess()
        self.spawn_results = [None, replacement]

        self.assertTrue(supervisor.check_once())
        self.assertIs(supervisor.process, dead)

        self.clock += 1.0
        self.assertTrue(supervisor.check_once())
        self.assertIs(supervisor.process, replacement)
        self.assertEqual(len(self.spawned), 2)

    def test_a_failed_spawn_still_spends_the_restart_budget(self):
        supervisor = self._supervisor(FakeCaptureProcess(returncode=-9))
        self.spawn_results = [None, None, None]

        for _ in range(3):
            self.clock += 1.0
            self.assertTrue(supervisor.check_once())

        self.clock += 1.0
        self.assertFalse(supervisor.check_once())
        self.assertIn("giving up on restarting it", self.logs[-1])

    def test_a_failed_reconnect_is_reported_but_keeps_supervising(self):
        supervisor = self._supervisor(
            FakeCaptureProcess(returncode=-9),
            reconnect=lambda: False,
        )

        self.assertTrue(supervisor.check_once())
        self.assertIn("could not re-attach", self.logs[-1])

    def test_restart_attempts_are_logged_to_stderr_by_default(self):
        # The operator only sees this if it reaches the terminal - the child's
        # own stdout/stderr go to a log file, not the console.
        import sniff4hound.manage as manage_module

        supervisor = manage_module.CaptureSupervisor(
            process=FakeCaptureProcess(returncode=-9),
            ipc_socket="/run/sniff4hound/capture-8080.sock",
            ipc_token_file="/run/sniff4hound/capture-8080.token",
            ipc_token="a" * 64,
            spawn=lambda socket_path, token_file: FakeCaptureProcess(),
            write_token=lambda path, token: True,
            remove_token=lambda path: None,
            shutdown_requested=lambda: False,
        )

        output = io.StringIO()
        with redirect_stderr(output):
            self.assertTrue(supervisor.check_once())

        self.assertIn("exited unexpectedly", output.getvalue())


    def test_the_polling_thread_notices_a_death_and_stops_on_request(self):
        # check_once() is what the other tests drive; this proves the daemon
        # thread around it actually polls and that stop() ends it.
        restarted = threading.Event()
        process = FakeCaptureProcess()
        supervisor = self._supervisor(
            process,
            poll_interval=0.01,
            reconnect=lambda: (restarted.set(), True)[1],
        )
        self.addCleanup(supervisor.stop)

        supervisor.start()
        self.assertFalse(restarted.wait(0.1), "a live child must not be restarted")

        process.die()
        self.assertTrue(restarted.wait(2.0), "the supervisor never noticed the child died")

        supervisor.stop()
        supervisor._thread.join(timeout=2.0)
        self.assertFalse(supervisor._thread.is_alive())


class CaptureSupervisorWiringTests(unittest.TestCase):
    def test_main_stops_the_supervisor_before_terminating_the_child(self):
        # Ordering is the whole guarantee: a supervisor still ticking while
        # shutdown terminates the child reads that as a crash and respawns a
        # privileged process as the app exits.
        import inspect

        import sniff4hound.manage as manage_module

        source = inspect.getsource(manage_module.main)
        stop_supervisor = source.index("capture_supervisor.stop()")
        shutdown_index = source.index("shutdown_capture()\n        if not embedded:\n            _stop_capture_child(")
        self.assertLess(stop_supervisor, shutdown_index)

    def test_main_signals_the_current_child_not_the_originally_spawned_one(self):
        # After a restart the handle main() spawned is stale; terminating it
        # is a no-op and leaves the live child running as an orphaned root
        # process.
        import inspect

        import sniff4hound.manage as manage_module

        source = inspect.getsource(manage_module.main)
        self.assertIn("capture_process = capture_supervisor.process", source)
        reassign = source.index("capture_process = capture_supervisor.process")
        stop_child = source.index("_stop_capture_child(capture_process)")
        self.assertLess(reassign, stop_child)


if __name__ == "__main__":
    unittest.main()
