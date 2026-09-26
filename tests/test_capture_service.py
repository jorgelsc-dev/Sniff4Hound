from __future__ import annotations

import importlib
import io
import os
import tempfile
import threading
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
        return RuntimeController(**params)

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
        # IpcClient never reconnects on its own, so a respawn alone would
        # leave the web process detached from the child it just started.
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

        # Spawning anyway would start a child that mints its own token and is
        # unreachable over IPC - worse than not restarting at all.
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
        shutdown_index = source.index("shutdown_capture()\n        _stop_capture_child(")
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
