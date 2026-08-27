from __future__ import annotations

import importlib
import io
import os
import tempfile
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


if __name__ == "__main__":
    unittest.main()
