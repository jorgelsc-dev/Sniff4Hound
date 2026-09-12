import unittest

from sniff4hound.web_console import execute_dashboard_command


class _Runtime:
    def __init__(self):
        self.running = {"sniffer": False, "honeypot": False}
        self.mode = "sniffer"

    def snapshot(self):
        return {
            "mode": self.mode,
            "sniffer": {"running": self.running["sniffer"], "packets_seen": 4, "available_interfaces": ["eth0"], "selected_interfaces": []},
            "honeypot": {"running": self.running["honeypot"], "packets_seen": 2},
        }

    def start(self, engine=None):
        targets = self.running if engine == "all" else [engine or self.mode]
        for target in targets:
            self.running[target] = True
        return self.snapshot()

    def stop(self, engine=None):
        targets = self.running if engine == "all" else [engine or self.mode]
        for target in targets:
            self.running[target] = False
        return self.snapshot()

    def set_mode(self, mode):
        self.mode = mode
        return self.snapshot()

    def set_sniffer_interfaces(self, _names):
        return self.snapshot()

    def list_honeypot_listeners(self):
        return []


class _Store:
    def list_recent_alerts(self, **_kwargs): return []
    def list_packets(self, **_kwargs): return []
    def top_ips(self, **_kwargs): return [{"ip": "192.168.1.1", "value": 12}]
    def top_ports(self, **_kwargs): return []
    def top_protocols(self, **_kwargs): return []
    def ip_intel(self, _ip): return {}
    def list_monitors(self): return []


class _Hub:
    def list_clients(self): return []
    def broadcast(self, _payload): return None


class WebConsoleTests(unittest.TestCase):
    def setUp(self):
        self.runtime = _Runtime()
        self.kwargs = {"runtime": self.runtime, "store": _Store(), "hub": _Hub()}

    def test_status_and_engine_control(self):
        status = execute_dashboard_command("/status", **self.kwargs)
        self.assertIn("Sniffer: detenido", status["output"])
        started = execute_dashboard_command("/start all", **self.kwargs)
        self.assertTrue(started["ok"])
        self.assertTrue(all(self.runtime.running.values()))

    def test_system_and_destructive_commands_are_not_available(self):
        for command in ("ls", "/clear all --yes", "/quit", "/does-not-exist"):
            with self.subTest(command=command), self.assertRaises(ValueError):
                execute_dashboard_command(command, **self.kwargs)

    def test_top_command_formats_store_label_and_value(self):
        result = execute_dashboard_command("/top ips 5", **self.kwargs)
        self.assertIn("192.168.1.1 · 12", result["output"])

if __name__ == "__main__":
    unittest.main()
