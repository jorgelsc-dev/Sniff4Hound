from __future__ import annotations

import io
import sys
import threading
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from sniff4hound import console


class _FakeRuntime:
    def __init__(self):
        self.mode_calls = []
        self.interface_calls = []
        self.listener_calls = []
        self.started = 0
        self.stopped = 0

    def snapshot(self):
        return {
            "mode": "sniffer",
            "active": {
                "running": True,
                "packets_seen": 42,
                "available_interfaces": ["lo", "eth0", "wlan0"],
                "selected_interfaces": ["eth0"],
            },
        }

    def start(self):
        self.started += 1
        return self.snapshot()

    def stop(self):
        self.stopped += 1
        return {"mode": "sniffer", "active": {"running": False}}

    def set_mode(self, mode):
        self.mode_calls.append(mode)
        return {"mode": mode}

    def set_sniffer_interfaces(self, names):
        self.interface_calls.append(list(names))
        return {"interfaces": list(names)}

    def list_honeypot_listeners(self):
        return [{"id": "tcp/22", "enabled": True, "running": False, "label": "ssh"}]

    def set_honeypot_listener_enabled(self, listener_id, enabled):
        self.listener_calls.append((listener_id, enabled))
        return {"id": listener_id, "enabled": enabled}


class _FakeHub:
    def list_clients(self):
        return [{"id": 1, "addr": "127.0.0.1", "connected_at": "now"}]


class _FakeStore:
    def __init__(self):
        self.toggles = []
        self.cleared = []

    def list_monitors(self):
        return [
            {"id": "builtin-credentials", "name": "Cleartext credentials",
             "enabled": True, "action": {"severity": "high"}, "mode": "regex", "source": "builtin"},
            {"id": "builtin-port-scan", "name": "Port scan",
             "enabled": False, "action": {"severity": "medium"}, "mode": "stateful", "source": "builtin"},
        ]

    def get_monitor(self, monitor_id):
        for row in self.list_monitors():
            if row["id"] == monitor_id:
                return row
        return None

    def set_monitor_enabled(self, monitor_id, enabled):
        self.toggles.append((monitor_id, enabled))

    def top_ips(self, *, limit=10):
        return [{"ip": "10.0.0.5", "count": 9}, {"ip": "10.0.0.9", "count": 4}][:limit]

    def clear_detections(self, scope="all"):
        self.cleared.append(scope)
        return {"packets": 12}

    def purge_capture_data(self):
        self.cleared.append("everything")
        return {"packets": 12, "flows": 3, "domains": 1}


def _context(store=None, runtime=None, hub=None):
    return console.ConsoleContext(
        host="127.0.0.1",
        port=45678,
        runtime=runtime or _FakeRuntime(),
        hub=hub or _FakeHub(),
        append_chat_message=lambda *args, **kwargs: {"content": "note"},
        store=store if store is not None else _FakeStore(),
    )


def _run(line, context):
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        console.handle_console_line(line, context)
    return buffer.getvalue()


def _complete(buffer, text):
    return console.build_console_completion_candidates(buffer, text, len(buffer) - len(text))


class ConsoleRegistryTests(unittest.TestCase):
    def test_every_command_has_a_handler(self):
        declared = {spec.command for spec in console.CONSOLE_COMMAND_SPECS}
        self.assertEqual(declared, set(console.CONSOLE_HANDLERS))

    def test_every_alias_resolves_to_a_real_command(self):
        for alias, target in console.CONSOLE_COMMAND_ALIASES.items():
            self.assertIn(target, console.CONSOLE_HANDLERS, f"{alias} -> {target}")

    def test_declared_completion_providers_all_exist(self):
        for spec in console.CONSOLE_COMMAND_SPECS:
            for entry in spec.completions or ():
                if isinstance(entry, str) and entry.startswith("@"):
                    self.assertIn(entry, console._COMPLETION_PROVIDERS, spec.command)

    def test_usage_line_starts_with_its_own_command(self):
        for spec in console.CONSOLE_COMMAND_SPECS:
            self.assertTrue(spec.usage_line().startswith(spec.command), spec.command)


class ConsoleCompletionTests(unittest.TestCase):
    def setUp(self):
        console.set_active_console_context(_context())
        self.addCleanup(console.set_active_console_context, None)

    def test_completes_command_names_from_a_prefix(self):
        self.assertEqual(_complete("/mo", "/mo"), ["/mode", "/monitor", "/monitors"])

    def test_bare_slash_offers_every_command_and_alias(self):
        self.assertEqual(len(_complete("/", "/")), len(console.CONSOLE_COMPLETION_TOKENS))

    def test_plain_text_is_not_completed_as_a_command(self):
        self.assertEqual(_complete("hello", "hello"), [])

    def test_completes_literal_first_argument(self):
        self.assertEqual(_complete("/mode ", ""), ["sniffer", "honeypot"])
        self.assertEqual(_complete("/mode s", "s"), ["sniffer"])

    def test_completes_second_argument_slot_independently(self):
        self.assertEqual(_complete("/monitor ", ""), ["show", "on", "off"])
        self.assertEqual(_complete("/monitor off ", ""), ["builtin-credentials", "builtin-port-scan"])

    def test_dynamic_provider_reads_the_live_runtime(self):
        self.assertEqual(_complete("/interfaces ", ""), ["all", "lo", "eth0", "wlan0"])

    def test_trailing_provider_slot_repeats_for_extra_arguments(self):
        # /interfaces takes any number of names, so slot 4 must still complete.
        self.assertEqual(_complete("/interfaces eth0 lo wlan0 ", ""), ["all", "lo", "eth0", "wlan0"])

    def test_unknown_command_completes_nothing(self):
        self.assertEqual(_complete("/nope ", ""), [])

    def test_command_without_declared_arguments_completes_nothing(self):
        self.assertEqual(_complete("/status ", ""), [])

    def test_help_completes_command_names(self):
        self.assertIn("/mode", _complete("/help /mo", "/mo"))

    def test_provider_failure_degrades_to_no_candidates(self):
        class Exploding:
            def snapshot(self):
                raise RuntimeError("capture process gone")

        console.set_active_console_context(_context(runtime=Exploding()))
        self.assertEqual(_complete("/interfaces ", ""), [])


class ConsoleCommandTests(unittest.TestCase):
    def test_status_reports_mode_and_clients(self):
        output = _run("/status", _context())
        self.assertIn("mode=sniffer", output)
        self.assertIn("ws_clients=1", output)

    def test_mode_rejects_an_unknown_engine(self):
        runtime = _FakeRuntime()
        output = _run("/mode bogus", _context(runtime=runtime))
        self.assertIn("Usage: /mode", output)
        self.assertEqual(runtime.mode_calls, [])

    def test_restart_stops_then_starts(self):
        runtime = _FakeRuntime()
        _run("/restart", _context(runtime=runtime))
        self.assertEqual((runtime.stopped, runtime.started), (1, 1))

    def test_interfaces_without_arguments_lists_and_marks_the_selection(self):
        output = _run("/interfaces", _context())
        self.assertIn("* eth0", output)
        self.assertIn("wlan0", output)

    def test_interfaces_all_clears_the_selection(self):
        runtime = _FakeRuntime()
        _run("/interfaces all", _context(runtime=runtime))
        self.assertEqual(runtime.interface_calls, [[]])

    def test_interfaces_sets_the_named_interfaces(self):
        runtime = _FakeRuntime()
        _run("/interfaces eth0 wlan0", _context(runtime=runtime))
        self.assertEqual(runtime.interface_calls, [["eth0", "wlan0"]])

    def test_monitor_toggle_calls_the_store(self):
        store = _FakeStore()
        _run("/monitor off builtin-credentials", _context(store=store))
        self.assertEqual(store.toggles, [("builtin-credentials", False)])

    def test_monitor_reports_an_unknown_id(self):
        store = _FakeStore()
        output = _run("/monitor on does-not-exist", _context(store=store))
        self.assertIn("No such monitor", output)
        self.assertEqual(store.toggles, [])

    def test_monitors_search_filters_by_substring(self):
        output = _run("/monitors port", _context())
        self.assertIn("builtin-port-scan", output)
        self.assertNotIn("builtin-credentials", output)

    def test_listener_toggle_reaches_the_runtime(self):
        runtime = _FakeRuntime()
        _run("/listener on tcp/22", _context(runtime=runtime))
        self.assertEqual(runtime.listener_calls, [("tcp/22", True)])

    def test_clear_requires_explicit_confirmation(self):
        store = _FakeStore()
        output = _run("/clear all", _context(store=store))
        self.assertIn("--yes", output)
        self.assertEqual(store.cleared, [], "destructive command ran without confirmation")

    def test_clear_with_yes_actually_clears(self):
        store = _FakeStore()
        _run("/clear all --yes", _context(store=store))
        self.assertEqual(store.cleared, ["all"])

    def test_clear_rejects_an_unknown_scope(self):
        store = _FakeStore()
        output = _run("/clear the-whole-disk --yes", _context(store=store))
        self.assertIn("Usage: /clear", output)
        self.assertEqual(store.cleared, [])

    def test_clear_monitors_maps_to_the_store_sniffer_scope(self):
        # The dashboard and this command say "monitors"; SniffStore calls the
        # same half "sniffer". Passing "monitors" straight through used to
        # raise "Unknown scope".
        store = _FakeStore()
        _run("/clear monitors --yes", _context(store=store))
        self.assertEqual(store.cleared, ["sniffer"])

    def test_clear_everything_purges_capture_data(self):
        store = _FakeStore()
        _run("/clear everything --yes", _context(store=store))
        self.assertEqual(store.cleared, ["everything"])

    def test_clear_everything_still_needs_confirmation(self):
        store = _FakeStore()
        output = _run("/clear everything", _context(store=store))
        self.assertIn("--yes", output)
        self.assertIn("flows", output)
        self.assertEqual(store.cleared, [])

    def test_top_ips_renders_rows(self):
        output = _run("/top ips", _context())
        self.assertIn("10.0.0.5", output)

    def test_unknown_command_is_reported(self):
        self.assertIn("Unknown command", _run("/nope", _context()))

    def test_plain_text_becomes_an_operator_note(self):
        self.assertIn("[note]", _run("perimeter looks quiet", _context()))

    def test_a_failing_handler_does_not_escape(self):
        class Exploding:
            def list_clients(self):
                raise RuntimeError("hub is gone")

        # The console thread must survive: a live server with no shell is
        # worse than a command that reports it failed.
        output = _run("/status", _context(hub=Exploding()))
        self.assertIn("/status failed", output)

    def test_unbalanced_quotes_report_instead_of_raising(self):
        self.assertIn("Invalid command", _run('/broadcast "unclosed', _context()))

    def test_quit_requests_shutdown_once(self):
        with patch.object(console, "request_process_shutdown", return_value=True) as shutdown:
            output = _run("/quit", _context())
        shutdown.assert_called_once_with()
        self.assertIn("Stopping Sniff4Hound", output)


class ConsoleStartupTests(unittest.TestCase):
    """The console runs on its own daemon thread, so anything it raises is
    swallowed into a `Exception in thread sniff4hound-console` traceback on
    stderr and the operator is left with a live server and a dead shell.

    Regression: extracting the console into its own module left
    `_configure_console_autocomplete` behind in manage.py, and nothing caught
    it because no test had ever actually started the loop.
    """

    def _start(self):
        import sniff4hound.manage as manage_module

        class _TtyIn(io.StringIO):
            def isatty(self):
                return True

        class _TtyOut(io.StringIO):
            def isatty(self):
                return True

        raised = []
        previous_hook = threading.excepthook
        threading.excepthook = lambda args: raised.append(args)
        self.addCleanup(setattr, threading, "excepthook", previous_hook)

        with patch.object(sys, "stdin", _TtyIn("")), patch.object(sys, "stdout", _TtyOut()):
            thread = manage_module._start_interactive_console(
                host="127.0.0.1",
                port=45678,
                runtime=_FakeRuntime(),
                hub=_FakeHub(),
                append_chat_message=lambda *args, **kwargs: {},
                store=_FakeStore(),
            )
        if thread is not None:
            thread.join(timeout=5)
        return thread, raised

    def test_console_thread_starts_without_raising(self):
        thread, raised = self._start()
        self.assertIsNotNone(thread, "console thread was never started")
        self.assertEqual(
            [f"{a.exc_type.__name__}: {a.exc_value}" for a in raised],
            [],
        )

    def test_console_is_not_started_without_a_tty(self):
        import sniff4hound.manage as manage_module

        with patch.object(sys.stdin, "isatty", return_value=False):
            thread = manage_module._start_interactive_console(
                host="127.0.0.1",
                port=45678,
                runtime=_FakeRuntime(),
                hub=_FakeHub(),
                append_chat_message=lambda *args, **kwargs: {},
            )
        self.assertIsNone(thread)

    def test_autocomplete_setup_is_callable_and_reports_a_bool(self):
        self.assertIsInstance(console.configure_console_autocomplete(), bool)

    def test_manage_still_exposes_the_private_console_names(self):
        import sniff4hound.manage as manage_module

        # manage.py is the console's historical entry point; these names are
        # re-exported on purpose and _console_loop calls one of them.
        for name in (
            "_configure_console_autocomplete",
            "_build_console_completion_candidates",
            "_handle_console_line",
            "_resolve_console_command",
            "_print_console_help",
            "_format_runtime_status",
        ):
            self.assertTrue(callable(getattr(manage_module, name, None)), name)


class ConsoleHelpTests(unittest.TestCase):
    def setUp(self):
        console.set_active_console_context(_context())
        self.addCleanup(console.set_active_console_context, None)

    def test_help_lists_every_command(self):
        output = _run("/help", _context())
        for spec in console.CONSOLE_COMMAND_SPECS:
            self.assertIn(spec.command, output)

    def test_help_for_one_command_shows_usage_and_valid_values(self):
        output = _run("/help /mode", _context())
        self.assertIn("/mode sniffer|honeypot", output)
        self.assertIn("sniffer", output)
        self.assertIn("honeypot", output)

    def test_help_resolves_aliases(self):
        self.assertIn("/status", _run("/help /stats", _context()))

    def test_help_for_an_unknown_command_says_so(self):
        self.assertIn("Unknown command", _run("/help /nope", _context()))


if __name__ == "__main__":
    unittest.main()
