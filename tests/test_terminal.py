from __future__ import annotations

import io
import sys
import threading
import unittest
from unittest.mock import patch

from sniff4hound import terminal


class _FakeTty(io.StringIO):
    def isatty(self):
        return True


class _FakePipe(io.StringIO):
    def isatty(self):
        return False


def _emit_with(text, *, pending="", tty=True, active=True, **kwargs):
    stream = _FakeTty() if tty else _FakePipe()
    with patch.object(terminal, "readline") as fake_readline:
        fake_readline.get_line_buffer.return_value = pending
        with patch.object(sys, "stdout", stream):
            terminal.set_prompt_active(active)
            try:
                terminal.emit(text, **kwargs)
            finally:
                terminal.set_prompt_active(False)
    return stream.getvalue()


class EmitAbovePromptTests(unittest.TestCase):
    def tearDown(self):
        terminal.set_prompt_active(False)

    def test_restores_what_the_operator_was_typing(self):
        # The bug this exists for: a log line printed mid-command used to eat
        # the input, so typing "/help" arrived as several stray notes.
        out = _emit_with("GET /api/runtime/ 200", pending="/hel")
        self.assertTrue(out.endswith(f"{terminal.PROMPT}/hel"), out)

    def test_erases_the_prompt_line_before_writing(self):
        out = _emit_with("a log line", pending="/status")
        self.assertTrue(out.startswith("\r\033[K"), repr(out))
        # The log itself must not be preceded by the old prompt text.
        self.assertNotIn(f"{terminal.PROMPT}/status\na log line", out)

    def test_prompt_follows_the_log_line_without_a_blank_line(self):
        # One newline, not two: a padding blank line after every access-log
        # row double-spaced the whole console for no benefit.
        out = _emit_with("a log line", pending="")
        self.assertIn(f"line\n{terminal.PROMPT}", out)
        self.assertNotIn(f"\n\n{terminal.PROMPT}", out)

    def test_consecutive_log_lines_are_not_double_spaced(self):
        stream = _FakeTty()
        with patch.object(terminal, "readline") as fake_readline:
            fake_readline.get_line_buffer.return_value = ""
            with patch.object(sys, "stdout", stream):
                terminal.set_prompt_active(True)
                try:
                    terminal.emit("first")
                    terminal.emit("second")
                finally:
                    terminal.set_prompt_active(False)
        self.assertNotIn("\n\n", stream.getvalue())

    def test_message_is_written_exactly_once(self):
        out = _emit_with("unique-marker", pending="/x")
        self.assertEqual(out.count("unique-marker"), 1, out)

    def test_plain_print_when_no_prompt_is_showing(self):
        out = _emit_with("a log line", active=False)
        self.assertEqual(out, "a log line\n")

    def test_plain_print_when_stdout_is_not_a_tty(self):
        # Piped output (systemd, a file) must stay free of escape codes.
        out = _emit_with("a log line", pending="/x", tty=False)
        self.assertEqual(out, "a log line\n")
        self.assertNotIn("\033[", out)

    def test_empty_pending_buffer_still_redraws_the_prompt(self):
        out = _emit_with("a log line", pending="")
        self.assertTrue(out.endswith(terminal.PROMPT), out)

    def test_a_broken_readline_does_not_raise(self):
        stream = _FakeTty()
        with patch.object(terminal, "readline") as fake_readline:
            fake_readline.get_line_buffer.side_effect = RuntimeError("boom")
            with patch.object(sys, "stdout", stream):
                terminal.set_prompt_active(True)
                terminal.emit("still logged")  # must not raise
                terminal.set_prompt_active(False)
        self.assertIn("still logged", stream.getvalue())

    def test_concurrent_emits_do_not_interleave(self):
        # Each emit is an erase/write/redraw triple; without the write lock two
        # threads can splice their sequences together and corrupt the line.
        stream = _FakeTty()
        # Zero-padded so no name is a prefix of another: "line-1" would
        # otherwise match inside "line-10" and fake a duplicate.
        lines = [f"line-{i:03d}-end" for i in range(40)]
        with patch.object(terminal, "readline") as fake_readline:
            fake_readline.get_line_buffer.return_value = ""
            with patch.object(sys, "stdout", stream):
                terminal.set_prompt_active(True)
                threads = [threading.Thread(target=terminal.emit, args=(line,)) for line in lines]
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join()
                terminal.set_prompt_active(False)
        out = stream.getvalue()
        for line in lines:
            self.assertEqual(out.count(line), 1, f"{line} was mangled")


class PromptStateTests(unittest.TestCase):
    def tearDown(self):
        terminal.set_prompt_active(False)

    def test_prompt_state_round_trips(self):
        self.assertFalse(terminal.prompt_is_active())
        terminal.set_prompt_active(True)
        self.assertTrue(terminal.prompt_is_active())
        terminal.set_prompt_active(False)
        self.assertFalse(terminal.prompt_is_active())


class AccessLogRoutingTests(unittest.TestCase):
    def test_access_log_writes_through_the_terminal_helper(self):
        # Regression guard: a plain print() here is what broke the prompt.
        from sniff4hound import access_log

        with patch.object(terminal, "emit") as emit:
            access_log._emit("a log line")
        emit.assert_called_once_with("a log line")


if __name__ == "__main__":
    unittest.main()
