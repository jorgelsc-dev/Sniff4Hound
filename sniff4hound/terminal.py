"""Printing to a terminal that is also waiting on `input()`.

The web server, the capture threads and the WebSocket hub all print from
their own threads while the interactive console sits blocked in `input()`.
A bare `print()` from those threads writes straight over whatever the
operator is halfway through typing: the access log used to interleave itself
character by character with the command being entered, so typing `/help`
came out as three separate garbage notes.

`emit()` fixes that the way any line-oriented REPL does it - erase the
prompt line, write the message, then redraw the prompt with the partially
typed buffer restored, so the caret ends up exactly where it was.
"""

from __future__ import annotations

import sys
import threading

try:
    import readline
except ImportError:  # pragma: no cover - platform dependent
    readline = None

PROMPT = "sniff4hound> "

# Erase from the cursor to the end of the line, after returning to column 0.
_CLEAR_LINE = "\r\033[K"

_state_lock = threading.RLock()
# Serializes the erase/write/redraw sequence: two threads interleaving those
# three writes would corrupt the line just as badly as the bare prints did.
_write_lock = threading.RLock()
_prompt_active = False


def set_prompt_active(active: bool) -> None:
    """Called by the console around `input()` so `emit()` knows whether a
    prompt is currently on screen waiting to be redrawn."""
    global _prompt_active
    with _state_lock:
        _prompt_active = bool(active)


def prompt_is_active() -> bool:
    with _state_lock:
        return _prompt_active


def _stdout_is_tty() -> bool:
    try:
        return bool(sys.stdout.isatty())
    except Exception:
        return False


def _pending_input() -> str:
    """What the operator has typed but not yet submitted."""
    if readline is None:
        return ""
    try:
        return readline.get_line_buffer() or ""
    except Exception:
        return ""


def emit(text: str) -> None:
    """Write `text` above the prompt, leaving any in-progress input intact.

    Falls back to a plain print when there is no prompt to protect (piped
    output, a non-interactive run, or the console not started yet).
    """
    line = str(text)
    if not prompt_is_active() or not _stdout_is_tty():
        try:
            print(line, flush=True)
        except Exception:
            # Logging must never take down the thread that was reporting.
            pass
        return

    pending = _pending_input()
    try:
        with _write_lock:
            out = sys.stdout
            out.write(_CLEAR_LINE)
            out.write(line + "\n")
            out.write(PROMPT + pending)
            out.flush()
    except Exception:
        pass
