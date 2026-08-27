from __future__ import annotations

import errno
import os
import shlex
import socket
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
import unicodedata
import webbrowser
from dataclasses import dataclass
from pathlib import Path

from .ipc import generate_ipc_token
from .process_control import request_process_shutdown, reset_process_shutdown_request
from .terminal import PROMPT, set_prompt_active
from .settings import (
    DATA_DIR,
    DB_PATH,
    DEFAULT_PORT,
    HOST,
    PORT,
    default_ipc_token_path,
    resolve_ipc_socket,
    resolve_ipc_token,
    write_ipc_token_file,
)

try:
    import termios
except ImportError:  # pragma: no cover - non-POSIX platforms
    termios = None


from .console import (  # noqa: F401  (re-exported: manage.py is the console's public entry point)
    CONSOLE_COMMAND_ALIASES,
    CONSOLE_COMMAND_SPECS,
    CONSOLE_COMPLETION_TOKENS,
    ConsoleCommandSpec,
    ConsoleContext,
    build_console_completion_candidates,
    configure_console_autocomplete,
    format_runtime_status,
    handle_console_line,
    print_console_help,
    resolve_console_command,
    set_active_console_context,
)

# Private aliases kept so the existing console tests - and any operator muscle
# memory in a REPL - keep addressing these by their original names.
_resolve_console_command = resolve_console_command
_build_console_completion_candidates = build_console_completion_candidates
_print_console_help = print_console_help
_format_runtime_status = format_runtime_status
_configure_console_autocomplete = configure_console_autocomplete


def _handle_console_line(
    raw_line: str,
    *,
    host: str,
    port: int,
    runtime,
    hub,
    append_chat_message,
    store=None,
) -> None:
    handle_console_line(
        raw_line,
        ConsoleContext(
            host=host,
            port=port,
            runtime=runtime,
            hub=hub,
            append_chat_message=append_chat_message,
            store=store,
        ),
    )


BANNER_INNER_WIDTH = 64
FALLBACK_PORT_SCAN_SIZE = 100


def _display_width(value: str) -> int:
    width = 0
    for char in str(value or ""):
        if char in "\r\n":
            continue
        if unicodedata.combining(char):
            continue
        width += 2 if unicodedata.east_asian_width(char) in {"F", "W"} else 1
    return width


def _trim_to_display_width(value: str, max_width: int) -> str:
    chars: list[str] = []
    width = 0
    for char in str(value or ""):
        if char in "\r\n":
            continue
        char_width = 0 if unicodedata.combining(char) else 2 if unicodedata.east_asian_width(char) in {"F", "W"} else 1
        if width + char_width > max_width:
            break
        chars.append(char)
        width += char_width
    return "".join(chars)


def _fit_banner_text(value: str = "", *, align: str = "left") -> str:
    text = _trim_to_display_width(value, BANNER_INNER_WIDTH)
    padding = max(0, BANNER_INNER_WIDTH - _display_width(text))
    if align == "center":
        left = padding // 2
        right = padding - left
        return f"{' ' * left}{text}{' ' * right}"
    if align == "right":
        return f"{' ' * padding}{text}"
    return f"{text}{' ' * padding}"


def _banner_rule(left: str, fill: str, right: str) -> str:
    return f"{left}{fill * BANNER_INNER_WIDTH}{right}"


def _banner_line(value: str = "", *, align: str = "left") -> str:
    return f"║{_fit_banner_text(value, align=align)}║"


def _snapshot_tty_attrs():
    """Save the controlling terminal's current line-discipline settings,
    if any."""
    if termios is None or not sys.stdin.isatty():
        return None
    try:
        return termios.tcgetattr(sys.stdin.fileno())
    except termios.error:
        return None


def _restore_tty_attrs(attrs) -> None:
    """Undo whatever `sudo`'s authentication prompt for the capture child
    did to the shared controlling terminal. A password or fingerprint-
    reader (PAM) prompt commonly switches the tty to raw mode - notably
    without ONLCR, so a bare "\\n" stops returning the cursor to column 0
    and every subsequent printed line drifts further right than the last,
    staircasing the startup banner. `sudo` keeps the same controlling
    terminal as this process even though the capture child's stdout/
    stderr are redirected to a log file (redirection only affects those
    fds, not tty line discipline), so it has to be put back explicitly
    before printing anything of our own."""
    if termios is None or attrs is None:
        return
    try:
        termios.tcsetattr(sys.stdin.fileno(), termios.TCSANOW, attrs)
    except termios.error:
        pass


def _stdout_is_tty() -> bool:
    try:
        return bool(sys.stdout.isatty())
    except Exception:
        return False


def _print_startup_banner(host: str, port: int):
    """Print the startup banner with the active security code."""
    from .auth import REQUIRE_AUTH, get_security_code
    from . import __version__

    token = get_security_code()
    base_url = f"http://{host}:{port}"
    lines = [
        _banner_rule("╔", "═", "╗"),
        _banner_line(f"🐕 SNIFF4HOUND v{__version__}", align="center"),
        _banner_rule("╠", "═", "╣"),
        _banner_line(),
        _banner_line("  Starting server"),
        _banner_line(f"  Link: {base_url}/"),
        _banner_line(f"  Auth Required: {'YES' if REQUIRE_AUTH else 'NO'}"),
        _banner_line(),
        _banner_line("  SECURITY CODE (required to unlock the frontend):"),
        _banner_line(),
        _banner_line(f"    {token}"),
        _banner_line(),
        _banner_line("  Copy the code above and paste it in the auth prompt"),
        _banner_line(),
        _banner_rule("╠", "═", "╣"),
        _banner_line("  Press Ctrl+C to stop"),
        _banner_rule("╚", "═", "╝"),
    ]
    # `sudo`'s PAM prompt for the capture child ("Place your right index
    # finger on the fingerprint reader") is written straight to /dev/tty and
    # leaves its last, unterminated line on screen - a stray "\" ended up
    # sitting right above the banner. Erase whatever is left on the current
    # line before drawing over it.
    prefix = "\r\033[K" if _stdout_is_tty() else ""
    print(prefix + "\n" + "\n".join(lines))


def _candidate_ports(preferred_port: int) -> tuple[int, ...]:
    """Try the requested port first, then nearby fallbacks in a stable order."""
    try:
        preferred_port = int(preferred_port)
    except Exception:
        preferred_port = DEFAULT_PORT
    preferred_port = min(65535, max(1, preferred_port))
    block_start = max(1, (preferred_port // 10) * 10)
    block_end = min(65535, block_start + 9)
    scan_end = min(65535, block_start + FALLBACK_PORT_SCAN_SIZE - 1)
    candidates = []
    seen = set()

    def add_candidate(port: int) -> None:
        if 1 <= int(port) <= 65535 and port not in seen:
            candidates.append(port)
            seen.add(port)

    add_candidate(preferred_port)
    for port in range(block_start, block_end + 1):
        add_candidate(port)
    for port in range(block_end + 1, scan_end + 1):
        add_candidate(port)

    backfill = FALLBACK_PORT_SCAN_SIZE - len(candidates)
    if backfill > 0:
        for port in range(block_start - 1, max(0, block_start - backfill) - 1, -1):
            add_candidate(port)
    return tuple(candidates)


def _port_is_available(host: str, port: int) -> bool:
    """Return False when the target TCP address is already in use."""
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        try:
            sock.bind((host, port))
        except OSError as exc:
            if exc.errno == errno.EADDRINUSE:
                return False
            raise
    return True


def _select_listen_port(host: str, preferred_port: int) -> int | None:
    """Pick the first free port from the preferred port and its nearby fallback block."""
    for candidate in _candidate_ports(preferred_port):
        if _port_is_available(host, candidate):
            return candidate
    return None


def _print_port_fallback_notice(preferred_port: int, selected_port: int) -> None:
    """Explain when Sniff4Hound switches to a nearby free port."""
    print(
        f"\n[i] Port {preferred_port} is busy. Using {selected_port} instead.\n",
        file=sys.stderr,
    )


def _print_address_in_use_error(host: str, preferred_port: int) -> None:
    """Print a clean error when no port is free in the fallback scan range."""
    candidates = _candidate_ports(preferred_port)
    window_start = min(candidates) if candidates else preferred_port
    window_end = max(candidates) if candidates else preferred_port
    print(
        f"\n[!] Cannot start Sniff4Hound: no free port available on {host} in {window_start}-{window_end}.",
        file=sys.stderr,
    )
    print(
        "    Stop the existing process or set SNIFF4HOUND_HOST/SNIFF4HOUND_PORT to another value.\n",
        file=sys.stderr,
    )


def _resolve_db_path() -> Path:
    path = Path(DB_PATH)
    return path if path.is_absolute() else Path.cwd() / path


def _print_db_permission_error(exc: sqlite3.OperationalError) -> None:
    """Sniff4Hound's web process (this one) never runs as root - it opens
    the SQLite database as the invoking user. A "readonly database" error
    here almost always means the db file (or its -wal/-shm siblings) is
    left over from a run under `sudo`, so this process can no longer write
    to it."""
    db_path = _resolve_db_path()
    print(f"\n[!] Cannot open the Sniff4Hound database: {exc}", file=sys.stderr)
    print(f"    Path: {db_path}", file=sys.stderr)
    print(
        "    This usually means the database was previously created by a "
        "privileged (root/sudo) run and this unprivileged process can't write "
        "to it anymore.",
        file=sys.stderr,
    )
    print(
        f"    Fix: sudo chown \"$(id -un):$(id -gn)\" {db_path} {db_path}-wal {db_path}-shm 2>/dev/null\n"
        "    (or delete those files to let Sniff4Hound recreate them, or point "
        "SNIFF4HOUND_DB_PATH at a location you own).\n",
        file=sys.stderr,
    )


def _running_as_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _print_root_invocation_error() -> None:
    """Refusing to ever start this process as root is what makes the
    permission error in _print_db_permission_error() unable to recur: as
    long as Sniff4Hound.db is only ever created by an unprivileged run, no
    future unprivileged run can find it root-owned and unwritable."""
    print("\n[!] Do not run this with `sudo` / as root.", file=sys.stderr)
    print(
        "    The web server and database are meant to run as your normal user - "
        "it spawns the privileged capture child itself (via sudo) when it needs "
        "raw-socket access. Running the whole process as root instead leaves "
        "Sniff4Hound.db owned by root, which then breaks every later "
        "unprivileged run with 'attempt to write a readonly database'.",
        file=sys.stderr,
    )
    print("    Run it as yourself instead, without sudo.\n", file=sys.stderr)


# Policy: capture (raw-socket sniffing, honeypot low-port binds) always
# requires root — a demo/no-capture mode that silently runs unprivileged is
# more confusing than useful, and there is no env var to bypass this. This
# process (the web server) never elevates itself anymore; it spawns
# `sniff4hound-capture` as a privileged child and talks to it over the local
# IPC socket (see sniff4hound/ipc.py,
# sniff4hound/capture_service.py). If elevation of the child fails, this
# process refuses to start rather than silently serving without capture.


# Environment variables that must never be forwarded as `sudo env KEY=VALUE`
# arguments: everything on a process's command line is world-readable through
# /proc/<pid>/cmdline for as long as it runs, so a secret passed that way is
# readable by every local user on the box. The IPC token travels as a path to
# a 0600 file instead (SNIFF4HOUND_IPC_TOKEN_FILE); the JWT signing secret has
# no business in the capture child at all.
CAPTURE_ENV_DENYLIST = frozenset({"SNIFF4HOUND_IPC_TOKEN", "SNIFF4HOUND_JWT_SECRET"})


def _build_capture_relaunch_command(ipc_socket: str, ipc_token_file: str, owner_uid: int) -> list[str]:
    command = ["sudo", "env"]
    for key in sorted(os.environ):
        if key.startswith("SNIFF4HOUND_") and key not in CAPTURE_ENV_DENYLIST:
            command.append(f"{key}={os.environ[key]}")
    # The Debian package doesn't install `sniff4hound` into system
    # site-packages - it's only importable via PYTHONPATH pointing at the
    # vendored copy under /usr/lib/sniff4hound/vendor (see
    # scripts/deb_wrapper.sh). `sudo env ...` does not inherit our
    # PYTHONPATH on its own (sudo resets the environment by default), so it
    # has to be forwarded explicitly or the privileged child can't import
    # the package at all.
    pythonpath = os.environ.get("PYTHONPATH")
    if pythonpath:
        command.append(f"PYTHONPATH={pythonpath}")
    command.append(f"SNIFF4HOUND_IPC_SOCKET={ipc_socket}")
    command.append(f"SNIFF4HOUND_IPC_TOKEN_FILE={ipc_token_file}")
    command.append(f"SNIFF4HOUND_IPC_OWNER_UID={owner_uid}")
    command.extend([sys.executable, "-m", "sniff4hound.capture_service"])
    return command


def _print_capture_elevation_error() -> None:
    print("[!] The capture process requires root/administrator privileges and will not start without them.", file=sys.stderr)
    print("    Raw-socket packet capture is not possible as a regular user.", file=sys.stderr)
    print("    Install sudo, or run `sniff4hound-capture` yourself as root and point this process at it", file=sys.stderr)
    print("    with SNIFF4HOUND_IPC_SOCKET / SNIFF4HOUND_IPC_TOKEN.", file=sys.stderr)


def _remove_ipc_token_file(path: str | None) -> None:
    if not path:
        return
    try:
        Path(path).unlink()
    except OSError:
        pass


def _capture_log_path(ipc_socket: str) -> Path:
    return Path(ipc_socket).with_suffix(".log")


def _open_capture_log(ipc_socket: str):
    log_path = _capture_log_path(ipc_socket)
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        return open(log_path, "ab", buffering=0)
    except OSError:
        return None


def _spawn_capture_child(ipc_socket: str, ipc_token_file: str):
    if shutil.which("sudo") is None:
        _print_capture_elevation_error()
        return None
    command = _build_capture_relaunch_command(ipc_socket, ipc_token_file, os.getuid())

    # The capture child (and the `sudo`/PAM prompt in front of it) must not
    # inherit this process's stdout/stderr: both processes would then write
    # to the same terminal concurrently and, since each does its own
    # line-buffered flushing, their output interleaves unpredictably -
    # producing exactly the garbled/staircased banner this fixes. `sudo`
    # still shows its password/fingerprint prompt fine either way, since it
    # talks to /dev/tty directly rather than through stdout/stderr.
    #
    # stdin must be detached for the same reason, and it is not optional:
    # since sudo 1.9.14 `use_pty` is the built-in default, so sudo runs the
    # capture child on a pty of its own and spends the whole session relaying
    # our terminal into it. With stdin inherited, sudo and the console's
    # input() are two readers on one tty and every keystroke goes to whoever
    # reads first - typing "/help" arrived as "[note] p" with the rest eaten.
    log_file = _open_capture_log(ipc_socket)
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=log_file if log_file is not None else subprocess.DEVNULL,
            stderr=log_file if log_file is not None else subprocess.DEVNULL,
        )
    except OSError as exc:
        print(f"[!] Unable to launch the capture process: {exc}", file=sys.stderr)
        return None
    finally:
        if log_file is not None:
            log_file.close()

    if log_file is not None:
        print(f"[i] Capture process output is logged to {_capture_log_path(ipc_socket)}", file=sys.stderr)
    return process


def _wait_for_process(process, timeout: float) -> bool:
    """`Popen.wait()`, but a KeyboardInterrupt while waiting (the user
    getting impatient - e.g. `sudo` is still blocked on a fingerprint/
    password prompt for the capture child) is treated as "not done yet"
    instead of propagating and aborting the rest of shutdown."""
    try:
        process.wait(timeout=timeout)
        return True
    except subprocess.TimeoutExpired:
        return False
    except KeyboardInterrupt:
        print(
            "\n[i] Still stopping the capture process (it may be waiting on a "
            "sudo prompt) - hang on...",
            file=sys.stderr,
        )
        return False


def _stop_capture_child(process, *, timeout: float = 5.0) -> None:
    if process is None or process.poll() is not None:
        return
    print("[i] Stopping the capture process...", file=sys.stderr)
    try:
        process.terminate()
    except Exception:
        pass

    if _wait_for_process(process, timeout):
        return

    # Graceful shutdown didn't finish in time (or got interrupted again) -
    # SIGKILL is unblockable, so this is guaranteed to actually end the
    # privileged child rather than leaving it orphaned.
    try:
        process.kill()
    except Exception:
        pass
    _wait_for_process(process, 2.0)


def _start_interactive_console(
    *,
    host: str,
    port: int,
    runtime,
    hub,
    append_chat_message,
    store=None,
) -> threading.Thread | None:
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        return None

    context = ConsoleContext(
        host=host,
        port=port,
        runtime=runtime,
        hub=hub,
        append_chat_message=append_chat_message,
        store=store,
    )
    # readline's completer is a context-free global callback, so the "@..."
    # completions read the live runtime back through this module-level slot.
    set_active_console_context(context)

    def _console_loop():
        autocomplete_ready = _configure_console_autocomplete()
        hint = " Press Tab to complete commands and their arguments." if autocomplete_ready else ""
        print(f"[console] Interactive shell ready. Type /help.{hint} Plain text becomes an operator note.")
        while True:
            try:
                # Tells terminal.emit() there is a prompt on screen to redraw,
                # so log lines from other threads do not eat the input.
                set_prompt_active(True)
                line = input(PROMPT)
            except (EOFError, OSError, ValueError):
                break
            except KeyboardInterrupt:
                print()
                request_process_shutdown()
                break
            finally:
                set_prompt_active(False)
            handle_console_line(line, context)

    thread = threading.Thread(
        target=_console_loop,
        name="sniff4hound-console",
        daemon=True,
    )
    thread.start()
    return thread


def _stop_interactive_console(
    thread: threading.Thread | None,
    *,
    input_stream=None,
    join_timeout: float = 1.0,
) -> None:
    if thread is None:
        return
    stream = sys.stdin if input_stream is None else input_stream
    try:
        if stream is not None and not getattr(stream, "closed", False):
            stream.close()
    except Exception:
        pass
    if thread.is_alive():
        try:
            thread.join(timeout=join_timeout)
        except KeyboardInterrupt:
            pass


def main():
    """Combined single-command entry point (`sniff4hound`). Runs the web
    server + database as the invoking (unprivileged) user, and spawns a
    privileged `sniff4hound-capture` child over local IPC for raw-socket
    access. Only the capture child ever needs root - see CLAUDE.md."""
    if _running_as_root():
        _print_root_invocation_error()
        return 1
    reset_process_shutdown_request()
    tty_attrs = _snapshot_tty_attrs()
    host = str(HOST)
    requested_port = int(PORT)
    selected_port = _select_listen_port(host, requested_port)
    console_thread = None
    capture_process = None

    if selected_port is None:
        _print_address_in_use_error(host, requested_port)
        return 1

    ipc_socket = resolve_ipc_socket(selected_port)
    ipc_token = resolve_ipc_token() or generate_ipc_token()
    # The token reaches the privileged child through a 0600 file whose path
    # (never its contents) is what goes on the `sudo env ...` command line -
    # /proc/<pid>/cmdline is world-readable, so the old
    # `SNIFF4HOUND_IPC_TOKEN=<64 hex>` argument handed the capture channel's
    # shared secret to every local user for the life of the process. The file
    # is removed as soon as the child has connected, and again on shutdown.
    ipc_token_file = default_ipc_token_path(ipc_socket)
    if not write_ipc_token_file(ipc_token_file, ipc_token):
        print(f"[!] Could not write the capture IPC token file at {ipc_token_file}.", file=sys.stderr)
        return 1
    os.environ["SNIFF4HOUND_IPC_SOCKET"] = ipc_socket
    os.environ["SNIFF4HOUND_IPC_TOKEN_FILE"] = ipc_token_file
    os.environ.pop("SNIFF4HOUND_IPC_TOKEN", None)
    # DATA_DIR (and so the default DB_PATH, honeypot log/db/certs - see
    # settings.py and honeypot.py) defaults to this process's home
    # directory. The capture child below is relaunched via `sudo`, which
    # resets HOME to root's home by default, so without pinning this
    # explicitly the two processes would silently compute two different
    # paths and the privileged child would persist captured traffic where
    # the web process never looks. setdefault() so an operator-provided
    # SNIFF4HOUND_DATA_DIR/SNIFF4HOUND_DB_PATH still wins.
    os.environ.setdefault("SNIFF4HOUND_DATA_DIR", str(DATA_DIR))

    # Import (and so construct sniff4hound.app's SniffStore, as this
    # unprivileged user) *before* spawning the privileged capture child.
    # Both processes open the same SQLite file; whichever one creates it
    # first owns it on disk, and a root-owned DB file/WAL is unwritable by
    # this process afterwards. Importing first guarantees the web process
    # wins that race regardless of how fast the capture child starts.
    try:
        from .app import app, append_chat_message, bootstrap_capture, connect_capture_service, hub, runtime, shutdown_capture, store
    except sqlite3.OperationalError as exc:
        _print_db_permission_error(exc)
        return 1

    capture_process = _spawn_capture_child(ipc_socket, ipc_token_file)
    if capture_process is None:
        _remove_ipc_token_file(ipc_token_file)
        return 1

    try:
        time.sleep(0.2)
        if capture_process.poll() is not None:
            print(f"[!] Capture process exited immediately (code {capture_process.returncode}).", file=sys.stderr)
            return 1
        if not connect_capture_service():
            print("[!] Sniff4Hound cannot start without the capture process. See the error above.", file=sys.stderr)
            return 1
        # The child has authenticated by now, so nothing needs the file any
        # more - shrink the window in which it exists at all.
        _remove_ipc_token_file(ipc_token_file)

        # sudo's password/fingerprint prompt for the capture child we just
        # waited on can leave the shared controlling terminal in raw mode
        # (see _restore_tty_attrs) - put it back before printing anything.
        _restore_tty_attrs(tty_attrs)

        if selected_port != requested_port:
            _print_port_fallback_notice(requested_port, selected_port)
        _print_startup_banner(host, selected_port)
        console_thread = _start_interactive_console(
            host=host,
            port=selected_port,
            runtime=runtime,
            hub=hub,
            append_chat_message=append_chat_message,
            store=store,
        )
        bootstrap_capture()
        app.run(host, selected_port)
    except OSError as exc:
        if exc.errno == errno.EADDRINUSE:
            _print_address_in_use_error(host, requested_port)
            return 1
        raise
    except KeyboardInterrupt:
        print("\n\n🛑 Shutting down gracefully...\n")
    finally:
        _stop_interactive_console(console_thread)
        shutdown_capture()
        _stop_capture_child(capture_process)
        _remove_ipc_token_file(ipc_token_file)
        reset_process_shutdown_request()
    return 0


def main_web():
    """Standalone entry point for the unprivileged web process
    (`sniff4hound-web`). Never elevates privileges and never spawns a
    capture child - expects SNIFF4HOUND_IPC_SOCKET/SNIFF4HOUND_IPC_TOKEN to
    already point at a `sniff4hound-capture` process started separately
    (its own systemd unit, a different user, a different host, ...)."""
    if _running_as_root():
        _print_root_invocation_error()
        return 1
    reset_process_shutdown_request()
    host = str(HOST)
    requested_port = int(PORT)
    selected_port = _select_listen_port(host, requested_port)
    console_thread = None

    if selected_port is None:
        _print_address_in_use_error(host, requested_port)
        return 1

    try:
        from .app import app, append_chat_message, bootstrap_capture, connect_capture_service, hub, runtime, shutdown_capture, store
    except sqlite3.OperationalError as exc:
        _print_db_permission_error(exc)
        return 1

    try:
        if not connect_capture_service():
            print("[!] sniff4hound-web cannot start without a reachable capture process.", file=sys.stderr)
            return 1

        if selected_port != requested_port:
            _print_port_fallback_notice(requested_port, selected_port)
        _print_startup_banner(host, selected_port)
        console_thread = _start_interactive_console(
            host=host,
            port=selected_port,
            runtime=runtime,
            hub=hub,
            append_chat_message=append_chat_message,
            store=store,
        )
        bootstrap_capture()
        app.run(host, selected_port)
    except OSError as exc:
        if exc.errno == errno.EADDRINUSE:
            _print_address_in_use_error(host, requested_port)
            return 1
        raise
    except KeyboardInterrupt:
        print("\n\n🛑 Shutting down gracefully...\n")
    finally:
        _stop_interactive_console(console_thread)
        shutdown_capture()
        reset_process_shutdown_request()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
