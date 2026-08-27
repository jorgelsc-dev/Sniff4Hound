"""Entry point for the privileged capture process (`sniff4hound-capture`).

Owns everything that needs elevated privileges: `Sniffer` (raw AF_PACKET
sockets) and `HoneypotEngine` (binds ports <1024). Talks to the unprivileged
web process (`sniff4hound.app`, started by `sniff4hound-web` or the combined
`sniff4hound` command) over a local Unix-socket IPC channel (`sniff4hound.ipc`) - never
opens a network-facing HTTP listener itself.

Privilege policy mirrors what `manage.py` used to enforce for the whole
process: capture requires root and will not run without it, with no
environment variable to bypass this - raw-socket capture is the point of
the tool. See CLAUDE.md.
"""

from __future__ import annotations

import os
import shlex
import shutil
import signal
import sys
import tempfile
import time
from pathlib import Path

from .ipc import IpcEventSink, IpcServer, generate_ipc_token
from .process_control import process_shutdown_requested, request_process_shutdown, reset_process_shutdown_request
from .runtime_controller import RuntimeController
from .settings import CAPTURE_AUTO_START, CAPTURE_INTERFACES, DB_PATH, PORT
from .settings import (
    resolve_ipc_owner_uid,
    resolve_ipc_socket,
    resolve_ipc_token,
    resolve_ipc_token_file,
    write_ipc_token_file,
)


def _is_running_as_admin() -> bool:
    geteuid = getattr(os, "geteuid", None)
    if callable(geteuid):
        try:
            return int(geteuid()) == 0
        except Exception:
            return False
    return False


# Never forwarded on the `sudo env ...` command line: /proc/<pid>/cmdline is
# world-readable, so a secret passed as an argument is readable by every
# local user. An operator-supplied SNIFF4HOUND_IPC_TOKEN is spilled to a 0600
# file first and only its path is forwarded (see _relaunch_env_assignments).
ADMIN_RELAUNCH_ENV_DENYLIST = frozenset({"SNIFF4HOUND_IPC_TOKEN", "SNIFF4HOUND_JWT_SECRET"})


def _spill_ipc_token_to_file(token: str) -> str:
    """Write an inherited IPC token to a private 0600 file so the sudo
    relaunch can pass a path instead of the secret itself. Returns "" when
    the file could not be created."""
    directory = tempfile.mkdtemp(prefix="sniff4hound-capture-")
    try:
        os.chmod(directory, 0o700)
    except OSError:
        pass
    path = str(Path(directory) / "ipc.token")
    if not write_ipc_token_file(path, token):
        return ""
    # The relaunched (root) process reads it back and removes it, see main().
    os.environ["SNIFF4HOUND_IPC_TOKEN_FILE_EPHEMERAL"] = "1"
    return path


def _relaunch_env_assignments() -> list[str]:
    assignments = []
    token = os.environ.get("SNIFF4HOUND_IPC_TOKEN", "").strip()
    token_file = os.environ.get("SNIFF4HOUND_IPC_TOKEN_FILE", "").strip()
    if token and not token_file:
        spilled = _spill_ipc_token_to_file(token)
        if spilled:
            os.environ["SNIFF4HOUND_IPC_TOKEN_FILE"] = spilled
    for key in sorted(os.environ):
        if key.startswith("SNIFF4HOUND_") and key not in ADMIN_RELAUNCH_ENV_DENYLIST:
            assignments.append(f"{key}={os.environ[key]}")
    return assignments


def _build_admin_relaunch_command() -> list[str]:
    command = ["sudo", "env", *_relaunch_env_assignments()]
    command.extend([sys.executable, "-m", "sniff4hound.capture_service", *sys.argv[1:]])
    return command


def _print_admin_required_message() -> None:
    command = shlex.join([sys.executable, "-m", "sniff4hound.capture_service", *sys.argv[1:]])
    print("[!] sniff4hound-capture requires root/administrator privileges and will not start without them.", file=sys.stderr)
    print("    Raw-socket packet capture is not possible as a regular user.", file=sys.stderr)
    print(f"    Re-run with: sudo {command}", file=sys.stderr)


def _chown_sqlite_files(db_path, uid: int) -> None:
    """Best-effort: if this (root) process happened to create the shared
    SQLite database (and its WAL/SHM sidecars) before the unprivileged web
    process got to it, hand ownership back so that process can still open
    it for writing. The combined `sniff4hound` command avoids this race by
    construction (see manage.main()), but a split `sniff4hound-web` /
    `sniff4hound-capture` deployment has no such ordering guarantee."""
    base = str(db_path)
    for suffix in ("", "-wal", "-shm", "-journal"):
        candidate = Path(f"{base}{suffix}")
        if candidate.exists():
            try:
                os.chown(candidate, uid, -1)
            except OSError:
                pass


def _ensure_admin_privileges() -> bool:
    if _is_running_as_admin():
        return True
    if shutil.which("sudo") is None:
        _print_admin_required_message()
        return False
    try:
        os.execvp("sudo", _build_admin_relaunch_command())
    except OSError as exc:
        print(f"[!] Unable to elevate sniff4hound-capture automatically: {exc}", file=sys.stderr)
        _print_admin_required_message()
        return False
    return True  # unreachable when execvp succeeds


def _discard_ephemeral_token_file(path: str) -> None:
    if not path:
        return
    target = Path(path)
    try:
        target.unlink()
    except OSError:
        pass
    try:
        target.parent.rmdir()
    except OSError:
        pass


def main() -> int:
    reset_process_shutdown_request()

    if not _is_running_as_admin() and not _ensure_admin_privileges():
        return 1

    from .honeypot import HoneypotEngine
    from .sniffer import Sniffer
    from .store import SniffStore

    token = resolve_ipc_token()
    # A token file created purely to keep the secret off the sudo command
    # line has done its job the moment it has been read (see
    # _spill_ipc_token_to_file).
    if token and os.environ.get("SNIFF4HOUND_IPC_TOKEN_FILE_EPHEMERAL", "") == "1":
        _discard_ephemeral_token_file(resolve_ipc_token_file())
    token_was_generated = not token
    if token_was_generated:
        token = generate_ipc_token()
    socket_path = resolve_ipc_socket(PORT)
    owner_uid = resolve_ipc_owner_uid()

    store = SniffStore(DB_PATH)
    server = IpcServer(socket_path, token)
    event_sink = IpcEventSink(server)
    sniffer = Sniffer(store, event_sink, interfaces=CAPTURE_INTERFACES)
    honeypot = HoneypotEngine(store, event_sink)
    runtime = RuntimeController(
        store=store,
        sniffer=sniffer,
        honeypot=honeypot,
        hub=event_sink,
        capture_auto_start=CAPTURE_AUTO_START,
    )

    server.methods.update(
        {
            "start": runtime.start,
            "stop": runtime.stop,
            "set_mode": runtime.set_mode,
            # Sniffer and honeypot are independent engines; set_engines sets
            # the running set outright (none, either, or both).
            "set_engines": runtime.set_engines,
            "set_sniffer_interfaces": runtime.set_sniffer_interfaces,
            "set_sniffer_interface": runtime.set_sniffer_interface,
            "list_honeypot_listeners": runtime.list_honeypot_listeners,
            "create_honeypot_listener": runtime.create_honeypot_listener,
            "set_honeypot_listener_enabled": runtime.set_honeypot_listener_enabled,
            "snapshot": runtime.snapshot,
            "shutdown": request_process_shutdown,
        }
    )

    if owner_uid is not None and os.geteuid() == 0:
        try:
            server.chown_socket(owner_uid)
        except OSError as exc:
            print(f"[!] Could not chown IPC socket to uid {owner_uid}: {exc}", file=sys.stderr)
        _chown_sqlite_files(DB_PATH, owner_uid)

    signal.signal(signal.SIGTERM, lambda _signum, _frame: request_process_shutdown(signum=signal.SIGINT))

    server.start()
    print(f"[capture] Listening on {server.socket_path}")
    if token_was_generated:
        print("[capture] No SNIFF4HOUND_IPC_TOKEN provided - generated one for standalone use:")
        print(f"[capture]   SNIFF4HOUND_IPC_SOCKET={socket_path}")
        print(f"[capture]   SNIFF4HOUND_IPC_TOKEN={token}")

    try:
        while not process_shutdown_requested():
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        print("\n[capture] Shutting down...")
        try:
            sniffer.stop()
        except Exception:
            pass
        try:
            honeypot.stop()
        except Exception:
            pass
        server.stop()
        try:
            store.close()
        except Exception:
            pass
        reset_process_shutdown_request()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
