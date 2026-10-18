"""Root desktop runtime tied to Electron's lifetime through its stdin pipe.

Polkit execs the runtime as root, so the unprivileged shell cannot send it a
termination signal. Closing the pipe (or crashing the shell) asks this process
to terminate itself instead. No password or application data uses that pipe.
"""

from __future__ import annotations

import signal
import sys
import threading

from .process_control import request_process_shutdown


def _terminate_runtime() -> None:
    # manage.main() handles SIGINT with its cleanup/finally path. SIGTERM's
    # default action can exit before engines, jobs and stores are closed.
    request_process_shutdown(signum=signal.SIGINT)


def _watch_parent(stream, terminate=_terminate_runtime) -> None:
    try:
        while stream.read(1):
            pass
    except OSError:
        pass
    terminate()


def main() -> int:
    from . import manage

    threading.Thread(
        target=_watch_parent,
        args=(sys.stdin.buffer,),
        name="sniff4hound-desktop-lifetime",
        daemon=True,
    ).start()
    return manage.main()


if __name__ == "__main__":
    raise SystemExit(main())
