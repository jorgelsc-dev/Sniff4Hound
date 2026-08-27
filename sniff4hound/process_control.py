from __future__ import annotations

import os
import signal
import threading


_shutdown_lock = threading.Lock()
_shutdown_requested = threading.Event()


def reset_process_shutdown_request() -> None:
    _shutdown_requested.clear()


def process_shutdown_requested() -> bool:
    return _shutdown_requested.is_set()


def request_process_shutdown(*, signum: int = signal.SIGINT, delay: float = 0.0) -> bool:
    with _shutdown_lock:
        if _shutdown_requested.is_set():
            return False
        _shutdown_requested.set()

    def _send_signal() -> None:
        try:
            os.kill(os.getpid(), signum)
        except ProcessLookupError:
            pass

    if delay > 0:
        timer = threading.Timer(delay, _send_signal)
        timer.daemon = True
        timer.start()
    else:
        _send_signal()
    return True
