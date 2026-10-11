"""The capture engines, running inside the web process.

By default the privileged engines live in their own process (`capture_service`)
and the web process drives them over local IPC. The combined entry point is
already one elevated process tree, so there it runs them in place instead: the
same `Sniffer`, `HoneypotEngine` and `RuntimeController`, with no socket in
between. That removes a whole class of failure (a stalled or restarted capture
process, a rejected token, a missed reconnect) and the child, the token file and
the supervisor that existed to manage it.

What the split gave that is kept:

* The engines write through their own database connection, so a burst of
  captured packets does not queue behind a long API read on the same connection
  (SQLite is in WAL mode: readers and a writer run side by side).
* Events do not run on the capture threads. They go through a bounded queue to a
  delivery thread, so a slow WebSocket client cannot hold up packet capture; when
  that queue is full an event is dropped and counted, as a slow IPC peer dropped
  them before.
"""

from __future__ import annotations

import queue
import threading
from typing import Any, Callable

from . import log_setup
from .resource_guard import ResourceGuard
from .runtime_controller import RuntimeController
from .settings import CAPTURE_AUTO_START, CAPTURE_INTERFACES, DB_PATH

EVENT_QUEUE_SIZE = 10000
_STOP = object()


class EventSink:
    """What the engines are given as their hub: they only ever call
    `.broadcast(dict)`. Delivery happens on a thread of its own."""

    def __init__(self, deliver: Callable[[dict], None], *, maxsize: int = EVENT_QUEUE_SIZE) -> None:
        self._deliver = deliver
        self._queue: queue.Queue = queue.Queue(maxsize=maxsize)
        self.dropped = 0
        self._thread = threading.Thread(target=self._run, name="sniff4hound-capture-events", daemon=True)
        self._thread.start()

    def broadcast(self, payload: dict) -> None:
        try:
            self._queue.put_nowait(payload)
        except queue.Full:
            self.dropped += 1

    def _run(self) -> None:
        while True:
            payload = self._queue.get()
            if payload is _STOP:
                return
            try:
                self._deliver(payload)
            except Exception:  # noqa: BLE001 - one bad listener must not end the event stream
                pass

    def close(self, timeout: float = 2.0) -> None:
        # Whatever is still queued is delivered first; the sentinel goes in last.
        try:
            self._queue.put(_STOP, timeout=timeout)
        except queue.Full:
            return
        self._thread.join(timeout)


class EmbeddedCapture:
    """A `RuntimeController` and its engines, in this process.

    `runtime` has the public methods of `RuntimeController`, which are the same
    ones the web process calls on the capture process over IPC, so no route has
    to know which of the two it is talking to.
    """

    def __init__(
        self,
        deliver: Callable[[dict], None],
        *,
        db_path=DB_PATH,
        interfaces=CAPTURE_INTERFACES,
        auto_start: bool = CAPTURE_AUTO_START,
    ) -> None:
        # Imported here and not at the top: honeypot.py opens its log file as it
        # is imported, and sniffer.py pulls in raw-socket machinery. A web process
        # that talks to a separate capture process must import neither.
        from .honeypot import HoneypotEngine
        from .sniffer import Sniffer
        from .store import SniffStore

        self.store = SniffStore(db_path)
        self.events = EventSink(deliver)
        self.sniffer = Sniffer(self.store, self.events, interfaces=interfaces)
        self.honeypot = HoneypotEngine(self.store, self.events)
        self.runtime = RuntimeController(
            store=self.store,
            sniffer=self.sniffer,
            honeypot=self.honeypot,
            hub=self.events,
            capture_auto_start=auto_start,
        )
        # Stops capture and the pipeline jobs when a CPU/RAM/storage limit is
        # exceeded, and resumes them once back under the threshold.
        self.guard = ResourceGuard(self.store, self.sniffer, log_dir=log_setup.log_directory())
        self.guard.start()
        self._closed = False

    def close(self) -> None:
        """Stop everything, in an order that cannot leave a thread writing to a
        closed database. Every step runs even if an earlier one fails."""
        if self._closed:
            return
        self._closed = True
        for step in (self.guard.stop, self.sniffer.stop, self.honeypot.stop, self.events.close, self.store.close):
            try:
                step()
            except Exception:  # noqa: BLE001
                pass
