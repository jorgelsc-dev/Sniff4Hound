"""Minimal, stdlib-only IPC used between the unprivileged web process and the
privileged capture process (raw sockets and low ports both live in the
capture process; see `capture_service.py`).

Transport is a Unix domain socket carrying length-prefixed JSON frames.
Two message shapes cross the wire after an initial token handshake:

- request/response: the web process calls a method exposed by the capture
  process's `RuntimeController` (start/stop/set_mode/...) and blocks for the
  matching response, correlated by an id.
- event: fire-and-forget payloads the capture process pushes unprompted -
  the exact dicts `Sniffer`/`HoneypotEngine` already build for `hub.broadcast`
  (packet/stats_update/runtime_mode), forwarded verbatim to the web process's
  real `WebSocketHub` so the frontend sees no difference.

No third-party dependencies, consistent with project policy.
"""

from __future__ import annotations

import json
import os
import secrets
import socket
import struct
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable

_LEN_STRUCT = struct.Struct("!I")
MAX_FRAME_BYTES = 16 * 1024 * 1024


class IpcError(RuntimeError):
    pass


class IpcAuthError(IpcError):
    pass


class IpcDisconnected(IpcError):
    pass


def generate_ipc_token() -> str:
    return secrets.token_hex(32)


def _tokens_match(candidate: Any, expected: str) -> bool:
    if not isinstance(candidate, str) or not expected:
        return False
    return secrets.compare_digest(candidate, expected)


def _send_frame(sock: socket.socket, payload: dict, lock: threading.Lock) -> None:
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    if len(data) > MAX_FRAME_BYTES:
        raise IpcError("IPC frame too large")
    with lock:
        sock.sendall(_LEN_STRUCT.pack(len(data)))
        sock.sendall(data)


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise IpcDisconnected("IPC connection closed")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _recv_frame(sock: socket.socket) -> dict:
    header = _recv_exact(sock, _LEN_STRUCT.size)
    (length,) = _LEN_STRUCT.unpack(header)
    if length > MAX_FRAME_BYTES:
        raise IpcError("IPC frame too large")
    data = _recv_exact(sock, length)
    return json.loads(data.decode("utf-8"))


def _close_socket(sock: socket.socket | None) -> None:
    """Tear a connection down so the *peer* and any blocked reader notice.

    `close()` alone is not enough: on Linux a thread already blocked in
    `recv()` on that fd keeps the underlying socket alive, so closing the fd
    neither wakes that thread nor sends a FIN. The other end then sees a
    connection that is still open but will never answer - which is how
    stopping the capture service used to leave the web process holding a
    zombie link, every runtime call hanging for the full call timeout before
    failing instead of reconnecting. `shutdown()` is what actually signals
    both sides; it raises if the socket is already disconnected, which is
    fine and ignorable.
    """
    if sock is None:
        return
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


def prepare_socket_path(path: str) -> Path:
    socket_path = Path(path).expanduser()
    socket_path.parent.mkdir(parents=True, exist_ok=True, mode=0o711)
    try:
        os.chmod(socket_path.parent, 0o711)
    except OSError:
        pass
    if socket_path.exists() or socket_path.is_symlink():
        socket_path.unlink()
    return socket_path


class IpcServer:
    """Runs in the privileged capture process. Accepts one active client
    connection at a time (the web process), authenticates it with a shared
    token, and dispatches requests to `self.methods`."""

    # Requests are handed to this many worker threads instead of being run
    # inline on the connection's read loop. Inline execution made every
    # runtime call head-of-line blocked behind the slowest one: stopping the
    # honeypot joins a thread per listener (290 enabled by default), and for
    # as long as that ran the reader never even *read* the next frame - so
    # toggling one engine reliably timed out the other engine's toggle, and
    # both surfaced as "Internal Server Error". Engine mutations are still
    # serialised, just by `RuntimeController`'s own lock rather than by
    # starving the transport; cheap reads (snapshot) answer meanwhile.
    MAX_DISPATCH_WORKERS = 8

    # Ceiling on how long an accepted connection may take to present its
    # token before its session thread gives up.
    HANDSHAKE_TIMEOUT_SECONDS = 10.0

    def __init__(self, socket_path: str, token: str, *, methods: dict[str, Callable[..., Any]] | None = None):
        self.methods: dict[str, Callable[..., Any]] = dict(methods or {})
        self._token = token
        self._socket_path = prepare_socket_path(socket_path)
        self._server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server_sock.bind(str(self._socket_path))
        os.chmod(self._socket_path, 0o600)
        # Room for a reconnect to queue while a stale session is still being
        # torn down; a backlog of 1 could refuse the very connection that is
        # meant to replace the dead one.
        self._server_sock.listen(8)
        self._client_sock: socket.socket | None = None
        self._write_lock = threading.Lock()
        self._client_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._dispatch_pool = ThreadPoolExecutor(
            max_workers=self.MAX_DISPATCH_WORKERS,
            thread_name_prefix="sniff4hound-ipc-dispatch",
        )
        self._accept_thread = threading.Thread(target=self._accept_loop, name="sniff4hound-ipc-accept", daemon=True)

    @property
    def socket_path(self) -> Path:
        return self._socket_path

    def chown_socket(self, uid: int) -> None:
        os.chown(self._socket_path, uid, -1)

    def start(self) -> None:
        self._accept_thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        try:
            self._server_sock.close()
        except OSError:
            pass
        with self._client_lock:
            client = self._client_sock
            self._client_sock = None
        _close_socket(client)
        try:
            self._socket_path.unlink()
        except OSError:
            pass
        # Not waited on: a dispatch still running is an engine call holding
        # RuntimeController's lock, and capture_service's shutdown path stops
        # the engines right after this - blocking here would just add its
        # timeout to every shutdown.
        self._dispatch_pool.shutdown(wait=False)

    def has_client(self) -> bool:
        with self._client_lock:
            return self._client_sock is not None

    def _accept_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                conn, _addr = self._server_sock.accept()
            except OSError:
                return
            # Each connection is served on its own thread so the accept loop
            # is always ready for the next one. Serving inline meant a stale
            # connection whose peer had gone away without a clean close (its
            # reader blocked in recv() forever) also blocked *accepting*, so
            # the web process could never reconnect - the reconnect logic in
            # IpcClient would have been defeated by the server side.
            threading.Thread(
                target=self._serve_client,
                args=(conn,),
                name="sniff4hound-ipc-session",
                daemon=True,
            ).start()

    def _serve_client(self, conn: socket.socket) -> None:
        try:
            self._handle_client(conn)
        except IpcDisconnected:
            pass
        except Exception:
            pass
        finally:
            _close_socket(conn)

    def _handle_client(self, conn: socket.socket) -> None:
        # A peer that connects and then says nothing must not hold a session
        # thread open indefinitely. Only the handshake is bounded; the request
        # loop below is meant to block in recv() until there is work.
        conn.settimeout(self.HANDSHAKE_TIMEOUT_SECONDS)
        hello = _recv_frame(conn)
        conn.settimeout(None)
        if hello.get("kind") != "hello" or not _tokens_match(hello.get("token"), self._token):
            try:
                _send_frame(conn, {"kind": "hello_ack", "ok": False, "error": "unauthorized"}, self._write_lock)
            finally:
                conn.close()
            return
        _send_frame(conn, {"kind": "hello_ack", "ok": True}, self._write_lock)
        with self._client_lock:
            previous = self._client_sock
            self._client_sock = conn
        _close_socket(previous)
        try:
            while not self._stop_event.is_set():
                message = _recv_frame(conn)
                if message.get("kind") == "request":
                    try:
                        self._dispatch_pool.submit(self._dispatch, conn, message)
                    except RuntimeError:
                        # Pool already shut down (stop() raced this frame) -
                        # run it inline so the caller still gets an answer
                        # rather than blocking until its timeout.
                        self._dispatch(conn, message)
        finally:
            with self._client_lock:
                if self._client_sock is conn:
                    self._client_sock = None

    def _dispatch(self, conn: socket.socket, message: dict) -> None:
        request_id = message.get("id")
        method_name = str(message.get("method") or "")
        args = message.get("args") or {}
        try:
            handler = self.methods.get(method_name)
            if handler is None:
                raise IpcError(f"Unknown IPC method: {method_name}")
            result = handler(**args)
            _send_frame(conn, {"kind": "response", "id": request_id, "ok": True, "result": result}, self._write_lock)
        except Exception as exc:
            _send_frame(conn, {"kind": "response", "id": request_id, "ok": False, "error": str(exc)}, self._write_lock)

    def publish(self, payload: dict) -> None:
        with self._client_lock:
            conn = self._client_sock
        if conn is None:
            return
        try:
            _send_frame(conn, {"kind": "event", "payload": payload}, self._write_lock)
        except Exception:
            with self._client_lock:
                if self._client_sock is conn:
                    self._client_sock = None


class IpcEventSink:
    """Drop-in replacement for `WebSocketHub` handed to `Sniffer`/
    `HoneypotEngine` inside the capture process - they only ever call
    `.broadcast(dict)`, so no engine code needs to change."""

    def __init__(self, server: IpcServer):
        self._server = server

    def broadcast(self, payload: dict) -> None:
        self._server.publish(payload)


class _PendingCall:
    # `generation` records which connection this call was sent on, so a
    # retiring connection only fails the calls that were actually riding it.
    __slots__ = ("_event", "_message", "generation")

    def __init__(self, generation: int = -1) -> None:
        self._event = threading.Event()
        self._message: dict | None = None
        self.generation = generation

    def deliver(self, message: dict) -> None:
        self._message = message
        self._event.set()

    def fail(self, error: str) -> None:
        self._message = {"ok": False, "error": error}
        self._event.set()

    def wait(self, timeout: float) -> dict:
        if not self._event.wait(timeout):
            raise IpcError("IPC call timed out")
        assert self._message is not None
        return self._message


class IpcClient:
    """Runs in the unprivileged web process. Connects to the capture
    process's Unix socket, authenticates with the shared token, and lets
    callers issue blocking RPC calls while a background reader thread
    delivers unsolicited events to `on_event`.

    The link is re-established on demand. It used to be connected exactly
    once, at startup, and never again: the moment it dropped - the capture
    process restarted, or anything closed the socket - `connected` went false
    for good and *every* later runtime call raised, so the whole app answered
    "Internal Server Error" on any attempt to start or stop an engine until
    it was restarted. Reconnecting is what makes that recoverable.
    """

    # A reconnect happens inside an HTTP request, so it gets a much shorter
    # budget than the startup connect: better to fail that one request with a
    # clear "capture service unreachable" than to hold the operator's click
    # for the full startup window. The next call tries again.
    RECONNECT_TIMEOUT_SECONDS = 5.0

    # Per-attempt ceiling on connect + token exchange, as opposed to the
    # whole-loop budget in `connect_timeout`.
    HANDSHAKE_TIMEOUT_SECONDS = 5.0

    # How long a failed reconnect suppresses the next attempt. Without this,
    # every request that touches the capture service pays the full reconnect
    # budget while the service is down, and because those attempts serialise
    # on `_connect_lock` they queue up behind each other - enough concurrent
    # runtime calls would occupy all of `jobs.JobQueue`'s workers and make
    # unrelated routes crawl. Short enough that recovery still feels
    # immediate once the capture process is back.
    RECONNECT_COOLDOWN_SECONDS = 1.0

    def __init__(
        self,
        socket_path: str,
        token: str,
        *,
        on_event: Callable[[dict], None] | None = None,
        connect_timeout: float = 20.0,
        call_timeout: float = 10.0,
    ):
        self._socket_path = socket_path
        self._token = token
        self._on_event = on_event
        self._connect_timeout = connect_timeout
        self._call_timeout = call_timeout
        self._sock: socket.socket | None = None
        self._write_lock = threading.Lock()
        self._pending: dict[str, _PendingCall] = {}
        self._pending_lock = threading.Lock()
        self._reader_thread: threading.Thread | None = None
        self._connected = threading.Event()
        self._stop_event = threading.Event()
        # Serialises reconnect attempts so a burst of concurrent requests
        # arriving just after the link dropped produces one attempt, not one
        # per request. Never held while a call is in flight.
        self._connect_lock = threading.RLock()
        # An unauthorized handshake is not a transient fault: the token is
        # wrong and retrying only feeds the auth rate limiter. Latched so
        # reconnects give up immediately instead of hammering.
        self._auth_failed = False
        # When the last reconnect attempt failed, for RECONNECT_COOLDOWN_SECONDS.
        self._last_connect_failure_at = 0.0
        # Bumped on every successful connect. A reader thread that finally
        # notices its socket is dead must not fail calls belonging to the
        # connection that replaced it - without this, the first request after
        # a reconnect was killed by the *previous* connection's cleanup.
        self._generation = 0

    @property
    def connected(self) -> bool:
        return self._connected.is_set()

    def connect(self, *, timeout: float | None = None) -> None:
        with self._connect_lock:
            if self._connected.is_set():
                return
            if self._auth_failed:
                raise IpcAuthError("Capture service rejected the IPC token")
            budget = self._connect_timeout if timeout is None else timeout
            deadline = time.monotonic() + budget
            last_error: Exception | None = None
            while not self._stop_event.is_set():
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                try:
                    # Bounded handshake. `connect_timeout` only ever limited
                    # how long this *loop* retried; the handshake itself was a
                    # blocking recv with no deadline, so a capture process
                    # that accepted the connection and then never answered
                    # (wedged, or mid-shutdown) hung the caller forever -
                    # at startup, or inside whichever HTTP request happened to
                    # trigger the reconnect.
                    sock.settimeout(self.HANDSHAKE_TIMEOUT_SECONDS)
                    sock.connect(self._socket_path)
                    _send_frame(sock, {"kind": "hello", "token": self._token}, self._write_lock)
                    ack = _recv_frame(sock)
                    if not ack.get("ok"):
                        raise IpcAuthError(str(ack.get("error") or "unauthorized"))
                    # Back to blocking for the reader loop, which is supposed
                    # to sit in recv() indefinitely waiting for events.
                    sock.settimeout(None)
                    self._sock = sock
                    self._generation += 1
                    self._connected.set()
                    self._reader_thread = threading.Thread(
                        target=self._read_loop,
                        args=(sock, self._generation),
                        name="sniff4hound-ipc-reader",
                        daemon=True,
                    )
                    self._reader_thread.start()
                    self._last_connect_failure_at = 0.0
                    return
                except IpcAuthError:
                    sock.close()
                    self._auth_failed = True
                    raise
                except (FileNotFoundError, ConnectionRefusedError, OSError) as exc:
                    sock.close()
                    last_error = exc
                if time.monotonic() >= deadline:
                    break
                time.sleep(0.25)
            self._last_connect_failure_at = time.monotonic()
            raise IpcError(f"Could not connect to the capture service: {last_error}")

    def _ensure_connected(self) -> None:
        """Reconnect if the link is down. Raises when it cannot be restored."""
        if self._connected.is_set():
            return
        if self._stop_event.is_set():
            raise IpcDisconnected("IPC client closed")
        # Checked before taking `_connect_lock`, so callers that arrive during
        # the cooldown fail immediately instead of queueing behind whoever is
        # mid-attempt. Deliberately not applied to an explicit connect() -
        # startup should use its full budget.
        since_failure = time.monotonic() - self._last_connect_failure_at
        if self._last_connect_failure_at and since_failure < self.RECONNECT_COOLDOWN_SECONDS:
            raise IpcDisconnected(
                "Capture service unreachable (last reconnect attempt failed "
                f"{since_failure:.1f}s ago)"
            )
        self.connect(timeout=self.RECONNECT_TIMEOUT_SECONDS)

    def _read_loop(self, sock: socket.socket, generation: int) -> None:
        # The socket is passed in rather than read off self._sock: a reconnect
        # replaces that attribute, and a reader still looping on it would
        # start consuming the *new* connection's frames alongside the new
        # reader, so responses would be delivered to whichever won the race.
        try:
            while not self._stop_event.is_set():
                message = _recv_frame(sock)
                kind = message.get("kind")
                if kind == "response":
                    self._resolve(message)
                elif kind == "event" and self._on_event is not None:
                    try:
                        self._on_event(message.get("payload") or {})
                    except Exception:
                        pass
        except IpcDisconnected:
            pass
        except Exception:
            pass
        finally:
            self._drop_connection(sock, "IPC connection lost", generation=generation)

    def _drop_connection(
        self, sock: socket.socket | None, error: str, *, generation: int | None = None
    ) -> None:
        """Retire `sock` and fail the calls that were riding on it.

        `generation` scopes the fail-all to that one connection. A reader only
        learns its socket is dead when its blocked recv() finally returns,
        which can be *after* a reconnect has already installed a working link
        and a new call is in flight on it - failing everything indiscriminately
        made that first post-reconnect request error out for no reason.
        `None` means "every pending call", which is what close() wants.
        """
        with self._connect_lock:
            # Only tear down the shared state if this reader still owns the
            # live socket - a reconnect may already have installed a newer
            # one, and clearing `_connected` for it would leave the client
            # marked down while it is perfectly usable.
            if sock is None or self._sock is sock:
                self._sock = None
                self._connected.clear()
            self._fail_all_pending(error, generation=generation)
        _close_socket(sock)

    def _resolve(self, message: dict) -> None:
        request_id = message.get("id")
        with self._pending_lock:
            pending = self._pending.pop(request_id, None)
        if pending is not None:
            pending.deliver(message)

    def _fail_all_pending(self, error: str, *, generation: int | None = None) -> None:
        with self._pending_lock:
            if generation is None:
                pending_items = list(self._pending.values())
                self._pending.clear()
            else:
                doomed = [key for key, call in self._pending.items() if call.generation == generation]
                pending_items = [self._pending.pop(key) for key in doomed]
        for pending in pending_items:
            pending.fail(error)

    def call(self, method: str, **kwargs: Any) -> Any:
        """Issue one RPC, reconnecting first if the link is down.

        A send that fails is retried once on a fresh connection, because a
        frame that never left this process cannot have been acted on. A call
        that *was* sent and then lost the link is never retried - the capture
        process may well have run it, and re-running `create_listener` or
        `stop` on a maybe-applied request is worse than reporting the error.
        """
        pending = _PendingCall()
        for attempt in (1, 2):
            self._ensure_connected()
            request_id = uuid.uuid4().hex
            with self._connect_lock:
                sock = self._sock
                if sock is None or not self._connected.is_set():
                    continue  # dropped again between the two; _ensure_connected retries
                pending.generation = self._generation
                with self._pending_lock:
                    self._pending[request_id] = pending
            frame = {"kind": "request", "id": request_id, "method": method, "args": kwargs}
            try:
                _send_frame(sock, frame, self._write_lock)
                break
            except Exception as exc:
                with self._pending_lock:
                    self._pending.pop(request_id, None)
                self._drop_connection(sock, "IPC connection lost", generation=pending.generation)
                if attempt == 2:
                    raise IpcDisconnected(str(exc)) from exc
        else:
            raise IpcDisconnected("Not connected to the capture service")
        message = pending.wait(self._call_timeout)
        if not message.get("ok"):
            raise IpcError(str(message.get("error") or "IPC call failed"))
        return message.get("result")

    def close(self) -> None:
        self._stop_event.set()
        self._drop_connection(self._sock, "IPC client closed")
