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

    def __init__(self, socket_path: str, token: str, *, methods: dict[str, Callable[..., Any]] | None = None):
        self.methods: dict[str, Callable[..., Any]] = dict(methods or {})
        self._token = token
        self._socket_path = prepare_socket_path(socket_path)
        self._server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server_sock.bind(str(self._socket_path))
        os.chmod(self._socket_path, 0o600)
        self._server_sock.listen(1)
        self._client_sock: socket.socket | None = None
        self._write_lock = threading.Lock()
        self._client_lock = threading.Lock()
        self._stop_event = threading.Event()
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
        if client is not None:
            try:
                client.close()
            except OSError:
                pass
        try:
            self._socket_path.unlink()
        except OSError:
            pass

    def has_client(self) -> bool:
        with self._client_lock:
            return self._client_sock is not None

    def _accept_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                conn, _addr = self._server_sock.accept()
            except OSError:
                return
            try:
                self._handle_client(conn)
            except IpcDisconnected:
                pass
            except Exception:
                pass

    def _handle_client(self, conn: socket.socket) -> None:
        hello = _recv_frame(conn)
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
        if previous is not None:
            try:
                previous.close()
            except OSError:
                pass
        try:
            while not self._stop_event.is_set():
                message = _recv_frame(conn)
                if message.get("kind") == "request":
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
    __slots__ = ("_event", "_message")

    def __init__(self) -> None:
        self._event = threading.Event()
        self._message: dict | None = None

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
    delivers unsolicited events to `on_event`."""

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

    @property
    def connected(self) -> bool:
        return self._connected.is_set()

    def connect(self) -> None:
        deadline = time.monotonic() + self._connect_timeout
        last_error: Exception | None = None
        while time.monotonic() < deadline and not self._stop_event.is_set():
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                sock.connect(self._socket_path)
                _send_frame(sock, {"kind": "hello", "token": self._token}, self._write_lock)
                ack = _recv_frame(sock)
                if not ack.get("ok"):
                    raise IpcAuthError(str(ack.get("error") or "unauthorized"))
                self._sock = sock
                self._connected.set()
                self._reader_thread = threading.Thread(
                    target=self._read_loop, name="sniff4hound-ipc-reader", daemon=True
                )
                self._reader_thread.start()
                return
            except IpcAuthError:
                sock.close()
                raise
            except (FileNotFoundError, ConnectionRefusedError, OSError) as exc:
                sock.close()
                last_error = exc
                time.sleep(0.25)
        raise IpcError(f"Could not connect to the capture service: {last_error}")

    def _read_loop(self) -> None:
        sock = self._sock
        assert sock is not None
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
            self._connected.clear()
            self._fail_all_pending("IPC connection lost")

    def _resolve(self, message: dict) -> None:
        request_id = message.get("id")
        with self._pending_lock:
            pending = self._pending.pop(request_id, None)
        if pending is not None:
            pending.deliver(message)

    def _fail_all_pending(self, error: str) -> None:
        with self._pending_lock:
            pending_items = list(self._pending.values())
            self._pending.clear()
        for pending in pending_items:
            pending.fail(error)

    def call(self, method: str, **kwargs: Any) -> Any:
        if not self._connected.is_set() or self._sock is None:
            raise IpcDisconnected("Not connected to the capture service")
        request_id = uuid.uuid4().hex
        pending = _PendingCall()
        with self._pending_lock:
            self._pending[request_id] = pending
        try:
            _send_frame(self._sock, {"kind": "request", "id": request_id, "method": method, "args": kwargs}, self._write_lock)
        except Exception as exc:
            with self._pending_lock:
                self._pending.pop(request_id, None)
            raise IpcDisconnected(str(exc)) from exc
        message = pending.wait(self._call_timeout)
        if not message.get("ok"):
            raise IpcError(str(message.get("error") or "IPC call failed"))
        return message.get("result")

    def close(self) -> None:
        self._stop_event.set()
        sock = self._sock
        self._sock = None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        self._connected.clear()
        self._fail_all_pending("IPC client closed")
