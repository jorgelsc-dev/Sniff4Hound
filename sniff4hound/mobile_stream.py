from __future__ import annotations

import fcntl
import html
import json
import queue
import secrets
import socket
import ssl
import struct
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from .tls import ensure_mobile_tls, public_mobile_ca_pem
from .utils import safe_int, utc_now


MOBILE_STREAM_DEFAULT_PORT = 45679
# Two separate clocks, because approval sits between them. A fresh QR waits
# this long for a device to actually scan it and for the operator to accept
# that device...
PAIRING_APPROVAL_TTL_SECONDS = 300
# ...and only once accepted does the 60s code window start. Pairing a phone
# is a deliberate, supervised act; the short clock belongs on the secret, not
# on how fast the operator can walk to the desk.
PAIRING_TTL_SECONDS = 60
STREAM_QUEUE_SIZE = 200
STREAM_KEEPALIVE_SECONDS = 25
MAX_STREAM_EVENT_SECONDS = 24 * 60 * 60
_SIOCGIFADDR = 0x8915


@dataclass(frozen=True)
class InterfaceAddress:
    name: str
    address: str
    label: str
    loopback: bool = False


@dataclass
class Pairing:
    id: str
    interface: str
    address: str
    port: int
    created_at: float
    expires_at: float
    code: str = ""
    seen_at: float = 0.0
    approved_at: float = 0.0
    consumed_at: float = 0.0
    failed_at: float = 0.0
    client: str = ""
    # Captured when the device first knocks, so the operator can judge *this*
    # device before any code exists. Wall clock alongside the monotonic
    # seen_at because this one is shown to a human.
    user_agent: str = ""
    seen_at_utc: str = ""


@dataclass
class MobileSession:
    token: str
    interface: str
    address: str
    client: str
    user_agent: str
    created_at: float
    last_seen: float
    revoked_at: float = 0.0
    label: str = "Mobile viewer"
    event_count: int = 0


@dataclass
class MobileServerState:
    interface: str = ""
    address: str = ""
    port: int = MOBILE_STREAM_DEFAULT_PORT
    running: bool = False
    url_base: str = ""
    ca_pem: str = ""
    http3: dict[str, Any] = field(default_factory=dict)


def discover_interfaces() -> list[InterfaceAddress]:
    rows: list[InterfaceAddress] = []
    try:
        names = [name for _, name in socket.if_nameindex()]
    except OSError:
        return rows
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        for name in names:
            try:
                packed = fcntl.ioctl(
                    probe.fileno(),
                    _SIOCGIFADDR,
                    struct.pack("256s", name[:15].encode("utf-8")),
                )
                address = socket.inet_ntoa(packed[20:24])
            except OSError:
                continue
            loopback = address.startswith("127.")
            rows.append(
                InterfaceAddress(
                    name=name,
                    address=address,
                    label=f"{name} - {address}",
                    loopback=loopback,
                )
            )
    rows.sort(key=lambda item: (item.loopback, item.name, item.address))
    return rows


def _now() -> float:
    return time.monotonic()


def _public_event(payload: dict[str, Any]) -> dict[str, Any] | None:
    event_type = str(payload.get("type") or "").strip()
    generated_at = str(payload.get("generated_at") or utc_now())
    if event_type == "packet":
        packet = payload.get("packet") if isinstance(payload.get("packet"), dict) else {}
        tags = packet.get("tags") if isinstance(packet.get("tags"), list) else []
        public_tags = []
        for tag in tags[:8]:
            if not isinstance(tag, dict):
                continue
            # Deliberately no `value`. A tag's value is whatever
            # monitors.describe_match() extracted as the reason the packet
            # matched, and for any monitor with a payload_regex that is
            # `found.group(0)` - a literal slice of the decoded payload. So
            # forwarding it puts captured cleartext (a password in a form
            # post, a session cookie, a token) on the LAN, which is the one
            # thing this stream is specified never to carry. The rule that
            # fired and how bad it is: that is the alert. The matched bytes
            # stay on the desktop.
            public_tags.append({
                "key": str(tag.get("key") or "")[:80],
                "severity": str(tag.get("severity") or "")[:40],
            })
        return {
            "type": "packet",
            "generated_at": generated_at,
            "source": "honeypot" if str(packet.get("interface") or "").startswith("honeypot:") else "sniffer",
            "src_ip": str(packet.get("src_ip") or ""),
            "dst_ip": str(packet.get("dst_ip") or ""),
            "src_port": safe_int(packet.get("src_port"), 0),
            "dst_port": safe_int(packet.get("dst_port"), 0),
            "proto": str(packet.get("proto") or "").lower(),
            "length": safe_int(packet.get("length") or packet.get("payload_len"), 0),
            "summary": str(packet.get("summary") or "")[:180],
            "tags": public_tags,
            "persisted": bool(payload.get("persisted", True)),
        }
    if event_type == "stats_update":
        stats = payload.get("stats") if isinstance(payload.get("stats"), dict) else {}
        return {
            "type": "stats_update",
            "generated_at": generated_at,
            "stats": {
                "packets_seen": safe_int(stats.get("packets_seen"), 0),
                "packets_stored": safe_int(stats.get("packets_stored"), 0),
                "packets_total_bytes": safe_int(stats.get("packets_total_bytes"), 0),
                "mode": str(stats.get("mode") or ""),
            },
        }
    if event_type == "runtime_mode":
        runtime = payload.get("runtime") if isinstance(payload.get("runtime"), dict) else {}
        return {
            "type": "runtime_mode",
            "generated_at": generated_at,
            "running_engines": list(runtime.get("running_engines") or [])[:4],
            "mode": str(runtime.get("mode") or ""),
        }
    if event_type in {"data_clear_progress", "job_update"}:
        return {
            "type": event_type,
            "generated_at": generated_at,
            "status": str(payload.get("status") or ""),
            "message": str(payload.get("message") or "")[:180],
        }
    return None


def _sse_frame(event: str, data: dict[str, Any]) -> bytes:
    body = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    return f"event: {event}\ndata: {body}\n\n".encode("utf-8")


class MobileStreamService:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._pairings: dict[str, Pairing] = {}
        self._sessions: dict[str, MobileSession] = {}
        self._subscribers: dict[int, tuple[str, queue.Queue[dict[str, Any]]]] = {}
        self._server: ThreadingHTTPServer | None = None
        self._server_thread: threading.Thread | None = None
        self._state = MobileServerState()

    def interfaces(self) -> list[dict[str, Any]]:
        return [item.__dict__ for item in discover_interfaces()]

    def status(self) -> dict[str, Any]:
        with self._lock:
            self._prune_locked()
            return {
                **self._state.__dict__,
                "pairings": [self._pairing_view(item) for item in self._pairings.values()],
                "sessions": [self._session_view(item) for item in self._sessions.values()],
            }

    def start(self, interface: str, *, port: int = MOBILE_STREAM_DEFAULT_PORT) -> dict[str, Any]:
        interface = str(interface or "").strip()
        if not interface:
            raise ValueError("interface is required")
        selected = next((item for item in discover_interfaces() if item.name == interface), None)
        if selected is None:
            raise ValueError(f"interface {interface!r} is not available")
        if selected.loopback:
            raise ValueError("loopback interfaces cannot be used for mobile streaming")
        port = max(1, min(65535, safe_int(port, MOBILE_STREAM_DEFAULT_PORT)))
        with self._lock:
            same_listener = self._state.running and self._state.interface == selected.name and self._state.port == port
        if same_listener:
            return self.status()
        self.stop()
        tls_material = ensure_mobile_tls(selected.address)
        server = _MobileHTTPServer((selected.address, port), _MobileStreamHandler, self)
        server.socket = tls_material.ssl_context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(
            target=server.serve_forever,
            name="sniff4hound-mobile-stream",
            daemon=True,
        )
        with self._lock:
            self._server = server
            self._server_thread = thread
            self._state = MobileServerState(
                interface=selected.name,
                address=selected.address,
                port=port,
                running=True,
                url_base=f"https://{selected.address}:{port}",
                ca_pem=public_mobile_ca_pem(),
                http3={
                    "enabled": False,
                    "transport": "https+sse",
                    "reason": "The embedded Python listener serves the mobile stream over TLS and SSE; no QUIC transport is bundled.",
                },
            )
        thread.start()
        return self.status()

    def stop(self) -> dict[str, Any]:
        with self._lock:
            server = self._server
            self._server = None
            self._server_thread = None
            self._state = MobileServerState()
            self._pairings.clear()
            for session in self._sessions.values():
                session.revoked_at = _now()
            self._notify_all({"type": "revoked", "generated_at": utc_now()})
        if server is not None:
            server.shutdown()
            server.server_close()
        return self.status()

    def create_pairing(self, interface: str, *, port: int = MOBILE_STREAM_DEFAULT_PORT) -> dict[str, Any]:
        state = self.start(interface, port=port)
        with self._lock:
            pairing_id = secrets.token_urlsafe(18)
            now = _now()
            pairing = Pairing(
                id=pairing_id,
                interface=self._state.interface,
                address=self._state.address,
                port=self._state.port,
                created_at=now,
                expires_at=now + PAIRING_APPROVAL_TTL_SECONDS,
            )
            self._pairings[pairing_id] = pairing
            view = self._pairing_view(pairing)
            view["url"] = f"{self._state.url_base}/mobile/pair/{pairing_id}"
            view["server"] = state
            return view

    def pairing(self, pairing_id: str) -> dict[str, Any] | None:
        with self._lock:
            self._prune_locked()
            pairing = self._pairings.get(str(pairing_id or ""))
            if not pairing:
                return None
            view = self._pairing_view(pairing)
            view["url"] = f"{self._state.url_base}/mobile/pair/{pairing.id}"
            return view

    def open_pairing(self, pairing_id: str, *, client: str, user_agent: str = "") -> Pairing | None:
        """Record that a device knocked. Deliberately issues no code.

        The device is not trusted yet, and nothing is served to it: this only
        captures who is asking (IP, User-Agent, time) so the operator has
        something to judge. The secret comes into existence in
        approve_pairing(), after a human says yes - which is what makes this
        stronger than a QR that carries a fixed secret anyone who photographs
        the screen can replay.
        """
        with self._lock:
            self._prune_locked()
            pairing = self._pairings.get(str(pairing_id or ""))
            if not pairing or pairing.consumed_at or pairing.failed_at:
                return None
            now = _now()
            if pairing.expires_at <= now:
                self._pairings.pop(pairing.id, None)
                return None
            # The phone re-polls this page while it waits to be accepted, so
            # only the first knock defines the device being judged - a later
            # refresh must not silently re-describe it, least of all after
            # the operator already approved what they were shown.
            if not pairing.approved_at and not pairing.seen_at:
                pairing.seen_at = now
                pairing.seen_at_utc = utc_now()
                pairing.client = str(client or "")
                pairing.user_agent = str(user_agent or "")[:180]
            return pairing

    def approve_pairing(self, pairing_id: str) -> dict[str, Any] | None:
        """Operator accepts the device; only now does a code exist.

        Starts the short code window (PAIRING_TTL_SECONDS) from this moment,
        not from when the QR was drawn, so the 60s is the phone's time to type
        the code rather than a race the operator is also running in.
        """
        with self._lock:
            self._prune_locked()
            pairing = self._pairings.get(str(pairing_id or ""))
            if not pairing or pairing.consumed_at or pairing.failed_at:
                return None
            now = _now()
            if pairing.expires_at <= now:
                self._pairings.pop(pairing.id, None)
                return None
            if not pairing.seen_at:
                # Nothing has scanned it yet, so there is no device to
                # approve. Approving in advance would put a live code on
                # screen waiting for whoever reaches the URL first.
                return None
            if not pairing.approved_at:
                pairing.approved_at = now
                pairing.code = f"{secrets.randbelow(1_000_000):06d}"
                pairing.expires_at = now + PAIRING_TTL_SECONDS
            view = self._pairing_view(pairing)
            view["url"] = f"{self._state.url_base}/mobile/pair/{pairing.id}"
            return view

    def verify_pairing(self, pairing_id: str, code: str, *, client: str, user_agent: str) -> str | None:
        with self._lock:
            pairing = self._pairings.get(str(pairing_id or ""))
            now = _now()
            if not pairing or pairing.expires_at <= now or pairing.consumed_at or pairing.failed_at:
                return None
            if not pairing.approved_at or not pairing.code:
                # No approval, no code to be right about. Guessing cannot be
                # what grants access.
                return None
            if pairing.client and str(client or "") != pairing.client:
                # The approval was for a specific device. Without this, the
                # operator vouches for the phone they were shown while the
                # code stays usable by anyone else holding the link - which
                # would make the whole approval step decorative.
                pairing.failed_at = now
                return None
            if str(code or "").strip() != pairing.code:
                pairing.failed_at = now
                return None
            pairing.consumed_at = now
            token = secrets.token_urlsafe(32)
            self._sessions[token] = MobileSession(
                token=token,
                interface=pairing.interface,
                address=pairing.address,
                client=str(client or ""),
                user_agent=str(user_agent or "")[:180],
                created_at=now,
                last_seen=now,
            )
            self._pairings.pop(pairing.id, None)
            return token

    def revoke_session(self, token: str) -> bool:
        with self._lock:
            session = self._sessions.get(str(token or ""))
            if not session:
                return False
            session.revoked_at = _now()
            # Targeted: revoking one device must not knock the others off.
            # The phone closes its EventSource on this event and does not
            # reconnect, so broadcasting it took every paired device dark.
            self._notify_all({"type": "revoked", "generated_at": utc_now()}, token=session.token)
            return True

    def session(self, token: str) -> MobileSession | None:
        with self._lock:
            session = self._sessions.get(str(token or ""))
            if not session or session.revoked_at:
                return None
            session.last_seen = _now()
            return session

    def record_event(self, payload: dict[str, Any]) -> None:
        event = _public_event(payload)
        if event is None:
            return
        with self._lock:
            self._notify_all(event)

    def event_stream(self, token: str):
        q: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=STREAM_QUEUE_SIZE)
        subscriber_id = id(q)
        with self._lock:
            session = self.session(token)
            if session is None:
                yield _sse_frame("revoked", {"type": "revoked", "generated_at": utc_now()})
                return
            self._subscribers[subscriber_id] = (token, q)
        started = _now()
        try:
            yield _sse_frame("hello", {"type": "hello", "generated_at": utc_now()})
            while _now() - started < MAX_STREAM_EVENT_SECONDS:
                if self.session(token) is None:
                    yield _sse_frame("revoked", {"type": "revoked", "generated_at": utc_now()})
                    return
                try:
                    event = q.get(timeout=STREAM_KEEPALIVE_SECONDS)
                except queue.Empty:
                    yield b": keepalive\n\n"
                    continue
                yield _sse_frame(str(event.get("type") or "event"), event)
        finally:
            with self._lock:
                self._subscribers.pop(subscriber_id, None)

    def _notify_all(self, event: dict[str, Any], *, token: str | None = None) -> None:
        """Fan an event out to subscribers, or to exactly one when `token` is
        given - the revoke case, where the target is the *only* device that
        should hear about it."""
        dead = []
        for subscriber_id, (subscriber_token, q) in self._subscribers.items():
            if token is not None and subscriber_token != token:
                continue
            session = self._sessions.get(subscriber_token)
            # A revoked session still gets its own targeted event: that frame
            # is how its phone learns it was cut off. Without this exception
            # the revoked device is the one subscriber that never hears.
            if not session or (session.revoked_at and token is None):
                dead.append(subscriber_id)
                continue
            try:
                q.put_nowait(event)
                session.event_count += 1
            except queue.Full:
                try:
                    q.get_nowait()
                    q.put_nowait(event)
                    session.event_count += 1
                except queue.Empty:
                    pass
        for subscriber_id in dead:
            self._subscribers.pop(subscriber_id, None)

    def _prune_locked(self) -> None:
        now = _now()
        expired = [key for key, item in self._pairings.items() if item.expires_at <= now or item.failed_at]
        for key in expired:
            self._pairings.pop(key, None)

    def _pairing_view(self, pairing: Pairing) -> dict[str, Any]:
        now = _now()
        status = "pending"
        if pairing.seen_at and not pairing.approved_at:
            # A device is waiting on the operator. This is the state the
            # desktop has to surface with the who/where/when of the attempt.
            status = "awaiting_approval"
        if pairing.approved_at:
            status = "waiting_code"
        if pairing.consumed_at:
            status = "paired"
        if pairing.failed_at:
            status = "closed"
        if pairing.expires_at <= now:
            status = "expired"
        return {
            "id": pairing.id,
            "interface": pairing.interface,
            "address": pairing.address,
            "port": pairing.port,
            "status": status,
            # Empty until approval - there is no code to leak before then.
            "code": pairing.code,
            "seen": bool(pairing.seen_at),
            "approved": bool(pairing.approved_at),
            "client": pairing.client,
            "user_agent": pairing.user_agent,
            "seen_at": pairing.seen_at_utc,
            "expires_in": max(0, int(pairing.expires_at - now)),
        }

    def _session_view(self, session: MobileSession) -> dict[str, Any]:
        return {
            "token": session.token,
            "token_hint": session.token[:8],
            "interface": session.interface,
            "address": session.address,
            "client": session.client,
            "user_agent": session.user_agent,
            "created_at": session.created_at,
            "last_seen": session.last_seen,
            "revoked": bool(session.revoked_at),
            "event_count": session.event_count,
        }


class _MobileHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, server_address, RequestHandlerClass, service: MobileStreamService):
        self.service = service
        super().__init__(server_address, RequestHandlerClass)


class _MobileStreamHandler(BaseHTTPRequestHandler):
    server: _MobileHTTPServer

    def log_message(self, _format, *args):  # pragma: no cover - keep terminal clean
        return

    def _client(self) -> str:
        return str(self.client_address[0] if self.client_address else "")

    def _send(self, status: int, body: bytes, content_type: str = "text/html; charset=utf-8", headers=None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        for key, value in (headers or {}).items():
            self.send_header(str(key), str(value))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        if path == "/mobile/ca.pem":
            self._send(200, public_mobile_ca_pem().encode("utf-8"), "application/x-pem-file")
            return
        if path.startswith("/mobile/pair/"):
            pairing_id = path.rsplit("/", 1)[-1]
            pairing = self.server.service.open_pairing(
                pairing_id,
                client=self._client(),
                user_agent=self.headers.get("User-Agent", ""),
            )
            if not pairing:
                self._send(410, _closed_page().encode("utf-8"))
                return
            if not pairing.approved_at:
                # Nothing is served to an unapproved device but a holding
                # page that refreshes itself until the operator accepts it.
                self._send(200, _awaiting_approval_page().encode("utf-8"))
                return
            self._send(200, _pairing_page(pairing).encode("utf-8"))
            return
        if path.startswith("/mobile/session/"):
            token = path.rsplit("/", 1)[-1]
            if self.server.service.session(token) is None:
                self._send(403, _closed_page("Session revoked or expired.").encode("utf-8"))
                return
            self._send(200, _session_page(token).encode("utf-8"))
            return
        if path == "/mobile/events":
            token = (parse_qs(parsed.query).get("session") or [""])[0]
            if self.server.service.session(token) is None:
                self._send(403, b"forbidden", "text/plain; charset=utf-8")
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            try:
                for chunk in self.server.service.event_stream(token):
                    self.wfile.write(chunk)
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                return
            return
        self._send(404, _closed_page("Not found.").encode("utf-8"))

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        if path.startswith("/mobile/pair/") and path.endswith("/verify"):
            parts = path.split("/")
            pairing_id = parts[-2] if len(parts) >= 4 else ""
            length = min(4096, safe_int(self.headers.get("Content-Length"), 0))
            body = self.rfile.read(length).decode("utf-8", errors="replace")
            code = (parse_qs(body).get("code") or [""])[0]
            token = self.server.service.verify_pairing(
                pairing_id,
                code,
                client=self._client(),
                user_agent=self.headers.get("User-Agent", ""),
            )
            if not token:
                self._send(403, _closed_page("Incorrect code. This link is now closed.").encode("utf-8"))
                return
            self.send_response(303)
            self.send_header("Location", f"/mobile/session/{token}")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            return
        self._send(404, _closed_page("Not found.").encode("utf-8"))


def _shell(title: str, body: str) -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<style>
:root {{ color-scheme: dark; font-family: Inter, system-ui, sans-serif; background: #071014; color: #edf7f5; }}
body {{ margin: 0; min-height: 100vh; background: linear-gradient(140deg, #071014, #102226 58%, #182b24); }}
main {{ width: min(920px, calc(100vw - 32px)); margin: 0 auto; padding: 32px 0; }}
.panel {{ border: 1px solid rgba(255,255,255,.14); background: rgba(8,16,20,.84); border-radius: 18px; padding: 22px; box-shadow: 0 20px 70px rgba(0,0,0,.28); }}
h1 {{ font-size: clamp(28px, 8vw, 46px); margin: 0 0 10px; letter-spacing: 0; }}
p {{ color: #b9cbc8; line-height: 1.55; }}
input {{ width: 100%; box-sizing: border-box; border: 1px solid rgba(255,255,255,.18); background: #0f1b20; color: #fff; border-radius: 12px; padding: 16px; font-size: 24px; text-align: center; letter-spacing: 8px; }}
button {{ width: 100%; margin-top: 14px; border: 0; border-radius: 12px; padding: 14px 18px; background: #34d399; color: #05100c; font-weight: 800; font-size: 16px; }}
.events {{ display: grid; gap: 10px; margin-top: 18px; }}
.event {{ border: 1px solid rgba(255,255,255,.12); border-radius: 14px; padding: 12px; background: rgba(255,255,255,.05); }}
.meta {{ color: #8fb2ad; font-size: 12px; }}
.tag {{ display: inline-block; margin: 8px 6px 0 0; padding: 3px 8px; border-radius: 999px; background: rgba(52,211,153,.14); color: #9ff0c9; font-size: 12px; }}
</style>
</head>
<body><main><section class="panel">{body}</section></main></body>
</html>"""


def _pairing_page(pairing: Pairing) -> str:
    return _shell(
        "Sniff4Hound Pairing",
        f"""
<h1>Enter pairing code</h1>
<p>This device was approved. Type the 6-digit code now shown in Sniff4Hound Settings. This link closes after one wrong attempt or when the timer expires.</p>
<form method="post" action="/mobile/pair/{html.escape(pairing.id)}/verify">
  <input name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" pattern="[0-9]{{6}}" autofocus>
  <button type="submit">Unlock live stream</button>
</form>
<p class="meta">Interface {html.escape(pairing.interface)} · {html.escape(pairing.address)} · expires in {max(0, int(pairing.expires_at - _now()))}s</p>
""",
    )


def _session_page(token: str) -> str:
    token_json = json.dumps(token)
    return _shell(
        "Sniff4Hound Mobile Stream",
        f"""
<h1>Live stream</h1>
<p>Read-only alerts and traffic events. Payloads and control actions are not exposed to this device.</p>
<div id="status" class="meta">Connecting...</div>
<div id="events" class="events"></div>
<script>
const events = document.getElementById("events");
const status = document.getElementById("status");
function addEvent(data) {{
  const row = document.createElement("div");
  row.className = "event";
  const title = data.type === "packet"
    ? `${{data.proto || "?"}} ${{data.src_ip || "?"}}:${{data.src_port || ""}} -> ${{data.dst_ip || "?"}}:${{data.dst_port || ""}}`
    : data.type;
  const heading = document.createElement("strong");
  heading.textContent = title;
  const meta = document.createElement("div");
  meta.className = "meta";
  meta.textContent = data.generated_at || "";
  const summary = document.createElement("div");
  summary.textContent = data.summary || data.message || "";
  row.appendChild(heading);
  row.appendChild(meta);
  row.appendChild(summary);
  (data.tags || []).forEach(tag => {{
    const span = document.createElement("span");
    span.className = "tag";
    span.textContent = [tag.severity, tag.key].filter(Boolean).join(" ");
    row.appendChild(span);
  }});
  events.prepend(row);
  while (events.children.length > 80) events.removeChild(events.lastChild);
}}
const token = {token_json};
const source = new EventSource(`/mobile/events?session=${{encodeURIComponent(token)}}`);
source.addEventListener("hello", () => {{ status.textContent = "Connected"; }});
source.addEventListener("packet", (event) => addEvent(JSON.parse(event.data)));
source.addEventListener("stats_update", (event) => addEvent(JSON.parse(event.data)));
source.addEventListener("runtime_mode", (event) => addEvent(JSON.parse(event.data)));
source.addEventListener("revoked", () => {{ status.textContent = "Session revoked"; source.close(); }});
source.onerror = () => {{ status.textContent = "Reconnecting..."; }};
</script>
""",
    )


def _awaiting_approval_page() -> str:
    # Plain meta-refresh rather than JS: this page exists before the device is
    # trusted with anything, so it should do as little as possible.
    return _shell(
        "Sniff4Hound Pairing",
        """
<meta http-equiv="refresh" content="3">
<h1>Waiting for approval</h1>
<p>This device has asked to connect. Approve it in Sniff4Hound Settings on the
desktop - the access attempt is shown there with this device's address and
browser. A 6-digit code appears here once it is accepted.</p>
<p class="meta">This page refreshes itself.</p>
""",
    )


def _closed_page(message: str = "This mobile link is closed.") -> str:
    return _shell("Sniff4Hound Mobile Stream", f"<h1>Closed</h1><p>{html.escape(message)}</p>")
