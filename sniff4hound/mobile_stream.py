from __future__ import annotations

import fcntl
import html
import json
import queue
import re
import secrets
import socket
import struct
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qs, urlencode

from wsbuilder import App, Request, Response
from wsbuilder.server import HTTPServer

from . import http3_listener, log_setup, mdns
from .tls import ca_fingerprint_sha256, ensure_mobile_tls, public_mobile_ca_pem
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

# Log lines reach the phone only if the device asks for them (`level=` on the
# event stream) and only as the fields below. The levels are the ones the log
# settings offer; a CRITICAL record is kept and ranks above ERROR.
LOG_FEED_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")
_LOG_RANK = {"DEBUG": 10, "INFO": 20, "WARNING": 30, "ERROR": 40, "CRITICAL": 50}
LOG_SOURCES = ("web", "capture")
LOG_BACKLOG = 40            # lines a phone gets when it connects
LOG_RING_SIZE = 1500        # recent lines kept, across every level, to build that backlog
LOG_MESSAGE_LIMIT = 240
LOG_POLL_SECONDS = 1.0
LOG_READ_LIMIT = 512 * 1024  # most bytes read from one file per poll
_LOG_TAIL_BYTES = 300 * 8192


@dataclass(frozen=True)
class InterfaceAddress:
    name: str
    address: str
    label: str
    loopback: bool = False
    up: bool = True
    virtual: bool = False
    default_route: bool = False


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
    mdns_url_base: str = ""
    ca_pem: str = ""
    #: SHA-256 fingerprint of ca_pem, as the phone shows it, so the operator can
    #: compare the two before trusting the certificate.
    ca_sha256: str = ""
    http3: dict[str, Any] = field(default_factory=dict)
    mdns: dict[str, Any] = field(default_factory=dict)


def _default_route_interface() -> str:
    try:
        routes = Path("/proc/net/route").read_text().splitlines()[1:]
        defaults = [row.split() for row in routes if len(row.split()) > 7
                    and row.split()[1] == "00000000" and int(row.split()[3], 16) & 1]
        return min(defaults, key=lambda row: int(row[6]))[0] if defaults else ""
    except (OSError, ValueError):
        return ""


def discover_interfaces() -> list[InterfaceAddress]:
    rows: list[InterfaceAddress] = []
    default_route = _default_route_interface()
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
            try:
                flags = fcntl.ioctl(probe.fileno(), 0x8913, struct.pack("256s", name[:15].encode("utf-8")))
                up = bool(struct.unpack_from("H", flags, 16)[0] & 1)
            except OSError:
                up = False
            rows.append(
                InterfaceAddress(
                    name=name,
                    address=address,
                    label=f"{name} - {address}",
                    loopback=loopback,
                    up=up,
                    virtual=name.startswith(("docker", "br-", "veth", "virbr")),
                    default_route=name == default_route,
                )
            )
    rows.sort(key=lambda item: (not item.up, item.loopback, not item.default_route, item.virtual, item.name, item.address))
    return rows


def _now() -> float:
    return time.monotonic()


def normalize_log_level(value: Any) -> str | None:
    """The level a phone asked for, or None when it asked for no logs (or for
    something that is not a level)."""
    name = str(value or "").strip().upper()
    return name if name in LOG_FEED_LEVELS else None


def _log_rank(level: Any) -> int:
    return _LOG_RANK.get(str(level or "").upper(), 0)


# What must not leave the desktop even inside a log line: a security code, a
# session or pairing token, an Authorization header, a password. Log messages
# interpolate request lines, headers and exception text, so the line is scrubbed
# on top of only forwarding its message.
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]+")
_BEARER = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}")
_SECRET_PAIR = re.compile(
    r"(?i)\b(code|token|ticket|session|secret|password|passwd|pwd|api[_-]?key|authorization|cookie)"
    # The value may be "Bearer <token>" / "Basic <credentials>", scheme and secret together.
    r"\b(\s*[:=]\s*)(\"[^\"]*\"|'[^']*'|(?:(?:bearer|basic)\s+)?[^\s,;&\"')]+)"
)
_LONG_SECRET = re.compile(r"\b[A-Fa-f0-9]{32,}\b|\b[A-Za-z0-9_-]{40,}\b")


def _scrub_log_text(value: Any) -> str:
    text = _CONTROL_CHARS.sub(" ", str(value or ""))
    text = " ".join(text.split())
    text = _SECRET_PAIR.sub(lambda m: f"{m.group(1)}{m.group(2)}[redacted]", text)
    text = _BEARER.sub(lambda m: f"{m.group(1)} [redacted]", text)
    text = _LONG_SECRET.sub("[redacted]", text)
    if len(text) > LOG_MESSAGE_LIMIT:
        text = text[: LOG_MESSAGE_LIMIT - 1] + "…"
    return text


def _public_log(record: Any, source: str) -> dict[str, Any] | None:
    """One log record as the phone sees it: level, where it came from, the
    logger and the scrubbed message. Nothing else of the record is forwarded:
    its extra fields carry SQL text, job arguments and packet previews, and
    its traceback carries file paths."""
    if not isinstance(record, dict):
        return None
    message = _scrub_log_text(record.get("message"))
    if not message:
        return None
    level = str(record.get("level") or "INFO").strip().upper()
    if level not in _LOG_RANK:
        level = "INFO"
    logger = str(record.get("logger") or "")
    if logger.startswith("sniff4hound."):
        logger = logger[len("sniff4hound."):]
    return {
        "type": "log",
        "generated_at": str(record.get("timestamp") or utc_now())[:40],
        "level": level,
        "source": source,
        "logger": _scrub_log_text(logger)[:60],
        "message": message,
    }


def _default_log_dir() -> Path | None:
    return log_setup.log_directory()


def _parse_log_lines(data: bytes, source: str) -> list[dict[str, Any]]:
    events = []
    for raw in data.splitlines():
        try:
            record = json.loads(raw)
        except ValueError:
            continue
        event = _public_log(record, source)
        if event is not None:
            events.append(event)
    return events


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
        self._app: App | None = None
        self._tcp_server: HTTPServer | None = None
        self._tcp_thread: threading.Thread | None = None
        self._h3_server = None
        self._mdns_service = None
        self._state = MobileServerState()
        # Log feed. A subscriber appears in `_log_levels` only if its phone asked
        # for logs, mapped to the lowest rank it wants. The follower thread and
        # the ring exist only while at least one such subscriber is connected.
        self._log_levels: dict[int, int] = {}
        self._log_dir: Callable[[], Path | None] = _default_log_dir
        self._log_ring: deque[dict[str, Any]] = deque(maxlen=LOG_RING_SIZE)
        self._log_offsets: dict[str, tuple[int, int]] = {}
        self._log_stop = threading.Event()
        self._log_follower: threading.Thread | None = None

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
        return self._listen(selected.name, selected.address, port)

    def _listen(self, interface: str, address: str, port: int) -> dict[str, Any]:
        """Serve the mobile stream at ``address:port``: TLS over TCP and, on the
        same port number over UDP, HTTP/3. Every TCP response carries ``Alt-Svc``,
        so a client that trusts the certificate moves to HTTP/3 after its first
        request - a browser cannot open that first connection over QUIC."""
        # wsbuilder binds inside its serving thread, where a busy port would show
        # up as a traceback nobody sees. Probe here so it fails with a message.
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            probe.bind((address, port))
        except OSError as exc:
            raise ValueError(f"port {port} on {address} is unavailable ({exc.strerror})") from exc
        finally:
            probe.close()
        tls_material = ensure_mobile_tls(address)
        advertised: dict[str, str] = {}
        app = _build_mobile_app(self, advertised)
        h3_server, h3_reason = http3_listener.open_http3(app, tls_material, address, port)
        if h3_server is not None:
            advertised["alt_svc"] = http3_listener.alt_svc_for(h3_server)
        tcp_server = HTTPServer(address, port, app, ssl_context=tls_material.ssl_context)
        thread = threading.Thread(target=tcp_server.serve_forever, name="sniff4hound-mobile-stream", daemon=True)
        thread.start()
        deadline = time.monotonic() + _LISTEN_TIMEOUT_SECONDS
        while not tcp_server.wait_until_serving(0.05):
            if not thread.is_alive() or time.monotonic() > deadline:
                tcp_server.stop()
                if h3_server is not None:
                    h3_server.stop()
                app.close()
                raise ValueError(f"the mobile stream could not listen on https://{address}:{port}")
        published = None
        try:
            published = mdns.publish("stream", address, port, http3=h3_server is not None)
        except Exception as exc:
            # The listener is reachable by its selected LAN address even when
            # the OS/browser cannot publish or resolve .local names. Keep mDNS
            # as optional discovery instead of making it a single point of
            # failure for the QR.
            discovery = {
                "enabled": False,
                "hostname": "",
                "port": port,
                "addresses": [address],
                "error": str(exc),
            }
        else:
            discovery = published.metadata() if published else {"enabled": False, "addresses": [address], "port": port}
        mdns_hostname = str(discovery.get("hostname") or "").strip()
        ca_pem = public_mobile_ca_pem()
        with self._lock:
            self._app = app
            self._tcp_server = tcp_server
            self._tcp_thread = thread
            self._h3_server = h3_server
            self._mdns_service = published
            self._state = MobileServerState(
                interface=interface,
                address=address,
                port=port,
                running=True,
                # Numeric LAN addresses work in browsers that lack an mDNS NSS
                # module (the common Firefox "Server Not Found" case). The
                # certificate already contains this exact IP.
                url_base=f"https://{address}:{port}",
                mdns_url_base=f"https://{mdns_hostname}:{port}" if mdns_hostname else "",
                ca_pem=ca_pem,
                ca_sha256=ca_fingerprint_sha256(ca_pem),
                mdns=discovery,
                http3={
                    "enabled": h3_server is not None,
                    "transport": "https+h3" if h3_server is not None else "https",
                    "port": port,
                    "alt_svc": advertised.get("alt_svc", ""),
                    "reason": "" if h3_server is not None else f"HTTP/3 is off: {h3_reason}. The stream is served over HTTPS (HTTP/1.1).",
                },
            )
        return self.status()

    def stop(self) -> dict[str, Any]:
        with self._lock:
            servers = (self._tcp_server, self._h3_server)
            app = self._app
            published = self._mdns_service
            self._mdns_service = None
            self._tcp_server = None
            self._tcp_thread = None
            self._h3_server = None
            self._app = None
            self._state = MobileServerState()
            self._pairings.clear()
            for session in self._sessions.values():
                session.revoked_at = _now()
            self._notify_all({"type": "revoked", "generated_at": utc_now()})
            self._log_stop.set()
        if published is not None:
            try:
                published.close()
            except Exception:  # noqa: BLE001 - still stop both data listeners
                pass
        for server in servers:
            if server is not None:
                try:
                    server.stop()
                except Exception:  # noqa: BLE001 - one listener failing to stop must not leave the other running
                    pass
        if app is not None:
            try:
                app.close()
            except Exception:  # noqa: BLE001
                pass
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
            self._add_pairing_urls(view, pairing)
            view["server"] = state
            return view

    def pairing(self, pairing_id: str) -> dict[str, Any] | None:
        with self._lock:
            self._prune_locked()
            pairing = self._pairings.get(str(pairing_id or ""))
            if not pairing:
                return None
            view = self._pairing_view(pairing)
            self._add_pairing_urls(view, pairing)
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
            self._add_pairing_urls(view, pairing)
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

    def event_stream(self, token: str, log_level: str | None = None):
        """The SSE frames for one phone. `log_level` is the lowest level of log
        line it wants (DEBUG, INFO, WARNING, ERROR); None, or anything else,
        means it gets no log lines at all."""
        level = normalize_log_level(log_level)
        q: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=STREAM_QUEUE_SIZE)
        subscriber_id = id(q)
        backlog: list[dict[str, Any]] = []
        with self._lock:
            session = self.session(token)
            if session is None:
                yield _sse_frame("revoked", {"type": "revoked", "generated_at": utc_now()})
                return
            self._subscribers[subscriber_id] = (token, q)
            if level:
                # Registered and backlogged under one lock hold, so a line is in
                # the backlog or in the queue, never both and never neither.
                self._log_levels[subscriber_id] = _log_rank(level)
                self._start_log_follower_locked()
                backlog = self._log_backlog_locked(_log_rank(level))
        started = _now()
        try:
            yield _sse_frame("hello", {"type": "hello", "generated_at": utc_now()})
            for event in backlog:
                yield _sse_frame("log", event)
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
                self._log_levels.pop(subscriber_id, None)
                if not self._log_levels:
                    self._log_stop.set()

    def _log_backlog_locked(self, floor: int) -> list[dict[str, Any]]:
        matching = [event for event in self._log_ring if _log_rank(event["level"]) >= floor]
        return matching[-LOG_BACKLOG:]

    def _start_log_follower_locked(self) -> None:
        """Start following the log files for the first phone that wants logs.
        The files are read from where they end now, with their recent history
        loaded into the ring, so a phone's backlog and its live lines meet
        without a gap or a repeat."""
        follower = self._log_follower
        if follower is not None and follower.is_alive() and not self._log_stop.is_set():
            return
        self._log_stop = threading.Event()
        self._log_ring.clear()
        self._log_offsets.clear()
        directory = self._log_dir()
        if directory is not None:
            history: list[dict[str, Any]] = []
            for source in LOG_SOURCES:
                history.extend(self._seed_log_source(Path(directory) / f"{source}.ndjson", source))
            history.sort(key=lambda event: event["generated_at"])
            self._log_ring.extend(history[-LOG_RING_SIZE:])
        self._log_follower = threading.Thread(
            target=self._follow_logs,
            args=(self._log_stop,),
            name="sniff4hound-mobile-logs",
            daemon=True,
        )
        self._log_follower.start()

    def _seed_log_source(self, path: Path, source: str) -> list[dict[str, Any]]:
        try:
            stat = path.stat()
        except OSError:
            return []
        size = stat.st_size
        span = min(size, _LOG_TAIL_BYTES)
        data = b""
        if span:
            try:
                with path.open("rb") as handle:
                    handle.seek(size - span)
                    data = handle.read(span)
            except OSError:
                return []
        if span < size:
            # The window starts mid-line; drop that partial first line.
            data = data.split(b"\n", 1)[1] if b"\n" in data else b""
        complete = data[: data.rfind(b"\n") + 1] if b"\n" in data else b""
        # The offset is where the complete lines end, so a line still being
        # written is read whole by the next poll instead of being split.
        self._log_offsets[source] = (stat.st_ino, size - (len(data) - len(complete)))
        return _parse_log_lines(complete, source)

    def _read_new_log_lines(self, path: Path, source: str) -> list[dict[str, Any]]:
        try:
            stat = path.stat()
        except OSError:
            self._log_offsets.pop(source, None)
            return []
        inode, offset = self._log_offsets.get(source, (stat.st_ino, 0))
        if inode != stat.st_ino or stat.st_size < offset:
            offset = 0  # rotated or truncated: this is a new file, read it from its start
        if stat.st_size <= offset:
            self._log_offsets[source] = (stat.st_ino, offset)
            return []
        try:
            with path.open("rb") as handle:
                handle.seek(offset)
                data = handle.read(min(stat.st_size - offset, LOG_READ_LIMIT))
        except OSError:
            return []
        end = data.rfind(b"\n")
        if end < 0:
            # No complete line yet. One longer than the read limit would stall
            # the feed for good, so skip it.
            if len(data) >= LOG_READ_LIMIT:
                self._log_offsets[source] = (stat.st_ino, offset + len(data))
            return []
        self._log_offsets[source] = (stat.st_ino, offset + end + 1)
        return _parse_log_lines(data[: end + 1], source)

    def _poll_logs_locked(self) -> None:
        directory = self._log_dir()
        if directory is None:
            return
        fresh: list[dict[str, Any]] = []
        for source in LOG_SOURCES:
            fresh.extend(self._read_new_log_lines(Path(directory) / f"{source}.ndjson", source))
        fresh.sort(key=lambda event: event["generated_at"])
        for event in fresh:
            self._log_ring.append(event)
            self._notify_all(event)

    def _follow_logs(self, stop: threading.Event) -> None:
        while not stop.wait(LOG_POLL_SECONDS):
            with self._lock:
                if stop is not self._log_stop or not self._log_levels:
                    return
                try:
                    self._poll_logs_locked()
                except Exception:  # noqa: BLE001 - a log feed must never take the stream down
                    pass

    def _notify_all(self, event: dict[str, Any], *, token: str | None = None) -> None:
        """Fan an event out to subscribers, or to exactly one when `token` is
        given - the revoke case, where the target is the *only* device that
        should hear about it."""
        dead = []
        is_log = event.get("type") == "log"
        for subscriber_id, (subscriber_token, q) in self._subscribers.items():
            if token is not None and subscriber_token != token:
                continue
            if is_log:
                # Only a phone that asked for logs gets them, and only from the
                # level it chose upward.
                wanted = self._log_levels.get(subscriber_id)
                if wanted is None or _log_rank(event.get("level")) < wanted:
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

    def _add_pairing_urls(self, view: dict[str, Any], pairing: Pairing) -> None:
        path = f"/mobile/pair/{pairing.id}"
        view["url"] = f"{self._state.url_base}{path}"
        view["mdns_url"] = f"{self._state.mdns_url_base}{path}" if self._state.mdns_url_base else ""

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


# wsbuilder resolves routes by exact path, so the pairing and session links keep
# their /mobile/pair/<id> and /mobile/session/<token> shape (QR codes, form
# actions and redirects use them) and are rewritten to the fixed routes below,
# with the id or token carried as a query parameter. The leading underscore keeps
# those internal names out of reach of any real pairing id.
_PAIR_PATH = re.compile(r"^/mobile/pair/([^/]+)(/verify)?$")
_SESSION_PATH = re.compile(r"^/mobile/session/([^/]+)$")
_LISTEN_TIMEOUT_SECONDS = 5.0


def _header(request: Request, name: str) -> str:
    wanted = name.lower()
    for key, value in (request.headers or {}).items():
        if str(key).lower() == wanted:
            return str(value)
    return ""


def _client_ip(request: Request) -> str:
    client = request.client
    return str(client[0]) if client else ""


def _reply(status: int, body: bytes | str, content_type: str = "text/html; charset=utf-8", headers=None) -> Response:
    if isinstance(body, str):
        body = body.encode("utf-8")
    merged = {
        "Content-Type": content_type,
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
    }
    merged.update(headers or {})
    return Response(status, body=body, headers=merged)


def _with_path_params(request: Request, path: str, **params: str) -> Request:
    query = dict(request.query)
    query.update(params)  # what the path said wins over a query parameter of the same name
    return Request(
        request.method,
        path,
        urlencode(query),
        request.headers,
        request.body,
        request.client,
        tls=request.tls,
        version=request.version,
        trailers=request.trailers,
    )


def _build_mobile_app(service: MobileStreamService, advertised: dict[str, str]) -> App:
    """The mobile stream's routes as a wsbuilder app, so the same handlers are
    served over HTTP/1.1 and HTTP/3. ``advertised["alt_svc"]`` is read per
    response: it is filled in once the HTTP/3 listener is up."""
    app = App()  # no CORS: the pages are same-origin, nothing here is for another site

    @app.view("/mobile/ca.pem")
    def ca_pem(_request):
        return _reply(200, public_mobile_ca_pem(), "application/x-pem-file")

    @app.view("/mobile/ca.crt")
    def ca_download(_request):
        # The type is what makes a phone offer to install it: iOS Safari treats
        # application/x-x509-ca-cert as a profile to install, and Android keeps it as a
        # .crt the certificate installer lists. Public by nature - it is a CA
        # certificate, not a key - and the same bytes /mobile/ca.pem already serves.
        pem = public_mobile_ca_pem()
        if not pem.strip():
            return _reply(404, _closed_page("No certificate is available."))
        return _reply(
            200,
            pem,
            "application/x-x509-ca-cert",
            {"Content-Disposition": 'attachment; filename="sniff4hound-ca.crt"'},
        )

    @app.view("/mobile/certificate")
    def certificate_page(_request):
        return _reply(200, _certificate_page(public_mobile_ca_pem()))

    @app.view("/mobile/_pair")
    def pair_page(request):
        pairing = service.open_pairing(
            request.query.get("id", ""),
            client=_client_ip(request),
            user_agent=_header(request, "user-agent"),
        )
        if not pairing:
            return _reply(410, _closed_page())
        if not pairing.approved_at:
            # Nothing is served to an unapproved device but a holding
            # page that refreshes itself until the operator accepts it.
            return _reply(200, _awaiting_approval_page())
        return _reply(200, _pairing_page(pairing))

    @app.view("/mobile/_pair-verify", methods=("POST",))
    def pair_verify(request):
        body = bytes(request.body or b"")[:4096].decode("utf-8", errors="replace")
        code = (parse_qs(body).get("code") or [""])[0]
        token = service.verify_pairing(
            request.query.get("id", ""),
            code,
            client=_client_ip(request),
            user_agent=_header(request, "user-agent"),
        )
        if not token:
            return _reply(403, _closed_page("Incorrect code. This link is now closed."))
        return Response(303, body=b"", headers={"Location": f"/mobile/session/{token}", "Cache-Control": "no-store"})

    @app.view("/mobile/_session")
    def session_page(request):
        token = request.query.get("token", "")
        if service.session(token) is None:
            return _reply(403, _closed_page("Session revoked or expired."))
        return _reply(200, _session_page(token))

    @app.view("/mobile/events")
    def events(request):
        token = request.query.get("session", "")
        # No `level`, or one that is not a level, means this phone gets no logs.
        log_level = normalize_log_level(request.query.get("level", ""))
        if service.session(token) is None:
            return _reply(403, b"forbidden", "text/plain; charset=utf-8")
        return Response(
            200,
            stream=service.event_stream(token, log_level=log_level),
            headers={"Content-Type": "text/event-stream; charset=utf-8", "Cache-Control": "no-store"},
        )

    original_dispatch = app.dispatch

    def dispatch(request):
        path = request.path.rstrip("/") or "/"
        pair = _PAIR_PATH.match(path)
        session = None if pair else _SESSION_PATH.match(path)
        if pair:
            request = _with_path_params(request, "/mobile/_pair-verify" if pair.group(2) else "/mobile/_pair", id=pair.group(1))
        elif session:
            request = _with_path_params(request, "/mobile/_session", token=session.group(1))
        response = original_dispatch(request)
        if getattr(response, "status", 0) == 404 and not pair and not session:
            response = _reply(404, _closed_page("Not found."))
        alt_svc = advertised.get("alt_svc")
        if alt_svc and hasattr(response, "headers"):
            response.headers.setdefault("Alt-Svc", alt_svc)
        return response

    app.dispatch = dispatch
    return app


_CERTIFICATE_LINK = (
    '<p class="meta"><a href="/mobile/certificate">Install the certificate</a> '
    "to remove the browser warning and let this phone use HTTP/3.</p>"
)


def _shell(title: str, body: str, *, certificate_link: bool = True) -> str:
    footer = _CERTIFICATE_LINK if certificate_link else ""
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
.tabs, .levels {{ display: flex; flex-wrap: wrap; align-items: center; gap: 8px; margin-top: 16px; }}
.tab, .chip {{ width: auto; margin: 0; border: 1px solid rgba(255,255,255,.18); background: rgba(255,255,255,.06); color: #cfe3df; padding: 8px 14px; border-radius: 999px; font-size: 14px; font-weight: 700; cursor: pointer; }}
.tab.on, .chip.on {{ background: #34d399; border-color: #34d399; color: #05100c; }}
.chip.lv-DEBUG.on {{ background: #9fb3ae; border-color: #9fb3ae; }}
.chip.lv-WARNING.on {{ background: #fbbf24; border-color: #fbbf24; }}
.chip.lv-ERROR.on {{ background: #f87171; border-color: #f87171; }}
a {{ color: #7ee0b8; }}
.button {{ display: block; box-sizing: border-box; width: 100%; margin-top: 14px; border-radius: 12px; padding: 14px 18px; background: #34d399; color: #05100c; font-weight: 800; font-size: 16px; text-align: center; text-decoration: none; }}
h2 {{ font-size: 18px; margin: 22px 0 6px; }}
ol {{ color: #b9cbc8; line-height: 1.55; padding-left: 22px; }}
.fingerprint {{ overflow-wrap: anywhere; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; color: #cfe3df; }}
.badge {{ display: inline-block; min-width: 18px; margin-left: 4px; padding: 1px 6px; border-radius: 999px; background: #fbbf24; color: #1a1304; font-size: 12px; text-align: center; }}
.badge[hidden], [hidden] {{ display: none; }}
.log {{ display: grid; gap: 4px; padding: 10px 12px; border-left: 4px solid #9fb3ae; border-radius: 10px; }}
.log .head {{ display: flex; flex-wrap: wrap; align-items: baseline; gap: 8px; }}
.log .lvl {{ font-size: 11px; font-weight: 800; letter-spacing: .06em; color: #9fb3ae; }}
.log .msg {{ overflow-wrap: anywhere; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 13px; line-height: 1.45; }}
.log.lv-INFO {{ border-left-color: #60a5fa; }} .log.lv-INFO .lvl {{ color: #60a5fa; }}
.log.lv-WARNING {{ border-left-color: #fbbf24; }} .log.lv-WARNING .lvl {{ color: #fbbf24; }}
.log.lv-ERROR, .log.lv-CRITICAL {{ border-left-color: #f87171; }} .log.lv-ERROR .lvl, .log.lv-CRITICAL .lvl {{ color: #f87171; }}
</style>
</head>
<body><main><section class="panel">{body}{footer}</section></main></body>
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
    levels_json = json.dumps(list(LOG_FEED_LEVELS))
    return _shell(
        "Sniff4Hound Mobile Stream",
        f"""
<h1>Live stream</h1>
<p>Read-only alerts, traffic events and log lines. Payloads and control actions are not exposed to this device.</p>
<div id="status" class="meta">Connecting...</div>
<div id="protocol" class="meta"></div>
<div class="tabs" role="tablist">
  <button type="button" class="tab on" role="tab" aria-selected="true" data-tab="events">Events</button>
  <button type="button" class="tab" role="tab" aria-selected="false" data-tab="logs">Logs <span id="log-badge" class="badge" hidden>0</span></button>
</div>
<div id="events" class="events"></div>
<div id="logs-panel" hidden>
  <div class="levels" role="group" aria-label="Minimum log level">
    <span class="meta">Level</span>
    <button type="button" class="chip lv-DEBUG" data-level="DEBUG" aria-pressed="false">Debug</button>
    <button type="button" class="chip lv-INFO" data-level="INFO" aria-pressed="false">Info</button>
    <button type="button" class="chip lv-WARNING" data-level="WARNING" aria-pressed="false">Warning</button>
    <button type="button" class="chip lv-ERROR" data-level="ERROR" aria-pressed="false">Error</button>
  </div>
  <div id="level-note" class="meta"></div>
  <div id="logs" class="events"></div>
  <p id="logs-empty" class="meta">No log lines at this level yet.</p>
</div>
<script>
const events = document.getElementById("events");
const status = document.getElementById("status");
(function showProtocol() {{
  const nav = performance.getEntriesByType("navigation")[0];
  const proto = nav && nav.nextHopProtocol;
  const label = proto === "h3" ? "HTTP/3" : proto === "h2" ? "HTTP/2" : proto ? "HTTPS (" + proto + ")" : "";
  if (label) document.getElementById("protocol").textContent = "Connection: " + label;
}})();
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
const LEVELS = {levels_json};
const logs = document.getElementById("logs");
const logsEmpty = document.getElementById("logs-empty");
const badge = document.getElementById("log-badge");
let level = "INFO";
let unseen = 0;
let counting = false;
let source = null;
try {{
  const saved = localStorage.getItem("sniff4hound-log-level");
  if (LEVELS.includes(saved)) level = saved;
}} catch (error) {{}}
function addLog(data) {{
  const row = document.createElement("div");
  row.className = `event log lv-${{data.level || "INFO"}}`;
  const head = document.createElement("div");
  head.className = "head";
  const lvl = document.createElement("span");
  lvl.className = "lvl";
  lvl.textContent = data.level || "INFO";
  const meta = document.createElement("span");
  meta.className = "meta";
  meta.textContent = [data.source, data.logger, data.generated_at].filter(Boolean).join(" \\u00b7 ");
  head.appendChild(lvl);
  head.appendChild(meta);
  const msg = document.createElement("div");
  msg.className = "msg";
  msg.textContent = data.message || "";
  row.appendChild(head);
  row.appendChild(msg);
  logs.prepend(row);
  while (logs.children.length > 200) logs.removeChild(logs.lastChild);
  logsEmpty.hidden = true;
  if (counting && document.getElementById("logs-panel").hidden) {{
    unseen += 1;
    badge.textContent = String(unseen);
    badge.hidden = false;
  }}
}}
function paintLevels() {{
  document.querySelectorAll(".chip").forEach((chip) => {{
    const on = chip.dataset.level === level;
    chip.classList.toggle("on", on);
    chip.setAttribute("aria-pressed", String(on));
  }});
  document.getElementById("level-note").textContent = level === "ERROR"
    ? "Showing errors only"
    : `Showing ${{level.toLowerCase()}} and above`;
}}
function showTab(next) {{
  document.getElementById("events").hidden = next !== "events";
  document.getElementById("logs-panel").hidden = next !== "logs";
  document.querySelectorAll(".tab").forEach((tab) => {{
    const on = tab.dataset.tab === next;
    tab.classList.toggle("on", on);
    tab.setAttribute("aria-selected", String(on));
  }});
  if (next === "logs") {{ unseen = 0; badge.hidden = true; }}
}}
function setLevel(next) {{
  if (!LEVELS.includes(next) || next === level) return;
  level = next;
  try {{ localStorage.setItem("sniff4hound-log-level", level); }} catch (error) {{}}
  logs.textContent = "";
  logsEmpty.hidden = false;
  paintLevels();
  connect();
}}
function connect() {{
  if (source) source.close();
  counting = false;
  source = new EventSource(`/mobile/events?session=${{encodeURIComponent(token)}}&level=${{encodeURIComponent(level)}}`);
  source.addEventListener("hello", () => {{
    status.textContent = "Connected";
    // The lines a phone gets on connecting are history, not news.
    setTimeout(() => {{ counting = true; }}, 800);
  }});
  source.addEventListener("packet", (event) => addEvent(JSON.parse(event.data)));
  source.addEventListener("stats_update", (event) => addEvent(JSON.parse(event.data)));
  source.addEventListener("runtime_mode", (event) => addEvent(JSON.parse(event.data)));
  source.addEventListener("log", (event) => addLog(JSON.parse(event.data)));
  source.addEventListener("revoked", () => {{ status.textContent = "Session revoked"; source.close(); }});
  source.onerror = () => {{ status.textContent = "Reconnecting..."; }};
}}
document.querySelectorAll(".tab").forEach((tab) => tab.addEventListener("click", () => showTab(tab.dataset.tab)));
document.querySelectorAll(".chip").forEach((chip) => chip.addEventListener("click", () => setLevel(chip.dataset.level)));
paintLevels();
connect();
</script>
""",
    )


def _certificate_page(pem: str) -> str:
    fingerprint = ca_fingerprint_sha256(pem)
    if not fingerprint:
        return _shell("Sniff4Hound Certificate", "<h1>Certificate</h1><p>No certificate is available yet.</p>", certificate_link=False)
    return _shell(
        "Sniff4Hound Certificate",
        f"""
<h1>Install the certificate</h1>
<p>This Sniff4Hound signs its own certificate, so the browser warns that the connection is not private and cannot use HTTP/3. Installing the certificate once on this phone removes the warning. Only do it if you started this Sniff4Hound yourself.</p>
<a class="button" href="/mobile/ca.crt" download="sniff4hound-ca.crt">Download certificate</a>
<p class="meta">SHA-256 fingerprint</p>
<p class="fingerprint">{html.escape(fingerprint)}</p>
<p class="meta">Sniff4Hound Settings on the desktop shows the same fingerprint. Install it only if both match.</p>
<h2>Android</h2>
<ol>
  <li>Download the certificate with Chrome.</li>
  <li>Open Settings, then Security (or Security &amp; privacy), then Encryption &amp; credentials, then Install a certificate, then CA certificate.</li>
  <li>Confirm the warning and pick <b>sniff4hound-ca.crt</b> from Downloads.</li>
</ol>
<h2>iPhone and iPad</h2>
<ol>
  <li>Open this page in Safari and tap Download certificate, then Allow.</li>
  <li>Open Settings, tap <b>Profile Downloaded</b> and install it.</li>
  <li>Open Settings, General, About, Certificate Trust Settings, and turn on full trust for <b>Sniff4Hound Mobile Stream CA</b>.</li>
</ol>
<p class="meta">Remove it later under Settings, Security, Encryption &amp; credentials, User credentials on Android, or Settings, General, VPN &amp; Device Management on iOS.</p>
<p class="meta">HTTP/3 starts on a later page load, once the browser has seen this server offer it.</p>
""",
        certificate_link=False,
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
