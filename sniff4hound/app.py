from __future__ import annotations

import errno
import json
import mimetypes
import sys
import time
from functools import wraps
from os import getenv
import threading
from pathlib import Path
from typing import Any

import wsbuilder as _wsbuilder_package
import wsbuilder.framework as _wsbuilder_framework
import wsbuilder.http as _wsbuilder_http
import wsbuilder.server as _wsbuilder_server
import wsbuilder.ws as _wsbuilder_ws
from wsbuilder import App, Response, parse_close_payload

from . import __version__
from . import access_log
from .auth import authenticate_request, extract_token_from_header, RATE_LIMITER, REQUIRE_AUTH
from .export import (
    EXPORT_DATASETS,
    EXPORT_FIELDS,
    EXPORT_FORMATS,
    build_export,
    export_filename,
    normalize_format,
    rows_to_csv,
)
from .ipc import IpcClient
from .settings import (
    API_MAX_LIMIT,
    CAPTURE_AUTO_START,
    DB_PATH,
    DEFAULT_DOCS_DESCRIPTION,
    DEFAULT_DOCS_TITLE,
    HOST,
    PORT,
    resolve_ipc_connect_timeout,
    resolve_ipc_socket,
    resolve_ipc_token,
)
from .process_control import process_shutdown_requested, request_process_shutdown
from .store import SniffStore
from .utils import (
    KNOWN_PROTOCOLS,
    bytes_to_hex_preview,
    clamp_int,
    ip_scope,
    json_dumps,
    normalize_protocol_name,
    normalize_text,
    parse_since_window,
    safe_float,
    safe_int,
    utc_now,
)


PACKAGE_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_ROOT.parent
SOURCE_FRONTEND_DIST_DIR = PROJECT_ROOT / "frontend" / "dist"
PACKAGE_FRONTEND_DIST_DIR = PACKAGE_ROOT / "_frontend_dist"
FRONTEND_PUBLIC_DIR = PROJECT_ROOT / "frontend" / "public"
DOCS_DIR = PROJECT_ROOT / "docs"


def _resolve_frontend_dist_dir() -> Path:
    override = str(getenv("SNIFF4HOUND_FRONTEND_DIST", "")).strip()
    candidates = []
    if override:
        candidates.append(Path(override).expanduser())
    candidates.extend([SOURCE_FRONTEND_DIST_DIR, PACKAGE_FRONTEND_DIST_DIR])
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return candidates[0]


FRONTEND_DIST_DIR = _resolve_frontend_dist_dir()
# Every path vue-router can land on has to be served index.html here too,
# or a refresh (F5), a bookmark or a link pasted into a ticket - the basic
# shift-handoff gesture - answers a bare-text 404 instead of the SPA.
# /settings, /domains, /paths and /ips were missing and did exactly that.
# Each entry is registered both with and without a trailing slash (see
# _register_static_frontend), since "/soc/" used to 404 while "/soc" worked.
SPA_ROUTES = (
    "/dashboard",
    "/radar",
    "/investigate",
    "/sniffer",
    "/honeypot",
    "/protocols",
    # Every protocol slice, generated from utils.KNOWN_PROTOCOLS - the page
    # renders a card per protocol the sniffer can emit, and hand-listing a
    # subset here meant /protocols/mdns, /protocols/igmp and even
    # /protocols/unknown answered a bare 404 on refresh.
    *(f"/protocols/{proto}" for proto in KNOWN_PROTOCOLS),
    "/map",
    "/charts",
    "/explorer",
    "/agents",
    "/targets",
    "/sessions",
    "/intel",
    "/ports",
    "/banners",
    "/tags",
    "/catalog",
    "/soc",
    "/monitors",
    "/settings",
    "/domains",
    "/paths",
    "/ips",
    "/api",
)


def _is_benign_http_send_error(exc: Exception) -> bool:
    if isinstance(exc, (BrokenPipeError, ConnectionResetError)):
        return True
    return isinstance(exc, OSError) and getattr(exc, "errno", None) in {
        errno.EPIPE,
        errno.ECONNRESET,
        errno.ECONNABORTED,
    }


def _guarded_send_http_response(conn, response, *, send_body=True):
    status_code = int(response.status)
    if not 100 <= status_code <= 599:
        raise ValueError("HTTP response status must be between 100 and 599")
    reason = _wsbuilder_http.validate_header_value(
        response.reason or _wsbuilder_http.STATUS_MESSAGES.get(status_code, "Unknown")
    )
    headers = {}
    seen_headers = set()
    for name, value in (response.headers or {}).items():
        header_name = _wsbuilder_http.validate_header_name(name)
        normalized = header_name.lower()
        if normalized in seen_headers:
            raise ValueError(f"Duplicate response header: {header_name}")
        seen_headers.add(normalized)
        headers[header_name] = _wsbuilder_http.validate_header_value(value)

    lowermap = {k.lower(): v for k, v in headers.items()}
    status_allows_body = not (100 <= status_code < 200 or status_code in {204, 304})
    should_send_body = bool(send_body and status_allows_body)
    if not status_allows_body:
        for name in list(headers):
            if name.lower() in {"content-length", "transfer-encoding"}:
                headers.pop(name)
        lowermap = {k.lower(): v for k, v in headers.items()}
    elif getattr(response, "is_stream", False):
        if "transfer-encoding" not in lowermap and "content-length" not in lowermap:
            headers["Transfer-Encoding"] = "chunked"
        lowermap = {k.lower(): v for k, v in headers.items()}
    elif "content-length" not in lowermap:
        headers["Content-Length"] = str(len(response.body))
        lowermap = {k.lower(): v for k, v in headers.items()}
    if "connection" not in lowermap:
        headers["Connection"] = "close"
        lowermap = {k.lower(): v for k, v in headers.items()}
    status_line = f"HTTP/1.1 {status_code} {reason}\r\n"
    hdrs = ""
    for key, value in headers.items():
        hdrs += f"{key}: {value}\r\n"
    resp = status_line + hdrs + "\r\n"
    try:
        conn.sendall(resp.encode("utf-8"))
        if not should_send_body:
            return
        if getattr(response, "is_stream", False):
            use_chunked = "chunked" in lowermap.get("transfer-encoding", "").lower()
            for chunk in _wsbuilder_http._iter_stream_chunks(response.stream):
                if use_chunked:
                    conn.sendall(f"{len(chunk):X}\r\n".encode("utf-8"))
                    conn.sendall(chunk)
                    conn.sendall(b"\r\n")
                else:
                    conn.sendall(chunk)
            if use_chunked:
                conn.sendall(b"0\r\n\r\n")
        else:
            conn.sendall(response.body)
    except Exception as exc:
        if _is_benign_http_send_error(exc):
            return
        print(f"[http] send error {status_code}: {exc}")


# wsbuilder re-exports `send_http_response` from several modules, and the call
# sites resolve it from their own module globals at call time - so every module
# that binds the name has to be replaced, not just the one that defines it.
_WSBUILDER_SEND_MODULES = (
    _wsbuilder_http,
    _wsbuilder_server,
    _wsbuilder_ws,
    _wsbuilder_framework,
    _wsbuilder_package,
)


def _install_wsbuilder_http_send_guard():
    # Only modules that already bind the name are patched. `wsbuilder/__init__`
    # does not re-export `send_http_response`, so assigning it there created an
    # attribute nothing ever read; and patching a module that does not bind the
    # name would hide a future rename behind an attribute no call site reads.
    # Testing first keeps the guard honest either way, whichever modules a
    # given wsbuilder release happens to export it from.
    for module in _WSBUILDER_SEND_MODULES:
        if hasattr(module, "send_http_response"):
            module.send_http_response = _guarded_send_http_response


_install_wsbuilder_http_send_guard()

app = App()


def _install_access_log():
    """Wrap `app.dispatch` so every served HTTP request produces one
    nginx-combined access line (see access_log.py).

    A dispatch wrapper rather than wsbuilder's `metrics` hooks: those fire
    with only (method, path, status) and never see the Request, so the
    client address, Referer and User-Agent the combined format needs are
    simply not reachable from there. wsbuilder calls `self.app.dispatch(...)`
    on the instance, so replacing the bound attribute is enough.

    The response is logged even when dispatch raises: an unhandled handler
    error is exactly the request an operator most wants in the log, and
    wsbuilder turns it into a 500 immediately after.
    """
    original_dispatch = app.dispatch

    def dispatch_with_access_log(request):
        started_at = time.perf_counter()
        try:
            response = original_dispatch(request)
        except BaseException:
            access_log.log_request(request, 500, 0, time.perf_counter() - started_at)
            raise
        try:
            access_log.log_response(request, response, started_at)
        except Exception:
            pass
        return response

    app.dispatch = dispatch_with_access_log


_install_access_log()
store = SniffStore(DB_PATH)


class WebSocketHub:
    def __init__(self):
        self._lock = threading.RLock()
        self._clients: dict[int, dict[str, Any]] = {}

    def register(self, ws):
        with self._lock:
            client_id = id(ws)
            self._clients[client_id] = {
                "id": client_id,
                "addr": list(getattr(ws, "addr", ()) or ()),
                "subprotocol": getattr(ws, "subprotocol", "") or "",
                "connected_at": utc_now(),
                "last_seen": utc_now(),
                "ws": ws,
                # At most one periodic snapshot per client. Replacing rather
                # than appending is deliberate: a client that navigates
                # between protocols would otherwise accumulate subscriptions
                # and multiply the server-side query cost with every hop.
                "subscription": None,
            }
        return client_id

    def subscribe_snapshot(self, ws, params: dict, interval: float):
        """Ask for a periodic snapshot on this connection, replacing any prior one."""
        with self._lock:
            client = self._clients.get(id(ws))
            if client is None:
                return False
            client["subscription"] = {
                "params": dict(params),
                "interval": float(interval),
                # Due immediately: the first delivery is what replaces the
                # HTTP round trip the view would otherwise make on mount.
                "due_at": 0.0,
            }
            return True

    def unsubscribe_snapshot(self, ws):
        with self._lock:
            client = self._clients.get(id(ws))
            if client is not None:
                client["subscription"] = None

    def due_subscriptions(self, now: float) -> list[tuple]:
        """(ws, params) for every subscription whose interval has elapsed.

        The due time is advanced here, under the lock, so a slow snapshot
        cannot cause the same client to be picked up twice.
        """
        due = []
        with self._lock:
            for client in self._clients.values():
                subscription = client.get("subscription")
                ws = client.get("ws")
                if not subscription or ws is None:
                    continue
                if subscription["due_at"] > now:
                    continue
                subscription["due_at"] = now + subscription["interval"]
                due.append((ws, dict(subscription["params"])))
        return due

    def send_to(self, ws, payload: dict) -> bool:
        """One message to one client. Drops the client if the socket is gone."""
        try:
            ws.send_text(_json_text(payload))
        except Exception:
            self.unregister(ws)
            return False
        with self._lock:
            client = self._clients.get(id(ws))
            if client is not None:
                client["last_seen"] = utc_now()
        return True

    def unregister(self, ws):
        with self._lock:
            self._clients.pop(id(ws), None)

    def touch(self, ws):
        with self._lock:
            client = self._clients.get(id(ws))
            if client:
                client["last_seen"] = utc_now()

    def list_clients(self):
        with self._lock:
            rows = []
            for client in self._clients.values():
                row = {key: value for key, value in client.items() if key != "ws"}
                row["connected"] = True
                rows.append(row)
            return rows

    def broadcast(self, payload: dict):
        message = _json_text(payload)
        dead = []
        with self._lock:
            for client_id, client in self._clients.items():
                ws = client.get("ws")
                if ws is None:
                    dead.append(client_id)
                    continue
                try:
                    ws.send_text(message)
                    client["last_seen"] = utc_now()
                except Exception:
                    dead.append(client_id)
            for client_id in dead:
                self._clients.pop(client_id, None)

    def ping(self, payload: bytes = b""):
        dead = []
        with self._lock:
            for client_id, client in self._clients.items():
                ws = client.get("ws")
                if ws is None:
                    dead.append(client_id)
                    continue
                try:
                    ws.send_ping(payload or b"sniff4hound")
                except Exception:
                    dead.append(client_id)
            for client_id in dead:
                self._clients.pop(client_id, None)

    def close(self, code=1000, reason=""):
        with self._lock:
            clients = list(self._clients.values())
            self._clients.clear()
        for client in clients:
            ws = client.get("ws")
            if ws is None:
                continue
            try:
                ws.close(code, reason)
            except Exception:
                pass


hub = WebSocketHub()


class RuntimeControllerClient:
    """Web-process proxy for the real `RuntimeController`, which lives in
    the privileged capture process (see `capture_service.py`). Same public
    method names as that class so none of the HTTP routes below need to
    know capture moved to a different process."""

    def __init__(self, ipc_client: IpcClient):
        self._ipc_client = ipc_client
        self.mode = "sniffer"

    def _remember_mode(self, snapshot):
        if isinstance(snapshot, dict) and snapshot.get("mode"):
            self.mode = str(snapshot["mode"])
        return snapshot

    def snapshot(self):
        return self._remember_mode(self._ipc_client.call("snapshot"))

    def start(self, engine=None):
        return self._remember_mode(self._ipc_client.call("start", engine=engine))

    def stop(self, engine=None):
        return self._remember_mode(self._ipc_client.call("stop", engine=engine))

    def set_engines(self, selection):
        return self._remember_mode(self._ipc_client.call("set_engines", selection=selection))

    def set_mode(self, mode: str):
        return self._remember_mode(self._ipc_client.call("set_mode", mode=mode))

    def set_sniffer_interfaces(self, interfaces=None):
        return self._remember_mode(self._ipc_client.call("set_sniffer_interfaces", interfaces=interfaces))

    def set_sniffer_interface(self, interface: str = ""):
        return self._remember_mode(self._ipc_client.call("set_sniffer_interface", interface=interface))

    def list_honeypot_listeners(self):
        return self._ipc_client.call("list_honeypot_listeners")

    def create_honeypot_listener(self, proto: str, port, label: str = ""):
        return self._ipc_client.call("create_honeypot_listener", proto=proto, port=port, label=label)

    def set_honeypot_listener_enabled(self, listener_id: str, enabled: bool):
        return self._ipc_client.call("set_honeypot_listener_enabled", listener_id=listener_id, enabled=enabled)


def _on_capture_event(payload: dict) -> None:
    hub.broadcast(payload)
    if payload.get("type") == "runtime_mode":
        mode = (payload.get("runtime") or {}).get("mode")
        if mode:
            runtime.mode = str(mode)


ipc_client = IpcClient(
    resolve_ipc_socket(PORT),
    resolve_ipc_token(),
    on_event=_on_capture_event,
    connect_timeout=resolve_ipc_connect_timeout(),
)
runtime = RuntimeControllerClient(ipc_client)


def connect_capture_service() -> bool:
    """Connect to the privileged capture process. Must be called once
    before serving requests - `bootstrap_capture()`/the runtime endpoints
    would otherwise block/fail on the first real call instead of failing
    fast with a clear error."""
    try:
        ipc_client.connect()
    except Exception as exc:
        print(f"[!] Could not connect to the capture service: {exc}", file=sys.stderr)
        return False
    try:
        runtime.snapshot()
    except Exception:
        pass
    return True
AUTH_SESSION_PATH = "/api/auth/session"
DOCS_PATHS = ("/docs", "/docs.json")
WS_AUTH_CLOSE_CODE = 4401
# Bounds for the periodic snapshot channel. The floor is not a preference:
# each delivery runs the same aggregate queries the HTTP endpoint does, over
# the whole filtered set, so an unbounded interval lets any authenticated
# client pin the database by asking for zero. The ceiling keeps a forgotten
# tab from holding a subscription that never fires.
WS_SNAPSHOT_MIN_INTERVAL_SECONDS = 2.0
WS_SNAPSHOT_MAX_INTERVAL_SECONDS = 300.0
WS_SNAPSHOT_DEFAULT_INTERVAL_SECONDS = 10.0
# How often the pusher wakes to look for due subscriptions. Finer than the
# minimum interval so the delivery jitter stays below a second.
WS_SNAPSHOT_TICK_SECONDS = 0.5

WS_KEEPALIVE_INTERVAL_SECONDS = 25.0
WS_PONG_TIMEOUT_SECONDS = 10.0

ENDPOINTS = [
    {"method": "GET", "path": "/", "desc": "Frontend SPA shell."},
    {"method": "GET", "path": "/docs", "desc": "Automatic runtime documentation."},
    {"method": "GET", "path": "/docs.json", "desc": "Automatic runtime docs payload."},
    {"method": "GET", "path": "/protocols/", "desc": "Observed protocol list."},
    {"method": "GET", "path": "/api/protocols/snapshot/", "desc": "One protocol slice: counters, protocol-specific facets, timeline and rows, in a single read."},
    {"method": "GET", "path": "/count/targets/", "desc": "Count capture sessions."},
    {"method": "GET", "path": "/count/ports/", "desc": "Count captured packets."},
    {"method": "GET", "path": "/count/ports/tcp/", "desc": "Count TCP packets."},
    {"method": "GET", "path": "/count/ports/udp/", "desc": "Count UDP packets."},
    {"method": "GET", "path": "/count/ports/icmp/", "desc": "Count ICMP packets."},
    {"method": "GET", "path": "/count/ports/sctp/", "desc": "Count SCTP packets."},
    {"method": "GET", "path": "/count/banners/", "desc": "Count captured responses."},
    {"method": "GET", "path": "/targets/", "desc": "List capture sessions."},
    {"method": "POST", "path": "/target/", "desc": "Create a capture session."},
    {"method": "PUT", "path": "/target/", "desc": "Update a capture session."},
    {"method": "DELETE", "path": "/target/", "desc": "Delete a capture session."},
    {"method": "POST", "path": "/target/action/", "desc": "Start/stop/restart a capture session."},
    {"method": "POST", "path": "/target/action/bulk/", "desc": "Bulk control capture sessions by protocol."},
    {"method": "GET", "path": "/ports/", "desc": "List captured packets."},
    {"method": "GET", "path": "/ports/tcp/", "desc": "List captured TCP packets."},
    {"method": "GET", "path": "/ports/udp/", "desc": "List captured UDP packets."},
    {"method": "GET", "path": "/ports/icmp/", "desc": "List captured ICMP packets."},
    {"method": "GET", "path": "/ports/sctp/", "desc": "List captured SCTP packets."},
    {"method": "GET", "path": "/banners/", "desc": "List responses."},
    {"method": "GET", "path": "/tags/", "desc": "List packet tags."},
    {"method": "GET", "path": "/api/dashboard/", "desc": "Dashboard snapshot."},
    {"method": "GET", "path": "/api/charts/analytics", "desc": "Analytics snapshot for charts."},
    {"method": "GET", "path": "/api/map/scan", "desc": "Network map snapshot."},
    {"method": "GET", "path": "/api/endpoints/", "desc": "Endpoint catalog."},
    {"method": "GET", "path": AUTH_SESSION_PATH, "desc": "Session auth requirements and validation."},
    {"method": "GET", "path": "/api/ip/domains/", "desc": "Domain discovery for an IP."},
    {"method": "GET", "path": "/api/ip/ttl-path/", "desc": "TTL path estimate for an IP."},
    {"method": "GET", "path": "/api/ip/intel/", "desc": "Combined host intel."},
    {"method": "GET", "path": "/api/soc/analysis/", "desc": "Iterative SOC triage analysis."},
    {"method": "GET", "path": "/api/runtime/", "desc": "Runtime mode and engine snapshot."},
    {"method": "POST", "path": "/api/runtime/", "desc": "Start/stop engines and update the sniffer interface. Sniffer and honeypot are independent: {\"engines\": {\"sniffer\": true, \"honeypot\": true}} runs both, {\"engine\": \"honeypot\", \"action\": \"stop\"} stops one."},
    {"method": "GET", "path": "/api/settings/location", "desc": "Declared sensor site location used to plot private/loopback hosts."},
    {"method": "POST", "path": "/api/settings/location", "desc": "Set or clear the declared sensor site location."},
    {"method": "GET", "path": "/api/detection/scopes", "desc": "IP scopes muted for detection (capture is unaffected)."},
    {"method": "POST", "path": "/api/detection/scopes", "desc": "Mute detection for loopback / private / public traffic."},
    {"method": "GET", "path": "/api/honeypot/listeners/", "desc": "List service listeners (builtin + custom) and their enabled/running state."},
    {"method": "POST", "path": "/api/honeypot/listeners/", "desc": "Create a new service listener. Listeners can only be created or toggled, never edited or deleted."},
    {"method": "POST", "path": "/api/honeypot/listeners/toggle", "desc": "Enable/disable a service listener (builtin or custom) without removing it."},
    {"method": "GET", "path": "/api/ws/clients", "desc": "Connected WebSocket clients."},
    {"method": "POST", "path": "/api/ws/broadcast", "desc": "Broadcast a WebSocket payload."},
    {"method": "POST", "path": "/api/ws/ping", "desc": "Ping all WebSocket clients."},
    {"method": "POST", "path": "/api/ws/close", "desc": "Close one or all WebSocket clients."},
    {"method": "POST", "path": "/api/app/shutdown", "desc": "Request a graceful shutdown of the local Sniff4Hound process."},
    {"method": "GET", "path": "/api/chat/messages", "desc": "Chat message log."},
    {"method": "POST", "path": "/api/chat/messages", "desc": "Post a message to the operator chat."},
    {"method": "POST", "path": "/api/chat/clear", "desc": "Clear chat message log."},
    {"method": "GET", "path": "/api/catalog/file/banner-rules", "desc": "File catalog rulesets."},
    {"method": "POST", "path": "/api/catalog/file/banner-rules", "desc": "Store file catalog rulesets."},
    {"method": "GET", "path": "/api/catalog/file/banner-requests", "desc": "File catalog packet signatures."},
    {"method": "POST", "path": "/api/catalog/file/banner-requests", "desc": "Store file catalog packet signatures."},
    {"method": "GET", "path": "/api/catalog/file/ip-presets", "desc": "File catalog capture presets."},
    {"method": "POST", "path": "/api/catalog/file/ip-presets", "desc": "Store file catalog capture presets."},
    {"method": "GET", "path": "/api/catalog/banner-rules/", "desc": "List rulesets."},
    {"method": "POST", "path": "/api/catalog/banner-rules/", "desc": "Create ruleset."},
    {"method": "PUT", "path": "/api/catalog/banner-rules/", "desc": "Update ruleset."},
    {"method": "DELETE", "path": "/api/catalog/banner-rules/", "desc": "Delete ruleset."},
    {"method": "GET", "path": "/api/catalog/banner-requests/", "desc": "List packet signature templates."},
    {"method": "POST", "path": "/api/catalog/banner-requests/", "desc": "Create packet signature template."},
    {"method": "PUT", "path": "/api/catalog/banner-requests/", "desc": "Update packet signature template."},
    {"method": "DELETE", "path": "/api/catalog/banner-requests/", "desc": "Delete packet signature template."},
    {"method": "GET", "path": "/api/catalog/ip-presets/", "desc": "List capture presets."},
    {"method": "POST", "path": "/api/catalog/ip-presets/", "desc": "Create capture preset."},
    {"method": "PUT", "path": "/api/catalog/ip-presets/", "desc": "Update capture preset."},
    {"method": "DELETE", "path": "/api/catalog/ip-presets/", "desc": "Delete capture preset."},
    {"method": "GET", "path": "/api/monitors/", "desc": "List detection monitors."},
    {"method": "POST", "path": "/api/monitors/", "desc": "Create a custom monitor."},
    {"method": "PUT", "path": "/api/monitors/", "desc": "Update a custom monitor."},
    {"method": "DELETE", "path": "/api/monitors/", "desc": "Delete a custom monitor."},
    {"method": "POST", "path": "/api/monitors/toggle", "desc": "Enable/disable any monitor, including builtins, without editing or deleting it."},
    {"method": "GET", "path": "/api/monitors/config", "desc": "Read the monitor persistence-filter toggle."},
    {"method": "POST", "path": "/api/monitors/config", "desc": "Toggle whether only detected traffic is persisted."},
    {"method": "GET", "path": "/api/blacklist/", "desc": "List blacklist entries (optionally filtered by ?category=ip|domain|path)."},
    {"method": "POST", "path": "/api/blacklist/", "desc": "Create a blacklist entry (category, match_type, value, label)."},
    {"method": "DELETE", "path": "/api/blacklist/", "desc": "Delete a blacklist entry."},
    {"method": "POST", "path": "/api/blacklist/toggle", "desc": "Enable/disable a blacklist entry without deleting it."},
    {"method": "GET", "path": "/api/domains/", "desc": "Searchable catalog of domains seen in DNS/HTTP/TLS traffic."},
    {"method": "GET", "path": "/api/paths/", "desc": "Searchable catalog of HTTP request paths."},
    {"method": "GET", "path": "/api/intel/ips/", "desc": "Searchable catalog of IPs seen in stored traffic. ?scope=public|private|local|multicast|reserved|unknown (comma separated) filters by address scope; the full vocabulary and per-scope counts come back in the X-Scope-Counts header."},
    {"method": "GET", "path": "/api/monitors/packets/", "desc": "Packets that matched a given monitor."},
    {"method": "GET", "path": "/api/alerts/recent", "desc": "Lean recent monitor-hit feed (src/dst IP + severity only, no packet bodies)."},
    {"method": "POST", "path": "/api/data/clear/", "desc": "Clear stored data for a scope: 'monitors', 'honeypot', 'all' (detection history), or 'everything' (also flows/domains/paths/sessions). Never deletes monitor/listener definitions."},
    {"method": "GET", "path": "/api/export/", "desc": "Available IOC export datasets, formats and column sets."},
    {"method": "GET", "path": "/api/export/alerts", "desc": "Monitor hits as indicators (rule, severity, 5-tuple, first/last seen). ?format=csv|json"},
    {"method": "GET", "path": "/api/export/endpoints", "desc": "Observed IPs with hit counts, worst severity and the rules that flagged them. ?format=csv|json"},
    {"method": "GET", "path": "/api/export/flows", "desc": "Conversations (5-tuple) with packet/byte counts and observed banners. ?format=csv|json"},
    {"method": "GET", "path": "/api/export/domains", "desc": "Domains seen in DNS/TLS-SNI/HTTP traffic, with address and port. ?format=csv|json"},
]

_STATIC_ROUTES_REGISTERED = False
_CHAT_MESSAGES: list[dict[str, Any]] = []


def _json_response(payload, status=200):
    return Response.json(payload, status=status)


def _text_response(text, status=200):
    return Response.text(text, status=status)


def _html_response(text, status=200):
    return Response.html(text, status=status)


class _InvalidJsonBody(ValueError):
    pass


class _NotFound(ValueError):
    """A request that named something that doesn't exist (an unknown
    session/listener/response id). Subclasses ValueError so every existing
    `raise ValueError(...)` call site keeps working, but the API guard maps
    it to 404 rather than 400."""


def _read_json_body(request):
    raw = request.text() if request is not None else ""
    stripped = str(raw or "").strip()
    if not stripped:
        return {}
    try:
        data = json.loads(stripped)
    except Exception as exc:
        raise _InvalidJsonBody("Request body is not valid JSON") from exc
    if isinstance(data, dict):
        return data
    raise _InvalidJsonBody("Request body must be a JSON object")


def _normalize_limit(value, default=200, maximum=None):
    """`limit` for the paginated list endpoints.

    Absent -> the endpoint's own default. Unparseable or below 1 -> 400,
    instead of the old silent fallback to the default (an export script
    with a typo in the parameter used to walk away with a subset of the
    data believing it had all of it). Above the ceiling -> clamped to
    settings.API_MAX_LIMIT, and the response's X-Truncated header says so.
    """
    ceiling = int(API_MAX_LIMIT if maximum is None else maximum)
    raw = str(value if value is not None else "").strip()
    if not raw:
        return int(default)
    try:
        number = int(raw)
    except Exception:
        raise ValueError(f"limit must be an integer between 1 and {ceiling}")
    if number < 1:
        raise ValueError(f"limit must be an integer between 1 and {ceiling}")
    return min(number, ceiling)


def _normalize_offset(value):
    raw = str(value if value is not None else "").strip()
    if not raw:
        return 0
    try:
        number = int(raw)
    except Exception:
        raise ValueError("offset must be an integer of 0 or more")
    if number < 0:
        raise ValueError("offset must be an integer of 0 or more")
    return min(number, 100_000_000)


def _normalize_since(request):
    """Optional relative time window shared by every list endpoint:
    ?since=15m|1h|6h|24h|7d. Absent means no temporal filter."""
    return parse_since_window(request.query.get("since") if request is not None else "")


def _listing_response(rows, *, total, limit, offset, extra_headers=None):
    """Bare-array listings keep their exact JSON shape - clients already
    index into them - so the pagination facts ride along as headers
    instead. `total_available`/`returned`/`truncated` are the same three
    values the object-shaped endpoints get as keys.

    `extra_headers` is for per-endpoint metadata that would otherwise have to
    become a second request or break the array shape (the IP catalog's
    per-scope breakdown, for instance). Anything passed there is added to
    Access-Control-Expose-Headers too, otherwise a browser cannot read it.
    """
    rows = list(rows)
    returned = len(rows)
    total = max(int(total), offset + returned)
    headers = {
        "X-Total-Available": str(total),
        "X-Returned": str(returned),
        "X-Truncated": "true" if (int(offset) + returned) < total else "false",
    }
    headers.update(extra_headers or {})
    headers["Access-Control-Expose-Headers"] = ", ".join(headers)
    return Response.json(rows, headers=headers)


def _json_safe(value):
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes_to_hex_preview(bytes(value))
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(item) for item in value]
    return str(value)


def _json_text(payload) -> str:
    return json.dumps(_json_safe(payload), ensure_ascii=False)


def _decode_json_items(value, default=None):
    fallback = [] if default is None else default
    if value is None:
        return fallback
    if isinstance(value, (list, tuple)):
        return list(value)
    if isinstance(value, dict):
        return value
    text = str(value or "").strip()
    if not text:
        return fallback
    try:
        parsed = json.loads(text)
    except Exception:
        return fallback
    if isinstance(parsed, (list, tuple)):
        return list(parsed)
    if isinstance(parsed, dict):
        return parsed
    return fallback


def _request_header(request, *names: str) -> str | None:
    if request is None:
        return None
    headers = getattr(request, "headers", {}) or {}
    for name in names:
        value = headers.get(name)
        if value:
            return str(value)
        lower = str(name or "").lower()
        value = headers.get(lower)
        if value:
            return str(value)
    return None


def _extract_request_query_token(request) -> str | None:
    if request is None:
        return None
    query = getattr(request, "query", {}) or {}
    for key in ("security_code", "access_token", "token", "auth"):
        value = query.get(key)
        if value:
            return str(value).strip() or None
    return None


def _extract_request_token(request, *, allow_query: bool = False) -> str | None:
    auth_header = _request_header(request, "Authorization", "authorization")
    token = extract_token_from_header(auth_header)
    if token:
        return token

    direct_token = _request_header(
        request,
        "X-Security-Code",
        "x-security-code",
        "X-Access-Token",
        "x-access-token",
    )
    if direct_token:
        return str(direct_token).strip() or None

    if allow_query:
        return _extract_request_query_token(request)
    return None


def _authenticate_request(request, *, allow_query: bool = False) -> tuple[bool, dict[str, Any] | None]:
    return authenticate_request(_extract_request_token(request, allow_query=allow_query))


def _client_address(request) -> str:
    """Source address of a request, for the auth rate limiter and the
    security log. Deliberately the transport peer only - an X-Forwarded-For
    header is attacker-controlled, and keying a lockout on it would let a
    guessing loop reset its own counter on every attempt."""
    if request is None:
        return "unknown"
    client = getattr(request, "client", None)
    if isinstance(client, (tuple, list)) and client:
        return str(client[0] or "unknown")
    return str(client or "unknown") or "unknown"


def _unauthorized_response(message: str = "Security code required") -> Response:
    return Response.json(
        {
            "status": "error",
            "code": "auth_required",
            "message": message,
            "authenticated": False,
            "require_auth": bool(REQUIRE_AUTH),
        },
        status=401,
        headers={"WWW-Authenticate": 'Bearer realm="Sniff4Hound"'},
    )


def _rate_limited_response(retry_after: float) -> Response:
    seconds = max(1, int(retry_after + 0.999))
    return Response.json(
        {
            "status": "error",
            "code": "auth_rate_limited",
            "message": f"Too many failed authentication attempts. Retry in {seconds}s.",
            "authenticated": False,
            "require_auth": bool(REQUIRE_AUTH),
            "retry_after": seconds,
        },
        status=429,
        headers={
            "Retry-After": str(seconds),
            "WWW-Authenticate": 'Bearer realm="Sniff4Hound"',
        },
    )


def _guard_request_auth(request, *, allow_query: bool = False) -> Response | None:
    """Shared auth gate for the API routes and the WebSocket handshake.

    Returns None when the caller is authenticated (or auth is disabled), and
    the response to send otherwise. Every rejection is both counted against
    the source address (incremental backoff, see auth.AuthRateLimiter) and
    written to the security log - before this, a 401 left no trace at all,
    so a brute-force run against the security code was invisible.
    """
    if not REQUIRE_AUTH:
        return None
    client = _client_address(request)
    allowed, retry_after = RATE_LIMITER.check(client)
    if not allowed:
        access_log.log_auth_failure(
            request,
            client=client,
            reason="rate_limited",
            status=429,
            retry_after=retry_after,
        )
        return _rate_limited_response(retry_after)

    is_authenticated, _user_info = _authenticate_request(request, allow_query=allow_query)
    if is_authenticated:
        RATE_LIMITER.register_success(client)
        return None

    lockout = RATE_LIMITER.register_failure(client)
    access_log.log_auth_failure(
        request,
        client=client,
        reason="invalid_token",
        status=401,
        retry_after=lockout,
    )
    return _unauthorized_response("Invalid or missing security code")


def append_chat_message(
    content: str,
    *,
    author: str = "operator",
    kind: str = "note",
    meta: dict[str, Any] | None = None,
    broadcast: bool = False,
) -> dict[str, Any]:
    message = {
        "id": f"chat-{len(_CHAT_MESSAGES) + 1}",
        "author": str(author or "operator"),
        "kind": str(kind or "note"),
        "content": str(content or "").strip(),
        "meta": dict(meta or {}),
        "created_at": utc_now(),
    }
    if not message["content"]:
        return message

    _CHAT_MESSAGES.append(message)
    if len(_CHAT_MESSAGES) > 500:
        del _CHAT_MESSAGES[:-500]
    if broadcast:
        hub.broadcast({"type": "chat_message", "message": message, "generated_at": message["created_at"]})
    # Echo anything that did not come from the terminal itself onto the
    # console, otherwise the chat is one-way: the operator types into
    # `sniff4hound>` and never sees the dashboard answer.
    if message["author"] != "operator":
        try:
            from .terminal import emit

            emit(f"[chat] {message['author']}: {message['content']}")
        except Exception:
            pass
    return message


def _packet_row_to_port(packet: dict) -> dict:
    created = packet.get("created_at") or utc_now()
    updated = packet.get("updated_at") or created
    payload_text = str(packet.get("payload_text") or "").strip()
    banner = str(packet.get("banner_text") or packet.get("summary") or payload_text).strip()
    tags = _decode_json_items(packet.get("tags_json") or [], default=[])
    rule_hits = _decode_json_items(packet.get("rule_hits_json") or [], default=[])
    tags_text = ", ".join(
        str(tag.get("value") or tag.get("key") or "").strip()
        for tag in tags
        if isinstance(tag, dict)
    )
    return {
        "id": packet.get("id"),
        "ip": packet.get("dst_ip") or packet.get("src_ip") or "",
        "port": packet.get("dst_port") or packet.get("src_port") or 0,
        "proto": packet.get("proto") or "unknown",
        "state": packet.get("state") or "open",
        "scan_state": packet.get("scan_state") or "active",
        "progress": 100.0 if banner else 0.0,
        "banner": banner,
        "tags_text": tags_text,
        "favicon_id": packet.get("id") or 0,
        "created_at": created,
        "updated_at": updated,
        "length": packet.get("length") or 0,
        "payload_len": packet.get("payload_len") or 0,
        "summary": packet.get("summary") or "",
        "session_id": packet.get("session_id") or 0,
        "flow_key": packet.get("flow_key") or "",
        "interface": packet.get("interface") or "",
        "direction": packet.get("direction") or "unknown",
        "eth_src": packet.get("eth_src") or "",
        "eth_dst": packet.get("eth_dst") or "",
        "ip_version": packet.get("ip_version") or 0,
        "src_ip": packet.get("src_ip") or "",
        "dst_ip": packet.get("dst_ip") or "",
        "src_port": packet.get("src_port") or 0,
        "dst_port": packet.get("dst_port") or 0,
        "ttl": packet.get("ttl") or 0,
        "hop_limit": packet.get("hop_limit") or 0,
        "tcp_flags": packet.get("tcp_flags") or "",
        "icmp_type": packet.get("icmp_type") or 0,
        "icmp_code": packet.get("icmp_code") or 0,
        "arp_opcode": packet.get("arp_opcode") or 0,
        "payload_text": payload_text,
        "payload_hex": packet.get("payload_hex") or "",
        "banner_text": banner,
        "tags": tags,
        "rule_hits": rule_hits,
    }


def _packet_row_to_banner(packet: dict) -> dict:
    created = packet.get("created_at") or utc_now()
    updated = packet.get("updated_at") or created
    tags = _decode_json_items(packet.get("tags_json") or [], default=[])
    return {
        "id": packet.get("id"),
        "ip": packet.get("ip") or packet.get("dst_ip") or packet.get("src_ip") or "",
        "port": packet.get("port") or packet.get("dst_port") or packet.get("src_port") or 0,
        "proto": packet.get("proto") or "unknown",
        "response_plain": packet.get("response_plain") or "",
        "response_size": packet.get("response_size") or len(str(packet.get("response_plain") or "").encode("utf-8", errors="ignore")),
        "scan_state": packet.get("scan_state") or "active",
        "port_id": packet.get("port_id") or packet.get("packet_id") or 0,
        "favicon_id": packet.get("favicon_id") or packet.get("id") or 0,
        "state": packet.get("state") or "open",
        "created_at": created,
        "updated_at": updated,
        "packet_id": packet.get("packet_id") or packet.get("port_id") or 0,
        "session_id": packet.get("session_id") or 0,
        "flow_key": packet.get("flow_key") or "",
        "interface": packet.get("interface") or "",
        "direction": packet.get("direction") or "unknown",
        "src_ip": packet.get("src_ip") or "",
        "dst_ip": packet.get("dst_ip") or "",
        "src_port": packet.get("src_port") or 0,
        "dst_port": packet.get("dst_port") or 0,
        "summary": packet.get("summary") or "",
        "tags": tags,
    }


def _packet_row_to_tag(packet: dict) -> dict:
    return {
        "id": packet.get("id"),
        "ip": packet.get("ip") or packet.get("dst_ip") or packet.get("src_ip") or "",
        "port": packet.get("port") or packet.get("dst_port") or packet.get("src_port") or 0,
        "proto": packet.get("proto") or "unknown",
        "key": packet.get("key") or "",
        "value": packet.get("value") or "",
        "created_at": packet.get("created_at") or utc_now(),
        "updated_at": packet.get("updated_at") or packet.get("created_at") or utc_now(),
    }


def _session_row(row: dict) -> dict:
    return {
        "id": row.get("id"),
        "network": row.get("network") or "",
        "type": row.get("type") or "",
        "proto": row.get("proto") or "",
        "port_mode": row.get("port_mode") or "preset",
        "port_start": row.get("port_start") or 0,
        "port_end": row.get("port_end") or 0,
        "status": row.get("status") or "stopped",
        "timesleep": row.get("timesleep") or 0.0,
        "progress": row.get("progress") or 0.0,
        "interface": row.get("interface") or "",
        "filter_text": row.get("filter_text") or "",
        "created_at": row.get("created_at") or utc_now(),
        "updated_at": row.get("updated_at") or row.get("created_at") or utc_now(),
    }


def _ruleset_row(row: dict) -> dict:
    return {
        "id": row.get("id"),
        "name": row.get("name") or "",
        "description": row.get("description") or "",
        "enabled": bool(row.get("enabled")),
        "priority": row.get("priority") or 0,
        "source": row.get("source") or "custom",
        "match": row.get("match") or {},
        "action": row.get("action") or {},
        "created_at": row.get("created_at") or utc_now(),
        "updated_at": row.get("updated_at") or row.get("created_at") or utc_now(),
    }


def _monitor_row(row: dict, match_counts: dict | None = None) -> dict:
    counts = match_counts or {}
    return {
        "id": row.get("id"),
        "name": row.get("name") or "",
        "description": row.get("description") or "",
        "enabled": bool(row.get("enabled")),
        "priority": row.get("priority") or 0,
        "source": row.get("source") or "custom",
        "mode": row.get("mode") or "rule",
        "match": row.get("match") or {},
        "action": row.get("action") or {},
        "match_count": int(counts.get(str(row.get("id")), 0)),
        "created_at": row.get("created_at") or utc_now(),
        "updated_at": row.get("updated_at") or row.get("created_at") or utc_now(),
    }


def _packets_to_grouped_proto(limit=250, search=""):
    packets = store.list_packets(limit=limit, search=search)
    grouped: dict[str, list[dict]] = {}
    for packet in packets:
        row = _packet_row_to_port(packet)
        grouped.setdefault(normalize_protocol_name(row["proto"]), []).append(row)
    return grouped


def _capture_session_action(row: dict, action: str, *, clean_results=False):
    action = str(action or "").strip().lower()
    session_id = safe_int(row.get("id"), 0)
    if action == "start":
        store.set_session_status(session_id, "active")
        return store.get_session(session_id)
    if action == "stop":
        store.set_session_status(session_id, "stopped")
        return store.get_session(session_id)
    if action == "restart":
        store.set_session_status(session_id, "restarting", progress=0.0)
        store.set_session_status(session_id, "active", progress=0.0)
        if clean_results:
            _clear_packets_for_session(session_id)
        return store.get_session(session_id)
    if action == "delete":
        if clean_results:
            _clear_packets_for_session(session_id)
        store.delete_session(session_id)
        return None
    raise ValueError(f"Unsupported action: {action}")


def _clear_packets_for_session(session_id: int):
    with store._lock:
        rows = store._conn.execute(
            "SELECT id, flow_key FROM packets WHERE session_id = ?",
            (int(session_id),),
        ).fetchall()
        packet_ids = [int(row["id"]) for row in rows if row["id"] is not None]
        flow_keys = [str(row["flow_key"] or "").strip() for row in rows if row["flow_key"]]
        if packet_ids:
            placeholders = ",".join("?" for _ in packet_ids)
            store._conn.execute(
                f"DELETE FROM payloads WHERE packet_id IN ({placeholders})",
                tuple(packet_ids),
            )
            store._conn.execute(
                f"DELETE FROM tags WHERE packet_id IN ({placeholders})",
                tuple(packet_ids),
            )
        if flow_keys:
            placeholders = ",".join("?" for _ in flow_keys)
            store._conn.execute(
                f"DELETE FROM flows WHERE flow_key IN ({placeholders})",
                tuple(flow_keys),
            )
        store._conn.execute("DELETE FROM packets WHERE session_id = ?", (int(session_id),))
        store._conn.commit()


def _packet_action(packet_row: dict, action: str, *, clean_results=False):
    packet_id = safe_int(packet_row.get("id"), 0)
    action = str(action or "").strip().lower()
    if action == "start":
        with store._lock:
            store._conn.execute("UPDATE packets SET state = 'open', scan_state = 'active', updated_at = ? WHERE id = ?", (utc_now(), packet_id))
            store._conn.commit()
        return store.get_packet(packet_id)
    if action == "stop":
        with store._lock:
            store._conn.execute("UPDATE packets SET state = 'filtered', scan_state = 'stopped', updated_at = ? WHERE id = ?", (utc_now(), packet_id))
            store._conn.commit()
        return store.get_packet(packet_id)
    if action == "restart":
        with store._lock:
            store._conn.execute("UPDATE packets SET state = 'open', scan_state = 'restarting', updated_at = ? WHERE id = ?", (utc_now(), packet_id))
            store._conn.execute("UPDATE packets SET scan_state = 'active', updated_at = ? WHERE id = ?", (utc_now(), packet_id))
            if clean_results:
                store._conn.execute("DELETE FROM payloads WHERE packet_id = ?", (packet_id,))
                store._conn.execute("DELETE FROM tags WHERE packet_id = ?", (packet_id,))
            store._conn.commit()
        return store.get_packet(packet_id)
    if action == "delete":
        with store._lock:
            store._conn.execute("DELETE FROM packets WHERE id = ?", (packet_id,))
            if clean_results:
                store._conn.execute("DELETE FROM payloads WHERE packet_id = ?", (packet_id,))
                store._conn.execute("DELETE FROM tags WHERE packet_id = ?", (packet_id,))
            store._conn.commit()
        return None
    raise ValueError(f"Unsupported action: {action}")


def _banner_action(banner_row: dict, action: str, *, clean_results=False):
    banner_id = safe_int(banner_row.get("id"), 0)
    action = str(action or "").strip().lower()
    if action == "start":
        with store._lock:
            store._conn.execute("UPDATE payloads SET state = 'open', scan_state = 'active', updated_at = ? WHERE id = ?", (utc_now(), banner_id))
            store._conn.commit()
        return store.get_payload(banner_id)
    if action == "stop":
        with store._lock:
            store._conn.execute("UPDATE payloads SET state = 'filtered', scan_state = 'stopped', updated_at = ? WHERE id = ?", (utc_now(), banner_id))
            store._conn.commit()
        return store.get_payload(banner_id)
    if action == "restart":
        with store._lock:
            store._conn.execute("UPDATE payloads SET state = 'open', scan_state = 'restarting', updated_at = ? WHERE id = ?", (utc_now(), banner_id))
            store._conn.execute("UPDATE payloads SET scan_state = 'active', updated_at = ? WHERE id = ?", (utc_now(), banner_id))
            if clean_results:
                store._conn.execute("DELETE FROM tags WHERE packet_id = ?", (safe_int(banner_row.get("port_id"), 0),))
            store._conn.commit()
        return store.get_payload(banner_id)
    if action == "delete":
        with store._lock:
            store._conn.execute("DELETE FROM payloads WHERE id = ?", (banner_id,))
            store._conn.commit()
        return None
    raise ValueError(f"Unsupported action: {action}")


def _static_file_response(path: Path):
    if not path.exists() or not path.is_file():
        return None
    content_type = mimetypes.guess_type(str(path))[0] or "application/octet-stream"
    return Response(body=path.read_bytes(), headers={"Content-Type": content_type})


def _frontend_index_html() -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{DEFAULT_DOCS_TITLE}</title>
  <style>
    :root {{
      color-scheme: dark;
      --bg: #0b1120;
      --panel: rgba(9, 16, 30, 0.94);
      --line: rgba(117, 171, 217, 0.22);
      --ink: #eef6ff;
      --muted: #9ab0c9;
      --brand: #4cc9f0;
      --accent: #06d6a0;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      min-height: 100vh;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background:
        radial-gradient(circle at top left, rgba(76, 201, 240, 0.14), transparent 26%),
        radial-gradient(circle at right bottom, rgba(6, 214, 160, 0.12), transparent 24%),
        linear-gradient(180deg, #08101f, #0b1120 52%, #060a14);
      color: var(--ink);
    }}
    .wrap {{
      max-width: 1120px;
      margin: 0 auto;
      padding: 32px 18px 56px;
    }}
    .hero {{
      border: 1px solid var(--line);
      border-radius: 28px;
      background: linear-gradient(135deg, rgba(13, 23, 40, 0.98), rgba(10, 16, 28, 0.9));
      box-shadow: 0 20px 60px rgba(0,0,0,.28);
      padding: 28px;
    }}
    h1 {{
      margin: 0 0 12px;
      font-size: clamp(2rem, 4vw, 3.6rem);
      letter-spacing: -0.04em;
      line-height: 1;
    }}
    p {{
      color: var(--muted);
      line-height: 1.65;
      margin: 0 0 16px;
      max-width: 75ch;
    }}
    .chips {{ display: flex; flex-wrap: wrap; gap: 10px; margin-top: 18px; }}
    .chip {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 10px 14px;
      border-radius: 999px;
      border: 1px solid var(--line);
      background: rgba(255,255,255,.03);
      color: var(--ink);
      text-decoration: none;
    }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 14px;
      margin-top: 18px;
    }}
    .card {{
      border: 1px solid var(--line);
      background: var(--panel);
      border-radius: 22px;
      padding: 18px;
    }}
    .k {{ color: var(--muted); font-size: .78rem; text-transform: uppercase; letter-spacing: .12em; }}
    .v {{ font-size: 1.5rem; font-weight: 800; margin-top: 6px; letter-spacing: -.03em; }}
    code {{
      background: rgba(255,255,255,.05);
      padding: 0 .35em;
      border-radius: .35rem;
    }}
    @media (max-width: 780px) {{
      .grid {{ grid-template-columns: 1fr; }}
      .hero {{ padding: 20px; }}
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <section class="hero">
      <h1>{DEFAULT_DOCS_TITLE}</h1>
      <p>{DEFAULT_DOCS_DESCRIPTION}</p>
      <div class="chips">
        <a class="chip" href="/docs">Runtime docs</a>
        <a class="chip" href="/api/dashboard/">API snapshot</a>
        <a class="chip" href="/api/endpoints/">Endpoint catalog</a>
        <a class="chip" href="/protocols/">Protocols</a>
      </div>
      <div class="grid">
        <div class="card"><div class="k">Database</div><div class="v"><code>{DB_PATH}</code></div></div>
        <div class="card"><div class="k">Capture</div><div class="v">live</div></div>
        <div class="card"><div class="k">Version</div><div class="v">{__version__}</div></div>
      </div>
    </section>
  </div>
</body>
</html>"""


def _attach_runtime_docs():
    app.enable_docs(path="/docs", json_path="/docs.json", title=DEFAULT_DOCS_TITLE, description=DEFAULT_DOCS_DESCRIPTION)


def _spa_route_paths() -> tuple[str, ...]:
    """SPA_ROUTES plus a trailing-slash twin for each - "/soc" served the
    app while "/soc/" 404'd, which is not a distinction anyone pasting a
    link into a ticket is going to make. "/api" is left alone: it is a
    prefix of the real API routes and must not grow an "/api/" view."""
    paths = []
    for route_path in SPA_ROUTES:
        paths.append(route_path)
        if route_path != "/api" and not route_path.endswith("/"):
            paths.append(f"{route_path}/")
    return tuple(paths)


def _register_static_frontend():
    global _STATIC_ROUTES_REGISTERED
    if _STATIC_ROUTES_REGISTERED:
        return
    _STATIC_ROUTES_REGISTERED = True
    if FRONTEND_DIST_DIR.exists():
        for file_path in FRONTEND_DIST_DIR.rglob("*"):
            if not file_path.is_file():
                continue
            route_path = "/" + file_path.relative_to(FRONTEND_DIST_DIR).as_posix()
            if route_path.endswith("/index.html"):
                route_path = route_path[:-11] or "/"
            if route_path == "/":
                continue

            @app.view(route_path, methods=("GET",))
            def _serve_static(_request, _file_path=file_path):
                response = _static_file_response(_file_path)
                return response or Response.text("Not Found", status=404)

        for route_path in _spa_route_paths():
            @app.view(route_path, methods=("GET",))
            def _serve_spa(_request):
                index_path = FRONTEND_DIST_DIR / "index.html"
                response = _static_file_response(index_path)
                if response:
                    return response
                return Response.html(_frontend_index_html())
    else:
        @app.view("/", methods=("GET",))
        def _root(_request):
            return Response.html(_frontend_index_html())


def _make_ruleset_payloads(filename: str):
    rows = store.read_catalog_file(filename)
    return [dict(item) for item in rows]


def _write_ruleset_payloads(filename: str, rows: list[dict]):
    store.write_catalog_file(filename, rows)
    return rows


def _catalog_endpoint(name: str, filename: str):
    if name == "rules":
        rows = [_ruleset_row(row) for row in store.list_rulesets()]
        return rows
    return _make_ruleset_payloads(filename)


@app.view("/")
def root(_request):
    if FRONTEND_DIST_DIR.exists():
        response = _static_file_response(FRONTEND_DIST_DIR / "index.html")
        if response:
            return response
    return Response.html(_frontend_index_html())


@app.view("/favicon.ico")
def favicon(_request):
    for path in (
        FRONTEND_DIST_DIR / "favicon.ico",
        FRONTEND_PUBLIC_DIR / "favicon.ico",
    ):
        response = _static_file_response(path)
        if response:
            return response
    return response or Response.text("", status=204)


@app.api("/protocols/", methods=("GET",))
def protocols(_request):
    return store.list_protocols()


@app.api("/api/protocols/snapshot/", methods=("GET",))
def protocol_snapshot_api(request):
    """One protocol slice - counters, per-protocol facets, timeline and rows.

    Replaces the five calls the Protocols view used to make per refresh
    (/protocols/, /api/charts/analytics, /banners/, /ports/, /tags/). The
    facets are chosen per protocol and aggregated over the whole filtered
    set, so ARP reports who-has/is-at rather than the port-scan "open vs
    filtered" counters every slice used to show.
    """
    proto = normalize_protocol_name(request.query.get("proto") or "")
    return store.protocol_snapshot(
        proto="" if proto == "all" else proto,
        mode=str(request.query.get("mode") or "").strip().lower(),
        interface=str(request.query.get("interface") or "").strip(),
        search=str(request.query.get("search") or "").strip(),
        since=_normalize_since(request),
        limit=_normalize_limit(request.query.get("limit"), default=250),
    )


@app.api("/count/targets/", methods=("GET",))
def count_targets(_request):
    return {"count_targets": store.list_count("sessions")}


@app.api("/count/ports/", methods=("GET",))
def count_ports(_request):
    return {"count_ports": store.list_count("packets")}


@app.api("/count/ports/tcp/", methods=("GET",))
def count_ports_tcp(_request):
    return {"count_ports_tcp": store._count_where("packets", "LOWER(proto) = 'tcp'")}


@app.api("/count/ports/udp/", methods=("GET",))
def count_ports_udp(_request):
    return {"count_ports_udp": store._count_where("packets", "LOWER(proto) = 'udp'")}


@app.api("/count/ports/icmp/", methods=("GET",))
def count_ports_icmp(_request):
    return {"count_ports_icmp": store._count_where("packets", "LOWER(proto) IN ('icmp','icmpv6')")}


@app.api("/count/ports/sctp/", methods=("GET",))
def count_ports_sctp(_request):
    return {"count_ports_sctp": store._count_where("packets", "LOWER(proto) = 'sctp'")}


@app.api("/count/banners/", methods=("GET",))
def count_banners(_request):
    return {"count_banners": store.list_count("payloads")}


@app.api("/targets/", methods=("GET",))
def list_targets(_request):
    search = str(_request.query.get("search") or "").strip()
    proto = str(_request.query.get("proto") or "").strip()
    limit = _normalize_limit(_request.query.get("limit"), default=200)
    offset = _normalize_offset(_request.query.get("offset"))
    since = _normalize_since(_request)
    rows = store.list_sessions(limit=limit, offset=offset, search=search, proto=proto, since=since)
    return _listing_response(
        [_session_row(row) for row in rows],
        total=store.count_sessions(search=search, proto=proto, since=since),
        limit=limit,
        offset=offset,
    )


@app.api("/target/", methods=("POST", "PUT", "DELETE"))
def target_crud(request):
    payload = _read_json_body(request)
    method = request.method.upper()
    if method == "POST":
        row = store.create_session(payload)
        return _session_row(row)
    session_id = safe_int(payload.get("id"), 0)
    if not session_id:
        raise ValueError("id is required")
    if method == "PUT":
        row = store.update_session(session_id, payload)
        return _session_row(row) if row else {}
    if method == "DELETE":
        if payload.get("clean_results"):
            _clear_packets_for_session(session_id)
        store.delete_session(session_id)
        return {"status": "ok"}
    raise ValueError("Unsupported method")


@app.api("/target/action/", methods=("POST",))
def target_action(request):
    payload = _read_json_body(request)
    session_id = safe_int(payload.get("id"), 0)
    action = str(payload.get("action") or "").strip().lower()
    clean_results = bool(payload.get("clean_results"))
    row = store.get_session(session_id)
    if not row:
        raise _NotFound("Unknown session id")
    updated = _capture_session_action(row, action, clean_results=clean_results)
    return _session_row(updated) if updated else {"status": "ok"}


@app.api("/target/action/bulk/", methods=("POST",))
def target_action_bulk(request):
    payload = _read_json_body(request)
    action = str(payload.get("action") or "").strip().lower()
    proto = normalize_protocol_name(payload.get("proto"))
    clean_results = bool(payload.get("clean_results"))
    rows = store.list_sessions(limit=1000, proto=proto)
    for row in rows:
        _capture_session_action(row, action, clean_results=clean_results)
    return {"status": "ok", "count": len(rows), "action": action, "proto": proto}


@app.api("/ports/", methods=("GET", "DELETE"))
def ports_all(request):
    if request.method.upper() == "DELETE":
        with store._lock:
            store._conn.execute("DELETE FROM packets")
            store._conn.execute("DELETE FROM flows")
            store._conn.execute("DELETE FROM payloads")
            store._conn.execute("DELETE FROM tags")
            store._conn.commit()
        return {"status": "ok"}
    search = str(request.query.get("search") or "").strip()
    proto_value = str(request.query.get("proto") or "").strip()
    proto = normalize_protocol_name(proto_value) if proto_value else ""
    mode = str(request.query.get("mode") or "").strip().lower()
    interface = str(request.query.get("interface") or "").strip()
    limit = _normalize_limit(request.query.get("limit"), default=250)
    offset = _normalize_offset(request.query.get("offset"))
    since = _normalize_since(request)
    rows = store.list_packets(
        proto=proto,
        mode=mode,
        interface=interface,
        limit=limit,
        offset=offset,
        search=search,
        since=since,
    )
    return _listing_response(
        [_packet_row_to_port(row) for row in rows],
        total=store.count_packets(proto=proto, mode=mode, interface=interface, search=search, since=since),
        limit=limit,
        offset=offset,
    )


def _ports_by_proto(request, proto_name: str):
    if request.method.upper() == "DELETE":
        with store._lock:
            store._conn.execute("DELETE FROM packets WHERE LOWER(proto) = ?", (normalize_protocol_name(proto_name),))
            store._conn.execute("DELETE FROM flows WHERE LOWER(proto) = ?", (normalize_protocol_name(proto_name),))
            store._conn.execute("DELETE FROM payloads WHERE LOWER(proto) = ?", (normalize_protocol_name(proto_name),))
            store._conn.execute("DELETE FROM tags WHERE LOWER(proto) = ?", (normalize_protocol_name(proto_name),))
            store._conn.commit()
        return {"status": "ok"}
    search = str(request.query.get("search") or "").strip()
    mode = str(request.query.get("mode") or "").strip().lower()
    interface = str(request.query.get("interface") or "").strip()
    limit = _normalize_limit(request.query.get("limit"), default=250)
    offset = _normalize_offset(request.query.get("offset"))
    since = _normalize_since(request)
    rows = store.list_packets(
        proto=proto_name,
        mode=mode,
        interface=interface,
        limit=limit,
        offset=offset,
        search=search,
        since=since,
    )
    return _listing_response(
        [_packet_row_to_port(row) for row in rows],
        total=store.count_packets(proto=proto_name, mode=mode, interface=interface, search=search, since=since),
        limit=limit,
        offset=offset,
    )


@app.api("/ports/tcp/", methods=("GET", "DELETE"))
def ports_tcp(request):
    return _ports_by_proto(request, "tcp")


@app.api("/ports/udp/", methods=("GET", "DELETE"))
def ports_udp(request):
    return _ports_by_proto(request, "udp")


@app.api("/ports/icmp/", methods=("GET", "DELETE"))
def ports_icmp(request):
    return _ports_by_proto(request, "icmp")


@app.api("/ports/sctp/", methods=("GET", "DELETE"))
def ports_sctp(request):
    return _ports_by_proto(request, "sctp")


@app.api("/banners/", methods=("GET", "DELETE"))
def banners(request):
    if request.method.upper() == "DELETE":
        with store._lock:
            store._conn.execute("DELETE FROM payloads")
            store._conn.commit()
        return {"status": "ok"}
    search = str(request.query.get("search") or "").strip()
    proto_value = str(request.query.get("proto") or "").strip()
    proto = normalize_protocol_name(proto_value) if proto_value else ""
    mode = str(request.query.get("mode") or "").strip().lower()
    interface = str(request.query.get("interface") or "").strip()
    limit = _normalize_limit(request.query.get("limit"), default=250)
    offset = _normalize_offset(request.query.get("offset"))
    since = _normalize_since(request)
    rows = store.list_payloads(
        search=search,
        proto=proto,
        mode=mode,
        interface=interface,
        limit=limit,
        offset=offset,
        since=since,
    )
    return _listing_response(
        [_packet_row_to_banner(row) for row in rows],
        total=store.count_payloads(search=search, proto=proto, mode=mode, interface=interface, since=since),
        limit=limit,
        offset=offset,
    )


@app.api("/banner/action/", methods=("POST",))
def banner_action(request):
    payload = _read_json_body(request)
    banner_id = safe_int(payload.get("id"), 0)
    action = str(payload.get("action") or "").strip().lower()
    clean_results = bool(payload.get("clean_results"))
    row = store.get_payload(banner_id)
    if not row:
        raise _NotFound("Unknown response id")
    updated = _banner_action(row, action, clean_results=clean_results)
    return _packet_row_to_banner(updated) if updated else {"status": "ok"}


@app.api("/tags/", methods=("GET",))
def tags(request):
    search = str(request.query.get("search") or "").strip()
    proto = normalize_protocol_name(request.query.get("proto"))
    limit = _normalize_limit(request.query.get("limit"), default=400)
    offset = _normalize_offset(request.query.get("offset"))
    since = _normalize_since(request)
    rows = store.list_tags(limit=limit, offset=offset, proto=proto, search=search, since=since)
    return _listing_response(
        [_packet_row_to_tag(row) for row in rows],
        total=store.count_tags(proto=proto, search=search, since=since),
        limit=limit,
        offset=offset,
    )


@app.api("/tags/tcp/", methods=("GET",))
def tags_tcp(request):
    request.query["proto"] = "tcp"
    return tags(request)


@app.api("/tags/udp/", methods=("GET",))
def tags_udp(request):
    request.query["proto"] = "udp"
    return tags(request)


@app.api("/tags/icmp/", methods=("GET",))
def tags_icmp(request):
    request.query["proto"] = "icmp"
    return tags(request)


@app.api("/tags/sctp/", methods=("GET",))
def tags_sctp(request):
    request.query["proto"] = "sctp"
    return tags(request)


@app.api("/api/dashboard/", methods=("GET",))
def dashboard(request):
    payload = store.dashboard_snapshot(ws_clients=hub.list_clients())
    payload["runtime"] = runtime.snapshot()
    return payload


@app.api("/api/charts/analytics", methods=("GET",))
def charts_analytics(_request):
    return store.analytics_snapshot()


@app.api("/api/map/scan", methods=("GET",))
def map_scan(request):
    limit = _normalize_limit(request.query.get("limit"), default=500, maximum=2000)
    snapshot = store.map_snapshot(limit=limit)
    return {"data": snapshot}


@app.api("/api/endpoints/", methods=("GET",))
def endpoints(_request):
    return store.endpoint_catalog(ENDPOINTS)


@app.api(AUTH_SESSION_PATH, methods=("GET",))
def auth_session(request):
    token = _extract_request_token(request)
    client = _client_address(request)
    # This route is the one the guard skips (the SPA has to be able to ask
    # whether a code is needed), which also makes it the only free oracle
    # for "is this code right?" - so it carries the same per-source backoff
    # and security logging as every guarded route.
    if REQUIRE_AUTH and token:
        allowed, retry_after = RATE_LIMITER.check(client)
        if not allowed:
            access_log.log_auth_failure(
                request, client=client, reason="rate_limited", status=429, retry_after=retry_after
            )
            return _rate_limited_response(retry_after)
    is_authenticated, _user_info = _authenticate_request(request)
    if REQUIRE_AUTH and token:
        if is_authenticated:
            RATE_LIMITER.register_success(client)
        else:
            lockout = RATE_LIMITER.register_failure(client)
            access_log.log_auth_failure(
                request, client=client, reason="invalid_token", status=401, retry_after=lockout
            )
    if REQUIRE_AUTH and not token:
        return {
            "require_auth": True,
            "authenticated": False,
            "message": "Security code required",
            "security_code_label": "Security code",
            "security_code_length": 8,
            "ws_auth_close_code": WS_AUTH_CLOSE_CODE,
        }
    if REQUIRE_AUTH and token and not is_authenticated:
        return {
            "require_auth": True,
            "authenticated": False,
            "message": "Invalid security code",
            "security_code_label": "Security code",
            "security_code_length": 8,
            "ws_auth_close_code": WS_AUTH_CLOSE_CODE,
        }
    return {
        "require_auth": bool(REQUIRE_AUTH),
        "authenticated": bool(is_authenticated or not REQUIRE_AUTH),
        "message": "Authenticated" if is_authenticated else "Authentication not required",
        "security_code_label": "Security code",
        "security_code_length": 8,
        "ws_auth_close_code": WS_AUTH_CLOSE_CODE,
    }


@app.api("/api/hello", methods=("GET",))
def hello(_request):
    return {"status": "ok", "message": f"Sniff4Hound is running in {runtime.mode} mode", "version": __version__}


@app.api("/api/echo", methods=("POST",))
def echo(request):
    return {"status": "ok", "body": request.text()}


@app.api("/api/ws/clients", methods=("GET",))
def ws_clients(_request):
    return hub.list_clients()


@app.api("/api/ws/broadcast", methods=("POST",))
def ws_broadcast(request):
    payload = _read_json_body(request)
    message_type = str(payload.get("type") or "note").strip().lower() or "note"
    message = str(payload.get("message") or payload.get("text") or "").strip()
    hub.broadcast({"type": message_type, "message": message, "generated_at": utc_now()})
    return {"status": "ok", "clients": len(hub.list_clients())}


@app.api("/api/ws/ping", methods=("POST",))
def ws_ping(request):
    payload = _read_json_body(request)
    hub.ping(str(payload.get("payload") or payload.get("message") or "").encode("utf-8"))
    return {"status": "ok"}


@app.api("/api/ws/close", methods=("POST",))
def ws_close(request):
    payload = _read_json_body(request)
    target_id = safe_int(payload.get("client_id"), 0)
    code = safe_int(payload.get("code"), 1000)
    reason = str(payload.get("reason") or "").strip()
    if target_id:
        clients = hub.list_clients()
        for client in clients:
            if safe_int(client.get("id"), 0) != target_id:
                continue
            with hub._lock:
                ws = hub._clients.get(target_id, {}).get("ws")
            if ws:
                try:
                    ws.close(code, reason)
                except Exception:
                    pass
                hub.unregister(ws)
            break
    else:
        hub.close(code, reason)
    return {"status": "ok"}


@app.api("/api/chat/messages", methods=("GET", "POST"))
def chat_messages(request):
    if request.method.upper() == "GET":
        limit = _normalize_limit(request.query.get("limit"), default=50, maximum=500)
        return list(reversed(_CHAT_MESSAGES[-limit:]))
    payload = _read_json_body(request)
    content = str(payload.get("content") or payload.get("message") or "").strip()
    if not content:
        raise ValueError("content is required")
    if len(content) > 2000:
        raise ValueError("content must be 2000 characters or fewer")
    # Fixed author: this endpoint is reachable by anyone holding the security
    # code, so letting the caller name itself would make the operator/dashboard
    # distinction in the transcript meaningless.
    return append_chat_message(
        content,
        author="dashboard",
        kind="note",
        meta={"source": "dashboard"},
        broadcast=True,
    )


@app.api("/api/chat/clear", methods=("POST",))
def chat_clear(_request):
    _CHAT_MESSAGES.clear()
    return {"status": "ok"}


@app.api("/api/app/shutdown", methods=("POST",))
def app_shutdown(request):
    payload = _read_json_body(request)
    delay_seconds = max(0.0, min(safe_float(payload.get("delay"), 0.2), 3.0))
    requested = request_process_shutdown(delay=delay_seconds)
    return {
        "status": "ok",
        "shutdown_requested": bool(requested),
        "shutdown_pending": bool(requested or process_shutdown_requested()),
        "delay_seconds": delay_seconds,
    }


@app.api("/api/ip/domains/", methods=("GET",))
def ip_domains(request):
    return store.domains_for_ip(request.query.get("ip"))


@app.api("/api/ip/ttl-path/", methods=("GET",))
def ip_ttl_path(request):
    return store.ttl_path_for_ip(request.query.get("ip"))


@app.api("/api/ip/intel/", methods=("GET",))
def ip_intel(request):
    ip = str(request.query.get("ip") or "").strip()
    refresh = safe_int(request.query.get("refresh"), 0)
    payload = store.ip_intel(ip)
    # `payload["domains"]` and `payload["ttl_path"]` used to be overwritten
    # here with hardcoded empties and a constant estimated_ttl of 64, which
    # discarded the real values store.ip_intel() had just computed and told
    # the analyst "no known domains, no hops" about hosts the database had
    # plenty of both for. Whatever the store returns now stands.
    payload["cached"] = not bool(refresh)
    payload["generated_at"] = utc_now()
    host = payload.get("host", {}) if isinstance(payload.get("host"), dict) else {}
    payload["host_profile"] = {
        "target": {
            "ip": ip,
            "scope": ip_scope(ip),
            # Was a hardcoded {"found": False} sitting next to a populated
            # host.geo in the same response - two panels of the same tool
            # disagreeing about the same host.
            "geo": host.get("geo", {"found": False}),
        },
        "transport": host.get("transport", {}),
        "application": _host_application_profile(payload),
        "metrics": {
            "packet_count": payload.get("summary", {}).get("packets", 0),
            "flow_count": payload.get("summary", {}).get("flows", 0),
        },
        "notes": [],
    }
    return payload


def _host_application_profile(payload: dict) -> dict:
    """Fills the HTTP/TLS half of a host profile from evidence that is
    already in the response (observed banners and the domain catalog's own
    source labels) rather than shipping empty strings under the name of a
    fingerprint that was never taken."""
    services = ((payload.get("host") or {}).get("transport") or {}).get("services") or []
    http_banner = ""
    tls_banner = ""
    for service in services:
        if not isinstance(service, dict):
            continue
        banner = str(service.get("banner") or "").strip()
        if not banner:
            continue
        port = safe_int(service.get("port"), 0)
        if not tls_banner and (port in {443, 8443} or "tls" in banner.lower()):
            tls_banner = banner
        elif not http_banner and (port in {80, 8080, 8000} or "http/" in banner.lower()):
            http_banner = banner
    domains = (payload.get("domains") or {}).get("domains") or []
    sni_names = [str(row.get("name") or "") for row in domains if str(row.get("source") or "") == "tls_sni"]
    host_names = [str(row.get("name") or "") for row in domains if str(row.get("source") or "") == "http_host"]
    return {
        "http": {"banner": http_banner, "headers": {}, "hosts": host_names},
        "tls": {"banner": tls_banner, "fingerprint": {}, "sni": sni_names},
        "fingerprint": {},
    }


@app.api("/api/soc/analysis/", methods=("GET",))
def soc_analysis(request):
    cycles = clamp_int(request.query.get("cycles"), 1, 4, default=4) or 4
    limit = _normalize_limit(request.query.get("limit"), default=500, maximum=2000)
    return store.soc_analysis_snapshot(cycles=cycles, limit=limit)


@app.api("/api/runtime/", methods=("GET", "POST"))
def runtime_api(request):
    if request.method.upper() == "GET":
        return runtime.snapshot()
    payload = _read_json_body(request)
    mode = str(payload.get("mode") or payload.get("runtime") or "").strip().lower()
    if mode and mode not in {"sniffer", "honeypot"}:
        raise ValueError(f"Unsupported mode: {mode}")
    action = str(payload.get("action") or "").strip().lower()
    has_interface = any(key in payload for key in ("interface", "interfaces", "sniffer_interface", "sniffer_interfaces"))
    interfaces = payload.get("interfaces", payload.get("sniffer_interfaces"))
    if interfaces is None:
        interfaces = payload.get("interface", payload.get("sniffer_interface", ""))
    # Which engine an action applies to. Absent means "the focused mode",
    # which is what every existing caller sends; "all"/"both" acts on the
    # pair. `mode` still selects the focused engine, but it no longer stops
    # the other one - the two run independently now.
    engine = payload.get("engine", payload.get("engines"))
    if isinstance(engine, str) and engine.strip().lower() not in {"", "sniffer", "honeypot", "all", "both"}:
        raise ValueError(f"Unsupported engine: {engine}")

    snapshot = None
    if has_interface:
        snapshot = runtime.set_sniffer_interfaces(interfaces)

    # {"engines": {"sniffer": true, "honeypot": false}} sets the running set
    # outright - any of the four combinations, including neither.
    if isinstance(engine, dict) or (isinstance(engine, (list, tuple)) and not action):
        snapshot = runtime.set_engines(engine)
        engine = None

    if action == "start":
        if mode:
            snapshot = runtime.set_mode(mode)
        snapshot = runtime.start(engine if engine else (mode or None))
    elif action == "stop":
        if engine:
            snapshot = runtime.stop(engine)
        elif mode:
            snapshot = runtime.stop(mode)
        else:
            snapshot = runtime.stop()
    if mode and not action:
        snapshot = runtime.set_mode(mode)
    if snapshot is None:
        raise ValueError("mode, engine or interface is required")
    return snapshot


@app.api("/api/honeypot/listeners/", methods=("GET", "POST"))
def honeypot_listeners_api(request):
    if request.method.upper() == "GET":
        return runtime.list_honeypot_listeners()
    payload = _read_json_body(request)
    proto = str(payload.get("proto") or "").strip().lower()
    port = payload.get("port")
    label = str(payload.get("label") or "").strip()
    return runtime.create_honeypot_listener(proto, port, label)


@app.api("/api/honeypot/listeners/toggle", methods=("POST",))
def honeypot_listeners_toggle_api(request):
    payload = _read_json_body(request)
    listener_id = str(payload.get("id") or "").strip()
    if not listener_id:
        raise ValueError("id is required")
    if "enabled" not in payload:
        raise ValueError("enabled is required")
    enabled = bool(payload.get("enabled"))
    return runtime.set_honeypot_listener_enabled(listener_id, enabled)


@app.api("/api/catalog/file/banner-rules", methods=("GET", "POST"))
def file_banner_rules(request):
    filename = "banner_regex_rules.json"
    if request.method.upper() == "GET":
        return store.read_catalog_file(filename)
    payload = _read_json_body(request)
    rows = payload if isinstance(payload, list) else payload.get("rows", [])
    if not isinstance(rows, list):
        rows = []
    store.write_catalog_file(filename, [item for item in rows if isinstance(item, dict)])
    return {"status": "ok", "count": len(rows)}


@app.api("/api/catalog/file/banner-requests", methods=("GET", "POST"))
def file_banner_requests(request):
    filename = "banner_probe_requests.json"
    if request.method.upper() == "GET":
        return store.read_catalog_file(filename)
    payload = _read_json_body(request)
    rows = payload if isinstance(payload, list) else payload.get("rows", [])
    if not isinstance(rows, list):
        rows = []
    store.write_catalog_file(filename, [item for item in rows if isinstance(item, dict)])
    return {"status": "ok", "count": len(rows)}


@app.api("/api/catalog/file/ip-presets", methods=("GET", "POST"))
def file_ip_presets(request):
    filename = "ip_presets.json"
    if request.method.upper() == "GET":
        return store.read_catalog_file(filename)
    payload = _read_json_body(request)
    rows = payload if isinstance(payload, list) else payload.get("rows", [])
    if not isinstance(rows, list):
        rows = []
    store.write_catalog_file(filename, [item for item in rows if isinstance(item, dict)])
    return {"status": "ok", "count": len(rows)}


@app.api("/api/catalog/banner-rules/", methods=("GET", "POST", "PUT", "DELETE"))
def catalog_rules(request):
    if request.method.upper() == "GET":
        return [_ruleset_row(row) for row in store.list_rulesets()]
    payload = _read_json_body(request)
    if request.method.upper() == "POST":
        return _ruleset_row(store.save_ruleset(payload))
    if request.method.upper() == "PUT":
        return _ruleset_row(store.save_ruleset(payload))
    if request.method.upper() == "DELETE":
        rule_id = str(payload.get("id") or "").strip()
        if not rule_id:
            raise ValueError("id is required")
        store.delete_ruleset(rule_id)
        return {"status": "ok"}
    raise ValueError("Unsupported method")


@app.api("/api/catalog/banner-requests/", methods=("GET", "POST", "PUT", "DELETE"))
def catalog_requests(request):
    filename = "banner_probe_requests.json"
    if request.method.upper() == "GET":
        return store.read_catalog_file(filename)
    payload = _read_json_body(request)
    rows = store.read_catalog_file(filename)
    if request.method.upper() in {"POST", "PUT"}:
        row = dict(payload)
        row_id = str(row.get("id") or row.get("name") or "").strip() or f"request-{len(rows) + 1}"
        row["id"] = row_id
        updated = False
        for index, existing in enumerate(rows):
            existing_id = str(existing.get("id") or existing.get("name") or "").strip()
            if existing_id == row_id:
                rows[index] = row
                updated = True
                break
        if not updated:
            rows.append(row)
        store.write_catalog_file(filename, rows)
        return row
    if request.method.upper() == "DELETE":
        row_id = str(payload.get("id") or "").strip()
        rows = [row for row in rows if str(row.get("id") or row.get("name") or "").strip() != row_id]
        store.write_catalog_file(filename, rows)
        return {"status": "ok"}
    raise ValueError("Unsupported method")


@app.api("/api/catalog/ip-presets/", methods=("GET", "POST", "PUT", "DELETE"))
def catalog_presets(request):
    filename = "ip_presets.json"
    if request.method.upper() == "GET":
        return store.read_catalog_file(filename)
    payload = _read_json_body(request)
    rows = store.read_catalog_file(filename)
    if request.method.upper() in {"POST", "PUT"}:
        row = dict(payload)
        row_id = str(row.get("id") or row.get("name") or "").strip() or f"preset-{len(rows) + 1}"
        row["id"] = row_id
        updated = False
        for index, existing in enumerate(rows):
            existing_id = str(existing.get("id") or existing.get("name") or "").strip()
            if existing_id == row_id:
                rows[index] = row
                updated = True
                break
        if not updated:
            rows.append(row)
        store.write_catalog_file(filename, rows)
        return row
    if request.method.upper() == "DELETE":
        row_id = str(payload.get("id") or "").strip()
        rows = [row for row in rows if str(row.get("id") or row.get("name") or "").strip() != row_id]
        store.write_catalog_file(filename, rows)
        return {"status": "ok"}
    raise ValueError("Unsupported method")


@app.api("/api/monitors/", methods=("GET", "POST", "PUT", "DELETE"))
def monitors_collection(request):
    if request.method.upper() == "GET":
        match_counts = store.monitor_match_counts()
        return [_monitor_row(row, match_counts) for row in store.list_monitors()]
    payload = _read_json_body(request)
    if request.method.upper() in {"POST", "PUT"}:
        return _monitor_row(store.save_monitor(payload))
    if request.method.upper() == "DELETE":
        monitor_id = str(payload.get("id") or "").strip()
        if not monitor_id:
            raise ValueError("id is required")
        store.delete_monitor(monitor_id)
        return {"status": "ok"}
    raise ValueError("Unsupported method")


@app.api("/api/monitors/toggle", methods=("POST",))
def monitors_toggle(request):
    payload = _read_json_body(request)
    monitor_id = str(payload.get("id") or "").strip()
    if not monitor_id:
        raise ValueError("id is required")
    if "enabled" not in payload:
        raise ValueError("enabled is required")
    enabled = bool(payload.get("enabled"))
    return _monitor_row(store.set_monitor_enabled(monitor_id, enabled))


@app.api("/api/monitors/config", methods=("GET", "POST"))
def monitors_config(request):
    if request.method.upper() == "GET":
        return {"filter_enabled": store.get_monitor_filter_enabled()}
    payload = _read_json_body(request)
    if "filter_enabled" not in payload:
        raise ValueError("filter_enabled is required")
    enabled = bool(payload.get("filter_enabled"))
    return {"filter_enabled": store.set_monitor_filter_enabled(enabled)}


@app.api("/api/settings/location", methods=("GET", "POST"))
def declared_location_api(request):
    """The sensor's own site location, used to plot private/loopback hosts."""
    if request.method.upper() == "GET":
        return store.get_declared_location()
    payload = _read_json_body(request)
    if payload.get("clear"):
        return store.set_declared_location(None, None, label=str(payload.get("label") or ""))
    if "lat" not in payload or "lon" not in payload:
        raise ValueError("lat and lon are required (or pass clear: true)")
    return store.set_declared_location(
        payload.get("lat"),
        payload.get("lon"),
        label=str(payload.get("label") or ""),
    )


@app.api("/api/detection/scopes", methods=("GET", "POST"))
def detection_scopes_api(request):
    """Which IP scopes are muted for detection. Capture is unaffected."""
    from .utils import DETECTION_IP_SCOPES

    if request.method.upper() == "GET":
        return {
            "available_scopes": list(DETECTION_IP_SCOPES),
            "exclude_scopes": store.get_detection_exclude_scopes(),
        }
    payload = _read_json_body(request)
    if "exclude_scopes" not in payload:
        raise ValueError("exclude_scopes is required")
    scopes = payload.get("exclude_scopes")
    if scopes is None:
        scopes = []
    if not isinstance(scopes, (list, tuple, str)):
        raise ValueError("exclude_scopes must be a list of scope names")
    return {
        "available_scopes": list(DETECTION_IP_SCOPES),
        "exclude_scopes": store.set_detection_exclude_scopes(scopes),
    }


def _blacklist_row(row: dict) -> dict:
    return {
        "id": row.get("id"),
        "category": row.get("category"),
        "match_type": row.get("match_type"),
        "value": row.get("value"),
        "label": row.get("label"),
        "enabled": bool(row.get("enabled")),
        "created_at": row.get("created_at"),
        "updated_at": row.get("updated_at"),
    }


@app.api("/api/blacklist/", methods=("GET", "POST", "DELETE"))
def blacklist_collection(request):
    if request.method.upper() == "GET":
        category = str(request.query.get("category") or "").strip()
        return [_blacklist_row(row) for row in store.list_blacklist_entries(category)]
    payload = _read_json_body(request)
    if request.method.upper() == "POST":
        entry = store.create_blacklist_entry(
            category=str(payload.get("category") or ""),
            match_type=str(payload.get("match_type") or "exact"),
            value=str(payload.get("value") or ""),
            label=str(payload.get("label") or ""),
        )
        return _blacklist_row(entry)
    if request.method.upper() == "DELETE":
        entry_id = str(payload.get("id") or "").strip()
        if not entry_id:
            raise ValueError("id is required")
        store.delete_blacklist_entry(entry_id)
        return {"status": "ok"}
    raise ValueError("Unsupported method")


@app.api("/api/blacklist/toggle", methods=("POST",))
def blacklist_toggle(request):
    payload = _read_json_body(request)
    entry_id = str(payload.get("id") or "").strip()
    if not entry_id:
        raise ValueError("id is required")
    if "enabled" not in payload:
        raise ValueError("enabled is required")
    enabled = bool(payload.get("enabled"))
    return _blacklist_row(store.set_blacklist_entry_enabled(entry_id, enabled))


@app.api("/api/domains/", methods=("GET",))
def domains_collection(request):
    search = str(request.query.get("search") or "").strip()
    limit = _normalize_limit(request.query.get("limit"), default=200)
    offset = _normalize_offset(request.query.get("offset"))
    since = _normalize_since(request)
    return _listing_response(
        store.list_domains(search=search, limit=limit, offset=offset, since=since),
        total=store.count_domains(search=search, since=since),
        limit=limit,
        offset=offset,
    )


@app.api("/api/paths/", methods=("GET",))
def paths_collection(request):
    search = str(request.query.get("search") or "").strip()
    limit = _normalize_limit(request.query.get("limit"), default=200)
    offset = _normalize_offset(request.query.get("offset"))
    since = _normalize_since(request)
    return _listing_response(
        store.list_paths(search=search, limit=limit, offset=offset, since=since),
        total=store.count_paths(search=search, since=since),
        limit=limit,
        offset=offset,
    )


@app.api("/api/intel/ips/", methods=("GET",))
def ip_catalog_collection(request):
    search = str(request.query.get("search") or "").strip()
    limit = _normalize_limit(request.query.get("limit"), default=200)
    offset = _normalize_offset(request.query.get("offset"))
    since = _normalize_since(request)
    scope = str(request.query.get("scope") or "").strip()
    return _listing_response(
        store.list_ip_catalog(search=search, limit=limit, offset=offset, since=since, scope=scope),
        total=store.count_ip_catalog(search=search, since=since, scope=scope),
        limit=limit,
        offset=offset,
        # Always the *unfiltered* breakdown: the filter chips have to keep
        # showing what the other scopes hold while one of them is selected.
        # It rides as a header because this endpoint answers with a bare
        # array by contract - adding a key here would break every caller
        # that indexes into the response.
        extra_headers={"X-Scope-Counts": _json_text(store.ip_catalog_scope_counts(search=search, since=since))},
    )


@app.api("/api/alerts/recent", methods=("GET",))
def alerts_recent(request):
    limit = _normalize_limit(request.query.get("limit"), default=500)
    offset = _normalize_offset(request.query.get("offset"))
    since = _normalize_since(request)
    severity = str(request.query.get("severity") or "").strip()
    return _listing_response(
        store.list_recent_alerts(limit=limit, offset=offset, since=since, severity=severity),
        total=store.count_recent_alerts(since=since, severity=severity),
        limit=limit,
        offset=offset,
    )


@app.api("/api/monitors/packets/", methods=("GET",))
def monitor_matched_packets(request):
    monitor_id = str(request.query.get("monitor_id") or "").strip()
    if not monitor_id:
        raise ValueError("monitor_id is required")
    search = str(request.query.get("search") or "").strip()
    limit = _normalize_limit(request.query.get("limit"), default=200)
    offset = _normalize_offset(request.query.get("offset"))
    since = _normalize_since(request)
    return _listing_response(
        store.list_packets_by_monitor(monitor_id, search=search, limit=limit, offset=offset, since=since),
        total=store.count_packets_by_monitor(monitor_id, since=since),
        limit=limit,
        offset=offset,
    )


def _export_response(request, dataset: str):
    """Shared handler for `/api/export/<dataset>`.

    Sits inside the same auth guard as every other API route (it is
    registered with `@app.api`, so `_apply_api_auth_guards()` wraps it),
    and reuses the existing store listings rather than adding new SQL.
    """
    fmt = normalize_format(request.query.get("format") or "json")
    limit = _normalize_limit(request.query.get("limit"), default=5000)
    offset = _normalize_offset(request.query.get("offset"))
    since = _normalize_since(request)
    severity = str(request.query.get("severity") or "").strip()
    search = str(request.query.get("search") or "").strip()
    proto = str(request.query.get("proto") or "").strip()
    payload = build_export(
        store,
        dataset,
        limit=limit,
        offset=offset,
        since=since,
        severity=severity,
        search=search,
        proto=proto,
    )
    filename = export_filename(dataset, fmt)
    disposition = f'attachment; filename="{filename}"'
    if fmt == "csv":
        return Response.text(
            rows_to_csv(payload["fields"], payload["rows"]),
            headers={
                "Content-Type": "text/csv; charset=utf-8",
                "Content-Disposition": disposition,
                "Access-Control-Expose-Headers": "Content-Disposition",
            },
        )
    return Response.json(
        payload,
        headers={
            "Content-Disposition": disposition,
            "Access-Control-Expose-Headers": "Content-Disposition",
        },
    )


@app.api("/api/export/", methods=("GET",))
def export_index(_request):
    """What can be exported, and how - so an integration does not have to
    guess the dataset names or the column set."""
    return {
        "datasets": list(EXPORT_DATASETS),
        "formats": list(EXPORT_FORMATS),
        "fields": {name: list(fields) for name, fields in EXPORT_FIELDS.items()},
        "generated_at": utc_now(),
    }


@app.api("/api/export/alerts", methods=("GET",))
def export_alerts(request):
    return _export_response(request, "alerts")


@app.api("/api/export/endpoints", methods=("GET",))
def export_endpoints(request):
    return _export_response(request, "endpoints")


@app.api("/api/export/flows", methods=("GET",))
def export_flows(request):
    return _export_response(request, "flows")


@app.api("/api/export/domains", methods=("GET",))
def export_domains(request):
    return _export_response(request, "domains")


@app.api("/api/data/clear/", methods=("POST",))
def clear_detections_api(request):
    payload = _read_json_body(request)
    scope = str(payload.get("scope") or "all").strip().lower()
    # The frontend's Monitors view calls this "monitors" (it only ever
    # shows sniffer-side traffic - honeypot hits live in their own view);
    # SniffStore.clear_detections uses "sniffer" for that same half.
    if scope == "everything":
        # Wipes the capture-produced tables outright (flows, domains, paths and
        # sessions included), not just per-packet detection history.
        result = store.purge_capture_data()
        from .honeypot import clear_honeypot_events

        result["honeypot_events"] = clear_honeypot_events()
        return result
    store_scope = "sniffer" if scope == "monitors" else scope
    if store_scope not in {"all", "honeypot", "sniffer"}:
        raise ValueError("scope must be 'monitors', 'honeypot', 'all', or 'everything'")
    result = store.clear_detections(store_scope)
    if store_scope in ("all", "honeypot"):
        # Lazy import - sniff4hound.honeypot must never load as a side effect
        # of importing sniff4hound.app/sniff4hound.store (see
        # honeypot_ports.py's own note on this), only when actually needed.
        from .honeypot import clear_honeypot_events

        result["honeypot_events"] = clear_honeypot_events()
    return result


def _apply_api_auth_guards():
    """Wraps every API route (plus the framework's own docs routes) in the
    auth check and the request-validation error mapping.

    The docs pair is deliberately included: `/docs` and `/docs.json` are
    registered by wsbuilder's enable_docs(), and `/docs` in particular is a
    `view`, not an `api`, so a `kind == "api"` filter left both wide open.
    They publish the full route inventory - every path, method, handler
    name and Python module of a security sensor - and that is not public
    information."""
    for route in app.router.routes:
        path = getattr(route, "path", "")
        if getattr(route, "kind", "") != "api" and path not in DOCS_PATHS:
            continue
        if path == AUTH_SESSION_PATH:
            continue

        current_handler = getattr(route, "handler", None)
        if current_handler is None or getattr(current_handler, "_sniff4hound_auth_wrapped", False):
            continue

        @wraps(current_handler)
        def guarded_handler(request, *args, _handler=current_handler, **kwargs):
            denied = _guard_request_auth(request)
            if denied is not None:
                return denied
            try:
                return _handler(request, *args, **kwargs)
            except _InvalidJsonBody as exc:
                return Response.json(
                    {"status": "error", "code": "invalid_json", "message": str(exc)},
                    status=400,
                )
            except _NotFound as exc:
                return Response.json(
                    {"status": "error", "code": "not_found", "message": str(exc)},
                    status=404,
                )
            except ValueError as exc:
                # ~30 `raise ValueError("<param> is required")` validation
                # guards live in the handlers below. Unwrapped, every one of
                # them surfaced as a bare 500 "Internal Server Error", which
                # a SIEM collector or response automation cannot tell apart
                # from "the sensor is down" - and which threw away the one
                # thing the caller needed, the message saying what was wrong.
                return Response.json(
                    {"status": "error", "code": "invalid_request", "message": str(exc)},
                    status=400,
                )

        guarded_handler._sniff4hound_auth_wrapped = True
        route.handler = guarded_handler


def _protocol_snapshot_payload(params: dict) -> dict:
    """The same slice the HTTP endpoint returns, for one subscription."""
    return {
        "type": "protocol_snapshot",
        "protocol": params.get("proto") or "all",
        "snapshot": store.protocol_snapshot(
            proto=params.get("proto") or "",
            mode=params.get("mode") or "",
            interface=params.get("interface") or "",
            search=params.get("search") or "",
            since=params.get("since") or "",
            limit=int(params.get("limit") or 250),
        ),
        "generated_at": utc_now(),
    }


def _snapshot_pusher_loop(stop_event: threading.Event):
    """Deliver every due subscription, one at a time.

    Deliberately a single thread rather than one per connection: each delivery
    runs aggregate queries over the whole filtered set, and serialising them
    bounds what a roomful of open dashboards can do to the database. A slow
    query delays the next client's frame; it cannot multiply the load.
    """
    while not stop_event.wait(WS_SNAPSHOT_TICK_SECONDS):
        try:
            due = hub.due_subscriptions(time.monotonic())
        except Exception:
            continue
        for ws, params in due:
            try:
                payload = _protocol_snapshot_payload(params)
            except Exception as exc:
                # A failed query must not kill the pusher for every other
                # client, and the subscriber has to learn that its slice
                # stopped updating rather than silently seeing stale data.
                hub.send_to(ws, {
                    "type": "protocol_snapshot_error",
                    "protocol": params.get("proto") or "all",
                    "message": str(exc)[:200],
                    "generated_at": utc_now(),
                })
                continue
            hub.send_to(ws, payload)


_snapshot_pusher_stop = threading.Event()
_snapshot_pusher_lock = threading.Lock()
_snapshot_pusher_thread = None


def _ensure_snapshot_pusher():
    """Start the pusher on first use, and only once.

    Started lazily rather than at import: a module-scope thread is leaked by
    every reimport of this module, which is exactly what the test suite does
    when it reloads the auth stack - it left one orphaned thread per reload,
    each still walking the hub. It also means a process that never serves a
    subscriber (the CLI, a packaging run) does not carry the thread at all.
    """
    global _snapshot_pusher_thread
    with _snapshot_pusher_lock:
        if _snapshot_pusher_thread is not None and _snapshot_pusher_thread.is_alive():
            return _snapshot_pusher_thread
        _snapshot_pusher_stop.clear()
        _snapshot_pusher_thread = threading.Thread(
            target=_snapshot_pusher_loop,
            args=(_snapshot_pusher_stop,),
            name="sniff4hound-ws-snapshots",
            daemon=True,
        )
        _snapshot_pusher_thread.start()
        return _snapshot_pusher_thread


@app.ws(
    "/ws/",
    keepalive_interval=WS_KEEPALIVE_INTERVAL_SECONDS,
    pong_timeout=WS_PONG_TIMEOUT_SECONDS,
    ping_payload=b"sniff4hound",
)
def websocket_handler(ws, request=None):
    ws_started_at = time.perf_counter()
    if REQUIRE_AUTH:
        denied = _guard_request_auth(request, allow_query=True)
        if denied is not None:
            status = int(getattr(denied, "status", 401) or 401)
            try:
                ws.send_text(
                    _json_text(
                        {
                            "type": "auth_required",
                            "status": status,
                            "message": (
                                "Too many failed authentication attempts"
                                if status == 429
                                else "Invalid or missing security code"
                            ),
                            "generated_at": utc_now(),
                        }
                    )
                )
            except Exception:
                pass
            try:
                ws.close(WS_AUTH_CLOSE_CODE, "Unauthorized")
            except Exception:
                pass
            # The handshake itself succeeded (wsbuilder already answered
            # 101) and only then did the token check reject the client, so
            # both lines are logged - otherwise an unauthorized client is
            # indistinguishable from one that never connected.
            access_log.log_websocket_open(request)
            access_log.log_websocket_close(request, WS_AUTH_CLOSE_CODE, ws_started_at)
            return

    access_log.log_websocket_open(request)
    ws_close_code = 1000
    hub.register(ws)
    try:
        ws.send_text(_json_text({"type": "welcome", "message": "Sniff4Hound websocket connected", "generated_at": utc_now()}))
        # Each opening message is guarded on its own. They used to share the
        # handler's outer `except`, so a transient failure building one of
        # them - runtime.snapshot() raises IpcDisconnected whenever the
        # capture service is not attached - tore down the whole connection
        # before the read loop ever started, instead of just omitting that
        # one message. The socket itself is fine in that case, and the client
        # can ask again with an explicit action.
        for message_type, builder in (
            ("scan_map_snapshot", lambda: {"data": store.map_snapshot(limit=100)}),
            ("runtime_mode", lambda: {"runtime": runtime.snapshot()}),
        ):
            try:
                body = builder()
            except Exception:
                continue
            ws.send_text(_json_text({"type": message_type, **body, "generated_at": utc_now()}))
        while True:
            frame = ws.recv_frame()
            opcode = getattr(frame, "opcode", 0)
            payload = getattr(frame, "payload", b"")
            if opcode == 0x8:
                code, reason = parse_close_payload(payload)
                ws_close_code = code or 1000
                try:
                    ws.close(ws_close_code, reason or "")
                except Exception:
                    pass
                break
            if opcode == 0x9:
                try:
                    ws.send_pong(payload)
                except Exception:
                    break
                continue
            if opcode != 0x1:
                continue
            try:
                data = json.loads(payload.decode("utf-8", errors="ignore"))
            except Exception:
                continue
            if not isinstance(data, dict):
                continue
            action = str(data.get("action") or "").strip().lower()
            if action == "scan_map_snapshot":
                ws.send_text(_json_text({"type": "scan_map_snapshot", "data": store.map_snapshot(limit=safe_int(data.get("limit"), 100)), "generated_at": utc_now()}))
            elif action == "runtime_snapshot":
                ws.send_text(_json_text({"type": "runtime_mode", "runtime": runtime.snapshot(), "generated_at": utc_now()}))
            elif action == "runtime_mode":
                ws.send_text(_json_text({"type": "runtime_mode", "runtime": runtime.snapshot(), "generated_at": utc_now()}))
            elif action == "subscribe_protocol_snapshot":
                proto = normalize_protocol_name(data.get("proto") or "")
                interval = safe_float(data.get("interval"), WS_SNAPSHOT_DEFAULT_INTERVAL_SECONDS)
                # Clamped, not rejected: a client asking for 0 gets the floor
                # rather than an error it would have to handle, and cannot
                # spin the query loop either way.
                interval = max(
                    WS_SNAPSHOT_MIN_INTERVAL_SECONDS,
                    min(WS_SNAPSHOT_MAX_INTERVAL_SECONDS, interval),
                )
                params = {
                    "proto": "" if proto == "all" else proto,
                    "mode": str(data.get("mode") or "").strip().lower(),
                    "interface": str(data.get("interface") or "").strip(),
                    "search": str(data.get("search") or "").strip(),
                    "since": str(data.get("since") or "").strip(),
                    "limit": _normalize_limit(data.get("limit"), default=250),
                }
                hub.subscribe_snapshot(ws, params, interval)
                _ensure_snapshot_pusher()
                ws.send_text(_json_text({
                    "type": "protocol_snapshot_subscribed",
                    "protocol": params["proto"] or "all",
                    "interval": interval,
                    "limit": params["limit"],
                    "generated_at": utc_now(),
                }))
            elif action == "unsubscribe_protocol_snapshot":
                hub.unsubscribe_snapshot(ws)
                ws.send_text(_json_text({
                    "type": "protocol_snapshot_unsubscribed",
                    "generated_at": utc_now(),
                }))
            elif action == "ping":
                ws.send_text(_json_text({"type": "pong", "generated_at": utc_now()}))
            hub.touch(ws)
    except Exception:
        pass
    finally:
        hub.unregister(ws)
        access_log.log_websocket_close(request, ws_close_code, ws_started_at)


# Order matters: _attach_runtime_docs() registers /docs and /docs.json, so
# the guard pass has to run *after* it or those two routes never get
# wrapped - which is exactly how they ended up reachable without a token.
_attach_runtime_docs()
_apply_api_auth_guards()
_register_static_frontend()


def bootstrap_capture():
    if CAPTURE_AUTO_START:
        runtime.start()


def shutdown_capture():
    # Every step below is bounded (IPC calls time out on their own) and
    # must always run to completion so the process can exit cleanly - a
    # stray Ctrl+C while one of them is waiting (e.g. the capture process
    # is still mid-sudo-prompt and hasn't answered yet) must not abort the
    # rest of the shutdown with an uncaught KeyboardInterrupt, which isn't
    # an Exception subclass and would otherwise skip closing the store/hub
    # and leave the privileged capture child un-signaled.
    try:
        runtime.stop()
    except (Exception, KeyboardInterrupt):
        pass
    try:
        ipc_client.call("shutdown")
    except (Exception, KeyboardInterrupt):
        pass
    try:
        ipc_client.close()
    except (Exception, KeyboardInterrupt):
        pass
    try:
        _snapshot_pusher_stop.set()
    except (Exception, KeyboardInterrupt):
        pass
    try:
        hub.close()
    except (Exception, KeyboardInterrupt):
        pass
    try:
        store.close()
    except (Exception, KeyboardInterrupt):
        pass
