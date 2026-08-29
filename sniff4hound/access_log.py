"""Compact access logging for the web process.

One line per served request:

    2026-08-26T14:27:41+00:00 HTTP/1.1 GET /api/runtime/?since=1h ref=- loc=- 200

Fields, in order: UTC ISO-8601 timestamp, protocol, method, request target
(path plus query), the request's Referer, the response's Location header, and
the status code. `ref` and `loc` stay as "-" when absent; `loc` is what makes
a bare 3xx line readable, since otherwise the redirect target is invisible.

Timestamps are UTC, in the exact format `utils.utc_now()` writes into every
`created_at` column, so an access line and the API/capture events it produced
sort and correlate as plain strings. They used to be local wall-clock time,
which silently drifted apart from everything else the sensor records.

Credentials never reach the line: the frontend passes the session code in the
WebSocket handshake query string (`/ws/?security_code=...`), so the query of
both the request target and the Referer is scrubbed of the auth parameters
before anything is printed - otherwise every reconnect wrote the live code to
the console in clear text.

WebSocket handshakes are logged as the HTTP request they actually are, with
status 101, and the matching close gets its own `WS CLOSE` line carrying the
close code and how long the session lasted - without it a connection rejected
right after the handshake (an unauthorized client hitting 4401) looks
identical to a healthy session that streamed for an hour.

Before this, the only thing the terminal ever printed about HTTP was
wsbuilder's `[http] handler error ...` line, which fires solely when an
exception escapes a handler: every ordinary request, every 401, every 404 and
every WebSocket upgrade was invisible. That made the console actively
misleading - the sole HTTP output was a stack of scary-looking error lines
with no successful traffic around them for scale.

Deliberately stdout, not the JSON capture logger: this is operator-facing
console output that shares a terminal with the interactive `sniff4hound>`
console, so it follows the same convention as wsbuilder's own `[http]` and
`[ws]` lines.
"""

from __future__ import annotations

import sys
import time

from .settings import ACCESS_LOG_COLOR, ACCESS_LOG_ENABLED
from .utils import utc_now

# Query parameters carrying an authentication credential (see
# app._extract_request_query_token, plus the frontend bootstrap `code` link).
# Their values are replaced before the request target - or a Referer - is ever
# written out.
REDACTED_QUERY_KEYS = frozenset({"code", "security_code", "access_token", "token", "auth"})
REDACTED_VALUE = "REDACTED"


def _timestamp() -> str:
    """Timestamps come straight from utils.utc_now(), so an access line and
    the `created_at` of the rows the request produced are byte-for-byte the
    same format and sort together without any conversion."""
    return utc_now()


def redact_query(query: str) -> str:
    """Replace the value of every auth-bearing query parameter.

    Deliberately hand-rolled rather than parse_qsl/urlencode: this must not
    re-encode, reorder or drop the parts of a query it does not touch, since
    the line is also read as a record of what the client actually sent.
    """
    raw = str(query or "")
    if not raw:
        return ""
    parts = []
    for chunk in raw.split("&"):
        key, sep, _value = chunk.partition("=")
        if sep and key.strip().lower() in REDACTED_QUERY_KEYS:
            parts.append(f"{key}={REDACTED_VALUE}")
        else:
            parts.append(chunk)
    return "&".join(parts)


def redact_url(value: str) -> str:
    """Same treatment for a full URL (a Referer), query part only."""
    text = str(value or "")
    head, sep, query = text.partition("?")
    if not sep:
        return text
    return f"{head}?{redact_query(query)}"


_RESET = "\033[0m"
_STATUS_COLORS = (
    (500, "\033[1;31m"),  # 5xx - bold red
    (400, "\033[0;33m"),  # 4xx - yellow
    (300, "\033[0;36m"),  # 3xx - cyan
    (200, "\033[0;32m"),  # 2xx/1xx - green
)


def _use_color() -> bool:
    if ACCESS_LOG_COLOR == "always":
        return True
    if ACCESS_LOG_COLOR == "never":
        return False
    try:
        return bool(sys.stdout.isatty())
    except Exception:
        # A closed or exotic stdout is not worth crashing a request over.
        return False


def _colorize_status(status: int) -> str:
    text = str(int(status))
    if not _use_color():
        return text
    for threshold, color in _STATUS_COLORS:
        if status >= threshold:
            return f"{color}{text}{_RESET}"
    return text


def _sanitize_field(value: str, default: str = "-") -> str:
    """Make a caller-controlled string safe to drop into a space-separated
    line.

    The fields here are delimited by spaces, so a Referer of
    `evil loc=/admin 200` would otherwise render as extra columns and let a
    remote client forge the status code a log parser reads back. Whitespace
    (spaces, tabs, and the newlines that would fake an entire second entry)
    is escaped rather than dropped, so the real value stays legible.
    """
    text = str(value or "").strip()
    if not text:
        return default
    out = []
    for char in text:
        if char in " \t":
            out.append("%20")
        elif char in "\r\n":
            out.append("%0A")
        elif ord(char) < 0x20 or ord(char) == 0x7F:
            out.append("?")
        else:
            out.append(char)
    return "".join(out)


def _client_address(request) -> str:
    client = getattr(request, "client", None)
    if isinstance(client, (tuple, list)) and client:
        return str(client[0] or "-")
    return str(client or "-")


def _header(request, name: str, default: str = "-") -> str:
    headers = getattr(request, "headers", None) or {}
    value = ""
    try:
        # wsbuilder lowercases incoming header names; fall back to a
        # case-insensitive sweep so this keeps working if that ever changes.
        value = headers.get(name) or headers.get(name.title()) or ""
        if not value:
            for key, candidate in headers.items():
                if str(key).lower() == name:
                    value = candidate
                    break
    except Exception:
        value = ""
    if name == "referer":
        value = redact_url(value)
    return _sanitize_field(value, default)


def _method(request) -> str:
    return _sanitize_field(getattr(request, "method", ""))


def _target(request) -> str:
    path = str(getattr(request, "path", "") or "-")
    query = redact_query(str(getattr(request, "query_string", "") or ""))
    return _sanitize_field(f"{path}?{query}" if query else path)


def _protocol(request) -> str:
    protocol = str(getattr(request, "http_version", "") or "HTTP/1.1")
    return _sanitize_field(protocol) if protocol.upper().startswith("HTTP") else "HTTP/1.1"


def _response_header(response, name: str, default: str = "-") -> str:
    """A response header (Location, mostly) - the redirect target is the one
    thing a bare 3xx line otherwise leaves you guessing about."""
    if response is None:
        return default
    headers = getattr(response, "headers", None) or {}
    try:
        for key, value in headers.items():
            if str(key).lower() == name:
                return _sanitize_field(value, default)
    except Exception:
        return default
    return default


def _body_bytes(response) -> int:
    body = getattr(response, "body", None)
    if body is None:
        return 0
    try:
        return len(body)
    except Exception:
        return 0


def _emit(line: str) -> None:
    # Routed through terminal.emit() rather than print(): these lines come off
    # the HTTP threads while the interactive console is blocked in input(),
    # and a bare print lands in the middle of whatever is being typed.
    from .terminal import emit

    emit(line)


def log_request(request, status: int, body_bytes: int, duration_seconds: float, response=None) -> None:
    """Write one access line. Never raises."""
    if not ACCESS_LOG_ENABLED:
        return
    try:
        _emit(
            f"{_timestamp()} "
            f"{_protocol(request)} {_method(request)} {_target(request)} "
            f'ref={_header(request, "referer")} '
            f"loc={_response_header(response, 'location')} "
            f"{_colorize_status(status)}"
        )
    except Exception:
        pass


def log_response(request, response, started_at: float) -> None:
    """Log a completed HTTP response, timed from `started_at` (perf_counter)."""
    if not ACCESS_LOG_ENABLED:
        return
    status = getattr(response, "status", 0) or 0
    log_request(request, int(status), _body_bytes(response), time.perf_counter() - started_at, response=response)


def log_websocket_open(request) -> None:
    """Log the WebSocket handshake as the HTTP 101 it actually is."""
    log_request(request, 101, 0, 0.0)


def log_websocket_close(request, code: int, started_at: float) -> None:
    """Log the close of a WebSocket session, with its close code and how long
    it lasted."""
    if not ACCESS_LOG_ENABLED:
        return
    try:
        stamp = _timestamp()
        path = str(getattr(request, "path", "") or "/ws/")
        elapsed = max(0.0, time.perf_counter() - started_at)
        _emit(
            f"{stamp} WS CLOSE {path} "
            f"after={elapsed:.1f}s close={int(code)}"
        )
    except Exception:
        pass


def log_auth_failure(
    request,
    *,
    client: str = "",
    reason: str = "invalid_token",
    status: int = 401,
    retry_after: float = 0.0,
) -> None:
    """Write one security line per rejected authentication attempt.

    Every 401 used to leave the console completely silent, which meant a
    credential-guessing loop against the API or the WebSocket handshake was
    invisible to the operator watching the very sensor being attacked - the
    access line for the request said "401" with no source address and
    nothing tying repeated attempts together. `client` is the source
    address, `reason` separates a bad/absent token from a request already
    refused by the rate limiter, and `retry_after` is how long the source is
    locked out for (0 while it is still under the threshold).
    """
    if not ACCESS_LOG_ENABLED:
        return
    try:
        _emit(
            f"{_timestamp()} SECURITY AUTH-FAIL "
            f"{_protocol(request)} {_method(request)} {_target(request)} "
            f"client={_sanitize_field(client)} "
            f"reason={_sanitize_field(reason, 'unknown')} "
            f"retry_after={max(0.0, float(retry_after)):.0f}s "
            f"{_colorize_status(int(status))}"
        )
    except Exception:
        pass
