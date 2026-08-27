from __future__ import annotations

import ipaddress
import json
import math
import re
from datetime import datetime, timedelta, timezone


from .app_protocols import (
    ETHER_PROTOCOLS,
    SNAP_PROTOCOLS,
    IP_PROTOCOLS,
    TCP_PORT_PROTOCOLS,
    UDP_PORT_PROTOCOLS,
)

PRINTABLE_RE = re.compile(r"[^\x20-\x7E]+")


SINCE_WINDOW_RE = re.compile(r"^(\d+)\s*([smhdw])$", re.IGNORECASE)
SINCE_WINDOW_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def utc_since(seconds: float) -> str:
    """ISO-8601 timestamp `seconds` in the past, in the exact same format
    `utc_now()` writes into every `created_at` column - so a caller can
    compare the two as plain strings in SQL without a date() conversion
    that would defeat the index."""
    return (datetime.now(timezone.utc) - timedelta(seconds=float(seconds))).isoformat(timespec="seconds")


def parse_since_window(value) -> str:
    """Turns a relative window (`15m`, `1h`, `6h`, `24h`, `7d`) into the
    absolute ISO cutoff the store filters `created_at` against. Empty/None
    means "no temporal filter". Raises ValueError on anything else, so the
    API answers 400 instead of silently ignoring a typo and handing back a
    window the caller never asked for."""
    raw = str(value or "").strip()
    if not raw:
        return ""
    match = SINCE_WINDOW_RE.match(raw)
    if not match:
        raise ValueError(
            "since must be a relative window like '15m', '1h', '6h', '24h' or '7d'"
        )
    amount = int(match.group(1))
    if amount <= 0:
        raise ValueError("since window must be greater than zero")
    seconds = amount * SINCE_WINDOW_UNITS[match.group(2).lower()]
    return utc_since(seconds)


def ip_scope(value) -> str:
    """'local' / 'public' / 'unknown' for an address, via stdlib ipaddress
    rather than string prefixes - the old `startswith("10.")` check missed
    172.16/12, 169.254/16, 100.64/10, ::1 and fc00::/7, so a corporate
    172.20.x.x network classified entirely as "public"."""
    text = str(value or "").strip()
    if not text:
        return "unknown"
    try:
        address = ipaddress.ip_address(text)
    except Exception:
        return "unknown"
    if address.is_loopback or address.is_private or address.is_link_local or address.is_reserved:
        return "local"
    return "public"


DETECTION_IP_SCOPES = ("loopback", "private", "public")


def detection_ip_scope(value) -> str:
    """'loopback' / 'private' / 'public' / 'unknown' for one address.

    Separate from `ip_scope()` above, which deliberately collapses loopback
    and RFC1918 into a single "local" bucket for the dashboard's local-vs-
    remote split. The detection filter needs them apart: muting your own
    loopback chatter is a very different decision from muting the whole LAN.
    """
    text = str(value or "").strip()
    if not text:
        return "unknown"
    try:
        address = ipaddress.ip_address(text)
    except Exception:
        return "unknown"
    if address.is_loopback:
        return "loopback"
    # `is_global` rather than `not is_private`: CGNAT (100.64.0.0/10) and the
    # documentation ranges are neither private nor global in the stdlib, so a
    # `not is_private` test would file an ISP's carrier-grade NAT range as
    # public internet and keep alerting on it after the operator muted
    # "public". Anything not globally routable is "private" for this filter.
    return "public" if address.is_global else "private"


def clamp_int(value, minimum, maximum, default=None):
    try:
        number = int(value)
    except Exception:
        return default
    return max(int(minimum), min(int(maximum), number))


def safe_int(value, default=0):
    try:
        return int(value)
    except Exception:
        return int(default)


def safe_float(value, default=0.0):
    try:
        return float(value)
    except Exception:
        # `float(default)` would raise TypeError all over again for the
        # `safe_float(x, None)` callers - the "no value" sentinel used for
        # optional coordinates - turning a safe accessor into a crash.
        try:
            return float(default)
        except (TypeError, ValueError):
            return default


def json_dumps(value) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def json_loads(value, default=None):
    if value in (None, ""):
        return default
    try:
        return json.loads(value)
    except Exception:
        return default


def normalize_text(value, limit=240):
    raw = "" if value is None else str(value)
    cleaned = PRINTABLE_RE.sub(" ", raw).strip()
    cleaned = re.sub(r"\s+", " ", cleaned)
    if limit and len(cleaned) > limit:
        return cleaned[: max(0, int(limit) - 1)].rstrip() + "…"
    return cleaned


def bytes_to_hex_preview(payload: bytes, limit: int = 256, max_length: int | None = None) -> str:
    if not payload:
        return ""
    effective_limit = max_length if max_length is not None else limit
    return payload[: max(0, int(effective_limit))].hex()


def bytes_to_text_preview(payload: bytes, limit: int = 240) -> str:
    if not payload:
        return ""
    text = payload.decode("utf-8", errors="ignore")
    return normalize_text(text, limit=limit)


def format_mac(raw: bytes | bytearray | None) -> str:
    if not raw:
        return ""
    return ":".join(f"{byte:02x}" for byte in bytes(raw)[:6])


def is_printable_payload(payload: bytes) -> bool:
    if not payload:
        return False
    printable = 0
    for byte in payload[: min(len(payload), 128)]:
        if 32 <= byte <= 126 or byte in {9, 10, 13}:
            printable += 1
    return printable >= max(8, math.ceil(min(len(payload), 128) * 0.55))


def unique_ordered(values):
    seen = set()
    ordered = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        ordered.append(value)
    return ordered


# Every value Sniffer.parse_packet can write into packet["proto"], in the
# order the Protocols page should list them. Kept here (rather than in
# sniffer.py) so store.list_protocols()'s empty-database fallback and
# app.py's SPA route table can share one definition: a protocol missing from
# app.SPA_ROUTES answers a bare 404 on refresh, and every one of these but
# the first seven used to be missing.
# Protocols the capture pipeline can put in `packet["proto"]`.
#
# The link/network/transport names are listed here explicitly because they
# come from hand-written decoders in sniffer.py; everything above transport
# is derived from app_protocols' own tables instead of being re-typed, so a
# port or signature added there cannot end up producing a protocol the
# Protocols view has no route or card for (app.py builds /protocols/<name>
# straight off this tuple).
_CORE_PROTOCOLS = (
    "tcp",
    "udp",
    "sctp",
    "icmp",
    "icmpv6",
    "arp",
    "rarp",
    "ipv6",
    "igmp",
    "gre",
    "esp",
    "ah",
    "dhcp",
    "mdns",
    "llmnr",
    "nbns",
    "modbus",
    "dnp3",
    "snmp",
    "syslog",
    "tftp",
    "radius",
    "mqtt",
    "stp",
    "llc",
    "llc-snap",
)

_RESIDUAL_PROTOCOLS = ("unknown", "unparseable")

KNOWN_PROTOCOLS = (
    *_CORE_PROTOCOLS,
    *sorted(
        (
            set(TCP_PORT_PROTOCOLS.values())
            | set(UDP_PORT_PROTOCOLS.values())
            | set(IP_PROTOCOLS.values())
            | set(ETHER_PROTOCOLS.values())
            | set(SNAP_PROTOCOLS.values())
            # Signature-only answers: classify_tcp/classify_udp can return
            # these without the port tables ever mentioning them.
            | {"tls", "http", "ssh", "sip", "vnc", "telnet", "smb", "ssdp", "quic", "dns"}
        )
        - set(_CORE_PROTOCOLS)
    ),
    *_RESIDUAL_PROTOCOLS,
)


def normalize_protocol_name(value: str) -> str:
    return str(value or "").strip().lower() or "unknown"


def stable_flow_key(proto: str, src_ip: str, src_port, dst_ip: str, dst_port) -> str:
    left = f"{src_ip}:{src_port}"
    right = f"{dst_ip}:{dst_port}"
    if left <= right:
        ordered = (left, right)
    else:
        ordered = (right, left)
    return f"{normalize_protocol_name(proto)}|{ordered[0]}|{ordered[1]}"


def local_ip_candidates() -> set[str]:
    candidates = {"127.0.0.1", "::1"}
    try:
        import socket

        hostname = socket.gethostname()
        for family, _, _, _, sockaddr in socket.getaddrinfo(hostname, None):
            if not sockaddr:
                continue
            address = sockaddr[0]
            if isinstance(address, str):
                candidates.add(address)
    except Exception:
        pass
    return candidates


def is_probably_ipv4(text: str) -> bool:
    try:
        ipaddress.IPv4Address(str(text).strip())
        return True
    except Exception:
        return False


def is_probably_ipv6(text: str) -> bool:
    try:
        ipaddress.IPv6Address(str(text).strip())
        return True
    except Exception:
        return False
