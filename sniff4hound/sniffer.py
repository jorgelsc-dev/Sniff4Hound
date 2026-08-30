from __future__ import annotations

import ipaddress
import math
import re
import socket
import sqlite3
import threading
import time
from dataclasses import dataclass, field

from .anomaly import AnomalyEngine
from .logger import get_capture_logger
from .monitors import RuleAlertThrottle, ensure_monitor_index, evaluate_packet, indexed_monitors_by_id
from .rulesets import build_packet_text, classify_packet, literal_packet_text_pattern
from .settings import (
    CAPTURE_BUFFER_BYTES,
    CAPTURE_POLL_TIMEOUT,
    CAPTURE_PROMISCUOUS,
    MONITOR_MIN_SEVERITY_DEFAULT,
    MONITOR_SEVERITIES,
    MONITOR_SUPPRESS_GENERATED_INFO_DEFAULT,
    PAYLOAD_TEXT_MAX_CHARS,
)
from .app_decoders import decode as decode_app_payload
from .app_protocols import (
    ETHER_PROTOCOLS,
    SNAP_PROTOCOLS,
    IP_PROTOCOLS,
    classify_tcp,
    classify_udp,
)
from .utils import (
    detection_ip_scope,
    bytes_to_hex_preview,
    bytes_to_text_preview,
    format_mac,
    is_printable_payload,
    local_ip_candidates,
    normalize_protocol_name,
    normalize_text,
    safe_int,
    stable_flow_key,
    utc_now,
)


ETHERTYPE_VLAN = {0x8100, 0x88A8, 0x9100}
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_ARP = 0x0806
STP_MULTICAST_MAC = "01:80:c2:00:00:00"

# Protocols that live at layer 2 and are not carried over IP. The detection
# IP-scope filter deliberately has no say over these: ARP in particular does
# carry IPv4 addresses in its own payload, so without this list an operator
# excluding "private" silently loses every ARP frame on the segment.
LINK_LAYER_PROTOCOLS = frozenset(
    {
        "arp",
        "rarp",
        "stp",
        "llc",
        "llc-snap",
        "lldp",
        "cdp",
        "eapol",
        "loop",
        "wol",
    }
)
LLC_STP_HEADER = b"\x42\x42\x03"
MONITOR_SEVERITY_RANK = {severity: index for index, severity in enumerate(MONITOR_SEVERITIES)}
# IEEE 802.3: the two bytes after the MACs are a *length* when <= 1500, and an
# EtherType only when >= 1536. Values in between are undefined. Reading a
# length as an EtherType is what filed these frames as "unknown protocol".
ETHERNET_MAX_PAYLOAD_LENGTH = 1500
ETHERTYPE_MIN = 0x0600
# LLC service access points worth naming. 0xAA/0xAA + control 0x03 is SNAP,
# which carries a real EtherType and is handled separately.
LLC_SAP_NAMES = {
    0x00: "null",
    0x02: "llc-sublayer-mgmt",
    0x06: "ip",
    0x0E: "proway-nm",
    0x42: "stp",
    0x4E: "mms",
    0x7E: "x25",
    0x80: "xns",
    0x86: "nestar",
    0x8E: "proway",
    0x98: "arp",
    0xAA: "snap",
    0xBC: "vines",
    0xE0: "ipx",
    0xF0: "netbios",
    0xF4: "lan-mgmt",
    0xFE: "osi",
    0xFF: "ipx-raw",
}
LLC_SNAP_SAP = 0xAA
LLC_SNAP_CONTROL = 0x03
IP_PROTO_TCP = 6
IP_PROTO_UDP = 17
IP_PROTO_SCTP = 132
IP_PROTO_ICMP = 1
IP_PROTO_ICMPV6 = 58
IP_PROTO_IGMP = 2
IP_PROTO_GRE = 47
IP_PROTO_IPV6_HOP_BY_HOP = 0
IP_PROTO_IPV6_ROUTING = 43
IP_PROTO_IPV6_FRAGMENT = 44
IP_PROTO_IPV6_ESP = 50  # IP protocol 50 (ESP) — same number for IPv4 and IPv6, reused for both dispatches below
IP_PROTO_IPV6_AH = 51  # IP protocol 51 (AH) — same number for IPv4 and IPv6, reused for both dispatches below
IP_PROTO_IPV6_DESTINATION = 60
IP_PROTO_IPV6_MOBILITY = 135
IP_PROTO_IPV6_HIP = 139
IP_PROTO_IPV6_SHIM6 = 140
SOL_PACKET = 263
PACKET_ADD_MEMBERSHIP = 1
PACKET_MR_PROMISC = 1
ETH_P_ALL = 0x0003
MONITOR_CACHE_TTL_SECONDS = 2.0
# Cap on Sniffer._tls_flows (see its docstring) - a busy sniffed network can
# accumulate many thousands of concurrent flows; this is a best-effort
# memory, not a correctness-critical structure, so a wholesale clear once
# this cap is hit is preferable to the complexity of real LRU eviction.
TLS_FLOW_MEMORY_CAP = 20000
RULESET_CACHE_TTL_SECONDS = 2.0
STATS_BROADCAST_MIN_INTERVAL_SECONDS = 1.0

LOGGER = get_capture_logger()

HTTP_REQUEST_LINE_RE = re.compile(
    r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE)\s+(\S+)\s+HTTP/\d\.\d",
    re.IGNORECASE,
)
# Anchored on a preceding separator rather than on `^`+MULTILINE: the text
# this runs against is `packet["payload_text"]`, which normalize_text() has
# already flattened to a single line (CRLF collapsed to spaces). A `^` then
# only ever matches the very start of the request line, so the Host header
# was never found and `http_host` came back empty for every HTTP request -
# which in turn kept every HTTP-derived domain out of the catalog. Matching
# on "start of string, newline, or space" works on both the flattened text
# and the raw CRLF form. The separator class also keeps `X-Forwarded-Host:`
# (preceded by "-") from being mistaken for the real Host header.
HTTP_HOST_HEADER_RE = re.compile(r"(?:^|[\r\n ])Host:[ \t]*([^\r\n ]+)", re.IGNORECASE)


def extract_http_request(text: str) -> tuple[str, str, str]:
    if not text:
        return "", "", ""
    match = HTTP_REQUEST_LINE_RE.match(text.strip())
    if not match:
        return "", "", ""
    method = match.group(1).upper()
    path = match.group(2).strip()
    host_match = HTTP_HOST_HEADER_RE.search(text)
    host = host_match.group(1).strip() if host_match else ""
    return method, path, host


def extract_dns_query_name(payload: bytes) -> str:
    try:
        if len(payload) < 12:
            return ""
        is_response = bool(payload[2] & 0x80)
        if is_response:
            # Responses echo the question section too, but src/dst are
            # reversed from the query (server -> client). Only extract from
            # the query itself so the resolver's IP:53 is what gets recorded,
            # not the client's own address and ephemeral port.
            return ""
        qdcount = int.from_bytes(payload[4:6], "big")
        if qdcount < 1:
            return ""
        offset = 12
        labels = []
        while offset < len(payload):
            length = payload[offset]
            if length == 0:
                offset += 1
                break
            if length & 0xC0:
                return ""
            offset += 1
            if offset + length > len(payload):
                return ""
            label = payload[offset : offset + length]
            if not label.isascii():
                return ""
            labels.append(label.decode("ascii"))
            offset += length
            if offset > 512:
                return ""
        name = ".".join(labels).strip(".").lower()
        if not name or not name.isprintable():
            return ""
        return name
    except Exception:
        return ""


def _looks_like_tls_record(payload: bytes) -> bool:
    """True for any TLS record (ContentType + ProtocolVersion header:
    handshake 0x16, application data 0x17, alert 0x15, change-cipher-spec
    0x14, each followed by 0x03 0x00-0x04 for SSLv3/TLS1.0-1.3) - not just
    the ClientHello case _classify_tcp_banner already special-cases.

    Only the handshake's ClientHello is ever meaningfully cleartext (that's
    what extract_tls_sni parses, straight off the raw bytes - unaffected by
    this function). Everything else, and above all TLS Application Data
    (0x17) - the bulk of any HTTPS session after the handshake completes -
    is ciphertext: uniformly random bytes that, sampled over is_printable_
    payload's 128-byte window, pass the "mostly printable ASCII" check
    often enough to be decoded as pseudo-readable garbage. That garbage
    then coincidentally matches all kinds of unrelated monitor content/
    regex patterns (a stray "google.com"-shaped run, a 2-letter country
    code, a TLD suffix) - a real, observed false-positive source across
    many monitors, not a hypothetical one. Skip it entirely rather than
    let it enter payload_text/summary/banner_text at all.
    """
    return len(payload) >= 3 and payload[0] in (0x14, 0x15, 0x16, 0x17) and payload[1] == 0x03 and payload[2] <= 0x04


def extract_tls_sni(payload: bytes) -> str:
    try:
        if len(payload) < 44 or payload[0] != 0x16:
            return ""
        if payload[5] != 0x01:
            return ""
        pos = 9
        pos += 2 + 32
        if pos >= len(payload):
            return ""
        session_id_len = payload[pos]
        pos += 1 + session_id_len
        if pos + 2 > len(payload):
            return ""
        cipher_len = int.from_bytes(payload[pos : pos + 2], "big")
        pos += 2 + cipher_len
        if pos >= len(payload):
            return ""
        comp_len = payload[pos]
        pos += 1 + comp_len
        if pos + 2 > len(payload):
            return ""
        ext_total_len = int.from_bytes(payload[pos : pos + 2], "big")
        pos += 2
        end = min(pos + ext_total_len, len(payload))
        while pos + 4 <= end:
            ext_type = int.from_bytes(payload[pos : pos + 2], "big")
            ext_len = int.from_bytes(payload[pos + 2 : pos + 4], "big")
            ext_data_start = pos + 4
            if ext_type == 0x0000 and ext_data_start + 2 <= end:
                p = ext_data_start + 2
                if p + 3 <= end:
                    name_type = payload[p]
                    name_len = int.from_bytes(payload[p + 1 : p + 3], "big")
                    p += 3
                    if name_type == 0 and p + name_len <= end:
                        name = payload[p : p + name_len]
                        if name.isascii():
                            return name.decode("ascii").strip().lower()
                return ""
            pos = ext_data_start + ext_len
        return ""
    except Exception:
        return ""


ARP_OPERATIONS = {
    1: "request", 2: "reply",
    3: "RARP request", 4: "RARP reply",
    8: "InARP request", 9: "InARP reply",
}
ARP_HW_TYPES = {1: "Ethernet", 6: "IEEE 802", 15: "Frame Relay", 16: "ATM", 17: "HDLC"}

DNS_QTYPE_NAMES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
    16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY",
}
DNS_RCODE_NAMES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
DHCP_MSG_TYPES = {
    1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE",
    5: "ACK", 6: "NAK", 7: "RELEASE", 8: "INFORM",
}
IGMP_TYPE_NAMES = {
    0x11: "membership query",
    0x12: "v1 membership report",
    0x16: "v2 membership report",
    0x17: "leave group",
    0x22: "v3 membership report",
}

# --- ICS/SCADA and infrastructure protocol tables -------------------------

MODBUS_FUNCTION_NAMES = {
    1: "read-coils", 2: "read-discrete-inputs", 3: "read-holding-registers",
    4: "read-input-registers", 5: "write-single-coil", 6: "write-single-register",
    7: "read-exception-status", 8: "diagnostics", 11: "get-comm-event-counter",
    15: "write-multiple-coils", 16: "write-multiple-registers",
    17: "report-server-id", 20: "read-file-record", 21: "write-file-record",
    22: "mask-write-register", 23: "read-write-multiple-registers",
    24: "read-fifo-queue", 43: "encapsulated-interface-transport",
}
# Function codes that change process state on the target device - the
# single highest-value signal a passive ICS monitor can surface.
MODBUS_WRITE_FUNCTION_CODES = {5, 6, 15, 16, 21, 22, 23}

DNP3_START = b"\x05\x64"
DNP3_FUNCTION_NAMES = {
    0: "confirm", 1: "read", 2: "write", 3: "select", 4: "operate",
    5: "direct-operate", 6: "direct-operate-noack", 7: "immediate-freeze",
    8: "immediate-freeze-noack", 9: "freeze-clear", 10: "freeze-clear-noack",
    11: "freeze-at-time", 12: "freeze-at-time-noack", 13: "cold-restart",
    14: "warm-restart", 15: "initialize-data", 16: "initialize-application",
    17: "start-application", 18: "stop-application", 19: "save-configuration",
    20: "enable-unsolicited", 21: "disable-unsolicited", 22: "assign-class",
    23: "delay-measure", 24: "record-current-time", 129: "response",
    130: "unsolicited-response",
}
DNP3_RESTART_FUNCTION_CODES = {13, 14}

TFTP_OPCODE_NAMES = {1: "RRQ", 2: "WRQ", 3: "DATA", 4: "ACK", 5: "ERROR", 6: "OACK"}

RADIUS_CODE_NAMES = {
    1: "Access-Request", 2: "Access-Accept", 3: "Access-Reject",
    4: "Accounting-Request", 5: "Accounting-Response", 11: "Access-Challenge",
    12: "Status-Server", 13: "Status-Client",
}

MQTT_PACKET_TYPE_NAMES = {
    1: "CONNECT", 2: "CONNACK", 3: "PUBLISH", 4: "PUBACK", 5: "PUBREC",
    6: "PUBREL", 7: "PUBCOMP", 8: "SUBSCRIBE", 9: "SUBACK", 10: "UNSUBSCRIBE",
    11: "UNSUBACK", 12: "PINGREQ", 13: "PINGRESP", 14: "DISCONNECT",
}

SYSLOG_SEVERITY_NAMES = {
    0: "emergency", 1: "alert", 2: "critical", 3: "error",
    4: "warning", 5: "notice", 6: "info", 7: "debug",
}


def _read_dns_name(payload: bytes, offset: int, *, max_jumps: int = 20) -> tuple[str, int]:
    """Decode a (possibly compressed) DNS name starting at `offset`.

    Returns (name, offset_after_the_name_as_it_appears_at_the_call_site) — the
    second value follows only the FIRST compression pointer encountered (or the
    terminating zero length if there was none), per RFC 1035 §4.1.4, so callers
    can keep walking the rest of the message correctly even when this name used
    compression.
    """
    labels: list[str] = []
    jumps = 0
    resume_at: int | None = None
    pos = offset
    while True:
        if pos < 0 or pos >= len(payload):
            break
        length = payload[pos]
        if length == 0:
            pos += 1
            if resume_at is None:
                resume_at = pos
            break
        if (length & 0xC0) == 0xC0:
            if pos + 1 >= len(payload):
                break
            pointer = ((length & 0x3F) << 8) | payload[pos + 1]
            if resume_at is None:
                resume_at = pos + 2
            jumps += 1
            if jumps > max_jumps or pointer >= len(payload) or pointer == pos:
                break
            pos = pointer
            continue
        pos += 1
        if pos + length > len(payload):
            break
        label = bytes(payload[pos : pos + length])
        pos += length
        try:
            labels.append(label.decode("ascii"))
        except Exception:
            labels.append(label.decode("latin-1", errors="replace"))
        if len(labels) > 128:
            break
    name = ".".join(labels).strip(".").lower()
    if resume_at is None:
        resume_at = pos
    return name, resume_at


def _dns_rdata_preview(rtype: int, rdata: bytes, full_payload: bytes, rdata_offset: int) -> str:
    try:
        if rtype == 1 and len(rdata) == 4:  # A
            return str(ipaddress.IPv4Address(rdata))
        if rtype == 28 and len(rdata) == 16:  # AAAA
            return str(ipaddress.IPv6Address(rdata))
        if rtype in (2, 5, 12):  # NS, CNAME, PTR — a (possibly compressed) name
            name, _ = _read_dns_name(full_payload, rdata_offset)
            return name
        if rtype == 16:  # TXT
            texts = []
            pos = 0
            while pos < len(rdata):
                length = rdata[pos]
                pos += 1
                texts.append(rdata[pos : pos + length].decode("ascii", errors="replace"))
                pos += length
            return " ".join(texts)
        return rdata.hex()[:64]
    except Exception:
        return rdata.hex()[:64] if rdata else ""


def parse_dns_message(payload: bytes) -> dict:
    """Full-ish DNS message parser: question + answer records, for both
    queries AND responses (unlike `extract_dns_query_name`, which only reads
    the query leg and is kept as-is for backward compatibility)."""
    result = {"is_response": False, "rcode": 0, "questions": [], "answers": []}
    try:
        if len(payload) < 12:
            return result
        flags = int.from_bytes(payload[2:4], "big")
        result["is_response"] = bool(flags & 0x8000)
        result["rcode"] = flags & 0x000F
        qdcount = int.from_bytes(payload[4:6], "big")
        ancount = int.from_bytes(payload[6:8], "big")
        offset = 12
        questions = []
        for _ in range(min(qdcount, 32)):
            if offset >= len(payload):
                break
            name, offset = _read_dns_name(payload, offset)
            if offset + 4 > len(payload):
                break
            qtype = int.from_bytes(payload[offset : offset + 2], "big")
            qclass = int.from_bytes(payload[offset + 2 : offset + 4], "big")
            offset += 4
            questions.append({"name": name, "qtype": qtype, "qclass": qclass})
        result["questions"] = questions
        answers = []
        for _ in range(min(ancount, 32)):
            if offset >= len(payload):
                break
            name, offset = _read_dns_name(payload, offset)
            if offset + 10 > len(payload):
                break
            rtype = int.from_bytes(payload[offset : offset + 2], "big")
            ttl = int.from_bytes(payload[offset + 4 : offset + 8], "big")
            rdlength = int.from_bytes(payload[offset + 8 : offset + 10], "big")
            offset += 10
            rdata = payload[offset : offset + rdlength] if offset + rdlength <= len(payload) else b""
            rdata_preview = _dns_rdata_preview(rtype, rdata, payload, offset)
            offset += rdlength
            answers.append({"name": name, "qtype": rtype, "ttl": ttl, "rdata": rdata_preview})
        result["answers"] = answers
    except Exception:
        pass
    return result


def _dns_message_summary(prefix: str, parsed: dict) -> str:
    if parsed.get("questions"):
        question = parsed["questions"][0]
        qtype_name = DNS_QTYPE_NAMES.get(question["qtype"], str(question["qtype"]))
        kind = "response" if parsed.get("is_response") else "query"
        base = f"{prefix} {kind} {question['name']} {qtype_name}"
    else:
        base = f"{prefix} message"
    if parsed.get("is_response"):
        answers = parsed.get("answers") or []
        if answers:
            base += f" -> {answers[0]['rdata']}"
        rcode = parsed.get("rcode") or 0
        if rcode:
            base += f" [{DNS_RCODE_NAMES.get(rcode, str(rcode))}]"
    return base


def decode_nbns_name(encoded: bytes) -> str:
    """Decode an RFC 1002 §4.1 "first-level encoded" NBNS name (32 half-ASCII
    nibble-pair bytes) — an entirely different wire format from DNS labels,
    so this does NOT reuse `_read_dns_name`."""
    try:
        if len(encoded) != 32:
            return ""
        chars = []
        for i in range(0, 32, 2):
            hi = encoded[i] - 0x41
            lo = encoded[i + 1] - 0x41
            if not (0 <= hi <= 15 and 0 <= lo <= 15):
                return ""
            chars.append(chr((hi << 4) | lo))
        return "".join(chars).rstrip("\x00").rstrip()
    except Exception:
        return ""


@dataclass
class CaptureState:
    running: bool = False
    interfaces: list[str] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)
    packets_seen: int = 0
    packets_total_bytes: int = 0
    packets_stored: int = 0
    # Frames the parser could not make sense of, in total and per interface.
    # A frame that fails to parse is not just a curiosity: a sudden spike is
    # what deliberate malformed/fuzzed traffic aimed at evading or crashing
    # the sensor looks like from the inside, and until now the only trace of
    # one was a line in the JSON log nobody watches.
    packets_unparseable: int = 0
    unparseable_by_interface: dict[str, int] = field(default_factory=dict)
    last_unparseable_at: str = ""
    started_at: str = ""
    last_packet_at: str = ""


def build_base_packet(
    now: str,
    interface: str,
    data: bytes,
    payload: bytes,
    *,
    eth_src: str = "",
    eth_dst: str = "",
    eth_type: int = 0,
) -> dict:
    """Build the flat ~35-key packet dict shared by every capture path.

    Extracted out of `Sniffer._new_packet` (which is now a thin wrapper around
    this) so any capture path can build a schema-compatible packet dict
    without duplicating this literal or depending on a `Sniffer` instance.
    """
    return {
        "session_id": 0,
        "interface": str(interface or "").strip(),
        "eth_src": eth_src,
        "eth_dst": eth_dst,
        "eth_type": eth_type,
        "ip_version": 0,
        "src_ip": "",
        "dst_ip": "",
        "proto": "unknown",
        # Transport that carried the frame, kept alongside `proto` because
        # `proto` holds the *application* protocol once one is identified
        # (http, tls, dns...). Without this, a rule matching
        # protocols:["tcp"] stops seeing every segment whose application
        # protocol was recognised - which is exactly how the builtin SNMP
        # monitor silently stopped firing once _parse_snmp set proto="snmp".
        "transport": "",
        "src_port": 0,
        "dst_port": 0,
        "ttl": 0,
        "hop_limit": 0,
        "length": len(data),
        "payload_len": len(payload),
        "state": "filtered" if not payload else "open",
        "scan_state": "active",
        "tcp_flags": "",
        "icmp_type": 0,
        "icmp_code": 0,
        "arp_opcode": 0,
        "summary": "",
        "payload_text": "",
        "payload_hex": bytes_to_hex_preview(payload),
        "banner_text": "",
        "direction": "unknown",
        "domain": "",
        "domain_source": "",
        "http_method": "",
        "http_path": "",
        "http_host": "",
        "raw_packet": data[:],
        "created_at": now,
        "updated_at": now,
    }


class Sniffer:
    def __init__(self, store, hub, *, interfaces: tuple[str, ...] = ()):
        self.store = store
        self.hub = hub
        self._allowed_interfaces = tuple(
            str(interface).strip()
            for interface in (interfaces or ())
            if str(interface).strip()
        )
        self._selected_interfaces: tuple[str, ...] = ()
        self._stop_event = threading.Event()
        self._threads: list[threading.Thread] = []
        self._state_lock = threading.RLock()
        self.state = CaptureState()
        self._local_ips = local_ip_candidates()
        self._monitor_cache: list[dict] = []
        self._whitelist_cache: list[dict] = []
        self._monitor_filter_enabled = True
        self._monitor_min_severity = MONITOR_MIN_SEVERITY_DEFAULT
        self._monitor_suppress_generated_info = MONITOR_SUPPRESS_GENERATED_INFO_DEFAULT
        self._detection_exclude_scopes: frozenset[str] = frozenset()
        self._monitor_cache_at = 0.0
        self._monitor_refresh_lock = threading.Lock()
        self._monitor_refresh_in_flight = False
        self._ruleset_cache: list[dict] = []
        self._ruleset_cache_at = 0.0
        self._last_stats_broadcast_at = 0.0
        self._anomaly = AnomalyEngine()
        self._rule_throttle = RuleAlertThrottle()
        # Per-flow "this TCP flow is carrying TLS" memory. A single TLS
        # record (especially Application Data, the bulk of any HTTPS
        # session after the handshake) is routinely larger than one Ethernet
        # frame and spans several TCP segments - only the *first* segment of
        # that record starts with the TLS record header
        # (_looks_like_tls_record checks byte 0/1/2), so a purely
        # per-packet check misses every continuation segment, whose leading
        # bytes are just more ciphertext with no header at all. Those
        # continuation segments then decode as printable-looking garbage
        # (is_printable_payload's 55%-of-first-128-bytes heuristic clears
        # often enough on random bytes) and can coincidentally trigger
        # unrelated monitor content/regex matches - a real false-positive
        # source confirmed against live captured traffic. Once any segment
        # on a flow is recognized as a TLS record, every later segment on
        # that same flow is treated as opaque too, closing that gap.
        # Bounded and cleared wholesale rather than LRU-evicted: this is a
        # best-effort optimization for a live capture session, not a
        # correctness-critical structure - an occasional false "not TLS"
        # right after a clear is fine, and far simpler than real eviction.
        self._tls_flows: dict[str, float] = {}
        self._tls_flows_lock = threading.Lock()

    def _discover_interfaces(self) -> list[str]:
        try:
            names = [name for _, name in socket.if_nameindex()]
            if names:
                return names
        except Exception:
            pass
        return ["lo"]

    def list_available_interfaces(self) -> list[str]:
        if self._allowed_interfaces:
            return list(self._allowed_interfaces)
        return self._discover_interfaces()

    def list_interfaces(self) -> list[str]:
        if self._selected_interfaces:
            return list(self._selected_interfaces)
        return self.list_available_interfaces()

    def set_interfaces(self, interfaces=None):
        raw_items = interfaces
        if raw_items is None:
            raw_items = []
        elif isinstance(raw_items, str):
            raw_items = [raw_items]

        available = set(self.list_available_interfaces())
        normalized: list[str] = []
        seen: set[str] = set()
        for item in raw_items:
            value = str(item or "").strip()
            if not value or value in seen:
                continue
            if value not in available:
                raise ValueError(f"Unknown interface: {value}")
            normalized.append(value)
            seen.add(value)
        with self._state_lock:
            self._selected_interfaces = tuple(normalized)
        return self.snapshot()

    def set_interface(self, interface: str = ""):
        selected = str(interface or "").strip()
        return self.set_interfaces([selected] if selected else [])

    def selected_interfaces(self) -> list[str]:
        with self._state_lock:
            return list(self._selected_interfaces)

    def selected_interface(self) -> str:
        selected = self.selected_interfaces()
        return selected[0] if len(selected) == 1 else ""

    def selected_interfaces_label(self) -> str:
        selected = self.selected_interfaces()
        if not selected:
            return "all interfaces"
        if len(selected) == 1:
            return selected[0]
        return f"{len(selected)} interfaces"

    def snapshot(self):
        with self._state_lock:
            selected = list(self._selected_interfaces)
            available = self.list_available_interfaces()
            active_threads = sum(1 for thread in self._threads if thread.is_alive())
            errors = dict(self.state.errors)
            capture_state = "idle"
            if self.state.running and active_threads > 0:
                capture_state = "running"
            elif self.state.running and errors:
                capture_state = "blocked"
            return {
                "running": bool(self.state.running),
                "capture_state": capture_state,
                "interfaces": list(self.state.interfaces),
                "available_interfaces": available,
                "selected_interfaces": selected,
                "selected_interface": selected[0] if len(selected) == 1 else "",
                "errors": errors,
                "packets_seen": int(self.state.packets_seen),
                "packets_total_bytes": int(self.state.packets_total_bytes),
                "packets_stored": int(self.state.packets_stored),
                "packets_unparseable": int(self.state.packets_unparseable),
                "unparseable_by_interface": dict(self.state.unparseable_by_interface),
                "last_unparseable_at": self.state.last_unparseable_at,
                "started_at": self.state.started_at,
                "last_packet_at": self.state.last_packet_at,
                "active_threads": active_threads,
            }

    def start(self):
        with self._state_lock:
            if self.state.running:
                return self.snapshot()
            self._stop_event.clear()
            self.state.running = True
            self.state.interfaces = self.list_interfaces()
            self.state.errors = {}
            self.state.started_at = utc_now()
            self.state.last_packet_at = ""
            self.state.packets_seen = 0
            self.state.packets_total_bytes = 0
            self.state.packets_stored = 0
            self.state.packets_unparseable = 0
            self.state.unparseable_by_interface = {}
            self.state.last_unparseable_at = ""
            threads = []
            for interface in self.state.interfaces:
                thread = threading.Thread(
                    target=self._capture_worker,
                    args=(interface,),
                    name=f"sniff4hound-capture-{interface}",
                    daemon=True,
                )
                thread.start()
                threads.append(thread)
            self._threads = threads
        return self.snapshot()

    def stop(self):
        self._stop_event.set()
        with self._state_lock:
            self.state.running = False
        for thread in list(self._threads):
            if thread.is_alive():
                thread.join(timeout=0.8)
        self._threads = []
        return self.snapshot()

    def restart(self):
        self.stop()
        return self.start()

    def _set_error(self, interface: str, message: str):
        with self._state_lock:
            self.state.errors[str(interface)] = str(message)

    def _touch_packet(self, packet: dict, *, stored: bool = False):
        payload_len = safe_int(packet.get("payload_len", 0), 0)
        length = safe_int(packet.get("length", 0), 0)
        with self._state_lock:
            self.state.packets_seen += 1
            self.state.packets_total_bytes += max(length, payload_len)
            if stored:
                self.state.packets_stored += 1
            self.state.last_packet_at = utc_now()

    def _broadcast_packet(self, packet: dict, *, persisted: bool = True):
        event = {
            "type": "packet",
            "packet": packet,
            "persisted": bool(persisted),
            "generated_at": utc_now(),
        }
        self.hub.broadcast(event)
        self._broadcast_stats()

    def _broadcast_stats_throttled(self):
        now = time.monotonic()
        if now - self._last_stats_broadcast_at < STATS_BROADCAST_MIN_INTERVAL_SECONDS:
            return
        self._last_stats_broadcast_at = now
        self._broadcast_stats()

    def _broadcast_stats(self):
        self.hub.broadcast(
            {
                "type": "stats_update",
                "stats": {
                    "packets_seen": self.state.packets_seen,
                    "packets_total_bytes": self.state.packets_total_bytes,
                    "packets_stored": self.state.packets_stored,
                    "packets_unparseable": self.state.packets_unparseable,
                    "unparseable_by_interface": dict(self.state.unparseable_by_interface),
                },
                "generated_at": utc_now(),
            }
        )

    def _get_monitor_context(self):
        now = time.monotonic()
        if now - self._monitor_cache_at >= MONITOR_CACHE_TTL_SECONDS:
            # store.list_monitors() - a full SELECT plus a JSON decode of
            # two columns per row - runs in well under a millisecond at a
            # few dozen monitors, but at the full catalog size (tens of
            # thousands) it costs well over a second. This method runs on
            # the capture thread for every packet whose TTL has expired, so
            # doing that fetch here synchronously would stall live capture
            # for that long every refresh. Kick it off in the background
            # instead and keep serving the last-known-good cache (atomic
            # attribute swap, no lock needed on this read side) until it's
            # ready - a monitor add/edit lags a refresh cycle or two before
            # it's live, which is a far better trade than blocking capture.
            #
            # The very first fetch (cold start, nothing cached yet) is the
            # one exception: there's no last-known-good cache to fall back
            # to, so it runs synchronously, same as before this catalog
            # grew - a one-time, once-per-Sniffer-instance cost.
            cold_start = self._monitor_cache_at == 0.0
            self._monitor_cache_at = now
            if cold_start:
                self._refresh_monitor_cache()
            else:
                with self._monitor_refresh_lock:
                    already_refreshing = self._monitor_refresh_in_flight
                    self._monitor_refresh_in_flight = True
                if not already_refreshing:
                    threading.Thread(
                        target=self._refresh_monitor_cache,
                        daemon=True,
                        name="sniff4hound-monitor-refresh",
                    ).start()
        return self._monitor_cache, self._monitor_filter_enabled

    def _filter_monitor_hits(self, hits: list[dict]) -> list[dict]:
        if not hits:
            return hits
        min_rank = MONITOR_SEVERITY_RANK.get(self._monitor_min_severity, 0)
        filtered = []
        for hit in hits:
            severity = str(hit.get("severity") or "info").strip().lower()
            rank = MONITOR_SEVERITY_RANK.get(severity, 0)
            if rank < min_rank:
                continue
            monitor_id = str(hit.get("monitor_id") or "").strip()
            if (
                self._monitor_suppress_generated_info
                and monitor_id.startswith("builtin-signal-")
                and severity in {"info", "low"}
            ):
                continue
            filtered.append(hit)
        return filtered

    def _detection_muted(self, packet: dict) -> bool:
        """True when this packet's traffic falls entirely inside an excluded
        IP scope.

        Both endpoints have to match: muting "private" should silence LAN
        chatter, but a private host talking to a public address is exactly
        the traffic an analyst still wants flagged, so a packet with one end
        outside the excluded scopes still gets detected. An address that
        cannot be classified ("unknown") never mutes anything.

        Link-layer protocols are exempt outright. ARP carries IPv4 addresses
        in its own payload (see _parse_arp), so excluding "private" used to
        silence every ARP frame on the segment - which is neither an IP scope
        decision nor what the operator asked for: it emptied the Protocols
        page's ARP slice and starved host discovery (Radar/Map) of the very
        traffic builtin-l2-discovery exists to keep. An IP-scope filter has
        no jurisdiction over a protocol that is not IP.
        """
        scopes = self._detection_exclude_scopes
        if not scopes:
            return False
        proto = normalize_protocol_name(packet.get("proto"))
        # "llc-<dsap>" (llc-ipx, llc-netbios, ...) is named per DSAP by
        # _parse_llc, so match the family by prefix rather than listing them.
        if proto in LINK_LAYER_PROTOCOLS or proto.startswith("llc-"):
            return False
        src = detection_ip_scope(packet.get("src_ip"))
        dst = detection_ip_scope(packet.get("dst_ip"))
        if src == "unknown" or dst == "unknown":
            return False
        return src in scopes and dst in scopes

    def _whitelist_entry_matches_packet(self, entry: dict, packet: dict, *, packet_text: str | None = None) -> bool:
        if not entry or not entry.get("enabled", True):
            return False
        category = str(entry.get("category") or "").strip().lower()
        value = str(entry.get("value") or "").strip()
        if not category or not value:
            return False
        is_regex = str(entry.get("match_type") or "exact").strip().lower() == "regex"
        if category == "ip":
            src_ip = str(packet.get("src_ip") or "").strip().lower()
            dst_ip = str(packet.get("dst_ip") or "").strip().lower()
            if is_regex:
                try:
                    pattern = re.compile(value)
                except re.error:
                    return False
                return bool(pattern.search(src_ip) or pattern.search(dst_ip))
            wanted = value.lower()
            return src_ip == wanted or dst_ip == wanted
        if category not in ("domain", "path"):
            return False
        if packet_text is None:
            packet_text = build_packet_text(packet)
        if is_regex:
            try:
                return bool(re.search(value, packet_text, flags=re.IGNORECASE))
            except re.error:
                return False
        pattern = literal_packet_text_pattern(value.lower())
        return bool(re.search(pattern, packet_text))

    def _whitelisted(self, packet: dict) -> bool:
        entries = self._whitelist_cache
        if not entries:
            return False
        packet_text = None
        for entry in entries:
            if self._whitelist_entry_matches_packet(entry, packet, packet_text=packet_text):
                return True
            category = str(entry.get("category") or "").strip().lower()
            if category in ("domain", "path"):
                packet_text = packet_text if packet_text is not None else build_packet_text(packet)
        return False

    def _refresh_monitor_cache(self):
        try:
            monitors = self.store.list_monitors()
            list_whitelist = getattr(self.store, "list_whitelist_entries", None)
            whitelist = list_whitelist() if callable(list_whitelist) else []
            if not isinstance(whitelist, list):
                whitelist = []
            filter_enabled = self.store.get_monitor_filter_enabled()
            get_min_severity = getattr(self.store, "get_monitor_min_severity", None)
            get_suppress_generated_info = getattr(self.store, "get_monitor_suppress_generated_info", None)
            min_severity = get_min_severity() if callable(get_min_severity) else MONITOR_MIN_SEVERITY_DEFAULT
            suppress_generated_info = (
                get_suppress_generated_info()
                if callable(get_suppress_generated_info)
                else MONITOR_SUPPRESS_GENERATED_INFO_DEFAULT
            )
            exclude_scopes = frozenset(self.store.get_detection_exclude_scopes())
            # Builds/refreshes monitors.evaluate_packet()'s content index
            # for this exact list object; its own expensive part (the
            # multi-pattern automaton) is itself built in a further
            # background thread - see that module.
            ensure_monitor_index(monitors)
            self._monitor_cache = monitors
            self._whitelist_cache = whitelist
            self._monitor_filter_enabled = filter_enabled
            self._monitor_min_severity = min_severity
            self._monitor_suppress_generated_info = suppress_generated_info
            self._detection_exclude_scopes = exclude_scopes
        except sqlite3.ProgrammingError as exc:
            if "closed database" in str(exc).lower():
                LOGGER.debug("Skipped monitor refresh after store close")
            else:
                LOGGER.exception("Failed to refresh monitors")
        except Exception:
            LOGGER.exception("Failed to refresh monitors")
        finally:
            with self._monitor_refresh_lock:
                self._monitor_refresh_in_flight = False

    def _get_rulesets(self):
        now = time.monotonic()
        if now - self._ruleset_cache_at >= RULESET_CACHE_TTL_SECONDS:
            try:
                self._ruleset_cache = self.store.list_rulesets()
            except Exception:
                LOGGER.exception("Failed to refresh rulesets")
            self._ruleset_cache_at = now
        return self._ruleset_cache

    def _capture_worker(self, interface: str):
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, CAPTURE_BUFFER_BYTES)
            sock.settimeout(CAPTURE_POLL_TIMEOUT)
            try:
                sock.bind((interface, 0))
            except Exception as exc:
                self._set_error(interface, f"bind failed: {exc}")
            if CAPTURE_PROMISCUOUS:
                self._enable_promiscuous(sock, interface)
        except PermissionError as exc:
            self._set_error(interface, f"permission denied: {exc}")
            return
        except Exception as exc:
            self._set_error(interface, f"socket unavailable: {exc}")
            return

        while not self._stop_event.is_set():
            try:
                data, _ = sock.recvfrom(CAPTURE_BUFFER_BYTES)
            except socket.timeout:
                continue
            except OSError as exc:
                if self._stop_event.is_set():
                    break
                self._set_error(interface, str(exc))
                continue
            if not data:
                continue
            try:
                packet = self.parse_packet(data, interface=interface)
            except Exception as exc:
                # A parser bug on one malformed frame must never take down
                # the whole capture thread - fall back to a taggable
                # "unparseable" record instead of letting the exception
                # propagate out of the loop.
                LOGGER.exception("Failed to parse captured frame on %s", interface)
                packet = self._build_unparseable_packet(interface, data, reason=str(exc) or type(exc).__name__)
            if not packet:
                packet = self._build_unparseable_packet(interface, data, reason="frame too short to parse")
            try:
                self._store_packet(packet)
            except Exception:
                LOGGER.exception("Failed to process captured packet on %s", interface)

        try:
            sock.close()
        except Exception:
            pass

    def _build_unparseable_packet(self, interface: str, data: bytes, *, reason: str) -> dict:
        """A frame that either raised while parsing or was too short to even
        attempt (`parse_packet` returning `None`) - still worth a record so
        it's visible/taggable rather than silently vanishing, tagged
        distinctly from `proto="unknown"` (a *recognized* structure with an
        unrecognized protocol number)."""
        self._count_unparseable(interface)
        packet = build_base_packet(utc_now(), interface, data, data)
        packet["proto"] = "unparseable"
        packet["parse_error"] = reason
        summary = f"Unparseable frame ({len(data)}B): {reason}"
        packet["summary"] = summary
        packet["banner_text"] = summary
        return self._finalize_packet(packet)

    def _count_unparseable(self, interface: str) -> None:
        """Per-interface tally of frames the parser rejected, surfaced by
        `snapshot()` and the `stats_update` event so a burst of malformed
        frames on one interface is visible on the dashboard instead of only
        in the JSON log."""
        name = str(interface or "").strip() or "unknown"
        with self._state_lock:
            self.state.packets_unparseable += 1
            self.state.unparseable_by_interface[name] = int(self.state.unparseable_by_interface.get(name, 0)) + 1
            self.state.last_unparseable_at = utc_now()

    def _enable_promiscuous(self, sock, interface: str):
        try:
            ifindex = socket.if_nametoindex(interface)
        except Exception:
            return
        try:
            ifindex_bytes = int(ifindex).to_bytes(4, "little", signed=True)
            req_type = int(PACKET_MR_PROMISC).to_bytes(2, "little", signed=False)
            req_alen = (0).to_bytes(2, "little", signed=False)
            req_addr = bytes(8)
            sock.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, ifindex_bytes + req_type + req_alen + req_addr)
        except Exception as exc:
            self._set_error(interface, f"promiscuous mode unavailable: {exc}")


    def _store_packet(self, packet: dict):
        monitors, filter_enabled = self._get_monitor_context()
        detection_muted = self._detection_muted(packet) or self._whitelisted(packet)
        if detection_muted:
            matches = []
            monitor_hits = []
        else:
            rulesets = self._get_rulesets()
            matches = classify_packet(packet, rulesets)
            monitor_hits = evaluate_packet(packet, monitors) if filter_enabled else []
            monitor_hits = self._filter_monitor_hits(monitor_hits)
            if monitor_hits:
                monitor_hits = self._rule_throttle.filter(monitor_hits, packet.get("src_ip"))
            # Anomaly detectors run unconditionally, regardless of filter_enabled —
            # a rate/state-based detector that only ever saw already-matched
            # traffic could never build a useful baseline.
            try:
                anomaly_hits = self._anomaly.evaluate(packet, monitors, monitors_by_id=indexed_monitors_by_id(monitors))
            except Exception:
                LOGGER.exception("Anomaly detection failed")
                anomaly_hits = []
            if anomaly_hits:
                monitor_hits = list(monitor_hits) + list(anomaly_hits)
        tags = self._build_packet_tags(packet, matches, monitor_hits)
        packet["rule_hits"] = matches
        packet["monitor_hits"] = monitor_hits
        packet["tags"] = tags
        packet["banner_text"] = packet.get("banner_text") or packet.get("payload_text") or ""

        detected = detection_muted or bool(monitor_hits) or not filter_enabled
        if detected:
            saved = self.store.register_packet(packet)
            self._touch_packet(saved or packet, stored=True)
            self._broadcast_packet(saved or packet, persisted=True)
            self._record_intel(packet)
        else:
            # Undetected traffic can arrive at wire speed; broadcasting a full
            # "packet" event for every one of them would flood connected
            # dashboards. Only the counters need to stay live for this case,
            # and even those are time-throttled so the broadcast rate has a
            # hard ceiling regardless of how fast packets arrive.
            self._touch_packet(packet, stored=False)
            self._broadcast_stats_throttled()

        if self.state.packets_seen % 50 == 0:
            self.store.trim_oversized_tables()

    def _record_intel(self, packet: dict):
        domain = str(packet.get("domain") or "").strip()
        if domain:
            try:
                self.store.record_domain(
                    name=domain,
                    source=str(packet.get("domain_source") or "").strip(),
                    ip=str(packet.get("dst_ip") or packet.get("src_ip") or "").strip(),
                    port=safe_int(packet.get("dst_port") or packet.get("src_port") or 0, 0),
                    proto=normalize_protocol_name(packet.get("proto")),
                )
            except Exception:
                LOGGER.exception("Failed to record domain intel")

        path = str(packet.get("http_path") or "").strip()
        if path:
            try:
                self.store.record_path(
                    path=path,
                    method=str(packet.get("http_method") or "GET").strip().upper() or "GET",
                    host=str(packet.get("http_host") or "").strip(),
                    ip=str(packet.get("dst_ip") or packet.get("src_ip") or "").strip(),
                    port=safe_int(packet.get("dst_port") or packet.get("src_port") or 0, 0),
                )
            except Exception:
                LOGGER.exception("Failed to record path intel")

    def _build_packet_tags(self, packet: dict, matches: list[dict], monitor_hits: list[dict] | None = None) -> list[dict]:
        tags = [
            {"key": "proto", "value": normalize_protocol_name(packet.get("proto"))},
            {"key": "state", "value": str(packet.get("state") or "open").strip().lower() or "open"},
            {"key": "direction", "value": str(packet.get("direction") or "unknown").strip().lower() or "unknown"},
        ]
        if packet.get("src_port"):
            tags.append({"key": "src_port", "value": str(packet.get("src_port"))})
        if packet.get("dst_port"):
            tags.append({"key": "dst_port", "value": str(packet.get("dst_port"))})
        for match in matches:
            label = str(match.get("label") or match.get("tag") or match.get("rule_name") or "").strip()
            if label:
                tags.append({"key": "rule", "value": label, "severity": str(match.get("severity") or "info")})
        for hit in monitor_hits or []:
            severity = str(hit.get("severity") or "info")
            label = str(hit.get("label") or hit.get("tag") or hit.get("monitor_name") or "").strip()
            if label:
                # `severity` rides along on the "monitor" tag entry itself
                # (rather than only on "detail"/"monitor_id") so clients can
                # decide what's worth surfacing (e.g. a notification) without
                # needing a second lookup back to the monitor definition.
                tags.append({"key": "monitor", "value": label, "severity": severity})
            monitor_id = str(hit.get("monitor_id") or "").strip()
            if monitor_id:
                tags.append({"key": "monitor_id", "value": monitor_id, "severity": severity})
            detail = str(hit.get("detail") or "").strip()
            if detail:
                tags.append({"key": "detail", "value": detail, "severity": severity})
        return tags

    def parse_packet(self, data: bytes, *, interface: str = "") -> dict | None:
        if not data:
            return None
        now = utc_now()
        if self._looks_like_raw_ipv4(data):
            packet = self._new_packet(now, interface, data, data, eth_type=ETHERTYPE_IPV4)
            self._parse_ipv4(packet, data)
            return self._finalize_packet(packet)
        if self._looks_like_raw_ipv6(data):
            packet = self._new_packet(now, interface, data, data, eth_type=ETHERTYPE_IPV6)
            self._parse_ipv6(packet, data)
            return self._finalize_packet(packet)
        if len(data) < 14:
            return None
        frame = memoryview(data)
        dst_mac = format_mac(frame[0:6])
        src_mac = format_mac(frame[6:12])
        eth_type = int.from_bytes(frame[12:14], "big")
        offset = 14
        while eth_type in ETHERTYPE_VLAN and len(frame) >= offset + 4:
            eth_type = int.from_bytes(frame[offset + 2 : offset + 4], "big")
            offset += 4
        payload = bytes(frame[offset:])
        packet = self._new_packet(
            now,
            interface,
            data,
            payload,
            eth_src=src_mac,
            eth_dst=dst_mac,
            eth_type=eth_type,
        )
        if eth_type == ETHERTYPE_IPV4:
            self._parse_ipv4(packet, payload)
        elif eth_type == ETHERTYPE_IPV6:
            self._parse_ipv6(packet, payload)
        elif eth_type == ETHERTYPE_ARP:
            self._parse_arp(packet, payload)
        elif self._is_stp_bpdu(packet, payload):
            self._parse_stp(packet, payload)
        elif eth_type <= ETHERNET_MAX_PAYLOAD_LENGTH:
            # Not an EtherType at all - an IEEE 802.3 length field, with an
            # 802.2 LLC header (and possibly SNAP) where the upper-layer
            # protocol lives.
            self._parse_llc(packet, payload, declared_length=eth_type)
        else:
            # EtherTypes with no dedicated decoder but a well-known name -
            # LLDP/CDP neighbour discovery, 802.1X (EAPOL), Wake-on-LAN,
            # PPPoE, MPLS and the industrial buses. Discovery and 802.1X
            # frames in particular are exactly what an operator wants to
            # slice on, and they were all landing in "unknown".
            named = ETHER_PROTOCOLS.get(eth_type, "")
            if named:
                packet["proto"] = named
                packet["summary"] = f"{named.upper()} frame from {packet['eth_src']} ({len(payload)} bytes)"
                self._apply_app_decoder(packet, named, payload)
            else:
                packet["summary"] = f"EtherType 0x{eth_type:04x} payload {len(payload)} bytes"
            packet["payload_text"] = self._interpret_payload(packet, payload)
            packet["banner_text"] = packet["payload_text"]
        return self._finalize_packet(packet)

    def _apply_app_decoder(self, packet: dict, proto: str, payload: bytes):
        """Merge a protocol decoder's fields into the packet.

        `summary` and `banner_text` are overwritten because a decoded line
        ("SSH-2.0-OpenSSH_9.6", "SMB2 CREATE", "NTP private/monlist request")
        is strictly more informative than the generic
        "TCP a:1 -> b:2" the transport parser produced. Every other key is
        merged as-is so the extracted fields reach the packet row.
        """
        details = decode_app_payload(proto, payload)
        if not details:
            return
        for key, value in details.items():
            if value in ("", None):
                continue
            packet[key] = value

    def _parse_llc(self, packet: dict, payload: bytes, *, declared_length: int = 0):
        """Decode an IEEE 802.3 frame's LLC (802.2) header, and the SNAP
        header when there is one.

        Frames whose length field is <= 1500 carry LLC rather than a bare
        upper-layer protocol. Without this they all landed in the catch-all
        branch as `proto: unknown` with a misleading
        "EtherType 0x0006" summary - the 0x0006 being the payload length.
        """
        packet["llc_length"] = int(declared_length)
        if len(payload) < 3:
            packet["proto"] = "llc"
            packet["summary"] = f"IEEE 802.3 LLC (truncated, {len(payload)} bytes)"
            packet["payload_text"] = self._interpret_payload(packet, payload)
            packet["banner_text"] = packet["payload_text"]
            return

        dsap, ssap, control = payload[0], payload[1], payload[2]
        packet["llc_dsap"] = dsap
        packet["llc_ssap"] = ssap
        packet["llc_control"] = control

        if dsap == LLC_SNAP_SAP and ssap == LLC_SNAP_SAP and control == LLC_SNAP_CONTROL and len(payload) >= 8:
            # SNAP re-introduces a real EtherType after a 3-byte OUI, so the
            # existing parsers can take it from here.
            oui = payload[3:6]
            snap_type = int.from_bytes(payload[6:8], "big")
            body = bytes(payload[8:])
            packet["llc_snap_oui"] = oui.hex(":")
            packet["llc_snap_ethertype"] = snap_type
            packet["eth_type"] = snap_type
            if snap_type == ETHERTYPE_IPV4:
                self._parse_ipv4(packet, body)
                return
            if snap_type == ETHERTYPE_IPV6:
                self._parse_ipv6(packet, body)
                return
            if snap_type == ETHERTYPE_ARP:
                self._parse_arp(packet, body)
                return
            # Cisco's discovery protocols do not get an EtherType of their
            # own: they are identified by the Cisco OUI plus a protocol id
            # inside SNAP, so they only become nameable here.
            snap_named = SNAP_PROTOCOLS.get((oui, snap_type))
            if snap_named:
                packet["proto"] = snap_named
                packet["summary"] = f"{snap_named.upper()} frame from {packet['eth_src']} ({len(body)} bytes)"
                self._apply_app_decoder(packet, snap_named, body)
                packet["payload_text"] = self._interpret_payload(packet, body)
                packet["banner_text"] = packet["payload_text"]
                return
            packet["proto"] = "llc-snap"
            packet["summary"] = (
                f"IEEE 802.3 SNAP OUI {oui.hex(':')} EtherType 0x{snap_type:04x} "
                f"payload {len(body)} bytes"
            )
            packet["payload_text"] = self._interpret_payload(packet, body)
            packet["banner_text"] = packet["payload_text"]
            return

        dsap_name = LLC_SAP_NAMES.get(dsap & 0xFE)
        ssap_name = LLC_SAP_NAMES.get(ssap & 0xFE)
        packet["proto"] = f"llc-{dsap_name}" if dsap_name else "llc"
        # The low bit of DSAP marks a group address, and of SSAP a response;
        # naming them off the masked value keeps both halves readable.
        label = dsap_name or f"0x{dsap:02x}"
        packet["summary"] = (
            f"IEEE 802.3 LLC {label} DSAP 0x{dsap:02x} SSAP 0x{ssap:02x} "
            f"control 0x{control:02x} payload {len(payload) - 3} bytes"
        )
        packet["payload_text"] = self._interpret_payload(packet, bytes(payload[3:]))
        packet["banner_text"] = packet["summary"]

    def _new_packet(
        self,
        now: str,
        interface: str,
        data: bytes,
        payload: bytes,
        *,
        eth_src: str = "",
        eth_dst: str = "",
        eth_type: int = 0,
    ) -> dict:
        return build_base_packet(
            now, interface, data, payload, eth_src=eth_src, eth_dst=eth_dst, eth_type=eth_type
        )

    def _finalize_packet(self, packet: dict) -> dict:
        packet["flow_key"] = stable_flow_key(
            packet.get("proto") or "unknown",
            packet.get("src_ip") or packet.get("eth_src") or "unknown",
            packet.get("src_port") or 0,
            packet.get("dst_ip") or packet.get("eth_dst") or "unknown",
            packet.get("dst_port") or 0,
        )
        packet["direction"] = self._direction_for(packet)
        packet["banner_text"] = packet.get("banner_text") or packet.get("payload_text") or ""
        packet["state"] = packet.get("state") or ("open" if packet.get("payload_len", 0) else "filtered")
        packet["payload_text"] = packet.get("payload_text") or ""
        packet["payload_hex"] = packet.get("payload_hex") or ""
        packet["summary"] = packet.get("summary") or self._fallback_summary(packet)
        return packet

    def _looks_like_raw_ipv4(self, data: bytes) -> bool:
        if len(data) < 20 or (data[0] >> 4) != 4:
            return False
        header_length = (data[0] & 0x0F) * 4
        if header_length < 20 or header_length > len(data):
            return False
        total_length = int.from_bytes(data[2:4], "big")
        if total_length and total_length < header_length:
            return False
        try:
            ipaddress.IPv4Address(data[12:16])
            ipaddress.IPv4Address(data[16:20])
        except Exception:
            return False
        return self._ipv4_checksum_is_valid(data[:header_length])

    def _looks_like_raw_ipv6(self, data: bytes) -> bool:
        if len(data) < 40 or (data[0] >> 4) != 6:
            return False
        try:
            ipaddress.IPv6Address(data[8:24])
            ipaddress.IPv6Address(data[24:40])
        except Exception:
            return False
        return True

    def _ipv4_checksum_is_valid(self, header: bytes) -> bool:
        if len(header) < 20 or (len(header) % 2) != 0:
            return False
        total = 0
        for index in range(0, len(header), 2):
            total += int.from_bytes(header[index : index + 2], "big")
        while total > 0xFFFF:
            total = (total & 0xFFFF) + (total >> 16)
        return (total & 0xFFFF) == 0xFFFF

    def _is_stp_bpdu(self, packet: dict, payload: bytes) -> bool:
        return (
            str(packet.get("eth_dst") or "").lower() == STP_MULTICAST_MAC
            and len(payload) >= len(LLC_STP_HEADER)
            and payload[:3] == LLC_STP_HEADER
        )

    def _direction_for(self, packet: dict) -> str:
        src_ip = str(packet.get("src_ip") or "").strip()
        dst_ip = str(packet.get("dst_ip") or "").strip()
        local_ips = self._local_ips
        if src_ip in local_ips and dst_ip and dst_ip not in local_ips:
            return "outbound"
        if dst_ip in local_ips and src_ip and src_ip not in local_ips:
            return "inbound"
        if src_ip in local_ips and dst_ip in local_ips:
            return "local"
        return "unknown"

    def _fallback_summary(self, packet: dict) -> str:
        proto = normalize_protocol_name(packet.get("proto"))
        src = packet.get("src_ip") or packet.get("eth_src") or "?"
        dst = packet.get("dst_ip") or packet.get("eth_dst") or "?"
        port_text = ""
        src_port = safe_int(packet.get("src_port", 0), 0)
        dst_port = safe_int(packet.get("dst_port", 0), 0)
        if src_port or dst_port:
            port_text = f" {src_port}->{dst_port}"
        return f"{proto.upper()} {src}{port_text} → {dst}"

    def _parse_ipv4(self, packet: dict, payload: bytes):
        if len(payload) < 20:
            packet["summary"] = "IPv4 packet"
            packet["payload_text"] = self._interpret_payload(packet, payload)
            packet["banner_text"] = packet["payload_text"]
            return
        version_ihl = payload[0]
        ihl = (version_ihl & 0x0F) * 4
        total_length = int.from_bytes(payload[2:4], "big")
        packet["ip_version"] = 4
        packet["ttl"] = payload[8]
        proto = payload[9]
        packet["src_ip"] = str(ipaddress.IPv4Address(payload[12:16]))
        packet["dst_ip"] = str(ipaddress.IPv4Address(payload[16:20]))
        body = payload[ihl:total_length] if total_length > ihl else payload[ihl:]
        if proto == IP_PROTO_TCP:
            self._parse_tcp(packet, body)
        elif proto == IP_PROTO_UDP:
            self._parse_udp(packet, body)
        elif proto == IP_PROTO_SCTP:
            self._parse_sctp(packet, body)
        elif proto == IP_PROTO_ICMP:
            self._parse_icmp(packet, body)
        elif proto == IP_PROTO_IGMP:
            self._parse_igmp(packet, body)
        elif proto == IP_PROTO_GRE:
            self._parse_gre(packet, body)
        elif proto == IP_PROTO_IPV6_ESP:
            self._parse_esp(packet, body, ip_version=4)
        elif proto == IP_PROTO_IPV6_AH:
            self._parse_ah(packet, body, ip_version=4)
        else:
            # No dedicated decoder, but the IP protocol number still names the
            # protocol (OSPF, VRRP, EIGRP, PIM...). Naming it beats filing
            # every routing-protocol frame under "unknown".
            named = IP_PROTOCOLS.get(proto, "")
            packet["proto"] = named or "unknown"
            label = named.upper() if named else f"IPv4 protocol {proto}"
            packet["summary"] = f"{label} {packet['src_ip']} → {packet['dst_ip']}"
            packet["payload_text"] = self._interpret_payload(packet, body)
            packet["banner_text"] = packet["payload_text"]
        if not packet.get("summary"):
            packet["summary"] = self._fallback_summary(packet)

    def _parse_ipv6(self, packet: dict, payload: bytes):
        if len(payload) < 40:
            packet["summary"] = "IPv6 packet"
            packet["payload_text"] = self._interpret_payload(packet, payload)
            packet["banner_text"] = packet["payload_text"]
            return
        packet["ip_version"] = 6
        packet["hop_limit"] = payload[7]
        packet["src_ip"] = str(ipaddress.IPv6Address(payload[8:24]))
        packet["dst_ip"] = str(ipaddress.IPv6Address(payload[24:40]))
        next_header, body, detail = self._unwrap_ipv6_transport(payload)
        if next_header == IP_PROTO_TCP:
            self._parse_tcp(packet, body, ip_version=6)
        elif next_header == IP_PROTO_UDP:
            self._parse_udp(packet, body, ip_version=6)
        elif next_header == IP_PROTO_SCTP:
            self._parse_sctp(packet, body, ip_version=6)
        elif next_header == IP_PROTO_ICMPV6:
            self._parse_icmp(packet, body, ipv6=True)
        elif next_header == IP_PROTO_IPV6_ESP:
            self._parse_esp(packet, body, ip_version=6)
        elif next_header == IP_PROTO_IPV6_AH:
            self._parse_ah(packet, body, ip_version=6)
        else:
            named = IP_PROTOCOLS.get(next_header, "")
            packet["proto"] = named or "unknown"
            packet["summary"] = f"IPv6 {named.upper() or detail} {packet['src_ip']} → {packet['dst_ip']}"
            packet["payload_text"] = self._interpret_payload(packet, body)
            packet["banner_text"] = packet["payload_text"]
        if not packet.get("summary"):
            packet["summary"] = self._fallback_summary(packet)

    def _unwrap_ipv6_transport(self, payload: bytes) -> tuple[int | None, bytes, str]:
        next_header = payload[6]
        offset = 40

        # Walk common IPv6 extension headers so we still reach the transport payload.
        while True:
            if next_header in {
                IP_PROTO_IPV6_HOP_BY_HOP,
                IP_PROTO_IPV6_ROUTING,
                IP_PROTO_IPV6_DESTINATION,
                IP_PROTO_IPV6_MOBILITY,
                IP_PROTO_IPV6_HIP,
                IP_PROTO_IPV6_SHIM6,
            }:
                if len(payload) < offset + 2:
                    return None, payload[offset:], "truncated IPv6 extension"
                header_length = (payload[offset + 1] + 1) * 8
                if header_length <= 0 or len(payload) < offset + header_length:
                    return None, payload[offset:], "truncated IPv6 extension"
                next_header = payload[offset]
                offset += header_length
                continue
            if next_header == IP_PROTO_IPV6_FRAGMENT:
                if len(payload) < offset + 8:
                    return None, payload[offset:], "truncated IPv6 fragment"
                fragment_offset = ((int.from_bytes(payload[offset + 2 : offset + 4], "big")) >> 3) & 0x1FFF
                next_header = payload[offset]
                offset += 8
                if fragment_offset:
                    return None, payload[offset:], "non-initial IPv6 fragment"
                continue
            if next_header == IP_PROTO_IPV6_AH:
                # Hand off to _parse_ah rather than walking past it here, so IPv6
                # AH packets get the same SPI/seq extraction as IPv4 AH packets
                # (it does its own inner-protocol dispatch on the AH-stripped body).
                return IP_PROTO_IPV6_AH, payload[offset:], "AH"
            if next_header == IP_PROTO_IPV6_ESP:
                return IP_PROTO_IPV6_ESP, payload[offset:], "ESP"
            break

        return next_header, payload[offset:], f"protocol {next_header}"

    def _parse_arp(self, packet: dict, payload: bytes):
        if len(payload) < 28:
            packet["proto"] = "arp"
            packet["summary"] = "ARP packet"
            packet["payload_text"] = self._interpret_payload(packet, payload)
            packet["banner_text"] = packet["payload_text"]
            return
        packet["proto"] = "arp"
        opcode = int.from_bytes(payload[6:8], "big")
        packet["arp_opcode"] = opcode
        # The ARP payload carries its own sender/target hardware addresses,
        # which are NOT the Ethernet header's. Only reading the frame header
        # loses the pair that matters: a host claiming an address it does not
        # own announces the victim's IP with its own MAC inside the payload,
        # and the mismatch below is the whole tell.
        sender_mac = format_mac(payload[8:14])
        target_mac = format_mac(payload[18:24])
        packet["src_ip"] = str(ipaddress.IPv4Address(payload[14:18]))
        packet["dst_ip"] = str(ipaddress.IPv4Address(payload[24:28]))
        packet["src_port"] = 0
        packet["dst_port"] = 0
        packet["arp_operation"] = ARP_OPERATIONS.get(opcode, f"opcode {opcode}")
        packet["arp_sender_mac"] = sender_mac
        packet["arp_target_mac"] = target_mac
        packet["arp_hardware_type"] = ARP_HW_TYPES.get(
            int.from_bytes(payload[0:2], "big"), str(int.from_bytes(payload[0:2], "big"))
        )
        eth_src = str(packet.get("eth_src") or "").lower()
        if eth_src and sender_mac and sender_mac.lower() != eth_src:
            # Legitimate stacks put the same address in both places. A
            # disagreement is either a spoofing attempt or a proxy-ARP device,
            # and both are worth surfacing rather than leaving in the bytes.
            packet["arp_mac_mismatch"] = f"{eth_src} announces {sender_mac}"
        packet["summary"] = (
            f"ARP {packet['arp_operation']} {packet['src_ip']} ({sender_mac}) -> {packet['dst_ip']}"
        )
        packet["payload_text"] = self._interpret_payload(packet, payload)
        packet["banner_text"] = packet["payload_text"] or packet["summary"]

    def _parse_stp(self, packet: dict, payload: bytes):
        packet["proto"] = "stp"
        packet["summary"] = "STP BPDU"
        packet["payload_text"] = self._interpret_payload(packet, payload)
        packet["banner_text"] = packet["payload_text"] or packet["summary"]

    def _parse_tcp(self, packet: dict, body: bytes, *, ip_version: int = 4):
        if len(body) < 20:
            packet["proto"] = "tcp"
            packet["transport"] = "tcp"
            packet["summary"] = "TCP packet"
            packet["payload_text"] = self._interpret_payload(packet, body)
            packet["banner_text"] = packet["payload_text"]
            return
        packet["proto"] = "tcp"
        packet["transport"] = "tcp"
        packet["src_port"] = int.from_bytes(body[0:2], "big")
        packet["dst_port"] = int.from_bytes(body[2:4], "big")
        data_offset = (body[12] >> 4) * 4
        flags_byte = body[13]
        flags = []
        for mask, name in (
            (0x01, "FIN"),
            (0x02, "SYN"),
            (0x04, "RST"),
            (0x08, "PSH"),
            (0x10, "ACK"),
            (0x20, "URG"),
            (0x40, "ECE"),
            (0x80, "CWR"),
        ):
            if flags_byte & mask:
                flags.append(name)
        # "NONE" rather than "" for a segment that really carries no flag
        # bits: build_base_packet defaults tcp_flags to "", and so do the
        # honeypot's synthetic packets, so an empty string cannot mean "zero
        # flags observed" without every undecoded packet looking like a NULL
        # scan. Only this line, which has actually read the TCP header, can
        # say that - and a NULL scan is precisely a flagless segment.
        packet["tcp_flags"] = ",".join(flags) if flags else "NONE"
        payload = body[data_offset:] if data_offset and len(body) >= data_offset else body[20:]
        if (packet["src_port"] == 53 or packet["dst_port"] == 53) and len(payload) > 2:
            # DNS-over-TCP (RFC 1035 §4.2.2): a 2-byte big-endian length prefix
            # precedes the message. Only take this path if it actually looks
            # like a DNS message, so unrelated TCP/53 traffic still falls
            # through to the generic handling below.
            prefix_len = int.from_bytes(payload[0:2], "big")
            dns_payload = payload[2 : 2 + prefix_len] if prefix_len and prefix_len <= len(payload) - 2 else payload[2:]
            parsed_dns = parse_dns_message(dns_payload)
            if parsed_dns.get("questions") or parsed_dns.get("answers"):
                packet["proto"] = "dns"
                self._apply_dns_result(packet, dns_payload, prefix="DNS", source="dns")
                if ip_version == 6 and not packet.get("hop_limit"):
                    packet["hop_limit"] = 64
                return
        if (packet["src_port"] == 502 or packet["dst_port"] == 502) and len(payload) >= 8:
            self._parse_modbus(packet, payload)
            if ip_version == 6 and not packet.get("hop_limit"):
                packet["hop_limit"] = 64
            return
        if (packet["src_port"] == 20000 or packet["dst_port"] == 20000) and payload[0:2] == DNP3_START:
            self._parse_dnp3(packet, payload)
            if ip_version == 6 and not packet.get("hop_limit"):
                packet["hop_limit"] = 64
            return
        if (packet["src_port"] == 1883 or packet["dst_port"] == 1883) and payload:
            self._parse_mqtt(packet, payload)
            if ip_version == 6 and not packet.get("hop_limit"):
                packet["hop_limit"] = 64
            return
        packet["payload_text"] = self._interpret_payload(packet, payload)
        packet["banner_text"] = packet["payload_text"] or self._classify_tcp_banner(packet, payload)
        packet["summary"] = packet["banner_text"] or f"TCP {packet['src_ip']}:{packet['src_port']} → {packet['dst_ip']}:{packet['dst_port']}"
        if ip_version == 6 and not packet.get("hop_limit"):
            packet["hop_limit"] = 64
        if len(payload) >= 1 and payload[:1] == b"\x16":
            packet["banner_text"] = packet["banner_text"] or "TLS handshake"
            sni = extract_tls_sni(payload)
            if sni:
                packet["domain"] = sni
                packet["domain_source"] = "tls_sni"
        # Name the application protocol riding on this segment, following the
        # same convention the hand-written decoders above already use (mDNS,
        # SNMP, Modbus... all replace `proto` with their own name). Only
        # reached when none of those claimed the packet, so a specific
        # decoder's answer is never overwritten by this weaker guess.
        app_proto = classify_tcp(packet["src_port"], packet["dst_port"], payload)
        if app_proto:
            packet["proto"] = app_proto
            self._apply_app_decoder(packet, app_proto, payload)
        method, path, host = extract_http_request(packet["payload_text"])
        if method:
            packet["http_method"] = method
            packet["http_path"] = path
            packet["http_host"] = host
            if host:
                packet["domain"] = host
                packet["domain_source"] = "http_host"

    def _parse_udp(self, packet: dict, body: bytes, *, ip_version: int = 4):
        if len(body) < 8:
            packet["proto"] = "udp"
            packet["transport"] = "udp"
            packet["summary"] = "UDP packet"
            packet["payload_text"] = self._interpret_payload(packet, body)
            packet["banner_text"] = packet["payload_text"]
            return
        packet["proto"] = "udp"
        packet["transport"] = "udp"
        packet["src_port"] = int.from_bytes(body[0:2], "big")
        packet["dst_port"] = int.from_bytes(body[2:4], "big")
        length = int.from_bytes(body[4:6], "big")
        payload = body[8:length] if length > 8 and length <= len(body) else body[8:]
        packet["payload_text"] = self._interpret_payload(packet, payload)
        packet["banner_text"] = packet["payload_text"] or self._classify_udp_banner(packet, payload)
        packet["summary"] = packet["banner_text"] or f"UDP {packet['src_ip']}:{packet['src_port']} → {packet['dst_ip']}:{packet['dst_port']}"
        if ip_version == 6 and not packet.get("hop_limit"):
            packet["hop_limit"] = 64
        src_port = packet["src_port"]
        dst_port = packet["dst_port"]
        if src_port == 53 or dst_port == 53:
            # Named like every other decoded application protocol here
            # (mDNS/LLMNR already do this). Rules written against
            # protocols:["udp"] keep matching through `transport`.
            packet["proto"] = "dns"
            self._apply_dns_result(packet, payload, prefix="DNS", source="dns")
        elif src_port in (67, 68) or dst_port in (67, 68):
            self._parse_dhcp(packet, payload)
        elif src_port == 5353 or dst_port == 5353:
            packet["proto"] = "mdns"
            self._apply_dns_result(packet, payload, prefix="mDNS", source="mdns")
        elif src_port == 5355 or dst_port == 5355:
            packet["proto"] = "llmnr"
            self._apply_dns_result(packet, payload, prefix="LLMNR", source="llmnr")
        elif src_port == 137 or dst_port == 137:
            self._parse_nbns(packet, payload)
        elif src_port in (161, 162) or dst_port in (161, 162):
            self._parse_snmp(packet, payload)
        elif src_port == 514 or dst_port == 514:
            self._parse_syslog(packet, payload)
        elif src_port == 69 or dst_port == 69:
            self._parse_tftp(packet, payload)
        elif src_port in (1812, 1813) or dst_port in (1812, 1813):
            self._parse_radius(packet, payload)
        elif (src_port == 20000 or dst_port == 20000) and payload[0:2] == DNP3_START:
            self._parse_dnp3(packet, payload)
        else:
            # Same fallback role as the TCP branch: only datagrams no
            # dedicated decoder above matched reach this point.
            app_proto = classify_udp(src_port, dst_port, payload)
            if app_proto:
                packet["proto"] = app_proto
                self._apply_app_decoder(packet, app_proto, payload)

    def _parse_sctp(self, packet: dict, body: bytes, *, ip_version: int = 4):
        if len(body) < 12:
            packet["proto"] = "sctp"
            packet["transport"] = "sctp"
            packet["summary"] = "SCTP packet"
            packet["payload_text"] = self._interpret_payload(packet, body)
            packet["banner_text"] = packet["payload_text"]
            return
        packet["proto"] = "sctp"
        packet["src_port"] = int.from_bytes(body[0:2], "big")
        packet["dst_port"] = int.from_bytes(body[2:4], "big")
        payload = body[12:]
        packet["payload_text"] = self._interpret_payload(packet, payload)
        packet["banner_text"] = packet["payload_text"]
        packet["summary"] = packet["banner_text"] or f"SCTP {packet['src_ip']}:{packet['src_port']} → {packet['dst_ip']}:{packet['dst_port']}"
        if ip_version == 6 and not packet.get("hop_limit"):
            packet["hop_limit"] = 64

    def _parse_icmp(self, packet: dict, body: bytes, *, ipv6: bool = False):
        if len(body) < 4:
            packet["proto"] = "icmpv6" if ipv6 else "icmp"
            packet["summary"] = "ICMP packet"
            packet["payload_text"] = self._interpret_payload(packet, body)
            packet["banner_text"] = packet["payload_text"]
            return
        packet["proto"] = "icmpv6" if ipv6 else "icmp"
        packet["icmp_type"] = body[0]
        packet["icmp_code"] = body[1]
        packet["payload_text"] = self._interpret_payload(packet, body[4:])
        packet["banner_text"] = packet["payload_text"] or self._classify_icmp_banner(packet)
        packet["summary"] = packet["banner_text"] or f"{packet['proto'].upper()} type {packet['icmp_type']} code {packet['icmp_code']}"

    def _parse_igmp(self, packet: dict, body: bytes):
        packet["proto"] = "igmp"
        if len(body) < 8:
            packet["summary"] = "IGMP packet"
            packet["banner_text"] = packet["summary"]
            packet["payload_text"] = self._interpret_payload(packet, body)
            return
        msg_type = body[0]
        type_name = IGMP_TYPE_NAMES.get(msg_type, f"type 0x{msg_type:02x}")
        try:
            group = str(ipaddress.IPv4Address(body[4:8]))
        except Exception:
            group = ""
        summary = f"IGMP {type_name}"
        if group and group != "0.0.0.0":
            packet["igmp_group"] = group
            summary += f" group={group}"
        packet["summary"] = summary
        packet["banner_text"] = summary
        packet["payload_text"] = summary

    def _parse_gre(self, packet: dict, body: bytes):
        packet["proto"] = "gre"
        if len(body) < 4:
            packet["summary"] = "GRE packet"
            packet["banner_text"] = packet["summary"]
            return
        flags_version = int.from_bytes(body[0:2], "big")
        checksum_present = bool(flags_version & 0x8000)
        key_present = bool(flags_version & 0x2000)
        seq_present = bool(flags_version & 0x1000)
        proto_type = int.from_bytes(body[2:4], "big")
        offset = 4
        if checksum_present and len(body) >= offset + 4:
            offset += 4
        key = None
        if key_present and len(body) >= offset + 4:
            key = int.from_bytes(body[offset : offset + 4], "big")
            offset += 4
        if seq_present and len(body) >= offset + 4:
            offset += 4
        summary = f"GRE tunnel inner-proto 0x{proto_type:04x}"
        if key is not None:
            summary += f" key=0x{key:08x}"
        packet["summary"] = summary
        packet["banner_text"] = summary
        packet["payload_text"] = summary

    def _parse_esp(self, packet: dict, body: bytes, *, ip_version: int = 4):
        packet["proto"] = "esp"
        if len(body) < 8:
            packet["summary"] = "ESP packet"
            packet["banner_text"] = packet["summary"]
            return
        spi = int.from_bytes(body[0:4], "big")
        seq = int.from_bytes(body[4:8], "big")
        summary = f"ESP SPI=0x{spi:08x} seq={seq} (encrypted payload)"
        packet["summary"] = summary
        packet["banner_text"] = summary

    def _ah_header_length(self, length_field: int) -> int:
        # RFC 4302 §2.2: header length is expressed in 4-byte words, minus 2.
        return (length_field + 2) * 4

    def _parse_ah(self, packet: dict, body: bytes, *, ip_version: int = 4):
        if len(body) < 12:
            packet["proto"] = "ah"
            packet["summary"] = "AH packet"
            packet["banner_text"] = packet["summary"]
            return
        next_header = body[0]
        header_length = self._ah_header_length(body[1])
        spi = int.from_bytes(body[4:8], "big")
        seq = int.from_bytes(body[8:12], "big")
        inner = body[header_length:] if 0 < header_length <= len(body) else b""
        icmp_proto = IP_PROTO_ICMPV6 if ip_version == 6 else IP_PROTO_ICMP
        if next_header == IP_PROTO_TCP:
            self._parse_tcp(packet, inner, ip_version=ip_version)
        elif next_header == IP_PROTO_UDP:
            self._parse_udp(packet, inner, ip_version=ip_version)
        elif next_header == icmp_proto:
            self._parse_icmp(packet, inner, ipv6=(ip_version == 6))
        else:
            packet["proto"] = "ah"
            packet["summary"] = f"AH protocol {next_header}"
            packet["banner_text"] = packet["summary"]
        packet["summary"] = f"AH SPI=0x{spi:08x} seq={seq} | " + (packet.get("summary") or "")
        packet["banner_text"] = packet["summary"]

    def _parse_dhcp(self, packet: dict, payload: bytes):
        packet["proto"] = "dhcp"
        try:
            if len(payload) < 240 or payload[236:240] != b"\x63\x82\x53\x63":
                packet["summary"] = "DHCP/BOOTP packet"
                packet["banner_text"] = packet["summary"]
                return
            msg_type = None
            requested_ip = ""
            hostname = ""
            vendor_class = ""
            offset = 240
            while offset < len(payload):
                code = payload[offset]
                offset += 1
                if code == 0xFF:
                    break
                if code == 0x00:
                    continue
                if offset >= len(payload):
                    break
                length = payload[offset]
                offset += 1
                if offset + length > len(payload):
                    break
                value = payload[offset : offset + length]
                offset += length
                if code == 53 and len(value) == 1:
                    msg_type = value[0]
                elif code == 50 and len(value) == 4:
                    requested_ip = str(ipaddress.IPv4Address(value))
                elif code == 12:
                    hostname = value.decode("ascii", errors="replace")
                elif code == 60:
                    vendor_class = value.decode("ascii", errors="replace")
            type_name = DHCP_MSG_TYPES.get(msg_type, f"type {msg_type}" if msg_type is not None else "message")
            if msg_type is not None:
                # The readable name, not the raw number: "DISCOVER" is what a
                # reader needs, and the number is recoverable from it.
                packet["dhcp_msg_type"] = type_name
            # These three are the DHCP lease conversation's whole value for an
            # asset inventory - who asked, calling itself what, for which
            # address - and they only ever reached the summary string.
            if hostname:
                packet["dhcp_hostname"] = hostname
            if requested_ip:
                packet["dhcp_requested_ip"] = requested_ip
            if vendor_class:
                packet["dhcp_vendor_class"] = vendor_class
            parts = [f"DHCP {type_name}"]
            if hostname:
                parts.append(f"host={hostname}")
            if requested_ip:
                parts.append(f"requested={requested_ip}")
            if vendor_class:
                parts.append(f"vendor={vendor_class}")
            summary = " ".join(parts)
            packet["summary"] = summary
            packet["banner_text"] = summary
            packet["payload_text"] = summary
        except Exception:
            packet["summary"] = packet.get("summary") or "DHCP/BOOTP packet"
            packet["banner_text"] = packet["summary"]

    def _parse_nbns(self, packet: dict, payload: bytes):
        packet["proto"] = "nbns"
        try:
            if len(payload) < 12:
                packet["summary"] = "NBNS packet"
                packet["banner_text"] = packet["summary"]
                return
            flags = int.from_bytes(payload[2:4], "big")
            is_response = bool(flags & 0x8000)
            qdcount = int.from_bytes(payload[4:6], "big")
            name = ""
            offset = 12
            if qdcount >= 1 and len(payload) >= offset + 1:
                length = payload[offset]
                if length == 32 and len(payload) >= offset + 1 + 32:
                    name = decode_nbns_name(payload[offset + 1 : offset + 33])
            summary = f"NBNS {'response' if is_response else 'query'}"
            if name:
                summary += f" for {name}"
            packet["summary"] = summary
            packet["banner_text"] = summary
            packet["payload_text"] = summary
        except Exception:
            packet["summary"] = packet.get("summary") or "NBNS packet"
            packet["banner_text"] = packet["summary"]

    def _parse_modbus(self, packet: dict, payload: bytes):
        # MBAP header (RFC-less but universally implemented as): Transaction
        # ID(2) + Protocol ID(2, always 0 for Modbus) + Length(2) + Unit ID(1),
        # then the PDU: Function Code(1) + data. A response to an error has
        # the top bit of the function code set (fc | 0x80) followed by a
        # 1-byte exception code.
        packet["proto"] = "modbus"
        try:
            if len(payload) < 8:
                packet["summary"] = "Modbus packet"
                packet["banner_text"] = packet["summary"]
                return
            unit_id = payload[6]
            function_code = payload[7]
            is_exception = bool(function_code & 0x80)
            base_code = function_code & 0x7F
            func_name = MODBUS_FUNCTION_NAMES.get(base_code, f"fc-{base_code}")
            is_write = base_code in MODBUS_WRITE_FUNCTION_CODES
            packet["modbus_unit_id"] = unit_id
            packet["modbus_function_code"] = base_code
            packet["modbus_is_write"] = is_write
            kind = "write" if is_write else "read/other"
            summary = f"Modbus {func_name} ({kind}) unit={unit_id}"
            if is_exception:
                exception_code = payload[8] if len(payload) > 8 else None
                summary = f"Modbus EXCEPTION {func_name} unit={unit_id} code={exception_code}"
            packet["summary"] = summary
            packet["banner_text"] = summary
            packet["payload_text"] = summary
        except Exception:
            packet["summary"] = packet.get("summary") or "Modbus packet"
            packet["banner_text"] = packet["summary"]

    def _parse_dnp3(self, packet: dict, payload: bytes):
        # Best-effort: DNP3 chunks its payload into CRC-protected 16-byte
        # blocks past the data-link header, which this doesn't reassemble -
        # it decodes the fixed 10-byte data-link header (start bytes,
        # length, control, destination, source) and, for the common case of
        # a short single-block frame, peeks the application-layer function
        # code right after the 2-byte data-link CRC. Enough to flag
        # restart/unsolicited-response commands; a truncated/multi-block
        # frame just degrades to reporting the data-link fields alone.
        packet["proto"] = "dnp3"
        try:
            if len(payload) < 10 or payload[0:2] != DNP3_START:
                packet["summary"] = "DNP3 packet"
                packet["banner_text"] = packet["summary"]
                return
            dest = int.from_bytes(payload[4:6], "little")
            src = int.from_bytes(payload[6:8], "little")
            packet["dnp3_dest"] = dest
            packet["dnp3_src"] = src
            function_code = None
            # 8-byte data-link header (start+length+control+dest+src) + 2-byte
            # CRC = 10 bytes consumed; transport control byte at [10],
            # application control byte at [11], function code at [12].
            if len(payload) >= 13:
                function_code = payload[12]
            packet["dnp3_function_code"] = function_code
            func_name = (
                DNP3_FUNCTION_NAMES.get(function_code, f"fc-{function_code}")
                if function_code is not None
                else "unknown"
            )
            summary = f"DNP3 {func_name} src={src} dest={dest}"
            packet["summary"] = summary
            packet["banner_text"] = summary
            packet["payload_text"] = summary
        except Exception:
            packet["summary"] = packet.get("summary") or "DNP3 packet"
            packet["banner_text"] = packet["summary"]

    def _read_ber_length(self, data: bytes, offset: int) -> tuple[int | None, int]:
        """Minimal BER/DER length-octet decoder (short and long form) - just
        enough to walk SNMP's outer SEQUENCE/INTEGER/OCTET STRING TLVs
        without a real ASN.1 library."""
        if offset >= len(data):
            return None, offset
        first = data[offset]
        offset += 1
        if first < 0x80:
            return first, offset
        num_bytes = first & 0x7F
        if num_bytes == 0 or offset + num_bytes > len(data):
            return None, offset
        length = int.from_bytes(data[offset : offset + num_bytes], "big")
        return length, offset + num_bytes

    def _parse_snmp(self, packet: dict, payload: bytes):
        # SNMPv1/v2c's outer structure is BER: SEQUENCE { INTEGER version,
        # OCTET STRING community, PDU ... } - the community string (SNMP's
        # entire access control for v1/v2c, sent in cleartext) sits at a
        # fixed shallow offset right after the version integer. SNMPv3 uses
        # a different structure with no plain community string; the OCTET
        # STRING tag check below simply won't match there and this degrades
        # to reporting just the version.
        packet["proto"] = "snmp"
        try:
            if len(payload) < 2 or payload[0] != 0x30:
                packet["summary"] = "SNMP packet"
                packet["banner_text"] = packet["summary"]
                return
            pos = 1
            _seq_len, pos = self._read_ber_length(payload, pos)
            version = None
            community = ""
            if pos < len(payload) and payload[pos] == 0x02:  # INTEGER version
                pos += 1
                length, pos = self._read_ber_length(payload, pos)
                if length and pos + length <= len(payload):
                    version = int.from_bytes(payload[pos : pos + length], "big")
                    pos += length
            if pos < len(payload) and payload[pos] == 0x04:  # OCTET STRING community
                pos += 1
                length, pos = self._read_ber_length(payload, pos)
                if length and pos + length <= len(payload):
                    community = payload[pos : pos + length].decode("utf-8", errors="replace")
                    pos += length
            version_name = {0: "v1", 1: "v2c"}.get(version, f"v{version}" if version is not None else "?")
            packet["snmp_version"] = version_name
            packet["snmp_community"] = community
            summary = f"SNMP {version_name}"
            if community:
                summary += f" community='{community}'"
            packet["summary"] = summary
            packet["banner_text"] = summary
            packet["payload_text"] = summary
        except Exception:
            packet["summary"] = packet.get("summary") or "SNMP packet"
            packet["banner_text"] = packet["summary"]

    def _parse_syslog(self, packet: dict, payload: bytes):
        packet["proto"] = "syslog"
        try:
            text = bytes_to_text_preview(payload, limit=400)
            message = text
            pri = None
            if text.startswith("<"):
                end = text.find(">")
                if 1 <= end <= 4 and text[1:end].isdigit():
                    pri = int(text[1:end])
                    message = text[end + 1 :]
            message = message.strip()
            if pri is not None:
                severity = SYSLOG_SEVERITY_NAMES.get(pri % 8, str(pri % 8))
                facility = pri // 8
                packet["syslog_severity"] = severity
                packet["syslog_facility"] = facility
                summary = f"Syslog facility={facility} severity={severity}"
                if message:
                    summary += f": {message[:120]}"
            else:
                summary = f"Syslog: {message[:120]}" if message else "Syslog message"
            packet["summary"] = summary
            packet["banner_text"] = summary
            packet["payload_text"] = message or summary
        except Exception:
            packet["summary"] = packet.get("summary") or "Syslog message"
            packet["banner_text"] = packet["summary"]

    def _parse_tftp(self, packet: dict, payload: bytes):
        packet["proto"] = "tftp"
        try:
            if len(payload) < 2:
                packet["summary"] = "TFTP packet"
                packet["banner_text"] = packet["summary"]
                return
            opcode = int.from_bytes(payload[0:2], "big")
            opcode_name = TFTP_OPCODE_NAMES.get(opcode, f"opcode-{opcode}")
            summary = f"TFTP {opcode_name}"
            if opcode in (1, 2) and len(payload) > 2:  # RRQ / WRQ
                parts = payload[2:].split(b"\x00")
                filename = parts[0].decode("ascii", errors="replace") if parts and parts[0] else ""
                mode = parts[1].decode("ascii", errors="replace") if len(parts) > 1 and parts[1] else ""
                if filename:
                    packet["tftp_filename"] = filename
                if mode:
                    packet["tftp_mode"] = mode
                    summary += f" file='{filename}'"
                if mode:
                    summary += f" mode={mode}"
            packet["summary"] = summary
            packet["banner_text"] = summary
            packet["payload_text"] = summary
        except Exception:
            packet["summary"] = packet.get("summary") or "TFTP packet"
            packet["banner_text"] = packet["summary"]

    def _parse_radius(self, packet: dict, payload: bytes):
        packet["proto"] = "radius"
        try:
            if len(payload) < 20:
                packet["summary"] = "RADIUS packet"
                packet["banner_text"] = packet["summary"]
                return
            code_name = RADIUS_CODE_NAMES.get(payload[0], f"code-{payload[0]}")
            username = ""
            nas_ip = ""
            offset = 20
            while offset + 2 <= len(payload):
                attr_type = payload[offset]
                attr_len = payload[offset + 1]
                if attr_len < 2 or offset + attr_len > len(payload):
                    break
                value = payload[offset + 2 : offset + attr_len]
                if attr_type == 1:  # User-Name
                    username = value.decode("utf-8", errors="replace")
                elif attr_type == 4 and len(value) == 4:  # NAS-IP-Address
                    nas_ip = str(ipaddress.IPv4Address(value))
                offset += attr_len
            if username:
                packet["radius_username"] = username
            if nas_ip:
                packet["radius_nas_ip"] = nas_ip
            summary = f"RADIUS {code_name}"
            if username:
                summary += f" user='{username}'"
            if nas_ip:
                summary += f" nas={nas_ip}"
            packet["summary"] = summary
            packet["banner_text"] = summary
            packet["payload_text"] = summary
        except Exception:
            packet["summary"] = packet.get("summary") or "RADIUS packet"
            packet["banner_text"] = packet["summary"]

    def _read_mqtt_remaining_length(self, payload: bytes, offset: int) -> tuple[int | None, int]:
        multiplier = 1
        value = 0
        start = offset
        while offset < len(payload) and offset - start < 4:
            byte = payload[offset]
            offset += 1
            value += (byte & 0x7F) * multiplier
            if not (byte & 0x80):
                return value, offset
            multiplier *= 128
        return None, offset

    def _read_mqtt_string(self, payload: bytes, offset: int) -> tuple[str, int]:
        if offset + 2 > len(payload):
            return "", offset
        length = int.from_bytes(payload[offset : offset + 2], "big")
        offset += 2
        if length == 0 or offset + length > len(payload):
            return "", offset
        return payload[offset : offset + length].decode("utf-8", errors="replace"), offset + length

    def _parse_mqtt(self, packet: dict, payload: bytes):
        packet["proto"] = "mqtt"
        try:
            packet_type = (payload[0] >> 4) & 0x0F
            type_name = MQTT_PACKET_TYPE_NAMES.get(packet_type, f"type-{packet_type}")
            summary = f"MQTT {type_name}"
            if packet_type == 1 and len(payload) > 1:  # CONNECT
                _remaining_length, offset = self._read_mqtt_remaining_length(payload, 1)
                _protocol_name, offset = self._read_mqtt_string(payload, offset)
                offset += 1  # protocol level
                connect_flags = payload[offset] if offset < len(payload) else 0
                offset += 1
                offset += 2  # keep alive
                client_id, offset = self._read_mqtt_string(payload, offset)
                if connect_flags & 0x04:  # will flag - skip will topic + message
                    _, offset = self._read_mqtt_string(payload, offset)
                    _, offset = self._read_mqtt_string(payload, offset)
                username = ""
                password_present = False
                if connect_flags & 0x80:  # username flag
                    username, offset = self._read_mqtt_string(payload, offset)
                if connect_flags & 0x40:  # password flag
                    password_present = True
                if client_id:
                    packet["mqtt_client_id"] = client_id
                    summary += f" client='{client_id}'"
                if username:
                    packet["mqtt_username"] = username
                    summary += f" user='{username}'"
                if password_present:
                    summary += " password=<present>"
            packet["summary"] = summary
            packet["banner_text"] = summary
            packet["payload_text"] = summary
        except Exception:
            packet["summary"] = packet.get("summary") or "MQTT packet"
            packet["banner_text"] = packet["summary"]

    def _apply_dns_result(self, packet: dict, payload: bytes, *, prefix: str, source: str):
        parsed = parse_dns_message(payload)
        questions = parsed.get("questions") or []
        answers = parsed.get("answers") or []
        if questions:
            packet["domain"] = questions[0]["name"]
            packet["domain_source"] = source
            packet["dns_qtype"] = DNS_QTYPE_NAMES.get(
                questions[0].get("qtype"), str(questions[0].get("qtype") or "")
            )
        packet["dns_kind"] = "response" if parsed.get("is_response") else "query"
        packet["dns_rcode"] = DNS_RCODE_NAMES.get(
            parsed.get("rcode") or 0, str(parsed.get("rcode") or 0)
        )
        # The resolved value, and the name->value pair it belongs to. Both were
        # parsed already and then survived only inside the summary string, so
        # "which address did this name resolve to" could not be answered
        # without reading free text. `dns_answer` alone would lose which name
        # it answered, which is the half that matters for tracking an
        # infrastructure change or a poisoned reply.
        if answers:
            first = answers[0]
            value = str(first.get("rdata") or "").strip()
            if value:
                packet["dns_answer"] = value
                name = str(first.get("name") or packet.get("domain") or "").strip()
                packet["dns_mapping"] = f"{name} -> {value}" if name else value
                packet["dns_answer_type"] = DNS_QTYPE_NAMES.get(
                    first.get("qtype"), str(first.get("qtype") or "")
                )
        summary = _dns_message_summary(prefix, parsed)
        if summary:
            packet["summary"] = summary
            packet["banner_text"] = summary
            if not packet.get("payload_text"):
                packet["payload_text"] = summary

    def _is_tls_payload(self, packet: dict, payload: bytes) -> bool:
        """Stateless TLS-record-header check, extended with per-flow memory
        for TCP so continuation segments of a multi-segment TLS record
        (which carry no header of their own - see self._tls_flows'
        docstring in __init__) are still recognized as opaque ciphertext.
        Falls back to the stateless check alone for non-TCP callers/packets
        with no usable flow identity."""
        if _looks_like_tls_record(payload):
            if packet.get("proto") == "tcp":
                flow_key = stable_flow_key(
                    "tcp",
                    packet.get("src_ip", ""),
                    packet.get("src_port", 0),
                    packet.get("dst_ip", ""),
                    packet.get("dst_port", 0),
                )
                with self._tls_flows_lock:
                    if len(self._tls_flows) >= TLS_FLOW_MEMORY_CAP:
                        self._tls_flows.clear()
                    self._tls_flows[flow_key] = time.monotonic()
            return True
        if packet.get("proto") != "tcp":
            return False
        flow_key = stable_flow_key(
            "tcp",
            packet.get("src_ip", ""),
            packet.get("src_port", 0),
            packet.get("dst_ip", ""),
            packet.get("dst_port", 0),
        )
        with self._tls_flows_lock:
            return flow_key in self._tls_flows

    def _interpret_payload(self, packet: dict, payload: bytes) -> str:
        if not payload:
            return ""
        # A TLS record (handshake, application data, alert, ...) is
        # ciphertext beyond the ClientHello - is_printable_payload's 55%-
        # of-first-128-bytes heuristic isn't reliable enough to reject it
        # (uniformly random bytes clear that bar often enough in practice,
        # confirmed against real captured traffic), so check the record
        # header explicitly first rather than relying on that heuristic
        # alone for this specific, very common case.
        if self._is_tls_payload(packet, payload):
            return ""
        # Binary/encrypted payloads decode into misleading "text" here -
        # `bytes.decode(errors="ignore")` silently drops undecodable bytes
        # and keeps whatever printable-looking fragments remain, which is
        # random noise that can coincidentally contain a monitor's regex
        # trigger word (e.g. a webshell name). Only trust the decode when
        # the payload is actually mostly-printable to begin with.
        if not is_printable_payload(payload):
            return ""
        text = bytes_to_text_preview(payload, limit=PAYLOAD_TEXT_MAX_CHARS)
        if text:
            packet["state"] = "open"
        return text

    def _classify_tcp_banner(self, packet: dict, payload: bytes) -> str:
        src_port = safe_int(packet.get("src_port"), 0)
        dst_port = safe_int(packet.get("dst_port"), 0)
        if payload.startswith(b"\x16\x03"):
            return "TLS handshake"
        # Any other TLS record (application data, alert, change-cipher-spec)
        # - or a continuation segment of one, tracked via per-flow memory -
        # is ciphertext. `text` below is only meaningful decoded output for
        # genuine cleartext protocols, so this must come before it's used as
        # the fallback return value, or ciphertext-decoded-as-garbage leaks
        # into banner_text/summary exactly like the payload_text case this
        # mirrors (see _interpret_payload/_is_tls_payload).
        if self._is_tls_payload(packet, payload):
            return "TLS application data"
        text = bytes_to_text_preview(payload, limit=PAYLOAD_TEXT_MAX_CHARS)
        if text.startswith("HTTP/1."):
            return "HTTP response"
        if text.startswith("GET ") or text.startswith("POST ") or text.startswith("HEAD "):
            return "HTTP request"
        if src_port == 22 or dst_port == 22:
            return "SSH session"
        if src_port == 25 or dst_port == 25:
            return "SMTP session"
        if src_port == 445 or dst_port == 445:
            return "SMB session"
        if src_port == 3389 or dst_port == 3389:
            return "RDP session"
        return text

    def _classify_udp_banner(self, packet: dict, payload: bytes) -> str:
        src_port = safe_int(packet.get("src_port"), 0)
        dst_port = safe_int(packet.get("dst_port"), 0)
        text = bytes_to_text_preview(payload, limit=PAYLOAD_TEXT_MAX_CHARS)
        if src_port == 53 or dst_port == 53:
            return "DNS message"
        if src_port == 67 or dst_port == 67 or src_port == 68 or dst_port == 68:
            return "DHCP message"
        if src_port == 123 or dst_port == 123:
            return "NTP message"
        if src_port == 5353 or dst_port == 5353:
            return "mDNS message"
        return text

    def _classify_icmp_banner(self, packet: dict) -> str:
        type_code = (safe_int(packet.get("icmp_type"), 0), safe_int(packet.get("icmp_code"), 0))
        if type_code == (8, 0):
            return "ICMP echo request"
        if type_code == (0, 0):
            return "ICMP echo reply"
        return ""

    def _build_packet_from_sample(self, sample: dict, *, interface: str) -> dict:
        now = utc_now()
        proto = normalize_protocol_name(sample.get("proto"))
        src_ip = str(sample.get("src_ip") or "10.0.0.1").strip()
        dst_ip = str(sample.get("dst_ip") or "10.0.0.2").strip()
        src_port = safe_int(sample.get("src_port", 0), 0)
        dst_port = safe_int(sample.get("dst_port", 0), 0)
        payload_text = str(sample.get("payload_text") or "").strip()
        payload_bytes = payload_text.encode("utf-8", errors="ignore")
        packet = {
            "session_id": 0,
            "interface": interface,
            "eth_src": "aa:bb:cc:dd:ee:01",
            "eth_dst": "aa:bb:cc:dd:ee:02",
            "eth_type": ETHERTYPE_IPV4,
            "ip_version": 4,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "proto": proto,
            "src_port": src_port,
            "dst_port": dst_port,
            "ttl": 64,
            "hop_limit": 0,
            "length": 64 + len(payload_bytes),
            "payload_len": len(payload_bytes),
            "state": "open" if payload_bytes else "filtered",
            "scan_state": "active",
            "tcp_flags": "PSH,ACK" if proto == "tcp" else "",
            "icmp_type": 0 if proto == "icmp" else 0,
            "icmp_code": 0,
            "arp_opcode": 0,
            "summary": str(sample.get("summary") or ""),
            "payload_text": payload_text,
            "payload_hex": payload_bytes.hex(),
            "banner_text": str(sample.get("banner_text") or payload_text or ""),
            "direction": "unknown",
            "raw_packet": payload_bytes,
            "created_at": now,
            "updated_at": now,
        }
        packet["flow_key"] = stable_flow_key(proto, src_ip, src_port, dst_ip, dst_port)
        packet["direction"] = self._direction_for(packet)
        if not packet["summary"]:
            packet["summary"] = self._fallback_summary(packet)
        return packet
