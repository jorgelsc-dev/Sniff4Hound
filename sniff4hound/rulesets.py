from __future__ import annotations

import re
from pathlib import Path
import json

from .runtime_paths import resolve_data_file
from .utils import normalize_protocol_name, unique_ordered, safe_int


# Compiled-pattern cache, keyed by pattern text, shared by every ruleset/
# monitor regex check. CPython's own `re` module already memoizes compiled
# patterns internally, but that cache is process-global, shared by every
# unrelated regex call in the app, and capped small (512 entries by
# default) - with hundreds of distinct monitor/ruleset patterns evaluated
# on every captured packet, it thrashes constantly. This cache is scoped to
# just those patterns and, in practice, converges to one entry per distinct
# pattern and then stays stable for the life of the process. `None` is
# cached too, so a pattern that fails to compile isn't retried every packet.
_COMPILED_REGEX_CACHE: dict[str, "re.Pattern | None"] = {}


def _compiled_regex(pattern: str):
    if pattern in _COMPILED_REGEX_CACHE:
        return _COMPILED_REGEX_CACHE[pattern]
    try:
        compiled = re.compile(pattern, re.IGNORECASE)
    except re.error:
        compiled = None
    _COMPILED_REGEX_CACHE[pattern] = compiled
    return compiled


def literal_packet_text_pattern(value: str) -> str:
    """Regex for an exact IOC inside build_packet_text().

    Word boundaries work for plain words and most domains, but not for paths
    that begin with "/" or other punctuation. Bound instead on characters that
    can be part of host/path tokens, so "evil.com" does not match
    "notevil.com" and "/admin" still matches a request path.
    """
    return r"(?<![A-Za-z0-9_.-])" + re.escape(str(value or "").strip()) + r"(?![A-Za-z0-9_.-])"


# TCP flag names as sniffer.py writes them into packet["tcp_flags"] (a
# comma-joined string, "" when the segment carries no flags at all). Single
# letters are accepted too so a rule can be written the way tcpdump prints
# them ("FPU" for a Xmas scan).
_TCP_FLAG_ALIASES = {
    "F": "FIN", "FIN": "FIN",
    "S": "SYN", "SYN": "SYN",
    "R": "RST", "RST": "RST",
    "P": "PSH", "PSH": "PSH",
    "A": "ACK", "ACK": "ACK",
    "U": "URG", "URG": "URG",
    "E": "ECE", "ECE": "ECE",
    "C": "CWR", "CWR": "CWR",
}
# Spelled-out "no flags set", since an empty string cannot survive the list
# normalizers - and a flagless segment is exactly what a NULL scan is.
_TCP_FLAGS_NONE = "NONE"


def parse_tcp_flags(value) -> frozenset:
    """Canonical flag set from any of the accepted spellings.

    Accepts "SYN,ACK", "syn ack", "SA", "S+A" and ["SYN", "ACK"]; returns an
    empty set for "" / "NONE" / None, which is what a NULL scan looks like.
    """
    if value is None:
        return frozenset()
    if isinstance(value, (list, tuple, set, frozenset)):
        items = []
        for entry in value:
            items.extend(parse_tcp_flags(entry))
        return frozenset(items)
    text = str(value).strip().upper()
    if not text or text == _TCP_FLAGS_NONE:
        return frozenset()
    for separator in (",", "+", "|", "/", " "):
        text = text.replace(separator, ",")
    parts = [part for part in text.split(",") if part]
    flags = set()
    for part in parts:
        name = _TCP_FLAG_ALIASES.get(part)
        if name:
            flags.add(name)
            continue
        # "FPU"/"SA" - a run of single-letter flags with no separator.
        if all(letter in _TCP_FLAG_ALIASES for letter in part):
            flags.update(_TCP_FLAG_ALIASES[letter] for letter in part)
    return frozenset(flags)


def _tcp_flag_spec(value) -> str:
    """Normalized, storable spelling of one flag-set criterion."""
    flags = parse_tcp_flags(value)
    if not flags:
        return _TCP_FLAGS_NONE
    return ",".join(sorted(flags))


DEFAULT_RULESETS = [
    {
        "id": "builtin-arp",
        "name": "ARP discovery",
        "description": "Layer 2 ARP packets and address resolution chatter.",
        "enabled": True,
        "priority": 10,
        "source": "builtin",
        "match": {"eth_types": [0x0806]},
        "action": {"tag": "arp", "label": "ARP", "severity": "info"},
    },
    {
        "id": "builtin-ipv6",
        "name": "IPv6 traffic",
        "description": "Any IPv6 frame, including neighbor discovery and extension headers.",
        "enabled": True,
        "priority": 20,
        "source": "builtin",
        "match": {"ip_versions": [6]},
        "action": {"tag": "ipv6", "label": "IPv6", "severity": "info"},
    },
    {
        "id": "builtin-dns",
        "name": "DNS telemetry",
        "description": "DNS queries and responses over UDP/TCP port 53.",
        "enabled": True,
        "priority": 30,
        "source": "builtin",
        "match": {"protocols": ["udp", "tcp"], "ports": [53]},
        "action": {"tag": "dns", "label": "DNS", "severity": "low"},
    },
    {
        "id": "builtin-http",
        "name": "HTTP traffic",
        "description": "HTTP requests, responses and common web ports.",
        "enabled": True,
        "priority": 40,
        "source": "builtin",
        "match": {
            "protocols": ["tcp"],
            "ports": [80, 8080, 8000, 8888, 5000, 3000],
            "payload_contains": ["GET ", "POST ", "HEAD ", "HTTP/1.", "PUT ", "DELETE "],
        },
        "action": {"tag": "http", "label": "HTTP", "severity": "medium"},
    },
    {
        "id": "builtin-tls",
        "name": "TLS handshake",
        "description": "TLS client/server handshakes and common secure web ports.",
        "enabled": True,
        "priority": 50,
        "source": "builtin",
        "match": {"protocols": ["tcp"], "ports": [443, 8443, 9443], "payload_prefix_hex": ["16"]},
        "action": {"tag": "tls", "label": "TLS", "severity": "medium"},
    },
    {
        "id": "builtin-icmp",
        "name": "ICMP telemetry",
        "description": "Echo, destination unreachable and other ICMP messages.",
        "enabled": True,
        "priority": 60,
        "source": "builtin",
        "match": {"protocols": ["icmp", "icmpv6"]},
        "action": {"tag": "icmp", "label": "ICMP", "severity": "info"},
    },
]


def _default_ruleset_path() -> Path:
    return resolve_data_file("default_rulesets.json")


def load_builtin_rulesets() -> list[dict]:
    path = _default_ruleset_path()
    if path.exists():
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(payload, list):
                return [normalize_ruleset(item, allow_source=True) for item in payload if isinstance(item, dict)]
        except Exception:
            pass
    return [normalize_ruleset(item, allow_source=True) for item in DEFAULT_RULESETS]


def normalize_ruleset(item: dict, allow_source: bool = False) -> dict:
    data = item if isinstance(item, dict) else {}
    rule_id = str(data.get("id") or data.get("slug") or data.get("name") or "").strip()
    if not rule_id:
        rule_id = "custom-rule"
    name = str(data.get("name") or rule_id).strip() or rule_id
    description = str(data.get("description") or "").strip()
    enabled = bool(data.get("enabled", True))
    priority = safe_int(data.get("priority", 100), 100)
    match = data.get("match") if isinstance(data.get("match"), dict) else {}
    action = data.get("action") if isinstance(data.get("action"), dict) else {}
    normalized = {
        "id": rule_id,
        "name": name,
        "description": description,
        "enabled": enabled,
        "priority": priority,
        "match": normalize_match(match),
        "action": normalize_action(action),
    }
    if allow_source:
        normalized["source"] = str(data.get("source") or "custom").strip() or "custom"
    return normalized


def normalize_match(match: dict) -> dict:
    data = match if isinstance(match, dict) else {}

    def _list(key):
        raw = data.get(key, [])
        if isinstance(raw, (list, tuple, set)):
            values = raw
        else:
            values = [] if raw in (None, "") else [raw]
        cleaned = []
        for item in values:
            if item is None:
                continue
            if isinstance(item, str) and not item.strip():
                continue
            cleaned.append(normalize_protocol_name(item) if key in {"protocols", "exclude_protocols"} else item)
        return unique_ordered(cleaned)

    def _int_list(key):
        values = []
        raw = data.get(key, [])
        if not isinstance(raw, (list, tuple, set)):
            raw = [raw]
        for item in raw:
            try:
                values.append(int(item))
            except Exception:
                continue
        return unique_ordered(values)

    normalized = {
        "protocols": _list("protocols"),
        "exclude_protocols": _list("exclude_protocols"),
        "ip_versions": _int_list("ip_versions"),
        "eth_types": _int_list("eth_types"),
        "ports": _int_list("ports"),
        "src_ports": _int_list("src_ports"),
        "dst_ports": _int_list("dst_ports"),
        "port_regex": [str(item).strip() for item in _list("port_regex") if str(item).strip()],
        "ips": [str(item).strip().lower() for item in _list("ips") if str(item).strip()],
        "ip_regex": [str(item).strip() for item in _list("ip_regex") if str(item).strip()],
        "protocol_regex": [str(item).strip() for item in _list("protocol_regex") if str(item).strip()],
        "payload_contains": [str(item) for item in _list("payload_contains") if str(item).strip()],
        "payload_prefix_hex": [
            str(item).strip().lower().replace("0x", "")
            for item in _list("payload_prefix_hex")
            if str(item).strip()
        ],
        "payload_regex": [str(item).strip() for item in _list("payload_regex") if str(item).strip()],
        # Negative-context regex: ANY match here cancels an otherwise-fired
        # rule (ORed, same as payload_regex, just inverted). Lets a broad
        # signature ("union select") stay broad while excluding a known
        # benign context (e.g. an admin-tool's own information_schema
        # query) without having to make the positive regex itself more
        # fragile.
        "payload_regex_exclude": [str(item).strip() for item in _list("payload_regex_exclude") if str(item).strip()],
        # Scopes a content signature to request-side traffic only (HTTP
        # request lines/headers/bodies), skipping response bodies. Response
        # payloads legitimately contain most content signatures verbatim
        # (any HTML page has "<script", any JSON API echoes "user=" style
        # field names) so signatures aimed at what a client *sends* - XSS,
        # SQLi, command injection, path traversal payloads - false-positive
        # constantly without this.
        "request_only": bool(data.get("request_only", False)),
        # Header-field criteria. The payload/content keys above cannot express
        # a port scan (no payload at all, the signature *is* the flag
        # combination), a spoofed ARP reply or an ICMP type, so they get
        # first-class criteria rather than being forced through summary text.
        "tcp_flags": [_tcp_flag_spec(item) for item in _list("tcp_flags")],
        "tcp_flags_any": sorted(parse_tcp_flags(_list("tcp_flags_any"))),
        "tcp_flags_all": sorted(parse_tcp_flags(_list("tcp_flags_all"))),
        "icmp_types": _int_list("icmp_types"),
        "icmp_codes": _int_list("icmp_codes"),
        "arp_opcodes": _int_list("arp_opcodes"),
        "min_length": safe_int(data.get("min_length", 0), 0),
        "max_length": safe_int(data.get("max_length", 0), 0),
        "min_payload_text_length": safe_int(data.get("min_payload_text_length", 0), 0),
        # Declarative "N matches within T seconds" condition for
        # `mode: "stateful"` monitors - see anomaly.GenericThresholdDetector.
        # Zero/empty means "not a counting rule"; the other match criteria
        # above still decide what counts as one event.
        "count_threshold": max(0, safe_int(data.get("count_threshold", 0), 0)),
        "window_seconds": max(0, safe_int(data.get("window_seconds", 0), 0)),
        "group_by": _group_by_spec(data.get("group_by")),
    }
    return normalized


_GROUP_BY_CHOICES = frozenset({"src_ip", "dst_ip", "src_ip+dst_port", "dst_ip+dst_port", "src_ip+dst_ip"})


def _group_by_spec(value) -> str:
    text = str(value or "").strip().lower()
    return text if text in _GROUP_BY_CHOICES else "src_ip"


def normalize_action(action: dict) -> dict:
    data = action if isinstance(action, dict) else {}
    return {
        "tag": str(data.get("tag") or "").strip(),
        "label": str(data.get("label") or "").strip(),
        "severity": str(data.get("severity") or "info").strip().lower() or "info",
    }


def build_packet_text(packet: dict) -> str:
    """Text buffers that content/regex monitor criteria are allowed to inspect.

    Keep endpoint addresses out of this joined blob: established IDS engines
    scope payload/content matches separately from header fields, and mixing
    src/dst IPs or MACs into the payload buffer makes IOC-like literals fire
    on routing metadata rather than observed application data.
    """
    return " ".join(
        str(value)
        for value in (
            packet.get("summary"),
            packet.get("payload_text"),
            packet.get("domain"),
            packet.get("http_host"),
            packet.get("http_path"),
            packet.get("http_method"),
        )
        if value not in (None, "")
    ).lower()


def _is_http_response_packet(packet: dict) -> bool:
    """True for a packet carrying an HTTP response's start-line/body.

    Mirrors the same "HTTP/1." status-line prefix Sniffer._classify_tcp_banner
    already uses to label response segments - a request packet always starts
    with a method token (GET/POST/...) instead, so this is a cheap, reliable
    request/response split without needing a dedicated capture-side field.
    """
    text = str(packet.get("payload_text") or "").lstrip()
    return text[:5].upper() == "HTTP/"


def rule_matches_packet(rule: dict, packet: dict, *, packet_text: str | None = None) -> bool:
    if not rule or not rule.get("enabled", True):
        return False
    match = rule.get("match") if isinstance(rule.get("match"), dict) else {}
    if match.get("request_only") and _is_http_response_packet(packet):
        return False

    proto = normalize_protocol_name(packet.get("proto"))
    # Cheap protocol/port/length checks below run first and short-circuit
    # most non-matches, so packet_text (a string join + lower() over six
    # fields) is only built when a payload_contains/payload_regex check
    # actually needs it - and only once, even if the caller is evaluating
    # hundreds of rules against the same packet (see classify_packet /
    # sniff4hound.monitors.evaluate_packet, which compute it once per packet
    # and pass it in).
    payload_hex = str(packet.get("payload_hex") or "").lower()
    packet_length = safe_int(packet.get("length", 0), 0)

    protocols = [normalize_protocol_name(item) for item in match.get("protocols", []) if str(item).strip()]
    excluded_protocols = [normalize_protocol_name(item) for item in match.get("exclude_protocols", []) if str(item).strip()]
    if excluded_protocols:
        transport = str(packet.get("transport") or "").strip().lower()
        if proto in excluded_protocols or (transport and transport in excluded_protocols):
            return False

    if protocols:
        # A rule naming a transport ("tcp"/"udp") must keep matching after the
        # capture path has identified the application protocol on top of it,
        # so both names are accepted. Matching only `proto` is what stopped
        # the builtin SNMP rule (protocols:["udp"]) from ever firing once
        # _parse_snmp started reporting proto="snmp".
        # Deliberately NOT normalize_protocol_name(): that maps "" to
        # "unknown", which would give every packet with no transport recorded
        # a phantom transport of "unknown" and fire the
        # builtin-unknown-protocol rule on all of them.
        transport = str(packet.get("transport") or "").strip().lower()
        if proto not in protocols and (not transport or transport not in protocols):
            return False

    ip_versions = [safe_int(item, 0) for item in match.get("ip_versions", []) if safe_int(item, 0)]
    if ip_versions and safe_int(packet.get("ip_version", 0), 0) not in ip_versions:
        return False

    eth_types = [safe_int(item, 0) for item in match.get("eth_types", []) if safe_int(item, 0)]
    if eth_types and safe_int(packet.get("eth_type", 0), 0) not in eth_types:
        return False

    ports = [safe_int(item, 0) for item in match.get("ports", []) if safe_int(item, 0)]
    if ports:
        src_port = safe_int(packet.get("src_port", 0), 0)
        dst_port = safe_int(packet.get("dst_port", 0), 0)
        if src_port not in ports and dst_port not in ports:
            return False

    src_ports = [safe_int(item, 0) for item in match.get("src_ports", []) if safe_int(item, 0)]
    if src_ports and safe_int(packet.get("src_port", 0), 0) not in src_ports:
        return False

    dst_ports = [safe_int(item, 0) for item in match.get("dst_ports", []) if safe_int(item, 0)]
    if dst_ports and safe_int(packet.get("dst_port", 0), 0) not in dst_ports:
        return False

    port_regexes = [str(item).strip() for item in match.get("port_regex", []) if str(item).strip()]
    if port_regexes:
        src_port = str(safe_int(packet.get("src_port", 0), 0))
        dst_port = str(safe_int(packet.get("dst_port", 0), 0))
        matched_port = False
        for pattern in port_regexes:
            compiled = _compiled_regex(pattern)
            if compiled is not None and (compiled.search(src_port) or compiled.search(dst_port)):
                matched_port = True
                break
        if not matched_port:
            return False

    # Deliberately checked as direct header fields (src_ip/dst_ip), not via
    # build_packet_text's payload blob - that blob excludes endpoint
    # addresses on purpose (see its own docstring) so payload/content
    # criteria never fire on routing metadata. IP matching needs the exact
    # opposite: precise equality (or a regex explicitly scoped to just
    # these two fields) against the real address, not a substring search
    # over a blob that could contain one address as a substring of another
    # (e.g. "1.2.3.4" is a substring of "21.2.3.45").
    ips = [str(item).strip().lower() for item in match.get("ips", []) if str(item).strip()]
    if ips:
        src_ip = str(packet.get("src_ip") or "").strip().lower()
        dst_ip = str(packet.get("dst_ip") or "").strip().lower()
        if src_ip not in ips and dst_ip not in ips:
            return False

    ip_regexes = [str(item).strip() for item in match.get("ip_regex", []) if str(item).strip()]
    if ip_regexes:
        src_ip = str(packet.get("src_ip") or "")
        dst_ip = str(packet.get("dst_ip") or "")
        matched_ip = False
        for pattern in ip_regexes:
            compiled = _compiled_regex(pattern)
            if compiled is not None and (compiled.search(src_ip) or compiled.search(dst_ip)):
                matched_ip = True
                break
        if not matched_ip:
            return False

    protocol_regexes = [str(item).strip() for item in match.get("protocol_regex", []) if str(item).strip()]
    if protocol_regexes:
        transport = str(packet.get("transport") or "").strip().lower()
        matched_protocol = False
        for pattern in protocol_regexes:
            compiled = _compiled_regex(pattern)
            if compiled is not None and (compiled.search(proto) or (transport and compiled.search(transport))):
                matched_protocol = True
                break
        if not matched_protocol:
            return False

    # Header-field criteria: a scan, a spoofed ARP reply or an ICMP redirect
    # carries no payload to search, so these are matched against the decoded
    # header fields directly.
    flag_specs = [str(item) for item in match.get("tcp_flags", []) if str(item).strip()]
    flags_any = parse_tcp_flags(match.get("tcp_flags_any", []))
    flags_all = parse_tcp_flags(match.get("tcp_flags_all", []))
    if flag_specs or flags_any or flags_all:
        # Only TCP carries flags; without this an ARP or UDP frame (whose
        # tcp_flags is "") would match a NULL-scan rule on every packet.
        if proto != "tcp":
            return False
        raw_flags = str(packet.get("tcp_flags") or "").strip()
        if not raw_flags:
            # No decoded TCP header (build_base_packet's default, a synthetic
            # honeypot packet, a hand-built dict). Absent is not the same as
            # "no flags set"; treating it as the latter made every such packet
            # a critical NULL-scan hit.
            return False
        packet_flags = parse_tcp_flags(raw_flags)
        if flag_specs and not any(packet_flags == parse_tcp_flags(spec) for spec in flag_specs):
            return False
        if flags_any and not (packet_flags & flags_any):
            return False
        if flags_all and not flags_all.issubset(packet_flags):
            return False

    icmp_types = [safe_int(item, -1) for item in match.get("icmp_types", []) if safe_int(item, -1) >= 0]
    if icmp_types:
        if proto not in ("icmp", "icmpv6"):
            return False
        if safe_int(packet.get("icmp_type", -1), -1) not in icmp_types:
            return False

    icmp_codes = [safe_int(item, -1) for item in match.get("icmp_codes", []) if safe_int(item, -1) >= 0]
    if icmp_codes:
        if proto not in ("icmp", "icmpv6"):
            return False
        if safe_int(packet.get("icmp_code", -1), -1) not in icmp_codes:
            return False

    arp_opcodes = [safe_int(item, 0) for item in match.get("arp_opcodes", []) if safe_int(item, 0)]
    if arp_opcodes and safe_int(packet.get("arp_opcode", 0), 0) not in arp_opcodes:
        return False

    needles = [str(item).lower() for item in match.get("payload_contains", []) if str(item).strip()]
    prefix_hex = [str(item).lower().replace("0x", "") for item in match.get("payload_prefix_hex", []) if str(item).strip()]
    regexes = [str(item).strip() for item in match.get("payload_regex", []) if str(item).strip()]
    exclude_regexes = [str(item).strip() for item in match.get("payload_regex_exclude", []) if str(item).strip()]
    min_length = safe_int(match.get("min_length", 0), 0)
    max_length = safe_int(match.get("max_length", 0), 0)
    min_payload_text_length = safe_int(match.get("min_payload_text_length", 0), 0)

    if not any(
        (
            protocols, ip_versions, eth_types, ports, src_ports, dst_ports, port_regexes, ips, ip_regexes,
            protocol_regexes,
            needles, prefix_hex, regexes, flag_specs, flags_any, flags_all,
            icmp_types, icmp_codes, arp_opcodes,
        )
    ):
        if not (min_length or max_length or min_payload_text_length):
            # A pure count condition (count_threshold + window_seconds, no
            # other filter) is a deliberately valid, "any packet counts as
            # an event" monitor for GenericThresholdDetector - falling
            # through to the ordinary "no criteria at all" rejection below
            # would make such a monitor normalize successfully but never
            # actually match a single packet.
            if not (match.get("count_threshold") and match.get("window_seconds")):
                return False

    if needles or regexes or exclude_regexes:
        if packet_text is None:
            packet_text = build_packet_text(packet)

    if needles and not any(needle in packet_text for needle in needles):
        return False

    if prefix_hex and not any(payload_hex.startswith(prefix) for prefix in prefix_hex):
        return False

    if regexes:
        matched_any = False
        for pattern in regexes:
            compiled = _compiled_regex(pattern)
            if compiled is not None and compiled.search(packet_text):
                matched_any = True
                break
        if not matched_any:
            return False

    if exclude_regexes:
        for pattern in exclude_regexes:
            compiled = _compiled_regex(pattern)
            if compiled is not None and compiled.search(packet_text):
                return False

    if min_length and packet_length < min_length:
        return False

    if max_length and packet_length > max_length:
        return False

    if min_payload_text_length:
        # `payload_text` is only ever populated by Sniffer._interpret_payload()
        # after utils.is_printable_payload() confirmed the raw bytes are
        # mostly (>=55%) printable ASCII - so a length threshold here is a
        # reliable "readable/plaintext payload" signal, not a guess based on
        # summary/IP/MAC text that's always present regardless of payload.
        payload_text_length = len(str(packet.get("payload_text") or ""))
        if payload_text_length < min_payload_text_length:
            return False

    return True


def classify_packet(packet: dict, rulesets: list[dict]) -> list[dict]:
    matches = []
    packet_text = build_packet_text(packet)
    for rule in sorted(rulesets, key=lambda item: (safe_int(item.get("priority", 100), 100), str(item.get("name") or ""))):
        if rule_matches_packet(rule, packet, packet_text=packet_text):
            action = rule.get("action") if isinstance(rule.get("action"), dict) else {}
            matches.append(
                {
                    "rule_id": rule.get("id"),
                    "rule_name": rule.get("name"),
                    "tag": action.get("tag") or rule.get("id"),
                    "label": action.get("label") or rule.get("name"),
                    "severity": action.get("severity") or "info",
                }
            )
    return matches
