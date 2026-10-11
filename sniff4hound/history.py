"""DNS and ARP history: what one packet contributes, and the settings that govern it.

The history is a record of what the network *said*, kept whether or not anything
about it raised an alert. That is the difference from the packets table, which
only holds traffic that alerted (or was muted or excluded, which still lands
there untagged): a quiet resolver lookup or a new ARP binding is not an alert,
and it is exactly what an investigator wants to look back at later.

Everything in this module is a plain function of its input - no store, no
threads - so what a packet turns into can be checked on its own. Aggregating the
observations and writing them is the recorder's job (history_recorder.py).
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any

# Ceilings that keep one hostile packet from becoming a huge row.
MAX_DOMAIN_LENGTH = 253
MAX_ANSWER_LENGTH = 255
MAX_RECORDS_PER_PACKET = 32

HISTORY_DEFAULTS = {
    "dns_enabled": True,
    "arp_enabled": True,
    # How long a row stays after it was last seen. History is meant to outlive
    # the packets table (7 days by default), so the default is long; 0 keeps rows
    # until the row caps below push the oldest out.
    "retention_days": 90,
    "max_dns_rows": 200_000,
    "max_arp_bindings": 50_000,
    "max_arp_events": 100_000,
}

HISTORY_BOUNDS = {
    "retention_days": (0, 3650),
    "max_dns_rows": (1_000, 5_000_000),
    "max_arp_bindings": (100, 1_000_000),
    "max_arp_events": (100, 2_000_000),
}

BOOLEAN_FIELDS = ("dns_enabled", "arp_enabled")

# What kind of change an arp_events row records.
ARP_EVENT_KINDS = ("new_device", "ip_mac_changed", "mac_new_ip", "mac_mismatch")

_FALSE_TEXT = {"", "0", "false", "no", "off", "n"}
_TRUE_TEXT = {"1", "true", "yes", "on", "y"}


def _as_bool(value: Any, field: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and value in (0, 1):
        return bool(value)
    text = str(value).strip().lower()
    if text in _TRUE_TEXT:
        return True
    if text in _FALSE_TEXT:
        return False
    raise ValueError(f"{field} must be true or false")


def _bounded_int(value: Any, field: str, low: int, high: int) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{field} must be a whole number between {low} and {high}")
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        raise ValueError(f"{field} must be a whole number between {low} and {high}") from None
    if not low <= number <= high:
        raise ValueError(f"{field} must be between {low} and {high}")
    return number


def coerce_history_config(values: Any, current: dict | None = None) -> dict:
    """The full history configuration after applying a partial update.

    ``current`` is what is stored now (defaults for anything missing). A field
    that is absent keeps its current value, so a bad field rejects the whole
    update before anything is written. Unknown fields are an error: a typo should
    not silently do nothing.
    """
    if not isinstance(values, dict):
        raise ValueError("history config must be an object")
    unknown = sorted(set(values) - set(HISTORY_DEFAULTS))
    if unknown:
        raise ValueError(f"unknown history setting: {', '.join(unknown)}")
    merged = {**HISTORY_DEFAULTS, **(current or {})}
    for field in BOOLEAN_FIELDS:
        if field in values:
            merged[field] = _as_bool(values[field], field)
    for field, (low, high) in HISTORY_BOUNDS.items():
        if field in values:
            merged[field] = _bounded_int(values[field], field, low, high)
    return {field: merged[field] for field in HISTORY_DEFAULTS}


# --- DNS -------------------------------------------------------------------


@dataclass(frozen=True)
class DnsObservation:
    """One thing a DNS packet said: a question asked, or a record handed back."""

    domain: str
    record_type: str
    answer: str  # "" for a question, or for an answer-less response (NXDOMAIN...)
    is_response: bool
    rcode: str
    ttl: int | None
    source: str  # dns | mdns | llmnr
    transport: str
    client: str
    resolver: str


def normalize_domain(name: Any) -> str:
    text = str(name or "").strip().strip(".").lower()
    return text if 0 < len(text) <= MAX_DOMAIN_LENGTH else ""


def dns_observations(packet: dict) -> list[DnsObservation]:
    """What a decoded DNS/mDNS/LLMNR packet adds to the history.

    The sniffer attaches the parsed message as ``packet["dns_records"]``; a packet
    without it (not DNS, or one that did not parse) contributes nothing.
    """
    records = packet.get("dns_records")
    if not isinstance(records, dict):
        return []
    is_response = bool(records.get("is_response"))
    rcode = str(records.get("rcode") or "NOERROR")
    source = str(packet.get("domain_source") or "dns").strip().lower() or "dns"
    transport = str(packet.get("transport") or "udp").strip().lower() or "udp"
    src_ip = str(packet.get("src_ip") or "").strip()
    dst_ip = str(packet.get("dst_ip") or "").strip()
    # A query goes client -> resolver; a response comes back resolver -> client.
    client, resolver = (dst_ip, src_ip) if is_response else (src_ip, dst_ip)

    def build(domain: str, record_type: str, answer: str, ttl: int | None) -> DnsObservation:
        return DnsObservation(
            domain=domain,
            record_type=record_type,
            answer=answer,
            is_response=is_response,
            rcode=rcode,
            ttl=ttl,
            source=source,
            transport=transport,
            client=client,
            resolver=resolver,
        )

    found: list[DnsObservation] = []
    answers = [item for item in (records.get("answers") or []) if isinstance(item, dict)]
    for item in answers[:MAX_RECORDS_PER_PACKET]:
        domain = normalize_domain(item.get("name"))
        data = str(item.get("data") or "").strip()[:MAX_ANSWER_LENGTH]
        if not domain or not data:
            continue
        ttl = item.get("ttl")
        found.append(build(domain, str(item.get("type") or "?"), data, int(ttl) if isinstance(ttl, int) and ttl >= 0 else None))

    # The question is recorded too: a lookup that was never answered, or answered
    # with an error, has no record of its own and would otherwise leave no trace.
    # A successful response that carried records is already fully described by
    # them (a CNAME chain answers a question for a name it never repeats), so
    # adding an "answer-less" row beside them would only suggest it failed.
    if is_response and rcode == "NOERROR" and found:
        return found
    for item in [q for q in (records.get("questions") or []) if isinstance(q, dict)][:MAX_RECORDS_PER_PACKET]:
        domain = normalize_domain(item.get("name"))
        record_type = str(item.get("type") or "?")
        if domain:
            found.append(build(domain, record_type, "", None))
    return found


# --- ARP -------------------------------------------------------------------

_NULL_MACS = {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}


@dataclass(frozen=True)
class ArpObservation:
    ip: str
    mac: str
    operation: str  # request | reply | other
    interface: str
    gratuitous: bool  # the sender announces its own address
    mismatch: str  # "" or "<ethernet source> announces <arp sender>"


def normalize_mac(value: Any) -> str:
    text = str(value or "").strip().lower().replace("-", ":")
    parts = text.split(":")
    if len(parts) != 6 or any(len(part) != 2 for part in parts):
        return ""
    try:
        for part in parts:
            int(part, 16)
    except ValueError:
        return ""
    return "" if text in _NULL_MACS else text


def arp_observation(packet: dict) -> ArpObservation | None:
    """The IP-to-MAC claim an ARP packet makes, or None when it makes none.

    The claim is the *sender* pair carried inside the ARP payload, which is what
    the sender asserts about itself. A probe (sender 0.0.0.0) asserts nothing
    about an address and is skipped.
    """
    if str(packet.get("proto") or "").lower() != "arp":
        return None
    mac = normalize_mac(packet.get("arp_sender_mac"))
    if not mac:
        return None
    try:
        sender = ipaddress.IPv4Address(str(packet.get("src_ip") or "").strip())
    except ValueError:
        return None
    if sender.is_unspecified or sender.is_multicast:
        return None
    target = str(packet.get("dst_ip") or "").strip()
    opcode = int(packet.get("arp_opcode") or 0)
    return ArpObservation(
        ip=str(sender),
        mac=mac,
        operation={1: "request", 2: "reply"}.get(opcode, "other"),
        interface=str(packet.get("interface") or "").strip(),
        gratuitous=target == str(sender),
        mismatch=str(packet.get("arp_mac_mismatch") or "").strip(),
    )
