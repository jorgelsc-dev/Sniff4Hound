"""Conservative device-type inference from already captured metadata.

The classifier intentionally avoids active probing.  A label is emitted only
when ports, protocols, banners or decoder metadata provide useful evidence;
otherwise the device stays ``Unknown`` instead of presenting a guess as fact.
"""

from __future__ import annotations

import re
from collections import defaultdict


DEVICE_TYPES = ("Router", "Switch", "Phone", "PC", "Server", "Printer", "Camera", "IoT", "Unknown")

_KEYWORDS = {
    "Router": {
        "router": 5, "gateway": 4, "openwrt": 6, "mikrotik": 6, "routeros": 6,
        "juniper": 5, "cisco ios": 6, "fritz!box": 6, "pfsense": 5,
    },
    "Switch": {"switch": 5, "lldp": 4, "spanning tree": 5, "cdp": 3},
    "Phone": {
        "iphone": 7, "android": 6, "smartphone": 7, "galaxy": 5, "pixel": 5,
        "ios": 4, "_airplay": 4, "_companion-link": 5,
    },
    "PC": {
        "workstation": 5, "windows": 4, "macbook": 6, "desktop": 5,
        "ubuntu": 3, "fedora": 3,
    },
    "Server": {
        "server": 3, "nginx": 5, "apache": 5, "openssh": 4, "postgresql": 5,
        "mysql": 5, "redis": 5, "kubernetes": 5,
    },
    "Printer": {
        "printer": 7, "jetdirect": 7, "laserjet": 7, "epson": 5,
        "brother": 4, "cups": 5, "ipp": 4,
    },
    "Camera": {"camera": 6, "onvif": 7, "ipcam": 7, "rtsp": 4, "hikvision": 7, "dahua": 7},
    "IoT": {"iot": 5, "mqtt": 5, "coap": 5, "home assistant": 5, "zigbee": 5},
}

_PORT_HINTS = {
    67: ("Router", 5, "DHCP server (67)"),
    179: ("Router", 6, "BGP (179)"),
    520: ("Router", 5, "RIP (520)"),
    515: ("Printer", 6, "LPD printing (515)"),
    631: ("Printer", 6, "IPP printing (631)"),
    9100: ("Printer", 7, "JetDirect printing (9100)"),
    554: ("Camera", 5, "RTSP media (554)"),
    8554: ("Camera", 5, "RTSP media (8554)"),
    1883: ("IoT", 5, "MQTT (1883)"),
    8883: ("IoT", 5, "MQTT TLS (8883)"),
    5683: ("IoT", 6, "CoAP (5683)"),
    5684: ("IoT", 6, "CoAP DTLS (5684)"),
    135: ("PC", 2, "Windows RPC (135)"),
    139: ("PC", 3, "NetBIOS (139)"),
    445: ("PC", 3, "SMB (445)"),
    3389: ("PC", 4, "Remote Desktop (3389)"),
}

_SERVER_PORTS = {21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 5432, 6379, 8080, 8443}
_PROTOCOL_HINTS = {
    "ospf": ("Router", 7), "bgp": ("Router", 7), "rip": ("Router", 6),
    "vrrp": ("Router", 6), "hsrp": ("Router", 6),
    "lldp": ("Switch", 6), "cdp": ("Switch", 6), "stp": ("Switch", 6),
    "mqtt": ("IoT", 5), "coap": ("IoT", 6), "rtsp": ("Camera", 4),
}

# Whole-token matching, not "keyword in text": a plain substring check let
# short/common keywords fire on unrelated text that merely happened to
# contain them (e.g. "ios" inside "servicios"/"radios", "ipp" inside
# "shipping", "cdp" inside a random hex/base64 run) - the classifier looked
# confident while actually guessing. A keyword now only counts when it is
# not glued to another letter/digit on either side, so it has to appear as
# its own token/phrase in the observed metadata to count as evidence.
def _compile_keyword(keyword: str) -> "re.Pattern[str]":
    return re.compile(r"(?<![a-z0-9])" + re.escape(keyword) + r"(?![a-z0-9])")


_KEYWORD_PATTERNS = {
    kind: [(keyword, _compile_keyword(keyword), weight) for keyword, weight in keywords.items()]
    for kind, keywords in _KEYWORDS.items()
}


def infer_device_profile(observations) -> dict:
    """Return a label, confidence and short evidence list.

    ``observations`` are endpoint-relative packet facts.  They contain only
    metadata already stored by Sniff4Hound and never require a probe.
    """
    scores = defaultdict(int)
    evidence = defaultdict(list)
    local_ports = set()
    protocols = set()
    text_parts = []

    for row in observations or ():
        port = int(row.get("local_port") or 0)
        if port:
            local_ports.add(port)
        proto = str(row.get("proto") or "").strip().lower()
        if proto:
            protocols.add(proto)
        for key in ("summary", "banner_text", "domain", "details_json", "tags_json"):
            value = str(row.get(key) or "").strip()
            if value:
                text_parts.append(value.lower())

    for port in sorted(local_ports):
        hint = _PORT_HINTS.get(port)
        if hint:
            kind, weight, reason = hint
            scores[kind] += weight
            evidence[kind].append(reason)
        if port in _SERVER_PORTS:
            scores["Server"] += 2
            evidence["Server"].append(f"service port {port}")

    for proto in protocols:
        hint = _PROTOCOL_HINTS.get(proto)
        if hint:
            kind, weight = hint
            scores[kind] += weight
            evidence[kind].append(f"{proto.upper()} protocol")

    searchable = " ".join(text_parts)[:20000]
    for kind, patterns in _KEYWORD_PATTERNS.items():
        for keyword, pattern, weight in patterns:
            if pattern.search(searchable):
                scores[kind] += weight
                evidence[kind].append(f'metadata "{keyword}"')

    if not scores:
        return {"device_type": "Unknown", "device_confidence": "unknown", "device_evidence": []}

    ranked = sorted(scores.items(), key=lambda item: (-item[1], DEVICE_TYPES.index(item[0])))
    kind, score = ranked[0]
    runner_up = ranked[1][1] if len(ranked) > 1 else 0
    if score < 3:
        return {"device_type": "Unknown", "device_confidence": "unknown", "device_evidence": []}
    confidence = "high" if score >= 7 and score - runner_up >= 3 else "medium" if score >= 4 else "low"
    unique_evidence = list(dict.fromkeys(evidence[kind]))[:3]
    return {"device_type": kind, "device_confidence": confidence, "device_evidence": unique_evidence}
