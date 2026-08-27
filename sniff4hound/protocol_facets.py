"""Per-protocol statistics for the Protocols view.

The Protocols page used to render the same four counters (frames, open,
filtered, other) for all of its protocol slices, which says nothing about
the protocol being looked at: "open vs filtered" is a port-scan notion, and
it is meaningless for ARP, STP or DHCP. This module declares, per protocol,
which columns actually carry signal for that protocol and how to label the
raw values, so the view can render facets that match what the traffic is.

Everything here is aggregated with SQL GROUP BY over the same filtered
packet set the listing uses - never by pulling rows into Python and
counting them - so a slice of a few hundred thousand packets costs one
indexed scan per facet instead of a transfer.
"""

from __future__ import annotations

from .utils import safe_int


# --- value labellers -------------------------------------------------------
# Raw wire values are numbers; an operator reads names. Each labeller maps
# the stored column value to something human, falling back to the raw value
# when the code is unknown rather than hiding it.

ICMP_TYPES = {
    0: "Echo reply",
    3: "Destination unreachable",
    4: "Source quench",
    5: "Redirect",
    8: "Echo request",
    9: "Router advertisement",
    10: "Router solicitation",
    11: "Time exceeded",
    12: "Parameter problem",
    13: "Timestamp",
    14: "Timestamp reply",
    17: "Address mask request",
    18: "Address mask reply",
}

ICMPV6_TYPES = {
    1: "Destination unreachable",
    2: "Packet too big",
    3: "Time exceeded",
    4: "Parameter problem",
    128: "Echo request",
    129: "Echo reply",
    130: "Multicast listener query",
    131: "Multicast listener report",
    132: "Multicast listener done",
    133: "Router solicitation",
    134: "Router advertisement",
    135: "Neighbor solicitation",
    136: "Neighbor advertisement",
    137: "Redirect",
    143: "Multicast listener report v2",
}

ARP_OPCODES = {
    1: "Request (who-has)",
    2: "Reply (is-at)",
    3: "RARP request",
    4: "RARP reply",
    8: "InARP request",
    9: "InARP reply",
}

IGMP_TYPES = {
    0x11: "Membership query",
    0x12: "Membership report v1",
    0x16: "Membership report v2",
    0x17: "Leave group",
    0x22: "Membership report v3",
}


def _label_icmp(value) -> str:
    code = safe_int(value, 0)
    return f"{code} · {ICMP_TYPES[code]}" if code in ICMP_TYPES else f"Type {code}"


def _label_icmpv6(value) -> str:
    code = safe_int(value, 0)
    return f"{code} · {ICMPV6_TYPES[code]}" if code in ICMPV6_TYPES else f"Type {code}"


def _label_arp(value) -> str:
    code = safe_int(value, 0)
    return ARP_OPCODES.get(code, f"Opcode {code}")


def _label_igmp(value) -> str:
    code = safe_int(value, 0)
    return IGMP_TYPES.get(code, f"Type {code}")


def _label_port(value) -> str:
    port = safe_int(value, 0)
    return str(port) if port else "none"


def _label_plain(value) -> str:
    text = str(value if value is not None else "").strip()
    return text or "none"


def _label_ip_version(value) -> str:
    version = safe_int(value, 0)
    return {4: "IPv4", 6: "IPv6"}.get(version, "unknown")


LABELLERS = {
    "icmp_type": _label_icmp,
    "icmpv6_type": _label_icmpv6,
    "arp_opcode": _label_arp,
    "igmp_type": _label_igmp,
    "src_port": _label_port,
    "dst_port": _label_port,
    "ip_version": _label_ip_version,
}


# --- facet declarations ----------------------------------------------------
# A facet is (column, title, subtitle). `column` must be a real column of
# `packets` - these names are interpolated into SQL, so they are never
# allowed to come from a request; see resolve_facets().

PACKET_COLUMNS = frozenset(
    {
        "interface", "direction", "eth_src", "eth_dst", "eth_type", "ip_version",
        "src_ip", "dst_ip", "proto", "src_port", "dst_port", "ttl", "hop_limit",
        "length", "payload_len", "state", "scan_state", "tcp_flags", "icmp_type",
        "icmp_code", "arp_opcode", "domain", "domain_source", "http_method",
        "http_path", "http_host", "summary",
    }
)

# Facets shared by anything that rides on IP and has ports.
_PORT_FACETS = (
    ("dst_port", "Destination ports", "Where the traffic is headed."),
    ("src_port", "Source ports", "Where the traffic came from."),
)

_DNSISH_FACETS = (
    ("domain", "Queried names", "Names resolved through this protocol."),
    ("src_ip", "Top resolvers", "Hosts asking or answering."),
)

DEFAULT_FACETS = (
    ("interface", "Interfaces", "Where these frames were seen."),
    ("direction", "Direction", "Inbound versus outbound."),
    ("length", "Frame sizes", "Distribution of frame length."),
)

PROTOCOL_FACETS: dict[str, tuple] = {
    # --- transport ---------------------------------------------------------
    "tcp": (
        ("tcp_flags", "Flag combinations", "SYN-only bursts are scans; RST bursts are refusals."),
        ("dst_port", "Destination ports", "Services being contacted."),
        ("state", "Connection state", "How the peer answered."),
    ),
    "udp": (
        ("dst_port", "Destination ports", "Services being contacted."),
        ("src_port", "Source ports", "Where the datagrams came from."),
        ("length", "Datagram sizes", "Amplification shows up as a size skew."),
    ),
    "sctp": _PORT_FACETS + (("state", "Association state", "How the association progressed."),),
    "dccp": _PORT_FACETS,
    "udplite": _PORT_FACETS,
    # --- network -----------------------------------------------------------
    "icmp": (
        ("icmp_type", "ICMP types", "Echo, unreachable, redirect and friends."),
        ("icmp_code", "ICMP codes", "The subtype of each message."),
        ("src_ip", "Top sources", "Who is emitting these messages."),
    ),
    "icmpv6": (
        ("icmp_type", "ICMPv6 types", "Neighbor discovery lives here."),
        ("icmp_code", "ICMPv6 codes", "The subtype of each message."),
        ("src_ip", "Top sources", "Who is emitting these messages."),
    ),
    "igmp": (
        ("icmp_type", "IGMP types", "Queries, reports and leaves."),
        ("dst_ip", "Multicast groups", "Groups being joined or queried."),
    ),
    "arp": (
        ("arp_opcode", "Operation", "Who-has requests versus is-at replies."),
        ("eth_src", "Sender MACs", "A MAC answering for many IPs is spoofing."),
        ("dst_ip", "Targets asked about", "Sequential targets mean a sweep."),
    ),
    "rarp": (
        ("arp_opcode", "Operation", "Reverse address resolution exchanges."),
        ("eth_src", "Sender MACs", "Hardware asking for its own address."),
    ),
    "ipv6": (
        ("hop_limit", "Hop limit", "A hop-limit spread hints at distinct origins."),
        ("dst_ip", "Destinations", "Where the traffic is going."),
    ),
    "gre": (("src_ip", "Tunnel endpoints", "Encapsulation peers."),),
    "esp": (("src_ip", "Tunnel endpoints", "IPsec peers exchanging ESP."),),
    "ah": (("src_ip", "Tunnel endpoints", "IPsec peers exchanging AH."),),
    "ospf": (("src_ip", "Speaking routers", "Routers in the OSPF adjacency."),),
    "vrrp": (("src_ip", "Advertising routers", "Who claims the virtual address."),),
    # --- link --------------------------------------------------------------
    "stp": (
        ("eth_src", "Bridge MACs", "A new root bridge is a topology change."),
        ("interface", "Interfaces", "Where BPDUs are arriving."),
    ),
    "llc": (("eth_src", "Source MACs", "Stations using bare LLC."),),
    "llc-snap": (("eth_src", "Source MACs", "Stations using LLC/SNAP."),),
    "lldp": (
        ("eth_src", "Advertising MACs", "Devices announcing themselves."),
        ("interface", "Interfaces", "Where neighbours were discovered."),
    ),
    "cdp": (
        ("eth_src", "Advertising MACs", "Cisco devices announcing themselves."),
        ("interface", "Interfaces", "Where neighbours were discovered."),
    ),
    "eapol": (
        ("eth_src", "Supplicant MACs", "Stations authenticating to the port."),
        ("interface", "Interfaces", "Where 802.1X exchanges happen."),
    ),
    "wol": (("eth_dst", "Woken MACs", "Targets of magic packets."),),
    # --- application: name resolution --------------------------------------
    "dns": _DNSISH_FACETS + (("dst_port", "Ports", "53, or a non-standard resolver."),),
    "mdns": _DNSISH_FACETS,
    "llmnr": _DNSISH_FACETS,
    "nbns": (("domain", "Queried names", "NetBIOS names being resolved."), ("src_ip", "Top hosts", "Who is asking.")),
    "ssdp": (("http_method", "Methods", "M-SEARCH discovery versus NOTIFY."), ("src_ip", "Announcing hosts", "Devices advertising services.")),
    # --- application: web --------------------------------------------------
    "http": (
        ("http_method", "Methods", "GET-heavy is browsing; POST-heavy is upload."),
        ("http_host", "Hosts", "Virtual hosts being requested."),
        ("http_path", "Paths", "Repeated odd paths are enumeration."),
    ),
    "tls": (
        ("domain", "SNI names", "The hostname requested inside the handshake."),
        ("dst_port", "Ports", "443, or TLS somewhere unexpected."),
        ("dst_ip", "Destinations", "Where the sessions terminate."),
    ),
    "quic": (("domain", "SNI names", "Names inside the QUIC handshake."), ("dst_ip", "Destinations", "Where the sessions terminate.")),
    # --- application: infrastructure ---------------------------------------
    "dhcp": (
        ("summary", "Message types", "DISCOVER/OFFER/REQUEST/ACK balance."),
        ("eth_src", "Client MACs", "Which hardware is asking for a lease."),
    ),
    "ntp": (("src_ip", "Time sources", "Servers being polled."), ("dst_port", "Ports", "123, or something pretending.")),
    "snmp": (("src_ip", "Agents and managers", "Who is polling whom."), ("dst_port", "Ports", "161 polling versus 162 traps.")),
    "syslog": (("src_ip", "Log sources", "Hosts shipping their logs."),),
    "tftp": (("src_ip", "Peers", "Hosts moving files without auth."),),
    "radius": (("src_ip", "NAS clients", "Devices authenticating users."),),
    "kerberos": (("src_ip", "Principals", "Hosts requesting tickets."),),
    "ldap": (("dst_ip", "Directory servers", "Where the queries land."), ("dst_port", "Ports", "389 plain versus 636 TLS.")),
    "smb": (("dst_ip", "File servers", "Where the shares live."), ("dst_port", "Ports", "445 direct versus 139 over NetBIOS.")),
    "rdp": (("dst_ip", "Targets", "Hosts exposing remote desktop."), ("src_ip", "Origins", "Where the sessions come from.")),
    "ssh": (("dst_ip", "Targets", "Hosts exposing SSH."), ("src_ip", "Origins", "Repeated origins are brute force.")),
    "telnet": (("dst_ip", "Targets", "Hosts still exposing telnet."), ("src_ip", "Origins", "Where the sessions come from.")),
    "ftp": (("dst_ip", "Servers", "Hosts exposing FTP."), ("src_ip", "Origins", "Where the sessions come from.")),
    "smtp": (("dst_ip", "Mail servers", "Where mail is delivered."), ("src_ip", "Senders", "Hosts submitting mail.")),
    "imap": (("dst_ip", "Mail servers", "Where mailboxes are read."),),
    "pop3": (("dst_ip", "Mail servers", "Where mailboxes are drained."),),
    "sip": (("dst_ip", "Signalling peers", "Where calls are set up."),),
    "rtp": (("dst_ip", "Media peers", "Where the media flows."), ("dst_port", "Ports", "Even ports carry media, odd carry RTCP.")),
    "bgp": (("src_ip", "Peers", "Routers in the BGP session."),),
    "mqtt": (("dst_ip", "Brokers", "Where clients publish."),),
    "modbus": (("dst_ip", "PLC endpoints", "Devices being commanded."), ("summary", "Function codes", "Writes are more sensitive than reads.")),
    "dnp3": (("dst_ip", "Outstations", "Devices being polled."), ("summary", "Function codes", "Control requests versus reads.")),
    "vxlan": (("src_ip", "Tunnel endpoints", "VTEPs carrying overlay traffic."),),
    "wireguard": (("src_ip", "Tunnel endpoints", "WireGuard peers."),),
    "isakmp": (("src_ip", "Tunnel endpoints", "IKE negotiation peers."),),
    # --- residual ----------------------------------------------------------
    "unknown": DEFAULT_FACETS,
    "unparseable": (
        ("interface", "Interfaces", "Where malformed frames arrive - a spike is possible evasion."),
        ("length", "Frame sizes", "Truncated or oversized frames stand out here."),
        ("eth_src", "Source MACs", "Who is emitting frames the parser rejects."),
    ),
}


def resolve_facets(proto: str) -> tuple:
    """Facets for a protocol, guaranteed to reference real columns.

    The column names are interpolated into SQL, so this is the only place
    allowed to decide them: an unknown protocol gets DEFAULT_FACETS rather
    than anything derived from the caller's string, and every declared
    column is checked against PACKET_COLUMNS.
    """
    facets = PROTOCOL_FACETS.get(str(proto or "").strip().lower(), DEFAULT_FACETS)
    return tuple(facet for facet in facets if facet[0] in PACKET_COLUMNS)


def label_value(column: str, value):
    """Human label for a grouped value, keyed by the column it came from."""
    labeller = LABELLERS.get(str(column or ""))
    if labeller is not None:
        return labeller(value)
    return _label_plain(value)
