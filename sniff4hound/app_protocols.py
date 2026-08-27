"""Application-layer (and remaining lower-layer) protocol identification.

The capture pipeline already decodes a handful of protocols by hand - DNS,
DHCP, mDNS, SNMP, Modbus, DNP3 and friends - and each of those sets
`packet["proto"]` to its own name rather than leaving it as "tcp"/"udp".
This module extends that same convention to the rest of the stack, so the
Protocols view can offer a slice per real protocol instead of lumping every
TCP session under "tcp".

Identification is signature-first, port-second, deliberately:

* a signature is evidence about the bytes actually on the wire, so SSH on
  2222 or HTTP on 8080 is still recognised, and
* a port is only a convention, so it is consulted only after the signatures
  come up empty. It is still a fallback, not a veto: a segment carrying the
  middle of a TLS record starts at no recognisable boundary, so TCP/443 with
  unrecognisable bytes is reported as "tls" on the strength of the port
  alone. Port-derived names are therefore a best guess, not an assertion
  about the payload.

Everything here is stdlib-only byte inspection; no third-party parsing
libraries, per the project's capture-pipeline policy.
"""

from __future__ import annotations


# --- IP protocol numbers not already dispatched by sniffer.py -------------

IP_PROTO_IPIP = 4
IP_PROTO_EGP = 8
IP_PROTO_DCCP = 33
IP_PROTO_RSVP = 46
IP_PROTO_EIGRP = 88
IP_PROTO_OSPF = 89
IP_PROTO_PIM = 103
IP_PROTO_VRRP = 112
IP_PROTO_L2TP = 115
IP_PROTO_SCTP = 132
IP_PROTO_UDPLITE = 136

# IP protocol number -> protocol name, for the numbers sniffer.py does not
# already give a dedicated parser.
IP_PROTOCOLS = {
    IP_PROTO_IPIP: "ipip",
    IP_PROTO_EGP: "egp",
    IP_PROTO_DCCP: "dccp",
    IP_PROTO_RSVP: "rsvp",
    IP_PROTO_EIGRP: "eigrp",
    IP_PROTO_OSPF: "ospf",
    IP_PROTO_PIM: "pim",
    IP_PROTO_VRRP: "vrrp",
    IP_PROTO_L2TP: "l2tp",
    IP_PROTO_UDPLITE: "udplite",
}

# --- EtherTypes handled above the IPv4/IPv6/ARP dispatch ------------------

ETHERTYPE_LLDP = 0x88CC
ETHERTYPE_EAPOL = 0x888E
ETHERTYPE_PPPOE_DISCOVERY = 0x8863
ETHERTYPE_PPPOE_SESSION = 0x8864
ETHERTYPE_MPLS = 0x8847
ETHERTYPE_PROFINET = 0x8892
ETHERTYPE_ETHERCAT = 0x88A4
ETHERTYPE_LOOP = 0x9000
ETHERTYPE_WOL = 0x0842

ETHER_PROTOCOLS = {
    ETHERTYPE_LLDP: "lldp",
    ETHERTYPE_EAPOL: "eapol",
    ETHERTYPE_PPPOE_DISCOVERY: "pppoe",
    ETHERTYPE_PPPOE_SESSION: "pppoe",
    ETHERTYPE_MPLS: "mpls",
    ETHERTYPE_PROFINET: "profinet",
    ETHERTYPE_ETHERCAT: "ethercat",
    ETHERTYPE_LOOP: "loop",
    ETHERTYPE_WOL: "wol",
}

# --- SNAP-encapsulated protocols ------------------------------------------
# Some link-layer protocols have no EtherType at all: they are addressed by
# an OUI plus a protocol id inside an 802.2 SNAP header. Keyed by
# (OUI bytes, protocol id).

OUI_CISCO = b"\x00\x00\x0c"

SNAP_PROTOCOLS = {
    (OUI_CISCO, 0x2000): "cdp",
    (OUI_CISCO, 0x2004): "dtp",
    (OUI_CISCO, 0x010B): "pvstp",
}


# --- Port conventions ------------------------------------------------------

TCP_PORT_PROTOCOLS = {
    21: "ftp", 2121: "ftp",
    20: "ftp-data",
    22: "ssh", 2222: "ssh", 8022: "ssh",
    23: "telnet", 2323: "telnet",
    25: "smtp", 587: "smtp", 2525: "smtp",
    465: "smtps",
    43: "whois",
    79: "finger",
    80: "http", 8000: "http", 8008: "http", 8080: "http", 8081: "http", 8888: "http",
    88: "kerberos",
    110: "pop3", 995: "pop3s",
    111: "rpcbind",
    119: "nntp",
    135: "msrpc",
    139: "smb", 445: "smb",
    143: "imap", 993: "imaps",
    179: "bgp",
    389: "ldap", 3268: "ldap",
    443: "tls", 8443: "tls", 9443: "tls",
    636: "ldaps", 3269: "ldaps",
    873: "rsync",
    1080: "socks",
    1433: "mssql",
    1521: "oracle",
    1723: "pptp",
    3128: "http-proxy",
    3306: "mysql", 3307: "mysql",
    3389: "rdp", 3390: "rdp",
    5060: "sip", 5061: "sip",
    5222: "xmpp", 5269: "xmpp",
    5432: "postgres", 5433: "postgres",
    5672: "amqp",
    5900: "vnc", 5901: "vnc", 5902: "vnc", 5903: "vnc",
    6379: "redis", 6380: "redis",
    6667: "irc", 6697: "irc",
    9200: "elasticsearch",
    9418: "git",
    11211: "memcached",
    27017: "mongodb",
    1883: "mqtt", 8883: "mqtt",
    502: "modbus",
    20000: "dnp3",
    47808: "bacnet",
    102: "s7comm",
}

UDP_PORT_PROTOCOLS = {
    53: "dns",
    67: "dhcp", 68: "dhcp", 546: "dhcpv6", 547: "dhcpv6",
    69: "tftp",
    88: "kerberos",
    123: "ntp",
    137: "nbns", 138: "nbdgm",
    161: "snmp", 162: "snmp",
    177: "xdmcp",
    500: "isakmp", 4500: "isakmp",
    514: "syslog",
    520: "rip", 521: "rip",
    623: "ipmi",
    1194: "openvpn",
    1701: "l2tp",
    1812: "radius", 1813: "radius",
    1900: "ssdp",
    3478: "stun", 3479: "stun",
    4789: "vxlan",
    5060: "sip", 5061: "sip",
    5353: "mdns",
    5355: "llmnr",
    6081: "geneve",
    5683: "coap", 5684: "coap",
    51820: "wireguard",
    47808: "bacnet",
    443: "quic",
}

# HTTP request methods that may open a plaintext HTTP request line, plus the
# status-line prefix a response starts with.
_HTTP_PREFIXES = (
    b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ",
    b"TRACE ", b"CONNECT ", b"HTTP/",
)

# SSDP and SIP both ride on HTTP-like request lines, so they are checked
# before the generic HTTP prefixes below.
_SSDP_PREFIXES = (b"M-SEARCH ", b"NOTIFY ", b"HTTP/1.1 200 OK\r\nCACHE-CONTROL")
_SIP_PREFIXES = (
    b"INVITE ", b"REGISTER ", b"SUBSCRIBE ", b"BYE ", b"CANCEL ", b"ACK ",
    b"OPTIONS sip:", b"SIP/2.0",
)


def _looks_like_tls(payload: bytes) -> bool:
    """A TLS record header: content type, then a 0x03 0x0x version pair.

    Same shape check sniffer.py already uses to keep ciphertext out of
    payload_text; repeated here so classification does not depend on import
    order between the two modules.
    """
    return (
        len(payload) >= 3
        and payload[0] in (0x14, 0x15, 0x16, 0x17)
        and payload[1] == 0x03
        and payload[2] <= 0x04
    )


def _looks_like_quic(payload: bytes) -> bool:
    """QUIC long header: high bit set, fixed bit set, then a 4-byte version.

    Version 0 is Version Negotiation, which is still QUIC. Short-header
    (1-RTT) packets carry no version and are indistinguishable from noise,
    so those fall back to the port map.
    """
    if len(payload) < 5:
        return False
    first = payload[0]
    if not (first & 0x80):
        return False
    if not (first & 0x40):
        return False
    version = int.from_bytes(payload[1:5], "big")
    return version == 0 or (version >> 16) in (0x0000, 0x0001, 0xFF00, 0xFACE)


def _startswith_any(payload: bytes, prefixes) -> bool:
    return any(payload.startswith(prefix) for prefix in prefixes)


def classify_tcp(src_port: int, dst_port: int, payload: bytes) -> str:
    """Best-effort protocol name for a TCP segment, or "" when unknown."""
    data = payload or b""
    if data:
        if _looks_like_tls(data):
            return "tls"
        if data.startswith(b"SSH-"):
            return "ssh"
        if _startswith_any(data, _SIP_PREFIXES):
            return "sip"
        if _startswith_any(data, _HTTP_PREFIXES):
            return "http"
        if data.startswith(b"RFB "):
            return "vnc"
        if data.startswith(b"\xff\xfb") or data.startswith(b"\xff\xfd"):
            return "telnet"
        if data[0:1] == b"\xff" and len(data) >= 4 and data[1] in (0xFB, 0xFC, 0xFD, 0xFE):
            return "telnet"
        # SMB2 and the older SMB1 both announce themselves in the first four
        # bytes of the NetBIOS-framed payload.
        if b"\xfeSMB" in data[:8] or b"\xffSMB" in data[:8]:
            return "smb"
    return _port_protocol(TCP_PORT_PROTOCOLS, src_port, dst_port)


def classify_udp(src_port: int, dst_port: int, payload: bytes) -> str:
    """Best-effort protocol name for a UDP datagram, or "" when unknown."""
    data = payload or b""
    if data:
        if _startswith_any(data, _SSDP_PREFIXES):
            return "ssdp"
        if _startswith_any(data, _SIP_PREFIXES):
            return "sip"
        if _looks_like_quic(data):
            return "quic"
    return _port_protocol(UDP_PORT_PROTOCOLS, src_port, dst_port)


def _port_protocol(table: dict, src_port: int, dst_port: int) -> str:
    """Resolve a port pair against a conventions table.

    The destination is consulted first: for a client->server segment that is
    the service being addressed, and preferring the source would label a
    reply from an ephemeral port by whatever service happens to share that
    number.
    """
    for port in (int(dst_port or 0), int(src_port or 0)):
        name = table.get(port)
        if name:
            return name
    return ""
