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

# --- protocol detail keys --------------------------------------------------
# The application decoders in app_decoders.py extract far more than the
# `packets` table has columns for, and everything without a column used to be
# dropped on insert. Those extras are persisted as JSON in `packets.details_json`
# and faceted through json_extract().
#
# This whitelist is the security boundary for that path, exactly as
# PACKET_COLUMNS is for real columns: a facet key reaches SQL only if it is
# declared here, so nothing derived from a request can ever be interpolated.
DETAIL_KEYS = frozenset(
    {
        "ai_sample", "ai_detection_status",
        "http_status", "http_server", "http_user_agent",
        "tls_version", "tls_record", "tls_handshake",
        "ssh_version", "ssh_software",
        "sip_method", "sip_from", "sip_to",
        "smb_command", "smb_version",
        "ssdp_method", "ssdp_target",
        "ntp_mode", "ntp_stratum", "ntp_version", "ntp_amplification_candidate",
        "quic_version", "quic_packet",
        "ldap_operation", "kerberos_message", "bgp_message", "redis_command",
        "stun_method", "isakmp_exchange", "isakmp_version",
        "wireguard_message", "vxlan_vni",
        "lldp_port_id", "cdp_device_id", "cdp_port_id", "cdp_software",
        "eapol_type",
        "dns_kind", "dns_qtype", "dns_rcode", "dns_answer", "dns_answer_type",
        "dns_mapping",
        "arp_operation", "arp_sender_mac", "arp_target_mac", "arp_hardware_type",
        "arp_mac_mismatch",
        # Already assigned by the sniffer's own parsers and dropped until now.
        # snmp_community and the usernames are credentials, but they were
        # already being written verbatim into `summary` by the same parsers, so
        # whitelisting them here changes what can be queried, not what is
        # stored. Passwords are deliberately absent: the MQTT parser records
        # only whether one was present.
        "dhcp_msg_type", "dhcp_hostname", "dhcp_requested_ip", "dhcp_vendor_class",
        "snmp_community", "snmp_version",
        "radius_username", "radius_nas_ip",
        "tftp_filename", "tftp_mode",
        "mqtt_username", "mqtt_client_id",
        "modbus_function_code", "modbus_unit_id", "modbus_is_write",
        "dnp3_function_code", "dnp3_src", "dnp3_dest",
        "syslog_facility", "syslog_severity",
        "llc_dsap", "llc_ssap", "llc_control", "llc_length",
        "llc_snap_oui", "llc_snap_ethertype",
        "igmp_group",
    }
)

DETAILS_COLUMN = "details_json"


def facet_expression(key: str) -> str:
    """SQL expression that yields a facet's value, or "" if the key is unknown.

    Both branches are whitelist-checked, so the returned string never contains
    anything that came from a caller. A real column is emitted bare; a detail
    key becomes a json_extract() over the details column. The key is embedded
    as a literal rather than bound because SQLite will not accept a parameter
    inside a JSON path, and it is safe here precisely because it can only be a
    member of DETAIL_KEYS.
    """
    name = str(key or "").strip()
    if name in PACKET_COLUMNS:
        return name
    if name in DETAIL_KEYS:
        return f"json_extract({DETAILS_COLUMN}, '$.{name}')"
    return ""


# Columns whose zero is "the field does not apply here" rather than a real
# reading. ICMP/IGMP types are deliberately absent: type 0 is Echo Reply, a
# genuine value that must keep its bar.
_ZERO_MEANS_ABSENT = frozenset(
    {"src_port", "dst_port", "arp_opcode", "eth_type", "ip_version", "ttl", "hop_limit"}
)


def facet_present_predicate(key: str) -> str:
    """SQL predicate selecting the rows where this facet has a real value.

    A facet is a "top values" chart, and an absent field is not a value: left
    in, it becomes one "none" bar that outranks and flattens every real one.
    The rows are not thrown away - protocol_snapshot() reports them as the
    facet's `missing` count - they just stop competing for the top slots.
    """
    expression = facet_expression(key)
    if not expression:
        return ""
    if expression != key:
        return f"{expression} IS NOT NULL AND {expression} != ''"
    if key in _ZERO_MEANS_ABSENT:
        return f"{key} != 0"
    return f"{key} IS NOT NULL AND {key} != ''"


def extract_details(packet: dict) -> dict:
    """The whitelisted decoder extras carried by a packet, ready to persist."""
    details = {}
    for key in DETAIL_KEYS:
        value = packet.get(key)
        if value in ("", None):
            continue
        if isinstance(value, bool):
            details[key] = "yes" if value else "no"
            continue
        details[key] = str(value)[:200]
    return details


# Facets shared by anything that rides on IP and has ports.
_PORT_FACETS = (
    ("dst_port", "Destination ports", "Where the traffic is headed."),
    ("src_port", "Source ports", "Where the traffic came from."),
)

_DNSISH_FACETS = (
    ("dns_mapping", "Name to address", "What each name actually resolved to."),
    ("domain", "Queried names", "Names resolved through this protocol."),
    ("dns_answer", "Resolved addresses", "One address serving many names is shared hosting - or a sinkhole."),
    ("dns_qtype", "Record types", "A/AAAA is browsing; TXT and ANY are exfiltration and amplification."),
    ("dns_rcode", "Response codes", "An NXDOMAIN storm is domain-generation malware."),
    ("src_ip", "Top resolvers", "Hosts asking or answering."),
)

def _SERVER_CLIENT_FACETS(server_title: str, server_hint: str, port_hint: str) -> tuple:
    """The facet shape for a client/server application protocol.

    Written once because roughly twenty protocols answer the same three
    questions - who serves, who asks, on which port - and spelling that out
    per protocol is how the table drifts out of step with itself.
    """
    return (
        ("dst_ip", server_title, server_hint),
        ("src_ip", "Clients", "Which hosts are connecting."),
        ("dst_port", "Ports", port_hint),
    )


def _TUNNEL_FACETS(hint: str) -> tuple:
    return (
        ("src_ip", "Tunnel endpoints", hint),
        ("dst_ip", "Peer endpoints", "The far side of each tunnel."),
        ("length", "Frame sizes", "Encapsulation shows up as a size floor."),
    )


def _ROUTING_FACETS(hint: str) -> tuple:
    return (
        ("src_ip", "Speaking routers", hint),
        ("dst_ip", "Destinations", "Multicast group or directed neighbour."),
    )


def _ICS_FACETS(hint: str) -> tuple:
    return (
        ("dst_ip", "Devices addressed", hint),
        ("src_ip", "Engineering stations", "Which host is issuing the commands."),
        ("dst_port", "Ports", "The control port each device answers on."),
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
        ("igmp_group", "Groups", "The group carried in the message, not the frame destination."),
        ("dst_ip", "Destinations", "Where the message was addressed."),
    ),
    "arp": (
        ("arp_operation", "Operation", "Who-has requests versus is-at replies."),
        ("arp_mac_mismatch", "Ethernet/ARP mismatches", "The frame's MAC disagreeing with the one announced inside is how spoofing looks."),
        ("arp_sender_mac", "Announced sender MACs", "The MAC claimed inside the payload, which is what peers cache."),
        ("src_ip", "Announced sender IPs", "One MAC claiming several is a takeover attempt."),
        ("dst_ip", "Targets asked about", "Sequential targets mean a sweep."),
        ("arp_target_mac", "Target MACs", "All-zero in a request, filled in a reply."),
        ("eth_src", "Frame source MACs", "The Ethernet header, to compare against the announced one."),
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
    "llc": (
        ("llc_dsap", "Destination SAPs", "Which upper-layer service the frame targets."),
        ("llc_ssap", "Source SAPs", "Which service emitted it."),
        ("eth_src", "Source MACs", "Stations using bare LLC."),
    ),
    "llc-snap": (
        ("llc_snap_oui", "Vendor OUIs", "A non-zero OUI means a vendor-private protocol."),
        ("llc_snap_ethertype", "Encapsulated types", "What rides inside the SNAP header."),
        ("eth_src", "Source MACs", "Stations using LLC/SNAP."),
    ),
    "lldp": (
        ("eth_src", "Advertising MACs", "Devices announcing themselves."),
        ("lldp_port_id", "Port IDs", "Which switch port each neighbour sits on."),
        ("interface", "Interfaces", "Where neighbours were discovered."),
    ),
    "cdp": (
        ("cdp_device_id", "Device IDs", "Hostnames the neighbours announce."),
        ("cdp_port_id", "Port IDs", "Which port each neighbour is wired to."),
        ("cdp_software", "Software versions", "Unpatched IOS shows up here."),
        ("eth_src", "Advertising MACs", "Cisco devices announcing themselves."),
    ),
    "eapol": (
        ("eapol_type", "Frame types", "Repeated Start frames are a supplicant that never passes."),
        ("eth_src", "Supplicant MACs", "Stations authenticating to the port."),
        ("interface", "Interfaces", "Where 802.1X exchanges happen."),
    ),
    "wol": (("eth_dst", "Woken MACs", "Targets of magic packets."),),
    # --- application: name resolution --------------------------------------
    "dns": _DNSISH_FACETS + (("dst_port", "Ports", "53, or a non-standard resolver."),),
    "dhcpv6": (
        ("src_ip", "Clients and servers", "Who is leasing addresses over IPv6."),
        ("eth_src", "Client MACs", "Which hardware is asking for a lease."),
    ),
    "mdns": _DNSISH_FACETS,
    "llmnr": _DNSISH_FACETS,
    "nbns": (("domain", "Queried names", "NetBIOS names being resolved."), ("src_ip", "Top hosts", "Who is asking.")),
    "ssdp": (
        ("ssdp_method", "Methods", "M-SEARCH discovery versus NOTIFY."),
        ("ssdp_target", "Search targets", "What is being hunted on the segment."),
        ("src_ip", "Announcing hosts", "Devices advertising services."),
    ),
    # --- application: web --------------------------------------------------
    "http": (
        ("http_method", "Methods", "GET-heavy is browsing; POST-heavy is upload."),
        ("http_host", "Hosts", "Virtual hosts being requested."),
        ("http_path", "Paths", "Repeated odd paths are enumeration."),
        ("http_status", "Response status", "A 401/403 wall is probing; 5xx is a struggling backend."),
        ("http_server", "Server software", "Names and versions the responses advertise."),
        ("http_user_agent", "User agents", "One agent across many paths is a scanner."),
    ),
    "tls": (
        ("domain", "SNI names", "The hostname requested inside the handshake."),
        ("tls_version", "Versions", "Anything below 1.2 is a downgrade worth chasing."),
        ("tls_handshake", "Handshake messages", "ClientHello floods are scans."),
        ("dst_port", "Ports", "443, or TLS somewhere unexpected."),
        ("dst_ip", "Destinations", "Where the sessions terminate."),
    ),
    "quic": (
        ("domain", "SNI names", "Names inside the QUIC handshake."),
        ("quic_version", "Versions", "Draft versions still in play."),
        ("quic_packet", "Packet types", "Initial packets are new sessions."),
        ("dst_ip", "Destinations", "Where the sessions terminate."),
    ),
    # --- application: infrastructure ---------------------------------------
    "dhcp": (
        ("dhcp_msg_type", "Message types", "DISCOVER/OFFER/REQUEST/ACK balance."),
        ("dhcp_hostname", "Client hostnames", "What each device calls itself - the cheapest asset inventory on the wire."),
        ("dhcp_vendor_class", "Vendor classes", "Identifies the OS or appliance family behind the lease."),
        ("dhcp_requested_ip", "Requested addresses", "A client insisting on an address it does not hold is worth a look."),
        ("eth_src", "Client MACs", "Which hardware is asking for a lease."),
    ),
    "ntp": (
        ("ntp_mode", "Modes", "Mode 7 is the monlist amplification vector."),
        ("ntp_amplification_candidate", "Amplification candidates", "Requests that return far more than they cost."),
        ("ntp_stratum", "Stratum", "Stratum 0 or 16 means an unsynchronised source."),
        ("src_ip", "Time sources", "Servers being polled."),
    ),
    "snmp": (
        ("snmp_community", "Community strings", "'public' and 'private' are unchanged defaults, and they are credentials."),
        ("snmp_version", "Versions", "v1 and v2c send the community in clear text."),
        ("src_ip", "Agents and managers", "Who is polling whom."),
        ("dst_port", "Ports", "161 polling versus 162 traps."),
    ),
    "syslog": (
        ("syslog_severity", "Severity", "A burst of emerg/alert is the first sign of something breaking."),
        ("syslog_facility", "Facility", "Which subsystem is talking - auth is the one to watch."),
        ("src_ip", "Log sources", "Hosts shipping their logs."),
    ),
    "tftp": (
        ("tftp_filename", "Filenames", "TFTP has no authentication, so the name is the whole access control."),
        ("tftp_mode", "Transfer modes", "netascii versus octet."),
        ("src_ip", "Peers", "Hosts moving files without auth."),
    ),
    "radius": (
        ("radius_username", "Usernames", "Repeated failures for one name are a spray."),
        ("radius_nas_ip", "NAS addresses", "Which access device forwarded the request."),
        ("src_ip", "NAS clients", "Devices authenticating users."),
    ),
    "kerberos": (
        ("kerberos_message", "Message types", "AS-REQ bursts are roasting attempts."),
        ("src_ip", "Principals", "Hosts requesting tickets."),
    ),
    "ldap": (
        ("ldap_operation", "Operations", "Bind storms are credential spraying."),
        ("dst_ip", "Directory servers", "Where the queries land."),
        ("dst_port", "Ports", "389 plain versus 636 TLS."),
    ),
    "smb": (
        ("smb_command", "Commands", "Session setup bursts are share enumeration."),
        ("smb_version", "Dialects", "SMB1 is the ransomware-era dialect."),
        ("dst_ip", "File servers", "Where the shares live."),
        ("dst_port", "Ports", "445 direct versus 139 over NetBIOS."),
    ),
    "rdp": (("dst_ip", "Targets", "Hosts exposing remote desktop."), ("src_ip", "Origins", "Where the sessions come from.")),
    "ssh": (
        ("ssh_software", "Client and server software", "An odd library name is automation, not a person."),
        ("ssh_version", "Protocol versions", "SSH-1 is obsolete and should not appear."),
        ("dst_ip", "Targets", "Hosts exposing SSH."),
        ("src_ip", "Origins", "Repeated origins are brute force."),
    ),
    "telnet": (("dst_ip", "Targets", "Hosts still exposing telnet."), ("src_ip", "Origins", "Where the sessions come from.")),
    "ftp": (("dst_ip", "Servers", "Hosts exposing FTP."), ("src_ip", "Origins", "Where the sessions come from.")),
    "smtp": (("dst_ip", "Mail servers", "Where mail is delivered."), ("src_ip", "Senders", "Hosts submitting mail.")),
    "imap": (("dst_ip", "Mail servers", "Where mailboxes are read."),),
    "pop3": (("dst_ip", "Mail servers", "Where mailboxes are drained."),),
    "sip": (
        ("sip_method", "Methods", "REGISTER floods are toll-fraud probing."),
        ("sip_from", "From", "Who is placing the calls."),
        ("sip_to", "To", "Sequential destinations mean dialling enumeration."),
        ("dst_ip", "Signalling peers", "Where calls are set up."),
    ),
    "rtp": (("dst_ip", "Media peers", "Where the media flows."), ("dst_port", "Ports", "Even ports carry media, odd carry RTCP.")),
    "bgp": (
        ("bgp_message", "Message types", "Repeated OPEN means a session that will not settle."),
        ("src_ip", "Peers", "Routers in the BGP session."),
    ),
    "mqtt": (
        ("mqtt_client_id", "Client IDs", "How each publisher identifies itself."),
        ("mqtt_username", "Usernames", "Present only when the client authenticates at all."),
        ("dst_ip", "Brokers", "Where clients publish."),
    ),
    "modbus": (
        ("modbus_function_code", "Function codes", "Writes are more sensitive than reads."),
        ("modbus_is_write", "Reads versus writes", "A write to a PLC changes physical state."),
        ("modbus_unit_id", "Unit IDs", "Which slave device behind the gateway."),
        ("dst_ip", "PLC endpoints", "Devices being commanded."),
    ),
    "dnp3": (
        ("dnp3_function_code", "Function codes", "Control requests versus reads."),
        ("dnp3_src", "Source addresses", "The DNP3 link address, not the IP."),
        ("dnp3_dest", "Destination addresses", "Which outstation is being addressed."),
        ("dst_ip", "Outstations", "Devices being polled."),
    ),
    "vxlan": (
        ("vxlan_vni", "Segment IDs", "Which overlay segments cross this link."),
        ("src_ip", "Tunnel endpoints", "VTEPs carrying overlay traffic."),
    ),
    "wireguard": (
        ("wireguard_message", "Message types", "Handshake churn without transport data is a failing peer."),
        ("src_ip", "Tunnel endpoints", "WireGuard peers."),
    ),
    "isakmp": (
        ("isakmp_exchange", "Exchange types", "Aggressive mode leaks the identity hash."),
        ("isakmp_version", "IKE versions", "IKEv1 still lingers on old gear."),
        ("src_ip", "Tunnel endpoints", "IKE negotiation peers."),
    ),
    "redis": (
        ("redis_command", "Commands", "CONFIG and SLAVEOF are the takeover pair."),
        ("dst_ip", "Servers", "Where the commands land."),
        ("src_ip", "Clients", "Who is issuing them."),
    ),
    "stun": (
        ("stun_method", "Methods", "Binding requests map NAT; allocations relay media."),
        ("dst_ip", "STUN servers", "Which servers are being asked."),
        ("src_ip", "Clients", "Hosts discovering their own address."),
    ),
    # --- application: databases and caches ---------------------------------
    # These all share the same shape - a server port, a small set of clients,
    # and a blast radius measured in rows - so they share a facet shape too:
    # who is serving, who is asking, and on which port it was reachable.
    "mysql": _SERVER_CLIENT_FACETS("MySQL servers", "Hosts running the database.", "3306, or a moved port."),
    "postgres": _SERVER_CLIENT_FACETS("PostgreSQL servers", "Hosts running the database.", "5432, or a moved port."),
    "mssql": _SERVER_CLIENT_FACETS("SQL Server hosts", "Hosts running the database.", "1433, or a named instance."),
    "oracle": _SERVER_CLIENT_FACETS("Oracle listeners", "Hosts running the database.", "1521, or a moved listener."),
    "mongodb": _SERVER_CLIENT_FACETS("MongoDB hosts", "Historically exposed without auth.", "27017, or a moved port."),
    "elasticsearch": _SERVER_CLIENT_FACETS("Elasticsearch nodes", "Cluster members answering queries.", "9200 REST versus 9300 transport."),
    "memcached": _SERVER_CLIENT_FACETS("Memcached hosts", "UDP memcached is a major amplifier.", "11211, on UDP or TCP."),
    # --- application: TLS-wrapped services ---------------------------------
    "imaps": _SERVER_CLIENT_FACETS("Mail servers", "Where mailboxes are read over TLS.", "993, or a moved port."),
    "pop3s": _SERVER_CLIENT_FACETS("Mail servers", "Where mailboxes are drained over TLS.", "995, or a moved port."),
    "smtps": _SERVER_CLIENT_FACETS("Mail servers", "Where mail is submitted over TLS.", "465 implicit versus 587 STARTTLS."),
    "ldaps": _SERVER_CLIENT_FACETS("Directory servers", "Where the queries land over TLS.", "636, or a global catalogue port."),
    # --- application: remote access and file movement ----------------------
    "vnc": _SERVER_CLIENT_FACETS("VNC targets", "Screens exposed on the network.", "5900 upward, one per display."),
    "xdmcp": _SERVER_CLIENT_FACETS("Display managers", "Hosts offering remote X sessions.", "177, usually on UDP."),
    "rsync": _SERVER_CLIENT_FACETS("Rsync daemons", "Hosts exposing modules, often unauthenticated.", "873, or tunnelled."),
    "git": _SERVER_CLIENT_FACETS("Git daemons", "Repositories served over the bare protocol.", "9418, which has no authentication."),
    "ftp-data": (
        ("dst_ip", "Transfer peers", "Where the bytes are going."),
        ("length", "Transfer sizes", "A single large flow is a bulk copy."),
        ("src_ip", "Origins", "Which host opened the data channel."),
    ),
    "socks": _SERVER_CLIENT_FACETS("Proxy hosts", "An open SOCKS proxy relays anything.", "1080, or a moved port."),
    "http-proxy": (
        ("http_host", "Proxied hosts", "Where the tunnelled requests are headed."),
        ("http_method", "Methods", "CONNECT is a tunnel, not a fetch."),
        ("src_ip", "Clients", "Who is proxying through this host."),
    ),
    # --- application: messaging and directory ------------------------------
    "coap": _SERVER_CLIENT_FACETS("CoAP endpoints", "Constrained devices answering requests.", "5683 plain versus 5684 DTLS."),
    "amqp": _SERVER_CLIENT_FACETS("Brokers", "Where messages are published.", "5672, or 5671 over TLS."),
    "xmpp": _SERVER_CLIENT_FACETS("XMPP servers", "Where sessions are established.", "5222 client versus 5269 server."),
    "irc": (
        ("dst_ip", "IRC servers", "Long-lived IRC to an unknown host is classic C2."),
        ("dst_port", "Ports", "6667 and neighbours, or somewhere hidden."),
        ("src_ip", "Clients", "Which host keeps the channel open."),
    ),
    "nntp": _SERVER_CLIENT_FACETS("News servers", "Where articles are fetched.", "119, or 563 over TLS."),
    "finger": _SERVER_CLIENT_FACETS("Finger hosts", "A user-enumeration service that should not be running.", "79, and rarely anything else."),
    "whois": _SERVER_CLIENT_FACETS("Whois servers", "Registries being queried.", "43, and rarely anything else."),
    # --- application: RPC and management -----------------------------------
    "msrpc": _SERVER_CLIENT_FACETS("RPC endpoints", "The endpoint mapper is the first lateral-movement stop.", "135, then a high dynamic port."),
    "rpcbind": _SERVER_CLIENT_FACETS("Portmapper hosts", "It reveals every RPC service behind it.", "111, on UDP or TCP."),
    "nbdgm": (
        ("eth_src", "Source MACs", "Stations using NetBIOS datagrams."),
        ("dst_ip", "Destinations", "Broadcast versus directed traffic."),
    ),
    "ipmi": _SERVER_CLIENT_FACETS("BMC endpoints", "Out-of-band controllers reachable from the network.", "623, usually on UDP."),
    # --- network: tunnels and encapsulation --------------------------------
    "l2tp": _TUNNEL_FACETS("L2TP peers."),
    "pptp": _TUNNEL_FACETS("PPTP peers, on an obsolete cipher suite."),
    "openvpn": _TUNNEL_FACETS("OpenVPN peers."),
    "geneve": _TUNNEL_FACETS("Geneve endpoints carrying overlay traffic."),
    "ipip": _TUNNEL_FACETS("IP-in-IP tunnel endpoints."),
    "mpls": _TUNNEL_FACETS("Label-switching neighbours."),
    "pppoe": (
        ("eth_src", "Session MACs", "Which access concentrator each session rides."),
        ("interface", "Interfaces", "Where PPPoE discovery is happening."),
    ),
    # --- network: routing --------------------------------------------------
    "rip": _ROUTING_FACETS("Routers advertising RIP updates."),
    "egp": _ROUTING_FACETS("Routers speaking EGP."),
    "eigrp": _ROUTING_FACETS("Routers in the EIGRP adjacency."),
    "pim": _ROUTING_FACETS("Routers building multicast trees."),
    "rsvp": _ROUTING_FACETS("Routers reserving bandwidth."),
    # --- link: switching control -------------------------------------------
    "dtp": (
        ("eth_src", "Negotiating MACs", "DTP left on is how VLAN hopping starts."),
        ("interface", "Interfaces", "Which ports still negotiate trunking."),
    ),
    "pvstp": (
        ("eth_src", "Bridge MACs", "A new root bridge is a topology change."),
        ("interface", "Interfaces", "Where per-VLAN BPDUs arrive."),
    ),
    "loop": (
        ("eth_src", "Source MACs", "Loopback frames returning to their sender."),
        ("interface", "Interfaces", "A spike here is a physical loop."),
    ),
    # --- industrial control ------------------------------------------------
    "s7comm": _ICS_FACETS("S7 PLCs being addressed."),
    "bacnet": _ICS_FACETS("Building-automation controllers."),
    "profinet": _ICS_FACETS("PROFINET devices on the cell network."),
    "ethercat": (
        ("eth_src", "Source MACs", "EtherCAT rides raw Ethernet, so MACs are the identity."),
        ("interface", "Interfaces", "Fieldbus segments carrying the cycle."),
    ),
    # --- residual ----------------------------------------------------------
    "unknown": DEFAULT_FACETS,
    "unparseable": (
        ("interface", "Interfaces", "Where malformed frames arrive - a spike is possible evasion."),
        ("length", "Frame sizes", "Truncated or oversized frames stand out here."),
        ("eth_src", "Source MACs", "Who is emitting frames the parser rejects."),
    ),
}


# --- packet table columns --------------------------------------------------
# The rows table used to render the same twelve columns for all 108 protocols,
# so an ARP listing spent four of them on src_port, dst_port, tcp_flags and
# state - all constant - and showed none of the fields the ARP payload
# actually carries. These declare what each protocol is worth showing.

_BASE_COLUMNS = (
    ("updated_at", "Seen"),
    ("interface", "Interface"),
    ("direction", "Direction"),
)
_ENDPOINT_COLUMNS = (
    ("src_ip", "Src IP"),
    ("src_port", "Src Port"),
    ("dst_ip", "Dst IP"),
    ("dst_port", "Dst Port"),
)
_TAIL_COLUMNS = (("length", "Size"), ("summary", "Summary"))

DEFAULT_ROW_COLUMNS = _BASE_COLUMNS + (("state", "State"),) + _ENDPOINT_COLUMNS + _TAIL_COLUMNS

PROTOCOL_ROW_COLUMNS: dict[str, tuple] = {
    # ARP has no ports and no connection state; what it does have is two
    # hardware addresses and two protocol addresses per frame.
    "arp": _BASE_COLUMNS + (
        ("arp_operation", "Operation"),
        ("eth_src", "Frame MAC"),
        ("arp_sender_mac", "Announced MAC"),
        ("src_ip", "Sender IP"),
        ("arp_target_mac", "Target MAC"),
        ("dst_ip", "Target IP"),
        ("arp_mac_mismatch", "Mismatch"),
    ),
    "rarp": _BASE_COLUMNS + (
        ("arp_operation", "Operation"),
        ("eth_src", "Frame MAC"),
        ("arp_sender_mac", "Announced MAC"),
        ("src_ip", "Sender IP"),
        ("dst_ip", "Target IP"),
    ),
    "http": _BASE_COLUMNS + _ENDPOINT_COLUMNS + (
        ("http_method", "Method"),
        ("http_status", "Status"),
        ("http_host", "Host"),
        ("http_path", "Path"),
        ("http_server", "Server"),
        ("http_user_agent", "User agent"),
    ),
    "dns": _BASE_COLUMNS + _ENDPOINT_COLUMNS + (
        ("dns_kind", "Kind"),
        ("dns_qtype", "Type"),
        ("domain", "Name"),
        ("dns_answer", "Answer"),
        ("dns_rcode", "Code"),
    ),
    "tls": _BASE_COLUMNS + _ENDPOINT_COLUMNS + (
        ("domain", "SNI"),
        ("tls_version", "Version"),
        ("tls_handshake", "Handshake"),
    ),
    "quic": _BASE_COLUMNS + _ENDPOINT_COLUMNS + (
        ("domain", "SNI"),
        ("quic_version", "Version"),
        ("quic_packet", "Packet"),
    ),
    "ssh": _BASE_COLUMNS + _ENDPOINT_COLUMNS + (
        ("ssh_version", "Version"),
        ("ssh_software", "Software"),
    ),
    "sip": _BASE_COLUMNS + _ENDPOINT_COLUMNS + (
        ("sip_method", "Method"),
        ("sip_from", "From"),
        ("sip_to", "To"),
    ),
    "smb": _BASE_COLUMNS + _ENDPOINT_COLUMNS + (
        ("smb_command", "Command"),
        ("smb_version", "Dialect"),
    ),
    "ntp": _BASE_COLUMNS + _ENDPOINT_COLUMNS + (
        ("ntp_mode", "Mode"),
        ("ntp_stratum", "Stratum"),
        ("ntp_amplification_candidate", "Amplifier"),
    ),
    "icmp": _BASE_COLUMNS + (
        ("src_ip", "Src IP"),
        ("dst_ip", "Dst IP"),
        ("icmp_type", "Type"),
        ("icmp_code", "Code"),
        ("ttl", "TTL"),
    ) + _TAIL_COLUMNS,
    "icmpv6": _BASE_COLUMNS + (
        ("src_ip", "Src IP"),
        ("dst_ip", "Dst IP"),
        ("icmp_type", "Type"),
        ("icmp_code", "Code"),
        ("hop_limit", "Hop limit"),
    ) + _TAIL_COLUMNS,
    "tcp": _BASE_COLUMNS + (("state", "State"),) + _ENDPOINT_COLUMNS + (
        ("tcp_flags", "Flags"),
        ("ttl", "TTL"),
    ) + _TAIL_COLUMNS,
    # Link-layer protocols have no IP addressing at all.
    "stp": _BASE_COLUMNS + (("eth_src", "Bridge MAC"), ("eth_dst", "Dst MAC")) + _TAIL_COLUMNS,
    "lldp": _BASE_COLUMNS + (("eth_src", "Neighbour MAC"), ("lldp_port_id", "Port ID")) + _TAIL_COLUMNS,
    "cdp": _BASE_COLUMNS + (
        ("eth_src", "Neighbour MAC"),
        ("cdp_device_id", "Device"),
        ("cdp_port_id", "Port"),
        ("cdp_software", "Software"),
    ),
    "eapol": _BASE_COLUMNS + (("eth_src", "Supplicant MAC"), ("eapol_type", "Type")) + _TAIL_COLUMNS,
    "dhcp": _BASE_COLUMNS + (
        ("dhcp_msg_type", "Message"),
        ("eth_src", "Client MAC"),
        ("dhcp_hostname", "Hostname"),
        ("dhcp_vendor_class", "Vendor"),
        ("dhcp_requested_ip", "Requested IP"),
    ),
    "snmp": _BASE_COLUMNS + _ENDPOINT_COLUMNS + (
        ("snmp_version", "Version"),
        ("snmp_community", "Community"),
    ),
    "radius": _BASE_COLUMNS + _ENDPOINT_COLUMNS + (
        ("radius_username", "Username"),
        ("radius_nas_ip", "NAS IP"),
    ),
    "tftp": _BASE_COLUMNS + _ENDPOINT_COLUMNS + (
        ("tftp_filename", "Filename"),
        ("tftp_mode", "Mode"),
    ),
    "mqtt": _BASE_COLUMNS + _ENDPOINT_COLUMNS + (
        ("mqtt_client_id", "Client ID"),
        ("mqtt_username", "Username"),
    ),
    "modbus": _BASE_COLUMNS + _ENDPOINT_COLUMNS + (
        ("modbus_function_code", "Function"),
        ("modbus_is_write", "Write"),
        ("modbus_unit_id", "Unit"),
    ),
    "dnp3": _BASE_COLUMNS + _ENDPOINT_COLUMNS + (
        ("dnp3_function_code", "Function"),
        ("dnp3_src", "Link src"),
        ("dnp3_dest", "Link dst"),
    ),
    "syslog": _BASE_COLUMNS + _ENDPOINT_COLUMNS + (
        ("syslog_severity", "Severity"),
        ("syslog_facility", "Facility"),
    ) + _TAIL_COLUMNS,
    "igmp": _BASE_COLUMNS + (
        ("src_ip", "Src IP"),
        ("icmp_type", "Type"),
        ("igmp_group", "Group"),
        ("dst_ip", "Dst IP"),
    ) + _TAIL_COLUMNS,
}


def resolve_row_columns(proto: str) -> tuple:
    """Columns for the packet table of one protocol.

    Same whitelist discipline as resolve_facets: every key must be a real
    column or a declared detail key, so a typo drops the column instead of
    reaching the client as an unreadable field name.
    """
    columns = PROTOCOL_ROW_COLUMNS.get(str(proto or "").strip().lower(), DEFAULT_ROW_COLUMNS)
    return tuple(
        (key, label) for key, label in columns
        if key in PACKET_COLUMNS or key in DETAIL_KEYS or key == "updated_at"
    )


def resolve_facets(proto: str) -> tuple:
    """Facets for a protocol, guaranteed to reference declared keys.

    The names are interpolated into SQL, so this is the only place allowed to
    decide them: an unknown protocol gets DEFAULT_FACETS rather than anything
    derived from the caller's string, and every declared key is checked against
    PACKET_COLUMNS (real columns) or DETAIL_KEYS (decoder extras stored as
    JSON). Callers turn the key into an expression with facet_expression().
    """
    facets = PROTOCOL_FACETS.get(str(proto or "").strip().lower(), DEFAULT_FACETS)
    return tuple(
        facet for facet in facets
        if facet[0] in PACKET_COLUMNS or facet[0] in DETAIL_KEYS
    )


def label_value(column: str, value):
    """Human label for a grouped value, keyed by the column it came from."""
    labeller = LABELLERS.get(str(column or ""))
    if labeller is not None:
        return labeller(value)
    return _label_plain(value)
