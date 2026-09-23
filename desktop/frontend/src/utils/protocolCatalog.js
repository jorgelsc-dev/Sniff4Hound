// Presentation metadata for every protocol the capture pipeline can report.
//
// The backend decides *what* a protocol slice contains (sniff4hound/
// protocol_facets.py picks the facets, store.protocol_snapshot aggregates
// them); this file only decides how each one is labelled and grouped in the
// UI. Protocols are grouped by the layer they live at so the rail reads as a
// stack rather than as one flat list of a hundred chips.

export const LAYERS = [
  { key: "link", label: "Link", description: "Layer 2: frames on the local segment.", color: "purple" },
  { key: "network", label: "Network", description: "Layer 3: addressing, routing and control.", color: "info" },
  { key: "transport", label: "Transport", description: "Layer 4: ports, sessions and datagrams.", color: "success" },
  { key: "application", label: "Application", description: "Layer 7: the services that ride on top.", color: "warning" },
  { key: "other", label: "Residual", description: "Unclassified or undecodable traffic.", color: "error" },
];

// How a protocol picks its layer. Written down because the table drifted
// without it: QUIC sat under Application although it is what HTTP/3 rides on,
// and the tunnels were split down the middle - GRE, ESP, AH, IP-in-IP and L2TP
// under Network while PPTP, OpenVPN, WireGuard, VXLAN and Geneve sat under
// Application, despite doing the same job.
//
//   link         frames that never leave the segment, and the protocols that
//                manage it (ARP, STP, LLDP, EAPOL...)
//   network      addressing, routing and control - and anything that carries
//                another network's traffic inside it, which is what every
//                tunnel and overlay does, whichever port it rides on
//   transport    what applications open a connection *on*: TCP, UDP, SCTP,
//                DCCP, UDP-Lite and QUIC
//   application  the services that ride on a transport

// [layer, icon, label, description]. Anything not listed falls back to the
// layer default, so adding a port to app_protocols.py yields a usable card
// without touching this table.
const CATALOG = {
  // --- link ---------------------------------------------------------------
  arp: ["link", "mdi-lan-pending", "ARP", "Address resolution: who-has requests and is-at replies."],
  rarp: ["link", "mdi-lan-pending", "RARP", "Reverse address resolution."],
  stp: ["link", "mdi-file-tree", "STP", "Spanning tree BPDUs and topology changes."],
  llc: ["link", "mdi-view-headline", "LLC", "Bare IEEE 802.2 logical link control."],
  "llc-snap": ["link", "mdi-view-headline", "LLC/SNAP", "802.2 with a SNAP header."],
  lldp: ["link", "mdi-lan-connect", "LLDP", "Link-layer neighbour discovery announcements."],
  cdp: ["link", "mdi-lan-connect", "CDP", "Cisco neighbour discovery announcements."],
  dtp: ["link", "mdi-source-branch", "DTP", "Trunk negotiation - a VLAN-hopping prerequisite."],
  pvstp: ["link", "mdi-file-tree-outline", "PVSTP", "Per-VLAN spanning tree BPDUs."],
  eapol: ["link", "mdi-shield-key", "802.1X", "Port-based authentication (EAPOL) exchanges."],
  wol: ["link", "mdi-power", "Wake-on-LAN", "Magic packets waking hosts on the segment."],
  pppoe: ["link", "mdi-transit-connection", "PPPoE", "PPP session establishment over Ethernet."],
  mpls: ["link", "mdi-label-multiple", "MPLS", "Label-switched forwarding."],
  profinet: ["link", "mdi-factory", "PROFINET", "Industrial Ethernet fieldbus traffic."],
  ethercat: ["link", "mdi-factory", "EtherCAT", "Real-time industrial Ethernet."],
  loop: ["link", "mdi-refresh", "Loopback", "Ethernet configuration test frames."],

  // --- network ------------------------------------------------------------
  ipv6: ["network", "mdi-ip-network", "IPv6", "IPv6 traffic with no decoded upper layer."],
  icmp: ["network", "mdi-help-network", "ICMP", "Echo, unreachable, redirect and time-exceeded messages."],
  icmpv6: ["network", "mdi-help-network", "ICMPv6", "Neighbour discovery and IPv6 control messages."],
  igmp: ["network", "mdi-account-group", "IGMP", "Multicast group membership."],
  gre: ["network", "mdi-tunnel", "GRE", "Generic routing encapsulation tunnels."],
  esp: ["network", "mdi-lock", "ESP", "IPsec encapsulating security payload."],
  ah: ["network", "mdi-lock-check", "AH", "IPsec authentication header."],
  ospf: ["network", "mdi-routes", "OSPF", "Link-state routing adjacencies and updates."],
  eigrp: ["network", "mdi-routes", "EIGRP", "Cisco hybrid routing protocol."],
  rip: ["network", "mdi-routes", "RIP", "Distance-vector routing updates."],
  pim: ["network", "mdi-account-group", "PIM", "Protocol-independent multicast routing."],
  vrrp: ["network", "mdi-server-network", "VRRP", "Virtual router redundancy advertisements."],
  ipip: ["network", "mdi-tunnel", "IP-in-IP", "IP encapsulated directly inside IP."],
  egp: ["network", "mdi-routes", "EGP", "Legacy exterior gateway protocol."],
  rsvp: ["network", "mdi-timer-sand", "RSVP", "Resource reservation signalling."],
  l2tp: ["network", "mdi-tunnel", "L2TP", "Layer 2 tunnelling."],

  // --- transport ----------------------------------------------------------
  tcp: ["transport", "mdi-ethernet", "TCP", "Connection-oriented segments, flags and session state."],
  udp: ["transport", "mdi-lan", "UDP", "Connectionless datagrams and their ports."],
  sctp: ["transport", "mdi-lan-connect", "SCTP", "Multi-stream transport associations."],
  dccp: ["transport", "mdi-lan-connect", "DCCP", "Congestion-controlled datagram transport."],
  udplite: ["transport", "mdi-lan", "UDP-Lite", "Partial-checksum datagram transport."],

  // --- application: name resolution & discovery ---------------------------
  dns: ["application", "mdi-dns", "DNS", "Name resolution: queried names, resolvers and answers."],
  mdns: ["application", "mdi-dns-outline", "mDNS", "Multicast name resolution on the local segment."],
  llmnr: ["application", "mdi-dns-outline", "LLMNR", "Link-local multicast name resolution."],
  nbns: ["application", "mdi-dns-outline", "NBNS", "NetBIOS name service lookups."],
  nbdgm: ["application", "mdi-dns-outline", "NetBIOS DGM", "NetBIOS datagram service."],
  ssdp: ["application", "mdi-cast", "SSDP", "UPnP service discovery announcements and searches."],

  // --- application: web ---------------------------------------------------
  http: ["application", "mdi-web", "HTTP", "Cleartext web requests: methods, hosts and paths."],
  "http-proxy": ["application", "mdi-web-box", "HTTP proxy", "Traffic addressed to a forward proxy."],
  tls: ["application", "mdi-lock-check", "TLS", "Encrypted sessions, identified by SNI where visible."],
  quic: ["transport", "mdi-rocket-launch", "QUIC", "HTTP/3 transport over UDP."],

  // --- application: mail --------------------------------------------------
  smtp: ["application", "mdi-email-fast", "SMTP", "Mail submission and relay."],
  smtps: ["application", "mdi-email-lock", "SMTPS", "Implicit-TLS mail submission."],
  imap: ["application", "mdi-email-open", "IMAP", "Mailbox access in the clear."],
  imaps: ["application", "mdi-email-lock", "IMAPS", "Encrypted mailbox access."],
  pop3: ["application", "mdi-email-arrow-left", "POP3", "Mailbox retrieval in the clear."],
  pop3s: ["application", "mdi-email-lock", "POP3S", "Encrypted mailbox retrieval."],

  // --- application: remote access & transfer ------------------------------
  ssh: ["application", "mdi-console", "SSH", "Encrypted remote shell sessions."],
  telnet: ["application", "mdi-console-line", "Telnet", "Cleartext remote shell - credentials in the open."],
  rdp: ["application", "mdi-monitor-share", "RDP", "Remote desktop sessions."],
  vnc: ["application", "mdi-monitor-share", "VNC", "Remote framebuffer sessions."],
  ftp: ["application", "mdi-file-upload", "FTP", "Cleartext file transfer control channel."],
  "ftp-data": ["application", "mdi-file-upload-outline", "FTP data", "FTP bulk data channel."],
  tftp: ["application", "mdi-file-send", "TFTP", "Unauthenticated file transfer."],
  rsync: ["application", "mdi-file-sync", "rsync", "File synchronisation sessions."],
  smb: ["application", "mdi-folder-network", "SMB", "Windows file and printer sharing."],
  msrpc: ["application", "mdi-cog-transfer", "MSRPC", "Microsoft RPC endpoint traffic."],
  rpcbind: ["application", "mdi-cog-transfer", "rpcbind", "ONC RPC portmapper lookups."],
  git: ["application", "mdi-git", "Git", "Git protocol transfers."],
  socks: ["application", "mdi-shuffle-variant", "SOCKS", "Proxied connections."],
  pptp: ["network", "mdi-tunnel", "PPTP", "Legacy VPN control channel."],

  // --- application: directory, auth & infrastructure ----------------------
  ldap: ["application", "mdi-account-search", "LDAP", "Directory queries in the clear."],
  ldaps: ["application", "mdi-account-lock", "LDAPS", "Encrypted directory queries."],
  kerberos: ["application", "mdi-ticket-account", "Kerberos", "Ticket requests and grants."],
  radius: ["application", "mdi-account-key", "RADIUS", "Network access authentication."],
  ntp: ["application", "mdi-clock-outline", "NTP", "Time synchronisation - a classic amplification vector."],
  dhcp: ["application", "mdi-ip-network-outline", "DHCP", "Lease negotiation: DISCOVER, OFFER, REQUEST, ACK."],
  dhcpv6: ["application", "mdi-ip-network-outline", "DHCPv6", "IPv6 lease negotiation."],
  snmp: ["application", "mdi-console-network", "SNMP", "Device polling and traps."],
  syslog: ["application", "mdi-text-box-outline", "Syslog", "Log shipping in the clear."],
  ipmi: ["application", "mdi-server", "IPMI", "Out-of-band server management."],
  xdmcp: ["application", "mdi-monitor", "XDMCP", "X display manager sessions."],
  finger: ["application", "mdi-account-question", "Finger", "Legacy user lookup service."],
  whois: ["application", "mdi-account-search-outline", "WHOIS", "Registration lookups."],
  nntp: ["application", "mdi-newspaper", "NNTP", "Usenet news transfer."],

  // --- application: databases & caches ------------------------------------
  mysql: ["application", "mdi-database", "MySQL", "Database sessions."],
  postgres: ["application", "mdi-database", "PostgreSQL", "Database sessions."],
  mssql: ["application", "mdi-database", "MSSQL", "Database sessions."],
  oracle: ["application", "mdi-database", "Oracle", "Database sessions."],
  mongodb: ["application", "mdi-database", "MongoDB", "Document store sessions."],
  redis: ["application", "mdi-database-outline", "Redis", "Key-value store commands."],
  memcached: ["application", "mdi-database-outline", "Memcached", "Cache traffic - a known amplification vector."],
  elasticsearch: ["application", "mdi-database-search", "Elasticsearch", "Search cluster HTTP API."],

  // --- application: messaging & realtime ----------------------------------
  mqtt: ["application", "mdi-message-processing", "MQTT", "Publish/subscribe broker traffic."],
  amqp: ["application", "mdi-message-processing-outline", "AMQP", "Message queue traffic."],
  xmpp: ["application", "mdi-chat", "XMPP", "Instant messaging sessions."],
  irc: ["application", "mdi-forum", "IRC", "Chat sessions - a long-standing C2 channel."],
  sip: ["application", "mdi-phone-in-talk", "SIP", "Call signalling."],
  stun: ["application", "mdi-phone-sync", "STUN", "NAT traversal discovery."],
  coap: ["application", "mdi-chip", "CoAP", "Constrained-device REST traffic."],

  // --- application: tunnels & overlays ------------------------------------
  isakmp: ["application", "mdi-key-chain", "ISAKMP/IKE", "IPsec key negotiation."],
  openvpn: ["network", "mdi-vpn", "OpenVPN", "VPN tunnel traffic."],
  wireguard: ["network", "mdi-vpn", "WireGuard", "VPN tunnel traffic."],
  vxlan: ["network", "mdi-layers-triple", "VXLAN", "Layer 2 overlay encapsulation."],
  geneve: ["network", "mdi-layers-triple", "Geneve", "Network virtualisation encapsulation."],

  // --- application: industrial --------------------------------------------
  modbus: ["application", "mdi-factory", "Modbus", "PLC reads and writes - writes change physical state."],
  dnp3: ["application", "mdi-factory", "DNP3", "SCADA outstation polling and control."],
  bacnet: ["application", "mdi-home-thermometer", "BACnet", "Building automation traffic."],
  s7comm: ["application", "mdi-factory", "S7comm", "Siemens S7 PLC traffic."],
  bgp: ["application", "mdi-earth", "BGP", "Inter-domain routing sessions."],

  // --- residual -----------------------------------------------------------
  unknown: ["other", "mdi-help-circle-outline", "Unknown", "Recognised structure, unrecognised protocol number."],
  unparseable: ["other", "mdi-alert-octagon-outline", "Unparseable", "Frames the parser rejected - a spike may be evasion or fuzzing."],
};

const LAYER_DEFAULTS = {
  link: ["mdi-ethernet-cable", "Layer 2 traffic on the local segment."],
  network: ["mdi-ip-network", "Layer 3 traffic."],
  transport: ["mdi-lan", "Layer 4 traffic."],
  application: ["mdi-application-outline", "Application-layer traffic."],
  other: ["mdi-radar", "Unclassified traffic."],
};

const LAYER_COLORS = Object.fromEntries(LAYERS.map((layer) => [layer.key, layer.color]));

function prettyName(proto) {
  return String(proto || "")
    .split("-")
    .map((part) => (part.length <= 4 ? part.toUpperCase() : part.charAt(0).toUpperCase() + part.slice(1)))
    .join("-");
}

export function describeProtocol(proto) {
  const key = String(proto || "").trim().toLowerCase() || "unknown";
  const entry = CATALOG[key];
  if (entry) {
    const [layer, icon, label, description] = entry;
    return { key, layer, icon, label, description, color: LAYER_COLORS[layer] || "info" };
  }
  // Not catalogued: still give it a usable card rather than dropping it.
  const layer = "application";
  const [icon, description] = LAYER_DEFAULTS[layer];
  return { key, layer, icon, label: prettyName(key), description, color: LAYER_COLORS[layer] };
}

export function groupByLayer(protocols) {
  const groups = new Map(LAYERS.map((layer) => [layer.key, []]));
  for (const proto of protocols) {
    const described = describeProtocol(proto.key !== undefined ? proto.key : proto);
    const bucket = groups.get(described.layer) || groups.get("other");
    bucket.push(typeof proto === "object" ? { ...proto, ...described } : described);
  }
  return LAYERS.map((layer) => ({ ...layer, protocols: groups.get(layer.key) || [] })).filter(
    (layer) => layer.protocols.length > 0
  );
}

// Every protocol this build knows how to name. The Protocols view seeds its
// routing/ordering from this rather than from a short hand-written fallback:
// selectedProtocol validates the URL against the list it has *before* the
// first snapshot arrives, so a name missing here makes /protocols/<name>
// silently fall back to the first protocol in the list.
export const ALL_PROTOCOLS = Object.keys(CATALOG);

const LAYER_RANK = Object.fromEntries(LAYERS.map((layer, index) => [layer.key, index]));

// Ordered by layer first (link -> network -> transport -> application ->
// residual), then by the order they are declared inside each layer, so the
// rail reads bottom-of-the-stack upwards instead of alphabetically.
export function orderProtocolKeys(protocols) {
  const declared = new Map(ALL_PROTOCOLS.map((proto, index) => [proto, index]));
  return [...new Set(protocols)].sort((left, right) => {
    const leftLayer = LAYER_RANK[describeProtocol(left).layer] ?? 99;
    const rightLayer = LAYER_RANK[describeProtocol(right).layer] ?? 99;
    if (leftLayer !== rightLayer) return leftLayer - rightLayer;
    const leftRank = declared.has(left) ? declared.get(left) : Number.MAX_SAFE_INTEGER;
    const rightRank = declared.has(right) ? declared.get(right) : Number.MAX_SAFE_INTEGER;
    if (leftRank !== rightRank) return leftRank - rightRank;
    return left.localeCompare(right);
  });
}
