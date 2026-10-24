// Presentation metadata for every protocol the capture pipeline can report.
//
// The backend decides *what* a protocol slice contains (sniff4hound/
// protocol_facets.py picks the facets, store.protocol_snapshot aggregates
// them); this file only decides how each one is labelled and grouped in the
// UI. Protocols are grouped by the layer they live at so the rail reads as a
// stack rather than as one flat list of a hundred chips.

export const LAYERS = [
  { key: "link", label: "Enlace", description: "Capa 2: tramas del segmento local.", color: "purple" },
  { key: "network", label: "Red", description: "Capa 3: direccionamiento, enrutamiento y control.", color: "info" },
  { key: "transport", label: "Transporte", description: "Capa 4: puertos, sesiones y datagramas.", color: "success" },
  { key: "application", label: "Aplicación", description: "Capa 7: servicios de aplicación.", color: "warning" },
  { key: "other", label: "Residual", description: "Tráfico sin clasificar o sin decodificar.", color: "error" },
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
  arp: ["link", "mdi-lan-pending", "ARP", "Resolución de direcciones: consultas who-has y respuestas is-at."],
  rarp: ["link", "mdi-lan-pending", "RARP", "Resolución inversa de direcciones."],
  stp: ["link", "mdi-file-tree", "STP", "BPDUs de árbol de expansión y cambios de topología."],
  llc: ["link", "mdi-view-headline", "LLC", "Control de enlace lógico IEEE 802.2."],
  "llc-snap": ["link", "mdi-view-headline", "LLC/SNAP", "802.2 con cabecera SNAP."],
  lldp: ["link", "mdi-lan-connect", "LLDP", "Anuncios de descubrimiento de vecinos en la capa de enlace."],
  cdp: ["link", "mdi-lan-connect", "CDP", "Anuncios de descubrimiento de vecinos Cisco."],
  dtp: ["link", "mdi-source-branch", "DTP", "Negociación de enlaces troncales, requisito para saltos de VLAN."],
  pvstp: ["link", "mdi-file-tree-outline", "PVSTP", "BPDUs de árbol de expansión por VLAN."],
  eapol: ["link", "mdi-shield-key", "802.1X", "Intercambios de autenticación por puerto (EAPOL)."],
  wol: ["link", "mdi-power", "Wake-on-LAN", "Paquetes mágicos que despiertan hosts del segmento."],
  pppoe: ["link", "mdi-transit-connection", "PPPoE", "Establecimiento de sesiones PPP sobre Ethernet."],
  mpls: ["link", "mdi-label-multiple", "MPLS", "Reenvío mediante conmutación de etiquetas."],
  profinet: ["link", "mdi-factory", "PROFINET", "Tráfico de bus de campo Ethernet industrial."],
  ethercat: ["link", "mdi-factory", "EtherCAT", "Ethernet industrial en tiempo real."],
  loop: ["link", "mdi-refresh", "Bucle local", "Tramas de prueba de configuración Ethernet."],

  // --- network ------------------------------------------------------------
  ipv6: ["network", "mdi-ip-network", "IPv6", "Tráfico IPv6 sin una capa superior decodificada."],
  icmp: ["network", "mdi-help-network", "ICMP", "Mensajes de eco, destino inalcanzable, redirección y tiempo agotado."],
  icmpv6: ["network", "mdi-help-network", "ICMPv6", "Descubrimiento de vecinos y mensajes de control IPv6."],
  igmp: ["network", "mdi-account-group", "IGMP", "Pertenencia a grupos multicast."],
  gre: ["network", "mdi-tunnel", "GRE", "Túneles de encapsulación genérica de enrutamiento."],
  esp: ["network", "mdi-lock", "ESP", "Contenido de seguridad encapsulado de IPsec."],
  ah: ["network", "mdi-lock-check", "AH", "Cabecera de autenticación IPsec."],
  ospf: ["network", "mdi-routes", "OSPF", "Adyacencias y actualizaciones de enrutamiento de estado de enlace."],
  eigrp: ["network", "mdi-routes", "EIGRP", "Protocolo de enrutamiento híbrido Cisco."],
  rip: ["network", "mdi-routes", "RIP", "Actualizaciones de enrutamiento por vector de distancia."],
  pim: ["network", "mdi-account-group", "PIM", "Enrutamiento multicast independiente del protocolo."],
  vrrp: ["network", "mdi-server-network", "VRRP", "Anuncios de redundancia de routers virtuales."],
  ipip: ["network", "mdi-tunnel", "IP-in-IP", "IP encapsulado directamente dentro de IP."],
  egp: ["network", "mdi-routes", "EGP", "Protocolo heredado de pasarela exterior."],
  rsvp: ["network", "mdi-timer-sand", "RSVP", "Señalización de reserva de recursos."],
  l2tp: ["network", "mdi-tunnel", "L2TP", "Túneles de capa 2."],

  // --- transport ----------------------------------------------------------
  tcp: ["transport", "mdi-ethernet", "TCP", "Segmentos orientados a conexión, flags y estado de sesión."],
  udp: ["transport", "mdi-lan", "UDP", "Datagramas sin conexión y sus puertos."],
  sctp: ["transport", "mdi-lan-connect", "SCTP", "Asociaciones de transporte con múltiples flujos."],
  dccp: ["transport", "mdi-lan-connect", "DCCP", "Transporte de datagramas con control de congestión."],
  udplite: ["transport", "mdi-lan", "UDP-Lite", "Transporte de datagramas con checksum parcial."],

  // --- application: name resolution & discovery ---------------------------
  dns: ["application", "mdi-dns", "DNS", "Resolución de nombres: consultas, resolvedores y respuestas."],
  mdns: ["application", "mdi-dns-outline", "mDNS", "Resolución multicast de nombres en el segmento local."],
  llmnr: ["application", "mdi-dns-outline", "LLMNR", "Resolución multicast de nombres en el enlace local."],
  nbns: ["application", "mdi-dns-outline", "NBNS", "Consultas al servicio de nombres NetBIOS."],
  nbdgm: ["application", "mdi-dns-outline", "NetBIOS DGM", "Servicio de datagramas NetBIOS."],
  ssdp: ["application", "mdi-cast", "SSDP", "Anuncios y búsquedas de descubrimiento de servicios UPnP."],

  // --- application: web ---------------------------------------------------
  http: ["application", "mdi-web", "HTTP", "Peticiones web en texto claro: métodos, hosts y rutas."],
  "http-proxy": ["application", "mdi-web-box", "Proxy HTTP", "Tráfico dirigido a un proxy de salida."],
  tls: ["application", "mdi-lock-check", "TLS", "Sesiones cifradas identificadas por SNI cuando es visible."],
  quic: ["transport", "mdi-rocket-launch", "QUIC", "Transporte HTTP/3 sobre UDP."],

  // --- application: mail --------------------------------------------------
  smtp: ["application", "mdi-email-fast", "SMTP", "Envío y retransmisión de correo."],
  smtps: ["application", "mdi-email-lock", "SMTPS", "Envío de correo con TLS implícito."],
  imap: ["application", "mdi-email-open", "IMAP", "Acceso a buzones sin cifrado."],
  imaps: ["application", "mdi-email-lock", "IMAPS", "Acceso cifrado a buzones."],
  pop3: ["application", "mdi-email-arrow-left", "POP3", "Descarga de correo sin cifrado."],
  pop3s: ["application", "mdi-email-lock", "POP3S", "Descarga cifrada de correo."],

  // --- application: remote access & transfer ------------------------------
  ssh: ["application", "mdi-console", "SSH", "Sesiones cifradas de consola remota."],
  telnet: ["application", "mdi-console-line", "Telnet", "Consola remota sin cifrado, con credenciales visibles."],
  rdp: ["application", "mdi-monitor-share", "RDP", "Sesiones de escritorio remoto."],
  vnc: ["application", "mdi-monitor-share", "VNC", "Sesiones de visualización remota."],
  ftp: ["application", "mdi-file-upload", "FTP", "Canal de control de transferencia de archivos sin cifrado."],
  "ftp-data": ["application", "mdi-file-upload-outline", "Datos FTP", "Canal de datos de FTP."],
  tftp: ["application", "mdi-file-send", "TFTP", "Transferencia de archivos sin autenticación."],
  rsync: ["application", "mdi-file-sync", "rsync", "Sesiones de sincronización de archivos."],
  smb: ["application", "mdi-folder-network", "SMB", "Archivos e impresoras compartidos de Windows."],
  msrpc: ["application", "mdi-cog-transfer", "MSRPC", "Tráfico de endpoints RPC de Microsoft."],
  rpcbind: ["application", "mdi-cog-transfer", "rpcbind", "Consultas al mapeador de puertos ONC RPC."],
  git: ["application", "mdi-git", "Git", "Transferencias mediante el protocolo Git."],
  socks: ["application", "mdi-shuffle-variant", "SOCKS", "Conexiones mediante proxy."],
  pptp: ["network", "mdi-tunnel", "PPTP", "Canal de control de VPN heredada."],

  // --- application: directory, auth & infrastructure ----------------------
  ldap: ["application", "mdi-account-search", "LDAP", "Consultas de directorio sin cifrado."],
  ldaps: ["application", "mdi-account-lock", "LDAPS", "Consultas cifradas de directorio."],
  kerberos: ["application", "mdi-ticket-account", "Kerberos", "Solicitudes y concesiones de tickets."],
  radius: ["application", "mdi-account-key", "RADIUS", "Autenticación de acceso a la red."],
  ntp: ["application", "mdi-clock-outline", "NTP", "Sincronización horaria, un vector habitual de amplificación."],
  dhcp: ["application", "mdi-ip-network-outline", "DHCP", "Negociación de concesiones: DISCOVER, OFFER, REQUEST, ACK."],
  dhcpv6: ["application", "mdi-ip-network-outline", "DHCPv6", "Negociación de concesiones IPv6."],
  snmp: ["application", "mdi-console-network", "SNMP", "Consultas periódicas y notificaciones de dispositivos."],
  syslog: ["application", "mdi-text-box-outline", "Syslog", "Envío de logs sin cifrado."],
  ipmi: ["application", "mdi-server", "IPMI", "Administración de servidores fuera de banda."],
  xdmcp: ["application", "mdi-monitor", "XDMCP", "Sesiones del gestor de pantalla X."],
  finger: ["application", "mdi-account-question", "Finger", "Servicio heredado de consulta de usuarios."],
  whois: ["application", "mdi-account-search-outline", "WHOIS", "Consultas de registros."],
  nntp: ["application", "mdi-newspaper", "NNTP", "Transferencia de noticias Usenet."],

  // --- application: databases & caches ------------------------------------
  mysql: ["application", "mdi-database", "MySQL", "Sesiones de bases de datos."],
  postgres: ["application", "mdi-database", "PostgreSQL", "Sesiones de bases de datos."],
  mssql: ["application", "mdi-database", "MSSQL", "Sesiones de bases de datos."],
  oracle: ["application", "mdi-database", "Oracle", "Sesiones de bases de datos."],
  mongodb: ["application", "mdi-database", "MongoDB", "Sesiones de almacenamiento de documentos."],
  redis: ["application", "mdi-database-outline", "Redis", "Comandos de almacenamiento clave-valor."],
  memcached: ["application", "mdi-database-outline", "Memcached", "Tráfico de caché, un vector conocido de amplificación."],
  elasticsearch: ["application", "mdi-database-search", "Elasticsearch", "API HTTP de clúster de búsqueda."],

  // --- application: messaging & realtime ----------------------------------
  mqtt: ["application", "mdi-message-processing", "MQTT", "Tráfico de publicación y suscripción."],
  amqp: ["application", "mdi-message-processing-outline", "AMQP", "Tráfico de colas de mensajes."],
  xmpp: ["application", "mdi-chat", "XMPP", "Sesiones de mensajería instantánea."],
  irc: ["application", "mdi-forum", "IRC", "Sesiones de chat, un canal C2 habitual."],
  sip: ["application", "mdi-phone-in-talk", "SIP", "Señalización de llamadas."],
  stun: ["application", "mdi-phone-sync", "STUN", "Descubrimiento para atravesar NAT."],
  coap: ["application", "mdi-chip", "CoAP", "Tráfico REST de dispositivos con recursos limitados."],

  // --- application: tunnels & overlays ------------------------------------
  isakmp: ["application", "mdi-key-chain", "ISAKMP/IKE", "Negociación de claves IPsec."],
  openvpn: ["network", "mdi-vpn", "OpenVPN", "Tráfico de túneles VPN."],
  wireguard: ["network", "mdi-vpn", "WireGuard", "Tráfico de túneles VPN."],
  vxlan: ["network", "mdi-layers-triple", "VXLAN", "Encapsulación de red superpuesta de capa 2."],
  geneve: ["network", "mdi-layers-triple", "Geneve", "Encapsulación de virtualización de red."],

  // --- application: industrial --------------------------------------------
  modbus: ["application", "mdi-factory", "Modbus", "Lecturas y escrituras de PLC; las escrituras cambian el estado físico."],
  dnp3: ["application", "mdi-factory", "DNP3", "Consultas y control de estaciones SCADA."],
  bacnet: ["application", "mdi-home-thermometer", "BACnet", "Tráfico de automatización de edificios."],
  s7comm: ["application", "mdi-factory", "S7comm", "Tráfico de PLC Siemens S7."],
  bgp: ["application", "mdi-earth", "BGP", "Sesiones de enrutamiento entre dominios."],

  // --- residual -----------------------------------------------------------
  unknown: ["other", "mdi-help-circle-outline", "Desconocido", "Estructura reconocida con número de protocolo desconocido."],
  unparseable: ["other", "mdi-alert-octagon-outline", "No decodificable", "Tramas rechazadas por el parser; un pico puede indicar evasión o fuzzing."],
};

const LAYER_DEFAULTS = {
  link: ["mdi-ethernet-cable", "Tráfico de capa 2 en el segmento local."],
  network: ["mdi-ip-network", "Tráfico de capa 3."],
  transport: ["mdi-lan", "Tráfico de capa 4."],
  application: ["mdi-application-outline", "Tráfico de capa de aplicación."],
  other: ["mdi-radar", "Tráfico sin clasificar."],
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
