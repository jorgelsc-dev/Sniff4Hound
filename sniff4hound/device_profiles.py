"""Conservative device-type inference from already captured metadata.

The classifier intentionally avoids active probing.  A label is emitted only
when ports, protocols, banners or decoder metadata provide useful evidence;
otherwise the device stays ``Unknown`` instead of presenting a guess as fact.

What a packet says is about its *sender*.  An HTTP response names the server
that sent it, a User-Agent names the client that sent it, a DHCP request names
the host that made it.  So each observation says whether the host being
classified sent that packet (``sent``), and the facts a packet carries count for
the sender only: a PC that merely receives pages from an nginx is not an nginx.

Evidence comes in three strengths, and only the first two can decide a type:

* structured decoder fields of the sender (``http_server``, ``http_user_agent``,
  ``ssh_software``, ``dhcp_*``, ``lldp_*``/``cdp_*``, ``ssdp_*``);
* what the host does: it answers on a service port, serves HTTP, answers DNS,
  hands out DHCP leases;
* passive network facts for hosts on the local network: the initial TTL and a
  randomized hardware address.

Free text is the weakest.  It is read only from fields that describe a device
(banners, advertisements, host names) and never from web page bodies, which are
somebody else's content: a JavaScript ``switch`` statement in a downloaded page
once made a public web server show up as a network switch.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass

DEVICE_TYPES = ("Router", "Switch", "Phone", "PC", "Server", "Printer", "Camera", "IoT", "Unknown")

#: Product id -> label. The ids are what the UI maps to a logo.
PRODUCTS = {
    # web servers, proxies and CDNs
    "nginx": "Nginx", "openresty": "OpenResty", "apache": "Apache", "tomcat": "Apache Tomcat",
    "iis": "Microsoft IIS", "litespeed": "LiteSpeed", "caddy": "Caddy", "envoy": "Envoy",
    "haproxy": "HAProxy", "traefik": "Traefik", "lighttpd": "lighttpd", "jetty": "Jetty",
    "gunicorn": "Gunicorn", "werkzeug": "Werkzeug", "uvicorn": "Uvicorn", "kestrel": "Kestrel",
    "express": "Express", "nodejs": "Node.js", "php": "PHP", "cloudflare": "Cloudflare",
    "google": "Google", "akamai": "Akamai", "fastly": "Fastly", "cloudfront": "Amazon CloudFront",
    # services
    "openssh": "OpenSSH", "dropbear": "Dropbear", "postgresql": "PostgreSQL", "mysql": "MySQL",
    "mariadb": "MariaDB", "redis": "Redis", "mongodb": "MongoDB", "elasticsearch": "Elasticsearch",
    "kubernetes": "Kubernetes", "docker": "Docker", "postfix": "Postfix", "exim": "Exim",
    "vsftpd": "vsftpd", "proftpd": "ProFTPD", "mosquitto": "Mosquitto", "cups": "CUPS",
    # network equipment
    "openwrt": "OpenWrt", "mikrotik": "MikroTik", "cisco": "Cisco", "ubiquiti": "Ubiquiti",
    "pfsense": "pfSense", "fritzbox": "FRITZ!Box", "tplink": "TP-Link", "netgear": "NETGEAR",
    "juniper": "Juniper",
    # printers, cameras, IoT and appliances
    "hp": "HP", "epson": "Epson", "brother": "Brother", "canon": "Canon", "hikvision": "Hikvision",
    "dahua": "Dahua", "homeassistant": "Home Assistant", "synology": "Synology", "qnap": "QNAP",
    "zigbee": "Zigbee",
    # operating systems
    "windows": "Windows", "linux": "Linux", "apple": "Apple", "android": "Android",
    "ubuntu": "Ubuntu", "debian": "Debian", "raspberrypi": "Raspberry Pi", "chromeos": "ChromeOS",
    "freebsd": "FreeBSD",
}

#: Between two products backing the same type, the more specific one is shown:
#: "Debian" says more than "Linux".
_GENERIC_PRODUCTS = {"linux", "apple", "windows", "android"}

# ---------------------------------------------------------------------------
# Rule tables. Each rule is matched against the lower-cased value of one field.
# ---------------------------------------------------------------------------

# `Server:` response header -> (pattern, product, device type, weight). The first
# rule that matches wins, so the more specific ones come first ("Apache-Coyote"
# is Tomcat, not Apache). Embedded web interfaces name the kind of device the
# server belongs to, and weigh more than the 7 that merely serving web pages from
# port 80 is worth, or every router's admin page would read as "Server"; the
# rest are plain servers.
_SERVER_HEADER_RULES = (
    (r"apache-coyote|tomcat", "tomcat", "Server", 6),
    (r"openresty", "openresty", "Server", 6),
    (r"nginx", "nginx", "Server", 6),
    (r"apache", "apache", "Server", 6),
    (r"microsoft-iis|\biis\b", "iis", "Server", 6),
    (r"litespeed", "litespeed", "Server", 6),
    (r"caddy", "caddy", "Server", 6),
    (r"envoy", "envoy", "Server", 6),
    (r"haproxy", "haproxy", "Server", 6),
    (r"traefik", "traefik", "Server", 6),
    (r"lighttpd", "lighttpd", "Server", 5),
    (r"jetty", "jetty", "Server", 5),
    (r"gunicorn", "gunicorn", "Server", 6),
    (r"werkzeug", "werkzeug", "Server", 5),
    (r"uvicorn|hypercorn", "uvicorn", "Server", 5),
    (r"kestrel", "kestrel", "Server", 5),
    (r"\bexpress\b", "express", "Server", 5),
    (r"cloudflare", "cloudflare", "Server", 6),
    (r"akamai", "akamai", "Server", 6),
    (r"fastly", "fastly", "Server", 6),
    (r"cloudfront", "cloudfront", "Server", 6),
    (r"^(?:gws|gse|esf|sffe|gfe|ghs)\b|google frontend", "google", "Server", 6),
    (r"synology", "synology", "Server", 6),
    (r"qnap", "qnap", "Server", 6),
    (r"uhttpd", "openwrt", "Router", 10),
    (r"mikrotik|routeros", "mikrotik", "Router", 10),
    (r"fritz!?box", "fritzbox", "Router", 10),
    (r"pfsense", "pfsense", "Router", 10),
    (r"ubnt|ubiquiti|unifi", "ubiquiti", "Router", 9),
    (r"tp-?link", "tplink", "Router", 9),
    (r"netgear", "netgear", "Router", 9),
    (r"hikvision|app-webs|dvrdvs-webs", "hikvision", "Camera", 10),
    (r"dnvrs-webs|dahua", "dahua", "Camera", 10),
    (r"hp http server|hp-chai|hp laserjet|hp officejet|hp deskjet|virata-emweb", "hp", "Printer", 10),
    (r"epson", "epson", "Printer", 10),
    (r"brother", "brother", "Printer", 10),
    (r"canon", "canon", "Printer", 9),
    (r"home ?assistant", "homeassistant", "IoT", 10),
    (r"rompager|allegro-software", "", "Router", 9),
    (r"mini_httpd|micro_httpd|goahead|boa/|thttpd|embedthis|mbedthis|\becos\b", "", "IoT", 9),
)

# `User-Agent` request header -> (pattern, device type, weight, product, label).
# Order matters: an iPhone's agent also says "like Mac OS X" and an Android
# phone's says "Linux".
_USER_AGENT_RULES = (
    (r"iphone|ipad|ipod|cpu (?:iphone )?os \d", "Phone", 8, "apple", "iOS"),
    (r"android", "Phone", 7, "android", "Android"),
    (r"dalvik/", "Phone", 6, "android", "Android"),
    (r"windows nt|windows phone|windows-update-agent|microsoft-cryptoapi|microsoft ncsi", "PC", 7, "windows", "Windows"),
    (r"macintosh|mac os x", "PC", 7, "apple", "macOS"),
    (r"\bcros\b", "PC", 7, "chromeos", "ChromeOS"),
    (r"ubuntu", "PC", 6, "ubuntu", "Ubuntu"),
    (r"x11;|linux x86_64|linux i[3-6]86|linux aarch64|wayland", "PC", 6, "linux", "Linux"),
    (r"smart-?tv|tizen|web0s|webos|roku|appletv|hbbtv|crkey|chromecast|playstation|nintendo|xbox", "IoT", 6, "", ""),
    (r"esp8266|esp32|arduino", "IoT", 7, "", ""),
    # Scripts and libraries say little about the machine; enough to tip a tie, not to decide.
    (r"curl/|wget/|python-requests|python-urllib|go-http-client|libwww|okhttp|java/|apache-httpclient", "PC", 2, "", ""),
)

# DHCP option 60 (vendor class).
_DHCP_VENDOR_RULES = (
    (r"^android-dhcp", "Phone", 8, "android", "Android"),
    (r"^msft 5\.0", "PC", 6, "windows", "Windows"),
    (r"^udhcp|busybox", "IoT", 4, "linux", ""),
    (r"^dhcpcd", "PC", 2, "linux", ""),
    (r"ubnt|ubiquiti", "Router", 4, "ubiquiti", ""),
    (r"cisco", "Switch", 3, "cisco", ""),
)

# DHCP option 12 (host name), which the host picks for itself.
_HOSTNAME_RULES = (
    (r"iphone|ipad", "Phone", 8, "apple", "iOS"),
    (r"android|galaxy|pixel|redmi|xiaomi|oneplus|motorola", "Phone", 7, "android", "Android"),
    (r"macbook|imac|mac-?mini|\bmbp\b|-mbp|mac-?pro|macstudio", "PC", 7, "apple", "macOS"),
    (r"^desktop-[a-z0-9]+|^laptop-[a-z0-9]+|^win-[a-z0-9]+", "PC", 6, "windows", "Windows"),
    (r"printer|^hp[0-9a-f]{6}\b|^npi[0-9a-f]{6}|^epson|^brw[0-9a-f]{6}|^canon", "Printer", 7, "", ""),
    (r"ipcam|^cam[-_0-9]|camera", "Camera", 6, "", ""),
    (r"^esp[-_]?[0-9a-f]+|tasmota|shelly|sonoff|^wled|homeassistant", "IoT", 7, "", ""),
    (r"raspberrypi|^rpi[-_0-9]", "IoT", 4, "raspberrypi", ""),
)

# `ssh_software` sent by the SSH *server* (from port 22) -> (pattern, type, weight, product).
_SSH_SERVER_RULES = (
    (r"^rosssh", "Router", 8, "mikrotik"),
    (r"dropbear", "Router", 3, "dropbear"),
    (r"^cisco", "Switch", 3, "cisco"),
    (r"openssh", "Server", 4, "openssh"),
    (r"^libssh|^paramiko|^asyncssh|^wolfssh|^go$|^golang", "Server", 3, ""),
)
# The operating system a Linux/BSD distribution puts in the SSH banner suffix.
_SSH_OS_RULES = (
    (r"raspbian|raspberry", "raspberrypi"),
    (r"ubuntu", "ubuntu"),
    (r"debian", "debian"),
    (r"freebsd", "freebsd"),
)

# LLDP/CDP system descriptions and UPnP device types -> (pattern, type, weight, product).
_DESCRIPTION_RULES = (
    (r"internetgatewaydevice|wandevice|wanconnectiondevice", "Router", 8, ""),
    (r"miniupnpd", "Router", 5, ""),
    (r"mediarenderer|mediaserver|urn:dial-multiscreen", "IoT", 4, ""),
    (r"urn:schemas-upnp-org:device:printer|printer", "Printer", 6, ""),
    (r"\brouter\b|routeros|ios[- ]xr|junos", "Router", 7, ""),
    (r"\bswitch\b|catalyst|nexus|procurve", "Switch", 8, ""),
    (r"mikrotik", "Router", 6, "mikrotik"),
    (r"ubiquiti|unifi|ubnt", "Router", 5, "ubiquiti"),
    (r"cisco", "Switch", 3, "cisco"),
)

# Free text, weakest of all. Read only from fields that describe a device.
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
        "nginx": 5, "apache": 5, "openssh": 4, "postgresql": 5,
        "mysql": 5, "redis": 5, "kubernetes": 5, "proftpd": 5, "vsftpd": 5, "postfix": 5, "exim": 5,
    },
    "Printer": {
        "printer": 7, "jetdirect": 7, "laserjet": 7, "epson": 5,
        "brother": 4, "cups": 5, "ipp": 4,
    },
    "Camera": {"camera": 6, "onvif": 7, "ipcam": 7, "rtsp": 4, "hikvision": 7, "dahua": 7},
    "IoT": {"iot": 5, "mqtt": 5, "coap": 5, "home assistant": 5, "zigbee": 5},
}
_KEYWORD_PRODUCTS = {
    "openwrt": "openwrt", "mikrotik": "mikrotik", "routeros": "mikrotik", "fritz!box": "fritzbox",
    "pfsense": "pfsense", "juniper": "juniper", "android": "android", "iphone": "apple", "ios": "apple",
    "macbook": "apple", "windows": "windows", "ubuntu": "ubuntu", "nginx": "nginx", "apache": "apache",
    "openssh": "openssh", "postgresql": "postgresql", "mysql": "mysql", "redis": "redis",
    "kubernetes": "kubernetes", "proftpd": "proftpd", "vsftpd": "vsftpd", "postfix": "postfix",
    "exim": "exim", "epson": "epson", "brother": "brother", "cups": "cups", "hikvision": "hikvision",
    "dahua": "dahua", "home assistant": "homeassistant", "zigbee": "zigbee",
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
# A port a service listens on. 68 is the DHCP *client* port, even though it is
# below 1024.
_SERVICE_PORTS = (set(range(1, 1024)) | _SERVER_PORTS | set(_PORT_HINTS)) - {68}

_PROTOCOL_HINTS = {
    "ospf": ("Router", 7), "bgp": ("Router", 7), "rip": ("Router", 6),
    "vrrp": ("Router", 6), "hsrp": ("Router", 6),
    "lldp": ("Switch", 6), "cdp": ("Switch", 6), "stp": ("Switch", 6),
    "mqtt": ("IoT", 5), "coap": ("IoT", 6), "rtsp": ("Camera", 4),
}

#: Protocols whose payload is somebody's content or an opaque stream. A keyword
#: found there says nothing about the host that sent it.
_CONTENT_PROTOS = {"http", "http-proxy", "tls", "quic", "dns"}
#: ...and those with structured rules of their own, whose text must not be read a
#: second time as keywords (an SSH client's "OpenSSH" banner is not a server).
_NO_TEXT_PROTOS = _CONTENT_PROTOS | {"ssh"}
#: Protocols where the sender advertises its own name.
_SELF_NAMING_PROTOS = {"mdns", "dns-sd", "netbios", "llmnr", "dhcp", "ssdp"}

#: Scopes whose hosts are on, or one hop from, the capture machine's own network:
#: the TTL they send and the hardware address they use say something about them.
#: For anything farther away the TTL has crossed routers and the hardware address
#: is the gateway's.
_LAN_SCOPES = {"private", "local"}

#: Types a public address does not show without strong evidence: a host on the
#: Internet is a server, not somebody's phone because its banner said "android".
#: Free text never counts for these, and a structured fact must weigh at least this much.
_LAN_ONLY_TYPES = {"PC", "Phone", "Switch"}
_PUBLIC_MIN_WEIGHT = 6

#: Locally administered addresses that are not a phone's privacy address.
_NOT_PRIVACY_MAC_PREFIXES = ("02:42:", "52:54:00:")


def _compile_keyword(keyword: str) -> "re.Pattern[str]":
    """Whole-token matching, not "keyword in text": a plain substring check let
    short/common keywords fire on unrelated text that merely happened to contain
    them (e.g. "ios" inside "servicios"/"radios", "ipp" inside "shipping", "cdp"
    inside a random hex/base64 run). A keyword only counts when it is not glued
    to another letter or digit on either side."""
    return re.compile(r"(?<![a-z0-9])" + re.escape(keyword) + r"(?![a-z0-9])")


_KEYWORD_PATTERNS = {
    kind: [(keyword, _compile_keyword(keyword), weight) for keyword, weight in keywords.items()]
    for kind, keywords in _KEYWORDS.items()
}
_COMPILED = {
    name: [(re.compile(rule[0]),) + tuple(rule[1:]) for rule in rules]
    for name, rules in {
        "server": _SERVER_HEADER_RULES, "agent": _USER_AGENT_RULES, "vendor": _DHCP_VENDOR_RULES,
        "hostname": _HOSTNAME_RULES, "ssh": _SSH_SERVER_RULES, "ssh_os": _SSH_OS_RULES,
        "description": _DESCRIPTION_RULES,
    }.items()
}
#: How much descriptive text of one host is scanned for keywords.
_TEXT_LIMIT = 20000
_VERSION_AFTER = re.compile(r"[/ _-]v?(\d+(?:\.\d+){0,3})")
_OPENSSH_VERSION = re.compile(r"openssh_([0-9][0-9a-z.]*)")


@dataclass(frozen=True)
class _Hit:
    kind: str
    weight: int
    text: str
    product: str = ""
    label: str = ""
    version: str = ""
    #: Free text rather than a structured field or something the host did.
    weak: bool = False


def _first_rule(table: str, value: str):
    """The first rule of ``table`` that matches ``value``, with the match."""
    for rule in _COMPILED[table]:
        match = rule[0].search(value)
        if match:
            return rule, match
    return None, None


def _version_after(value: str, match: "re.Match[str]") -> str:
    found = _VERSION_AFTER.match(value, match.end())
    return found.group(1) if found else ""


def _json_details(value) -> dict:
    if isinstance(value, dict):
        return value
    text = str(value or "").strip()
    if not text or text[0] != "{":
        return {}
    try:
        parsed = json.loads(text)
    except ValueError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _port(value) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _side(local_port: int, peer_port: int) -> str:
    """Whether this host is the service ("server") or the one connecting
    ("client") in the conversation a packet belongs to, from the two ports."""
    local_service = local_port in _SERVICE_PORTS
    peer_service = peer_port in _SERVICE_PORTS
    if local_service and not peer_service:
        return "server"
    if peer_service and not local_service:
        return "client"
    return ""


def _initial_ttl(ttl: int) -> int:
    """The initial TTL a host started from, given what arrived (64, 128 or 255)."""
    return 64 if ttl <= 64 else 128 if ttl <= 128 else 255


def _scan_text(text: str, hits: list) -> None:
    """Weak keyword evidence from text that describes the device."""
    if not text:
        return
    for kind, patterns in _KEYWORD_PATTERNS.items():
        for keyword, pattern, weight in patterns:
            if pattern.search(text):
                hits.append(_Hit(kind, weight, f'metadata "{keyword}"', _KEYWORD_PRODUCTS.get(keyword, ""), weak=True))


def _sender_facts(row: dict, details: dict, side: str, hits: list) -> None:
    """Structured facts a packet carries about its own sender."""
    server = str(details.get("http_server") or "").strip().lower()
    if server:
        rule, match = _first_rule("server", server)
        if rule:
            _pattern, product, kind, weight = rule
            hits.append(_Hit(kind, weight, f'HTTP Server header "{str(details["http_server"]).strip()[:40]}"',
                             product, "", _version_after(server, match)))
        else:
            hits.append(_Hit("Server", 3, "HTTP Server header"))

    agent = str(details.get("http_user_agent") or "").strip().lower()
    if agent:
        rule, _match = _first_rule("agent", agent)
        if rule:
            _pattern, kind, weight, product, label = rule
            descriptor = label or ("script or tool" if weight <= 2 else kind)
            hits.append(_Hit(kind, weight, f"User-Agent: {descriptor}", product, label))

    banner = str(details.get("ssh_software") or "").strip().lower()
    if banner:
        if _port(row.get("local_port")) == 22:
            rule, match = _first_rule("ssh", banner)
            if rule:
                _pattern, kind, weight, product = rule
                version = ""
                if product == "openssh":
                    found = _OPENSSH_VERSION.search(banner)
                    version = found.group(1) if found else ""
                hits.append(_Hit(kind, weight, f"SSH server {str(details['ssh_software']).strip()[:40]}", product, "", version))
            else:
                hits.append(_Hit("Server", 3, "SSH server (22)"))
            os_rule, _ = _first_rule("ssh_os", banner)
            if os_rule:
                hits.append(_Hit("Server", 1, f"{PRODUCTS[os_rule[1]]} SSH banner", os_rule[1]))
        else:
            # A client announcing itself from an ephemeral port: all it tells us is the system it runs on.
            os_rule, _ = _first_rule("ssh_os", banner)
            if os_rule:
                hits.append(_Hit("PC", 2, f"{PRODUCTS[os_rule[1]]} SSH client", os_rule[1]))

    vendor = str(details.get("dhcp_vendor_class") or "").strip().lower()
    if vendor:
        rule, _match = _first_rule("vendor", vendor)
        if rule:
            _pattern, kind, weight, product, label = rule
            hits.append(_Hit(kind, weight, f'DHCP vendor class "{str(details["dhcp_vendor_class"]).strip()[:30]}"', product, label))
    hostname = str(details.get("dhcp_hostname") or "").strip().lower()
    if hostname:
        rule, _match = _first_rule("hostname", hostname)
        if rule:
            _pattern, kind, weight, product, label = rule
            hits.append(_Hit(kind, weight, f'host name "{str(details["dhcp_hostname"]).strip()[:30]}"', product, label))

    description = " ".join(
        str(details.get(key) or "")
        for key in ("lldp_system_description", "lldp_system_name", "cdp_software", "cdp_device_id", "ssdp_target")
    ).strip().lower()
    if description:
        rule, _match = _first_rule("description", description)
        if rule:
            _pattern, kind, weight, product = rule
            hits.append(_Hit(kind, weight, "LLDP/CDP/UPnP description", product))



def infer_device_profile(observations, scope: str = "") -> dict:
    """Return a label, confidence, short evidence list and the product it runs.

    ``observations`` are endpoint-relative packet facts: ``sent`` says whether the
    host being classified sent the packet, ``local_port``/``peer_port`` are its
    port and the other end's, and the rest is what the packet carried. They are
    metadata already stored by Sniff4Hound and never require a probe. ``scope`` is
    the address scope (``"public"``, ``"private"``, ...), which decides which
    network-level facts apply and which types need strong evidence.

    Rows without a ``sent`` key are taken as sent by the host, as before.
    """
    hits: list[_Hit] = []
    protocols = set()
    server_ports = set()
    text_parts: list[str] = []

    for row in observations or ():
        sent = bool(row.get("sent", True))
        local_port = _port(row.get("local_port"))
        peer_port = _port(row.get("peer_port"))
        proto = str(row.get("proto") or "").strip().lower()
        side = _side(local_port, peer_port)
        details = _json_details(row.get("details_json"))

        # What the conversation says about the host's role holds whichever way the packet went.
        if side != "client" and local_port in _SERVICE_PORTS:
            server_ports.add(local_port)
        if not sent:
            continue

        if proto:
            protocols.add(proto)
        _sender_facts(row, details, side, hits)

        if proto == "http" and side == "server":
            # Whatever it sends from a service port - the response line, a header, a body chunk - is a web server talking.
            hits.append(_Hit("Server", 5, f"serves HTTP ({local_port})"))
        if proto == "dns" and local_port == 53:
            # On a LAN the resolver is usually the gateway, but a Pi-hole or a domain
            # controller answers DNS too: alone this is a hint, with DHCP it is a router.
            hits.append(_Hit("Router" if scope == "private" else "Server", 3 if scope == "private" else 4, "answers DNS (53)"))
        if proto == "tls" and side == "server":
            hits.append(_Hit("Server", 4, f"serves TLS ({local_port})"))

        if scope in _LAN_SCOPES:
            ttl = _port(row.get("ttl"))
            if ttl and _initial_ttl(ttl) == 128:
                hits.append(_Hit("PC", 4, "TTL 128 (Windows)", "windows", "Windows"))
            mac = str(row.get("eth") or "").strip().lower()
            if len(mac) >= 8 and mac.count(":") == 5:
                try:
                    first = int(mac[:2], 16)
                except ValueError:
                    first = 0
                if first & 2 and not first & 1 and not mac.startswith(_NOT_PRIVACY_MAC_PREFIXES):
                    hits.append(_Hit("Phone", 3, "randomized MAC address"))

        if proto not in _NO_TEXT_PROTOS:
            text_parts.append(str(row.get("banner_text") or ""))
            text_parts.append(str(row.get("summary") or ""))
            text_parts.extend(str(value) for value in details.values())
        if proto in _SELF_NAMING_PROTOS or local_port == 5353:
            text_parts.append(str(row.get("domain") or ""))

    # One pass over the host's descriptive text, not one per row and field: with
    # ~60 keywords that is the difference between a handful of regex searches per
    # host and several thousand.
    _scan_text(" ".join(text_parts).lower()[:_TEXT_LIMIT], hits)

    for port in sorted(server_ports):
        hint = _PORT_HINTS.get(port)
        if hint:
            kind, weight, reason = hint
            hits.append(_Hit(kind, weight, reason))
        if port in _SERVER_PORTS:
            hits.append(_Hit("Server", 2, f"service port {port}"))
    for proto in sorted(protocols):
        hint = _PROTOCOL_HINTS.get(proto)
        if hint:
            kind, weight = hint
            hits.append(_Hit(kind, weight, f"{proto.upper()} protocol"))

    # A host on the Internet is a server unless something says loudly otherwise.
    if scope == "public":
        hits = [hit for hit in hits if hit.kind not in _LAN_ONLY_TYPES or (not hit.weak and hit.weight >= _PUBLIC_MIN_WEIGHT)]

    scores: dict[str, int] = defaultdict(int)
    seen = set()
    by_kind: dict[str, list[_Hit]] = defaultdict(list)
    for hit in hits:
        key = (hit.kind, hit.text)
        if key in seen:
            continue
        seen.add(key)
        scores[hit.kind] += hit.weight
        by_kind[hit.kind].append(hit)

    if not scores:
        return _profile("Unknown", "unknown", [], None)
    ranked = sorted(scores.items(), key=lambda item: (-item[1], DEVICE_TYPES.index(item[0])))
    kind, score = ranked[0]
    runner_up = ranked[1][1] if len(ranked) > 1 else 0
    if score < 3:
        return _profile("Unknown", "unknown", [], None)
    confidence = "high" if score >= 7 and score - runner_up >= 3 else "medium" if score >= 4 else "low"
    winners = sorted(by_kind[kind], key=lambda hit: -hit.weight)
    evidence = list(dict.fromkeys(hit.text for hit in winners))[:3]
    return _profile(kind, confidence, evidence, _best_product(winners))


def unknown_profile() -> dict:
    """The profile of an address there is nothing to classify (broadcast, multicast...)."""
    return _profile("Unknown", "unknown", [], None)


def _best_product(hits: list):
    """The product to show for the winning type: the most specific one that backs
    it, the strongest of those."""
    candidates = [hit for hit in hits if hit.product]
    if not candidates:
        return None
    return max(candidates, key=lambda hit: (hit.product not in _GENERIC_PRODUCTS, hit.weight))


def _profile(kind: str, confidence: str, evidence: list, product) -> dict:
    return {
        "device_type": kind,
        "device_confidence": confidence,
        "device_evidence": evidence,
        "device_product": product.product if product else "",
        "device_product_label": (product.label or PRODUCTS.get(product.product, product.product)) if product else "",
        "device_product_version": product.version if product else "",
    }
