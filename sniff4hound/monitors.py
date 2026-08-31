from __future__ import annotations

import copy
import functools
import re
import threading
import time
from pathlib import Path
import json

from . import settings
from .ahocorasick import AhoCorasick
from .runtime_paths import resolve_data_file
from .rulesets import build_packet_text, normalize_action, normalize_match, rule_matches_packet
from .utils import json_dumps, normalize_protocol_name, safe_int

NOISY_GENERATED_SIGNAL_LITERALS = frozenset(
    {
        "m-search",
        "m-search * http/1.1",
        "mozilla/",
        "mozilla/4.0",
        "mozilla/5.0",
        "user-agent: mozilla",
        "http/1.1 200 ok",
        "keep-alive",
        "application/json",
        "application/x-www-form-urlencoded",
        "multipart/form-data",
        "content-disposition: form-data; name=",
        "text/html",
        "text/html; charset=utf-8",
        "text/html; charset=utf-8\r\n",
        "text/xml",
        "application/xml",
        "image/webp",
        "gzip, deflate",
        "gzip, deflate, br",
        "content-encoding: gzip",
        "charset=utf-8",
    }
)

BUILTIN_MONITOR_QUALITY_OVERRIDES = {
    # These are parser-coverage breadcrumbs, not attack findings. Keeping
    # them enabled at low severity lets an operator investigate weird traffic
    # without allowing a noisy segment to dominate monitor results.
    "builtin-unknown-protocol": {"severity": "low"},
    "builtin-unparseable-packet": {"severity": "medium"},
    # Discovery protocols are normal on many LANs. They stay visible, but
    # should not look like high-confidence security alerts by default.
    "builtin-llmnr": {"severity": "low"},
    "builtin-nbns": {"severity": "low"},
    "builtin-ssdp": {"severity": "low"},
    "builtin-wsd": {"severity": "low"},
}


DEFAULT_MONITORS = [
    {
        "id": "builtin-credentials",
        "name": "Cleartext credentials",
        "description": "Username/password fields sent in the clear (HTTP forms, plaintext protocols).",
        "enabled": True,
        "priority": 10,
        "source": "builtin",
        "mode": "regex",
        "match": {
            # request_only: a server *response* routinely echoes these same
            # field names back (a JSON API returning {"username": "..."},
            # an HTML form's `name="password"` attribute, a JS bundle's
            # form-validation code) without ever having carried a real
            # credential - only what the client actually *sent* is a
            # genuine cleartext-credential exposure. protocols: ["tcp"] -
            # non-TCP payload text is either absent or a best-effort decode
            # of something that was never meant to be read as text (mDNS/
            # QUIC/etc.), and short generic patterns like these coincide
            # with that noise by chance often enough to matter.
            "request_only": True,
            "protocols": ["tcp"],
            "payload_regex": [
                r"pass(word|wd)?\s*[:=]",
                r"user(name)?\s*[:=]",
                r"\blogin\s*[:=]",
            ],
        },
        "action": {"tag": "credentials", "label": "Cleartext credentials", "severity": "high"},
    },
    {
        "id": "builtin-admin-ports",
        "name": "Sensitive admin ports",
        "description": "Traffic on commonly abused administrative/remote-access ports.",
        "enabled": True,
        "priority": 20,
        "source": "builtin",
        "mode": "rule",
        "match": {"ports": [21, 23, 135, 139, 445, 3389, 5900]},
        "action": {"tag": "admin-port", "label": "Admin port", "severity": "medium"},
    },
    {
        "id": "builtin-sqli",
        "name": "SQL injection pattern",
        "description": "Common SQL injection payload signatures seen in request traffic.",
        "enabled": True,
        "priority": 30,
        "source": "builtin",
        "mode": "regex",
        "match": {
            # request_only: an admin panel/DB-tool page (phpMyAdmin, a
            # query builder, API docs) routinely echoes "UNION SELECT" /
            # "DROP TABLE" back in its own *response* HTML - only the
            # client-sent side is an actual injection attempt.
            "request_only": True,
            "protocols": ["tcp"],
            "payload_regex": [
                r"union\s+select",
                r"or\s+1\s*=\s*1",
                r"drop\s+table",
                r"'\s*or\s*'1'\s*=\s*'1",
            ],
        },
        "action": {"tag": "sqli", "label": "SQL injection", "severity": "high"},
    },
    {
        "id": "builtin-xss",
        "name": "XSS pattern",
        "description": "Common cross-site scripting payload signatures seen in request traffic.",
        "enabled": True,
        "priority": 40,
        "source": "builtin",
        "mode": "regex",
        "match": {
            # request_only: this was the single biggest false-positive
            # source in the default ruleset - every ordinary HTML page a
            # sniffed host loads ships a `<script` tag in the *response*
            # body. Only a `<script`/`onerror=`/`javascript:` payload
            # riding in what the client sends (a query param, a form post)
            # is an actual reflected/DOM XSS attempt.
            "request_only": True,
            "protocols": ["tcp"],
            "payload_regex": [
                r"<script",
                r"onerror\s*=",
                r"javascript:",
            ],
        },
        "action": {"tag": "xss", "label": "XSS attempt", "severity": "medium"},
    },
    {
        "id": "builtin-icmp-oversized",
        "name": "Oversized ICMP",
        "description": "Unusually large ICMP/ICMPv6 payloads, a common tunneling/exfiltration signal.",
        "enabled": True,
        "priority": 50,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ["icmp", "icmpv6"], "min_length": 128},
        "action": {"tag": "icmp-oversized", "label": "Oversized ICMP", "severity": "medium"},
    },
    {
        "id": "builtin-l2-discovery",
        "name": "L2/discovery traffic",
        "description": "ARP resolution chatter, kept by default so host discovery (Radar/Map) stays populated.",
        "enabled": True,
        "priority": 60,
        "source": "builtin",
        "mode": "rule",
        "match": {"eth_types": [0x0806]},
        "action": {"tag": "discovery", "label": "L2 discovery", "severity": "info"},
    },
    {
        "id": "builtin-dns-domains",
        "name": "DNS domain lookups",
        "description": "DNS traffic on port 53. Feeds the Domains catalog with queried domain names.",
        "enabled": True,
        "priority": 70,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ["udp", "tcp"], "ports": [53]},
        "action": {"tag": "dns", "label": "DNS lookup", "severity": "info"},
    },
    {
        "id": "builtin-http-requests",
        "name": "HTTP requests",
        "description": "Plaintext HTTP requests. Feeds the Paths catalog with request methods/paths and the Domains catalog with Host headers.",
        "enabled": True,
        "priority": 80,
        "source": "builtin",
        "mode": "rule",
        "match": {
            "protocols": ["tcp"],
            "payload_contains": ["GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "HTTP/1."],
        },
        "action": {"tag": "http-request", "label": "HTTP request", "severity": "info"},
    },
    {
        "id": "builtin-tls-sni",
        "name": "TLS SNI / HTTPS domains",
        "description": "TLS ClientHello handshakes. Feeds the Domains catalog with the requested server name (SNI).",
        "enabled": True,
        "priority": 90,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ["tcp"], "ports": [443, 8443, 9443], "payload_prefix_hex": ["16"]},
        "action": {"tag": "tls-sni", "label": "TLS SNI", "severity": "info"},
    },
    {
        "id": "builtin-insecure-telnet",
        "name": "Telnet traffic",
        "description": "Unencrypted remote-shell protocol. Credentials and session data travel in the clear.",
        "enabled": False,
        "priority": 100,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ["tcp"], "ports": [23]},
        "action": {"tag": "telnet", "label": "Telnet", "severity": "medium"},
    },
    {
        "id": "builtin-insecure-ftp",
        "name": "FTP traffic",
        "description": "Unencrypted file-transfer protocol. Credentials and commands travel in the clear.",
        "enabled": False,
        "priority": 110,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ["tcp"], "ports": [21]},
        "action": {"tag": "ftp", "label": "FTP", "severity": "medium"},
    },
    {
        "id": "builtin-insecure-snmp",
        "name": "SNMP traffic",
        "description": "SNMP agent/manager traffic. Community strings (often 'public'/'private') travel unauthenticated in v1/v2c.",
        "enabled": False,
        "priority": 120,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ["udp"], "ports": [161, 162]},
        "action": {"tag": "snmp", "label": "SNMP", "severity": "medium"},
    },
    {
        "id": "builtin-plaintext-payload",
        "name": "Readable plaintext payload",
        "description": "Payload decodes to a substantial run of human-readable application text. Discovery/control protocols are excluded so normal multicast chatter does not double-fire as plaintext.",
        "enabled": True,
        "priority": 125,
        "source": "builtin",
        "mode": "rule",
        "match": {
            "min_payload_text_length": 32,
            "exclude_protocols": [
                "arp", "rarp", "stp", "llc", "llc-snap", "cdp", "lldp", "eapol",
                "igmp", "icmp", "icmpv6", "mdns", "llmnr", "nbns", "ssdp", "dhcp",
                "ntp", "snmp", "gre", "esp", "ah", "tls", "quic",
            ],
        },
        "action": {"tag": "plaintext", "label": "Readable plaintext", "severity": "low"},
    },
    {
        "id": "builtin-http-basic-auth",
        "name": "HTTP Basic Auth",
        "description": "HTTP requests carrying a base64-encoded Basic Authorization header (credentials recoverable, not encrypted).",
        "enabled": True,
        "priority": 130,
        "source": "builtin",
        "mode": "regex",
        "match": {"request_only": True, "protocols": ["tcp"], "payload_regex": [r"authorization:\s*basic\s+[a-z0-9+/=]+"]},
        "action": {"tag": "http-basic-auth", "label": "HTTP Basic Auth", "severity": "high"},
    },
    {
        "id": "builtin-dns-long-subdomain",
        "name": "DNS long/suspicious subdomain",
        "description": "DNS query names with an unusually long label, a common signature of DNS tunneling or data exfiltration.",
        "enabled": True,
        "priority": 140,
        "source": "builtin",
        "mode": "regex",
        "match": {"protocols": ["udp", "tcp"], "ports": [53], "payload_regex": [r"\b[a-z0-9][a-z0-9-]{39,}\.[a-z0-9.-]+\b"]},
        "action": {"tag": "dns-long-subdomain", "label": "Suspicious DNS subdomain", "severity": "medium"},
    },
    {
        "id": "builtin-dns-hex-subdomain",
        "name": "DNS hex-encoded subdomain",
        "description": "Long hex-only DNS query label, a common signature of DNS tunneling/C2 beaconing implants that hex-encode exfiltrated data or commands.",
        "enabled": True,
        "priority": 141,
        "source": "builtin",
        "mode": "regex",
        "match": {"protocols": ["udp", "tcp"], "ports": [53], "payload_regex": [r"\b[a-f0-9]{32,}\.[a-z0-9.-]+\b"]},
        "action": {"tag": "dns-hex-subdomain", "label": "Hex-encoded DNS subdomain", "severity": "medium"},
    },
    {
        "id": "builtin-dns-query-flood",
        "name": "DNS query flood",
        "description": "Stateful: flags a source sending an unusually high rate of DNS queries within a short window — bulk lookups are a common DGA-malware-beaconing or misbehaving-host signature.",
        "enabled": True,
        "priority": 145,
        "source": "builtin",
        "mode": "stateful",
        "match": {"protocols": ["udp", "tcp"], "ports": [53]},
        "action": {"tag": "dns-query-flood", "label": "DNS query flood", "severity": "medium"},
    },
    {
        "id": "builtin-arp-spoof",
        "name": "ARP spoofing / MITM",
        "description": "Stateful: flags an IP address whose ARP-announced MAC address changes, a classic ARP-spoofing/MITM signature.",
        "enabled": True,
        "priority": 15,
        "source": "builtin",
        "mode": "stateful",
        "match": {"eth_types": [0x0806]},
        "action": {"tag": "arp-spoof", "label": "ARP spoofing suspected", "severity": "critical"},
    },
    {
        "id": "builtin-icmp-flood",
        "name": "ICMP flood",
        "description": "Stateful: flags a source sending an unusually high rate of ICMP/ICMPv6 packets within a short window.",
        "enabled": True,
        "priority": 55,
        "source": "builtin",
        "mode": "stateful",
        "match": {"protocols": ["icmp", "icmpv6"]},
        "action": {"tag": "icmp-flood", "label": "ICMP flood", "severity": "high"},
    },
    {
        "id": "builtin-syn-flood",
        "name": "TCP SYN flood",
        "description": "Stateful: flags a source sending an unusually high rate of bare TCP SYN packets within a short window — the classic SYN-flood DoS signature.",
        "enabled": True,
        "priority": 6,
        "source": "builtin",
        "mode": "stateful",
        "match": {"protocols": ["tcp"]},
        "action": {"tag": "syn-flood", "label": "TCP SYN flood", "severity": "high"},
    },
    {
        "id": "builtin-brute-force-login",
        "name": "Login brute-force attempt",
        "description": "Stateful: flags repeated connection attempts from the same source to a credential-bearing service (SSH/RDP/FTP/Telnet/DB) within a short window.",
        "enabled": True,
        "priority": 7,
        "source": "builtin",
        "mode": "stateful",
        "match": {"protocols": ["tcp"], "ports": [21, 22, 23, 25, 110, 143, 993, 995, 1433, 3306, 3389, 5432, 5900]},
        "action": {"tag": "brute-force-login", "label": "Login brute-force attempt", "severity": "high"},
    },
    # --- ICS/SCADA (Modbus/TCP, DNP3) ---
    {
        "id": "builtin-modbus-write-command",
        "name": "Modbus write command",
        "description": "A Modbus write function code (write single/multiple coil or register, mask write, or a combined read/write) - the source is changing physical process state on an ICS device, the single highest-value signal a passive Modbus monitor can surface.",
        "enabled": True,
        "priority": 170,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ["modbus"], "payload_contains": ["(write)"]},
        "action": {"tag": "modbus-write-command", "label": "Modbus write command", "severity": "high"},
    },
    {
        "id": "builtin-modbus-traffic-seen",
        "name": "Modbus traffic seen",
        "description": "Any Modbus/TCP traffic (port 502) - visibility into ICS activity on the network, not just writes.",
        "enabled": False,
        "priority": 171,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ["modbus"], "min_length": 1},
        "action": {"tag": "modbus-traffic", "label": "Modbus traffic", "severity": "info"},
    },
    {
        "id": "builtin-dnp3-restart-command",
        "name": "DNP3 cold/warm restart command",
        "description": "A DNP3 outstation is being remotely cold- or warm-restarted (function codes 13/14) - rarely benign; a common DoS/disruption technique against ICS outstations.",
        "enabled": True,
        "priority": 172,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ["dnp3"], "payload_contains": ["cold-restart", "warm-restart"]},
        "action": {"tag": "dnp3-restart-command", "label": "DNP3 restart command", "severity": "critical"},
    },
    {
        "id": "builtin-dnp3-unsolicited-response",
        "name": "DNP3 unsolicited response",
        "description": "A DNP3 outstation pushed data without being polled (function code 130) - normal in some deployments, but a burst from a device that never does this is a known DNP3 attack/DoS pattern.",
        "enabled": True,
        "priority": 173,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ["dnp3"], "payload_contains": ["unsolicited-response"]},
        "action": {"tag": "dnp3-unsolicited-response", "label": "DNP3 unsolicited response", "severity": "medium"},
    },
    {
        "id": "builtin-dnp3-traffic-seen",
        "name": "DNP3 traffic seen",
        "description": "Any DNP3 traffic (port 20000) - visibility into ICS activity on the network.",
        "enabled": False,
        "priority": 174,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ["dnp3"], "min_length": 1},
        "action": {"tag": "dnp3-traffic", "label": "DNP3 traffic", "severity": "info"},
    },
    {
        "id": "builtin-dhcp-rogue-server",
        "name": "DHCP rogue server",
        "description": "Stateful: flags more than one distinct source IP handing out DHCP leases - a classic rogue/unauthorized DHCP server signature, visible on any local segment since DHCP is broadcast.",
        "enabled": True,
        "priority": 175,
        "source": "builtin",
        "mode": "stateful",
        "match": {"protocols": ["dhcp"]},
        "action": {"tag": "dhcp-rogue-server", "label": "DHCP rogue server", "severity": "critical"},
    },
    # --- Infrastructure/management protocols (SNMP, Syslog, TFTP, RADIUS, MQTT) ---
    {
        "id": "builtin-snmp-weak-community",
        "name": "SNMP default/weak community string",
        "description": "SNMPv1/v2c community string sent in cleartext matches a well-known default ('public', 'private', 'community') - SNMP's entire access control for v1/v2c, exposed on the wire.",
        "enabled": True,
        "priority": 180,
        "source": "builtin",
        "mode": "rule",
        "match": {
            "protocols": ["snmp"],
            "payload_contains": ["community='public'", "community='private'", "community='community'"],
        },
        "action": {"tag": "snmp-weak-community", "label": "SNMP weak community string", "severity": "high"},
    },
    {
        "id": "builtin-snmp-traffic-seen",
        "name": "SNMP traffic seen",
        "description": "Any SNMP traffic (ports 161/162) - visibility into device management activity on the network.",
        "enabled": False,
        "priority": 181,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ["snmp"], "min_length": 1},
        "action": {"tag": "snmp-traffic", "label": "SNMP traffic", "severity": "info"},
    },
    {
        "id": "builtin-syslog-high-severity",
        "name": "Syslog high-severity message",
        "description": "A syslog message (port 514) at emergency/alert/critical severity - visibility into what devices on the network are actively reporting as broken.",
        "enabled": True,
        "priority": 182,
        "source": "builtin",
        "mode": "rule",
        "match": {
            "protocols": ["syslog"],
            "payload_contains": ["severity=emergency", "severity=alert", "severity=critical"],
        },
        "action": {"tag": "syslog-high-severity", "label": "Syslog high-severity message", "severity": "medium"},
    },
    {
        "id": "builtin-tftp-file-transfer",
        "name": "TFTP file transfer",
        "description": "A TFTP read/write request (port 69) - TFTP has no authentication or encryption; common for network-gear firmware/config transfer, also abused to plant tampered firmware.",
        "enabled": False,
        "priority": 183,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ["tftp"], "payload_contains": ["RRQ", "WRQ"]},
        "action": {"tag": "tftp-file-transfer", "label": "TFTP file transfer", "severity": "medium"},
    },
    {
        "id": "builtin-radius-traffic-seen",
        "name": "RADIUS traffic seen",
        "description": "Any RADIUS traffic (ports 1812/1813) - AAA/network-login activity visibility. Passwords in RADIUS are always hashed, so this is metadata-only (NAS IP, username), not credential exposure.",
        "enabled": False,
        "priority": 184,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ["radius"], "min_length": 1},
        "action": {"tag": "radius-traffic", "label": "RADIUS traffic", "severity": "info"},
    },
    {
        "id": "builtin-mqtt-cleartext-credentials",
        "name": "MQTT cleartext credentials",
        "description": "An MQTT CONNECT packet (port 1883) carries a username/password - IoT brokers frequently ship without TLS, exposing device credentials on the wire.",
        "enabled": True,
        "priority": 185,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ["mqtt"], "payload_contains": ["password=<present>"]},
        "action": {"tag": "mqtt-cleartext-credentials", "label": "MQTT cleartext credentials", "severity": "high"},
    },
    {
        "id": "builtin-mqtt-traffic-seen",
        "name": "MQTT traffic seen",
        "description": "Any MQTT traffic (port 1883) - visibility into IoT device activity on the network.",
        "enabled": False,
        "priority": 186,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ["mqtt"], "min_length": 1},
        "action": {"tag": "mqtt-traffic", "label": "MQTT traffic", "severity": "info"},
    },
    # --- Recent (2023-2024) mass-exploited CVEs with a simple, low-false-positive string signature ---
    {
        "id": "builtin-cve-2024-1709-screenconnect",
        "name": "ConnectWise ScreenConnect auth bypass (CVE-2024-1709)",
        "description": "Request targets /SetupWizard.aspx/ on what should be an already-configured instance - a .NET path-parsing quirk (CVE-2024-1709, CVSS 10) lets an attacker reach the setup wizard and create an admin account.",
        "enabled": True,
        "priority": 190,
        "source": "builtin",
        "mode": "regex",
        "match": {"request_only": True, "protocols": ["tcp"], "payload_regex": [r"/setupwizard\.aspx/"]},
        "action": {"tag": "cve-2024-1709-screenconnect", "label": "ScreenConnect auth bypass (CVE-2024-1709)", "severity": "critical"},
    },
    {
        "id": "builtin-cve-2024-21887-ivanti",
        "name": "Ivanti Connect Secure path traversal (CVE-2023-46805 / CVE-2024-21887)",
        "description": "The exact path-traversal payload observed in mass, nation-state exploitation of chained Ivanti Connect Secure/Policy Secure auth-bypass + command-injection zero-days.",
        "enabled": True,
        "priority": 191,
        "source": "builtin",
        "mode": "regex",
        "match": {"request_only": True, "protocols": ["tcp"], "payload_regex": [r"api/v1/totp/user-backup-code/\.\./"]},
        "action": {"tag": "cve-2024-21887-ivanti", "label": "Ivanti Connect Secure path traversal (CVE-2023-46805/CVE-2024-21887)", "severity": "critical"},
    },
    # --- Parser coverage gaps: traffic the sniffer can't classify or parse ---
    {
        "id": "builtin-unknown-protocol",
        "name": "Unknown protocol traffic",
        "description": "A recognized Ethernet/IP structure carried a protocol number or EtherType this sniffer doesn't have a dedicated parser for (proto='unknown'). Not malformed - just unclassified.",
        "enabled": False,
        "priority": 195,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ["unknown"], "min_length": 1},
        "action": {"tag": "unknown-protocol", "label": "Unknown protocol traffic", "severity": "high"},
    },
    {
        "id": "builtin-unparseable-packet",
        "name": "Unparseable packet",
        "description": "A frame that either raised an exception while being parsed, or was too short/malformed to even attempt (proto='unparseable') - distinct from 'unknown protocol', which means a recognized structure with an unrecognized protocol number. Worth a look: malformed frames are a common fuzzing/exploit-attempt signature.",
        "enabled": False,
        "priority": 196,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ["unparseable"], "min_length": 1},
        "action": {"tag": "unparseable-packet", "label": "Unparseable packet", "severity": "high"},
    },
    # --- Sensitive data exposure (PII / secrets in cleartext traffic) ---
    {
        "id": "builtin-sensitive-credit-card",
        "name": "Credit card number exposed",
        "description": "Visa/MasterCard/Amex/Discover-shaped number sequence seen in cleartext traffic.",
        "enabled": True,
        "priority": 200,
        "source": "builtin",
        "mode": "regex",
        "match": {
            "payload_regex": [
                r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"
            ]
        },
        "action": {"tag": "sensitive-credit-card", "label": "Credit card exposed", "severity": "critical"},
    },
    {
        "id": "builtin-sensitive-ssn",
        "name": "US SSN exposed",
        "description": "US Social Security Number-shaped sequence (###-##-####) seen in cleartext traffic.",
        "enabled": True,
        "priority": 201,
        "source": "builtin",
        "mode": "regex",
        "match": {"payload_regex": [r"\b\d{3}-\d{2}-\d{4}\b"]},
        "action": {"tag": "sensitive-ssn", "label": "SSN exposed", "severity": "critical"},
    },
    {
        "id": "builtin-sensitive-private-key",
        "name": "Private key material exposed",
        "description": "PEM-encoded private key header (RSA/EC/DSA/OpenSSH/PGP) seen in cleartext traffic.",
        "enabled": True,
        "priority": 202,
        "source": "builtin",
        "mode": "regex",
        "match": {"payload_regex": [r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"]},
        "action": {"tag": "sensitive-private-key", "label": "Private key exposed", "severity": "critical"},
    },
    {
        "id": "builtin-sensitive-aws-key",
        "name": "AWS access key exposed",
        "description": "AWS access key ID pattern (AKIA...) seen in cleartext traffic.",
        "enabled": True,
        "priority": 203,
        "source": "builtin",
        "mode": "regex",
        "match": {"payload_regex": [r"\bAKIA[0-9A-Z]{16}\b"]},
        "action": {"tag": "sensitive-aws-key", "label": "AWS key exposed", "severity": "critical"},
    },
    {
        "id": "builtin-sensitive-jwt",
        "name": "JWT token exposed",
        "description": "JSON Web Token (header.payload.signature) seen in cleartext traffic.",
        "enabled": True,
        "priority": 204,
        "source": "builtin",
        "mode": "regex",
        "match": {"payload_regex": [r"\beyj[a-z0-9_-]{10,}\.eyj[a-z0-9_-]{10,}\.[a-z0-9_-]{10,}\b"]},
        "action": {"tag": "sensitive-jwt", "label": "JWT exposed", "severity": "medium"},
    },
    {
        "id": "builtin-sensitive-api-token",
        "name": "API token exposed",
        "description": "GitHub or Slack API token pattern seen in cleartext traffic.",
        "enabled": True,
        "priority": 205,
        "source": "builtin",
        "mode": "regex",
        "match": {"payload_regex": [r"\b(gh[pousr]_[a-z0-9]{36}|xox[baprs]-[0-9a-z-]{10,})\b"]},
        "action": {"tag": "sensitive-api-token", "label": "API token exposed", "severity": "high"},
    },
    {
        "id": "builtin-sensitive-db-connstring",
        "name": "Database credentials in connection string",
        "description": "MongoDB/Postgres/MySQL/Redis connection string with embedded username:password seen in cleartext traffic.",
        "enabled": True,
        "priority": 206,
        "source": "builtin",
        "mode": "regex",
        "match": {"payload_regex": [r"\b(mongodb|postgres(?:ql)?|mysql|redis)://[^:/\s]+:[^@/\s]+@"]},
        "action": {"tag": "sensitive-db-connstring", "label": "DB credentials exposed", "severity": "critical"},
    },
    {
        "id": "builtin-sensitive-crypto-wallet",
        "name": "Cryptocurrency wallet address exposed",
        "description": "Bitcoin (legacy/bech32) or Ethereum wallet address seen in cleartext traffic — useful for spotting ransom demands or payout addresses.",
        "enabled": True,
        "priority": 207,
        "source": "builtin",
        "mode": "regex",
        "match": {"payload_regex": [r"\b(bc1[a-z0-9]{25,39}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-f0-9]{40})\b"]},
        "action": {"tag": "sensitive-crypto-wallet", "label": "Crypto wallet address exposed", "severity": "medium"},
    },
    {
        "id": "builtin-sensitive-cloud-api-key",
        "name": "Cloud provider API key exposed",
        "description": "Google Cloud/Firebase (AIza...) or Stripe live secret key (sk_live_...) pattern seen in cleartext traffic.",
        "enabled": True,
        "priority": 208,
        "source": "builtin",
        "mode": "regex",
        "match": {"payload_regex": [r"\b(aiza[0-9a-z_-]{35}|sk_live_[0-9a-z]{16,})\b"]},
        "action": {"tag": "sensitive-cloud-api-key", "label": "Cloud API key exposed", "severity": "critical"},
    },
    {
        "id": "builtin-sensitive-ntlm-auth",
        "name": "NTLM/Negotiate auth exposed",
        "description": "HTTP WWW-Authenticate/Authorization header advertising NTLM or Negotiate (Windows integrated auth) — the handshake is crackable offline if captured.",
        "enabled": True,
        "priority": 209,
        "source": "builtin",
        "mode": "regex",
        "match": {"payload_regex": [r"(www-authenticate|authorization):\s*(ntlm|negotiate)\b"]},
        "action": {"tag": "sensitive-ntlm-auth", "label": "NTLM/Negotiate auth exposed", "severity": "medium"},
    },
    # --- Tor / anonymization network usage ---
    {
        "id": "builtin-tor-ports",
        "name": "Tor network ports",
        "description": "Traffic on well-known Tor OR/directory/SOCKS ports.",
        "enabled": True,
        "priority": 210,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ["tcp"], "ports": [9001, 9030, 9040, 9050, 9051, 9150]},
        "action": {"tag": "tor-port", "label": "Tor network traffic", "severity": "medium"},
    },
    {
        "id": "builtin-tor-onion-domain",
        "name": ".onion domain reference",
        "description": "A Tor hidden-service (.onion) address seen in DNS/HTTP/mDNS/LLMNR traffic.",
        "enabled": True,
        "priority": 211,
        "source": "builtin",
        "mode": "regex",
        "match": {"payload_regex": [r"\b[a-z2-7]{16,56}\.onion\b"]},
        "action": {"tag": "tor-onion-domain", "label": "Tor .onion address", "severity": "medium"},
    },
    # --- Suspicious / high-risk domains (heuristic, no external blocklist feed) ---
    {
        "id": "builtin-suspicious-tld",
        "name": "High-abuse TLD",
        "description": "DNS/HTTP traffic referencing a TLD commonly abused for phishing/malware distribution (heuristic, not a live threat-intel feed).",
        "enabled": False,
        "priority": 220,
        "source": "builtin",
        "mode": "regex",
        "match": {"payload_regex": [r"\.(xyz|top|club|work|zip|mov|country|gq|cf|tk|ml|ga|icu|rest|monster)\b"]},
        "action": {"tag": "suspicious-tld", "label": "High-abuse TLD", "severity": "low"},
    },
    {
        "id": "builtin-domain-typosquat-pattern",
        "name": "Typosquat-shaped domain",
        "description": "Multi-hyphen domain name carrying a login/verify/account-style keyword, commonly used in typosquatting/phishing campaigns (e.g. brand-login-secure.com).",
        "enabled": False,
        "priority": 221,
        "source": "builtin",
        "mode": "regex",
        # Any bare "word-word-word.tld" shape is also just how ordinary
        # cloud/CDN infrastructure names itself (AWS/Azure/Akamai regional
        # and service hostnames are almost always multi-hyphen), so matching
        # that shape alone flagged huge amounts of legitimate traffic. A
        # phishing-shaped domain specifically sandwiches an
        # account-action/brand-trust keyword between two other segments;
        # requiring that keyword is what actually carries the signal.
        "match": {
            "payload_regex": [
                r"\b[a-z0-9]+-(login|signin|secure|verify|verification|account|update|confirm|support"
                r"|billing|wallet|password|security|banking|invoice|refund)-[a-z0-9]+\.(com|net|info|biz|org)\b"
            ]
        },
        "action": {"tag": "domain-typosquat-pattern", "label": "Typosquat-shaped domain", "severity": "low"},
    },
    # --- Web attacks ---
    {
        "id": "builtin-path-traversal",
        "name": "Path traversal attempt",
        "description": "Directory traversal sequence (../, encoded or double-encoded) seen in request traffic.",
        "enabled": True,
        "priority": 230,
        "source": "builtin",
        "mode": "regex",
        "match": {"request_only": True, "protocols": ["tcp"], "payload_regex": [r"(\.\.[\\/]){2,}|%2e%2e%2f|%252e%252e%252f"]},
        "action": {"tag": "path-traversal", "label": "Path traversal attempt", "severity": "high"},
    },
    {
        "id": "builtin-command-injection",
        "name": "Command injection attempt",
        "description": "Shell metacharacter sequence commonly used for OS command injection.",
        "enabled": True,
        "priority": 231,
        "source": "builtin",
        "mode": "regex",
        # request_only: the backtick/`$(...)` alternatives otherwise fire on
        # any markdown/code-snippet/chat-API payload riding in a normal
        # response body (backticked code spans, shell examples in docs).
        # protocols: ["tcp"] - observed matching decoded mDNS/UDP service
        # discovery text (a device announcing an mDNS service name that
        # happened to contain a byte sequence read back as a backtick pair)
        # on live traffic; command injection is a request/response
        # application-layer attack, never something UDP broadcast chatter
        # should be evaluated against.
        "match": {
            "request_only": True,
            "protocols": ["tcp"],
            "payload_regex": [r";\s*(cat|wget|curl|nc|bash|sh|python|perl)\s|\$\([^)]+\)|`[^`]+`"],
        },
        "action": {"tag": "command-injection", "label": "Command injection attempt", "severity": "high"},
    },
    {
        "id": "builtin-log4shell",
        "name": "Log4Shell / JNDI injection",
        "description": "${jndi:...} lookup pattern seen in traffic — the Log4Shell (CVE-2021-44228) exploitation signature.",
        "enabled": True,
        "priority": 232,
        "source": "builtin",
        "mode": "regex",
        "match": {"request_only": True, "protocols": ["tcp"], "payload_regex": [r"\$\{jndi:(ldap|rmi|dns|iiop|corba|nis)://"]},
        "action": {"tag": "log4shell", "label": "Log4Shell / JNDI injection", "severity": "critical"},
    },
    {
        "id": "builtin-shellshock",
        "name": "Shellshock exploitation attempt",
        "description": "Bash function-definition-in-environment-variable pattern (CVE-2014-6271) seen in traffic.",
        "enabled": True,
        "priority": 233,
        "source": "builtin",
        "mode": "rule",
        "match": {"request_only": True, "protocols": ["tcp"], "payload_contains": ["() { :;"]},
        "action": {"tag": "shellshock", "label": "Shellshock attempt", "severity": "critical"},
    },
    {
        "id": "builtin-xxe-injection",
        "name": "XXE injection attempt",
        "description": "XML external entity declaration (<!ENTITY ... SYSTEM) seen in request traffic — used to read local files or trigger SSRF via a vulnerable XML parser.",
        "enabled": True,
        "priority": 234,
        "source": "builtin",
        "mode": "regex",
        "match": {"request_only": True, "protocols": ["tcp"], "payload_regex": [r"<!entity\s+\S+\s+system\s+[\"']"]},
        "action": {"tag": "xxe-injection", "label": "XXE injection attempt", "severity": "high"},
    },
    {
        "id": "builtin-ssrf-attempt",
        "name": "SSRF probe attempt",
        "description": "Request targeting a non-HTTP internal scheme (file/gopher/dict) or the cloud instance-metadata address — a common server-side request forgery signature.",
        "enabled": True,
        "priority": 235,
        "source": "builtin",
        "mode": "regex",
        "match": {"request_only": True, "protocols": ["tcp"], "payload_regex": [r"\b(file|gopher|dict)://|169\.254\.169\.254|metadata\.google\.internal"]},
        "action": {"tag": "ssrf-attempt", "label": "SSRF probe attempt", "severity": "high"},
    },
    {
        "id": "builtin-ssti-attempt",
        "name": "Server-side template injection attempt",
        "description": "Template-expression probe pattern (e.g. {{7*7}}, ${7*7}) commonly used to fingerprint SSTI-vulnerable template engines.",
        "enabled": True,
        "priority": 236,
        "source": "builtin",
        "mode": "regex",
        "match": {"request_only": True, "protocols": ["tcp"], "payload_regex": [r"\{\{\s*7\s*\*\s*7\s*\}\}|\$\{\s*7\s*\*\s*7\s*\}"]},
        "action": {"tag": "ssti-attempt", "label": "SSTI attempt", "severity": "medium"},
    },
    {
        "id": "builtin-insecure-deserialization",
        "name": "Insecure deserialization payload",
        "description": "Java (rO0AB... base64 magic bytes) or PHP (O:8:\"stdClass\":...) serialized-object signature seen in request traffic.",
        "enabled": True,
        "priority": 237,
        "source": "builtin",
        "mode": "regex",
        "match": {"request_only": True, "protocols": ["tcp"], "payload_regex": [r"ro0ab[a-z0-9+/=]{6,}|o:\d+:\"[a-z0-9_\\]+\":\d+:\{"]},
        "action": {"tag": "insecure-deserialization", "label": "Insecure deserialization payload", "severity": "high"},
    },
    {
        "id": "builtin-webshell-reference",
        "name": "Known web shell reference",
        "description": "Filename or marker matching a well-known PHP/ASP web shell (c99, r57, b374k, wso, weevely) seen in request traffic.",
        "enabled": True,
        "priority": 238,
        "source": "builtin",
        "mode": "regex",
        "match": {"request_only": True, "protocols": ["tcp"], "payload_regex": [r"\b(c99|r57|b374k|wso|weevely)(shell)?\b"]},
        "action": {"tag": "webshell-reference", "label": "Web shell reference", "severity": "critical"},
    },
    {
        "id": "builtin-root-id-response",
        "name": "Root id command response",
        "description": "Unix id command output showing uid/gid/groups as root, the classic testmyids.com IDS validation response.",
        "enabled": True,
        "priority": 239,
        "source": "builtin",
        "mode": "regex",
        "match": {
            "protocols": ["tcp"],
            "payload_regex": [r"(?:^|[^A-Za-z0-9_])uid=0\(root\)\s+gid=0\(root\)\s+groups=0\(root\)(?![A-Za-z0-9_])"],
        },
        "action": {"tag": "root-id-response", "label": "Root id command response", "severity": "critical"},
    },
    {
        "id": "builtin-nosql-injection",
        "name": "NoSQL injection pattern",
        "description": "MongoDB query-operator injection pattern ($where/$ne/$gt as a JSON key) seen in request traffic.",
        "enabled": True,
        "priority": 239,
        "source": "builtin",
        "mode": "regex",
        "match": {"request_only": True, "protocols": ["tcp"], "payload_regex": [r"\{\s*\"\$(where|ne|gt|regex)\"\s*:"]},
        "action": {"tag": "nosql-injection", "label": "NoSQL injection attempt", "severity": "high"},
    },
    {
        "id": "builtin-crlf-injection",
        "name": "CRLF / HTTP response-splitting attempt",
        "description": "URL-encoded CRLF sequence injected into a request line/parameter, used for HTTP response splitting or header/cookie injection.",
        "enabled": True,
        "priority": 243,
        "source": "builtin",
        "mode": "regex",
        # A literal, unencoded "\r\nset-cookie:" is just what every ordinary
        # HTTP response that sets a session cookie looks like on the wire -
        # matching it here made this rule fire on nearly all normal web
        # traffic. The actual injection signature is the *encoded* CRLF
        # (%0d%0a) landing inside a request, which only happens when an
        # attacker smuggles it through a URL/parameter.
        "match": {"request_only": True, "protocols": ["tcp"], "payload_regex": [r"%0d%0a(set-cookie|location):"]},
        "action": {"tag": "crlf-injection", "label": "CRLF injection attempt", "severity": "medium"},
    },
    {
        "id": "builtin-ldap-injection",
        "name": "LDAP injection pattern",
        "description": "LDAP search-filter injection pattern (wildcard/always-true filter) seen in request traffic.",
        "enabled": True,
        "priority": 244,
        "source": "builtin",
        "mode": "regex",
        "match": {"request_only": True, "protocols": ["tcp"], "payload_regex": [r"\(\s*\|\s*\(.*=\*\)\)|\(\s*&\s*\(.*=\*\)\)"]},
        "action": {"tag": "ldap-injection", "label": "LDAP injection attempt", "severity": "high"},
    },
    {
        "id": "builtin-struts2-ognl-injection",
        "name": "Struts2 OGNL injection attempt",
        "description": "OGNL expression invoking Runtime.exec via a Content-Type/parameter, the CVE-2017-5638-style Apache Struts2 exploitation signature.",
        "enabled": True,
        "priority": 245,
        "source": "builtin",
        "mode": "regex",
        "match": {"request_only": True, "protocols": ["tcp"], "payload_regex": [r"%\{.*getruntime\(\).*exec|ognl\.ognlcontext"]},
        "action": {"tag": "struts2-ognl-injection", "label": "Struts2 OGNL injection attempt", "severity": "critical"},
    },
    {
        "id": "builtin-spring4shell-attempt",
        "name": "Spring4Shell exploitation attempt",
        "description": "class.module.classLoader parameter-pollution pattern seen in request traffic — the Spring4Shell (CVE-2022-22965) exploitation signature.",
        "enabled": True,
        "priority": 246,
        "source": "builtin",
        "mode": "regex",
        "match": {"request_only": True, "protocols": ["tcp"], "payload_regex": [r"class\.module\.classloader"]},
        "action": {"tag": "spring4shell-attempt", "label": "Spring4Shell attempt", "severity": "critical"},
    },
    # --- Policy violations ---
    {
        "id": "builtin-p2p-bittorrent",
        "name": "BitTorrent / P2P traffic",
        "description": "BitTorrent peer-wire protocol handshake seen in traffic.",
        "enabled": True,
        "priority": 240,
        "source": "builtin",
        "mode": "rule",
        "match": {"payload_contains": ["BitTorrent protocol"]},
        "action": {"tag": "p2p-bittorrent", "label": "BitTorrent traffic", "severity": "low"},
    },
    {
        "id": "builtin-crypto-mining",
        "name": "Cryptocurrency mining (Stratum)",
        "description": "Stratum mining-pool protocol messages seen in traffic — cryptojacking/unauthorized mining signal.",
        "enabled": True,
        "priority": 241,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ["tcp"], "payload_contains": ["mining.subscribe", "mining.notify", "mining.authorize"]},
        "action": {"tag": "crypto-mining", "label": "Cryptomining traffic", "severity": "high"},
    },
    {
        "id": "builtin-suspicious-user-agent",
        "name": "Known scanner/attack-tool user agent",
        "description": "HTTP User-Agent header matching a well-known scanning/exploitation tool (sqlmap, Nikto, Nmap, masscan, etc.).",
        "enabled": True,
        "priority": 242,
        "source": "builtin",
        "mode": "regex",
        "match": {
            "request_only": True,
            "protocols": ["tcp"],
            "payload_regex": [
                r"user-agent:\s*[^\r\n]*(sqlmap|nikto|nmap|masscan|zgrab|metasploit|dirbuster|gobuster|wpscan"
                r"|whatweb|acunetix|nessus|openvas|qualys|burpsuite|hydra|nuclei|ffuf|feroxbuster)"
            ]
        },
        "action": {"tag": "suspicious-user-agent", "label": "Scanner tool user agent", "severity": "high"},
    },
    # --- Malware / C2 / botnet activity ---
    {
        "id": "builtin-eicar-test-string",
        "name": "EICAR antivirus test string",
        "description": "The standardized EICAR test file signature — not real malware, but its presence in traffic confirms AV/content-inspection is (or isn't) actually scanning the stream.",
        "enabled": True,
        "priority": 250,
        "source": "builtin",
        "mode": "rule",
        "match": {"payload_contains": ["X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR"]},
        "action": {"tag": "eicar-test-string", "label": "EICAR test string", "severity": "info"},
    },
    {
        "id": "builtin-iot-default-credentials",
        "name": "IoT/Telnet default credential attempt",
        "description": "Common factory-default username:password pair (admin/admin, root/12345, etc.) attempted over Telnet — the classic Mirai-family IoT botnet infection signature.",
        "enabled": True,
        "priority": 251,
        "source": "builtin",
        "mode": "regex",
        "match": {
            "protocols": ["tcp"],
            "ports": [23],
            "payload_regex": [r"\b(admin|root|support|user|guest|default):(admin|root|12345|123456|password|default|guest|1234|toor)\b"],
        },
        "action": {"tag": "iot-default-credentials", "label": "IoT default credential attempt", "severity": "critical"},
    },
    {
        "id": "builtin-ransomware-note-language",
        "name": "Ransomware note language",
        "description": "Phrasing characteristic of a ransomware ransom note (files encrypted + payment demand) seen in cleartext traffic.",
        "enabled": True,
        "priority": 252,
        "source": "builtin",
        "mode": "regex",
        "match": {
            "payload_regex": [
                r"your (files|documents|data)\s+(have been|were|has been)\s+encrypted",
                r"decrypt.{0,30}(bitcoin|btc|monero|xmr)",
            ]
        },
        "action": {"tag": "ransomware-note-language", "label": "Ransomware note language", "severity": "critical"},
    },
    {
        "id": "builtin-crypto-mining-pool-domain",
        "name": "Cryptomining pool domain reference",
        "description": "DNS/HTTP traffic referencing a well-known public cryptocurrency mining pool — unauthorized/cryptojacking signal distinct from the raw Stratum protocol check.",
        "enabled": True,
        "priority": 253,
        "source": "builtin",
        "mode": "regex",
        "match": {"payload_regex": [r"\b[a-z0-9.-]*(minexmr|nanopool|ethermine|f2pool|antpool|2miners|supportxmr)\.[a-z]{2,}\b"]},
        "action": {"tag": "crypto-mining-pool-domain", "label": "Cryptomining pool domain", "severity": "medium"},
    },
    # --- Phishing ---
    {
        "id": "builtin-phishing-urgency-language",
        "name": "Phishing urgency/credential-harvest language",
        "description": "Account-verification urgency phrasing (verify/confirm/suspended + immediately/24 hours) commonly used in phishing lures.",
        "enabled": True,
        "priority": 260,
        "source": "builtin",
        "mode": "regex",
        "match": {
            "payload_regex": [
                r"\b(verify|confirm|re-?validate)\b[^.]{0,25}\b(your\s+)?(account|password|identity)\b[^.]{0,25}\b(immediately|urgent(ly)?|24\s*hours|suspend(ed)?)\b"
            ]
        },
        "action": {"tag": "phishing-urgency-language", "label": "Phishing urgency language", "severity": "medium"},
    },
    {
        "id": "builtin-punycode-domain",
        "name": "Punycode/IDN homograph domain",
        "description": "xn-- (punycode) encoded domain label — a common technique for homograph/lookalike-domain phishing.",
        "enabled": False,
        "priority": 261,
        "source": "builtin",
        "mode": "regex",
        "match": {"payload_regex": [r"\bxn--[a-z0-9-]+\b"]},
        "action": {"tag": "punycode-domain", "label": "Punycode/IDN domain", "severity": "low"},
    },
    # --- Reconnaissance (stateful) ---
    {
        "id": "builtin-port-scan",
        "name": "Port scan / reconnaissance",
        "description": "Stateful: flags a source touching many distinct destination ports within a short window.",
        "enabled": True,
        "priority": 5,
        "source": "builtin",
        "mode": "stateful",
        "match": {"protocols": ["tcp", "udp"]},
        "action": {"tag": "port-scan", "label": "Port scan detected", "severity": "high"},
    },
    # --- Restricted / acceptable-use content categories ---
    # Distinct from the security-threat categories above: these flag access
    # to content categories commonly restricted by acceptable-use policy
    # (parental controls, corporate DLP/compliance, honeypot/threat-intel
    # analysis of what an attacker or a monitored host is reaching for) —
    # tagged "policy-*" rather than a security severity class. Detection is
    # deliberately shape/keyword/label-based only (the same technique real
    # DNS/URL content filters use), never content generation: no explicit,
    # graphic, or instructional material is included or produced here.
    {
        "id": "builtin-policy-adult-content-label",
        "name": "Adult-content self-label (RTA) detected",
        "description": "The industry-standard RTA (\"Restricted To Adults\", ICRA/ASACP) self-rating label, which adult sites are expected to publish specifically so content filters can detect them.",
        "enabled": False,
        "priority": 300,
        "source": "builtin",
        "mode": "regex",
        "match": {"payload_regex": [r"rta-5042-1996-1400-1577-rta"]},
        "action": {"tag": "policy-adult-content", "label": "Adult content (RTA label)", "severity": "medium"},
    },
    {
        "id": "builtin-policy-adult-content-domain",
        "name": "Adult-content domain heuristic",
        "description": "Hostname containing a common adult-industry keyword (heuristic domain-shape match, the same technique DNS/URL content filters use — not a curated site list).",
        "enabled": False,
        "priority": 301,
        "source": "builtin",
        "mode": "regex",
        "match": {"payload_regex": [r"\b[a-z0-9-]*(porn|xxx|nsfw)[a-z0-9-]*\.(com|net|org|xxx|tv|cam|to|io)\b"]},
        "action": {"tag": "policy-adult-content", "label": "Adult content (domain heuristic)", "severity": "low"},
    },
    {
        "id": "builtin-policy-weapons-marketplace",
        "name": "Weapons marketplace language",
        "description": "Commerce-context language for firearms/ammunition/suppressors (buy/sell/ship + weapon term) seen in cleartext traffic — a policy/compliance signal, not a technical exploitation risk.",
        "enabled": False,
        "priority": 302,
        "source": "builtin",
        "mode": "regex",
        "match": {
            "payload_regex": [
                r"\b(buy|sell|selling|ship(ping)?)\b[^.\r\n]{0,25}\b(firearms?|handguns?|pistols?|rifles?|shotguns?|ammunition|ammo|silencers?|suppressors?)\b",
                r"\b(guns?|firearms?|weapons?)\s+for\s+sale\b",
            ]
        },
        "action": {"tag": "policy-weapons-content", "label": "Weapons marketplace language", "severity": "high"},
    },
    {
        "id": "builtin-policy-drugs-marketplace",
        "name": "Illegal drug marketplace language",
        "description": "Commerce-context language for controlled substances (drug name + sale/quantity/pricing term) seen in cleartext traffic — commonly seen in darknet-market traffic.",
        "enabled": False,
        "priority": 303,
        "source": "builtin",
        "mode": "regex",
        "match": {
            "payload_regex": [
                r"\b(cocaine|heroin|fentanyl|methamphetamine|crystal meth|mdma|ecstasy|lsd)\b[^.\r\n]{0,25}\b(for sale|kilo|kg|gram|grams|ounce|price|shipping|stealth)\b",
                r"\bdark ?net market\b",
            ]
        },
        "action": {"tag": "policy-drugs-content", "label": "Drug marketplace language", "severity": "high"},
    },
    {
        "id": "builtin-policy-fraud-carding",
        "name": "Stolen payment data marketplace language",
        "description": "Carding-forum jargon (CVV/fullz/dumps + sale/pricing term) seen in cleartext traffic — stolen-payment-data marketplace signal.",
        "enabled": False,
        "priority": 304,
        "source": "builtin",
        "mode": "regex",
        "match": {
            "payload_regex": [
                r"\b(cvv2?|fullz|dumps\+pin|dumps)\b[^.\r\n]{0,20}\b(for sale|price|\$\d)\b",
                r"\bcarding\b[^.\r\n]{0,15}\b(forum|tutorial|method)\b",
            ]
        },
        "action": {"tag": "policy-fraud-content", "label": "Stolen payment data marketplace", "severity": "high"},
    },
    {
        "id": "builtin-policy-unlicensed-gambling",
        "name": "Unlicensed gambling marketplace language",
        "description": "Offshore/unlicensed online-gambling promotional language (casino/sportsbook + deposit-bonus/no-verification term) seen in cleartext traffic.",
        "enabled": False,
        "priority": 305,
        "source": "builtin",
        "mode": "regex",
        "match": {
            "payload_regex": [
                r"\b(casino|sportsbook|online poker)\b[^.\r\n]{0,20}\b(deposit bonus|no.?verification|no.?kyc)\b"
            ]
        },
        "action": {"tag": "policy-gambling-content", "label": "Unlicensed gambling language", "severity": "low"},
    },
    # --- Header-field signatures ------------------------------------------
    # Everything below matches on decoded header fields (TCP flag sets, ICMP
    # types, ARP opcodes, ports) rather than payload text, so it works on the
    # traffic that carries no readable payload at all - which is exactly the
    # traffic a scan, a discovery protocol or an industrial bus produces.
    {
        "id": "builtin-tcp-scan-null",
        "name": "TCP NULL scan",
        "description": "A TCP segment with no flags set at all - nmap -sN. No legitimate stack emits one.",
        "enabled": True,
        "priority": 7,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp'], "tcp_flags": ['NONE']},
        "action": {"tag": "scan-null", "label": "TCP NULL scan", "severity": "critical"},
    },
    {
        "id": "builtin-tcp-scan-xmas",
        "name": "TCP Xmas scan",
        "description": "FIN+PSH+URG set together - nmap -sX. Lights up the segment 'like a Christmas tree'.",
        "enabled": True,
        "priority": 7,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp'], "tcp_flags": ['FIN,PSH,URG']},
        "action": {"tag": "scan-xmas", "label": "TCP Xmas scan", "severity": "critical"},
    },
    {
        "id": "builtin-tcp-scan-fin",
        "name": "TCP FIN scan",
        "description": "A bare FIN with no established session - nmap -sF, probing closed ports without a handshake.",
        "enabled": True,
        "priority": 7,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp'], "tcp_flags": ['FIN']},
        "action": {"tag": "scan-fin", "label": "TCP FIN scan", "severity": "high"},
    },
    {
        "id": "builtin-tcp-scan-maimon",
        "name": "TCP Maimon scan",
        "description": "FIN+ACK probe (nmap -sM), exploiting BSD-derived stacks that drop it on open ports.",
        "enabled": True,
        "priority": 7,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp'], "tcp_flags": ['FIN,ACK']},
        "action": {"tag": "scan-maimon", "label": "TCP Maimon scan", "severity": "high"},
    },
    {
        "id": "builtin-tcp-scan-synfin",
        "name": "TCP SYN/FIN scan",
        "description": "SYN and FIN set at once - a contradictory combination used to slip past stateless filters.",
        "enabled": True,
        "priority": 7,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp'], "tcp_flags": ['FIN,SYN']},
        "action": {"tag": "scan-synfin", "label": "TCP SYN/FIN scan", "severity": "critical"},
    },
    {
        "id": "builtin-tcp-scan-urg",
        "name": "TCP URG-only probe",
        "description": "URG alone, with no ACK - a malformed probe used for OS fingerprinting.",
        "enabled": True,
        "priority": 7,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp'], "tcp_flags": ['URG']},
        "action": {"tag": "scan-urg", "label": "TCP URG-only probe", "severity": "high"},
    },
    {
        "id": "builtin-tcp-scan-all",
        "name": "TCP all-flags scan",
        "description": "Every flag bit set - a deliberately malformed fingerprinting probe.",
        "enabled": True,
        "priority": 7,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp'], "tcp_flags": ['CWR,ECE,URG,ACK,PSH,RST,SYN,FIN']},
        "action": {"tag": "scan-all", "label": "TCP all-flags scan", "severity": "critical"},
    },
    {
        "id": "builtin-tcp-rst-sweep",
        "name": "TCP RST/ACK sweep",
        "description": (
            "20+ RST+ACK responses from the same source within 10s - individually normal (any "
            "rejected connection produces one), but a burst of them from one host is the reply "
            "pattern a port scan leaves behind on closed ports. Counted rather than fired on the "
            "first packet, since a single RST+ACK carries no signal at all."
        ),
        "enabled": True,
        "priority": 90,
        "source": "builtin",
        "mode": "stateful",
        "match": {
            "protocols": ['tcp'],
            "tcp_flags": ['RST,ACK'],
            "count_threshold": 20,
            "window_seconds": 10,
            "group_by": "src_ip",
        },
        "action": {"tag": "tcp-reset-sweep", "label": "TCP RST/ACK sweep", "severity": "medium"},
    },
    {
        "id": "builtin-icmp-redirect",
        "name": "ICMP redirect",
        "description": "An ICMP redirect rewrites a host's routing table - a classic MITM primitive and almost never legitimate on a modern LAN.",
        "enabled": True,
        "priority": 58,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['icmp', 'icmpv6'], "icmp_types": [5]},
        "action": {"tag": "icmp-redirect", "label": "ICMP redirect", "severity": "high"},
    },
    {
        "id": "builtin-icmp-timestamp",
        "name": "ICMP timestamp request",
        "description": "Timestamp probes are used to fingerprint the host clock and OS, and to bypass ping-based filters.",
        "enabled": False,
        "priority": 58,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['icmp', 'icmpv6'], "icmp_types": [13]},
        "action": {"tag": "icmp-timestamp", "label": "ICMP timestamp request", "severity": "medium"},
    },
    {
        "id": "builtin-icmp-addr-mask",
        "name": "ICMP address mask request",
        "description": "Address-mask probes map subnet layout during reconnaissance.",
        "enabled": False,
        "priority": 58,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['icmp', 'icmpv6'], "icmp_types": [17]},
        "action": {"tag": "icmp-addr-mask", "label": "ICMP address mask request", "severity": "medium"},
    },
    {
        "id": "builtin-icmp-info-request",
        "name": "ICMP information request",
        "description": "An obsolete (RFC 792) request type; its presence is a scanner, not a real host.",
        "enabled": False,
        "priority": 58,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['icmp', 'icmpv6'], "icmp_types": [15]},
        "action": {"tag": "icmp-info-request", "label": "ICMP information request", "severity": "medium"},
    },
    {
        "id": "builtin-icmp-router-advert",
        "name": "ICMP router advertisement",
        "description": "Rogue router advertisements redirect a whole segment's default gateway.",
        "enabled": False,
        "priority": 58,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['icmp', 'icmpv6'], "icmp_types": [9]},
        "action": {"tag": "icmp-router-advert", "label": "ICMP router advertisement", "severity": "high"},
    },
    {
        "id": "builtin-icmp-unreachable",
        "name": "ICMP destination unreachable",
        "description": "Unreachable messages, including the admin-prohibited replies a firewall emits under scan.",
        "enabled": False,
        "priority": 58,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['icmp', 'icmpv6'], "icmp_types": [3]},
        "action": {"tag": "icmp-unreachable", "label": "ICMP destination unreachable", "severity": "info"},
    },
    {
        "id": "builtin-arp-gratuitous",
        "name": "Gratuitous ARP",
        "description": "An unsolicited ARP reply. Legitimate during failover, but also how an attacker poisons neighbours' caches - the stateful builtin-arp-spoof monitor tracks whether the binding actually changed.",
        "enabled": False,
        "priority": 62,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['arp'], "arp_opcodes": [2]},
        "action": {"tag": "arp-gratuitous", "label": "Gratuitous ARP", "severity": "info"},
    },
    {
        "id": "builtin-rarp",
        "name": "RARP request",
        "description": "Reverse ARP (opcode 3/4) - obsolete since BOOTP, so present-day RARP is either ancient equipment or someone probing for it.",
        "enabled": False,
        "priority": 62,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['arp', 'rarp'], "arp_opcodes": [3, 4]},
        "action": {"tag": "rarp", "label": "RARP", "severity": "low"},
    },
    {
        "id": "builtin-mdns",
        "name": "mDNS (Bonjour)",
        "description": "Multicast DNS service discovery - maps every advertised host and service on the segment.",
        "enabled": False,
        "priority": 120,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['udp', 'mdns'], "ports": [5353]},
        "action": {"tag": "mdns", "label": "mDNS (Bonjour)", "severity": "info"},
    },
    {
        "id": "builtin-llmnr",
        "name": "LLMNR",
        "description": "Link-Local Multicast Name Resolution - the protocol Responder abuses to harvest NTLM hashes.",
        "enabled": False,
        "priority": 120,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['udp', 'tcp', 'llmnr'], "ports": [5355]},
        "action": {"tag": "llmnr", "label": "LLMNR", "severity": "medium"},
    },
    {
        "id": "builtin-nbns",
        "name": "NetBIOS name service",
        "description": "NetBIOS name resolution - legacy Windows discovery, and the other half of an LLMNR/NBT-NS poisoning attack.",
        "enabled": False,
        "priority": 120,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['udp', 'nbns'], "ports": [137]},
        "action": {"tag": "nbns", "label": "NetBIOS name service", "severity": "medium"},
    },
    {
        "id": "builtin-nbds",
        "name": "NetBIOS datagram",
        "description": "NetBIOS datagram service - legacy Windows browse-list traffic.",
        "enabled": False,
        "priority": 120,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['udp'], "ports": [138]},
        "action": {"tag": "nbds", "label": "NetBIOS datagram", "severity": "info"},
    },
    {
        "id": "builtin-ssdp",
        "name": "SSDP / UPnP",
        "description": "UPnP discovery - enumerates IoT devices and is a well-known reflection/amplification vector.",
        "enabled": False,
        "priority": 120,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['udp'], "ports": [1900]},
        "action": {"tag": "ssdp", "label": "SSDP / UPnP", "severity": "medium"},
    },
    {
        "id": "builtin-wsd",
        "name": "WS-Discovery",
        "description": "Web Services Discovery - printer/camera enumeration and a high-factor amplification vector.",
        "enabled": False,
        "priority": 120,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['udp'], "ports": [3702]},
        "action": {"tag": "wsd", "label": "WS-Discovery", "severity": "medium"},
    },
    {
        "id": "builtin-lldp",
        "name": "LLDP",
        "description": "Link Layer Discovery Protocol - switches advertising port, VLAN and chassis details.",
        "enabled": False,
        "priority": 120,
        "source": "builtin",
        "mode": "rule",
        "match": {"eth_types": [35020]},
        "action": {"tag": "lldp", "label": "LLDP", "severity": "info"},
    },
    {
        "id": "builtin-cdp",
        "name": "CDP",
        "description": "Cisco Discovery Protocol - leaks device model, IOS version, VLAN and management address.",
        "enabled": False,
        "priority": 120,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['cdp']},
        "action": {"tag": "cdp", "label": "CDP", "severity": "info"},
    },
    {
        "id": "builtin-ldap",
        "name": "LDAP (cleartext)",
        "description": "Unencrypted LDAP - directory queries and simple binds carry credentials in the clear.",
        "enabled": False,
        "priority": 100,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp', 'udp'], "ports": [389, 3268]},
        "action": {"tag": "ldap", "label": "LDAP (cleartext)", "severity": "high"},
    },
    {
        "id": "builtin-ldaps",
        "name": "LDAPS",
        "description": "LDAP over TLS.",
        "enabled": False,
        "priority": 100,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp'], "ports": [636, 3269]},
        "action": {"tag": "ldaps", "label": "LDAPS", "severity": "info"},
    },
    {
        "id": "builtin-kerberos",
        "name": "Kerberos",
        "description": "Kerberos authentication - AS-REQ/TGS traffic is the target of AS-REP roasting and Kerberoasting.",
        "enabled": False,
        "priority": 100,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp', 'udp'], "ports": [88, 464]},
        "action": {"tag": "kerberos", "label": "Kerberos", "severity": "medium"},
    },
    {
        "id": "builtin-tacacs",
        "name": "TACACS+",
        "description": "TACACS+ device administration - the credentials protecting the network gear itself.",
        "enabled": False,
        "priority": 100,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp'], "ports": [49]},
        "action": {"tag": "tacacs", "label": "TACACS+", "severity": "high"},
    },
    {
        "id": "builtin-msrpc",
        "name": "MSRPC endpoint mapper",
        "description": "Windows RPC endpoint mapper - the entry point for lateral movement and countless RCEs.",
        "enabled": False,
        "priority": 100,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp', 'udp'], "ports": [135]},
        "action": {"tag": "msrpc", "label": "MSRPC endpoint mapper", "severity": "high"},
    },
    {
        "id": "builtin-winrm",
        "name": "WinRM",
        "description": "Windows Remote Management - remote PowerShell, a primary lateral-movement channel.",
        "enabled": False,
        "priority": 100,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp'], "ports": [5985, 5986]},
        "action": {"tag": "winrm", "label": "WinRM", "severity": "high"},
    },
    {
        "id": "builtin-rlogin",
        "name": "rlogin / rsh / rexec",
        "description": "Berkeley r-services - no encryption and trust-based authentication. Any use is a finding.",
        "enabled": True,
        "priority": 100,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp'], "ports": [512, 513, 514]},
        "action": {"tag": "rlogin", "label": "rlogin / rsh / rexec", "severity": "critical"},
    },
    {
        "id": "builtin-x11",
        "name": "X11 forwarding",
        "description": "Unauthenticated X11 exposes the whole display: keystrokes and screen contents.",
        "enabled": False,
        "priority": 100,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp'], "ports": [6000, 6001, 6002, 6003, 6004, 6005]},
        "action": {"tag": "x11", "label": "X11 forwarding", "severity": "high"},
    },
    {
        "id": "builtin-svc-mysql",
        "name": "MySQL / MariaDB traffic",
        "description": "MySQL / MariaDB on 3306/33060. Database and infrastructure services are rarely meant to be reachable across a monitored segment.",
        "enabled": False,
        "priority": 130,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp'], "ports": [3306, 33060]},
        "action": {"tag": "svc-mysql", "label": "MySQL / MariaDB", "severity": "high"},
    },
    {
        "id": "builtin-svc-postgres",
        "name": "PostgreSQL traffic",
        "description": "PostgreSQL on 5432. Database and infrastructure services are rarely meant to be reachable across a monitored segment.",
        "enabled": False,
        "priority": 130,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp'], "ports": [5432]},
        "action": {"tag": "svc-postgres", "label": "PostgreSQL", "severity": "high"},
    },
    {
        "id": "builtin-svc-mssql",
        "name": "Microsoft SQL Server traffic",
        "description": "Microsoft SQL Server on 1433/1434. Database and infrastructure services are rarely meant to be reachable across a monitored segment.",
        "enabled": False,
        "priority": 130,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp'], "ports": [1433, 1434]},
        "action": {"tag": "svc-mssql", "label": "Microsoft SQL Server", "severity": "high"},
    },
    {
        "id": "builtin-svc-oracle",
        "name": "Oracle TNS traffic",
        "description": "Oracle TNS on 1521/1526/1830. Database and infrastructure services are rarely meant to be reachable across a monitored segment.",
        "enabled": False,
        "priority": 130,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp'], "ports": [1521, 1526, 1830]},
        "action": {"tag": "svc-oracle", "label": "Oracle TNS", "severity": "high"},
    },
    {
        "id": "builtin-svc-mongodb",
        "name": "MongoDB traffic",
        "description": "MongoDB on 27017/27018/27019. Database and infrastructure services are rarely meant to be reachable across a monitored segment.",
        "enabled": False,
        "priority": 130,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp'], "ports": [27017, 27018, 27019]},
        "action": {"tag": "svc-mongodb", "label": "MongoDB", "severity": "high"},
    },
    {
        "id": "builtin-svc-redis",
        "name": "Redis traffic",
        "description": "Redis on 6379/6380. Database and infrastructure services are rarely meant to be reachable across a monitored segment.",
        "enabled": False,
        "priority": 130,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp'], "ports": [6379, 6380]},
        "action": {"tag": "svc-redis", "label": "Redis", "severity": "high"},
    },
    {
        "id": "builtin-svc-memcached",
        "name": "Memcached traffic",
        "description": "Memcached on 11211. Database and infrastructure services are rarely meant to be reachable across a monitored segment.",
        "enabled": False,
        "priority": 130,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp'], "ports": [11211]},
        "action": {"tag": "svc-memcached", "label": "Memcached", "severity": "high"},
    },
    {
        "id": "builtin-svc-elastic",
        "name": "Elasticsearch traffic",
        "description": "Elasticsearch on 9200/9300. Database and infrastructure services are rarely meant to be reachable across a monitored segment.",
        "enabled": False,
        "priority": 130,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp'], "ports": [9200, 9300]},
        "action": {"tag": "svc-elastic", "label": "Elasticsearch", "severity": "high"},
    },
    {
        "id": "builtin-svc-cassandra",
        "name": "Cassandra traffic",
        "description": "Cassandra on 9042/9160. Database and infrastructure services are rarely meant to be reachable across a monitored segment.",
        "enabled": False,
        "priority": 130,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp'], "ports": [9042, 9160]},
        "action": {"tag": "svc-cassandra", "label": "Cassandra", "severity": "medium"},
    },
    {
        "id": "builtin-svc-couchdb",
        "name": "CouchDB traffic",
        "description": "CouchDB on 5984/6984. Database and infrastructure services are rarely meant to be reachable across a monitored segment.",
        "enabled": False,
        "priority": 130,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp'], "ports": [5984, 6984]},
        "action": {"tag": "svc-couchdb", "label": "CouchDB", "severity": "medium"},
    },
    {
        "id": "builtin-svc-influxdb",
        "name": "InfluxDB traffic",
        "description": "InfluxDB on 8086. Database and infrastructure services are rarely meant to be reachable across a monitored segment.",
        "enabled": False,
        "priority": 130,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp'], "ports": [8086]},
        "action": {"tag": "svc-influxdb", "label": "InfluxDB", "severity": "medium"},
    },
    {
        "id": "builtin-svc-neo4j",
        "name": "Neo4j / Bolt traffic",
        "description": "Neo4j / Bolt on 7687/7474. Database and infrastructure services are rarely meant to be reachable across a monitored segment.",
        "enabled": False,
        "priority": 130,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp'], "ports": [7687, 7474]},
        "action": {"tag": "svc-neo4j", "label": "Neo4j / Bolt", "severity": "medium"},
    },
    {
        "id": "builtin-svc-clickhouse",
        "name": "ClickHouse traffic",
        "description": "ClickHouse on 8123/9000. Database and infrastructure services are rarely meant to be reachable across a monitored segment.",
        "enabled": False,
        "priority": 130,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp'], "ports": [8123]},
        "action": {"tag": "svc-clickhouse", "label": "ClickHouse", "severity": "medium"},
    },
    {
        "id": "builtin-svc-etcd",
        "name": "etcd traffic",
        "description": "etcd on 2379/2380. Database and infrastructure services are rarely meant to be reachable across a monitored segment.",
        "enabled": False,
        "priority": 130,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp'], "ports": [2379, 2380]},
        "action": {"tag": "svc-etcd", "label": "etcd", "severity": "high"},
    },
    {
        "id": "builtin-svc-zookeeper",
        "name": "ZooKeeper traffic",
        "description": "ZooKeeper on 2181/2888/3888. Database and infrastructure services are rarely meant to be reachable across a monitored segment.",
        "enabled": False,
        "priority": 130,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp'], "ports": [2181, 2888, 3888]},
        "action": {"tag": "svc-zookeeper", "label": "ZooKeeper", "severity": "medium"},
    },
    {
        "id": "builtin-svc-consul",
        "name": "Consul traffic",
        "description": "Consul on 8500/8600. Database and infrastructure services are rarely meant to be reachable across a monitored segment.",
        "enabled": False,
        "priority": 130,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp'], "ports": [8500, 8600]},
        "action": {"tag": "svc-consul", "label": "Consul", "severity": "medium"},
    },
    {
        "id": "builtin-svc-amqp",
        "name": "AMQP / RabbitMQ traffic",
        "description": "AMQP / RabbitMQ on 5672/5671/15672. Database and infrastructure services are rarely meant to be reachable across a monitored segment.",
        "enabled": False,
        "priority": 130,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp'], "ports": [5672, 5671, 15672]},
        "action": {"tag": "svc-amqp", "label": "AMQP / RabbitMQ", "severity": "medium"},
    },
    {
        "id": "builtin-svc-kafka",
        "name": "Kafka traffic",
        "description": "Kafka on 9092/9093. Database and infrastructure services are rarely meant to be reachable across a monitored segment.",
        "enabled": False,
        "priority": 130,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp'], "ports": [9092, 9093]},
        "action": {"tag": "svc-kafka", "label": "Kafka", "severity": "medium"},
    },
    {
        "id": "builtin-svc-nats",
        "name": "NATS traffic",
        "description": "NATS on 4222/6222/8222. Database and infrastructure services are rarely meant to be reachable across a monitored segment.",
        "enabled": False,
        "priority": 130,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp'], "ports": [4222, 6222, 8222]},
        "action": {"tag": "svc-nats", "label": "NATS", "severity": "medium"},
    },
    {
        "id": "builtin-svc-stomp",
        "name": "STOMP traffic",
        "description": "STOMP on 61613/61614. Database and infrastructure services are rarely meant to be reachable across a monitored segment.",
        "enabled": False,
        "priority": 130,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp'], "ports": [61613, 61614]},
        "action": {"tag": "svc-stomp", "label": "STOMP", "severity": "low"},
    },
    {
        "id": "builtin-svc-jmx-rmi",
        "name": "Java RMI / JMX traffic",
        "description": "Java RMI / JMX on 1099/1098/9999. Database and infrastructure services are rarely meant to be reachable across a monitored segment.",
        "enabled": True,
        "priority": 130,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp'], "ports": [1099, 1098]},
        "action": {"tag": "svc-jmx-rmi", "label": "Java RMI / JMX", "severity": "high"},
    },
    {
        "id": "builtin-svc-jdwp",
        "name": "Java debug wire protocol traffic",
        "description": "Java debug wire protocol on 5005/8000. Database and infrastructure services are rarely meant to be reachable across a monitored segment.",
        "enabled": True,
        "priority": 130,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp'], "ports": [5005]},
        "action": {"tag": "svc-jdwp", "label": "Java debug wire protocol", "severity": "critical"},
    },
    {
        "id": "builtin-svc-docker-api",
        "name": "Docker remote API traffic",
        "description": "Docker remote API on 2375/2376. Database and infrastructure services are rarely meant to be reachable across a monitored segment.",
        "enabled": True,
        "priority": 130,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp'], "ports": [2375, 2376]},
        "action": {"tag": "svc-docker-api", "label": "Docker remote API", "severity": "critical"},
    },
    {
        "id": "builtin-svc-kubelet",
        "name": "Kubernetes kubelet / API traffic",
        "description": "Kubernetes kubelet / API on 6443/10250/10255. Database and infrastructure services are rarely meant to be reachable across a monitored segment.",
        "enabled": True,
        "priority": 130,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp'], "ports": [6443, 10250, 10255]},
        "action": {"tag": "svc-kubelet", "label": "Kubernetes kubelet / API", "severity": "critical"},
    },
    {
        "id": "builtin-ics-s7comm",
        "name": "Siemens S7comm traffic",
        "description": "Siemens S7comm industrial-control traffic. Unauthenticated by design - any appearance on a monitored segment matters.",
        "enabled": False,
        "priority": 45,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp'], "ports": [102]},
        "action": {"tag": "ics-s7comm", "label": "Siemens S7comm", "severity": "critical"},
    },
    {
        "id": "builtin-ics-bacnet",
        "name": "BACnet traffic",
        "description": "BACnet industrial-control traffic. Unauthenticated by design - any appearance on a monitored segment matters.",
        "enabled": False,
        "priority": 45,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['udp'], "ports": [47808, 47809]},
        "action": {"tag": "ics-bacnet", "label": "BACnet", "severity": "high"},
    },
    {
        "id": "builtin-ics-iec104",
        "name": "IEC 60870-5-104 traffic",
        "description": "IEC 60870-5-104 industrial-control traffic. Unauthenticated by design - any appearance on a monitored segment matters.",
        "enabled": False,
        "priority": 45,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp'], "ports": [2404]},
        "action": {"tag": "ics-iec104", "label": "IEC 60870-5-104", "severity": "critical"},
    },
    {
        "id": "builtin-ics-opcua",
        "name": "OPC UA traffic",
        "description": "OPC UA industrial-control traffic. Unauthenticated by design - any appearance on a monitored segment matters.",
        "enabled": False,
        "priority": 45,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp'], "ports": [4840, 4843]},
        "action": {"tag": "ics-opcua", "label": "OPC UA", "severity": "high"},
    },
    {
        "id": "builtin-ics-ethernetip",
        "name": "EtherNet/IP traffic",
        "description": "EtherNet/IP industrial-control traffic. Unauthenticated by design - any appearance on a monitored segment matters.",
        "enabled": False,
        "priority": 45,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp', 'udp'], "ports": [44818, 2222]},
        "action": {"tag": "ics-ethernetip", "label": "EtherNet/IP", "severity": "critical"},
    },
    {
        "id": "builtin-ics-profinet",
        "name": "PROFINET traffic",
        "description": "PROFINET industrial-control traffic. Unauthenticated by design - any appearance on a monitored segment matters.",
        "enabled": False,
        "priority": 45,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['udp'], "ports": [34962, 34963, 34964]},
        "action": {"tag": "ics-profinet", "label": "PROFINET", "severity": "high"},
    },
    {
        "id": "builtin-ics-fins",
        "name": "OMRON FINS traffic",
        "description": "OMRON FINS industrial-control traffic. Unauthenticated by design - any appearance on a monitored segment matters.",
        "enabled": False,
        "priority": 45,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp', 'udp'], "ports": [9600]},
        "action": {"tag": "ics-fins", "label": "OMRON FINS", "severity": "high"},
    },
    {
        "id": "builtin-ics-melsec",
        "name": "Mitsubishi MELSEC traffic",
        "description": "Mitsubishi MELSEC industrial-control traffic. Unauthenticated by design - any appearance on a monitored segment matters.",
        "enabled": False,
        "priority": 45,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp'], "ports": [5006, 5007]},
        "action": {"tag": "ics-melsec", "label": "Mitsubishi MELSEC", "severity": "high"},
    },
    {
        "id": "builtin-ics-crimson",
        "name": "Red Lion Crimson traffic",
        "description": "Red Lion Crimson industrial-control traffic. Unauthenticated by design - any appearance on a monitored segment matters.",
        "enabled": False,
        "priority": 45,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp'], "ports": [789]},
        "action": {"tag": "ics-crimson", "label": "Red Lion Crimson", "severity": "high"},
    },
    {
        "id": "builtin-ics-hart",
        "name": "HART-IP traffic",
        "description": "HART-IP industrial-control traffic. Unauthenticated by design - any appearance on a monitored segment matters.",
        "enabled": False,
        "priority": 45,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp', 'udp'], "ports": [5094]},
        "action": {"tag": "ics-hart", "label": "HART-IP", "severity": "high"},
    },
    {
        "id": "builtin-ics-codesys",
        "name": "CODESYS traffic",
        "description": "CODESYS industrial-control traffic. Unauthenticated by design - any appearance on a monitored segment matters.",
        "enabled": False,
        "priority": 45,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp'], "ports": [1200, 2455]},
        "action": {"tag": "ics-codesys", "label": "CODESYS", "severity": "high"},
    },
    {
        "id": "builtin-ics-pcworx",
        "name": "PC Worx traffic",
        "description": "PC Worx industrial-control traffic. Unauthenticated by design - any appearance on a monitored segment matters.",
        "enabled": False,
        "priority": 45,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp'], "ports": [1962]},
        "action": {"tag": "ics-pcworx", "label": "PC Worx", "severity": "high"},
    },
    {
        "id": "builtin-proto-echo",
        "name": "Echo (RFC 862)",
        "description": "Obsolete echo service - a classic amplification/loop vector.",
        "enabled": False,
        "priority": 140,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp', 'udp'], "ports": [7]},
        "action": {"tag": "proto-echo", "label": "Echo (RFC 862)", "severity": "medium"},
    },
    {
        "id": "builtin-proto-discard",
        "name": "Discard (RFC 863)",
        "description": "Obsolete discard service.",
        "enabled": False,
        "priority": 140,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp', 'udp'], "ports": [9]},
        "action": {"tag": "proto-discard", "label": "Discard (RFC 863)", "severity": "low"},
    },
    {
        "id": "builtin-proto-daytime",
        "name": "Daytime (RFC 867)",
        "description": "Obsolete daytime service - amplification vector.",
        "enabled": False,
        "priority": 140,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp', 'udp'], "ports": [13]},
        "action": {"tag": "proto-daytime", "label": "Daytime (RFC 867)", "severity": "medium"},
    },
    {
        "id": "builtin-proto-qotd",
        "name": "QOTD (RFC 865)",
        "description": "Quote of the day - an amplification vector still found on printers.",
        "enabled": False,
        "priority": 140,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp', 'udp'], "ports": [17]},
        "action": {"tag": "proto-qotd", "label": "QOTD (RFC 865)", "severity": "medium"},
    },
    {
        "id": "builtin-proto-chargen",
        "name": "CHARGEN (RFC 864)",
        "description": "Character generator - one of the highest-factor UDP amplification vectors in existence.",
        "enabled": False,
        "priority": 140,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp', 'udp'], "ports": [19]},
        "action": {"tag": "proto-chargen", "label": "CHARGEN (RFC 864)", "severity": "high"},
    },
    {
        "id": "builtin-proto-time",
        "name": "Time (RFC 868)",
        "description": "Obsolete time protocol.",
        "enabled": False,
        "priority": 140,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp', 'udp'], "ports": [37]},
        "action": {"tag": "proto-time", "label": "Time (RFC 868)", "severity": "low"},
    },
    {
        "id": "builtin-proto-whois",
        "name": "WHOIS",
        "description": "WHOIS lookups in cleartext.",
        "enabled": False,
        "priority": 140,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp'], "ports": [43]},
        "action": {"tag": "proto-whois", "label": "WHOIS", "severity": "info"},
    },
    {
        "id": "builtin-proto-gopher",
        "name": "Gopher",
        "description": "Gopher - long obsolete, and a favourite SSRF pivot protocol.",
        "enabled": False,
        "priority": 140,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp'], "ports": [70]},
        "action": {"tag": "proto-gopher", "label": "Gopher", "severity": "medium"},
    },
    {
        "id": "builtin-proto-finger",
        "name": "Finger",
        "description": "Finger enumerates local user accounts. Obsolete and information-leaking by design.",
        "enabled": False,
        "priority": 140,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp'], "ports": [79]},
        "action": {"tag": "proto-finger", "label": "Finger", "severity": "high"},
    },
    {
        "id": "builtin-proto-ident",
        "name": "Ident (auth)",
        "description": "Ident - leaks the local username owning a connection.",
        "enabled": False,
        "priority": 140,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp'], "ports": [113]},
        "action": {"tag": "proto-ident", "label": "Ident (auth)", "severity": "medium"},
    },
    {
        "id": "builtin-proto-nntp",
        "name": "NNTP",
        "description": "Usenet news transport.",
        "enabled": False,
        "priority": 140,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp'], "ports": [119, 563]},
        "action": {"tag": "proto-nntp", "label": "NNTP", "severity": "low"},
    },
    {
        "id": "builtin-proto-irc",
        "name": "IRC",
        "description": "IRC - still the control channel for a long tail of botnet families.",
        "enabled": False,
        "priority": 140,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp'], "ports": [6660, 6661, 6662, 6663, 6664, 6665, 6666, 6667, 6668, 6669, 6697]},
        "action": {"tag": "proto-irc", "label": "IRC", "severity": "high"},
    },
    {
        "id": "builtin-proto-rsync",
        "name": "rsync daemon",
        "description": "An rsync daemon, frequently exposed with no authentication and world-readable modules.",
        "enabled": False,
        "priority": 140,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp'], "ports": [873]},
        "action": {"tag": "proto-rsync", "label": "rsync daemon", "severity": "high"},
    },
    {
        "id": "builtin-proto-lpd",
        "name": "LPD printing",
        "description": "Line printer daemon.",
        "enabled": False,
        "priority": 140,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp'], "ports": [515]},
        "action": {"tag": "proto-lpd", "label": "LPD printing", "severity": "low"},
    },
    {
        "id": "builtin-proto-ipp",
        "name": "IPP / CUPS",
        "description": "Internet Printing Protocol.",
        "enabled": False,
        "priority": 140,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp', 'udp'], "ports": [631]},
        "action": {"tag": "proto-ipp", "label": "IPP / CUPS", "severity": "low"},
    },
    {
        "id": "builtin-proto-afp",
        "name": "Apple Filing Protocol",
        "description": "AFP file sharing.",
        "enabled": False,
        "priority": 140,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp'], "ports": [548]},
        "action": {"tag": "proto-afp", "label": "Apple Filing Protocol", "severity": "low"},
    },
    {
        "id": "builtin-proto-nfs",
        "name": "NFS",
        "description": "NFS and its portmapper - exports are commonly world-readable.",
        "enabled": False,
        "priority": 140,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp', 'udp'], "ports": [2049, 111]},
        "action": {"tag": "proto-nfs", "label": "NFS", "severity": "high"},
    },
    {
        "id": "builtin-proto-iscsi",
        "name": "iSCSI",
        "description": "iSCSI - raw block-device access over the network.",
        "enabled": False,
        "priority": 140,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp'], "ports": [3260]},
        "action": {"tag": "proto-iscsi", "label": "iSCSI", "severity": "high"},
    },
    {
        "id": "builtin-proto-ipmi",
        "name": "IPMI / BMC",
        "description": "IPMI out-of-band management - cipher-zero and hash-disclosure flaws make an exposed BMC a full host compromise.",
        "enabled": True,
        "priority": 140,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['udp'], "ports": [623]},
        "action": {"tag": "proto-ipmi", "label": "IPMI / BMC", "severity": "critical"},
    },
    {
        "id": "builtin-proto-bgp",
        "name": "BGP",
        "description": "Border Gateway Protocol sessions.",
        "enabled": False,
        "priority": 140,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp'], "ports": [179]},
        "action": {"tag": "proto-bgp", "label": "BGP", "severity": "medium"},
    },
    {
        "id": "builtin-proto-rip",
        "name": "RIP",
        "description": "RIP routing updates - unauthenticated route injection.",
        "enabled": False,
        "priority": 140,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['udp'], "ports": [520, 521]},
        "action": {"tag": "proto-rip", "label": "RIP", "severity": "medium"},
    },
    {
        "id": "builtin-proto-ldp",
        "name": "MPLS LDP",
        "description": "Label Distribution Protocol.",
        "enabled": False,
        "priority": 140,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp', 'udp'], "ports": [646]},
        "action": {"tag": "proto-ldp", "label": "MPLS LDP", "severity": "low"},
    },
    {
        "id": "builtin-proto-vrrp-port",
        "name": "VRRP/HSRP",
        "description": "Gateway redundancy protocols - a spoofed advertisement takes over the default gateway.",
        "enabled": False,
        "priority": 140,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['udp'], "ports": [1985, 3222]},
        "action": {"tag": "proto-vrrp-port", "label": "VRRP/HSRP", "severity": "high"},
    },
    {
        "id": "builtin-proto-coap",
        "name": "CoAP",
        "description": "Constrained Application Protocol - IoT, and an amplification vector.",
        "enabled": False,
        "priority": 140,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['udp'], "ports": [5683, 5684]},
        "action": {"tag": "proto-coap", "label": "CoAP", "severity": "medium"},
    },
    {
        "id": "builtin-proto-mqtt",
        "name": "MQTT (cleartext)",
        "description": "Unencrypted MQTT - IoT telemetry and commands in the clear.",
        "enabled": False,
        "priority": 140,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp', 'mqtt'], "ports": [1883]},
        "action": {"tag": "proto-mqtt", "label": "MQTT (cleartext)", "severity": "high"},
    },
    {
        "id": "builtin-proto-rtsp",
        "name": "RTSP",
        "description": "Camera/streaming control - default credentials are the norm.",
        "enabled": False,
        "priority": 140,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp', 'udp'], "ports": [554, 8554]},
        "action": {"tag": "proto-rtsp", "label": "RTSP", "severity": "medium"},
    },
    {
        "id": "builtin-proto-sip",
        "name": "SIP",
        "description": "SIP signalling - toll fraud and registration hijacking.",
        "enabled": False,
        "priority": 140,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp', 'udp'], "ports": [5060, 5061]},
        "action": {"tag": "proto-sip", "label": "SIP", "severity": "medium"},
    },
    {
        "id": "builtin-proto-h323",
        "name": "H.323",
        "description": "H.323 call setup.",
        "enabled": False,
        "priority": 140,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp'], "ports": [1720]},
        "action": {"tag": "proto-h323", "label": "H.323", "severity": "low"},
    },
    {
        "id": "builtin-proto-iax",
        "name": "IAX2",
        "description": "Asterisk inter-exchange protocol.",
        "enabled": False,
        "priority": 140,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['udp'], "ports": [4569]},
        "action": {"tag": "proto-iax", "label": "IAX2", "severity": "low"},
    },
    {
        "id": "builtin-proto-teredo",
        "name": "Teredo",
        "description": "Teredo IPv6 tunnelling - carries IPv6 straight through IPv4-only filtering.",
        "enabled": False,
        "priority": 140,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['udp'], "ports": [3544]},
        "action": {"tag": "proto-teredo", "label": "Teredo", "severity": "high"},
    },
    {
        "id": "builtin-proto-socks",
        "name": "SOCKS proxy",
        "description": "SOCKS proxy - pivoting and egress laundering.",
        "enabled": False,
        "priority": 140,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp'], "ports": [1080, 1081]},
        "action": {"tag": "proto-socks", "label": "SOCKS proxy", "severity": "high"},
    },
    {
        "id": "builtin-proto-openvpn",
        "name": "OpenVPN",
        "description": "OpenVPN tunnel.",
        "enabled": False,
        "priority": 140,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp', 'udp'], "ports": [1194]},
        "action": {"tag": "proto-openvpn", "label": "OpenVPN", "severity": "medium"},
    },
    {
        "id": "builtin-proto-wireguard",
        "name": "WireGuard",
        "description": "WireGuard tunnel.",
        "enabled": False,
        "priority": 140,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['udp'], "ports": [51820]},
        "action": {"tag": "proto-wireguard", "label": "WireGuard", "severity": "medium"},
    },
    {
        "id": "builtin-proto-ipsec",
        "name": "IPsec IKE / NAT-T",
        "description": "IKE negotiation and NAT traversal.",
        "enabled": False,
        "priority": 140,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['udp'], "ports": [500, 4500]},
        "action": {"tag": "proto-ipsec", "label": "IPsec IKE / NAT-T", "severity": "medium"},
    },
    {
        "id": "builtin-proto-l2tp",
        "name": "L2TP",
        "description": "L2TP tunnelling.",
        "enabled": False,
        "priority": 140,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['udp'], "ports": [1701]},
        "action": {"tag": "proto-l2tp", "label": "L2TP", "severity": "medium"},
    },
    {
        "id": "builtin-proto-pptp",
        "name": "PPTP",
        "description": "PPTP - cryptographically broken (MS-CHAPv2) and trivially decryptable.",
        "enabled": False,
        "priority": 140,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp'], "ports": [1723]},
        "action": {"tag": "proto-pptp", "label": "PPTP", "severity": "high"},
    },
    {
        "id": "builtin-proto-ntp",
        "name": "NTP",
        "description": "NTP - the monlist amplification vector, and a time-shift attack surface.",
        "enabled": False,
        "priority": 140,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['udp'], "ports": [123]},
        "action": {"tag": "proto-ntp", "label": "NTP", "severity": "info"},
    },
    {
        "id": "builtin-proto-snmp-trap",
        "name": "SNMP trap",
        "description": "SNMP traps.",
        "enabled": False,
        "priority": 140,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['udp', 'snmp'], "ports": [162]},
        "action": {"tag": "proto-snmp-trap", "label": "SNMP trap", "severity": "low"},
    },
    {
        "id": "builtin-proto-bittorrent-port",
        "name": "BitTorrent tracker/DHT",
        "description": "BitTorrent peer and DHT ports.",
        "enabled": False,
        "priority": 140,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp', 'udp'], "ports": [6881, 6882, 6883, 6889, 51413]},
        "action": {"tag": "proto-bittorrent-port", "label": "BitTorrent tracker/DHT", "severity": "medium"},
    },
    {
        "id": "builtin-proto-steam",
        "name": "Steam / game traffic",
        "description": "Game server traffic - also a UDP reflection vector.",
        "enabled": False,
        "priority": 140,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ['tcp', 'udp'], "ports": [27015, 27016, 27036]},
        "action": {"tag": "proto-steam", "label": "Steam / game traffic", "severity": "info"},
    },
    # Protocols the sniffer decodes into a proto of their own but that had no
    # monitor at all - IGMP alone accounted for the single largest slice of a
    # live capture while being entirely unclassified.
    {
        "id": "builtin-proto-igmp",
        "name": "IGMP",
        "description": "Multicast group membership. Normal on any segment with streaming or discovery, but IGMP queries also enumerate multicast listeners.",
        "enabled": False,
        "priority": 140,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ["igmp"]},
        "action": {"tag": "igmp", "label": "IGMP", "severity": "info"},
    },
    {
        "id": "builtin-proto-gre",
        "name": "GRE tunnel",
        "description": "Generic Routing Encapsulation - a tunnel carrying arbitrary traffic past segment boundaries.",
        "enabled": False,
        "priority": 130,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ["gre"]},
        "action": {"tag": "gre", "label": "GRE tunnel", "severity": "medium"},
    },
    {
        "id": "builtin-proto-esp",
        "name": "IPsec ESP",
        "description": "Encapsulating Security Payload - encrypted IPsec traffic; the payload is opaque to inspection by design.",
        "enabled": False,
        "priority": 130,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ["esp"]},
        "action": {"tag": "esp", "label": "IPsec ESP", "severity": "info"},
    },
    {
        "id": "builtin-proto-ah",
        "name": "IPsec AH",
        "description": "Authentication Header - integrity-protected IPsec traffic.",
        "enabled": False,
        "priority": 130,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ["ah"]},
        "action": {"tag": "ah", "label": "IPsec AH", "severity": "info"},
    },
    {
        "id": "builtin-proto-stp",
        "name": "STP / RSTP",
        "description": "Spanning Tree BPDUs. A BPDU with a superior bridge priority from an unexpected port is a topology takeover (STP root hijack).",
        "enabled": False,
        "priority": 140,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ["stp"]},
        "action": {"tag": "stp", "label": "STP", "severity": "low"},
    },
    {
        "id": "builtin-proto-llc",
        "name": "IEEE 802.2 LLC",
        "description": "Legacy LLC/SNAP frames - IPX, NetBIOS over LLC and other pre-Ethernet-II encapsulations.",
        "enabled": False,
        "priority": 145,
        "source": "builtin",
        "mode": "rule",
        "match": {"protocols": ["llc", "llc-snap"]},
        "action": {"tag": "llc", "label": "LLC", "severity": "info"},
    },
]


def _default_monitor_path() -> Path:
    return resolve_data_file("default_monitors.json")


def _is_noisy_generated_signal_monitor(monitor: dict) -> bool:
    monitor_id = str(monitor.get("id") or "")
    if not monitor_id.startswith("builtin-signal-"):
        return False
    match = monitor.get("match") if isinstance(monitor.get("match"), dict) else {}
    contains = [str(item).strip().lower() for item in match.get("payload_contains", []) if str(item).strip()]
    if not contains:
        return False
    if match.get("payload_regex") or match.get("payload_prefix_hex") or match.get("ips") or match.get("ip_regex"):
        return False
    return any(value in NOISY_GENERATED_SIGNAL_LITERALS for value in contains)


def _apply_builtin_monitor_quality_overrides(monitor: dict) -> dict:
    monitor_id = str(monitor.get("id") or "").strip()
    overrides = BUILTIN_MONITOR_QUALITY_OVERRIDES.get(monitor_id)
    if not overrides:
        return monitor
    action = monitor.get("action") if isinstance(monitor.get("action"), dict) else {}
    action = dict(action)
    if "severity" in overrides:
        action["severity"] = str(overrides["severity"]).strip().lower()
    monitor = dict(monitor)
    monitor["action"] = action
    return monitor


@functools.lru_cache(maxsize=1)
def _load_builtin_monitors_cached() -> tuple[dict, ...]:
    # The packaged default_monitors.json is read-only, installed data
    # that never changes for the life of a running process - parsing and
    # normalizing several thousand entries (a second-plus at this catalog's
    # size) on every single call, including SniffStore._seed_baseline()'s
    # own two calls per startup, is pure waste. Cached as a tuple (an
    # immutable sequence) so nothing can accidentally mutate the shared
    # result; load_builtin_monitors() below still hands back a fresh list.
    path = _default_monitor_path()
    catalog: list[dict] = []
    if path.exists():
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(payload, list):
                catalog = [
                    _apply_builtin_monitor_quality_overrides(
                        normalize_monitor(item, allow_source=True, validate_regex=False)
                    )
                    for item in payload
                    if isinstance(item, dict)
                ]
                catalog = [item for item in catalog if not _is_noisy_generated_signal_monitor(item)]
        except Exception:
            catalog = []
    if not catalog:
        return tuple(
            _apply_builtin_monitor_quality_overrides(normalize_monitor(item, allow_source=True))
            for item in DEFAULT_MONITORS
        )

    # The packaged catalog is generated and huge; DEFAULT_MONITORS is the
    # hand-written, actively-tuned set in this file. DEFAULT_MONITORS wins
    # for any id both define: it used to be the other way around (the file
    # "owns" every id it defines), which meant a fix made here to an id the
    # bulk catalog also happened to define - e.g. narrowing a noisy
    # false-positive-prone regex - was silently discarded the moment the
    # catalog was regenerated, with no error or warning. A hand-tuned rule
    # in this file is deliberate; the file's copy of the same id is, by
    # definition, whatever the bulk generation process produced for it -
    # so the hand-tuned one is the one that should stick.
    positions = {str(item.get("id") or ""): index for index, item in enumerate(catalog)}
    for item in DEFAULT_MONITORS:
        monitor_id = str(item.get("id") or "").strip()
        if not monitor_id:
            continue
        normalized = _apply_builtin_monitor_quality_overrides(normalize_monitor(item, allow_source=True))
        if monitor_id in positions:
            catalog[positions[monitor_id]] = normalized
        else:
            positions[monitor_id] = len(catalog)
            catalog.append(normalized)
    return tuple(catalog)


def load_builtin_monitors() -> list[dict]:
    """The bundled catalog, as rows the caller owns and may mutate.

    Deep-copying tens of thousands of entries is not free (see
    iter_builtin_monitors below), so prefer that when the rows are only read.
    """
    return [copy.deepcopy(item) for item in _load_builtin_monitors_cached()]


def iter_builtin_monitors() -> tuple[dict, ...]:
    """The bundled catalog itself, shared and **not** to be mutated.

    load_builtin_monitors() hands out a deep copy so a caller can edit its rows
    without corrupting the process-wide cache, and one test pins that. The cost
    of that guarantee is not small: the catalog is roughly thirty thousand
    monitors and twenty-odd megabytes once expanded, and copy.deepcopy walks
    every nested dict and list, which measured at ~0.6s per call. SniffStore
    calls it twice on construction, so every store paid over a second to build
    rows it only ever read fields off - and every test that builds a store paid
    it again.

    This returns the cached tuple directly for exactly those read-only callers.
    Mutating anything reached through it corrupts the catalog for the whole
    process; use load_builtin_monitors() if the rows need to be edited.
    """
    return _load_builtin_monitors_cached()


@functools.lru_cache(maxsize=1)
def builtin_monitor_seed_fields() -> tuple[tuple, ...]:
    """The catalog flattened into the columns the monitors table stores.

    Seeding serialises `match` and `action` to JSON for every builtin monitor,
    and the result is byte-identical on every call: the catalog is read-only,
    packaged data. Doing it per SniffStore meant ~1.2 million json.dumps calls
    across a test run - measured at a third of the wall clock of the slowest
    test class - to rebuild strings that never differ.

    `_seed_new_builtin_monitors` also compares these strings against the stored
    row to detect a changed definition, so both callers must serialise the same
    way; sharing one cached tuple is what guarantees that.
    """
    rows = []
    for monitor in _load_builtin_monitors_cached():
        monitor_id = str(monitor.get("id") or "").strip()
        if not monitor_id:
            continue
        rows.append(
            (
                monitor_id,
                str(monitor.get("name") or monitor_id),
                str(monitor.get("description") or ""),
                1 if monitor.get("enabled", True) else 0,
                safe_int(monitor.get("priority", 100), 100),
                str(monitor.get("source") or "builtin"),
                str(monitor.get("mode") or "rule"),
                json_dumps(monitor.get("match") or {}),
                json_dumps(monitor.get("action") or {}),
            )
        )
    return tuple(rows)


def _iter_match_tree(match: dict):
    yield match
    for key in ("all", "any", "none"):
        for child in match.get(key, []) if isinstance(match.get(key), list) else []:
            if isinstance(child, dict):
                yield from _iter_match_tree(child)


def _iter_positive_match_nodes(match: dict):
    yield match
    for key in ("all", "any"):
        for child in match.get(key, []) if isinstance(match.get(key), list) else []:
            if isinstance(child, dict):
                yield from _iter_positive_match_nodes(child)


def _validate_match_not_empty(match: dict):
    criteria_keys = (
        "protocols",
        "ip_versions",
        "eth_types",
        "ports",
        "src_ports",
        "dst_ports",
        "port_regex",
        "ips",
        "ip_regex",
        "protocol_regex",
        "payload_contains",
        "payload_prefix_hex",
        "payload_regex",
        "tcp_flags",
        "tcp_flags_any",
        "tcp_flags_all",
        "icmp_types",
        "icmp_codes",
        "arp_opcodes",
    )
    positive_nodes = list(_iter_positive_match_nodes(match))
    has_list_criteria = any(node.get(key) for node in positive_nodes for key in criteria_keys)
    has_length_criteria = any(
        bool(node.get("min_length"))
        or bool(node.get("max_length"))
        or bool(node.get("min_payload_text_length"))
        for node in positive_nodes
    )
    # A pure declarative count condition ("N events within T seconds",
    # with no other filter - e.g. "any traffic from the same source more
    # than N times/T") is itself a valid, non-empty condition for a
    # `mode: "stateful"` monitor targeting GenericThresholdDetector; it
    # would otherwise be rejected here even though every other criterion
    # is deliberately optional for it (see rulesets.normalize_match).
    has_count_criteria = any(
        bool(node.get("count_threshold")) and bool(node.get("window_seconds"))
        for node in positive_nodes
    )
    if not has_list_criteria and not has_length_criteria and not has_count_criteria:
        raise ValueError("Monitor match must include at least one condition")


def _validate_regex_patterns(match: dict):
    patterns = []
    for node in _iter_match_tree(match):
        patterns.extend(str(pattern) for pattern in node.get("payload_regex", []) if str(pattern).strip())
        patterns.extend(str(pattern) for pattern in node.get("payload_regex_exclude", []) if str(pattern).strip())
        patterns.extend(str(pattern) for pattern in node.get("ip_regex", []) if str(pattern).strip())
        patterns.extend(str(pattern) for pattern in node.get("port_regex", []) if str(pattern).strip())
        patterns.extend(str(pattern) for pattern in node.get("protocol_regex", []) if str(pattern).strip())
        patterns.extend(str(pattern) for pattern in node.get("exclude_ip_regex", []) if str(pattern).strip())
        patterns.extend(str(pattern) for pattern in node.get("exclude_port_regex", []) if str(pattern).strip())
        patterns.extend(str(pattern) for pattern in node.get("exclude_protocol_regex", []) if str(pattern).strip())
    if len(patterns) > settings.MONITOR_MAX_REGEX_PATTERNS:
        raise ValueError(f"Too many regex patterns (max {settings.MONITOR_MAX_REGEX_PATTERNS})")
    for pattern in patterns:
        if len(pattern) > settings.MONITOR_MAX_REGEX_LENGTH:
            raise ValueError(f"Regex pattern is too long (max {settings.MONITOR_MAX_REGEX_LENGTH} characters)")
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ValueError(f"Invalid regex pattern '{pattern}': {exc}") from exc
        if _regex_has_backtracking_risk(pattern):
            raise ValueError(f"Regex pattern has nested or ambiguous repetition risk: '{pattern}'")


def _regex_has_backtracking_risk(pattern: str) -> bool:
    """Cheap guardrail for user-defined monitor regexes.

    Sniff4Hound evaluates monitor regexes on the capture path, so reject the
    common catastrophic-backtracking shapes up front instead of relying on a
    runtime timeout that Python's stdlib regex engine does not provide.
    """
    if re.search(r"\\[1-9]", pattern):
        return True
    for group in re.findall(r"\(([^()]*)\)\s*(?:[+*]|\{\d+,?\d*\})", pattern):
        has_inner_repeat = re.search(r"(?:\.\*|\.\+|\\[dwsDWS][+*]|\[[^\]]+\][+*]|[A-Za-z0-9][+*])", group)
        has_literal_separator = re.search(r"(?:\\[./:_-]|[./:_-])", group)
        if has_inner_repeat and not has_literal_separator:
            return True
    if re.search(r"\.\*\s*(?:\.\*|\{)", pattern):
        return True
    if re.search(r"\([^)]*\|[^)]*\)\s*(?:[+*]|\{\d+,?\d*\})", pattern):
        alternatives = re.findall(r"\(([^)]*\|[^)]*)\)\s*(?:[+*]|\{\d+,?\d*\})", pattern)
        for group in alternatives:
            parts = [part.strip("\\^$") for part in group.split("|") if part]
            if any(left and right and (left.startswith(right) or right.startswith(left)) for left in parts for right in parts if left != right):
                return True
    return False


def normalize_monitor(item: dict, allow_source: bool = False, *, validate_regex: bool = True) -> dict:
    data = item if isinstance(item, dict) else {}
    rule_id = str(data.get("id") or data.get("slug") or data.get("name") or "").strip()
    if not rule_id:
        rule_id = "custom-monitor"
    name = str(data.get("name") or rule_id).strip() or rule_id
    description = str(data.get("description") or "").strip()
    enabled = bool(data.get("enabled", True))
    priority = safe_int(data.get("priority", 100), 100)
    match = normalize_match(data.get("match") if isinstance(data.get("match"), dict) else {})
    mode = str(data.get("mode") or "").strip().lower()
    if mode not in {"rule", "regex", "stateful"}:
        mode = "regex" if match.get("payload_regex") and not any(
            match.get(key)
            for key in ("protocols", "ip_versions", "eth_types", "ports", "src_ports", "dst_ports", "payload_contains", "payload_prefix_hex")
        ) else "rule"

    _validate_match_not_empty(match)
    if validate_regex:
        # Always validated for user-submitted monitors (the API's
        # save_monitor -> normalize_monitor path), where a syntax error
        # should be rejected up front with a clear message. Skipped for
        # load_builtin_monitors()'s large, bundled catalog purely for load-time
        # performance - re.compile() on every one of several thousand
        # regexes on every single app startup adds real, avoidable delay.
        # Skipping it is still safe at match time: rule_matches_packet's
        # regex cache (rulesets._compiled_regex) catches a bad pattern
        # there too and just treats it as never matching, never a crash or
        # a false "matches everything".
        _validate_regex_patterns(match)

    normalized = {
        "id": rule_id,
        "name": name,
        "description": description,
        "enabled": enabled,
        "priority": priority,
        "mode": mode,
        "match": match,
        "action": normalize_action(data.get("action") if isinstance(data.get("action"), dict) else {}),
    }
    if allow_source:
        normalized["source"] = str(data.get("source") or "custom").strip() or "custom"
    return normalized


def monitor_matches_packet(monitor: dict, packet: dict, *, packet_text: str | None = None) -> bool:
    return rule_matches_packet(monitor, packet, packet_text=packet_text)


# --- Content index -----------------------------------------------------
#
# With only a few dozen monitors, checking every one of them against every
# captured packet is cheap. With hundreds or thousands (the full catalog
# size), it isn't - the vast majority carry a
# `payload_contains` criterion, so most of that work is "is any of these
# literal strings present in this packet's text", which is exactly what a
# multi-pattern matcher (sniff4hound.ahocorasick.AhoCorasick) answers in one
# pass over the text instead of one `in` check per monitor.
#
# This module-level cache is keyed by the exact `monitors` list *object*
# Sniffer._get_monitor_context() hands out (re-fetched, and so a new list
# instance, every MONITOR_CACHE_TTL_SECONDS): ensure_monitor_index() is
# meant to be called once per that refresh, not once per packet, and
# evaluate_packet() only trusts the cache when it's given that exact same
# object back - anything else (every test in this repo builds its own
# monitors list ad hoc and never calls ensure_monitor_index) transparently
# falls back to the plain O(monitors) scan below, so correctness never
# depends on the cache being present or fresh.
#
# Two different rebuild costs are split apart deliberately:
#   - `_monitors_by_id` / `_always_check` (which monitors have no
#     payload_contains and so must always run the real check) are cheap to
#     rebuild (a single pass, no regex/trie work) and are done synchronously
#     - they're the ones `rule_matches_packet` uses for the authoritative
#       enabled/match check, so they must never be stale.
#   - the AhoCorasick automaton itself is the expensive part (its build
#     time scales with total pattern length - seconds, not milliseconds, at
#     tens of thousands of monitors) and is only ever used to *narrow*
#     candidates, never to authoritatively decide a match, so it's safe to
#     build in a background thread and keep serving the previous automaton
#     (or none at all) until the new one is ready. The practical effect of
#     that lag is bounded to "a monitor added seconds ago might take one
#     more refresh cycle before its content match starts firing" - it can
#     never cause a stale/disabled monitor to incorrectly match, because
#     every candidate is still re-validated against the fresh monitor dict.
_index_lock = threading.Lock()
_indexed_monitors_ref: list | None = None
_index_signature: tuple | None = None
_building_signature: tuple | None = None
_monitors_by_id: dict[str, dict] = {}
_always_check: list[dict] = []
_content_automaton = None
_content_to_ids: dict[str, list[str]] = {}
_monitor_positions: dict[str, int] = {}


def _monitor_index_signature(monitors: list[dict]) -> tuple:
    return tuple(
        (
            str(item.get("id") or ""),
            str(item.get("updated_at") or ""),
            bool(item.get("enabled", True)),
            str(item.get("mode") or ""),
            str(item.get("name") or ""),
            safe_int(item.get("priority", 100), 100),
            json.dumps(item.get("match") or {}, sort_keys=True, separators=(",", ":"), ensure_ascii=True),
            json.dumps(item.get("action") or {}, sort_keys=True, separators=(",", ":"), ensure_ascii=True),
        )
        for item in monitors
    )


def ensure_monitor_index(monitors: list[dict]) -> None:
    """Refresh the content index for this monitors list if needed. Meant to
    be called from Sniffer._get_monitor_context() (every
    MONITOR_CACHE_TTL_SECONDS), not from the per-packet path - the
    signature computation alone is O(len(monitors))."""
    global _indexed_monitors_ref, _index_signature, _building_signature
    global _monitors_by_id, _always_check, _monitor_positions

    signature = _monitor_index_signature(monitors)
    with _index_lock:
        if signature == _index_signature:
            _indexed_monitors_ref = monitors
            return
        _index_signature = signature

        monitors_by_id: dict[str, dict] = {}
        always_check: list[dict] = []
        content_to_ids: dict[str, list[str]] = {}
        monitor_positions: dict[str, int] = {}
        for position, monitor in enumerate(monitors):
            monitor_id = str(monitor.get("id") or "")
            monitor_positions[monitor_id] = position
            monitors_by_id[monitor_id] = monitor
            contains = (monitor.get("match") or {}).get("payload_contains") or []
            if not contains:
                always_check.append(monitor)
                continue
            for content in contains:
                content_to_ids.setdefault(str(content).lower(), []).append(monitor_id)
        _monitors_by_id = monitors_by_id
        _always_check = always_check
        _monitor_positions = monitor_positions
        _indexed_monitors_ref = monitors

        already_building = _building_signature == signature
        _building_signature = signature

    if already_building:
        return

    def _build_automaton() -> None:
        global _content_automaton, _content_to_ids, _building_signature
        automaton = AhoCorasick(content_to_ids.keys())
        with _index_lock:
            if _index_signature == signature:
                _content_automaton = automaton
                _content_to_ids = content_to_ids
            if _building_signature == signature:
                _building_signature = None

    threading.Thread(target=_build_automaton, daemon=True, name="sniff4hound-monitor-index").start()


def indexed_monitors_by_id(monitors: list[dict]) -> dict[str, dict] | None:
    """The id->monitor lookup ensure_monitor_index() already built for this
    exact monitors list object (unlike the content automaton, this part is
    always built synchronously, so it's available as soon as
    ensure_monitor_index() returns) - or None if that was never called for
    this object (e.g. a test building its own ad hoc monitors list), in
    which case the caller should build its own. Used by
    anomaly.AnomalyEngine.evaluate() to avoid its own O(len(monitors)) scan
    on every packet just to find a handful of fixed, known ids."""
    with _index_lock:
        if monitors is _indexed_monitors_ref:
            return _monitors_by_id
    return None


def _indexed_candidates(monitors: list[dict], packet_text: str) -> list[dict] | None:
    with _index_lock:
        if monitors is not _indexed_monitors_ref or _content_automaton is None:
            return None
        automaton = _content_automaton
        content_to_ids = _content_to_ids
        monitors_by_id = _monitors_by_id
        always_check = _always_check
        monitor_positions = _monitor_positions

    hit_ids: set[str] = set()
    for content in automaton.search(packet_text):
        hit_ids.update(content_to_ids.get(content, ()))

    candidates = list(always_check)
    for monitor_id in hit_ids:
        monitor = monitors_by_id.get(monitor_id)
        if monitor is not None:
            candidates.append(monitor)
    candidates.sort(key=lambda item: monitor_positions.get(str(item.get("id") or ""), len(monitor_positions)))
    return candidates


class RuleAlertThrottle:
    """Per-process rate limiter for rule/regex-mode monitor hits - a
    declarative, per-signature rate limit. Without it, any monitor whose
    match criteria stay true for many packets in the same burst (a scan, a
    page load pulling in dozens of resources, a chatty flow) re-fires on
    every single matching packet: a generic-enough signature can match
    hundreds of times in one capture window with no throttling at all.

    Deliberately scoped to severities "medium" and up: "info"/"low"
    monitors (DNS/HTTP/TLS-SNI/L2 discovery/protocol-seen/...) are
    visibility feeds, not alerts - Domains/Paths/Radar and similar
    catalogs depend on those firing on every single match, not just the
    first one in a window. Keyed by (monitor, source address) so a genuine
    attack from one host doesn't suppress the same monitor firing for a
    different host. State is in-memory only, not persisted across restarts
    - acceptable for this scope, same tradeoff as anomaly.py's detectors.
    """

    THROTTLED_SEVERITIES = frozenset({"medium", "high", "critical"})

    def __init__(self, window_seconds: int | None = None):
        self._window_seconds = window_seconds or settings.MONITOR_ALERT_COOLDOWN_SECONDS
        self._last_emit: dict[tuple[str, str], float] = {}

    def filter(self, hits: list[dict], source: str = "") -> list[dict]:
        if not hits:
            return hits
        now = time.monotonic()
        source_key = str(source or "").strip()
        allowed = []
        for hit in hits:
            severity = str(hit.get("severity") or "info").strip().lower()
            if severity not in self.THROTTLED_SEVERITIES:
                allowed.append(hit)
                continue
            key = (str(hit.get("monitor_id") or hit.get("tag") or ""), source_key)
            last = self._last_emit.get(key)
            if last is not None and now - last < self._window_seconds:
                continue
            self._last_emit[key] = now
            allowed.append(hit)
        return allowed


def evaluate_packet(packet: dict, monitors: list[dict]) -> list[dict]:
    # `monitors` is expected pre-sorted by (priority, name) - store.list_monitors()
    # already orders that way in SQL, and this is called once per captured
    # packet against every enabled monitor, so re-sorting here on every call
    # would be pure waste. packet_text (a string join + lower() over several
    # fields) is likewise built once per packet rather than once per
    # monitor - see rule_matches_packet.
    matches = []
    packet_text = build_packet_text(packet)
    candidates = _indexed_candidates(monitors, packet_text)
    if candidates is None:
        candidates = monitors
    for monitor in candidates:
        if str(monitor.get("mode") or "").strip().lower() == "stateful":
            # Stateful monitors have no declarative match logic to evaluate here —
            # they're driven by anomaly.AnomalyEngine, which runs separately and
            # unconditionally in Sniffer._store_packet.
            continue
        try:
            if not monitor_matches_packet(monitor, packet, packet_text=packet_text):
                continue
        except Exception:
            continue
        action = monitor.get("action") if isinstance(monitor.get("action"), dict) else {}
        matches.append(
            {
                "monitor_id": monitor.get("id"),
                "monitor_name": monitor.get("name"),
                "tag": action.get("tag") or monitor.get("id"),
                "label": action.get("label") or monitor.get("name"),
                "severity": action.get("severity") or "info",
            }
        )
    return matches


def describe_match(monitor: dict, packet: dict) -> str:
    """Best-effort description of the specific value that made this packet match the monitor."""
    match = monitor.get("match") if isinstance(monitor.get("match"), dict) else {}
    domain = str(packet.get("domain") or "").strip()
    domain_source = str(packet.get("domain_source") or "").strip()

    regexes = [str(item).strip() for item in match.get("payload_regex", []) if str(item).strip()]
    if regexes:
        packet_text = build_packet_text(packet)
        for pattern in regexes:
            try:
                found = re.search(pattern, packet_text, re.IGNORECASE)
            except re.error:
                continue
            if found:
                value = found.group(0).strip()
                if value:
                    return value[:120]
        if domain:
            return domain

    if domain and domain_source:
        return domain

    http_path = str(packet.get("http_path") or "").strip()
    if http_path and match.get("payload_contains"):
        return http_path

    needles = [str(item) for item in match.get("payload_contains", []) if str(item).strip()]
    if needles:
        packet_text = build_packet_text(packet)
        for needle in needles:
            if needle.lower() in packet_text:
                return needle.strip()

    prefix_hex = [str(item) for item in match.get("payload_prefix_hex", []) if str(item).strip()]
    if prefix_hex:
        return f"payload starts 0x{prefix_hex[0]}"

    ports = [safe_int(item, 0) for item in match.get("ports", []) if safe_int(item, 0)]
    if ports:
        src_port = safe_int(packet.get("src_port", 0), 0)
        dst_port = safe_int(packet.get("dst_port", 0), 0)
        if dst_port in ports:
            return f"port {dst_port}"
        if src_port in ports:
            return f"port {src_port}"

    eth_types = [safe_int(item, 0) for item in match.get("eth_types", []) if safe_int(item, 0)]
    if eth_types:
        return f"eth 0x{safe_int(packet.get('eth_type', 0), 0):04x}"

    protocols = [normalize_protocol_name(item) for item in match.get("protocols", []) if str(item).strip()]
    if protocols:
        return normalize_protocol_name(packet.get("proto"))

    min_length = safe_int(match.get("min_length", 0), 0)
    if min_length:
        return f"length {safe_int(packet.get('length', 0), 0)}B"

    if match.get("min_payload_text_length"):
        payload_text = str(packet.get("payload_text") or "").strip()
        if payload_text:
            return payload_text[:120]

    return ""
