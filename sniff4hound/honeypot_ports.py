"""Side-effect-free listener port sets.

The runtime imports this data from both privileged and unprivileged paths, so
keep the module to plain constants. The selected ports cover common scan
targets, alternate admin ports, and less-common enterprise/OT services without
trying to bind the full 1-65535 range by default.
"""

from __future__ import annotations

import socket

HTTP_TCP_PORTS = {
    80,
    81,
    82,
    280,
    591,
    593,
    631,
    777,
    800,
    801,
    808,
    880,
    888,
    898,
    981,
    2082,
    3000,
    3001,
    3128,
    3333,
    5000,
    5002,
    5601,
    5800,
    5984,
    5985,
    7000,
    7001,
    7080,
    7474,
    7777,
    8000,
    8001,
    8008,
    8010,
    8069,
    8080,
    8081,
    8082,
    8088,
    8090,
    8091,
    8098,
    8100,
    8180,
    8181,
    8222,
    8280,
    8500,
    8880,
    8888,
    8983,
    9000,
    9001,
    9080,
    9090,
    9091,
    9200,
    9999,
    10000,
    10255,
    11371,
    15672,
    50070,
    50075,
    50090,
}
HTTPS_TCP_PORTS = {
    443,
    2083,
    2376,
    4443,
    5001,
    5986,
    6443,
    6984,
    7002,
    7443,
    8443,
    8501,
    8834,
    9043,
    9443,
    9444,
    10443,
    10250,
    12443,
}
FTP_PORTS = {20, 21, 115, 2121}
FTPS_PORTS = {989, 990}
SMTP_PORTS = {25, 587, 2525}
SMTPS_PORTS = {465}
POP3_PORTS = {110}
POP3S_PORTS = {995}
IMAP_PORTS = {143}
IMAPS_PORTS = {993}
TELNET_PORTS = {23, 2323}
SSH_PORTS = {22, 2222, 8022}
MYSQL_PORTS = {3306, 3307}
POSTGRES_PORTS = {5432, 5433}
LDAP_PORTS = {389, 3268}
LDAPS_PORTS = {636, 3269}
REDIS_PORTS = {6379, 6380}
MEMCACHED_TCP_PORTS = {11211}
VNC_PORTS = {5900, 5901, 5902, 5903, 5904, 5905}
RDP_PORTS = {3389, 3390}
SMB_PORTS = {135, 139, 445}
DNS_TCP_PORTS = {53}
DNS_TLS_TCP_PORTS = {853}
MONGODB_PORTS = {27017, 27018, 27019, 28017}
MQTT_PORTS = {1883, 1884}
MQTTS_PORTS = {8883}
AMQP_PORTS = {5672}
AMQPS_PORTS = {5671}
RTSP_PORTS = {554}

AUTH_TCP_PORTS = {49, 88, 464, 749}
FILE_SHARING_TCP_PORTS = {111, 512, 513, 514, 515, 548, 873, 2049, 3260}
DATABASE_TCP_PORTS = {1433, 1434, 1521, 1830, 2483, 2484, 3050, 50000}
SEARCH_BIGDATA_TCP_PORTS = {7199, 9042, 9160, 9300, 50010, 50030, 50060, 50070, 50075, 50090}
REMOTE_ACCESS_TCP_PORTS = {106, 199, 902, 1723, 3389, 3390, 4899, 5900, 5901, 5902, 5903, 5904, 5905, 5985, 5986, 6000, 6001, 6002, 6129, 7070}
MESSAGING_TCP_PORTS = {5222, 5269, 5555, 61613, 61614, 61616}
DEVOPS_TCP_PORTS = {2181, 2375, 2376, 2379, 2380, 4789, 5000, 5001, 6443, 8009, 8089, 10050, 10051, 10250, 10255, 11211}
ICS_OT_TCP_PORTS = {102, 502, 1089, 1091, 1911, 1962, 2000, 2404, 4000, 4840, 9600, 18245, 20000, 20547, 34962, 34963, 34964, 34980, 44818, 47808, 55000}
LEGACY_TCP_PORTS = {1, 7, 9, 13, 17, 19, 37, 43, 70, 79, 101, 113, 119, 179, 264, 427, 444, 563, 646, 1080, 9100}
GENERIC_TLS_TCP_PORTS = {853, 563, 2484}
GENERIC_TCP_PORTS = (
    AUTH_TCP_PORTS
    | FILE_SHARING_TCP_PORTS
    | DATABASE_TCP_PORTS
    | SEARCH_BIGDATA_TCP_PORTS
    | REMOTE_ACCESS_TCP_PORTS
    | MESSAGING_TCP_PORTS
    | DEVOPS_TCP_PORTS
    | ICS_OT_TCP_PORTS
    | LEGACY_TCP_PORTS
    | GENERIC_TLS_TCP_PORTS
)

TLS_TCP_PORTS = (
    HTTPS_TCP_PORTS
    | FTPS_PORTS
    | SMTPS_PORTS
    | POP3S_PORTS
    | IMAPS_PORTS
    | LDAPS_PORTS
    | MQTTS_PORTS
    | AMQPS_PORTS
    | DNS_TLS_TCP_PORTS
    | GENERIC_TLS_TCP_PORTS
)

DNS_UDP_PORTS = {53}
DHCP_UDP_PORTS = {67, 68, 546, 547}
TFTP_UDP_PORTS = {69}
NTP_UDP_PORTS = {123}
NETBIOS_UDP_PORTS = {137, 138}
SNMP_UDP_PORTS = {161, 162}
IPSEC_UDP_PORTS = {500, 4500, 1701}
SYSLOG_UDP_PORTS = {514}
RIP_UDP_PORTS = {520}
RADIUS_UDP_PORTS = {1645, 1646, 1812, 1813}
SSDP_UDP_PORTS = {1900}
SIP_UDP_PORTS = {5060, 5061}
MDNS_UDP_PORTS = {5353, 5355}
MEMCACHED_UDP_PORTS = {11211}
KERBEROS_UDP_PORTS = {88, 464}
RPC_UDP_PORTS = {111, 135, 2049}
VPN_UDP_PORTS = {1194, 51820}
QUIC_UDP_PORTS = {443, 8443}
IPMI_UDP_PORTS = {623}
MSSQL_UDP_PORTS = {1434}
DISCOVERY_UDP_PORTS = {177, 3702, 5351, 10080}
REALTIME_UDP_PORTS = {3478, 5004, 5005, 9987, 27015, 27016, 27960}
COAP_UDP_PORTS = {5683, 5684}
ICS_OT_UDP_PORTS = {102, 502, 2222, 44818, 47808}
OVERLAY_UDP_PORTS = {4789, 6081}

DEFAULT_ENABLED_PORTS = {
    "tcp": sorted(
        HTTP_TCP_PORTS
        | HTTPS_TCP_PORTS
        | FTP_PORTS
        | FTPS_PORTS
        | SMTP_PORTS
        | SMTPS_PORTS
        | POP3_PORTS
        | POP3S_PORTS
        | IMAP_PORTS
        | IMAPS_PORTS
        | TELNET_PORTS
        | SSH_PORTS
        | MYSQL_PORTS
        | POSTGRES_PORTS
        | LDAP_PORTS
        | LDAPS_PORTS
        | REDIS_PORTS
        | MEMCACHED_TCP_PORTS
        | VNC_PORTS
        | RDP_PORTS
        | SMB_PORTS
        | DNS_TCP_PORTS
        | MONGODB_PORTS
        | MQTT_PORTS
        | MQTTS_PORTS
        | AMQP_PORTS
        | AMQPS_PORTS
        | RTSP_PORTS
        | GENERIC_TCP_PORTS
    ),
    "udp": sorted(
        DNS_UDP_PORTS
        | DHCP_UDP_PORTS
        | TFTP_UDP_PORTS
        | NTP_UDP_PORTS
        | NETBIOS_UDP_PORTS
        | SNMP_UDP_PORTS
        | IPSEC_UDP_PORTS
        | SYSLOG_UDP_PORTS
        | RIP_UDP_PORTS
        | RADIUS_UDP_PORTS
        | SSDP_UDP_PORTS
        | SIP_UDP_PORTS
        | MDNS_UDP_PORTS
        | MEMCACHED_UDP_PORTS
        | KERBEROS_UDP_PORTS
        | RPC_UDP_PORTS
        | VPN_UDP_PORTS
        | QUIC_UDP_PORTS
        | IPMI_UDP_PORTS
        | MSSQL_UDP_PORTS
        | DISCOVERY_UDP_PORTS
        | REALTIME_UDP_PORTS
        | COAP_UDP_PORTS
        | ICS_OT_UDP_PORTS
        | OVERLAY_UDP_PORTS
    ),
}

EXPANDED_LISTENER_PORT_MAX = 5000

COMMON_PORTS = {
    proto: sorted(set(DEFAULT_ENABLED_PORTS.get(proto, ())) | set(range(1, EXPANDED_LISTENER_PORT_MAX + 1)))
    for proto in ("tcp", "udp")
}


def service_label(proto: str, port: int) -> str:
    proto = str(proto or "").strip().lower()
    port = int(port)
    if proto == "tcp":
        if port in HTTP_TCP_PORTS:
            return "HTTP web service"
        if port in HTTPS_TCP_PORTS:
            return "HTTPS web service"
        if port in SSH_PORTS:
            return "SSH remote shell"
        if port in FTP_PORTS or port in FTPS_PORTS:
            return "FTP file transfer"
        if port in SMTP_PORTS or port in SMTPS_PORTS:
            return "SMTP mail service"
        if port in MYSQL_PORTS:
            return "MySQL database"
        if port in POSTGRES_PORTS:
            return "PostgreSQL database"
        if port in SMB_PORTS:
            return "SMB file sharing"
        if port in RDP_PORTS:
            return "RDP remote desktop"
        if port in ICS_OT_TCP_PORTS:
            return "Industrial/OT service"
    elif proto == "udp":
        if port in DNS_UDP_PORTS:
            return "DNS service"
        if port in DHCP_UDP_PORTS:
            return "DHCP service"
        if port in NTP_UDP_PORTS:
            return "NTP time service"
        if port in SNMP_UDP_PORTS:
            return "SNMP management"
        if port in SSDP_UDP_PORTS or port in MDNS_UDP_PORTS or port in NETBIOS_UDP_PORTS:
            return "Discovery service"
        if port in ICS_OT_UDP_PORTS:
            return "Industrial/OT service"
    try:
        name = socket.getservbyport(port, proto)
    except OSError:
        name = ""
    if name:
        return f"{name.upper()} service"
    return f"{proto.upper()} service {port}"
