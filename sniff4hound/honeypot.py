from __future__ import annotations

import fcntl
import ipaddress
import logging
import queue
import select
import shutil
import socket
import sqlite3
import ssl
import struct
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import formatdate
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

from .utils import (
    bytes_to_hex_preview,
    bytes_to_text_preview,
    normalize_protocol_name,
    normalize_text,
    safe_int,
    utc_now,
)
from .honeypot_ports import (  # noqa: F401 - re-exported, used throughout this module's dispatch below
    AMQP_PORTS,
    AMQPS_PORTS,
    COMMON_PORTS,
    DNS_TCP_PORTS,
    DNS_UDP_PORTS,
    DHCP_UDP_PORTS,
    FTP_PORTS,
    FTPS_PORTS,
    GENERIC_TCP_PORTS,
    HTTP_TCP_PORTS,
    HTTPS_TCP_PORTS,
    IMAP_PORTS,
    IMAPS_PORTS,
    IPSEC_UDP_PORTS,
    LDAP_PORTS,
    LDAPS_PORTS,
    MDNS_UDP_PORTS,
    MEMCACHED_TCP_PORTS,
    MEMCACHED_UDP_PORTS,
    MONGODB_PORTS,
    MQTT_PORTS,
    MQTTS_PORTS,
    MYSQL_PORTS,
    NETBIOS_UDP_PORTS,
    NTP_UDP_PORTS,
    POP3_PORTS,
    POP3S_PORTS,
    POSTGRES_PORTS,
    RADIUS_UDP_PORTS,
    RDP_PORTS,
    REDIS_PORTS,
    RIP_UDP_PORTS,
    RTSP_PORTS,
    SIP_UDP_PORTS,
    SMB_PORTS,
    SMTP_PORTS,
    SMTPS_PORTS,
    SNMP_UDP_PORTS,
    SSDP_UDP_PORTS,
    SSH_PORTS,
    SYSLOG_UDP_PORTS,
    TELNET_PORTS,
    TFTP_UDP_PORTS,
    TLS_TCP_PORTS,
    VNC_PORTS,
    service_label,
)

from .settings import DATA_DIR, PAYLOAD_TEXT_MAX_CHARS

LOG_MAX_BYTES = 10 * 1024 * 1024
LOG_BACKUP_COUNT = 5
LOG_FILE = DATA_DIR / "service_listener.log"
EVENT_DB_FILE = DATA_DIR / "service_events.db"
CERT_FILE = DATA_DIR / "service_cert.pem"
KEY_FILE = DATA_DIR / "service_key.pem"
DATA_DIR.mkdir(parents=True, exist_ok=True)

EVENT_DB_TABLES = ("connection_events", "tls_sessions", "dns_queries")


def clear_honeypot_events() -> dict:
    """Deletes every row from the honeypot's own event-detail database
    (honeypot_events.db - connection_events/tls_sessions/dns_queries),
    separate from SniffStore's packets/tags which
    sniff4hound.store.SniffStore.clear_detections(scope="honeypot") already
    handles. Opens its own short-lived connection rather than requiring a
    live HoneypotEngine instance, since honeypot mode may not be the
    currently active runtime mode when an operator wants to clear this
    history."""
    counts = {table: 0 for table in EVENT_DB_TABLES}
    if not EVENT_DB_FILE.exists():
        return counts
    conn = sqlite3.connect(EVENT_DB_FILE)
    try:
        for table in EVENT_DB_TABLES:
            try:
                cursor = conn.execute(f"DELETE FROM {table}")
            except sqlite3.OperationalError:
                continue  # table not created yet - honeypot mode never ran
            counts[table] = max(0, cursor.rowcount)
        conn.commit()
    finally:
        conn.close()
    return counts

BIND_HOST = "0.0.0.0"
_SIOCGIFADDR = 0x8915
READ_TIMEOUT_SECONDS = 6
MAX_PACKET_SIZE = 4096
MAX_HTTP_REQUEST_SIZE = 16384
MAX_COMMAND_ROUNDS = 20
DB_BATCH_SIZE = 100

FAVICON_ICO = bytes.fromhex(
    "00000100010001010000010020003000000016000000"
    "280000000100000002000000010020000000000008000000"
    "130B0000130B000000000000000000000000FFFF000000000000"
)

TCP_BANNERS: dict[int, str | bytes] = {
    21: "220 ProFTPD 1.3.5 Server ready\r\n",
    22: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3\r\n",
    23: "Debian GNU/Linux 12 ttyS0\r\nlogin: ",
    25: "220 mx01.local ESMTP Postfix\r\n",
    53: "DNS service ready\r\n",
    110: "+OK Dovecot ready.\r\n",
    139: b"\x00\x00\x00\x85\xffSMBr\x00\x00\x00\x00\x18\x01\x28\x00",
    143: "* OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR IDLE AUTH=PLAIN] Dovecot ready.\r\n",
    389: "LDAP service ready\r\n",
    445: b"\x00\x00\x00\x90\xffSMBr\x00\x00\x00\x00\x18\x53\xc8",
    554: "RTSP/1.0 200 OK\r\nServer: Live555 Streaming Media v2018.08.28\r\n\r\n",
    587: "220 mx01.local ESMTP Postfix\r\n",
    990: "220 ProFTPD 1.3.5 Server ready\r\n",
    993: "* OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR IDLE AUTH=PLAIN] Dovecot ready.\r\n",
    995: "+OK Dovecot ready.\r\n",
    2049: "NFS service ready\r\n",
    2121: "220 ProFTPD 1.3.5 Server ready\r\n",
    3306: b"\x19\x00\x00\x00\x0a8.0.30-0ubuntu0.20.04.2\x00\x01\x00\x00\x00abcdefgh\x00",
    3389: b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x124\x00\x02\x00\x08\x00\x02\x00\x00\x00",
    5432: "PostgreSQL 13.0\r\n",
    5671: b"AMQP\x00\x00\x09\x01",
    5672: b"AMQP\x00\x00\x09\x01",
    5900: b"RFB 003.008\n",
    6379: b"-NOAUTH Authentication required.\r\n",
    8000: "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n",
    8080: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.46 (Ubuntu)\r\n\r\n",
    8888: "HTTP/1.1 200 OK\r\nServer: Caddy/2.7.0\r\n\r\n",
    9200: "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n",
    9443: "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n",
    11211: "STAT pid 2134\r\nEND\r\n",
    27017: "It looks like you are trying to access MongoDB over HTTP on the native driver port.\n",
}

UDP_BANNERS: dict[int, str | bytes] = {
    53: b"\x00\x00\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00",
    67: "DHCP Service",
    68: "DHCP Client",
    69: "TFTP Server",
    123: "NTPv4 Server",
    137: "NetBIOS Name Service",
    138: "NetBIOS Datagram Service",
    161: "public\nSNMPv1 Server",
    500: "ISAKMP Response",
    514: "<13>syslog accepted",
    520: "RIP Response",
    1812: "RADIUS Access-Reject",
    1813: "RADIUS Accounting-Response",
    4500: "IKEv2 Response",
    1900: "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nSERVER: UPnP/1.0 Portable SDK\r\n\r\n",
    5060: "SIP/2.0 200 OK\r\nServer: Asterisk PBX 18.9.0\r\n\r\n",
    5353: b"\x00\x00\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00",
    11211: "STAT version 1.6.9\r\nEND\r\n",
}


def _build_logger() -> logging.Logger:
    logger = logging.getLogger("sniff4hound.honeypot")
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    try:
        handler = RotatingFileHandler(
            LOG_FILE,
            maxBytes=LOG_MAX_BYTES,
            backupCount=LOG_BACKUP_COUNT,
            encoding="utf-8",
        )
        handler.setFormatter(logging.Formatter("%(asctime)s - %(message)s"))
    except OSError:
        handler = logging.NullHandler()
    logger.addHandler(handler)
    logger.propagate = False
    return logger


LOGGER = _build_logger()


def _discover_host_ipv4_addresses() -> list[str]:
    """Every IPv4 address currently assigned to a local interface, minus
    loopback (127.0.0.0/8) - used so the honeypot binds each listener
    directly to the host's real IPs instead of the 0.0.0.0 wildcard, which
    would otherwise also quietly answer on 127.0.0.1. Linux-only
    (SIOCGIFADDR ioctl), matching this project's existing AF_PACKET-based
    capture code, which is already Linux-only."""
    addresses: list[str] = []
    seen: set[str] = set()
    try:
        names = [name for _, name in socket.if_nameindex()]
    except Exception:
        return addresses
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        for name in names:
            try:
                packed = fcntl.ioctl(
                    probe.fileno(),
                    _SIOCGIFADDR,
                    struct.pack("256s", name[:15].encode("utf-8")),
                )
                ip = socket.inet_ntoa(packed[20:24])
            except OSError:
                continue
            try:
                if ipaddress.ip_address(ip).is_loopback:
                    continue
            except ValueError:
                continue
            if ip not in seen:
                seen.add(ip)
                addresses.append(ip)
    return addresses


def _normalize_payload(data):
    if data is None:
        return b""
    if isinstance(data, (bytes, bytearray)):
        return bytes(data)
    return str(data).encode("utf-8", errors="replace")


def _safe_send(sock, payload):
    if payload is None:
        return
    try:
        sock.sendall(payload if isinstance(payload, (bytes, bytearray)) else str(payload).encode("utf-8", errors="replace"))
    except Exception:
        pass


def _recv_line(sock, max_len: int = MAX_PACKET_SIZE) -> bytes:
    data = b""
    while len(data) < max_len:
        try:
            chunk = sock.recv(1)
        except socket.timeout:
            break
        if not chunk:
            break
        data += chunk
        if data.endswith(b"\n"):
            break
    return data


def _decode_line(data: bytes) -> str:
    return data.decode("utf-8", errors="replace").strip()


def _generic_tcp_banner(port: int) -> str:
    label = service_label("tcp", int(port)).replace("\r", " ").replace("\n", " ").strip()
    return f"220 {label} ready\r\n"


def _read_http_request(sock) -> bytes:
    sock.settimeout(READ_TIMEOUT_SECONDS)
    data = b""
    while b"\r\n\r\n" not in data and len(data) < MAX_HTTP_REQUEST_SIZE:
        chunk = sock.recv(MAX_PACKET_SIZE)
        if not chunk:
            break
        data += chunk
    return data


def _build_http_response(status_code: int, reason: str, body: bytes, content_type: str) -> bytes:
    headers = [
        f"HTTP/1.1 {status_code} {reason}",
        "Server: nginx/1.18.0",
        f"Date: {formatdate(usegmt=True)}",
        f"Content-Type: {content_type}",
        f"Content-Length: {len(body)}",
        "Connection: close",
    ]
    return ("\r\n".join(headers) + "\r\n\r\n").encode("utf-8") + body


def _normalize_dns_response_ip(response_ip: str) -> bytes:
    try:
        return socket.inet_aton(response_ip)
    except OSError:
        return socket.inet_aton("127.0.0.1")


def _decode_dns_name(packet: bytes, start_idx: int):
    labels = []
    idx = start_idx
    next_idx = start_idx
    jumped = False
    jumps = 0

    while idx < len(packet):
        length = packet[idx]
        if length == 0:
            idx += 1
            if not jumped:
                next_idx = idx
            break
        if (length & 0xC0) == 0xC0:
            if idx + 1 >= len(packet):
                raise ValueError("Nombre DNS comprimido truncado")
            pointer = ((length & 0x3F) << 8) | packet[idx + 1]
            if pointer >= len(packet):
                raise ValueError("Puntero DNS fuera de rango")
            if not jumped:
                next_idx = idx + 2
            idx = pointer
            jumped = True
            jumps += 1
            if jumps > 20:
                raise ValueError("Demasiados saltos en nombre DNS")
            continue
        if length > 63:
            raise ValueError("Etiqueta DNS invalida")
        idx += 1
        if idx + length > len(packet):
            raise ValueError("Etiqueta DNS truncada")
        labels.append(packet[idx : idx + length].decode("utf-8", errors="replace"))
        idx += length
    else:
        raise ValueError("Nombre DNS sin terminador")

    return (".".join(labels) if labels else "."), next_idx


def _parse_dns_questions(query: bytes):
    if len(query) < 12:
        return []

    qdcount = int.from_bytes(query[4:6], "big")
    idx = 12
    questions = []
    for _ in range(qdcount):
        if idx >= len(query):
            break
        name_offset = idx
        try:
            domain, name_end = _decode_dns_name(query, idx)
        except ValueError:
            break
        if name_end + 4 > len(query):
            break
        qtype = int.from_bytes(query[name_end : name_end + 2], "big")
        qclass = int.from_bytes(query[name_end + 2 : name_end + 4], "big")
        question_end = name_end + 4
        questions.append(
            {
                "domain": domain,
                "qtype": qtype,
                "qclass": qclass,
                "name_offset": name_offset,
                "wire": query[idx:question_end],
            }
        )
        idx = question_end
    return questions


def _build_dns_response(query: bytes, response_ip: str):
    if len(query) < 12:
        return UDP_BANNERS[53], []

    transaction_id = query[:2]
    questions = _parse_dns_questions(query)
    if not questions:
        empty_header = transaction_id + b"\x81\x82" + b"\x00\x00\x00\x00\x00\x00\x00\x00"
        return empty_header, []

    question_section = b"".join(question["wire"] for question in questions)
    ip_bytes = _normalize_dns_response_ip(response_ip)

    answers = []
    for question in questions:
        name_ptr = (0xC000 | question["name_offset"]).to_bytes(2, "big")
        answer = name_ptr + b"\x00\x01\x00\x01" + (60).to_bytes(4, "big") + b"\x00\x04" + ip_bytes
        answers.append(answer)

    header = (
        transaction_id
        + b"\x81\x80"
        + len(questions).to_bytes(2, "big")
        + len(answers).to_bytes(2, "big")
        + b"\x00\x00\x00\x00"
    )
    return header + question_section + b"".join(answers), questions


def _build_ntp_response(request_data: bytes) -> bytes:
    response = bytearray(48)
    response[0] = 0x24
    response[1] = 1
    response[2] = 6
    response[3] = 0xEC

    ntp_epoch = datetime(1900, 1, 1, tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    seconds_since_ntp = int((now - ntp_epoch).total_seconds())
    timestamp = seconds_since_ntp.to_bytes(4, "big", signed=False) + b"\x00\x00\x00\x00"

    if len(request_data) >= 48:
        response[24:32] = request_data[40:48]
    response[32:40] = timestamp
    response[40:48] = timestamp
    return bytes(response)


def _build_sip_response(request_data: bytes, addr):
    text = request_data.decode("utf-8", errors="replace")
    headers = {}
    for line in text.split("\r\n")[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()

    via = headers.get("via", f"SIP/2.0/UDP {addr[0]}:{addr[1]};branch=z9hG4bK-524287")
    from_h = headers.get("from", "<sip:scanner@example.net>")
    to_h = headers.get("to", "<sip:service@example.net>")
    call_id = headers.get("call-id", "call-000001")
    cseq = headers.get("cseq", "1 OPTIONS")

    return (
        "SIP/2.0 200 OK\r\n"
        f"Via: {via}\r\n"
        f"From: {from_h}\r\n"
        f"To: {to_h};tag=as5f3a2c1\r\n"
        f"Call-ID: {call_id}\r\n"
        f"CSeq: {cseq}\r\n"
        "Server: Asterisk PBX 18.9.0\r\n"
        "Content-Length: 0\r\n\r\n"
    ).encode("utf-8")


def _build_rtsp_response(request_text: str) -> bytes:
    cseq = "1"
    for line in request_text.split("\r\n"):
        if line.lower().startswith("cseq:"):
            cseq = line.split(":", 1)[1].strip()
            break

    return (
        "RTSP/1.0 200 OK\r\n"
        f"CSeq: {cseq}\r\n"
        "Server: Live555 Streaming Media v2018.08.28\r\n"
        "Public: OPTIONS, DESCRIBE, SETUP, TEARDOWN, PLAY, PAUSE\r\n"
        "Content-Length: 0\r\n\r\n"
    ).encode("utf-8")


def _build_ldap_bind_response(request_data: bytes) -> bytes:
    message_id = 1
    if len(request_data) >= 5 and request_data[0] == 0x30 and request_data[2] == 0x02 and request_data[3] == 0x01:
        message_id = request_data[4]
    return bytes([0x30, 0x0C, 0x02, 0x01, message_id, 0x61, 0x07, 0x0A, 0x01, 0x31, 0x04, 0x00, 0x04, 0x00])


def _build_postgres_error_packet() -> bytes:
    payload = b"SERROR\x00C28000\x00Mpassword authentication failed\x00\x00"
    error_response = b"E" + (len(payload) + 4).to_bytes(4, "big") + payload
    ready_for_query = b"Z\x00\x00\x00\x05I"
    return error_response + ready_for_query


# A fixed-but-plausible server GUID for the SMB2 Negotiate Response below -
# real servers advertise a random-looking, per-install GUID here; a fixed
# one is fine for a passive decoy (it's never load-bearing to a real client,
# just present-and-well-formed) and keeps the response byte-for-byte
# reproducible for tests.
_SMB2_SERVER_GUID = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")


def _build_smb2_negotiate_response() -> bytes:
    """A minimal, structurally-correct SMB2 NEGOTIATE_RESPONSE (dialect
    2.0.2, the oldest SMB2 dialect - avoids the SMB 3.x negotiate-context
    fields a fuller response would need), wrapped in its NetBIOS Session
    Service framing. Answered unconditionally regardless of whether the
    client opened with legacy SMB1 (\\xffSMB) or SMB2 (\\xfeSMB) framing -
    see _handle_smb_service's docstring for why that matches real modern
    Windows server behavior rather than being a tell."""
    header = (
        b"\xfeSMB"  # ProtocolId
        + (64).to_bytes(2, "little")  # StructureSize
        + b"\x00\x00"  # CreditCharge
        + b"\x00\x00\x00\x00"  # Status
        + (0).to_bytes(2, "little")  # Command = SMB2 NEGOTIATE
        + (1).to_bytes(2, "little")  # CreditResponse
        + (1).to_bytes(4, "little")  # Flags = SMB2_FLAGS_SERVER_TO_REDIR
        + b"\x00\x00\x00\x00"  # NextCommand
        + b"\x00" * 8  # MessageId
        + b"\x00" * 4  # Reserved
        + b"\x00" * 4  # TreeId
        + b"\x00" * 8  # SessionId
        + b"\x00" * 16  # Signature
    )
    now_filetime = int((time.time() + 11644473600) * 10_000_000).to_bytes(8, "little")
    body = (
        (65).to_bytes(2, "little")  # StructureSize
        + (1).to_bytes(2, "little")  # SecurityMode = signing enabled
        + (0x0202).to_bytes(2, "little")  # DialectRevision = 2.0.2
        + b"\x00\x00"  # Reserved
        + _SMB2_SERVER_GUID  # ServerGuid
        + b"\x00\x00\x00\x00"  # Capabilities
        + (0x00010000).to_bytes(4, "little")  # MaxTransactSize
        + (0x00010000).to_bytes(4, "little")  # MaxReadSize
        + (0x00010000).to_bytes(4, "little")  # MaxWriteSize
        + now_filetime  # SystemTime
        + b"\x00" * 8  # ServerStartTime
        + (128).to_bytes(2, "little")  # SecurityBufferOffset (64 header + 64 body)
        + (0).to_bytes(2, "little")  # SecurityBufferLength
        + b"\x00\x00\x00\x00"  # Reserved2
    )
    message = header + body
    return len(message).to_bytes(4, "big") + message  # NetBIOS Session Service framing


def _build_rdp_connection_confirm() -> bytes:
    """A minimal RFC 905 X.224 Connection Confirm TPDU carrying an
    RDP_NEG_RSP selecting PROTOCOL_RDP (standard RDP security, no
    TLS/CredSSP) - the simplest response that still completes the very
    first round trip of an RDP connection attempt (MS-RDPBCGR §2.2.1.4),
    wrapped in its TPKT header."""
    rdp_neg_rsp = (
        b"\x02"  # Type = TYPE_RDP_NEG_RSP
        + b"\x00"  # Flags
        + (8).to_bytes(2, "little")  # Length
        + (0).to_bytes(4, "little")  # SelectedProtocol = PROTOCOL_RDP
    )
    x224_body = (
        b"\xd0"  # CC CDT (Connection Confirm, credit 0)
        + b"\x00\x00"  # DST-REF
        + b"\x00\x00"  # SRC-REF
        + b"\x00"  # Class option
        + rdp_neg_rsp
    )
    x224 = bytes([len(x224_body)]) + x224_body
    tpkt_length = 4 + len(x224)
    return b"\x03\x00" + tpkt_length.to_bytes(2, "big") + x224


@dataclass
class HoneypotState:
    running: bool = False
    errors: dict[str, str] = field(default_factory=dict)
    packets_seen: int = 0
    packets_total_bytes: int = 0
    started_at: str = ""
    last_event_at: str = ""
    session_id: int = 0


class HoneypotEngine:
    def __init__(self, store, hub, *, bind_host: str = BIND_HOST):
        self.store = store
        self.hub = hub
        self.bind_host = bind_host
        self._stop_event = threading.Event()
        self._state_lock = threading.RLock()
        self._event_queue: queue.Queue[dict[str, Any]] = queue.Queue()
        # Each listener gets its own stop event/thread, keyed by id
        # ("tcp/22") - the shared `_stop_event` above still governs the
        # writer thread and overall engine lifecycle, but per-listener
        # start/stop needs per-listener signaling.
        self._listener_stop_events: dict[str, threading.Event] = {}
        self._listener_threads: dict[str, threading.Thread] = {}
        self._writer_thread: threading.Thread | None = None
        self._start_thread: threading.Thread | None = None
        self._state = HoneypotState()
        self._tls_sni_map: dict[int, str] = {}
        self._tls_sni_lock = threading.Lock()
        self._event_db: sqlite3.Connection | None = None
        self._tls_context: ssl.SSLContext | None = None

    def _set_error(self, name: str, message: str):
        with self._state_lock:
            self._state.errors[str(name)] = str(message)

    def _touch_packet(self, packet: dict):
        payload_len = safe_int(packet.get("payload_len", 0), 0)
        length = safe_int(packet.get("length", 0), 0)
        with self._state_lock:
            self._state.packets_seen += 1
            self._state.packets_total_bytes += max(length, payload_len)
            self._state.last_event_at = utc_now()

    def _session_id(self) -> int:
        with self._state_lock:
            if self._state.session_id > 0 and self.store.get_session(self._state.session_id):
                return self._state.session_id

        existing = safe_int(self.store.get_runtime_config("honeypot_session_id", "0"), 0)
        if existing and self.store.get_session(existing):
            with self._state_lock:
                self._state.session_id = existing
            return existing

        row = self.store.create_session(
            {
                "network": "0.0.0.0/0",
                "type": "service-listener",
                "proto": "all",
                "port_mode": "preset",
                "port_start": 0,
                "port_end": 0,
                "status": "active",
                "timesleep": 0.5,
                "progress": 0.0,
                "interface": "service",
                "filter_text": "service listener mode",
            }
        )
        session_id = safe_int(row.get("id"), 0)
        if session_id:
            self.store.set_runtime_config("honeypot_session_id", str(session_id))
        with self._state_lock:
            self._state.session_id = session_id
        return session_id

    def _ensure_event_db(self):
        if self._event_db is not None:
            return self._event_db
        conn = sqlite3.connect(EVENT_DB_FILE, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS connection_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_time TEXT NOT NULL,
                protocol TEXT NOT NULL,
                dst_port INTEGER NOT NULL,
                src_ip TEXT NOT NULL,
                src_port INTEGER NOT NULL,
                data_len INTEGER NOT NULL,
                data_preview TEXT,
                data BLOB
            );
            CREATE INDEX IF NOT EXISTS idx_connection_events_time ON connection_events(event_time);
            CREATE INDEX IF NOT EXISTS idx_connection_events_protocol ON connection_events(protocol);
            CREATE INDEX IF NOT EXISTS idx_connection_events_src ON connection_events(src_ip, src_port);
            CREATE INDEX IF NOT EXISTS idx_connection_events_dst_port ON connection_events(dst_port);

            CREATE TABLE IF NOT EXISTS tls_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_time TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                src_port INTEGER NOT NULL,
                dst_port INTEGER NOT NULL,
                tls_version TEXT,
                cipher_name TEXT,
                cipher_protocol TEXT,
                cipher_bits INTEGER,
                alpn TEXT,
                sni TEXT,
                peer_cert BLOB
            );
            CREATE INDEX IF NOT EXISTS idx_tls_sessions_time ON tls_sessions(event_time);
            CREATE INDEX IF NOT EXISTS idx_tls_sessions_src ON tls_sessions(src_ip, src_port);
            CREATE INDEX IF NOT EXISTS idx_tls_sessions_dst_port ON tls_sessions(dst_port);

            CREATE TABLE IF NOT EXISTS dns_queries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_time TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                src_port INTEGER NOT NULL,
                dst_port INTEGER NOT NULL,
                domain TEXT NOT NULL,
                query_type INTEGER NOT NULL,
                response_ip TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_dns_queries_time ON dns_queries(event_time);
            CREATE INDEX IF NOT EXISTS idx_dns_queries_domain ON dns_queries(domain);
            CREATE INDEX IF NOT EXISTS idx_dns_queries_src ON dns_queries(src_ip, src_port);
            """
        )
        self._event_db = conn
        return conn

    def _close_event_db(self):
        conn = self._event_db
        self._event_db = None
        if conn is None:
            return
        try:
            conn.close()
        except Exception:
            pass

    def _event_writer(self):
        conn = None
        try:
            conn = self._ensure_event_db()
        except Exception as error:
            self._set_error("events", str(error))
            LOGGER.exception("No se pudo abrir la base auxiliar de listeners")
        try:
            while not self._stop_event.is_set() or not self._event_queue.empty():
                try:
                    event = self._event_queue.get(timeout=0.5)
                except queue.Empty:
                    continue
                batch = [event]
                while len(batch) < DB_BATCH_SIZE:
                    try:
                        batch.append(self._event_queue.get_nowait())
                    except queue.Empty:
                        break

                try:
                    for item in batch:
                        packet = item.get("packet") if isinstance(item, dict) else None
                        meta = item.get("meta") if isinstance(item, dict) else {}
                        if not isinstance(packet, dict):
                            continue
                        if conn is not None:
                            self._insert_event_row(conn, packet, meta if isinstance(meta, dict) else {})
                        saved = self.store.register_packet(packet)
                        self._touch_packet(saved or packet)
                        self._broadcast_packet(saved or packet)
                except Exception:
                    LOGGER.exception("Error al guardar eventos de listeners")
                finally:
                    for _ in batch:
                        self._event_queue.task_done()
        finally:
            if conn is not None:
                try:
                    conn.commit()
                except Exception:
                    pass

    def _insert_event_row(self, conn: sqlite3.Connection, packet: dict, meta: dict):
        payload = _normalize_payload(packet.get("raw_packet") or packet.get("payload_text") or b"")
        event_time = str(packet.get("created_at") or utc_now())
        proto = normalize_protocol_name(packet.get("proto"))
        src_ip = str(packet.get("src_ip") or "").strip()
        src_port = safe_int(packet.get("src_port", 0), 0)
        dst_port = safe_int(packet.get("dst_port", 0), 0)
        conn.execute(
            """
            INSERT INTO connection_events
            (event_time, protocol, dst_port, src_ip, src_port, data_len, data_preview, data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_time,
                proto,
                dst_port,
                src_ip,
                src_port,
                safe_int(packet.get("length") or len(payload), 0),
                bytes_to_hex_preview(payload),
                sqlite3.Binary(payload),
            ),
        )
        tls = meta.get("tls") if isinstance(meta, dict) else None
        if isinstance(tls, dict):
            peer_cert = tls.get("peer_cert") or b""
            if isinstance(peer_cert, str):
                peer_cert = peer_cert.encode("utf-8", errors="replace")
            conn.execute(
                """
                INSERT INTO tls_sessions
                (event_time, src_ip, src_port, dst_port, tls_version, cipher_name, cipher_protocol, cipher_bits, alpn, sni, peer_cert)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_time,
                    src_ip,
                    src_port,
                    dst_port,
                    str(tls.get("tls_version") or ""),
                    str(tls.get("cipher_name") or ""),
                    str(tls.get("cipher_protocol") or ""),
                    safe_int(tls.get("cipher_bits"), 0),
                    str(tls.get("alpn") or ""),
                    str(tls.get("sni") or ""),
                    sqlite3.Binary(bytes(peer_cert)),
                ),
            )
        dns = meta.get("dns") if isinstance(meta, dict) else None
        if isinstance(dns, dict):
            for question in dns.get("questions") or []:
                if not isinstance(question, dict):
                    continue
                conn.execute(
                    """
                    INSERT INTO dns_queries
                    (event_time, src_ip, src_port, dst_port, domain, query_type, response_ip)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event_time,
                        src_ip,
                        src_port,
                        dst_port,
                        str(question.get("domain") or ""),
                        safe_int(question.get("qtype"), 0),
                        str(dns.get("response_ip") or "127.0.0.1"),
                    ),
                )
        conn.commit()

    def _broadcast_packet(self, packet: dict):
        self.hub.broadcast({"type": "packet", "packet": packet, "generated_at": utc_now()})
        self.hub.broadcast(
            {
                "type": "stats_update",
                "stats": {
                    "packets_seen": self._state.packets_seen,
                    "packets_total_bytes": self._state.packets_total_bytes,
                    "mode": "honeypot",
                },
                "generated_at": utc_now(),
            }
        )

    def _listener_view(self, row: dict) -> dict:
        listener_id = str(row.get("id") or "")
        thread = self._listener_threads.get(listener_id)
        return {
            "id": listener_id,
            "proto": row.get("proto"),
            "port": row.get("port"),
            "label": row.get("label") or "",
            "enabled": bool(row.get("enabled")),
            "source": row.get("source") or "builtin",
            "running": bool(thread is not None and thread.is_alive()),
        }

    def snapshot(self, *, include_listeners: bool = True) -> dict:
        listener_rows = self.store.list_honeypot_listeners() if include_listeners else []
        listeners = []
        for row in listener_rows:
            listeners.append(self._listener_view(row))
        listener_counts = {}
        count_honeypot_listeners = getattr(self.store, "count_honeypot_listeners", None)
        if callable(count_honeypot_listeners):
            listener_counts = count_honeypot_listeners()
        else:
            listener_counts = {
                "total": len(listeners),
                "enabled": sum(1 for item in listeners if item.get("enabled")),
                "custom": sum(1 for item in listeners if item.get("source") == "custom"),
            }
        running_listener_count = sum(1 for thread in self._listener_threads.values() if thread.is_alive())
        with self._state_lock:
            return {
                "running": bool(self._state.running),
                "mode": "honeypot",
                "errors": dict(self._state.errors),
                "listeners": listeners,
                "listener_count": safe_int(listener_counts.get("total"), len(listeners)),
                "enabled_listener_count": safe_int(listener_counts.get("enabled"), 0),
                "custom_listener_count": safe_int(listener_counts.get("custom"), 0),
                "running_listener_count": running_listener_count,
                "packets_seen": int(self._state.packets_seen),
                "packets_total_bytes": int(self._state.packets_total_bytes),
                "started_at": self._state.started_at,
                "last_event_at": self._state.last_event_at,
                "session_id": int(self._state.session_id),
                "active_threads": running_listener_count + (1 if self._writer_thread and self._writer_thread.is_alive() else 0),
                "log_file": str(LOG_FILE),
                "event_db": str(EVENT_DB_FILE),
                "tls_ready": self._tls_context is not None,
            }

    def start(self):
        with self._state_lock:
            if self._state.running:
                return self.snapshot()
            self._stop_event.clear()
            self._state.running = True
            self._state.errors = {}
            self._state.packets_seen = 0
            self._state.packets_total_bytes = 0
            self._state.started_at = utc_now()
            self._state.last_event_at = ""

        self._session_id()
        self._writer_thread = threading.Thread(target=self._event_writer, name="sniff4hound-listener-writer", daemon=True)
        self._writer_thread.start()

        # Binding every enabled listener (TLS setup + one bind()/thread
        # spawn per port) runs on a background thread so this call - and
        # the IPC dispatch loop that's synchronously blocked on it - return
        # immediately. With hundreds of enabled listeners the sequential
        # bind loop used to take long enough to starve unrelated IPC calls
        # (e.g. runtime.snapshot() on every dashboard/WS connect), which is
        # what made the app appear to hang right after starting the
        # honeypot. `running` is already true above so callers can poll
        # snapshot() to watch `running_listener_count` climb.
        self._start_thread = threading.Thread(target=self._start_listeners, name="sniff4hound-honeypot-start", daemon=True)
        self._start_thread.start()

        return self.snapshot()

    def _start_listeners(self):
        try:
            self._tls_context = self._create_tls_context()
            LOGGER.info("TLS habilitado con certificados %s y %s", CERT_FILE, KEY_FILE)
        except Exception as error:
            self._tls_context = None
            self._set_error("tls", str(error))
            LOGGER.exception("No se pudo inicializar TLS")

        started = 0
        for listener in self.store.list_honeypot_listeners():
            if self._stop_event.is_set():
                break
            if not listener.get("enabled"):
                continue
            if self._spawn_listener(listener["id"], listener["proto"], listener["port"]):
                started += 1

        LOGGER.info("Motor de listeners activo en %s con %s listeners", self.bind_host, started)

    def stop(self):
        self._stop_event.set()
        with self._state_lock:
            self._state.running = False
        # start() may still be mid-flight spawning listeners on its own
        # background thread; it checks _stop_event between listeners and
        # exits promptly once it sees it, but wait it out (briefly) so the
        # listener_ids snapshot below isn't taken mid-spawn and doesn't miss
        # a listener that starts right after.
        if self._start_thread and self._start_thread.is_alive():
            self._start_thread.join(timeout=2.0)
        # Signal every listener's stop_event before joining any of them -
        # each listener thread only notices within its own ~1s accept()/
        # recvfrom() timeout, so joining sequentially (signal, join, signal,
        # join, ...) made total shutdown time scale with the listener count
        # (dozens of listener ports -> tens of seconds, well past the IPC
        # call timeout). Signalling all of them up front means they all
        # start winding down concurrently and the joins below just wait out
        # the shared ~1s grace period once.
        listener_ids = list(self._listener_threads.keys())
        for listener_id in listener_ids:
            stop_event = self._listener_stop_events.pop(listener_id, None)
            if stop_event is not None:
                stop_event.set()
        for listener_id in listener_ids:
            thread = self._listener_threads.pop(listener_id, None)
            if thread is not None and thread.is_alive():
                thread.join(timeout=1.5)
        if self._writer_thread and self._writer_thread.is_alive():
            self._writer_thread.join(timeout=1.2)
        self._writer_thread = None
        self._close_event_db()
        try:
            session_id = int(self._state.session_id or 0)
            if session_id:
                self.store.set_session_status(session_id, "stopped")
        except Exception:
            pass
        return self.snapshot()

    def restart(self):
        self.stop()
        return self.start()

    def _bootstrap_self_signed_cert(self):
        if CERT_FILE.is_file() and KEY_FILE.is_file():
            return
        openssl_path = shutil.which("openssl")
        if not openssl_path:
            return
        command = [
            openssl_path, "req", "-x509", "-nodes",
            "-newkey", "rsa:2048",
            "-keyout", str(KEY_FILE),
            "-out", str(CERT_FILE),
            "-days", "825",
            "-subj", "/O=Local Services/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
        ]
        try:
            subprocess.run(command, check=True, capture_output=True, timeout=15)
        except Exception:
            # Older OpenSSL builds may not support -addext; retry without SAN.
            try:
                subprocess.run(command[:-2], check=True, capture_output=True, timeout=15)
            except Exception as error:
                LOGGER.warning("No se pudo autogenerar el certificado TLS con OpenSSL: %s", error)
                return
        try:
            KEY_FILE.chmod(0o600)
        except Exception:
            pass
        LOGGER.info("Certificado TLS autogenerado con OpenSSL: %s, %s", CERT_FILE, KEY_FILE)

    def _create_tls_context(self):
        self._bootstrap_self_signed_cert()
        if not CERT_FILE.is_file() or not KEY_FILE.is_file():
            raise FileNotFoundError(
                f"No se encontraron certificados TLS: {CERT_FILE} y/o {KEY_FILE}. "
                "Generalos con OpenSSL o copia un par PEM valido."
            )
        tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls_context.minimum_version = ssl.TLSVersion.TLSv1_2
        tls_context.load_cert_chain(certfile=str(CERT_FILE), keyfile=str(KEY_FILE))
        tls_context.set_servername_callback(self._remember_tls_sni)
        return tls_context

    def _remember_tls_sni(self, ssl_sock, server_name, _ssl_context):
        if not server_name:
            return
        try:
            fileno = ssl_sock.fileno()
        except Exception:
            return
        with self._tls_sni_lock:
            self._tls_sni_map[fileno] = server_name

    def _capture_tls_session(self, addr, port: int, tls_sock):
        cipher = tls_sock.cipher() or ("", "", None)
        tls_version = tls_sock.version() or ""
        alpn = tls_sock.selected_alpn_protocol() or ""
        peer_cert = b""
        try:
            peer_cert = tls_sock.getpeercert(binary_form=True) or b""
        except Exception:
            peer_cert = b""

        sni = ""
        try:
            fileno = tls_sock.fileno()
            with self._tls_sni_lock:
                sni = self._tls_sni_map.pop(fileno, "") or ""
        except Exception:
            sni = ""

        summary = (
            f"TLS session version={tls_version or '-'} "
            f"cipher={cipher[0] if len(cipher) > 0 else '-'} "
            f"protocol={cipher[1] if len(cipher) > 1 else '-'} "
            f"bits={cipher[2] if len(cipher) > 2 else '-'} "
            f"sni={sni or '-'} alpn={alpn or '-'}"
        )
        LOGGER.info("%s:%s -> %s", addr[0], addr[1], summary)
        return {
            "tls_version": tls_version,
            "cipher_name": cipher[0] if len(cipher) > 0 else "",
            "cipher_protocol": cipher[1] if len(cipher) > 1 else "",
            "cipher_bits": cipher[2] if len(cipher) > 2 else None,
            "alpn": alpn,
            "sni": sni,
            "peer_cert": peer_cert,
            "summary": summary,
        }

    def _socket_listener_ip(self, sock, peer_ip: str) -> str:
        try:
            local_ip = sock.getsockname()[0]
            if local_ip and local_ip != "0.0.0.0":
                return local_ip
        except Exception:
            pass
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe_sock:
                probe_sock.connect((peer_ip, 53))
                local_ip = probe_sock.getsockname()[0]
                if local_ip:
                    return local_ip
        except Exception:
            pass
        return "127.0.0.1"

    def _build_packet(
        self,
        *,
        protocol: str,
        port: int,
        addr,
        data=None,
        banner_text: str = "",
        summary: str = "",
        meta: dict[str, Any] | None = None,
    ) -> dict:
        payload = _normalize_payload(data)
        payload_text = bytes_to_text_preview(payload, limit=PAYLOAD_TEXT_MAX_CHARS)
        listener_ip = self.bind_host if self.bind_host not in {"0.0.0.0", "::"} else "127.0.0.1"
        packet = {
            "session_id": self._session_id(),
            "interface": f"honeypot:{port}",
            "direction": "inbound",
            "eth_src": "",
            "eth_dst": "",
            "eth_type": 0,
            "ip_version": 4,
            "src_ip": addr[0],
            "dst_ip": listener_ip,
            "proto": normalize_protocol_name(protocol),
            "src_port": addr[1],
            "dst_port": port,
            "ttl": 64,
            "hop_limit": 0,
            "length": len(payload),
            "payload_len": len(payload),
            "state": "open",
            "scan_state": "active",
            "tcp_flags": "",
            "icmp_type": 0,
            "icmp_code": 0,
            "arp_opcode": 0,
            "summary": normalize_text(summary or banner_text or f"{protocol.upper()} honeypot", limit=PAYLOAD_TEXT_MAX_CHARS),
            "payload_text": normalize_text(payload_text, limit=PAYLOAD_TEXT_MAX_CHARS),
            "payload_hex": bytes_to_hex_preview(payload),
            "banner_text": normalize_text(banner_text or summary or payload_text, limit=PAYLOAD_TEXT_MAX_CHARS),
            "tags": [
                {"key": "mode", "value": "honeypot"},
                {"key": "service", "value": normalize_protocol_name(protocol)},
                {"key": "port", "value": str(port)},
                # A "monitor"/"monitor_id" pair, same shape Sniffer's monitor
                # engine emits - this is what the frontend's notifyForPacketEvent
                # (appStore.js) scans for to pop a toast/notification. Honeypot
                # traffic never runs through evaluate_packet/AnomalyEngine (a
                # separate pipeline by design), so this is added directly here
                # rather than via a DEFAULT_MONITORS catalog entry - there's no
                # declarative match to toggle, every honeypot hit is inherently
                # notable. "critical" severity clears NOTIFY_MONITOR_SEVERITIES
                # so it always toasts, matching the Sniffer-side "alert me"
                # behavior for high/critical monitors.
                {"key": "monitor", "value": "Honeypot hit", "severity": "critical"},
                {"key": "monitor_id", "value": "builtin-honeypot-hit", "severity": "critical"},
            ],
            "rule_hits": [
                {
                    "rule_id": "honeypot",
                    "rule_name": "Honeypot",
                    "tag": "honeypot",
                    "label": "Honeypot",
                    "severity": "high",
                }
            ],
            "raw_packet": payload,
            "created_at": utc_now(),
            "updated_at": utc_now(),
        }
        if meta:
            packet["listener_meta"] = meta
            if meta.get("tls"):
                packet["tags"].append({"key": "tls", "value": "enabled"})
            if meta.get("sni"):
                packet["tags"].append({"key": "sni", "value": str(meta.get("sni"))})
        return packet

    def _emit_packet(self, packet: dict):
        self._event_queue.put({"packet": packet, "meta": packet.get("listener_meta") or {}})

    def _resolve_bind_hosts(self) -> list[str]:
        """Which local addresses a listener should bind to. The wildcard
        default (bind_host="0.0.0.0"/"::") is expanded to every host IPv4
        address except loopback, so the honeypot never answers on
        127.0.0.0/8; an explicit non-wildcard bind_host is used as-is. If
        no non-loopback address can be discovered (e.g. an isolated
        sandbox with only "lo"), fall back to the wildcard bind so the
        honeypot still starts rather than silently binding nothing."""
        if self.bind_host not in {"0.0.0.0", "::"}:
            return [self.bind_host]
        hosts = _discover_host_ipv4_addresses()
        if not hosts:
            LOGGER.warning(
                "No se encontraron IPs no loopback en el host; fallback a %s", self.bind_host
            )
            return [self.bind_host]
        return hosts

    def _listen(self, port: int, handler, *, udp: bool = False, stop_event: threading.Event):
        sock_type = socket.SOCK_DGRAM if udp else socket.SOCK_STREAM
        hosts = self._resolve_bind_hosts()
        sockets: list[socket.socket] = []
        for host in hosts:
            sock = socket.socket(socket.AF_INET, sock_type)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind((host, port))
            except Exception as error:
                self._set_error(f"{'udp' if udp else 'tcp'}/{port}@{host}", f"bind failed: {error}")
                LOGGER.exception("No se pudo enlazar %s:%s", host, port)
                sock.close()
                continue
            if not udp:
                sock.listen(20)
            sockets.append(sock)

        if not sockets:
            return

        try:
            if not udp:
                LOGGER.info("TCP listener activo en %s:%s (%d IP(s))", hosts, port, len(sockets))
                while not stop_event.is_set():
                    try:
                        ready, _, _ = select.select(sockets, [], [], 1.0)
                    except OSError:
                        if stop_event.is_set():
                            break
                        continue
                    for ready_sock in ready:
                        try:
                            client, addr = ready_sock.accept()
                        except OSError as error:
                            if stop_event.is_set():
                                break
                            self._set_error(f"tcp/{port}", str(error))
                            continue
                        threading.Thread(target=handler, args=(client, addr, port), daemon=True).start()
            else:
                LOGGER.info("UDP listener activo en %s:%s (%d IP(s))", hosts, port, len(sockets))
                while not stop_event.is_set():
                    try:
                        ready, _, _ = select.select(sockets, [], [], 1.0)
                    except OSError:
                        if stop_event.is_set():
                            break
                        continue
                    for ready_sock in ready:
                        try:
                            data, addr = ready_sock.recvfrom(MAX_PACKET_SIZE)
                        except OSError as error:
                            if stop_event.is_set():
                                break
                            self._set_error(f"udp/{port}", str(error))
                            continue
                        if data:
                            handler(ready_sock, addr, port, data)
        finally:
            for sock in sockets:
                try:
                    sock.close()
                except Exception:
                    pass

    def _tcp_listener(self, port: int, stop_event: threading.Event, tls_context=None):
        if tls_context is not None:
            self._listen(
                port,
                lambda client, addr, p: self._handle_tcp(client, addr, p, tls_context=tls_context),
                stop_event=stop_event,
            )
        else:
            self._listen(port, self._handle_tcp, stop_event=stop_event)

    def _udp_listener(self, port: int, stop_event: threading.Event):
        self._listen(port, self._handle_udp, udp=True, stop_event=stop_event)

    def _spawn_listener(self, listener_id: str, proto: str, port: int) -> bool:
        """Start a single listener's thread, if it isn't already running.
        Returns False (with an error recorded) only for a TCP/TLS listener
        whose TLS context isn't ready - every other failure surfaces later,
        from inside the thread, via `_set_error` (bind failures etc.)."""
        existing = self._listener_threads.get(listener_id)
        if existing is not None and existing.is_alive():
            return True
        stop_event = threading.Event()
        if proto == "tcp":
            tls_context = self._tls_context if port in TLS_TCP_PORTS else None
            if port in TLS_TCP_PORTS and tls_context is None:
                self._set_error(listener_id, "TLS context unavailable")
                return False
            thread = threading.Thread(
                target=self._tcp_listener,
                args=(port, stop_event, tls_context),
                name=f"sniff4hound-listener-tcp-{port}",
                daemon=True,
            )
        else:
            thread = threading.Thread(
                target=self._udp_listener,
                args=(port, stop_event),
                name=f"sniff4hound-listener-udp-{port}",
                daemon=True,
            )
        self._listener_stop_events[listener_id] = stop_event
        thread.start()
        self._listener_threads[listener_id] = thread
        return True

    def _stop_listener_thread(self, listener_id: str):
        stop_event = self._listener_stop_events.pop(listener_id, None)
        if stop_event is not None:
            stop_event.set()
        thread = self._listener_threads.pop(listener_id, None)
        if thread is not None and thread.is_alive():
            thread.join(timeout=1.5)

    def set_listener_enabled(self, listener_id: str, enabled: bool) -> dict:
        """The only way to change a listener after creation - flips its
        stored `enabled` flag and, if the engine is currently running,
        starts/stops its live thread to match immediately. Never edits the
        listener's proto/port, and there is no delete."""
        listener = self.store.set_honeypot_listener_enabled(listener_id, enabled)
        with self._state_lock:
            running = bool(self._state.running)
        if running:
            if enabled:
                self._spawn_listener(listener["id"], listener["proto"], listener["port"])
            else:
                self._stop_listener_thread(listener_id)
        return self.snapshot()

    def create_listener(self, proto: str, port: int, label: str = "") -> dict:
        """Add a brand-new listener (always starts enabled). If the engine
        is currently running, its thread starts immediately; otherwise it
        joins the roster the next time `start()` runs."""
        listener = self.store.create_honeypot_listener(proto, port, label)
        with self._state_lock:
            running = bool(self._state.running)
        if running:
            self._spawn_listener(listener["id"], listener["proto"], listener["port"])
        return self.snapshot()

    def _handle_tcp(self, client_sock, addr, port, tls_context=None):
        wrapped_sock = client_sock
        meta: dict[str, Any] = {}
        use_tls = tls_context is not None
        try:
            if use_tls:
                wrapped_sock = tls_context.wrap_socket(client_sock, server_side=True)
                meta["tls"] = self._capture_tls_session(addr, port, wrapped_sock)

            if port in HTTP_TCP_PORTS or port in HTTPS_TCP_PORTS:
                self._handle_http_service(wrapped_sock, addr, port, use_tls=use_tls, meta=meta)
            elif port in FTP_PORTS or port in FTPS_PORTS:
                self._handle_ftp_service(wrapped_sock, addr, port, use_tls=use_tls, meta=meta)
            elif port in SMTP_PORTS or port in SMTPS_PORTS:
                self._handle_smtp_service(wrapped_sock, addr, port, use_tls=use_tls, meta=meta)
            elif port in POP3_PORTS or port in POP3S_PORTS:
                self._handle_pop3_service(wrapped_sock, addr, port, use_tls=use_tls, meta=meta)
            elif port in IMAP_PORTS or port in IMAPS_PORTS:
                self._handle_imap_service(wrapped_sock, addr, port, use_tls=use_tls, meta=meta)
            elif port in TELNET_PORTS:
                self._handle_telnet_service(wrapped_sock, addr, port, meta=meta)
            elif port in SSH_PORTS:
                self._handle_ssh_service(wrapped_sock, addr, port, meta=meta)
            elif port in MYSQL_PORTS:
                self._handle_mysql_service(wrapped_sock, addr, port, meta=meta)
            elif port in POSTGRES_PORTS:
                self._handle_postgres_service(wrapped_sock, addr, port, meta=meta)
            elif port in REDIS_PORTS:
                self._handle_redis_service(wrapped_sock, addr, port, meta=meta)
            elif port in MEMCACHED_TCP_PORTS:
                self._handle_memcached_service(wrapped_sock, addr, port, meta=meta)
            elif port in VNC_PORTS:
                self._handle_vnc_service(wrapped_sock, addr, port, meta=meta)
            elif port in MQTT_PORTS or port in MQTTS_PORTS:
                self._handle_mqtt_service(wrapped_sock, addr, port, use_tls=use_tls, meta=meta)
            elif port in AMQP_PORTS or port in AMQPS_PORTS:
                self._handle_amqp_service(wrapped_sock, addr, port, use_tls=use_tls, meta=meta)
            elif port in LDAP_PORTS or port in LDAPS_PORTS:
                self._handle_ldap_service(wrapped_sock, addr, port, use_tls=use_tls, meta=meta)
            elif port in RTSP_PORTS:
                self._handle_rtsp_service(wrapped_sock, addr, port, meta=meta)
            elif port in DNS_TCP_PORTS:
                self._handle_dns_tcp_service(wrapped_sock, addr, port, meta=meta)
            elif port in MONGODB_PORTS:
                self._handle_mongodb_service(wrapped_sock, addr, port, meta=meta)
            elif port in SMB_PORTS:
                self._handle_smb_service(wrapped_sock, addr, port, meta=meta)
            elif port in RDP_PORTS:
                self._handle_rdp_service(wrapped_sock, addr, port, meta=meta)
            else:
                self._handle_generic_tcp(wrapped_sock, addr, port, use_tls=use_tls, meta=meta)
        except ssl.SSLError as error:
            LOGGER.info("TLS error en puerto %s: %s", port, error)
            self._set_error(f"tls/{port}", str(error))
        except Exception as error:
            LOGGER.exception("TCP Error en puerto %s", port)
            self._set_error(f"tcp/{port}", str(error))
        finally:
            try:
                wrapped_sock.close()
            except Exception:
                pass

    def _handle_http_service(self, client_sock, addr, port, *, use_tls=False, meta=None):
        request_data = b""
        try:
            request_data = _read_http_request(client_sock)
        except Exception:
            request_data = b""
        scheme = "HTTPS" if use_tls else "HTTP"
        if request_data:
            request_line = request_data.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
            LOGGER.info("%s %s %s -> %s", scheme, addr[0], addr[1], request_line)
        body = (
            "<html><head><title>It works</title>"
            '<link rel="icon" type="image/x-icon" href="/favicon.ico"></head>'
            "<body><h1>It works</h1><p>Default server page.</p></body></html>"
        ).encode("utf-8")
        response = _build_http_response(200, "OK", body, "text/html; charset=utf-8")
        if request_data:
            path = "/"
            request_line = request_data.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
            parts = request_line.split()
            if len(parts) >= 2:
                path = parts[1]
            if path == "/favicon.ico":
                response = _build_http_response(200, "OK", FAVICON_ICO, "image/x-icon")
        _safe_send(client_sock, response)
        packet = self._build_packet(
            protocol="tcp",
            port=port,
            addr=addr,
            data=request_data or b"(sin datos)",
            banner_text=f"{scheme} response",
            summary=f"{scheme} response",
            meta=meta,
        )
        self._emit_packet(packet)

    def _handle_ftp_service(self, client_sock, addr, port, *, use_tls=False, meta=None):
        banner = TCP_BANNERS.get(port, "220 ProFTPD 1.3.5 Server ready\r\n")
        _safe_send(client_sock, banner)
        client_sock.settimeout(READ_TIMEOUT_SECONDS)
        saw_data = b""
        for _ in range(MAX_COMMAND_ROUNDS):
            line = _recv_line(client_sock)
            if not line:
                break
            saw_data += line
            command = _decode_line(line).split(" ", 1)[0].upper()
            if command == "USER":
                _safe_send(client_sock, b"331 Password required\r\n")
            elif command == "PASS":
                _safe_send(client_sock, b"230 Login successful\r\n")
            elif command == "SYST":
                _safe_send(client_sock, b"215 UNIX Type: L8\r\n")
            elif command in {"PWD", "XPWD"}:
                _safe_send(client_sock, b'257 "/" is current directory\r\n')
            elif command == "QUIT":
                _safe_send(client_sock, b"221 Goodbye\r\n")
                break
            else:
                _safe_send(client_sock, b"502 Command not implemented\r\n")
        packet = self._build_packet(
            protocol="tcp",
            port=port,
            addr=addr,
            data=saw_data or b"(sin datos)",
            banner_text="FTP banner",
            summary="FTP session",
            meta=meta,
        )
        self._emit_packet(packet)

    def _handle_smtp_service(self, client_sock, addr, port, *, use_tls=False, meta=None):
        banner = TCP_BANNERS.get(port, "220 mx01.local ESMTP Postfix\r\n")
        _safe_send(client_sock, banner)
        client_sock.settimeout(READ_TIMEOUT_SECONDS)
        buffer = b""
        in_data_mode = False
        for _ in range(MAX_COMMAND_ROUNDS * 2):
            line_bytes = _recv_line(client_sock)
            if not line_bytes:
                break
            buffer += line_bytes
            line = _decode_line(line_bytes)
            if in_data_mode:
                if line == ".":
                    _safe_send(client_sock, b"250 2.0.0 Message queued as A1B2C3D4E5\r\n")
                    in_data_mode = False
                continue
            command = line.split(" ", 1)[0].upper() if line else ""
            if command in {"EHLO", "HELO"}:
                _safe_send(client_sock, b"250-mx01.local Hello\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n250-8BITMIME\r\n250 HELP\r\n")
            elif command in {"MAIL", "RCPT", "RSET", "NOOP"}:
                _safe_send(client_sock, b"250 2.1.0 Ok\r\n")
            elif command == "DATA":
                _safe_send(client_sock, b"354 End data with <CR><LF>.<CR><LF>\r\n")
                in_data_mode = True
            elif command == "STARTTLS":
                _safe_send(client_sock, b"454 4.7.0 TLS not available in this session\r\n")
            elif command == "QUIT":
                _safe_send(client_sock, b"221 2.0.0 Bye\r\n")
                break
            else:
                _safe_send(client_sock, b"500 5.5.2 Error: command not recognized\r\n")
        packet = self._build_packet(
            protocol="tcp",
            port=port,
            addr=addr,
            data=buffer or b"(sin datos)",
            banner_text="SMTP banner",
            summary="SMTP session",
            meta=meta,
        )
        self._emit_packet(packet)

    def _handle_pop3_service(self, client_sock, addr, port, *, use_tls=False, meta=None):
        _safe_send(client_sock, TCP_BANNERS.get(port, "+OK Dovecot ready.\r\n"))
        client_sock.settimeout(READ_TIMEOUT_SECONDS)
        buffer = b""
        for _ in range(MAX_COMMAND_ROUNDS):
            line = _recv_line(client_sock)
            if not line:
                break
            buffer += line
            command = _decode_line(line).split(" ", 1)[0].upper()
            if command == "USER":
                _safe_send(client_sock, b"+OK user accepted\r\n")
            elif command == "PASS":
                _safe_send(client_sock, b"+OK mailbox has 2 messages (320 octets)\r\n")
            elif command == "STAT":
                _safe_send(client_sock, b"+OK 2 320\r\n")
            elif command == "LIST":
                _safe_send(client_sock, b"+OK 2 messages\r\n1 120\r\n2 200\r\n.\r\n")
            elif command == "QUIT":
                _safe_send(client_sock, b"+OK Goodbye\r\n")
                break
            else:
                _safe_send(client_sock, b"-ERR Unknown command\r\n")
        packet = self._build_packet(protocol="tcp", port=port, addr=addr, data=buffer or b"(sin datos)", banner_text="POP3 banner", summary="POP3 session", meta=meta)
        self._emit_packet(packet)

    def _handle_imap_service(self, client_sock, addr, port, *, use_tls=False, meta=None):
        _safe_send(client_sock, TCP_BANNERS.get(port, "* OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR IDLE AUTH=PLAIN] Dovecot ready.\r\n"))
        client_sock.settimeout(READ_TIMEOUT_SECONDS)
        buffer = b""
        for _ in range(MAX_COMMAND_ROUNDS):
            line = _recv_line(client_sock)
            if not line:
                break
            buffer += line
            text = _decode_line(line)
            parts = text.split()
            tag = parts[0] if parts else "A000"
            command = parts[1].upper() if len(parts) > 1 else ""
            if command == "CAPABILITY":
                _safe_send(client_sock, b"* CAPABILITY IMAP4rev1 AUTH=PLAIN IDLE\r\n")
                _safe_send(client_sock, f"{tag} OK CAPABILITY completed\r\n".encode())
            elif command == "LOGIN":
                _safe_send(client_sock, f"{tag} OK LOGIN completed\r\n".encode())
            elif command == "LOGOUT":
                _safe_send(client_sock, b"* BYE Logging out\r\n")
                _safe_send(client_sock, f"{tag} OK LOGOUT completed\r\n".encode())
                break
            else:
                _safe_send(client_sock, f"{tag} BAD Command not supported\r\n".encode())
        packet = self._build_packet(protocol="tcp", port=port, addr=addr, data=buffer or b"(sin datos)", banner_text="IMAP banner", summary="IMAP session", meta=meta)
        self._emit_packet(packet)

    def _handle_telnet_service(self, client_sock, addr, port, *, meta=None):
        _safe_send(client_sock, TCP_BANNERS.get(port, "Debian GNU/Linux 12 ttyS0\r\nlogin: "))
        client_sock.settimeout(READ_TIMEOUT_SECONDS)
        buffer = b""
        username = _recv_line(client_sock)
        if username:
            buffer += username
            _safe_send(client_sock, b"Password: ")
            password = _recv_line(client_sock)
            if password:
                buffer += password
        _safe_send(client_sock, b"\r\nLogin incorrect\r\nConnection closed by foreign host.\r\n")
        packet = self._build_packet(protocol="tcp", port=port, addr=addr, data=buffer or b"(sin datos)", banner_text="Telnet banner", summary="Telnet login", meta=meta)
        self._emit_packet(packet)

    def _handle_ssh_service(self, client_sock, addr, port, *, meta=None):
        _safe_send(client_sock, TCP_BANNERS.get(port, "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3\r\n"))
        client_sock.settimeout(READ_TIMEOUT_SECONDS)
        data = b""
        try:
            data = client_sock.recv(MAX_PACKET_SIZE)
            if data:
                LOGGER.info("SSH packet from %s:%s", addr[0], addr[1])
        except socket.timeout:
            pass
        packet = self._build_packet(protocol="tcp", port=port, addr=addr, data=data or b"(sin datos)", banner_text="SSH banner", summary="SSH handshake", meta=meta)
        self._emit_packet(packet)

    def _handle_mysql_service(self, client_sock, addr, port, *, meta=None):
        protocol_payload = (
            b"\x0a"
            b"8.0.30-0ubuntu0.20.04.2\x00"
            b"\x01\x00\x00\x00"
            b"abcdefgh\x00"
            b"\xff\xf7"
            b"\x21"
            b"\x02\x00"
            b"\xff\xdf"
            b"\x15"
            + (b"\x00" * 10)
            + b"ijklmnopqrstuvwx\x00"
            + b"mysql_native_password\x00"
        )
        _safe_send(client_sock, len(protocol_payload).to_bytes(3, "little") + b"\x00" + protocol_payload)
        client_sock.settimeout(READ_TIMEOUT_SECONDS)
        data = b""
        try:
            data = client_sock.recv(MAX_PACKET_SIZE)
            if data:
                payload = b"\xff\x15\x04#28000Access denied"
                _safe_send(client_sock, len(payload).to_bytes(3, "little") + b"\x02" + payload)
        except socket.timeout:
            pass
        packet = self._build_packet(protocol="tcp", port=port, addr=addr, data=data or b"(sin datos)", banner_text="MySQL banner", summary="MySQL handshake", meta=meta)
        self._emit_packet(packet)

    def _handle_postgres_service(self, client_sock, addr, port, *, meta=None):
        client_sock.settimeout(READ_TIMEOUT_SECONDS)
        data = b""
        try:
            data = client_sock.recv(MAX_PACKET_SIZE)
            if data:
                if len(data) >= 8 and data[:4] == b"\x00\x00\x00\x08" and data[4:8] == b"\x04\xd2\x16/":
                    _safe_send(client_sock, b"N")
                    data += client_sock.recv(MAX_PACKET_SIZE)
                _safe_send(client_sock, _build_postgres_error_packet())
        except socket.timeout:
            pass
        packet = self._build_packet(protocol="tcp", port=port, addr=addr, data=data or b"(sin datos)", banner_text="PostgreSQL banner", summary="Postgres handshake", meta=meta)
        self._emit_packet(packet)

    def _handle_redis_service(self, client_sock, addr, port, *, meta=None):
        _safe_send(client_sock, TCP_BANNERS.get(port, b"-NOAUTH Authentication required.\r\n"))
        client_sock.settimeout(READ_TIMEOUT_SECONDS)
        data = b""
        for _ in range(MAX_COMMAND_ROUNDS):
            try:
                chunk = client_sock.recv(MAX_PACKET_SIZE)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
            upper_data = chunk.upper()
            if b"PING" in upper_data:
                _safe_send(client_sock, b"+PONG\r\n")
            elif b"INFO" in upper_data:
                body = b"# Server\r\nredis_version:7.0.11\r\nrole:master"
                _safe_send(client_sock, b"$" + str(len(body)).encode() + b"\r\n" + body + b"\r\n")
            elif b"SET" in upper_data:
                _safe_send(client_sock, b"+OK\r\n")
            elif b"GET" in upper_data:
                _safe_send(client_sock, b"$-1\r\n")
            elif b"QUIT" in upper_data:
                _safe_send(client_sock, b"+OK\r\n")
                break
            else:
                _safe_send(client_sock, b"-ERR unknown command\r\n")
        packet = self._build_packet(protocol="tcp", port=port, addr=addr, data=data or b"(sin datos)", banner_text="Redis banner", summary="Redis session", meta=meta)
        self._emit_packet(packet)

    def _handle_memcached_service(self, client_sock, addr, port, *, meta=None):
        _safe_send(client_sock, b"STAT pid 2134\r\nEND\r\n")
        client_sock.settimeout(READ_TIMEOUT_SECONDS)
        data = b""
        for _ in range(MAX_COMMAND_ROUNDS):
            line = _recv_line(client_sock)
            if not line:
                break
            data += line
            parts = _decode_line(line).split()
            command = parts[0].lower() if parts else ""
            if command == "version":
                _safe_send(client_sock, b"VERSION 1.6.9\r\n")
            elif command == "stats":
                _safe_send(client_sock, b"STAT version 1.6.9\r\nSTAT uptime 86400\r\nEND\r\n")
            elif command == "get":
                _safe_send(client_sock, b"END\r\n")
            elif command in {"set", "add", "replace"}:
                _safe_send(client_sock, b"STORED\r\n")
            elif command == "quit":
                break
            else:
                _safe_send(client_sock, b"ERROR\r\n")
        packet = self._build_packet(protocol="tcp", port=port, addr=addr, data=data or b"(sin datos)", banner_text="Memcached banner", summary="Memcached session", meta=meta)
        self._emit_packet(packet)

    def _handle_vnc_service(self, client_sock, addr, port, *, meta=None):
        _safe_send(client_sock, TCP_BANNERS.get(port, b"RFB 003.008\n"))
        client_sock.settimeout(READ_TIMEOUT_SECONDS)
        data = b""
        try:
            data = client_sock.recv(MAX_PACKET_SIZE)
            if data:
                _safe_send(client_sock, b"\x01\x01")
        except socket.timeout:
            pass
        packet = self._build_packet(protocol="tcp", port=port, addr=addr, data=data or b"(sin datos)", banner_text="VNC banner", summary="VNC handshake", meta=meta)
        self._emit_packet(packet)

    def _handle_mqtt_service(self, client_sock, addr, port, *, use_tls=False, meta=None):
        client_sock.settimeout(READ_TIMEOUT_SECONDS)
        data = b""
        for _ in range(MAX_COMMAND_ROUNDS):
            try:
                packet = client_sock.recv(MAX_PACKET_SIZE)
            except socket.timeout:
                break
            if not packet:
                break
            data += packet
            packet_type = packet[0] >> 4
            if packet_type == 1:
                _safe_send(client_sock, b"\x20\x02\x00\x00")
            elif packet_type == 8:
                _safe_send(client_sock, b"\x90\x03\x00\x01\x00")
            elif packet_type == 12:
                _safe_send(client_sock, b"\xd0\x00")
            elif packet_type == 14:
                break
            else:
                _safe_send(client_sock, b"\xd0\x00")
        packet = self._build_packet(protocol="tcp", port=port, addr=addr, data=data or b"(sin datos)", banner_text="MQTT banner", summary="MQTT session", meta=meta)
        self._emit_packet(packet)

    def _handle_amqp_service(self, client_sock, addr, port, *, use_tls=False, meta=None):
        _safe_send(client_sock, TCP_BANNERS.get(port, b"AMQP\x00\x00\x09\x01"))
        client_sock.settimeout(READ_TIMEOUT_SECONDS)
        data = b""
        try:
            data = client_sock.recv(MAX_PACKET_SIZE)
            if data:
                _safe_send(client_sock, b"AMQP\x00\x00\x09\x01")
        except socket.timeout:
            pass
        packet = self._build_packet(protocol="tcp", port=port, addr=addr, data=data or b"(sin datos)", banner_text="AMQP banner", summary="AMQP session", meta=meta)
        self._emit_packet(packet)

    def _handle_ldap_service(self, client_sock, addr, port, *, use_tls=False, meta=None):
        client_sock.settimeout(READ_TIMEOUT_SECONDS)
        data = b""
        try:
            data = client_sock.recv(MAX_PACKET_SIZE)
            if data:
                _safe_send(client_sock, _build_ldap_bind_response(data))
        except socket.timeout:
            pass
        packet = self._build_packet(protocol="tcp", port=port, addr=addr, data=data or b"(sin datos)", banner_text="LDAP banner", summary="LDAP session", meta=meta)
        self._emit_packet(packet)

    def _handle_rtsp_service(self, client_sock, addr, port, *, meta=None):
        request = _read_http_request(client_sock)
        if request:
            _safe_send(client_sock, _build_rtsp_response(request.decode("utf-8", errors="replace")))
        packet = self._build_packet(protocol="tcp", port=port, addr=addr, data=request or b"(sin datos)", banner_text="RTSP banner", summary="RTSP session", meta=meta)
        self._emit_packet(packet)

    def _handle_dns_tcp_service(self, client_sock, addr, port, *, meta=None):
        client_sock.settimeout(READ_TIMEOUT_SECONDS)
        packet_data = b""
        try:
            packet = client_sock.recv(MAX_PACKET_SIZE)
            if not packet:
                return
            packet_data = packet
            if len(packet) < 2:
                return
            query_length = int.from_bytes(packet[:2], "big")
            query = packet[2:]
            while len(query) < query_length:
                chunk = client_sock.recv(MAX_PACKET_SIZE)
                if not chunk:
                    break
                query += chunk
            query = query[:query_length]
            response_ip = self._socket_listener_ip(client_sock, addr[0])
            response_body, questions = _build_dns_response(query, response_ip)
            if questions:
                domains = ", ".join(question["domain"] for question in questions)
                LOGGER.info("DNS query %s -> %s", addr[0], domains)
                if meta is None:
                    meta = {}
                meta["dns"] = {"questions": questions, "response_ip": response_ip}
            _safe_send(client_sock, len(response_body).to_bytes(2, "big") + response_body)
        except socket.timeout:
            pass
        packet = self._build_packet(protocol="tcp", port=port, addr=addr, data=packet_data or b"(sin datos)", banner_text="DNS query", summary="DNS query", meta=meta)
        self._emit_packet(packet)

    def _handle_mongodb_service(self, client_sock, addr, port, *, meta=None):
        _safe_send(
            client_sock,
            TCP_BANNERS.get(
                port,
                "It looks like you are trying to access MongoDB over HTTP on the native driver port.\n",
            ),
        )
        client_sock.settimeout(READ_TIMEOUT_SECONDS)
        data = b""
        try:
            data = client_sock.recv(MAX_PACKET_SIZE)
        except socket.timeout:
            pass
        packet = self._build_packet(protocol="tcp", port=port, addr=addr, data=data or b"(sin datos)", banner_text="MongoDB banner", summary="MongoDB session", meta=meta)
        self._emit_packet(packet)

    def _handle_smb_service(self, client_sock, addr, port, *, meta=None):
        # SMB is client-speaks-first (unlike FTP/SSH/SMTP/...), so wait for
        # the client's own Negotiate request before answering at all - a
        # server that talks before being spoken to is itself a tell.
        client_sock.settimeout(READ_TIMEOUT_SECONDS)
        request = b""
        try:
            request = client_sock.recv(MAX_PACKET_SIZE)
        except socket.timeout:
            pass
        if request:
            # Real modern Windows servers (SMB1 disabled by default since
            # Server 2012) reply with an SMB2 header even to an SMB1
            # Negotiate that advertises an "SMB 2.???" dialect string -
            # answering SMB2 unconditionally, regardless of which magic
            # (\xffSMB legacy vs \xfeSMB) the client actually opened with,
            # matches that real-world behavior rather than being a tell.
            _safe_send(client_sock, _build_smb2_negotiate_response())
        packet = self._build_packet(
            protocol="tcp", port=port, addr=addr, data=request or b"(sin datos)",
            banner_text="SMB2 negotiate response", summary="SMB negotiate", meta=meta,
        )
        self._emit_packet(packet)

    def _handle_rdp_service(self, client_sock, addr, port, *, meta=None):
        # Same client-speaks-first shape as SMB: wait for the X.224
        # Connection Request before answering with a Connection Confirm.
        client_sock.settimeout(READ_TIMEOUT_SECONDS)
        request = b""
        try:
            request = client_sock.recv(MAX_PACKET_SIZE)
        except socket.timeout:
            pass
        if request:
            _safe_send(client_sock, _build_rdp_connection_confirm())
        packet = self._build_packet(
            protocol="tcp", port=port, addr=addr, data=request or b"(sin datos)",
            banner_text="RDP connection confirm", summary="RDP negotiate", meta=meta,
        )
        self._emit_packet(packet)

    def _handle_generic_tcp(self, client_sock, addr, port, *, use_tls=False, meta=None):
        banner = TCP_BANNERS.get(port, _generic_tcp_banner(port))
        _safe_send(client_sock, banner)
        client_sock.settimeout(READ_TIMEOUT_SECONDS)
        data = b""
        for _ in range(MAX_COMMAND_ROUNDS):
            try:
                chunk = client_sock.recv(MAX_PACKET_SIZE)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
        packet = self._build_packet(protocol="tcp", port=port, addr=addr, data=data or b"(sin datos)", banner_text=str(banner), summary="Generic TCP session", meta=meta)
        self._emit_packet(packet)

    def _handle_udp(self, sock, addr, port, data: bytes):
        LOGGER.info("UDP %s:%s -> %s", addr[0], addr[1], port)
        response = self._udp_response_for(port, data, addr)
        if response:
            try:
                sock.sendto(response, addr)
            except Exception:
                pass
        meta: dict[str, Any] = {}
        if port in DNS_UDP_PORTS:
            response_ip = self._socket_listener_ip(sock, addr[0])
            _, questions = _build_dns_response(data, response_ip)
            if questions:
                meta["dns"] = {"questions": questions, "response_ip": response_ip}
        packet = self._build_packet(protocol="udp", port=port, addr=addr, data=data, banner_text="UDP datagram", summary="UDP datagram", meta=meta)
        self._emit_packet(packet)

    def _udp_response_for(self, port: int, data: bytes, addr):
        if port == 68:
            return None
        if port in DNS_UDP_PORTS:
            response_ip = self._socket_listener_ip(None, addr[0])
            response, _questions = _build_dns_response(data, response_ip)
            return response
        if port in NTP_UDP_PORTS:
            return _build_ntp_response(data)
        if port in SIP_UDP_PORTS:
            return _build_sip_response(data, addr)
        if port in SNMP_UDP_PORTS:
            return b"\x30\x29\x02\x01\x01\x04\x06public\xa2\x1c\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00\x30\x0e\x30\x0c\x06\x08+\x06\x01\x02\x01\x01\x01\x00\x05\x00"
        if port in SYSLOG_UDP_PORTS:
            return UDP_BANNERS[514].encode("utf-8")
        if port in RADIUS_UDP_PORTS:
            return str(UDP_BANNERS[port]).encode("utf-8")
        if port in MDNS_UDP_PORTS:
            return UDP_BANNERS[5353]
        banner = UDP_BANNERS.get(port)
        if banner is None:
            return None
        return banner.encode("utf-8") if isinstance(banner, str) else banner
