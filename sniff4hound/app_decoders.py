"""Content decoders for the protocols app_protocols.py can identify.

Identification only answers "what is this?". Without a decoder a slice of
SSH, NTP, LDAP or BGP traffic renders as rows of "TCP 10.0.0.1:50000 ->
10.0.0.2:22" - the protocol name is on the card but nothing on screen says
what actually happened. Each decoder here turns the first bytes of a
payload into a one-line summary and a handful of named fields, which is
what the Protocols view facets and the packet table then show.

Rules every decoder follows:

* Bounds are checked before every read. A decoder runs on attacker-supplied
  bytes, and the capture loop treats an exception as an unparseable frame,
  so a sloppy slice would turn hostile traffic into a blind spot.
* A decoder returns {} when the payload does not look like its protocol,
  rather than guessing. Port-derived identification is a best guess already
  (see app_protocols), and a wrong decode is worse than none.
* Nothing here reaches for the network or a third-party parser: stdlib byte
  handling only, per the project's capture-pipeline policy.
"""

from __future__ import annotations

from .utils import bytes_to_text_preview


MAX_LINE = 200


def _ascii_line(payload: bytes, limit: int = MAX_LINE) -> str:
    """First CR/LF-terminated line, as printable ASCII."""
    end = len(payload)
    for terminator in (b"\r\n", b"\n"):
        found = payload.find(terminator)
        if found != -1:
            end = min(end, found)
    return bytes_to_text_preview(payload[:end], limit=limit).strip()


def _header_value(payload: bytes, name: bytes, limit: int = 120) -> str:
    """Value of one header from an HTTP-shaped message, case-insensitively."""
    lowered = payload[:2048].lower()
    needle = b"\r\n" + name.lower() + b":"
    index = lowered.find(needle)
    if index == -1:
        if lowered.startswith(name.lower() + b":"):
            index = 0
            start = len(name) + 1
        else:
            return ""
    else:
        start = index + len(needle)
    end = payload.find(b"\r\n", start)
    if end == -1:
        end = min(len(payload), start + limit)
    return bytes_to_text_preview(payload[start:end], limit=limit).strip()


# --- TLS -------------------------------------------------------------------

TLS_RECORD_TYPES = {0x14: "change-cipher-spec", 0x15: "alert", 0x16: "handshake", 0x17: "application-data"}
TLS_HANDSHAKE_TYPES = {
    1: "client-hello", 2: "server-hello", 4: "new-session-ticket", 11: "certificate",
    12: "server-key-exchange", 13: "certificate-request", 14: "server-hello-done",
    15: "certificate-verify", 16: "client-key-exchange", 20: "finished",
}
TLS_VERSIONS = {0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3", 0x0300: "SSL 3.0"}


def decode_tls(payload: bytes) -> dict:
    if len(payload) < 5 or payload[0] not in TLS_RECORD_TYPES or payload[1] != 0x03:
        return {}
    record = TLS_RECORD_TYPES[payload[0]]
    version = TLS_VERSIONS.get(int.from_bytes(payload[1:3], "big"), "")
    fields = {"tls_record": record, "tls_version": version}
    if payload[0] == 0x16 and len(payload) >= 6:
        handshake = TLS_HANDSHAKE_TYPES.get(payload[5], f"type-{payload[5]}")
        fields["tls_handshake"] = handshake
        # The record-layer version of a ClientHello is pinned low for
        # compatibility; the real one is negotiated in an extension, so
        # reporting it as "the" version would be misleading.
        label = f"TLS {handshake}"
        if version and payload[5] != 1:
            label = f"{version} {handshake}"
        fields["summary"] = label
    else:
        fields["summary"] = f"{version or 'TLS'} {record}".strip()
    return fields


# --- SSH -------------------------------------------------------------------

def decode_ssh(payload: bytes) -> dict:
    if not payload.startswith(b"SSH-"):
        return {}
    banner = _ascii_line(payload)
    parts = banner.split("-", 2)
    software = parts[2] if len(parts) > 2 else ""
    return {
        "ssh_version": parts[1] if len(parts) > 1 else "",
        "ssh_software": software,
        "summary": f"SSH {banner}",
        "banner_text": banner,
    }


# --- HTTP ------------------------------------------------------------------

HTTP_METHODS = (b"GET", b"POST", b"HEAD", b"PUT", b"DELETE", b"OPTIONS", b"PATCH", b"TRACE", b"CONNECT")


def decode_http(payload: bytes) -> dict:
    if payload.startswith(b"HTTP/"):
        line = _ascii_line(payload)
        parts = line.split(" ", 2)
        status = parts[1] if len(parts) > 1 and parts[1].isdigit() else ""
        fields = {
            "http_status": status,
            "http_server": _header_value(payload, b"Server"),
            "summary": f"HTTP response {line}",
        }
        return {key: value for key, value in fields.items() if value}
    if not any(payload.startswith(method + b" ") for method in HTTP_METHODS):
        return {}
    line = _ascii_line(payload)
    parts = line.split(" ", 2)
    return {
        "http_method": parts[0] if parts else "",
        "http_path": parts[1] if len(parts) > 1 else "",
        "http_host": _header_value(payload, b"Host"),
        "http_user_agent": _header_value(payload, b"User-Agent"),
        "summary": f"HTTP {line}",
    }


# --- NTP -------------------------------------------------------------------

NTP_MODES = {
    0: "reserved", 1: "symmetric-active", 2: "symmetric-passive", 3: "client",
    4: "server", 5: "broadcast", 6: "control", 7: "private",
}


def decode_ntp(payload: bytes) -> dict:
    if len(payload) < 4:
        return {}
    flags = payload[0]
    mode = NTP_MODES.get(flags & 0x07, "unknown")
    version = (flags >> 3) & 0x07
    stratum = payload[1]
    fields = {"ntp_mode": mode, "ntp_version": version, "ntp_stratum": stratum}
    # Mode 7 is the vendor-private space that carries monlist, the request
    # behind the classic ~500x NTP amplification attack. Worth calling out by
    # name rather than reporting a bare "mode 7".
    if (flags & 0x07) == 7:
        fields["summary"] = "NTP private/monlist request (amplification vector)"
        fields["ntp_amplification_candidate"] = True
    else:
        fields["summary"] = f"NTP v{version} {mode} stratum {stratum}"
    return fields


# --- Line-oriented text protocols -----------------------------------------

def _decode_line_protocol(payload: bytes, label: str) -> dict:
    line = _ascii_line(payload)
    if not line:
        return {}
    token = line.split(" ", 1)[0]
    fields = {"summary": f"{label} {line}", "banner_text": line}
    # SMTP/FTP continuation lines are "250-text" (hyphen) as well as
    # "250 text" (space), so the status is the leading digit run, not the
    # whole first token - otherwise a multiline greeting is filed as a
    # command named "250-MAIL.EXAMPLE.COM".
    digits = ""
    for char in token:
        if not char.isdigit():
            break
        digits += char
    if digits and (len(digits) == len(token) or token[len(digits)] in "-+"):
        fields[f"{label.lower()}_status"] = digits
    else:
        fields[f"{label.lower()}_command"] = token.upper()
    return fields


def decode_ftp(payload: bytes) -> dict:
    return _decode_line_protocol(payload, "FTP")


def decode_smtp(payload: bytes) -> dict:
    return _decode_line_protocol(payload, "SMTP")


def decode_pop3(payload: bytes) -> dict:
    return _decode_line_protocol(payload, "POP3")


def decode_imap(payload: bytes) -> dict:
    return _decode_line_protocol(payload, "IMAP")


def decode_irc(payload: bytes) -> dict:
    return _decode_line_protocol(payload, "IRC")


def decode_nntp(payload: bytes) -> dict:
    return _decode_line_protocol(payload, "NNTP")


def decode_redis(payload: bytes) -> dict:
    # RESP: "*<count>\r\n$<len>\r\n<COMMAND>\r\n..."
    if not payload.startswith((b"*", b"+", b"-", b"$", b":")):
        return {}
    text = bytes_to_text_preview(payload[:160], limit=160)
    command = ""
    for chunk in text.replace("\\r\\n", " ").split():
        if chunk.isalpha() and len(chunk) > 2:
            command = chunk.upper()
            break
    return {"redis_command": command, "summary": f"Redis {command or 'command'}"}


# --- SIP / SSDP ------------------------------------------------------------

def decode_sip(payload: bytes) -> dict:
    line = _ascii_line(payload)
    if not line:
        return {}
    return {
        "sip_method": line.split(" ", 1)[0],
        "sip_from": _header_value(payload, b"From"),
        "sip_to": _header_value(payload, b"To"),
        "summary": f"SIP {line}",
    }


def decode_ssdp(payload: bytes) -> dict:
    line = _ascii_line(payload)
    if not line:
        return {}
    target = _header_value(payload, b"ST") or _header_value(payload, b"NT")
    return {
        "ssdp_method": line.split(" ", 1)[0],
        "ssdp_target": target,
        "summary": f"SSDP {line.split(' ', 1)[0]}" + (f" for {target}" if target else ""),
    }


# --- Binary infrastructure protocols --------------------------------------

BGP_MESSAGE_TYPES = {1: "OPEN", 2: "UPDATE", 3: "NOTIFICATION", 4: "KEEPALIVE", 5: "ROUTE-REFRESH"}


def decode_bgp(payload: bytes) -> dict:
    # A BGP message opens with a 16-byte all-ones marker, then length+type.
    if len(payload) < 19 or payload[:16] != b"\xff" * 16:
        return {}
    kind = BGP_MESSAGE_TYPES.get(payload[18], f"type-{payload[18]}")
    return {"bgp_message": kind, "summary": f"BGP {kind}"}


KERBEROS_MESSAGE_TYPES = {
    10: "AS-REQ", 11: "AS-REP", 12: "TGS-REQ", 13: "TGS-REP",
    14: "AP-REQ", 15: "AP-REP", 30: "KRB-ERROR",
}


def decode_kerberos(payload: bytes) -> dict:
    # Application-tagged ASN.1: 0x6a = AS-REQ (application 10), etc.
    if not payload:
        return {}
    tag = payload[0]
    if tag & 0xE0 != 0x60:
        return {}
    kind = KERBEROS_MESSAGE_TYPES.get(tag & 0x1F)
    if not kind:
        return {}
    return {"kerberos_message": kind, "summary": f"Kerberos {kind}"}


LDAP_OPERATIONS = {
    0: "bind-request", 1: "bind-response", 2: "unbind-request", 3: "search-request",
    4: "search-entry", 5: "search-done", 6: "modify-request", 8: "add-request",
    10: "delete-request", 16: "abandon-request", 23: "extended-request",
}


def decode_ldap(payload: bytes) -> dict:
    # SEQUENCE { messageID INTEGER, protocolOp [APPLICATION n] ... }
    if len(payload) < 7 or payload[0] != 0x30:
        return {}
    offset = 2
    if payload[1] & 0x80:
        offset = 2 + (payload[1] & 0x7F)
    if offset + 2 > len(payload) or payload[offset] != 0x02:
        return {}
    offset += 2 + payload[offset + 1]
    if offset >= len(payload):
        return {}
    operation = LDAP_OPERATIONS.get(payload[offset] & 0x1F)
    if not operation:
        return {}
    return {"ldap_operation": operation, "summary": f"LDAP {operation}"}


SMB2_COMMANDS = {
    0: "NEGOTIATE", 1: "SESSION_SETUP", 2: "LOGOFF", 3: "TREE_CONNECT", 4: "TREE_DISCONNECT",
    5: "CREATE", 6: "CLOSE", 8: "READ", 9: "WRITE", 14: "QUERY_DIRECTORY", 16: "QUERY_INFO",
}


def decode_smb(payload: bytes) -> dict:
    # NetBIOS session framing puts 4 bytes in front of the SMB header.
    for start in (0, 4):
        window = payload[start : start + 8]
        if window[:4] == b"\xfeSMB" and len(payload) >= start + 16:
            command = int.from_bytes(payload[start + 12 : start + 14], "little")
            name = SMB2_COMMANDS.get(command, f"command-{command}")
            return {"smb_version": "SMB2", "smb_command": name, "summary": f"SMB2 {name}"}
        if window[:4] == b"\xffSMB":
            return {"smb_version": "SMB1", "summary": "SMB1 (legacy dialect)"}
    return {}


def decode_quic(payload: bytes) -> dict:
    if len(payload) < 5 or not (payload[0] & 0x80):
        return {}
    version = int.from_bytes(payload[1:5], "big")
    if version == 0:
        return {"quic_version": "negotiation", "summary": "QUIC version negotiation"}
    kinds = {0: "initial", 1: "0-RTT", 2: "handshake", 3: "retry"}
    kind = kinds.get((payload[0] & 0x30) >> 4, "long-header")
    return {"quic_version": f"0x{version:08x}", "quic_packet": kind, "summary": f"QUIC {kind}"}


STUN_METHODS = {0x0001: "binding-request", 0x0101: "binding-response", 0x0111: "binding-error"}


def decode_stun(payload: bytes) -> dict:
    if len(payload) < 20 or payload[4:8] != b"\x21\x12\xa4\x42":
        return {}
    method = STUN_METHODS.get(int.from_bytes(payload[0:2], "big"), "message")
    return {"stun_method": method, "summary": f"STUN {method}"}


ISAKMP_EXCHANGES = {
    2: "identity-protection", 4: "aggressive", 5: "informational",
    34: "IKE_SA_INIT", 35: "IKE_AUTH", 36: "CREATE_CHILD_SA", 37: "INFORMATIONAL",
}


def decode_isakmp(payload: bytes) -> dict:
    if len(payload) < 28:
        return {}
    exchange = ISAKMP_EXCHANGES.get(payload[18], f"exchange-{payload[18]}")
    version = payload[17]
    return {
        "isakmp_exchange": exchange,
        "isakmp_version": f"{version >> 4}.{version & 0x0F}",
        "summary": f"ISAKMP/IKEv{version >> 4} {exchange}",
    }


WIREGUARD_TYPES = {1: "handshake-initiation", 2: "handshake-response", 3: "cookie-reply", 4: "transport-data"}


def decode_wireguard(payload: bytes) -> dict:
    if len(payload) < 4 or payload[1:4] != b"\x00\x00\x00":
        return {}
    kind = WIREGUARD_TYPES.get(payload[0])
    if not kind:
        return {}
    return {"wireguard_message": kind, "summary": f"WireGuard {kind}"}


def decode_vxlan(payload: bytes) -> dict:
    if len(payload) < 8 or not (payload[0] & 0x08):
        return {}
    vni = int.from_bytes(payload[4:7], "big")
    return {"vxlan_vni": vni, "summary": f"VXLAN VNI {vni}"}


# --- Link-layer discovery --------------------------------------------------

LLDP_TLV_TYPES = {1: "chassis-id", 2: "port-id", 3: "ttl", 4: "port-description", 5: "system-name", 6: "system-description"}


def decode_lldp(payload: bytes) -> dict:
    """Walk LLDP TLVs for the neighbour's identity.

    This is the asset-discovery payoff of seeing LLDP at all: the system
    name and port id say which switch port a host is plugged into.
    """
    fields: dict = {}
    offset = 0
    while offset + 2 <= len(payload):
        header = int.from_bytes(payload[offset : offset + 2], "big")
        tlv_type = header >> 9
        length = header & 0x01FF
        offset += 2
        if tlv_type == 0 or offset + length > len(payload):
            break
        value = payload[offset : offset + length]
        name = LLDP_TLV_TYPES.get(tlv_type)
        if name in ("system-name", "port-description"):
            fields[f"lldp_{name.replace('-', '_')}"] = bytes_to_text_preview(value, limit=80)
        elif name == "port-id" and len(value) > 1:
            fields["lldp_port_id"] = bytes_to_text_preview(value[1:], limit=60)
        offset += length
    if not fields:
        return {}
    label = fields.get("lldp_system_name") or "neighbour"
    port = fields.get("lldp_port_id")
    fields["summary"] = f"LLDP {label}" + (f" port {port}" if port else "")
    return fields


EAPOL_TYPES = {0: "EAP-packet", 1: "start", 2: "logoff", 3: "key", 4: "encapsulated-ASF-alert"}


def decode_eapol(payload: bytes) -> dict:
    if len(payload) < 4:
        return {}
    kind = EAPOL_TYPES.get(payload[1], f"type-{payload[1]}")
    return {"eapol_type": kind, "summary": f"802.1X EAPOL {kind}"}


def decode_cdp(payload: bytes) -> dict:
    """CDP TLVs, for the device id a Cisco neighbour announces."""
    if len(payload) < 4:
        return {}
    offset = 4
    fields: dict = {}
    while offset + 4 <= len(payload):
        tlv_type = int.from_bytes(payload[offset : offset + 2], "big")
        length = int.from_bytes(payload[offset + 2 : offset + 4], "big")
        if length < 4 or offset + length > len(payload):
            break
        value = payload[offset + 4 : offset + length]
        if tlv_type == 0x0001:
            fields["cdp_device_id"] = bytes_to_text_preview(value, limit=80)
        elif tlv_type == 0x0003:
            fields["cdp_port_id"] = bytes_to_text_preview(value, limit=60)
        elif tlv_type == 0x0005:
            fields["cdp_software"] = bytes_to_text_preview(value, limit=100)
        offset += length
    if not fields:
        return {}
    fields["summary"] = "CDP " + (fields.get("cdp_device_id") or "advertisement")
    return fields


DECODERS = {
    "tls": decode_tls,
    "ssh": decode_ssh,
    "http": decode_http,
    "http-proxy": decode_http,
    "ntp": decode_ntp,
    "ftp": decode_ftp,
    "smtp": decode_smtp,
    "pop3": decode_pop3,
    "imap": decode_imap,
    "irc": decode_irc,
    "nntp": decode_nntp,
    "redis": decode_redis,
    "sip": decode_sip,
    "ssdp": decode_ssdp,
    "bgp": decode_bgp,
    "kerberos": decode_kerberos,
    "ldap": decode_ldap,
    "smb": decode_smb,
    "quic": decode_quic,
    "stun": decode_stun,
    "isakmp": decode_isakmp,
    "wireguard": decode_wireguard,
    "vxlan": decode_vxlan,
    "lldp": decode_lldp,
    "eapol": decode_eapol,
    "cdp": decode_cdp,
}


def decode(proto: str, payload: bytes) -> dict:
    """Protocol-specific fields for a payload, or {} when nothing is known.

    Never raises: the capture loop records an exception here as an
    unparseable frame, so a decoder tripping on hostile bytes would turn
    that traffic into a blind spot rather than a decoded row.
    """
    decoder = DECODERS.get(str(proto or "").strip().lower())
    if decoder is None or not payload:
        return {}
    try:
        result = decoder(bytes(payload))
    except Exception:
        return {}
    return result if isinstance(result, dict) else {}
