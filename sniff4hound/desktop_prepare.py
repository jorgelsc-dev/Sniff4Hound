"""What the desktop shell has to know before it starts Chromium.

Chromium reads its trust and QUIC switches once, at launch, and the runtime it
is about to talk to is not running yet. So the shell asks this module first
(``python -m sniff4hound.desktop_prepare``) and gets one JSON line back:

* ``port``: the port the runtime will listen on, free for both TCP and UDP (the
  runtime serves HTTP/3 on the same number over UDP). The shell hands it to the
  runtime, so Chromium can be told to speak HTTP/3 to that exact origin.
* ``server_spki_sha256``: the public-key hash of the runtime's persistent server
  key (and the CA that signs for it), created here if they do not exist yet, so
  Chromium can be told to trust that one key for QUIC. The key, not the CA, is
  what is pinned: the runtime's QUIC stack sends its certificate chain in a single
  packet, which only has room for the server's own certificate.

Both are absent when they cannot be provided (TLS off, OpenSSL missing, no free
port); the shell then simply does not turn HTTP/3 on.
"""

from __future__ import annotations

import json
import socket
import sys

from .settings import HOST, PORT, TLS_ENABLED


def udp_port_is_available(host: str, port: int) -> bool:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        try:
            sock.bind((host, port))
        except OSError:
            return False
    return True


def choose_port(host: str, preferred: int) -> int | None:
    """The first of the runtime's candidate ports that is free on TCP and UDP."""
    from .manage import _candidate_ports, _port_is_available

    for candidate in _candidate_ports(preferred):
        if _port_is_available(host, candidate) and udp_port_is_available(host, candidate):
            return candidate
    return None


def prepare(host: str = HOST, preferred: int = PORT) -> dict:
    result: dict = {"host": host, "port": None, "server_spki_sha256": "", "ca_created": False}
    result["port"] = choose_port(host, preferred)
    if TLS_ENABLED:
        try:
            from .tls import ensure_runtime_ca, ensure_server_key, server_key_pin

            _, created = ensure_runtime_ca()
            result["server_spki_sha256"] = server_key_pin(ensure_server_key(renew=created))
            result["ca_created"] = bool(created)
        except Exception as exc:  # noqa: BLE001 - the shell goes on without HTTP/3
            print(f"runtime CA unavailable: {exc}", file=sys.stderr)
    return result


def main() -> int:
    print(json.dumps(prepare(), separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
