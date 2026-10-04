"""HTTP/3 listener for the runtime API.

The transport (QUIC, TLS 1.3 inside it, HTTP/3 framing) lives in wsbuilder's
``Http3Server``. It dispatches every request through ``app.dispatch``, the same
entry point HTTP/1.1 and HTTP/2 use, so authentication, rate limits, security
checks and the access log apply unchanged.

HTTP/3 always runs over TLS 1.3, so it is only available when
``SNIFF4HOUND_TLS`` is on. A client finds it through the ``Alt-Svc`` header this
module hands to the app, which is why :func:`alt_svc_value` is read by
``app.py`` on every response.
"""

from __future__ import annotations

import socket
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from wsbuilder.http3_server import Http3Server, alt_svc_header

#: How long a client may remember the HTTP/3 endpoint. Each launch generates a
#: new certificate, so a stale entry only costs one failed attempt before the
#: client falls back to TCP; keep it short rather than the library's 24 hours.
ALT_SVC_MAX_AGE_SECONDS = 3600

_STARTUP_TIMEOUT_SECONDS = 5.0

_active_alt_svc: str | None = None


@dataclass(frozen=True)
class _PemFiles:
    """The shape wsbuilder's QUIC stack reads a certificate from, backed by the
    runtime PEM files :func:`sniff4hound.tls.ensure_runtime_tls` wrote."""

    certificate_pem: bytes
    chain_pem: bytes
    private_key_pem: bytes
    key_password: bytes | None = None

    @classmethod
    def from_material(cls, material) -> "_PemFiles":
        return cls(
            certificate_pem=Path(material.server_cert).read_bytes(),
            chain_pem=b"",
            private_key_pem=Path(material.server_key).read_bytes(),
        )


def alt_svc_value() -> str | None:
    """The ``Alt-Svc`` value to advertise, or None while HTTP/3 is not listening."""
    return _active_alt_svc


def start_http3(app, tls_material, host: str, port: int) -> Http3Server | None:
    """Serve ``app`` over HTTP/3 on a UDP socket at ``host:port``.

    Returns the running server, or None when the UDP port cannot be bound. The
    TCP API keeps working in that case; it just is not advertised as HTTP/3.
    """
    global _active_alt_svc

    # wsbuilder binds inside its serving thread and does not close the socket
    # when the bind fails, so a busy port would print a thread traceback and
    # leak a descriptor. Probe the bind here so that failure stays a one-line
    # notice.
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.bind((host, port))
    except OSError as exc:
        print(f"[!] HTTP/3 disabled: udp://{host}:{port}/ is unavailable ({exc.strerror}). The TCP API is unaffected.")
        return None
    finally:
        probe.close()

    server = Http3Server(
        host,
        port,
        app,
        _PemFiles.from_material(tls_material),
        # Retry-based address validation stays off. wsbuilder's Retry path does
        # not interoperate: after a Retry it keys the connection on the client's
        # new destination id and never sends retry_source_connection_id, so a
        # real client (curl, Chromium) aborts the handshake. Until that is fixed
        # in wsbuilder, the 3x anti-amplification budget still bounds what an
        # unvalidated address can make us send.
        require_address_validation=False,
    )
    thread = threading.Thread(target=server.serve_forever, name="sniff4hound-http3", daemon=True)
    thread.start()

    deadline = time.monotonic() + _STARTUP_TIMEOUT_SECONDS
    while not server.wait_until_serving(0.05):
        if not thread.is_alive() or time.monotonic() > deadline:
            server.stop()
            print(f"[!] HTTP/3 disabled: could not listen on udp://{host}:{port}/. The TCP API is unaffected.")
            return None

    bound_port = server.server_address[1]
    _active_alt_svc = alt_svc_header(bound_port, max_age=ALT_SVC_MAX_AGE_SECONDS)
    return server


def stop_http3(server: Http3Server | None) -> None:
    global _active_alt_svc

    if server is None:
        return
    _active_alt_svc = None
    server.stop()
