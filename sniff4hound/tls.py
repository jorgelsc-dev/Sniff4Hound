from __future__ import annotations

import ipaddress
import secrets
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from .settings import DATA_DIR, TLS_CERT_DAYS


TLS_DIR = DATA_DIR / "tls"
CA_KEY_FILE = TLS_DIR / "sniff4hound-ca.key"
CA_CERT_FILE = TLS_DIR / "sniff4hound-ca.pem"
SERVER_KEY_FILE = TLS_DIR / "sniff4hound-server.key"
SERVER_CSR_FILE = TLS_DIR / "sniff4hound-server.csr"
SERVER_CERT_FILE = TLS_DIR / "sniff4hound-server.pem"
SERVER_EXT_FILE = TLS_DIR / "sniff4hound-server.ext"
CA_SERIAL_FILE = TLS_DIR / "sniff4hound-ca.srl"
MOBILE_CA_KEY_FILE = TLS_DIR / "sniff4hound-mobile-ca.key"
MOBILE_CA_CERT_FILE = TLS_DIR / "sniff4hound-mobile-ca.pem"
MOBILE_SERVER_KEY_FILE = TLS_DIR / "sniff4hound-mobile-server.key"
MOBILE_SERVER_CSR_FILE = TLS_DIR / "sniff4hound-mobile-server.csr"
MOBILE_SERVER_CERT_FILE = TLS_DIR / "sniff4hound-mobile-server.pem"
MOBILE_SERVER_EXT_FILE = TLS_DIR / "sniff4hound-mobile-server.ext"
MOBILE_CA_SERIAL_FILE = TLS_DIR / "sniff4hound-mobile-ca.srl"
_MOBILE_CA_CERT_ACTIVE: Path | None = None


@dataclass(frozen=True)
class RuntimeTlsMaterial:
    ca_cert: Path
    server_cert: Path
    server_key: Path
    ssl_context: ssl.SSLContext


def _run_openssl(args: list[str]) -> None:
    openssl = shutil.which("openssl")
    if not openssl:
        raise RuntimeError("OpenSSL is required to generate Sniff4Hound TLS certificates.")
    subprocess.run(
        [openssl, *args],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )


def _host_alt_names(host: str) -> tuple[list[str], list[str]]:
    dns_names = {"localhost"}
    ip_names = {"127.0.0.1", "::1"}
    candidates = {str(host or "").strip(), socket.gethostname(), socket.getfqdn()}
    for candidate in candidates:
        if not candidate or candidate in {"0.0.0.0", "::"}:
            continue
        try:
            ip_names.add(str(ipaddress.ip_address(candidate)))
        except ValueError:
            dns_names.add(candidate)
    return sorted(dns_names), sorted(ip_names)


def _write_server_ext(host: str, path: Path = SERVER_EXT_FILE) -> None:
    dns_names, ip_names = _host_alt_names(host)
    lines = [
        "basicConstraints=CA:FALSE",
        "keyUsage=digitalSignature,keyEncipherment",
        "extendedKeyUsage=serverAuth",
        "subjectAltName=@alt_names",
        "",
        "[alt_names]",
    ]
    for index, name in enumerate(dns_names, start=1):
        lines.append(f"DNS.{index}={name}")
    for index, name in enumerate(ip_names, start=1):
        lines.append(f"IP.{index}={name}")
    TLS_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _remove_previous_material() -> None:
    for path in (
        CA_KEY_FILE,
        CA_CERT_FILE,
        SERVER_KEY_FILE,
        SERVER_CSR_FILE,
        SERVER_CERT_FILE,
        SERVER_EXT_FILE,
        CA_SERIAL_FILE,
    ):
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def _remove_previous_mobile_material() -> None:
    for path in (
        MOBILE_CA_KEY_FILE,
        MOBILE_CA_CERT_FILE,
        MOBILE_SERVER_KEY_FILE,
        MOBILE_SERVER_CSR_FILE,
        MOBILE_SERVER_CERT_FILE,
        MOBILE_SERVER_EXT_FILE,
        MOBILE_CA_SERIAL_FILE,
    ):
        try:
            path.unlink()
        except (FileNotFoundError, OSError):
            pass


def public_ca_pem() -> str:
    try:
        return CA_CERT_FILE.read_text(encoding="utf-8")
    except OSError:
        return ""


def public_mobile_ca_pem() -> str:
    if _MOBILE_CA_CERT_ACTIVE is not None:
        try:
            return _MOBILE_CA_CERT_ACTIVE.read_text(encoding="utf-8")
        except OSError:
            pass
    try:
        return MOBILE_CA_CERT_FILE.read_text(encoding="utf-8")
    except OSError:
        return ""


def ensure_runtime_tls(host: str) -> RuntimeTlsMaterial:
    """Create a short-lived CA and server cert for this process.

    The material is deliberately regenerated on each TLS-enabled launch. A
    desktop client trusts the returned CA for the configured backend origin
    only, so persisting it longer than the process buys little and widens the
    window after a local file disclosure.
    """
    TLS_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    _remove_previous_material()
    _run_openssl(["genrsa", "-out", str(CA_KEY_FILE), "2048"])
    _run_openssl(
        [
            "req",
            "-x509",
            "-new",
            "-nodes",
            "-key",
            str(CA_KEY_FILE),
            "-sha256",
            "-days",
            str(TLS_CERT_DAYS),
            "-out",
            str(CA_CERT_FILE),
            "-subj",
            "/CN=Sniff4Hound Temporary Runtime CA",
        ]
    )
    _run_openssl(["genrsa", "-out", str(SERVER_KEY_FILE), "2048"])
    common_name = str(host or "localhost").strip()
    if common_name in {"0.0.0.0", "::", ""}:
        common_name = "localhost"
    _run_openssl(
        [
            "req",
            "-new",
            "-key",
            str(SERVER_KEY_FILE),
            "-out",
            str(SERVER_CSR_FILE),
            "-subj",
            f"/CN={common_name}",
        ]
    )
    _write_server_ext(host)
    _run_openssl(
        [
            "x509",
            "-req",
            "-in",
            str(SERVER_CSR_FILE),
            "-CA",
            str(CA_CERT_FILE),
            "-CAkey",
            str(CA_KEY_FILE),
            "-CAcreateserial",
            "-out",
            str(SERVER_CERT_FILE),
            "-days",
            str(TLS_CERT_DAYS),
            "-sha256",
            "-extfile",
            str(SERVER_EXT_FILE),
        ]
    )
    for secret in (CA_KEY_FILE, SERVER_KEY_FILE):
        try:
            secret.chmod(0o600)
        except OSError:
            pass
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=str(SERVER_CERT_FILE), keyfile=str(SERVER_KEY_FILE))
    return RuntimeTlsMaterial(CA_CERT_FILE, SERVER_CERT_FILE, SERVER_KEY_FILE, context)


def ensure_mobile_tls(host: str) -> RuntimeTlsMaterial:
    """Create TLS material for the LAN-only mobile stream listener.

    The mobile listener binds to an operator-selected interface address, so it
    needs a certificate whose SAN contains that exact IP. It uses distinct
    files from the desktop/runtime API certificate to avoid invalidating the
    Electron shell's trusted CA while the operator rotates mobile links.
    """
    global _MOBILE_CA_CERT_ACTIVE

    tls_dir = TLS_DIR
    try:
        tls_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        probe = tls_dir / ".mobile-write-test"
        probe.write_text("", encoding="utf-8")
        probe.unlink()
    except OSError:
        tls_dir = Path(tempfile.mkdtemp(prefix="sniff4hound-mobile-tls-"))
    # Use unique filenames so a developer run as an unprivileged user does not
    # fail merely because an older root-elevated desktop run left 0600 files in
    # the shared data dir. Best-effort cleanup above is kept for packaged runs,
    # but startup never depends on it.
    _remove_previous_mobile_material()
    stem = f"sniff4hound-mobile-{int(time.time())}-{secrets.token_hex(4)}"
    ca_key = tls_dir / f"{stem}-ca.key"
    ca_cert = tls_dir / f"{stem}-ca.pem"
    server_key = tls_dir / f"{stem}-server.key"
    server_csr = tls_dir / f"{stem}-server.csr"
    server_cert = tls_dir / f"{stem}-server.pem"
    server_ext = tls_dir / f"{stem}-server.ext"

    _run_openssl(["genrsa", "-out", str(ca_key), "2048"])
    _run_openssl(
        [
            "req",
            "-x509",
            "-new",
            "-nodes",
            "-key",
            str(ca_key),
            "-sha256",
            "-days",
            str(TLS_CERT_DAYS),
            "-out",
            str(ca_cert),
            "-subj",
            "/CN=Sniff4Hound Mobile Stream CA",
        ]
    )
    _run_openssl(["genrsa", "-out", str(server_key), "2048"])
    common_name = str(host or "localhost").strip()
    if common_name in {"0.0.0.0", "::", ""}:
        common_name = "localhost"
    _run_openssl(
        [
            "req",
            "-new",
            "-key",
            str(server_key),
            "-out",
            str(server_csr),
            "-subj",
            f"/CN={common_name}",
        ]
    )
    _write_server_ext(host, server_ext)
    _run_openssl(
        [
            "x509",
            "-req",
            "-in",
            str(server_csr),
            "-CA",
            str(ca_cert),
            "-CAkey",
            str(ca_key),
            "-CAcreateserial",
            "-out",
            str(server_cert),
            "-days",
            str(TLS_CERT_DAYS),
            "-sha256",
            "-extfile",
            str(server_ext),
        ]
    )
    for secret in (ca_key, server_key):
        try:
            secret.chmod(0o600)
        except OSError:
            pass
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=str(server_cert), keyfile=str(server_key))
    _MOBILE_CA_CERT_ACTIVE = ca_cert
    return RuntimeTlsMaterial(ca_cert, server_cert, server_key, context)
