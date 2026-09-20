from __future__ import annotations

import ipaddress
import shutil
import socket
import ssl
import subprocess
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


def _write_server_ext(host: str) -> None:
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
    SERVER_EXT_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")


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


def public_ca_pem() -> str:
    try:
        return CA_CERT_FILE.read_text(encoding="utf-8")
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
