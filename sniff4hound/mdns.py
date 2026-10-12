"""Local service names and DNS-SD publication through wsbuilder."""

from __future__ import annotations

import argparse
import atexit
import hashlib
import ipaddress
import json
import os
import re
import socket
from dataclasses import dataclass
from pathlib import Path


SERVICE_TYPE = "_sniff4hound._tcp.local."


def default_hostname(role: str = "stream") -> str:
    try:
        identity = Path("/etc/machine-id").read_text().strip() or socket.gethostname()
    except OSError:
        identity = socket.gethostname()
    suffix = hashlib.sha256(identity.encode()).hexdigest()[:12]
    prefix = "sniff4hound-runtime" if role == "runtime" else "sniff4hound"
    return f"{prefix}-{suffix}.local"


def normalize_hostname(value: str) -> str:
    name = str(value).strip().lower().rstrip(".")
    if len(name) > 253 or not name.endswith(".local") or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in name.split(".")
    ):
        raise ValueError("mDNS hostnames must be valid names ending in .local")
    return name


def bind_addresses(host: str) -> tuple[str, ...]:
    if host == "localhost":
        return ("127.0.0.1",)
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        # Keep existing IPv4 hostname bind settings working as well as literals.
        address = ipaddress.ip_address(socket.gethostbyname(host))
    if address.is_unspecified:
        from .mobile_stream import discover_interfaces

        addresses = tuple(item.address for item in discover_interfaces() if not item.loopback)
        if not addresses:
            raise ValueError("no local interface is available to publish the runtime")
        return addresses
    if address.is_multicast:
        raise ValueError("an mDNS service needs a unicast listener address")
    return (str(address),)


@dataclass
class PublishedService:
    server: object
    service: object
    closed: bool = False

    def metadata(self) -> dict:
        service = self.service
        return {
            "enabled": not self.closed,
            "service_type": service.service_type,
            "service_name": service.name,
            "hostname": service.hostname.rstrip("."),
            "port": service.port,
            "addresses": list(service.addresses),
        }

    def close(self) -> None:
        if not self.closed:
            self.closed = True
            atexit.unregister(self.close)
            self.server.close()


def publish(role: str, address: str, port: int, *, tls: bool = True, http3: bool = False) -> PublishedService | None:
    from .settings import MDNS_ENABLED, MDNS_HOST, MOBILE_HOST

    if not MDNS_ENABLED:
        return None
    from wsbuilder import LocalMDNSServer

    hostname = normalize_hostname(MDNS_HOST if role == "runtime" else MOBILE_HOST)
    addresses = bind_addresses(address)
    server = LocalMDNSServer(interfaces=list(addresses), ip_version="v6" if ":" in addresses[0] else "v4")
    hostname_id = hashlib.sha256(hostname.encode()).hexdigest()[:12]
    try:
        service = server.register_service(
            f"Sniff4Hound {role} {hostname_id} {port}-{os.getpid()}",
            port,
            addresses,
            service_type=SERVICE_TYPE,
            hostname=hostname,
            properties={
                "role": role,
                "scheme": "https" if tls else "http",
                "path": "/mobile" if role == "stream" else "/",
                "http3": "1" if http3 else "0",
            },
        )
    except Exception:
        server.close()
        raise
    published = PublishedService(server, service)
    atexit.register(published.close)
    return published


def resolve(name: str, address: str, *, timeout: float = 3.0) -> dict:
    from wsbuilder import LocalMDNSServer

    addresses = bind_addresses(address)
    with LocalMDNSServer(interfaces=list(addresses), ip_version="v6" if ":" in addresses[0] else "v4") as server:
        service = server.resolve_service(name, service_type=SERVICE_TYPE, timeout=timeout)
        if service is None:
            raise ValueError("the local runtime's mDNS service did not answer")
        result = PublishedService(server, service).metadata()
        result["role"] = (service.properties.get(b"role") or b"").decode("ascii")
        result["scheme"] = (service.properties.get(b"scheme") or b"").decode("ascii")
        return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Resolve a Sniff4Hound DNS-SD service")
    parser.add_argument("--service", required=True)
    parser.add_argument("--address", required=True)
    parser.add_argument("--timeout", type=float, default=3.0)
    args = parser.parse_args()
    print(json.dumps(resolve(args.service, args.address, timeout=args.timeout), separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
