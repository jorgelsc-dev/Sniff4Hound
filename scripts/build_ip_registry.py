#!/usr/bin/env python3
"""Build `sniff4hound/data/ip_registry.json` from the five RIR delegation files.

The Regional Internet Registries (the "NICs") publish, daily, exactly which
address blocks they have delegated to which country. That is the authoritative
source for "which country does this address belong to" - the same data every
country-level GeoIP database is derived from - and it is freely redistributable.

Shipping it in-tree removes the runtime dependency on a system libGeoIP plus a
country database being installed: without those, every public address used to
come back unlocated and the map stayed empty.

    python scripts/build_ip_registry.py            # download and rebuild
    python scripts/build_ip_registry.py --from-dir /path/with/delegated-*  # offline

Record format (pipe-separated), per RFC-ish RIR spec:

    registry|cc|type|start|value|date|status[|opaque-id]

For ipv4, `value` is a *host count* (not a prefix length) and is not always a
power of two, so a block can span several CIDRs - the ranges are stored as
explicit start/end integers instead. For ipv6, `value` is the prefix length.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "sniff4hound" / "data" / "ip_registry.json"

SOURCES = {
    "afrinic": "https://ftp.afrinic.net/stats/afrinic/delegated-afrinic-extended-latest",
    "apnic": "https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest",
    "arin": "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
    "lacnic": "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest",
    "ripencc": "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest",
}

# Which RIR serves which part of the world. Used for the region label when a
# country code is missing or unhelpful.
RIR_REGIONS = {
    "afrinic": "Africa",
    "apnic": "Asia-Pacific",
    "arin": "North America",
    "lacnic": "Latin America & Caribbean",
    "ripencc": "Europe, Middle East & Central Asia",
}

# Only delegated space maps to a country. "reserved" and "available" blocks are
# unallocated and must not be attributed to anyone.
USABLE_STATUSES = {"allocated", "assigned"}


def download(destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    for name, url in SOURCES.items():
        target = destination / f"{name}.txt"
        print(f"[fetch] {name} <- {url}", file=sys.stderr)
        with urllib.request.urlopen(url, timeout=300) as response:
            target.write_bytes(response.read())


def parse_file(path: Path, registry: str, v4: list, v6: list) -> None:
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("|")
        if len(parts) < 7:
            continue
        _reg, country, kind, start, value, _date, status = parts[:7]
        # "*" is the header/summary row, not a delegation.
        if country in ("", "*") or start in ("", "*"):
            continue
        if status.strip().lower() not in USABLE_STATUSES:
            continue
        country = country.strip().upper()
        if len(country) != 2:
            continue
        try:
            if kind == "ipv4":
                first = int(ipaddress.IPv4Address(start))
                count = int(value)
                if count <= 0:
                    continue
                v4.append((first, first + count - 1, country, registry))
            elif kind == "ipv6":
                network = ipaddress.IPv6Network(f"{start}/{int(value)}", strict=False)
                v6.append((int(network.network_address), int(network.broadcast_address), country, registry))
        except (ValueError, ipaddress.AddressValueError):
            continue


def merge(rows: list) -> list:
    """Sort by start address and merge blocks that touch and agree.

    The RIRs hand out contiguous runs of small blocks to the same country all
    the time; collapsing them cuts the shipped file down substantially without
    losing a single lookup result.
    """
    rows.sort(key=lambda row: (row[0], row[1]))
    merged: list = []
    for start, end, country, registry in rows:
        if merged:
            prev = merged[-1]
            if prev[2] == country and prev[3] == registry and start <= prev[1] + 1:
                if end > prev[1]:
                    merged[-1] = (prev[0], end, country, registry)
                continue
        merged.append((start, end, country, registry))
    return merged


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--from-dir", type=Path, help="Use already-downloaded delegation files instead of fetching.")
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args()

    source_dir = args.from_dir
    if source_dir is None:
        source_dir = ROOT / "build" / "rir"
        download(source_dir)

    v4: list = []
    v6: list = []
    for name in SOURCES:
        path = source_dir / f"{name}.txt"
        if not path.exists():
            print(f"[warn] missing {path}", file=sys.stderr)
            continue
        parse_file(path, name, v4, v6)

    raw_v4, raw_v6 = len(v4), len(v6)
    v4 = merge(v4)
    v6 = merge(v6)

    payload = {
        "source": "RIR delegated-extended files",
        "registries": RIR_REGIONS,
        # Flat arrays rather than dicts: this file is bisected on load, and the
        # per-row key names would triple its size for nothing.
        "ipv4": [[start, end, cc, rir] for start, end, cc, rir in v4],
        "ipv6": [[start, end, cc, rir] for start, end, cc, rir in v6],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, separators=(",", ":")) + "\n", encoding="utf-8")

    size_mb = args.output.stat().st_size / (1024 * 1024)
    print(f"[ok] ipv4 {raw_v4} -> {len(v4)} ranges", file=sys.stderr)
    print(f"[ok] ipv6 {raw_v6} -> {len(v6)} ranges", file=sys.stderr)
    print(f"[ok] wrote {args.output} ({size_mb:.1f} MB)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
