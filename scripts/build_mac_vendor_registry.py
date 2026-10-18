#!/usr/bin/env python3
"""Build the bundled MAC-vendor catalog from IEEE's public assignments.

IEEE Registration Authority is the authoritative source.  All assignment
classes that can identify an EUI-48/MAC address are included:

    MA-L  24-bit prefix (the traditional OUI)
    MA-M  28-bit prefix
    MA-S  36-bit prefix (OUI-36)
    IAB   legacy 36-bit assignments

Only the assignment, organization name and registry class are retained.  The
postal address in the source CSV is unrelated to identification and would add
several megabytes to every installation.

    python scripts/build_mac_vendor_registry.py
    python scripts/build_mac_vendor_registry.py --from-dir /path/to/csvs

An offline directory must contain mal.csv, mam.csv, mas.csv and iab.csv.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
import sys
import tempfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "sniff4hound" / "data" / "mac_vendors.json"

SOURCES = {
    "MA-L": ("mal.csv", "https://standards-oui.ieee.org/oui/oui.csv", 24),
    "MA-M": ("mam.csv", "https://standards-oui.ieee.org/oui28/mam.csv", 28),
    "MA-S": ("mas.csv", "https://standards-oui.ieee.org/oui36/oui36.csv", 36),
    "IAB": ("iab.csv", "https://standards-oui.ieee.org/iab/iab.csv", 36),
}


def download(destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    for registry, (filename, url, _bits) in SOURCES.items():
        print(f"[fetch] {registry} <- {url}", file=sys.stderr)
        request = urllib.request.Request(url, headers={"User-Agent": "Sniff4Hound registry builder"})
        with urllib.request.urlopen(request, timeout=300) as response:
            (destination / filename).write_bytes(response.read())


def read_assignments(path: Path, registry: str, bits: int) -> dict[str, list[str]]:
    expected_length = bits // 4
    assignments: dict[str, list[str]] = {}
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            prefix = "".join(char for char in str(row.get("Assignment") or "").upper() if char in "0123456789ABCDEF")
            organization = " ".join(str(row.get("Organization Name") or "").split())
            if len(prefix) != expected_length or not organization:
                continue
            # A handful of historical MA-L values occur more than once in the
            # official file.  The later row is IEEE's current public answer.
            assignments[prefix] = [organization, registry]
    return assignments


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--from-dir", type=Path, help="Use already-downloaded IEEE CSV files.")
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args()

    temporary = None
    source_dir = args.from_dir
    if source_dir is None:
        temporary = tempfile.TemporaryDirectory(prefix="sniff4hound-ieee-")
        source_dir = Path(temporary.name)
        download(source_dir)

    prefixes: dict[str, dict[str, list[str]]] = {"24": {}, "28": {}, "36": {}}
    sources: dict[str, dict[str, str | int]] = {}
    for registry, (filename, url, bits) in SOURCES.items():
        path = source_dir / filename
        if not path.is_file():
            parser.error(f"missing IEEE source file: {path}")
        rows = read_assignments(path, registry, bits)
        # MA-S is the current 36-bit registry and therefore wins over a legacy
        # IAB row in the unlikely event IEEE publishes the same prefix in both.
        if registry == "IAB":
            for prefix, value in rows.items():
                prefixes[str(bits)].setdefault(prefix, value)
        else:
            prefixes[str(bits)].update(rows)
        sources[registry] = {"url": url, "sha256": sha256(path), "rows": len(rows)}

    payload = {
        "source": "IEEE Registration Authority public listings",
        "source_page": "https://standards.ieee.org/products-programs/regauth/",
        "generated_at": dt.datetime.now(dt.timezone.utc).date().isoformat(),
        "sources": sources,
        "prefixes": {bits: dict(sorted(values.items())) for bits, values in prefixes.items()},
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")
    total = sum(len(values) for values in prefixes.values())
    print(f"[ok] wrote {total:,} IEEE assignments to {args.output} ({args.output.stat().st_size / 1048576:.1f} MB)", file=sys.stderr)
    if temporary is not None:
        temporary.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
