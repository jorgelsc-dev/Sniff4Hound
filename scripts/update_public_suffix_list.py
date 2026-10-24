#!/usr/bin/env python3
"""Refresh the bundled Public Suffix List from its canonical URL."""

from __future__ import annotations

import argparse
import hashlib
import tempfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "sniff4hound" / "data" / "public_suffix_list.dat"
SOURCE = "https://publicsuffix.org/list/public_suffix_list.dat"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args()
    request = urllib.request.Request(SOURCE, headers={"User-Agent": "Sniff4Hound PSL updater"})
    with urllib.request.urlopen(request, timeout=300) as response:
        content = response.read()
    text = content.decode("utf-8")
    rules = [line for line in text.splitlines() if line and not line.startswith("//")]
    if "License, v. 2.0" not in text or "mozilla.org/MPL/2.0" not in text or len(rules) < 10_000:
        raise ValueError("the downloaded Public Suffix List failed validation")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=args.output.parent, delete=False) as handle:
        handle.write(content)
        temporary = Path(handle.name)
    temporary.replace(args.output)
    digest = hashlib.sha256(content).hexdigest()
    print(f"[ok] wrote {len(rules):,} PSL rules to {args.output} (sha256 {digest})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
