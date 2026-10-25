#!/usr/bin/env python3
"""Fail when an npm lockfile resolves a package from a non-official registry.

Every `package-lock.json` tracked in the repository (or the paths given on the
command line) must resolve its tarballs from https://registry.npmjs.org/ only.
A lockfile generated behind a mirror (e.g. registry.npmmirror.com) still pins
sha512 integrity, but ties the availability of every `npm ci` - and so the
.deb and Electron builds - to that third-party host.

Entries without a `resolved` URL (workspace links, bundled dependencies) are
ignored. Exit status: 0 when every URL is allowed, 1 otherwise.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit

ALLOWED_PREFIX = "https://registry.npmjs.org/"
ROOT = Path(__file__).resolve().parent.parent


def tracked_lockfiles() -> list[Path]:
    output = subprocess.run(
        ["git", "ls-files", "-z", "--", "*package-lock.json"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    ).stdout.decode()
    return [ROOT / name for name in output.split("\0") if name]


def bad_entries(lockfile: Path) -> list[tuple[str, str]]:
    data = json.loads(lockfile.read_text(encoding="utf-8"))
    bad = []
    for name, entry in (data.get("packages") or {}).items():
        resolved = entry.get("resolved") if isinstance(entry, dict) else None
        if not resolved or resolved.startswith("file:"):
            continue
        if not resolved.startswith(ALLOWED_PREFIX):
            bad.append((name or "<root>", resolved))
    return bad


def main(argv: list[str]) -> int:
    lockfiles = [Path(arg).resolve() for arg in argv] or tracked_lockfiles()
    if not lockfiles:
        print("No package-lock.json files found.")
        return 0
    failed = False
    for lockfile in lockfiles:
        bad = bad_entries(lockfile)
        label = lockfile.relative_to(ROOT) if lockfile.is_relative_to(ROOT) else lockfile
        if not bad:
            print(f"ok   {label}")
            continue
        failed = True
        hosts = sorted({urlsplit(url).netloc or url for _, url in bad})
        print(f"FAIL {label}: {len(bad)} entries outside {ALLOWED_PREFIX} (hosts: {', '.join(hosts)})")
        for name, url in bad[:10]:
            print(f"     {name}: {url}")
        if len(bad) > 10:
            print(f"     ... and {len(bad) - 10} more")
    if failed:
        print(
            "Regenerate the lockfile against the official registry "
            "(the directory's .npmrc must set registry=https://registry.npmjs.org/)."
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
