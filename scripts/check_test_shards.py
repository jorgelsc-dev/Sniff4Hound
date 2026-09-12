#!/usr/bin/env python3
"""Fail if a tests/test_*.py module isn't covered by any CI shard.

The backend-tests CI job runs the suite as several parallel shards (see
.github/test-shards.json) instead of one `unittest discover`, so a new test
file has to be added to a shard explicitly - otherwise it would silently
never run in CI. This script is the guard: it diffs the modules discovered
on disk against the modules referenced by the shards.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SHARDS_PATH = REPO_ROOT / ".github" / "test-shards.json"
TESTS_DIR = REPO_ROOT / "tests"


def discovered_modules() -> set[str]:
    return {
        f"tests.{path.stem}"
        for path in TESTS_DIR.glob("test_*.py")
    }


def shard_modules() -> set[str]:
    data = json.loads(SHARDS_PATH.read_text())
    modules = set()
    for shard in data["shards"]:
        for target in shard:
            # A target is either "tests.test_foo" or "tests.test_foo.SomeClass".
            parts = target.split(".")
            modules.add(".".join(parts[:2]))
    return modules


def main() -> int:
    on_disk = discovered_modules()
    covered = shard_modules()
    missing = sorted(on_disk - covered)
    stale = sorted(covered - on_disk)

    if missing:
        print(
            "The following test modules exist under tests/ but are not "
            f"listed in {SHARDS_PATH.relative_to(REPO_ROOT)}, so CI would "
            "never run them:",
            file=sys.stderr,
        )
        for name in missing:
            print(f"  - {name}", file=sys.stderr)
        print(
            "Add each one to a shard in that file (pick the lightest shard).",
            file=sys.stderr,
        )

    if stale:
        print(
            f"The following modules are listed in {SHARDS_PATH.relative_to(REPO_ROOT)} "
            "but no longer exist under tests/ - remove them:",
            file=sys.stderr,
        )
        for name in stale:
            print(f"  - {name}", file=sys.stderr)

    if missing or stale:
        return 1

    print(f"All {len(on_disk)} test modules are covered by a shard.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
