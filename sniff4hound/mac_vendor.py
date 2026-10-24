"""Offline MAC-address vendor lookup from IEEE's public registries.

The generated catalog is bundled under ``sniff4hound/data`` and loaded lazily
once.  Lookup uses the longest applicable assignment (MA-S/IAB, then MA-M,
then MA-L), so a smaller block delegated by a parent OUI gets its own owner.
No MAC address or network observation leaves the machine.
"""

from __future__ import annotations

import json
import threading
from typing import Any

from .runtime_paths import resolve_data_file

REGISTRY_FILENAME = "mac_vendors.json"

_lock = threading.Lock()
_loaded = False
_prefixes: dict[int, dict[str, list[str]]] = {24: {}, 28: {}, 36: {}}
_metadata: dict[str, Any] = {}


def _load() -> None:
    global _loaded, _prefixes, _metadata
    if _loaded:
        return
    with _lock:
        if _loaded:
            return
        try:
            path = resolve_data_file(REGISTRY_FILENAME)
            payload = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
        except (OSError, ValueError, TypeError):
            payload = {}
        raw = payload.get("prefixes") if isinstance(payload, dict) else {}
        if not isinstance(raw, dict):
            raw = {}
        _prefixes = {
            bits: values if isinstance((values := raw.get(str(bits))), dict) else {}
            for bits in (24, 28, 36)
        }
        _metadata = {key: value for key, value in payload.items() if key != "prefixes"} if isinstance(payload, dict) else {}
        _loaded = True


def _mac_hex(value: Any) -> str:
    text = str(value or "").strip().upper()
    compact = "".join(char for char in text if char not in ":-. ")
    if len(compact) != 12 or any(char not in "0123456789ABCDEF" for char in compact):
        return ""
    return compact


def is_available() -> bool:
    _load()
    return any(_prefixes.values())


def assignment_counts() -> dict[str, int]:
    _load()
    return {str(bits): len(_prefixes[bits]) for bits in (24, 28, 36)}


def catalog_metadata() -> dict[str, Any]:
    _load()
    return dict(_metadata)


def lookup(mac: Any) -> dict[str, Any]:
    """Describe an EUI-48 address without ever raising.

    ``vendor`` is present only for a globally administered IEEE assignment.
    ``kind`` distinguishes invalid, broadcast, multicast, local/randomized,
    globally assigned, and globally formatted but unregistered addresses.
    """
    compact = _mac_hex(mac)
    if not compact:
        return {"kind": "invalid", "vendor": "", "registry": "", "prefix": "", "prefix_bits": 0}
    if compact == "FFFFFFFFFFFF":
        return {"kind": "broadcast", "vendor": "", "registry": "", "prefix": "", "prefix_bits": 0}
    first_octet = int(compact[:2], 16)
    if first_octet & 0x01:
        return {"kind": "multicast", "vendor": "", "registry": "", "prefix": "", "prefix_bits": 0}
    if first_octet & 0x02:
        return {"kind": "local", "vendor": "", "registry": "", "prefix": "", "prefix_bits": 0}

    _load()
    for bits in (36, 28, 24):
        prefix = compact[: bits // 4]
        assignment = _prefixes[bits].get(prefix)
        if isinstance(assignment, list) and assignment:
            return {
                "kind": "global",
                "vendor": str(assignment[0]),
                "registry": str(assignment[1]) if len(assignment) > 1 else "",
                "prefix": prefix,
                "prefix_bits": bits,
            }
    return {"kind": "unknown", "vendor": "", "registry": "", "prefix": "", "prefix_bits": 0}


def enrich(row: dict, field: str = "mac", prefix: str = "mac_") -> dict:
    """Add lookup fields to an API row in place and return it."""
    result = lookup(row.get(field))
    row[f"{prefix}vendor"] = result["vendor"]
    row[f"{prefix}vendor_registry"] = result["registry"]
    row[f"{prefix}vendor_prefix"] = result["prefix"]
    row[f"{prefix}vendor_prefix_bits"] = result["prefix_bits"]
    row[f"{prefix}address_kind"] = result["kind"]
    return row
