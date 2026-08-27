"""Country/region lookup from the bundled RIR delegation catalog.

`sniff4hound/data/ip_registry.json` is built by `scripts/build_ip_registry.py`
straight from the five Regional Internet Registries' daily delegation files -
the same authoritative source every country-level GeoIP database derives from,
and freely redistributable.

Shipping it removes the hard dependency on a system libGeoIP plus a country
database: without those installed, every public address came back unlocated
and the map stayed empty. libGeoIP still wins when it is present (it carries
city-level data in some builds); this is the fallback that always works.

Lookups bisect a sorted array of (start, end) integers, so a hit costs
O(log n) over ~143k IPv4 ranges. The catalog is parsed once, lazily, on the
first lookup - importing this module must stay cheap because
`sniff4hound.store` imports it at startup.
"""

from __future__ import annotations

import bisect
import ipaddress
import json
import threading

from .runtime_paths import resolve_data_file

REGISTRY_FILENAME = "ip_registry.json"

_lock = threading.Lock()
_loaded = False
_starts_v4: list[int] = []
_rows_v4: list = []
_starts_v6: list[int] = []
_rows_v6: list = []
_regions: dict[str, str] = {}


def _load() -> None:
    global _loaded, _starts_v4, _rows_v4, _starts_v6, _rows_v6, _regions
    if _loaded:
        return
    with _lock:
        if _loaded:
            return
        try:
            path = resolve_data_file(REGISTRY_FILENAME)
            payload = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
        except Exception:
            payload = {}
        rows_v4 = payload.get("ipv4") or []
        rows_v6 = payload.get("ipv6") or []
        # Kept as parallel arrays: bisect needs a plain sorted sequence, and
        # building one list of starts is cheaper than a key function per probe.
        _rows_v4 = rows_v4
        _rows_v6 = rows_v6
        _starts_v4 = [row[0] for row in rows_v4]
        _starts_v6 = [row[0] for row in rows_v6]
        _regions = payload.get("registries") or {}
        _loaded = True


def is_available() -> bool:
    _load()
    return bool(_rows_v4 or _rows_v6)


def range_counts() -> tuple[int, int]:
    _load()
    return len(_rows_v4), len(_rows_v6)


def _search(starts: list[int], rows: list, value: int):
    if not starts:
        return None
    # The rightmost range whose start is <= value; it is a hit only if the
    # address also falls inside that range's end (the space has holes).
    index = bisect.bisect_right(starts, value) - 1
    if index < 0:
        return None
    row = rows[index]
    return row if value <= row[1] else None


def lookup(ip: str) -> dict:
    """Return `{country_code, registry, region}` for an address, or `{}`.

    Never raises: an unparseable address, a missing catalog or unallocated
    space all come back as an empty dict.
    """
    text = str(ip or "").strip()
    if not text:
        return {}
    _load()
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return {}

    value = int(address)
    row = _search(_starts_v6, _rows_v6, value) if address.version == 6 else _search(_starts_v4, _rows_v4, value)
    if not row:
        return {}
    country = str(row[2] or "").upper()
    registry = str(row[3] or "")
    return {
        "country_code": country,
        "registry": registry,
        "region": _regions.get(registry, ""),
    }
