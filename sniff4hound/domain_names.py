"""Domain hierarchy helpers backed by the bundled Public Suffix List.

DNS names cannot be grouped reliably by taking the last two labels: for
``service.example.co.uk`` the registrable domain is ``example.co.uk``.  The
Public Suffix List supplies the exact, wildcard and exception rules needed to
find that boundary without sending observed names to an external service.
"""

from __future__ import annotations

import ipaddress
import threading
from typing import Any

from .runtime_paths import resolve_data_file

PUBLIC_SUFFIX_FILENAME = "public_suffix_list.dat"

_lock = threading.Lock()
_loaded = False
_exact_rules: frozenset[str] = frozenset()
_wildcard_rules: frozenset[str] = frozenset()
_exception_rules: frozenset[str] = frozenset()


def _ascii_name(value: Any) -> str:
    text = str(value or "").strip().strip(".").lower()
    if not text or len(text) > 253:
        return ""
    labels = []
    for label in text.split("."):
        if not label:
            return ""
        try:
            labels.append(label.encode("idna").decode("ascii"))
        except UnicodeError:
            # DNS-SD names can contain underscore labels, which Python's IDNA
            # codec intentionally rejects. They are still useful hierarchy.
            labels.append(label)
    return ".".join(labels)


def _load() -> None:
    global _loaded, _exact_rules, _wildcard_rules, _exception_rules
    if _loaded:
        return
    with _lock:
        if _loaded:
            return
        exact: set[str] = set()
        wildcard: set[str] = set()
        exception: set[str] = set()
        try:
            lines = resolve_data_file(PUBLIC_SUFFIX_FILENAME).read_text(encoding="utf-8").splitlines()
        except OSError:
            lines = []
        for raw in lines:
            rule = raw.strip()
            if not rule or rule.startswith("//"):
                continue
            target = exact
            if rule.startswith("!"):
                target = exception
                rule = rule[1:]
            elif rule.startswith("*."):
                target = wildcard
                rule = rule[2:]
            normalized = _ascii_name(rule)
            if normalized:
                target.add(normalized)
        _exact_rules = frozenset(exact)
        _wildcard_rules = frozenset(wildcard)
        _exception_rules = frozenset(exception)
        _loaded = True


def rule_counts() -> dict[str, int]:
    """Rule totals, mainly for catalog integrity checks and diagnostics."""
    _load()
    return {
        "exact": len(_exact_rules),
        "wildcard": len(_wildcard_rules),
        "exception": len(_exception_rules),
    }


def registrable_domain(value: Any) -> str:
    """Return the registrable/base domain for a DNS name.

    IP literals and single-label local names are returned unchanged. If the
    catalog is unavailable, the PSL-defined default ``*`` rule still gives a
    useful last-two-label fallback.
    """
    name = _ascii_name(value)
    if not name:
        return ""
    try:
        ipaddress.ip_address(name)
        return name
    except ValueError:
        pass
    labels = name.split(".")
    if len(labels) == 1:
        return name

    _load()
    exception_labels = 0
    exact_labels = 0
    wildcard_labels = 0
    for index in range(len(labels)):
        suffix = ".".join(labels[index:])
        count = len(labels) - index
        if suffix in _exception_rules:
            exception_labels = max(exception_labels, count)
        if suffix in _exact_rules:
            exact_labels = max(exact_labels, count)
        if index > 0 and suffix in _wildcard_rules:
            wildcard_labels = max(wildcard_labels, count + 1)

    if exception_labels:
        public_suffix_labels = exception_labels - 1
    else:
        public_suffix_labels = max(1, exact_labels, wildcard_labels)
    if len(labels) <= public_suffix_labels:
        return name
    return ".".join(labels[-(public_suffix_labels + 1):])


def describe(value: Any) -> dict[str, Any]:
    """Return base-domain and subdomain fields for one observed name."""
    name = _ascii_name(value)
    base = registrable_domain(name)
    subdomain = ""
    if name and base and name != base and name.endswith(f".{base}"):
        subdomain = name[: -(len(base) + 1)]
    return {
        "base_domain": base,
        "subdomain": subdomain,
        "is_subdomain": bool(subdomain),
    }


def enrich(row: dict, field: str = "domain") -> dict:
    """Add hierarchy fields to an API row in place and return it."""
    row.update(describe(row.get(field)))
    return row
