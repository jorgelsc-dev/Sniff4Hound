"""IOC / evidence export for the SOC surfaces.

Everything the dashboard shows lived only behind the JSON list endpoints,
which is fine for the SPA and useless for the rest of a SOC workflow: there
was no way to hand an analyst, a ticket, a SIEM or a blocklist the
indicators this sensor produced without scraping the UI. This module turns
four of `store.py`'s existing listings into flat, IOC-shaped rows and
serialises them as CSV or JSON.

Datasets:

- `alerts`    - monitor hits aggregated per (rule, source, destination,
                port), with severity, the rule that fired, its evidence
                line and first/last seen.
- `endpoints` - every IP the sensor observed, with hit counts, first/last
                seen and the worst severity it was ever flagged with.
- `flows`     - conversations (5-tuple) with packet/byte counts and the
                banner text observed on them.
- `domains`   - domain names seen in DNS/TLS-SNI/HTTP traffic, with the
                address and port they were resolved against.

Every row carries `first_seen`/`last_seen` in the same UTC ISO-8601 format
as the rest of the database, so an exported line stays correlatable with
the packets it came from.

Stdlib only (`csv`, `io`) - consistent with project policy.
"""

from __future__ import annotations

import csv
import io
from typing import Any

from .utils import utc_now


EXPORT_FORMATS = ("json", "csv")

SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")

ALERT_FIELDS = (
    "rule_id",
    "rule",
    "severity",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "proto",
    "domain",
    "interface",
    "direction",
    "detail",
    "hit_count",
    "first_seen",
    "last_seen",
)

ENDPOINT_FIELDS = (
    "ip",
    "private",
    "hit_count",
    "alert_count",
    "max_severity",
    "rules",
    "first_seen",
    "last_seen",
)

FLOW_FIELDS = (
    "flow_key",
    "proto",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "packet_count",
    "byte_count",
    "state",
    "scan_state",
    "banner_text",
    "tags",
    "first_seen",
    "last_seen",
)

DOMAIN_FIELDS = (
    "domain",
    "source",
    "ip",
    "port",
    "proto",
    "hit_count",
    "first_seen",
    "last_seen",
)

EXPORT_FIELDS: dict[str, tuple[str, ...]] = {
    "alerts": ALERT_FIELDS,
    "endpoints": ENDPOINT_FIELDS,
    "flows": FLOW_FIELDS,
    "domains": DOMAIN_FIELDS,
}

EXPORT_DATASETS = tuple(EXPORT_FIELDS)


def normalize_dataset(value: Any) -> str:
    dataset = str(value or "").strip().lower()
    if dataset not in EXPORT_FIELDS:
        raise ValueError(f"dataset must be one of: {', '.join(EXPORT_DATASETS)}")
    return dataset


def normalize_format(value: Any) -> str:
    fmt = str(value or "json").strip().lower()
    if fmt not in EXPORT_FORMATS:
        raise ValueError(f"format must be one of: {', '.join(EXPORT_FORMATS)}")
    return fmt


def _severity_rank(value: Any) -> int:
    name = str(value or "").strip().lower()
    return SEVERITY_ORDER.index(name) if name in SEVERITY_ORDER else -1


def _text(value: Any) -> str:
    return str(value if value is not None else "").strip()


def _int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _alert_rows(store, *, limit: int, offset: int, since: str, severity: str, search: str = "") -> list[dict[str, Any]]:
    """Monitor hits collapsed into indicators.

    `list_recent_alerts()` is per-packet, so a port scan shows up as
    hundreds of near-identical rows. An exported indicator wants one line
    per (rule, source, destination, port) with a count and a first/last
    seen instead - that is the shape a ticket, a SIEM or a blocklist can
    actually consume.

    `search` scopes to one entity (exact IP or domain/http_host match, see
    Store._alert_filter) - without it, exporting "alerts about this host"
    silently returned alerts for the whole database (finding 1.21).
    """
    raw = store.list_recent_alerts(limit=limit, offset=offset, since=since, severity=severity, search=search)
    grouped: dict[tuple, dict[str, Any]] = {}
    for row in raw:
        key = (
            _text(row.get("monitor_id")),
            _text(row.get("monitor")),
            _text(row.get("src_ip")),
            _text(row.get("dst_ip")),
            _int(row.get("dst_port")),
            _text(row.get("proto")),
        )
        created_at = _text(row.get("created_at"))
        entry = grouped.get(key)
        if entry is None:
            entry = {
                "rule_id": key[0],
                "rule": key[1],
                "severity": _text(row.get("severity")),
                "src_ip": key[2],
                "src_port": _int(row.get("src_port")),
                "dst_ip": key[3],
                "dst_port": key[4],
                "proto": key[5],
                "domain": _text(row.get("domain")) or _text(row.get("http_host")),
                "interface": _text(row.get("interface")),
                "direction": _text(row.get("direction")),
                "detail": _text(row.get("detail")),
                "hit_count": 0,
                "first_seen": created_at,
                "last_seen": created_at,
            }
            grouped[key] = entry
        entry["hit_count"] += 1
        if _severity_rank(row.get("severity")) > _severity_rank(entry["severity"]):
            entry["severity"] = _text(row.get("severity"))
        if not entry["detail"]:
            entry["detail"] = _text(row.get("detail"))
        if not entry["domain"]:
            entry["domain"] = _text(row.get("domain")) or _text(row.get("http_host"))
        if created_at:
            if not entry["first_seen"] or created_at < entry["first_seen"]:
                entry["first_seen"] = created_at
            if created_at > entry["last_seen"]:
                entry["last_seen"] = created_at
    rows = list(grouped.values())
    # Worst first, then most recent - the order an analyst triages in.
    rows.sort(key=lambda item: (_severity_rank(item["severity"]), item["last_seen"]), reverse=True)
    return rows


def _alert_index(store, *, since: str) -> tuple[dict[str, dict[str, Any]], bool]:
    """ip -> worst severity / rule names, used to enrich the endpoint
    export so an exported address says *why* it is interesting.

    Returns `(index, partial)`. A read failure used to come back as an
    empty index indistinguishable from "no alerts anywhere" (finding
    1.22) - callers now get `partial=True` and must say so in the export
    instead of silently implying a clean result."""
    index: dict[str, dict[str, Any]] = {}
    try:
        alerts = store.list_recent_alerts(limit=2000, offset=0, since=since, severity="")
    except Exception:
        return index, True
    for row in alerts:
        severity = _text(row.get("severity"))
        rule = _text(row.get("monitor"))
        for ip in (_text(row.get("src_ip")), _text(row.get("dst_ip"))):
            if not ip:
                continue
            entry = index.setdefault(ip, {"alert_count": 0, "max_severity": "", "rules": set()})
            entry["alert_count"] += 1
            if _severity_rank(severity) > _severity_rank(entry["max_severity"]):
                entry["max_severity"] = severity
            if rule:
                entry["rules"].add(rule)
    # The 2000-row cap above is a real limit, not a coincidence of what
    # happened to exist - if it was hit, some ip's alert_count/max_severity
    # here can be an undercount, so that counts as partial too.
    return index, len(alerts) >= 2000


def _endpoint_rows(store, *, limit: int, offset: int, since: str, search: str) -> tuple[list[dict[str, Any]], bool]:
    catalog = store.list_ip_catalog(search=search, limit=limit, offset=offset, since=since)
    alerts, alerts_partial = _alert_index(store, since=since)
    rows = []
    for row in catalog:
        ip = _text(row.get("ip"))
        extra = alerts.get(ip) or {}
        rules = sorted(extra.get("rules") or ())
        rows.append(
            {
                "ip": ip,
                "private": bool(row.get("private")),
                "hit_count": _int(row.get("hit_count")),
                "alert_count": _int(extra.get("alert_count")),
                "max_severity": _text(extra.get("max_severity")),
                "rules": "; ".join(rules),
                "first_seen": _text(row.get("first_seen")),
                "last_seen": _text(row.get("last_seen")),
            }
        )
    return rows, alerts_partial


def _flow_rows(store, *, limit: int, offset: int, search: str, proto: str, since: str) -> list[dict[str, Any]]:
    rows = []
    for row in store.list_flows(proto=proto, search=search, limit=limit, offset=offset, since=since):
        rows.append(
            {
                "flow_key": _text(row.get("flow_key")),
                "proto": _text(row.get("proto")),
                "src_ip": _text(row.get("src_ip")),
                "src_port": _int(row.get("src_port")),
                "dst_ip": _text(row.get("dst_ip")),
                "dst_port": _int(row.get("dst_port")),
                "packet_count": _int(row.get("packet_count")),
                "byte_count": _int(row.get("byte_count")),
                "state": _text(row.get("state")),
                "scan_state": _text(row.get("scan_state")),
                "banner_text": _text(row.get("banner_text")),
                "tags": _text(row.get("tags_json")),
                "first_seen": _text(row.get("first_seen")),
                "last_seen": _text(row.get("last_seen")),
            }
        )
    return rows


def _domain_rows(store, *, limit: int, offset: int, since: str, search: str) -> list[dict[str, Any]]:
    rows = []
    for row in store.list_domains(search=search, limit=limit, offset=offset, since=since):
        rows.append(
            {
                "domain": _text(row.get("name")),
                "source": _text(row.get("source")),
                "ip": _text(row.get("ip")),
                "port": _int(row.get("port")),
                "proto": _text(row.get("proto")),
                "hit_count": _int(row.get("hit_count")),
                "first_seen": _text(row.get("first_seen")),
                "last_seen": _text(row.get("last_seen")),
            }
        )
    return rows


def build_export(
    store,
    dataset: str,
    *,
    limit: int = 5000,
    offset: int = 0,
    since: str = "",
    severity: str = "",
    search: str = "",
    proto: str = "",
) -> dict[str, Any]:
    """Build one export payload: `{dataset, generated_at, fields, count,
    total_available, truncated, partial, rows}`.

    `total_available` is how many rows in the store match the same filter
    that produced `rows` (not just this page's length); `truncated` says
    whether this export's `rows` is a subset of that; `partial` says a
    dependent read (alert enrichment) failed or hit its own cap, so the
    numbers above could be an undercount even where `truncated` is false
    (finding 1.22)."""
    name = normalize_dataset(dataset)
    partial = False
    if name == "alerts":
        # _alert_rows groups a paginated window of raw events - "count=1"
        # here can mean "1 group from a full page of raw hits", not "this
        # rule fired once ever". `total_available` is that raw-event total,
        # so a caller can tell whether the grouped counts might be short.
        total_available = store.count_recent_alerts(since=since, severity=severity, search=search)
        rows = _alert_rows(store, limit=limit, offset=offset, since=since, severity=severity, search=search)
        truncated = total_available > (offset + limit)
        partial = truncated
    elif name == "endpoints":
        rows, alerts_partial = _endpoint_rows(store, limit=limit, offset=offset, since=since, search=search)
        total_available = store.count_ip_catalog(search=search, since=since)
        truncated = total_available > (offset + len(rows))
        partial = alerts_partial
    elif name == "flows":
        rows = _flow_rows(store, limit=limit, offset=offset, search=search, proto=proto, since=since)
        total_available = store.count_flows(proto=proto, search=search, since=since)
        truncated = total_available > (offset + len(rows))
    else:
        rows = _domain_rows(store, limit=limit, offset=offset, since=since, search=search)
        total_available = store.count_domains(search=search, since=since)
        truncated = total_available > (offset + len(rows))
    return {
        "dataset": name,
        "generated_at": utc_now(),
        "since": str(since or ""),
        "limit": limit,
        "offset": offset,
        "counter_scope": "lifetime totals for flows active since cutoff" if name == "flows" else "retained evidence",
        "fields": list(EXPORT_FIELDS[name]),
        "count": len(rows),
        "total_available": total_available,
        "truncated": truncated,
        "partial": partial,
        "rows": rows,
    }


def _csv_safe_cell(value):
    # Quoting alone does not stop spreadsheet formula interpretation.
    if isinstance(value, str) and value.lstrip(" \t\r\n").startswith(("=", "+", "-", "@")):
        return "'" + value
    if isinstance(value, str) and value.startswith(("\t", "\r", "\n")):
        return "'" + value
    return value


def rows_to_csv(fields, rows) -> str:
    """RFC 4180 CSV via the stdlib writer, so a value containing a comma,
    a quote or a newline (a banner, a rule's evidence line) cannot break
    out of its column."""
    buffer = io.StringIO()
    columns = list(fields)
    writer = csv.DictWriter(buffer, fieldnames=columns, extrasaction="ignore", lineterminator="\r\n")
    writer.writeheader()
    for row in rows:
        writer.writerow({column: _csv_safe_cell(row.get(column, "")) for column in columns})
    return buffer.getvalue()


def export_filename(dataset: str, fmt: str) -> str:
    stamp = utc_now().replace(":", "").replace("-", "")
    return f"sniff4hound-{normalize_dataset(dataset)}-{stamp}.{normalize_format(fmt)}"
