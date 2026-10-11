"""Storage for the DNS and ARP history (see history.py for what goes in).

A mixin for SniffStore, kept out of store.py so that file does not grow another
screenful of SQL. It relies on the host class for ``_lock``, ``_conn``,
``_fetchall``/``_fetchone`` and the runtime-config accessors.

Three tables, all small by construction because rows are *aggregates*, not
packets: one row per distinct (domain, record type, answer) for DNS, one per
(ip, mac) pair for ARP, and one per notable ARP change. A burst of a million
identical lookups is one row whose counter moved, which is what makes it
affordable to record every one of them regardless of alerts.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any, Iterable

from .history import (
    ARP_EVENT_KINDS,
    HISTORY_DEFAULTS,
    coerce_history_config,
)
from .utils import json_dumps, json_loads, utc_now, utc_since

HISTORY_CONFIG_KEY = "history_config"
# Distinct clients/resolvers remembered per DNS row: enough to see who asks,
# not an unbounded set one DGA run could fill.
MAX_REMEMBERED_PEERS = 20

HISTORY_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS dns_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT NOT NULL,
        record_type TEXT NOT NULL,
        answer TEXT NOT NULL DEFAULT '',
        source TEXT NOT NULL DEFAULT 'dns',
        transport TEXT NOT NULL DEFAULT 'udp',
        query_count INTEGER NOT NULL DEFAULT 0,
        response_count INTEGER NOT NULL DEFAULT 0,
        error_count INTEGER NOT NULL DEFAULT 0,
        last_rcode TEXT NOT NULL DEFAULT '',
        ttl_min INTEGER,
        ttl_max INTEGER,
        ttl_last INTEGER,
        last_client TEXT NOT NULL DEFAULT '',
        last_resolver TEXT NOT NULL DEFAULT '',
        clients_json TEXT NOT NULL DEFAULT '[]',
        resolvers_json TEXT NOT NULL DEFAULT '[]',
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        UNIQUE(domain, record_type, answer)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS arp_bindings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT NOT NULL,
        mac TEXT NOT NULL,
        interface TEXT NOT NULL DEFAULT '',
        packet_count INTEGER NOT NULL DEFAULT 0,
        request_count INTEGER NOT NULL DEFAULT 0,
        reply_count INTEGER NOT NULL DEFAULT 0,
        gratuitous_count INTEGER NOT NULL DEFAULT 0,
        mismatch_count INTEGER NOT NULL DEFAULT 0,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        UNIQUE(ip, mac)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS arp_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        kind TEXT NOT NULL,
        ip TEXT NOT NULL DEFAULT '',
        mac TEXT NOT NULL DEFAULT '',
        previous_ip TEXT NOT NULL DEFAULT '',
        previous_mac TEXT NOT NULL DEFAULT '',
        interface TEXT NOT NULL DEFAULT '',
        detail TEXT NOT NULL DEFAULT '',
        occurred_at TEXT NOT NULL
    )
    """,
)

HISTORY_INDEXES = (
    "CREATE INDEX IF NOT EXISTS idx_dns_history_domain ON dns_history(domain)",
    "CREATE INDEX IF NOT EXISTS idx_dns_history_answer ON dns_history(answer)",
    "CREATE INDEX IF NOT EXISTS idx_dns_history_last_seen ON dns_history(last_seen)",
    "CREATE INDEX IF NOT EXISTS idx_arp_bindings_mac ON arp_bindings(mac)",
    "CREATE INDEX IF NOT EXISTS idx_arp_bindings_ip ON arp_bindings(ip)",
    "CREATE INDEX IF NOT EXISTS idx_arp_bindings_last_seen ON arp_bindings(last_seen)",
    "CREATE INDEX IF NOT EXISTS idx_arp_events_at ON arp_events(occurred_at)",
    "CREATE INDEX IF NOT EXISTS idx_arp_events_kind ON arp_events(kind, occurred_at)",
    "CREATE INDEX IF NOT EXISTS idx_arp_events_ip ON arp_events(ip)",
    "CREATE INDEX IF NOT EXISTS idx_arp_events_mac ON arp_events(mac)",
)

HISTORY_TABLES = ("dns_history", "arp_bindings", "arp_events")
_CLEAR_SCOPES = {
    "dns": ("dns_history",),
    "arp": ("arp_bindings", "arp_events"),
    "all": HISTORY_TABLES,
}


def _merge_peers(existing_json: str, new: Iterable[str]) -> list[str]:
    """The remembered peers with the new ones appended, newest last, capped."""
    merged = [item for item in json_loads(existing_json, default=[]) if isinstance(item, str)]
    for peer in new:
        if peer and peer not in merged:
            merged.append(peer)
    return merged[-MAX_REMEMBERED_PEERS:]


def _like(text: str) -> str:
    return f"%{str(text).strip().lower()}%"


class HistoryStoreMixin:
    # --- configuration ---------------------------------------------------

    def get_history_config(self) -> dict:
        stored = json_loads(self.get_runtime_config(HISTORY_CONFIG_KEY, ""), default={})
        try:
            return coerce_history_config(stored if isinstance(stored, dict) else {})
        except ValueError:
            # A stored value that no longer validates must not stop recording.
            return dict(HISTORY_DEFAULTS)

    def set_history_config(self, values: Any) -> dict:
        config = coerce_history_config(values, self.get_history_config())
        self.set_runtime_config(HISTORY_CONFIG_KEY, json.dumps(config, separators=(",", ":")))
        return config

    # --- writing ---------------------------------------------------------

    def write_history(self, dns: Iterable[dict], arp: Iterable[dict], events: Iterable[dict]) -> dict:
        """Merge aggregated observations into the history tables in one transaction.

        ``dns`` and ``arp`` rows are the recorder's aggregates (counts since the
        last flush); they are added to what is stored. ``events`` are appended.
        """
        dns, arp, events = list(dns), list(arp), list(events)
        written = {"dns": 0, "arp": 0, "events": 0}
        if not (dns or arp or events):
            return written
        with self.write_batch():
            for row in dns:
                self._merge_dns_row(row)
                written["dns"] += 1
            for row in arp:
                self._merge_arp_row(row)
                written["arp"] += 1
            for event in events:
                self._insert_arp_event(event)
                written["events"] += 1
        return written

    def _merge_dns_row(self, row: dict) -> None:
        domain, record_type, answer = row["domain"], row["record_type"], row["answer"]
        existing = self._conn.execute(
            "SELECT id, ttl_min, ttl_max, clients_json, resolvers_json, first_seen, last_seen "
            "FROM dns_history WHERE domain = ? AND record_type = ? AND answer = ?",
            (domain, record_type, answer),
        ).fetchone()
        clients = row.get("clients") or []
        resolvers = row.get("resolvers") or []
        ttl_min, ttl_max, ttl_last = row.get("ttl_min"), row.get("ttl_max"), row.get("ttl_last")
        if existing is None:
            self._conn.execute(
                """
                INSERT INTO dns_history
                (domain, record_type, answer, source, transport, query_count, response_count, error_count,
                 last_rcode, ttl_min, ttl_max, ttl_last, last_client, last_resolver, clients_json,
                 resolvers_json, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    domain, record_type, answer, row["source"], row["transport"],
                    row["query_count"], row["response_count"], row["error_count"], row["last_rcode"],
                    ttl_min, ttl_max, ttl_last, row["last_client"], row["last_resolver"],
                    json_dumps(_merge_peers("[]", clients)), json_dumps(_merge_peers("[]", resolvers)),
                    row["first_seen"], row["last_seen"],
                ),
            )
            return
        merged_min = ttl_min if existing["ttl_min"] is None else (existing["ttl_min"] if ttl_min is None else min(existing["ttl_min"], ttl_min))
        merged_max = ttl_max if existing["ttl_max"] is None else (existing["ttl_max"] if ttl_max is None else max(existing["ttl_max"], ttl_max))
        self._conn.execute(
            """
            UPDATE dns_history SET
              source = ?, transport = ?,
              query_count = query_count + ?, response_count = response_count + ?, error_count = error_count + ?,
              last_rcode = CASE WHEN ? != '' THEN ? ELSE last_rcode END,
              ttl_min = ?, ttl_max = ?, ttl_last = COALESCE(?, ttl_last),
              last_client = CASE WHEN ? != '' THEN ? ELSE last_client END,
              last_resolver = CASE WHEN ? != '' THEN ? ELSE last_resolver END,
              clients_json = ?, resolvers_json = ?,
              first_seen = MIN(first_seen, ?), last_seen = MAX(last_seen, ?)
            WHERE id = ?
            """,
            (
                row["source"], row["transport"],
                row["query_count"], row["response_count"], row["error_count"],
                row["last_rcode"], row["last_rcode"],
                merged_min, merged_max, ttl_last,
                row["last_client"], row["last_client"], row["last_resolver"], row["last_resolver"],
                json_dumps(_merge_peers(existing["clients_json"], clients)),
                json_dumps(_merge_peers(existing["resolvers_json"], resolvers)),
                row["first_seen"], row["last_seen"],
                existing["id"],
            ),
        )

    def _merge_arp_row(self, row: dict) -> None:
        self._conn.execute(
            """
            INSERT INTO arp_bindings
            (ip, mac, interface, packet_count, request_count, reply_count, gratuitous_count, mismatch_count,
             first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip, mac) DO UPDATE SET
              interface = CASE WHEN excluded.interface != '' THEN excluded.interface ELSE interface END,
              packet_count = packet_count + excluded.packet_count,
              request_count = request_count + excluded.request_count,
              reply_count = reply_count + excluded.reply_count,
              gratuitous_count = gratuitous_count + excluded.gratuitous_count,
              mismatch_count = mismatch_count + excluded.mismatch_count,
              first_seen = MIN(first_seen, excluded.first_seen),
              last_seen = MAX(last_seen, excluded.last_seen)
            """,
            (
                row["ip"], row["mac"], row["interface"], row["packet_count"], row["request_count"],
                row["reply_count"], row["gratuitous_count"], row["mismatch_count"],
                row["first_seen"], row["last_seen"],
            ),
        )

    def _insert_arp_event(self, event: dict) -> None:
        kind = str(event.get("kind") or "")
        if kind not in ARP_EVENT_KINDS:
            raise ValueError(f"unknown ARP event kind: {kind}")
        self._conn.execute(
            "INSERT INTO arp_events (kind, ip, mac, previous_ip, previous_mac, interface, detail, occurred_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                kind,
                str(event.get("ip") or ""),
                str(event.get("mac") or ""),
                str(event.get("previous_ip") or ""),
                str(event.get("previous_mac") or ""),
                str(event.get("interface") or ""),
                str(event.get("detail") or "")[:500],
                str(event.get("occurred_at") or utc_now()),
            ),
        )

    def arp_known_pairs(self, limit: int = 100_000) -> list[tuple[str, str]]:
        """Every (ip, mac) pair on record, oldest first, so a recorder that just
        started can tell a new binding from one it saw before the restart."""
        rows = self._fetchall(
            "SELECT ip, mac FROM arp_bindings ORDER BY last_seen ASC, id ASC LIMIT ?", (int(limit),)
        )
        return [(row["ip"], row["mac"]) for row in rows]

    # --- reading ---------------------------------------------------------

    def _dns_filter(self, *, search="", record_type="", rcode="", since="", ip="", domain=""):
        clauses: list[str] = []
        params: list[Any] = []
        if since:
            clauses.append("last_seen >= ?")
            params.append(str(since))
        if record_type:
            clauses.append("UPPER(record_type) = ?")
            params.append(str(record_type).strip().upper())
        if rcode:
            clauses.append("UPPER(last_rcode) = ?")
            params.append(str(rcode).strip().upper())
        if domain:
            clauses.append("domain = ?")
            params.append(str(domain).strip().lower())
        if ip:
            clauses.append("(answer = ? OR last_client = ? OR last_resolver = ? OR clients_json LIKE ?)")
            value = str(ip).strip()
            params.extend([value, value, value, f'%"{value}"%'])
        if search:
            needle = _like(search)
            clauses.append(
                "(LOWER(domain) LIKE ? OR LOWER(answer) LIKE ? OR LOWER(record_type) LIKE ? "
                "OR LOWER(last_client) LIKE ? OR LOWER(last_resolver) LIKE ?)"
            )
            params.extend([needle] * 5)
        return (f"WHERE {' AND '.join(clauses)}" if clauses else ""), params

    def list_dns_history(self, *, search="", record_type="", rcode="", since="", ip="", domain="", limit=200, offset=0):
        where, params = self._dns_filter(search=search, record_type=record_type, rcode=rcode, since=since, ip=ip, domain=domain)
        rows = self._fetchall(
            f"SELECT * FROM dns_history {where} ORDER BY last_seen DESC, id DESC LIMIT ? OFFSET ?",
            (*params, int(limit), int(offset)),
        )
        for row in rows:
            row["clients"] = json_loads(row.pop("clients_json", "[]"), default=[])
            row["resolvers"] = json_loads(row.pop("resolvers_json", "[]"), default=[])
        return rows

    def count_dns_history(self, *, search="", record_type="", rcode="", since="", ip="", domain=""):
        where, params = self._dns_filter(search=search, record_type=record_type, rcode=rcode, since=since, ip=ip, domain=domain)
        row = self._fetchone(f"SELECT COUNT(*) AS count FROM dns_history {where}", tuple(params))
        return int((row or {}).get("count") or 0)

    def _arp_binding_filter(self, *, search="", ip="", mac="", since=""):
        clauses: list[str] = []
        params: list[Any] = []
        if since:
            clauses.append("last_seen >= ?")
            params.append(str(since))
        if ip:
            clauses.append("ip = ?")
            params.append(str(ip).strip())
        if mac:
            clauses.append("mac = ?")
            params.append(str(mac).strip().lower())
        if search:
            needle = _like(search)
            clauses.append("(LOWER(ip) LIKE ? OR LOWER(mac) LIKE ? OR LOWER(interface) LIKE ?)")
            params.extend([needle] * 3)
        return (f"WHERE {' AND '.join(clauses)}" if clauses else ""), params

    def list_arp_bindings(self, *, search="", ip="", mac="", since="", limit=200, offset=0):
        where, params = self._arp_binding_filter(search=search, ip=ip, mac=mac, since=since)
        return self._fetchall(
            f"SELECT * FROM arp_bindings {where} ORDER BY last_seen DESC, id DESC LIMIT ? OFFSET ?",
            (*params, int(limit), int(offset)),
        )

    def count_arp_bindings(self, *, search="", ip="", mac="", since=""):
        where, params = self._arp_binding_filter(search=search, ip=ip, mac=mac, since=since)
        row = self._fetchone(f"SELECT COUNT(*) AS count FROM arp_bindings {where}", tuple(params))
        return int((row or {}).get("count") or 0)

    def list_arp_devices(self, *, search="", since="", limit=200, offset=0):
        """One row per MAC address: every IP it has claimed, and when."""
        where, params = self._arp_binding_filter(search=search, since=since)
        rows = self._fetchall(
            f"""
            SELECT mac,
                   COUNT(*) AS ip_count,
                   GROUP_CONCAT(ip, ',') AS ips,
                   (SELECT b2.ip FROM arp_bindings b2 WHERE b2.mac = b.mac ORDER BY b2.last_seen DESC, b2.id DESC LIMIT 1) AS current_ip,
                   MAX(interface) AS interface,
                   SUM(packet_count) AS packet_count,
                   SUM(mismatch_count) AS mismatch_count,
                   MIN(first_seen) AS first_seen,
                   MAX(last_seen) AS last_seen
            FROM arp_bindings b {where}
            GROUP BY mac
            ORDER BY last_seen DESC, mac
            LIMIT ? OFFSET ?
            """,
            (*params, int(limit), int(offset)),
        )
        for row in rows:
            row["ips"] = [ip for ip in str(row.get("ips") or "").split(",") if ip]
        return rows

    def count_arp_devices(self, *, search="", since=""):
        where, params = self._arp_binding_filter(search=search, since=since)
        row = self._fetchone(f"SELECT COUNT(DISTINCT mac) AS count FROM arp_bindings {where}", tuple(params))
        return int((row or {}).get("count") or 0)

    def _arp_event_filter(self, *, search="", kind="", since="", ip="", mac=""):
        clauses: list[str] = []
        params: list[Any] = []
        if since:
            clauses.append("occurred_at >= ?")
            params.append(str(since))
        if kind:
            clauses.append("kind = ?")
            params.append(str(kind).strip().lower())
        if ip:
            clauses.append("(ip = ? OR previous_ip = ?)")
            params.extend([str(ip).strip()] * 2)
        if mac:
            clauses.append("(mac = ? OR previous_mac = ?)")
            params.extend([str(mac).strip().lower()] * 2)
        if search:
            needle = _like(search)
            clauses.append(
                "(LOWER(ip) LIKE ? OR LOWER(mac) LIKE ? OR LOWER(previous_ip) LIKE ? "
                "OR LOWER(previous_mac) LIKE ? OR LOWER(detail) LIKE ?)"
            )
            params.extend([needle] * 5)
        return (f"WHERE {' AND '.join(clauses)}" if clauses else ""), params

    def list_arp_events(self, *, search="", kind="", since="", ip="", mac="", limit=200, offset=0):
        where, params = self._arp_event_filter(search=search, kind=kind, since=since, ip=ip, mac=mac)
        return self._fetchall(
            f"SELECT * FROM arp_events {where} ORDER BY occurred_at DESC, id DESC LIMIT ? OFFSET ?",
            (*params, int(limit), int(offset)),
        )

    def count_arp_events(self, *, search="", kind="", since="", ip="", mac=""):
        where, params = self._arp_event_filter(search=search, kind=kind, since=since, ip=ip, mac=mac)
        row = self._fetchone(f"SELECT COUNT(*) AS count FROM arp_events {where}", tuple(params))
        return int((row or {}).get("count") or 0)

    def history_totals(self) -> dict:
        """Row counts, for the headers of the history views and the settings panel."""
        counts: dict[str, int] = {}
        for table in HISTORY_TABLES:
            row = self._fetchone(f"SELECT COUNT(*) AS count FROM {table}")
            counts[table] = int((row or {}).get("count") or 0)
        device_row = self._fetchone("SELECT COUNT(DISTINCT mac) AS count FROM arp_bindings")
        counts["arp_devices"] = int((device_row or {}).get("count") or 0)
        return counts

    # --- retention -------------------------------------------------------

    def prune_history(self) -> dict:
        """Apply the history retention: rows older than the window go, then the
        oldest rows over each table's cap. Both are measured on last_seen, so a
        domain or binding that keeps being seen is never aged out."""
        config = self.get_history_config()
        caps = {
            "dns_history": ("last_seen", config["max_dns_rows"]),
            "arp_bindings": ("last_seen", config["max_arp_bindings"]),
            "arp_events": ("occurred_at", config["max_arp_events"]),
        }
        deleted = {table: 0 for table in HISTORY_TABLES}
        with self._lock:
            if config["retention_days"] > 0:
                cutoff = utc_since(config["retention_days"] * 86400)
                for table, (column, _cap) in caps.items():
                    deleted[table] += max(0, self._conn.execute(f"DELETE FROM {table} WHERE {column} < ?", (cutoff,)).rowcount)
            for table, (column, cap) in caps.items():
                count = int(self._conn.execute(f"SELECT COUNT(*) AS c FROM {table}").fetchone()["c"] or 0)
                overflow = count - int(cap)
                if overflow > 0:
                    deleted[table] += max(0, self._conn.execute(
                        f"DELETE FROM {table} WHERE id IN (SELECT id FROM {table} ORDER BY {column} ASC, id ASC LIMIT ?)",
                        (overflow,),
                    ).rowcount)
            self._conn.commit()
        return deleted

    def clear_history(self, scope: str = "all") -> dict:
        tables = _CLEAR_SCOPES.get(str(scope or "").strip().lower())
        if tables is None:
            raise ValueError(f"unknown history scope: {scope!r} (use dns, arp or all)")
        deleted: dict[str, int] = {}
        with self._lock:
            for table in tables:
                try:
                    deleted[table] = max(0, self._conn.execute(f"DELETE FROM {table}").rowcount)
                except sqlite3.Error:
                    deleted[table] = 0
            self._conn.commit()
        return deleted
