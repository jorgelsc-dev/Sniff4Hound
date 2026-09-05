from __future__ import annotations

import ctypes
import ctypes.util
import ipaddress
import json
import re
import sqlite3
import threading
import time
import uuid
from collections import Counter, defaultdict
from pathlib import Path

from . import ip_registry
from .runtime_paths import ensure_data_dir, resolve_data_file
from .monitors import builtin_monitor_seed_fields, describe_match, normalize_monitor
from .protocol_facets import (
    DETAIL_KEYS,
    extract_details,
    facet_expression,
    facet_present_predicate,
    label_value,
    resolve_facets,
    resolve_row_columns,
)
from .rulesets import literal_packet_text_pattern, load_builtin_rulesets, normalize_ruleset
from .settings import (
    MONITOR_FILTER_DEFAULT,
    MONITOR_MIN_SEVERITY_DEFAULT,
    MONITOR_SEVERITIES,
    MONITOR_SUPPRESS_GENERATED_INFO_DEFAULT,
    PAYLOAD_TEXT_MAX_CHARS,
    DECLARED_LATITUDE,
    DECLARED_LOCATION_LABEL,
    DECLARED_LONGITUDE,
    DETECTION_EXCLUDE_SCOPES,
    RETENTION_ALERT_DAYS,
    RETENTION_DAYS,
    RETENTION_INTERVAL_SECONDS,
    RETENTION_MAX_PACKETS,
)
from .utils import (
    KNOWN_PROTOCOLS,
    bytes_to_hex_preview,
    bytes_to_text_preview,
    clamp_int,
    json_dumps,
    json_loads,
    local_ip_candidates,
    normalize_protocol_name,
    normalize_text,
    safe_float,
    safe_int,
    stable_flow_key,
    utc_now,
    utc_since,
)


# Row-count backstops. These are no longer the primary retention policy
# (settings.RETENTION_DAYS is - see _enforce_retention); they only exist so
# a burst of traffic can't grow a table without bound between two temporal
# sweeps. Sized off settings.RETENTION_MAX_PACKETS so raising retention
# raises all of them together.
PACKET_TABLE_LIMIT = int(RETENTION_MAX_PACKETS)
PAYLOAD_TABLE_LIMIT = int(RETENTION_MAX_PACKETS)
FLOW_TABLE_LIMIT = int(RETENTION_MAX_PACKETS)
TAG_TABLE_LIMIT = int(RETENTION_MAX_PACKETS) * 2
DOMAIN_TABLE_LIMIT = 50000
PATH_TABLE_LIMIT = 50000
# A `sessions` row is written per stored packet, and the old
# trim_oversized_tables() never pruned the table at all - 43k rows / 5 MB
# observed on a live instance after minutes of capture.
SESSION_TABLE_LIMIT = 20000
_GEOIP_COUNTRY_DB_PATHS = (
    Path("/usr/share/GeoIP/GeoIP.dat"),
    Path("/usr/local/share/GeoIP/GeoIP.dat"),
)
_GEOIP_COUNTRY_V6_DB_PATHS = (
    Path("/usr/share/GeoIP/GeoIPv6.dat"),
    Path("/usr/local/share/GeoIP/GeoIPv6.dat"),
)
_ZONEINFO_COUNTRY_PATHS = (
    Path("/usr/share/zoneinfo/zone1970.tab"),
    Path("/usr/share/zoneinfo/zone.tab"),
)


def _row_to_dict(row, columns=None):
    if row is None:
        return None
    if columns:
        data = {column: value for column, value in zip(columns, tuple(row))}
    elif isinstance(row, dict):
        data = dict(row)
    elif hasattr(row, "keys"):
        keys = list(row.keys())
        data = {column: value for column, value in zip(keys, tuple(row))}
    else:
        data = dict(row)
    for key, value in list(data.items()):
        if isinstance(value, (bytes, bytearray, memoryview)):
            data[key] = bytes_to_hex_preview(bytes(value))
    return data


def _sqlite_text_factory(value):
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).decode("utf-8", errors="replace")
    return str(value)


def _flatten_packet_details(row: dict) -> dict:
    """A packet row with its decoder extras lifted to top-level keys.

    The extras are stored as one JSON column so the schema does not need a
    column per protocol, but a client should not have to parse a nested blob
    to read a field the table is asked to display. Only whitelisted keys are
    lifted, so a malformed or hand-edited blob cannot introduce arbitrary
    field names. `raw_packet` is dropped here too: it is every captured byte,
    which the Investigate view fetches per packet and a 250-row listing must
    never carry.
    """
    packet = {key: value for key, value in row.items() if key != "raw_packet"}
    details = json_loads(packet.get("details_json") or "{}", {}) or {}
    if isinstance(details, dict):
        for key, value in details.items():
            if key in DETAIL_KEYS:
                packet[key] = value
    return packet


def _coerce_json(value, default):
    if isinstance(value, (dict, list, tuple)):
        return value
    return json_loads(value, default=default)


def _ip_scope(ip: str) -> str:
    text = str(ip or "").strip()
    if not text:
        return "unknown"
    try:
        ip_obj = ipaddress.ip_address(text)
    except Exception:
        return "unknown"
    if ip_obj.is_loopback:
        return "local"
    if ip_obj.is_multicast:
        return "multicast"
    if ip_obj.is_private or ip_obj.is_link_local:
        return "private"
    if getattr(ip_obj, "is_reserved", False) or getattr(ip_obj, "is_unspecified", False):
        return "reserved"
    if ip_obj.is_global:
        return "public"
    return "private"


IP_SCOPES = ("local", "private", "public", "multicast", "reserved", "unknown")

# Ceiling on the distinct-IP scan behind scope filtering and scope counts, so
# a database with a pathological number of unique addresses cannot turn one
# listing request into an unbounded materialisation.
IP_CATALOG_SCAN_LIMIT = 50000

PACKET_LIST_COLUMNS = (
    "id",
    "session_id",
    "flow_key",
    "interface",
    "direction",
    "eth_src",
    "eth_dst",
    "eth_type",
    "ip_version",
    "src_ip",
    "dst_ip",
    "proto",
    "transport",
    "src_port",
    "dst_port",
    "ttl",
    "hop_limit",
    "length",
    "payload_len",
    "state",
    "scan_state",
    "tcp_flags",
    "icmp_type",
    "icmp_code",
    "arp_opcode",
    "summary",
    "payload_text",
    "payload_hex",
    "banner_text",
    "domain",
    "domain_source",
    "http_method",
    "http_path",
    "http_host",
    "details_json",
    "tags_json",
    "rule_hits_json",
    "created_at",
    "updated_at",
)
PACKET_LIST_SELECT = ", ".join(PACKET_LIST_COLUMNS)


def normalize_ip_scope_filter(value) -> tuple:
    """Parse a scope filter ("public", "private,local", ...) into known scopes.

    Unknown names are dropped rather than raising: a stale bookmark asking
    for a scope that no longer exists should show everything, not a 400.
    """
    if isinstance(value, (list, tuple, set)):
        candidates = list(value)
    else:
        candidates = str(value or "").replace(" ", "").split(",")
    wanted = [str(item).strip().lower() for item in candidates if str(item).strip()]
    selected = tuple(dict.fromkeys(scope for scope in wanted if scope in IP_SCOPES))
    # Selecting every scope is the same as selecting none - keep the cheap
    # SQL path in that case.
    return () if len(selected) == len(IP_SCOPES) else selected


def _soc_ip_scope(ip: str) -> str:
    return _ip_scope(ip)


def _parse_iso6709_component(value: str) -> float | None:
    text = str(value or "").strip()
    if not text or text[0] not in "+-":
        return None
    sign = -1.0 if text[0] == "-" else 1.0
    digits = text[1:]
    if len(digits) not in (4, 5, 6, 7) or not digits.isdigit():
        return None
    degree_len = 2 if len(digits) in (4, 6) else 3
    degree = int(digits[:degree_len])
    minute = int(digits[degree_len : degree_len + 2])
    second = int(digits[degree_len + 2 : degree_len + 4]) if len(digits) > degree_len + 2 else 0
    return sign * (degree + (minute / 60.0) + (second / 3600.0))


def _parse_iso6709_pair(value: str) -> tuple[float | None, float | None]:
    text = str(value or "").strip()
    if not text:
        return None, None
    split_at = -1
    for index in range(1, len(text)):
        if text[index] in "+-":
            split_at = index
            break
    if split_at <= 0:
        return None, None
    return _parse_iso6709_component(text[:split_at]), _parse_iso6709_component(text[split_at:])


def _load_country_centroids() -> dict[str, dict[str, float]]:
    buckets: dict[str, list[float]] = {}
    for path in _ZONEINFO_COUNTRY_PATHS:
        if not path.exists():
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception:
            continue
        for line in lines:
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) < 3:
                continue
            countries = [item.strip().upper() for item in parts[0].split(",") if item.strip()]
            lat, lon = _parse_iso6709_pair(parts[1])
            if lat is None or lon is None:
                continue
            for country_code in countries:
                bucket = buckets.setdefault(country_code, [0.0, 0.0, 0.0])
                bucket[0] += lat
                bucket[1] += lon
                bucket[2] += 1.0
        break
    centroids = {}
    for country_code, values in buckets.items():
        count = values[2] or 1.0
        centroids[country_code] = {
            "lat": round(values[0] / count, 6),
            "lon": round(values[1] / count, 6),
        }
    return centroids


class _GeoCountryResolver:
    def __init__(self):
        self._lock = threading.RLock()
        self._cache: dict[str, dict] = {}
        self._centroids = _load_country_centroids()
        self._lib = None
        self._db_v4 = None
        self._db_v6 = None
        self._load_library()

    def _load_library(self):
        library_name = ctypes.util.find_library("GeoIP")
        if not library_name:
            return
        try:
            self._lib = ctypes.CDLL(library_name)
        except Exception:
            self._lib = None
            return
        self._lib.GeoIP_open.argtypes = [ctypes.c_char_p, ctypes.c_int]
        self._lib.GeoIP_open.restype = ctypes.c_void_p
        self._lib.GeoIP_delete.argtypes = [ctypes.c_void_p]
        self._lib.GeoIP_delete.restype = None
        self._lib.GeoIP_country_code_by_addr.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        self._lib.GeoIP_country_code_by_addr.restype = ctypes.c_char_p
        self._lib.GeoIP_country_name_by_addr.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        self._lib.GeoIP_country_name_by_addr.restype = ctypes.c_char_p
        if hasattr(self._lib, "GeoIP_country_code_by_addr_v6"):
            self._lib.GeoIP_country_code_by_addr_v6.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
            self._lib.GeoIP_country_code_by_addr_v6.restype = ctypes.c_char_p
        if hasattr(self._lib, "GeoIP_country_name_by_addr_v6"):
            self._lib.GeoIP_country_name_by_addr_v6.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
            self._lib.GeoIP_country_name_by_addr_v6.restype = ctypes.c_char_p
        self._db_v4 = self._open_database(_GEOIP_COUNTRY_DB_PATHS)
        self._db_v6 = self._open_database(_GEOIP_COUNTRY_V6_DB_PATHS)

    def _open_database(self, paths: tuple[Path, ...]):
        if not self._lib:
            return None
        for path in paths:
            if not path.exists():
                continue
            try:
                handle = self._lib.GeoIP_open(str(path).encode("utf-8"), 0)
            except Exception:
                handle = None
            if handle:
                return handle
        return None

    def describe_source(self) -> str:
        if (self._db_v4 or self._db_v6) and self._centroids:
            return "country-db-zoneinfo"
        if self._db_v4 or self._db_v6:
            return "country-db"
        if ip_registry.is_available():
            return "rir-registry-zoneinfo" if self._centroids else "rir-registry"
        return "empty"

    def lookup(self, ip: str) -> dict:
        text = str(ip or "").strip()
        if not text:
            return {}
        cached = self._cache.get(text)
        if cached is not None:
            return dict(cached)
        try:
            ip_obj = ipaddress.ip_address(text)
        except Exception:
            return {}

        country_code = ""
        country_name = ""
        encoded = text.encode("utf-8", errors="ignore")
        with self._lock:
            if ip_obj.version == 6 and self._db_v6 and hasattr(self._lib, "GeoIP_country_code_by_addr_v6"):
                raw_code = self._lib.GeoIP_country_code_by_addr_v6(self._db_v6, encoded)
                raw_name = self._lib.GeoIP_country_name_by_addr_v6(self._db_v6, encoded)
            elif self._db_v4:
                raw_code = self._lib.GeoIP_country_code_by_addr(self._db_v4, encoded)
                raw_name = self._lib.GeoIP_country_name_by_addr(self._db_v4, encoded)
            else:
                raw_code = None
                raw_name = None
        if raw_code:
            try:
                country_code = raw_code.decode("utf-8", errors="ignore").strip().upper()
            except Exception:
                country_code = ""
        if raw_name:
            try:
                country_name = raw_name.decode("utf-8", errors="ignore").strip()
            except Exception:
                country_name = ""

        registry_name = ""
        region_name = ""
        if not country_code:
            # No libGeoIP, no country database, or an address it does not
            # cover: fall back to the bundled RIR delegation catalog, which
            # is the same data those databases are built from.
            registry_hit = ip_registry.lookup(text)
            if registry_hit:
                country_code = registry_hit.get("country_code") or ""
                registry_name = registry_hit.get("registry") or ""
                region_name = registry_hit.get("region") or ""

        centroid = self._centroids.get(country_code or "")
        result = {
            "found": bool(country_code),
            "country_code": country_code,
            "country": country_name,
            "registry": registry_name,
            "region": region_name,
            "lat": centroid.get("lat") if centroid else None,
            "lon": centroid.get("lon") if centroid else None,
            "precision": "country" if centroid else "",
            "source": self.describe_source(),
        }
        self._cache[text] = dict(result)
        return result

    def close(self):
        with self._lock:
            for handle in (self._db_v4, self._db_v6):
                if handle and self._lib:
                    try:
                        self._lib.GeoIP_delete(handle)
                    except Exception:
                        pass
            self._db_v4 = None
            self._db_v6 = None


def _soc_payload_signature(text: str) -> str:
    raw = str(text or "").strip()
    if not raw:
        return "empty"
    lowered = raw.lower()
    if raw.startswith("{") or raw.startswith("[") or '"type":' in lowered or '"packet"' in lowered:
        return "structured"
    if lowered.startswith("get ") or lowered.startswith("post ") or "http/" in lowered:
        return "http-like"
    alnum_space = sum(ch.isalnum() or ch.isspace() for ch in raw)
    symbol_ratio = 1 - (alnum_space / max(1, len(raw)))
    if symbol_ratio > 0.32 or (len(raw) > 80 and raw.count(" ") < len(raw) * 0.18):
        return "noisy"
    return "text"


class SniffStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        if not self.path.is_absolute():
            self.path = Path.cwd() / self.path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._last_retention_at = 0.0
        self._conn = self._open_connection()
        self._geoip_resolver = _GeoCountryResolver()
        self._create_schema()
        self._seed_baseline()

    def _open_connection(self):
        conn = sqlite3.connect(self.path, check_same_thread=False)
        conn.text_factory = _sqlite_text_factory
        conn.row_factory = sqlite3.Row
        # auto_vacuum only takes effect if it's set before anything else
        # touches the (empty) file - including switching the journal mode,
        # which was found to already be enough to lock it in at NONE. That
        # ordering bug meant every database this app ever created had
        # auto_vacuum permanently off despite the PRAGMA call below: every
        # PRAGMA incremental_vacuum elsewhere (purge_capture_data,
        # enforce_retention's per-trim reclaim) was a silent no-op, so the
        # file only ever grew and never gave space back, on every purge and
        # every retention cycle. Changing auto_vacuum on an existing
        # non-empty database needs a full VACUUM (the exact stall this
        # codebase deliberately avoids elsewhere), so this fixes it only for
        # a database created from now on - an existing one keeps its
        # current mode until it's recreated.
        conn.execute("PRAGMA auto_vacuum=INCREMENTAL")
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def _recover_connection(self):
        """Get this connection writable again after a "database is locked".

        Two processes share this database - the unprivileged web process and
        the privileged capture child - and a connection can be left unable to
        write while the database itself is perfectly free (observed after a
        purge: the capture child failed on every single packet for twenty
        minutes while other connections took the write lock instantly). A
        rollback clears the common case; when it does not, the connection is
        replaced outright. Losing a connection is cheap. Silently dropping
        every captured packet until the process is restarted is not.
        """
        try:
            self._conn.rollback()
            self._conn.execute("SELECT 1").fetchone()
            return
        except sqlite3.Error:
            pass
        try:
            self._conn.close()
        except sqlite3.Error:
            pass
        self._conn = self._open_connection()

    @property
    def local_ips(self) -> set[str]:
        return local_ip_candidates()

    def _create_schema(self):
        schema = [
            """
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                network TEXT NOT NULL,
                type TEXT NOT NULL,
                proto TEXT NOT NULL,
                port_mode TEXT NOT NULL,
                port_start INTEGER NOT NULL DEFAULT 0,
                port_end INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'stopped',
                timesleep REAL NOT NULL DEFAULT 0.5,
                progress REAL NOT NULL DEFAULT 0.0,
                interface TEXT NOT NULL DEFAULT '',
                filter_text TEXT NOT NULL DEFAULT '',
                packets_seen INTEGER NOT NULL DEFAULT 0,
                bytes_seen INTEGER NOT NULL DEFAULT 0,
                rules_seen INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS flows (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                flow_key TEXT NOT NULL UNIQUE,
                proto TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                src_port INTEGER NOT NULL DEFAULT 0,
                dst_port INTEGER NOT NULL DEFAULT 0,
                packet_count INTEGER NOT NULL DEFAULT 0,
                byte_count INTEGER NOT NULL DEFAULT 0,
                state TEXT NOT NULL DEFAULT 'open',
                scan_state TEXT NOT NULL DEFAULT 'active',
                banner_text TEXT NOT NULL DEFAULT '',
                tags_json TEXT NOT NULL DEFAULT '[]',
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL DEFAULT 0,
                flow_key TEXT NOT NULL DEFAULT '',
                interface TEXT NOT NULL DEFAULT '',
                direction TEXT NOT NULL DEFAULT 'unknown',
                eth_src TEXT NOT NULL DEFAULT '',
                eth_dst TEXT NOT NULL DEFAULT '',
                eth_type INTEGER NOT NULL DEFAULT 0,
                ip_version INTEGER NOT NULL DEFAULT 0,
                src_ip TEXT NOT NULL DEFAULT '',
                dst_ip TEXT NOT NULL DEFAULT '',
                proto TEXT NOT NULL DEFAULT 'unknown',
                transport TEXT NOT NULL DEFAULT '',
                src_port INTEGER NOT NULL DEFAULT 0,
                dst_port INTEGER NOT NULL DEFAULT 0,
                ttl INTEGER NOT NULL DEFAULT 0,
                hop_limit INTEGER NOT NULL DEFAULT 0,
                length INTEGER NOT NULL DEFAULT 0,
                payload_len INTEGER NOT NULL DEFAULT 0,
                state TEXT NOT NULL DEFAULT 'open',
                scan_state TEXT NOT NULL DEFAULT 'active',
                tcp_flags TEXT NOT NULL DEFAULT '',
                icmp_type INTEGER NOT NULL DEFAULT 0,
                icmp_code INTEGER NOT NULL DEFAULT 0,
                arp_opcode INTEGER NOT NULL DEFAULT 0,
                summary TEXT NOT NULL DEFAULT '',
                payload_text TEXT NOT NULL DEFAULT '',
                payload_hex TEXT NOT NULL DEFAULT '',
                banner_text TEXT NOT NULL DEFAULT '',
                domain TEXT NOT NULL DEFAULT '',
                domain_source TEXT NOT NULL DEFAULT '',
                http_method TEXT NOT NULL DEFAULT '',
                http_path TEXT NOT NULL DEFAULT '',
                http_host TEXT NOT NULL DEFAULT '',
                details_json TEXT NOT NULL DEFAULT '{}',
                tags_json TEXT NOT NULL DEFAULT '[]',
                rule_hits_json TEXT NOT NULL DEFAULT '[]',
                raw_packet BLOB,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS payloads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                packet_id INTEGER NOT NULL,
                flow_key TEXT NOT NULL DEFAULT '',
                ip TEXT NOT NULL DEFAULT '',
                port INTEGER NOT NULL DEFAULT 0,
                proto TEXT NOT NULL DEFAULT 'unknown',
                response_plain TEXT NOT NULL DEFAULT '',
                response_size INTEGER NOT NULL DEFAULT 0,
                scan_state TEXT NOT NULL DEFAULT 'active',
                port_id INTEGER NOT NULL DEFAULT 0,
                favicon_id INTEGER NOT NULL DEFAULT 0,
                state TEXT NOT NULL DEFAULT 'open',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS tags (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                packet_id INTEGER NOT NULL,
                flow_key TEXT NOT NULL DEFAULT '',
                ip TEXT NOT NULL DEFAULT '',
                port INTEGER NOT NULL DEFAULT 0,
                proto TEXT NOT NULL DEFAULT 'unknown',
                key TEXT NOT NULL DEFAULT '',
                value TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS rulesets (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                enabled INTEGER NOT NULL DEFAULT 1,
                priority INTEGER NOT NULL DEFAULT 100,
                source TEXT NOT NULL DEFAULT 'custom',
                match_json TEXT NOT NULL DEFAULT '{}',
                action_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS runtime_config (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS domains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                source TEXT NOT NULL DEFAULT '',
                ip TEXT NOT NULL DEFAULT '',
                port INTEGER NOT NULL DEFAULT 0,
                proto TEXT NOT NULL DEFAULT '',
                hit_count INTEGER NOT NULL DEFAULT 1,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS paths (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT NOT NULL,
                method TEXT NOT NULL DEFAULT 'GET',
                host TEXT NOT NULL DEFAULT '',
                ip TEXT NOT NULL DEFAULT '',
                port INTEGER NOT NULL DEFAULT 0,
                hit_count INTEGER NOT NULL DEFAULT 1,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(method, path, host)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS monitors (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                enabled INTEGER NOT NULL DEFAULT 1,
                priority INTEGER NOT NULL DEFAULT 100,
                source TEXT NOT NULL DEFAULT 'custom',
                mode TEXT NOT NULL DEFAULT 'rule',
                match_json TEXT NOT NULL DEFAULT '{}',
                action_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS honeypot_listeners (
                id TEXT PRIMARY KEY,
                proto TEXT NOT NULL,
                port INTEGER NOT NULL,
                label TEXT NOT NULL DEFAULT '',
                enabled INTEGER NOT NULL DEFAULT 1,
                source TEXT NOT NULL DEFAULT 'builtin',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS blacklist_entries (
                id TEXT PRIMARY KEY,
                category TEXT NOT NULL,
                match_type TEXT NOT NULL DEFAULT 'exact',
                value TEXT NOT NULL,
                label TEXT NOT NULL DEFAULT '',
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS whitelist_entries (
                id TEXT PRIMARY KEY,
                category TEXT NOT NULL,
                match_type TEXT NOT NULL DEFAULT 'exact',
                value TEXT NOT NULL,
                label TEXT NOT NULL DEFAULT '',
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """,
        ]
        with self._lock:
            for statement in schema:
                self._conn.execute(statement)
            self._conn.commit()
            self._migrate_packets_columns()
            self._migrate_tags_columns()
            self._create_indexes()

    def _migrate_packets_columns(self):
        existing = {row["name"] for row in self._conn.execute("PRAGMA table_info(packets)")}
        additions = {
            "domain": "TEXT NOT NULL DEFAULT ''",
            "domain_source": "TEXT NOT NULL DEFAULT ''",
            "http_method": "TEXT NOT NULL DEFAULT ''",
            "http_path": "TEXT NOT NULL DEFAULT ''",
            "http_host": "TEXT NOT NULL DEFAULT ''",
            # Transport under an identified application protocol; see
            # build_base_packet(). Empty on rows written before this column
            # existed, which is why every read treats "" as "unknown", never
            # as "not TCP".
            "transport": "TEXT NOT NULL DEFAULT ''",
            # Decoder output that has no column of its own. app_decoders emits
            # roughly forty fields and the table only ever had columns for five
            # of them, so the rest - the HTTP Server header, the TLS version,
            # the SSH software banner, the SIP peers - was extracted on every
            # packet and then discarded here. Storing it as JSON keeps those
            # facts queryable without a column per protocol, and without a
            # migration every time a decoder learns a new field.
            "details_json": "TEXT NOT NULL DEFAULT '{}'",
        }
        for column, definition in additions.items():
            if column not in existing:
                self._conn.execute(f"ALTER TABLE packets ADD COLUMN {column} {definition}")
        self._conn.commit()

    def _migrate_tags_columns(self):
        # `severity` lets list_recent_alerts() answer "which hosts have
        # monitor hits, and how bad" straight from the small `tags` table
        # (indexed by key) instead of scanning full `packets` rows
        # (raw_packet/payload_text/tags_json and the rest) just to reread a
        # value already present on the tag dict that register_packet() was
        # handed.
        existing = {row["name"] for row in self._conn.execute("PRAGMA table_info(tags)")}
        if "severity" not in existing:
            self._conn.execute("ALTER TABLE tags ADD COLUMN severity TEXT NOT NULL DEFAULT ''")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_tags_key_packet ON tags(key, packet_id)")
        self._conn.commit()

    def _create_indexes(self):
        # `packets` had no index at all beyond its implicit rowid, which
        # only went unnoticed because the table was capped at 2000 rows.
        # Temporal retention (settings.RETENTION_DAYS) makes it grow by
        # several orders of magnitude, and every one of these columns is
        # filtered on by list_packets()/ip_intel()/enforce_retention().
        for statement in (
            "CREATE INDEX IF NOT EXISTS idx_packets_created ON packets(created_at)",
            "CREATE INDEX IF NOT EXISTS idx_packets_src ON packets(src_ip, created_at)",
            "CREATE INDEX IF NOT EXISTS idx_packets_dst ON packets(dst_ip, created_at)",
            "CREATE INDEX IF NOT EXISTS idx_packets_flow ON packets(flow_key)",
            "CREATE INDEX IF NOT EXISTS idx_packets_iface ON packets(interface, created_at)",
            "CREATE INDEX IF NOT EXISTS idx_packets_proto_dp ON packets(proto, dst_port)",
            "CREATE INDEX IF NOT EXISTS idx_packets_domain ON packets(domain)",
            "CREATE INDEX IF NOT EXISTS idx_tags_severity ON tags(severity, packet_id)",
            "CREATE INDEX IF NOT EXISTS idx_tags_packet ON tags(packet_id)",
            "CREATE INDEX IF NOT EXISTS idx_payloads_packet ON payloads(packet_id)",
            "CREATE INDEX IF NOT EXISTS idx_flows_last_seen ON flows(last_seen)",
            "CREATE INDEX IF NOT EXISTS idx_domains_ip ON domains(ip)",
            "CREATE INDEX IF NOT EXISTS idx_blacklist_category ON blacklist_entries(category, enabled)",
            "CREATE INDEX IF NOT EXISTS idx_whitelist_category ON whitelist_entries(category, enabled)",
        ):
            self._conn.execute(statement)
        self._conn.commit()

    def _seed_baseline(self):
        with self._lock:
            cursor = self._conn.execute("SELECT COUNT(*) AS count FROM rulesets")
            count = int(cursor.fetchone()["count"] or 0)
            if count == 0:
                now = utc_now()
                for rule in load_builtin_rulesets():
                    self._conn.execute(
                        """
                        INSERT OR REPLACE INTO rulesets
                        (id, name, description, enabled, priority, source, match_json, action_json, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            str(rule.get("id") or rule.get("name")),
                            str(rule.get("name") or rule.get("id")),
                            str(rule.get("description") or ""),
                            1 if rule.get("enabled", True) else 0,
                            safe_int(rule.get("priority", 100), 100),
                            str(rule.get("source") or "builtin"),
                            json_dumps(rule.get("match") or {}),
                            json_dumps(rule.get("action") or {}),
                            now,
                            now,
                        ),
                    )
                self._conn.commit()

            cursor = self._conn.execute("SELECT COUNT(*) AS count FROM monitors")
            count = int(cursor.fetchone()["count"] or 0)
            if count == 0:
                now = utc_now()
                rows = [
                    (
                        monitor_id,
                        name,
                        description,
                        enabled,
                        priority,
                        source,
                        mode,
                        match_json,
                        action_json,
                        now,
                        now,
                    )
                    for (
                        monitor_id,
                        name,
                        description,
                        enabled,
                        priority,
                        source,
                        mode,
                        match_json,
                        action_json,
                    ) in builtin_monitor_seed_fields()
                ]
                self._conn.executemany(
                    """
                    INSERT OR REPLACE INTO monitors
                    (id, name, description, enabled, priority, source, mode, match_json, action_json, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    rows,
                )
                self._conn.commit()

            self._seed_new_builtin_monitors()
            self._apply_new_monitor_defaults_once()

        self._seed_file_catalogs()
        self._seed_builtin_honeypot_listeners()

    def _seed_builtin_honeypot_listeners(self):
        """Additive migration, same shape as `_seed_new_builtin_monitors`:
        insert any built-in listener (from `honeypot.COMMON_PORTS`) that
        isn't already in the table, by id, without touching any existing
        row - so a listener the user has since disabled stays disabled
        across restarts, and a new port added to COMMON_PORTS in a later
        release still reaches already-populated databases."""
        from .honeypot_ports import COMMON_PORTS, DEFAULT_ENABLED_PORTS, service_label

        cursor = self._conn.execute("SELECT id, label FROM honeypot_listeners")
        existing_rows = {str(row["id"]): dict(row) for row in cursor.fetchall()}
        now = utc_now()
        update_rows = []
        insert_rows = []
        for proto in ("tcp", "udp"):
            default_enabled = set(DEFAULT_ENABLED_PORTS.get(proto, ()))
            for port in COMMON_PORTS.get(proto, ()):
                listener_id = f"{proto}/{port}"
                label = service_label(proto, int(port))
                if listener_id in existing_rows:
                    if not str(existing_rows[listener_id].get("label") or "").strip():
                        update_rows.append((label, listener_id))
                    continue
                insert_rows.append(
                    (listener_id, proto, int(port), label, 1 if int(port) in default_enabled else 0, now, now)
                )
        if update_rows:
            self._conn.executemany("UPDATE honeypot_listeners SET label = ? WHERE id = ?", update_rows)
        if insert_rows:
            self._conn.executemany(
                """
                INSERT OR IGNORE INTO honeypot_listeners
                (id, proto, port, label, enabled, source, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, 'builtin', ?, ?)
                """,
                insert_rows,
            )
        if update_rows or insert_rows:
            self._conn.commit()

    def list_honeypot_listeners(self):
        rows = self._fetchall("SELECT * FROM honeypot_listeners ORDER BY proto ASC, port ASC")
        for row in rows:
            row["enabled"] = bool(row.get("enabled"))
        return rows

    def count_honeypot_listeners(self) -> dict:
        row = self._fetchone(
            """
            SELECT
              COUNT(*) AS total,
              COALESCE(SUM(CASE WHEN enabled THEN 1 ELSE 0 END), 0) AS enabled,
              COALESCE(SUM(CASE WHEN source = 'custom' THEN 1 ELSE 0 END), 0) AS custom
            FROM honeypot_listeners
            """
        )
        return {
            "total": safe_int((row or {}).get("total"), 0),
            "enabled": safe_int((row or {}).get("enabled"), 0),
            "custom": safe_int((row or {}).get("custom"), 0),
        }

    def get_honeypot_listener(self, listener_id: str):
        row = self._fetchone("SELECT * FROM honeypot_listeners WHERE id = ?", (str(listener_id),))
        if not row:
            return None
        row["enabled"] = bool(row.get("enabled"))
        return row

    def create_honeypot_listener(self, proto: str, port: int, label: str = ""):
        proto = str(proto or "").strip().lower()
        if proto not in ("tcp", "udp"):
            raise ValueError("proto must be 'tcp' or 'udp'")
        port = safe_int(port, 0)
        if port < 1 or port > 65535:
            raise ValueError("port must be between 1 and 65535")
        listener_id = f"{proto}/{port}"
        if self.get_honeypot_listener(listener_id):
            raise ValueError(f"Listener {listener_id} already exists")
        now = utc_now()
        self._execute(
            """
            INSERT INTO honeypot_listeners (id, proto, port, label, enabled, source, created_at, updated_at)
            VALUES (?, ?, ?, ?, 1, 'custom', ?, ?)
            """,
            (listener_id, proto, port, str(label or ""), now, now),
            commit=True,
        )
        return self.get_honeypot_listener(listener_id)

    def set_honeypot_listener_enabled(self, listener_id: str, enabled: bool):
        """Flip a listener's `enabled` flag only - this is the *only* way to
        change any listener after creation, builtin or custom alike; there
        is deliberately no edit/delete path (see honeypot.py's HoneypotView
        docs) so the historical record of what was ever exposed stays intact."""
        existing = self.get_honeypot_listener(listener_id)
        if not existing:
            raise ValueError(f"Unknown listener id: {listener_id}")
        now = utc_now()
        self._execute(
            "UPDATE honeypot_listeners SET enabled = ?, updated_at = ? WHERE id = ?",
            (1 if enabled else 0, now, str(listener_id)),
            commit=True,
        )
        return self.get_honeypot_listener(listener_id)

    def _seed_new_builtin_monitors(self):
        """Additive + pruning + definition-sync migration, run on every
        startup (not just against a brand new DB - see the `count == 0`
        seeding above):

        - Insert any catalog id that isn't already in the table, by id,
          without touching any existing row - so monitors added in a later
          release reach already-populated databases too.
        - Remove any *builtin* row whose id is no longer in the current
          catalog. The bundled catalog can and does change between
          releases as quality filters improve (a pattern
          that turned out to be a false-positive magnet, or too broad to
          be a meaningful signature at all) - without this, a row seeded by
          an earlier, broader catalog would sit in the table and keep
          matching live traffic forever, since a plain additive migration
          only ever adds. Already-stored packets/tags that reference a
          pruned id are untouched (they're the historical record of what
          it once flagged); only the live definition goes away.
        - Sync name/description/priority/mode/match_json/action_json for
          any *builtin* row whose catalog definition changed since it was
          seeded (e.g. a false-positive-prone regex/content literal
          tightened, or a severity re-classified by the native catalog
          builder). Deliberately leaves
          `enabled` untouched: that's the one field a user can have
          manually flipped (via /api/monitors/toggle) on a builtin
          monitor, and a catalog update must never silently re-enable or
          re-disable a row the user already made a call on. Only a fix
          that ships as a *removed* id (handled by the pruning step above)
          can retroactively force a monitor off.

        Never touches a `source = 'custom'` row for either the delete or
        the sync - a user's own monitor is never in the bundled catalog
        to begin with, so it can't collide, but both are still scoped to
        `source = 'builtin'` as a second guard.
        """
        cursor = self._conn.execute(
            "SELECT id, source, name, description, priority, mode, match_json, action_json FROM monitors"
        )
        existing_rows = {str(row["id"]): dict(row) for row in cursor.fetchall()}

        catalog = builtin_monitor_seed_fields()
        catalog_ids = {row[0] for row in catalog}

        now = utc_now()
        insert_rows = []
        update_rows = []
        for (
            monitor_id,
            name,
            description,
            enabled,
            priority,
            source,
            mode,
            match_json,
            action_json,
        ) in catalog:
            existing = existing_rows.get(monitor_id)
            if existing is None:
                insert_rows.append(
                    (
                        monitor_id,
                        name,
                        description,
                        enabled,
                        priority,
                        source,
                        mode,
                        match_json,
                        action_json,
                        now,
                        now,
                    )
                )
                continue
            if existing.get("source") != "builtin":
                continue
            if (
                existing.get("name") == name
                and existing.get("description") == description
                and safe_int(existing.get("priority"), 100) == priority
                and existing.get("mode") == mode
                and existing.get("match_json") == match_json
                and existing.get("action_json") == action_json
            ):
                continue
            update_rows.append((name, description, priority, mode, match_json, action_json, now, monitor_id))

        if insert_rows:
            # executemany() over one prepared statement instead of one
            # execute() call per row - with thousands of builtin monitors
            # this migration runs on every single startup (not just the first), so the
            # per-statement overhead of a Python-level loop adds up fast.
            self._conn.executemany(
                """
                INSERT OR IGNORE INTO monitors
                (id, name, description, enabled, priority, source, mode, match_json, action_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                insert_rows,
            )
        if update_rows:
            self._conn.executemany(
                """
                UPDATE monitors
                SET name = ?, description = ?, priority = ?, mode = ?, match_json = ?, action_json = ?, updated_at = ?
                WHERE id = ? AND source = 'builtin'
                """,
                update_rows,
            )

        stale_builtin_ids = [
            monitor_id
            for monitor_id, row in existing_rows.items()
            if row.get("source") == "builtin" and monitor_id not in catalog_ids
        ]
        if stale_builtin_ids:
            placeholders = ",".join("?" for _ in stale_builtin_ids)
            self._conn.execute(
                f"DELETE FROM monitors WHERE source = 'builtin' AND id IN ({placeholders})",
                stale_builtin_ids,
            )

        if insert_rows or update_rows or stale_builtin_ids:
            self._conn.commit()

    def _apply_new_monitor_defaults_once(self):
        """One-time reset of builtin `enabled` to the current catalog's
        defaults, for databases seeded before the "critical monitors on by
        default, the rest opt-in" policy shipped.

        `_seed_new_builtin_monitors` above deliberately never overwrites
        `enabled` on an already-seeded row - that's the right behavior
        going forward (a user's manual toggle must survive a later catalog
        update), but it also means an existing database seeded under the
        old "almost everything on" defaults would keep that state forever
        without one deliberate, versioned reset. Guarded by a
        `runtime_config` flag so this runs exactly once per database, ever
        - after that, `_seed_new_builtin_monitors`'s normal never-touch-
        `enabled` rule applies again and any toggle made after the reset
        is respected like any other.
        """
        MIGRATION_KEY = "builtin_monitor_defaults_reset_v2"
        if self.get_runtime_config(MIGRATION_KEY, "") == "1":
            return
        rows = [(enabled, monitor_id) for monitor_id, _, _, enabled, *_ in builtin_monitor_seed_fields()]
        if rows:
            self._conn.executemany(
                "UPDATE monitors SET enabled = ? WHERE id = ? AND source = 'builtin'",
                rows,
            )
            self._conn.commit()
        self.set_runtime_config(MIGRATION_KEY, "1")

    def _seed_file_catalogs(self):
        catalogs = {
            "banner_regex_rules.json": load_builtin_rulesets(),
            "banner_probe_requests.json": [
                {
                    "id": "http-get",
                    "name": "HTTP GET",
                    "description": "Common HTTP request pattern for live payload previews.",
                    "enabled": True,
                    "priority": 10,
                    "match": {"protocols": ["tcp"], "payload_contains": ["GET "]},
                    "action": {"tag": "http-get", "label": "HTTP GET", "severity": "low"},
                },
                {
                    "id": "http-post",
                    "name": "HTTP POST",
                    "description": "Common HTTP POST payload pattern.",
                    "enabled": True,
                    "priority": 11,
                    "match": {"protocols": ["tcp"], "payload_contains": ["POST "]},
                    "action": {"tag": "http-post", "label": "HTTP POST", "severity": "low"},
                },
            ],
            "ip_presets.json": [
                {
                    "id": "all-interfaces",
                    "name": "All interfaces",
                    "description": "Watch every visible interface and store every observed packet.",
                    "interface": "",
                    "network": "0.0.0.0/0",
                    "proto": "all",
                    "port_mode": "preset",
                    "port_start": 0,
                    "port_end": 0,
                },
                {
                    "id": "loopback",
                    "name": "Loopback",
                    "description": "Useful local-development preset.",
                    "interface": "lo",
                    "network": "127.0.0.0/8",
                    "proto": "tcp",
                    "port_mode": "preset",
                    "port_start": 0,
                    "port_end": 0,
                },
            ],
        }
        for filename, payload in catalogs.items():
            path = resolve_data_file(filename)
            if path.exists():
                continue
            try:
                path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
            except Exception:
                pass

    def close(self):
        with self._lock:
            try:
                self._geoip_resolver.close()
            except Exception:
                pass
            try:
                self._conn.close()
            except Exception:
                pass

    # SQLite reports a busy/wedged connection through more than one
    # exception class - most commonly OperationalError, but a connection
    # that got out of sync with the file underneath it (the other of the
    # two processes sharing this database committed or checkpointed at just
    # the wrong moment) can also surface as the base DatabaseError, e.g.
    # "another row available" - so every sqlite3.Error is inspected, and
    # only its message decides whether it's worth a recovery attempt versus
    # a genuine SQL error that must propagate untouched.
    _RECOVERABLE_ERRORS = (
        "database is locked",
        "database is busy",
        "cannot commit",
        "closed database",
        "another row available",
    )

    def _execute(self, sql, params=(), *, commit=False):
        with self._lock:
            try:
                cursor = self._conn.execute(sql, params)
                if commit:
                    self._conn.commit()
                return cursor
            except sqlite3.Error as exc:
                message = str(exc).lower()
                if not any(token in message for token in self._RECOVERABLE_ERRORS):
                    raise
                # One retry on a fresh or rolled-back connection. Anything
                # still failing after that is a real problem and propagates.
                self._recover_connection()
                cursor = self._conn.execute(sql, params)
                if commit:
                    self._conn.commit()
                return cursor

    def _fetchall(self, sql, params=()):
        cursor = self._execute(sql, params)
        columns = [column[0] for column in (cursor.description or ())]
        return [_row_to_dict(row, columns=columns) for row in cursor.fetchall()]

    def _fetchone(self, sql, params=()):
        cursor = self._execute(sql, params)
        columns = [column[0] for column in (cursor.description or ())]
        return _row_to_dict(cursor.fetchone(), columns=columns)

    def _ensure_session(self, session_id: int):
        if session_id and self._fetchone("SELECT id FROM sessions WHERE id = ?", (session_id,)):
            return int(session_id)
        now = utc_now()
        cursor = self._execute(
            """
            INSERT INTO sessions
            (network, type, proto, port_mode, port_start, port_end, status, timesleep, progress, interface,
             filter_text, packets_seen, bytes_seen, rules_seen, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 0, ?, ?)
            """,
            (
                "0.0.0.0/0",
                "all",
                "all",
                "preset",
                0,
                0,
                "active",
                0.5,
                0.0,
                "",
                "",
                now,
                now,
            ),
            commit=True,
        )
        return int(cursor.lastrowid)

    def create_session(self, data: dict) -> dict:
        now = utc_now()
        payload = {
            "network": str(data.get("network") or "0.0.0.0/0").strip() or "0.0.0.0/0",
            "type": str(data.get("type") or "all").strip() or "all",
            "proto": normalize_protocol_name(data.get("proto") or "all"),
            "port_mode": str(data.get("port_mode") or "preset").strip().lower() or "preset",
            "port_start": safe_int(data.get("port_start", data.get("port")), 0),
            "port_end": safe_int(data.get("port_end", data.get("port")), 0),
            "status": str(data.get("status") or "stopped").strip().lower() or "stopped",
            "timesleep": safe_float(data.get("timesleep", 0.5), 0.5),
            "progress": safe_float(data.get("progress", 0.0), 0.0),
            "interface": str(data.get("interface") or "").strip(),
            "filter_text": str(data.get("filter_text") or "").strip(),
        }
        if payload["port_mode"] not in {"preset", "single", "range"}:
            payload["port_mode"] = "preset"
        if payload["status"] not in {"active", "stopped", "restarting"}:
            payload["status"] = "stopped"
        with self._lock:
            cursor = self._conn.execute(
                """
                INSERT INTO sessions
                (network, type, proto, port_mode, port_start, port_end, status, timesleep, progress, interface,
                 filter_text, packets_seen, bytes_seen, rules_seen, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 0, ?, ?)
                """,
                (
                    payload["network"],
                    payload["type"],
                    payload["proto"],
                    payload["port_mode"],
                    payload["port_start"],
                    payload["port_end"],
                    payload["status"],
                    payload["timesleep"],
                    payload["progress"],
                    payload["interface"],
                    payload["filter_text"],
                    now,
                    now,
                ),
            )
            self._conn.commit()
            return self.get_session(cursor.lastrowid)

    def update_session(self, session_id: int, data: dict) -> dict | None:
        existing = self.get_session(session_id)
        if not existing:
            return None
        updated = {
            "network": str(data.get("network", existing["network"])).strip() or existing["network"],
            "type": str(data.get("type", existing["type"])).strip() or existing["type"],
            "proto": normalize_protocol_name(data.get("proto", existing["proto"])),
            "port_mode": str(data.get("port_mode", existing["port_mode"])).strip().lower() or existing["port_mode"],
            "port_start": safe_int(data.get("port_start", existing["port_start"]), existing["port_start"]),
            "port_end": safe_int(data.get("port_end", existing["port_end"]), existing["port_end"]),
            "status": str(data.get("status", existing["status"])).strip().lower() or existing["status"],
            "timesleep": safe_float(data.get("timesleep", existing["timesleep"]), existing["timesleep"]),
            "progress": safe_float(data.get("progress", existing["progress"]), existing["progress"]),
            "interface": str(data.get("interface", existing["interface"])).strip(),
            "filter_text": str(data.get("filter_text", existing["filter_text"])).strip(),
        }
        if updated["port_mode"] not in {"preset", "single", "range"}:
            updated["port_mode"] = existing["port_mode"]
        if updated["status"] not in {"active", "stopped", "restarting"}:
            updated["status"] = existing["status"]
        now = utc_now()
        self._execute(
            """
            UPDATE sessions
            SET network = ?, type = ?, proto = ?, port_mode = ?, port_start = ?, port_end = ?,
                status = ?, timesleep = ?, progress = ?, interface = ?, filter_text = ?, updated_at = ?
            WHERE id = ?
            """,
            (
                updated["network"],
                updated["type"],
                updated["proto"],
                updated["port_mode"],
                updated["port_start"],
                updated["port_end"],
                updated["status"],
                updated["timesleep"],
                updated["progress"],
                updated["interface"],
                updated["filter_text"],
                now,
                session_id,
            ),
            commit=True,
        )
        return self.get_session(session_id)

    def delete_session(self, session_id: int) -> bool:
        with self._lock:
            self._conn.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
            self._conn.commit()
        return True

    def set_session_status(self, session_id: int, status: str, *, progress: float | None = None):
        status = str(status or "").strip().lower() or "stopped"
        if status not in {"active", "stopped", "restarting"}:
            status = "stopped"
        updates = ["status = ?", "updated_at = ?"]
        values = [status, utc_now()]
        if progress is not None:
            updates.insert(0, "progress = ?")
            values.insert(0, float(progress))
        values.append(session_id)
        self._execute(
            f"UPDATE sessions SET {', '.join(updates)} WHERE id = ?",
            tuple(values),
            commit=True,
        )
        return self.get_session(session_id)

    def bump_session_counters(self, session_id: int, packet_length: int, rule_count: int):
        session_id = self._ensure_session(session_id)
        now = utc_now()
        with self._lock:
            self._conn.execute(
                """
                UPDATE sessions
                SET packets_seen = packets_seen + 1,
                    bytes_seen = bytes_seen + ?,
                    rules_seen = rules_seen + ?,
                    progress = MIN(100.0, progress + 0.25),
                    updated_at = ?
                WHERE id = ?
                """,
                (int(packet_length), int(rule_count), now, session_id),
            )
            self._conn.commit()

    def get_session(self, session_id: int):
        return self._fetchone("SELECT * FROM sessions WHERE id = ?", (session_id,))

    def _session_filter(self, *, search="", proto="", since=""):
        clauses = []
        params = []
        if since:
            clauses.append("created_at >= ?")
            params.append(str(since))
        if proto:
            clauses.append("LOWER(proto) = ?")
            params.append(normalize_protocol_name(proto))
        if search:
            needle = f"%{str(search).strip().lower()}%"
            clauses.append(
                "("
                "LOWER(network) LIKE ? OR LOWER(type) LIKE ? OR LOWER(proto) LIKE ? "
                "OR LOWER(status) LIKE ? OR LOWER(interface) LIKE ? OR LOWER(filter_text) LIKE ?"
                ")"
            )
            params.extend([needle] * 6)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        return where, params

    def list_sessions(self, *, limit=200, offset=0, search="", proto="", since=""):
        where, params = self._session_filter(search=search, proto=proto, since=since)
        params = list(params)
        params.extend([int(limit), int(offset)])
        return self._fetchall(
            f"SELECT * FROM sessions {where} ORDER BY id DESC LIMIT ? OFFSET ?",
            tuple(params),
        )

    def count_sessions(self, *, search="", proto="", since=""):
        where, params = self._session_filter(search=search, proto=proto, since=since)
        row = self._fetchone(f"SELECT COUNT(*) AS count FROM sessions {where}", tuple(params))
        return int((row or {}).get("count") or 0)

    def protocol_snapshot(self, *, proto="", mode="", interface="", search="", since="", limit=250):
        """Everything the Protocols view needs for one protocol, in one read.

        The view previously issued five REST calls per refresh (/protocols/,
        /api/charts/analytics, /banners/, /ports/, /tags/) and recomputed its
        charts in the browser from a truncated page of rows - so the numbers
        described the first 500 rows, not the slice. Here the counters and
        facets are aggregated with GROUP BY over the whole filtered set, and
        the facets themselves are chosen per protocol by protocol_facets, so
        ARP reports who-has/is-at instead of "open vs filtered".
        """
        proto_name = normalize_protocol_name(proto) if proto else ""
        where, params = self._packet_filter(
            proto=proto_name, search=search, interface=interface, mode=mode, since=since
        )
        params = list(params)

        totals = self._fetchone(
            f"""
            SELECT
                COUNT(*) AS frames,
                COALESCE(SUM(length), 0) AS bytes_total,
                COALESCE(AVG(length), 0) AS bytes_avg,
                COUNT(DISTINCT src_ip) AS unique_sources,
                COUNT(DISTINCT dst_ip) AS unique_destinations,
                COUNT(DISTINCT flow_key) AS unique_flows,
                MIN(created_at) AS first_seen,
                MAX(created_at) AS last_seen
            FROM packets {where}
            """,
            tuple(params),
        ) or {}

        facets = []
        for column, title, subtitle in resolve_facets(proto_name):
            expression = facet_expression(column)
            present = facet_present_predicate(column)
            if not expression or not present:
                continue
            facet_where = f"{where} AND {present}" if where else f"WHERE {present}"
            missing_row = self._fetchone(
                f"SELECT COUNT(*) AS missing FROM packets {where}"
                f"{' AND' if where else ' WHERE'} NOT ({present})",
                tuple(params),
            ) or {}
            rows = self._fetchall(
                f"""
                SELECT {expression} AS value, COUNT(*) AS count
                FROM packets {facet_where}
                GROUP BY {expression}
                ORDER BY count DESC, value ASC
                LIMIT 8
                """,
                tuple(params),
            )
            facets.append(
                {
                    "key": column,
                    "title": title,
                    "subtitle": subtitle,
                    # Frames in the filtered slice that carry no value for this
                    # facet. Excluded from `series` so they cannot flatten the
                    # chart, reported here so they are not silently dropped.
                    "missing": safe_int(missing_row.get("missing"), 0),
                    "series": [
                        {
                            "label": label_value(column, row.get("value")),
                            "raw": row.get("value"),
                            "count": safe_int(row.get("count"), 0),
                        }
                        for row in rows
                    ],
                }
            )

        timeline = self._fetchall(
            f"""
            SELECT substr(created_at, 1, 13) AS bucket, COUNT(*) AS count
            FROM packets {where}
            GROUP BY bucket
            ORDER BY bucket ASC
            LIMIT 168
            """,
            tuple(params),
        )

        return {
            "protocol": proto_name or "all",
            "totals": {
                "frames": safe_int(totals.get("frames"), 0),
                "bytes_total": safe_int(totals.get("bytes_total"), 0),
                "bytes_avg": round(safe_float(totals.get("bytes_avg"), 0.0), 1),
                "unique_sources": safe_int(totals.get("unique_sources"), 0),
                "unique_destinations": safe_int(totals.get("unique_destinations"), 0),
                "unique_flows": safe_int(totals.get("unique_flows"), 0),
                "first_seen": totals.get("first_seen") or "",
                "last_seen": totals.get("last_seen") or "",
            },
            "facets": facets,
            "timeline": [
                {"label": str(row.get("bucket") or ""), "count": safe_int(row.get("count"), 0)}
                for row in timeline
            ],
            # The raw frame is a BLOB of every captured byte; it is what the
            # Investigate view fetches on demand for one packet, never what a
            # 250-row listing should carry over the socket.
            # Which columns this protocol is worth showing. Sent with the slice
            # because the client cannot know it: it is the same per-protocol
            # decision that picks the facets, and hardcoding one list in the
            # view is what made an ARP listing spend four columns on ports and
            # flags that are always empty.
            "columns": [{"key": key, "label": label} for key, label in resolve_row_columns(proto_name)],
            "packets": [
                _flatten_packet_details(row)
                for row in self.list_packets(
                    proto=proto_name, mode=mode, interface=interface, search=search, since=since, limit=int(limit)
                )
            ],
            # Banners and tags travel with the slice rather than as their own
            # requests: the view needs all three to render one screen, and
            # fetching them separately is what made a single refresh cost five
            # round trips.
            "banners": self.list_payloads(
                proto=proto_name, mode=mode, interface=interface, search=search, since=since, limit=int(limit)
            ),
            # Scoped through the packet each tag belongs to. list_tags() only
            # knows since/proto/search - the tags table has no interface or
            # direction column - so calling it here would show tags harvested
            # on another interface (or in the other runtime mode) inside a
            # slice every other key in this payload has filtered.
            "tags": self._fetchall(
                f"""
                SELECT tags.* FROM tags
                WHERE tags.packet_id IN (SELECT id FROM packets {where})
                ORDER BY tags.id DESC
                LIMIT ?
                """,
                tuple(params + [int(limit)]),
            ),
            # The protocol rail needs every observed protocol and how much
            # traffic each holds. Shipping it here is what lets the view drop
            # its separate /protocols/ and /api/charts/analytics calls.
            "catalog": self.protocol_catalog(mode=mode, interface=interface, since=since),
            "generated_at": utc_now(),
        }

    def protocol_catalog(self, *, mode="", interface="", since=""):
        """Every protocol present in the slice, with its frame count."""
        where, params = self._packet_filter(mode=mode, interface=interface, since=since)
        rows = self._fetchall(
            f"""
            SELECT proto, COUNT(*) AS count
            FROM packets {where}
            GROUP BY proto
            ORDER BY count DESC
            """,
            tuple(params),
        )
        observed = {
            normalize_protocol_name(row.get("proto")): safe_int(row.get("count"), 0)
            for row in rows
            if row.get("proto")
        }
        # Protocols the parser can emit but that have not been seen yet are
        # still listed, at zero, so the rail is a stable map of what this
        # build supports rather than a list that appears one card at a time.
        return [
            {"protocol": proto, "count": observed.get(proto, 0)}
            for proto in sorted(set(KNOWN_PROTOCOLS) | set(observed))
        ]

    def list_protocols(self):
        rows = self._fetchall("SELECT DISTINCT proto FROM packets ORDER BY proto ASC")
        protocols = [normalize_protocol_name(row["proto"]) for row in rows if row.get("proto")]
        if not protocols:
            protocols = list(KNOWN_PROTOCOLS)
        return sorted(set(protocols))

    def _packet_filter(self, *, proto="", session_id=0, search="", interface="", mode="", since=""):
        """Shared WHERE builder for list_packets()/count_packets() so the
        "how many are there in total" answer can never drift from the page
        of rows that was actually returned."""
        clauses = []
        params = []
        if since:
            clauses.append("created_at >= ?")
            params.append(str(since))
        if proto:
            clauses.append("LOWER(proto) = ?")
            params.append(normalize_protocol_name(proto))
        if session_id:
            clauses.append("session_id = ?")
            params.append(int(session_id))
        interface_value = str(interface or "").strip().lower()
        if interface_value:
            if interface_value.endswith("*"):
                clauses.append("LOWER(interface) LIKE ?")
                params.append(f"{interface_value[:-1]}%")
            else:
                clauses.append("LOWER(interface) = ?")
                params.append(interface_value)
        mode_value = str(mode or "").strip().lower()
        if mode_value == "honeypot":
            clauses.append(
                "("
                "LOWER(interface) = 'honeypot' OR LOWER(interface) LIKE 'honeypot:%' OR "
                "LOWER(interface) = 'service' OR LOWER(interface) LIKE 'service:%'"
                ")"
            )
        elif mode_value == "sniffer":
            clauses.append(
                "("
                "LOWER(interface) != 'honeypot' AND LOWER(interface) NOT LIKE 'honeypot:%' AND "
                "LOWER(interface) != 'service' AND LOWER(interface) NOT LIKE 'service:%'"
                ")"
            )
        if search:
            needle = f"%{str(search).strip().lower()}%"
            clauses.append(
                "("
                "LOWER(src_ip) LIKE ? OR LOWER(dst_ip) LIKE ? OR LOWER(summary) LIKE ? OR "
                "LOWER(payload_text) LIKE ? OR LOWER(banner_text) LIKE ? OR LOWER(tags_json) LIKE ? OR "
                "LOWER(interface) LIKE ? OR LOWER(direction) LIKE ? OR CAST(src_port AS TEXT) LIKE ? OR CAST(dst_port AS TEXT) LIKE ?"
                ")"
            )
            params.extend([needle] * 10)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        return where, params

    def list_packets(self, *, proto="", session_id=0, search="", interface="", mode="", limit=250, offset=0, since="", include_raw=False):
        where, params = self._packet_filter(
            proto=proto, session_id=session_id, search=search, interface=interface, mode=mode, since=since
        )
        params = list(params)
        params.extend([int(limit), int(offset)])
        columns = "*" if include_raw else PACKET_LIST_SELECT
        return self._fetchall(
            f"SELECT {columns} FROM packets {where} ORDER BY id DESC LIMIT ? OFFSET ?",
            tuple(params),
        )

    def list_ai_packets(self):
        # Convert the bounded BLOB in SQL: the normal row serializer limits
        # binary fields to a 256-byte preview and would lose image data.
        return self._fetchall("""
            SELECT id, proto, src_ip, dst_ip, src_port, dst_port, created_at,
                   length, payload_hex, details_json, tags_json, rule_hits_json,
                   hex(substr(raw_packet, 1, 4096)) AS frame_hex,
                   length(raw_packet) AS frame_length
            FROM packets ORDER BY id DESC LIMIT 200
        """)

    def count_packets(self, *, proto="", session_id=0, search="", interface="", mode="", since=""):
        where, params = self._packet_filter(
            proto=proto, session_id=session_id, search=search, interface=interface, mode=mode, since=since
        )
        row = self._fetchone(f"SELECT COUNT(*) AS count FROM packets {where}", tuple(params))
        return int((row or {}).get("count") or 0)

    def list_packets_by_monitor(self, monitor_id: str, *, search="", limit=200, offset=0, since=""):
        clauses = ["tags.key = 'monitor_id'", "tags.value = ?"]
        params = [str(monitor_id)]
        if since:
            clauses.append("packets.created_at >= ?")
            params.append(str(since))
        if search:
            needle = f"%{str(search).strip().lower()}%"
            clauses.append(
                "("
                "LOWER(packets.src_ip) LIKE ? OR LOWER(packets.dst_ip) LIKE ? OR LOWER(packets.summary) LIKE ? OR "
                "LOWER(packets.payload_text) LIKE ? OR LOWER(packets.banner_text) LIKE ? OR "
                "CAST(packets.src_port AS TEXT) LIKE ? OR CAST(packets.dst_port AS TEXT) LIKE ?"
                ")"
            )
            params.extend([needle] * 7)
        where = f"WHERE {' AND '.join(clauses)}"
        params.extend([int(limit), int(offset)])
        rows = self._fetchall(
            f"""
            SELECT DISTINCT packets.*
            FROM packets
            JOIN tags ON tags.packet_id = packets.id
            {where}
            ORDER BY packets.id DESC
            LIMIT ? OFFSET ?
            """,
            tuple(params),
        )
        monitor = self.get_monitor(monitor_id)
        if monitor:
            for row in rows:
                row["matched_value"] = describe_match(monitor, row)
        else:
            for row in rows:
                row["matched_value"] = ""
        return rows

    def count_packets_by_monitor(self, monitor_id: str, *, since=""):
        clauses = ["tags.key = 'monitor_id'", "tags.value = ?"]
        params = [str(monitor_id)]
        if since:
            clauses.append("packets.created_at >= ?")
            params.append(str(since))
        row = self._fetchone(
            f"""
            SELECT COUNT(DISTINCT packets.id) AS count
            FROM packets
            JOIN tags ON tags.packet_id = packets.id
            WHERE {' AND '.join(clauses)}
            """,
            tuple(params),
        )
        return int((row or {}).get("count") or 0)

    def list_recent_alerts(self, *, limit=500, offset=0, since="", severity=""):
        """Lean feed of recent monitor hits for UI surfaces - like the Radar
        host graph badges - that need to know *which hosts got flagged, how
        badly, and why*, but not the full packet row
        (raw_packet/payload_text/tags_json and the rest) that list_packets()
        would otherwise ship for every one of them.

        Carries the 5-tuple, interface/direction and the hit's own
        `monitor_id`/`detail` so an alert is triageable and pivotable on its
        own: `detail` ("127.0.0.1 touched 15 distinct ports within 10s") was
        already being persisted by the stateful detectors and simply never
        served, and without `monitor_id` there was no way to get from an
        alert to /api/monitors/packets/, which keys on the id rather than
        the display name the alert carries."""
        where, params = self._alert_filter(since=since, severity=severity)
        params = list(params)
        params.extend([int(limit), int(offset)])
        # _build_packet_tags() writes one 'monitor' row immediately followed
        # by that same hit's 'monitor_id'/'detail' rows, so a hit's extra
        # tags are the ones sitting between this 'monitor' tag and the next
        # one. Correlating on that window (rather than a plain LEFT JOIN on
        # packet_id) keeps a packet with several hits from fanning one alert
        # out into N x M rows.
        next_monitor = (
            "COALESCE((SELECT MIN(nxt.id) FROM tags AS nxt "
            "WHERE nxt.packet_id = tags.packet_id AND nxt.key = 'monitor' AND nxt.id > tags.id), 9223372036854775807)"
        )
        rows = self._fetchall(
            f"""
            SELECT packets.id AS packet_id, packets.src_ip AS src_ip, packets.dst_ip AS dst_ip,
                   packets.src_port AS src_port, packets.dst_port AS dst_port, packets.proto AS proto,
                   packets.interface AS interface, packets.direction AS direction,
                   packets.domain AS domain, packets.http_host AS http_host,
                   tags.value AS monitor, tags.severity AS severity, packets.created_at AS created_at,
                   (SELECT sibling.value FROM tags AS sibling
                     WHERE sibling.packet_id = tags.packet_id AND sibling.key = 'monitor_id'
                       AND sibling.id > tags.id AND sibling.id < {next_monitor}
                     ORDER BY sibling.id ASC LIMIT 1) AS monitor_id,
                   (SELECT sibling.value FROM tags AS sibling
                     WHERE sibling.packet_id = tags.packet_id AND sibling.key = 'detail'
                       AND sibling.id > tags.id AND sibling.id < {next_monitor}
                     ORDER BY sibling.id ASC LIMIT 1) AS detail
            FROM tags
            JOIN packets ON packets.id = tags.packet_id
            {where}
            ORDER BY packets.id DESC
            LIMIT ? OFFSET ?
            """,
            tuple(params),
        )
        for row in rows:
            row["monitor_id"] = str(row.get("monitor_id") or "")
            row["detail"] = str(row.get("detail") or "")
        return rows

    def _alert_filter(self, *, since="", severity=""):
        clauses = ["tags.key = 'monitor'", "tags.severity != ''"]
        params = []
        if since:
            clauses.append("packets.created_at >= ?")
            params.append(str(since))
        wanted = [item.strip().lower() for item in str(severity or "").split(",") if item.strip()]
        if wanted:
            clauses.append(f"LOWER(tags.severity) IN ({','.join('?' for _ in wanted)})")
            params.extend(wanted)
        return f"WHERE {' AND '.join(clauses)}", params

    def count_recent_alerts(self, *, since="", severity=""):
        where, params = self._alert_filter(since=since, severity=severity)
        row = self._fetchone(
            f"""
            SELECT COUNT(*) AS count
            FROM tags
            JOIN packets ON packets.id = tags.packet_id
            {where}
            """,
            tuple(params),
        )
        return int((row or {}).get("count") or 0)

    def list_flows(self, *, proto="", search="", limit=250, offset=0):
        clauses = []
        params = []
        if proto:
            clauses.append("LOWER(proto) = ?")
            params.append(normalize_protocol_name(proto))
        if search:
            needle = f"%{str(search).strip().lower()}%"
            clauses.append(
                "("
                "LOWER(src_ip) LIKE ? OR LOWER(dst_ip) LIKE ? OR LOWER(flow_key) LIKE ? OR "
                "LOWER(banner_text) LIKE ? OR LOWER(tags_json) LIKE ?"
                ")"
            )
            params.extend([needle] * 5)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.extend([int(limit), int(offset)])
        return self._fetchall(
            f"SELECT * FROM flows {where} ORDER BY packet_count DESC, id DESC LIMIT ? OFFSET ?",
            tuple(params),
        )

    def _payload_filter(self, *, search="", proto="", interface="", mode="", since=""):
        clauses = []
        params = []
        if since:
            clauses.append("payloads.created_at >= ?")
            params.append(str(since))
        if proto:
            clauses.append("LOWER(payloads.proto) = ?")
            params.append(normalize_protocol_name(proto))
        interface_value = str(interface or "").strip().lower()
        if interface_value:
            if interface_value.endswith("*"):
                clauses.append("LOWER(COALESCE(p.interface, '')) LIKE ?")
                params.append(f"{interface_value[:-1]}%")
            else:
                clauses.append("LOWER(COALESCE(p.interface, '')) = ?")
                params.append(interface_value)
        mode_value = str(mode or "").strip().lower()
        if mode_value == "honeypot":
            clauses.append(
                "("
                "LOWER(COALESCE(p.interface, '')) = 'honeypot' OR LOWER(COALESCE(p.interface, '')) LIKE 'honeypot:%' OR "
                "LOWER(COALESCE(p.interface, '')) = 'service' OR LOWER(COALESCE(p.interface, '')) LIKE 'service:%'"
                ")"
            )
        elif mode_value == "sniffer":
            clauses.append(
                "("
                "LOWER(COALESCE(p.interface, '')) != 'honeypot' AND LOWER(COALESCE(p.interface, '')) NOT LIKE 'honeypot:%' AND "
                "LOWER(COALESCE(p.interface, '')) != 'service' AND LOWER(COALESCE(p.interface, '')) NOT LIKE 'service:%'"
                ")"
            )
        if search:
            needle = f"%{str(search).strip().lower()}%"
            clauses.append(
                "("
                "LOWER(payloads.response_plain) LIKE ? OR LOWER(payloads.ip) LIKE ? OR LOWER(payloads.proto) LIKE ? OR "
                "LOWER(COALESCE(p.interface, '')) LIKE ? OR LOWER(COALESCE(p.src_ip, '')) LIKE ? OR LOWER(COALESCE(p.dst_ip, '')) LIKE ? OR "
                "CAST(payloads.port AS TEXT) LIKE ? OR CAST(COALESCE(p.src_port, 0) AS TEXT) LIKE ? OR CAST(COALESCE(p.dst_port, 0) AS TEXT) LIKE ?"
                ")"
            )
            params.extend([needle] * 9)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        return where, params

    def _payload_join(self) -> str:
        return "FROM payloads LEFT JOIN packets AS p ON p.id = payloads.packet_id"

    def count_payloads(self, *, search="", proto="", interface="", mode="", since=""):
        where, params = self._payload_filter(search=search, proto=proto, interface=interface, mode=mode, since=since)
        row = self._fetchone(f"SELECT COUNT(*) AS count {self._payload_join()} {where}", tuple(params))
        return int((row or {}).get("count") or 0)

    def list_payloads(self, *, search="", proto="", interface="", mode="", limit=250, offset=0, since=""):
        where, params = self._payload_filter(search=search, proto=proto, interface=interface, mode=mode, since=since)
        params = list(params)
        params.extend([int(limit), int(offset)])
        return self._fetchall(
            f"""
            SELECT
                payloads.*,
                p.session_id AS session_id,
                p.interface AS interface,
                p.direction AS direction,
                p.src_ip AS src_ip,
                p.dst_ip AS dst_ip,
                p.src_port AS src_port,
                p.dst_port AS dst_port,
                p.summary AS summary,
                p.tags_json AS tags_json
            FROM payloads
            LEFT JOIN packets AS p
                ON p.id = payloads.packet_id
            {where}
            ORDER BY payloads.id DESC
            LIMIT ? OFFSET ?
            """,
            tuple(params),
        )

    def _tag_filter(self, *, proto="", search="", since=""):
        clauses = []
        params = []
        if since:
            clauses.append("created_at >= ?")
            params.append(str(since))
        if proto:
            clauses.append("LOWER(proto) = ?")
            params.append(normalize_protocol_name(proto))
        if search:
            needle = f"%{str(search).strip().lower()}%"
            clauses.append(
                "("
                "LOWER(ip) LIKE ? OR LOWER(key) LIKE ? OR LOWER(value) LIKE ? OR LOWER(flow_key) LIKE ?"
                ")"
            )
            params.extend([needle] * 4)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        return where, params

    def list_tags(self, *, proto="", search="", limit=400, offset=0, since=""):
        where, params = self._tag_filter(proto=proto, search=search, since=since)
        params = list(params)
        params.extend([int(limit), int(offset)])
        return self._fetchall(
            f"SELECT * FROM tags {where} ORDER BY id DESC LIMIT ? OFFSET ?",
            tuple(params),
        )

    def count_tags(self, *, proto="", search="", since=""):
        where, params = self._tag_filter(proto=proto, search=search, since=since)
        row = self._fetchone(f"SELECT COUNT(*) AS count FROM tags {where}", tuple(params))
        return int((row or {}).get("count") or 0)

    def record_domain(self, *, name: str, source: str = "", ip: str = "", port: int = 0, proto: str = ""):
        name = str(name or "").strip().lower()
        if not name:
            return None
        now = utc_now()
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO domains (name, source, ip, port, proto, hit_count, first_seen, last_seen, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                  source = excluded.source,
                  ip = excluded.ip,
                  port = excluded.port,
                  proto = excluded.proto,
                  hit_count = hit_count + 1,
                  last_seen = excluded.last_seen,
                  updated_at = excluded.updated_at
                """,
                (name, str(source or ""), str(ip or ""), safe_int(port, 0), normalize_protocol_name(proto), now, now, now, now),
            )
            self._conn.commit()
        return self._fetchone("SELECT * FROM domains WHERE name = ?", (name,))

    def _domain_filter(self, *, search="", since=""):
        clauses = []
        params = []
        if since:
            clauses.append("last_seen >= ?")
            params.append(str(since))
        if search:
            needle = f"%{str(search).strip().lower()}%"
            clauses.append("(LOWER(name) LIKE ? OR LOWER(source) LIKE ? OR LOWER(ip) LIKE ?)")
            params.extend([needle] * 3)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        return where, params

    def list_domains(self, *, search="", limit=200, offset=0, since=""):
        where, params = self._domain_filter(search=search, since=since)
        params = list(params)
        params.extend([int(limit), int(offset)])
        return self._fetchall(
            f"SELECT * FROM domains {where} ORDER BY last_seen DESC LIMIT ? OFFSET ?",
            tuple(params),
        )

    def count_domains(self, *, search="", since=""):
        where, params = self._domain_filter(search=search, since=since)
        row = self._fetchone(f"SELECT COUNT(*) AS count FROM domains {where}", tuple(params))
        return int((row or {}).get("count") or 0)

    def record_path(self, *, path: str, method: str = "GET", host: str = "", ip: str = "", port: int = 0):
        path = str(path or "").strip()
        if not path:
            return None
        method = str(method or "GET").strip().upper() or "GET"
        host = str(host or "").strip().lower()
        now = utc_now()
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO paths (path, method, host, ip, port, hit_count, first_seen, last_seen, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
                ON CONFLICT(method, path, host) DO UPDATE SET
                  ip = excluded.ip,
                  port = excluded.port,
                  hit_count = hit_count + 1,
                  last_seen = excluded.last_seen,
                  updated_at = excluded.updated_at
                """,
                (path, method, host, str(ip or ""), safe_int(port, 0), now, now, now, now),
            )
            self._conn.commit()
        return self._fetchone(
            "SELECT * FROM paths WHERE method = ? AND path = ? AND host = ?",
            (method, path, host),
        )

    def _path_filter(self, *, search="", since=""):
        clauses = []
        params = []
        if since:
            clauses.append("last_seen >= ?")
            params.append(str(since))
        if search:
            needle = f"%{str(search).strip().lower()}%"
            clauses.append("(LOWER(path) LIKE ? OR LOWER(host) LIKE ? OR LOWER(method) LIKE ? OR LOWER(ip) LIKE ?)")
            params.extend([needle] * 4)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        return where, params

    def list_paths(self, *, search="", limit=200, offset=0, since=""):
        where, params = self._path_filter(search=search, since=since)
        params = list(params)
        params.extend([int(limit), int(offset)])
        return self._fetchall(
            f"SELECT * FROM paths {where} ORDER BY last_seen DESC LIMIT ? OFFSET ?",
            tuple(params),
        )

    def count_paths(self, *, search="", since=""):
        where, params = self._path_filter(search=search, since=since)
        row = self._fetchone(f"SELECT COUNT(*) AS count FROM paths {where}", tuple(params))
        return int((row or {}).get("count") or 0)

    def _ip_catalog_source(self, *, search="", since=""):
        clauses = []
        params = []
        if since:
            clauses.append("created_at >= ?")
            params.append(str(since))
        if search:
            clauses.append("LOWER(ip) LIKE ?")
            params.append(f"%{str(search).strip().lower()}%")
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        source = """
            FROM (
              SELECT src_ip AS ip, created_at FROM packets WHERE src_ip != ''
              UNION ALL
              SELECT dst_ip AS ip, created_at FROM packets WHERE dst_ip != ''
            )
        """
        return source, where, params

    def count_ip_catalog(self, *, search="", since="", scope=""):
        wanted = normalize_ip_scope_filter(scope)
        if wanted:
            return len(self._grouped_ip_catalog(search=search, since=since, scope=wanted))
        source, where, params = self._ip_catalog_source(search=search, since=since)
        row = self._fetchone(
            f"SELECT COUNT(*) AS count FROM (SELECT ip {source} {where} GROUP BY ip)",
            tuple(params),
        )
        return int((row or {}).get("count") or 0)

    def ip_catalog_scope_counts(self, *, search="", since=""):
        """Distinct-IP and hit totals per address scope.

        Feeds both the filter chips (so an operator sees how many addresses
        each filter would show before clicking) and the scope chart, which
        previously only knew "private vs public" and therefore filed every
        loopback address under private.
        """
        # Every known scope is present, at zero when unseen: this is also the
        # only place the scope vocabulary reaches a client, so omitting the
        # empty ones would leave the UI unable to offer a filter for a scope
        # that simply has no traffic yet.
        counts: dict[str, dict[str, int]] = {
            scope: {"addresses": 0, "hits": 0} for scope in IP_SCOPES
        }
        for row in self._grouped_ip_catalog(search=search, since=since, scope=()):
            bucket = counts.setdefault(row["scope"], {"addresses": 0, "hits": 0})
            bucket["addresses"] += 1
            bucket["hits"] += safe_int(row.get("hit_count"), 0)
        return counts

    def _grouped_ip_catalog(self, *, search="", since="", scope=()):
        """Every distinct IP in the slice, classified and optionally filtered.

        Scope is decided by _ip_scope(), the same helper the SOC snapshot and
        /api/intel/ip use - deliberately not re-expressed as SQL range
        predicates, which would be a second copy of the RFC1918/ULA/link-local
        rules free to drift from the first. The grouped scan this walks is
        the one count_ip_catalog() already runs on every request, so filtering
        here costs no extra query.
        """
        source, where, params = self._ip_catalog_source(search=search, since=since)
        rows = self._fetchall(
            f"""
            SELECT
              ip,
              COUNT(*) AS hit_count,
              MIN(created_at) AS first_seen,
              MAX(created_at) AS last_seen
            {source}
            {where}
            GROUP BY ip
            ORDER BY last_seen DESC
            LIMIT ?
            """,
            tuple(list(params) + [IP_CATALOG_SCAN_LIMIT]),
        )
        classified = []
        for row in rows:
            ip = str(row.get("ip") or "")
            row["scope"] = _ip_scope(ip)
            try:
                row["private"] = ipaddress.ip_address(ip).is_private
            except Exception:
                row["private"] = False
            if scope and row["scope"] not in scope:
                continue
            classified.append(row)
        return classified

    def list_ip_catalog(self, *, search="", limit=200, offset=0, since="", scope=""):
        wanted = normalize_ip_scope_filter(scope)
        if wanted:
            # Scope is not expressible in SQLite, so the page has to be cut
            # after classification - otherwise LIMIT would count rows the
            # filter then removes and the last page would come back short.
            rows = self._grouped_ip_catalog(search=search, since=since, scope=wanted)
            start = max(0, int(offset))
            return rows[start : start + int(limit)]
        source, where, params = self._ip_catalog_source(search=search, since=since)
        params = list(params)
        params.extend([int(limit), int(offset)])
        rows = self._fetchall(
            f"""
            SELECT
              ip,
              COUNT(*) AS hit_count,
              MIN(created_at) AS first_seen,
              MAX(created_at) AS last_seen
            {source}
            {where}
            GROUP BY ip
            ORDER BY last_seen DESC
            LIMIT ? OFFSET ?
            """,
            tuple(params),
        )
        for row in rows:
            ip = str(row.get("ip") or "")
            row["scope"] = _ip_scope(ip)
            try:
                row["private"] = ipaddress.ip_address(ip).is_private
            except Exception:
                row["private"] = False
        return rows

    def list_rulesets(self):
        rows = self._fetchall("SELECT * FROM rulesets ORDER BY priority ASC, name ASC")
        for row in rows:
            row["match"] = _coerce_json(row.get("match_json"), {}) or {}
            row["action"] = _coerce_json(row.get("action_json"), {}) or {}
            row["enabled"] = bool(row.get("enabled"))
        return rows

    def get_ruleset(self, rule_id: str):
        row = self._fetchone("SELECT * FROM rulesets WHERE id = ?", (str(rule_id),))
        if not row:
            return None
        row["match"] = _coerce_json(row.get("match_json"), {}) or {}
        row["action"] = _coerce_json(row.get("action_json"), {}) or {}
        row["enabled"] = bool(row.get("enabled"))
        return row

    def save_ruleset(self, data: dict):
        normalized = normalize_ruleset(data, allow_source=True)
        rule_id = normalized["id"]
        existing = self.get_ruleset(rule_id)
        if existing and existing.get("source") == "builtin":
            raise ValueError("Builtin rulesets are read-only")
        now = utc_now()
        self._execute(
            """
            INSERT INTO rulesets (id, name, description, enabled, priority, source, match_json, action_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
              name = excluded.name,
              description = excluded.description,
              enabled = excluded.enabled,
              priority = excluded.priority,
              source = excluded.source,
              match_json = excluded.match_json,
              action_json = excluded.action_json,
              updated_at = excluded.updated_at
            """,
            (
                rule_id,
                normalized["name"],
                normalized.get("description", ""),
                1 if normalized.get("enabled", True) else 0,
                int(normalized.get("priority", 100)),
                str(normalized.get("source") or "custom"),
                json_dumps(normalized.get("match") or {}),
                json_dumps(normalized.get("action") or {}),
                now,
                now,
            ),
            commit=True,
        )
        return self.get_ruleset(rule_id)

    def delete_ruleset(self, rule_id: str):
        existing = self.get_ruleset(rule_id)
        if existing and existing.get("source") == "builtin":
            raise ValueError("Builtin rulesets are read-only")
        self._execute("DELETE FROM rulesets WHERE id = ?", (str(rule_id),), commit=True)
        return True

    def list_monitors(self):
        rows = self._fetchall("SELECT * FROM monitors ORDER BY priority ASC, name ASC")
        for row in rows:
            row["match"] = _coerce_json(row.get("match_json"), {}) or {}
            row["action"] = _coerce_json(row.get("action_json"), {}) or {}
            row["enabled"] = bool(row.get("enabled"))
        return rows

    def monitor_match_counts(self) -> dict:
        """Matched-packet count per monitor id, in one grouped query - not
        folded into list_monitors() itself since that's also polled every
        MONITOR_CACHE_TTL_SECONDS by the live capture path (Sniffer), which
        has no use for these counts and shouldn't pay for them."""
        rows = self._fetchall(
            """
            SELECT tags.value AS monitor_id, COUNT(DISTINCT tags.packet_id) AS count
            FROM tags
            WHERE tags.key = 'monitor_id'
            GROUP BY tags.value
            """
        )
        return {str(row["monitor_id"]): int(row["count"]) for row in rows}

    def get_monitor(self, monitor_id: str):
        row = self._fetchone("SELECT * FROM monitors WHERE id = ?", (str(monitor_id),))
        if not row:
            return None
        row["match"] = _coerce_json(row.get("match_json"), {}) or {}
        row["action"] = _coerce_json(row.get("action_json"), {}) or {}
        row["enabled"] = bool(row.get("enabled"))
        return row

    def save_monitor(self, data: dict):
        normalized = normalize_monitor(data, allow_source=True)
        monitor_id = normalized["id"]
        existing = self.get_monitor(monitor_id)
        if existing and existing.get("source") == "builtin":
            raise ValueError("Builtin monitors are read-only")
        if existing and existing.get("source") == "blacklist":
            raise ValueError("Blacklist-derived monitors can only be edited from the Blacklist settings tab")
        now = utc_now()
        self._execute(
            """
            INSERT INTO monitors (id, name, description, enabled, priority, source, mode, match_json, action_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
              name = excluded.name,
              description = excluded.description,
              enabled = excluded.enabled,
              priority = excluded.priority,
              source = excluded.source,
              mode = excluded.mode,
              match_json = excluded.match_json,
              action_json = excluded.action_json,
              updated_at = excluded.updated_at
            """,
            (
                monitor_id,
                normalized["name"],
                normalized.get("description", ""),
                1 if normalized.get("enabled", True) else 0,
                int(normalized.get("priority", 100)),
                str(normalized.get("source") or "custom"),
                str(normalized.get("mode") or "rule"),
                json_dumps(normalized.get("match") or {}),
                json_dumps(normalized.get("action") or {}),
                now,
                now,
            ),
            commit=True,
        )
        return self.get_monitor(monitor_id)

    def delete_monitor(self, monitor_id: str):
        existing = self.get_monitor(monitor_id)
        if existing and existing.get("source") == "builtin":
            raise ValueError("Builtin monitors are read-only")
        if existing and existing.get("source") == "blacklist":
            raise ValueError("Blacklist-derived monitors can only be removed from the Blacklist settings tab")
        self._execute("DELETE FROM monitors WHERE id = ?", (str(monitor_id),), commit=True)
        return True

    def set_monitor_enabled(self, monitor_id: str, enabled: bool):
        """Flip a monitor's `enabled` flag only - unlike `save_monitor`,
        this is allowed for builtin monitors too. Builtins stay read-only
        for their definition (name/match/action can't be edited, and they
        can't be deleted), but toggling one off is just "stop applying this
        rule", not a change to what the rule does.

        Blacklist-derived monitors are the one exception: toggling them
        here (bypassing set_blacklist_entry_enabled) would desync the
        monitors table from blacklist_entries.enabled, so the Blacklist tab
        would keep showing an entry as "on" after its monitor was actually
        switched off elsewhere. Route through the Blacklist tab instead,
        same as save_monitor/delete_monitor already do for this source.
        """
        existing = self.get_monitor(monitor_id)
        if not existing:
            raise ValueError(f"Unknown monitor id: {monitor_id}")
        if existing.get("source") == "blacklist":
            raise ValueError("Blacklist-derived monitors can only be toggled from the Blacklist settings tab")
        now = utc_now()
        self._execute(
            "UPDATE monitors SET enabled = ?, updated_at = ? WHERE id = ?",
            (1 if enabled else 0, now, str(monitor_id)),
            commit=True,
        )
        return self.get_monitor(monitor_id)

    # --- Blacklist -----------------------------------------------------
    #
    # A blacklist entry (an IP/domain/path/port/protocol an operator wants flagged
    # unconditionally) is stored in its own table so the dedicated
    # Blacklist settings UI can list/manage them without wading through the
    # full monitors catalog - but detection itself is never duplicated:
    # every enabled entry is mirrored 1:1 into the `monitors` table (same
    # id, source='blacklist') so it flows through the exact same
    # evaluate_packet/RuleAlertThrottle/notification pipeline every other
    # monitor already uses, for free. Deleting/disabling the entry
    # deletes/disables its mirrored monitor row too, in the same
    # transaction-adjacent call, so the two never drift out of sync.
    #
    # "Exact" match is implemented as a word-boundary-anchored regex
    # (`\bre.escape(value)\b`), not a bare payload_contains substring -
    # build_packet_text joins fields like `src_ip`/`dst_ip` with no
    # delimiter guarantee beyond a space, so a plain substring match on an
    # IP would false-positive against any IP that merely *contains* the
    # blacklisted one as a run of digits (e.g. blacklisting "1.2.3.4"
    # would also match "21.2.3.4" and "1.2.3.45" via naive substring
    # matching). The word-boundary regex form matches the literal value
    # only when it isn't glued to more word characters on either side,
    # which is what an operator typing an exact IP/domain/path actually
    # means. Port/protocol entries match their decoded packet fields
    # directly. "Regex" mode uses the operator's own pattern verbatim.

    BLACKLIST_CATEGORIES = ("ip", "domain", "path", "port", "protocol")

    def _blacklist_monitor_id(self, entry_id: str) -> str:
        return str(entry_id)

    def _normalize_list_value(self, category: str, value: str, *, exact: bool = True) -> str:
        category = str(category or "").strip().lower()
        value = str(value or "").strip()
        if not value:
            raise ValueError("value is required")
        if category == "port" and exact:
            port = safe_int(value, 0)
            if port < 1 or port > 65535 or str(port) != value:
                raise ValueError("port must be an integer between 1 and 65535")
            return str(port)
        if category == "protocol" and exact:
            normalized = normalize_protocol_name(value)
            return normalized
        return value

    def _sync_blacklist_monitor(self, entry: dict):
        category = str(entry.get("category") or "")
        value = str(entry.get("value") or "")
        is_regex = str(entry.get("match_type")) == "regex"
        if category == "ip":
            # rulesets.build_packet_text deliberately excludes src_ip/dst_ip
            # (see its own docstring) so ordinary payload/content criteria
            # never fire on routing metadata - so an IP blacklist entry
            # can't ride on payload_contains/payload_regex at all. `ips`/
            # `ip_regex` check packet["src_ip"]/packet["dst_ip"] directly
            # instead (see rulesets.rule_matches_packet). "Exact" here means
            # exact string equality against the real address - not a
            # substring/regex match, which would risk one IP false-
            # positive-matching another that merely contains it as a
            # run of digits (e.g. "1.2.3.4" inside "21.2.3.45").
            match = {"ip_regex": [value]} if is_regex else {"ips": [value.strip().lower()]}
        elif category == "port":
            match = {"port_regex": [value]} if is_regex else {"ports": [safe_int(value, 0)]}
        elif category == "protocol":
            match = {"protocol_regex": [value]} if is_regex else {"protocols": [normalize_protocol_name(value)]}
        else:
            # Domain/path values DO appear in build_packet_text (via
            # summary/payload_text/domain/http_host/http_path/http_method),
            # so these stay payload-based. "Exact" is still word-boundary-
            # anchored rather than a bare substring, for the same reason:
            # a bare substring match on "evil.com" would also fire on
            # "notevil.com" or an unrelated domain that merely contains
            # that run of characters.
            pattern = value if is_regex else literal_packet_text_pattern(value)
            match = {"payload_regex": [pattern]}
        label = str(entry.get("label") or "").strip() or f"Blacklisted {category}: {value}"
        now = utc_now()
        self._execute(
            """
            INSERT INTO monitors (id, name, description, enabled, priority, source, mode, match_json, action_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, 'blacklist', ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
              name = excluded.name,
              description = excluded.description,
              enabled = excluded.enabled,
              mode = excluded.mode,
              match_json = excluded.match_json,
              action_json = excluded.action_json,
              updated_at = excluded.updated_at
            """,
            (
                self._blacklist_monitor_id(entry["id"]),
                label,
                f"Blacklist entry ({category}, {entry.get('match_type')}): {value}",
                1 if entry.get("enabled", True) else 0,
                1,
                "regex" if is_regex else "rule",
                json_dumps(match),
                json_dumps({"tag": f"blacklist-{category}", "label": label, "severity": "critical"}),
                now,
                now,
            ),
            commit=True,
        )

    def list_blacklist_entries(self, category: str = "") -> list[dict]:
        category = str(category or "").strip().lower()
        if category:
            rows = self._fetchall(
                "SELECT * FROM blacklist_entries WHERE category = ? ORDER BY created_at DESC",
                (category,),
            )
        else:
            rows = self._fetchall("SELECT * FROM blacklist_entries ORDER BY created_at DESC")
        for row in rows:
            row["enabled"] = bool(row.get("enabled"))
        return rows

    def get_blacklist_entry(self, entry_id: str):
        row = self._fetchone("SELECT * FROM blacklist_entries WHERE id = ?", (str(entry_id),))
        if not row:
            return None
        row["enabled"] = bool(row.get("enabled"))
        return row

    def create_blacklist_entry(self, category: str, match_type: str, value: str, label: str = "") -> dict:
        category = str(category or "").strip().lower()
        if category not in self.BLACKLIST_CATEGORIES:
            raise ValueError(f"category must be one of {self.BLACKLIST_CATEGORIES}")
        match_type = str(match_type or "exact").strip().lower()
        if match_type not in ("exact", "regex"):
            raise ValueError("match_type must be 'exact' or 'regex'")
        value = str(value or "").strip()
        if not value:
            raise ValueError("value is required")
        if match_type == "regex":
            try:
                re.compile(value)
            except re.error as exc:
                raise ValueError(f"Invalid regex pattern: {exc}") from exc
        else:
            value = self._normalize_list_value(category, value, exact=True)
        entry_id = f"blacklist-{category}-{uuid.uuid4().hex[:12]}"
        now = utc_now()
        self._execute(
            """
            INSERT INTO blacklist_entries (id, category, match_type, value, label, enabled, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, 1, ?, ?)
            """,
            (entry_id, category, match_type, value, str(label or "").strip(), now, now),
            commit=True,
        )
        entry = self.get_blacklist_entry(entry_id)
        self._sync_blacklist_monitor(entry)
        return entry

    def set_blacklist_entry_enabled(self, entry_id: str, enabled: bool) -> dict:
        existing = self.get_blacklist_entry(entry_id)
        if not existing:
            raise ValueError(f"Unknown blacklist entry id: {entry_id}")
        now = utc_now()
        self._execute(
            "UPDATE blacklist_entries SET enabled = ?, updated_at = ? WHERE id = ?",
            (1 if enabled else 0, now, str(entry_id)),
            commit=True,
        )
        entry = self.get_blacklist_entry(entry_id)
        self._sync_blacklist_monitor(entry)
        return entry

    def delete_blacklist_entry(self, entry_id: str) -> bool:
        existing = self.get_blacklist_entry(entry_id)
        if not existing:
            raise ValueError(f"Unknown blacklist entry id: {entry_id}")
        with self._lock:
            self._conn.execute("DELETE FROM blacklist_entries WHERE id = ?", (str(entry_id),))
            self._conn.execute(
                "DELETE FROM monitors WHERE id = ? AND source = 'blacklist'",
                (self._blacklist_monitor_id(entry_id),),
            )
            self._conn.commit()
        return True

    # --- Whitelist -----------------------------------------------------
    #
    # Whitelist entries are deliberately not mirrored into `monitors`: their
    # job is the inverse of a blacklist entry. A matching packet is still
    # counted and stored, but it skips ruleset classification, monitor
    # evaluation and anomaly detection, which removes noisy known-good
    # hosts/domains/paths without making capture look dead.

    WHITELIST_CATEGORIES = BLACKLIST_CATEGORIES

    def list_whitelist_entries(self, category: str = "") -> list[dict]:
        category = str(category or "").strip().lower()
        if category:
            rows = self._fetchall(
                "SELECT * FROM whitelist_entries WHERE category = ? ORDER BY created_at DESC",
                (category,),
            )
        else:
            rows = self._fetchall("SELECT * FROM whitelist_entries ORDER BY created_at DESC")
        for row in rows:
            row["enabled"] = bool(row.get("enabled"))
        return rows

    def get_whitelist_entry(self, entry_id: str):
        row = self._fetchone("SELECT * FROM whitelist_entries WHERE id = ?", (str(entry_id),))
        if not row:
            return None
        row["enabled"] = bool(row.get("enabled"))
        return row

    def create_whitelist_entry(self, category: str, match_type: str, value: str, label: str = "") -> dict:
        category = str(category or "").strip().lower()
        if category not in self.WHITELIST_CATEGORIES:
            raise ValueError(f"category must be one of {self.WHITELIST_CATEGORIES}")
        match_type = str(match_type or "exact").strip().lower()
        if match_type not in ("exact", "regex"):
            raise ValueError("match_type must be 'exact' or 'regex'")
        value = str(value or "").strip()
        if not value:
            raise ValueError("value is required")
        if match_type == "regex":
            try:
                re.compile(value)
            except re.error as exc:
                raise ValueError(f"Invalid regex pattern: {exc}") from exc
        else:
            value = self._normalize_list_value(category, value, exact=True)
        entry_id = f"whitelist-{category}-{uuid.uuid4().hex[:12]}"
        now = utc_now()
        self._execute(
            """
            INSERT INTO whitelist_entries (id, category, match_type, value, label, enabled, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, 1, ?, ?)
            """,
            (entry_id, category, match_type, value, str(label or "").strip(), now, now),
            commit=True,
        )
        return self.get_whitelist_entry(entry_id)

    def set_whitelist_entry_enabled(self, entry_id: str, enabled: bool) -> dict:
        existing = self.get_whitelist_entry(entry_id)
        if not existing:
            raise ValueError(f"Unknown whitelist entry id: {entry_id}")
        now = utc_now()
        self._execute(
            "UPDATE whitelist_entries SET enabled = ?, updated_at = ? WHERE id = ?",
            (1 if enabled else 0, now, str(entry_id)),
            commit=True,
        )
        return self.get_whitelist_entry(entry_id)

    def delete_whitelist_entry(self, entry_id: str) -> bool:
        existing = self.get_whitelist_entry(entry_id)
        if not existing:
            raise ValueError(f"Unknown whitelist entry id: {entry_id}")
        self._execute("DELETE FROM whitelist_entries WHERE id = ?", (str(entry_id),), commit=True)
        return True

    def get_monitor_filter_enabled(self) -> bool:
        default = "1" if MONITOR_FILTER_DEFAULT else "0"
        value = self.get_runtime_config("monitor_filter_enabled", default)
        return str(value).strip().lower() in {"1", "true", "yes", "on"}

    def set_monitor_filter_enabled(self, value: bool):
        self.set_runtime_config("monitor_filter_enabled", "1" if value else "0")
        return self.get_monitor_filter_enabled()

    def get_monitor_min_severity(self) -> str:
        value = str(self.get_runtime_config("monitor_min_severity", MONITOR_MIN_SEVERITY_DEFAULT) or "").strip().lower()
        return value if value in MONITOR_SEVERITIES else MONITOR_MIN_SEVERITY_DEFAULT

    def set_monitor_min_severity(self, severity: str) -> str:
        value = str(severity or "").strip().lower()
        if value not in MONITOR_SEVERITIES:
            raise ValueError(f"unknown severity {value!r}; expected one of {', '.join(MONITOR_SEVERITIES)}")
        self.set_runtime_config("monitor_min_severity", value)
        return self.get_monitor_min_severity()

    def get_monitor_suppress_generated_info(self) -> bool:
        default = "1" if MONITOR_SUPPRESS_GENERATED_INFO_DEFAULT else "0"
        value = self.get_runtime_config("monitor_suppress_generated_info", default)
        return str(value).strip().lower() in {"1", "true", "yes", "on"}

    def set_monitor_suppress_generated_info(self, value: bool) -> bool:
        self.set_runtime_config("monitor_suppress_generated_info", "1" if value else "0")
        return self.get_monitor_suppress_generated_info()

    def get_monitor_config(self) -> dict:
        return {
            "filter_enabled": self.get_monitor_filter_enabled(),
            "min_severity": self.get_monitor_min_severity(),
            "suppress_generated_info": self.get_monitor_suppress_generated_info(),
            "severity_options": list(MONITOR_SEVERITIES),
        }

    def get_detection_exclude_scopes(self) -> list[str]:
        """IP scopes whose traffic must not be run through detection."""
        from .utils import DETECTION_IP_SCOPES

        default = ",".join(sorted(DETECTION_EXCLUDE_SCOPES))
        raw = self.get_runtime_config("detection_exclude_scopes", default)
        wanted = {item.strip().lower() for item in str(raw or "").split(",") if item.strip()}
        return sorted(wanted & set(DETECTION_IP_SCOPES))

    def set_detection_exclude_scopes(self, scopes) -> list[str]:
        from .utils import DETECTION_IP_SCOPES

        if isinstance(scopes, str):
            scopes = scopes.split(",")
        wanted = {str(item).strip().lower() for item in (scopes or []) if str(item).strip()}
        unknown = wanted - set(DETECTION_IP_SCOPES)
        if unknown:
            raise ValueError(
                f"unknown scope(s) {', '.join(sorted(unknown))}; expected any of {', '.join(DETECTION_IP_SCOPES)}"
            )
        self.set_runtime_config("detection_exclude_scopes", ",".join(sorted(wanted)))
        return self.get_detection_exclude_scopes()

    def list_count(self, table: str) -> int:
        row = self._fetchone(f"SELECT COUNT(*) AS count FROM {table}")
        return int(row["count"] or 0) if row else 0

    def list_payload_sizes(self):
        return self._fetchall(
            """
            SELECT
              CASE
                WHEN response_size < 128 THEN 'tiny'
                WHEN response_size < 512 THEN 'small'
                WHEN response_size < 2048 THEN 'medium'
                ELSE 'large'
              END AS bucket,
              COUNT(*) AS value
            FROM payloads
            GROUP BY bucket
            ORDER BY value DESC, bucket ASC
            """
        )

    def top_protocols(self, *, limit=8):
        return self._fetchall(
            """
            SELECT proto AS label, COUNT(*) AS value
            FROM packets
            GROUP BY proto
            ORDER BY value DESC, label ASC
            LIMIT ?
            """,
            (int(limit),),
        )

    def top_ports(self, *, limit=10, since=""):
        where = "WHERE COALESCE(NULLIF(dst_port, 0), src_port) > 0"
        params = []
        if since:
            where += " AND created_at >= ?"
            params.append(str(since))
        params.append(int(limit))
        return self._fetchall(
            f"""
            SELECT
              COALESCE(NULLIF(dst_port, 0), src_port) AS port,
              COUNT(*) AS value
            FROM packets
            {where}
            GROUP BY port
            ORDER BY value DESC, port ASC
            LIMIT ?
            """,
            tuple(params),
        )

    def top_ips(self, *, limit=10, since=""):
        created_filter = "AND created_at >= ?" if since else ""
        params = [str(since), str(since)] if since else []
        params.append(int(limit))
        return self._fetchall(
            f"""
            SELECT ip, COUNT(*) AS value
            FROM (
              SELECT src_ip AS ip FROM packets WHERE src_ip != '' {created_filter}
              UNION ALL
              SELECT dst_ip AS ip FROM packets WHERE dst_ip != '' {created_filter}
            )
            GROUP BY ip
            ORDER BY value DESC, ip ASC
            LIMIT ?
            """,
            tuple(params),
        )

    def top_tag_keys(self, *, limit=10, since=""):
        where, params = self._tag_filter(since=since)
        params = list(params)
        params.append(int(limit))
        return self._fetchall(
            f"""
            SELECT key AS label, COUNT(*) AS value
            FROM tags
            {where}
            GROUP BY key
            ORDER BY value DESC, label ASC
            LIMIT ?
            """,
            tuple(params),
        )

    def top_service_signatures(self, *, limit=10, since=""):
        clauses = ["COALESCE(NULLIF(banner_text, ''), summary, payload_text, '') != ''"]
        params = []
        if since:
            clauses.append("created_at >= ?")
            params.append(str(since))
        where = f"WHERE {' AND '.join(clauses)}"
        params.append(int(limit))
        return self._fetchall(
            f"""
            SELECT
              COALESCE(NULLIF(banner_text, ''), summary, payload_text, 'payload') AS label,
              COUNT(*) AS value
            FROM packets
            {where}
            GROUP BY label
            ORDER BY value DESC, label ASC
            LIMIT ?
            """,
            tuple(params),
        )

    def summary_counts(self, *, since="") -> dict:
        sessions = self.count_sessions(since=since) if since else self.list_count("sessions")
        packets = self.count_packets(since=since) if since else self.list_count("packets")
        payloads = self.count_payloads(since=since) if since else self.list_count("payloads")
        tags = self.count_tags(since=since) if since else self.list_count("tags")
        flows = self.list_count("flows")
        rules = self.list_count("rulesets")
        created_filter = "AND created_at >= ?" if since else ""
        unique_params = (str(since), str(since)) if since else ()
        unique_hosts_row = self._fetchone(
            f"""
            SELECT COUNT(DISTINCT ip) AS count
            FROM (
                SELECT src_ip AS ip FROM packets WHERE src_ip != '' {created_filter}
                UNION ALL
                SELECT dst_ip AS ip FROM packets WHERE dst_ip != '' {created_filter}
            )
            """,
            unique_params,
        )
        packet_where, packet_params = self._packet_filter(since=since)

        def count_state(state: str) -> int:
            where = f"{packet_where} AND state = ?" if packet_where else "WHERE state = ?"
            row = self._fetchone(f"SELECT COUNT(*) AS count FROM packets {where}", tuple(list(packet_params) + [state]))
            return int((row or {}).get("count") or 0)

        return {
            "sessions": sessions,
            "packets": packets,
            "payloads": payloads,
            "tags": tags,
            "flows": flows,
            "rulesets": rules,
            "open_packets": count_state("open"),
            "filtered_packets": count_state("filtered"),
            "unique_hosts": int(unique_hosts_row["count"] or 0) if unique_hosts_row else 0,
        }

    def _count_where(self, table_or_subquery: str, where_clause: str, *, count_distinct=False, distinct_column="id"):
        if count_distinct:
            sql = f"SELECT COUNT(DISTINCT {distinct_column}) AS count FROM {table_or_subquery} WHERE {where_clause}"
        else:
            sql = f"SELECT COUNT(*) AS count FROM {table_or_subquery} WHERE {where_clause}"
        row = self._fetchone(sql)
        return int(row["count"] or 0) if row else 0

    def dashboard_snapshot(self, *, ws_clients=None, compact=False, since="") -> dict:
        ws_clients = list(ws_clients or [])
        if since:
            protocols = [
                row["protocol"]
                for row in self.protocol_catalog(since=since)
                if safe_int(row.get("count"), 0) > 0
            ]
        else:
            protocols = self.list_protocols()
        counts = {
            "count_targets": self.count_sessions(since=since) if since else self.list_count("sessions"),
            "count_ports": self.count_packets(since=since) if since else self.list_count("packets"),
            "count_banners": self.count_payloads(since=since) if since else self.list_count("payloads"),
            "count_tags": self.count_tags(since=since) if since else self.list_count("tags"),
            "count_rulesets": self.list_count("rulesets"),
            "count_monitors": self.list_count("monitors"),
            "count_domains": self.count_domains(since=since) if since else self.list_count("domains"),
            "count_paths": self.count_paths(since=since) if since else self.list_count("paths"),
        }
        if compact:
            sessions = []
            packets = []
            payloads = []
            tags = []
            ports_by_proto = {}
        else:
            sessions = self.list_sessions(limit=20, since=since)
            packets = self.list_packets(limit=20, since=since)
            payloads = self.list_payloads(limit=20, since=since)
            tags = self.list_tags(limit=20, since=since)
            ports_by_proto = {}
            for proto in protocols:
                ports_by_proto[proto] = self.list_packets(proto=proto, limit=12, since=since)
        return {
            "generated_at": utc_now(),
            "counts": counts,
            "sessions": sessions,
            "targets": sessions,
            "packets": packets,
            "ports": ports_by_proto,
            "banners": payloads,
            "tags": tags,
            "ws_clients": ws_clients,
            "protocols": protocols,
        }

    def analytics_snapshot(self, *, since="") -> dict:
        summary = self.summary_counts(since=since)
        packet_where, packet_params = self._packet_filter(since=since)
        proto_rows = self._fetchall(
            f"""
            SELECT proto, COUNT(*) AS value
            FROM packets
            {packet_where + ' AND' if packet_where else 'WHERE'} proto != ''
            GROUP BY proto
            ORDER BY value DESC, proto ASC
            """,
            tuple(packet_params),
        )
        state_rows = self._fetchall(
            f"""
            SELECT proto, state, COUNT(*) AS value
            FROM packets
            {packet_where + ' AND' if packet_where else 'WHERE'} proto != ''
            GROUP BY proto, state
            ORDER BY proto ASC, value DESC, state ASC
            """,
            tuple(packet_params),
        )
        ports_by_proto = [
            {"label": normalize_protocol_name(row.get("proto")), "value": safe_int(row.get("value"), 0)}
            for row in proto_rows
            if row.get("proto")
        ]
        states_by_proto = defaultdict(list)
        for row in state_rows:
            proto = normalize_protocol_name(row.get("proto"))
            if not proto:
                continue
            state = str(row.get("state") or "open").strip().lower() or "open"
            states_by_proto[proto].append({"label": state, "value": safe_int(row.get("value"), 0)})
        ports_state_by_proto = [
            {"label": proto, "series": rows}
            for proto, rows in states_by_proto.items()
        ]
        top_open_ports = self.top_ports(limit=12, since=since)
        top_ips_by_open_ports = self.top_ips(limit=12, since=since)
        risk_ports = [
            item for item in top_open_ports if safe_int(item.get("port"), 0) in {21, 22, 23, 25, 53, 110, 135, 139, 143, 445, 3389}
        ]
        targets_by_status = [
            {
                "label": str(row.get("status") or "stopped").strip().lower() or "stopped",
                "value": safe_int(row.get("value"), 0),
            }
            for row in self._fetchall(
                """
                SELECT status, COUNT(*) AS value
                FROM sessions
                GROUP BY status
                ORDER BY value DESC, status ASC
                """
            )
        ]
        session_where, session_params = self._session_filter(since=since)
        target_progress_buckets = self._bucket_rows(
            [
                safe_float(row.get("progress", 0.0), 0.0)
                for row in self._fetchall(
                    f"SELECT progress FROM sessions {session_where} LIMIT 1000",
                    tuple(session_params),
                )
            ]
        )
        payload_where, payload_params = self._payload_filter(since=since)
        banner_length_buckets = self._bucket_rows(
            [
                safe_int(row.get("response_size", 0), 0)
                for row in self._fetchall(
                    f"SELECT response_size FROM payloads {payload_where} LIMIT 1000",
                    tuple(payload_params),
                )
            ],
            size_mode=True,
        )
        top_tag_keys = self.top_tag_keys(limit=12, since=since)
        top_service_signatures = self.top_service_signatures(limit=12, since=since)
        timeline = self._timeline_snapshot_from_sql(since=since)
        return {
            "generated_at": utc_now(),
            "summary": {
                "targets": summary["sessions"],
                "ports": summary["packets"],
                "open_ports": summary["open_packets"],
                "filtered_ports": summary["filtered_packets"],
                "banners": summary["payloads"],
                "tags": summary["tags"],
                "favicons": 0,
                "unique_hosts": summary["unique_hosts"],
            },
            "ports_by_proto": ports_by_proto,
            "ports_state_by_proto": ports_state_by_proto,
            "top_open_ports": top_open_ports,
            "top_ips_by_open_ports": top_ips_by_open_ports,
            "risk_ports": risk_ports,
            "targets_by_status": targets_by_status,
            "target_progress_buckets": target_progress_buckets,
            "banner_length_buckets": banner_length_buckets,
            "top_tag_keys": top_tag_keys,
            "top_service_signatures": top_service_signatures,
            "timeline": timeline,
        }

    def _timeline_snapshot_from_sql(self, *, since=""):
        for table in ("packets", "sessions", "flows"):
            clauses = ["created_at != ''"]
            params = []
            if since:
                clauses.append("created_at >= ?")
                params.append(str(since))
            where = f"WHERE {' AND '.join(clauses)}"
            rows = self._fetchall(
                f"""
                SELECT substr(created_at, 1, 10) AS label, COUNT(*) AS value
                FROM {table}
                {where}
                GROUP BY label
                ORDER BY label DESC
                LIMIT 30
                """,
                tuple(params),
            )
            if rows:
                return [
                    {"label": str(row.get("label") or ""), "value": safe_int(row.get("value"), 0)}
                    for row in reversed(rows)
                ]
        return []

    def soc_analysis_snapshot(self, *, cycles=4, limit=PACKET_TABLE_LIMIT) -> dict:
        cycle_count = clamp_int(cycles, 1, 4)
        sample_limit = clamp_int(limit, 250, PACKET_TABLE_LIMIT)
        packets = self.list_packets(limit=sample_limit)
        payloads = self.list_payloads(limit=min(sample_limit, PAYLOAD_TABLE_LIMIT))
        tags = self.list_tags(limit=min(sample_limit * 2, TAG_TABLE_LIMIT))
        flows = self.list_flows(limit=min(sample_limit, FLOW_TABLE_LIMIT))
        snapshot = self.analytics_snapshot()
        snapshot["timeline"] = self._timeline_snapshot(packets, self.list_sessions(limit=1000), flows)

        risky_ports = {21, 22, 23, 25, 53, 110, 135, 139, 143, 445, 3389}
        packet_total = len(packets)
        direction_counts = Counter(
            str(row.get("direction") or "unknown").strip().lower() or "unknown"
            for row in packets
        )
        state_counts = Counter(
            str(row.get("state") or "open").strip().lower() or "open"
            for row in packets
        )
        proto_counts = Counter(normalize_protocol_name(row.get("proto")) for row in packets)
        row_scope_counts = Counter()
        host_counts = Counter()
        host_protocols = defaultdict(Counter)
        host_ports = defaultdict(Counter)
        host_scopes: dict[str, str] = {}
        port_counts = Counter()
        port_protocols = defaultdict(Counter)
        port_scopes = defaultdict(Counter)
        conversation_counts = Counter()
        payload_signatures = Counter()
        payload_signature_examples = defaultdict(list)
        tag_key_counts = Counter()
        tag_value_counts = Counter()
        public_hosts = set()
        private_hosts = set()
        local_hosts = set()

        for row in packets:
            proto = normalize_protocol_name(row.get("proto"))
            src_ip = str(row.get("src_ip") or "").strip()
            dst_ip = str(row.get("dst_ip") or "").strip()
            src_port = safe_int(row.get("src_port"), 0)
            dst_port = safe_int(row.get("dst_port"), 0)
            unique_hosts = {host for host in (src_ip, dst_ip) if host}
            unique_ports = {port for port in (src_port, dst_port) if port > 0}
            scopes = {_soc_ip_scope(host) for host in unique_hosts}
            scopes.discard("unknown")
            if scopes == {"local"}:
                row_scope = "local"
            elif "public" in scopes and "private" in scopes:
                row_scope = "cross-scope"
            elif "public" in scopes:
                row_scope = "public"
            elif "private" in scopes:
                row_scope = "private"
            elif "local" in scopes:
                row_scope = "local"
            else:
                row_scope = "unknown"
            row_scope_counts[row_scope] += 1

            for host in unique_hosts:
                host_counts[host] += 1
                host_protocols[host][proto] += 1
                for port in unique_ports:
                    host_ports[host][port] += 1
                if host not in host_scopes:
                    host_scopes[host] = _soc_ip_scope(host)
                scope = host_scopes[host]
                if scope == "public":
                    public_hosts.add(host)
                elif scope == "private":
                    private_hosts.add(host)
                elif scope == "local":
                    local_hosts.add(host)

            for port in unique_ports:
                port_counts[port] += 1
                port_protocols[port][proto] += 1
                port_scopes[port][row_scope] += 1

            if src_ip and dst_ip:
                port_label = "/".join(str(port) for port in sorted(unique_ports)) if unique_ports else "0"
                conversation_counts[(src_ip, dst_ip, proto, port_label, row_scope)] += 1

        for payload in payloads:
            signature = _soc_payload_signature(payload.get("response_plain") or payload.get("summary"))
            payload_signatures[signature] += 1
            example = normalize_text(payload.get("response_plain") or payload.get("summary") or "", limit=120)
            if example and len(payload_signature_examples[signature]) < 3:
                payload_signature_examples[signature].append(example)

        for tag in tags:
            key = str(tag.get("key") or "").strip()
            value = str(tag.get("value") or "").strip()
            if key:
                tag_key_counts[key] += 1
            if value:
                tag_value_counts[value] += 1

        findings = []
        cycles_data = []
        finding_seq = 0

        def add_finding(cycle_id, severity, category, title, evidence, recommendation, confidence=0.8):
            nonlocal finding_seq
            finding_seq += 1
            finding = {
                "id": f"soc-{finding_seq}",
                "cycle": cycle_id,
                "severity": severity,
                "category": category,
                "title": title,
                "confidence": round(float(confidence), 2),
                "evidence": [str(item) for item in evidence if str(item).strip()],
                "recommendation": str(recommendation or "").strip(),
            }
            findings.append(finding)
            return finding["id"]

        def host_note(host, count):
            scope = host_scopes.get(host, _soc_ip_scope(host))
            notes = []
            if host == "127.0.0.1":
                notes.append("loopback")
            if scope == "public":
                notes.append("validate ownership")
            elif scope == "private":
                notes.append("internal")
            elif scope == "local":
                notes.append("local")
            if count >= max(10, packet_total // 2):
                notes.append("dominant")
            if any(port in risky_ports for port in host_ports.get(host, {})):
                notes.append("sensitive port")
            return ", ".join(notes) if notes else "observed"

        def conversation_note(src, dst, proto, port_label, row_scope):
            notes = []
            if src == dst == "127.0.0.1":
                notes.append("loopback")
            if row_scope == "cross-scope":
                notes.append("public->private")
            elif row_scope in {"public", "private", "local"}:
                notes.append(row_scope)
            if port_label == "51820" or "51820" in port_label:
                notes.append("tunnel-like")
            if port_label == "443" or "443" in port_label:
                notes.append("tls/web")
            if proto == "udp":
                notes.append("udp")
            return ", ".join(notes) if notes else "observed"

        def port_note(port, row_scope):
            notes = []
            if port in risky_ports:
                notes.append("sensitive port")
            if port >= 49152 and row_scope == "local":
                notes.append("ephemeral")
            if row_scope == "cross-scope":
                notes.append("cross-scope")
            elif row_scope in {"public", "private", "local"}:
                notes.append(row_scope)
            if port == 443:
                notes.append("tls/web")
            if port == 51820:
                notes.append("tunnel-like")
            return ", ".join(notes) if notes else "observed"

        def payload_note(signature):
            return {
                "structured": "JSON-like telemetry",
                "http-like": "cleartext HTTP",
                "noisy": "low semantic density",
                "text": "plain text",
                "empty": "empty payloads",
            }.get(signature, "observed")

        top_protocol_rows = [
            {"label": proto, "value": value}
            for proto, value in proto_counts.most_common()
            if proto
        ]
        top_public_hosts = [
            host for host, _ in host_counts.most_common()
            if host_scopes.get(host) == "public"
        ]
        top_host_rows = []
        for host, count in host_counts.most_common(8):
            protocols = ", ".join(proto for proto, _ in host_protocols[host].most_common(3)) or "unknown"
            ports = ", ".join(str(port) for port, _ in host_ports[host].most_common(3)) or "-"
            top_host_rows.append(
                {
                    "ip": host,
                    "value": count,
                    "scope": host_scopes.get(host, _soc_ip_scope(host)),
                    "protocols": protocols,
                    "ports": ports,
                    "note": host_note(host, count),
                }
            )

        top_conversation_rows = []
        for (src_ip, dst_ip, proto, port_label, row_scope), count in conversation_counts.most_common(8):
            top_conversation_rows.append(
                {
                    "label": f"{src_ip} -> {dst_ip}",
                    "value": count,
                    "proto": proto,
                    "ports": port_label,
                    "scope": row_scope,
                    "note": conversation_note(src_ip, dst_ip, proto, port_label, row_scope),
                }
            )

        top_port_rows = []
        for port, count in port_counts.most_common(8):
            protocols = ", ".join(proto for proto, _ in port_protocols[port].most_common(3)) or "unknown"
            scope = port_scopes[port].most_common(1)[0][0] if port_scopes[port] else "unknown"
            top_port_rows.append(
                {
                    "port": port,
                    "value": count,
                    "protocols": protocols,
                    "scope": scope,
                    "note": port_note(port, scope),
                }
            )

        payload_pattern_rows = []
        for signature, count in payload_signatures.most_common():
            examples = payload_signature_examples.get(signature, [])
            payload_pattern_rows.append(
                {
                    "label": signature,
                    "value": count,
                    "note": payload_note(signature),
                    "example": examples[0] if examples else "",
                }
            )

        total_local_rows = row_scope_counts["local"]
        total_cross_scope_rows = row_scope_counts["cross-scope"]
        total_public_rows = row_scope_counts["public"]
        total_private_rows = row_scope_counts["private"]
        total_unknown_rows = row_scope_counts["unknown"]
        direction_unknown_rows = direction_counts["unknown"]
        direction_unknown_ratio = (direction_unknown_rows / packet_total) if packet_total else 0.0
        noisy_payloads = payload_signatures["noisy"]
        structured_payloads = payload_signatures["structured"]

        cycle_1_findings = []
        cycle_1_observations = []
        if top_protocol_rows:
            cycle_1_observations.append(
                ", ".join(f"{item['label']}={item['value']}" for item in top_protocol_rows[:3])
            )
        if packet_total:
            cycle_1_observations.append(f"{total_local_rows} local rows out of {packet_total} sampled packets")
            cycle_1_observations.append(f"{total_cross_scope_rows} cross-scope rows detected")
        if packet_total and total_local_rows >= int(packet_total * 0.5):
            cycle_1_findings.append(
                add_finding(
                    1,
                    "info",
                    "baseline",
                    f"Loopback and local traffic dominate ({total_local_rows}/{packet_total})",
                    [
                        f"local rows={total_local_rows}",
                        f"private rows={total_private_rows}",
                        f"public rows={total_public_rows}",
                    ],
                    "Treat most of this sample as local telemetry and move the hunt to the outliers.",
                    confidence=0.97,
                )
            )
        if packet_total and direction_unknown_ratio >= 0.5:
            cycle_1_findings.append(
                add_finding(
                    1,
                    "low",
                    "telemetry-gap",
                    f"Direction is unknown on {direction_unknown_rows}/{packet_total} rows",
                    [
                        f"unknown direction rows={direction_unknown_rows}",
                        "source/destination pairing is more reliable than direction metadata here",
                    ],
                    "Use IP pairing and port ownership until the capture pipeline emits better direction labels.",
                    confidence=0.99,
                )
            )
        if top_public_hosts:
            public_preview = ", ".join(top_public_hosts[:2])
            cycle_1_findings.append(
                add_finding(
                    1,
                    "medium",
                    "external-exposure",
                    f"Public hosts are present: {public_preview}",
                    [f"public hosts={len(top_public_hosts)}", public_preview],
                    "Validate ownership and allowed services for the public endpoints before treating them as benign.",
                    confidence=0.85,
                )
            )
        if len([item for item in top_protocol_rows if item["label"]]) <= 2:
            cycle_1_findings.append(
                add_finding(
                    1,
                    "info",
                    "protocol-mix",
                    "The sampled traffic is limited to a narrow protocol mix",
                    [", ".join(item["label"] for item in top_protocol_rows[:3]) or "no protocol data"],
                    "No packet-level evidence of additional protocol families in this slice.",
                    confidence=0.88,
                )
            )
        if not direction_counts.get("unknown") and total_unknown_rows == 0:
            cycle_1_findings.append(
                add_finding(
                    1,
                    "info",
                    "coverage",
                    "No unknown protocol rows or honeypot artifacts are present in this sample",
                    ["unknown protocol rows=0", "honeypot rows=0"],
                    "Keep this slice in the low-risk bucket unless new protocol families appear.",
                    confidence=0.9,
                )
            )
        cycles_data.append(
            {
                "id": 1,
                "title": "Baseline triage",
                "need": [
                    "packet volume",
                    "protocol mix",
                    "local vs public split",
                    "direction metadata",
                ],
                "observations": cycle_1_observations,
                "finding_ids": cycle_1_findings,
                "finding_count": len(cycle_1_findings),
            }
        )

        cycle_2_findings = []
        cycle_2_observations = []
        if top_conversation_rows:
            cycle_2_observations.append(
                f"Top conversation: {top_conversation_rows[0]['label']} ({top_conversation_rows[0]['value']})"
            )
        if top_port_rows:
            cycle_2_observations.append(
                ", ".join(f"{item['port']}={item['value']}" for item in top_port_rows[:4])
            )
        if top_host_rows:
            cycle_2_observations.append(
                f"Top host: {top_host_rows[0]['ip']} ({top_host_rows[0]['value']})"
            )
        if total_local_rows and top_host_rows and top_host_rows[0]["ip"] == "127.0.0.1":
            cycle_2_findings.append(
                add_finding(
                    2,
                    "info",
                    "loopback-hotspot",
                    "Loopback conversations dominate the top of the table",
                    [
                        f"host={top_host_rows[0]['ip']}",
                        f"packets={top_host_rows[0]['value']}",
                        f"ports={top_host_rows[0]['ports']}",
                    ],
                    "Keep this bucket low priority unless the process owner changes.",
                    confidence=0.96,
                )
            )
        if any(safe_int(item.get("port"), 0) == 51820 for item in top_port_rows):
            cycle_2_findings.append(
                add_finding(
                    2,
                    "medium",
                    "tunnel-review",
                    "UDP/51820 is active in the sample",
                    [
                        "port=51820",
                        ", ".join(
                            row["label"]
                            for row in top_conversation_rows
                            if "51820" in str(row.get("ports") or "")
                        )
                        or "no direct conversation note",
                    ],
                    "Validate whether an encrypted tunnel, VPN client, or other remote access path is expected.",
                    confidence=0.9,
                )
            )
        if any(safe_int(item.get("port"), 0) == 443 for item in top_port_rows):
            cycle_2_findings.append(
                add_finding(
                    2,
                    "medium",
                    "tls-review",
                    "Port 443 is present across multiple hosts",
                    [
                        ", ".join(
                            row["label"]
                            for row in top_conversation_rows
                            if "443" in str(row.get("ports") or "")
                        )
                        or "443 conversations present",
                        ", ".join(
                            row["ip"]
                            for row in top_host_rows
                            if row.get("scope") == "public"
                        )
                        or "no public host list",
                    ],
                    "Confirm certificate ownership and whether these TLS-like flows are part of the expected workload.",
                    confidence=0.84,
                )
            )
        if any(item["scope"] == "cross-scope" for item in top_conversation_rows):
            cycle_2_findings.append(
                add_finding(
                    2,
                    "low",
                    "cross-scope",
                    "Cross-scope conversations are visible in the top flows",
                    [
                        ", ".join(item["label"] for item in top_conversation_rows if item["scope"] == "cross-scope")
                        or "no cross-scope rows",
                    ],
                    "Validate whether these public-to-private exchanges are expected and authorized.",
                    confidence=0.8,
                )
            )
        cycles_data.append(
            {
                "id": 2,
                "title": "Conversation drill-down",
                "need": [
                    "top conversations",
                    "hot ports",
                    "peer scopes",
                    "likely service owners",
                ],
                "observations": cycle_2_observations,
                "finding_ids": cycle_2_findings,
                "finding_count": len(cycle_2_findings),
            }
        )

        cycle_3_findings = []
        cycle_3_observations = []
        if payload_pattern_rows:
            cycle_3_observations.append(
                ", ".join(
                    f"{item['label']}={item['value']}"
                    for item in payload_pattern_rows[:4]
                )
            )
        if tag_key_counts:
            cycle_3_observations.append(
                ", ".join(
                    f"{label}={value}"
                    for label, value in tag_key_counts.most_common(4)
                )
            )
        if structured_payloads and noisy_payloads:
            cycle_3_findings.append(
                add_finding(
                    3,
                    "info",
                    "payload-shape",
                    "The sample splits between structured and noisy payloads",
                    [
                        f"structured payloads={structured_payloads}",
                        f"noisy payloads={noisy_payloads}",
                    ],
                    "Use payload shape to separate telemetry from opaque transport noise.",
                    confidence=0.86,
                )
            )
        if structured_payloads:
            cycle_3_findings.append(
                add_finding(
                    3,
                    "info",
                    "telemetry",
                    "Structured JSON-like payloads are present in the local traffic",
                    [
                        ", ".join(payload_signature_examples.get("structured", [])[:2]) or "structured payload evidence present",
                    ],
                    "The loopback activity looks like internal telemetry or event relay traffic.",
                    confidence=0.82,
                )
            )
        if noisy_payloads and top_public_hosts:
            cycle_3_findings.append(
                add_finding(
                    3,
                    "low",
                    "opaque-transport",
                    "Noisy payloads appear on the public-facing side of the sample",
                    [
                        f"noisy payloads={noisy_payloads}",
                        ", ".join(top_public_hosts[:2]),
                    ],
                    "Validate the noisy flows only if they are not expected encrypted or compressed transports.",
                    confidence=0.76,
                )
            )
        if tag_key_counts:
            cycle_3_findings.append(
                add_finding(
                    3,
                    "info",
                    "tag-depth",
                    "Tags stay at transport metadata depth",
                    [
                        ", ".join(f"{label}={value}" for label, value in tag_key_counts.most_common(4)),
                        ", ".join(f"{label}={value}" for label, value in tag_value_counts.most_common(4)) or "no tag values",
                    ],
                    "Add application context or host ownership metadata if you want deeper SOC triage.",
                    confidence=0.9,
                )
            )
        cycles_data.append(
            {
                "id": 3,
                "title": "Payload and tag correlation",
                "need": [
                    "payload shape",
                    "tag depth",
                    "application context",
                    "evidence quality",
                ],
                "observations": cycle_3_observations,
                "finding_ids": cycle_3_findings,
                "finding_count": len(cycle_3_findings),
            }
        )

        cycle_4_findings = []
        cycle_4_observations = []
        if top_host_rows:
            cycle_4_observations.append(
                f"Most active host: {top_host_rows[0]['ip']} ({top_host_rows[0]['scope']})"
            )
        if payload_pattern_rows:
            cycle_4_observations.append(
                f"Payload mix: {', '.join(item['label'] for item in payload_pattern_rows[:3])}"
            )

        questions = []
        if top_host_rows:
            questions.append(f"Which process owns {top_host_rows[0]['ip']} and its top ports {top_host_rows[0]['ports']}?")
        if top_public_hosts:
            questions.append(f"Are the public endpoints {', '.join(top_public_hosts[:2])} expected in this environment?")
        if any(item["port"] == 51820 for item in top_port_rows):
            questions.append("Is UDP/51820 expected or should it be treated as a tunnel review item?")
        if direction_unknown_rows:
            questions.append("Can the capture pipeline improve direction tagging for faster triage?")

        if questions:
            cycle_4_observations.append(f"Analyst questions: {len(questions)}")

        selected_cycle_count = cycle_count
        selected_cycle_ids = set(range(1, selected_cycle_count + 1))
        selected_findings = [finding for finding in findings if finding["cycle"] in selected_cycle_ids]
        if selected_findings:
            severity_weights = {"high": 20, "medium": 12, "low": 5, "info": 2}
            risk_score = sum(severity_weights.get(finding["severity"], 1) for finding in selected_findings)
        else:
            risk_score = 0
        risk_score += min(10, len(top_public_hosts) * 4)
        risk_score += min(10, total_cross_scope_rows * 2)
        risk_score += min(8, int(direction_unknown_ratio * 20))
        risk_score += min(8, noisy_payloads * 2)
        if total_local_rows >= packet_total * 0.5:
            risk_score -= 4
        risk_score = clamp_int(risk_score, 0, 100)
        if risk_score >= 65:
            verdict = "investigate"
        elif risk_score >= 35:
            verdict = "review"
        elif risk_score >= 15:
            verdict = "monitor"
        else:
            verdict = "observe"

        if verdict in {"investigate", "review"}:
            cycle_4_findings.append(
                add_finding(
                    4,
                    "medium" if verdict == "review" else "high",
                    "priority",
                    f"SOC priority is {verdict}",
                    [
                        f"risk score={risk_score}",
                        f"public hosts={len(top_public_hosts)}",
                        f"cross-scope rows={total_cross_scope_rows}",
                    ],
                    "Focus on external 443 and 51820 flows first, then map the loopback owners.",
                    confidence=0.9,
                )
            )
        if questions:
            cycle_4_findings.append(
                add_finding(
                    4,
                    "info",
                    "hunt-questions",
                    "Analyst questions are ready for follow-up",
                    questions[:3],
                    "Use the questions as the next pass for host ownership and service validation.",
                    confidence=0.93,
                )
            )
        cycles_data.append(
            {
                "id": 4,
                "title": "Triage decision",
                "need": [
                    "priority",
                    "open questions",
                    "next actions",
                    "validation targets",
                ],
                "observations": cycle_4_observations,
                "finding_ids": cycle_4_findings,
                "finding_count": len(cycle_4_findings),
            }
        )

        selected_cycles = cycles_data[:selected_cycle_count]
        selected_finding_ids = {
            finding_id
            for cycle in selected_cycles
            for finding_id in cycle["finding_ids"]
        }
        selected_findings = [finding for finding in findings if finding["id"] in selected_finding_ids]
        severity_counts = Counter(finding["severity"] for finding in selected_findings)
        if not questions:
            questions = [
                "Which host should be investigated first?",
                "Are the public flows expected?",
                "Is the loopback telemetry an internal control channel?",
            ]

        snapshot["soc_summary"] = {
            "sampled_packets": packet_total,
            "sampled_payloads": len(payloads),
            "sampled_tags": len(tags),
            "sampled_flows": len(flows),
            "protocols_seen": len([proto for proto in proto_counts if proto]),
            "local_rows": total_local_rows,
            "private_rows": total_private_rows,
            "public_rows": total_public_rows,
            "cross_scope_rows": total_cross_scope_rows,
            "unknown_rows": total_unknown_rows,
            "direction_unknown_rows": direction_unknown_rows,
            "structured_payloads": structured_payloads,
            "noisy_payloads": noisy_payloads,
            "risk_score": risk_score,
            "verdict": verdict,
            "priority": verdict,
            "findings_total": len(selected_findings),
            "high_findings": severity_counts.get("high", 0),
            "medium_findings": severity_counts.get("medium", 0),
            "low_findings": severity_counts.get("low", 0),
            "info_findings": severity_counts.get("info", 0),
        }
        snapshot["cycles"] = selected_cycles
        snapshot["findings"] = selected_findings
        snapshot["top_hosts"] = top_host_rows
        snapshot["top_conversations"] = top_conversation_rows
        snapshot["top_ports"] = top_port_rows
        snapshot["payload_patterns"] = payload_pattern_rows
        snapshot["questions"] = questions
        snapshot["signals"] = {
            "protocols": top_protocol_rows,
            "directions": [
                {"label": label, "value": value}
                for label, value in direction_counts.most_common()
            ],
            "states": [
                {"label": label, "value": value}
                for label, value in state_counts.most_common()
            ],
            "row_scopes": [
                {"label": label, "value": value}
                for label, value in row_scope_counts.most_common()
            ],
        }
        return snapshot

    def _bucket_rows(self, values, *, size_mode=False):
        buckets = Counter()
        for value in values:
            numeric = safe_float(value, 0.0) if not size_mode else safe_int(value, 0)
            if numeric <= 0:
                bucket = "0"
            elif size_mode:
                if numeric < 128:
                    bucket = "<128B"
                elif numeric < 512:
                    bucket = "128-511B"
                elif numeric < 2048:
                    bucket = "512B-2KB"
                else:
                    bucket = "2KB+"
            else:
                if numeric < 20:
                    bucket = "0-19"
                elif numeric < 40:
                    bucket = "20-39"
                elif numeric < 60:
                    bucket = "40-59"
                elif numeric < 80:
                    bucket = "60-79"
                else:
                    bucket = "80-100"
            buckets[bucket] += 1
        return [{"label": label, "value": value} for label, value in buckets.most_common()]

    def _timeline_snapshot(self, packets, sessions, flows):
        buckets = Counter()
        for row in packets:
            created = str(row.get("created_at") or "")[:10]
            if created:
                buckets[created] += 1
        if not buckets:
            for row in sessions:
                created = str(row.get("created_at") or "")[:10]
                if created:
                    buckets[created] += 1
        if not buckets:
            for row in flows:
                created = str(row.get("created_at") or "")[:10]
                if created:
                    buckets[created] += 1
        return [{"label": label, "value": value} for label, value in sorted(buckets.items())][-30:]

    def map_snapshot(self, limit=500) -> dict:
        packets = self.list_packets(limit=limit)
        # Resolved once per snapshot rather than per host: it is a config read
        # and this loop runs over every address in the window.
        declared_location = self.get_declared_location()
        hosts = {}
        public_points = []
        private_hosts = []
        seen = set()
        for row in packets:
            for ip_key in ("src_ip", "dst_ip"):
                ip = str(row.get(ip_key) or "").strip()
                if not ip or ip in seen:
                    continue
                seen.add(ip)
                node = self._host_node(ip, declared_location)
                hosts[ip] = node
                if node["private"]:
                    private_hosts.append(node)
                else:
                    public_points.append(node)
        links = []
        for row in packets:
            src = str(row.get("src_ip") or "").strip()
            dst = str(row.get("dst_ip") or "").strip()
            if not src or not dst:
                continue
            links.append(
                {
                    "source": src,
                    "target": dst,
                    "proto": row.get("proto"),
                    "value": max(1, safe_int(row.get("length", 0), 0)),
                }
            )
        # Per-country rollup of the same window the points are drawn from.
        # Built here rather than in SQL because the country of an address comes
        # from the bundled IP registry, which SQLite knows nothing about - and
        # built from the packets rather than from the hosts so that a country
        # with one very busy address does not read the same as one with a dozen
        # idle ones.
        countries: dict[str, dict] = {}
        for row in packets:
            length = safe_int(row.get("length", 0), 0)
            proto = normalize_protocol_name(row.get("proto"))
            for ip_key in ("src_ip", "dst_ip"):
                node = hosts.get(str(row.get(ip_key) or "").strip())
                # Private addresses have no country of their own; counting them
                # under the declared site would inflate it with local chatter.
                if node is None or node.get("private") or not node.get("country_code"):
                    continue
                code = node["country_code"]
                entry = countries.get(code)
                if entry is None:
                    entry = countries[code] = {
                        "country_code": code,
                        "country": node.get("country") or code,
                        "registry": node.get("registry") or "",
                        "lat": node.get("lat"),
                        "lon": node.get("lon"),
                        "hosts": set(),
                        "protocols": {},
                        "packets": 0,
                        "bytes": 0,
                    }
                entry["hosts"].add(node["ip"])
                entry["packets"] += 1
                entry["bytes"] += length
                entry["protocols"][proto] = entry["protocols"].get(proto, 0) + 1
        country_stats = sorted(
            (
                {
                    **{key: value for key, value in entry.items() if key not in ("hosts", "protocols")},
                    "hosts": len(entry["hosts"]),
                    "addresses": sorted(entry["hosts"])[:25],
                    "protocols": [
                        {"proto": name, "packets": count}
                        for name, count in sorted(
                            entry["protocols"].items(), key=lambda item: (-item[1], item[0])
                        )[:8]
                    ],
                }
                for entry in countries.values()
            ),
            key=lambda item: (-item["packets"], item["country_code"]),
        )

        summary = {
            "total_hosts": len(hosts),
            "public_hosts": len([item for item in hosts.values() if not item["private"]]),
            "private_hosts": len([item for item in hosts.values() if item["private"]]),
            "unmapped_public_hosts": len(
                [
                    item
                    for item in hosts.values()
                    if not item["private"] and (item.get("lat") is None or item.get("lon") is None)
                ]
            ),
            "total_ports": self.list_count("packets"),
            "total_open_ports": self._count_where("packets", "state = 'open'"),
        }
        resolved_public_hosts = len(
            [
                item
                for item in public_points
                if item.get("lat") is not None and item.get("lon") is not None
            ]
        )
        geoip_source = self._geoip_resolver.describe_source()
        return {
            "generated_at": utc_now(),
            # The arc origin is this sensor. Once a site location is declared
            # the map can anchor the arcs on it instead of an off-canvas point.
            "origin": {
                "ip": "127.0.0.1",
                "label": declared_location.get("label") or "Sniff origin",
                "lat": declared_location.get("lat"),
                "lon": declared_location.get("lon"),
                "declared": bool(declared_location.get("configured")),
            },
            "declared_location": declared_location,
            # What each country accounts for in this window, so the map can
            # answer "who is this and what have they been doing" on selection
            # instead of only plotting a dot.
            "countries": country_stats,
            "summary": summary,
            "public_points": public_points,
            "private_hosts": private_hosts,
            "private_bucket": {"count": len(private_hosts)},
            "geoip": {
                "source": geoip_source,
                "rows": resolved_public_hosts,
                "resolved_public_hosts": resolved_public_hosts,
                "total_public_hosts": len(public_points),
                "generated_at": utc_now(),
                "partial": resolved_public_hosts < len(public_points),
                "precision": "country" if geoip_source.startswith("country-db") else "",
            },
            "links": links,
        }

    def _host_node(self, ip: str, declared_location: dict | None = None) -> dict:
        scope = _ip_scope(ip)
        private = scope != "public"
        geo = self._geoip_resolver.lookup(ip) if not private else {}
        lat = safe_float(geo.get("lat"), None) if geo.get("lat") is not None else None
        lon = safe_float(geo.get("lon"), None) if geo.get("lon") is not None else None
        precision = str(geo.get("precision") or "").strip()
        if private:
            # A private or loopback address has no registry entry to geolocate,
            # so it lands on the operator-declared site location - that is
            # where the machine actually is. Without one it stays unplotted.
            site = declared_location if declared_location is not None else self.get_declared_location()
            if site.get("configured"):
                lat = site.get("lat")
                lon = site.get("lon")
                precision = "declared"
        return {
            "id": ip,
            "ip": ip,
            "label": ip,
            "private": private,
            "scope": scope,
            "lat": lat,
            "lon": lon,
            "country_code": str(geo.get("country_code") or "").upper(),
            "country": str(geo.get("country") or "").strip(),
            "registry": str(geo.get("registry") or "").strip(),
            "region": str(geo.get("region") or "").strip(),
            "geo_precision": precision,
        }

    def endpoint_catalog(self, routes: list[dict]) -> list[dict]:
        return [
            {
                "method": str(route.get("method") or "GET"),
                "path": str(route.get("path") or "/"),
                "desc": str(route.get("desc") or ""),
            }
            for route in routes
        ]

    def domains_for_ip(self, ip: str) -> dict:
        """Domains this store has actually associated with `ip`, from the
        `domains` catalog (DNS answers / mDNS / TLS SNI / HTTP Host) and
        from `packets.domain` on traffic to or from the address.

        Replaces a handler that returned a hardcoded empty list regardless
        of what was in the database - which reads to an analyst as "this IP
        has no known names", a false negative that is worse than no
        endpoint at all."""
        ip = str(ip or "").strip()
        if not ip:
            raise ValueError("ip is required")
        rows = self._fetchall(
            "SELECT name, source, port, proto, hit_count, first_seen, last_seen FROM domains WHERE ip = ? ORDER BY last_seen DESC",
            (ip,),
        )
        known = {str(row.get("name") or "").lower() for row in rows}
        observed = self._fetchall(
            """
            SELECT domain AS name, domain_source AS source, COUNT(*) AS hit_count,
                   MIN(created_at) AS first_seen, MAX(created_at) AS last_seen
            FROM packets
            WHERE domain != '' AND (src_ip = ? OR dst_ip = ?)
            GROUP BY domain, domain_source
            ORDER BY last_seen DESC
            """,
            (ip, ip),
        )
        for row in observed:
            name = str(row.get("name") or "").lower()
            if name and name not in known:
                known.add(name)
                rows.append({**row, "port": 0, "proto": ""})
        sources = Counter(str(row.get("source") or "unknown") for row in rows)
        return {
            "ip": ip,
            "domains": rows,
            "sources": dict(sources),
            "observed": bool(rows),
            "generated_at": utc_now(),
        }

    def ttl_path_for_ip(self, ip: str) -> dict:
        """Hop-count estimate derived from the TTL/hop-limit values actually
        observed on packets *sourced* by `ip`, instead of the constant 64
        the endpoint used to return for every address on the internet.

        The estimate is the classic one: pick the smallest common initial
        TTL (64/128/255) at or above what was seen, and call the difference
        the hop count. `observed: false` (with no estimate at all) when
        there is nothing to base it on - an honest "unknown" beats a
        fabricated number an analyst might act on."""
        ip = str(ip or "").strip()
        if not ip:
            raise ValueError("ip is required")
        rows = self._fetchall(
            """
            SELECT MAX(ttl, hop_limit) AS observed_ttl, COUNT(*) AS packets
            FROM packets
            WHERE src_ip = ? AND (ttl > 0 OR hop_limit > 0)
            GROUP BY observed_ttl
            ORDER BY packets DESC
            """,
            (ip,),
        )
        hops = []
        for row in rows:
            observed_ttl = safe_int(row.get("observed_ttl"), 0)
            if observed_ttl <= 0:
                continue
            initial = next((candidate for candidate in (64, 128, 255) if candidate >= observed_ttl), 255)
            hops.append(
                {
                    "observed_ttl": observed_ttl,
                    "initial_ttl_guess": initial,
                    "hop_count": max(0, initial - observed_ttl),
                    "packets": safe_int(row.get("packets"), 0),
                }
            )
        return {
            "ip": ip,
            "observed": bool(hops),
            "estimated_ttl": hops[0]["observed_ttl"] if hops else None,
            "estimated_hops": hops[0]["hop_count"] if hops else None,
            "hops": hops,
            "generated_at": utc_now(),
        }

    def ip_intel(self, ip: str) -> dict:
        ip = str(ip or "").strip()
        if not ip:
            raise ValueError("ip is required")
        related_packets = self.list_packets(search=ip, limit=250)
        related_flows = self.list_flows(search=ip, limit=100)
        related_payloads = [
            payload for payload in self.list_payloads(limit=250)
            if payload.get("ip") == ip or ip in str(payload.get("flow_key") or "")
        ]
        related_tags = [
            tag for tag in self.list_tags(limit=400)
            if tag.get("ip") == ip or ip in str(tag.get("flow_key") or "")
        ]
        services = []
        for row in related_packets:
            tags = json_loads(row.get("tags_json"), default=[]) or []
            tags_text = ", ".join(
                str(tag.get("value") or tag.get("key") or "").strip()
                for tag in tags
                if isinstance(tag, dict) and (tag.get("value") or tag.get("key"))
            )
            if not tags_text:
                tags_text = ", ".join(
                    str(tag).strip()
                    for tag in tags
                    if str(tag).strip()
                )
            services.append(
                {
                    "ip": row.get("dst_ip") or row.get("src_ip") or ip,
                    "port": safe_int(row.get("dst_port") or row.get("src_port"), 0),
                    "proto": row.get("proto") or "unknown",
                    "state": row.get("state") or "open",
                    "banner": row.get("banner_text") or row.get("summary") or "",
                    "tags_text": tags_text,
                }
            )
        transport = {
            "services": unique_ordered_dicts(services, key_fields=("ip", "port", "proto")),
            "banners": related_payloads,
            "tags": related_tags,
            "flows": related_flows,
        }
        # "Observed"/"low_filtering" used to be returned even for a host the
        # database had never seen a single packet from - a defensive verdict
        # with zero evidence behind it. Say "insufficient_data" and show the
        # counts the (weak) inference is actually based on instead.
        firewall = {
            "summary": "observed" if related_packets else "not observed",
            "status": "mixed_filtering" if related_packets else "insufficient_data",
            "evidence": {"packets": len(related_packets), "flows": len(related_flows)},
        }
        host_node = self._host_node(ip)
        geo = {
            "found": bool(host_node.get("country_code")),
            "area": host_node.get("country") or "",
            "country": host_node.get("country") or "",
            "country_code": host_node.get("country_code") or "",
            "lat": host_node.get("lat"),
            "lon": host_node.get("lon"),
            "precision": host_node.get("geo_precision") or "",
        }
        return {
            "ip": ip,
            "summary": {
                "packets": len(related_packets),
                "flows": len(related_flows),
                "payloads": len(related_payloads),
                "tags": len(related_tags),
            },
            "host": {
                "transport": transport,
                "firewall": firewall,
                "geo": geo,
            },
            "domains": self.domains_for_ip(ip),
            "ttl_path": self.ttl_path_for_ip(ip),
            "intel": {
                "services": transport["services"],
                "payloads": related_payloads,
                "tags": related_tags,
            },
        }

    def register_packet(self, packet: dict) -> dict:
        now = utc_now()
        rule_hits = packet.get("rule_hits") if isinstance(packet.get("rule_hits"), list) else []
        tags = packet.get("tags") if isinstance(packet.get("tags"), list) else []
        payload_text = normalize_text(packet.get("payload_text") or "", limit=PAYLOAD_TEXT_MAX_CHARS)
        summary_text = normalize_text(packet.get("summary") or "", limit=PAYLOAD_TEXT_MAX_CHARS)
        banner_text = normalize_text(packet.get("banner_text") or payload_text, limit=PAYLOAD_TEXT_MAX_CHARS)
        payload_hex = str(packet.get("payload_hex") or "")
        length = safe_int(packet.get("length", 0), 0)
        payload_len = safe_int(packet.get("payload_len", 0), 0)
        state = str(packet.get("state") or ("open" if payload_len else "filtered")).strip().lower() or "open"
        scan_state = str(packet.get("scan_state") or "active").strip().lower() or "active"
        flow_key = str(packet.get("flow_key") or stable_flow_key(
            packet.get("proto", "unknown"),
            packet.get("src_ip", ""),
            packet.get("src_port", 0),
            packet.get("dst_ip", ""),
            packet.get("dst_port", 0),
        )).strip()
        packet_row = (
            flow_key,
            str(packet.get("interface") or "").strip(),
            str(packet.get("direction") or "unknown").strip(),
            str(packet.get("eth_src") or "").strip(),
            str(packet.get("eth_dst") or "").strip(),
            safe_int(packet.get("eth_type", 0), 0),
            safe_int(packet.get("ip_version", 0), 0),
            str(packet.get("src_ip") or "").strip(),
            str(packet.get("dst_ip") or "").strip(),
            normalize_protocol_name(packet.get("proto")),
            str(packet.get("transport") or "").strip().lower(),
            safe_int(packet.get("src_port", 0), 0),
            safe_int(packet.get("dst_port", 0), 0),
            safe_int(packet.get("ttl", 0), 0),
            safe_int(packet.get("hop_limit", 0), 0),
            length,
            payload_len,
            state,
            scan_state,
            str(packet.get("tcp_flags") or "").strip(),
            safe_int(packet.get("icmp_type", 0), 0),
            safe_int(packet.get("icmp_code", 0), 0),
            safe_int(packet.get("arp_opcode", 0), 0),
            summary_text,
            payload_text,
            payload_hex,
            banner_text,
            str(packet.get("domain") or "").strip().lower(),
            str(packet.get("domain_source") or "").strip(),
            str(packet.get("http_method") or "").strip().upper(),
            str(packet.get("http_path") or "").strip(),
            str(packet.get("http_host") or "").strip().lower(),
            json_dumps(extract_details(packet)),
            json_dumps(tags),
            json_dumps(rule_hits),
            packet.get("raw_packet"),
            now,
            now,
        )
        with self._lock:
            try:
                return self._write_packet_rows(packet, packet_row, flow_key, tags, rule_hits, banner_text, length, payload_len, now)
            except sqlite3.Error as exc:
                if not any(token in str(exc).lower() for token in self._RECOVERABLE_ERRORS):
                    raise
                # The whole insert is retried, not just the failing statement:
                # a packet row, its flow, tags and payload have to land
                # together or not at all.
                self._recover_connection()
                return self._write_packet_rows(packet, packet_row, flow_key, tags, rule_hits, banner_text, length, payload_len, now)

    def _write_packet_rows(self, packet, packet_row, flow_key, tags, rule_hits, banner_text, length, payload_len, now):
        """The write half of register_packet, so it can be retried whole.

        Caller holds self._lock.
        """
        session_id = self._ensure_session(safe_int(packet.get("session_id", 0), 0))
        cursor = self._conn.execute(
            """
            INSERT INTO packets
            (session_id, flow_key, interface, direction, eth_src, eth_dst, eth_type, ip_version,
             src_ip, dst_ip, proto, transport, src_port, dst_port, ttl, hop_limit, length, payload_len,
             state, scan_state, tcp_flags, icmp_type, icmp_code, arp_opcode, summary,
             payload_text, payload_hex, banner_text, domain, domain_source, http_method,
             http_path, http_host, details_json, tags_json, rule_hits_json, raw_packet,
             created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (session_id, *packet_row),
        )
        packet_id = cursor.lastrowid
        self._upsert_flow(packet_id, session_id, flow_key, packet, tags, banner_text, now)
        self._insert_tag_rows(packet_id, flow_key, packet, tags, now)
        self._insert_payload_row(packet_id, flow_key, packet, banner_text, now)
        self.bump_session_counters(session_id, length or payload_len, len(rule_hits))
        self._conn.commit()

        return self.get_packet(packet_id)

    def _upsert_flow(self, packet_id: int, session_id: int, flow_key: str, packet: dict, tags: list, banner_text: str, now: str):
        values = (
            flow_key,
            normalize_protocol_name(packet.get("proto")),
            str(packet.get("src_ip") or "").strip(),
            str(packet.get("dst_ip") or "").strip(),
            safe_int(packet.get("src_port", 0), 0),
            safe_int(packet.get("dst_port", 0), 0),
            safe_int(packet.get("length", 0), 0),
            str(packet.get("state") or "open").strip().lower() or "open",
            str(packet.get("scan_state") or "active").strip().lower() or "active",
            banner_text,
            json_dumps([tag.get("key") for tag in tags if isinstance(tag, dict)]),
            now,
            now,
            now,
            now,
        )
        self._conn.execute(
            """
            INSERT INTO flows
            (flow_key, proto, src_ip, dst_ip, src_port, dst_port, packet_count, byte_count,
             state, scan_state, banner_text, tags_json, first_seen, last_seen, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(flow_key) DO UPDATE SET
              packet_count = packet_count + 1,
              byte_count = byte_count + excluded.byte_count,
              state = excluded.state,
              scan_state = excluded.scan_state,
              banner_text = CASE
                WHEN excluded.banner_text != '' THEN excluded.banner_text
                ELSE banner_text
              END,
              tags_json = excluded.tags_json,
              last_seen = excluded.last_seen,
              updated_at = excluded.updated_at
            """,
            values,
        )

    def _insert_tag_rows(self, packet_id: int, flow_key: str, packet: dict, tags: list, now: str):
        if not tags:
            return
        for tag in tags:
            if not isinstance(tag, dict):
                continue
            key = str(tag.get("key") or tag.get("tag") or "").strip()
            value = str(tag.get("value") or tag.get("label") or "").strip()
            severity = str(tag.get("severity") or "").strip().lower()
            if not key:
                continue
            self._conn.execute(
                """
                INSERT INTO tags
                (packet_id, flow_key, ip, port, proto, key, value, severity, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    packet_id,
                    flow_key,
                    str(packet.get("dst_ip") or packet.get("src_ip") or "").strip(),
                    safe_int(packet.get("dst_port") or packet.get("src_port") or 0, 0),
                    normalize_protocol_name(packet.get("proto")),
                    key,
                    value,
                    severity,
                    now,
                    now,
                ),
            )

    def _insert_payload_row(self, packet_id: int, flow_key: str, packet: dict, banner_text: str, now: str):
        payload_text = str(packet.get("payload_text") or "").strip()
        if not payload_text and not banner_text:
            return
        response_plain = banner_text or payload_text
        response_size = len(response_plain.encode("utf-8", errors="ignore"))
        self._conn.execute(
            """
            INSERT INTO payloads
            (packet_id, flow_key, ip, port, proto, response_plain, response_size, scan_state, port_id, favicon_id, state, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                packet_id,
                flow_key,
                str(packet.get("dst_ip") or packet.get("src_ip") or "").strip(),
                safe_int(packet.get("dst_port") or packet.get("src_port") or 0, 0),
                normalize_protocol_name(packet.get("proto")),
                response_plain,
                response_size,
                str(packet.get("scan_state") or "active").strip().lower() or "active",
                packet_id,
                packet_id,
                str(packet.get("state") or "open").strip().lower() or "open",
                now,
                now,
            ),
        )

    def get_packet(self, packet_id: int):
        return self._fetchone("SELECT * FROM packets WHERE id = ?", (packet_id,))

    def get_flow(self, flow_key: str):
        return self._fetchone("SELECT * FROM flows WHERE flow_key = ?", (flow_key,))

    def get_payload(self, payload_id: int):
        return self._fetchone("SELECT * FROM payloads WHERE id = ?", (payload_id,))

    def get_tag(self, tag_id: int):
        return self._fetchone("SELECT * FROM tags WHERE id = ?", (tag_id,))

    def packet_detail_with_tags(self, packet_id: int):
        packet = self.get_packet(packet_id)
        if not packet:
            return None
        packet["tags"] = self._fetchall("SELECT * FROM tags WHERE packet_id = ? ORDER BY id ASC", (packet_id,))
        packet["payload"] = self._fetchone("SELECT * FROM payloads WHERE packet_id = ? ORDER BY id DESC LIMIT 1", (packet_id,))
        return packet

    def trim_oversized_tables(self, *, force: bool = False):
        """Called opportunistically from the capture thread. Self-throttles
        to settings.RETENTION_INTERVAL_SECONDS so the DELETEs don't run
        every few packets; pass force=True to bypass the throttle (tests,
        and any caller that just did a bulk insert)."""
        now = time.monotonic()
        if not force:
            with self._lock:
                if now - self._last_retention_at < RETENTION_INTERVAL_SECONDS:
                    return {"skipped": True}
                self._last_retention_at = now
        else:
            with self._lock:
                self._last_retention_at = now
        return self.enforce_retention()

    def enforce_retention(self) -> dict:
        """Temporal retention with a row-count backstop.

        1. Delete packets older than RETENTION_DAYS, *except* those
           carrying a high/critical monitor tag, which get
           RETENTION_ALERT_DAYS instead. A pure FIFO-by-id trim (the old
           policy) evicted exactly backwards: high-volume info/low rows
           pushed out the handful of rows worth investigating.
        2. Cascade the delete to the tags/payloads that hang off those
           packets, then age out the standalone catalogs.
        3. Only then apply the row cap, and even there prefer unflagged
           rows first.
        """
        result = {"packets": 0, "tags": 0, "payloads": 0, "flows": 0, "sessions": 0}
        if RETENTION_DAYS > 0:
            cutoff = utc_since(RETENTION_DAYS * 86400)
            alert_cutoff = utc_since(max(RETENTION_DAYS, RETENTION_ALERT_DAYS) * 86400)
            with self._lock:
                deleted = self._conn.execute(
                    """
                    DELETE FROM packets
                    WHERE created_at < ?
                      AND (
                        created_at < ?
                        OR id NOT IN (
                            SELECT packet_id FROM tags
                            WHERE severity IN ('high', 'critical')
                        )
                      )
                    """,
                    (cutoff, alert_cutoff),
                ).rowcount
                result["packets"] += max(0, deleted)
                result["flows"] += max(0, self._conn.execute("DELETE FROM flows WHERE last_seen < ?", (cutoff,)).rowcount)
                self._conn.commit()

        with self._lock:
            result["tags"] += max(
                0, self._conn.execute("DELETE FROM tags WHERE packet_id NOT IN (SELECT id FROM packets)").rowcount
            )
            result["payloads"] += max(
                0, self._conn.execute("DELETE FROM payloads WHERE packet_id NOT IN (SELECT id FROM packets)").rowcount
            )
            self._conn.commit()

        result["packets"] += self._trim_table("packets", PACKET_TABLE_LIMIT)
        result["payloads"] += self._trim_table("payloads", PAYLOAD_TABLE_LIMIT)
        result["flows"] += self._trim_table("flows", FLOW_TABLE_LIMIT)
        result["tags"] += self._trim_table("tags", TAG_TABLE_LIMIT)
        result["sessions"] += self._trim_table("sessions", SESSION_TABLE_LIMIT)
        self._trim_table("domains", DOMAIN_TABLE_LIMIT)
        self._trim_table("paths", PATH_TABLE_LIMIT)

        # Reclaim the freed pages instead of letting the file grow
        # monotonically (a live instance went 49.8 MB -> 91.9 MB in four
        # minutes while holding only 2000 packets). No-op on a database
        # created before auto_vacuum=INCREMENTAL was set.
        try:
            with self._lock:
                self._conn.execute("PRAGMA incremental_vacuum(256)")
                self._conn.commit()
        except sqlite3.Error:
            pass
        return result

    def _trim_table(self, table: str, limit: int) -> int:
        with self._lock:
            row = self._conn.execute(f"SELECT COUNT(*) AS count FROM {table}").fetchone()
            count = int(row["count"] or 0) if row else 0
            overflow = count - int(limit)
            if overflow <= 0:
                return 0
            deleted = self._conn.execute(
                f"DELETE FROM {table} WHERE id IN (SELECT id FROM {table} ORDER BY id ASC LIMIT ?)",
                (overflow,),
            ).rowcount
            self._conn.commit()
            return max(0, deleted)

    # Tables that only ever hold data produced by a capture/honeypot run.
    # Deliberately excludes `monitors`, `rulesets`, `honeypot_listeners`,
    # `blacklist_entries`, `whitelist_entries` and `runtime_config`: those are definitions and
    # configuration the operator authored, not captured traffic, and wiping
    # them would silently undo tuning work.
    CAPTURE_DATA_TABLES = ("tags", "payloads", "packets", "flows", "domains", "paths", "sessions")

    def get_declared_location(self) -> dict:
        """Where this sensor sits, as declared by the operator.

        Private and loopback addresses cannot be geolocated - there is no
        public registry entry to look up - so the map needs somewhere to put
        them. Returns lat/lon of None when nothing has been declared, and the
        map then leaves local hosts off the world view as before.
        """
        raw_lat = self.get_runtime_config("declared_latitude", "" if DECLARED_LATITUDE is None else str(DECLARED_LATITUDE))
        raw_lon = self.get_runtime_config("declared_longitude", "" if DECLARED_LONGITUDE is None else str(DECLARED_LONGITUDE))
        label = self.get_runtime_config("declared_location_label", DECLARED_LOCATION_LABEL)
        lat = safe_float(raw_lat, None) if str(raw_lat or "").strip() else None
        lon = safe_float(raw_lon, None) if str(raw_lon or "").strip() else None
        if lat is None or lon is None or not (-90.0 <= lat <= 90.0) or not (-180.0 <= lon <= 180.0):
            lat = lon = None
        return {
            "lat": lat,
            "lon": lon,
            "label": str(label or "").strip(),
            "configured": lat is not None and lon is not None,
        }

    def set_declared_location(self, lat, lon, label: str = "") -> dict:
        """Store the sensor's location. Passing None for both coordinates
        clears it."""
        if lat is None and lon is None:
            self.set_runtime_config("declared_latitude", "")
            self.set_runtime_config("declared_longitude", "")
            self.set_runtime_config("declared_location_label", str(label or "").strip())
            return self.get_declared_location()
        parsed_lat = safe_float(lat, None)
        parsed_lon = safe_float(lon, None)
        if parsed_lat is None or parsed_lon is None:
            raise ValueError("lat and lon must both be numbers, or both omitted to clear")
        if not -90.0 <= parsed_lat <= 90.0:
            raise ValueError("lat must be between -90 and 90")
        if not -180.0 <= parsed_lon <= 180.0:
            raise ValueError("lon must be between -180 and 180")
        self.set_runtime_config("declared_latitude", f"{parsed_lat:.6f}")
        self.set_runtime_config("declared_longitude", f"{parsed_lon:.6f}")
        self.set_runtime_config("declared_location_label", str(label or "").strip()[:120])
        return self.get_declared_location()

    def purge_capture_data(self, *, progress=None) -> dict:
        """Delete every row produced by capture and honeypot activity.

        Broader than `clear_detections`, which only removes per-packet
        detection history and deliberately leaves the running catalogs
        (flows, domains, paths, sessions) alone so an active session's
        counters stay consistent. This is the "start from an empty database"
        button, so it takes those too.

        `progress`, if given, is called with a single status dict after each
        table is cleared and periodically while compacting - the two
        stretches an operator watching the "Clear data" dialog actually
        waits through on a database that's grown large. It is best-effort
        (any exception from it is swallowed) and never affects what gets
        deleted.
        """

        def _report(**status):
            if progress is not None:
                try:
                    progress(status)
                except Exception:
                    pass

        deleted: dict[str, int] = {}
        with self._lock:
            totals: dict[str, int] = {}
            for table in self.CAPTURE_DATA_TABLES:
                try:
                    row = self._conn.execute(f"SELECT COUNT(*) AS c FROM {table}").fetchone()
                    totals[table] = int(row["c"] or 0) if row else 0
                except sqlite3.Error:
                    totals[table] = 0
            rows_total = sum(totals.values())
            rows_done = 0
            _report(phase="deleting", table=None, rows_done=0, rows_total=rows_total)
            for table in self.CAPTURE_DATA_TABLES:
                try:
                    cursor = self._conn.execute(f"DELETE FROM {table}")
                    deleted[table] = int(cursor.rowcount or 0)
                except sqlite3.Error:
                    # A table missing on an older schema must not abort the
                    # rest of the purge.
                    deleted[table] = 0
                rows_done += deleted[table]
                _report(phase="deleting", table=table, rows_done=rows_done, rows_total=rows_total)
            try:
                self._conn.execute("DELETE FROM sqlite_sequence")
            except sqlite3.Error:
                pass
            self._conn.commit()
            # Reclaim the file. Deliberately NOT a full VACUUM: that rewrites
            # the whole database, and this store is shared with the privileged
            # capture child, which was observed unable to write a single packet
            # for twenty minutes afterwards while the database itself was free.
            # The schema sets auto_vacuum=INCREMENTAL, so the free pages can be
            # given back without rebuilding the file, and truncating the WAL
            # returns the rest. Reclaiming in bounded chunks (rather than one
            # unbounded PRAGMA incremental_vacuum call) is what makes a
            # "compacting" progress step possible - it also keeps any single
            # call from holding the write lock for the whole freelist at
            # once, on a database that can be tens of thousands of pages
            # after a large purge.
            try:
                free_row = self._conn.execute("PRAGMA freelist_count").fetchone()
                pages_total = int(free_row[0] or 0) if free_row else 0
            except sqlite3.Error:
                pages_total = 0
            if pages_total:
                _report(phase="compacting", pages_done=0, pages_total=pages_total)
                remaining = pages_total
                # PRAGMA incremental_vacuum(N)'s "up to N pages" is what the
                # docs promise, but it was observed reclaiming only ONE page
                # per call - regardless of N, and even with no N at all - on
                # at least one SQLite build. A fixed iteration count can't
                # cover both that case and the normal one (where a single
                # call reclaims everything), so this is time-boxed instead:
                # keep taking bites while it's actually making progress and
                # there's time left in the budget, then make exactly one
                # more unbounded call for whatever remains and stop - on a
                # build where N is honored that call is a fast no-op (the
                # loop already finished); on one where it isn't, the file
                # is left slightly larger than optimal rather than the
                # purge hanging for a long, unbounded stretch reclaiming it
                # one page at a time.
                deadline = time.monotonic() + 2.0
                last_reported_at = time.monotonic()
                while remaining > 0 and time.monotonic() < deadline:
                    try:
                        self._conn.execute("PRAGMA incremental_vacuum(2000)")
                        self._conn.commit()
                        next_row = self._conn.execute("PRAGMA freelist_count").fetchone()
                        next_remaining = int(next_row[0] or 0) if next_row else 0
                    except sqlite3.Error:
                        remaining = 0
                        break
                    if next_remaining >= remaining:
                        # No progress this round - stop instead of looping
                        # forever (e.g. auto_vacuum isn't INCREMENTAL on an
                        # older database, so the PRAGMA is a silent no-op).
                        break
                    remaining = next_remaining
                    # Throttled: on a build where each call only frees one
                    # page, this loop can run thousands of times - a
                    # broadcast (a WS send to every connected client) per
                    # page would spam the dashboard far more than it would
                    # inform it.
                    now = time.monotonic()
                    if now - last_reported_at >= 0.15:
                        last_reported_at = now
                        _report(phase="compacting", pages_done=pages_total - remaining, pages_total=pages_total)
                if remaining > 0:
                    try:
                        self._conn.execute("PRAGMA incremental_vacuum")
                        self._conn.commit()
                        final_row = self._conn.execute("PRAGMA freelist_count").fetchone()
                        remaining = int(final_row[0] or 0) if final_row else remaining
                    except sqlite3.Error:
                        pass
                # Unconditional and unthrottled: the last in-loop report may
                # have been skipped by the throttle above, so this is what
                # guarantees the dialog actually reaches 100% instead of
                # stalling a few points short of it.
                _report(phase="compacting", pages_done=max(0, pages_total - remaining), pages_total=pages_total)
            try:
                self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            except sqlite3.Error:
                pass
            _report(phase="done", rows_done=rows_done, rows_total=rows_total)
        return deleted

    def clear_detections(self, scope: str = "all") -> dict:
        """Deletes stored packets/tags/payloads - the underlying data behind
        the Monitors and inbound-service "hits" tables - so an operator can clear
        out noise (e.g. right after tuning/disabling noisy monitors) without
        touching the monitor/listener *definitions* themselves, which live
        in a separate table this never runs a DELETE against.

        Scoped by `packets.interface`: listener traffic is recorded under
        the current "service:" prefix, while older rows may still use the
        legacy "honeypot:" prefix. Everything else is sniffer-side traffic.
        'all' clears both. Never touches `sessions`, `flows`,
        `domains`, or `paths` - those are running counters/catalogs, not
        per-packet detection history, and clearing them out from under an
        active capture session would desync its own live counters.
        """
        scope = str(scope or "all").strip().lower()
        if scope not in {"all", "honeypot", "sniffer"}:
            raise ValueError(f"Unknown scope: {scope!r} (expected 'all', 'honeypot', or 'sniffer')")

        if scope == "all":
            packet_filter = ""
            params: tuple = ()
        elif scope == "honeypot":
            packet_filter = "WHERE interface LIKE ? OR interface = ? OR interface LIKE ? OR interface = ?"
            params = ("honeypot%", "honeypot", "service:%", "service")
        else:
            packet_filter = "WHERE interface NOT LIKE ? AND interface != ? AND interface NOT LIKE ? AND interface != ?"
            params = ("honeypot%", "honeypot", "service:%", "service")

        with self._lock:
            tags_deleted = self._conn.execute(
                f"DELETE FROM tags WHERE packet_id IN (SELECT id FROM packets {packet_filter})", params
            ).rowcount
            payloads_deleted = self._conn.execute(
                f"DELETE FROM payloads WHERE packet_id IN (SELECT id FROM packets {packet_filter})", params
            ).rowcount
            packets_deleted = self._conn.execute(f"DELETE FROM packets {packet_filter}", params).rowcount
            self._conn.commit()

        return {
            "scope": scope,
            "packets": max(0, packets_deleted),
            "tags": max(0, tags_deleted),
            "payloads": max(0, payloads_deleted),
        }

    def read_catalog_file(self, filename: str) -> list[dict]:
        path = resolve_data_file(filename)
        if not path.exists():
            return []
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return []
        if not isinstance(payload, list):
            return []
        return [item for item in payload if isinstance(item, dict)]

    def write_catalog_file(self, filename: str, rows: list[dict]):
        path = resolve_data_file(filename)
        path.write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")

    def get_runtime_config(self, key: str, default: str = "") -> str:
        row = self._fetchone("SELECT value FROM runtime_config WHERE key = ?", (str(key),))
        if not row:
            return str(default)
        value = row.get("value")
        return str(value if value is not None else default)

    def set_runtime_config(self, key: str, value: str):
        now = utc_now()
        self._execute(
            """
            INSERT INTO runtime_config (key, value, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET
              value = excluded.value,
              updated_at = excluded.updated_at
            """,
            (str(key), str(value), now),
            commit=True,
        )
        return str(value)

    def upsert_catalog_file_row(self, filename: str, row: dict):
        rows = self.read_catalog_file(filename)
        item = dict(row or {})
        item_id = str(item.get("id") or item.get("name") or "").strip()
        if not item_id:
            item_id = f"{filename.rsplit('.', 1)[0]}-{len(rows) + 1}"
            item["id"] = item_id
        found = False
        for index, existing in enumerate(rows):
            existing_id = str(existing.get("id") or existing.get("name") or "").strip()
            if existing_id == item_id:
                rows[index] = item
                found = True
                break
        if not found:
            rows.append(item)
        self.write_catalog_file(filename, rows)
        return item

    def delete_catalog_file_row(self, filename: str, item_id: str):
        rows = self.read_catalog_file(filename)
        filtered = [
            item for item in rows
            if str(item.get("id") or item.get("name") or "").strip() != str(item_id).strip()
        ]
        self.write_catalog_file(filename, filtered)
        return True


def unique_ordered_dicts(rows: list[dict], *, key_fields: tuple[str, ...]):
    seen = set()
    result = []
    for row in rows:
        key = tuple(str(row.get(field) or "").strip() for field in key_fields)
        if key in seen:
            continue
        seen.add(key)
        result.append(row)
    return result
