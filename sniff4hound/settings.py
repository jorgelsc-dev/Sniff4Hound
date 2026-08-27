from __future__ import annotations

import os
import secrets
from os import getenv
from pathlib import Path


# The project was renamed from SniffHound to Sniff4Hound. Every setting is
# read through _env(), so honouring the old variable names here is all it
# takes for an existing install to keep working - there is no second place
# that reads os.environ directly.
LEGACY_ENV_PREFIX = "SNIFFHOUND_"
ENV_PREFIX = "SNIFF4HOUND_"


def _env(key: str, default: str = "") -> str:
    value = getenv(key)
    if value is not None:
        return value
    if key.startswith(ENV_PREFIX):
        legacy = getenv(LEGACY_ENV_PREFIX + key[len(ENV_PREFIX):])
        if legacy is not None:
            return legacy
    return default


def _as_int(value, default: int) -> int:
    try:
        return int(value)
    except Exception:
        return int(default)


def _as_float(value, default: float) -> float:
    try:
        return float(value)
    except Exception:
        return float(default)


def _as_bool(value, default: bool = False) -> bool:
    raw = str(value if value is not None else "").strip().lower()
    if not raw:
        return bool(default)
    return raw in {"1", "true", "yes", "on", "y"}


DEFAULT_PORT = 45678

HOST = str(_env("SNIFF4HOUND_HOST", _env("HOST", "127.0.0.1"))).strip() or "127.0.0.1"
PORT = _as_int(_env("SNIFF4HOUND_PORT", str(DEFAULT_PORT)), DEFAULT_PORT)


def default_data_dir() -> Path:
    """Per-user data directory, preferring the current name.

    An install that predates the SniffHound -> Sniff4Hound rename keeps its
    database where it already is: creating a fresh empty directory next to a
    populated one would silently look like all captured data had been lost.
    The old directory is only adopted when the new one does not exist yet.
    """
    xdg_data_home = str(_env("XDG_DATA_HOME", "")).strip()
    base = Path(xdg_data_home) if xdg_data_home else Path.home() / ".local" / "share"
    current = base / "sniff4hound"
    if current.exists():
        return current
    legacy = base / "sniffhound"
    if legacy.exists():
        return legacy
    return current


# Fixed per-user data directory (XDG-style) rather than the process cwd, so
# uninstall tooling (see scripts/build_deb.sh's postrm) has one known
# location to purge instead of guessing at whatever cwd sniff4hound was last
# run from.
DATA_DIR = Path(str(_env("SNIFF4HOUND_DATA_DIR", "")).strip() or default_data_dir())


def resolve_data_path(value: str, default_name: str) -> str:
    """Anchor a configured runtime path to DATA_DIR unless it is absolute.

    A *relative* SNIFF4HOUND_DB_PATH (the docs used to suggest a bare
    `Sniff4Hound.db`) resolved against the process cwd, so the same install
    grew a separate database in every directory it was ever launched from -
    that is how a 46 MB `Sniff4Hound.db` ended up sitting inside `frontend/`.
    Runtime state now always lands under DATA_DIR; an absolute path is still
    honoured verbatim for operators who really do want it elsewhere.
    """
    raw = str(value or "").strip()
    if not raw:
        return str(DATA_DIR / default_name)
    candidate = Path(raw).expanduser()
    if candidate.is_absolute():
        return str(candidate)
    return str(DATA_DIR / candidate)


DB_PATH = resolve_data_path(_env("SNIFF4HOUND_DB_PATH", ""), "Sniff4Hound.db")
DEBUG = _as_bool(_env("SNIFF4HOUND_DEBUG", "1"), default=True)
RUNTIME_MODE = str(_env("SNIFF4HOUND_RUNTIME_MODE", _env("SNIFF4HOUND_MODE", "sniffer"))).strip().lower() or "sniffer"

CAPTURE_AUTO_START = _as_bool(_env("SNIFF4HOUND_CAPTURE_AUTO_START", "0"), default=False)
CAPTURE_INTERFACES = tuple(
    item.strip()
    for item in str(_env("SNIFF4HOUND_CAPTURE_INTERFACES", "")).split(",")
    if item.strip()
)
CAPTURE_PROMISCUOUS = _as_bool(_env("SNIFF4HOUND_PROMISCUOUS", "1"), default=True)
CAPTURE_SNAPLEN = max(64, _as_int(_env("SNIFF4HOUND_SNAPLEN", "65535"), 65535))
CAPTURE_POLL_TIMEOUT = max(0.05, _as_float(_env("SNIFF4HOUND_POLL_TIMEOUT", "0.5"), 0.5))
CAPTURE_BUFFER_BYTES = max(65536, _as_int(_env("SNIFF4HOUND_CAPTURE_BUFFER_BYTES", "524288"), 524288))


def _as_port_set(value) -> frozenset[int]:
    ports = set()
    for item in str(value or "").split(","):
        item = item.strip()
        if item.isdigit():
            port = int(item)
            if 0 < port <= 65535:
                ports.add(port)
    return frozenset(ports)


# Sniff4Hound's own web listener is, on loopback, by far the loudest talker
# the capture threads can see: every WebSocket "packet" event the dashboard
# receives travels back over `lo` and gets captured, stored, evaluated
# against the whole monitor catalog and re-broadcast - a feedback loop that
# measured 95% of all stored rows on a live instance and evicted the real
# traffic out of the retention window. Frames to/from the sensor's own
# HTTP/WS port are dropped before they are ever counted or stored.
# CAPTURE_EXCLUDE_PORTS adds extra ports (comma-separated) on top of the
# web port; set SNIFF4HOUND_CAPTURE_EXCLUDE_SELF=0 to keep the self-traffic
# (only useful when debugging Sniff4Hound itself).
CAPTURE_EXCLUDE_SELF = _as_bool(_env("SNIFF4HOUND_CAPTURE_EXCLUDE_SELF", "1"), default=True)
CAPTURE_EXCLUDE_PORTS = _as_port_set(_env("SNIFF4HOUND_CAPTURE_EXCLUDE_PORTS", ""))

# nginx-style access logging for the web process (see access_log.py). On by
# default: without it the terminal only ever prints wsbuilder's
# "[http] handler error" line, so successful traffic - and every WebSocket
# handshake - was invisible. Set SNIFF4HOUND_ACCESS_LOG=0 to silence it.
# SNIFF4HOUND_ACCESS_LOG_COLOR: auto (colorize the status only on a TTY),
# always, or never.
# Detection scope filter: mute monitor/anomaly detection for traffic whose
# source *and* destination both fall in one of these buckets ("loopback",
# "private", "public"). Empty (the default) means detect on everything.
# Only detection is muted - the packet is still captured and stored, so the
# traffic stays visible in the capture views. Runtime-configurable from the
# Sniffer settings; this env var only supplies the initial value.
def _as_scope_set(value) -> frozenset[str]:
    from .utils import DETECTION_IP_SCOPES

    wanted = {
        item.strip().lower()
        for item in str(value or "").replace(";", ",").split(",")
        if item.strip()
    }
    return frozenset(wanted & set(DETECTION_IP_SCOPES))


# Declared site location: where this sensor physically sits. Private and
# loopback addresses have no geolocation of their own (there is nothing to
# look up), so the map plots them all at this point instead of dropping them.
# Initial value only - it is editable at runtime from Settings.
def _as_coord(value, low: float, high: float):
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = float(text)
    except (TypeError, ValueError):
        return None
    return parsed if low <= parsed <= high else None


DECLARED_LATITUDE = _as_coord(_env("SNIFF4HOUND_DECLARED_LATITUDE", ""), -90.0, 90.0)
DECLARED_LONGITUDE = _as_coord(_env("SNIFF4HOUND_DECLARED_LONGITUDE", ""), -180.0, 180.0)
DECLARED_LOCATION_LABEL = str(_env("SNIFF4HOUND_DECLARED_LOCATION_LABEL", "")).strip()

DETECTION_EXCLUDE_SCOPES = _as_scope_set(_env("SNIFF4HOUND_DETECTION_EXCLUDE_SCOPES", ""))

ACCESS_LOG_ENABLED = _as_bool(_env("SNIFF4HOUND_ACCESS_LOG", "1"), default=True)
ACCESS_LOG_COLOR = str(_env("SNIFF4HOUND_ACCESS_LOG_COLOR", "auto")).strip().lower() or "auto"
if ACCESS_LOG_COLOR not in ("auto", "always", "never"):
    ACCESS_LOG_COLOR = "auto"


# ---------------------------------------------------------------------------
# Authentication (see sniff4hound/auth.py)
# ---------------------------------------------------------------------------
# There is deliberately NO built-in default JWT signing secret. A literal
# baked into the source ships in every checkout and in the .deb, so anyone
# holding it can mint a token that `authenticate_request()` accepts on any
# installation that never set SNIFF4HOUND_JWT_SECRET - i.e. a complete auth
# bypass with no knowledge of the printed security code. When the env var is
# unset the secret is generated once per installation with
# `secrets.token_hex(32)` and persisted 0600 next to the database; if that
# file cannot be created (read-only data dir, exotic FS) the process falls
# back to an ephemeral in-memory secret, which is different on every start.
JWT_SECRET_FILE = str(_env("SNIFF4HOUND_JWT_SECRET_FILE", "")).strip() or str(DATA_DIR / "jwt_secret")
JWT_TTL_SECONDS = max(60, _as_int(_env("SNIFF4HOUND_JWT_TTL", "3600"), 3600))
# Hard ceiling for a caller-supplied `expires_in`: an integration asking for
# a ten-year token would otherwise get one, and these tokens have no
# server-side session to revoke them against.
JWT_MAX_TTL_SECONDS = max(60, _as_int(_env("SNIFF4HOUND_JWT_MAX_TTL", "86400"), 86400))

# Rate limiting / lockout for failed API + WebSocket authentication
# (see auth.AuthRateLimiter). Sliding window per source IP with an
# incremental backoff, so a stolen-code guessing loop stops being free.
AUTH_RATE_LIMIT_ENABLED = _as_bool(_env("SNIFF4HOUND_AUTH_RATE_LIMIT", "1"), default=True)
AUTH_FAILURE_WINDOW_SECONDS = max(1, _as_int(_env("SNIFF4HOUND_AUTH_FAILURE_WINDOW_SECONDS", "60"), 60))
AUTH_FAILURE_THRESHOLD = max(1, _as_int(_env("SNIFF4HOUND_AUTH_FAILURE_THRESHOLD", "10"), 10))
AUTH_LOCKOUT_BASE_SECONDS = max(1, _as_int(_env("SNIFF4HOUND_AUTH_LOCKOUT_BASE_SECONDS", "5"), 5))
AUTH_LOCKOUT_MAX_SECONDS = max(
    AUTH_LOCKOUT_BASE_SECONDS,
    _as_int(_env("SNIFF4HOUND_AUTH_LOCKOUT_MAX_SECONDS", "300"), 300),
)
# Bound on how many distinct source IPs the limiter tracks, so a spoofed-IP
# flood cannot grow the in-memory table without limit.
AUTH_RATE_LIMIT_MAX_CLIENTS = max(64, _as_int(_env("SNIFF4HOUND_AUTH_RATE_LIMIT_MAX_CLIENTS", "4096"), 4096))


def _load_persisted_jwt_secret(path: Path) -> str:
    try:
        raw = path.read_text(encoding="utf-8").strip()
    except OSError:
        return ""
    except Exception:
        return ""
    return raw if len(raw) >= 32 else ""


def _persist_jwt_secret(path: Path, secret: str) -> bool:
    """Create the secret file atomically and 0600. O_EXCL matters: two
    processes starting at the same time must not each believe they created
    it and then sign with two different secrets."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        handle = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return False
    except OSError:
        return False
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(secret)
    except OSError:
        return False
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return True


def resolve_jwt_secret() -> str:
    """Per-installation JWT signing secret. Never a constant."""
    override = str(_env("SNIFF4HOUND_JWT_SECRET", "")).strip()
    if override:
        return override
    path = Path(JWT_SECRET_FILE).expanduser()
    existing = _load_persisted_jwt_secret(path)
    if existing:
        return existing
    candidate = secrets.token_hex(32)
    if _persist_jwt_secret(path, candidate):
        return candidate
    # Lost the O_EXCL race with a concurrent start: use what that one wrote.
    existing = _load_persisted_jwt_secret(path)
    if existing:
        return existing
    return secrets.token_hex(32)


def capture_excluded_ports() -> frozenset[int]:
    """Ports whose traffic never reaches the store. Resolved lazily because
    `manage.py` may fall back to a different listen port than the one
    settings computed at import time, and re-exports it as
    SNIFF4HOUND_PORT before spawning the privileged capture child."""
    if not CAPTURE_EXCLUDE_SELF:
        return CAPTURE_EXCLUDE_PORTS
    own_port = _as_int(_env("SNIFF4HOUND_PORT", str(PORT)), PORT)
    return frozenset(CAPTURE_EXCLUDE_PORTS | {own_port})


# Retention. The old policy was a pure row cap (2000 packets / 4000 tags)
# trimmed FIFO by id, which on a live loopback capture worked out to about
# 99 seconds of history - far too short for anyone to investigate an alert
# after the fact, and biased against the very rows worth keeping since
# high-volume info/low hits evicted the high/critical ones. Retention is
# now primarily *temporal*, with the row cap demoted to a very high
# backstop so an unattended sensor still can't fill the disk.
RETENTION_DAYS = max(0, _as_int(_env("SNIFF4HOUND_RETENTION_DAYS", "7"), 7))
# Rows carrying a high/critical monitor tag survive the plain RETENTION_DAYS
# sweep for this much longer - those are the ones an analyst comes looking
# for days after the fact.
RETENTION_ALERT_DAYS = max(0, _as_int(_env("SNIFF4HOUND_RETENTION_ALERT_DAYS", "30"), 30))
RETENTION_MAX_PACKETS = max(1000, _as_int(_env("SNIFF4HOUND_RETENTION_MAX_PACKETS", "200000"), 200000))
# The purge walks indexed columns but still costs a few DELETEs; the
# capture thread calls it opportunistically, so it self-throttles to at
# most once per this interval.
RETENTION_INTERVAL_SECONDS = max(5, _as_int(_env("SNIFF4HOUND_RETENTION_INTERVAL_SECONDS", "60"), 60))

# Ceiling for `limit` on the paginated list endpoints. The old hard-coded
# 1000 meant a client could never retrieve more than 1000 rows of the
# history retention now actually keeps.
API_MAX_LIMIT = max(100, _as_int(_env("SNIFF4HOUND_API_MAX_LIMIT", "20000"), 20000))

# Ceiling for the decoded payload_text/summary/banner_text stored per packet
# (sniffer.py's _interpret_payload/_classify_*_banner and store.py's
# register_packet both apply this, so a packet's stored preview can't be
# silently re-truncated by a smaller limit further down the pipeline). Raised
# from the old 240/400-char UI-preview limits, which were cutting off
# real single-frame captures (e.g. a full set of HTTP response headers) well
# before anything useful was visible. A standard Ethernet frame's payload
# tops out around 1460 bytes, so 4096 comfortably covers any realistic
# single non-jumbo frame in full while still bounding the per-packet text
# blob every monitor's regex/contains check runs against on the live
# capture thread (rulesets.build_packet_text joins this in on every packet).
PAYLOAD_TEXT_MAX_CHARS = max(240, _as_int(_env("SNIFF4HOUND_PAYLOAD_TEXT_MAX_CHARS", "4096"), 4096))

ICMP_FLOOD_WINDOW_SECONDS = max(1, _as_int(_env("SNIFF4HOUND_ICMP_FLOOD_WINDOW_SECONDS", "5"), 5))
ICMP_FLOOD_THRESHOLD = max(1, _as_int(_env("SNIFF4HOUND_ICMP_FLOOD_THRESHOLD", "30"), 30))
ARP_SPOOF_COOLDOWN_SECONDS = max(1, _as_int(_env("SNIFF4HOUND_ARP_SPOOF_COOLDOWN_SECONDS", "30"), 30))
PORT_SCAN_WINDOW_SECONDS = max(1, _as_int(_env("SNIFF4HOUND_PORT_SCAN_WINDOW_SECONDS", "10"), 10))
PORT_SCAN_DISTINCT_PORTS_THRESHOLD = max(1, _as_int(_env("SNIFF4HOUND_PORT_SCAN_DISTINCT_PORTS_THRESHOLD", "15"), 15))
SYN_FLOOD_WINDOW_SECONDS = max(1, _as_int(_env("SNIFF4HOUND_SYN_FLOOD_WINDOW_SECONDS", "5"), 5))
SYN_FLOOD_THRESHOLD = max(1, _as_int(_env("SNIFF4HOUND_SYN_FLOOD_THRESHOLD", "50"), 50))
BRUTE_FORCE_WINDOW_SECONDS = max(1, _as_int(_env("SNIFF4HOUND_BRUTE_FORCE_WINDOW_SECONDS", "30"), 30))
BRUTE_FORCE_THRESHOLD = max(1, _as_int(_env("SNIFF4HOUND_BRUTE_FORCE_THRESHOLD", "8"), 8))
DNS_QUERY_FLOOD_WINDOW_SECONDS = max(1, _as_int(_env("SNIFF4HOUND_DNS_QUERY_FLOOD_WINDOW_SECONDS", "10"), 10))
DNS_QUERY_FLOOD_THRESHOLD = max(1, _as_int(_env("SNIFF4HOUND_DNS_QUERY_FLOOD_THRESHOLD", "60"), 60))
DHCP_ROGUE_SERVER_COOLDOWN_SECONDS = max(1, _as_int(_env("SNIFF4HOUND_DHCP_ROGUE_SERVER_COOLDOWN_SECONDS", "60"), 60))

# Per-signature rate limit for rule/regex-mode monitors at medium severity
# and up - the same (monitor, source) pair won't re-alert more than once
# per this window, no
# matter how many matching packets arrive in between. Deliberately excludes
# "info"/"low" monitors (DNS/HTTP/TLS-SNI/discovery/protocol-seen/...),
# which must keep firing on every match since Domains/Paths/Radar and
# similar catalogs depend on that. See monitors.RuleAlertThrottle.
MONITOR_ALERT_COOLDOWN_SECONDS = max(1, _as_int(_env("SNIFF4HOUND_MONITOR_ALERT_COOLDOWN_SECONDS", "45"), 45))
MONITOR_MAX_REGEX_PATTERNS = max(1, _as_int(_env("SNIFF4HOUND_MONITOR_MAX_REGEX_PATTERNS", "8"), 8))
MONITOR_MAX_REGEX_LENGTH = max(128, _as_int(_env("SNIFF4HOUND_MONITOR_MAX_REGEX_LENGTH", "2048"), 2048))

DEFAULT_RULESET_FILE = str(_env("SNIFF4HOUND_RULESET_FILE", "default_rulesets.json")).strip()
MONITOR_FILTER_DEFAULT = _as_bool(_env("SNIFF4HOUND_MONITOR_FILTER_DEFAULT", "1"), default=True)
DEFAULT_DOCS_TITLE = str(_env("SNIFF4HOUND_DOCS_TITLE", "Sniff4Hound")).strip() or "Sniff4Hound"
DEFAULT_DOCS_DESCRIPTION = str(
    _env(
        "SNIFF4HOUND_DOCS_DESCRIPTION",
        "Native packet sniffer with SQLite persistence, live stats, an optional honeypot mode, and a wsbuilder frontend.",
    )
).strip()

# IPC between the unprivileged web process and the privileged capture process
# (see sniff4hound/ipc.py, sniff4hound/capture_service.py). Read lazily via
# functions rather than cached at import time: `manage.py` generates the
# socket path/token and injects them into os.environ for its own subsequent
# `from .app import ...`, which happens after `sniff4hound.settings` has
# already been imported once - module-level constants would freeze the
# pre-injection (empty) values.


def default_ipc_socket_path(port: int | None = None) -> str:
    runtime_dir = str(_env("XDG_RUNTIME_DIR", "")).strip()
    base = runtime_dir or "/tmp"
    effective_port = int(port) if port is not None else PORT
    return str(Path(base) / "sniff4hound" / f"capture-{effective_port}.sock")


def resolve_ipc_socket(port: int | None = None) -> str:
    override = str(_env("SNIFF4HOUND_IPC_SOCKET", "")).strip()
    return override or default_ipc_socket_path(port)


def resolve_ipc_token_file() -> str:
    return str(_env("SNIFF4HOUND_IPC_TOKEN_FILE", "")).strip()


def read_ipc_token_file(path: str | None = None) -> str:
    candidate = str(path or resolve_ipc_token_file()).strip()
    if not candidate:
        return ""
    try:
        return Path(candidate).expanduser().read_text(encoding="utf-8").strip()
    except OSError:
        return ""
    except Exception:
        return ""


def resolve_ipc_token() -> str:
    """Shared secret for the local capture IPC channel.

    The token file is preferred over SNIFF4HOUND_IPC_TOKEN: `manage.py`
    spawns the privileged child through `sudo env KEY=VALUE ...`, and every
    one of those assignments is world-readable in /proc/<pid>/cmdline for
    the whole life of the process - so the token itself never travels that
    way any more, only the path to a 0600 file holding it. The environment
    variable is still honoured for split deployments where an operator
    starts `sniff4hound-capture` themselves.
    """
    from_file = read_ipc_token_file()
    if from_file:
        return from_file
    return str(_env("SNIFF4HOUND_IPC_TOKEN", "")).strip()


def write_ipc_token_file(path: str | Path, token: str) -> bool:
    """Persist the IPC token 0600 for the privileged child to read."""
    target = Path(path).expanduser()
    try:
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    except OSError:
        return False
    try:
        if target.exists() or target.is_symlink():
            target.unlink()
    except OSError:
        return False
    try:
        handle = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError:
        return False
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(str(token or ""))
    except OSError:
        return False
    try:
        os.chmod(target, 0o600)
    except OSError:
        pass
    return True


def default_ipc_token_path(socket_path: str | Path) -> str:
    """Sits next to the IPC socket (XDG_RUNTIME_DIR, or /tmp), whose parent
    directory this process already creates and owns."""
    return str(Path(socket_path).with_suffix(".token"))


def resolve_ipc_owner_uid() -> int | None:
    raw = str(_env("SNIFF4HOUND_IPC_OWNER_UID", "")).strip()
    return int(raw) if raw.isdigit() else None


def resolve_ipc_connect_timeout() -> float:
    return max(1.0, _as_float(_env("SNIFF4HOUND_IPC_CONNECT_TIMEOUT", "20"), 20.0))
