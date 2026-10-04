"""Process-wide logging: one configurable level, size rotation, count and age
retention, and live reconfiguration.

Every `sniff4hound.*` logger propagates to one root handler set here: a
console handler (stderr) and a file handler writing NDJSON to
`<data>/logs/<process>.ndjson`. The file path goes through wsbuilder's
`NDJSONLog`, so the whole stack shares a single append path; rotation and
retention live in `RotatingNDJSONSink` on top of it.

Each process (web, capture) writes its own file. The capture process runs as
root, so it hands the files back to the operator's uid - otherwise the web
process could not append to them after a rotation.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import sys
import threading
import time
from pathlib import Path

from wsbuilder.logs import NDJSONLog

from .logger import NDJsonFormatter
from . import settings


def default_log_dir() -> Path:
    """Where both processes write their logs: next to the database, in the
    same data directory settings resolves (SNIFF4HOUND_DATA_DIR wins there).
    SNIFF4HOUND_LOG_DIR overrides it outright."""
    override = os.environ.get("SNIFF4HOUND_LOG_DIR", "").strip()
    if override:
        return Path(override)
    return Path(settings.DATA_DIR) / "logs"


LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")
LOG_DEFAULTS = {
    "level": "DEBUG",
    "max_mb": 20,
    "backups": 5,
    "retention_days": 14,
    "slow_ms": 200,
}
LOG_BOUNDS = {
    "max_mb": (1, 1024),
    "backups": (0, 100),
    "retention_days": (0, 3650),
    "slow_ms": (10, 60000),
}
# Statements slower than this are logged at DEBUG even below the slow threshold.
SQL_DEBUG_MS = 50

_LEVEL_RANK = {name: index for index, name in enumerate(LOG_LEVELS)}
_STATE = {"sink": None, "process": "", "slow_ms": LOG_DEFAULTS["slow_ms"], "owner": None, "log_dir": None}
_HANDLER_TAG = "_sniff4hound_handler"


def coerce_log_settings(values: dict) -> dict:
    """Validates a partial log config. Raises ValueError before anything is stored."""
    if not isinstance(values, dict):
        raise ValueError("log config must be an object")
    clean = {}
    if "level" in values:
        level = str(values["level"] or "").strip().upper()
        if level not in LOG_LEVELS:
            raise ValueError(f"level must be one of: {', '.join(LOG_LEVELS)}")
        clean["level"] = level
    for field, (low, high) in LOG_BOUNDS.items():
        if field not in values:
            continue
        raw = values[field]
        if isinstance(raw, bool) or not isinstance(raw, (int, float, str)):
            raise ValueError(f"{field} must be an integer")
        try:
            number = int(raw)
        except (TypeError, ValueError):
            raise ValueError(f"{field} must be an integer") from None
        if number < low or number > high:
            raise ValueError(f"{field} must be between {low} and {high}")
        clean[field] = number
    return clean


class RotatingNDJSONSink:
    """Appends NDJSON lines, rotating by size and pruning by count and age."""

    def __init__(self, path: Path, *, max_bytes: int, backups: int, retention_days: int, owner=None):
        self.path = Path(path)
        self._log = NDJSONLog(self.path)
        self._lock = threading.Lock()
        self._owner = owner
        self.max_bytes = int(max_bytes)
        self.backups = int(backups)
        self.retention_days = int(retention_days)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._hand_back()

    def configure(self, *, max_bytes: int, backups: int, retention_days: int) -> None:
        with self._lock:
            self.max_bytes = int(max_bytes)
            self.backups = int(backups)
            self.retention_days = int(retention_days)

    def write(self, record: dict) -> None:
        with self._lock:
            try:
                size = self.path.stat().st_size
            except FileNotFoundError:
                size = 0
            if size >= self.max_bytes:
                self._rotate()
            self._log.append(record)

    def _rotated(self, index: int) -> Path:
        return self.path.with_name(f"{self.path.name}.{index}")

    def _rotate(self) -> None:
        if self.backups == 0:
            self.path.unlink(missing_ok=True)
        else:
            # Shift .N-1 -> .N from the oldest down; os.replace drops the old .N.
            for index in range(self.backups, 0, -1):
                source = self.path if index == 1 else self._rotated(index - 1)
                if source.exists():
                    os.replace(source, self._rotated(index))
        self._hand_back()
        self._prune_locked()

    def _rotated_files(self):
        return [p for p in self.path.parent.glob(f"{self.path.name}.*") if p.suffix[1:].isdigit()]

    def _prune_locked(self) -> int:
        removed = 0
        cutoff = time.time() - self.retention_days * 86400 if self.retention_days > 0 else None
        for candidate in self._rotated_files():
            index = int(candidate.suffix[1:])
            too_many = index > self.backups
            too_old = cutoff is not None and candidate.stat().st_mtime < cutoff
            if too_many or too_old:
                try:
                    candidate.unlink()
                    removed += 1
                except FileNotFoundError:
                    pass
        return removed

    def maintain(self) -> int:
        """Applies retention without waiting for the next rotation."""
        with self._lock:
            return self._prune_locked()

    def _hand_back(self) -> None:
        if self._owner is None:
            return
        uid, gid = self._owner
        for path in (self.path, self.path.parent):
            try:
                os.chown(path, uid, gid)
            except (OSError, FileNotFoundError):
                pass

    def tail(self, lines: int = 200, min_level: str | None = None) -> list[dict]:
        """Last `lines` records at or above `min_level`, newest last."""
        wanted = max(1, min(int(lines), 2000))
        try:
            size = self.path.stat().st_size
        except FileNotFoundError:
            return []
        span = min(size, wanted * 8192)
        with self.path.open("rb") as fh:
            fh.seek(size - span)
            data = fh.read().decode("utf-8", errors="replace")
        rows = []
        floor = _LEVEL_RANK.get(str(min_level or "").upper(), 0)
        for raw in data.splitlines()[1 if span < size else 0:]:
            try:
                row = json.loads(raw)
            except ValueError:
                continue
            if _LEVEL_RANK.get(str(row.get("level", "")).upper(), 0) >= floor:
                rows.append(row)
        return rows[-wanted:]


class SinkHandler(logging.Handler):
    """Routes formatted records into a RotatingNDJSONSink."""

    def __init__(self, sink: RotatingNDJSONSink):
        super().__init__()
        self.sink = sink

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.sink.write(json.loads(self.format(record)))
        except Exception:  # noqa: BLE001 - logging must never take the process down
            self.handleError(record)


def configure(process: str, log_dir: Path, config: dict, *, owner=None) -> RotatingNDJSONSink:
    """Installs the handlers on the `sniff4hound` logger. Safe to call again."""
    root = logging.getLogger("sniff4hound")
    for handler in list(root.handlers):
        if getattr(handler, _HANDLER_TAG, False):
            root.removeHandler(handler)
    sink = RotatingNDJSONSink(
        Path(log_dir) / f"{process}.ndjson",
        max_bytes=int(config["max_mb"]) * 1024 * 1024,
        backups=config["backups"],
        retention_days=config["retention_days"],
        owner=owner,
    )
    console = logging.StreamHandler(sys.stderr)
    console.setFormatter(NDJsonFormatter())
    file_handler = SinkHandler(sink)
    file_handler.setFormatter(NDJsonFormatter())
    for handler in (console, file_handler):
        setattr(handler, _HANDLER_TAG, True)
        root.addHandler(handler)
    root.propagate = False
    _STATE.update(sink=sink, process=process, owner=owner, log_dir=Path(log_dir))
    apply_config(config)
    return sink


def apply_config(config: dict) -> None:
    """Changes level, rotation and retention of a configured process in place."""
    level = getattr(logging, str(config["level"]).upper(), logging.DEBUG)
    root = logging.getLogger("sniff4hound")
    root.setLevel(level)
    for handler in root.handlers:
        if getattr(handler, _HANDLER_TAG, False):
            handler.setLevel(level)
    _STATE["slow_ms"] = int(config["slow_ms"])
    sink = _STATE["sink"]
    if sink is not None:
        sink.configure(
            max_bytes=int(config["max_mb"]) * 1024 * 1024,
            backups=config["backups"],
            retention_days=config["retention_days"],
        )


def current_sink() -> RotatingNDJSONSink | None:
    return _STATE["sink"]


def tail(process: str, lines: int = 200, min_level: str | None = None) -> list[dict]:
    sink = _STATE["sink"]
    if sink is None or _STATE["process"] != process:
        target = _STATE.get("log_dir")
        if target is None:
            return []
        return RotatingNDJSONSink(Path(target) / f"{process}.ndjson", max_bytes=1, backups=0,
                                  retention_days=0).tail(lines, min_level)
    return sink.tail(lines, min_level)


def note_statement(sql: str, elapsed_ms: float) -> None:
    """Records a slow or notable SQL statement. Called on every store statement."""
    if elapsed_ms < SQL_DEBUG_MS:
        return
    label = " ".join(str(sql).split())[:160]
    logger = logging.getLogger("sniff4hound.store")
    if elapsed_ms >= _STATE["slow_ms"]:
        logger.warning("slow statement", extra={"extra_fields": {"ms": round(elapsed_ms, 1), "sql": label}})
    else:
        logger.debug("statement", extra={"extra_fields": {"ms": round(elapsed_ms, 1), "sql": label}})


def start_reload_loop(read_config, *, interval: float = 10.0) -> threading.Thread:
    """Re-reads the stored log config periodically so changes apply to this process."""

    def loop():
        while True:
            time.sleep(interval)
            try:
                apply_config(read_config())
                sink = _STATE["sink"]
                if sink is not None:
                    sink.maintain()
            except sqlite3.ProgrammingError as exc:
                # The store behind read_config was closed (shutdown, or a test
                # tearing its database down). Nothing left to reload from.
                if "closed" in str(exc).lower():
                    return
                logging.getLogger("sniff4hound.logs").debug("log config reload skipped: %s", exc)
            except Exception:  # noqa: BLE001 - a bad read must not stop the loop
                logging.getLogger("sniff4hound.logs").exception("log config reload failed")

    thread = threading.Thread(target=loop, name="sniff4hound-log-config", daemon=True)
    thread.start()
    return thread


__all__ = [
    "LOG_BOUNDS",
    "LOG_DEFAULTS",
    "LOG_LEVELS",
    "RotatingNDJSONSink",
    "SinkHandler",
    "apply_config",
    "coerce_log_settings",
    "configure",
    "current_sink",
    "note_statement",
    "start_reload_loop",
    "tail",
]
