"""Resource limits for the capture process: CPU, RAM and storage.

The guard samples the capture process every few seconds. When a configured
limit is exceeded on two consecutive samples it stops capture and the packet
pipeline jobs, the same way a restart would, and records a trip. It starts them
again on its own once every enabled limit is back under the resume threshold -
but only if the guard was the one that stopped them, never over a manual stop.

Settings, live state and counters are kept in runtime_config, so the web
process can show and edit them and the counters survive restarts.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from pathlib import Path

from . import settings
from .logger import get_logger

LOGGER = get_logger("sniff4hound.limits")

LIMIT_KINDS = ("cpu", "ram", "storage")
LIMIT_DEFAULTS = {
    "cpu_percent": 0,         # % of the whole machine's CPU, 0 = off
    "ram_mb": 0,              # resident memory of the capture process, 0 = off
    "storage_mb": 0,          # database + WAL + logs on disk, 0 = off
    "resume_percent": 80,     # resume when every enabled limit is below this share of its limit
    "sample_seconds": 5,      # how often to measure
    "cooldown_seconds": 300,  # minimum pause before a resume; stops on/off cycling
}
LIMIT_BOUNDS = {
    "cpu_percent": (0, 100),
    "ram_mb": (0, 262144),
    "storage_mb": (0, 10485760),
    "resume_percent": (10, 99),
    "sample_seconds": (1, 300),
    "cooldown_seconds": (0, 3600),
}
TRIP_SAMPLES = 2
WRITE_EVERY_SECONDS = 30.0


def coerce_limit_settings(values: dict) -> dict:
    """Validates a partial limit update. Raises ValueError before anything is stored."""
    if not isinstance(values, dict):
        raise ValueError("limit config must be an object")
    clean = {}
    for field, (low, high) in LIMIT_BOUNDS.items():
        if field not in values:
            continue
        raw = values[field]
        if raw is None:
            raise ValueError(f"{field} must be a number")
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


def rss_mb() -> float:
    """Resident memory of this process, from /proc (no extra dependency)."""
    try:
        with open("/proc/self/status", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) / 1024.0
    except (OSError, ValueError, IndexError):
        pass
    return 0.0


def storage_mb(paths: list[Path]) -> float:
    total = 0
    for root in paths:
        if root.is_dir():
            for child in root.rglob("*"):
                try:
                    if child.is_file():
                        total += child.stat().st_size
                except OSError:
                    pass
        else:
            for candidate in (root, Path(f"{root}-wal"), Path(f"{root}-shm")):
                try:
                    total += candidate.stat().st_size
                except OSError:
                    pass
    return total / (1024.0 * 1024.0)


class ResourceGuard:
    def __init__(self, store, sniffer, *, log_dir: Path):
        self._store = store
        self._sniffer = sniffer
        self._log_dir = Path(log_dir)
        self._db_path = Path(settings.DB_PATH)
        self._cpus = max(1, os.cpu_count() or 1)
        self._last_cpu = time.process_time()
        self._last_wall = time.monotonic()
        self._over = {kind: 0 for kind in LIMIT_KINDS}
        self._paused_by_guard = False
        self._paused_since = 0.0
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        # State lives here between samples. It is written to the database only
        # on a change, or every WRITE_EVERY_SECONDS: a write per sample held the
        # store lock while SQLite waited on the other process, stalling capture.
        self._state: dict = {}
        self._last_write = 0.0

    # -- configuration and counters --------------------------------------

    def config(self) -> dict:
        return self._store.get_limit_config()

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        # A pause recorded by a previous process is stale: this process did not
        # stop anything, so it has nothing to resume. Clear the flag rather than
        # show "Pausado" forever. Capture itself is left to the operator.
        state = self._store.get_limit_state()
        if state.get("paused"):
            state["paused"] = False
            state["reason"] = ""
            state["stale_pause_cleared_at"] = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())
            self._store.set_limit_state(state)
            LOGGER.info("cleared a pause left by a previous process")
        self._state = self._store.get_limit_state()
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="sniff4hound-limits", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        # Wait for the sampling thread to leave its current pass: a sample that
        # is still writing state would otherwise race whoever closes the store
        # or removes the data directory right after stop() returns.
        self._stop.set()
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=5)

    def _loop(self):
        while not self._stop.is_set():
            config = self.config()
            try:
                self.sample(config)
            except Exception:  # noqa: BLE001 - the guard must keep running
                LOGGER.exception("resource sample failed")
            self._stop.wait(config["sample_seconds"])

    # -- one measurement pass ---------------------------------------------

    def measure(self) -> dict:
        now_cpu = time.process_time()
        now_wall = time.monotonic()
        wall = max(1e-6, now_wall - self._last_wall)
        cpu_share = (now_cpu - self._last_cpu) / wall / self._cpus * 100.0
        self._last_cpu, self._last_wall = now_cpu, now_wall
        return {
            "cpu_percent": round(cpu_share, 1),
            "ram_mb": round(rss_mb(), 1),
            "storage_mb": round(storage_mb([self._db_path, self._log_dir]), 1),
        }

    def sample(self, config: dict | None = None) -> dict:
        config = config or self.config()
        values = self.measure()
        limits = {"cpu": config["cpu_percent"], "ram": config["ram_mb"], "storage": config["storage_mb"]}
        measured = {"cpu": values["cpu_percent"], "ram": values["ram_mb"], "storage": values["storage_mb"]}
        exceeded = []
        for kind in LIMIT_KINDS:
            limit = limits[kind]
            if limit and measured[kind] > limit:
                self._over[kind] += 1
                if self._over[kind] == TRIP_SAMPLES:
                    exceeded.append(kind)
            else:
                self._over[kind] = 0

        state = self._state
        state["measured"] = {**values, "at": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())}
        changed = False
        if exceeded and not self._paused_by_guard:
            self._trip(exceeded, state, measured, limits)
            changed = True
        elif (self._paused_by_guard
              and time.monotonic() - self._paused_since >= config["cooldown_seconds"]
              and self._below_resume(limits, measured, config["resume_percent"])):
            self._resume(state)
            changed = True
        if changed or time.monotonic() - self._last_write >= WRITE_EVERY_SECONDS:
            self._persist(state)
        return state

    def _persist(self, state: dict) -> None:
        try:
            self._store.set_limit_state(state)
            self._last_write = time.monotonic()
        except sqlite3.OperationalError as exc:
            # The database is busy with the other process. Keep the state in
            # memory and try again on a later sample instead of blocking here.
            LOGGER.debug("limit state write deferred: %s", exc)

    def _below_resume(self, limits: dict, measured: dict, resume_percent: int) -> bool:
        for kind in LIMIT_KINDS:
            limit = limits[kind]
            if limit and measured[kind] >= limit * resume_percent / 100.0:
                return False
        return True

    def _trip(self, kinds, state, measured, limits):
        with self._lock:
            self._paused_by_guard = True
            self._paused_since = time.monotonic()
        self._sniffer.stop()
        counters = state.setdefault("counters", {"trips": 0, "by_kind": {k: 0 for k in LIMIT_KINDS},
                                                 "paused_seconds": 0.0})
        counters["trips"] += 1
        for kind in kinds:
            counters["by_kind"][kind] = counters["by_kind"].get(kind, 0) + 1
        state["paused"] = True
        state["reason"] = ", ".join(kinds)
        state["paused_at"] = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())
        state["last_trip"] = {"at": state["paused_at"], "kinds": list(kinds),
                              "values": {k: measured[k] for k in kinds},
                              "limits": {k: limits[k] for k in kinds}}
        LOGGER.warning("resource limit reached; capture and jobs stopped",
                       extra={"extra_fields": {"kinds": list(kinds), "values": {k: measured[k] for k in kinds},
                                               "limits": {k: limits[k] for k in kinds}}})

    def _resume(self, state):
        with self._lock:
            paused_for = time.monotonic() - self._paused_since if self._paused_since else 0.0
            self._paused_by_guard = False
            self._paused_since = 0.0
        self._sniffer.start()
        counters = state.setdefault("counters", {"trips": 0, "by_kind": {k: 0 for k in LIMIT_KINDS},
                                                 "paused_seconds": 0.0})
        counters["paused_seconds"] = round(float(counters.get("paused_seconds", 0.0)) + paused_for, 1)
        state["paused"] = False
        state["reason"] = ""
        state["resumed_at"] = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())
        LOGGER.info("resource limits back under threshold; capture resumed",
                    extra={"extra_fields": {"paused_seconds": round(paused_for, 1)}})

    def reset_counters(self) -> dict:
        state = self._state or self._store.get_limit_state()
        state["counters"] = {"trips": 0, "by_kind": {k: 0 for k in LIMIT_KINDS}, "paused_seconds": 0.0}
        self._state = state
        self._persist(state)
        return state


def read_state_fallback() -> dict:
    return {"paused": False, "reason": "", "counters": {"trips": 0, "by_kind": {k: 0 for k in LIMIT_KINDS},
                                                       "paused_seconds": 0.0}, "measured": {}}


def decode_state(raw: str) -> dict:
    try:
        data = json.loads(raw) if raw else {}
    except ValueError:
        data = {}
    return data if isinstance(data, dict) else {}
