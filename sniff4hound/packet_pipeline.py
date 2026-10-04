"""Packet cache and processing-job settings for the capture pipeline.

Capture threads no longer run the full evaluation inline. Each parsed packet is
pushed into a bounded `PacketCache`, and a small pool of processing jobs takes
packets off it, evaluates them and persists the ones that matter. The cache
limit is the retention bound: when it is full the oldest waiting packet is
dropped (and counted), so a burst can never grow memory without limit and the
newest traffic is always the part that survives.
"""

from __future__ import annotations

import threading
from collections import deque

PACKET_CACHE_LIMIT_DEFAULT = 20000
PACKET_CACHE_LIMIT_MIN = 1000
PACKET_CACHE_LIMIT_MAX = 1000000

PACKET_JOBS_DEFAULT = 2
# Packets a job takes from the cache and writes in one SQLite transaction. One
# commit per batch instead of per packet is what keeps persistence from
# becoming the bottleneck (and the write-lock contention) under load.
PIPELINE_BATCH_MAX = 64
PACKET_JOBS_MIN = 1
PACKET_JOBS_MAX = 16

# "alerts": only packets that raised something (or muted/training traffic) are
# persisted, the historical behaviour. "all": every packet a job processes is
# persisted, for operators who need the full capture in SniffStore.
PERSIST_MODE_DEFAULT = "alerts"
PERSIST_MODES = ("alerts", "all")


class PacketCache:
    """Thread-safe bounded FIFO between capture threads and processing jobs."""

    def __init__(self, limit: int = PACKET_CACHE_LIMIT_DEFAULT):
        self._items: deque = deque()
        self._limit = int(limit)
        self._cond = threading.Condition()
        self._closed = False
        self.accepted = 0
        self.dropped = 0
        # Highest depth reached since the last reset: how close a burst came
        # to the retention limit, even when nothing was dropped.
        self.peak = 0

    @property
    def closed(self) -> bool:
        with self._cond:
            return self._closed

    @property
    def limit(self) -> int:
        with self._cond:
            return self._limit

    def __len__(self) -> int:
        with self._cond:
            return len(self._items)

    def put(self, item) -> bool:
        """Adds an item, evicting the oldest one when the cache is full."""
        with self._cond:
            if self._closed:
                return False
            while len(self._items) >= self._limit:
                self._items.popleft()
                self.dropped += 1
            self._items.append(item)
            self.accepted += 1
            if len(self._items) > self.peak:
                self.peak = len(self._items)
            self._cond.notify()
            return True

    def get_many(self, limit: int) -> list:
        """Takes up to `limit` waiting items without blocking."""
        with self._cond:
            taken = []
            while self._items and len(taken) < limit:
                taken.append(self._items.popleft())
            return taken

    def get(self, timeout: float = 0.5):
        """Returns the oldest waiting item, or None after `timeout` (or close)."""
        with self._cond:
            if not self._items and not self._closed:
                self._cond.wait(timeout)
            if self._items:
                return self._items.popleft()
            return None

    def set_limit(self, limit: int):
        """Changes the retention bound; shrinking evicts the oldest items now."""
        with self._cond:
            self._limit = int(limit)
            while len(self._items) > self._limit:
                self._items.popleft()
                self.dropped += 1

    def reset_counters(self):
        """Zeroes accepted/dropped/peak. Waiting items are kept."""
        with self._cond:
            self.accepted = 0
            self.dropped = 0
            self.peak = len(self._items)

    def close(self):
        """Stops accepting items, discards what is waiting and wakes the jobs."""
        with self._cond:
            self._closed = True
            self._items.clear()
            self._cond.notify_all()


def coerce_pipeline_settings(values: dict) -> dict:
    """Validates a partial pipeline config. Raises ValueError on bad input."""
    if not isinstance(values, dict):
        raise ValueError("pipeline config must be an object")
    clean = {}
    if "cache_limit" in values:
        clean["cache_limit"] = _bounded_int(values["cache_limit"], "cache_limit",
                                            PACKET_CACHE_LIMIT_MIN, PACKET_CACHE_LIMIT_MAX)
    if "jobs" in values:
        clean["jobs"] = _bounded_int(values["jobs"], "jobs", PACKET_JOBS_MIN, PACKET_JOBS_MAX)
    if "persist_mode" in values:
        mode = str(values["persist_mode"] or "").strip().lower()
        if mode not in PERSIST_MODES:
            raise ValueError(f"persist_mode must be one of: {', '.join(PERSIST_MODES)}")
        clean["persist_mode"] = mode
    return clean


def _bounded_int(value, name: str, low: int, high: int) -> int:
    # bool is an int subclass; reject it so `true` cannot pass as 1.
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        raise ValueError(f"{name} must be an integer")
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"{name} must be an integer") from None
    if number < low or number > high:
        raise ValueError(f"{name} must be between {low} and {high}")
    return number
