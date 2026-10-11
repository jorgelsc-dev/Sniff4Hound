"""Records DNS and ARP history from the packets the sniffer sees.

The sniffer hands every packet to :meth:`HistoryRecorder.observe` before it
decides anything about it - before detection, muting, exclusions or whether the
packet will be stored at all. So the history is complete by construction: what
the network said is recorded whether or not it raised an alert, and whether or
not a scope or exclusion silenced detection for it. (Only the operator's own
whitelist, a deliberate "stop tracking this host", is honoured upstream.)

Writing a row per packet would make the database grow with link speed, which is
what the packets table is designed to avoid. Instead the recorder *aggregates*:
a lookup repeated a thousand times is one pending row whose counter reads a
thousand, and a background thread merges what has accumulated into the history
tables every couple of seconds, in one transaction. Memory is bounded as well:
past ``max_pending`` distinct keys between flushes (a flood of random names, say)
new keys are counted as dropped instead of growing without limit.

It also tracks which MAC each IP last claimed, to notice the changes ARP history
exists to show: a new device, an address that moved to another MAC (spoofing, or
a replaced NIC), a device that took another address, and a frame whose Ethernet
source disagrees with the ARP sender.
"""

from __future__ import annotations

import threading
import time
from typing import Callable

from .history import HISTORY_DEFAULTS, ArpObservation, DnsObservation, arp_observation, dns_observations
from .logger import get_logger
from .utils import utc_now

LOGGER = get_logger(__name__)

# One mismatch event per (ip, mac) per this many seconds: a proxy-ARP device
# disagrees on every frame, and a log of "it did it again" is not information.
MISMATCH_EVENT_INTERVAL_SECONDS = 3600.0
MAX_REMEMBERED_PEERS = 20


class HistoryRecorder:
    CONFIG_REFRESH_SECONDS = 5.0
    FLUSH_INTERVAL_SECONDS = 2.0
    PRUNE_INTERVAL_SECONDS = 3600.0
    MAX_PENDING = 5000
    ARP_STATE_LIMIT = 100_000

    def __init__(
        self,
        store,
        *,
        flush_interval: float | None = None,
        max_pending: int | None = None,
        start_thread: bool = True,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.store = store
        self.flush_interval = float(self.FLUSH_INTERVAL_SECONDS if flush_interval is None else flush_interval)
        self.max_pending = int(self.MAX_PENDING if max_pending is None else max_pending)
        self._start_thread = start_thread
        self._monotonic = monotonic

        self._lock = threading.Lock()
        # One flush at a time: the background thread and a stopping sniffer can both call it.
        self._flush_lock = threading.Lock()
        self._dns: dict[tuple[str, str, str], dict] = {}
        self._arp: dict[tuple[str, str], dict] = {}
        self._events: list[dict] = []
        # A batch that failed to write is kept and retried with the next one.
        self._retry: tuple[list[dict], list[dict], list[dict]] = ([], [], [])

        self._config: dict | None = None
        self._config_at = float("-inf")

        # ARP memory: the MAC an address last belonged to, and what each MAC has used.
        self._arp_ready = False
        self._ip_mac: dict[str, str] = {}
        self._mac_ips: dict[str, set[str]] = {}
        self._mac_last_ip: dict[str, str] = {}
        self._mismatch_at: dict[tuple[str, str], float] = {}

        self.counters = {"dns": 0, "arp": 0, "dropped": 0, "flushes": 0, "write_errors": 0}
        self._thread: threading.Thread | None = None
        self._wake = threading.Event()
        self._closed = False
        self._last_prune = monotonic()

    # --- ingest ----------------------------------------------------------

    def observe(self, packet: dict) -> None:
        """Take what this packet adds to the history. Never raises, never blocks
        on the database: the caller is a capture thread."""
        try:
            config = self._current_config()
            observed_at = str(packet.get("created_at") or "") or utc_now()
            if config["dns_enabled"]:
                observations = dns_observations(packet)
            else:
                observations = []
            arp = arp_observation(packet) if config["arp_enabled"] else None
            if not observations and arp is None:
                return
            with self._lock:
                for observation in observations:
                    self._add_dns(observation, observed_at)
                if arp is not None:
                    self._add_arp(arp, observed_at)
                pending = len(self._dns) + len(self._arp) + len(self._events)
            if pending >= self.max_pending // 2:
                self._wake.set()
            self._ensure_thread()
        except Exception:  # noqa: BLE001 - history must never take capture down
            LOGGER.debug("history observe failed", exc_info=True)

    def _current_config(self) -> dict:
        now = self._monotonic()
        if self._config is None or now - self._config_at >= self.CONFIG_REFRESH_SECONDS:
            try:
                self._config = self.store.get_history_config()
            except Exception:  # noqa: BLE001 - keep the last known settings
                if self._config is None:
                    self._config = dict(HISTORY_DEFAULTS)
            self._config_at = now
        return self._config

    def _add_dns(self, obs: DnsObservation, observed_at: str) -> None:
        key = (obs.domain, obs.record_type, obs.answer)
        row = self._dns.get(key)
        if row is None:
            if len(self._dns) >= self.max_pending:
                self.counters["dropped"] += 1
                return
            row = self._dns[key] = {
                "domain": obs.domain,
                "record_type": obs.record_type,
                "answer": obs.answer,
                "source": obs.source,
                "transport": obs.transport,
                "query_count": 0,
                "response_count": 0,
                "error_count": 0,
                "last_rcode": "",
                "ttl_min": None,
                "ttl_max": None,
                "ttl_last": None,
                "last_client": "",
                "last_resolver": "",
                "clients": [],
                "resolvers": [],
                "first_seen": observed_at,
                "last_seen": observed_at,
            }
        self.counters["dns"] += 1
        if obs.is_response:
            row["response_count"] += 1
            row["last_rcode"] = obs.rcode
            if obs.rcode != "NOERROR":
                row["error_count"] += 1
        else:
            row["query_count"] += 1
        row["source"], row["transport"] = obs.source, obs.transport
        if obs.ttl is not None:
            row["ttl_last"] = obs.ttl
            row["ttl_min"] = obs.ttl if row["ttl_min"] is None else min(row["ttl_min"], obs.ttl)
            row["ttl_max"] = obs.ttl if row["ttl_max"] is None else max(row["ttl_max"], obs.ttl)
        if obs.client:
            row["last_client"] = obs.client
            if obs.client not in row["clients"] and len(row["clients"]) < MAX_REMEMBERED_PEERS:
                row["clients"].append(obs.client)
        if obs.resolver:
            row["last_resolver"] = obs.resolver
            if obs.resolver not in row["resolvers"] and len(row["resolvers"]) < MAX_REMEMBERED_PEERS:
                row["resolvers"].append(obs.resolver)
        if observed_at < row["first_seen"]:
            row["first_seen"] = observed_at
        if observed_at > row["last_seen"]:
            row["last_seen"] = observed_at

    def _add_arp(self, obs: ArpObservation, observed_at: str) -> None:
        self._load_arp_state()
        key = (obs.ip, obs.mac)
        row = self._arp.get(key)
        if row is None:
            if len(self._arp) >= self.max_pending:
                self.counters["dropped"] += 1
                return
            row = self._arp[key] = {
                "ip": obs.ip,
                "mac": obs.mac,
                "interface": obs.interface,
                "packet_count": 0,
                "request_count": 0,
                "reply_count": 0,
                "gratuitous_count": 0,
                "mismatch_count": 0,
                "first_seen": observed_at,
                "last_seen": observed_at,
            }
        self.counters["arp"] += 1
        row["packet_count"] += 1
        if obs.operation == "request":
            row["request_count"] += 1
        elif obs.operation == "reply":
            row["reply_count"] += 1
        if obs.gratuitous:
            row["gratuitous_count"] += 1
        if obs.mismatch:
            row["mismatch_count"] += 1
        if obs.interface:
            row["interface"] = obs.interface
        if observed_at < row["first_seen"]:
            row["first_seen"] = observed_at
        if observed_at > row["last_seen"]:
            row["last_seen"] = observed_at

        previous_mac = self._ip_mac.get(obs.ip, "")
        known_ips = self._mac_ips.get(obs.mac)
        if known_ips is None:
            self._event("new_device", obs, observed_at, detail=f"first seen claiming {obs.ip}")
        elif obs.ip not in known_ips:
            previous_ip = self._mac_last_ip.get(obs.mac, "")
            self._event("mac_new_ip", obs, observed_at, previous_ip=previous_ip,
                        detail=f"{obs.mac} now also uses {obs.ip}")
        if previous_mac and previous_mac != obs.mac:
            self._event("ip_mac_changed", obs, observed_at, previous_mac=previous_mac,
                        detail=f"{obs.ip} moved from {previous_mac} to {obs.mac}")
        if obs.mismatch:
            now = self._monotonic()
            mismatch_key = (obs.ip, obs.mac)
            if now - self._mismatch_at.get(mismatch_key, float("-inf")) >= MISMATCH_EVENT_INTERVAL_SECONDS:
                self._mismatch_at[mismatch_key] = now
                self._event("mac_mismatch", obs, observed_at, detail=obs.mismatch)
                if len(self._mismatch_at) > self.max_pending:
                    self._mismatch_at.clear()
        self._ip_mac[obs.ip] = obs.mac
        self._mac_ips.setdefault(obs.mac, set()).add(obs.ip)
        self._mac_last_ip[obs.mac] = obs.ip

    def _event(self, kind: str, obs: ArpObservation, observed_at: str, *, previous_ip: str = "",
               previous_mac: str = "", detail: str = "") -> None:
        if len(self._events) >= self.max_pending:
            self.counters["dropped"] += 1
            return
        self._events.append({
            "kind": kind,
            "ip": obs.ip,
            "mac": obs.mac,
            "previous_ip": previous_ip,
            "previous_mac": previous_mac,
            "interface": obs.interface,
            "detail": detail,
            "occurred_at": observed_at,
        })

    def _load_arp_state(self) -> None:
        """Learn the bindings recorded before this process started, once, so a
        restart does not report every known device as new."""
        if self._arp_ready:
            return
        self._arp_ready = True
        try:
            pairs = self.store.arp_known_pairs(self.ARP_STATE_LIMIT)
        except Exception:  # noqa: BLE001 - start empty rather than not record
            LOGGER.debug("could not load the known ARP bindings", exc_info=True)
            return
        for ip, mac in pairs:
            self._ip_mac[ip] = mac
            self._mac_ips.setdefault(mac, set()).add(ip)
            self._mac_last_ip[mac] = ip

    # --- writing ---------------------------------------------------------

    def flush(self) -> dict:
        """Write what has accumulated. Safe to call from any thread."""
        with self._flush_lock:
            with self._lock:
                dns, arp, events = list(self._dns.values()), list(self._arp.values()), self._events
                self._dns, self._arp, self._events = {}, {}, []
            retry_dns, retry_arp, retry_events = self._retry
            dns, arp, events = retry_dns + dns, retry_arp + arp, retry_events + events
            self._retry = ([], [], [])
            if not (dns or arp or events):
                return {"dns": 0, "arp": 0, "events": 0}
            try:
                written = self.store.write_history(dns, arp, events)
            except Exception:  # noqa: BLE001
                self.counters["write_errors"] += 1
                LOGGER.warning("could not write the DNS/ARP history; keeping it for the next flush", exc_info=True)
                keep = self.max_pending * 4
                self._retry = (dns[-keep:], arp[-keep:], events[-keep:])
                return {"dns": 0, "arp": 0, "events": 0, "error": True}
            self.counters["flushes"] += 1
            return written

    def prune(self) -> dict:
        try:
            return self.store.prune_history()
        except Exception:  # noqa: BLE001
            LOGGER.warning("could not prune the DNS/ARP history", exc_info=True)
            return {}

    # --- lifecycle -------------------------------------------------------

    def _ensure_thread(self) -> None:
        if not self._start_thread or self._thread is not None or self._closed:
            return
        with self._lock:
            if self._thread is not None:
                return
            self._thread = threading.Thread(target=self._run, name="sniff4hound-history", daemon=True)
            self._thread.start()

    def _run(self) -> None:
        while not self._closed:
            self._wake.wait(self.flush_interval)
            self._wake.clear()
            self.flush()
            if self._monotonic() - self._last_prune >= self.PRUNE_INTERVAL_SECONDS:
                self._last_prune = self._monotonic()
                self.prune()

    def close(self) -> None:
        """Write what is pending and stop the background thread."""
        self._closed = True
        self._wake.set()
        thread = self._thread
        if thread is not None and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=3.0)
        self.flush()
