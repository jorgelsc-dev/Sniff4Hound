"""Stateful, multi-packet anomaly detection.

The declarative rule/monitor engine in `rulesets.py`/`monitors.py` is a pure,
memoryless function of a single packet — it cannot express "N events from the
same source within T seconds" or "this IP has claimed two different MACs"
conditions. This module fills that gap with a small set of purpose-built,
in-process detectors (state lives in memory only, not persisted across
restarts — acceptable for this scope since these are live-traffic signals).

`AnomalyEngine.evaluate()` is called unconditionally from
`Sniffer._store_packet()` for every captured packet (independent of the
"store only detected traffic" toggle, since a detector that only saw already
-matched traffic could never build a useful baseline) and returns hits shaped
identically to `monitors.evaluate_packet()`'s output, so they merge into the
exact same tagging/persistence pipeline with no schema changes.
"""

from __future__ import annotations

import collections
import time

from . import settings
from .rulesets import build_packet_text, rule_matches_packet
from .utils import safe_int


class ArpSpoofDetector:
    """Flags an IP address whose ARP-announced MAC address changes."""

    def __init__(self):
        self._bindings: dict[str, str] = {}
        self._last_alert: dict[str, float] = {}

    def evaluate(self, packet: dict) -> dict | None:
        if packet.get("proto") != "arp" or packet.get("arp_opcode") != 2:
            return None
        ip = str(packet.get("src_ip") or "").strip()
        mac = str(packet.get("eth_src") or "").strip().lower()
        if not ip or not mac or ip == "0.0.0.0":
            return None
        if mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            return None
        known = self._bindings.get(ip)
        if known is None:
            self._bindings[ip] = mac
            return None
        if known == mac:
            return None
        now = time.monotonic()
        last = self._last_alert.get(ip)
        self._bindings[ip] = mac
        # `time.monotonic()` is relative to an arbitrary reference point (on
        # Linux, often process/system start) - it is NOT guaranteed to
        # already exceed the cooldown window, especially on a short-lived CI
        # runner. A `None` sentinel (never alerted before) must always fire,
        # not be compared against as if it were "a long time ago".
        if last is not None and now - last < settings.ARP_SPOOF_COOLDOWN_SECONDS:
            return None
        self._last_alert[ip] = now
        return {"detail": f"{ip} now claimed by {mac}, previously {known}"}


class _SlidingWindowFloodDetector:
    """Shared "N events per source within T seconds" bookkeeping."""

    def __init__(self, window_seconds: int, threshold: int):
        self._window_seconds = window_seconds
        self._threshold = threshold
        self._events: dict[str, collections.deque] = collections.defaultdict(collections.deque)

    def _record(self, key: str) -> bool:
        now = time.monotonic()
        events = self._events[key]
        events.append(now)
        cutoff = now - self._window_seconds
        while events and events[0] < cutoff:
            events.popleft()
        if len(events) >= self._threshold:
            events.clear()  # re-arm so a sustained flood doesn't tag every single packet
            return True
        return False


class IcmpFloodDetector(_SlidingWindowFloodDetector):
    def __init__(self):
        super().__init__(settings.ICMP_FLOOD_WINDOW_SECONDS, settings.ICMP_FLOOD_THRESHOLD)

    def evaluate(self, packet: dict) -> dict | None:
        if packet.get("proto") not in ("icmp", "icmpv6"):
            return None
        key = str(packet.get("src_ip") or "").strip()
        if not key:
            return None
        if self._record(key):
            return {
                "detail": f"{key} sent {self._threshold}+ ICMP packets within {self._window_seconds}s"
            }
        return None


class PortScanDetector:
    """Flags a source that touches many distinct destination ports within a
    short window — classic TCP/UDP port-scan/reconnaissance behavior."""

    def __init__(self):
        self._window_seconds = settings.PORT_SCAN_WINDOW_SECONDS
        self._threshold = settings.PORT_SCAN_DISTINCT_PORTS_THRESHOLD
        self._events: dict[str, collections.deque] = collections.defaultdict(collections.deque)
        self._last_alert: dict[str, float] = {}

    def evaluate(self, packet: dict) -> dict | None:
        proto = packet.get("proto")
        if proto not in ("tcp", "udp"):
            return None
        if proto == "tcp":
            # Only bare SYN (connection-initiation) packets count as a probe.
            # Without this, a remote server's own SYN-ACK/ACK/RST replies -
            # sent back to the many distinct ephemeral source ports a single
            # local host used for ordinary parallel connections - look
            # identical to that server "touching many destination ports",
            # misattributing the scan to whichever side happens to reply.
            flags = str(packet.get("tcp_flags") or "")
            if "SYN" not in flags or "ACK" in flags:
                return None
        src_ip = str(packet.get("src_ip") or "").strip()
        dst_port = packet.get("dst_port")
        if not src_ip or not dst_port:
            return None
        now = time.monotonic()
        events = self._events[src_ip]
        events.append((now, dst_port))
        cutoff = now - self._window_seconds
        while events and events[0][0] < cutoff:
            events.popleft()
        distinct_ports = {port for _, port in events}
        if len(distinct_ports) < self._threshold:
            return None
        last = self._last_alert.get(src_ip)
        if last is not None and now - last < self._window_seconds:
            return None
        self._last_alert[src_ip] = now
        return {
            "detail": f"{src_ip} touched {len(distinct_ports)} distinct ports within {self._window_seconds}s"
        }


class SynFloodDetector(_SlidingWindowFloodDetector):
    """Flags a source sending an unusually high rate of bare TCP SYN
    (connection-initiation, no ACK) packets within a short window — the
    classic SYN-flood DoS signature."""

    def __init__(self):
        super().__init__(settings.SYN_FLOOD_WINDOW_SECONDS, settings.SYN_FLOOD_THRESHOLD)

    def evaluate(self, packet: dict) -> dict | None:
        if packet.get("proto") != "tcp":
            return None
        flags = str(packet.get("tcp_flags") or "")
        if "SYN" not in flags or "ACK" in flags:
            return None
        key = str(packet.get("src_ip") or "").strip()
        if not key:
            return None
        if self._record(key):
            return {
                "detail": f"{key} sent {self._threshold}+ bare TCP SYN packets within {self._window_seconds}s"
            }
        return None


class BruteForceLoginDetector:
    """Flags a source repeatedly opening connections to a
    credential-bearing service (SSH/RDP/FTP/Telnet/DB ports) on the same
    destination within a short window — a login brute-force signature."""

    LOGIN_PORTS = (21, 22, 23, 25, 110, 143, 993, 995, 1433, 3306, 3389, 5432, 5900)

    def __init__(self):
        self._window_seconds = settings.BRUTE_FORCE_WINDOW_SECONDS
        self._threshold = settings.BRUTE_FORCE_THRESHOLD
        self._events: dict[str, collections.deque] = collections.defaultdict(collections.deque)
        self._last_alert: dict[str, float] = {}

    def evaluate(self, packet: dict) -> dict | None:
        if packet.get("proto") != "tcp":
            return None
        flags = str(packet.get("tcp_flags") or "")
        if "SYN" not in flags or "ACK" in flags:
            return None
        dst_port = packet.get("dst_port")
        if dst_port not in self.LOGIN_PORTS:
            return None
        src_ip = str(packet.get("src_ip") or "").strip()
        dst_ip = str(packet.get("dst_ip") or "").strip()
        if not src_ip or not dst_ip:
            return None
        key = f"{src_ip}->{dst_ip}:{dst_port}"
        now = time.monotonic()
        events = self._events[key]
        events.append(now)
        cutoff = now - self._window_seconds
        while events and events[0] < cutoff:
            events.popleft()
        if len(events) < self._threshold:
            return None
        last = self._last_alert.get(key)
        if last is not None and now - last < self._window_seconds:
            return None
        self._last_alert[key] = now
        return {
            "detail": (
                f"{src_ip} attempted {len(events)}+ connections to {dst_ip}:{dst_port} "
                f"within {self._window_seconds}s"
            )
        }


class DnsQueryFloodDetector(_SlidingWindowFloodDetector):
    """Flags a source sending an unusually high rate of DNS queries within
    a short window — bulk lookups are a common signature of DGA-based
    malware beaconing or a misbehaving/compromised host."""

    def __init__(self):
        super().__init__(settings.DNS_QUERY_FLOOD_WINDOW_SECONDS, settings.DNS_QUERY_FLOOD_THRESHOLD)

    def evaluate(self, packet: dict) -> dict | None:
        if packet.get("proto") not in ("tcp", "udp") or packet.get("dst_port") != 53:
            return None
        key = str(packet.get("src_ip") or "").strip()
        if not key:
            return None
        if self._record(key):
            return {
                "detail": f"{key} sent {self._threshold}+ DNS queries within {self._window_seconds}s"
            }
        return None


class DhcpRogueServerDetector:
    """Flags more than one distinct source IP handing out DHCP leases
    (DHCPOFFER/DHCPACK) - a classic rogue/unauthorized DHCP server signature.
    An attacker's server races the legitimate one to answer first, pointing
    victims at a malicious gateway/DNS server."""

    OFFER_ACK_TYPES = (2, 5)  # DHCPOFFER, DHCPACK

    def __init__(self):
        self._servers: set[str] = set()
        self._last_alert: float | None = None

    def evaluate(self, packet: dict) -> dict | None:
        if packet.get("proto") != "dhcp" or packet.get("dhcp_msg_type") not in self.OFFER_ACK_TYPES:
            return None
        src_ip = str(packet.get("src_ip") or "").strip()
        if not src_ip:
            return None
        self._servers.add(src_ip)
        if len(self._servers) <= 1:
            return None
        now = time.monotonic()
        if self._last_alert is not None and now - self._last_alert < settings.DHCP_ROGUE_SERVER_COOLDOWN_SECONDS:
            return None
        self._last_alert = now
        return {
            "detail": f"{len(self._servers)} distinct DHCP servers observed: {', '.join(sorted(self._servers))}"
        }


def _group_key(packet: dict, spec: str) -> str:
    """Composite state key for GenericThresholdDetector's `group_by`.

    Mirrors the header fields the bespoke detectors above already group by
    (src_ip alone, or src_ip+dst_port for the login/port-scan cases) so a
    declarative monitor gets the same shape of "who/what is doing this
    repeatedly" bucketing without needing a new Python class.
    """
    src_ip = str(packet.get("src_ip") or "").strip()
    dst_ip = str(packet.get("dst_ip") or "").strip()
    dst_port = packet.get("dst_port")
    if spec == "dst_ip":
        return dst_ip
    if spec == "src_ip+dst_port":
        return f"{src_ip}:{dst_port}" if src_ip and dst_port else ""
    if spec == "dst_ip+dst_port":
        return f"{dst_ip}:{dst_port}" if dst_ip and dst_port else ""
    if spec == "src_ip+dst_ip":
        return f"{src_ip}->{dst_ip}" if src_ip and dst_ip else ""
    return src_ip


class GenericThresholdDetector:
    """Windowed count over any declarative match.

    Lets a `mode: "stateful"` monitor express "N matches of my own
    protocol/port/payload criteria from the same source within T seconds"
    purely through match.count_threshold/window_seconds/group_by, instead
    of needing a bespoke detector class wired into AnomalyEngine._detectors
    like the ones above. rule_matches_packet reuses the exact same match
    schema every rule/regex-mode monitor already has, so "what counts as
    one event" stays fully declarative too.
    """

    def __init__(self, monitor_id: str):
        self._monitor_id = monitor_id
        self._events: dict[str, collections.deque] = collections.defaultdict(collections.deque)
        self._last_alert: dict[str, float] = {}

    def evaluate(self, packet: dict, monitor: dict, *, packet_text: str) -> dict | None:
        match = monitor.get("match") if isinstance(monitor.get("match"), dict) else {}
        threshold = safe_int(match.get("count_threshold", 0), 0)
        window = safe_int(match.get("window_seconds", 0), 0)
        if threshold <= 0 or window <= 0:
            return None
        if not rule_matches_packet(monitor, packet, packet_text=packet_text):
            return None
        key = _group_key(packet, str(match.get("group_by") or "src_ip"))
        if not key:
            return None
        now = time.monotonic()
        events = self._events[key]
        events.append(now)
        cutoff = now - window
        while events and events[0] < cutoff:
            events.popleft()
        if len(events) < threshold:
            return None
        last = self._last_alert.get(key)
        if last is not None and now - last < window:
            return None
        self._last_alert[key] = now
        return {"detail": f"{key}: {len(events)}+ matches within {window}s"}


class AnomalyEngine:
    def __init__(self):
        self._detectors = {
            "builtin-arp-spoof": ArpSpoofDetector(),
            "builtin-icmp-flood": IcmpFloodDetector(),
            "builtin-port-scan": PortScanDetector(),
            "builtin-syn-flood": SynFloodDetector(),
            "builtin-brute-force-login": BruteForceLoginDetector(),
            "builtin-dns-query-flood": DnsQueryFloodDetector(),
            "builtin-dhcp-rogue-server": DhcpRogueServerDetector(),
        }
        self._generic_detectors: dict[str, GenericThresholdDetector] = {}
        self._generic_candidate_ids: frozenset[str] = frozenset()
        self._generic_candidates_source: int | None = None

    def evaluate(self, packet: dict, monitors: list[dict], *, monitors_by_id: dict[str, dict] | None = None) -> list[dict]:
        # Only ever looks up a handful of fixed, known ids (self._detectors'
        # keys), so building a full id->monitor map by scanning `monitors`
        # here - as this used to do unconditionally - is O(len(monitors))
        # of wasted work on every single captured packet once that list
        # gets into the thousands (the full builtin catalog size).
        # Sniffer._store_packet passes the id map it already built once per
        # ~2s monitor refresh (monitors.indexed_monitors_by_id) instead;
        # this still falls back to building one here so direct callers
        # (every test in test_anomaly.py) keep working unchanged.
        if monitors_by_id is None:
            monitors_by_id = {str(monitor.get("id") or ""): monitor for monitor in monitors}
        hits = []
        for monitor_id, detector in self._detectors.items():
            monitor = monitors_by_id.get(monitor_id)
            if not monitor or not monitor.get("enabled", True):
                continue
            if str(monitor.get("mode") or "").strip().lower() != "stateful":
                continue
            try:
                hit = detector.evaluate(packet)
            except Exception:
                hit = None
            if not hit:
                continue
            action = monitor.get("action") if isinstance(monitor.get("action"), dict) else {}
            hits.append(
                {
                    "monitor_id": monitor_id,
                    "monitor_name": monitor.get("name"),
                    "tag": action.get("tag") or monitor_id,
                    "label": action.get("label") or monitor.get("name"),
                    "severity": action.get("severity") or "info",
                    "detail": hit.get("detail", ""),
                }
            )

        # Same id-map-identity trick as the fixed detectors above: which ids
        # are eligible for the generic engine only changes when the monitors
        # list itself is refreshed (~every 2s, see Sniffer._get_monitor_context),
        # so this full scan is memoized on the dict's identity instead of
        # running on every single captured packet.
        if id(monitors_by_id) != self._generic_candidates_source:
            self._generic_candidate_ids = frozenset(
                mid
                for mid, monitor in monitors_by_id.items()
                if mid not in self._detectors
                and str(monitor.get("mode") or "").strip().lower() == "stateful"
                and safe_int((monitor.get("match") or {}).get("count_threshold", 0), 0) > 0
            )
            self._generic_candidates_source = id(monitors_by_id)

        if self._generic_candidate_ids:
            packet_text = build_packet_text(packet)
            for monitor_id in self._generic_candidate_ids:
                monitor = monitors_by_id.get(monitor_id)
                if not monitor or not monitor.get("enabled", True):
                    continue
                detector = self._generic_detectors.setdefault(monitor_id, GenericThresholdDetector(monitor_id))
                try:
                    hit = detector.evaluate(packet, monitor, packet_text=packet_text)
                except Exception:
                    hit = None
                if not hit:
                    continue
                action = monitor.get("action") if isinstance(monitor.get("action"), dict) else {}
                hits.append(
                    {
                        "monitor_id": monitor_id,
                        "monitor_name": monitor.get("name"),
                        "tag": action.get("tag") or monitor_id,
                        "label": action.get("label") or monitor.get("name"),
                        "severity": action.get("severity") or "info",
                        "detail": hit.get("detail", ""),
                    }
                )
        return hits
