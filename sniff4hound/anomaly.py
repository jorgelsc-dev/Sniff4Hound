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
        return hits
