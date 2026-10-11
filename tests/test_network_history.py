"""DNS and ARP history: extraction, storage, recording and the pipeline contract.

The contract that matters most is the last class: the history is written for
every DNS and ARP packet the sniffer sees, whether or not anything alerted and
whether or not an exclusion or scope silenced detection for it.
"""

from __future__ import annotations

import socket
import struct
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock

from sniff4hound.history import (
    HISTORY_DEFAULTS,
    arp_observation,
    coerce_history_config,
    dns_observations,
    normalize_domain,
    normalize_mac,
)
from sniff4hound.history_recorder import MISMATCH_EVENT_INTERVAL_SECONDS, HistoryRecorder
from sniff4hound.sniffer import Sniffer
from sniff4hound.store import SniffStore


def _stamp(seconds_ago: float = 0.0) -> str:
    moment = datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


# --- frames -----------------------------------------------------------------


def _mac(text: str) -> bytes:
    return bytes(int(part, 16) for part in text.split(":"))


def _dns_name(name: str) -> bytes:
    return b"".join(bytes([len(label)]) + label.encode() for label in name.strip(".").split(".")) + b"\x00"


def _dns_message(*, response: bool, name: str, qtype: int = 1, answers=(), rcode: int = 0) -> bytes:
    flags = (0x8180 if response else 0x0100) | rcode
    header = struct.pack("!HHHHHH", 0x1234, flags, 1, len(answers), 0, 0)
    question = _dns_name(name) + struct.pack("!HH", qtype, 1)
    body = b""
    for rtype, ttl, rdata in answers:
        body += b"\xc0\x0c" + struct.pack("!HHIH", rtype, 1, ttl, len(rdata)) + rdata
    return header + question + body


def _udp_frame(src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes,
               src_mac="aa:bb:cc:00:00:01", dst_mac="aa:bb:cc:00:00:02") -> bytes:
    udp = struct.pack("!HHHH", src_port, dst_port, 8 + len(payload), 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
                     socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    return _mac(dst_mac) + _mac(src_mac) + b"\x08\x00" + ip + udp


def _dns_query_frame(name="example.com", client="192.168.1.10", resolver="192.168.1.1", qtype=1) -> bytes:
    return _udp_frame(client, resolver, 40000, 53, _dns_message(response=False, name=name, qtype=qtype))


def _dns_response_frame(name="example.com", answers=((1, 300, bytes([93, 184, 216, 34])),), rcode=0,
                        client="192.168.1.10", resolver="192.168.1.1", qtype=1) -> bytes:
    return _udp_frame(resolver, client, 53, 40000,
                      _dns_message(response=True, name=name, qtype=qtype, answers=answers, rcode=rcode))


def _arp_frame(sender_ip: str, sender_mac: str, target_ip: str, *, opcode=1, target_mac="00:00:00:00:00:00",
               eth_src: str | None = None) -> bytes:
    arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, opcode) + _mac(sender_mac) + socket.inet_aton(sender_ip) \
        + _mac(target_mac) + socket.inet_aton(target_ip)
    return _mac("ff:ff:ff:ff:ff:ff") + _mac(eth_src or sender_mac) + b"\x08\x06" + arp


# --- pure extraction -----------------------------------------------------------


class HistoryConfigTests(unittest.TestCase):
    def test_the_defaults_record_both_and_keep_ninety_days(self):
        self.assertEqual(coerce_history_config({}), HISTORY_DEFAULTS)
        self.assertTrue(HISTORY_DEFAULTS["dns_enabled"] and HISTORY_DEFAULTS["arp_enabled"])
        self.assertEqual(HISTORY_DEFAULTS["retention_days"], 90)

    def test_a_partial_update_keeps_everything_else(self):
        current = coerce_history_config({"retention_days": 30})
        self.assertEqual(coerce_history_config({"dns_enabled": False}, current)["retention_days"], 30)

    def test_values_are_checked_and_a_bad_one_rejects_the_whole_update(self):
        for bad in ({"retention_days": -1}, {"retention_days": 99999}, {"max_dns_rows": 5}, {"dns_enabled": "maybe"},
                    {"retention_days": "ten"}, {"retention_days": True}, {"typo": 1}):
            with self.assertRaises(ValueError, msg=str(bad)):
                coerce_history_config(bad)
        with self.assertRaises(ValueError):
            coerce_history_config(["not", "an", "object"])

    def test_booleans_accept_the_usual_spellings(self):
        for text, expected in (("true", True), ("0", False), ("off", False), ("yes", True), (1, True), (False, False)):
            self.assertIs(coerce_history_config({"arp_enabled": text})["arp_enabled"], expected, text)


class DnsExtractionTests(unittest.TestCase):
    def _packet(self, *, response, questions, answers=(), rcode="NOERROR", src="192.168.1.10", dst="192.168.1.1"):
        return {
            "src_ip": src, "dst_ip": dst, "domain_source": "dns", "transport": "udp",
            "dns_records": {"is_response": response, "rcode": rcode, "questions": list(questions), "answers": list(answers)},
        }

    def test_a_query_is_one_observation_from_client_to_resolver(self):
        found = dns_observations(self._packet(response=False, questions=[{"name": "Example.COM.", "type": "A"}]))
        self.assertEqual(len(found), 1)
        self.assertEqual((found[0].domain, found[0].record_type, found[0].answer), ("example.com", "A", ""))
        self.assertEqual((found[0].client, found[0].resolver, found[0].is_response), ("192.168.1.10", "192.168.1.1", False))

    def test_a_response_records_each_answer_and_swaps_the_peers(self):
        found = dns_observations(self._packet(
            response=True, src="192.168.1.1", dst="192.168.1.10",
            questions=[{"name": "www.example.com", "type": "A"}],
            answers=[{"name": "www.example.com", "type": "CNAME", "ttl": 60, "data": "cdn.example.net"},
                     {"name": "cdn.example.net", "type": "A", "ttl": 30, "data": "203.0.113.7"}]))
        self.assertEqual([(o.domain, o.record_type, o.answer, o.ttl) for o in found],
                         [("www.example.com", "CNAME", "cdn.example.net", 60), ("cdn.example.net", "A", "203.0.113.7", 30)])
        self.assertEqual((found[0].client, found[0].resolver), ("192.168.1.10", "192.168.1.1"))

    def test_an_error_response_still_leaves_a_trace_of_the_question(self):
        found = dns_observations(self._packet(response=True, rcode="NXDOMAIN", questions=[{"name": "nope.example", "type": "A"}]))
        self.assertEqual([(o.domain, o.answer, o.rcode, o.is_response) for o in found], [("nope.example", "", "NXDOMAIN", True)])

    def test_an_answered_question_is_not_counted_twice(self):
        found = dns_observations(self._packet(
            response=True, questions=[{"name": "a.example", "type": "A"}],
            answers=[{"name": "a.example", "type": "A", "ttl": 5, "data": "198.51.100.1"}]))
        self.assertEqual([o.answer for o in found], ["198.51.100.1"])

    def test_junk_is_ignored(self):
        self.assertEqual(dns_observations({"proto": "tcp"}), [])
        self.assertEqual(dns_observations({"dns_records": "garbage"}), [])
        found = dns_observations(self._packet(
            response=True, questions=[{"name": "", "type": "A"}, {"name": "x" * 300, "type": "A"}],
            answers=[{"name": "ok.example", "type": "A", "ttl": -1, "data": ""}, "not a dict"]))
        self.assertEqual(found, [])

    def test_names_are_normalised(self):
        self.assertEqual(normalize_domain(" WWW.Example.Com. "), "www.example.com")
        self.assertEqual(normalize_domain(""), "")
        self.assertEqual(normalize_domain("a" * 254), "")


class ArpExtractionTests(unittest.TestCase):
    def _packet(self, **overrides):
        packet = {"proto": "arp", "src_ip": "192.168.1.20", "dst_ip": "192.168.1.1", "arp_opcode": 1,
                  "arp_sender_mac": "AA:BB:CC:DD:EE:20", "interface": "eth0"}
        packet.update(overrides)
        return packet

    def test_the_claim_is_the_sender_pair_in_the_payload(self):
        found = arp_observation(self._packet())
        self.assertEqual((found.ip, found.mac, found.operation, found.interface), ("192.168.1.20", "aa:bb:cc:dd:ee:20", "request", "eth0"))
        self.assertFalse(found.gratuitous)

    def test_replies_and_gratuitous_announcements(self):
        self.assertEqual(arp_observation(self._packet(arp_opcode=2)).operation, "reply")
        self.assertTrue(arp_observation(self._packet(dst_ip="192.168.1.20")).gratuitous)

    def test_a_probe_asserts_nothing_and_is_skipped(self):
        self.assertIsNone(arp_observation(self._packet(src_ip="0.0.0.0")))

    def test_bogus_senders_are_skipped(self):
        for overrides in ({"arp_sender_mac": "00:00:00:00:00:00"}, {"arp_sender_mac": "ff:ff:ff:ff:ff:ff"},
                          {"arp_sender_mac": "nonsense"}, {"src_ip": "not-an-ip"}, {"src_ip": "224.0.0.1"}, {"proto": "tcp"}):
            self.assertIsNone(arp_observation(self._packet(**overrides)), overrides)

    def test_the_sniffers_mismatch_note_comes_through(self):
        self.assertEqual(arp_observation(self._packet(arp_mac_mismatch="a announces b")).mismatch, "a announces b")

    def test_macs_are_normalised(self):
        self.assertEqual(normalize_mac("AA-BB-CC-DD-EE-FF"), "aa:bb:cc:dd:ee:ff")
        self.assertEqual(normalize_mac("aabbccddeeff"), "")


# --- storage -----------------------------------------------------------------


class StoreCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.store = SniffStore(Path(self._tmp.name) / "history.db")
        self.addCleanup(self.store.close)


def _dns_row(domain="example.com", rtype="A", answer="", **over):
    row = {"domain": domain, "record_type": rtype, "answer": answer, "source": "dns", "transport": "udp",
           "query_count": 0, "response_count": 0, "error_count": 0, "last_rcode": "", "ttl_min": None, "ttl_max": None,
           "ttl_last": None, "last_client": "", "last_resolver": "", "clients": [], "resolvers": [],
           "first_seen": _stamp(), "last_seen": _stamp()}
    row.update(over)
    return row


def _arp_row(ip="192.168.1.20", mac="aa:bb:cc:dd:ee:20", **over):
    row = {"ip": ip, "mac": mac, "interface": "eth0", "packet_count": 1, "request_count": 1, "reply_count": 0,
           "gratuitous_count": 0, "mismatch_count": 0, "first_seen": _stamp(), "last_seen": _stamp()}
    row.update(over)
    return row


class HistoryStoreTests(StoreCase):
    def test_a_fresh_database_has_the_tables_and_default_settings(self):
        self.assertEqual(self.store.history_totals(), {"dns_history": 0, "arp_bindings": 0, "arp_events": 0, "arp_devices": 0})
        self.assertEqual(self.store.get_history_config(), HISTORY_DEFAULTS)

    def test_settings_round_trip_and_a_bad_update_changes_nothing(self):
        self.store.set_history_config({"retention_days": 14, "arp_enabled": False})
        self.assertEqual(self.store.get_history_config()["retention_days"], 14)
        self.assertFalse(self.store.get_history_config()["arp_enabled"])
        with self.assertRaises(ValueError):
            self.store.set_history_config({"retention_days": 7, "max_dns_rows": 1})
        self.assertEqual(self.store.get_history_config()["retention_days"], 14)

    def test_a_stored_value_that_no_longer_validates_falls_back_to_defaults(self):
        self.store.set_runtime_config("history_config", '{"retention_days": -5}')
        self.assertEqual(self.store.get_history_config(), HISTORY_DEFAULTS)

    def test_dns_rows_accumulate_instead_of_duplicating(self):
        first = _stamp(60)
        self.store.write_history([_dns_row(query_count=2, last_client="10.0.0.1", clients=["10.0.0.1"], first_seen=first)], [], [])
        self.store.write_history([_dns_row(query_count=3, last_client="10.0.0.2", clients=["10.0.0.2", "10.0.0.1"])], [], [])
        rows = self.store.list_dns_history()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["query_count"], 5)
        self.assertEqual(rows[0]["clients"], ["10.0.0.1", "10.0.0.2"])
        self.assertEqual(rows[0]["last_client"], "10.0.0.2")
        self.assertEqual(rows[0]["first_seen"], first, "the first sighting is never moved forward")

    def test_ttl_range_and_the_last_response_code_follow_the_data(self):
        self.store.write_history([_dns_row(answer="1.1.1.1", response_count=1, last_rcode="NOERROR", ttl_min=60, ttl_max=60, ttl_last=60)], [], [])
        self.store.write_history([_dns_row(answer="1.1.1.1", response_count=1, error_count=1, last_rcode="SERVFAIL", ttl_min=20, ttl_max=300, ttl_last=300)], [], [])
        row = self.store.list_dns_history()[0]
        self.assertEqual((row["ttl_min"], row["ttl_max"], row["ttl_last"]), (20, 300, 300))
        self.assertEqual((row["response_count"], row["error_count"], row["last_rcode"]), (2, 1, "SERVFAIL"))

    def test_a_query_that_carries_no_response_code_does_not_erase_the_last_one(self):
        self.store.write_history([_dns_row(answer="", response_count=1, last_rcode="NXDOMAIN")], [], [])
        self.store.write_history([_dns_row(answer="", query_count=1, last_rcode="")], [], [])
        self.assertEqual(self.store.list_dns_history()[0]["last_rcode"], "NXDOMAIN")

    def test_remembered_peers_are_capped(self):
        peers = [f"10.0.{i // 250}.{i % 250 + 1}" for i in range(60)]
        self.store.write_history([_dns_row(query_count=1, clients=peers)], [], [])
        self.assertLessEqual(len(self.store.list_dns_history()[0]["clients"]), 20)

    def test_dns_filters(self):
        now = _stamp()
        self.store.write_history([
            _dns_row("example.com", "A", "93.184.216.34", response_count=1, last_rcode="NOERROR", last_client="10.0.0.5"),
            _dns_row("example.com", "AAAA", "2606:2800::1", response_count=1, last_rcode="NOERROR"),
            _dns_row("gone.example", "A", "", response_count=1, error_count=1, last_rcode="NXDOMAIN"),
            _dns_row("old.example", "A", "", query_count=1, last_seen=_stamp(7200), first_seen=_stamp(7200)),
        ], [], [])
        listed = lambda **kw: sorted((r["domain"], r["record_type"]) for r in self.store.list_dns_history(**kw))
        self.assertEqual(listed(search="EXAMPLE.COM"), [("example.com", "A"), ("example.com", "AAAA")])
        self.assertEqual(listed(record_type="aaaa"), [("example.com", "AAAA")])
        self.assertEqual(listed(rcode="nxdomain"), [("gone.example", "A")])
        self.assertEqual(listed(ip="93.184.216.34"), [("example.com", "A")])
        self.assertEqual(listed(ip="10.0.0.5"), [("example.com", "A")])
        self.assertEqual(listed(domain="gone.example"), [("gone.example", "A")])
        self.assertEqual(listed(search="2606"), [("example.com", "AAAA")])
        self.assertNotIn(("old.example", "A"), listed(since=_stamp(3600)))
        self.assertEqual(self.store.count_dns_history(search="example.com"), 2)
        self.assertEqual(self.store.count_dns_history(), 4)
        self.assertEqual(len(self.store.list_dns_history(limit=2)), 2)
        self.assertEqual(len(self.store.list_dns_history(limit=2, offset=3)), 1)
        del now

    def test_dns_search_treats_percent_and_underscore_as_text(self):
        self.store.write_history([_dns_row("a_b.example", "A", "")], [], [])
        # Not a wildcard: this must not match every row.
        self.assertEqual(self.store.count_dns_history(ip='%'), 0)

    def test_arp_bindings_accumulate_and_devices_group_by_mac(self):
        self.store.write_history([], [
            _arp_row("192.168.1.20", "aa:bb:cc:dd:ee:20", packet_count=3, request_count=2, reply_count=1, first_seen=_stamp(500), last_seen=_stamp(100)),
            _arp_row("192.168.1.21", "aa:bb:cc:dd:ee:20", packet_count=1, last_seen=_stamp(10)),
            _arp_row("192.168.1.30", "aa:bb:cc:dd:ee:30", packet_count=4, mismatch_count=2, last_seen=_stamp(50)),
        ], [])
        self.store.write_history([], [_arp_row("192.168.1.20", "aa:bb:cc:dd:ee:20", packet_count=2, request_count=2)], [])
        bindings = {(r["ip"], r["mac"]): r for r in self.store.list_arp_bindings()}
        self.assertEqual(len(bindings), 3)
        self.assertEqual(bindings[("192.168.1.20", "aa:bb:cc:dd:ee:20")]["packet_count"], 5)
        devices = {r["mac"]: r for r in self.store.list_arp_devices()}
        self.assertEqual(set(devices), {"aa:bb:cc:dd:ee:20", "aa:bb:cc:dd:ee:30"})
        first = devices["aa:bb:cc:dd:ee:20"]
        self.assertEqual(sorted(first["ips"]), ["192.168.1.20", "192.168.1.21"])
        self.assertEqual(first["ip_count"], 2)
        self.assertEqual(first["packet_count"], 6)
        self.assertEqual(first["current_ip"], "192.168.1.20", "the binding seen most recently")
        self.assertEqual(devices["aa:bb:cc:dd:ee:30"]["mismatch_count"], 2)
        self.assertEqual(self.store.count_arp_devices(), 2)
        self.assertEqual(self.store.count_arp_bindings(mac="AA:BB:CC:DD:EE:20"), 2)
        self.assertEqual(self.store.count_arp_bindings(ip="192.168.1.30"), 1)
        self.assertEqual(self.store.count_arp_bindings(search="ee:30"), 1)

    def test_arp_events_are_listed_newest_first_and_filtered(self):
        self.store.write_history([], [], [
            {"kind": "new_device", "ip": "192.168.1.20", "mac": "aa:bb:cc:dd:ee:20", "occurred_at": _stamp(300)},
            {"kind": "ip_mac_changed", "ip": "192.168.1.20", "mac": "aa:bb:cc:dd:ee:99", "previous_mac": "aa:bb:cc:dd:ee:20",
             "detail": "moved", "occurred_at": _stamp(100)},
            {"kind": "mac_mismatch", "ip": "192.168.1.5", "mac": "aa:bb:cc:dd:ee:05", "occurred_at": _stamp(10)},
        ])
        self.assertEqual([e["kind"] for e in self.store.list_arp_events()], ["mac_mismatch", "ip_mac_changed", "new_device"])
        self.assertEqual([e["kind"] for e in self.store.list_arp_events(kind="ip_mac_changed")], ["ip_mac_changed"])
        self.assertEqual(self.store.count_arp_events(mac="aa:bb:cc:dd:ee:20"), 2, "as the new or the previous owner")
        self.assertEqual(self.store.count_arp_events(ip="192.168.1.20"), 2)
        self.assertEqual(self.store.count_arp_events(search="moved"), 1)
        self.assertEqual(self.store.count_arp_events(since=_stamp(60)), 1)

    def test_an_unknown_event_kind_is_refused_and_the_batch_is_rolled_back(self):
        with self.assertRaises(ValueError):
            self.store.write_history([_dns_row(query_count=1)], [], [{"kind": "made-up"}])
        self.assertEqual(self.store.count_dns_history(), 0, "the whole batch is atomic")

    def test_retention_removes_rows_not_seen_within_the_window_and_keeps_active_ones(self):
        self.store.set_history_config({"retention_days": 1})
        old = _stamp(3 * 86400)
        self.store.write_history(
            [_dns_row("stale.example", answer="", query_count=1, first_seen=old, last_seen=old),
             _dns_row("busy.example", answer="", query_count=1, first_seen=old, last_seen=_stamp())],
            [_arp_row("192.168.1.99", "aa:bb:cc:dd:ee:99", first_seen=old, last_seen=old)],
            [{"kind": "new_device", "ip": "192.168.1.99", "mac": "aa:bb:cc:dd:ee:99", "occurred_at": old}])
        deleted = self.store.prune_history()
        self.assertEqual(deleted, {"dns_history": 1, "arp_bindings": 1, "arp_events": 1})
        self.assertEqual([r["domain"] for r in self.store.list_dns_history()], ["busy.example"])

    def test_zero_days_keeps_everything_until_a_cap_is_hit(self):
        self.store.set_history_config({"retention_days": 0})
        old = _stamp(400 * 86400)
        self.store.write_history([_dns_row("ancient.example", answer="", query_count=1, last_seen=old, first_seen=old)], [], [])
        self.assertEqual(self.store.prune_history()["dns_history"], 0)

    def test_the_row_cap_drops_the_least_recently_seen(self):
        self.store.set_history_config({"max_dns_rows": 1000})
        rows = [_dns_row(f"d{i}.example", answer="", query_count=1, last_seen=_stamp(2000 - i), first_seen=_stamp(2000 - i)) for i in range(1005)]
        self.store.write_history(rows, [], [])
        self.assertEqual(self.store.prune_history()["dns_history"], 5)
        remaining = {r["domain"] for r in self.store.list_dns_history(limit=2000)}
        self.assertNotIn("d0.example", remaining)
        self.assertIn("d1004.example", remaining)
        self.assertEqual(len(remaining), 1000)

    def test_clearing_by_scope(self):
        self.store.write_history([_dns_row(query_count=1)], [_arp_row()], [{"kind": "new_device", "ip": "1.1.1.1", "mac": "aa:bb:cc:dd:ee:20"}])
        self.assertEqual(self.store.clear_history("dns"), {"dns_history": 1})
        self.assertEqual(self.store.history_totals()["arp_bindings"], 1)
        self.assertEqual(self.store.clear_history("arp"), {"arp_bindings": 1, "arp_events": 1})
        with self.assertRaises(ValueError):
            self.store.clear_history("everything")

    def test_purging_all_capture_data_takes_the_history_with_it(self):
        self.store.write_history([_dns_row(query_count=1)], [_arp_row()], [])
        self.store.purge_capture_data()
        self.assertEqual(self.store.history_totals()["dns_history"], 0)
        self.assertEqual(self.store.history_totals()["arp_bindings"], 0)

    def test_known_pairs_come_back_oldest_first(self):
        self.store.write_history([], [_arp_row("1.1.1.1", "aa:bb:cc:dd:ee:01", last_seen=_stamp(100)),
                                      _arp_row("2.2.2.2", "aa:bb:cc:dd:ee:02", last_seen=_stamp(5))], [])
        self.assertEqual(self.store.arp_known_pairs(), [("1.1.1.1", "aa:bb:cc:dd:ee:01"), ("2.2.2.2", "aa:bb:cc:dd:ee:02")])


# --- recorder ----------------------------------------------------------------


class RecorderCase(StoreCase):
    def recorder(self, **kw):
        kw.setdefault("start_thread", False)
        recorder = HistoryRecorder(self.store, **kw)
        self.addCleanup(recorder.close)
        return recorder

    @staticmethod
    def dns_packet(name="example.com", *, response=False, answers=(), rcode="NOERROR", client="10.0.0.5", resolver="10.0.0.1", created_at=None):
        packet = {
            "proto": "dns", "domain_source": "dns", "transport": "udp", "created_at": created_at or _stamp(),
            "src_ip": resolver if response else client, "dst_ip": client if response else resolver,
            "dns_records": {"is_response": response, "rcode": rcode, "questions": [{"name": name, "type": "A"}],
                            "answers": list(answers)},
        }
        return packet

    @staticmethod
    def arp_packet(ip, mac, *, opcode=1, target=None, mismatch="", interface="eth0"):
        packet = {"proto": "arp", "src_ip": ip, "dst_ip": target or "192.168.1.1", "arp_opcode": opcode,
                  "arp_sender_mac": mac, "interface": interface, "created_at": _stamp()}
        if mismatch:
            packet["arp_mac_mismatch"] = mismatch
        return packet


class HistoryRecorderTests(RecorderCase):
    def test_a_thousand_identical_lookups_are_one_row_with_a_counter(self):
        recorder = self.recorder()
        for _ in range(1000):
            recorder.observe(self.dns_packet())
        self.assertEqual(self.store.count_dns_history(), 0, "nothing is written per packet")
        self.assertEqual(recorder.flush()["dns"], 1)
        rows = self.store.list_dns_history()
        self.assertEqual((len(rows), rows[0]["query_count"]), (1, 1000))

    def test_responses_and_queries_share_what_they_have_in_common(self):
        recorder = self.recorder()
        recorder.observe(self.dns_packet())
        recorder.observe(self.dns_packet(response=True, answers=[{"name": "example.com", "type": "A", "ttl": 120, "data": "93.184.216.34"}]))
        recorder.flush()
        by_answer = {r["answer"]: r for r in self.store.list_dns_history()}
        self.assertEqual(by_answer[""]["query_count"], 1)
        self.assertEqual((by_answer["93.184.216.34"]["response_count"], by_answer["93.184.216.34"]["ttl_last"]), (1, 120))
        self.assertEqual(by_answer["93.184.216.34"]["last_client"], "10.0.0.5")
        self.assertEqual(by_answer["93.184.216.34"]["last_resolver"], "10.0.0.1")

    def test_failed_lookups_are_counted_as_errors(self):
        recorder = self.recorder()
        recorder.observe(self.dns_packet("nope.example", response=True, rcode="NXDOMAIN"))
        recorder.flush()
        row = self.store.list_dns_history()[0]
        self.assertEqual((row["error_count"], row["last_rcode"]), (1, "NXDOMAIN"))

    def test_the_packets_own_timestamp_is_the_time_of_the_observation(self):
        recorder = self.recorder()
        earlier = _stamp(3600)
        recorder.observe(self.dns_packet(created_at=earlier))
        recorder.flush()
        self.assertEqual(self.store.list_dns_history()[0]["first_seen"], earlier)

    def test_a_new_device_is_reported_once_and_known_ones_are_not(self):
        recorder = self.recorder()
        recorder.observe(self.arp_packet("192.168.1.20", "aa:bb:cc:dd:ee:20"))
        recorder.observe(self.arp_packet("192.168.1.20", "aa:bb:cc:dd:ee:20", opcode=2))
        recorder.flush()
        events = self.store.list_arp_events()
        self.assertEqual([e["kind"] for e in events], ["new_device"])
        binding = self.store.list_arp_bindings()[0]
        self.assertEqual((binding["packet_count"], binding["request_count"], binding["reply_count"]), (2, 1, 1))

    def test_an_address_that_moves_to_another_mac_is_a_change(self):
        recorder = self.recorder()
        recorder.observe(self.arp_packet("192.168.1.1", "aa:bb:cc:00:00:01"))
        recorder.observe(self.arp_packet("192.168.1.1", "aa:bb:cc:00:00:99"))
        recorder.flush()
        changed = [e for e in self.store.list_arp_events() if e["kind"] == "ip_mac_changed"]
        self.assertEqual(len(changed), 1)
        self.assertEqual((changed[0]["ip"], changed[0]["mac"], changed[0]["previous_mac"]), ("192.168.1.1", "aa:bb:cc:00:00:99", "aa:bb:cc:00:00:01"))
        self.assertEqual(self.store.count_arp_bindings(ip="192.168.1.1"), 2, "both claims stay on record")

    def test_a_known_device_taking_another_address_is_noted(self):
        recorder = self.recorder()
        recorder.observe(self.arp_packet("192.168.1.20", "aa:bb:cc:dd:ee:20"))
        recorder.observe(self.arp_packet("192.168.1.77", "aa:bb:cc:dd:ee:20"))
        recorder.flush()
        event = [e for e in self.store.list_arp_events() if e["kind"] == "mac_new_ip"][0]
        self.assertEqual((event["ip"], event["previous_ip"]), ("192.168.1.77", "192.168.1.20"))

    def test_a_mismatch_is_an_event_but_a_noisy_device_is_not_a_flood(self):
        now = [1000.0]
        recorder = self.recorder(monotonic=lambda: now[0])
        for _ in range(50):
            recorder.observe(self.arp_packet("192.168.1.5", "aa:bb:cc:dd:ee:05", mismatch="aa:bb:cc:dd:ee:01 announces aa:bb:cc:dd:ee:05"))
        recorder.flush()
        self.assertEqual(self.store.count_arp_events(kind="mac_mismatch"), 1)
        self.assertEqual(self.store.list_arp_bindings()[0]["mismatch_count"], 50, "every one is still counted")
        now[0] += MISMATCH_EVENT_INTERVAL_SECONDS + 1
        recorder.observe(self.arp_packet("192.168.1.5", "aa:bb:cc:dd:ee:05", mismatch="again"))
        recorder.flush()
        self.assertEqual(self.store.count_arp_events(kind="mac_mismatch"), 2)

    def test_a_restart_does_not_report_known_devices_as_new(self):
        first = self.recorder()
        first.observe(self.arp_packet("192.168.1.20", "aa:bb:cc:dd:ee:20"))
        first.flush()
        second = self.recorder()
        second.observe(self.arp_packet("192.168.1.20", "aa:bb:cc:dd:ee:20"))
        second.flush()
        self.assertEqual(self.store.count_arp_events(kind="new_device"), 1)
        # ...and a change that happened while it was down is still caught.
        second.observe(self.arp_packet("192.168.1.20", "aa:bb:cc:dd:ee:77"))
        second.flush()
        self.assertEqual(self.store.count_arp_events(kind="ip_mac_changed"), 1)

    def test_probes_and_non_arp_packets_record_nothing(self):
        recorder = self.recorder()
        recorder.observe(self.arp_packet("0.0.0.0", "aa:bb:cc:dd:ee:20"))
        recorder.observe({"proto": "tcp", "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2"})
        recorder.observe({})
        self.assertEqual(recorder.flush(), {"dns": 0, "arp": 0, "events": 0})

    def test_memory_is_bounded_when_names_never_repeat(self):
        recorder = self.recorder(max_pending=50)
        for index in range(500):
            recorder.observe(self.dns_packet(f"random{index}.example"))
        self.assertEqual(recorder.flush()["dns"], 50)
        self.assertEqual(recorder.counters["dropped"], 450)
        recorder.observe(self.dns_packet("random0.example"))
        self.assertEqual(recorder.flush()["dns"], 1, "after a flush there is room again")

    def test_settings_apply_live_and_a_disabled_table_records_nothing(self):
        now = [0.0]
        recorder = self.recorder(monotonic=lambda: now[0])
        self.store.set_history_config({"dns_enabled": False})
        recorder.observe(self.dns_packet("off.example"))
        recorder.observe(self.arp_packet("192.168.1.20", "aa:bb:cc:dd:ee:20"))
        self.assertEqual(recorder.flush(), {"dns": 0, "arp": 1, "events": 1})
        self.store.set_history_config({"dns_enabled": True, "arp_enabled": False})
        recorder.observe(self.dns_packet("still-off-until-refresh.example"))
        now[0] += HistoryRecorder.CONFIG_REFRESH_SECONDS + 1
        recorder.observe(self.dns_packet("on.example"))
        recorder.observe(self.arp_packet("192.168.1.21", "aa:bb:cc:dd:ee:21"))
        recorder.flush()
        domains = {r["domain"] for r in self.store.list_dns_history()}
        self.assertIn("on.example", domains)
        self.assertEqual(self.store.count_arp_bindings(), 1)

    def test_a_failed_write_is_kept_and_retried_not_lost(self):
        recorder = self.recorder()
        recorder.observe(self.dns_packet("kept.example"))
        real = self.store.write_history
        self.store.write_history = MagicMock(side_effect=RuntimeError("disk is full"))
        self.assertTrue(recorder.flush().get("error"))
        self.assertEqual(recorder.counters["write_errors"], 1)
        self.store.write_history = real
        recorder.observe(self.dns_packet("kept.example"))
        recorder.flush()
        self.assertEqual(self.store.list_dns_history()[0]["query_count"], 2)

    def test_a_broken_packet_never_raises_into_capture(self):
        recorder = self.recorder()
        recorder.observe({"dns_records": {"is_response": True, "questions": 5, "answers": object()}})
        recorder.observe({"proto": "arp", "arp_sender_mac": "aa:bb:cc:dd:ee:20", "src_ip": "1.2.3.4", "arp_opcode": "x"})

    def test_the_background_thread_writes_without_being_asked(self):
        recorder = self.recorder(start_thread=True, flush_interval=0.05)
        recorder.observe(self.dns_packet("background.example"))
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not self.store.count_dns_history():
            time.sleep(0.02)
        self.assertEqual(self.store.count_dns_history(), 1)

    def test_closing_writes_what_is_pending(self):
        recorder = HistoryRecorder(self.store, start_thread=True, flush_interval=60)
        recorder.observe(self.dns_packet("pending.example"))
        recorder.close()
        self.assertEqual(self.store.count_dns_history(), 1)


# --- the pipeline contract ------------------------------------------------------


class SnifferHistoryPipelineTests(StoreCase):
    """Real frames through the real parser and `_store_packet`."""

    def sniffer(self):
        sniffer = Sniffer(self.store, MagicMock(), interfaces=[])
        self.addCleanup(sniffer._history.close)
        # The same plumbing ExcludedTrafficPipelineTests uses to keep the
        # context caches from querying the database mid-test.
        sniffer._monitor_cache = []
        sniffer._monitor_cache_at = 999999999.0
        sniffer._ruleset_cache = []
        sniffer._ruleset_cache_at = 999999999.0
        return sniffer

    def feed(self, sniffer, frame, interface="eth0"):
        packet = sniffer.parse_packet(frame, interface=interface)
        self.assertIsNotNone(packet)
        sniffer._store_packet(packet)
        return packet

    def test_dns_is_recorded_though_nothing_alerted_and_nothing_else_was_stored(self):
        sniffer = self.sniffer()
        self.store.set_monitor_filter_enabled(True)
        self.feed(sniffer, _dns_query_frame("quiet.example"))
        self.feed(sniffer, _dns_response_frame("quiet.example"))
        sniffer._history.flush()
        self.assertEqual(self.store.list_packets(limit=10), [], "clean traffic is not persisted as packets")
        rows = {r["answer"]: r for r in self.store.list_dns_history()}
        self.assertEqual(set(rows), {"", "93.184.216.34"})
        self.assertEqual(rows["93.184.216.34"]["ttl_last"], 300)
        self.assertEqual(rows[""]["last_client"], "192.168.1.10")

    def test_arp_is_recorded_with_its_changes(self):
        sniffer = self.sniffer()
        self.feed(sniffer, _arp_frame("192.168.1.1", "aa:bb:cc:00:00:01", "192.168.1.10", opcode=2, target_mac="aa:bb:cc:00:00:0a"))
        self.feed(sniffer, _arp_frame("192.168.1.1", "aa:bb:cc:00:00:66", "192.168.1.10", opcode=2, target_mac="aa:bb:cc:00:00:0a"))
        sniffer._history.flush()
        kinds = [e["kind"] for e in self.store.list_arp_events()]
        self.assertIn("ip_mac_changed", kinds)
        self.assertEqual(kinds.count("new_device"), 2)
        self.assertEqual(self.store.count_arp_bindings(ip="192.168.1.1"), 2)

    def test_a_spoofed_ethernet_source_is_seen_as_a_mismatch(self):
        sniffer = self.sniffer()
        self.feed(sniffer, _arp_frame("192.168.1.9", "aa:bb:cc:00:00:09", "192.168.1.1", eth_src="de:ad:be:ef:00:01"))
        sniffer._history.flush()
        self.assertEqual(self.store.count_arp_events(kind="mac_mismatch"), 1)

    def test_an_exclusion_filter_does_not_stop_the_history(self):
        sniffer = self.sniffer()
        self.store.set_exclusion_filters({"protocols": ["dns", "arp"], "cidrs": ["192.168.1.0/24"]})
        sniffer._exclusion_filters = self.store.get_exclusion_filters()
        from sniff4hound.store import compile_exclusion_networks

        sniffer._exclusion_networks = compile_exclusion_networks(sniffer._exclusion_filters)
        dns_packet = self.feed(sniffer, _dns_response_frame("excluded.example"))
        arp_packet = self.feed(sniffer, _arp_frame("192.168.1.20", "aa:bb:cc:dd:ee:20", "192.168.1.1"))
        self.assertTrue(sniffer._exclusion_filtered(dns_packet) and sniffer._exclusion_filtered(arp_packet),
                        "the premise: detection really is excluded for these")
        sniffer._history.flush()
        self.assertEqual(self.store.count_dns_history(domain="excluded.example"), 1)
        self.assertEqual(self.store.count_arp_bindings(ip="192.168.1.20"), 1)

    def test_a_muted_ip_scope_does_not_stop_the_history(self):
        sniffer = self.sniffer()
        self.store.set_detection_exclude_scopes(["private", "loopback"])
        sniffer._detection_exclude_scopes = frozenset(self.store.get_detection_exclude_scopes())
        packet = self.feed(sniffer, _dns_query_frame("muted.example"))
        self.assertTrue(sniffer._detection_muted(packet))
        sniffer._history.flush()
        self.assertEqual(self.store.count_dns_history(domain="muted.example"), 1)

    def test_an_alerting_packet_is_recorded_too(self):
        sniffer = self.sniffer()
        sniffer._monitor_cache = [{
            "id": "dns-any", "name": "any dns", "enabled": True, "mode": "rule",
            "match": {"protocols": ["dns"]}, "action": {"tag": "dns", "label": "DNS", "severity": "high"},
        }]
        sniffer._monitor_filter_enabled = True
        packet = self.feed(sniffer, _dns_query_frame("alerting.example"))
        sniffer._history.flush()
        self.assertEqual(self.store.count_dns_history(domain="alerting.example"), 1)
        del packet

    def test_a_whitelisted_host_is_the_one_thing_left_out(self):
        sniffer = self.sniffer()
        self.store.create_whitelist_entry(category="ip", match_type="exact", value="192.168.1.10")
        sniffer._whitelist_cache = self.store.list_whitelist_entries()
        self.assertTrue(sniffer._whitelist_cache, "premise: the entry is loaded")
        self.feed(sniffer, _dns_query_frame("whitelisted.example", client="192.168.1.10"))
        sniffer._history.flush()
        self.assertEqual(self.store.count_dns_history(domain="whitelisted.example"), 0)

    def test_a_disabled_table_stops_recording_after_the_settings_refresh(self):
        sniffer = self.sniffer()
        self.store.set_history_config({"dns_enabled": False})
        sniffer._history._config = None
        self.feed(sniffer, _dns_query_frame("disabled.example"))
        sniffer._history.flush()
        self.assertEqual(self.store.count_dns_history(), 0)

    def test_stopping_the_sniffer_writes_what_is_pending(self):
        sniffer = self.sniffer()
        self.feed(sniffer, _dns_query_frame("flushed.example"))
        self.assertEqual(self.store.count_dns_history(), 0)
        sniffer.stop()
        self.assertEqual(self.store.count_dns_history(domain="flushed.example"), 1)

    def test_mdns_and_llmnr_are_recorded_with_their_source(self):
        sniffer = self.sniffer()
        self.feed(sniffer, _udp_frame("192.168.1.30", "224.0.0.251", 5353, 5353, _dns_message(response=False, name="printer.local")))
        self.feed(sniffer, _udp_frame("192.168.1.30", "224.0.0.252", 40000, 5355, _dns_message(response=False, name="wpad")))
        sniffer._history.flush()
        sources = {r["domain"]: r["source"] for r in self.store.list_dns_history()}
        self.assertEqual(sources, {"printer.local": "mdns", "wpad": "llmnr"})

    def test_what_the_packets_table_stores_does_not_grow_with_the_dns_records(self):
        sniffer = self.sniffer()
        self.store.set_monitor_filter_enabled(False)
        sniffer._pipeline_persist_all = True
        packet = self.feed(sniffer, _dns_response_frame("details.example"))
        stored = self.store.list_packets(limit=5)
        self.assertEqual(len(stored), 1)
        self.assertNotIn("dns_records", str(stored[0].get("details") or stored[0].get("details_json") or ""))
        self.assertIn("dns_records", packet)


if __name__ == "__main__":
    unittest.main()
