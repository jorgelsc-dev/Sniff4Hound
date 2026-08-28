from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from sniff4hound.protocol_facets import (
    DETAIL_KEYS,
    PACKET_COLUMNS,
    PROTOCOL_FACETS,
    extract_details,
    facet_expression,
    facet_present_predicate,
    PROTOCOL_ROW_COLUMNS,
    resolve_facets,
    resolve_row_columns,
)
from sniff4hound.utils import KNOWN_PROTOCOLS
from sniff4hound.store import SniffStore


def _facet(snapshot: dict, key: str) -> dict:
    for facet in snapshot.get("facets", []):
        if facet.get("key") == key:
            return facet
    raise AssertionError(f"facet {key!r} missing from {[f['key'] for f in snapshot.get('facets', [])]}")


def _counts(facet: dict) -> dict:
    return {item["label"]: item["count"] for item in facet["series"]}


class FacetExpressionTests(unittest.TestCase):
    """facet_expression is the only place a facet name reaches SQL."""

    def test_a_real_column_is_emitted_bare(self):
        self.assertEqual(facet_expression("src_ip"), "src_ip")

    def test_a_detail_key_becomes_a_json_extract(self):
        self.assertEqual(
            facet_expression("http_server"),
            "json_extract(details_json, '$.http_server')",
        )

    def test_anything_undeclared_is_refused(self):
        # The return value is interpolated into SQL, so a name that is neither
        # a column nor a declared detail key has to yield nothing at all -
        # never a passthrough of the caller's string.
        for probe in (
            "details_json); DROP TABLE packets;--",
            "1=1",
            "json_extract(x,'$.y')",
            "http_server; SELECT 1",
            "",
            None,
        ):
            self.assertEqual(facet_expression(probe), "", f"{probe!r} was not refused")

    def test_every_declared_facet_resolves_to_an_expression(self):
        # A typo in PROTOCOL_FACETS would otherwise silently drop a table from
        # the view rather than fail anywhere.
        for proto, facets in PROTOCOL_FACETS.items():
            for key, _title, _subtitle in facets:
                self.assertTrue(
                    facet_expression(key),
                    f"{proto} declares {key!r}, which is neither a column nor a detail key",
                )

    def test_resolve_facets_accepts_both_kinds_and_drops_the_rest(self):
        for proto, facets in PROTOCOL_FACETS.items():
            for key, _title, _subtitle in resolve_facets(proto):
                self.assertTrue(
                    key in PACKET_COLUMNS or key in DETAIL_KEYS,
                    f"{proto} leaked {key!r}",
                )

    def test_an_unknown_protocol_falls_back_instead_of_echoing_the_caller(self):
        facets = resolve_facets("'; DROP TABLE packets;--")
        self.assertTrue(facets)
        for key, _title, _subtitle in facets:
            self.assertIn(key, PACKET_COLUMNS)


class ProtocolCoverageTests(unittest.TestCase):
    def test_every_recognised_protocol_has_its_own_facets(self):
        # Falling back to DEFAULT_FACETS means the view shows interface,
        # direction and frame size - three tables that say the same thing for
        # every protocol and answer nothing about any of them.
        missing = [p for p in KNOWN_PROTOCOLS if p not in PROTOCOL_FACETS]
        self.assertEqual(missing, [], f"protocols still falling back to the generic tables: {missing}")

    def test_no_protocol_resolves_to_an_empty_table_set(self):
        for proto in KNOWN_PROTOCOLS:
            self.assertTrue(resolve_facets(proto), f"{proto} resolves to no facets at all")


class RowColumnTests(unittest.TestCase):
    def test_every_declared_column_survives_resolution(self):
        # A key that is neither a column nor a detail key is dropped silently,
        # so a typo would remove a column from the table rather than fail.
        for proto, columns in PROTOCOL_ROW_COLUMNS.items():
            resolved = {key for key, _label in resolve_row_columns(proto)}
            dropped = [key for key, _label in columns if key not in resolved]
            self.assertEqual(dropped, [], f"{proto} declares unusable columns: {dropped}")

    def test_arp_columns_carry_addresses_instead_of_ports(self):
        # ARP has no ports and no connection state; showing them spent four of
        # twelve columns on fields that are constant for the whole protocol.
        keys = {key for key, _label in resolve_row_columns("arp")}
        self.assertIn("arp_sender_mac", keys)
        self.assertIn("arp_target_mac", keys)
        self.assertIn("arp_mac_mismatch", keys)
        self.assertNotIn("src_port", keys)
        self.assertNotIn("dst_port", keys)

    def test_an_unknown_protocol_still_gets_a_usable_table(self):
        keys = {key for key, _label in resolve_row_columns("'; DROP TABLE packets;--")}
        self.assertIn("src_ip", keys)
        self.assertIn("summary", keys)


class ArpParsingTests(unittest.TestCase):
    """The ARP payload carries addresses the Ethernet header does not."""

    @staticmethod
    def _payload(opcode, sender_mac, sender_ip, target_mac, target_ip):
        import struct
        return (
            struct.pack("!HHBBH", 1, 0x0800, 6, 4, opcode)
            + bytes.fromhex(sender_mac.replace(":", ""))
            + bytes(int(part) for part in sender_ip.split("."))
            + bytes.fromhex(target_mac.replace(":", ""))
            + bytes(int(part) for part in target_ip.split("."))
        )

    def _parse(self, eth_src, **kwargs):
        from sniff4hound.sniffer import Sniffer
        packet = {"eth_src": eth_src, "eth_dst": "ff:ff:ff:ff:ff:ff", "length": 60}
        Sniffer._parse_arp(Sniffer.__new__(Sniffer), packet, self._payload(**kwargs))
        return packet

    def test_the_payload_addresses_are_extracted(self):
        packet = self._parse(
            "aa:bb:cc:dd:ee:01",
            opcode=1, sender_mac="aa:bb:cc:dd:ee:01", sender_ip="192.168.15.10",
            target_mac="00:00:00:00:00:00", target_ip="192.168.15.1",
        )
        self.assertEqual(packet["arp_operation"], "request")
        self.assertEqual(packet["arp_sender_mac"], "aa:bb:cc:dd:ee:01")
        self.assertEqual(packet["arp_target_mac"], "00:00:00:00:00:00")
        self.assertEqual(packet["src_ip"], "192.168.15.10")
        self.assertEqual(packet["dst_ip"], "192.168.15.1")
        self.assertEqual(packet["arp_hardware_type"], "Ethernet")

    def test_a_matching_frame_and_payload_raise_no_mismatch(self):
        packet = self._parse(
            "aa:bb:cc:dd:ee:01",
            opcode=1, sender_mac="aa:bb:cc:dd:ee:01", sender_ip="192.168.15.10",
            target_mac="00:00:00:00:00:00", target_ip="192.168.15.1",
        )
        self.assertNotIn("arp_mac_mismatch", packet)

    def test_a_frame_announcing_someone_elses_mac_is_flagged(self):
        # This is what ARP spoofing looks like on the wire: the frame comes
        # from one MAC while the payload announces another host's.
        packet = self._parse(
            "de:ad:be:ef:00:99",
            opcode=2, sender_mac="aa:bb:cc:dd:ee:01", sender_ip="192.168.15.1",
            target_mac="aa:bb:cc:dd:ee:02", target_ip="192.168.15.10",
        )
        self.assertIn("arp_mac_mismatch", packet)
        self.assertIn("de:ad:be:ef:00:99", packet["arp_mac_mismatch"])
        self.assertIn("aa:bb:cc:dd:ee:01", packet["arp_mac_mismatch"])

    def test_a_truncated_frame_does_not_raise(self):
        from sniff4hound.sniffer import Sniffer
        packet = {"eth_src": "aa:bb:cc:dd:ee:01", "length": 20}
        Sniffer._parse_arp(Sniffer.__new__(Sniffer), packet, b"\x00" * 10)
        self.assertEqual(packet["proto"], "arp")


class PresencePredicateTests(unittest.TestCase):
    def test_a_text_column_excludes_the_empty_string(self):
        self.assertEqual(facet_present_predicate("src_ip"), "src_ip IS NOT NULL AND src_ip != ''")

    def test_a_port_column_treats_zero_as_absent(self):
        self.assertEqual(facet_present_predicate("dst_port"), "dst_port != 0")

    def test_icmp_type_keeps_zero_because_it_is_echo_reply(self):
        # Type 0 is a real ICMP message, so it must not be filtered out the way
        # port 0 is.
        self.assertNotIn("!= 0", facet_present_predicate("icmp_type"))

    def test_an_undeclared_key_yields_no_predicate(self):
        self.assertEqual(facet_present_predicate("nope; DROP TABLE packets"), "")


class ExtractDetailsTests(unittest.TestCase):
    def test_only_whitelisted_keys_survive(self):
        details = extract_details(
            {"http_server": "nginx/1.24.0", "src_ip": "10.0.0.1", "not_a_key": "x"}
        )
        self.assertEqual(details, {"http_server": "nginx/1.24.0"})

    def test_empty_values_are_dropped(self):
        self.assertEqual(extract_details({"http_server": "", "http_status": None}), {})

    def test_booleans_become_readable_labels(self):
        # ntp_amplification_candidate is emitted as a bool; "True"/"False" would
        # read as debug output in the chart legend.
        self.assertEqual(
            extract_details({"ntp_amplification_candidate": True}),
            {"ntp_amplification_candidate": "yes"},
        )

    def test_values_are_bounded(self):
        details = extract_details({"http_user_agent": "A" * 5000})
        self.assertLessEqual(len(details["http_user_agent"]), 200)


class DetailFacetPersistenceTests(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.store = SniffStore(str(Path(self._dir.name) / "facets.db"))
        self.addCleanup(self.store.close)

    def _http(self, **extra):
        packet = {
            "proto": "http",
            "src_ip": "10.0.0.5",
            "dst_ip": "10.0.0.9",
            "src_port": 80,
            "dst_port": 44000,
            "length": 200,
            "payload_len": 100,
        }
        packet.update(extra)
        self.store.register_packet(packet)

    def test_decoder_extras_reach_the_database(self):
        # These fields were extracted on every packet and then dropped, because
        # the insert only ever named columns that exist.
        self._http(http_status="200", http_server="nginx/1.24.0")
        row = self.store._conn.execute(
            "SELECT details_json FROM packets ORDER BY id DESC LIMIT 1"
        ).fetchone()
        self.assertEqual(
            json.loads(row["details_json"]),
            {"http_status": "200", "http_server": "nginx/1.24.0"},
        )

    def test_http_reports_status_server_and_agent(self):
        for _ in range(3):
            self._http(http_status="200", http_server="nginx/1.24.0", http_user_agent="curl/8.5.0")
        self._http(http_status="404", http_server="Apache/2.4.58")

        snapshot = self.store.protocol_snapshot(proto="http")
        self.assertEqual(_counts(_facet(snapshot, "http_status")), {"200": 3, "404": 1})
        self.assertEqual(
            _counts(_facet(snapshot, "http_server")),
            {"nginx/1.24.0": 3, "Apache/2.4.58": 1},
        )
        self.assertEqual(_counts(_facet(snapshot, "http_user_agent")), {"curl/8.5.0": 3})

    def test_packets_without_the_field_do_not_become_a_bucket(self):
        # json_extract answers NULL for a key the decoder never set. Counting
        # those would put one "empty" bar on top of every real value.
        self._http(http_server="nginx/1.24.0")
        self._http(http_method="GET", http_path="/")
        self._http(http_method="GET", http_path="/x")

        snapshot = self.store.protocol_snapshot(proto="http")
        self.assertEqual(_counts(_facet(snapshot, "http_server")), {"nginx/1.24.0": 1})

    def test_a_protocol_keeps_its_column_facets_too(self):
        self._http(http_method="GET", http_path="/", http_server="nginx/1.24.0")
        snapshot = self.store.protocol_snapshot(proto="http")
        keys = {facet["key"] for facet in snapshot["facets"]}
        self.assertIn("http_method", keys)
        self.assertIn("http_server", keys)

    def test_absent_values_are_counted_rather_than_charted(self):
        # Two frames carry a Host, three do not. The chart must show the two
        # real hosts, and the three have to remain visible as a count so the
        # reader can tell a chart built from 2 of 5 frames from one built
        # from all 5.
        self._http(http_host="a.example")
        self._http(http_host="b.example")
        for _ in range(3):
            self._http(http_method="GET")

        hosts = _facet(self.store.protocol_snapshot(proto="http"), "http_host")
        self.assertEqual(_counts(hosts), {"a.example": 1, "b.example": 1})
        self.assertEqual(hosts["missing"], 3)
        self.assertNotIn("none", _counts(hosts))

    def test_missing_is_zero_when_every_frame_has_the_field(self):
        self._http(http_method="GET")
        self._http(http_method="POST")
        methods = _facet(self.store.protocol_snapshot(proto="http"), "http_method")
        self.assertEqual(methods["missing"], 0)

    def test_dns_reports_which_address_a_name_resolved_to(self):
        # The answer records were parsed all along and survived only inside the
        # summary string, so "what did this name resolve to" could not be
        # asked of the data.
        self.store.register_packet({
            "proto": "dns", "src_ip": "10.0.0.1", "dst_ip": "1.1.1.1",
            "src_port": 50000, "dst_port": 53, "length": 90,
            "domain": "example.com", "dns_kind": "response", "dns_qtype": "A",
            "dns_rcode": "NOERROR", "dns_answer": "93.184.216.34",
            "dns_mapping": "example.com -> 93.184.216.34",
        })
        self.store.register_packet({
            "proto": "dns", "src_ip": "10.0.0.1", "dst_ip": "1.1.1.1",
            "src_port": 50001, "dst_port": 53, "length": 90,
            "domain": "evil.test", "dns_kind": "response", "dns_qtype": "A",
            "dns_rcode": "NXDOMAIN",
        })
        snapshot = self.store.protocol_snapshot(proto="dns")
        self.assertEqual(
            _counts(_facet(snapshot, "dns_mapping")),
            {"example.com -> 93.184.216.34": 1},
        )
        self.assertEqual(_counts(_facet(snapshot, "dns_answer")), {"93.184.216.34": 1})
        self.assertEqual(
            _counts(_facet(snapshot, "dns_rcode")), {"NOERROR": 1, "NXDOMAIN": 1}
        )
        # The unresolved query is not charted as an answer, but is still counted.
        self.assertEqual(_facet(snapshot, "dns_answer")["missing"], 1)

    def test_row_details_are_lifted_to_top_level_fields(self):
        # The table reads row[column.key]; making the client parse a nested
        # JSON blob to render a declared column would be a trap.
        self.store.register_packet({
            "proto": "arp", "src_ip": "192.168.15.10", "dst_ip": "192.168.15.1",
            "eth_src": "de:ad:be:ef:00:99", "length": 60, "arp_opcode": 2,
            "arp_operation": "reply", "arp_sender_mac": "aa:bb:cc:dd:ee:01",
            "arp_target_mac": "aa:bb:cc:dd:ee:02",
            "arp_mac_mismatch": "de:ad:be:ef:00:99 announces aa:bb:cc:dd:ee:01",
        })
        snapshot = self.store.protocol_snapshot(proto="arp")
        row = snapshot["packets"][0]
        self.assertEqual(row["arp_sender_mac"], "aa:bb:cc:dd:ee:01")
        self.assertEqual(row["arp_operation"], "reply")
        # And every column the snapshot declares must be readable off the row.
        for column in snapshot["columns"]:
            self.assertIn(column["key"], row, f"column {column['key']} is not on the row")

    def test_the_snapshot_declares_the_protocols_own_columns(self):
        self.store.register_packet({"proto": "arp", "src_ip": "10.0.0.1",
                                    "dst_ip": "10.0.0.2", "length": 60})
        keys = [c["key"] for c in self.store.protocol_snapshot(proto="arp")["columns"]]
        self.assertIn("arp_sender_mac", keys)
        self.assertNotIn("src_port", keys)

    def test_details_are_scoped_to_the_protocol_being_asked_about(self):
        self._http(http_server="nginx/1.24.0")
        self.store.register_packet(
            {"proto": "tls", "src_ip": "10.0.0.5", "dst_ip": "10.0.0.9",
             "length": 120, "tls_version": "TLS 1.3"}
        )
        http_keys = {f["key"] for f in self.store.protocol_snapshot(proto="http")["facets"]}
        tls_keys = {f["key"] for f in self.store.protocol_snapshot(proto="tls")["facets"]}
        self.assertIn("http_server", http_keys)
        self.assertNotIn("tls_version", http_keys)
        self.assertIn("tls_version", tls_keys)


class DetailsColumnMigrationTests(unittest.TestCase):
    def test_a_database_written_before_the_column_existed_still_opens(self):
        # Databases created by earlier versions have no details_json. Opening
        # one has to add the column rather than fail, and faceting a protocol
        # whose facets are detail-based must return empty series, not raise.
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "legacy.db"

        store = SniffStore(str(path))
        store.register_packet({"proto": "http", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
                               "length": 100, "http_method": "GET"})
        store.close()

        conn = sqlite3.connect(str(path))
        conn.execute("ALTER TABLE packets DROP COLUMN details_json")
        conn.commit()
        columns = {row[1] for row in conn.execute("PRAGMA table_info(packets)")}
        conn.close()
        self.assertNotIn("details_json", columns, "precondition: the column was not removed")

        reopened = SniffStore(str(path))
        self.addCleanup(reopened.close)
        columns = {row["name"] for row in reopened._conn.execute("PRAGMA table_info(packets)")}
        self.assertIn("details_json", columns)

        snapshot = reopened.protocol_snapshot(proto="http")
        self.assertEqual(_counts(_facet(snapshot, "http_server")), {})


if __name__ == "__main__":
    unittest.main()
