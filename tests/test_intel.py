from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from sniff4hound.sniffer import (
    Sniffer,
    extract_dns_query_name,
    extract_http_request,
    extract_tls_sni,
)
from sniff4hound.store import SniffStore
from sniff4hound.utils import normalize_text


def _build_dns_query(name: str = "example.com") -> bytes:
    header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    question = b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\x00"
    question += struct.pack(">HH", 1, 1)
    return header + question


def _build_dns_response(name: str = "example.com") -> bytes:
    # QR bit set (0x8000) marks this as a response echoing the same question.
    header = struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
    question = b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\x00"
    question += struct.pack(">HH", 1, 1)
    answer = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + bytes([93, 184, 216, 34])
    return header + question + answer


def _build_tls_client_hello(sni: str = "example.com") -> bytes:
    server_name = sni.encode()
    sni_entry = b"\x00" + struct.pack(">H", len(server_name)) + server_name
    sni_list = struct.pack(">H", len(sni_entry)) + sni_entry
    ext_server_name = struct.pack(">HH", 0x0000, len(sni_list)) + sni_list
    session_id = b""
    cipher_suites = b"\x00\x35"
    compression_methods = b"\x00"
    body = (
        b"\x03\x03"
        + b"\x00" * 32
        + bytes([len(session_id)])
        + session_id
        + struct.pack(">H", len(cipher_suites))
        + cipher_suites
        + bytes([len(compression_methods)])
        + compression_methods
        + struct.pack(">H", len(ext_server_name))
        + ext_server_name
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake


class TestExtractionHelpers(unittest.TestCase):
    def test_extract_dns_query_name(self):
        self.assertEqual(extract_dns_query_name(_build_dns_query("example.com")), "example.com")

    def test_extract_dns_query_name_handles_garbage(self):
        self.assertEqual(extract_dns_query_name(b"\x00\x01\x02"), "")
        self.assertEqual(extract_dns_query_name(b""), "")

    def test_extract_dns_query_name_ignores_responses(self):
        # A response's src/dst are reversed from the query (resolver -> client);
        # extracting from it would record the client's own IP/ephemeral port
        # as if it were the resolver. Only queries should be extracted.
        self.assertEqual(extract_dns_query_name(_build_dns_response("example.com")), "")

    def test_extract_tls_sni(self):
        self.assertEqual(extract_tls_sni(_build_tls_client_hello("secure.example.org")), "secure.example.org")

    def test_extract_tls_sni_ignores_non_handshake(self):
        self.assertEqual(extract_tls_sni(b"\x17\x03\x01\x00\x05hello"), "")
        self.assertEqual(extract_tls_sni(b""), "")

    def test_extract_http_request(self):
        text = "POST /api/login HTTP/1.1\r\nHost: portal.example.net\r\nContent-Length: 4\r\n\r\nuser"
        method, path, host = extract_http_request(text)
        self.assertEqual(method, "POST")
        self.assertEqual(path, "/api/login")
        self.assertEqual(host, "portal.example.net")

    def test_extract_http_request_no_match(self):
        self.assertEqual(extract_http_request("not an http request"), ("", "", ""))
        self.assertEqual(extract_http_request(""), ("", "", ""))

    def test_extract_http_request_finds_host_in_normalized_payload_text(self):
        # Regression: the sniffer calls extract_http_request() with
        # `packet["payload_text"]`, which normalize_text() has already
        # flattened to a single line. A `^Host:` anchor under re.MULTILINE
        # then never matched, so http_host came back empty for every HTTP
        # request and no HTTP-derived domain ever reached the catalog.
        raw = "GET /login HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.0\r\n\r\n"
        flattened = normalize_text(raw, limit=4096)
        self.assertNotIn("\n", flattened)
        self.assertEqual(extract_http_request(flattened), ("GET", "/login", "example.com"))
        # The raw CRLF form must keep working too.
        self.assertEqual(extract_http_request(raw), ("GET", "/login", "example.com"))

    def test_extract_http_request_ignores_x_forwarded_host(self):
        raw = "GET / HTTP/1.1\r\nX-Forwarded-Host: evil.test\r\nHost: real.example\r\n\r\n"
        self.assertEqual(extract_http_request(normalize_text(raw, limit=4096))[2], "real.example")

    def test_extract_http_request_keeps_host_port(self):
        raw = "GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n"
        self.assertEqual(extract_http_request(normalize_text(raw, limit=4096))[2], "example.com:8080")


class TestStoreIntelCatalogs(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test.db"
        self.store = SniffStore(self.db_path)

    def tearDown(self):
        self.store.close()
        self.temp_dir.cleanup()

    def test_record_domain_upserts_and_increments_hit_count(self):
        self.store.record_domain(name="Example.COM", source="dns", ip="10.0.0.1", port=53, proto="udp")
        self.store.record_domain(name="example.com", source="dns", ip="10.0.0.1", port=53, proto="udp")
        rows = self.store.list_domains()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["name"], "example.com")
        self.assertEqual(rows[0]["hit_count"], 2)

    def test_register_packet_persists_domain_and_http_fields(self):
        saved = self.store.register_packet(
            {
                "src_ip": "10.0.0.5",
                "dst_ip": "93.184.216.34",
                "proto": "tcp",
                "src_port": 51234,
                "dst_port": 80,
                "length": 100,
                "payload_len": 50,
                "domain": "Shop.Example.com",
                "domain_source": "http_host",
                "http_method": "get",
                "http_path": "/widgets",
                "http_host": "Shop.Example.com",
            }
        )
        self.assertEqual(saved["domain"], "shop.example.com")
        self.assertEqual(saved["domain_source"], "http_host")
        self.assertEqual(saved["http_method"], "GET")
        self.assertEqual(saved["http_path"], "/widgets")
        self.assertEqual(saved["http_host"], "shop.example.com")

    def test_migration_adds_domain_columns_to_legacy_packets_table(self):
        with self.store._lock:
            # A genuinely legacy database predates these columns, so it has
            # no index over them either. SQLite refuses to DROP a column an
            # existing index still references, so drop the index first to
            # reproduce that older shape faithfully.
            self.store._conn.execute("DROP INDEX IF EXISTS idx_packets_domain")
            self.store._conn.execute("ALTER TABLE packets DROP COLUMN domain")
            self.store._conn.execute("ALTER TABLE packets DROP COLUMN http_path")
            self.store._conn.commit()
        # Re-running schema creation (as __init__ does on every open) must restore the columns.
        self.store._create_schema()
        columns = {row["name"] for row in self.store._conn.execute("PRAGMA table_info(packets)")}
        self.assertIn("domain", columns)
        self.assertIn("http_path", columns)
        # The index has to come back too, otherwise every domain lookup on an
        # upgraded database silently degrades to a full table scan.
        indexes = {row["name"] for row in self.store._conn.execute("PRAGMA index_list(packets)")}
        self.assertIn("idx_packets_domain", indexes)

    def test_list_domains_search_filters(self):
        self.store.record_domain(name="api.example.com", source="tls_sni")
        self.store.record_domain(name="tracker.ads.net", source="tls_sni")
        rows = self.store.list_domains(search="example")
        self.assertEqual([row["name"] for row in rows], ["api.example.com"])

    def test_record_path_upserts_and_increments_hit_count(self):
        self.store.record_path(path="/login", method="post", host="example.com", ip="10.0.0.1", port=443)
        self.store.record_path(path="/login", method="POST", host="example.com", ip="10.0.0.1", port=443)
        rows = self.store.list_paths()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["hit_count"], 2)
        self.assertEqual(rows[0]["method"], "POST")

    def test_record_path_distinguishes_by_method_and_host(self):
        self.store.record_path(path="/login", method="GET", host="a.example.com")
        self.store.record_path(path="/login", method="POST", host="a.example.com")
        self.store.record_path(path="/login", method="GET", host="b.example.com")
        self.assertEqual(len(self.store.list_paths()), 3)

    def test_list_ip_catalog_aggregates_src_and_dst(self):
        self.store.register_packet(
            {
                "src_ip": "10.0.0.5",
                "dst_ip": "10.0.0.9",
                "proto": "tcp",
                "src_port": 1111,
                "dst_port": 2222,
                "length": 60,
                "payload_len": 0,
            }
        )
        rows = self.store.list_ip_catalog()
        ips = {row["ip"] for row in rows}
        self.assertEqual(ips, {"10.0.0.5", "10.0.0.9"})
        for row in rows:
            self.assertTrue(row["private"])

    def test_list_ip_catalog_search(self):
        self.store.register_packet(
            {"src_ip": "10.0.0.5", "dst_ip": "8.8.8.8", "proto": "udp", "src_port": 1, "dst_port": 53, "length": 40}
        )
        rows = self.store.list_ip_catalog(search="8.8.8.8")
        self.assertEqual([row["ip"] for row in rows], ["8.8.8.8"])


class TestSnifferIntelIntegration(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test.db"
        self.store = SniffStore(self.db_path)
        self.sniffer = Sniffer(self.store, MagicMock(), interfaces=())

    def tearDown(self):
        self.store.close()
        self.temp_dir.cleanup()

    def _base_packet(self, **overrides) -> dict:
        packet = {
            "session_id": 0,
            "interface": "test0",
            "eth_src": "",
            "eth_dst": "",
            "eth_type": 0x0800,
            "ip_version": 4,
            "src_ip": "10.0.0.5",
            "dst_ip": "93.184.216.34",
            "proto": "tcp",
            "src_port": 51234,
            "dst_port": 80,
            "ttl": 64,
            "hop_limit": 0,
            "length": 200,
            "payload_len": 80,
            "state": "open",
            "scan_state": "active",
            "tcp_flags": "",
            "icmp_type": 0,
            "icmp_code": 0,
            "arp_opcode": 0,
            "summary": "",
            "payload_text": "",
            "payload_hex": "",
            "banner_text": "",
            "domain": "",
            "domain_source": "",
            "http_method": "",
            "http_path": "",
            "http_host": "",
            "raw_packet": b"",
        }
        packet.update(overrides)
        return packet

    def test_http_request_populates_domains_and_paths(self):
        packet = self._base_packet(
            payload_text="GET /widgets HTTP/1.1\r\nHost: shop.example.com\r\n\r\n",
            http_method="GET",
            http_path="/widgets",
            http_host="shop.example.com",
            domain="shop.example.com",
            domain_source="http_host",
        )
        self.sniffer._store_packet(packet)
        domains = self.store.list_domains()
        paths = self.store.list_paths()
        self.assertEqual([row["name"] for row in domains], ["shop.example.com"])
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0]["path"], "/widgets")
        self.assertEqual(paths[0]["method"], "GET")

    def test_undetected_packet_does_not_record_intel(self):
        packet = self._base_packet(
            dst_port=9999,
            domain="should-not-be-stored.example",
            domain_source="http_host",
        )
        self.sniffer._store_packet(packet)
        self.assertEqual(self.store.list_domains(), [])

    def test_parse_udp_extracts_dns_domain(self):
        dns_query = _build_dns_query("resolved.example.com")
        udp_body = struct.pack(">HHHH", 51234, 53, 8 + len(dns_query), 0) + dns_query
        packet = self._base_packet(proto="unknown", src_port=0, dst_port=0)
        self.sniffer._parse_udp(packet, udp_body)
        self.assertEqual(packet["domain"], "resolved.example.com")
        self.assertEqual(packet["domain_source"], "dns")

    def test_parse_tcp_extracts_tls_sni(self):
        client_hello = _build_tls_client_hello("handshake.example.net")
        tcp_body = (
            struct.pack(">HH", 51234, 443)
            + (0).to_bytes(4, "big")
            + (0).to_bytes(4, "big")
            + bytes([0x50, 0x18])
            + b"\x00" * 6
            + client_hello
        )
        packet = self._base_packet(proto="unknown", src_port=0, dst_port=0)
        self.sniffer._parse_tcp(packet, tcp_body)
        self.assertEqual(packet["domain"], "handshake.example.net")
        self.assertEqual(packet["domain_source"], "tls_sni")


if __name__ == "__main__":
    unittest.main()
