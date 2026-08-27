from __future__ import annotations

import ipaddress
import struct
import unittest
from unittest.mock import MagicMock

from sniff4hound.sniffer import (
    Sniffer,
    build_base_packet,
    decode_nbns_name,
    parse_dns_message,
)


def _build_dns_query(name: str = "example.com", qtype: int = 1) -> bytes:
    header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    question = b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\x00"
    question += struct.pack(">HH", qtype, 1)
    return header + question


def _build_dns_response(name: str = "example.com", ip: str = "93.184.216.34", rcode: int = 0) -> bytes:
    flags = 0x8000 | (rcode & 0x000F)
    header = struct.pack(">HHHHHH", 0x1234, flags, 1, 1, 0, 0)
    question = b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\x00"
    question += struct.pack(">HH", 1, 1)
    # Answer name uses a compression pointer back to the question at offset 12.
    answer = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 300, 4) + bytes(map(int, ip.split(".")))
    return header + question + answer


def _encode_nbns_name(name: str) -> bytes:
    padded = name.upper().ljust(15)[:15] + "\x00"
    out = bytearray()
    for ch in padded:
        byte = ord(ch)
        out.append(0x41 + (byte >> 4))
        out.append(0x41 + (byte & 0x0F))
    return bytes(out)


class TestParseDnsMessage(unittest.TestCase):
    def test_query(self):
        parsed = parse_dns_message(_build_dns_query("example.com"))
        self.assertFalse(parsed["is_response"])
        self.assertEqual(parsed["questions"][0]["name"], "example.com")
        self.assertEqual(parsed["questions"][0]["qtype"], 1)
        self.assertEqual(parsed["answers"], [])

    def test_response_with_compressed_answer_name(self):
        parsed = parse_dns_message(_build_dns_response("example.com", "93.184.216.34"))
        self.assertTrue(parsed["is_response"])
        self.assertEqual(parsed["rcode"], 0)
        self.assertEqual(parsed["answers"][0]["name"], "example.com")
        self.assertEqual(parsed["answers"][0]["rdata"], "93.184.216.34")
        self.assertEqual(parsed["answers"][0]["ttl"], 300)

    def test_nxdomain_response(self):
        parsed = parse_dns_message(_build_dns_response("nope.example.com", rcode=3))
        self.assertEqual(parsed["rcode"], 3)

    def test_garbage_does_not_raise(self):
        parsed = parse_dns_message(b"\x00\x01\x02")
        self.assertEqual(parsed["questions"], [])
        self.assertEqual(parsed["answers"], [])
        parsed = parse_dns_message(b"")
        self.assertEqual(parsed["questions"], [])

    def test_malicious_compression_loop_does_not_hang(self):
        # Two labels that point at each other — must not infinite-loop.
        header = struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0)
        payload = header + b"\xc0\x0c" + struct.pack(">HH", 1, 1)
        parsed = parse_dns_message(payload)  # should return promptly, not hang
        self.assertIsInstance(parsed, dict)


class TestDecodeNbnsName(unittest.TestCase):
    def test_round_trip(self):
        encoded = _encode_nbns_name("FILESERVER")
        self.assertEqual(decode_nbns_name(encoded), "FILESERVER")

    def test_wrong_length_returns_empty(self):
        self.assertEqual(decode_nbns_name(b"short"), "")

    def test_invalid_nibble_returns_empty(self):
        self.assertEqual(decode_nbns_name(b"\x00" * 32), "")


def _packet(**overrides) -> dict:
    packet = build_base_packet("now", "eth0", b"\x00" * 40, b"\x00" * 40)
    packet.update(overrides)
    return packet


class TestSnifferProtocolParsers(unittest.TestCase):
    def setUp(self):
        self.sniffer = Sniffer(MagicMock(), MagicMock(), interfaces=())

    def test_parse_dhcp_discover(self):
        options = bytearray()
        options += bytes([53, 1, 1])  # DHCPDISCOVER
        options += bytes([12, 4]) + b"host"
        options += bytes([50, 4]) + bytes(map(int, "10.0.0.50".split(".")))
        options += bytes([255])
        payload = bytes(240)
        payload = payload[:236] + b"\x63\x82\x53\x63" + bytes(options)
        packet = _packet()
        self.sniffer._parse_dhcp(packet, payload)
        self.assertEqual(packet["proto"], "dhcp")
        self.assertIn("DISCOVER", packet["summary"])
        self.assertIn("host=host", packet["summary"])
        self.assertIn("requested=10.0.0.50", packet["summary"])

    def test_parse_dhcp_missing_magic_cookie_falls_back(self):
        packet = _packet()
        self.sniffer._parse_dhcp(packet, b"\x00" * 240)
        self.assertEqual(packet["proto"], "dhcp")
        self.assertEqual(packet["summary"], "DHCP/BOOTP packet")

    def test_parse_udp_dispatches_dns(self):
        query = _build_dns_query("example.com")
        udp = struct.pack(">HHHH", 53000, 53, 8 + len(query), 0) + query
        packet = _packet(src_ip="10.0.0.1", dst_ip="8.8.8.8")
        self.sniffer._parse_udp(packet, udp)
        # DNS names itself, like every other decoded application protocol
        # here (mDNS/LLMNR/SNMP already did). The transport it rode on is
        # kept in `transport`, which is what rules written against
        # protocols:["udp"] now match on - see rule_matches_packet().
        self.assertEqual(packet["proto"], "dns")
        self.assertEqual(packet["transport"], "udp")
        self.assertEqual(packet["domain"], "example.com")
        self.assertIn("example.com", packet["summary"])

    def test_parse_udp_dispatches_dhcp(self):
        options = bytes([53, 1, 1, 255])
        dhcp_payload = bytes(236) + b"\x63\x82\x53\x63" + options
        udp = struct.pack(">HHHH", 68, 67, 8 + len(dhcp_payload), 0) + dhcp_payload
        packet = _packet()
        self.sniffer._parse_udp(packet, udp)
        self.assertEqual(packet["proto"], "dhcp")

    def test_parse_udp_dispatches_mdns(self):
        query = _build_dns_query("printer.local")
        udp = struct.pack(">HHHH", 5353, 5353, 8 + len(query), 0) + query
        packet = _packet()
        self.sniffer._parse_udp(packet, udp)
        self.assertEqual(packet["proto"], "mdns")
        self.assertEqual(packet["domain"], "printer.local")

    def test_parse_udp_dispatches_llmnr(self):
        query = _build_dns_query("myhost")
        udp = struct.pack(">HHHH", 5355, 5355, 8 + len(query), 0) + query
        packet = _packet()
        self.sniffer._parse_udp(packet, udp)
        self.assertEqual(packet["proto"], "llmnr")

    def test_parse_udp_dispatches_nbns(self):
        header = struct.pack(">HHHHHH", 1, 0x0110, 1, 0, 0, 0)
        name = _encode_nbns_name("WORKGROUP")
        nbns_payload = header + bytes([32]) + name + struct.pack(">HH", 0x20, 1)
        udp = struct.pack(">HHHH", 137, 137, 8 + len(nbns_payload), 0) + nbns_payload
        packet = _packet()
        self.sniffer._parse_udp(packet, udp)
        self.assertEqual(packet["proto"], "nbns")
        self.assertIn("WORKGROUP", packet["summary"])

    def test_parse_tcp_dispatches_dns_over_tcp(self):
        query = _build_dns_query("example.com")
        tcp_payload = struct.pack(">H", len(query)) + query
        tcp = bytearray(20)
        struct.pack_into(">HH", tcp, 0, 53001, 53)
        tcp[12] = 5 << 4  # data offset = 20 bytes
        packet = _packet()
        self.sniffer._parse_tcp(packet, bytes(tcp) + tcp_payload)
        self.assertEqual(packet["proto"], "dns")
        self.assertEqual(packet["transport"], "tcp")
        self.assertEqual(packet["domain"], "example.com")

    def test_parse_igmp_v2_report(self):
        body = bytes([0x16, 0, 0, 0]) + bytes(map(int, "239.1.1.1".split(".")))
        packet = _packet()
        self.sniffer._parse_igmp(packet, body)
        self.assertEqual(packet["proto"], "igmp")
        self.assertIn("239.1.1.1", packet["summary"])
        self.assertIn("v2 membership report", packet["summary"])

    def test_parse_gre_with_key(self):
        body = struct.pack(">HH", 0x2000, 0x0800) + struct.pack(">I", 0xDEADBEEF)
        packet = _packet()
        self.sniffer._parse_gre(packet, body)
        self.assertEqual(packet["proto"], "gre")
        self.assertIn("deadbeef", packet["summary"])
        self.assertIn("0x0800", packet["summary"])

    def test_parse_esp_extracts_spi_and_seq(self):
        body = struct.pack(">II", 0x1234, 99) + b"\x00" * 16
        packet = _packet()
        self.sniffer._parse_esp(packet, body, ip_version=4)
        self.assertEqual(packet["proto"], "esp")
        self.assertIn("00001234", packet["summary"])
        self.assertIn("seq=99", packet["summary"])

    def test_parse_ah_dispatches_inner_tcp(self):
        inner_tcp = bytearray(20)
        struct.pack_into(">HH", inner_tcp, 0, 51000, 443)
        inner_tcp[12] = 5 << 4
        ah = bytes([6, 1, 0, 0]) + struct.pack(">II", 0x5555, 7) + bytes(inner_tcp)
        packet = _packet(src_ip="1.2.3.4", dst_ip="5.6.7.8")
        self.sniffer._parse_ah(packet, ah, ip_version=4)
        # The inner segment is addressed to 443, so it is reported as TLS;
        # the AH envelope it arrived in is still described in the summary.
        self.assertEqual(packet["proto"], "tls")
        self.assertEqual(packet["transport"], "tcp")
        self.assertIn("AH SPI=0x00005555 seq=7", packet["summary"])

    def test_ipv4_dispatch_routes_igmp_gre_esp_ah(self):
        # Build a minimal IPv4 header (20 bytes, no options) around each body.
        def ipv4_header(proto: int, total_length: int) -> bytes:
            version_ihl = (4 << 4) | 5
            header = bytearray(20)
            header[0] = version_ihl
            struct.pack_into(">H", header, 2, total_length)
            header[8] = 64
            header[9] = proto
            header[12:16] = bytes(map(int, "10.0.0.1".split(".")))
            header[16:20] = bytes(map(int, "10.0.0.2".split(".")))
            # Fix checksum so _looks_like_raw_ipv4 (used elsewhere) would accept it;
            # not required for _parse_ipv4 itself, which is called directly here.
            return bytes(header)

        igmp_body = bytes([0x11, 0, 0, 0]) + bytes(4)
        packet = _packet()
        self.sniffer._parse_ipv4(packet, ipv4_header(2, 20 + len(igmp_body)) + igmp_body)
        self.assertEqual(packet["proto"], "igmp")

        gre_body = struct.pack(">HH", 0, 0x0800)
        packet = _packet()
        self.sniffer._parse_ipv4(packet, ipv4_header(47, 20 + len(gre_body)) + gre_body)
        self.assertEqual(packet["proto"], "gre")

        esp_body = struct.pack(">II", 1, 1) + b"\x00" * 8
        packet = _packet()
        self.sniffer._parse_ipv4(packet, ipv4_header(50, 20 + len(esp_body)) + esp_body)
        self.assertEqual(packet["proto"], "esp")

        ah_body = bytes([17, 1, 0, 0]) + struct.pack(">II", 1, 1) + struct.pack(">HHHH", 1, 2, 8, 0)
        packet = _packet()
        self.sniffer._parse_ipv4(packet, ipv4_header(51, 20 + len(ah_body)) + ah_body)
        self.assertEqual(packet["proto"], "udp")  # AH-authenticated UDP, dispatched through

    def test_ipv6_ah_and_esp_via_unwrap(self):
        def ipv6_header(next_header: int, payload: bytes) -> bytes:
            header = bytearray(40)
            header[0] = 6 << 4
            struct.pack_into(">H", header, 4, len(payload))
            header[6] = next_header
            header[7] = 64
            header[8:24] = ipaddress.IPv6Address("2001:db8::1").packed
            header[24:40] = ipaddress.IPv6Address("2001:db8::2").packed
            return bytes(header) + payload

        inner_udp = struct.pack(">HHHH", 1234, 53, 8, 0)
        ah_payload = bytes([17, 1, 0, 0]) + struct.pack(">II", 1, 1) + inner_udp
        packet = _packet()
        self.sniffer._parse_ipv6(packet, ipv6_header(51, ah_payload))
        # Inner datagram is UDP/53, so the application protocol is DNS.
        self.assertEqual(packet["proto"], "dns")
        self.assertEqual(packet["transport"], "udp")
        self.assertIn("AH SPI=", packet["summary"])

        esp_payload = struct.pack(">II", 2, 2) + b"\x00" * 8
        packet = _packet()
        self.sniffer._parse_ipv6(packet, ipv6_header(50, esp_payload))
        self.assertEqual(packet["proto"], "esp")


if __name__ == "__main__":
    unittest.main()
