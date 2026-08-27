"""Content decoding for identified application protocols.

Naming a protocol is not the same as supporting it: without a decoder an
SSH or NTP slice renders as rows of "TCP 10.0.0.1:50000 -> 10.0.0.2:22" and
tells an analyst nothing. These tests pin what each decoder extracts, and -
more importantly - that none of them can be made to raise on hostile input,
since the capture loop turns an exception into an unparseable frame and the
traffic then disappears from the view entirely.
"""

from __future__ import annotations

import os
import struct
import tempfile
import unittest

from sniff4hound.app_decoders import DECODERS, decode


class DecoderFieldTests(unittest.TestCase):
    def test_tls_reports_record_and_handshake_type(self):
        fields = decode("tls", b"\x16\x03\x01\x00\x50\x01\x00\x00L\x03\x03")
        self.assertEqual(fields["tls_record"], "handshake")
        self.assertEqual(fields["tls_handshake"], "client-hello")

    def test_ssh_reports_the_software_banner(self):
        fields = decode("ssh", b"SSH-2.0-OpenSSH_9.6p1 Debian-1\r\n")
        self.assertEqual(fields["ssh_version"], "2.0")
        self.assertEqual(fields["ssh_software"], "OpenSSH_9.6p1 Debian-1")

    def test_http_request_and_response_are_both_decoded(self):
        request = decode("http", b"GET /admin HTTP/1.1\r\nHost: intranet.local\r\n\r\n")
        self.assertEqual(request["http_method"], "GET")
        self.assertEqual(request["http_host"], "intranet.local")
        response = decode("http", b"HTTP/1.1 401 Unauthorized\r\nServer: nginx/1.24.0\r\n\r\n")
        self.assertEqual(response["http_status"], "401")
        self.assertEqual(response["http_server"], "nginx/1.24.0")

    def test_ntp_private_mode_is_flagged_as_an_amplification_vector(self):
        # Mode 7 carries monlist, the request behind ~500x NTP reflection.
        fields = decode("ntp", bytes([0x17]) + b"\x00" * 47)
        self.assertTrue(fields["ntp_amplification_candidate"])
        self.assertIn("amplification", fields["summary"])

    def test_ntp_normal_client_is_not_flagged(self):
        fields = decode("ntp", bytes([0x1B, 3]) + b"\x00" * 46)
        self.assertNotIn("ntp_amplification_candidate", fields)
        self.assertEqual(fields["ntp_mode"], "client")

    def test_multiline_smtp_status_is_not_read_as_a_command(self):
        # "250-text" is a continuation line, not a command named 250-TEXT.
        self.assertEqual(decode("smtp", b"250-mail.example.com Hello\r\n")["smtp_status"], "250")
        self.assertEqual(decode("smtp", b"EHLO client.local\r\n")["smtp_command"], "EHLO")

    def test_smb_reports_dialect_and_command(self):
        header = b"\x00\x00\x00\x40" + b"\xfeSMB" + b"\x40\x00\x00\x00" + b"\x00" * 4 + b"\x05\x00" + b"\x00" * 48
        fields = decode("smb", header)
        self.assertEqual(fields["smb_version"], "SMB2")
        self.assertEqual(fields["smb_command"], "CREATE")

    def test_bgp_message_type(self):
        self.assertEqual(decode("bgp", b"\xff" * 16 + b"\x00\x13\x04")["bgp_message"], "KEEPALIVE")

    def test_vxlan_reports_the_vni(self):
        self.assertEqual(decode("vxlan", b"\x08\x00\x00\x00\x00\x12\x34\x00")["vxlan_vni"], 0x1234)

    def test_lldp_reports_the_neighbour_identity(self):
        # TLV 5 (system-name) then TLV 2 (port-id, subtype byte first).
        name = b"switch-core-1"
        port = b"\x05Gi1/0/24"
        payload = (
            struct.pack("!H", (5 << 9) | len(name)) + name
            + struct.pack("!H", (2 << 9) | len(port)) + port
            + b"\x00\x00"
        )
        fields = decode("lldp", payload)
        self.assertEqual(fields["lldp_system_name"], "switch-core-1")
        self.assertEqual(fields["lldp_port_id"], "Gi1/0/24")

    def test_unknown_protocol_decodes_to_nothing(self):
        self.assertEqual(decode("definitely-not-a-protocol", b"anything"), {})

    def test_payload_that_does_not_match_returns_nothing(self):
        # Port-derived identification is a guess; a decoder must not invent a
        # decode for bytes that are plainly not its protocol.
        self.assertEqual(decode("ssh", b"not an ssh banner"), {})
        self.assertEqual(decode("bgp", b"\x00" * 32), {})


class DecoderRobustnessTests(unittest.TestCase):
    """No decoder may raise. The capture loop records an exception as an
    unparseable frame, so a decoder that trips on hostile bytes turns that
    traffic into a blind spot instead of a decoded row."""

    HOSTILE = (
        b"",
        b"\x00",
        b"\xff" * 4,
        b"\xff" * 4096,
        bytes(range(256)),
        b"\x30\x82\xff\xff" + b"\x00" * 8,     # ASN.1 claiming a huge length
        b"\x16\x03\x01\xff\xff",               # TLS record claiming a huge length
        struct.pack("!H", (5 << 9) | 0x1FF),   # LLDP TLV claiming 511 bytes it lacks
    )

    def test_no_decoder_raises_on_hostile_input(self):
        for proto in DECODERS:
            for payload in self.HOSTILE:
                with self.subTest(proto=proto, payload=payload[:8]):
                    self.assertIsInstance(decode(proto, payload), dict)

    def test_random_payloads_never_raise(self):
        for proto in DECODERS:
            for _ in range(20):
                self.assertIsInstance(decode(proto, os.urandom(64)), dict)


class SnifferIntegrationTests(unittest.TestCase):
    """Decoded fields have to survive the real parse path."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        from sniff4hound.sniffer import Sniffer
        from sniff4hound.store import SniffStore

        class _Hub:
            def broadcast(self, *args, **kwargs):
                pass

        store = SniffStore(os.path.join(self._tmp.name, "decode.db"))
        self.addCleanup(store.close)
        self.sniffer = Sniffer(store, _Hub())

    def _tcp_frame(self, dst_port: int, payload: bytes) -> bytes:
        tcp = bytearray(20)
        struct.pack_into("!HH", tcp, 0, 50000, dst_port)
        tcp[12] = 5 << 4
        total = 20 + 20 + len(payload)
        ip = (
            bytes([0x45, 0]) + struct.pack("!H", total) + bytes([0, 0, 0, 0, 64, 6, 0, 0])
            + bytes([10, 0, 0, 1]) + bytes([10, 0, 0, 2])
        )
        return bytes.fromhex("aabbccddeeff") + bytes.fromhex("112233445566") + b"\x08\x00" + ip + bytes(tcp) + payload

    def test_ssh_banner_reaches_the_packet(self):
        packet = self.sniffer.parse_packet(
            self._tcp_frame(22, b"SSH-2.0-OpenSSH_9.6p1 Debian-1\r\n"), interface="eth0"
        )
        self.assertEqual(packet["proto"], "ssh")
        self.assertEqual(packet["ssh_software"], "OpenSSH_9.6p1 Debian-1")
        self.assertIn("OpenSSH", packet["summary"])

    def test_http_host_survives_the_legacy_extractor(self):
        # _parse_tcp runs extract_http_request() after the decoder; it must
        # not overwrite a decoded host with an empty one.
        packet = self.sniffer.parse_packet(
            self._tcp_frame(80, b"GET /admin HTTP/1.1\r\nHost: intranet.local\r\n\r\n"), interface="eth0"
        )
        self.assertEqual(packet["http_host"], "intranet.local")

    def test_a_decoder_failure_never_loses_the_packet(self):
        packet = self.sniffer.parse_packet(self._tcp_frame(22, b"\xff" * 64), interface="eth0")
        self.assertEqual(packet["proto"], "ssh")  # port-derived, decoder declined
        self.assertTrue(packet["summary"])


if __name__ == "__main__":
    unittest.main()
