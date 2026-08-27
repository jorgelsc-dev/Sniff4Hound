from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from sniff4hound.sniffer import Sniffer
from sniff4hound.store import SniffStore


class ProtocolParsingTestCase(unittest.TestCase):
    """Base fixture: a Sniffer instance backed by a scratch SQLite store, used
    to call the individual `_parse_<protocol>` methods directly with hand
    -built payload bytes rather than full Ethernet/IP frames."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test.db"
        self.store = SniffStore(self.db_path)
        self.sniffer = Sniffer(self.store, MagicMock(), interfaces=())

    def tearDown(self):
        self.store.close()
        self.temp_dir.cleanup()

    def _packet(self) -> dict:
        return {"src_ip": "10.0.0.5", "dst_ip": "10.0.0.1"}


class TestModbusParsing(ProtocolParsingTestCase):
    def _mbap(self, *, unit_id: int, function_code: int, extra: bytes = b"") -> bytes:
        # Transaction ID(2) + Protocol ID(2, 0) + Length(2) + Unit ID(1) + Function Code(1)
        return b"\x00\x01\x00\x00\x00\x02" + bytes([unit_id, function_code]) + extra

    def test_read_holding_registers_is_not_a_write(self):
        packet = self._packet()
        self.sniffer._parse_modbus(packet, self._mbap(unit_id=1, function_code=3))
        self.assertEqual(packet["proto"], "modbus")
        self.assertFalse(packet["modbus_is_write"])
        self.assertEqual(packet["modbus_function_code"], 3)
        self.assertIn("read-holding-registers", packet["summary"])

    def test_write_single_coil_is_flagged_as_write(self):
        packet = self._packet()
        self.sniffer._parse_modbus(packet, self._mbap(unit_id=1, function_code=5))
        self.assertTrue(packet["modbus_is_write"])
        self.assertIn("write-single-coil", packet["summary"])
        self.assertIn("(write)", packet["summary"])

    def test_write_multiple_registers_is_flagged_as_write(self):
        packet = self._packet()
        self.sniffer._parse_modbus(packet, self._mbap(unit_id=7, function_code=16))
        self.assertTrue(packet["modbus_is_write"])
        self.assertEqual(packet["modbus_unit_id"], 7)

    def test_exception_response_decoded(self):
        packet = self._packet()
        self.sniffer._parse_modbus(packet, self._mbap(unit_id=1, function_code=0x83, extra=b"\x02"))
        self.assertIn("EXCEPTION", packet["summary"])

    def test_truncated_frame_does_not_raise(self):
        packet = self._packet()
        self.sniffer._parse_modbus(packet, b"\x00\x01")
        self.assertEqual(packet["proto"], "modbus")
        self.assertEqual(packet["summary"], "Modbus packet")


class TestDnp3Parsing(ProtocolParsingTestCase):
    def _frame(self, *, function_code: int) -> bytes:
        # Data-link header (10B): start(2) + length(1) + control(1) + dest(2,LE) + src(2,LE) + CRC(2)
        header = b"\x05\x64\x0a\xc4" + (7).to_bytes(2, "little") + (1024).to_bytes(2, "little") + b"\x00\x00"
        # Transport(1) + Application Control(1) + Function Code(1)
        app = b"\xc0\xc0" + bytes([function_code])
        return header + app

    def test_cold_restart_is_decoded(self):
        packet = self._packet()
        self.sniffer._parse_dnp3(packet, self._frame(function_code=13))
        self.assertEqual(packet["proto"], "dnp3")
        self.assertEqual(packet["dnp3_function_code"], 13)
        self.assertIn("cold-restart", packet["summary"])
        self.assertEqual(packet["dnp3_src"], 1024)
        self.assertEqual(packet["dnp3_dest"], 7)

    def test_unsolicited_response_is_decoded(self):
        packet = self._packet()
        self.sniffer._parse_dnp3(packet, self._frame(function_code=130))
        self.assertIn("unsolicited-response", packet["summary"])

    def test_missing_start_bytes_falls_back(self):
        packet = self._packet()
        self.sniffer._parse_dnp3(packet, b"\x00" * 12)
        self.assertEqual(packet["summary"], "DNP3 packet")


class TestSnmpParsing(ProtocolParsingTestCase):
    def _message(self, *, version: int, community: bytes) -> bytes:
        version_tlv = b"\x02\x01" + bytes([version])
        community_tlv = b"\x04" + bytes([len(community)]) + community
        pdu = b"\xa0\x00"  # empty GetRequest PDU, just enough to not be truncated
        body = version_tlv + community_tlv + pdu
        return b"\x30" + bytes([len(body)]) + body

    def test_v1_community_string_extracted(self):
        packet = self._packet()
        self.sniffer._parse_snmp(packet, self._message(version=0, community=b"public"))
        self.assertEqual(packet["proto"], "snmp")
        self.assertEqual(packet["snmp_version"], "v1")
        self.assertEqual(packet["snmp_community"], "public")
        self.assertIn("community='public'", packet["summary"])

    def test_v2c_community_string_extracted(self):
        packet = self._packet()
        self.sniffer._parse_snmp(packet, self._message(version=1, community=b"private"))
        self.assertEqual(packet["snmp_version"], "v2c")
        self.assertEqual(packet["snmp_community"], "private")

    def test_not_a_sequence_falls_back(self):
        packet = self._packet()
        self.sniffer._parse_snmp(packet, b"\x00\x01\x02")
        self.assertEqual(packet["summary"], "SNMP packet")


class TestSyslogParsing(ProtocolParsingTestCase):
    def test_pri_facility_and_severity_decoded(self):
        # PRI 165 = facility 20 (local4) * 8 + severity 5 (notice)
        packet = self._packet()
        self.sniffer._parse_syslog(packet, b"<165>host sshd: Failed password for root")
        self.assertEqual(packet["proto"], "syslog")
        self.assertEqual(packet["syslog_facility"], 20)
        self.assertEqual(packet["syslog_severity"], "notice")
        self.assertIn("Failed password for root", packet["summary"])

    def test_message_without_pri_still_captured(self):
        packet = self._packet()
        self.sniffer._parse_syslog(packet, b"plain text log line, no PRI header")
        self.assertNotIn("syslog_severity", packet)
        self.assertIn("plain text log line", packet["summary"])


class TestTftpParsing(ProtocolParsingTestCase):
    def test_read_request_extracts_filename_and_mode(self):
        packet = self._packet()
        payload = b"\x00\x01" + b"firmware.bin\x00" + b"octet\x00"
        self.sniffer._parse_tftp(packet, payload)
        self.assertEqual(packet["proto"], "tftp")
        self.assertEqual(packet["tftp_filename"], "firmware.bin")
        self.assertIn("RRQ", packet["summary"])
        self.assertIn("mode=octet", packet["summary"])

    def test_ack_opcode_has_no_filename(self):
        packet = self._packet()
        self.sniffer._parse_tftp(packet, b"\x00\x04\x00\x01")
        self.assertIn("ACK", packet["summary"])
        self.assertNotIn("tftp_filename", packet)


class TestRadiusParsing(ProtocolParsingTestCase):
    def _access_request(self, *, username: bytes) -> bytes:
        header = bytes([1, 1]) + (20 + 2 + len(username)).to_bytes(2, "big") + b"\x00" * 16
        user_attr = bytes([1, 2 + len(username)]) + username
        return header + user_attr

    def test_username_extracted_from_access_request(self):
        packet = self._packet()
        self.sniffer._parse_radius(packet, self._access_request(username=b"jdoe"))
        self.assertEqual(packet["proto"], "radius")
        self.assertEqual(packet["radius_username"], "jdoe")
        self.assertIn("Access-Request", packet["summary"])

    def test_truncated_header_falls_back(self):
        packet = self._packet()
        self.sniffer._parse_radius(packet, b"\x01\x01\x00\x14")
        self.assertEqual(packet["summary"], "RADIUS packet")


class TestMqttParsing(ProtocolParsingTestCase):
    def _connect_packet(self, *, client_id: str, username: str = "", password: bool = False) -> bytes:
        protocol_name = b"\x00\x04MQTT"
        protocol_level = b"\x04"
        flags = 0x02  # clean session
        if username:
            flags |= 0x80
        if password:
            flags |= 0x40
        keep_alive = b"\x00\x3c"
        client_id_bytes = client_id.encode("utf-8")
        variable_and_payload = protocol_name + protocol_level + bytes([flags]) + keep_alive
        variable_and_payload += len(client_id_bytes).to_bytes(2, "big") + client_id_bytes
        if username:
            username_bytes = username.encode("utf-8")
            variable_and_payload += len(username_bytes).to_bytes(2, "big") + username_bytes
        if password:
            password_bytes = b"hunter2"
            variable_and_payload += len(password_bytes).to_bytes(2, "big") + password_bytes
        fixed_header = bytes([0x10]) + bytes([len(variable_and_payload)])
        return fixed_header + variable_and_payload

    def test_connect_extracts_client_id(self):
        packet = self._packet()
        self.sniffer._parse_mqtt(packet, self._connect_packet(client_id="sensor-42"))
        self.assertEqual(packet["proto"], "mqtt")
        self.assertEqual(packet["mqtt_client_id"], "sensor-42")
        self.assertIn("CONNECT", packet["summary"])

    def test_connect_flags_cleartext_credentials(self):
        packet = self._packet()
        self.sniffer._parse_mqtt(
            packet, self._connect_packet(client_id="sensor-42", username="admin", password=True)
        )
        self.assertEqual(packet["mqtt_username"], "admin")
        self.assertIn("password=<present>", packet["summary"])

    def test_connect_without_credentials_has_no_password_marker(self):
        packet = self._packet()
        self.sniffer._parse_mqtt(packet, self._connect_packet(client_id="sensor-42"))
        self.assertNotIn("mqtt_username", packet)
        self.assertNotIn("password=<present>", packet["summary"])

    def test_pingreq_has_no_client_id_field(self):
        packet = self._packet()
        self.sniffer._parse_mqtt(packet, bytes([0xC0, 0x00]))
        self.assertIn("PINGREQ", packet["summary"])
        self.assertNotIn("mqtt_client_id", packet)


if __name__ == "__main__":
    unittest.main()
