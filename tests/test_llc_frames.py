from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from sniff4hound.sniffer import Sniffer
from sniff4hound.store import SniffStore

DST = "8ce9eeb690c7"
SRC = "eee7ab1ecf1b"


class LlcFrameTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        store = SniffStore(Path(tmp.name) / "llc.db")
        self.addCleanup(store.close)
        self.sniffer = Sniffer(store, MagicMock(), interfaces=[])

    def _parse(self, hexstr):
        return self.sniffer.parse_packet(bytes.fromhex(hexstr), interface="wlan0")

    def test_length_field_is_not_read_as_an_ethertype(self):
        # Real capture that used to land as proto "unknown" with the summary
        # "EtherType 0x0006": 0x0006 is the 802.3 length field, and it matches
        # the 6 payload bytes exactly.
        packet = self._parse(f"{DST}{SRC}00060001af810102")
        self.assertNotEqual(packet["proto"], "unknown")
        self.assertNotIn("EtherType 0x0006", packet["summary"])
        self.assertEqual(packet["llc_length"], 6)

    def test_decodes_the_llc_header_of_that_frame(self):
        packet = self._parse(f"{DST}{SRC}00060001af810102")
        self.assertEqual(packet["llc_dsap"], 0x00)
        self.assertEqual(packet["llc_ssap"], 0x01)
        self.assertEqual(packet["llc_control"], 0xAF)
        self.assertEqual(packet["proto"], "llc-null")
        self.assertIn("DSAP 0x00", packet["summary"])
        self.assertIn("SSAP 0x01", packet["summary"])

    def test_snap_frames_delegate_to_the_real_ethertype(self):
        # SNAP (AA AA 03) + zero OUI + 0x0806 must come out as ARP, not as a
        # generic LLC frame.
        frame = f"ffffffffffff{SRC}" + "0020" + "aaaa03" + "000000" + "0806" + "0001080006040001"
        packet = self._parse(frame)
        self.assertEqual(packet["proto"], "arp")
        self.assertEqual(packet["llc_snap_ethertype"], 0x0806)
        self.assertEqual(packet["llc_snap_oui"], "00:00:00")

    def test_snap_with_an_unknown_ethertype_stays_labelled(self):
        # Deliberately not OUI 00:00:0c / type 0x2000 - that pair is Cisco's
        # CDP, which this parser now names (see the test below). An example
        # meant to stand for "unrecognised" has to actually be unrecognised.
        frame = f"ffffffffffff{SRC}" + "0010" + "aaaa03" + "00abcd" + "9999" + "deadbeef"
        packet = self._parse(frame)
        self.assertEqual(packet["proto"], "llc-snap")
        self.assertIn("00:ab:cd", packet["summary"])
        self.assertIn("0x9999", packet["summary"])

    def test_snap_names_cisco_discovery_protocol(self):
        # CDP has no EtherType of its own: it is addressed by the Cisco OUI
        # plus a protocol id inside SNAP, so this is the only place it can be
        # identified.
        frame = f"01000ccccccc{SRC}" + "0010" + "aaaa03" + "00000c" + "2000" + "02b4000000000000"
        packet = self._parse(frame)
        self.assertEqual(packet["proto"], "cdp")

    def test_named_saps_appear_in_the_protocol(self):
        for dsap, expected in ((0xE0, "llc-ipx"), (0xF0, "llc-netbios"), (0xFE, "llc-osi")):
            packet = self._parse(f"{DST}{SRC}0005{dsap:02x}{dsap:02x}03aabb")
            self.assertEqual(packet["proto"], expected, f"DSAP 0x{dsap:02x}")

    def test_a_truncated_llc_header_does_not_raise(self):
        packet = self._parse(f"{DST}{SRC}000201")
        self.assertEqual(packet["proto"], "llc")
        self.assertIn("truncated", packet["summary"])

    def test_stp_still_parses_as_stp(self):
        # STP arrives as 802.3 too; it is matched earlier by its multicast MAC
        # and 42:42:03 header, and must not be swallowed by the LLC branch.
        frame = "0180c2000000" + SRC + "0026" + "424203" + "00" * 35
        self.assertEqual(self._parse(frame)["proto"], "stp")

    def test_ethernet_ii_frames_are_untouched(self):
        frame = f"ffffffffffff{SRC}" + "0806" + "0001080006040001"
        packet = self._parse(frame)
        self.assertEqual(packet["proto"], "arp")
        self.assertNotIn("llc_dsap", packet)

    def test_a_real_ethertype_above_the_cutoff_is_still_an_ethertype(self):
        # 0x0800 is IPv4 and must never be read as a length.
        frame = f"ffffffffffff{SRC}" + "0800" + "45" + "00" * 19
        self.assertNotIn("llc_dsap", self._parse(frame))


if __name__ == "__main__":
    unittest.main()
