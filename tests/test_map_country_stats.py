from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from sniff4hound.store import SniffStore


class CountryRollupTests(unittest.TestCase):
    """map_snapshot's per-country rollup, which the map popup renders."""

    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.store = SniffStore(str(Path(self._dir.name) / "map.db"))
        self.addCleanup(self.store.close)

    def _packet(self, dst_ip, proto="tls", length=500, src_ip="192.168.1.10"):
        self.store.register_packet({
            "proto": proto, "src_ip": src_ip, "dst_ip": dst_ip,
            "src_port": 50000, "dst_port": 443, "length": length, "interface": "eth0",
        })

    def _countries(self):
        return {
            entry["country_code"]: entry
            for entry in self.store.map_snapshot(limit=500).get("countries", [])
        }

    def test_public_addresses_are_grouped_by_country(self):
        # Addresses from the bundled registry, one per RIR, so the rollup is
        # exercised against real catalogue data rather than a stub.
        self._packet("8.8.8.8")
        self._packet("1.1.1.1")
        countries = self._countries()
        self.assertIn("US", countries)
        self.assertIn("AU", countries)

    def test_it_counts_packets_and_bytes_not_just_hosts(self):
        # A country with one very busy address must not read the same as one
        # with a single quiet packet, which is all a host count would say.
        for _ in range(4):
            self._packet("8.8.8.8", length=1000)
        self._packet("1.1.1.1", length=100)

        countries = self._countries()
        self.assertEqual(countries["US"]["packets"], 4)
        self.assertEqual(countries["US"]["bytes"], 4000)
        self.assertEqual(countries["US"]["hosts"], 1)
        self.assertEqual(countries["AU"]["packets"], 1)

    def test_private_addresses_are_not_given_a_country(self):
        # They have no registry entry, and folding them into the declared site
        # would swamp it with local chatter.
        self._packet("10.0.0.5", src_ip="192.168.1.10")
        for entry in self._countries().values():
            self.assertNotIn("10.0.0.5", entry.get("addresses", []))

    def test_the_protocol_breakdown_is_per_country(self):
        self._packet("8.8.8.8", proto="tls")
        self._packet("8.8.8.8", proto="tls")
        self._packet("8.8.8.8", proto="dns")
        breakdown = {
            item["proto"]: item["packets"] for item in self._countries()["US"]["protocols"]
        }
        self.assertEqual(breakdown, {"tls": 2, "dns": 1})

    def test_countries_come_back_busiest_first(self):
        for _ in range(3):
            self._packet("8.8.8.8")
        self._packet("1.1.1.1")
        ordered = [entry["country_code"] for entry in self.store.map_snapshot(limit=500)["countries"]]
        self.assertEqual(ordered[:2], ["US", "AU"])

    def test_the_rollup_carries_what_the_popup_renders(self):
        # The popup reads these directly; a missing key renders as blank.
        self._packet("8.8.8.8")
        entry = self._countries()["US"]
        for key in ("country_code", "country", "hosts", "packets", "bytes", "protocols", "addresses"):
            self.assertIn(key, entry)

    def test_an_empty_capture_reports_no_countries(self):
        self.assertEqual(self.store.map_snapshot(limit=500)["countries"], [])


if __name__ == "__main__":
    unittest.main()
