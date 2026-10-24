"""Bundled IEEE MAC-vendor registry and longest-prefix lookup."""

from __future__ import annotations

import unittest

from sniff4hound import mac_vendor


class MacVendorRegistryTests(unittest.TestCase):
    def test_the_complete_ieee_catalog_is_bundled(self):
        self.assertTrue(mac_vendor.is_available())
        counts = mac_vendor.assignment_counts()
        self.assertGreater(counts["24"], 40_000)
        self.assertGreater(counts["28"], 6_000)
        self.assertGreater(counts["36"], 11_000)
        metadata = mac_vendor.catalog_metadata()
        self.assertEqual(metadata["source"], "IEEE Registration Authority public listings")
        self.assertEqual(set(metadata["sources"]), {"MA-L", "MA-M", "MA-S", "IAB"})
        for source in metadata["sources"].values():
            self.assertEqual(len(source["sha256"]), 64)

    def test_ma_l_resolves_a_global_mac(self):
        result = mac_vendor.lookup("f0:ee:7a:12:34:56")
        self.assertEqual(result["vendor"], "Apple, Inc.")
        self.assertEqual((result["registry"], result["prefix_bits"]), ("MA-L", 24))

    def test_the_longest_prefix_wins_over_the_parent_ieee_oui(self):
        medium = mac_vendor.lookup("f0:40:af:9a:bc:de")
        small = mac_vendor.lookup("8c:1f:64:34:ab:cd")
        legacy = mac_vendor.lookup("40:d8:55:0d:7a:bc")
        self.assertEqual((medium["vendor"], medium["registry"], medium["prefix_bits"]), ("Raspberry Pi (Trading) Ltd", "MA-M", 28))
        self.assertEqual((small["vendor"], small["registry"], small["prefix_bits"]), ("Raspberry Pi (Trading) Ltd", "MA-S", 36))
        self.assertEqual((legacy["vendor"], legacy["registry"], legacy["prefix_bits"]), ("Avant Technologies", "IAB", 36))

    def test_non_global_addresses_are_classified_without_false_vendors(self):
        cases = {
            "02:00:00:00:00:01": "local",
            "01:00:5e:00:00:01": "multicast",
            "ff:ff:ff:ff:ff:ff": "broadcast",
            "not-a-mac": "invalid",
        }
        for address, kind in cases.items():
            with self.subTest(address=address):
                result = mac_vendor.lookup(address)
                self.assertEqual(result["kind"], kind)
                self.assertEqual(result["vendor"], "")

    def test_enrichment_adds_api_fields_without_changing_the_mac(self):
        row = {"mac": "f0-ee-7a-12-34-56"}
        self.assertIs(mac_vendor.enrich(row), row)
        self.assertEqual(row["mac"], "f0-ee-7a-12-34-56")
        self.assertEqual(row["mac_vendor"], "Apple, Inc.")
        self.assertEqual(row["mac_vendor_registry"], "MA-L")
        self.assertEqual(row["mac_vendor_prefix_bits"], 24)


if __name__ == "__main__":
    unittest.main()
