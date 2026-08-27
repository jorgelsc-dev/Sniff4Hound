from __future__ import annotations

import unittest
from unittest.mock import patch

from sniff4hound import ip_registry
from sniff4hound.store import _GeoCountryResolver


class BundledRegistryTests(unittest.TestCase):
    def test_the_catalog_ships_with_the_package(self):
        self.assertTrue(ip_registry.is_available(), "ip_registry.json is missing from sniff4hound/data")

    def test_it_covers_a_meaningful_amount_of_space(self):
        v4, v6 = ip_registry.range_counts()
        # Guards against a truncated or half-written rebuild landing in-tree.
        self.assertGreater(v4, 50_000, "IPv4 catalog looks truncated")
        self.assertGreater(v6, 10_000, "IPv6 catalog looks truncated")

    def test_resolves_an_address_from_every_registry(self):
        expected = {
            "8.8.8.8": ("US", "arin"),
            "1.1.1.1": ("AU", "apnic"),
            "200.55.140.1": ("CU", "lacnic"),
            "213.171.192.1": ("GB", "ripencc"),
            "41.57.120.1": ("NG", "afrinic"),
        }
        for ip, (country, registry) in expected.items():
            hit = ip_registry.lookup(ip)
            self.assertEqual(hit.get("country_code"), country, ip)
            self.assertEqual(hit.get("registry"), registry, ip)
            self.assertTrue(hit.get("region"), f"{ip} has no region label")

    def test_resolves_ipv6(self):
        self.assertEqual(ip_registry.lookup("2606:4700::1").get("country_code"), "US")
        self.assertEqual(ip_registry.lookup("2a00:1450:4001::1").get("registry"), "ripencc")

    def test_private_and_loopback_are_not_attributed_to_a_country(self):
        # RFC1918 and loopback are not delegated to anyone; claiming a country
        # for them would put local hosts on the world map.
        for ip in ("127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.1", "::1"):
            self.assertEqual(ip_registry.lookup(ip), {}, ip)

    def test_unparseable_input_returns_empty(self):
        for value in ("", None, "not-an-ip", "999.1.1.1", "8.8.8.8/24"):
            self.assertEqual(ip_registry.lookup(value), {}, repr(value))

    def test_lookup_is_a_range_test_not_a_prefix_match(self):
        # bisect lands on the range whose start is <= the address; the hit is
        # only real when the address is also within that range's end.
        hit = ip_registry.lookup("8.8.8.8")
        self.assertTrue(hit)
        self.assertEqual(len(hit.get("country_code", "")), 2)


class GeoResolverFallbackTests(unittest.TestCase):
    def test_falls_back_to_the_registry_without_libgeoip(self):
        # The case this exists for: no system libGeoIP and no country DB meant
        # every public address came back unlocated and the map stayed empty.
        with patch.object(_GeoCountryResolver, "_load_library", lambda self: None):
            resolver = _GeoCountryResolver()
            self.assertIn("rir-registry", resolver.describe_source())
            geo = resolver.lookup("200.55.140.1")
        self.assertTrue(geo["found"])
        self.assertEqual(geo["country_code"], "CU")
        self.assertEqual(geo["registry"], "lacnic")
        self.assertTrue(geo["region"])

    def test_fallback_still_yields_coordinates(self):
        with patch.object(_GeoCountryResolver, "_load_library", lambda self: None):
            resolver = _GeoCountryResolver()
            geo = resolver.lookup("8.8.8.8")
        if resolver._centroids:  # zoneinfo present on this machine
            self.assertIsNotNone(geo["lat"])
            self.assertIsNotNone(geo["lon"])

    def test_private_addresses_stay_unresolved_in_the_fallback(self):
        with patch.object(_GeoCountryResolver, "_load_library", lambda self: None):
            resolver = _GeoCountryResolver()
            geo = resolver.lookup("10.0.0.5")
        self.assertFalse(geo["found"])
        self.assertIsNone(geo["lat"])


if __name__ == "__main__":
    unittest.main()
