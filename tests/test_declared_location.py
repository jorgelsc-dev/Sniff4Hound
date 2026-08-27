from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from sniff4hound.store import SniffStore
from sniff4hound.utils import safe_float


class SafeFloatSentinelTests(unittest.TestCase):
    def test_none_default_survives_an_unparseable_value(self):
        # `float(None)` raises, so a plain `return float(default)` turned the
        # "no value" sentinel used for optional coordinates into a TypeError.
        self.assertIsNone(safe_float("not-a-number", None))
        self.assertIsNone(safe_float(None, None))

    def test_numeric_defaults_and_values_are_unaffected(self):
        self.assertEqual(safe_float("2.5", None), 2.5)
        self.assertEqual(safe_float("nope", 0.0), 0.0)
        self.assertEqual(safe_float("nope", 7), 7.0)


class DeclaredLocationTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.store = SniffStore(Path(self._tmp.name) / "location.db")
        self.addCleanup(self.store.close)

    def test_unset_by_default(self):
        location = self.store.get_declared_location()
        self.assertFalse(location["configured"])
        self.assertIsNone(location["lat"])
        self.assertIsNone(location["lon"])

    def test_round_trips_coordinates_and_label(self):
        saved = self.store.set_declared_location(23.1136, -82.3666, "Main office")
        self.assertTrue(saved["configured"])
        self.assertAlmostEqual(saved["lat"], 23.1136, places=4)
        self.assertAlmostEqual(saved["lon"], -82.3666, places=4)
        self.assertEqual(saved["label"], "Main office")
        self.assertEqual(self.store.get_declared_location(), saved)

    def test_rejects_out_of_range_coordinates(self):
        for lat, lon in ((91, 0), (-91, 0), (0, 181), (0, -181)):
            with self.assertRaises(ValueError, msg=f"{lat},{lon}"):
                self.store.set_declared_location(lat, lon)

    def test_rejects_non_numeric_coordinates(self):
        for lat, lon in (("west", 0), (None, 5), (10, "north")):
            with self.assertRaises(ValueError, msg=f"{lat},{lon}"):
                self.store.set_declared_location(lat, lon)

    def test_a_rejected_write_leaves_the_previous_value(self):
        self.store.set_declared_location(10.0, 20.0, "keep me")
        with self.assertRaises(ValueError):
            self.store.set_declared_location(999, 999)
        self.assertEqual(self.store.get_declared_location()["label"], "keep me")

    def test_clearing_removes_the_location(self):
        self.store.set_declared_location(10.0, 20.0, "gone")
        cleared = self.store.set_declared_location(None, None)
        self.assertFalse(cleared["configured"])
        self.assertIsNone(cleared["lat"])

    def test_label_is_length_capped(self):
        saved = self.store.set_declared_location(0, 0, "x" * 400)
        self.assertLessEqual(len(saved["label"]), 120)


class HostNodePlacementTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.store = SniffStore(Path(self._tmp.name) / "nodes.db")
        self.addCleanup(self.store.close)

    def test_private_hosts_land_on_the_declared_location(self):
        self.store.set_declared_location(23.1136, -82.3666, "Main office")
        for ip in ("10.0.0.5", "192.168.1.20", "172.20.1.1"):
            node = self.store._host_node(ip)
            self.assertTrue(node["private"], ip)
            self.assertAlmostEqual(node["lat"], 23.1136, places=4, msg=ip)
            self.assertAlmostEqual(node["lon"], -82.3666, places=4, msg=ip)
            self.assertEqual(node["geo_precision"], "declared", ip)

    def test_loopback_lands_on_the_declared_location_too(self):
        self.store.set_declared_location(1.5, 2.5)
        node = self.store._host_node("127.0.0.1")
        self.assertAlmostEqual(node["lat"], 1.5, places=4)
        self.assertEqual(node["geo_precision"], "declared")

    def test_private_hosts_stay_unplotted_without_a_declared_location(self):
        node = self.store._host_node("10.0.0.5")
        self.assertIsNone(node["lat"])
        self.assertIsNone(node["lon"])
        self.assertNotEqual(node["geo_precision"], "declared")

    def test_public_hosts_keep_their_own_geolocation(self):
        # The declared site must never override a public address: those are
        # resolved from the registry blocks and belong where they resolve.
        self.store.set_declared_location(23.1136, -82.3666)
        node = self.store._host_node("8.8.8.8")
        self.assertFalse(node["private"])
        self.assertNotEqual(node["geo_precision"], "declared")
        if node["lat"] is not None:
            self.assertNotAlmostEqual(node["lat"], 23.1136, places=4)

    def test_map_origin_moves_to_the_declared_location(self):
        # The arc origin used to be a fixed off-canvas pixel anchor, so every
        # trace converged on a point floating outside the map. With a site
        # declared it has to carry real coordinates for the map to place it.
        self.store.set_declared_location(23.1136, -82.3666, "Main office")
        origin = self.store.map_snapshot(limit=5)["origin"]
        self.assertTrue(origin["declared"])
        self.assertAlmostEqual(origin["lat"], 23.1136, places=4)
        self.assertAlmostEqual(origin["lon"], -82.3666, places=4)
        self.assertEqual(origin["label"], "Main office")

    def test_map_origin_has_no_coordinates_until_a_site_is_declared(self):
        origin = self.store.map_snapshot(limit=5)["origin"]
        self.assertFalse(origin["declared"])
        self.assertIsNone(origin["lat"])
        self.assertIsNone(origin["lon"])
        self.assertEqual(origin["label"], "Sniff origin")

    def test_map_origin_falls_back_to_the_generic_label(self):
        self.store.set_declared_location(1.0, 2.0)
        self.assertEqual(self.store.map_snapshot(limit=5)["origin"]["label"], "Sniff origin")

    def test_map_snapshot_exposes_the_declared_location(self):
        self.store.set_declared_location(10.0, 20.0, "Site A")
        snapshot = self.store.map_snapshot(limit=5)
        self.assertEqual(snapshot["declared_location"]["label"], "Site A")
        self.assertTrue(snapshot["declared_location"]["configured"])


if __name__ == "__main__":
    unittest.main()
