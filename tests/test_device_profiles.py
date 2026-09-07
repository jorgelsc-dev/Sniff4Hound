import tempfile
import unittest
from pathlib import Path

from sniff4hound.device_profiles import infer_device_profile
from sniff4hound.store import SniffStore


class DeviceProfileTests(unittest.TestCase):
    def test_known_service_metadata_selects_device_and_evidence(self):
        profile = infer_device_profile([
            {"local_port": 9100, "proto": "tcp", "banner_text": "HP LaserJet JetDirect"},
        ])
        self.assertEqual(profile["device_type"], "Printer")
        self.assertEqual(profile["device_confidence"], "high")
        self.assertTrue(profile["device_evidence"])

    def test_phone_uses_decoder_metadata_without_active_probe(self):
        profile = infer_device_profile([
            {"local_port": 5353, "proto": "mdns", "details_json": '{"service":"_companion-link","name":"Jorge iPhone"}'},
        ])
        self.assertEqual(profile["device_type"], "Phone")

    def test_ambiguous_metadata_stays_unknown(self):
        profile = infer_device_profile([{"local_port": 50123, "proto": "tcp"}])
        self.assertEqual(profile["device_type"], "Unknown")
        self.assertEqual(profile["device_confidence"], "unknown")

    def test_ip_catalog_is_enriched_with_device_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = SniffStore(Path(tmp) / "devices.db")
            self.addCleanup(store.close)
            store.register_packet({
                "src_ip": "192.168.1.20", "dst_ip": "192.168.1.40",
                "src_port": 52331, "dst_port": 9100, "proto": "tcp",
                "banner_text": "HP LaserJet", "interface": "eth0", "length": 80,
            })
            rows = {row["ip"]: row for row in store.list_ip_catalog(limit=20)}
            self.assertEqual(rows["192.168.1.40"]["device_type"], "Printer")
            self.assertIn("device_evidence", rows["192.168.1.40"])


if __name__ == "__main__":
    unittest.main()
