"""Operator benign/malign review labels on captured packets (POST
/api/packets/review) are independent of the AI-learning feedback stored for
the AI view - they live in the generic `tags` table so any packet listing
(sniffer, monitor matches) can surface and edit them.
"""

from __future__ import annotations

import os
import tempfile
import unittest

from sniff4hound.store import SniffStore


class PacketReviewTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.store = SniffStore(os.path.join(self._tmp.name, "review.db"))
        self.addCleanup(self.store.close)
        self.packet_id = self.store.register_packet(
            {
                "proto": "tcp",
                "src_ip": "10.0.0.5",
                "dst_ip": "10.0.0.6",
                "src_port": 1234,
                "dst_port": 80,
            }
        )["id"]

    def test_new_packets_are_unreviewed(self):
        rows = self.store.list_packets()
        self.assertEqual(rows[0]["review_label"], "")

    def test_label_benign_then_malicious_then_clear(self):
        result = self.store.save_packet_review(self.packet_id, "benign")
        self.assertEqual(result["review_label"], "benign")
        self.assertEqual(self.store.list_packets()[0]["review_label"], "benign")

        result = self.store.save_packet_review(self.packet_id, "malicious")
        self.assertEqual(result["review_label"], "malicious")
        self.assertEqual(self.store.list_packets()[0]["review_label"], "malicious")

        result = self.store.save_packet_review(self.packet_id, "unreviewed")
        self.assertEqual(result["review_label"], "")
        self.assertEqual(self.store.list_packets()[0]["review_label"], "")

    def test_rejects_invalid_label(self):
        with self.assertRaises(ValueError):
            self.store.save_packet_review(self.packet_id, "not-a-label")

    def test_rejects_unknown_packet(self):
        with self.assertRaises(ValueError):
            self.store.save_packet_review(999999, "benign")


if __name__ == "__main__":
    unittest.main()
