from __future__ import annotations

import json
import unittest

from sniff4hound.mobile_stream import (
    PAIRING_TTL_SECONDS,
    MobileServerState,
    MobileStreamService,
    Pairing,
    _now,
    _public_event,
)


class MobileStreamPairingTests(unittest.TestCase):
    def setUp(self):
        self.service = MobileStreamService()
        self.service._state = MobileServerState(
            interface="eth0",
            address="192.0.2.10",
            port=45679,
            running=True,
            url_base="https://192.0.2.10:45679",
        )

    def _pairing(self, pairing_id="pair-1"):
        pairing = Pairing(
            id=pairing_id,
            interface="eth0",
            address="192.0.2.10",
            port=45679,
            created_at=_now(),
            expires_at=_now() + PAIRING_TTL_SECONDS,
        )
        self.service._pairings[pairing_id] = pairing
        return pairing

    def test_opening_a_pairing_generates_a_six_digit_code(self):
        self._pairing()
        opened = self.service.open_pairing("pair-1", client="192.0.2.20")

        self.assertIsNotNone(opened)
        self.assertRegex(opened.code, r"^\d{6}$")
        self.assertEqual(opened.client, "192.0.2.20")
        self.assertEqual(self.service.pairing("pair-1")["status"], "waiting_code")

    def test_wrong_code_closes_the_pairing_without_a_session(self):
        pairing = self._pairing()
        self.service.open_pairing(pairing.id, client="192.0.2.20")

        token = self.service.verify_pairing(
            pairing.id,
            "000000" if pairing.code != "000000" else "111111",
            client="192.0.2.20",
            user_agent="phone",
        )

        self.assertIsNone(token)
        self.assertIsNone(self.service.verify_pairing(pairing.id, pairing.code, client="192.0.2.20", user_agent="phone"))

    def test_correct_code_creates_a_revocable_readonly_session(self):
        pairing = self._pairing()
        self.service.open_pairing(pairing.id, client="192.0.2.20")

        token = self.service.verify_pairing(pairing.id, pairing.code, client="192.0.2.20", user_agent="phone")

        self.assertIsInstance(token, str)
        self.assertIsNotNone(self.service.session(token))
        self.assertTrue(self.service.revoke_session(token))
        self.assertIsNone(self.service.session(token))


class MobileStreamEventTests(unittest.TestCase):
    def test_packet_events_are_redacted_for_mobile_streaming(self):
        event = _public_event(
            {
                "type": "packet",
                "generated_at": "2026-09-26T00:00:00Z",
                "packet": {
                    "src_ip": "10.0.0.5",
                    "src_port": 12345,
                    "dst_ip": "10.0.0.8",
                    "dst_port": 443,
                    "proto": "tcp",
                    "length": 120,
                    "payload_text": "password=secret",
                    "payload_hex": "70617373776f7264",
                    "summary": "TLS client hello",
                    "tags": [{"key": "monitor", "value": "Suspicious login", "severity": "high"}],
                },
            }
        )

        encoded = json.dumps(event)
        self.assertEqual(event["src_ip"], "10.0.0.5")
        self.assertIn("Suspicious login", encoded)
        self.assertNotIn("password", encoded)
        self.assertNotIn("payload", encoded)


if __name__ == "__main__":
    unittest.main()
