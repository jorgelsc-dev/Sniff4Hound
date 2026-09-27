from __future__ import annotations

import json
import unittest

import queue

from sniff4hound.mobile_stream import (
    PAIRING_APPROVAL_TTL_SECONDS,
    PAIRING_TTL_SECONDS,
    MobileServerState,
    MobileSession,
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
            expires_at=_now() + PAIRING_APPROVAL_TTL_SECONDS,
        )
        self.service._pairings[pairing_id] = pairing
        return pairing

    def _approved(self, pairing_id="pair-1", *, client="192.0.2.20", user_agent="phone"):
        """The full supervised path: device knocks, operator accepts."""
        pairing = self._pairing(pairing_id)
        self.service.open_pairing(pairing_id, client=client, user_agent=user_agent)
        self.service.approve_pairing(pairing_id)
        return pairing

    def test_a_device_that_knocks_gets_no_code_until_a_human_accepts_it(self):
        # The point of the whole flow. If reaching the URL were enough to
        # mint a code, the QR would effectively carry the secret and anyone
        # who photographed the screen - or guessed the link - would be one
        # screen-glance away from the stream.
        self._pairing()

        opened = self.service.open_pairing("pair-1", client="192.0.2.20", user_agent="iPhone")

        self.assertIsNotNone(opened)
        self.assertEqual(opened.code, "", "a code existed before the operator approved anything")
        view = self.service.pairing("pair-1")
        self.assertEqual(view["status"], "awaiting_approval")
        self.assertFalse(view["approved"])
        self.assertEqual(view["code"], "")
        # ...and the desktop has what it needs to make the decision.
        self.assertEqual(view["client"], "192.0.2.20")
        self.assertEqual(view["user_agent"], "iPhone")
        self.assertTrue(view["seen_at"], "no timestamp for the operator to judge")

    def test_an_unapproved_code_cannot_be_guessed_into_a_session(self):
        # Belt and braces: even if a caller reached verify_pairing directly,
        # with no code issued there is nothing to be right about.
        self._pairing()
        self.service.open_pairing("pair-1", client="192.0.2.20")

        for guess in ("", "000000", "123456"):
            self.assertIsNone(
                self.service.verify_pairing("pair-1", guess, client="192.0.2.20", user_agent="phone"),
                f"guess {guess!r} was accepted without an approval",
            )

    def test_approval_issues_the_code_and_starts_the_short_window(self):
        pairing = self._pairing()
        self.service.open_pairing("pair-1", client="192.0.2.20", user_agent="iPhone")

        approved = self.service.approve_pairing("pair-1")

        self.assertIsNotNone(approved)
        self.assertRegex(approved["code"], r"^\d{6}$")
        self.assertEqual(approved["status"], "waiting_code")
        self.assertTrue(approved["approved"])
        # The 60s is the phone's time to type, measured from the accept - not
        # a clock the operator was also racing while walking to the desk.
        self.assertLessEqual(approved["expires_in"], PAIRING_TTL_SECONDS)
        self.assertGreater(approved["expires_in"], PAIRING_TTL_SECONDS - 5)
        self.assertGreater(pairing.approved_at, 0.0)

    def test_approving_before_any_device_knocks_is_refused(self):
        # Otherwise an operator could put a live code on screen for whoever
        # reaches the URL first, which is the property this flow removes.
        self._pairing()

        self.assertIsNone(self.service.approve_pairing("pair-1"))
        self.assertEqual(self.service.pairing("pair-1")["code"], "")

    def test_a_later_refresh_cannot_redescribe_an_approved_device(self):
        # The phone re-polls the holding page while it waits. If each poll
        # overwrote the recorded device, what the operator approved and what
        # is connected could differ.
        self._approved(client="192.0.2.20", user_agent="iPhone")

        self.service.open_pairing("pair-1", client="198.51.100.9", user_agent="curl/8")

        view = self.service.pairing("pair-1")
        self.assertEqual(view["client"], "192.0.2.20")
        self.assertEqual(view["user_agent"], "iPhone")

    def test_the_code_only_works_from_the_device_that_was_approved(self):
        # Otherwise the operator vouches for the phone they were shown while
        # the code stays usable by anyone else holding the link, and the
        # approval step is decorative.
        pairing = self._approved(client="192.0.2.20", user_agent="iPhone")

        stolen = self.service.verify_pairing(
            pairing.id, pairing.code, client="198.51.100.9", user_agent="curl/8",
        )

        self.assertIsNone(stolen)
        # ...and the attempt burns the link rather than leaving it open for
        # the next try.
        self.assertIsNone(
            self.service.verify_pairing(pairing.id, pairing.code, client="192.0.2.20", user_agent="iPhone")
        )

    def test_wrong_code_closes_the_pairing_without_a_session(self):
        pairing = self._approved()

        token = self.service.verify_pairing(
            pairing.id,
            "000000" if pairing.code != "000000" else "111111",
            client="192.0.2.20",
            user_agent="phone",
        )

        self.assertIsNone(token)
        self.assertIsNone(self.service.verify_pairing(pairing.id, pairing.code, client="192.0.2.20", user_agent="phone"))

    def test_correct_code_creates_a_revocable_readonly_session(self):
        pairing = self._approved()

        token = self.service.verify_pairing(pairing.id, pairing.code, client="192.0.2.20", user_agent="phone")

        self.assertIsInstance(token, str)
        self.assertIsNotNone(self.service.session(token))
        self.assertTrue(self.service.revoke_session(token))
        self.assertIsNone(self.service.session(token))


class MobileStreamRevokeTests(unittest.TestCase):
    """The spec allows several phones at once, each revoked on its own. The
    revoke event was broadcast to every subscriber, and the phone closes its
    EventSource when it arrives - so cutting off one device took all of them
    dark, while the device actually being revoked was the one subscriber
    skipped."""

    def setUp(self):
        self.service = MobileStreamService()
        self.queues = {}
        for name in ("a", "b"):
            token = f"token-{name}"
            self.service._sessions[token] = MobileSession(
                token=token, interface="eth0", address="192.0.2.10",
                client=f"192.0.2.2{name}", user_agent=name,
                created_at=_now(), last_seen=_now(),
            )
            q: queue.Queue = queue.Queue(maxsize=10)
            self.queues[token] = q
            self.service._subscribers[id(q)] = (token, q)

    def _drain(self, token):
        events = []
        while not self.queues[token].empty():
            events.append(self.queues[token].get_nowait()["type"])
        return events

    def test_revoking_one_phone_leaves_the_others_streaming(self):
        self.service.revoke_session("token-a")

        self.assertEqual(self._drain("token-b"), [], "an unrelated phone was told it was revoked")
        self.assertIsNotNone(self.service.session("token-b"))

    def test_the_revoked_phone_is_the_one_that_hears_about_it(self):
        self.service.revoke_session("token-a")

        self.assertEqual(self._drain("token-a"), ["revoked"])
        self.assertIsNone(self.service.session("token-a"))

    def test_events_still_reach_every_live_subscriber(self):
        self.service.record_event({
            "type": "runtime_mode",
            "runtime": {"mode": "capture", "running_engines": ["sniffer"]},
        })

        self.assertEqual(self._drain("token-a"), ["runtime_mode"])
        self.assertEqual(self._drain("token-b"), ["runtime_mode"])


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
        self.assertEqual(event["tags"], [{"key": "monitor", "severity": "high"}])
        self.assertNotIn("password", encoded)
        self.assertNotIn("payload", encoded)

    def test_a_tag_value_never_reaches_the_phone(self):
        # This test used to assert the opposite - that the tag's value is
        # forwarded - because its fixture used a hand-written label
        # ("Suspicious login") as the value. Real values are not labels:
        # monitors.describe_match() returns `found.group(0)` for any monitor
        # carrying a payload_regex, i.e. a literal slice of the decoded
        # payload. So the value channel was carrying captured cleartext to the
        # phone over the LAN, and the fixture was the only reason the test
        # did not say so.
        leaked = "password=supersecret123!&csrf=ab12"
        event = _public_event(
            {
                "type": "packet",
                "packet": {
                    "src_ip": "10.0.0.5", "dst_ip": "93.184.216.34",
                    "proto": "http", "src_port": 51000, "dst_port": 80, "length": 220,
                    "summary": "HTTP POST /login",
                    "tags": [{"key": "creds", "value": leaked, "severity": "high"}],
                },
            }
        )

        encoded = json.dumps(event)
        self.assertNotIn("supersecret123", encoded)
        self.assertNotIn(leaked, encoded)
        # The alert itself survives: which rule fired, and how serious.
        self.assertEqual(event["tags"], [{"key": "creds", "severity": "high"}])

    def test_the_leak_is_reproduced_from_a_real_monitor_match(self):
        # Not a synthetic value: run the actual monitor matcher so this keeps
        # holding if describe_match's output ever changes shape.
        from sniff4hound.monitors import describe_match, normalize_monitor

        monitor = normalize_monitor({
            "id": "creds", "name": "Cleartext credentials", "severity": "high",
            "match": {"payload_regex": [r"password=\S+"]},
        })
        packet = {
            "src_ip": "10.0.0.5", "dst_ip": "93.184.216.34", "proto": "http",
            "src_port": 51000, "dst_port": 80, "length": 220,
            "summary": "HTTP POST /login",
            "payload_text": "POST /login HTTP/1.1\r\n\r\nuser=jorge&password=SuperSecret123!",
        }
        value = describe_match(monitor, packet)
        self.assertIn("supersecret123!", value.lower(), "fixture no longer exercises a payload match")

        event = _public_event({
            "type": "packet",
            "packet": {**packet, "tags": [{"key": "creds", "value": value, "severity": "high"}]},
        })

        self.assertNotIn("supersecret123", json.dumps(event).lower())


if __name__ == "__main__":
    unittest.main()
