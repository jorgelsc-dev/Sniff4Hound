from __future__ import annotations

import http.client
import json
import os
import socket
import ssl
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import queue

from wsbuilder import Request

from sniff4hound.mobile_stream import (
    LOG_BACKLOG,
    LOG_MESSAGE_LIMIT,
    PAIRING_APPROVAL_TTL_SECONDS,
    PAIRING_TTL_SECONDS,
    MobileServerState,
    MobileSession,
    MobileStreamService,
    Pairing,
    _build_mobile_app,
    _log_rank,
    _now,
    _public_event,
    _public_log,
    _scrub_log_text,
    _session_page,
    normalize_log_level,
)
from tests.test_http3_listener import _write_self_signed_material


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

    def test_concurrent_knocks_cannot_replace_the_approved_device(self):
        self._pairing()
        clients = [f"192.0.2.{20 + index}" for index in range(8)]
        with ThreadPoolExecutor(max_workers=8) as workers:
            list(workers.map(
                lambda index: self.service.open_pairing(
                    "pair-1", client=f"192.0.2.{20 + index}", user_agent=f"phone-{index}"
                ),
                range(8),
            ))

        view = self.service.pairing("pair-1")
        self.assertIn(view["client"], clients)
        self.assertEqual(view["user_agent"], f"phone-{clients.index(view['client'])}")
        approved = self.service.approve_pairing("pair-1")
        self.assertIsNotNone(approved)
        self.assertIsNotNone(self.service.verify_pairing(
            "pair-1", approved["code"], client=view["client"], user_agent=view["user_agent"]
        ))


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


class MobileStreamLogFormatTests(unittest.TestCase):
    """The stream is specified never to carry captured payloads or secrets. A
    log line interpolates request lines, headers and exception text, so what a
    phone may see of one is cut down to a few fields and scrubbed."""

    def test_a_log_line_carries_only_level_source_logger_and_message(self):
        event = _public_log(
            {
                "timestamp": "2026-10-11T00:00:01.000000+00:00",
                "level": "WARNING",
                "logger": "sniff4hound.honeypot",
                "message": "listener restarted",
                "module": "honeypot",
                "function": "_serve",
                "line": 1100,
                # What a record can carry besides its message: all of it stays home.
                "sql": "SELECT payload_text FROM packets WHERE src_ip = '203.0.113.9'",
                "job": "9c6a12346bd54cd8a6c478b91e2f77de",
                "exception": 'Traceback (most recent call last):\n  File "/root/app.py", line 4',
            },
            "capture",
        )

        self.assertEqual(
            set(event),
            {"type", "generated_at", "level", "source", "logger", "message"},
        )
        self.assertEqual(event["type"], "log")
        self.assertEqual(event["level"], "WARNING")
        self.assertEqual(event["source"], "capture")
        self.assertEqual(event["logger"], "honeypot", "the package prefix adds nothing on a phone")
        self.assertEqual(event["message"], "listener restarted")
        self.assertNotIn("SELECT", json.dumps(event))
        self.assertNotIn("Traceback", json.dumps(event))

    def test_secrets_in_a_message_are_redacted_and_the_rest_is_kept(self):
        cases = {
            "login failed code=Ab12Cd34 from 203.0.113.9": "Ab12Cd34",
            "GET /api/feed?ticket=abc123def456&refresh=1 -> 200": "abc123def456",
            "Authorization: Bearer abcdefghijklmnop12345": "abcdefghijklmnop12345",
            "rejected X-Security-Code: Zz9Yy8Xx": "Zz9Yy8Xx",
            "session token 0123456789abcdef0123456789abcdef0123": "0123456789abcdef0123456789abcdef0123",
            "password='hunter2 hunter3' was refused": "hunter2",
            'cookie: "sid=abc; theme=dark"': "sid=abc",
        }
        for message, secret in cases.items():
            with self.subTest(message=message):
                scrubbed = _scrub_log_text(message)
                self.assertNotIn(secret, scrubbed)
                self.assertIn("[redacted]", scrubbed)
        # Redaction is not a blanket wipe: the parts around it still read.
        self.assertEqual(
            _scrub_log_text("login failed code=Ab12Cd34 from 203.0.113.9"),
            "login failed code=[redacted] from 203.0.113.9",
        )
        self.assertIn("refresh=1", _scrub_log_text("GET /api/feed?ticket=abc123def456&refresh=1 -> 200"))
        # A scheme and its token are one secret, not two.
        self.assertEqual(
            _scrub_log_text("Authorization: Bearer abcdefghijklmnop12345 refused on tcp/8080"),
            "Authorization: [redacted] refused on tcp/8080",
        )
        # A bare bearer token with no key in front of it still goes.
        self.assertNotIn("abcdefghijklmnop12345", _scrub_log_text("sent Bearer abcdefghijklmnop12345 upstream"))

    def test_a_message_is_flattened_and_cut_to_length(self):
        flat = _scrub_log_text("first line\nsecond\tline\r\n\x1b[31mred\x1b[0m")
        self.assertNotRegex(flat, r"[\x00-\x1f\x7f]")
        self.assertEqual(flat.split()[:2], ["first", "line"])

        long_text = _scrub_log_text("word " * 200)
        self.assertEqual(len(long_text), LOG_MESSAGE_LIMIT)
        self.assertTrue(long_text.endswith("…"))

    def test_an_empty_message_is_not_worth_sending(self):
        self.assertIsNone(_public_log({"level": "INFO", "message": "  \n "}, "web"))
        self.assertIsNone(_public_log("not a record", "web"))

    def test_levels(self):
        self.assertEqual(normalize_log_level("warning"), "WARNING")
        self.assertEqual(normalize_log_level(" Debug "), "DEBUG")
        for bad in ("TRACE", "", None, "CRITICAL", "off"):
            with self.subTest(bad=bad):
                self.assertIsNone(normalize_log_level(bad), "a phone can only ask for a level the settings offer")
        self.assertGreater(_log_rank("CRITICAL"), _log_rank("ERROR"))
        self.assertGreater(_log_rank("ERROR"), _log_rank("WARNING"))
        self.assertGreater(_log_rank("INFO"), _log_rank("DEBUG"))
        # An unknown level is shown as INFO rather than dropped or ranked below DEBUG.
        self.assertEqual(_public_log({"level": "NOTICE", "message": "x"}, "web")["level"], "INFO")

    def test_log_lines_do_not_come_through_the_event_hub(self):
        # Logs are read from the log files, never accepted from the runtime's
        # event hub, so nothing that reaches record_event can smuggle one in.
        self.assertIsNone(_public_event({"type": "log", "level": "ERROR", "message": "forged"}))


class MobileStreamLogFeedTests(unittest.TestCase):
    """Log lines reach a phone only if it asked for them, only from the level it
    chose upward, and without a gap or a repeat between its backlog and live lines."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)
        self.service = MobileStreamService()
        self.service._log_dir = lambda: self.dir
        # The follower thread polls on its own clock; these tests poll by hand.
        patcher = patch("sniff4hound.mobile_stream.LOG_POLL_SECONDS", 3600)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(lambda: self.service._log_stop.set())
        self._tick = 0

    def _record(self, level, message, **extra):
        self._tick += 1
        moment = datetime(2026, 10, 11, tzinfo=timezone.utc) + timedelta(seconds=self._tick)
        return {
            "timestamp": moment.isoformat(),
            "level": level,
            "logger": "sniff4hound.jobs",
            "message": message,
            **extra,
        }

    def _write(self, source, *records, newline=True):
        with (self.dir / f"{source}.ndjson").open("a", encoding="utf-8") as handle:
            for record in records:
                handle.write(json.dumps(record) + ("\n" if newline else ""))

    def _phone(self, name, level):
        token = f"token-{name}"
        self.service._sessions[token] = MobileSession(
            token=token, interface="eth0", address="192.0.2.10", client="192.0.2.20",
            user_agent=name, created_at=_now(), last_seen=_now(),
        )
        generator = self.service.event_stream(token, log_level=level)
        self.addCleanup(generator.close)
        return token, generator

    def _queue_of(self, token):
        return next(q for _id, (tok, q) in self.service._subscribers.items() if tok == token)

    def _drain(self, token):
        q = self._queue_of(token)
        events = []
        while not q.empty():
            events.append(q.get_nowait())
        return events

    def _poll(self):
        with self.service._lock:
            self.service._poll_logs_locked()

    def test_only_a_phone_that_asked_gets_logs_and_only_from_its_level_up(self):
        info, info_stream = self._phone("info", "INFO")
        error, error_stream = self._phone("error", "ERROR")
        quiet, quiet_stream = self._phone("quiet", None)
        for stream in (info_stream, error_stream, quiet_stream):
            self.assertIn(b"event: hello", next(stream))

        self._write("web", self._record("DEBUG", "d"), self._record("INFO", "i"), self._record("WARNING", "w"),
                    self._record("ERROR", "e"), self._record("CRITICAL", "c"))
        self._poll()

        self.assertEqual([e["message"] for e in self._drain(info)], ["i", "w", "e", "c"])
        self.assertEqual([e["message"] for e in self._drain(error)], ["e", "c"])
        self.assertEqual(self._drain(quiet), [], "a phone that did not ask received log lines")

    def test_a_phone_that_asked_for_no_logs_costs_nothing(self):
        token, stream = self._phone("quiet", None)
        next(stream)
        self.assertEqual(self.service._log_levels, {})
        self.assertIsNone(self.service._log_follower, "nothing is following the log files for no one")

    def test_other_events_still_reach_a_phone_whatever_its_log_level(self):
        error, stream = self._phone("error", "ERROR")
        next(stream)
        self.service.record_event({"type": "runtime_mode", "runtime": {"mode": "capture", "running_engines": []}})
        self.assertEqual([e["type"] for e in self._drain(error)], ["runtime_mode"])

    def test_history_is_the_backlog_and_live_lines_do_not_repeat_it(self):
        self._write("web", self._record("INFO", "old web"), self._record("DEBUG", "old debug"))
        self._write("capture", self._record("WARNING", "old capture"))

        token, stream = self._phone("a", "INFO")
        self.assertIn(b"event: hello", next(stream))
        backlog = [json.loads(next(stream).split(b"data: ", 1)[1]) for _ in range(2)]
        self.assertEqual([e["message"] for e in backlog], ["old web", "old capture"])
        self.assertEqual([e["source"] for e in backlog], ["web", "capture"])

        self._poll()
        self.assertEqual(self._drain(token), [], "history was delivered again as if it were new")

        self._write("web", self._record("INFO", "new web"))
        self._write("capture", self._record("ERROR", "new capture"))
        self._poll()
        self.assertEqual([e["message"] for e in self._drain(token)], ["new web", "new capture"])
        self._poll()
        self.assertEqual(self._drain(token), [], "a line was delivered twice")

    def test_the_backlog_is_capped_and_filtered_by_level(self):
        total = LOG_BACKLOG * 3  # every other line is an ERROR, so well over the cap
        for index in range(total):
            self._write("web", self._record("INFO" if index % 2 else "ERROR", f"line {index}"))
        token, stream = self._phone("a", "ERROR")
        next(stream)
        frames = []
        for _ in range(LOG_BACKLOG):
            frames.append(json.loads(next(stream).split(b"data: ", 1)[1]))
        self.assertTrue(all(frame["level"] == "ERROR" for frame in frames))
        newest_error = max(index for index in range(total) if index % 2 == 0)
        self.assertEqual(frames[-1]["message"], f"line {newest_error}", "the newest lines are the ones kept")
        self.assertEqual(frames[0]["message"], f"line {newest_error - 2 * (LOG_BACKLOG - 1)}")
        # ...and that was all of it: the next frame is the idle keepalive, not a 41st line.
        with patch("sniff4hound.mobile_stream.STREAM_KEEPALIVE_SECONDS", 0.05):
            self.assertEqual(next(stream), b": keepalive\n\n")

    def test_a_line_still_being_written_is_read_whole_on_the_next_poll(self):
        token, stream = self._phone("a", "INFO")
        next(stream)
        half = json.dumps(self._record("INFO", "split across two writes"))
        with (self.dir / "web.ndjson").open("a", encoding="utf-8") as handle:
            handle.write(half[:20])
        self._poll()
        self.assertEqual(self._drain(token), [])
        with (self.dir / "web.ndjson").open("a", encoding="utf-8") as handle:
            handle.write(half[20:] + "\n")
        self._poll()
        self.assertEqual([e["message"] for e in self._drain(token)], ["split across two writes"])

    def test_a_rotated_file_is_read_from_its_start(self):
        self._write("web", self._record("INFO", "before rotation"))
        token, stream = self._phone("a", "INFO")
        next(stream)
        next(stream)  # the backlog line

        rotated = self.dir / "web.ndjson.1"
        os.replace(self.dir / "web.ndjson", rotated)
        self._write("web", self._record("INFO", "after rotation"))
        self._poll()

        self.assertEqual([e["message"] for e in self._drain(token)], ["after rotation"])

    def test_missing_log_files_are_not_an_error(self):
        self.service._log_dir = lambda: None
        token, stream = self._phone("a", "INFO")
        next(stream)
        self._poll()
        self.assertEqual(self._drain(token), [])

        self.service._log_dir = lambda: self.dir / "does-not-exist"
        self._poll()
        self.assertEqual(self._drain(token), [])

    def test_the_follower_stops_when_the_last_phone_with_logs_leaves(self):
        token, stream = self._phone("a", "INFO")
        next(stream)
        self.assertIsNotNone(self.service._log_follower)
        self.assertFalse(self.service._log_stop.is_set())

        stream.close()

        self.assertEqual(self.service._log_levels, {})
        self.assertTrue(self.service._log_stop.is_set(), "nothing was left to follow the log files for")

    def test_the_follower_keeps_going_while_one_phone_with_logs_remains(self):
        _a, stream_a = self._phone("a", "INFO")
        _b, stream_b = self._phone("b", "WARNING")
        next(stream_a)
        next(stream_b)
        stream_a.close()
        self.assertFalse(self.service._log_stop.is_set())
        stream_b.close()
        self.assertTrue(self.service._log_stop.is_set())

    def test_the_session_page_offers_the_level_filter(self):
        page = _session_page("tok-123")
        for level in ("DEBUG", "INFO", "WARNING", "ERROR"):
            self.assertIn(f'data-level="{level}"', page)
        self.assertIn('addEventListener("log"', page)
        self.assertIn("&level=", page)
        self.assertIn("Payloads and control actions are not exposed", page)


class MobileStreamAppTests(unittest.TestCase):
    """The mobile stream's routes as a wsbuilder app: the same handlers answer
    HTTP/1.1 and HTTP/3, because both transports call this app's dispatch."""

    CLIENT = ("192.0.2.20", 50000)

    def setUp(self):
        self.service = MobileStreamService()
        self.service._state = MobileServerState(
            interface="eth0", address="192.0.2.10", port=45679, running=True,
            url_base="https://192.0.2.10:45679",
        )
        self.advertised: dict[str, str] = {}
        self.app = _build_mobile_app(self.service, self.advertised)

    def _call(self, path, *, method="GET", query="", body=b"", client=None):
        request = Request(method, path, query, {"user-agent": "phone"}, body, client or self.CLIENT)
        return self.app.dispatch(request)

    def _text(self, response):
        return bytes(response.body).decode("utf-8")

    def _headers(self, response):
        return {str(key).lower(): str(value) for key, value in response.headers.items()}

    def _approved_pairing(self, pairing_id="pair-1"):
        pairing = Pairing(
            id=pairing_id, interface="eth0", address="192.0.2.10", port=45679,
            created_at=_now(), expires_at=_now() + PAIRING_APPROVAL_TTL_SECONDS,
        )
        self.service._pairings[pairing_id] = pairing
        self._call(f"/mobile/pair/{pairing_id}")
        self.service.approve_pairing(pairing_id)
        return pairing

    def _session(self, token="live-token"):
        self.service._sessions[token] = MobileSession(
            token=token, interface="eth0", address="192.0.2.10", client=self.CLIENT[0],
            user_agent="phone", created_at=_now(), last_seen=_now(),
        )
        return token

    def test_the_ca_is_served_never_cached_and_without_cors(self):
        self.assertEqual(self._call("/mobile/ca.pem").status, 403)
        self._session()
        with patch("sniff4hound.mobile_stream.public_mobile_ca_pem", return_value="-----BEGIN CERTIFICATE-----\nx\n"):
            response = self._call("/mobile/ca.pem", query="session=live-token")
        self.assertEqual(response.status, 200)
        headers = self._headers(response)
        self.assertEqual(headers["content-type"], "application/x-pem-file")
        self.assertEqual(headers["cache-control"], "no-store")
        self.assertEqual(headers["x-content-type-options"], "nosniff")
        self.assertEqual(headers["referrer-policy"], "no-referrer")
        self.assertNotIn("access-control-allow-origin", headers, "the pages are same-origin; nothing here is for another site")

    def test_the_ca_downloads_as_a_certificate_a_phone_offers_to_install(self):
        pem = "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n"
        self.assertEqual(self._call("/mobile/ca.crt").status, 403)
        self._session()
        with patch("sniff4hound.mobile_stream.public_mobile_ca_pem", return_value=pem):
            response = self._call("/mobile/ca.crt", query="session=live-token")
        self.assertEqual(response.status, 200)
        headers = self._headers(response)
        self.assertEqual(headers["content-type"], "application/x-x509-ca-cert")
        self.assertEqual(headers["content-disposition"], 'attachment; filename="sniff4hound-ca.crt"')
        self.assertEqual(headers["cache-control"], "no-store")
        self.assertNotIn("access-control-allow-origin", headers)
        self.assertEqual(self._text(response), pem)

    def test_without_a_ca_the_download_is_a_clear_404_not_an_empty_file(self):
        self._session()
        with patch("sniff4hound.mobile_stream.public_mobile_ca_pem", return_value=""):
            response = self._call("/mobile/ca.crt", query="session=live-token")
        self.assertEqual(response.status, 404)
        self.assertNotEqual(self._headers(response)["content-type"], "application/x-x509-ca-cert")

    def test_the_certificate_page_offers_the_download_and_the_fingerprint_to_check(self):
        from sniff4hound.tls import ca_fingerprint_sha256

        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {"SNIFF4HOUND_DATA_DIR": tmp}):
            import importlib

            import sniff4hound.settings as settings
            import sniff4hound.tls as tls

            importlib.reload(settings)
            tls = importlib.reload(tls)
            try:
                tls.ensure_mobile_tls("192.0.2.10")
                pem = tls.public_mobile_ca_pem()
                with patch("sniff4hound.mobile_stream.public_mobile_ca_pem", return_value=pem):
                    self._session()
                    page = self._text(self._call("/mobile/certificate", query="session=live-token"))
                fingerprint = tls.ca_fingerprint_sha256(pem)
            finally:
                importlib.reload(settings)
                importlib.reload(tls)
        self.assertTrue(fingerprint)
        self.assertIn(fingerprint, page)
        self.assertIn('href="/mobile/ca.crt?session=live-token"', page)
        for expected in ("Android", "iPhone", "Certificate Trust Settings", "Install a certificate"):
            self.assertIn(expected, page)
        self.assertNotIn("<script", page, "an instruction page needs no script")
        self.assertNotIn("/mobile/certificate", page, "the page does not link to itself")

    def test_the_certificate_page_without_a_ca_says_so(self):
        self._session()
        with patch("sniff4hound.mobile_stream.public_mobile_ca_pem", return_value=""):
            page = self._text(self._call("/mobile/certificate", query="session=live-token"))
        self.assertIn("No certificate is available", page)
        self.assertNotIn("/mobile/ca.crt", page)

    def test_every_stream_page_links_to_the_certificate(self):
        from sniff4hound.mobile_stream import _awaiting_approval_page, _closed_page, _pairing_page, _session_page

        pairing = self._approved_pairing("pair-links")
        pages = {
            "awaiting": _awaiting_approval_page(),
            "pairing": _pairing_page(pairing),
            "session": _session_page("tok"),
            "closed": _closed_page(),
        }
        for name, page in pages.items():
            if name == "session":
                self.assertIn('href="/mobile/certificate?session=tok"', page, name)
            else:
                self.assertNotIn('href="/mobile/certificate"', page, name)

    def test_the_waiting_page_still_runs_no_script(self):
        from sniff4hound.mobile_stream import _awaiting_approval_page

        self.assertNotIn("<script", _awaiting_approval_page())

    def test_the_session_page_tells_which_protocol_it_arrived_by(self):
        page = _session_page("tok-123")
        self.assertIn("nextHopProtocol", page)
        self.assertIn('id="protocol"', page)

    def test_a_device_that_knocks_sees_a_holding_page_until_the_operator_approves(self):
        pairing = Pairing(
            id="pair-1", interface="eth0", address="192.0.2.10", port=45679,
            created_at=_now(), expires_at=_now() + PAIRING_APPROVAL_TTL_SECONDS,
        )
        self.service._pairings["pair-1"] = pairing

        waiting = self._call("/mobile/pair/pair-1")
        self.assertEqual(waiting.status, 200)
        self.assertIn("Waiting for approval", self._text(waiting))
        self.assertNotIn(pairing.code or "no-code-yet", self._text(waiting))

        self.service.approve_pairing("pair-1")
        approved = self._call("/mobile/pair/pair-1")
        self.assertEqual(approved.status, 200)
        self.assertIn("Enter pairing code", self._text(approved))

    def test_an_unknown_pairing_link_is_closed(self):
        response = self._call("/mobile/pair/never-issued")
        self.assertEqual(response.status, 410)
        self.assertIn("closed", self._text(response))

    def test_the_right_code_redirects_to_a_session(self):
        pairing = self._approved_pairing()
        response = self._call("/mobile/pair/pair-1/verify", method="POST", body=f"code={pairing.code}".encode())

        self.assertEqual(response.status, 303)
        location = self._headers(response)["location"]
        self.assertTrue(location.startswith("/mobile/session/"), location)
        token = location.rsplit("/", 1)[-1]
        self.assertIsNotNone(self.service.session(token), "the redirect names a session that does not exist")

    def test_a_wrong_code_closes_the_link_for_good(self):
        pairing = self._approved_pairing()
        wrong = self._call("/mobile/pair/pair-1/verify", method="POST", body=b"code=000000")
        self.assertEqual(wrong.status, 403)
        self.assertIn("Incorrect code", self._text(wrong))

        retry = self._call("/mobile/pair/pair-1/verify", method="POST", body=f"code={pairing.code}".encode())
        self.assertEqual(retry.status, 403, "the correct code worked after a wrong attempt")
        self.assertEqual(self.service._sessions, {})

    def test_the_code_works_only_from_the_device_that_was_approved(self):
        pairing = self._approved_pairing()
        elsewhere = self._call(
            "/mobile/pair/pair-1/verify", method="POST", body=f"code={pairing.code}".encode(),
            client=("192.0.2.99", 40000),
        )
        self.assertEqual(elsewhere.status, 403)

    def test_the_session_page_and_the_stream_need_a_live_session(self):
        self.assertEqual(self._call("/mobile/session/nope").status, 403)
        events = self._call("/mobile/events", query="session=nope&level=INFO")
        self.assertEqual(events.status, 403)
        self.assertEqual(self._text(events), "forbidden")

        token = self._session()
        page = self._call(f"/mobile/session/{token}")
        self.assertEqual(page.status, 200)
        self.assertIn("Live stream", self._text(page))
        self.assertIn(token, self._text(page))

    def test_the_event_stream_is_sse_and_starts_with_hello(self):
        token = self._session()
        response = self._call("/mobile/events", query=f"session={token}")

        self.assertEqual(response.status, 200)
        self.assertTrue(self._headers(response)["content-type"].startswith("text/event-stream"))
        self.assertEqual(self._headers(response)["cache-control"], "no-store")
        stream = iter(response.stream)
        self.assertIn(b"event: hello", next(stream))
        response.stream.close()

    def test_the_id_in_the_path_wins_over_one_in_the_query(self):
        real = self._session("real-token")
        # The path says which session; a query parameter of the same name cannot redirect it.
        self.assertEqual(self._call(f"/mobile/session/{real}", query="token=other").status, 200)
        self.assertEqual(self._call("/mobile/session/other", query=f"token={real}").status, 403)

    def test_odd_paths_reach_no_handler(self):
        for path in ("/mobile/pair/a/b/verify", "/mobile/session/a/b", "/mobile/pair/../session/x", "/nothing", "/"):
            with self.subTest(path=path):
                response = self._call(path)
                self.assertEqual(response.status, 404)
                self.assertIn("Not found.", self._text(response))

    def test_alt_svc_is_advertised_only_once_http3_is_listening(self):
        self._session("live-token")
        with patch("sniff4hound.mobile_stream.public_mobile_ca_pem", return_value="PEM"):
            self.assertNotIn("alt-svc", self._headers(self._call("/mobile/ca.pem", query="session=live-token")))

            self.advertised["alt_svc"] = 'h3=":45679"; ma=3600'
            self.assertEqual(self._headers(self._call("/mobile/ca.pem", query="session=live-token"))["alt-svc"], 'h3=":45679"; ma=3600')
        # ...on error pages too, so a client that first lands on a stale link still learns it.
        self.assertEqual(self._headers(self._call("/nothing"))["alt-svc"], 'h3=":45679"; ma=3600')


def _free_tcp_udp_port() -> int:
    """A port number that is free for both TCP and UDP, which is what the
    mobile stream needs: TLS over TCP and HTTP/3 over UDP on the same number."""
    for _ in range(50):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp:
            tcp.bind(("127.0.0.1", 0))
            port = tcp.getsockname()[1]
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            try:
                udp.bind(("127.0.0.1", port))
            except OSError:
                continue
        return port
    raise RuntimeError("no port free for both TCP and UDP")


class MobileStreamListenTests(unittest.TestCase):
    """The service as it is started: TLS over TCP plus HTTP/3 on the same port."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        material = _write_self_signed_material(Path(self._tmp.name))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(material.server_cert), str(material.server_key))
        material.ssl_context = context
        for target, value in (
            ("sniff4hound.mobile_stream.ensure_mobile_tls", material),
            ("sniff4hound.mobile_stream.public_mobile_ca_pem", "PEM"),
        ):
            patcher = patch(target, return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.service = MobileStreamService()
        self.service._sessions["live-token"] = MobileSession(
            token="live-token", interface="lo", address="127.0.0.1", client="127.0.0.1",
            user_agent="test", created_at=_now(), last_seen=_now(),
        )
        self.addCleanup(self.service.stop)

    def _https_get(self, port, path):
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        connection = http.client.HTTPSConnection("127.0.0.1", port, timeout=5, context=context)
        try:
            connection.request("GET", path)
            response = connection.getresponse()
            return response.status, {key.lower(): value for key, value in response.getheaders()}, response.read()
        finally:
            connection.close()

    def _port_is_free(self, port) -> bool:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp:
            try:
                tcp.bind(("127.0.0.1", port))
            except OSError:
                return False
        return True

    def test_it_serves_https_and_advertises_http3_on_the_same_port(self):
        port = _free_tcp_udp_port()
        state = self.service._listen("lo", "127.0.0.1", port)

        self.assertTrue(state["running"])
        self.assertTrue(state["mdns"]["enabled"])
        self.assertEqual(state["mdns"]["addresses"], ["127.0.0.1"])
        self.assertTrue(state["mdns"]["hostname"].endswith(".local"))
        self.assertEqual(state["url_base"], f"https://127.0.0.1:{port}")
        self.assertEqual(state["mdns_url_base"], f'https://{state["mdns"]["hostname"]}:{port}')
        self.assertTrue(state["http3"]["enabled"])
        self.assertEqual(state["http3"]["transport"], "https+h3")
        self.assertIn(f'h3=":{port}"', state["http3"]["alt_svc"])
        status, headers, body = self._https_get(port, "/mobile/ca.pem?session=live-token")
        self.assertEqual((status, body), (200, b"PEM"))
        self.assertEqual(headers["alt-svc"], state["http3"]["alt_svc"])
        status, _headers, body = self._https_get(port, "/mobile/nowhere")
        self.assertEqual(status, 404)
        self.assertIn(b"Not found.", body)

    def test_stopping_releases_both_listeners(self):
        port = _free_tcp_udp_port()
        self.service._listen("lo", "127.0.0.1", port)
        self.assertFalse(self._port_is_free(port))

        state = self.service.stop()

        self.assertFalse(state["running"])
        deadline = time.monotonic() + 5
        while not self._port_is_free(port) and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertTrue(self._port_is_free(port), "the TCP listener outlived stop()")
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.bind(("127.0.0.1", port))  # raises if the HTTP/3 listener is still holding it

    def test_failed_mdns_publication_keeps_the_ip_stream_available(self):
        port = _free_tcp_udp_port()
        with patch("sniff4hound.mobile_stream.mdns.publish", side_effect=OSError("multicast unavailable")):
            state = self.service._listen("lo", "127.0.0.1", port)
        self.assertTrue(state["running"])
        self.assertEqual(state["url_base"], f"https://127.0.0.1:{port}")
        self.assertFalse(state["mdns"]["enabled"])
        self.assertIn("multicast unavailable", state["mdns"]["error"])
        status, _headers, _body = self._https_get(port, "/mobile/ca.pem?session=live-token")
        self.assertEqual(status, 200)
        self.service.stop()
        deadline = time.monotonic() + 5
        while not self._port_is_free(port) and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertTrue(self._port_is_free(port))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.bind(("127.0.0.1", port))

    def test_a_busy_tcp_port_fails_with_a_message_instead_of_inside_a_thread(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as holder:
            holder.bind(("127.0.0.1", 0))
            holder.listen(1)
            port = holder.getsockname()[1]
            with self.assertRaises(ValueError) as caught:
                self.service._listen("lo", "127.0.0.1", port)
        self.assertIn(str(port), str(caught.exception))
        self.assertIn("unavailable", str(caught.exception))
        self.assertFalse(self.service.status()["running"])

    def test_without_udp_it_still_serves_https_and_says_why_http3_is_off(self):
        port = _free_tcp_udp_port()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as holder:
            holder.bind(("127.0.0.1", port))
            state = self.service._listen("lo", "127.0.0.1", port)

            self.assertTrue(state["running"])
            self.assertFalse(state["http3"]["enabled"])
            self.assertEqual(state["http3"]["transport"], "https")
            self.assertIn("HTTP/3 is off", state["http3"]["reason"])
            status, headers, _body = self._https_get(port, "/mobile/ca.pem?session=live-token")
            self.assertEqual(status, 200)
            self.assertNotIn("alt-svc", headers, "HTTP/3 was advertised while nothing listens for it")


if __name__ == "__main__":
    unittest.main()
