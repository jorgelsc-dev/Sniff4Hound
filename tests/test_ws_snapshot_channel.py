from __future__ import annotations

import json
import os
import tempfile
import threading
import time
import unittest
import unittest.mock


class _FakeFrame:
    def __init__(self, payload: bytes, opcode: int = 0x1):
        self.opcode = opcode
        self.payload = payload


class _FakeWS:
    """Enough of a wsbuilder socket to drive websocket_handler's read loop."""

    def __init__(self, actions=()):
        self.addr = ("127.0.0.1", 0)
        self.subprotocol = ""
        self.sent: list[dict] = []
        self.closed_with = None
        self._frames = [
            _FakeFrame(json.dumps(action).encode("utf-8")) for action in actions
        ]
        # A close frame terminates the loop instead of blocking forever.
        self._frames.append(_FakeFrame(b"\x03\xe8", opcode=0x8))

    def send_text(self, message):
        self.sent.append(json.loads(message))

    def send_pong(self, _payload):
        pass

    def recv_frame(self):
        if not self._frames:
            raise RuntimeError("no more frames")
        return self._frames.pop(0)

    def close(self, code=1000, reason=""):
        self.closed_with = (code, reason)

    def types(self):
        return [message.get("type") for message in self.sent]

    def first_of(self, message_type):
        for message in self.sent:
            if message.get("type") == message_type:
                return message
        raise AssertionError(f"{message_type} not sent; got {self.types()}")


class _DeadWS(_FakeWS):
    def send_text(self, message):
        raise OSError("broken pipe")


def _app_module():
    # No mkdtemp() here. tests/__init__.py already points SNIFF4HOUND_DATA_DIR
    # at a throwaway directory before any test module is imported, and
    # setdefault() evaluates its default eagerly - so calling mkdtemp() inline
    # created and immediately orphaned a directory on every single call,
    # whether or not the variable was already set.
    import sniff4hound.app as app_module

    return app_module


class SubscriptionSchedulingTests(unittest.TestCase):
    def setUp(self):
        self.app = _app_module()
        self.hub = self.app.hub
        self.ws = _FakeWS()
        self.hub.register(self.ws)
        self.addCleanup(self.hub.unregister, self.ws)

    def _params(self, **extra):
        params = {"proto": "arp", "mode": "", "interface": "", "search": "", "since": "", "limit": 10}
        params.update(extra)
        return params

    def test_a_new_subscription_is_due_immediately(self):
        # The first delivery is what replaces the HTTP request the view would
        # otherwise make on mount, so it must not wait a whole interval.
        self.hub.subscribe_snapshot(self.ws, self._params(), 5.0)
        self.assertEqual(len(self.hub.due_subscriptions(time.monotonic())), 1)

    def test_it_does_not_fire_again_before_the_interval(self):
        now = time.monotonic()
        self.hub.subscribe_snapshot(self.ws, self._params(), 5.0)
        self.hub.due_subscriptions(now)
        self.assertEqual(self.hub.due_subscriptions(now + 4.9), [])

    def test_it_fires_again_after_the_interval(self):
        now = time.monotonic()
        self.hub.subscribe_snapshot(self.ws, self._params(), 5.0)
        self.hub.due_subscriptions(now)
        self.assertEqual(len(self.hub.due_subscriptions(now + 5.1)), 1)

    def test_resubscribing_replaces_instead_of_accumulating(self):
        # Navigating between protocols must not leave the previous slice being
        # computed forever; that is how one tab turns into N queries per tick.
        self.hub.subscribe_snapshot(self.ws, self._params(proto="arp"), 5.0)
        self.hub.subscribe_snapshot(self.ws, self._params(proto="dns"), 5.0)
        due = self.hub.due_subscriptions(time.monotonic())
        self.assertEqual(len(due), 1)
        self.assertEqual(due[0][1]["proto"], "dns")

    def test_unsubscribing_stops_delivery(self):
        self.hub.subscribe_snapshot(self.ws, self._params(), 5.0)
        self.hub.unsubscribe_snapshot(self.ws)
        self.assertEqual(self.hub.due_subscriptions(time.monotonic() + 3600), [])

    def test_an_unregistered_client_cannot_subscribe(self):
        stranger = _FakeWS()
        self.assertFalse(self.hub.subscribe_snapshot(stranger, self._params(), 5.0))

    def test_a_dead_socket_is_dropped_rather_than_retried(self):
        dead = _DeadWS()
        self.hub.register(dead)
        self.hub.subscribe_snapshot(dead, self._params(), 5.0)
        self.assertFalse(self.hub.send_to(dead, {"type": "x"}))
        self.assertEqual(self.hub.due_subscriptions(time.monotonic() + 3600), [])


class SubscribeActionTests(unittest.TestCase):
    """The inbound action, driven through the real handler loop."""

    def setUp(self):
        self.app = _app_module()
        # The handler authenticates before it reads a single frame, so the
        # action parsing under test is unreachable with auth on. The auth path
        # itself is covered by tests/test_smoke.py.
        patcher = unittest.mock.patch.object(self.app, "REQUIRE_AUTH", False)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _run(self, actions):
        ws = _FakeWS(actions)
        self.app.websocket_handler(ws, request=None)
        return ws

    def test_subscribing_acknowledges_with_the_effective_settings(self):
        ws = self._run([{"action": "subscribe_protocol_snapshot", "proto": "arp", "interval": 7}])
        ack = ws.first_of("protocol_snapshot_subscribed")
        self.assertEqual(ack["protocol"], "arp")
        self.assertEqual(ack["interval"], 7.0)

    def test_a_zero_interval_is_clamped_to_the_floor(self):
        # Unbounded, this would run the aggregate queries in a tight loop for
        # as long as the client stays connected.
        ws = self._run([{"action": "subscribe_protocol_snapshot", "proto": "arp", "interval": 0}])
        self.assertEqual(
            ws.first_of("protocol_snapshot_subscribed")["interval"],
            self.app.WS_SNAPSHOT_MIN_INTERVAL_SECONDS,
        )

    def test_a_negative_interval_is_clamped_too(self):
        ws = self._run([{"action": "subscribe_protocol_snapshot", "proto": "arp", "interval": -30}])
        self.assertEqual(
            ws.first_of("protocol_snapshot_subscribed")["interval"],
            self.app.WS_SNAPSHOT_MIN_INTERVAL_SECONDS,
        )

    def test_a_huge_interval_is_capped(self):
        ws = self._run([{"action": "subscribe_protocol_snapshot", "proto": "arp", "interval": 99999}])
        self.assertEqual(
            ws.first_of("protocol_snapshot_subscribed")["interval"],
            self.app.WS_SNAPSHOT_MAX_INTERVAL_SECONDS,
        )

    def test_the_limit_is_normalized_like_the_http_endpoint(self):
        ws = self._run([
            {"action": "subscribe_protocol_snapshot", "proto": "arp", "limit": 10_000_000}
        ])
        acknowledged = ws.first_of("protocol_snapshot_subscribed")["limit"]
        self.assertLess(acknowledged, 10_000_000)

    def test_unsubscribing_is_acknowledged(self):
        ws = self._run([
            {"action": "subscribe_protocol_snapshot", "proto": "arp"},
            {"action": "unsubscribe_protocol_snapshot"},
        ])
        self.assertIn("protocol_snapshot_unsubscribed", ws.types())

    def test_an_unknown_action_is_ignored_rather_than_fatal(self):
        ws = self._run([{"action": "definitely_not_a_real_action"}])
        self.assertIn("welcome", ws.types())


class SnapshotPayloadTests(unittest.TestCase):
    def test_the_pushed_payload_matches_the_http_slice(self):
        app = _app_module()
        params = {"proto": "arp", "mode": "", "interface": "", "search": "", "since": "", "limit": 10}
        payload = app._protocol_snapshot_payload(params)
        self.assertEqual(payload["type"], "protocol_snapshot")
        self.assertEqual(payload["protocol"], "arp")
        # The view renders straight off these three, so the channel has to
        # carry the same shape the endpoint returns, not a reduced one.
        for key in ("totals", "facets", "columns", "packets"):
            self.assertIn(key, payload["snapshot"])

    def test_the_pusher_starts_on_demand_and_is_a_daemon(self):
        app = _app_module()
        thread = app._ensure_snapshot_pusher()
        self.assertTrue(thread.is_alive())
        # A non-daemon pusher would keep the process alive on shutdown.
        self.assertTrue(thread.daemon)

    def test_asking_for_the_pusher_repeatedly_starts_only_one(self):
        # One thread total, not one per connection or per import: each delivery
        # runs aggregate queries, and duplicates would multiply the database
        # load. Starting it at import leaked one thread per module reload,
        # which is how this was found.
        app = _app_module()
        first = app._ensure_snapshot_pusher()
        for _ in range(5):
            self.assertIs(app._ensure_snapshot_pusher(), first)
        pushers = [t for t in threading.enumerate()
                   if t.name == "sniff4hound-ws-snapshots" and t.is_alive()]
        self.assertEqual(len(pushers), 1)

    def test_no_pusher_runs_until_something_subscribes(self):
        # Importing the app must not cost a thread; a CLI or packaging run
        # never serves a subscriber.
        import subprocess
        import sys

        # The data dir is forced, not defaulted: SNIFF4HOUND_DATA_DIR is
        # inherited from this process, so setdefault() would silently point the
        # child at the suite's own database and put a second writer on it.
        environment = dict(os.environ)
        # The child needs a directory of its own - inheriting this process's
        # would put a second writer on the suite's database - and it has to be
        # removed afterwards, which is what TemporaryDirectory guarantees even
        # if the assertion below fails.
        child_data_dir = tempfile.TemporaryDirectory(prefix="s4h-wsproc-")
        self.addCleanup(child_data_dir.cleanup)
        environment["SNIFF4HOUND_DATA_DIR"] = child_data_dir.name
        result = subprocess.run(
            [sys.executable, "-c",
             "import threading, sniff4hound.app;"
             "print(sum(1 for t in threading.enumerate()"
             " if t.name == 'sniff4hound-ws-snapshots'))"],
            capture_output=True, text=True, env=environment, timeout=120,
        )
        self.assertEqual(result.stdout.strip().splitlines()[-1], "0", result.stderr[-500:])


if __name__ == "__main__":
    unittest.main()
