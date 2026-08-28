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
        _ws, _feed, params = due[0]
        self.assertEqual(params["proto"], "dns")

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


class _FakeQuery(dict):
    def get(self, key, default=None):
        return dict.get(self, key, default)


class _FakeRequest:
    def __init__(self, **query):
        self.query = _FakeQuery({k: v for k, v in query.items() if v is not None})


class FeedRouteTests(unittest.TestCase):
    """One websocket route per data feed, parameterised entirely by its URL."""

    def setUp(self):
        self.app = _app_module()

    def test_every_feed_has_a_builder_and_a_route(self):
        # A route without a builder would accept the connection and then fail
        # on the first push, which the client sees as a silent dead stream.
        for name in self.app.WS_FEEDS:
            self.assertTrue(callable(self.app.WS_FEEDS[name]), f"{name} has no builder")

    def test_every_feed_produces_a_payload(self):
        params = self.app._normalize_feed_params(_FakeRequest(limit="10"))
        for name in self.app.WS_FEEDS:
            payload = self.app._feed_payload(name, params)
            self.assertEqual(payload["type"], "feed_data")
            self.assertEqual(payload["feed"], name)
            self.assertIn("data", payload)
            self.assertIn("generated_at", payload)

    def test_an_unknown_feed_is_refused(self):
        with self.assertRaises(KeyError):
            self.app._feed_payload("../../etc/passwd", {})

    def test_refresh_is_read_as_milliseconds(self):
        self.assertAlmostEqual(
            self.app._normalize_refresh(_FakeRequest(refresh="10000")), 10.0
        )

    def test_a_fast_refresh_is_clamped_to_the_floor(self):
        # The example in the request was refresh=100. Served literally, that is
        # ten aggregate queries a second per open socket.
        for raw in ("100", "1", "0", "-5"):
            self.assertEqual(
                self.app._normalize_refresh(_FakeRequest(refresh=raw)),
                self.app.WS_SNAPSHOT_MIN_INTERVAL_SECONDS,
                f"refresh={raw} was not clamped",
            )

    def test_a_huge_refresh_is_capped(self):
        self.assertEqual(
            self.app._normalize_refresh(_FakeRequest(refresh="999999999")),
            self.app.WS_SNAPSHOT_MAX_INTERVAL_SECONDS,
        )

    def test_a_missing_or_unparseable_refresh_falls_back(self):
        for request in (_FakeRequest(), _FakeRequest(refresh="abc")):
            self.assertEqual(
                self.app._normalize_refresh(request),
                self.app.WS_SNAPSHOT_DEFAULT_INTERVAL_SECONDS,
            )

    def test_limit_is_capped_like_the_http_endpoints(self):
        params = self.app._normalize_feed_params(_FakeRequest(limit="100000"))
        self.assertLess(params["limit"], 100000)

    def test_all_is_normalised_to_no_protocol_filter(self):
        self.assertEqual(self.app._normalize_feed_params(_FakeRequest(proto="all"))["proto"], "")

    def test_the_protocol_filter_is_normalised(self):
        self.assertEqual(self.app._normalize_feed_params(_FakeRequest(proto="  ARP "))["proto"], "arp")


class FeedSubscriptionTests(unittest.TestCase):
    def setUp(self):
        self.app = _app_module()
        self.hub = self.app.hub
        self.ws = _FakeWS()
        self.hub.register(self.ws)
        self.addCleanup(self.hub.unregister, self.ws)

    def test_the_subscription_remembers_which_feed_it_serves(self):
        self.hub.subscribe_snapshot(self.ws, {"proto": "", "limit": 10}, 5.0, feed="tags")
        due = self.hub.due_subscriptions(time.monotonic())
        self.assertEqual(len(due), 1)
        _ws, feed, _params = due[0]
        self.assertEqual(feed, "tags")

    def test_the_multiplexed_channel_keeps_its_own_message_type(self):
        # The Protocols view already listens for protocol_snapshot; the feed
        # routes must not change that envelope out from under it.
        payload = self.app._protocol_snapshot_payload(
            {"proto": "arp", "mode": "", "interface": "", "search": "", "since": "", "limit": 10}
        )
        self.assertEqual(payload["type"], "protocol_snapshot")
        self.assertIn("snapshot", payload)


class WsGetDispatchTests(unittest.TestCase):
    """Every read-only endpoint answers over the socket, through the real router."""

    def setUp(self):
        self.app = _app_module()
        import sniff4hound.auth as auth_module

        self.auth = auth_module
        self._previous_token = auth_module._SESSION_TOKEN
        auth_module._SESSION_TOKEN = "Ab12Cd34"
        self.addCleanup(setattr, auth_module, "_SESSION_TOKEN", self._previous_token)

    def _authed(self):
        return _FakeRequest(security_code="Ab12Cd34")

    def test_a_read_answers_with_data(self):
        result = self.app._ws_get_result(self._authed(), "/api/hello", {})
        self.assertEqual(result["status"], 200)
        self.assertIsInstance(result["data"], dict)

    def test_listing_headers_survive_the_socket(self):
        # The listing endpoints put their totals - and the IP scope breakdown -
        # in headers. A frame has none, so they travel in the payload; dropping
        # them would blank the "showing N of M" line and the scope chips.
        result = self.app._ws_get_result(self._authed(), "/api/intel/ips/", {"limit": 5})
        self.assertEqual(result["status"], 200)
        self.assertIn("X-Total-Available", result["headers"])
        self.assertIn("X-Scope-Counts", result["headers"])

    def test_query_parameters_reach_the_handler(self):
        result = self.app._ws_get_result(self._authed(), "/api/domains/", {"limit": 5})
        self.assertEqual(result["status"], 200)
        self.assertEqual(result["headers"].get("X-Returned"), "0")

    def _http_status(self, credential=None):
        """What an HTTP GET with the same credential would answer."""
        from wsbuilder import Request

        headers = {"X-Security-Code": credential} if credential else {}
        route = self.app.app.router.resolve("/api/hello", "GET")
        result = route.handler(Request("GET", "/api/hello", "", headers, b"", ("127.0.0.1", 0)))
        return 200 if isinstance(result, (dict, list)) else int(getattr(result, "status", 200) or 200)

    def test_the_socket_answers_exactly_what_http_would(self):
        """The security claim, stated so it does not depend on ambient config.

        `_apply_api_auth_guards()` wraps the handlers at import time, and other
        test modules reload sniff4hound.app with SNIFF4HOUND_REQUIRE_AUTH=0 -
        so asserting a bare 401 here passes alone and fails in a full run, for
        a reason that has nothing to do with this code. What must hold either
        way is the equivalence: a websocket client gets what an HTTP client
        with the same credential gets, and nothing more.
        """
        for credential in (None, "nope", "Ab12Cd34"):
            source = _FakeRequest(security_code=credential) if credential else _FakeRequest()
            through_socket = self.app._ws_get_result(source, "/api/hello", {})["status"]
            self.assertEqual(
                through_socket,
                self._http_status(credential),
                f"credential {credential!r}: socket and HTTP disagree",
            )

    def test_an_unauthenticated_socket_is_refused(self):
        # Only meaningful while the guards are actually installed; see above.
        if not self.app.REQUIRE_AUTH or self._http_status() == 200:
            self.skipTest("auth guards are not installed on this module instance")
        self.assertEqual(self.app._ws_get_result(_FakeRequest(), "/api/hello", {})["status"], 401)

    def test_a_wrong_credential_is_refused(self):
        if not self.app.REQUIRE_AUTH or self._http_status("nope") == 200:
            self.skipTest("auth guards are not installed on this module instance")
        result = self.app._ws_get_result(_FakeRequest(security_code="nope"), "/api/hello", {})
        self.assertEqual(result["status"], 401)

    def test_a_relative_path_is_refused(self):
        self.assertEqual(self.app._ws_get_result(self._authed(), "nope", {})["status"], 400)

    def test_an_unknown_route_is_refused(self):
        self.assertEqual(
            self.app._ws_get_result(self._authed(), "/api/does-not-exist/", {})["status"], 404
        )

    def test_a_non_api_route_is_refused(self):
        # A static or view route reached this way would answer with a page.
        self.assertEqual(self.app._ws_get_result(self._authed(), "/", {})["status"], 405)

    def test_downloads_stay_on_http(self):
        result = self.app._ws_get_result(self._authed(), "/api/export/alerts", {})
        self.assertEqual(result["status"], 400)
        self.assertIn("download", result["error"])


class FeedHttpParityTests(unittest.TestCase):
    """A feed must answer exactly what its HTTP endpoint answers.

    This is the property three separate bugs broke at once, and none of them
    was visible from either side alone: the feeds filtered by the protocol
    literally named "unknown" and returned nothing, they skipped the row
    shaping the endpoints apply, and /tags/ had the same protocol bug on the
    HTTP side. Comparing the two paths is what catches that class of drift.
    """

    FEEDS = (
        ("ports", "/ports/"),
        ("ips", "/ports/"),
        ("banners", "/banners/"),
        ("tags", "/tags/"),
        ("targets", "/targets/"),
        ("domains", "/api/domains/"),
        ("paths", "/api/paths/"),
        ("ipcatalog", "/api/intel/ips/"),
    )

    def setUp(self):
        self.app = _app_module()
        import sniff4hound.auth as auth_module

        previous = auth_module._SESSION_TOKEN
        auth_module._SESSION_TOKEN = "Ab12Cd34"
        self.addCleanup(setattr, auth_module, "_SESSION_TOKEN", previous)
        for index in range(3):
            self.app.store.register_packet({
                "proto": "tcp", "src_ip": f"10.9.9.{index}", "dst_ip": "10.9.9.250",
                "src_port": 4000 + index, "dst_port": 80, "length": 120,
                "interface": "parity0", "payload_len": 40,
                "banner_text": "HTTP/1.1 200 OK", "raw_packet": b"\x00\xff",
                "tags": [{"key": "parity", "label": "Parity", "severity": "low"}],
            })

    def _both(self, feed, path):
        params = self.app._normalize_feed_params(_FakeRequest(limit="50"))
        streamed = self.app._feed_payload(feed, params)["data"]
        if isinstance(streamed, dict):
            streamed = streamed.get("rows", streamed)
        answered = self.app._ws_get_result(
            _FakeRequest(security_code="Ab12Cd34"), path, {"limit": 50}
        )
        return streamed, answered

    def test_each_feed_returns_what_its_endpoint_returns(self):
        for feed, path in self.FEEDS:
            with self.subTest(feed=feed):
                streamed, answered = self._both(feed, path)
                self.assertEqual(answered["status"], 200, f"{path} did not answer")
                self.assertEqual(
                    len(streamed), len(answered["data"]),
                    f"{feed} and {path} disagree on how many rows exist",
                )
                if streamed and answered["data"]:
                    self.assertEqual(
                        sorted(streamed[0]), sorted(answered["data"][0]),
                        f"{feed} rows are shaped differently from {path}",
                    )

    def test_an_unfiltered_feed_is_not_filtered_by_protocol(self):
        # normalize_protocol_name("") answers "unknown", a real protocol name
        # here - so normalising before deciding whether a filter was asked for
        # turned every unfiltered feed into an empty list.
        params = self.app._normalize_feed_params(_FakeRequest())
        self.assertEqual(params["proto"], "")
        self.assertTrue(self.app._feed_payload("ports", params)["data"])

    def test_all_is_also_no_filter(self):
        self.assertEqual(self.app._normalize_feed_params(_FakeRequest(proto="all"))["proto"], "")

    def test_an_explicit_protocol_still_filters(self):
        params = self.app._normalize_feed_params(_FakeRequest(proto="tcp"))
        self.assertEqual(params["proto"], "tcp")
        self.assertTrue(self.app._feed_payload("ports", params)["data"])
        empty = self.app._normalize_feed_params(_FakeRequest(proto="sctp"))
        self.assertEqual(self.app._feed_payload("ports", empty)["data"], [])

    def test_the_raw_capture_never_rides_in_a_listing(self):
        # raw_packet is every captured byte. The endpoints drop it; a feed that
        # skipped their shaping would push it to every client on every tick.
        for feed, _path in self.FEEDS:
            with self.subTest(feed=feed):
                rows = self.app._feed_payload(
                    feed, self.app._normalize_feed_params(_FakeRequest(limit="50"))
                )["data"]
                if isinstance(rows, dict):
                    rows = rows.get("rows", rows)
                for row in rows or []:
                    self.assertNotIn("raw_packet", row, f"{feed} leaks the raw capture")

    def test_a_bare_tags_listing_is_not_filtered_to_unidentified_traffic(self):
        # /tags/ normalised the protocol before checking whether one was asked
        # for, so opening the listing with no filter answered with only the
        # rows whose protocol could not be identified - in practice, nothing.
        answered = self.app._ws_get_result(
            _FakeRequest(security_code="Ab12Cd34"), "/tags/", {"limit": 50}
        )
        self.assertEqual(answered["status"], 200)
        self.assertTrue(answered["data"], "a bare /tags/ answered with no rows")


if __name__ == "__main__":
    unittest.main()
