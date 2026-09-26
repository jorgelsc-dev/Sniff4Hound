from __future__ import annotations

import tempfile
import threading
import time
import unittest
from pathlib import Path

from sniff4hound.ipc import (
    IpcAuthError,
    IpcClient,
    IpcError,
    IpcEventSink,
    IpcServer,
    generate_ipc_token,
)


def _wait_until(predicate, *, timeout=2.0, interval=0.02):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


def _succeeds(client, method, **kwargs) -> bool:
    try:
        client.call(method, **kwargs)
        return True
    except Exception:
        return False


class IpcTests(unittest.TestCase):
    def setUp(self):
        self._tmp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp_dir.cleanup)
        self.socket_path = str(Path(self._tmp_dir.name) / "capture.sock")
        self.token = generate_ipc_token()

    def _start_server(self, methods=None):
        server = IpcServer(self.socket_path, self.token, methods=methods)
        server.start()
        self.addCleanup(server.stop)
        return server

    def test_request_response_round_trip(self):
        server = self._start_server({"echo": lambda value=None: {"echoed": value}})
        client = IpcClient(self.socket_path, self.token, connect_timeout=2)
        client.connect()
        self.addCleanup(client.close)

        self.assertEqual(client.call("echo", value=42), {"echoed": 42})

    def test_unknown_method_raises_ipc_error(self):
        server = self._start_server()
        client = IpcClient(self.socket_path, self.token, connect_timeout=2)
        client.connect()
        self.addCleanup(client.close)

        with self.assertRaises(IpcError):
            client.call("does_not_exist")

    def test_handler_exception_is_propagated_as_ipc_error(self):
        def _boom():
            raise RuntimeError("kaboom")

        server = self._start_server({"boom": _boom})
        client = IpcClient(self.socket_path, self.token, connect_timeout=2)
        client.connect()
        self.addCleanup(client.close)

        with self.assertRaises(IpcError) as ctx:
            client.call("boom")
        self.assertIn("kaboom", str(ctx.exception))

    def test_wrong_token_is_rejected(self):
        self._start_server()
        client = IpcClient(self.socket_path, "wrong-token", connect_timeout=2)

        with self.assertRaises(IpcAuthError):
            client.connect()

    def test_connect_times_out_when_socket_never_appears(self):
        client = IpcClient(str(Path(self._tmp_dir.name) / "missing.sock"), self.token, connect_timeout=0.3)
        with self.assertRaises(IpcError):
            client.connect()

    def test_event_sink_publishes_to_connected_client(self):
        server = self._start_server()
        events = []
        client = IpcClient(self.socket_path, self.token, on_event=events.append, connect_timeout=2)
        client.connect()
        self.addCleanup(client.close)

        sink = IpcEventSink(server)
        _wait_until(server.has_client)
        sink.broadcast({"type": "packet", "packet": {"id": 1}})

        self.assertTrue(_wait_until(lambda: len(events) == 1))
        self.assertEqual(events[0], {"type": "packet", "packet": {"id": 1}})

    def test_publish_without_client_is_a_noop(self):
        server = self._start_server()
        sink = IpcEventSink(server)
        sink.broadcast({"type": "packet"})  # must not raise

    def test_call_fails_fast_once_disconnected(self):
        server = self._start_server()
        client = IpcClient(self.socket_path, self.token, connect_timeout=2)
        client.connect()
        client.close()

        with self.assertRaises(Exception):
            client.call("snapshot")


class IpcReconnectTests(unittest.TestCase):
    """The web process used to connect exactly once, at startup. When that
    link dropped - capture process restarted, socket closed, anything - the
    client stayed down for good and every later runtime call raised, so the
    app answered "Internal Server Error" on every attempt to start or stop
    an engine until it was restarted."""

    def setUp(self):
        self._tmp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp_dir.cleanup)
        self.socket_path = str(Path(self._tmp_dir.name) / "capture.sock")
        self.token = generate_ipc_token()
        self.methods = {"snapshot": lambda: {"mode": "sniffer"}}

    def _start_server(self):
        server = IpcServer(self.socket_path, self.token, methods=self.methods)
        server.start()
        self.addCleanup(server.stop)
        return server

    def test_call_reconnects_after_the_capture_process_restarts(self):
        server = self._start_server()
        client = IpcClient(self.socket_path, self.token, connect_timeout=2, call_timeout=2)
        client.connect()
        self.addCleanup(client.close)
        self.assertEqual(client.call("snapshot"), {"mode": "sniffer"})

        server.stop()
        self.assertTrue(_wait_until(lambda: not client.connected))
        self._start_server()

        self.assertEqual(client.call("snapshot"), {"mode": "sniffer"})
        self.assertTrue(client.connected)
        # Still healthy afterwards, i.e. the reconnect installed a working
        # reader rather than leaving a half-built connection behind.
        self.assertEqual(client.call("snapshot"), {"mode": "sniffer"})

    def test_reconnect_does_not_retry_a_rejected_token(self):
        self._start_server()
        client = IpcClient(self.socket_path, "wrong-token", connect_timeout=1, call_timeout=1)
        with self.assertRaises(IpcAuthError):
            client.connect()
        # Latched: a bad token is not a transient fault, and retrying it only
        # feeds the auth rate limiter.
        with self.assertRaises(IpcAuthError):
            client.call("snapshot")

    def test_a_failed_reconnect_puts_later_calls_on_a_short_cooldown(self):
        """Every API route goes through `jobs.JobQueue`'s small worker pool, and
        reconnect attempts serialise on one lock. Without a cooldown, each call
        made while the capture service is down pays the full reconnect budget
        and queues behind the previous one, so a handful of runtime requests
        would occupy every worker and slow unrelated routes to a crawl."""
        server = self._start_server()
        client = IpcClient(self.socket_path, self.token, connect_timeout=2, call_timeout=2)
        client.connect()
        self.addCleanup(client.close)
        self.assertEqual(client.call("snapshot"), {"mode": "sniffer"})

        server.stop()
        self.assertTrue(_wait_until(lambda: not client.connected))

        started = time.monotonic()
        with self.assertRaises(IpcError):
            client.call("snapshot")
        first_attempt = time.monotonic() - started
        # That one really tried (and so paid the reconnect budget).
        self.assertGreater(first_attempt, 0.2)

        started = time.monotonic()
        with self.assertRaises(IpcError):
            client.call("snapshot")
        second_attempt = time.monotonic() - started
        self.assertLess(second_attempt, 0.2, "a call inside the cooldown must fail fast")

    def test_the_cooldown_still_lets_the_client_recover(self):
        server = self._start_server()
        client = IpcClient(self.socket_path, self.token, connect_timeout=2, call_timeout=2)
        client.connect()
        self.addCleanup(client.close)

        server.stop()
        self.assertTrue(_wait_until(lambda: not client.connected))
        with self.assertRaises(IpcError):
            client.call("snapshot")

        self._start_server()
        # The cooldown delays the next attempt, it does not cancel it.
        self.assertTrue(
            _wait_until(lambda: _succeeds(client, "snapshot"), timeout=10),
            msg="client never reconnected after the capture service returned",
        )

    def test_a_slow_call_does_not_block_another_call(self):
        """Requests used to run inline on the connection's read loop, so the
        next frame was not even read until the current handler returned:
        stopping the honeypot (a thread join per listener) reliably timed out
        the sniffer's toggle, and the operator saw both fail."""
        release = threading.Event()
        entered = threading.Event()
        self.addCleanup(release.set)

        def slow():
            entered.set()
            release.wait(timeout=10)
            return {"slow": True}

        server = IpcServer(
            self.socket_path,
            self.token,
            methods={"slow": slow, "fast": lambda: {"fast": True}},
        )
        server.start()
        self.addCleanup(server.stop)

        client = IpcClient(self.socket_path, self.token, connect_timeout=2, call_timeout=5)
        client.connect()
        self.addCleanup(client.close)

        slow_result = {}
        slow_thread = threading.Thread(target=lambda: slow_result.update(client.call("slow")))
        slow_thread.start()
        try:
            # Wait for the slow handler to actually be *running*, not merely
            # for the client to be connected: otherwise "fast" can reach the
            # server first and the test proves nothing.
            self.assertTrue(entered.wait(timeout=5))
            self.assertEqual(client.call("fast"), {"fast": True})
        finally:
            release.set()
            slow_thread.join(timeout=10)
        self.assertEqual(slow_result, {"slow": True})


if __name__ == "__main__":
    unittest.main()
