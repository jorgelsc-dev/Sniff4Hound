from __future__ import annotations

import tempfile
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


if __name__ == "__main__":
    unittest.main()
