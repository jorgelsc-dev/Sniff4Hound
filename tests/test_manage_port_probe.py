from __future__ import annotations

import errno
import socket
import time
import unittest

from sniff4hound import manage


def _server_style_listener(host: str = "127.0.0.1", port: int = 0) -> socket.socket:
    """A listening socket bound the way the real web server binds
    (wsbuilder's HTTPServer sets SO_REUSEADDR before bind())."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(8)
    return sock


def _plain_bind_fails(host: str, port: int) -> bool:
    """What the probe used to do before #294: bind() without SO_REUSEADDR."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.bind((host, port))
        except OSError as exc:
            if exc.errno == errno.EADDRINUSE:
                return True
            raise
    return False


@unittest.skipIf(manage.os.name == "nt", "TIME-WAIT bind semantics are BSD/Linux specific")
class TestPortProbeAfterServerRestart(unittest.TestCase):
    """#294: restarting the web process left the server-side halves of its
    closed connections in TIME-WAIT, the probe (no SO_REUSEADDR) reported the
    port busy and the runtime silently moved to port+1, so remote consoles
    pointed at the old port never reconnected."""

    host = "127.0.0.1"

    def _port_with_only_time_wait_leftovers(self) -> int:
        listener = _server_style_listener(self.host)
        port = listener.getsockname()[1]
        client = socket.create_connection((self.host, port), timeout=5)
        accepted, _ = listener.accept()
        # The server closes first, as it does when it shuts down, so the
        # server-side socket (local port == `port`) is the one left in
        # FIN-WAIT-2/TIME-WAIT.
        accepted.close()
        client.settimeout(5)
        self.assertEqual(client.recv(1), b"", "client never saw the server's FIN")
        client.close()
        listener.close()
        return port

    def test_port_held_only_by_time_wait_connections_counts_as_available(self):
        port = self._port_with_only_time_wait_leftovers()
        # Prove the scenario is real: the old probe would have called it busy.
        deadline = time.monotonic() + 2
        while not _plain_bind_fails(self.host, port):
            if time.monotonic() > deadline:
                self.skipTest("kernel left no TIME-WAIT leftover on the port")
            time.sleep(0.01)

        self.assertTrue(manage._port_is_available(self.host, port))
        self.assertEqual(manage._select_listen_port(self.host, port), port)
        # ...and the probe agrees with the server's own bind.
        restarted = _server_style_listener(self.host, port)
        restarted.close()

    def test_port_with_a_real_listener_is_still_busy(self):
        with _server_style_listener(self.host) as listener:
            port = listener.getsockname()[1]
            self.assertFalse(manage._port_is_available(self.host, port))
            selected = manage._select_listen_port(self.host, port)
            self.assertIsNotNone(selected)
            self.assertNotEqual(selected, port)

    def test_port_bound_without_reuseaddr_is_still_busy(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as holder:
            holder.bind((self.host, 0))
            port = holder.getsockname()[1]
            self.assertFalse(manage._port_is_available(self.host, port))


if __name__ == "__main__":
    unittest.main()
