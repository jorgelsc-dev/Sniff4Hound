import datetime
import io
import ipaddress
import os
import socket
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace

from wsbuilder import App, Response


def _write_self_signed_material(directory: Path):
    """An ECDSA certificate, which the QUIC stack accepts without extra setup."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path = directory / "server.pem"
    key_path = directory / "server.key"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return SimpleNamespace(server_cert=cert_path, server_key=key_path)


def _free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Http3ListenerTests(unittest.TestCase):
    def setUp(self):
        from sniff4hound import http3_listener

        self.listener = http3_listener
        self.tmp = tempfile.TemporaryDirectory()
        self.material = _write_self_signed_material(Path(self.tmp.name))
        self.servers = []

    def tearDown(self):
        for server in self.servers:
            server.stop()
        self.listener.stop_http3(None)
        self.listener._active_alt_svc = None
        self.tmp.cleanup()

    def test_listener_binds_udp_and_advertises_alt_svc_until_stopped(self):
        port = _free_udp_port()
        server = self.listener.start_http3(App(), self.material, "127.0.0.1", port)
        self.assertIsNotNone(server)
        self.servers.append(server)

        self.assertEqual(self.listener.alt_svc_value(), f'h3=":{port}"; ma=3600')

        self.listener.stop_http3(server)
        self.assertIsNone(self.listener.alt_svc_value())

    def test_busy_udp_port_disables_http3_without_advertising_it(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as occupied:
            occupied.bind(("127.0.0.1", 0))
            port = occupied.getsockname()[1]
            output = io.StringIO()
            with redirect_stdout(output):
                server = self.listener.start_http3(App(), self.material, "127.0.0.1", port)

        self.assertIsNone(server)
        self.assertIsNone(self.listener.alt_svc_value())
        self.assertIn("HTTP/3 disabled", output.getvalue())
        self.assertIn(f":{port}/", output.getvalue())

    def test_stop_is_safe_when_http3_never_started(self):
        self.listener.stop_http3(None)
        self.assertIsNone(self.listener.alt_svc_value())


class AltSvcOnResponsesTests(unittest.TestCase):
    def setUp(self):
        self._previous = os.environ.get("SNIFF4HOUND_DATA_DIR")
        self._tmp = tempfile.TemporaryDirectory()
        os.environ["SNIFF4HOUND_DATA_DIR"] = self._tmp.name
        import sniff4hound.app as app_module
        from sniff4hound import http3_listener

        self.app_module = app_module
        self.listener = http3_listener

    def tearDown(self):
        self.listener._active_alt_svc = None
        if self._previous is None:
            os.environ.pop("SNIFF4HOUND_DATA_DIR", None)
        else:
            os.environ["SNIFF4HOUND_DATA_DIR"] = self._previous
        self._tmp.cleanup()

    def _dispatch(self):
        from wsbuilder import Request

        request = Request("GET", "/api/hello", "", {"host": "127.0.0.1"}, b"", ("127.0.0.1", 1))
        return self.app_module.app.dispatch(request)

    def test_responses_advertise_http3_only_while_the_listener_is_up(self):
        self.listener._active_alt_svc = 'h3=":45678"; ma=3600'
        self.assertEqual(self._dispatch().headers.get("Alt-Svc"), 'h3=":45678"; ma=3600')

        self.listener._active_alt_svc = None
        self.assertNotIn("Alt-Svc", self._dispatch().headers)


class SendGuardKeepAliveTests(unittest.TestCase):
    """wsbuilder decides keep-alive per request and passes it to the send guard.
    Announcing ``Connection: close`` while the server keeps the socket open makes
    clients drop it, so the guard must follow that decision."""

    class _Conn:
        def __init__(self):
            self.sent = []

        def sendall(self, data):
            self.sent.append(bytes(data))

        def head(self):
            return b"".join(self.sent).split(b"\r\n\r\n", 1)[0].decode()

    def setUp(self):
        self._previous = os.environ.get("SNIFF4HOUND_DATA_DIR")
        self._tmp = tempfile.TemporaryDirectory()
        os.environ["SNIFF4HOUND_DATA_DIR"] = self._tmp.name
        import sniff4hound.app as app_module

        self.guard = app_module._guarded_send_http_response

    def tearDown(self):
        if self._previous is None:
            os.environ.pop("SNIFF4HOUND_DATA_DIR", None)
        else:
            os.environ["SNIFF4HOUND_DATA_DIR"] = self._previous
        self._tmp.cleanup()

    def test_close_is_announced_when_the_server_will_not_reuse_the_socket(self):
        conn = self._Conn()
        self.guard(conn, Response.text("ok"), keep_alive=False)
        self.assertIn("Connection: close", conn.head())

    def test_no_close_is_announced_when_the_server_keeps_the_socket(self):
        conn = self._Conn()
        self.guard(conn, Response.text("ok"), keep_alive=True)
        self.assertNotIn("Connection: close", conn.head())
        self.assertTrue(conn.head().startswith("HTTP/1.1 200 OK"))

    def test_http_09_is_delegated_to_wsbuilder_writer(self):
        calls = []

        def fake_original(conn, response, **kwargs):
            calls.append(kwargs)

        import sniff4hound.app as app_module

        conn = self._Conn()
        saved = app_module._WSBUILDER_SEND_HTTP_RESPONSE
        app_module._WSBUILDER_SEND_HTTP_RESPONSE = fake_original
        try:
            self.guard(conn, Response.text("ok"), version=app_module._WSBUILDER_HTTP_0_9)
        finally:
            app_module._WSBUILDER_SEND_HTTP_RESPONSE = saved
        self.assertEqual(calls, [{"send_body": True, "version": app_module._WSBUILDER_HTTP_0_9}])
        self.assertEqual(conn.sent, [])


if __name__ == "__main__":
    unittest.main()
