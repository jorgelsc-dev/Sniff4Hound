"""The runtime's CA and server key outlive the process; the certificate does not.

That is what lets a client trust the runtime once: the desktop shell pins the
server's public key before it starts Chromium, and a remote sensor keeps the CA
it was given. These tests use the real OpenSSL, in a temporary data directory.
"""

import base64
import hashlib
import io
import json
import os
import shutil
import socket
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from importlib import reload
from pathlib import Path
from unittest.mock import patch


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL is required")
class PersistentRuntimeCaTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self._previous = os.environ.get("SNIFF4HOUND_DATA_DIR")
        os.environ["SNIFF4HOUND_DATA_DIR"] = self._tmp.name
        self.addCleanup(self._restore)
        import sniff4hound.settings as settings
        import sniff4hound.tls as tls

        reload(settings)
        self.tls = reload(tls)

    def _restore(self):
        import sniff4hound.settings as settings
        import sniff4hound.tls as tls

        if self._previous is None:
            os.environ.pop("SNIFF4HOUND_DATA_DIR", None)
        else:
            os.environ["SNIFF4HOUND_DATA_DIR"] = self._previous
        reload(settings)
        reload(tls)

    def _pin_by_openssl(self, key: Path) -> str:
        """The documented way to compute an SPKI pin, with plain OpenSSL tools."""
        public = subprocess.run(["openssl", "pkey", "-in", str(key), "-pubout", "-outform", "der"], capture_output=True, check=True).stdout
        return base64.b64encode(hashlib.sha256(public).digest()).decode()

    def test_the_ca_is_created_once_and_then_kept(self):
        first, created_first = self.tls.ensure_runtime_ca()
        body = first.read_bytes()
        second, created_second = self.tls.ensure_runtime_ca()
        self.assertTrue(created_first)
        self.assertFalse(created_second)
        self.assertEqual(second.read_bytes(), body)

    def test_the_server_certificate_is_new_each_launch_but_signed_by_the_same_ca(self):
        one = self.tls.ensure_runtime_tls("127.0.0.1")
        cert_one, ca_one = one.server_cert.read_bytes(), one.ca_cert.read_bytes()
        two = self.tls.ensure_runtime_tls("127.0.0.1")
        self.assertNotEqual(two.server_cert.read_bytes(), cert_one, "the certificate is renewed per launch")
        self.assertEqual(two.ca_cert.read_bytes(), ca_one, "the CA is not")
        verify = subprocess.run(
            ["openssl", "verify", "-CAfile", str(two.ca_cert), str(two.server_cert)], capture_output=True, text=True
        )
        self.assertEqual(verify.returncode, 0, verify.stderr + verify.stdout)

    def test_the_server_key_and_so_its_pin_survive_the_restart(self):
        self.tls.ensure_runtime_tls("127.0.0.1")
        pin = self.tls.server_key_pin()
        self.tls.ensure_runtime_tls("127.0.0.1")
        self.assertEqual(self.tls.server_key_pin(), pin)

    def test_the_pin_is_the_sha256_of_the_public_key_in_base64(self):
        self.tls.ensure_runtime_tls("127.0.0.1")
        self.assertEqual(self.tls.server_key_pin(), self._pin_by_openssl(self.tls.SERVER_KEY_FILE))
        self.assertRegex(self.tls.server_key_pin(), r"^[A-Za-z0-9+/]{43}=$")

    def test_the_certificate_names_loopback_and_localhost(self):
        material = self.tls.ensure_runtime_tls("127.0.0.1")
        text = subprocess.run(
            ["openssl", "x509", "-in", str(material.server_cert), "-noout", "-ext", "subjectAltName"], capture_output=True, text=True
        ).stdout
        self.assertIn("IP Address:127.0.0.1", text)
        self.assertIn("DNS:localhost", text)

    def test_private_keys_are_owner_only_in_a_private_directory(self):
        self.tls.ensure_runtime_tls("127.0.0.1")
        for key in (self.tls.CA_KEY_FILE, self.tls.SERVER_KEY_FILE):
            self.assertEqual(os.stat(key).st_mode & 0o777, 0o600, key.name)
        self.assertEqual(os.stat(self.tls.TLS_DIR).st_mode & 0o777, 0o700)

    def test_a_missing_ca_key_replaces_the_ca_and_the_server_key_with_it(self):
        self.tls.ensure_runtime_tls("127.0.0.1")
        old_ca, old_pin = self.tls.CA_CERT_FILE.read_bytes(), self.tls.server_key_pin()
        self.tls.CA_KEY_FILE.unlink()
        self.tls.ensure_runtime_tls("127.0.0.1")
        self.assertNotEqual(self.tls.CA_CERT_FILE.read_bytes(), old_ca)
        self.assertNotEqual(self.tls.server_key_pin(), old_pin, "everything rotates together")

    def test_a_key_that_does_not_belong_to_the_ca_certificate_is_not_trusted(self):
        self.tls.ensure_runtime_ca()
        other = Path(self._tmp.name) / "other.key"
        self.tls._generate_ec_key(other)
        shutil.copyfile(other, self.tls.CA_KEY_FILE)
        self.assertFalse(self.tls._ca_is_reusable())
        _, created = self.tls.ensure_runtime_ca()
        self.assertTrue(created)

    def test_a_ca_close_to_expiry_is_renewed(self):
        self.tls.ensure_runtime_ca()
        with patch.object(self.tls, "CA_RENEW_BEFORE_DAYS", 100000):
            self.assertFalse(self.tls._ca_is_reusable())

    def test_an_old_rsa_server_key_is_replaced_by_an_ec_key(self):
        self.tls.ensure_runtime_ca()
        subprocess.run(["openssl", "genrsa", "-out", str(self.tls.SERVER_KEY_FILE), "2048"], check=True, capture_output=True)
        self.assertFalse(self.tls._is_ec_p256_key(self.tls.SERVER_KEY_FILE))
        self.tls.ensure_runtime_tls("127.0.0.1")
        self.assertTrue(self.tls._is_ec_p256_key(self.tls.SERVER_KEY_FILE))

    def test_the_certificate_stays_small_enough_for_one_quic_packet(self):
        # wsbuilder sends the server's whole TLS flight as a single QUIC packet,
        # and Chromium drops a datagram bigger than ~1450 bytes. An RSA-2048
        # certificate already used most of that; the EC one leaves room.
        material = self.tls.ensure_runtime_tls("127.0.0.1")
        der = subprocess.run(["openssl", "x509", "-in", str(material.server_cert), "-outform", "der"], capture_output=True, check=True).stdout
        self.assertLess(len(der), 700)

    def test_the_context_serves_the_certificate(self):
        import ssl

        material = self.tls.ensure_runtime_tls("127.0.0.1")
        self.assertIsInstance(material.ssl_context, ssl.SSLContext)


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL is required")
class DesktopPrepareTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self._previous = os.environ.get("SNIFF4HOUND_DATA_DIR")
        os.environ["SNIFF4HOUND_DATA_DIR"] = self._tmp.name
        self.addCleanup(self._restore)
        import sniff4hound.settings as settings
        import sniff4hound.tls as tls

        reload(settings)
        reload(tls)
        import sniff4hound.desktop_prepare as prepare

        self.prepare = reload(prepare)

    def _restore(self):
        import sniff4hound.settings as settings
        import sniff4hound.tls as tls

        if self._previous is None:
            os.environ.pop("SNIFF4HOUND_DATA_DIR", None)
        else:
            os.environ["SNIFF4HOUND_DATA_DIR"] = self._previous
        reload(settings)
        reload(tls)

    def _hold(self, kind, host="127.0.0.1"):
        sock = socket.socket(socket.AF_INET, kind)
        self.addCleanup(sock.close)
        sock.bind((host, 0))
        if kind == socket.SOCK_STREAM:
            sock.listen(1)
        return sock.getsockname()[1]

    def test_it_reports_a_free_port_and_the_pin_of_the_server_key(self):
        result = self.prepare.prepare("127.0.0.1", 45678)
        from sniff4hound import tls

        self.assertIsInstance(result["port"], int)
        self.assertEqual(result["server_spki_sha256"], tls.server_key_pin())
        self.assertTrue(result["ca_created"])
        self.assertFalse(self.prepare.prepare("127.0.0.1", 45678)["ca_created"], "the CA is only created once")

    def test_a_port_busy_on_tcp_is_skipped(self):
        busy = self._hold(socket.SOCK_STREAM)
        self.assertNotEqual(self.prepare.choose_port("127.0.0.1", busy), busy)

    def test_a_port_busy_on_udp_is_skipped_because_http3_needs_it(self):
        busy = self._hold(socket.SOCK_DGRAM)
        chosen = self.prepare.choose_port("127.0.0.1", busy)
        self.assertIsNotNone(chosen)
        self.assertNotEqual(chosen, busy)

    def test_without_tls_there_is_no_pin(self):
        with patch.object(self.prepare, "TLS_ENABLED", False):
            result = self.prepare.prepare("127.0.0.1", 45678)
        self.assertEqual(result["server_spki_sha256"], "")
        self.assertIsNotNone(result["port"])

    def test_the_command_prints_one_json_line(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            self.assertEqual(self.prepare.main(), 0)
        line = buffer.getvalue().strip()
        self.assertEqual(len(line.splitlines()), 1)
        self.assertEqual(set(json.loads(line)), {"host", "port", "server_spki_sha256", "ca_created"})


class DesktopReadyHttp3Tests(unittest.TestCase):
    def test_the_ready_line_says_whether_http3_is_listening(self):
        from sniff4hound import manage

        for flag in (True, False):
            buffer = io.StringIO()
            with patch.object(manage, "resolve_desktop_code_path", return_value="/nonexistent/code"), \
                 patch("sniff4hound.auth.REQUIRE_AUTH", False), \
                 redirect_stdout(buffer):
                manage._emit_desktop_ready("127.0.0.1", 45678, http3=flag)
            payload = json.loads(buffer.getvalue().split(manage.DESKTOP_READY_PREFIX, 1)[1])
            self.assertIs(payload["http3"], flag)


if __name__ == "__main__":
    unittest.main()
