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
class PersistentMobileCaTests(unittest.TestCase):
    """The mobile stream's CA is what a phone installs, so it has to outlive the
    stream being stopped and started - and stay apart from the runtime's CA."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self._previous = {name: os.environ.get(name) for name in ("SNIFF4HOUND_DATA_DIR", "SNIFF4HOUND_MOBILE_HOST")}
        os.environ["SNIFF4HOUND_DATA_DIR"] = self._tmp.name
        os.environ.pop("SNIFF4HOUND_MOBILE_HOST", None)
        self.addCleanup(self._restore)
        self.tls = self._reload()

    def _reload(self):
        import sniff4hound.settings as settings
        import sniff4hound.tls as tls

        reload(settings)
        return reload(tls)

    def _restore(self):
        for name, value in self._previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        self._reload()

    def _names(self, certificate):
        return subprocess.run(
            ["openssl", "x509", "-in", str(certificate), "-noout", "-ext", "subjectAltName"], capture_output=True, text=True
        ).stdout

    def test_the_ca_a_phone_installed_is_the_one_after_a_restart(self):
        first = self.tls.ensure_mobile_tls("192.0.2.10")
        installed = first.ca_cert.read_bytes()
        second = self.tls.ensure_mobile_tls("192.0.2.10")
        self.assertEqual(second.ca_cert.read_bytes(), installed)
        self.assertEqual(self.tls.public_mobile_ca_pem().encode(), installed)

    def test_the_certificate_is_new_each_time_and_still_signed_by_that_ca(self):
        first = self.tls.ensure_mobile_tls("192.0.2.10")
        before = first.server_cert.read_bytes()
        second = self.tls.ensure_mobile_tls("192.0.2.10")
        self.assertNotEqual(second.server_cert.read_bytes(), before)
        verify = subprocess.run(["openssl", "verify", "-CAfile", str(second.ca_cert), str(second.server_cert)], capture_output=True, text=True)
        self.assertEqual(verify.returncode, 0, verify.stdout + verify.stderr)

    def test_it_answers_to_the_address_and_to_sniff4hound_local(self):
        names = self._names(self.tls.ensure_mobile_tls("192.0.2.10").server_cert)
        self.assertIn("IP Address:192.0.2.10", names)
        self.assertIn("DNS:sniff4hound.local", names)

    def test_the_name_can_be_changed_and_a_bad_one_is_ignored(self):
        os.environ["SNIFF4HOUND_MOBILE_HOST"] = "stream.lan"
        names = self._names(self._reload().ensure_mobile_tls("192.0.2.10").server_cert)
        self.assertIn("DNS:stream.lan", names)
        self.assertNotIn("sniff4hound.local", names)

        # a value that would add lines to the OpenSSL extension file
        os.environ["SNIFF4HOUND_MOBILE_HOST"] = "evil.local\nbasicConstraints=CA:TRUE"
        names = self._names(self._reload().ensure_mobile_tls("192.0.2.10").server_cert)
        self.assertNotIn("evil", names)
        self.assertNotIn("CA:TRUE", names)

    def test_names_are_checked_before_they_go_into_a_request(self):
        for good in ("sniff4hound.local", "a.b-c.example", "h4ck"):
            self.assertTrue(self.tls._valid_dns_name(good), good)
        for bad in ("", "-bad.local", "a..b", "x y", "a=b", "x\ny", "ü.local", "a" * 64 + ".local"):
            self.assertFalse(self.tls._valid_dns_name(bad), repr(bad))

    def test_the_mobile_ca_is_not_the_runtime_ca(self):
        mobile = self.tls.ensure_mobile_tls("192.0.2.10")
        runtime = self.tls.ensure_runtime_tls("127.0.0.1")
        self.assertNotEqual(mobile.ca_cert.read_bytes(), runtime.ca_cert.read_bytes())
        subject = subprocess.run(["openssl", "x509", "-in", str(mobile.ca_cert), "-noout", "-subject"], capture_output=True, text=True).stdout
        self.assertIn("Mobile Stream CA", subject)

    def test_the_keys_are_owner_only(self):
        self.tls.ensure_mobile_tls("192.0.2.10")
        for key in (self.tls.MOBILE_CA_KEY_FILE, self.tls.MOBILE_SERVER_KEY_FILE):
            self.assertEqual(os.stat(key).st_mode & 0o777, 0o600, key.name)

    def test_an_unwritable_tls_directory_falls_back_to_material_that_is_not_kept(self):
        unusable = Path(self._tmp.name) / "file-not-a-directory"
        unusable.write_text("x")
        with patch.object(self.tls, "TLS_DIR", unusable / "tls"):
            material = self.tls.ensure_mobile_tls("192.0.2.10")
        self.addCleanup(shutil.rmtree, material.ca_cert.parent, True)
        self.assertTrue(material.ca_cert.is_file())
        self.assertNotEqual(material.ca_cert.parent, unusable / "tls")
        self.assertIsNotNone(material.ssl_context)

    def test_the_fingerprint_is_what_openssl_reports(self):
        material = self.tls.ensure_mobile_tls("192.0.2.10")
        expected = subprocess.run(
            ["openssl", "x509", "-in", str(material.ca_cert), "-noout", "-fingerprint", "-sha256"], capture_output=True, text=True
        ).stdout.strip().split("=", 1)[1]
        self.assertEqual(self.tls.ca_fingerprint_sha256(self.tls.public_mobile_ca_pem()), expected)

    def test_a_fingerprint_needs_a_certificate(self):
        for junk in ("", "not a certificate", None):
            self.assertEqual(self.tls.ca_fingerprint_sha256(junk), "")


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
