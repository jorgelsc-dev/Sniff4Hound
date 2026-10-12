from __future__ import annotations

import os
import socket
import ssl
import tempfile
import unittest
import uuid
from importlib import reload
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from urllib.parse import urlsplit

from sniff4hound import mdns, settings


class MdnsPublicationTests(unittest.TestCase):
    def test_names_are_stable_distinct_and_reject_rule_or_certificate_injection(self):
        self.assertEqual(mdns.default_hostname(), mdns.default_hostname())
        self.assertNotEqual(mdns.default_hostname(), mdns.default_hostname("runtime"))
        self.assertEqual(mdns.normalize_hostname("Runtime.LOCAL."), "runtime.local")
        for invalid in ("runtime.example", "bad_name.local", "x.local, MAP * attacker", "bad.local\nDNS.2=evil"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                mdns.normalize_hostname(invalid)

    def test_runtime_is_advertised_only_on_its_bound_interface_without_credentials(self):
        server = MagicMock()
        service = SimpleNamespace(name="fixture._sniff4hound._tcp.local.", service_type=mdns.SERVICE_TYPE,
                                  hostname="fixture.local.", port=12345, addresses=("127.0.0.1",))
        server.register_service.return_value = service
        with patch.object(settings, "MDNS_ENABLED", True), patch.object(settings, "MDNS_HOST", "fixture.local"), \
                patch("wsbuilder.LocalMDNSServer", return_value=server) as factory:
            published = mdns.publish("runtime", "127.0.0.1", 12345, http3=True)
        try:
            factory.assert_called_once_with(interfaces=["127.0.0.1"], ip_version="v4")
            props = server.register_service.call_args.kwargs["properties"]
            self.assertEqual(props, {"role": "runtime", "scheme": "https", "path": "/", "http3": "1"})
            self.assertEqual(published.metadata()["hostname"], "fixture.local")
        finally:
            published.close()
        published.close()
        server.close.assert_called_once()

    def test_disabled_discovery_opens_no_sockets(self):
        with patch.object(settings, "MDNS_ENABLED", False), patch("wsbuilder.LocalMDNSServer") as factory:
            self.assertIsNone(mdns.publish("runtime", "127.0.0.1", 12345))
            factory.assert_not_called()

    def test_a_failed_publication_closes_its_backend(self):
        server = MagicMock()
        server.register_service.side_effect = OSError("multicast unavailable")
        with patch.object(settings, "MDNS_ENABLED", True), patch("wsbuilder.LocalMDNSServer", return_value=server):
            with self.assertRaises(OSError):
                mdns.publish("runtime", "127.0.0.1", 12345)
        server.close.assert_called_once()

    def test_wildcard_binding_publishes_only_concrete_addresses(self):
        interfaces = [SimpleNamespace(address="127.0.0.1", loopback=True),
                      SimpleNamespace(address="192.0.2.10", loopback=False)]
        with patch("sniff4hound.mobile_stream.discover_interfaces", return_value=interfaces):
            self.assertEqual(mdns.bind_addresses("0.0.0.0"), ("192.0.2.10",))


class MdnsLoopbackIntegrationTests(unittest.TestCase):
    def test_wsbuilder_resolves_a_real_announcement_on_loopback(self):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        host = f"s4h-test-{uuid.uuid4().hex[:12]}.local"
        with patch.object(settings, "MDNS_ENABLED", True), patch.object(settings, "MDNS_HOST", host):
            published = mdns.publish("runtime", "127.0.0.1", port, http3=True)
        try:
            found = mdns.resolve(published.service.name, "127.0.0.1")
            self.assertEqual(found["hostname"], host)
            self.assertEqual(found["port"], port)
            self.assertEqual(found["addresses"], ["127.0.0.1"])
            self.assertEqual(found["role"], "runtime")
            self.assertEqual(found["scheme"], "https")
        finally:
            published.close()

    def test_a_mobile_pairing_name_resolves_and_passes_tls_hostname_verification(self):
        from sniff4hound import tls
        from sniff4hound.mobile_stream import MobileStreamService

        host = f"s4h-mobile-{uuid.uuid4().hex[:12]}.local"
        # Restore imported settings even if a network assertion fails.
        self.addCleanup(lambda: reload(tls))
        self.addCleanup(lambda: reload(settings))
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(os.environ, {"SNIFF4HOUND_DATA_DIR": directory, "SNIFF4HOUND_MOBILE_HOST": host, "SNIFF4HOUND_MDNS": "1"}):
                reload(settings)
                reload(tls)
                service = MobileStreamService()
                try:
                    with socket.socket() as probe:
                        probe.bind(("127.0.0.1", 0))
                        port = probe.getsockname()[1]
                    state = service._listen("fixture", "127.0.0.1", port)
                    with patch.object(service, "start", return_value=state):
                        pairing = service.create_pairing("fixture", port=port)
                    target = urlsplit(pairing["url"])
                    self.assertEqual(target.hostname, host)
                    found = mdns.resolve(state["mdns"]["service_name"], "127.0.0.1")
                    self.assertEqual(found["role"], "stream")
                    context = ssl.create_default_context(cadata=state["ca_pem"])
                    context.minimum_version = ssl.TLSVersion.TLSv1_2
                    with socket.create_connection((found["addresses"][0], found["port"]), timeout=3) as connection:
                        with context.wrap_socket(connection, server_hostname=host) as secure:
                            secure.sendall(f"GET {target.path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n".encode())
                            self.assertTrue(secure.recv(4096).startswith(b"HTTP/1.1 200"))
                finally:
                    service.stop()


if __name__ == "__main__":
    unittest.main()
