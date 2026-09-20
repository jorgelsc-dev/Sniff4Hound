import os
import ssl
import tempfile
import unittest
from importlib import reload
from pathlib import Path


class RuntimeTlsTests(unittest.TestCase):
    def test_runtime_tls_generates_ca_and_server_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            previous = os.environ.get("SNIFF4HOUND_DATA_DIR")
            os.environ["SNIFF4HOUND_DATA_DIR"] = tmp
            try:
                import sniff4hound.settings as settings
                import sniff4hound.tls as runtime_tls

                reload(settings)
                runtime_tls = reload(runtime_tls)
                material = runtime_tls.ensure_runtime_tls("127.0.0.1")
                self.assertTrue(material.ca_cert.exists())
                self.assertIn("BEGIN CERTIFICATE", runtime_tls.public_ca_pem())
                self.assertIsInstance(material.ssl_context, ssl.SSLContext)
                self.assertTrue(material.server_cert.exists())
                self.assertTrue(material.server_key.exists())
                self.assertEqual(Path(tmp) / "tls", runtime_tls.TLS_DIR)
            finally:
                if previous is None:
                    os.environ.pop("SNIFF4HOUND_DATA_DIR", None)
                else:
                    os.environ["SNIFF4HOUND_DATA_DIR"] = previous
                reload(settings)
                reload(runtime_tls)


if __name__ == "__main__":
    unittest.main()
