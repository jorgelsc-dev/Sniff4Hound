"""Every API route the app documents is actually served.

The exclusions and pipeline-settings handlers were deleted by accident together
with the AI feature (#167), while the endpoint list, the store, the sniffer and
the Settings panels that call them all stayed - so those panels answered 404
for days and nothing failed. This is the check that would have said so.
"""

from __future__ import annotations

import importlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from wsbuilder import Request


class DocumentedRouteTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        names = ("SNIFF4HOUND_DB_PATH", "SNIFF4HOUND_REQUIRE_AUTH")
        self._previous = {name: os.environ.get(name) for name in names}
        self.addCleanup(self._restore)
        os.environ["SNIFF4HOUND_DB_PATH"] = str(Path(self._tmp.name) / "routes.db")
        os.environ["SNIFF4HOUND_REQUIRE_AUTH"] = "0"
        self.app_module = self._reload()

    @staticmethod
    def _reload():
        import sniff4hound.app as app_module
        import sniff4hound.auth as auth_module
        import sniff4hound.settings as settings_module

        try:
            sys.modules["sniff4hound.app"].store.close()
        except Exception:
            pass
        importlib.reload(settings_module)
        importlib.reload(auth_module)
        return importlib.reload(app_module)

    def _restore(self):
        try:
            self.app_module.store.close()
        except Exception:
            pass
        for name, value in self._previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        self._reload()

    def _call(self, path, *, method="GET", body=None):
        payload = json.dumps(body).encode("utf-8") if body is not None else b""
        request = Request(method, path, "", {"host": "127.0.0.1:45678", "content-type": "application/json"}, payload, ("127.0.0.1", 40000))
        return self.app_module.app.dispatch(request)

    def _json(self, response):
        return json.loads(bytes(response.body).decode("utf-8"))

    def test_every_documented_endpoint_has_a_handler(self):
        router = self.app_module.app.router
        unrouted = []
        for row in self.app_module.ENDPOINTS:
            path = str(row["path"])
            if not path.startswith("/"):
                continue
            if row["method"].upper() not in {m.upper() for m in (router.allowed_methods(path) or ())}:
                unrouted.append((row["method"], path))
        self.assertEqual(unrouted, [], "documented in ENDPOINTS but nothing answers them")

    def test_the_exclusion_filter_can_be_read_and_saved(self):
        empty = self._json(self._call("/api/detection/exclusions"))
        self.assertEqual(empty, {"exclusion_filters": {"ip_types": [], "cidrs": [], "protocols": [], "ports": []}})
        saved = self._call("/api/detection/exclusions", method="POST", body={
            "exclusion_filters": {"ip_types": ["loopback"], "cidrs": ["10.0.0.0/8"], "protocols": ["DNS"], "ports": [53, "123"]}})
        self.assertEqual(saved.status, 200)
        stored = self._json(saved)["exclusion_filters"]
        self.assertEqual((stored["ip_types"], stored["cidrs"], stored["protocols"], stored["ports"]), (["loopback"], ["10.0.0.0/8"], ["dns"], [53, 123]))
        self.assertEqual(self._json(self._call("/api/detection/exclusions"))["exclusion_filters"], stored, "it persisted")

    def test_a_bad_exclusion_is_a_400_and_changes_nothing(self):
        for bad in ({"ip_types": ["martian"]}, {"cidrs": ["not-a-network"]}, {"ports": [70000]}, {"protocols": "dns"}):
            response = self._call("/api/detection/exclusions", method="POST", body={"exclusion_filters": bad})
            self.assertEqual(response.status, 400, bad)
        self.assertEqual(self._json(self._call("/api/detection/exclusions"))["exclusion_filters"]["ip_types"], [])

    def test_the_pipeline_settings_can_be_read_and_saved(self):
        config = self._json(self._call("/api/pipeline/config"))
        self.assertEqual(set(config), {"cache_limit", "jobs", "persist_mode"})
        saved = self._json(self._call("/api/pipeline/config", method="POST", body={"cache_limit": 5000, "jobs": 3, "persist_mode": "all"}))
        self.assertEqual((saved["cache_limit"], saved["jobs"], saved["persist_mode"]), (5000, 3, "all"))
        self.assertEqual(self._json(self._call("/api/pipeline/config"))["jobs"], 3)

    def test_a_bad_pipeline_setting_is_a_400(self):
        self.assertEqual(self._call("/api/pipeline/config", method="POST", body={"persist_mode": "sometimes"}).status, 400)
        self.assertEqual(self._call("/api/pipeline/config", method="POST", body={"jobs": 9999}).status, 400)

    def test_resetting_the_counters_goes_to_the_capture_side(self):
        fake = MagicMock()
        fake.reset_packet_pipeline.return_value = {"accepted": 0, "dropped": 0}
        with patch.object(self.app_module, "runtime", fake):
            response = self._call("/api/pipeline/reset", method="POST", body={})
        self.assertEqual(response.status, 200)
        fake.reset_packet_pipeline.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
