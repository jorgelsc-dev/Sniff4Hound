"""Address-scope filtering for the IP catalog.

Loopback used to be reported as "private" (ipaddress calls 127.0.0.1
private), so the IPs view could not tell an operator's own machine apart
from the rest of the LAN. These tests pin the three-way split and the
contract the endpoint answers with - a bare array plus an X-Scope-Counts
header, because callers index into that array directly.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest

from sniff4hound.store import SniffStore, normalize_ip_scope_filter


class _EnvGuard:
    """Set env vars for one test and put the environment back afterwards.

    settings.py reads SNIFF4HOUND_* once at import, so a test that leaves one
    behind changes what every later module-reload computes. Leaking
    SNIFF4HOUND_DATA_DIR here made three unrelated tests in test_smoke.py
    fail on a full-suite run while passing in isolation.
    """

    def __init__(self, **values):
        self._values = values
        self._previous = {}

    def __enter__(self):
        for key, value in self._values.items():
            self._previous[key] = os.environ.get(key)
            os.environ[key] = value
        return self

    def __exit__(self, *exc_info):
        for key, previous in self._previous.items():
            if previous is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = previous
        return False


class ScopeFilterParsingTests(unittest.TestCase):
    def test_known_scopes_are_kept_in_order(self):
        self.assertEqual(normalize_ip_scope_filter("local,public"), ("local", "public"))

    def test_unknown_names_are_dropped_rather_than_rejected(self):
        # A stale bookmark asking for a scope that no longer exists should
        # show everything, not fail the request.
        self.assertEqual(normalize_ip_scope_filter("nonsense"), ())

    def test_selecting_every_scope_is_the_same_as_no_filter(self):
        self.assertEqual(
            normalize_ip_scope_filter("local,private,public,multicast,reserved,unknown"), ()
        )

    def test_accepts_a_list_as_well_as_a_string(self):
        self.assertEqual(normalize_ip_scope_filter(["public", "public"]), ("public",))


class ScopeFilterQueryTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        # SniffStore takes the path explicitly, so this test needs no env var
        # at all - setting SNIFF4HOUND_DATA_DIR here would only leak.
        self.store = SniffStore(os.path.join(self._tmp.name, "scope.db"))
        self.addCleanup(self.store.close)
        for src, dst in (
            ("127.0.0.1", "127.0.0.1"),
            ("192.168.1.5", "8.8.8.8"),
            ("1.1.1.1", "192.168.1.5"),
            ("224.0.0.251", "224.0.0.251"),
        ):
            self.store.register_packet(
                {
                    "src_ip": src, "dst_ip": dst, "proto": "udp", "transport": "udp",
                    "interface": "eth0", "length": 100, "src_port": 5353, "dst_port": 5353,
                }
            )

    def _ips(self, scope=""):
        return sorted(row["ip"] for row in self.store.list_ip_catalog(scope=scope, limit=100))

    def test_loopback_is_not_filed_under_private(self):
        self.assertEqual(self._ips("local"), ["127.0.0.1"])
        self.assertEqual(self._ips("private"), ["192.168.1.5"])

    def test_public_and_multicast_are_separate(self):
        self.assertEqual(self._ips("public"), ["1.1.1.1", "8.8.8.8"])
        self.assertEqual(self._ips("multicast"), ["224.0.0.251"])

    def test_scopes_combine(self):
        self.assertEqual(self._ips("local,public"), ["1.1.1.1", "127.0.0.1", "8.8.8.8"])

    def test_count_matches_the_filtered_rows(self):
        for scope in ("local", "private", "public", "multicast", "local,public"):
            self.assertEqual(
                self.store.count_ip_catalog(scope=scope), len(self._ips(scope)), scope
            )

    def test_every_row_carries_its_scope(self):
        for row in self.store.list_ip_catalog(limit=100):
            self.assertIn("scope", row)

    def test_scope_counts_cover_every_observed_address(self):
        counts = self.store.ip_catalog_scope_counts()
        total = sum(bucket["addresses"] for bucket in counts.values())
        self.assertEqual(total, self.store.count_ip_catalog())


class ScopeHeaderContractTests(unittest.TestCase):
    """The endpoint answers with a bare array; the breakdown is a header.

    Regression: attaching it as a dict key raised
    "'Response' object does not support item assignment" and every
    /api/intel/ips/ request answered 500.
    """

    def setUp(self):
        import importlib
        import sys

        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)

        guard = _EnvGuard(
            SNIFF4HOUND_DATA_DIR=self._tmp.name,
            SNIFF4HOUND_DB_PATH=os.path.join(self._tmp.name, "contract.db"),
            SNIFF4HOUND_REQUIRE_AUTH="0",
        )
        guard.__enter__()
        self.addCleanup(guard.__exit__)

        import sniff4hound.app as app_module
        import sniff4hound.settings as settings_module

        # settings computes DATA_DIR/DB_PATH at import, so it has to be
        # reloaded too - reloading only sniff4hound.app would keep writing
        # into the shared suite database and give false isolation.
        previous_app = sys.modules.get("sniff4hound.app")
        if previous_app is not None and getattr(previous_app, "store", None) is not None:
            try:
                previous_app.store.close()
            except Exception:
                pass
        importlib.reload(settings_module)
        self.app_module = importlib.reload(app_module)

        # Leave the module-global store open and pointing at a real database:
        # closing it here would break every later test that touches
        # sniff4hound.app.store without reloading first.
        def _restore():
            try:
                self.app_module.store.close()
            except Exception:
                pass
            importlib.reload(settings_module)
            importlib.reload(app_module)

        self.addCleanup(_restore)

        self.app_module.store.register_packet(
            {
                "src_ip": "1.1.1.1", "dst_ip": "192.168.1.5", "proto": "udp",
                "transport": "udp", "interface": "eth0", "length": 100,
                "src_port": 5353, "dst_port": 5353,
            }
        )

    def test_listing_returns_an_array_with_the_breakdown_in_a_header(self):
        from wsbuilder import Request

        # Through app.dispatch, not the module-global function: the auth pass
        # rebinds route.handler on the router, so calling the module attribute
        # would verify the contract off the path a real request travels.
        request = Request("GET", "/api/intel/ips/", "limit=500", {}, b"", ("127.0.0.1", 0))
        response = self.app_module.app.dispatch(request)

        self.assertEqual(response.status, 200)
        payload = json.loads(response.body if isinstance(response.body, str) else response.body.decode())
        self.assertIsInstance(payload, list, "callers index into this array directly")

        counts = json.loads(response.headers["X-Scope-Counts"])
        self.assertIn("public", counts)
        # A browser can only read a custom header that is explicitly exposed.
        self.assertIn("X-Scope-Counts", response.headers["Access-Control-Expose-Headers"])


if __name__ == "__main__":
    unittest.main()
