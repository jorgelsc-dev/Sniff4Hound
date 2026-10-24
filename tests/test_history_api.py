"""The DNS and ARP history API: listings, settings and the guarded clear."""

from __future__ import annotations

import importlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

from wsbuilder import Request

from tests.test_network_history import _arp_row, _dns_row, _stamp


class HistoryApiTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        names = ("SNIFF4HOUND_DB_PATH", "SNIFF4HOUND_REQUIRE_AUTH")
        self._previous = {name: os.environ.get(name) for name in names}
        self.addCleanup(self._restore)
        os.environ["SNIFF4HOUND_DB_PATH"] = str(Path(self._tmp.name) / "api.db")
        os.environ["SNIFF4HOUND_REQUIRE_AUTH"] = "0"
        self.app_module = self._reload()
        self.store = self.app_module.store

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

    def _call(self, path, *, method="GET", query="", body=None):
        payload = json.dumps(body).encode("utf-8") if body is not None else b""
        request = Request(method, path, query, {"host": "127.0.0.1:45678", "content-type": "application/json"}, payload, ("127.0.0.1", 40000))
        return self.app_module.app.dispatch(request)

    def _json(self, response):
        return json.loads(bytes(response.body).decode("utf-8"))

    def _headers(self, response):
        return {str(k).lower(): str(v) for k, v in response.headers.items()}

    def _seed(self):
        self.store.write_history(
            [
                _dns_row("example.com", "A", "93.184.216.34", response_count=3, last_rcode="NOERROR", ttl_last=300,
                         last_client="10.0.0.5", clients=["10.0.0.5"], last_resolver="10.0.0.1", resolvers=["10.0.0.1"]),
                _dns_row("example.com", "AAAA", "2606:2800::1", response_count=1, last_rcode="NOERROR"),
                _dns_row("gone.example", "A", "", response_count=2, error_count=2, last_rcode="NXDOMAIN"),
            ],
            [_arp_row("192.168.1.20", "aa:bb:cc:dd:ee:20", packet_count=4), _arp_row("192.168.1.21", "aa:bb:cc:dd:ee:20")],
            [{"kind": "new_device", "ip": "192.168.1.20", "mac": "aa:bb:cc:dd:ee:20", "occurred_at": _stamp(60)},
             {"kind": "mac_new_ip", "ip": "192.168.1.21", "mac": "aa:bb:cc:dd:ee:20", "previous_ip": "192.168.1.20", "occurred_at": _stamp(5)}],
        )

    def test_the_dns_listing_returns_rows_and_the_pagination_headers(self):
        self._seed()
        response = self._call("/api/history/dns/")
        rows = self._json(response)
        self.assertEqual(response.status, 200)
        self.assertEqual(len(rows), 3)
        self.assertEqual(self._headers(response)["x-total-available"], "3")
        first = next(r for r in rows if r["answer"] == "93.184.216.34")
        self.assertEqual(first["clients"], ["10.0.0.5"])
        self.assertNotIn("clients_json", first)

    def test_dns_filters_and_paging(self):
        self._seed()
        names = lambda query: sorted((r["domain"], r["record_type"]) for r in self._json(self._call("/api/history/dns/", query=query)))
        self.assertEqual(names("search=gone"), [("gone.example", "A")])
        self.assertEqual(names("type=AAAA"), [("example.com", "AAAA")])
        self.assertEqual(names("rcode=NXDOMAIN"), [("gone.example", "A")])
        self.assertEqual(names("ip=93.184.216.34"), [("example.com", "A")])
        self.assertEqual(names("domain=example.com"), [("example.com", "A"), ("example.com", "AAAA")])
        page = self._call("/api/history/dns/", query="limit=1&offset=2")
        self.assertEqual(len(self._json(page)), 1)
        self.assertEqual(self._headers(page)["x-total-available"], "3")

    def test_dns_parent_filter_includes_subdomains_on_label_boundaries(self):
        self.store.write_history(
            [
                _dns_row("example.co.uk", query_count=1),
                _dns_row("api.example.co.uk", query_count=2),
                _dns_row("deep.api.example.co.uk", query_count=3),
                _dns_row("notexample.co.uk", query_count=4),
            ],
            [],
            [],
        )
        rows = self._json(self._call("/api/history/dns/", query="parent=example.co.uk"))
        self.assertEqual({row["domain"] for row in rows}, {"example.co.uk", "api.example.co.uk", "deep.api.example.co.uk"})
        deep = next(row for row in rows if row["domain"] == "deep.api.example.co.uk")
        self.assertEqual((deep["base_domain"], deep["subdomain"], deep["is_subdomain"]), ("example.co.uk", "deep.api", True))

    def test_a_bad_limit_is_a_400_not_a_silent_default(self):
        self.assertEqual(self._call("/api/history/dns/", query="limit=lots").status, 400)

    def test_arp_bindings_devices_and_events(self):
        self._seed()
        bindings = self._json(self._call("/api/history/arp/"))
        self.assertEqual(len(bindings), 2)
        self.assertEqual(bindings[0]["mac_address_kind"], "local")
        self.assertEqual(bindings[0]["mac_vendor"], "")
        self.assertEqual(len(self._json(self._call("/api/history/arp/", query="ip=192.168.1.21"))), 1)
        devices = self._json(self._call("/api/history/arp/devices/"))
        self.assertEqual(len(devices), 1)
        self.assertEqual(sorted(devices[0]["ips"]), ["192.168.1.20", "192.168.1.21"])
        self.assertEqual(devices[0]["mac_address_kind"], "local")
        events = self._json(self._call("/api/history/arp/events/"))
        self.assertEqual([e["kind"] for e in events], ["mac_new_ip", "new_device"])
        self.assertTrue(all("mac_vendor_registry" in event for event in events))
        only = self._json(self._call("/api/history/arp/events/", query="kind=new_device"))
        self.assertEqual([e["kind"] for e in only], ["new_device"])

    def test_arp_search_includes_the_derived_ieee_manufacturer(self):
        self.store.write_history([], [_arp_row("192.168.1.50", "f0:ee:7a:12:34:56")], [])
        bindings = self._json(self._call("/api/history/arp/", query="search=apple"))
        devices = self._json(self._call("/api/history/arp/devices/", query="search=apple"))
        self.assertEqual([row["mac"] for row in bindings], ["f0:ee:7a:12:34:56"])
        self.assertEqual([row["mac"] for row in devices], ["f0:ee:7a:12:34:56"])
        self.assertEqual(bindings[0]["mac_vendor"], "Apple, Inc.")
        self.assertEqual(bindings[0]["mac_vendor_registry"], "MA-L")

    def test_the_config_comes_with_the_row_counts(self):
        self._seed()
        payload = self._json(self._call("/api/history/config"))
        self.assertEqual(payload["config"]["retention_days"], 90)
        self.assertTrue(payload["config"]["dns_enabled"])
        self.assertEqual(payload["totals"]["dns_history"], 3)
        self.assertEqual(payload["totals"]["arp_devices"], 1)

    def test_the_config_can_be_changed_and_a_bad_value_changes_nothing(self):
        saved = self._json(self._call("/api/history/config", method="POST", body={"retention_days": 30, "arp_enabled": False}))
        self.assertEqual((saved["config"]["retention_days"], saved["config"]["arp_enabled"]), (30, False))
        self.assertEqual(self.store.get_history_config()["retention_days"], 30)
        bad = self._call("/api/history/config", method="POST", body={"retention_days": 99999})
        self.assertEqual(bad.status, 400)
        self.assertEqual(self.store.get_history_config()["retention_days"], 30)
        self.assertEqual(self._call("/api/history/config", method="POST", body={"nonsense": 1}).status, 400)

    def test_clearing_asks_for_confirmation_first(self):
        self._seed()
        preview = self._json(self._call("/api/history/clear", method="POST", body={"scope": "dns"}))
        self.assertEqual(preview, {"status": "confirm_required", "scope": "dns", "rows": 3})
        self.assertEqual(self.store.count_dns_history(), 3, "nothing was deleted")
        self.assertEqual(self._json(self._call("/api/history/clear", method="POST", body={"scope": "all"}))["rows"], 3 + 2 + 2)

    def test_clearing_by_scope(self):
        self._seed()
        done = self._json(self._call("/api/history/clear", method="POST", body={"scope": "arp", "confirm": True}))
        self.assertEqual(done["status"], "ok")
        self.assertEqual(done["deleted"], {"arp_bindings": 2, "arp_events": 2})
        self.assertEqual(self.store.count_dns_history(), 3)
        self._call("/api/history/clear", method="POST", body={"confirm": True})
        self.assertEqual(self.store.history_totals()["dns_history"], 0)

    def test_an_unknown_scope_is_a_400(self):
        self.assertEqual(self._call("/api/history/clear", method="POST", body={"scope": "tcp", "confirm": True}).status, 400)

    def test_every_history_route_needs_the_security_code(self):
        os.environ["SNIFF4HOUND_REQUIRE_AUTH"] = "1"
        self.app_module = self._reload()
        for method, path in (("GET", "/api/history/dns/"), ("GET", "/api/history/arp/"), ("GET", "/api/history/arp/devices/"),
                             ("GET", "/api/history/arp/events/"), ("GET", "/api/history/config"), ("POST", "/api/history/config"),
                             ("POST", "/api/history/clear")):
            response = self._call(path, method=method, body={} if method == "POST" else None)
            self.assertEqual(response.status, 401, f"{method} {path} answered without credentials")

    def test_every_new_route_is_documented(self):
        documented = {(row["method"], row["path"]) for row in self.app_module.ENDPOINTS}
        for expected in (("GET", "/api/history/dns/"), ("GET", "/api/history/arp/"), ("GET", "/api/history/arp/devices/"),
                         ("GET", "/api/history/arp/events/"), ("GET", "/api/history/config"), ("POST", "/api/history/config"),
                         ("POST", "/api/history/clear")):
            self.assertIn(expected, documented)


if __name__ == "__main__":
    unittest.main()
