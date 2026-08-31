from __future__ import annotations

import json
import re
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import sniff4hound.monitors as monitors_module
from sniff4hound.monitors import (
    DEFAULT_MONITORS,
    describe_match,
    evaluate_packet,
    load_builtin_monitors,
    normalize_monitor,
)
from sniff4hound.settings import PORT as SNIFFER_PORT
from sniff4hound.sniffer import Sniffer
from sniff4hound.store import SniffStore


def _await_monitor_index_ready(sniffer: Sniffer, timeout: float = 15.0) -> None:
    """Sniffer._get_monitor_context() fetches the monitors list (and
    monitors.ensure_monitor_index() builds its content index) in a
    background thread so the capture loop is never blocked by either - fine
    for production, but a test that fires many packets through a real
    Sniffer and asserts on time-throttled broadcast counts needs both
    actually warm first, or every one of those packets pays the much
    slower unindexed full scan and the throttle window (1s, see
    sniffer.STATS_BROADCAST_MIN_INTERVAL_SECONDS) elapses for real partway
    through, producing extra broadcasts that have nothing to do with the
    behavior under test. Re-reads sniffer._monitor_cache on every poll
    (rather than capturing it once) since the background refresh swaps it
    for a new list object when it completes."""
    sniffer._get_monitor_context()  # kicks off the background refresh if one isn't already in flight
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        monitors = sniffer._monitor_cache
        if (
            monitors
            and monitors_module._indexed_monitors_ref is monitors
            and monitors_module._content_automaton is not None
        ):
            return
        time.sleep(0.05)


def _packet(**overrides) -> dict:
    base = {
        "proto": "tcp",
        "ip_version": 4,
        "eth_type": 0x0800,
        "src_ip": "10.0.0.5",
        "dst_ip": "10.0.0.1",
        "src_port": 51234,
        "dst_port": 80,
        "length": 60,
        "payload_len": 20,
        "payload_text": "",
        "payload_hex": "",
        "summary": "",
        "eth_src": "",
        "eth_dst": "",
    }
    base.update(overrides)
    return base


class TestLoadBuiltinMonitors(unittest.TestCase):
    """load_builtin_monitors() prefers sniff4hound/data/default_monitors.json
    (the full bundled catalog) over the smaller hand-written
    DEFAULT_MONITORS list, but silently falls back to DEFAULT_MONITORS on
    *any* exception while reading/normalizing that file - a single bad
    entry would otherwise take the other ~900+ down with it. Pin the
    guarantees that make that safe."""

    def test_loads_at_least_two_thousand_monitors(self):
        monitors = load_builtin_monitors()
        self.assertGreaterEqual(len(monitors), 2000)

    def test_did_not_silently_fall_back_to_the_small_default_list(self):
        # If default_monitors.json failed to parse/normalize, every builtin
        # would come back with source="builtin" but the *count* would match
        # len(DEFAULT_MONITORS) exactly (currently ~90) instead of ~1000 -
        # that's the actual failure mode this guards, not just "is it a
        # round number".
        monitors = load_builtin_monitors()
        self.assertGreater(len(monitors), len(DEFAULT_MONITORS))

    def test_every_builtin_monitor_has_a_unique_id(self):
        monitors = load_builtin_monitors()
        ids = [item["id"] for item in monitors]
        self.assertEqual(len(ids), len(set(ids)))

    def test_builtin_monitor_loads_do_not_share_mutable_rows(self):
        monitors = load_builtin_monitors()
        original_name = monitors[0]["name"]
        monitors[0]["name"] = "Mutated in one caller"
        self.assertEqual(load_builtin_monitors()[0]["name"], original_name)

    def test_every_builtin_monitor_is_already_normalized(self):
        # normalize_monitor() must be idempotent on load_builtin_monitors()'s
        # own output - re-normalizing (as store.py does when seeding/saving)
        # must not raise or change the result.
        for monitor in load_builtin_monitors():
            renormalized = normalize_monitor(dict(monitor), allow_source=True)
            self.assertEqual(renormalized["id"], monitor["id"])
            self.assertIn(monitor["action"]["severity"], {"critical", "high", "medium", "low", "info"})
            self.assertIn(monitor["mode"], {"rule", "regex", "stateful"})

    def test_default_monitors_overrides_the_packaged_catalog_for_shared_ids(self):
        # Regression: an id both DEFAULT_MONITORS and the packaged JSON
        # define used to keep the *file's* version outright - a hand-tuned
        # fix made to DEFAULT_MONITORS for an id the bulk-generated catalog
        # also happens to define was silently discarded, with nothing
        # surfacing the mismatch. DEFAULT_MONITORS must win instead: it's
        # the actively-maintained, hand-curated source.
        by_id = {item["id"]: item for item in load_builtin_monitors()}
        shared_ids = [item["id"] for item in DEFAULT_MONITORS if item["id"] in by_id]
        self.assertTrue(shared_ids, "expected at least one id defined in both sources to exercise the merge")
        for monitor_id in shared_ids:
            expected = normalize_monitor(dict(next(m for m in DEFAULT_MONITORS if m["id"] == monitor_id)), allow_source=True)
            self.assertEqual(by_id[monitor_id]["match"], expected["match"])

    def test_builtin_catalog_has_source_neutral_visible_text(self):
        blocked = re.compile(
            "|".join(
                (
                    r"adapted\s+from",
                    r"\b" + "emer" + "ging" + r"\s+" + "thr" + "eats?" + r"\b",
                    r"\b" + "pro" + "of" + "point" + r"\b",
                    r"\b" + "suri" + "cata" + r"\b",
                    r"\b" + "sno" + "rt" + r"\b",
                    r"\b" + "e" + "t" + r"[\s-]+open\b",
                    r"\b[a-z]{1,3}-open-\d",
                    r"\b" + "e" + "t" + r"\b",
                    r"https?://",
                )
            ),
            re.IGNORECASE,
        )
        bad = []
        for monitor in load_builtin_monitors():
            action = monitor.get("action") if isinstance(monitor.get("action"), dict) else {}
            text = json.dumps(
                {
                    "id": monitor.get("id"),
                    "name": monitor.get("name"),
                    "description": monitor.get("description"),
                    "source": monitor.get("source"),
                    "match": monitor.get("match"),
                    "action_tag": action.get("tag"),
                    "action_label": action.get("label"),
                },
                ensure_ascii=True,
                sort_keys=True,
            )
            if blocked.search(text):
                bad.append(monitor.get("id"))
        self.assertEqual(bad[:10], [])


class TestNormalizeMonitor(unittest.TestCase):
    def test_rejects_empty_match(self):
        with self.assertRaises(ValueError):
            normalize_monitor({"id": "empty", "name": "Empty", "match": {}})

    def test_rejects_invalid_regex(self):
        with self.assertRaises(ValueError):
            normalize_monitor(
                {"id": "bad-regex", "name": "Bad regex", "match": {"payload_regex": ["("]}}
            )

    def test_rejects_regex_with_backtracking_risk(self):
        with self.assertRaises(ValueError):
            normalize_monitor(
                {
                    "id": "redos-risk",
                    "name": "Risky regex",
                    "match": {"payload_regex": [r"(a+)+$"]},
                }
            )

    def test_rejects_blank_string_only_criteria(self):
        for key in ("payload_contains", "payload_prefix_hex", "payload_regex", "protocols"):
            with self.subTest(key=key):
                with self.assertRaises(ValueError):
                    normalize_monitor({"id": f"blank-{key}", "name": "Blank", "match": {key: ["   "]}})

    def test_accepts_rule_mode(self):
        monitor = normalize_monitor(
            {"id": "custom-ports", "name": "Custom ports", "match": {"ports": [4444]}}
        )
        self.assertEqual(monitor["mode"], "rule")
        self.assertEqual(monitor["match"]["ports"], [4444])

    def test_accepts_regex_mode(self):
        monitor = normalize_monitor(
            {"id": "custom-regex", "name": "Custom regex", "match": {"payload_regex": ["token=\\w+"]}}
        )
        self.assertEqual(monitor["mode"], "regex")

    def test_builtin_monitors_normalize_cleanly(self):
        for raw in DEFAULT_MONITORS:
            normalized = normalize_monitor(raw, allow_source=True)
            self.assertEqual(normalized["source"], "builtin")

    def test_noisy_generated_signal_monitors_are_pruned(self):
        from sniff4hound.monitors import load_builtin_monitors

        monitor_ids = {item["id"] for item in load_builtin_monitors()}
        self.assertNotIn("builtin-signal-attempted-admin-158cffea283a", monitor_ids)
        self.assertNotIn("builtin-signal-attempted-dos-da42390b909c", monitor_ids)
        self.assertNotIn("builtin-signal-trojan-activity-d9ef2a92901f", monitor_ids)
        self.assertNotIn("builtin-signal-command-and-control-d218fa2d0688", monitor_ids)
        self.assertIn("builtin-signal-network-scan-3fbcc245b8ce", monitor_ids)

    def test_stateful_mode_is_preserved(self):
        # Regression test: normalize_monitor used to only whitelist
        # {"rule", "regex"} and would silently coerce any other mode value to
        # "rule" — which would have destroyed "stateful" on every load,
        # breaking evaluate_packet()'s ability to skip these monitors so
        # anomaly.AnomalyEngine can drive them instead.
        stateful_ids = {
            raw["id"] for raw in DEFAULT_MONITORS if raw.get("mode") == "stateful"
        }
        self.assertTrue(stateful_ids, "expected at least one stateful builtin monitor")
        for raw in DEFAULT_MONITORS:
            if raw["id"] in stateful_ids:
                normalized = normalize_monitor(raw, allow_source=True)
                self.assertEqual(normalized["mode"], "stateful")


class TestEvaluatePacket(unittest.TestCase):
    def setUp(self):
        self.monitors = [normalize_monitor(item, allow_source=True) for item in DEFAULT_MONITORS]

    def test_credentials_regex_matches(self):
        packet = _packet(payload_text="POST /login HTTP/1.1\r\nusername=admin&password=hunter2")
        hits = evaluate_packet(packet, self.monitors)
        tags = {hit["tag"] for hit in hits}
        self.assertIn("credentials", tags)

    def test_admin_port_matches(self):
        packet = _packet(proto="tcp", dst_port=3389, src_port=51000)
        hits = evaluate_packet(packet, self.monitors)
        tags = {hit["tag"] for hit in hits}
        self.assertIn("admin-port", tags)

    def test_arp_l2_discovery_matches(self):
        packet = _packet(proto="arp", eth_type=0x0806, ip_version=0, src_port=0, dst_port=0)
        hits = evaluate_packet(packet, self.monitors)
        tags = {hit["tag"] for hit in hits}
        self.assertIn("discovery", tags)

    def test_plain_traffic_does_not_match(self):
        packet = _packet(dst_port=443, payload_text="", payload_hex="")
        hits = evaluate_packet(packet, self.monitors)
        self.assertEqual(hits, [])

    def test_readable_payload_text_matches_plaintext_monitor(self):
        packet = _packet(payload_text="220 Welcome to the FTP server, please authenticate")
        hits = evaluate_packet(packet, self.monitors)
        tags = {hit["tag"] for hit in hits}
        self.assertIn("plaintext", tags)

    def test_discovery_payload_text_does_not_match_plaintext_monitor(self):
        for proto in ("mdns", "igmp", "ssdp", "ntp"):
            with self.subTest(proto=proto):
                packet = _packet(proto=proto, payload_text="normal multicast discovery payload with readable labels")
                hits = evaluate_packet(packet, self.monitors)
                tags = {hit["tag"] for hit in hits}
                self.assertNotIn("plaintext", tags)

    def test_short_payload_text_does_not_match_plaintext_monitor(self):
        packet = _packet(payload_text="hi")
        hits = evaluate_packet(packet, self.monitors)
        tags = {hit["tag"] for hit in hits}
        self.assertNotIn("plaintext", tags)

    def test_stateful_monitors_are_never_matched_declaratively(self):
        # Stateful monitors have no declarative match logic — evaluate_packet
        # must skip them entirely (they're handled by anomaly.AnomalyEngine),
        # even though their `match` dict happens to overlap with this packet.
        packet = _packet(proto="arp", eth_type=0x0806, ip_version=0, src_port=0, dst_port=0)
        hits = evaluate_packet(packet, self.monitors)
        monitor_ids = {hit["monitor_id"] for hit in hits}
        self.assertNotIn("builtin-arp-spoof", monitor_ids)

    def test_bad_regex_in_saved_monitor_does_not_crash_evaluation(self):
        broken = dict(self.monitors[0])
        broken["match"] = dict(broken["match"])
        # Bypass normalize_monitor's validation to simulate a corrupted row.
        broken["match"]["payload_regex"] = ["("]
        hits = evaluate_packet(_packet(payload_text="anything"), [broken])
        self.assertEqual(hits, [])

    def test_corrupt_blank_criteria_do_not_match_every_packet(self):
        monitor = {
            "id": "corrupt-blank",
            "name": "Corrupt blank",
            "enabled": True,
            "mode": "rule",
            "match": {"payload_contains": ["   "], "payload_regex": ["   "], "payload_prefix_hex": ["   "]},
            "action": {"tag": "corrupt-blank", "label": "Corrupt blank", "severity": "high"},
        }
        self.assertEqual(evaluate_packet(_packet(payload_text="ordinary traffic"), [monitor]), [])

    def test_payload_literals_do_not_match_only_endpoint_addresses(self):
        monitor = normalize_monitor(
            {
                "id": "address-literal",
                "name": "Address literal",
                "match": {"payload_contains": ["10.0.0.5"]},
                "action": {"tag": "address-literal", "label": "Address literal", "severity": "medium"},
            }
        )
        self.assertEqual(evaluate_packet(_packet(src_ip="10.0.0.5", payload_text="ordinary traffic"), [monitor]), [])

    def test_full_builtin_catalog_still_matches_core_monitors(self):
        hits = evaluate_packet(
            _packet(payload_text="POST /login HTTP/1.1\r\nusername=admin&password=hunter2"),
            load_builtin_monitors(),
        )
        self.assertIn("credentials", {hit["tag"] for hit in hits})

    def test_monitor_index_refreshes_when_match_changes_without_timestamp_change(self):
        first = [
            normalize_monitor(
                {
                    "id": "custom-index-refresh",
                    "name": "Old signal",
                    "updated_at": "2026-01-01T00:00:00Z",
                    "match": {"payload_contains": ["old-index-signal"]},
                    "action": {"tag": "old-index-signal", "label": "Old signal", "severity": "medium"},
                }
            )
        ]
        second = [
            normalize_monitor(
                {
                    "id": "custom-index-refresh",
                    "name": "New signal",
                    "updated_at": "2026-01-01T00:00:00Z",
                    "match": {"payload_contains": ["new-index-signal"]},
                    "action": {"tag": "new-index-signal", "label": "New signal", "severity": "medium"},
                }
            )
        ]

        monitors_module.ensure_monitor_index(first)
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline and "old-index-signal" not in monitors_module._content_to_ids:
            time.sleep(0.01)
        self.assertIn("old-index-signal", monitors_module._content_to_ids)

        monitors_module.ensure_monitor_index(second)
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline and "new-index-signal" not in monitors_module._content_to_ids:
            time.sleep(0.01)
        self.assertIn("new-index-signal", monitors_module._content_to_ids)

        self.assertEqual(evaluate_packet(_packet(payload_text="old-index-signal"), second), [])
        hits = evaluate_packet(_packet(payload_text="new-index-signal"), second)
        self.assertEqual({hit["tag"] for hit in hits}, {"new-index-signal"})


class TestDescribeMatch(unittest.TestCase):
    def setUp(self):
        self.monitors = {
            item["id"]: item for item in (normalize_monitor(entry, allow_source=True) for entry in DEFAULT_MONITORS)
        }

    def test_regex_monitor_returns_matched_substring(self):
        monitor = self.monitors["builtin-credentials"]
        packet = _packet(payload_text="POST /login HTTP/1.1\r\nusername=admin&password=hunter2")
        value = describe_match(monitor, packet)
        self.assertIn("password", value.lower())

    def test_rule_monitor_returns_matched_port(self):
        monitor = self.monitors["builtin-admin-ports"]
        packet = _packet(dst_port=3389)
        self.assertEqual(describe_match(monitor, packet), "port 3389")

    def test_domain_takes_priority_when_present(self):
        monitor = self.monitors["builtin-dns-domains"]
        packet = _packet(proto="udp", dst_port=53, domain="example.com", domain_source="dns")
        self.assertEqual(describe_match(monitor, packet), "example.com")

    def test_arp_monitor_returns_eth_type(self):
        monitor = self.monitors["builtin-l2-discovery"]
        packet = _packet(proto="arp", eth_type=0x0806)
        self.assertEqual(describe_match(monitor, packet), "eth 0x0806")


class TestStoreMonitors(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test.db"
        self.store = SniffStore(self.db_path)

    def tearDown(self):
        self.store.close()
        self.temp_dir.cleanup()

    def test_builtin_monitors_are_seeded(self):
        monitors = self.store.list_monitors()
        self.assertGreaterEqual(len(monitors), 2000)
        ids = {row["id"] for row in monitors}
        self.assertIn("builtin-credentials", ids)
        self.assertIn("builtin-arp-spoof", ids)
        self.assertTrue(all(row["source"] == "builtin" for row in monitors))

    def test_builtin_monitor_definitions_sync_on_reopen(self):
        with self.store._lock:
            self.store._conn.execute(
                """
                UPDATE monitors
                SET name = 'Legacy catalog name',
                    description = 'Legacy catalog description',
                    action_json = '{"tag":"legacy-catalog","label":"Legacy catalog","severity":"low"}'
                WHERE id = 'builtin-credentials'
                """
            )
            self.store._conn.commit()

        reopened = SniffStore(self.db_path)
        try:
            updated = {row["id"]: row for row in reopened.list_monitors()}["builtin-credentials"]
        finally:
            reopened.close()

        self.assertEqual(updated["name"], "Cleartext credentials")
        self.assertEqual(updated["action"]["tag"], "credentials")

    def test_builtin_defaults_are_reset_exactly_once_for_a_pre_existing_db(self):
        # Simulates a database seeded before the "critical monitors on by
        # default, the rest opt-in" policy shipped: flip a builtin row's
        # `enabled` away from the current catalog default and clear the
        # migration marker, so this database looks like one that predates
        # _apply_new_monitor_defaults_once. Reopening must force-sync it to
        # the catalog default exactly once - and a toggle made *after*
        # that reset must survive a further reopen untouched, same as any
        # other builtin row.
        catalog_default = {row["id"]: row["enabled"] for row in self.store.list_monitors()}
        flipped_id = next(mid for mid, enabled in catalog_default.items() if enabled)
        with self.store._lock:
            self.store._conn.execute(
                "UPDATE monitors SET enabled = 0 WHERE id = ?", (flipped_id,)
            )
            self.store._conn.execute(
                "DELETE FROM runtime_config WHERE key = 'builtin_monitor_defaults_reset_v2'"
            )
            self.store._conn.commit()

        reopened = SniffStore(self.db_path)
        try:
            synced = {row["id"]: row["enabled"] for row in reopened.list_monitors()}
        finally:
            reopened.close()
        self.assertTrue(synced[flipped_id], "expected the one-shot migration to restore the catalog default")

        # A manual toggle made after the reset must stick across a further reopen.
        third = SniffStore(self.db_path)
        try:
            third.set_monitor_enabled(flipped_id, False)
        finally:
            third.close()
        fourth = SniffStore(self.db_path)
        try:
            final = {row["id"]: row["enabled"] for row in fourth.list_monitors()}
        finally:
            fourth.close()
        self.assertFalse(final[flipped_id], "a toggle made after the one-shot reset must not be reverted again")

    def test_new_builtin_monitors_reach_an_already_populated_db_without_touching_custom_rows(self):
        # Regression test for _seed_new_builtin_monitors(): simulate an
        # "old" DB that predates the new builtins (and already has a
        # user's own custom monitor), then reopen the store and confirm
        # the new builtins get added by id and nothing existing is touched.
        self.store.save_monitor(
            {"id": "custom-1", "name": "My custom monitor", "match": {"ports": [9999]}}
        )
        new_ids = [row["id"] for row in DEFAULT_MONITORS if row.get("mode") == "stateful"]
        self.assertTrue(new_ids)
        with self.store._lock:
            for monitor_id in new_ids:
                self.store._conn.execute("DELETE FROM monitors WHERE id = ?", (monitor_id,))
            self.store._conn.commit()
        remaining_ids = {row["id"] for row in self.store.list_monitors()}
        self.assertFalse(remaining_ids.intersection(new_ids))
        self.assertIn("custom-1", remaining_ids)

        reopened = SniffStore(self.db_path)
        try:
            ids_after = {row["id"] for row in reopened.list_monitors()}
        finally:
            reopened.close()
        self.assertTrue(set(new_ids).issubset(ids_after))
        self.assertIn("custom-1", ids_after)

    def test_stale_builtin_monitors_are_pruned_without_touching_custom_rows(self):
        # Regression test: the bundled catalog can change between
        # releases (a pattern that turned out to be a
        # false-positive magnet gets filtered out by a later, stricter
        # heuristic), and a plain additive migration would leave a builtin
        # id seeded by an earlier run sitting in the table forever, still
        # matching live traffic, even though the current catalog no longer
        # includes it. _seed_new_builtin_monitors() must remove it - but
        # must never remove a user's own custom monitor, even one that
        # happens to share the "looks stale" shape (source='builtin' rows
        # not in the current catalog are the only thing in scope).
        self.store.save_monitor(
            {"id": "custom-1", "name": "My custom monitor", "match": {"ports": [9999]}}
        )
        stale_id = "sig-legacy-0000000-not-in-current-catalog"
        with self.store._lock:
            self.store._conn.execute(
                """
                INSERT INTO monitors
                (id, name, description, enabled, priority, source, mode, match_json, action_json, created_at, updated_at)
                VALUES (?, 'Stale test monitor', '', 1, 500, 'builtin', 'regex', '{"payload_regex": ["^."]}', '{}', '2020-01-01', '2020-01-01')
                """,
                (stale_id,),
            )
            self.store._conn.commit()
        ids_before = {row["id"] for row in self.store.list_monitors()}
        self.assertIn(stale_id, ids_before)

        reopened = SniffStore(self.db_path)
        try:
            ids_after = {row["id"] for row in reopened.list_monitors()}
        finally:
            reopened.close()
        self.assertNotIn(stale_id, ids_after)
        self.assertIn("custom-1", ids_after)
        self.assertIn("builtin-credentials", ids_after)

    def test_save_list_delete_custom_monitor(self):
        saved = self.store.save_monitor(
            {"id": "custom-1", "name": "My monitor", "match": {"ports": [9999]}}
        )
        self.assertEqual(saved["source"], "custom")
        ids = {row["id"] for row in self.store.list_monitors()}
        self.assertIn("custom-1", ids)
        self.store.delete_monitor("custom-1")
        ids = {row["id"] for row in self.store.list_monitors()}
        self.assertNotIn("custom-1", ids)

    def test_builtin_monitor_is_read_only(self):
        with self.assertRaises(ValueError):
            self.store.save_monitor({"id": "builtin-credentials", "name": "Hacked"})
        with self.assertRaises(ValueError):
            self.store.delete_monitor("builtin-credentials")

    def test_builtin_monitor_can_be_toggled_but_not_otherwise_changed(self):
        # set_monitor_enabled is the one exception to "builtins are
        # read-only" - flipping enabled doesn't change what the rule does,
        # only whether it's currently applied.
        updated = self.store.set_monitor_enabled("builtin-credentials", False)
        self.assertFalse(updated["enabled"])
        self.assertEqual(updated["name"], "Cleartext credentials")

        updated = self.store.set_monitor_enabled("builtin-credentials", True)
        self.assertTrue(updated["enabled"])

        # Still can't edit its definition or delete it.
        with self.assertRaises(ValueError):
            self.store.save_monitor({"id": "builtin-credentials", "name": "Hacked"})
        with self.assertRaises(ValueError):
            self.store.delete_monitor("builtin-credentials")

    def test_set_monitor_enabled_rejects_unknown_id(self):
        with self.assertRaises(ValueError):
            self.store.set_monitor_enabled("does-not-exist", False)

    def test_monitor_filter_toggle_defaults_and_persists(self):
        self.assertTrue(self.store.get_monitor_filter_enabled())
        self.store.set_monitor_filter_enabled(False)
        self.assertFalse(self.store.get_monitor_filter_enabled())

    def test_monitor_quality_config_defaults_and_persists(self):
        config = self.store.get_monitor_config()
        self.assertEqual(config["min_severity"], "info")
        self.assertTrue(config["suppress_generated_info"])
        self.assertIn("critical", config["severity_options"])

        self.assertEqual(self.store.set_monitor_min_severity("medium"), "medium")
        self.assertFalse(self.store.set_monitor_suppress_generated_info(False))
        config = self.store.get_monitor_config()
        self.assertEqual(config["min_severity"], "medium")
        self.assertFalse(config["suppress_generated_info"])

    def test_monitor_min_severity_rejects_unknown_values(self):
        with self.assertRaises(ValueError):
            self.store.set_monitor_min_severity("urgent")


class TestSnifferGatedPersistence(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test.db"
        self.store = SniffStore(self.db_path)
        self.sniffer = Sniffer(self.store, MagicMock(), interfaces=())

    def tearDown(self):
        self.store.close()
        self.temp_dir.cleanup()

    def _base_packet(self, **overrides) -> dict:
        packet = {
            "session_id": 0,
            "interface": "test0",
            "eth_src": "",
            "eth_dst": "",
            "eth_type": 0x0800,
            "ip_version": 4,
            "src_ip": "10.0.0.5",
            "dst_ip": "10.0.0.9",
            "proto": "tcp",
            "src_port": 51234,
            "dst_port": 8081,
            "ttl": 64,
            "hop_limit": 0,
            "length": 60,
            "payload_len": 10,
            "state": "open",
            "scan_state": "active",
            "tcp_flags": "",
            "icmp_type": 0,
            "icmp_code": 0,
            "arp_opcode": 0,
            "summary": "",
            "payload_text": "",
            "payload_hex": "",
            "banner_text": "",
            "raw_packet": b"",
        }
        packet.update(overrides)
        return packet

    def test_undetected_packet_is_not_persisted(self):
        self.sniffer._store_packet(self._base_packet())
        self.assertEqual(self.store.list_count("packets"), 0)
        self.assertEqual(self.sniffer.state.packets_seen, 1)
        self.assertEqual(self.sniffer.state.packets_stored, 0)

    def test_detected_packet_is_persisted(self):
        self.sniffer._store_packet(self._base_packet(dst_port=3389))
        self.assertEqual(self.store.list_count("packets"), 1)
        self.assertEqual(self.sniffer.state.packets_stored, 1)

    def test_own_dashboard_traffic_is_seen_but_never_stored(self):
        # Regression: a live dashboard tab's own polling/WebSocket traffic
        # to this app's web port, captured right back by this same sniffer,
        # was observed saturating the capture socket under normal desktop
        # use. dst_port==3389 above is what would normally persist (an
        # admin-port hit); pointed at PORT instead, it must not, even
        # though otherwise identical.
        self.sniffer._store_packet(self._base_packet(transport="tcp", dst_port=3389, src_port=SNIFFER_PORT))
        self.assertEqual(self.store.list_count("packets"), 0)
        self.assertEqual(self.sniffer.state.packets_seen, 1)
        self.assertEqual(self.sniffer.state.packets_stored, 0)

    def test_own_dashboard_traffic_as_destination_is_also_skipped(self):
        self.sniffer._store_packet(self._base_packet(transport="tcp", src_port=3389, dst_port=SNIFFER_PORT))
        self.assertEqual(self.store.list_count("packets"), 0)

    def test_non_tcp_traffic_on_the_same_port_number_is_not_excluded(self):
        # The exclusion is TCP-specific (this app's listener is TCP) - a UDP
        # packet that merely happens to share the port number is unrelated
        # traffic and must not be short-circuited by it.
        packet = self._base_packet(transport="udp", proto="udp", dst_port=SNIFFER_PORT, src_port=51234)
        self.assertFalse(self.sniffer._is_own_dashboard_traffic(packet))

    def test_filter_disabled_persists_everything(self):
        self.store.set_monitor_filter_enabled(False)
        self.sniffer._store_packet(self._base_packet())
        self.assertEqual(self.store.list_count("packets"), 1)
        self.assertEqual(self.sniffer.state.packets_stored, 1)

    def test_minimum_monitor_severity_filters_stored_hits(self):
        self.store.set_monitor_min_severity("high")
        self.sniffer._store_packet(self._base_packet(dst_port=3389))
        self.assertEqual(self.store.list_count("packets"), 0)

        self.sniffer._store_packet(
            self._base_packet(
                dst_port=80,
                payload_len=56,
                payload_text="POST /login HTTP/1.1\r\nusername=admin&password=hunter2",
            )
        )
        self.assertEqual(self.store.list_count("packets"), 1)

    def test_generated_info_signals_are_suppressed_by_default(self):
        self.sniffer._monitor_cache = [
            normalize_monitor(
                {
                    "id": "builtin-signal-noisy",
                    "name": "Generated noisy signal",
                    "match": {"payload_contains": ["application/json"]},
                    "action": {"tag": "generated-noisy", "label": "Generated noisy", "severity": "low"},
                }
            )
        ]
        self.sniffer._monitor_cache_at = 999999999.0
        self.sniffer._ruleset_cache = []
        self.sniffer._ruleset_cache_at = 999999999.0
        self.sniffer._store_packet(self._base_packet(payload_text="HTTP/1.1 200 OK\r\nContent-Type: application/json"))
        self.assertEqual(self.store.list_count("packets"), 0)

    def test_generated_info_signals_can_be_reenabled(self):
        self.store.set_monitor_suppress_generated_info(False)
        self.sniffer._monitor_cache = [
            normalize_monitor(
                {
                    "id": "builtin-signal-noisy",
                    "name": "Generated noisy signal",
                    "match": {"payload_contains": ["application/json"]},
                    "action": {"tag": "generated-noisy", "label": "Generated noisy", "severity": "low"},
                }
            )
        ]
        self.sniffer._monitor_suppress_generated_info = False
        self.sniffer._monitor_cache_at = 999999999.0
        self.sniffer._ruleset_cache = []
        self.sniffer._ruleset_cache_at = 999999999.0
        self.sniffer._store_packet(self._base_packet(payload_text="HTTP/1.1 200 OK\r\nContent-Type: application/json"))
        self.assertEqual(self.store.list_count("packets"), 1)

    def test_undetected_packets_are_time_throttled_on_the_websocket(self):
        # Warm the content index (see _await_monitor_index_ready) first so
        # the 201 packets below don't each pay the much slower unindexed
        # full scan across the whole builtin catalog.
        _await_monitor_index_ready(self.sniffer)
        self.sniffer.hub.reset_mock()
        self.sniffer._store_packet(self._base_packet())
        self.assertEqual(self.sniffer.hub.broadcast.call_count, 1)
        broadcast_type = self.sniffer.hub.broadcast.call_args[0][0]["type"]
        self.assertEqual(broadcast_type, "stats_update")
        # Freeze time.monotonic() for the throttle check itself
        # (Sniffer._broadcast_stats_throttled) so this assertion covers the
        # throttling logic on its own terms - "many packets within one
        # window produce one broadcast" - rather than depending on this
        # process actually processing 200 packets in under one real second,
        # which varies with whatever else is running on the machine/in the
        # rest of the test suite at the time.
        with patch("sniff4hound.sniffer.time.monotonic", return_value=time.monotonic()):
            for _ in range(200):
                self.sniffer._store_packet(self._base_packet())
        # Still within the same throttle window, so wire-speed traffic can't flood the socket.
        self.assertEqual(self.sniffer.hub.broadcast.call_count, 1)

    def test_detected_packet_always_broadcasts_full_packet_event(self):
        self.sniffer._store_packet(self._base_packet(dst_port=3389))
        types = [call.args[0]["type"] for call in self.sniffer.hub.broadcast.call_args_list]
        self.assertEqual(types, ["packet", "stats_update"])

    def test_detected_packet_broadcast_includes_severity_on_monitor_tag(self):
        # Frontend notifications decide what's "important" from this field -
        # it has to ride along on the WS "packet" event, not just live in
        # the monitor definition server-side.
        self.sniffer._store_packet(self._base_packet(dst_port=3389))
        packet_call = next(
            call for call in self.sniffer.hub.broadcast.call_args_list if call.args[0]["type"] == "packet"
        )
        broadcast_packet = packet_call.args[0]["packet"]
        tags = json.loads(broadcast_packet["tags_json"])
        monitor_tags = [tag for tag in tags if tag.get("key") == "monitor"]
        self.assertTrue(monitor_tags)
        self.assertEqual(monitor_tags[0]["severity"], "medium")

    def test_detected_packet_is_queryable_by_monitor_id(self):
        self.sniffer._store_packet(self._base_packet(dst_port=3389))
        rows = self.store.list_packets_by_monitor("builtin-admin-ports")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["dst_port"], 3389)
        self.assertEqual(self.store.list_packets_by_monitor("builtin-credentials"), [])

    def test_monitor_match_counts_only_includes_matched_monitors(self):
        # Different src_ip on each packet - RuleAlertThrottle (see
        # monitors.py) rate-limits repeat medium+ severity hits from the
        # *same* source, so two hits from the same source within the
        # cooldown window would otherwise only count once here.
        self.sniffer._store_packet(self._base_packet(dst_port=3389))
        self.sniffer._store_packet(self._base_packet(dst_port=3389, src_ip="10.0.0.6", dst_ip="10.0.0.50"))
        counts = self.store.monitor_match_counts()
        self.assertEqual(counts.get("builtin-admin-ports"), 2)
        self.assertNotIn("builtin-credentials", counts)

    def test_list_packets_by_monitor_includes_matched_value(self):
        self.sniffer._store_packet(self._base_packet(dst_port=3389))
        rows = self.store.list_packets_by_monitor("builtin-admin-ports")
        self.assertEqual(rows[0]["matched_value"], "port 3389")

    def test_list_packets_by_monitor_search_filters(self):
        self.sniffer._store_packet(self._base_packet(dst_port=3389, dst_ip="10.0.0.50"))
        self.sniffer._store_packet(self._base_packet(dst_port=3389, dst_ip="10.0.0.99"))
        rows = self.store.list_packets_by_monitor("builtin-admin-ports", search="10.0.0.50")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["dst_ip"], "10.0.0.50")


if __name__ == "__main__":
    unittest.main()
