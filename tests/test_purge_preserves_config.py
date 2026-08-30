"""The dashboard's "Clear data" button purges everything capture and the
honeypot produced. The one guarantee an operator relies on when pressing it
is that the catalogs they configured by hand - monitors, listeners,
rulesets, allow/block lists and the selected NICs - are NOT part of that purge.
"""

from __future__ import annotations

import os
import tempfile
import unittest

from sniff4hound.store import SniffStore


# Everything the purge is allowed to touch. Anything outside this set is
# operator configuration and must survive.
PURGEABLE_TABLES = {"tags", "payloads", "packets", "flows", "domains", "paths", "sessions"}

CONFIG_TABLES = ("monitors", "honeypot_listeners", "rulesets", "blacklist_entries", "whitelist_entries")


class PurgePreservesConfigTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.store = SniffStore(os.path.join(self._tmp.name, "purge.db"))
        self.addCleanup(self.store.close)

    def _count(self, table: str) -> int:
        return int(self.store._conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])

    def test_purge_only_touches_capture_tables(self):
        self.assertEqual(set(SniffStore.CAPTURE_DATA_TABLES), PURGEABLE_TABLES)

    def test_configuration_survives_a_full_purge(self):
        # The built-in catalogs are seeded on first open, so these are
        # non-zero without having to fabricate rows.
        before = {table: self._count(table) for table in CONFIG_TABLES}
        self.assertGreater(before["monitors"], 0, "expected seeded monitor definitions")
        self.assertGreater(before["honeypot_listeners"], 0, "expected seeded listeners")

        self.store.set_runtime_config("selected_interfaces", "eth0,wlan0")

        self.store.purge_capture_data()

        after = {table: self._count(table) for table in CONFIG_TABLES}
        self.assertEqual(before, after)
        # The selected NICs are runtime_config, which the purge must leave
        # alone too - otherwise the next capture starts on no interfaces.
        self.assertEqual(self.store.get_runtime_config("selected_interfaces", ""), "eth0,wlan0")

    def test_purge_reports_the_capture_tables_it_cleared(self):
        deleted = self.store.purge_capture_data()
        self.assertEqual(set(deleted), PURGEABLE_TABLES)

    def test_new_databases_get_incremental_auto_vacuum(self):
        # Regression: PRAGMA auto_vacuum=INCREMENTAL used to be set *after*
        # PRAGMA journal_mode=WAL in _open_connection, which is too late for
        # SQLite to accept it - so it silently stayed NONE, and every
        # PRAGMA incremental_vacuum this store ever ran (here and in
        # enforce_retention) was a total no-op. The database file only ever
        # grew, on every purge and every retention cycle.
        self.assertEqual(self.store._conn.execute("PRAGMA auto_vacuum").fetchone()[0], 2)

    def test_purge_reports_progress(self):
        packet = {
            "src_ip": "10.0.0.1", "dst_ip": "1.1.1.1", "proto": "tls", "transport": "tcp",
            "interface": "eth0", "length": 200, "src_port": 50000, "dst_port": 443,
        }
        for _ in range(20):
            self.store.register_packet(packet)

        events = []
        deleted = self.store.purge_capture_data(progress=events.append)

        self.assertTrue(events, "expected at least one progress update")
        self.assertEqual(events[0]["phase"], "deleting")
        self.assertEqual(events[-1]["phase"], "done")
        self.assertEqual(events[-1]["rows_done"], events[-1]["rows_total"])
        self.assertEqual(events[-1]["rows_done"], sum(deleted.values()))
        # Every "deleting" update's rows_done is monotonically non-decreasing
        # and never exceeds the declared total - the frontend renders this
        # straight into a percentage, so a value outside that range would
        # show a progress bar going backwards or past 100%.
        deleting = [e for e in events if e["phase"] == "deleting"]
        rows_done_sequence = [e["rows_done"] for e in deleting]
        self.assertEqual(rows_done_sequence, sorted(rows_done_sequence))
        for event in deleting:
            self.assertLessEqual(event["rows_done"], event["rows_total"])

    def test_purge_progress_errors_do_not_break_the_purge(self):
        # progress is best-effort: a broken callback must not stop rows
        # from actually being deleted.
        self.store.register_packet({
            "src_ip": "10.0.0.1", "dst_ip": "1.1.1.1", "proto": "tls", "transport": "tcp",
            "interface": "eth0", "length": 200, "src_port": 50000, "dst_port": 443,
        })

        def boom(_status):
            raise RuntimeError("frontend disconnected mid-broadcast")

        deleted = self.store.purge_capture_data(progress=boom)
        self.assertEqual(deleted["packets"], 1)


if __name__ == "__main__":
    unittest.main()
