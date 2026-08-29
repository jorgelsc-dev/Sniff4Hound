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


if __name__ == "__main__":
    unittest.main()
