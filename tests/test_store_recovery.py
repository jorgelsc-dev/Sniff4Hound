"""The store has to survive a connection that stops being able to write.

Two processes share this database: the unprivileged web process and the
privileged capture child. A connection was observed left unable to write
while the database itself was free - the capture child failed on *every*
packet for twenty minutes, and nothing recovered it short of restarting the
process. Since the sniffer treats a failed store as a dropped packet, that
is a silent, total loss of capture. These tests pin the recovery path.
"""

from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest

from sniff4hound.store import SniffStore


class ConnectionRecoveryTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.path = os.path.join(self._tmp.name, "recover.db")
        self.store = SniffStore(self.path)
        self.addCleanup(self.store.close)

    def _packet(self, ip="10.0.0.1"):
        return {
            "src_ip": ip, "dst_ip": "1.1.1.1", "proto": "tls", "transport": "tcp",
            "interface": "eth0", "length": 200, "src_port": 50000, "dst_port": 443,
        }

    def test_writes_survive_a_closed_connection(self):
        # The bluntest form of a wedged connection: it is simply gone.
        # Without recovery every later packet raises ProgrammingError and is
        # dropped for the life of the process.
        self.store._conn.close()
        self.store.register_packet(self._packet())
        self.assertEqual(self.store.list_count("packets"), 1)

    def test_writes_survive_a_connection_left_mid_transaction(self):
        self.store._conn.execute("BEGIN")
        self.store.register_packet(self._packet())
        self.assertEqual(self.store.list_count("packets"), 1)

    def test_recovery_reopens_a_working_connection(self):
        self.store._conn.close()
        self.store._recover_connection()
        self.assertEqual(self.store._conn.execute("SELECT 1").fetchone()[0], 1)

    def test_a_real_error_is_not_swallowed(self):
        # Recovery is only for lock/connection trouble. A genuine SQL error
        # must still reach the caller instead of being retried into silence.
        with self.assertRaises(sqlite3.OperationalError):
            self.store._execute("SELECT * FROM table_that_does_not_exist")

    def test_writes_resume_after_another_process_holds_the_write_lock(self):
        holder = textwrap.dedent(
            """
            import sqlite3, sys, time
            conn = sqlite3.connect(sys.argv[1], timeout=30)
            conn.execute("PRAGMA busy_timeout=30000")
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("INSERT INTO sessions (network, type, proto, port_mode, port_start,"
                         " port_end, status, timesleep, progress, interface, filter_text,"
                         " packets_seen, bytes_seen, rules_seen, created_at, updated_at)"
                         " VALUES ('x','all','all','preset',0,0,'active',0.5,0.0,'','',0,0,0,'now','now')")
            print("locked", flush=True)
            time.sleep(2)
            conn.rollback()
            conn.close()
            """
        )
        script = os.path.join(self._tmp.name, "holder.py")
        with open(script, "w", encoding="utf-8") as handle:
            handle.write(holder)
        proc = subprocess.Popen([sys.executable, script, self.path], stdout=subprocess.PIPE, text=True)
        self.addCleanup(proc.wait)
        self.assertEqual(proc.stdout.readline().strip(), "locked")

        # The write may block while the other process holds the lock, but it
        # must land once that clears - never fail permanently.
        deadline = time.time() + 30
        while time.time() < deadline:
            try:
                self.store.register_packet(self._packet())
                break
            except sqlite3.OperationalError:
                time.sleep(0.2)
        else:
            self.fail("writes never resumed after the other process released the lock")
        self.assertGreaterEqual(self.store.list_count("packets"), 1)


class PurgeDoesNotWedgeOtherConnectionsTests(unittest.TestCase):
    """Clearing stored data must not cost the other process its ability to
    write. The dashboard's Clear-data button ran a full VACUUM, which
    rewrites the whole file while the capture child has it open."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.path = os.path.join(self._tmp.name, "purge.db")
        self.web = SniffStore(self.path)
        self.addCleanup(self.web.close)
        self.capture = SniffStore(self.path)
        self.addCleanup(self.capture.close)

    def test_the_capture_side_still_writes_after_a_purge(self):
        packet = {
            "src_ip": "10.0.0.1", "dst_ip": "1.1.1.1", "proto": "tls", "transport": "tcp",
            "interface": "eth0", "length": 200, "src_port": 50000, "dst_port": 443,
        }
        for _ in range(50):
            self.capture.register_packet(packet)

        self.web.purge_capture_data()

        for _ in range(10):
            self.capture.register_packet(packet)
        self.assertEqual(self.capture.list_count("packets"), 10)

    def test_purge_no_longer_runs_a_whole_file_vacuum(self):
        import inspect

        source = inspect.getsource(SniffStore.purge_capture_data)
        self.assertNotIn('execute("VACUUM")', source)
        self.assertIn("incremental_vacuum", source)


if __name__ == "__main__":
    unittest.main()
