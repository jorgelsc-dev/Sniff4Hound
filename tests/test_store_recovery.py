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

    def test_writes_survive_another_row_available(self):
        # Observed in production on POST /api/detection/scopes while the
        # privileged capture child was writing loopback packets
        # concurrently: sqlite3 can report a connection knocked out of sync
        # as the base DatabaseError ("another row available"), not just
        # OperationalError - a class this recovery path used to miss
        # entirely, so the request 500'd on the very first hiccup instead
        # of retrying like every other transient lock/connection error.
        # sqlite3.Connection.execute is a read-only slot, so the flaky
        # behavior has to come from a thin proxy standing in for the real
        # connection rather than a per-instance monkeypatch.
        real_conn = self.store._conn
        calls = {"n": 0}

        class FlakyConn:
            def execute(self, *args, **kwargs):
                calls["n"] += 1
                if calls["n"] == 1:
                    raise sqlite3.DatabaseError("another row available")
                return real_conn.execute(*args, **kwargs)

            def __getattr__(self, name):
                return getattr(real_conn, name)

        self.store._conn = FlakyConn()
        self.store.set_detection_exclude_scopes(["loopback"])
        self.assertEqual(self.store.get_detection_exclude_scopes(), ["loopback"])

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
        # It reclaims in capped bites instead, via the bounded helper.
        self.assertIn("reclaim_free_pages", source)
        self.assertIn("incremental_vacuum", inspect.getsource(SniffStore.reclaim_free_pages))


def _fat_packet(ip="10.0.0.1"):
    """A packet big enough that a few thousand of them move the page count."""
    return {
        "src_ip": ip, "dst_ip": "1.1.1.1", "proto": "tls", "transport": "tcp",
        "interface": "eth0", "length": 1400, "src_port": 50000, "dst_port": 443,
        "raw_packet": b"\xab" * 3000, "payload_text": "payload " * 250,
    }


class ReclaimActuallyShrinksTheFileTests(unittest.TestCase):
    """Taking the whole-file VACUUM out of the purge path (see above) left
    nothing at all reclaiming space, and the database grew without bound:
    an operator's file reached 5.55 GiB holding ~200 MiB of live data, with
    96.4% of it sitting on the freelist. Deleting rows is only half a
    purge - these pin the half that gives the pages back."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.path = os.path.join(self._tmp.name, "reclaim.db")
        self.store = SniffStore(self.path)
        self.addCleanup(self.store.close)

    def _pages(self):
        conn = self.store._conn
        return (
            conn.execute("PRAGMA page_count").fetchone()[0],
            conn.execute("PRAGMA freelist_count").fetchone()[0],
        )

    def _fill(self, count=3000):
        for _ in range(count):
            self.store.register_packet(_fat_packet())

    def test_a_purge_shrinks_the_file_it_freed_pages_from(self):
        self._fill()
        grown_pages, _ = self._pages()

        self.store.purge_capture_data()

        pages, free = self._pages()
        self.assertLess(pages, grown_pages, "purge freed pages but the file kept them")
        # Not just smaller - the freelist is actually drained, so the next
        # capture reuses the file instead of extending it again.
        self.assertEqual(free, 0)

    def test_retention_reclaims_without_draining_the_whole_freelist(self):
        # enforce_retention runs on the capture thread, so its reclaim is
        # capped per sweep. It has to make progress, but a single sweep must
        # not turn into an unbounded rewrite.
        #
        # The exact count matters, not just "some progress": PRAGMA
        # incremental_vacuum frees a page per step of the statement and
        # Connection.execute() steps it once, so running it without
        # draining the cursor frees exactly ONE page however large N is.
        # That reads like a working bounded reclaim while letting the
        # freelist outgrow it 255 pages to 1 every sweep.
        self._fill()
        self.store._conn.execute("DELETE FROM packets")
        self.store._conn.commit()
        _pages, free_before = self._pages()
        self.assertGreater(free_before, 256, "test needs a freelist larger than one bite")

        reclaimed = self.store.reclaim_free_pages(256)

        _pages, free_after = self._pages()
        self.assertEqual(reclaimed, 256)
        self.assertEqual(free_after, free_before - 256)

    def test_reclaim_is_a_harmless_no_op_with_nothing_to_reclaim(self):
        self.assertEqual(self.store.reclaim_free_pages(256), 0)

    def test_an_older_database_is_migrated_to_incremental_auto_vacuum(self):
        # The case that made all of the above dead code in the field. A
        # database created before this app set auto_vacuum=INCREMENTAL is
        # stuck at NONE for life, and in that mode every PRAGMA
        # incremental_vacuum is a silent no-op - so a purge deletes the rows
        # and the file never gives a single page back.
        legacy = os.path.join(self._tmp.name, "legacy.db")
        conn = sqlite3.connect(legacy)
        conn.execute("PRAGMA auto_vacuum=NONE")
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("CREATE TABLE filler (id INTEGER PRIMARY KEY, blob BLOB)")
        conn.executemany("INSERT INTO filler (blob) VALUES (?)", [(b"z" * 4000,) for _ in range(20000)])
        conn.commit()
        conn.execute("DELETE FROM filler")
        conn.commit()
        self.assertEqual(conn.execute("PRAGMA auto_vacuum").fetchone()[0], 0)
        grown = conn.execute("PRAGMA page_count").fetchone()[0]
        self.assertGreater(conn.execute("PRAGMA freelist_count").fetchone()[0], 1000)
        conn.close()

        store = SniffStore(legacy)
        self.addCleanup(store.close)

        stats = store.database_storage_stats()
        self.assertTrue(stats["incremental_reclaim"], "older database was left unable to reclaim")
        self.assertEqual(stats["auto_vacuum"], 2)
        self.assertLess(stats["page_count"], grown)
        # And from here on the ordinary bounded reclaim works on it, which is
        # the whole point of the migration.
        store._conn.execute("INSERT INTO filler (blob) VALUES (?)", (b"z" * 4000,))
        store._conn.execute("DELETE FROM filler")
        store._conn.commit()
        self.assertEqual(store._auto_vacuum_mode(), 2)

    def test_the_migration_is_skipped_when_there_is_too_much_live_data(self):
        # VACUUM's cost tracks live content, so the migration is bounded by
        # refusing to run on a database with more of it than can be rewritten
        # quickly. Startup must not stall for minutes on a big database.
        from sniff4hound import store as store_module

        legacy = os.path.join(self._tmp.name, "huge.db")
        conn = sqlite3.connect(legacy)
        conn.execute("PRAGMA auto_vacuum=NONE")
        conn.execute("CREATE TABLE filler (id INTEGER PRIMARY KEY, blob BLOB)")
        conn.executemany("INSERT INTO filler (blob) VALUES (?)", [(b"z" * 4000,) for _ in range(5000)])
        conn.commit()
        conn.close()

        original = store_module.AUTOVACUUM_MIGRATION_MAX_LIVE_BYTES
        store_module.AUTOVACUUM_MIGRATION_MAX_LIVE_BYTES = 1024
        self.addCleanup(setattr, store_module, "AUTOVACUUM_MIGRATION_MAX_LIVE_BYTES", original)

        store = SniffStore(legacy)
        self.addCleanup(store.close)

        self.assertEqual(store._autovacuum_migration["state"], "deferred")
        self.assertEqual(store._autovacuum_migration["reason"], "live_data_over_cap")
        # Skipped, not broken: the store is fully usable, it just cannot
        # shrink until an operator runs the explicit compaction.
        self.assertFalse(store.database_storage_stats()["incremental_reclaim"])
        store.register_packet(_fat_packet())
        self.assertEqual(store.list_count("packets"), 1)

        # ...which is exactly what the operator action is for.
        result = store.compact_database()
        self.assertEqual(result["state"], "compacted")
        self.assertTrue(store.database_storage_stats()["incremental_reclaim"])

    def test_storage_stats_report_what_is_reclaimable(self):
        self._fill()
        self.store._conn.execute("DELETE FROM packets")
        self.store._conn.commit()

        stats = self.store.database_storage_stats()

        self.assertEqual(stats["file_bytes"], stats["page_size"] * stats["page_count"])
        self.assertEqual(stats["free_bytes"], stats["page_size"] * stats["freelist_count"])
        self.assertEqual(stats["live_bytes"], stats["file_bytes"] - stats["free_bytes"])
        self.assertGreater(stats["free_ratio"], 0.0)
        self.assertTrue(stats["incremental_reclaim"])


class ReclaimDoesNotBlockAConcurrentWriterTests(unittest.TestCase):
    """The reason #117 pulled VACUUM out of the purge path: the privileged
    capture child shares this database, and a whole-file rewrite left it
    unable to store a single packet for twenty minutes. Whatever reclaims
    space now has to keep its hands off the write lock long enough for the
    other process to keep working."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.path = os.path.join(self._tmp.name, "concurrent.db")
        self.web = SniffStore(self.path)
        self.addCleanup(self.web.close)

    def _writer_script(self):
        return textwrap.dedent(
            """
            import sys, time
            from sniff4hound.store import SniffStore
            store = SniffStore(sys.argv[1])
            packet = {
                "src_ip": "10.0.0.9", "dst_ip": "1.1.1.1", "proto": "tls",
                "transport": "tcp", "interface": "eth0", "length": 200,
                "src_port": 50000, "dst_port": 443,
            }
            print("ready", flush=True)
            deadline = time.time() + 20
            written = 0
            while time.time() < deadline:
                line = sys.stdin.readline()
                if not line or line.strip() == "stop":
                    break
                store.register_packet(packet)
                written += 1
                print(f"wrote {written}", flush=True)
            store.close()
            """
        )

    def test_a_reclaim_leaves_the_other_process_writing(self):
        script = os.path.join(self._tmp.name, "writer.py")
        with open(script, "w", encoding="utf-8") as handle:
            handle.write(self._writer_script())
        env = dict(os.environ)
        env["PYTHONPATH"] = os.pathsep.join(
            [os.path.dirname(os.path.dirname(os.path.abspath(__file__))), env.get("PYTHONPATH", "")]
        )
        proc = subprocess.Popen(
            [sys.executable, script, self.path],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, env=env,
        )
        self.addCleanup(proc.wait)
        self.addCleanup(proc.kill)
        self.assertEqual(proc.stdout.readline().strip(), "ready")

        # Build a freelist worth reclaiming on this side.
        for _ in range(2000):
            self.web.register_packet(_fat_packet())
        self.web._conn.execute("DELETE FROM packets")
        self.web._conn.commit()
        self.assertGreater(self.web._page_stats()[2], 0, "test needs free pages to reclaim")

        # Each round: the other process writes a packet, then this one takes
        # a bite out of the freelist. A reclaim that held the write lock the
        # way a whole-file VACUUM does would stall the next write past the
        # timeout instead of interleaving with it.
        for _ in range(10):
            proc.stdin.write("go\n")
            proc.stdin.flush()
            started = time.time()
            line = proc.stdout.readline().strip()
            self.assertTrue(line.startswith("wrote"), f"writer stopped storing packets: {line!r}")
            self.assertLess(time.time() - started, 10, "a reclaim blocked the other process's write")
            self.web.reclaim_free_pages(64)

        proc.stdin.write("stop\n")
        proc.stdin.flush()
        self.assertEqual(self.web.list_count("packets"), 10)

    def test_a_purge_leaves_the_other_process_writing(self):
        # Same guarantee for the full purge-then-reclaim path, which is what
        # the dashboard's Clear-data button actually runs.
        capture = SniffStore(self.path)
        self.addCleanup(capture.close)
        for _ in range(2000):
            capture.register_packet(_fat_packet())

        started = time.monotonic()
        self.web.purge_capture_data()
        elapsed = time.monotonic() - started

        # purge_capture_data time-boxes its reclaim; if that budget ever goes
        # away this is the test that notices.
        self.assertLess(elapsed, 15, "purge took long enough to look like a whole-file rewrite")
        capture.register_packet(_fat_packet())
        self.assertEqual(capture.list_count("packets"), 1)


if __name__ == "__main__":
    unittest.main()
