import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]


class ConfigurationSecurityTests(unittest.TestCase):
    def test_auth_disabled_rejects_non_loopback_host(self):
        env = os.environ.copy()
        env.update({"SNIFF4HOUND_HOST": "0.0.0.0", "SNIFF4HOUND_REQUIRE_AUTH": "0"})
        result = subprocess.run(
            [sys.executable, "-c", "import sniff4hound.settings"],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("only allowed with a loopback", result.stderr)

    def test_auth_disabled_allows_loopback_host(self):
        env = os.environ.copy()
        with tempfile.TemporaryDirectory() as data_dir:
            env.update({
                "SNIFF4HOUND_HOST": "[::1]",
                "SNIFF4HOUND_REQUIRE_AUTH": "0",
                "SNIFF4HOUND_DATA_DIR": data_dir,
            })
            result = subprocess.run(
                [sys.executable, "-c", "import sniff4hound.settings"],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
            )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_invalid_auth_value_is_rejected(self):
        env = os.environ.copy()
        env["SNIFF4HOUND_REQUIRE_AUTH"] = "perhaps"
        result = subprocess.run(
            [sys.executable, "-c", "import sniff4hound.settings"],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must be a boolean", result.stderr)

    def test_storage_counts_rotated_logs_and_sqlite_sidecars(self):
        from sniff4hound.resource_guard import storage_mb

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory) / "service_listener.log"
            base.write_bytes(b"a")
            Path(f"{base}.1").write_bytes(b"bb")
            Path(f"{base}.2.gz").write_bytes(b"ccc")
            database = Path(directory) / "service_events.db"
            database.write_bytes(b"d")
            Path(f"{database}-wal").write_bytes(b"ww")
            Path(f"{database}-shm").write_bytes(b"sss")
            self.assertEqual(storage_mb([base, database]), 12 / (1024 * 1024))

    def test_honeypot_retention_truncates_wal_without_unlinking_live_sidecars(self):
        from sniff4hound import honeypot

        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "events.db"
            connection = sqlite3.connect(database)
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("CREATE TABLE connection_events (event_time TEXT)")
            connection.execute("INSERT INTO connection_events VALUES ('2000-01-01T00:00:00+00:00')")
            connection.commit()
            with patch.object(honeypot, "EVENT_DB_FILE", database):
                result = honeypot.purge_honeypot_events_before("2020-01-01T00:00:00+00:00")
            connection.close()
            self.assertEqual(result["connection_events"], 1)
            self.assertFalse(database.with_name(database.name + "-wal").exists())

    def test_honeypot_auxiliary_db_scrubs_raw_bytes_and_peer_cert(self):
        from sniff4hound import honeypot

        class Store:
            def get_raw_retention_enabled(self):
                return False

        with tempfile.TemporaryDirectory() as directory:
            connection = sqlite3.connect(Path(directory) / "events.db")
            connection.executescript(
                """
                CREATE TABLE connection_events (
                    event_time TEXT, protocol TEXT, dst_port INTEGER,
                    src_ip TEXT, src_port INTEGER, data_len INTEGER,
                    data_preview TEXT, data BLOB
                );
                CREATE TABLE tls_sessions (
                    event_time TEXT, src_ip TEXT, src_port INTEGER,
                    dst_port INTEGER, tls_version TEXT, cipher_name TEXT,
                    cipher_protocol TEXT, cipher_bits INTEGER, alpn TEXT,
                    sni TEXT, peer_cert BLOB
                );
                CREATE TABLE dns_queries (
                    event_time TEXT, src_ip TEXT, src_port INTEGER,
                    dst_port INTEGER, domain TEXT, query_type INTEGER,
                    response_ip TEXT
                );
                """
            )
            engine = honeypot.HoneypotEngine.__new__(honeypot.HoneypotEngine)
            engine.store = Store()
            engine._insert_event_row(
                connection,
                {
                    "raw_packet": b"secret-payload",
                    "length": 14,
                    "proto": "tls",
                    "src_ip": "192.0.2.5",
                    "src_port": 40000,
                    "dst_port": 443,
                },
                {"tls": {"peer_cert": b"secret-certificate", "sni": "example.test"}},
            )
            connection.commit()
            event = connection.execute("SELECT data, data_preview FROM connection_events").fetchone()
            cert = connection.execute("SELECT peer_cert FROM tls_sessions").fetchone()[0]
            self.assertIsNone(event[0])
            self.assertEqual(event[1], "")
            self.assertIsNone(cert)
            connection.close()


if __name__ == "__main__":
    unittest.main()
