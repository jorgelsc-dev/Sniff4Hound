"""Log level, rotation, retention and the read-back tail."""

from __future__ import annotations

import logging
import os
import tempfile
import time
import unittest
from pathlib import Path

from sniff4hound import log_setup
from sniff4hound.store import SniffStore


def _cfg(**overrides):
    config = dict(log_setup.LOG_DEFAULTS)
    config.update(overrides)
    return config


class LogSettingsValidationTests(unittest.TestCase):
    def test_accepts_valid_values_and_normalises_level(self):
        self.assertEqual(
            log_setup.coerce_log_settings({"level": "warning", "max_mb": "5", "backups": 2}),
            {"level": "WARNING", "max_mb": 5, "backups": 2},
        )

    def test_rejects_unknown_level_and_out_of_range_numbers(self):
        for values in ({"level": "TRACE"}, {"max_mb": 0}, {"backups": 101}, {"retention_days": -1}, {"slow_ms": True}):
            with self.subTest(values=values), self.assertRaises(ValueError):
                log_setup.coerce_log_settings(values)


class RotatingSinkTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)

    def test_rotates_by_size_and_keeps_only_the_configured_backups(self):
        sink = log_setup.RotatingNDJSONSink(self.dir / "web.ndjson", max_bytes=400, backups=2, retention_days=0)
        for number in range(200):
            sink.write({"level": "DEBUG", "message": "x" * 50, "n": number})
        names = sorted(p.name for p in self.dir.glob("web.ndjson*"))
        self.assertEqual(names, ["web.ndjson", "web.ndjson.1", "web.ndjson.2"])
        self.assertLessEqual((self.dir / "web.ndjson").stat().st_size, 400 + 200)

    def test_zero_backups_truncates_instead_of_keeping_history(self):
        sink = log_setup.RotatingNDJSONSink(self.dir / "web.ndjson", max_bytes=300, backups=0, retention_days=0)
        for number in range(50):
            sink.write({"level": "DEBUG", "message": "y" * 40, "n": number})
        self.assertEqual(list(self.dir.glob("web.ndjson.*")), [])

    def test_retention_removes_rotated_files_older_than_the_window(self):
        sink = log_setup.RotatingNDJSONSink(self.dir / "web.ndjson", max_bytes=10**9, backups=5, retention_days=7)
        old = self.dir / "web.ndjson.1"
        old.write_text('{"level":"INFO","message":"old"}\n')
        ancient = time.time() - 30 * 86400
        os.utime(old, (ancient, ancient))
        fresh = self.dir / "web.ndjson.2"
        fresh.write_text('{"level":"INFO","message":"fresh"}\n')
        removed = sink.maintain()
        self.assertEqual(removed, 1)
        self.assertFalse(old.exists())
        self.assertTrue(fresh.exists())

    def test_tail_returns_newest_rows_filtered_by_level(self):
        sink = log_setup.RotatingNDJSONSink(self.dir / "web.ndjson", max_bytes=10**9, backups=0, retention_days=0)
        for number in range(30):
            sink.write({"level": "DEBUG" if number % 2 else "WARNING", "message": f"m{number}"})
        rows = sink.tail(lines=5, min_level="WARNING")
        self.assertEqual(len(rows), 5)
        self.assertTrue(all(row["level"] == "WARNING" for row in rows))
        self.assertEqual(rows[-1]["message"], "m28")


class ConfiguredLoggingTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        root = logging.getLogger("sniff4hound")
        before = (list(root.handlers), root.level, root.propagate)

        def restore():
            for handler in list(root.handlers):
                if handler not in before[0]:
                    root.removeHandler(handler)
                    handler.close()
            root.setLevel(before[1])
            root.propagate = before[2]

        self.addCleanup(restore)

    def test_level_change_applies_to_the_running_logger(self):
        log_setup.configure("web", Path(self._tmp.name), _cfg(level="DEBUG"))
        logger = logging.getLogger("sniff4hound.tests.level")
        logger.debug("first debug line")
        log_setup.apply_config(_cfg(level="WARNING"))
        logger.debug("second debug line - should be dropped")
        logger.warning("visible warning")
        rows = log_setup.tail("web", lines=50)
        messages = [row["message"] for row in rows]
        self.assertIn("first debug line", messages)
        self.assertNotIn("second debug line - should be dropped", messages)
        self.assertIn("visible warning", messages)

    def test_configure_is_idempotent_and_does_not_duplicate_handlers(self):
        log_setup.configure("web", Path(self._tmp.name), _cfg())
        log_setup.configure("web", Path(self._tmp.name), _cfg())
        tagged = [h for h in logging.getLogger("sniff4hound").handlers if getattr(h, log_setup._HANDLER_TAG, False)]
        self.assertEqual(len(tagged), 2)


class StoredLogConfigTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.store = SniffStore(os.path.join(self._tmp.name, "logs.db"))
        self.addCleanup(self.store.close)

    def test_defaults_then_round_trip(self):
        self.assertEqual(self.store.get_log_config()["level"], "DEBUG")
        saved = self.store.set_log_config({"level": "info", "max_mb": 3, "retention_days": 2})
        self.assertEqual((saved["level"], saved["max_mb"], saved["retention_days"]), ("INFO", 3, 2))
        self.assertEqual(saved["backups"], log_setup.LOG_DEFAULTS["backups"])

    def test_invalid_update_writes_nothing(self):
        self.store.set_log_config({"level": "WARNING"})
        with self.assertRaises(ValueError):
            self.store.set_log_config({"level": "WARNING", "backups": 500})
        self.assertEqual(self.store.get_log_config()["level"], "WARNING")


if __name__ == "__main__":
    unittest.main()
