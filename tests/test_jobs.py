from __future__ import annotations

import tempfile
import threading
import time
import unittest
from pathlib import Path

from sniff4hound.jobs import STATUS_DONE, STATUS_ERROR, JobQueue
from sniff4hound.store import SniffStore
from sniff4hound.utils import utc_now, utc_since


def _wait_until(predicate, *, timeout=3.0, interval=0.02):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


class JobQueueTests(unittest.TestCase):
    def setUp(self):
        self._tmp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp_dir.cleanup)
        self.store = SniffStore(str(Path(self._tmp_dir.name) / "jobs.db"))
        self.addCleanup(self.store.close)
        self.broadcasts = []
        self.queue = JobQueue(
            store=self.store, broadcast=self.broadcasts.append, workers=2
        )
        self.addCleanup(self.queue.shutdown)

    def _job_rows(self) -> int:
        return int(self.store._fetchone("SELECT COUNT(*) AS c FROM jobs")["c"])

    def test_fast_call_answers_inline_and_writes_nothing(self):
        finished, payload = self.queue.submit("fast", lambda: {"ok": 1})

        self.assertTrue(finished)
        self.assertEqual(payload, {"ok": 1})
        # The whole point of the inline window: a request the UI makes
        # constantly must not add a row to the database the capture engine is
        # writing packets into.
        self.assertEqual(self._job_rows(), 0)

    def test_slow_call_is_deferred_and_collected_by_id(self):
        finished, job_id = self.queue.submit(
            "slow", lambda: time.sleep(0.4) or {"ok": 2}, inline_window=0.05
        )

        self.assertFalse(finished)
        self.assertEqual(self._job_rows(), 1)
        self.assertTrue(_wait_until(lambda: self.queue.get(job_id)["status"] == STATUS_DONE))
        self.assertEqual(self.queue.get(job_id)["result"], {"ok": 2})

    def test_finished_deferred_job_broadcasts_without_its_payload(self):
        _, job_id = self.queue.submit(
            "slow", lambda: time.sleep(0.3) or {"big": "x" * 1000}, inline_window=0.05
        )
        self.assertTrue(_wait_until(lambda: self.broadcasts))

        frame = self.broadcasts[-1]
        self.assertEqual(frame["type"], "job_update")
        self.assertEqual(frame["id"], job_id)
        self.assertEqual(frame["status"], STATUS_DONE)
        # The result is collected over HTTP: putting it on the frame would
        # hand a copy to every connected client.
        self.assertNotIn("result", frame)

    def test_inline_failure_reraises_the_original_exception(self):
        def boom():
            raise ValueError("limit is required")

        # app.py maps ValueError to a 400 with the message intact; wrapping it
        # in a queue-specific error would turn every validation guard in the
        # API into an opaque 500.
        with self.assertRaises(ValueError) as caught:
            self.queue.submit("boom", boom)
        self.assertEqual(str(caught.exception), "limit is required")

    def test_deferred_failure_records_message_and_type(self):
        def boom():
            time.sleep(0.3)
            raise KeyError("missing")

        _, job_id = self.queue.submit("boom", boom, inline_window=0.05)
        self.assertTrue(_wait_until(lambda: self.queue.get(job_id)["status"] == STATUS_ERROR))

        job = self.queue.get(job_id)
        self.assertEqual(job["error_type"], "KeyError")
        self.assertIn("missing", job["error"])

    def test_deferred_job_survives_a_restart(self):
        _, job_id = self.queue.submit(
            "slow", lambda: time.sleep(0.3) or {"ok": 3}, inline_window=0.05
        )
        self.assertTrue(_wait_until(lambda: self.queue.get(job_id)["status"] == STATUS_DONE))

        # A fresh queue on the same database has an empty registry, exactly
        # like the backend coming back up: SQLite is the only thing that can
        # still answer.
        restarted = JobQueue(store=self.store, broadcast=None, workers=1)
        self.addCleanup(restarted.shutdown)
        recovered = restarted.get(job_id)

        self.assertEqual(recovered["status"], STATUS_DONE)
        self.assertEqual(recovered["result"], {"ok": 3})

    def test_unknown_id_returns_none(self):
        self.assertIsNone(self.queue.get("does-not-exist"))
        self.assertIsNone(self.queue.get(""))

    def test_reaper_drops_expired_jobs_and_keeps_recent_ones(self):
        self.store.upsert_job({
            "id": "old", "kind": "k", "status": STATUS_DONE, "result": {"a": 1},
            "created_at": utc_since(7200), "finished_at": utc_since(7100),
        })
        self.store.upsert_job({
            "id": "recent", "kind": "k", "status": STATUS_DONE, "result": {"a": 2},
            "created_at": utc_now(), "finished_at": utc_now(),
        })

        self.queue.reap()

        self.assertIsNone(self.store.get_job("old"))
        self.assertIsNotNone(self.store.get_job("recent"))

    def test_a_slow_job_does_not_block_the_next_request(self):
        release = threading.Event()
        _, blocked_id = self.queue.submit("blocker", release.wait, inline_window=0.05)

        started = time.monotonic()
        finished, payload = self.queue.submit("fast", lambda: "through")

        self.assertTrue(finished)
        self.assertEqual(payload, "through")
        self.assertLess(time.monotonic() - started, 1.0)

        # Let the blocked worker finish and land its row inside the test, not
        # during teardown - a write that arrives after the store is closed
        # leaves SQLite side files behind and breaks the tmpdir cleanup.
        release.set()
        self.assertTrue(_wait_until(lambda: self.queue.get(blocked_id)["status"] == STATUS_DONE))


if __name__ == "__main__":
    unittest.main()
