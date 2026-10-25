from __future__ import annotations

import tempfile
import threading
import time
import unittest
import weakref
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

    def test_a_job_running_across_a_restart_is_reported_interrupted(self):
        release = threading.Event()
        self.addCleanup(release.set)
        _, done_id = self.queue.submit(
            "slow", lambda: time.sleep(0.1) or {"ok": 4}, inline_window=0.01
        )
        self.assertTrue(_wait_until(lambda: self.queue.get(done_id)["status"] == STATUS_DONE))
        _, running_id = self.queue.submit("stuck", release.wait, inline_window=0.01)
        self.assertEqual(self.store.get_job(running_id)["status"], "running")
        self.store.upsert_job({"id": "never-started", "kind": "k", "status": "queued"})

        # The backend comes back up: a fresh queue on the same database.
        restarted = JobQueue(store=self.store, broadcast=None, workers=1)
        self.addCleanup(restarted.shutdown)

        interrupted = restarted.get(running_id)
        self.assertEqual(interrupted["status"], STATUS_ERROR)
        self.assertEqual(interrupted["error_type"], "Interrupted")
        self.assertTrue(interrupted["finished_at"])
        self.assertEqual(restarted.get("never-started")["error_type"], "Interrupted")
        finished = restarted.get(done_id)
        self.assertEqual(finished["status"], STATUS_DONE)
        self.assertEqual(finished["result"], {"ok": 4})
        self.assertEqual(finished["error_type"], "")

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


class JobTimeoutTests(unittest.TestCase):
    def test_wedged_job_is_answered_as_an_error_and_the_queue_keeps_moving(self):
        import time as _time
        from unittest.mock import patch as _patch

        from sniff4hound import jobs as jobs_module

        release = threading.Event()
        queue = JobQueue(workers=1, timeout=0.2)
        self.addCleanup(queue.shutdown)
        self.addCleanup(release.set)

        def wedged():
            release.wait(timeout=5)
            return "late"

        with _patch.object(jobs_module, "WATCHDOG_INTERVAL_SECONDS", 0.05):
            done, job_id = queue.submit("wedged", wedged, inline_window=0)
            self.assertFalse(done)
            deadline = _time.monotonic() + 3
            snapshot = queue.get(job_id)
            while snapshot["status"] != "error" and _time.monotonic() < deadline:
                _time.sleep(0.05)
                snapshot = queue.get(job_id)
            self.assertEqual(snapshot["status"], "error")
            self.assertEqual(snapshot["error_type"], "TimeoutError")

            # The single worker is still inside the wedged handler; the
            # watchdog must have replaced it, or this would never run.
            done, value = queue.submit("quick", lambda: "ok", inline_window=2.0)
            self.assertTrue(done)
            self.assertEqual(value, "ok")
        release.set()


class ReadJobsNeverPersistTests(unittest.TestCase):
    def test_slow_read_answers_on_the_request_and_writes_no_job_row(self):
        queue = JobQueue(workers=1, timeout=5)
        self.addCleanup(queue.shutdown)
        writes = []
        queue._persist = lambda job: writes.append(job.id)

        def slow_read():
            time.sleep(0.5)  # well past the 0.2 s inline window
            return {"ok": True}

        finished, payload = queue.submit("GET /api/example", slow_read, persist=False)
        self.assertTrue(finished)
        self.assertEqual(payload, {"ok": True})
        self.assertEqual(writes, [])

    def test_slow_write_still_persists_and_returns_a_job_id(self):
        queue = JobQueue(workers=1, timeout=5)
        self.addCleanup(queue.shutdown)
        writes = []
        queue._persist = lambda job: writes.append(job.id)

        finished, job_id = queue.submit("POST /api/example", lambda: time.sleep(0.5) or {"ok": True})
        self.assertFalse(finished)
        self.assertEqual(writes, [job_id])


class ReadTimeoutSupervisionTests(unittest.TestCase):
    def setUp(self):
        self.queue = JobQueue(workers=1, timeout=0.08)
        self.releases = []
        self.addCleanup(self._cleanup)
        self.writes = []
        self.queue._persist = lambda job: self.writes.append(job.id)

    def _cleanup(self):
        for release in self.releases:
            release.set()
        self.queue.shutdown()

    def _blocked_read(self):
        release = threading.Event()
        self.releases.append(release)
        entered = threading.Event()

        def blocked():
            entered.set()
            release.wait(timeout=5)
            return "late"

        with self.assertRaises(TimeoutError):
            self.queue.submit("blocked read", blocked, persist=False)
        self.assertTrue(entered.is_set())
        return release

    def test_repeated_read_timeouts_recover_and_retire_only_the_replaced_worker(self):
        for _ in range(3):
            release = self._blocked_read()
            self.queue._abandon_overdue()
            with self.queue._lock:
                job = next(iter(self.queue._running.values()))
                self.assertEqual(self.queue._jobs, {})
                self.assertTrue(job.abandoned)
            # Several healthy completions must not consume the retirement
            # owed by the still-blocked worker.
            for _ in range(3):
                self.assertEqual(self.queue.submit("fast read", lambda: "ok", persist=False), (True, "ok"))
            release.set()
            self.assertTrue(_wait_until(lambda: len(self.queue._threads) == 1))
            self.assertIsNone(job.result)
            self.assertIsInstance(job.exception, TimeoutError)
            self.assertEqual(self.queue._surplus, 0)
        self.assertEqual(self.writes, [])
        self.assertTrue(_wait_until(lambda: not self.queue._running))
        self.queue.shutdown()
        self.assertEqual(self.queue._threads, [])
        self.assertFalse(self.queue._watchdog.is_alive())
        self.assertFalse(self.queue._reaper.is_alive())
        self.assertEqual(self.queue._queue.unfinished_tasks, 0)

    def test_stuck_handlers_have_a_bounded_replacement_budget(self):
        self._blocked_read()
        self._blocked_read()
        self.assertEqual(len(self.queue._threads), 2)
        for _ in range(3):
            self.queue._abandon_overdue()
        self.assertEqual(len(self.queue._threads), 2)
        queued_ran = threading.Event()
        with self.assertRaises(TimeoutError):
            self.queue.submit("expired before execution", queued_ran.set, persist=False)
        self.assertFalse(queued_ran.is_set())
        self.assertTrue(self.queue._queue.empty(), "expired reads retained queued handlers")
        handler = lambda: "must be released"
        reference = weakref.ref(handler)
        with self.assertRaises(TimeoutError):
            self.queue.submit("cancelled closure", handler, persist=False)
        del handler
        self.assertIsNone(reference(), "expired read retained its handler closure")
        self.releases[0].set()
        self.assertTrue(_wait_until(lambda: self.queue._surplus == 0))
        self.releases[1].set()
        self.assertTrue(_wait_until(lambda: self.queue._queue.unfinished_tasks == 0))
        self.assertFalse(queued_ran.is_set(), "an expired queued handler ran later")
        self.assertEqual(self.queue.submit("recovered", lambda: "ok", persist=False), (True, "ok"))
        self.assertEqual(self.writes, [])

    def test_shutdown_with_stuck_read_is_bounded_and_retires_after_release(self):
        release = self._blocked_read()
        started = time.monotonic()
        self.queue.shutdown(timeout=0.05)
        self.assertLess(time.monotonic() - started, 0.5)
        with self.assertRaises(RuntimeError):
            self.queue.submit("after shutdown", lambda: "no")
        release.set()
        self.assertTrue(_wait_until(lambda: not self.queue._threads))
        self.assertEqual(self.queue._running, {})
        self.assertEqual(self.queue._jobs, {})
        self.assertEqual(self.queue._queue.unfinished_tasks, 0)
        self.assertEqual(self.writes, [])
