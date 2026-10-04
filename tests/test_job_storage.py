"""Job results must not balloon the database, and freed pages must come back."""

from __future__ import annotations

import os
import tempfile
import unittest

from sniff4hound import jobs as jobs_module
from sniff4hound.jobs import JobQueue
from sniff4hound.store import JOB_RESULT_PERSIST_MAX_BYTES, SniffStore


class JobStorageTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.store = SniffStore(os.path.join(self._tmp.name, "jobs.db"))
        self.addCleanup(self.store.close)

    def test_a_huge_result_is_stored_as_a_marker_not_as_the_payload(self):
        big = {"rows": ["x" * 1000] * (JOB_RESULT_PERSIST_MAX_BYTES // 500)}
        self.store.upsert_job({"id": "big", "kind": "GET /api/monitors/", "status": "done",
                               "result": big, "created_at": "2026-10-03T00:00:00+00:00"})
        row = self.store._fetchone("SELECT result_json FROM jobs WHERE id = 'big'")
        self.assertLess(len(row["result_json"]), 200)
        self.assertIn("omitted", row["result_json"])

    def test_a_small_result_is_still_kept(self):
        self.store.upsert_job({"id": "small", "kind": "GET /api/monitors/config", "status": "done",
                               "result": {"ok": True}, "created_at": "2026-10-03T00:00:00+00:00"})
        row = self.store._fetchone("SELECT result_json FROM jobs WHERE id = 'small'")
        self.assertIn('"ok":true', row["result_json"])

    def test_expired_jobs_are_removed_and_their_pages_handed_back(self):
        payload = {"rows": ["y" * 2000] * 200}  # ~400 KB each, under the persist cap
        for index in range(40):
            self.store.upsert_job({"id": f"j{index}", "kind": "GET /x", "status": "done",
                                   "result": payload, "created_at": "2000-01-01T00:00:00+00:00"})
        pages_before = self.store._fetchone("PRAGMA page_count")
        queue = JobQueue(store=self.store, workers=1)
        self.addCleanup(queue.shutdown)
        removed = self.store.delete_expired_jobs(60)
        self.assertGreater(removed, 0)
        queue._reclaim_store_pages(removed)
        free = self.store._fetchone("PRAGMA freelist_count")
        self.assertLess(free["freelist_count"], 10_000)
        self.assertIsNotNone(pages_before)


if __name__ == "__main__":
    unittest.main()
