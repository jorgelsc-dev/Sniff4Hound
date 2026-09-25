"""Background job queue for API requests.

Every queued API call goes through `JobQueue.submit()`. The queue answers in
one of two ways:

* **inline** - the handler finished inside `INLINE_WINDOW_SECONDS`, so the
  caller gets the result on the original request and no row is ever written.
  This is the common case: most routes here answer a cached snapshot or a
  small indexed SELECT in single-digit milliseconds, and making those pay an
  INSERT plus a second round-trip would be a straight downgrade - on the same
  SQLite file the capture engine is writing packets into, where extra writers
  serialise against packet storage.
* **deferred** - the handler is still running when that window closes, so the
  job is persisted and the caller gets `201 Created` with its id, then polls
  `GET /api/jobs/<id>` (and/or waits for the `job_update` websocket frame).

Results stay in an in-memory registry regardless, so a poll that arrives
before the row is committed still sees the finished job. SQLite is what makes
a deferred job survive a backend restart.
"""

from __future__ import annotations

import queue
import threading
import time
import traceback
import uuid
from typing import Any, Callable

from .utils import utc_now, utc_since

# How long the original request waits before giving up and handing back an id.
# Long enough to absorb an ordinary query, short enough that a caller stuck
# behind a slow one is not left hanging.
INLINE_WINDOW_SECONDS = 0.2

# Worker threads. The work is SQLite reads and Python analysis, so this is
# about keeping one slow request from blocking the next, not about throughput.
DEFAULT_WORKERS = 4

# A deferred job older than this is dropped by the reaper, results included.
JOB_TTL_SECONDS = 1800
REAP_INTERVAL_SECONDS = 300

STATUS_QUEUED = "queued"
STATUS_RUNNING = "running"
STATUS_DONE = "done"
STATUS_ERROR = "error"


class Job:
    __slots__ = (
        "id", "kind", "status", "result", "error", "error_type", "exception",
        "created_at", "finished_at", "done", "persisted", "lock",
    )

    def __init__(self, job_id: str, kind: str):
        self.id = job_id
        self.kind = kind
        self.status = STATUS_QUEUED
        self.result: Any = None
        self.error = ""
        self.error_type = ""
        # Kept so the inline path can re-raise the original and reuse app.py's
        # existing exception-to-status mapping (ValueError -> 400, _NotFound ->
        # 404) instead of flattening every failure into one generic error.
        self.exception: BaseException | None = None
        self.created_at = utc_now()
        self.finished_at = ""
        self.done = threading.Event()
        # Set once the submitting request has given up waiting; the worker
        # reads it to decide whether this job needs to reach SQLite at all.
        self.persisted = False
        self.lock = threading.Lock()

    def snapshot(self) -> dict:
        return {
            "id": self.id,
            "kind": self.kind,
            "status": self.status,
            "result": self.result,
            "error": self.error,
            "error_type": self.error_type,
            "created_at": self.created_at,
            "finished_at": self.finished_at,
        }


class JobQueue:
    def __init__(self, store=None, broadcast: Callable[[dict], None] | None = None,
                 workers: int = DEFAULT_WORKERS):
        self._store = store
        self._broadcast = broadcast
        self._queue: queue.Queue = queue.Queue()
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()
        self._threads = []
        self._stopping = threading.Event()
        for index in range(max(1, int(workers))):
            thread = threading.Thread(
                target=self._worker, name=f"sniff4hound-job-{index}", daemon=True
            )
            thread.start()
            self._threads.append(thread)
        self._reaper = threading.Thread(
            target=self._reap_loop, name="sniff4hound-job-reaper", daemon=True
        )
        self._reaper.start()

    # -- submission ---------------------------------------------------------

    def submit(self, kind: str, fn: Callable[[], Any], *,
               inline_window: float = INLINE_WINDOW_SECONDS):
        """Runs `fn` on a worker.

        Returns `(True, result)` when it finished inside the inline window, or
        `(False, job_id)` when the caller has to come back for it.
        """
        job = Job(uuid.uuid4().hex, kind)
        with self._lock:
            self._jobs[job.id] = job
        self._queue.put((job, fn))

        if job.done.wait(timeout=max(0.0, float(inline_window))):
            # Finished in time: hand the answer back on this request and drop
            # the record - nothing will ever poll for it.
            with self._lock:
                self._jobs.pop(job.id, None)
            if job.exception is not None:
                raise job.exception
            return True, job.result

        # Out of time. Claim the job for polling before the worker can decide
        # it has nobody waiting, so the two can never both skip the write.
        with job.lock:
            if job.done.is_set():
                with self._lock:
                    self._jobs.pop(job.id, None)
                if job.exception is not None:
                    raise job.exception
                return True, job.result
            job.persisted = True
        self._persist(job)
        return False, job.id

    # -- retrieval ----------------------------------------------------------

    def get(self, job_id: str) -> dict | None:
        key = str(job_id or "").strip()
        if not key:
            return None
        with self._lock:
            job = self._jobs.get(key)
        if job is not None:
            return job.snapshot()
        # Not in memory: either this backend restarted, or the reaper already
        # dropped it. SQLite is the only place left that might know.
        if self._store is None:
            return None
        return self._store.get_job(key)

    # -- internals ----------------------------------------------------------

    def _worker(self):
        while not self._stopping.is_set():
            item = self._queue.get()
            if item is None:
                self._queue.task_done()
                return
            job, fn = item
            job.status = STATUS_RUNNING
            try:
                result = fn()
                job.result = result
                job.status = STATUS_DONE
            except Exception as exc:  # noqa: BLE001 - reported to the caller
                # No traceback here on purpose. Most of what lands in this
                # branch is a handler's own `raise ValueError("<param> is
                # required")`, which app.py maps to a clean 400 - printing a
                # stack trace for every one of those would bury real faults in
                # routine client mistakes. The error travels on the job either
                # way, and the inline path re-raises the original.
                job.exception = exc
                job.error = str(exc) or type(exc).__name__
                job.error_type = type(exc).__name__
                job.status = STATUS_ERROR
            finally:
                job.finished_at = utc_now()
                with job.lock:
                    needs_write = job.persisted
                    job.done.set()
                if needs_write:
                    self._finish(job)
                self._queue.task_done()

    def _persist(self, job: Job):
        if self._store is None:
            return
        try:
            self._store.upsert_job(job.snapshot())
        except Exception:  # noqa: BLE001 - the in-memory copy still answers
            traceback.print_exc()

    def _finish(self, job: Job):
        self._persist(job)
        if self._broadcast is None:
            return
        try:
            # Deliberately without the payload: a result can be megabytes of
            # snapshot, and every connected client would get a copy. The frame
            # is a nudge to stop waiting for the next poll interval.
            self._broadcast({
                "type": "job_update",
                "id": job.id,
                "kind": job.kind,
                "status": job.status,
                "generated_at": utc_now(),
            })
        except Exception:  # noqa: BLE001 - a dead socket must not fail the job
            traceback.print_exc()

    def reap(self):
        """Drops finished jobs the caller never came back for."""
        if self._store is not None:
            try:
                self._store.delete_expired_jobs(JOB_TTL_SECONDS)
            except Exception:  # noqa: BLE001
                traceback.print_exc()
        # A job whose submitter stopped waiting is also still pinned in the
        # registry; the row is durable, so dropping the copy is safe.
        cutoff = utc_since(JOB_TTL_SECONDS)
        with self._lock:
            for job_id, job in list(self._jobs.items()):
                if job.done.is_set() and job.created_at < cutoff:
                    self._jobs.pop(job_id, None)

    def _reap_loop(self):
        while not self._stopping.wait(REAP_INTERVAL_SECONDS):
            self.reap()

    def shutdown(self, timeout: float = 2.0):
        """Stops the workers and waits briefly for in-flight jobs to settle.

        The wait matters: a worker that finishes after the store is closed
        tries to write its result into a dead connection. That is caught, but
        it also leaves SQLite side files behind, so the orderly path is to give
        the work a moment to land first. Bounded, because shutdown must not
        hang on a job that is genuinely stuck.
        """
        self._stopping.set()
        for _ in self._threads:
            self._queue.put(None)
        deadline = time.monotonic() + max(0.0, float(timeout))
        for thread in self._threads:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            thread.join(timeout=remaining)
