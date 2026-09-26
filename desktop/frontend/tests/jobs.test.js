import assert from "node:assert/strict";
import test from "node:test";
import appStore from "../src/state/appStore.js";

// The queue contract lives in httpFetchWithMeta: a 200 is the answer, a 201
// carrying a job_id means "collect this from /api/jobs/". Callers see neither -
// they always get a promise of the payload - so these drive the real store
// through a stubbed fetch rather than testing a seam that does not exist.
function withFetch(handler, run) {
  const originalFetch = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, options = {}) => {
    calls.push(String(url));
    return handler(String(url), options, calls.length);
  };
  return run(calls).finally(() => {
    globalThis.fetch = originalFetch;
    appStore.state.pendingJobs = 0;
  });
}

const json = (body, status = 200) => new Response(JSON.stringify(body), { status });

test("a 200 is returned as-is and never creates a job", () => withFetch(
  () => json({ value: 42 }),
  async (calls) => {
    const data = await appStore.fetchJsonPromise("/api/dashboard/");
    assert.deepEqual(data, { value: 42 });
    assert.equal(calls.length, 1);
    assert.equal(appStore.state.pendingJobs, 0);
  },
));

test("a 201 is collected from the job route and resolves to the result", () => withFetch(
  (url) => {
    if (url.includes("/api/jobs/")) {
      return json({ id: "j1", status: "done", result: { rows: [1, 2] } });
    }
    return json({ status: "queued", job_id: "j1" }, 201);
  },
  async (calls) => {
    const data = await appStore.fetchJsonPromise("/api/soc/analysis/");
    assert.deepEqual(data, { rows: [1, 2] });
    assert.ok(calls[1].includes("id=j1"));
    // The counter has to come back down, or the loading indicator sticks.
    assert.equal(appStore.state.pendingJobs, 0);
  },
));

test("a job keeps being polled while it is still running", () => withFetch(
  (url, _options, call) => {
    if (!url.includes("/api/jobs/")) return json({ job_id: "j2" }, 201);
    if (call < 4) return json({ id: "j2", status: "running" });
    return json({ id: "j2", status: "done", result: "listo" });
  },
  async (calls) => {
    const data = await appStore.fetchJsonPromise("/api/ai/packets/");
    assert.equal(data, "listo");
    assert.ok(calls.length >= 4);
  },
));

test("a failed job rejects with the server's message and type", () => withFetch(
  (url) => {
    if (url.includes("/api/jobs/")) {
      return json({ id: "j3", status: "error", error: "limit is required", error_type: "ValueError" });
    }
    return json({ job_id: "j3" }, 201);
  },
  async () => {
    await assert.rejects(
      appStore.fetchJsonPromise("/api/map/scan"),
      (err) => err.message === "limit is required" && err.code === "ValueError",
    );
    // A rejection must release the counter too, not just a success.
    assert.equal(appStore.state.pendingJobs, 0);
  },
));

// Covers the polling path only: with no websocket frame in play both waiters
// fall back to their own timers, so this does not exercise the wake-up that
// the Set-of-records registry fixes. It is here to pin the concurrent case -
// two callers parked on one id must both receive the result.
test("two callers waiting on the same job id both resolve", () => withFetch(
  (url, _options, call) => {
    if (!url.includes("/api/jobs/")) return json({ job_id: "shared" }, 201);
    if (call <= 4) return json({ id: "shared", status: "running" });
    return json({ id: "shared", status: "done", result: "ambos" });
  },
  async () => {
    const [first, second] = await Promise.all([
      appStore.fetchJsonPromise("/api/soc/analysis/"),
      appStore.fetchJsonPromise("/api/soc/analysis/"),
    ]);
    assert.equal(first, "ambos");
    assert.equal(second, "ambos");
    assert.equal(appStore.state.pendingJobs, 0);
  },
));

test("pendingJobs rises while a job is outstanding", () => withFetch(
  (url, _options, call) => {
    if (!url.includes("/api/jobs/")) return json({ job_id: "j4" }, 201);
    if (call < 3) {
      assert.equal(appStore.state.pendingJobs, 1);
      return json({ id: "j4", status: "queued" });
    }
    return json({ id: "j4", status: "done", result: null });
  },
  async () => {
    await appStore.fetchJsonPromise("/api/intel/ips/graph");
    assert.equal(appStore.state.pendingJobs, 0);
  },
));
