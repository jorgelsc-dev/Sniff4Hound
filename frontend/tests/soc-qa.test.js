import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { parse } from "@vue/compiler-sfc";
import appStore from "../src/state/appStore.js";
import { rowsToCsv } from "../src/utils/exporters.js";

// Exercise the actual Options API methods/computed properties. Rendering and
// navigation are verified separately in the browser against the built SPA.
function view(name, store) {
  const { descriptor } = parse(readFileSync(new URL(`../src/views/${name}.vue`, import.meta.url), "utf8"));
  const script = descriptor.script.content
    .replace(/^import .*;$/gm, "")
    .replace(/components: \{[\s\S]*?\},/, "components: {},")
    .replace("export default", "return");
  const definition = new Function("store", "formatTimestamp", "buildExportFilename", "downloadTextFile", script)(store, String, () => "test.json", () => {});
  const vm = definition.data();
  for (const [key, method] of Object.entries(definition.methods)) vm[key] = method.bind(vm);
  for (const [key, computed] of Object.entries(definition.computed)) {
    Object.defineProperty(vm, key, typeof computed === "function"
      ? { get: computed.bind(vm) }
      : { get: computed.get.bind(vm), set: computed.set?.bind(vm) });
  }
  return { vm, definition };
}

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}

function memoryStorage(seed = {}) {
  const values = new Map(Object.entries(seed));
  return {
    getItem: (key) => values.get(String(key)) ?? null,
    setItem: (key, value) => { values.set(String(key), String(value)); },
    removeItem: (key) => { values.delete(String(key)); },
    clear: () => { values.clear(); },
  };
}

const evidence = (packets = 1) => ({ soc_summary: { sampled_packets: packets, risk_score: 8, verdict: "observe" }, cycles: [], generated_at: "2026-09-05T10:00:00Z" });

test("CSV neutralizes remote formulas, retains quoting and numeric values", () => {
  const values = ["=1+1", "+SUM(A1)", "-1+2", "@SUM(A1)", "  =1", "\ttext", -5, 'a,b"c\nd'];
  const csv = rowsToCsv(values.map(value => ({ value })), [{ key: "value", label: "Evidence" }]);
  assert.equal(csv, 'Evidence\r\n\'=1+1\r\n\'+SUM(A1)\r\n\'-1+2\r\n\'@SUM(A1)\r\n\'  =1\r\n\'\ttext\r\n-5\r\n"a,b""c\nd"');
  assert.equal(values[0], "=1+1");
});

test("replaced and closed streams cannot deliver stale frames or fallback", () => {
  const original = globalThis.window;
  const sockets = [];
  class Socket {
    static OPEN = 1;
    constructor() { this.events = {}; this.readyState = 1; sockets.push(this); }
    addEventListener(name, callback) { this.events[name] = callback; }
    close() { this.readyState = 3; this.emit("close"); }
    emit(name, payload = {}) { this.events[name]?.({ data: JSON.stringify(payload) }); }
  }
  globalThis.window = { WebSocket: Socket, location: { origin: "http://localhost" } };
  let fallbacks = 0;
  const received = [];
  const handle = appStore.openDataFeed("soc", { since: "15m" }, value => received.push(value), () => { fallbacks += 1; });
  try {
    const old = sockets[0];
    handle.update({ since: "1h" });
    old.emit("message", { type: "feed_data", data: "old" });
    old.emit("error");
    old.emit("close");
    const current = sockets[1];
    current.emit("message", { type: "feed_data", data: "current" });
    assert.deepEqual(received.map(value => value.data), ["current"]);
    assert.equal(fallbacks, 0);
    handle.close();
    current.emit("message", { type: "feed_data", data: "after close" });
    assert.equal(received.length, 1);
  } finally {
    handle.close();
    globalThis.window = original;
  }
});

test("legacy localStorage security code is not re-persisted to sessionStorage", async () => {
  const originalWindow = globalThis.window;
  const originalFetch = globalThis.fetch;
  const legacyToken = "legacy-secret";
  const localStorage = memoryStorage({ "sniff4hound.securityCode": legacyToken });
  const sessionStorage = memoryStorage();
  globalThis.window = {
    localStorage,
    sessionStorage,
    location: {
      href: "http://localhost/",
      origin: "http://localhost",
      protocol: "http:",
      hostname: "localhost",
      port: "",
    },
    history: { replaceState() {} },
  };
  globalThis.fetch = async (url, options = {}) => {
    const path = String(url);
    if (path.endsWith("/api/auth/session")) {
      assert.equal(options.headers["X-Security-Code"], legacyToken);
      return new Response(JSON.stringify({ require_auth: true, authenticated: true }), { status: 200 });
    }
    if (path.endsWith("/api/runtime/")) {
      return new Response(JSON.stringify({ runtime: { mode: "sniffer" } }), { status: 200 });
    }
    return new Response(JSON.stringify({}), { status: 200 });
  };

  try {
    await appStore.bootstrap();
    assert.equal(appStore.state.authToken, legacyToken);
    assert.equal(localStorage.getItem("sniff4hound.securityCode"), null);
    assert.equal(sessionStorage.getItem("sniff4hound.securityCode"), null);
  } finally {
    appStore.signOut();
    appStore.state.authStatus = "unknown";
    appStore.state.authRequired = false;
    appStore.state.authReady = false;
    appStore.state.authPromptOpen = false;
    globalThis.window = originalWindow;
    globalThis.fetch = originalFetch;
  }
});

test("startup URL security code stays in memory only", async () => {
  const originalWindow = globalThis.window;
  const originalFetch = globalThis.fetch;
  const localStorage = memoryStorage();
  const sessionStorage = memoryStorage();
  let cleanedUrl = "";
  globalThis.window = {
    localStorage,
    sessionStorage,
    location: {
      href: "http://localhost/?code=url-secret",
      origin: "http://localhost",
      protocol: "http:",
      hostname: "localhost",
      port: "",
    },
    history: { replaceState(_state, _title, url) { cleanedUrl = url; } },
  };
  globalThis.fetch = async (url, options = {}) => {
    const path = String(url);
    if (path.endsWith("/api/auth/session")) {
      assert.equal(options.headers["X-Security-Code"], "url-secret");
      return new Response(JSON.stringify({ require_auth: true, authenticated: true }), { status: 200 });
    }
    if (path.endsWith("/api/runtime/")) {
      return new Response(JSON.stringify({ runtime: { mode: "sniffer" } }), { status: 200 });
    }
    return new Response(JSON.stringify({}), { status: 200 });
  };

  try {
    await appStore.bootstrap();
    assert.equal(appStore.state.authToken, "url-secret");
    assert.equal(cleanedUrl, "/");
    assert.equal(localStorage.getItem("sniff4hound.securityCode"), null);
    assert.equal(sessionStorage.getItem("sniff4hound.securityCode"), null);
  } finally {
    appStore.signOut();
    appStore.state.authStatus = "unknown";
    appStore.state.authRequired = false;
    appStore.state.authReady = false;
    appStore.state.authPromptOpen = false;
    globalThis.window = originalWindow;
    globalThis.fetch = originalFetch;
  }
});

test("empty SOC never implies observation is sufficient", () => {
  const { vm } = view("SocView", { state: {} });
  vm.analysis = evidence(0);
  assert.equal(vm.hasEvidence, false);
  assert.equal(vm.riskLabel, "Not assessed");
  assert.equal(vm.verdictLabel, "insufficient-evidence");
  assert.match(vm.verdictTitle, /Insufficient evidence/);
});

test("SOC pause survives changing depth and time range", async () => {
  let sockets = 0;
  let requests = 0;
  const store = {
    state: { timeRange: "15m" },
    openDataFeed: () => { sockets += 1; return { close() {} }; },
    buildListQuery: () => "?since=15m",
    fetchJsonPromise: async () => { requests += 1; return evidence(); },
  };
  const { vm, definition } = view("SocView", store);
  vm.liveRefreshEnabled = false;
  definition.watch.cyclesRequested.call(vm);
  await Promise.resolve();
  definition.watch.timeRange.call(vm);
  await Promise.resolve();
  assert.equal(sockets, 0);
  assert.equal(requests, 2);
  assert.equal(vm.liveRefreshEnabled, false);
});

test("SOC rejects an old HTTP response after filter reconfiguration", async () => {
  const pending = deferred();
  const store = { state: { timeRange: "1h" }, buildListQuery: () => "", fetchJsonPromise: () => pending.promise };
  const { vm } = view("SocView", store);
  const request = vm.load();
  vm.closeFeed();
  pending.resolve(evidence(99));
  await request;
  assert.equal(vm.hasEvidence, false);
});

test("SOC critical findings precede high severity", () => {
  const { vm } = view("SocView", { state: {} });
  vm.analysis = { findings: [{ id: "high", cycle: 1, severity: "high" }, { id: "critical", cycle: 1, severity: "critical" }] };
  assert.equal(vm.findingsForCycle(1)[0].id, "critical");
  assert.equal(vm.severityColor("critical"), "error");
});

test("Investigate only applies the latest host result", async () => {
  const old = deferred();
  const recent = deferred();
  const store = { state: {}, fetchJsonPromise: path => path.includes("intel") ? (path.includes("10.0.0.1") ? old.promise : recent.promise) : Promise.resolve({}) };
  const { vm } = view("InvestigateView", store);
  vm.queryIp = "10.0.0.1";
  const first = vm.load();
  vm.queryIp = "10.0.0.2";
  const second = vm.load();
  recent.resolve({ host: "new" });
  await second;
  old.resolve({ host: "old" });
  await first;
  assert.equal(vm.intel.host, "new");
  assert.equal(vm.loading, false);
});

test("typing another target clears previous evidence and invalidates pending results", async () => {
  const pending = deferred();
  const { vm } = view("InvestigateView", { fetchJsonPromise: () => pending.promise });
  vm.queryIp = "10.0.0.1";
  const request = vm.load();
  vm.targetInput = "10.0.0.2";
  pending.resolve({ host: "old" });
  await request;
  assert.deepEqual(vm.intel, {});
  assert.equal(vm.lastUpdated, "");
});

test("domain deep links do not load or replace the target with seed hosts", () => {
  const { vm, definition } = view("InvestigateView", { state: {} });
  vm.queryDomain = "example.test";
  let seeds = 0;
  vm.loadSeed = () => { seeds += 1; };
  definition.mounted.call(vm);
  assert.equal(seeds, 0);
});

test("late host suggestions cannot overwrite a manually selected target", async () => {
  const pending = deferred();
  const { vm } = view("InvestigateView", { fetchJsonPromise: () => pending.promise });
  const request = vm.loadSeed();
  vm.targetInput = "10.0.0.2";
  pending.resolve({ top_ips_by_open_ports: [{ ip: "10.0.0.1" }] });
  await request;
  assert.equal(vm.queryIp, "10.0.0.2");
  assert.deepEqual(vm.analytics, {});
});

test("SOC evidence tables bind existing computed rows", () => {
  const source = readFileSync(new URL("../src/views/SocView.vue", import.meta.url), "utf8");
  const { vm } = view("SocView", { state: {} });
  vm.analysis = {
    top_hosts: [{ ip: "8.8.8.8" }],
    top_conversations: [{ label: "test flow" }],
    top_ports: [{ port: 443 }],
  };
  for (const [title, property] of [["Top Hosts", "hostRows"], ["Top Conversations", "conversationRows"], ["Top Ports", "portRows"]]) {
    const binding = source.match(new RegExp(`title="${title}"[\\s\\S]*?:rows="([^"]+)"`));
    assert.equal(binding?.[1], property);
    assert.equal(vm[binding[1]].length, 1);
  }
});
