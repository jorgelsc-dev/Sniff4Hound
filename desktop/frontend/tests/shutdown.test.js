import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import test from "node:test";
import { parse } from "@vue/compiler-sfc";
import appStore from "../src/state/appStore.js";

const require = createRequire(import.meta.url);
const { createShutdownController } = require("../../lib/shutdown.js");

function app(window, reject = false) {
  const calls = [];
  const store = {
    state: { shutdownPending: false },
    shutdownApplication(options) {
      calls.push(options);
      this.state.shutdownPending = true;
      return reject ? Promise.reject(new Error("connection closed")) : Promise.resolve({});
    },
  };
  const { descriptor } = parse(readFileSync(new URL("../src/App.vue", import.meta.url), "utf8"));
  const script = descriptor.script.content.replace(/^import .*;$/gm, "")
    .replace(/components: \{[\s\S]*?\},/, "components: {},")
    .replace("export default", "return");
  const definition = new Function("store", "window", "nextTick", script)(store, window, callback => callback());
  const vm = definition.data();
  for (const [key, method] of Object.entries(definition.methods)) vm[key] = method.bind(vm);
  for (const [key, computed] of Object.entries(definition.computed)) Object.defineProperty(vm, key, { get: computed.bind(vm) });
  return { vm, calls, definition };
}

test("shutdown starts cleanup immediately and closes after exactly three seconds, once", t => {
  t.mock.timers.enable({ apis: ["Date", "setTimeout"], now: 1000 });
  const calls = [];
  const controller = createShutdownController({ cleanup: () => calls.push("cleanup"), close: () => calls.push("close") });
  assert.equal(controller.isPending(), false);
  assert.deepEqual(controller.start(), { deadline: 4000 });
  assert.deepEqual(calls, ["cleanup"]);
  t.mock.timers.tick(1000);
  assert.deepEqual(controller.start(), { deadline: 4000 }, "another click cannot restart the countdown");
  t.mock.timers.tick(1999);
  assert.deepEqual(calls, ["cleanup"]);
  t.mock.timers.tick(1);
  assert.deepEqual(calls, ["cleanup", "close"]);
});

test("the stop button displays 3, 2, 1 without confirmation or an error alert", async t => {
  t.mock.timers.enable({ apis: ["Date", "setTimeout", "setInterval"], now: 1000 });
  let closes = 0;
  const window = { location: { href: "http://localhost/" }, confirm: () => assert.fail("no confirmation"), alert: () => assert.fail("no blocking alert"), close: () => { closes += 1; } };
  const { vm, calls, definition } = app(window, true);
  t.after(() => definition.beforeUnmount.call(vm));
  vm.shutdownApplication();
  vm.shutdownApplication();
  await Promise.resolve();
  assert.deepEqual(calls, [{ stopRuntime: true }]);
  assert.equal(vm.shutdownLabel, "Cerrando en 3...");
  t.mock.timers.tick(1000);
  assert.equal(vm.shutdownLabel, "Cerrando en 2...");
  t.mock.timers.tick(1000);
  assert.equal(vm.shutdownLabel, "Cerrando en 1...");
  assert.equal(closes, 0);
  t.mock.timers.tick(1000);
  assert.equal(closes, 1);
});

test("desktop shutdown immediately delegates owned-process cleanup to Electron", async t => {
  t.mock.timers.enable({ apis: ["Date", "setTimeout", "setInterval"], now: 1000 });
  let starts = 0;
  const window = { location: { href: "app://shell/" }, sniff4houndDesktop: {
    shutdown: () => { starts += 1; return Promise.resolve({ deadline: 4000 }); },
    close: () => assert.fail("Electron owns the scheduled close"),
  } };
  const { vm, calls, definition } = app(window);
  t.after(() => definition.beforeUnmount.call(vm));
  vm.shutdownApplication();
  await Promise.resolve();
  assert.equal(starts, 1);
  assert.deepEqual(calls, [{ stopRuntime: false }]);
  t.mock.timers.tick(3000);
});

test("closing a remote console never requests remote server shutdown", t => {
  t.mock.timers.enable({ apis: ["Date", "setTimeout", "setInterval"], now: 1000 });
  const { vm, calls, definition } = app({ location: { href: "http://localhost/?desktop_backend=remote" }, close() {} });
  t.after(() => definition.beforeUnmount.call(vm));
  vm.shutdownApplication();
  assert.deepEqual(calls, [{ stopRuntime: false }]);
});

test("client shutdown stops deferred-job polling and keeps reconnect disabled after a network error", async t => {
  const originalFetch = globalThis.fetch;
  let polls = 0;
  globalThis.fetch = async url => {
    if (String(url).includes("/api/app/shutdown")) throw new Error("connection closed");
    if (String(url).includes("/api/jobs/")) { polls += 1; return new Response(JSON.stringify({ status: "running" })); }
    return new Response(JSON.stringify({ job_id: "pending" }), { status: 201 });
  };
  t.after(() => { globalThis.fetch = originalFetch; appStore.state.shutdownPending = false; });
  const pending = appStore.fetchJsonPromise("/api/dashboard/");
  const rejected = assert.rejects(pending, { name: "AbortError" });
  while (!polls) await new Promise(resolve => setImmediate(resolve));
  await new Promise(resolve => setImmediate(resolve));
  await assert.rejects(appStore.shutdownApplication(), /connection closed/);
  await rejected;
  assert.equal(appStore.state.shutdownPending, true);
  assert.equal(appStore.state.pendingJobs, 0);
  assert.equal(polls, 1);
});

test("client shutdown closes every data feed and prevents it from reconnecting", async t => {
  const originalWindow = globalThis.window;
  const originalEventSource = globalThis.EventSource;
  const sources = [];
  globalThis.window = { location: { origin: "http://localhost" } };
  globalThis.EventSource = class {
    constructor() { sources.push(this); this.closed = false; }
    addEventListener() {}
    close() { this.closed = true; }
  };
  const feeds = [appStore.openDataFeed("sniffer", {}, () => {}), appStore.openDataFeed("honeypot", {}, () => {})];
  t.after(() => {
    feeds.forEach(feed => feed.close());
    globalThis.window = originalWindow;
    globalThis.EventSource = originalEventSource;
    appStore.state.shutdownPending = false;
  });
  await appStore.shutdownApplication({ stopRuntime: false });
  assert.equal(sources.length, 2);
  assert.ok(sources.every(source => source.closed));
  assert.equal(feeds[0].update({ limit: 1 }), false);
  assert.equal(appStore.openDataFeed("sniffer", {}, () => {}).ok, false);
  assert.equal(sources.length, 2);
});

test("API activity cannot restart during the countdown", async t => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = () => assert.fail("no new network activity after shutdown starts");
  t.after(() => { globalThis.fetch = originalFetch; appStore.state.shutdownPending = false; });
  await appStore.shutdownApplication({ stopRuntime: false });
  await assert.rejects(appStore.fetchJsonPromise("/api/dashboard/"), { name: "AbortError" });
  assert.equal(appStore.state.tasks.length, 0);
});
