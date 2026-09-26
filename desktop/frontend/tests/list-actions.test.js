import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { parse } from "@vue/compiler-sfc";

// Same approach as soc-qa.test.js: evaluate the SFC's own Options API script
// against a stub store, so these exercise the real methods rather than a copy.
function component(path, store) {
  const { descriptor } = parse(readFileSync(new URL(path, import.meta.url), "utf8"));
  const script = descriptor.script.content
    .replace(/^import .*;$/gm, "")
    .replace("export default", "return");
  const definition = new Function("store", script)(store);
  const vm = { ...definition.data(), $emit: () => {} };
  for (const [key, method] of Object.entries(definition.methods)) vm[key] = method.bind(vm);
  for (const [key, computed] of Object.entries(definition.computed || {})) {
    Object.defineProperty(vm, key, { get: computed.bind(vm) });
  }
  return vm;
}

function stubStore() {
  const calls = [];
  const record = name => (payload) => {
    calls.push({ name, payload });
    return Promise.resolve({});
  };
  return {
    calls,
    createWhitelistEntry: record("createWhitelistEntry"),
    createBlacklistEntry: record("createBlacklistEntry"),
    whitelistIpAndForget: record("whitelistIpAndForget"),
    pushNotification: record("pushNotification"),
  };
}

function icons(store, props = {}) {
  const vm = component("../src/components/ui/ListActionIcons.vue", store);
  return Object.assign(vm, { value: "10.0.0.5", category: "ip", ...props });
}

test("whitelisting never uses the history-purging variant", async () => {
  const store = stubStore();
  const vm = icons(store);

  await vm.run("whitelist");

  // whitelistIpAndForget irreversibly deletes that host's stored packets. This
  // control sits on every table row, so reaching it by one click would make a
  // misclick destructive.
  assert.deepEqual(store.calls.map(call => call.name), ["createWhitelistEntry"]);
});

test("entries are exact matches carrying the right category", async () => {
  const store = stubStore();
  const vm = icons(store, { value: "example.com", category: "domain" });

  await vm.run("blacklist");

  const { name, payload } = store.calls[0];
  assert.equal(name, "createBlacklistEntry");
  assert.equal(payload.category, "domain");
  assert.equal(payload.matchType, "exact");
  assert.equal(payload.value, "example.com");
  assert.match(payload.label, /Blocked dominio: example\.com/);
});

test("a category the API would reject is never submitted", async () => {
  const store = stubStore();
  const vm = icons(store, { category: "mac" });

  await vm.run("blacklist");

  assert.equal(store.calls.length, 0);
});

test("a blank value is never submitted", async () => {
  const store = stubStore();
  const vm = icons(store, { value: "   " });

  await vm.run("whitelist");

  assert.equal(store.calls.length, 0);
});

test("a failure notifies instead of failing silently", async () => {
  const store = stubStore();
  store.createBlacklistEntry = () => Promise.reject(new Error("duplicada"));
  const vm = icons(store);

  await vm.run("blacklist");

  const notice = store.calls.find(call => call.name === "pushNotification");
  assert.ok(notice, "expected a notification");
  assert.equal(notice.payload.message, "duplicada");
});
