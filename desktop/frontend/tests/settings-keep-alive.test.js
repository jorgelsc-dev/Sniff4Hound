import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { parse } from "@vue/compiler-sfc";
import { KeepAlive, createRenderer, h, nextTick, reactive, ref } from "vue";
import { optionsView } from "./helpers/options-view.js";

const source = path => readFileSync(new URL(path, import.meta.url), "utf8");
const appTemplate = parse(source("../src/App.vue")).descriptor.template.content;
// The exact include list App.vue hands to KeepAlive, so the shell below
// caches the same views the app does.
const CACHED_VIEWS = (appTemplate.match(/<keep-alive include="([^"]*)">/) || [])[1];

// Minimal host so the real Vue runtime (KeepAlive, watchers, lifecycle) runs
// under node --test without a DOM.
const { createApp } = createRenderer({
  createElement: tag => ({ tag, children: [], parent: null }),
  createText: text => ({ text, parent: null }),
  createComment: text => ({ comment: text, parent: null }),
  setText(node, text) { node.text = text; },
  setElementText(node, text) { node.children = [{ text, parent: node }]; },
  insert(child, parent, anchor) {
    if (child.parent) child.parent.children.splice(child.parent.children.indexOf(child), 1);
    const at = anchor ? parent.children.indexOf(anchor) : -1;
    if (at < 0) parent.children.push(child);
    else parent.children.splice(at, 0, child);
    child.parent = parent;
  },
  remove(child) {
    if (!child.parent) return;
    child.parent.children.splice(child.parent.children.indexOf(child), 1);
    child.parent = null;
  },
  parentNode: node => node.parent,
  nextSibling(node) {
    if (!node.parent) return null;
    const siblings = node.parent.children;
    return siblings[siblings.indexOf(node) + 1] || null;
  },
  patchProp() {},
});

function settingsStore() {
  const calls = [];
  const state = { apiBase: "fixture" };
  const store = new Proxy({ state }, {
    get(target, key) {
      if (key in target) return target[key];
      return async (...args) => {
        calls.push([key, ...args]);
        if (key === "fetchJsonPromise" && args[0] === "/api/pipeline/config") {
          return { cache_limit: 20000, jobs: 2, persist_mode: "alerts" };
        }
        return null;
      };
    },
  });
  return { store, calls };
}

async function flush() {
  for (let i = 0; i < 5; i += 1) {
    await nextTick();
    await new Promise(resolve => setImmediate(resolve));
  }
}

async function mountSettingsShell(t) {
  t.mock.timers.enable({ apis: ["setInterval", "setTimeout"] });
  const { store, calls } = settingsStore();
  const { definition } = await optionsView("SettingsView", store, "views", {
    qrcode: { default: { toDataURL: async () => "" } },
  });
  const Settings = { ...definition, render: () => null };
  const Honeypot = { name: "HoneypotView", render: () => null };
  const route = reactive({ name: "settings", path: "/settings", query: { section: "packetcache" } });
  const replaced = [];
  const current = ref("settings");
  const app = createApp({
    // Same shape as App.vue: <keep-alive include="SettingsView"><component :is="Component" />.
    render: () => h(KeepAlive, { include: CACHED_VIEWS }, [h(current.value === "settings" ? Settings : Honeypot)]),
  });
  app.config.globalProperties.$route = route;
  app.config.globalProperties.$router = { replace: location => replaced.push(location) };
  let vm = null;
  app.mixin({ mounted() { if (this.$options.name === "SettingsView") vm = this; } });
  app.mount({ tag: "root", children: [], parent: null });
  await flush();
  const go = async (name, query = {}) => {
    route.name = name;
    route.path = name === "settings" ? "/settings" : `/${name}`;
    route.query = query;
    current.value = name === "settings" ? "settings" : "other";
    await flush();
  };
  const pipelineReads = () => calls.filter(call => call[0] === "fetchJsonPromise" && call[1] === "/api/pipeline/config").length;
  return { app, go, replaced, pipelineReads, vm: () => vm };
}

test("App.vue keeps only SettingsView alive inside the routed view", () => {
  assert.match(
    appTemplate,
    /<router-view v-slot="\{ Component \}">\s*<transition[^>]*>[\s\S]*?<keep-alive include="SettingsView">\s*<component :is="Component" \/>\s*<\/keep-alive>\s*<\/transition>/,
  );
  assert.equal(CACHED_VIEWS, "SettingsView");
  // KeepAlive matches by component name: renaming the view must fail here.
  assert.match(source("../src/views/SettingsView.vue"), /\n {2}name: "SettingsView",\n/);
});

test("an unsaved Settings draft survives leaving for another route and coming back", async t => {
  const shell = await mountSettingsShell(t);
  const first = shell.vm();
  assert.ok(first, "SettingsView mounted");
  assert.equal(first.pipelineDraft.cache_limit, 20000);
  first.pipelineDraft.cache_limit = 45678;

  await shell.go("honeypot");
  await shell.go("dashboard");
  await shell.go("settings", { section: "packetcache" });

  assert.equal(shell.vm(), first, "the same instance is reactivated, not remounted");
  assert.equal(first.pipelineDraft.cache_limit, 45678);
  assert.equal(first.activeTab, "packetcache");
  shell.app.unmount();
});

test("a cached Settings view ignores other routes and stops polling while hidden", async t => {
  const shell = await mountSettingsShell(t);
  const vm = shell.vm();
  assert.equal(shell.pipelineReads(), 1);
  t.mock.timers.tick(10000);
  await flush();
  assert.equal(shell.pipelineReads(), 2, "polls while visible");

  await shell.go("soc");
  assert.equal(vm.graphStatusTimer, null);
  assert.equal(vm.activeTab, "packetcache", "another route's empty query does not reset the tab");
  assert.deepEqual(shell.replaced, [], "the hidden view never rewrites another route's query");
  t.mock.timers.tick(60000);
  await flush();
  assert.equal(shell.pipelineReads(), 2, "no polling while hidden");

  vm.pipelineDraft.cache_limit = 31337;
  await shell.go("settings", { section: "packetcache" });
  assert.equal(shell.pipelineReads(), 3, "refreshes once on return");
  assert.equal(vm.pipelineDraft.cache_limit, 31337, "the refresh does not overwrite the draft");
  t.mock.timers.tick(10000);
  await flush();
  assert.equal(shell.pipelineReads(), 4, "polling resumes");

  shell.app.unmount();
  t.mock.timers.tick(60000);
  await flush();
  assert.equal(shell.pipelineReads(), 4, "unmount still clears the timer");
});

test("a pending mobile pairing poll pauses while hidden and resumes on return", async t => {
  const shell = await mountSettingsShell(t);
  const vm = shell.vm();
  vm.mobilePairing = { id: "pair-1", status: "waiting", expires_in: 120 };
  vm.mobilePairingTimer = setInterval(vm.refreshMobilePairing, 1500);
  await shell.go("honeypot");
  assert.equal(vm.mobilePairingTimer, null);
  await shell.go("settings", { section: "packetcache" });
  assert.notEqual(vm.mobilePairingTimer, null);

  vm.mobilePairing = { id: "pair-1", status: "paired", expires_in: 0 };
  clearInterval(vm.mobilePairingTimer);
  vm.mobilePairingTimer = null;
  await shell.go("honeypot");
  await shell.go("settings", { section: "packetcache" });
  assert.equal(vm.mobilePairingTimer, null, "a finished pairing is not polled again");
  shell.app.unmount();
});
