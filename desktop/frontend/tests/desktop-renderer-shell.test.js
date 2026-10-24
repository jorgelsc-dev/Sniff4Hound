import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import test from "node:test";
import vm from "node:vm";
import { blockFileDrops, installMenuNavigation } from "../src/utils/desktopShell.js";

const require = createRequire(import.meta.url);

function fakeRouter(path = "/") {
  const router = { pushes: [], currentRoute: { value: { fullPath: path } } };
  router.push = (target) => {
    router.pushes.push(target);
    router.currentRoute.value = { fullPath: target };
    return Promise.resolve();
  };
  return router;
}

test("menu routes are applied with the router instead of reloading", () => {
  const channel = new EventEmitter();
  const desktopApi = {
    onMenuNavigate: (handler) => {
      const listener = (route) => handler(route);
      channel.on("navigate", listener);
      return () => channel.off("navigate", listener);
    },
  };
  const router = fakeRouter("/");
  const stop = installMenuNavigation(desktopApi, router);
  channel.emit("navigate", "/soc");
  channel.emit("navigate", "/soc");
  channel.emit("navigate", "/settings");
  for (const bad of ["//evil.example", "/\\evil", "https://evil.example/", "soc", "", undefined]) channel.emit("navigate", bad);
  assert.deepEqual(router.pushes, ["/soc", "/settings"]);
  stop();
  channel.emit("navigate", "/");
  assert.deepEqual(router.pushes, ["/soc", "/settings"]);
});

test("a rejected router navigation is contained and other environments are no-ops", async () => {
  let handler = null;
  const router = fakeRouter("/");
  router.push = () => Promise.reject(new Error("guard cancelled"));
  installMenuNavigation({ onMenuNavigate: (fn) => { handler = fn; return () => {}; } }, router);
  handler("/soc");
  await new Promise(setImmediate);
  assert.equal(typeof installMenuNavigation(undefined, router), "function");
  assert.equal(typeof installMenuNavigation({}, router), "function");
});

test("the preload exposes onMenuNavigate on its own channel with an unsubscribe", () => {
  const ipcRenderer = new EventEmitter();
  let api = null;
  vm.runInNewContext(readFileSync(new URL("../../preload.js", import.meta.url), "utf8"), {
    process: { platform: "linux" },
    require: () => ({ contextBridge: { exposeInMainWorld: (_name, value) => { api = value; } }, ipcRenderer }),
  });
  const routes = [];
  const stop = api.onMenuNavigate((route) => routes.push(route));
  ipcRenderer.emit("desktop-menu:navigate", {}, "/honeypot");
  stop();
  ipcRenderer.emit("desktop-menu:navigate", {}, "/soc");
  assert.deepEqual(routes, ["/honeypot"]);
  assert.equal(typeof api.onMenuNavigate(null), "function");
});

test("the SPA and the splash cancel the browser's open-dropped-file default", () => {
  const target = new EventEmitter();
  target.addEventListener = (type, fn) => target.on(type, fn);
  blockFileDrops(target);
  for (const type of ["dragover", "drop"]) {
    let prevented = false;
    target.emit(type, { preventDefault: () => { prevented = true; } });
    assert.equal(prevented, true, type);
  }
  assert.match(readFileSync(new URL("../src/main.js", import.meta.url), "utf8"), /blockFileDrops\(window\);\s*installMenuNavigation\(window\.sniff4houndDesktop, router\);/);

  // The real splash script, with just enough DOM to run.
  const listeners = {};
  const element = () => ({ disabled: false, value: "", textContent: "", classList: { toggle() {} }, focus() {}, addEventListener() {} });
  vm.runInNewContext(readFileSync(new URL("../../splash.js", import.meta.url), "utf8"), {
    window: { sniff4houndDesktop: null, addEventListener: (type, fn) => { listeners[type] = fn; } },
    document: { getElementById: element, querySelectorAll: () => [] },
  });
  for (const type of ["dragover", "drop"]) {
    let prevented = false;
    listeners[type]({ preventDefault: () => { prevented = true; } });
    assert.equal(prevented, true, `splash ${type}`);
  }
});

test("main loads the shell only when the window is not already showing it", () => {
  const main = readFileSync(new URL("../../main.js", import.meta.url), "utf8");
  const navigate = main.slice(main.indexOf("function navigate(routePath)"), main.indexOf("function installMenu()"));
  assert.match(navigate, /menuNavigationMode\(contents\.getURL\(\), \{ loading \}\) === "renderer"/);
  assert.match(navigate, /contents\.send\("desktop-menu:navigate", String\(routePath \|\| "\/"\)\);\s*return;/);
  assert.match(navigate, /loadShell\(routePath\);/);
  assert.equal(typeof require("../../lib/window-security.js").menuNavigationMode, "function");
});
