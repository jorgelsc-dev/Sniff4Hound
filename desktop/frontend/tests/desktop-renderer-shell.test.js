import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { readFileSync } from "node:fs";
import test from "node:test";
import vm from "node:vm";
import { blockFileDrops } from "../src/utils/desktopShell.js";

test("the SPA and the splash cancel the browser's open-dropped-file default", () => {
  const target = new EventEmitter();
  target.addEventListener = (type, fn) => target.on(type, fn);
  blockFileDrops(target);
  for (const type of ["dragover", "drop"]) {
    let prevented = false;
    target.emit(type, { preventDefault: () => { prevented = true; } });
    assert.equal(prevented, true, type);
  }
  assert.match(readFileSync(new URL("../src/main.js", import.meta.url), "utf8"), /blockFileDrops\(window\);/);

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
