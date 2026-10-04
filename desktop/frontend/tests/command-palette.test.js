import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { parse } from "@vue/compiler-sfc";

function palette() {
  const { descriptor } = parse(readFileSync(new URL("../src/components/layout/CommandPalette.vue", import.meta.url), "utf8"));
  const script = descriptor.script.content.replace(/^import .*;$/gm, "").replace("export default", "return");
  const store = { state: { commandPaletteOpen: false } };
  const focus = [];
  const document = { querySelector: () => ({ focus: options => focus.push({ target: "trigger", options }) }) };
  const definition = new Function("store", "document", script)(store, document);
  const vm = {
    ...definition.data(),
    results: [{ id: "nav:/sniffer" }],
    $nextTick: callback => callback(),
    $refs: { input: { focus: () => focus.push({ target: "input" }) } },
  };
  for (const [key, method] of Object.entries(definition.methods)) vm[key] = method.bind(vm);
  return { vm, definition, focus, store };
}

test("opening the palette from shared state resets and focuses its search", () => {
  const { vm, definition, store, focus } = palette();
  vm.query = "old search";
  vm.activeId = "old selection";
  store.state.commandPaletteOpen = true;
  definition.watch["store.state.commandPaletteOpen"].call(vm, true);
  assert.equal(vm.query, "");
  assert.equal(vm.activeId, "nav:/sniffer");
  assert.deepEqual(focus, [{ target: "input" }]);
});

test("closing state does not refocus the removed search field", () => {
  const { vm, definition, focus } = palette();
  definition.watch["store.state.commandPaletteOpen"].call(vm, false);
  assert.deepEqual(focus, []);
});

test("Escape closes an open palette and restores the trigger focus", () => {
  const { vm, store, focus } = palette();
  store.state.commandPaletteOpen = true;
  let prevented = false;
  vm.handleKeydown({ key: "Escape", preventDefault: () => { prevented = true; } });
  assert.equal(store.state.commandPaletteOpen, false);
  assert.equal(prevented, true);
  assert.deepEqual(focus, [{ target: "trigger", options: { preventScroll: true } }]);
});

test("Escape leaves other dialogs alone when the palette is closed", () => {
  const { vm, focus } = palette();
  vm.handleKeydown({ key: "Escape", preventDefault: () => assert.fail("Escape should not be consumed") });
  assert.deepEqual(focus, []);
});
