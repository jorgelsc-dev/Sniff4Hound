import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { babelParse, compileScript, parse } from "@vue/compiler-sfc";
import * as vue from "vue";
import * as d3 from "d3";
import * as graph from "../src/components/settings/settingsGraph.js";

async function inspector() {
  const source = readFileSync(new URL("../src/components/settings/ConfigGraphNav.vue", import.meta.url), "utf8");
  const descriptor = parse(source).descriptor;
  let code = compileScript(descriptor, { id: "focus-test" }).content;
  const watchers = [];
  const modules = {
    vue: { ...vue, onMounted() {}, onBeforeUnmount() {}, watch(get, callback) { watchers.push({ get, callback }); } },
    d3,
    "./settingsGraph": graph,
  };
  const bindings = {};
  for (const entry of [...babelParse(code, { sourceType: "module" }).program.body].reverse()) {
    if (entry.type === "ImportDeclaration") {
      for (const spec of entry.specifiers) bindings[spec.local.name] = modules[entry.source.value][spec.imported.name];
      code = code.slice(0, entry.start) + code.slice(entry.end);
    } else if (entry.type === "ExportDefaultDeclaration") {
      code = code.slice(0, entry.start) + "return " + code.slice(entry.declaration.start);
    }
  }
  const definition = new Function(...Object.keys(bindings), code)(...Object.values(bindings));
  const props = { modelValue: "ai", states: {}, refreshing: false };
  const emitted = [];
  const state = definition.setup(props, { expose() {}, emit: (...args) => emitted.push(args) });
  return { state, props, emitted, watchers };
}

// Native visibility/layout is verified by the coordinating agent in Electron.
// These DOM doubles exercise the production handler's selection and focus side
// effects, including retained inactive panels and fieldset-disabled controls.
function control(document, options = {}) {
  return vue.markRaw({
    tabIndex: options.tabIndex ?? 0,
    matches: () => Boolean(options.disabled || options.ariaDisabled || options.disabledFieldset),
    closest: () => options.inert || options.hiddenAncestor || options.ariaHiddenAncestor,
    getClientRects: () => options.noLayout ? [] : [{}],
    visibility: options.visibility || "visible",
    focus() { document.activeElement = this; },
  });
}

function tab(state, document, shiftKey = false) {
  let prevented = false;
  state.handleInspectorKeydown({ key: "Tab", shiftKey, preventDefault() { prevented = true; } });
  return { prevented, target: document.activeElement };
}

test("inspector wraps only through visible, enabled, non-inert controls", async t => {
  const oldDocument = globalThis.document;
  const oldStyle = globalThis.getComputedStyle;
  t.after(() => { globalThis.document = oldDocument; globalThis.getComputedStyle = oldStyle; });
  const document = globalThis.document = { activeElement: null };
  globalThis.getComputedStyle = element => ({ visibility: element.visibility });
  const { state } = await inspector();
  const first = control(document);
  const last = control(document);
  const excluded = [
    { noLayout: true }, { hiddenAncestor: true }, { ariaHiddenAncestor: true },
    { inert: true }, { disabled: true }, { ariaDisabled: true },
    { disabledFieldset: true }, { tabIndex: -1 }, { visibility: "hidden" }, { visibility: "collapse" },
  ].map(options => control(document, options));
  let candidates = [first, ...excluded, last, ...excluded];
  const dialog = control(document);
  dialog.querySelectorAll = () => candidates;
  state.inspector.value = dialog;
  document.activeElement = first;
  assert.deepEqual(tab(state, document, true), { prevented: true, target: last });
  assert.deepEqual(tab(state, document), { prevented: true, target: first });
  document.activeElement = excluded[0];
  assert.equal(tab(state, document).target, first, "recover focus from retained inactive panel");
  document.activeElement = last;
  candidates = [first, ...excluded];
  assert.equal(tab(state, document, true).target, first, "panel switch recomputes candidates");
  candidates = excluded;
  assert.equal(tab(state, document).target, dialog, "no visible controls focuses dialog itself");
  state.inspector.value = null;
  assert.equal(tab(state, document).prevented, false, "unmounted dialog is safe");
});

test("inspector focuses close on section changes and restores the originating graph card", async () => {
  const { state, emitted, watchers } = await inspector();
  let focused = "";
  state.closeButton.value = { $el: { focus() { focused = "close"; } } };
  state.inspectorBody.value = { scrollTop: 90 };
  const node = { focus() { focused = "ai"; } };
  state.setNodeEl("ai", node);
  watchers[0].callback("ai", "connection");
  await vue.nextTick();
  assert.equal(focused, "close");
  assert.equal(state.inspectorBody.value.scrollTop, 0);
  state.closeInspector();
  assert.deepEqual(emitted, [["update:modelValue", ""]]);
  await vue.nextTick();
  assert.equal(focused, "ai");
});

function elements(ast, tag) {
  const result = [];
  function walk(node) {
    if (node.type === 1 && node.tag === tag) result.push(node);
    for (const child of node.children || []) walk(child);
  }
  walk(ast);
  return result;
}
function attribute(node, name) { return node.props.find(prop => prop.type === 6 && prop.name === name)?.value?.content; }
function binding(node, name) { return node.props.find(prop => prop.type === 7 && prop.name === "bind" && prop.arg?.content === name)?.exp?.content; }

test("compiled graph markup labels tooltips, uses select label IDs, and preserves visible card names", () => {
  const descriptor = parse(readFileSync(new URL("../src/components/settings/ConfigGraphNav.vue", import.meta.url), "utf8")).descriptor;
  const ast = descriptor.template.ast;
  const select = elements(ast, "v-select")[0];
  assert.equal(attribute(select, "label"), "Componentes");
  assert.equal(attribute(select, "id"), "config-component-select");
  assert.equal(attribute(select, "aria-label"), undefined, "visible label supplies accessible name");
  for (const tooltip of elements(ast, "v-tooltip")) {
    assert.ok(attribute(tooltip, "aria-label") || binding(tooltip, "aria-label"), "teleported overlay has its own name");
  }
  const card = elements(ast, "button").find(node => attribute(node, "class") === "config-node");
  assert.equal(binding(card, "aria-label"), undefined, "card name comes from its full visible contents");
  assert.ok(binding(card, "aria-describedby"), "optional AI context remains available");
  const dialog = elements(ast, "div").find(node => attribute(node, "role") === "dialog");
  assert.ok(dialog.props.some(prop => prop.type === 7 && prop.name === "on" && prop.arg.content === "keydown" && prop.modifiers.some(modifier => modifier.content === "esc")), "Escape invokes close handler");
  const top = parse(readFileSync(new URL("../src/components/layout/AppTopBar.vue", import.meta.url), "utf8")).descriptor.template.ast;
  const trigger = elements(top, "button")[0];
  const text = elements(trigger, "span")[0].children[0].content;
  assert.ok(attribute(trigger, "aria-label").includes(text));
  assert.equal(attribute(elements(trigger, "kbd")[0], "aria-hidden"), "true");
});
