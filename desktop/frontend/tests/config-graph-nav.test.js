import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { parse } from "@vue/compiler-sfc";

const source = readFileSync(new URL("../src/components/settings/ConfigGraphNav.vue", import.meta.url), "utf8");
const { descriptor } = parse(source);
const template = descriptor.template.content;
const script = descriptor.scriptSetup.content;
const styles = descriptor.styles.map(style => style.content).join("\n");

test("graph exposes an understandable keyboard and screen-reader contract", () => {
  assert.match(template, /role="region"/);
  assert.match(template, /aria-describedby="config-canvas-help"/);
  assert.match(template, /Usa Tab para recorrer los componentes/);
  assert.match(template, /:aria-pressed="modelValue === node\.section"/);
  assert.match(template, /:title="`\$\{node\.label\}/);
});

test("inspector manages focus and keeps keyboard navigation inside the dialog", () => {
  assert.match(template, /role="dialog"[\s\S]*aria-modal="true"/);
  assert.match(template, /ref="closeButton"/);
  assert.match(template, /@keydown="handleInspectorKeydown"/);
  assert.match(script, /function handleInspectorKeydown\(event\)/);
  assert.match(script, /if \(event\.shiftKey && document\.activeElement === first\)/);
  assert.match(script, /if \(value && value !== previous\) nextTick\(focusCloseButton\)/);
});

test("arrow navigation wraps through every graph node", () => {
  assert.match(template, /@keydown\.arrow-right\.prevent="moveToNode\(node, 1\)"/);
  assert.match(template, /@keydown\.arrow-left\.prevent="moveToNode\(node, -1\)"/);
  assert.match(script, /\(index \+ direction \+ SETTINGS_NODES\.length\) % SETTINGS_NODES\.length/);
});

test("focus indicators and small-screen layout remain explicit", () => {
  assert.match(styles, /\.config-canvas:focus-visible\s*\{[^}]*outline: 2px/);
  assert.match(styles, /\.config-node:focus-visible, \.config-node\.is-selected/);
  assert.match(styles, /@media \(max-width: 700px\)/);
  assert.match(styles, /\.config-node \{ width: 224px; height: 168px/);
  assert.match(styles, /prefers-reduced-motion: reduce/);
});
