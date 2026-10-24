import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { parse } from "@vue/compiler-sfc";
import { NAV_LINKS } from "../src/utils/navigation.js";
import {
  normalizeSettingsSection,
  settingsRoute,
  VALID_TABS,
} from "../src/components/settings/settingsGraph.js";

const root = new URL("../src/", import.meta.url);
const read = (path) => readFileSync(new URL(path, root), "utf8");

test("MapPanel uses packet vocabulary consistently", () => {
  const source = read("components/MapPanel.vue");
  assert.equal((source.match(/Open-port packets/g) || []).length, 2);
  assert.doesNotMatch(source, />Active services<\/th>/);
});

test("Exclusions is a valid, normalized Settings deep link", () => {
  assert.ok(VALID_TABS.has("exclusions"));
  assert.equal(normalizeSettingsSection("exclusions"), "exclusions");
  assert.equal(normalizeSettingsSection("unknown"), "");
  assert.deepEqual(settingsRoute("exclusions"), {
    path: "/settings",
    query: { section: "exclusions" },
  });
  assert.ok(NAV_LINKS.find(item => item.label === "Configuración").children.some(
    child => child.to === "/settings?section=exclusions",
  ));
});

test("EntityTable actions meet touch, focus, and mobile contracts", () => {
  const source = read("components/ui/EntityTablePanel.vue");
  const { descriptor } = parse(source);
  const template = descriptor.template.content;
  const styles = descriptor.styles.map(style => style.content).join("\n");
  assert.match(template, /type="button"[\s\S]*aria-label="Excluir este valor"/);
  assert.match(styles, /width: 28px;[\s\S]*height: 28px;/);
  assert.match(styles, /\.cell-filter-btn:focus-visible\s*\{[\s\S]*outline: 2px/);
  assert.match(styles, /@media \(max-width: 600px\), \(pointer: coarse\)/);
  assert.match(styles, /\.cell-filter-wrap__actions\s*\{[\s\S]*opacity: 1;/);
});
