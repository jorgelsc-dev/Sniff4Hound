import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { AI_SETTINGS_PATH, loadAiSettings, normalizeAiSettings, setAiEnabled } from "../src/utils/aiSettings.js";

const panelSource = readFileSync(new URL("../src/components/settings/AiSettingsPanel.vue", import.meta.url), "utf8");
const settingsSource = readFileSync(new URL("../src/views/SettingsView.vue", import.meta.url), "utf8");

test("the AI adapter follows the backend settings contract", async () => {
  const calls = [];
  const store = {
    fetchJsonPromise(path, options) {
      calls.push({ path, options });
      return Promise.resolve({ enabled: true });
    },
  };

  assert.deepEqual(await loadAiSettings(store), { enabled: true });
  assert.deepEqual(await setAiEnabled(store, false), { enabled: true });
  assert.equal(calls[0].path, AI_SETTINGS_PATH);
  assert.equal(calls[0].options, undefined);
  assert.equal(calls[1].options.method, "POST");
  assert.deepEqual(JSON.parse(calls[1].options.body), { enabled: false });
});

test("the adapter rejects an ambiguous backend response", () => {
  assert.throws(() => normalizeAiSettings({ ai_enabled: true }), /no incluye enabled/);
  assert.throws(() => normalizeAiSettings(null), /no es válida/);
});

test("the Settings UI exposes an accessible optional AI toggle", () => {
  assert.match(settingsSource, /<AiSettingsPanel class="mt-4" \/>/);
  assert.match(panelSource, /:aria-label="enabled \? 'Desactivar uso de IA' : 'Activar uso de IA'"/);
  assert.match(panelSource, /:loading="saving"/);
  assert.match(panelSource, /:disabled="loading \|\| saving/);
  assert.match(panelSource, /La IA es opcional/);
  assert.match(panelSource, /no reemplaza las reglas/);
  assert.match(panelSource, /this\.enabled = previous/);
});
