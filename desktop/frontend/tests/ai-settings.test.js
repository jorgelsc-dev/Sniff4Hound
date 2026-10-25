import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { AI_SETTINGS_PATH, aiModelReady, loadAiSettings, normalizeAiSettings, setAiEnabled } from "../src/utils/aiSettings.js";
import { SETTINGS_EDGES } from "../src/components/settings/settingsGraph.js";
import { deferred, optionsView } from "./helpers/options-view.js";

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

  assert.deepEqual(await loadAiSettings(store), { enabled: true, modelStatus: "not_configured" });
  assert.deepEqual(await setAiEnabled(store, false), { enabled: true, modelStatus: "not_configured" });
  assert.equal(calls[0].path, AI_SETTINGS_PATH);
  assert.equal(calls[0].options, undefined);
  assert.equal(calls[1].options.method, "POST");
  assert.deepEqual(JSON.parse(calls[1].options.body), { enabled: false });
});

test("the adapter rejects an ambiguous backend response", () => {
  assert.throws(() => normalizeAiSettings({ ai_enabled: true }), /no incluye enabled/);
  assert.throws(() => normalizeAiSettings(null), /no es válida/);
});

test("the adapter rejects non-boolean writes instead of coercing them", () => {
  const store = { fetchJsonPromise() { throw new Error("the request must not be sent"); } };
  assert.throws(() => setAiEnabled(store, "false"), /requiere un booleano/);
  assert.throws(() => setAiEnabled(store, 1), /requiere un booleano/);
});

test("the Settings UI exposes an accessible optional AI toggle", () => {
  assert.match(settingsSource, /<v-window-item value="ai">[\s\S]*<AiSettingsPanel \/>/);
  assert.match(panelSource, /:aria-label="enabled \? 'Desactivar uso de IA' : 'Activar uso de IA'"/);
  assert.match(panelSource, /:loading="saving"/);
  assert.match(panelSource, /:disabled="loading \|\| saving \|\| !confirmed/);
  assert.doesNotMatch(panelSource, /Boolean\(error\)/);
  assert.match(panelSource, /La IA es opcional/);
  assert.match(panelSource, /no reemplaza las reglas/);
  assert.match(panelSource, /this\.enabled = previous/);
});

test("the AI UI exposes honest context metrics and privacy boundaries", async () => {
  assert.match(panelSource, /Resumen operativo/);
  assert.match(panelSource, /Modelo y ejecución/);
  assert.match(panelSource, /Qué hace hoy/);
  assert.match(panelSource, /Gráfico de actividad agregada/);
  assert.match(panelSource, /Opciones de análisis/);
  assert.match(panelSource, /Sin payloads/);
  assert.match(panelSource, /Sin envío externo/);
  assert.match(panelSource, /Inferencias/);
  assert.match(settingsSource, /metric\("Datos", "Agregados", "ok"\)/);

  const { store } = aiStore();
  store.state.liveActivity = { total: 12 };
  store.state.pendingJobs = 2;
  store.state.runtime = { running_engines: ["sniffer"] };
  const { vm } = await optionsView("AiSettingsPanel", store, "components/settings");
  assert.deepEqual(vm.contextMetrics.map(metric => metric.value), ["12/s", "2", "1/2", "0"]);
  assert.equal(vm.analysisOptions.length, 4);
  assert.equal(vm.modelSummary.items.find(item => item.label === "Modelo").value, "No configurado");
  assert.equal(vm.activityPeak, "12");
  assert.equal(vm.activityAverage, "12");
  assert.match(vm.activityChartLabel, /pico 12 paquetes por segundo/);
});

test("the AI graph node makes its optional behavior clear", () => {
  assert.match(panelSource, /IA es opcional/);
  assert.match(settingsSource, /fetchJsonPromise\("\/api\/settings\/ai"\)/);
  assert.match(settingsSource, /!config \? "Sin datos" : !enabled \? "IA desactivada" : ready \? "IA lista" : "Permitida · sin modelo"/);
  assert.match(settingsSource, /online && ready,/);
});

test("a saved preference is not an operational model", () => {
  assert.equal(aiModelReady(normalizeAiSettings({ enabled: true })), false);
  assert.equal(aiModelReady(normalizeAiSettings({ enabled: true, model_status: "not_configured" })), false);
  assert.equal(aiModelReady(normalizeAiSettings({ enabled: false, model_status: "ready" })), false);
  assert.equal(aiModelReady(normalizeAiSettings({ enabled: true, model_status: "ready" })), true);
  assert.doesNotMatch(panelSource, /proveedor configurado/);
  assert.match(panelSource, /no hay un modelo de IA configurado/);
});

test("AI graph wires are marked planned until a real consumer exists", () => {
  const aiEdges = SETTINGS_EDGES.filter(edge => edge.from === "ai" || edge.to === "ai");
  assert.equal(aiEdges.length, 2);
  for (const edge of aiEdges) {
    assert.equal(edge.planned, true);
    assert.match(edge.label, /planificado/);
  }
});

function aiStore() {
  const calls = [];
  return {
    calls,
    store: {
      state: { wsStatus: "online" },
      fetchJsonPromise(path, options) {
        const pending = deferred();
        calls.push({ path, options, ...pending });
        return pending.promise;
      },
    },
  };
}

test("a failed load is unknown, not off, and Reintentar recovers the panel", async () => {
  const { store, calls } = aiStore();
  const { vm } = await optionsView("AiSettingsPanel", store, "components/settings");
  const first = vm.load();
  calls[0].reject(new Error("HTTP 503"));
  await first;
  assert.equal(vm.confirmed, false);
  assert.equal(vm.chip.label, "Estado desconocido");
  assert.match(vm.description, /No se pudo confirmar/);
  await vm.toggle(true);
  assert.equal(calls.length, 1, "an unconfirmed value must not be written");
  const retry = vm.load();
  calls[1].resolve({ enabled: true, model_status: "not_configured" });
  await retry;
  assert.equal(vm.confirmed, true);
  assert.equal(vm.error, "");
  assert.equal(vm.chip.label, "Permitida · sin modelo");
});

test("a 503 while saving rolls back but leaves the switch usable", async () => {
  const { store, calls } = aiStore();
  const { vm } = await optionsView("AiSettingsPanel", store, "components/settings");
  const loaded = vm.load();
  calls[0].resolve({ enabled: false, model_status: "not_configured" });
  await loaded;
  const failed = vm.toggle(true);
  assert.match(vm.description, /Guardando/);
  calls[1].reject(new Error("HTTP 503"));
  await failed;
  assert.equal(vm.enabled, false);
  assert.equal(vm.confirmed, true, "the previous value is still the confirmed one");
  assert.equal(vm.saving, false);
  const saved = vm.toggle(true);
  calls[2].resolve({ enabled: true, model_status: "not_configured" });
  await saved;
  assert.equal(vm.enabled, true);
});

test("reconnecting reloads the AI panel", async () => {
  const { store, calls } = aiStore();
  const { vm, definition } = await optionsView("AiSettingsPanel", store, "components/settings");
  definition.watch["store.state.wsStatus"].call(vm, "online", "offline");
  assert.equal(calls.length, 1);
  assert.equal(calls[0].path, AI_SETTINGS_PATH);
  definition.watch["store.state.wsStatus"].call(vm, "online", "online");
  assert.equal(calls.length, 1);
});
