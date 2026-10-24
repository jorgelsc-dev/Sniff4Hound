import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import test from "node:test";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const read = (name) => readFileSync(path.join(root, "src", name), "utf8");

test("dashboard requests carry the selected period and reject stale loads", () => {
  const dashboard = read("views/DashboardView.vue");
  assert.match(dashboard, /params\.set\("since", range\)/);
  assert.match(dashboard, /loadRevision/);
  assert.match(dashboard, /if \(revision !== this\.loadRevision\) return/);
  assert.match(dashboard, /this\.loadController\.abort\(\)/);
  // Partial refresh failures retain the last usable evidence instead of
  // replacing it with empty panels.
  assert.doesNotMatch(dashboard, /this\.dashboard = \{\};[\s\S]*No se pudo cargar el resumen/);
  assert.doesNotMatch(dashboard, /this\.packets = \[\];[\s\S]*No se pudieron cargar los paquetes/);
});

test("HTTP dashboard reads have caller cancellation and a timeout", () => {
  const store = read("state/appStore.js");
  assert.match(store, /const timeoutMs = Number\(config\.timeoutMs \|\| 15000\)/);
  assert.match(store, /requestOpts\.signal/);
  assert.match(store, /clearTimeout\(timeoutId\)/);
});

test("the protocol atlas chooses observed traffic and uses Spanish labels", () => {
  const protocols = read("views/ProtocolsView.vue");
  assert.match(protocols, /const withTraffic = this\.supportedProtocols/);
  assert.match(protocols, /return withTraffic\[0\]/);
  assert.match(protocols, /label: "Desconocido"/);
});

test("SOC labels are consistently Spanish", () => {
  const soc = read("views/SocView.vue");
  for (const label of ["Abrir Sniffer", "Evaluación actual", "Puntuación de riesgo", "Muestra truncada", "Evidencia", "Recomendación"]) {
    assert.match(soc, new RegExp(label));
  }
  for (const label of ["Open Sniffer", "Current assessment", "Risk score", "Sample truncated", "Recommendation"]) {
    assert.doesNotMatch(soc, new RegExp(label));
  }
});
