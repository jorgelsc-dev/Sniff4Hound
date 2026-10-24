import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { parse } from "@vue/compiler-sfc";
import { describeProtocol, LAYERS } from "../src/utils/protocolCatalog.js";
import { protocolText } from "../src/utils/protocolText.js";
import { stageReading } from "../src/utils/flowGraph.js";
import { bridgedFetch, connectionErrorMessage } from "../src/utils/httpBridge.js";
import { formatTimestamp, normalizeProto } from "../src/utils/traffic.js";
import { SETTINGS_NODES } from "../src/components/settings/settingsGraph.js";

const source = path => readFileSync(new URL(path, import.meta.url), "utf8");
function method(file, name, globals = {}) {
  const { descriptor } = parse(source(file));
  const match = descriptor.script.content.match(new RegExp(`^    (async )?${name}\\(([^)]*)\\) \\{([\\s\\S]*?)^    \\},`, "m"));
  assert.ok(match, `method ${name}`);
  return new Function(...Object.keys(globals), `return ${match[1] || ""}function(${match[2]}) {${match[3]}}`)(...Object.values(globals));
}

test("pipeline distinguishes loading, failure, confirmed zero and stale values", () => {
  assert.equal(stageReading({ value: null, online: true, loading: true }).status, "Cargando");
  assert.equal(stageReading({ value: null, online: true, error: true }).metric, "—");
  assert.equal(stageReading({ value: 0, online: true, status: "Vacío" }).status, "Vacío");
  const stale = stageReading({ value: 93, online: false, updatedAt: "now", status: "Persistiendo" });
  assert.equal(stale.metric, "93");
  assert.equal(stale.status, "Datos obsoletos");
  assert.equal(stale.live, false);
});

test("failed dashboard refresh preserves values and marks them stale", async () => {
  const store = { state: {}, fetchJsonPromise: async () => { throw new Error("timeout"); } };
  const load = method("../src/components/layout/FlowShell.vue", "load", { store });
  const vm = { expanded: true, requestId: 0, counts: { count_ports: 93 }, updatedAt: "earlier" };
  await load.call(vm);
  assert.deepEqual(vm.counts, { count_ports: 93 });
  assert.equal(vm.loadError, true);
  assert.equal(vm.loading, false);
});

test("disconnected sensor has a visible chooser action wired to preload", async () => {
  const calls = [];
  const reconnect = method("../src/components/layout/FlowShell.vue", "reconnect", {
    window: { sniff4houndDesktop: { showConnectionChooser: () => calls.push("chooser") } },
  });
  await reconnect.call({});
  assert.deepEqual(calls, ["chooser"]);
  const template = parse(source("../src/components/layout/FlowShell.vue")).descriptor.template.content;
  assert.match(template, /v-if="!online"[\s\S]*@click="reconnect">Reconectar \/ Cambiar sensor/);
});

test("bridge strips Electron invocation details and suggests a useful action", async () => {
  const original = globalThis.window;
  globalThis.window = { sniff4houndDesktop: { httpRequest: async () => { throw new Error("Error invoking remote method 'desktop-http:request': Error: Remote backend timed out."); } } };
  try {
    await assert.rejects(bridgedFetch("https://sensor.local/api/hello"), error => {
      assert.match(error.message, /sensor.*Reintenta/);
      assert.doesNotMatch(error.message, /remote method|Remote backend/);
      return true;
    });
    assert.match(connectionErrorMessage(new Error("Response is too large.")), /Reduce la búsqueda/);
    assert.match(connectionErrorMessage(new Error("ECONNREFUSED")), /cambia de sensor/);
    assert.match(connectionErrorMessage(new Error("CERT_INVALID")), /certificado/);
  } finally { globalThis.window = original; }
});

test("monitor settings send search, enabled, page size and offset to the server", async () => {
  const requests = [];
  const store = {
    listMonitors: async query => { requests.push(query); return { items: [{ id: "result" }], total_available: 99 }; },
    getMonitorConfig: async () => ({}),
  };
  const vm = { store, monitorRequestId: 0, monitorPage: 3, monitorQuery: "dns", monitorEnabled: "1", applyMonitorConfig() {} };
  await method("../src/views/SettingsView.vue", "load").call(vm);
  assert.deepEqual(requests, [{ limit: 25, offset: 50, q: "dns", enabled: "1" }]);
  assert.equal(vm.monitorTotal, 99);
  assert.equal(vm.monitors[0].id, "result");
});

test("lightweight monitor rows fetch full details before opening the editor", async () => {
  const requests = [];
  const vm = { store: { fetchJsonPromise: async path => { requests.push(path); return { id: "a/b", match: { ports: [53] } }; } } };
  const detail = await method("../src/views/SettingsView.vue", "monitorDetail").call(vm, { id: "a/b" });
  assert.deepEqual(detail.match.ports, [53]);
  assert.deepEqual(requests, ["/api/monitors/?id=a%2Fb"]);
});

test("listener settings search and paginate on the backend", async () => {
  const queries = [];
  const vm = { listenerRequestId: 0, listenerPage: 2, listenerSearch: "ssh", store: {
    listHoneypotListeners: async query => { queries.push(query); return { items: [{ id: "tcp/22" }], total_available: 27 }; },
  } };
  await method("../src/views/SettingsView.vue", "loadListeners").call(vm);
  assert.deepEqual(queries, [{ limit: 25, offset: 25, q: "ssh" }]);
  assert.equal(vm.listenerTotal, 27);
});

test("protocol landing fetches the busiest slice after obtaining period counts", async () => {
  const body = source("../src/views/ProtocolsView.vue").match(/function normalizeProtocolKey\(value\) \{([\s\S]*?)\n\}/)[1];
  const normalizeProtocolKey = new Function("normalizeProto", `return function(value) {${body}}`)(normalizeProto);
  const selected = method("../src/views/ProtocolsView.vue", "selectedProtocol", { normalizeProtocolKey });
  const calls = [];
  const vm = {
    $route: { params: {} }, supportedProtocols: ["unknown", "arp", "dns"], snapshot: {},
    store: { fetchProtocolSnapshot: async query => {
      calls.push(query.proto);
      return { catalog: [{ protocol: "unknown", count: 0 }, { protocol: "arp", count: 2 }, { protocol: "dns", count: 20 }], packets: query.proto === "dns" ? [{ proto: "dns" }] : [] };
    } },
    packetLimit: 100, applySnapshot(snapshot) { this.snapshot = snapshot; this.packetRows = snapshot.packets; }, startSnapshotStream() {},
  };
  Object.defineProperty(vm, "protocolCountMap", { get() { return Object.fromEntries((this.snapshot.catalog || []).map(row => [row.protocol, row.count])); } });
  Object.defineProperty(vm, "selectedProtocol", { get() { return selected.call(this); } });
  await method("../src/views/ProtocolsView.vue", "load", { normalizeProtocolKey }).call(vm);
  assert.deepEqual(calls, ["", "dns"]);
  assert.equal(vm.packetRows[0].proto, "dns");
  vm.$route.params.proto = "arp";
  assert.equal(vm.selectedProtocol, "arp");
});

test("undeclared sensor coordinates do not project null to Null Island", () => {
  const project = method("../src/components/MapPanel.vue", "projectedOrigin");
  const vm = { originPoint: { lat: null, lon: null, declared: false }, projectPoint: () => assert.fail("no projection without a location") };
  assert.equal(project.call(vm), null);
  vm.originPoint = { lat: 0, lon: 0, declared: true };
  vm.projectPoint = (lon, lat) => ({ x: lon, y: lat });
  assert.deepEqual(project.call(vm), { x: 0, y: 0 });
  assert.match(source("../src/components/MapPanel.vue"), /Configura la ubicación del sensor/);
});

test("dates and numbers use Spanish independently of the operator locale", () => {
  const iso = "2026-10-17T18:37:38Z";
  assert.equal(formatTimestamp(iso), new Date(iso).toLocaleString("es-ES"));
  const formatNumber = method("../src/views/IpsView.vue", "formatCount");
  assert.equal(formatNumber.call({}, 43811), Number(43811).toLocaleString("es-ES"));
  assert.match(source("../src/main.js"), /locale: \{ locale: "es"/);
});

test("desktop CSP, renderer sandbox and permission denial remain wired", () => {
  const index = source("../index.html");
  const splash = source("../../splash.html");
  const main = source("../../main.js");
  for (const html of [index, splash]) {
    assert.match(html, /Content-Security-Policy/);
    assert.match(html, /script-src 'self'/);
    assert.doesNotMatch(html, /<script>(?!<\/script>)/);
  }
  assert.match(main, /sandbox: true/);
  assert.match(main, /setPermissionRequestHandler\([\s\S]*?callback\(false\)/);
  assert.match(main, /setPermissionCheckHandler\(\(\) => false\)/);
  assert.match(main, /const connect = origin \? `connect-src 'self' \$\{origin\} \$\{websocketOrigin\}`/);
});

test("desktop realtime bridge renews its timeout when heartbeat data arrives", () => {
  const main = source("../../main.js");
  const bridgeStart = main.indexOf('ipcMain.handle("desktop-http:stream-open"');
  const dataStart = main.indexOf('response.on("data", (chunk) => {', bridgeStart);
  const refresh = main.indexOf("refreshTimeout();", dataStart);
  const byteCount = main.indexOf("bytes += chunk.length;", dataStart);
  assert.ok(dataStart > bridgeStart, "the HTTP bridge must handle streamed response chunks");
  assert.ok(refresh > dataStart && refresh < byteCount, "heartbeats must renew the inactivity timeout");
  assert.match(main, /const refreshTimeout = \(\) => \{/);
  assert.match(main, /HTTP_BRIDGE_STREAM_TIMEOUT_MS\);/);
});

test("connection modes show Spanish status and no remote status for local startup", () => {
  const splash = source("../../splash.html");
  const script = source("../../splash.js");
  assert.match(splash, /lang="es"/);
  assert.match(splash, /Conecta tu sensor/);
  assert.match(script, /Esperando autorización/);
  assert.match(script, /Comprobando el sensor remoto/);
  assert.doesNotMatch(script, /Checking|Authorize|Unable to/);
});


test("protocol presentation metadata is Spanish while protocol identifiers stay stable", () => {
  assert.equal(describeProtocol("dns").key, "dns");
  assert.match(describeProtocol("dns").description, /Resolución de nombres/);
  assert.equal(LAYERS.find(layer => layer.key === "application").label, "Aplicación");
  assert.equal(protocolText("Destination port"), "Puerto destino");
  assert.equal(protocolText("example.test"), "example.test");
});


test("settings use aggregate listener counts rather than the current catalog page", () => {
  const vm = {
    store: { state: { wsStatus: "online" } },
    runtime: { sniffer: {}, honeypot: { enabled_listener_count: 290 } },
    listeners: [{ enabled: true }], detectionScopes: [], detectionScopeOptions: [],
    monitorStats: { enabled: 18032, total: 29465 },
    graphFresh: { honeypot: true, detection: true },
  };
  const states = method("../src/views/SettingsView.vue", "graphStates").call(vm);
  assert.equal(states.honeypot.label, "290 listeners habilitados");
  assert.equal(states.detection.metrics[0].value, "18.032/29.465");
});

test("settings graph distinguishes initial loading from a failed refresh", () => {
  const vm = {
    store: { state: { wsStatus: "online", notifySoundEnabled: false } },
    runtime: { sniffer: {}, honeypot: {} },
    pipelineConfig: null, pipelineLive: null, graphFresh: {}, graphErrors: {}, graphReady: false,
    statusRefreshing: false, graphExtras: {}, storageStats: null, locationConfigured: false,
    locationSaved: {}, locationSummary: "", locationError: "", monitorStats: null, monitors: [],
    error: "", monitorMinSeverity: "info", suppressGeneratedInfo: true, detectionScopes: [],
    detectionScopeOptions: [], logConfig: null, limitsData: null,
    formatDbBytes: value => `${value} B`,
  };
  const graphStates = method("../src/views/SettingsView.vue", "graphStates");
  assert.equal(graphStates.call(vm).runtime.label, "Cargando");
  vm.graphReady = true;
  vm.graphErrors = { runtime: true };
  assert.equal(graphStates.call(vm).runtime.label, "Error al actualizar");
});

test("settings graph covers every real settings section and only marks configured filters active", () => {
  const template = parse(source("../src/views/SettingsView.vue")).descriptor.template.content;
  const renderedSections = [...template.matchAll(/<v-window-item value="([^"]+)"/g)].map(match => match[1]);
  assert.deepEqual(renderedSections.sort(), SETTINGS_NODES.map(node => node.section).sort());

  const vm = {
    store: { state: { wsStatus: "online", notifySoundEnabled: false } },
    runtime: { sniffer: {}, honeypot: {} }, pipelineConfig: {}, pipelineLive: null,
    graphFresh: Object.fromEntries(SETTINGS_NODES.map(node => [node.section, true])),
    graphErrors: {}, graphReady: true, statusRefreshing: false, graphExtras: {},
    storageStats: null, locationConfigured: false, locationSaved: {}, locationSummary: "",
    locationError: "", monitorStats: null, monitors: [], error: "", monitorMinSeverity: "info",
    suppressGeneratedInfo: true, detectionScopes: [], detectionScopeOptions: [], logConfig: null,
    limitsData: null, formatDbBytes: value => `${value} B`,
  };
  const states = method("../src/views/SettingsView.vue", "graphStates").call(vm);
  assert.equal(states.location.active, false);
  assert.equal(states.scope.active, false);
  assert.equal(states.exclusions.active, false);
});

test("settings graph refresh owns location and scope freshness", () => {
  const view = source("../src/views/SettingsView.vue");
  assert.match(view, /this\.store\.getDeclaredLocation\(\),\s*this\.store\.getDetectionScopes\(\),/);
  assert.match(view, /scope: fresh\(12\)/);
  assert.match(view, /location: fresh\(11\)/);
  assert.match(view, /if \(value\(11\)\) this\.applyLocation\(value\(11\)\)/);
  assert.match(view, /if \(value\(12\)\) \{/);
});

test("settings graph cards expose truncated content through their accessible name", () => {
  const template = parse(source("../src/components/settings/ConfigGraphNav.vue")).descriptor.template.content;
  assert.match(template, /:aria-label="nodeAccessibleLabel\(node\)"/);
  assert.match(template, /:title="node.detail"/);
  assert.match(template, /:title="metric.label"/);
  assert.match(template, /:title="node.state.label \|\| 'Ajustes'"/);
});
