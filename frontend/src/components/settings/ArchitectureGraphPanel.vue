<template>
  <div class="arch-graph">
    <div class="arch-graph__head">
      <h3 class="text-subtitle-1 font-weight-bold">Arquitectura de Sniff4Hound</h3>
      <p class="text-body-2 arch-graph__hint">
        Cómo se relacionan los componentes de la app. Los nodos con
        <v-icon icon="mdi-pencil-circle" size="12" color="secondary" /> anillo punteado admiten
        edición - haz click para ver su descripción y saltar a su configuración. Las líneas punteadas
        salen de un componente que ahora mismo no está corriendo.
      </p>
    </div>
    <div class="arch-graph__scroll">
      <svg :viewBox="`0 0 ${viewBoxWidth} ${viewBoxHeight}`" preserveAspectRatio="xMidYMid meet" role="img" aria-label="Diagrama de arquitectura de Sniff4Hound, interactivo">
        <text v-for="col in columns" :key="`col-${col.index}`" :x="columnX(col.index)" :y="18" text-anchor="middle" fill="currentColor" font-size="10" font-weight="700" letter-spacing="1">{{ col.label }}</text>

        <line v-for="(edge, i) in edges" :key="`edge-${i}`" :x1="edge.x1" :y1="edge.y1" :x2="edge.x2" :y2="edge.y2" :stroke="edge.color" stroke-width="1.1" :opacity="edge.active ? 0.32 : 0.18" :stroke-dasharray="edge.active ? null : '5 4'" marker-end="url(#arch-arrow)" />
        <circle v-for="dot in pulseDots" :key="dot.id" :cx="dot.x" :cy="dot.y" :r="dot.r" :fill="dot.color" :opacity="dot.opacity" class="arch-signal-dot" />

        <defs>
          <marker id="arch-arrow" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
            <path d="M0,0 L8,4 L0,8 z" fill="#5c7a8f" />
          </marker>
        </defs>

        <g v-for="node in nodes" :key="node.id" tabindex="0" role="button" :aria-label="`Ver ${node.label} - ${node.active ? 'activo' : 'inactivo'}`"
          class="arch-node" :class="{ 'arch-node--editable': node.editable, 'arch-node--selected': selectedId === node.id, 'arch-node--inactive': !node.active }"
          @click="selectNode(node.id)" @keydown.enter="selectNode(node.id)" @keydown.space.prevent="selectNode(node.id)">
          <circle v-if="node.editable" :cx="node.x" :cy="node.y" :r="NODE_RADIUS + 5" fill="none" :stroke="node.color" stroke-width="1.2" stroke-dasharray="3 3" class="arch-node__ring" />
          <circle :cx="node.x" :cy="node.y" :r="NODE_RADIUS" :fill="node.color" :opacity="selectedId === node.id ? 1 : node.active ? 0.85 : 0.35" stroke="#0a1420" stroke-width="1.5" />
          <foreignObject :x="node.x - 10" :y="node.y - 10" width="20" height="20" class="arch-node__icon">
            <i :class="['mdi', node.icon]" />
          </foreignObject>
          <circle v-if="node.hasStatus" :cx="node.x + NODE_RADIUS - 2" :cy="node.y + NODE_RADIUS - 2" r="4" :fill="node.active ? '#3ddc84' : '#5c6b7a'" stroke="#0a1420" stroke-width="1" />
          <text :x="node.x" :y="node.y + NODE_RADIUS + 13" text-anchor="middle" fill="currentColor" font-size="8.5">{{ node.label }}</text>
        </g>
      </svg>
    </div>

    <div v-if="selected" class="arch-info-panel">
      <div class="arch-info-panel__head">
        <span class="arch-info-panel__dot" :style="{ background: selected.color }" />
        <strong>{{ selected.label }}</strong>
        <v-chip v-if="selected.hasStatus" size="x-small" :color="selected.active ? 'success' : 'default'" variant="tonal">
          {{ selected.active ? "Activo" : "Inactivo" }}
        </v-chip>
        <v-btn icon size="x-small" variant="text" class="ml-auto" aria-label="Cerrar" @click="selectedId = null">
          <v-icon icon="mdi-close" size="14" />
        </v-btn>
      </div>
      <p class="arch-info-panel__desc">{{ selected.description }}</p>
      <div class="arch-info-panel__actions">
        <v-btn v-if="selected.editable" size="x-small" color="primary" @click="goToSettings(selected.settingsTab)">
          Configurar <v-icon icon="mdi-arrow-right" size="12" end />
        </v-btn>
        <template v-else-if="selected.id === 'store'">
          <v-btn size="x-small" variant="tonal" @click="goToSettings('blacklist')">Lista negra</v-btn>
          <v-btn size="x-small" variant="tonal" @click="goToSettings('exclusions')">Exclusiones</v-btn>
        </template>
        <span v-else class="arch-info-panel__readonly">Sin ajustes propios - es infraestructura interna.</span>
      </div>
    </div>
  </div>
</template>
<script setup>
import { computed, onBeforeUnmount, onMounted, ref } from "vue";
import { interpolateRgb, interval as d3Interval } from "d3";
import store from "../../state/appStore";

const emit = defineEmits(["open-settings-tab"]);

// Real on/off state per statusKey, read from the same endpoints the rest of
// the app already uses (no new backend surface) - a node without a
// statusKey (the infrastructure ones: Store, Auth, API, Dashboard, Fuentes)
// has no real "off" state at this level and is always shown as active.
const status = ref({ sniffer: false, honeypot: false, runtime: false, monitors: false, ai: false });
async function loadStatus() {
  try {
    const [runtime, monitors, aiConfig] = await Promise.all([
      store.fetchJsonPromise("/api/runtime/"),
      store.fetchJsonPromise("/api/monitors/"),
      store.fetchJsonPromise("/api/ai/config"),
    ]);
    status.value = {
      sniffer: !!runtime?.sniffer?.running,
      honeypot: !!runtime?.honeypot?.running,
      runtime: !!runtime?.sniffer?.running || !!runtime?.honeypot?.running,
      monitors: Array.isArray(monitors) && monitors.some((m) => m.enabled),
      ai: !!aiConfig?.training_enabled,
    };
  } catch {
    // Best-effort status only - the diagram still works (just shows every
    // engine as inactive) if these calls fail, e.g. no backend reachable.
  }
}
let statusTimer = null;

// Column categories mirror the "Data Source -> Ingestion -> Transformation ->
// Data Lake -> Visualisation" layered-pipeline framing the user asked to
// match, adapted to this app's actual components (see sniff4hound/*.py).
const COLUMN_LABELS = ["Fuentes", "Captura", "Detección", "Almacenamiento", "Acceso", "Visualización"];
const COLUMN_COLORS = ["#6c8197", "#0fe8ff", "#c084fc", "#3ddc84", "#ffb454", "#ff6b84"];

const NODE_DEFS = [
  { id: "sources", label: "Tráfico / conexiones", column: 0, editable: false, icon: "mdi-access-point-network",
    description: "Tráfico de la NIC en modo promiscuo y conexiones entrantes a los puertos señuelo - el origen de todo lo que la app procesa." },
  { id: "sniffer", label: "Sniffer", column: 1, editable: true, settingsTab: "capture", icon: "mdi-ethernet", statusKey: "sniffer",
    description: "Captura pasiva raw-socket (Ethernet, VLAN, ARP, IP, TCP/UDP/ICMP, protocolos de aplicación). Evalúa reglas e IA por paquete y persiste en SniffStore." },
  { id: "honeypot", label: "Honeypot", column: 1, editable: true, settingsTab: "honeypot", icon: "mdi-spider-web", statusKey: "honeypot",
    description: "Señuelos activos (HTTP, SSH, FTP, SMB, DNS, MySQL, Redis, RDP, VNC...) que registran cada intento de conexión y lo tratan como evidencia." },
  { id: "runtime", label: "Modo / Runtime", column: 1, editable: true, settingsTab: "capture", icon: "mdi-source-branch", statusKey: "runtime",
    description: "Orquesta qué motor corre (Sniffer, Honeypot o ambos a la vez) y qué interfaces usa el Sniffer." },
  { id: "monitors", label: "Monitors", column: 2, editable: true, settingsTab: "detection", icon: "mdi-target-account", statusKey: "monitors",
    description: "Motor de reglas (patrones/regex, severidad, inclusión/exclusión) que etiqueta cada paquete capturado, venga de Sniffer o Honeypot." },
  { id: "ai_lof", label: "IA · Outliers", column: 2, editable: true, settingsTab: "ai", icon: "mdi-chart-scatter-plot", statusKey: "ai",
    description: "Detector LOF no supervisado: convierte los bytes de cada paquete en una imagen y puntúa anomalías por cohorte de protocolo/origen." },
  { id: "ai_classifier", label: "IA · Clasificador", column: 2, editable: true, settingsTab: "ai", icon: "mdi-brain", statusKey: "ai",
    description: "Red entrenada con el feedback del operador (benigno/maligno). Incluye el torneo de arquitecturas que compite varias formas de red hasta que la mejora se estanca." },
  { id: "store", label: "SniffStore", column: 3, editable: false, icon: "mdi-database",
    description: "Persistencia SQLite central: paquetes, tags, flows, sesiones, config de monitors, lista negra/blanca, exclusiones, config en tiempo real. Todo lo demás lee o escribe acá." },
  { id: "auth", label: "Auth", column: 4, editable: false, icon: "mdi-lock-outline",
    description: "Código de sesión generado al arrancar más JWT firmado (HS256) que protegen cada ruta de la API/WebSocket." },
  { id: "api", label: "API / WebSocket", column: 4, editable: false, icon: "mdi-api",
    description: "Puerta de entrada HTTP + WebSocket (wsbuilder) que expone todo lo anterior al dashboard." },
  { id: "dashboard", label: "Dashboard", column: 5, editable: false, icon: "mdi-view-dashboard",
    description: "La SPA Vue que estás usando ahora mismo - consume la API/WebSocket y muestra todo en vivo." },
];

const EDGE_DEFS = [
  ["sources", "sniffer"], ["sources", "honeypot"],
  ["runtime", "sniffer"], ["runtime", "honeypot"],
  ["sniffer", "monitors"], ["sniffer", "ai_lof"], ["sniffer", "ai_classifier"], ["sniffer", "store"],
  ["honeypot", "store"],
  ["monitors", "store"], ["ai_lof", "store"], ["ai_classifier", "store"],
  ["store", "api"], ["auth", "api"], ["api", "dashboard"],
];

const selectedId = ref(null);
function selectNode(id) {
  selectedId.value = selectedId.value === id ? null : id;
}
function goToSettings(tab) {
  if (!tab) return;
  emit("open-settings-tab", tab);
}

// --- Layout: fixed columns, same pattern as NeuralGraph.vue's columnX/rowY,
// simplified since every column here holds at most 3 nodes (no density
// tiers needed). ---
const TOP_MARGIN = 34;
const SIDE_MARGIN = 50;
const NODE_RADIUS = 16;
const ROW_HEIGHT = 74;
const viewBoxWidth = 920;

const columns = computed(() => COLUMN_LABELS.map((label, index) => ({ index, label })));
function columnX(index) {
  const usable = viewBoxWidth - SIDE_MARGIN * 2;
  const step = COLUMN_LABELS.length > 1 ? usable / (COLUMN_LABELS.length - 1) : 0;
  return SIDE_MARGIN + index * step;
}
const columnCounts = computed(() => {
  const counts = new Array(COLUMN_LABELS.length).fill(0);
  for (const def of NODE_DEFS) counts[def.column] += 1;
  return counts;
});
const maxRowsInAnyColumn = computed(() => Math.max(...columnCounts.value));
const viewBoxHeight = computed(() => TOP_MARGIN + maxRowsInAnyColumn.value * ROW_HEIGHT + 20);
function rowY(rowIndex, rowCount) {
  const offset = (maxRowsInAnyColumn.value - rowCount) / 2;
  return TOP_MARGIN + (offset + rowIndex + 0.5) * ROW_HEIGHT;
}

const nodes = computed(() => {
  const seenPerColumn = new Array(COLUMN_LABELS.length).fill(0);
  return NODE_DEFS.map((def) => {
    const rowIndex = seenPerColumn[def.column]++;
    return {
      ...def,
      x: columnX(def.column),
      y: rowY(rowIndex, columnCounts.value[def.column]),
      color: COLUMN_COLORS[def.column],
      hasStatus: !!def.statusKey,
      active: def.statusKey ? !!status.value[def.statusKey] : true,
    };
  });
});
const nodesById = computed(() => Object.fromEntries(nodes.value.map((n) => [n.id, n])));
const edges = computed(() =>
  EDGE_DEFS.map(([fromId, toId]) => {
    const from = nodesById.value[fromId];
    const to = nodesById.value[toId];
    return {
      x1: from.x, y1: from.y, x2: to.x, y2: to.y,
      color: interpolateRgb(from.color, to.color)(0.5),
      active: from.active,
    };
  })
);
const selected = computed(() => (selectedId.value ? nodesById.value[selectedId.value] : null));

// --- Life: a few traveling dots along the edges, same lightweight ambient
// touch as NeuralGraph.vue, so the diagram doesn't read as a frozen image. ---
const tick = ref(0);
let ambientTimer = null;
const pulseDots = computed(() => {
  const t = tick.value;
  // Only the active edges get a traveling pulse - a dashed, inactive edge
  // has nothing flowing through it right now.
  return edges.value.filter((edge) => edge.active).map((edge, i) => {
    const speed = 1400;
    const progress = ((t / speed + i / edges.value.length) % 1 + 1) % 1;
    return {
      id: `dot-${i}`,
      x: edge.x1 + (edge.x2 - edge.x1) * progress,
      y: edge.y1 + (edge.y2 - edge.y1) * progress,
      r: 1.8,
      color: edge.color,
      opacity: Math.max(0, Math.sin(progress * Math.PI)) * 0.7,
    };
  });
});

onMounted(() => {
  ambientTimer = d3Interval((elapsed) => { tick.value = elapsed; }, 60);
  loadStatus();
  statusTimer = setInterval(loadStatus, 8000);
});
onBeforeUnmount(() => {
  ambientTimer?.stop();
  clearInterval(statusTimer);
});
</script>
<style scoped>
.arch-graph { padding: 4px 2px; }
.arch-graph__hint { color: var(--text-dim); max-width: 620px; }
.arch-graph__hint .v-icon { vertical-align: -2px; }
.arch-graph__scroll { overflow: auto; max-height: 420px; }
.arch-graph__scroll svg { width: 100%; min-width: 640px; display: block; }
.arch-node { cursor: pointer; }
.arch-node text { pointer-events: none; }
.arch-node:focus circle:nth-of-type(2) { stroke: #fff; stroke-width: 3; }
.arch-node--selected circle:nth-of-type(2) { stroke: #fff; stroke-width: 2.5; }
.arch-node--inactive text { opacity: 0.55; }
.arch-node__ring { animation: arch-ring-spin 12s linear infinite; transform-origin: center; }
@keyframes arch-ring-spin {
  from { stroke-dashoffset: 0; }
  to { stroke-dashoffset: -24; }
}
.arch-node__icon { pointer-events: none; overflow: visible; }
.arch-node__icon i { display: block; width: 20px; height: 20px; line-height: 20px; font-size: 15px; text-align: center; color: #071019; }
.arch-signal-dot { pointer-events: none; filter: drop-shadow(0 0 2px currentColor); }

.arch-info-panel {
  margin-top: 10px;
  max-width: 420px;
  background: rgba(10, 20, 32, 0.85);
  border: 1px solid #8acbdf22;
  border-radius: 10px;
  padding: 10px 12px;
}
.arch-info-panel__head { display: flex; align-items: center; gap: 8px; font-size: 0.78rem; }
.arch-info-panel__dot { width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }
.arch-info-panel__desc { margin: 6px 0 8px; font-size: 0.68rem; color: var(--text-dim); line-height: 1.5; }
.arch-info-panel__actions { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
.arch-info-panel__readonly { font-size: 0.62rem; color: var(--text-dim); font-style: italic; }
</style>
