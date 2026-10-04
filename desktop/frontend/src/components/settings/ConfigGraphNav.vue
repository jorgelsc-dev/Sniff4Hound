<template>
  <section class="config-workspace" :class="{ 'has-inspector': selected }">
    <header class="config-toolbar">
      <div class="config-title">
        <v-icon icon="mdi-source-branch" size="20" />
        <h1>Configuración</h1>
        <span class="config-project">Sniff4Hound</span>
      </div>
      <div class="config-tools">
        <v-select
          :model-value="modelValue"
          :items="SETTINGS_NODES"
          item-title="label"
          item-value="section"
          placeholder="Componentes"
          aria-label="Seleccionar componente"
          prepend-inner-icon="mdi-cube-outline"
          variant="outlined"
          density="compact"
          hide-details
          class="config-jump"
          @update:model-value="$emit('update:modelValue', $event)"
        />
        <v-btn icon="mdi-refresh" size="small" variant="text" :loading="refreshing" aria-label="Actualizar estados" @click="$emit('refresh')">
          <v-icon icon="mdi-refresh" />
          <v-tooltip activator="parent">Actualizar estados</v-tooltip>
        </v-btn>
      </div>
    </header>

    <div class="config-workspace__body">
      <div class="config-canvas-shell">
        <div
          ref="viewport"
          class="config-canvas"
          tabindex="0"
          aria-label="Grafo de configuración"
          @keydown.esc="closeInspector"
        >
          <div ref="world" class="config-world" :style="{ transform: `translate(${transform.x}px, ${transform.y}px) scale(${transform.k})` }">
            <svg class="config-wires" width="1" height="1" aria-hidden="true">
              <defs>
                <marker id="config-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
                  <path d="M0,0 L10,5 L0,10 z" fill-opacity="0.9" style="fill: context-stroke" />
                </marker>
              </defs>
              <!-- Only wires carrying real traffic are drawn: an idle link shows nothing. -->
              <g v-for="edge in flowingEdges" :key="edge.id" :class="{ 'is-related': edge.related }">
                <path :d="edge.path" class="config-wire" :style="{ '--wire-color': edge.color }" marker-end="url(#config-arrow)" />
              </g>
            </svg>
            <span
              v-for="edge in flowingEdges"
              :key="'label-' + edge.id"
              class="config-edge-label"
              :class="{ 'is-related': edge.related }"
              :style="{ left: edge.mid.x + 'px', top: edge.mid.y + 'px', '--edge-color': edge.color }"
            >{{ edge.label }}</span>
            <button
              v-for="node in nodes"
              :key="node.id"
              :ref="el => setNodeEl(node.id, el)"
              type="button"
              class="config-node"
              :class="{ 'is-selected': modelValue === node.section, 'is-running': node.state.active }"
              :data-node="node.id"
              :style="{ left: node.x + 'px', top: node.y + 'px', '--node-color': node.color }"
              :aria-label="'Configurar ' + node.label"
              :aria-expanded="modelValue === node.section"
              aria-controls="settings-inspector"
              @click="$emit('update:modelValue', node.section)"
              @mouseenter="hoveredId = node.id"
              @mouseleave="hoveredId = ''"
              @focus="revealNode(node)"
              @keydown.esc.stop="closeInspector"
            >
              <span class="config-node__head">
                <span class="config-node__icon"><v-icon :icon="node.icon" size="18" /></span>
                <strong>{{ node.label }}</strong>
                <v-icon icon="mdi-chevron-right" size="16" class="config-node__open" />
              </span>
              <span class="config-node__detail">{{ node.detail }}</span>
              <span v-if="node.state.metrics?.length" class="config-node__metrics">
                <span
                  v-for="metric in node.state.metrics"
                  :key="metric.label"
                  class="config-node__metric"
                  :class="metric.tone ? 'is-' + metric.tone : ''"
                >
                  <small>{{ metric.label }}</small>
                  <strong :title="String(metric.value)">{{ metric.value }}</strong>
                </span>
              </span>
              <span class="config-node__status" :class="{ 'is-unknown': node.state.unknown }">
                <span class="config-node__dot" />
                <span>{{ node.state.label || "Ajustes" }}</span>
              </span>
              <span class="config-node__port config-node__port--in" />
              <span class="config-node__port config-node__port--out" />
            </button>
          </div>
        </div>
        <div class="config-canvas-tools">
          <span class="config-component-count">{{ nodes.length }} componentes</span>
          <div class="config-zoom">
            <v-btn icon="mdi-minus" size="x-small" variant="text" :disabled="transform.k <= 0.15" aria-label="Alejar" @click="zoomBy(0.8)">
              <v-icon icon="mdi-minus" /><v-tooltip activator="parent">Alejar</v-tooltip>
            </v-btn>
            <output aria-label="Zoom">{{ Math.round(transform.k * 100) }}%</output>
            <v-btn icon="mdi-plus" size="x-small" variant="text" :disabled="transform.k >= 1.8" aria-label="Acercar" @click="zoomBy(1.25)">
              <v-icon icon="mdi-plus" /><v-tooltip activator="parent">Acercar</v-tooltip>
            </v-btn>
            <span class="config-tool-divider" />
            <v-btn icon="mdi-fit-to-screen-outline" size="x-small" variant="text" aria-label="Ajustar grafo" @click="fitGraph">
              <v-icon icon="mdi-fit-to-screen-outline" /><v-tooltip activator="parent">Ajustar grafo</v-tooltip>
            </v-btn>
            <v-btn icon="mdi-auto-fix" size="x-small" variant="text" aria-label="Restablecer posiciones" @click="resetLayout">
              <v-icon icon="mdi-auto-fix" /><v-tooltip activator="parent">Restablecer posiciones</v-tooltip>
            </v-btn>
          </div>
        </div>
      </div>

      <Transition name="config-overlay">
        <div v-show="selected" class="config-overlay" @click.self="closeInspector">
          <div
            id="settings-inspector"
            class="config-overlay__card"
            role="dialog"
            aria-modal="true"
            aria-labelledby="config-inspector-title"
            :style="{ '--node-color': selected?.color }"
            @keydown.esc="closeInspector"
          >
            <header class="config-overlay__header">
              <span class="config-overlay__icon"><v-icon :icon="selected?.icon || 'mdi-cog-outline'" /></span>
              <div class="config-overlay__title">
                <span>{{ selected?.detail }}</span>
                <h2 id="config-inspector-title">{{ selected?.label }}</h2>
              </div>
              <v-btn icon="mdi-close" size="small" variant="text" aria-label="Cerrar configuración" @click="closeInspector">
                <v-icon icon="mdi-close" /><v-tooltip activator="parent">Cerrar configuración</v-tooltip>
              </v-btn>
            </header>
            <div ref="inspectorBody" class="config-overlay__body">
              <slot />
            </div>
          </div>
        </div>
      </Transition>
    </div>
  </section>
</template>

<script setup>
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from "vue";
import { drag, select, zoom, zoomIdentity } from "d3";
import {
  GRAPH_LANES, GRAPH_CARD, GRAPH_STORAGE_KEY, SETTINGS_NODES, SETTINGS_EDGES,
  defaultPosition, validPositions, graphBounds, connectionPath, edgeMidpoint,
} from "./settingsGraph";

const props = defineProps({
  modelValue: { type: String, default: "" },
  states: { type: Object, default: () => ({}) },
  refreshing: { type: Boolean, default: false },
});
const emit = defineEmits(["update:modelValue", "refresh"]);
const viewport = ref(null);
const world = ref(null);
const inspectorBody = ref(null);
const positions = ref({});
const hoveredId = ref("");
const transform = ref(zoomIdentity);
const nodeEls = new Map();
let selection;
let resizeObserver;
let resizeFrame;
const nodes = computed(() => SETTINGS_NODES.map(node => ({
  ...node,
  ...(positions.value[node.id] || defaultPosition(node)),
  color: GRAPH_LANES[node.lane].color,
  state: props.states[node.section] || { unknown: true, label: "Sin datos" },
})));
const selected = computed(() => nodes.value.find(node => node.section === props.modelValue));
const edges = computed(() => {
  const byId = Object.fromEntries(nodes.value.map(node => [node.id, node]));
  const focus = hoveredId.value || selected.value?.id || "";
  return SETTINGS_EDGES.map((edge) => {
    const from = byId[edge.from];
    const to = byId[edge.to];
    const ends = [edge.from, edge.to];
    return {
      id: edge.from + "-" + edge.to,
      label: edge.label,
      path: connectionPath(from, to),
      mid: edgeMidpoint(from, to),
      color: from.color,
      active: Boolean(from.state.active && to.state.active),
      related: Boolean(focus) && ends.includes(focus),
    };
  });
});
const flowingEdges = computed(() => edges.value.filter(edge => edge.active));

function setNodeEl(id, el) {
  if (el) nodeEls.set(id, el);
  else nodeEls.delete(id);
}
function savePositions() {
  try { localStorage.setItem(GRAPH_STORAGE_KEY, JSON.stringify(positions.value)); } catch { /* Session-only layout when storage is unavailable. */ }
}
function closeInspector() {
  const id = selected.value?.id;
  emit("update:modelValue", "");
  nextTick(() => nodeEls.get(id)?.focus({ preventScroll: true }));
}
const zoomBehavior = zoom()
  .scaleExtent([0.15, 1.8])
  .extent(() => [[0, 0], [viewport.value.clientWidth, viewport.value.clientHeight]])
  .filter(event => !event.target.closest(".config-node") && !event.button)
  .on("zoom", event => { transform.value = event.transform; });

function fitGraph() {
  if (!selection || !viewport.value.clientWidth) return;
  const bounds = graphBounds(nodes.value);
  const width = viewport.value.clientWidth;
  const height = viewport.value.clientHeight;
  // Fit the entire graph; zoom and the section selector retain access to details.
  const scale = Math.max(0.15, Math.min(1, (width - 32) / bounds.width, (height - 30) / bounds.height));
  const x = width < bounds.width * scale ? 16 - bounds.x * scale : (width - bounds.width * scale) / 2 - bounds.x * scale;
  const y = Math.max(12, (height - bounds.height * scale) / 2) - bounds.y * scale;
  selection.call(zoomBehavior.transform, zoomIdentity.translate(x, y).scale(scale));
}
function zoomBy(factor) {
  selection?.call(zoomBehavior.scaleBy, factor);
}
function resetLayout() {
  positions.value = {};
  savePositions();
  fitGraph();
}
function revealNode(node) {
  if (!selection) return;
  const [x, y] = transform.value.apply([node.x, node.y]);
  const width = GRAPH_CARD.width * transform.value.k;
  const height = GRAPH_CARD.height * transform.value.k;
  if (x < 0 || y < 0 || x + width > viewport.value.clientWidth || y + height > viewport.value.clientHeight) {
    selection.call(zoomBehavior.translateTo, node.x + GRAPH_CARD.width / 2, node.y + GRAPH_CARD.height / 2);
  }
}

watch(() => props.modelValue, () => {
  if (inspectorBody.value) inspectorBody.value.scrollTop = 0;
});
onMounted(() => {
  try { positions.value = validPositions(JSON.parse(localStorage.getItem(GRAPH_STORAGE_KEY))); } catch { /* Use the default layout. */ }
  selection = select(viewport.value).call(zoomBehavior).on("dblclick.zoom", null);
  const nodeDrag = drag()
    .container(() => viewport.value)
    .clickDistance(5)
    .subject((_event, id) => {
      const node = nodes.value.find(item => item.id === id);
      const [x, y] = transform.value.apply([node.x, node.y]);
      return { x, y };
    })
    .on("drag", (event, id) => {
      const [x, y] = transform.value.invert([event.x, event.y]);
      positions.value[id] = { x, y };
    })
    .on("end", savePositions);
  for (const [id, el] of nodeEls) select(el).datum(id).call(nodeDrag);
  resizeObserver = new ResizeObserver(() => {
    cancelAnimationFrame(resizeFrame);
    resizeFrame = requestAnimationFrame(fitGraph);
  });
  resizeObserver.observe(viewport.value);
  fitGraph();
});
onBeforeUnmount(() => {
  resizeObserver?.disconnect();
  cancelAnimationFrame(resizeFrame);
  selection?.on(".zoom", null);
  for (const el of nodeEls.values()) select(el).on(".drag", null);
});
</script>

<style scoped>
.config-workspace {
  --config-bg: var(--bg-0);
  --config-panel: var(--surface-1);
  height: var(--app-canvas-height);
  min-height: 0;
  display: flex;
  flex-direction: column;
  color: var(--text-soft);
  background: var(--config-bg);
  border: 0;
  border-radius: 0;
  overflow: hidden;
  letter-spacing: 0;
}
.config-toolbar { min-height: 58px; flex: 0 0 auto; padding: 10px 16px; border-bottom: 1px solid var(--stroke); display: flex; align-items: center; justify-content: space-between; gap: 12px; background: var(--surface-1); }
.config-title, .config-tools { display: flex; align-items: center; gap: 12px; min-width: 0; }
.config-title > .v-icon { color: #b79aeb; }
.config-title h1 { font-size: 19px; font-weight: 650; letter-spacing: 0; white-space: nowrap; }
.config-project { font-size: 12px; color: var(--text-dim); border-left: 1px solid var(--stroke); padding-left: 12px; }
.config-jump { width: 220px; }
.config-workspace__body { flex: 1; display: flex; min-height: 0; position: relative; }
.config-canvas-shell { flex: 1; min-width: 0; position: relative; overflow: hidden; }
.config-canvas { position: absolute; inset: 0 0 54px; overflow: hidden; outline: none; cursor: grab; touch-action: none; background-color: var(--surface-0); background-image: radial-gradient(rgba(255, 255, 255, 0.07) 0.8px, transparent 0.8px); background-size: 22px 22px; }
.config-canvas:active { cursor: grabbing; }
.config-canvas:focus-visible { outline: 1px solid #b79aeb; outline-offset: -2px; }
.config-world { position: absolute; inset: 0; transform-origin: 0 0; will-change: transform; }
.config-wires { position: absolute; top: 0; left: 0; overflow: visible; pointer-events: none; }
.config-wire {
  fill: none; stroke: var(--wire-color); stroke-width: 2.4; stroke-linecap: round;
  filter: drop-shadow(0 0 4px var(--wire-color));
  transition: stroke-width 160ms;
}
.is-related .config-wire { stroke-width: 3.4; }
.config-edge-label {
  position: absolute; transform: translate(-50%, -50%); padding: 2px 7px; border-radius: 999px;
  font-size: 10px; line-height: 14px; white-space: nowrap; color: var(--edge-color); background: var(--surface-0);
  border: 1px solid color-mix(in srgb, var(--edge-color) 40%, transparent); pointer-events: none;
  transition: opacity 160ms, color 160ms;
}
.config-edge-label.is-related { font-weight: 600; box-shadow: 0 0 0 3px var(--surface-0); }
.config-node { position: absolute; width: 252px; height: 176px; box-sizing: border-box; padding: 12px 14px 0; display: flex; flex-direction: column; border: 1px solid var(--stroke); border-radius: 10px; background: linear-gradient(180deg, color-mix(in srgb, var(--node-color) 8%, transparent), transparent 55%), var(--surface-1); color: var(--text-soft); text-align: left; cursor: grab; box-shadow: 0 1px 0 rgba(255, 255, 255, 0.02) inset; transition: border-color 160ms, background 160ms, box-shadow 160ms; user-select: none; touch-action: none; overflow: hidden; }
.config-node::before { content: ""; position: absolute; left: 14px; right: 14px; top: 0; height: 2px; border-radius: 0 0 2px 2px; background: var(--node-color); opacity: 0.85; }
.config-node:hover { background: var(--surface-2); border-color: var(--node-color); }
.config-node:active { cursor: grabbing; }
.config-node:focus-visible, .config-node.is-selected { outline: 2px solid var(--node-color); outline-offset: 3px; border-color: var(--node-color); box-shadow: 0 8px 24px rgba(0, 0, 0, 0.36); }
.config-node__head { display: flex; align-items: center; gap: 9px; }
.config-node__head strong { font-size: 13.5px; font-weight: 600; flex: 1; min-width: 0; letter-spacing: 0; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.config-node__icon { color: var(--node-color); display: flex; }
.config-node__open { color: #7d7f8c; }
.config-node__detail { display: block; font-size: 11px; color: var(--text-dim); margin: 4px 0 0; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.config-node__metrics { display: grid; grid-template-columns: 1fr 1fr; gap: 6px; margin-top: 10px; }
.config-node__metric { display: flex; flex-direction: column; gap: 2px; min-width: 0; padding: 5px 8px; border-radius: 6px; background: rgba(255, 255, 255, 0.035); border: 1px solid rgba(255, 255, 255, 0.045); }
.config-node__metric small { font-size: 9px; text-transform: uppercase; letter-spacing: 0.06em; color: var(--text-dim); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.config-node__metric strong { font-size: 12.5px; font-weight: 600; color: var(--text-soft); font-variant-numeric: tabular-nums; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.config-node__metric.is-ok strong { color: #69c798; }
.config-node__metric.is-warn strong { color: #e4b96c; }
.config-node__metric.is-alert strong { color: #ef7a7a; }
.config-node__status { margin: auto -14px 0; padding: 0 14px; height: 30px; border-top: 1px solid var(--stroke); display: flex; align-items: center; gap: 7px; font-size: 10px; color: var(--text-dim); background: rgba(255, 255, 255, 0.025); }
.config-node__status > span:last-child { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.config-node__dot { width: 6px; height: 6px; flex: 0 0 6px; border-radius: 50%; background: #81838e; }
.is-running .config-node__dot { background: #69c798; }
.is-unknown .config-node__dot { background: #e4b96c; }
.config-node__port { position: absolute; width: 7px; height: 7px; border: 1px solid #70727e; border-radius: 50%; background: #202126; top: 44px; }
.config-node__port--in { left: -4px; }
.config-node__port--out { right: -4px; }
.config-canvas-tools { position: absolute; bottom: 0; left: 0; right: 0; height: 54px; padding: 9px 16px; display: flex; align-items: center; justify-content: space-between; gap: 10px; border-top: 1px solid var(--stroke); background: var(--surface-1); }
.config-component-count { color: var(--text-dim); font-size: 11px; }
.config-zoom { display: flex; align-items: center; gap: 3px; }
.config-zoom output { width: 42px; text-align: center; font-size: 11px; color: #b2b4bf; font-variant-numeric: tabular-nums; }
.config-tool-divider { height: 18px; width: 1px; background: #3b3c43; margin: 0 5px; }
.config-overlay { position: absolute; inset: 0; z-index: 3; display: flex; align-items: center; justify-content: center; padding: 32px; background: rgba(5, 8, 12, 0.84); backdrop-filter: blur(8px); }
.config-overlay__card { display: flex; flex-direction: column; width: min(980px, 100%); max-height: 100%; background: var(--config-panel); border: 1px solid var(--stroke-strong); border-top: 3px solid var(--node-color, #b79aeb); border-radius: 8px; box-shadow: 0 24px 60px rgba(0, 0, 0, 0.62); overflow: hidden; }
.config-overlay__header { display: flex; align-items: center; gap: 12px; padding: 16px 20px; border-bottom: 1px solid var(--stroke); flex: 0 0 auto; }
.config-overlay__icon { display: flex; color: var(--node-color, #b79aeb); }
.config-overlay__title { flex: 1; min-width: 0; }
.config-overlay__title span { font-size: 11px; color: #aaaeba; }
.config-overlay__title h2 { font-size: 19px; font-weight: 600; letter-spacing: 0; overflow-wrap: break-word; }
.config-overlay__body { overflow: auto; flex: 1; padding: 22px; min-height: 0; scrollbar-gutter: stable; }
.config-overlay-enter-active, .config-overlay-leave-active { transition: opacity 180ms ease; }
.config-overlay-enter-active .config-overlay__card, .config-overlay-leave-active .config-overlay__card { transition: opacity 180ms ease, transform 180ms ease; }
.config-overlay-enter-from, .config-overlay-leave-to { opacity: 0; }
.config-overlay-enter-from .config-overlay__card, .config-overlay-leave-to .config-overlay__card { opacity: 0; transform: scale(0.96) translateY(8px); }
@media (max-width: 1100px) { .config-project { display: none; } }
@media (max-width: 700px) {
  .config-toolbar { padding: 10px; gap: 8px; flex-wrap: wrap; }
  .config-title { gap: 6px; }
  .config-title h1 { font-size: 17px; }
  .config-jump { width: 154px; }
  .config-tools { gap: 2px; }
  .config-overlay { padding: 0; }
  .config-overlay__card { width: 100%; height: 100%; max-height: 100%; border-radius: 0; border-left: 0; border-right: 0; }
  .config-overlay__header { padding: 12px 14px; }
  .config-overlay__body { padding: 14px; }
  .config-component-count { display: none; }
  .config-canvas-tools { justify-content: center; }
}
@media (max-width: 480px) {
  .config-tools { flex: 1 1 100%; }
  .config-jump { width: auto; flex: 1; }
  .config-title h1 { font-size: 16px; }
}
@media (prefers-reduced-motion: reduce) {
    .config-node, .config-overlay-enter-active, .config-overlay-leave-active { transition: none; }
}
</style>
