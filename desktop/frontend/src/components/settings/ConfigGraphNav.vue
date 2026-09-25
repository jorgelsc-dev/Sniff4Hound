<template>
  <section class="config-workspace" :class="{ 'has-inspector': selected }">
    <header class="config-toolbar">
      <div class="config-title">
        <v-icon icon="mdi-source-branch" size="20" />
        <h1>Settings</h1>
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
              <g v-for="edge in edges" :key="edge.id" :class="{ 'is-related': edge.related, 'is-flowing': edge.active }">
                <path :d="edge.path" class="config-wire" :style="{ stroke: edge.color }" />
                <path v-if="edge.active" :d="edge.path" class="config-wire-signal" :style="{ stroke: edge.color, animationDelay: edge.delay }" />
              </g>
            </svg>
            <span
              v-for="(column, index) in GRAPH_COLUMNS"
              :key="column.label"
              class="config-column"
              :style="{ left: (40 + index * 312) + 'px', color: column.color }"
            >{{ column.label }}</span>
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
              @focus="revealNode(node)"
              @keydown.esc.stop="closeInspector"
            >
              <span class="config-node__head">
                <span class="config-node__icon"><v-icon :icon="node.icon" size="21" /></span>
                <strong>{{ node.label }}</strong>
                <v-icon icon="mdi-chevron-right" size="17" class="config-node__open" />
              </span>
              <span class="config-node__detail">{{ node.detail }}</span>
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
            <v-btn icon="mdi-minus" size="x-small" variant="text" :disabled="transform.k <= 0.35" aria-label="Alejar" @click="zoomBy(0.8)">
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
  GRAPH_COLUMNS, GRAPH_CARD, GRAPH_STORAGE_KEY, SETTINGS_NODES, SETTINGS_EDGES,
  defaultPosition, validPositions, graphBounds, connectionPath,
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
const transform = ref(zoomIdentity);
const nodeEls = new Map();
let selection;
let resizeObserver;
let resizeFrame;
const nodes = computed(() => SETTINGS_NODES.map(node => ({
  ...node,
  ...(positions.value[node.id] || defaultPosition(node)),
  color: GRAPH_COLUMNS[node.column].color,
  state: props.states[node.section] || { unknown: true, label: "Sin datos" },
})));
const selected = computed(() => nodes.value.find(node => node.section === props.modelValue));
const edges = computed(() => {
  const byId = Object.fromEntries(nodes.value.map(node => [node.id, node]));
  return SETTINGS_EDGES.map(([from, to], index) => ({
    id: from + "-" + to,
    path: connectionPath(byId[from], byId[to]),
    color: byId[from].color,
    active: Boolean(byId[from].state.active && byId[to].state.active),
    related: selected.value && [from, to].includes(selected.value.id),
    delay: (-index * 0.37) + "s",
  }));
});

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
  .scaleExtent([0.35, 1.8])
  .extent(() => [[0, 0], [viewport.value.clientWidth, viewport.value.clientHeight]])
  .filter(event => !event.target.closest(".config-node") && !event.button)
  .on("zoom", event => { transform.value = event.transform; });

function fitGraph() {
  if (!selection || !viewport.value.clientWidth) return;
  const bounds = graphBounds(nodes.value);
  const width = viewport.value.clientWidth;
  const height = viewport.value.clientHeight;
  // Keep cards readable on narrow screens; the canvas remains pannable.
  const scale = Math.max(0.62, Math.min(1, (width - 32) / bounds.width, (height - 30) / bounds.height));
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
  --config-bg: #111215;
  --config-panel: #191a1e;
  height: calc(100dvh - 92px);
  min-height: 560px;
  display: flex;
  flex-direction: column;
  color: #e8e9ec;
  background: var(--config-bg);
  border: 1px solid #303138;
  overflow: hidden;
  letter-spacing: 0;
}
.config-toolbar { min-height: 64px; flex: 0 0 auto; padding: 10px 18px; border-bottom: 1px solid #2d2e35; display: flex; align-items: center; justify-content: space-between; gap: 12px; background: #17181c; }
.config-title, .config-tools { display: flex; align-items: center; gap: 12px; min-width: 0; }
.config-title > .v-icon { color: #b79aeb; }
.config-title h1 { font-size: 19px; font-weight: 650; letter-spacing: 0; }
.config-project { font-size: 12px; color: #92949f; border-left: 1px solid #393a42; padding-left: 12px; }
.config-jump { width: 220px; }
.config-workspace__body { flex: 1; display: flex; min-height: 0; position: relative; }
.config-canvas-shell { flex: 1; min-width: 0; position: relative; overflow: hidden; }
.config-canvas { position: absolute; inset: 0 0 58px; overflow: hidden; outline: none; cursor: grab; touch-action: none; background-image: radial-gradient(#33343a 0.8px, transparent 0.8px); background-size: 22px 22px; }
.config-canvas:active { cursor: grabbing; }
.config-canvas:focus-visible { outline: 1px solid #b79aeb; outline-offset: -2px; }
.config-world { position: absolute; inset: 0; transform-origin: 0 0; will-change: transform; }
.config-wires { position: absolute; top: 0; left: 0; overflow: visible; pointer-events: none; }
.config-wire { fill: none; stroke-width: 1.4; opacity: 0.25; }
.is-related .config-wire { opacity: 0.85; stroke-width: 2; }
.config-wire-signal { fill: none; stroke-width: 2.4; stroke-dasharray: 8 160; animation: wire-flow 4s linear infinite; opacity: 0.75; }
.config-column { position: absolute; top: 22px; font-size: 12px; font-weight: 600; }
.config-node { position: absolute; width: 238px; height: 112px; padding: 14px 16px 0; border: 1px solid #3b3c44; border-radius: 8px; background: #1c1d22; color: #ebecef; text-align: left; cursor: grab; box-shadow: 0 5px 16px #0003; transition: border-color 160ms, background 160ms, box-shadow 160ms; user-select: none; touch-action: none; }
.config-node:hover { background: #24252b; border-color: var(--node-color); }
.config-node:active { cursor: grabbing; }
.config-node:focus-visible, .config-node.is-selected { outline: 2px solid var(--node-color); outline-offset: 3px; border-color: var(--node-color); box-shadow: 0 6px 24px #0006; }
.config-node__head { display: flex; align-items: center; gap: 9px; }
.config-node__head strong { font-size: 14px; font-weight: 600; flex: 1; letter-spacing: 0; }
.config-node__icon { color: var(--node-color); display: flex; }
.config-node__open { color: #7d7f8c; }
.config-node__detail { display: block; font-size: 11px; color: #a8aab5; margin: 7px 0 12px; }
.config-node__status { margin: 0 -16px; padding: 8px 14px; height: 31px; border-top: 1px solid #34353b; display: flex; align-items: center; gap: 7px; font-size: 10px; color: #aeb0ba; background: #ffffff03; border-radius: 0 0 8px 8px; }
.config-node__status > span:last-child { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.config-node__dot { width: 6px; height: 6px; flex: 0 0 6px; border-radius: 50%; background: #81838e; }
.is-running .config-node__dot { background: #69c798; }
.is-unknown .config-node__dot { background: #e4b96c; }
.config-node__port { position: absolute; width: 7px; height: 7px; border: 1px solid #70727e; border-radius: 50%; background: #202126; top: 52px; }
.config-node__port--in { left: -4px; }
.config-node__port--out { right: -4px; }
.config-canvas-tools { position: absolute; bottom: 0; left: 0; right: 0; height: 58px; padding: 10px 16px; display: flex; align-items: center; justify-content: space-between; gap: 10px; border-top: 1px solid #2d2e35; background: #17181c; }
.config-component-count { color: #999ba6; font-size: 11px; }
.config-zoom { display: flex; align-items: center; gap: 3px; }
.config-zoom output { width: 42px; text-align: center; font-size: 11px; color: #b2b4bf; font-variant-numeric: tabular-nums; }
.config-tool-divider { height: 18px; width: 1px; background: #3b3c43; margin: 0 5px; }
.config-overlay { position: absolute; inset: 0; z-index: 3; display: flex; align-items: center; justify-content: center; padding: 32px; background: #08080bd9; backdrop-filter: blur(3px); }
.config-overlay__card { display: flex; flex-direction: column; width: min(980px, 100%); max-height: 100%; background: var(--config-panel); border: 1px solid #3c3d45; border-top: 3px solid var(--node-color, #b79aeb); border-radius: 10px; box-shadow: 0 24px 60px #000a; overflow: hidden; }
.config-overlay__header { display: flex; align-items: center; gap: 12px; padding: 18px 22px; border-bottom: 1px solid #33343c; flex: 0 0 auto; }
.config-overlay__icon { display: flex; color: var(--node-color, #b79aeb); }
.config-overlay__title { flex: 1; min-width: 0; }
.config-overlay__title span { font-size: 11px; color: #aaaeba; }
.config-overlay__title h2 { font-size: 19px; font-weight: 600; letter-spacing: 0; overflow-wrap: break-word; }
.config-overlay__body { overflow: auto; flex: 1; padding: 22px; min-height: 0; scrollbar-gutter: stable; }
.config-overlay-enter-active, .config-overlay-leave-active { transition: opacity 180ms ease; }
.config-overlay-enter-active .config-overlay__card, .config-overlay-leave-active .config-overlay__card { transition: opacity 180ms ease, transform 180ms ease; }
.config-overlay-enter-from, .config-overlay-leave-to { opacity: 0; }
.config-overlay-enter-from .config-overlay__card, .config-overlay-leave-to .config-overlay__card { opacity: 0; transform: scale(0.96) translateY(8px); }
@keyframes wire-flow { to { stroke-dashoffset: -168; } }
@media (max-width: 1100px) { .config-project { display: none; } }
@media (max-width: 700px) {
  .config-workspace { height: calc(100dvh - 116px); min-height: 540px; }
  .config-toolbar { padding: 10px; gap: 8px; }
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
@media (prefers-reduced-motion: reduce) {
  .config-wire-signal { animation: none; }
  .config-node, .config-overlay-enter-active, .config-overlay-leave-active { transition: none; }
}
</style>
