<template>
  <v-card class="tournament-graph pa-3" :class="`tournament-graph--${candidate.status || 'queued'}`" variant="tonal">
    <div class="tournament-graph__head">
      <span class="text-body-2 font-weight-bold">{{ shapeLabel }}</span>
      <v-chip size="x-small" :color="statusColor">{{ statusLabel }}</v-chip>
      <v-chip v-if="candidate.accuracy != null" size="x-small" variant="tonal">
        {{ Math.round(candidate.accuracy * 100) }}%
      </v-chip>
    </div>
    <div class="tournament-graph__progress">
      <span class="text-caption">Época {{ candidate.epoch || 0 }}/{{ candidate.total_epochs || 80 }}</span>
      <v-progress-linear
        :model-value="progressPercent"
        :color="statusColor"
        height="4"
        rounded
      />
      <span v-if="candidate.loss != null" class="text-caption">pérdida {{ candidate.loss.toFixed(4) }}</span>
    </div>
    <div class="tournament-graph__zoom">
      <v-btn icon size="x-small" variant="tonal" aria-label="Alejar" :disabled="zoom <= MIN_ZOOM" @click="zoomBy(-ZOOM_STEP)">
        <v-icon icon="mdi-magnify-minus-outline" size="14" />
      </v-btn>
      <span class="tournament-graph__zoom-level">{{ Math.round(zoom * 100) }}%</span>
      <v-btn icon size="x-small" variant="tonal" aria-label="Acercar" :disabled="zoom >= MAX_ZOOM" @click="zoomBy(ZOOM_STEP)">
        <v-icon icon="mdi-magnify-plus-outline" size="14" />
      </v-btn>
    </div>
    <div class="tournament-graph__scroll" @wheel="onWheel">
      <svg :viewBox="`0 0 ${viewBoxWidth} ${viewBoxHeight}`" preserveAspectRatio="xMidYMid meet" :style="{ transform: `scale(${zoom})` }" role="img" :aria-label="`Candidata ${shapeLabel}, ${statusLabel}`">
        <text v-for="(label, i) in columnLabels" :key="label" :x="columnX(i)" y="12" text-anchor="middle" fill="currentColor" font-size="8">{{ label }}</text>
        <line v-for="(edge, i) in edges" :key="`edge-${i}`" :x1="edge.x1" :y1="edge.y1" :x2="edge.x2" :y2="edge.y2" :stroke="edgeColor" stroke-width="0.6" :opacity="0.22" />
        <circle v-for="node in nodes" :key="node.id" :cx="node.x" :cy="node.y" :r="node.r" :fill="nodeColor" :class="{ 'tournament-node--training': candidate.status === 'training' }" />
      </svg>
    </div>
  </v-card>
</template>
<script setup>
import { computed, ref } from "vue";

const props = defineProps({
  candidate: { type: Object, required: true },
  featureCount: { type: Number, default: 8 },
});

const hiddenSizes = computed(() => props.candidate.hidden_sizes || []);
const columnSizes = computed(() => [props.featureCount, ...hiddenSizes.value, 1]);
const numColumns = computed(() => columnSizes.value.length);
const shapeLabel = computed(() => columnSizes.value.join(" → "));
const columnLabels = computed(() => [
  "Entrada",
  ...hiddenSizes.value.map((_, i) => `Oculta ${i + 1}`),
  "Salida",
]);

const STATUS_META = {
  queued: { label: "En cola", color: "grey" },
  training: { label: "Entrenando", color: "info" },
  done: { label: "Evaluada", color: "primary" },
  champion: { label: "Campeona", color: "success" },
  disqualified: { label: "Descalificada", color: "error" },
};
const statusLabel = computed(() => STATUS_META[props.candidate.status]?.label || "En cola");
const statusColor = computed(() => STATUS_META[props.candidate.status]?.color || "grey");
const nodeColor = computed(() => {
  if (props.candidate.status === "champion") return "#3ddc84";
  if (props.candidate.status === "disqualified") return "#ff6b84";
  if (props.candidate.status === "training") return "#0fe8ff";
  return "#6c8197";
});
const edgeColor = computed(() => nodeColor.value);
const progressPercent = computed(() => {
  const total = props.candidate.total_epochs || 80;
  return Math.min(100, Math.round(((props.candidate.epoch || 0) / total) * 100));
});

// Static grid layout only - no live weights/activations for an in-progress
// candidate (see store.get_ai_tournament_state()), so unlike NeuralGraph.vue
// this never needs the settle-animation/drag/weight-color machinery, just a
// topology sketch of the shape being trained.
const TOP_MARGIN = 20;
const SIDE_MARGIN = 30;
const viewBoxWidth = 260;
const ROW_HEIGHT = 16;
const NODE_RADIUS = 5;
const maxRowCount = computed(() => Math.max(...columnSizes.value));
const viewBoxHeight = computed(() => TOP_MARGIN + Math.min(maxRowCount.value, 14) * ROW_HEIGHT + 10);
function columnX(index) {
  const usable = viewBoxWidth - SIDE_MARGIN * 2;
  const step = numColumns.value > 1 ? usable / (numColumns.value - 1) : 0;
  return SIDE_MARGIN + index * step;
}
function rowY(index, rowCount) {
  const shown = Math.min(rowCount, 14);
  const offset = (Math.min(maxRowCount.value, 14) - shown) / 2;
  return TOP_MARGIN + (offset + Math.min(index, shown - 1)) * ROW_HEIGHT;
}
const columns = computed(() =>
  columnSizes.value.map((count, colIdx) => {
    const shown = Math.min(count, 14);
    return Array.from({ length: shown }, (_, i) => ({
      id: `${colIdx}_${i}`,
      x: columnX(colIdx),
      y: rowY(i, count),
      r: NODE_RADIUS,
    }));
  })
);
const nodes = computed(() => columns.value.flat());
const edges = computed(() => {
  const result = [];
  for (let c = 0; c < columns.value.length - 1; c++) {
    for (const from of columns.value[c]) {
      for (const to of columns.value[c + 1]) {
        result.push({ x1: from.x, y1: from.y, x2: to.x, y2: to.y });
      }
    }
  }
  return result;
});

const MIN_ZOOM = 0.5;
const MAX_ZOOM = 3;
const ZOOM_STEP = 0.25;
const zoom = ref(1);
function zoomBy(delta) {
  zoom.value = Math.min(MAX_ZOOM, Math.max(MIN_ZOOM, Math.round((zoom.value + delta) * 100) / 100));
}
function onWheel(event) {
  if (!event.ctrlKey && !event.metaKey) return;
  event.preventDefault();
  zoomBy(event.deltaY < 0 ? ZOOM_STEP : -ZOOM_STEP);
}
</script>
<style scoped>
.tournament-graph { border: 1px solid transparent; transition: border-color 0.2s ease; }
.tournament-graph--champion { border-color: #3ddc84; }
.tournament-graph--disqualified { opacity: 0.65; }
.tournament-graph--training { border-color: #0fe8ff55; }
.tournament-graph__head { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
.tournament-graph__progress { display: flex; align-items: center; gap: 8px; margin: 6px 0; }
.tournament-graph__progress .text-caption { min-width: 5.5em; }
.tournament-graph__zoom { display: flex; align-items: center; gap: 4px; margin-bottom: 4px; }
.tournament-graph__zoom-level { min-width: 3em; text-align: center; font-size: 0.65rem; color: var(--text-dim); }
.tournament-graph__scroll { overflow: auto; max-height: 160px; }
.tournament-graph__scroll svg { width: 100%; max-width: 320px; display: block; margin: 0 auto; transform-origin: top center; }
.tournament-node--training { animation: tournament-pulse 1.2s ease-in-out infinite; }
@keyframes tournament-pulse {
  0%, 100% { opacity: 0.5; }
  50% { opacity: 1; }
}
</style>
