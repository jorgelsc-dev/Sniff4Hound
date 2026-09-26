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
    <div class="tournament-graph__figure">
      <svg :viewBox="`0 0 ${VIEWBOX_WIDTH} ${viewBoxHeight}`" preserveAspectRatio="xMidYMid meet" role="img" :aria-label="graphLabel">
        <text v-for="column in columnMeta" :key="`label-${column.index}`" :x="column.x" y="10" text-anchor="middle" fill="currentColor" font-size="7" opacity="0.6">{{ column.label }}</text>
        <line v-for="(edge, i) in edges" :key="`edge-${i}`" :x1="edge.x1" :y1="edge.y1" :x2="edge.x2" :y2="edge.y2" :stroke="edgeColor" stroke-width="0.5" :opacity="0.2" />
        <circle v-for="node in nodes" :key="node.id" :cx="node.x" :cy="node.y" :r="NODE_RADIUS" :fill="nodeColor" :class="{ 'tournament-node--training': candidate.status === 'training' }" />
        <!-- A layer taller than MAX_ROWS is drawn clipped; saying so beats
             quietly sketching a different shape than the header claims. -->
        <text v-for="column in truncatedColumns" :key="`more-${column.index}`" :x="column.x" :y="viewBoxHeight - 2" text-anchor="middle" :fill="nodeColor" font-size="6" opacity="0.85">+{{ column.hidden }}</text>
      </svg>
    </div>
  </v-card>
</template>
<script setup>
import { computed } from "vue";

const props = defineProps({
  candidate: { type: Object, required: true },
  featureCount: { type: Number, default: 8 },
});

const hiddenSizes = computed(() => props.candidate.hidden_sizes || []);
const columnSizes = computed(() => [props.featureCount, ...hiddenSizes.value, 1]);
const numColumns = computed(() => columnSizes.value.length);
const shapeLabel = computed(() => columnSizes.value.join(" → "));
// Abbreviated on purpose. A deep candidate puts nine or more columns inside a
// fixed viewBox, where "Entrada"/"Oculta 1"/... are far wider than the space
// between two columns and run into each other - the header already spells the
// shape out in full.
const columnLabels = computed(() => [
  "Ent",
  ...hiddenSizes.value.map((_, i) => `H${i + 1}`),
  "Sal",
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
const TOP_MARGIN = 18;
const SIDE_MARGIN = 16;
const VIEWBOX_WIDTH = 300;
const ROW_HEIGHT = 11;
const NODE_RADIUS = 3.4;
const MAX_ROWS = 14;
const BOTTOM_MARGIN = 12;
const maxRowCount = computed(() => Math.min(Math.max(...columnSizes.value), MAX_ROWS));
const viewBoxHeight = computed(() => TOP_MARGIN + maxRowCount.value * ROW_HEIGHT + BOTTOM_MARGIN);
const graphLabel = computed(() => `Candidata ${shapeLabel.value}, ${statusLabel.value}`);

function columnX(index) {
  const usable = VIEWBOX_WIDTH - SIDE_MARGIN * 2;
  const step = numColumns.value > 1 ? usable / (numColumns.value - 1) : 0;
  return SIDE_MARGIN + index * step;
}
function rowY(index, rowCount) {
  const shown = Math.min(rowCount, MAX_ROWS);
  const offset = (maxRowCount.value - shown) / 2;
  return TOP_MARGIN + (offset + index) * ROW_HEIGHT;
}
const columnMeta = computed(() => columnSizes.value.map((count, index) => ({
  index,
  count,
  x: columnX(index),
  label: columnLabels.value[index],
  hidden: Math.max(0, count - MAX_ROWS),
})));
const truncatedColumns = computed(() => columnMeta.value.filter(column => column.hidden > 0));
const columns = computed(() =>
  columnSizes.value.map((count, colIdx) => {
    const shown = Math.min(count, MAX_ROWS);
    return Array.from({ length: shown }, (_, i) => ({
      id: `${colIdx}_${i}`,
      x: columnX(colIdx),
      y: rowY(i, count),
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

</script>
<style scoped>
.tournament-graph { border: 1px solid transparent; transition: border-color 0.2s ease; }
.tournament-graph--champion { border-color: #3ddc84; }
.tournament-graph--disqualified { opacity: 0.65; }
.tournament-graph--training { border-color: #0fe8ff55; }
.tournament-graph__head { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
.tournament-graph__progress { display: flex; align-items: center; gap: 8px; margin: 6px 0; }
.tournament-graph__progress .text-caption { min-width: 5.5em; }
/* No inner scroller: the viewBox already grows with the deepest layer, so the
   whole topology fits the card and the per-card zoom controls it used to need
   are gone with it. */
.tournament-graph__figure { margin-top: 2px; }
.tournament-graph__figure svg { width: 100%; height: auto; display: block; }
.tournament-node--training { animation: tournament-pulse 1.2s ease-in-out infinite; }
@keyframes tournament-pulse {
  0%, 100% { opacity: 0.5; }
  50% { opacity: 1; }
}
</style>
