<template>
  <v-card class="pa-4 mb-4" variant="tonal">
    <div class="d-flex flex-wrap ga-3 align-center">
      <h2 class="text-subtitle-1 font-weight-bold">Red neuronal · {{ shapeLabel }}</h2>
      <v-chip size="small">Revisión {{ learning.revision }}</v-chip>
      <v-chip :color="learning.ready ? 'success' : 'warning'" size="small">{{ learning.ready ? 'Modelo experimental' : 'Aprendizaje inicial' }}</v-chip>
    </div>
    <p class="mt-2 text-body-2">{{ packet ? `Activaciones reales del paquete #${packet.id}` : 'Selecciona un paquete para ver sus activaciones.' }} · Pesos azules positivos, rojos negativos. Pulsa una neurona para inspeccionarla.</p>
    <div class="network-scroll">
      <svg :viewBox="`0 0 ${viewBoxWidth} ${viewBoxHeight}`" role="img" aria-label="Red neuronal con pesos y activaciones reales">
        <text v-for="(label, i) in columnLabels" :key="label" :x="columnX(i)" y="14" text-anchor="middle" fill="currentColor" font-size="9">{{ label }}</text>
        <line v-for="(edge, i) in edges" :key="i" :x1="edge.from.x" :y1="edge.from.y" :x2="edge.to.x" :y2="edge.to.y"
          :stroke="edge.weight >= 0 ? '#56baff' : '#ff7788'" :stroke-width="Math.min(4, 0.3 + Math.abs(edge.weight))" opacity="0.4">
          <title>Peso {{ edge.weight.toFixed(5) }} · contribución {{ edge.contribution === null ? 'sin paquete' : edge.contribution.toFixed(5) }}</title>
        </line>
        <g v-for="node in nodes" :key="node.id" tabindex="0" role="button" :aria-label="`Inspeccionar ${node.label}`"
          class="neuron" @click="selectNode(node.id)" @keydown.enter="selectNode(node.id)" @keydown.space.prevent="selectNode(node.id)">
          <circle :cx="node.x" :cy="node.y" r="12" :fill="node.activation === null ? '#263344' : `hsl(${node.activation < 0 ? 350 : 195} 60% ${22 + Math.abs(node.activation) * 28}%)`"
            :stroke="selectedId === node.id ? '#fff' : '#6c8197'" stroke-width="1.5" />
          <text :x="node.x" :y="node.y + 3" text-anchor="middle" fill="white" font-size="7">{{ node.activation === null ? '—' : node.activation.toFixed(2) }}</text>
          <text :x="node.x" :y="node.y + 22" text-anchor="middle" fill="currentColor" font-size="7.5">{{ node.label }}</text>
        </g>
      </svg>
    </div>
    <p class="text-body-2">Umbral de decisión: {{ (learning.threshold * 100).toFixed(0) }}/100. {{ learning.ready ? 'La salida participa en la prioridad de revisión.' : 'La salida aún no participa en el score: hacen falta 3 ejemplos benignos y 3 maliciosos distintos.' }}</p>
    <v-expansion-panels v-model="openPanel" class="mt-3">
      <v-expansion-panel :title="`Inspección: ${selected?.label || 'selecciona una neurona'}`">
        <v-expansion-panel-text>
          <p v-if="selected">Activación: {{ selected.activation ?? 'sin paquete' }} · Sesgo: {{ selected.bias ?? 'no aplica' }} · Umbral de suma para activación cero (tanh) o 0.5 (sigmoide): {{ selected.bias === null ? 'no aplica' : -selected.bias }}</p>
          <v-table density="compact">
            <thead><tr><th>Entrada</th><th>Peso</th><th>Contribución al nodo</th></tr></thead>
            <tbody><tr v-for="edge in incoming" :key="edge.from.id"><td>{{ edge.from.label }}</td><td>{{ edge.weight.toFixed(6) }}</td><td>{{ edge.contribution?.toFixed(6) ?? '—' }}</td></tr></tbody>
          </v-table>
        </v-expansion-panel-text>
      </v-expansion-panel>
    </v-expansion-panels>
  </v-card>
</template>
<script setup>
import { computed, ref } from "vue";
const props = defineProps({ learning: { type: Object, required: true }, packet: { type: Object, default: null } });
const selectedId = ref("output");
const openPanel = ref(null);
function selectNode(id) { selectedId.value = id; openPanel.value = 0; }

// The hidden-layer shape is a configurable knob (Configuración > IA) -
// anywhere from 1 to MAX_HIDDEN_LAYERS layers, each with its own width -
// not always a single 6-neuron layer, so the whole graph is laid out from
// the model's actual persisted shape rather than an assumed one.
const hiddenSizes = computed(() =>
  Array.isArray(props.learning.hidden_sizes) && props.learning.hidden_sizes.length
    ? props.learning.hidden_sizes
    : props.learning.parameters.layers.slice(0, -1).map((layer) => layer.b.length)
);
const columnSizes = computed(() => [props.learning.feature_names.length, ...hiddenSizes.value, 1]);
const numColumns = computed(() => columnSizes.value.length);
const maxRows = computed(() => Math.max(...columnSizes.value));
const shapeLabel = computed(() => columnSizes.value.join(" → "));
const columnLabels = computed(() => [
  "Entrada",
  ...hiddenSizes.value.map((_, i) => `Oculta ${i + 1} (tanh)`),
  "Salida (sigmoide)",
]);

const ROW_HEIGHT = 30;
const TOP_MARGIN = 34;
const SIDE_MARGIN = 60;
const viewBoxWidth = 720;
const viewBoxHeight = computed(() => TOP_MARGIN + maxRows.value * ROW_HEIGHT + 14);
function columnX(index) {
  const usable = viewBoxWidth - SIDE_MARGIN * 2;
  const step = numColumns.value > 1 ? usable / (numColumns.value - 1) : 0;
  return SIDE_MARGIN + index * step;
}
function rowY(index, rowCount) {
  // Centers a shorter column vertically against the tallest one instead of
  // always top-aligning, so a 3-neuron layer next to a 16-neuron one still
  // reads as part of the same network rather than floating at the top.
  const offset = ((maxRows.value - rowCount) / 2) * ROW_HEIGHT;
  return TOP_MARGIN + offset + index * ROW_HEIGHT;
}

const columns = computed(() => {
  const a = props.packet?.activations;
  const cols = [];
  cols.push(
    props.learning.feature_names.map((label, i) => ({
      id: `c0_${i}`,
      label,
      x: columnX(0),
      y: rowY(i, props.learning.feature_names.length),
      activation: a?.input?.[i] ?? null,
      bias: null,
    }))
  );
  hiddenSizes.value.forEach((size, layerIdx) => {
    const layer = props.learning.parameters.layers[layerIdx];
    const col = [];
    for (let i = 0; i < size; i++) {
      col.push({
        id: `c${layerIdx + 1}_${i}`,
        label: `L${layerIdx + 1}·${i + 1}`,
        x: columnX(layerIdx + 1),
        y: rowY(i, size),
        activation: a?.hidden_layers?.[layerIdx]?.[i] ?? null,
        bias: layer.b[i],
      });
    }
    cols.push(col);
  });
  const outputLayer = props.learning.parameters.layers[props.learning.parameters.layers.length - 1];
  cols.push([
    {
      id: "output",
      label: "Riesgo",
      x: columnX(numColumns.value - 1),
      y: rowY(0, 1),
      activation: a?.output ?? null,
      bias: outputLayer.b[0],
    },
  ]);
  return cols;
});
const nodes = computed(() => columns.value.flat());
const edges = computed(() => {
  const result = [];
  const add = (from, to, weight) =>
    result.push({ from, to, weight, contribution: from.activation === null ? null : from.activation * weight });
  const layers = props.learning.parameters.layers;
  for (let layerIdx = 0; layerIdx < layers.length; layerIdx++) {
    const fromCol = columns.value[layerIdx];
    const toCol = columns.value[layerIdx + 1];
    layers[layerIdx].w.forEach((weights, j) => weights.forEach((weight, i) => add(fromCol[i], toCol[j], weight)));
  }
  return result;
});
const selected = computed(() => nodes.value.find((n) => n.id === selectedId.value));
const incoming = computed(() => edges.value.filter((e) => e.to.id === selectedId.value));
</script>
<style scoped>
.network-scroll { overflow: auto; max-height: 360px; }
/* The SVG's width:100% with no cap let it grow to fill a wide desktop
   viewport, and since the viewBox's aspect ratio is preserved, everything
   inside - circles, text, the whole layout - scaled up right along with it,
   which is what actually made the font/nodes look oversized. Capping the
   rendered width keeps it close to its designed (viewBox) scale on wide
   screens; it can still shrink on narrow ones. */
svg { width: 100%; max-width: 560px; min-width: 300px; display: block; margin: 0 auto; }
.neuron { cursor: pointer; }
.neuron:focus circle { stroke: white; stroke-width: 4; }
</style>
