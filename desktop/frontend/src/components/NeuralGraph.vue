<template>
  <v-card :class="[immersive ? 'neural-stage' : 'pa-4 mb-4']" :variant="immersive ? 'flat' : 'tonal'">
    <div class="neural-graph-header">
      <div class="d-flex flex-wrap ga-3 align-center">
        <h2 class="text-subtitle-1 font-weight-bold">Red neuronal · {{ shapeLabel }}</h2>
        <v-chip size="small">Revisión {{ learning.revision }}</v-chip>
        <v-chip :color="learning.ready ? 'success' : 'warning'" size="small">{{ learning.ready ? 'Modelo experimental' : 'Aprendizaje inicial' }}</v-chip>
      </div>
      <p class="mt-2 text-body-2">{{ packet ? `Activaciones reales del paquete #${packet.id}` : 'Selecciona un paquete para ver sus activaciones.' }} · Pesos azules positivos, rojos negativos. Pulsa una neurona para inspeccionarla.{{ editable ? ' Usa los controles + / × sobre la red para editar capas y neuronas.' : '' }}</p>
      <slot name="hud-extra" />
    </div>
    <div class="network-zoom-toolbar">
      <v-btn icon size="x-small" variant="tonal" aria-label="Alejar" :disabled="zoom <= MIN_ZOOM" @click="zoomBy(-ZOOM_STEP)">
        <v-icon icon="mdi-magnify-minus-outline" size="16" />
      </v-btn>
      <span class="network-zoom-level">{{ Math.round(zoom * 100) }}%</span>
      <v-btn icon size="x-small" variant="tonal" aria-label="Acercar" :disabled="zoom >= MAX_ZOOM" @click="zoomBy(ZOOM_STEP)">
        <v-icon icon="mdi-magnify-plus-outline" size="16" />
      </v-btn>
      <v-btn size="x-small" variant="text" class="ml-1" :disabled="isDefaultView" @click="resetZoom">Ajustar vista</v-btn>
    </div>
    <div class="network-scroll">
      <svg ref="svgRoot" :viewBox="`0 0 ${viewBoxWidth} ${viewBoxHeight}`" preserveAspectRatio="xMidYMid meet" :class="{ 'neural-svg--immersive': immersive }" role="img" aria-label="Red neuronal con pesos y activaciones reales, animada en tiempo real">
        <g ref="zoomLayer">
          <text v-for="(label, i) in columnLabels" :key="label" :x="columnX(i)" y="14" text-anchor="middle" fill="currentColor" font-size="9">{{ label }}</text>
          <line v-for="(edge, i) in edges" :key="`edge-${i}`" :x1="edge.from.x" :y1="edge.from.y" :x2="edge.to.x" :y2="edge.to.y"
            :stroke="edge.color" :stroke-width="Math.min(4, 0.3 + edge.magnitude * 3.4)" :opacity="0.16 + edge.magnitude * 0.34"
            :stroke-dasharray="edge.pending ? '4 3' : null">
            <title>{{ edge.pending ? 'Conexión pendiente de guardar (sin pesos entrenados aún)' : `Peso ${edge.weight.toFixed(5)} · contribución ${edge.contribution === null ? 'sin paquete' : edge.contribution.toFixed(5)}` }}</title>
          </line>
          <circle v-for="dot in pulseDots" :key="dot.id" :cx="dot.x" :cy="dot.y" :r="dot.r" :fill="dot.color" :opacity="dot.opacity" class="signal-dot" />
          <g v-for="node in nodes" :key="node.id" :ref="(el) => setNodeEl(node.id, el)" tabindex="0" role="button" :aria-label="`Inspeccionar ${node.label}`"
            class="neuron" :class="{ 'is-dragging': draggingId === node.id, 'is-pending': node.pending }"
            @click="selectNode(node.id)" @keydown.enter="selectNode(node.id)" @keydown.space.prevent="selectNode(node.id)"
            @pointerenter="hoveredId = node.id" @pointerleave="hoveredId = hoveredId === node.id ? null : hoveredId">
            <title>{{ node.label }}{{ node.pending ? ' · pendiente de guardar' : '' }}{{ node.activation === null ? '' : ` · ${node.activation.toFixed(3)}` }}</title>
            <circle class="neuron-halo" :cx="node.x" :cy="node.y" :r="haloRadius(node)" :fill="node.color" :opacity="node.glow" />
            <circle :cx="node.x" :cy="node.y" :r="nodeRadius(node)" :fill="node.color"
              :stroke="selectedId === node.id ? '#fff' : node.pending ? '#c9b8ff' : '#6c8197'" stroke-width="1.5"
              :stroke-dasharray="node.pending ? '2 2' : null" />
            <text v-if="nodeRadius(node) >= 9" :x="node.x" :y="node.y + 3" text-anchor="middle" fill="white" font-size="7">{{ node.activation === null ? '—' : node.activation.toFixed(2) }}</text>
            <text v-if="labelVisible(node)" :x="node.x" :y="node.y + nodeRadius(node) + 10" text-anchor="middle" fill="currentColor" font-size="7.5">{{ node.label }}</text>
          </g>
          <g v-if="editable" class="rnn-editor-layer">
            <g v-for="ctl in neuronAddControls" :key="ctl.id" class="editor-control editor-control--add"
              tabindex="0" role="button" :aria-label="`Añadir neurona a la ${ctl.layerLabel}`"
              @click="addNeuron(ctl.layerIdx)" @keydown.enter="addNeuron(ctl.layerIdx)" @keydown.space.prevent="addNeuron(ctl.layerIdx)">
              <circle :cx="ctl.x" :cy="ctl.y" r="7" />
              <text :x="ctl.x" :y="ctl.y + 3" text-anchor="middle">+</text>
            </g>
            <g v-for="ctl in neuronRemoveControls" :key="ctl.id" class="editor-control editor-control--remove"
              tabindex="0" role="button" :aria-label="`Quitar una neurona de la ${ctl.layerLabel}`"
              @click.stop="removeNeuron(ctl.layerIdx)" @keydown.enter="removeNeuron(ctl.layerIdx)" @keydown.space.prevent="removeNeuron(ctl.layerIdx)">
              <circle :cx="ctl.x" :cy="ctl.y" r="6" />
              <text :x="ctl.x" :y="ctl.y + 3" text-anchor="middle">×</text>
            </g>
            <g v-if="layerRemoveControl" class="editor-control editor-control--remove-layer"
              tabindex="0" role="button" aria-label="Quitar la última capa oculta"
              @click="removeLastLayer" @keydown.enter="removeLastLayer" @keydown.space.prevent="removeLastLayer">
              <circle :cx="layerRemoveControl.x" :cy="layerRemoveControl.y" r="6" />
              <text :x="layerRemoveControl.x" :y="layerRemoveControl.y + 3" text-anchor="middle">×</text>
            </g>
            <g class="editor-control editor-control--add-layer"
              tabindex="0" role="button" aria-label="Añadir una capa oculta al final de la red"
              @click="addHiddenLayer" @keydown.enter="addHiddenLayer" @keydown.space.prevent="addHiddenLayer">
              <circle :cx="addLayerControl.x" :cy="addLayerControl.y" r="9" />
              <text :x="addLayerControl.x" :y="addLayerControl.y + 4" text-anchor="middle">+</text>
              <text :x="addLayerControl.x" :y="addLayerControl.y + 19" text-anchor="middle" class="editor-control__label">Capa</text>
            </g>
          </g>
        </g>
      </svg>
    </div>
    <p v-if="!immersive" class="text-body-2">Umbral de decisión: {{ (learning.threshold * 100).toFixed(0) }}/100. {{ learning.ready ? 'La salida participa en la prioridad de revisión.' : 'La salida aún no participa en el score: hacen falta 3 ejemplos benignos y 3 maliciosos distintos.' }}</p>

    <div v-if="editable && learningConfigDraft" class="network-editor-panel">
      <div class="network-editor-panel__head">
        <span class="network-editor-panel__title">AJUSTES DEL MOTOR</span>
        <v-chip size="x-small" color="primary">{{ hiddenSizes.length }} capa(s) · {{ hiddenSizes.join('-') }}</v-chip>
        <v-chip v-if="effectiveness.ready" size="x-small" :color="effectivenessColor">
          Acierto en entrenamiento {{ Math.round(effectiveness.accuracy * 100) }}% ({{ effectiveness.correct }}/{{ effectiveness.total }})
          <v-tooltip activator="parent">Medido sobre los mismos ejemplos con los que el modelo entrenó (resustitución), no sobre datos no vistos.</v-tooltip>
        </v-chip>
        <v-chip v-else size="x-small" color="warning">Pendiente de evaluar<v-tooltip activator="parent">Se necesitan al menos 3 revisiones benignas y 3 maliciosas.</v-tooltip></v-chip>
      </div>
      <p class="network-editor-panel__hint">Pulsa + para añadir una neurona o capa; pulsa × para quitar la última de una capa o la última capa oculta.</p>
      <v-alert v-if="suggestion.architecture" type="info" variant="tonal" density="compact" class="mt-2">
        <div class="d-flex flex-wrap align-center ga-2">
          <div class="flex-grow-1">
            Sugerencia: <strong>{{ suggestion.architecture.hidden_sizes.join('-') }}</strong>
            ({{ Math.round(suggestion.architecture.suggested_accuracy * 100) }}% vs {{ Math.round(suggestion.architecture.current_accuracy * 100) }}%)
          </div>
          <div class="d-flex ga-1">
            <v-btn size="x-small" color="primary" :loading="suggestionBusy === 'architecture'" @click="applySuggestion('architecture')">Aplicar</v-btn>
            <v-btn size="x-small" variant="text" :disabled="!!suggestionBusy" @click="dismissSuggestion('architecture')">Descartar</v-btn>
          </div>
        </div>
      </v-alert>
      <v-alert v-if="suggestion.cohort" type="info" variant="tonal" density="compact" class="mt-2">
        <div class="d-flex flex-wrap align-center ga-2">
          <div class="flex-grow-1">
            Sugerencia LOF: <strong>{{ suggestion.cohort.min_cohort }}</strong>
            (separación {{ suggestion.cohort.suggested_separation }} vs {{ suggestion.cohort.current_separation }})
          </div>
          <div class="d-flex ga-1">
            <v-btn size="x-small" color="primary" :loading="suggestionBusy === 'cohort'" @click="applySuggestion('cohort')">Aplicar</v-btn>
            <v-btn size="x-small" variant="text" :disabled="!!suggestionBusy" @click="dismissSuggestion('cohort')">Descartar</v-btn>
          </div>
        </div>
      </v-alert>
      <v-alert v-if="suggestionError" type="error" density="compact" class="mt-2">{{ suggestionError }}</v-alert>
      <v-alert v-if="learningConfigError" type="error" density="compact" class="mt-2">{{ learningConfigError }}</v-alert>
      <div class="network-editor-panel__lof">
        <span>Grupo LOF · {{ learningConfigDraft.min_cohort }}</span>
        <v-slider aria-label="Tamaño mínimo de grupo LOF" v-model="learningConfigDraft.min_cohort" :min="minCohortMin" :max="minCohortMax" :step="1" thumb-label hide-details />
      </div>
      <div class="d-flex flex-wrap ga-2 mt-2">
        <v-btn color="primary" size="x-small" :loading="savingLearningConfig" @click="saveLearningConfig">Guardar y reentrenar</v-btn>
        <v-btn variant="text" size="x-small" :disabled="savingLearningConfig" @click="resetLearningConfigDraft">Descartar</v-btn>
        <v-btn variant="outlined" color="secondary" size="x-small" icon :loading="exportingModel" aria-label="Exportar modelo" @click="exportModel">
          <v-icon icon="mdi-tray-arrow-down" size="14" />
        </v-btn>
        <v-btn variant="outlined" color="secondary" size="x-small" icon :loading="importingModel" aria-label="Importar modelo" @click="triggerImport">
          <v-icon icon="mdi-tray-arrow-up" size="14" />
        </v-btn>
        <input ref="importInput" type="file" accept="application/json" class="d-none" @change="importModel" />
      </div>
      <v-alert v-if="modelIoMessage" :type="modelIoError ? 'error' : 'success'" density="compact" class="mt-2">{{ modelIoMessage }}</v-alert>
    </div>
  </v-card>
</template>
<script setup>
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from "vue";
import {
  drag as d3Drag,
  forceCollide,
  forceSimulation,
  forceX,
  forceY,
  interpolateRgb,
  interval as d3Interval,
  scaleLinear,
  select as d3Select,
  zoom as d3Zoom,
  zoomIdentity,
} from "d3";
import store from "../state/appStore";

const props = defineProps({
  learning: { type: Object, required: true },
  packet: { type: Object, default: null },
  immersive: { type: Boolean, default: false },
  // Only meaningful together with `immersive`: turns the graph itself into
  // the architecture editor (see the editor-layer controls below) instead of
  // relying on a separate side panel. AiView.vue's non-immersive usage never
  // passes these, so it keeps its own standalone NeuralNetworkConfigPanel.
  learningConfig: { type: Object, default: null },
  effectiveness: {
    type: Object,
    default: () => ({ ready: false, accuracy: null, correct: 0, total: 0 }),
  },
  suggestion: {
    type: Object,
    default: () => ({ architecture: null, cohort: null }),
  },
});
const emit = defineEmits(["config-saved", "reload-requested"]);
const editable = computed(() => props.immersive && !!props.learningConfig);

const selectedId = ref("output");
const hoveredId = ref(null);
function selectNode(id) { selectedId.value = id; }

// A column with many neurons (layer width has no upper bound, see the
// editor controls below) packs its labels tightly enough at the default
// 12px radius that a neuron's own caption collides with the next neuron's
// halo/circle - "no se ve el texto, se tapa por otros nodos". Shrinking the
// circle and hiding the always-on caption once a column gets dense
// (revealing it again on hover/selection, same as clicking through to the
// inspector) keeps every label legible without redoing the grid layout.
function nodeRadius(node) {
  if (node.rowCount <= 8) return 12;
  if (node.rowCount <= 12) return 9;
  return 7;
}
function haloRadius(node) {
  return nodeRadius(node) + 5;
}
function labelVisible(node) {
  return node.rowCount <= 8 || node.id === selectedId.value || node.id === hoveredId.value;
}

// Pan/zoom via d3-zoom, applied as a transform on the <g ref="zoomLayer">
// wrapping the graph rather than a CSS scale() on the <svg> itself: that
// lets d3 own both panning (drag) and zooming (wheel) together, in the same
// coordinate space the neuron drag behavior already uses (see nodeDrag
// below), instead of a wheel-only zoom with no way to pan except the
// container's native scrollbars - the only way to reach a control on a wide
// network like a 5-hidden-layer tournament graph.
const MIN_ZOOM = 0.5;
const MAX_ZOOM = 3;
const ZOOM_STEP = 0.25;
const zoomLayer = ref(null);
const viewTransform = ref(zoomIdentity);
const zoom = computed(() => viewTransform.value.k);
const isDefaultView = computed(() => viewTransform.value.k === 1 && viewTransform.value.x === 0 && viewTransform.value.y === 0);

const zoomBehavior = d3Zoom()
  .scaleExtent([MIN_ZOOM, MAX_ZOOM])
  .filter((event) => {
    // Plain wheel still scrolls the page/container as normal; only
    // ctrl/cmd+wheel (the same modifier browsers use for page zoom) drives
    // the graph zoom, so scrolling past the graph doesn't accidentally
    // resize it - regardless of what's directly under the cursor.
    if (event.type === "wheel") return event.ctrlKey || event.metaKey;
    // A drag-to-pan gesture starting on a neuron or an editor +/× control
    // must not also start a pan: neurons run their own d3-drag (see
    // nodeDrag below) and the controls are plain clicks, either of which a
    // competing pan gesture from the same pointerdown would race with.
    if (event.target.closest(".editor-control, .neuron")) return false;
    return !event.button;
  })
  .on("zoom", (event) => {
    viewTransform.value = event.transform;
    if (zoomLayer.value) zoomLayer.value.setAttribute("transform", event.transform.toString());
  });
let zoomSelection = null;
function zoomBy(delta) {
  if (!zoomSelection) return;
  const next = Math.min(MAX_ZOOM, Math.max(MIN_ZOOM, Math.round((zoom.value + delta) * 100) / 100));
  zoomSelection.transition().duration(150).call(zoomBehavior.scaleTo, next);
}
function resetZoom() {
  zoomSelection?.transition().duration(200).call(zoomBehavior.transform, zoomIdentity);
}

// --- Architecture editing (immersive + learningConfig only) ---------------
// Layer count and width have no upper bound (sniff4hound.ai_learning -
// MIN_HIDDEN_NEURONS/MIN_HIDDEN_LAYERS is the only floor, both 1); the
// backend re-validates on save regardless of what's edited here. Editing
// only ever touches the *tail* hidden layer for add/remove-layer (and a
// layer's own neuron count in place) so every earlier transition's index
// into the live, already-trained weights stays valid - see rawEdges below,
// which relies on that to know which edges can still show a real weight.
const MIN_HIDDEN_NEURONS = 1;
const DEFAULT_HIDDEN_NEURONS = 6;
const minCohortMin = 5;
const minCohortMax = 200;

const learningConfigDraft = ref(null);
const learningConfigLoaded = ref(false);
const savingLearningConfig = ref(false);
const learningConfigError = ref("");

function resetLearningConfigDraft() {
  const source = props.learningConfig || { hidden_sizes: [6], min_cohort: 20 };
  learningConfigDraft.value = { hidden_sizes: [...source.hidden_sizes], min_cohort: source.min_cohort };
  learningConfigError.value = "";
}
// Only auto-populates the draft once, the first time a real config arrives -
// otherwise a live snapshot landing mid-edit would clobber whatever the
// operator is still clicking through on the graph.
watch(
  () => props.learningConfig,
  (value) => {
    if (learningConfigLoaded.value || !value) return;
    learningConfigLoaded.value = true;
    resetLearningConfigDraft();
  },
  { immediate: true }
);

function addNeuron(layerIdx) {
  const sizes = learningConfigDraft.value.hidden_sizes;
  sizes.splice(layerIdx, 1, sizes[layerIdx] + 1);
}
function removeNeuron(layerIdx) {
  const sizes = learningConfigDraft.value.hidden_sizes;
  const next = sizes[layerIdx] - 1;
  if (next < MIN_HIDDEN_NEURONS) return;
  sizes.splice(layerIdx, 1, next);
}
function addHiddenLayer() {
  learningConfigDraft.value.hidden_sizes.push(DEFAULT_HIDDEN_NEURONS);
}
function removeLastLayer() {
  const sizes = learningConfigDraft.value.hidden_sizes;
  if (sizes.length <= 1) return;
  sizes.pop();
}

async function saveLearningConfig() {
  savingLearningConfig.value = true;
  learningConfigError.value = "";
  try {
    const config = await store.fetchJsonPromise("/api/ai/config", {
      method: "POST",
      body: JSON.stringify({
        learning_config: { hidden_sizes: learningConfigDraft.value.hidden_sizes, min_cohort: learningConfigDraft.value.min_cohort },
      }),
    });
    learningConfigDraft.value = { hidden_sizes: [...config.learning_config.hidden_sizes], min_cohort: config.learning_config.min_cohort };
    emit("config-saved", config.learning_config);
    emit("reload-requested");
  } catch (err) {
    learningConfigError.value = err.message || "No se pudo guardar la configuración.";
  } finally {
    savingLearningConfig.value = false;
  }
}

const suggestionBusy = ref(null);
const suggestionError = ref("");
async function applySuggestion(kind) {
  suggestionBusy.value = kind;
  suggestionError.value = "";
  try {
    const result = await store.fetchJsonPromise("/api/ai/suggestion", {
      method: "POST",
      body: JSON.stringify({ action: "apply", kind }),
    });
    if (result.learning_config) {
      learningConfigDraft.value = {
        hidden_sizes: [...result.learning_config.hidden_sizes],
        min_cohort: result.learning_config.min_cohort,
      };
      emit("config-saved", result.learning_config);
    }
    emit("reload-requested");
  } catch (err) {
    suggestionError.value = err.message || "No se pudo aplicar la sugerencia.";
  } finally {
    suggestionBusy.value = null;
  }
}
async function dismissSuggestion(kind) {
  suggestionBusy.value = kind;
  suggestionError.value = "";
  try {
    await store.fetchJsonPromise("/api/ai/suggestion", {
      method: "POST",
      body: JSON.stringify({ action: "dismiss", kind }),
    });
    emit("reload-requested");
  } catch (err) {
    suggestionError.value = err.message || "No se pudo descartar la sugerencia.";
  } finally {
    suggestionBusy.value = null;
  }
}

const effectivenessColor = computed(() => {
  const accuracy = props.effectiveness.accuracy;
  if (accuracy === null) return "warning";
  if (accuracy >= 0.8) return "success";
  if (accuracy >= 0.5) return "warning";
  return "error";
});

const importInput = ref(null);
const exportingModel = ref(false);
const importingModel = ref(false);
const modelIoMessage = ref("");
const modelIoError = ref(false);
async function exportModel() {
  exportingModel.value = true;
  modelIoMessage.value = "";
  modelIoError.value = false;
  try {
    const payload = await store.fetchJsonPromise("/api/ai/model");
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `sniff4hound-ai-model-${payload.hidden_sizes.join("-")}.json`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
    modelIoMessage.value = "Modelo exportado.";
  } catch (err) {
    modelIoError.value = true;
    modelIoMessage.value = err.message || "No se pudo exportar el modelo.";
  } finally {
    exportingModel.value = false;
  }
}
function triggerImport() {
  importInput.value?.click();
}
async function importModel(event) {
  const file = event.target.files?.[0];
  event.target.value = "";
  if (!file) return;
  importingModel.value = true;
  modelIoMessage.value = "";
  modelIoError.value = false;
  try {
    const text = await file.text();
    const payload = JSON.parse(text);
    const config = await store.fetchJsonPromise("/api/ai/model", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    modelIoMessage.value = `Modelo importado: ${config.hidden_sizes.join("-")}.`;
    emit("reload-requested");
  } catch (err) {
    modelIoError.value = true;
    modelIoMessage.value = err.message || "No se pudo importar el modelo.";
  } finally {
    importingModel.value = false;
  }
}

// --- Layout ------------------------------------------------------------
// The hidden-layer shape is a configurable knob - any number of layers,
// each with its own width, with no upper bound. In editable mode the graph
// is laid out from the *draft* shape (what's being edited, even before
// saving); otherwise from the model's actual persisted shape.
const liveHiddenSizes = computed(() =>
  Array.isArray(props.learning.hidden_sizes) && props.learning.hidden_sizes.length
    ? props.learning.hidden_sizes
    : props.learning.parameters.layers.slice(0, -1).map((layer) => layer.b.length)
);
const hiddenSizes = computed(() =>
  editable.value && learningConfigDraft.value ? learningConfigDraft.value.hidden_sizes : liveHiddenSizes.value
);
const columnSizes = computed(() => [props.learning.feature_names.length, ...hiddenSizes.value, 1]);
const numColumns = computed(() => columnSizes.value.length);
const shapeLabel = computed(() => columnSizes.value.join(" → "));
const columnLabels = computed(() => [
  "Entrada",
  ...hiddenSizes.value.map((_, i) => `Oculta ${i + 1} (tanh)`),
  "Salida (sigmoide)",
]);

// Row spacing depends on a column's own density, not a single network-wide
// constant: a sparse column (<=8 neurons, see nodeRadius()/labelVisible()
// above) keeps full-size circles with an always-on caption below them and
// needs the roomier spacing to clear it, while a dense column already
// shrinks its circles and hides the caption by default, so it can be packed
// much tighter. Sharing one row height across every column would force
// *every* column to pay for whichever one is densest - a single 16-neuron
// hidden layer would blow up the whole diagram's height even though its own
// neurons no longer need that much room.
function rowHeightFor(rowCount) {
  if (rowCount <= 8) return 40;
  if (rowCount <= 12) return 24;
  return 20;
}
const TOP_MARGIN = 34;
const SIDE_MARGIN = 60;
const viewBoxWidth = 720;
const maxColumnHeight = computed(() =>
  Math.max(...columnSizes.value.map((count) => count * rowHeightFor(count)))
);
const viewBoxHeight = computed(() => TOP_MARGIN + maxColumnHeight.value + 14);
function columnX(index) {
  const usable = viewBoxWidth - SIDE_MARGIN * 2;
  const step = numColumns.value > 1 ? usable / (numColumns.value - 1) : 0;
  return SIDE_MARGIN + index * step;
}
function rowY(index, rowCount) {
  // Centers a shorter/tighter column vertically against the tallest one
  // instead of always top-aligning, so e.g. a 3-neuron layer next to a
  // 16-neuron one still reads as part of the same network rather than
  // floating at the top.
  const rowHeight = rowHeightFor(rowCount);
  const offset = (maxColumnHeight.value - rowCount * rowHeight) / 2;
  return TOP_MARGIN + offset + index * rowHeight;
}

// Editor affordances are anchored to the static grid position (not the
// jittered/dragged node position) so they never chase a moving target.
const neuronAddControls = computed(() => {
  if (!editable.value || !learningConfigDraft.value) return [];
  return hiddenSizes.value.map((size, layerIdx) => ({
    id: `add-${layerIdx}`,
    layerIdx,
    layerLabel: `capa ${layerIdx + 1}`,
    x: columnX(layerIdx + 1),
    y: rowY(size - 1, size) + rowHeightFor(size),
  }));
});
const neuronRemoveControls = computed(() => {
  if (!editable.value || !learningConfigDraft.value) return [];
  return hiddenSizes.value
    .map((size, layerIdx) => ({ size, layerIdx }))
    .filter(({ size }) => size > MIN_HIDDEN_NEURONS)
    .map(({ size, layerIdx }) => {
      const radius = nodeRadius({ rowCount: size });
      return {
        id: `remove-${layerIdx}`,
        layerIdx,
        layerLabel: `capa ${layerIdx + 1}`,
        x: columnX(layerIdx + 1) + radius + 6,
        y: rowY(size - 1, size) - radius - 2,
      };
    });
});
const layerRemoveControl = computed(() => {
  if (!editable.value || !learningConfigDraft.value || hiddenSizes.value.length <= 1) return null;
  const lastIdx = hiddenSizes.value.length - 1;
  // y: 14 matches the column-label text's own baseline (see the <text> at
  // y="14" above) - placing the control there put it directly on top of
  // that label ("Oculta N (tanh)" rendered with an "×" badge stamped over
  // the "h)"). Dropping it below the label's line clears the text instead.
  return { x: columnX(lastIdx + 1) + 26, y: 26 };
});
const addLayerControl = computed(() => {
  const lastHiddenX = columnX(hiddenSizes.value.length);
  const outputX = columnX(numColumns.value - 1);
  return { x: (lastHiddenX + outputX) / 2, y: TOP_MARGIN + maxColumnHeight.value / 2 };
});

const columns = computed(() => {
  const a = props.packet?.activations;
  const cols = [];
  cols.push(
    props.learning.feature_names.map((label, i) => ({
      id: `c0_${i}`,
      label,
      x: columnX(0),
      y: rowY(i, props.learning.feature_names.length),
      rowCount: props.learning.feature_names.length,
      activation: a?.input?.[i] ?? null,
      bias: null,
      pending: false,
    }))
  );
  const liveSizes = liveHiddenSizes.value;
  hiddenSizes.value.forEach((size, layerIdx) => {
    const layer = props.learning.parameters.layers[layerIdx];
    const liveSize = liveSizes[layerIdx] ?? 0;
    const col = [];
    for (let i = 0; i < size; i++) {
      // A neuron is "pending" (not yet trained/persisted) if its whole
      // layer doesn't exist live yet, or if it's beyond that layer's live
      // width - i.e. it was just added on the graph and hasn't been saved.
      const pending = !layer || i >= liveSize;
      col.push({
        id: `c${layerIdx + 1}_${i}`,
        label: `L${layerIdx + 1}·${i + 1}`,
        x: columnX(layerIdx + 1),
        y: rowY(i, size),
        rowCount: size,
        activation: pending ? null : (a?.hidden_layers?.[layerIdx]?.[i] ?? null),
        bias: pending ? null : layer.b[i],
        pending,
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
      rowCount: 1,
      activation: a?.output ?? null,
      bias: outputLayer.b[0],
      pending: false,
    },
  ]);
  return cols;
});
const rawNodes = computed(() => columns.value.flat());
// Edges are built per adjacent-column transition, checking whether that
// transition still lines up with the live, already-trained weight matrix at
// the same index. Since add/remove-layer only ever touches the tail layer
// (see the editor functions above), every transition before the edited
// point keeps a stable index into `learning.parameters.layers` - only the
// transition feeding the (possibly now-different) last column, or one that
// touches a resized layer's new/removed rows, needs the pending fallback.
const rawEdges = computed(() => {
  const result = [];
  const liveLayers = props.learning.parameters.layers;
  const liveDepth = liveHiddenSizes.value.length;
  const draftDepth = hiddenSizes.value.length;
  for (let t = 0; t <= draftDepth; t++) {
    const fromCol = columns.value[t];
    const toCol = columns.value[t + 1];
    const isFinal = t === draftDepth;
    const structurallyValid = isFinal ? draftDepth === liveDepth : t < liveDepth;
    const liveLayer = structurallyValid ? liveLayers[t] : null;
    toCol.forEach((toNode, j) => {
      fromCol.forEach((fromNode, i) => {
        const rawWeight = !fromNode.pending && !toNode.pending && liveLayer ? liveLayer.w[j]?.[i] : undefined;
        const pending = rawWeight === undefined;
        const weight = pending ? 0 : rawWeight;
        result.push({
          from: fromNode,
          to: toNode,
          weight,
          pending,
          contribution: pending || fromNode.activation === null ? null : fromNode.activation * weight,
        });
      });
    });
  }
  return result;
});

// --- Life: color, an organic "settle" jitter, and a continuous ambient
// pulse so the graph never reads as a frozen diagram, layered on top of
// the real weights/activations above rather than replacing them. ---
const POSITIVE_COLOR = "#0fe8ff"; // --brand-cyan
const NEGATIVE_COLOR = "#ff6b84"; // matches the app's existing alert/power red
const NEUTRAL_COLOR = "#26333f";
const PENDING_COLOR = "#8a6bff"; // marks a neuron/edge added on the graph but not yet saved/trained
const PENDING_EDGE_COLOR = "rgba(138, 107, 255, 0.55)";
const activationScale = scaleLinear().domain([-1, 0, 1]).range([NEGATIVE_COLOR, NEUTRAL_COLOR, POSITIVE_COLOR]).interpolate(interpolateRgb).clamp(true);
const maxAbsWeight = computed(() => rawEdges.value.reduce((max, e) => Math.max(max, Math.abs(e.weight)), 1e-6));
function weightColor(weight) {
  const t = Math.abs(weight) / maxAbsWeight.value;
  return interpolateRgb("#39485a", weight >= 0 ? POSITIVE_COLOR : NEGATIVE_COLOR)(Math.min(1, t));
}
function hashPhase(id) {
  let h = 0;
  for (let i = 0; i < id.length; i++) h = (h * 31 + id.charCodeAt(i)) >>> 0;
  return (h % 1000) / 1000 * Math.PI * 2;
}

// One-shot d3-force "settle" animation: nodes are born scattered around
// their grid slot and the sim pulls them back into place, so opening the
// view (or reshaping the network, including a live edit) feels like the
// network assembling itself rather than a diagram just appearing.
const jitter = ref({});
let simulation = null;
// id -> the node's own live datum in the running d3-force simulation (the
// `targets` array below) - kept around so the drag behavior can pin/release
// a node's fx/fy directly on the same simulation that settles it, instead of
// a separate absolute-position override. Rebuilt every restart since a
// resized layer reassigns what each id/index refers to and a stale entry
// would then point at the wrong neuron.
const simNodesById = new Map();
function restartSettleSimulation() {
  simulation?.stop();
  simNodesById.clear();
  const targets = rawNodes.value.map((node) => ({
    id: node.id,
    fx0: node.x,
    fy0: node.y,
    x: node.x + (Math.random() - 0.5) * 90,
    y: node.y + (Math.random() - 0.5) * 90,
  }));
  for (const target of targets) simNodesById.set(target.id, target);
  simulation = forceSimulation(targets)
    .force("x", forceX((d) => d.fx0).strength(0.12))
    .force("y", forceY((d) => d.fy0).strength(0.12))
    .force("collide", forceCollide(9))
    .alpha(1)
    .alphaDecay(0.045)
    .on("tick", () => {
      const next = {};
      for (const d of targets) next[d.id] = { dx: d.x - d.fx0, dy: d.y - d.fy0 };
      jitter.value = next;
    });
}
watch(
  () => rawNodes.value.map((n) => n.id).join("|"),
  async () => {
    restartSettleSimulation();
    // New/removed neurons mean new/removed <g> elements - wait for Vue to
    // actually render them before (re)binding drag to the current set.
    await nextTick();
    bindDragToNodes();
  }
);

// Continuous ambient timer: a slow per-neuron "breathing" glow plus small
// dots traveling input->output along the strongest connections, speed and
// intensity weighted by |weight| - and both burst brighter for ~1.4s
// whenever a real backend event lands (a training revision bump, or a
// different packet's activations arriving), so "real time" ties back to
// genuine model updates over the live feed, not just decoration.
const tick = ref(0);
const flashUntil = ref(0);
function triggerFlash() {
  flashUntil.value = Date.now() + 1400;
}
watch(() => props.learning?.revision, (next, prev) => { if (prev !== undefined && next !== prev) triggerFlash(); });
watch(() => props.packet?.id, (next, prev) => { if (prev !== undefined && next !== prev && next != null) triggerFlash(); });
let ambientTimer = null;

const nodes = computed(() =>
  rawNodes.value.map((node) => {
    const j = jitter.value[node.id];
    const boost = Date.now() < flashUntil.value ? 0.5 : 0;
    const phase = hashPhase(node.id);
    const breathe = 0.32 + 0.22 * (0.5 + 0.5 * Math.sin(tick.value / 480 + phase)) + boost;
    return {
      ...node,
      x: node.x + (j?.dx || 0),
      y: node.y + (j?.dy || 0),
      color: node.pending ? PENDING_COLOR : node.activation === null ? NEUTRAL_COLOR : activationScale(node.activation),
      glow: Math.min(1, breathe),
    };
  })
);
// Edges are re-anchored to the jittered node positions (not the raw grid
// coordinates) so a line never visually detaches from the neuron it
// connects to while the settle animation is dragging that neuron back
// toward its slot.
const nodesById = computed(() => {
  const map = {};
  for (const node of nodes.value) map[node.id] = node;
  return map;
});
const edges = computed(() =>
  rawEdges.value.map((edge) => ({
    ...edge,
    from: nodesById.value[edge.from.id] || edge.from,
    to: nodesById.value[edge.to.id] || edge.to,
    magnitude: edge.pending ? 0 : Math.min(1, Math.abs(edge.weight) / maxAbsWeight.value),
    color: edge.pending ? PENDING_EDGE_COLOR : weightColor(edge.weight),
  }))
);
const topEdges = computed(() => edges.value.filter((e) => !e.pending).sort((a, b) => b.magnitude - a.magnitude).slice(0, 24));
const pulseDots = computed(() => {
  const t = tick.value;
  const boost = Date.now() < flashUntil.value ? 2.1 : 1;
  return topEdges.value.map((edge, i) => {
    const speed = 900 / (0.5 + edge.magnitude * 2.5) / boost;
    const progress = ((t / speed + i / topEdges.value.length) % 1 + 1) % 1;
    return {
      id: `dot-${i}`,
      x: edge.from.x + (edge.to.x - edge.from.x) * progress,
      y: edge.from.y + (edge.to.y - edge.from.y) * progress,
      r: 1.4 + edge.magnitude * 1.4,
      color: edge.color,
      opacity: Math.max(0, Math.sin(progress * Math.PI)) * (0.35 + edge.magnitude * 0.5) * boost,
    };
  });
});

// Drag-and-drop repositioning, via d3-drag pinning the node's fx/fy on the
// *same* force simulation that settles new/reshaped neurons into their grid
// slot (see restartSettleSimulation above), rather than a separate absolute-
// position override with its own bounds and no way back. That unification
// is what makes release well-behaved: clearing fx/fy on drag end hands the
// node back to the simulation's own forceX/forceY "home" springs, so it
// visibly eases back to its slot instead of staying wherever it was
// dropped - permanently detached, edges stretched in a long diagonal mess
// disconnected from the rest of the layered network.
//
// d3-drag also replaces the screen-to-SVG coordinate math (getScreenCTM())
// that hand-rolled pointer handling needed - `.container()` gives event.x/y
// already in the svg's own viewBox space, correct through the ctrl/cmd+wheel
// zoom (a CSS transform: scale) and the SVG's responsive scaling - and
// `.clickDistance()` is d3's own equivalent of the old manual
// movement-threshold + "suppress the click that follows a drag" logic.
const DRAG_THRESHOLD = 3;
const svgRoot = ref(null);
const draggingId = ref(null);
const nodeEls = new Map();
function setNodeEl(id, el) {
  if (el) nodeEls.set(id, el);
  else nodeEls.delete(id);
}

const nodeDrag = d3Drag()
  .container(() => svgRoot.value)
  .clickDistance(DRAG_THRESHOLD)
  .subject((event, id) => {
    const target = simNodesById.get(id);
    return { x: target ? target.x : 0, y: target ? target.y : 0 };
  })
  .on("start", (event, id) => {
    draggingId.value = id;
    // Reheat the simulation so it keeps ticking (and animating the eventual
    // spring-back) for the duration of the drag instead of sitting idle at
    // its already-settled alpha.
    simulation?.alphaTarget(0.3).restart();
  })
  .on("drag", (event, id) => {
    const target = simNodesById.get(id);
    if (!target) return;
    const radius = nodeRadius(nodesById.value[id] || { rowCount: 8 });
    target.fx = Math.min(viewBoxWidth - radius, Math.max(radius, event.x));
    target.fy = Math.min(viewBoxHeight.value - radius, Math.max(radius, event.y));
  })
  .on("end", (event, id) => {
    const target = simNodesById.get(id);
    if (target) {
      target.fx = null;
      target.fy = null;
    }
    simulation?.alphaTarget(0);
    draggingId.value = null;
  });

function bindDragToNodes() {
  for (const [id, el] of nodeEls) {
    d3Select(el).datum(id).call(nodeDrag);
  }
}

onMounted(() => {
  restartSettleSimulation();
  nextTick(() => bindDragToNodes());
  ambientTimer = d3Interval((elapsed) => { tick.value = elapsed; }, 60);
  zoomSelection = d3Select(svgRoot.value).call(zoomBehavior);
});
onBeforeUnmount(() => {
  simulation?.stop();
  ambientTimer?.stop();
  zoomSelection?.on(".zoom", null);
});
</script>
<style scoped>
.network-zoom-toolbar {
  display: flex;
  align-items: center;
  gap: 4px;
  margin: 8px 0 -4px;
}

.network-zoom-level {
  min-width: 3.2em;
  text-align: center;
  font-size: 0.72rem;
  font-variant-numeric: tabular-nums;
  color: var(--text-dim);
}

/* Panning is now d3-zoom's own drag-the-canvas gesture (see the toolbar's
   zoomBehavior above), applied as a transform on the <g ref="zoomLayer">
   inside the SVG's fixed viewBox rather than the container scrolling a
   CSS-enlarged element - overflow stays hidden so content panned past the
   edge is clipped instead of growing the container's scrollbars. */
.network-scroll { overflow: hidden; max-height: 360px; }
/* The SVG's width:100% with no cap let it grow to fill a wide desktop
   viewport, and since the viewBox's aspect ratio is preserved, everything
   inside - circles, text, the whole layout - scaled up right along with it,
   which is what actually made the font/nodes look oversized. Capping the
   rendered width keeps it close to its designed (viewBox) scale on wide
   screens; it can still shrink on narrow ones. touch-action: none hands
   touch gestures on the graph to d3-zoom instead of the browser's own
   scroll/pinch handling. */
svg {
  width: 100%;
  max-width: 560px;
  min-width: 300px;
  display: block;
  margin: 0 auto;
  touch-action: none;
  cursor: grab;
}
svg:active { cursor: grabbing; }
.neuron { cursor: grab; touch-action: none; }
.neuron.is-dragging { cursor: grabbing; }
.neuron:focus circle { stroke: white; stroke-width: 4; }
.neuron-halo { filter: blur(2px); pointer-events: none; }
.signal-dot { pointer-events: none; filter: drop-shadow(0 0 2px currentColor); }

/* Editor affordances: small +/x controls drawn directly on the graph so
   architecture edits happen on the network itself instead of a separate
   form. Kept visually distinct (violet) from the cyan/red weight language. */
.editor-control { cursor: pointer; touch-action: none; }
.editor-control circle { fill: rgba(18, 26, 40, 0.85); stroke: #8a6bff; stroke-width: 1.5; transition: fill 0.12s ease, stroke 0.12s ease; }
.editor-control text { fill: #c9b8ff; font-size: 9px; font-weight: 700; pointer-events: none; user-select: none; }
.editor-control:hover circle, .editor-control:focus circle { fill: #8a6bff; stroke: #d9ccff; }
.editor-control:hover text, .editor-control:focus text { fill: #fff; }
.editor-control:focus { outline: none; }
.editor-control--remove circle, .editor-control--remove-layer circle { stroke: #ff6b84; }
.editor-control--remove text, .editor-control--remove-layer text { fill: #ffb8c4; }
.editor-control--remove:hover circle, .editor-control--remove:focus circle,
.editor-control--remove-layer:hover circle, .editor-control--remove-layer:focus circle { fill: #ff6b84; stroke: #ffc2cc; }
.editor-control--remove:hover text, .editor-control--remove:focus text,
.editor-control--remove-layer:hover text, .editor-control--remove-layer:focus text { fill: #fff; }
.editor-control__label { font-size: 6.5px; font-weight: 400; fill: var(--text-dim); pointer-events: none; }

/* The SVG fits both dimensions, so wide windows never crop tall layers. */
.neural-stage {
  position: absolute;
  inset: 0;
  width: 100%;
  height: 100%;
  padding: 0;
  border: 0;
  border-radius: 0;
  background: transparent;
  overflow: hidden;
}
/* Immersive mode fills the whole viewport - the inspector/editor panels
   below float as transparent overlays on top of it, they no longer reserve
   their own layout space, so the graph itself reads as truly full-screen. */
/* Bottom clearance matches the corner overlay panels' own footprint (see
   network-editor-panel/rnn-charts below) so the graph's
   own outer columns - which naturally reach the full height of whichever
   column is tallest - never render underneath a panel and become
   unreadable/unclickable there. A fixed px reserve (not vh) keeps the
   graph's own fixed-width viewBox close to the container's aspect ratio;
   a too-short container turns "meet" scaling width-limited instead of
   height-limited and leaves large empty margins on both sides. */
.neural-stage .network-scroll {
  position: absolute;
  inset: 96px 20px 320px;
  max-height: none;
  min-height: 0;
  overflow: auto;
}
.neural-stage .neural-svg--immersive {
  width: 100%;
  height: 100%;
  min-width: 0;
  max-width: none;
  margin: 0;
  transform-origin: top left;
}
.neural-stage .neural-graph-header {
  position: absolute;
  top: 14px;
  left: 20px;
  right: 220px;
  z-index: 2;
  background: transparent;
  pointer-events: none;
}
.neural-stage .neural-graph-header :deep(.v-btn) { pointer-events: auto; }
.neural-stage .neural-graph-header h2 { font-size: .8rem !important; }
.neural-stage .neural-graph-header p { font-size: .65rem !important; margin-top: 5px !important; color: var(--text-dim); }
.neural-stage .neural-graph-header :deep(.v-chip) { height: 21px; font-size: .6rem; }
.neural-stage .neural-graph-header :deep(.text-caption) { font-size: .65rem !important; }
.neural-stage .network-zoom-toolbar {
  position: absolute;
  right: 16px;
  top: 12px;
  z-index: 3;
  margin: 0;
  padding: 4px;
  background: transparent;
}
/* Bottom-left floating architecture/LOF/save toolbar - the part of "Ajustes
   del motor" that isn't a direct graph interaction (LOF size, save/discard,
   import/export). Transparent background so the live graph stays visible
   underneath; a light blur keeps the small text legible over it. */
.neural-stage .network-editor-panel {
  position: absolute;
  left: 16px;
  bottom: 16px;
  z-index: 4;
  width: min(320px, calc(50% - 24px));
  max-height: 260px;
  overflow-y: auto;
  scrollbar-width: thin;
  background: transparent;
  backdrop-filter: blur(4px);
  padding: 10px 12px;
  border-radius: 10px;
}
.neural-stage .network-editor-panel__head { display: flex; align-items: center; flex-wrap: wrap; gap: 6px; }
.neural-stage .network-editor-panel__title { font-size: .68rem; letter-spacing: .06em; font-weight: 700; color: var(--text-soft); }
.neural-stage .network-editor-panel__hint { font-size: .58rem; color: var(--text-dim); margin: 6px 0 0; line-height: 1.4; }
.neural-stage .network-editor-panel__lof { margin-top: 8px; }
.neural-stage .network-editor-panel__lof span { font-size: .62rem; color: var(--text-dim); }
.neural-stage .network-editor-panel :deep(.v-chip) { height: 18px; font-size: .58rem; }
.neural-stage .network-editor-panel :deep(.v-btn) { font-size: .58rem; letter-spacing: .02em; min-height: 22px; height: 24px; }
.neural-stage .network-editor-panel :deep(.v-btn--icon) { width: 24px; }
.neural-stage .network-editor-panel :deep(.v-alert) { background: rgba(10, 25, 40, .85); padding: 6px 8px; font-size: .6rem; }
.neural-stage .network-editor-panel :deep(.v-slider) { --v-slider-thumb-size: 12px; --v-slider-track-size: 2px; margin-inline: 4px; }

@media (max-width: 800px) {
  .neural-stage .neural-graph-header { right: 12px; left: 12px; top: 10px; }
  .neural-stage .neural-graph-header p { max-width: 100%; }
  .neural-stage .network-zoom-toolbar { top: auto; bottom: 380px; right: 10px; }
  .neural-stage .network-scroll { inset: 125px 8px 340px; }
  .neural-stage .network-editor-panel { left: 8px; right: 8px; width: auto; bottom: 8px; max-height: 220px; }
}
</style>
