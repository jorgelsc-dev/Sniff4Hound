<template>
  <v-card :class="[floating ? 'nnc-floating' : 'pa-5 mb-4']" :variant="floating ? 'flat' : 'tonal'">
    <div class="d-flex align-center flex-wrap ga-3 mb-2">
      <h2 :class="floating ? 'text-subtitle-2 mb-0' : 'text-h6 mb-0'">Ajustes del motor</h2>
      <v-chip v-if="learningConfig" :size="floating ? 'x-small' : 'small'" color="primary">
        {{ learningConfig.hidden_sizes.length }} capa(s) oculta(s) · {{ learningConfig.hidden_sizes.join('-') }}
      </v-chip>
      <v-chip v-if="effectiveness.ready" size="small" :color="effectivenessColor">
        Acierto en entrenamiento {{ Math.round(effectiveness.accuracy * 100) }}% ({{ effectiveness.correct }}/{{ effectiveness.total }})
        <v-tooltip activator="parent">Medido sobre los mismos ejemplos con los que el modelo entrenó (resustitución), no sobre datos no vistos.</v-tooltip>
      </v-chip>
      <v-chip v-else :size="floating ? 'x-small' : 'small'" color="warning">{{ floating ? 'Pendiente de evaluar' : 'Acierto en entrenamiento: faltan revisiones (mín. 3 benignos y 3 maliciosos)' }}<v-tooltip activator="parent">Se necesitan al menos 3 revisiones benignas y 3 maliciosas.</v-tooltip></v-chip>
    </div>
    <p v-if="!floating" class="text-body-2 text-medium-emphasis mb-3">
      La red neuronal aprende de tus revisiones; el detector LOF agrupa paquetes del mismo
      protocolo para medir cuáles son atípicos. Ambos motores tienen parámetros reales que puedes
      ajustar - capas y neuronas por capa para la red, tamaño mínimo de grupo para el LOF. El LOF no puntúa grupos por debajo de ese mínimo.
    </p>
    <v-alert v-if="suggestion.architecture" type="info" variant="tonal" density="comfortable" class="mb-3">
      <div class="d-flex flex-wrap align-center ga-3">
        <div class="flex-grow-1 text-body-2">
          Sugerencia: cambiar la red a <strong>{{ suggestion.architecture.hidden_sizes.join('-') }}</strong>
          (precisión estimada {{ Math.round(suggestion.architecture.suggested_accuracy * 100) }}% frente al
          {{ Math.round(suggestion.architecture.current_accuracy * 100) }}% actual).
        </div>
        <div class="d-flex ga-2">
          <v-btn size="small" color="primary" :loading="suggestionBusy === 'architecture'" @click="applySuggestion('architecture')">Aplicar</v-btn>
          <v-btn size="small" variant="text" :disabled="!!suggestionBusy" @click="dismissSuggestion('architecture')">Descartar</v-btn>
        </div>
      </div>
    </v-alert>
    <v-alert v-if="suggestion.cohort" type="info" variant="tonal" density="comfortable" class="mb-3">
      <div class="d-flex flex-wrap align-center ga-3">
        <div class="flex-grow-1 text-body-2">
          Sugerencia: cambiar el tamaño mínimo de grupo (LOF) a <strong>{{ suggestion.cohort.min_cohort }}</strong>
          (separación benigno/malicioso estimada {{ suggestion.cohort.suggested_separation }} frente a
          {{ suggestion.cohort.current_separation }} actual).
        </div>
        <div class="d-flex ga-2">
          <v-btn size="small" color="primary" :loading="suggestionBusy === 'cohort'" @click="applySuggestion('cohort')">Aplicar</v-btn>
          <v-btn size="small" variant="text" :disabled="!!suggestionBusy" @click="dismissSuggestion('cohort')">Descartar</v-btn>
        </div>
      </div>
    </v-alert>
    <v-alert v-if="suggestionError" type="error" density="comfortable" class="mb-3">{{ suggestionError }}</v-alert>
    <v-alert v-if="learningConfigError" type="error" density="comfortable" class="mb-3">{{ learningConfigError }}</v-alert>
    <v-row dense v-if="learningConfigDraft">
      <v-col cols="12" md="6">
        <div class="d-flex align-center justify-space-between flex-wrap ga-2">
          <div class="text-caption text-medium-emphasis">{{ floating ? 'Neuronas por capa' : 'Capas ocultas y neuronas por capa' }}</div>
          <div class="d-flex align-center ga-2">
            <v-text-field
              :model-value="learningConfigDraft.hidden_sizes.length"
              type="number"
              min="1"
              step="1"
              density="compact"
              variant="outlined"
              hide-details
              class="layer-count-field"
              aria-label="Número de capas ocultas"
              @update:model-value="setHiddenLayerCount"
            />
            <v-btn size="x-small" variant="tonal" color="primary" prepend-icon="mdi-plus" @click="addHiddenLayer">
              Añadir capa
            </v-btn>
          </div>
        </div>
        <div v-for="(size, index) in learningConfigDraft.hidden_sizes" :key="index" class="hidden-layer-row">
          <span class="hidden-layer-row__label">Capa {{ index + 1 }}</span>
          <v-text-field
            :model-value="size"
            type="number"
            min="1"
            step="1"
            density="compact"
            variant="outlined"
            hide-details
            class="neuron-count-field"
            :aria-label="`Neuronas de la capa ${index + 1}`"
            @update:model-value="(value) => setHiddenLayerSize(index, value)"
          />
          <v-btn
            icon
            size="x-small"
            variant="text"
            color="error"
            :disabled="learningConfigDraft.hidden_sizes.length <= 1"
            aria-label="Quitar capa"
            @click="removeHiddenLayer(index)"
          >
            <v-icon icon="mdi-close" size="16" />
          </v-btn>
        </div>
        <p v-if="!floating" class="text-caption text-medium-emphasis mt-1">
          Sin límite de capas ni de neuronas por capa. Más grande puede aprender patrones más complejos
          con más ejemplos, pero tarda más en reentrenar y es más fácil de sobreajustar. Cambiar la forma
          reentrena el modelo desde tus ejemplos guardados.
        </p>
      </v-col>
      <v-col cols="12" md="6">
        <div class="text-caption text-medium-emphasis">{{ floating ? `Grupo LOF · ${learningConfigDraft.min_cohort}` : 'Tamaño mínimo de grupo (detector LOF)' }}</div>
        <v-slider aria-label="Tamaño mínimo de grupo LOF" v-model="learningConfigDraft.min_cohort" :min="minCohortMin" :max="minCohortMax" :step="1"
          :thumb-label="floating ? true : 'always'" hide-details />
        <p v-if="!floating" class="text-caption text-medium-emphasis mt-1">
          Cuántos paquetes del mismo protocolo hacen falta antes de que el LOF empiece a puntuar ese grupo.
          Más bajo: cubre protocolos poco frecuentes antes, pero con puntuaciones menos estables.
        </p>
      </v-col>
    </v-row>
    <div class="d-flex flex-wrap ga-2 mt-3">
      <v-btn color="primary" size="small" :loading="savingLearningConfig" @click="saveLearningConfig">Guardar y reentrenar</v-btn>
      <v-btn variant="text" size="small" :disabled="savingLearningConfig" @click="resetLearningConfigDraft">Descartar</v-btn>
      <v-spacer v-if="!floating" />
      <v-btn variant="outlined" color="secondary" size="small" :icon="floating" :prepend-icon="floating ? undefined : 'mdi-tray-arrow-down'" :loading="exportingModel" :aria-label="floating ? 'Exportar modelo' : undefined" @click="exportModel">
        <v-icon v-if="floating" icon="mdi-tray-arrow-down" size="16" />
        <template v-else>Exportar modelo</template>
      </v-btn>
      <v-btn variant="outlined" color="secondary" size="small" :icon="floating" :prepend-icon="floating ? undefined : 'mdi-tray-arrow-up'" :loading="importingModel" :aria-label="floating ? 'Importar modelo' : undefined" @click="triggerImport">
        <v-icon v-if="floating" icon="mdi-tray-arrow-up" size="16" />
        <template v-else>Importar modelo</template>
      </v-btn>
      <input ref="importInput" type="file" accept="application/json" class="d-none" @change="importModel" />
    </div>
    <v-alert v-if="modelIoMessage" :type="modelIoError ? 'error' : 'success'" density="comfortable" class="mt-3">
      {{ modelIoMessage }}
    </v-alert>
  </v-card>
</template>

<script setup>
import { computed, ref, watch } from "vue";
import store from "../../state/appStore";

const props = defineProps({
  learningConfig: { type: Object, default: null },
  effectiveness: {
    type: Object,
    default: () => ({ ready: false, accuracy: null, correct: 0, total: 0 }),
  },
  // Auto-tuning recommendations from the backend's background architecture
  // (ai_learning.suggest_architecture) and LOF-cohort (packet_ai.suggest_min_cohort)
  // search - never applied on their own, just surfaced here for the operator
  // to accept or dismiss.
  suggestion: {
    type: Object,
    default: () => ({ architecture: null, cohort: null }),
  },
  floating: { type: Boolean, default: false },
});
const emit = defineEmits(["config-saved", "reload-requested"]);

// Layer count and width have no upper bound (sniff4hound.ai_learning -
// MIN_HIDDEN_NEURONS/MIN_HIDDEN_LAYERS is the only floor, both 1); the
// backend re-validates on save regardless of what's typed here.
const MIN_HIDDEN_NEURONS = 1;
const DEFAULT_HIDDEN_NEURONS = 6;
const minCohortMin = 5;
const minCohortMax = 200;

const learningConfigDraft = ref(null);
const learningConfigLoaded = ref(false);
const savingLearningConfig = ref(false);
const learningConfigError = ref("");

const effectivenessColor = computed(() => {
  const accuracy = props.effectiveness.accuracy;
  if (accuracy === null) return "warning";
  if (accuracy >= 0.8) return "success";
  if (accuracy >= 0.5) return "warning";
  return "error";
});

function resetLearningConfigDraft() {
  const source = props.learningConfig || { hidden_sizes: [6], min_cohort: 20 };
  learningConfigDraft.value = { hidden_sizes: [...source.hidden_sizes], min_cohort: source.min_cohort };
  learningConfigError.value = "";
}

// Only auto-populates the draft once, the first time a real config arrives -
// otherwise a live snapshot landing mid-edit would clobber whatever the
// operator is still typing/dragging.
watch(
  () => props.learningConfig,
  (value) => {
    if (learningConfigLoaded.value || !value) return;
    learningConfigLoaded.value = true;
    resetLearningConfigDraft();
  },
  { immediate: true }
);

function addHiddenLayer() {
  learningConfigDraft.value.hidden_sizes.push(DEFAULT_HIDDEN_NEURONS);
}

function removeHiddenLayer(index) {
  if (learningConfigDraft.value.hidden_sizes.length <= 1) return;
  learningConfigDraft.value.hidden_sizes.splice(index, 1);
}

function clampNeurons(value) {
  const parsed = Math.round(Number(value));
  return Number.isFinite(parsed) && parsed >= MIN_HIDDEN_NEURONS ? parsed : MIN_HIDDEN_NEURONS;
}

function setHiddenLayerSize(index, value) {
  learningConfigDraft.value.hidden_sizes.splice(index, 1, clampNeurons(value));
}

// Typing a layer count directly resizes the array instead of requiring one
// "Añadir capa" click per layer - the only practical way to reach a large
// depth now that there's no cap on how many layers you can have.
function setHiddenLayerCount(value) {
  const count = clampNeurons(value);
  const sizes = learningConfigDraft.value.hidden_sizes;
  if (count === sizes.length) return;
  if (count < sizes.length) {
    sizes.splice(count);
  } else {
    sizes.push(...Array(count - sizes.length).fill(DEFAULT_HIDDEN_NEURONS));
  }
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
</script>

<style scoped>
.hidden-layer-row {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-top: 6px;
}
.hidden-layer-row__label {
  flex: 0 0 56px;
  font-size: 0.76rem;
  color: var(--text-dim);
}
.hidden-layer-row .v-text-field,
.layer-count-field {
  flex: 1 1 auto;
}
.neuron-count-field {
  max-width: 92px;
}
.layer-count-field {
  max-width: 76px;
}
.nnc-floating {
  padding: 6px 4px;
  background: transparent;
  border: 0;
  box-shadow: none;
  border-radius: 0;
  width: 100%;
  overflow: visible;
}
.nnc-floating h2 { font-size: .75rem !important; }
.nnc-floating :deep(.text-caption) { font-size: .65rem !important; }
.nnc-floating :deep(.v-chip) { height: 20px; font-size: .6rem; }
.nnc-floating :deep(.v-btn) { font-size: .6rem; letter-spacing: .02em; min-height: 24px; height: 26px; }
.nnc-floating :deep(.v-btn--icon) { width: 26px; }
.nnc-floating :deep(.v-col) { flex: 0 0 50%; max-width: 50%; }
.nnc-floating :deep(.v-slider) { --v-slider-thumb-size: 12px; --v-slider-track-size: 2px; margin-inline: 6px; }
.nnc-floating :deep(.v-input__control) { min-height: 28px; }
.nnc-floating :deep(.v-field__input) { min-height: 26px; padding: 0 8px; font-size: .65rem; }
.nnc-floating .hidden-layer-row { gap: 3px; margin-top: 0; }
.nnc-floating .hidden-layer-row__label { flex-basis: 54px; font-size: .6rem; }
.nnc-floating .neuron-count-field { max-width: 64px; }
.nnc-floating .layer-count-field { max-width: 56px; }
.nnc-floating > .d-flex { gap: 5px !important; }
.nnc-floating :deep(.v-alert) { background: rgba(10, 25, 40, .92); padding: 8px; font-size: .7rem; }
@media (max-width: 480px) {
  .nnc-floating :deep(.v-col) { flex-basis: 100%; max-width: 100%; }
}
</style>
