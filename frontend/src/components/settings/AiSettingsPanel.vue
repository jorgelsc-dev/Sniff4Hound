<template>
  <div>
    <DataPanel
      title="Aprendizaje incremental"
      subtitle="La red aprende con minibatches pequeños sobre los pesos persistidos; nunca recorre el dataset completo en cada revisión."
      variant="tonal"
      class="mb-4"
      :loading="loading"
    >
      <div class="d-flex flex-wrap ga-2 mb-4">
        <v-chip color="success" variant="tonal" prepend-icon="mdi-content-save-check-outline">
          Pesos persistentes
        </v-chip>
        <v-chip color="info" variant="tonal">
          {{ training.updates || 0 }} actualizaciones
        </v-chip>
        <v-chip color="secondary" variant="tonal">
          Minibatch {{ training.batch_size || 0 }}/{{ training.batch_limit || 8 }}
        </v-chip>
        <v-chip variant="tonal">{{ learning.total || 0 }} ejemplos conservados</v-chip>
      </div>
      <v-alert type="info" variant="tonal" density="comfortable">
        Cada etiqueta del operador produce un paso acotado. Los pesos, la revisión y el historial se
        guardan en la base local, por lo que el aprendizaje continúa después de reiniciar.
      </v-alert>
      <v-btn class="mt-4" to="/ai" variant="outlined" prepend-icon="mdi-brain">
        Abrir revisión y entrenamiento
      </v-btn>
    </DataPanel>

    <DataPanel
      title="Muestreo"
      subtitle="Controla qué tráfico llega al análisis local sin modificar la captura ni los monitores."
      variant="tonal"
      :loading="loading || saving"
    >
      <v-switch
        v-model="samplingEnabled"
        label="Conservar una muestra de tráfico sin alertas (máximo 1 paquete/s)"
        color="primary"
        inset
        :disabled="saving"
        @update:model-value="save"
      />
      <v-alert type="info" variant="tonal" density="comfortable">
        Los filtros de exclusión (IP, CIDR, puerto, protocolo) ahora viven en la pestaña
        <strong>Exclusions</strong> de esta misma pantalla - aplican a Monitores y a la detección
        del Sniffer, no solo a la IA.
      </v-alert>
      <v-alert v-if="error" type="error" variant="tonal" density="comfortable" class="mt-3">{{ error }}</v-alert>
      <v-alert v-if="saved" type="success" variant="tonal" density="comfortable" class="mt-3">Configuración guardada.</v-alert>
    </DataPanel>

    <DataPanel
      title="Ajustes del motor de IA"
      subtitle="Los parámetros reales que tienen los dos motores de IA - sin fingir controles que no existen."
      variant="tonal"
      class="mt-4"
      :loading="loading || savingLearning"
    >
      <div class="d-flex flex-wrap ga-2 mb-4">
        <v-chip size="small" color="primary">{{ learningConfig.hidden_sizes.length }} capa(s) · {{ learningConfig.hidden_sizes.join('-') }}</v-chip>
        <v-chip size="small" color="secondary">Cohorte mínima LOF: {{ learningConfig.min_cohort }}</v-chip>
        <v-chip v-if="effectiveness.ready" size="small" :color="effectivenessColor">
          Efectividad {{ Math.round(effectiveness.accuracy * 100) }}% ({{ effectiveness.correct }}/{{ effectiveness.total }})
        </v-chip>
        <v-chip v-else size="small" color="warning">Efectividad: faltan revisiones</v-chip>
      </div>
      <v-row dense>
        <v-col cols="12" md="6">
          <div class="d-flex align-center justify-space-between flex-wrap ga-2">
            <div class="text-caption text-medium-emphasis">Capas ocultas y neuronas por capa</div>
            <div class="d-flex align-center ga-2">
              <v-text-field
                :model-value="learningDraft.hidden_sizes.length"
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
          <div v-for="(size, index) in learningDraft.hidden_sizes" :key="index" class="hidden-layer-row">
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
              :disabled="learningDraft.hidden_sizes.length <= 1"
              aria-label="Quitar capa"
              @click="removeHiddenLayer(index)"
            >
              <v-icon icon="mdi-close" size="16" />
            </v-btn>
          </div>
          <p class="text-caption text-medium-emphasis mt-1">
            Sin límite de capas ni de neuronas por capa. Cambiar la forma reentrena el modelo desde tus
            ejemplos guardados.
          </p>
        </v-col>
        <v-col cols="12" md="6">
          <div class="text-caption text-medium-emphasis">Tamaño mínimo de grupo (LOF)</div>
          <v-slider v-model="learningDraft.min_cohort" :min="5" :max="200" :step="1" thumb-label="always" hide-details />
        </v-col>
      </v-row>
      <div class="d-flex flex-wrap ga-2 mt-2">
        <v-btn color="primary" variant="flat" :loading="savingLearning" @click="saveLearning">Guardar y reentrenar</v-btn>
        <v-btn variant="text" :disabled="savingLearning" @click="resetLearningDraft">Descartar cambios</v-btn>
        <v-spacer />
        <v-btn variant="outlined" color="secondary" prepend-icon="mdi-tray-arrow-down" :loading="exportingModel" @click="exportModel">
          Exportar modelo
        </v-btn>
        <v-btn variant="outlined" color="secondary" prepend-icon="mdi-tray-arrow-up" :loading="importingModel" @click="triggerImport">
          Importar modelo
        </v-btn>
        <input ref="importInput" type="file" accept="application/json" class="d-none" @change="importModel" />
      </div>
      <v-alert v-if="learningError" type="error" variant="tonal" density="comfortable" class="mt-3">{{ learningError }}</v-alert>
      <v-alert v-if="modelIoMessage" :type="modelIoError ? 'error' : 'success'" variant="tonal" density="comfortable" class="mt-3">
        {{ modelIoMessage }}
      </v-alert>
      <v-btn class="mt-4" to="/ai" variant="text" prepend-icon="mdi-brain">Ver detalle en la vista de IA</v-btn>
    </DataPanel>
  </div>
</template>

<script>
import store from "../../state/appStore";
import DataPanel from "../ui/DataPanel.vue";

// Layer count and width have no upper bound (sniff4hound.ai_learning -
// MIN_HIDDEN_NEURONS/MIN_HIDDEN_LAYERS is the only floor, both 1); the
// backend re-validates on save regardless of what's typed here.
const MIN_HIDDEN_NEURONS = 1;
const DEFAULT_HIDDEN_NEURONS = 6;

export default {
  name: "AiSettingsPanel",
  components: { DataPanel },
  data() {
    return {
      store,
      loading: false,
      saving: false,
      saved: false,
      error: "",
      samplingEnabled: false,
      learning: {},
      learningConfig: { hidden_sizes: [6], min_cohort: 20 },
      learningDraft: { hidden_sizes: [6], min_cohort: 20 },
      savingLearning: false,
      learningError: "",
      exportingModel: false,
      importingModel: false,
      modelIoMessage: "",
      modelIoError: false,
    };
  },
  computed: {
    training() {
      return this.learning.training || {};
    },
    effectiveness() {
      return this.learning.effectiveness || { ready: false, accuracy: null, correct: 0, total: 0 };
    },
    effectivenessColor() {
      const accuracy = this.effectiveness.accuracy;
      if (accuracy === null) return "warning";
      if (accuracy >= 0.8) return "success";
      if (accuracy >= 0.5) return "warning";
      return "error";
    },
  },
  mounted() {
    this.load();
  },
  methods: {
    resetLearningDraft() {
      this.learningDraft = { hidden_sizes: [...this.learningConfig.hidden_sizes], min_cohort: this.learningConfig.min_cohort };
      this.learningError = "";
    },
    addHiddenLayer() {
      this.learningDraft.hidden_sizes.push(DEFAULT_HIDDEN_NEURONS);
    },
    removeHiddenLayer(index) {
      if (this.learningDraft.hidden_sizes.length <= 1) return;
      this.learningDraft.hidden_sizes.splice(index, 1);
    },
    clampNeurons(value) {
      const parsed = Math.round(Number(value));
      return Number.isFinite(parsed) && parsed >= MIN_HIDDEN_NEURONS ? parsed : MIN_HIDDEN_NEURONS;
    },
    setHiddenLayerSize(index, value) {
      this.learningDraft.hidden_sizes.splice(index, 1, this.clampNeurons(value));
    },
    setHiddenLayerCount(value) {
      const count = this.clampNeurons(value);
      const sizes = this.learningDraft.hidden_sizes;
      if (count === sizes.length) return;
      if (count < sizes.length) {
        sizes.splice(count);
      } else {
        sizes.push(...Array(count - sizes.length).fill(DEFAULT_HIDDEN_NEURONS));
      }
    },
    triggerImport() {
      this.$refs.importInput?.click();
    },
    exportModel() {
      this.exportingModel = true;
      this.modelIoMessage = "";
      this.modelIoError = false;
      this.store.fetchJsonPromise("/api/ai/model")
        .then((payload) => {
          const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
          const url = URL.createObjectURL(blob);
          const link = document.createElement("a");
          link.href = url;
          link.download = `sniff4hound-ai-model-${payload.hidden_sizes.join("-")}.json`;
          document.body.appendChild(link);
          link.click();
          link.remove();
          URL.revokeObjectURL(url);
          this.modelIoMessage = "Modelo exportado.";
        })
        .catch((error) => {
          this.modelIoError = true;
          this.modelIoMessage = error.message || "No se pudo exportar el modelo.";
        })
        .finally(() => { this.exportingModel = false; });
    },
    importModel(event) {
      const file = event.target.files && event.target.files[0];
      event.target.value = "";
      if (!file) return;
      this.importingModel = true;
      this.modelIoMessage = "";
      this.modelIoError = false;
      file.text()
        .then((text) => this.store.fetchJsonPromise("/api/ai/model", { method: "POST", body: text }))
        .then((config) => {
          this.modelIoMessage = `Modelo importado: ${config.hidden_sizes.join("-")}.`;
          return this.load();
        })
        .catch((error) => {
          this.modelIoError = true;
          this.modelIoMessage = error.message || "No se pudo importar el modelo.";
        })
        .finally(() => { this.importingModel = false; });
    },
    load() {
      this.loading = true;
      this.error = "";
      return Promise.all([
        this.store.fetchJsonPromise("/api/ai/config"),
        this.store.fetchJsonPromise("/api/ai/packets/?threshold=50", {}, { preferHttp: true }),
      ])
        .then(([config, snapshot]) => {
          this.samplingEnabled = Boolean(config.sampling_enabled);
          this.learningConfig = config.learning_config || this.learningConfig;
          this.resetLearningDraft();
          this.learning = snapshot.learning || {};
        })
        .catch((error) => { this.error = error.message || "No se pudo cargar la configuración de IA."; })
        .finally(() => { this.loading = false; });
    },
    save() {
      if (this.saving) return;
      this.saving = true;
      this.saved = false;
      this.error = "";
      this.store.fetchJsonPromise("/api/ai/config", {
        method: "POST",
        body: JSON.stringify({ sampling_enabled: Boolean(this.samplingEnabled) }),
      })
        .then(() => { this.saved = true; })
        .catch((error) => { this.error = error.message || "No se pudo guardar la configuración de IA."; })
        .finally(() => { this.saving = false; });
    },
    saveLearning() {
      if (this.savingLearning) return;
      this.savingLearning = true;
      this.learningError = "";
      this.store.fetchJsonPromise("/api/ai/config", {
        method: "POST",
        body: JSON.stringify({ learning_config: { ...this.learningDraft } }),
      })
        .then((config) => {
          this.learningConfig = config.learning_config;
          this.resetLearningDraft();
          return this.load();
        })
        .catch((error) => { this.learningError = error.message || "No se pudo guardar la configuración."; })
        .finally(() => { this.savingLearning = false; });
    },
  },
};
</script>

<style scoped>
.hidden-layer-row { display: flex; align-items: center; gap: 10px; margin-top: 6px; }
.hidden-layer-row__label { flex: 0 0 56px; font-size: 0.76rem; color: var(--text-dim); }
.neuron-count-field { max-width: 92px; }
.layer-count-field { max-width: 76px; }
</style>
