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
        <v-chip size="small" color="primary">{{ learningConfig.hidden_neurons }} neuronas ocultas</v-chip>
        <v-chip size="small" color="secondary">Cohorte mínima LOF: {{ learningConfig.min_cohort }}</v-chip>
        <v-chip v-if="effectiveness.ready" size="small" :color="effectivenessColor">
          Efectividad {{ Math.round(effectiveness.accuracy * 100) }}% ({{ effectiveness.correct }}/{{ effectiveness.total }})
        </v-chip>
        <v-chip v-else size="small" color="warning">Efectividad: faltan revisiones</v-chip>
      </div>
      <v-row dense>
        <v-col cols="12" md="6">
          <div class="text-caption text-medium-emphasis">Neuronas en la capa oculta</div>
          <v-slider v-model="learningDraft.hidden_neurons" :min="3" :max="16" :step="1" thumb-label="always" hide-details />
        </v-col>
        <v-col cols="12" md="6">
          <div class="text-caption text-medium-emphasis">Tamaño mínimo de grupo (LOF)</div>
          <v-slider v-model="learningDraft.min_cohort" :min="5" :max="200" :step="1" thumb-label="always" hide-details />
        </v-col>
      </v-row>
      <div class="d-flex ga-2 mt-2">
        <v-btn color="primary" variant="flat" :loading="savingLearning" @click="saveLearning">Guardar y reentrenar</v-btn>
        <v-btn variant="text" :disabled="savingLearning" @click="resetLearningDraft">Descartar cambios</v-btn>
      </div>
      <v-alert v-if="learningError" type="error" variant="tonal" density="comfortable" class="mt-3">{{ learningError }}</v-alert>
      <v-btn class="mt-4" to="/ai" variant="text" prepend-icon="mdi-brain">Ver detalle en la vista de IA</v-btn>
    </DataPanel>
  </div>
</template>

<script>
import store from "../../state/appStore";
import DataPanel from "../ui/DataPanel.vue";

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
      learningConfig: { hidden_neurons: 6, min_cohort: 20 },
      learningDraft: { hidden_neurons: 6, min_cohort: 20 },
      savingLearning: false,
      learningError: "",
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
      this.learningDraft = { ...this.learningConfig };
      this.learningError = "";
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
