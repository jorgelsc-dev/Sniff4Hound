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
      title="Muestreo y exclusiones de IA"
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
      <v-row dense>
        <v-col cols="12" md="4">
          <v-select
            v-model="filters.ip_types"
            :items="ipTypeOptions"
            item-title="title"
            item-value="value"
            label="Tipos de IP excluidos"
            multiple chips closable-chips clearable variant="outlined"
          />
        </v-col>
        <v-col cols="12" md="8">
          <v-combobox v-model="filters.cidrs" label="IPs o redes CIDR excluidas" multiple chips closable-chips clearable variant="outlined" />
          <v-combobox v-model="filters.protocols" label="Protocolos excluidos" multiple chips closable-chips clearable variant="outlined" />
          <v-combobox v-model="filters.ports" label="Puertos excluidos" multiple chips closable-chips clearable variant="outlined" />
        </v-col>
      </v-row>
      <div class="d-flex justify-end">
        <v-btn color="primary" variant="flat" :loading="saving" @click="save">Guardar configuración de IA</v-btn>
      </div>
      <v-alert v-if="error" type="error" variant="tonal" density="comfortable" class="mt-3">{{ error }}</v-alert>
      <v-alert v-if="saved" type="success" variant="tonal" density="comfortable" class="mt-3">Configuración guardada.</v-alert>
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
      filters: { ip_types: [], cidrs: [], protocols: [], ports: [] },
      learning: {},
      ipTypeOptions: [
        { title: "Loopback", value: "loopback" },
        { title: "Privadas", value: "private" },
        { title: "Públicas", value: "public" },
        { title: "Multicast", value: "multicast" },
      ],
    };
  },
  computed: {
    training() {
      return this.learning.training || {};
    },
  },
  mounted() {
    this.load();
  },
  methods: {
    load() {
      this.loading = true;
      this.error = "";
      return Promise.all([
        this.store.fetchJsonPromise("/api/ai/config"),
        this.store.fetchJsonPromise("/api/ai/packets/?threshold=50", {}, { preferHttp: true }),
      ])
        .then(([config, snapshot]) => {
          this.samplingEnabled = Boolean(config.sampling_enabled);
          const filters = config.exclusion_filters || {};
          this.filters = {
            ip_types: [...(filters.ip_types || [])],
            cidrs: [...(filters.cidrs || [])],
            protocols: [...(filters.protocols || [])],
            ports: (filters.ports || []).map(String),
          };
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
      const ports = this.filters.ports
        .map((value) => Number(value))
        .filter((value) => Number.isInteger(value) && value >= 0 && value <= 65535);
      this.store.fetchJsonPromise("/api/ai/config", {
        method: "POST",
        body: JSON.stringify({
          sampling_enabled: Boolean(this.samplingEnabled),
          exclusion_filters: {
            ip_types: this.filters.ip_types,
            cidrs: this.filters.cidrs,
            protocols: this.filters.protocols,
            ports,
          },
        }),
      })
        .then(() => { this.saved = true; })
        .catch((error) => { this.error = error.message || "No se pudo guardar la configuración de IA."; })
        .finally(() => { this.saving = false; });
    },
  },
};
</script>
