<template>
  <v-menu location="bottom end">
    <template #activator="{ props: menuProps }">
      <v-btn
        v-bind="menuProps"
        variant="outlined"
        color="primary"
        density="comfortable"
        prepend-icon="mdi-file-export-outline"
        :loading="busy"
        aria-label="Exportar indicadores"
      >
        Exportar
      </v-btn>
    </template>
    <v-list density="compact" min-width="260">
      <v-list-subheader>Descargar indicadores</v-list-subheader>
      <template v-for="dataset in datasets" :key="dataset">
        <v-list-item
          :title="`${labelFor(dataset)} (CSV)`"
          :subtitle="descriptionFor(dataset)"
          prepend-icon="mdi-file-delimited-outline"
          @click="download(dataset, 'csv')"
        />
        <v-list-item
          :title="`${labelFor(dataset)} (JSON)`"
          prepend-icon="mdi-code-json"
          @click="download(dataset, 'json')"
        />
      </template>
    </v-list>
  </v-menu>
</template>

<script>
import store from "../../state/appStore";

const DATASET_LABELS = {
  alerts: "Alertas",
  endpoints: "Endpoints",
  flows: "Flujos",
  domains: "Dominios",
};

const DATASET_DESCRIPTIONS = {
  alerts: "Regla, severidad, 5-tupla, evidencia y primer/último avistamiento",
  endpoints: "IPs observadas con conteo de hits y peor severidad",
  flows: "Flujos activos en la ventana y conteo total de paquetes/bytes",
  domains: "Dominios vistos en tráfico DNS, TLS-SNI o HTTP",
};

export default {
  name: "IocExportMenu",
  props: {
    // Datasets offered by this menu, in order. Must match the names
    // sniff4hound/export.py exposes under /api/export/.
    datasets: {
      type: Array,
      default: () => ["alerts", "endpoints", "flows", "domains"],
    },
    // Extra query parameters (search, severity, proto) forwarded verbatim.
    params: {
      type: Object,
      default: () => ({}),
    },
  },
  data() {
    return {
      store,
      busy: false,
    };
  },
  methods: {
    labelFor(dataset) {
      return DATASET_LABELS[dataset] || dataset;
    },
    descriptionFor(dataset) {
      return DATASET_DESCRIPTIONS[dataset] || "";
    },
    download(dataset, format) {
      if (this.busy) return;
      this.busy = true;
      this.store
        .downloadIocExport(dataset, format, this.params)
        .then((filename) => {
          this.store.pushNotification({
            kind: "export",
            severity: "info",
            title: "Indicadores exportados",
            message: `Descargado ${filename}`,
            groupKey: `ioc-export:${dataset}`,
          });
        })
        .catch((error) => {
          this.store.pushNotification({
            kind: "export",
            severity: "high",
            title: "Falló la exportación",
            message: String((error && error.message) || error),
            groupKey: `ioc-export-error:${dataset}`,
          });
        })
        .finally(() => {
          this.busy = false;
        });
    },
  },
};
</script>
