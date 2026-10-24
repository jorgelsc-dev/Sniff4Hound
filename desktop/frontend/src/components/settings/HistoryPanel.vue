<template>
  <div>
    <v-alert type="info" variant="tonal" density="comfortable" class="mb-4">
      El historial DNS y ARP se guarda <strong>siempre</strong> que el sniffer vea el tráfico: no depende de que haya
      una alerta, y las exclusiones y los ámbitos silenciados solo detienen la <em>detección</em>, no el historial.
      Lo único que lo omite es una IP de la lista blanca, que significa «deja de seguir a este equipo».
      A diferencia de los paquetes, no crece con el tráfico: una consulta repetida suma a un contador en una fila.
    </v-alert>

    <v-alert v-if="error" type="error" variant="tonal" class="mb-4">{{ error }}</v-alert>

    <DataPanel
      title="Qué se registra"
      subtitle="Los cambios se aplican en unos segundos, también en el proceso de captura."
      variant="tonal"
      :loading="loading"
    >
      <v-row dense>
        <v-col cols="12" md="6">
          <v-switch
            v-model="draft.dns_enabled"
            color="primary"
            inset
            hide-details
            label="Historial DNS"
          />
          <div class="text-caption text-medium-emphasis ml-14 mb-4">
            Dominios consultados, direcciones y registros devueltos (A, AAAA, CNAME, MX, TXT...), códigos de respuesta,
            TTL, clientes y resolvers. Incluye mDNS y LLMNR.
          </div>
        </v-col>
        <v-col cols="12" md="6">
          <v-switch
            v-model="draft.arp_enabled"
            color="primary"
            inset
            hide-details
            label="Historial ARP"
          />
          <div class="text-caption text-medium-emphasis ml-14 mb-4">
            Asociaciones IP ↔ MAC, dispositivos detectados y cambios: dispositivo nuevo, IP que cambia de MAC,
            dispositivo con otra IP y discrepancias entre Ethernet y ARP.
          </div>
        </v-col>
      </v-row>
    </DataPanel>

    <DataPanel
      title="Retención"
      subtitle="Las filas se miden por la última vez que se vieron: algo que sigue apareciendo nunca caduca."
      variant="tonal"
      class="mt-4"
      :loading="loading"
    >
      <v-row dense>
        <v-col cols="12" md="3">
          <v-text-field
            v-model.number="draft.retention_days"
            type="number"
            min="0"
            max="3650"
            label="Días a conservar"
            hint="0 = sin límite de tiempo (solo manda el máximo de filas)"
            persistent-hint
            variant="outlined"
            density="comfortable"
          />
        </v-col>
        <v-col cols="12" md="3">
          <v-text-field
            v-model.number="draft.max_dns_rows"
            type="number"
            min="1000"
            label="Máximo de filas DNS"
            variant="outlined"
            density="comfortable"
            persistent-hint
            hint="Se descartan las menos recientes"
          />
        </v-col>
        <v-col cols="12" md="3">
          <v-text-field
            v-model.number="draft.max_arp_bindings"
            type="number"
            min="100"
            label="Máximo de asociaciones ARP"
            variant="outlined"
            density="comfortable"
            persistent-hint
            hint="Pares IP ↔ MAC"
          />
        </v-col>
        <v-col cols="12" md="3">
          <v-text-field
            v-model.number="draft.max_arp_events"
            type="number"
            min="100"
            label="Máximo de cambios ARP"
            variant="outlined"
            density="comfortable"
            persistent-hint
            hint="Eventos registrados"
          />
        </v-col>
      </v-row>
      <div class="d-flex flex-wrap ga-2 mt-2 align-center">
        <v-btn color="primary" variant="flat" :loading="saving" :disabled="!dirty" @click="save">Guardar</v-btn>
        <v-btn variant="text" :disabled="saving || !dirty" @click="resetDraft">Descartar cambios</v-btn>
        <v-btn variant="text" :disabled="saving" @click="useDefaults">Valores por defecto</v-btn>
        <v-chip v-if="saved" size="small" color="success" variant="tonal" prepend-icon="mdi-check">Guardado</v-chip>
      </div>
    </DataPanel>

    <DataPanel
      title="Contenido actual"
      subtitle="Lo que hay guardado ahora mismo."
      variant="tonal"
      class="mt-4"
      :loading="loading"
    >
      <div class="d-flex flex-wrap ga-2 mb-4">
        <v-chip color="info" variant="tonal" prepend-icon="mdi-dns-outline">{{ count("dns_history") }} registros DNS</v-chip>
        <v-chip color="primary" variant="tonal" prepend-icon="mdi-swap-horizontal">{{ count("arp_bindings") }} asociaciones ARP</v-chip>
        <v-chip color="secondary" variant="tonal" prepend-icon="mdi-lan-connect">{{ count("arp_devices") }} dispositivos</v-chip>
        <v-chip color="warning" variant="tonal" prepend-icon="mdi-history">{{ count("arp_events") }} cambios</v-chip>
      </div>
      <div class="d-flex flex-wrap ga-2">
        <v-btn variant="outlined" prepend-icon="mdi-dns-outline" to="/dns">Abrir DNS</v-btn>
        <v-btn variant="outlined" prepend-icon="mdi-lan-connect" to="/arp">Abrir ARP</v-btn>
        <v-spacer />
        <v-btn color="error" variant="text" prepend-icon="mdi-delete-outline" :disabled="clearing" @click="askClear('dns')">Vaciar DNS</v-btn>
        <v-btn color="error" variant="text" prepend-icon="mdi-delete-outline" :disabled="clearing" @click="askClear('arp')">Vaciar ARP</v-btn>
        <v-btn color="error" variant="tonal" prepend-icon="mdi-delete-sweep-outline" :disabled="clearing" @click="askClear('all')">Vaciar todo</v-btn>
      </div>
    </DataPanel>

    <v-dialog v-model="confirm.open" max-width="460">
      <v-card>
        <v-card-title>Vaciar historial {{ scopeLabel(confirm.scope) }}</v-card-title>
        <v-card-text>
          Se van a borrar <strong>{{ Number(confirm.rows).toLocaleString("es-ES") }}</strong> filas. No se puede deshacer.
          Lo que el sniffer vea a partir de ahora se vuelve a registrar.
        </v-card-text>
        <v-card-actions>
          <v-spacer />
          <v-btn variant="text" :disabled="clearing" @click="confirm.open = false">Cancelar</v-btn>
          <v-btn color="error" variant="flat" :loading="clearing" @click="doClear">Borrar</v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>
  </div>
</template>

<script>
import store from "../../state/appStore";
import DataPanel from "../ui/DataPanel.vue";

const DEFAULTS = {
  dns_enabled: true,
  arp_enabled: true,
  retention_days: 90,
  max_dns_rows: 200000,
  max_arp_bindings: 50000,
  max_arp_events: 100000,
};
const SCOPE_LABELS = { dns: "DNS", arp: "ARP", all: "DNS y ARP" };

export default {
  name: "HistoryPanel",
  components: { DataPanel },
  emits: ["changed"],
  data() {
    return {
      store,
      loading: false,
      saving: false,
      saved: false,
      clearing: false,
      error: "",
      config: { ...DEFAULTS },
      draft: { ...DEFAULTS },
      totals: {},
      confirm: { open: false, scope: "all", rows: 0 },
    };
  },
  computed: {
    dirty() {
      return Object.keys(DEFAULTS).some((key) => this.draft[key] !== this.config[key]);
    },
  },
  mounted() {
    this.load();
  },
  methods: {
    scopeLabel(scope) {
      return SCOPE_LABELS[scope] || scope;
    },
    count(key) {
      const value = this.totals ? this.totals[key] : null;
      return value === undefined || value === null ? "-" : Number(value).toLocaleString("es-ES");
    },
    apply(payload) {
      const config = { ...DEFAULTS, ...((payload && payload.config) || {}) };
      this.config = config;
      this.draft = { ...config };
      this.totals = (payload && payload.totals) || {};
    },
    resetDraft() {
      this.draft = { ...this.config };
    },
    useDefaults() {
      this.draft = { ...DEFAULTS };
      this.saved = false;
    },
    load() {
      this.loading = true;
      this.error = "";
      return this.store
        .getHistoryConfig()
        .then((payload) => this.apply(payload))
        .catch((err) => {
          this.error = (err && err.message) || "No se pudo leer la configuración del historial";
        })
        .finally(() => {
          this.loading = false;
        });
    },
    save() {
      this.saving = true;
      this.saved = false;
      this.error = "";
      const payload = {};
      Object.keys(DEFAULTS).forEach((key) => {
        payload[key] = this.draft[key];
      });
      return this.store
        .saveHistoryConfig(payload)
        .then((result) => {
          this.apply(result);
          this.saved = true;
          this.$emit("changed");
        })
        .catch((err) => {
          this.error = (err && err.message) || "No se pudo guardar la configuración del historial";
        })
        .finally(() => {
          this.saving = false;
        });
    },
    // The first call only counts; nothing is deleted until the person confirms.
    askClear(scope) {
      this.error = "";
      return this.store
        .clearHistory(scope)
        .then((preview) => {
          this.confirm = { open: true, scope, rows: Number((preview && preview.rows) || 0) };
        })
        .catch((err) => {
          this.error = (err && err.message) || "No se pudo preparar el borrado";
        });
    },
    doClear() {
      this.clearing = true;
      return this.store
        .clearHistory(this.confirm.scope, { confirm: true })
        .then(() => {
          this.confirm.open = false;
          this.$emit("changed");
          return this.load();
        })
        .catch((err) => {
          this.confirm.open = false;
          this.error = (err && err.message) || "No se pudo vaciar el historial";
        })
        .finally(() => {
          this.clearing = false;
        });
    },
  },
};
</script>
