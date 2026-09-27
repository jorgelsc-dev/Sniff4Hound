<template>
  <div>
    <v-alert type="info" variant="tonal" density="comfortable" class="mb-4">
      El tráfico que coincida con estos criterios se silencia en detección del Sniffer, Monitores
      y muestreo de IA. No afecta la captura cruda ni lo que se guarda. Úsalo para tráfico loopback
      del panel, redes internas conocidas o protocolos/puertos ruidosos que no deben disparar detecciones.
    </v-alert>

    <v-alert v-if="error" type="error" variant="tonal" class="mb-4">{{ error }}</v-alert>

    <DataPanel
      title="Filtro de exclusión"
      subtitle="En coincidencias por tipo de IP/CIDR se revisan ambos extremos; una coincidencia por puerto o protocolo aplica en cualquier dirección."
      variant="tonal"
      :loading="loading"
    >
      <v-row dense>
        <v-col cols="12" md="4">
          <div class="text-caption text-medium-emphasis mb-1">Tipo de IP</div>
          <v-checkbox
            v-for="opt in ipTypeOptions"
            :key="opt.value"
            v-model="draft.ip_types"
            :value="opt.value"
            :label="opt.label"
            density="compact"
            hide-details
          />
        </v-col>
        <v-col cols="12" md="8">
          <v-combobox
            v-model="draft.cidrs"
            label="IPs o bloques CIDR excluidos"
            hint="e.g. 127.0.0.1, 10.0.0.0/8, 203.0.113.5"
            persistent-hint
            multiple chips closable-chips clearable
            variant="outlined"
            density="comfortable"
            class="mb-4"
          />
          <v-combobox
            v-model="draft.protocols"
            label="Protocolos excluidos"
            hint="e.g. dns, icmp, ntp"
            persistent-hint
            multiple chips closable-chips clearable
            variant="outlined"
            density="comfortable"
            class="mb-4"
          />
          <v-combobox
            v-model="draft.ports"
            label="Puertos excluidos"
            hint="Coincide con puerto origen o destino"
            persistent-hint
            multiple chips closable-chips clearable
            variant="outlined"
            density="comfortable"
          />
        </v-col>
      </v-row>
      <div class="d-flex ga-2 mt-2">
        <v-btn color="primary" variant="flat" :loading="saving" @click="save">Guardar filtro</v-btn>
        <v-btn variant="text" :disabled="saving" @click="resetDraft">Descartar cambios</v-btn>
        <v-chip v-if="activeFilterCount" size="small" color="warning" class="align-self-center">
          {{ activeFilterCount }} activos
        </v-chip>
      </div>
      <v-alert v-if="saved" type="success" variant="tonal" density="comfortable" class="mt-3">
        Filtro guardado.
      </v-alert>
    </DataPanel>
  </div>
</template>

<script>
import store from "../../state/appStore";
import DataPanel from "../ui/DataPanel.vue";

const emptyFilters = () => ({ ip_types: [], cidrs: [], protocols: [], ports: [] });

export default {
  name: "ExclusionsPanel",
  components: { DataPanel },
  data() {
    return {
      store,
      loading: false,
      saving: false,
      saved: false,
      error: "",
      filters: emptyFilters(),
      draft: emptyFilters(),
      ipTypeOptions: [
        { value: "loopback", label: "Loopback (127.0.0.1, ::1)" },
        { value: "private", label: "Privada (RFC1918, link-local)" },
        { value: "public", label: "Pública" },
        { value: "multicast", label: "Multicast / broadcast" },
      ],
    };
  },
  computed: {
    activeFilterCount() {
      return (
        this.draft.ip_types.length +
        this.draft.cidrs.length +
        this.draft.protocols.length +
        this.draft.ports.length
      );
    },
  },
  mounted() {
    this.load();
  },
  methods: {
    resetDraft() {
      const source = this.filters || emptyFilters();
      this.draft = {
        ip_types: [...(source.ip_types || [])],
        cidrs: [...(source.cidrs || [])],
        protocols: [...(source.protocols || [])],
        ports: (source.ports || []).map(String),
      };
      this.error = "";
    },
    load() {
      this.loading = true;
      this.error = "";
      return this.store
        .fetchJsonPromise("/api/detection/exclusions")
        .then((payload) => {
          this.filters = payload.exclusion_filters || emptyFilters();
          this.resetDraft();
        })
        .catch((err) => {
          this.error = (err && err.message) || "No se pudo cargar el filtro de exclusión.";
        })
        .finally(() => {
          this.loading = false;
        });
    },
    save() {
      if (this.saving) return;
      this.saving = true;
      this.saved = false;
      this.error = "";
      const ports = this.draft.ports
        .map((value) => Number(value))
        .filter((value) => Number.isInteger(value) && value >= 0 && value <= 65535);
      this.store
        .fetchJsonPromise("/api/detection/exclusions", {
          method: "POST",
          body: JSON.stringify({
            exclusion_filters: {
              ip_types: this.draft.ip_types,
              cidrs: this.draft.cidrs,
              protocols: this.draft.protocols,
              ports,
            },
          }),
        })
        .then((payload) => {
          this.filters = payload.exclusion_filters;
          this.resetDraft();
          this.saved = true;
        })
        .catch((err) => {
          this.error = (err && err.message) || "No se pudo guardar el filtro de exclusión.";
        })
        .finally(() => {
          this.saving = false;
        });
    },
  },
};
</script>
