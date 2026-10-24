<template>
  <DataPanel
    title="Uso de IA"
    subtitle="La IA es opcional y puede ayudarte a enriquecer la investigación, pero no reemplaza las reglas ni la detección configurada."
    variant="tonal"
    :loading="loading"
    loading-text="Consultando la configuración de IA…"
    :error="error"
    class="ai-settings-panel"
    @refresh="load"
  >
    <template #header-actions>
      <v-chip
        size="small"
        variant="tonal"
        :color="chip.color"
        :prepend-icon="chip.icon"
      >
        {{ chip.label }}
      </v-chip>
    </template>

    <div class="ai-settings-panel__row">
      <div>
        <div class="text-body-2 font-weight-medium">Permitir uso de IA</div>
        <div class="text-caption text-medium-emphasis mt-1">
          Guarda tu permiso para que futuras funciones de IA analicen métricas agregadas.
          Las reglas siguen siendo la base de la detección.
        </div>
      </div>
      <v-switch
        :model-value="enabled"
        :loading="saving"
        :disabled="loading || saving || !confirmed || store.state.wsStatus !== 'online'"
        :aria-label="enabled ? 'Desactivar uso de IA' : 'Activar uso de IA'"
        :aria-describedby="'ai-settings-description'"
        color="success"
        hide-details
        inset
        @update:model-value="toggle"
      />
    </div>
    <div id="ai-settings-description" class="text-caption text-medium-emphasis mt-3" role="status" aria-live="polite">
      {{ description }}
    </div>
    <div v-if="!confirmed && !loading" class="mt-3">
      <v-btn
        size="small"
        variant="tonal"
        color="primary"
        prepend-icon="mdi-refresh"
        :disabled="store.state.wsStatus !== 'online'"
        @click="load"
      >
        Reintentar
      </v-btn>
    </div>
    <v-alert type="info" variant="tonal" density="comfortable" class="mt-4" prepend-icon="mdi-help-circle-outline">
      <strong>Estado actual:</strong> todavía no hay un modelo de IA configurado. Activar el interruptor solo guarda la
      preferencia; no se ejecuta ninguna inferencia ni se envían datos. La captura y las reglas siguen funcionando.
    </v-alert>
  </DataPanel>
</template>

<script>
import DataPanel from "../ui/DataPanel.vue";
import store from "../../state/appStore";
import { aiModelReady, loadAiSettings, setAiEnabled } from "../../utils/aiSettings.js";

export default {
  name: "AiSettingsPanel",
  components: { DataPanel },
  data() {
    return {
      store,
      enabled: false,
      modelStatus: "not_configured",
      // False until the backend has confirmed the value: a failed load is
      // "unknown", never "AI is off".
      confirmed: false,
      loading: true,
      saving: false,
      error: "",
    };
  },
  computed: {
    ready() {
      return aiModelReady({ enabled: this.enabled, modelStatus: this.modelStatus });
    },
    chip() {
      if (this.loading) return { label: "Cargando", color: "secondary", icon: "mdi-progress-clock" };
      if (!this.confirmed) return { label: "Estado desconocido", color: "warning", icon: "mdi-help-circle-outline" };
      if (!this.enabled) return { label: "Desactivada", color: "secondary", icon: "mdi-robot-off-outline" };
      if (this.ready) return { label: "Lista", color: "success", icon: "mdi-robot-happy-outline" };
      return { label: "Permitida · sin modelo", color: "info", icon: "mdi-robot-confused-outline" };
    },
    description() {
      if (this.saving) return "Guardando la preferencia de IA…";
      if (this.loading) return "Consultando la configuración de IA…";
      if (!this.confirmed) return "No se pudo confirmar la preferencia de IA. Reintenta cuando la conexión esté disponible.";
      if (!this.enabled) return "La IA está apagada; el análisis por reglas continúa disponible.";
      if (this.ready) return "La IA está lista para las funciones que la soportan.";
      return "Preferencia guardada: la IA está permitida, pero no hay modelo configurado, así que no se analiza nada.";
    },
  },
  watch: {
    // Reload after a reconnect so a transient outage does not leave the
    // panel stuck on the error from before.
    "store.state.wsStatus"(status, previous) {
      if (status === "online" && previous !== "online" && !this.saving) this.load();
    },
  },
  mounted() {
    this.load();
  },
  methods: {
    async load() {
      if (this.saving) return;
      this.loading = true;
      this.error = "";
      try {
        const settings = await loadAiSettings(this.store);
        this.enabled = settings.enabled;
        this.modelStatus = settings.modelStatus;
        this.confirmed = true;
      } catch (err) {
        this.confirmed = false;
        this.error = err?.message || "No se pudo cargar la configuración de IA.";
      } finally {
        this.loading = false;
      }
    },
    async toggle(value) {
      if (this.saving || this.loading || !this.confirmed) return;
      const next = Boolean(value);
      const previous = this.enabled;
      this.enabled = next;
      this.saving = true;
      this.error = "";
      try {
        const settings = await setAiEnabled(this.store, next);
        this.enabled = settings.enabled;
        this.modelStatus = settings.modelStatus;
      } catch (err) {
        // The last confirmed value stays valid, so the switch remains usable
        // for another attempt.
        this.enabled = previous;
        this.error = err?.message || "No se pudo cambiar el uso de IA.";
      } finally {
        this.saving = false;
      }
    },
  },
};
</script>
