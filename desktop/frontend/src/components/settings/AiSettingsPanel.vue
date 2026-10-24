<template>
  <DataPanel
    title="Uso de IA"
    subtitle="La IA es opcional y puede ayudarte a enriquecer la investigación, pero no reemplaza las reglas ni la detección configurada."
    variant="tonal"
    :loading="loading"
    loading-text="Consultando la configuración de IA…"
    :error="error"
    class="ai-settings-panel"
  >
    <template #header-actions>
      <v-chip
        size="small"
        variant="tonal"
        :color="loading ? 'secondary' : enabled ? 'success' : 'secondary'"
        :prepend-icon="loading ? 'mdi-progress-clock' : enabled ? 'mdi-robot-happy-outline' : 'mdi-robot-off-outline'"
      >
        {{ loading ? "Cargando" : enabled ? "Activada" : "Desactivada" }}
      </v-chip>
    </template>

    <div class="ai-settings-panel__row">
      <div>
        <div class="text-body-2 font-weight-medium">Permitir uso de IA</div>
        <div class="text-caption text-medium-emphasis mt-1">
          Actívala solo si quieres que las funciones de IA disponibles consulten el proveedor configurado.
          Las reglas siguen siendo la base de la detección.
        </div>
      </div>
      <v-switch
        :model-value="enabled"
        :loading="saving"
        :disabled="loading || saving || Boolean(error) || store.state.wsStatus !== 'online'"
        :aria-label="enabled ? 'Desactivar uso de IA' : 'Activar uso de IA'"
        :aria-describedby="'ai-settings-description'"
        color="success"
        hide-details
        inset
        @update:model-value="toggle"
      />
    </div>
    <div id="ai-settings-description" class="text-caption text-medium-emphasis mt-3">
      {{ enabled ? "La IA está disponible para las funciones que la soportan." : "La IA está apagada; el análisis por reglas continúa disponible." }}
    </div>
  </DataPanel>
</template>

<script>
import DataPanel from "../ui/DataPanel.vue";
import store from "../../state/appStore";
import { loadAiSettings, setAiEnabled } from "../../utils/aiSettings.js";

export default {
  name: "AiSettingsPanel",
  components: { DataPanel },
  data() {
    return {
      store,
      enabled: false,
      loading: true,
      saving: false,
      error: "",
    };
  },
  mounted() {
    this.load();
  },
  methods: {
    async load() {
      this.loading = true;
      this.error = "";
      try {
        const settings = await loadAiSettings(this.store);
        this.enabled = settings.enabled;
      } catch (err) {
        this.error = err?.message || "No se pudo cargar la configuración de IA.";
      } finally {
        this.loading = false;
      }
    },
    async toggle(value) {
      if (this.saving || this.loading) return;
      const next = Boolean(value);
      const previous = this.enabled;
      this.enabled = next;
      this.saving = true;
      this.error = "";
      try {
        const settings = await setAiEnabled(this.store, next);
        this.enabled = settings.enabled;
      } catch (err) {
        this.enabled = previous;
        this.error = err?.message || "No se pudo cambiar el uso de IA.";
      } finally {
        this.saving = false;
      }
    },
  },
};
</script>
