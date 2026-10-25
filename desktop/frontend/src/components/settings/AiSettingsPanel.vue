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
    <div class="ai-settings-panel__section mt-5">
      <div class="ai-settings-panel__section-heading">
        <div>
          <div class="text-body-2 font-weight-medium">Resumen operativo</div>
          <div class="text-caption text-medium-emphasis mt-1">
            Contexto agregado del sensor para saber qué podría analizar la IA. No es telemetría enviada a un modelo.
          </div>
        </div>
        <v-chip size="x-small" variant="tonal" color="secondary" prepend-icon="mdi-chart-box-outline">
          Solo lectura
        </v-chip>
      </div>
      <div class="ai-settings-panel__metrics" aria-label="Métricas de contexto de IA">
        <div v-for="metric in contextMetrics" :key="metric.label" class="ai-settings-panel__metric">
          <span class="text-caption text-medium-emphasis">{{ metric.label }}</span>
          <strong :class="metric.tone ? `text-${metric.tone}` : ''">{{ metric.value }}</strong>
          <span class="text-caption text-medium-emphasis">{{ metric.detail }}</span>
        </div>
      </div>
    </div>
    <div class="ai-settings-panel__section mt-5">
      <div class="text-body-2 font-weight-medium">Opciones de análisis</div>
      <div class="text-caption text-medium-emphasis mt-1">
        Define el alcance esperado antes de conectar un modelo. Estas opciones no activan inferencias ni cambian la captura.
      </div>
      <div class="ai-settings-panel__options mt-3">
        <div v-for="option in analysisOptions" :key="option.title" class="ai-settings-panel__option">
          <v-icon :icon="option.icon" size="18" color="primary" />
          <div class="ai-settings-panel__option-copy">
            <span class="text-body-2">{{ option.title }}</span>
            <span class="text-caption text-medium-emphasis">{{ option.description }}</span>
          </div>
          <v-chip size="x-small" variant="tonal" :color="option.color">{{ option.status }}</v-chip>
        </div>
      </div>
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
    contextMetrics() {
      const activity = this.store.state.liveActivity || {};
      const runtime = this.store.state.runtime || {};
      const engines = Array.isArray(runtime.running_engines) ? runtime.running_engines.length : 0;
      const online = this.store.state.wsStatus === "online";
      return [
        {
          label: "Actividad",
          value: online ? `${Number(activity.total || 0).toLocaleString("es-ES")}/s` : "—",
          detail: online ? "paquetes recientes" : "sin conexión",
          tone: online && Number(activity.total || 0) > 0 ? "success" : "",
        },
        {
          label: "Procesamiento",
          value: online ? Number(this.store.state.pendingJobs || 0).toLocaleString("es-ES") : "—",
          detail: "jobs pendientes",
          tone: online && Number(this.store.state.pendingJobs || 0) > 0 ? "warning" : "",
        },
        {
          label: "Motores",
          value: online ? `${engines}/2` : "—",
          detail: online ? "en ejecución" : "sin conexión",
          tone: online && engines > 0 ? "success" : "",
        },
        {
          label: "Inferencias",
          value: "0",
          detail: "sin modelo conectado",
          tone: "",
        },
      ];
    },
    analysisOptions() {
      return [
        { icon: "mdi-chart-box-outline", title: "Resumen agregado", description: "Tendencias sin payloads", status: "Preparado", color: "success" },
        { icon: "mdi-shield-lock-outline", title: "Sin payloads", description: "No analiza contenido de paquetes", status: "Protegido", color: "success" },
        { icon: "mdi-cloud-off-outline", title: "Sin envío externo", description: "No se comparte información fuera del sensor", status: "Activo", color: "success" },
        { icon: "mdi-lightbulb-outline", title: "Triage asistido", description: "Se habilitará al configurar un modelo", status: "Próximamente", color: "secondary" },
      ];
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

<style scoped>
.ai-settings-panel__section { border-top: 1px solid rgba(255, 255, 255, 0.08); padding-top: 18px; }
.ai-settings-panel__section-heading { display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; }
.ai-settings-panel__metrics { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; margin-top: 14px; }
.ai-settings-panel__metric { display: flex; flex-direction: column; gap: 3px; min-height: 76px; padding: 11px 12px; border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 10px; background: rgba(255, 255, 255, 0.025); }
.ai-settings-panel__metric strong { font-size: 18px; line-height: 1.1; font-variant-numeric: tabular-nums; }
.ai-settings-panel__options { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; }
.ai-settings-panel__option { display: flex; align-items: center; gap: 10px; min-width: 0; padding: 11px 12px; border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 10px; background: rgba(255, 255, 255, 0.025); }
.ai-settings-panel__option-copy { display: flex; flex: 1; min-width: 0; flex-direction: column; gap: 3px; }
.ai-settings-panel__option-copy span { overflow-wrap: anywhere; }
@media (max-width: 700px) {
  .ai-settings-panel__metrics, .ai-settings-panel__options { grid-template-columns: 1fr 1fr; }
  .ai-settings-panel__section-heading { align-items: flex-start; }
}
</style>
