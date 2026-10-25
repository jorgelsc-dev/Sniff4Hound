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
      <div class="ai-settings-panel__runbar">
        <div>
          <div class="text-body-2 font-weight-medium">Análisis bajo demanda</div>
          <div class="text-caption text-medium-emphasis mt-1">Calcula un nivel de riesgo agregado y sus señales explicables.</div>
        </div>
        <div class="ai-settings-panel__run-actions">
          <v-select v-model="analysisWindow" :items="analysisWindows" label="Ventana" density="compact" hide-details variant="outlined" :disabled="!ready || analyzing" />
          <v-btn color="primary" prepend-icon="mdi-play-circle-outline" :loading="analyzing" :disabled="!ready || analyzing" @click="runAnalysis">Analizar ahora</v-btn>
        </div>
      </div>
      <div v-if="currentResult" class="ai-settings-panel__result mt-3">
        <div class="ai-settings-panel__score">
          <span class="text-caption text-medium-emphasis">Riesgo agregado</span>
          <strong>{{ resultScore }}/100</strong>
          <v-chip size="x-small" variant="tonal" color="warning">{{ currentResult.label }}</v-chip>
          <span class="text-caption text-medium-emphasis">Confianza {{ Math.round((currentResult.confidence || 0) * 100) }}%</span>
        </div>
        <div class="ai-settings-panel__findings">
          <div v-for="finding in resultFindings" :key="finding.title" class="ai-settings-panel__finding">
            <v-icon :icon="finding.severity === 'high' ? 'mdi-alert' : finding.severity === 'medium' ? 'mdi-alert-outline' : 'mdi-information-outline'" size="17" color="primary" />
            <div><strong>{{ finding.title }}</strong><span>{{ finding.detail }}</span></div>
          </div>
        </div>
        <div class="ai-settings-panel__features" aria-label="Variables usadas por el análisis">
          <div v-for="feature in featureBars" :key="feature.label" class="ai-settings-panel__feature">
            <span>{{ feature.label }}</span><b>{{ feature.value }}</b><i><em :style="{ width: feature.width }" /></i>
          </div>
        </div>
      </div>
    </div>
    <div class="ai-settings-panel__section mt-5">
      <div class="ai-settings-panel__section-heading">
        <div>
          <div class="text-body-2 font-weight-medium">Modelo y ejecución</div>
          <div class="text-caption text-medium-emphasis mt-1">
            Motor local sobre métricas agregadas, con ejecuciones medibles y sin datos sensibles.
          </div>
        </div>
        <v-chip size="x-small" variant="tonal" :color="ready ? 'success' : 'warning'" prepend-icon="mdi-robot-outline">
          {{ modelSummary.status }}
        </v-chip>
      </div>
      <div class="ai-settings-panel__model-grid mt-3">
        <div v-for="item in modelSummary.items" :key="item.label" class="ai-settings-panel__model-item">
          <span class="text-caption text-medium-emphasis">{{ item.label }}</span>
          <strong>{{ item.value }}</strong>
          <span class="text-caption text-medium-emphasis">{{ item.detail }}</span>
        </div>
      </div>
      <v-alert type="info" variant="tonal" density="compact" class="mt-3" prepend-icon="mdi-information-outline">
        <strong>Qué hace hoy:</strong> ejecuta un análisis local determinista sobre métricas agregadas. No lee payloads,
        no envía datos fuera del sensor y no bloquea la captura.
      </v-alert>
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
        Define el alcance del motor local. Estas opciones no cambian la captura.
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
    <div class="ai-settings-panel__section mt-5">
      <div class="ai-settings-panel__section-heading">
        <div>
          <div class="text-body-2 font-weight-medium">Gráfico de actividad agregada</div>
          <div class="text-caption text-medium-emphasis mt-1">
            Muestra la actividad agregada que acompaña al análisis; no representa predicciones ni puntuaciones del modelo.
          </div>
        </div>
        <v-chip size="x-small" variant="outlined" color="secondary">{{ activityPeak }} paq/s pico</v-chip>
      </div>
      <div class="ai-settings-panel__chart mt-3" role="img" :aria-label="activityChartLabel">
        <svg viewBox="0 0 360 108" preserveAspectRatio="none" aria-hidden="true">
          <line v-for="line in chartGrid" :key="line" x1="0" :y1="line" x2="360" :y2="line" class="ai-settings-panel__chart-grid" />
          <polyline :points="activityChartPoints" class="ai-settings-panel__chart-line" />
          <circle v-for="point in activityChartDots" :key="point.key" :cx="point.x" :cy="point.y" r="2.5" class="ai-settings-panel__chart-dot" />
        </svg>
        <div class="ai-settings-panel__chart-empty" v-if="!hasActivity">Aún no hay actividad agregada disponible.</div>
      </div>
      <div class="ai-settings-panel__chart-footer text-caption text-medium-emphasis">
        <span>Promedio: {{ activityAverage }} paq/s</span>
        <span>{{ activitySamples.length }} muestras recientes</span>
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
      <strong>Privacidad:</strong> el motor usa solamente contadores y métricas agregadas. No procesa payloads ni envía
      datos a proveedores externos; la captura y las reglas siguen funcionando independientemente.
    </v-alert>
  </DataPanel>
</template>

<script>
import DataPanel from "../ui/DataPanel.vue";
import store from "../../state/appStore";
import { aiModelReady, loadAiAnalysis, loadAiSettings, runAiAnalysis, setAiEnabled } from "../../utils/aiSettings.js";

export default {
  name: "AiSettingsPanel",
  components: { DataPanel },
  data() {
    return {
      store,
      enabled: false,
      modelStatus: "not_configured",
      analysisState: { provider: "Local aggregate engine", model: "sniff4hound-aggregate-risk-v1", totalRuns: 0, totalFindings: 0, lastRun: null, history: [] },
      // False until the backend has confirmed the value: a failed load is
      // "unknown", never "AI is off".
      confirmed: false,
      loading: true,
      saving: false,
      analyzing: false,
      analysisWindow: "24h",
      analysisWindows: [
        { title: "Últimas 24 horas", value: "24h" },
        { title: "Últimos 7 días", value: "7d" },
        { title: "Todo", value: "" },
      ],
      error: "",
      activitySamples: [Number(store.state.liveActivity?.total) || 0],
      lastActivitySample: null,
    };
  },
  computed: {
    ready() {
      return aiModelReady({ enabled: this.enabled, modelStatus: this.modelStatus });
    },
    modelSummary() {
      const status = this.loading ? "Consultando" : this.modelStatus === "ready" ? (this.enabled ? "Modelo listo" : "Disponible · apagada") : "Sin modelo";
      return {
        status,
        items: [
          { label: "Proveedor", value: this.analysisState.provider, detail: "ejecución local" },
          { label: "Modelo", value: this.analysisState.model, detail: this.ready ? "operativo" : "activa la IA" },
          { label: "Ejecuciones", value: this.analysisState.totalRuns.toLocaleString("es-ES"), detail: `${this.analysisState.totalFindings.toLocaleString("es-ES")} señales` },
          { label: "Última ejecución", value: this.lastRunLabel, detail: this.analysisState.lastRun ? "resultado disponible" : "sin historial" },
        ],
      };
    },
    lastRunLabel() {
      if (!this.analysisState.lastRun?.generated_at) return "Nunca";
      return new Date(this.analysisState.lastRun.generated_at).toLocaleTimeString("es-ES", { hour: "2-digit", minute: "2-digit" });
    },
    currentResult() { return this.analysisState.lastRun; },
    resultScore() {
      return this.currentResult ? Number(this.currentResult.score || 0).toLocaleString("es-ES", { maximumFractionDigits: 1 }) : "—";
    },
    resultFindings() { return this.currentResult?.findings || []; },
    featureBars() {
      const features = this.currentResult?.features || {};
      const max = Math.max(1, ...Object.values(features).map(value => Number(value) || 0));
      return Object.entries(features).slice(0, 8).map(([label, value]) => ({ label, value, width: `${Math.max(3, (Number(value) / max) * 100)}%` }));
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
        { icon: "mdi-lightbulb-outline", title: "Triage asistido", description: "Señales explicables del análisis agregado", status: "Disponible", color: "success" },
      ];
    },
    hasActivity() {
      return this.activitySamples.some(value => Number(value) > 0);
    },
    activityPeak() {
      return Math.max(0, ...this.activitySamples.map(value => Number(value) || 0)).toLocaleString("es-ES");
    },
    activityAverage() {
      if (!this.activitySamples.length) return "0";
      const average = this.activitySamples.reduce((sum, value) => sum + (Number(value) || 0), 0) / this.activitySamples.length;
      return average.toLocaleString("es-ES", { maximumFractionDigits: 1 });
    },
    chartGrid() {
      return [20, 54, 88];
    },
    activityChartPoints() {
      return this.activityChartDots.map(point => `${point.x},${point.y}`).join(" ");
    },
    activityChartDots() {
      const samples = this.activitySamples.length ? this.activitySamples : [0];
      const max = Math.max(1, ...samples.map(value => Number(value) || 0));
      const denominator = Math.max(1, samples.length - 1);
      return samples.map((value, index) => ({
        key: `${index}-${value}`,
        x: (index / denominator) * 360,
        y: 94 - ((Number(value) || 0) / max) * 76,
      }));
    },
    activityChartLabel() {
      return `Actividad agregada del sensor: pico ${this.activityPeak} paquetes por segundo, promedio ${this.activityAverage} paquetes por segundo`;
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
    "store.state.liveActivity": {
      deep: true,
      handler(value) {
        if (this.store.state.wsStatus !== "online") return;
        const sample = Number(value?.total) || 0;
        if (sample === this.lastActivitySample) return;
        this.lastActivitySample = sample;
        this.activitySamples = [...this.activitySamples, sample].slice(-24);
      },
    },
  },
  mounted() {
    this.lastActivitySample = Number(this.store.state.liveActivity?.total) || 0;
    this.activitySamples = [this.lastActivitySample];
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
        this.analysisState = settings;
        this.confirmed = true;
      } catch (err) {
        this.confirmed = false;
        this.error = err?.message || "No se pudo cargar la configuración de IA.";
      } finally {
        this.loading = false;
      }
    },
    async loadAnalysis() {
      try {
        this.analysisState = await loadAiAnalysis(this.store);
      } catch (err) {
        this.error = err?.message || "No se pudieron cargar las estadísticas de IA.";
      }
    },
    async runAnalysis() {
      if (this.analyzing || !this.ready) return;
      this.analyzing = true;
      this.error = "";
      try {
        this.analysisState = await runAiAnalysis(this.store, this.analysisWindow);
      } catch (err) {
        this.error = err?.message || "No se pudo ejecutar el análisis de IA.";
      } finally {
        this.analyzing = false;
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
        this.analysisState = { ...this.analysisState, ...settings };
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
.ai-settings-panel__model-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; }
.ai-settings-panel__model-item { display: flex; flex-direction: column; gap: 3px; min-height: 70px; padding: 10px 12px; border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 10px; background: rgba(255, 255, 255, 0.025); }
.ai-settings-panel__model-item strong { font-size: 15px; line-height: 1.15; overflow-wrap: anywhere; }
.ai-settings-panel__options { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; }
.ai-settings-panel__option { display: flex; align-items: center; gap: 10px; min-width: 0; padding: 11px 12px; border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 10px; background: rgba(255, 255, 255, 0.025); }
.ai-settings-panel__option-copy { display: flex; flex: 1; min-width: 0; flex-direction: column; gap: 3px; }
.ai-settings-panel__option-copy span { overflow-wrap: anywhere; }
.ai-settings-panel__chart { position: relative; height: 128px; padding: 10px 0; border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 10px; background: rgba(255, 255, 255, 0.025); overflow: hidden; }
.ai-settings-panel__chart svg { display: block; width: 100%; height: 100%; }
.ai-settings-panel__chart-grid { stroke: rgba(255, 255, 255, 0.1); stroke-dasharray: 3 5; }
.ai-settings-panel__chart-line { fill: none; stroke: rgb(var(--v-theme-primary)); stroke-width: 2.5; stroke-linecap: round; stroke-linejoin: round; }
.ai-settings-panel__chart-dot { fill: rgb(var(--v-theme-primary)); }
.ai-settings-panel__chart-empty { position: absolute; inset: 0; display: grid; place-items: center; color: rgba(255, 255, 255, 0.48); font-size: 12px; }
.ai-settings-panel__chart-footer { display: flex; justify-content: space-between; gap: 12px; margin-top: 7px; }
.ai-settings-panel__runbar { display: flex; align-items: flex-end; justify-content: space-between; gap: 16px; }
.ai-settings-panel__run-actions { display: flex; align-items: center; gap: 10px; min-width: 320px; }
.ai-settings-panel__run-actions .v-select { max-width: 150px; }
.ai-settings-panel__result { display: grid; grid-template-columns: 150px minmax(240px, 1fr) minmax(220px, 1fr); gap: 16px; padding: 14px; border: 1px solid rgba(255,255,255,.08); border-radius: 10px; background: rgba(255,255,255,.025); }
.ai-settings-panel__score { display: flex; flex-direction: column; align-items: flex-start; gap: 5px; }
.ai-settings-panel__score strong { font-size: 30px; line-height: 1; font-variant-numeric: tabular-nums; }
.ai-settings-panel__findings { display: flex; flex-direction: column; gap: 9px; }
.ai-settings-panel__finding { display: flex; gap: 8px; align-items: flex-start; }
.ai-settings-panel__finding div { display: flex; flex-direction: column; gap: 2px; min-width: 0; }
.ai-settings-panel__finding span { font-size: 12px; color: rgba(255,255,255,.6); }
.ai-settings-panel__features { display: flex; flex-direction: column; gap: 7px; }
.ai-settings-panel__feature { display: grid; grid-template-columns: 105px 28px 1fr; align-items: center; gap: 7px; font-size: 12px; }
.ai-settings-panel__feature b { text-align: right; font-variant-numeric: tabular-nums; }
.ai-settings-panel__feature i { display: block; height: 6px; border-radius: 6px; background: rgba(255,255,255,.1); overflow: hidden; }
.ai-settings-panel__feature em { display: block; height: 100%; border-radius: inherit; background: rgb(var(--v-theme-primary)); }
@media (max-width: 700px) {
  .ai-settings-panel__metrics, .ai-settings-panel__model-grid, .ai-settings-panel__options { grid-template-columns: 1fr 1fr; }
  .ai-settings-panel__runbar, .ai-settings-panel__result { display: flex; flex-direction: column; align-items: stretch; }
  .ai-settings-panel__run-actions { min-width: 0; }
  .ai-settings-panel__section-heading { align-items: flex-start; }
}
</style>
