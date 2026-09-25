<template>
  <div class="statistics-dashboard">
    <ViewHeader overline="OPERACIONES" title="Dashboard" description="Actividad de red y estadísticas de la telemetría almacenada."
      show-time-range :refresh-loading="loading" refresh-label="Actualizar" @refresh="load" />

    <div class="dashboard-toolbar">
      <span class="text-caption text-medium-emphasis" role="status">{{ loading ? 'Actualizando métricas…' : lastUpdated ? `Actualizado ${lastUpdated}` : 'Esperando datos' }}</span>
      <div class="dashboard-links">
        <v-btn to="/dashboard/overview" size="small" variant="text" prepend-icon="mdi-shield-alert-outline">Alertas IA</v-btn>
        <v-btn to="/dashboard/node-map" size="small" variant="text" prepend-icon="mdi-graph-outline">Nodos</v-btn>
        <v-btn to="/dashboard/live-map" size="small" variant="text" prepend-icon="mdi-earth">Mapa en vivo</v-btn>
      </div>
    </div>
    <v-alert v-if="error" type="error" variant="tonal" class="mb-4">{{ error }}</v-alert>

    <SystemFlowCanvas
      class="mb-4"
      :totals="flowTotals"
      :runtime="dashboard?.runtime || store.state.runtime || {}"
      :activity="store.state.liveActivity"
      :online="store.state.wsStatus === 'online'"
      @open="$router.push($event.route)"
    />

    <div class="metrics-grid">
      <v-card v-for="metric in metrics" :key="metric.label" class="stat-card" variant="tonal">
        <div class="stat-heading"><span>{{ metric.label }}</span><v-icon :icon="metric.icon" :color="metric.color" size="21" /></div>
        <div class="stat-value" :class="`text-${metric.color}`">{{ analytics ? number(metric.value) : '—' }}</div>
        <div class="text-caption text-medium-emphasis">{{ metric.caption }}</div>
      </v-card>
    </div>

    <div class="charts-grid">
      <v-card variant="tonal" class="activity-card">
        <div class="panel-heading">
          <div><h2>Actividad histórica</h2><p>Registros por día · últimos 30 días con actividad del período</p></div>
          <v-icon icon="mdi-chart-timeline-variant" color="primary" />
        </div>
        <div v-if="timeline.length" class="activity-chart" role="img" aria-label="Histograma de registros por día. Cada barra indica fecha y cantidad.">
          <div v-for="day in timeline" :key="day.label" class="activity-column">
            <span class="activity-count">{{ number(day.value) }}</span>
            <div class="activity-track"><div class="activity-bar" :style="{ height: `${day.width}%` }"><v-tooltip activator="parent">{{ day.label }}: {{ number(day.value) }} registros</v-tooltip></div></div>
            <span class="activity-date">{{ day.label.slice(5) }}</span>
          </div>
        </div>
        <div v-else class="empty-chart"><v-icon icon="mdi-chart-bar" size="40" /><p>{{ loading ? 'Cargando actividad…' : 'Sin actividad registrada en este período' }}</p></div>
      </v-card>
      <ChartCard title="Distribución por protocolo" subtitle="Cantidad de paquetes por protocolo" :series="protocols" empty-text="Sin protocolos registrados en este período." />
      <ChartCard title="Hosts con más actividad" subtitle="Apariciones como origen o destino de paquetes" :series="hosts" empty-text="Sin hosts registrados en este período." />
      <ChartCard title="Puertos más frecuentes" subtitle="Paquetes por puerto de destino (u origen si no hay destino)" :series="ports" color="success" fill="linear-gradient(90deg, #20bda9, #64dfc4)" empty-text="Sin puertos registrados en este período." />
      <ChartCard title="Etiquetas detectadas" subtitle="Coincidencias de reglas y metadatos analizados" :series="tags" color="warning" fill="linear-gradient(90deg, #d89932, #f4cc79)" empty-text="Sin etiquetas registradas en este período." />
    </div>
  </div>
</template>

<script>
import store from "../state/appStore";
import ViewHeader from "../components/ui/ViewHeader.vue";
import ChartCard from "../components/ui/ChartCard.vue";
import SystemFlowCanvas from "../components/flow/SystemFlowCanvas.vue";

function series(rows, key = "label", limit = 8) {
  const items = (Array.isArray(rows) ? rows : []).slice(0, limit);
  const max = Math.max(1, ...items.map((row) => Number(row.value) || 0));
  return items.map((row) => ({ label: String(row[key]), value: Number(row.value) || 0, width: (Number(row.value) || 0) / max * 100 }));
}

export default {
  name: "DashboardHubView",
  components: { ViewHeader, ChartCard, SystemFlowCanvas },
  data: () => ({ store, analytics: null, dashboard: null, loading: false, error: "", lastUpdated: "", requestId: 0, refreshTimer: null, unsubscribe: null }),
  computed: {
    apiBase() { return this.store.state.apiBase; },
    metrics() {
      const s = this.analytics?.summary || {};
      return [
        { label: "Paquetes almacenados", value: s.ports, caption: "Telemetría del período", icon: "mdi-ethernet", color: "primary" },
        { label: "Hosts únicos", value: s.unique_hosts, caption: "Direcciones IP observadas", icon: "mdi-lan-connect", color: "info" },
        { label: "Protocolos", value: this.analytics?.ports_by_proto?.length, caption: "Familias de tráfico detectadas", icon: "mdi-source-branch", color: "success" },
        { label: "Etiquetas", value: s.tags, caption: "Reglas y metadatos registrados", icon: "mdi-tag-multiple-outline", color: "warning" },
        { label: "Respuestas", value: s.banners, caption: "Payloads y banners guardados", icon: "mdi-server-network", color: "secondary" },
        { label: "Paquetes filtrados", value: s.filtered_ports, caption: "Registros con estado filtrado", icon: "mdi-filter-outline", color: "warning" },
      ];
    },
    protocols() { return series(this.analytics?.ports_by_proto); },
    hosts() { return series(this.analytics?.top_ips_by_open_ports, "ip"); },
    ports() { return series(this.analytics?.top_open_ports, "port"); },
    tags() { return series(this.analytics?.top_tag_keys); },
    timeline() { return series(this.analytics?.timeline, "label", 30); },
    // Every figure here comes straight from dashboard_snapshot()/analytics_snapshot();
    // the canvas adds no derived metrics of its own beyond the live packet rate.
    flowTotals() {
      const counts = this.dashboard?.counts || {};
      const sniffer = this.dashboard?.runtime?.sniffer || {};
      return {
        interfaces: (sniffer.interfaces || []).length,
        packets: counts.count_ports,
        protocols: this.analytics?.ports_by_proto?.length,
        monitors: counts.count_monitors,
        payloads: counts.count_banners,
        detections: counts.count_tags,
      };
    },
  },
  watch: { apiBase() { this.load(); } },
  mounted() {
    this.load();
    this.unsubscribe = store.subscribeTableRefresh((event) => {
      if (!["packet", "stats_update", "runtime_mode"].includes(event?.type) || this.refreshTimer) return;
      this.refreshTimer = setTimeout(() => { this.refreshTimer = null; this.load(); }, 10000);
    });
  },
  beforeUnmount() {
    this.requestId++;
    clearTimeout(this.refreshTimer);
    this.unsubscribe?.();
  },
  methods: {
    number(value) { return Number(value || 0).toLocaleString("es"); },
    async load() {
      const id = ++this.requestId;
      this.loading = true;
      this.error = "";
      const params = new URLSearchParams({ compact: "1" });
      if (store.state.timeRange) params.set("since", store.state.timeRange);
      const results = await Promise.allSettled([
        store.fetchJsonPromise(`/api/charts/analytics?${params}`),
        store.fetchJsonPromise(`/api/dashboard/?${params}`),
      ]);
      if (id !== this.requestId) return;
      this.analytics = results[0].status === "fulfilled" ? results[0].value : null;
      this.dashboard = results[1].status === "fulfilled" ? results[1].value : null;
      this.error = results.some((result) => result.status === "rejected") ? "No se pudieron cargar todos los datos. Pulsa actualizar para volver a intentar." : "";
      this.lastUpdated = this.analytics ? new Date().toLocaleTimeString("es") : "";
      this.loading = false;
    },
  },
};
</script>

<style scoped>
.dashboard-toolbar, .dashboard-links, .stat-heading, .panel-heading { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
.dashboard-toolbar { margin-bottom: 18px; flex-wrap: wrap; }
.dashboard-links { flex-wrap: wrap; gap: 4px; }
.metrics-grid { display: grid; grid-template-columns: repeat(6, minmax(0, 1fr)); gap: 12px; margin-bottom: 18px; }
.stat-card { padding: 18px; border-radius: 12px; background: linear-gradient(135deg, rgba(26, 111, 136, .12), transparent); }
.stat-heading { font-size: .8rem; color: rgb(var(--v-theme-on-surface)); }
.stat-value { font-size: 1.9rem; font-weight: 700; font-family: var(--font-mono); margin: 10px 0 4px; overflow-wrap: anywhere; }
.charts-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 16px; }
.activity-card { grid-column: span 2; }
.activity-card { padding: 22px; border-radius: 16px; }
h2 { font-size: 1rem; font-weight: 600; }
.panel-heading p { font-size: .75rem; opacity: .65; margin-top: 4px; }
.activity-chart { display: flex; gap: 8px; height: 220px; margin-top: 24px; overflow-x: auto; }
.activity-column { flex: 1; min-width: 34px; display: flex; flex-direction: column; align-items: center; }
.activity-count, .activity-date { font-size: .65rem; opacity: .7; white-space: nowrap; }
.activity-track { height: 170px; width: 100%; display: flex; align-items: flex-end; border-bottom: 1px solid rgba(120, 190, 220, .2); margin: 8px 0; background: repeating-linear-gradient(to top, transparent 0, transparent 41px, rgba(120, 190, 220, .08) 42px); }
.activity-bar { width: 75%; margin: 0 auto; background: linear-gradient(0deg, #17618f, #32d4e5); border-radius: 4px 4px 0 0; min-height: 2px; }
.empty-chart { min-height: 220px; display: grid; place-content: center; justify-items: center; gap: 12px; opacity: .55; font-size: .85rem; }
@media (max-width: 1280px) { .metrics-grid { grid-template-columns: repeat(3, minmax(0, 1fr)); } .charts-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
@media (max-width: 700px) { .metrics-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); } .charts-grid { grid-template-columns: minmax(0, 1fr); } .activity-card { grid-column: auto; } .stat-card { padding: 14px; } }
</style>
