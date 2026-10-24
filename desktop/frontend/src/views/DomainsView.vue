<template>
  <div>
    <ViewHeader
      overline="Detección"
      title="Dominios"
      description="Dominios observados en consultas DNS, cabeceras HTTP Host y TLS SNI."
      :refresh-loading="loading"
      @refresh="load"
    />

    <v-alert v-if="error" type="error" variant="tonal" class="mb-4">
      {{ error }}
    </v-alert>

    <v-row dense>
      <v-col v-for="chart in chartPanels" :key="chart.key" cols="12" lg="4">
        <ChartCard
          :title="chart.title"
          :subtitle="chart.subtitle"
          :series="chart.series"
          :fill="chart.fill"
          :color="chart.color"
        />
      </v-col>
    </v-row>

    <EntityTablePanel
      title="Dominios"
      subtitle="Una fila por dominio observado, con la fuente que permitió descubrirlo."
      class="mt-6"
      v-model:live-enabled="liveRefreshEnabled"
      :live-refresh="true"
      :rows="domains"
      :columns="columns"
      :loading="loading"
      :error="error"
      :last-updated="lastUpdated"
      search-enabled
      search-label="Buscar dominios"
      search-placeholder="Domain, source, IP..."
      :page-size="25"
      empty-text="Todavía no se han observado dominios"
      @refresh="load"
    >
      <template #cell-name="{ value }">
        <template v-if="value">
          <span class="mono">{{ value }}</span>
          <ListActionIcons inline :value="value" category="domain" />
        </template>
        <span v-else>-</span>
      </template>
      <template #cell-source="{ value }">
        <v-chip size="x-small" :color="domainSourceColor(value)" variant="tonal">
          {{ domainSourceLabel(value) }}
        </v-chip>
      </template>
      <template #cell-ip="{ value }">
        <template v-if="value">
          <router-link class="mono ip-link" :to="{ path: '/investigate', query: { ip: value } }">
            {{ value }}
          </router-link>
          <ListActionIcons inline :value="value" category="ip" />
        </template>
        <span v-else>-</span>
      </template>
      <template #cell-last_seen="{ value }">
        {{ formatTimestamp(value) }}
      </template>
    </EntityTablePanel>
  </div>
</template>

<script>
import store from "../state/appStore";
import ViewHeader from "../components/ui/ViewHeader.vue";
import EntityTablePanel from "../components/ui/EntityTablePanel.vue";
import ChartCard from "../components/ui/ChartCard.vue";
import ListActionIcons from "../components/ui/ListActionIcons.vue";
import { formatTimestamp, groupSumSeries, topSeriesByValue } from "../utils/traffic";

const DOMAIN_SOURCE_LABELS = {
  dns: "DNS",
  tls_sni: "TLS SNI",
  http_host: "HTTP Host",
};
// Cadence for the stream, in milliseconds.
const FEED_REFRESH_MS = 1000;
const FEED_LIMIT = 500;

export default {
  name: "DomainsView",
  components: {
    ViewHeader,
    ListActionIcons,
    EntityTablePanel,
    ChartCard,
  },
  data() {
    return {
      store,
      loading: false,
      error: "",
      lastUpdated: "",
      domains: [],
      liveRefreshEnabled: true,
      feedHandle: null,
      feedRevision: 0,
      loadRevision: 0,
      disposed: false,
      columns: [
        { key: "name", label: "Domain" },
        { key: "source", label: "Source" },
        { key: "ip", label: "Last IP" },
        { key: "port", label: "Port" },
        { key: "proto", label: "Proto" },
        { key: "hit_count", label: "Hits" },
        { key: "last_seen", label: "Last seen" },
      ],
    };
  },
  computed: {
    chartPanels() {
      return [
        {
          key: "top",
          title: "Top domains by hits",
          subtitle: "Highest-traffic domains in this slice.",
          color: "info",
          fill: "linear-gradient(90deg, rgba(52, 230, 255, 0.94), rgba(74, 136, 255, 0.85))",
          series: topSeriesByValue(this.domains, (item) => item.name, (item) => item.hit_count, 8),
        },
        {
          key: "source",
          title: "By source",
          subtitle: "Total hits grouped by how the domain was observed.",
          color: "warning",
          fill: "linear-gradient(90deg, rgba(255, 159, 67, 0.92), rgba(243, 177, 75, 0.78))",
          series: groupSumSeries(this.domains, (item) => this.domainSourceLabel(item.source), (item) => item.hit_count),
        },
        {
          key: "proto",
          title: "By protocol",
          subtitle: "Total hits grouped by the transport protocol.",
          color: "secondary",
          fill: "linear-gradient(90deg, rgba(158, 130, 255, 0.92), rgba(120, 96, 230, 0.78))",
          series: groupSumSeries(this.domains, (item) => String(item.proto || "").toUpperCase(), (item) => item.hit_count),
        },
      ];
    },
  },
  watch: {
    liveRefreshEnabled(value) {
      if (value) this.openFeed();
      else {
        this.closeFeed();
        this.loading = false;
      }
    },
    "store.state.apiBase"() { this.openFeed(); },
    "store.state.timeRange"() { this.openFeed(); },
  },
  mounted() {
    this.openFeed();
  },
  beforeUnmount() {
    this.disposed = true;
    this.closeFeed();
  },
  methods: {
    formatTimestamp,
    domainSourceLabel(value) {
      return DOMAIN_SOURCE_LABELS[value] || value || "unknown";
    },
    domainSourceColor(value) {
      if (value === "dns") return "info";
      if (value === "tls_sni") return "success";
      if (value === "http_host") return "primary";
      return "secondary";
    },
    // /ws/domains carries the same rows the HTTP listing returned, pushed at
    // the interval in its URL. This view used to re-issue the whole read on
    // every websocket "something changed" event.
    feedContext() {
      return JSON.stringify([this.store.state.apiBase, this.store.state.timeRange]);
    },
    openFeed() {
      this.closeFeed();
      if (this.disposed || !this.liveRefreshEnabled) return;
      const revision = this.feedRevision;
      const context = this.feedContext();
      const current = () => !this.disposed && this.liveRefreshEnabled
        && revision === this.feedRevision && context === this.feedContext();
      this.loading = true;
      this.feedHandle = this.store.openDataFeed(
        "domains",
        { limit: FEED_LIMIT, refresh: FEED_REFRESH_MS, since: this.store.state.timeRange },
        (payload) => { if (current()) this.applyFeed(payload); },
        () => { if (current()) this.load({ silent: true }); },
      );
    },
    closeFeed() {
      // Invalidate callbacks before close(), including an already pending fallback.
      this.feedRevision += 1;
      this.loadRevision += 1;
      this.feedHandle?.close();
      this.feedHandle = null;
    },
    applyFeed(payload) {
      if (this.disposed || !this.liveRefreshEnabled) return;
      if (payload && payload.type === "feed_error") {
        this.error = payload.message || "El flujo de dominios dejó de actualizarse";
        this.loading = false;
        return;
      }
      if (!payload || payload.type !== "feed_data") return;
      this.loadRevision += 1;
      this.domains = this.store.feedListResult(payload).rows;
      this.error = "";
      this.lastUpdated = new Date().toLocaleTimeString("es-ES");
      this.loading = false;
    },
    // Kept as the single-shot fallback for when the stream cannot serve.
    load(options = {}) {
      const automatic = Boolean(options.silent);
      if (this.disposed || (automatic && !this.liveRefreshEnabled)) return Promise.resolve();
      const revision = ++this.loadRevision;
      const context = this.feedContext();
      const current = () => !this.disposed && (!automatic || this.liveRefreshEnabled)
        && revision === this.loadRevision && context === this.feedContext();
      if (!options.silent) this.loading = true;
      this.error = "";
      return this.store
        .listDomains({ limit: 500 })
        .then((payload) => {
          if (!current()) return;
          this.domains = this.store.extractArray(payload);
          this.lastUpdated = new Date().toLocaleTimeString("es-ES");
        })
        .catch((err) => {
          if (!current()) return;
          this.error = (err && err.message) || "No se pudieron cargar los dominios";
        })
        .finally(() => {
          if (current()) this.loading = false;
        });
    },
  },
};
</script>

<style scoped>
.mono {
  font-family: var(--font-mono);
}

.ip-link {
  color: rgba(108, 186, 228, 0.98);
  text-decoration: none;
}

.ip-link:hover {
  text-decoration: underline;
}
</style>
