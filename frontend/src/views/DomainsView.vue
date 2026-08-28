<template>
  <div>
    <ViewHeader
      overline="Detection"
      title="Domains"
      description="Domains observed via DNS lookups, HTTP Host headers, and TLS SNI. Only populated while the matching monitors are enabled."
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
      title="Domains"
      subtitle="One row per distinct domain seen, with the source it was observed through."
      class="mt-6"
      v-model:live-enabled="liveRefreshEnabled"
      :live-refresh="true"
      :rows="domains"
      :columns="columns"
      :loading="loading"
      :error="error"
      :last-updated="lastUpdated"
      search-enabled
      search-label="Search domains"
      search-placeholder="Domain, source, IP..."
      :page-size="25"
      empty-text="No domains observed yet"
      @refresh="load"
    >
      <template #cell-source="{ value }">
        <v-chip size="x-small" :color="domainSourceColor(value)" variant="tonal">
          {{ domainSourceLabel(value) }}
        </v-chip>
      </template>
      <template #cell-ip="{ value }">
        <router-link v-if="value" class="mono ip-link" :to="{ path: '/investigate', query: { ip: value } }">
          {{ value }}
        </router-link>
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
  mounted() {
    this.openFeed();
  },
  beforeUnmount() {
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
    openFeed() {
      this.closeFeed();
      this.loading = true;
      this.feedHandle = this.store.openDataFeed(
        "domains",
        { limit: FEED_LIMIT, refresh: FEED_REFRESH_MS },
        (payload) => this.applyFeed(payload),
        () => {
          this.load({ silent: true }).catch(() => null);
        },
      );
    },
    closeFeed() {
      if (this.feedHandle) {
        this.feedHandle.close();
        this.feedHandle = null;
      }
    },
    applyFeed(payload) {
      if (payload && payload.type === "feed_error") {
        this.error = payload.message || "The domains stream stopped updating";
        this.loading = false;
        return;
      }
      if (!payload || payload.type !== "feed_data") return;
      this.domains = this.store.feedListResult(payload).rows;
      this.error = "";
      this.lastUpdated = new Date().toLocaleTimeString();
      this.loading = false;
    },
    // Kept as the single-shot fallback for when the stream cannot serve.
    load(options = {}) {
      if (!options.silent) this.loading = true;
      this.error = "";
      return this.store
        .listDomains({ limit: 500 })
        .then((payload) => {
          this.domains = this.store.extractArray(payload);
          this.lastUpdated = new Date().toLocaleTimeString();
        })
        .catch((err) => {
          this.domains = [];
          this.error = (err && err.message) || "Failed to load domains";
        })
        .finally(() => {
          this.loading = false;
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
