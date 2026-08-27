<template>
  <div>
    <ViewHeader
      overline="Detection"
      title="IPs"
      description="Distinct source/destination IPs seen in stored (detected) traffic."
      :refresh-loading="loading"
      @refresh="load"
    />

    <v-alert v-if="error" type="error" variant="tonal" class="mb-4">
      {{ error }}
    </v-alert>

    <v-card variant="tonal" class="pa-4 mb-4 scope-filter" rounded="lg">
      <div class="d-flex align-center justify-space-between flex-wrap ga-3">
        <div>
          <div class="text-subtitle-2">Address scope</div>
          <div class="text-caption text-medium-emphasis">
            Loopback is counted separately from private - a 127.0.0.0/8 address is not
            an address on your LAN.
          </div>
        </div>
        <div class="d-flex align-center ga-2 flex-wrap">
          <v-chip
            v-for="option in scopeOptions"
            :key="option.value"
            :color="option.color"
            :variant="isScopeSelected(option.value) ? 'flat' : 'outlined'"
            size="small"
            :disabled="loading"
            @click="toggleScope(option.value)"
          >
            {{ option.label }}
            <span class="scope-filter__count">{{ formatCount(option.addresses) }}</span>
          </v-chip>
          <v-btn
            v-if="selectedScopes.length"
            size="small"
            variant="text"
            :disabled="loading"
            @click="clearScopes"
          >
            Clear
          </v-btn>
        </div>
      </div>
    </v-card>

    <v-row dense>
      <v-col v-for="chart in chartPanels" :key="chart.key" cols="12" md="6">
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
      title="IPs"
      subtitle="One row per distinct IP address seen in stored traffic."
      class="mt-6"
      v-model:live-enabled="liveRefreshEnabled"
      :live-refresh="true"
      :rows="ips"
      :columns="columns"
      :loading="loading"
      :error="error"
      :last-updated="lastUpdated"
      search-enabled
      search-label="Search IPs"
      search-placeholder="IP address..."
      :page-size="25"
      :total-available="meta.totalAvailable"
      :truncated="meta.truncated"
      empty-text="No IPs observed yet"
      @refresh="load"
    >
      <template #cell-ip="{ value }">
        <router-link v-if="value" class="mono ip-link" :to="{ path: '/investigate', query: { ip: value } }">
          {{ value }}
        </router-link>
        <span v-else>-</span>
      </template>
      <template #cell-scope="{ item }">
        <v-chip size="x-small" :color="scopeColor(item.scope)" variant="tonal">
          {{ scopeLabel(item.scope) }}
        </v-chip>
      </template>
      <template #cell-first_seen="{ value }">
        {{ formatTimestamp(value) }}
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
import { formatTimestamp, topSeriesByValue } from "../utils/traffic";

const REFRESH_EVENT_TYPES = new Set(["packet", "stats_update", "runtime_mode"]);

// Mirrors store.IP_SCOPES. "local" is the backend's name for loopback; it is
// shown as "Loopback" because that is what an operator calls 127.0.0.1.
const SCOPE_OPTIONS = [
  { value: "public", label: "Public", color: "warning" },
  { value: "private", label: "Private", color: "secondary" },
  { value: "local", label: "Loopback", color: "info" },
  { value: "multicast", label: "Multicast", color: "purple" },
  { value: "reserved", label: "Reserved", color: "blue-grey" },
  { value: "unknown", label: "Unknown", color: "grey" },
];
const SCOPE_LABELS = new Map(SCOPE_OPTIONS.map((option) => [option.value, option.label]));
const SCOPE_COLORS = new Map(SCOPE_OPTIONS.map((option) => [option.value, option.color]));

export default {
  name: "IpsView",
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
      ips: [],
      liveRefreshEnabled: true,
      wsRefreshTimer: null,
      stopTableRefreshSubscription: null,
      selectedScopes: [],
      // null = no breakdown available (yet, or the header was stripped);
      // {} would wrongly read as "every scope is empty".
      scopeCounts: null,
      meta: { totalAvailable: null, returned: null, truncated: null },
      columns: [
        { key: "ip", label: "IP" },
        { key: "scope", label: "Scope", sortable: false },
        { key: "hit_count", label: "Hits" },
        { key: "first_seen", label: "First seen" },
        { key: "last_seen", label: "Last seen" },
      ],
    };
  },
  computed: {
    chartPanels() {
      return [
        {
          key: "top",
          title: "Top IPs by hits",
          subtitle: "Highest-traffic addresses in this slice.",
          color: "info",
          fill: "linear-gradient(90deg, rgba(52, 230, 255, 0.94), rgba(74, 136, 255, 0.85))",
          series: topSeriesByValue(this.ips, (item) => item.ip, (item) => item.hit_count, 8),
        },
        {
          key: "scope",
          title: "Hits by address scope",
          subtitle: "Counted over the whole slice, not just the loaded page.",
          color: "warning",
          fill: "linear-gradient(90deg, rgba(255, 159, 67, 0.92), rgba(243, 177, 75, 0.78))",
          series: this.scopeSeries,
        },
      ];
    },
    scopeOptions() {
      const counts = this.scopeCounts;
      const options = SCOPE_OPTIONS.map((option) => {
        const bucket = (counts && counts[option.value]) || {};
        return { ...option, addresses: Number(bucket.addresses || 0), hits: Number(bucket.hits || 0) };
      });
      // With no breakdown at all (header stripped by a proxy, or a failed
      // load) keep every chip clickable rather than silently removing the
      // whole filter bar and leaving no sign the feature exists.
      if (!counts) return options;
      return options.filter((option) => option.addresses > 0 || this.isScopeSelected(option.value));
    },
    // Built from the backend's unfiltered breakdown rather than from the
    // loaded rows, so the chart still describes the whole slice while a
    // filter is applied and when the table is truncated to its page limit.
    scopeSeries() {
      return this.scopeOptions
        .filter((option) => option.hits > 0)
        .map((option) => ({ label: option.label, value: option.hits }))
        .sort((left, right) => right.value - left.value);
    },
  },
  mounted() {
    this.load();
    this.stopTableRefreshSubscription = this.store.subscribeTableRefresh(this.handleWsRefresh);
  },
  beforeUnmount() {
    if (this.wsRefreshTimer) {
      clearTimeout(this.wsRefreshTimer);
      this.wsRefreshTimer = null;
    }
    if (typeof this.stopTableRefreshSubscription === "function") {
      this.stopTableRefreshSubscription();
      this.stopTableRefreshSubscription = null;
    }
  },
  methods: {
    formatTimestamp,
    scopeLabel(value) {
      return SCOPE_LABELS.get(String(value || "").trim().toLowerCase()) || "Unknown";
    },
    scopeColor(value) {
      return SCOPE_COLORS.get(String(value || "").trim().toLowerCase()) || "grey";
    },
    formatCount(value) {
      return Number(value || 0).toLocaleString();
    },
    isScopeSelected(value) {
      return this.selectedScopes.includes(value);
    },
    toggleScope(value) {
      this.selectedScopes = this.isScopeSelected(value)
        ? this.selectedScopes.filter((scope) => scope !== value)
        : [...this.selectedScopes, value];
      this.load();
    },
    clearScopes() {
      if (!this.selectedScopes.length) return;
      this.selectedScopes = [];
      this.load();
    },
    handleWsRefresh(event) {
      if (!this.liveRefreshEnabled) return;
      const eventType = String((event && event.type) || "").trim().toLowerCase();
      if (!REFRESH_EVENT_TYPES.has(eventType)) return;
      if (this.wsRefreshTimer) return;
      this.wsRefreshTimer = setTimeout(() => {
        this.wsRefreshTimer = null;
        this.load({ silent: true }).catch(() => {
          // keep current data on transient refresh errors
        });
      }, 10000);
    },
    load(options = {}) {
      if (!options.silent) this.loading = true;
      this.error = "";
      return this.store
        .listIpCatalogWithScopes({ limit: 500, scope: this.selectedScopes })
        .then(({ rows, scopeCounts, meta }) => {
          this.ips = rows;
          this.scopeCounts = scopeCounts;
          this.meta = meta || { totalAvailable: null, returned: null, truncated: null };
          this.lastUpdated = new Date().toLocaleTimeString();
        })
        .catch((err) => {
          this.ips = [];
          // Clear the breakdown too: leaving it would render chips and a
          // chart describing rows that are no longer on screen.
          this.scopeCounts = null;
          this.meta = { totalAvailable: null, returned: null, truncated: null };
          this.error = (err && err.message) || "Failed to load IPs";
        })
        .finally(() => {
          this.loading = false;
        });
    },
  },
};
</script>

<style scoped>
.scope-filter__count {
  margin-left: 6px;
  opacity: 0.7;
  font-variant-numeric: tabular-nums;
}

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
