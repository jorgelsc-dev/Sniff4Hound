<template>
  <div>
    <ViewHeader
      overline="Recon"
      title="Traffic Radar"
      description="Map active hosts, highlight busy ports, and jump into the busiest IPs."
      :refresh-loading="loading"
      @refresh="load"
    />

    <v-row dense>
      <v-col v-for="metric in metricCards" :key="metric.key" cols="12" sm="6" xl="3">
        <v-card variant="tonal" class="pa-5 metric-card">
          <div class="d-flex align-center justify-space-between ga-3">
            <div>
              <div class="text-caption text-medium-emphasis">{{ metric.label }}</div>
              <div class="text-h5 font-weight-bold" :class="metric.colorClass">{{ metric.value }}</div>
            </div>
            <v-icon :icon="metric.icon" class="metric-icon" :class="metric.colorClass" />
          </div>
          <div class="text-caption text-medium-emphasis mt-3">{{ metric.caption }}</div>
        </v-card>
      </v-col>
    </v-row>

    <v-alert v-if="error" type="error" variant="tonal" class="mt-6">
      {{ error }}
    </v-alert>

    <div class="mt-6">
      <HostRadarPanel
        title="Host Interaction Radar"
        subtitle="Loopback and private hosts only - clickable nodes and animated traffic relationships inside your network."
        :snapshot="mapSnapshot"
        :top-hosts="topHosts"
        :host-alerts="hostAlerts"
        :loading="loading"
        :error="error"
        :last-updated="lastUpdated"
        :show-refresh="true"
        :live-refresh="false"
        :live-enabled="false"
        @refresh="load"
      />
    </div>

    <div class="mt-6">
      <MapPanel
        panel-title="Topology Radar"
        panel-subtitle="See host placement and point density at a glance."
        :snapshot="mapSnapshot"
        :external-realtime="true"
        :show-refresh="true"
        :show-panel-header="true"
        :show-intro="false"
        :show-projection-switch="true"
        default-projection="flat"
        :immersive="true"
      />
    </div>

    <v-row class="mt-4" dense>
      <v-col cols="12" xl="6">
        <EntityTablePanel
          title="Risk Ports"
          subtitle="Highest hit ports seen in the current slice."
          :rows="riskPorts"
          :columns="riskPortColumns"
          :loading="loading"
          :error="error"
          :last-updated="lastUpdated"
          :live-refresh="true"
          :search-enabled="true"
          search-label="Search ports"
          search-placeholder="Port, hit count, or label"
          empty-text="No risk ports yet"
          :page-size="12"
          @refresh="load"
        >
          <template #cell-port="{ value }">
            <v-chip size="x-small" color="warning" variant="tonal">
              {{ value }}
            </v-chip>
          </template>
        </EntityTablePanel>
      </v-col>

      <v-col cols="12" xl="6">
        <EntityTablePanel
          title="Top Hosts"
          subtitle="Hosts with the most open ports."
          :rows="topHosts"
          :columns="hostColumns"
          :loading="loading"
          :error="error"
          :last-updated="lastUpdated"
          :live-refresh="true"
          :search-enabled="true"
          search-label="Search hosts"
          search-placeholder="IP or open ports"
          empty-text="No host activity yet"
          :page-size="12"
          @refresh="load"
        >
          <template #cell-ip="{ item, value }">
            <router-link class="host-link" :to="{ path: '/investigate', query: { ip: value } }">
              {{ item.ip }}
            </router-link>
          </template>
          <template #cell-value="{ value }">
            <v-chip size="x-small" color="info" variant="tonal">
              {{ value }}
            </v-chip>
          </template>
        </EntityTablePanel>
      </v-col>
    </v-row>
  </div>
</template>

<script>
import store from "../state/appStore";
import ViewHeader from "../components/ui/ViewHeader.vue";
import EntityTablePanel from "../components/ui/EntityTablePanel.vue";
import HostRadarPanel from "../components/HostRadarPanel.vue";
import MapPanel from "../components/MapPanel.vue";

const RADAR_REFRESH_EVENT_TYPES = new Set([
  "stats_update",
]);
const RADAR_REFRESH_DELAY_MS = 10000;
const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1 };

// Rolls recent alert rows up into a per-IP { count, severity } map so the
// host graph can badge every node currently involved in a monitor hit,
// counting it against both the source and the destination endpoint. Fed by
// /api/alerts/recent, which already filters to monitor hits server-side -
// no packet bodies to scan here.
function buildHostAlerts(rows) {
  const alerts = {};
  const bump = (ip, severity) => {
    const key = String(ip || "").trim();
    if (!key) return;
    const entry = alerts[key] || { count: 0, severity: "low" };
    entry.count += 1;
    if ((SEVERITY_RANK[severity] || 0) > (SEVERITY_RANK[entry.severity] || 0)) {
      entry.severity = severity;
    }
    alerts[key] = entry;
  };
  (Array.isArray(rows) ? rows : []).forEach((row) => {
    const severity = String((row && row.severity) || "").trim().toLowerCase();
    if (!SEVERITY_RANK[severity]) return;
    bump(row.src_ip, severity);
    bump(row.dst_ip, severity);
  });
  return alerts;
}

export default {
  name: "RadarView",
  components: {
    ViewHeader,
    EntityTablePanel,
    HostRadarPanel,
    MapPanel,
  },
  data() {
    return {
      store,
      loading: false,
      error: "",
      lastUpdated: "",
      analytics: {},
      mapSnapshot: {},
      hostAlerts: {},
      wsRefreshTimer: null,
      stopTableRefreshSubscription: null,
      stopMapSnapshotSubscription: null,
      riskPortColumns: [
        { key: "port", label: "Port" },
        { key: "value", label: "Hits" },
      ],
      hostColumns: [
        { key: "ip", label: "IP" },
        { key: "value", label: "Open Ports" },
      ],
    };
  },
  computed: {
    apiBase() {
      return this.store.state.apiBase;
    },
    metricCards() {
      const summary = this.analytics.summary || {};
      const mapSummary = this.mapSnapshot.summary || {};
      return [
        {
          key: "packets",
          label: "Packets",
          value: Number(summary.ports || 0),
          caption: "Traffic rows seen in analytics",
          icon: "mdi-ethernet",
          colorClass: "text-success",
        },
        {
          key: "hosts",
          label: "Hosts",
          value: Number(mapSummary.total_hosts || summary.unique_hosts || 0),
          caption: "Distinct hosts in the map snapshot",
          icon: "mdi-lan-connect",
          colorClass: "text-info",
        },
        {
          key: "open",
          label: "Open Ports",
          value: Number(summary.open_ports || 0),
          caption: "Ports with active responses",
          icon: "mdi-radar",
          colorClass: "text-warning",
        },
        {
          key: "banners",
          label: "Responses",
          value: Number(summary.banners || 0),
          caption: "Decoded payload evidence",
          icon: "mdi-message-text",
          colorClass: "text-primary",
        },
      ];
    },
    riskPorts() {
      return Array.isArray(this.analytics.risk_ports) ? this.analytics.risk_ports.slice(0, 24) : [];
    },
    topHosts() {
      return Array.isArray(this.analytics.top_ips_by_open_ports) ? this.analytics.top_ips_by_open_ports.slice(0, 24) : [];
    },
  },
  watch: {
    apiBase() {
      this.load();
    },
  },
  mounted() {
    this.stopMapSnapshotSubscription = this.store.subscribeMapSnapshot(this.handleRealtimeMapSnapshot);
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
    if (typeof this.stopMapSnapshotSubscription === "function") {
      this.stopMapSnapshotSubscription();
      this.stopMapSnapshotSubscription = null;
    }
  },
  methods: {
    handleRealtimeMapSnapshot(event) {
      const snapshot = event && event.snapshot ? event.snapshot : null;
      if (!snapshot) return;
      this.mapSnapshot = snapshot;
      this.lastUpdated = new Date().toLocaleTimeString();
      if (this.error === "Failed to load map snapshot") {
        this.error = "";
      }
    },
    handleWsRefresh(event) {
      const eventType = String((event && event.type) || "").trim().toLowerCase();
      if (!RADAR_REFRESH_EVENT_TYPES.has(eventType)) return;
      if (this.wsRefreshTimer || this.loading) return;
      this.wsRefreshTimer = setTimeout(() => {
        this.wsRefreshTimer = null;
        Promise.all([
          this.loadAnalytics(),
          this.loadHostAlerts(),
        ]).catch(() => {
          // keep the current radar visible on transient realtime failures
        });
      }, RADAR_REFRESH_DELAY_MS);
    },
    loadAnalytics() {
      return this.store.fetchJsonPromise("/api/charts/analytics").then((payload) => {
        this.analytics = payload || {};
        this.lastUpdated = new Date().toLocaleTimeString();
        if (this.error === "Failed to load analytics") {
          this.error = "";
        }
        return payload;
      });
    },
    loadHostAlerts() {
      // Best-effort: alert badges are a nice-to-have overlay on the host
      // graph, never a reason to block or error out the main radar load.
      // Uses the lean alerts-only feed (src/dst IP + severity) instead of
      // pulling full packet rows just to read their monitor tags.
      return this.store
        .fetchJsonPromise("/api/alerts/recent?limit=500")
        .then((payload) => {
          this.hostAlerts = buildHostAlerts(this.store.extractArray(payload));
        })
        .catch(() => {});
    },
    load() {
      this.loading = true;
      this.error = "";
      return Promise.allSettled([
        this.store.fetchJsonPromise("/api/charts/analytics"),
        this.store.fetchJsonPromise("/api/map/scan?limit=500"),
        this.loadHostAlerts(),
      ])
        .then(([analyticsRes, mapRes]) => {
          if (analyticsRes.status === "fulfilled") {
            this.analytics = analyticsRes.value || {};
          } else {
            this.analytics = {};
            this.error = (analyticsRes.reason && analyticsRes.reason.message) || "Failed to load analytics";
          }
          if (mapRes.status === "fulfilled") {
            this.mapSnapshot = (mapRes.value && mapRes.value.data) || {};
          } else if (!this.error) {
            if (!this.mapSnapshot || !Object.keys(this.mapSnapshot).length) {
              this.mapSnapshot = {};
              this.error = (mapRes.reason && mapRes.reason.message) || "Failed to load map snapshot";
            }
          }
          this.lastUpdated = new Date().toLocaleTimeString();
        })
        .finally(() => {
          this.loading = false;
        });
    },
  },
};
</script>

<style scoped>
.metric-card {
  border-radius: 16px;
}

.metric-icon {
  opacity: 0.92;
}

.timeline-chip-grid {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.host-link {
  color: rgba(108, 186, 228, 0.98);
  text-decoration: none;
}

.host-link:hover {
  text-decoration: underline;
}
</style>
