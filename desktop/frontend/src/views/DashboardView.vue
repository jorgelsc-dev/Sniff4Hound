<template>
  <div>
    <ViewHeader
      overline="Operations"
      title="Resumen"
      description="Live telemetry metrics."
      :refresh-loading="loading"
      :show-time-range="true"
      @refresh="load"
    >
      <template #actions-prepend>
        <v-btn size="small" variant="text" prepend-icon="mdi-view-dashboard-outline" to="/">
          Dashboards
        </v-btn>
        <ClearDataButton @cleared="load" />
      </template>
    </ViewHeader>

    <v-row density="compact" class="metric-row mb-4">
      <v-col v-for="metric in metricCards" :key="metric.key" cols="6" sm="4" lg="2">
        <v-card variant="tonal" class="pa-2 metric-card">
          <div class="d-flex align-center justify-space-between ga-2">
            <div>
              <div class="text-caption metric-label text-medium-emphasis">{{ metric.label }}</div>
              <div class="text-subtitle-1 font-weight-bold metric-value" :class="metric.colorClass">{{ metric.value }}</div>
            </div>
            <v-icon :icon="metric.icon" class="metric-icon" size="18" :class="metric.colorClass" />
          </div>
          <div class="text-caption text-medium-emphasis metric-caption">{{ metric.caption }}</div>
        </v-card>
      </v-col>
    </v-row>
    <v-alert v-if="error" type="error" variant="tonal" class="my-3">
      {{ error }}
    </v-alert>


  </div>
</template>

<script>
import store from "../state/appStore";
import ViewHeader from "../components/ui/ViewHeader.vue";
import ClearDataButton from "../components/ui/ClearDataButton.vue";
import {
  buildPacketSizeSummary,
  buildPacketSummary,
  formatTimestamp,
  isHoneypotInterface,
} from "../utils/traffic";

const REFRESH_EVENT_TYPES = new Set(["packet", "stats_update", "runtime_mode"]);

export default {
  name: "DashboardView",
  components: {
    ViewHeader,
    ClearDataButton,
  },
  data() {
    return {
      store,
      loading: false,
      error: "",
      lastUpdated: "",
      liveRefreshEnabled: true,
      engineBusy: { sniffer: false, honeypot: false },
      engineDesired: { sniffer: null, honeypot: null },
      engineError: "",
      dashboard: {},
      analytics: {},
      packets: [],
      packetLimit: 12,
      packetsMeta: { totalAvailable: null, returned: null, truncated: null },
      packetColumns: [
        { key: "updated_at", label: "Seen" },
        { key: "interface", label: "Interface" },
        { key: "proto", label: "Proto" },
        { key: "state", label: "State" },
        { key: "src_ip", label: "Src IP" },
        { key: "src_port", label: "Src Port" },
        { key: "dst_ip", label: "Dst IP" },
        { key: "dst_port", label: "Dst Port" },
        { key: "size", label: "Size" },
        { key: "summary", label: "Summary" },
      ],
      packetSearchFields: [
        "updated_at",
        "interface",
        "proto",
        "state",
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "length",
        "payload_len",
        "summary",
        "payload_text",
        "banner_text",
        "flow_key",
        "tcp_flags",
        "icmp_type",
        "icmp_code",
      ],
      packetFilterDefinitions: [
        {
          key: "proto",
          label: "Proto",
          field: "proto",
          optionLabel: (value) => String(value || "").toUpperCase(),
        },
        {
          key: "interface",
          label: "Interface",
          field: "interface",
        },
        {
          key: "state",
          label: "State",
          field: "state",
        },
      ],
      wsRefreshTimer: null,
      stopTableRefreshSubscription: null,
    };
  },
  computed: {
    apiBase() {
      return this.store.state.apiBase;
    },
    counts() {
      return this.dashboard && this.dashboard.counts ? this.dashboard.counts : {};
    },
    runtime() {
      const dashboardRuntime = this.dashboard && this.dashboard.runtime && typeof this.dashboard.runtime === "object"
        ? this.dashboard.runtime
        : {};
      const liveRuntime = this.store.state.runtime && typeof this.store.state.runtime === "object"
        ? this.store.state.runtime
        : {};
      return {
        ...dashboardRuntime,
        ...liveRuntime,
        sniffer: {
          ...(dashboardRuntime.sniffer && typeof dashboardRuntime.sniffer === "object" ? dashboardRuntime.sniffer : {}),
          ...(liveRuntime.sniffer && typeof liveRuntime.sniffer === "object" ? liveRuntime.sniffer : {}),
        },
        honeypot: {
          ...(dashboardRuntime.honeypot && typeof dashboardRuntime.honeypot === "object" ? dashboardRuntime.honeypot : {}),
          ...(liveRuntime.honeypot && typeof liveRuntime.honeypot === "object" ? liveRuntime.honeypot : {}),
        },
      };
    },
    snifferRuntime() {
      return this.runtime.sniffer && typeof this.runtime.sniffer === "object" ? this.runtime.sniffer : {};
    },
    honeypotRuntime() {
      return this.runtime.honeypot && typeof this.runtime.honeypot === "object" ? this.runtime.honeypot : {};
    },
    metricCards() {
      const analyticsSummary = this.analytics.summary || {};
      return [
        {
          key: "tags",
          label: "Tags",
          value: Number(this.counts.count_tags || 0),
          caption: "Rule hits and parsed metadata",
          icon: "mdi-tag-multiple",
          colorClass: "text-primary",
        },
        {
          key: "packets",
          label: "Packets",
          value: Number(this.counts.count_ports || 0),
          caption: "Frames written into packet telemetry",
          icon: "mdi-ethernet",
          colorClass: "text-success",
        },
        {
          key: "responses",
          label: "Responses",
          value: Number(this.counts.count_banners || 0),
          caption: "Decoded payload and banner artifacts",
          icon: "mdi-server-network",
          colorClass: "text-info",
        },
        {
          key: "hosts",
          label: "Unique Hosts",
          value: Number(analyticsSummary.unique_hosts || 0),
          caption: "Distinct IPs seen across the capture set",
          icon: "mdi-lan-connect",
          colorClass: "text-warning",
        },
        {
          key: "protocols",
          label: "Protocols",
          value: this.protocolCount,
          caption: "Observed protocol families",
          icon: "mdi-source-branch",
          colorClass: "text-secondary",
        },
        {
          key: "honeypot",
          label: "Honeypot Hits",
          value: this.honeypotPacketsSeen,
          caption: "Inbound events recorded by honeypot listeners",
          icon: "mdi-server-security",
          colorClass: "text-warning",
        },
      ];
    },
    protocolSeries() {
      // Capped for the chart, which only has room to plot a top-N - the
      // "Protocols" stat card must not read off this truncated series (that
      // pinned the counter at <=8 regardless of how many protocols were
      // actually observed, finding 1.12). See protocolCount below for the
      // real total.
      return Array.isArray(this.analytics.ports_by_proto)
        ? this.analytics.ports_by_proto.slice(0, 8)
        : [];
    },
    protocolCount() {
      return Array.isArray(this.analytics.ports_by_proto) ? this.analytics.ports_by_proto.length : 0;
    },
    wsClientCount() {
      const clients = this.dashboard && Array.isArray(this.dashboard.ws_clients) ? this.dashboard.ws_clients : [];
      return clients.length;
    },
    recentPackets() {
      return Array.isArray(this.packets) ? this.packets : [];
    },
    timeRangeLabel() {
      return this.store.timeRangeLabel();
    },
    snifferRunning() {
      return this.engineDesired.sniffer === null
        ? Boolean(this.snifferRuntime.running)
        : Boolean(this.engineDesired.sniffer);
    },
    honeypotRunning() {
      return this.engineDesired.honeypot === null
        ? Boolean(this.honeypotRuntime.running)
        : Boolean(this.engineDesired.honeypot);
    },
    // Both engines writing at once is supported, but it is worth saying out
    // loud: raw capture sees the honeypot's own traffic too, so those
    // connections land in the store twice under different interfaces.
    bothEnginesRunning() {
      return this.snifferRunning && this.honeypotRunning;
    },
    snifferBlocked() {
      return String(this.snifferRuntime.capture_state || "").trim().toLowerCase() === "blocked";
    },
    snifferStatusLabel() {
      if (this.engineDesired.sniffer === true) return "Starting";
      if (this.engineDesired.sniffer === false) return "Stopping";
      if (this.snifferBlocked) return "Blocked";
      if (this.snifferRuntime.running) return "Running";
      return "Stopped";
    },
    snifferChipColor() {
      if (this.snifferBlocked) return "error";
      if (this.snifferRuntime.running) return "success";
      return "secondary";
    },
    snifferStatusIcon() {
      if (this.engineDesired.sniffer !== null) return "mdi-progress-clock";
      if (this.snifferBlocked) return "mdi-alert-circle-outline";
      if (this.snifferRuntime.running) return "mdi-play-circle-outline";
      return "mdi-stop-circle-outline";
    },
    snifferPacketsSeen() {
      return Number(this.snifferRuntime.packets_seen || 0);
    },
    snifferUnparseable() {
      // Only shown once it is non-zero: a rising count is the visible sign
      // of malformed/fuzzed frames aimed at the parser itself.
      return Number(this.snifferRuntime.packets_unparseable || 0);
    },
    snifferInterfacesLabel() {
      const active = Array.isArray(this.snifferRuntime.interfaces) ? this.snifferRuntime.interfaces : [];
      const selected = Array.isArray(this.snifferRuntime.selected_interfaces)
        ? this.snifferRuntime.selected_interfaces
        : [];
      if (active.length === 1) return active[0];
      if (active.length > 1) return `${active.length} active`;
      if (selected.length === 1) return selected[0];
      if (selected.length > 1) return `${selected.length} selected`;
      return "all visible";
    },
    snifferSummary() {
      if (this.snifferBlocked) return this.snifferErrorSummary;
      if (this.snifferRuntime.running) return "Passive capture is running.";
      return `Stopped. Ready on ${this.snifferInterfacesLabel}.`;
    },
    snifferErrorSummary() {
      const entries = this.snifferRuntime.errors && typeof this.snifferRuntime.errors === "object"
        ? Object.entries(this.snifferRuntime.errors)
        : [];
      if (!entries.length) return "Packet capture is blocked on the selected interfaces.";
      return entries
        .slice(0, 2)
        .map(([name, message]) => `${name}: ${message}`)
        .join(" | ");
    },
    honeypotPacketsSeen() {
      return Number(this.honeypotRuntime.packets_seen || 0);
    },
    honeypotStatusLabel() {
      if (this.engineDesired.honeypot === true) return "Starting";
      if (this.engineDesired.honeypot === false) return "Stopping";
      if (this.honeypotRuntime.running) return "Running";
      return "Stopped";
    },
    honeypotChipColor() {
      return this.honeypotRuntime.running ? "warning" : "secondary";
    },
    honeypotStatusIcon() {
      if (this.engineDesired.honeypot !== null) return "mdi-progress-clock";
      return this.honeypotRuntime.running ? "mdi-play-circle-outline" : "mdi-stop-circle-outline";
    },
    honeypotListenersLabel() {
      const listenerCount = Number(this.honeypotRuntime.listener_count);
      if (Number.isFinite(listenerCount) && listenerCount > 0) {
        if (listenerCount === 1) return "1 listener";
        return `${listenerCount} listeners`;
      }
      const listeners = Array.isArray(this.honeypotRuntime.listeners) ? this.honeypotRuntime.listeners : [];
      if (listeners.length === 1) return "1 listener";
      return `${listeners.length} listeners`;
    },
    honeypotSummary() {
      if (this.honeypotRuntime.running) return "Honeypot is accepting inbound traffic.";
      return "Stopped until you start the honeypot.";
    },
  },
  watch: {
    apiBase() {
      this.load();
    },
    liveRefreshEnabled(value) {
      if (!value && this.wsRefreshTimer) {
        clearTimeout(this.wsRefreshTimer);
        this.wsRefreshTimer = null;
      }
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
    toggleEngine(engine, shouldRun) {
      if (this.engineBusy[engine]) return;
      this.engineBusy[engine] = true;
      this.engineDesired[engine] = Boolean(shouldRun);
      this.engineError = "";
      this.store
        .controlEngine(engine, shouldRun ? "start" : "stop")
        .then(() => {
          this.engineDesired[engine] = null;
        })
        .catch((err) => {
          this.engineDesired[engine] = null;
          this.engineError = (err && err.message) || `Failed to ${shouldRun ? "start" : "stop"} the ${engine}`;
        })
        .finally(() => {
          this.engineBusy[engine] = false;
          this.load({ silent: true }).catch(() => null);
        });
    },
    buildPacketSizeSummary,
    buildPacketSummary,
    formatTimestamp,
    normalizeStatus(value) {
      const raw = String(value || "active").trim().toLowerCase();
      if (raw === "open" || raw === "active") return raw;
      if (raw === "filtered" || raw === "blocked") return raw;
      if (raw === "closed") return raw;
      if (raw === "restarting") return "restarting";
      if (raw === "stopped") return "stopped";
      return "active";
    },
    statusColor(value) {
      const status = this.normalizeStatus(value);
      if (status === "open" || status === "active") return "success";
      if (status === "restarting") return "info";
      if (status === "filtered" || status === "blocked" || status === "stopped") return "warning";
      if (status === "closed") return "error";
      return "warning";
    },
    interfaceChipColor(value) {
      return isHoneypotInterface(value) ? "warning" : "info";
    },
    handleWsRefresh(event) {
      if (!this.liveRefreshEnabled) return;
      const eventType = String((event && event.type) || "").trim().toLowerCase();
      if (!REFRESH_EVENT_TYPES.has(eventType)) return;
      if (this.wsRefreshTimer) return;
      this.wsRefreshTimer = setTimeout(() => {
        this.wsRefreshTimer = null;
        this.load({ silent: true }).catch(() => {
          // preserve current dashboard on transient realtime failures
        });
      }, 10000);
    },
    loadMorePackets() {
      this.packetLimit = Math.min(this.packetLimit + 100, 5000);
      this.load({ silent: true }).catch(() => null);
    },
    dashboardQuery() {
      const params = new URLSearchParams({ compact: "1" });
      const range = String(this.store.state.timeRange || "").trim();
      if (range) params.set("since", range);
      return `?${params.toString()}`;
    },
    load(options = {}) {
      if (!options.silent) this.loading = true;
      this.error = "";
      const dashboardQuery = this.dashboardQuery();
      return Promise.allSettled([
        this.store.fetchJsonPromise(`/api/dashboard/${dashboardQuery}`),
        this.store.fetchJsonPromise(`/api/charts/analytics${dashboardQuery}`),
        this.store.fetchListPromise("/ports/", { limit: this.packetLimit }),
      ])
        .then(([dashboardRes, analyticsRes, packetsRes]) => {
          const errors = [];
          if (dashboardRes.status === "fulfilled") {
            this.dashboard = dashboardRes.value || {};
          } else {
            this.dashboard = {};
            errors.push((dashboardRes.reason && dashboardRes.reason.message) || "Failed to load dashboard snapshot");
          }
          if (analyticsRes.status === "fulfilled") {
            this.analytics = analyticsRes.value || {};
          } else {
            this.analytics = {};
            errors.push((analyticsRes.reason && analyticsRes.reason.message) || "Failed to load analytics");
          }
          if (packetsRes.status === "fulfilled") {
            this.packets = packetsRes.value.rows;
            this.packetsMeta = packetsRes.value.meta;
          } else {
            this.packets = [];
            this.packetsMeta = { totalAvailable: null, returned: null, truncated: null };
            errors.push((packetsRes.reason && packetsRes.reason.message) || "Failed to load packets");
          }
          this.lastUpdated = new Date().toLocaleTimeString();
          this.error = errors.join(" | ");
        })
        .finally(() => {
          this.loading = false;
        });
    },
  },
};
</script>

<style scoped>
.metric-row {
  margin-top: -2px;
}

.metric-card {
  min-height: 68px;
  border-radius: 8px;
}

.metric-label {
  font-size: 0.72rem;
  line-height: 1.2;
}

.metric-value {
  line-height: 1.25;
}

.metric-icon {
  opacity: 0.92;
}

.metric-caption {
  margin-top: 2px;
  font-size: 0.72rem;
  line-height: 1.25;
  display: -webkit-box;
  -webkit-box-orient: vertical;
  -webkit-line-clamp: 2;
  line-clamp: 2;
  overflow: hidden;
  line-height: 1.25;
}

.flow-cell {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.flow-cell__arrow {
  color: rgba(121, 213, 248, 0.9);
}

.mono {
  font-family: var(--font-mono);
}

.meta-cell{
  /* Fixed width, not max-width: with `overflow-wrap: anywhere` a
     cell's min-content width is a single character, so the table's
     auto layout was free to collapse the column to ~1ch and wrap the
     banner one letter per line, blowing the row up to hundreds of
     pixels tall. A definite width pins the column; the clamp keeps
     every row the same height and the full text stays in the title
     attribute. */
  width: 160px;
  display: -webkit-box;
  -webkit-box-orient: vertical;
  -webkit-line-clamp: 2;
  line-clamp: 2;
  overflow: hidden;
  overflow-wrap: anywhere;
  vertical-align: top;
}

.summary-cell {
  display: inline-block;
  max-width: 420px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

</style>
