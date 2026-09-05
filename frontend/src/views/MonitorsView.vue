<template>
  <div>
    <ViewHeader
      overline="Detection"
      title="Monitors"
      description="Only traffic that matches an enabled monitor gets written to disk. Everything else is parsed, counted live, and discarded."
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

    <div class="d-flex justify-end mt-6 mb-3 ga-2">
      <v-btn
        size="small"
        variant="text"
        color="error"
        icon
        :disabled="!monitorsWithTraffic.length"
        @click="clearDialog = true"
        aria-label="Clear alerts"
      >
        <v-icon icon="mdi-delete-sweep-outline" />
        <v-tooltip activator="parent" location="bottom">Clear alerts</v-tooltip>
      </v-btn>
      <v-btn
        size="small"
        variant="text"
        color="primary"
        icon
        to="/settings?section=detection"
        aria-label="Manage monitors &amp; persistence filter"
      >
        <v-icon icon="mdi-cog-outline" />
        <v-tooltip activator="parent" location="bottom">Manage monitors &amp; persistence filter</v-tooltip>
      </v-btn>
    </div>

    <v-dialog v-model="clearDialog" max-width="420">
      <v-card class="pa-4">
        <div class="text-h6 mb-3">Clear alerts?</div>
        <div class="text-caption text-medium-emphasis mb-3">
          Deletes every stored packet/tag matched by a monitor (sniffer-side traffic only - inbound
          service hits are cleared separately from the Services view). Monitor definitions and their
          enabled/disabled state are untouched. This can't be undone.
        </div>
        <v-alert v-if="clearError" type="error" variant="tonal" density="comfortable" class="mb-3">
          {{ clearError }}
        </v-alert>
        <div class="d-flex justify-end ga-2">
          <v-btn variant="text" @click="clearDialog = false">Cancel</v-btn>
          <v-btn color="error" variant="flat" :loading="clearing" @click="confirmClear">Clear alerts</v-btn>
        </div>
      </v-card>
    </v-dialog>

    <div class="d-flex align-center justify-space-between flex-wrap ga-2 mt-2 mb-3">
      <div>
        <div class="text-h6">Monitor Traffic</div>
        <div class="text-caption text-medium-emphasis">
          One table per monitor with matched traffic, generated automatically — a monitor appears here
          as soon as it has at least one match. Expand any monitor to filter/search its matched
          packets and see its stats and charts.
        </div>
      </div>
    </div>

    <v-expansion-panels
      v-if="monitorsWithTraffic.length"
      v-model="expandedMonitorPanel"
      variant="accordion"
      class="monitor-traffic-panels mb-6"
    >
      <v-expansion-panel
        v-for="monitor in monitorsWithTraffic"
        :id="`monitor-row-${monitor.id}`"
        :key="monitor.id"
        :value="monitor.id"
      >
        <v-expansion-panel-title>
          <div class="d-flex align-center flex-wrap ga-2">
            <v-chip
              size="x-small"
              color="info"
              variant="tonal"
              prepend-icon="mdi-table-row"
              class="match-count-chip"
            >
              {{ monitor.match_count.toLocaleString() }}
            </v-chip>
            <router-link
              class="font-weight-medium monitor-name-link"
              :to="{ path: '/investigate', query: { monitor: monitor.id } }"
              @click.stop
            >
              {{ monitor.name }}
            </router-link>
            <v-chip size="x-small" :color="modeColor(monitor.mode)" variant="tonal">
              {{ modeLabel(monitor.mode) }}
            </v-chip>
            <v-chip size="x-small" :color="severityColor(monitor.action && monitor.action.severity)" variant="tonal">
              {{ (monitor.action && monitor.action.severity) || "info" }}
            </v-chip>
            <v-chip size="x-small" :color="monitor.source === 'builtin' ? 'secondary' : 'success'" variant="tonal">
              {{ monitor.source === "builtin" ? "Built-in" : "Custom" }}
            </v-chip>
            <v-chip size="x-small" :color="monitor.enabled ? 'success' : 'secondary'" variant="outlined">
              {{ monitor.enabled ? "Enabled" : "Disabled" }}
            </v-chip>
            <v-btn
              size="x-small"
              variant="text"
              color="info"
              icon="mdi-magnify"
              :to="{ path: '/investigate', query: { monitor: monitor.id } }"
              aria-label="Investigate this monitor"
              @click.stop
            />
            <v-btn
              size="x-small"
              variant="text"
              color="secondary"
              icon="mdi-file-document-outline"
              aria-label="View rule"
              @click.stop="openRuleDetail(monitor)"
            >
              <v-icon icon="mdi-file-document-outline" />
              <v-tooltip activator="parent" location="bottom">View rule</v-tooltip>
            </v-btn>
          </div>
        </v-expansion-panel-title>
        <v-expansion-panel-text>
          <MonitorMatchesPanel :monitor="monitor" />
        </v-expansion-panel-text>
      </v-expansion-panel>
    </v-expansion-panels>

    <v-alert v-else type="info" variant="tonal" density="comfortable" class="mb-6">
      No monitor has matched any traffic yet. Monitors show up here automatically as soon as they
      have at least one match.
    </v-alert>

    <RuleDetailDialog v-model="ruleDetailOpen" :monitor="ruleDetailMonitor" />

    <div class="d-flex flex-wrap ga-2 mb-6">
      <v-btn size="small" variant="tonal" color="info" prepend-icon="mdi-web" to="/domains">
        Domains catalog
      </v-btn>
      <v-btn size="small" variant="tonal" color="info" icon to="/paths"
        aria-label="Paths catalog"
      >
        <v-icon icon="mdi-routes" />
        <v-tooltip activator="parent" location="bottom">Paths catalog</v-tooltip>
      </v-btn>
      <v-btn size="small" variant="tonal" color="info" icon to="/ips"
        aria-label="IPs catalog"
      >
        <v-icon icon="mdi-ip-network" />
        <v-tooltip activator="parent" location="bottom">IPs catalog</v-tooltip>
      </v-btn>
    </div>
  </div>
</template>

<script>
import store from "../state/appStore";
import ViewHeader from "../components/ui/ViewHeader.vue";
import MonitorMatchesPanel from "../components/monitors/MonitorMatchesPanel.vue";
import RuleDetailDialog from "../components/monitors/RuleDetailDialog.vue";

const REFRESH_EVENT_TYPES = new Set(["packet", "stats_update", "runtime_mode"]);

export default {
  name: "MonitorsView",
  components: {
    ViewHeader,
    MonitorMatchesPanel,
    RuleDetailDialog,
  },
  data() {
    return {
      store,
      loading: false,
      error: "",
      lastUpdated: "",
      monitors: [],
      liveRefreshEnabled: true,
      wsRefreshTimer: null,
      stopTableRefreshSubscription: null,
      expandedMonitorPanel: null,
      clearDialog: false,
      clearing: false,
      clearError: "",
      ruleDetailOpen: false,
      ruleDetailMonitor: null,
    };
  },
  computed: {
    monitorsWithTraffic() {
      return this.monitors.filter((item) => Number(item.match_count) > 0);
    },
    metricCards() {
      const monitors = this.monitors;
      const enabled = monitors.filter((item) => item.enabled).length;
      const builtin = monitors.filter((item) => item.source === "builtin").length;
      const custom = monitors.length - builtin;
      return [
        {
          key: "total",
          label: "Monitors",
          value: monitors.length,
          caption: "Total detection definitions",
          icon: "mdi-target-account",
          colorClass: "text-primary",
        },
        {
          key: "enabled",
          label: "Enabled",
          value: enabled,
          caption: "Actively gating persistence",
          icon: "mdi-shield-check-outline",
          colorClass: "text-success",
        },
        {
          key: "builtin",
          label: "Built-in",
          value: builtin,
          caption: "Curated defaults, toggle only",
          icon: "mdi-shield-star-outline",
          colorClass: "text-info",
        },
        {
          key: "custom",
          label: "Custom",
          value: custom,
          caption: "Your rule and regex monitors",
          icon: "mdi-shield-edit-outline",
          colorClass: "text-warning",
        },
      ];
    },
  },
  mounted() {
    this.load().then(() => this.focusMonitorFromQuery());
    this.stopTableRefreshSubscription = this.store.subscribeTableRefresh(this.handleWsRefresh);
  },
  watch: {
    // Clicking a notification while already on /monitors changes the query
    // string without remounting this view, so mounted() alone won't catch it.
    "$route.query.monitor"(next) {
      if (next) this.focusMonitorFromQuery();
    },
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
    severityColor(value) {
      const severity = String(value || "info").trim().toLowerCase();
      if (severity === "critical") return "error";
      if (severity === "high") return "error";
      if (severity === "medium") return "warning";
      if (severity === "low") return "info";
      return "secondary";
    },
    modeLabel(value) {
      const mode = String(value || "").trim().toLowerCase();
      if (mode === "regex") return "Regex";
      if (mode === "stateful") return "Stateful";
      return "Rule";
    },
    modeColor(value) {
      const mode = String(value || "").trim().toLowerCase();
      if (mode === "regex") return "info";
      if (mode === "stateful") return "warning";
      return "primary";
    },
    openRuleDetail(monitor) {
      this.ruleDetailMonitor = monitor;
      this.ruleDetailOpen = true;
    },
    focusMonitorFromQuery() {
      const target = String((this.$route.query && this.$route.query.monitor) || "").trim();
      if (!target) return;
      const monitor = this.monitors.find((item) => item.id === target || item.name === target);
      if (!monitor) return;
      this.expandedMonitorPanel = monitor.id;
      this.$nextTick(() => {
        const el = document.getElementById(`monitor-row-${monitor.id}`);
        if (el && typeof el.scrollIntoView === "function") {
          el.scrollIntoView({ behavior: "smooth", block: "center" });
        }
      });
    },
    confirmClear() {
      this.clearing = true;
      this.clearError = "";
      this.store
        .clearDetections("monitors")
        .then(() => {
          this.clearDialog = false;
          this.expandedMonitorPanel = null;
          return this.load();
        })
        .catch((err) => {
          this.clearError = (err && err.message) || "Failed to clear alerts";
        })
        .finally(() => {
          this.clearing = false;
        });
    },
    load(options = {}) {
      if (!options.silent) this.loading = true;
      this.error = "";
      return this.store
        .listMonitors()
        .then((payload) => {
          this.monitors = this.store.extractArray(payload);
          this.lastUpdated = new Date().toLocaleTimeString();
        })
        .catch((err) => {
          this.monitors = [];
          this.error = (err && err.message) || "Failed to load monitors";
        })
        .finally(() => {
          this.loading = false;
        });
    },
  },
};
</script>

<style scoped>
.match-count-chip {
  font-variant-numeric: tabular-nums;
  font-weight: 700;
}

.monitor-name-link {
  color: rgba(229, 241, 252, 0.94);
  text-decoration: none;
}

.monitor-name-link:hover {
  color: rgba(108, 186, 228, 0.98);
  text-decoration: underline;
}

.metric-card {
  border-radius: 16px;
}

.metric-icon {
  opacity: 0.92;
}

.monitor-traffic-panels {
  border-radius: 16px;
  overflow: hidden;
}
</style>
