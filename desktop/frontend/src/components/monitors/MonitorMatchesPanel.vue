<template>
  <div class="monitor-matches pa-4">
    <div class="d-flex flex-wrap align-center ga-2 mb-4">
      <v-chip size="small" variant="tonal" color="primary">
        Matched: {{ stats.total }}
      </v-chip>
      <v-chip size="small" variant="tonal" color="info">
        Unique sources: {{ stats.uniqueSrc }}
      </v-chip>
      <v-chip size="small" variant="tonal" color="secondary">
        Unique targets: {{ stats.uniqueDst }}
      </v-chip>
      <v-chip size="small" variant="outlined">
        Last match: {{ stats.lastSeen || "-" }}
      </v-chip>
      <v-spacer />
      <v-btn
        size="small"
        variant="outlined"
        color="primary"
        prepend-icon="mdi-refresh"
        :loading="loading"
        @click="load()"
      >
        Refresh
      </v-btn>
      <v-btn
        size="small"
        variant="outlined"
        color="secondary"
        prepend-icon="mdi-download"
        :disabled="!rows.length"
        @click="downloadJson"
      >
        Download JSON
      </v-btn>
    </div>

    <v-alert v-if="error" type="error" variant="tonal" density="comfortable" class="mb-3">
      {{ error }}
    </v-alert>

    <v-row v-if="rows.length" dense class="mb-4">
      <v-col v-for="chart in chartPanels" :key="chart.key" cols="12" md="4">
        <v-card variant="tonal" class="pa-4 chart-card">
          <div class="text-caption text-medium-emphasis mb-2">{{ chart.title }}</div>
          <div class="chart-stack">
            <div v-for="item in chart.series" :key="`${chart.key}-${item.label}`" class="chart-row">
              <div class="chart-row__label" :title="item.label">{{ item.label }}</div>
              <div class="chart-row__track" aria-hidden="true">
                <div class="chart-row__fill" :style="{ width: `${item.width}%`, background: chart.fill }" />
              </div>
              <div class="chart-row__value">{{ item.value }}</div>
            </div>
            <div v-if="!chart.series.length" class="text-caption text-medium-emphasis">No data yet</div>
          </div>
        </v-card>
      </v-col>
    </v-row>

    <EntityTablePanel
      title="Matched packets"
      :subtitle="`Traffic that triggered '${monitor.name}'. The Match column shows the specific value that satisfied this monitor. Expand a row for the full packet record.`"
      v-model:live-enabled="liveRefreshEnabled"
      :live-refresh="true"
      :rows="rows"
      :columns="columns"
      :loading="loading"
      :expandable-rows="true"
      :packet-review-enabled="true"
      variant="flat"
      search-enabled
      search-label="Search matched traffic"
      search-placeholder="IP, port, summary, matched value..."
      :search-fields="searchFields"
      :page-size="10"
      empty-text="No traffic has matched this monitor yet"
      @refresh="load"
    >
      <template #cell-matched_value="{ value }">
        <span class="match-value">{{ value || "-" }}</span>
      </template>
      <template #cell-updated_at="{ value }">
        {{ formatTimestamp(value) }}
      </template>
      <template #cell-proto="{ value }">
        <v-chip size="x-small" color="primary" variant="tonal">
          {{ String(value || "unknown").toUpperCase() }}
        </v-chip>
      </template>
      <template #cell-state="{ value }">
        <v-chip size="x-small" :color="statusColor(value)" variant="tonal">
          {{ value || "unknown" }}
        </v-chip>
      </template>
      <template #cell-src_ip="{ item, value }">
        <router-link
          v-if="item.src_ip"
          class="mono ip-link"
          :to="{ path: '/investigate', query: { ip: item.src_ip } }"
        >
          {{ value }}
        </router-link>
        <span v-else class="mono">-</span>
      </template>
      <template #cell-dst_ip="{ item, value }">
        <router-link
          v-if="item.dst_ip"
          class="mono ip-link"
          :to="{ path: '/investigate', query: { ip: item.dst_ip } }"
        >
          {{ value }}
        </router-link>
        <span v-else class="mono">-</span>
      </template>
      <template #cell-size="{ item }">
        <span class="meta-cell">{{ buildPacketSizeSummary(item) }}</span>
      </template>
      <template #cell-summary="{ item }">
        <span class="summary-cell">{{ buildPacketSummary(item, 140) || "-" }}</span>
      </template>
    </EntityTablePanel>
  </div>
</template>

<script>
import store from "../../state/appStore";
import EntityTablePanel from "../ui/EntityTablePanel.vue";
import { buildPacketSizeSummary, buildPacketSummary, formatTimestamp } from "../../utils/traffic";

const REFRESH_EVENT_TYPES = new Set(["packet", "stats_update", "runtime_mode"]);

function buildCountSeries(rows, selector, limit = 6) {
  const counts = new Map();
  rows.forEach((row) => {
    const text = String(selector(row) || "").trim();
    if (!text) return;
    counts.set(text, (counts.get(text) || 0) + 1);
  });
  const ordered = [...counts.entries()]
    .map(([label, value]) => ({ label, value }))
    .sort((left, right) => right.value - left.value || left.label.localeCompare(right.label))
    .slice(0, limit);
  const maxValue = ordered.length ? Math.max(...ordered.map((item) => item.value)) : 0;
  return ordered.map((item) => ({
    ...item,
    width: maxValue > 0 ? Math.max(10, Math.round((item.value / maxValue) * 100)) : 0,
  }));
}

function buildTimelineSeries(rows) {
  const buckets = new Map();
  rows.forEach((row) => {
    const created = String(row.updated_at || row.created_at || "").trim();
    if (!created) return;
    const key = created.slice(0, 13);
    if (!key) return;
    buckets.set(key, (buckets.get(key) || 0) + 1);
  });
  const ordered = [...buckets.entries()]
    .sort((left, right) => left[0].localeCompare(right[0]))
    .slice(-8)
    .map(([label, value]) => ({ label: label.slice(11), value }));
  const maxValue = ordered.length ? Math.max(...ordered.map((item) => item.value)) : 0;
  return ordered.map((item) => ({
    ...item,
    width: maxValue > 0 ? Math.max(10, Math.round((item.value / maxValue) * 100)) : 0,
  }));
}

export default {
  name: "MonitorMatchesPanel",
  components: { EntityTablePanel },
  props: {
    monitor: {
      type: Object,
      required: true,
    },
    // Set to false to render a static snapshot with no WS-driven polling at
    // all (see mounted() below) - used by InvestigateView, which is meant
    // to show exactly what was selected and nothing that shifts under the
    // reader while they're looking at it.
    liveRefresh: {
      type: Boolean,
      default: true,
    },
  },
  data() {
    return {
      rows: [],
      loading: false,
      error: "",
      columns: [
        { key: "matched_value", label: "Match" },
        { key: "updated_at", label: "Seen" },
        { key: "proto", label: "Proto" },
        { key: "state", label: "State" },
        { key: "src_ip", label: "Src IP" },
        { key: "src_port", label: "Src Port" },
        { key: "dst_ip", label: "Dst IP" },
        { key: "dst_port", label: "Dst Port" },
        { key: "size", label: "Size" },
        { key: "summary", label: "Summary" },
      ],
      liveRefreshEnabled: true,
      wsRefreshTimer: null,
      stopTableRefreshSubscription: null,
    };
  },
  computed: {
    searchFields() {
      return [
        "matched_value",
        "updated_at",
        "proto",
        "state",
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "length",
        "payload_len",
        "summary",
        "banner_text",
        "payload_text",
      ];
    },
    stats() {
      const srcIps = new Set(this.rows.map((row) => String(row.src_ip || "").trim()).filter(Boolean));
      const dstIps = new Set(this.rows.map((row) => String(row.dst_ip || "").trim()).filter(Boolean));
      const lastRow = this.rows[0];
      return {
        total: this.rows.length,
        uniqueSrc: srcIps.size,
        uniqueDst: dstIps.size,
        lastSeen: lastRow ? formatTimestamp(lastRow.updated_at) : "",
      };
    },
    chartPanels() {
      return [
        {
          key: "matches",
          title: "Top matched values",
          fill: "linear-gradient(90deg, rgba(52, 230, 255, 0.94), rgba(74, 136, 255, 0.85))",
          series: buildCountSeries(this.rows, (row) => row.matched_value),
        },
        {
          key: "proto",
          title: "By protocol",
          fill: "linear-gradient(90deg, rgba(255, 159, 67, 0.92), rgba(243, 177, 75, 0.78))",
          series: buildCountSeries(this.rows, (row) => String(row.proto || "").toUpperCase()),
        },
        {
          key: "timeline",
          title: "Recent activity (by hour)",
          fill: "linear-gradient(90deg, rgba(158, 130, 255, 0.92), rgba(120, 96, 230, 0.78))",
          series: buildTimelineSeries(this.rows),
        },
      ];
    },
  },
  mounted() {
    this.load();
    if (this.liveRefresh) {
      this.stopTableRefreshSubscription = store.subscribeTableRefresh(this.handleWsRefresh);
    } else {
      this.liveRefreshEnabled = false;
    }
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
    buildPacketSummary,
    buildPacketSizeSummary,
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
    statusColor(value) {
      const state = String(value || "").trim().toLowerCase();
      if (state === "open" || state === "active") return "success";
      if (state === "filtered" || state === "blocked") return "warning";
      if (state === "closed") return "error";
      return "secondary";
    },
    downloadJson() {
      if (!this.rows.length) return;
      const payload = {
        monitor_id: this.monitor.id,
        monitor_name: this.monitor.name,
        exported_at: new Date().toISOString(),
        count: this.rows.length,
        packets: this.rows,
      };
      const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const safeId = String(this.monitor.id || "monitor").replace(/[^a-z0-9_-]+/gi, "-");
      const link = document.createElement("a");
      link.href = url;
      link.download = `sniff4hound-${safeId}-${Date.now()}.json`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
    },
    load(options = {}) {
      if (!options.silent) this.loading = true;
      this.error = "";
      return store
        .listMonitorPackets(this.monitor.id, { limit: 200 })
        .then((payload) => {
          this.rows = store.extractArray(payload);
        })
        .catch((err) => {
          this.rows = [];
          this.error = (err && err.message) || "Failed to load matched traffic";
        })
        .finally(() => {
          this.loading = false;
        });
    },
  },
};
</script>

<style scoped>
.monitor-matches {
  background: rgba(6, 12, 22, 0.4);
}

.ip-link {
  color: rgba(108, 186, 228, 0.98);
  text-decoration: none;
}

.ip-link:hover {
  text-decoration: underline;
}

.mono {
  font-family: var(--font-mono);
}

.match-value {
  display: inline-block;
  max-width: 220px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-family: var(--font-mono);
  font-weight: 700;
  color: rgba(120, 224, 255, 0.96);
}

.meta-cell{
  /* Fixed width, not max-width: with `overflow-wrap: anywhere` a
     cell's min-content width is a single character, so the table's
     auto layout was free to collapse the column to ~1ch and wrap the
     banner one letter per line, blowing the row up to hundreds of
     pixels tall. A definite width pins the column; the clamp keeps
     every row the same height and the full text stays in the title
     attribute. */
  width: 140px;
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
  max-width: 360px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.chart-card {
  border-radius: 14px;
  height: 100%;
}

.chart-stack {
  display: grid;
  gap: 8px;
}

.chart-row {
  display: grid;
  grid-template-columns: minmax(74px, 1.1fr) minmax(0, 2.8fr) auto;
  align-items: center;
  gap: 8px;
}

.chart-row__label {
  overflow: hidden;
  white-space: nowrap;
  text-overflow: ellipsis;
  color: rgba(205, 221, 236, 0.86);
  font-size: 0.82rem;
}

.chart-row__track {
  position: relative;
  height: 8px;
  overflow: hidden;
  border-radius: 999px;
  background: rgba(9, 16, 24, 0.86);
  box-shadow: inset 0 0 0 1px rgba(103, 176, 219, 0.08);
}

.chart-row__fill {
  height: 100%;
  border-radius: inherit;
}

.chart-row__value {
  min-width: 3ch;
  text-align: right;
  color: rgba(229, 241, 252, 0.92);
  font-family: var(--font-mono);
  font-size: 0.78rem;
}
</style>
