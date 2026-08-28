<template>
  <div>
    <ViewHeader
      overline="Active Defense"
      title="Honeypot"
      description="Inspect inbound traffic that reached honeypot listeners and review the responses emitted by those decoy services."
      :refresh-loading="loading"
      :show-time-range="true"
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

    <div class="d-flex justify-end mt-2 mb-2 ga-2">
      <v-btn
        size="small"
        variant="text"
        color="error"
        icon
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
        to="/settings?section=honeypot"
        aria-label="Manage listeners"
      >
        <v-icon icon="mdi-cog-outline" />
        <v-tooltip activator="parent" location="bottom">Manage listeners</v-tooltip>
      </v-btn>
    </div>

    <v-dialog v-model="clearDialog" max-width="420">
      <v-card class="pa-4">
        <div class="text-h6 mb-3">Clear alerts?</div>
        <div class="text-caption text-medium-emphasis mb-3">
          Deletes every stored honeypot hit (inbound traffic, responses, and the TLS/DNS event
          detail behind them). Listener definitions and their enabled/disabled state are untouched.
          This can't be undone.
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

    <MonitorMatchesPanel :monitor="honeypotHitsMonitor" class="mt-4 mb-2" />

    <v-row dense class="mt-4">
      <v-col cols="12" md="5">
        <v-text-field
          v-model.trim="filters.query"
          label="Search honeypot traffic"
          name="honeypot_search"
          placeholder="IP, port, response, summary..."
          prepend-inner-icon="mdi-magnify"
          clearable
          variant="outlined"
          density="comfortable"
        />
      </v-col>
      <v-col cols="12" sm="6" md="3">
        <v-select
          v-model="filters.proto"
          :items="protocolOptions"
          label="Protocol"
          item-title="label"
          item-value="value"
          clearable
          variant="outlined"
          density="comfortable"
        />
      </v-col>
      <v-col cols="12" sm="6" md="4">
        <v-select
          v-model="filters.service"
          :items="serviceOptions"
          label="Service"
          item-title="label"
          item-value="value"
          clearable
          variant="outlined"
          density="comfortable"
        />
      </v-col>
    </v-row>

    <div class="d-flex flex-wrap ga-2 mt-2">
      <v-chip size="small" color="warning" variant="tonal" prepend-icon="mdi-access-point-check">
        Listeners: {{ listenerCount }}
      </v-chip>
      <v-chip size="small" variant="outlined" prepend-icon="mdi-table-eye">
        Traffic rows: {{ filteredPackets.length }}
      </v-chip>
      <v-chip size="small" variant="outlined" prepend-icon="mdi-content-save-check-outline">
        Response rows: {{ filteredBanners.length }}
      </v-chip>
    </div>

    <v-row class="mt-4" dense>
      <v-col cols="12" xl="7">
        <EntityTablePanel
          title="Inbound Traffic"
          subtitle="Connections and datagrams that hit honeypot listeners."
          v-model:live-enabled="liveRefreshEnabled"
          :rows="filteredPackets"
          :columns="packetColumns"
          :expandable-rows="true"
          :loading="loading"
          :error="error"
          :last-updated="lastUpdated"
          :live-refresh="true"
          :page-size="30"
          empty-text="No honeypot traffic recorded"
          :total-available="packetsMeta.totalAvailable"
          :truncated="packetsMeta.truncated"
          :range-label="timeRangeLabel"
          @refresh="load"
          @load-more="loadMore"
        >
          <template #cell-updated_at="{ value }">
            {{ formatTimestamp(value) }}
          </template>
          <template #cell-interface="{ value }">
            <v-chip size="x-small" color="warning" variant="tonal">
              {{ value || "honeypot" }}
            </v-chip>
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
          <template #cell-src_ip="{ value }">
            <span class="mono">{{ value || "-" }}</span>
          </template>
          <template #cell-dst_ip="{ value }">
            <span class="mono">{{ value || "-" }}</span>
          </template>
          <template #cell-size="{ item }">
            <span class="meta-cell">{{ buildPacketSizeSummary(item) }}</span>
          </template>
          <template #cell-flow_key="{ value }">
            <span class="mono flow-key" :title="value || '-'">{{ truncateMiddle(value, 10, 10) || "-" }}</span>
          </template>
          <template #cell-summary="{ item }">
            <span class="summary-cell">{{ buildPacketSummary(item, 170) || "-" }}</span>
          </template>
        </EntityTablePanel>
      </v-col>

      <v-col cols="12" xl="5">
        <EntityTablePanel
          title="Honeypot Responses"
          subtitle="Decoded payloads and replies emitted by honeypot listeners."
          v-model:live-enabled="liveRefreshEnabled"
          :rows="filteredBanners"
          :columns="bannerColumns"
          :expandable-rows="true"
          :loading="loading"
          :error="error"
          :last-updated="lastUpdated"
          :live-refresh="true"
          :page-size="30"
          empty-text="No honeypot responses recorded"
          :total-available="bannersMeta.totalAvailable"
          :truncated="bannersMeta.truncated"
          :range-label="timeRangeLabel"
          @refresh="load"
          @load-more="loadMore"
        >
          <template #cell-updated_at="{ value }">
            {{ formatTimestamp(value) }}
          </template>
          <template #cell-interface="{ value }">
            <v-chip size="x-small" color="warning" variant="tonal">
              {{ value || "honeypot" }}
            </v-chip>
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
          <template #cell-src_ip="{ value }">
            <span class="mono">{{ value || "-" }}</span>
          </template>
          <template #cell-dst_ip="{ value }">
            <span class="mono">{{ value || "-" }}</span>
          </template>
          <template #cell-response_size="{ value }">
            <span class="meta-cell">{{ formatSize(value) }}</span>
          </template>
          <template #cell-flow_key="{ value }">
            <span class="mono flow-key" :title="value || '-'">{{ truncateMiddle(value, 10, 10) || "-" }}</span>
          </template>
          <template #cell-response_plain="{ item }">
            <span class="summary-cell">{{ buildResponseSummary(item, 180) || "-" }}</span>
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
import MonitorMatchesPanel from "../components/monitors/MonitorMatchesPanel.vue";
import {
  buildPacketSizeSummary,
  buildPacketSummary,
  buildResponseSummary,
  formatTimestamp,
  formatBytes,
  hasOptionValue,
  matchesSearch,
  truncateMiddle,
  uniqueSorted,
} from "../utils/traffic";

// Cadence for the stream, in milliseconds.
const FEED_REFRESH_MS = 1000;

export default {
  name: "HoneypotView",
  components: {
    ViewHeader,
    EntityTablePanel,
    MonitorMatchesPanel,
  },
  data() {
    return {
      store,
      loading: false,
      error: "",
      lastUpdated: "",
      liveRefreshEnabled: true,
      packets: [],
      banners: [],
      packetLimit: 400,
      bannerLimit: 250,
      packetsMeta: { totalAvailable: null, returned: null, truncated: null },
      bannersMeta: { totalAvailable: null, returned: null, truncated: null },
      runtimeError: "",
      clearDialog: false,
      clearing: false,
      clearError: "",
      filters: {
        query: "",
        proto: "",
        service: "",
      },
      packetColumns: [
        { key: "updated_at", label: "Seen" },
        { key: "interface", label: "Listener" },
        { key: "proto", label: "Proto" },
        { key: "state", label: "State" },
        { key: "src_ip", label: "Src IP" },
        { key: "src_port", label: "Src Port" },
        { key: "dst_ip", label: "Dst IP" },
        { key: "dst_port", label: "Dst Port" },
        { key: "size", label: "Size" },
        { key: "flow_key", label: "Flow" },
        { key: "summary", label: "Summary" },
      ],
      bannerColumns: [
        { key: "updated_at", label: "Seen" },
        { key: "interface", label: "Listener" },
        { key: "proto", label: "Proto" },
        { key: "state", label: "State" },
        { key: "src_ip", label: "Src IP" },
        { key: "src_port", label: "Src Port" },
        { key: "dst_ip", label: "Dst IP" },
        { key: "dst_port", label: "Dst Port" },
        { key: "response_size", label: "Size" },
        { key: "flow_key", label: "Flow" },
        { key: "response_plain", label: "Response" },
      ],
      packetFeed: null,
      bannerFeed: null,
    };
  },
  computed: {
    timeRangeLabel() {
      return this.store.timeRangeLabel();
    },
    honeypotHitsMonitor() {
      // Not a real entry in the monitors catalog; honeypot traffic never runs
      // through evaluate_packet/AnomalyEngine. This shape lets
      // MonitorMatchesPanel query the synthetic honeypot-hit id.
      return { id: "builtin-honeypot-hit", name: "Honeypot hits" };
    },
    apiBase() {
      return this.store.state.apiBase;
    },
    runtime() {
      const runtime = this.store.state.runtime || {};
      return runtime.honeypot && typeof runtime.honeypot === "object" ? runtime.honeypot : {};
    },
    listenerCount() {
      const listeners = Array.isArray(this.runtime.listeners) ? this.runtime.listeners : [];
      return listeners.length;
    },
    metricCards() {
      const packets = this.packets;
      const sources = new Set(packets.map((item) => String(item.src_ip || "").trim()).filter(Boolean));
      const services = new Set(packets.map((item) => String(item.dst_port || "").trim()).filter(Boolean));
      const protocols = new Set(packets.map((item) => String(item.proto || "").trim()).filter(Boolean));
      return [
        {
          key: "events",
          label: "Traffic Hits",
          value: packets.length,
          caption: "Inbound events accepted by honeypot listeners",
          icon: "mdi-radar",
          colorClass: "text-warning",
        },
        {
          key: "responses",
          label: "Responses",
          value: this.banners.length,
          caption: "Decoded honeypot payload or banner rows",
          icon: "mdi-reply-all",
          colorClass: "text-info",
        },
        {
          key: "sources",
          label: "Source IPs",
          value: sources.size,
          caption: "Distinct remote addresses seen in this slice",
          icon: "mdi-ip-network",
          colorClass: "text-primary",
        },
        {
          key: "services",
          label: "Services",
          value: Math.max(services.size, protocols.size),
          caption: `${this.listenerCount} listeners currently configured`,
          icon: "mdi-server-security",
          colorClass: "text-success",
        },
      ];
    },
    protocolOptions() {
      const values = uniqueSorted([
        ...this.packets.map((item) => item.proto),
        ...this.banners.map((item) => item.proto),
      ]);
      return [{ label: "All", value: "" }, ...values.map((value) => ({ label: value.toUpperCase(), value }))];
    },
    serviceOptions() {
      const values = uniqueSorted(
        this.packets.map((item) => String(item.dst_port || item.port || "").trim()).filter(Boolean)
      );
      return [{ label: "All", value: "" }, ...values.map((value) => ({ label: `Port ${value}`, value }))];
    },
    filteredPackets() {
      const query = String(this.filters.query || "").trim().toLowerCase();
      const proto = String(this.filters.proto || "").trim().toLowerCase();
      const service = String(this.filters.service || "").trim();
      return this.packets.filter((item) => {
        if (proto && String(item.proto || "").trim().toLowerCase() !== proto) return false;
        if (service && String(item.dst_port || item.port || "").trim() !== service) return false;
        return matchesSearch(query, [
          item.interface,
          item.proto,
          item.src_ip,
          item.dst_ip,
          item.src_port,
          item.dst_port,
          item.state,
          item.flow_key,
          item.summary,
          item.banner_text,
          item.payload_text,
          item.payload_hex,
        ]);
      });
    },
    filteredBanners() {
      const query = String(this.filters.query || "").trim().toLowerCase();
      const proto = String(this.filters.proto || "").trim().toLowerCase();
      const service = String(this.filters.service || "").trim();
      return this.banners.filter((item) => {
        if (proto && String(item.proto || "").trim().toLowerCase() !== proto) return false;
        if (service && String(item.port || item.dst_port || "").trim() !== service) return false;
        return matchesSearch(query, [
          item.interface,
          item.proto,
          item.src_ip,
          item.dst_ip,
          item.src_port,
          item.dst_port,
          item.state,
          item.flow_key,
          item.response_size,
          item.response_plain,
          item.summary,
        ]);
      });
    },
  },
  watch: {
    liveRefreshEnabled(value) {
      if (value) this.openFeeds();
      else this.closeFeeds();
    },
    packetLimit() {
      this.openFeeds();
    },
    bannerLimit() {
      this.openFeeds();
    },
    apiBase() {
      this.openFeeds();
    },
  },
  mounted() {
    this.store.initRuntime();
    this.openFeeds();
  },
  beforeUnmount() {
    this.closeFeeds();
  },
  methods: {
    buildPacketSizeSummary,
    buildPacketSummary,
    buildResponseSummary,
    formatTimestamp,
    truncateMiddle,
    syncFilters() {
      if (!hasOptionValue(this.protocolOptions, this.filters.proto)) this.filters.proto = "";
      if (!hasOptionValue(this.serviceOptions, this.filters.service)) this.filters.service = "";
    },
    formatSize(value) {
      return formatBytes(value) || "-";
    },
    confirmClear() {
      this.clearing = true;
      this.clearError = "";
      this.store
        .clearDetections("honeypot")
        .then(() => this.load())
        .then(() => {
          this.clearDialog = false;
        })
        .catch((err) => {
          this.clearError = (err && err.message) || "Failed to clear alerts";
        })
        .finally(() => {
          this.clearing = false;
        });
    },
    statusColor(value) {
      const state = String(value || "").trim().toLowerCase();
      if (state === "open" || state === "active") return "success";
      if (state === "filtered" || state === "blocked") return "warning";
      if (state === "closed") return "error";
      return "secondary";
    },
    loadMore() {
      this.packetLimit = Math.min(this.packetLimit + 1000, 20000);
      this.bannerLimit = Math.min(this.bannerLimit + 500, 20000);
      this.load({ silent: true }).catch(() => null);
    },
    // Two streams, one per table: /ws/ports and /ws/banners, both scoped to
    // mode=honeypot. Separate sockets rather than one multiplexed feed because
    // the two tables page independently - changing the packet limit must not
    // re-send the responses table as well.
    openFeeds() {
      this.closeFeeds();
      this.loading = true;
      this.packetFeed = this.store.openDataFeed(
        "ports",
        { mode: "honeypot", limit: this.packetLimit, refresh: FEED_REFRESH_MS },
        (payload) => this.applyPacketFeed(payload),
        () => {
          this.load({ silent: true }).catch(() => null);
        },
      );
      this.bannerFeed = this.store.openDataFeed(
        "banners",
        { mode: "honeypot", limit: this.bannerLimit, refresh: FEED_REFRESH_MS },
        (payload) => this.applyBannerFeed(payload),
        () => {
          this.load({ silent: true }).catch(() => null);
        },
      );
    },
    closeFeeds() {
      [this.packetFeed, this.bannerFeed].forEach((handle) => {
        if (handle) handle.close();
      });
      this.packetFeed = null;
      this.bannerFeed = null;
    },
    applyPacketFeed(payload) {
      if (payload && payload.type === "feed_error") {
        this.error = payload.message || "The service traffic stream stopped updating";
        this.loading = false;
        return;
      }
      if (!payload || payload.type !== "feed_data") return;
      const { rows, meta } = this.store.feedListResult(payload);
      this.packets = rows;
      this.packetsMeta = meta;
      this.error = "";
      this.syncFilters();
      this.lastUpdated = new Date().toLocaleTimeString();
      this.loading = false;
    },
    applyBannerFeed(payload) {
      if (payload && payload.type === "feed_error") {
        this.error = payload.message || "The service responses stream stopped updating";
        return;
      }
      if (!payload || payload.type !== "feed_data") return;
      const { rows, meta } = this.store.feedListResult(payload);
      this.banners = rows;
      this.bannersMeta = meta;
      this.syncFilters();
    },
    // Kept as the single-shot fallback for when a stream cannot serve.
    load(options = {}) {
      if (!options.silent) this.loading = true;
      this.error = "";
      return Promise.allSettled([
        this.store.fetchListPromise("/ports/", { params: { mode: "honeypot" }, limit: this.packetLimit }),
        this.store.fetchListPromise("/banners/", { params: { mode: "honeypot" }, limit: this.bannerLimit }),
        this.store.initRuntime(),
      ])
        .then(([packetsRes, bannersRes]) => {
          const errors = [];
          if (packetsRes.status === "fulfilled") {
            this.packets = packetsRes.value.rows;
            this.packetsMeta = packetsRes.value.meta;
          } else {
            this.packets = [];
            this.packetsMeta = { totalAvailable: null, returned: null, truncated: null };
            errors.push((packetsRes.reason && packetsRes.reason.message) || "Failed to load service traffic");
          }
          if (bannersRes.status === "fulfilled") {
            this.banners = bannersRes.value.rows;
            this.bannersMeta = bannersRes.value.meta;
          } else {
            this.banners = [];
            this.bannersMeta = { totalAvailable: null, returned: null, truncated: null };
            errors.push((bannersRes.reason && bannersRes.reason.message) || "Failed to load service responses");
          }
          this.error = errors.join(" | ");
          this.syncFilters();
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

.engine-card {
  border-radius: 16px;
}

.metric-icon {
  opacity: 0.92;
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

.flow-key {
  display: inline-block;
  max-width: 170px;
}

.summary-cell {
  display: inline-block;
  max-width: 420px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
</style>
