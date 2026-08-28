<template>
  <div>
    <ViewHeader
      overline="Telemetry"
      title="Sniffer"
      description="Inspect every captured packet, choose which interfaces to listen on, and filter by protocol, direction, and state."
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

    <v-alert
      v-if="snifferBlocked"
      type="error"
      variant="tonal"
      class="mt-6"
    >
      {{ snifferErrorSummary }}
    </v-alert>

    <v-alert v-if="error" type="error" variant="tonal" class="mt-6">
      {{ error }}
    </v-alert>

    <div class="mt-6">
      <v-row dense class="mb-3">
        <v-col cols="12" md="4">
          <v-text-field
            v-model.trim="filters.query"
            label="Search packets"
            name="sniffer_packet_search"
            placeholder="IP, port, payload, summary..."
            prepend-inner-icon="mdi-magnify"
            clearable
            variant="outlined"
            density="comfortable"
          />
        </v-col>
        <v-col cols="12" sm="6" md="2">
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
        <v-col cols="12" sm="6" md="2">
          <v-select
            v-model="filters.interface"
            :items="interfaceOptions"
            label="Interface"
            item-title="label"
            item-value="value"
            clearable
            variant="outlined"
            density="comfortable"
          />
        </v-col>
        <v-col cols="12" sm="6" md="2">
          <v-select
            v-model="filters.direction"
            :items="directionOptions"
            label="Direction"
            item-title="label"
            item-value="value"
            clearable
            variant="outlined"
            density="comfortable"
          />
        </v-col>
        <v-col cols="12" sm="6" md="2">
          <v-select
            v-model="filters.state"
            :items="stateOptions"
            label="State"
            item-title="label"
            item-value="value"
            clearable
            variant="outlined"
            density="comfortable"
          />
        </v-col>
      </v-row>

      <div class="d-flex flex-wrap ga-2 mb-4">
        <v-chip size="small" variant="tonal" color="info" prepend-icon="mdi-lan-check">
          Selected: {{ selectedInterfacesLabel }}
        </v-chip>
        <v-chip size="small" variant="outlined" prepend-icon="mdi-access-point-network">
          Active interfaces: {{ activeInterfacesLabel }}
        </v-chip>
        <v-chip size="small" variant="outlined" prepend-icon="mdi-table-eye">
          Visible rows: {{ filteredPackets.length }}
        </v-chip>
        <v-chip size="small" variant="outlined" color="info" prepend-icon="mdi-download-network-outline">
          Captured: {{ runtime.packets_seen || 0 }}
        </v-chip>
        <v-chip size="small" variant="outlined" color="success" prepend-icon="mdi-database-check">
          Stored (detected): {{ runtime.packets_stored || 0 }}
        </v-chip>
        <v-chip
          v-if="unparseableCount > 0"
          size="small"
          variant="outlined"
          color="warning"
          prepend-icon="mdi-alert-decagram-outline"
        >
          Unparseable frames: {{ unparseableCount }}
          <v-tooltip activator="parent" location="bottom">
            {{ unparseableTooltip }}
          </v-tooltip>
        </v-chip>
        <v-btn
          size="small"
          variant="text"
          color="primary"
          icon
          to="/monitors"
          aria-label="View detection monitors"
        >
          <v-icon icon="mdi-target-account" />
          <v-tooltip activator="parent" location="bottom">View detection monitors</v-tooltip>
        </v-btn>
        <v-btn
          size="small"
          variant="text"
          color="primary"
          icon
          to="/settings?section=capture"
          aria-label="Configure interfaces"
        >
          <v-icon icon="mdi-cog-outline" />
          <v-tooltip activator="parent" location="bottom">Configure interfaces</v-tooltip>
        </v-btn>
      </div>

      <TimeHistogram
        title="Packets over time"
        subtitle="Volume of the packets currently loaded, bucketed by capture time."
        :rows="filteredPackets"
        timestamp-key="created_at"
        :loading="loading"
        :error="error"
        :last-updated="lastUpdated"
        count-label="packets"
        empty-text="No packets in the current window yet"
        class="mb-4"
      />

      <EntityTablePanel
        title="Packets"
        subtitle="Newest packet rows emitted by the passive sniffer."
        v-model:live-enabled="liveRefreshEnabled"
        :rows="filteredPackets"
        :columns="columns"
        :expandable-rows="true"
        :loading="loading"
        :error="error"
        :last-updated="lastUpdated"
        :live-refresh="true"
        :page-size="40"
        empty-text="No sniffer packets available"
        :total-available="packetsMeta.totalAvailable"
        :truncated="packetsMeta.truncated"
        :range-label="timeRangeLabel"
        @refresh="load"
        @load-more="loadMorePackets"
      >
        <template #cell-updated_at="{ value }">
          {{ formatTimestamp(value) }}
        </template>
        <template #cell-interface="{ value }">
          <v-chip size="x-small" color="info" variant="tonal">
            {{ value || "unknown" }}
          </v-chip>
        </template>
        <template #cell-proto="{ value }">
          <v-chip size="x-small" color="primary" variant="tonal">
            {{ String(value || "unknown").toUpperCase() }}
          </v-chip>
        </template>
        <template #cell-direction="{ value }">
          <v-chip
            size="x-small"
            :color="String(value || '').trim().toLowerCase() === 'inbound' ? 'warning' : 'success'"
            variant="tonal"
          >
            {{ value || "unknown" }}
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
        <template #cell-route="{ item }">
          <span class="meta-cell">{{ buildPacketRouteSummary(item) }}</span>
        </template>
        <template #cell-flow_key="{ value }">
          <span class="mono flow-key" :title="value || '-'">{{ truncateMiddle(value, 10, 10) || "-" }}</span>
        </template>
        <template #cell-detail="{ item }">
          <span class="detail-cell">{{ buildPacketDetail(item) }}</span>
        </template>
        <template #cell-summary="{ item }">
          <span class="summary-cell">{{ buildPacketSummary(item, 180) || "-" }}</span>
        </template>
      </EntityTablePanel>
    </div>
  </div>
</template>

<script>
import store from "../state/appStore";
import ViewHeader from "../components/ui/ViewHeader.vue";
import EntityTablePanel from "../components/ui/EntityTablePanel.vue";
import TimeHistogram from "../components/ui/TimeHistogram.vue";
import {
  buildPacketDetail,
  buildPacketRouteSummary,
  buildPacketSizeSummary,
  buildPacketSummary,
  formatTimestamp,
  hasOptionValue,
  matchesSearch,
  truncateMiddle,
  uniqueSorted,
} from "../utils/traffic";

// Cadence for the stream, in milliseconds.
const FEED_REFRESH_MS = 1000;

export default {
  name: "SnifferView",
  components: {
    ViewHeader,
    EntityTablePanel,
    TimeHistogram,
  },
  data() {
    return {
      store,
      loading: false,
      error: "",
      lastUpdated: "",
      liveRefreshEnabled: true,
      packets: [],
      packetLimit: 600,
      packetsMeta: { totalAvailable: null, returned: null, truncated: null },
      runtimeError: "",
      filters: {
        query: "",
        proto: "",
        interface: "",
        direction: "",
        state: "",
      },
      columns: [
        { key: "updated_at", label: "Seen" },
        { key: "interface", label: "Interface" },
        { key: "proto", label: "Proto" },
        { key: "direction", label: "Direction" },
        { key: "state", label: "State" },
        { key: "src_ip", label: "Src IP" },
        { key: "src_port", label: "Src Port" },
        { key: "dst_ip", label: "Dst IP" },
        { key: "dst_port", label: "Dst Port" },
        { key: "size", label: "Size" },
        { key: "route", label: "Network" },
        { key: "flow_key", label: "Flow" },
        { key: "detail", label: "Signal" },
        { key: "summary", label: "Summary" },
      ],
      feedHandle: null,
    };
  },
  computed: {
    apiBase() {
      return this.store.state.apiBase;
    },
    timeRangeLabel() {
      return this.store.timeRangeLabel();
    },
    runtime() {
      const runtime = this.store.state.runtime || {};
      return runtime.sniffer && typeof runtime.sniffer === "object" ? runtime.sniffer : {};
    },
    snifferBlocked() {
      return String(this.runtime.capture_state || "").trim().toLowerCase() === "blocked";
    },
    snifferErrorSummary() {
      const entries = this.runtime.errors && typeof this.runtime.errors === "object"
        ? Object.entries(this.runtime.errors)
        : [];
      if (!entries.length) return "Packet capture is blocked on the selected interfaces.";
      return entries
        .slice(0, 2)
        .map(([name, message]) => `${name}: ${message}`)
        .join(" | ");
    },
    metricCards() {
      const packets = this.packets;
      const protocols = new Set(packets.map((item) => String(item.proto || "").trim()).filter(Boolean));
      const interfaces = new Set(packets.map((item) => String(item.interface || "").trim()).filter(Boolean));
      const withPayload = packets.filter((item) => String(item.payload_text || item.banner_text || "").trim()).length;
      const inbound = packets.filter((item) => String(item.direction || "").trim().toLowerCase() === "inbound").length;
      return [
        {
          key: "packets",
          label: "Packets",
          value: packets.length,
          caption: "Latest sniffer rows loaded into the grid",
          icon: "mdi-ethernet",
          colorClass: "text-success",
        },
        {
          key: "protocols",
          label: "Protocols",
          value: protocols.size,
          caption: "Observed protocol families in this slice",
          icon: "mdi-source-branch",
          colorClass: "text-info",
        },
        {
          key: "interfaces",
          label: "Interfaces",
          value: interfaces.size,
          caption: "Interfaces currently represented in rows",
          icon: "mdi-lan",
          colorClass: "text-primary",
        },
        {
          key: "payloads",
          label: "Payload Rows",
          value: withPayload,
          caption: `${inbound} inbound packets in the current slice`,
          icon: "mdi-text-box-search",
          colorClass: "text-warning",
        },
      ];
    },
    protocolOptions() {
      const values = uniqueSorted(this.packets.map((item) => item.proto));
      return [{ label: "All", value: "" }, ...values.map((value) => ({ label: value.toUpperCase(), value }))];
    },
    interfaceOptions() {
      const values = uniqueSorted(this.packets.map((item) => item.interface));
      return [{ label: "All", value: "" }, ...values.map((value) => ({ label: value, value }))];
    },
    directionOptions() {
      const values = uniqueSorted(this.packets.map((item) => item.direction));
      return [{ label: "All", value: "" }, ...values.map((value) => ({ label: value, value }))];
    },
    stateOptions() {
      const values = uniqueSorted(this.packets.map((item) => item.state));
      return [{ label: "All", value: "" }, ...values.map((value) => ({ label: value, value }))];
    },
    selectedInterfacesLabel() {
      const values = Array.isArray(this.runtime.selected_interfaces) ? this.runtime.selected_interfaces : [];
      if (!values.length) return "all visible";
      return values.join(", ");
    },
    activeInterfacesLabel() {
      const values = Array.isArray(this.runtime.interfaces) ? this.runtime.interfaces : [];
      if (!values.length) return "none";
      if (values.length === 1) return values[0];
      return `${values.length} active`;
    },
    unparseableCount() {
      return Number(this.runtime.packets_unparseable || 0);
    },
    unparseableTooltip() {
      // A spike of frames the parser cannot decode is what fuzzing or an
      // evasion attempt against the sensor looks like, so the per-interface
      // breakdown is the useful part.
      const perInterface = this.runtime.unparseable_by_interface || {};
      const parts = Object.keys(perInterface)
        .sort()
        .map((name) => `${name}: ${perInterface[name]}`);
      const detail = parts.length ? ` (${parts.join(", ")})` : "";
      return `Frames the parser could not decode${detail}. A sudden rise can indicate malformed or fuzzed traffic aimed at the sensor.`;
    },
    filteredPackets() {
      const query = String(this.filters.query || "").trim().toLowerCase();
      const proto = String(this.filters.proto || "").trim().toLowerCase();
      const interfaceName = String(this.filters.interface || "").trim().toLowerCase();
      const direction = String(this.filters.direction || "").trim().toLowerCase();
      const state = String(this.filters.state || "").trim().toLowerCase();
      return this.packets.filter((item) => {
        if (proto && String(item.proto || "").trim().toLowerCase() !== proto) return false;
        if (interfaceName && String(item.interface || "").trim().toLowerCase() !== interfaceName) return false;
        if (direction && String(item.direction || "").trim().toLowerCase() !== direction) return false;
        if (state && String(item.state || "").trim().toLowerCase() !== state) return false;
        return matchesSearch(query, [
          item.interface,
          item.proto,
          item.direction,
          item.state,
          item.scan_state,
          item.src_ip,
          item.dst_ip,
          item.src_port,
          item.dst_port,
          item.flow_key,
          item.eth_src,
          item.eth_dst,
          item.ttl,
          item.hop_limit,
          item.summary,
          item.banner_text,
          item.payload_text,
          item.payload_hex,
          item.tcp_flags,
          item.tags || [],
          item.rule_hits || [],
        ]);
      });
    },
  },
  watch: {
    apiBase() {
      this.openFeed();
    },
    packetLimit() {
      // Reconfiguring means a new socket: the parameters live in the URL, so
      // the running one describes the old slice and cannot be re-pointed.
      this.openFeed();
    },
    liveRefreshEnabled(value) {
      // The panel's live toggle now controls the stream itself. Leaving the
      // socket open while the switch says "off" would keep the server running
      // its query for a view that is telling the user it stopped.
      if (value) this.openFeed();
      else this.closeFeed();
    },
  },
  mounted() {
    this.store.initRuntime();
    this.openFeed();
  },
  beforeUnmount() {
    this.closeFeed();
  },
  methods: {
    buildPacketDetail,
    buildPacketRouteSummary,
    buildPacketSizeSummary,
    buildPacketSummary,
    formatTimestamp,
    truncateMiddle,
    syncFilters() {
      if (!hasOptionValue(this.protocolOptions, this.filters.proto)) this.filters.proto = "";
      if (!hasOptionValue(this.interfaceOptions, this.filters.interface)) this.filters.interface = "";
      if (!hasOptionValue(this.directionOptions, this.filters.direction)) this.filters.direction = "";
      if (!hasOptionValue(this.stateOptions, this.filters.state)) this.filters.state = "";
    },
    statusColor(value) {
      const state = String(value || "").trim().toLowerCase();
      if (state === "open" || state === "active") return "success";
      if (state === "filtered" || state === "blocked") return "warning";
      if (state === "closed") return "error";
      return "secondary";
    },
    // The table is fed by its own websocket now: /ws/ports carries the same
    // rows /ports/ returned, pushed at the interval in its URL. The view used
    // to re-issue the whole HTTP read on every websocket "something changed"
    // event, which is the polling this replaces.
    openFeed() {
      this.closeFeed();
      this.loading = true;
      this.feedHandle = this.store.openDataFeed(
        "ports",
        { mode: "sniffer", limit: this.packetLimit, refresh: FEED_REFRESH_MS },
        (payload) => this.applyFeed(payload),
        // Only when the stream cannot serve: no socket, or one that never
        // delivered a first frame. A single read, not a resumed poll.
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
        this.error = payload.message || "The sniffer stream stopped updating";
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
    loadMorePackets() {
      this.packetLimit = Math.min(this.packetLimit + 1000, 20000);
      this.load({ silent: true }).catch(() => null);
    },
    load(options = {}) {
      if (!options.silent) this.loading = true;
      this.error = "";
      return Promise.allSettled([
        this.store.fetchListPromise("/ports/", { params: { mode: "sniffer" }, limit: this.packetLimit }),
        this.store.initRuntime(),
      ])
        .then(([packetsRes]) => {
          if (packetsRes.status === "fulfilled") {
            this.packets = packetsRes.value.rows;
            this.packetsMeta = packetsRes.value.meta;
            this.error = "";
          } else {
            this.packets = [];
            this.packetsMeta = { totalAvailable: null, returned: null, truncated: null };
            this.error = (packetsRes.reason && packetsRes.reason.message) || "Failed to load sniffer packets";
          }
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

.meta-cell,
.detail-cell{
  /* Fixed width, not max-width: with `overflow-wrap: anywhere` a
     cell's min-content width is a single character, so the table's
     auto layout was free to collapse the column to ~1ch and wrap the
     banner one letter per line, blowing the row up to hundreds of
     pixels tall. A definite width pins the column; the clamp keeps
     every row the same height and the full text stays in the title
     attribute. */
  width: 180px;
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
  max-width: 180px;
}

.summary-cell {
  display: inline-block;
  max-width: 480px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

</style>
