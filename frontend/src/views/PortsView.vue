<template>
  <div>
    <ViewHeader
      overline="Packets"
      title="Packet Intelligence"
      description="Review captured packet activity by protocol."
      :refresh-loading="loading"
      @refresh="load"
    />

    <DataPanel
      title="Captured Packets"
      subtitle="Switch protocol tabs and track endpoint state with WebSocket-assisted refresh."
      v-model:live-enabled="liveRefreshEnabled"
      :loading="loading"
      :show-skeleton="false"
      :error="error"
      :last-updated="lastUpdated"
      :live-refresh="true"
      @refresh="load"
    >
      <v-alert v-if="!protocols.length && !loading" type="info" variant="tonal" class="mt-4">
        No protocols available from backend.
      </v-alert>

      <template v-else>
        <v-row dense class="mt-2">
          <v-col cols="12" md="7">
            <v-text-field
              v-model.trim="tableFilters.query"
              label="Search packets"
              name="port_table_search"
              placeholder="IP, port, state..."
              prepend-inner-icon="mdi-magnify"
              clearable
              variant="outlined"
              density="comfortable"
            />
          </v-col>
          <v-col cols="12" md="3">
            <v-select
              v-model="tableFilters.state"
              :items="stateFilterOptions"
              label="State"
              name="port_table_state_filter"
              item-title="label"
              item-value="value"
              clearable
              variant="outlined"
              density="comfortable"
            />
          </v-col>
        </v-row>
        <div class="protocol-toolbar mt-4">
          <div class="protocol-toolbar__meta">
            <v-chip size="small" color="primary" variant="tonal">
              {{ activeProtoLabel }}
            </v-chip>
            <v-chip size="small" color="info" variant="tonal">
              Visible rows: {{ visibleRowCount }}
            </v-chip>
            <v-chip size="small" variant="outlined">
              Total rows: {{ totalRowCount }}
            </v-chip>
          </div>
        </div>
        <v-tabs v-model="tab" color="primary" class="mt-4">
          <v-tab v-for="proto in protocols" :key="proto" :value="proto" :disabled="loading">
            {{ proto.toUpperCase() }}
          </v-tab>
        </v-tabs>
        <v-window v-model="tab" class="mt-4">
          <v-window-item v-for="proto in protocols" :key="`win-${proto}`" :value="proto">
            <div class="ports-table-wrap">
              <v-data-table
                :page="paginationByProto[proto] || 1"
                :sort-by="sortByByProto[proto] || []"
                :expanded="expandedRowsByProto[proto] || []"
                :headers="portTableHeaders"
                :items="filteredRowsByProto[proto] || []"
                :items-per-page="PAGE_SIZE"
                :items-per-page-options="portItemsPerPageOptions"
                :hide-default-footer="(filteredRowsByProto[proto] || []).length <= PAGE_SIZE"
                :hide-no-data="loading"
                :item-value="resolvePortTableRowKey"
                expand-strategy="single"
                show-expand
                density="comfortable"
                mobile-breakpoint="960"
                class="ports-data-table"
                @update:page="setPageForProto(proto, $event)"
                @update:sort-by="setSortByForProto(proto, $event)"
                @update:expanded="setExpandedRowsForProto(proto, $event)"
              >
                <template v-slot:[portSlotNames.expandHeader]>
                  <span class="ports-data-table__expand-header" aria-hidden="true"></span>
                </template>

                <template v-slot:[portSlotNames.expandItem]="{ internalItem, isExpanded, toggleExpand }">
                  <v-btn
                    icon
                    size="small"
                    variant="text"
                    color="info"
                    class="ports-data-table__expand-button"
                    :aria-label="isExpanded(internalItem) ? 'Collapse JSON view' : 'Expand JSON view'"
                    @click.stop="toggleExpand(internalItem)"
                  >
                    <v-icon :icon="isExpanded(internalItem) ? 'mdi-chevron-down' : 'mdi-chevron-right'" />
                  </v-btn>
                </template>

                <template v-slot:[portSlotNames.updatedAt]="{ item }">
                  {{ formatTimestamp(item.updated_at) }}
                </template>

                <template v-slot:[portSlotNames.proto]="{ item }">
                  <v-chip size="x-small" color="primary" variant="tonal">
                    {{ String(item.proto || proto || "unknown").toUpperCase() }}
                  </v-chip>
                </template>

                <template v-slot:[portSlotNames.interface]="{ item }">
                  <v-chip size="x-small" color="info" variant="tonal">
                    {{ item.interface || "unknown" }}
                  </v-chip>
                </template>

                <template v-slot:[portSlotNames.ip]="{ item }">
                  <router-link
                    v-if="item.ip"
                    class="mono ip-link"
                    :to="{ path: '/investigate', query: { ip: item.ip } }"
                  >
                    {{ item.ip }}
                  </router-link>
                  <span v-else>-</span>
                </template>

                <template v-slot:[portSlotNames.state]="{ item }">
                  <div :title="formatStateTooltip(item)">
                    <v-chip size="x-small" :color="portStateColor(item)" variant="tonal">
                      {{ formatStateLabel(item) }}
                    </v-chip>
                  </div>
                </template>

                <template v-slot:[portSlotNames.scanState]="{ item }">
                  <v-chip
                    size="x-small"
                    :color="scanStatusColor(item.scan_state)"
                    variant="tonal"
                  >
                    {{ scanStatusLabel(item.scan_state) }}
                  </v-chip>
                </template>

                <template v-slot:[portSlotNames.progress]="{ item }">
                  <ProgressCell :value="item.progress" />
                </template>

                <template v-slot:[portSlotNames.summary]="{ item }">
                  <span class="summary-cell">{{ buildPacketSummary(item, 140) || "-" }}</span>
                </template>

                <template v-slot:[portSlotNames.actions]="{ item }">
                  <div class="row-actions">
                    <v-btn
                      size="x-small"
                      color="success"
                      variant="tonal"
                      :disabled="loading || isPortActionLoading(item.id, 'start') || normalizePortScanState(item.scan_state) === 'active'"
                      @click="runPortAction(item, 'start')"
                    >
                      Start
                    </v-btn>
                    <v-btn
                      size="x-small"
                      color="warning"
                      variant="tonal"
                      :disabled="loading || isPortActionLoading(item.id, 'stop') || normalizePortScanState(item.scan_state) === 'stopped'"
                      @click="runPortAction(item, 'stop')"
                    >
                      Stop
                    </v-btn>
                    <v-btn
                      size="x-small"
                      color="info"
                      variant="tonal"
                      :disabled="loading || isPortActionLoading(item.id, 'restart')"
                      @click="runPortAction(item, 'restart')"
                    >
                      Restart
                    </v-btn>
                  </div>
                </template>

                <template #expanded-row="{ columns, item }">
                  <tr class="ports-data-table__expanded-row">
                    <td :colspan="columns.length" class="ports-data-table__expanded-cell">
                      <div class="ports-json-panel">
                        <div class="ports-json-panel__label">Full packet JSON</div>
                        <pre class="ports-json">{{ formatPortRowJson(item) }}</pre>
                      </div>
                    </td>
                  </tr>
                </template>

                <template #no-data>
                  <div class="text-medium-emphasis py-4 text-center">
                    No {{ proto.toUpperCase() }} packets
                  </div>
                </template>
              </v-data-table>
            </div>
          </v-window-item>
        </v-window>
      </template>
    </DataPanel>
  </div>
</template>

<script>
import store from "../state/appStore";
import ViewHeader from "../components/ui/ViewHeader.vue";
import DataPanel from "../components/ui/DataPanel.vue";
import ProgressCell from "../components/ui/ProgressCell.vue";
import {
  buildPacketSummary,
  formatTimestamp,
  hasOptionValue,
  matchesSearch,
} from "../utils/traffic";

const FALLBACK_PROTOCOLS = ["tcp", "udp", "icmp", "icmpv6", "arp", "sctp", "stp", "unknown"];
const PAGE_SIZE = 80;
const REFRESH_EVENT_TYPES = new Set(["packet", "stats_update", "runtime_mode"]);

export default {
  name: "PortsView",
  components: {
    ViewHeader,
    DataPanel,
    ProgressCell,
  },
  data() {
    return {
      store,
      loading: false,
      error: "",
      lastUpdated: "",
      liveRefreshEnabled: true,
      tab: "tcp",
      protocols: [],
      portsByProto: {},
      tableFilters: {
        query: "",
        state: "",
      },
      portActionLoading: {
        id: null,
        action: "",
      },
      paginationByProto: {},
      sortByByProto: {},
      expandedRowsByProto: {},
      lastProtocolsSyncAt: 0,
      wsRefreshTimer: null,
      stopTableRefreshSubscription: null,
    };
  },
  computed: {
    apiBase() {
      return this.store.state.apiBase;
    },
    stateFilterOptions() {
      const states = [...new Set(
        this.rowsFor(this.tab).map((item) => String(item.state || "").trim().toLowerCase())
      )]
        .filter(Boolean)
        .sort();
      return [{ label: "All", value: "" }, ...states.map((value) => ({ label: value, value }))];
    },
    activeProtoLabel() {
      const proto = String(this.tab || "").trim().toUpperCase();
      return proto ? `Control ${proto}` : "Control";
    },
    visibleRowCount() {
      return Array.isArray(this.filteredRowsByProto[this.tab]) ? this.filteredRowsByProto[this.tab].length : 0;
    },
    totalRowCount() {
      return Array.isArray(this.rowsFor(this.tab)) ? this.rowsFor(this.tab).length : 0;
    },
    portSlotNames() {
      return {
        expandHeader: "header.data-table-expand",
        expandItem: "item.data-table-expand",
        updatedAt: "item.updated_at",
        proto: "item.proto",
        interface: "item.interface",
        ip: "item.ip",
        state: "item.state",
        scanState: "item.scan_state",
        progress: "item.progress",
        summary: "item.summary",
        actions: "item.actions",
      };
    },
    portItemsPerPageOptions() {
      return [
        { title: String(PAGE_SIZE), value: PAGE_SIZE },
        { title: String(PAGE_SIZE * 2), value: PAGE_SIZE * 2 },
        { title: "All", value: -1 },
      ];
    },
    portTableHeaders() {
      return [
        { key: "data-table-expand", title: "", sortable: false, width: 48 },
        { key: "updated_at", title: "Seen" },
        { key: "proto", title: "Proto" },
        { key: "interface", title: "Interface" },
        { key: "ip", title: "IP" },
        { key: "port", title: "Port" },
        { key: "state", title: "Endpoint State" },
        { key: "scan_state", title: "Response Status" },
        { key: "progress", title: "Response Progress", sortable: false },
        { key: "summary", title: "Summary", sortable: false },
        { key: "actions", title: "Actions", sortable: false },
      ];
    },
    filteredRowsByProto() {
      const query = String(this.tableFilters.query || "").trim();
      const state = String(this.tableFilters.state || "").trim().toLowerCase();
      const mapped = {};
      this.protocols.forEach((proto) => {
        mapped[proto] = this.rowsFor(proto).filter((item) => {
          if (state && String(item.state || "").trim().toLowerCase() !== state) {
            return false;
          }
          return matchesSearch(query, [
            item.id,
            item.ip,
            item.port,
            item.interface,
            item.proto,
            item.state,
            item.scan_state,
            item.progress,
            item.summary,
            item.banner,
            item.flow_key,
            item.src_ip,
            item.src_port,
            item.dst_ip,
            item.dst_port,
            item.length,
            item.payload_len,
            this.formatStateLabel(item),
            this.formatStateTooltip(item),
          ]);
        });
      });
      return mapped;
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
    tab() {
      this.tableFilters.state = "";
      this.ensureTableStateForProto(this.tab);
    },
    tableFilters: {
      deep: true,
      handler() {
        this.resetPagination();
        this.resetExpandedRows();
      },
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
    buildPacketSummary,
    formatTimestamp,
    normalizePortScanState(value) {
      const raw = String(value || "active").trim().toLowerCase();
      if (raw === "restarting") return "restarting";
      if (raw === "stopped") return "stopped";
      return "active";
    },
    isPortActionLoading(id, action) {
      return this.portActionLoading.id === id && this.portActionLoading.action === action;
    },
    scanStatusLabel(value) {
      const status = this.normalizePortScanState(value);
      if (status === "restarting") return "restarting";
      if (status === "stopped") return "stopped";
      return "active";
    },
    scanStatusColor(value) {
      const status = this.normalizePortScanState(value);
      if (status === "restarting") return "info";
      if (status === "stopped") return "warning";
      return "success";
    },
    portStateColor(row) {
      const state = String(row?.state || "").trim().toLowerCase();
      if (state === "open") return "success";
      if (state === "filtered") return "warning";
      if (state === "closed") return "error";
      return "secondary";
    },
    formatStateLabel(row) {
      const proto = String(row?.proto || "").trim().toLowerCase();
      const state = String(row?.state || "").trim().toLowerCase();
      if (!state) return "-";
      if (proto === "icmp" && state === "filtered") return "no reply";
      return state;
    },
    portRowKey(proto, item) {
      const normalizedProto = String(proto || "").trim().toLowerCase() || "unknown";
      const numericId = Number(item && item.id);
      if (Number.isFinite(numericId) && numericId > 0) {
        return `${normalizedProto}:${numericId}`;
      }
      const ip = String((item && (item.ip || item.src_ip || item.dst_ip)) || "").trim() || "unknown";
      const port = String(item && (item.port ?? item.src_port ?? item.dst_port) != null ? (item.port ?? item.src_port ?? item.dst_port) : "").trim() || "na";
      const updatedAt = String(item && item.updated_at || "").trim() || "na";
      return `${normalizedProto}:${ip}:${port}:${updatedAt}`;
    },
    resolvePortTableRowKey(item) {
      return this.portRowKey(item && item.proto, item);
    },
    formatPortRowJson(item) {
      try {
        return JSON.stringify(item || {}, null, 2);
      } catch (err) {
        return JSON.stringify({ error: err && err.message ? err.message : "Unable to serialize row" }, null, 2);
      }
    },
    formatStateTooltip(row) {
      const proto = String(row?.proto || "").trim().toLowerCase();
      const state = String(row?.state || "").trim().toLowerCase();
      if (!state) return "-";
      if (proto === "icmp" && state === "filtered") {
        return "ICMP echo reply was not received. The host may be down or a firewall may be dropping the probe.";
      }
      if (proto === "icmp" && state === "open") {
        return "ICMP echo reply received.";
      }
      return state;
    },
    rowsFor(proto) {
      return this.portsByProto[proto] || [];
    },
    setPageForProto(proto, page) {
      const key = String(proto || "").trim().toLowerCase();
      if (!key) return;
      const parsed = Number(page);
      this.paginationByProto = {
        ...this.paginationByProto,
        [key]: Number.isFinite(parsed) && parsed > 0 ? parsed : 1,
      };
    },
    setSortByForProto(proto, sortBy) {
      const key = String(proto || "").trim().toLowerCase();
      if (!key) return;
      this.sortByByProto = {
        ...this.sortByByProto,
        [key]: Array.isArray(sortBy) ? sortBy : [],
      };
    },
    setExpandedRowsForProto(proto, expanded) {
      const key = String(proto || "").trim().toLowerCase();
      if (!key) return;
      this.expandedRowsByProto = {
        ...this.expandedRowsByProto,
        [key]: Array.isArray(expanded) ? expanded : [],
      };
    },
    ensureTableStateForProto(proto) {
      const key = String(proto || "").trim().toLowerCase();
      if (!key) return;
      if (!Number(this.paginationByProto[key])) {
        this.paginationByProto = { ...this.paginationByProto, [key]: 1 };
      }
      if (!Array.isArray(this.sortByByProto[key])) {
        this.sortByByProto = { ...this.sortByByProto, [key]: [] };
      }
      if (!Array.isArray(this.expandedRowsByProto[key])) {
        this.expandedRowsByProto = { ...this.expandedRowsByProto, [key]: [] };
      }
    },
    resetPagination() {
      const next = {};
      this.protocols.forEach((proto) => {
        next[proto] = 1;
      });
      this.paginationByProto = next;
    },
    resetExpandedRows() {
      const next = {};
      this.protocols.forEach((proto) => {
        next[proto] = [];
      });
      this.expandedRowsByProto = next;
    },
    syncExpandedRows() {
      const next = {};
      this.protocols.forEach((proto) => {
        const visibleKeys = new Set(
          (this.filteredRowsByProto[proto] || []).map((item) => this.portRowKey(proto, item))
        );
        const current = Array.isArray(this.expandedRowsByProto[proto])
          ? this.expandedRowsByProto[proto]
          : [];
        next[proto] = current.filter((key) => visibleKeys.has(String(key)));
      });
      this.expandedRowsByProto = next;
    },
    syncFilters() {
      if (!hasOptionValue(this.stateFilterOptions, this.tableFilters.state)) {
        this.tableFilters.state = "";
      }
      this.syncExpandedRows();
    },
    handleWsRefresh(event) {
      if (!this.liveRefreshEnabled) return;
      const eventType = String((event && event.type) || "").trim().toLowerCase();
      if (!REFRESH_EVENT_TYPES.has(eventType)) return;
      if (this.wsRefreshTimer) return;
      this.wsRefreshTimer = setTimeout(() => {
        this.wsRefreshTimer = null;
        this.refreshActiveProtocolRealtime().catch(() => {
          // keep stale table on transient realtime errors
        });
      }, 10000);
    },
    normalizeProtocols(raw) {
      const items = this.store.extractArray(raw);
      const unique = [...new Set(items.map((item) => String(item).trim().toLowerCase()))];
      return unique.filter(Boolean);
    },
    loadProtocols() {
      return this.store.fetchJsonPromise("/protocols/").then((protocolsRes) => {
        const protocols = this.normalizeProtocols(protocolsRes);
        return protocols.length ? protocols : FALLBACK_PROTOCOLS;
      });
    },
    loadPortsForProtocols(protocols) {
      const list = Array.isArray(protocols) && protocols.length ? protocols : FALLBACK_PROTOCOLS;
      return Promise.allSettled(
        list.map((proto) => this.store.fetchJsonPromise(`/ports/?proto=${encodeURIComponent(proto)}`))
      ).then((responses) => {
        const mapped = {};
        list.forEach((proto, index) => {
          const result = responses[index];
          mapped[proto] =
            result && result.status === "fulfilled"
              ? this.store.extractArray(result.value)
              : [];
        });
        this.portsByProto = mapped;
        this.protocols = list;
        list.forEach((proto) => this.ensureTableStateForProto(proto));
        this.syncFilters();
      });
    },
    refreshActiveProtocolRealtime() {
      const now = Date.now();
      const shouldSyncProtocols = now - this.lastProtocolsSyncAt >= 30000;
      if (shouldSyncProtocols) {
        return this.load({ silent: true }).catch(() => {
          // keep stale table on transient refresh errors
        });
      }
      const activeProto = String(this.tab || "").trim().toLowerCase();
      if (!activeProto) return Promise.resolve();
      return this.store
        .fetchJsonPromise(`/ports/?proto=${encodeURIComponent(activeProto)}`)
        .then((payload) => {
          this.portsByProto = {
            ...this.portsByProto,
            [activeProto]: this.store.extractArray(payload),
          };
          this.lastUpdated = new Date().toLocaleTimeString();
          this.ensureTableStateForProto(activeProto);
          this.syncFilters();
        })
        .catch(() => {
          // keep stale table on transient refresh errors
        });
    },
    load(options = {}) {
      if (!options.silent) this.loading = true;
      this.error = "";
      return Promise.allSettled([this.loadProtocols()])
        .then(([protocolsRes]) => {
          const protocols =
            protocolsRes.status === "fulfilled" ? protocolsRes.value : FALLBACK_PROTOCOLS;
          if (!protocols.length) {
            this.protocols = [];
            this.portsByProto = {};
            this.paginationByProto = {};
            this.sortByByProto = {};
            this.expandedRowsByProto = {};
            return [];
          }
          if (!protocols.includes(this.tab)) {
            this.tab = protocols[0];
          }
          return this.loadPortsForProtocols(protocols);
        })
        .then(() => {
          this.lastUpdated = new Date().toLocaleTimeString();
          this.lastProtocolsSyncAt = Date.now();
          this.syncFilters();
        })
        .catch((err) => {
          this.protocols = FALLBACK_PROTOCOLS;
          this.portsByProto = {};
          this.resetPagination();
          this.sortByByProto = {};
          this.expandedRowsByProto = {};
          this.lastUpdated = "";
          this.error = err.message || "Failed to load packets";
          this.syncFilters();
        })
        .finally(() => {
          this.loading = false;
        });
    },
    runPortAction(item, action) {
      const endpointId = Number(item && item.id);
      if (!Number.isFinite(endpointId) || endpointId <= 0) {
        this.error = "Invalid session id";
        return Promise.resolve();
      }
      const proto = String(item && item.proto || "").trim().toUpperCase() || "endpoint";
      const ip = String(item && item.ip || "").trim() || "n/a";
      const port = String(item && item.port != null ? item.port : "").trim() || "n/a";
      if (action === "stop") {
        const ok = typeof window !== "undefined"
          ? window.confirm(`Stop ${proto} endpoint ${ip}:${port}?`)
          : true;
        if (!ok) return Promise.resolve();
      }
      if (action === "restart") {
        const ok = typeof window !== "undefined"
          ? window.confirm(`Restart ${proto} endpoint ${ip}:${port} and clear collected response artifacts?`)
          : true;
        if (!ok) return Promise.resolve();
      }
      this.error = "";
      this.portActionLoading = { id: endpointId, action };
      return this.store
        .fetchJsonPromise("/port/action/", {
          method: "POST",
          body: JSON.stringify({
            id: endpointId,
            action,
            clean_results: action === "restart",
          }),
        })
        .then(() => this.refreshActiveProtocolRealtime())
        .catch((err) => {
          this.error = err.message || `Failed to ${action} packet endpoint`;
        })
        .finally(() => {
          this.portActionLoading = { id: null, action: "" };
        });
    },
  },
};
</script>

<style scoped>
.protocol-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  flex-wrap: wrap;
}

.protocol-toolbar__meta,
.protocol-toolbar__actions {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.row-actions {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
}

.ports-table-wrap {
  border-radius: 14px;
}

.ports-data-table :deep(.v-table__wrapper) {
  overflow: auto;
}

.ports-data-table :deep(table) {
  min-width: 100%;
}

.ports-data-table :deep(thead th) {
  position: sticky;
  top: 0;
  z-index: 2;
  backdrop-filter: blur(12px);
  background: rgba(8, 14, 22, 0.94);
}

.ports-data-table :deep(tbody td) {
  vertical-align: top;
  border-bottom: 1px solid rgba(99, 173, 219, 0.1);
}

.ports-data-table :deep(tbody tr:hover > td) {
  background: rgba(14, 23, 36, 0.88);
}

.ports-data-table :deep(.v-data-table__td--expanded-row) {
  width: 48px;
}

.ports-data-table__expand-header {
  display: inline-block;
  width: 18px;
}

.ports-data-table__expand-button {
  margin-inline-start: -4px;
}

.ports-data-table__expanded-row :deep(td) {
  padding: 0;
}

.ports-data-table__expanded-cell {
  background: rgba(6, 12, 22, 0.56);
}

.ports-json-panel {
  padding: 14px 16px;
  border-top: 1px solid rgba(99, 173, 219, 0.14);
  background: linear-gradient(180deg, rgba(11, 19, 31, 0.94), rgba(7, 13, 21, 0.88));
}

.ports-json-panel__label {
  margin-bottom: 10px;
  color: rgba(158, 196, 225, 0.8);
  font-size: 0.72rem;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}

.ports-json {
  margin: 0;
  max-height: 360px;
  overflow: auto;
  color: rgba(229, 241, 252, 0.96);
  font-family: var(--font-mono);
  font-size: 0.79rem;
  line-height: 1.6;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
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

.summary-cell {
  display: inline-block;
  max-width: 420px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
</style>
