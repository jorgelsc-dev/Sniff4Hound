<template>
  <div>
    <ViewHeader
      overline="Sessions"
      title="Session Control"
      description="Define capture scopes or listener profiles and control each runtime session."
      :refresh-loading="loading"
      @refresh="load"
    />

    <DataPanel
      title="Create Session"
      subtitle="Add a network scope or honeypot listener profile."
      :error="createError"
      :show-refresh="false"
      class="mb-6"
    >
      <v-form @submit.prevent="createTarget">
        <v-row dense>
          <v-col cols="12" md="4">
            <v-text-field
              v-model="form.network"
              label="CIDR network"
              name="target_network"
              placeholder="10.0.0.0/24"
              :disabled="creating || loading"
              variant="outlined"
              density="comfortable"
            />
          </v-col>
          <v-col cols="12" md="2">
            <v-select
              v-model="form.proto"
              :items="protos"
              label="Proto"
              name="target_proto"
              :disabled="creating || loading"
              variant="outlined"
              density="comfortable"
            />
          </v-col>
          <v-col cols="12" md="2">
            <v-select
              v-model="form.port_mode"
              :items="portModes"
              label="Listener mode"
              name="target_port_mode"
              item-title="label"
              item-value="value"
              :disabled="creating || loading"
              variant="outlined"
              density="comfortable"
            />
          </v-col>
          <v-col cols="12" md="2">
            <v-select
              v-model="form.type"
              :items="types"
              label="Template type"
              name="target_type"
              :disabled="creating || loading || form.port_mode !== 'preset'"
              variant="outlined"
              density="comfortable"
            />
          </v-col>
          <v-col cols="12" md="2">
            <v-text-field
              v-model.number="form.timesleep"
              label="Timesleep"
              name="target_timesleep"
              type="number"
              step="0.1"
              min="0"
              :disabled="creating || loading"
              variant="outlined"
              density="comfortable"
            />
          </v-col>
        </v-row>
        <v-row dense>
          <v-col v-if="form.port_mode === 'single'" cols="12" md="2">
            <v-text-field
              v-model.number="form.port_single"
              label="Port"
              name="target_port_single"
              type="number"
              min="1"
              max="65535"
              :disabled="creating || loading"
              variant="outlined"
              density="comfortable"
            />
          </v-col>
          <v-col v-if="form.port_mode === 'range'" cols="12" md="2">
            <v-text-field
              v-model.number="form.port_start"
              label="Port start"
              name="target_port_start"
              type="number"
              min="1"
              max="65535"
              :disabled="creating || loading"
              variant="outlined"
              density="comfortable"
            />
          </v-col>
          <v-col v-if="form.port_mode === 'range'" cols="12" md="2">
            <v-text-field
              v-model.number="form.port_end"
              label="Port end"
              name="target_port_end"
              type="number"
              min="1"
              max="65535"
              :disabled="creating || loading"
              variant="outlined"
              density="comfortable"
            />
          </v-col>
          <v-col cols="12" md="2" class="d-flex align-center">
            <v-btn
              color="primary"
              variant="flat"
              type="submit"
              :disabled="creating || loading"
            >
              Add
            </v-btn>
          </v-col>
        </v-row>
      </v-form>
    </DataPanel>

    <v-row dense class="mb-4">
      <v-col cols="12" md="5">
        <v-text-field
          v-model.trim="tableFilters.query"
          label="Search sessions"
          name="target_table_search"
          placeholder="IP, network, protocol, port..."
          prepend-inner-icon="mdi-magnify"
          clearable
          variant="outlined"
          density="comfortable"
        />
      </v-col>
      <v-col cols="12" md="2">
        <v-select
          v-model="tableFilters.proto"
          :items="targetProtoFilterOptions"
          label="Proto"
          name="target_table_proto_filter"
          item-title="label"
          item-value="value"
          clearable
          variant="outlined"
          density="comfortable"
        />
      </v-col>
      <v-col cols="12" md="2">
        <v-select
          v-model="tableFilters.status"
          :items="targetStatusFilterOptions"
          label="Status"
          name="target_table_status_filter"
          item-title="label"
          item-value="value"
          clearable
          variant="outlined"
          density="comfortable"
        />
      </v-col>
      <v-col cols="12" md="3">
        <v-select
          v-model="tableFilters.portMode"
          :items="targetPortModeFilterOptions"
          label="Listener mode"
          name="target_table_mode_filter"
          item-title="label"
          item-value="value"
          clearable
          variant="outlined"
          density="comfortable"
        />
      </v-col>
    </v-row>

    <EntityTablePanel
      title="Active Sessions"
      subtitle="Manage each session with start/restart/stop/delete controls."
      :rows="filteredTargets"
      :columns="columns"
      :loading="loading"
      :error="error"
      :last-updated="lastUpdated"
      :live-refresh="true"
      empty-text="No sessions registered"
      @refresh="load"
    >
      <template #cell-progress="{ value }">
        <ProgressCell :value="value" />
      </template>

      <template #cell-port_scope="{ item }">
        <span>{{ formatPortScope(item) }}</span>
      </template>

      <template #cell-status="{ value }">
        <v-chip size="small" :color="statusColor(value)" variant="tonal">
          {{ normalizeStatus(value) }}
        </v-chip>
      </template>

      <template #cell-actions="{ item }">
        <div class="target-actions">
          <v-btn
            size="x-small"
            color="success"
            variant="tonal"
            :disabled="loading || creating || isActionLoading(item.id, 'start') || normalizeStatus(item.status) === 'active'"
            @click="runTargetAction(item, 'start')"
          >
            Start
          </v-btn>
          <v-btn
            size="x-small"
            color="info"
            variant="tonal"
            :disabled="loading || creating || isActionLoading(item.id, 'restart')"
            @click="runTargetAction(item, 'restart')"
          >
            Restart
          </v-btn>
          <v-btn
            size="x-small"
            color="warning"
            variant="tonal"
            :disabled="loading || creating || isActionLoading(item.id, 'stop') || normalizeStatus(item.status) === 'stopped'"
            @click="runTargetAction(item, 'stop')"
          >
            Stop
          </v-btn>
          <v-btn
            size="x-small"
            color="error"
            variant="tonal"
            :disabled="loading || creating || isActionLoading(item.id, 'delete')"
            @click="runTargetAction(item, 'delete')"
          >
            Delete
          </v-btn>
        </div>
      </template>
    </EntityTablePanel>
  </div>
</template>

<script>
import store from "../state/appStore";
import ViewHeader from "../components/ui/ViewHeader.vue";
import DataPanel from "../components/ui/DataPanel.vue";
import EntityTablePanel from "../components/ui/EntityTablePanel.vue";
import ProgressCell from "../components/ui/ProgressCell.vue";
import {
  hasOptionValue,
  matchesSearch,
  uniqueSorted,
} from "../utils/traffic";

export default {
  name: "TargetsView",
  components: {
    ViewHeader,
    DataPanel,
    EntityTablePanel,
    ProgressCell,
  },
  data() {
    return {
      store,
      loading: false,
      error: "",
      createError: "",
      creating: false,
      lastUpdated: "",
      targets: [],
      columns: [
        { key: "id", label: "ID" },
        { key: "network", label: "Network" },
        { key: "type", label: "Type" },
        { key: "proto", label: "Proto" },
        { key: "port_scope", label: "Scope" },
        { key: "status", label: "Status" },
        { key: "progress", label: "Progress" },
        { key: "timesleep", label: "Timesleep" },
        { key: "actions", label: "Actions" },
      ],
      types: ["common", "not_common", "full"],
      portModes: [
        { label: "Preset", value: "preset" },
        { label: "Single", value: "single" },
        { label: "Range", value: "range" },
      ],
      protos: [],
      form: {
        network: "",
        type: "common",
        proto: "tcp",
        port_mode: "preset",
        port_single: 80,
        port_start: 1,
        port_end: 1024,
        timesleep: 0.5,
      },
      actionLoading: {
        id: null,
        action: "",
      },
      tableFilters: {
        query: "",
        proto: "",
        status: "",
        portMode: "",
      },
    };
  },
  computed: {
    apiBase() {
      return this.store.state.apiBase;
    },
    targetProtoFilterOptions() {
      const values = uniqueSorted(
        this.targets.map((item) => String(item.proto || "").trim().toLowerCase())
      );
      return [{ label: "All", value: "" }, ...values.map((value) => ({ label: value.toUpperCase(), value }))];
    },
    targetStatusFilterOptions() {
      const values = uniqueSorted(this.targets.map((item) => this.normalizeStatus(item.status)));
      return [{ label: "All", value: "" }, ...values.map((value) => ({ label: value, value }))];
    },
    targetPortModeFilterOptions() {
      const values = uniqueSorted(this.targets.map((item) => this.normalizePortMode(item.port_mode)));
      return [{ label: "All", value: "" }, ...values.map((value) => ({ label: value, value }))];
    },
    filteredTargets() {
      const query = String(this.tableFilters.query || "").trim();
      const proto = String(this.tableFilters.proto || "").trim().toLowerCase();
      const status = String(this.tableFilters.status || "").trim().toLowerCase();
      const portMode = String(this.tableFilters.portMode || "").trim().toLowerCase();
      return this.targets.filter((item) => {
        if (proto && String(item.proto || "").trim().toLowerCase() !== proto) return false;
        if (status && this.normalizeStatus(item.status) !== status) return false;
        if (portMode && this.normalizePortMode(item.port_mode) !== portMode) return false;
        return matchesSearch(query, [
          item.id,
          item.network,
          item.type,
          item.proto,
          this.normalizeStatus(item.status),
          this.normalizePortMode(item.port_mode),
          this.formatPortScope(item),
          item.port_start,
          item.port_end,
          item.timesleep,
          item.agent_mode,
          item.agent_id,
        ]);
      });
    },
  },
  watch: {
    apiBase() {
      this.load();
    },
  },
  mounted() {
    this.load();
  },
  methods: {
    syncFilters() {
      if (!hasOptionValue(this.targetProtoFilterOptions, this.tableFilters.proto)) {
        this.tableFilters.proto = "";
      }
      if (!hasOptionValue(this.targetStatusFilterOptions, this.tableFilters.status)) {
        this.tableFilters.status = "";
      }
      if (!hasOptionValue(this.targetPortModeFilterOptions, this.tableFilters.portMode)) {
        this.tableFilters.portMode = "";
      }
    },
    normalizeStatus(value) {
      const raw = String(value || "active").trim().toLowerCase();
      if (raw === "restarting") return "restarting";
      if (raw === "stopped") return "stopped";
      return "active";
    },
    statusColor(value) {
      const status = this.normalizeStatus(value);
      if (status === "active") return "success";
      if (status === "restarting") return "info";
      return "warning";
    },
    normalizePortMode(value) {
      const mode = String(value || "preset").trim().toLowerCase();
      if (mode === "single") return "single";
      if (mode === "range") return "range";
      return "preset";
    },
    formatPortScope(item) {
      const mode = this.normalizePortMode(item && item.port_mode);
      const start = Number(item && item.port_start);
      const end = Number(item && item.port_end);
      if (mode === "single" && Number.isFinite(start) && start > 0) {
        return `single:${start}`;
      }
      if (
        mode === "range" &&
        Number.isFinite(start) &&
        Number.isFinite(end) &&
        start > 0 &&
        end > 0
      ) {
        return `range:${start}-${end}`;
      }
      return String(item && item.type ? item.type : "preset");
    },
    parsePort(value, label) {
      const port = Number(value);
      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        throw new Error(`${label} must be between 1 and 65535`);
      }
      return port;
    },
    buildCreatePayload() {
      const mode = this.normalizePortMode(this.form.port_mode);
      const payload = {
        network: this.form.network,
        type: this.form.type,
        proto: this.form.proto,
        timesleep: this.form.timesleep,
        port_mode: mode,
      };
      if (mode === "single") {
        const port = this.parsePort(this.form.port_single, "Port");
        payload.type = "full";
        payload.port_start = port;
        payload.port_end = port;
      } else if (mode === "range") {
        const start = this.parsePort(this.form.port_start, "Port start");
        const end = this.parsePort(this.form.port_end, "Port end");
        if (start > end) {
          throw new Error("Port start must be <= Port end");
        }
        payload.type = "full";
        payload.port_start = start;
        payload.port_end = end;
      }
      payload.agent_mode = "local";
      payload.agent_id = "local";
      return payload;
    },
    isActionLoading(id, action) {
      return this.actionLoading.id === id && this.actionLoading.action === action;
    },
    normalizeProtocols(raw) {
      const items = this.store.extractArray(raw);
      const unique = [...new Set(items.map((item) => String(item).trim().toLowerCase()))];
      return unique.filter(Boolean);
    },
    load() {
      this.loading = true;
      this.error = "";
      return Promise.all([
        this.store.fetchJsonPromise("/targets/"),
        this.store.fetchJsonPromise("/protocols/"),
      ])
        .then(([targetsRes, protocolsRes]) => {
          this.targets = this.store.extractArray(targetsRes);
          this.protos = this.normalizeProtocols(protocolsRes);
          if (!this.protos.length) {
            this.protos = ["tcp", "udp", "icmp", "sctp"];
          }
          if (!this.protos.includes(this.form.proto)) {
            this.form.proto = this.protos[0];
          }
          this.syncFilters();
          this.lastUpdated = new Date().toLocaleTimeString();
        })
        .catch((err) => {
          this.targets = [];
          this.protos = ["tcp", "udp", "icmp", "sctp"];
          if (!this.protos.includes(this.form.proto)) {
            this.form.proto = this.protos[0];
          }
          this.syncFilters();
          this.lastUpdated = "";
          this.error = err.message || "Failed to load sessions";
        })
        .finally(() => {
          this.loading = false;
        });
    },
    createTarget() {
      this.createError = "";
      this.creating = true;
      let payload;
      try {
        payload = this.buildCreatePayload();
      } catch (err) {
        this.creating = false;
        this.createError = err.message || "Invalid session payload";
        return Promise.resolve();
      }
      return this.store
        .fetchJsonPromise("/target/", {
          method: "POST",
          body: JSON.stringify(payload),
        })
        .then(() => this.load())
        .catch((err) => {
          this.createError = err.message || "Failed to create session";
        })
        .finally(() => {
          this.creating = false;
        });
    },
    runTargetAction(item, action) {
      const targetId = Number(item && item.id);
      if (!Number.isFinite(targetId) || targetId <= 0) {
        this.error = "Invalid session id";
        return Promise.resolve();
      }

      if (action === "delete") {
        const ok = typeof window !== "undefined"
          ? window.confirm(`Delete session #${targetId}?`)
          : true;
        if (!ok) return Promise.resolve();
      }

      if (action === "restart") {
        const ok = typeof window !== "undefined"
          ? window.confirm(`Restart session #${targetId} and clear previous results?`)
          : true;
        if (!ok) return Promise.resolve();
      }

      this.error = "";
      this.actionLoading.id = targetId;
      this.actionLoading.action = action;

      const payload = {
        id: targetId,
        action,
        clean_results: action === "restart" || action === "delete",
      };

      return this.store
        .fetchJsonPromise("/target/action/", {
          method: "POST",
          body: JSON.stringify(payload),
        })
        .then(() => this.load())
        .catch((err) => {
          this.error = err.message || `Failed to ${action} session`;
        })
        .finally(() => {
          this.actionLoading.id = null;
          this.actionLoading.action = "";
        });
    },
  },
};
</script>

<style scoped>
.target-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}
</style>
