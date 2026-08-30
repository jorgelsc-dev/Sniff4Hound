<template>
  <div class="clear-data-button">
    <v-btn
      :size="size"
      :variant="variant"
      color="error"
      prepend-icon="mdi-database-remove-outline"
      :disabled="busy"
      @click="open"
    >
      {{ label }}
      <v-tooltip activator="parent" location="bottom">
        Delete every packet, flow and honeypot event. Monitors, listeners and settings survive.
      </v-tooltip>
    </v-btn>

    <v-dialog v-model="dialog" max-width="520">
      <v-card class="pa-4">
        <div class="d-flex align-center ga-2 mb-3">
          <v-icon icon="mdi-alert-outline" color="error" />
          <span class="text-h6">Clear all captured data?</span>
        </div>

        <div class="text-body-2 mb-3">
          This deletes everything capture and the honeypot have recorded, then compacts the
          database file on disk. It cannot be undone.
        </div>

        <div class="clear-data-button__lists mb-3">
          <div class="clear-data-button__list clear-data-button__list--removed">
            <div class="text-caption font-weight-medium text-error mb-1">
              <v-icon icon="mdi-close-circle-outline" size="x-small" class="mr-1" />Deleted
            </div>
            <ul class="text-caption text-medium-emphasis">
              <li v-for="item in removedItems" :key="`removed-${item}`">{{ item }}</li>
            </ul>
          </div>
          <div class="clear-data-button__list clear-data-button__list--kept">
            <div class="text-caption font-weight-medium text-success mb-1">
              <v-icon icon="mdi-check-circle-outline" size="x-small" class="mr-1" />Kept
            </div>
            <ul class="text-caption text-medium-emphasis">
              <li v-for="item in keptItems" :key="`kept-${item}`">{{ item }}</li>
            </ul>
          </div>
        </div>

        <v-alert v-if="runtimeRunning" type="info" variant="tonal" density="compact" class="mb-3">
          {{ runtimeLabel }} is still running, so new rows start arriving again immediately.
          Stop it first for a clean slate.
        </v-alert>

        <div v-if="busy" class="mb-3">
          <div class="d-flex justify-space-between text-caption text-medium-emphasis mb-1">
            <span>{{ progressLabel }}</span>
            <span v-if="progressPercent !== null">{{ progressPercent }}%</span>
          </div>
          <v-progress-linear
            :model-value="progressPercent ?? undefined"
            :indeterminate="progressPercent === null"
            color="error"
            height="6"
            rounded
          />
        </div>

        <v-alert v-if="error" type="error" variant="tonal" density="compact" class="mb-3">
          {{ error }}
        </v-alert>

        <div class="d-flex justify-end ga-2">
          <v-btn variant="text" :disabled="busy" @click="dialog = false">Cancel</v-btn>
          <v-btn color="error" variant="flat" :loading="busy" @click="confirm">
            Delete everything
          </v-btn>
        </div>
      </v-card>
    </v-dialog>
  </div>
</template>

<script>
import store from "../../state/appStore";

// Mirrors SniffStore.CAPTURE_DATA_TABLES plus the honeypot's own event
// database: the operator has to be able to see, before confirming, that the
// catalogs they configured by hand are not part of the purge.
const REMOVED_ITEMS = [
  "Packets, tags and payloads",
  "Flows, domains and paths",
  "Capture sessions and counters",
  "Honeypot connection, TLS and DNS events",
];

const KEPT_ITEMS = [
  "Monitor definitions and rulesets",
  "Honeypot listener configuration",
  "Whitelist and blacklist entries",
  "Interface selection and settings",
];

export default {
  name: "ClearDataButton",
  props: {
    label: {
      type: String,
      default: "Clear data",
    },
    size: {
      type: String,
      default: "small",
    },
    variant: {
      type: String,
      default: "outlined",
    },
  },
  emits: ["cleared"],
  data() {
    return {
      store,
      dialog: false,
      busy: false,
      error: "",
    };
  },
  computed: {
    // `running` lives on the active engine's own block, not on the runtime
    // payload's top level - see /api/runtime/'s {mode, active:{running,...}}.
    runtimeRunning() {
      const runtime = this.store.state.runtime || {};
      const active = runtime.active && typeof runtime.active === "object" ? runtime.active : {};
      return Boolean(active.running);
    },
    runtimeLabel() {
      const mode = String((this.store.state.runtime || {}).mode || "").trim().toLowerCase();
      return mode === "honeypot" ? "The honeypot" : "The sniffer";
    },
    removedItems() {
      return REMOVED_ITEMS;
    },
    keptItems() {
      return KEPT_ITEMS;
    },
    // Rides the "data_clear_progress" WS frames the backend broadcasts
    // while purge_capture_data() works through the capture tables and then
    // compacts the freed pages - see clear_detections_api. Null (and so an
    // indeterminate bar) until the first frame arrives or once a phase
    // this component doesn't recognize shows up.
    progress() {
      return this.store.state.dataClearProgress;
    },
    progressPercent() {
      const progress = this.progress;
      if (!progress) return null;
      if (progress.phase === "deleting") {
        const total = Number(progress.rows_total) || 0;
        if (total <= 0) return null;
        const done = Number(progress.rows_done) || 0;
        return Math.max(0, Math.min(100, Math.round((done / total) * 100)));
      }
      if (progress.phase === "compacting") {
        const total = Number(progress.pages_total) || 0;
        if (total <= 0) return null;
        const done = Number(progress.pages_done) || 0;
        return Math.max(0, Math.min(100, Math.round((done / total) * 100)));
      }
      if (progress.phase === "done") return 100;
      return null;
    },
    progressLabel() {
      const progress = this.progress;
      if (!progress) return "Deleting...";
      if (progress.phase === "deleting") {
        const done = Number(progress.rows_done) || 0;
        const total = Number(progress.rows_total) || 0;
        return total ? `Deleting rows... (${done.toLocaleString()} / ${total.toLocaleString()})` : "Deleting rows...";
      }
      if (progress.phase === "compacting") {
        return "Compacting database file...";
      }
      return "Finishing up...";
    },
  },
  methods: {
    open() {
      this.error = "";
      this.store.state.dataClearProgress = null;
      this.dialog = true;
    },
    // The endpoint answers with {table: count}, except honeypot_events which
    // is itself a {table: count} map - flatten both shapes into one total so
    // a nested dict is not silently counted as zero.
    countDeleted(payload) {
      if (!payload || typeof payload !== "object") return 0;
      return Object.values(payload).reduce((total, value) => {
        if (value && typeof value === "object") return total + this.countDeleted(value);
        const count = Number(value);
        return Number.isFinite(count) && count > 0 ? total + count : total;
      }, 0);
    },
    confirm() {
      if (this.busy) return;
      this.busy = true;
      this.error = "";
      this.store
        .clearDetections("everything")
        .then((payload) => {
          const deleted = this.countDeleted(payload);
          this.store.pushNotification({
            kind: "data",
            severity: "info",
            title: "Stored data cleared",
            message: deleted
              ? `Deleted ${deleted.toLocaleString()} rows. Monitors, listeners and settings were kept.`
              : "There was nothing left to delete.",
            groupKey: "data:cleared",
          });
          this.dialog = false;
          this.store.initRuntime();
          this.$emit("cleared", payload);
        })
        .catch((err) => {
          this.error = (err && err.message) || "Failed to clear stored data";
        })
        .finally(() => {
          this.busy = false;
          this.store.state.dataClearProgress = null;
        });
    },
  },
};
</script>

<style scoped>
.clear-data-button__lists {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 12px;
}

.clear-data-button__list {
  border-radius: 8px;
  padding: 10px 12px;
  border: 1px solid rgba(var(--v-border-color), 0.16);
}

.clear-data-button__list ul {
  padding-left: 16px;
  margin: 0;
}
</style>
