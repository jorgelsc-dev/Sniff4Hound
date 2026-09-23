<template>
  <v-dialog :model-value="modelValue" max-width="720" @update:model-value="$emit('update:modelValue', $event)">
    <v-card v-if="monitor" rounded="xl" class="pa-2">
      <v-card-title class="d-flex align-center flex-wrap ga-2">
        <span class="text-h6">{{ monitor.name }}</span>
        <v-chip size="x-small" :color="monitor.source === 'builtin' ? 'secondary' : 'success'" variant="tonal">
          {{ monitor.source === "builtin" ? "Built-in" : "Custom" }}
        </v-chip>
        <v-chip size="x-small" color="primary" variant="tonal">{{ modeLabel(monitor.mode) }}</v-chip>
        <v-chip size="x-small" :color="severityColor(monitor.action && monitor.action.severity)" variant="tonal">
          {{ (monitor.action && monitor.action.severity) || "info" }}
        </v-chip>
        <v-chip size="x-small" :color="monitor.enabled ? 'success' : 'secondary'" variant="outlined">
          {{ monitor.enabled ? "Enabled" : "Disabled" }}
        </v-chip>
      </v-card-title>
      <v-card-text>
        <v-alert
          v-if="monitor.source === 'builtin'"
          type="info"
          variant="tonal"
          density="comfortable"
          class="mb-4"
        >
          This is a built-in default rule and is read-only. It can only be enabled or disabled from
          Settings → Detection.
        </v-alert>
        <p v-if="monitor.description" class="text-body-2 mb-4">{{ monitor.description }}</p>

        <div class="text-overline text-medium-emphasis mb-1">Match conditions</div>
        <div v-if="matchFields.length" class="rule-field-grid mb-4">
          <div v-for="field in matchFields" :key="`match-${field.key}`" class="rule-field">
            <div class="rule-field__label">{{ field.label }}</div>
            <div class="rule-field__value">{{ field.value }}</div>
          </div>
        </div>
        <p v-else class="text-body-2 text-medium-emphasis mb-4">No conditions configured.</p>

        <div class="text-overline text-medium-emphasis mb-1">Action</div>
        <div v-if="actionFields.length" class="rule-field-grid mb-4">
          <div v-for="field in actionFields" :key="`action-${field.key}`" class="rule-field">
            <div class="rule-field__label">{{ field.label }}</div>
            <div class="rule-field__value">{{ field.value }}</div>
          </div>
        </div>

        <div class="d-flex flex-wrap ga-4 text-caption text-medium-emphasis mb-2">
          <span>Priority: {{ monitor.priority ?? 100 }}</span>
          <span v-if="monitor.created_at">Created: {{ formatTimestamp(monitor.created_at) }}</span>
          <span v-if="monitor.updated_at">Updated: {{ formatTimestamp(monitor.updated_at) }}</span>
        </div>

        <v-expansion-panels variant="accordion" class="mt-2">
          <v-expansion-panel title="Raw rule JSON">
            <v-expansion-panel-text>
              <pre class="rule-json">{{ rawJson }}</pre>
            </v-expansion-panel-text>
          </v-expansion-panel>
        </v-expansion-panels>
      </v-card-text>
      <v-card-actions class="justify-end">
        <v-btn variant="text" @click="$emit('update:modelValue', false)">Close</v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>
</template>

<script>
function humanizeKey(key) {
  return String(key || "")
    .replace(/_/g, " ")
    .replace(/^./, (char) => char.toUpperCase());
}

function isEmptyValue(value) {
  if (value === null || value === undefined || value === "") return true;
  if (Array.isArray(value)) return value.length === 0;
  if (typeof value === "number") return value === 0;
  if (typeof value === "object") return Object.keys(value).length === 0;
  return false;
}

function formatValue(value) {
  if (Array.isArray(value)) {
    return value
      .map((entry) => (entry && typeof entry === "object" ? JSON.stringify(entry) : String(entry)))
      .join(", ");
  }
  if (value && typeof value === "object") return JSON.stringify(value);
  return String(value);
}

// Reads as "everything the rule comprises": any non-empty field on match/action
// is shown, without hardcoding the field list, so custom rule builder fields
// (payload_contains, ip_regex, exclude_*, nested AND/OR conditions, ...) show
// up the same way built-in fields do.
function fieldsFrom(source) {
  if (!source || typeof source !== "object") return [];
  return Object.keys(source)
    .filter((key) => !isEmptyValue(source[key]))
    .map((key) => ({ key, label: humanizeKey(key), value: formatValue(source[key]) }));
}

export default {
  name: "RuleDetailDialog",
  props: {
    modelValue: {
      type: Boolean,
      default: false,
    },
    monitor: {
      type: Object,
      default: null,
    },
  },
  emits: ["update:modelValue"],
  computed: {
    matchFields() {
      return fieldsFrom(this.monitor && this.monitor.match);
    },
    actionFields() {
      return fieldsFrom(this.monitor && this.monitor.action);
    },
    rawJson() {
      try {
        return JSON.stringify(this.monitor, null, 2);
      } catch {
        return "{}";
      }
    },
  },
  methods: {
    modeLabel(value) {
      const mode = String(value || "").trim().toLowerCase();
      if (mode === "regex") return "Regex";
      if (mode === "stateful") return "Stateful";
      return "Rule";
    },
    severityColor(value) {
      const severity = String(value || "info").trim().toLowerCase();
      if (severity === "critical" || severity === "high") return "error";
      if (severity === "medium") return "warning";
      if (severity === "low") return "info";
      return "secondary";
    },
    formatTimestamp(value) {
      const date = new Date(value);
      return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
    },
  },
};
</script>

<style scoped>
.rule-field-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
  gap: 10px 16px;
}

.rule-field__label {
  font-size: 0.72rem;
  font-weight: 700;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  color: rgba(158, 196, 225, 0.78);
}

.rule-field__value {
  font-size: 0.86rem;
  overflow-wrap: anywhere;
}

.rule-json {
  margin: 0;
  max-height: 320px;
  overflow: auto;
  font-family: var(--font-mono);
  font-size: 0.78rem;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}
</style>
