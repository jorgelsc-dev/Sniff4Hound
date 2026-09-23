<template>
  <span class="regex-helper-trigger">
    <v-btn
      icon="mdi-auto-fix"
      size="small"
      variant="text"
      color="info"
      density="comfortable"
      aria-label="Regex helper"
      @click="open"
    >
      <v-icon icon="mdi-auto-fix" />
      <v-tooltip activator="parent" location="top">Regex helper</v-tooltip>
    </v-btn>

    <v-dialog v-model="dialogOpen" max-width="640">
      <v-card class="pa-4 regex-helper-card">
        <div class="d-flex align-center justify-space-between mb-2">
          <div class="text-h6">Regex helper</div>
          <v-btn icon="mdi-close" size="small" variant="text" @click="dialogOpen = false" />
        </div>
        <div class="text-caption text-medium-emphasis mb-4">
          Build a pattern from common building blocks, then check it against a sample string before
          using it. Patterns run case-insensitively against the packet's decoded text.
        </div>

        <div class="text-subtitle-2 mb-1">Building blocks</div>
        <div class="d-flex flex-wrap ga-2 mb-4">
          <v-btn
            v-for="block in blocks"
            :key="block.label"
            size="small"
            variant="tonal"
            color="primary"
            @click="insertBlock(block)"
          >
            {{ block.label }}
          </v-btn>
        </div>

        <v-textarea
          v-model="working"
          label="Pattern"
          rows="2"
          auto-grow
          variant="outlined"
          density="comfortable"
          class="mono-field"
          :error-messages="patternError"
        />

        <v-text-field
          v-model="sample"
          label="Test string"
          hint="Paste a sample line of traffic to see whether the pattern above matches it"
          persistent-hint
          variant="outlined"
          density="comfortable"
          class="mt-2 mono-field"
        />

        <v-alert
          v-if="sample"
          :type="testResult.ok ? 'success' : 'warning'"
          variant="tonal"
          density="comfortable"
          class="mt-3"
        >
          {{ testResult.message }}
        </v-alert>

        <div class="text-caption text-medium-emphasis mt-4 mb-1">Cheat sheet</div>
        <div class="cheat-sheet">
          <div v-for="row in cheatSheet" :key="row.token" class="cheat-row">
            <code>{{ row.token }}</code>
            <span>{{ row.meaning }}</span>
          </div>
        </div>

        <v-card-actions class="px-0 mt-4">
          <v-spacer />
          <v-btn variant="text" @click="dialogOpen = false">Cancel</v-btn>
          <v-btn color="primary" variant="flat" :disabled="!canApply" @click="apply">
            Use this pattern
          </v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>
  </span>
</template>

<script>
// Reusable pattern-building assistant for every payload_regex-style input in
// the app (custom monitor regex, blacklist regex entries, ...). Deliberately
// standalone/dialog-based rather than baked into a single field component,
// so any existing text-field/combobox can drop in a trigger button next to
// it without restructuring its own v-model wiring - the parent decides what
// to do with the emitted pattern (set a single value, or push onto an array
// of patterns).
const BUILDING_BLOCKS = [
  { label: "Starts with...", snippet: "^" },
  { label: "Ends with...", snippet: "$" },
  { label: "Any characters", snippet: ".*" },
  { label: "One or more digits", snippet: "\\d+" },
  { label: "Word boundary", snippet: "\\b" },
  { label: "One of these (OR)", snippet: "(?:optionA|optionB)" },
  { label: "IP-address shaped", snippet: "\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}" },
  { label: "Domain-shaped", snippet: "[a-z0-9-]+\\.[a-z]{2,}" },
  { label: "Optional group", snippet: "(?:...)?" },
  { label: "Literal dot", snippet: "\\." },
];

const CHEAT_SHEET = [
  { token: ".", meaning: "any single character" },
  { token: "\\d", meaning: "a digit (0-9)" },
  { token: "\\w", meaning: "a letter, digit, or underscore" },
  { token: "\\s", meaning: "whitespace" },
  { token: "+", meaning: "one or more of the previous token" },
  { token: "*", meaning: "zero or more of the previous token" },
  { token: "?", meaning: "zero or one of the previous token (optional)" },
  { token: "{2,5}", meaning: "between 2 and 5 repeats" },
  { token: "(?:a|b)", meaning: "either a or b (non-capturing)" },
  { token: "^ / $", meaning: "start / end of the text" },
];

export default {
  name: "RegexHelperButton",
  props: {
    initialValue: {
      type: String,
      default: "",
    },
  },
  emits: ["apply"],
  data() {
    return {
      dialogOpen: false,
      working: "",
      sample: "",
      blocks: BUILDING_BLOCKS,
      cheatSheet: CHEAT_SHEET,
    };
  },
  computed: {
    patternError() {
      if (!this.working) return [];
      try {
        new RegExp(this.working, "i");
        return [];
      } catch (error) {
        return [`Invalid pattern: ${(error && error.message) || "syntax error"}`];
      }
    },
    canApply() {
      return Boolean(this.working.trim()) && this.patternError.length === 0;
    },
    testResult() {
      if (!this.sample) return { ok: false, message: "" };
      if (this.patternError.length) return { ok: false, message: "Fix the pattern above first." };
      try {
        const re = new RegExp(this.working, "i");
        const match = this.sample.match(re);
        if (match) {
          return { ok: true, message: `Matches: "${match[0]}"` };
        }
        return { ok: false, message: "No match against this test string." };
      } catch {
        return { ok: false, message: "Fix the pattern above first." };
      }
    },
  },
  methods: {
    open() {
      this.working = this.initialValue || "";
      this.sample = "";
      this.dialogOpen = true;
    },
    insertBlock(block) {
      this.working = `${this.working}${block.snippet}`;
    },
    apply() {
      if (!this.canApply) return;
      this.$emit("apply", this.working.trim());
      this.dialogOpen = false;
    },
  },
};
</script>

<style scoped>
.regex-helper-trigger {
  display: inline-flex;
}

.mono-field :deep(textarea),
.mono-field :deep(input) {
  font-family: "JetBrains Mono", "Fira Code", ui-monospace, monospace;
  font-size: 0.85rem;
}

.cheat-sheet {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
  gap: 4px 12px;
  font-size: 0.78rem;
}

.cheat-row {
  display: flex;
  align-items: baseline;
  gap: 8px;
  color: rgba(255, 255, 255, 0.68);
}

.cheat-row code {
  flex: 0 0 auto;
  padding: 1px 6px;
  border-radius: 6px;
  background: rgba(var(--brand-cyan-rgb), 0.14);
  color: rgba(var(--brand-cyan-rgb), 0.95);
  font-size: 0.76rem;
}
</style>
