<template>
  <span class="regex-helper-trigger">
    <v-btn
      icon="mdi-auto-fix"
      size="small"
      variant="text"
      color="info"
      density="comfortable"
      aria-label="Ayudante de regex"
      @click="open"
    >
      <v-icon icon="mdi-auto-fix" />
      <v-tooltip activator="parent" location="top">Ayudante de regex</v-tooltip>
    </v-btn>

    <v-dialog v-model="dialogOpen" max-width="640">
      <v-card class="pa-4 regex-helper-card">
        <div class="d-flex align-center justify-space-between mb-2">
          <div class="text-h6">Ayudante de regex</div>
          <v-btn icon="mdi-close" size="small" variant="text" @click="dialogOpen = false" />
        </div>
        <div class="text-caption text-medium-emphasis mb-4">
          Construye un patrón con bloques comunes y pruébalo con una muestra antes de usarlo.
          Los patrones se evalúan sin distinguir mayúsculas en el texto decodificado del paquete.
        </div>

        <div class="text-subtitle-2 mb-1">Bloques</div>
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
          label="Patrón"
          rows="2"
          auto-grow
          variant="outlined"
          density="comfortable"
          class="mono-field"
          :error-messages="patternError"
        />

        <v-text-field
          v-model="sample"
          label="Texto de prueba"
          hint="Pega una línea de tráfico para comprobar si coincide con el patrón"
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

        <div class="text-caption text-medium-emphasis mt-4 mb-1">Referencia rápida</div>
        <div class="cheat-sheet">
          <div v-for="row in cheatSheet" :key="row.token" class="cheat-row">
            <code>{{ row.token }}</code>
            <span>{{ row.meaning }}</span>
          </div>
        </div>

        <v-card-actions class="px-0 mt-4">
          <v-spacer />
          <v-btn variant="text" @click="dialogOpen = false">Cancelar</v-btn>
          <v-btn color="primary" variant="flat" :disabled="!canApply" @click="apply">
            Usar patrón
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
  { label: "Empieza con...", snippet: "^" },
  { label: "Termina con...", snippet: "$" },
  { label: "Cualquier texto", snippet: ".*" },
  { label: "Uno o más dígitos", snippet: "\\d+" },
  { label: "Límite de palabra", snippet: "\\b" },
  { label: "Una opción (OR)", snippet: "(?:opcionA|opcionB)" },
  { label: "Forma de IP", snippet: "\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}" },
  { label: "Forma de dominio", snippet: "[a-z0-9-]+\\.[a-z]{2,}" },
  { label: "Grupo opcional", snippet: "(?:...)?" },
  { label: "Punto literal", snippet: "\\." },
];

const CHEAT_SHEET = [
  { token: ".", meaning: "cualquier carácter" },
  { token: "\\d", meaning: "un dígito (0-9)" },
  { token: "\\w", meaning: "letra, dígito o guion bajo" },
  { token: "\\s", meaning: "espacio en blanco" },
  { token: "+", meaning: "uno o más del token anterior" },
  { token: "*", meaning: "cero o más del token anterior" },
  { token: "?", meaning: "cero o uno del token anterior" },
  { token: "{2,5}", meaning: "entre 2 y 5 repeticiones" },
  { token: "(?:a|b)", meaning: "a o b, sin capturar" },
  { token: "^ / $", meaning: "inicio / fin del texto" },
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
        return [`Patrón inválido: ${(error && error.message) || "error de sintaxis"}`];
      }
    },
    canApply() {
      return Boolean(this.working.trim()) && this.patternError.length === 0;
    },
    testResult() {
      if (!this.sample) return { ok: false, message: "" };
      if (this.patternError.length) return { ok: false, message: "Corrige primero el patrón." };
      try {
        const re = new RegExp(this.working, "i");
        const match = this.sample.match(re);
        if (match) {
          return { ok: true, message: `Coincide con: "${match[0]}"` };
        }
        return { ok: false, message: "No coincide con este texto de prueba." };
      } catch {
        return { ok: false, message: "Corrige primero el patrón." };
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
