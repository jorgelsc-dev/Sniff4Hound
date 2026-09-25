<template>
  <div class="ai-mode-controls">
    <div v-for="control in controls" :key="control.field" class="ai-mode-control">
      <div>
        <h3>{{ control.label }}</h3>
        <p>{{ control.description }}</p>
      </div>
      <v-switch
        :model-value="Boolean(config?.[control.field])"
        :aria-label="control.label"
        :loading="pending === control.field"
        :disabled="!config || Boolean(pending) || (control.field === 'ai_alert_mode_enabled' && !config.raw_retention_enabled && !config.ai_alert_mode_enabled)"
        color="success"
        hide-details
        inset
        @update:model-value="update(control.field, $event)"
      />
    </div>
    <v-alert v-if="error" type="error" variant="tonal" class="mt-3">{{ error }}</v-alert>
    <v-alert v-if="saved" type="success" variant="tonal" density="compact" class="mt-3">Configuración guardada.</v-alert>
  </div>
</template>

<script setup>
import { computed, ref } from "vue";
import store from "../../state/appStore";

const props = defineProps({
  config: { type: Object, default: null },
  storageOnly: { type: Boolean, default: false },
});
const emit = defineEmits(["updated"]);
const pending = ref("");
const error = ref("");
const saved = ref(false);
const controls = computed(() => [
  { field: "raw_retention_enabled", label: "Conservar bytes originales", description: "Guarda el paquete original para que el clasificador pueda analizarlo." },
  ...(props.storageOnly ? [] : [
    { field: "training_enabled", label: "Entrenamiento", description: "Aprendizaje automático y torneo de arquitecturas." },
    { field: "training_capture_enabled", label: "Captura de entrenamiento", description: "Conserva también tráfico limpio. Al desactivar se eliminan los paquetes guardados solo para entrenamiento." },
    { field: "ai_alert_mode_enabled", label: "Alertas por IA", description: "La IA decide las alertas cuando el entrenamiento está apagado. Requiere conservar los bytes originales." },
  ]),
]);

async function update(field, value) {
  if (pending.value) return;
  pending.value = field;
  error.value = "";
  saved.value = false;
  try {
    const result = await store.fetchJsonPromise("/api/ai/config", {
      method: "POST", body: JSON.stringify({ [field]: Boolean(value) }),
    });
    emit("updated", { ...props.config, ...result });
    saved.value = true;
  } catch (err) {
    error.value = err.message || "No se pudo guardar la configuración.";
  } finally {
    pending.value = "";
  }
}
</script>

<style scoped>
.ai-mode-control { display: flex; align-items: flex-start; gap: 20px; padding: 16px 0; border-bottom: 1px solid #363740; }
.ai-mode-control > div:first-child { flex: 1; min-width: 0; }
.ai-mode-control h3 { font-size: 14px; font-weight: 600; }
.ai-mode-control p { color: #a8aab6; font-size: 12px; line-height: 1.6; margin-top: 5px; }
.ai-mode-control .v-switch { flex: 0 0 auto; }
</style>
