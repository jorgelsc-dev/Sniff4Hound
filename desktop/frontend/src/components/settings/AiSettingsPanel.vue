<template>
  <div class="ai-settings">
    <v-progress-linear v-if="loading" indeterminate color="primary" aria-label="Cargando IA" />
    <v-alert v-if="error" type="error" variant="tonal" class="mb-3">{{ error }}</v-alert>
    <AiModeControls :config="config" @updated="applyConfig" />
    <div v-if="learning" class="ai-learning-status">
      <span>{{ learning.training?.updates || 0 }} actualizaciones</span>
      <span>{{ learning.total || 0 }} ejemplos</span>
    </div>
    <NeuralNetworkConfigPanel
      v-if="config"
      :learning-config="config.learning_config"
      :effectiveness="learning?.effectiveness"
      :suggestion="suggestion"
      @config-saved="applyLearningConfig"
      @reload-requested="load"
    />
  </div>
</template>

<script setup>
import { onMounted, ref } from "vue";
import store from "../../state/appStore";
import AiModeControls from "./AiModeControls.vue";
import NeuralNetworkConfigPanel from "../ai/NeuralNetworkConfigPanel.vue";

const emit = defineEmits(["updated"]);
const config = ref(null);
const learning = ref(null);
const suggestion = ref({ architecture: null, cohort: null });
const loading = ref(false);
const error = ref("");

function applyConfig(value) {
  config.value = value;
  emit("updated");
}
function applyLearningConfig(value) {
  config.value = { ...config.value, learning_config: value };
  emit("updated");
}
async function load() {
  loading.value = true;
  error.value = "";
  const results = await Promise.allSettled([
    store.fetchJsonPromise("/api/ai/config"),
    store.fetchJsonPromise("/api/ai/packets/?threshold=50", {}, { preferHttp: true }),
  ]);
  if (results[0].status === "fulfilled") config.value = results[0].value;
  else error.value = results[0].reason.message || "No se pudo cargar la configuración.";
  if (results[1].status === "fulfilled") {
    learning.value = results[1].value.learning || null;
    suggestion.value = results[1].value.learning_suggestion || { architecture: null, cohort: null };
  }
  loading.value = false;
}
onMounted(load);
</script>

<style scoped>
.ai-learning-status { display: flex; gap: 16px; flex-wrap: wrap; font-size: 12px; color: #a8aab6; padding: 20px 0; }
.ai-settings :deep(.v-card) { background: transparent; border: 0; box-shadow: none; padding: 0 !important; border-radius: 0; }
.ai-settings :deep(.text-h6) { font-size: 16px !important; letter-spacing: 0 !important; }
</style>
