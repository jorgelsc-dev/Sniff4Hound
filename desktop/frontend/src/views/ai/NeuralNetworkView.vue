<template>
  <div class="rnn-stage" :class="{ 'rnn-stage--tournament': showTournament }">
    <TournamentPanel
      v-if="showTournament"
      :tournament="tournament"
      :feature-count="learning.feature_names.length"
    />
    <NeuralGraph
      v-else-if="learning"
      immersive
      :learning="learning"
      :packet="selectedPacket"
      :learning-config="learningConfig"
      :effectiveness="learning?.effectiveness"
      :suggestion="suggestion"
      @config-saved="handleConfigSaved"
      @reload-requested="load"
    >
      <template #hud-extra>
        <div class="d-flex flex-wrap align-center ga-2 mt-2">
          <v-chip size="x-small" :color="streamStatus === 'En vivo' ? 'success' : 'warning'">{{ streamStatus }}</v-chip>
          <span class="text-caption text-medium-emphasis">{{ trainingModeLabel }} · {{ learning.training?.samples_seen || 0 }} muestras</span>
        </div>
        <v-btn size="x-small" variant="text" class="mt-1 pl-0" to="/ai/overview">Ver galería y revisiones →</v-btn>
      </template>
    </NeuralGraph>
    <div v-else class="rnn-stage__empty">
      <v-progress-circular indeterminate color="primary" size="28" class="mb-3" />
      <div>{{ error || "Conectando con el motor de IA..." }}</div>
    </div>

    <div v-if="learning" class="rnn-charts">
      <LearningProgressPanel :learning="learning" :suggestion="suggestion" :tournament="tournament" />
    </div>
  </div>
</template>

<script setup>
import { computed, onBeforeUnmount, onMounted, ref } from "vue";
import LearningProgressPanel from "../../components/ai/LearningProgressPanel.vue";
import TournamentPanel from "../../components/ai/TournamentPanel.vue";
import NeuralGraph from "../../components/NeuralGraph.vue";
import store from "../../state/appStore";

const result = ref({ rows: [], learning: null, learning_config: null });
const learning = computed(() => result.value.learning);
const learningConfig = computed(() => result.value.learning_config);
const suggestion = computed(() => result.value.learning_suggestion || { architecture: null, cohort: null });
const selectedPacket = computed(() => result.value.rows?.[0] || null);
const tournament = computed(() => result.value.ai_tournament || { active: false, round: 0, candidates: [], champion: null, rounds_history: [], stop_reason: null });
// Stays on the tournament view through its last round even after `active`
// flips false, so the operator sees which candidate won (and which got
// disqualified) instead of the view silently swapping back to the single
// production graph the instant training stops.
const showTournament = computed(() => tournament.value.active || tournament.value.candidates.length > 0);
const error = ref("");
const streamStatus = ref("Conectando");
let lastReceived = 0;
let disposed = false;
let feed = null;
let fallbackTimer = null;
let staleTimer = null;

const trainingModeLabel = computed(() => {
  const mode = learning.value?.training?.mode;
  if (mode === "imported") return "Modelo importado";
  if (mode === "full_retrain_on_config_change") return "Reentrenando forma";
  return "Aprendizaje incremental";
});

function handleConfigSaved(config) {
  result.value.learning_config = config;
}

function applySnapshot(snapshot) {
  if (disposed || !snapshot) return;
  if ((snapshot.learning?.revision ?? 0) < (result.value.learning?.revision ?? 0)) return;
  result.value = snapshot;
  lastReceived = Date.now();
  error.value = "";
}

function openFeed() {
  feed?.close();
  streamStatus.value = "Conectando";
  feed = store.openDataFeed("ai", { threshold: 50, refresh: 5000 }, (payload) => {
    if (disposed) return;
    if (payload.type === "feed_error") { error.value = payload.message; streamStatus.value = "Error de actualización"; return; }
    if (payload.type !== "feed_data") return;
    applySnapshot(payload.data);
    streamStatus.value = "En vivo";
  }, () => { if (!disposed) streamStatus.value = "Reconectando · respaldo HTTP"; });
}

async function load() {
  try {
    const snapshot = await store.fetchJsonPromise("/api/ai/packets/?threshold=50", {}, { preferHttp: true });
    if (disposed) return;
    applySnapshot(snapshot);
    if (streamStatus.value !== "En vivo") streamStatus.value = "Respaldo HTTP";
  } catch (err) {
    error.value = err.message || "No se pudo conectar con el motor de IA.";
  }
}

onMounted(() => {
  load();
  openFeed();
  fallbackTimer = setInterval(() => { if (Date.now() - lastReceived > 10000) load(); }, 5000);
  staleTimer = setInterval(() => { if (lastReceived && Date.now() - lastReceived > 12000) streamStatus.value = "Datos desactualizados"; }, 1000);
});
onBeforeUnmount(() => {
  disposed = true;
  feed?.close();
  clearInterval(fallbackTimer);
  clearInterval(staleTimer);
});
</script>

<style scoped>
.rnn-stage {
  position: relative;

  height: var(--app-canvas-height);
  width: 100%;
  overflow: hidden;
  background: var(--bg-0);
  box-sizing: border-box;
}
.rnn-stage__empty {
  position: absolute;
  inset: 0;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  color: var(--text-dim);
}
/* The production graph reserves HUD space; the scrollable tournament uses
   its own chart row so the cards and final result cannot be covered. */
.rnn-charts {
  position: absolute;
  right: 16px;
  bottom: 16px;
  z-index: 6;
  width: min(340px, calc(50% - 24px));
  max-height: 232px;
  overflow-y: auto;
  scrollbar-width: thin;
  background: transparent;
  backdrop-filter: blur(4px);
  border-radius: 8px;
  padding: 8px 10px;
}
.rnn-stage--tournament {
  display: grid;
  grid-template-rows: minmax(0, 1fr) auto;
}
.rnn-stage--tournament .rnn-charts {
  position: relative;
  inset: auto;
  width: 100%;
  max-height: min(30dvh, 180px);
  padding: 12px var(--app-gutter);
  border-top: 1px solid var(--stroke);
  border-radius: 0;
  background: var(--surface-0);
  backdrop-filter: none;
}
@media (max-width: 800px) {
  .rnn-charts { left: 8px; right: 8px; width: auto; bottom: 216px; max-height: 108px; }
}
@media (max-height: 720px) {
  .rnn-charts { max-height: 180px; }
}
@media (max-width: 800px) and (max-height: 720px) {
  .rnn-charts { bottom: 136px; max-height: 76px; }
}
</style>
