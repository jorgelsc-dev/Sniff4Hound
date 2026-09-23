<template>
  <div class="tournament-panel">
    <div class="tournament-panel__head">
      <v-icon icon="mdi-trophy-variant" size="18" />
      <span>Torneo de arquitecturas · Ronda {{ tournament.round || 1 }}</span>
      <v-chip size="x-small" :color="tournament.active ? 'info' : 'success'">
        {{ tournament.active ? "Entrenando" : stopReasonLabel }}
      </v-chip>
    </div>
    <p class="tournament-panel__hint">
      {{ TOURNAMENT_CANDIDATES_PER_ROUND }} candidatas entrenan a la vez; la mejor de cada ronda pasa a la
      siguiente junto con 2 candidatas nuevas al azar (variando capas y neuronas hasta ±2). Corre sin
      parar mientras el entrenamiento esté activo.
    </p>
    <div class="tournament-panel__graphs">
      <TournamentGraph
        v-for="(candidate, index) in candidates"
        :key="index"
        :candidate="candidate"
        :feature-count="featureCount"
      />
    </div>
    <p v-if="tournament.champion && !tournament.active" class="tournament-panel__champion">
      Campeona: <strong>{{ (tournament.champion.hidden_sizes || []).join(" → ") }}</strong>
      <template v-if="tournament.champion.accuracy != null">
        ({{ Math.round(tournament.champion.accuracy * 100) }}% · {{ evaluationModeLabel(tournament.champion.evaluation_mode) }})
      </template>
      · revisá la sugerencia para aplicarla.
    </p>
  </div>
</template>
<script setup>
import { computed } from "vue";
import TournamentGraph from "./TournamentGraph.vue";

const TOURNAMENT_CANDIDATES_PER_ROUND = 3;

const props = defineProps({
  tournament: { type: Object, required: true },
  featureCount: { type: Number, default: 8 },
});

const candidates = computed(() => props.tournament.candidates || []);
const STOP_REASON_LABEL = { training_disabled: "Entrenamiento apagado", manual: "Detenido manualmente" };
const stopReasonLabel = computed(() => STOP_REASON_LABEL[props.tournament.stop_reason] || "Finalizado");
// Below VALIDATION_MIN_PER_CLASS (ai_learning.py), a round scores every
// candidate on the same examples it trained on - the label says so instead
// of implying every round validates on data the model never saw (1.25).
function evaluationModeLabel(mode) {
  return mode === "holdout" ? "validado en datos no vistos" : "sobre datos de entrenamiento";
}
</script>
<style scoped>
.tournament-panel {
  height: 100%;
  overflow-y: auto;
  padding: 16px 20px 320px;
  box-sizing: border-box;
}
.tournament-panel__head {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 0.8rem;
  font-weight: 700;
}
.tournament-panel__hint {
  margin: 6px 0 14px;
  font-size: 0.68rem;
  color: var(--text-dim);
  max-width: 640px;
}
.tournament-panel__graphs {
  display: flex;
  flex-direction: column;
  gap: 12px;
  max-width: 420px;
}
.tournament-panel__champion {
  margin-top: 14px;
  font-size: 0.72rem;
  color: #5ddbc7;
}
</style>
