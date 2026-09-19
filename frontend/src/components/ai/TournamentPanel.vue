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
        ({{ Math.round(tournament.champion.accuracy * 100) }}%)
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
