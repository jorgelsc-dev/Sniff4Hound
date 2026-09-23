<template>
  <section class="learning-progress" aria-label="Progreso del aprendizaje y selección de modelo">
    <div class="progress-heading"><span><v-icon icon="mdi-brain" size="17" /> APRENDIZAJE</span><span class="status-pill">{{ learning.ready ? 'En evolución' : 'Preparando modelo' }}</span></div>
    <div class="readiness">
      <v-progress-circular :model-value="readiness" :size="48" :width="3" color="primary"><span class="ring-value">{{ readiness }}%</span></v-progress-circular>
      <div class="class-progress">
        <div v-for="item in classes" :key="item.label" class="class-row"><span>{{ item.label }}</span><v-progress-linear :model-value="Math.min(100, item.count / 3 * 100)" :color="item.color" height="4" rounded /><strong>{{ item.count }}<small> / 3 mín.</small></strong></div>
        <p>{{ learning.ready ? 'Mínimo de ambas clases alcanzado · el entrenamiento continúa' : 'Ejemplos distintos necesarios para activar la puntuación neuronal' }}</p>
      </div>
    </div>
    <div class="learning-stats"><span><strong>{{ number(learning.training?.updates) }}</strong> actualizaciones</span><span><strong>{{ number(learning.total) }}</strong> ejemplos retenidos</span><span>Error <strong>{{ loss === null ? '—' : loss.toFixed(4) }}</strong></span>
      <svg v-if="losses.length > 1" viewBox="0 0 100 24" role="img" aria-label="Evolución del error en los últimos pasos"><polyline :points="lossPoints" fill="none" stroke="#43dbcc" stroke-width="2" /></svg>
    </div>
    <div class="selection-heading"><span><v-icon icon="mdi-trophy-outline" size="16" /> SELECCIÓN DE MODELO</span><span>{{ selectionLabel }}</span></div>
    <template v-if="ranked.length">
      <div class="model-race"><div v-for="(model, index) in ranked.slice(0, 3)" :key="model.hidden_sizes.join('-')" class="model-row"><span class="model-rank">{{ index === 0 ? '★' : index + 1 }}</span><span class="model-shape">{{ model.hidden_sizes.join(' → ') }} <small v-if="model.current">base</small></span><v-progress-linear :model-value="model.accuracy * 100" :color="model.current ? 'primary' : 'secondary'" height="4" rounded /><strong>{{ (model.accuracy * 100).toFixed(1) }}%</strong></div></div>
      <p class="selection-note">{{ search.candidates.length }} alternativas evaluadas · acierto sobre ejemplos de entrenamiento, no validación independiente.</p>
    </template>
    <p v-else class="selection-note">{{ learning.ready ? 'La comparación aparecerá al completar la próxima búsqueda.' : 'La búsqueda necesita al menos 3 ejemplos benignos y 3 malignos.' }}</p>
    <div class="tournament-controls">
      <span v-if="tournament.active" class="tournament-controls__status tournament-controls__status--active">
        <v-icon icon="mdi-tournament" size="13" /> Torneo en curso · ronda {{ tournament.round }}
      </span>
      <span v-else-if="readyForTournament" class="tournament-controls__status">
        Se inicia solo cuando hay ejemplos suficientes, mientras el entrenamiento esté activo.
      </span>
      <span v-else class="tournament-controls__hint">Necesita 3 ejemplos benignos y 3 malignos para empezar el torneo.</span>
      <v-btn v-if="tournament.active" size="x-small" color="error" variant="tonal" :loading="tournamentBusy" @click="stopTournament">
        Detener
      </v-btn>
    </div>
    <p v-if="tournament.stop_reason === 'training_disabled'" class="selection-note">El torneo se detuvo porque el entrenamiento está apagado - se reanuda solo al reactivarlo.</p>
    <v-alert v-if="tournamentError" type="error" density="compact" class="mt-2">{{ tournamentError }}</v-alert>
    <div v-if="suggestion.architecture" class="recommendation">
      <v-icon icon="mdi-auto-fix" size="14" /> Propuesta {{ suggestion.architecture.hidden_sizes.join(' → ') }}
      <template v-if="suggestion.architecture.current_accuracy != null">
        · +{{ ((suggestion.architecture.suggested_accuracy - suggestion.architecture.current_accuracy) * 100).toFixed(1) }} puntos
      </template>
      <template v-else>
        · {{ (suggestion.architecture.suggested_accuracy * 100).toFixed(1) }}% de acierto
      </template>
      . Puedes aplicarla en los ajustes.
    </div>
    <div v-else class="next-search"><span>Próxima comparación</span><v-progress-linear :model-value="nextProgress" height="3" color="secondary" rounded /><span>{{ suggestion.next_check?.completed ?? 0 }}/{{ suggestion.next_check?.required ?? 5 }} actualizaciones</span></div>
    <p v-if="search?.checked_at" class="search-date">Última búsqueda: {{ new Date(search.checked_at).toLocaleTimeString('es') }} · revisión {{ search.revision }}</p>
  </section>
</template>

<script setup>
import { computed, ref } from "vue";
import store from "../../state/appStore";
const props = defineProps({
  learning: { type: Object, required: true },
  suggestion: { type: Object, default: () => ({}) },
  tournament: { type: Object, default: () => ({ active: false, candidates: [] }) },
});
const classes = computed(() => [
  { label: "Benignos", count: props.learning.counts?.benign || 0, color: "success" },
  { label: "Malignos", count: props.learning.counts?.malicious || 0, color: "error" },
]);
const readiness = computed(() => Math.round(classes.value.reduce((sum, item) => sum + Math.min(3, item.count), 0) / 6 * 100));
const losses = computed(() => (props.learning.history || []).map(item => Number(item.loss)).filter(Number.isFinite));
const loss = computed(() => losses.value.length ? losses.value.at(-1) : null);
const lossPoints = computed(() => {
  const min = Math.min(...losses.value), max = Math.max(...losses.value);
  return losses.value.map((value, index) => `${index / (losses.value.length - 1) * 100},${22 - (value - min) / (max - min || 1) * 20}`).join(" ");
});
const search = computed(() => props.suggestion.search);
const ranked = computed(() => search.value?.status === "complete" ? [
  { hidden_sizes: search.value.current_hidden_sizes, accuracy: search.value.current_accuracy, current: true },
  ...(search.value.candidates || []),
].filter(item => Number.isFinite(item.accuracy)).sort((a, b) => b.accuracy - a.accuracy) : []);
const selectionLabel = computed(() => props.suggestion.architecture ? "Mejora encontrada" : !props.learning.ready ? "Esperando ejemplos" : ranked.value.length ? "Comparación completada" : "Recopilando datos");
const nextProgress = computed(() => Math.min(100, (props.suggestion.next_check?.completed || 0) / (props.suggestion.next_check?.required || 5) * 100));
function number(value) { return Number(value || 0).toLocaleString("es"); }

// The tournament starts itself once training is on and there are enough
// labelled examples (see store.maybe_start_ai_tournament()) - no manual
// start here, only a stop override while training stays on.
const readyForTournament = computed(() => classes.value.every((item) => item.count >= 3));
const tournamentBusy = ref(false);
const tournamentError = ref("");
async function stopTournament() {
  tournamentBusy.value = true;
  tournamentError.value = "";
  try {
    await store.fetchJsonPromise("/api/ai/tournament", { method: "POST", body: JSON.stringify({ action: "stop" }) });
  } catch (err) {
    tournamentError.value = err.message || "No se pudo detener el torneo.";
  } finally {
    tournamentBusy.value = false;
  }
}
</script>

<style scoped>
.learning-progress { padding: 6px 2px; color: var(--text-soft); font-size: .65rem; }
.progress-heading, .selection-heading { display: flex; align-items: center; justify-content: space-between; gap: 8px; font-size: .63rem; letter-spacing: .08em; }
.progress-heading > span:first-child, .selection-heading > span:first-child { display: flex; align-items: center; gap: 6px; }
.status-pill { color: #4ddbc4; background: #32d3b511; border: 1px solid #32d3b522; border-radius: 20px; padding: 3px 8px; letter-spacing: 0; }
.readiness { display: flex; gap: 14px; align-items: center; margin: 12px 0; }
.ring-value { font-size: .65rem; font-weight: 700; }
.class-progress { flex: 1; min-width: 0; }
.class-row { display: grid; grid-template-columns: 50px 1fr 78px; align-items: center; gap: 8px; margin: 5px 0; }
.class-row strong { text-align: right; }
small, p { color: var(--text-dim); font-weight: 400; }
p { font-size: .57rem; margin-top: 6px; line-height: 1.5; }
.learning-stats { display: flex; align-items: center; gap: 12px; color: var(--text-dim); font-size: .58rem; }
.learning-stats strong { color: var(--text-soft); }
.learning-stats svg { width: 65px; height: 20px; margin-left: auto; }
.selection-heading { margin-top: 12px; border-top: 1px solid #82c1d51c; padding-top: 10px; }
.selection-heading > span:last-child { letter-spacing: 0; color: #bca0ff; font-size: .6rem; }
.model-race { margin-top: 7px; }
.model-row { display: grid; grid-template-columns: 12px 90px 1fr 43px; gap: 8px; align-items: center; margin: 5px 0; font-size: .6rem; }
.model-rank { color: #c3a4ff; }
.model-row strong { text-align: right; }
.next-search { display: flex; align-items: center; gap: 10px; margin-top: 8px; font-size: .56rem; color: var(--text-dim); }
.next-search > span { flex-shrink: 0; }
.recommendation { color: #5ddbc7; background: #2ec9b30b; padding: 6px; border-radius: 5px; margin-top: 6px; font-size: .6rem; }
.search-date { opacity: .65; font-size: .53rem; }
.tournament-controls { display: flex; align-items: center; gap: 8px; margin-top: 8px; flex-wrap: wrap; }
.tournament-controls__hint { font-size: .56rem; color: var(--text-dim); }
.tournament-controls__status { display: flex; align-items: center; gap: 4px; font-size: .58rem; color: var(--text-dim); }
.tournament-controls__status--active { color: #5ddbc7; }
</style>
