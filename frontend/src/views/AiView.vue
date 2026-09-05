<template>
  <div>
    <ViewHeader overline="IA LOCAL" title="SOC · Inteligencia de paquetes"
      description="Cada byte es un píxel: 0 es negro y 255 es blanco. Explora patrones y posibles alertas omitidas."
      :refresh-loading="loading" @refresh="load">
      <template #actions>
        <v-btn prepend-icon="mdi-refresh" :loading="loading" @click="load">Analizar paquetes</v-btn>
      </template>
    </ViewHeader>
    <v-alert v-if="error" type="error" class="mb-4">{{ error }}</v-alert>
    <v-card class="pa-5 mb-4" variant="tonal">
      <div class="d-flex flex-wrap align-center ga-4">
        <v-chip color="primary">LOF + red neuronal local</v-chip>
        <v-chip :color="streamStatus === 'En vivo' ? 'success' : 'warning'">{{ streamStatus }} · {{ lastUpdate || "esperando" }}</v-chip>
        <v-chip>{{ result.analyzed || 0 }} analizados / {{ result.rows.length }} registros</v-chip>
        <v-chip color="warning">{{ result.candidates || 0 }} posibles falsos negativos</v-chip>
      </div>
      <p class="mt-4">El score de 0 a 100 mide anomalía visual dentro del mismo protocolo; no es una probabilidad de ataque. Se necesitan al menos 20 imágenes comparables. Un posible falso negativo requiere revisión humana.</p>
      <p class="mt-2 text-medium-emphasis">Se analizan los últimos 200 registros, hasta 4096 bytes por paquete. Sin muestreo, el filtro de monitores puede excluir el tráfico sin alertas. Los datos permanecen en este equipo.</p>
      <v-switch :model-value="result.sampling_enabled" label="Conservar una muestra sin alertas (máximo 1 paquete/s)"
        color="primary" hide-details :disabled="loading || saving" :loading="saving" @update:model-value="setSampling" />
      <v-row class="mt-3" align="center">
        <v-col cols="12" md="6">
          <v-slider v-model="threshold" label="Umbral" :min="1" :max="99" :step="1" thumb-label="always" hide-details />
        </v-col>
        <v-col cols="12" md="6">
          <v-checkbox v-model="onlyCandidates" label="Solo posibles falsos negativos" hide-details />
        </v-col>
      </v-row>
      <p class="text-caption mt-3">Umbral aplicado: {{ result.threshold ?? 50 }}. Pulsa Analizar paquetes para aplicar cambios. Actualización en vivo cada 5 segundos. La muestra comparte la retención y el borrado del sniffer.</p>
    </v-card>

    <v-card class="pa-5 mb-4" variant="tonal">
      <div class="d-flex align-center flex-wrap ga-2 mb-2">
        <h2 class="text-h6 mb-0">Excluir tráfico del análisis</h2>
        <v-chip v-if="activeFilterCount" size="small" color="warning">{{ activeFilterCount }} filtro(s) activo(s)</v-chip>
      </div>
      <p class="text-body-2 text-medium-emphasis mb-3">
        El tráfico que coincida con alguno de estos criterios se ignora al analizar paquetes (no
        afecta a la captura ni a los monitores). Útil para excluir loopback/salud del propio panel,
        redes internas conocidas, o protocolos/puertos ruidosos que no aportan al análisis de imagen.
      </p>
      <v-alert v-if="filtersError" type="error" density="comfortable" class="mb-3">{{ filtersError }}</v-alert>
      <v-row dense>
        <v-col cols="12" md="4">
          <div class="text-caption text-medium-emphasis mb-1">Tipo de IP</div>
          <v-checkbox v-for="opt in ipTypeOptions" :key="opt.value" v-model="filtersDraft.ip_types" :value="opt.value" :label="opt.label" density="compact" hide-details />
        </v-col>
        <v-col cols="12" md="8">
          <v-combobox v-model="filtersDraft.cidrs" label="IPs o bloques CIDR excluidos" hint="Ej: 127.0.0.1, 10.0.0.0/8, 203.0.113.5" persistent-hint multiple chips closable-chips clearable variant="outlined" density="comfortable" class="mb-4" />
          <v-combobox v-model="filtersDraft.protocols" label="Protocolos excluidos" hint="Ej: dns, icmp, ntp" persistent-hint multiple chips closable-chips clearable variant="outlined" density="comfortable" class="mb-4" />
          <v-combobox v-model="filtersDraft.ports" label="Puertos excluidos" hint="Coincide con puerto origen o destino" persistent-hint multiple chips closable-chips clearable variant="outlined" density="comfortable" />
        </v-col>
      </v-row>
      <div class="d-flex ga-2 mt-2">
        <v-btn color="primary" :loading="savingFilters" @click="saveFilters">Guardar filtros</v-btn>
        <v-btn variant="text" :disabled="savingFilters" @click="resetFiltersDraft">Descartar cambios</v-btn>
      </div>
    </v-card>
    <template v-if="result.learning">
      <NeuralGraph ref="graph" :learning="result.learning" :packet="selectedPacket" />
      <v-card class="pa-5 mb-4" variant="tonal">
        <h2 class="text-h6">Aprendizaje de los operadores</h2>
        <p class="mt-2">{{ result.learning.total }}/{{ result.learning.capacity }} ejemplos · {{ result.learning.counts.benign || 0 }} benignos · {{ result.learning.counts.malicious || 0 }} maliciosos · revisión {{ result.learning.revision }}</p>
        <p class="text-body-2 mt-2">Cada revisión enseña al modelo. La confianza (1–3) pondera el aprendizaje. Repetir una etiqueta no multiplica su recompensa; corregirla o retirarla reconstruye el modelo. Los ejemplos de aprendizaje se conservan al borrar capturas.</p>
        <p class="text-caption mt-2">Pérdida de entrenamiento: {{ result.learning.history.at(-1)?.loss ?? 'sin entrenamiento' }}. No mide precisión fuera de las muestras revisadas. La red requiere validación con tráfico etiquetado independiente.</p>
        <v-expansion-panels class="mt-3">
          <v-expansion-panel title="Últimas revisiones y curva de entrenamiento">
            <v-expansion-panel-text>
              <div class="d-flex flex-wrap ga-2 mb-3"><v-chip v-for="point in result.learning.history" :key="point.epoch" size="small">Época {{ point.epoch }} · pérdida {{ point.loss }}</v-chip></div>
              <p v-for="entry in [...result.learning.audit].reverse()" :key="entry.revision" class="text-body-2 mb-2">r{{ entry.revision }} · #{{ entry.packet_id }} · {{ entry.label }} · confianza {{ entry.confidence }} · {{ entry.at }} — {{ entry.note }}</p>
            </v-expansion-panel-text>
          </v-expansion-panel>
        </v-expansion-panels>
      </v-card>
      <v-card class="pa-5 mb-4" variant="tonal">
        <h2 class="text-h6">Prioridad SOC por origen</h2>
        <p class="text-body-2 mt-2">Correlación de los últimos 200 registros. Revisa el flujo, contrasta reglas y contexto del host, y etiqueta la evidencia antes de decidir una contención.</p>
        <v-table density="compact"><thead><tr><th>Origen</th><th>Paquetes</th><th>Con alertas</th><th>Pendientes candidatos</th><th>Score máximo</th></tr></thead>
          <tbody><tr v-for="host in result.hosts" :key="host.ip"><td>{{ host.ip || 'Desconocido' }}</td><td>{{ host.packets }}</td><td>{{ host.alerts }}</td><td>{{ host.candidates }}</td><td>{{ host.max_score }}</td></tr></tbody>
        </v-table>
        <v-btn class="mt-3" to="/soc" variant="text">Abrir análisis SOC general</v-btn>
      </v-card>
    </template>
    <v-alert v-if="!loading && !visibleRows.length" type="info" variant="tonal">
      {{ result.rows.length ? 'No hay candidatos con el umbral aplicado. Esto no demuestra ausencia de amenazas.' : 'Todavía no hay paquetes. Activa la captura y el muestreo para incluir tráfico sin alertas.' }}
    </v-alert>
    <v-row>
      <v-col v-for="packet in visibleRows" :key="packet.id" cols="12" sm="6" lg="4">
        <v-card class="pa-4 h-100" variant="tonal">
          <div class="d-flex align-center justify-space-between ga-2 mb-3">
            <strong>#{{ packet.id }} · {{ packet.proto || 'unknown' }}</strong>
            <v-chip :color="packet.candidate ? 'warning' : 'primary'" size="small">Prioridad {{ packet.priority_score ?? packet.score ?? '—' }}/100</v-chip>
          </div>
          <div class="packet-image">
            <img v-if="packet.image" :src="packet.image" :alt="`Bytes del paquete ${packet.id} en escala de grises`" />
            <span v-else>Sin bytes disponibles</span>
          </div>
          <div class="d-flex flex-wrap ga-2 mt-3">
            <v-chip size="small">LOF {{ packet.score ?? '—' }}</v-chip>
            <v-chip size="small">Neuronal {{ packet.neural_score ?? '—' }}</v-chip>
            <v-chip v-if="packet.feedback" color="success" size="small">Revisado: {{ packet.feedback.label }}</v-chip>
          </div>
          <p class="endpoints mt-3">{{ packet.src_ip || '?' }}:{{ packet.src_port || 0 }} → {{ packet.dst_ip || '?' }}:{{ packet.dst_port || 0 }}</p>
          <div class="text-caption text-medium-emphasis mt-2">{{ packet.byte_count }} bytes · {{ packet.width }} × {{ packet.height }} píxeles · {{ packet.partial ? 'Imagen parcial' : 'Trama completa' }}</div>
          <div class="text-caption text-medium-emphasis">{{ packet.created_at }} · Grupo: {{ packet.cohort_size }} imágenes</div>
          <v-progress-linear v-if="packet.score !== null" :model-value="packet.score" :color="packet.candidate ? 'warning' : 'primary'" class="my-3" rounded height="6" />
          <p class="text-body-2 mt-3">{{ statusLabel(packet) }}</p>
          <div class="d-flex flex-wrap ga-2 mt-3">
            <v-btn size="small" :variant="selectedId === packet.id ? 'flat' : 'outlined'" @click="inspectPacket(packet)">Ver neuronas</v-btn>
            <v-btn size="small" color="primary" :disabled="!packet.byte_count" @click="openReview(packet)">Revisar / enseñar</v-btn>
          </div>
          <p v-if="packet.lof !== null" class="text-caption mt-2">Densidad relativa LOF: {{ packet.lof }}. Valores mayores indican un patrón más aislado.</p>
        </v-card>
      </v-col>
    </v-row>
    <v-dialog v-model="reviewOpen" max-width="560" :persistent="savingFeedback">
      <v-card class="pa-5">
        <h2 class="text-h6">Revisar paquete #{{ reviewPacket?.id }}</h2>
        <p class="text-body-2 my-3">Indica tu conclusión tras revisar la evidencia. Esta señal actualizará los pesos del modelo local.</p>
        <v-select v-model="reviewLabel" label="Conclusión" :items="labels" />
        <v-select v-model="reviewConfidence" label="Confianza / incentivo" :items="[1, 2, 3]" />
        <v-textarea v-model="reviewNote" label="Evidencia o motivo" maxlength="500" counter="500" rows="3" />
        <v-alert v-if="feedbackError" type="error" class="mb-3">{{ feedbackError }}</v-alert>
        <div class="d-flex ga-3 justify-end"><v-btn :disabled="savingFeedback" @click="reviewOpen = false">Cancelar</v-btn><v-btn color="primary" :loading="savingFeedback" :disabled="!reviewLabel" @click="sendFeedback">Guardar y aprender</v-btn></div>
      </v-card>
    </v-dialog>
  </div>
</template>

<script setup>
import { computed, onMounted, onBeforeUnmount, ref } from "vue";
import ViewHeader from "../components/ui/ViewHeader.vue";
import NeuralGraph from "../components/NeuralGraph.vue";
import store from "../state/appStore";

const result = ref({ rows: [], sampling_enabled: false, exclusion_filters: null });
const threshold = ref(50);
const selectedId = ref(null);
const graph = ref(null);
function inspectPacket(packet) {
  selectedId.value = packet.id;
  graph.value?.$el?.scrollIntoView({ behavior: "smooth", block: "start" });
}
const selectedPacket = computed(() => result.value.rows.find(p => p.id === selectedId.value) || result.value.rows[0] || null);
const streamStatus = ref("Conectando");
const lastUpdate = ref("");
let feed = null;
let feedThreshold = null;
let fallbackTimer = null;
let staleTimer = null;
let disposed = false;
let lastReceived = 0;
const reviewOpen = ref(false);
const reviewPacket = ref(null);
const reviewLabel = ref(null);
const reviewConfidence = ref(1);
const reviewNote = ref("");
const savingFeedback = ref(false);
const feedbackError = ref("");
const labels = [{ title: "Benigno", value: "benign" }, { title: "Malicioso", value: "malicious" }, { title: "Retirar etiqueta", value: "unreviewed" }];

const ipTypeOptions = [
  { value: "loopback", label: "Loopback (127.0.0.1, ::1)" },
  { value: "private", label: "Privada (RFC1918, link-local)" },
  { value: "public", label: "Pública" },
  { value: "multicast", label: "Multicast / broadcast" },
];
const emptyFilters = () => ({ ip_types: [], cidrs: [], protocols: [], ports: [] });
const filtersDraft = ref(emptyFilters());
const filtersLoaded = ref(false);
const savingFilters = ref(false);
const filtersError = ref("");
const activeFilterCount = computed(() =>
  filtersDraft.value.ip_types.length + filtersDraft.value.cidrs.length +
  filtersDraft.value.protocols.length + filtersDraft.value.ports.length
);

function resetFiltersDraft() {
  const source = result.value.exclusion_filters || emptyFilters();
  filtersDraft.value = {
    ip_types: [...(source.ip_types || [])],
    cidrs: [...(source.cidrs || [])],
    protocols: [...(source.protocols || [])],
    ports: (source.ports || []).map(String),
  };
  filtersError.value = "";
}

async function saveFilters() {
  savingFilters.value = true;
  filtersError.value = "";
  try {
    const ports = filtersDraft.value.ports
      .map((value) => Number(value))
      .filter((value) => Number.isInteger(value) && value >= 0 && value <= 65535);
    const config = await store.fetchJsonPromise("/api/ai/config", {
      method: "POST",
      body: JSON.stringify({
        exclusion_filters: {
          ip_types: filtersDraft.value.ip_types,
          cidrs: filtersDraft.value.cidrs,
          protocols: filtersDraft.value.protocols,
          ports,
        },
      }),
    });
    result.value.exclusion_filters = config.exclusion_filters;
    resetFiltersDraft();
    await load();
  } catch (err) {
    filtersError.value = err.message || "No se pudieron guardar los filtros.";
  } finally {
    savingFilters.value = false;
  }
}

function applySnapshot(snapshot) {
  if (disposed || (snapshot.learning?.revision ?? 0) < (result.value.learning?.revision ?? 0)) return;
  if (snapshot.generated_at < (result.value.generated_at || "")) return;
  result.value = snapshot;
  lastReceived = Date.now();
  lastUpdate.value = new Date(snapshot.generated_at).toLocaleTimeString();
  error.value = "";
  if (!filtersLoaded.value && snapshot.exclusion_filters) {
    filtersLoaded.value = true;
    resetFiltersDraft();
  }
}

function openFeed() {
  feed?.close();
  streamStatus.value = "Conectando";
  feed = store.openDataFeed("ai", { threshold: feedThreshold, refresh: 5000 }, payload => {
    if (disposed) return;
    if (payload.type === "feed_error") { error.value = payload.message; streamStatus.value = "Error de actualización"; return; }
    if (payload.type !== "feed_data") return;
    if (Number(payload.data.threshold) !== Number(feedThreshold)) return;
    applySnapshot(payload.data);
    streamStatus.value = "En vivo";
  }, () => { if (!disposed) streamStatus.value = "Reconectando · respaldo HTTP"; });
}

function openReview(packet) {
  reviewPacket.value = packet;
  reviewLabel.value = packet.feedback?.label || null;
  reviewConfidence.value = packet.feedback?.confidence || 1;
  reviewNote.value = packet.feedback?.note || "";
  feedbackError.value = "";
  reviewOpen.value = true;
}

async function sendFeedback() {
  savingFeedback.value = true;
  feedbackError.value = "";
  try {
    await store.fetchJsonPromise("/api/ai/feedback", { method: "POST", body: JSON.stringify({ packet_id: reviewPacket.value.id, label: reviewLabel.value, confidence: reviewConfidence.value, note: reviewNote.value }) });
    reviewOpen.value = false;
    await load();
  } catch (err) { feedbackError.value = err.message || "No se pudo guardar la revisión."; }
  finally { savingFeedback.value = false; }
}
const onlyCandidates = ref(false);
const loading = ref(false);
const saving = ref(false);
const error = ref("");
const visibleRows = computed(() => result.value.rows.filter(packet => !onlyCandidates.value || packet.candidate && !packet.reviewed));

async function load(options = {}) {
  if (loading.value) return;
  loading.value = true;
  error.value = "";
  try {
    const requested = options.background ? (result.value.threshold ?? 50) : threshold.value;
    const snapshot = await store.fetchJsonPromise(`/api/ai/packets/?threshold=${requested}`, {}, { preferHttp: true });
    if (disposed || (!options.background && requested !== threshold.value)) return;
    applySnapshot(snapshot);
    if (streamStatus.value !== "En vivo") streamStatus.value = "Respaldo HTTP";
    if (!feed || Number(snapshot.threshold) !== Number(feedThreshold)) { feedThreshold = snapshot.threshold; openFeed(); }
  } catch (err) {
    error.value = err.message || "No se pudieron analizar los paquetes.";
  } finally {
    loading.value = false;
  }
}

async function setSampling(enabled) {
  saving.value = true;
  error.value = "";
  try {
    const config = await store.fetchJsonPromise("/api/ai/config", {
      method: "POST", body: JSON.stringify({ sampling_enabled: enabled }),
    });
    result.value.sampling_enabled = config.sampling_enabled;
  } catch (err) {
    error.value = err.message || "No se pudo actualizar el muestreo.";
  } finally {
    saving.value = false;
  }
}

function statusLabel(packet) {
  if (packet.status === "no_bytes") return "No se puede analizar este registro sin bytes.";
  if (packet.feedback) return `Conclusión del operador: ${packet.feedback.label}. Puedes corregirla o retirar la etiqueta.`;
  if (packet.status === "insufficient_data" && packet.neural_score === null) return "Esperando un grupo LOF de 20 imágenes o suficientes revisiones para la red neuronal.";
  if (packet.alerted) return "Ya tiene una coincidencia de reglas o monitores.";
  if (packet.detection_status !== "evaluated") return "Sin evaluación completa de monitores registrada; no se clasifica como falso negativo.";
  if (packet.candidate) return "Posible falso negativo: patrón atípico sin alertas registradas. Revisar.";
  return "Sin anomalía por encima del umbral; no equivale a tráfico seguro.";
}

onMounted(() => {
  load();
  fallbackTimer = setInterval(() => { if (Date.now() - lastReceived > 10000) load({ background: true }); }, 5000);
  staleTimer = setInterval(() => { if (lastReceived && Date.now() - lastReceived > 12000) streamStatus.value = "Datos desactualizados"; }, 1000);
});
onBeforeUnmount(() => { disposed = true; feed?.close(); clearInterval(fallbackTimer); clearInterval(staleTimer); });
</script>

<style scoped>
.packet-image { height: 160px; display: flex; align-items: center; justify-content: center; background: #080c13; border: 1px solid #344054; border-radius: 8px; overflow: hidden; }
.packet-image img { width: 100%; height: 100%; object-fit: contain; image-rendering: pixelated; }
.endpoints { overflow-wrap: anywhere; font-family: monospace; }
</style>
