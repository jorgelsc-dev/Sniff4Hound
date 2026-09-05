<template>
  <div>
    <ViewHeader overline="IA LOCAL" title="Paquetes como imágenes"
      description="Cada byte es un píxel: 0 es negro y 255 es blanco. Explora patrones y posibles alertas omitidas."
      :refresh-loading="loading" @refresh="load">
      <template #actions>
        <v-btn prepend-icon="mdi-refresh" :loading="loading" @click="load">Analizar paquetes</v-btn>
      </template>
    </ViewHeader>
    <v-alert v-if="error" type="error" class="mb-4">{{ error }}</v-alert>
    <v-card class="pa-5 mb-4" variant="tonal">
      <div class="d-flex flex-wrap align-center ga-4">
        <v-chip color="primary">Modelo local · LOF</v-chip>
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
      <p class="text-caption mt-3">Umbral aplicado: {{ result.threshold ?? 50 }}. Pulsa Analizar paquetes para aplicar cambios. La muestra comparte la retención y el borrado del sniffer.</p>
    </v-card>
    <v-alert v-if="!loading && !visibleRows.length" type="info" variant="tonal">
      {{ result.rows.length ? 'No hay candidatos con el umbral aplicado. Esto no demuestra ausencia de amenazas.' : 'Todavía no hay paquetes. Activa la captura y el muestreo para incluir tráfico sin alertas.' }}
    </v-alert>
    <v-row>
      <v-col v-for="packet in visibleRows" :key="packet.id" cols="12" sm="6" lg="4">
        <v-card class="pa-4 h-100" variant="tonal">
          <div class="d-flex align-center justify-space-between ga-2 mb-3">
            <strong>#{{ packet.id }} · {{ packet.proto || 'unknown' }}</strong>
            <v-chip :color="packet.candidate ? 'warning' : 'primary'" size="small">{{ packet.score === null ? 'Sin score' : `${packet.score} / 100` }}</v-chip>
          </div>
          <div class="packet-image">
            <img v-if="packet.image" :src="packet.image" :alt="`Bytes del paquete ${packet.id} en escala de grises`" />
            <span v-else>Sin bytes disponibles</span>
          </div>
          <p class="endpoints mt-3">{{ packet.src_ip || '?' }}:{{ packet.src_port || 0 }} → {{ packet.dst_ip || '?' }}:{{ packet.dst_port || 0 }}</p>
          <div class="text-caption text-medium-emphasis mt-2">{{ packet.byte_count }} bytes · {{ packet.width }} × {{ packet.height }} píxeles · {{ packet.partial ? 'Imagen parcial' : 'Trama completa' }}</div>
          <div class="text-caption text-medium-emphasis">{{ packet.created_at }} · Grupo: {{ packet.cohort_size }} imágenes</div>
          <v-progress-linear v-if="packet.score !== null" :model-value="packet.score" :color="packet.candidate ? 'warning' : 'primary'" class="my-3" rounded height="6" />
          <p class="text-body-2 mt-3">{{ statusLabel(packet) }}</p>
          <p v-if="packet.lof !== null" class="text-caption mt-2">Densidad relativa LOF: {{ packet.lof }}. Valores mayores indican un patrón más aislado.</p>
        </v-card>
      </v-col>
    </v-row>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from "vue";
import ViewHeader from "../components/ui/ViewHeader.vue";
import store from "../state/appStore";

const result = ref({ rows: [], sampling_enabled: false });
const threshold = ref(50);
const onlyCandidates = ref(false);
const loading = ref(false);
const saving = ref(false);
const error = ref("");
const visibleRows = computed(() => result.value.rows.filter(packet => !onlyCandidates.value || packet.candidate));

async function load() {
  if (loading.value) return;
  loading.value = true;
  error.value = "";
  try {
    result.value = await store.fetchJsonPromise(`/api/ai/packets/?threshold=${threshold.value}`);
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
  if (packet.status === "insufficient_data") return "Esperando al menos 20 imágenes del mismo protocolo y tipo de captura.";
  if (packet.alerted) return "Ya tiene una coincidencia de reglas o monitores.";
  if (packet.detection_status !== "evaluated") return "Sin evaluación completa de monitores registrada; no se clasifica como falso negativo.";
  if (packet.candidate) return "Posible falso negativo: patrón atípico sin alertas registradas. Revisar.";
  return "Sin anomalía por encima del umbral; no equivale a tráfico seguro.";
}

onMounted(load);
</script>

<style scoped>
.packet-image { height: 160px; display: flex; align-items: center; justify-content: center; background: #080c13; border: 1px solid #344054; border-radius: 8px; overflow: hidden; }
.packet-image img { width: 100%; height: 100%; object-fit: contain; image-rendering: pixelated; }
.endpoints { overflow-wrap: anywhere; font-family: monospace; }
</style>
