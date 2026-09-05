<template>
  <v-card class="pa-5 mb-4" variant="tonal">
    <div class="d-flex flex-wrap ga-3 align-center">
      <h2 class="text-h6">Red neuronal · 8 → 6 → 1</h2>
      <v-chip size="small">Revisión {{ learning.revision }}</v-chip>
      <v-chip :color="learning.ready ? 'success' : 'warning'" size="small">{{ learning.ready ? 'Modelo experimental' : 'Aprendizaje inicial' }}</v-chip>
    </div>
    <p class="mt-2 text-body-2">{{ packet ? `Activaciones reales del paquete #${packet.id}` : 'Selecciona un paquete para ver sus activaciones.' }} · Pesos azules positivos, rojos negativos. Pulsa una neurona para inspeccionarla.</p>
    <div class="network-scroll">
      <svg viewBox="0 0 880 440" role="img" aria-label="Red neuronal con pesos y activaciones reales">
        <text x="20" y="24" fill="currentColor">Características de imagen</text>
        <text x="405" y="24" fill="currentColor">Capa tanh</text>
        <text x="700" y="24" fill="currentColor">Salida sigmoide</text>
        <line v-for="(edge, i) in edges" :key="i" :x1="edge.from.x" :y1="edge.from.y" :x2="edge.to.x" :y2="edge.to.y"
          :stroke="edge.weight >= 0 ? '#56baff' : '#ff7788'" :stroke-width="Math.min(5, 0.4 + Math.abs(edge.weight))" opacity="0.45">
          <title>Peso {{ edge.weight.toFixed(5) }} · contribución {{ edge.contribution === null ? 'sin paquete' : edge.contribution.toFixed(5) }}</title>
        </line>
        <g v-for="node in nodes" :key="node.id" tabindex="0" role="button" :aria-label="`Inspeccionar ${node.label}`"
          class="neuron" @click="selectNode(node.id)" @keydown.enter="selectNode(node.id)" @keydown.space.prevent="selectNode(node.id)">
          <circle :cx="node.x" :cy="node.y" r="18" :fill="node.activation === null ? '#263344' : `hsl(${node.activation < 0 ? 350 : 195} 60% ${22 + Math.abs(node.activation) * 28}%)`"
            :stroke="selectedId === node.id ? '#fff' : '#6c8197'" stroke-width="2" />
          <text :x="node.x" :y="node.y + 4" text-anchor="middle" fill="white" font-size="10">{{ node.activation === null ? '—' : node.activation.toFixed(2) }}</text>
          <text :x="node.x - 25" :y="node.y + 4" text-anchor="end" fill="currentColor" font-size="11">{{ node.label }}</text>
        </g>
      </svg>
    </div>
    <p class="text-body-2">Umbral de decisión: {{ (learning.threshold * 100).toFixed(0) }}/100. {{ learning.ready ? 'La salida participa en la prioridad de revisión.' : 'La salida aún no participa en el score: hacen falta 3 ejemplos benignos y 3 maliciosos distintos.' }}</p>
    <v-expansion-panels v-model="openPanel" class="mt-3">
      <v-expansion-panel :title="`Inspección: ${selected?.label || 'selecciona una neurona'}`">
        <v-expansion-panel-text>
          <p v-if="selected">Activación: {{ selected.activation ?? 'sin paquete' }} · Sesgo: {{ selected.bias ?? 'no aplica' }} · Umbral de suma para activación cero (tanh) o 0.5 (sigmoide): {{ selected.bias === null ? 'no aplica' : -selected.bias }}</p>
          <v-table density="compact">
            <thead><tr><th>Entrada</th><th>Peso</th><th>Contribución al nodo</th></tr></thead>
            <tbody><tr v-for="edge in incoming" :key="edge.from.id"><td>{{ edge.from.label }}</td><td>{{ edge.weight.toFixed(6) }}</td><td>{{ edge.contribution?.toFixed(6) ?? '—' }}</td></tr></tbody>
          </v-table>
        </v-expansion-panel-text>
      </v-expansion-panel>
    </v-expansion-panels>
  </v-card>
</template>
<script setup>
import { computed, ref } from "vue";
const props = defineProps({ learning: { type: Object, required: true }, packet: { type: Object, default: null } });
const selectedId = ref("output");
const openPanel = ref(null);
function selectNode(id) { selectedId.value = id; openPanel.value = 0; }
const nodes = computed(() => {
  const a = props.packet?.activations;
  const inputs = props.learning.feature_names.map((label, i) => ({ id: `i${i}`, label, x: 230, y: 65 + i * 48, activation: a?.input?.[i] ?? null, bias: null }));
  const hidden = props.learning.parameters.b1.map((bias, i) => ({ id: `h${i}`, label: `H${i + 1}`, x: 460, y: 100 + i * 52, activation: a?.hidden?.[i] ?? null, bias }));
  return [...inputs, ...hidden, { id: "output", label: "Riesgo", x: 780, y: 230, activation: a?.output ?? null, bias: props.learning.parameters.b2 }];
});
const edges = computed(() => {
  const result = [];
  const add = (from, to, weight) => result.push({ from, to, weight, contribution: from.activation === null ? null : from.activation * weight });
  props.learning.parameters.w1.forEach((weights, j) => weights.forEach((weight, i) => add(nodes.value[i], nodes.value[8 + j], weight)));
  props.learning.parameters.w2.forEach((weight, j) => add(nodes.value[8 + j], nodes.value[14], weight));
  return result;
});
const selected = computed(() => nodes.value.find(n => n.id === selectedId.value));
const incoming = computed(() => edges.value.filter(e => e.to.id === selectedId.value));
</script>
<style scoped>
.network-scroll { overflow-x: auto; }
svg { width: 100%; min-width: 680px; max-height: 440px; }
.neuron { cursor: pointer; }
.neuron:focus circle { stroke: white; stroke-width: 4; }
</style>
