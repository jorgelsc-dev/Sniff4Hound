<template>
  <section class="flow" :class="{ 'is-idle': !online }">
    <header class="flow__bar">
      <div class="flow__identity">
        <span class="flow__pulse" :class="pulseClass" />
        <h2>{{ headline }}</h2>
        <span class="flow__sub">{{ subline }}</span>
      </div>
      <div class="flow__rate">
        <output aria-label="Paquetes por segundo">{{ displayRate }}</output>
        <span>paq/s</span>
      </div>
    </header>

    <div ref="viewport" class="flow__canvas" aria-label="Tubería de captura en vivo">
      <div class="flow__world" :style="worldStyle">
        <svg class="flow__wires" width="1" height="1" aria-hidden="true">
          <g v-for="wire in wires" :key="wire.id">
            <path :d="wire.path" class="flow__wire" :style="{ stroke: wire.color }" />
            <path
              v-if="wire.flowing"
              :d="wire.path"
              class="flow__wire-signal"
              :style="{
                stroke: wire.color,
                strokeDasharray: wire.dash,
                animationDuration: wire.duration,
                opacity: wire.opacity,
              }"
            />
          </g>
        </svg>

        <button
          v-for="node in nodes"
          :key="node.id"
          type="button"
          class="flow__node"
          :class="{ 'is-live': node.live, 'is-muted': !online }"
          :style="{ left: node.x + 'px', top: node.y + 'px', '--stage': node.color }"
          :aria-label="node.label + ': ' + node.status"
          @click="$emit('open', node)"
        >
          <span class="flow__node-top">
            <v-icon :icon="node.icon" size="19" />
            <strong>{{ node.label }}</strong>
          </span>
          <span class="flow__metric">
            <b>{{ node.metric }}</b>
            <i>{{ node.unit }}</i>
          </span>
          <span class="flow__status"><span class="flow__dot" />{{ node.status }}</span>
        </button>
      </div>
    </div>
  </section>
</template>

<script setup>
import { computed, onBeforeUnmount, onMounted, ref } from "vue";
import { connectionPath, flowAnimation, graphBounds } from "../../utils/flowGraph";

const CARD = { width: 186, height: 104 };
const STAGES = {
  ingress: "#54cbd8",
  engine: "#7fd1e8",
  store: "#69c798",
  analysis: "#b79aeb",
  output: "#e4b96c",
};

const props = defineProps({
  // { interfaces, packets, protocols, monitors, payloads, detections }
  totals: { type: Object, default: () => ({}) },
  runtime: { type: Object, default: () => ({}) },
  activity: { type: Object, default: () => ({}) },
  online: { type: Boolean, default: false },
});
defineEmits(["open"]);

const viewport = ref(null);
const scale = ref(1);
const offset = ref({ x: 0, y: 0 });
let resizeObserver;
let resizeFrame;

const rate = computed(() => Number(props.activity?.total) || 0);
const snifferRate = computed(() => Number(props.activity?.sniffer) || 0);
const honeypotRate = computed(() => Number(props.activity?.honeypot) || 0);
const snifferOn = computed(() => Boolean(props.runtime?.sniffer?.running));
const honeypotOn = computed(() => Boolean(props.runtime?.honeypot?.running));
const anyEngineOn = computed(() => snifferOn.value || honeypotOn.value);

const displayRate = computed(() => (rate.value >= 10 ? Math.round(rate.value) : rate.value.toFixed(1)));
const pulseClass = computed(() => {
  if (!props.online) return "is-off";
  return rate.value > 0 ? "is-live" : "is-ready";
});
const headline = computed(() => {
  if (!props.online) return "Sensor desconectado";
  if (!anyEngineOn.value) return "Motores detenidos";
  return rate.value > 0 ? "Capturando tráfico" : "A la escucha";
});
const subline = computed(() => {
  if (!props.online) return "Sin conexión con el backend";
  if (!anyEngineOn.value) return "Arranca un motor para ver el flujo";
  return `${count("interfaces")} interfaces · ${count("protocols")} protocolos`;
});

function count(key) {
  return Number(props.totals?.[key]) || 0;
}
function compact(value) {
  const n = Number(value) || 0;
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`;
  return String(n);
}

// Left-to-right: what the sensor sees, what processes it, where it lands, what
// interprets it, what reaches the operator. The metric on each card is the one
// number that tells you whether that stage is doing its job.
const layout = computed(() => [
  {
    id: "interfaces", label: "Interfaces", icon: "mdi-ethernet", column: 0, row: 1,
    color: STAGES.ingress, metric: compact(count("interfaces")), unit: "activas",
    status: count("interfaces") ? "Escuchando" : "Ninguna seleccionada",
    live: props.online && count("interfaces") > 0, route: "/settings?section=capture",
  },
  {
    id: "sniffer", label: "Sniffer", icon: "mdi-radar", column: 1, row: 0,
    color: STAGES.engine, metric: snifferRate.value.toFixed(1), unit: "paq/s",
    status: snifferOn.value ? "En ejecución" : "Detenido",
    live: props.online && snifferOn.value, route: "/sniffer",
  },
  {
    id: "honeypot", label: "Honeypot", icon: "mdi-spider-web", column: 1, row: 2,
    color: STAGES.engine, metric: honeypotRate.value.toFixed(1), unit: "paq/s",
    status: honeypotOn.value ? "En ejecución" : "Detenido",
    live: props.online && honeypotOn.value, route: "/honeypot",
  },
  {
    id: "store", label: "SniffStore", icon: "mdi-database-outline", column: 2, row: 1,
    color: STAGES.store, metric: compact(count("packets")), unit: "paquetes",
    status: count("packets") ? "Persistiendo" : "Vacío",
    live: props.online && count("packets") > 0, route: "/sniffer",
  },
  {
    id: "monitors", label: "Monitores", icon: "mdi-shield-search", column: 3, row: 0,
    color: STAGES.analysis, metric: compact(count("monitors")), unit: "reglas",
    status: count("monitors") ? "Evaluando" : "Sin reglas",
    live: props.online && count("monitors") > 0, route: "/monitors",
  },
  {
    // The classifier reads retained payloads, so that count is what tells you
    // whether it has anything to work with.
    id: "ai", label: "IA", icon: "mdi-brain", column: 3, row: 2,
    color: STAGES.analysis, metric: compact(count("payloads")), unit: "payloads",
    status: count("payloads") ? "Analizando" : "Sin muestras",
    live: props.online && count("payloads") > 0, route: "/ai",
  },
  {
    id: "alerts", label: "Detecciones", icon: "mdi-bell-ring-outline", column: 4, row: 1,
    color: STAGES.output, metric: compact(count("detections")), unit: "etiquetas",
    status: count("detections") ? "Requiere revisión" : "Todo limpio",
    live: props.online && count("detections") > 0, route: "/soc",
  },
]);

const nodes = computed(() => layout.value.map(node => ({
  ...node,
  x: 30 + node.column * (CARD.width + 86),
  y: 26 + node.row * (CARD.height + 34),
})));

const LINKS = [
  ["interfaces", "sniffer", "sniffer"],
  ["interfaces", "honeypot", "honeypot"],
  ["sniffer", "store", "sniffer"],
  ["honeypot", "store", "honeypot"],
  ["store", "monitors", "total"],
  ["store", "ai", "total"],
  ["monitors", "alerts", "total"],
  ["ai", "alerts", "total"],
];

const wires = computed(() => {
  const byId = Object.fromEntries(nodes.value.map(node => [node.id, node]));
  return LINKS.map(([from, to, lane]) => {
    const source = byId[from];
    const target = byId[to];
    const laneRate = lane === "sniffer" ? snifferRate.value
      : lane === "honeypot" ? honeypotRate.value : rate.value;
    const anim = flowAnimation(laneRate);
    return {
      id: `${from}-${to}`,
      path: connectionPath(source, target, CARD),
      color: target.color,
      flowing: props.online && laneRate > 0 && source.live && target.live,
      ...anim,
    };
  });
});

const worldStyle = computed(() => ({
  transform: `translate(${offset.value.x}px, ${offset.value.y}px) scale(${scale.value})`,
}));

// The pipeline is a fixed, readable diagram rather than a pannable workspace:
// it always scales to fit whatever width the panel gets, so the whole path from
// interface to alert stays on screen without the operator moving anything.
function fit() {
  const el = viewport.value;
  if (!el || !el.clientWidth) return;
  const bounds = graphBounds(nodes.value, CARD, { x: 24, top: 24, bottom: 24 });
  const next = Math.min(1.08, (el.clientWidth - 8) / bounds.width, (el.clientHeight - 8) / bounds.height);
  scale.value = Math.max(0.42, next);
  offset.value = {
    x: (el.clientWidth - bounds.width * scale.value) / 2 - bounds.x * scale.value,
    y: (el.clientHeight - bounds.height * scale.value) / 2 - bounds.y * scale.value,
  };
}

onMounted(() => {
  resizeObserver = new ResizeObserver(() => {
    cancelAnimationFrame(resizeFrame);
    resizeFrame = requestAnimationFrame(fit);
  });
  resizeObserver.observe(viewport.value);
  fit();
});
onBeforeUnmount(() => {
  resizeObserver?.disconnect();
  cancelAnimationFrame(resizeFrame);
});
</script>

<style scoped>
.flow {
  border: 1px solid #263445;
  border-radius: 14px;
  background:
    radial-gradient(120% 140% at 12% 0%, #12263a 0%, transparent 58%),
    linear-gradient(180deg, #0c1826 0%, #091320 100%);
  overflow: hidden;
  transition: border-color 400ms ease;
}
.flow.is-idle { border-color: #23303f; }
.flow__bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  padding: 13px 20px;
  border-bottom: 1px solid #1d2b3b;
  background: #0a141f99;
}
.flow__identity { display: flex; align-items: center; gap: 11px; min-width: 0; }
.flow__identity h2 { font-size: 15px; font-weight: 650; color: #e6edf5; white-space: nowrap; }
.flow__sub {
  font-size: 12px; color: #7c8ca0; border-left: 1px solid #27374a;
  padding-left: 11px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.flow__pulse { width: 8px; height: 8px; border-radius: 50%; flex: 0 0 8px; background: #46576b; }
.flow__pulse.is-ready { background: #e4b96c; }
.flow__pulse.is-live { background: #4ad7b7; animation: flow-pulse 1.9s ease-in-out infinite; }
.flow__rate { display: flex; align-items: baseline; gap: 5px; flex: 0 0 auto; }
.flow__rate output {
  font-size: 21px; font-weight: 680; color: #0fe8ff;
  font-variant-numeric: tabular-nums; letter-spacing: -0.4px;
}
.flow__rate span { font-size: 11px; color: #74889c; }

.flow__canvas {
  position: relative;
  height: 318px;
  overflow: hidden;
  background-image: radial-gradient(#1b2836 1px, transparent 1px);
  background-size: 21px 21px;
}
.flow__world { position: absolute; inset: 0; transform-origin: 0 0; }
.flow__wires { position: absolute; top: 0; left: 0; overflow: visible; pointer-events: none; }
.flow__wire { fill: none; stroke-width: 1.5; opacity: 0.2; }
.flow__wire-signal {
  fill: none; stroke-width: 2.6; stroke-linecap: round;
  animation: flow-stream linear infinite;
}

.flow__node {
  position: absolute;
  width: 186px;
  height: 104px;
  padding: 12px 14px;
  display: flex;
  flex-direction: column;
  gap: 3px;
  text-align: left;
  border: 1px solid #2b3a4c;
  border-radius: 11px;
  background: linear-gradient(180deg, #16263a 0%, #101e2f 100%);
  color: #dce6f1;
  cursor: pointer;
  box-shadow: 0 6px 18px #0004;
  transition: transform 200ms cubic-bezier(0.32, 0.72, 0, 1), border-color 200ms ease, box-shadow 200ms ease;
}
.flow__node:hover { transform: translateY(-3px); border-color: var(--stage); box-shadow: 0 12px 28px #0006; }
.flow__node:focus-visible { outline: 2px solid var(--stage); outline-offset: 3px; }
.flow__node.is-live { border-color: color-mix(in srgb, var(--stage) 55%, #2b3a4c); }
.flow__node.is-muted { opacity: 0.55; }
.flow__node-top { display: flex; align-items: center; gap: 8px; color: var(--stage); }
.flow__node-top strong { font-size: 12.5px; font-weight: 620; color: #e6edf5; letter-spacing: 0.1px; }
.flow__metric { display: flex; align-items: baseline; gap: 5px; margin-top: auto; }
.flow__metric b {
  font-size: 23px; font-weight: 660; color: #f2f7fb;
  font-variant-numeric: tabular-nums; letter-spacing: -0.6px;
}
.flow__metric i { font-style: normal; font-size: 11px; color: #7f91a6; }
.flow__status { display: flex; align-items: center; gap: 6px; font-size: 10.5px; color: #8698ac; }
.flow__dot { width: 5px; height: 5px; border-radius: 50%; background: #46576b; flex: 0 0 5px; }
.is-live .flow__dot { background: var(--stage); box-shadow: 0 0 7px var(--stage); }

@keyframes flow-stream { to { stroke-dashoffset: -164; } }
@keyframes flow-pulse {
  0%, 100% { box-shadow: 0 0 0 0 #4ad7b755; }
  50% { box-shadow: 0 0 0 5px #4ad7b700; }
}
@media (max-width: 860px) { .flow__canvas { height: 270px; } .flow__sub { display: none; } }
@media (prefers-reduced-motion: reduce) {
  .flow__wire-signal, .flow__pulse.is-live { animation: none; }
  .flow__node { transition: none; }
}
</style>
