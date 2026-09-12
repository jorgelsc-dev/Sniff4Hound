<template>
  <v-card variant="tonal" class="pa-4 mb-6 ip-graph-card" rounded="lg">
    <div class="d-flex flex-wrap ga-3 align-center justify-space-between">
      <div>
        <h2 class="text-subtitle-1 font-weight-bold">Mapa de relaciones</h2>
        <p class="text-caption text-medium-emphasis mb-0">
          {{ nodes.length }} IPs · {{ edges.length }} relaciones observadas. Arrastra para mover el área,
          usa los botones o Ctrl/Cmd + rueda para el zoom.
        </p>
      </div>
      <v-btn size="small" variant="tonal" :loading="loading" @click="load">
        <v-icon icon="mdi-refresh" start size="16" />
        Actualizar
      </v-btn>
    </div>

    <v-alert v-if="error" type="error" variant="tonal" density="comfortable" class="mt-3">
      {{ error }}
    </v-alert>

    <div class="ip-graph-toolbar mt-3">
      <v-btn icon size="x-small" variant="tonal" aria-label="Alejar" :disabled="zoom <= MIN_ZOOM" @click="zoomOut">
        <v-icon icon="mdi-magnify-minus-outline" size="16" />
      </v-btn>
      <span class="ip-graph-zoom-level">{{ Math.round(zoom * 100) }}%</span>
      <v-btn icon size="x-small" variant="tonal" aria-label="Acercar" :disabled="zoom >= MAX_ZOOM" @click="zoomIn">
        <v-icon icon="mdi-magnify-plus-outline" size="16" />
      </v-btn>
      <v-btn size="x-small" variant="text" @click="resetView">Restablecer vista</v-btn>
      <v-spacer />
      <div class="ip-graph-legend">
        <span v-for="type in legendTypes" :key="type" class="ip-graph-legend__item">
          <v-icon :icon="deviceIconOf(type)" :color="deviceColorOf(type)" size="13" />
          {{ type }}
        </span>
      </div>
    </div>

    <div
      ref="viewport"
      class="ip-graph-viewport"
      :class="{ 'is-panning': panning }"
      @wheel="onWheel"
      @pointerdown="onPointerDown"
      @pointermove="onPointerMove"
      @pointerup="onPointerUp"
      @pointerleave="onPointerUp"
      @pointercancel="onPointerUp"
    >
      <div v-if="loading && !nodes.length" class="ip-graph-empty">
        <v-progress-circular indeterminate size="22" width="2" color="info" class="mb-2" />
        <div>Cargando relaciones…</div>
      </div>
      <div v-else-if="!nodes.length" class="ip-graph-empty">
        <v-icon icon="mdi-lan-disconnect" size="26" class="mb-2" />
        <div>Aún no hay IPs observadas para dibujar el mapa.</div>
      </div>
      <svg
        v-else
        :viewBox="`0 0 ${CANVAS_WIDTH} ${CANVAS_HEIGHT}`"
        class="ip-graph-svg"
        role="img"
        aria-label="Mapa de relaciones entre direcciones IP observadas"
      >
        <g :transform="`translate(${pan.x} ${pan.y}) scale(${zoom})`">
          <line
            v-for="edge in layoutEdges"
            :key="edge.id"
            :x1="edge.from.x"
            :y1="edge.from.y"
            :x2="edge.to.x"
            :y2="edge.to.y"
            :stroke-width="edge.strokeWidth"
            class="ip-graph-edge"
            :class="{ 'is-dimmed': selectedIp && !edge.touches(selectedIp) }"
          >
            <title>{{ edge.from.ip }} ↔ {{ edge.to.ip }} · {{ edge.weight }} paquetes · {{ edge.flowCount }} flujo(s)</title>
          </line>
          <g
            v-for="node in layoutNodes"
            :key="node.ip"
            class="ip-graph-node"
            :class="{ 'is-selected': selectedIp === node.ip, 'is-dimmed': selectedIp && selectedIp !== node.ip && !isNeighbor(node.ip) }"
            tabindex="0"
            role="button"
            :aria-label="`Inspeccionar ${node.ip}`"
            @click="selectNode(node.ip)"
            @keydown.enter="selectNode(node.ip)"
            @keydown.space.prevent="selectNode(node.ip)"
          >
            <circle
              :cx="node.x"
              :cy="node.y"
              :r="node.radius"
              fill="currentColor"
              class="ip-graph-node__circle"
              :class="`text-${deviceColorOf(node.device_type)}`"
              :stroke="selectedIp === node.ip ? '#fff' : 'rgba(255,255,255,0.35)'"
            />
            <foreignObject :x="node.x - 9" :y="node.y - 9" width="18" height="18" style="pointer-events: none">
              <div class="ip-graph-node__icon">
                <span class="mdi" :class="deviceIconOf(node.device_type)"></span>
              </div>
            </foreignObject>
            <text :x="node.x" :y="node.y + node.radius + 12" text-anchor="middle" class="ip-graph-node__label mono">
              {{ node.ip }}
            </text>
          </g>
        </g>
      </svg>
    </div>

    <div v-if="selectedNode" class="ip-graph-inspector mt-3">
      <div class="d-flex align-center ga-2">
        <v-avatar size="26" :color="deviceColorOf(selectedNode.device_type)" variant="tonal">
          <v-icon :icon="deviceIconOf(selectedNode.device_type)" size="15" />
        </v-avatar>
        <span class="mono text-subtitle-2">{{ selectedNode.ip }}</span>
        <v-chip size="x-small" variant="tonal">{{ selectedNode.device_type || "Unknown" }}</v-chip>
        <v-chip size="x-small" variant="outlined">{{ selectedNode.hit_count }} hits</v-chip>
        <v-spacer />
        <router-link class="ip-graph-inspector__link" :to="{ path: '/investigate', query: { ip: selectedNode.ip } }">
          Investigar <v-icon icon="mdi-arrow-right" size="13" />
        </router-link>
      </div>
      <div v-if="selectedNeighbors.length" class="ip-graph-inspector__connections mt-2">
        <span class="text-caption text-medium-emphasis">{{ selectedNeighbors.length }} relación(es):</span>
        <span v-for="neighbor in selectedNeighbors" :key="neighbor.ip" class="ip-graph-inspector__connection mono">
          {{ neighbor.ip }} <span class="text-medium-emphasis">×{{ neighbor.weight }}</span>
        </span>
      </div>
    </div>
  </v-card>
</template>

<script>
import store from "../state/appStore";
import { deviceIcon, deviceColor } from "../utils/devices";

const CANVAS_WIDTH = 900;
const CANVAS_HEIGHT = 520;
const NODE_LIMIT = 150;
const MIN_ZOOM = 0.4;
const MAX_ZOOM = 3;
const ZOOM_STEP = 0.25;

// A compact Fruchterman-Reingold force layout: nodes repel each other,
// edges pull their endpoints together, both effects shrink each pass
// ("cooling") so the layout settles instead of oscillating forever. Cheap
// enough to just rerun from scratch whenever the node/edge set changes -
// no incremental physics loop needed for a few hundred nodes.
function computeLayout(nodes, edges) {
  const positions = new Map();
  const n = nodes.length;
  if (!n) return positions;
  const cx = CANVAS_WIDTH / 2;
  const cy = CANVAS_HEIGHT / 2;
  const radius = Math.min(CANVAS_WIDTH, CANVAS_HEIGHT) / 2 - 50;
  nodes.forEach((node, i) => {
    const angle = (2 * Math.PI * i) / n;
    positions.set(node.ip, {
      x: cx + radius * Math.cos(angle) * Math.sqrt((i + 1) / n),
      y: cy + radius * Math.sin(angle) * Math.sqrt((i + 1) / n),
    });
  });
  if (n === 1) return positions;
  const area = CANVAS_WIDTH * CANVAS_HEIGHT;
  const k = Math.sqrt(area / n);
  const iterations = n > 200 ? 70 : n > 80 ? 110 : 160;
  let temperature = CANVAS_WIDTH / 10;
  const disp = new Map();
  for (let iter = 0; iter < iterations; iter++) {
    nodes.forEach((node) => disp.set(node.ip, { x: 0, y: 0 }));
    for (let i = 0; i < n; i++) {
      for (let j = i + 1; j < n; j++) {
        const a = nodes[i];
        const b = nodes[j];
        const pa = positions.get(a.ip);
        const pb = positions.get(b.ip);
        let dx = pa.x - pb.x;
        let dy = pa.y - pb.y;
        const dist = Math.sqrt(dx * dx + dy * dy) || 0.01;
        const force = (k * k) / dist;
        dx = (dx / dist) * force;
        dy = (dy / dist) * force;
        const da = disp.get(a.ip);
        const db = disp.get(b.ip);
        da.x += dx;
        da.y += dy;
        db.x -= dx;
        db.y -= dy;
      }
    }
    edges.forEach((edge) => {
      const pa = positions.get(edge.src_ip);
      const pb = positions.get(edge.dst_ip);
      if (!pa || !pb) return;
      let dx = pa.x - pb.x;
      let dy = pa.y - pb.y;
      const dist = Math.sqrt(dx * dx + dy * dy) || 0.01;
      const force = (dist * dist) / k;
      dx = (dx / dist) * force;
      dy = (dy / dist) * force;
      const da = disp.get(edge.src_ip);
      const db = disp.get(edge.dst_ip);
      da.x -= dx;
      da.y -= dy;
      db.x += dx;
      db.y += dy;
    });
    nodes.forEach((node) => {
      const d = disp.get(node.ip);
      const dist = Math.sqrt(d.x * d.x + d.y * d.y) || 0.01;
      const limited = Math.min(dist, temperature);
      const p = positions.get(node.ip);
      p.x = Math.min(CANVAS_WIDTH - 34, Math.max(34, p.x + (d.x / dist) * limited));
      p.y = Math.min(CANVAS_HEIGHT - 34, Math.max(34, p.y + (d.y / dist) * limited));
    });
    temperature *= 0.94;
  }
  return positions;
}

export default {
  name: "IpRelationshipGraph",
  props: {
    // Address-scope filter from the parent view (public/private/local/...),
    // kept in sync so the graph shows the same slice as the table below it.
    scopes: { type: Array, default: () => [] },
  },
  data() {
    return {
      MIN_ZOOM,
      MAX_ZOOM,
      loading: false,
      error: "",
      nodes: [],
      edges: [],
      zoom: 1,
      pan: { x: 0, y: 0 },
      panning: false,
      panStart: null,
      selectedIp: null,
    };
  },
  computed: {
    positions() {
      return computeLayout(this.nodes, this.edges);
    },
    maxHitCount() {
      return this.nodes.reduce((max, node) => Math.max(max, Number(node.hit_count) || 0), 1);
    },
    maxWeight() {
      return this.edges.reduce((max, edge) => Math.max(max, Number(edge.weight) || 0), 1);
    },
    layoutNodes() {
      return this.nodes.map((node) => {
        const pos = this.positions.get(node.ip) || { x: CANVAS_WIDTH / 2, y: CANVAS_HEIGHT / 2 };
        const share = (Number(node.hit_count) || 0) / this.maxHitCount;
        return { ...node, x: pos.x, y: pos.y, radius: 9 + share * 11 };
      });
    },
    nodesByIp() {
      return new Map(this.layoutNodes.map((node) => [node.ip, node]));
    },
    layoutEdges() {
      return this.edges
        .map((edge, i) => {
          const from = this.nodesByIp.get(edge.src_ip);
          const to = this.nodesByIp.get(edge.dst_ip);
          if (!from || !to) return null;
          const share = (Number(edge.weight) || 0) / this.maxWeight;
          return {
            id: `${edge.src_ip}->${edge.dst_ip}-${i}`,
            from,
            to,
            weight: edge.weight,
            flowCount: edge.flow_count,
            strokeWidth: 0.6 + share * 3,
            touches: (ip) => edge.src_ip === ip || edge.dst_ip === ip,
          };
        })
        .filter(Boolean);
    },
    legendTypes() {
      const seen = new Set(this.nodes.map((node) => node.device_type || "Unknown"));
      return Array.from(seen).sort();
    },
    selectedNode() {
      return this.selectedIp ? this.nodesByIp.get(this.selectedIp) || null : null;
    },
    selectedNeighbors() {
      if (!this.selectedIp) return [];
      const rows = [];
      this.edges.forEach((edge) => {
        if (edge.src_ip === this.selectedIp) rows.push({ ip: edge.dst_ip, weight: edge.weight });
        else if (edge.dst_ip === this.selectedIp) rows.push({ ip: edge.src_ip, weight: edge.weight });
      });
      return rows.sort((a, b) => b.weight - a.weight);
    },
  },
  watch: {
    scopes() {
      this.load();
    },
  },
  mounted() {
    this.load();
  },
  methods: {
    deviceIconOf: deviceIcon,
    deviceColorOf: deviceColor,
    load() {
      this.loading = true;
      this.error = "";
      store
        .fetchIpRelationshipGraph({ limit: NODE_LIMIT, scope: this.scopes })
        .then((payload) => {
          const data = payload && typeof payload === "object" ? payload : {};
          this.nodes = Array.isArray(data.nodes) ? data.nodes : [];
          this.edges = Array.isArray(data.edges) ? data.edges : [];
          if (this.selectedIp && !this.nodes.some((node) => node.ip === this.selectedIp)) {
            this.selectedIp = null;
          }
        })
        .catch((err) => {
          this.error = (err && err.message) || "No se pudo cargar el mapa de relaciones";
        })
        .finally(() => {
          this.loading = false;
        });
    },
    isNeighbor(ip) {
      return this.selectedNeighbors.some((neighbor) => neighbor.ip === ip);
    },
    selectNode(ip) {
      this.selectedIp = this.selectedIp === ip ? null : ip;
    },
    zoomBy(delta) {
      this.zoom = Math.min(MAX_ZOOM, Math.max(MIN_ZOOM, Math.round((this.zoom + delta) * 100) / 100));
    },
    // Options API templates only see `this.*` - a bare module-level const
    // like ZOOM_STEP is invisible there (unlike <script setup>, which
    // auto-exposes top-level bindings), so @click="zoomBy(-ZOOM_STEP)" in
    // the template silently evaluated to zoomBy(NaN). These wrap the
    // module constant on the JS side instead.
    zoomIn() {
      this.zoomBy(ZOOM_STEP);
    },
    zoomOut() {
      this.zoomBy(-ZOOM_STEP);
    },
    resetView() {
      this.zoom = 1;
      this.pan = { x: 0, y: 0 };
    },
    onWheel(event) {
      if (!event.ctrlKey && !event.metaKey) return;
      event.preventDefault();
      this.zoomBy(event.deltaY < 0 ? ZOOM_STEP : -ZOOM_STEP);
    },
    onPointerDown(event) {
      // Only the background/svg should start a pan - letting a node's own
      // click-to-select handler fire without the viewport also treating it
      // as the start of a drag.
      this.panning = true;
      this.panStart = { x: event.clientX - this.pan.x, y: event.clientY - this.pan.y };
      if (this.$refs.viewport && event.pointerId != null) {
        this.$refs.viewport.setPointerCapture(event.pointerId);
      }
    },
    onPointerMove(event) {
      if (!this.panning || !this.panStart) return;
      this.pan = { x: event.clientX - this.panStart.x, y: event.clientY - this.panStart.y };
    },
    onPointerUp() {
      this.panning = false;
      this.panStart = null;
    },
  },
};
</script>

<style scoped>
.ip-graph-toolbar {
  display: flex;
  align-items: center;
  gap: 4px;
  flex-wrap: wrap;
}

.ip-graph-zoom-level {
  min-width: 3.2em;
  text-align: center;
  font-size: 0.72rem;
  font-variant-numeric: tabular-nums;
  color: var(--text-dim);
}

.ip-graph-legend {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
}

.ip-graph-legend__item {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  font-size: 0.7rem;
  color: var(--text-dim);
}

.ip-graph-viewport {
  position: relative;
  margin-top: 10px;
  border-radius: 10px;
  border: 1px solid rgba(var(--brand-sky-rgb), 0.16);
  background: rgba(3, 8, 14, 0.5);
  height: 480px;
  overflow: hidden;
  cursor: grab;
  touch-action: none;
}

.ip-graph-viewport.is-panning {
  cursor: grabbing;
}

.ip-graph-empty {
  height: 100%;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  color: var(--text-dim);
  font-size: 0.85rem;
  text-align: center;
  padding: 0 20px;
}

.ip-graph-svg {
  width: 100%;
  height: 100%;
  display: block;
}

.ip-graph-edge {
  stroke: rgba(102, 212, 255, 0.35);
  transition: opacity 0.15s ease, stroke-width 0.15s ease;
}

.ip-graph-edge.is-dimmed {
  opacity: 0.12;
}

.ip-graph-node {
  cursor: pointer;
  transition: opacity 0.15s ease;
}

.ip-graph-node.is-dimmed {
  opacity: 0.3;
}

.ip-graph-node:focus {
  outline: none;
}

.ip-graph-node:focus .ip-graph-node__circle {
  stroke: white;
  stroke-width: 3;
}

.ip-graph-node__circle {
  stroke-width: 1.5;
  opacity: 0.92;
}

.ip-graph-node.is-selected .ip-graph-node__circle {
  stroke-width: 2.5;
}

.ip-graph-node__icon {
  width: 18px;
  height: 18px;
  display: flex;
  align-items: center;
  justify-content: center;
  color: white;
  font-size: 11px;
  pointer-events: none;
}

.ip-graph-node__label {
  font-size: 8px;
  fill: rgba(210, 223, 238, 0.8);
  pointer-events: none;
}

.ip-graph-inspector {
  border-radius: 10px;
  border: 1px solid rgba(var(--brand-sky-rgb), 0.16);
  background: rgba(8, 14, 23, 0.6);
  padding: 10px 12px;
}

.ip-graph-inspector__link {
  color: rgba(108, 186, 228, 0.98);
  text-decoration: none;
  font-size: 0.78rem;
  white-space: nowrap;
}

.ip-graph-inspector__link:hover {
  text-decoration: underline;
}

.ip-graph-inspector__connections {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
}

.ip-graph-inspector__connection {
  font-size: 0.74rem;
  color: var(--text-soft);
  background: rgba(255, 255, 255, 0.05);
  border-radius: 999px;
  padding: 2px 8px;
}

.mono {
  font-family: var(--font-mono);
}
</style>
