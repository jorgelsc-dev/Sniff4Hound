<template>
  <v-card
    variant="tonal"
    class="ip-graph-card"
    :class="canvasOnly ? 'ip-graph-card--canvas' : expanded ? 'pa-4 ip-graph-card--expanded' : 'pa-4 mb-6'"
    rounded="lg"
  >
    <div v-if="!canvasOnly" class="d-flex flex-wrap ga-3 align-center justify-space-between">
      <div>
        <h2 class="text-subtitle-1 font-weight-bold">Mapa de relaciones</h2>
      </div>
      <v-btn size="small" variant="tonal" :loading="loading" @click="load">
        <v-icon icon="mdi-refresh" start size="16" />
        Actualizar
      </v-btn>
    </div>

    <v-alert v-if="error" type="error" variant="tonal" density="comfortable" class="mt-3">
      {{ error }}
    </v-alert>

    <div v-if="!canvasOnly" class="ip-graph-toolbar mt-3">
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
      :class="{ 'is-panning': panning, 'ip-graph-viewport--expanded': expanded }"
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
        ref="svg"
        :viewBox="`0 0 ${canvasWidth} ${canvasHeight}`"
        class="ip-graph-svg"
        role="img"
        aria-label="Mapa de relaciones entre direcciones IP observadas"
      >
        <defs>
          <linearGradient id="ip-graph-edge-gradient" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stop-color="rgba(93, 204, 255, 0.72)" />
            <stop offset="55%" stop-color="rgba(112, 232, 190, 0.78)" />
            <stop offset="100%" stop-color="rgba(255, 190, 116, 0.72)" />
          </linearGradient>
          <filter id="ip-graph-node-glow" x="-65%" y="-65%" width="230%" height="230%">
            <feGaussianBlur stdDeviation="4.8" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
          <marker
            id="ip-graph-arrow"
            markerWidth="8"
            markerHeight="8"
            refX="7"
            refY="4"
            orient="auto"
            markerUnits="strokeWidth"
          >
            <path d="M0,0 L8,4 L0,8 Z" fill="rgba(152, 231, 255, 0.58)" />
          </marker>
        </defs>
        <g ref="graphGroup" :transform="`translate(${pan.x} ${pan.y}) scale(${zoom})`">
          <g class="ip-graph-edge-layer">
            <g
              v-for="edge in layoutEdges"
              :key="edge.id"
              class="ip-graph-edge-shell"
              :class="{ 'is-dimmed': edge.isDimmed, 'is-highlighted': edge.isHighlighted }"
              @pointerenter="hoveredEdgeId = edge.id"
              @pointerleave="hoveredEdgeId = hoveredEdgeId === edge.id ? null : hoveredEdgeId"
            >
              <title>{{ edge.from.ip }} → {{ edge.to.ip }} · {{ edge.weight }} paquetes · {{ edge.flowCount }} flujo(s)</title>
              <path :d="edge.path" :stroke-width="edge.glowWidth" class="ip-graph-edge__glow" />
              <path
                :d="edge.path"
                :stroke-width="edge.strokeWidth"
                :marker-end="edge.markerEnd"
                :style="{ opacity: edge.opacity }"
                class="ip-graph-edge"
              />
            </g>
            <circle
              v-for="edge in animatedEdges"
              :key="`packet-${edge.id}`"
              :r="edge.packetRadius"
              class="ip-graph-edge-packet"
              aria-hidden="true"
            >
              <animateMotion
                :path="edge.path"
                :dur="edge.packetDuration"
                :begin="edge.packetDelay"
                repeatCount="indefinite"
                rotate="auto"
              />
            </circle>
          </g>
          <g
            v-for="node in layoutNodes"
            :key="node.ip"
            class="ip-graph-node"
            :class="{
              'is-selected': selectedIp === node.ip,
              'is-hovered': hoveredIp === node.ip,
              'is-dimmed': selectedIp && selectedIp !== node.ip && !isNeighbor(node.ip),
              'is-dragging': draggingIp === node.ip,
            }"
            :style="node.styleVars"
            tabindex="0"
            role="button"
            :aria-label="`Inspeccionar ${node.ip}`"
            @click="onNodeClick(node)"
            @keydown.enter="selectNode(node.ip)"
            @keydown.space.prevent="selectNode(node.ip)"
            @pointerdown="onNodePointerDown(node, $event)"
            @pointermove="onNodePointerMove($event)"
            @pointerup="onNodePointerUp($event)"
            @pointercancel="onNodePointerUp($event)"
            @pointerenter="hoveredIp = node.ip"
            @pointerleave="hoveredIp = hoveredIp === node.ip ? null : hoveredIp"
          >
            <title>{{ node.ip }} · {{ node.display.label }}{{ node.display.detail ? ` (${node.display.detail})` : "" }} · {{ node.scopeLabel }} · {{ node.hit_count }} hits · {{ node.degree }} enlaces</title>
            <circle :cx="node.x" :cy="node.y" :r="node.radius + 13" class="ip-graph-node__halo" />
            <circle :cx="node.x" :cy="node.y" :r="node.radius + 4" class="ip-graph-node__ring" />
            <circle
              :cx="node.x"
              :cy="node.y"
              :r="node.radius"
              fill="currentColor"
              class="ip-graph-node__circle"
              :class="`text-${node.display.color}`"
              :stroke="selectedIp === node.ip ? '#fff' : 'rgba(255,255,255,0.35)'"
            />
            <circle
              v-if="node.degree"
              :cx="node.x + node.radius * 0.72"
              :cy="node.y - node.radius * 0.72"
              :r="node.degreeBadgeRadius"
              class="ip-graph-node__degree"
            />
            <foreignObject :x="node.x - 10" :y="node.y - 10" width="20" height="20" style="pointer-events: none">
              <div class="ip-graph-node__icon">
                <span class="mdi" :class="node.display.icon"></span>
              </div>
            </foreignObject>
            <g v-if="visibleLabels.has(node.ip)" class="ip-graph-node__label-group">
              <text
                :x="node.x"
                :y="node.y + node.radius + 13"
                text-anchor="middle"
                class="ip-graph-node__label ip-graph-node__label--shadow mono"
              >
                {{ node.ip }}
              </text>
              <text
                :x="node.x"
                :y="node.y + node.radius + 13"
                text-anchor="middle"
                class="ip-graph-node__label mono"
              >
                {{ node.ip }}
              </text>
            </g>
          </g>
        </g>
      </svg>
      <div v-if="nodes.length && !canvasOnly" class="ip-graph-hud">
        <span><strong>{{ nodes.length }}</strong> nodos</span>
        <span><strong>{{ edges.length }}</strong> relaciones</span>
        <span v-if="hubNode">Hub <span class="mono">{{ hubNode.ip }}</span></span>
      </div>
      <div v-if="focusedNode" class="ip-graph-focus-card">
        <v-icon :icon="focusedNode.display.icon" :color="focusedNode.display.color" size="16" />
        <span class="mono">{{ focusedNode.ip }}</span>
        <span>{{ focusedNode.display.label }}</span>
        <span>{{ focusedNode.hit_count }} hits</span>
        <span>{{ focusedNode.degree }} enlaces</span>
      </div>
    </div>

    <v-dialog :model-value="Boolean(selectedNode)" max-width="460" @update:model-value="(open) => !open && closeInspector()">
      <v-card v-if="selectedNode" rounded="lg" class="ip-graph-popup">
        <v-card-item>
          <template #prepend>
            <v-avatar :color="selectedNode.display.color" variant="tonal" size="34">
              <v-icon :icon="selectedNode.display.icon" size="19" />
            </v-avatar>
          </template>
          <v-card-title class="mono">{{ selectedNode.ip }}</v-card-title>
          <v-card-subtitle>
            {{ selectedNode.display.label }}
            <span v-if="selectedNode.display.detail">· {{ selectedNode.display.detail }}</span>
          </v-card-subtitle>
          <template #append>
            <v-btn icon="mdi-close" variant="text" size="small" @click="closeInspector" />
          </template>
        </v-card-item>

        <v-card-text class="ip-graph-popup__body">
          <div class="ip-graph-popup__metrics">
            <div class="ip-graph-popup__metric">
              <span class="ip-graph-popup__metric-label">Hits</span>
              <span class="ip-graph-popup__metric-value">{{ selectedNode.hit_count }}</span>
            </div>
            <div class="ip-graph-popup__metric">
              <span class="ip-graph-popup__metric-label">Confianza</span>
              <span class="ip-graph-popup__metric-value">{{ confidenceLabel(selectedNode.device_confidence) }}</span>
            </div>
            <div class="ip-graph-popup__metric">
              <span class="ip-graph-popup__metric-label">Relaciones</span>
              <span class="ip-graph-popup__metric-value">{{ selectedNeighbors.length }}</span>
            </div>
            <div class="ip-graph-popup__metric">
              <span class="ip-graph-popup__metric-label">Ámbito</span>
              <span class="ip-graph-popup__metric-value">{{ selectedNode.scope || "—" }}</span>
            </div>
            <div class="ip-graph-popup__metric ip-graph-popup__metric--wide">
              <span class="ip-graph-popup__metric-label">Primera vez</span>
              <span class="ip-graph-popup__metric-value">{{ formatTimestamp(selectedNode.first_seen) }}</span>
            </div>
            <div class="ip-graph-popup__metric ip-graph-popup__metric--wide">
              <span class="ip-graph-popup__metric-label">Última vez</span>
              <span class="ip-graph-popup__metric-value">{{ formatTimestamp(selectedNode.last_seen) }}</span>
            </div>
          </div>

          <div v-if="selectedNode.device_evidence?.length" class="ip-graph-popup__evidence">
            <span class="text-caption text-medium-emphasis">Evidencia:</span>
            <span v-for="(item, i) in selectedNode.device_evidence" :key="i" class="ip-graph-popup__evidence-item">
              {{ item }}
            </span>
          </div>

          <div v-if="selectedNeighbors.length" class="ip-graph-inspector__connections mt-3">
            <span class="text-caption text-medium-emphasis">Se comunica con:</span>
            <span v-for="neighbor in visibleNeighbors" :key="neighbor.ip" class="ip-graph-inspector__connection mono">
              {{ neighbor.ip }} <span class="text-medium-emphasis">×{{ neighbor.weight }}</span>
            </span>
            <span v-if="hiddenNeighborCount" class="ip-graph-inspector__connection ip-graph-inspector__connection--muted">
              +{{ hiddenNeighborCount }} más
            </span>
          </div>

          <div v-if="loadingAssociations" class="ip-graph-popup__associations-loading mt-3">
            <v-progress-circular indeterminate size="14" width="2" color="info" />
            <span class="text-caption text-medium-emphasis">Buscando dominios y paths asociados…</span>
          </div>
          <template v-else>
            <div v-if="selectedDomains.length" class="ip-graph-inspector__connections mt-3">
              <span class="text-caption text-medium-emphasis">Dominios:</span>
              <span v-for="domain in selectedDomains" :key="domain.id ?? domain.name" class="ip-graph-inspector__connection mono">
                {{ domain.name }}
              </span>
            </div>
            <div v-if="selectedPaths.length" class="ip-graph-inspector__connections mt-3">
              <span class="text-caption text-medium-emphasis">Paths:</span>
              <span
                v-for="path in selectedPaths"
                :key="path.id ?? `${path.method}-${path.path}-${path.host}`"
                class="ip-graph-inspector__connection mono"
              >
                {{ path.method }} {{ path.path }}
              </span>
            </div>
          </template>

          <v-alert v-if="actionError" type="error" variant="tonal" density="comfortable" class="mt-3">
            {{ actionError }}
          </v-alert>
          <v-alert v-if="actionNotice" type="success" variant="tonal" density="comfortable" class="mt-3">
            {{ actionNotice }}
          </v-alert>
        </v-card-text>

        <v-card-actions class="flex-wrap ga-2">
          <v-btn
            size="small"
            variant="tonal"
            color="error"
            :loading="blacklisting"
            prepend-icon="mdi-cancel"
            @click="blacklistSelected"
          >
            Bloquear
          </v-btn>
          <v-btn
            size="small"
            variant="tonal"
            color="warning"
            :loading="whitelisting"
            prepend-icon="mdi-shield-check-outline"
            @click="whitelistSelected"
          >
            Whitelist (borra historial)
          </v-btn>
          <v-spacer />
          <router-link class="ip-graph-inspector__link" :to="{ path: '/investigate', query: { ip: selectedNode.ip } }">
            Investigar <v-icon icon="mdi-arrow-right" size="13" />
          </router-link>
        </v-card-actions>
      </v-card>
    </v-dialog>
  </v-card>
</template>

<script>
import {
  forceCenter,
  forceCollide,
  forceLink,
  forceManyBody,
  forceSimulation,
  forceX,
  forceY,
  scaleLinear,
  scaleSqrt,
} from "d3";
import store from "../state/appStore";
import { deviceIcon, deviceColor, deviceDisplay } from "../utils/devices";
import { formatTimestamp } from "../utils/traffic";

const CANVAS_WIDTH = 900;
const CANVAS_HEIGHT = 520;
const NODE_LIMIT = 150;
const NODE_RADIUS_MIN = 8;
const NODE_RADIUS_MAX = 24;
const MIN_ZOOM = 0.4;
const MAX_ZOOM = 3;
const ZOOM_STEP = 0.25;
// Same order of magnitude as OperationsCenter's own alert-refresh interval -
// frequent enough that the graph feels live, not so frequent that panning
// or an open popup keeps getting interrupted by a redraw.
const AUTO_REFRESH_MS = 15000;
// Rough monospace advance width in px for the 8px label font - just needs
// to be a reasonable upper bound for collision purposes, not exact metrics.
const LABEL_CHAR_WIDTH = 4.6;
// Minimum gap kept between two node circles' edges when one is dragged near
// another - the same idea as the force layout's repulsion, just applied on
// demand instead of continuously.
const NODE_MARGIN = 10;
// Canvas-space distance (immune to zoom, since it's measured in the <g>'s
// own coordinate system) a pointer must travel before a press on a node
// counts as a drag rather than a click - without this, the small jitter
// every real pointer device produces on a "click" would fire a drag on
// every tap and swallow the click that opens the inspector.
const DRAG_THRESHOLD = 3;

const GRAPH_PADDING = 42;
const EDGE_CURVE_MIN = 14;
const EDGE_CURVE_MAX = 76;

const SCOPE_THEMES = {
  private: {
    fill: "rgba(88, 208, 157, 0.94)",
    ring: "rgba(143, 255, 218, 0.74)",
    glow: "rgba(88, 208, 157, 0.24)",
    badge: "Privada",
  },
  public: {
    fill: "rgba(86, 178, 255, 0.95)",
    ring: "rgba(149, 220, 255, 0.82)",
    glow: "rgba(86, 178, 255, 0.24)",
    badge: "Publica",
  },
  local: {
    fill: "rgba(255, 181, 92, 0.95)",
    ring: "rgba(255, 224, 164, 0.82)",
    glow: "rgba(255, 181, 92, 0.24)",
    badge: "Local",
  },
  multicast: {
    fill: "rgba(176, 139, 255, 0.94)",
    ring: "rgba(220, 201, 255, 0.78)",
    glow: "rgba(176, 139, 255, 0.22)",
    badge: "Multicast",
  },
  reserved: {
    fill: "rgba(238, 128, 154, 0.94)",
    ring: "rgba(255, 189, 204, 0.78)",
    glow: "rgba(238, 128, 154, 0.22)",
    badge: "Reservada",
  },
  unknown: {
    fill: "rgba(176, 188, 202, 0.9)",
    ring: "rgba(226, 233, 241, 0.6)",
    glow: "rgba(176, 188, 202, 0.18)",
    badge: "Sin ambito",
  },
};

function stableHash(value) {
  const text = String(value || "");
  let hash = 0;
  for (let index = 0; index < text.length; index += 1) {
    hash = ((hash * 33) + text.charCodeAt(index)) >>> 0;
  }
  return hash || 1;
}

function clamp(value, min, max) {
  return Math.min(max, Math.max(min, value));
}

function nodeHitCount(node) {
  return Number(node && node.hit_count) || 0;
}

function edgeWeight(edge) {
  return Number(edge && edge.weight) || 0;
}

function normalizedScope(scope) {
  const value = String(scope || "").toLowerCase();
  return SCOPE_THEMES[value] ? value : "unknown";
}

function graphScopeTheme(scope) {
  return SCOPE_THEMES[normalizedScope(scope)] || SCOPE_THEMES.unknown;
}

function computeDegrees(edges, allowedIps = null) {
  const degree = new Map();
  edges.forEach((edge) => {
    const src = String(edge.src_ip || "");
    const dst = String(edge.dst_ip || "");
    if (!src || !dst) return;
    if (allowedIps && (!allowedIps.has(src) || !allowedIps.has(dst))) return;
    degree.set(src, (degree.get(src) || 0) + 1);
    degree.set(dst, (degree.get(dst) || 0) + 1);
  });
  return degree;
}

function clusterTarget(node, maxDegree, width, height) {
  const scope = normalizedScope(node.scope);
  const type = String(node.device_type || "").toLowerCase();
  const degreeShare = maxDegree ? (node._layoutDegree || 0) / maxDegree : 0;
  if (degreeShare >= 0.34 || type === "router" || type === "switch") {
    return { x: width * 0.46, y: height * 0.52, strength: 0.15 };
  }
  if (scope === "public") return { x: width * 0.73, y: height * 0.25, strength: 0.13 };
  if (scope === "private") return { x: width * 0.39, y: height * 0.58, strength: 0.1 };
  if (scope === "local") return { x: width * 0.2, y: height * 0.72, strength: 0.12 };
  if (scope === "multicast" || scope === "reserved") {
    return { x: width * 0.76, y: height * 0.72, strength: 0.12 };
  }
  return { x: width * 0.5, y: height * 0.48, strength: 0.06 };
}

function edgePath(from, to, edge, index) {
  const dx = to.x - from.x;
  const dy = to.y - from.y;
  const distance = Math.hypot(dx, dy) || 1;
  const normalX = -dy / distance;
  const normalY = dx / distance;
  const direction = stableHash(`${edge.src_ip}->${edge.dst_ip}:${index}`) % 2 ? 1 : -1;
  const curve = clamp(distance * (0.11 + (1 - edge.weightShare) * 0.07), EDGE_CURVE_MIN, EDGE_CURVE_MAX);
  const mx = (from.x + to.x) / 2 + normalX * curve * direction;
  const my = (from.y + to.y) / 2 + normalY * curve * direction;
  return `M${from.x.toFixed(1)} ${from.y.toFixed(1)} Q${mx.toFixed(1)} ${my.toFixed(1)} ${to.x.toFixed(1)} ${to.y.toFixed(1)}`;
}

// D3 gives this graph a calmer network-map feel than the old circular seed:
// hubs gravitate toward the center, public/private/local scopes drift toward
// different zones, and edge weights pull busy conversations closer together.
function computeLayout(nodes, edges, width = CANVAS_WIDTH, height = CANVAS_HEIGHT) {
  const positions = new Map();
  const n = nodes.length;
  if (!n) return positions;

  const allowedIps = new Set(nodes.map((node) => String(node.ip || "")));
  const degreeByIp = computeDegrees(edges, allowedIps);
  const maxDegree = Math.max(1, ...degreeByIp.values());
  const maxHitCount = Math.max(1, ...nodes.map((node) => nodeHitCount(node)));
  const maxWeight = Math.max(1, ...edges.map((edge) => edgeWeight(edge)));
  const radiusScale = scaleSqrt()
    .domain([0, maxHitCount])
    .range([NODE_RADIUS_MIN, NODE_RADIUS_MAX])
    .clamp(true);

  const layoutNodes = nodes.map((node, index) => {
    const id = String(node.ip || "");
    const degree = degreeByIp.get(id) || 0;
    const target = clusterTarget({ ...node, _layoutDegree: degree }, maxDegree, width, height);
    const seed = stableHash(`${id}:${index}`);
    const angle = ((seed % 720) / 720) * Math.PI * 2;
    const orbit = 36 + (1 - degree / maxDegree) * 118;
    const spiral = 0.42 + Math.sqrt((index + 1) / n) * 0.62;
    return {
      ...node,
      id,
      degree,
      hitCount: nodeHitCount(node),
      cluster: target,
      x: clamp(target.x + Math.cos(angle) * orbit * spiral, GRAPH_PADDING, width - GRAPH_PADDING),
      y: clamp(target.y + Math.sin(angle) * orbit * spiral * 0.78, GRAPH_PADDING, height - GRAPH_PADDING),
    };
  });

  const links = edges
    .map((edge) => {
      const source = String(edge.src_ip || "");
      const target = String(edge.dst_ip || "");
      if (!allowedIps.has(source) || !allowedIps.has(target)) return null;
      return {
        ...edge,
        source,
        target,
        weight: edgeWeight(edge),
        weightShare: edgeWeight(edge) / maxWeight,
      };
    })
    .filter(Boolean);

  const simulation = forceSimulation(layoutNodes)
    .force(
      "link",
      forceLink(links)
        .id((node) => node.id)
        .distance((link) => {
          const sourceDegree = link.source && link.source.degree ? link.source.degree : 0;
          const targetDegree = link.target && link.target.degree ? link.target.degree : 0;
          const degreeLift = ((sourceDegree + targetDegree) / maxDegree) * 28;
          return clamp(158 - link.weightShare * 84 + degreeLift, 54, 180);
        })
        .strength((link) => clamp(0.12 + link.weightShare * 0.32, 0.12, 0.46))
    )
    .force("charge", forceManyBody().strength((node) => -118 - Math.sqrt(node.degree + 1) * 46).distanceMax(360))
    .force("collide", forceCollide((node) => radiusScale(node.hitCount) + 20).strength(0.94).iterations(4))
    .force("x", forceX((node) => node.cluster.x).strength((node) => node.cluster.strength))
    .force("y", forceY((node) => node.cluster.y).strength((node) => node.cluster.strength))
    .force("center", forceCenter(width / 2, height / 2))
    .stop();

  const ticks = n > 120 ? 260 : n > 60 ? 310 : 360;
  for (let tick = 0; tick < ticks; tick += 1) simulation.tick();

  layoutNodes.forEach((node) => {
    const margin = radiusScale(node.hitCount) + 24;
    positions.set(node.id, {
      x: clamp(node.x, margin, width - margin),
      y: clamp(node.y, margin, height - margin),
      degree: node.degree,
    });
  });
  return positions;
}

export default {
  name: "IpRelationshipGraph",
  props: {
    // Address-scope filter from the parent view (public/private/local/...),
    // kept in sync so the graph shows the same slice as the table below it.
    scopes: { type: Array, default: () => [] },
    // Full-bleed dashboard mode: taller viewport, and the layout's own
    // coordinate space tracks the measured element instead of the fixed
    // 900x520 default - otherwise a wide viewport just letterboxes the
    // same small graph with empty space on both sides.
    expanded: { type: Boolean, default: false },
    canvasOnly: { type: Boolean, default: false },
  },
  data() {
    return {
      MIN_ZOOM,
      MAX_ZOOM,
      loading: false,
      error: "",
      nodes: [],
      edges: [],
      canvasWidth: CANVAS_WIDTH,
      canvasHeight: CANVAS_HEIGHT,
      resizeObserver: null,
      resizeApplyTimer: null,
      zoom: 1,
      pan: { x: 0, y: 0 },
      panning: false,
      panStart: null,
      selectedIp: null,
      hoveredIp: null,
      hoveredEdgeId: null,
      blacklisting: false,
      whitelisting: false,
      actionError: "",
      actionNotice: "",
      selectedDomains: [],
      selectedPaths: [],
      loadingAssociations: false,
      refreshTimer: null,
      // ip -> {x, y} overrides from manual dragging, layered on top of the
      // computed force layout. Kept across reloads/auto-refresh so a
      // manually arranged graph doesn't jump back on the next poll.
      manualPositions: new Map(),
      draggingIp: null,
      dragStartLocal: null,
      dragOffset: { x: 0, y: 0 },
      dragMoved: false,
      suppressClickIp: null,
    };
  },
  computed: {
    positions() {
      return computeLayout(this.nodes, this.edges, this.canvasWidth, this.canvasHeight);
    },
    degreeByIp() {
      const ips = new Set(this.nodes.map((node) => String(node.ip || "")));
      return computeDegrees(this.edges, ips);
    },
    maxHitCount() {
      return this.nodes.reduce((max, node) => Math.max(max, nodeHitCount(node)), 1);
    },
    maxWeight() {
      return this.edges.reduce((max, edge) => Math.max(max, edgeWeight(edge)), 1);
    },
    nodeRadiusScale() {
      return scaleSqrt()
        .domain([0, this.maxHitCount])
        .range([NODE_RADIUS_MIN, NODE_RADIUS_MAX])
        .clamp(true);
    },
    edgeWidthScale() {
      return scaleLinear()
        .domain([0, this.maxWeight])
        .range([0.8, 4.25])
        .clamp(true);
    },
    edgeOpacityScale() {
      return scaleLinear()
        .domain([0, this.maxWeight])
        .range([0.3, 0.82])
        .clamp(true);
    },
    layoutNodes() {
      return this.nodes.map((node) => {
        const pos = this.manualPositions.get(node.ip) ||
          this.positions.get(node.ip) || { x: this.canvasWidth / 2, y: this.canvasHeight / 2 };
        const theme = graphScopeTheme(node.scope);
        const hitCount = nodeHitCount(node);
        const degree = this.degreeByIp.get(node.ip) || pos.degree || 0;
        return {
          ...node,
          hit_count: hitCount,
          x: pos.x,
          y: pos.y,
          degree,
          radius: this.nodeRadiusScale(hitCount),
          degreeBadgeRadius: clamp(Math.sqrt(degree + 1) + 2.4, 3.6, 7),
          display: deviceDisplay(node),
          scopeLabel: theme.badge,
          styleVars: {
            "--node-fill": theme.fill,
            "--node-ring": theme.ring,
            "--node-glow": theme.glow,
          },
        };
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
          const weight = edgeWeight(edge);
          const weightShare = weight / this.maxWeight;
          const id = `${edge.src_ip}->${edge.dst_ip}-${i}`;
          const touches = (ip) => edge.src_ip === ip || edge.dst_ip === ip;
          const highlighted = this.hoveredEdgeId === id ||
            (this.selectedIp && touches(this.selectedIp)) ||
            (this.hoveredIp && touches(this.hoveredIp));
          return {
            id,
            from,
            to,
            weight,
            weightShare,
            flowCount: Number(edge.flow_count) || 0,
            strokeWidth: this.edgeWidthScale(weight),
            glowWidth: this.edgeWidthScale(weight) + 5,
            opacity: this.edgeOpacityScale(weight),
            path: edgePath(from, to, { ...edge, weightShare }, i),
            markerEnd: this.selectedIp && !touches(this.selectedIp) ? null : "url(#ip-graph-arrow)",
            isDimmed: Boolean(this.selectedIp && !touches(this.selectedIp)),
            isHighlighted: Boolean(highlighted),
            touches,
          };
        })
        .filter(Boolean);
    },
    animatedEdges() {
      const pool = this.selectedIp
        ? this.layoutEdges.filter((edge) => edge.touches(this.selectedIp))
        : [...this.layoutEdges].sort((a, b) => b.weight - a.weight).slice(0, 18);
      return pool
        .filter((edge) => !edge.isDimmed)
        .slice(0, this.selectedIp ? 28 : 18)
        .map((edge) => {
          const jitter = (stableHash(edge.id) % 1100) / 1000;
          return {
            ...edge,
            packetRadius: clamp(edge.strokeWidth * 0.72, 1.5, 3.3),
            packetDuration: `${(6.6 - edge.weightShare * 3 + jitter).toFixed(1)}s`,
            packetDelay: `${(-jitter * 4).toFixed(2)}s`,
          };
        });
    },
    // Greedy label placement: bigger nodes (by radius, i.e. more hits)
    // claim their label first; a smaller node whose label box would
    // overlap an already-claimed one is skipped for now - it is still
    // fully clickable, names itself in a native <title> tooltip on hover,
    // and always shows its label the moment it is hovered or selected.
    // This is what keeps one node's label from burying another's instead
    // of just letting every node draw one regardless of how crowded the
    // layout got.
    visibleLabels() {
      const visible = new Set();
      const placed = [];
      const sorted = [...this.layoutNodes].sort((a, b) => b.degree - a.degree || b.radius - a.radius);
      for (const node of sorted) {
        const focused = this.selectedIp === node.ip || this.hoveredIp === node.ip;
        const width = Math.max(20, node.ip.length * LABEL_CHAR_WIDTH);
        const box = {
          left: node.x - width / 2,
          right: node.x + width / 2,
          top: node.y + node.radius + 3,
          bottom: node.y + node.radius + 17,
        };
        const overlaps = placed.some(
          (other) => box.left < other.right && box.right > other.left && box.top < other.bottom && box.bottom > other.top
        );
        if (focused || !overlaps) {
          visible.add(node.ip);
          placed.push(box);
        }
      }
      return visible;
    },
    legendTypes() {
      const seen = new Set(this.nodes.map((node) => node.device_type || "Unknown"));
      return Array.from(seen).sort();
    },
    selectedNode() {
      return this.selectedIp ? this.nodesByIp.get(this.selectedIp) || null : null;
    },
    focusedNode() {
      const ip = this.hoveredIp || this.selectedIp;
      return ip ? this.nodesByIp.get(ip) || null : null;
    },
    hubNode() {
      return [...this.layoutNodes].sort((a, b) => b.degree - a.degree || b.hit_count - a.hit_count)[0] || null;
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
    // A hub node can have dozens/hundreds of neighbors - listing all of
    // them pushed the blacklist/whitelist buttons below the fold entirely.
    // The popup is a quick "who is this and what do I do about it" glance,
    // not a full neighbor browser (that's what "Investigar" is for), so
    // it only ever shows the heaviest few.
    visibleNeighbors() {
      return this.selectedNeighbors.slice(0, 12);
    },
    hiddenNeighborCount() {
      return Math.max(0, this.selectedNeighbors.length - this.visibleNeighbors.length);
    },
  },
  watch: {
    scopes() {
      this.load();
    },
  },
  mounted() {
    this.load();
    // Same self-contained polling pattern as OperationsCenter's alert
    // refresh - the graph does not otherwise know when new traffic
    // arrives, so without this it only ever updated on a manual click.
    this.refreshTimer = setInterval(() => {
      this.load({ silent: true });
      if (this.selectedIp) this.loadAssociations(this.selectedIp);
    }, AUTO_REFRESH_MS);
    this.observeViewportSize();
  },
  beforeUnmount() {
    if (this.refreshTimer) clearInterval(this.refreshTimer);
    if (this.resizeObserver) {
      this.resizeObserver.disconnect();
      this.resizeObserver = null;
    }
    if (this.resizeApplyTimer) {
      clearTimeout(this.resizeApplyTimer);
      this.resizeApplyTimer = null;
    }
  },
  methods: {
    deviceIconOf: deviceIcon,
    deviceColorOf: deviceColor,
    formatTimestamp,
    // Keeps the graph's own coordinate space matching the rendered box so a
    // wide viewport (the full-bleed dashboards) actually spreads the layout
    // out instead of the SVG's default "meet" scaling letterboxing the same
    // 900x520 graph with empty space on both sides.
    observeViewportSize() {
      const el = this.$refs.viewport;
      if (!el || typeof ResizeObserver === "undefined") return;
      this.applyViewportSize(el);
      this.resizeObserver = new ResizeObserver(() => {
        if (this.resizeApplyTimer) clearTimeout(this.resizeApplyTimer);
        this.resizeApplyTimer = setTimeout(() => this.applyViewportSize(el), 150);
      });
      this.resizeObserver.observe(el);
    },
    applyViewportSize(el) {
      const width = Math.round(el.clientWidth);
      const height = Math.round(el.clientHeight);
      if (width > 0) this.canvasWidth = Math.max(CANVAS_WIDTH, width);
      if (height > 0) this.canvasHeight = Math.max(CANVAS_HEIGHT, height);
    },
    confidenceLabel(value) {
      return ({ high: "alta", medium: "media", low: "baja" })[value] || "sin clasificar";
    },
    load({ silent = false } = {}) {
      if (!silent) this.loading = true;
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
          const currentIps = new Set(this.nodes.map((node) => node.ip));
          if (this.hoveredIp && !currentIps.has(this.hoveredIp)) this.hoveredIp = null;
          this.hoveredEdgeId = null;
          for (const ip of this.manualPositions.keys()) {
            if (!currentIps.has(ip)) this.manualPositions.delete(ip);
          }
        })
        .catch((err) => {
          // A silent background refresh failing transiently should not
          // blank out an error banner over an otherwise-fine graph.
          if (!silent) this.error = (err && err.message) || "No se pudo cargar el mapa de relaciones";
        })
        .finally(() => {
          this.loading = false;
        });
    },
    isNeighbor(ip) {
      return this.selectedNeighbors.some((neighbor) => neighbor.ip === ip);
    },
    // Dominios/paths observados con esta IP como origen o destino - fetched
    // on demand per selected node (not embedded in the graph payload, which
    // can have 150 nodes) with a small limit, since the popup only ever
    // shows a handful before linking out to the full catalog.
    loadAssociations(ip) {
      this.loadingAssociations = true;
      Promise.all([
        store.listDomains({ ip, limit: 8 }),
        store.listPaths({ ip, limit: 8 }),
      ])
        .then(([domainsResult, pathsResult]) => {
          if (this.selectedIp !== ip) return; // user moved on before this resolved
          this.selectedDomains = Array.isArray(domainsResult) ? domainsResult : [];
          this.selectedPaths = Array.isArray(pathsResult) ? pathsResult : [];
        })
        .catch(() => {
          if (this.selectedIp !== ip) return;
          this.selectedDomains = [];
          this.selectedPaths = [];
        })
        .finally(() => {
          if (this.selectedIp === ip) this.loadingAssociations = false;
        });
    },
    selectNode(ip) {
      this.actionError = "";
      this.actionNotice = "";
      const opening = this.selectedIp !== ip;
      this.selectedIp = opening ? ip : null;
      if (opening) {
        this.selectedDomains = [];
        this.selectedPaths = [];
        this.loadAssociations(ip);
      }
    },
    closeInspector() {
      this.selectedIp = null;
      this.actionError = "";
      this.actionNotice = "";
    },
    blacklistSelected() {
      if (!this.selectedNode || this.blacklisting) return;
      const ip = this.selectedNode.ip;
      this.blacklisting = true;
      this.actionError = "";
      this.actionNotice = "";
      store
        .createBlacklistEntry({ category: "ip", matchType: "exact", value: ip })
        .then(() => {
          this.actionNotice = `${ip} agregada a la blacklist.`;
        })
        .catch((err) => {
          this.actionError = (err && err.message) || "No se pudo bloquear la IP";
        })
        .finally(() => {
          this.blacklisting = false;
        });
    },
    // Two-step: first call asks the backend how many packets a purge
    // would remove (nothing is deleted yet), then a native confirm()
    // names that real count before the second call actually does it -
    // whitelisting an IP here is irreversible (see FAQA.md / purge_ip_data).
    whitelistSelected() {
      if (!this.selectedNode || this.whitelisting) return;
      const ip = this.selectedNode.ip;
      this.whitelisting = true;
      this.actionError = "";
      this.actionNotice = "";
      store
        .whitelistIpAndForget(ip)
        .then((preview) => {
          const count = Number(preview && preview.packets) || 0;
          const proceed = window.confirm(
            `Esto va a eliminar ${count} paquete(s) ya capturados de ${ip} y a dejar de registrar tráfico nuevo de esta IP. ` +
              "No se puede deshacer. ¿Continuar?"
          );
          if (!proceed) {
            this.whitelisting = false;
            return null;
          }
          return store.whitelistIpAndForget(ip, { confirm: true });
        })
        .then((result) => {
          if (!result) return;
          this.actionNotice = `${ip} en whitelist. Se eliminaron ${result.purged?.packets ?? 0} paquete(s).`;
          this.selectedIp = null;
          this.load();
        })
        .catch((err) => {
          this.actionError = (err && err.message) || "No se pudo poner la IP en whitelist";
        })
        .finally(() => {
          this.whitelisting = false;
        });
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
      this.hoveredEdgeId = null;
      this.manualPositions.clear();
    },
    // Converts a pointer event's screen coordinates into the <g>'s own
    // coordinate system (the same space node.x/node.y live in) via the
    // element's screen CTM, so pan and zoom are inverted for free instead
    // of re-deriving them by hand from viewBox/transform math.
    clientToLocal(event) {
      const svgEl = this.$refs.svg;
      const groupEl = this.$refs.graphGroup;
      if (!svgEl || !groupEl) return null;
      const ctm = groupEl.getScreenCTM();
      if (!ctm) return null;
      const pt = svgEl.createSVGPoint();
      pt.x = event.clientX;
      pt.y = event.clientY;
      const local = pt.matrixTransform(ctm.inverse());
      return { x: local.x, y: local.y };
    },
    onNodeClick(node) {
      // A drag ends with the same pointerup/click sequence as a tap, so a
      // just-finished drag would otherwise also pop open the inspector.
      if (this.suppressClickIp === node.ip) {
        this.suppressClickIp = null;
        return;
      }
      this.selectNode(node.ip);
    },
    onNodePointerDown(node, event) {
      // Keep this from also bubbling into the viewport's pan handler.
      event.stopPropagation();
      const local = this.clientToLocal(event);
      if (!local) return;
      this.draggingIp = node.ip;
      this.dragMoved = false;
      this.dragStartLocal = local;
      this.dragOffset = { x: local.x - node.x, y: local.y - node.y };
      if (event.pointerId != null && event.currentTarget.setPointerCapture) {
        event.currentTarget.setPointerCapture(event.pointerId);
      }
    },
    onNodePointerMove(event) {
      if (!this.draggingIp) return;
      const local = this.clientToLocal(event);
      if (!local) return;
      if (!this.dragMoved) {
        const dx = local.x - this.dragStartLocal.x;
        const dy = local.y - this.dragStartLocal.y;
        if (Math.hypot(dx, dy) < DRAG_THRESHOLD) return;
        this.dragMoved = true;
      }
      const node = this.nodesByIp.get(this.draggingIp);
      const radius = node ? node.radius : 12;
      const x = Math.min(this.canvasWidth - radius, Math.max(radius, local.x - this.dragOffset.x));
      const y = Math.min(this.canvasHeight - radius, Math.max(radius, local.y - this.dragOffset.y));
      this.manualPositions.set(this.draggingIp, { x, y });
      this.resolveOverlaps(this.draggingIp);
    },
    onNodePointerUp() {
      if (!this.draggingIp) return;
      const ip = this.draggingIp;
      if (this.dragMoved) {
        this.suppressClickIp = ip;
        // Safety net in case the click that normally follows pointerup
        // never fires (e.g. the release lands outside any element) - it
        // still runs after the browser's own click dispatch either way,
        // so a real click on this node is never eaten.
        setTimeout(() => {
          if (this.suppressClickIp === ip) this.suppressClickIp = null;
        }, 0);
      }
      this.draggingIp = null;
      this.dragStartLocal = null;
    },
    // Pushes any node that ends up too close to the one just moved outward
    // along the line between them, just enough to restore NODE_MARGIN of
    // clearance - the "keep a margin from the others" half of dragging.
    // One pass per pointermove is enough: dragging fires this dozens of
    // times a second, so a chain of nearby nodes settles within a couple
    // of frames without needing a full relaxation loop here.
    resolveOverlaps(movedIp) {
      const nodes = this.layoutNodes;
      const moved = nodes.find((candidate) => candidate.ip === movedIp);
      if (!moved) return;
      nodes.forEach((other) => {
        if (other.ip === movedIp) return;
        let dx = other.x - moved.x;
        let dy = other.y - moved.y;
        const dist = Math.sqrt(dx * dx + dy * dy) || 0.01;
        const minDist = moved.radius + other.radius + NODE_MARGIN;
        if (dist >= minDist) return;
        const push = minDist - dist;
        dx /= dist;
        dy /= dist;
        const x = Math.min(this.canvasWidth - other.radius, Math.max(other.radius, other.x + dx * push));
        const y = Math.min(this.canvasHeight - other.radius, Math.max(other.radius, other.y + dy * push));
        this.manualPositions.set(other.ip, { x, y });
      });
    },
    onWheel(event) {
      if (!event.ctrlKey && !event.metaKey) return;
      event.preventDefault();
      this.zoomBy(event.deltaY < 0 ? ZOOM_STEP : -ZOOM_STEP);
    },
    onPointerDown(event) {
      // Only the background/svg should start a pan. This used to capture
      // the pointer unconditionally, which - regardless of where inside
      // the viewport the press actually started - hijacked every
      // following pointerup (and, on real hardware, the click that fires
      // after it) to the viewport itself: a node's own click-to-select
      // never got a chance to run, so clicking a node silently did
      // nothing instead of opening its popup. Bailing out here when the
      // press started on a node leaves that node's own @click handler
      // free to fire normally.
      if (event.target && event.target.closest && event.target.closest(".ip-graph-node")) {
        return;
      }
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
  border-radius: 8px;
  border: 1px solid rgba(var(--brand-sky-rgb), 0.2);
  background:
    linear-gradient(rgba(148, 190, 226, 0.055) 1px, transparent 1px),
    linear-gradient(90deg, rgba(148, 190, 226, 0.045) 1px, transparent 1px),
    linear-gradient(180deg, rgba(6, 14, 24, 0.96), rgba(9, 18, 27, 0.92));
  background-size: 32px 32px, 32px 32px, auto;
  height: 480px;
  overflow: hidden;
  cursor: grab;
  touch-action: none;
  box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.04), inset 0 -40px 80px rgba(0, 0, 0, 0.22);
}

.ip-graph-viewport::before {
  content: "";
  position: absolute;
  inset: 0;
  pointer-events: none;
  background: linear-gradient(135deg, rgba(102, 212, 255, 0.1), transparent 34%, rgba(94, 244, 186, 0.06));
  z-index: 1;
}

.ip-graph-viewport.is-panning {
  cursor: grabbing;
}

.ip-graph-viewport--expanded {
  height: calc(100vh - 250px);
  min-height: 560px;
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
  position: relative;
  z-index: 0;
}

.ip-graph-edge-layer,
.ip-graph-edge-shell {
  pointer-events: stroke;
}

.ip-graph-edge-shell {
  transition: opacity 0.15s ease;
}

.ip-graph-edge {
  fill: none;
  stroke: url(#ip-graph-edge-gradient);
  stroke-linecap: round;
  stroke-linejoin: round;
  transition: opacity 0.15s ease, stroke-width 0.15s ease, stroke 0.15s ease;
}

.ip-graph-edge__glow {
  fill: none;
  stroke: rgba(102, 212, 255, 0.25);
  stroke-linecap: round;
  opacity: 0.16;
}

.ip-graph-edge-shell.is-dimmed {
  opacity: 0.13;
}

.ip-graph-edge-shell.is-highlighted .ip-graph-edge {
  opacity: 1 !important;
  stroke: rgba(152, 235, 255, 0.96);
}

.ip-graph-edge-shell.is-highlighted .ip-graph-edge__glow {
  opacity: 0.44;
}

.ip-graph-edge-packet {
  fill: rgba(222, 252, 255, 0.94);
  filter: drop-shadow(0 0 4px rgba(126, 229, 255, 0.9));
  pointer-events: none;
}

.ip-graph-node {
  cursor: grab;
  touch-action: none;
  transition: opacity 0.15s ease, filter 0.15s ease;
}

.ip-graph-node.is-dimmed {
  opacity: 0.24;
}

.ip-graph-node.is-dragging {
  cursor: grabbing;
  filter: drop-shadow(0 8px 14px rgba(0, 0, 0, 0.34));
}

.ip-graph-node:focus {
  outline: none;
}

.ip-graph-node:focus .ip-graph-node__ring,
.ip-graph-node.is-selected .ip-graph-node__ring {
  stroke: white;
  stroke-width: 2;
  opacity: 0.95;
}

.ip-graph-node__halo {
  fill: var(--node-glow);
  filter: url(#ip-graph-node-glow);
  opacity: 0.72;
  transition: opacity 0.15s ease;
}

.ip-graph-node__ring {
  fill: none;
  stroke: var(--node-ring);
  stroke-width: 1.1;
  stroke-dasharray: 2.6 4.2;
  opacity: 0.62;
  transition: opacity 0.15s ease, stroke-width 0.15s ease;
}

.ip-graph-node__circle {
  stroke-width: 1.5;
  opacity: 0.95;
  filter: drop-shadow(0 5px 10px rgba(0, 0, 0, 0.32));
  transition: opacity 0.15s ease, stroke-width 0.15s ease;
}

.ip-graph-node.is-hovered .ip-graph-node__halo,
.ip-graph-node.is-selected .ip-graph-node__halo {
  opacity: 1;
}

.ip-graph-node.is-selected .ip-graph-node__circle {
  stroke-width: 2.5;
}

.ip-graph-node__degree {
  fill: var(--node-fill);
  stroke: rgba(6, 13, 21, 0.86);
  stroke-width: 1.2;
}

.ip-graph-node__icon {
  width: 20px;
  height: 20px;
  display: flex;
  align-items: center;
  justify-content: center;
  color: white;
  font-size: 12px;
  text-shadow: 0 1px 5px rgba(0, 0, 0, 0.55);
  pointer-events: none;
}

.ip-graph-node__label {
  font-size: 8.5px;
  fill: rgba(222, 234, 246, 0.9);
  pointer-events: none;
}

.ip-graph-node__label--shadow {
  stroke: rgba(2, 8, 14, 0.82);
  stroke-width: 3.5;
  paint-order: stroke;
}

.ip-graph-hud,
.ip-graph-focus-card {
  position: absolute;
  z-index: 2;
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  pointer-events: none;
  border: 1px solid rgba(174, 218, 255, 0.14);
  background: rgba(5, 13, 22, 0.74);
  box-shadow: 0 10px 28px rgba(0, 0, 0, 0.28);
  backdrop-filter: blur(10px);
}

.ip-graph-hud {
  top: 12px;
  left: 12px;
  max-width: calc(100% - 24px);
  gap: 9px;
  border-radius: 8px;
  padding: 7px 10px;
  font-size: 0.72rem;
  color: rgba(224, 236, 247, 0.86);
}

.ip-graph-hud strong {
  color: white;
  font-weight: 700;
}

.ip-graph-focus-card {
  right: 12px;
  bottom: 12px;
  max-width: min(520px, calc(100% - 24px));
  gap: 8px;
  border-radius: 8px;
  padding: 8px 10px;
  font-size: 0.72rem;
  color: rgba(225, 238, 248, 0.92);
}

.ip-graph-popup__body {
  max-height: 50vh;
  overflow-y: auto;
}

.ip-graph-popup__metrics {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 8px 14px;
  margin-bottom: 4px;
}

.ip-graph-popup__metric {
  display: flex;
  flex-direction: column;
  gap: 1px;
}

.ip-graph-popup__metric--wide {
  grid-column: span 2;
}

.ip-graph-popup__metric-label {
  font-size: 0.68rem;
  text-transform: uppercase;
  letter-spacing: 0;
  color: var(--text-dim);
}

.ip-graph-popup__metric-value {
  font-size: 0.85rem;
  font-weight: 600;
}

.ip-graph-popup__evidence {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 6px;
  margin-top: 8px;
}

.ip-graph-popup__associations-loading {
  display: flex;
  align-items: center;
  gap: 8px;
}

.ip-graph-popup__evidence-item {
  font-size: 0.72rem;
  color: var(--text-soft);
  background: rgba(255, 255, 255, 0.05);
  border-radius: 999px;
  padding: 2px 8px;
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

.ip-graph-inspector__connection--muted {
  color: var(--text-dim);
  background: transparent;
}

.mono {
  font-family: var(--font-mono);
}

@media (max-width: 700px) {
  .ip-graph-viewport {
    height: 390px;
  }

  .ip-graph-hud {
    right: 10px;
    left: 10px;
    top: 10px;
  }

  .ip-graph-focus-card {
    right: 10px;
    left: 10px;
    bottom: 10px;
  }
}

.ip-graph-card.ip-graph-card--canvas {
  height: calc(100dvh - var(--v-layout-top, 0px) - var(--v-layout-bottom, 0px));
  padding: 0;
  border: 0;
  border-radius: 0 !important;
  background: transparent;
  box-shadow: none;
}

.ip-graph-card--canvas .ip-graph-viewport {
  height: 100%;
  min-height: 0;
  margin: 0;
  border: 0;
  border-radius: 0;
}

.ip-graph-card--canvas > .v-alert {
  position: absolute;
  top: 12px;
  left: 12px;
  right: 12px;
  z-index: 5;
}
</style>
