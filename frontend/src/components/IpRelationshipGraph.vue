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
            @pointerenter="hoveredIp = node.ip"
            @pointerleave="hoveredIp = hoveredIp === node.ip ? null : hoveredIp"
          >
            <title>{{ node.ip }} · {{ node.display.label }}{{ node.display.detail ? ` (${node.display.detail})` : "" }} · {{ node.hit_count }} hits</title>
            <circle
              :cx="node.x"
              :cy="node.y"
              :r="node.radius"
              fill="currentColor"
              class="ip-graph-node__circle"
              :class="`text-${node.display.color}`"
              :stroke="selectedIp === node.ip ? '#fff' : 'rgba(255,255,255,0.35)'"
            />
            <foreignObject :x="node.x - 9" :y="node.y - 9" width="18" height="18" style="pointer-events: none">
              <div class="ip-graph-node__icon">
                <span class="mdi" :class="node.display.icon"></span>
              </div>
            </foreignObject>
            <text
              v-if="visibleLabels.has(node.ip)"
              :x="node.x"
              :y="node.y + node.radius + 12"
              text-anchor="middle"
              class="ip-graph-node__label mono"
            >
              {{ node.ip }}
            </text>
          </g>
        </g>
      </svg>
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
import store from "../state/appStore";
import { deviceIcon, deviceColor, deviceDisplay } from "../utils/devices";
import { formatTimestamp } from "../utils/traffic";

const CANVAS_WIDTH = 900;
const CANVAS_HEIGHT = 520;
const NODE_LIMIT = 150;
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
  // A bit stronger than the "textbook" sqrt(area/n) repulsion constant -
  // with labels drawn under each node, purely area-proportional spacing
  // still left many pairs closer than their label widths, which is what
  // produced the wall of overlapping text this was tuned against.
  const k = Math.sqrt(area / n) * 1.35;
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
      hoveredIp: null,
      blacklisting: false,
      whitelisting: false,
      actionError: "",
      actionNotice: "",
      selectedDomains: [],
      selectedPaths: [],
      loadingAssociations: false,
      refreshTimer: null,
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
        return { ...node, x: pos.x, y: pos.y, radius: 9 + share * 11, display: deviceDisplay(node) };
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
      const sorted = [...this.layoutNodes].sort((a, b) => b.radius - a.radius);
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
  },
  beforeUnmount() {
    if (this.refreshTimer) clearInterval(this.refreshTimer);
  },
  methods: {
    deviceIconOf: deviceIcon,
    deviceColorOf: deviceColor,
    formatTimestamp,
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
  letter-spacing: 0.05em;
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
</style>
