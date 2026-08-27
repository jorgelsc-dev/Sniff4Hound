<template>
  <DataPanel
    :title="title"
    :subtitle="subtitle"
    :loading="loading"
    :error="error"
    :last-updated="lastUpdated"
    :show-refresh="showRefresh"
    :live-refresh="liveRefresh"
    :live-enabled="liveEnabled"
    :show-header="showHeader"
    :keep-content-on-loading="true"
    @refresh="$emit('refresh')"
    @update:liveEnabled="$emit('update:liveEnabled', $event)"
  >
    <div class="host-radar-shell">
      <div class="host-radar-stage">
        <svg
          :viewBox="`0 0 ${stageWidth} ${stageHeight}`"
          role="img"
          aria-label="Historical host attack view with animated source to target packet lanes"
        >
          <defs>
            <!-- Flat stage backdrop. This used to be a radial gradient with a
                 bright centre, which washed out the node halos painted on top -
                 those carry meaning (scope, emphasis, alerts) and need the
                 contrast more than the background needs decoration. -->
            <linearGradient :id="stageGlowGradientId" x1="0%" y1="0%" x2="0%" y2="100%">
              <stop offset="0%" stop-color="rgba(6, 18, 32, 0.96)" />
              <stop offset="100%" stop-color="rgba(3, 10, 18, 0.98)" />
            </linearGradient>
            <linearGradient :id="frameGradientId" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stop-color="rgba(94, 227, 255, 0.16)" />
              <stop offset="48%" stop-color="rgba(92, 245, 186, 0.56)" />
              <stop offset="100%" stop-color="rgba(255, 176, 96, 0.18)" />
            </linearGradient>
            <filter :id="arcGlowFilterId" x="-30%" y="-30%" width="160%" height="160%">
              <feGaussianBlur stdDeviation="3.2" result="blurred" />
              <feMerge>
                <feMergeNode in="blurred" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
            <filter :id="nodeGlowFilterId" x="-80%" y="-80%" width="260%" height="260%">
              <feGaussianBlur stdDeviation="4.4" result="nodeBlur" />
              <feMerge>
                <feMergeNode in="nodeBlur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
            <marker
              :id="attackMarkerId"
              viewBox="0 0 10 10"
              refX="8.2"
              refY="5"
              markerWidth="5.2"
              markerHeight="5.2"
              orient="auto"
            >
              <path d="M0,0 L10,5 L0,10 z" fill="rgba(255, 184, 116, 0.92)" />
            </marker>
          </defs>

          <rect
            x="0"
            y="0"
            :width="stageWidth"
            :height="stageHeight"
            fill="rgba(3, 9, 17, 0.98)"
          />
          <rect
            :x="stagePadding"
            :y="stagePadding"
            :width="stageWidth - (stagePadding * 2)"
            :height="stageHeight - (stagePadding * 2)"
            :fill="`url(#${stageGlowGradientId})`"
            stroke="rgba(83, 166, 214, 0.18)"
            stroke-width="1"
            rx="24"
          />
          <rect
            :x="stagePadding + 8"
            :y="stagePadding + 8"
            :width="stageWidth - (stagePadding * 2) - 16"
            :height="stageHeight - (stagePadding * 2) - 16"
            fill="none"
            :stroke="`url(#${frameGradientId})`"
            stroke-width="1"
            rx="20"
            opacity="0.78"
          />

          <g class="host-radar-mesh">
            <path
              v-for="meshPath in backdropPaths"
              :key="meshPath.id"
              :d="meshPath.d"
              fill="none"
              :stroke="meshPath.stroke"
              :stroke-width="meshPath.strokeWidth"
              :stroke-dasharray="meshPath.dash"
              :opacity="meshPath.opacity"
            />
          </g>

          <g v-if="arcPaths.length" class="host-radar-arcs">
            <path
              v-for="arc in arcPaths"
              :key="`glow-${arc.id}`"
              :d="arc.d"
              fill="none"
              :stroke="arc.glow"
              :stroke-width="arc.strokeWidth + 2.8"
              stroke-linecap="round"
              :opacity="arc.glowOpacity"
              :filter="`url(#${arcGlowFilterId})`"
            />
            <path
              v-for="arc in arcPaths"
              :key="arc.id"
              :d="arc.d"
              fill="none"
              :stroke="arc.stroke"
              :stroke-width="arc.strokeWidth"
              stroke-linecap="round"
              class="host-radar-flow"
              :style="arc.style"
              :opacity="arc.strokeOpacity"
              :marker-end="arc.markerEnd"
            />
            <circle
              v-for="arc in activeArcPaths"
              :key="`impact-${arc.id}`"
              :cx="arc.target.x"
              :cy="arc.target.y"
              :fill="arc.traceColor"
              r="2"
              opacity="0"
            >
              <animate attributeName="r" values="2;10;2" :dur="arc.duration" :begin="arc.begin" repeatCount="indefinite" />
              <animate attributeName="opacity" values="0;0.24;0" :dur="arc.duration" :begin="arc.begin" repeatCount="indefinite" />
            </circle>
            <circle
              v-for="arc in arcPaths"
              :key="`trace-glow-${arc.id}`"
              :r="arc.traceRadius * 2.85"
              :fill="arc.traceGlow"
              class="host-radar-trace host-radar-trace--glow"
              :opacity="arc.traceGlowOpacity"
              :filter="`url(#${nodeGlowFilterId})`"
            >
              <animateMotion :dur="arc.duration" :begin="arc.begin" repeatCount="indefinite" :path="arc.d" />
            </circle>
            <circle
              v-for="arc in arcPaths"
              :key="`trace-${arc.id}`"
              :r="arc.traceRadius"
              :fill="arc.traceColor"
              :stroke="arc.traceStroke"
              stroke-width="0.58"
              class="host-radar-trace"
              :opacity="arc.traceOpacity"
            >
              <animateMotion :dur="arc.duration" :begin="arc.begin" repeatCount="indefinite" :path="arc.d" />
            </circle>
          </g>

          <g v-if="layoutNodes.length" class="host-radar-nodes">
            <g
              v-for="node in layoutNodes"
              :key="node.ip"
              class="host-radar-node"
              :class="{ 'host-radar-node--historical': !node.activeNow }"
              :transform="`translate(${node.x}, ${node.y})`"
              :opacity="node.nodeOpacity"
              @click="navigateToHost(node)"
            >
              <title>{{ nodeTooltip(node) }}</title>
              <circle
                :r="node.haloRadius"
                :fill="node.glow"
                :opacity="node.activeNow ? 0.24 : 0.12"
                :filter="`url(#${nodeGlowFilterId})`"
              />
              <circle
                :r="node.ringRadius"
                fill="none"
                :stroke="node.ring"
                stroke-width="1"
                :opacity="node.activeNow ? 0.78 : 0.38"
              />
              <g :transform="`scale(${node.iconScale})`">
                <circle
                  r="12.4"
                  :fill="node.body"
                  stroke="rgba(235, 246, 255, 0.82)"
                  stroke-width="0.9"
                />
                <circle
                  r="7.2"
                  :fill="node.screen"
                />
                <path
                  d="M0,-4.8 L0,4.8 M-4.8,0 L4.8,0"
                  stroke="rgba(235, 246, 255, 0.74)"
                  stroke-width="1.05"
                  stroke-linecap="round"
                />
                <path
                  d="M-8.8,7.8 L-3.6,3.8 M8.4,-7.2 L3.6,-3.2"
                  :stroke="node.base"
                  stroke-width="1.2"
                  stroke-linecap="round"
                />
                <circle
                  cx="-10.4"
                  cy="9.2"
                  r="3.3"
                  :fill="node.base"
                />
                <circle
                  cx="10"
                  cy="-8.6"
                  r="3.1"
                  :fill="node.badge"
                />
                <circle
                  cx="0"
                  cy="0"
                  r="2.1"
                  fill="rgba(238, 246, 255, 0.96)"
                />
              </g>

              <g
                v-if="node.alertCount > 0"
                class="host-radar-alert-badge"
                :transform="`translate(${node.haloRadius * 0.72}, ${-node.haloRadius * 0.72})`"
              >
                <title>{{ node.alertCount }} {{ node.alertSeverity }} alert{{ node.alertCount === 1 ? '' : 's' }} on {{ node.ip }}</title>
                <circle r="6.6" :fill="node.alertFill" :stroke="node.alertRing" stroke-width="1.1" />
                <text
                  text-anchor="middle"
                  dominant-baseline="central"
                  dy="0.5"
                  fill="rgba(10, 14, 22, 0.94)"
                  font-size="7.6px"
                  font-weight="800"
                >{{ node.alertCount > 99 ? "99+" : node.alertCount }}</text>
              </g>
              <text
                :y="node.labelY"
                text-anchor="middle"
                fill="rgba(237, 244, 255, 0.96)"
                font-size="9.2px"
                font-weight="700"
                :opacity="node.labelOpacity"
              >
                {{ compactIp(node.ip) }}
              </text>
              <text
                :y="node.metricY"
                text-anchor="middle"
                fill="rgba(170, 200, 226, 0.86)"
                font-size="8.1px"
                font-weight="600"
                :opacity="node.metricOpacity"
              >
                {{ node.metricLabel }}
              </text>
            </g>
          </g>

          <g v-else class="host-radar-empty">
            <text
              :x="stageCenterX"
              :y="stageCenterY - 10"
              text-anchor="middle"
              fill="rgba(230, 239, 252, 0.94)"
              font-size="18px"
              font-weight="700"
            >
              Waiting for host conversations
            </text>
            <text
              :x="stageCenterX"
              :y="stageCenterY + 18"
              text-anchor="middle"
              fill="rgba(164, 193, 220, 0.82)"
              font-size="12px"
            >
              Loopback and private hosts remain visible as history while live attack lanes animate from source to target.
            </text>
          </g>
        </svg>

        <div class="host-radar-overlay">
          <div class="host-radar-overlay__eyebrow">Host Graph View</div>
          <div class="host-radar-overlay__copy">
            Loopback and private hosts stay in the live node graph while packet attacks animate from source to destination and older nodes fade into history. Public endpoints are on the world map above.
          </div>
        </div>

        <div class="host-radar-legend">
          <span class="legend-chip legend-chip--live">Live attack</span>
          <span class="legend-chip legend-chip--history">Historical host</span>
          <span class="legend-chip legend-chip--pc">Node icon</span>
          <span class="legend-chip legend-chip--alert">Alert count</span>
        </div>
      </div>

      <div class="host-radar-summary">
        <div class="summary-card">
          <div class="summary-card__label">Live hosts</div>
          <div class="summary-card__value">{{ activeHostCount }}</div>
        </div>
        <div class="summary-card">
          <div class="summary-card__label">Historical hosts</div>
          <div class="summary-card__value">{{ historicalHostCount }}</div>
        </div>
        <div class="summary-card">
          <div class="summary-card__label">Live lanes</div>
          <div class="summary-card__value">{{ activeArcPaths.length }}</div>
        </div>
        <div class="summary-card">
          <div class="summary-card__label">Busiest node</div>
          <div class="summary-card__value summary-card__value--sm">{{ busiestHostLabel }}</div>
        </div>
      </div>

      <div v-if="hotLanes.length" class="host-radar-lanes">
        <div v-for="lane in hotLanes" :key="lane.id" class="lane-card">
          <div class="lane-card__route">{{ compactIp(lane.source) }} -> {{ compactIp(lane.target) }}</div>
          <div class="lane-card__meta">
            {{ lane.packets }} packets · {{ lane.protocolLabel || "unknown" }} · {{ lane.activeNow ? "live" : "historical" }}
          </div>
        </div>
      </div>
    </div>
  </DataPanel>
</template>

<script>
import DataPanel from "./ui/DataPanel.vue";

const STAGE_WIDTH = 980;
const STAGE_HEIGHT = 560;
const STAGE_PADDING = 20;
const MAX_VISIBLE_HOSTS = 24;
const MAX_VISIBLE_LINKS = 28;
const MAX_HISTORICAL_HOSTS = 42;
const MAX_HISTORICAL_LINKS = 64;
const HISTORY_RETENTION_MS = 1000 * 60 * 45;

function normalizeIp(value) {
  return String(value || "").trim();
}

function normalizeProto(value) {
  return String(value || "unknown").trim().toLowerCase() || "unknown";
}

// The radar answers "what is talking inside my network", so it is scoped to
// loopback and private addresses. Public endpoints are still captured, still
// counted, and still plotted on the world map above - they are simply not
// what this graph is for, and a handful of CDN addresses used to crowd out
// the LAN hosts it exists to show.
const RADAR_SCOPES = new Set(["local", "private"]);

function isRenderableHost(ip) {
  const normalized = normalizeIp(ip);
  if (!normalized) return false;
  return RADAR_SCOPES.has(classifyHost(normalized));
}

function parseIpv4Octets(value) {
  const match = String(value || "").match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!match) return null;
  const octets = match.slice(1).map((item) => Number(item));
  return octets.every((item) => Number.isInteger(item) && item >= 0 && item <= 255)
    ? octets
    : null;
}

function classifyHost(ip, fallbackPrivate = false) {
  const raw = normalizeIp(ip).toLowerCase();
  if (!raw) return fallbackPrivate ? "private" : "public";
  if (raw === "localhost" || raw === "::1") return "local";
  if (raw === "::") return "reserved";
  if (raw.includes(":")) {
    if (raw.startsWith("fe80:")) return "local";
    if (raw.startsWith("fc") || raw.startsWith("fd")) return "private";
    if (raw.startsWith("ff")) return "multicast";
    if (raw.startsWith("2001:db8")) return "reserved";
    return "public";
  }

  const octets = parseIpv4Octets(raw);
  if (!octets) return fallbackPrivate ? "private" : "public";
  const [a, b, c, d] = octets;

  if (a === 127) return "local";
  if (a === 169 && b === 254) return "local";
  if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) return "private";
  if (a === 100 && b >= 64 && b <= 127) return "private";
  if (a === 198 && (b === 18 || b === 19)) return "private";
  if (a >= 224 && a <= 239) return "multicast";
  if (a === 0 || a >= 240 || (a === 255 && b === 255 && c === 255 && d === 255)) return "reserved";
  if (a === 192 && b === 0 && c === 0) return "reserved";
  if (a === 192 && b === 0 && c === 2) return "reserved";
  if (a === 192 && b === 88 && c === 99) return "reserved";
  if (a === 198 && b === 51 && c === 100) return "reserved";
  if (a === 203 && b === 0 && c === 113) return "reserved";
  return "public";
}

function stableHash(value) {
  const text = String(value || "");
  let hash = 0;
  for (let index = 0; index < text.length; index += 1) {
    hash = ((hash * 33) + text.charCodeAt(index)) >>> 0;
  }
  return hash || 1;
}

function protoPalette(proto) {
  if (proto === "tcp") {
    return {
      stroke: "rgba(93, 204, 255, 0.82)",
      glow: "rgba(93, 204, 255, 0.36)",
      trace: "rgba(162, 230, 255, 0.98)",
    };
  }
  if (proto === "udp") {
    return {
      stroke: "rgba(94, 244, 186, 0.8)",
      glow: "rgba(94, 244, 186, 0.34)",
      trace: "rgba(179, 255, 224, 0.98)",
    };
  }
  if (proto === "icmp" || proto === "icmpv6") {
    return {
      stroke: "rgba(255, 187, 98, 0.84)",
      glow: "rgba(255, 187, 98, 0.34)",
      trace: "rgba(255, 228, 182, 0.98)",
    };
  }
  return {
    stroke: "rgba(164, 142, 255, 0.76)",
    glow: "rgba(164, 142, 255, 0.3)",
    trace: "rgba(219, 211, 255, 0.96)",
  };
}

function scopeTheme(scope, emphasis = 0) {
  if (scope === "public") {
    return {
      body: emphasis >= 2 ? "rgba(255, 92, 112, 0.92)" : "rgba(46, 138, 255, 0.92)",
      screen: emphasis >= 2 ? "rgba(255, 204, 210, 0.94)" : "rgba(165, 223, 255, 0.95)",
      ring: emphasis >= 2 ? "rgba(255, 151, 166, 0.88)" : "rgba(116, 214, 255, 0.84)",
      glow: emphasis >= 2 ? "rgba(255, 92, 112, 0.42)" : "rgba(46, 138, 255, 0.34)",
      badge: emphasis >= 2 ? "rgba(255, 211, 111, 0.95)" : "rgba(126, 244, 255, 0.94)",
      base: emphasis >= 2 ? "rgba(255, 134, 148, 0.88)" : "rgba(126, 214, 255, 0.88)",
    };
  }
  if (scope === "local") {
    return {
      body: "rgba(255, 183, 82, 0.94)",
      screen: "rgba(255, 234, 192, 0.95)",
      ring: "rgba(255, 209, 144, 0.86)",
      glow: "rgba(255, 183, 82, 0.38)",
      badge: "rgba(255, 109, 109, 0.94)",
      base: "rgba(255, 214, 150, 0.88)",
    };
  }
  return {
    body: emphasis >= 2 ? "rgba(243, 177, 75, 0.92)" : "rgba(56, 205, 153, 0.9)",
    screen: emphasis >= 2 ? "rgba(255, 232, 187, 0.95)" : "rgba(194, 255, 233, 0.95)",
    ring: emphasis >= 2 ? "rgba(255, 217, 155, 0.84)" : "rgba(135, 251, 210, 0.82)",
    glow: emphasis >= 2 ? "rgba(243, 177, 75, 0.36)" : "rgba(56, 205, 153, 0.34)",
    badge: emphasis >= 2 ? "rgba(255, 121, 121, 0.95)" : "rgba(105, 233, 199, 0.94)",
    base: emphasis >= 2 ? "rgba(255, 208, 133, 0.86)" : "rgba(143, 255, 217, 0.88)",
  };
}

// Mirrors the theme colors in main.js (Vuetify "error"/"warning"/"info") so
// the alert badge reads consistently with severity chips elsewhere in the app.
function severityBadgeTheme(severity) {
  const normalized = String(severity || "").trim().toLowerCase();
  if (normalized === "critical" || normalized === "high") {
    return { fill: "#ff647a", ring: "rgba(255, 189, 199, 0.9)" };
  }
  if (normalized === "medium") {
    return { fill: "#f5bb62", ring: "rgba(255, 224, 173, 0.9)" };
  }
  return { fill: "#4b8fff", ring: "rgba(178, 205, 255, 0.9)" };
}

export default {
  name: "HostRadarPanel",
  components: {
    DataPanel,
  },
  props: {
    snapshot: {
      type: Object,
      default: () => ({}),
    },
    topHosts: {
      type: Array,
      default: () => [],
    },
    // Per-IP alert rollup built by the parent view from recent monitor hits:
    // { [ip]: { count: number, severity: "critical"|"high"|"medium"|"low" } }.
    hostAlerts: {
      type: Object,
      default: () => ({}),
    },
    title: {
      type: String,
      default: "Host Transit Radar",
    },
    subtitle: {
      type: String,
      default: "Animated source-to-target packet flow with historical workstation nodes.",
    },
    loading: {
      type: Boolean,
      default: false,
    },
    error: {
      type: String,
      default: "",
    },
    lastUpdated: {
      type: String,
      default: "",
    },
    showRefresh: {
      type: Boolean,
      default: false,
    },
    liveRefresh: {
      type: Boolean,
      default: false,
    },
    liveEnabled: {
      type: Boolean,
      default: false,
    },
    showHeader: {
      type: Boolean,
      default: true,
    },
  },
  emits: ["refresh", "update:liveEnabled"],
  data() {
    return {
      stageWidth: STAGE_WIDTH,
      stageHeight: STAGE_HEIGHT,
      stagePadding: STAGE_PADDING,
      stageUid: Math.random().toString(16).slice(2, 10),
      historicalHosts: [],
      historicalLinks: [],
    };
  },
  computed: {
    stageCenterX() {
      return this.stageWidth / 2;
    },
    stageCenterY() {
      return this.stageHeight / 2 + 4;
    },
    stageGlowGradientId() {
      return `host-stage-glow-${this.stageUid}`;
    },
    frameGradientId() {
      return `host-stage-frame-${this.stageUid}`;
    },
    arcGlowFilterId() {
      return `host-stage-arc-${this.stageUid}`;
    },
    nodeGlowFilterId() {
      return `host-stage-node-${this.stageUid}`;
    },
    attackMarkerId() {
      return `host-stage-attack-${this.stageUid}`;
    },
    backdropPaths() {
      return [
        {
          id: "mesh-left",
          d: this.buildBackdropArc(96, 336, 534, 152, -1, 0.2),
          stroke: "rgba(86, 214, 255, 0.18)",
          strokeWidth: 1.1,
          dash: "",
          opacity: 0.82,
        },
        {
          id: "mesh-core",
          d: this.buildBackdropArc(172, 244, 810, 230, 1, 0.16),
          stroke: "rgba(96, 245, 189, 0.14)",
          strokeWidth: 0.96,
          dash: "9 14",
          opacity: 0.9,
        },
        {
          id: "mesh-right",
          d: this.buildBackdropArc(440, 146, 886, 332, 1, 0.18),
          stroke: "rgba(255, 186, 114, 0.16)",
          strokeWidth: 1.06,
          dash: "",
          opacity: 0.8,
        },
        {
          id: "mesh-history",
          d: this.buildBackdropArc(84, 410, 896, 406, -1, 0.08),
          stroke: "rgba(122, 188, 255, 0.12)",
          strokeWidth: 0.9,
          dash: "6 16",
          opacity: 0.82,
        },
      ];
    },
    aggregatedLinks() {
      const raw = Array.isArray(this.snapshot && this.snapshot.links) ? this.snapshot.links : [];
      const byKey = new Map();
      raw.forEach((row) => {
        const source = normalizeIp(row && row.source);
        const target = normalizeIp(row && row.target);
        if (!source || !target) return;
        if (!isRenderableHost(source) || !isRenderableHost(target)) return;
        const proto = normalizeProto(row && row.proto);
        const bytes = Math.max(1, Number(row && row.value) || 1);
        const key = `${source}__${target}`;
        if (!byKey.has(key)) {
          byKey.set(key, {
            id: key,
            source,
            target,
            packets: 0,
            bytes: 0,
            protoCounts: {},
          });
        }
        const entry = byKey.get(key);
        entry.packets += 1;
        entry.bytes += bytes;
        entry.protoCounts[proto] = (entry.protoCounts[proto] || 0) + 1;
      });
      return Array.from(byKey.values())
        .map((entry) => {
          const protocols = Object.entries(entry.protoCounts)
            .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]))
            .map(([proto]) => proto);
          return {
            ...entry,
            protocols,
            dominantProto: protocols[0] || "unknown",
            protocolLabel: protocols.slice(0, 3).join(", "),
            weight: (entry.packets * 8) + (Math.log10(entry.bytes + 10) * 22),
          };
        })
        .sort((left, right) => right.weight - left.weight || left.id.localeCompare(right.id));
    },
    hostIndex() {
      const hosts = new Map();
      const seedHost = (row, fallbackPrivate = false) => {
        const ip = normalizeIp(row && (row.ip || row.id || row.label));
        // Same scope restriction as the links: a public host seeded from
        // public_points or topHosts would otherwise appear as an isolated
        // node with no edges, since every link touching it was dropped.
        if (!ip || !isRenderableHost(ip)) return null;
        if (!hosts.has(ip)) {
          const explicitScope = String(row && row.scope ? row.scope : "").trim().toLowerCase();
          hosts.set(ip, {
            ip,
            label: ip,
            scope: explicitScope || classifyHost(ip, Boolean((row && row.private) || fallbackPrivate)),
            openPorts: 0,
            trafficPackets: 0,
            trafficBytes: 0,
            linkCount: 0,
            outgoingPackets: 0,
            incomingPackets: 0,
            outgoingBytes: 0,
            incomingBytes: 0,
            protocols: new Set(),
          });
        }
        return hosts.get(ip);
      };

      const publicPoints = Array.isArray(this.snapshot && this.snapshot.public_points)
        ? this.snapshot.public_points
        : [];
      const privateHosts = Array.isArray(this.snapshot && this.snapshot.private_hosts)
        ? this.snapshot.private_hosts
        : [];
      publicPoints.forEach((row) => seedHost(row, false));
      privateHosts.forEach((row) => seedHost(row, true));
      this.topHosts.forEach((row) => seedHost(row, false));

      this.aggregatedLinks.forEach((link) => {
        const sourceHost = seedHost({ ip: link.source }, false);
        const targetHost = seedHost({ ip: link.target }, false);
        if (sourceHost) {
          sourceHost.trafficPackets += link.packets;
          sourceHost.trafficBytes += link.bytes;
          sourceHost.linkCount += 1;
          sourceHost.outgoingPackets += link.packets;
          sourceHost.outgoingBytes += link.bytes;
          link.protocols.forEach((proto) => sourceHost.protocols.add(proto));
        }
        if (targetHost) {
          targetHost.trafficPackets += link.packets;
          targetHost.trafficBytes += link.bytes;
          targetHost.linkCount += 1;
          targetHost.incomingPackets += link.packets;
          targetHost.incomingBytes += link.bytes;
          link.protocols.forEach((proto) => targetHost.protocols.add(proto));
        }
      });

      this.topHosts.forEach((row) => {
        const ip = normalizeIp(row && (row.ip || row.label));
        if (!ip || !hosts.has(ip)) return;
        hosts.get(ip).openPorts = Math.max(
          hosts.get(ip).openPorts,
          Number(row && (row.value || row.open_ports || row.open_port_count)) || 0
        );
      });

      return Array.from(hosts.values())
        .map((host) => {
          const protocols = Array.from(host.protocols).sort();
          const emphasis = host.openPorts >= 12 || host.trafficPackets >= 18
            ? 2
            : host.openPorts >= 6 || host.trafficPackets >= 10
              ? 1
              : 0;
          const role = host.outgoingPackets >= (host.incomingPackets * 1.28) && host.outgoingPackets >= 2
            ? "source"
            : host.incomingPackets >= (host.outgoingPackets * 1.28) && host.incomingPackets >= 2
              ? "target"
              : "relay";
          const theme = scopeTheme(host.scope, emphasis);
          const score = (host.trafficPackets * 7) +
            (Math.min(48, host.openPorts) * 4) +
            (Math.log10(host.trafficBytes + 10) * 18);
          const alertInfo = this.hostAlerts && this.hostAlerts[host.ip];
          const alertCount = Math.max(0, Number(alertInfo && alertInfo.count) || 0);
          const alertTheme = alertCount > 0 ? severityBadgeTheme(alertInfo.severity) : null;
          return {
            ...host,
            protocols,
            emphasis,
            role,
            score,
            metricLabel: host.openPorts > 0 ? `${host.openPorts} ports` : `${host.trafficPackets} pkts`,
            ...theme,
            alertCount,
            alertSeverity: alertCount > 0 ? String(alertInfo.severity || "").trim().toLowerCase() : "",
            alertFill: alertTheme ? alertTheme.fill : "",
            alertRing: alertTheme ? alertTheme.ring : "",
          };
        })
        .sort((left, right) => right.score - left.score || left.ip.localeCompare(right.ip));
    },
    visibleNodes() {
      const selected = [];
      const seen = new Set();
      const hostLookup = new Map(this.historicalHosts.map((host) => [host.ip, host]));
      const pushHost = (value) => {
        const host = typeof value === "string" ? hostLookup.get(value) : value;
        if (!host || seen.has(host.ip) || selected.length >= MAX_VISIBLE_HOSTS) return;
        selected.push(host);
        seen.add(host.ip);
      };

      this.historicalLinks.slice(0, MAX_VISIBLE_LINKS).forEach((link) => {
        pushHost(link.source);
        pushHost(link.target);
      });
      this.historicalHosts.forEach((host) => pushHost(host));
      return selected;
    },
    layoutNodes() {
      const nodes = this.visibleNodes.slice(0, MAX_VISIBLE_HOSTS);
      if (!nodes.length) return [];
      return this.layoutPinnedNodes(nodes).slice(0, MAX_VISIBLE_HOSTS);
    },
    visibleLinks() {
      const visibleIps = new Set(this.layoutNodes.map((node) => node.ip));
      const rawLinks = this.historicalLinks
        .filter((link) => visibleIps.has(link.source) && visibleIps.has(link.target))
        .slice(0, MAX_VISIBLE_LINKS);
      const pairCounts = new Map();
      return rawLinks.map((link) => {
        const pairKey = [link.source, link.target].sort().join("__");
        const pairCount = pairCounts.get(pairKey) || 0;
        pairCounts.set(pairKey, pairCount + 1);
        return {
          ...link,
          curveSign: pairCount % 2 === 1 ? -1 : 1,
          curveLevel: Math.floor(pairCount / 2) + 1,
        };
      });
    },
    arcPaths() {
      const nodeLookup = new Map(this.layoutNodes.map((node) => [node.ip, node]));
      return this.visibleLinks
        .map((link, index) => {
          const source = nodeLookup.get(link.source);
          const target = nodeLookup.get(link.target);
          if (!source || !target) return null;
          const palette = protoPalette(link.dominantProto);
          const strength = Math.max(1, Math.min(2.4, 1 + (Math.log2((link.packets || 0) + 1) * 0.28)));
          const laneOpacity = link.activeNow
            ? 0.92
            : Math.max(0.2, (Number(link.staleFactor) || 0.2) * 0.52);
          return {
            id: `${link.id}-${index}`,
            source,
            target,
            active: Boolean(link.activeNow),
            d: this.buildArcPath(source, target, link.curveSign, link.curveLevel),
            stroke: palette.stroke,
            glow: palette.glow,
            traceColor: palette.trace,
            strokeWidth: strength,
            strokeOpacity: laneOpacity,
            glowOpacity: link.activeNow ? 0.18 : Math.max(0.06, laneOpacity * 0.38),
            traceRadius: Math.max(2.4, Math.min(4.2, 2.1 + (Math.log2((link.packets || 0) + 1) * 0.34))),
            traceGlow: palette.glow,
            traceStroke: "rgba(236, 246, 255, 0.88)",
            traceOpacity: link.activeNow ? 0.98 : Math.max(0.46, laneOpacity * 0.96),
            traceGlowOpacity: link.activeNow ? 0.34 : Math.max(0.16, laneOpacity * 0.54),
            duration: `${(2.7 + ((index % 5) * 0.22)).toFixed(2)}s`,
            begin: `${(index % 7) * 0.15}s`,
            markerEnd: link.activeNow ? `url(#${this.attackMarkerId})` : "",
            style: {
              animationDuration: `${(2.5 + ((index % 4) * 0.24)).toFixed(2)}s`,
              animationDelay: `${(index % 6) * 0.11}s`,
            },
          };
        })
        .filter(Boolean);
    },
    activeArcPaths() {
      return this.arcPaths.filter((arc) => arc.active);
    },
    activeHostCount() {
      return this.historicalHosts.filter((host) => host.activeNow).length;
    },
    historicalHostCount() {
      return this.historicalHosts.filter((host) => !host.activeNow).length;
    },
    visibleProtocolCount() {
      return new Set(this.visibleLinks.flatMap((link) => link.protocols || [])).size;
    },
    busiestHostLabel() {
      const hot = this.historicalHosts[0];
      return hot ? this.compactIp(hot.ip) : "n/a";
    },
    hotLanes() {
      return this.visibleLinks.slice(0, 6);
    },
  },
  watch: {
    snapshot: {
      immediate: true,
      handler() {
        this.syncHistoryFromCurrentData();
      },
    },
    topHosts: {
      handler() {
        this.syncHistoryFromCurrentData();
      },
    },
  },
  methods: {
    compactIp(value) {
      const ip = normalizeIp(value);
      if (ip.length <= 18) return ip;
      return `${ip.slice(0, 9)}...${ip.slice(-6)}`;
    },
    layoutPinnedNodes(nodes) {
      const ordered = [...nodes].sort((left, right) =>
        Number(right.activeNow) - Number(left.activeNow) ||
        right.score - left.score ||
        (right.lastSeenAt || 0) - (left.lastSeenAt || 0) ||
        left.ip.localeCompare(right.ip)
      );
      const totalNodes = ordered.length || 1;
      return ordered.map((node) => {
        const x = Number.isFinite(Number(node.fixedX)) ? Number(node.fixedX) : this.stageCenterX;
        const y = Number.isFinite(Number(node.fixedY)) ? Number(node.fixedY) : this.stageCenterY;
        const baseScale = node.activeNow
          ? (totalNodes >= 18 ? 0.42 : totalNodes >= 12 ? 0.48 : totalNodes >= 8 ? 0.54 : 0.6)
          : (totalNodes >= 18 ? 0.32 : totalNodes >= 12 ? 0.35 : totalNodes >= 8 ? 0.38 : 0.42);
        return this.decorateGraphNode(node, x, y, baseScale, totalNodes);
      });
    },
    fixedGraphSlots() {
      const centerX = this.stageCenterX;
      const centerY = this.stageCenterY;
      const groups = {
        core: [
          [-120, -32], [-58, -84], [34, -92], [116, -44], [-108, 64],
          [-18, 10], [70, 28], [134, 90], [-42, 118], [48, 134],
        ],
        source: [
          [-208, -98], [-258, -24], [-230, 76], [-318, -112], [-342, -2],
          [-300, 110], [-386, -86], [-394, 34], [-344, 176], [-242, 172],
        ],
        target: [
          [208, -98], [258, -24], [230, 76], [318, -112], [342, -2],
          [300, 110], [386, -86], [394, 34], [344, 176], [242, 172],
        ],
        local: [
          [-164, 178], [-88, 194], [0, 184], [92, 198], [168, 180], [0, 236],
        ],
        history: [
          [-132, -154], [0, -162], [132, -154], [-398, 72], [398, 68],
          [-364, 202], [364, 198], [-236, -126], [236, -126],
        ],
      };
      return Object.entries(groups).flatMap(([group, offsets]) =>
        offsets.map(([dx, dy], index) => ({
          key: `${group}-${index}`,
          group,
          x: centerX + dx,
          y: centerY + dy,
        }))
      );
    },
    preferredSlotGroups(node) {
      const groups = [];
      if (!node.activeNow) groups.push("history");
      if (node.role === "source") groups.push("source");
      else if (node.role === "target") groups.push("target");
      else groups.push("core");
      if (node.scope === "local" || node.scope === "private") groups.push("local");
      groups.push("core", "history", "source", "target", "local");
      return Array.from(new Set(groups));
    },
    slotPreferenceScore(node, slot) {
      const groupOrder = this.preferredSlotGroups(node);
      const groupRank = Math.max(0, groupOrder.indexOf(slot.group));
      const centerDistance = Math.hypot(slot.x - this.stageCenterX, slot.y - this.stageCenterY);
      const agePenalty = node.activeNow ? 0 : Math.min(140, (Number(node.historyAgeMs) || 0) / 90000);
      const jitter = (stableHash(`${node.ip}:${slot.key}`) % 1000) / 1000;
      return (groupRank * 1000) + centerDistance + agePenalty + (jitter * 14);
    },
    reconcileFixedNodePositions(hosts) {
      const slots = this.fixedGraphSlots();
      const slotByKey = new Map(slots.map((slot) => [slot.key, slot]));
      const previousHosts = new Map(this.historicalHosts.map((host) => [host.ip, host]));
      const assignments = new Map();
      const claimedSlots = new Set();

      hosts.forEach((host) => {
        const previous = previousHosts.get(host.ip);
        const previousKey = previous && previous.layoutSlotKey;
        const previousSlot = previousKey ? slotByKey.get(previousKey) : null;
        if (!previousSlot || claimedSlots.has(previousSlot.key)) return;
        claimedSlots.add(previousSlot.key);
        assignments.set(host.ip, {
          slotKey: previousSlot.key,
          x: previousSlot.x,
          y: previousSlot.y,
        });
      });

      hosts
        .filter((host) => !assignments.has(host.ip))
        .forEach((host) => {
          const availableSlots = slots.filter((slot) => !claimedSlots.has(slot.key));
          if (!availableSlots.length) {
            assignments.set(host.ip, {
              slotKey: `fallback-${host.ip}`,
              x: this.stageCenterX,
              y: this.stageCenterY,
            });
            return;
          }
          const bestSlot = availableSlots
            .map((slot) => ({
              slot,
              score: this.slotPreferenceScore(host, slot),
            }))
            .sort((left, right) => left.score - right.score || left.slot.key.localeCompare(right.slot.key))[0].slot;
          claimedSlots.add(bestSlot.key);
          assignments.set(host.ip, {
            slotKey: bestSlot.key,
            x: bestSlot.x,
            y: bestSlot.y,
          });
        });

      return assignments;
    },
    layoutRelationshipGraph(nodes) {
      const ordered = [...nodes].sort((left, right) =>
        Number(right.activeNow) - Number(left.activeNow) ||
        right.score - left.score ||
        (right.lastSeenAt || 0) - (left.lastSeenAt || 0) ||
        left.ip.localeCompare(right.ip)
      );
      if (!ordered.length) return [];
      if (ordered.length === 1) {
        return [this.decorateGraphNode(ordered[0], this.stageCenterX, this.stageCenterY - 24, 0.62, ordered.length)];
      }

      const nodeIds = new Set(ordered.map((node) => node.ip));
      const relationLinks = this.historicalLinks
        .filter((link) => nodeIds.has(link.source) && nodeIds.has(link.target))
        .slice(0, MAX_VISIBLE_LINKS);

      const degreeMap = new Map(ordered.map((node) => [node.ip, 0]));
      relationLinks.forEach((link) => {
        degreeMap.set(link.source, (degreeMap.get(link.source) || 0) + 1);
        degreeMap.set(link.target, (degreeMap.get(link.target) || 0) + 1);
      });

      const anchor = ordered.reduce((best, node) => {
        const weight = (Number(node.activeNow) * 220) + ((degreeMap.get(node.ip) || 0) * 38) + Number(node.score || 0);
        if (!best || weight > best.weight) {
          return { node, weight };
        }
        return best;
      }, null)?.node || ordered[0];

      const totalNodes = ordered.length;
      const centerX = this.stageCenterX;
      const centerY = this.stageCenterY - (totalNodes >= 10 ? 4 : 18);
      const innerRadiusX = 136 + Math.min(72, totalNodes * 5.5);
      const innerRadiusY = 92 + Math.min(56, totalNodes * 3.6);
      const outerRadiusX = innerRadiusX + 88;
      const outerRadiusY = innerRadiusY + 74;
      const farRadiusX = outerRadiusX + 54;
      const farRadiusY = outerRadiusY + 38;
      const bounds = {
        minX: 86,
        maxX: this.stageWidth - 86,
        minY: 118,
        maxY: this.stageHeight - 74,
      };

      const positions = new Map();
      ordered.forEach((node, index) => {
        if (node.ip === anchor.ip) {
          positions.set(node.ip, {
            x: centerX,
            y: centerY - 12,
            vx: 0,
            vy: 0,
            fixed: true,
          });
          return;
        }
        const hash = stableHash(node.ip);
        const jitter = ((hash % 1000) / 1000) - 0.5;
        const activeBias = node.activeNow ? 0 : 1;
        const ring = index <= 6
          ? 0
          : index <= 14
            ? 1
            : 2;
        let angleDeg = 90;
        if (node.role === "source") angleDeg = 208;
        else if (node.role === "target") angleDeg = 332;
        else if (node.scope === "local") angleDeg = 258;
        else if (node.scope === "multicast" || node.scope === "reserved") angleDeg = 20;
        const angle = (angleDeg + (jitter * (node.activeNow ? 58 : 96))) * (Math.PI / 180);
        const radiusX = ring === 0 ? innerRadiusX : ring === 1 ? outerRadiusX : farRadiusX;
        const radiusY = ring === 0 ? innerRadiusY : ring === 1 ? outerRadiusY : farRadiusY;
        positions.set(node.ip, {
          x: centerX + (Math.cos(angle) * radiusX * (1 + (activeBias * 0.08))),
          y: centerY + (Math.sin(angle) * radiusY * (1 + (activeBias * 0.12))),
          vx: 0,
          vy: 0,
          fixed: false,
        });
      });

      for (let step = 0; step < 54; step += 1) {
        for (let index = 0; index < ordered.length; index += 1) {
          for (let otherIndex = index + 1; otherIndex < ordered.length; otherIndex += 1) {
            const left = ordered[index];
            const right = ordered[otherIndex];
            const lp = positions.get(left.ip);
            const rp = positions.get(right.ip);
            if (!lp || !rp) continue;
            const dx = rp.x - lp.x;
            const dy = rp.y - lp.y;
            const distance = Math.max(1, Math.hypot(dx, dy));
            const repulsion = Math.min(26, (12000 / (distance * distance)));
            const nx = dx / distance;
            const ny = dy / distance;
            if (!lp.fixed) {
              lp.vx -= nx * repulsion;
              lp.vy -= ny * repulsion;
            }
            if (!rp.fixed) {
              rp.vx += nx * repulsion;
              rp.vy += ny * repulsion;
            }
          }
        }

        relationLinks.forEach((link) => {
          const sourcePos = positions.get(link.source);
          const targetPos = positions.get(link.target);
          if (!sourcePos || !targetPos) return;
          const dx = targetPos.x - sourcePos.x;
          const dy = targetPos.y - sourcePos.y;
          const distance = Math.max(1, Math.hypot(dx, dy));
          const ideal = link.activeNow ? 146 : 182;
          const spring = (distance - ideal) * 0.015;
          const nx = dx / distance;
          const ny = dy / distance;
          if (!sourcePos.fixed) {
            sourcePos.vx += nx * spring;
            sourcePos.vy += ny * spring;
          }
          if (!targetPos.fixed) {
            targetPos.vx -= nx * spring;
            targetPos.vy -= ny * spring;
          }
        });

        ordered.forEach((node) => {
          const position = positions.get(node.ip);
          if (!position || position.fixed) return;
          const target = this.preferredGraphTarget(node, {
            centerX,
            centerY,
            innerRadiusX,
            innerRadiusY,
            outerRadiusX,
            outerRadiusY,
            farRadiusX,
            farRadiusY,
            totalNodes,
          });
          position.vx += (target.x - position.x) * 0.0054;
          position.vy += (target.y - position.y) * 0.0054;
          position.x += position.vx;
          position.y += position.vy;
          position.vx *= 0.8;
          position.vy *= 0.8;
          position.x = Math.max(bounds.minX, Math.min(bounds.maxX, position.x));
          position.y = Math.max(bounds.minY, Math.min(bounds.maxY, position.y));
        });
      }

      return this.resolveNodeCollisions(
        ordered.map((node) => {
          const position = positions.get(node.ip) || { x: centerX, y: centerY };
          const baseScale = node.activeNow
            ? (totalNodes >= 18 ? 0.42 : totalNodes >= 12 ? 0.48 : totalNodes >= 8 ? 0.54 : 0.6)
            : (totalNodes >= 18 ? 0.32 : totalNodes >= 12 ? 0.35 : totalNodes >= 8 ? 0.38 : 0.42);
          return this.decorateGraphNode(node, position.x, position.y, baseScale, totalNodes);
        }),
        {
          minDistance: totalNodes >= 18 ? 74 : totalNodes >= 12 ? 88 : 104,
          minX: bounds.minX,
          maxX: bounds.maxX,
          minY: bounds.minY,
          maxY: bounds.maxY,
          iterations: 6,
        }
      );
    },
    preferredGraphTarget(node, context) {
      const {
        centerX,
        centerY,
        innerRadiusX,
        innerRadiusY,
        outerRadiusX,
        outerRadiusY,
        farRadiusX,
        farRadiusY,
      } = context;
      const hash = stableHash(node.ip);
      const jitter = ((hash % 1000) / 1000) - 0.5;
      let angleDeg = 86;
      if (node.role === "source") angleDeg = 210;
      else if (node.role === "target") angleDeg = 334;
      else if (node.scope === "local") angleDeg = 260;
      else if (node.scope === "multicast" || node.scope === "reserved") angleDeg = 18;
      const angle = (angleDeg + (jitter * (node.activeNow ? 42 : 78))) * (Math.PI / 180);
      const radiusX = node.activeNow
        ? innerRadiusX
        : (node.historyAgeMs || 0) > (HISTORY_RETENTION_MS * 0.35) ? farRadiusX : outerRadiusX;
      const radiusY = node.activeNow
        ? innerRadiusY
        : (node.historyAgeMs || 0) > (HISTORY_RETENTION_MS * 0.35) ? farRadiusY : outerRadiusY;
      return {
        x: centerX + (Math.cos(angle) * radiusX),
        y: centerY + (Math.sin(angle) * radiusY),
      };
    },
    distributeActiveGraphNodes(nodes) {
      const ordered = [...nodes].sort((left, right) => right.score - left.score || left.ip.localeCompare(right.ip));
      if (!ordered.length) return [];
      if (ordered.length === 1) {
        return [this.decorateGraphNode(ordered[0], this.stageCenterX, 214, 0.72)];
      }
      if (ordered.length === 2) {
        return [
          this.decorateGraphNode(ordered[0], this.stageCenterX - 172, 224, 0.68),
          this.decorateGraphNode(ordered[1], this.stageCenterX + 172, 246, 0.68),
        ];
      }

      const anchor = ordered[0];
      const remainder = ordered.slice(1);
      const leftNodes = remainder.filter((node) => node.role === "source");
      const rightNodes = remainder.filter((node) => node.role === "target");
      const centerNodes = remainder.filter((node) => node.role !== "source" && node.role !== "target");
      const balancedCenter = centerNodes.concat(
        leftNodes.length > rightNodes.length ? leftNodes.splice(Math.ceil(leftNodes.length / 2)) : [],
        rightNodes.length > leftNodes.length ? rightNodes.splice(Math.ceil(rightNodes.length / 2)) : []
      );

      return this.resolveNodeCollisions([
        this.decorateGraphNode(anchor, this.stageCenterX, 186, 0.74),
        ...this.placeNodesOnArc(leftNodes, {
          centerX: 220,
          centerY: 252,
          radiusX: 142,
          radiusY: 132,
          startAngle: -138,
          endAngle: 58,
          baseScale: 0.6,
        }),
        ...this.placeNodesOnArc(balancedCenter, {
          centerX: this.stageCenterX,
          centerY: 308,
          radiusX: 286,
          radiusY: 104,
          startAngle: -176,
          endAngle: -4,
          baseScale: 0.56,
        }),
        ...this.placeNodesOnArc(rightNodes, {
          centerX: 760,
          centerY: 252,
          radiusX: 142,
          radiusY: 132,
          startAngle: 122,
          endAngle: 316,
          baseScale: 0.6,
        }),
      ], {
        minDistance: 124,
        minX: 90,
        maxX: this.stageWidth - 90,
        minY: 124,
        maxY: 392,
        iterations: 5,
      });
    },
    placeNodesOnArc(nodes, config = {}) {
      const ordered = [...nodes].sort((left, right) => right.score - left.score || left.ip.localeCompare(right.ip));
      if (!ordered.length) return [];
      const centerX = Number(config.centerX) || this.stageCenterX;
      const centerY = Number(config.centerY) || this.stageCenterY;
      const radiusX = Math.max(24, Number(config.radiusX) || 120);
      const radiusY = Math.max(18, Number(config.radiusY) || 80);
      const startAngle = (Number(config.startAngle) || -140) * (Math.PI / 180);
      const endAngle = (Number(config.endAngle) || -40) * (Math.PI / 180);
      const baseScale = Number(config.baseScale) || 0.58;
      return ordered.map((node, index) => {
        const progress = ordered.length === 1 ? 0.5 : index / (ordered.length - 1);
        const angle = startAngle + ((endAngle - startAngle) * progress);
        const sway = ((index % 2 === 0 ? 1 : -1) * Math.min(14, 7 + ordered.length));
        const x = centerX + (Math.cos(angle) * radiusX) + (Math.sin(angle) * sway * 0.14);
        const y = centerY + (Math.sin(angle) * radiusY) + ((index % 2 === 0 ? -1 : 1) * sway * 0.34);
        return this.decorateGraphNode(node, x, y, baseScale);
      });
    },
    decorateGraphNode(node, x, y, baseScale = 0.58, totalNodeCount = 1) {
      const densityFactor = totalNodeCount >= 18
        ? 0.74
        : totalNodeCount >= 12
          ? 0.82
          : totalNodeCount >= 8
            ? 0.9
            : 1;
      const iconScale = Math.min(0.74, (baseScale + (node.emphasis * 0.04) + (node.activeNow ? 0.02 : 0)) * densityFactor);
      const staleFactor = Math.max(0.3, Number(node.staleFactor || 0.34));
      const labelY = iconScale <= 0.34 ? 12 : iconScale <= 0.42 ? 15 : iconScale <= 0.5 ? 17 : 20;
      return {
        ...node,
        x,
        y,
        iconScale,
        haloRadius: (iconScale <= 0.4 ? 8.4 : 11.2) + (node.emphasis * 2.4),
        ringRadius: (iconScale <= 0.4 ? 6.2 : 8.2) + (node.emphasis * 1.7),
        labelY,
        metricY: labelY + (iconScale <= 0.4 ? 9 : 11),
        nodeOpacity: node.activeNow ? 1 : staleFactor,
        labelOpacity: node.activeNow ? 0.98 : Math.max(0.5, staleFactor),
        metricOpacity: node.activeNow ? 0.82 : Math.max(0.38, staleFactor * 0.92),
      };
    },
    resolveNodeCollisions(nodes, options = {}) {
      const minDistance = Math.max(24, Number(options.minDistance) || 96);
      const minX = Number(options.minX) || 80;
      const maxX = Number(options.maxX) || (this.stageWidth - 80);
      const minY = Number(options.minY) || 96;
      const maxY = Number(options.maxY) || (this.stageHeight - 96);
      const iterations = Math.max(1, Number(options.iterations) || 4);
      const working = nodes.map((node) => ({
        ...node,
        x: Number(node.x) || this.stageCenterX,
        y: Number(node.y) || this.stageCenterY,
      }));

      for (let round = 0; round < iterations; round += 1) {
        for (let index = 0; index < working.length; index += 1) {
          for (let otherIndex = index + 1; otherIndex < working.length; otherIndex += 1) {
            const node = working[index];
            const other = working[otherIndex];
            const dx = other.x - node.x;
            const dy = other.y - node.y;
            const distance = Math.hypot(dx, dy) || 0.001;
            if (distance >= minDistance) continue;
            const overlap = (minDistance - distance) / 2;
            const nx = dx / distance;
            const ny = dy / distance;
            node.x -= nx * overlap;
            node.y -= ny * overlap;
            other.x += nx * overlap;
            other.y += ny * overlap;
          }
        }
        working.forEach((node) => {
          node.x = Math.max(minX, Math.min(maxX, node.x));
          node.y = Math.max(minY, Math.min(maxY, node.y));
        });
      }

      return working;
    },
    distributeHistoricalNodes(nodes) {
      const ordered = [...nodes]
        .sort((left, right) => (right.lastSeenAt || 0) - (left.lastSeenAt || 0) || left.ip.localeCompare(right.ip))
        .slice(0, Math.max(0, MAX_VISIBLE_HOSTS));
      const firstRowCount = Math.min(12, ordered.length);
      const secondRowCount = Math.min(12, Math.max(0, ordered.length - firstRowCount));
      const rows = [
        ordered.slice(0, firstRowCount),
        ordered.slice(firstRowCount, firstRowCount + secondRowCount),
      ].filter((row) => row.length);

      const yPositions = [454, 502];
      return this.resolveNodeCollisions(rows.flatMap((row, rowIndex) => row.map((node, index) => {
        const progress = row.length === 1 ? 0.5 : index / (row.length - 1);
        const x = 106 + (progress * (this.stageWidth - 212));
        const archLift = Math.sin(progress * Math.PI) * (rowIndex === 0 ? 20 : 12);
        const baseNode = this.decorateGraphNode(node, x, (yPositions[rowIndex] || 502) - archLift, 0.34);
        return {
          ...baseNode,
          iconScale: Math.min(0.4, baseNode.iconScale),
          haloRadius: 6.8,
          ringRadius: 5.2,
          labelY: 14,
          metricY: 24,
          nodeOpacity: Math.max(0.34, Number(node.staleFactor || 0.34)),
          labelOpacity: Math.max(0.52, Number(node.staleFactor || 0.34)),
          metricOpacity: Math.max(0.4, Number(node.staleFactor || 0.34) * 0.92),
        };
      })), {
        minDistance: 74,
        minX: 90,
        maxX: this.stageWidth - 90,
        minY: 432,
        maxY: 516,
        iterations: 3,
      });
    },
    syncHistoryFromCurrentData() {
      const now = Date.now();
      const currentHosts = this.hostIndex;
      const currentLinks = this.aggregatedLinks;

      const hostMap = new Map(
        this.historicalHosts.map((host) => [
          host.ip,
          {
            ...host,
            protocols: Array.isArray(host.protocols) ? host.protocols.slice() : [],
            activeNow: false,
          },
        ])
      );

      currentHosts.forEach((host) => {
        const existing = hostMap.get(host.ip);
        hostMap.set(host.ip, {
          ...existing,
          ...host,
          firstSeenAt: existing && existing.firstSeenAt ? existing.firstSeenAt : now,
          lastSeenAt: now,
          activeNow: true,
        });
      });

      let hosts = Array.from(hostMap.values())
        .map((host) => {
          const historyAgeMs = Math.max(0, now - Number(host.lastSeenAt || now));
          const staleFactor = host.activeNow
            ? 1
            : Math.max(0.28, 1 - Math.min(0.72, historyAgeMs / HISTORY_RETENTION_MS));
          return {
            ...host,
            historyAgeMs,
            staleFactor,
            metricLabel: host.activeNow
              ? (host.openPorts > 0 ? `${host.openPorts} ports` : `${host.trafficPackets} pkts`)
              : `hist ${Math.max(1, Math.round(historyAgeMs / 60000))}m`,
          };
        })
        .filter((host) => host.activeNow || host.historyAgeMs <= HISTORY_RETENTION_MS)
        .sort((left, right) =>
          Number(right.activeNow) - Number(left.activeNow) ||
          right.score - left.score ||
          (right.lastSeenAt || 0) - (left.lastSeenAt || 0) ||
          left.ip.localeCompare(right.ip)
        )
        .slice(0, MAX_HISTORICAL_HOSTS);

      const hostWhitelist = new Set(hosts.map((host) => host.ip));
      const linkMap = new Map(
        this.historicalLinks.map((link) => [
          link.id,
          {
            ...link,
            protocols: Array.isArray(link.protocols) ? link.protocols.slice() : [],
            activeNow: false,
          },
        ])
      );

      currentLinks.forEach((link) => {
        const existing = linkMap.get(link.id);
        linkMap.set(link.id, {
          ...existing,
          ...link,
          firstSeenAt: existing && existing.firstSeenAt ? existing.firstSeenAt : now,
          lastSeenAt: now,
          activeNow: true,
        });
      });

      const links = Array.from(linkMap.values())
        .filter((link) => hostWhitelist.has(link.source) && hostWhitelist.has(link.target))
        .map((link) => {
          const historyAgeMs = Math.max(0, now - Number(link.lastSeenAt || now));
          const staleFactor = link.activeNow
            ? 1
            : Math.max(0.22, 1 - Math.min(0.78, historyAgeMs / HISTORY_RETENTION_MS));
          return {
            ...link,
            historyAgeMs,
            staleFactor,
          };
        })
        .filter((link) => link.activeNow || link.historyAgeMs <= HISTORY_RETENTION_MS)
        .sort((left, right) =>
          Number(right.activeNow) - Number(left.activeNow) ||
          right.weight - left.weight ||
          (right.lastSeenAt || 0) - (left.lastSeenAt || 0) ||
          left.id.localeCompare(right.id)
        )
        .slice(0, MAX_HISTORICAL_LINKS);

      hosts = hosts.filter((host) => {
        if (host.activeNow) return true;
        return links.some((link) => link.source === host.ip || link.target === host.ip) || host.historyAgeMs <= HISTORY_RETENTION_MS;
      });

      const fixedPositions = this.reconcileFixedNodePositions(hosts);
      hosts = hosts.map((host) => {
        const assigned = fixedPositions.get(host.ip);
        if (!assigned) return host;
        return {
          ...host,
          fixedX: assigned.x,
          fixedY: assigned.y,
          layoutSlotKey: assigned.slotKey,
        };
      });

      this.historicalHosts = hosts;
      this.historicalLinks = links;
    },
    buildArcPath(source, target, curveSign = 1, curveLevel = 1) {
      const sx = Number(source.x) || 0;
      const sy = Number(source.y) || 0;
      const tx = Number(target.x) || 0;
      const ty = Number(target.y) || 0;
      const dx = tx - sx;
      const dy = ty - sy;
      const distance = Math.hypot(dx, dy) || 1;
      const mx = (sx + tx) / 2;
      const my = (sy + ty) / 2;
      const nx = -dy / distance;
      const ny = dx / distance;
      const bend = Math.min(84, 18 + (distance * 0.12) + ((curveLevel - 1) * 12));
      const cx = mx + (nx * bend * curveSign);
      const cy = my + (ny * bend * curveSign);
      return `M${sx.toFixed(2)},${sy.toFixed(2)} Q${cx.toFixed(2)},${cy.toFixed(2)} ${tx.toFixed(2)},${ty.toFixed(2)}`;
    },
    buildBackdropArc(sx, sy, tx, ty, curveSign = 1, curvature = 0.18) {
      const dx = tx - sx;
      const dy = ty - sy;
      const distance = Math.hypot(dx, dy) || 1;
      const mx = (sx + tx) / 2;
      const my = (sy + ty) / 2;
      const nx = -dy / distance;
      const ny = dx / distance;
      const bend = Math.min(146, 18 + (distance * Math.max(0.04, curvature)));
      const cx = mx + (nx * bend * curveSign);
      const cy = my + (ny * bend * curveSign);
      return `M${sx.toFixed(2)},${sy.toFixed(2)} Q${cx.toFixed(2)},${cy.toFixed(2)} ${tx.toFixed(2)},${ty.toFixed(2)}`;
    },
    nodeTooltip(node) {
      const protocols = Array.isArray(node.protocols) && node.protocols.length
        ? node.protocols.join(", ")
        : "no protocol sample";
      const history = node.activeNow ? "live" : "historical";
      const alertPart = node.alertCount > 0
        ? ` | ${node.alertCount} ${node.alertSeverity} alert${node.alertCount === 1 ? "" : "s"}`
        : "";
      return `${node.ip} | ${node.scope || "unknown"} host | ${history} | ${node.trafficPackets} packets | ${node.openPorts} open ports | ${protocols}${alertPart}`;
    },
    navigateToHost(node) {
      if (!node || !node.ip || !this.$router) return;
      this.$router.push({ path: "/investigate", query: { ip: node.ip } });
    },
  },
};
</script>

<style scoped>
.host-radar-shell {
  display: grid;
  gap: 16px;
}

.host-radar-stage {
  position: relative;
  overflow: hidden;
  border-radius: 24px;
  border: 1px solid rgba(94, 176, 226, 0.22);
  background: linear-gradient(180deg, rgba(4, 12, 24, 0.99), rgba(3, 8, 16, 0.98));
  box-shadow:
    inset 0 0 0 1px rgba(255, 255, 255, 0.03),
    inset 0 26px 80px rgba(39, 110, 174, 0.08),
    0 24px 60px rgba(3, 8, 15, 0.42);
}

.host-radar-stage svg {
  display: block;
  width: 100%;
  height: clamp(360px, 48vw, 620px);
  aspect-ratio: 16 / 9;
}

.host-radar-overlay {
  position: absolute;
  top: 18px;
  left: 18px;
  max-width: min(420px, calc(100% - 36px));
  padding: 14px 16px;
  border-radius: 18px;
  border: 1px solid rgba(107, 194, 232, 0.16);
  background: linear-gradient(180deg, rgba(7, 16, 30, 0.84), rgba(5, 10, 18, 0.74));
  backdrop-filter: blur(12px);
  box-shadow: 0 14px 30px rgba(2, 8, 15, 0.34);
}

.host-radar-overlay__eyebrow {
  color: rgba(116, 232, 255, 0.92);
  font-size: 0.72rem;
  font-weight: 700;
  letter-spacing: 0.16em;
  text-transform: uppercase;
}

.host-radar-overlay__copy {
  margin-top: 8px;
  color: rgba(205, 223, 241, 0.86);
  font-size: 0.92rem;
  line-height: 1.55;
}

.host-radar-legend {
  position: absolute;
  right: 18px;
  bottom: 18px;
  display: flex;
  flex-wrap: wrap;
  justify-content: flex-end;
  gap: 8px;
  max-width: min(420px, calc(100% - 36px));
}

.legend-chip {
  padding: 6px 11px;
  border-radius: 999px;
  border: 1px solid transparent;
  background: rgba(6, 13, 25, 0.8);
  color: rgba(224, 237, 250, 0.94);
  font-size: 0.68rem;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  backdrop-filter: blur(10px);
}

.legend-chip--live {
  border-color: rgba(255, 187, 98, 0.9);
}

.legend-chip--history {
  border-color: rgba(164, 182, 205, 0.56);
}

.legend-chip--pc {
  border-color: rgba(93, 204, 255, 0.84);
}

.legend-chip--alert {
  border-color: rgba(255, 100, 122, 0.9);
}

.host-radar-alert-badge {
  pointer-events: none;
}

.host-radar-flow {
  stroke-dasharray: 10 13;
  animation: host-radar-flow 2.8s linear infinite;
}

.host-radar-trace {
  pointer-events: none;
  mix-blend-mode: screen;
}

.host-radar-node {
  cursor: pointer;
  transition: opacity 180ms ease;
}

.host-radar-node--historical {
  cursor: default;
}

.host-radar-summary {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px;
}

.summary-card {
  padding: 14px 16px;
  border-radius: 18px;
  border: 1px solid rgba(100, 184, 229, 0.14);
  background: linear-gradient(180deg, rgba(10, 17, 31, 0.88), rgba(6, 11, 19, 0.78));
}

.summary-card__label {
  color: rgba(157, 189, 216, 0.82);
  font-size: 0.72rem;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}

.summary-card__value {
  margin-top: 10px;
  color: rgba(239, 245, 255, 0.98);
  font-family: var(--font-heading);
  font-size: 1.32rem;
  font-weight: 680;
}

.summary-card__value--sm {
  font-size: 1rem;
}

.host-radar-lanes {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 12px;
}

.lane-card {
  padding: 14px 16px;
  border-radius: 16px;
  border: 1px solid rgba(96, 182, 226, 0.14);
  background:
    linear-gradient(180deg, rgba(8, 16, 28, 0.88), rgba(4, 9, 17, 0.82));
}

.lane-card__route {
  color: rgba(239, 245, 255, 0.96);
  font-size: 0.82rem;
  font-weight: 700;
  letter-spacing: 0.02em;
}

.lane-card__meta {
  margin-top: 6px;
  color: rgba(165, 196, 222, 0.84);
  font-size: 0.76rem;
  font-weight: 600;
}

@keyframes host-radar-flow {
  from {
    stroke-dashoffset: 52;
  }
  to {
    stroke-dashoffset: 0;
  }
}

@media (max-width: 1180px) {
  .host-radar-summary,
  .host-radar-lanes {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}

@media (max-width: 780px) {
  .host-radar-stage svg {
    height: clamp(340px, 78vw, 520px);
  }

  .host-radar-overlay,
  .host-radar-legend {
    left: 12px;
    right: 12px;
    max-width: none;
  }

  .host-radar-legend {
    left: auto;
    justify-content: flex-start;
  }

  .host-radar-summary,
  .host-radar-lanes {
    grid-template-columns: minmax(0, 1fr);
  }
}
</style>
