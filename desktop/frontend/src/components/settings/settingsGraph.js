import {
  connectionPath as routeConnection,
  graphBounds as boundsOf,
  validPositions as keepValidPositions,
} from "../../utils/flowGraph.js";

export const GRAPH_CARD = { width: 252, height: 176 };
// v2: the lane layout replaced the four-column one. Positions saved under v1
// would pin cards to the old geometry, so they are simply not read.
export const GRAPH_STORAGE_KEY = "sniff4hound.settingsGraphCards.v2";

// Colour groups for the cards: traffic path, operator-facing, system. Drawn as
// card accents only; no background or header per group.
export const GRAPH_LANES = [
  { color: "#54cbd8" },
  { color: "#b79aeb" },
  { color: "#e4b96c" },
];

export const SETTINGS_NODES = [
  // Group 0 - traffic flows left to right through the columns.
  { id: "runtime", section: "runtime", label: "Runtime", icon: "mdi-source-branch", lane: 0, column: 0, row: 0, detail: "Motores de captura" },
  { id: "location", section: "location", label: "Sensor", icon: "mdi-map-marker-outline", lane: 0, column: 0, row: 1, detail: "Ubicación del sensor" },
  { id: "honeypot", section: "honeypot", label: "Honeypot", icon: "mdi-spider-web", lane: 0, column: 1, row: 0, detail: "Puertos y listeners" },
  { id: "sniffer", section: "capture", label: "Sniffer", icon: "mdi-ethernet", lane: 0, column: 1, row: 1, detail: "Interfaces de red" },
  { id: "cache", section: "packetcache", label: "Caché de paquetes", icon: "mdi-cached", lane: 0, column: 2, row: 1, detail: "Retención de paquetes" },
  { id: "jobs", section: "packetjobs", label: "Jobs de procesamiento", icon: "mdi-cog-sync-outline", lane: 0, column: 3, row: 1, detail: "Procesan y persisten" },
  { id: "ai", section: "ai", label: "IA opcional", icon: "mdi-robot-outline", lane: 1, column: 4, row: 0, detail: "Análisis agregado" },
  { id: "monitors", section: "detection", label: "Monitores", icon: "mdi-radar", lane: 0, column: 4, row: 2, detail: "Reglas y severidad" },
  { id: "store", section: "storage", label: "SniffStore", icon: "mdi-database-outline", lane: 0, column: 5, row: 1, detail: "Historial y retención" },
  { id: "history", section: "history", label: "Historial DNS y ARP", icon: "mdi-history", lane: 0, column: 5, row: 0, detail: "Siempre se guarda" },

  // Group 1 - what the operator sets and what reaches them.
  { id: "scope", section: "scope", label: "Alcance", icon: "mdi-select-search", lane: 1, column: 2, row: 2, detail: "Ámbitos de detección" },
  { id: "exclusions", section: "exclusions", label: "Exclusiones", icon: "mdi-filter-off-outline", lane: 1, column: 3, row: 2, detail: "IP, puertos y protocolos" },
  { id: "blacklist", section: "blacklist", label: "Listas de acceso", icon: "mdi-format-list-checks", lane: 1, column: 5, row: 2, detail: "Bloqueados y permitidos" },
  { id: "connection", section: "connection", label: "API / WebSocket", icon: "mdi-connection", lane: 1, column: 6, row: 1, detail: "Conexión y autenticación" },
  { id: "notifications", section: "notifications", label: "Notificaciones", icon: "mdi-bell-outline", lane: 1, column: 6, row: 2, detail: "Alertas de este equipo" },

  // Group 2 - resources and the log that explains them.
  { id: "logs", section: "logs", label: "Logs", icon: "mdi-text-box-search-outline", lane: 2, column: 1, row: 2, detail: "Nivel, rotación y consulta" },
  { id: "limits", section: "limits", label: "Límites de recursos", icon: "mdi-speedometer", lane: 2, column: 0, row: 2, detail: "CPU, RAM y almacenamiento" },
];

// Keep every Settings entry point on the same URL vocabulary. In particular,
// Exclusions is a real section even though it is rendered by the graph shell.
export const VALID_TABS = new Set(SETTINGS_NODES.map(node => node.section));

export function normalizeSettingsSection(section) {
  const requested = String(section || "").trim();
  return VALID_TABS.has(requested) ? requested : "";
}

export function settingsRoute(section) {
  const normalized = normalizeSettingsSection(section);
  return { path: "/settings", query: normalized ? { section: normalized } : {} };
}

// [from, to, label] - the label says what travels along the wire.
export const SETTINGS_EDGES = [
  { from: "runtime", to: "sniffer", label: "inicia" },
  { from: "runtime", to: "honeypot", label: "inicia" },
  { from: "location", to: "sniffer", label: "tráfico" },
  { from: "sniffer", to: "cache", label: "paquetes" },
  { from: "cache", to: "jobs", label: "lotes" },
  { from: "jobs", to: "ai", label: "analiza" },
  { from: "ai", to: "store", label: "apoya" },
  { from: "jobs", to: "monitors", label: "alertas" },
  { from: "jobs", to: "store", label: "persiste" },
  // The sniffer feeds the history directly, ahead of detection: it records DNS
  // and ARP whether or not anything alerted, which is why this edge does not
  // go through the cache, the jobs or the monitors.
  { from: "sniffer", to: "history", label: "DNS y ARP" },
  { from: "history", to: "store", label: "persiste" },
  // Monitor hits are stored as alerts (sniffer: is_alert), not only through the job queue.
  { from: "monitors", to: "store", label: "guarda alertas" },
  { from: "honeypot", to: "monitors", label: "señuelos" },
  { from: "scope", to: "exclusions", label: "filtra" },
  { from: "exclusions", to: "monitors", label: "filtra" },
  { from: "blacklist", to: "store", label: "reglas" },
  { from: "store", to: "connection", label: "consulta" },
  { from: "connection", to: "notifications", label: "avisa" },
  { from: "limits", to: "sniffer", label: "pausa" },
];

const GAP = { x: 60, y: 46 };
const NODE_IDS = SETTINGS_NODES.map(node => node.id);

export function defaultPosition(node) {
  return {
    x: 40 + node.column * (GRAPH_CARD.width + GAP.x),
    y: 60 + node.row * (GRAPH_CARD.height + GAP.y),
  };
}

export function validPositions(value) {
  return keepValidPositions(value, NODE_IDS);
}

export function graphBounds(nodes) {
  // Leave room for side-routed connectors, arrowheads and edge labels. This
  // padding is part of the fit calculation, so those visual elements cannot
  // be clipped when the graph is centered in the viewport.
  return boundsOf(nodes, GRAPH_CARD, { x: 58, top: 58, bottom: 58 });
}

// Midpoint of a routed wire, for its label. Mirrors the bezier endpoints
// closely enough to sit on the wire without measuring the path.
export function edgeMidpoint(from, to) {
  const sameColumn = Math.abs(to.x - from.x) < GRAPH_CARD.width;
  if (sameColumn) {
    // Vertical connectors detour around the left side of both cards. A
    // geometric midpoint would land inside a card, hiding the label and often
    // making it look like the connector is broken.
    return {
      x: Math.min(from.x, to.x) - 26,
      y: (from.y + to.y) / 2 + GRAPH_CARD.height / 2,
    };
  }
  return {
    x: (from.x + to.x) / 2 + GRAPH_CARD.width / 2,
    y: (from.y + to.y) / 2 + GRAPH_CARD.height / 2,
  };
}

export function connectionPath(from, to) {
  return routeConnection(from, to, GRAPH_CARD);
}
