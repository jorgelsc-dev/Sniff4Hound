import {
  connectionPath as routeConnection,
  defaultPosition as positionOnGrid,
  graphBounds as boundsOf,
  validPositions as keepValidPositions,
} from "../../utils/flowGraph";

export const GRAPH_CARD = { width: 238, height: 112 };
export const GRAPH_STORAGE_KEY = "sniff4hound.settingsGraphCards.v1";
export const GRAPH_COLUMNS = [
  { label: "Captura", color: "#54cbd8" },
  { label: "Detección", color: "#b79aeb" },
  { label: "Datos", color: "#69c798" },
  { label: "Sistema", color: "#e4b96c" },
];

export const SETTINGS_NODES = [
  { id: "runtime", section: "runtime", label: "Runtime", icon: "mdi-source-branch", column: 0, row: 0, detail: "Motores de captura" },
  { id: "sniffer", section: "capture", label: "Sniffer", icon: "mdi-ethernet", column: 0, row: 1, detail: "Interfaces de red" },
  { id: "honeypot", section: "honeypot", label: "Honeypot", icon: "mdi-spider-web", column: 0, row: 2, detail: "Puertos y listeners" },
  { id: "location", section: "location", label: "Sensor", icon: "mdi-map-marker-outline", column: 0, row: 3, detail: "Ubicación del sensor" },
  { id: "monitors", section: "detection", label: "Monitores", icon: "mdi-radar", column: 1, row: 0, detail: "Reglas y severidad" },
  { id: "ai", section: "ai", label: "Inteligencia artificial", icon: "mdi-brain", column: 1, row: 1, detail: "Clasificador y detector LOF" },
  { id: "exclusions", section: "exclusions", label: "Exclusiones", icon: "mdi-filter-off-outline", column: 1, row: 2, detail: "IP, puertos y protocolos" },
  { id: "scope", section: "scope", label: "Alcance", icon: "mdi-select-search", column: 1, row: 3, detail: "Ámbitos de detección" },
  { id: "store", section: "storage", label: "SniffStore", icon: "mdi-database-outline", column: 2, row: 1, detail: "Historial y retención" },
  { id: "blacklist", section: "blacklist", label: "Listas de acceso", icon: "mdi-format-list-checks", column: 2, row: 2, detail: "Bloqueados y permitidos" },
  { id: "connection", section: "connection", label: "API / WebSocket", icon: "mdi-connection", column: 3, row: 1, detail: "Conexión y autenticación" },
  { id: "notifications", section: "notifications", label: "Notificaciones", icon: "mdi-bell-outline", column: 3, row: 2, detail: "Alertas de este equipo" },
];

export const SETTINGS_EDGES = [
  ["runtime", "sniffer"], ["runtime", "honeypot"],
  ["location", "sniffer"], ["sniffer", "monitors"], ["sniffer", "ai"],
  ["honeypot", "monitors"], ["scope", "exclusions"],
  ["exclusions", "monitors"], ["monitors", "store"], ["ai", "store"],
  ["blacklist", "store"], ["store", "connection"], ["connection", "notifications"],
];

const NODE_IDS = SETTINGS_NODES.map(node => node.id);
// The 312/158 step this layout was authored against, expressed as the gap the
// shared grid helper takes.
const GRID_GAP = { x: 312 - GRAPH_CARD.width, y: 158 - GRAPH_CARD.height };

export function defaultPosition(node) {
  return positionOnGrid(node, GRAPH_CARD, GRID_GAP);
}

export function validPositions(value) {
  return keepValidPositions(value, NODE_IDS);
}

export function graphBounds(nodes) {
  return boundsOf(nodes, GRAPH_CARD);
}

export function connectionPath(from, to) {
  return routeConnection(from, to, GRAPH_CARD);
}
