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

export function defaultPosition(node) {
  return { x: 40 + node.column * 312, y: 60 + node.row * 158 };
}

export function validPositions(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  return Object.fromEntries(SETTINGS_NODES.flatMap(({ id }) => {
    const pos = value[id];
    return Number.isFinite(pos?.x) && Number.isFinite(pos?.y)
      && Math.abs(pos.x) < 10000 && Math.abs(pos.y) < 10000
      ? [[id, { x: pos.x, y: pos.y }]] : [];
  }));
}

export function graphBounds(nodes) {
  const left = Math.min(...nodes.map(n => n.x)) - 30;
  const top = Math.min(...nodes.map(n => n.y)) - 48;
  const right = Math.max(...nodes.map(n => n.x + GRAPH_CARD.width)) + 30;
  const bottom = Math.max(...nodes.map(n => n.y + GRAPH_CARD.height)) + 30;
  return { x: left, y: top, width: right - left, height: bottom - top };
}

export function connectionPath(from, to) {
  const { width, height } = GRAPH_CARD;
  if (Math.abs(to.x - from.x) < width) {
    const downward = to.y > from.y;
    const x1 = from.x + width / 2;
    const y1 = from.y + (downward ? height : 0);
    const x2 = to.x + width / 2;
    const y2 = to.y + (downward ? 0 : height);
    // Side routing keeps vertical connections clear of intermediate cards.
    const side = Math.min(from.x, to.x) - 26;
    return `M ${x1} ${y1} C ${side} ${y1}, ${side} ${y2}, ${x2} ${y2}`;
  }
  const forward = to.x > from.x;
  const x1 = from.x + (forward ? width : 0);
  const y1 = from.y + height / 2;
  const x2 = to.x + (forward ? 0 : width);
  const y2 = to.y + height / 2;
  const bend = Math.max(40, Math.abs(x2 - x1) / 2);
  const sign = forward ? 1 : -1;
  return `M ${x1} ${y1} C ${x1 + bend * sign} ${y1}, ${x2 - bend * sign} ${y2}, ${x2} ${y2}`;
}
