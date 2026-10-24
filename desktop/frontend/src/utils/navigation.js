// Every destination the shell can reach, in one place. The activity rail
// (GlobalToolsMenu) renders the tree; the command palette flattens it. They
// used to be the same list typed twice, which is how a route ends up
// reachable from one and not the other.

export const NAV_LINKS = [
  {
    label: "Panel principal",
    to: "/",
    icon: "mdi-view-dashboard",
    color: "primary",
    children: [
      { label: "Resumen", to: "/dashboard/overview", icon: "mdi-view-dashboard-outline" },
      { label: "Mapa de Nodos", to: "/dashboard/node-map", icon: "mdi-graph-outline" },
      { label: "Mapa en Vivo", to: "/dashboard/live-map", icon: "mdi-earth" },
    ],
  },
  { label: "Chat", to: "/chat", icon: "mdi-message-processing-outline", color: "info" },
  { label: "Configuración", to: "/settings", icon: "mdi-cog-outline", color: "secondary" },
  { label: "SOC", to: "/soc", icon: "mdi-shield-search", color: "error" },
  { label: "Investigar", to: "/investigate", icon: "mdi-magnify-scan", color: "info" },
  { label: "Monitores", to: "/monitors", icon: "mdi-target-account", color: "success" },
  { label: "Protocolos", to: "/protocols", icon: "mdi-swap-horizontal", color: "secondary" },
  { label: "Sniffer", to: "/sniffer", icon: "mdi-ethernet", color: "info" },
  { label: "ARP", to: "/arp", icon: "mdi-lan-connect", color: "success" },
  { label: "DNS", to: "/dns", icon: "mdi-dns-outline", color: "info" },
  { label: "Honeypot", to: "/honeypot", icon: "mdi-spider-web", color: "warning" },
  { label: "Dominios", to: "/domains", icon: "mdi-web", color: "primary" },
  { label: "Rutas HTTP", to: "/paths", icon: "mdi-routes", color: "secondary" },
  { label: "IPs", to: "/ips", icon: "mdi-ip-network", color: "success" },
];

// Flattened for search: a child carries its parent's name so typing "mapa"
// finds "Dashboard / Mapa en Vivo" and the result still says where it lives.
export function navDestinations() {
  return NAV_LINKS.flatMap((link) => [
    { label: link.label, to: link.to, icon: link.icon, group: "Ir a" },
    ...(link.children || []).map(child => ({
      label: child.label,
      to: child.to,
      icon: child.icon,
      group: "Ir a",
      parent: link.label,
    })),
  ]);
}

// Case- and accent-insensitive subsequence match, so "cnf" finds
// "Configuración" and "protocolos" matches whether or not the typed query
// carries the accent.
function fold(value) {
  return String(value || "")
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase();
}

export function queryScore(item, query) {
  const needle = fold(query).trim();
  if (!needle) return 1;
  const label = fold(item.label);
  if (label === needle) return 1000;
  if (label.split(/\s+/).some(word => word.startsWith(needle))) return 800;
  if (label.includes(needle)) return 600;
  const context = fold(`${item.parent || ""} ${item.keywords || ""}`);
  if (context.includes(needle)) return 400;
  // Abbreviations are confined to a single word, with a density floor:
  // "cnf" can find configuración; letters scattered across a sentence cannot.
  if (needle.length < 3 || /\s/.test(needle)) return 0;
  for (const word of label.split(/\s+/)) {
    if (!word.startsWith(needle[0])) continue;
    let index = 0;
    let end = 0;
    for (const char of needle) {
      const found = word.indexOf(char, index);
      if (found < 0) { index = -1; break; }
      end = found + 1;
      index = end;
    }
    if (index >= 0 && needle.length / end >= 0.45) return 100 * needle.length / end;
  }
  return 0;
}

export function matchesQuery(item, query) {
  return queryScore(item, query) > 0;
}
