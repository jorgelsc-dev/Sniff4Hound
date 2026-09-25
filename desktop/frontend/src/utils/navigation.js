// Every destination the shell can reach, in one place. The activity rail
// (GlobalToolsMenu) renders the tree; the command palette flattens it. They
// used to be the same list typed twice, which is how a route ends up
// reachable from one and not the other.

export const NAV_LINKS = [
  {
    label: "Dashboard",
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
  {
    label: "IA",
    to: "/ai",
    icon: "mdi-brain",
    color: "secondary",
    children: [
      { label: "Resumen", to: "/ai/overview", icon: "mdi-clipboard-pulse-outline" },
      { label: "RNN Red Neuronal", to: "/ai/neural-network", icon: "mdi-hub-outline" },
    ],
  },
  { label: "SOC", to: "/soc", icon: "mdi-shield-search", color: "error" },
  { label: "Investigar", to: "/investigate", icon: "mdi-magnify-scan", color: "info" },
  { label: "Monitores", to: "/monitors", icon: "mdi-target-account", color: "success" },
  { label: "Protocolos", to: "/protocols", icon: "mdi-swap-horizontal", color: "secondary" },
  { label: "Sniffer", to: "/sniffer", icon: "mdi-ethernet", color: "info" },
  { label: "Honeypot", to: "/honeypot", icon: "mdi-spider-web", color: "warning" },
  { label: "Dominios", to: "/domains", icon: "mdi-web", color: "primary" },
  { label: "Paths", to: "/paths", icon: "mdi-routes", color: "secondary" },
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

export function matchesQuery(item, query) {
  const needle = fold(query).replace(/\s+/g, "");
  if (!needle) return true;
  const haystack = fold(`${item.parent || ""} ${item.label} ${item.keywords || ""}`);
  let index = 0;
  for (const char of needle) {
    index = haystack.indexOf(char, index);
    if (index === -1) return false;
    index += 1;
  }
  return true;
}
