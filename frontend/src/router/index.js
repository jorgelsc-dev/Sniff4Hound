import { createRouter, createWebHistory } from "vue-router";
import { appBaseUrl } from "../utils/runtimeEnv";

const routes = [
  { path: "/", name: "dashboard", component: () => import("../views/DashboardView.vue") },
  { path: "/radar", name: "radar", component: () => import("../views/RadarView.vue") },
  { path: "/investigate", name: "investigate", component: () => import("../views/InvestigateView.vue") },
  { path: "/sniffer", name: "sniffer", component: () => import("../views/SnifferView.vue") },
  { path: "/soc", name: "soc", component: () => import("../views/SocView.vue") },
  {
    path: "/protocols/:proto?",
    name: "protocols",
    alias: ["/protocolos", "/protocolos/:proto?"],
    component: () => import("../views/ProtocolsView.vue"),
  },
  { path: "/honeypot", name: "honeypot", component: () => import("../views/HoneypotView.vue") },
  { path: "/monitors", name: "monitors", component: () => import("../views/MonitorsView.vue") },
  { path: "/domains", name: "domains", component: () => import("../views/DomainsView.vue") },
  { path: "/paths", name: "paths", component: () => import("../views/PathsView.vue") },
  { path: "/ips", name: "ips", component: () => import("../views/IpsView.vue") },
  { path: "/settings", name: "settings", component: () => import("../views/SettingsView.vue") },
  { path: "/targets", redirect: "/" },
  { path: "/sessions", redirect: "/" },
  { path: "/intel", redirect: "/investigate" },
  { path: "/ports", redirect: "/sniffer" },
  { path: "/banners", redirect: "/honeypot" },
  { path: "/:pathMatch(.*)*", redirect: "/" },
];

const router = createRouter({
  history: createWebHistory(appBaseUrl()),
  routes,
  scrollBehavior() {
    return { left: 0, top: 0 };
  },
});

export default router;
