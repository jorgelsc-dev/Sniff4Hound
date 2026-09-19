import { createRouter, createWebHistory, createMemoryHistory } from "vue-router";
import { appBaseUrl } from "../utils/runtimeEnv.js";

const routes = [
  { path: "/ai", name: "ai", component: () => import("../views/AiHubView.vue") },
  { path: "/ai/overview", name: "ai-overview", component: () => import("../views/AiView.vue") },
  {
    path: "/ai/neural-network",
    name: "ai-neural-network",
    component: () => import("../views/ai/NeuralNetworkView.vue"),
    meta: { fullWidth: true, canvasOnly: true },
  },
  { path: "/", name: "dashboard", component: () => import("../views/DashboardHubView.vue") },
  {
    path: "/dashboard/overview",
    name: "dashboard-overview",
    component: () => import("../views/DashboardView.vue"),
  },
  {
    path: "/dashboard/node-map",
    name: "dashboard-node-map",
    component: () => import("../views/dashboard/NodeMapDashboardView.vue"),
    meta: { fullWidth: true, canvasOnly: true },
  },
  {
    path: "/dashboard/live-map",
    name: "dashboard-live-map",
    component: () => import("../views/dashboard/LiveMapDashboardView.vue"),
    meta: { fullWidth: true, canvasOnly: true },
  },
  { path: "/chat", name: "chat", component: () => import("../views/ChatView.vue"), meta: { fullWidth: true, canvasOnly: true } },
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

// vue-router's default history needs `window`/`document`. This module is
// also reached from the plain-Node unit test runner (no DOM at all), which
// otherwise crashes at import time before a single test can run - swap to
// the DOM-free memory history there; every real (browser/Electron) load
// always has `window`.
const router = createRouter({
  history: typeof window !== "undefined" ? createWebHistory(appBaseUrl()) : createMemoryHistory(appBaseUrl()),
  routes,
  scrollBehavior() {
    return { left: 0, top: 0 };
  },
});

export default router;
