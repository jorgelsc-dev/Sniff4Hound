export function appBaseUrl() {
  return String(import.meta.env.BASE_URL || "/").replace(/\/?$/, "/");
}

export function apiBaseEnv() {
  return String(import.meta.env.VITE_API_BASE || "").trim();
}
