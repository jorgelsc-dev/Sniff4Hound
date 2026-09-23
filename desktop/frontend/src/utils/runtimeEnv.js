export function appBaseUrl() {
  // `import.meta.env` only exists under Vite - this module is also reached
  // by the plain-Node unit test runner (frontend/tests/soc-qa.test.js ->
  // appStore.js -> router/index.js -> here), where it is undefined rather
  // than absent, so a plain `.env.BASE_URL` throws instead of falling back.
  return String(import.meta.env?.BASE_URL || "/").replace(/\/?$/, "/");
}

export function apiBaseEnv() {
  return String(import.meta.env?.VITE_API_BASE || "").trim();
}
