// Adapter for the optional AI setting. The backend contract is intentionally
// kept here so the Settings UI does not depend on endpoint details:
//
//   GET|POST /api/settings/ai          -> settings + local engine metadata
//   GET  /api/settings/ai/analysis     -> execution stats and history
//   POST /api/settings/ai/analysis     -> one aggregate analysis
//
// The backend owns the default and persistence policy. The UI never assumes
// that AI replaces rule-based detection. The default provider is a local,
// deterministic aggregate engine; no external model or network call is used.
export const AI_SETTINGS_PATH = "/api/settings/ai";
export const AI_ANALYSIS_PATH = "/api/settings/ai/analysis";

export function normalizeAiSettings(payload) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new Error("La respuesta de configuración de IA no es válida.");
  }
  if (typeof payload.enabled !== "boolean") {
    throw new Error("La respuesta de configuración de IA no incluye enabled.");
  }
  // An older backend without model_status has no model either.
  const modelStatus = typeof payload.model_status === "string" && payload.model_status
    ? payload.model_status
    : "not_configured";
  return {
    enabled: payload.enabled,
    modelStatus,
    provider: typeof payload.provider === "string" ? payload.provider : "Local aggregate engine",
    model: typeof payload.model === "string" ? payload.model : "sniff4hound-aggregate-risk-v1",
    totalRuns: Number(payload.total_runs) || 0,
    totalFindings: Number(payload.total_findings) || 0,
    lastRun: payload.last_run && typeof payload.last_run === "object" ? payload.last_run : null,
    history: Array.isArray(payload.history) ? payload.history : [],
  };
}

export function aiModelReady(settings) {
  return Boolean(settings && settings.enabled && settings.modelStatus === "ready");
}

export function loadAiSettings(store) {
  return store.fetchJsonPromise(AI_SETTINGS_PATH).then(normalizeAiSettings);
}

export function setAiEnabled(store, enabled) {
  if (typeof enabled !== "boolean") {
    throw new TypeError("La configuración de IA requiere un booleano.");
  }
  return store.fetchJsonPromise(AI_SETTINGS_PATH, {
    method: "POST",
    body: JSON.stringify({ enabled }),
  }).then(normalizeAiSettings);
}

export function loadAiAnalysis(store) {
  return store.fetchJsonPromise(AI_ANALYSIS_PATH).then(normalizeAiSettings);
}

export function runAiAnalysis(store, since = "") {
  const query = since ? `?since=${encodeURIComponent(since)}` : "";
  return store.fetchJsonPromise(`${AI_ANALYSIS_PATH}${query}`, {
    method: "POST",
    body: JSON.stringify({}),
  }).then(payload => ({
    ...normalizeAiSettings(payload),
    status: payload?.status || "completed",
    result: payload?.result && typeof payload.result === "object" ? payload.result : null,
    message: typeof payload?.message === "string" ? payload.message : "",
  }));
}
