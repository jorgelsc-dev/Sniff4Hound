// Adapter for the optional AI setting. The backend contract is intentionally
// kept here so the Settings UI does not depend on endpoint details:
//
//   GET  /api/settings/ai              -> { enabled: boolean, model_status }
//   POST /api/settings/ai              <- { enabled: boolean }
//   POST response                      -> { enabled: boolean, model_status }
//
// The backend owns the default and persistence policy. The UI only exposes
// the operator's preference and never assumes that AI replaces rule-based
// detection. `enabled` is permission only: `model_status` says whether a
// model can actually run ("not_configured" until a provider is wired in).
export const AI_SETTINGS_PATH = "/api/settings/ai";

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
  return { enabled: payload.enabled, modelStatus };
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
