// Adapter for the optional AI setting. The backend contract is intentionally
// kept here so the Settings UI does not depend on endpoint details:
//
//   GET  /api/settings/ai              -> { enabled: boolean }
//   POST /api/settings/ai              <- { enabled: boolean }
//   POST response                      -> { enabled: boolean }
//
// The backend owns the default and persistence policy. The UI only exposes
// the operator's preference and never assumes that AI replaces rule-based
// detection.
export const AI_SETTINGS_PATH = "/api/settings/ai";

export function normalizeAiSettings(payload) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new Error("La respuesta de configuración de IA no es válida.");
  }
  if (typeof payload.enabled !== "boolean") {
    throw new Error("La respuesta de configuración de IA no incluye enabled.");
  }
  return { enabled: payload.enabled };
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
