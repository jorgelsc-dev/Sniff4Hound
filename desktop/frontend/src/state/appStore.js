import { reactive } from "vue";
import { apiBaseEnv } from "../utils/runtimeEnv.js";
import { buildExportFilename, downloadTextFile } from "../utils/exporters.js";
import router from "../router/index.js";

const AUTH_SESSION_PATH = "/api/auth/session";
const STORAGE_KEY_API = "sniff4hound.apiBase";
const STORAGE_KEY_AUTH = "sniff4hound.securityCode";
const LEGACY_STORAGE_KEY_AUTH = "sniff4hound.sessionToken";
const QUERY_AUTH_KEYS = ["code"];
const QUERY_API_BASE_KEY = "api_base";
const STORAGE_KEY_NOTIFY_SOUND = "sniff4hound.notifySoundEnabled";
const STORAGE_KEY_TIME_RANGE = "sniff4hound.timeRange";
// Relative windows understood by the API's `since` query parameter. The empty
// value means "no temporal filter" (everything the store still holds).
const TIME_RANGE_OPTIONS = [
  { label: "15m", value: "15m", description: "Last 15 minutes" },
  { label: "1h", value: "1h", description: "Last hour" },
  { label: "6h", value: "6h", description: "Last 6 hours" },
  { label: "24h", value: "24h", description: "Last 24 hours" },
  { label: "7d", value: "7d", description: "Last 7 days" },
  { label: "All", value: "", description: "No time filter" },
];
const TIME_RANGE_VALUES = new Set(TIME_RANGE_OPTIONS.map((option) => option.value));
const WS_RECONNECT_DELAY_MS = 1800;
const WS_REFRESH_THROTTLE_MS = 10000;
const LIVE_ACTIVITY_WINDOW_MS = 5000;
const LIVE_ACTIVITY_TICK_MS = 500;
const JOB_POLL_MIN_MS = 220;
const JOB_POLL_MAX_MS = 2000;
const WS_AUTH_CLOSE_CODE = 4401;
const APP_SHUTDOWN_DELAY_SECONDS = 0.2;
const WS_REFRESH_EVENT_TYPES = new Set([
  "welcome",
  "packet",
  "stats_update",
  "runtime_mode",
  "chat_message",
]);
// What counts as "important enough for a popup" - everything else stays
// available in the regular views (Monitors/SOC/etc.) without interrupting.
const NOTIFY_MONITOR_SEVERITIES = new Set(["high", "critical"]);

const state = reactive({
  apiBase: "",
  wsStatus: "offline",
  runtimeMode: "sniffer",
  runtime: {},
  realtimeMapSnapshot: null,
  realtimeMapGeneratedAt: "",
  authReady: false,
  authRequired: false,
  authStatus: "unknown",
  authToken: "",
  authError: "",
  authPromptOpen: false,
  // Ctrl/Cmd+K palette. In the store rather than local to CommandPalette so
  // the top bar's search affordance can open it without a component ref.
  commandPaletteOpen: false,
  shutdownPending: false,
  notifySoundEnabled: true,
  // Incremented on every inbound chat frame; ChatView watches it.
  chatRevision: 0,
  timeRange: "",
  // Latest "data_clear_progress" WS frame (see clear_detections_api /
  // purge_capture_data in the backend) while a "Clear data" purge is
  // in flight; null once no purge is running. ClearDataButton renders a
  // real progress bar off this instead of a bare spinner.
  dataClearProgress: null,
  // Rolling packets/second over the last LIVE_ACTIVITY_WINDOW_MS, split by
  // which engine produced the traffic. scheduleTableRefresh() deliberately
  // coalesces inbound frames down to one table refresh every 10s, which is
  // right for tables but erases any sense of *rate* - this keeps the raw
  // arrival cadence so the pipeline canvas can animate at the real speed.
  liveActivity: { total: 0, sniffer: 0, honeypot: 0, lastPacketAt: 0, seen: 0 },
  // How many requests are currently parked on a queued job. Anything above
  // zero means the UI is waiting on the backend for something that outran the
  // inline window.
  pendingJobs: 0,
});

const tableRefreshSubscribers = new Set();
const mapSnapshotSubscribers = new Set();

let inMemoryAuthToken = "";
let wsClient = null;
let wsReconnectTimer = null;
let wsRefreshTimer = null;
let wsPendingRefreshPayload = null;
let wsCoalescedEventCount = 0;
let wsConnectAttempt = 0;
let notificationPermissionRequested = false;
let audioContext = null;
let lastRuntimeForNotify = null;
let hasEverConnectedRealtime = false;
let isRealtimeCurrentlyOnline = false;

function suggestApiBaseFromLocation(locationLike = null) {
  const locationRef =
    locationLike ||
    (typeof window !== "undefined" && window.location ? window.location : null);
  if (!locationRef) return "";

  const protocol = String(locationRef.protocol || "http:");
  const hostname = String(locationRef.hostname || "127.0.0.1");
  const port = String(locationRef.port || "");
  const isDevPort = port === "8080" || port === "5173" || port === "3000";
  if (isDevPort) {
    return `${protocol}//${hostname}:45678`;
  }
  return String(locationRef.origin || `${protocol}//${hostname}${port ? `:${port}` : ""}`);
}

// The desktop shell now loads this SPA natively from disk (file://, see
// desktop/main.js's loadShell()) instead of the backend serving it over
// HTTP, so the page's own origin no longer has anything to do with where
// the API lives - main.js passes the real backend origin (local or a
// "connect to remote sensor" target) as this query param on every load,
// same pattern as the security code below. Takes priority over the stored/
// guessed base since a fresh launch always knows the current backend
// better than a stale localStorage value from a previous run.
function readStartupApiBaseFromUrl() {
  if (typeof window === "undefined" || !window.location) {
    return "";
  }
  let parsed;
  try {
    parsed = new URL(window.location.href);
  } catch {
    return "";
  }
  const value = parsed.searchParams.get(QUERY_API_BASE_KEY);
  if (!value) return "";
  parsed.searchParams.delete(QUERY_API_BASE_KEY);
  const cleanUrl = `${parsed.pathname}${parsed.search}${parsed.hash}`;
  try {
    window.history.replaceState(window.history.state, "", cleanUrl);
  } catch {
    // keeping a tidy address bar is helpful, not required
  }
  return String(value).trim();
}

function initApiBase() {
  if (typeof window === "undefined") {
    state.apiBase = "";
    return;
  }
  const storedApiBase = window.localStorage
    ? window.localStorage.getItem(STORAGE_KEY_API)
    : "";
  const base =
    readStartupApiBaseFromUrl() ||
    storedApiBase ||
    apiBaseEnv() ||
    suggestApiBaseFromLocation(window.location) ||
    "";
  state.apiBase = String(base || "").replace(/\/+$/, "");
  if (window.localStorage && state.apiBase) {
    window.localStorage.setItem(STORAGE_KEY_API, state.apiBase);
  }
}

function setApiBase(value) {
  const cleaned = String(value || "").trim().replace(/\/+$/, "");
  state.apiBase = cleaned;
  state.realtimeMapSnapshot = null;
  state.realtimeMapGeneratedAt = "";
  if (typeof window !== "undefined" && window.localStorage) {
    window.localStorage.setItem(STORAGE_KEY_API, cleaned);
  }
  reconnectRealtime();
}

function readStartupAuthTokenFromUrl() {
  if (typeof window === "undefined" || !window.location) {
    return "";
  }
  let parsed = null;
  try {
    parsed = new URL(window.location.href);
  } catch {
    return "";
  }
  let token = "";
  QUERY_AUTH_KEYS.some((key) => {
    const value = parsed.searchParams.get(key);
    if (!value) return false;
    token = String(value).trim();
    return Boolean(token);
  });
  if (QUERY_AUTH_KEYS.some((key) => parsed.searchParams.has(key))) {
    QUERY_AUTH_KEYS.forEach((key) => parsed.searchParams.delete(key));
    const cleanUrl = `${parsed.pathname}${parsed.search}${parsed.hash}`;
    try {
      window.history.replaceState(window.history.state, "", cleanUrl);
    } catch {
      // keeping a tidy address bar is helpful, not required
    }
  }
  return token;
}

function readLocalAuthToken() {
  if (typeof window === "undefined") {
    return "";
  }
  let token = "";
  try {
    token = window.sessionStorage
      ? String(
          window.sessionStorage.getItem(STORAGE_KEY_AUTH) ||
            window.sessionStorage.getItem(LEGACY_STORAGE_KEY_AUTH) ||
            "",
        ).trim()
      : "";
  } catch {
    // storage may be unavailable; fall through to localStorage cleanup
  }
  try {
    if (!token) {
      token = window.localStorage
        ? String(
            window.localStorage.getItem(STORAGE_KEY_AUTH) ||
              window.localStorage.getItem(LEGACY_STORAGE_KEY_AUTH) ||
              "",
          ).trim()
        : "";
    }
  } catch {
    // localStorage may be unavailable; cleanup below still tries sessionStorage
  }
  clearStoredAuthTokens();
  return token;
}

function clearStoredAuthTokens() {
  if (typeof window === "undefined") {
    return;
  }
  try {
    if (window.sessionStorage) {
      window.sessionStorage.removeItem(STORAGE_KEY_AUTH);
      window.sessionStorage.removeItem(LEGACY_STORAGE_KEY_AUTH);
    }
    if (window.localStorage) {
      window.localStorage.removeItem(STORAGE_KEY_AUTH);
      window.localStorage.removeItem(LEGACY_STORAGE_KEY_AUTH);
    }
  } catch {
    // private-mode / disabled storage: nothing to clean up
  }
}

function readStoredAuthToken() {
  const urlToken = readStartupAuthTokenFromUrl();
  if (urlToken) {
    persistAuthToken(urlToken);
    return urlToken;
  }
  const storedToken = readLocalAuthToken();
  return String(inMemoryAuthToken || storedToken).trim();
}

function persistAuthToken(token) {
  const cleaned = String(token || "").trim();
  inMemoryAuthToken = cleaned;
  if (typeof window === "undefined") {
    return;
  }
  try {
    clearStoredAuthTokens();
  } catch {
    // storage may be unavailable; the in-memory copy still covers this tab
  }
}

function signOut() {
  setAuthToken("");
  state.authStatus = state.authRequired ? "required" : "unknown";
  state.authError = "";
  state.authPromptOpen = Boolean(state.authRequired);
  destroyRealtime();
}

function setAuthToken(token) {
  const cleaned = String(token || "").trim();
  state.authToken = cleaned;
  persistAuthToken(cleaned);
}

function lockRealtimeForAuth() {
  state.wsStatus = "locked";
}

function applyRuntimeSnapshot(payload) {
  const runtime = payload && typeof payload === "object" ? payload.runtime || payload : {};
  const mode = String(runtime.mode || payload.mode || "").trim().toLowerCase();
  if (mode) {
    state.runtimeMode = mode;
  }
  state.runtime = runtime && typeof runtime === "object" ? runtime : {};
  return state.runtime;
}

function initRuntime() {
  if (state.authRequired && state.authStatus !== "authenticated") {
    return Promise.resolve(null);
  }
  return fetchJsonPromise("/api/runtime/")
    .then((payload) => {
      applyRuntimeSnapshot(payload);
      return payload;
    })
    .catch(() => null);
}

function setRuntimeMode(mode) {
  const normalized = String(mode || "").trim().toLowerCase();
  if (!normalized) {
    return Promise.resolve(state.runtime);
  }
  return fetchJsonPromise("/api/runtime/", {
    method: "POST",
    body: JSON.stringify({ mode: normalized }),
  }).then((payload) => {
    applyRuntimeSnapshot(payload);
    return payload;
  });
}

function controlRuntimeMode(mode, action) {
  const normalizedMode = String(mode || "").trim().toLowerCase();
  const normalizedAction = String(action || "").trim().toLowerCase();
  if (!normalizedAction) {
    return Promise.resolve(state.runtime);
  }
  const body = { action: normalizedAction };
  if (normalizedMode) {
    body.mode = normalizedMode;
  }
  return fetchJsonPromise("/api/runtime/", {
    method: "POST",
    body: JSON.stringify(body),
  }).then((payload) => {
    applyRuntimeSnapshot(payload);
    return payload;
  });
}

// Start/stop one engine by name. Unlike controlRuntimeMode(), this never
// changes which engine the mode-scoped controls focus on - the two engines
// are independent, so starting the honeypot must not move the operator's
// view off the sniffer.
function controlEngine(engine, action) {
  const name = String(engine || "").trim().toLowerCase();
  const normalizedAction = String(action || "").trim().toLowerCase();
  if (!name || !normalizedAction) {
    return Promise.resolve(state.runtime);
  }
  return fetchJsonPromise("/api/runtime/", {
    method: "POST",
    body: JSON.stringify({ engine: name, action: normalizedAction }),
  }).then((payload) => {
    applyRuntimeSnapshot(payload);
    return payload;
  });
}

// Bring the running set to exactly this selection: none, either, or both.
function setEngines({ sniffer, honeypot } = {}) {
  const engines = {};
  if (sniffer !== undefined) engines.sniffer = Boolean(sniffer);
  if (honeypot !== undefined) engines.honeypot = Boolean(honeypot);
  return fetchJsonPromise("/api/runtime/", {
    method: "POST",
    body: JSON.stringify({ engines }),
  }).then((payload) => {
    applyRuntimeSnapshot(payload);
    return payload;
  });
}

function setSnifferInterface(interfaceName) {
  const values = String(interfaceName || "").trim();
  return setSnifferInterfaces(values ? [values] : []);
}

function setSnifferInterfaces(interfaceNames) {
  const normalized = Array.isArray(interfaceNames)
    ? [...new Set(interfaceNames.map((item) => String(item || "").trim()).filter(Boolean))]
    : [];
  return fetchJsonPromise("/api/runtime/", {
    method: "POST",
    body: JSON.stringify({
      interfaces: normalized,
    }),
  }).then((payload) => {
    applyRuntimeSnapshot(payload);
    return payload;
  });
}

function listMonitors() {
  return fetchJsonPromise("/api/monitors/");
}

function saveMonitor(payload) {
  const method = payload && payload.id ? "PUT" : "POST";
  return fetchJsonPromise("/api/monitors/", {
    method,
    body: JSON.stringify(payload || {}),
  });
}

function deleteMonitor(id) {
  return fetchJsonPromise("/api/monitors/", {
    method: "DELETE",
    body: JSON.stringify({ id }),
  });
}

function toggleMonitorEnabled(id, enabled) {
  return fetchJsonPromise("/api/monitors/toggle", {
    method: "POST",
    body: JSON.stringify({ id, enabled: Boolean(enabled) }),
  });
}

function getMonitorConfig() {
  return fetchJsonPromise("/api/monitors/config");
}

function reviewPacket(packetId, label) {
  return fetchJsonPromise("/api/packets/review", {
    method: "POST",
    body: JSON.stringify({ packet_id: Number(packetId), label }),
  });
}

function getDeclaredLocation() {
  return fetchJsonPromise("/api/settings/location");
}

function setDeclaredLocation(lat, lon, label) {
  return fetchJsonPromise("/api/settings/location", {
    method: "POST",
    body: JSON.stringify({ lat, lon, label: String(label || "") }),
  });
}

function clearDeclaredLocation() {
  return fetchJsonPromise("/api/settings/location", {
    method: "POST",
    body: JSON.stringify({ clear: true }),
  });
}

function getDetectionScopes() {
  return fetchJsonPromise("/api/detection/scopes");
}

function setDetectionScopes(scopes) {
  return fetchJsonPromise("/api/detection/scopes", {
    method: "POST",
    body: JSON.stringify({ exclude_scopes: Array.isArray(scopes) ? scopes : [] }),
  });
}

function listChatMessages(limit = 100) {
  return fetchJsonPromise(`/api/chat/messages?limit=${encodeURIComponent(limit)}`);
}

function postChatMessage(content) {
  return fetchJsonPromise("/api/chat/messages", {
    method: "POST",
    body: JSON.stringify({ content: String(content || "").trim() }),
  });
}

function executeConsoleCommand(command) {
  return fetchJsonPromise("/api/console/execute", {
    method: "POST",
    body: JSON.stringify({ command: String(command || "").trim() }),
  });
}

function listHoneypotListeners() {
  return fetchJsonPromise("/api/honeypot/listeners/");
}

function createHoneypotListener(proto, port, label) {
  return fetchJsonPromise("/api/honeypot/listeners/", {
    method: "POST",
    body: JSON.stringify({ proto, port, label: label || "" }),
  });
}

function toggleHoneypotListenerEnabled(id, enabled) {
  return fetchJsonPromise("/api/honeypot/listeners/toggle", {
    method: "POST",
    body: JSON.stringify({ id, enabled: Boolean(enabled) }),
  });
}

function setMonitorConfig(payload) {
  return fetchJsonPromise("/api/monitors/config", {
    method: "POST",
    body: JSON.stringify(payload || {}),
  });
}

function listBlacklistEntries(category = "") {
  const query = category ? `?category=${encodeURIComponent(category)}` : "";
  return fetchJsonPromise(`/api/blacklist/${query}`);
}

function createBlacklistEntry({ category, matchType, value, label = "" }) {
  return fetchJsonPromise("/api/blacklist/", {
    method: "POST",
    body: JSON.stringify({ category, match_type: matchType, value, label }),
  });
}

function deleteBlacklistEntry(id) {
  return fetchJsonPromise("/api/blacklist/", {
    method: "DELETE",
    body: JSON.stringify({ id }),
  });
}

function toggleBlacklistEntry(id, enabled) {
  return fetchJsonPromise("/api/blacklist/toggle", {
    method: "POST",
    body: JSON.stringify({ id, enabled: Boolean(enabled) }),
  });
}

function listWhitelistEntries(category = "") {
  const query = category ? `?category=${encodeURIComponent(category)}` : "";
  return fetchJsonPromise(`/api/whitelist/${query}`);
}

function createWhitelistEntry({ category, matchType, value, label = "" }) {
  return fetchJsonPromise("/api/whitelist/", {
    method: "POST",
    body: JSON.stringify({ category, match_type: matchType, value, label }),
  });
}

function deleteWhitelistEntry(id) {
  return fetchJsonPromise("/api/whitelist/", {
    method: "DELETE",
    body: JSON.stringify({ id }),
  });
}

function toggleWhitelistEntry(id, enabled) {
  return fetchJsonPromise("/api/whitelist/toggle", {
    method: "POST",
    body: JSON.stringify({ id, enabled: Boolean(enabled) }),
  });
}

// Whitelisting an IP from the IP graph's popup is deliberately stronger
// than a plain whitelist entry: it also forgets everything already
// captured about that host (see sniff4hound/app.py:whitelist_ip). Call
// without `confirm` first to get a real packet count for a confirmation
// prompt, then again with `confirm: true` to actually do it.
function whitelistIpAndForget(ip, { confirm = false } = {}) {
  return fetchJsonPromise("/api/whitelist/ip", {
    method: "POST",
    body: JSON.stringify({ ip, confirm: Boolean(confirm) }),
  });
}

function buildIntelQuery({ search = "", limit = 200, offset = 0, scope = "", ip = "" } = {}) {
  const params = new URLSearchParams();
  if (search) params.set("search", search);
  if (limit) params.set("limit", String(limit));
  if (offset) params.set("offset", String(offset));
  // Address-scope filter (public/private/local/...), comma separated.
  // Endpoints that do not know it simply ignore the parameter.
  const scopes = Array.isArray(scope) ? scope.join(",") : String(scope || "");
  if (scopes) params.set("scope", scopes);
  // Narrows domains/paths to one address - the IP graph popup's "dominios
  // y paths asociados". Endpoints that do not know it simply ignore it.
  if (ip) params.set("ip", ip);
  const query = params.toString();
  return query ? `?${query}` : "";
}

function listDomains(options) {
  return fetchJsonPromise(`/api/domains/${buildIntelQuery(options)}`);
}

function listPaths(options) {
  return fetchJsonPromise(`/api/paths/${buildIntelQuery(options)}`);
}

// One protocol slice: counters, protocol-specific facets, timeline, rows,
// banners and tags. Replaces the five separate calls the Protocols view used
// to make on every refresh.
function fetchProtocolSnapshot({ proto = "", limit = 250, search = "", mode = "", interface: iface = "" } = {}) {
  const params = new URLSearchParams();
  if (proto) params.set("proto", proto);
  if (limit) params.set("limit", String(limit));
  if (search) params.set("search", search);
  if (mode) params.set("mode", mode);
  if (iface) params.set("interface", iface);
  const range = state.timeRange;
  if (range) params.set("since", range);
  return fetchJsonPromise(`/api/protocols/snapshot/?${params.toString()}`);
}

// The IP listing, its pagination envelope, and the per-scope breakdown. The
// breakdown rides in the X-Scope-Counts header rather than in the body
// because /api/intel/ips/ answers with a bare array by contract, so this
// needs the response object - which fetchJsonPromise does not hand back.
function listIpCatalogWithScopes(options) {
  return fetchWithMeta(`/api/intel/ips/${buildIntelQuery(options)}`).then(({ data, response }) => {
    const rows = extractArray(data);
    let scopeCounts = null;
    try {
      const raw = response && response.headers ? response.headers.get("X-Scope-Counts") : "";
      if (raw) scopeCounts = JSON.parse(raw) || null;
    } catch {
      // Malformed header: treat it as absent rather than as "all zeroes",
      // so the caller can tell "no breakdown available" from "no traffic".
      scopeCounts = null;
    }
    // The same envelope every other listing gets, so a truncated IP catalog
    // is not presented as a complete one.
    return { rows, scopeCounts, meta: readListMeta(data, response, rows) };
  });
}

// Nodes (same shape as listIpCatalogWithScopes rows, device type included)
// plus edges (src_ip, dst_ip, weight, flow_count) for the IP relationship
// graph - a plain object body, unlike /api/intel/ips/'s bare-array contract.
function fetchIpRelationshipGraph(options) {
  return fetchJsonPromise(`/api/intel/ips/graph${buildIntelQuery(options)}`);
}

function clearDetections(scope) {
  return fetchJsonPromise("/api/data/clear/", {
    method: "POST",
    body: JSON.stringify({ scope: String(scope || "all").trim().toLowerCase() }),
  });
}

function listMonitorPackets(monitorId, options) {
  const params = new URLSearchParams();
  params.set("monitor_id", monitorId);
  const search = (options && options.search) || "";
  const limit = (options && options.limit) || 200;
  if (search) params.set("search", search);
  if (limit) params.set("limit", String(limit));
  return fetchJsonPromise(`/api/monitors/packets/?${params.toString()}`);
}

function apiUrl(path) {
  const base = state.apiBase ? state.apiBase.replace(/\/+$/, "") : "";
  const safePath = path && path.startsWith("/") ? path : `/${path || ""}`;
  return `${base}${safePath}`;
}

function parseJsonSafe(text) {
  try {
    return text ? JSON.parse(text) : null;
  } catch {
    return null;
  }
}

function buildHttpError(res, text, data) {
  const trimmed = (text || "").trim();
  const looksLikeHtml =
    trimmed.startsWith("<!DOCTYPE") ||
    trimmed.startsWith("<html") ||
    trimmed.startsWith("<!doctype");
  const message =
    (data && data.message) ||
    (data && data.status) ||
    (looksLikeHtml
      ? `HTTP ${res.status} ${res.statusText}`
      : trimmed || `HTTP ${res.status} ${res.statusText}`);
  const error = new Error(message);
  error.status = res.status;
  error.payload = data;
  return error;
}

function applyAuthHeader(headers = {}, token = state.authToken) {
  const nextHeaders = { ...headers };
  // Authorization only, not X-Security-Code: the desktop shell's requests
  // are cross-origin now (file:// page, http(s):// API - see apiBase
  // above), and X-Security-Code isn't in the backend's CORS preflight
  // allow-list the way Authorization already is, so sending it would fail
  // preflight and block the request entirely. The backend already checks
  // Authorization first (see _extract_request_token in sniff4hound/app.py),
  // so this loses nothing.
  if (
    token &&
    !nextHeaders.Authorization &&
    !nextHeaders.authorization
  ) {
    nextHeaders.Authorization = `Bearer ${token}`;
  }
  return nextHeaders;
}

function clearReconnectTimer() {
  if (!wsReconnectTimer) return;
  clearTimeout(wsReconnectTimer);
  wsReconnectTimer = null;
}

function destroyRealtime() {
  wsConnectAttempt += 1;
  clearReconnectTimer();
  stopLiveActivityTicker();
  if (wsRefreshTimer) {
    clearTimeout(wsRefreshTimer);
    wsRefreshTimer = null;
  }
  wsPendingRefreshPayload = null;
  wsCoalescedEventCount = 0;
  if (!wsClient) {
    if (state.authRequired && state.authStatus !== "authenticated") {
      lockRealtimeForAuth();
    } else {
      state.wsStatus = "offline";
    }
    return;
  }
  const socket = wsClient;
  wsClient = null;
  try {
    socket.close();
  } catch {
    // ignore close failures
  } finally {
    if (state.authRequired && state.authStatus !== "authenticated") {
      lockRealtimeForAuth();
    } else {
      state.wsStatus = "offline";
    }
  }
}

function openAuthPrompt(message = "") {
  if (message) {
    state.authError = String(message);
  }
  state.authPromptOpen = true;
  state.authReady = true;
  if (state.authRequired) {
    state.authStatus = "required";
  }
  destroyRealtime();
}

function handleUnauthorized(message = "Authentication required") {
  setAuthToken("");
  state.authRequired = true;
  state.authStatus = "required";
  state.authError = String(message || "Authentication required");
  state.authPromptOpen = true;
  state.authReady = true;
  destroyRealtime();
}

// --- GET over the websocket -------------------------------------------------
// Reads travel on the socket that is already open; HTTP is left for static
// assets, for the methods that change state, and for downloads. Intercepted
// here rather than in each view so every existing caller of fetchJsonPromise
// and fetchListPromise gets it without being rewritten - and so a single
// place decides when to fall back.

const WS_GET_TIMEOUT_MS = 15000;
// Downloads: they answer with CSV and Content-Disposition, which is a file
// transfer, not a data read.
const WS_GET_DENIED_PREFIXES = ["/api/export/"];
const pendingWsGets = new Map();
let wsGetSequence = 0;

// How long a read waits for a socket that is still connecting. At startup the
// views mount before the handshake completes, so without this every first
// paint fell straight through to HTTP - which is exactly the burst of GETs
// still visible in the access log after the reads were moved to the socket.
const WS_GET_CONNECT_GRACE_MS = 1500;

function isWsGetEligible(path, options) {
  const method = String((options && options.method) || "GET").toUpperCase();
  if (method !== "GET") return false;
  if (typeof window === "undefined" || typeof window.WebSocket === "undefined") return false;
  const clean = String(path || "").split("?")[0];
  return !WS_GET_DENIED_PREFIXES.some((prefix) => clean.startsWith(prefix));
}

function waitForWsOpen(timeoutMs = WS_GET_CONNECT_GRACE_MS) {
  if (typeof window === "undefined" || typeof window.WebSocket === "undefined") {
    return Promise.resolve(false);
  }
  if (wsClient && wsClient.readyState === window.WebSocket.OPEN) return Promise.resolve(true);
  // Only worth waiting for a socket that is actually on its way. A closed or
  // absent one would just delay the HTTP read by the whole grace period.
  if (!wsClient || wsClient.readyState !== window.WebSocket.CONNECTING) {
    return Promise.resolve(false);
  }
  const socket = wsClient;
  return new Promise((resolve) => {
    let settled = false;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      socket.removeEventListener("open", onOpen);
      socket.removeEventListener("error", onFail);
      socket.removeEventListener("close", onFail);
      resolve(value);
    };
    const onOpen = () => finish(true);
    const onFail = () => finish(false);
    socket.addEventListener("open", onOpen);
    socket.addEventListener("error", onFail);
    socket.addEventListener("close", onFail);
    setTimeout(() => finish(false), timeoutMs);
  });
}

function resolveWsGet(payload) {
  const pending = pendingWsGets.get(String(payload.id || ""));
  if (!pending) return;
  pendingWsGets.delete(String(payload.id || ""));
  clearTimeout(pending.timer);
  pending.settle(payload);
}

function wsGet(path) {
  const [bare, search = ""] = String(path || "").split("?");
  const params = {};
  new URLSearchParams(search).forEach((value, key) => {
    params[key] = value;
  });
  const id = `get-${++wsGetSequence}`;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      pendingWsGets.delete(id);
      // Rejecting rather than hanging: the caller falls back to HTTP, which is
      // the difference between a slow view and a permanently empty one.
      reject(new Error("websocket read timed out"));
    }, WS_GET_TIMEOUT_MS);
    pendingWsGets.set(id, {
      timer,
      settle: (payload) => {
        const status = Number(payload.status || 0);
        if (status === 401) {
          handleUnauthorized((payload.data && payload.data.message) || "Session expired.");
        }
        if (status < 200 || status >= 300) {
          const error = new Error(
            payload.error || (payload.data && payload.data.message) || `Request failed (${status})`
          );
          error.status = status;
          reject(error);
          return;
        }
        resolve({
          data: payload.data,
          // Shaped like a fetch Response for readListMeta(), which reads the
          // X-Total-Available / X-Returned / X-Scope-Counts headers the listing
          // endpoints answer with. Dropping them would blank the "showing N of
          // M" line and the IP scope chips.
          response: {
            ok: true,
            status,
            headers: {
              get: (name) => {
                const wanted = String(name || "").toLowerCase();
                const found = Object.keys(payload.headers || {}).find(
                  (key) => key.toLowerCase() === wanted
                );
                return found ? payload.headers[found] : null;
              },
            },
          },
        });
      },
    });
    try {
      wsClient.send(JSON.stringify({ action: "get", id, path: bare, params }));
    } catch (err) {
      pendingWsGets.delete(id);
      clearTimeout(timer);
      reject(err);
    }
  });
}

function fetchWithMeta(path, options = {}, config = {}) {
  const opts = { ...options };
  const attachAuth = config.attachAuth !== false;
  const token = Object.prototype.hasOwnProperty.call(config, "token")
    ? config.token
    : state.authToken;
  opts.headers = attachAuth ? applyAuthHeader(opts.headers || {}, token) : { ...(opts.headers || {}) };
  if (opts.body && !opts.headers["Content-Type"] && !opts.headers["content-type"]) {
    opts.headers["Content-Type"] = "application/json";
  }
  if (isWsGetEligible(path, options) && config.preferHttp !== true) {
    return waitForWsOpen().then((ready) => {
      if (!ready) return httpFetchWithMeta(path, opts, config);
      // On any websocket trouble the same request goes out over HTTP, so a
      // read never fails just because the socket did. A status carried back
      // from the server is a real answer, though, and must not be retried.
      return wsGet(path).catch((err) => {
        if (err && err.status) throw err;
        return httpFetchWithMeta(path, opts, config);
      });
    });
  }
  return httpFetchWithMeta(path, opts, config);
}

function httpFetchWithMeta(path, opts, config) {
  return fetch(apiUrl(path), opts).then((res) =>
    res.text().then((text) => {
      const data = parseJsonSafe(text);
      if (!res.ok) {
        const error = buildHttpError(res, text, data);
        if (res.status === 401 && config.handleUnauthorized !== false) {
          handleUnauthorized((data && data.message) || error.message);
        }
        throw error;
      }
      // 201 + job_id means the backend queued this instead of answering it
      // (see sniff4hound/jobs.py): it ran past the inline window, so the
      // result has to be collected separately. Handled here rather than at
      // each call site so every existing caller keeps its plain "promise of
      // the payload" contract and needs no change.
      if (res.status === 201 && data && data.job_id) {
        return awaitJob(data.job_id, config).then(result => ({ data: result, response: res }));
      }
      return { data, response: res };
    })
  );
}

// --- deferred jobs ---------------------------------------------------------
// The jobs currently being waited on, so a "job_update" frame can wake one the
// moment it finishes instead of leaving it to sit out the rest of its poll
// interval.
//
// A set of records rather than a map keyed by job id: two callers can end up
// waiting on the same id, and keying by it meant the second registration
// silently replaced the first, leaving that one to fall back to its timer. It
// also keeps the frame's id - a value off the wire - out of any position where
// it selects what gets invoked.
const jobWaiters = new Set();

function notifyJobFinished(jobId) {
  const id = String(jobId || "");
  if (!id) return;
  for (const waiter of jobWaiters) {
    if (waiter.id === id) waiter.wake();
  }
}

// Starts tight - most deferred jobs are only just past the inline window -
// then backs off, so a genuinely long one does not fire hundreds of requests
// while it runs.
function jobPollDelay(attempt) {
  return Math.min(JOB_POLL_MAX_MS, Math.round(JOB_POLL_MIN_MS * Math.pow(1.6, attempt)));
}

function awaitJob(jobId, config = {}) {
  const id = String(jobId || "").trim();
  if (!id) return Promise.reject(new Error("Missing job id"));
  state.pendingJobs += 1;
  let attempt = 0;
  // Held at this scope so the final cleanup can drop a registration left
  // behind when the poll rejects mid-wait.
  let currentWaiter = null;

  const poll = () => fetchJsonPromise(`/api/jobs/?id=${encodeURIComponent(id)}`, {}, {
    ...config,
    preferHttp: true,
  }).then((job) => {
    const status = String((job && job.status) || "").toLowerCase();
    if (status === "done") return job.result;
    if (status === "error") {
      const error = new Error(job.error || "La petición falló en el servidor.");
      error.code = job.error_type || "job_failed";
      throw error;
    }
    // Still queued or running: continue on whichever comes first, the
    // websocket nudge or the next scheduled check.
    return new Promise((resolve) => {
      const timer = setTimeout(resolve, jobPollDelay(attempt));
      currentWaiter = {
        id,
        wake: () => {
          clearTimeout(timer);
          resolve();
        },
      };
      jobWaiters.add(currentWaiter);
    }).then(() => {
      jobWaiters.delete(currentWaiter);
      currentWaiter = null;
      attempt += 1;
      return poll();
    });
  });

  return poll().finally(() => {
    if (currentWaiter) jobWaiters.delete(currentWaiter);
    state.pendingJobs = Math.max(0, state.pendingJobs - 1);
  });
}

function fetchJsonPromise(path, options = {}, config = {}) {
  return fetchWithMeta(path, options, config).then((result) => result.data);
}

function requestWsTicket() {
  if (!state.authToken) return Promise.resolve("");
  return fetchJsonPromise("/api/ws/ticket", { method: "POST" }, { preferHttp: true })
    .then((payload) => String((payload && payload.ticket) || "").trim());
}

const IOC_EXPORT_DATASETS = new Set(["alerts", "endpoints", "flows", "domains"]);

function exportFilenameFromResponse(res, fallback) {
  try {
    const disposition = res.headers.get("Content-Disposition") || "";
    const match = /filename="?([^";]+)"?/i.exec(disposition);
    if (match && match[1]) return match[1];
  } catch {
    // header not readable: fall back to a locally built name
  }
  return fallback;
}

// Server-side IOC export (see sniff4hound/export.py). Deliberately not the
// client-side rowsToCsv() the table panels use: those can only serialise the
// page of rows already loaded into the browser, while these endpoints export
// the full window straight from the database, with severity, the rule that
// fired and first/last seen attached.
function downloadIocExport(dataset, format = "csv", params = {}) {
  const name = String(dataset || "").trim().toLowerCase();
  if (!IOC_EXPORT_DATASETS.has(name)) {
    return Promise.reject(new Error(`Unknown export dataset: ${dataset}`));
  }
  const fmt = String(format || "csv").trim().toLowerCase() === "json" ? "json" : "csv";
  const query = new URLSearchParams();
  query.set("format", fmt);
  const since = Object.prototype.hasOwnProperty.call(params, "since") ? params.since : state.timeRange;
  if (since) query.set("since", String(since));
  Object.keys(params).forEach((key) => {
    if (key === "since") return;
    const value = params[key];
    if (value === null || value === undefined || value === "") return;
    query.set(key, String(value));
  });
  return fetch(apiUrl(`/api/export/${name}?${query.toString()}`), {
    headers: applyAuthHeader({}),
  }).then((res) =>
    res.text().then((text) => {
      if (!res.ok) {
        const data = parseJsonSafe(text);
        const error = buildHttpError(res, text, data);
        if (res.status === 401) {
          handleUnauthorized((data && data.message) || error.message);
        }
        throw error;
      }
      const filename = exportFilenameFromResponse(res, buildExportFilename(name, fmt));
      downloadTextFile(filename, text, fmt === "csv" ? "text/csv" : "application/json");
      return filename;
    })
  );
}

function fetchJson(path, options = {}) {
  return fetchJsonPromise(path, options);
}

function normalizeTimeRange(value) {
  const cleaned = String(value === null || value === undefined ? "" : value).trim().toLowerCase();
  return TIME_RANGE_VALUES.has(cleaned) ? cleaned : "";
}

function initTimeRange() {
  if (typeof window === "undefined" || !window.localStorage) {
    state.timeRange = "";
    return;
  }
  state.timeRange = normalizeTimeRange(window.localStorage.getItem(STORAGE_KEY_TIME_RANGE));
}

function setTimeRange(value) {
  const normalized = normalizeTimeRange(value);
  state.timeRange = normalized;
  if (typeof window !== "undefined" && window.localStorage) {
    try {
      window.localStorage.setItem(STORAGE_KEY_TIME_RANGE, normalized);
    } catch {
      // storage disabled: the range still applies for this tab
    }
  }
  return normalized;
}

// Human-readable name of the active window, for "showing X of Y in the last
// hour" style notices. Empty string when no filter is applied.
function timeRangeLabel(value = undefined) {
  const active = value === undefined ? state.timeRange : normalizeTimeRange(value);
  if (!active) return "";
  const option = TIME_RANGE_OPTIONS.find((entry) => entry.value === active);
  return option ? option.description.toLowerCase() : "";
}

// Builds the query string for a list endpoint, always folding in the global
// time range. `since`/`limit`/`offset` are additive parameters the API ignores
// when it does not know them yet, so this is safe before the backend ships.
function buildListQuery({ params = {}, limit = null, offset = 0, since = undefined } = {}) {
  const search = new URLSearchParams();
  Object.keys(params || {}).forEach((key) => {
    const value = params[key];
    if (value === null || value === undefined || value === "") return;
    search.set(key, String(value));
  });
  const window_ = since === undefined ? state.timeRange : normalizeTimeRange(since);
  if (window_) search.set("since", window_);
  if (Number.isFinite(Number(limit)) && Number(limit) > 0) search.set("limit", String(Math.floor(Number(limit))));
  if (Number.isFinite(Number(offset)) && Number(offset) > 0) search.set("offset", String(Math.floor(Number(offset))));
  const query = search.toString();
  return query ? `?${query}` : "";
}

function firstFiniteNumber(candidates) {
  for (const candidate of candidates) {
    if (candidate === null || candidate === undefined || candidate === "") continue;
    const parsed = Number(candidate);
    if (Number.isFinite(parsed) && parsed >= 0) return parsed;
  }
  return null;
}

function coerceBoolean(value) {
  if (value === null || value === undefined || value === "") return null;
  if (typeof value === "boolean") return value;
  const text = String(value).trim().toLowerCase();
  if (["1", "true", "yes"].includes(text)) return true;
  if (["0", "false", "no"].includes(text)) return false;
  return null;
}

// Reads the pagination envelope the API adds on top of a list response. It is
// deliberately tolerant: the values may arrive as object fields, as HTTP
// headers, or not at all - in which case every field is simply null and the
// UI falls back to "we do not know how much was left behind".
function readListMeta(payload, response, rows) {
  const headers = response && response.headers && typeof response.headers.get === "function"
    ? response.headers
    : null;
  const header = (name) => (headers ? headers.get(name) : null);
  const envelope = payload && typeof payload === "object" && !Array.isArray(payload) ? payload : {};
  const returned = firstFiniteNumber([envelope.returned, header("X-Returned"), rows.length]);
  const totalAvailable = firstFiniteNumber([envelope.total_available, header("X-Total-Available")]);
  let truncated = coerceBoolean(
    envelope.truncated !== undefined ? envelope.truncated : header("X-Truncated")
  );
  if (truncated === null && totalAvailable !== null && returned !== null) {
    truncated = totalAvailable > returned;
  }
  return { returned, totalAvailable, truncated };
}

function fetchListPromise(path, options = {}) {
  const query = buildListQuery(options);
  return fetchWithMeta(`${path}${query}`).then(({ data, response }) => {
    const rows = extractArray(data);
    return { rows, meta: readListMeta(data, response, rows), payload: data };
  });
}

function requestSessionAuth(token = state.authToken) {
  const headers = token ? { "X-Security-Code": token } : {};
  return fetchJsonPromise(
    AUTH_SESSION_PATH,
    { method: "GET", headers },
    { attachAuth: false, handleUnauthorized: false }
  );
}

function activateAuthenticatedSession() {
  state.authStatus = "authenticated";
  state.authError = "";
  state.authPromptOpen = false;
  state.authReady = true;
  return initRuntime().finally(() => {
    reconnectRealtime();
  });
}

function bootstrap() {
  state.authReady = false;
  state.authError = "";
  state.shutdownPending = false;
  state.authToken = readStoredAuthToken();
  return requestSessionAuth(state.authToken)
    .then((payload) => {
      state.authRequired = Boolean(payload && payload.require_auth);
      if (!state.authRequired) {
        return activateAuthenticatedSession().then(() => payload);
      }
      if (payload && payload.authenticated) {
        return activateAuthenticatedSession().then(() => payload);
      }
      state.authStatus = "required";
      state.authReady = true;
      state.authPromptOpen = true;
      state.authError = String((payload && payload.message) || "Security code required");
      setAuthToken("");
      destroyRealtime();
      return payload;
    })
    .catch(() => {
      state.authReady = true;
      if (state.authRequired && state.authStatus !== "authenticated") {
        lockRealtimeForAuth();
      }
      return null;
    });
}

function authenticateSessionToken(rawToken) {
  const token = String(rawToken || "").trim();
  if (!token) {
    const error = new Error("Security code required");
    state.authRequired = true;
    state.authStatus = "required";
    state.authError = error.message;
    state.authPromptOpen = true;
    return Promise.reject(error);
  }
  return requestSessionAuth(token).then((payload) => {
    state.authRequired = Boolean(payload && payload.require_auth);
    if (!payload || !payload.authenticated) {
      handleUnauthorized((payload && payload.message) || "Invalid security code");
      throw new Error((payload && payload.message) || "Invalid security code");
    }
    setAuthToken(token);
    return activateAuthenticatedSession().then(() => payload);
  });
}

function extractArray(payload) {
  if (Array.isArray(payload)) return payload;
  if (payload && Array.isArray(payload.datas)) return payload.datas;
  return [];
}

function notifyTableRefresh(payload) {
  if (!tableRefreshSubscribers.size) return;
  tableRefreshSubscribers.forEach((subscriber) => {
    try {
      subscriber(payload);
    } catch {
      // ignore subscriber-level failures
    }
  });
}

function notifyMapSnapshotSubscribers(snapshot, meta = {}) {
  if (!mapSnapshotSubscribers.size) return;
  const payload = { snapshot, meta };
  mapSnapshotSubscribers.forEach((subscriber) => {
    try {
      subscriber(payload);
    } catch {
      // ignore subscriber-level failures
    }
  });
}

function applyRealtimeMapSnapshot(snapshot, meta = {}) {
  const normalized = snapshot && typeof snapshot === "object" ? snapshot : null;
  state.realtimeMapSnapshot = normalized;
  state.realtimeMapGeneratedAt = String(meta.generatedAt || meta.generated_at || "").trim();
  if (!normalized) return;
  notifyMapSnapshotSubscribers(normalized, meta);
}

// --- protocol snapshot stream ---------------------------------------------
// The Protocols view used to refresh itself with a full HTTP GET of
// /api/protocols/snapshot/ every few seconds, per open tab: a fresh
// connection, a re-authenticated request and an access-log line, all to
// redeliver a slice the server could have pushed down the socket that was
// already open. These carry the same payload over the existing connection.

const protocolSnapshotSubscribers = new Set();
// Remembered so the stream can be re-established after a reconnect. Without
// this the view would sit on a stale slice with no visible error: the socket
// comes back, but the server has no record of what this client was watching.
let protocolSnapshotRequest = null;

function subscribeProtocolSnapshot(handler) {
  if (typeof handler !== "function") return () => {};
  protocolSnapshotSubscribers.add(handler);
  return () => protocolSnapshotSubscribers.delete(handler);
}

function notifyProtocolSnapshotSubscribers(payload) {
  protocolSnapshotSubscribers.forEach((handler) => {
    try {
      handler(payload);
    } catch {
      // A failing view must not stop the others from updating.
    }
  });
}

function sendWsAction(message) {
  if (typeof window === "undefined" || typeof window.WebSocket === "undefined") {
    return false;
  }
  if (!wsClient || wsClient.readyState !== window.WebSocket.OPEN) {
    return false;
  }
  try {
    wsClient.send(JSON.stringify(message));
    return true;
  } catch {
    return false;
  }
}

function startProtocolSnapshotStream(params = {}) {
  const request = {
    action: "subscribe_protocol_snapshot",
    proto: String(params.proto || "").trim().toLowerCase(),
    mode: String(params.mode || "").trim().toLowerCase(),
    interface: String(params.interface || "").trim(),
    search: String(params.search || "").trim(),
    since: String(params.since || "").trim(),
    limit: Number(params.limit) || 250,
    interval: Number(params.interval) || 10,
  };
  protocolSnapshotRequest = request;
  return sendWsAction(request);
}

function stopProtocolSnapshotStream() {
  protocolSnapshotRequest = null;
  return sendWsAction({ action: "unsubscribe_protocol_snapshot" });
}

function resumeProtocolSnapshotStream() {
  if (!protocolSnapshotRequest) return false;
  return sendWsAction(protocolSnapshotRequest);
}

function requestRealtimeMapSnapshot(limit = 300) {
  if (typeof window === "undefined" || typeof window.WebSocket === "undefined") {
    return false;
  }
  if (!wsClient || wsClient.readyState !== window.WebSocket.OPEN) {
    return false;
  }
  try {
    wsClient.send(JSON.stringify({ action: "scan_map_snapshot", limit: Number(limit) || 300 }));
    return true;
  } catch {
    return false;
  }
}

function initNotifySound() {
  if (typeof window === "undefined" || !window.localStorage) {
    state.notifySoundEnabled = true;
    return;
  }
  const stored = window.localStorage.getItem(STORAGE_KEY_NOTIFY_SOUND);
  state.notifySoundEnabled = stored === null ? true : stored === "1";
}

function setNotifySoundEnabled(enabled) {
  state.notifySoundEnabled = Boolean(enabled);
  if (typeof window !== "undefined" && window.localStorage) {
    window.localStorage.setItem(STORAGE_KEY_NOTIFY_SOUND, state.notifySoundEnabled ? "1" : "0");
  }
}

function ensureAudioContext() {
  if (typeof window === "undefined") return null;
  const AudioContextClass = window.AudioContext || window.webkitAudioContext;
  if (!AudioContextClass) return null;
  if (!audioContext) {
    try {
      audioContext = new AudioContextClass();
    } catch {
      return null;
    }
  }
  if (audioContext.state === "suspended" && typeof audioContext.resume === "function") {
    audioContext.resume().catch(() => {});
  }
  return audioContext;
}

function playTone(ctx, { frequency, startTime, duration, gain = 0.07 }) {
  const oscillator = ctx.createOscillator();
  const gainNode = ctx.createGain();
  oscillator.type = "sine";
  oscillator.frequency.setValueAtTime(frequency, startTime);
  gainNode.gain.setValueAtTime(0, startTime);
  gainNode.gain.linearRampToValueAtTime(gain, startTime + 0.015);
  gainNode.gain.exponentialRampToValueAtTime(0.0001, startTime + duration);
  oscillator.connect(gainNode);
  gainNode.connect(ctx.destination);
  oscillator.start(startTime);
  oscillator.stop(startTime + duration + 0.03);
}

function playNotificationSound(severity) {
  if (!state.notifySoundEnabled) return;
  const ctx = ensureAudioContext();
  if (!ctx) return;
  try {
    const now = ctx.currentTime;
    if (severity === "critical" || severity === "high") {
      // Two-tone rising chirp - more urgent, harder to miss.
      playTone(ctx, { frequency: 880, startTime: now, duration: 0.11, gain: 0.09 });
      playTone(ctx, { frequency: 1108, startTime: now + 0.12, duration: 0.14, gain: 0.09 });
    } else {
      // Single soft ping for everything else.
      playTone(ctx, { frequency: 660, startTime: now, duration: 0.15, gain: 0.055 });
    }
  } catch {
    // Best-effort only - autoplay restrictions or a missing AudioContext
    // must never break the notification itself.
  }
}

// Best-effort: only matters in a plain browser tab (a user gesture may be
// required before the prompt is even allowed to show). Electron's default
// session auto-grants permission requests, so this is a no-op there -
// Notification.permission already reads "granted" before this ever runs.
function ensureNotificationPermission() {
  if (typeof Notification === "undefined" || notificationPermissionRequested) return;
  notificationPermissionRequested = true;
  if (Notification.permission === "default") {
    Notification.requestPermission().catch(() => {});
  }
}

// Native OS notification via the standard Web Notification API - inside
// Electron's renderer this surfaces as a real system notification with no
// extra main-process plumbing needed. `silent: true` because the app's own
// severity-based tone (playNotificationSound) is the intended audio cue;
// without it the OS would layer its own default "ding" on top.
function showSystemNotification({ title, body, tag, href }) {
  ensureNotificationPermission();
  if (typeof Notification === "undefined" || Notification.permission !== "granted") return;
  try {
    const notification = new Notification(title, { body, tag, silent: true });
    if (href) {
      notification.onclick = () => {
        try { window.focus(); } catch { /* not focusable in this context */ }
        router.push(href).catch(() => {});
        notification.close();
      };
    }
  } catch {
    // Best-effort only - an unsupported platform or a stale permission edge
    // case must never break the underlying alert (the sound already covers
    // it) or the caller.
  }
}

function pushNotification({
  kind = "info",
  severity = "info",
  title = "",
  message = "",
  groupKey = "",
  href = "",
} = {}) {
  const cleanTitle = String(title || "").trim();
  if (!cleanTitle) return null;
  const normalizedSeverity = String(severity || "info").trim().toLowerCase();
  const normalizedHref = String(href || "").trim();
  // Reusing the same tag for a repeat occurrence (a noisy monitor, a
  // flapping connection) lets the OS/browser coalesce it into the existing
  // notification instead of piling up duplicates - same intent as the old
  // in-app list's "bump an existing entry's counter".
  const tag = groupKey || `${kind}:${cleanTitle}`;
  playNotificationSound(normalizedSeverity);
  showSystemNotification({ title: cleanTitle, body: String(message || "").trim(), tag, href: normalizedHref });
  return { kind, severity: normalizedSeverity, title: cleanTitle, message, href: normalizedHref };
}

function parsePacketTags(packet) {
  if (!packet) return [];
  if (Array.isArray(packet.tags)) return packet.tags;
  const raw = packet.tags_json;
  if (typeof raw !== "string" || !raw) return [];
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function extractMonitorHitsFromTags(tags) {
  // sniff4hound.sniffer._build_packet_tags emits a "monitor" tag immediately
  // followed by that same hit's "monitor_id" (and "detail") tags, in that
  // fixed order - see sniff4hound/sniffer.py. Group consecutive entries back
  // into one hit per monitor instead of relying on a shared index.
  const hits = [];
  let current = null;
  tags.forEach((tag) => {
    if (!tag) return;
    if (tag.key === "monitor") {
      const label = String(tag.value || "").trim();
      if (!label) {
        current = null;
        return;
      }
      current = { label, severity: String(tag.severity || "info").trim().toLowerCase(), monitorId: "" };
      hits.push(current);
    } else if (tag.key === "monitor_id" && current) {
      current.monitorId = String(tag.value || "").trim();
    }
  });
  return hits;
}

function notifyForPacketEvent(payload) {
  const packet = payload && payload.packet;
  const tags = parsePacketTags(packet);
  if (!tags.length) return;
  const hits = extractMonitorHitsFromTags(tags).filter((hit) => NOTIFY_MONITOR_SEVERITIES.has(hit.severity));
  if (!hits.length) return;
  const srcIp = String((packet && packet.src_ip) || "").trim();
  const dstIp = String((packet && packet.dst_ip) || "").trim();
  const dstPort = (packet && packet.dst_port) || "";
  const route = srcIp && dstIp ? `${srcIp} → ${dstIp}${dstPort ? `:${dstPort}` : ""}` : "";
  hits.forEach((hit) => {
    // Honeypot hits have no real entry in the monitors catalog - this traffic
    // never runs through evaluate_packet/AnomalyEngine, so send it to the
    // dedicated honeypot table instead.
    const isHoneypotHit = hit.monitorId === "builtin-honeypot-hit";
    pushNotification({
      kind: "monitor",
      severity: hit.severity,
      title: hit.label,
      message: route,
      // Grouped by monitor alone (not monitor+source) - "solo una por
      // monitor maximo": every hit for the same monitor bumps one counter
      // instead of piling up a separate entry per source IP.
      groupKey: `monitor:${hit.monitorId || hit.label}`,
      href: isHoneypotHit ? "/honeypot" : `/monitors?monitor=${encodeURIComponent(hit.monitorId || hit.label)}`,
    });
  });
}

function notifyForRuntimeChange(payload) {
  const runtime = (payload && (payload.runtime || payload)) || {};
  const mode = String(runtime.mode || "").trim().toLowerCase();
  const active = runtime.active && typeof runtime.active === "object" ? runtime.active : {};
  const running = Boolean(active.running);
  const previous = lastRuntimeForNotify;
  lastRuntimeForNotify = { mode, running };
  if (!mode || !previous) return; // skip the very first snapshot after (re)connecting
  if (previous.mode !== mode) {
    pushNotification({
      kind: "runtime",
      severity: "medium",
      title: "Runtime mode changed",
      message: `Switched to ${mode} mode`,
      groupKey: "runtime:mode",
    });
    return;
  }
  if (previous.running !== running) {
    pushNotification({
      kind: "runtime",
      severity: running ? "low" : "medium",
      title: running ? "Capture started" : "Capture stopped",
      message: `${mode} engine is now ${running ? "running" : "stopped"}`,
      groupKey: "runtime:running",
    });
  }
}

function notifyForChatMessage(payload) {
  // Bumped on every inbound chat frame so ChatView can refresh (and count
  // unread) off a single watcher instead of polling.
  state.chatRevision = (state.chatRevision || 0) + 1;
  const message = payload && payload.message;
  const content = message && String(message.content || "").trim();
  if (!content) return;
  const author = String((message && message.author) || "operator").trim() || "operator";
  // Commands typed in this browser produce a dashboard row plus a system
  // result row. They are already visible in the operations console and must
  // not turn into two self-notifications in the bell.
  if (author === "dashboard" || author === "system") return;
  pushNotification({
    kind: "broadcast",
    severity: "info",
    title: `Note from ${author}`,
    message: content,
    groupKey: `broadcast:${content}`,
  });
}

function notifyForConnectionChange(kind) {
  if (kind === "restored") {
    pushNotification({
      kind: "connection",
      severity: "low",
      title: "Realtime connection restored",
      message: "Live packet/stats stream reconnected.",
      groupKey: "connection:restored",
    });
  } else if (kind === "lost") {
    pushNotification({
      kind: "connection",
      severity: "medium",
      title: "Realtime connection lost",
      message: "Reconnecting to the live packet/stats stream...",
      groupKey: "connection:lost",
    });
  }
}

function evaluateNotificationsForMessage(type, payload) {
  if (type === "packet") {
    notifyForPacketEvent(payload);
  } else if (type === "runtime_mode") {
    notifyForRuntimeChange(payload);
  } else if (type === "chat_message") {
    notifyForChatMessage(payload);
  }
}

// --- live activity (packets/second) ----------------------------------------
// Arrival timestamps for the current window, newest last. Only ever holds a
// few seconds of events, so the linear scan on each tick stays trivial even
// under a heavy capture.
const liveActivityEvents = [];
let liveActivityTimer = null;

function isHoneypotInterface(name) {
  const iface = String(name || "").trim().toLowerCase();
  return iface === "honeypot" || iface.startsWith("honeypot")
    || iface === "service" || iface.startsWith("service:");
}

function recomputeLiveActivity() {
  const cutoff = Date.now() - LIVE_ACTIVITY_WINDOW_MS;
  while (liveActivityEvents.length && liveActivityEvents[0].at < cutoff) {
    liveActivityEvents.shift();
  }
  const seconds = LIVE_ACTIVITY_WINDOW_MS / 1000;
  let honeypot = 0;
  for (const event of liveActivityEvents) {
    if (event.honeypot) honeypot += 1;
  }
  const total = liveActivityEvents.length;
  const activity = state.liveActivity;
  activity.total = total / seconds;
  activity.honeypot = honeypot / seconds;
  activity.sniffer = (total - honeypot) / seconds;
  if (!total) activity.total = activity.sniffer = activity.honeypot = 0;
}

function recordLiveActivity(type, payload) {
  if (type !== "packet") return;
  const packet = payload && payload.packet;
  liveActivityEvents.push({
    at: Date.now(),
    honeypot: isHoneypotInterface(packet && packet.interface),
  });
  state.liveActivity.lastPacketAt = Date.now();
  state.liveActivity.seen += 1;
}

// The window has to keep draining even when nothing is arriving, otherwise a
// capture that goes quiet would freeze the wires at their last busy rate
// instead of visibly settling down.
function startLiveActivityTicker() {
  if (liveActivityTimer) return;
  liveActivityTimer = setInterval(recomputeLiveActivity, LIVE_ACTIVITY_TICK_MS);
}

function stopLiveActivityTicker() {
  if (liveActivityTimer) clearInterval(liveActivityTimer);
  liveActivityTimer = null;
  liveActivityEvents.length = 0;
  Object.assign(state.liveActivity, { total: 0, sniffer: 0, honeypot: 0 });
}

function scheduleTableRefresh(payload) {
  wsPendingRefreshPayload = payload;
  // The throttle below drops every event that arrives while a flush is
  // pending. Counting them first is what lets a paused panel say "142 updates
  // pending" instead of silently swallowing the burst.
  wsCoalescedEventCount += 1;
  if (wsRefreshTimer) return;
  wsRefreshTimer = setTimeout(() => {
    wsRefreshTimer = null;
    const pending = wsPendingRefreshPayload
      ? { ...wsPendingRefreshPayload, eventCount: wsCoalescedEventCount }
      : wsPendingRefreshPayload;
    wsPendingRefreshPayload = null;
    wsCoalescedEventCount = 0;
    const type = String((pending && pending.type) || "").trim().toLowerCase();
    if (
      mapSnapshotSubscribers.size &&
      (type === "packet" || type === "stats_update" || type === "scan_map_update")
    ) {
      requestRealtimeMapSnapshot(300);
    }
    notifyTableRefresh(pending);
  }, WS_REFRESH_THROTTLE_MS);
}

// --- per-feed websocket streams --------------------------------------------
// One socket per data feed, with everything the stream needs in its URL:
//   /ws/<feed>?ws_ticket=...&refresh=1000&limit=500&proto=arp
//
// Changing what you are watching closes the socket and opens another. That is
// the point of putting the parameters in the URL rather than in a subscribe
// message: a live connection can never end up serving a slice its URL does not
// describe, so there is no state to get out of step on either side.

function feedUrl(feed, params = {}, ticket = "") {
  let base = state.apiBase;
  if (!base && typeof window !== "undefined") {
    base = window.location.origin;
  }
  const query = new URLSearchParams();
  if (ticket) query.set("ws_ticket", ticket);
  Object.entries(params).forEach(([key, value]) => {
    if (value === undefined || value === null || value === "") return;
    query.set(key, String(value));
  });
  const path = `/ws/${String(feed || "").replace(/^\/+|\/+$/g, "")}`;
  try {
    const parsed = new URL(base);
    parsed.protocol = parsed.protocol === "https:" ? "wss:" : "ws:";
    parsed.pathname = path;
    parsed.search = query.toString();
    return parsed.toString();
  } catch {
    const host = typeof window !== "undefined" ? window.location.host : "127.0.0.1:45678";
    const protocol =
      typeof window !== "undefined" && window.location.protocol === "https:" ? "wss" : "ws";
    const suffix = query.toString();
    return `${protocol}://${host}${path}${suffix ? `?${suffix}` : ""}`;
  }
}

// `onUnavailable` is what lets a view drop its HTTP polling entirely and still
// render: it fires when the socket cannot be opened, or when it opens but the
// first frame does not arrive in time (a server that accepted the connection
// and then went quiet looks exactly like a working one from here). The view
// answers it with a single HTTP read, not by resuming a poll.
const FEED_FIRST_FRAME_TIMEOUT_MS = 4000;
// The server can drop a feed socket at any point (proxy idle timeout, restart,
// its own push-cycle bookkeeping) with no warning to the client. Without a
// reconnect loop here, a view's `loading` flag - set on connect and cleared
// only by an incoming frame - would spin forever once that happens.
const FEED_RECONNECT_BASE_MS = 1000;
const FEED_RECONNECT_MAX_MS = 15000;
const FEED_MAX_SILENT_RECONNECTS = 3;

function openDataFeed(feed, params, onMessage, onUnavailable) {
  const giveUp = () => {
    if (typeof onUnavailable === "function") {
      try {
        onUnavailable();
      } catch {
        // The caller's fallback failing must not break the stream handle.
      }
    }
  };
  if (typeof window === "undefined" || typeof window.WebSocket === "undefined") {
    giveUp();
    return { ok: false, update: () => false, close: () => {}, isOpen: () => false };
  }
  let socket = null;
  let closedByCaller = false;
  let firstFrameTimer = null;
  let reconnectTimer = null;
  let reconnectAttempts = 0;
  let hasGivenUp = false;
  let currentParams = params || {};
  let connectAttempt = 0;

  const clearFirstFrameTimer = () => {
    if (firstFrameTimer) {
      clearTimeout(firstFrameTimer);
      firstFrameTimer = null;
    }
  };
  const clearReconnectTimer = () => {
    if (reconnectTimer) {
      clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }
  };

  const connect = (next) => {
    currentParams = next || {};
    const attempt = ++connectAttempt;
    clearReconnectTimer();
    // Closed before opening the replacement, not after: two sockets for the
    // same feed would both be pushed to, and the view would render whichever
    // frame happened to arrive last.
    if (socket) {
      const previousSocket = socket;
      socket = null;
      try {
        previousSocket.close(1000, "reconfigured");
      } catch {
        // Already closing; the new socket is what matters.
      }
      socket = null;
    }
    if (closedByCaller) return false;
    const openWithTicket = (ticket = "") => {
      if (closedByCaller || attempt !== connectAttempt) return;
      try {
        socket = new window.WebSocket(feedUrl(feed, currentParams, ticket));
      } catch {
        socket = null;
        giveUp();
        return;
      }
      const connectedSocket = socket;
      const isCurrent = () => !closedByCaller && socket === connectedSocket;
      clearFirstFrameTimer();
      firstFrameTimer = setTimeout(() => {
        firstFrameTimer = null;
        if (isCurrent()) giveUp();
      }, FEED_FIRST_FRAME_TIMEOUT_MS);
      socket.addEventListener("error", () => {
        if (!isCurrent()) return;
        clearFirstFrameTimer();
        if (!closedByCaller) giveUp();
      });
      socket.addEventListener("close", () => {
        if (!isCurrent()) return;
        clearFirstFrameTimer();
        if (closedByCaller) return;
        // Keep retrying the connection so a view that already fell back to HTTP
        // still recovers once the stream comes back, but stop leaving the caller
        // hanging past a few attempts - fall back explicitly instead. Only the
        // *first* attempt past the threshold calls giveUp(): without the
        // `hasGivenUp` guard, every subsequent close (the connection keeps
        // retrying in the background) would re-trigger the caller's fallback
        // forever instead of once.
        reconnectAttempts += 1;
        if (reconnectAttempts > FEED_MAX_SILENT_RECONNECTS && !hasGivenUp) {
          hasGivenUp = true;
          giveUp();
        }
        const delay = Math.min(FEED_RECONNECT_BASE_MS * reconnectAttempts, FEED_RECONNECT_MAX_MS);
        reconnectTimer = setTimeout(() => {
          reconnectTimer = null;
          connect(currentParams);
        }, delay);
      });
      socket.addEventListener("message", (event) => {
        if (!isCurrent()) return;
        const payload = parseJsonSafe(event.data);
        if (!payload || typeof payload !== "object") return;
        if (String(payload.type || "") === "auth_required") {
          clearFirstFrameTimer();
          handleUnauthorized(payload.message || "Session expired. Re-enter the security code.");
          return;
        }
        if (String(payload.type || "") === "feed_data") {
          clearFirstFrameTimer();
          reconnectAttempts = 0;
          hasGivenUp = false;
        }
        try {
          onMessage(payload);
        } catch {
          // A failing view must not tear down its own stream.
        }
      });
    };
    if (state.authToken) {
      requestWsTicket().then(openWithTicket).catch(() => giveUp());
    } else {
      openWithTicket("");
    }
    return true;
  };

  const ok = connect(params || {});
  return {
    ok,
    update: (next) => connect(next || {}),
    close: () => {
      closedByCaller = true;
      clearFirstFrameTimer();
      clearReconnectTimer();
      if (socket) {
        try {
          socket.close(1000, "closed");
        } catch {
          // ignore
        }
        socket = null;
      }
    },
    isOpen: () => Boolean(socket && socket.readyState === window.WebSocket.OPEN),
  };
}

// Feeds emit the raw payload their HTTP counterpart returns. The list views
// render a {rows, meta} envelope, so this rebuilds it - `totalAvailable` stays
// null because a stream carries no total, and claiming one would make the
// "showing N of M" line lie.
function feedListResult(payload) {
  const rows = Array.isArray(payload && payload.data) ? payload.data : [];
  return {
    rows,
    meta: { totalAvailable: null, returned: rows.length, truncated: null },
  };
}

function wsUrl(ticket = "") {
  let base = state.apiBase;
  if (!base && typeof window !== "undefined") {
    base = window.location.origin;
  }
  try {
    const parsed = new URL(base);
    parsed.protocol = parsed.protocol === "https:" ? "wss:" : "ws:";
    parsed.pathname = "/ws/";
    parsed.search = "";
    if (ticket) {
      parsed.searchParams.set("ws_ticket", ticket);
    }
    return parsed.toString();
  } catch {
    if (typeof window !== "undefined") {
      const protocol = window.location.protocol === "https:" ? "wss" : "ws";
      const suffix = ticket
        ? `?ws_ticket=${encodeURIComponent(ticket)}`
        : "";
      return `${protocol}://${window.location.host}/ws/${suffix}`;
    }
  }
  const suffix = ticket
    ? `?ws_ticket=${encodeURIComponent(ticket)}`
    : "";
  return `ws://127.0.0.1:45678/ws/${suffix}`;
}

function scheduleReconnect() {
  if (typeof window === "undefined") return;
  if (state.shutdownPending) {
    state.wsStatus = "offline";
    return;
  }
  if (state.authRequired && state.authStatus !== "authenticated") {
    lockRealtimeForAuth();
    return;
  }
  if (wsReconnectTimer) return;
  clearReconnectTimer();
  state.wsStatus = "offline";
  wsReconnectTimer = setTimeout(() => {
    wsReconnectTimer = null;
    connectRealtime();
  }, WS_RECONNECT_DELAY_MS);
}

function reconnectRealtime() {
  if (typeof window === "undefined") return;
  if (state.shutdownPending) {
    state.wsStatus = "offline";
    return;
  }
  destroyRealtime();
  connectRealtime();
}

function connectRealtime() {
  if (typeof window === "undefined" || typeof window.WebSocket === "undefined") {
    state.wsStatus = "offline";
    return;
  }
  if (state.shutdownPending) {
    state.wsStatus = "offline";
    return;
  }
  if (state.authRequired && state.authStatus !== "authenticated") {
    lockRealtimeForAuth();
    return;
  }
  if (state.wsStatus === "connecting") {
    return;
  }
  if (
    wsClient &&
    (wsClient.readyState === window.WebSocket.OPEN ||
      wsClient.readyState === window.WebSocket.CONNECTING)
  ) {
    return;
  }

  state.wsStatus = "connecting";
  const attempt = ++wsConnectAttempt;
  requestWsTicket()
    .then((ticket) => {
      if (attempt !== wsConnectAttempt || state.shutdownPending) return;
      let socket;
      try {
        socket = new window.WebSocket(wsUrl(ticket));
      } catch {
        state.wsStatus = "error";
        scheduleReconnect();
        return;
      }
      wsClient = socket;
      attachRealtimeSocket(socket);
    })
    .catch(() => {
      if (attempt !== wsConnectAttempt) return;
      state.wsStatus = "error";
      scheduleReconnect();
    });
}

function attachRealtimeSocket(socket) {
  socket.addEventListener("open", () => {
    if (wsClient !== socket) return;
    clearReconnectTimer();
    const isReconnect = hasEverConnectedRealtime;
    state.wsStatus = "online";
    startLiveActivityTicker();
    // The server keeps subscriptions per connection, so a reconnect starts
    // with none. Re-sending is what keeps a view that was streaming from
    // quietly freezing on the slice it had when the socket dropped.
    resumeProtocolSnapshotStream();
    if (!requestRealtimeMapSnapshot(300)) {
      state.wsStatus = "error";
    }
    isRealtimeCurrentlyOnline = true;
    if (isReconnect) {
      notifyForConnectionChange("restored");
    }
    hasEverConnectedRealtime = true;
  });

  socket.addEventListener("message", (event) => {
    if (wsClient !== socket) return;
    const payload = parseJsonSafe(event.data);
    if (!payload || typeof payload !== "object") return;
    const type = String(payload.type || "").trim().toLowerCase();
    if (type === "auth_required") {
      handleUnauthorized(payload.message || "Session expired. Re-enter the security code.");
      try {
        socket.close(WS_AUTH_CLOSE_CODE, "Unauthorized");
      } catch {
        // ignore close failures
      }
      return;
    }
    if (type === "runtime_mode") {
      applyRuntimeSnapshot(payload);
    }
    if (type === "data_clear_progress") {
      state.dataClearProgress = payload;
    }
    if (type === "job_update") {
      // Carries no result - a snapshot can be large and every client would
      // get a copy. It only says "stop waiting", and awaitJob() collects the
      // payload over HTTP.
      notifyJobFinished(payload.id);
      return;
    }
    if (type === "get_result") {
      resolveWsGet(payload);
      return;
    }
    if (type === "protocol_snapshot" || type === "protocol_snapshot_error") {
      notifyProtocolSnapshotSubscribers({
        type,
        protocol: String(payload.protocol || "").trim().toLowerCase(),
        snapshot: payload.snapshot || null,
        message: payload.message || "",
        generatedAt: payload.generated_at || "",
        receivedAt: Date.now(),
      });
      return;
    }
    if (type === "scan_map_snapshot" || type === "scan_map_update") {
      applyRealtimeMapSnapshot(payload.data, {
        type,
        generatedAt: payload.generated_at,
        receivedAt: Date.now(),
      });
    }
    recordLiveActivity(type, payload);
    evaluateNotificationsForMessage(type, payload);
    if (!WS_REFRESH_EVENT_TYPES.has(type)) return;
    scheduleTableRefresh({
      type,
      payload,
      receivedAt: Date.now(),
    });
  });

  socket.addEventListener("error", () => {
    if (wsClient !== socket) return;
    state.wsStatus = "error";
  });

  socket.addEventListener("close", (event) => {
    if (wsClient !== socket) return;
    wsClient = null;
    stopLiveActivityTicker();
    if (event && event.code === WS_AUTH_CLOSE_CODE) {
      handleUnauthorized("Session expired. Re-enter the security code.");
      return;
    }
    if (isRealtimeCurrentlyOnline) {
      notifyForConnectionChange("lost");
    }
    isRealtimeCurrentlyOnline = false;
    state.wsStatus = "offline";
    scheduleReconnect();
  });
}

function initRealtime() {
  if (state.shutdownPending) return;
  connectRealtime();
}

function shutdownApplication() {
  if (state.shutdownPending) {
    return Promise.resolve({ status: "ok", shutdown_pending: true, shutdown_requested: false });
  }
  state.shutdownPending = true;
  clearReconnectTimer();
  destroyRealtime();
  return fetchJsonPromise("/api/app/shutdown", {
    method: "POST",
    body: JSON.stringify({ delay: APP_SHUTDOWN_DELAY_SECONDS }),
  }).catch((error) => {
    state.shutdownPending = false;
    reconnectRealtime();
    throw error;
  });
}

function subscribeTableRefresh(handler) {
  if (typeof handler !== "function") {
    return () => {};
  }
  tableRefreshSubscribers.add(handler);
  return () => {
    tableRefreshSubscribers.delete(handler);
  };
}

function subscribeMapSnapshot(handler) {
  if (typeof handler !== "function") {
    return () => {};
  }
  mapSnapshotSubscribers.add(handler);
  if (state.realtimeMapSnapshot) {
    try {
      handler({
        snapshot: state.realtimeMapSnapshot,
        meta: {
          type: "cached",
          generatedAt: state.realtimeMapGeneratedAt,
        },
      });
    } catch {
      // ignore subscriber-level failures
    }
  }
  return () => {
    mapSnapshotSubscribers.delete(handler);
  };
}

function getRealtimeMapSnapshot() {
  return state.realtimeMapSnapshot;
}

export default {
  state,
  suggestApiBaseFromLocation,
  initApiBase,
  bootstrap,
  initRealtime,
  setApiBase,
  apiUrl,
  fetchJsonPromise,
  fetchJson,
  fetchListPromise,
  buildListQuery,
  extractArray,
  timeRangeOptions: TIME_RANGE_OPTIONS,
  initTimeRange,
  setTimeRange,
  timeRangeLabel,
  initRuntime,
  setRuntimeMode,
  controlEngine,
  setEngines,
  controlRuntimeMode,
  shutdownApplication,
  setSnifferInterface,
  setSnifferInterfaces,
  listMonitors,
  saveMonitor,
  deleteMonitor,
  toggleMonitorEnabled,
  getMonitorConfig,
  setMonitorConfig,
  reviewPacket,
  getDetectionScopes,
  setDetectionScopes,
  getDeclaredLocation,
  setDeclaredLocation,
  clearDeclaredLocation,
  listChatMessages,
  postChatMessage,
  executeConsoleCommand,
  listBlacklistEntries,
  createBlacklistEntry,
  deleteBlacklistEntry,
  toggleBlacklistEntry,
  listWhitelistEntries,
  createWhitelistEntry,
  deleteWhitelistEntry,
  toggleWhitelistEntry,
  whitelistIpAndForget,
  listHoneypotListeners,
  createHoneypotListener,
  toggleHoneypotListenerEnabled,
  listDomains,
  listPaths,
  fetchProtocolSnapshot,
  listIpCatalogWithScopes,
  fetchIpRelationshipGraph,
  listMonitorPackets,
  clearDetections,
  downloadIocExport,
  reconnectRealtime,
  destroyRealtime,
  subscribeTableRefresh,
  subscribeMapSnapshot,
  getRealtimeMapSnapshot,
  requestRealtimeMapSnapshot,
  subscribeProtocolSnapshot,
  openDataFeed,
  feedListResult,
  startProtocolSnapshotStream,
  stopProtocolSnapshotStream,
  openAuthPrompt,
  authenticateSessionToken,
  signOut,
  initNotifySound,
  setNotifySoundEnabled,
  pushNotification,
};
