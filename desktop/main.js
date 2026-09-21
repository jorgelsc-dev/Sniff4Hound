const { app, BrowserWindow, Menu, ipcMain, shell, dialog, protocol, session } = require("electron");
const { spawn } = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const https = require("node:https");
const path = require("node:path");
const { URL, URLSearchParams } = require("./lib/simple-url");

const READY_PREFIX = "SNIFF4HOUND_DESKTOP_READY ";
const DEFAULT_PORT = "45678";
const CONNECTION_STATE_FILE = "connection.json";
const APP_SCHEME = "app";

// The bundled SPA (frontend/dist, a Vite build with <script type="module">
// entry points - see loadShell()/registerAppProtocol() below) can't be
// loaded via a plain file:// URL: Chromium always fetches module scripts in
// CORS mode regardless of any HTML attribute, and file: is a
// "CorsDisabledScheme" - every module script failed to load and the app
// never mounted (verified empirically against a real build). Registering
// a privileged custom scheme instead gives the bundled UI a real origin
// that supports fetch/CORS like http(s) does, which is the standard fix for
// this exact Vite+Electron combination. Must run before the app is ready.
protocol.registerSchemesAsPrivileged([
  {
    scheme: APP_SCHEME,
    privileges: {
      standard: true,
      secure: true,
      supportFetchAPI: true,
      corsEnabled: true,
      stream: true,
    },
  },
]);

// Chromium's setuid sandbox helper needs a root-owned, setuid `chrome-sandbox`
// binary (or an AppArmor profile permitting unprivileged user namespaces on
// newer Debian/Ubuntu) to work at all. The combined .deb this app ships in
// installs everything under /usr/lib/sniff4hound/desktop as regular files, so
// that helper never has the permissions it needs - disable the sandbox
// instead of shipping a setuid-root binary for it. The security cost is
// modest here: this window only ever renders our own bundled frontend, never
// arbitrary remote content, and the actual privileged engine (dashboard
// server + packet capture) is a separate process elevated on its own - see
// sniff4hound/manage.py's _ensure_running_as_root().
if (process.platform === "linux") {
  app.commandLine.appendSwitch("no-sandbox");
}

// AI/automation channel: always-on Chrome DevTools Protocol remote debugging
// on a fixed, well-known port, so an agent never has to ask the operator to
// relaunch with a special flag first - see AGENTS.md's "Desktop App:
// AI/Automation Access" for how to attach and drive/inspect the running
// window (click elements, read the DOM, screenshot) exactly like a user
// would. Deliberate, operator-directed tradeoff: any other local process can
// attach to this port and fully control the window, a real attack surface
// for a tool that already runs elevated - set SNIFF4HOUND_DESKTOP_DEBUG_PORT
// to a different port, or to "0"/"false"/"off" to disable it outright, for a
// deployment that wants it closed instead.
const DEFAULT_DESKTOP_DEBUG_PORT = "9223";
const desktopDebugPortRaw = String(process.env.SNIFF4HOUND_DESKTOP_DEBUG_PORT ?? DEFAULT_DESKTOP_DEBUG_PORT).trim();
const desktopDebugDisabled = ["0", "false", "off", "no", ""].includes(desktopDebugPortRaw.toLowerCase());
if (!desktopDebugDisabled) {
  app.commandLine.appendSwitch("remote-debugging-port", desktopDebugPortRaw);
  app.commandLine.appendSwitch("remote-allow-origins", "*");
}

// Every path that hands a URL to shell.openExternal() (new-window clicks,
// blocked in-window navigations, the menu's GitHub link, and the
// contextIsolation'd renderer bridge in preload.js) funnels through this
// allowlist first. shell.openExternal() dispatches to the OS's own handler
// for the URL's scheme - unrestricted, that includes `file:` (opens local
// files/directories) and platform-specific handler schemes, not just
// `javascript:`/`data:` (which openExternal itself already refuses to
// launch, but defense in depth costs nothing here). A compromised renderer
// or a malicious link served through the backend should not be able to
// reach any of that (finding 1.11).
const ALLOWED_EXTERNAL_PROTOCOLS = new Set(["http:", "https:", "mailto:"]);

function isAllowedExternalUrl(url) {
  try {
    const parsed = new URL(String(url || ""));
    return ALLOWED_EXTERNAL_PROTOCOLS.has(parsed.protocol);
  } catch {
    return false;
  }
}

let mainWindow = null;
let backendProcess = null;
let backendReady = null;
let backendExited = false;
let suppressNextBackendExit = false;
let quitting = false;
let stdoutBuffer = "";
let stderrBuffer = "";
const recentBackendLines = [];
const trustedRuntimeCas = new Map();
let certificateTrustInstalled = false;

function normalizeOrigin(value) {
  try {
    return new URL(value).origin;
  } catch {
    return "";
  }
}

function x509FromPemOrDer(value) {
  if (!value) return null;
  try {
    return new crypto.X509Certificate(value);
  } catch {
    return null;
  }
}

function certificateFingerprint(value) {
  const cert = x509FromPemOrDer(value);
  if (!cert) return "";
  return crypto.createHash("sha256").update(cert.raw).digest("hex");
}

function registerTrustedRuntimeCa(config, caPem) {
  const pem = String(caPem || "").trim();
  if (!pem.includes("BEGIN CERTIFICATE")) return false;
  const origin = normalizeOrigin(config.origin || config.url);
  if (!origin) return false;
  const caCert = x509FromPemOrDer(pem);
  if (!caCert) return false;
  trustedRuntimeCas.set(origin, {
    origin,
    host: String(config.host || new URL(origin).hostname),
    caPem: pem,
    caCert,
    caFingerprint: certificateFingerprint(pem),
    publicKey: caCert.publicKey,
  });
  return true;
}

function trustedCaForOrigin(origin) {
  return trustedRuntimeCas.get(normalizeOrigin(origin));
}

function isLoopbackHost(hostname) {
  const host = String(hostname || "").toLowerCase();
  return host === "localhost" || host === "127.0.0.1" || host === "::1" || host === "[::1]";
}

function certificateIsSignedByTrustedCa(cert, trusted) {
  const leaf = x509FromPemOrDer(cert);
  if (!leaf || !trusted) return false;
  try {
    return leaf.verify(trusted.publicKey);
  } catch {
    return false;
  }
}

function certificateMatchesTrustedCa(cert, trusted) {
  return Boolean(trusted && cert && certificateFingerprint(cert) === trusted.caFingerprint);
}

function electronCertificateData(certificate) {
  if (!certificate) return "";
  if (certificate.data) return String(certificate.data);
  return "";
}

function electronCertificateIsTrusted(certificate, trusted) {
  const leaf = electronCertificateData(certificate);
  if (certificateIsSignedByTrustedCa(leaf, trusted)) return true;
  const issuer = certificate && certificate.issuerCert ? electronCertificateData(certificate.issuerCert) : "";
  return certificateMatchesTrustedCa(issuer, trusted);
}

function installRuntimeCertificateTrust() {
  if (certificateTrustInstalled) return;
  certificateTrustInstalled = true;
  session.defaultSession.setCertificateVerifyProc((request, callback) => {
    if (request.verificationResult === "net::OK") {
      callback(0);
      return;
    }
    const origin = normalizeOrigin(request.url);
    const trusted = trustedCaForOrigin(origin);
    if ((trusted && request.hostname === trusted.host) || isLoopbackHost(request.hostname)) {
      callback(0);
      return;
    }
    callback(-2);
  });
  app.on("certificate-error", (event, _webContents, url, _error, certificate, callback) => {
    const origin = normalizeOrigin(url);
    const trusted = trustedCaForOrigin(origin);
    let hostname = "";
    try {
      hostname = new URL(url).hostname;
    } catch {
      hostname = "";
    }
    if ((trusted && hostname === trusted.host) || isLoopbackHost(hostname)) {
      event.preventDefault();
      callback(true);
      return;
    }
    callback(false);
  });
}

function repoRoot() {
  return path.resolve(__dirname, "..");
}

function rememberBackendLine(line) {
  const trimmed = String(line || "").trim();
  if (!trimmed) return;
  recentBackendLines.push(trimmed);
  while (recentBackendLines.length > 80) recentBackendLines.shift();
}

function connectionStatePath() {
  return path.join(app.getPath("userData"), CONNECTION_STATE_FILE);
}

function readConnectionState() {
  try {
    const raw = fs.readFileSync(connectionStatePath(), "utf8");
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

function writeConnectionState(payload) {
  try {
    fs.mkdirSync(app.getPath("userData"), { recursive: true });
    fs.writeFileSync(connectionStatePath(), JSON.stringify(payload || {}, null, 2));
  } catch {
    // The launcher still works; it just will not remember the last target.
  }
}

function sendLauncherStatus(message) {
  if (!mainWindow || mainWindow.isDestroyed()) return;
  mainWindow.webContents.send("desktop-runtime:status", String(message || ""));
}

// The merged .deb installs one Python runtime here, shared by both the CLI
// (scripts/deb_wrapper.sh) and this app, instead of each bundling its own
// copy - see scripts/build_deb.sh.
const SHARED_VENDOR_DIR = "/usr/lib/sniff4hound/vendor";

function usingSharedVendorRuntime() {
  // Only for the actual packaged/installed app: a machine can easily have
  // an unrelated, stale sniff4hound .deb already installed at this same
  // path from a previous release, and `npm run dev` unpackaged is
  // specifically for testing the live source tree in this repo - silently
  // running whatever happens to be installed system-wide instead would
  // make dev mode indistinguishable from testing old, already-shipped code.
  return app.isPackaged && !process.env.SNIFF4HOUND_DESKTOP_PYTHON && fs.existsSync(SHARED_VENDOR_DIR);
}

function resolvePython() {
  if (process.env.SNIFF4HOUND_DESKTOP_PYTHON) {
    return process.env.SNIFF4HOUND_DESKTOP_PYTHON;
  }

  if (usingSharedVendorRuntime()) {
    return "/usr/bin/python3";
  }

  const packagedPython = path.join(process.resourcesPath || "", "python-venv", "bin", "python");
  if (app.isPackaged && fs.existsSync(packagedPython)) {
    return packagedPython;
  }

  const preparedPython = path.join(repoRoot(), "build", "desktop", "runtime", "python-venv", "bin", "python");
  if (fs.existsSync(preparedPython)) {
    return preparedPython;
  }

  // Dev checkout: prefer this repo's own virtualenv over a bare "python3"
  // lookup on PATH. The latter resolves to whatever system interpreter
  // happens to be first on PATH, which has none of this project's
  // dependencies (wsbuilder, etc.) installed - only `sniff4hound` itself
  // would appear importable there, and only via the cwd-relative `-m`
  // lookup, which masked this for the package itself but not for its deps.
  const repoVenvPython = path.join(repoRoot(), ".venv", "bin", "python3");
  if (fs.existsSync(repoVenvPython)) {
    return repoVenvPython;
  }

  return process.env.PYTHON || "python3";
}

function resolveFrontendDist() {
  if (process.env.SNIFF4HOUND_FRONTEND_DIST) {
    return process.env.SNIFF4HOUND_FRONTEND_DIST;
  }
  if (usingSharedVendorRuntime()) {
    // The shared vendor tree carries its own vendored copy at
    // sniff4hound/_frontend_dist (setup.py's custom build_py copies
    // frontend/dist there at package-build time - see PACKAGE_FRONTEND_DIR
    // in setup.py) - Electron now loads this directly (loadShell()) instead
    // of the Python backend serving it, so main.js has to know this path
    // itself rather than delegating to the backend.
    return path.join(SHARED_VENDOR_DIR, "sniff4hound", "_frontend_dist");
  }
  const packagedDist = path.join(process.resourcesPath || "", "frontend-dist");
  if (app.isPackaged && fs.existsSync(path.join(packagedDist, "index.html"))) {
    return packagedDist;
  }
  return path.join(repoRoot(), "frontend", "dist");
}

function venvRootForPython(pythonPath) {
  const binDir = path.dirname(pythonPath);
  return path.dirname(binDir);
}

function backendEnv(pythonPath) {
  const env = {
    ...process.env,
    PYTHONUNBUFFERED: "1",
    PYTHONNOUSERSITE: "1",
    SNIFF4HOUND_DESKTOP: "1",
    SNIFF4HOUND_HOST: process.env.SNIFF4HOUND_HOST || "127.0.0.1",
    SNIFF4HOUND_PORT: process.env.SNIFF4HOUND_PORT || DEFAULT_PORT,
    SNIFF4HOUND_CAPTURE_AUTO_START: "0",
    SNIFF4HOUND_TLS: process.env.SNIFF4HOUND_TLS || "1",
  };

  if (usingSharedVendorRuntime()) {
    // Mirrors scripts/deb_wrapper.sh: the shared vendor dir isn't on system
    // site-packages, only importable via PYTHONPATH.
    env.PYTHONPATH = env.PYTHONPATH ? `${SHARED_VENDOR_DIR}${path.delimiter}${env.PYTHONPATH}` : SHARED_VENDOR_DIR;
    return env;
  }

  const venvRoot = venvRootForPython(pythonPath);
  if (fs.existsSync(path.join(venvRoot, "pyvenv.cfg"))) {
    env.VIRTUAL_ENV = venvRoot;
    env.PATH = `${path.join(venvRoot, "bin")}${path.delimiter}${env.PATH || ""}`;
  }

  return env;
}

function readLines(chunk, streamName, onLine) {
  const text = chunk.toString("utf8");
  if (streamName === "stdout") {
    stdoutBuffer += text;
    let index = stdoutBuffer.indexOf("\n");
    while (index >= 0) {
      const line = stdoutBuffer.slice(0, index).replace(/\r$/, "");
      stdoutBuffer = stdoutBuffer.slice(index + 1);
      onLine(line);
      index = stdoutBuffer.indexOf("\n");
    }
    return;
  }

  stderrBuffer += text;
  let index = stderrBuffer.indexOf("\n");
  while (index >= 0) {
    const line = stderrBuffer.slice(0, index).replace(/\r$/, "");
    stderrBuffer = stderrBuffer.slice(index + 1);
    onLine(line);
    index = stderrBuffer.indexOf("\n");
  }
}

function startBackend() {
  if (backendProcess) {
    return;
  }
  backendExited = false;
  backendReady = null;
  recentBackendLines.length = 0;
  const pythonPath = resolvePython();
  const env = backendEnv(pythonPath);
  const cwd = app.isPackaged ? process.resourcesPath : repoRoot();

  sendLauncherStatus("Starting local backend...");
  backendProcess = spawn(pythonPath, ["-m", "sniff4hound.manage"], {
    cwd,
    env,
    stdio: ["ignore", "pipe", "pipe"],
  });

  backendProcess.stdout.on("data", (chunk) => {
    readLines(chunk, "stdout", (line) => {
      if (line.startsWith(READY_PREFIX)) {
        try {
          backendReady = JSON.parse(line.slice(READY_PREFIX.length));
          backendReady.connection = "local";
          backendReady.protocol = backendReady.protocol || "http";
          backendReady.origin = new URL(backendReady.url).origin;
          if (backendReady.ca_pem) {
            registerTrustedRuntimeCa(backendReady, backendReady.ca_pem);
          }
          writeConnectionState({ mode: "local" });
          loadBackendWindow();
        } catch (error) {
          rememberBackendLine(`Invalid ready payload: ${error.message}`);
        }
        return;
      }
      rememberBackendLine(line);
      sendLauncherStatus(line);
    });
  });

  backendProcess.stderr.on("data", (chunk) => {
    readLines(chunk, "stderr", (line) => {
      rememberBackendLine(line);
      sendLauncherStatus(line);
    });
  });

  backendProcess.on("error", (error) => {
    rememberBackendLine(error.message);
    showBackendFailure("Sniff4Hound could not start the Python runtime.");
  });

  backendProcess.on("exit", (code, signal) => {
    backendExited = true;
    backendProcess = null;
    if (suppressNextBackendExit) {
      suppressNextBackendExit = false;
      return;
    }
    if (quitting) return;
    if (backendReady && (code === 0 || signal === "SIGINT" || signal === "SIGTERM")) {
      quitting = true;
      app.quit();
      return;
    }
    // manage.py self-elevates via execvp() (see _ensure_running_as_root()),
    // replacing its own process image with pkexec's - so this exit event
    // carries pkexec's own exit code, and 126/127 mean the operator
    // dismissed the polkit prompt or failed/declined authentication (see
    // `man pkexec`), not a bug to diagnose. Quitting outright instead of
    // parking the window behind a failure dialog matches canceling any
    // other elevation prompt: the action just doesn't happen, rather than
    // leaving the launcher stuck on screen for no obvious reason.
    if (!backendReady && !signal && (code === 126 || code === 127)) {
      quitting = true;
      app.quit();
      return;
    }
    showBackendFailure(`Sniff4Hound backend exited (${signal || code}).`);
  });
}

function parseRemoteTarget(payload) {
  const protocol = "https";
  const rawHost = String(payload.host || "").trim();
  const rawPort = String(payload.port || "").trim();
  const securityCode = String(payload.securityCode || payload.code || "").trim();
  const caPem = String(payload.caPem || payload.publicCa || "").trim();
  if (!rawHost) {
    throw new Error("Remote host is required.");
  }

  let url = null;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(rawHost)) {
    url = new URL(rawHost);
    url.protocol = "https:";
    if (rawPort) url.port = rawPort;
  } else {
    url = new URL(`${protocol}://${rawHost}`);
    if (rawPort) url.port = rawPort;
  }

  if (!["http:", "https:"].includes(url.protocol)) {
    throw new Error("Remote target must use HTTP or HTTPS.");
  }
  if (rawPort && (!/^\d+$/.test(rawPort) || Number(rawPort) < 1 || Number(rawPort) > 65535)) {
    throw new Error("Port must be between 1 and 65535.");
  }

  url.pathname = "/";
  url.search = "";
  if (securityCode) url.searchParams.set("code", securityCode);
  url.searchParams.set("desktop", "1");
  url.searchParams.set("desktop_backend", "remote");

  return {
    connection: "remote",
    url: url.toString(),
    origin: url.origin,
    host: url.hostname,
    port: url.port || "443",
    protocol,
    security_code: securityCode,
    ca_pem: caPem,
    auth_required: Boolean(securityCode),
  };
}

function requestText(url, headers = {}, optionsOverride = {}) {
  return new Promise((resolve, reject) => {
    const client = url.protocol === "https:" ? https : http;
    // Built as a plain options object (hostname/port/path) rather than
    // handing `url` straight to client.request(): that overload only
    // special-cases Node's own `URL` instances, and our SimpleURL isn't one
    // - passed directly it would silently be treated as the options
    // argument and shift the real options (method/headers/timeout) into the
    // callback slot instead.
    const options = {
      hostname: url.hostname,
      port: url.port || (url.protocol === "https:" ? 443 : 80),
      path: `${url.pathname}${url.search}`,
      method: "GET",
      headers,
      timeout: 7000,
      ...optionsOverride,
    };
    const request = client.request(
      options,
      (response) => {
        let body = "";
        response.setEncoding("utf8");
        response.on("data", (chunk) => {
          body += chunk;
          if (body.length > 1024 * 1024) request.destroy(new Error("Response is too large."));
        });
        response.on("end", () => {
          if (response.statusCode < 200 || response.statusCode >= 300) {
            reject(new Error(`Remote backend returned HTTP ${response.statusCode}.`));
            return;
          }
          resolve(body);
        });
      },
    );
    request.on("timeout", () => request.destroy(new Error("Remote backend timed out.")));
    request.on("error", reject);
    request.end();
  });
}

async function requestJson(url, headers = {}, optionsOverride = {}) {
  const body = await requestText(url, headers, optionsOverride);
  try {
    return body ? JSON.parse(body) : {};
  } catch {
    throw new Error("Remote backend did not return JSON.");
  }
}

async function fetchRemotePublicCa(config) {
  if (config.protocol !== "https") return "";
  if (config.ca_pem) {
    if (!registerTrustedRuntimeCa(config, config.ca_pem)) {
      throw new Error("The pasted /publicca certificate is not a valid PEM certificate.");
    }
    return config.ca_pem;
  }
  const caUrl = new URL("/publicca", config.origin);
  const trusted = trustedCaForOrigin(config.origin);
  const tlsOptions = trusted ? { ca: trusted.caPem } : {};
  let caPem = "";
  try {
    caPem = await requestText(caUrl, {}, tlsOptions);
  } catch (error) {
    throw new Error(
      "Paste the sensor /publicca PEM before connecting, or use a certificate trusted by this desktop.",
    );
  }
  if (!registerTrustedRuntimeCa(config, caPem)) {
    throw new Error("Remote backend did not return a valid Sniff4Hound CA.");
  }
  return caPem;
}

async function verifyRemoteConnection(config) {
  await fetchRemotePublicCa(config);
  const sessionUrl = new URL("/api/auth/session", config.origin);
  const headers = config.security_code ? { "X-Security-Code": config.security_code } : {};
  const trusted = trustedCaForOrigin(config.origin);
  const tlsOptions = config.protocol === "https" && trusted
    ? { ca: trusted.caPem }
    : {};
  const payload = await requestJson(sessionUrl, headers, tlsOptions);
  const authRequired = Boolean(payload && payload.require_auth);
  if (authRequired && !(payload && payload.authenticated)) {
    throw new Error("Invalid or missing security code.");
  }
  return {
    ...config,
    auth_required: authRequired,
  };
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1360,
    height: 860,
    minWidth: 980,
    minHeight: 640,
    show: false,
    frame: false,
    backgroundColor: "#06111d",
    icon: path.join(__dirname, "assets", "icon.png"),
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
    },
  });

  mainWindow.loadFile(path.join(__dirname, "splash.html"));
  mainWindow.once("ready-to-show", () => mainWindow.show());

  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (isAllowedExternalUrl(url)) shell.openExternal(url);
    return { action: "deny" };
  });

  mainWindow.webContents.on("will-navigate", (event, url) => {
    if (!backendReady) return;
    const allowedOrigin = new URL(backendReady.url).origin;
    try {
      const target = new URL(url);
      if (target.protocol === "file:") return;
      if (target.origin === allowedOrigin) return;
    } catch {
      // fall through to block malformed navigations
    }
    event.preventDefault();
    if (isAllowedExternalUrl(url)) shell.openExternal(url);
  });

  mainWindow.on("close", () => {
    quitting = true;
    stopBackend();
  });
}

// Builds the query string the bundled SPA reads on boot (see appStore.js's
// initApiBase()/readStartupAuthTokenFromUrl()): which backend to call
// (api_base - local or a "connect to remote sensor" target, since both now
// load the exact same local shell instead of the remote's own page) and the
// security code. Which view to land on travels separately, as the URL's
// hash (see loadShell()) - frontend/src/router/index.js runs in hash mode
// precisely so this works under the app:// scheme (registerAppProtocol()
// below), where a path-changing pushState() (what a root-relative query
// value would need turning into a route) throws a SecurityError, same as
// it would under a plain file:// load.
function shellSearch() {
  if (!backendReady) return "";
  const params = new URLSearchParams();
  const backendProtocol = backendReady.protocol || "http";
  params.set("api_base", `${backendProtocol}://${backendReady.host}:${backendReady.port}`);
  if (backendReady.auth_required && backendReady.security_code) {
    params.set("code", backendReady.security_code);
  }
  params.set("desktop", "1");
  params.set("desktop_backend", backendReady.connection === "remote" ? "remote" : "local");
  return params.toString();
}

// Extensions actually present in a Vite build of frontend/ (checked against
// a real `npm run build` output) - not a general-purpose MIME database,
// just enough for protocol.handle() below to answer each file with a
// content type the renderer will actually execute/render as (a JS module
// served as application/octet-stream, for instance, is silently refused).
const DIST_MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".geojson": "application/geo+json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".woff": "font/woff",
  ".woff2": "font/woff2",
  ".ttf": "font/ttf",
  ".eot": "application/vnd.ms-fontobject",
  ".txt": "text/plain; charset=utf-8",
};

function registerAppProtocol() {
  const distDir = path.resolve(resolveFrontendDist());
  protocol.handle(APP_SCHEME, (request) => {
    const requestUrl = new URL(request.url);
    let relativePath = decodeURIComponent(requestUrl.pathname || "/");
    if (relativePath === "" || relativePath === "/") relativePath = "/index.html";
    const filePath = path.join(distDir, relativePath);
    // Refuses anything a "/../.." in the request path would resolve
    // outside distDir - nothing legitimate ever needs that, this is our
    // own bundled UI's fixed set of files, not a general file server.
    if (filePath !== distDir && !filePath.startsWith(distDir + path.sep)) {
      return new Response("Not Found", { status: 404 });
    }
    try {
      const data = fs.readFileSync(filePath);
      const contentType = DIST_MIME_TYPES[path.extname(filePath).toLowerCase()] || "application/octet-stream";
      return new Response(data, { status: 200, headers: { "Content-Type": contentType } });
    } catch {
      return new Response("Not Found", { status: 404 });
    }
  });
}

function loadShell(routePath) {
  if (!mainWindow || mainWindow.isDestroyed() || !backendReady) return;
  const search = shellSearch();
  const hash = String(routePath || "/");
  console.log("[desktop] backend security_code:", backendReady.security_code);
  console.log("[desktop] auth_required:", backendReady.auth_required);
  console.log("[desktop] search params:", search);
  mainWindow.loadURL(`${APP_SCHEME}://shell/index.html${search ? `?${search}` : ""}#${hash}`);
}

function navigate(routePath) {
  loadShell(routePath);
}

function installMenu() {
  const template = [
    {
      label: "File",
      submenu: [
        { label: "Connection...", accelerator: "CommandOrControl+Shift+C", click: () => showConnectionChooser() },
        { type: "separator" },
        { label: "Dashboard", accelerator: "CommandOrControl+1", click: () => navigate("/") },
        { label: "SOC", accelerator: "CommandOrControl+2", click: () => navigate("/soc") },
        { label: "Sniffer", accelerator: "CommandOrControl+3", click: () => navigate("/sniffer") },
        { label: "Honeypot", accelerator: "CommandOrControl+4", click: () => navigate("/honeypot") },
        { type: "separator" },
        { role: "quit", label: "Quit Sniff4Hound" },
      ],
    },
    {
      label: "View",
      submenu: [
        { role: "reload" },
        { role: "toggleDevTools" },
        { type: "separator" },
        { role: "resetZoom" },
        { role: "zoomIn" },
        { role: "zoomOut" },
      ],
    },
    {
      label: "Tools",
      submenu: [
        { label: "Investigate", click: () => navigate("/investigate") },
        { label: "Protocols", click: () => navigate("/protocols") },
        { label: "Monitors", click: () => navigate("/monitors") },
        { label: "Settings", click: () => navigate("/settings") },
      ],
    },
    {
      label: "Help",
      submenu: [
        {
          label: "Open Project",
          click: () => shell.openExternal("https://github.com/jorgelsc-dev/Sniff4Hound"),
        },
      ],
    },
  ];
  Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

function loadBackendWindow() {
  if (!mainWindow || mainWindow.isDestroyed() || !backendReady) return;
  installMenu();
  loadShell("/");
}

function showConnectionChooser() {
  if (!mainWindow || mainWindow.isDestroyed()) return;
  Menu.setApplicationMenu(null);
  mainWindow.loadFile(path.join(__dirname, "splash.html"));
}

function showBackendFailure(message) {
  if (!mainWindow || mainWindow.isDestroyed()) return;
  const detail = recentBackendLines.slice(-12).join("\n");
  dialog.showMessageBox(mainWindow, {
    type: "error",
    title: "Sniff4Hound startup failed",
    message,
    detail: detail || "No backend output was captured.",
  });
}

function stopBackend(options = {}) {
  if (!backendProcess || backendExited) return;
  suppressNextBackendExit = Boolean(options.keepApp);
  try {
    backendProcess.kill("SIGINT");
  } catch {
    suppressNextBackendExit = false;
    return;
  }
  setTimeout(() => {
    if (backendProcess && !backendExited) {
      try {
        backendProcess.kill("SIGTERM");
      } catch {
        // process already exited
      }
    }
  }, 5000);
}

async function connectRemote(payload) {
  const parsed = parseRemoteTarget(payload || {});
  sendLauncherStatus("Checking remote backend...");
  const verified = await verifyRemoteConnection(parsed);
  if (backendProcess) {
    stopBackend({ keepApp: true });
  }
  backendReady = verified;
  backendExited = false;
  writeConnectionState({
    mode: "remote",
    protocol: verified.protocol,
    host: verified.host,
    port: verified.port,
  });
  loadBackendWindow();
  return { ok: true, target: { ...verified, security_code: "" } };
}

ipcMain.handle("desktop-window:minimize", () => {
  if (mainWindow && !mainWindow.isDestroyed()) mainWindow.minimize();
});

ipcMain.handle("desktop-window:maximize", () => {
  if (!mainWindow || mainWindow.isDestroyed()) return;
  if (mainWindow.isMaximized()) {
    mainWindow.unmaximize();
  } else {
    mainWindow.maximize();
  }
});

ipcMain.handle("desktop-window:close", () => {
  if (mainWindow && !mainWindow.isDestroyed()) mainWindow.close();
});

ipcMain.handle("desktop-shell:open-external", (_event, url) => {
  // The renderer-facing bridge (preload.js) forwards whatever string the
  // SPA passes, unvalidated - this is the only place left that can refuse
  // a `file:`/`javascript:`/other unexpected scheme before it reaches the
  // OS's own URL handler.
  if (!url || !isAllowedExternalUrl(url)) return;
  shell.openExternal(url);
});

ipcMain.handle("desktop-runtime:get-connection-defaults", () => {
  const state = readConnectionState();
  return {
    localPort: process.env.SNIFF4HOUND_PORT || DEFAULT_PORT,
    mode: state.mode || "local",
    protocol: state.protocol || "http",
    host: state.host || "127.0.0.1",
    port: state.port || DEFAULT_PORT,
  };
});

ipcMain.handle("desktop-runtime:start-local", () => {
  startBackend();
  return { ok: true };
});

ipcMain.handle("desktop-runtime:connect-remote", async (_event, payload) => {
  try {
    return await connectRemote(payload || {});
  } catch (error) {
    const message = error && error.message ? error.message : "Unable to connect to remote backend.";
    sendLauncherStatus(message);
    return { ok: false, error: message };
  }
});

ipcMain.handle("desktop-runtime:show-connection-chooser", () => {
  showConnectionChooser();
  return { ok: true };
});

app.whenReady().then(() => {
  installRuntimeCertificateTrust();
  registerAppProtocol();
  createWindow();
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});

app.on("before-quit", () => {
  quitting = true;
  stopBackend();
});
