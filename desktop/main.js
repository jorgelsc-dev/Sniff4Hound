const { app, BrowserWindow, Menu, ipcMain, net, shell, dialog, protocol, session } = require("electron");
const { spawn, execFile, execFileSync } = require("node:child_process");
const crypto = require("node:crypto");
const https = require("node:https");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const { URL, URLSearchParams } = require("./lib/simple-url");
const elevation = require("./lib/elevation");
const { configureGraphics } = require("./lib/graphics");
const { createShutdownController } = require("./lib/shutdown");
const { startPrivateSessionBus } = require("./lib/session-bus");
const quicPin = require("./lib/quic-pin");
const { verifyLocalService } = require("./lib/mdns");
const { createStreamRegistry, openBridgeStream } = require("./lib/bridge-streams");
const windowSecurity = require("./lib/window-security");

const READY_PREFIX = "SNIFF4HOUND_DESKTOP_READY ";
const DEFAULT_PORT = "45678";
const CONNECTION_STATE_FILE = "connection.json";
const APP_SCHEME = "app";

// Open Electron in the operator's desktop session first. The local runtime
// is authorized from that window and launched separately as root; relaunching
// Chromium as root breaks display access on modern Linux desktops.
function effectiveUid() {
  // Not defined off POSIX; the elevation code treats that as "nothing to do".
  return typeof process.geteuid === "function" ? process.geteuid() : 0;
}

const stopSessionBus = startPrivateSessionBus({
  platform: process.platform,
  euid: effectiveUid(),
  env: process.env,
  which: elevation.findExecutable,
  execFileSync,
  kill: (pid, signal) => process.kill(pid, signal),
  log: (line) => console.error(line),
});
if (stopSessionBus) {
  process.on("exit", stopSessionBus);
}
// Terminal interruption also runs before-quit, which stops the root runtime.
for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) process.on(signal, () => app.quit());

// A manually root-launched shell leaves configuration root-owned; give it back so
// an unprivileged launch can still use it.
function handBackUserData() {
  const uid = Number(process.env.SNIFF4HOUND_INVOKING_UID);
  const gid = Number(process.env.SNIFF4HOUND_INVOKING_GID);
  if (effectiveUid() !== 0 || !Number.isInteger(uid) || uid <= 0) return;
  elevation.chownTree(app.getPath("userData"), uid, Number.isInteger(gid) && gid >= 0 ? gid : uid);
}

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

// Keep renderer sandboxing enabled for normal operator launches.
configureGraphics({ app, platform: process.platform, euid: effectiveUid() });

// AI/automation channel: opt-in Chrome DevTools Protocol remote debugging -
// off unless SNIFF4HOUND_DESKTOP_DEBUG_PORT names a port, so a normal launch
// prints no "DevTools listening on ws://..." banner and opens no port. Set
// it to a port number to enable it for a session (see AGENTS.md's "Desktop
// App: AI/Automation Access" for how to attach and drive/inspect the running
// window - click elements, read the DOM, screenshot - exactly like a user
// would). Any other local process can attach to an open port and fully
// control a window connected to a privileged runtime, which is why access is opt-in.
const desktopDebugPortRaw = String(process.env.SNIFF4HOUND_DESKTOP_DEBUG_PORT ?? "0").trim();
const desktopDebugDisabled = ["0", "false", "off", "no", ""].includes(desktopDebugPortRaw.toLowerCase());
const desktopDebugPort = /^\d+$/.test(desktopDebugPortRaw) ? Number(desktopDebugPortRaw) : NaN;
const desktopDebugPortValid = Number.isInteger(desktopDebugPort) && desktopDebugPort >= 1024 && desktopDebugPort <= 65535;
const desktopRunningAsRoot = typeof process.getuid === "function" && process.getuid() === 0;
if (!desktopDebugDisabled && desktopDebugPortValid && !desktopRunningAsRoot) {
  app.commandLine.appendSwitch("remote-debugging-port", String(desktopDebugPort));
  app.commandLine.appendSwitch("remote-debugging-address", "127.0.0.1");
} else if (!desktopDebugDisabled && (!desktopDebugPortValid || desktopRunningAsRoot)) {
  console.error("SNIFF4HOUND_DESKTOP_DEBUG_PORT ignored: valid loopback-only debug requires a non-root desktop process and a port in 1024..65535");
}

// The runtime's certificate is issued by a private CA. Over TCP this switch lets
// Chromium accept loopback TLS without validating it, which covers a loopback
// runtime that is not the local backend (a remote sensor behind a tunnel) and
// the first requests before the session's verify proc below is installed.
// It does nothing for QUIC: Chromium's QUIC stack only validates, and
// HTTP/3 to the local backend is trusted by pinning the runtime's persistent
// server key instead (prepareRuntimeNetworking() below, lib/quic-pin.js).
// Once the local backend is ready the verify proc below is installed too, so
// its certificate is validated against the pinned CA over TCP.
app.commandLine.appendSwitch("allow-insecure-localhost");

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

// The packaged connection chooser. With app://shell it is the only document
// the window may show (will-navigate) and the only one besides the shell whose
// frame may call IPC (handleIpc); see lib/window-security.js.
const SPLASH_PATH = path.join(__dirname, "splash.html");
const SHELL_ONLY = [windowSecurity.SHELL];
const SPLASH_ONLY = [windowSecurity.SPLASH];
const SHELL_OR_SPLASH = [windowSecurity.SHELL, windowSecurity.SPLASH];

// Every ipcMain handler checks the calling frame first: only the main frame
// of the documents in `allow` reaches the handler. The launcher channels are
// for the chooser only and the data bridge for the shell only.
function handleIpc(channel, allow, handler) {
  ipcMain.handle(channel, (event, ...args) => {
    if (!windowSecurity.senderAllowed(event, { splashPath: SPLASH_PATH, allow })) {
      throw new Error(`Blocked ${channel} from an unexpected frame.`);
    }
    return handler(event, ...args);
  });
}

let mainWindow = null;
let mainWindowShown = Promise.resolve();
let backendProcess = null;
let backendReady = null;
let backendAttempt = null;
let quitting = false;
const recentBackendLines = [];
const trustedRuntimeCas = new Map();
let certificateTrustInstalled = false;
let startupPrivilegeRequest = true;
const shutdownController = createShutdownController({
  cleanup: () => {
    try {
      stopBackend();
    } finally {
      httpStreams.abortAll();
    }
  },
  close: () => {
    quitting = true;
    app.quit();
  },
});

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

// The local backend is a process this app spawned itself, listening on
// loopback with a certificate it generated at startup. Its traffic never
// leaves the machine, so there is no man in the middle to protect against and
// the self-signed cert is accepted on that basis alone. A *remote* sensor gets
// no such pass: nothing about it is under our control.
function isOwnLocalBackend(hostname) {
  return Boolean(backendReady && backendReady.connection === "local") && isLoopbackHost(hostname);
}

// Accept an otherwise-untrusted certificate only when it actually chains up to
// the CA the operator pasted for this origin. Matching the hostname alone -
// which is what this used to do - accepts any self-signed certificate an
// attacker cares to present for that name, which is precisely the certificate
// a man in the middle has. The hostname check stays as well, so a CA pinned
// for one sensor cannot vouch for a different host.
function runtimeCertificateIsAcceptable(hostname, origin, certificate) {
  const trusted = trustedCaForOrigin(origin);
  if (trusted && hostname === trusted.host && electronCertificateIsTrusted(certificate, trusted)) {
    return true;
  }
  return isOwnLocalBackend(hostname);
}

// Electron's certificate-verify request carries the hostname but no URL, so the
// origin is unknown there. Match the pinned CAs by host instead and accept the
// certificate only if one of them actually signed it. The port is not visible to
// this callback, so two sensors on the same host with different CAs are both
// candidates; the signature check is what decides.
function runtimeCertificateIsPinnedForHost(hostname, certificate) {
  if (!hostname) return false;
  for (const trusted of trustedRuntimeCas.values()) {
    if (trusted.host === hostname && electronCertificateIsTrusted(certificate, trusted)) {
      return true;
    }
  }
  return false;
}

// The session verify proc pins a runtime's CA for TCP requests (including the
// main process's own net requests). It is installed when a non-loopback runtime
// is connected and when the local backend reports ready.
// Without it, Chromium fails every new TLS connection to the runtime's private-CA
// certificate with net_error -202 (logged as "handshake failed") and only then
// lets the loopback switch (see allow-insecure-localhost above) override the
// error: requests worked, but the console filled with errors. It only covers
// TCP; the local backend's HTTP/3 does not go through it (see prepareRuntimeNetworking()).
let runtimeVerifyProcInstalled = false;

function installRuntimeVerifyProc() {
  if (runtimeVerifyProcInstalled) return;
  runtimeVerifyProcInstalled = true;
  session.defaultSession.setCertificateVerifyProc((request, callback) => {
    const ownNamedRuntime = backendReady && backendReady.connection === "local" && backendReady.mdns &&
      request.hostname === backendReady.host;
    if (request.verificationResult === "net::OK" && !ownNamedRuntime) {
      callback(0);
      return;
    }
    const origin = normalizeOrigin(request.url);
    if (
      runtimeCertificateIsAcceptable(request.hostname, origin, request.certificate) ||
      runtimeCertificateIsPinnedForHost(request.hostname, request.certificate)
    ) {
      callback(0);
      return;
    }
    callback(-2);
  });
}

function installRuntimeCertificateTrust() {
  if (certificateTrustInstalled) return;
  certificateTrustInstalled = true;
  app.on("certificate-error", (event, _webContents, url, _error, certificate, callback) => {
    const origin = normalizeOrigin(url);
    let hostname = "";
    try {
      hostname = new URL(url).hostname;
    } catch {
      hostname = "";
    }
    if (runtimeCertificateIsAcceptable(hostname, origin, certificate)) {
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

function desktopCodeFilePath() {
  return path.join(app.getPath("userData"), "desktop-code.secret");
}

// The backend writes the security code to a 0600 file and prints only its
// path, so the code never travels over the stdout this process shares with
// the journal. It is single-use: read it once and remove it, so a crash does
// not leave the code sitting in the runtime directory.
function readDesktopCodeFile(codePath) {
  const target = String(codePath || "").trim();
  if (!target) return "";
  let code = "";
  try {
    code = fs.readFileSync(target, "utf8").trim();
  } catch {
    code = "";
  }
  try {
    fs.unlinkSync(target);
  } catch {
    /* already gone, or never ours to remove */
  }
  return code;
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
  return path.join(__dirname, "frontend", "dist");
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
    // The port Chromium was told to speak HTTP/3 to, when it could be chosen
    // in advance (see prepareRuntimeNetworking()).
    SNIFF4HOUND_PORT: String((preparedRuntime && preparedRuntime.port) || process.env.SNIFF4HOUND_PORT || DEFAULT_PORT),
    SNIFF4HOUND_CAPTURE_AUTO_START: "0",
    SNIFF4HOUND_TLS: process.env.SNIFF4HOUND_TLS || "1",
    // Where the backend should leave the security code. It has to be a
    // directory this (unprivileged) process can read: the backend re-execs
    // itself through pkexec, which does not forward XDG_RUNTIME_DIR, so its
    // own default would land under root's runtime directory. The assignment
    // survives that re-exec because of the SNIFF4HOUND_ prefix.
    SNIFF4HOUND_DESKTOP_CODE_FILE: desktopCodeFilePath(),
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

function readLines(attempt, chunk, streamName, onLine) {
  attempt[streamName] += chunk.toString("utf8");
  let index = attempt[streamName].indexOf("\n");
  while (index >= 0) {
    const line = attempt[streamName].slice(0, index).replace(/\r$/, "");
    attempt[streamName] = attempt[streamName].slice(index + 1);
    onLine(line);
    index = attempt[streamName].indexOf("\n");
  }
}

function startBackend() {
  // Concurrent requests share the same result, which means verified readiness,
  // not merely a successful spawn or a READY announcement.
  if (backendAttempt) return backendAttempt.promise;
  backendReady = null;
  recentBackendLines.length = 0;
  const attempt = { stdout: "", stderr: "", announced: false, exited: false };
  attempt.promise = new Promise((resolve) => { attempt.finish = resolve; });
  backendAttempt = attempt;
  const isCurrent = () => backendAttempt === attempt && !quitting && !shutdownController.isPending();
  const fail = (message) => {
    if (!isCurrent()) return;
    rememberBackendLine(message);
    const wasReady = Boolean(backendReady);
    attempt.finish({ ok: false, error: message });
    stopBackend();
    if (wasReady) showConnectionChooser();
    sendLauncherStatus(message);
    showBackendFailure(message);
  };

  sendLauncherStatus("Autoriza el sensor local en el diálogo de autenticación...");
  let pythonPath, env, cwd;
  try {
    pythonPath = resolvePython();
    env = backendEnv(pythonPath);
    cwd = app.isPackaged ? process.resourcesPath : repoRoot();
    attempt.process = elevation.launchRuntime({
      spawn, target: pythonPath, args: ["-m", "sniff4hound.desktop_runtime"], cwd, env,
      platform: process.platform, euid: effectiveUid(),
      uid: typeof process.getuid === "function" ? process.getuid() : 0,
      gid: typeof process.getgid === "function" ? process.getgid() : 0,
      home: os.homedir(), which: elevation.findExecutable,
    });
    backendProcess = attempt.process;
  } catch (error) {
    fail(error.message);
    return attempt.promise;
  }
  const startedProcess = attempt.process;
  startedProcess.stdin.on("error", () => {}); // The child may close its lifetime pipe while exiting.

  startedProcess.stdout.on("data", (chunk) => {
    if (!isCurrent()) return;
    readLines(attempt, chunk, "stdout", async (line) => {
      if (!isCurrent()) return;
      if (line.startsWith(READY_PREFIX)) {
        if (attempt.announced) return;
        attempt.announced = true;
        try {
          const announcedRuntime = JSON.parse(line.slice(READY_PREFIX.length));
          announcedRuntime.connection = "local";
          announcedRuntime.protocol = announcedRuntime.protocol || "http";
          announcedRuntime.origin = new URL(announcedRuntime.url).origin;
          sendLauncherStatus("Comprobando el sensor local...");
          await verifyLocalService({ execFile, python: pythonPath, env, cwd, ready: announcedRuntime, prepared: preparedRuntime });
          if (!isCurrent()) return;
          if (quicPin.forcedOriginIsUnserved(forcedQuicOrigin, announcedRuntime)) {
            throw new Error(
              "The runtime could not open its HTTP/3 (UDP) listener. " +
                "Set SNIFF4HOUND_DESKTOP_HTTP3=0 to use HTTPS over TCP only.",
            );
          }
          announcedRuntime.security_code = readDesktopCodeFile(announcedRuntime.security_code_file);
          delete announcedRuntime.security_code_file;
          if (announcedRuntime.ca_pem) {
            registerTrustedRuntimeCa(announcedRuntime, announcedRuntime.ca_pem);
          }
          installRuntimeVerifyProc();
          backendReady = announcedRuntime;
          writeConnectionState({ mode: "local" });
          loadBackendWindow();
          attempt.finish({ ok: true });
        } catch (error) {
          fail(error.message);
        }
        return;
      }
      rememberBackendLine(line);
      sendLauncherStatus(line);
    });
  });

  startedProcess.stderr.on("data", (chunk) => {
    if (!isCurrent()) return;
    readLines(attempt, chunk, "stderr", (line) => {
      rememberBackendLine(line);
      sendLauncherStatus(line);
    });
  });

  startedProcess.on("error", (error) => {
    // A stopped attempt can still emit EPERM as pkexec switches uid. Its pipe
    // is already closed; it must not clear or fail a newer local/remote session.
    fail(error.message);
  });

  startedProcess.on("exit", (code, signal) => {
    attempt.exited = true;
    if (!isCurrent()) return;
    const wasReady = Boolean(backendReady);
    const refused = !wasReady && !signal && elevation.looksLikeRefusedElevation(code);
    const message = refused
      ? "Authorization cancelled. You can retry the local sensor or connect remotely."
      : `Sniff4Hound backend exited (${signal || code}).`;
    attempt.finish({ ok: false, error: message });
    stopBackend();
    if (wasReady && (code === 0 || signal === "SIGINT" || signal === "SIGTERM")) {
      quitting = true;
      app.quit();
      return;
    }
    if (wasReady) showConnectionChooser();
    sendLauncherStatus(message);
    if (!refused) showBackendFailure(message);
  });
  return attempt.promise;
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

// Runs on Electron's net module, i.e. Chromium's network stack, because that is
// the one that speaks HTTP/3: Node's https cannot. Trust for the runtime CA is
// applied by the session's certificate verify proc (installRuntimeCertificateTrust),
// which net requests go through too, so no per-request `ca` option is needed.
function performRequest({ method = "GET", url, headers = {}, body = null, limit = 1024 * 1024, timeoutMs = 7000 }) {
  const target = new URL(String(url));
  if (target.protocol === "https:" && isLoopbackHost(target.hostname)) {
    // The main process's own checks against a loopback runtime. net's TCP path
    // does not honour the loopback switch, so it is pinned here with node:https,
    // which takes the CA explicitly. The UI's data traffic does not come this way.
    const trusted = trustedCaForOrigin(target.origin);
    if (!trusted) return Promise.reject(new Error("Runtime certificate is not pinned."));
    return new Promise((resolve, reject) => {
      const req = https.request({
        method,
        hostname: target.hostname,
        port: target.port || 443,
        path: `${target.pathname}${target.search}`,
        headers,
        ca: trusted.caPem,
        timeout: timeoutMs,
      }, (response) => {
        const chunks = [];
        let size = 0;
        response.on("data", (chunk) => {
          size += chunk.length;
          if (size > limit) {
            req.destroy(new Error("La respuesta del sensor es demasiado grande. Reduce la búsqueda o el tamaño de página."));
            return;
          }
          chunks.push(chunk);
        });
        response.on("end", () => resolve({ status: response.statusCode, body: Buffer.concat(chunks).toString("utf8") }));
        response.on("error", reject);
      });
      req.on("timeout", () => req.destroy(new Error("El sensor tardó demasiado en responder. Reintenta o cambia de sensor.")));
      req.on("error", reject);
      if (body !== null && body !== undefined) req.write(body);
      req.end();
    });
  }
  return new Promise((resolve, reject) => {
    const request = net.request({ method, url: String(url), redirect: "error" });
    for (const [name, value] of Object.entries(headers || {})) {
      request.setHeader(name, value);
    }
    let settled = false;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) reject(error);
      else resolve(value);
    };
    const timer = setTimeout(() => {
      request.abort();
      finish(new Error("El sensor tardó demasiado en responder. Reintenta o cambia de sensor."));
    }, timeoutMs);
    request.on("response", (response) => {
      const chunks = [];
      let size = 0;
      response.on("data", (chunk) => {
        size += chunk.length;
        if (size > limit) {
          request.abort();
          finish(new Error("La respuesta del sensor es demasiado grande. Reduce la búsqueda o el tamaño de página."));
          return;
        }
        chunks.push(chunk);
      });
      response.on("end", () => {
        finish(null, {
          status: response.statusCode,
          body: Buffer.concat(chunks).toString("utf8"),
        });
      });
      response.on("error", (error) => finish(error));
    });
    request.on("error", (error) => finish(error));
    if (body !== null && body !== undefined) request.write(body);
    request.end();
  });
}

function requestText(url, headers = {}) {
  return performRequest({ url, headers }).then((result) => {
    if (result.status < 200 || result.status >= 300) {
      throw new Error(`Remote backend returned HTTP ${result.status}.`);
    }
    return result.body;
  });
}

// --- Renderer HTTP bridge --------------------------------------------------
//
// The renderer's own QUIC attempts are not dependable under Chromium's
// renderer network stack, so the UI's requests and its realtime stream go
// through here instead: the main process speaks HTTP/3 to the runtime and hands
// the answers back. Only origins whose CA the user has pinned (trustedRuntimeCas,
// set when a runtime is connected) are reachable, so this cannot be used as an
// open proxy from the renderer.

const HTTP_BRIDGE_BODY_LIMIT = 32 * 1024 * 1024;
// Streams are limited by what is pending (one unterminated event), not by
// their lifetime total, and closed after a period without data - see
// lib/bridge-streams.js.
const httpStreams = createStreamRegistry();

function bridgeTargetAllowed(rawUrl) {
  const origin = normalizeOrigin(rawUrl);
  return Boolean(origin) && origin.startsWith("https://") && Boolean(trustedCaForOrigin(origin));
}

function bridgeRequestOptions(payload) {
  if (!payload || typeof payload !== "object") throw new Error("Invalid request.");
  if (!bridgeTargetAllowed(payload.url)) throw new Error("Request target is not a pinned runtime.");
  return {
    method: String(payload.method || "GET").toUpperCase(),
    url: String(payload.url),
    headers: payload.headers && typeof payload.headers === "object" ? payload.headers : {},
    body: typeof payload.body === "string" ? payload.body : null,
    limit: HTTP_BRIDGE_BODY_LIMIT,
    timeoutMs: 30000,
  };
}

handleIpc("desktop-http:request", SHELL_ONLY, (_event, payload) => performRequest(bridgeRequestOptions(payload)));

handleIpc("desktop-http:stream-open", SHELL_ONLY, (event, payload) => {
  const options = bridgeRequestOptions({ ...payload, method: "GET" });
  const contents = event.sender;
  // One 'destroyed' and one navigation listener per webContents: its streams
  // end with the document that opened them (reload, sensor switch, chooser).
  httpStreams.watch(contents);
  return openBridgeStream({
    id: String(payload.id || ""),
    ownerId: contents.id,
    url: options.url,
    headers: options.headers,
    createRequest: (requestOptions) => net.request(requestOptions),
    registry: httpStreams,
    send: (message) => {
      if (!contents.isDestroyed()) contents.send("desktop-http:stream", { id: String(payload.id), ...message });
    },
  });
});

handleIpc("desktop-http:stream-close", SHELL_ONLY, (event, payload) => {
  const id = String((payload && payload.id) || "");
  const stream = httpStreams.get(id);
  if (stream && stream.ownerId === event.sender.id) {
    stream.cleanup();
    stream.request.abort();
    return { closed: true };
  }
  return { closed: false };
});

async function requestJson(url, headers = {}, optionsOverride = {}) {
  const body = await requestText(url, headers, optionsOverride);
  try {
    return body ? JSON.parse(body) : {};
  } catch {
    throw new Error("El sensor devolvió una respuesta no válida.");
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
    throw new Error("El sensor no devolvió una CA válida de Sniff4Hound.");
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
    throw new Error("Código de seguridad incorrecto o ausente.");
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
    backgroundColor: "#080a0d",
    icon: path.join(__dirname, "assets", "icon.png"),
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });

  mainWindowShown = new Promise((resolve) => {
    mainWindow.once("ready-to-show", () => {
      mainWindow.show();
      resolve();
    });
  });
  // System notifications for the bundled SPA (monitor alerts, connection
  // loss, chat) and no other permission for any document.
  mainWindow.webContents.session.setPermissionRequestHandler((contents, permission, callback, details) => {
    const requestingUrl = (details && details.requestingUrl) || (contents && contents.getURL ? contents.getURL() : "");
    callback(windowSecurity.permissionAllowed(permission, requestingUrl));
  });
  mainWindow.webContents.session.setPermissionCheckHandler((_contents, permission, requestingOrigin) =>
    windowSecurity.permissionAllowed(permission, requestingOrigin));
  mainWindow.loadFile(SPLASH_PATH);

  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (isAllowedExternalUrl(url)) shell.openExternal(url);
    return { action: "deny" };
  });

  // Renderer-initiated navigations (links, location changes, a file dropped
  // on the window) may only reach the chooser or the shell; web links open in
  // the operator's browser instead, everything else is dropped.
  mainWindow.webContents.on("will-navigate", (event, url) => {
    if (windowSecurity.navigationAllowed(url, { splashPath: SPLASH_PATH })) return;
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
      let data = fs.readFileSync(filePath);
      if (path.extname(filePath) === ".html") {
        const origin = backendReady && new URL(backendReady.url || backendReady.origin).origin;
        const websocketOrigin = origin && origin.replace(/^http/, "ws");
        const connect = origin ? `connect-src 'self' ${origin} ${websocketOrigin}` : "connect-src 'self'";
        data = Buffer.from(data.toString("utf8").replace("connect-src 'self'", connect));
      }
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
  mainWindow.loadURL(`${APP_SCHEME}://shell/index.html${search ? `?${search}` : ""}#${hash}`);
}

// Menu routes switch the loaded SPA's route in place (preload's
// onMenuNavigate); loadShell() is only for a window not showing the shell yet.
function navigate(routePath) {
  if (!mainWindow || mainWindow.isDestroyed() || !backendReady) return;
  const contents = mainWindow.webContents;
  const loading = typeof contents.isLoadingMainFrame === "function" && contents.isLoadingMainFrame();
  if (windowSecurity.menuNavigationMode(contents.getURL(), { loading }) === "renderer") {
    contents.send("desktop-menu:navigate", String(routePath || "/"));
    return;
  }
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
  mainWindow.loadFile(SPLASH_PATH);
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

function stopBackend() {
  const attempt = backendAttempt;
  if (!attempt) return;
  // Invalidate before ending the pipe: exit/error/verification callbacks may
  // run immediately or after a retry has installed a different child.
  backendAttempt = null;
  backendProcess = null;
  backendReady = null;
  attempt.finish({ ok: false, error: "The local sensor attempt was stopped. You can retry or connect remotely." });
  const stoppingProcess = attempt.process;
  if (!stoppingProcess) return;
  // Polkit execs Python as root, which the operator cannot signal directly.
  // Closing only this child's pipe asks it to clean up and terminate itself.
  try { stoppingProcess.stdin.end(); } catch { /* The pipe may already be closed. */ }
  if (attempt.exited || attempt.announced) return;
  try { stoppingProcess.kill("SIGINT"); } catch { /* The pipe still stops a root runtime. */ }
  setTimeout(() => {
    if (!attempt.exited) {
      try { stoppingProcess.kill("SIGTERM"); } catch { /* Already exited or switched uid. */ }
    }
  }, 5000).unref();
}

async function connectRemote(payload) {
  const parsed = parseRemoteTarget(payload || {});
  if (!isLoopbackHost(parsed.host)) installRuntimeVerifyProc();
  sendLauncherStatus("Checking remote backend...");
  const verified = await verifyRemoteConnection(parsed);
  if (quitting || shutdownController.isPending()) return { ok: false, error: "The desktop window is closing." };
  if (backendProcess) {
    stopBackend();
  }
  backendReady = verified;
  writeConnectionState({
    mode: "remote",
    protocol: verified.protocol,
    host: verified.host,
    port: verified.port,
  });
  loadBackendWindow();
  return { ok: true, target: { ...verified, security_code: "" } };
}

handleIpc("desktop-window:minimize", SHELL_OR_SPLASH, () => {
  if (mainWindow && !mainWindow.isDestroyed()) mainWindow.minimize();
});

handleIpc("desktop-window:maximize", SHELL_OR_SPLASH, () => {
  if (!mainWindow || mainWindow.isDestroyed()) return;
  if (mainWindow.isMaximized()) {
    mainWindow.unmaximize();
  } else {
    mainWindow.maximize();
  }
});

handleIpc("desktop-window:close", SHELL_OR_SPLASH, () => {
  if (mainWindow && !mainWindow.isDestroyed()) mainWindow.close();
});

handleIpc("desktop-window:shutdown", SHELL_OR_SPLASH, () => shutdownController.start());

handleIpc("desktop-shell:open-external", SHELL_ONLY, (_event, url) => {
  // The renderer-facing bridge (preload.js) forwards whatever string the
  // SPA passes, unvalidated - this is the only place left that can refuse
  // a `file:`/`javascript:`/other unexpected scheme before it reaches the
  // OS's own URL handler.
  if (!url || !isAllowedExternalUrl(url)) return;
  shell.openExternal(url);
});

handleIpc("desktop-runtime:get-connection-defaults", SPLASH_ONLY, () => {
  const state = readConnectionState();
  const requiresPrivileges = process.platform === "linux" && effectiveUid() !== 0;
  const requestPrivileges = startupPrivilegeRequest && requiresPrivileges && state.mode !== "remote" && !elevation.optedOut(process.env);
  startupPrivilegeRequest = false;
  return {
    requiresPrivileges,
    requestPrivileges,
    localPort: process.env.SNIFF4HOUND_PORT || DEFAULT_PORT,
    mode: state.mode || "local",
    protocol: state.protocol || "http",
    host: state.host || "127.0.0.1",
    port: state.port || DEFAULT_PORT,
  };
});

handleIpc("desktop-runtime:start-local", SPLASH_ONLY, async () => {
  await mainWindowShown;
  if (quitting || shutdownController.isPending() || !mainWindow || mainWindow.isDestroyed()) return { ok: false, error: "The desktop window is closing." };
  return startBackend();
});

handleIpc("desktop-runtime:connect-remote", SPLASH_ONLY, async (_event, payload) => {
  try {
    return await connectRemote(payload || {});
  } catch (error) {
    const message = error && error.message ? error.message : "No se pudo conectar al sensor remoto. Revisa la dirección, el código y la CA.";
    sendLauncherStatus(message);
    return { ok: false, error: message };
  }
});

handleIpc("desktop-runtime:show-connection-chooser", SHELL_ONLY, () => {
  showConnectionChooser();
  return { ok: true };
});

// Prepare the local name mapping and HTTP/3 before Chromium starts. The shell
// verifies the child's DNS-SD service before using this exact origin. An absent
// server-key pin disables QUIC; mDNS failures are reported during startup.
let preparedRuntime = null;
// "host:port" Chromium was told to speak HTTP/3 to, with no TCP fallback.
let forcedQuicOrigin = "";

function prepareRuntimeNetworking() {
  if (process.platform !== "linux") return;
  const pythonPath = resolvePython();
  preparedRuntime = quicPin.prepareRuntime({
    execFileSync,
    python: pythonPath,
    env: backendEnv(pythonPath),
    cwd: app.isPackaged ? process.resourcesPath : repoRoot(),
  });
  for (const [name, value] of [...quicPin.resolverSwitches(preparedRuntime), ...quicPin.quicSwitches({ prepared: preparedRuntime, env: process.env })]) {
    app.commandLine.appendSwitch(name, value);
    if (name === "origin-to-force-quic-on") forcedQuicOrigin = value;
  }
}
prepareRuntimeNetworking();

app.whenReady().then(() => {
  handBackUserData();
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

process.on("exit", () => {
  handBackUserData();
});
