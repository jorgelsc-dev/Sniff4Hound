const { app, BrowserWindow, Menu, ipcMain, shell, dialog } = require("electron");
const { spawn } = require("node:child_process");
const fs = require("node:fs");
const http = require("node:http");
const https = require("node:https");
const path = require("node:path");

const READY_PREFIX = "SNIFF4HOUND_DESKTOP_READY ";
const DEFAULT_PORT = "45678";
const CONNECTION_STATE_FILE = "connection.json";

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

let mainWindow = null;
let backendProcess = null;
let backendReady = null;
let backendExited = false;
let suppressNextBackendExit = false;
let quitting = false;
let stdoutBuffer = "";
let stderrBuffer = "";
const recentBackendLines = [];

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
  return !process.env.SNIFF4HOUND_DESKTOP_PYTHON && fs.existsSync(SHARED_VENDOR_DIR);
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

  return process.env.PYTHON || "python3";
}

function resolveFrontendDist() {
  if (process.env.SNIFF4HOUND_FRONTEND_DIST) {
    return process.env.SNIFF4HOUND_FRONTEND_DIST;
  }
  if (usingSharedVendorRuntime()) {
    // The shared vendor tree already carries its own _frontend_dist (built
    // in by setup.py's custom build_py) - the Python backend resolves it on
    // its own, same as the CLI does. Returning "" here leaves
    // SNIFF4HOUND_FRONTEND_DIST unset instead of forcing a path that has no
    // meaning once main.js is running from inside the installed package.
    return "";
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
  const frontendDist = resolveFrontendDist();
  const env = {
    ...process.env,
    PYTHONUNBUFFERED: "1",
    PYTHONNOUSERSITE: "1",
    SNIFF4HOUND_DESKTOP: "1",
    SNIFF4HOUND_HOST: process.env.SNIFF4HOUND_HOST || "127.0.0.1",
    SNIFF4HOUND_PORT: process.env.SNIFF4HOUND_PORT || DEFAULT_PORT,
    SNIFF4HOUND_CAPTURE_AUTO_START: "0",
  };
  if (frontendDist) {
    env.SNIFF4HOUND_FRONTEND_DIST = frontendDist;
  }

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
    showBackendFailure(`Sniff4Hound backend exited (${signal || code}).`);
  });
}

function parseRemoteTarget(payload) {
  const protocol = String(payload.protocol || "http").trim().toLowerCase() === "https" ? "https" : "http";
  const rawHost = String(payload.host || "").trim();
  const rawPort = String(payload.port || "").trim();
  const securityCode = String(payload.securityCode || payload.code || "").trim();
  if (!rawHost) {
    throw new Error("Remote host is required.");
  }

  let url = null;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(rawHost)) {
    url = new URL(rawHost);
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
    port: url.port || (url.protocol === "https:" ? "443" : "80"),
    protocol: url.protocol.replace(":", ""),
    security_code: securityCode,
    auth_required: Boolean(securityCode),
  };
}

function requestJson(url, headers = {}) {
  return new Promise((resolve, reject) => {
    const client = url.protocol === "https:" ? https : http;
    const request = client.request(
      url,
      {
        method: "GET",
        headers,
        timeout: 7000,
      },
      (response) => {
        let body = "";
        response.setEncoding("utf8");
        response.on("data", (chunk) => {
          body += chunk;
          if (body.length > 1024 * 1024) request.destroy(new Error("Response is too large."));
        });
        response.on("end", () => {
          let payload = null;
          try {
            payload = body ? JSON.parse(body) : {};
          } catch {
            reject(new Error("Remote backend did not return JSON."));
            return;
          }
          if (response.statusCode < 200 || response.statusCode >= 300) {
            reject(new Error(payload.message || `Remote backend returned HTTP ${response.statusCode}.`));
            return;
          }
          resolve(payload);
        });
      },
    );
    request.on("timeout", () => request.destroy(new Error("Remote backend timed out.")));
    request.on("error", reject);
    request.end();
  });
}

async function verifyRemoteConnection(config) {
  const sessionUrl = new URL("/api/auth/session", config.origin);
  const headers = config.security_code ? { "X-Security-Code": config.security_code } : {};
  const payload = await requestJson(sessionUrl, headers);
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
    shell.openExternal(url);
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
    shell.openExternal(url);
  });

  mainWindow.on("close", () => {
    quitting = true;
    stopBackend();
  });
}

function routeUrl(routePath) {
  if (!backendReady) return "";
  const base = new URL(backendReady.url);
  const target = new URL(String(routePath || "/"), "http://sniff4hound.local");
  base.pathname = target.pathname || "/";
  base.search = target.search || "";
  if (backendReady.auth_required && backendReady.security_code) {
    base.searchParams.set("code", backendReady.security_code);
  }
  base.searchParams.set("desktop", "1");
  base.searchParams.set("desktop_backend", backendReady.connection === "remote" ? "remote" : "local");
  return base.toString();
}

function navigate(routePath) {
  const url = routeUrl(routePath);
  if (url && mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.loadURL(url);
  }
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
  mainWindow.loadURL(backendReady.url);
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
  if (!url) return;
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
  createWindow();
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});

app.on("before-quit", () => {
  quitting = true;
  stopBackend();
});
