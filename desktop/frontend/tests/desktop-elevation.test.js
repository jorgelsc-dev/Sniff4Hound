import assert from "node:assert/strict";
import { createRequire } from "node:module";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { EventEmitter } from "node:events";
import test from "node:test";
import vm from "node:vm";

// The desktop shell's CommonJS elevation helpers. Nothing here elevates: they
// only build the command the shell would run, from fake lookups.
const require = createRequire(import.meta.url);
const elevation = require("../../lib/elevation.js");
const { configureGraphics, graphicsSwitches } = require("../../lib/graphics.js");

const BASE_ENV = {
  DISPLAY: ":0",
  XAUTHORITY: "/home/op/.Xauthority",
  XDG_RUNTIME_DIR: "/run/user/1000",
  HOME: "/home/op",
  PATH: "/home/op/.venv/bin:/usr/bin",
  SNIFF4HOUND_DESKTOP_DEBUG_PORT: "9223",
  SNIFF4HOUND_JWT_SECRET: "never-on-a-command-line",
  SNIFF4HOUND_IPC_TOKEN: "nor-this",
  SECRET_TOKEN: "not-listed",
  LC_ALL: "es_VE.UTF-8",
};

const which = (found) => (name) => found[name] || null;
const build = (overrides = {}) =>
  elevation.buildElevationCommand({
    target: "/opt/s4h/python",
    args: ["-m", "sniff4hound.desktop_runtime"],
    env: BASE_ENV,
    uid: 1000,
    gid: 1000,
    home: "/home/op",
    which: which({ sudo: "/usr/bin/sudo", pkexec: "/usr/bin/pkexec" }),
    ...overrides,
  });

test("the opt-out skips the automatic UI request but does not bypass runtime privileges", () => {
  for (const off of ["0", "false", "off", "no", " OFF "]) assert.equal(elevation.optedOut({ SNIFF4HOUND_DESKTOP_ELEVATE: off }), true);
  assert.equal(elevation.optedOut({}), false);
  assert.equal(elevation.optedOut({ SNIFF4HOUND_DESKTOP_ELEVATE: "1" }), false);
});

test("the root runtime keeps the operator's HOME, data environment and settings", () => {
  const assignments = elevation.forwardedAssignments({ env: BASE_ENV, uid: 1000, gid: 1001, home: "/home/op" });
  for (const expected of [
    "DISPLAY=:0",
    "XAUTHORITY=/home/op/.Xauthority",
    "XDG_RUNTIME_DIR=/run/user/1000",
    "HOME=/home/op",
    "PATH=/home/op/.venv/bin:/usr/bin",
    "SNIFF4HOUND_DESKTOP_DEBUG_PORT=9223",
    "LC_ALL=es_VE.UTF-8",
    "SNIFF4HOUND_INVOKING_UID=1000",
    "SNIFF4HOUND_INVOKING_GID=1001",
  ]) {
    assert.ok(assignments.includes(expected), `missing ${expected}`);
  }
});

test("secrets and unlisted variables never reach the command line", () => {
  const joined = elevation.forwardedAssignments({ env: BASE_ENV, uid: 1000, gid: 1000, home: "/home/op" }).join("\n");
  assert.doesNotMatch(joined, /JWT_SECRET|IPC_TOKEN|SECRET_TOKEN|never-on-a-command-line|nor-this/);
});

test("HOME is taken from the lookup when the environment has none", () => {
  const noHome = { ...BASE_ENV };
  delete noHome.HOME;
  const assignments = elevation.forwardedAssignments({ env: noHome, uid: 1000, gid: 1000, home: "/home/op" });
  assert.ok(assignments.includes("HOME=/home/op"));
});

test("the operator's implicit X11 authority is made explicit before elevation", () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "s4h-xauth-test-"));
  try {
    const env = { DISPLAY: ":0", HOME: home };
    const forward = () => elevation.forwardedAssignments({ env, uid: 1000, gid: 1000, home });
    assert.ok(!forward().some((item) => item.startsWith("XAUTHORITY=")), "do not invent a missing authority file");
    const authority = path.join(home, ".Xauthority");
    fs.writeFileSync(authority, "fixture-cookie", { mode: 0o600 });
    const assignments = forward();
    assert.ok(assignments.includes(`XAUTHORITY=${authority}`));
    assert.doesNotMatch(assignments.join("\n"), /fixture-cookie/, "only the path goes on the command line");
    assert.equal(fs.statSync(authority).mode & 0o777, 0o600, "cookie permissions remain private");

    env.XAUTHORITY = "/run/user/1000/xwayland-auth";
    assert.ok(forward().includes("XAUTHORITY=/run/user/1000/xwayland-auth"), "an explicit compositor cookie wins");
    delete env.DISPLAY;
    delete env.XAUTHORITY;
    assert.ok(!forward().some((item) => item.startsWith("XAUTHORITY=")), "a Wayland-only session needs no X11 cookie");
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test("relative authority paths survive a privilege tool changing its working directory", () => {
  const assignments = elevation.forwardedAssignments({
    env: { DISPLAY: ":0", XAUTHORITY: "relative-cookie" }, uid: 1000, gid: 1000, home: "/home/op",
  });
  assert.ok(assignments.includes(`XAUTHORITY=${path.resolve("relative-cookie")}`));
});

test("a value with a newline or NUL cannot split the assignment", () => {
  const assignments = elevation.forwardedAssignments({
    env: { DISPLAY: ":0\nSNIFF4HOUND_X=1", LANG: "a\0b", PATH: "/usr/bin", XAUTHORITY: {} },
    uid: 1,
    gid: 1,
    home: "/h",
  });
  assert.ok(!assignments.some((item) => /^(DISPLAY|LANG|XAUTHORITY)=/.test(item)));
  assert.ok(assignments.includes("PATH=/usr/bin"));
});

test("authentication uses the native Polkit agent even when sudo and zenity are installed", () => {
  const plan = build({ which: which({ pkexec: "/usr/bin/pkexec", sudo: "/usr/bin/sudo", zenity: "/usr/bin/zenity" }) });
  assert.equal(plan.command, "/usr/bin/pkexec");
  assert.deepEqual(plan.args.slice(0, 3), ["--disable-internal-agent", "--keep-cwd", "env"]);
  const at = plan.args.indexOf("/opt/s4h/python");
  assert.deepEqual(plan.args.slice(at), ["/opt/s4h/python", "-m", "sniff4hound.desktop_runtime"]);
  assert.doesNotMatch(plan.args.join("\n"), /electron|--no-sandbox|--ozone-platform|SUDO_ASKPASS/);
});

test("a normal desktop retains acceleration; only a manually root-launched shell avoids GL", () => {
  for (const [platform, euid, expected] of [
    ["linux", 0, true],
    ["linux", 1000, false],
    ["darwin", 0, false],
    ["win32", 0, false],
  ]) {
    const switches = [];
    let software = false;
    const app = {
      commandLine: { appendSwitch: (name, value) => switches.push([name, value].filter((item) => item !== undefined)) },
      disableHardwareAcceleration: () => { software = true; },
    };
    configureGraphics({ app, platform, euid, env: {}, args: [] });
    assert.equal(software, expected, `${platform}, uid ${euid}`);
    assert.deepEqual(switches, platform !== "linux" ? [] : expected
      ? [["no-sandbox"], ["disable-gpu"], ["disable-software-rasterizer"]]
      : []);
  }
});

test("only root defaults to X11 when an authenticated display is available", () => {
  const options = { platform: "linux", euid: 0, env: { DISPLAY: ":0", XDG_SESSION_TYPE: "wayland" } };
  const platformSwitches = (overrides = {}) => graphicsSwitches({ ...options, ...overrides }).filter(([name]) => name === "ozone-platform");
  assert.deepEqual(platformSwitches(), [["ozone-platform", "x11"]]);
  assert.deepEqual(platformSwitches({ euid: 1000 }), []);
  assert.deepEqual(platformSwitches({ env: { WAYLAND_DISPLAY: "wayland-0" } }), []);
  assert.deepEqual(platformSwitches({ args: ["--ozone-platform=wayland"] }), []);
  assert.deepEqual(platformSwitches({ args: ["--ozone-platform", "wayland"] }), []);
});

test("sudo and a generic password dialog cannot replace native Polkit authentication", () => {
  assert.equal(build({ which: which({}) }), null);
  assert.equal(build({ which: which({ sudo: "/usr/bin/sudo", zenity: "/usr/bin/zenity" }) }), null);
});

test("Polkit cancellation and authorization failure are distinguished from runtime crashes", () => {
  assert.equal(elevation.looksLikeRefusedElevation(126), true);
  assert.equal(elevation.looksLikeRefusedElevation(127), true);
  assert.equal(elevation.looksLikeRefusedElevation(1), false);
  assert.equal(elevation.looksLikeRefusedElevation(0), false);
});

test("system directories win over a same-named program earlier on PATH", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "s4h-path-test-"));
  try {
    // `sh` is in a system directory on every Linux box this runs on
    const fake = path.join(tmp, "sh");
    fs.writeFileSync(fake, "#!/bin/sh\n", { mode: 0o755 });
    const found = elevation.findExecutable("sh", `${tmp}:/usr/bin`);
    assert.ok(found && found !== fake, "a program of the same name in the operator's own directory must lose");
    assert.equal(elevation.findExecutable("sniff4hound-no-such-tool", tmp), null);
    assert.equal(elevation.findExecutable("sniff4hound-fake", `${tmp}`), null);
    fs.writeFileSync(path.join(tmp, "sniff4hound-fake"), "#!/bin/sh\n", { mode: 0o755 });
    assert.equal(elevation.findExecutable("sniff4hound-fake", tmp), path.join(tmp, "sniff4hound-fake"));
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("handing a tree back changes only what is not already the operator's", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "s4h-chown-test-"));
  try {
    fs.mkdirSync(path.join(tmp, "a", "b"), { recursive: true });
    fs.writeFileSync(path.join(tmp, "a", "b", "f"), "x");
    fs.symlinkSync("/etc/passwd", path.join(tmp, "link"));
    const { uid, gid } = fs.statSync(tmp);
    assert.equal(elevation.chownTree(tmp, uid, gid), 0, "everything is already ours");
    assert.equal(elevation.chownTree(path.join(tmp, "does-not-exist"), uid, gid), 0, "a missing tree is not an error");
    // the symlink's target is never touched (lchown on the link itself)
    assert.equal(fs.lstatSync(path.join(tmp, "link")).isSymbolicLink(), true);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

// Runtime spawning without requesting actual credentials.
function runtimeRig(overrides = {}) {
  const calls = [];
  const child = new EventEmitter();
  const options = {
    spawn: (...args) => { calls.push(args); return child; },
    target: "/opt/s4h/python", args: ["-m", "sniff4hound.desktop_runtime"], cwd: "/repo",
    env: { ...BASE_ENV }, platform: "linux", euid: 1000, uid: 1000, gid: 1000,
    home: "/home/op", which: which({ pkexec: "/usr/bin/pkexec" }),
    ...overrides,
  };
  return { calls, child, run: () => elevation.launchRuntime(options) };
}

test("the runtime is launched with Polkit and a parent lifetime pipe", () => {
  const { calls, child, run } = runtimeRig();
  assert.equal(run(), child);
  const [command, args, options] = calls[0];
  assert.equal(command, "/usr/bin/pkexec");
  assert.equal(args[0], "--disable-internal-agent");
  assert.equal(options.cwd, "/repo");
  assert.deepEqual(options.stdio, ["pipe", "pipe", "pipe"]);
  assert.ok(!("SUDO_ASKPASS" in options.env));
});

test("already-root and non-Linux runtimes start directly without a second prompt", () => {
  for (const overrides of [{ euid: 0 }, { platform: "darwin" }]) {
    const { calls, run } = runtimeRig(overrides);
    run();
    assert.equal(calls[0][0], "/opt/s4h/python");
    assert.deepEqual(calls[0][1], ["-m", "sniff4hound.desktop_runtime"]);
  }
});

test("missing graphical elevation tools fail before starting any unprivileged backend", () => {
  const { calls, run } = runtimeRig({ which: which({ sudo: "/usr/bin/sudo" }) });
  assert.throws(run, /Install pkexec/);
  assert.deepEqual(calls, []);
});

// Evaluate the actual main/preload/splash scripts. Every OS-facing dependency
// is replaced: no Electron, display, network, user data, process or root access.
const desktopSource = (name) => fs.readFileSync(new URL(`../../${name}`, import.meta.url), "utf8");
const PREPARED = { host: "127.0.0.1", port: 45678, mdnsHost: "fixture.local", address: "127.0.0.1", spki: "A".repeat(43) + "=" };
const ANNOUNCEMENT = { enabled: true, service_name: "fixture._sniff4hound._tcp.local.",
  service_type: "_sniff4hound._tcp.local.", hostname: PREPARED.mdnsHost, port: PREPARED.port, addresses: [PREPARED.address] };
const READY = { url: "https://fixture.local:45678/", host: "fixture.local", port: 45678,
  protocol: "https", mdns: ANNOUNCEMENT, http3: true };
const tick = () => new Promise((resolve) => setImmediate(resolve));

async function desktopVm({ debugPort, uid = 1000, launchError = null } = {}) {
  const children = [], switches = [], discovery = [], loads = [], statuses = [], errors = [], timers = [], writes = [];
  const handlers = new Map();
  const permissions = {}, menus = [], sent = [], opened = [];
  const proc = Object.assign(new EventEmitter(), {
    platform: "linux", env: { SNIFF4HOUND_DESKTOP_ELEVATE: "0", SNIFF4HOUND_DESKTOP_HTTP3: "1" }, argv: [],
    getuid: () => uid, geteuid: () => uid, getgid: () => uid,
    kill: () => assert.fail("must never signal another process by pid"),
  });
  if (debugPort !== undefined) proc.env.SNIFF4HOUND_DESKTOP_DEBUG_PORT = debugPort;
  const app = Object.assign(new EventEmitter(), {
    commandLine: { appendSwitch: (...args) => switches.push(args) },
    disableHardwareAcceleration() {}, getPath: () => "/fixture-user-data", isPackaged: false,
    whenReady: () => Promise.resolve(), quit: () => { app.emit("before-quit"); },
  });
  let window;
  class Window extends EventEmitter {
    constructor() {
      super();
      window = this;
      this.webContents = Object.assign(new EventEmitter(), {
        id: 1, session: {
          setPermissionRequestHandler: (handler) => { permissions.request = handler; },
          setPermissionCheckHandler: (handler) => { permissions.check = handler; },
        },
        setWindowOpenHandler() {},
        send: (channel, message) => { sent.push([channel, message]); if (channel === "desktop-runtime:status") statuses.push(message); },
        // What Electron reports for the loadFile()/loadURL() calls recorded below.
        getURL: () => { const last = loads.at(-1) || ""; return last.startsWith("app:") ? last : pathToFileURL(last).href; },
        isDestroyed: () => false,
      });
    }
    isDestroyed() { return false; }
    loadFile(file) { loads.push(file); }
    loadURL(url) { loads.push(url); }
    show() {}
    close() { this.emit("close"); }
  }
  const ipcRenderer = Object.assign(new EventEmitter(), {
    // The calling frame is the window's main frame showing its current document.
    invoke: (channel, ...args) => Promise.resolve().then(() => handlers.get(channel)({
      sender: window.webContents, senderFrame: { url: window.webContents.getURL(), parent: null },
    }, ...args)),
  });
  let api;
  const electron = {
    app, BrowserWindow: Window,
    Menu: { setApplicationMenu: (menu) => menus.push(menu), buildFromTemplate: (template) => template },
    ipcMain: { handle: (channel, handler) => handlers.set(channel, handler) },
    net: { request: () => assert.fail("unexpected network access") }, shell: { openExternal: (url) => opened.push(url) },
    dialog: { showMessageBox: (_window, detail) => errors.push(detail.message) },
    protocol: { registerSchemesAsPrivileged() {}, handle() {} },
    session: { defaultSession: { setCertificateVerifyProc() {} } },
    contextBridge: { exposeInMainWorld: (_name, bridge) => { api = bridge; } }, ipcRenderer,
  };
  const dependencies = {
    electron,
    "node:child_process": {
      spawn: () => assert.fail("unexpected spawn"),
      execFile: (_command, _args, _options, callback) => discovery.push(callback),
      execFileSync: () => assert.fail("unexpected synchronous process"),
    },
    "node:fs": {
      existsSync: () => false, readFileSync: () => { throw new Error("no fixture file"); },
      unlinkSync: () => assert.fail("no file should be removed without a supplied path"),
      mkdirSync() {}, writeFileSync: (file, value) => writes.push([file, value]),
    },
    "node:os": { homedir: () => "/fixture-home" },
    "node:https": { request: () => assert.fail("unexpected HTTPS access") },
    "./lib/elevation": {
      ...elevation, findExecutable: () => null,
      launchRuntime: () => {
        if (launchError) { const error = launchError; launchError = null; throw error; }
        const child = new EventEmitter();
        child.stdout = new EventEmitter(); child.stderr = new EventEmitter();
        child.stdin = Object.assign(new EventEmitter(), { ends: 0, end() { this.ends += 1; } });
        child.signals = [];
        child.kill = (signal) => { child.signals.push(signal); };
        children.push(child);
        return child;
      },
    },
    "./lib/session-bus": { startPrivateSessionBus: () => null },
    "./lib/quic-pin": { ...require("../../lib/quic-pin.js"), prepareRuntime: () => PREPARED },
  };
  const context = vm.createContext({
    require: (name) => {
      if (Object.hasOwn(dependencies, name)) return dependencies[name];
      if (["node:crypto", "node:string_decoder", "node:path"].includes(name)) return require(name);
      if (name.startsWith("./lib/")) return require(`../../${name.slice(2)}`);
      assert.fail(`unexpected dependency: ${name}`);
    },
    __dirname: "/fixture/desktop", process: proc, Buffer, Response,
    console: { error: (message) => errors.push(message) },
    setTimeout: (callback, delay) => { timers.push({ callback, delay }); return { unref() {} }; },
    clearTimeout() {},
  });
  vm.runInContext(desktopSource("main.js"), context, { filename: "desktop/main.js" });
  await tick();
  window.emit("ready-to-show");
  vm.runInNewContext(desktopSource("preload.js"), { require: () => electron, process: proc });
  return {
    api, app, children, switches, discovery, loads, statuses, errors, timers, writes, window,
    handlers, permissions, menus, sent, opened,
    state: () => vm.runInContext("({ backendProcess, backendReady, backendAttempt, quitting })", context),
    announce: (child = children.at(-1), payload = READY) => child.stdout.emit("data", Buffer.from(
      `SNIFF4HOUND_DESKTOP_READY ${typeof payload === "string" ? payload : JSON.stringify(payload)}\n`)),
    resolveDiscovery: (error = null, changes = {}, at = discovery.length - 1) => discovery[at](error,
      JSON.stringify({ ...ANNOUNCEMENT, role: "runtime", scheme: "https", ...changes })),
    // Only the remote transport is stubbed; IPC, target parsing and the session
    // switch remain the production code, so no remote sensor is contacted.
    remoteTransport: () => vm.runInContext("verifyRemoteConnection = async (config) => config", context),
  };
}

async function splashVm(api) {
  const elements = new Map();
  for (const name of ["log", "status-row", "local-start", "remote-form", "remote-connect", "remote-host", "remote-port", "remote-code", "remote-ca"]) {
    elements.set(name, { disabled: false, value: "", textContent: "", listeners: {},
      classList: { toggle() {} }, focus() {},
      addEventListener(type, callback) { this.listeners[type] = callback; } });
  }
  vm.runInNewContext(desktopSource("splash.js"), {
    window: { sniff4houndDesktop: api },
    document: { getElementById: (name) => elements.get(name), querySelectorAll: () => [] },
  });
  await tick();
  return {
    element: (name) => elements.get(name),
    local: () => elements.get("local-start").listeners.click(),
    remote: () => elements.get("remote-form").listeners.submit({ preventDefault() {} }),
    busy: () => [elements.get("local-start").disabled, elements.get("remote-connect").disabled],
  };
}

test("main VM enables CDP only for an explicit valid non-root loopback port", async () => {
  for (const debugPort of [undefined, "", "0", "false", " OFF ", "no", "invalid", "1023", "65536", "9223.5", "9223", " 65535 "]) {
    for (const uid of [1000, 0]) {
      const rig = await desktopVm({ debugPort, uid });
      const debug = rig.switches.filter(([name]) => name.startsWith("remote-debugging-"));
      assert.deepEqual(debug, uid !== 0 && ["9223", " 65535 "].includes(debugPort)
        ? [["remote-debugging-port", debugPort.trim()], ["remote-debugging-address", "127.0.0.1"]] : []);
      assert.equal(rig.children.length, 0);
      assert.equal(rig.loads.length, 1, "the chooser loads even for invalid debug values");
    }
  }
});

test("local IPC and splash wait for discovery, share one attempt and succeed only after verification", async () => {
  const rig = await desktopVm();
  const splash = await splashVm(rig.api);
  let finished = false;
  const first = splash.local().then(() => { finished = true; });
  const second = rig.api.startLocal();
  await tick();
  assert.equal(rig.children.length, 1);
  assert.deepEqual(splash.busy(), [true, true]);
  assert.equal(finished, false);
  rig.announce();
  rig.announce();
  assert.equal(rig.discovery.length, 1, "duplicate READY cannot start a second verifier");
  assert.equal(rig.state().backendReady, null);
  assert.equal(finished, false);
  assert.equal(rig.loads.length, 1);
  rig.resolveDiscovery();
  await first;
  assert.equal((await second).ok, true);
  assert.equal(rig.state().backendReady.connection, "local");
  assert.match(rig.loads.at(-1), /^app:\/\/shell\/index.html/);
  assert.equal(rig.children[0].stdin.ends, 0);
  await assert.rejects(rig.api.startLocal(), /Blocked desktop-runtime:start-local/,
    "the launcher channels are for the chooser only");
  assert.equal(rig.children.length, 1);
  rig.window.close();
  rig.app.emit("before-quit");
  assert.equal(rig.children[0].stdin.ends, 1, "close is idempotent after success");
});

test("mDNS failure releases splash, cleans only its child and retries despite late events", async () => {
  const rig = await desktopVm();
  const splash = await splashVm(rig.api);
  const first = splash.local();
  await tick();
  const old = rig.children[0];
  rig.announce();
  rig.resolveDiscovery(new Error("fixture timeout"));
  await first;
  assert.deepEqual(splash.busy(), [false, false]);
  assert.match(splash.element("log").textContent, /Could not resolve/);
  assert.equal(old.stdin.ends, 1);
  assert.equal(rig.state().backendProcess, null);
  assert.equal(rig.state().backendAttempt, null);
  assert.equal(rig.state().backendReady, null);
  const retry = splash.local();
  await tick();
  const current = rig.children[1];
  old.emit("error", Object.assign(new Error("late error"), { code: "EPERM" }));
  old.emit("exit", 1, null);
  old.stdout.emit("data", Buffer.from("stale partial output"));
  old.stderr.emit("data", Buffer.from("stale stderr\n"));
  rig.announce(current);
  rig.resolveDiscovery();
  await retry;
  assert.equal(current.stdin.ends, 0);
  assert.equal(rig.state().backendProcess, current);
  assert.equal(rig.errors.length, 1);
  assert.equal(rig.loads.length, 2);
});

test("failed local verification permits a remote connection without touching another session", async () => {
  const rig = await desktopVm();
  const splash = await splashVm(rig.api);
  const first = splash.local();
  await tick(); rig.announce(); rig.resolveDiscovery(new Error("timeout")); await first;
  rig.remoteTransport();
  splash.element("remote-host").value = "sensor.example";
  await splash.remote();
  const child = rig.children[0];
  child.emit("exit", 0, "SIGTERM");
  child.emit("error", new Error("late local error"));
  assert.equal(rig.state().backendReady.connection, "remote");
  assert.equal(rig.state().backendReady.host, "sensor.example");
  assert.equal(rig.state().quitting, false);
  assert.equal(child.stdin.ends, 1);
  rig.window.close();
  assert.equal(child.stdin.ends, 1, "closing a remote session never signals a local process again");
  assert.equal(rig.children.length, 1);
});

test("READY, launch, process and QUIC failures all settle failure and permit a new attempt", async (t) => {
  const cases = [
    ["spawn throws", () => {}, /spawn fixture/, new Error("spawn fixture")],
    ["malformed READY", (rig) => rig.announce(undefined, "{"), /JSON|property/],
    ["bad READY URL", (rig) => rig.announce(undefined, { ...READY, url: "invalid" }), /URL/],
    ["missing mDNS", (rig) => rig.announce(undefined, { ...READY, mdns: undefined }), /did not publish/],
    ["mDNS mismatch", (rig) => { rig.announce(); rig.resolveDiscovery(null, { port: 1 }); }, /different runtime/],
    ["QUIC missing", (rig) => { rig.announce(undefined, { ...READY, http3: false }); rig.resolveDiscovery(); }, /HTTP\/3/],
    ["process error", (rig) => rig.children[0].emit("error", new Error("fixture process error")), /fixture process error/],
    ["early exit", (rig) => rig.children[0].emit("exit", 1, null), /exited/],
    ["cancel authorization", (rig) => rig.children[0].emit("exit", 126, null), /Authorization cancelled/],
  ];
  for (const [name, fail, expected, launchError] of cases) await t.test(name, async () => {
    const rig = await desktopVm({ launchError });
    const first = rig.api.startLocal();
    await tick(); fail(rig);
    const result = await first;
    assert.equal(result.ok, false);
    assert.match(result.error, expected);
    assert.equal(rig.state().backendReady, null);
    assert.equal(rig.state().backendProcess, null);
    const previous = rig.children.at(-1);
    if (previous) assert.equal(previous.stdin.ends, 1);
    const retry = rig.api.startLocal();
    await tick(); rig.announce(); rig.resolveDiscovery();
    assert.equal((await retry).ok, true);
    assert.equal(rig.state().backendProcess, rig.children.at(-1));
  });
});

test("close and shutdown settle pending startup and ignore late discovery success or failure", async () => {
  for (const phase of ["before READY", "during verification"]) {
    for (const close of ["window", "quit", "shutdown"]) {
      for (const lateError of [null, new Error("late discovery failure")]) {
        const rig = await desktopVm();
        const pending = rig.api.startLocal();
        await tick();
        if (phase === "during verification") rig.announce();
        if (close === "window") rig.window.close();
        else if (close === "quit") rig.app.emit("before-quit");
        else await rig.api.shutdown();
        assert.equal((await pending).ok, false);
        if (phase === "during verification") rig.resolveDiscovery(lateError);
        else rig.announce();
        rig.children[0].emit("exit", 0, "SIGTERM");
        rig.app.emit("before-quit");
        await tick();
        assert.equal(rig.children[0].stdin.ends, 1);
        assert.equal(rig.state().backendReady, null);
        assert.equal(rig.state().backendProcess, null);
        assert.equal(rig.errors.length, 0);
        assert.equal(rig.loads.length, 1);
        assert.equal((await rig.api.startLocal()).ok, false);
      }
    }
  }
});

test("verification callbacks and child exit during retry cannot complete the wrong attempt", async () => {
  for (const lateError of [null, new Error("stale discovery")]) {
    const rig = await desktopVm();
    const first = rig.api.startLocal();
    await tick(); rig.announce();
    const previous = rig.children[0];
    previous.emit("error", new Error("first attempt failed"));
    assert.equal((await first).ok, false);
    const retry = rig.api.startLocal();
    await tick();
    rig.resolveDiscovery(lateError, {}, 0);
    previous.emit("exit", 1, null);
    await tick();
    assert.equal(rig.state().backendReady, null);
    assert.equal(rig.state().backendProcess, rig.children[1]);
    rig.announce(); rig.resolveDiscovery();
    assert.equal((await retry).ok, true);
    assert.equal(rig.errors.length, 1);
  }
});

test("splash releases local and remote controls when IPC rejects or returns no verified success", async () => {
  for (const result of [undefined, { accepted: true }, { ok: false, error: "fixture failure" }, new Error("IPC rejected")]) {
    const call = async () => { if (result instanceof Error) throw result; return result; };
    const splash = await splashVm({ startLocal: call, connectRemote: call });
    await splash.local();
    assert.deepEqual(splash.busy(), [false, false]);
    await splash.remote();
    assert.deepEqual(splash.busy(), [false, false]);
    assert.ok(splash.element("log").textContent);
  }
});

test("established local runtime errors and crashes return to the chooser and permit retry", async () => {
  for (const event of ["error", "exit"]) {
    const rig = await desktopVm();
    const first = rig.api.startLocal();
    await tick(); rig.announce(); rig.resolveDiscovery();
    assert.equal((await first).ok, true);
    if (event === "error") rig.children[0].emit("error", new Error("runtime failure"));
    else rig.children[0].emit("exit", 1, null);
    assert.match(rig.loads.at(-1), /splash.html$/);
    assert.equal(rig.state().backendReady, null);
    const retry = rig.api.startLocal();
    await tick(); rig.announce(); rig.resolveDiscovery();
    assert.equal((await retry).ok, true);
    assert.equal(rig.children.length, 2);
  }
});

test("early cleanup tolerates denied signals and its fallback targets only the failed child", async () => {
  const rig = await desktopVm();
  const first = rig.api.startLocal();
  await tick();
  const old = rig.children[0];
  old.stdout.emit("data", Buffer.from("partial old output"));
  old.kill = (signal) => { old.signals.push(signal); throw Object.assign(new Error("denied"), { code: "EPERM" }); };
  old.emit("error", new Error("failed before READY"));
  assert.equal((await first).ok, false);
  const retry = rig.api.startLocal();
  await tick();
  const current = rig.children[1];
  for (const { callback } of rig.timers) callback();
  assert.deepEqual(old.signals, ["SIGINT", "SIGTERM"]);
  assert.deepEqual(current.signals, []);
  old.stdin.emit("error", new Error("closed pipe"));
  assert.equal(old.stdin.ends, 1);
  rig.announce(); rig.resolveDiscovery();
  assert.equal((await retry).ok, true, "partial lines from an old attempt cannot corrupt READY");
  old.emit("exit", 0, "SIGTERM");
  assert.equal(rig.state().backendProcess, current);
});

// Window hardening (#276, #277, #278) on the real main.js.
const menuItem = (rig, label) => rig.menus.at(-1).flatMap((menu) => menu.submenu).find((item) => item.label === label);
const navigateEvent = () => ({ prevented: false, preventDefault() { this.prevented = true; } });

test("will-navigate keeps the window on the chooser or the shell before and after connecting", async () => {
  const rig = await desktopVm();
  const check = (url) => { const event = navigateEvent(); rig.window.webContents.emit("will-navigate", event, url); return event.prevented; };
  for (const phase of ["before", "after"]) {
    if (phase === "after") {
      const started = rig.api.startLocal();
      await tick(); rig.announce(); rig.resolveDiscovery();
      assert.equal((await started).ok, true);
    }
    assert.equal(check("file:///tmp/x.html"), true, `${phase}: a dropped or local file is blocked`);
    assert.equal(check("file:///fixture/desktop/other.html"), true, phase);
    assert.equal(check("data:text/html,x"), true, phase);
    assert.equal(check("https://sensor.example/"), true, phase);
    assert.equal(check("file:///fixture/desktop/splash.html"), false, phase);
    assert.equal(check("app://shell/index.html#/"), false, phase);
  }
  assert.deepEqual(rig.opened, ["https://sensor.example/", "https://sensor.example/"], "web links go to the browser");
});

test("IPC from an unexpected document or frame is refused before any handler runs", async () => {
  const rig = await desktopVm();
  const call = (channel, frame, ...args) => Promise.resolve().then(() => rig.handlers.get(channel)({
    sender: rig.window.webContents, senderFrame: frame }, ...args));
  const local = { url: "file:///tmp/x.html", parent: null };
  for (const channel of rig.handlers.keys()) {
    await assert.rejects(call(channel, local), /Blocked .* from an unexpected frame/, channel);
    await assert.rejects(call(channel, null), /unexpected frame/, channel);
    await assert.rejects(call(channel, { url: "app://shell/index.html", parent: {} }), /unexpected frame/, channel);
  }
  // The data bridge belongs to the shell, the launcher to the chooser.
  const splash = { url: "file:///fixture/desktop/splash.html", parent: null };
  await assert.rejects(call("desktop-http:request", splash, { url: "https://sensor.example/" }), /unexpected frame/);
  await assert.rejects(call("desktop-shell:open-external", splash, "https://example.com"), /unexpected frame/);
  const shell = { url: "app://shell/index.html#/", parent: null };
  for (const channel of ["desktop-runtime:start-local", "desktop-runtime:connect-remote", "desktop-runtime:get-connection-defaults"]) {
    await assert.rejects(call(channel, shell), /unexpected frame/, channel);
  }
  assert.equal(rig.children.length, 0);
  assert.equal((await call("desktop-runtime:get-connection-defaults", splash)).mode, "local");
});

test("only app://shell is granted notifications; every other permission is denied", async () => {
  const rig = await desktopVm();
  const { request, check } = rig.permissions;
  const contents = (url) => ({ getURL: () => url });
  const ask = (permission, url) => new Promise((resolve) => request(contents(url), permission, resolve, { requestingUrl: url }));
  assert.equal(await ask("notifications", "app://shell/index.html#/"), true);
  assert.equal(await ask("notifications", "file:///fixture/desktop/splash.html"), false);
  assert.equal(await ask("media", "app://shell/index.html"), false);
  assert.equal(await new Promise((resolve) => request(contents("app://shell/index.html"), "notifications", resolve)), true,
    "without details the webContents URL decides");
  assert.equal(check(null, "notifications", "app://shell", {}), true);
  for (const [permission, origin] of [["geolocation", "app://shell"], ["notifications", "file://"], ["notifications", "https://sensor.example"]]) {
    assert.equal(check(null, permission, origin, {}), false, `${permission} ${origin}`);
  }
});

test("menu shortcuts route a loaded shell over IPC and load the shell only when it is not showing", async () => {
  const rig = await desktopVm();
  const started = rig.api.startLocal();
  await tick(); rig.announce(); rig.resolveDiscovery();
  assert.equal((await started).ok, true);
  const loads = rig.loads.length;
  menuItem(rig, "SOC").click();
  menuItem(rig, "Settings").click();
  assert.equal(rig.loads.length, loads, "no document reload");
  assert.deepEqual(rig.sent.filter(([channel]) => channel === "desktop-menu:navigate"), [
    ["desktop-menu:navigate", "/soc"], ["desktop-menu:navigate", "/settings"]]);
  rig.window.webContents.isLoadingMainFrame = () => true;
  menuItem(rig, "Honeypot").click();
  assert.match(rig.loads.at(-1), /^app:\/\/shell\/index\.html\?.*#\/honeypot$/, "a shell still loading is reloaded at the route");
});
