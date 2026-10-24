import assert from "node:assert/strict";
import { createRequire } from "node:module";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { EventEmitter } from "node:events";
import test from "node:test";

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
