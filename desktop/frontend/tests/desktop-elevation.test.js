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
    target: "/opt/s4h/electron",
    args: ["."],
    env: BASE_ENV,
    uid: 1000,
    gid: 1000,
    home: "/home/op",
    which: which({ sudo: "/usr/bin/sudo", pkexec: "/usr/bin/pkexec" }),
    askpass: "/tmp/askpass.sh",
    hasTerminal: false,
    ...overrides,
  });

test("only an unprivileged Linux launch hands over to a root copy", () => {
  const ok = { platform: "linux", euid: 1000, env: {} };
  assert.equal(elevation.shouldElevate(ok), true);
  assert.equal(elevation.shouldElevate({ ...ok, euid: 0 }), false, "already root");
  assert.equal(elevation.shouldElevate({ ...ok, platform: "darwin" }), false);
  assert.equal(elevation.shouldElevate({ ...ok, platform: "win32", euid: 0 }), false);
});

test("the opt-out and the marker both stop a relaunch", () => {
  const launch = (env) => elevation.shouldElevate({ platform: "linux", euid: 1000, env });
  for (const off of ["0", "false", "off", "no", " OFF "]) {
    assert.equal(launch({ SNIFF4HOUND_DESKTOP_ELEVATE: off }), false, off);
  }
  assert.equal(launch({ SNIFF4HOUND_DESKTOP_ELEVATE: "1" }), true);
  assert.equal(launch({ SNIFF4HOUND_DESKTOP_ELEVATED: "1" }), false, "a root copy that is not root must not loop");
});

test("the root copy gets the display, the operator's HOME and the runtime settings", () => {
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
    "SNIFF4HOUND_DESKTOP_ELEVATED=1",
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

test("a value with a newline or NUL cannot split the assignment", () => {
  const assignments = elevation.forwardedAssignments({
    env: { DISPLAY: ":0\nSNIFF4HOUND_X=1", LANG: "a\0b", PATH: "/usr/bin" },
    uid: 1,
    gid: 1,
    home: "/h",
  });
  assert.ok(!assignments.some((item) => item.startsWith("DISPLAY=") || item.startsWith("LANG=")));
  assert.ok(assignments.includes("PATH=/usr/bin"));
});

test("without a terminal sudo runs with the graphical askpass", () => {
  const plan = build();
  assert.equal(plan.command, "/usr/bin/sudo");
  assert.equal(plan.args[0], "-A");
  assert.equal(plan.args[1], "env");
  assert.deepEqual(plan.env, { SUDO_ASKPASS: "/tmp/askpass.sh" });
});

test("with a terminal sudo prompts there, without -A", () => {
  const plan = build({ hasTerminal: true, askpass: null });
  assert.equal(plan.command, "/usr/bin/sudo");
  assert.equal(plan.args[0], "env");
  assert.ok(!plan.args.includes("-A"));
});

test("the program is the target with --no-sandbox on the real command line", () => {
  const { args } = build({ args: [".", "--inspect=0"] });
  const at = args.indexOf("/opt/s4h/electron");
  assert.deepEqual(args.slice(at), ["/opt/s4h/electron", "--no-sandbox", ".", "--inspect=0"]);
  // every environment assignment comes before the program
  assert.ok(args.slice(0, at).every((item) => item === "-A" || item === "env" || /^[A-Z_0-9]+=/.test(item)));
});

test("pkexec is the fallback when sudo cannot prompt", () => {
  const plan = build({ which: which({ sudo: "/usr/bin/sudo", pkexec: "/usr/bin/pkexec" }), askpass: null });
  assert.equal(plan.command, "/usr/bin/pkexec");
  assert.equal(plan.args[0], "env");
});

test("no sudo and no pkexec means no way to elevate", () => {
  assert.equal(build({ which: which({}) }), null);
  assert.equal(build({ which: which({ sudo: "/usr/bin/sudo" }), askpass: null }), null);
});

test("a cancelled prompt is told apart from a crash", () => {
  assert.equal(elevation.looksLikeRefusedElevation(126, ""), true, "pkexec: dismissed");
  assert.equal(elevation.looksLikeRefusedElevation(127, ""), true, "pkexec: not authorized");
  assert.equal(elevation.looksLikeRefusedElevation(1, "sudo: no password was provided\n"), true);
  assert.equal(elevation.looksLikeRefusedElevation(1, "sudo: 3 incorrect password attempts\n"), true);
  assert.equal(elevation.looksLikeRefusedElevation(1, "sudo: unable to resolve host box\nsegfault"), false);
  assert.equal(elevation.looksLikeRefusedElevation(0, "sudo: a password is required"), false, "a clean exit is never a refusal");
  assert.equal(elevation.looksLikeRefusedElevation(1, "Gtk-WARNING"), false);
});

test("the askpass helper is a private script that calls zenity, or ssh-askpass as is", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "s4h-askpass-test-"));
  try {
    const helper = elevation.createAskpassHelper({ which: which({ zenity: "/usr/bin/zenity" }), tmpdir: tmp });
    assert.equal(path.dirname(helper.path), helper.dir);
    assert.equal(fs.statSync(helper.dir).mode & 0o077, 0, "directory must be private");
    assert.equal(fs.statSync(helper.path).mode & 0o777, 0o700);
    assert.match(fs.readFileSync(helper.path, "utf8"), /exec '\/usr\/bin\/zenity' --password/);

    const ssh = elevation.createAskpassHelper({ which: which({ "ssh-askpass": "/usr/bin/ssh-askpass" }), tmpdir: tmp });
    assert.deepEqual(ssh, { path: "/usr/bin/ssh-askpass", dir: null });
    assert.equal(elevation.createAskpassHelper({ which: which({}), tmpdir: tmp }), null);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("a zenity path with a quote cannot break out of the script", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "s4h-askpass-test-"));
  try {
    const helper = elevation.createAskpassHelper({ which: which({ zenity: "/opt/it's/zenity" }), tmpdir: tmp });
    assert.match(fs.readFileSync(helper.path, "utf8"), /exec '\/opt\/it'\\''s\/zenity' --password/);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
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

// --- the launcher around a fake spawn --------------------------------------

function launcherRig(overrides = {}) {
  const calls = { spawn: [], exit: [], log: [], signals: new Map(), kills: [], stderr: [] };
  const child = Object.assign(new EventEmitter(), { stderr: new EventEmitter(), kill: (sig) => calls.kills.push(sig) });
  const options = {
    spawn: (command, args, opts) => {
      calls.spawn.push({ command, args, opts });
      return child;
    },
    exit: (code) => calls.exit.push(code),
    log: (line) => calls.log.push(line),
    onSignal: (signal, handler) => calls.signals.set(signal, handler),
    stderr: { write: (chunk) => calls.stderr.push(String(chunk)) },
    env: { ...BASE_ENV },
    argv: ["/opt/s4h/electron", "."],
    execPath: "/opt/s4h/electron",
    platform: "linux",
    euid: 1000,
    uid: 1000,
    gid: 1000,
    home: "/home/op",
    isTTY: true,
    which: which({ sudo: "/usr/bin/sudo" }),
    ...overrides,
  };
  return { calls, child, run: () => elevation.runElevatedLauncher(options) };
}

test("the launcher starts the root copy and exits with its code", () => {
  const { calls, child, run } = launcherRig();
  assert.equal(run(), true, "this process is only a launcher");
  assert.equal(calls.spawn.length, 1);
  assert.equal(calls.spawn[0].command, "/usr/bin/sudo");
  assert.deepEqual(calls.spawn[0].opts.stdio, ["inherit", "inherit", "pipe"]);
  assert.deepEqual(calls.exit, [], "it waits for the root copy");

  child.emit("exit", 0, null);
  assert.deepEqual(calls.exit, [0]);
});

test("the root copy's exit code, or a signal, is passed on", () => {
  const first = launcherRig();
  first.run();
  first.child.emit("exit", 3, null);
  assert.deepEqual(first.calls.exit, [3]);

  const second = launcherRig();
  second.run();
  second.child.emit("exit", null, "SIGKILL");
  assert.deepEqual(second.calls.exit, [1]);
});

test("stopping the launcher stops the root copy through sudo", () => {
  const { calls, run } = launcherRig();
  run();
  assert.deepEqual([...calls.signals.keys()].sort(), ["SIGHUP", "SIGINT", "SIGTERM"]);
  calls.signals.get("SIGTERM")();
  calls.signals.get("SIGINT")();
  assert.deepEqual(calls.kills, ["SIGTERM", "SIGINT"]);
});

test("a cancelled prompt exits quietly with an explanation, not an error", () => {
  const { calls, child, run } = launcherRig();
  run();
  child.stderr.emit("data", Buffer.from("sudo: no password was provided\n"));
  child.emit("exit", 1, null);
  assert.deepEqual(calls.exit, [1]);
  assert.equal(calls.log.length, 1);
  assert.match(calls.log[0], /Privileges were not granted/);
  assert.deepEqual(calls.stderr, ["sudo: no password was provided\n"], "sudo's own message still reaches the terminal");
});

test("a crash of the root copy is not reported as a refusal", () => {
  const { calls, child, run } = launcherRig();
  run();
  child.stderr.emit("data", Buffer.from("Segmentation fault\n"));
  child.emit("exit", 139, null);
  assert.deepEqual(calls.exit, [139]);
  assert.deepEqual(calls.log, []);
});

test("a program that cannot be started ends the launcher", () => {
  const { calls, child, run } = launcherRig();
  run();
  child.emit("error", new Error("spawn sudo ENOENT"));
  assert.deepEqual(calls.exit, [1]);
  assert.match(calls.log[0], /Could not start the privileged app: spawn sudo ENOENT/);
});

test("nothing is started when already root, opted out, or on another OS", () => {
  for (const overrides of [
    { euid: 0 },
    { platform: "darwin" },
    { env: { ...BASE_ENV, SNIFF4HOUND_DESKTOP_ELEVATE: "0" } },
    { env: { ...BASE_ENV, SNIFF4HOUND_DESKTOP_ELEVATED: "1" } },
  ]) {
    const { calls, run } = launcherRig(overrides);
    assert.equal(run(), false);
    assert.deepEqual(calls.spawn, []);
  }
});

test("with no way to elevate the launch goes on unprivileged and says why", () => {
  const { calls, run } = launcherRig({ which: which({}) });
  assert.equal(run(), false);
  assert.deepEqual(calls.spawn, []);
  assert.match(calls.log[0], /No way to ask for privileges/);
});

test("an AppImage is relaunched by its file, not by its mount", () => {
  const { calls, run } = launcherRig({ env: { ...BASE_ENV, APPIMAGE: "/home/op/Sniff4Hound.AppImage" } });
  run();
  const { args } = calls.spawn[0];
  assert.deepEqual(args.slice(args.indexOf("/home/op/Sniff4Hound.AppImage")), [
    "/home/op/Sniff4Hound.AppImage",
    "--no-sandbox",
    ".",
  ]);
  assert.ok(!args.includes("/opt/s4h/electron"));
});

test("a launcher without a terminal cleans up its askpass helper when the root copy ends", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "s4h-launcher-test-"));
  try {
    const { calls, child, run } = launcherRig({
      isTTY: false,
      tmpdir: tmp,
      which: which({ sudo: "/usr/bin/sudo", zenity: "/usr/bin/zenity" }),
    });
    run();
    assert.equal(calls.spawn[0].args[0], "-A");
    const askpass = calls.spawn[0].opts.env.SUDO_ASKPASS;
    assert.ok(fs.existsSync(askpass), "the helper exists while sudo may call it");
    child.emit("exit", 0, null);
    assert.equal(fs.existsSync(askpass), false);
    assert.equal(fs.existsSync(path.dirname(askpass)), false);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
