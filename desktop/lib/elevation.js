"use strict";

// Relaunching the desktop shell as root.
//
// The whole app - this Electron process, the web server and the packet
// capture it starts - runs as one privileged tree. Electron cannot raise its
// own privileges, so an unprivileged launch hands over to a root copy of
// itself through sudo (graphical askpass when there is no terminal) or pkexec,
// and waits for it. The root copy then starts the Python runtime, which sees
// it is already root and does not ask again.
//
// Everything in here is a plain function of its inputs (environment, uid,
// lookups) so the command that gets built can be checked without ever
// elevating anything.

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

// Set on the root copy so a launch that somehow still is not root cannot loop.
const ELEVATED_MARKER = "SNIFF4HOUND_DESKTOP_ELEVATED";
// SNIFF4HOUND_DESKTOP_ELEVATE=0 keeps the old shape: an unprivileged shell
// whose backend asks for privileges on its own.
const OPT_OUT = "SNIFF4HOUND_DESKTOP_ELEVATE";
const OFF_VALUES = new Set(["0", "false", "off", "no"]);

// What the root copy needs to put a window on the operator's screen and to
// find the same configuration and data. sudo and pkexec both reset the
// environment, so each of these is forwarded by name, as `env KEY=VALUE`.
const FORWARDED = [
  "DISPLAY",
  "XAUTHORITY",
  "WAYLAND_DISPLAY",
  "XDG_RUNTIME_DIR",
  "XDG_SESSION_TYPE",
  "XDG_CURRENT_DESKTOP",
  "XDG_CONFIG_HOME",
  "XDG_DATA_HOME",
  "XDG_CACHE_HOME",
  "DBUS_SESSION_BUS_ADDRESS",
  "ELECTRON_OZONE_PLATFORM_HINT",
  "HOME",
  "PATH",
  "LANG",
  "LANGUAGE",
  "VIRTUAL_ENV",
  "PYTHONPATH",
];
const FORWARDED_PREFIXES = ["LC_", "SNIFF4HOUND_"];
// Everything on a command line is readable by every local user through
// /proc/<pid>/cmdline while the process runs, so secrets never travel there.
const NEVER_FORWARDED = new Set(["SNIFF4HOUND_IPC_TOKEN", "SNIFF4HOUND_JWT_SECRET"]);

// sudo, pkexec and the askpass helper are looked up in the system directories
// before $PATH: a program of that name earlier on the operator's own PATH would
// otherwise get to ask for (and keep) their password.
const SYSTEM_DIRS = ["/usr/bin", "/bin", "/usr/local/bin", "/usr/sbin", "/sbin"];

function findExecutable(name, pathVar = process.env.PATH || "") {
  for (const dir of [...SYSTEM_DIRS, ...String(pathVar).split(path.delimiter)]) {
    if (!dir) continue;
    const candidate = path.join(dir, name);
    try {
      fs.accessSync(candidate, fs.constants.X_OK);
      if (fs.statSync(candidate).isFile()) return candidate;
    } catch {
      // not here
    }
  }
  return null;
}

function optedOut(env) {
  return OFF_VALUES.has(String(env[OPT_OUT] ?? "").trim().toLowerCase());
}

/** Whether this launch should hand over to a root copy of itself. */
function shouldElevate({ platform, euid, env }) {
  if (platform !== "linux") return false;
  if (typeof euid !== "number" || euid === 0) return false;
  if (optedOut(env)) return false;
  return !String(env[ELEVATED_MARKER] ?? "").trim();
}

/** The `KEY=VALUE` arguments for `env`, for the root copy. */
function forwardedAssignments({ env, uid, gid, home }) {
  const out = [];
  for (const key of Object.keys(env).sort()) {
    const listed = FORWARDED.includes(key) || FORWARDED_PREFIXES.some((prefix) => key.startsWith(prefix));
    if (!listed || NEVER_FORWARDED.has(key)) continue;
    const value = env[key];
    // A newline or NUL would split or truncate the assignment.
    if (typeof value !== "string" || /[\0\n\r]/.test(value)) continue;
    out.push(`${key}=${value}`);
  }
  // Both tools reset HOME to root's; without the operator's the root copy
  // would start with an empty configuration and a fresh database under /root.
  if (!out.some((item) => item.startsWith("HOME=")) && home) out.push(`HOME=${home}`);
  // Read by the Python runtime to hand files it creates back to the operator.
  out.push(`SNIFF4HOUND_INVOKING_UID=${uid}`);
  out.push(`SNIFF4HOUND_INVOKING_GID=${gid}`);
  out.push(`${ELEVATED_MARKER}=1`);
  return out;
}

/**
 * The command that starts the root copy, or null when this machine has no way
 * to elevate (the caller then stays unprivileged and the backend asks).
 *
 * `target` is what to run: the Electron binary, or the AppImage file itself
 * (an AppImage's own mount is a FUSE mount root cannot enter).
 * `--no-sandbox` has to be on the real command line: Chromium refuses to start
 * as root without it before any JavaScript has had the chance to add it.
 */
function buildElevationCommand({ target, args, env, uid, gid, home, which, askpass, hasTerminal }) {
  const assignments = forwardedAssignments({ env, uid, gid, home });
  const program = [target, "--no-sandbox", ...args];

  const sudo = which("sudo");
  if (sudo) {
    // Without a terminal sudo cannot read a password, so it needs a graphical
    // askpass. With one, it prompts there (and PAM can use a fingerprint).
    if (hasTerminal) {
      return { command: sudo, args: ["env", ...assignments, ...program], env: {} };
    }
    if (askpass) {
      return { command: sudo, args: ["-A", "env", ...assignments, ...program], env: { SUDO_ASKPASS: askpass } };
    }
  }
  const pkexec = which("pkexec");
  if (pkexec) {
    return { command: pkexec, args: ["env", ...assignments, ...program], env: {} };
  }
  return null;
}

/**
 * A script sudo can call as its askpass helper: zenity ignores positional
 * text, so it is wrapped in a tiny script. Made in a fresh 0700 directory so
 * nobody else can swap the file between its creation and sudo running it.
 */
function createAskpassHelper({ which, tmpdir = os.tmpdir() }) {
  const zenity = which("zenity");
  if (zenity) {
    const dir = fs.mkdtempSync(path.join(tmpdir, "sniff4hound-askpass-"));
    const script = path.join(dir, "askpass.sh");
    const quoted = zenity.replace(/'/g, `'\\''`);
    fs.writeFileSync(
      script,
      `#!/bin/sh\nexec '${quoted}' --password --title="Sniff4Hound: privilegios necesarios"\n`,
      { mode: 0o700 },
    );
    return { path: script, dir };
  }
  const sshAskpass = which("ssh-askpass");
  return sshAskpass ? { path: sshAskpass, dir: null } : null;
}

/** Whether sudo itself (not the app) refused: a cancelled or wrong password. */
function looksLikeRefusedElevation(code, stderrText) {
  if (code === 126 || code === 127) return true; // pkexec: dismissed / not authorized
  return code !== 0 && /^sudo: .*(password|authentication|sudoers|not allowed)/im.test(stderrText || "");
}

/**
 * The unprivileged side: starts the root copy and waits for it. Returns false
 * when this launch should simply carry on as it is (already root, opted out,
 * not Linux, or no way to elevate), true when the caller is only a launcher and
 * must not open a window - `exit(code)` is called once the root copy is gone.
 * Every effect is injected so it can be exercised with fakes.
 */
function runElevatedLauncher({ spawn, exit, log, onSignal, env, argv, execPath, platform, euid, uid, gid, home, isTTY, which, tmpdir, stderr = process.stderr }) {
  if (!shouldElevate({ platform, euid, env })) return false;
  const hasTerminal = Boolean(isTTY);
  const askpass = hasTerminal ? null : createAskpassHelper({ which, tmpdir });
  const plan = buildElevationCommand({
    // An AppImage's own mount cannot be entered by root; run the file itself.
    target: env.APPIMAGE || execPath,
    args: argv.slice(1).filter((arg) => arg !== "--no-sandbox"),
    env,
    uid,
    gid,
    home,
    which,
    askpass: askpass && askpass.path,
    hasTerminal,
  });
  const cleanup = () => {
    if (askpass && askpass.dir) fs.rmSync(askpass.dir, { recursive: true, force: true });
  };
  if (!plan) {
    cleanup();
    log(
      "[!] No way to ask for privileges (sudo with a terminal or zenity/ssh-askpass, or pkexec); " +
        "starting unprivileged - the backend will ask for them itself.",
    );
    return false;
  }

  const child = spawn(plan.command, plan.args, {
    env: { ...env, ...plan.env },
    stdio: ["inherit", "inherit", "pipe"],
  });
  let stderrTail = "";
  child.stderr.on("data", (chunk) => {
    stderr.write(chunk);
    stderrTail = (stderrTail + chunk.toString("utf8")).slice(-4000);
  });
  // sudo relays these to the root copy instead of leaving it running.
  for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) onSignal(signal, () => child.kill(signal));
  child.on("error", (error) => {
    cleanup();
    log(`[!] Could not start the privileged app: ${error.message}`);
    exit(1);
  });
  child.on("exit", (code, signal) => {
    cleanup();
    if (looksLikeRefusedElevation(code, stderrTail)) {
      // Cancelling the prompt means the action simply does not happen, as with
      // any other elevation prompt - no error dialog left on screen.
      log("[i] Privileges were not granted; Sniff4Hound needs them to capture traffic and exits.");
    }
    exit(code ?? (signal ? 1 : 0));
  });
  return true;
}

/**
 * The root copy writes the configuration directory as root; hand it back to the
 * operator so an unprivileged launch (SNIFF4HOUND_DESKTOP_ELEVATE=0) can still
 * read and write it. Best effort: an entry that cannot be changed is skipped.
 */
function chownTree(root, uid, gid) {
  let changed = 0;
  const visit = (target) => {
    let stat;
    try {
      stat = fs.lstatSync(target);
    } catch {
      return;
    }
    if (stat.uid !== uid || stat.gid !== gid) {
      try {
        fs.lchownSync(target, uid, gid);
        changed += 1;
      } catch {
        // not ours to change, or gone meanwhile
      }
    }
    if (!stat.isDirectory()) return;
    let names = [];
    try {
      names = fs.readdirSync(target);
    } catch {
      return;
    }
    for (const name of names) visit(path.join(target, name));
  };
  visit(root);
  return changed;
}

module.exports = {
  ELEVATED_MARKER,
  OPT_OUT,
  buildElevationCommand,
  chownTree,
  createAskpassHelper,
  findExecutable,
  forwardedAssignments,
  looksLikeRefusedElevation,
  runElevatedLauncher,
  shouldElevate,
};
