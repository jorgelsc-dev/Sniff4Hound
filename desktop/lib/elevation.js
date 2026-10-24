"use strict";

// Graphical elevation for the Python runtime. Electron keeps the operator's
// uid and desktop session; only the server and capture engines run as root.
// Command construction is separate from spawning so no test needs privileges.

const fs = require("node:fs");
const path = require("node:path");

// Skip the automatic startup request; the local-sensor button still authorizes
// the runtime. Retained for existing automation sessions.
const OPT_OUT = "SNIFF4HOUND_DESKTOP_ELEVATE";
const OFF_VALUES = new Set(["0", "false", "off", "no"]);

// Preserve the runtime data/configuration across Polkit's environment reset.
// Settings are forwarded by name as `env KEY=VALUE`.
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

// Resolve pkexec from system directories first so a same-named program on
// the operator's PATH cannot impersonate the system authentication tool.
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

/** The `KEY=VALUE` arguments for `env`, for the root runtime. */
function forwardedAssignments({ env, uid, gid, home }) {
  const launchEnv = { ...env };
  // Xlib's implicit authority lookup can change after switching users. Make
  // the operator's default explicit without changing X11's access controls.
  if (launchEnv.DISPLAY && !launchEnv.XAUTHORITY && home) {
    const authority = path.join(home, ".Xauthority");
    try {
      fs.accessSync(authority, fs.constants.R_OK);
      if (fs.statSync(authority).isFile()) launchEnv.XAUTHORITY = authority;
    } catch {
      // A cookie-less display (for example a test X server) needs no file.
    }
  }
  if (typeof launchEnv.XAUTHORITY === "string" && launchEnv.XAUTHORITY && !/[\0\n\r]/.test(launchEnv.XAUTHORITY)) {
    launchEnv.XAUTHORITY = path.resolve(launchEnv.XAUTHORITY);
  }
  const out = [];
  for (const key of Object.keys(launchEnv).sort()) {
    const listed = FORWARDED.includes(key) || FORWARDED_PREFIXES.some((prefix) => key.startsWith(prefix));
    if (!listed || NEVER_FORWARDED.has(key)) continue;
    const value = launchEnv[key];
    // A newline or NUL would split or truncate the assignment.
    if (typeof value !== "string" || /[\0\n\r]/.test(value)) continue;
    out.push(`${key}=${value}`);
  }
  // Both tools reset HOME to root's; without the operator's the runtime
  // would start with an empty configuration and a fresh database under /root.
  if (!out.some((item) => item.startsWith("HOME=")) && home) out.push(`HOME=${home}`);
  // Read by the Python runtime to hand files it creates back to the operator.
  out.push(`SNIFF4HOUND_INVOKING_UID=${uid}`);
  out.push(`SNIFF4HOUND_INVOKING_GID=${gid}`);
  return out;
}

/** Ask the desktop's native Polkit agent to authorize only the runtime. */
function buildElevationCommand({ target, args, env, uid, gid, home, which }) {
  const pkexec = which("pkexec");
  if (!pkexec) return null;
  return {
    command: pkexec,
    args: ["--disable-internal-agent", "--keep-cwd", "env", ...forwardedAssignments({ env, uid, gid, home }), target, ...args],
  };
}

/** Polkit: 126 means dismissed, 127 means authorization was not obtained. */
function looksLikeRefusedElevation(code) {
  return code === 126 || code === 127;
}

/** Keep stdin as a lifetime pipe; EOF makes the root runtime stop itself. */
function launchRuntime({ spawn, target, args, cwd, env, platform, euid, uid, gid, home, which }) {
  const options = { cwd, env, stdio: ["pipe", "pipe", "pipe"] };
  if (platform !== "linux" || euid === 0) return spawn(target, args, options);
  const plan = buildElevationCommand({ target, args, env, uid, gid, home, which });
  if (!plan) throw new Error("Install pkexec (Polkit) and enable your desktop's authentication agent to authorize the local sensor.");
  return spawn(plan.command, plan.args, options);
}

/**
 * Hand configuration from a manually root-launched shell back to the operator.
 * Best effort: an entry that cannot be changed is skipped.
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
  OPT_OUT,
  buildElevationCommand,
  chownTree,
  findExecutable,
  forwardedAssignments,
  looksLikeRefusedElevation,
  launchRuntime,
  optedOut,
};
