"use strict";

const fs = require("node:fs");

function processStartTime(pid) {
  try {
    const stat = fs.readFileSync(`/proc/${pid}/stat`, "utf8");
    // Fields after the parenthesized command begin at field 3; starttime is 22.
    return stat.slice(stat.lastIndexOf(")") + 2).trim().split(/\s+/)[19] || null;
  } catch {
    return null;
  }
}

/** Start a session bus owned by the elevated app; return its cleanup or null. */
function startPrivateSessionBus({ platform, euid, env, which, execFileSync, kill, log, getStartTime = processStartTime }) {
  if (platform !== "linux" || euid !== 0) return null;
  const daemon = which("dbus-daemon");
  if (!daemon) return null;

  let pid;
  let startedAt;
  let stopped = false;
  const stop = () => {
    if (stopped || !Number.isInteger(pid) || pid <= 1) return;
    stopped = true;
    // A crashed bus's pid may have been reused during a long capture session.
    if (!startedAt || getStartTime(pid) !== startedAt) return;
    try {
      kill(pid, "SIGTERM");
    } catch {
      // The bus may already have exited.
    }
  };
  try {
    // Unlike wrapping Electron in dbus-run-session, this keeps Electron as
    // sudo's direct child so termination signals still reach the app itself.
    const output = execFileSync(daemon, ["--session", "--fork", "--print-address=1", "--print-pid=1"], {
      env,
      encoding: "utf8",
      timeout: 5000,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const [address, pidText] = output.trim().split(/\r?\n/);
    pid = Number(pidText);
    if (Number.isInteger(pid) && pid > 1) startedAt = getStartTime(pid);
    if (!address.startsWith("unix:") || !Number.isInteger(pid) || pid <= 1) {
      throw new Error("dbus-daemon returned an invalid address or pid");
    }
    if (!startedAt) throw new Error("could not inspect the private session bus process");
    // A user's session bus authenticates that user's uid, not root. Switch
    // only this process tree to the private socket before Chromium is ready.
    env.DBUS_SESSION_BUS_ADDRESS = address;
    for (const key of ["DBUS_SESSION_BUS_PID", "DBUS_SESSION_BUS_WINDOWID", "DBUS_STARTER_ADDRESS", "DBUS_STARTER_BUS_TYPE"]) {
      delete env[key];
    }
    return stop;
  } catch (error) {
    stop();
    log(`[!] Could not start the private desktop session bus: ${error.message}`);
    return null;
  }
}

module.exports = { startPrivateSessionBus };
