"use strict";

// HTTP/3 for the local runtime.
//
// Chromium only speaks HTTP/3 to a server whose certificate it trusts, and it
// has no way to be told afterwards: its trust and QUIC switches are read once,
// at launch. So before the shell starts Chromium it asks the Python runtime for
// two facts (sniff4hound/desktop_prepare.py): the port the runtime is going to
// listen on, free on TCP and UDP, and the public-key hash of its persistent CA.
//
// With those, Chromium is told to
//   - trust that one public key (--ignore-certificate-errors-spki-list), which
//     the runtime's server certificate chains to, and
//   - use QUIC for that one origin (--origin-to-force-quic-on): browsers learn
//     about HTTP/3 from an Alt-Svc header, but never act on one for an IP
//     address, and the runtime is addressed as 127.0.0.1.
//
// Plain functions of their inputs, so the switches can be checked without
// starting anything.

const OFF_VALUES = new Set(["0", "false", "off", "no"]);
const SPKI_RE = /^[A-Za-z0-9+/]{43}=$/;
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "::1", "localhost"]);

function http3Disabled(env) {
  return OFF_VALUES.has(String(env.SNIFF4HOUND_DESKTOP_HTTP3 ?? "").trim().toLowerCase());
}

function tlsDisabled(env) {
  return OFF_VALUES.has(String(env.SNIFF4HOUND_TLS ?? "").trim().toLowerCase());
}

/** Ask the runtime what it is going to use. Null when it cannot say. */
function prepareRuntime({ execFileSync, python, env, cwd, timeoutMs = 10000 }) {
  let output = "";
  try {
    output = execFileSync(python, ["-m", "sniff4hound.desktop_prepare"], {
      env,
      cwd,
      timeout: timeoutMs,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    });
  } catch {
    return null;
  }
  const line = String(output).trim().split("\n").pop();
  let parsed;
  try {
    parsed = JSON.parse(line);
  } catch {
    return null;
  }
  const port = Number(parsed && parsed.port);
  const host = String((parsed && parsed.host) || "");
  const spki = String((parsed && parsed.server_spki_sha256) || "");
  if (!Number.isInteger(port) || port < 1 || port > 65535 || !host) return null;
  return { host, port, spki: SPKI_RE.test(spki) ? spki : "" };
}

/** `host:port` as Chromium writes an origin in --origin-to-force-quic-on. */
function originForQuic(host, port) {
  return host.includes(":") ? `[${host}]:${port}` : `${host}:${port}`;
}

/**
 * The [switch, value] pairs that turn on HTTP/3 to the local runtime, or []
 * when it should not be: opted out, TLS off, no CA yet, or a runtime that is
 * not on this machine's loopback (a remote sensor keeps going over TCP).
 */
function quicSwitches({ prepared, env }) {
  if (!prepared || !prepared.spki) return [];
  if (http3Disabled(env) || tlsDisabled(env)) return [];
  if (!LOOPBACK_HOSTS.has(prepared.host)) return [];
  const host = prepared.host === "localhost" ? "127.0.0.1" : prepared.host;
  return [
    ["ignore-certificate-errors-spki-list", prepared.spki],
    ["origin-to-force-quic-on", originForQuic(host, prepared.port)],
  ];
}

/**
 * True when Chromium was told to reach `forcedOrigin` ("host:port") over QUIC
 * and the runtime that just announced itself, at that address, says it has no
 * HTTP/3 listener.
 */
function forcedOriginIsUnserved(forcedOrigin, ready) {
  if (!forcedOrigin || !ready) return false;
  const announced = originForQuic(String(ready.host || ""), Number(ready.port));
  return announced === forcedOrigin && ready.http3 === false;
}

module.exports = { forcedOriginIsUnserved, http3Disabled, originForQuic, prepareRuntime, quicSwitches };
