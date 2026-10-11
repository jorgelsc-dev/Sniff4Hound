import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

// The desktop shell's CommonJS helper that decides the Chromium switches for
// HTTP/3 to the local runtime. Nothing here starts a process or Chromium.
const require = createRequire(import.meta.url);
const quic = require("../../lib/quic-pin.js");

const PIN = "PtGaAFE++hsNTMeOxy/QtCcO3L4uuhVZlp0LARdEbiQ=";
const prepared = { host: "127.0.0.1", port: 45678, spki: PIN };
const run = (output) =>
  quic.prepareRuntime({ execFileSync: () => output, python: "python3", env: {}, cwd: "/", timeoutMs: 1 });

test("the runtime's answer becomes the port and the pin", () => {
  const out = JSON.stringify({ host: "127.0.0.1", port: 45671, server_spki_sha256: PIN, ca_created: true });
  assert.deepEqual(run(`${out}\n`), { host: "127.0.0.1", port: 45671, spki: PIN });
});

test("only the last line counts, so a stray warning before it does not matter", () => {
  const out = JSON.stringify({ host: "127.0.0.1", port: 45678, server_spki_sha256: PIN });
  assert.equal(run(`DeprecationWarning: something\n${out}\n`).port, 45678);
});

test("a pin that is not a SHA-256 in base64 is dropped, the port is kept", () => {
  const out = JSON.stringify({ host: "127.0.0.1", port: 45678, server_spki_sha256: "not-a-pin" });
  assert.deepEqual(run(out), { host: "127.0.0.1", port: 45678, spki: "" });
});

test("anything unusable gives no answer rather than a wrong one", () => {
  assert.equal(run("not json"), null);
  assert.equal(run(""), null);
  assert.equal(run(JSON.stringify({ host: "127.0.0.1", port: 0 })), null);
  assert.equal(run(JSON.stringify({ host: "127.0.0.1", port: 70000 })), null);
  assert.equal(run(JSON.stringify({ host: "", port: 45678 })), null);
  assert.equal(run(JSON.stringify({ port: "45678.5", host: "127.0.0.1" })), null);
});

test("a runtime that cannot be started gives no answer", () => {
  const throwing = () => {
    throw new Error("ENOENT");
  };
  assert.equal(quic.prepareRuntime({ execFileSync: throwing, python: "x", env: {}, cwd: "/" }), null);
});

test("it asks the runtime's own module, with no terminal and a time limit", () => {
  let seen;
  quic.prepareRuntime({
    execFileSync: (command, args, options) => {
      seen = { command, args, options };
      return "";
    },
    python: "/venv/bin/python3",
    env: { A: "1" },
    cwd: "/repo",
  });
  assert.equal(seen.command, "/venv/bin/python3");
  assert.deepEqual(seen.args, ["-m", "sniff4hound.desktop_prepare"]);
  assert.equal(seen.options.cwd, "/repo");
  assert.deepEqual(seen.options.env, { A: "1" });
  assert.ok(seen.options.timeout > 0);
  assert.equal(seen.options.stdio[0], "ignore");
});

test("HTTP/3 to the local runtime is two switches: trust that key, force QUIC for that origin", () => {
  assert.deepEqual(quic.quicSwitches({ prepared, env: {} }), [
    ["ignore-certificate-errors-spki-list", PIN],
    ["origin-to-force-quic-on", "127.0.0.1:45678"],
  ]);
});

test("no pin, no switches: without a trusted key QUIC would only fail", () => {
  assert.deepEqual(quic.quicSwitches({ prepared: { ...prepared, spki: "" }, env: {} }), []);
  assert.deepEqual(quic.quicSwitches({ prepared: null, env: {} }), []);
});

test("it can be turned off, and is off without TLS", () => {
  for (const off of ["0", "false", "off", "no", " OFF "]) {
    assert.deepEqual(quic.quicSwitches({ prepared, env: { SNIFF4HOUND_DESKTOP_HTTP3: off } }), [], off);
  }
  assert.deepEqual(quic.quicSwitches({ prepared, env: { SNIFF4HOUND_TLS: "0" } }), []);
  assert.equal(quic.quicSwitches({ prepared, env: { SNIFF4HOUND_DESKTOP_HTTP3: "1" } }).length, 2);
});

test("a runtime that is not on loopback keeps going over TCP", () => {
  assert.deepEqual(quic.quicSwitches({ prepared: { ...prepared, host: "192.168.1.9" }, env: {} }), []);
  assert.deepEqual(quic.quicSwitches({ prepared: { ...prepared, host: "sensor.example" }, env: {} }), []);
});

test("localhost is forced as the address it resolves to, and IPv6 is bracketed", () => {
  assert.equal(quic.quicSwitches({ prepared: { ...prepared, host: "localhost" }, env: {} })[1][1], "127.0.0.1:45678");
  assert.equal(quic.originForQuic("::1", 45678), "[::1]:45678");
  assert.equal(quic.originForQuic("127.0.0.1", 1), "127.0.0.1:1");
});

test("only the one origin Chromium was told about is checked for a missing UDP side", () => {
  const forced = "127.0.0.1:45678";
  const ready = (over) => ({ host: "127.0.0.1", port: 45678, http3: false, ...over });
  assert.equal(quic.forcedOriginIsUnserved(forced, ready()), true);
  assert.equal(quic.forcedOriginIsUnserved(forced, ready({ http3: true })), false);
  assert.equal(quic.forcedOriginIsUnserved(forced, ready({ http3: undefined })), false, "an older runtime says nothing");
  assert.equal(quic.forcedOriginIsUnserved(forced, ready({ port: 45672 })), false, "a different port was not forced");
  assert.equal(quic.forcedOriginIsUnserved("", ready()), false, "nothing was forced");
  assert.equal(quic.forcedOriginIsUnserved(forced, null), false);
});
