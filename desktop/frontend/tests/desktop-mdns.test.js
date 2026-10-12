import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);
const { verifyLocalService, validHostname } = require("../../lib/mdns.js");
const quic = require("../../lib/quic-pin.js");
const PIN = "PtGaAFE++hsNTMeOxy/QtCcO3L4uuhVZlp0LARdEbiQ=";
const prepared = { host: "127.0.0.1", address: "127.0.0.1", mdnsHost: "runtime-test.local", port: 45678, spki: PIN };
const announcement = {
  enabled: true,
  service_name: "Sniff4Hound runtime 45678-1._sniff4hound._tcp.local.",
  service_type: "_sniff4hound._tcp.local.",
  hostname: prepared.mdnsHost,
  port: prepared.port,
  addresses: [prepared.address],
};
const ready = { host: prepared.mdnsHost, port: prepared.port, protocol: "https", mdns: announcement };

function verify(found = {}, overrides = {}) {
  return verifyLocalService({
    execFile: (_command, _args, _options, callback) => callback(null, JSON.stringify({ ...announcement, role: "runtime", scheme: "https", ...found })),
    python: "/venv/bin/python", cwd: "/repo", env: {}, ready, prepared, ...overrides,
  });
}

test("only a valid local name can enter Chromium resolver rules", () => {
  assert.equal(validHostname("runtime-test.local"), true);
  for (const host of ["runtime.example", "bad.local, MAP * attacker", "bad.local\n", "*.local"]) {
    assert.equal(validHostname(host), false);
    assert.deepEqual(quic.resolverSwitches({ ...prepared, mdnsHost: host }), []);
  }
});

test("the local mDNS origin retains QUIC and maps only its own bound address", () => {
  assert.deepEqual(quic.quicSwitches({ prepared, env: {} }), [
    ["ignore-certificate-errors-spki-list", PIN], ["origin-to-force-quic-on", "runtime-test.local:45678"],
  ]);
  assert.deepEqual(quic.resolverSwitches(prepared), [["host-resolver-rules", "MAP runtime-test.local 127.0.0.1"]]);
  assert.deepEqual(quic.resolverSwitches({ ...prepared, address: "::1" }), [["host-resolver-rules", "MAP runtime-test.local [::1]"]]);
  assert.deepEqual(quic.quicSwitches({ prepared, env: { SNIFF4HOUND_DESKTOP_HTTP3: "0" } }), []);
  assert.equal(quic.resolverSwitches(prepared).length, 1, "mDNS also works with HTTP/3 explicitly disabled");
});

test("the prepared runtime retains its mDNS hostname and selected interface", () => {
  const output = JSON.stringify({ host: "127.0.0.1", port: 45678, mdns_host: prepared.mdnsHost,
    connect_address: prepared.address, server_spki_sha256: PIN });
  assert.deepEqual(quic.prepareRuntime({ execFileSync: () => output, python: "python", env: {}, cwd: "/" }), prepared);
});

test("the exact DNS-SD endpoint must resolve before connecting", async () => {
  await verify();
  for (const changed of [{ hostname: "other.local" }, { addresses: ["192.0.2.10"] }, { port: 1 },
    { role: "stream" }, { scheme: "http" }, { service_name: "other._sniff4hound._tcp.local." }]) {
    await assert.rejects(verify(changed), /different runtime endpoint/);
  }
});

test("service discovery receives only public metadata on its command line", async () => {
  let seen;
  await verify({}, {
    env: { SNIFF4HOUND_JWT_SECRET: "secret-value" },
    execFile: (command, args, options, callback) => {
      seen = { command, args, options };
      callback(null, JSON.stringify({ ...announcement, role: "runtime", scheme: "https" }));
    },
  });
  assert.equal(seen.command, "/venv/bin/python");
  assert.deepEqual(seen.args, ["-m", "sniff4hound.mdns", "--service", announcement.service_name, "--address", "127.0.0.1", "--timeout", "3"]);
  assert.ok(seen.options.timeout > 0);
  assert.doesNotMatch(seen.args.join(" "), /JWT_SECRET|secret-value/);
});

test("discovery failure cannot fall back silently to an IP origin", async () => {
  await assert.rejects(verify({}, { ready: { ...ready, mdns: undefined } }), /did not publish/);
  await assert.rejects(verify({}, { execFile: (_cmd, _args, _opts, done) => done(new Error("timeout")) }), /Could not resolve/);
  await assert.rejects(verify({}, { ready: { ...ready, host: "127.0.0.1" } }), /differs/);
  await verify({}, { ready: { host: "127.0.0.1" }, prepared: null });
});

test("a named forced QUIC origin detects a missing UDP listener", () => {
  assert.equal(quic.forcedOriginIsUnserved("runtime-test.local:45678", { ...ready, http3: false }), true);
});
