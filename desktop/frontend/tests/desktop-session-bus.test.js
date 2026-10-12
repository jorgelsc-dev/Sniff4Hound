import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);
const { startPrivateSessionBus } = require("../../lib/session-bus.js");

function rig(overrides = {}) {
  const calls = { start: [], kill: [], log: [] };
  const env = {
    DBUS_SESSION_BUS_ADDRESS: "unix:path=/run/user/1000/bus",
    DBUS_SESSION_BUS_PID: "100",
    DISPLAY: ":0",
  };
  const options = {
    platform: "linux",
    euid: 0,
    env,
    which: (name) => name === "dbus-daemon" ? "/usr/bin/dbus-daemon" : null,
    execFileSync: (...args) => {
      calls.start.push(args);
      return "unix:path=/tmp/private-bus,guid=fixture\n200\n";
    },
    kill: (...args) => calls.kill.push(args),
    getStartTime: () => "fixture-start-time",
    log: (line) => calls.log.push(line),
    ...overrides,
  };
  return { calls, env, start: () => startPrivateSessionBus(options) };
}

test("only root on Linux starts a private bus, without changing the operator's session", () => {
  const { calls, env, start } = rig();
  const stop = start();
  assert.equal(typeof stop, "function");
  assert.equal(env.DBUS_SESSION_BUS_ADDRESS, "unix:path=/tmp/private-bus,guid=fixture");
  assert.ok(!("DBUS_SESSION_BUS_PID" in env));
  assert.equal(env.DISPLAY, ":0");
  const [command, args, options] = calls.start[0];
  assert.equal(command, "/usr/bin/dbus-daemon");
  assert.deepEqual(args, ["--session", "--fork", "--print-address=1", "--print-pid=1"]);
  assert.equal(options.timeout, 5000, "startup cannot wait forever on a broken daemon");
  stop();
  stop();
  assert.deepEqual(calls.kill, [[200, "SIGTERM"]], "cleanup kills only this bus, once");
});

test("unprivileged, non-Linux and missing-daemon launches keep their existing session", () => {
  for (const overrides of [{ euid: 1000 }, { platform: "darwin" }, { which: () => null }]) {
    const { calls, env, start } = rig(overrides);
    assert.equal(start(), null);
    assert.deepEqual(calls.start, []);
    assert.deepEqual(calls.kill, []);
    assert.equal(env.DBUS_SESSION_BUS_ADDRESS, "unix:path=/run/user/1000/bus");
  }
});

test("a daemon startup failure leaves the previous address and reports why", () => {
  const { calls, env, start } = rig({ execFileSync: () => { throw new Error("startup timed out"); } });
  assert.equal(start(), null);
  assert.equal(env.DBUS_SESSION_BUS_ADDRESS, "unix:path=/run/user/1000/bus");
  assert.deepEqual(calls.kill, []);
  assert.match(calls.log[0], /startup timed out/);
});

test("an invalid address is rejected and its newly started daemon is stopped", () => {
  const { calls, env, start } = rig({ execFileSync: () => "invalid-address\n201\n" });
  assert.equal(start(), null);
  assert.equal(env.DBUS_SESSION_BUS_ADDRESS, "unix:path=/run/user/1000/bus");
  assert.deepEqual(calls.kill, [[201, "SIGTERM"]]);
});

test("malformed daemon pids never become kill targets", () => {
  for (const pid of ["", "0", "1", "-1", "oops", "2.5"]) {
    const { calls, start } = rig({ execFileSync: () => `unix:path=/tmp/private-bus\n${pid}\n` });
    assert.equal(start(), null);
    assert.deepEqual(calls.kill, []);
  }
});

test("cleanup tolerates a bus that has already exited", () => {
  const { start } = rig({ kill: () => { throw new Error("ESRCH"); } });
  const stop = start();
  assert.doesNotThrow(stop);
});

test("cleanup cannot kill an unrelated process that reused the bus pid", () => {
  let startTime = "original-bus";
  const { calls, start } = rig({ getStartTime: () => startTime });
  const stop = start();
  startTime = "another-process";
  stop();
  assert.deepEqual(calls.kill, []);
});
