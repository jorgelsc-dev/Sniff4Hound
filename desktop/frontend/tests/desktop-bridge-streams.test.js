import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);
const {
  STREAM_PENDING_LIMIT, createPendingEventLimiter, createStreamRegistry, isMainFrameDocumentNavigation, openBridgeStream,
} = require("../../lib/bridge-streams.js");

// A stand-in for Electron's net request/response pair; no network is used.
function fakeRequest() {
  const request = Object.assign(new EventEmitter(), {
    headers: {}, aborted: 0, ended: false,
    setHeader(name, value) { this.headers[name] = value; },
    end() { this.ended = true; },
    abort() { this.aborted += 1; },
  });
  request.respond = (statusCode = 200) => {
    const response = Object.assign(new EventEmitter(), { statusCode });
    request.emit("response", response);
    return response;
  };
  return request;
}

function rig({ limit, registry = createStreamRegistry(), ownerId = 7 } = {}) {
  const requests = [];
  const sent = [];
  const timers = [];
  const open = (id, extra = {}) => openBridgeStream({
    id, ownerId, url: "https://sensor.example/realtime/stream?feed=ips", headers: { Authorization: "Bearer x" },
    registry, limit, send: (message) => sent.push({ id, ...message }),
    createRequest: (options) => { const request = fakeRequest(); request.options = options; requests.push(request); return request; },
    schedule: (callback, delay) => { const timer = { callback, delay, cancelled: false }; timers.push(timer); return timer; },
    cancel: (timer) => { timer.cancelled = true; },
    ...extra,
  });
  return { open, registry, requests, sent, timers };
}

const event = (bytes) => Buffer.from(`data: ${"x".repeat(bytes)}\n\n`);

test("the pending limit counts only bytes after the last complete event", () => {
  const limiter = createPendingEventLimiter(10);
  assert.equal(limiter.push(Buffer.from("data: 1234567890\n\n")), true);
  assert.equal(limiter.pending, 0);
  assert.equal(limiter.push(Buffer.from("data: 12")), true);
  assert.equal(limiter.pending, 8);
  assert.equal(limiter.push(Buffer.from("3")), true);
  assert.equal(limiter.push(Buffer.from("45")), false, "one unterminated event past the limit");
  // A terminator split across chunks (and CRLF / CR forms) is recognised.
  for (const [first, second] of [["data: a\n", "\n"], ["data: a\r\n\r", "\n"], ["data: a\r", "\r"]]) {
    const split = createPendingEventLimiter(10);
    split.push(Buffer.from(first));
    split.push(Buffer.from(second));
    assert.equal(split.pending, 0, JSON.stringify(first + second));
  }
  const tail = createPendingEventLimiter(100);
  tail.push(Buffer.from("data: done\n\ndata: next"));
  assert.equal(tail.pending, "data: next".length);
});

test("a long-lived stream relays far more than the limit in complete events", () => {
  const { open, requests, sent, registry } = rig();
  open("realtime-a-1");
  const response = requests[0].respond();
  const frame = event(64 * 1024);
  const frames = Math.ceil((STREAM_PENDING_LIMIT * 2) / frame.length);
  for (let i = 0; i < frames; i += 1) response.emit("data", frame);
  assert.ok(frames * frame.length > STREAM_PENDING_LIMIT * 2);
  assert.equal(sent.filter((message) => message.type === "data").length, frames);
  assert.equal(sent.some((message) => message.type === "error"), false);
  assert.equal(requests[0].aborted, 0);
  assert.equal(registry.has("realtime-a-1"), true);
});

test("one unterminated event larger than the limit is still cut", () => {
  const { open, requests, sent, registry } = rig({ limit: 1024 });
  open("realtime-a-1");
  const response = requests[0].respond();
  response.emit("data", Buffer.from("data: start"));
  response.emit("data", Buffer.alloc(1024, 120));
  assert.deepEqual(sent.at(-1), { id: "realtime-a-1", type: "error", message: "Stream is too large." });
  assert.equal(requests[0].aborted, 1);
  assert.equal(registry.has("realtime-a-1"), false);
  response.emit("data", event(1));
  response.emit("end");
  assert.equal(sent.at(-1).type, "error", "nothing is relayed after the cut");
});

test("every chunk renews the inactivity timeout and silence closes the stream", () => {
  const { open, requests, sent, timers, registry } = rig();
  open("realtime-a-1");
  assert.equal(requests[0].options.method, "GET");
  assert.equal(requests[0].options.redirect, "error");
  assert.equal(requests[0].headers.Authorization, "Bearer x");
  assert.equal(requests[0].ended, true);
  const response = requests[0].respond();
  response.emit("data", Buffer.from(": heartbeat\n\n"));
  assert.equal(timers.length, 2);
  assert.equal(timers[0].cancelled, true);
  timers[1].callback();
  assert.deepEqual(sent.at(-1), { id: "realtime-a-1", type: "error", message: "Stream timed out." });
  assert.equal(requests[0].aborted, 1);
  assert.equal(registry.size, 0);
});

test("duplicate or empty stream ids are refused", () => {
  const { open } = rig();
  open("realtime-a-1");
  assert.throws(() => open("realtime-a-1"), /Invalid stream id/);
  assert.throws(() => open(""), /Invalid stream id/);
});

test("a reload aborts the previous document's streams, leaving no registry entries", () => {
  const registry = createStreamRegistry();
  const contents = Object.assign(new EventEmitter(), { id: 7 });
  const other = Object.assign(new EventEmitter(), { id: 8 });
  const mine = rig({ registry, ownerId: 7 });
  const theirs = rig({ registry, ownerId: 8 });
  registry.watch(contents);
  registry.watch(other);
  mine.open("realtime-doc1-1");
  mine.open("realtime-doc1-2");
  theirs.open("realtime-docX-1");
  // Same-document (SPA hash route) and subframe navigations keep the streams.
  contents.emit("did-start-navigation", { isMainFrame: true, isSameDocument: true, url: "app://shell/index.html#/soc" });
  contents.emit("did-start-navigation", { isMainFrame: false, isSameDocument: false, url: "about:blank" });
  assert.deepEqual(registry.idsFor(7), ["realtime-doc1-1", "realtime-doc1-2"]);
  // A reload / sensor switch / return to the chooser.
  contents.emit("did-start-navigation", { isMainFrame: true, isSameDocument: false, url: "app://shell/index.html#/" });
  assert.deepEqual(registry.idsFor(7), []);
  assert.deepEqual(mine.requests.map((request) => request.aborted), [1, 1]);
  assert.deepEqual(registry.idsFor(8), ["realtime-docX-1"], "another window's streams are untouched");
  // A late chunk from an aborted stream is not relayed.
  const late = mine.requests[0].respond();
  late.emit("data", event(1));
  assert.equal(mine.sent.length, 0);
  other.emit("destroyed");
  assert.equal(registry.size, 0);
  assert.equal(theirs.requests[0].aborted, 1);
});

test("watching an owner adds one listener per event however many streams reconnect", () => {
  const registry = createStreamRegistry();
  const contents = Object.assign(new EventEmitter(), { id: 3 });
  const { open } = rig({ registry, ownerId: 3 });
  for (let i = 1; i <= 25; i += 1) {
    registry.watch(contents);
    open(`realtime-doc-${i}`);
    registry.get(`realtime-doc-${i}`).cleanup();
  }
  assert.equal(contents.listenerCount("destroyed"), 1);
  assert.equal(contents.listenerCount("did-start-navigation"), 1);
  assert.equal(registry.watch(contents), false);
});

test("navigation details are read from Electron's event object or positional arguments", () => {
  assert.equal(isMainFrameDocumentNavigation({ isMainFrame: true, isSameDocument: false }), true);
  assert.equal(isMainFrameDocumentNavigation({ isMainFrame: true, isSameDocument: true }), false);
  assert.equal(isMainFrameDocumentNavigation({ isMainFrame: false, isSameDocument: false }), false);
  assert.equal(isMainFrameDocumentNavigation({ preventDefault() {} }, "app://shell/", false, true), true);
  assert.equal(isMainFrameDocumentNavigation({ preventDefault() {} }, "app://shell/#/x", true, true), false);
  assert.equal(isMainFrameDocumentNavigation({}), false, "unknown shapes keep streams rather than guess");
});

test("abortAll ends every stream for shutdown", () => {
  const registry = createStreamRegistry();
  const a = rig({ registry, ownerId: 1 });
  const b = rig({ registry, ownerId: 2 });
  a.open("one");
  b.open("two");
  registry.abortAll();
  assert.equal(registry.size, 0);
  assert.equal(a.requests[0].aborted + b.requests[0].aborted, 2);
});

// Renderer side: ids are unique per document (realtimeChannel.js).
test("bridged stream ids never repeat across documents", async () => {
  // Each import with a distinct query is a fresh module instance, i.e. what a
  // reloaded document evaluates.
  const first = await import("../src/utils/realtimeChannel.js?document=1");
  const second = await import("../src/utils/realtimeChannel.js?document=2");
  const ids = [first.nextStreamId(), first.nextStreamId(), second.nextStreamId(), second.nextStreamId()];
  assert.equal(new Set(ids).size, ids.length);
  assert.match(ids[0], /^realtime-[\w-]+-1$/);
  assert.match(ids[2], /^realtime-[\w-]+-1$/);
  assert.notEqual(ids[0], ids[2], "both documents start their sequence at 1");
});

test("a bridged channel opens its stream with the document-unique id", async () => {
  const { RealtimeChannel, nextStreamId } = await import("../src/utils/realtimeChannel.js?document=3");
  const opened = [];
  const original = globalThis.window;
  globalThis.window = { sniff4houndDesktop: {
    httpRequest: async () => ({ status: 200, body: "" }),
    httpStreamOpen: async (payload) => { opened.push(payload); return { id: payload.id }; },
    httpStreamClose: async () => ({ closed: true }),
    onHttpStream: () => () => {},
  } };
  try {
    const channel = new RealtimeChannel("https://sensor.example:45678/realtime/stream");
    assert.equal(opened[0].id, channel.streamId);
    const prefix = nextStreamId().replace(/-\d+$/, "");
    assert.ok(channel.streamId.startsWith(`${prefix}-`));
    channel.close();
  } finally {
    globalThis.window = original;
  }
});
