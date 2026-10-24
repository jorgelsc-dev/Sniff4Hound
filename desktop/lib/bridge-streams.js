"use strict";

// Streamed responses of the renderer HTTP bridge (main.js, "Renderer HTTP
// bridge"): the realtime channel's server-sent events, relayed chunk by chunk
// from the main process's HTTP/3 request to the renderer that opened it.

const { StringDecoder } = require("node:string_decoder");

// Upper bound for data the renderer still has to buffer: the bytes after the
// last complete server-sent event. A healthy stream delivers complete events
// indefinitely, so a lifetime total would cut it after a few minutes of
// refreshes; one event that never ends is what this limit is for.
const STREAM_PENDING_LIMIT = 8 * 1024 * 1024;
// Inactivity timeout. The realtime endpoint emits a heartbeat every 15 seconds.
const STREAM_TIMEOUT_MS = 30000;

const EVENT_BOUNDARIES = ["\r\n\r\n", "\n\n", "\r\r"].map((text) => Buffer.from(text));
const LONGEST_BOUNDARY = 4;

// Offset just past the last blank line (an SSE event terminator), or -1.
function lastEventBoundaryEnd(buffer) {
  let end = -1;
  for (const boundary of EVENT_BOUNDARIES) {
    const index = buffer.lastIndexOf(boundary);
    if (index !== -1) end = Math.max(end, index + boundary.length);
  }
  return end;
}

/**
 * Tracks how many bytes of an unterminated event are pending. push() returns
 * false once that exceeds `limit`; complete events reset the count.
 */
function createPendingEventLimiter(limit = STREAM_PENDING_LIMIT) {
  let pending = 0;
  // The last bytes seen, so a terminator split across two chunks is found.
  let tail = Buffer.alloc(0);
  return {
    get pending() {
      return pending;
    },
    push(chunk) {
      const data = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk));
      const joined = tail.length ? Buffer.concat([tail, data]) : data;
      const end = lastEventBoundaryEnd(joined);
      pending = end === -1 ? pending + data.length : joined.length - end;
      tail = Buffer.from(joined.subarray(Math.max(0, joined.length - (LONGEST_BOUNDARY - 1))));
      return pending <= limit;
    },
  };
}

// A cross-document navigation of the main frame: a reload, loadURL()/loadFile()
// to another page, or a renderer-initiated navigation. Hash changes within the
// SPA (router.push) are same-document and keep their streams. Electron passes
// an event object with the details; older releases passed them positionally.
function isMainFrameDocumentNavigation(details, _url, isInPlace, isMainFrame) {
  const mainFrame = details && typeof details.isMainFrame === "boolean" ? details.isMainFrame : isMainFrame;
  const sameDocument = details && typeof details.isSameDocument === "boolean" ? details.isSameDocument : isInPlace;
  return mainFrame === true && sameDocument === false;
}

/**
 * Open streams by id, owned by the webContents that opened them. Streams are
 * aborted when their owner is destroyed or its main frame loads a new document
 * (reload, sensor switch, return to the chooser), each owner being watched by
 * exactly one listener per event however many streams it opens.
 */
function createStreamRegistry() {
  const streams = new Map();
  const watched = new WeakSet();

  const abort = (stream) => {
    if (!stream.cleanup()) return false;
    try {
      stream.request.abort();
    } catch {
      /* The request may already be closed. */
    }
    return true;
  };

  const registry = {
    get size() {
      return streams.size;
    },
    has: (id) => streams.has(id),
    get: (id) => streams.get(id),
    set: (id, stream) => streams.set(id, stream),
    // Removes the entry only if it still belongs to that owner.
    release(id, ownerId) {
      if (streams.get(id)?.ownerId === ownerId) streams.delete(id);
    },
    idsFor: (ownerId) => [...streams].filter(([, stream]) => stream.ownerId === ownerId).map(([id]) => id),
    abortOwner(ownerId) {
      let aborted = 0;
      for (const stream of [...streams.values()]) {
        if (stream.ownerId === ownerId && abort(stream)) aborted += 1;
      }
      for (const [id, stream] of [...streams]) if (stream.ownerId === ownerId) streams.delete(id);
      return aborted;
    },
    abortAll() {
      for (const stream of [...streams.values()]) abort(stream);
      streams.clear();
    },
    watch(contents) {
      if (!contents || watched.has(contents)) return false;
      watched.add(contents);
      const ownerId = contents.id;
      contents.once("destroyed", () => registry.abortOwner(ownerId));
      contents.on("did-start-navigation", (...args) => {
        if (isMainFrameDocumentNavigation(...args)) registry.abortOwner(ownerId);
      });
      return true;
    },
  };
  return registry;
}

/**
 * Starts one bridged stream and relays it to `send`. `createRequest` returns an
 * Electron net request (or a stand-in with on/setHeader/end/abort); `send`
 * receives {type: "data"|"end"|"error", ...} messages without the id.
 */
function openBridgeStream({
  id,
  ownerId,
  url,
  headers = {},
  createRequest,
  send,
  registry,
  limit = STREAM_PENDING_LIMIT,
  timeoutMs = STREAM_TIMEOUT_MS,
  schedule = setTimeout,
  cancel = clearTimeout,
}) {
  if (!id || registry.has(id)) throw new Error("Invalid stream id.");
  const decoder = new StringDecoder("utf8");
  const limiter = createPendingEventLimiter(limit);
  let finished = false;
  let timeout = null;
  const cleanup = () => {
    if (finished) return false;
    finished = true;
    if (timeout) cancel(timeout);
    timeout = null;
    registry.release(id, ownerId);
    return true;
  };
  const request = createRequest({ method: "GET", url, redirect: "error" });
  const fail = (message) => {
    if (!cleanup()) return;
    try {
      request.abort();
    } catch {
      /* Already closed. */
    }
    send({ type: "error", message });
  };
  const refreshTimeout = () => {
    if (finished) return;
    if (timeout) cancel(timeout);
    timeout = schedule(() => fail("Stream timed out."), timeoutMs);
  };
  for (const [name, value] of Object.entries(headers)) request.setHeader(name, value);
  registry.set(id, { request, ownerId, cleanup });
  refreshTimeout();
  request.on("response", (response) => {
    response.on("data", (chunk) => {
      if (finished) return;
      // Every chunk renews the inactivity timeout, so a healthy long-lived
      // stream is not closed after 30 seconds.
      refreshTimeout();
      if (!limiter.push(chunk)) {
        fail("Stream is too large.");
        return;
      }
      send({ type: "data", chunk: decoder.write(chunk) });
    });
    response.on("end", () => {
      if (!cleanup()) return;
      send({ type: "end", status: response.statusCode });
    });
    response.on("error", (error) => {
      if (!cleanup()) return;
      send({ type: "error", message: error.message });
    });
  });
  request.on("error", (error) => {
    if (!cleanup()) return;
    send({ type: "error", message: error.message });
  });
  request.end();
  return { id };
}

module.exports = {
  STREAM_PENDING_LIMIT,
  STREAM_TIMEOUT_MS,
  createPendingEventLimiter,
  createStreamRegistry,
  isMainFrameDocumentNavigation,
  openBridgeStream,
};
