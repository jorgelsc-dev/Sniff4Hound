// A WebSocket-shaped channel to the Sniff4Hound runtime, built on streamed
// responses (server to client) and requests (client to server) instead of a
// WebSocket, which Chromium cannot run over HTTP/3.
//
// The server pushes over a streamed GET and the client sends each action as a
// POST whose answer comes back on that stream. Under the desktop shell both
// ride the main process's HTTP/3 bridge (httpBridge.js); in a browser the
// stream is an EventSource. The rest of the app keeps the WebSocket interface
// it already uses: readyState, addEventListener, send, close.

import { bridgeFor, bridgedFetch } from "./httpBridge.js";

const CONNECTING = 0;
const OPEN = 1;
const CLOSING = 2;
const CLOSED = 3;

// Close code the realtime protocol uses for "the security code was rejected".
const AUTH_CLOSE_CODE = 4401;

let streamSequence = 0;

function parseJson(text) {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

export class RealtimeChannel {
  static CONNECTING = CONNECTING;
  static OPEN = OPEN;
  static CLOSING = CLOSING;
  static CLOSED = CLOSED;

  // `options.headers` returns the headers each request needs (the bearer token).
  constructor(url, options = {}) {
    this.url = url;
    this.readyState = CONNECTING;
    this.sessionId = "";
    this.headersFor = typeof options.headers === "function" ? options.headers : () => ({});
    this.listeners = { open: [], message: [], error: [], close: [] };
    this.sendChain = Promise.resolve();
    this.pending = [];
    this.finished = false;
    this.buffer = "";

    const bridge = bridgeFor(url);
    if (bridge && String(url).startsWith("https://")) {
      this.bridge = bridge;
      this.streamId = `realtime-${++streamSequence}`;
      this.stopListening = bridge.onHttpStream((message) => this.handleStreamMessage(message));
      bridge.httpStreamOpen({ id: this.streamId, url, headers: this.headersFor() }).catch(() => {
        this.finish(1006, "connection lost");
      });
      return;
    }

    this.source = new EventSource(url);
    this.source.onmessage = (event) => this.handleMessage(event);
    this.source.addEventListener("close", (event) => this.handleServerClose(event));
    this.source.onerror = () => {
      // EventSource would retry on its own with the same, now spent, ticket.
      // The app owns reconnection, so this channel closes and reports it.
      this.finish(1006, "connection lost");
    };
  }

  addEventListener(type, listener) {
    if (this.listeners[type]) this.listeners[type].push(listener);
  }

  removeEventListener(type, listener) {
    if (!this.listeners[type]) return;
    this.listeners[type] = this.listeners[type].filter((item) => item !== listener);
  }

  dispatch(type, event) {
    for (const listener of this.listeners[type] || []) {
      try {
        listener(event);
      } catch {
        // A listener failing must not stop the channel delivering the rest.
      }
    }
  }

  // Bridge stream: raw text in, parsed into server-sent events.
  handleStreamMessage(message) {
    if (!message || message.id !== this.streamId) return;
    if (message.type === "data") {
      this.buffer += message.chunk;
      this.consumeEvents();
      return;
    }
    if (message.type === "end") {
      this.finish(1006, "connection lost");
      return;
    }
    if (message.type === "error") {
      this.finish(1006, String(message.message || "connection lost"));
    }
  }

  // Server-sent events are blocks separated by a blank line; each block has an
  // optional `event:` name and one or more `data:` lines. `:` lines are comments.
  consumeEvents() {
    let boundary = this.buffer.indexOf("\n\n");
    while (boundary !== -1) {
      const block = this.buffer.slice(0, boundary);
      this.buffer = this.buffer.slice(boundary + 2);
      let name = "message";
      const data = [];
      for (const line of block.split("\n")) {
        if (line.startsWith("event:")) name = line.slice(6).trim();
        else if (line.startsWith("data:")) data.push(line.slice(5).replace(/^ /, ""));
      }
      if (data.length) {
        const event = { data: data.join("\n") };
        if (name === "close") this.handleServerClose(event);
        else this.handleMessage(event);
      }
      boundary = this.buffer.indexOf("\n\n");
    }
  }

  handleMessage(event) {
    const payload = parseJson(event.data);
    if (payload && payload.type === "session") {
      // The stream is up and the server has named this session; sends can go.
      this.sessionId = String(payload.session || "");
      this.readyState = OPEN;
      this.dispatch("open", { type: "open" });
      this.flushPending();
      return;
    }
    this.dispatch("message", { type: "message", data: event.data });
    if (payload && payload.type === "auth_required") {
      // The app has seen the message and runs its unauthorized handling on the
      // close below, the same as it did for the websocket's auth close.
      this.finish(AUTH_CLOSE_CODE, "Unauthorized");
    }
  }

  handleServerClose(event) {
    const detail = parseJson(event.data || "{}") || {};
    this.finish(Number(detail.code) || 1000, String(detail.reason || ""));
  }

  finish(code, reason) {
    if (this.finished) return;
    this.finished = true;
    this.readyState = CLOSED;
    if (this.bridge) {
      this.stopListening();
      this.bridge.httpStreamClose(this.streamId).catch(() => {});
    } else {
      this.source.close();
    }
    this.pending = [];
    this.dispatch("close", { type: "close", code, reason, wasClean: code === 1000 });
  }

  send(data) {
    if (this.readyState === CLOSED || this.readyState === CLOSING) {
      throw new Error("realtime channel is not open");
    }
    if (!this.sessionId) {
      // Sent before the session arrived; delivered in order once it does.
      this.pending.push(String(data));
      return;
    }
    this.post(String(data));
  }

  flushPending() {
    const queued = this.pending;
    this.pending = [];
    for (const data of queued) this.post(data);
  }

  post(data) {
    // A chain keeps the requests in the order send() was called, so a subscribe
    // followed by an unsubscribe cannot arrive the other way round.
    this.sendChain = this.sendChain.then(() => {
      const url = new URL(this.url);
      url.pathname = "/api/realtime/command";
      url.search = `?session=${encodeURIComponent(this.sessionId)}`;
      return bridgedFetch(url.toString(), {
        method: "POST",
        headers: { "Content-Type": "application/json", ...this.headersFor() },
        body: data,
      }).then((response) => {
        if (response.status === 410) this.finish(1001, "realtime session ended");
      });
    }).catch(() => {
      // A failed request is reported by the stream going quiet and the app
      // reconnecting; there is no per-message error channel to use here.
    });
  }

  close(code = 1000, reason = "") {
    if (this.readyState === CLOSED || this.readyState === CLOSING) return;
    this.readyState = CLOSING;
    this.finish(code, reason);
  }
}

export default RealtimeChannel;
