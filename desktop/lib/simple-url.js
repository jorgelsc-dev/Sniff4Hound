"use strict";

// Hand-rolled stand-in for the parts of the WHATWG URL API main.js relies on
// (absolute http(s)/mailto/file parsing, resolving an absolute path against
// a base origin, .searchParams.set(), and rebuilding via toString()). Not a
// general-purpose URL parser - only what those call sites in main.js need.
//
// Security note: main.js uses this to decide which URLs are safe to hand to
// shell.openExternal() / allow in in-window navigation, so parsing must fail
// closed (throw) on anything it doesn't confidently understand rather than
// guess - callers already wrap construction in try/catch and treat a throw
// as "block this".

const ABSOLUTE_URL_RE = /^([a-zA-Z][a-zA-Z0-9+.-]*):(\/\/)?(.*)$/s;

function encodePart(value) {
  return encodeURIComponent(String(value));
}

function decodePart(value) {
  try {
    return decodeURIComponent(String(value).replace(/\+/g, " "));
  } catch {
    return String(value);
  }
}

class SimpleSearchParams {
  constructor(rawQuery) {
    this._pairs = [];
    const query = String(rawQuery || "").replace(/^\?/, "");
    if (!query) return;
    for (const part of query.split("&")) {
      if (!part) continue;
      const eq = part.indexOf("=");
      const rawKey = eq === -1 ? part : part.slice(0, eq);
      const rawValue = eq === -1 ? "" : part.slice(eq + 1);
      this._pairs.push([decodePart(rawKey), decodePart(rawValue)]);
    }
  }

  set(key, value) {
    const k = String(key);
    const v = String(value);
    let found = false;
    this._pairs = this._pairs.reduce((kept, pair) => {
      if (pair[0] !== k) {
        kept.push(pair);
      } else if (!found) {
        kept.push([k, v]);
        found = true;
      }
      return kept;
    }, []);
    if (!found) this._pairs.push([k, v]);
  }

  toString() {
    return this._pairs.map(([k, v]) => `${encodePart(k)}=${encodePart(v)}`).join("&");
  }
}

function splitAuthority(authority) {
  let hostname = authority;
  const atIndex = authority.lastIndexOf("@");
  if (atIndex !== -1) hostname = authority.slice(atIndex + 1);

  let port = "";
  const colonIndex = hostname.lastIndexOf(":");
  if (colonIndex !== -1 && /^\d*$/.test(hostname.slice(colonIndex + 1))) {
    port = hostname.slice(colonIndex + 1);
    hostname = hostname.slice(0, colonIndex);
  }
  return { hostname: hostname.toLowerCase(), port };
}

class SimpleURL {
  constructor(input, base) {
    const raw = String(input == null ? "" : input);
    const absoluteMatch = ABSOLUTE_URL_RE.exec(raw);
    const hasAuthority = Boolean(absoluteMatch && absoluteMatch[2] === "//");

    let protocol;
    let rest;

    if (hasAuthority) {
      protocol = `${absoluteMatch[1].toLowerCase()}:`;
      rest = absoluteMatch[3];
    } else if (base !== undefined) {
      if (!raw.startsWith("/")) {
        throw new TypeError(`Unsupported relative URL (must start with "/"): ${raw}`);
      }
      const baseUrl = base instanceof SimpleURL ? base : new SimpleURL(base);
      protocol = baseUrl.protocol;
      rest = `${baseUrl.hostname}${baseUrl.port ? `:${baseUrl.port}` : ""}${raw}`;
    } else if (absoluteMatch) {
      // Opaque scheme with no authority section, e.g. "mailto:a@b.com" or
      // "javascript:...". Kept as its own branch (rather than folded into
      // the parse below) so callers can still read .protocol off it - the
      // allowlist check in main.js depends on that for schemes it rejects.
      this.protocol = `${absoluteMatch[1].toLowerCase()}:`;
      this.hostname = "";
      this.port = "";
      this.pathname = absoluteMatch[3] || "";
      this.hash = "";
      this._search = new SimpleSearchParams("");
      return;
    } else {
      throw new TypeError(`Invalid URL: ${raw}`);
    }

    const hashIndex = rest.indexOf("#");
    let hash = "";
    if (hashIndex !== -1) {
      hash = rest.slice(hashIndex);
      rest = rest.slice(0, hashIndex);
    }

    const queryIndex = rest.indexOf("?");
    let search = "";
    if (queryIndex !== -1) {
      search = rest.slice(queryIndex);
      rest = rest.slice(0, queryIndex);
    }

    const pathIndex = rest.indexOf("/");
    const authority = pathIndex === -1 ? rest : rest.slice(0, pathIndex);
    const pathname = pathIndex === -1 ? "" : rest.slice(pathIndex);
    const { hostname, port } = splitAuthority(authority);

    this.protocol = protocol;
    this.hostname = hostname;
    this.port = port;
    this.pathname = pathname || "/";
    this.hash = hash;
    this._search = new SimpleSearchParams(search);
  }

  get origin() {
    return `${this.protocol}//${this.hostname}${this.port ? `:${this.port}` : ""}`;
  }

  get search() {
    const query = this._search.toString();
    return query ? `?${query}` : "";
  }

  set search(value) {
    this._search = new SimpleSearchParams(value);
  }

  get searchParams() {
    return this._search;
  }

  toString() {
    if (!this.hostname) {
      // Opaque scheme (mailto:, javascript:, ...) - no authority to render.
      return `${this.protocol}${this.pathname}`;
    }
    return `${this.origin}${this.pathname}${this.search}${this.hash || ""}`;
  }
}

module.exports = { URL: SimpleURL };
