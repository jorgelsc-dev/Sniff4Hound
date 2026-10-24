"use strict";

// Which documents the main window may show, which of them may call which IPC
// channels, and which web permissions they get. The window only ever shows two
// documents: the packaged connection chooser (splash.html, via loadFile()) and
// the bundled SPA under app://shell (via loadURL()). Anything else - a dropped
// file, a stray link, a local HTML page - must neither replace them nor reach
// the preload's IPC surface.

const path = require("node:path");
const { fileURLToPath } = require("node:url");

const SHELL = "shell";
const SPLASH = "splash";

function parseUrl(value) {
  try {
    return new URL(String(value || ""));
  } catch {
    return null;
  }
}

// app://shell/... - the bundled SPA. app: is a non-special scheme, so its
// WHATWG origin is opaque; the protocol and host identify it instead.
function isShellUrl(value) {
  const url = parseUrl(value);
  return Boolean(url) && url.protocol === "app:" && url.host === SHELL && !url.username && !url.password;
}

// Exactly the packaged splash file, whatever its percent-encoding, and only on
// the local host.
function isSplashUrl(value, splashPath) {
  const url = parseUrl(value);
  if (!url || url.protocol !== "file:" || (url.host && url.host !== "localhost") || !splashPath) return false;
  try {
    return path.resolve(fileURLToPath(url)) === path.resolve(splashPath);
  } catch {
    return false;
  }
}

function documentKind(value, splashPath) {
  if (isShellUrl(value)) return SHELL;
  if (isSplashUrl(value, splashPath)) return SPLASH;
  return "";
}

// will-navigate: only the two documents above may load in the window.
function navigationAllowed(value, { splashPath }) {
  return documentKind(value, splashPath) !== "";
}

/**
 * True when an IPC event comes from the window's main frame showing one of the
 * `allow`ed documents ("shell", "splash"). A missing frame (navigated away or
 * destroyed) or a subframe is refused.
 */
function senderAllowed(event, { splashPath, allow }) {
  let frame = null;
  let url = "";
  try {
    frame = event && event.senderFrame;
    if (!frame || frame.parent) return false;
    url = frame.url;
  } catch {
    return false;
  }
  const kind = documentKind(url, splashPath);
  return kind !== "" && Array.isArray(allow) && allow.includes(kind);
}

// Web permissions: system notifications for the SPA, nothing for anyone else.
function permissionAllowed(permission, requestingUrl) {
  return permission === "notifications" && isShellUrl(requestingUrl);
}

// Menu shortcuts (Ctrl+1..4, Tools): a loaded SPA switches route in place, so
// drafts, results and live streams survive; only when the window is not
// showing a loaded shell does the menu load it.
function menuNavigationMode(currentUrl, { loading = false } = {}) {
  return isShellUrl(currentUrl) && !loading ? "renderer" : "load";
}

module.exports = {
  SHELL,
  menuNavigationMode,
  SPLASH,
  documentKind,
  isShellUrl,
  isSplashUrl,
  navigationAllowed,
  permissionAllowed,
  senderAllowed,
};
