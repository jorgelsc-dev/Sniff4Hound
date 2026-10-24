import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";
import test from "node:test";

const require = createRequire(import.meta.url);
const {
  isShellUrl, isSplashUrl, menuNavigationMode, navigationAllowed, permissionAllowed, senderAllowed,
} = require("../../lib/window-security.js");

const SPLASH = "/opt/Sniff 4 Hound/resources/app/splash.html";
const SPLASH_URL = pathToFileURL(SPLASH).href;
const frameEvent = (url, extra = {}) => ({ senderFrame: { url, parent: null, ...extra } });

test("only the bundled shell and the exact packaged splash count as app documents", () => {
  assert.equal(isShellUrl("app://shell/index.html?api_base=x#/soc"), true);
  assert.equal(isShellUrl("app://shell"), true);
  for (const url of ["app://other/index.html", "app://user:pw@shell/", "https://shell/", "file:///shell", "", null, "not a url"]) {
    assert.equal(isShellUrl(url), false, String(url));
  }
  assert.ok(SPLASH_URL.includes("%20"), "fixture path exercises percent-encoding");
  assert.equal(isSplashUrl(SPLASH_URL, SPLASH), true);
  assert.equal(isSplashUrl("file:///opt/Sniff 4 Hound/resources/app/splash.html", SPLASH), true);
  for (const url of ["file:///tmp/x.html", "file:///opt/Sniff%204%20Hound/resources/app/splash.htm",
    "file:///opt/Sniff%204%20Hound/resources/app/../app2/splash.html", "file://evil.example/opt/Sniff%204%20Hound/resources/app/splash.html",
    "app://shell/splash.html", "https://example.com/splash.html"]) {
    assert.equal(isSplashUrl(url, SPLASH), false, url);
  }
});

test("will-navigate permits only the splash and app://shell", () => {
  const options = { splashPath: SPLASH };
  assert.equal(navigationAllowed(SPLASH_URL, options), true);
  assert.equal(navigationAllowed("app://shell/index.html#/", options), true);
  for (const url of ["file:///tmp/x.html", "file:///home/op/Downloads/report.pdf", "https://sensor.example:45678/",
    "http://127.0.0.1:45678/", "data:text/html,<p>x</p>", "javascript:alert(1)", "about:blank", "garbage"]) {
    assert.equal(navigationAllowed(url, options), false, url);
  }
});

test("IPC senders are accepted only from the allowed document's main frame", () => {
  const options = (allow) => ({ splashPath: SPLASH, allow });
  assert.equal(senderAllowed(frameEvent("app://shell/index.html#/soc"), options(["shell"])), true);
  assert.equal(senderAllowed(frameEvent(SPLASH_URL), options(["splash"])), true);
  assert.equal(senderAllowed(frameEvent(SPLASH_URL), options(["shell", "splash"])), true);
  // Launcher channels: the shell may not start a runtime or connect elsewhere.
  assert.equal(senderAllowed(frameEvent("app://shell/index.html"), options(["splash"])), false);
  // Data bridge: the chooser may not use the shell's channels.
  assert.equal(senderAllowed(frameEvent(SPLASH_URL), options(["shell"])), false);
  for (const url of ["file:///tmp/x.html", "https://sensor.example/", "about:blank", ""]) {
    assert.equal(senderAllowed(frameEvent(url), options(["shell", "splash"])), false, url);
  }
  assert.equal(senderAllowed(frameEvent("app://shell/index.html", { parent: {} }), options(["shell"])), false, "subframes are refused");
  assert.equal(senderAllowed({}, options(["shell"])), false, "a navigated-away frame is refused");
  assert.equal(senderAllowed({ senderFrame: null }, options(["shell"])), false);
  assert.equal(senderAllowed(undefined, options(["shell"])), false);
  const throwing = { get senderFrame() { throw new Error("frame disposed"); } };
  assert.equal(senderAllowed(throwing, options(["shell"])), false);
  assert.equal(senderAllowed(frameEvent("app://shell/"), { splashPath: SPLASH }), false, "no allow list, no access");
});

test("only notifications are granted, and only to app://shell", () => {
  assert.equal(permissionAllowed("notifications", "app://shell"), true);
  assert.equal(permissionAllowed("notifications", "app://shell/index.html#/soc"), true);
  for (const permission of ["media", "geolocation", "midi", "clipboard-read", "clipboard-sanitized-write",
    "fullscreen", "openExternal", "pointerLock", "display-capture", "unknown"]) {
    assert.equal(permissionAllowed(permission, "app://shell"), false, permission);
  }
  for (const origin of ["file://", SPLASH_URL, "https://sensor.example", "app://other", "", undefined]) {
    assert.equal(permissionAllowed("notifications", origin), false, String(origin));
  }
});

test("menu shortcuts switch routes in a loaded shell and load it otherwise", () => {
  assert.equal(menuNavigationMode("app://shell/index.html?api_base=x#/"), "renderer");
  assert.equal(menuNavigationMode("app://shell/index.html#/", { loading: true }), "load");
  assert.equal(menuNavigationMode(SPLASH_URL), "load");
  assert.equal(menuNavigationMode(""), "load");
});
