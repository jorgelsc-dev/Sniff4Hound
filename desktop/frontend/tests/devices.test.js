import assert from "node:assert/strict";
import test from "node:test";
import { PRODUCT_LOGOS } from "../src/utils/productLogos.js";
import { deviceDisplay, logoColor, productDisplay } from "../src/utils/devices.js";

test("a recognised product shows its logo, its brand colour and its version", () => {
  const display = deviceDisplay({
    device_type: "Server",
    device_product: "nginx",
    device_product_label: "Nginx",
    device_product_version: "1.18.0",
  });
  assert.equal(display.label, "Server");
  assert.equal(display.detail, "Nginx 1.18.0");
  assert.equal(display.icon, `svg:${PRODUCT_LOGOS.nginx.path}`);
  assert.equal(display.iconColor, "#009639");
  assert.equal(display.color, "green", "the type colour still styles the avatar");
});

test("a product without a logo keeps the type's icon and only names itself", () => {
  const display = deviceDisplay({
    device_type: "Server",
    device_product: "iis",
    device_product_label: "Microsoft IIS",
    device_product_version: "10.0",
  });
  assert.equal(display.detail, "Microsoft IIS 10.0");
  assert.equal(display.icon, "mdi-server");
  assert.equal(display.iconColor, undefined);
});

test("Windows uses the font glyph MDI ships, since it has no bundled logo", () => {
  const display = deviceDisplay({ device_type: "PC", device_product: "windows", device_product_label: "Windows" });
  assert.equal(display.icon, "mdi-microsoft-windows");
  assert.equal(display.detail, "Windows");
});

test("a node with no product falls back to the type icon, and to the old evidence for an old runtime", () => {
  assert.equal(deviceDisplay({ device_type: "Router" }).icon, "mdi-router-network");
  assert.equal(deviceDisplay({ device_type: "Router" }).detail, null);
  assert.equal(deviceDisplay({}).label, "Unknown");
  assert.equal(productDisplay({ device_type: "Server" }), null);
  const legacy = deviceDisplay({ device_type: "Phone", device_evidence: ['metadata "android"'] });
  assert.equal(legacy.icon, "mdi-android");
  assert.equal(legacy.detail, "Android");
});

test("a product's label falls back to its id when the runtime sent none", () => {
  assert.equal(productDisplay({ device_product: "caddy" }).text, "caddy");
});

test("near-black brand colours are lightened so they show on the dark theme", () => {
  assert.equal(logoColor("000000"), "#E6EDF3", "Apple");
  assert.equal(logoColor("0A0A0A"), "#E6EDF3", "Express");
  assert.equal(logoColor("212121"), "#E6EDF3", "pfSense");
  assert.equal(logoColor("009639"), "#009639", "nginx keeps its green");
  assert.equal(logoColor("#d22128"), "#D22128", "Apache keeps its red");
  assert.equal(logoColor("A81D33"), "#E6EDF3", "Debian's dark red is too dim");
  assert.equal(logoColor("not a colour"), "#E6EDF3");
});

test("every bundled logo is a drawable single-path glyph with a brand colour", () => {
  for (const [id, logo] of Object.entries(PRODUCT_LOGOS)) {
    assert.match(logo.path, /^[Mm][^"]+$/, `${id} has no path`);
    assert.match(logo.hex, /^[0-9A-F]{6}$/, `${id} has no brand colour`);
    assert.ok(logo.title, `${id} has no title`);
    assert.match(logoColor(logo.hex), /^#[0-9A-F]{6}$/);
  }
  assert.ok(Object.keys(PRODUCT_LOGOS).length >= 40);
});
