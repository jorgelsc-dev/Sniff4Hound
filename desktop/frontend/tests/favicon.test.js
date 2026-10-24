import assert from "node:assert/strict";
import test from "node:test";
import { buildFaviconPath } from "../src/utils/favicon.js";

test("favicon fallback supports old rows without raw_url", () => {
  assert.equal(buildFaviconPath({ id: 42 }), "/favicons/raw/?id=42");
});

test("favicon URLs retain only the backend ticket and never auth tokens", () => {
  assert.equal(
    buildFaviconPath({
      id: 42,
      raw_url: "/favicons/raw/?id=42&ticket=short-lived&security_code=real-secret",
    }),
    "/favicons/raw/?id=42&ticket=short-lived",
  );
  assert.equal(buildFaviconPath({ id: 42, raw_url: "https://evil.test/?token=real-secret" }), "/favicons/raw/?id=42");
});
