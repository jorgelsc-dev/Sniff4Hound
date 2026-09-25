import assert from "node:assert/strict";
import test from "node:test";
import { NAV_LINKS, matchesQuery, navDestinations } from "../src/utils/navigation.js";

test("every nav destination is reachable from the flattened list", () => {
  const flattened = navDestinations();
  const expected = NAV_LINKS.flatMap(link => [link.to, ...(link.children || []).map(child => child.to)]);
  assert.deepEqual(flattened.map(item => item.to).sort(), expected.sort());
  // A child has to say where it lives, otherwise two "Resumen" entries
  // (Dashboard's and IA's) are indistinguishable in the palette.
  const summaries = flattened.filter(item => item.label === "Resumen");
  assert.equal(summaries.length, 2);
  assert.deepEqual(summaries.map(item => item.parent).sort(), ["Dashboard", "IA"]);
});

test("search ignores accents in both the query and the label", () => {
  const item = { label: "Configuración" };
  assert.ok(matchesQuery(item, "configuracion"));
  assert.ok(matchesQuery(item, "configuración"));
  assert.ok(matchesQuery(item, "CONFIGURACION"));
});

test("search matches a subsequence, not just a prefix", () => {
  assert.ok(matchesQuery({ label: "Configuración" }, "cnf"));
  assert.ok(matchesQuery({ label: "Mapa en Vivo", parent: "Dashboard" }, "dashvivo"));
  assert.ok(!matchesQuery({ label: "Sniffer" }, "zz"));
});

test("an empty query keeps every entry", () => {
  assert.equal(navDestinations().filter(item => matchesQuery(item, "")).length, navDestinations().length);
  assert.ok(matchesQuery({ label: "Sniffer" }, "   "));
});

test("keywords widen a match without changing the visible label", () => {
  const item = { label: "Iniciar Sniffer", keywords: "motor runtime start encender" };
  assert.ok(matchesQuery(item, "encender"));
  assert.ok(matchesQuery(item, "runtime"));
});
