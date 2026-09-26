import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { parse } from "@vue/compiler-sfc";

// Regression guard for an empty state that lied.
//
// Reported from the field: opening the node map showed "Aún no hay IPs
// observadas para dibujar el mapa." and only then did the map appear. The
// request had not failed and there was traffic - the component simply had
// not asked yet. `mounted()` runs *after* the initial render, so a component
// whose `loading` starts false renders one frame in which loading is false
// and the collection is empty, and any `v-else-if="!items.length"` branch
// wins it.
//
// "We asked and there is nothing" and "we have not asked" must not look the
// same, least of all in a tool whose whole job is telling an operator
// whether traffic exists.

function sfc(path) {
  const source = readFileSync(new URL(path, import.meta.url), "utf8");
  const { descriptor } = parse(source);
  return {
    // Comments stripped: they are not rendered, and a comment that quotes the
    // empty-state copy it explains would otherwise be mistaken for the real
    // thing and read as an unguarded branch.
    template: (descriptor.template?.content || "").replace(/<!--[\s\S]*?-->/g, ""),
    script: (descriptor.script?.content || "") + (descriptor.scriptSetup?.content || ""),
  };
}

// Components that fetch on mount and render an empty state from the same
// data. Each must start in the loading state.
const FETCHES_ON_MOUNT = [
  "../src/components/IpRelationshipGraph.vue",
  "../src/components/MapPanel.vue",
  "../src/components/monitors/MonitorMatchesPanel.vue",
  "../src/views/ProtocolsView.vue",
  "../src/views/ChatView.vue",
  "../src/views/MonitorsView.vue",
];

for (const path of FETCHES_ON_MOUNT) {
  const name = path.split("/").pop();

  test(`${name} starts in the loading state, not the empty state`, () => {
    const { script } = sfc(path);
    const declaration = script.match(/^\s*loading:\s*(true|false)\s*,/m);
    assert.ok(declaration, `${name}: expected a top-level \`loading\` in data()`);
    assert.equal(
      declaration[1],
      "true",
      `${name}: \`loading\` must initialise to true, otherwise the first rendered ` +
        "frame reports an empty result before anything has been requested",
    );
  });
}

test("every no-data message is guarded by the loading flag", () => {
  // The initial flag alone is not enough: a branch with no `loading` in its
  // condition at all still claims "nothing here" for the whole request, not
  // just the first frame. MapPanel's host table and MonitorMatchesPanel's
  // charts both did exactly that.
  const guarded = [
    ["../src/components/MapPanel.vue", "No hosts yet."],
    ["../src/components/monitors/MonitorMatchesPanel.vue", "No data yet"],
    ["../src/components/IpRelationshipGraph.vue", "Aún no hay IPs observadas"],
  ];

  for (const [path, message] of guarded) {
    const { template } = sfc(path);
    const line = template
      .split("\n")
      .find((candidate) => candidate.includes(message));
    assert.ok(line, `${path}: expected to still find the empty-state copy "${message}"`);

    // The element carrying the message must be reached through v-else-if,
    // i.e. it sits behind a preceding loading branch rather than standing on
    // its own v-if.
    const index = template.indexOf(message);
    const preceding = template.slice(0, index);
    const branch = preceding.lastIndexOf("v-else-if");
    const standalone = preceding.lastIndexOf("v-if=");
    assert.ok(
      branch > standalone,
      `${path}: the "${message}" empty state must sit behind a loading branch ` +
        "(v-else-if), so it cannot render while the first request is in flight",
    );
  }
});
