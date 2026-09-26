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
    template: descriptor.template?.content || "",
    script: (descriptor.script?.content || "") + (descriptor.scriptSetup?.content || ""),
  };
}

// Where the comments are, rather than removing them.
//
// This started as a regex strip of `<!-- ... -->`, which CodeQL correctly
// flagged (js/incomplete-multi-character-sanitization): one pass over nested
// or malformed markers leaves `<!--` behind. Nothing untrusted is involved
// here - these are repo files read off disk - but scanning for the ranges is
// both exact and simpler to reason about than a regex that has to be right
// about every edge case.
function commentRanges(text) {
  const ranges = [];
  let from = 0;
  for (;;) {
    const open = text.indexOf("<!--", from);
    if (open === -1) return ranges;
    const close = text.indexOf("-->", open + 4);
    const end = close === -1 ? text.length : close + 3;
    ranges.push([open, end]);
    from = end;
  }
}

// The first occurrence that is actually rendered. A comment explaining an
// empty state usually quotes its copy, and counting that as the real thing
// reads the branch as unguarded.
function indexOutsideComments(text, needle) {
  const ranges = commentRanges(text);
  let from = 0;
  for (;;) {
    const at = text.indexOf(needle, from);
    if (at === -1) return -1;
    if (!ranges.some(([start, end]) => at >= start && at < end)) return at;
    from = at + needle.length;
  }
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
    const index = indexOutsideComments(template, message);
    assert.notEqual(
      index,
      -1,
      `${path}: expected to still find the rendered empty-state copy "${message}"`,
    );

    // The element carrying the message must be reached through v-else-if,
    // i.e. it sits behind a preceding loading branch rather than standing on
    // its own v-if.
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
