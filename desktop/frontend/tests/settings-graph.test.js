import assert from "node:assert/strict";
import test from "node:test";
import {
  GRAPH_CARD,
  SETTINGS_EDGES,
  SETTINGS_NODES,
  connectionPath,
  defaultPosition,
  graphBounds,
} from "../src/components/settings/settingsGraph.js";

const positionedNodes = SETTINGS_NODES.map(node => ({
  ...node,
  ...defaultPosition(node),
}));

test("the default settings layout keeps every card ordered and non-overlapping", () => {
  const occupied = new Set();
  for (const node of positionedNodes) {
    const key = `${node.column}:${node.row}`;
    assert.ok(!occupied.has(key), `duplicate layout slot: ${key}`);
    occupied.add(key);
    assert.equal(node.x, 40 + node.column * (GRAPH_CARD.width + 60));
    assert.equal(node.y, 60 + node.row * (GRAPH_CARD.height + 46));
  }
});

test("graph bounds include visual connector clearance", () => {
  const bounds = graphBounds(positionedNodes);
  assert.equal(bounds.x, -18);
  assert.equal(bounds.y, 2);
  assert.equal(bounds.width, 2240);
  assert.equal(bounds.height, 736);
});

test("every configured edge has valid endpoints and a routed connector", () => {
  const byId = new Map(positionedNodes.map(node => [node.id, node]));
  for (const edge of SETTINGS_EDGES) {
    const from = byId.get(edge.from);
    const to = byId.get(edge.to);
    assert.ok(from, `missing source node: ${edge.from}`);
    assert.ok(to, `missing target node: ${edge.to}`);
    assert.match(connectionPath(from, to), /^M -?\d+(?:\.\d+)? -?\d+(?:\.\d+)? C /);
  }
});
