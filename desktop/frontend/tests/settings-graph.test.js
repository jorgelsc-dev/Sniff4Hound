import assert from "node:assert/strict";
import test from "node:test";
import {
  GRAPH_CARD,
  SETTINGS_EDGES,
  SETTINGS_NODES,
  connectionPath,
  defaultPosition,
  edgeMidpoint,
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

test("the graph has one complete node for every settings destination", () => {
  const sections = new Set(SETTINGS_NODES.map(node => node.section));
  assert.equal(SETTINGS_NODES.length, 16);
  assert.equal(sections.size, SETTINGS_NODES.length);
  for (const node of SETTINGS_NODES) {
    assert.ok(node.label && node.detail && node.icon, `incomplete node: ${node.id}`);
  }
});

test("configured edges follow the left-to-right layout", () => {
  const byId = new Map(SETTINGS_NODES.map(node => [node.id, node]));
  for (const edge of SETTINGS_EDGES) {
    const from = byId.get(edge.from);
    const to = byId.get(edge.to);
    assert.ok(to.column >= from.column, `backward edge: ${edge.from} -> ${edge.to}`);
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

test("detour labels stay outside cards while straight labels stay centered", () => {
  const history = positionedNodes.find(node => node.id === "history");
  const store = positionedNodes.find(node => node.id === "store");
  const vertical = edgeMidpoint(history, store);
  assert.equal(vertical.x, history.x - 26);
  assert.equal(vertical.y, (history.y + GRAPH_CARD.height + store.y) / 2);

  const runtime = positionedNodes.find(node => node.id === "runtime");
  const sniffer = positionedNodes.find(node => node.id === "sniffer");
  const horizontal = edgeMidpoint(runtime, sniffer);
  assert.equal(horizontal.x, (runtime.x + sniffer.x) / 2 + GRAPH_CARD.width / 2);
  assert.equal(horizontal.y, (runtime.y + sniffer.y) / 2 + GRAPH_CARD.height / 2);
});
