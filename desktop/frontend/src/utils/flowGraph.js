// Geometry shared by every flow canvas in the app (Settings' configuration
// graph, the Dashboard's live pipeline). Card size is a parameter because the
// two canvases render different-sized nodes; everything else - routing, bounds,
// persistence validation - is identical, so it lives here once.

export function defaultPosition(node, card, gap = { x: 74, y: 46 }) {
  return {
    x: 40 + node.column * (card.width + gap.x),
    y: 60 + node.row * (card.height + gap.y),
  };
}

// Drops anything that is not a finite, plausibly-on-canvas coordinate so a
// corrupted or hand-edited localStorage entry can never strand a node
// thousands of pixels away with no way back except clearing storage.
export function validPositions(value, ids) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  return Object.fromEntries(ids.flatMap((id) => {
    const pos = value[id];
    return Number.isFinite(pos?.x) && Number.isFinite(pos?.y)
      && Math.abs(pos.x) < 10000 && Math.abs(pos.y) < 10000
      ? [[id, { x: pos.x, y: pos.y }]] : [];
  }));
}

export function graphBounds(nodes, card, pad = { x: 30, top: 48, bottom: 30 }) {
  const left = Math.min(...nodes.map(n => n.x)) - pad.x;
  const top = Math.min(...nodes.map(n => n.y)) - pad.top;
  const right = Math.max(...nodes.map(n => n.x + card.width)) + pad.x;
  const bottom = Math.max(...nodes.map(n => n.y + card.height)) + pad.bottom;
  return { x: left, y: top, width: right - left, height: bottom - top };
}

// Cubic bezier between two cards. Near-vertical pairs route around the outside
// edge instead of straight down, which keeps the wire clear of any card sitting
// between them; everything else leaves the source's right port and enters the
// target's left port.
export function connectionPath(from, to, card) {
  const { width, height } = card;
  if (Math.abs(to.x - from.x) < width) {
    const downward = to.y > from.y;
    const x1 = from.x + width / 2;
    const y1 = from.y + (downward ? height : 0);
    const x2 = to.x + width / 2;
    const y2 = to.y + (downward ? 0 : height);
    const side = Math.min(from.x, to.x) - 26;
    return `M ${x1} ${y1} C ${side} ${y1}, ${side} ${y2}, ${x2} ${y2}`;
  }
  const forward = to.x > from.x;
  const x1 = from.x + (forward ? width : 0);
  const y1 = from.y + height / 2;
  const x2 = to.x + (forward ? 0 : width);
  const y2 = to.y + height / 2;
  const bend = Math.max(40, Math.abs(x2 - x1) / 2);
  const sign = forward ? 1 : -1;
  return `M ${x1} ${y1} C ${x1 + bend * sign} ${y1}, ${x2 - bend * sign} ${y2}, ${x2} ${y2}`;
}

// Maps a rate (packets/second) onto the dash animation of a wire. A quiet link
// shows a slow, sparse trickle; a busy one a dense fast stream - the speed is
// the metric, so throughput is readable without reading a number.
export function flowAnimation(rate) {
  const magnitude = Math.log10(Math.max(0, rate) + 1);
  const intensity = Math.min(1, magnitude / 2.6);
  return {
    intensity,
    duration: `${(4.2 - intensity * 3.3).toFixed(2)}s`,
    dash: `${(4 + intensity * 12).toFixed(1)} ${(150 - intensity * 116).toFixed(1)}`,
    opacity: (0.45 + intensity * 0.5).toFixed(2),
  };
}
