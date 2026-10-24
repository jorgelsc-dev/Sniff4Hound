import assert from "node:assert/strict";
import test from "node:test";
import { optionsView, feedStore } from "./helpers/options-view.js";

const snapshot = id => ({ packets: [{ id }], banners: [{ id }], tags: [{ id }], totals: { frames: 12 } });
const frame = id => ({ type: "feed_data", data: snapshot(id) });

for (const outcome of ["resolve", "reject"]) {
  test(`protocol navigation ignores old ${outcome}, including finally and stream startup`, async () => {
    const { store, reads, feeds } = feedStore();
    const { vm } = await optionsView("ProtocolsView", store);
    const first = vm.load();
    vm.$route.params.proto = "udp";
    const second = vm.load();
    reads[0][outcome](outcome === "resolve" ? snapshot("tcp") : new Error("old failure"));
    await first;
    assert.equal(vm.loading, true, "old finally must not finish UDP's loading");
    assert.equal(vm.error, "");
    assert.equal(feeds.length, 0);
    reads[1].resolve(snapshot("udp"));
    await second;
    assert.equal(vm.packetRows[0].id, "udp");
    assert.equal(vm.bannerRows[0].id, "udp");
    assert.equal(vm.tagRows[0].id, "udp");
    assert.equal(vm.packetsMeta.totalAvailable, 12);
    assert.equal(feeds.length, 1);
    assert.equal(feeds[0].feed, "protocols");
    assert.deepEqual(feeds[0].params, { proto: "udp", since: "1h", limit: 100, refresh: 1000 });
    assert.equal(vm.loading, false);
    // Also exercise the observed UDP-first / TCP-last completion order.
    vm.$route.params.proto = "tcp";
    const third = vm.load();
    vm.$route.params.proto = "udp";
    const fourth = vm.load();
    reads[3].resolve(snapshot("new udp"));
    await fourth;
    reads[2][outcome](outcome === "resolve" ? snapshot("late tcp") : new Error("late failure"));
    await third;
    assert.equal(vm.packetRows[0].id, "new udp");
    assert.equal(vm.error, "");
    assert.equal(feeds.length, 2);
  });
}

test("protocol period/limits invalidate HTTP and closed feed data/errors/fallback", async () => {
  const { store, reads, feeds } = feedStore();
  const { vm, definition } = await optionsView("ProtocolsView", store);
  let request = vm.load();
  reads[0].resolve(snapshot("initial"));
  await request;
  const oldFeed = feeds[0];
  store.state.timeRange = "24h";
  oldFeed.message(frame("old period"));
  oldFeed.message({ type: "feed_error", message: "old error" });
  oldFeed.unavailable();
  assert.equal(vm.packetRows[0].id, "initial");
  assert.equal(vm.error, "");
  assert.equal(vm.wsRefreshTimer, null);
  definition.watch["store.state.timeRange"].call(vm);
  assert.equal(oldFeed.closed, true);
  request = vm.load();
  reads[2].resolve(snapshot("24h"));
  await request;
  reads[1].reject(new Error("old period HTTP"));
  await Promise.resolve();
  assert.equal(vm.packetRows[0].id, "24h");
  assert.equal(feeds.at(-1).params.since, "24h");
  vm.loadMore();
  assert.equal(feeds.at(-1).closed, true);
  assert.equal(reads[3].params.limit, 1100);
  reads[3].resolve(snapshot("expanded"));
  await Promise.resolve();
  assert.equal(feeds.at(-1).params.limit, 1100);
  definition.beforeUnmount.call(vm);
});

test("protocol discovery and snapshot cannot complete after unmount", async () => {
  for (const discovery of [true, false]) {
    const { store, reads, feeds } = feedStore();
    const { vm, definition } = await optionsView("ProtocolsView", store);
    if (discovery) vm.$route.params = {};
    const request = vm.load();
    definition.beforeUnmount.call(vm);
    reads[0].resolve(discovery ? { catalog: [{ protocol: "udp", count: 10 }] } : snapshot("late"));
    await request;
    assert.deepEqual(vm.packetRows, []);
    assert.equal(vm.defaultProtocol, "");
    assert.equal(feeds.length, 0);
    assert.equal(reads.length, 1);
  }
});

test("protocol pause closes feeds, cancels fallback and permits intentional refresh", async () => {
  const { store, reads, feeds } = feedStore();
  const { vm, definition } = await optionsView("ProtocolsView", store);
  const request = vm.load();
  reads[0].resolve(snapshot("initial"));
  await request;
  feeds[0].unavailable();
  assert.ok(vm.wsRefreshTimer, "unavailable schedules HTTP fallback even without traffic");
  vm.liveRefreshEnabled = false;
  definition.watch.liveRefreshEnabled.call(vm, false);
  assert.equal(vm.wsRefreshTimer, null);
  assert.equal(feeds[0].closed, true);
  feeds[0].message(frame("paused"));
  feeds[0].message({ type: "feed_error", message: "paused error" });
  feeds[0].unavailable();
  await vm.load({ silent: true });
  assert.equal(reads.length, 1);
  assert.equal(vm.packetRows[0].id, "initial");
  const manual = vm.load();
  reads[1].resolve(snapshot("manual"));
  await manual;
  assert.equal(vm.packetRows[0].id, "manual");
  assert.equal(feeds.length, 1, "manual refresh must not restart live updates");
  vm.liveRefreshEnabled = true;
  definition.watch.liveRefreshEnabled.call(vm, true);
  reads[2].resolve(snapshot("resumed"));
  await Promise.resolve();
  assert.equal(vm.packetRows[0].id, "resumed");
  definition.beforeUnmount.call(vm);
});

for (const [name, rows] of [["DomainsView", "domains"], ["PathsView", "paths"]]) {
  test(`${name}: pause freezes order/time, rejects old callbacks and resumes fresh`, async () => {
    const { store, feeds, reads } = feedStore();
    const { vm, definition } = await optionsView(name, store);
    definition.mounted.call(vm);
    feeds[0].message({ type: "feed_data", data: [{ id: "a" }, { id: "b" }] });
    const initialRows = vm[rows];
    const initialTime = vm.lastUpdated;
    vm.liveRefreshEnabled = false;
    definition.watch.liveRefreshEnabled.call(vm, false);
    feeds[0].message({ type: "feed_data", data: [{ id: "b" }, { id: "a" }] });
    feeds[0].message({ type: "feed_error", message: "paused error" });
    feeds[0].unavailable();
    await vm.load({ silent: true });
    assert.equal(feeds[0].closed, true);
    assert.equal(reads.length, 0);
    assert.equal(vm[rows], initialRows);
    assert.equal(vm.lastUpdated, initialTime);
    assert.equal(vm.error, "");
    const manual = vm.load();
    reads[0].resolve([{ id: "manual" }]);
    await manual;
    assert.equal(vm[rows][0].id, "manual");
    assert.equal(feeds.length, 1);
    vm.liveRefreshEnabled = true;
    definition.watch.liveRefreshEnabled.call(vm, true);
    feeds[1].message({ type: "feed_data", data: [{ id: "fresh" }] });
    feeds[0].message({ type: "feed_data", data: [{ id: "obsolete" }] });
    assert.equal(vm[rows][0].id, "fresh");
    definition.beforeUnmount.call(vm);
    feeds[1].message({ type: "feed_error", message: "unmounted" });
    feeds[1].unavailable();
    assert.equal(vm.error, "");
    assert.equal(feeds[1].closed, true);
  });

  for (const outcome of ["resolve", "reject"]) {
    test(`${name}: fallback ${outcome} is inert across pause, period change and unmount`, async () => {
      for (const change of ["pause", "period", "unmount", "frame"]) {
        const { store, feeds, reads } = feedStore();
        const { vm, definition } = await optionsView(name, store);
        vm.openFeed();
        feeds[0].message({ type: "feed_data", data: [{ id: "initial" }] });
        const pending = vm.load({ silent: true });
        if (change === "pause") {
          vm.liveRefreshEnabled = false;
          definition.watch.liveRefreshEnabled.call(vm, false);
        } else if (change === "period") {
          store.state.timeRange = "24h";
          definition.watch["store.state.timeRange"].call(vm);
        } else if (change === "unmount") definition.beforeUnmount.call(vm);
        else feeds[0].message({ type: "feed_data", data: [{ id: "stream" }] });
        const currentRows = vm[rows];
        const currentTime = vm.lastUpdated;
        const currentLoading = vm.loading;
        reads[0][outcome](outcome === "resolve" ? [{ id: "old HTTP" }] : new Error("old failure"));
        await pending;
        assert.equal(vm[rows], currentRows, change);
        assert.equal(vm.lastUpdated, currentTime, change);
        assert.equal(vm.error, "", change);
        assert.equal(vm.loading, currentLoading, change);
        definition.beforeUnmount.call(vm);
      }
    });
  }
}

test("protocol fallback runs without traffic and recovery cancels pending HTTP", async t => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const { store, reads, feeds } = feedStore();
  const { vm, definition } = await optionsView("ProtocolsView", store);
  t.after(() => definition.beforeUnmount.call(vm));
  const request = vm.load();
  reads[0].resolve(snapshot("initial"));
  await request;
  feeds[0].unavailable();
  t.mock.timers.tick(10000);
  assert.equal(reads.length, 2);
  assert.equal(feeds[0].closed, true);
  feeds[0].message(frame("obsolete after fallback started"));
  reads[1].resolve(snapshot("fallback"));
  await Promise.resolve();
  assert.equal(vm.packetRows[0].id, "fallback");
  feeds[1].message({ type: "feed_error", message: "temporary failure" });
  assert.ok(vm.wsRefreshTimer);
  feeds[1].message(frame("recovered"));
  t.mock.timers.tick(10000);
  assert.equal(reads.length, 2, "a recovered feed cancels its fallback");
  assert.equal(vm.packetRows[0].id, "recovered");
  assert.equal(vm.error, "");
});

test("protocol view interoperates with the real appStore.openDataFeed transport", async t => {
  const { default: appStore } = await import("../src/state/appStore.js");
  const originalWindow = globalThis.window;
  const originalSource = globalThis.EventSource;
  const initial = { apiBase: appStore.state.apiBase, timeRange: appStore.state.timeRange,
    authToken: appStore.state.authToken, shutdownPending: appStore.state.shutdownPending };
  const sources = [];
  class Source {
    constructor(url) { this.url = url; sources.push(this); }
    addEventListener() {}
    close() { this.closed = true; }
    emit(payload) { this.onmessage({ data: JSON.stringify(payload) }); }
  }
  globalThis.EventSource = Source;
  globalThis.window = { location: { origin: "http://fixture.invalid" } };
  Object.assign(appStore.state, { apiBase: "http://fixture.invalid", timeRange: "24h", authToken: "", shutdownPending: false });
  const { vm, definition } = await optionsView("ProtocolsView", {
    ...appStore, fetchProtocolSnapshot: async () => snapshot("http"),
  });
  t.after(() => {
    definition.beforeUnmount.call(vm);
    Object.assign(appStore.state, initial);
    globalThis.window = originalWindow;
    globalThis.EventSource = originalSource;
  });
  await vm.load();
  const url = new URL(sources[0].url);
  assert.equal(url.pathname, "/realtime/stream");
  assert.equal(url.searchParams.get("feed"), "protocols");
  assert.equal(url.searchParams.get("proto"), "tcp");
  assert.equal(url.searchParams.get("since"), "24h");
  assert.equal(url.searchParams.get("limit"), "100");
  assert.equal(url.searchParams.get("refresh"), "1000");
  sources[0].emit(frame("transport"));
  assert.equal(vm.packetRows[0].id, "transport");
  vm.liveRefreshEnabled = false;
  definition.watch.liveRefreshEnabled.call(vm, false);
  assert.equal(sources[0].closed, true);
  sources[0].emit(frame("late transport"));
  assert.equal(vm.packetRows[0].id, "transport");
});
