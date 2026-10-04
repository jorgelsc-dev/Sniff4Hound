<template>
  <section v-if="expanded" class="flow-shell">
    <SystemFlowCanvas
      :totals="totals"
      :runtime="runtime"
      :activity="activity"
      :online="online"
      @open="open"
    />
    <button type="button" class="flow-shell__toggle" aria-expanded="true" @click="expanded = false">
      <v-icon icon="mdi-chevron-up" size="16" />
      Ocultar tubería
    </button>
  </section>

  <button v-else type="button" class="flow-shell__strip" aria-expanded="false" @click="expanded = true">
    <span class="flow-shell__pulse" :class="online ? (capturing ? 'is-live' : 'is-ready') : 'is-off'" />
    <strong>{{ online ? 'Tubería de captura' : 'Sensor desconectado' }}</strong>
    <span class="flow-shell__strip-meta">{{ stripMeta }}</span>
    <v-icon icon="mdi-chevron-down" size="16" />
  </button>
</template>

<script>
import SystemFlowCanvas from "../flow/SystemFlowCanvas.vue";
import store from "../../state/appStore";

const STORAGE_KEY = "sniff4hound.flowShell.expanded";

/**
 * The capture pipeline as a persistent shell rather than a widget owned by
 * one page.
 *
 * It used to live inside DashboardHubView, so it existed on exactly one
 * route and clicking a node navigated *away* from it - the canvas was a menu
 * you left behind, which is why moving between Sniffer/Honeypot/Monitors felt
 * like separate apps. Mounted here it stays put while `<router-view>` swaps
 * underneath, so a click reads as "show me this stage's table" instead of
 * "go somewhere else".
 *
 * Navigation is still a real `router.push`. Rendering the target view outside
 * its own route would leave `useRoute()` inside it pointing at whatever route
 * the app is actually on - ProtocolsView reads `:proto?` that way - so the
 * table would quietly show the wrong slice.
 */
export default {
  name: "FlowShell",
  components: { SystemFlowCanvas },
  data() {
    return {
      store,
      expanded: false,
      counts: {},
      protocolCount: 0,
      refreshTimer: null,
      unsubscribe: null,
      requestId: 0,
    };
  },
  computed: {
    runtime() {
      return store.state.runtime || {};
    },
    activity() {
      return store.state.liveActivity;
    },
    online() {
      return store.state.wsStatus === "online";
    },
    capturing() {
      return Boolean(this.runtime.sniffer?.running || this.runtime.honeypot?.running);
    },
    // Field names mirror dashboard_snapshot()/analytics_snapshot() exactly -
    // see the equivalent block that used to live in DashboardHubView.
    totals() {
      const sniffer = this.runtime.sniffer || {};
      return {
        interfaces: (sniffer.interfaces || []).length,
        packets: this.counts.count_ports,
        protocols: this.protocolCount,
        monitors: this.counts.count_monitors,
        payloads: this.counts.count_banners,
        detections: this.counts.count_tags,
      };
    },
    stripMeta() {
      const rate = Number(this.activity?.total) || 0;
      return `${rate >= 10 ? Math.round(rate) : rate.toFixed(1)} paq/s`;
    },
  },
  watch: {
    expanded(value) {
      try {
        window.localStorage.setItem(STORAGE_KEY, value ? "1" : "0");
      } catch {
        // Private mode / storage disabled: the preference just does not stick.
      }
      if (value) this.load();
    },
  },
  mounted() {
    try {
      const preference = window.localStorage.getItem(STORAGE_KEY);
      if (preference !== null) this.expanded = preference !== "0";
    } catch {
      // Keep the compact default when storage is unavailable.
    }
    this.load();
    // Same coalescing the dashboard uses: a busy capture pushes packet events
    // continuously, and refetching counts on each one would put this shell in
    // a request loop for numbers that only need to be roughly current.
    this.unsubscribe = store.subscribeTableRefresh((event) => {
      if (!["packet", "stats_update", "runtime_mode"].includes(event?.type) || this.refreshTimer) return;
      this.refreshTimer = setTimeout(() => {
        this.refreshTimer = null;
        this.load();
      }, 10000);
    });
  },
  beforeUnmount() {
    this.requestId++;
    clearTimeout(this.refreshTimer);
    this.unsubscribe?.();
  },
  methods: {
    open(node) {
      if (node?.route && node.route !== this.$route.fullPath) this.$router.push(node.route);
    },
    async load() {
      if (!this.expanded) return;
      const id = ++this.requestId;
      const params = new URLSearchParams({ compact: "1" });
      if (store.state.timeRange) params.set("since", store.state.timeRange);
      // allSettled, not all: the protocol count is cosmetic (it only feeds
      // the canvas subline), so it must never be able to blank out the
      // packet/monitor counters if that one endpoint is slow or erroring.
      const [dashboard, analytics] = await Promise.allSettled([
        store.fetchJsonPromise(`/api/dashboard/?${params}`),
        store.fetchJsonPromise(`/api/charts/analytics?${params}`),
      ]);
      if (id !== this.requestId) return;
      if (dashboard.status === "fulfilled") {
        this.counts = (dashboard.value && dashboard.value.counts) || {};
      }
      if (analytics.status === "fulfilled") {
        this.protocolCount = (analytics.value?.ports_by_proto || []).length;
      }
    },
  },
};
</script>

<style scoped>
.flow-shell {
  position: relative;
  margin-bottom: 18px;
}

.flow-shell__toggle,
.flow-shell__strip {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  border: 1px solid var(--stroke);
  border-radius: var(--radius-md);
  background: var(--surface-1);
  color: var(--text-dim);
  font: inherit;
  font-size: 0.78rem;
  padding: 6px 11px;
  cursor: pointer;
  transition: border-color 0.16s ease, color 0.16s ease;
}

.flow-shell__toggle:hover,
.flow-shell__strip:hover {
  border-color: var(--stroke-strong);
  color: var(--text-soft);
}

.flow-shell__toggle {
  position: absolute;
  right: 10px;
  bottom: 10px;
  background: rgba(8, 14, 22, 0.88);
  backdrop-filter: blur(10px);
}

.flow-shell__strip {
  width: 100%;
  justify-content: flex-start;
  margin-bottom: 20px;
  min-height: 44px;
  text-align: left;
}

.flow-shell__strip strong {
  color: var(--text-soft);
  font-weight: 550;
}

.flow-shell__strip-meta {
  margin-left: auto;
  font-family: var(--font-mono);
  font-variant-numeric: tabular-nums;
}

.flow-shell__pulse {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: var(--text-dim);
  flex: 0 0 7px;
}

.flow-shell__pulse.is-live {
  background: #4ad7b7;
  box-shadow: 0 0 0 3px rgba(74, 215, 183, 0.16);
}

.flow-shell__pulse.is-off {
  background: #ff647a;
}

.flow-shell__pulse.is-ready {
  background: #f5bb62;
}

@media (max-width: 600px) {
  .flow-shell__strip { flex-wrap: wrap; gap: 6px; }
  .flow-shell__strip strong { flex: 1; font-size: 0.75rem; }
  .flow-shell__strip-meta { font-size: 0.7rem; }
}
</style>
