<template>
  <v-card :variant="variant" class="pa-6 data-panel">
    <div
      v-if="showHeader"
      class="d-flex align-center justify-space-between flex-wrap ga-2 mb-4 panel-head"
    >
      <div class="d-flex align-center ga-3">
        <span class="panel-pulse" :class="`panel-pulse--${liveState.tone}`" role="img" :aria-label="liveState.label">
          <v-tooltip activator="parent" location="bottom">{{ liveState.label }}</v-tooltip>
        </span>
        <div>
          <div class="text-subtitle-1 font-weight-medium">{{ title }}</div>
          <div v-if="subtitle" class="text-body-2 text-medium-emphasis">
            {{ subtitle }}
          </div>
        </div>
      </div>
      <div class="d-flex align-center ga-2">
        <v-chip v-if="count !== null && count !== undefined" size="small" variant="tonal" color="primary">
          {{ count }} {{ countLabel }}
        </v-chip>
        <v-chip v-if="lastUpdated" size="small" variant="outlined" color="info">
          {{ lastUpdated }}
        </v-chip>
        <slot name="header-actions" />
        <v-chip
          v-if="pendingUpdates > 0"
          size="small"
          variant="tonal"
          color="warning"
          class="panel-pending-chip"
          prepend-icon="mdi-arrow-up-bold-circle-outline"
          @click="emitRefresh"
        >
          {{ pendingUpdates }} new
          <v-tooltip activator="parent" location="bottom">
            Live updates are paused - click to pull the latest rows.
          </v-tooltip>
        </v-chip>
        <v-btn
          v-if="liveRefresh"
          icon
          size="small"
          variant="text"
          :color="liveEnabled ? 'success' : 'warning'"
          :aria-label="liveEnabled ? 'Pause live refresh' : 'Resume live refresh'"
          @click="toggleLive"
        >
          <v-icon :icon="liveEnabled ? 'mdi-pause-circle-outline' : 'mdi-play-circle-outline'" />
          <v-tooltip activator="parent" location="bottom">
            {{ liveEnabled ? "Pause live refresh (freeze this panel)" : "Resume live refresh" }}
          </v-tooltip>
        </v-btn>
        <v-btn
          v-if="canRefresh"
          icon
          size="small"
          variant="text"
          color="primary"
          :loading="loading"
          :aria-label="`Refresh ${title}`"
          @click="emitRefresh"
        >
          <v-icon icon="mdi-refresh" />
          <v-tooltip activator="parent" location="bottom">Refresh this panel</v-tooltip>
        </v-btn>
        <v-btn
          v-if="collapsible"
          icon
          size="small"
          variant="text"
          color="secondary"
          :aria-label="collapsed ? `Expand ${title}` : `Collapse ${title}`"
          @click="collapsed = !collapsed"
        >
          <v-icon :icon="collapsed ? 'mdi-chevron-down' : 'mdi-chevron-up'" />
          <v-tooltip activator="parent" location="bottom">{{ collapsed ? "Expand" : "Collapse" }}</v-tooltip>
        </v-btn>
      </div>
    </div>

    <v-alert v-if="error" type="error" variant="tonal" class="mb-4">
      {{ error }}
    </v-alert>

    <div v-show="!collapsed">
      <transition name="panel-fade">
        <div v-if="loading" class="panel-loader-shell">
          <BrandMark :size="58" animated framed />
          <div class="panel-loader-copy">
            <div class="panel-loader-title">Loading {{ title }}</div>
            <div class="panel-loader-text">
              {{ loadingText || "Fetching the latest rows from the API." }}
            </div>
          </div>
        </div>
      </transition>

      <div class="panel-body">
        <div
          v-if="!loading || keepContentOnLoading"
          class="panel-content"
          :class="{ 'panel-content--loading': loading && keepContentOnLoading }"
        >
          <slot />
        </div>
      </div>
    </div>
  </v-card>
</template>

<script>
import BrandMark from "../brand/BrandMark.vue";
import store from "../../state/appStore";

export default {
  name: "DataPanel",
  components: {
    BrandMark,
  },
  props: {
    title: {
      type: String,
      required: true,
    },
    subtitle: {
      type: String,
      default: "",
    },
    loading: {
      type: Boolean,
      default: false,
    },
    showSkeleton: {
      type: Boolean,
      default: false,
    },
    keepContentOnLoading: {
      type: Boolean,
      default: true,
    },
    error: {
      type: String,
      default: "",
    },
    lastUpdated: {
      type: String,
      default: "",
    },
    showHeader: {
      type: Boolean,
      default: true,
    },
    variant: {
      type: String,
      default: "outlined",
    },
    collapsible: {
      type: Boolean,
      default: false,
    },
    defaultCollapsed: {
      type: Boolean,
      default: false,
    },
    count: {
      type: [Number, String],
      default: null,
    },
    countLabel: {
      type: String,
      default: "items",
    },
    loadingText: {
      type: String,
      default: "",
    },
    // When true the panel renders the Live pause/resume control and starts
    // counting realtime events that arrive while it is paused.
    liveRefresh: {
      type: Boolean,
      default: false,
    },
    liveEnabled: {
      type: Boolean,
      default: true,
    },
    showRefresh: {
      type: Boolean,
      default: true,
    },
  },
  // "refresh" must be declared, not just emitted: an undeclared event
  // stays in $attrs and Vue also drops the listener onto the root <v-card>
  // as a stray DOM attribute.
  emits: ["refresh", "update:liveEnabled"],
  data() {
    return {
      store,
      collapsed: this.defaultCollapsed,
      pendingUpdates: 0,
      stopRealtimeSubscription: null,
    };
  },
  computed: {
    // "refresh" is intentionally NOT declared in emits so the listener stays
    // visible in $attrs: that is how the panel knows whether the parent
    // actually wired a handler, instead of rendering a dead button.
    canRefresh() {
      return Boolean(this.showRefresh && this.$attrs.onRefresh);
    },
    // The pulse used to animate unconditionally, which read as "data is
    // flowing" even with the capture stopped or the socket down. It now
    // reflects the two things that actually have to be true for that claim.
    liveState() {
      const wsStatus = String(this.store.state.wsStatus || "").trim().toLowerCase();
      const runtime = this.store.state.runtime && typeof this.store.state.runtime === "object"
        ? this.store.state.runtime
        : {};
      const sniffer = runtime.sniffer && typeof runtime.sniffer === "object" ? runtime.sniffer : {};
      const honeypot = runtime.honeypot && typeof runtime.honeypot === "object" ? runtime.honeypot : {};
      const capturing = Boolean(sniffer.running || honeypot.running);
      if (wsStatus === "locked") {
        return { tone: "offline", label: "Realtime locked - authenticate to resume the live stream" };
      }
      if (wsStatus !== "online") {
        return { tone: "offline", label: `Realtime ${wsStatus || "offline"} - showing the last loaded snapshot` };
      }
      if (!capturing) {
        return { tone: "idle", label: "Realtime connected, capture stopped - no new traffic is arriving" };
      }
      if (this.liveRefresh && !this.liveEnabled) {
        return { tone: "paused", label: "Live refresh paused - this panel is frozen for analysis" };
      }
      return { tone: "live", label: "Live - capture running and realtime stream connected" };
    },
  },
  watch: {
    liveEnabled(value) {
      if (value) this.pendingUpdates = 0;
    },
  },
  mounted() {
    if (!this.liveRefresh) return;
    this.stopRealtimeSubscription = this.store.subscribeTableRefresh((event) => {
      if (this.liveEnabled) {
        this.pendingUpdates = 0;
        return;
      }
      const count = Number(event && event.eventCount);
      this.pendingUpdates += Number.isFinite(count) && count > 0 ? count : 1;
    });
  },
  beforeUnmount() {
    if (typeof this.stopRealtimeSubscription === "function") {
      this.stopRealtimeSubscription();
      this.stopRealtimeSubscription = null;
    }
  },
  methods: {
    emitRefresh() {
      this.pendingUpdates = 0;
      this.$emit("refresh");
    },
    toggleLive() {
      this.$emit("update:liveEnabled", !this.liveEnabled);
    },
  },
};
</script>

<style scoped>
.data-panel {
  border-radius: 18px;
  overflow: hidden;
}

.panel-head {
  padding-bottom: 10px;
  border-bottom: 1px solid rgba(104, 178, 221, 0.14);
}

/* The dot is a status indicator, not decoration: it only animates while data
   is genuinely arriving (see DataPanel.liveState). */
.panel-pulse {
  width: 10px;
  height: 10px;
  flex: 0 0 10px;
  border-radius: 999px;
  background: rgba(140, 165, 188, 0.55);
  cursor: help;
}

.panel-pulse--live {
  background: rgba(74, 215, 183, 0.95);
  box-shadow: 0 0 0 0 rgba(74, 215, 183, 0.32);
  animation: panel-pulse 2.1s ease-in-out infinite;
}

.panel-pulse--idle {
  background: rgba(245, 187, 98, 0.85);
}

.panel-pulse--paused {
  background: rgba(142, 99, 255, 0.85);
}

.panel-pulse--offline {
  background: rgba(140, 165, 188, 0.45);
  box-shadow: inset 0 0 0 1px rgba(140, 165, 188, 0.6);
}

.panel-pending-chip {
  cursor: pointer;
}

.panel-loader-shell {
  display: flex;
  align-items: center;
  gap: 16px;
  margin-bottom: 16px;
  padding: 14px 16px;
  border-radius: 16px;
  border: 1px solid rgba(var(--brand-sky-rgb), 0.16);
  background:
    radial-gradient(circle at 14% 26%, rgba(var(--brand-cyan-rgb), 0.13), transparent 38%),
    radial-gradient(circle at 90% 82%, rgba(var(--brand-violet-rgb), 0.14), transparent 44%),
    linear-gradient(145deg, rgba(10, 17, 28, 0.9), rgba(8, 14, 23, 0.82));
  box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.03), 0 16px 32px rgba(2, 7, 13, 0.18);
}

.panel-loader-copy {
  min-width: 0;
}

.panel-loader-title {
  font-family: var(--font-heading);
  font-size: 0.76rem;
  font-weight: 680;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  color: rgba(236, 245, 255, 0.95);
}

.panel-loader-text {
  margin-top: 4px;
  color: var(--text-dim);
  font-size: 0.84rem;
  line-height: 1.45;
}

.panel-body {
  position: relative;
  min-height: 78px;
}

.panel-content {
  transition: opacity 0.18s ease;
}

.panel-content--loading {
  opacity: 0.54;
}

@keyframes panel-pulse {
  0%,
  100% {
    box-shadow: 0 0 0 0 rgba(74, 215, 183, 0.3);
  }
  50% {
    box-shadow: 0 0 0 8px rgba(74, 215, 183, 0);
  }
}

.panel-fade-enter-active,
.panel-fade-leave-active {
  transition: opacity 0.2s ease;
}

.panel-fade-enter-from,
.panel-fade-leave-to {
  opacity: 0;
}

@media (max-width: 600px) {
  .panel-loader-shell {
    align-items: flex-start;
  }
}

</style>
