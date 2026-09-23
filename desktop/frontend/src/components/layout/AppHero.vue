<template>
  <v-sheet class="hero-banner" rounded="xl">
    <v-row align="stretch" class="pa-6 pa-md-8" dense>
      <v-col cols="12" md="6" class="hero-intro">
        <div class="text-overline text-primary">Network telemetry</div>
        <div class="text-h4 text-md-h3 font-weight-bold">Sniff4Hound Control Room</div>
        <div class="text-body-1 text-medium-emphasis mt-2">
          Start and configure packet capture or the honeypot from their own dedicated views,
          then drill into passive capture, honeypot hits, and detection monitors from here.
        </div>
        <div class="d-flex flex-wrap ga-3 mt-4">
          <v-btn color="primary" variant="flat" to="/sniffer">Sniffer</v-btn>
          <v-btn color="warning" variant="outlined" to="/honeypot">Honeypot</v-btn>
          <v-btn color="info" variant="outlined" to="/monitors">Monitors</v-btn>
        </div>
        <v-alert
          class="usage-notice mt-5"
          type="warning"
          variant="tonal"
          density="comfortable"
          icon="mdi-shield-check-outline"
        >
          Authorized use only. Run Sniff4Hound exclusively on systems, networks and IP ranges you
          own or administer, and only activate listener mode where you are allowed to bind the
          selected ports.
        </v-alert>
      </v-col>

      <v-col cols="12" md="6" class="hero-metrics-col">
        <div class="hero-metrics">
          <div class="hero-metrics__header">
            <div class="text-overline text-primary">Application metrics</div>
            <div class="text-caption text-medium-emphasis">
              Live snapshot of everything Sniff4Hound has recorded so far.
            </div>
          </div>
          <div class="hero-metrics__grid">
            <div v-for="metric in metrics" :key="metric.key" class="hero-metric">
              <v-icon :icon="metric.icon" class="hero-metric__icon" :class="metric.colorClass" />
              <div class="hero-metric__copy">
                <div class="hero-metric__value" :class="metric.colorClass">{{ metric.value }}</div>
                <div class="hero-metric__label">{{ metric.label }}</div>
              </div>
            </div>
          </div>
        </div>
      </v-col>
    </v-row>
  </v-sheet>
</template>

<script>
import store from "../../state/appStore";

const REFRESH_EVENT_TYPES = new Set(["packet", "stats_update", "runtime_mode"]);
const REFRESH_DEBOUNCE_MS = 10000;

export default {
  name: "AppHero",
  data() {
    return {
      store,
      counts: {},
      wsClientCount: 0,
      refreshTimer: null,
      stopTableRefreshSubscription: null,
    };
  },
  computed: {
    metrics() {
      return [
        {
          key: "packets",
          label: "Packets captured",
          value: Number(this.counts.count_ports || 0),
          icon: "mdi-ethernet",
          colorClass: "text-success",
        },
        {
          key: "tags",
          label: "Tags recorded",
          value: Number(this.counts.count_tags || 0),
          icon: "mdi-tag-multiple",
          colorClass: "text-primary",
        },
        {
          key: "responses",
          label: "Banners / responses",
          value: Number(this.counts.count_banners || 0),
          icon: "mdi-server-network",
          colorClass: "text-info",
        },
        {
          key: "monitors",
          label: "Active monitors",
          value: Number(this.counts.count_monitors || 0),
          icon: "mdi-radar",
          colorClass: "text-warning",
        },
        {
          key: "domains",
          label: "Domains seen",
          value: Number(this.counts.count_domains || 0),
          icon: "mdi-web",
          colorClass: "text-secondary",
        },
        {
          key: "clients",
          label: "Dashboards online",
          value: this.wsClientCount,
          icon: "mdi-monitor-dashboard",
          colorClass: "text-success",
        },
      ];
    },
  },
  mounted() {
    this.load();
    this.stopTableRefreshSubscription = this.store.subscribeTableRefresh(this.handleWsRefresh);
  },
  beforeUnmount() {
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
      this.refreshTimer = null;
    }
    if (typeof this.stopTableRefreshSubscription === "function") {
      this.stopTableRefreshSubscription();
      this.stopTableRefreshSubscription = null;
    }
  },
  methods: {
    load() {
      return this.store
        .fetchJsonPromise("/api/dashboard/?compact=1")
        .then((data) => {
          this.counts = (data && data.counts) || {};
          this.wsClientCount = Array.isArray(data && data.ws_clients) ? data.ws_clients.length : 0;
        })
        .catch(() => {
          // Purely decorative panel - keep whatever we last had on a transient failure.
        });
    },
    handleWsRefresh(event) {
      const eventType = String((event && event.type) || "").trim().toLowerCase();
      if (!REFRESH_EVENT_TYPES.has(eventType)) return;
      if (this.refreshTimer) return;
      this.refreshTimer = setTimeout(() => {
        this.refreshTimer = null;
        this.load();
      }, REFRESH_DEBOUNCE_MS);
    },
  },
};
</script>

<style scoped>
.hero-banner {
  position: relative;
  overflow: hidden;
  background:
    radial-gradient(110% 140% at -8% -24%, rgba(var(--brand-cyan-rgb), 0.2), transparent 58%),
    radial-gradient(90% 110% at 110% -30%, rgba(var(--brand-violet-rgb), 0.18), transparent 63%),
    linear-gradient(122deg, rgba(9, 14, 23, 0.98), rgba(7, 12, 20, 0.98));
  border: 1px solid rgba(var(--brand-sky-rgb), 0.22);
  box-shadow: 0 28px 56px rgba(2, 7, 14, 0.44), inset 0 0 0 1px rgba(255, 255, 255, 0.03);
}

.hero-banner::before {
  content: "";
  position: absolute;
  left: -8%;
  right: -8%;
  bottom: -80px;
  height: 220px;
  background: radial-gradient(
    60% 100% at 50% 100%,
    rgba(var(--brand-violet-rgb), 0.2),
    rgba(var(--brand-violet-rgb), 0)
  );
  pointer-events: none;
}

.usage-notice {
  border: 1px solid rgba(var(--brand-violet-rgb), 0.22);
  background:
    linear-gradient(180deg, rgba(23, 18, 46, 0.82), rgba(12, 15, 28, 0.64)) !important;
}

.hero-banner :deep(.v-btn) {
  letter-spacing: 0.04em;
}

.hero-intro {
  min-width: 0;
}

.hero-metrics-col {
  min-width: 0;
  display: flex;
}

.hero-metrics {
  width: 100%;
  display: flex;
  flex-direction: column;
  border-radius: 18px;
  border: 1px solid rgba(var(--brand-cyan-rgb), 0.18);
  background:
    radial-gradient(120% 140% at 100% 0%, rgba(var(--brand-violet-rgb), 0.14), transparent 60%),
    linear-gradient(180deg, rgba(10, 17, 28, 0.72), rgba(7, 12, 21, 0.6));
  padding: 20px;
}

@media (min-width: 960px) {
  .hero-metrics {
    height: 100%;
  }
}

.hero-metrics__header {
  margin-bottom: 14px;
}

.hero-metrics__grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 10px;
}

.hero-metric {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 12px;
  border-radius: 14px;
  border: 1px solid rgba(var(--brand-sky-rgb), 0.12);
  background: rgba(4, 10, 18, 0.44);
}

.hero-metric__icon {
  flex: 0 0 auto;
  opacity: 0.92;
}

.hero-metric__copy {
  min-width: 0;
}

.hero-metric__value {
  font-size: 1.15rem;
  font-weight: 700;
  line-height: 1.2;
}

.hero-metric__label {
  font-size: 0.72rem;
  color: rgba(176, 199, 220, 0.76);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

@media (max-width: 959px) {
  .hero-metrics {
    margin-top: 24px;
  }
}
</style>
