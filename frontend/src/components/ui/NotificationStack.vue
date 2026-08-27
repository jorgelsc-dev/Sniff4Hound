<template>
  <div class="notification-stack" aria-live="polite">
    <button
      v-if="items.length"
      type="button"
      class="notification-toolbar"
      :aria-label="soundEnabled ? 'Mute notification sounds' : 'Unmute notification sounds'"
      @click="toggleSound"
    >
      <v-icon :icon="soundEnabled ? 'mdi-volume-high' : 'mdi-volume-off'" size="14" />
      <span>{{ soundEnabled ? "Sound on" : "Muted" }}</span>
      <span class="notification-toolbar-divider" />
      <span class="notification-toolbar-clear" @click.stop="clearAll">Clear all</span>
    </button>

    <transition-group name="notif" tag="div" class="notification-list">
      <div
        v-for="item in items"
        :key="item.id"
        class="notification-card"
        :class="[`severity-${item.severity}`, { 'is-actionable': item.href }]"
        role="status"
        @click="handleCardClick(item)"
      >
        <v-icon class="notification-icon" :icon="iconFor(item)" size="18" />
        <div class="notification-body">
          <div class="notification-title-row">
            <span class="notification-title">{{ item.title }}</span>
            <v-chip v-if="item.count > 1" size="x-small" variant="flat" color="primary" class="notification-count">
              ×{{ item.count }}
            </v-chip>
          </div>
          <div v-if="item.message" class="notification-message">{{ item.message }}</div>
        </div>
        <button
          type="button"
          class="notification-close"
          aria-label="Dismiss notification"
          @click.stop="dismiss(item.id)"
        >
          <v-icon icon="mdi-close" size="14" />
        </button>
      </div>
    </transition-group>
  </div>
</template>

<script>
import store from "../../state/appStore";

const AUTO_DISMISS_MS = {
  critical: 20000,
  high: 14000,
  medium: 9000,
  low: 7000,
  info: 6000,
};

const ICONS_BY_KIND = {
  monitor: "mdi-shield-alert",
  runtime: "mdi-swap-horizontal-bold",
  broadcast: "mdi-bullhorn",
  connection: "mdi-lan-connect",
};

// Only the most recent MAX_VISIBLE notifications are ever shown at once -
// older ones stay in history (for "Clear all") but drop out of view rather
// than piling the stack up indefinitely.
const MAX_VISIBLE = 3;

export default {
  name: "NotificationStack",
  data() {
    return {
      store,
      timers: new Map(),
    };
  },
  computed: {
    items() {
      return this.store.state.notifications.filter((item) => !item.toastDismissed).slice(0, MAX_VISIBLE);
    },
    soundEnabled() {
      return Boolean(this.store.state.notifySoundEnabled);
    },
  },
  watch: {
    items(current) {
      const liveIds = new Set(current.map((item) => item.id));
      for (const id of this.timers.keys()) {
        if (!liveIds.has(id)) {
          clearTimeout(this.timers.get(id));
          this.timers.delete(id);
        }
      }
      current.forEach((item) => {
        if (this.timers.has(item.id)) return;
        const delay = AUTO_DISMISS_MS[item.severity] || AUTO_DISMISS_MS.info;
        const timer = setTimeout(() => this.dismiss(item.id), delay);
        this.timers.set(item.id, timer);
      });
    },
  },
  beforeUnmount() {
    this.timers.forEach((timer) => clearTimeout(timer));
    this.timers.clear();
  },
  methods: {
    iconFor(item) {
      return ICONS_BY_KIND[item.kind] || "mdi-bell-ring";
    },
    dismiss(id) {
      this.store.dismissToast(id);
    },
    handleCardClick(item) {
      if (item.href) {
        this.$router.push(item.href);
      }
      this.dismiss(item.id);
    },
    clearAll() {
      this.store.dismissAllToasts();
    },
    toggleSound() {
      this.store.setNotifySoundEnabled(!this.soundEnabled);
    },
  },
};
</script>

<style scoped>
.notification-stack {
  position: fixed;
  right: 18px;
  bottom: 18px;
  z-index: 3000;
  display: flex;
  flex-direction: column;
  align-items: flex-end;
  gap: 8px;
  width: min(360px, calc(100vw - 32px));
  pointer-events: none;
}

.notification-toolbar {
  pointer-events: auto;
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 4px 10px;
  border-radius: 999px;
  border: 1px solid rgba(102, 212, 255, 0.22);
  background: rgba(9, 16, 28, 0.9);
  color: rgba(210, 223, 238, 0.82);
  font-size: 0.72rem;
  cursor: pointer;
  align-self: flex-end;
}

.notification-toolbar-divider {
  width: 1px;
  height: 12px;
  background: rgba(210, 223, 238, 0.24);
}

.notification-toolbar-clear {
  color: rgba(52, 230, 255, 0.9);
}

.notification-toolbar-clear:hover {
  text-decoration: underline;
}

.notification-list {
  position: relative;
  display: flex;
  flex-direction: column;
  gap: 8px;
  width: 100%;
}

.notification-card {
  pointer-events: auto;
  display: flex;
  align-items: flex-start;
  gap: 10px;
  width: 100%;
  padding: 12px 12px;
  border-radius: 14px;
  border: 1px solid rgba(102, 212, 255, 0.22);
  background:
    radial-gradient(circle at top right, rgba(52, 230, 255, 0.1), transparent 45%),
    linear-gradient(160deg, rgba(11, 17, 27, 0.97), rgba(13, 20, 32, 0.98));
  box-shadow: 0 14px 30px rgba(2, 7, 14, 0.4), inset 0 0 0 1px rgba(255, 255, 255, 0.02);
  cursor: pointer;
}

.notification-card.severity-critical,
.notification-card.severity-high {
  border-color: rgba(255, 100, 122, 0.45);
}

.notification-card.severity-medium {
  border-color: rgba(245, 187, 98, 0.4);
}

.notification-card.severity-low {
  border-color: rgba(75, 143, 255, 0.4);
}

.notification-card.is-actionable:hover {
  border-color: rgba(52, 230, 255, 0.55);
  box-shadow: 0 14px 30px rgba(2, 7, 14, 0.4), 0 0 0 1px rgba(52, 230, 255, 0.2);
}

.notification-icon {
  margin-top: 2px;
  flex: 0 0 auto;
  color: rgba(52, 230, 255, 0.9);
}

.severity-critical .notification-icon,
.severity-high .notification-icon {
  color: #ff647a;
}

.severity-medium .notification-icon {
  color: #f5bb62;
}

.severity-low .notification-icon {
  color: #4b8fff;
}

.notification-body {
  flex: 1 1 auto;
  min-width: 0;
}

.notification-title-row {
  display: flex;
  align-items: center;
  gap: 6px;
}

.notification-title {
  font-size: 0.84rem;
  font-weight: 700;
  color: rgba(233, 241, 250, 0.96);
  line-height: 1.3;
  word-break: break-word;
}

.notification-count {
  flex: 0 0 auto;
  font-weight: 700;
}

.notification-message {
  margin-top: 2px;
  font-size: 0.76rem;
  color: rgba(200, 214, 230, 0.78);
  line-height: 1.35;
  word-break: break-word;
}

.notification-close {
  flex: 0 0 auto;
  display: grid;
  place-items: center;
  width: 22px;
  height: 22px;
  margin: -2px -2px 0 0;
  border-radius: 999px;
  border: none;
  background: transparent;
  color: rgba(210, 223, 238, 0.6);
  cursor: pointer;
}

.notification-close:hover {
  background: rgba(255, 255, 255, 0.08);
  color: rgba(233, 241, 250, 0.95);
}

.notif-enter-active,
.notif-leave-active {
  transition: opacity 0.2s ease, transform 0.22s ease;
}

.notif-enter-from,
.notif-leave-to {
  opacity: 0;
  transform: translateY(10px) scale(0.98);
}

.notif-leave-active {
  position: absolute;
}

@media (max-width: 600px) {
  .notification-stack {
    right: 10px;
    bottom: 10px;
    left: 10px;
    width: auto;
    align-items: stretch;
  }

  .notification-toolbar {
    align-self: flex-end;
  }
}
</style>
