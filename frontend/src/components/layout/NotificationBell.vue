<template>
  <v-menu location="bottom end" :close-on-content-click="false" max-width="380">
    <template #activator="{ props: menuProps }">
      <v-btn
        icon
        variant="text"
        size="small"
        class="bell-trigger"
        aria-label="Notifications"
        v-bind="menuProps"
      >
        <v-badge
          :model-value="totalCount > 0"
          :content="badgeContent"
          color="error"
          floating
          offset-x="2"
          offset-y="2"
        >
          <v-icon icon="mdi-bell-outline" size="22" />
        </v-badge>
      </v-btn>
    </template>

    <v-card class="bell-menu" rounded="lg">
      <div class="bell-menu-header">
        <span class="text-subtitle-2">Notifications</span>
        <button
          v-if="items.length"
          type="button"
          class="bell-menu-clear"
          @click="clearAll"
        >
          Clear all
        </button>
      </div>

      <div v-if="!items.length" class="bell-menu-empty">
        <v-icon icon="mdi-bell-sleep-outline" size="26" class="mb-2" />
        <div class="text-body-2">No notifications yet</div>
      </div>

      <div v-else class="bell-menu-list">
        <div
          v-for="item in items"
          :key="item.id"
          class="bell-menu-item"
          :class="[`severity-${item.severity}`, { 'is-actionable': item.href }]"
          @click="handleItemClick(item)"
        >
          <v-icon class="bell-menu-item-icon" :icon="iconFor(item)" size="16" />
          <div class="bell-menu-item-body">
            <div class="bell-menu-item-title-row">
              <span class="bell-menu-item-title">{{ item.title }}</span>
              <v-chip v-if="item.count > 1" size="x-small" variant="flat" color="primary">
                ×{{ item.count }}
              </v-chip>
            </div>
            <div v-if="item.message" class="bell-menu-item-message">{{ item.message }}</div>
            <div class="bell-menu-item-time">{{ relativeTime(item.createdAt) }}</div>
          </div>
          <button
            type="button"
            class="bell-menu-item-close"
            aria-label="Dismiss notification"
            @click.stop="dismiss(item.id)"
          >
            <v-icon icon="mdi-close" size="13" />
          </button>
        </div>
      </div>
    </v-card>
  </v-menu>
</template>

<script>
import store from "../../state/appStore";

const ICONS_BY_KIND = {
  monitor: "mdi-shield-alert",
  runtime: "mdi-swap-horizontal-bold",
  broadcast: "mdi-bullhorn",
  connection: "mdi-lan-connect",
};

export default {
  name: "NotificationBell",
  data() {
    return {
      store,
      now: Date.now(),
      clockTimer: null,
    };
  },
  computed: {
    items() {
      return this.store.state.notifications;
    },
    totalCount() {
      return this.items.length;
    },
    badgeContent() {
      return this.totalCount > 9 ? "9+" : String(this.totalCount);
    },
  },
  mounted() {
    // Keeps "x minutes ago" labels fresh while the menu is left open.
    this.clockTimer = setInterval(() => {
      this.now = Date.now();
    }, 30000);
  },
  beforeUnmount() {
    if (this.clockTimer) {
      clearInterval(this.clockTimer);
      this.clockTimer = null;
    }
  },
  methods: {
    iconFor(item) {
      return ICONS_BY_KIND[item.kind] || "mdi-bell-ring";
    },
    dismiss(id) {
      this.store.dismissNotification(id);
    },
    clearAll() {
      this.store.clearNotifications();
    },
    handleItemClick(item) {
      if (item.href) {
        this.$router.push(item.href);
      }
    },
    relativeTime(timestamp) {
      const deltaSeconds = Math.max(0, Math.round((this.now - timestamp) / 1000));
      if (deltaSeconds < 5) return "just now";
      if (deltaSeconds < 60) return `${deltaSeconds}s ago`;
      const minutes = Math.round(deltaSeconds / 60);
      if (minutes < 60) return `${minutes}m ago`;
      const hours = Math.round(minutes / 60);
      if (hours < 24) return `${hours}h ago`;
      return `${Math.round(hours / 24)}d ago`;
    },
  },
};
</script>

<style scoped>
.bell-trigger {
  color: rgba(210, 223, 238, 0.85);
}

.bell-menu {
  width: 360px;
  max-height: 480px;
  display: flex;
  flex-direction: column;
  border: 1px solid rgba(102, 212, 255, 0.22);
  background:
    radial-gradient(circle at top right, rgba(52, 230, 255, 0.1), transparent 45%),
    linear-gradient(160deg, rgba(11, 17, 27, 0.98), rgba(13, 20, 32, 0.99));
}

.bell-menu-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 12px 14px;
  border-bottom: 1px solid rgba(255, 255, 255, 0.06);
  flex: 0 0 auto;
}

.bell-menu-clear {
  font-size: 0.72rem;
  color: rgba(52, 230, 255, 0.9);
  cursor: pointer;
}

.bell-menu-clear:hover {
  text-decoration: underline;
}

.bell-menu-empty {
  padding: 28px 16px;
  text-align: center;
  color: rgba(200, 214, 230, 0.6);
}

.bell-menu-list {
  overflow-y: auto;
  flex: 1 1 auto;
}

.bell-menu-item {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  padding: 10px 14px;
  border-bottom: 1px solid rgba(255, 255, 255, 0.04);
  cursor: default;
}

.bell-menu-item.is-actionable {
  cursor: pointer;
}

.bell-menu-item.is-actionable:hover {
  background: rgba(52, 230, 255, 0.06);
}

.bell-menu-item-icon {
  margin-top: 2px;
  flex: 0 0 auto;
  color: rgba(52, 230, 255, 0.9);
}

.bell-menu-item.severity-critical .bell-menu-item-icon,
.bell-menu-item.severity-high .bell-menu-item-icon {
  color: #ff647a;
}

.bell-menu-item.severity-medium .bell-menu-item-icon {
  color: #f5bb62;
}

.bell-menu-item.severity-low .bell-menu-item-icon {
  color: #4b8fff;
}

.bell-menu-item-body {
  flex: 1 1 auto;
  min-width: 0;
}

.bell-menu-item-title-row {
  display: flex;
  align-items: center;
  gap: 6px;
}

.bell-menu-item-title {
  font-size: 0.8rem;
  font-weight: 700;
  color: rgba(233, 241, 250, 0.96);
  word-break: break-word;
}

.bell-menu-item-message {
  margin-top: 2px;
  font-size: 0.72rem;
  color: rgba(200, 214, 230, 0.75);
  word-break: break-word;
}

.bell-menu-item-time {
  margin-top: 3px;
  font-size: 0.66rem;
  color: rgba(200, 214, 230, 0.45);
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

.bell-menu-item-close {
  flex: 0 0 auto;
  display: grid;
  place-items: center;
  width: 20px;
  height: 20px;
  margin: -2px -2px 0 0;
  border-radius: 999px;
  border: none;
  background: transparent;
  color: rgba(210, 223, 238, 0.5);
  cursor: pointer;
}

.bell-menu-item-close:hover {
  background: rgba(255, 255, 255, 0.08);
  color: rgba(233, 241, 250, 0.95);
}
</style>
