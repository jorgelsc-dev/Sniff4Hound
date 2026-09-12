<template>
  <v-app-bar color="transparent" flat height="40" class="top-bar">
    <v-container class="d-flex align-center app-topbar">
      <div class="brand-lockup">
        <div class="brand-avatar mr-2">
          <BrandMark :size="30" />
        </div>
        <div class="brand-copy">
          <div class="text-body-2 font-weight-bold">Sniff4Hound</div>
        </div>
      </div>

      <v-spacer />

      <div class="status-rail">
        <NotificationBell />
        <v-btn
          icon
          color="error"
          variant="tonal"
          size="small"
          density="comfortable"
          class="shutdown-btn"
          :loading="shutdownPending"
          :disabled="shutdownPending"
          :aria-label="shutdownPending ? shutdownLabel || 'Stopping...' : 'Stop App'"
          @click="$emit('shutdown-app')"
        >
          <v-icon icon="mdi-power" />
          <v-tooltip activator="parent" location="bottom">
            {{ shutdownPending ? (shutdownLabel || "Stopping...") : "Stop App" }}
          </v-tooltip>
        </v-btn>
      </div>
    </v-container>
  </v-app-bar>
</template>

<script>
import BrandMark from "../brand/BrandMark.vue";
import NotificationBell from "./NotificationBell.vue";

export default {
  name: "AppTopBar",
  components: {
    BrandMark,
    NotificationBell,
  },
  props: {
    shutdownPending: {
      type: Boolean,
      default: false,
    },
    shutdownLabel: {
      type: String,
      default: "",
    },
  },
  emits: ["shutdown-app"],
};
</script>

<style scoped>
.top-bar {
  position: relative;
  overflow: hidden;
  border-bottom: 1px solid rgba(var(--brand-sky-rgb), 0.18);
  backdrop-filter: blur(18px) saturate(130%);
  background:
    radial-gradient(circle at 18% 0%, rgba(var(--brand-cyan-rgb), 0.14), transparent 34%),
    radial-gradient(circle at 82% 0%, rgba(var(--brand-violet-rgb), 0.16), transparent 40%),
    linear-gradient(180deg, rgba(6, 11, 18, 0.94) 0%, rgba(9, 17, 29, 0.78) 72%, rgba(9, 17, 29, 0.18) 100%);
  box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.03);
}

.top-bar::after {
  content: "";
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  height: 2px;
  background: linear-gradient(
    90deg,
    rgba(var(--brand-cyan-rgb), 0),
    rgba(var(--brand-cyan-rgb), 0.95),
    rgba(var(--brand-blue-rgb), 0.94),
    rgba(var(--brand-violet-rgb), 0.96),
    rgba(var(--brand-cyan-rgb), 0)
  );
  pointer-events: none;
}

.app-topbar {
  max-width: 1560px;
  width: 100%;
}

.brand-lockup {
  display: flex;
  align-items: center;
  min-width: 0;
}

.brand-avatar {
  width: 30px;
  height: 30px;
  flex: 0 0 30px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border-radius: 10px;
  border: 1px solid rgba(var(--brand-cyan-rgb), 0.22);
  background:
    radial-gradient(circle at 24% 22%, rgba(var(--brand-cyan-rgb), 0.14), transparent 44%),
    linear-gradient(145deg, rgba(10, 16, 27, 0.92), rgba(7, 12, 21, 0.86));
  box-shadow:
    0 0 0 1px rgba(var(--brand-violet-rgb), 0.12),
    0 0 12px rgba(var(--brand-cyan-rgb), 0.16);
  overflow: hidden;
}

.brand-copy {
  min-width: 0;
}

.brand-copy .text-body-2 {
  letter-spacing: 0.03em;
}

.status-rail {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: 6px;
  min-width: 0;
}

.shutdown-btn {
  letter-spacing: 0.04em;
  text-transform: uppercase;
}
</style>
