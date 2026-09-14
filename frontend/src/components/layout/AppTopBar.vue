<template>
  <v-app-bar
    color="transparent"
    flat
    height="40"
    class="top-bar"
    :class="{ 'top-bar--desktop': desktopMode }"
  >
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
          :color="remoteBackend ? 'secondary' : 'error'"
          variant="tonal"
          size="small"
          density="comfortable"
          class="shutdown-btn"
          :loading="shutdownPending"
          :disabled="shutdownPending"
          :aria-label="shutdownPending ? shutdownLabel || 'Stopping...' : stopButtonLabel"
          @click="$emit('shutdown-app')"
        >
          <v-icon :icon="stopButtonIcon" />
          <v-tooltip activator="parent" location="bottom">
            {{ shutdownPending ? (shutdownLabel || "Stopping...") : stopButtonLabel }}
          </v-tooltip>
        </v-btn>
        <div v-if="desktopMode" class="desktop-window-controls" aria-label="Window controls">
          <v-btn
            icon
            variant="text"
            size="small"
            density="compact"
            aria-label="Minimize"
            @click="runDesktopWindowAction('minimize')"
          >
            <v-icon icon="mdi-window-minimize" />
            <v-tooltip activator="parent" location="bottom">Minimize</v-tooltip>
          </v-btn>
          <v-btn
            icon
            variant="text"
            size="small"
            density="compact"
            aria-label="Maximize"
            @click="runDesktopWindowAction('maximize')"
          >
            <v-icon icon="mdi-window-maximize" />
            <v-tooltip activator="parent" location="bottom">Maximize</v-tooltip>
          </v-btn>
          <v-btn
            icon
            variant="text"
            size="small"
            density="compact"
            color="error"
            aria-label="Close"
            @click="runDesktopWindowAction('close')"
          >
            <v-icon icon="mdi-close" />
            <v-tooltip activator="parent" location="bottom">Close</v-tooltip>
          </v-btn>
        </div>
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
    remoteBackend: {
      type: Boolean,
      default: false,
    },
  },
  emits: ["shutdown-app"],
  data() {
    return {
      desktopApi: null,
    };
  },
  computed: {
    desktopMode() {
      return Boolean(this.desktopApi);
    },
    stopButtonIcon() {
      return this.remoteBackend ? "mdi-close-circle-outline" : "mdi-power";
    },
    stopButtonLabel() {
      return this.remoteBackend ? "Close App" : "Stop App";
    },
  },
  mounted() {
    if (typeof window !== "undefined" && window.sniff4houndDesktop) {
      this.desktopApi = window.sniff4houndDesktop;
    }
  },
  methods: {
    runDesktopWindowAction(action) {
      const fn = this.desktopApi && this.desktopApi[action];
      if (typeof fn === "function") {
        fn();
      }
    },
  },
};
</script>

<style scoped>
.top-bar {
  position: relative;
  /* Was overflow:hidden (only needed to clip the ::after accent line) - but
     that also clipped the notification bell's floating badge, which sits a
     few px above the bell icon and pokes past this 40px bar's edge. The
     accent line is a 2px strip pinned to top:0/left:0/right:0, so it never
     needs clipping in the first place. */
  border-bottom: 1px solid rgba(var(--brand-sky-rgb), 0.18);
  backdrop-filter: blur(18px) saturate(130%);
  background:
    radial-gradient(circle at 18% 0%, rgba(var(--brand-cyan-rgb), 0.14), transparent 34%),
    radial-gradient(circle at 82% 0%, rgba(var(--brand-violet-rgb), 0.16), transparent 40%),
    linear-gradient(180deg, rgba(6, 11, 18, 0.94) 0%, rgba(9, 17, 29, 0.78) 72%, rgba(9, 17, 29, 0.18) 100%);
  box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.03);
}

.top-bar--desktop {
  -webkit-app-region: drag;
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
  /* Was 6px - the bell's floating badge extends past the bell icon's own
     edge, and at 6px it overlapped the shutdown button's glow halo, which
     painted over (and hid) the badge's count digit. */
  gap: 22px;
  min-width: 0;
  -webkit-app-region: no-drag;
}

.shutdown-btn {
  letter-spacing: 0.04em;
  text-transform: uppercase;
  /* Matches NotificationBell's .bell-badge margin-top: that margin pushes
     the bell button down to keep its floating badge clear of the viewport
     edge, which otherwise misaligned it against this button. Applying the
     same offset here keeps both icons level. */
  margin-top: 10px;
}

.desktop-window-controls {
  display: inline-flex;
  align-items: center;
  gap: 2px;
  margin-top: 10px;
  padding-left: 6px;
  border-left: 1px solid rgba(var(--brand-sky-rgb), 0.16);
  -webkit-app-region: no-drag;
}
</style>
