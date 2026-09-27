<template>
  <v-app-bar
    color="transparent"
    flat
    height="48"
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

      <button
        type="button"
        class="command-trigger"
        aria-label="Buscar vistas, ajustes y acciones"
        aria-keyshortcuts="Control+K Meta+K"
        @click="store.state.commandPaletteOpen = true"
      >
        <v-icon icon="mdi-magnify" size="15" />
        <span>Buscar...</span>
        <kbd>{{ commandShortcut }}</kbd>
      </button>

      <v-spacer />

      <div class="status-rail">
        <v-btn
          v-if="!desktopMode"
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
            class="window-control window-control--minimize"
            aria-label="Minimize"
            @click="runDesktopWindowAction('minimize')"
          >
            <v-icon icon="mdi-window-minimize" size="18" />
            <v-tooltip activator="parent" location="bottom">Minimize</v-tooltip>
          </v-btn>
          <v-btn
            icon
            variant="text"
            size="small"
            density="compact"
            class="window-control window-control--maximize"
            aria-label="Maximize"
            @click="runDesktopWindowAction('maximize')"
          >
            <v-icon icon="mdi-window-maximize" size="17" />
            <v-tooltip activator="parent" location="bottom">Maximize</v-tooltip>
          </v-btn>
          <v-btn
            icon
            variant="text"
            size="small"
            density="compact"
            class="window-control window-control--close"
            aria-label="Close"
            @click="runDesktopWindowAction('close')"
          >
            <v-icon icon="mdi-close" size="19" />
            <v-tooltip activator="parent" location="bottom">Close</v-tooltip>
          </v-btn>
        </div>
      </div>
    </v-container>
  </v-app-bar>
</template>

<script>
import store from "../../state/appStore";
import BrandMark from "../brand/BrandMark.vue";

export default {
  name: "AppTopBar",
  components: {
    BrandMark,
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
      store,
      desktopApi: null,
    };
  },
  computed: {
    // Electron on macOS reports "darwin" through the preload bridge; every
    // other target this ships to is a Ctrl machine.
    commandShortcut() {
      const platform = String(this.desktopApi?.platform || (typeof navigator !== "undefined" ? navigator.platform : "")).toLowerCase();
      return platform.includes("mac") || platform.includes("darwin") ? "\u2318K" : "Ctrl K";
    },
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
     few px above the bell icon and pokes past this compact bar's edge. The
     accent line is pinned to top:0/left:0/right:0, so it never
     needs clipping in the first place. */
  border-bottom: 1px solid rgba(255, 255, 255, 0.08);
  backdrop-filter: blur(16px) saturate(125%);
  background:
    linear-gradient(180deg, rgba(8, 14, 22, 0.96) 0%, rgba(8, 14, 22, 0.86) 100%);
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
  height: 1px;
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
  gap: 10px;
  padding-inline: 12px;
}

.brand-lockup {
  display: flex;
  align-items: center;
  flex: 0 1 auto;
  min-width: 0;
}

.brand-avatar {
  width: 32px;
  height: 32px;
  flex: 0 0 32px;
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
  letter-spacing: 0;
}

.status-rail {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: 12px;
  flex: 0 0 auto;
  min-width: max-content;
  -webkit-app-region: no-drag;
}

/* The bar itself is the window's drag handle in desktop mode, which swallows
   clicks on anything inside it that does not opt out. */
.command-trigger {
  -webkit-app-region: no-drag;
  display: flex;
  align-items: center;
  gap: 9px;
  margin-left: clamp(12px, 3vw, 28px);
  padding: 0 10px;
  height: 32px;
  width: clamp(190px, 24vw, 340px);
  border: 1px solid var(--stroke);
  border-radius: 8px;
  background: rgba(4, 10, 18, 0.62);
  color: rgba(197, 210, 227, 0.72);
  font-size: 12.5px;
  cursor: pointer;
  transition: border-color 160ms ease, color 160ms ease, background 160ms ease;
}

.command-trigger:hover {
  border-color: rgba(var(--brand-cyan-rgb), 0.42);
  background: rgba(6, 14, 24, 0.72);
  color: rgba(226, 236, 248, 0.92);
}

.command-trigger:focus-visible {
  outline: 2px solid rgba(var(--brand-cyan-rgb), 0.6);
  outline-offset: 2px;
}

.command-trigger span {
  flex: 1;
  text-align: left;
}

.command-trigger kbd {
  font-size: 10px;
  letter-spacing: 0;
  padding: 1px 6px;
  border-radius: 4px;
  border: 1px solid rgba(var(--brand-sky-rgb), 0.2);
  background: rgba(255, 255, 255, 0.04);
  color: rgba(197, 210, 227, 0.72);
}

@media (max-width: 820px) {
  .command-trigger { width: 34px; margin-left: 4px; padding: 0; justify-content: center; flex: 0 0 34px; }
  .command-trigger span, .command-trigger kbd { display: none; }
}

@media (max-width: 520px) {
  .app-topbar {
    padding-inline: 8px;
    gap: 6px;
  }

  .brand-copy {
    display: none;
  }

  .brand-avatar {
    margin-right: 0 !important;
  }

  .desktop-window-controls {
    gap: 0;
    padding: 2px;
  }

  .window-control {
    width: 28px;
    min-width: 28px;
  }
}

.shutdown-btn {
  letter-spacing: 0.04em;
  text-transform: uppercase;
}

.desktop-window-controls {
  display: inline-flex;
  align-items: center;
  gap: 2px;
  padding: 3px;
  border: 1px solid var(--stroke);
  border-radius: 8px;
  background: rgba(4, 10, 18, 0.46);
  box-shadow: inset 0 0 0 1px rgba(255, 255, 255, 0.025);
  -webkit-app-region: no-drag;
}

.window-control {
  width: 30px;
  height: 28px;
  min-width: 30px;
  border-radius: 6px;
  color: rgba(216, 229, 244, 0.82);
}

.window-control:hover,
.window-control:focus-visible {
  background: rgba(255, 255, 255, 0.07);
  color: white;
}

.window-control--close {
  color: rgba(255, 103, 128, 0.94);
}

.window-control--close:hover,
.window-control--close:focus-visible {
  background: rgba(255, 90, 118, 0.16);
  color: white;
}
</style>
