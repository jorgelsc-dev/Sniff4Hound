<template>
  <teleport to="body">
    <nav v-if="desktopMode" class="desktop-activity-bar" aria-label="Navigation">
      <div class="desktop-activity-nav">
        <div v-for="tool in links" :key="tool.to" class="desktop-activity-item-wrap">
          <router-link
            v-if="!tool.children"
            class="desktop-activity-item"
            :class="{ 'desktop-activity-item--active': isActive(tool.to) }"
            :to="tool.to"
            :aria-label="tool.label"
          >
            <v-icon :icon="tool.icon" :color="isActive(tool.to) ? tool.color : undefined" size="22" />
            <v-tooltip activator="parent" location="right">{{ tool.label }}</v-tooltip>
          </router-link>

          <button
            v-else
            type="button"
            class="desktop-activity-item"
            :class="{ 'desktop-activity-item--active': isGroupActive(tool), 'desktop-activity-item--open': openGroup === tool.to }"
            :aria-label="tool.label"
            :aria-expanded="openGroup === tool.to ? 'true' : 'false'"
            @click="toggleGroup(tool, $event)"
          >
            <v-icon :icon="tool.icon" :color="isGroupActive(tool) ? tool.color : undefined" size="22" />
            <v-tooltip v-if="openGroup !== tool.to" activator="parent" location="right">{{ tool.label }}</v-tooltip>
          </button>
        </div>
      </div>

      <!-- Rendered outside .desktop-activity-nav (position:fixed, anchored
           via JS-measured coordinates) rather than nested + absolutely
           positioned inside it: that container's overflow-y:auto forces
           overflow-x to clip too (a linked pair in the overflow spec), which
           silently clipped this away entirely whenever it tried to render
           as a normal descendant - present in the DOM, never actually
           visible or hit-testable. -->
      <transition name="desktop-flyout">
        <div
          v-if="openTool"
          class="desktop-activity-flyout"
          role="menu"
          :aria-label="openTool.label"
          :style="{ top: `${flyoutAnchor.top}px`, left: `${flyoutAnchor.left}px` }"
        >
          <div class="desktop-activity-flyout__title">{{ openTool.label }}</div>
          <router-link
            v-for="child in openTool.children"
            :key="child.to"
            class="desktop-activity-flyout-item"
            role="menuitem"
            :to="child.to"
            @click="closeGroup"
          >
            <v-icon :icon="child.icon" size="16" />
            <span>{{ child.label }}</span>
          </router-link>
        </div>
      </transition>

      <div class="desktop-runtime-dock" aria-label="Runtime controls">
        <button
          v-for="control in quickControls"
          :key="control.key"
          type="button"
          class="desktop-runtime-button"
          :class="{
            'is-active': control.active,
            'is-busy': control.busy,
            'is-disabled': control.disabled,
          }"
          :style="control.styleVars"
          :aria-label="control.ariaLabel"
          :aria-pressed="control.active ? 'true' : 'false'"
          :aria-disabled="control.disabled ? 'true' : 'false'"
          @click="toggleQuickControl(control)"
        >
          <v-icon
            :icon="control.busy ? 'mdi-loading' : control.icon"
            size="20"
            :class="{ 'desktop-runtime-button__spin': control.busy }"
          />
          <span class="desktop-runtime-button__state" aria-hidden="true" />
          <v-tooltip activator="parent" location="right">{{ control.tooltip }}</v-tooltip>
        </button>

        <span class="desktop-runtime-divider" aria-hidden="true" />

        <button
          type="button"
          class="desktop-power-button"
          :class="{ 'is-busy': shutdownPending }"
          :aria-label="shutdownPending ? shutdownLabel || 'Apagando...' : shutdownButtonLabel"
          :aria-disabled="shutdownPending ? 'true' : 'false'"
          @click="requestShutdown"
        >
          <v-icon :icon="shutdownPending ? 'mdi-loading' : shutdownButtonIcon" size="22" :class="{ 'desktop-runtime-button__spin': shutdownPending }" />
          <v-tooltip activator="parent" location="right">
            {{ shutdownPending ? (shutdownLabel || "Apagando...") : shutdownButtonLabel }}
          </v-tooltip>
        </button>
      </div>
    </nav>

    <div v-if="desktopMode && openGroup" class="desktop-activity-backdrop" @click="closeGroup"></div>

    <div v-if="!desktopMode && open" class="tools-fab-backdrop" @click="close"></div>
    <div v-if="!desktopMode" class="tools-fab">
      <transition name="tools-fab-menu">
        <div v-if="open" class="tools-fab-menu" role="menu" aria-label="Navegación">
          <template v-for="tool in links" :key="tool.to">
            <router-link
              v-if="!tool.children"
              class="tools-fab-item"
              role="menuitem"
              :to="tool.to"
              @click="close"
            >
              <span class="tools-fab-item-label">{{ tool.label }}</span>
              <span class="tools-fab-item-icon">
                <v-icon :icon="tool.icon" :color="tool.color" size="20" />
              </span>
            </router-link>
            <template v-else>
              <div class="tools-fab-group-label">{{ tool.label }}</div>
              <router-link
                v-for="child in tool.children"
                :key="child.to"
                class="tools-fab-item tools-fab-item--child"
                role="menuitem"
                :to="child.to"
                @click="close"
              >
                <span class="tools-fab-item-label">{{ child.label }}</span>
                <span class="tools-fab-item-icon">
                  <v-icon :icon="child.icon" :color="tool.color" size="18" />
                </span>
              </router-link>
            </template>
          </template>
        </div>
      </transition>

      <button
        type="button"
        class="tools-fab-trigger"
        :aria-expanded="open ? 'true' : 'false'"
        aria-label="Navegación"
        @click="toggle"
      >
        <v-icon :icon="open ? 'mdi-close' : 'mdi-paw'" size="26" />
      </button>
    </div>
  </teleport>
</template>

<script>
import store from "../../state/appStore";

const QUICK_STATUS_REFRESH_MS = 15000;
const CONTROL_COLORS = {
  sniffer: "rgba(93, 204, 255, 0.96)",
  honeypot: "rgba(255, 187, 98, 0.96)",
  monitors: "rgba(117, 236, 177, 0.96)",
  ai: "rgba(178, 149, 255, 0.96)",
  trainingCapture: "rgba(94, 220, 200, 0.96)",
};

// Global, present on every view (not just the dashboard) - this is now the
// app's only navigation surface (the top bar stays focused on brand,
// notifications and desktop window controls), so it always has to be
// reachable wherever the operator currently is.
export default {
  name: "GlobalToolsMenu",
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
      desktopMode: false,
      open: false,
      openGroup: null,
      flyoutAnchor: { top: 0, left: 0 },
      quickStatusTimer: null,
      engineBusy: {
        sniffer: false,
        honeypot: false,
      },
      engineDesired: {
        sniffer: null,
        honeypot: null,
      },
      aiConfig: {
        training_enabled: false,
        training_capture_enabled: false,
        ai_alert_mode_enabled: false,
        raw_retention_enabled: true,
      },
      aiBusy: {
        monitors: false,
        ai: false,
        trainingCapture: false,
      },
      links: [
        {
          label: "Dashboard",
          to: "/",
          icon: "mdi-view-dashboard",
          color: "primary",
          children: [
            { label: "Resumen", to: "/dashboard/overview", icon: "mdi-view-dashboard-outline" },
            { label: "Mapa de Nodos", to: "/dashboard/node-map", icon: "mdi-graph-outline" },
            { label: "Mapa en Vivo", to: "/dashboard/live-map", icon: "mdi-earth" },
          ],
        },
        { label: "Chat", to: "/chat", icon: "mdi-message-processing-outline", color: "info" },
        { label: "Configuración", to: "/settings", icon: "mdi-cog-outline", color: "secondary" },
        {
          label: "IA",
          to: "/ai",
          icon: "mdi-brain",
          color: "secondary",
          children: [
            { label: "Resumen", to: "/ai/overview", icon: "mdi-clipboard-pulse-outline" },
            { label: "RNN Red Neuronal", to: "/ai/neural-network", icon: "mdi-hub-outline" },
          ],
        },
        { label: "SOC", to: "/soc", icon: "mdi-shield-search", color: "error" },
        { label: "Investigar", to: "/investigate", icon: "mdi-magnify-scan", color: "info" },
        { label: "Monitores", to: "/monitors", icon: "mdi-target-account", color: "success" },
        { label: "Protocolos", to: "/protocols", icon: "mdi-swap-horizontal", color: "secondary" },
        { label: "Sniffer", to: "/sniffer", icon: "mdi-ethernet", color: "info" },
        { label: "Honeypot", to: "/honeypot", icon: "mdi-spider-web", color: "warning" },
        { label: "Dominios", to: "/domains", icon: "mdi-web", color: "primary" },
        { label: "Paths", to: "/paths", icon: "mdi-routes", color: "secondary" },
        { label: "IPs", to: "/ips", icon: "mdi-ip-network", color: "success" },
      ],
    };
  },
  watch: {
    $route() {
      this.open = false;
      this.openGroup = null;
    },
    canUseApi(value) {
      if (value && this.desktopMode) {
        this.loadQuickStatus({ silent: true });
      }
    },
  },
  computed: {
    canUseApi() {
      if (!this.store.state.authReady) return false;
      if (!this.store.state.authRequired) return true;
      return this.store.state.authStatus === "authenticated";
    },
    runtime() {
      return this.store.state.runtime && typeof this.store.state.runtime === "object"
        ? this.store.state.runtime
        : {};
    },
    snifferRuntime() {
      return this.runtime.sniffer && typeof this.runtime.sniffer === "object" ? this.runtime.sniffer : {};
    },
    honeypotRuntime() {
      return this.runtime.honeypot && typeof this.runtime.honeypot === "object" ? this.runtime.honeypot : {};
    },
    snifferBlocked() {
      return String(this.snifferRuntime.capture_state || "").trim().toLowerCase() === "blocked";
    },
    snifferRunning() {
      return this.engineDesired.sniffer === null
        ? Boolean(this.snifferRuntime.running)
        : Boolean(this.engineDesired.sniffer);
    },
    honeypotRunning() {
      return this.engineDesired.honeypot === null
        ? Boolean(this.honeypotRuntime.running)
        : Boolean(this.engineDesired.honeypot);
    },
    monitorsRunning() {
      return Boolean(this.aiConfig.training_enabled);
    },
    aiRunning() {
      return Boolean(this.aiConfig.ai_alert_mode_enabled);
    },
    trainingCaptureRunning() {
      return Boolean(this.aiConfig.training_capture_enabled);
    },
    quickControls() {
      return [
        this.quickEngineControl({
          key: "sniffer",
          label: "Sniffer",
          icon: this.snifferBlocked ? "mdi-alert-circle-outline" : "mdi-ethernet",
          active: this.snifferRunning,
          busy: this.engineBusy.sniffer,
          disabled: this.snifferBlocked,
          disabledReason: this.snifferBlocked ? "captura bloqueada" : "",
        }),
        this.quickEngineControl({
          key: "honeypot",
          label: "Honeypot",
          icon: "mdi-spider-web",
          active: this.honeypotRunning,
          busy: this.engineBusy.honeypot,
        }),
        this.quickAiControl({
          key: "monitors",
          label: "Monitores",
          icon: "mdi-shield-search",
          active: this.monitorsRunning,
          busy: this.aiBusy.monitors,
          field: "training_enabled",
        }),
        this.quickAiControl({
          key: "ai",
          label: "IA",
          icon: "mdi-brain",
          active: this.aiRunning,
          busy: this.aiBusy.ai,
          field: "ai_alert_mode_enabled",
          disabled: !this.aiConfig.raw_retention_enabled,
          disabledReason: "requiere retencion raw",
        }),
        this.quickAiControl({
          key: "trainingCapture",
          label: "Training",
          icon: "mdi-school",
          active: this.trainingCaptureRunning,
          busy: this.aiBusy.trainingCapture,
          field: "training_capture_enabled",
        }),
      ];
    },
    openTool() {
      return this.links.find((tool) => tool.to === this.openGroup) || null;
    },
    shutdownButtonIcon() {
      return this.remoteBackend ? "mdi-close-circle-outline" : "mdi-power";
    },
    shutdownButtonLabel() {
      return this.remoteBackend ? "Cerrar app" : "Apagar Sniff4Hound";
    },
  },
  mounted() {
    this.desktopMode = Boolean(typeof window !== "undefined" && window.sniff4houndDesktop);
    if (this.desktopMode) {
      document.body.classList.add("sniff4hound-desktop-shell");
      this.loadQuickStatus({ silent: true });
      this.quickStatusTimer = setInterval(() => {
        this.loadQuickStatus({ silent: true });
      }, QUICK_STATUS_REFRESH_MS);
    }
    document.addEventListener("keydown", this.handleKeydown);
  },
  beforeUnmount() {
    document.body.classList.remove("sniff4hound-desktop-shell");
    if (this.quickStatusTimer) {
      clearInterval(this.quickStatusTimer);
      this.quickStatusTimer = null;
    }
    document.removeEventListener("keydown", this.handleKeydown);
  },
  methods: {
    quickEngineControl({ key, label, icon, active, busy, disabled = false, disabledReason = "" }) {
      const action = active ? "apagar" : "encender";
      return {
        key,
        kind: "engine",
        label,
        icon,
        active,
        busy,
        disabled,
        disabledReason,
        ariaLabel: `${label}: ${active ? "encendido" : "apagado"}`,
        tooltip: disabled
          ? `${label}: ${disabledReason}`
          : `${label}: ${active ? "encendido" : "apagado"} - click para ${action}`,
        styleVars: { "--control-color": CONTROL_COLORS[key] },
      };
    },
    quickAiControl({ key, label, icon, active, busy, field, disabled = false, disabledReason = "" }) {
      const action = active ? "apagar" : "encender";
      return {
        key,
        kind: "ai",
        field,
        label,
        icon,
        active,
        busy,
        disabled,
        disabledReason,
        ariaLabel: `${label}: ${active ? "encendida" : "apagada"}`,
        tooltip: disabled
          ? `${label}: ${disabledReason}`
          : `${label}: ${active ? "encendida" : "apagada"} - click para ${action}`,
        styleVars: { "--control-color": CONTROL_COLORS[key] },
      };
    },
    loadQuickStatus() {
      if (!this.desktopMode || !this.canUseApi) return Promise.resolve();
      return Promise.allSettled([
        this.store.initRuntime(),
        this.store.fetchJsonPromise("/api/ai/config"),
      ]).then(([, aiConfigRes]) => {
        if (aiConfigRes.status !== "fulfilled") return;
        const config = aiConfigRes.value || {};
        this.aiConfig = {
          training_enabled: Boolean(config.training_enabled),
          training_capture_enabled: Boolean(config.training_capture_enabled),
          ai_alert_mode_enabled: Boolean(config.ai_alert_mode_enabled),
          raw_retention_enabled: Boolean(config.raw_retention_enabled),
        };
      });
    },
    toggleQuickControl(control) {
      if (!control || control.busy || control.disabled) return;
      if (control.kind === "engine") {
        this.toggleEngine(control.key, !control.active);
      } else if (control.kind === "ai") {
        this.toggleAiFlag(control);
      }
    },
    toggleEngine(engine, shouldRun) {
      if (this.engineBusy[engine]) return;
      this.engineBusy[engine] = true;
      this.engineDesired[engine] = Boolean(shouldRun);
      this.store
        .controlEngine(engine, shouldRun ? "start" : "stop")
        .catch((err) => {
          this.store.pushNotification({
            kind: "runtime",
            severity: "high",
            title: `No se pudo ${shouldRun ? "encender" : "apagar"} ${engine}`,
            message: (err && err.message) || "Error de runtime",
            groupKey: `runtime:${engine}:quick-toggle-error`,
          });
        })
        .finally(() => {
          this.engineDesired[engine] = null;
          this.engineBusy[engine] = false;
          this.loadQuickStatus({ silent: true });
        });
    },
    toggleAiFlag(control) {
      const busyKey = control.key;
      if (this.aiBusy[busyKey]) return;
      this.aiBusy[busyKey] = true;
      this.store
        .fetchJsonPromise("/api/ai/config", {
          method: "POST",
          body: JSON.stringify({ [control.field]: !control.active }),
        })
        .then((config) => {
          this.aiConfig = {
            training_enabled: Boolean(config.training_enabled),
            training_capture_enabled: Boolean(config.training_capture_enabled),
            ai_alert_mode_enabled: Boolean(config.ai_alert_mode_enabled),
            raw_retention_enabled: Boolean(config.raw_retention_enabled),
          };
        })
        .catch((err) => {
          this.store.pushNotification({
            kind: "runtime",
            severity: "high",
            title: `No se pudo actualizar ${control.label}`,
            message: (err && err.message) || "Error de configuracion",
            groupKey: `runtime:${control.key}:quick-toggle-error`,
          });
        })
        .finally(() => {
          this.aiBusy[busyKey] = false;
          this.loadQuickStatus({ silent: true });
        });
    },
    requestShutdown() {
      if (this.shutdownPending) return;
      this.$emit("shutdown-app");
    },
    toggle() {
      this.open = !this.open;
    },
    close() {
      this.open = false;
    },
    handleKeydown(event) {
      if (event.key !== "Escape") return;
      if (this.openGroup) {
        this.closeGroup();
      } else if (this.open) {
        this.close();
      }
    },
    isActive(to) {
      const current = String(this.$route.path || "/");
      if (to === "/") return current === "/" || current.startsWith("/dashboard");
      return current === to || current.startsWith(`${to}/`);
    },
    isGroupActive(tool) {
      return this.isActive(tool.to) || (tool.children || []).some((child) => this.isActive(child.to));
    },
    toggleGroup(tool, event) {
      if (this.openGroup === tool.to) {
        this.closeGroup();
        return;
      }
      const rect = event.currentTarget.getBoundingClientRect();
      this.flyoutAnchor = { top: rect.top, left: rect.right + 8 };
      this.openGroup = tool.to;
    },
    closeGroup() {
      this.openGroup = null;
    },
  },
};
</script>

<style scoped>
.desktop-activity-bar {
  position: fixed;
  top: 40px;
  left: 0;
  bottom: 0;
  z-index: 2800;
  width: 52px;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  padding: 10px 0 12px;
  border-right: 1px solid rgba(var(--brand-sky-rgb), 0.16);
  background:
    linear-gradient(180deg, rgba(9, 17, 29, 0.98), rgba(5, 11, 20, 0.98)),
    #07101b;
  box-shadow: inset -1px 0 0 rgba(255, 255, 255, 0.02);
}

.desktop-activity-nav,
.desktop-runtime-dock {
  display: flex;
  flex-direction: column;
  align-items: center;
}

.desktop-activity-nav {
  flex: 1 1 auto;
  gap: 4px;
  width: 100%;
  min-height: 0;
  overflow-y: auto;
  scrollbar-width: none;
}

.desktop-activity-nav::-webkit-scrollbar {
  display: none;
}

.desktop-activity-item-wrap {
  position: relative;
  width: 100%;
  display: flex;
  justify-content: center;
}

.desktop-activity-item {
  position: relative;
  width: 44px;
  height: 42px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  color: rgba(211, 225, 241, 0.66);
  text-decoration: none;
  border-radius: 0;
  border: 0;
  background: transparent;
  padding: 0;
  cursor: pointer;
  outline: none;
}

.desktop-activity-item::before {
  content: "";
  position: absolute;
  left: 0;
  top: 8px;
  bottom: 8px;
  width: 2px;
  border-radius: 0 2px 2px 0;
  background: transparent;
}

.desktop-activity-item:hover,
.desktop-activity-item:focus-visible,
.desktop-activity-item--active,
.desktop-activity-item--open {
  color: rgba(244, 248, 252, 0.95);
  background: rgba(255, 255, 255, 0.05);
}

.desktop-activity-item--active::before {
  background: rgba(var(--brand-cyan-rgb), 0.95);
}

.desktop-activity-flyout {
  position: fixed;
  z-index: 2850;
  min-width: 190px;
  padding: 6px;
  background: rgba(8, 14, 23, 0.96);
  border: 1px solid rgba(var(--brand-sky-rgb), 0.2);
  border-radius: 10px;
  box-shadow: 0 10px 28px rgba(3, 8, 14, 0.55);
  backdrop-filter: blur(10px);
  -webkit-backdrop-filter: blur(10px);
}

.desktop-activity-flyout__title {
  padding: 4px 10px 6px;
  font-size: 0.7rem;
  font-weight: 650;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: var(--text-dim);
}

.desktop-activity-flyout-item {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 8px 10px;
  border-radius: 6px;
  color: var(--text-soft);
  text-decoration: none;
  font-size: 0.82rem;
  white-space: nowrap;
}

.desktop-activity-flyout-item:hover,
.desktop-activity-flyout-item:focus-visible {
  background: rgba(var(--brand-cyan-rgb), 0.12);
  outline: none;
}

.desktop-activity-backdrop {
  position: fixed;
  inset: 0;
  /* Below .desktop-activity-bar's own z-index (2800): that bar establishes
     its own stacking context, so the flyout nested inside it (z-index 2850)
     only outranks this backdrop *within* that context - against a sibling
     stacking context, only the bar's own 2800 counts. Sitting above the
     bar here would let this backdrop intercept every click meant for the
     flyout, closing it without ever reaching the link underneath. */
  z-index: 2790;
  background: transparent;
}

.desktop-flyout-enter-active,
.desktop-flyout-leave-active {
  transition: opacity 0.14s ease, transform 0.14s ease;
}

.desktop-flyout-enter-from,
.desktop-flyout-leave-to {
  opacity: 0;
  transform: translateX(-4px);
}

.desktop-runtime-dock {
  flex: 0 0 auto;
  gap: 5px;
  width: 100%;
  padding-top: 9px;
  border-top: 1px solid rgba(var(--brand-sky-rgb), 0.14);
}

.desktop-runtime-button,
.desktop-power-button {
  position: relative;
  width: 42px;
  height: 38px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border: 1px solid rgba(132, 174, 214, 0.14);
  border-radius: 8px;
  background: rgba(255, 255, 255, 0.035);
  color: rgba(215, 229, 243, 0.72);
  cursor: pointer;
  outline: none;
  transition: background 0.15s ease, border-color 0.15s ease, color 0.15s ease, transform 0.15s ease;
}

.desktop-runtime-button:hover,
.desktop-runtime-button:focus-visible {
  border-color: color-mix(in srgb, var(--control-color) 50%, transparent);
  background: color-mix(in srgb, var(--control-color) 12%, transparent);
  color: white;
}

.desktop-runtime-button:active,
.desktop-power-button:active {
  transform: translateY(1px);
}

.desktop-runtime-button.is-active {
  border-color: color-mix(in srgb, var(--control-color) 58%, transparent);
  background: color-mix(in srgb, var(--control-color) 17%, transparent);
  color: var(--control-color);
  box-shadow: 0 0 16px color-mix(in srgb, var(--control-color) 20%, transparent);
}

.desktop-runtime-button.is-disabled {
  cursor: not-allowed;
  opacity: 0.46;
}

.desktop-runtime-button__state {
  position: absolute;
  right: 7px;
  bottom: 7px;
  width: 6px;
  height: 6px;
  border-radius: 999px;
  background: rgba(134, 148, 166, 0.8);
  box-shadow: 0 0 0 2px rgba(5, 11, 20, 0.92);
}

.desktop-runtime-button.is-active .desktop-runtime-button__state {
  background: var(--control-color);
}

.desktop-runtime-button.is-busy .desktop-runtime-button__state {
  background: rgba(255, 205, 118, 0.96);
}

.desktop-runtime-button__spin {
  animation: desktop-control-spin 0.9s linear infinite;
}

.desktop-runtime-divider {
  width: 26px;
  height: 1px;
  margin: 4px 0;
  background: rgba(var(--brand-sky-rgb), 0.16);
}

.desktop-power-button {
  border-color: rgba(255, 91, 118, 0.28);
  background: rgba(255, 91, 118, 0.08);
  color: rgba(255, 98, 125, 0.96);
}

.desktop-power-button:hover,
.desktop-power-button:focus-visible {
  border-color: rgba(255, 109, 134, 0.62);
  background: rgba(255, 91, 118, 0.16);
  color: white;
  box-shadow: 0 0 18px rgba(255, 91, 118, 0.22);
}

.desktop-power-button.is-busy {
  color: rgba(255, 205, 118, 0.96);
}

@keyframes desktop-control-spin {
  to {
    transform: rotate(360deg);
  }
}

:global(body.sniff4hound-desktop-shell .app-main) {
  padding-left: 52px;
}

:global(body.sniff4hound-desktop-shell .app-container),
:global(body.sniff4hound-desktop-shell .app-topbar) {
  max-width: none;
}

.tools-fab-backdrop {
  position: fixed;
  inset: 0;
  background: rgba(4, 8, 13, 0.93);
  /* "Difumina mas el fondo" - still readable at blur(18px)/0.82 opacity, so
     pushed both further: heavier blur radius and a near-opaque backing tint
     underneath it (the tint alone already does most of the work in browsers
     where backdrop-filter is unsupported/disabled). */
  backdrop-filter: blur(32px) saturate(120%);
  -webkit-backdrop-filter: blur(32px) saturate(120%);
  z-index: 3090;
}

.tools-fab {
  position: fixed;
  right: 20px;
  bottom: 20px;
  z-index: 3100;
  display: flex;
  flex-direction: column;
  align-items: flex-end;
  gap: 10px;
}

.tools-fab-trigger {
  width: 56px;
  height: 56px;
  flex: none;
  border-radius: 50%;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border: 1px solid rgba(var(--brand-cyan-rgb), 0.5);
  background: linear-gradient(160deg, rgba(11, 20, 32, 0.96), rgba(6, 12, 20, 0.96));
  color: rgba(var(--brand-cyan-rgb), 0.98);
  box-shadow: 0 10px 28px rgba(3, 8, 14, 0.55), 0 0 0 1px rgba(var(--brand-cyan-rgb), 0.08);
  cursor: pointer;
  transition: transform 0.16s ease, border-color 0.16s ease, box-shadow 0.16s ease;
}

.tools-fab-trigger:hover,
.tools-fab-trigger:focus-visible {
  border-color: rgba(var(--brand-cyan-rgb), 0.85);
  box-shadow: 0 12px 32px rgba(3, 8, 14, 0.6), 0 0 0 4px rgba(var(--brand-cyan-rgb), 0.12);
  outline: none;
}

.tools-fab-trigger:active {
  transform: scale(0.94);
}

.tools-fab-menu {
  display: flex;
  flex-direction: column;
  align-items: flex-end;
  gap: 8px;
  max-width: calc(100vw - 40px);
  max-height: calc(100vh - 96px);
  overflow-y: auto;
  padding: 2px;
}

.tools-fab-item {
  min-height: 40px;
  display: inline-flex;
  align-items: center;
  gap: 10px;
  padding: 6px 8px 6px 14px;
  border-radius: 999px;
  border: 1px solid rgba(var(--brand-sky-rgb), 0.2);
  background: rgba(8, 14, 23, 0.94);
  color: var(--text-soft);
  text-decoration: none;
  font-size: 0.82rem;
  font-weight: 650;
  white-space: nowrap;
  box-shadow: 0 6px 18px rgba(3, 8, 14, 0.45);
}

.tools-fab-item:hover,
.tools-fab-item:focus-visible {
  border-color: rgba(var(--brand-cyan-rgb), 0.5);
  background: rgba(var(--brand-cyan-rgb), 0.1);
  outline: none;
}

.tools-fab-item-icon {
  width: 30px;
  height: 30px;
  flex: none;
  border-radius: 50%;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  background: rgba(255, 255, 255, 0.05);
}

.tools-fab-group-label {
  align-self: flex-end;
  padding: 2px 14px;
  font-size: 0.68rem;
  font-weight: 650;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: var(--text-dim);
}

.tools-fab-item--child {
  margin-right: 14px;
  opacity: 0.92;
}

.tools-fab-menu-enter-active,
.tools-fab-menu-leave-active {
  transition: opacity 0.16s ease, transform 0.16s ease;
}

.tools-fab-menu-enter-from,
.tools-fab-menu-leave-to {
  opacity: 0;
  transform: translateY(10px) scale(0.98);
}

@media (max-width: 480px) {
  .tools-fab {
    right: 14px;
    bottom: 14px;
  }
}
</style>
