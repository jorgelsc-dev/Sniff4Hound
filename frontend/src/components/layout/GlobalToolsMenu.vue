<template>
  <teleport to="body">
    <div v-if="open" class="tools-fab-backdrop" @click="close"></div>
    <div class="tools-fab">
      <transition name="tools-fab-menu">
        <div v-if="open" class="tools-fab-menu" role="menu" aria-label="Navegación">
          <router-link
            v-for="tool in links"
            :key="tool.to"
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
        </div>
      </transition>

      <button
        type="button"
        class="tools-fab-trigger"
        :aria-expanded="open ? 'true' : 'false'"
        aria-label="Navegación"
        @click="toggle"
      >
        <v-icon :icon="open ? 'mdi-close' : 'mdi-toolbox-outline'" size="26" />
      </button>
    </div>
  </teleport>
</template>

<script>
// Global, present on every view (not just the dashboard) - this is now the
// app's only navigation surface (the top bar was stripped down to just the
// logo, notifications and shutdown), so it always has to be reachable,
// wherever the operator currently is.
export default {
  name: "GlobalToolsMenu",
  data() {
    return {
      open: false,
      links: [
        { label: "Dashboard", to: "/", icon: "mdi-view-dashboard", color: "primary" },
        { label: "Chat", to: "/chat", icon: "mdi-message-processing-outline", color: "info" },
        { label: "Configuración", to: "/settings", icon: "mdi-cog-outline", color: "secondary" },
        { label: "IA", to: "/ai", icon: "mdi-brain", color: "secondary" },
        { label: "SOC", to: "/soc", icon: "mdi-shield-search", color: "error" },
        { label: "Investigar", to: "/investigate", icon: "mdi-magnify-scan", color: "info" },
        { label: "Monitores", to: "/monitors", icon: "mdi-target-account", color: "success" },
        { label: "Radar", to: "/radar", icon: "mdi-radar", color: "primary" },
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
    },
  },
  mounted() {
    document.addEventListener("keydown", this.handleKeydown);
  },
  beforeUnmount() {
    document.removeEventListener("keydown", this.handleKeydown);
  },
  methods: {
    toggle() {
      this.open = !this.open;
    },
    close() {
      this.open = false;
    },
    handleKeydown(event) {
      if (event.key === "Escape" && this.open) {
        this.close();
      }
    },
  },
};
</script>

<style scoped>
.tools-fab-backdrop {
  position: fixed;
  inset: 0;
  background: rgba(4, 8, 13, 0.82);
  /* "Difumina mucho mas que el fondo se vea casi nada" - the background
     behind the menu should read as nearly invisible, not just softened. */
  backdrop-filter: blur(18px) saturate(120%);
  -webkit-backdrop-filter: blur(18px) saturate(120%);
  z-index: 3090;
}

.tools-fab {
  position: fixed;
  right: 20px;
  bottom: 20px;
  /* NotificationStack.vue anchors toasts to this same corner at z-index
     3000, so a toast can render on top of and cover this button while it's
     visible - staying above it keeps the trigger clickable at all times. */
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
