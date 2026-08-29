<template>
  <v-app class="sniff4hound-app">
    <AppSidebar
      :open="drawer"
      :nav-items="navItems"
      @update:open="drawer = $event"
    />

    <AppTopBar
      :nav-items="navItems"
      :auth-required="authRequired"
      :auth-status="authStatus"
      :ws-status="wsStatus"
      :shutdown-pending="shutdownPending"
      @open-drawer="drawer = true"
      @open-auth="openAuthPrompt"
      @shutdown-app="shutdownApplication"
    />

    <v-main class="app-main">
      <v-container class="app-container">
        <div v-if="canRenderViews">
          <AppHero v-if="showHero" />

          <div :class="showHero ? 'mt-8' : 'mt-3'">
            <router-view v-slot="{ Component }">
              <transition name="view-fade" mode="out-in">
                <component :is="Component" />
              </transition>
            </router-view>
          </div>
        </div>

        <div v-else class="auth-stage">
          <v-sheet class="auth-stage-card" rounded="xl" elevation="0">
            <div class="auth-stage-kicker">Protected Console</div>
            <h1 class="auth-stage-title">Authentication required</h1>
            <p class="auth-stage-copy">
              Enter the security code shown in the terminal to unlock the dashboard and
              resume HTTP and WebSocket access.
            </p>
            <v-btn color="primary" size="large" variant="flat" @click="openAuthPrompt">
              Enter code
            </v-btn>
            <v-alert
              v-if="authError"
              class="mt-5"
              type="warning"
              variant="tonal"
              density="comfortable"
            >
              {{ authError }}
            </v-alert>
          </v-sheet>
        </div>
      </v-container>
    </v-main>

    <v-dialog :model-value="authPromptOpen" persistent max-width="520">
      <v-card class="auth-dialog-card" rounded="xl">
        <div class="auth-dialog-topline" />
        <v-card-title class="text-h5 pt-6">Security Code</v-card-title>
        <v-card-text class="pt-4">
          <p class="auth-dialog-copy">
            Open the startup link from the `sniff4hound` terminal or enter the
            8-character code here. The dashboard uses it for API and WebSocket access.
          </p>
          <v-alert
            type="info"
            variant="tonal"
            density="compact"
            class="mb-4"
            icon="mdi-shield-lock-outline"
          >
            The startup link saves the code in this browser until the next run gives you
            a new one. Sign out or enter a fresh code to replace it.
          </v-alert>
          <v-text-field
            ref="authInput"
            v-model="accessTokenInput"
            label="Security code"
            variant="outlined"
            density="comfortable"
            autocapitalize="off"
            autocomplete="one-time-code"
            spellcheck="false"
            :error-messages="authError ? [authError] : []"
            :loading="authSubmitting"
            @keyup.enter="submitAccessToken"
          />
        </v-card-text>
        <v-card-actions class="px-6 pb-6">
          <v-spacer />
          <v-btn
            color="primary"
            size="large"
            variant="flat"
            :loading="authSubmitting"
            @click="submitAccessToken"
          >
            Authenticate
          </v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>

    <NotificationStack />
  </v-app>
</template>

<script>
import { nextTick } from "vue";
import store from "./state/appStore";
import AppSidebar from "./components/layout/AppSidebar.vue";
import AppTopBar from "./components/layout/AppTopBar.vue";
import AppHero from "./components/layout/AppHero.vue";
import NotificationStack from "./components/ui/NotificationStack.vue";

export default {
  name: "App",
  components: {
    AppSidebar,
    AppTopBar,
    AppHero,
    NotificationStack,
  },
  data() {
    return {
      store,
      drawer: false,
      accessTokenInput: "",
      authSubmitting: false,
      // Ordered by the analyst's triage flow (alert -> understand -> pivot),
      // not by implementation order. SOC, Investigate and Protocols used to be
      // reachable only by typing the URL by hand.
      navItems: [
        { label: "Dashboard", to: "/", icon: "mdi-view-dashboard" },
        { label: "SOC", to: "/soc", icon: "mdi-shield-search" },
        { label: "Investigate", to: "/investigate", icon: "mdi-magnify-scan" },
        { label: "Monitors", to: "/monitors", icon: "mdi-target-account" },
        { label: "Radar", to: "/radar", icon: "mdi-radar" },
        { label: "Protocols", to: "/protocols", icon: "mdi-swap-horizontal" },
        { label: "Sniffer", to: "/sniffer", icon: "mdi-ethernet" },
        { label: "Honeypot", to: "/honeypot", icon: "mdi-spider-web" },
        // Supporting catalogs, grouped so the top bar stays readable.
        {
          label: "Assets",
          icon: "mdi-folder-network-outline",
          children: [
            { label: "Domains", to: "/domains", icon: "mdi-web" },
            { label: "Paths", to: "/paths", icon: "mdi-routes" },
            { label: "IPs", to: "/ips", icon: "mdi-ip-network" },
          ],
        },
      ],
    };
  },
  computed: {
    authError() {
      return this.store.state.authError || "";
    },
    authPromptOpen() {
      return Boolean(this.store.state.authPromptOpen);
    },
    authRequired() {
      return Boolean(this.store.state.authRequired);
    },
    authStatus() {
      return this.store.state.authStatus || "unknown";
    },
    canRenderViews() {
      if (!this.store.state.authReady) return false;
      if (!this.authRequired) return true;
      return this.authStatus === "authenticated";
    },
    wsStatus() {
      return this.store.state.wsStatus || "offline";
    },
    showHero() {
      if (!this.canRenderViews) return false;
      const name = String((this.$route && this.$route.name) || "").toLowerCase();
      return name === "dashboard";
    },
    shutdownPending() {
      return Boolean(this.store.state.shutdownPending);
    },
  },
  watch: {
    authPromptOpen: {
      immediate: true,
      handler(isOpen) {
        if (!isOpen) return;
        this.accessTokenInput = this.store.state.authToken || this.accessTokenInput || "";
        nextTick(() => {
          const field = this.$refs.authInput;
          if (field && typeof field.focus === "function") {
            field.focus();
          }
        });
      },
    },
  },
  methods: {
    openAuthPrompt() {
      this.accessTokenInput = this.store.state.authToken || this.accessTokenInput || "";
      this.store.openAuthPrompt();
    },
    submitAccessToken() {
      if (this.authSubmitting) return;
      this.authSubmitting = true;
      this.store
        .authenticateSessionToken(this.accessTokenInput)
        .then(() => {
          this.accessTokenInput = this.store.state.authToken || "";
        })
        .catch(() => null)
        .finally(() => {
          this.authSubmitting = false;
        });
    },
    shutdownApplication() {
      if (this.shutdownPending) return;
      if (typeof window !== "undefined") {
        const confirmed = window.confirm(
          "Stop Sniff4Hound and close the local dashboard process?"
        );
        if (!confirmed) return;
      }
      this.store.shutdownApplication().catch((error) => {
        if (typeof window !== "undefined" && error && error.message) {
          window.alert(error.message);
        }
      });
    },
  },
};
</script>

<style scoped>
.app-container {
  max-width: 1560px;
  width: 100%;
}

.app-main {
  padding-bottom: 40px;
}

.auth-stage {
  min-height: calc(100vh - 180px);
  display: grid;
  place-items: center;
  padding: 28px 0;
}

.auth-stage-card {
  width: min(100%, 680px);
  padding: 34px;
  border: 1px solid rgba(102, 212, 255, 0.22);
  background:
    radial-gradient(circle at top right, rgba(52, 230, 255, 0.12), transparent 40%),
    radial-gradient(circle at bottom left, rgba(149, 115, 255, 0.12), transparent 44%),
    linear-gradient(160deg, rgba(9, 14, 22, 0.96), rgba(12, 19, 31, 0.98));
  box-shadow: 0 28px 56px rgba(2, 7, 14, 0.44), inset 0 0 0 1px rgba(255, 255, 255, 0.03);
}

.auth-stage-kicker {
  color: rgba(52, 230, 255, 0.96);
  font-size: 0.78rem;
  font-weight: 700;
  letter-spacing: 0.18em;
  text-transform: uppercase;
}

.auth-stage-title {
  margin: 12px 0 10px;
  font-size: clamp(1.8rem, 4vw, 2.6rem);
  line-height: 1.05;
}

.auth-stage-copy,
.auth-dialog-copy {
  color: rgba(210, 223, 238, 0.88);
  line-height: 1.65;
}

.auth-dialog-card {
  overflow: hidden;
  border: 1px solid rgba(102, 212, 255, 0.22);
  background:
    radial-gradient(circle at top right, rgba(52, 230, 255, 0.12), transparent 40%),
    radial-gradient(circle at bottom left, rgba(149, 115, 255, 0.12), transparent 44%),
    linear-gradient(160deg, rgba(9, 14, 22, 0.96), rgba(12, 19, 31, 0.98));
}

.auth-dialog-topline {
  height: 6px;
  background: linear-gradient(90deg, rgba(52, 230, 255, 0.92), rgba(149, 115, 255, 0.92));
}

.view-fade-enter-active,
.view-fade-leave-active {
  transition: opacity 0.2s ease, transform 0.22s ease;
}

.view-fade-enter-from,
.view-fade-leave-to {
  opacity: 0;
  transform: translateY(6px);
}

@media (max-width: 959px) {
  .app-main {
    padding-bottom: 24px;
  }

  .auth-stage-card {
    padding: 24px;
  }
}
</style>
