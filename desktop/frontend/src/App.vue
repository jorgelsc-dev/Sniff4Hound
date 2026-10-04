<template>
  <v-app class="sniff4hound-app">
    <AppTopBar
      :shutdown-pending="shutdownPending"
      :shutdown-label="shutdownLabel"
      :remote-backend="desktopRemoteBackend"
      @shutdown-app="shutdownApplication"
    />
    <GlobalToolsMenu
      :shutdown-pending="shutdownPending"
      :shutdown-label="shutdownLabel"
      :remote-backend="desktopRemoteBackend"
      @shutdown-app="shutdownApplication"
    />
    <!-- Only once the session can actually reach the API: every entry either
         routes into a guarded view or calls the runtime. -->
    <CommandPalette v-if="canRenderViews" />
    <PendingJobsIndicator />

    <v-main class="app-main" :class="{ 'app-main--canvas': $route.meta.canvasOnly && canRenderViews }">
      <v-container class="app-container" :class="{ 'app-container--full': isFullWidthRoute }" :fluid="isFullWidthRoute">
        <div v-if="canRenderViews">
          <!-- Persistent across every table route: the pipeline is how you
               reach a table, so it must not unmount the moment you do.
               Skipped on canvasOnly routes (Settings/Chat), which are a
               full-bleed canvas already and would end up stacking two. -->
          <FlowShell v-if="!$route.meta.canvasOnly" />
          <div class="app-view">
            <router-view v-slot="{ Component }">
              <transition name="view-fade" mode="out-in">
                <component :is="Component" />
              </transition>
            </router-view>
          </div>
        </div>

        <div v-else class="auth-stage">
          <v-sheet class="auth-stage-card" rounded="lg" elevation="0">
            <div class="auth-stage-kicker">Consola protegida</div>
            <h1 class="auth-stage-title">Autenticación requerida</h1>
            <p class="auth-stage-copy">
              Introduce el código de seguridad mostrado en la terminal para desbloquear el
              panel y reanudar el acceso HTTP y WebSocket.
            </p>
            <v-btn color="primary" size="large" variant="flat" @click="openAuthPrompt">
              Introducir código
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
      <v-card class="auth-dialog-card" rounded="lg">
        <div class="auth-dialog-topline" />
        <v-card-title class="text-h5 pt-6">Código de seguridad</v-card-title>
        <v-card-text class="pt-4">
          <p class="auth-dialog-copy">
            Abre el enlace de inicio desde la terminal de `sniff4hound` o introduce aquí
            el código de 8 caracteres. El panel lo usa para el acceso API y WebSocket.
          </p>
          <v-alert
            type="info"
            variant="tonal"
            density="compact"
            class="mb-4"
            icon="mdi-shield-lock-outline"
          >
            El enlace de inicio conserva el código para esta pestaña. Cierra sesión o
            introduce un código nuevo para reemplazarlo.
          </v-alert>
          <v-text-field
            ref="authInput"
            v-model="accessTokenInput"
            label="Código de seguridad"
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
            Autenticar
          </v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>
  </v-app>
</template>

<script>
import { nextTick } from "vue";
import store from "./state/appStore";
import AppTopBar from "./components/layout/AppTopBar.vue";
import GlobalToolsMenu from "./components/layout/GlobalToolsMenu.vue";
import CommandPalette from "./components/layout/CommandPalette.vue";
import PendingJobsIndicator from "./components/layout/PendingJobsIndicator.vue";
import FlowShell from "./components/layout/FlowShell.vue";

// Purely a UX beat: give the operator a moment to see the "shutting down"
// state (and the backend a moment to actually stop) before the tab closes
// itself out from under them.
const SHUTDOWN_TAB_CLOSE_DELAY_MS = 4000;

function readDesktopBackendMode() {
  if (typeof window === "undefined" || !window.location) return "local";
  try {
    const parsed = new URL(window.location.href);
    return String(parsed.searchParams.get("desktop_backend") || "local").trim().toLowerCase();
  } catch {
    return "local";
  }
}

export default {
  name: "App",
  components: {
    AppTopBar,
    GlobalToolsMenu,
    CommandPalette,
    PendingJobsIndicator,
    FlowShell,
  },
  data() {
    return {
      store,
      accessTokenInput: "",
      authSubmitting: false,
      shutdownLabel: "",
      desktopBackendMode: readDesktopBackendMode(),
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
    shutdownPending() {
      return Boolean(this.store.state.shutdownPending);
    },
    desktopRemoteBackend() {
      return this.desktopBackendMode === "remote";
    },
    // Dedicated map/graph dashboards ask to fill the whole viewport instead
    // of sitting inside the app's usual 1560px-max content column.
    isFullWidthRoute() {
      return Boolean(this.$route.meta && this.$route.meta.fullWidth);
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
      if (this.desktopRemoteBackend) {
        if (typeof window !== "undefined") {
          const confirmed = window.confirm("Close Sniff4Hound Desktop?");
          if (!confirmed) return;
          const desktopApi = window.sniff4houndDesktop;
          if (desktopApi && typeof desktopApi.close === "function") {
            desktopApi.close();
            return;
          }
          if (typeof window.close === "function") {
            window.close();
          }
        }
        return;
      }
      if (typeof window !== "undefined") {
        const confirmed = window.confirm(
          "Stop Sniff4Hound and close the local dashboard process?"
        );
        if (!confirmed) return;
      }
      this.shutdownLabel = "Apagando...";
      this.store.shutdownApplication().catch((error) => {
        // The backend is terminating itself either way - a failed response
        // here is usually just the connection dropping mid-request, not a
        // real failure worth alarming over. Still surface it, but the tab
        // closes on schedule regardless.
        if (typeof window !== "undefined" && error && error.message) {
          window.alert(error.message);
        }
      });
      setTimeout(() => {
        if (typeof window === "undefined" || typeof window.close !== "function") return;
        this.shutdownLabel = "Cerrando pestaña...";
        // Browsers silently ignore window.close() on a tab the user
        // navigated to directly (as opposed to one opened via
        // window.open()) - there's no client-side way to detect or work
        // around that, so this is a best-effort close, not a guarantee.
        window.close();
      }, SHUTDOWN_TAB_CLOSE_DELAY_MS);
    },
  },
};
</script>

<style scoped>
.app-container {
  max-width: 1560px;
  width: 100%;
  padding: var(--app-gutter);
  min-width: 0;
}

.app-container--full {
  max-width: none;
}

.app-main {
  padding-bottom: 40px;
}

.app-main--canvas {
  padding-bottom: 0;
  --app-canvas-height: calc(100dvh - var(--v-layout-top, 48px) - var(--v-layout-bottom, 0px));
}

.app-main--canvas .app-container {
  padding: 0;
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
  background: var(--surface-1);
}

.auth-stage-kicker {
  color: rgba(52, 230, 255, 0.96);
  font-size: 0.78rem;
  font-weight: 700;
  letter-spacing: 0;
  text-transform: uppercase;
}

.auth-stage-title {
  margin: 12px 0 10px;
  font-size: 2rem;
  line-height: 1.2;
  overflow-wrap: anywhere;
}

.auth-stage-copy,
.auth-dialog-copy {
  color: rgba(210, 223, 238, 0.88);
  line-height: 1.65;
  margin-bottom: 20px;
}

.auth-dialog-card {
  overflow: hidden;
  border: 1px solid rgba(102, 212, 255, 0.22);
  background: var(--surface-1);
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

  .app-main--canvas {
    padding-bottom: 0;
  }

  .auth-stage-card {
    padding: 24px;
  }
}

@media (max-width: 600px) {
  .auth-stage-card { padding: 20px; }
  .auth-stage-title { font-size: 1.5rem; }
}
</style>
