<template>
  <div class="chat-view">
    <ViewHeader
      overline="Operación"
      title="Chat"
      :description="''"
      :refresh-loading="loading"
      @refresh="load"
    >
      <template #actions-prepend>
        <v-chip
          size="small"
          variant="tonal"
          :color="canLoad ? 'success' : 'warning'"
          :prepend-icon="canLoad ? 'mdi-shield-check-outline' : 'mdi-shield-lock-outline'"
        >
          {{ canLoad ? "Sesión activa" : "Bloqueado" }}
        </v-chip>
      </template>
    </ViewHeader>

    <v-row density="compact" class="chat-grid">
      <v-col cols="12" lg="8">
        <v-card variant="tonal" class="chat-workspace">
          <div class="chat-toolbar">
            <div class="chat-toolbar__copy">
              <div class="text-subtitle-1 font-weight-medium">Consola segura</div>
              <div class="chat-toolbar__meta">
                {{ filteredMessages.length }} mensajes · {{ commandCount }} comandos
              </div>
            </div>
            <div class="chat-toolbar__actions">
              <v-text-field
                v-model.trim="messageSearch"
                prepend-inner-icon="mdi-magnify"
                placeholder="Buscar"
                variant="outlined"
                density="compact"
                hide-details
                clearable
                class="message-search"
              />
              <v-btn
                icon
                size="small"
                variant="text"
                color="secondary"
                aria-label="Ir al final"
                @click="scrollToEnd"
              >
                <v-icon icon="mdi-arrow-down" />
                <v-tooltip activator="parent" location="bottom">Ir al final</v-tooltip>
              </v-btn>
              <v-btn
                icon
                size="small"
                variant="text"
                color="error"
                :disabled="!messages.length || clearing"
                :loading="clearing"
                aria-label="Limpiar chat"
                @click="clearChat"
              >
                <v-icon icon="mdi-broom" />
                <v-tooltip activator="parent" location="bottom">Limpiar chat</v-tooltip>
              </v-btn>
            </div>
          </div>

          <div class="chat-shortcuts">
            <v-chip
              v-for="shortcut in quickCommands"
              :key="shortcut.command"
              size="small"
              variant="outlined"
              :color="shortcut.color"
              :prepend-icon="shortcut.icon"
              :disabled="sending || !canLoad"
              class="chat-shortcut-chip"
              @click="runCommand(shortcut.command)"
            >
              {{ shortcut.label }}
            </v-chip>
          </div>

          <div ref="log" class="chat-log">
            <div v-if="loading && !messages.length" class="chat-empty">
              Cargando actividad...
            </div>
            <div v-else-if="!filteredMessages.length" class="chat-empty">
              Sin mensajes visibles.
            </div>
            <div
              v-for="message in filteredMessages"
              :key="message.id"
              class="chat-message"
              :class="{
                'chat-message--self': message.author === 'dashboard',
                'chat-message--system': message.author === 'system',
                'chat-message--command': message.kind === 'command',
                'chat-message--result': message.kind === 'command_result',
              }"
            >
              <div class="chat-message__bubble">
                <div class="chat-message__meta">
                  <span>{{ authorLabel(message.author) }}</span>
                  <span>{{ kindLabel(message.kind) }}</span>
                  <span>{{ formatTimestamp(message.created_at) }}</span>
                  <v-btn
                    icon
                    size="x-small"
                    variant="text"
                    color="secondary"
                    class="chat-message__copy"
                    aria-label="Copiar mensaje"
                    @click="copyMessage(message)"
                  >
                    <v-icon icon="mdi-content-copy" size="14" />
                    <v-tooltip activator="parent" location="bottom">Copiar</v-tooltip>
                  </v-btn>
                </div>
                <pre
                  v-if="message.kind === 'command_result'"
                  class="chat-message__content chat-message__content--pre"
                >{{ message.content }}</pre>
                <div v-else class="chat-message__content">{{ message.content }}</div>
              </div>
            </div>
          </div>

          <v-alert v-if="error" type="error" variant="tonal" density="compact" class="mx-4 mt-3">
            {{ error }}
          </v-alert>

          <div class="chat-composer">
            <v-textarea
              ref="composer"
              v-model="draft"
              label="Mensaje o comando"
              placeholder="/status"
              prepend-inner-icon="mdi-console-line"
              variant="outlined"
              density="compact"
              rows="2"
              max-rows="5"
              auto-grow
              hide-details
              maxlength="2000"
              :disabled="sending || !canLoad"
              @keydown="handleComposerKeydown"
            />
            <div class="composer-actions">
              <v-btn
                icon
                size="small"
                variant="text"
                color="secondary"
                :disabled="!draft || sending"
                aria-label="Limpiar entrada"
                @click="draft = ''"
              >
                <v-icon icon="mdi-close" />
                <v-tooltip activator="parent" location="bottom">Limpiar</v-tooltip>
              </v-btn>
              <v-btn
                color="primary"
                variant="flat"
                :loading="sending"
                :disabled="!draft.trim() || !canLoad"
                prepend-icon="mdi-send"
                @click="send"
              >
                Enviar
              </v-btn>
            </div>
          </div>
        </v-card>
      </v-col>

      <v-col cols="12" lg="4">
        <div class="chat-side-stack">
          <v-card variant="tonal" class="side-panel command-panel">
            <div class="side-panel__header">
              <div>
                <div class="text-subtitle-2">Comandos</div>
                <div class="side-panel__meta">{{ filteredCommands.length }} disponibles</div>
              </div>
              <v-icon icon="mdi-lightning-bolt-outline" color="warning" />
            </div>
            <v-text-field
              v-model.trim="commandSearch"
              prepend-inner-icon="mdi-magnify"
              placeholder="Filtrar"
              variant="outlined"
              density="compact"
              hide-details
              clearable
              class="mb-3"
            />
            <div class="command-list">
              <button
                v-for="command in filteredCommands"
                :key="command.command"
                type="button"
                class="command-item"
                @click="insertCommand(command.command)"
              >
                <v-icon :icon="command.icon" size="15" :color="command.color" />
                <span class="command-item__body">
                  <span class="command-item__label">{{ command.label }}</span>
                  <span class="command-item__command">{{ command.command }}</span>
                </span>
              </button>
            </div>
          </v-card>

          <v-card variant="tonal" class="side-panel runtime-panel">
            <div class="side-panel__header">
              <div>
                <div class="text-subtitle-2">Motores</div>
                <div class="side-panel__meta">{{ runtimeModeLabel }}</div>
              </div>
              <v-icon icon="mdi-server-network" color="info" />
            </div>
            <div class="engine-grid">
              <div
                v-for="engine in engineCards"
                :key="engine.key"
                class="engine-tile"
                :class="{ 'engine-tile--running': engine.running }"
              >
                <div class="engine-tile__main">
                  <v-icon :icon="engine.icon" :color="engine.color" size="18" />
                  <div>
                    <div class="engine-tile__label">{{ engine.label }}</div>
                    <div class="engine-tile__value">{{ engine.running ? "activo" : "detenido" }}</div>
                  </div>
                </div>
                <v-btn
                  size="x-small"
                  variant="tonal"
                  :color="engine.running ? 'error' : engine.color"
                  :loading="engineBusy === engine.key"
                  :disabled="Boolean(engineBusy) || !canLoad"
                  @click="toggleEngine(engine.key, !engine.running)"
                >
                  {{ engine.running ? "Stop" : "Start" }}
                </v-btn>
              </div>
            </div>
          </v-card>
        </div>
      </v-col>
    </v-row>
  </div>
</template>

<script>
import store from "../state/appStore";
import ViewHeader from "../components/ui/ViewHeader.vue";
import { copyText } from "../utils/clipboard";
import { formatTimestamp, matchesSearch } from "../utils/traffic";

const QUICK_COMMANDS = [
  { label: "Estado", command: "/status", icon: "mdi-heart-pulse", color: "success" },
  { label: "Alertas", command: "/alerts 8", icon: "mdi-shield-alert-outline", color: "error" },
  { label: "Paquetes", command: "/packets 8", icon: "mdi-ethernet", color: "info" },
  { label: "Top IPs", command: "/top ips 8", icon: "mdi-lan-connect", color: "primary" },
  { label: "Ayuda", command: "/help", icon: "mdi-help-circle-outline", color: "secondary" },
];

const COMMANDS = [
  { label: "Estado general", command: "/status", icon: "mdi-heart-pulse", color: "success" },
  { label: "Iniciar sniffer", command: "/start sniffer", icon: "mdi-play", color: "success" },
  { label: "Detener sniffer", command: "/stop sniffer", icon: "mdi-stop", color: "error" },
  { label: "Iniciar honeypot", command: "/start honeypot", icon: "mdi-play-circle-outline", color: "warning" },
  { label: "Detener honeypot", command: "/stop honeypot", icon: "mdi-stop-circle-outline", color: "error" },
  { label: "Iniciar ambos", command: "/start all", icon: "mdi-playlist-play", color: "success" },
  { label: "Detener ambos", command: "/stop all", icon: "mdi-stop-circle", color: "error" },
  { label: "Modo sniffer", command: "/mode sniffer", icon: "mdi-ethernet", color: "info" },
  { label: "Modo honeypot", command: "/mode honeypot", icon: "mdi-spider-web", color: "warning" },
  { label: "Interfaces", command: "/interfaces", icon: "mdi-lan", color: "primary" },
  { label: "Alertas recientes", command: "/alerts 10", icon: "mdi-shield-alert-outline", color: "error" },
  { label: "Paquetes recientes", command: "/packets 10", icon: "mdi-table-clock", color: "info" },
  { label: "Top IPs", command: "/top ips 10", icon: "mdi-ip-network", color: "primary" },
  { label: "Top puertos", command: "/top ports 10", icon: "mdi-pound", color: "secondary" },
  { label: "Top protocolos", command: "/top protocols 10", icon: "mdi-swap-horizontal", color: "secondary" },
  { label: "Monitores", command: "/monitors", icon: "mdi-target-account", color: "success" },
  { label: "Listeners", command: "/listeners", icon: "mdi-server-security", color: "warning" },
  { label: "Clientes", command: "/clients", icon: "mdi-monitor-dashboard", color: "info" },
  { label: "Ayuda", command: "/help", icon: "mdi-help-circle-outline", color: "secondary" },
];

export default {
  name: "ChatView",
  components: { ViewHeader },
  data() {
    return {
      store,
      messages: [],
      draft: "",
      messageSearch: "",
      commandSearch: "",
      loading: false,
      sending: false,
      clearing: false,
      error: "",
      engineBusy: "",
      quickCommands: QUICK_COMMANDS,
      commands: COMMANDS,
      history: [],
      historyIndex: -1,
    };
  },
  computed: {
    canLoad() {
      return !this.store.state.authRequired || this.store.state.authStatus === "authenticated";
    },
    filteredMessages() {
      const query = String(this.messageSearch || "").trim();
      if (!query) return this.messages;
      return this.messages.filter((message) =>
        matchesSearch(query, [
          message.author,
          message.kind,
          message.content,
          message.created_at,
        ])
      );
    },
    commandCount() {
      return this.messages.filter((message) => message.kind === "command").length;
    },
    filteredCommands() {
      const query = String(this.commandSearch || "").trim();
      const rows = this.commands;
      if (!query) return rows;
      return rows.filter((command) =>
        matchesSearch(query, [command.label, command.command])
      );
    },
    runtime() {
      return this.store.state.runtime && typeof this.store.state.runtime === "object"
        ? this.store.state.runtime
        : {};
    },
    runtimeModeLabel() {
      const mode = String(this.runtime.mode || this.store.state.runtimeMode || "sniffer").trim();
      return `modo ${mode || "sniffer"}`;
    },
    snifferRuntime() {
      return this.runtime.sniffer && typeof this.runtime.sniffer === "object" ? this.runtime.sniffer : {};
    },
    honeypotRuntime() {
      return this.runtime.honeypot && typeof this.runtime.honeypot === "object" ? this.runtime.honeypot : {};
    },
    engineCards() {
      return [
        {
          key: "sniffer",
          label: "Sniffer",
          icon: "mdi-ethernet",
          color: "info",
          running: Boolean(this.snifferRuntime.running),
        },
        {
          key: "honeypot",
          label: "Honeypot",
          icon: "mdi-spider-web",
          color: "warning",
          running: Boolean(this.honeypotRuntime.running),
        },
      ];
    },
  },
  watch: {
    canLoad(ready) {
      if (ready) this.load();
    },
    "store.state.chatRevision"() {
      this.load({ silent: true });
    },
  },
  mounted() {
    this.load();
    window.addEventListener("keydown", this.handleGlobalKeydown);
  },
  beforeUnmount() {
    window.removeEventListener("keydown", this.handleGlobalKeydown);
  },
  methods: {
    formatTimestamp,
    authorLabel(author) {
      if (author === "dashboard") return "Panel";
      if (author === "system") return "Sistema";
      return "Operador";
    },
    kindLabel(kind) {
      if (kind === "command") return "comando";
      if (kind === "command_result") return "salida";
      return "nota";
    },
    load(options = {}) {
      if (!this.canLoad) return Promise.resolve();
      if (!options.silent) this.loading = true;
      this.error = "";
      return this.store
        .listChatMessages(160)
        .then((rows) => {
          this.messages = Array.isArray(rows) ? [...rows].reverse() : [];
          this.$nextTick(this.scrollToEnd);
        })
        .catch((err) => {
          this.error = (err && err.message) || "No se pudo cargar el chat.";
        })
        .finally(() => {
          this.loading = false;
        });
    },
    send() {
      const content = String(this.draft || "").trim();
      if (!content || this.sending || !this.canLoad) return Promise.resolve();
      this.sending = true;
      this.error = "";
      this.rememberHistory(content);
      const request = content.startsWith("/")
        ? this.store.executeConsoleCommand(content)
        : this.store.postChatMessage(content);
      return request
        .then((result) => {
          this.draft = "";
          if (result && result.ok === false) {
            this.error = String(result.output || "El comando no se pudo ejecutar.");
          }
          return this.load({ silent: true });
        })
        .catch((err) => {
          this.error = (err && err.message) || "No se pudo enviar.";
        })
        .finally(() => {
          this.sending = false;
        });
    },
    runCommand(command) {
      this.draft = command;
      return this.send();
    },
    insertCommand(command) {
      this.draft = command;
      this.focusComposer();
    },
    autocompleteCommand() {
      const value = String(this.draft || "").trim().toLowerCase();
      if (!value.startsWith("/")) return false;
      const match = this.commands.find((command) => command.command.toLowerCase().startsWith(value));
      if (!match) return false;
      this.draft = match.command;
      return true;
    },
    rememberHistory(content) {
      this.history = [content, ...this.history.filter((entry) => entry !== content)].slice(0, 30);
      this.historyIndex = -1;
    },
    recallHistory() {
      if (!this.history.length) return;
      this.historyIndex = Math.min(this.historyIndex + 1, this.history.length - 1);
      this.draft = this.history[this.historyIndex] || "";
    },
    handleComposerKeydown(event) {
      if (event.key === "Enter" && !event.shiftKey) {
        event.preventDefault();
        this.send();
        return;
      }
      if (event.key === "Tab" && this.autocompleteCommand()) {
        event.preventDefault();
        return;
      }
      if (event.key === "ArrowUp" && !String(this.draft || "").trim()) {
        event.preventDefault();
        this.recallHistory();
      }
    },
    handleGlobalKeydown(event) {
      const primary = event.ctrlKey || event.metaKey;
      if (!primary) return;
      const key = String(event.key || "").toLowerCase();
      if (key === "k") {
        event.preventDefault();
        this.focusComposer();
      }
      if (key === "/" && !this.draft) {
        event.preventDefault();
        this.insertCommand("/help");
      }
    },
    focusComposer() {
      this.$nextTick(() => {
        const field = this.$refs.composer;
        if (field && typeof field.focus === "function") {
          field.focus();
        }
      });
    },
    scrollToEnd() {
      const log = this.$refs.log;
      if (log) log.scrollTop = log.scrollHeight;
    },
    copyMessage(message) {
      this.copyTextValue(message && message.content, "Mensaje");
    },
    copyTextValue(value, label) {
      copyText(value).then((copied) => {
        this.store.pushNotification({
          kind: "clipboard",
          severity: copied ? "info" : "medium",
          title: copied ? `${label} copiado` : `No se pudo copiar ${label}`,
          message: copied ? "" : "El navegador bloqueó el portapapeles.",
          groupKey: `chat-copy:${label}`,
        });
      });
    },
    clearChat() {
      if (!this.messages.length || this.clearing) return;
      if (typeof window !== "undefined" && !window.confirm("Limpiar el historial visible del chat?")) {
        return;
      }
      this.clearing = true;
      this.error = "";
      this.store
        .fetchJsonPromise("/api/chat/clear", { method: "POST" })
        .then(() => {
          this.messages = [];
        })
        .catch((err) => {
          this.error = (err && err.message) || "No se pudo limpiar el chat.";
        })
        .finally(() => {
          this.clearing = false;
        });
    },
    toggleEngine(engine, shouldRun) {
      if (this.engineBusy || !engine) return;
      this.engineBusy = engine;
      this.error = "";
      this.store
        .controlEngine(engine, shouldRun ? "start" : "stop")
        .catch((err) => {
          this.error = (err && err.message) || `No se pudo ${shouldRun ? "iniciar" : "detener"} ${engine}.`;
        })
        .finally(() => {
          this.engineBusy = "";
        });
    },
  },
};
</script>

<style scoped>
.chat-grid {
  align-items: stretch;
}

.chat-workspace,
.side-panel {
  border-radius: 8px;
}

.chat-workspace {
  /* Needed here: .chat-log is the internal scroller and the card's rounded
     corners must clip it. A side-panel has no internal scroller of its own
     (.chat-side-stack scrolls the whole column instead) - overflow:hidden
     here was clipping any panel content taller than the card's own
     content-based height, cutting off the bottom of the command list. */
  overflow: hidden;
}

.chat-workspace {
  /* Fixed, not min-height: with only a floor, a tall right-hand side stack
     (multiple stacked side panels) stretched this card past the viewport
     via v-row's align-items: stretch, pushing the composer off-screen and
     making the whole page scroll instead of just the message log. Capping
     it keeps the toolbar/shortcuts/composer put and leaves .chat-log's own
     overflow-y (below) as the only thing that scrolls. */
  height: calc(100vh - 186px);
  max-height: calc(100vh - 186px);
  display: flex;
  flex-direction: column;
}

.chat-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 12px 14px 10px;
  border-bottom: 1px solid rgba(var(--brand-sky-rgb), 0.14);
}

.chat-toolbar__copy {
  min-width: 0;
}

.chat-toolbar__meta,
.side-panel__meta {
  color: var(--text-dim);
  font-size: 0.74rem;
}

.chat-toolbar__actions {
  min-width: 0;
  display: flex;
  align-items: center;
  gap: 6px;
}

.message-search {
  width: min(30vw, 230px);
}

.chat-shortcuts {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  padding: 8px 14px;
  border-bottom: 1px solid rgba(var(--brand-sky-rgb), 0.1);
}

.chat-shortcut-chip {
  cursor: pointer;
  font-weight: 650;
}

.chat-log {
  /* flex-basis 0 + min-height 0 is what lets this shrink below its
     content's natural height instead of forcing the fixed-height
     .chat-workspace to overflow - without min-height: 0, a flex child's
     implicit height floor is its own content, which is exactly what pushed
     the composer below out of the clipped (overflow: hidden) card. This is
     the ONLY flexible element in that column; toolbar/shortcuts/composer
     keep their natural height and always stay visible. */
  flex: 1 1 0;
  min-height: 0;
  overflow-y: auto;
  padding: 14px;
  background: rgba(2, 8, 14, 0.58);
}

.chat-empty {
  min-height: 260px;
  display: grid;
  place-content: center;
  color: var(--text-dim);
  font-size: 0.9rem;
}

.chat-message {
  display: flex;
  justify-content: flex-start;
  margin-bottom: 9px;
}

.chat-message--self {
  justify-content: flex-end;
}

.chat-message__bubble {
  width: fit-content;
  max-width: min(760px, 86%);
  padding: 8px 10px;
  border-radius: 8px;
  border: 1px solid rgba(var(--brand-sky-rgb), 0.16);
  background: rgba(var(--brand-sky-rgb), 0.08);
}

.chat-message--self .chat-message__bubble {
  background: rgba(var(--brand-cyan-rgb), 0.1);
  border-color: rgba(var(--brand-cyan-rgb), 0.24);
}

.chat-message--system .chat-message__bubble {
  background: rgba(18, 27, 42, 0.88);
}

.chat-message--result .chat-message__bubble {
  max-width: min(840px, 94%);
  background: rgba(var(--brand-violet-rgb), 0.1);
  border-color: rgba(var(--brand-violet-rgb), 0.28);
}

.chat-message__meta {
  display: flex;
  align-items: center;
  gap: 7px;
  margin-bottom: 4px;
  color: rgba(191, 210, 232, 0.68);
  font-size: 0.66rem;
  text-transform: uppercase;
}

.chat-message__copy {
  /* Was opacity: 0 until hover/focus - easy to miss entirely on a touch
     device, or just never noticed, which is exactly what was reported as
     "missing". Always visible now, just dimmed until hovered/focused. */
  margin-left: auto;
  opacity: 0.55;
}

.chat-message__bubble:hover .chat-message__copy,
.chat-message__copy:focus-visible {
  opacity: 1;
}

.chat-message__content {
  color: var(--text-soft);
  font-size: 0.84rem;
  line-height: 1.42;
  white-space: pre-wrap;
  word-break: break-word;
}

.chat-message__content--pre {
  margin: 0;
  font-family: var(--font-mono);
  font-size: 0.78rem;
}

.chat-message--command .chat-message__content {
  font-family: var(--font-mono);
}

.chat-composer {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 10px;
  align-items: end;
  padding: 12px 14px 14px;
  border-top: 1px solid rgba(var(--brand-sky-rgb), 0.14);
}

.composer-actions {
  display: flex;
  align-items: center;
  gap: 6px;
}

.chat-side-stack {
  display: grid;
  align-content: start;
  gap: 10px;
  /* v-row's align-items: stretch matches this column's height to
     .chat-workspace, now fixed (see above) - scroll internally instead of
     overflowing that fixed box and dragging the page down with it. */
  height: calc(100vh - 186px);
  max-height: calc(100vh - 186px);
  overflow-y: auto;
}

.side-panel {
  padding: 12px;
}

.side-panel__header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 10px;
  margin-bottom: 10px;
}

.command-list {
  /* No max-height/scroll of its own: .chat-side-stack (the whole right
     column) already scrolls as one unit - nesting a second scroll region
     in here just hid most of the list behind its own tiny scrollbar
     instead of the column's. */
  display: grid;
  gap: 4px;
}

.command-item {
  width: 100%;
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 5px 8px;
  border: 1px solid rgba(var(--brand-sky-rgb), 0.14);
  border-radius: 6px;
  background: rgba(4, 10, 18, 0.45);
  color: inherit;
  cursor: pointer;
  text-align: left;
}

.command-item:hover,
.command-item:focus-visible {
  border-color: rgba(var(--brand-cyan-rgb), 0.42);
  background: rgba(var(--brand-cyan-rgb), 0.08);
  outline: none;
}

.command-item__body {
  min-width: 0;
  display: grid;
  gap: 1px;
}

.command-item__label {
  font-size: 0.78rem;
  color: var(--text-soft);
}

.command-item__command {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font: 0.68rem var(--font-mono);
  color: var(--text-dim);
}

.engine-grid {
  display: grid;
  gap: 8px;
}

.engine-tile {
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 8px;
  padding: 7px 8px;
  border-radius: 6px;
  border: 1px solid rgba(var(--brand-sky-rgb), 0.14);
  background: rgba(4, 10, 18, 0.45);
}

.engine-tile--running {
  border-color: rgba(74, 215, 183, 0.34);
}

.engine-tile__main {
  min-width: 0;
  display: flex;
  align-items: center;
  gap: 9px;
}

.engine-tile__label {
  font-size: 0.84rem;
  font-weight: 650;
}

.engine-tile__value {
  color: var(--text-dim);
  font-size: 0.74rem;
}

@media (max-width: 959px) {
  .chat-workspace,
  .chat-side-stack {
    /* Below lg, v-col stacks the two chat-grid columns instead of placing
       them side by side, so there's no more align-items: stretch height to
       fight - let both size to their natural content and the page scroll
       normally, same as any other stacked mobile layout. */
    height: auto;
    max-height: none;
    overflow-y: visible;
  }

  .chat-toolbar,
  .chat-composer {
    grid-template-columns: 1fr;
    align-items: stretch;
  }

  .chat-toolbar {
    flex-direction: column;
  }

  .chat-toolbar__actions,
  .message-search {
    width: 100%;
  }

  .chat-log {
    min-height: 360px;
    max-height: 58vh;
  }
}

@media (max-width: 600px) {
  .chat-shortcuts :deep(.v-chip) {
    flex: 1 1 calc(50% - 8px);
    justify-content: center;
  }

  .chat-message__bubble {
    max-width: 94%;
  }

  .composer-actions {
    justify-content: flex-end;
  }
}
</style>
