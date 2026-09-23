<template>
  <div class="chat-view">
    <header class="chat-header">
      <div class="chat-identity">
        <div class="chat-identity__title"><v-icon icon="mdi-console-line" color="primary" size="22" /><h1>Sniff4Hound <span>Chat</span></h1></div>
        <p>Tu espacio de operaciones</p>
        <div class="session-status"><span :class="{ 'session-status__dot--active': canLoad }" />{{ canLoad ? 'Sesión activa' : 'Sesión bloqueada' }}<span class="chat-counter">{{ filteredMessages.length }} mensajes · {{ commandCount }} comandos</span></div>
      </div>

      <aside class="chat-tools" aria-label="Herramientas y comandos del chat">
        <div class="tools-toolbar">
          <label class="message-search"><v-icon icon="mdi-magnify" size="16" /><input v-model="messageSearch" type="search" placeholder="Buscar en el chat" aria-label="Buscar en el chat" /></label>
          <v-btn icon="mdi-refresh" size="x-small" variant="text" :loading="loading" :disabled="!canLoad" aria-label="Actualizar chat" @click="load"><v-icon size="17" /><v-tooltip activator="parent">Actualizar chat</v-tooltip></v-btn>
          <v-btn icon="mdi-arrow-down" size="x-small" variant="text" aria-label="Ir al final" @click="scrollToEnd"><v-icon size="17" /><v-tooltip activator="parent">Ir al final</v-tooltip></v-btn>
          <v-btn icon="mdi-broom" size="x-small" variant="text" color="error" :loading="clearing" :disabled="!messages.length || clearing || !canLoad" aria-label="Limpiar chat" @click="clearChat"><v-icon size="17" /><v-tooltip activator="parent">Limpiar chat</v-tooltip></v-btn>
        </div>
        <div class="tools-engines">
          <span class="tools-caption">{{ runtimeModeLabel }}</span>
          <button v-for="engine in engineCards" :key="engine.key" type="button" class="engine-control" :disabled="Boolean(engineBusy) || !canLoad" :aria-label="`${engine.running ? 'Detener' : 'Iniciar'} ${engine.label}`" @click="toggleEngine(engine.key, !engine.running)">
            <span class="engine-dot" :class="{ 'engine-dot--active': engine.running }" />{{ engine.label }}
            <v-icon :icon="engineBusy === engine.key ? 'mdi-loading' : engine.running ? 'mdi-stop' : 'mdi-play'" :class="{ 'spin': engineBusy === engine.key }" size="14" />
            <v-tooltip activator="parent">{{ engine.running ? 'Activo · detener' : 'Detenido · iniciar' }}</v-tooltip>
          </button>
        </div>
        <div class="command-heading"><span>COMANDOS <small>{{ commands.length }}</small></span><span>Selecciona para escribir</span></div>
        <div class="command-grid">
          <button v-for="command in commands" :key="command.command" type="button" class="command-item" :disabled="sending || !canLoad" :aria-label="`${command.label}: ${command.command}`" @click="insertCommand(command.command)">
            <v-icon :icon="command.icon" size="13" :color="command.color" /><span>{{ command.label }}</span>
            <v-tooltip activator="parent" location="bottom">{{ command.command }}</v-tooltip>
          </button>
        </div>
      </aside>
    </header>

    <main class="chat-workspace">
      <div ref="log" class="chat-log" role="log" aria-label="Conversación" :aria-busy="loading">
        <div v-if="loading && !messages.length" class="chat-empty"><v-progress-circular indeterminate size="24" width="2" color="primary" /><p>Cargando conversación…</p></div>
        <div v-else-if="!messages.length && !messageSearch" class="chat-empty">
          <div class="welcome-mark"><v-icon icon="mdi-console-line" size="32" /></div>
          <h2>¿Qué quieres revisar?</h2>
          <p>Consulta la actividad de tu red, ejecuta comandos<br class="desktop-break" /> o deja una nota para tu próxima investigación.</p>
          <div class="welcome-suggestions">
            <button v-for="shortcut in quickCommands" :key="shortcut.command" type="button" :disabled="sending || !canLoad" @click="insertCommand(shortcut.command)"><v-icon :icon="shortcut.icon" size="18" :color="shortcut.color" />{{ shortcut.label }}<v-icon icon="mdi-arrow-top-right" size="14" /></button>
          </div>
        </div>
        <div v-else-if="!filteredMessages.length" class="chat-empty"><v-icon icon="mdi-magnify" size="30" /><h2>Sin coincidencias</h2><p>Prueba otra búsqueda para encontrar un mensaje.</p><v-btn variant="text" size="small" @click="messageSearch = ''">Ver conversación</v-btn></div>
        <div v-for="message in filteredMessages" :key="message.id" class="chat-message" :class="{ 'chat-message--self': message.author === 'dashboard', 'chat-message--result': message.kind === 'command_result' }">
          <div v-if="message.author !== 'dashboard'" class="message-avatar"><v-icon icon="mdi-console-line" size="18" /></div>
          <article class="chat-message__bubble">
            <div class="chat-message__meta"><strong>{{ authorLabel(message.author) }}</strong><span>{{ kindLabel(message.kind) }}</span><time>{{ formatTimestamp(message.created_at) }}</time><v-btn icon="mdi-content-copy" size="x-small" variant="text" aria-label="Copiar mensaje" @click="copyMessage(message)"><v-icon size="13" /><v-tooltip activator="parent">Copiar mensaje</v-tooltip></v-btn></div>
            <pre v-if="message.kind === 'command_result'" class="chat-message__content chat-message__content--pre">{{ message.content }}</pre>
            <div v-else class="chat-message__content">{{ message.content }}</div>
          </article>
        </div>
      </div>
      <div class="composer-wrap">
        <v-alert v-if="error" type="error" variant="tonal" density="compact" class="mb-3">{{ error }}</v-alert>
        <div class="chat-composer">
          <v-textarea ref="composer" v-model="draft" aria-label="Mensaje o comando" placeholder="Escribe un mensaje o un comando…" variant="plain" rows="1" max-rows="5" auto-grow hide-details maxlength="2000" :disabled="sending || !canLoad" @keydown="handleComposerKeydown" />
          <div class="composer-footer"><span><v-icon icon="mdi-console" size="14" /> / para comandos</span><div class="composer-actions"><v-btn v-if="draft" icon="mdi-close" size="x-small" variant="text" :disabled="sending" aria-label="Limpiar entrada" @click="draft = ''" /><v-btn icon="mdi-arrow-up" size="small" color="primary" variant="flat" :loading="sending" :disabled="!draft.trim() || !canLoad" aria-label="Enviar mensaje" @click="send" /></div></div>
        </div>
        <p class="composer-hint">Enter para enviar <span>·</span> Shift + Enter para nueva línea <span>·</span> Tab autocompleta comandos</p>
      </div>
    </main>
  </div>
</template>

<script>
import store from "../state/appStore";
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
  data() {
    return {
      store,
      messages: [],
      draft: "",
      messageSearch: "",
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
      if (author === "dashboard") return "Tú";
      if (author === "system") return "Sniff4Hound";
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
      if (event.isComposing) return;
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
.chat-view { height: calc(100dvh - var(--v-layout-top, 0px) - var(--v-layout-bottom, 0px)); display: flex; flex-direction: column; overflow: hidden; background: radial-gradient(ellipse at 45% 42%, rgba(27, 79, 93, .09), transparent 60%), #080e16; color: var(--text-soft); }
.chat-header { display: flex; justify-content: space-between; align-items: flex-start; gap: 24px; padding: 18px 24px 0; flex-shrink: 0; }
.chat-identity { padding-top: 6px; }
.chat-identity__title { display: flex; align-items: center; gap: 10px; }
h1 { font-size: 1rem; letter-spacing: .01em; }
h1 span { font-weight: 400; color: var(--text-dim); margin-left: 6px; }
.chat-identity p { font-size: .78rem; color: var(--text-dim); margin: 8px 0 15px; }
.session-status { display: flex; align-items: center; flex-wrap: wrap; gap: 7px; font-size: .67rem; color: var(--text-dim); }
.session-status > span:first-child, .engine-dot { width: 6px; height: 6px; border-radius: 50%; background: #708095; flex-shrink: 0; }
.session-status > .session-status__dot--active, .engine-dot--active { background: #4bd4b0; box-shadow: 0 0 8px #4bd4b033; }
.chat-counter { display: block; flex-basis: 100%; margin-left: 13px; opacity: .7; }
.chat-tools { width: 570px; flex-shrink: 0; padding: 10px 12px; border: 1px solid #7ab6d21c; border-radius: 12px; background: #101a26c9; }
.tools-toolbar, .tools-engines, .command-heading, .engine-control { display: flex; align-items: center; gap: 7px; }
.tools-toolbar { gap: 3px; }
.message-search { display: flex; align-items: center; gap: 7px; flex: 1; min-width: 0; color: var(--text-dim); }
.message-search input { width: 100%; min-width: 0; font-size: .72rem; color: var(--text-soft); outline: none; padding: 5px 0; }
.message-search:focus-within { color: #4ed9eb; }
.tools-engines { margin: 5px 0 10px; }
.tools-caption { font-size: .65rem; color: var(--text-dim); margin-right: auto; }
.engine-control { font-size: .65rem; padding: 3px 7px; border: 1px solid #7ab6d222; border-radius: 5px; }
.command-heading { justify-content: space-between; font-size: .58rem; color: var(--text-dim); padding-top: 8px; border-top: 1px solid #7ab6d217; margin-bottom: 6px; letter-spacing: .05em; }
.command-heading small { color: #45cede; margin-left: 4px; font-size: inherit; }
.command-heading > span:last-child { letter-spacing: 0; }
.command-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 4px; }
.command-item { display: flex; align-items: center; gap: 5px; min-width: 0; padding: 5px 6px; border-radius: 5px; background: #9dc7de06; border: 1px solid #9dc7de10; text-align: left; font-size: .63rem; line-height: 1.2; }
.command-item:hover, .engine-control:hover { background: #36c9dc15; border-color: #36c9dc55; }
button:focus-visible { outline: 2px solid #36c9dc; outline-offset: 2px; }
button:disabled { opacity: .4; cursor: default; }
.chat-workspace { display: flex; flex-direction: column; flex: 1; min-height: 0; }
.chat-log { flex: 1; min-height: 0; overflow-y: auto; padding: 24px max(24px, calc((100% - 860px) / 2)); scrollbar-width: thin; scrollbar-color: #263b4b transparent; }
.chat-empty { min-height: 100%; display: flex; flex-direction: column; justify-content: center; align-items: center; text-align: center; gap: 14px; padding: 20px 0 32px; }
.welcome-mark { display: grid; place-items: center; width: 58px; height: 58px; border: 1px solid #3ed5e333; background: linear-gradient(145deg, #153b49, #111d30); border-radius: 18px; color: #49d4e6; box-shadow: 0 0 42px #30c6dc0d; }
.chat-empty h2 { font-size: clamp(1.35rem, 2.3vw, 2rem); letter-spacing: -.025em; font-weight: 600; }
.chat-empty p { font-size: .85rem; line-height: 1.7; color: var(--text-dim); }
.welcome-suggestions { display: flex; justify-content: center; flex-wrap: wrap; gap: 8px; margin-top: 10px; }
.welcome-suggestions button { display: flex; align-items: center; gap: 9px; padding: 10px 12px; border: 1px solid #aac9e01c; border-radius: 10px; font-size: .75rem; background: #aac9e004; }
.welcome-suggestions button:hover { background: #aac9e00d; border-color: #46cfdf55; }
.chat-message { display: flex; align-items: flex-start; gap: 12px; margin: 0 auto 26px; max-width: 860px; }
.message-avatar { display: grid; place-items: center; width: 30px; height: 30px; flex-shrink: 0; border: 1px solid #40d4e32a; border-radius: 9px; color: #4ad5e3; background: #14313b; margin-top: 3px; }
.chat-message__bubble { min-width: 0; flex: 1; }
.chat-message--self { justify-content: flex-end; }
.chat-message--self .chat-message__bubble { flex: 0 1 auto; max-width: 85%; background: #1b2c3b; padding: 10px 16px 14px; border-radius: 18px 18px 4px 18px; }
.chat-message__meta { display: flex; align-items: center; flex-wrap: wrap; gap: 8px; color: var(--text-dim); font-size: .62rem; margin-bottom: 6px; }
.chat-message__meta strong { color: var(--text-soft); font-size: .75rem; }
.chat-message__meta time { margin-left: auto; }
.chat-message__content { font-size: .9rem; line-height: 1.75; white-space: pre-wrap; overflow-wrap: anywhere; }
.chat-message__content--pre { padding: 16px; border: 1px solid #8bc5dc22; border-radius: 12px; background: #050b12; font-family: var(--font-mono); font-size: .78rem; line-height: 1.65; margin: 0; overflow-x: auto; }
.composer-wrap { width: min(860px, calc(100% - 48px)); margin: 0 auto; flex-shrink: 0; padding-top: 6px; }
.chat-composer { padding: 10px 16px; border: 1px solid #8bb6ce30; background: #15212e; border-radius: 22px; box-shadow: 0 10px 30px #0002; }
.chat-composer:focus-within { border-color: #51b7cb77; }
.chat-composer :deep(.v-field__input) { padding: 4px 0 8px; font-size: .9rem; min-height: 36px; }
.chat-composer :deep(.v-field) { --v-field-padding-top: 0px; }
.composer-footer, .composer-actions { display: flex; align-items: center; justify-content: space-between; gap: 6px; }
.composer-footer > span { display: flex; align-items: center; gap: 6px; font-size: .67rem; color: var(--text-dim); }
.composer-hint { text-align: center; color: var(--text-dim); opacity: .7; font-size: .61rem; padding: 9px 0 13px; }
.composer-hint span { margin: 0 8px; }
.spin { animation: spin 1s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }
@media (max-width: 1100px) { .chat-header { padding: 12px 16px 0; gap: 12px; } .chat-tools { width: 510px; } .command-item { font-size: .6rem; padding: 5px 4px; } }
@media (max-width: 800px) { .chat-header { flex-direction: column; gap: 10px; } .chat-identity { display: flex; align-items: center; justify-content: space-between; width: 100%; gap: 12px; padding: 0; } .chat-identity p, .chat-counter { display: none; } .chat-tools { width: 100%; } .chat-log { padding: 20px 16px; } .chat-empty { padding: 12px 0; } .composer-wrap { width: calc(100% - 24px); } }
@media (max-width: 480px) { .chat-header { padding: 8px 10px 0; } h1 { font-size: .85rem; } .chat-tools { padding: 7px 8px; } .command-grid { grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 3px; } .command-item { font-size: .6rem; } .command-heading { margin-bottom: 5px; } .tools-engines { margin-bottom: 6px; } .composer-hint { font-size: .55rem; } .composer-hint span { margin: 0 3px; } .chat-message--self .chat-message__bubble { max-width: 95%; } .desktop-break { display: none; } }
@media (max-height: 700px) and (max-width: 800px) { .chat-view { overflow-y: auto; } .chat-workspace { flex: 1 0 340px; } }
</style>
