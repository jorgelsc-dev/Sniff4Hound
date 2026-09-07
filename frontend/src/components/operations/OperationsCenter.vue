<template>
  <v-row dense class="operations-center">
    <v-col cols="12" lg="7">
      <v-card variant="tonal" class="pa-0 h-100 operations-card">
        <div class="operations-header">
          <div>
            <div class="text-overline">Centro de mando</div>
            <h2 class="text-h6">Chat y consola operativa</h2>
            <p class="text-caption text-medium-emphasis mt-1">
              Las notas se comparten con la terminal. Los mensajes que comienzan con / ejecutan
              únicamente operaciones registradas de Sniff4Hound, nunca comandos del sistema.
            </p>
          </div>
          <v-chip size="small" variant="tonal" color="success" prepend-icon="mdi-shield-check-outline">
            Consola segura
          </v-chip>
        </div>

        <div class="quick-commands px-4 pb-3">
          <v-chip
            v-for="command in quickCommands"
            :key="command"
            size="small"
            variant="outlined"
            color="info"
            :disabled="sending"
            @click="runQuickCommand(command)"
          >
            {{ command }}
          </v-chip>
        </div>

        <div ref="log" class="operations-log">
          <div v-if="loadingChat && !messages.length" class="operations-empty">Cargando actividad…</div>
          <div v-else-if="!messages.length" class="operations-empty">
            Sin actividad todavía. Prueba <code>/help</code> o escribe una nota para el operador.
          </div>
          <div
            v-for="message in messages"
            :key="message.id"
            class="operations-message"
            :class="[`kind-${message.kind || 'note'}`, { 'is-self': message.author === 'dashboard' }]"
          >
            <div class="operations-message__meta">
              <span>{{ authorLabel(message.author) }}</span>
              <span>{{ formatTimestamp(message.created_at) }}</span>
            </div>
            <pre v-if="message.kind === 'command_result'" class="operations-message__content">{{ message.content }}</pre>
            <div v-else class="operations-message__content">{{ message.content }}</div>
          </div>
        </div>

        <v-alert v-if="consoleError" type="error" variant="tonal" density="compact" class="mx-4 mt-3">
          {{ consoleError }}
        </v-alert>
        <div class="operations-compose">
          <v-text-field
            v-model="draft"
            label="Mensaje o comando"
            placeholder="/status"
            prepend-inner-icon="mdi-console-line"
            density="comfortable"
            variant="outlined"
            hide-details
            maxlength="500"
            :disabled="sending"
            @keyup.enter="send"
          />
          <v-btn color="primary" variant="flat" :loading="sending" :disabled="!draft.trim()" @click="send">
            Ejecutar
          </v-btn>
        </div>
      </v-card>
    </v-col>

    <v-col cols="12" lg="5">
      <v-card variant="tonal" class="pa-0 h-100 operations-card">
        <div class="operations-header">
          <div>
            <div class="text-overline">Detección en vivo</div>
            <h2 class="text-h6">Alertas recientes</h2>
          </div>
          <div class="d-flex align-center ga-2">
            <v-chip size="small" :color="visibleAlerts.length ? 'error' : 'success'" variant="tonal">
              {{ visibleAlerts.length }} visibles
            </v-chip>
            <v-chip size="small" color="warning" variant="tonal" prepend-icon="mdi-brain">
              IA {{ aiCandidates.length }}
            </v-chip>
            <v-btn icon="mdi-refresh" size="x-small" variant="text" :loading="loadingAlerts" aria-label="Actualizar alertas" @click="loadAlerts" />
          </div>
        </div>
        <div v-if="!visibleAlerts.length && !loadingAlerts" class="alerts-empty">
          <v-icon icon="mdi-shield-check-outline" size="34" color="success" />
          <span>No hay alertas recientes.</span>
        </div>
        <div v-else class="alerts-list">
          <router-link
            v-for="alert in visibleAlerts"
            :key="`${alert.kind}-${alert.packet_id}-${alert.monitor_id || ''}`"
            class="alert-row"
            :to="alertLink(alert)"
          >
            <v-icon :icon="severityIcon(alert.severity)" :color="severityColor(alert.severity)" size="20" />
            <div class="alert-row__body">
              <div class="d-flex align-center justify-space-between ga-2">
                <strong>{{ alertTitle(alert) }}</strong>
                <v-chip size="x-small" :color="severityColor(alert.severity)" variant="tonal">
                  {{ alert.severity || "info" }}
                </v-chip>
              </div>
              <div class="alert-row__flow">
                {{ alert.src_ip || "?" }}:{{ alert.src_port || 0 }} → {{ alert.dst_ip || "?" }}:{{ alert.dst_port || 0 }}
              </div>
              <div v-if="alert.detail" class="text-caption text-medium-emphasis text-truncate">{{ alert.detail }}</div>
            </div>
          </router-link>
        </div>
        <div class="alerts-footer">
          <v-btn size="small" variant="text" prepend-icon="mdi-shield-search" to="/soc">Abrir SOC</v-btn>
          <v-btn size="small" variant="text" prepend-icon="mdi-bell-outline" to="/monitors">Ver todas</v-btn>
        </div>
      </v-card>
    </v-col>
  </v-row>
</template>

<script>
import store from "../../state/appStore";
import { formatTimestamp } from "../../utils/traffic";

export default {
  name: "OperationsCenter",
  data() {
    return {
      store,
      messages: [],
      alerts: [],
      aiCandidates: [],
      draft: "",
      sending: false,
      loadingChat: false,
      loadingAlerts: false,
      consoleError: "",
      refreshTimer: null,
      stopRefreshSubscription: null,
      quickCommands: ["/status", "/alerts 5", "/top ips 5", "/packets 5", "/help"],
    };
  },
  watch: {
    "store.state.chatRevision"() {
      this.loadMessages();
    },
  },
  computed: {
    visibleAlerts() {
      const monitorAlerts = this.alerts.map((alert) => ({ ...alert, kind: "monitor" }));
      const aiAlerts = this.aiCandidates.map((packet) => ({
        ...packet,
        kind: "ai",
        severity: Number(packet.priority_score || 0) >= 80 ? "high" : "medium",
        detail: `Prioridad ${packet.priority_score ?? packet.score ?? "—"}/100 · candidato sin alerta de reglas`,
      }));
      return [...monitorAlerts, ...aiAlerts]
        .sort((left, right) => String(right.created_at || "").localeCompare(String(left.created_at || "")))
        .slice(0, 8);
    },
  },
  mounted() {
    this.loadMessages();
    this.loadAlerts();
    this.refreshTimer = setInterval(this.loadAlerts, 15000);
    this.stopRefreshSubscription = this.store.subscribeTableRefresh(() => this.loadAlerts());
  },
  beforeUnmount() {
    if (this.refreshTimer) clearInterval(this.refreshTimer);
    if (typeof this.stopRefreshSubscription === "function") this.stopRefreshSubscription();
  },
  methods: {
    formatTimestamp,
    authorLabel(author) {
      if (author === "dashboard") return "Panel";
      if (author === "system") return "Sniff4Hound";
      return "Operador";
    },
    severityColor(value) {
      const severity = String(value || "").toLowerCase();
      if (severity === "critical" || severity === "high") return "error";
      if (severity === "medium") return "warning";
      return "info";
    },
    severityIcon(value) {
      return ["critical", "high"].includes(String(value || "").toLowerCase())
        ? "mdi-alert-octagon"
        : "mdi-shield-alert-outline";
    },
    alertTitle(alert) {
      return alert.kind === "ai" ? "Posible anomalía detectada por IA" : (alert.monitor || alert.monitor_id || "Detección");
    },
    alertLink(alert) {
      if (alert.kind === "ai") return { path: "/ai" };
      return { path: "/monitors", query: { monitor: alert.monitor_id, packet: alert.packet_id } };
    },
    loadMessages() {
      this.loadingChat = true;
      return this.store.listChatMessages(60)
        .then((rows) => {
          this.messages = Array.isArray(rows) ? [...rows].reverse() : [];
          this.$nextTick(() => {
            if (this.$refs.log) this.$refs.log.scrollTop = this.$refs.log.scrollHeight;
          });
        })
        .catch((error) => { this.consoleError = error.message || "No se pudo cargar la consola."; })
        .finally(() => { this.loadingChat = false; });
    },
    loadAlerts() {
      if (this.loadingAlerts) return Promise.resolve();
      this.loadingAlerts = true;
      return Promise.allSettled([
        this.store.fetchListPromise("/api/alerts/recent", { limit: 8 }),
        this.store.fetchJsonPromise("/api/ai/packets/?threshold=50", {}, { preferHttp: true }),
      ])
        .then(([alertsResult, aiResult]) => {
          if (alertsResult.status === "fulfilled") this.alerts = alertsResult.value.rows || [];
          if (aiResult.status === "fulfilled") {
            this.aiCandidates = (aiResult.value.rows || []).filter((packet) => packet.candidate && !packet.reviewed).slice(0, 5);
          }
        })
        .finally(() => { this.loadingAlerts = false; });
    },
    runQuickCommand(command) {
      this.draft = command;
      this.send();
    },
    send() {
      const content = this.draft.trim();
      if (!content || this.sending) return;
      this.sending = true;
      this.consoleError = "";
      const request = content.startsWith("/")
        ? this.store.executeConsoleCommand(content)
        : this.store.postChatMessage(content);
      request
        .then((result) => {
          this.draft = "";
          if (result && result.ok === false) this.consoleError = result.output;
          return Promise.all([this.loadMessages(), this.loadAlerts()]);
        })
        .catch((error) => { this.consoleError = error.message || "No se pudo enviar la operación."; })
        .finally(() => { this.sending = false; });
    },
  },
};
</script>

<style scoped>
.operations-center { margin-top: 18px; }
.operations-card { border-radius: 18px; overflow: hidden; }
.operations-header { display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; padding: 18px 18px 12px; }
.quick-commands { display: flex; flex-wrap: wrap; gap: 8px; }
.operations-log { height: 330px; overflow-y: auto; padding: 12px 16px; background: rgba(2, 8, 14, 0.72); border-block: 1px solid rgba(var(--brand-sky-rgb), 0.12); }
.operations-empty, .alerts-empty { min-height: 180px; display: grid; place-content: center; gap: 10px; text-align: center; color: var(--text-dim); }
.operations-message { max-width: 86%; margin: 0 0 10px; padding: 9px 11px; border-radius: 12px; background: rgba(var(--brand-sky-rgb), 0.08); border: 1px solid rgba(var(--brand-sky-rgb), 0.14); }
.operations-message.is-self { margin-left: auto; background: rgba(var(--brand-cyan-rgb), 0.11); }
.operations-message.kind-command, .operations-message.kind-command_result { font-family: var(--font-mono); }
.operations-message.kind-command_result { max-width: 96%; background: rgba(var(--brand-violet-rgb), 0.1); }
.operations-message__meta { display: flex; justify-content: space-between; gap: 12px; margin-bottom: 4px; color: var(--text-dim); font-size: 0.68rem; text-transform: uppercase; }
.operations-message__content { margin: 0; color: var(--text-soft); font-size: 0.82rem; line-height: 1.5; white-space: pre-wrap; word-break: break-word; font: inherit; }
.operations-compose { display: flex; gap: 10px; align-items: center; padding: 14px 16px 16px; }
.alerts-list { height: 352px; overflow-y: auto; padding: 0 12px; }
.alert-row { display: flex; gap: 11px; align-items: flex-start; padding: 11px 8px; color: inherit; text-decoration: none; border-bottom: 1px solid rgba(255,255,255,.06); }
.alert-row:hover { background: rgba(var(--brand-sky-rgb), .06); }
.alert-row__body { flex: 1; min-width: 0; }
.alert-row__flow { margin-top: 3px; color: var(--text-soft); font: .75rem var(--font-mono); }
.alerts-footer { display: flex; justify-content: flex-end; gap: 6px; padding: 10px 12px; border-top: 1px solid rgba(var(--brand-sky-rgb), .12); }
@media (max-width: 600px) { .operations-header, .operations-compose { align-items: stretch; flex-direction: column; } .operations-log { height: 300px; } }
</style>
