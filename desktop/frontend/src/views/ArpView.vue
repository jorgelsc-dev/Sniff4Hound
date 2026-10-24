<template>
  <div>
    <ViewHeader
      overline="Protocolos"
      title="ARP"
      description="Dispositivos de la red local, asociaciones entre IP y MAC y cambios de dirección. Se guarda todo el tráfico observado por el sniffer, haya o no una alerta."
      :refresh-loading="loading"
      @refresh="load"
    >
      <template #actions-prepend>
        <v-btn to="/protocols/arp" variant="text" prepend-icon="mdi-ethernet">Ver paquetes</v-btn>
        <v-switch
          v-model="autoRefresh"
          label="En vivo"
          density="compact"
          color="primary"
          hide-details
          inset
          class="live-switch"
        />
      </template>
    </ViewHeader>

    <v-alert v-if="disabledNotice" type="warning" variant="tonal" class="mb-4" icon="mdi-history">
      {{ disabledNotice }}
      <router-link class="settings-link" :to="{ path: '/settings', query: { section: 'history' } }">Abrir configuración</router-link>
    </v-alert>

    <v-alert v-if="error" type="error" variant="tonal" class="mb-4">
      {{ error }}
    </v-alert>

    <v-row dense class="mb-2">
      <v-col v-for="card in summaryCards" :key="card.key" cols="6" md="3">
        <v-card variant="tonal" :color="card.color" class="summary-card">
          <div class="text-caption text-medium-emphasis">{{ card.label }}</div>
          <div class="text-h5 font-weight-bold">{{ card.value }}</div>
        </v-card>
      </v-col>
    </v-row>

    <v-tabs v-model="tab" color="primary" density="comfortable" class="mb-4">
      <v-tab value="bindings" prepend-icon="mdi-swap-horizontal">Asociaciones IP ↔ MAC</v-tab>
      <v-tab value="devices" prepend-icon="mdi-lan-connect">Dispositivos</v-tab>
      <v-tab value="events" prepend-icon="mdi-history">Cambios</v-tab>
    </v-tabs>

    <div class="toolbar">
      <v-text-field
        v-model="search"
        label="Buscar"
        :placeholder="tab === 'events' ? 'IP, MAC, fabricante, detalle...' : 'IP, MAC, fabricante, interfaz...'"
        density="compact"
        variant="outlined"
        hide-details
        clearable
        prepend-inner-icon="mdi-magnify"
        class="filter-field filter-field--search"
      />
      <v-select
        v-if="tab === 'events'"
        v-model="kind"
        :items="kindOptions"
        label="Tipo de cambio"
        density="compact"
        variant="outlined"
        hide-details
        class="filter-field"
      />
      <v-select v-model="since" :items="sinceOptions" label="Visto en" density="compact" variant="outlined" hide-details class="filter-field" />
    </div>

    <EntityTablePanel
      v-if="tab === 'bindings'"
      title="Asociaciones IP ↔ MAC"
      subtitle="Cada par que se anunció por ARP. Una IP con más de una MAC es una asociación que cambió."
      :rows="bindings.rows"
      :columns="bindingColumns"
      :loading="loading"
      :error="error"
      :last-updated="lastUpdated"
      :total-available="bindings.meta.totalAvailable"
      :returned-count="bindings.meta.returned"
      :truncated="bindings.meta.truncated"
      :page-size="25"
      empty-text="Todavía no se ha visto ninguna asociación ARP"
      @load-more="loadMore"
    >
      <template #cell-ip="{ value }">
        <router-link class="mono ip-link" :to="{ path: '/investigate', query: { ip: value } }">{{ value }}</router-link>
      </template>
      <template #cell-mac="{ value }"><span class="mono">{{ value }}</span></template>
      <template #cell-mac_vendor="{ item }">
        <span>{{ vendorLabel(item) }}</span>
        <v-tooltip activator="parent" location="top">{{ vendorHint(item) }}</v-tooltip>
      </template>
      <template #cell-mismatch_count="{ value }">
        <v-chip v-if="Number(value) > 0" size="x-small" variant="tonal" color="warning">{{ value }}</v-chip>
        <span v-else class="text-medium-emphasis">0</span>
      </template>
      <template #cell-first_seen="{ value }">{{ formatTimestamp(value) }}</template>
      <template #cell-last_seen="{ value }">{{ formatTimestamp(value) }}</template>
    </EntityTablePanel>

    <EntityTablePanel
      v-else-if="tab === 'devices'"
      title="Dispositivos detectados"
      subtitle="Una fila por dirección MAC, con todas las IP que reclamó."
      :rows="devices.rows"
      :columns="deviceColumns"
      :loading="loading"
      :error="error"
      :last-updated="lastUpdated"
      :total-available="devices.meta.totalAvailable"
      :returned-count="devices.meta.returned"
      :truncated="devices.meta.truncated"
      :page-size="25"
      row-key="mac"
      empty-text="Todavía no se ha detectado ningún dispositivo"
      @load-more="loadMore"
    >
      <template #cell-mac="{ value }"><span class="mono">{{ value }}</span></template>
      <template #cell-mac_vendor="{ item }">
        <span>{{ vendorLabel(item) }}</span>
        <v-tooltip activator="parent" location="top">{{ vendorHint(item) }}</v-tooltip>
      </template>
      <template #cell-current_ip="{ value }">
        <router-link v-if="value" class="mono ip-link" :to="{ path: '/investigate', query: { ip: value } }">{{ value }}</router-link>
        <span v-else>-</span>
      </template>
      <template #cell-ips="{ item }">
        <v-chip v-for="ip in (item.ips || []).slice(0, 4)" :key="`${item.mac}-${ip}`" size="x-small" variant="outlined" class="mono mr-1">{{ ip }}</v-chip>
        <span v-if="(item.ips || []).length > 4" class="text-caption text-medium-emphasis">+{{ item.ips.length - 4 }}</span>
      </template>
      <template #cell-mismatch_count="{ value }">
        <v-chip v-if="Number(value) > 0" size="x-small" variant="tonal" color="warning">{{ value }}</v-chip>
        <span v-else class="text-medium-emphasis">0</span>
      </template>
      <template #cell-first_seen="{ value }">{{ formatTimestamp(value) }}</template>
      <template #cell-last_seen="{ value }">{{ formatTimestamp(value) }}</template>
    </EntityTablePanel>

    <EntityTablePanel
      v-else
      title="Cambios registrados"
      subtitle="Dispositivos nuevos, direcciones que cambiaron de MAC y discrepancias entre Ethernet y ARP, del más reciente al más antiguo."
      :rows="events.rows"
      :columns="eventColumns"
      :loading="loading"
      :error="error"
      :last-updated="lastUpdated"
      :total-available="events.meta.totalAvailable"
      :returned-count="events.meta.returned"
      :truncated="events.meta.truncated"
      :page-size="25"
      empty-text="No se ha registrado ningún cambio"
      @load-more="loadMore"
    >
      <template #cell-kind="{ value }">
        <v-chip size="x-small" variant="tonal" :color="eventColor(value)">
          {{ eventLabel(value) }}
          <v-tooltip activator="parent" location="top" max-width="320">{{ eventHelp(value) }}</v-tooltip>
        </v-chip>
      </template>
      <template #cell-ip="{ value }">
        <router-link v-if="value" class="mono ip-link" :to="{ path: '/investigate', query: { ip: value } }">{{ value }}</router-link>
        <span v-else>-</span>
      </template>
      <template #cell-mac="{ value }"><span class="mono">{{ value }}</span></template>
      <template #cell-mac_vendor="{ item }">
        <span>{{ vendorLabel(item) }}</span>
        <v-tooltip activator="parent" location="top">{{ vendorHint(item) }}</v-tooltip>
      </template>
      <template #cell-summary="{ item }">{{ eventSummary(item) }}</template>
      <template #cell-occurred_at="{ value }">{{ formatTimestamp(value) }}</template>
    </EntityTablePanel>
  </div>
</template>

<script>
import store from "../state/appStore";
import ViewHeader from "../components/ui/ViewHeader.vue";
import EntityTablePanel from "../components/ui/EntityTablePanel.vue";
import { formatTimestamp } from "../utils/traffic";
import { ARP_EVENT_KINDS, arpEventColor, arpEventHelp, arpEventLabel, arpEventSummary, macVendorHint, macVendorLabel } from "../utils/history";

const PAGE_SIZE = 500;
const LIVE_REFRESH_MS = 5000;
const SEARCH_DEBOUNCE_MS = 300;

const emptyList = () => ({ rows: [], meta: { totalAvailable: null, returned: null, truncated: null } });

export default {
  name: "ArpView",
  components: { ViewHeader, EntityTablePanel },
  data() {
    return {
      store,
      tab: "bindings",
      loading: false,
      error: "",
      lastUpdated: "",
      bindings: emptyList(),
      devices: emptyList(),
      events: emptyList(),
      totals: null,
      historyConfig: null,
      limit: PAGE_SIZE,
      search: "",
      kind: "",
      since: "",
      autoRefresh: true,
      timer: null,
      searchTimer: null,
      requestId: 0,
      kindOptions: [{ title: "Todos", value: "" }, ...ARP_EVENT_KINDS.map((value) => ({ title: arpEventLabel(value), value }))],
      sinceOptions: [
        { title: "Siempre", value: "" },
        { title: "Últimos 15 min", value: "15m" },
        { title: "Última hora", value: "1h" },
        { title: "Últimas 6 h", value: "6h" },
        { title: "Últimas 24 h", value: "24h" },
        { title: "Últimos 7 días", value: "7d" },
      ],
      bindingColumns: [
        { key: "ip", label: "IP" },
        { key: "mac", label: "MAC" },
        { key: "mac_vendor", label: "Fabricante", copy: false },
        { key: "interface", label: "Interfaz" },
        { key: "packet_count", label: "Paquetes" },
        { key: "request_count", label: "Solicitudes" },
        { key: "reply_count", label: "Respuestas" },
        { key: "gratuitous_count", label: "Gratuitos" },
        { key: "mismatch_count", label: "Discrepancias" },
        { key: "first_seen", label: "Primera vez" },
        { key: "last_seen", label: "Última vez" },
      ],
      deviceColumns: [
        { key: "mac", label: "MAC" },
        { key: "mac_vendor", label: "Fabricante", copy: false },
        { key: "current_ip", label: "IP actual" },
        { key: "ips", label: "IPs reclamadas", copy: false },
        { key: "ip_count", label: "Nº de IPs" },
        { key: "interface", label: "Interfaz" },
        { key: "packet_count", label: "Paquetes" },
        { key: "mismatch_count", label: "Discrepancias" },
        { key: "first_seen", label: "Primera vez" },
        { key: "last_seen", label: "Última vez" },
      ],
      eventColumns: [
        { key: "occurred_at", label: "Cuándo" },
        { key: "kind", label: "Cambio" },
        { key: "ip", label: "IP" },
        { key: "mac", label: "MAC" },
        { key: "mac_vendor", label: "Fabricante", copy: false },
        { key: "summary", label: "Qué cambió", copy: false },
        { key: "interface", label: "Interfaz" },
      ],
    };
  },
  computed: {
    disabledNotice() {
      if (this.historyConfig && this.historyConfig.arp_enabled === false) {
        return "El historial ARP está desactivado: no se está registrando tráfico nuevo.";
      }
      return "";
    },
    summaryCards() {
      const totals = this.totals || {};
      const count = (value) => (value === undefined || value === null ? "-" : Number(value).toLocaleString("es-ES"));
      return [
        { key: "devices", label: "Dispositivos", value: count(totals.arp_devices), color: "info" },
        { key: "bindings", label: "Asociaciones IP ↔ MAC", value: count(totals.arp_bindings), color: "primary" },
        { key: "events", label: "Cambios registrados", value: count(totals.arp_events), color: "secondary" },
        { key: "mismatch", label: "Discrepancias (en esta lista)", value: this.mismatchTotal, color: "warning" },
      ];
    },
    mismatchTotal() {
      return this.bindings.rows.reduce((sum, row) => sum + (Number(row.mismatch_count) || 0), 0).toLocaleString("es-ES");
    },
  },
  watch: {
    tab() {
      this.reload();
    },
    search() {
      clearTimeout(this.searchTimer);
      this.searchTimer = setTimeout(() => this.reload(), SEARCH_DEBOUNCE_MS);
    },
    kind() {
      this.reload();
    },
    since() {
      this.reload();
    },
    autoRefresh() {
      this.schedule();
    },
  },
  mounted() {
    this.load();
    this.schedule();
  },
  beforeUnmount() {
    clearInterval(this.timer);
    clearTimeout(this.searchTimer);
  },
  methods: {
    formatTimestamp,
    vendorLabel: macVendorLabel,
    vendorHint: macVendorHint,
    eventLabel: arpEventLabel,
    eventColor: arpEventColor,
    eventHelp: arpEventHelp,
    eventSummary: arpEventSummary,
    schedule() {
      clearInterval(this.timer);
      this.timer = this.autoRefresh ? setInterval(() => this.load({ silent: true }), LIVE_REFRESH_MS) : null;
    },
    reload() {
      this.limit = PAGE_SIZE;
      return this.load();
    },
    loadMore() {
      this.limit += PAGE_SIZE;
      return this.load();
    },
    fetchTab() {
      const common = { search: this.search || "", since: this.since, limit: this.limit };
      if (this.tab === "devices") return this.store.listArpDevices(common).then((result) => ({ key: "devices", result }));
      if (this.tab === "events") return this.store.listArpEvents({ ...common, kind: this.kind }).then((result) => ({ key: "events", result }));
      return this.store.listArpHistory(common).then((result) => ({ key: "bindings", result }));
    },
    load(options = {}) {
      if (!options.silent) this.loading = true;
      // Only the latest request may write its answer.
      const requestId = ++this.requestId;
      const refreshSummary = this.store
        .getHistoryConfig()
        .then((payload) => {
          this.totals = (payload && payload.totals) || null;
          this.historyConfig = (payload && payload.config) || null;
        })
        .catch(() => null);
      return Promise.all([this.fetchTab(), refreshSummary])
        .then(([{ key, result }]) => {
          if (requestId !== this.requestId) return;
          this[key] = { rows: result.rows, meta: result.meta };
          this.error = "";
          this.lastUpdated = new Date().toLocaleTimeString("es-ES");
        })
        .catch((err) => {
          if (requestId !== this.requestId) return;
          this.error = (err && err.message) || "No se pudo cargar el historial ARP";
        })
        .finally(() => {
          if (requestId === this.requestId) this.loading = false;
        });
    },
  },
};
</script>

<style scoped>
.mono {
  font-family: var(--font-mono);
}

.ip-link {
  color: rgba(108, 186, 228, 0.98);
  text-decoration: none;
}

.ip-link:hover {
  text-decoration: underline;
}

.settings-link {
  margin-left: 8px;
  color: inherit;
  font-weight: 600;
}

.live-switch {
  flex: 0 0 auto;
}

.summary-card {
  padding: 12px 16px;
}

.toolbar {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  margin-bottom: 16px;
}

.filter-field {
  min-width: 160px;
  max-width: 220px;
}

.filter-field--search {
  min-width: 240px;
  max-width: 340px;
}
</style>
