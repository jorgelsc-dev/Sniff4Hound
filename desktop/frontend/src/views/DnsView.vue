<template>
  <div>
    <ViewHeader
      overline="Protocolos"
      title="DNS"
      description="Consultas y respuestas DNS, mDNS y LLMNR: dominios, registros, direcciones y clientes. Se guarda todo el tráfico observado por el sniffer, haya o no una alerta."
      :refresh-loading="loading"
      @refresh="load"
    >
      <template #actions-prepend>
        <v-btn to="/protocols/dns" variant="text" prepend-icon="mdi-ethernet">Ver paquetes</v-btn>
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

    <v-row dense>
      <v-col v-for="chart in chartPanels" :key="chart.key" cols="12" lg="4">
        <ChartCard :title="chart.title" :subtitle="chart.subtitle" :series="chart.series" :fill="chart.fill" :color="chart.color" />
      </v-col>
    </v-row>

    <EntityTablePanel
      title="Registros DNS"
      :subtitle="recordsSubtitle"
      class="mt-6"
      :rows="rows"
      :columns="columns"
      :loading="loading"
      :error="error"
      :last-updated="lastUpdated"
      :total-available="meta.totalAvailable"
      :returned-count="meta.returned"
      :truncated="meta.truncated"
      :group-by="tableGroupBy"
      :page-size="25"
      row-key="id"
      expandable-rows
      empty-text="Todavía no se ha visto ninguna consulta DNS"
      @load-more="loadMore"
    >
      <template #header-actions>
        <v-text-field
          v-model="search"
          label="Buscar"
          placeholder="Dominio, IP, cliente, tipo..."
          density="compact"
          variant="outlined"
          hide-details
          clearable
          prepend-inner-icon="mdi-magnify"
          class="filter-field filter-field--search"
        />
        <v-combobox
          v-model="domainScope"
          :items="baseDomainOptions"
          label="Dominio base"
          placeholder="example.com"
          density="compact"
          variant="outlined"
          hide-details
          clearable
          class="filter-field filter-field--domain"
        />
        <v-select v-model="groupMode" :items="groupOptions" label="Organización" density="compact" variant="outlined" hide-details class="filter-field" />
        <v-select v-model="recordType" :items="typeOptions" label="Tipo" density="compact" variant="outlined" hide-details class="filter-field" />
        <v-select v-model="rcode" :items="rcodeOptions" label="Respuesta" density="compact" variant="outlined" hide-details class="filter-field" />
        <v-select v-model="since" :items="sinceOptions" label="Visto en" density="compact" variant="outlined" hide-details class="filter-field" />
      </template>
      <template #cell-domain="{ value }">
        <span class="mono">{{ value }}</span>
        <ListActionIcons inline :value="value" category="domain" />
      </template>
      <template #cell-base_domain="{ value }">
        <v-chip size="x-small" variant="tonal" color="info" class="base-domain-chip" @click.stop="filterBaseDomain(value)">
          {{ value }}
          <v-tooltip activator="parent" location="bottom">Mostrar este dominio y todos sus subdominios</v-tooltip>
        </v-chip>
      </template>
      <template #cell-record_type="{ value }">
        <v-chip size="x-small" variant="tonal" :color="typeColor(value)">{{ value }}</v-chip>
      </template>
      <template #cell-answer="{ value }">
        <template v-if="value">
          <router-link v-if="isIp(value)" class="mono ip-link" :to="{ path: '/investigate', query: { ip: value } }">{{ value }}</router-link>
          <span v-else class="mono">{{ value }}</span>
        </template>
        <span v-else class="text-medium-emphasis">sin respuesta</span>
      </template>
      <template #cell-last_rcode="{ value }">
        <v-chip v-if="value" size="x-small" variant="tonal" :color="rcodeColor(value)">{{ value }}</v-chip>
        <span v-else class="text-medium-emphasis">-</span>
      </template>
      <template #cell-ttl="{ item }">{{ ttlLabel(item) }}</template>
      <template #cell-last_client="{ value }">
        <router-link v-if="value" class="mono ip-link" :to="{ path: '/investigate', query: { ip: value } }">{{ value }}</router-link>
        <span v-else>-</span>
      </template>
      <template #cell-source="{ value }">
        <v-chip size="x-small" variant="tonal" :color="sourceColor(value)">{{ sourceLabel(value) }}</v-chip>
      </template>
      <template #cell-first_seen="{ value }">{{ formatTimestamp(value) }}</template>
      <template #cell-last_seen="{ value }">{{ formatTimestamp(value) }}</template>
      <template #row-expanded="{ item }">
        <div class="expanded">
          <div class="expanded__block">
            <div class="text-caption text-medium-emphasis">Clientes que lo pidieron ({{ (item.clients || []).length }})</div>
            <div class="expanded__chips">
              <v-chip v-for="peer in item.clients || []" :key="`c-${peer}`" size="x-small" variant="outlined" class="mono">{{ peer }}</v-chip>
              <span v-if="!(item.clients || []).length" class="text-medium-emphasis">-</span>
            </div>
          </div>
          <div class="expanded__block">
            <div class="text-caption text-medium-emphasis">Resolvers ({{ (item.resolvers || []).length }})</div>
            <div class="expanded__chips">
              <v-chip v-for="peer in item.resolvers || []" :key="`r-${peer}`" size="x-small" variant="outlined" class="mono">{{ peer }}</v-chip>
              <span v-if="!(item.resolvers || []).length" class="text-medium-emphasis">-</span>
            </div>
          </div>
          <div class="expanded__block">
            <div class="text-caption text-medium-emphasis">Jerarquía</div>
            <div class="mono">Base: {{ item.base_domain || item.domain }}</div>
            <div class="mono text-medium-emphasis">Subdominio: {{ item.subdomain || "-" }}</div>
          </div>
          <div class="expanded__block">
            <div class="text-caption text-medium-emphasis">Transporte</div>
            <div>{{ String(item.transport || "udp").toUpperCase() }}</div>
          </div>
        </div>
      </template>
    </EntityTablePanel>
  </div>
</template>

<script>
import store from "../state/appStore";
import ViewHeader from "../components/ui/ViewHeader.vue";
import EntityTablePanel from "../components/ui/EntityTablePanel.vue";
import ChartCard from "../components/ui/ChartCard.vue";
import ListActionIcons from "../components/ui/ListActionIcons.vue";
import { formatTimestamp, groupSumSeries } from "../utils/traffic";
import { dnsRcodeColor, dnsSourceLabel, dnsTypeColor, formatTtlRange, isIpAddress } from "../utils/history";

const PAGE_SIZE = 500;
const LIVE_REFRESH_MS = 5000;
const SEARCH_DEBOUNCE_MS = 300;

export default {
  name: "DnsView",
  components: { ViewHeader, EntityTablePanel, ChartCard, ListActionIcons },
  data() {
    return {
      store,
      loading: false,
      error: "",
      lastUpdated: "",
      rows: [],
      meta: { totalAvailable: null, returned: null, truncated: null },
      limit: PAGE_SIZE,
      search: "",
      domainScope: "",
      groupMode: "base",
      recordType: "",
      rcode: "",
      since: "",
      autoRefresh: true,
      historyConfig: null,
      timer: null,
      searchTimer: null,
      requestId: 0,
      groupOptions: [
        { title: "Por dominio base", value: "base" },
        { title: "Sin agrupar", value: "records" },
      ],
      typeOptions: [
        { title: "Todos", value: "" },
        ...["A", "AAAA", "CNAME", "MX", "TXT", "NS", "PTR", "SRV", "HTTPS", "SOA", "ANY"].map((value) => ({ title: value, value })),
      ],
      rcodeOptions: [
        { title: "Todas", value: "" },
        ...["NOERROR", "NXDOMAIN", "SERVFAIL", "REFUSED", "FORMERR", "NOTIMP"].map((value) => ({ title: value, value })),
      ],
      sinceOptions: [
        { title: "Siempre", value: "" },
        { title: "Últimos 15 min", value: "15m" },
        { title: "Última hora", value: "1h" },
        { title: "Últimas 6 h", value: "6h" },
        { title: "Últimas 24 h", value: "24h" },
        { title: "Últimos 7 días", value: "7d" },
      ],
      columns: [
        { key: "domain", label: "Dominio" },
        { key: "base_domain", label: "Dominio base" },
        { key: "record_type", label: "Tipo" },
        { key: "answer", label: "Respuesta" },
        { key: "query_count", label: "Consultas" },
        { key: "response_count", label: "Respuestas" },
        { key: "error_count", label: "Errores" },
        { key: "last_rcode", label: "Código" },
        { key: "ttl", label: "TTL", copy: false },
        { key: "last_client", label: "Cliente" },
        { key: "last_resolver", label: "Resolver" },
        { key: "source", label: "Fuente" },
        { key: "first_seen", label: "Primera vez" },
        { key: "last_seen", label: "Última vez" },
      ],
    };
  },
  computed: {
    baseDomainOptions() {
      const values = this.rows.map((row) => String(row.base_domain || row.domain || "").trim()).filter(Boolean);
      if (this.domainScope) values.push(String(this.domainScope));
      return [...new Set(values)].sort((left, right) => left.localeCompare(right));
    },
    tableGroupBy() {
      return this.groupMode === "base" ? [{ key: "base_domain", order: "asc" }] : [];
    },
    recordsSubtitle() {
      const prefix = this.domainScope
        ? `Mostrando ${this.domainScope} y todos sus subdominios.`
        : "Agrupado por el dominio registrable según la Public Suffix List.";
      return `${prefix} Una fila por dominio, tipo de registro y respuesta.`;
    },
    disabledNotice() {
      if (this.historyConfig && this.historyConfig.dns_enabled === false) {
        return "El historial DNS está desactivado: no se está registrando tráfico nuevo.";
      }
      return "";
    },
    chartPanels() {
      const total = (row) => (Number(row.query_count) || 0) + (Number(row.response_count) || 0);
      return [
        {
          key: "domains",
          title: "Dominios base más consultados",
          subtitle: "Suma la actividad de todos sus subdominios.",
          color: "info",
          fill: "linear-gradient(90deg, rgba(52, 230, 255, 0.94), rgba(74, 136, 255, 0.85))",
          series: groupSumSeries(this.rows, (row) => row.base_domain || row.domain, total, 8),
        },
        {
          key: "types",
          title: "Tipos de registro",
          subtitle: "Actividad agrupada por tipo.",
          color: "warning",
          fill: "linear-gradient(90deg, rgba(255, 159, 67, 0.92), rgba(243, 177, 75, 0.78))",
          series: groupSumSeries(this.rows, (row) => row.record_type, total),
        },
        {
          key: "errors",
          title: "Dominios base con errores",
          subtitle: "Agrupa NXDOMAIN, SERVFAIL y otros fallos de todos sus subdominios.",
          color: "error",
          fill: "linear-gradient(90deg, rgba(255, 107, 129, 0.94), rgba(222, 71, 99, 0.82))",
          series: groupSumSeries(
            this.rows.filter((row) => Number(row.error_count) > 0),
            (row) => row.base_domain || row.domain,
            (row) => row.error_count,
            8,
          ),
        },
      ];
    },
  },
  watch: {
    search() {
      clearTimeout(this.searchTimer);
      this.searchTimer = setTimeout(() => this.reload(), SEARCH_DEBOUNCE_MS);
    },
    domainScope() {
      this.reload();
    },
    recordType() {
      this.reload();
    },
    rcode() {
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
    this.loadConfig();
    this.schedule();
  },
  beforeUnmount() {
    clearInterval(this.timer);
    clearTimeout(this.searchTimer);
  },
  methods: {
    formatTimestamp,
    isIp: isIpAddress,
    typeColor: dnsTypeColor,
    rcodeColor: dnsRcodeColor,
    sourceLabel: dnsSourceLabel,
    sourceColor(value) {
      return value === "mdns" || value === "llmnr" ? "secondary" : "info";
    },
    ttlLabel(item) {
      return formatTtlRange(item.ttl_min, item.ttl_max);
    },
    filterBaseDomain(value) {
      this.domainScope = String(value || "").trim();
    },
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
    loadConfig() {
      return this.store
        .getHistoryConfig()
        .then((payload) => {
          this.historyConfig = (payload && payload.config) || null;
        })
        .catch(() => {
          this.historyConfig = null;
        });
    },
    load(options = {}) {
      if (!options.silent) this.loading = true;
      // Only the latest request may write its answer: a slow earlier search
      // must not overwrite what the person has typed since.
      const requestId = ++this.requestId;
      return this.store
        .listDnsHistory({
          search: this.search || "",
          parent: this.domainScope || "",
          type: this.recordType,
          rcode: this.rcode,
          since: this.since,
          limit: this.limit,
        })
        .then(({ rows, meta }) => {
          if (requestId !== this.requestId) return;
          this.rows = rows;
          this.meta = meta;
          this.error = "";
          this.lastUpdated = new Date().toLocaleTimeString("es-ES");
        })
        .catch((err) => {
          if (requestId !== this.requestId) return;
          this.error = (err && err.message) || "No se pudo cargar el historial DNS";
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

.filter-field {
  min-width: 140px;
  max-width: 200px;
}

.filter-field--search {
  min-width: 220px;
  max-width: 320px;
}

.filter-field--domain {
  min-width: 200px;
  max-width: 280px;
}

.base-domain-chip {
  cursor: pointer;
}

.expanded {
  display: flex;
  flex-wrap: wrap;
  gap: 24px;
  padding: 8px 4px;
}

.expanded__block {
  min-width: 180px;
}

.expanded__chips {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
  margin-top: 4px;
}
</style>
