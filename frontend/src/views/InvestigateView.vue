<template>
  <div>
    <ViewHeader
      overline="Investigation"
      :title="
        mode === 'monitor'
          ? 'Monitor Investigator'
          : targetKind === 'domain'
            ? 'Domain Investigator'
            : 'Host Investigator'
      "
      :description="
        mode === 'monitor'
          ? 'A static snapshot of everything this monitor has matched - packets, charts, and the source/target IPs, each one click away from its own investigation.'
          : targetKind === 'domain'
            ? 'Search a domain and pivot through packets, payloads, tags, and list controls.'
            : 'Search an IP and get a compact, evidence-first view of transport, payloads, tags, and flows.'
      "
      :refresh-loading="loading"
      @refresh="refresh"
    >
      <template #actions>
        <IocExportMenu :params="exportParams" />
        <v-btn
          icon="mdi-refresh"
          variant="outlined"
          color="primary"
          density="comfortable"
          :loading="loading"
          aria-label="Refresh"
          @click="refresh"
        >
          <v-icon icon="mdi-refresh" />
          <v-tooltip activator="parent" location="bottom">Refresh</v-tooltip>
        </v-btn>
      </template>
    </ViewHeader>

    <div v-if="mode === 'monitor'">
      <div class="d-flex align-center flex-wrap ga-2 mb-4">
        <v-btn size="small" variant="text" icon :to="{ path: '/investigate' }"
          aria-label="Back to host search"
        >
          <v-icon icon="mdi-arrow-left" />
          <v-tooltip activator="parent" location="bottom">Back to host search</v-tooltip>
        </v-btn>
        <v-chip size="small" variant="tonal" :color="severityColor(activeMonitor.action && activeMonitor.action.severity)">
          {{ (activeMonitor.action && activeMonitor.action.severity) || "info" }}
        </v-chip>
      </div>
      <MonitorMatchesPanel ref="matchesPanel" :monitor="activeMonitor" :live-refresh="false" />
      <v-alert type="info" variant="tonal" density="comfortable" class="mt-4">
        This snapshot doesn't refresh automatically - use the refresh button in the page header, or the
        "Refresh" button at the top of the matches panel, to pull the latest matches.
      </v-alert>
    </div>

    <div v-else>
    <v-row dense class="mb-3">
      <v-col cols="12" md="2">
        <v-btn-toggle
          v-model="targetKind"
          mandatory
          density="comfortable"
          color="primary"
          variant="outlined"
          class="investigate-toggle"
        >
          <v-btn value="ip" size="small">IP</v-btn>
          <v-btn value="domain" size="small">Domain</v-btn>
        </v-btn-toggle>
      </v-col>
      <v-col cols="12" md="5">
        <v-text-field
          v-model.trim="targetInput"
          :label="targetKind === 'domain' ? 'Investigate domain' : 'Investigate IP'"
          name="investigate_target"
          :placeholder="targetKind === 'domain' ? 'example.com' : '127.0.0.1'"
          prepend-inner-icon="mdi-magnify"
          clearable
          variant="outlined"
          density="comfortable"
          @keyup.enter="load"
        />
      </v-col>
      <v-col cols="12" md="5" class="d-flex align-center flex-wrap ga-2">
        <v-btn color="primary" variant="flat" :disabled="loading || !targetValue" @click="load">
          Investigate
        </v-btn>
        <v-btn variant="outlined" :disabled="loading || targetKind !== 'ip'" @click="setTopSuggestion">
          Top host
        </v-btn>
        <v-btn
          variant="tonal"
          color="success"
          prepend-icon="mdi-shield-check-outline"
          :loading="listActionSubmitting === 'whitelist'"
          :disabled="loading || !targetValue"
          @click="addListEntry('whitelist')"
        >
          Whitelist
        </v-btn>
        <v-btn
          variant="tonal"
          color="error"
          prepend-icon="mdi-shield-alert-outline"
          :loading="listActionSubmitting === 'blacklist'"
          :disabled="loading || !targetValue"
          @click="addListEntry('blacklist')"
        >
          Blacklist
        </v-btn>
      </v-col>
    </v-row>

    <div class="d-flex flex-wrap ga-2 mb-4">
      <v-chip
        v-for="item in suggestedHosts"
        :key="item.ip"
        size="small"
        variant="tonal"
        color="info"
        class="suggestion-chip"
        @click="queryIp = item.ip; load()"
      >
        {{ item.ip }} · {{ item.value }} open
      </v-chip>
    </div>

    <v-alert v-if="error" type="error" variant="tonal" class="mb-6">
      {{ error }}
    </v-alert>
    <v-alert v-if="listActionMessage" type="success" variant="tonal" density="comfortable" class="mb-6">
      {{ listActionMessage }}
    </v-alert>

    <v-row dense>
      <v-col v-for="metric in metricCards" :key="metric.key" cols="12" sm="6" xl="3">
        <v-card variant="tonal" class="pa-5 metric-card">
          <div class="d-flex align-center justify-space-between ga-3">
            <div>
              <div class="text-caption text-medium-emphasis">{{ metric.label }}</div>
              <div class="text-h5 font-weight-bold" :class="metric.colorClass">{{ metric.value }}</div>
            </div>
            <v-icon :icon="metric.icon" class="metric-icon" :class="metric.colorClass" />
          </div>
          <div class="text-caption text-medium-emphasis mt-3">{{ metric.caption }}</div>
        </v-card>
      </v-col>
    </v-row>

    <v-row class="mt-4" dense>
      <v-col cols="12" xl="6">
        <DataPanel
          title="Host Profile"
          subtitle="Scope, caching, and host profile context."
          :loading="loading"
          :error="''"
          :last-updated="lastUpdated"
          :show-refresh="false"
        >
          <div class="d-flex flex-wrap ga-2">
            <v-chip size="small" variant="tonal" color="primary">
              Scope: {{ hostScope }}
            </v-chip>
            <v-chip size="small" variant="tonal" color="info">
              Cached: {{ cachedLabel }}
            </v-chip>
            <v-chip size="small" variant="tonal" color="warning">
              Domains: {{ domainCount }}
            </v-chip>
            <v-chip size="small" variant="tonal" color="success">
              TTL hops: {{ ttlHopCount }}
            </v-chip>
          </div>
          <v-divider class="my-4" />
          <div class="text-subtitle-2 mb-2">Notes</div>
          <div class="text-body-2 text-medium-emphasis">
            {{ notesText }}
          </div>
        </DataPanel>
      </v-col>

      <v-col cols="12" xl="6">
        <DataPanel
          title="Application"
          subtitle="Quick application-layer fingerprint."
          :loading="loading"
          :error="''"
          :last-updated="lastUpdated"
          :show-refresh="false"
        >
          <div class="d-flex flex-wrap ga-2">
            <v-chip size="small" variant="tonal" color="info">
              HTTP: {{ appHttpLabel }}
            </v-chip>
            <v-chip size="small" variant="tonal" color="warning">
              TLS: {{ appTlsLabel }}
            </v-chip>
            <v-chip size="small" variant="tonal" color="secondary">
              Fingerprint: {{ appFingerprintLabel }}
            </v-chip>
          </div>
        </DataPanel>
      </v-col>
    </v-row>

    <v-row class="mt-4" dense>
      <v-col cols="12" xl="7">
        <EntityTablePanel
          title="Transport Services"
          subtitle="Services inferred from the host IP."
          :rows="transportServices"
          :columns="serviceColumns"
          :loading="loading"
          :error="error"
          :last-updated="lastUpdated"
          :live-refresh="false"
          :search-enabled="true"
          search-label="Search services"
          search-placeholder="IP, port, proto, state, banner, or tags"
          :filter-definitions="serviceFilters"
          empty-text="No services for this host"
          :page-size="12"
          @refresh="load"
        >
          <template #cell-port="{ value }">
            <v-chip size="x-small" color="info" variant="tonal">
              {{ value }}
            </v-chip>
          </template>
          <template #cell-banner="{ value }">
            <span class="summary-cell">{{ value || "-" }}</span>
          </template>
        </EntityTablePanel>
      </v-col>

      <v-col cols="12" xl="5">
        <EntityTablePanel
          title="Captured Responses"
          subtitle="Decoded payload text and protocol banners tied to this host."
          :rows="payloadRows"
          :columns="payloadColumns"
          :loading="loading"
          :error="error"
          :last-updated="lastUpdated"
          :live-refresh="false"
          :search-enabled="true"
          search-label="Search payloads"
          search-placeholder="IP, port, proto, or response"
          :filter-definitions="payloadFilters"
          empty-text="No payload evidence for this host"
          :page-size="12"
          @refresh="load"
        >
          <template #cell-response_plain="{ value }">
            <span class="summary-cell">{{ value || "-" }}</span>
          </template>
        </EntityTablePanel>
      </v-col>
    </v-row>

    <v-row class="mt-4" dense>
      <v-col cols="12" xl="7">
        <EntityTablePanel
          title="Flows"
          subtitle="Directed conversations tied to the selected host."
          :rows="flowRows"
          :columns="flowColumns"
          :loading="loading"
          :error="error"
          :last-updated="lastUpdated"
          :live-refresh="false"
          :search-enabled="true"
          search-label="Search flows"
          search-placeholder="Flow key, source, target, or banner"
          :filter-definitions="flowFilters"
          empty-text="No flows for this host"
          :page-size="12"
          @refresh="load"
        >
          <template #cell-banner_text="{ value }">
            <span class="summary-cell">{{ value || "-" }}</span>
          </template>
        </EntityTablePanel>
      </v-col>

      <v-col cols="12" xl="5">
        <EntityTablePanel
          title="Tags"
          subtitle="Rule hits and parsed tags."
          :rows="tagRows"
          :columns="tagColumns"
          :loading="loading"
          :error="error"
          :last-updated="lastUpdated"
          :live-refresh="false"
          :search-enabled="true"
          search-label="Search tags"
          search-placeholder="Key, value, proto, IP, or port"
          :filter-definitions="tagFilters"
          empty-text="No tags for this host"
          :page-size="12"
          @refresh="load"
        />
      </v-col>
    </v-row>
    </div>
  </div>
</template>

<script>
import store from "../state/appStore";
import ViewHeader from "../components/ui/ViewHeader.vue";
import IocExportMenu from "../components/ui/IocExportMenu.vue";
import DataPanel from "../components/ui/DataPanel.vue";
import EntityTablePanel from "../components/ui/EntityTablePanel.vue";
import MonitorMatchesPanel from "../components/monitors/MonitorMatchesPanel.vue";
import { uniqueSorted } from "../utils/traffic";

export default {
  name: "InvestigateView",
  components: {
    ViewHeader,
    IocExportMenu,
    DataPanel,
    EntityTablePanel,
    MonitorMatchesPanel,
  },
  data() {
    return {
      store,
      loading: false,
      error: "",
      lastUpdated: "",
      queryIp: "",
      queryDomain: "",
      targetKind: "ip",
      queryMonitor: "",
      monitors: [],
      analytics: {},
      intel: {},
      listActionSubmitting: "",
      listActionMessage: "",
      serviceColumns: [
        { key: "ip", label: "IP" },
        { key: "port", label: "Port" },
        { key: "proto", label: "Proto" },
        { key: "state", label: "State" },
        { key: "banner", label: "Banner" },
      ],
      payloadColumns: [
        { key: "ip", label: "IP" },
        { key: "port", label: "Port" },
        { key: "proto", label: "Proto" },
        { key: "response_size", label: "Size" },
        { key: "response_plain", label: "Response" },
      ],
      flowColumns: [
        { key: "flow_key", label: "Flow" },
        { key: "proto", label: "Proto" },
        { key: "src_ip", label: "Source" },
        { key: "dst_ip", label: "Target" },
        { key: "src_port", label: "S Port" },
        { key: "dst_port", label: "D Port" },
        { key: "state", label: "State" },
        { key: "packet_count", label: "Packets" },
        { key: "byte_count", label: "Bytes" },
        { key: "banner_text", label: "Banner" },
      ],
      tagColumns: [
        { key: "key", label: "Key" },
        { key: "value", label: "Value" },
        { key: "proto", label: "Proto" },
        { key: "ip", label: "IP" },
        { key: "port", label: "Port" },
      ],
    };
  },
  computed: {
    // Scopes the IOC export to whatever host is under investigation, so the
    // downloaded file matches what is on screen instead of the whole store.
    exportParams() {
      const target = this.targetValue;
      return target ? { search: target } : {};
    },
    targetInput: {
      get() {
        return this.targetKind === "domain" ? this.queryDomain : this.queryIp;
      },
      set(value) {
        if (this.targetKind === "domain") {
          this.queryDomain = String(value || "").trim();
        } else {
          this.queryIp = String(value || "").trim();
        }
      },
    },
    targetValue() {
      return String(this.targetInput || "").trim();
    },
    targetCategory() {
      return this.targetKind === "domain" ? "domain" : "ip";
    },
    targetLabel() {
      return this.targetKind === "domain" ? "domain" : "IP";
    },
    summary() {
      return this.intel.summary || {};
    },
    host() {
      return this.intel.host || {};
    },
    hostProfile() {
      return this.intel.host_profile || {};
    },
    transport() {
      return this.host.transport && typeof this.host.transport === "object" ? this.host.transport : {};
    },
    application() {
      return this.hostProfile.application && typeof this.hostProfile.application === "object"
        ? this.hostProfile.application
        : {};
    },
    transportServices() {
      return Array.isArray(this.transport.services) ? this.transport.services : [];
    },
    serviceFilters() {
      return [
        {
          key: "proto",
          label: "Proto",
          value: "proto",
          options: uniqueSorted(this.transportServices.map((row) => row.proto)),
        },
        {
          key: "state",
          label: "State",
          value: "state",
          options: uniqueSorted(this.transportServices.map((row) => row.state)),
        },
      ];
    },
    payloadRows() {
      return Array.isArray(this.transport.banners) ? this.transport.banners : [];
    },
    payloadFilters() {
      return [
        {
          key: "proto",
          label: "Proto",
          value: "proto",
          options: uniqueSorted(this.payloadRows.map((row) => row.proto)),
        },
      ];
    },
    flowRows() {
      return Array.isArray(this.transport.flows) ? this.transport.flows : [];
    },
    flowFilters() {
      return [
        {
          key: "proto",
          label: "Proto",
          value: "proto",
          options: uniqueSorted(this.flowRows.map((row) => row.proto)),
        },
        {
          key: "state",
          label: "State",
          value: "state",
          options: uniqueSorted(this.flowRows.map((row) => row.state)),
        },
      ];
    },
    tagRows() {
      return Array.isArray(this.transport.tags) ? this.transport.tags : [];
    },
    tagFilters() {
      return [
        {
          key: "proto",
          label: "Proto",
          value: "proto",
          options: uniqueSorted(this.tagRows.map((row) => row.proto)),
        },
      ];
    },
    metricCards() {
      return [
        {
          key: "packets",
          label: "Packets",
          value: Number(this.summary.packets || 0),
          caption: "Packets tied to this host",
          icon: "mdi-ethernet",
          colorClass: "text-success",
        },
        {
          key: "flows",
          label: "Flows",
          value: Number(this.summary.flows || 0),
          caption: "Correlated conversations",
          icon: "mdi-source-branch",
          colorClass: "text-info",
        },
        {
          key: "payloads",
          label: "Payloads",
          value: Number(this.summary.payloads || 0),
          caption: "Evidence rows and banners",
          icon: "mdi-message-text",
          colorClass: "text-warning",
        },
        {
          key: "tags",
          label: "Tags",
          value: Number(this.summary.tags || 0),
          caption: "Rule hits and parsed tags",
          icon: "mdi-tag-multiple",
          colorClass: "text-primary",
        },
      ];
    },
    hostScope() {
      return String((this.hostProfile.target && this.hostProfile.target.scope) || "unknown");
    },
    cachedLabel() {
      return this.intel.cached ? "yes" : "no";
    },
    domainCount() {
      const domains = this.intel.domains && Array.isArray(this.intel.domains.domains) ? this.intel.domains.domains : [];
      return domains.length;
    },
    ttlHopCount() {
      const hops = this.intel.ttl_path && Array.isArray(this.intel.ttl_path.hops) ? this.intel.ttl_path.hops : [];
      return hops.length;
    },
    notesText() {
      const notes = Array.isArray(this.hostProfile.notes) ? this.hostProfile.notes : [];
      if (!notes.length) return "No operator notes captured for this host.";
      return notes.join(" | ");
    },
    appHttpLabel() {
      const http = this.application.http || {};
      return http.banner ? "banner set" : "empty";
    },
    appTlsLabel() {
      const tls = this.application.tls || {};
      return Object.keys(tls.fingerprint || {}).length ? "fingerprint set" : "empty";
    },
    appFingerprintLabel() {
      const fingerprint = this.application.fingerprint || {};
      return Object.keys(fingerprint).length ? "present" : "empty";
    },
    suggestedHosts() {
      const rows = Array.isArray(this.analytics.top_ips_by_open_ports) ? this.analytics.top_ips_by_open_ports : [];
      return rows.slice(0, 8);
    },
    apiBase() {
      return this.store.state.apiBase;
    },
    mode() {
      return this.queryMonitor ? "monitor" : this.targetKind;
    },
    activeMonitor() {
      if (!this.queryMonitor) return {};
      const found = this.monitors.find((item) => item.id === this.queryMonitor);
      // Falls back to a synthesized {id, name} rather than waiting on the
      // full monitors list - MonitorMatchesPanel only strictly needs the
      // id to fetch matched packets, so this avoids a blank/loading flash
      // for the common case (monitors list not fetched yet on first paint).
      return found || { id: this.queryMonitor, name: this.queryMonitor, action: {} };
    },
  },
  watch: {
    apiBase() {
      this.load();
    },
    $route: {
      immediate: true,
      handler(route) {
        const query = (route && route.query) || {};
        const monitor = String(query.monitor || "").trim();
        const ip = String(query.ip || "").trim();
        const domain = String(query.domain || "").trim();
        // The two modes are mutually exclusive by URL shape (a monitor link
        // never carries ?ip= and vice versa) - clearing the one not present
        // in the current query is what lets clicking an IP inside monitor
        // mode (or a monitor link from anywhere) actually switch modes
        // instead of getting stuck showing whichever was set first.
        this.queryMonitor = monitor;
        if (monitor && !this.monitors.length) {
          this.loadMonitors();
        }
        if (ip && ip !== this.queryIp) {
          this.targetKind = "ip";
          this.queryIp = ip;
          this.load();
        } else if (domain && domain !== this.queryDomain) {
          this.targetKind = "domain";
          this.queryDomain = domain;
          this.load();
        } else if (!ip) {
          this.queryIp = "";
          if (!domain) this.queryDomain = "";
        }
      },
    },
  },
  mounted() {
    if (!this.queryIp && !this.queryMonitor) {
      this.loadSeed();
    }
  },
  methods: {
    refresh() {
      if (this.mode === "monitor") {
        if (this.$refs.matchesPanel && typeof this.$refs.matchesPanel.load === "function") {
          this.$refs.matchesPanel.load();
        }
        return Promise.resolve();
      }
      return this.load();
    },
    severityColor(value) {
      const severity = String(value || "info").trim().toLowerCase();
      if (severity === "critical" || severity === "high") return "error";
      if (severity === "medium") return "warning";
      if (severity === "low") return "info";
      return "secondary";
    },
    loadMonitors() {
      return this.store
        .listMonitors()
        .then((payload) => {
          this.monitors = this.store.extractArray(payload);
        })
        .catch(() => {
          // Best-effort enrichment only - activeMonitor already falls back
          // to a synthesized {id, name} when this list isn't available.
        });
    },
    loadSeed() {
      return this.store.fetchJsonPromise("/api/charts/analytics").then((payload) => {
        this.analytics = payload || {};
        const top = Array.isArray(this.analytics.top_ips_by_open_ports) ? this.analytics.top_ips_by_open_ports[0] : null;
        if (top && top.ip) {
          this.queryIp = top.ip;
          return this.load();
        }
        return this.load();
      });
    },
    setTopSuggestion() {
      const top = this.suggestedHosts[0];
      if (!top || !top.ip) return;
      this.targetKind = "ip";
      this.queryIp = top.ip;
      this.load();
    },
    load() {
      this.listActionMessage = "";
      if (this.targetKind === "domain") {
        return this.loadDomain();
      }
      const ip = String(this.queryIp || "").trim();
      if (!ip) {
        this.error = "Enter an IP to investigate.";
        this.intel = {};
        return Promise.resolve();
      }
      this.loading = true;
      this.error = "";
      return Promise.allSettled([
        this.store.fetchJsonPromise("/api/charts/analytics"),
        this.store.fetchJsonPromise(`/api/ip/intel/?ip=${encodeURIComponent(ip)}`),
      ])
        .then(([analyticsRes, intelRes]) => {
          if (analyticsRes.status === "fulfilled") {
            this.analytics = analyticsRes.value || {};
          }
          if (intelRes.status === "fulfilled") {
            this.intel = intelRes.value || {};
          } else {
            this.intel = {};
            this.error = (intelRes.reason && intelRes.reason.message) || `Failed to investigate ${ip}`;
          }
          this.lastUpdated = new Date().toLocaleTimeString();
        })
        .finally(() => {
          this.loading = false;
        });
    },
    loadDomain() {
      const domain = String(this.queryDomain || "").trim().toLowerCase();
      if (!domain) {
        this.error = "Enter a domain to investigate.";
        this.intel = {};
        return Promise.resolve();
      }
      this.loading = true;
      this.error = "";
      const search = encodeURIComponent(domain);
      return Promise.allSettled([
        this.store.fetchJsonPromise("/api/charts/analytics"),
        this.store.listDomains({ search: domain, limit: 250 }),
        this.store.fetchJsonPromise(`/ports/?search=${search}&limit=250`),
        this.store.fetchJsonPromise(`/banners/?search=${search}&limit=250`),
        this.store.fetchJsonPromise(`/tags/?search=${search}&limit=400`),
      ])
        .then(([analyticsRes, domainsRes, packetsRes, bannersRes, tagsRes]) => {
          if (analyticsRes.status === "fulfilled") {
            this.analytics = analyticsRes.value || {};
          }
          const domains = domainsRes.status === "fulfilled" ? this.store.extractArray(domainsRes.value) : [];
          const packets = packetsRes.status === "fulfilled" ? this.store.extractArray(packetsRes.value) : [];
          const banners = bannersRes.status === "fulfilled" ? this.store.extractArray(bannersRes.value) : [];
          const tags = tagsRes.status === "fulfilled" ? this.store.extractArray(tagsRes.value) : [];
          this.intel = {
            cached: false,
            summary: {
              packets: packets.length,
              flows: 0,
              payloads: banners.length,
              tags: tags.length,
            },
            host: {
              transport: {
                services: packets,
                banners,
                flows: [],
                tags,
              },
            },
            host_profile: {
              target: { scope: "domain" },
              notes: [`Evidence connected to ${domain}`],
              application: {},
            },
            domains: { domains },
            ttl_path: { hops: [] },
          };
          const failed = [domainsRes, packetsRes, bannersRes, tagsRes].find((res) => res.status === "rejected");
          if (failed) {
            this.error = (failed.reason && failed.reason.message) || `Failed to investigate ${domain}`;
          }
          this.lastUpdated = new Date().toLocaleTimeString();
        })
        .finally(() => {
          this.loading = false;
        });
    },
    addListEntry(kind) {
      const value = this.targetValue;
      if (!value) return;
      this.listActionSubmitting = kind;
      this.listActionMessage = "";
      this.error = "";
      const payload = {
        category: this.targetCategory,
        matchType: "exact",
        value,
        label: `${kind === "whitelist" ? "Trusted" : "Blocked"} ${this.targetLabel}: ${value}`,
      };
      const action = kind === "whitelist"
        ? this.store.createWhitelistEntry(payload)
        : this.store.createBlacklistEntry(payload);
      action
        .then(() => {
          this.listActionMessage = `${value} added to ${kind}.`;
        })
        .catch((err) => {
          this.error = (err && err.message) || `Failed to add ${value} to ${kind}`;
        })
        .finally(() => {
          this.listActionSubmitting = "";
        });
    },
  },
};
</script>

<style scoped>
.investigate-toggle {
  min-height: 44px;
}

.metric-card {
  border-radius: 16px;
}

.metric-icon {
  opacity: 0.92;
}

.suggestion-chip {
  cursor: pointer;
}

.summary-cell{
  /* Fixed width, not max-width: with `overflow-wrap: anywhere` a
     cell's min-content width is a single character, so the table's
     auto layout was free to collapse the column to ~1ch and wrap the
     banner one letter per line, blowing the row up to hundreds of
     pixels tall. A definite width pins the column; the clamp keeps
     every row the same height and the full text stays in the title
     attribute. */
  width: 220px;
  display: -webkit-box;
  -webkit-box-orient: vertical;
  -webkit-line-clamp: 2;
  line-clamp: 2;
  overflow: hidden;
  overflow-wrap: anywhere;
  vertical-align: top;
}
</style>
