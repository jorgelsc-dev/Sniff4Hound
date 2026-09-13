<template>
  <div>
    <ViewHeader
      overline="Operations"
      title="Dashboard"
      description="Runtime control, live telemetry metrics, and the latest captured traffic."
      :refresh-loading="loading"
      :show-time-range="true"
      @refresh="load"
    >
      <template #actions-prepend>
        <ClearDataButton @cleared="load" />
      </template>
    </ViewHeader>

    <EntityTablePanel
      title="Alertas y detecciones IA"
      subtitle="Paquetes puntuados por el motor de IA local (LOF + red neuronal), más recientes primero."
      class="mb-4"
      :rows="aiRows"
      :columns="aiColumns"
      :search-enabled="true"
      search-label="Buscar"
      search-placeholder="IP, puerto, protocolo, estado..."
      :search-fields="aiSearchFields"
      :filter-definitions="aiFilterDefinitions"
      :loading="loading"
      :error="''"
      :last-updated="lastUpdated"
      empty-text="Todavía no hay paquetes puntuados por la IA."
      :page-size="8"
      @refresh="load"
    >
      <template #header-actions>
        <v-chip size="small" color="primary">{{ aiSummary.analyzed }} analizados</v-chip>
        <v-chip size="small" color="warning">{{ aiSummary.candidates }} posibles falsos negativos</v-chip>
        <v-chip size="small" :color="aiSamplingEnabled ? 'success' : 'secondary'" variant="tonal">
          {{ aiSamplingEnabled ? "Training activo" : "Training detenido" }}
        </v-chip>
        <v-chip size="small" :color="aiAlertModeEnabled ? 'success' : 'secondary'" variant="tonal">
          {{ aiAlertModeEnabled ? "IA decide alertas" : "IA en modo consulta" }}
        </v-chip>
      </template>
      <template #cell-created_at="{ value }">
        {{ formatTimestamp(value) }}
      </template>
      <template #cell-proto="{ value }">
        <v-chip size="x-small" color="primary" variant="tonal">{{ String(value || "unknown").toUpperCase() }}</v-chip>
      </template>
      <template #cell-src_ip="{ value }">
        <span class="mono">{{ value || "-" }}</span>
      </template>
      <template #cell-dst_ip="{ value }">
        <span class="mono">{{ value || "-" }}</span>
      </template>
      <template #cell-score="{ value }">
        <span v-if="value === null || value === undefined" class="text-medium-emphasis">—</span>
        <v-chip v-else size="x-small" :color="aiScoreColor(value)" variant="tonal">{{ value }}</v-chip>
      </template>
      <template #cell-candidate="{ value }">
        <v-chip v-if="value" size="x-small" color="warning" variant="tonal">Posible falso negativo</v-chip>
        <span v-else class="text-medium-emphasis">—</span>
      </template>
      <template #cell-detection_status="{ value }">
        <v-chip size="x-small" variant="tonal">{{ value || "unknown" }}</v-chip>
      </template>
      <template #cell-actions="{ item }">
        <v-btn
          size="x-small"
          variant="text"
          :to="item.src_ip ? { path: '/investigate', query: { ip: item.src_ip } } : { path: '/ai' }"
          @click.stop
        >
          Investigar
        </v-btn>
      </template>
    </EntityTablePanel>

    <v-row density="compact" class="metric-row">
      <v-col v-for="metric in metricCards" :key="metric.key" cols="6" sm="4" lg="2">
        <v-card variant="tonal" class="pa-2 metric-card">
          <div class="d-flex align-center justify-space-between ga-2">
            <div>
              <div class="text-caption metric-label text-medium-emphasis">{{ metric.label }}</div>
              <div class="text-subtitle-1 font-weight-bold metric-value" :class="metric.colorClass">{{ metric.value }}</div>
            </div>
            <v-icon :icon="metric.icon" class="metric-icon" size="18" :class="metric.colorClass" />
          </div>
          <div class="text-caption text-medium-emphasis metric-caption">{{ metric.caption }}</div>
        </v-card>
      </v-col>
    </v-row>

    <v-alert v-if="error" type="error" variant="tonal" class="my-3">
      {{ error }}
    </v-alert>

    <v-row class="mt-3" density="compact">
      <v-col cols="12" md="6">
        <DataPanel
          title="Runtime Posture"
          subtitle="Both engines start stopped. Sniffer blockers and service-listener readiness are surfaced here."
          v-model:live-enabled="liveRefreshEnabled"
          :loading="loading"
          :error="''"
          :last-updated="lastUpdated"
          :live-refresh="true"
          @refresh="load"
        >
          <div class="runtime-grid">
            <div class="runtime-state-card">
              <div class="runtime-state-card__topline">
                <div>
                  <div class="text-subtitle-2">Sniffer</div>
                  <div class="text-caption text-medium-emphasis">
                    {{ snifferSummary }}
                  </div>
                </div>
                <div class="d-flex align-center ga-2">
                  <v-chip size="small" :color="snifferChipColor" variant="tonal" :prepend-icon="snifferStatusIcon">
                    {{ snifferStatusLabel }}
                  </v-chip>
                  <v-switch
                    :model-value="snifferRunning"
                    color="success"
                    density="compact"
                    hide-details
                    inset
                    :loading="engineBusy.sniffer"
                    :disabled="engineBusy.sniffer"
                    aria-label="Run the sniffer"
                    @update:model-value="(value) => toggleEngine('sniffer', value)"
                  />
                </div>
              </div>
              <div class="runtime-state-card__body">
                <div class="runtime-stat">
                  <span class="runtime-stat__label">Packets seen</span>
                  <span class="runtime-stat__value">{{ snifferPacketsSeen }}</span>
                </div>
                <div class="runtime-stat">
                  <span class="runtime-stat__label">Interfaces</span>
                  <span class="runtime-stat__value">{{ snifferInterfacesLabel }}</span>
                </div>
                <div v-if="snifferUnparseable > 0" class="runtime-stat">
                  <span class="runtime-stat__label">Unparseable frames</span>
                  <span class="runtime-stat__value text-warning">{{ snifferUnparseable }}</span>
                </div>
              </div>
            </div>

            <div class="runtime-state-card runtime-state-card--warm">
              <div class="runtime-state-card__topline">
                <div>
                  <div class="text-subtitle-2">Honeypot</div>
                  <div class="text-caption text-medium-emphasis">
                    {{ honeypotSummary }}
                  </div>
                </div>
                <div class="d-flex align-center ga-2">
                  <v-chip size="small" :color="honeypotChipColor" variant="tonal" :prepend-icon="honeypotStatusIcon">
                    {{ honeypotStatusLabel }}
                  </v-chip>
                  <v-switch
                    :model-value="honeypotRunning"
                    color="warning"
                    density="compact"
                    hide-details
                    inset
                    :loading="engineBusy.honeypot"
                    :disabled="engineBusy.honeypot"
                    aria-label="Run the honeypot"
                    @update:model-value="(value) => toggleEngine('honeypot', value)"
                  />
                </div>
              </div>
              <div class="runtime-state-card__body">
                <div class="runtime-stat">
                  <span class="runtime-stat__label">Events seen</span>
                  <span class="runtime-stat__value">{{ honeypotPacketsSeen }}</span>
                </div>
                <div class="runtime-stat">
                  <span class="runtime-stat__label">Listeners</span>
                  <span class="runtime-stat__value">{{ honeypotListenersLabel }}</span>
                </div>
              </div>
            </div>

            <div class="runtime-state-card runtime-state-card--ai">
              <div class="runtime-state-card__topline">
                <div>
                  <div class="text-subtitle-2">Training</div>
                  <div class="text-caption text-medium-emphasis">
                    {{ aiSamplingSummary }}
                  </div>
                </div>
                <div class="d-flex align-center ga-2">
                  <v-chip size="small" :color="aiSamplingEnabled ? 'success' : 'secondary'" variant="tonal" :prepend-icon="aiSamplingEnabled ? 'mdi-play-circle-outline' : 'mdi-stop-circle-outline'">
                    {{ aiSamplingEnabled ? "Running" : "Stopped" }}
                  </v-chip>
                  <v-switch
                    :model-value="aiSamplingEnabled"
                    color="secondary"
                    density="compact"
                    hide-details
                    inset
                    :loading="aiSamplingBusy"
                    :disabled="aiSamplingBusy"
                    aria-label="Run Training mode"
                    @update:model-value="toggleAiSampling"
                  />
                </div>
              </div>
              <div class="runtime-state-card__body">
                <div class="runtime-stat">
                  <span class="runtime-stat__label">Analizados</span>
                  <span class="runtime-stat__value">{{ aiSummary.analyzed }}</span>
                </div>
                <div class="runtime-stat">
                  <span class="runtime-stat__label">Posibles falsos negativos</span>
                  <span class="runtime-stat__value">{{ aiSummary.candidates }}</span>
                </div>
              </div>
            </div>

            <div class="runtime-state-card runtime-state-card--ai">
              <div class="runtime-state-card__topline">
                <div>
                  <div class="text-subtitle-2">IA</div>
                  <div class="text-caption text-medium-emphasis">
                    {{ aiAlertModeSummary }}
                  </div>
                </div>
                <div class="d-flex align-center ga-2">
                  <v-chip size="small" :color="aiAlertModeEnabled ? 'success' : 'secondary'" variant="tonal" :prepend-icon="aiAlertModeEnabled ? 'mdi-play-circle-outline' : 'mdi-stop-circle-outline'">
                    {{ aiAlertModeEnabled ? "Running" : "Stopped" }}
                  </v-chip>
                  <v-switch
                    :model-value="aiAlertModeEnabled"
                    color="secondary"
                    density="compact"
                    hide-details
                    inset
                    :loading="aiAlertModeBusy"
                    :disabled="aiAlertModeBusy || !rawRetentionEnabled"
                    :aria-label="rawRetentionEnabled ? 'Run the AI alert engine' : 'AI alert engine requires raw packet retention'"
                    @update:model-value="toggleAiAlertMode"
                  />
                </div>
              </div>
              <div class="runtime-state-card__body">
                <div class="runtime-stat">
                  <span class="runtime-stat__label">Bytes crudos</span>
                  <div class="d-flex align-center ga-2">
                    <span class="runtime-stat__value">{{ rawRetentionEnabled ? "Retenidos" : "No retenidos" }}</span>
                    <v-switch
                      :model-value="rawRetentionEnabled"
                      color="warning"
                      density="compact"
                      hide-details
                      inset
                      :loading="rawRetentionBusy"
                      :disabled="rawRetentionBusy"
                      aria-label="Toggle raw packet retention"
                      @update:model-value="toggleRawRetention"
                    />
                  </div>
                </div>
                <div v-if="!rawRetentionEnabled" class="runtime-stat">
                  <span class="runtime-stat__value text-warning">
                    El clasificador de IA necesita los bytes crudos del paquete para puntuar. Activa la retencion arriba.
                  </span>
                </div>
                <div v-else class="runtime-stat">
                  <span class="runtime-stat__label">Modo</span>
                  <span class="runtime-stat__value">{{ aiSamplingEnabled ? "IA + Training" : "Solo IA" }}</span>
                </div>
              </div>
            </div>
          </div>

          <v-alert
            v-if="engineError"
            type="error"
            variant="tonal"
            density="comfortable"
            class="mt-4"
          >
            {{ engineError }}
          </v-alert>

          <v-alert
            v-if="bothEnginesRunning"
            type="info"
            variant="tonal"
            density="comfortable"
            class="mt-4"
          >
            Both engines are running. The sniffer also captures the traffic reaching the
            honeypot, so those connections appear twice: once from raw capture and once as
            a <span class="mono">honeypot:&lt;port&gt;</span> row.
          </v-alert>

          <v-alert
            v-if="snifferBlocked"
            type="error"
            variant="tonal"
            density="comfortable"
            class="mt-4"
          >
            {{ snifferErrorSummary }}
          </v-alert>
        </DataPanel>
      </v-col>

      <v-col cols="12" md="6">
        <DataPanel
          title="Protocol Pressure"
          subtitle="Top observed protocols and quick entry points into the dedicated traffic views."
          v-model:live-enabled="liveRefreshEnabled"
          :loading="loading"
          :last-updated="lastUpdated"
          :live-refresh="true"
          @refresh="load"
        >
          <div class="d-flex flex-wrap ga-2">
            <v-btn color="primary" variant="flat" icon to="/soc"
              aria-label="Open SOC"
            >
              <v-icon icon="mdi-shield-search" />
              <v-tooltip activator="parent" location="bottom">Open SOC</v-tooltip>
            </v-btn>
            <v-btn color="info" variant="outlined" icon to="/investigate"
              aria-label="Investigate Host"
            >
              <v-icon icon="mdi-magnify-scan" />
              <v-tooltip activator="parent" location="bottom">Investigate Host</v-tooltip>
            </v-btn>
            <v-btn color="secondary" variant="outlined" icon to="/protocols"
              aria-label="Protocols"
            >
              <v-icon icon="mdi-swap-horizontal" />
              <v-tooltip activator="parent" location="bottom">Protocols</v-tooltip>
            </v-btn>
            <v-btn color="primary" variant="outlined" icon to="/sniffer" aria-label="Open Sniffer">
              <v-icon icon="mdi-ethernet" />
              <v-tooltip activator="parent" location="bottom">Open Sniffer</v-tooltip>
            </v-btn>
            <v-btn color="warning" variant="outlined" icon to="/honeypot" aria-label="Open Honeypot">
              <v-icon icon="mdi-spider-web" />
              <v-tooltip activator="parent" location="bottom">Open Honeypot</v-tooltip>
            </v-btn>
          </div>

          <v-divider class="my-4" />

          <div class="text-subtitle-2">Observed protocols</div>
          <div class="d-flex flex-wrap ga-2 mt-3">
            <v-chip
              v-for="item in protocolSeries"
              :key="item.label"
              size="small"
              variant="tonal"
              color="info"
            >
              {{ item.label.toUpperCase() }}: {{ item.value }}
            </v-chip>
            <span v-if="!protocolSeries.length" class="text-body-2 text-medium-emphasis">
              No packets recorded yet.
            </span>
          </div>

          <v-divider class="my-4" />

          <div class="text-subtitle-2">WebSocket clients</div>
          <div class="text-body-2 text-medium-emphasis mt-2">
            {{ wsClientCount }} dashboards connected to realtime updates.
          </div>
        </DataPanel>
      </v-col>
    </v-row>

    <v-row class="mt-3" density="compact">
      <v-col cols="12">
        <EntityTablePanel
          title="Latest Packets"
          subtitle="Newest captured frames from packet capture and honeypot listeners."
          v-model:live-enabled="liveRefreshEnabled"
          :rows="recentPackets"
          :columns="packetColumns"
          :search-enabled="true"
          search-label="Search packets"
          search-placeholder="IP, port, flow, summary..."
          :search-fields="packetSearchFields"
          :filter-definitions="packetFilterDefinitions"
          :expandable-rows="true"
          :loading="loading"
          :error="error"
          :last-updated="lastUpdated"
          :live-refresh="true"
          empty-text="No packets visible"
          :page-size="8"
          :total-available="packetsMeta.totalAvailable"
          :truncated="packetsMeta.truncated"
          :range-label="timeRangeLabel"
          @refresh="load"
          @load-more="loadMorePackets"
        >
          <template #cell-updated_at="{ value }">
            {{ formatTimestamp(value) }}
          </template>
          <template #cell-interface="{ value }">
            <v-chip size="x-small" :color="interfaceChipColor(value)" variant="tonal">
              {{ value || "unknown" }}
            </v-chip>
          </template>
          <template #cell-proto="{ value }">
            <v-chip size="x-small" color="primary" variant="tonal">
              {{ String(value || "unknown").toUpperCase() }}
            </v-chip>
          </template>
          <template #cell-state="{ value }">
            <v-chip size="x-small" :color="statusColor(value)" variant="tonal">
              {{ value || "unknown" }}
            </v-chip>
          </template>
          <template #cell-src_ip="{ value }">
            <span class="mono">{{ value || "-" }}</span>
          </template>
          <template #cell-dst_ip="{ value }">
            <span class="mono">{{ value || "-" }}</span>
          </template>
          <template #cell-size="{ item }">
            <span class="meta-cell">{{ buildPacketSizeSummary(item) }}</span>
          </template>
          <template #cell-summary="{ item }">
            <span class="summary-cell">{{ buildPacketSummary(item, 120) || "-" }}</span>
          </template>
        </EntityTablePanel>
      </v-col>
    </v-row>

  </div>
</template>

<script>
import store from "../state/appStore";
import ViewHeader from "../components/ui/ViewHeader.vue";
import DataPanel from "../components/ui/DataPanel.vue";
import EntityTablePanel from "../components/ui/EntityTablePanel.vue";
import ClearDataButton from "../components/ui/ClearDataButton.vue";
import {
  buildPacketSizeSummary,
  buildPacketSummary,
  formatTimestamp,
  isHoneypotInterface,
} from "../utils/traffic";

const REFRESH_EVENT_TYPES = new Set(["packet", "stats_update", "runtime_mode"]);

export default {
  name: "DashboardView",
  components: {
    ViewHeader,
    DataPanel,
    EntityTablePanel,
    ClearDataButton,
  },
  data() {
    return {
      store,
      loading: false,
      error: "",
      lastUpdated: "",
      liveRefreshEnabled: true,
      engineBusy: { sniffer: false, honeypot: false },
      engineDesired: { sniffer: null, honeypot: null },
      engineError: "",
      dashboard: {},
      analytics: {},
      aiRows: [],
      aiSummary: { analyzed: 0, candidates: 0 },
      aiSamplingEnabled: false,
      aiSamplingBusy: false,
      aiAlertModeEnabled: false,
      aiAlertModeBusy: false,
      rawRetentionEnabled: false,
      rawRetentionBusy: false,
      aiColumns: [
        { key: "created_at", label: "Seen" },
        { key: "proto", label: "Proto" },
        { key: "src_ip", label: "Src IP" },
        { key: "src_port", label: "Src Port" },
        { key: "dst_ip", label: "Dst IP" },
        { key: "dst_port", label: "Dst Port" },
        { key: "score", label: "Score" },
        { key: "candidate", label: "Flag" },
        { key: "detection_status", label: "Status" },
        { key: "actions", label: "", sortable: false },
      ],
      aiSearchFields: ["proto", "src_ip", "src_port", "dst_ip", "dst_port", "detection_status"],
      aiFilterDefinitions: [
        {
          key: "proto",
          label: "Proto",
          field: "proto",
          optionLabel: (value) => String(value || "").toUpperCase(),
        },
        {
          key: "detection_status",
          label: "Status",
          field: "detection_status",
        },
      ],
      packets: [],
      packetLimit: 12,
      packetsMeta: { totalAvailable: null, returned: null, truncated: null },
      packetColumns: [
        { key: "updated_at", label: "Seen" },
        { key: "interface", label: "Interface" },
        { key: "proto", label: "Proto" },
        { key: "state", label: "State" },
        { key: "src_ip", label: "Src IP" },
        { key: "src_port", label: "Src Port" },
        { key: "dst_ip", label: "Dst IP" },
        { key: "dst_port", label: "Dst Port" },
        { key: "size", label: "Size" },
        { key: "summary", label: "Summary" },
      ],
      packetSearchFields: [
        "updated_at",
        "interface",
        "proto",
        "state",
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "length",
        "payload_len",
        "summary",
        "payload_text",
        "banner_text",
        "flow_key",
        "tcp_flags",
        "icmp_type",
        "icmp_code",
      ],
      packetFilterDefinitions: [
        {
          key: "proto",
          label: "Proto",
          field: "proto",
          optionLabel: (value) => String(value || "").toUpperCase(),
        },
        {
          key: "interface",
          label: "Interface",
          field: "interface",
        },
        {
          key: "state",
          label: "State",
          field: "state",
        },
      ],
      wsRefreshTimer: null,
      stopTableRefreshSubscription: null,
    };
  },
  computed: {
    apiBase() {
      return this.store.state.apiBase;
    },
    counts() {
      return this.dashboard && this.dashboard.counts ? this.dashboard.counts : {};
    },
    runtime() {
      const dashboardRuntime = this.dashboard && this.dashboard.runtime && typeof this.dashboard.runtime === "object"
        ? this.dashboard.runtime
        : {};
      const liveRuntime = this.store.state.runtime && typeof this.store.state.runtime === "object"
        ? this.store.state.runtime
        : {};
      return {
        ...dashboardRuntime,
        ...liveRuntime,
        sniffer: {
          ...(dashboardRuntime.sniffer && typeof dashboardRuntime.sniffer === "object" ? dashboardRuntime.sniffer : {}),
          ...(liveRuntime.sniffer && typeof liveRuntime.sniffer === "object" ? liveRuntime.sniffer : {}),
        },
        honeypot: {
          ...(dashboardRuntime.honeypot && typeof dashboardRuntime.honeypot === "object" ? dashboardRuntime.honeypot : {}),
          ...(liveRuntime.honeypot && typeof liveRuntime.honeypot === "object" ? liveRuntime.honeypot : {}),
        },
      };
    },
    snifferRuntime() {
      return this.runtime.sniffer && typeof this.runtime.sniffer === "object" ? this.runtime.sniffer : {};
    },
    honeypotRuntime() {
      return this.runtime.honeypot && typeof this.runtime.honeypot === "object" ? this.runtime.honeypot : {};
    },
    metricCards() {
      const analyticsSummary = this.analytics.summary || {};
      return [
        {
          key: "tags",
          label: "Tags",
          value: Number(this.counts.count_tags || 0),
          caption: "Rule hits and parsed metadata",
          icon: "mdi-tag-multiple",
          colorClass: "text-primary",
        },
        {
          key: "packets",
          label: "Packets",
          value: Number(this.counts.count_ports || 0),
          caption: "Frames written into packet telemetry",
          icon: "mdi-ethernet",
          colorClass: "text-success",
        },
        {
          key: "responses",
          label: "Responses",
          value: Number(this.counts.count_banners || 0),
          caption: "Decoded payload and banner artifacts",
          icon: "mdi-server-network",
          colorClass: "text-info",
        },
        {
          key: "hosts",
          label: "Unique Hosts",
          value: Number(analyticsSummary.unique_hosts || 0),
          caption: "Distinct IPs seen across the capture set",
          icon: "mdi-lan-connect",
          colorClass: "text-warning",
        },
        {
          key: "protocols",
          label: "Protocols",
          value: this.protocolSeries.length,
          caption: "Observed protocol families",
          icon: "mdi-source-branch",
          colorClass: "text-secondary",
        },
        {
          key: "honeypot",
          label: "Honeypot Hits",
          value: this.honeypotPacketsSeen,
          caption: "Inbound events recorded by honeypot listeners",
          icon: "mdi-server-security",
          colorClass: "text-warning",
        },
      ];
    },
    protocolSeries() {
      return Array.isArray(this.analytics.ports_by_proto)
        ? this.analytics.ports_by_proto.slice(0, 8)
        : [];
    },
    wsClientCount() {
      const clients = this.dashboard && Array.isArray(this.dashboard.ws_clients) ? this.dashboard.ws_clients : [];
      return clients.length;
    },
    recentPackets() {
      return Array.isArray(this.packets) ? this.packets : [];
    },
    timeRangeLabel() {
      return this.store.timeRangeLabel();
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
    // Both engines writing at once is supported, but it is worth saying out
    // loud: raw capture sees the honeypot's own traffic too, so those
    // connections land in the store twice under different interfaces.
    bothEnginesRunning() {
      return this.snifferRunning && this.honeypotRunning;
    },
    snifferBlocked() {
      return String(this.snifferRuntime.capture_state || "").trim().toLowerCase() === "blocked";
    },
    snifferStatusLabel() {
      if (this.engineDesired.sniffer === true) return "Starting";
      if (this.engineDesired.sniffer === false) return "Stopping";
      if (this.snifferBlocked) return "Blocked";
      if (this.snifferRuntime.running) return "Running";
      return "Stopped";
    },
    snifferChipColor() {
      if (this.snifferBlocked) return "error";
      if (this.snifferRuntime.running) return "success";
      return "secondary";
    },
    snifferStatusIcon() {
      if (this.engineDesired.sniffer !== null) return "mdi-progress-clock";
      if (this.snifferBlocked) return "mdi-alert-circle-outline";
      if (this.snifferRuntime.running) return "mdi-play-circle-outline";
      return "mdi-stop-circle-outline";
    },
    snifferPacketsSeen() {
      return Number(this.snifferRuntime.packets_seen || 0);
    },
    snifferUnparseable() {
      // Only shown once it is non-zero: a rising count is the visible sign
      // of malformed/fuzzed frames aimed at the parser itself.
      return Number(this.snifferRuntime.packets_unparseable || 0);
    },
    snifferInterfacesLabel() {
      const active = Array.isArray(this.snifferRuntime.interfaces) ? this.snifferRuntime.interfaces : [];
      const selected = Array.isArray(this.snifferRuntime.selected_interfaces)
        ? this.snifferRuntime.selected_interfaces
        : [];
      if (active.length === 1) return active[0];
      if (active.length > 1) return `${active.length} active`;
      if (selected.length === 1) return selected[0];
      if (selected.length > 1) return `${selected.length} selected`;
      return "all visible";
    },
    snifferSummary() {
      if (this.snifferBlocked) return this.snifferErrorSummary;
      if (this.snifferRuntime.running) return "Passive capture is running.";
      return `Stopped. Ready on ${this.snifferInterfacesLabel}.`;
    },
    snifferErrorSummary() {
      const entries = this.snifferRuntime.errors && typeof this.snifferRuntime.errors === "object"
        ? Object.entries(this.snifferRuntime.errors)
        : [];
      if (!entries.length) return "Packet capture is blocked on the selected interfaces.";
      return entries
        .slice(0, 2)
        .map(([name, message]) => `${name}: ${message}`)
        .join(" | ");
    },
    honeypotPacketsSeen() {
      return Number(this.honeypotRuntime.packets_seen || 0);
    },
    honeypotStatusLabel() {
      if (this.engineDesired.honeypot === true) return "Starting";
      if (this.engineDesired.honeypot === false) return "Stopping";
      if (this.honeypotRuntime.running) return "Running";
      return "Stopped";
    },
    honeypotChipColor() {
      return this.honeypotRuntime.running ? "warning" : "secondary";
    },
    honeypotStatusIcon() {
      if (this.engineDesired.honeypot !== null) return "mdi-progress-clock";
      return this.honeypotRuntime.running ? "mdi-play-circle-outline" : "mdi-stop-circle-outline";
    },
    honeypotListenersLabel() {
      const listenerCount = Number(this.honeypotRuntime.listener_count);
      if (Number.isFinite(listenerCount) && listenerCount > 0) {
        if (listenerCount === 1) return "1 listener";
        return `${listenerCount} listeners`;
      }
      const listeners = Array.isArray(this.honeypotRuntime.listeners) ? this.honeypotRuntime.listeners : [];
      if (listeners.length === 1) return "1 listener";
      return `${listeners.length} listeners`;
    },
    honeypotSummary() {
      if (this.honeypotRuntime.running) return "Honeypot is accepting inbound traffic.";
      return "Stopped until you start the honeypot.";
    },
    aiSamplingSummary() {
      if (this.aiSamplingEnabled) {
        return "Reentrenando la IA con el veredicto de los Monitors en todo tráfico que genera alerta.";
      }
      return "Detenido. Solo se persiste el tráfico que ya generó una alerta.";
    },
    aiAlertModeSummary() {
      if (!this.rawRetentionEnabled) {
        return "Deshabilitado: activa la retención de bytes crudos para usarlo.";
      }
      if (this.aiAlertModeEnabled) {
        return this.aiSamplingEnabled
          ? "IA activa junto a Training: los Monitors siguen decidiendo la alerta."
          : "Solo IA: el catálogo de reglas está en pausa, la IA decide las alertas.";
      }
      return "Detenido. Los Monitors deciden las alertas normalmente.";
    },
  },
  watch: {
    apiBase() {
      this.load();
    },
    liveRefreshEnabled(value) {
      if (!value && this.wsRefreshTimer) {
        clearTimeout(this.wsRefreshTimer);
        this.wsRefreshTimer = null;
      }
    },
  },
  mounted() {
    this.load();
    this.stopTableRefreshSubscription = this.store.subscribeTableRefresh(this.handleWsRefresh);
  },
  beforeUnmount() {
    if (this.wsRefreshTimer) {
      clearTimeout(this.wsRefreshTimer);
      this.wsRefreshTimer = null;
    }
    if (typeof this.stopTableRefreshSubscription === "function") {
      this.stopTableRefreshSubscription();
      this.stopTableRefreshSubscription = null;
    }
  },
  methods: {
    toggleEngine(engine, shouldRun) {
      if (this.engineBusy[engine]) return;
      this.engineBusy[engine] = true;
      this.engineDesired[engine] = Boolean(shouldRun);
      this.engineError = "";
      this.store
        .controlEngine(engine, shouldRun ? "start" : "stop")
        .then(() => {
          this.engineDesired[engine] = null;
        })
        .catch((err) => {
          this.engineDesired[engine] = null;
          this.engineError = (err && err.message) || `Failed to ${shouldRun ? "start" : "stop"} the ${engine}`;
        })
        .finally(() => {
          this.engineBusy[engine] = false;
          this.load({ silent: true }).catch(() => null);
        });
    },
    // Unlike sniffer/honeypot, Training has no separate running process to
    // start/stop - it is a persistent flag on the capture pipeline: every
    // packet that passes exclusions/whitelist gets evaluated by Monitors
    // (rules + anomalies) as usual, and whatever raises an alert is
    // auto-fed to the IA trainer, labeled "malicious" from that verdict.
    toggleAiSampling(enabled) {
      if (this.aiSamplingBusy) return;
      this.aiSamplingBusy = true;
      this.engineError = "";
      this.store
        .fetchJsonPromise("/api/ai/config", {
          method: "POST",
          body: JSON.stringify({ training_enabled: Boolean(enabled) }),
        })
        .then((config) => {
          this.aiSamplingEnabled = Boolean(config.training_enabled);
        })
        .catch((err) => {
          this.engineError = (err && err.message) || "Failed to update Training mode";
        })
        .finally(() => {
          this.aiSamplingBusy = false;
        });
    },
    // Raw packet retention (SNIFF4HOUND_STORE_RAW_PACKET) used to be
    // startup-only; it now lives in runtime_config so it can be flipped
    // here without restarting sniff4hound. Turning it off does not purge
    // already-stored bytes immediately - that happens on the next process
    // start (see store._migrate_sensitive_capture_storage) - but it stops
    // new packets from keeping theirs right away.
    toggleRawRetention(enabled) {
      if (this.rawRetentionBusy) return;
      this.rawRetentionBusy = true;
      this.engineError = "";
      this.store
        .fetchJsonPromise("/api/ai/config", {
          method: "POST",
          body: JSON.stringify({ raw_retention_enabled: Boolean(enabled) }),
        })
        .then((config) => {
          this.rawRetentionEnabled = Boolean(config.raw_retention_enabled);
        })
        .catch((err) => {
          this.engineError = (err && err.message) || "Failed to update raw packet retention";
        })
        .finally(() => {
          this.rawRetentionBusy = false;
        });
    },
    // "Solo IA": the AI classifier decides alerts instead of the rule
    // catalog (only takes effect while Training is off - see backend
    // Sniffer._store_packet). Requires raw packet retention
    // (SNIFF4HOUND_STORE_RAW_PACKET=1) so the classifier has bytes to
    // score; the backend rejects enabling it otherwise.
    toggleAiAlertMode(enabled) {
      if (this.aiAlertModeBusy) return;
      this.aiAlertModeBusy = true;
      this.engineError = "";
      this.store
        .fetchJsonPromise("/api/ai/config", {
          method: "POST",
          body: JSON.stringify({ ai_alert_mode_enabled: Boolean(enabled) }),
        })
        .then((config) => {
          this.aiAlertModeEnabled = Boolean(config.ai_alert_mode_enabled);
        })
        .catch((err) => {
          this.engineError = (err && err.message) || "Failed to update the AI engine";
        })
        .finally(() => {
          this.aiAlertModeBusy = false;
        });
    },
    aiScoreColor(value) {
      const score = Number(value);
      if (!Number.isFinite(score)) return "secondary";
      if (score >= 75) return "error";
      if (score >= 50) return "warning";
      return "secondary";
    },
    buildPacketSizeSummary,
    buildPacketSummary,
    formatTimestamp,
    normalizeStatus(value) {
      const raw = String(value || "active").trim().toLowerCase();
      if (raw === "open" || raw === "active") return raw;
      if (raw === "filtered" || raw === "blocked") return raw;
      if (raw === "closed") return raw;
      if (raw === "restarting") return "restarting";
      if (raw === "stopped") return "stopped";
      return "active";
    },
    statusColor(value) {
      const status = this.normalizeStatus(value);
      if (status === "open" || status === "active") return "success";
      if (status === "restarting") return "info";
      if (status === "filtered" || status === "blocked" || status === "stopped") return "warning";
      if (status === "closed") return "error";
      return "warning";
    },
    interfaceChipColor(value) {
      return isHoneypotInterface(value) ? "warning" : "info";
    },
    handleWsRefresh(event) {
      if (!this.liveRefreshEnabled) return;
      const eventType = String((event && event.type) || "").trim().toLowerCase();
      if (!REFRESH_EVENT_TYPES.has(eventType)) return;
      if (this.wsRefreshTimer) return;
      this.wsRefreshTimer = setTimeout(() => {
        this.wsRefreshTimer = null;
        this.load({ silent: true }).catch(() => {
          // preserve current dashboard on transient realtime failures
        });
      }, 10000);
    },
    loadMorePackets() {
      this.packetLimit = Math.min(this.packetLimit + 100, 5000);
      this.load({ silent: true }).catch(() => null);
    },
    dashboardQuery() {
      const params = new URLSearchParams({ compact: "1" });
      const range = String(this.store.state.timeRange || "").trim();
      if (range) params.set("since", range);
      return `?${params.toString()}`;
    },
    load(options = {}) {
      if (!options.silent) this.loading = true;
      this.error = "";
      const dashboardQuery = this.dashboardQuery();
      return Promise.allSettled([
        this.store.fetchJsonPromise(`/api/dashboard/${dashboardQuery}`),
        this.store.fetchJsonPromise(`/api/charts/analytics${dashboardQuery}`),
        this.store.fetchListPromise("/ports/", { limit: this.packetLimit }),
        this.store.fetchJsonPromise("/api/ai/packets/?threshold=50"),
      ])
        .then(([dashboardRes, analyticsRes, packetsRes, aiRes]) => {
          const errors = [];
          if (dashboardRes.status === "fulfilled") {
            this.dashboard = dashboardRes.value || {};
          } else {
            this.dashboard = {};
            errors.push((dashboardRes.reason && dashboardRes.reason.message) || "Failed to load dashboard snapshot");
          }
          if (analyticsRes.status === "fulfilled") {
            this.analytics = analyticsRes.value || {};
          } else {
            this.analytics = {};
            errors.push((analyticsRes.reason && analyticsRes.reason.message) || "Failed to load analytics");
          }
          if (packetsRes.status === "fulfilled") {
            this.packets = packetsRes.value.rows;
            this.packetsMeta = packetsRes.value.meta;
          } else {
            this.packets = [];
            this.packetsMeta = { totalAvailable: null, returned: null, truncated: null };
            errors.push((packetsRes.reason && packetsRes.reason.message) || "Failed to load packets");
          }
          if (aiRes.status === "fulfilled") {
            const data = aiRes.value || {};
            this.aiRows = Array.isArray(data.rows) ? data.rows : [];
            this.aiSummary = { analyzed: Number(data.analyzed || 0), candidates: Number(data.candidates || 0) };
            this.aiSamplingEnabled = Boolean(data.training_enabled);
            this.aiAlertModeEnabled = Boolean(data.ai_alert_mode_enabled);
            this.rawRetentionEnabled = Boolean(data.raw_retention_enabled);
          } else {
            this.aiRows = [];
            this.aiSummary = { analyzed: 0, candidates: 0 };
            errors.push((aiRes.reason && aiRes.reason.message) || "Failed to load AI detections");
          }
          this.lastUpdated = new Date().toLocaleTimeString();
          this.error = errors.join(" | ");
        })
        .finally(() => {
          this.loading = false;
        });
    },
  },
};
</script>

<style scoped>
.metric-row {
  margin-top: -2px;
}

.metric-card {
  min-height: 68px;
  border-radius: 8px;
}

.metric-label {
  font-size: 0.72rem;
  line-height: 1.2;
}

.metric-value {
  line-height: 1.25;
}

.metric-icon {
  opacity: 0.92;
}

.metric-caption {
  margin-top: 2px;
  font-size: 0.72rem;
  line-height: 1.25;
  display: -webkit-box;
  -webkit-box-orient: vertical;
  -webkit-line-clamp: 2;
  line-clamp: 2;
  overflow: hidden;
  line-height: 1.25;
}

.runtime-grid {
  display: grid;
  /* 4 cards now (Sniffer/Honeypot/Training/IA) - a fixed 2-column grid left
     an odd card alone on its own row with an empty cell beside it. Auto-fit
     lets it settle into as many columns as fit on wide layouts and wrap
     down as space shrinks, same as the media-query fallback below already
     does. */
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: 8px;
}

.runtime-state-card {
  padding: 8px;
  border-radius: 8px;
  border: 1px solid rgba(104, 184, 229, 0.16);
  background: linear-gradient(180deg, rgba(12, 21, 33, 0.88), rgba(8, 14, 23, 0.84));
}

.runtime-state-card--warm {
  border-color: rgba(246, 179, 87, 0.16);
  background: linear-gradient(180deg, rgba(32, 22, 11, 0.76), rgba(15, 13, 10, 0.82));
}

.runtime-state-card--ai {
  border-color: rgba(166, 133, 246, 0.18);
  background: linear-gradient(180deg, rgba(24, 16, 34, 0.8), rgba(13, 10, 20, 0.84));
}

.runtime-state-card__topline {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 10px;
}

.runtime-state-card__body {
  display: grid;
  gap: 6px;
  margin-top: 8px;
}

.runtime-stat {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  padding: 4px 7px;
  border-radius: 6px;
  background: rgba(4, 10, 18, 0.44);
}

.runtime-stat__label {
  color: rgba(176, 199, 220, 0.76);
  font-size: 0.7rem;
}

.runtime-stat__value {
  font-weight: 700;
  font-size: 0.8rem;
}

.flow-cell {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.flow-cell__arrow {
  color: rgba(121, 213, 248, 0.9);
}

.mono {
  font-family: var(--font-mono);
}

.meta-cell{
  /* Fixed width, not max-width: with `overflow-wrap: anywhere` a
     cell's min-content width is a single character, so the table's
     auto layout was free to collapse the column to ~1ch and wrap the
     banner one letter per line, blowing the row up to hundreds of
     pixels tall. A definite width pins the column; the clamp keeps
     every row the same height and the full text stays in the title
     attribute. */
  width: 160px;
  display: -webkit-box;
  -webkit-box-orient: vertical;
  -webkit-line-clamp: 2;
  line-clamp: 2;
  overflow: hidden;
  overflow-wrap: anywhere;
  vertical-align: top;
}

.summary-cell {
  display: inline-block;
  max-width: 420px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

/* The panel is now only ~50% of the viewport from md up (it used to be
   full-width until xl), so the sniffer/honeypot/training/IA grid needs to
   collapse to one column across that whole md-to-xl range or its cards get
   cramped - not just below the old single 1264px cutoff. */
@media (max-width: 1900px) and (min-width: 600px) {
  .runtime-grid {
    grid-template-columns: 1fr;
  }
}

@media (max-width: 600px) {
  .runtime-grid {
    grid-template-columns: 1fr;
  }
}
</style>
