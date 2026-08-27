<template>
  <div class="protocols-view">
    <ViewHeader
      overline="Protocol Atlas"
      title="Protocols"
      description="Pick a supported family and review tables, stats, and charts tailored to that traffic type."
      :refresh-loading="loading"
      :show-time-range="true"
      @refresh="load"
    />

    <v-card class="protocol-hero pa-6 pa-md-7" rounded="xl" variant="tonal" :style="heroStyle">
      <v-row dense class="align-center">
        <v-col cols="12" lg="8">
          <div class="text-overline">Selected slice</div>
          <h2 class="protocol-hero__title">
            {{ selectedProfile.label }}
          </h2>
          <p class="protocol-hero__copy">
            {{ selectedProfile.description }}
          </p>

          <div class="protocol-hero__chips">
            <v-chip size="small" color="primary" variant="tonal">
              Rows: {{ formatNumber(packetRows.length) }}
            </v-chip>
            <v-chip size="small" color="success" variant="tonal">
              Banners: {{ formatNumber(bannerRows.length) }}
            </v-chip>
            <v-chip size="small" color="info" variant="tonal">
              Tags: {{ formatNumber(tagRows.length) }}
            </v-chip>
            <v-chip size="small" variant="outlined">
              Signal: {{ selectedProfile.signalLabel }}
            </v-chip>
          </div>
        </v-col>

        <v-col cols="12" lg="4">
          <div class="protocol-hero__panel">
            <div class="protocol-hero__panel-kicker">Current focus</div>
            <div class="protocol-hero__panel-title">
              {{ selectedProfile.focusTitle }}
            </div>
            <div class="protocol-hero__stats">
              <div class="protocol-hero__stat">
                <span>Unique endpoints</span>
                <strong>{{ formatNumber(uniqueEndpointCount) }}</strong>
              </div>
              <div class="protocol-hero__stat">
                <span>Average frame</span>
                <strong>{{ formatHumanBytes(averageFrameSize) }}</strong>
              </div>
              <div class="protocol-hero__stat">
                <span>Last updated</span>
                <strong>{{ lastUpdated || "pending" }}</strong>
              </div>
              <div class="protocol-hero__stat">
                <span>Supported protocols</span>
                <strong>{{ formatNumber(protocolCards.length) }}</strong>
              </div>
            </div>
          </div>
        </v-col>
      </v-row>
    </v-card>

    <div class="d-flex align-center justify-space-between flex-wrap ga-3 mt-6 mb-2">
      <div>
        <div class="text-subtitle-1">Protocol stack</div>
        <div class="text-caption text-medium-emphasis">
          Grouped by the layer each protocol lives at. By default only protocols with
          traffic are shown.
        </div>
      </div>
      <v-switch
        v-model="showEmptyProtocols"
        color="primary"
        density="compact"
        hide-details
        inset
        :label="`Show all ${formatNumber(protocolCards.length)} supported`"
      />
    </div>

    <div v-for="layer in protocolLayers" :key="layer.key" class="protocol-layer mb-4">
      <div class="protocol-layer__head">
        <v-chip :color="layer.color" size="small" variant="flat">{{ layer.label }}</v-chip>
        <span class="text-caption text-medium-emphasis">{{ layer.description }}</span>
        <span class="protocol-layer__count text-caption text-medium-emphasis">
          {{ formatNumber(layer.seen) }} seen · {{ formatNumber(layer.total) }} frames
        </span>
      </div>
      <div class="protocol-rail">
      <v-card
        v-for="proto in layer.protocols"
        :key="proto.key"
        :to="protocolRoute(proto.key)"
        class="protocol-card pa-4"
        :class="{ 'protocol-card--active': isSelectedProtocol(proto.key), 'protocol-card--idle': !proto.count }"
        rounded="xl"
        variant="tonal"
      >
        <div class="protocol-card__top">
          <v-avatar :color="proto.color" class="protocol-card__avatar" size="40" variant="tonal">
            <v-icon :icon="proto.icon" />
          </v-avatar>
          <v-chip :color="proto.color" size="x-small" variant="tonal">
            {{ formatNumber(proto.count) }}
          </v-chip>
        </div>
        <div class="text-subtitle-2 mt-4">
          {{ proto.label }}
        </div>
        <div class="text-body-2 text-medium-emphasis mt-1 protocol-card__copy">
          {{ proto.description }}
        </div>
      </v-card>
      </div>
    </div>

    <v-row class="mt-6" dense>
      <v-col v-for="metric in metricCards" :key="metric.key" cols="12" sm="6" xl="2">
        <v-card variant="tonal" class="pa-5 metric-card">
          <div class="d-flex align-center justify-space-between ga-3">
            <div>
              <div class="text-caption text-medium-emphasis">{{ metric.label }}</div>
              <div class="text-h5 font-weight-bold" :class="metric.colorClass">
                {{ metric.value }}
              </div>
            </div>
            <v-icon :icon="metric.icon" class="metric-icon" :class="metric.colorClass" />
          </div>
          <div class="text-caption text-medium-emphasis mt-3">
            {{ metric.caption }}
          </div>
        </v-card>
      </v-col>
    </v-row>

    <v-row class="mt-4" dense>
      <v-col v-for="chart in chartPanels" :key="chart.key" cols="12" lg="4">
        <v-card variant="tonal" class="pa-5 chart-card">
          <div class="d-flex align-start justify-space-between ga-3">
            <div>
              <div class="text-subtitle-1">{{ chart.title }}</div>
              <div class="text-caption text-medium-emphasis">
                {{ chart.subtitle }}
              </div>
            </div>
            <v-chip size="small" variant="outlined" :color="chart.color">
              {{ formatNumber(chart.series.length) }}
            </v-chip>
          </div>

          <div v-if="chart.series.length" class="chart-stack mt-4">
            <div v-for="item in chart.series" :key="`${chart.key}-${item.label}`" class="chart-row">
              <div class="chart-row__label" :title="item.label">
                {{ item.label }}
              </div>
              <div class="chart-row__track" aria-hidden="true">
                <div class="chart-row__fill" :style="chartFillStyle(chart, item)" />
              </div>
              <div class="chart-row__value">
                {{ formatNumber(item.value) }}
              </div>
            </div>
          </div>

          <div v-else class="chart-empty text-medium-emphasis mt-4">
            No data available for this slice.
          </div>
        </v-card>
      </v-col>
    </v-row>

    <v-alert v-if="error" type="error" variant="tonal" class="mt-6">
      {{ error }}
    </v-alert>

    <v-alert v-if="!loading && !packetRows.length" type="info" variant="tonal" class="mt-6">
      No {{ selectedProfile.label }} traffic recorded yet.
    </v-alert>

    <v-row class="mt-4" dense>
      <v-col cols="12" xl="8">
        <EntityTablePanel
          :title="packetTableTitle"
          :subtitle="packetTableSubtitle"
          v-model:live-enabled="liveRefreshEnabled"
          :rows="packetRows"
          :columns="packetColumns"
          :search-enabled="true"
          search-label="Search packets"
          :search-placeholder="packetSearchPlaceholder"
          :search-fields="packetSearchFields"
          :filter-definitions="packetFilterDefinitions"
          :expandable-rows="true"
          :loading="loading"
          :error="''"
          :last-updated="lastUpdated"
          :live-refresh="true"
          :page-size="30"
          :empty-text="packetEmptyText"
          :total-available="packetsMeta.totalAvailable"
          :truncated="packetsMeta.truncated"
          :range-label="timeRangeLabel"
          @refresh="load"
          @load-more="loadMore"
        >
          <template #cell-updated_at="{ value }">
            {{ formatTimestamp(value) }}
          </template>
          <template #cell-interface="{ value }">
            <v-chip size="x-small" color="info" variant="tonal">
              {{ value || "unknown" }}
            </v-chip>
          </template>
          <template #cell-direction="{ value }">
            <v-chip
              size="x-small"
              :color="directionColor(value)"
              variant="tonal"
            >
              {{ value || "unknown" }}
            </v-chip>
          </template>
          <template #cell-state="{ value }">
            <v-chip size="x-small" :color="stateColor(value)" variant="tonal">
              {{ normalizeStateLabel(value) }}
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
          <template #cell-route="{ item }">
            <span class="meta-cell">{{ buildPacketRouteSummary(item) }}</span>
          </template>
          <template #cell-signal="{ item }">
            <v-chip size="x-small" :color="signalColor" variant="tonal">
              {{ formatSignal(item) }}
            </v-chip>
          </template>
          <template #cell-summary="{ item }">
            <span class="summary-cell">{{ buildPacketSummary(item, 180) || "-" }}</span>
          </template>
        </EntityTablePanel>
      </v-col>

      <v-col cols="12" xl="4">
        <EntityTablePanel
          :title="bannerTableTitle"
          :subtitle="bannerTableSubtitle"
          v-model:live-enabled="liveRefreshEnabled"
          :rows="bannerRows"
          :columns="bannerColumns"
          :search-enabled="true"
          search-label="Search banners"
          search-placeholder="IP, port, response, summary..."
          :search-fields="bannerSearchFields"
          :filter-definitions="bannerFilterDefinitions"
          :loading="loading"
          :error="''"
          :last-updated="lastUpdated"
          :live-refresh="true"
          :page-size="18"
          :empty-text="bannerEmptyText"
          :total-available="bannersMeta.totalAvailable"
          :truncated="bannersMeta.truncated"
          :range-label="timeRangeLabel"
          @refresh="load"
          @load-more="loadMore"
        >
          <template #cell-updated_at="{ value }">
            {{ formatTimestamp(value) }}
          </template>
          <template #cell-interface="{ value }">
            <v-chip size="x-small" color="warning" variant="tonal">
              {{ value || "unknown" }}
            </v-chip>
          </template>
          <template #cell-state="{ value }">
            <v-chip size="x-small" :color="stateColor(value)" variant="tonal">
              {{ normalizeStateLabel(value) }}
            </v-chip>
          </template>
          <template #cell-src_ip="{ value }">
            <span class="mono">{{ value || "-" }}</span>
          </template>
          <template #cell-dst_ip="{ value }">
            <span class="mono">{{ value || "-" }}</span>
          </template>
          <template #cell-response_size="{ value }">
            <span class="meta-cell">{{ formatBytes(value) || "-" }}</span>
          </template>
          <template #cell-response_plain="{ item }">
            <span class="summary-cell">{{ buildResponseSummary(item, 170) || "-" }}</span>
          </template>
        </EntityTablePanel>

        <EntityTablePanel
          class="mt-4"
          :title="tagTableTitle"
          :subtitle="tagTableSubtitle"
          v-model:live-enabled="liveRefreshEnabled"
          :rows="tagRows"
          :columns="tagColumns"
          :search-enabled="true"
          search-label="Search tags"
          search-placeholder="Key, value, IP, port..."
          :search-fields="tagSearchFields"
          :filter-definitions="tagFilterDefinitions"
          :loading="loading"
          :error="''"
          :last-updated="lastUpdated"
          :live-refresh="true"
          :page-size="18"
          :empty-text="tagEmptyText"
          :total-available="tagsMeta.totalAvailable"
          :truncated="tagsMeta.truncated"
          :range-label="timeRangeLabel"
          @refresh="load"
          @load-more="loadMore"
        >
          <template #cell-updated_at="{ value }">
            {{ formatTimestamp(value) }}
          </template>
          <template #cell-ip="{ value }">
            <span class="mono">{{ value || "-" }}</span>
          </template>
          <template #cell-port="{ value }">
            <v-chip size="x-small" color="info" variant="tonal">
              {{ value || "-" }}
            </v-chip>
          </template>
          <template #cell-key="{ value }">
            <v-chip size="x-small" color="secondary" variant="tonal">
              {{ value || "-" }}
            </v-chip>
          </template>
          <template #cell-value="{ value }">
            <span class="summary-cell">{{ value || "-" }}</span>
          </template>
        </EntityTablePanel>
      </v-col>
    </v-row>
  </div>
</template>

<script>
import store from "../state/appStore";
import {
  ALL_PROTOCOLS,
  LAYERS,
  describeProtocol,
  groupByLayer,
  orderProtocolKeys,
} from "../utils/protocolCatalog";
import ViewHeader from "../components/ui/ViewHeader.vue";
import EntityTablePanel from "../components/ui/EntityTablePanel.vue";
import {
  buildPacketRouteSummary,
  buildPacketSizeSummary,
  buildPacketSummary,
  buildResponseSummary,
  formatBytes,
  formatEndpoint,
  formatTimestamp,
  normalizeProto,
} from "../utils/traffic";

// Every protocol the build knows about, not a short subset: selectedProtocol
// validates the route against this list before the first snapshot lands, so
// a name missing here makes /protocols/<name> fall back to TCP and load the
// wrong slice.
const FALLBACK_SUPPORTED_PROTOCOLS = ALL_PROTOCOLS;

const REFRESH_EVENT_TYPES = new Set(["packet", "stats_update", "runtime_mode"]);

const PROTOCOL_PROFILES = {
  tcp: {
    label: "TCP",
    description: "Inspect connection-oriented flows, flags, ports, and banners.",
    focusTitle: "Top ports",
    signalLabel: "Flags",
    icon: "mdi-ethernet",
    color: "success",
    accent: "rgba(53, 230, 177, 0.92)",
    subtitle: "Connection-oriented transport",
    tableHint: "Connection rows with response state and payload markers.",
  },
  udp: {
    label: "UDP",
    description: "Review datagrams, observed ports, and logged responses.",
    focusTitle: "Top ports",
    signalLabel: "Ports",
    icon: "mdi-lan",
    color: "info",
    accent: "rgba(74, 136, 255, 0.92)",
    subtitle: "Datagram transport",
    tableHint: "Datagram rows with lightweight state and payload hints.",
  },
  sctp: {
    label: "SCTP",
    description: "Group transport associations, ports, and related artifacts.",
    focusTitle: "Top ports",
    signalLabel: "Ports",
    icon: "mdi-lan-connect",
    color: "warning",
    accent: "rgba(243, 177, 75, 0.92)",
    subtitle: "Association transport",
    tableHint: "Multi-stream transport rows with endpoint visibility.",
  },
  icmp: {
    label: "ICMP",
    description: "Analyze ICMP types and codes for echo, error, and reachability.",
    focusTitle: "Top ICMP types",
    signalLabel: "Type / Code",
    icon: "mdi-pulse",
    color: "warning",
    accent: "rgba(243, 177, 75, 0.92)",
    subtitle: "Network control",
    tableHint: "Control packets with type, code, and reply state.",
  },
  icmpv6: {
    label: "ICMPv6",
    description: "Study IPv6 control messages and their types and codes.",
    focusTitle: "Top ICMP types",
    signalLabel: "Type / Code",
    icon: "mdi-pulse",
    color: "info",
    accent: "rgba(71, 176, 255, 0.92)",
    subtitle: "IPv6 control",
    tableHint: "IPv6 control traffic with hop visibility and type/code pairs.",
  },
  arp: {
    label: "ARP",
    description: "Check ARP requests and replies with opcode, MAC, and IP.",
    focusTitle: "Top opcodes",
    signalLabel: "Opcode",
    icon: "mdi-transit-connection-variant",
    color: "secondary",
    accent: "rgba(255, 159, 67, 0.92)",
    subtitle: "Link-layer resolution",
    tableHint: "Address resolution packets with ethernet and IPv4 fields.",
  },
  ipv6: {
    label: "IPv6",
    description: "Look at IPv6 headers, hop limits, and visible routes.",
    focusTitle: "Hop distribution",
    signalLabel: "Hop limit",
    icon: "mdi-ip-network",
    color: "primary",
    accent: "rgba(52, 230, 255, 0.92)",
    subtitle: "Network layer",
    tableHint: "Network-layer frames with hop limit and version metadata.",
  },
  unknown: {
    label: "Unknown",
    description: "Group traffic without a clear classification using generic metrics and columns.",
    focusTitle: "Top interfaces",
    signalLabel: "Generic",
    icon: "mdi-help-circle-outline",
    color: "secondary",
    accent: "rgba(151, 177, 207, 0.86)",
    subtitle: "Unclassified traffic",
    tableHint: "Generic packets that still expose IP, interface, and summary data.",
  },
  igmp: {
    label: "IGMP",
    description: "Track multicast group membership queries, reports, and leaves.",
    focusTitle: "Top groups",
    signalLabel: "Groups",
    icon: "mdi-account-group-outline",
    color: "info",
    accent: "rgba(74, 136, 255, 0.92)",
    subtitle: "Multicast membership",
    tableHint: "Membership reports with group address and source.",
  },
  mdns: {
    label: "mDNS",
    description: "Follow Bonjour service announcements and the hosts behind them.",
    focusTitle: "Top services",
    signalLabel: "Services",
    icon: "mdi-apple-finder",
    color: "info",
    accent: "rgba(122, 162, 247, 0.92)",
    subtitle: "Multicast service discovery",
    tableHint: "Advertised service names and the hosts announcing them.",
  },
  llmnr: {
    label: "LLMNR",
    description: "Watch link-local name resolution, the protocol Responder abuses.",
    focusTitle: "Top names",
    signalLabel: "Names",
    icon: "mdi-dns-outline",
    color: "warning",
    accent: "rgba(255, 184, 76, 0.92)",
    subtitle: "Link-local name resolution",
    tableHint: "Requested names and the responders that answered.",
  },
  nbns: {
    label: "NetBIOS",
    description: "Inspect legacy NetBIOS name registration and lookup traffic.",
    focusTitle: "Top names",
    signalLabel: "Names",
    icon: "mdi-microsoft-windows",
    color: "warning",
    accent: "rgba(255, 184, 76, 0.92)",
    subtitle: "Legacy Windows naming",
    tableHint: "NetBIOS names, node types, and registrations.",
  },
  dhcp: {
    label: "DHCP",
    description: "Follow address leases, and spot servers that should not be there.",
    focusTitle: "Top servers",
    signalLabel: "Message",
    icon: "mdi-ip-network-outline",
    color: "info",
    accent: "rgba(74, 136, 255, 0.92)",
    subtitle: "Address assignment",
    tableHint: "Discover/offer/request/ack exchanges per client.",
  },
  gre: {
    label: "GRE",
    description: "Examine encapsulated tunnels crossing segment boundaries.",
    focusTitle: "Top endpoints",
    signalLabel: "Tunnel",
    icon: "mdi-tunnel-outline",
    color: "warning",
    accent: "rgba(255, 184, 76, 0.92)",
    subtitle: "Tunnelled traffic",
    tableHint: "Tunnel endpoints and the protocol carried inside.",
  },
  esp: {
    label: "IPsec ESP",
    description: "Account for encrypted IPsec payloads by SPI and peer.",
    focusTitle: "Top peers",
    signalLabel: "SPI",
    icon: "mdi-lock-outline",
    color: "success",
    accent: "rgba(53, 230, 177, 0.92)",
    subtitle: "Encrypted tunnel",
    tableHint: "Security parameter index and sequence per peer.",
  },
  ah: {
    label: "IPsec AH",
    description: "Account for integrity-protected IPsec traffic.",
    focusTitle: "Top peers",
    signalLabel: "SPI",
    icon: "mdi-shield-check-outline",
    color: "success",
    accent: "rgba(53, 230, 177, 0.92)",
    subtitle: "Authenticated tunnel",
    tableHint: "Security parameter index and sequence per peer.",
  },
  stp: {
    label: "STP",
    description: "Review spanning-tree BPDUs and watch for topology takeovers.",
    focusTitle: "Top bridges",
    signalLabel: "BPDU",
    icon: "mdi-lan-pending",
    color: "secondary",
    accent: "rgba(151, 177, 207, 0.86)",
    subtitle: "Layer 2 topology",
    tableHint: "Bridge identifiers, priorities, and port roles.",
  },
  llc: {
    label: "LLC",
    description: "Decode IEEE 802.2 frames by DSAP/SSAP and control field.",
    focusTitle: "Top SAPs",
    signalLabel: "DSAP",
    icon: "mdi-layers-outline",
    color: "secondary",
    accent: "rgba(151, 177, 207, 0.86)",
    subtitle: "IEEE 802.2 encapsulation",
    tableHint: "Service access points and the protocol they carry.",
  },
  "llc-snap": {
    label: "LLC/SNAP",
    description: "Decode SNAP-encapsulated frames and the protocol inside.",
    focusTitle: "Top protocols",
    signalLabel: "OUI",
    icon: "mdi-layers-triple-outline",
    color: "secondary",
    accent: "rgba(151, 177, 207, 0.86)",
    subtitle: "SNAP encapsulation",
    tableHint: "Organisation identifier and encapsulated EtherType.",
  },
  rarp: {
    label: "RARP",
    description: "Spot reverse ARP, obsolete since BOOTP and rare in the wild.",
    focusTitle: "Top hosts",
    signalLabel: "Opcode",
    icon: "mdi-swap-horizontal",
    color: "warning",
    accent: "rgba(255, 184, 76, 0.92)",
    subtitle: "Reverse address resolution",
    tableHint: "Requests, replies, and the hardware addresses involved.",
  },
  modbus: {
    label: "Modbus",
    description: "Inspect industrial reads and writes against PLC registers.",
    focusTitle: "Top units",
    signalLabel: "Function",
    icon: "mdi-factory",
    color: "error",
    accent: "rgba(255, 107, 129, 0.92)",
    subtitle: "Industrial control",
    tableHint: "Function codes, unit identifiers, and register ranges.",
  },
  dnp3: {
    label: "DNP3",
    description: "Inspect SCADA outstation polling, controls, and unsolicited reports.",
    focusTitle: "Top outstations",
    signalLabel: "Function",
    icon: "mdi-transmission-tower",
    color: "error",
    accent: "rgba(255, 107, 129, 0.92)",
    subtitle: "Industrial control",
    tableHint: "Application function codes and outstation addresses.",
  },
  snmp: {
    label: "SNMP",
    description: "Review management queries, traps, and the community strings used.",
    focusTitle: "Top agents",
    signalLabel: "Community",
    icon: "mdi-router-network",
    color: "warning",
    accent: "rgba(255, 184, 76, 0.92)",
    subtitle: "Device management",
    tableHint: "Versions, community strings, and requested OIDs.",
  },
  syslog: {
    label: "Syslog",
    description: "Read forwarded log messages and their facility and severity.",
    focusTitle: "Top senders",
    signalLabel: "Severity",
    icon: "mdi-text-box-outline",
    color: "info",
    accent: "rgba(74, 136, 255, 0.92)",
    subtitle: "Log forwarding",
    tableHint: "Facility, severity, and message text per sender.",
  },
  tftp: {
    label: "TFTP",
    description: "Track unauthenticated file transfers, often firmware or configs.",
    focusTitle: "Top files",
    signalLabel: "Opcode",
    icon: "mdi-file-download-outline",
    color: "error",
    accent: "rgba(255, 107, 129, 0.92)",
    subtitle: "Unauthenticated transfer",
    tableHint: "Requested filenames, transfer modes, and directions.",
  },
  radius: {
    label: "RADIUS",
    description: "Follow network authentication requests and their outcomes.",
    focusTitle: "Top clients",
    signalLabel: "Code",
    icon: "mdi-account-key-outline",
    color: "warning",
    accent: "rgba(255, 184, 76, 0.92)",
    subtitle: "Network authentication",
    tableHint: "Access requests, accepts, rejects, and usernames.",
  },
  mqtt: {
    label: "MQTT",
    description: "Inspect IoT publish/subscribe traffic and cleartext credentials.",
    focusTitle: "Top topics",
    signalLabel: "Packet type",
    icon: "mdi-access-point",
    color: "warning",
    accent: "rgba(255, 184, 76, 0.92)",
    subtitle: "IoT messaging",
    tableHint: "Connect, publish, and subscribe packets per topic.",
  },
  unparseable: {
    label: "Unparseable",
    description: "Frames that could not be decoded at all, kept rather than dropped.",
    focusTitle: "Top interfaces",
    signalLabel: "Reason",
    icon: "mdi-alert-octagon-outline",
    color: "error",
    accent: "rgba(255, 107, 129, 0.92)",
    subtitle: "Malformed frames",
    tableHint: "Frame length and the reason decoding failed.",
  },
  default: {
    label: "Traffic",
    description: "Inspect protocol-specific traffic patterns.",
    focusTitle: "Focus",
    signalLabel: "Signal",
    icon: "mdi-radar",
    color: "info",
    accent: "rgba(74, 136, 255, 0.92)",
    subtitle: "Protocol slice",
    tableHint: "Traffic rows with generic frame details.",
  },
};

function profileFor(proto) {
  const known = PROTOCOL_PROFILES[proto];
  if (known) return known;
  // Derive a name from the protocol itself rather than reusing the generic
  // "Traffic" label: every protocol without a profile used to render an
  // identically-titled card, so a capture carrying both IGMP and mDNS showed
  // two cards called "Traffic" and no way to tell which was which.
  const label = String(proto || "unknown").toUpperCase();
  return {
    ...PROTOCOL_PROFILES.default,
    label,
    description: `Inspect ${label} frames, endpoints, and payload details.`,
  };
}

function normalizeProtocolKey(value) {
  const proto = normalizeProto(value);
  if (proto === "stcp") return "sctp";
  return proto || "unknown";
}

function orderProtocols(values) {
  const unique = new Set(FALLBACK_SUPPORTED_PROTOCOLS);
  (Array.isArray(values) ? values : []).forEach((value) => {
    const proto = normalizeProtocolKey(value);
    if (proto) {
      unique.add(proto);
    }
  });
  return orderProtocolKeys([...unique]);
}

function buildCountSeries(rows, selector, { labelPrefix = "", ignoreZero = false, limit = 6 } = {}) {
  const counts = new Map();
  (Array.isArray(rows) ? rows : []).forEach((row) => {
    const raw = typeof selector === "function" ? selector(row) : null;
    const values = Array.isArray(raw) ? raw : [raw];
    values.forEach((value) => {
      const text = String(value == null ? "" : value).trim();
      if (!text) return;
      if (ignoreZero && Number(text) === 0) return;
      const label = labelPrefix ? `${labelPrefix} ${text}` : text;
      counts.set(label, (counts.get(label) || 0) + 1);
    });
  });
  const ordered = [...counts.entries()]
    .map(([label, value]) => ({ label, value }))
    .sort((left, right) => right.value - left.value || left.label.localeCompare(right.label));
  const trimmed = ordered.slice(0, limit);
  const maxValue = trimmed.length ? Math.max(...trimmed.map((item) => item.value)) : 0;
  return trimmed.map((item) => ({
    ...item,
    width: maxValue > 0 ? Math.max(10, Math.round((item.value / maxValue) * 100)) : 0,
  }));
}

function buildStateSeries(rows) {
  const buckets = {
    open: 0,
    filtered: 0,
    closed: 0,
    other: 0,
  };
  (Array.isArray(rows) ? rows : []).forEach((row) => {
    const state = String(row && row.state ? row.state : "").trim().toLowerCase();
    if (Object.prototype.hasOwnProperty.call(buckets, state)) {
      buckets[state] += 1;
      return;
    }
    buckets.other += 1;
  });
  const ordered = [
    { label: "open", value: buckets.open },
    { label: "filtered", value: buckets.filtered },
    { label: "closed", value: buckets.closed },
    { label: "other", value: buckets.other },
  ].filter((item) => item.value > 0);
  const maxValue = ordered.length ? Math.max(...ordered.map((item) => item.value)) : 0;
  return ordered.map((item) => ({
    ...item,
    width: maxValue > 0 ? Math.max(10, Math.round((item.value / maxValue) * 100)) : 0,
  }));
}

function buildTimelineSeries(rows) {
  const buckets = new Map();
  (Array.isArray(rows) ? rows : []).forEach((row) => {
    const created = String((row && row.created_at) || (row && row.updated_at) || "").trim();
    if (!created) return;
    const key = created.slice(0, 10);
    if (!key) return;
    buckets.set(key, (buckets.get(key) || 0) + 1);
  });
  const ordered = [...buckets.entries()]
    .sort((left, right) => left[0].localeCompare(right[0]))
    .slice(-8)
    .map(([label, value]) => ({
      label,
      value,
    }));
  const maxValue = ordered.length ? Math.max(...ordered.map((item) => item.value)) : 0;
  return ordered.map((item) => ({
    ...item,
    width: maxValue > 0 ? Math.max(10, Math.round((item.value / maxValue) * 100)) : 0,
  }));
}

function formatDayLabel(value) {
  const text = String(value || "").trim();
  if (!text) return "-";
  const date = new Date(`${text}T00:00:00`);
  if (Number.isNaN(date.getTime())) return text;
  return date.toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

function uniqueEndpointSet(rows) {
  const endpoints = new Set();
  (Array.isArray(rows) ? rows : []).forEach((row) => {
    const src = formatEndpoint(row && row.src_ip, row && row.src_port);
    const dst = formatEndpoint(row && row.dst_ip, row && row.dst_port);
    if (src && src !== "-") endpoints.add(src);
    if (dst && dst !== "-") endpoints.add(dst);
  });
  return endpoints;
}

export default {
  name: "ProtocolsView",
  components: {
    ViewHeader,
    EntityTablePanel,
  },
  data() {
    return {
      store,
      loading: false,
      error: "",
      lastUpdated: "",
      liveRefreshEnabled: true,
      protocolCatalog: [],
      snapshot: {},
      showEmptyProtocols: false,
      packetRows: [],
      bannerRows: [],
      tagRows: [],
      packetLimit: 500,
      bannerLimit: 250,
      tagLimit: 250,
      packetsMeta: { totalAvailable: null, returned: null, truncated: null },
      bannersMeta: { totalAvailable: null, returned: null, truncated: null },
      tagsMeta: { totalAvailable: null, returned: null, truncated: null },
      wsRefreshTimer: null,
      stopTableRefreshSubscription: null,
    };
  },
  computed: {
    apiBase() {
      return this.store.state.apiBase;
    },
    timeRangeLabel() {
      return this.store.timeRangeLabel();
    },
    supportedProtocols() {
      const catalog = Array.isArray(this.snapshot.catalog) ? this.snapshot.catalog : [];
      const names = catalog.length
        ? catalog.map((item) => normalizeProtocolKey(item && item.protocol)).filter(Boolean)
        : this.protocolCatalog;
      return orderProtocols(names);
    },
    selectedProtocol() {
      const routeProto = normalizeProtocolKey(this.$route && this.$route.params ? this.$route.params.proto : "");
      if (routeProto && this.supportedProtocols.includes(routeProto)) {
        return routeProto;
      }
      return this.supportedProtocols[0] || "unknown";
    },
    selectedProfile() {
      const described = describeProtocol(this.selectedProtocol);
      const layer = LAYERS.find((item) => item.key === described.layer) || {};
      return { ...profileFor(this.selectedProtocol), ...described, layerLabel: layer.label || "" };
    },
    // {protocol: frame count} straight from the snapshot's catalog, which is
    // grouped over the whole slice - the old source (analytics.ports_by_proto)
    // was a truncated top-N list, so protocols outside it showed a count of 0.
    protocolCountMap() {
      const catalog = Array.isArray(this.snapshot.catalog) ? this.snapshot.catalog : [];
      return catalog.reduce((acc, item) => {
        const proto = normalizeProtocolKey(item && item.protocol);
        if (proto) acc[proto] = Number((item && item.count) || 0);
        return acc;
      }, {});
    },
    protocolCards() {
      return this.supportedProtocols.map((proto) => ({
        ...describeProtocol(proto),
        count: this.protocolCountMap[proto] || 0,
      }));
    },
    // The rail is grouped by layer so a hundred protocols read as a stack
    // rather than as one flat wall of chips. Layers with no traffic collapse
    // away unless the operator is looking at one of their protocols.
    protocolLayers() {
      const cards = this.protocolCards;
      const active = this.selectedProtocol;
      return groupByLayer(cards)
        .map((layer) => ({
          ...layer,
          protocols: layer.protocols.filter(
            (item) => item.count > 0 || item.key === active || this.showEmptyProtocols
          ),
          total: layer.protocols.reduce((sum, item) => sum + Number(item.count || 0), 0),
          seen: layer.protocols.filter((item) => item.count > 0).length,
        }))
        .filter((layer) => layer.protocols.length > 0);
    },
    packetColumns() {
      return [
        { key: "updated_at", label: "Seen" },
        { key: "interface", label: "Interface" },
        { key: "direction", label: "Direction" },
        { key: "state", label: "State" },
        { key: "src_ip", label: "Src IP" },
        { key: "src_port", label: "Src Port" },
        { key: "dst_ip", label: "Dst IP" },
        { key: "dst_port", label: "Dst Port" },
        { key: "size", label: "Size" },
        { key: "route", label: "Network" },
        { key: "signal", label: this.selectedProfile.signalLabel, sortable: false },
        { key: "summary", label: "Summary", sortable: false },
      ];
    },
    packetSearchFields() {
      return [
        "updated_at",
        "interface",
        "direction",
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
        "arp_opcode",
        "ip_version",
        "ttl",
        "hop_limit",
      ];
    },
    packetFilterDefinitions() {
      return [
        {
          key: "state",
          label: "State",
          field: "state",
        },
        {
          key: "direction",
          label: "Direction",
          field: "direction",
        },
        {
          key: "interface",
          label: "Interface",
          field: "interface",
        },
      ];
    },
    bannerColumns() {
      return [
        { key: "updated_at", label: "Seen" },
        { key: "interface", label: "Interface" },
        { key: "state", label: "State" },
        { key: "src_ip", label: "Src IP" },
        { key: "src_port", label: "Src Port" },
        { key: "dst_ip", label: "Dst IP" },
        { key: "dst_port", label: "Dst Port" },
        { key: "response_size", label: "Size" },
        { key: "response_plain", label: "Response", sortable: false },
      ];
    },
    bannerSearchFields() {
      return [
        "updated_at",
        "interface",
        "state",
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "response_size",
        "response_plain",
        "summary",
        "flow_key",
      ];
    },
    bannerFilterDefinitions() {
      return [
        {
          key: "state",
          label: "State",
          field: "state",
        },
        {
          key: "interface",
          label: "Interface",
          field: "interface",
        },
      ];
    },
    tagColumns() {
      return [
        { key: "updated_at", label: "Seen" },
        { key: "ip", label: "IP" },
        { key: "port", label: "Port" },
        { key: "key", label: "Key" },
        { key: "value", label: "Value", sortable: false },
      ];
    },
    tagSearchFields() {
      return ["updated_at", "ip", "port", "proto", "key", "value"];
    },
    tagFilterDefinitions() {
      return [
        {
          key: "key",
          label: "Key",
          field: "key",
        },
      ];
    },
    packetTableTitle() {
      return `${this.selectedProfile.label} Packets`;
    },
    packetTableSubtitle() {
      return this.selectedProfile.tableHint;
    },
    packetSearchPlaceholder() {
      return `${this.selectedProfile.label}, IP, port, summary...`;
    },
    packetEmptyText() {
      return `No ${this.selectedProfile.label} packet rows available`;
    },
    bannerTableTitle() {
      return `${this.selectedProfile.label} Banners`;
    },
    bannerTableSubtitle() {
      return `Decoded response payloads for ${this.selectedProfile.label}.`;
    },
    bannerEmptyText() {
      return `No ${this.selectedProfile.label} banners available`;
    },
    tagTableTitle() {
      return `${this.selectedProfile.label} Tags`;
    },
    tagTableSubtitle() {
      return `Parsed tags and labels for ${this.selectedProfile.label}.`;
    },
    tagEmptyText() {
      return `No ${this.selectedProfile.label} tags available`;
    },
    averageFrameSize() {
      if (!this.packetRows.length) return 0;
      const total = this.packetRows.reduce((sum, row) => sum + Number(row.length || 0), 0);
      return total / this.packetRows.length;
    },
    uniqueEndpointCount() {
      return uniqueEndpointSet(this.packetRows).size;
    },
    stateSeries() {
      return buildStateSeries(this.packetRows);
    },
    focusSeries() {
      const proto = this.selectedProtocol;
      if (proto === "tcp" || proto === "udp" || proto === "sctp") {
        return buildCountSeries(
          this.packetRows,
          (row) => {
            const dstPort = Number(row && row.dst_port ? row.dst_port : 0);
            const srcPort = Number(row && row.src_port ? row.src_port : 0);
            return dstPort || srcPort || 0;
          },
          { labelPrefix: "Port", ignoreZero: true, limit: 6 }
        );
      }
      if (proto === "icmp" || proto === "icmpv6") {
        return buildCountSeries(
          this.packetRows,
          (row) => {
            const type = Number(row && row.icmp_type != null ? row.icmp_type : 0);
            const code = Number(row && row.icmp_code ? row.icmp_code : 0);
            return `${type}${code ? `:${code}` : ""}`;
          },
          {
            labelPrefix: "Type",
            ignoreZero: false,
            limit: 6,
          }
        );
      }
      if (proto === "arp") {
        return buildCountSeries(
          this.packetRows,
          (row) => Number(row && row.arp_opcode ? row.arp_opcode : 0),
          { labelPrefix: "Opcode", ignoreZero: true, limit: 6 }
        );
      }
      if (proto === "ipv6") {
        return buildCountSeries(
          this.packetRows,
          (row) => Number(row && row.hop_limit ? row.hop_limit : 0),
          { labelPrefix: "Hop", ignoreZero: true, limit: 6 }
        );
      }
      const hasPorts = this.packetRows.some((row) => Number(row && (row.dst_port || row.src_port || 0)) > 0);
      if (hasPorts) {
        return buildCountSeries(
          this.packetRows,
          (row) => {
            const dstPort = Number(row && row.dst_port ? row.dst_port : 0);
            const srcPort = Number(row && row.src_port ? row.src_port : 0);
            return dstPort || srcPort || 0;
          },
          { labelPrefix: "Port", ignoreZero: true, limit: 6 }
        );
      }
      return buildCountSeries(
        this.packetRows,
        (row) => String(row && row.interface ? row.interface : "unknown").trim() || "unknown",
        { limit: 6 }
      );
    },
    timelineSeries() {
      return buildTimelineSeries(this.packetRows).map((item) => ({
        ...item,
        label: formatDayLabel(item.label),
      }));
    },
    // Rendered straight from the snapshot's facets: which columns carry
    // signal is decided per protocol by sniff4hound/protocol_facets.py, and
    // the counts are grouped over the whole slice rather than recomputed in
    // the browser from a truncated page of rows.
    chartPanels() {
      const facets = Array.isArray(this.snapshot.facets) ? this.snapshot.facets : [];
      const panels = facets.map((facet) => ({
        key: facet.key,
        title: facet.title,
        subtitle: facet.subtitle,
        color: this.selectedProfile.color,
        fill: `linear-gradient(90deg, ${this.selectedProfile.accent || "rgba(74, 136, 255, 0.92)"}, rgba(255, 255, 255, 0.12))`,
        series: (facet.series || []).map((item) => ({ label: item.label, value: item.count })),
      }));
      panels.push({
        key: "timeline",
        title: "Activity timeline",
        subtitle: "Frames per hour across the selected range.",
        color: "secondary",
        fill: "linear-gradient(90deg, rgba(255, 159, 67, 0.92), rgba(243, 177, 75, 0.78))",
        series: (Array.isArray(this.snapshot.timeline) ? this.snapshot.timeline : []).map((item) => ({
          label: String(item.label || "").replace("T", " ") + ":00",
          value: item.count,
        })),
      });
      return panels;
    },
    signalColor() {
      return this.selectedProfile.color || "primary";
    },
    // Counters describing the whole slice, aggregated server-side. The old
    // set (frames/open/filtered/other) was identical for all 105 protocols
    // and said nothing about any of them: "open vs filtered" is a port-scan
    // notion that means nothing for ARP, STP or DHCP.
    metricCards() {
      const totals = this.snapshot.totals || {};
      const cards = [
        {
          key: "frames",
          label: "Frames",
          value: this.formatNumber(totals.frames || 0),
          caption: `Every ${this.selectedProfile.label} frame in range.`,
          icon: this.selectedProfile.icon,
          colorClass: "text-primary",
        },
        {
          key: "sources",
          label: "Sources",
          value: this.formatNumber(totals.unique_sources || 0),
          caption: "Distinct addresses emitting this protocol.",
          icon: "mdi-account-arrow-right",
          colorClass: "text-info",
        },
        {
          key: "destinations",
          label: "Destinations",
          value: this.formatNumber(totals.unique_destinations || 0),
          caption: "Distinct addresses being addressed.",
          icon: "mdi-account-arrow-left",
          colorClass: "text-success",
        },
        {
          key: "conversations",
          label: "Conversations",
          value: this.formatNumber(totals.unique_flows || 0),
          caption: "Distinct flows in this slice.",
          icon: "mdi-swap-horizontal",
          colorClass: "text-secondary",
        },
        {
          key: "volume",
          label: "Volume",
          value: this.formatHumanBytes(totals.bytes_total || 0),
          caption: `Average frame ${this.formatHumanBytes(totals.bytes_avg || 0)}.`,
          icon: "mdi-database",
          colorClass: "text-warning",
        },
      ];
      // Banners only exist for protocols that actually answer with one, so
      // the tile is dropped rather than shown as a permanent zero.
      if (this.bannerRows.length) {
        cards.push({
          key: "banners",
          label: "Banners",
          value: this.formatNumber(this.bannerRows.length),
          caption: "Decoded replies in this slice.",
          icon: "mdi-message-text",
          colorClass: "text-info",
        });
      }
      return cards;
    },
    heroStyle() {
      return {
        "--protocol-accent": this.selectedProfile.accent,
      };
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
    "$route.params.proto"() {
      this.load();
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
    buildPacketRouteSummary,
    buildPacketSizeSummary,
    buildPacketSummary,
    buildResponseSummary,
    formatBytes,
    formatEndpoint,
    formatTimestamp,
    formatNumber(value) {
      const numeric = Number(value || 0);
      if (!Number.isFinite(numeric)) return "0";
      return numeric.toLocaleString();
    },
    formatHumanBytes(value) {
      const numeric = Number(value || 0);
      if (!Number.isFinite(numeric) || numeric <= 0) return "0 B";
      const units = ["B", "KB", "MB", "GB"];
      let size = numeric;
      let unitIndex = 0;
      while (size >= 1024 && unitIndex < units.length - 1) {
        size /= 1024;
        unitIndex += 1;
      }
      const rounded = size >= 10 || unitIndex === 0 ? Math.round(size) : Number(size.toFixed(1));
      return `${rounded} ${units[unitIndex]}`;
    },
    normalizeStateLabel(value) {
      const raw = String(value || "unknown").trim().toLowerCase();
      if (!raw) return "unknown";
      if (raw === "restarting") return "restarting";
      if (raw === "stopped") return "stopped";
      if (raw === "blocked") return "blocked";
      return raw;
    },
    stateColor(value) {
      const state = this.normalizeStateLabel(value);
      if (state === "open") return "success";
      if (state === "filtered") return "warning";
      if (state === "closed") return "error";
      if (state === "blocked") return "error";
      if (state === "restarting") return "info";
      if (state === "stopped") return "warning";
      return "secondary";
    },
    directionColor(value) {
      const direction = String(value || "").trim().toLowerCase();
      if (direction === "inbound") return "warning";
      if (direction === "outbound") return "success";
      return "info";
    },
    protocolRoute(proto) {
      const normalized = normalizeProtocolKey(proto);
      return `/protocols/${encodeURIComponent(normalized)}`;
    },
    isSelectedProtocol(proto) {
      return normalizeProtocolKey(proto) === this.selectedProtocol;
    },
    formatSignal(row) {
      const proto = this.selectedProtocol;
      if (!row || typeof row !== "object") return "-";
      if (proto === "tcp") {
        const flags = String(row.tcp_flags || "").trim();
        if (flags) return flags;
        const srcPort = Number(row.src_port || 0);
        const dstPort = Number(row.dst_port || 0);
        if (srcPort || dstPort) return `${srcPort || "?"} → ${dstPort || "?"}`;
        return "-";
      }
      if (proto === "udp" || proto === "sctp") {
        const srcPort = Number(row.src_port || 0);
        const dstPort = Number(row.dst_port || 0);
        if (srcPort || dstPort) return `${srcPort || "?"} → ${dstPort || "?"}`;
        return "-";
      }
      if (proto === "icmp" || proto === "icmpv6") {
        const type = Number(row.icmp_type || 0);
        const code = Number(row.icmp_code || 0);
        return `type ${type}${code ? ` / code ${code}` : ""}`;
      }
      if (proto === "arp") {
        const opcode = Number(row.arp_opcode || 0);
        return opcode ? `opcode ${opcode}` : "-";
      }
      if (proto === "ipv6") {
        const hop = Number(row.hop_limit || 0);
        if (hop) return `hop ${hop}`;
        const version = Number(row.ip_version || 0);
        return version ? `IPv${version}` : "-";
      }
      const parts = [];
      const version = Number(row.ip_version || 0);
      const hop = Number(row.hop_limit || 0);
      const ttl = Number(row.ttl || 0);
      const flags = String(row.tcp_flags || "").trim();
      if (version) parts.push(`IPv${version}`);
      if (hop) parts.push(`hop ${hop}`);
      if (ttl) parts.push(`ttl ${ttl}`);
      if (flags) parts.push(flags);
      return parts.join(" · ") || "generic";
    },
    chartFillStyle(chart, item) {
      return {
        width: `${item.width}%`,
        background: chart.fill,
      };
    },
    handleWsRefresh(event) {
      if (!this.liveRefreshEnabled) return;
      const eventType = String((event && event.type) || "").trim().toLowerCase();
      if (!REFRESH_EVENT_TYPES.has(eventType)) return;
      if (this.wsRefreshTimer) return;
      this.wsRefreshTimer = setTimeout(() => {
        this.wsRefreshTimer = null;
        this.load({ silent: true }).catch(() => {
          // Keep current slice on transient refresh errors.
        });
      }, 10000);
    },
    loadMore() {
      this.packetLimit = Math.min(this.packetLimit + 1000, 20000);
      this.bannerLimit = Math.min(this.bannerLimit + 500, 20000);
      this.tagLimit = Math.min(this.tagLimit + 500, 20000);
      this.load({ silent: true }).catch(() => null);
    },
    async load(options = {}) {
      if (!options.silent) this.loading = true;
      this.error = "";
      try {

        const errors = [];
        const selectedProto = this.selectedProtocol;
        // One request for the whole slice. Packets, banners, tags, the
        // per-protocol facets and the counters all come from
        // /api/protocols/snapshot/, where the counters are aggregated over
        // the entire filtered set instead of over the page of rows the
        // browser happened to receive.
        const [snapshotRes] = await Promise.allSettled([
          this.store.fetchProtocolSnapshot({ proto: selectedProto, limit: this.packetLimit }),
        ]);
        const packetsRes = snapshotRes.status === "fulfilled"
          ? { status: "fulfilled", value: { rows: snapshotRes.value.packets || [], meta: { totalAvailable: (snapshotRes.value.totals || {}).frames ?? null, returned: (snapshotRes.value.packets || []).length, truncated: null } } }
          : snapshotRes;
        const bannersRes = snapshotRes.status === "fulfilled"
          ? { status: "fulfilled", value: { rows: snapshotRes.value.banners || [], meta: { totalAvailable: null, returned: (snapshotRes.value.banners || []).length, truncated: null } } }
          : snapshotRes;
        const tagsRes = snapshotRes.status === "fulfilled"
          ? { status: "fulfilled", value: { rows: snapshotRes.value.tags || [], meta: { totalAvailable: null, returned: (snapshotRes.value.tags || []).length, truncated: null } } }
          : snapshotRes;
        this.snapshot = snapshotRes.status === "fulfilled" ? snapshotRes.value || {} : {};

        if (packetsRes.status === "fulfilled") {
          this.packetRows = packetsRes.value.rows;
          this.packetsMeta = packetsRes.value.meta;
        } else {
          this.packetRows = [];
          this.packetsMeta = { totalAvailable: null, returned: null, truncated: null };
          errors.push((packetsRes.reason && packetsRes.reason.message) || `Failed to load ${selectedProto} packets`);
        }

        if (bannersRes.status === "fulfilled") {
          this.bannerRows = bannersRes.value.rows;
          this.bannersMeta = bannersRes.value.meta;
        } else {
          this.bannerRows = [];
          this.bannersMeta = { totalAvailable: null, returned: null, truncated: null };
          errors.push((bannersRes.reason && bannersRes.reason.message) || `Failed to load ${selectedProto} banners`);
        }

        if (tagsRes.status === "fulfilled") {
          this.tagRows = tagsRes.value.rows;
          this.tagsMeta = tagsRes.value.meta;
        } else {
          this.tagRows = [];
          this.tagsMeta = { totalAvailable: null, returned: null, truncated: null };
          errors.push((tagsRes.reason && tagsRes.reason.message) || `Failed to load ${selectedProto} tags`);
        }

        this.lastUpdated = new Date().toLocaleTimeString();
        this.error = errors.join(" | ");
      } catch (err) {
        this.protocolCatalog = orderProtocols(FALLBACK_SUPPORTED_PROTOCOLS);
        this.snapshot = {};
        this.packetRows = [];
        this.bannerRows = [];
        this.tagRows = [];
        this.lastUpdated = "";
        this.error = (err && err.message) || "Failed to load protocol view";
      } finally {
        this.loading = false;
      }
    },
  },
};
</script>

<style scoped>
.protocols-view {
  position: relative;
}

.protocol-hero {
  position: relative;
  overflow: hidden;
  border: 1px solid rgba(96, 177, 223, 0.24);
  background:
    linear-gradient(145deg, rgba(12, 21, 32, 0.96), rgba(9, 16, 25, 0.92));
}

.protocol-hero__title {
  margin: 10px 0 0;
  font-size: clamp(2rem, 4vw, 3.25rem);
  line-height: 1;
}

.protocol-hero__copy {
  max-width: 72ch;
  margin: 14px 0 0;
  color: rgba(217, 229, 243, 0.82);
  line-height: 1.65;
}

.protocol-hero__chips {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-top: 18px;
}

.protocol-hero__panel {
  position: relative;
  padding: 18px 18px 16px;
  border: 1px solid rgba(104, 184, 229, 0.18);
  border-radius: 20px;
  background: linear-gradient(180deg, rgba(8, 15, 24, 0.76), rgba(7, 13, 21, 0.9));
  backdrop-filter: blur(10px);
}

.protocol-hero__panel-kicker {
  color: rgba(120, 220, 255, 0.92);
  font-size: 0.72rem;
  font-weight: 700;
  letter-spacing: 0.16em;
  text-transform: uppercase;
}

.protocol-hero__panel-title {
  margin-top: 10px;
  font-family: var(--font-heading);
  font-size: 1.5rem;
  line-height: 1.08;
}

.protocol-hero__stats {
  display: grid;
  gap: 10px;
  margin-top: 16px;
}

.protocol-hero__stat {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 10px 12px;
  border-radius: 14px;
  background: rgba(4, 10, 18, 0.42);
}

.protocol-hero__stat span {
  color: rgba(171, 194, 216, 0.78);
  font-size: 0.8rem;
}

.protocol-hero__stat strong {
  font-family: var(--font-mono);
  font-size: 0.88rem;
  font-weight: 700;
}

.protocol-layer__head {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
  margin-bottom: 10px;
}

.protocol-layer__count {
  margin-left: auto;
  font-variant-numeric: tabular-nums;
}

.protocol-card--idle {
  opacity: 0.55;
}

.protocol-rail {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
  gap: 12px;
}

.protocol-card {
  min-height: 170px;
  border: 1px solid rgba(104, 184, 229, 0.18);
  text-decoration: none;
}

.protocol-card:hover {
  border-color: rgba(120, 198, 237, 0.36);
  transform: translateY(-2px);
}

.protocol-card--active {
  border-color: rgba(52, 230, 255, 0.56);
  box-shadow: 0 18px 34px rgba(3, 8, 15, 0.42);
}

.protocol-card__top {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}

.protocol-card__avatar {
  color: #eff9ff;
}

.protocol-card__copy {
  min-height: 4.2em;
}

.metric-card {
  border-radius: 16px;
}

.metric-icon {
  opacity: 0.92;
}

.chart-card {
  border-radius: 16px;
}

.chart-stack {
  display: grid;
  gap: 10px;
}

.chart-row {
  display: grid;
  grid-template-columns: minmax(74px, 1.1fr) minmax(0, 2.8fr) auto;
  align-items: center;
  gap: 10px;
}

.chart-row__label {
  overflow: hidden;
  white-space: nowrap;
  text-overflow: ellipsis;
  color: rgba(205, 221, 236, 0.86);
  font-size: 0.86rem;
}

.chart-row__track {
  position: relative;
  height: 10px;
  overflow: hidden;
  border-radius: 999px;
  background: rgba(9, 16, 24, 0.86);
  box-shadow: inset 0 0 0 1px rgba(103, 176, 219, 0.08);
}

.chart-row__fill {
  height: 100%;
  border-radius: inherit;
}

.chart-row__value {
  min-width: 3ch;
  text-align: right;
  color: rgba(229, 241, 252, 0.92);
  font-family: var(--font-mono);
  font-size: 0.82rem;
}

.chart-empty {
  padding: 16px 0 4px;
  font-size: 0.92rem;
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
  width: 180px;
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

@media (max-width: 1264px) {
  .protocol-hero__panel {
    margin-top: 8px;
  }
}

@media (max-width: 959px) {
  .chart-row {
    grid-template-columns: minmax(64px, 1fr) minmax(0, 2.2fr) auto;
  }

  .summary-cell {
    max-width: 320px;
  }
}
</style>
