<template>
  <div>
    <ViewHeader
      overline="Configuration"
      title="Settings"
      description="Everything that changes how Sniff4Hound behaves lives here. Other views stay read-only: tables, charts, and live feeds."
      :show-refresh="false"
    />

    <v-tabs v-model="activeTab" color="primary" class="settings-tabs mb-6" grow>
      <v-tab value="capture">
        <v-icon icon="mdi-lan" start />
        Capture
      </v-tab>
      <v-tab value="honeypot">
        <v-icon icon="mdi-spider-web" start />
        Honeypot
      </v-tab>
      <v-tab value="detection">
        <v-icon icon="mdi-target-account" start />
        Detection
      </v-tab>
      <v-tab value="blacklist">
        <v-icon icon="mdi-cancel" start />
        Blacklist
      </v-tab>
      <v-tab value="notifications">
        <v-icon icon="mdi-bell-outline" start />
        Notifications
      </v-tab>
    </v-tabs>

    <v-window v-model="activeTab">
      <v-window-item value="capture">
        <DataPanel
          title="Capture Interfaces"
          subtitle="Select one or more interfaces to listen on. Leave it empty to sniff every visible interface."
          variant="tonal"
          :count="selectedSnifferInterfaces.length || snifferInterfaceOptions.length"
          count-label="interfaces"
          class="mb-4 interface-card"
        >
          <template #header-actions>
            <v-chip
              size="small"
              :color="snifferBlocked ? 'error' : 'info'"
              variant="outlined"
              :prepend-icon="snifferBlocked ? 'mdi-alert-circle-outline' : 'mdi-lan-check'"
            >
              {{ selectedInterfacesLabel }}
            </v-chip>
          </template>

          <v-row dense class="mt-2">
            <v-col cols="12" md="8">
              <v-select
                :model-value="selectedSnifferInterfaces"
                :items="snifferInterfaceOptions"
                label="Interfaces"
                item-title="label"
                item-value="value"
                variant="outlined"
                density="comfortable"
                hide-details="auto"
                multiple
                chips
                clearable
                closable-chips
                :loading="interfaceSubmitting"
                :disabled="!snifferInterfaceOptions.length"
                :error-messages="interfaceError ? [interfaceError] : []"
                @update:model-value="updateSnifferInterfaces"
              />
            </v-col>
            <v-col cols="12" md="4">
              <div class="interface-status">
                {{ snifferInterfaceStatus }}
              </div>
              <div class="text-caption text-medium-emphasis mt-2">
                {{ snifferInterfaceHint }}
              </div>
            </v-col>
          </v-row>
        </DataPanel>

        <DataPanel
          title="Detection scope"
          subtitle="Ignore traffic that stays entirely inside the selected scopes. Excluded packets are not classified, not tagged, not run through monitors or anomaly detectors, and never stored - not even with store-all-traffic on. They still count toward the packets-seen totals."
          variant="tonal"
          class="mb-4 scope-card"
        >
          <template #header-actions>
            <v-chip
              size="small"
              :color="detectionScopes.length ? 'warning' : 'success'"
              variant="tonal"
              :prepend-icon="detectionScopes.length ? 'mdi-filter-off-outline' : 'mdi-filter-check-outline'"
            >
              {{ detectionScopes.length ? `${detectionScopes.length} muted` : "Detecting everything" }}
            </v-chip>
          </template>

          <v-row dense class="mt-1" align="start">
            <v-col cols="12" md="7">
              <div class="d-flex flex-wrap ga-2">
                <v-checkbox
                  v-for="scope in detectionScopeOptions"
                  :key="scope.value"
                  :model-value="detectionScopes.includes(scope.value)"
                  :label="scope.label"
                  :disabled="detectionScopesSubmitting"
                  color="warning"
                  density="comfortable"
                  hide-details
                  class="scope-check"
                  @update:model-value="toggleDetectionScope(scope.value, $event)"
                />
              </div>
              <div class="text-caption text-medium-emphasis mt-2">
                Both endpoints must fall inside an excluded scope. Traffic from a private
                host out to a public address is still captured and analysed.
              </div>
            </v-col>
            <v-col cols="12" md="5">
              <div class="interface-status">{{ detectionScopeStatus }}</div>
              <div class="text-caption text-medium-emphasis mt-2">
                Leave every box unchecked to detect on all traffic.
              </div>
            </v-col>
          </v-row>

          <v-alert v-if="detectionScopesError" type="error" variant="tonal" density="comfortable" class="mt-3">
            {{ detectionScopesError }}
          </v-alert>
        </DataPanel>

        <DataPanel
          title="Sensor location"
          subtitle="Where this machine physically sits. Private and loopback addresses have no geolocation of their own, so the Radar map plots them all at this point. Public addresses keep their own location, resolved from the registry blocks."
          variant="tonal"
          class="mb-4 location-card"
        >
          <template #header-actions>
            <v-chip
              size="small"
              :color="locationConfigured ? 'success' : 'secondary'"
              variant="tonal"
              :prepend-icon="locationConfigured ? 'mdi-map-marker-check' : 'mdi-map-marker-off'"
            >
              {{ locationConfigured ? locationSummary : "Not set" }}
            </v-chip>
          </template>

          <div class="text-caption text-medium-emphasis mb-2">
            Click the map to drop the marker, or type the coordinates.
          </div>

          <LocationPicker
            :lat="locationDraft.lat"
            :lon="locationDraft.lon"
            :label="locationDraft.label"
            @update:lat="locationDraft.lat = $event"
            @update:lon="locationDraft.lon = $event"
            @update:label="locationDraft.label = $event"
          />

          <div class="d-flex justify-end ga-2 mt-3">
            <v-btn
              size="small"
              variant="text"
              color="secondary"
              :disabled="locationSubmitting || !locationConfigured"
              @click="clearLocation"
            >
              Clear
            </v-btn>
            <v-btn
              size="small"
              variant="flat"
              color="primary"
              :loading="locationSubmitting"
              :disabled="!locationDirty || !locationDraftValid"
              @click="saveLocation"
            >
              Save location
            </v-btn>
          </div>

          <v-alert v-if="locationError" type="error" variant="tonal" density="comfortable" class="mt-3">
            {{ locationError }}
          </v-alert>
        </DataPanel>

        <DataPanel
          title="Stored data"
          subtitle="Delete what capture and the honeypot have written to the database. Monitor definitions, listeners, blacklists and settings are never touched."
          variant="tonal"
          class="mb-4 purge-card"
        >
          <v-row dense align="center">
            <v-col cols="12" md="8">
              <div class="text-body-2">
                <strong>Detection history</strong> removes stored packets, tags and payloads.
                <strong>Everything</strong> also wipes flows, domains, paths and sessions, then
                compacts the database file on disk.
              </div>
            </v-col>
            <v-col cols="12" md="4" class="d-flex justify-md-end ga-2 flex-wrap">
              <v-btn
                size="small"
                variant="tonal"
                color="warning"
                :disabled="purging"
                @click="openPurge('all')"
              >
                Detection history
              </v-btn>
              <v-btn
                size="small"
                variant="tonal"
                color="error"
                :disabled="purging"
                @click="openPurge('everything')"
              >
                Everything
              </v-btn>
            </v-col>
          </v-row>

          <v-alert v-if="purgeResult" type="success" variant="tonal" density="comfortable" class="mt-3">
            {{ purgeResult }}
          </v-alert>
          <v-alert v-if="purgeError" type="error" variant="tonal" density="comfortable" class="mt-3">
            {{ purgeError }}
          </v-alert>
        </DataPanel>

        <v-dialog v-model="purgeDialog" max-width="460">
          <v-card class="pa-4">
            <div class="text-h6 mb-3">
              {{ purgeScope === "everything" ? "Delete all capture data?" : "Clear detection history?" }}
            </div>
            <div class="text-caption text-medium-emphasis mb-3">
              <template v-if="purgeScope === 'everything'">
                Deletes every packet, tag, payload, flow, domain, path and session written by
                capture and the honeypot, then compacts the database file. Monitor and listener
                definitions, blacklists and settings survive. This cannot be undone.
              </template>
              <template v-else>
                Deletes stored packets, tags and payloads. Flows, domains, paths and sessions are
                kept. This cannot be undone.
              </template>
            </div>
            <div class="d-flex justify-end ga-2">
              <v-btn variant="text" @click="purgeDialog = false">Cancel</v-btn>
              <v-btn color="error" variant="flat" :loading="purging" @click="confirmPurge">
                {{ purgeScope === "everything" ? "Delete everything" : "Clear history" }}
              </v-btn>
            </div>
          </v-card>
        </v-dialog>

      </v-window-item>

      <v-window-item value="honeypot">
        <DataPanel
          title="Listeners"
          subtitle="Enable or disable individual listeners. A listener can never be edited or removed once created - only turned on or off - so the record of what was ever exposed stays intact."
          variant="tonal"
          :count="listeners.length"
          count-label="listeners"
          :error="listenersError"
          class="mb-4 listeners-card"
        >
          <template #header-actions>
            <v-btn size="small" color="primary" variant="outlined" prepend-icon="mdi-plus" @click="openNewListenerDialog">
              New Listener
            </v-btn>
          </template>

          <v-text-field
            v-model.trim="listenerSearch"
            label="Search listeners"
            placeholder="proto, port, label, source..."
            prepend-inner-icon="mdi-magnify"
            clearable
            variant="outlined"
            density="comfortable"
            class="mb-3"
            hide-details
          />

          <v-data-table
            :headers="listenerHeaders"
            :items="listeners"
            :search="listenerSearch"
            :custom-filter="filterListenerRows"
            density="comfortable"
            items-per-page="10"
            no-data-text="No listeners yet."
            class="listeners-table"
          >
            <template v-slot:[`item.endpoint`]="{ item }">
              <span class="mono">{{ String(item.proto || "").toUpperCase() }}/{{ item.port }}</span>
            </template>
            <template v-slot:[`item.label`]="{ item }">
              {{ item.label || "-" }}
            </template>
            <template v-slot:[`item.source`]="{ item }">
              <v-chip size="x-small" :color="item.source === 'builtin' ? 'secondary' : 'info'" variant="tonal">
                {{ item.source }}
              </v-chip>
            </template>
            <template v-slot:[`item.running`]="{ item }">
              <v-chip
                size="x-small"
                :color="item.running ? 'success' : 'secondary'"
                variant="tonal"
                :prepend-icon="item.running ? 'mdi-check-circle-outline' : 'mdi-close-circle-outline'"
              >
                {{ item.running ? "Running" : "Stopped" }}
              </v-chip>
            </template>
            <template v-slot:[`item.enabled`]="{ item }">
              <v-switch
                :model-value="item.enabled"
                :loading="listenerTogglePending === item.id"
                :disabled="Boolean(listenerTogglePending)"
                density="compact"
                hide-details
                color="success"
                @update:model-value="(value) => toggleListener(item, value)"
              />
            </template>
          </v-data-table>
        </DataPanel>

        <v-dialog v-model="newListenerDialog" max-width="420">
          <v-card class="pa-4">
            <div class="text-h6 mb-3">New Listener</div>
            <div class="text-caption text-medium-emphasis mb-3">
              This can be enabled or disabled later, but never edited or removed - double-check the
              protocol and port before creating it.
            </div>
            <v-select
              v-model="newListener.proto"
              :items="['tcp', 'udp']"
              label="Protocol"
              variant="outlined"
              density="comfortable"
            />
            <v-text-field
              v-model.number="newListener.port"
              label="Port"
              type="number"
              variant="outlined"
              density="comfortable"
              :min="1"
              :max="65535"
            />
            <v-text-field
              v-model.trim="newListener.label"
              label="Label (optional)"
              variant="outlined"
              density="comfortable"
            />
            <v-alert v-if="newListenerError" type="error" variant="tonal" density="comfortable" class="mb-3">
              {{ newListenerError }}
            </v-alert>
            <div class="d-flex justify-end ga-2">
              <v-btn variant="text" @click="newListenerDialog = false">Cancel</v-btn>
              <v-btn color="primary" variant="flat" :loading="newListenerSubmitting" @click="createListener">
                Create
              </v-btn>
            </div>
          </v-card>
        </v-dialog>
      </v-window-item>

      <v-window-item value="detection">
        <v-alert v-if="error" type="error" variant="tonal" class="mb-4">
          {{ error }}
        </v-alert>
        <v-alert v-if="configError" type="error" variant="tonal" class="mb-4">
          {{ configError }}
        </v-alert>

        <v-card variant="tonal" class="pa-4 mb-4 filter-card">
          <div class="d-flex align-start justify-space-between flex-wrap ga-3">
            <div>
              <div class="text-subtitle-2 font-weight-medium">Store only detected traffic</div>
              <div class="text-caption text-medium-emphasis mt-1">
                When enabled (recommended), packets that don't match any enabled monitor are never
                written to SQLite - they're still counted live but not persisted or shown in
                history/analytics. Turn this off to fall back to persisting everything captured.
              </div>
            </div>
            <v-switch
              :model-value="filterEnabled"
              :loading="configSubmitting"
              color="primary"
              hide-details
              inset
              @update:model-value="toggleFilter"
            />
          </div>
        </v-card>

        <div class="d-flex justify-end mb-3">
          <v-btn color="primary" prepend-icon="mdi-plus" @click="openCreateDialog">
            New monitor
          </v-btn>
        </div>

        <EntityTablePanel
          title="Detection monitors"
          subtitle="Built-in monitors can be enabled/disabled but not edited or removed. Custom monitors can be edited or removed. Their live traffic and charts are on the Monitors page."
          :rows="monitors"
          :columns="columns"
          :loading="loading"
          :error="error"
          :last-updated="lastUpdated"
          search-enabled
          search-label="Search monitors"
          search-placeholder="Name, tag, description..."
          :page-size="25"
          empty-text="No monitors defined yet"
          @refresh="load"
        >
          <template #cell-mode="{ value }">
            <v-chip size="x-small" :color="modeColor(value)" variant="tonal">
              {{ modeLabel(value) }}
            </v-chip>
          </template>
          <template #cell-severity="{ item }">
            <v-chip size="x-small" :color="severityColor(item.action && item.action.severity)" variant="tonal">
              {{ (item.action && item.action.severity) || "info" }}
            </v-chip>
          </template>
          <template #cell-match_summary="{ item }">
            <span class="match-summary">{{ matchSummary(item) }}</span>
          </template>
          <template #cell-source="{ item }">
            <v-chip size="x-small" :color="item.source === 'builtin' ? 'secondary' : 'success'" variant="tonal">
              {{ item.source === "builtin" ? "Built-in" : "Custom" }}
            </v-chip>
          </template>
          <template #cell-enabled="{ item }">
            <v-switch
              :model-value="item.enabled"
              :disabled="isBusy(item.id)"
              color="primary"
              density="compact"
              hide-details
              inset
              @update:model-value="(value) => toggleEnabled(item, value)"
            />
          </template>
          <template #cell-actions="{ item }">
            <div class="row-actions">
              <v-btn
                v-if="item.source !== 'builtin'"
                size="small"
                variant="tonal"
                color="primary"
                prepend-icon="mdi-pencil"
                :disabled="isBusy(item.id)"
                @click="openEditDialog(item)"
              >
                Edit
              </v-btn>
              <v-btn
                v-if="item.source !== 'builtin'"
                size="small"
                variant="tonal"
                color="error"
                prepend-icon="mdi-delete"
                :loading="isBusy(item.id)"
                @click="removeMonitor(item)"
              >
                Delete
              </v-btn>
            </div>
          </template>
        </EntityTablePanel>

        <v-btn
          size="small"
          variant="text"
          color="primary"
          prepend-icon="mdi-chart-timeline-variant"
          class="mt-4"
          to="/monitors"
        >
          View monitor traffic &amp; charts
        </v-btn>

        <v-dialog v-model="dialogOpen" max-width="720">
          <v-card rounded="xl" class="pa-2">
            <v-card-title class="text-h6">
              {{ editingId ? "Edit monitor" : "New monitor" }}
            </v-card-title>
            <v-card-text>
              <v-alert v-if="formError" type="error" variant="tonal" density="comfortable" class="mb-4">
                {{ formError }}
              </v-alert>

              <v-row dense>
                <v-col cols="12" md="8">
                  <v-text-field v-model.trim="form.name" label="Name" variant="outlined" density="comfortable" />
                </v-col>
                <v-col cols="12" md="4">
                  <v-text-field
                    v-model.number="form.priority"
                    type="number"
                    label="Priority"
                    hint="Lower runs first"
                    persistent-hint
                    variant="outlined"
                    density="comfortable"
                  />
                </v-col>
                <v-col cols="12">
                  <v-text-field
                    v-model.trim="form.description"
                    label="Description"
                    variant="outlined"
                    density="comfortable"
                  />
                </v-col>
                <v-col cols="12" sm="6">
                  <v-select
                    v-model="form.severity"
                    :items="severityOptions"
                    label="Severity"
                    variant="outlined"
                    density="comfortable"
                  />
                </v-col>
                <v-col cols="12" sm="6">
                  <v-text-field
                    v-model.trim="form.tag"
                    label="Tag"
                    hint="Short label attached to stored packets"
                    persistent-hint
                    variant="outlined"
                    density="comfortable"
                  />
                </v-col>
              </v-row>

              <v-btn-toggle v-model="form.mode" mandatory color="primary" class="mode-toggle my-4">
                <v-btn value="rule">Rule builder</v-btn>
                <v-btn value="regex">Regex</v-btn>
              </v-btn-toggle>

              <div v-if="form.mode === 'rule'">
                <v-row dense>
                  <v-col cols="12" sm="6">
                    <v-select
                      v-model="form.protocols"
                      :items="protocolOptions"
                      label="Protocols"
                      multiple
                      chips
                      closable-chips
                      clearable
                      variant="outlined"
                      density="comfortable"
                    />
                  </v-col>
                  <v-col cols="12" sm="6">
                    <v-combobox
                      v-model="form.ports"
                      label="Ports"
                      hint="Matches source or destination port"
                      persistent-hint
                      multiple
                      chips
                      closable-chips
                      clearable
                      variant="outlined"
                      density="comfortable"
                    />
                  </v-col>
                  <v-col cols="12">
                    <v-combobox
                      v-model="form.payloadContains"
                      label="Payload contains"
                      hint="Case-insensitive plain-text substrings"
                      persistent-hint
                      multiple
                      chips
                      closable-chips
                      clearable
                      variant="outlined"
                      density="comfortable"
                    />
                  </v-col>
                  <v-col cols="12" sm="6">
                    <v-text-field
                      v-model.number="form.minLength"
                      type="number"
                      label="Min packet length"
                      variant="outlined"
                      density="comfortable"
                    />
                  </v-col>
                  <v-col cols="12" sm="6">
                    <v-text-field
                      v-model.number="form.maxLength"
                      type="number"
                      label="Max packet length"
                      variant="outlined"
                      density="comfortable"
                    />
                  </v-col>
                </v-row>
              </div>

              <div v-else class="d-flex align-start ga-2">
                <v-combobox
                  v-model="form.payloadRegex"
                  label="Regex patterns"
                  hint="Enter, then press Enter to add another pattern. Any pattern matching flags this packet."
                  persistent-hint
                  multiple
                  chips
                  closable-chips
                  clearable
                  variant="outlined"
                  density="comfortable"
                  :error-messages="regexErrors"
                  class="flex-grow-1"
                />
                <RegexHelperButton class="mt-2" @apply="(pattern) => form.payloadRegex.push(pattern)" />
              </div>
            </v-card-text>
            <v-card-actions>
              <v-spacer />
              <v-btn variant="text" @click="dialogOpen = false">Cancel</v-btn>
              <v-btn color="primary" variant="tonal" :loading="formSubmitting" @click="submitForm">
                Save monitor
              </v-btn>
            </v-card-actions>
          </v-card>
        </v-dialog>
      </v-window-item>

      <v-window-item value="blacklist">
        <BlacklistPanel />
      </v-window-item>

      <v-window-item value="notifications">
        <v-card variant="tonal" class="pa-4 notify-card">
          <div class="d-flex align-start justify-space-between flex-wrap ga-3">
            <div>
              <div class="text-subtitle-2 font-weight-medium">Notification sound</div>
              <div class="text-caption text-medium-emphasis mt-1">
                Play a sound in this browser tab when a new alert notification arrives. Saved locally
                to this browser, not to the server.
              </div>
            </div>
            <v-switch
              :model-value="store.state.notifySoundEnabled"
              color="primary"
              hide-details
              inset
              @update:model-value="(value) => store.setNotifySoundEnabled(value)"
            />
          </div>
        </v-card>
      </v-window-item>
    </v-window>
  </div>
</template>

<script>
import store from "../state/appStore";
import ViewHeader from "../components/ui/ViewHeader.vue";
import EntityTablePanel from "../components/ui/EntityTablePanel.vue";
import DataPanel from "../components/ui/DataPanel.vue";
import LocationPicker from "../components/settings/LocationPicker.vue";
import RegexHelperButton from "../components/ui/RegexHelperButton.vue";
import BlacklistPanel from "../components/settings/BlacklistPanel.vue";
import { formatTimestamp, matchesSearch, uniqueSorted } from "../utils/traffic";

const PROTOCOL_OPTIONS = [
  "tcp",
  "udp",
  "icmp",
  "icmpv6",
  "arp",
  "sctp",
  "modbus",
  "dnp3",
  "snmp",
  "syslog",
  "tftp",
  "radius",
  "mqtt",
  "llc",
  "llc-snap",
  "llc-ipx",
  "llc-netbios",
  "llc-osi",
];
const SEVERITY_OPTIONS = ["info", "low", "medium", "high", "critical"];
const VALID_TABS = new Set(["capture", "honeypot", "detection", "blacklist", "notifications"]);

function emptyForm() {
  return {
    name: "",
    description: "",
    priority: 100,
    severity: "medium",
    tag: "",
    mode: "rule",
    protocols: [],
    ports: [],
    payloadContains: [],
    minLength: null,
    maxLength: null,
    payloadRegex: [],
  };
}

export default {
  name: "SettingsView",
  components: {
    ViewHeader,
    EntityTablePanel,
    DataPanel,
    RegexHelperButton,
    BlacklistPanel,
    LocationPicker,
  },
  data() {
    const requested = String((this.$route && this.$route.query && this.$route.query.section) || "").trim();
    return {
      store,
      activeTab: VALID_TABS.has(requested) ? requested : "capture",

      // Capture
      interfaceSubmitting: false,
      interfaceError: "",
      detectionScopes: [],
      detectionScopeCatalog: [],
      detectionScopesSubmitting: false,
      detectionScopesError: "",
      locationSaved: { lat: null, lon: null, label: "", configured: false },
      locationDraft: { lat: null, lon: null, label: "" },
      locationSubmitting: false,
      locationError: "",
      purgeDialog: false,
      purgeScope: "all",
      purging: false,
      purgeError: "",
      purgeResult: "",

      // Service listeners
      listeners: [],
      listenersError: "",
      listenerTogglePending: "",
      listenerSearch: "",
      listenerHeaders: [
        { title: "Listener", key: "endpoint", value: (item) => `${item.proto}/${item.port}` },
        { title: "Label", key: "label" },
        { title: "Source", key: "source" },
        { title: "Status", key: "running" },
        { title: "Enabled", key: "enabled", sortable: false },
      ],
      newListenerDialog: false,
      newListenerSubmitting: false,
      newListenerError: "",
      newListener: { proto: "tcp", port: null, label: "" },

      // Detection monitors
      loading: false,
      error: "",
      lastUpdated: "",
      monitors: [],
      filterEnabled: true,
      configSubmitting: false,
      configError: "",
      busyIds: {},
      dialogOpen: false,
      editingId: "",
      form: emptyForm(),
      formError: "",
      formSubmitting: false,
      protocolOptions: PROTOCOL_OPTIONS,
      severityOptions: SEVERITY_OPTIONS,
      columns: [
        { key: "name", label: "Name" },
        { key: "mode", label: "Mode" },
        { key: "match_summary", label: "Match", sortable: false },
        { key: "severity", label: "Severity" },
        { key: "source", label: "Source" },
        { key: "enabled", label: "Enabled", sortable: false },
        { key: "actions", label: "", sortable: false, width: 200 },
      ],
    };
  },
  computed: {
    runtime() {
      return this.store.state.runtime || {};
    },
    snifferRuntime() {
      const runtime = this.runtime.sniffer;
      return runtime && typeof runtime === "object" ? runtime : {};
    },
    snifferBlocked() {
      return String(this.snifferRuntime.capture_state || "").trim().toLowerCase() === "blocked";
    },
    selectedInterfacesLabel() {
      const values = Array.isArray(this.snifferRuntime.selected_interfaces) ? this.snifferRuntime.selected_interfaces : [];
      if (!values.length) return "all visible";
      return values.join(", ");
    },
    selectedSnifferInterfaces() {
      const values = Array.isArray(this.snifferRuntime.selected_interfaces) ? this.snifferRuntime.selected_interfaces : [];
      return [...new Set(values.map((item) => String(item || "").trim()).filter(Boolean))];
    },
    snifferInterfaceOptions() {
      const values = Array.isArray(this.snifferRuntime.available_interfaces) ? this.snifferRuntime.available_interfaces : [];
      return uniqueSorted(values).map((value) => ({ label: value, value }));
    },
    snifferInterfaceStatus() {
      const active = Array.isArray(this.snifferRuntime.interfaces)
        ? this.snifferRuntime.interfaces.map((item) => String(item || "").trim()).filter(Boolean)
        : [];
      const state = String(this.snifferRuntime.capture_state || "").trim().toLowerCase();
      if (state === "blocked") {
        return `Capture is blocked on ${active.length || this.selectedSnifferInterfaces.length || 0} interfaces.`;
      }
      if (state === "running") {
        if (active.length === 1) return `Listening on ${active[0]}.`;
        if (active.length > 1) return `Listening on ${active.length} interfaces.`;
        return "Listening on all visible interfaces.";
      }
      if (!this.selectedSnifferInterfaces.length) {
        return "Ready to listen on every visible interface.";
      }
      return `Ready to listen on ${this.selectedInterfacesLabel}.`;
    },
    locationConfigured() {
      return Boolean(this.locationSaved.configured);
    },
    locationSummary() {
      const label = String(this.locationSaved.label || "").trim();
      if (label) return label;
      const { lat, lon } = this.locationSaved;
      return Number.isFinite(lat) && Number.isFinite(lon)
        ? `${Number(lat).toFixed(2)}, ${Number(lon).toFixed(2)}`
        : "Not set";
    },
    locationDraftValid() {
      const { lat, lon } = this.locationDraft;
      return Number.isFinite(lat) && Number.isFinite(lon);
    },
    locationDirty() {
      return (
        this.locationDraft.lat !== this.locationSaved.lat ||
        this.locationDraft.lon !== this.locationSaved.lon ||
        String(this.locationDraft.label || "") !== String(this.locationSaved.label || "")
      );
    },
    detectionScopeOptions() {
      const labels = {
        loopback: "Loopback (127.0.0.0/8, ::1)",
        private: "Private / LAN (RFC1918, link-local)",
        public: "Public (routable internet)",
      };
      const catalog = this.detectionScopeCatalog.length
        ? this.detectionScopeCatalog
        : ["loopback", "private", "public"];
      return catalog.map((value) => ({ value, label: labels[value] || value }));
    },
    detectionScopeStatus() {
      if (!this.detectionScopes.length) return "All captured traffic is analysed.";
      const names = this.detectionScopes.join(", ");
      return `Traffic between ${names} addresses is ignored entirely.`;
    },
    snifferInterfaceHint() {
      if (!this.snifferInterfaceOptions.length) {
        return "No interfaces have been reported yet. Refresh to rediscover them.";
      }
      return "An empty selection means Sniff4Hound will listen on every visible interface.";
    },
    regexErrors() {
      const invalid = (this.form.payloadRegex || []).filter((pattern) => !this.isValidRegex(pattern));
      return invalid.length ? [`Invalid regex: ${invalid.join(", ")}`] : [];
    },
  },
  watch: {
    "$route.query.section"(next) {
      const requested = String(next || "").trim();
      if (VALID_TABS.has(requested)) this.activeTab = requested;
    },
  },
  mounted() {
    this.store.initRuntime();
    this.loadListeners();
    this.loadDetectionScopes();
    this.loadLocation();
    this.load();
  },
  methods: {
    formatTimestamp,
    matchesSearch,
    // Capture
    loadLocation() {
      this.store
        .getDeclaredLocation()
        .then((payload) => this.applyLocation(payload))
        .catch((err) => {
          this.locationError = (err && err.message) || "Failed to load the sensor location";
        });
    },
    applyLocation(payload) {
      const row = payload && typeof payload === "object" ? payload : {};
      const lat = Number.isFinite(row.lat) ? row.lat : null;
      const lon = Number.isFinite(row.lon) ? row.lon : null;
      this.locationSaved = { lat, lon, label: row.label || "", configured: Boolean(row.configured) };
      this.locationDraft = { lat, lon, label: row.label || "" };
    },
    saveLocation() {
      if (this.locationSubmitting || !this.locationDraftValid) return;
      this.locationSubmitting = true;
      this.locationError = "";
      this.store
        .setDeclaredLocation(this.locationDraft.lat, this.locationDraft.lon, this.locationDraft.label)
        .then((payload) => this.applyLocation(payload))
        .catch((err) => {
          this.locationError = (err && err.message) || "Failed to save the sensor location";
        })
        .finally(() => {
          this.locationSubmitting = false;
        });
    },
    clearLocation() {
      if (this.locationSubmitting) return;
      this.locationSubmitting = true;
      this.locationError = "";
      this.store
        .clearDeclaredLocation()
        .then((payload) => this.applyLocation(payload))
        .catch((err) => {
          this.locationError = (err && err.message) || "Failed to clear the sensor location";
        })
        .finally(() => {
          this.locationSubmitting = false;
        });
    },
    loadDetectionScopes() {
      this.store
        .getDetectionScopes()
        .then((payload) => {
          this.detectionScopeCatalog = Array.isArray(payload && payload.available_scopes)
            ? payload.available_scopes
            : [];
          this.detectionScopes = Array.isArray(payload && payload.exclude_scopes)
            ? payload.exclude_scopes
            : [];
        })
        .catch((err) => {
          this.detectionScopesError = (err && err.message) || "Failed to load the detection scope filter";
        });
    },
    openPurge(scope) {
      this.purgeScope = scope;
      this.purgeError = "";
      this.purgeResult = "";
      this.purgeDialog = true;
    },
    confirmPurge() {
      if (this.purging) return;
      const scope = this.purgeScope;
      this.purging = true;
      this.purgeError = "";
      this.store
        .clearDetections(scope)
        .then((payload) => {
          const rows = payload && typeof payload === "object" ? payload : {};
          const detail = Object.entries(rows)
            .filter(([, value]) => Number(value) > 0)
            .map(([table, value]) => `${Number(value).toLocaleString()} ${table}`)
            .join(", ");
          this.purgeResult = detail ? `Deleted ${detail}.` : "Nothing left to delete.";
          this.purgeDialog = false;
          this.store.initRuntime();
        })
        .catch((err) => {
          this.purgeError = (err && err.message) || "Failed to clear stored data";
        })
        .finally(() => {
          this.purging = false;
        });
    },
    toggleDetectionScope(scope, checked) {
      if (this.detectionScopesSubmitting) return;
      const next = new Set(this.detectionScopes);
      if (checked) {
        next.add(scope);
      } else {
        next.delete(scope);
      }
      const wanted = [...next].sort();
      const previous = [...this.detectionScopes];
      // Optimistic: the checkbox is bound to this array, so without it the box
      // would visibly snap back until the round trip lands.
      this.detectionScopes = wanted;
      this.detectionScopesError = "";
      this.detectionScopesSubmitting = true;
      this.store
        .setDetectionScopes(wanted)
        .then((payload) => {
          this.detectionScopes = Array.isArray(payload && payload.exclude_scopes)
            ? payload.exclude_scopes
            : wanted;
        })
        .catch((err) => {
          this.detectionScopes = previous;
          this.detectionScopesError = (err && err.message) || "Failed to update the detection scope filter";
        })
        .finally(() => {
          this.detectionScopesSubmitting = false;
        });
    },
    updateSnifferInterfaces(value) {
      const normalized = Array.isArray(value)
        ? [...new Set(value.map((item) => String(item || "").trim()).filter(Boolean))]
        : [];
      if (this.interfaceSubmitting) {
        return;
      }
      const current = [...this.selectedSnifferInterfaces].sort();
      const incoming = [...normalized].sort();
      if (incoming.length === current.length && incoming.every((item, index) => item === current[index])) {
        return;
      }
      this.interfaceError = "";
      this.interfaceSubmitting = true;
      this.store
        .setSnifferInterfaces(normalized)
        .catch((err) => {
          this.interfaceError = err && err.message ? err.message : "Failed to update interfaces";
        })
        .finally(() => {
          this.interfaceSubmitting = false;
        });
    },
    // Service listeners
    filterListenerRows(value, query, item) {
      const needle = String(query || "").trim().toLowerCase();
      if (!needle) return true;
      const raw = item && item.raw ? item.raw : item;
      const haystack = [raw.proto, raw.port, raw.label, raw.source, raw.running ? "running" : "stopped"]
        .map((part) => String(part == null ? "" : part).toLowerCase())
        .join(" ");
      return haystack.includes(needle);
    },
    loadListeners() {
      return this.store
        .listHoneypotListeners()
        .then((payload) => {
          this.listeners = this.store.extractArray(payload);
          this.listenersError = "";
        })
        .catch((err) => {
          this.listeners = [];
          this.listenersError = (err && err.message) || "Failed to load listeners";
        });
    },
    toggleListener(listener, value) {
      if (this.listenerTogglePending) return;
      this.listenerTogglePending = listener.id;
      this.listenersError = "";
      this.store
        .toggleHoneypotListenerEnabled(listener.id, value)
        .then((snapshot) => {
          this.listeners = this.store.extractArray(snapshot && snapshot.listeners);
        })
        .catch((err) => {
          this.listenersError = (err && err.message) || `Failed to ${value ? "enable" : "disable"} ${listener.id}`;
        })
        .finally(() => {
          this.listenerTogglePending = "";
        });
    },
    openNewListenerDialog() {
      this.newListener = { proto: "tcp", port: null, label: "" };
      this.newListenerError = "";
      this.newListenerDialog = true;
    },
    createListener() {
      const port = Number(this.newListener.port);
      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        this.newListenerError = "Port must be a whole number between 1 and 65535";
        return;
      }
      const listenerId = `${this.newListener.proto}/${port}`;
      if (this.listeners.some((item) => item.id === listenerId)) {
        this.newListenerError = `${listenerId} already exists`;
        return;
      }
      this.newListenerSubmitting = true;
      this.newListenerError = "";
      this.store
        .createHoneypotListener(this.newListener.proto, port, this.newListener.label)
        .then((snapshot) => {
          this.listeners = this.store.extractArray(snapshot && snapshot.listeners);
          this.newListenerDialog = false;
        })
        .catch((err) => {
          this.newListenerError = (err && err.message) || "Failed to create listener";
        })
        .finally(() => {
          this.newListenerSubmitting = false;
        });
    },
    // Detection monitors
    isBusy(id) {
      return Boolean(this.busyIds[id]);
    },
    setBusy(id, value) {
      this.busyIds = { ...this.busyIds, [id]: value };
    },
    severityColor(value) {
      const severity = String(value || "info").trim().toLowerCase();
      if (severity === "critical") return "error";
      if (severity === "high") return "error";
      if (severity === "medium") return "warning";
      if (severity === "low") return "info";
      return "secondary";
    },
    modeLabel(value) {
      const mode = String(value || "").trim().toLowerCase();
      if (mode === "regex") return "Regex";
      if (mode === "stateful") return "Stateful";
      return "Rule";
    },
    modeColor(value) {
      const mode = String(value || "").trim().toLowerCase();
      if (mode === "regex") return "info";
      if (mode === "stateful") return "warning";
      return "primary";
    },
    matchSummary(item) {
      const match = item.match || {};
      const parts = [];
      if (match.protocols && match.protocols.length) parts.push(match.protocols.join("/").toUpperCase());
      if (match.ports && match.ports.length) parts.push(`ports ${match.ports.join(",")}`);
      if (match.eth_types && match.eth_types.length) {
        parts.push(`eth 0x${match.eth_types.map((value) => Number(value).toString(16)).join(",0x")}`);
      }
      if (match.payload_contains && match.payload_contains.length) {
        parts.push(`contains "${match.payload_contains.join('", "')}"`);
      }
      if (match.payload_regex && match.payload_regex.length) {
        parts.push(`regex ${match.payload_regex.length === 1 ? match.payload_regex[0] : `${match.payload_regex.length} patterns`}`);
      }
      if (match.min_length) parts.push(`>=${match.min_length}B`);
      if (match.max_length) parts.push(`<=${match.max_length}B`);
      if (match.min_payload_text_length) parts.push(`>=${match.min_payload_text_length} readable chars`);
      return parts.length ? parts.join(" · ") : "-";
    },
    isValidRegex(pattern) {
      try {
        new RegExp(pattern);
        return true;
      } catch {
        return false;
      }
    },
    toggleFilter(value) {
      this.configSubmitting = true;
      this.configError = "";
      this.store
        .setMonitorConfig({ filter_enabled: Boolean(value) })
        .then((payload) => {
          this.filterEnabled = Boolean(payload && payload.filter_enabled);
        })
        .catch((err) => {
          this.configError = (err && err.message) || "Failed to update the persistence filter";
        })
        .finally(() => {
          this.configSubmitting = false;
        });
    },
    toggleEnabled(item, value) {
      this.setBusy(item.id, true);
      this.store
        .toggleMonitorEnabled(item.id, Boolean(value))
        .then(() => this.load())
        .catch((err) => {
          this.error = (err && err.message) || "Failed to update monitor";
        })
        .finally(() => {
          this.setBusy(item.id, false);
        });
    },
    removeMonitor(item) {
      if (item.source === "builtin") return;
      const confirmed = typeof window !== "undefined" ? window.confirm(`Delete monitor "${item.name}"?`) : true;
      if (!confirmed) return;
      this.setBusy(item.id, true);
      this.store
        .deleteMonitor(item.id)
        .then(() => this.load())
        .catch((err) => {
          this.error = (err && err.message) || "Failed to delete monitor";
        })
        .finally(() => {
          this.setBusy(item.id, false);
        });
    },
    openCreateDialog() {
      this.editingId = "";
      this.form = emptyForm();
      this.formError = "";
      this.dialogOpen = true;
    },
    openEditDialog(item) {
      const match = item.match || {};
      const action = item.action || {};
      this.editingId = item.id;
      this.form = {
        name: item.name || "",
        description: item.description || "",
        priority: item.priority || 100,
        severity: action.severity || "medium",
        tag: action.tag || "",
        mode: item.mode === "regex" ? "regex" : "rule",
        protocols: Array.isArray(match.protocols) ? [...match.protocols] : [],
        ports: Array.isArray(match.ports) ? match.ports.map(String) : [],
        payloadContains: Array.isArray(match.payload_contains) ? [...match.payload_contains] : [],
        minLength: match.min_length || null,
        maxLength: match.max_length || null,
        payloadRegex: Array.isArray(match.payload_regex) ? [...match.payload_regex] : [],
      };
      this.formError = "";
      this.dialogOpen = true;
    },
    buildMatchPayload() {
      if (this.form.mode === "regex") {
        const patterns = (this.form.payloadRegex || []).map((item) => String(item || "").trim()).filter(Boolean);
        return { payload_regex: patterns };
      }
      const ports = (this.form.ports || [])
        .map((item) => Number(item))
        .filter((value) => Number.isFinite(value) && value > 0);
      const contains = (this.form.payloadContains || []).map((item) => String(item || "").trim()).filter(Boolean);
      return {
        protocols: [...(this.form.protocols || [])],
        ports,
        payload_contains: contains,
        min_length: Number(this.form.minLength) || 0,
        max_length: Number(this.form.maxLength) || 0,
      };
    },
    submitForm() {
      this.formError = "";
      const name = String(this.form.name || "").trim();
      if (!name) {
        this.formError = "Name is required";
        return;
      }
      if (this.form.mode === "regex") {
        const patterns = (this.form.payloadRegex || []).map((item) => String(item || "").trim()).filter(Boolean);
        if (!patterns.length) {
          this.formError = "Add at least one regex pattern";
          return;
        }
        if (patterns.some((pattern) => !this.isValidRegex(pattern))) {
          this.formError = "One or more regex patterns are invalid";
          return;
        }
      }
      const payload = {
        id: this.editingId || undefined,
        name,
        description: String(this.form.description || "").trim(),
        priority: Number(this.form.priority) || 100,
        mode: this.form.mode,
        match: this.buildMatchPayload(),
        action: {
          severity: this.form.severity,
          tag: String(this.form.tag || "").trim(),
          label: name,
        },
      };
      this.formSubmitting = true;
      this.store
        .saveMonitor(payload)
        .then(() => {
          this.dialogOpen = false;
          return this.load();
        })
        .catch((err) => {
          this.formError = (err && err.message) || "Failed to save monitor";
        })
        .finally(() => {
          this.formSubmitting = false;
        });
    },
    load(options = {}) {
      if (!options.silent) this.loading = true;
      this.error = "";
      return Promise.allSettled([this.store.listMonitors(), this.store.getMonitorConfig()])
        .then(([monitorsRes, configRes]) => {
          if (monitorsRes.status === "fulfilled") {
            this.monitors = this.store.extractArray(monitorsRes.value);
          } else {
            this.monitors = [];
            this.error = (monitorsRes.reason && monitorsRes.reason.message) || "Failed to load monitors";
          }
          if (configRes.status === "fulfilled") {
            this.filterEnabled = Boolean(configRes.value && configRes.value.filter_enabled);
            this.configError = "";
          } else {
            this.configError = (configRes.reason && configRes.reason.message) || "Failed to load persistence filter state";
          }
          this.lastUpdated = new Date().toLocaleTimeString();
        })
        .finally(() => {
          this.loading = false;
        });
    },
  },
};
</script>

<style scoped>
.settings-tabs {
  border-radius: 16px;
  overflow: hidden;
}

.interface-card,
.scope-card,
.purge-card,
.location-card,
.listeners-card,
.filter-card,
.notify-card {
  border-radius: 16px;
}

.mono {
  font-family: var(--font-mono);
}

.mode-toggle {
  width: 100%;
}

.match-summary {
  /* See the banner-cell note in EntityTablePanel: `overflow-wrap: anywhere`
     drops the cell's min-content width to one character, letting the table
     collapse the column and wrap the text vertically. */
  width: 420px;
  display: -webkit-box;
  -webkit-box-orient: vertical;
  -webkit-line-clamp: 2;
  line-clamp: 2;
  overflow: hidden;
  overflow-wrap: anywhere;
  vertical-align: top;
  font-family: var(--font-mono);
  font-size: 0.85rem;
}

.interface-status {
  min-height: 44px;
  padding: 12px 14px;
  border-radius: 14px;
  border: 1px solid rgba(118, 191, 232, 0.16);
  background: linear-gradient(180deg, rgba(10, 18, 29, 0.82), rgba(9, 15, 24, 0.76));
  color: rgba(229, 239, 249, 0.88);
  font-size: 0.92rem;
  line-height: 1.45;
}
</style>
