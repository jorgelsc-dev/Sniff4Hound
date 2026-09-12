<template>
  <div>
    <v-alert type="info" variant="tonal" density="comfortable" class="mb-4">
      Traffic matching any of these criteria is silenced from Sniffer detection, Monitors and AI
      sampling - it does not affect raw capture or what gets stored. Use this for your own
      dashboard's loopback traffic, known internal networks, or noisy protocols/ports you don't
      want triggering detections.
    </v-alert>

    <v-alert v-if="error" type="error" variant="tonal" class="mb-4">{{ error }}</v-alert>

    <DataPanel
      title="Exclusion filter"
      subtitle="Both endpoints of an IP-type/CIDR match are checked; a port or protocol match applies to either direction."
      variant="tonal"
      :loading="loading"
    >
      <v-row dense>
        <v-col cols="12" md="4">
          <div class="text-caption text-medium-emphasis mb-1">IP type</div>
          <v-checkbox
            v-for="opt in ipTypeOptions"
            :key="opt.value"
            v-model="draft.ip_types"
            :value="opt.value"
            :label="opt.label"
            density="compact"
            hide-details
          />
        </v-col>
        <v-col cols="12" md="8">
          <v-combobox
            v-model="draft.cidrs"
            label="Excluded IPs or CIDR blocks"
            hint="e.g. 127.0.0.1, 10.0.0.0/8, 203.0.113.5"
            persistent-hint
            multiple chips closable-chips clearable
            variant="outlined"
            density="comfortable"
            class="mb-4"
          />
          <v-combobox
            v-model="draft.protocols"
            label="Excluded protocols"
            hint="e.g. dns, icmp, ntp"
            persistent-hint
            multiple chips closable-chips clearable
            variant="outlined"
            density="comfortable"
            class="mb-4"
          />
          <v-combobox
            v-model="draft.ports"
            label="Excluded ports"
            hint="Matches source or destination port"
            persistent-hint
            multiple chips closable-chips clearable
            variant="outlined"
            density="comfortable"
          />
        </v-col>
      </v-row>
      <div class="d-flex ga-2 mt-2">
        <v-btn color="primary" variant="flat" :loading="saving" @click="save">Save filter</v-btn>
        <v-btn variant="text" :disabled="saving" @click="resetDraft">Discard changes</v-btn>
        <v-chip v-if="activeFilterCount" size="small" color="warning" class="align-self-center">
          {{ activeFilterCount }} active
        </v-chip>
      </div>
      <v-alert v-if="saved" type="success" variant="tonal" density="comfortable" class="mt-3">
        Filter saved.
      </v-alert>
    </DataPanel>
  </div>
</template>

<script>
import store from "../../state/appStore";
import DataPanel from "../ui/DataPanel.vue";

const emptyFilters = () => ({ ip_types: [], cidrs: [], protocols: [], ports: [] });

export default {
  name: "ExclusionsPanel",
  components: { DataPanel },
  data() {
    return {
      store,
      loading: false,
      saving: false,
      saved: false,
      error: "",
      filters: emptyFilters(),
      draft: emptyFilters(),
      ipTypeOptions: [
        { value: "loopback", label: "Loopback (127.0.0.1, ::1)" },
        { value: "private", label: "Private (RFC1918, link-local)" },
        { value: "public", label: "Public" },
        { value: "multicast", label: "Multicast / broadcast" },
      ],
    };
  },
  computed: {
    activeFilterCount() {
      return (
        this.draft.ip_types.length +
        this.draft.cidrs.length +
        this.draft.protocols.length +
        this.draft.ports.length
      );
    },
  },
  mounted() {
    this.load();
  },
  methods: {
    resetDraft() {
      const source = this.filters || emptyFilters();
      this.draft = {
        ip_types: [...(source.ip_types || [])],
        cidrs: [...(source.cidrs || [])],
        protocols: [...(source.protocols || [])],
        ports: (source.ports || []).map(String),
      };
      this.error = "";
    },
    load() {
      this.loading = true;
      this.error = "";
      return this.store
        .fetchJsonPromise("/api/detection/exclusions")
        .then((payload) => {
          this.filters = payload.exclusion_filters || emptyFilters();
          this.resetDraft();
        })
        .catch((err) => {
          this.error = (err && err.message) || "Failed to load the exclusion filter.";
        })
        .finally(() => {
          this.loading = false;
        });
    },
    save() {
      if (this.saving) return;
      this.saving = true;
      this.saved = false;
      this.error = "";
      const ports = this.draft.ports
        .map((value) => Number(value))
        .filter((value) => Number.isInteger(value) && value >= 0 && value <= 65535);
      this.store
        .fetchJsonPromise("/api/detection/exclusions", {
          method: "POST",
          body: JSON.stringify({
            exclusion_filters: {
              ip_types: this.draft.ip_types,
              cidrs: this.draft.cidrs,
              protocols: this.draft.protocols,
              ports,
            },
          }),
        })
        .then((payload) => {
          this.filters = payload.exclusion_filters;
          this.resetDraft();
          this.saved = true;
        })
        .catch((err) => {
          this.error = (err && err.message) || "Failed to save the exclusion filter.";
        })
        .finally(() => {
          this.saving = false;
        });
    },
  },
};
</script>
