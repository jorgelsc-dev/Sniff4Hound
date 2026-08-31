<template>
  <div>
    <v-alert type="info" variant="tonal" density="comfortable" class="mb-4">
      Blacklist entries create monitor hits and alerts automatically. Whitelist entries keep matching
      packets visible in capture, but skip rules, monitor hits and anomaly alerts.
    </v-alert>

    <v-alert v-if="error" type="error" variant="tonal" class="mb-4">{{ error }}</v-alert>

    <section v-for="group in listGroups" :key="group.kind" class="list-section">
      <div class="list-section-heading">
        <v-chip size="small" :color="group.color" variant="tonal" :prepend-icon="group.icon">
          {{ group.title }}
        </v-chip>
        <span>{{ group.description }}</span>
      </div>

      <BlacklistCategoryCard
        v-for="(card, index) in categoryCards(group.kind)"
        :key="`${group.kind}-${card.category}`"
        :category="card.category"
        :title="card.title"
        :subtitle="card.subtitle"
        :value-label="card.valueLabel"
        :value-placeholder="card.valuePlaceholder"
        :icon="card.icon"
        :entries="entriesFor(group.kind, card.category)"
        :submitting="submittingKey === `${group.kind}:${card.category}`"
        :error="formErrorFor(group.kind, card.category)"
        :class="{ 'mt-4': index > 0 }"
        @create="(payload) => createEntry(group.kind, payload)"
        @toggle="(entry, value) => toggleEntry(group.kind, entry, value)"
        @delete="(entry) => deleteEntry(group.kind, entry)"
      />
    </section>
  </div>
</template>

<script>
import store from "../../state/appStore";
import BlacklistCategoryCard from "./BlacklistCategoryCard.vue";

export default {
  name: "BlacklistPanel",
  components: {
    BlacklistCategoryCard,
  },
  data() {
    return {
      store,
      entries: { blacklist: [], whitelist: [] },
      error: "",
      submittingKey: "",
      formErrors: {},
      togglePending: "",
    };
  },
  mounted() {
    this.load();
  },
  computed: {
    listGroups() {
      return [
        {
          kind: "blacklist",
          title: "Blacklist",
          description: "Matches are promoted as detections and alerts.",
          icon: "mdi-cancel",
          color: "error",
        },
        {
          kind: "whitelist",
          title: "Whitelist",
          description: "Matches stay in capture, but do not fire detections.",
          icon: "mdi-shield-check-outline",
          color: "success",
        },
      ];
    },
  },
  methods: {
    categoryCards(kind) {
      const blacklist = kind === "blacklist";
      return [
        {
          category: "ip",
          title: `IP ${blacklist ? "Blacklist" : "Whitelist"}`,
          subtitle: blacklist
            ? "Flag traffic to or from a specific IP address."
            : "Trust traffic to or from a specific IP address.",
          valueLabel: "IP address",
          valuePlaceholder: "203.0.113.5",
          icon: "mdi-ip-network-outline",
        },
        {
          category: "domain",
          title: `Domain ${blacklist ? "Blacklist" : "Whitelist"}`,
          subtitle: blacklist
            ? "Flag DNS lookups or HTTP/TLS traffic referencing a specific domain."
            : "Trust DNS lookups or HTTP/TLS traffic referencing a specific domain.",
          valueLabel: "Domain",
          valuePlaceholder: blacklist ? "evil.example.com" : "trusted.example.com",
          icon: "mdi-web",
        },
        {
          category: "path",
          title: `Path ${blacklist ? "Blacklist" : "Whitelist"}`,
          subtitle: blacklist
            ? "Flag HTTP requests to a specific request path."
            : "Trust HTTP requests to a specific request path.",
          valueLabel: "Path",
          valuePlaceholder: blacklist ? "/wp-admin/setup-config.php" : "/health",
          icon: "mdi-routes",
        },
        {
          category: "port",
          title: `Port ${blacklist ? "Blacklist" : "Whitelist"}`,
          subtitle: blacklist
            ? "Flag traffic touching a specific source or destination port."
            : "Trust traffic touching a specific source or destination port.",
          valueLabel: "Port",
          valuePlaceholder: blacklist ? "3389" : "443",
          icon: "mdi-ethernet-cable",
        },
        {
          category: "protocol",
          title: `Protocol ${blacklist ? "Blacklist" : "Whitelist"}`,
          subtitle: blacklist
            ? "Flag traffic decoded as a specific transport or application protocol."
            : "Trust traffic decoded as a specific transport or application protocol.",
          valueLabel: "Protocol",
          valuePlaceholder: blacklist ? "telnet" : "dns",
          icon: "mdi-lan",
        },
      ];
    },
    formKey(kind, category) {
      return `${kind}:${category}`;
    },
    entriesFor(kind, category) {
      return (this.entries[kind] || []).filter((entry) => entry.category === category);
    },
    formErrorFor(kind, category) {
      return this.formErrors[this.formKey(kind, category)] || "";
    },
    load() {
      this.error = "";
      return Promise.all([this.store.listBlacklistEntries(), this.store.listWhitelistEntries()])
        .then(([blacklistPayload, whitelistPayload]) => {
          this.entries = {
            blacklist: this.store.extractArray(blacklistPayload),
            whitelist: this.store.extractArray(whitelistPayload),
          };
        })
        .catch((err) => {
          this.error = (err && err.message) || "Failed to load list entries";
        });
    },
    createEntry(kind, { category, matchType, value, label }) {
      const key = this.formKey(kind, category);
      this.formErrors[key] = "";
      this.submittingKey = key;
      const create = kind === "whitelist" ? this.store.createWhitelistEntry : this.store.createBlacklistEntry;
      create({ category, matchType, value, label })
        .then(() => this.load())
        .catch((err) => {
          this.formErrors[key] = (err && err.message) || "Failed to add entry";
        })
        .finally(() => {
          this.submittingKey = "";
        });
    },
    toggleEntry(kind, entry, value) {
      this.togglePending = entry.id;
      const toggle = kind === "whitelist" ? this.store.toggleWhitelistEntry : this.store.toggleBlacklistEntry;
      toggle(entry.id, value)
        .then(() => this.load())
        .catch((err) => {
          this.error = (err && err.message) || "Failed to update entry";
        })
        .finally(() => {
          this.togglePending = "";
        });
    },
    deleteEntry(kind, entry) {
      const remove = kind === "whitelist" ? this.store.deleteWhitelistEntry : this.store.deleteBlacklistEntry;
      remove(entry.id)
        .then(() => this.load())
        .catch((err) => {
          this.error = (err && err.message) || "Failed to delete entry";
        });
    },
  },
};
</script>

<style scoped>
.list-section + .list-section {
  margin-top: 28px;
}

.list-section-heading {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 10px;
  margin-bottom: 12px;
  color: rgba(255, 255, 255, 0.7);
  font-size: 0.86rem;
}
</style>
