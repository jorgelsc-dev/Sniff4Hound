<template>
  <div>
    <v-alert type="info" variant="tonal" density="comfortable" class="mb-4">
      Each entry here becomes its own monitor automatically - a match fires the same way any other
      monitor does (persistence, notifications, the Monitors view). Disabling or deleting an entry
      here disables/removes that monitor too.
    </v-alert>

    <v-alert v-if="error" type="error" variant="tonal" class="mb-4">{{ error }}</v-alert>

    <BlacklistCategoryCard
      category="ip"
      title="IP Blacklist"
      subtitle="Flag traffic to or from a specific IP address."
      value-label="IP address"
      value-placeholder="203.0.113.5"
      icon="mdi-ip-network-outline"
      :entries="entriesFor('ip')"
      :submitting="submittingCategory === 'ip'"
      :error="formErrorFor('ip')"
      @create="createEntry"
      @toggle="toggleEntry"
      @delete="deleteEntry"
    />

    <BlacklistCategoryCard
      category="domain"
      title="Domain Blacklist"
      subtitle="Flag DNS lookups or HTTP/TLS traffic referencing a specific domain."
      value-label="Domain"
      value-placeholder="evil.example.com"
      icon="mdi-web"
      :entries="entriesFor('domain')"
      :submitting="submittingCategory === 'domain'"
      :error="formErrorFor('domain')"
      class="mt-4"
      @create="createEntry"
      @toggle="toggleEntry"
      @delete="deleteEntry"
    />

    <BlacklistCategoryCard
      category="path"
      title="Path Blacklist"
      subtitle="Flag HTTP requests to a specific request path."
      value-label="Path"
      value-placeholder="/wp-admin/setup-config.php"
      icon="mdi-routes"
      :entries="entriesFor('path')"
      :submitting="submittingCategory === 'path'"
      :error="formErrorFor('path')"
      class="mt-4"
      @create="createEntry"
      @toggle="toggleEntry"
      @delete="deleteEntry"
    />
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
      entries: [],
      error: "",
      submittingCategory: "",
      formErrors: { ip: "", domain: "", path: "" },
      togglePending: "",
    };
  },
  mounted() {
    this.load();
  },
  methods: {
    entriesFor(category) {
      return this.entries.filter((entry) => entry.category === category);
    },
    formErrorFor(category) {
      return this.formErrors[category] || "";
    },
    load() {
      this.error = "";
      return this.store
        .listBlacklistEntries()
        .then((payload) => {
          this.entries = this.store.extractArray(payload);
        })
        .catch((err) => {
          this.error = (err && err.message) || "Failed to load blacklist entries";
        });
    },
    createEntry({ category, matchType, value, label }) {
      this.formErrors[category] = "";
      this.submittingCategory = category;
      this.store
        .createBlacklistEntry({ category, matchType, value, label })
        .then(() => this.load())
        .catch((err) => {
          this.formErrors[category] = (err && err.message) || "Failed to add entry";
        })
        .finally(() => {
          this.submittingCategory = "";
        });
    },
    toggleEntry(entry, value) {
      this.togglePending = entry.id;
      this.store
        .toggleBlacklistEntry(entry.id, value)
        .then(() => this.load())
        .catch((err) => {
          this.error = (err && err.message) || "Failed to update entry";
        })
        .finally(() => {
          this.togglePending = "";
        });
    },
    deleteEntry(entry) {
      this.store
        .deleteBlacklistEntry(entry.id)
        .then(() => this.load())
        .catch((err) => {
          this.error = (err && err.message) || "Failed to delete entry";
        });
    },
  },
};
</script>
