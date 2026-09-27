<template>
  <div>
    <v-alert type="info" variant="tonal" density="comfortable" class="mb-4">
      Las entradas de bloqueo crean detecciones y alertas automáticamente. Las entradas permitidas
      impiden que los paquetes coincidentes se guarden: no solo se silencian reglas y alertas,
      también se descartan de la captura igual que una IP purgada desde Configuración. Usa
      exclusiones (Configuración &gt; Exclusiones) si quieres silenciar detección sin ocultar el tráfico.
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
          title: "Lista de bloqueo",
          description: "Las coincidencias se elevan a detecciones y alertas.",
          icon: "mdi-cancel",
          color: "error",
        },
        {
          kind: "whitelist",
          title: "Lista permitida",
          description: "Las coincidencias permanecen en captura, pero no disparan detecciones.",
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
          title: `IP ${blacklist ? "bloqueadas" : "permitidas"}`,
          subtitle: blacklist
            ? "Marca tráfico hacia o desde una IP concreta."
            : "Confía en tráfico hacia o desde una IP concreta.",
          valueLabel: "Dirección IP",
          valuePlaceholder: "203.0.113.5",
          icon: "mdi-ip-network-outline",
        },
        {
          category: "domain",
          title: `Dominios ${blacklist ? "bloqueados" : "permitidos"}`,
          subtitle: blacklist
            ? "Marca consultas DNS o tráfico HTTP/TLS que referencia un dominio."
            : "Confía en consultas DNS o tráfico HTTP/TLS que referencia un dominio.",
          valueLabel: "Dominio",
          valuePlaceholder: blacklist ? "evil.example.com" : "trusted.example.com",
          icon: "mdi-web",
        },
        {
          category: "path",
          title: `Paths ${blacklist ? "bloqueados" : "permitidos"}`,
          subtitle: blacklist
            ? "Marca solicitudes HTTP hacia un path concreto."
            : "Confía en solicitudes HTTP hacia un path concreto.",
          valueLabel: "Path",
          valuePlaceholder: blacklist ? "/wp-admin/setup-config.php" : "/health",
          icon: "mdi-routes",
        },
        {
          category: "port",
          title: `Puertos ${blacklist ? "bloqueados" : "permitidos"}`,
          subtitle: blacklist
            ? "Marca tráfico que toque un puerto origen o destino concreto."
            : "Confía en tráfico que toque un puerto origen o destino concreto.",
          valueLabel: "Puerto",
          valuePlaceholder: blacklist ? "3389" : "443",
          icon: "mdi-ethernet-cable",
        },
        {
          category: "protocol",
          title: `Protocolos ${blacklist ? "bloqueados" : "permitidos"}`,
          subtitle: blacklist
            ? "Marca tráfico decodificado como un protocolo de transporte o aplicación."
            : "Confía en tráfico decodificado como un protocolo de transporte o aplicación.",
          valueLabel: "Protocolo",
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
          this.error = (err && err.message) || "No se pudieron cargar las entradas de listas";
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
          this.formErrors[key] = (err && err.message) || "No se pudo agregar la entrada";
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
          this.error = (err && err.message) || "No se pudo actualizar la entrada";
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
          this.error = (err && err.message) || "No se pudo eliminar la entrada";
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
