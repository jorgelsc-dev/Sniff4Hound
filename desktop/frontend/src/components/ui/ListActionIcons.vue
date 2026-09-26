<template>
  <span class="list-actions" :class="{ 'list-actions--inline': inline }">
    <v-btn
      v-for="action in actions"
      :key="action.kind"
      :icon="action.icon"
      :color="state === action.kind ? action.color : undefined"
      :loading="submitting === action.kind"
      :disabled="Boolean(submitting) || !value"
      :aria-label="action.aria"
      size="x-small"
      variant="text"
      density="comfortable"
      class="list-actions__btn"
      :class="{ 'is-confirmed': state === action.kind }"
      @click.stop.prevent="run(action.kind)"
    >
      <v-icon :icon="state === action.kind ? action.doneIcon : action.icon" size="17" />
      <v-tooltip activator="parent" location="top" open-delay="200">{{ action.tooltip }}</v-tooltip>
    </v-btn>
  </span>
</template>

<script>
import store from "../../state/appStore";

// Matches SniffStore.BLACKLIST_CATEGORIES; anything else is rejected by the
// API, so the component refuses to render rather than offering a button that
// can only fail.
const CATEGORIES = new Set(["ip", "domain", "path", "port", "protocol"]);
const CATEGORY_LABEL = {
  ip: "IP",
  domain: "dominio",
  path: "ruta",
  port: "puerto",
  protocol: "protocolo",
};
// How long the button stays in its confirmed state before returning to normal.
const CONFIRM_MS = 2200;

export default {
  name: "ListActionIcons",
  props: {
    value: { type: [String, Number], default: "" },
    category: { type: String, default: "ip" },
    // Sits flush against a table cell's text rather than as a standalone group.
    inline: { type: Boolean, default: false },
  },
  emits: ["added", "failed"],
  data() {
    return { store, submitting: "", state: "", timer: null };
  },
  computed: {
    label() {
      return CATEGORY_LABEL[this.category] || this.category;
    },
    actions() {
      const target = `${this.label} ${this.value}`;
      return [
        {
          kind: "whitelist",
          icon: "mdi-shield-check-outline",
          doneIcon: "mdi-shield-check",
          color: "success",
          tooltip: this.state === "whitelist" ? "Añadida a la whitelist" : `Confiar en ${target}`,
          aria: `Añadir ${target} a la whitelist`,
        },
        {
          kind: "blacklist",
          icon: "mdi-shield-alert-outline",
          doneIcon: "mdi-shield-alert",
          color: "error",
          tooltip: this.state === "blacklist" ? "Añadida a la blacklist" : `Bloquear ${target}`,
          aria: `Añadir ${target} a la blacklist`,
        },
      ];
    },
  },
  beforeUnmount() {
    clearTimeout(this.timer);
  },
  methods: {
    // Returns the in-flight request so a caller (or a test) can wait for the
    // outcome instead of guessing when it landed.
    run(kind) {
      const value = String(this.value || "").trim();
      if (!value || this.submitting || !CATEGORIES.has(this.category)) {
        return Promise.resolve();
      }
      this.submitting = kind;
      const payload = {
        category: this.category,
        matchType: "exact",
        value,
        label: `${kind === "whitelist" ? "Trusted" : "Blocked"} ${this.label}: ${value}`,
      };
      // createWhitelistEntry, not whitelistIpAndForget: this button appears on
      // every row, and the "forget" variant irreversibly purges that host's
      // stored history (see FAQA.md / purge_ip_data). A one-click control in a
      // table must not be able to destroy data.
      const request = kind === "whitelist"
        ? this.store.createWhitelistEntry(payload)
        : this.store.createBlacklistEntry(payload);
      return request
        .then(() => {
          this.state = kind;
          clearTimeout(this.timer);
          this.timer = setTimeout(() => { this.state = ""; }, CONFIRM_MS);
          this.$emit("added", { kind, value, category: this.category });
        })
        .catch((err) => {
          const message = (err && err.message) || `No se pudo añadir ${value} a la ${kind}.`;
          this.store.pushNotification({
            kind: "runtime",
            severity: "medium",
            title: `No se pudo actualizar la ${kind}`,
            message,
            groupKey: `list-action:${kind}:${value}`,
          });
          this.$emit("failed", { kind, value, message });
        })
        .finally(() => {
          this.submitting = "";
        });
    },
  },
};
</script>

<style scoped>
.list-actions { display: inline-flex; align-items: center; gap: 1px; }
.list-actions--inline { margin-left: 4px; vertical-align: middle; }
/* Dimmed rather than hidden-until-hover: these are meant to be easy to reach,
   and a control that only exists on hover is invisible to a touch screen and
   easy to miss entirely. Full strength on hover, focus, and once confirmed. */
.list-actions--inline .list-actions__btn {
  opacity: 0.5;
  transition: opacity 120ms ease;
}
.list-actions--inline .list-actions__btn:hover,
.list-actions--inline .list-actions__btn:focus-visible,
.list-actions--inline .list-actions__btn.is-confirmed,
tr:hover .list-actions--inline .list-actions__btn {
  opacity: 1;
}
</style>
