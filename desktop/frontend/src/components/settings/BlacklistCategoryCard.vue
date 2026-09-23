<template>
  <DataPanel :title="title" :subtitle="subtitle" variant="tonal" :count="entries.length" count-label="entries">
    <template #header-actions>
      <v-icon :icon="icon" />
    </template>

    <v-form @submit.prevent="submit">
      <v-row dense align="center">
        <v-col cols="12" sm="4">
          <v-text-field
            v-model.trim="draft.value"
            :label="valueLabel"
            :placeholder="valuePlaceholder"
            variant="outlined"
            density="comfortable"
            hide-details
          />
        </v-col>
        <v-col cols="6" sm="3">
          <v-select
            v-model="draft.matchType"
            :items="[{ title: 'Exact', value: 'exact' }, { title: 'Regex', value: 'regex' }]"
            label="Match type"
            variant="outlined"
            density="comfortable"
            hide-details
          />
        </v-col>
        <v-col cols="6" sm="3">
          <v-text-field
            v-model.trim="draft.label"
            label="Label (optional)"
            variant="outlined"
            density="comfortable"
            hide-details
          />
        </v-col>
        <v-col cols="12" sm="2" class="d-flex align-center ga-1">
          <RegexHelperButton
            v-if="draft.matchType === 'regex'"
            :initial-value="draft.value"
            @apply="(pattern) => (draft.value = pattern)"
          />
          <v-btn color="primary" variant="tonal" type="submit" :loading="submitting" block>
            Add
          </v-btn>
        </v-col>
      </v-row>
      <v-alert v-if="error" type="error" variant="tonal" density="comfortable" class="mt-2">
        {{ error }}
      </v-alert>
    </v-form>

    <v-table density="comfortable" class="mt-4 blacklist-table">
      <thead>
        <tr>
          <th>Value</th>
          <th>Match</th>
          <th>Label</th>
          <th>Enabled</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        <tr v-if="!entries.length">
          <td colspan="5" class="text-medium-emphasis text-center py-4">No entries yet.</td>
        </tr>
        <tr v-for="entry in entries" :key="entry.id">
          <td class="mono">{{ entry.value }}</td>
          <td>
            <v-chip size="x-small" :color="entry.match_type === 'regex' ? 'info' : 'secondary'" variant="tonal">
              {{ entry.match_type }}
            </v-chip>
          </td>
          <td>{{ entry.label || "-" }}</td>
          <td>
            <v-switch
              :model-value="entry.enabled"
              density="compact"
              hide-details
              color="success"
              @update:model-value="(value) => $emit('toggle', entry, value)"
            />
          </td>
          <td>
            <v-btn icon="mdi-delete-outline" size="small" variant="text" color="error" @click="$emit('delete', entry)" />
          </td>
        </tr>
      </tbody>
    </v-table>
  </DataPanel>
</template>

<script>
import DataPanel from "../ui/DataPanel.vue";
import RegexHelperButton from "../ui/RegexHelperButton.vue";

export default {
  name: "BlacklistCategoryCard",
  components: {
    DataPanel,
    RegexHelperButton,
  },
  props: {
    category: { type: String, required: true },
    title: { type: String, required: true },
    subtitle: { type: String, default: "" },
    valueLabel: { type: String, required: true },
    valuePlaceholder: { type: String, default: "" },
    icon: { type: String, default: "mdi-cancel" },
    entries: { type: Array, default: () => [] },
    submitting: { type: Boolean, default: false },
    error: { type: String, default: "" },
  },
  emits: ["create", "toggle", "delete"],
  data() {
    return {
      draft: { value: "", matchType: "exact", label: "" },
    };
  },
  watch: {
    submitting(value) {
      if (!value && !this.error) {
        this.draft.value = "";
        this.draft.label = "";
      }
    },
  },
  methods: {
    submit() {
      if (!this.draft.value.trim()) return;
      this.$emit("create", {
        category: this.category,
        matchType: this.draft.matchType,
        value: this.draft.value,
        label: this.draft.label,
      });
    },
  },
};
</script>

<style scoped>
.blacklist-table :deep(th) {
  font-size: 0.72rem;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: rgba(255, 255, 255, 0.5);
}
</style>
