<template>
  <div class="view-header d-flex align-start justify-space-between flex-wrap mb-4 ga-3">
    <div class="view-header__copy">
      <div v-if="overline" class="text-overline text-primary">{{ overline }}</div>
      <div class="text-h5 font-weight-bold view-header__title">{{ title }}</div>
      <div v-if="description" class="text-body-2 text-medium-emphasis view-header__description">
        {{ description }}
      </div>
    </div>
    <div class="d-flex align-center ga-2 header-actions">
      <div v-if="showTimeRange" class="time-range" role="group" aria-label="Time range">
        <v-btn-toggle
          :model-value="activeTimeRange"
          density="compact"
          variant="outlined"
          divided
          mandatory
          color="primary"
          class="time-range-toggle"
          @update:model-value="selectTimeRange"
        >
          <v-btn
            v-for="option in timeRangeOptions"
            :key="`range-${option.value || 'all'}`"
            :value="option.value"
            size="small"
          >
            {{ option.label }}
            <v-tooltip activator="parent" location="bottom">{{ option.description }}</v-tooltip>
          </v-btn>
        </v-btn-toggle>
      </div>
      <!-- Extra per-view actions sit before the refresh button without
           having to override (and re-implement) the default slot. -->
      <slot name="actions-prepend" />
      <slot name="actions">
        <v-btn
          v-if="showRefresh"
          icon="mdi-refresh"
          variant="outlined"
          color="primary"
          density="comfortable"
          :loading="refreshLoading"
          :aria-label="refreshLabel"
          @click="$emit('refresh')"
        >
          <v-icon icon="mdi-refresh" />
          <v-tooltip activator="parent" location="bottom">{{ refreshLabel }}</v-tooltip>
        </v-btn>
      </slot>
    </div>
  </div>
</template>

<script>
import store from "../../state/appStore";

export default {
  name: "ViewHeader",
  props: {
    overline: {
      type: String,
      default: "",
    },
    title: {
      type: String,
      required: true,
    },
    description: {
      type: String,
      default: "",
    },
    showRefresh: {
      type: Boolean,
      default: true,
    },
    refreshLabel: {
      type: String,
      default: "Refresh",
    },
    refreshLoading: {
      type: Boolean,
      default: false,
    },
    // Opt-in per view: only the views that actually forward `since` to their
    // endpoints should advertise a time range the user can change.
    showTimeRange: {
      type: Boolean,
      default: false,
    },
  },
  emits: ["refresh"],
  data() {
    return {
      store,
    };
  },
  computed: {
    timeRangeOptions() {
      return this.store.timeRangeOptions;
    },
    // The range lives in the store so it survives navigation between views.
    activeTimeRange() {
      return this.store.state.timeRange || "";
    },
  },
  methods: {
    selectTimeRange(value) {
      this.store.setTimeRange(value);
      // Reuse the view's existing @refresh wiring: changing the window has to
      // re-query the API, not just re-render what is already loaded.
      this.$emit("refresh");
    },
  },
};
</script>

<style scoped>
.view-header {
  position: relative;
  padding-bottom: 2px;
}

.view-header::after {
  content: "";
  position: absolute;
  left: 0;
  right: 0;
  bottom: -7px;
  height: 1px;
  background: linear-gradient(
    90deg,
    rgba(255, 255, 255, 0.16),
    rgba(255, 255, 255, 0.06),
    transparent
  );
}

.view-header__copy {
  flex: 1 1 360px;
  min-width: min(100%, 280px);
  max-width: 820px;
}

.view-header__title {
  letter-spacing: 0;
  overflow-wrap: anywhere;
}

.view-header__description {
  max-width: 72ch;
  overflow-wrap: anywhere;
}

.header-actions {
  flex: 0 1 auto;
  flex-wrap: wrap;
  min-height: 34px;
  justify-content: flex-end;
  margin-left: auto;
}

.time-range-toggle {
  height: 32px;
  border-radius: 8px;
}

.time-range-toggle :deep(.v-btn) {
  min-width: 44px;
  padding-inline: 8px;
  font-size: 0.74rem;
  letter-spacing: 0.04em;
}

@media (max-width: 600px) {
  .view-header {
    display: block !important;
  }

  .header-actions {
    width: 100%;
    justify-content: flex-start;
    margin-left: 0;
    overflow-x: auto;
    padding-bottom: 2px;
  }

  .time-range-toggle :deep(.v-btn) {
    min-width: 38px;
    padding-inline: 5px;
  }
}
</style>
