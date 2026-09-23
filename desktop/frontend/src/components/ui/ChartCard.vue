<template>
  <v-card variant="tonal" class="pa-5 chart-card">
    <div class="d-flex align-start justify-space-between ga-3">
      <div>
        <div class="text-subtitle-1">{{ title }}</div>
        <div v-if="subtitle" class="text-caption text-medium-emphasis">
          {{ subtitle }}
        </div>
      </div>
      <v-chip size="small" variant="outlined" :color="color">
        {{ series.length }}
      </v-chip>
    </div>

    <div v-if="series.length" class="chart-stack mt-4">
      <div v-for="item in series" :key="item.label" class="chart-row">
        <div class="chart-row__label" :title="item.label">
          {{ item.label }}
        </div>
        <div class="chart-row__track" aria-hidden="true">
          <div class="chart-row__fill" :style="{ width: `${item.width}%`, background: fill }" />
        </div>
        <div class="chart-row__value">
          {{ item.value.toLocaleString() }}
        </div>
      </div>
    </div>

    <div v-else class="chart-empty text-medium-emphasis mt-4">
      {{ emptyText }}
    </div>
  </v-card>
</template>

<script>
export default {
  name: "ChartCard",
  props: {
    title: {
      type: String,
      required: true,
    },
    subtitle: {
      type: String,
      default: "",
    },
    series: {
      type: Array,
      default: () => [],
    },
    fill: {
      type: String,
      default: "linear-gradient(90deg, rgba(52, 230, 255, 0.94), rgba(74, 136, 255, 0.85))",
    },
    color: {
      type: String,
      default: "primary",
    },
    emptyText: {
      type: String,
      default: "No data available for this slice.",
    },
  },
};
</script>

<style scoped>
.chart-card {
  border-radius: 16px;
  height: 100%;
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
</style>
