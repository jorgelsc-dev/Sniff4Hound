<template>
  <v-card variant="tonal" class="chart-card">
    <div class="d-flex align-start justify-space-between ga-3">
      <div class="chart-card__copy">
        <h2 class="text-subtitle-1">{{ title }}</h2>
        <div v-if="subtitle" class="text-caption text-medium-emphasis">
          {{ subtitle }}
        </div>
      </div>
      <v-chip size="small" variant="outlined" :color="color">
        {{ series.length }}
      </v-chip>
    </div>

    <div v-if="series.length" class="chart-stack mt-4" role="list">
      <div v-for="item in series" :key="item.label" class="chart-row" :class="{ 'chart-row--large': item.value.toLocaleString().length > 10 }" role="listitem">
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
      <v-icon icon="mdi-chart-bar" size="28" />
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
      default: "No hay datos disponibles para este período.",
    },
  },
};
</script>

<style scoped>
.chart-card {
  padding: 20px;
  border-radius: var(--radius-md);
  height: 100%;
  container-type: inline-size;
}

.chart-card__copy { min-width: 0; }
.chart-card__copy h2 { overflow-wrap: anywhere; }

.chart-stack {
  display: grid;
  gap: 9px;
}

.chart-row {
  display: grid;
  grid-template-columns: minmax(0, 1.15fr) minmax(40px, 2.7fr) minmax(5ch, max-content);
  align-items: center;
  gap: 10px;
  min-width: 0;
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
  height: 8px;
  overflow: hidden;
  border-radius: 4px;
  background: rgba(9, 16, 24, 0.78);
  box-shadow: inset 0 0 0 1px rgba(103, 176, 219, 0.08);
}

.chart-row__fill {
  height: 100%;
  border-radius: inherit;
}

.chart-row__value {
  min-width: 3ch;
  max-width: 100%;
  overflow-wrap: anywhere;
  text-align: right;
  color: rgba(229, 241, 252, 0.92);
  font-family: var(--font-mono);
  font-size: 0.82rem;
}

.chart-empty {
  min-height: 118px;
  display: grid;
  place-items: center;
  align-content: center;
  gap: 8px;
  padding: 16px 0 4px;
  font-size: 0.92rem;
  color: var(--text-dim);
  text-align: center;
}

@container (max-width: 340px) {
  .chart-row {
    grid-template-columns: minmax(0, 1fr) minmax(5ch, auto);
  }

  .chart-row__track {
    grid-column: 1 / -1;
    order: 3;
  }

  .chart-row--large {
    grid-template-columns: minmax(0, 1fr);
  }

  .chart-row--large .chart-row__value {
    text-align: left;
  }
}

@media (max-width: 600px) {
  .chart-card { padding: 16px; }
}
</style>
