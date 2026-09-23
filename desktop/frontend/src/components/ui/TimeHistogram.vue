<template>
  <DataPanel
    :title="title"
    :subtitle="subtitle"
    variant="tonal"
    :loading="loading"
    :show-skeleton="false"
    :error="error"
    :last-updated="lastUpdated"
    :count="total"
    :count-label="countLabel"
    class="histogram-panel"
  >
    <template #header-actions>
      <slot name="header-actions" />
    </template>

    <div v-if="!buckets.length" class="histogram-empty text-medium-emphasis">
      {{ emptyText }}
    </div>

    <div v-else class="histogram">
      <div class="histogram-plot" :style="{ height: `${height}px` }">
        <!-- Horizontal guides, drawn behind the bars, so a bar's height can
             actually be read off the axis instead of guessed. -->
        <div class="histogram-grid" aria-hidden="true">
          <div v-for="line in gridLines" :key="`grid-${line.value}`" class="histogram-grid__line" :style="{ bottom: `${line.offset}%` }">
            <span class="histogram-grid__label">{{ formatCount(line.value) }}</span>
          </div>
        </div>

        <div class="histogram-bars" role="img" :aria-label="accessibleSummary">
          <div
            v-for="bucket in buckets"
            :key="bucket.key"
            class="histogram-bar"
            :class="{ 'histogram-bar--empty': !bucket.count }"
          >
            <div
              class="histogram-bar__fill"
              :style="{ height: `${bucket.heightPercent}%` }"
            />
            <v-tooltip activator="parent" location="top">
              <div class="histogram-tip">
                <strong>{{ formatCount(bucket.count) }}</strong> {{ countLabel }}
                <div class="text-caption">{{ bucket.rangeLabel }}</div>
              </div>
            </v-tooltip>
          </div>
        </div>
      </div>

      <div class="histogram-axis">
        <span v-for="tick in axisTicks" :key="`tick-${tick.key}`" class="histogram-axis__tick">
          {{ tick.label }}
        </span>
      </div>
    </div>
  </DataPanel>
</template>

<script>
import DataPanel from "./DataPanel.vue";

export default {
  name: "TimeHistogram",
  components: { DataPanel },
  props: {
    title: { type: String, default: "Volume over time" },
    subtitle: { type: String, default: "" },
    rows: { type: Array, default: () => [] },
    // Which field carries the timestamp. Rows missing it are ignored rather
    // than bucketed at the epoch, which would flatten the whole chart.
    timestampKey: { type: String, default: "created_at" },
    bucketCount: { type: Number, default: 48 },
    height: { type: Number, default: 132 },
    countLabel: { type: String, default: "packets" },
    emptyText: { type: String, default: "No data in this window yet" },
    loading: { type: Boolean, default: false },
    error: { type: String, default: "" },
    lastUpdated: { type: String, default: "" },
  },
  computed: {
    timestamps() {
      const key = this.timestampKey;
      const values = [];
      for (const row of this.rows || []) {
        const raw = row && row[key];
        if (!raw) continue;
        const parsed = Date.parse(raw);
        if (!Number.isNaN(parsed)) values.push(parsed);
      }
      return values;
    },
    total() {
      return this.timestamps.length;
    },
    buckets() {
      const stamps = this.timestamps;
      if (!stamps.length) return [];

      const min = Math.min(...stamps);
      const max = Math.max(...stamps);
      const count = Math.max(1, Math.floor(this.bucketCount));
      // A capture that spans no time at all (one packet, or many within the
      // same millisecond) would divide by zero; give it a nominal 1s window.
      const span = max - min || 1000;
      const width = span / count;

      const totals = new Array(count).fill(0);
      for (const stamp of stamps) {
        const index = Math.min(count - 1, Math.floor((stamp - min) / width));
        totals[index] += 1;
      }

      const peak = Math.max(...totals) || 1;
      return totals.map((value, index) => {
        const start = new Date(min + index * width);
        const end = new Date(min + (index + 1) * width);
        return {
          key: index,
          count: value,
          heightPercent: (value / peak) * 100,
          start,
          rangeLabel: `${this.formatTime(start)} – ${this.formatTime(end)}`,
        };
      });
    },
    peakCount() {
      return this.buckets.reduce((max, bucket) => Math.max(max, bucket.count), 0);
    },
    gridLines() {
      const peak = this.peakCount;
      if (!peak) return [];
      return [0.5, 1].map((fraction) => ({
        value: Math.round(peak * fraction),
        offset: fraction * 100,
      }));
    },
    axisTicks() {
      const buckets = this.buckets;
      if (!buckets.length) return [];
      // Only the ends and the middle: any more and the labels collide at the
      // widths this sits in.
      const picks = [0, Math.floor(buckets.length / 2), buckets.length - 1];
      return [...new Set(picks)].map((index) => ({
        key: index,
        label: this.formatTime(buckets[index].start),
      }));
    },
    accessibleSummary() {
      if (!this.buckets.length) return this.emptyText;
      const first = this.axisTicks[0];
      const last = this.axisTicks[this.axisTicks.length - 1];
      return `${this.total} ${this.countLabel} between ${first ? first.label : "?"} and ${last ? last.label : "?"}, peak ${this.peakCount} per bucket`;
    },
  },
  methods: {
    formatTime(date) {
      try {
        return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
      } catch {
        return "";
      }
    },
    formatCount(value) {
      return Number(value || 0).toLocaleString();
    },
  },
};
</script>

<style scoped>
.histogram-plot {
  position: relative;
  width: 100%;
}

.histogram-grid {
  position: absolute;
  inset: 0;
  pointer-events: none;
}

.histogram-grid__line {
  position: absolute;
  left: 0;
  right: 0;
  border-top: 1px dashed rgba(var(--brand-sky-rgb), 0.16);
}

.histogram-grid__label {
  position: absolute;
  right: 0;
  top: -0.85em;
  font-size: 0.65rem;
  color: rgba(255, 255, 255, 0.4);
  background: rgba(5, 10, 18, 0.75);
  padding: 0 4px;
  border-radius: 4px;
}

.histogram-bars {
  position: relative;
  display: flex;
  align-items: flex-end;
  gap: 2px;
  height: 100%;
}

.histogram-bar {
  flex: 1 1 0;
  height: 100%;
  display: flex;
  align-items: flex-end;
  min-width: 2px;
  cursor: default;
}

.histogram-bar__fill {
  width: 100%;
  min-height: 2px;
  border-radius: 2px 2px 0 0;
  background: linear-gradient(
    180deg,
    rgba(var(--brand-cyan-rgb), 0.95),
    rgba(var(--brand-cyan-rgb), 0.35)
  );
  transition: height 0.18s ease-out;
}

/* An empty bucket keeps a hairline so gaps in the capture read as gaps
   rather than as the chart ending. */
.histogram-bar--empty .histogram-bar__fill {
  background: rgba(var(--brand-sky-rgb), 0.14);
}

.histogram-bar:hover .histogram-bar__fill {
  filter: brightness(1.25);
}

.histogram-axis {
  display: flex;
  justify-content: space-between;
  margin-top: 6px;
  font-size: 0.68rem;
  color: rgba(255, 255, 255, 0.45);
}

.histogram-empty {
  padding: 18px 0;
  text-align: center;
  font-size: 0.85rem;
}

.histogram-tip strong {
  font-size: 1rem;
}
</style>
