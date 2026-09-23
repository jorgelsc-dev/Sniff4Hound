<template>
  <div class="location-picker">
    <div class="location-map-wrap">
      <svg
        :viewBox="`0 0 ${width} ${height}`"
        class="location-map"
        role="application"
        aria-label="Click the map to set this sensor's location"
        @click="onMapClick"
      >
        <defs>
          <linearGradient :id="oceanId" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stop-color="rgba(8, 20, 34, 0.95)" />
            <stop offset="100%" stop-color="rgba(4, 12, 22, 0.95)" />
          </linearGradient>
        </defs>

        <rect x="0" y="0" :width="width" :height="height" :fill="`url(#${oceanId})`" rx="10" />

        <!-- Graticule first, so land sits on top of it. -->
        <g class="location-grid" aria-hidden="true">
          <line
            v-for="lat in [-60, -30, 0, 30, 60]"
            :key="`lat-${lat}`"
            x1="0"
            :y1="latToY(lat)"
            :x2="width"
            :y2="latToY(lat)"
          />
          <line
            v-for="lon in [-120, -60, 0, 60, 120]"
            :key="`lon-${lon}`"
            :x1="lonToX(lon)"
            y1="0"
            :x2="lonToX(lon)"
            :y2="height"
          />
        </g>

        <g class="location-land">
          <path v-for="shape in worldPaths" :key="shape.id" :d="shape.d" />
        </g>

        <g v-if="hasPoint" class="location-marker" :transform="`translate(${markerX}, ${markerY})`">
          <circle r="13" class="location-marker__halo" />
          <circle r="4.5" class="location-marker__dot" />
          <line x1="-9" y1="0" x2="-16" y2="0" />
          <line x1="9" y1="0" x2="16" y2="0" />
          <line x1="0" y1="-9" x2="0" y2="-16" />
          <line x1="0" y1="9" x2="0" y2="16" />
        </g>
      </svg>

      <div v-if="!worldPaths.length" class="location-map-note text-caption text-medium-emphasis">
        {{ geometryError || "Loading world geometry…" }}
      </div>
    </div>

    <v-row dense class="mt-3">
      <v-col cols="12" md="3">
        <v-text-field
          :model-value="latInput"
          label="Latitude"
          type="number"
          step="0.0001"
          min="-90"
          max="90"
          density="compact"
          variant="outlined"
          hide-details="auto"
          @update:model-value="onLatInput"
        />
      </v-col>
      <v-col cols="12" md="3">
        <v-text-field
          :model-value="lonInput"
          label="Longitude"
          type="number"
          step="0.0001"
          min="-180"
          max="180"
          density="compact"
          variant="outlined"
          hide-details="auto"
          @update:model-value="onLonInput"
        />
      </v-col>
      <v-col cols="12" md="6">
        <v-text-field
          :model-value="labelInput"
          label="Site label (optional)"
          placeholder="e.g. Main office"
          density="compact"
          variant="outlined"
          hide-details="auto"
          maxlength="120"
          @update:model-value="onLabelInput"
        />
      </v-col>
    </v-row>
  </div>
</template>

<script>
// Equirectangular projection: longitude and latitude map linearly onto x and
// y. Same projection the Radar map uses in flat mode, so a point picked here
// lands in the same spot there.
const WORLD_GEOJSON_CANDIDATES = ["geo/world-detailed.geojson", "geo/world.geojson"];

export default {
  name: "LocationPicker",
  props: {
    lat: { type: Number, default: null },
    lon: { type: Number, default: null },
    label: { type: String, default: "" },
    width: { type: Number, default: 720 },
    height: { type: Number, default: 340 },
  },
  emits: ["update:lat", "update:lon", "update:label", "picked"],
  data() {
    return {
      worldGeoJson: null,
      geometryError: "",
    };
  },
  computed: {
    oceanId() {
      return `loc-ocean-${this._uid || Math.random().toString(36).slice(2)}`;
    },
    hasPoint() {
      return Number.isFinite(this.lat) && Number.isFinite(this.lon);
    },
    markerX() {
      return this.lonToX(this.lon);
    },
    markerY() {
      return this.latToY(this.lat);
    },
    latInput() {
      return Number.isFinite(this.lat) ? Number(this.lat).toFixed(4) : "";
    },
    lonInput() {
      return Number.isFinite(this.lon) ? Number(this.lon).toFixed(4) : "";
    },
    labelInput() {
      return this.label || "";
    },
    worldPaths() {
      const features = Array.isArray(this.worldGeoJson && this.worldGeoJson.features)
        ? this.worldGeoJson.features
        : [];
      const paths = [];
      features.forEach((feature, featureIndex) => {
        const geometry = feature && feature.geometry;
        if (!geometry || !Array.isArray(geometry.coordinates)) return;
        const polygons =
          geometry.type === "Polygon"
            ? [geometry.coordinates]
            : geometry.type === "MultiPolygon"
              ? geometry.coordinates
              : [];
        polygons.forEach((polygon, polygonIndex) => {
          const d = polygon.map((ring) => this.ringToPath(ring)).filter(Boolean).join(" ");
          if (d) paths.push({ id: `land-${featureIndex}-${polygonIndex}`, d });
        });
      });
      return paths;
    },
  },
  mounted() {
    this.loadWorld();
  },
  methods: {
    lonToX(lon) {
      return ((Number(lon) + 180) / 360) * this.width;
    },
    latToY(lat) {
      return ((90 - Number(lat)) / 180) * this.height;
    },
    xToLon(x) {
      return (x / this.width) * 360 - 180;
    },
    yToLat(y) {
      return 90 - (y / this.height) * 180;
    },
    ringToPath(ring) {
      if (!Array.isArray(ring) || ring.length < 2) return "";
      let path = "";
      let prevLon = null;
      ring.forEach((pair, index) => {
        if (!Array.isArray(pair) || pair.length < 2) return;
        const lon = Number(pair[0]);
        const lat = Number(pair[1]);
        if (!Number.isFinite(lon) || !Number.isFinite(lat)) return;
        // Lift the pen when a ring wraps the antimeridian, otherwise the
        // shape is drawn as a band straight across the whole map.
        const command = index === 0 || (prevLon !== null && Math.abs(lon - prevLon) > 180) ? "M" : "L";
        path += `${command}${this.lonToX(lon).toFixed(2)},${this.latToY(lat).toFixed(2)} `;
        prevLon = lon;
      });
      return path ? `${path.trim()} Z` : "";
    },
    onMapClick(event) {
      const svg = event.currentTarget;
      const rect = svg.getBoundingClientRect();
      if (!rect.width || !rect.height) return;
      // The SVG scales to its container, so map client pixels back through
      // the viewBox before inverting the projection.
      const x = ((event.clientX - rect.left) / rect.width) * this.width;
      const y = ((event.clientY - rect.top) / rect.height) * this.height;
      const lon = Math.max(-180, Math.min(180, this.xToLon(x)));
      const lat = Math.max(-90, Math.min(90, this.yToLat(y)));
      this.$emit("update:lat", Number(lat.toFixed(4)));
      this.$emit("update:lon", Number(lon.toFixed(4)));
      this.$emit("picked", { lat: Number(lat.toFixed(4)), lon: Number(lon.toFixed(4)) });
    },
    onLatInput(value) {
      const parsed = Number(value);
      this.$emit("update:lat", Number.isFinite(parsed) ? Math.max(-90, Math.min(90, parsed)) : null);
    },
    onLonInput(value) {
      const parsed = Number(value);
      this.$emit("update:lon", Number.isFinite(parsed) ? Math.max(-180, Math.min(180, parsed)) : null);
    },
    onLabelInput(value) {
      this.$emit("update:label", String(value || ""));
    },
    assetBase() {
      const base = (import.meta.env && import.meta.env.BASE_URL) || "/";
      return base.endsWith("/") ? base : `${base}/`;
    },
    loadWorld() {
      const base = this.assetBase();
      const tryNext = (index = 0) => {
        if (index >= WORLD_GEOJSON_CANDIDATES.length) {
          this.geometryError = "World map unavailable; enter coordinates by hand.";
          return Promise.resolve(null);
        }
        return fetch(`${base}${WORLD_GEOJSON_CANDIDATES[index]}`)
          .then((res) => {
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            return res.json();
          })
          .then((payload) => {
            if (!payload || payload.type !== "FeatureCollection") throw new Error("bad geojson");
            this.worldGeoJson = payload;
            return payload;
          })
          .catch(() => tryNext(index + 1));
      };
      return tryNext();
    },
  },
};
</script>

<style scoped>
.location-map-wrap {
  position: relative;
}

.location-map {
  width: 100%;
  height: auto;
  display: block;
  border-radius: 10px;
  border: 1px solid rgba(var(--brand-sky-rgb), 0.2);
  cursor: crosshair;
}

.location-grid line {
  stroke: rgba(110, 192, 240, 0.14);
  stroke-width: 0.6;
}

.location-land path {
  fill: rgba(46, 96, 140, 0.55);
  stroke: rgba(126, 200, 244, 0.35);
  stroke-width: 0.4;
}

.location-marker line {
  stroke: rgba(var(--brand-cyan-rgb), 0.9);
  stroke-width: 1.4;
}

.location-marker__halo {
  fill: rgba(var(--brand-cyan-rgb), 0.16);
  stroke: rgba(var(--brand-cyan-rgb), 0.5);
  stroke-width: 1;
}

.location-marker__dot {
  fill: rgba(var(--brand-cyan-rgb), 0.95);
}

.location-map-note {
  position: absolute;
  inset: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  pointer-events: none;
}
</style>
