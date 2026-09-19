<template>
  <component
    :is="canvasOnly ? 'section' : 'DataPanel'"
    :class="{ 'map-canvas': canvasOnly }"
    :style="canvasOnly ? { '--map-dock-height': `${dockHeight}px` } : undefined"
    :title="panelTitle"
    :subtitle="panelSubtitle"
    :loading="loading"
    :error="error"
    :last-updated="lastUpdated"
    :show-header="showPanelHeader"
    :keep-content-on-loading="true"
  >
    <template #skeleton>
      <v-skeleton-loader type="image, table-thead, table-row@4" class="skeleton-block" />
    </template>

    <div v-if="showIntro" class="map-intro">
      <div class="map-intro__eyebrow">Live telemetry viewport</div>
      <div class="map-intro__title">{{ isGlobeMode ? "Orbital Telemetry Globe" : "Live Telemetry Map" }}</div>
      <div class="map-intro__description">
        {{
          isGlobeMode
            ? "Orthographic globe with auto-rotation, front-hemisphere clustering, and animated route traces."
            : "Only public IPs render on the map. Packet traces enter from outside the frame to keep focus on routable hosts."
        }}
      </div>
      <div v-if="statusInfoText || geoipInfoText" class="map-intro__meta">
        <span v-if="statusInfoText">{{ statusInfoText }}</span>
        <span
          v-if="statusInfoText && geoipInfoText"
          class="map-intro__meta-divider"
          aria-hidden="true"
        ></span>
        <span v-if="geoipInfoText">{{ geoipInfoText }}</span>
      </div>
    </div>

    <div
      class="map-wrapper"
      :class="[
        showIntro ? 'mt-4' : '',
        { 'map-wrapper--immersive': immersive, 'map-wrapper--globe': isGlobeMode },
      ]"
    >
      <div v-if="showProjectionSwitch || immersive" class="map-overlay">
        <div v-if="showProjectionSwitch" class="map-overlay__group">
          <div class="map-overlay__label">Projection</div>
          <v-btn-toggle
            v-model="projectionMode"
            mandatory
            density="comfortable"
            color="primary"
            variant="outlined"
            class="map-projection-toggle"
          >
            <v-btn value="flat" size="small">Mercator</v-btn>
            <v-btn value="globe" size="small">Globe</v-btn>
          </v-btn-toggle>
        </div>

        <div v-if="!isGlobeMode" class="map-zoom-controls">
          <v-btn icon size="small" variant="text" aria-label="Alejar mapa" :disabled="mapZoom <= 1" @click="zoomMap(mapZoom / 1.25)"><v-icon icon="mdi-minus" /></v-btn>
          <span>{{ Math.round(mapZoom * 100) }}%</span>
          <v-btn icon size="small" variant="text" aria-label="Acercar mapa" :disabled="mapZoom >= 8" @click="zoomMap(mapZoom * 1.25)"><v-icon icon="mdi-plus" /></v-btn>
          <v-btn icon size="small" variant="text" aria-label="Restablecer mapa" @click="resetMapView"><v-icon icon="mdi-fit-to-screen-outline" /></v-btn>
        </div>
      </div>

      <svg
        ref="mapSvg"
        :class="{ 'map-interactive': !isGlobeMode }"
        @wheel="onMapWheel"
        @pointerdown="startMapPan"
        @pointermove="moveMapPan"
        @pointerup="endMapPan"
        @pointercancel="endMapPan"
        @click.capture="guardMapClick"
        :viewBox="`0 0 ${mapWidth} ${mapHeight}`"
        preserveAspectRatio="xMidYMid meet"
        role="img"
        aria-label="Sniff4Hound geolocated telemetry map"
      >
        <defs>
          <linearGradient :id="landGradientId" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stop-color="rgba(102, 255, 210, 0.28)" />
            <stop offset="55%" stop-color="rgba(76, 175, 228, 0.18)" />
            <stop offset="100%" stop-color="rgba(48, 102, 160, 0.22)" />
          </linearGradient>
          <linearGradient :id="frameGradientId" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stop-color="rgba(85, 219, 255, 0.18)" />
            <stop offset="50%" stop-color="rgba(94, 248, 190, 0.6)" />
            <stop offset="100%" stop-color="rgba(255, 172, 78, 0.18)" />
          </linearGradient>
          <filter :id="arcGlowFilterId" x="-30%" y="-30%" width="160%" height="160%">
            <feGaussianBlur stdDeviation="3.4" result="blurred" />
            <feMerge>
              <feMergeNode in="blurred" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
          <filter :id="pointGlowFilterId" x="-80%" y="-80%" width="260%" height="260%">
            <feGaussianBlur stdDeviation="4.2" result="pointBlur" />
            <feMerge>
              <feMergeNode in="pointBlur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
          <clipPath :id="globeClipId">
            <circle :cx="globeCenterX" :cy="globeCenterY" :r="globeRadius" />
          </clipPath>
        </defs>

        <rect
          x="0"
          y="0"
          :width="mapWidth"
          :height="mapHeight"
          fill="rgba(4, 10, 18, 0.94)"
        />

        <g :transform="isGlobeMode ? undefined : `translate(${mapPan.x} ${mapPan.y}) scale(${mapZoom})`">
        <template v-if="!isGlobeMode">
          <!-- No ocean plate on the flat projection: the panel's own backdrop
               shows through instead. The inner frame below stays, since it is
               what still bounds the drawing area. -->
          <rect
            v-if="!canvasOnly"
            :x="mapPadding + 6"
            :y="mapPadding + 6"
            :width="mapWidth - (mapPadding * 2) - 12"
            :height="mapHeight - (mapPadding * 2) - 12"
            fill="none"
            :stroke="`url(#${frameGradientId})`"
            stroke-width="1"
            rx="12"
            opacity="0.72"
          />
        </template>

        <template v-else>
          <circle
            :cx="globeCenterX"
            :cy="globeCenterY"
            :r="globeRadius"
            fill="rgba(9, 34, 60, 0.96)"
            stroke="rgba(111, 216, 255, 0.34)"
            stroke-width="1.1"
          />
        </template>

        <g v-if="!isGlobeMode" class="map-land">
          <path
            v-for="shape in worldPaths"
            :key="shape.id"
            :d="shape.d"
            :fill="`url(#${landGradientId})`"
            stroke="rgba(143, 231, 202, 0.24)"
            stroke-width="0.9"
            :class="['map-country', { 'map-country--active': shape.active }]"
            @click="selectCountry(shape.iso)"
          >
            <title v-if="shape.name">{{ shape.name }}</title>
          </path>
        </g>

        <g v-if="isGlobeMode" :clip-path="`url(#${globeClipId})`" class="map-land map-land--globe">
          <path
            v-for="shape in worldPaths"
            :key="shape.id"
            :d="shape.d"
            :fill="`url(#${landGradientId})`"
            stroke="rgba(143, 231, 202, 0.22)"
            stroke-width="0.8"
            opacity="0.96"
            :class="['map-country', { 'map-country--active': shape.active }]"
            @click="selectCountry(shape.iso)"
          >
            <title v-if="shape.name">{{ shape.name }}</title>
          </path>
        </g>

        <g class="map-arcs" :clip-path="isGlobeMode ? `url(#${globeClipId})` : null">
          <path
            v-for="arc in arcPaths"
            :key="`glow-${arc.id}`"
            :d="arc.d"
            fill="none"
            :stroke="arc.glow"
            :stroke-width="arc.strokeWidth + 2.8"
            stroke-linecap="round"
            opacity="0.2"
            :filter="`url(#${arcGlowFilterId})`"
          />
          <path
            v-for="arc in arcPaths"
            :key="arc.id"
            :d="arc.d"
            fill="none"
            :stroke="arc.stroke"
            :stroke-width="arc.strokeWidth"
            stroke-linecap="round"
            class="map-arc-flow"
            :style="arc.style"
          />
          <circle
            v-for="arc in arcPaths"
            :key="`trace-${arc.id}`"
            :r="arc.traceRadius"
            :fill="arc.traceColor"
            class="map-arc-trace"
            :filter="`url(#${pointGlowFilterId})`"
          >
            <animateMotion :dur="arc.duration" :begin="arc.begin" repeatCount="indefinite" :path="arc.d" />
          </circle>
        </g>

        <!-- The sensor itself: every private and loopback address collapses
             into this one marker, since none of them can be geolocated. -->
        <g v-if="hasDeclaredOrigin" class="map-origin" :transform="`translate(${originCoord[0]}, ${originCoord[1]})`">
          <circle :r="14" class="map-origin__halo" :filter="`url(#${pointGlowFilterId})`" />
          <circle :r="4.4" class="map-origin__dot" />
          <text v-if="localHostCount" y="-18" text-anchor="middle" class="map-origin__label">
            {{ localHostCount }} local
          </text>
        </g>

        <g v-if="!isGlobeMode" class="map-points">
          <circle
            v-for="point in projectedPublicPoints"
            :key="`glow-${point.id}`"
            :cx="point.x"
            :cy="point.y"
            :r="point.radius * 3.4"
            :fill="point.glowColor"
            opacity="0.24"
            :filter="`url(#${pointGlowFilterId})`"
          />
          <circle
            v-for="point in projectedPublicPoints"
            :key="`ring-${point.id}`"
            :cx="point.x"
            :cy="point.y"
            :r="point.radius * 1.9"
            fill="none"
            :stroke="point.ringColor"
            stroke-width="0.9"
            opacity="0.72"
          />
          <circle
            v-for="point in projectedPublicPoints"
            :key="point.id"
            :cx="point.x"
            :cy="point.y"
            :r="point.radius"
            :fill="point.color"
            stroke="rgba(229, 247, 255, 0.8)"
            stroke-width="0.7"
          />
        </g>

        <g v-else :clip-path="`url(#${globeClipId})`" class="map-points map-points--globe">
          <circle
            v-for="point in projectedPublicPoints"
            :key="`glow-${point.id}`"
            :cx="point.x"
            :cy="point.y"
            :r="point.radius * 4.1"
            :fill="point.glowColor"
            opacity="0.24"
            :filter="`url(#${pointGlowFilterId})`"
          />
          <circle
            v-for="point in projectedPublicPoints"
            :key="`ring-${point.id}`"
            :cx="point.x"
            :cy="point.y"
            :r="point.radius * 2.1"
            fill="none"
            :stroke="point.ringColor"
            stroke-width="0.95"
            opacity="0.78"
          />
          <circle
            v-for="point in projectedPublicPoints"
            :key="point.id"
            :cx="point.x"
            :cy="point.y"
            :r="point.radius"
            :fill="point.color"
            stroke="rgba(229, 247, 255, 0.82)"
            stroke-width="0.74"
          />
        </g>

        </g>
      </svg>

      <!-- Selected country. Anchored over the map rather than below it so the
           shape stays visible while its numbers are read. -->
      <div v-if="selectedCountry" class="map-country-popup">
        <div class="map-country-popup__head">
          <div>
            <div class="map-country-popup__name">{{ selectedCountry.country }}</div>
            <div class="map-country-popup__meta">
              {{ selectedCountry.country_code }}
              <template v-if="selectedCountry.registry"> · {{ selectedCountry.registry.toUpperCase() }}</template>
            </div>
          </div>
          <v-btn icon="mdi-close" size="x-small" variant="text" @click="clearCountry" />
        </div>
        <div class="map-country-popup__stats">
          <div><span>Hosts</span><strong>{{ selectedCountry.hosts }}</strong></div>
          <div><span>Packets</span><strong>{{ selectedCountry.packets }}</strong></div>
          <div><span>Volume</span><strong>{{ formatBytes(selectedCountry.bytes) }}</strong></div>
        </div>
        <div v-if="selectedCountry.protocols && selectedCountry.protocols.length" class="map-country-popup__protos">
          <v-chip
            v-for="item in selectedCountry.protocols"
            :key="item.proto"
            size="x-small"
            variant="tonal"
            color="info"
          >{{ item.proto }} · {{ item.packets }}</v-chip>
        </div>
        <div v-if="selectedCountry.addresses && selectedCountry.addresses.length" class="map-country-popup__ips">
          <router-link
            v-for="ip in selectedCountry.addresses.slice(0, 6)"
            :key="ip"
            class="mono map-ip-link"
            :to="{ path: '/investigate', query: { ip } }"
          >
            {{ ip }}
          </router-link>
          <span v-if="selectedCountry.hosts > 6" class="map-country-popup__more">
            +{{ selectedCountry.hosts - 6 }} more
          </span>
        </div>
      </div>
    </div>

    <section v-if="!mapOnly" ref="infoDock" :class="{ 'map-info-dock': canvasOnly }" aria-label="Telemetry information">
      <div v-if="canvasOnly" class="map-info-dock__heading">
        <div class="map-info-dock__status" role="status">
          <span>{{ statusInfoText }}</span>
          <span>{{ geoipInfoText }}</span>
        </div>
        <v-btn size="small" variant="text" :aria-expanded="detailsOpen" aria-controls="map-host-details" @click="detailsOpen = !detailsOpen">
          Hosts <v-icon :icon="detailsOpen ? 'mdi-chevron-down' : 'mdi-chevron-up'" end />
        </v-btn>
      </div>
      <v-alert v-if="canvasOnly && error" type="error" density="compact" variant="tonal">{{ error }}</v-alert>
      <v-progress-linear v-if="canvasOnly && loading" indeterminate color="primary" aria-label="Loading map" />
    <!-- The same selection, reachable without hunting for a country on the
         map: a small country with heavy traffic is easier to find in a list
         than to click on a projection. -->
    <div v-if="!mapOnly && countryRanking.length" class="map-country-rail">
      <button
        v-for="entry in countryRanking"
        :key="entry.country_code"
        type="button"
        class="map-country-rail__item"
        :class="{ 'map-country-rail__item--on': entry.country_code === selectedCountryIso }"
        @click="selectCountry(entry.country_code)"
      >
        <span class="map-country-rail__code">{{ entry.country_code }}</span>
        <span class="map-country-rail__name">{{ entry.country }}</span>
        <span class="map-country-rail__count">{{ entry.packets }}</span>
      </button>
    </div>

    <div v-if="!mapOnly" class="map-summary">
      <div class="map-summary__item">
        <div class="map-summary__metric">
          <div class="text-caption text-medium-emphasis">Total hosts</div>
          <div class="text-h6 font-weight-bold text-primary">{{ summary.total_hosts }}</div>
        </div>
      </div>
      <div class="map-summary__item">
        <div class="map-summary__metric">
          <div class="text-caption text-medium-emphasis">Public hosts</div>
          <div class="text-h6 font-weight-bold text-success">{{ summary.public_hosts }}</div>
        </div>
      </div>
      <div class="map-summary__item">
        <div class="map-summary__metric">
          <div class="text-caption text-medium-emphasis">Unmapped public</div>
          <div class="text-h6 font-weight-bold text-warning">{{ summary.unmapped_public_hosts }}</div>
        </div>
      </div>
      <div class="map-summary__item">
        <div class="map-summary__metric">
          <div class="text-caption text-medium-emphasis">Active services</div>
          <div class="text-h6 font-weight-bold text-secondary">{{ summary.total_open_ports }}</div>
        </div>
      </div>
    </div>

    <v-table v-if="!mapOnly && (!canvasOnly || detailsOpen)" id="map-host-details" density="compact" class="mt-4 map-host-details">
      <thead>
        <tr>
          <th>IP</th>
          <th>Scope</th>
          <th>Region</th>
          <th>Active services</th>
          <th>Protocols</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="item in latestHosts" :key="item.id">
          <td>
            <router-link class="mono map-ip-link" :to="{ path: '/investigate', query: { ip: item.ip } }">
              {{ item.ip }}
            </router-link>
          </td>
          <td>{{ item.scope }}</td>
          <td>{{ item.region }}</td>
          <td>{{ item.open_port_count }}</td>
          <td>{{ item.protocols }}</td>
        </tr>
        <tr v-if="!latestHosts.length">
          <td colspan="5" class="text-center py-4 text-medium-emphasis">
            No hosts yet.
          </td>
        </tr>
      </tbody>
    </v-table>
    </section>
  </component>
</template>

<script>
import { geoArea, geoOrthographic, geoPath } from "d3";
import store from "../state/appStore";
import { appBaseUrl } from "../utils/runtimeEnv";
import DataPanel from "./ui/DataPanel.vue";

const GLOBE_ROTATION_SPEED = 3.2;
// ~25 fps: the ceiling on how often the globe re-projects, not how often
// the browser paints.
const GLOBE_FRAME_INTERVAL_MS = 40;
const GLOBE_FOCUS_OSCILLATION_DEG = 18;
const GLOBE_FOCUS_OSCILLATION_SPEED = 0.38;

export default {
  name: "MapPanel",
  components: {
    DataPanel,
  },
  props: {
    canvasOnly: { type: Boolean, default: false },
    mapOnly: {
      type: Boolean,
      default: false,
    },
    immersive: {
      type: Boolean,
      default: false,
    },
    panelTitle: {
      type: String,
      default: "Telemetry Map",
    },
    panelSubtitle: {
      type: String,
      default: "Public IPs geolocated from real results with WebSocket updates.",
    },
    showRefresh: {
      type: Boolean,
      default: false,
    },
    showPanelHeader: {
      type: Boolean,
      default: true,
    },
    showIntro: {
      type: Boolean,
      default: true,
    },
    showProjectionSwitch: {
      type: Boolean,
      default: false,
    },
    defaultProjection: {
      type: String,
      default: "flat",
    },
    snapshot: {
      type: Object,
      default: null,
    },
    externalRealtime: {
      type: Boolean,
      default: false,
    },
  },
  data() {
    return {
      store,
      detailsOpen: false,
      dockHeight: 180,
      dockObserver: null,
      error: "",
      loading: false,
      lastUpdated: "",
      liveRefreshEnabled: false,
      mapUid: this.buildMapUid(),
      mapZoom: 1,
      mapPan: { x: 0, y: 0 },
      mapDrag: null,
      mapDragged: false,
      flatMapWidth: 920,
      flatMapHeight: 470,
      globeMapSize: 720,
      mapPadding: 18,
      stopTableRefreshSubscription: null,
      stopMapSnapshotSubscription: null,
      worldGeoJsonDetailed: null,
      worldGeoJsonGlobe: null,
      publicPoints: [],
      countryStats: [],
      selectedCountryIso: "",
      originPoint: null,
      localHostCount: 0,
      geoipStatus: {
        source: "empty",
        rows: 0,
        generated_at: "",
        partial: false,
      },
      summary: {
        total_hosts: 0,
        public_hosts: 0,
        unmapped_public_hosts: 0,
        total_ports: 0,
        total_open_ports: 0,
      },
      projectionMode: String(this.defaultProjection || "flat").trim().toLowerCase() === "globe"
        ? "globe"
        : "flat",
      globeRotation: -18,
      globeTilt: 14,
      globeFocusLongitude: -18,
      globeOscillationTime: 0,
      globeFrameId: null,
      globeLastFrameTs: 0,
    };
  },
  computed: {
    apiBase() {
      return this.store.state.apiBase;
    },
    isGlobeMode() {
      return this.projectionMode === "globe";
    },
    globeClipId() {
      return `map-globe-clip-${this.mapUid}`;
    },
    landGradientId() {
      return `map-land-${this.mapUid}`;
    },
    frameGradientId() {
      return `map-frame-${this.mapUid}`;
    },
    arcGlowFilterId() {
      return `map-arc-glow-${this.mapUid}`;
    },
    pointGlowFilterId() {
      return `map-point-glow-${this.mapUid}`;
    },
    wsLabel() {
      const wsState = String(this.store.state.wsStatus || "").trim().toLowerCase();
      if (wsState === "online") return "WS online";
      if (wsState === "error") return "WS error";
      if (wsState === "offline") return "WS reconnecting";
      return "WS connecting";
    },
    geoipSourceLabel() {
      const source = String(this.geoipStatus.source || "").trim().toLowerCase();
      if (source === "country-db-zoneinfo") return "GeoIP country DB";
      if (source === "country-db") return "GeoIP country DB";
      if (source === "repo-seed-file") return "GeoIP repo seed";
      if (source === "fallback-rir-seed") return "GeoIP fallback";
      if (source === "external-db") return "GeoIP local DB";
      return "GeoIP pending";
    },
    statusInfoText() {
      const parts = [];
      if (this.wsLabel) parts.push(this.wsLabel);
      if (this.geoipSourceLabel) parts.push(this.geoipSourceLabel);
      return parts.join(" · ");
    },
    geoipInfoText() {
      const parts = [];
      const source = String(this.geoipStatus.source || "").trim().toLowerCase();
      const resolvedHosts = Number(this.geoipStatus.resolved_public_hosts) || 0;
      const totalPublicHosts = Number(this.geoipStatus.total_public_hosts) || 0;
      if (source === "country-db-zoneinfo" || source === "country-db") {
        if (totalPublicHosts > 0) {
          parts.push(`${resolvedHosts}/${totalPublicHosts} hosts mapped`);
        }
      } else {
        const rows = Number(this.geoipStatus.rows) || 0;
        if (rows > 0) parts.push(`${rows.toLocaleString()} blocks`);
      }
      if (this.geoipStatus.generated_at) parts.push(`seed ${this.geoipStatus.generated_at}`);
      if (this.geoipStatus.partial) parts.push("partial catalog");
      return parts.join(" · ");
    },
    mapWidth() {
      return this.isGlobeMode ? this.globeMapSize : this.flatMapWidth;
    },
    mapHeight() {
      return this.isGlobeMode ? this.globeMapSize : this.flatMapHeight;
    },
    globeCenterX() {
      return this.mapWidth / 2;
    },
    globeCenterY() {
      return this.mapHeight / 2;
    },
    globeRadius() {
      return Math.min(this.mapWidth, this.mapHeight) * 0.42;
    },
    originCoord() {
      // With a declared site location the arcs start where the sensor
      // actually is. Without one they fall back to an off-canvas anchor on
      // the left edge, which is what produced the stray point floating
      // outside the map.
      const projected = this.projectedOrigin;
      if (projected) {
        return [Math.round(projected.x), Math.round(projected.y)];
      }
      return [
        Math.round(this.mapPadding - 40),
        Math.round(this.isGlobeMode ? this.mapHeight * 0.24 : this.mapHeight * 0.54),
      ];
    },
    projectedOrigin() {
      const origin = this.originPoint;
      if (!origin) return null;
      const lat = Number(origin.lat);
      const lon = Number(origin.lon);
      if (!Number.isFinite(lat) || !Number.isFinite(lon)) return null;
      const projected = this.projectPoint(lon, lat);
      if (!projected || !Number.isFinite(projected.x) || !Number.isFinite(projected.y)) return null;
      // In globe mode a point on the far hemisphere projects to a
      // back-facing coordinate; anchoring arcs there would draw them through
      // the planet, so fall back until it rotates into view.
      if (this.isGlobeMode && Number.isFinite(projected.depth) && projected.depth < 0) return null;
      if (!this.isGlobeMode) return projected;
      const clamped = this.clampToGlobeInterior(projected.x, projected.y, 22);
      return { ...projected, x: clamped.x, y: clamped.y };
    },
    hasDeclaredOrigin() {
      return Boolean(this.projectedOrigin);
    },
    projectedPublicPoints() {
      const points = this.publicPoints
        .map((item) => {
          const coords = this.pointCoordinates(item);
          if (!coords) return null;
          const { lon, lat } = coords;
          const projected = this.projectPoint(lon, lat);
          if (!projected) return null;
          const depth = Number.isFinite(projected.depth) ? projected.depth : 1;
          const display = this.isGlobeMode
            ? this.clampToGlobeInterior(projected.x, projected.y, 10)
            : projected;
          return {
            ...item,
            id: `public-${item.ip}`,
            x: display.x,
            y: display.y,
            depth,
            color: this.pointColor(item, depth),
            glowColor: this.pointGlowColor(item, depth),
            ringColor: this.pointRingColor(item, depth),
            radius: this.pointRadius(item, depth),
          };
        })
        .filter(Boolean)
        .slice(0, 400);
      if (this.isGlobeMode) {
        points.sort((a, b) => a.depth - b.depth);
      }
      return points;
    },
    countryByIso() {
      const index = {};
      (this.countryStats || []).forEach((entry) => {
        const iso = String(entry.country_code || "").toUpperCase();
        if (iso) index[iso] = entry;
      });
      return index;
    },
    selectedCountry() {
      return this.selectedCountryIso ? this.countryByIso[this.selectedCountryIso] || null : null;
    },
    countryRanking() {
      // Already ordered by packets on the server; capped here so the panel
      // stays a summary rather than turning into a second table.
      return (this.countryStats || []).slice(0, 12);
    },
    // Latitude never changes as the globe turns, so its trigonometry is done
    // once here instead of on every point of every frame. What is left per
    // frame is the longitude pair, which is the only part rotation touches:
    // six trig calls per point become two.
    globeFeatures() {
      // Normalize each polygon independently; retain holes and island groups.
      const normalize = (rings) => {
        const polygon = { type: "Polygon", coordinates: rings };
        return geoArea(polygon) > 2 * Math.PI
          ? rings.map((ring) => [...ring].reverse())
          : rings;
      };
      return (this.worldGeoJsonDetailed?.features || []).map((feature) => {
        const geometry = feature.geometry;
        if (!geometry) return feature;
        const coordinates = geometry.type === "MultiPolygon"
          ? geometry.coordinates.map(normalize)
          : normalize(geometry.coordinates);
        return { ...feature, geometry: { ...geometry, coordinates } };
      });
    },
    worldPaths() {
      // The identity travels with every path of a country, not just the first:
      // a country drawn as several polygons has to answer to a click on any of
      // its islands. `active` keeps countries absent from this capture inert,
      // so a click never opens an empty panel.
      const paths = [];
      const push = (featureIndex, pathIndex, d, iso, name) => {
        if (!d) return;
        paths.push({
          id: `land-${featureIndex}-${pathIndex}`,
          d,
          iso,
          name,
          active: Boolean(iso && this.countryByIso[iso]),
        });
      };

      if (this.isGlobeMode) {
        // Spherical clipping closes polygons along the horizon, not with
        // straight chords between the last visible coastline vertices.
        const projection = geoOrthographic()
          .rotate([-this.globeRotation, -this.globeTilt])
          .translate([this.globeCenterX, this.globeCenterY])
          .scale(this.globeRadius)
          .clipAngle(90)
          .precision(0.5);
        const path = geoPath(projection);
        this.globeFeatures.forEach((feature, index) => {
          const properties = feature.properties || {};
          push(index, 0, path(feature), String(properties.iso_a2 || "").toUpperCase(), properties.name || "");
        });
        return paths;
      }

      const collection = this.worldGeoJsonDetailed;
      const features = Array.isArray(collection && collection.features) ? collection.features : [];
      features.forEach((feature, featureIndex) => {
        const properties = (feature && feature.properties) || {};
        const iso = String(properties.iso_a2 || "").toUpperCase();
        const name = String(properties.name || "").trim();
        this.geometryToPathsFlat(feature && feature.geometry).forEach((d, pathIndex) => {
          push(featureIndex, pathIndex, d, iso, name);
        });
      });
      return paths;
    },
    arcPaths() {
      return this.projectedPublicPoints.map((item, index) => {
        const openPorts = Number(item.open_port_count) || 0;
        return {
          id: `arc-${item.ip}`,
          d: this.buildArcPath(this.originCoord[0], this.originCoord[1], item.x, item.y),
          stroke: openPorts >= 20 ? "rgba(255,84,104,0.9)" : "rgba(74,136,255,0.76)",
          glow: openPorts >= 20 ? "rgba(255,84,104,0.44)" : "rgba(74,136,255,0.32)",
          strokeWidth: openPorts >= 20 ? 1.9 : 1.2,
          traceColor: openPorts >= 20 ? "rgba(255,153,167,0.96)" : "rgba(122,210,255,0.96)",
          traceRadius: openPorts >= 20 ? 3.2 : 2.8,
          duration: `${(3.2 + ((index % 7) * 0.34)).toFixed(2)}s`,
          begin: `${(index % 9) * 0.18}s`,
          style: {
            animationDuration: `${(2.8 + ((index % 6) * 0.28)).toFixed(2)}s`,
            animationDelay: `${(index % 5) * 0.14}s`,
          },
        };
      });
    },
    latestHosts() {
      return this.publicPoints.map((item) => ({
        id: `pub-${item.ip}`,
        ip: item.ip,
        scope: "public",
        region: `${item.rir || "RIR"} ${item.country || ""}`.trim(),
        open_port_count: Number(item.open_port_count) || 0,
        protocols: Array.isArray(item.protocols) ? item.protocols.join(", ") : "",
      }))
        .sort((a, b) => b.open_port_count - a.open_port_count || a.ip.localeCompare(b.ip))
        .slice(0, 10);
    },
  },
  watch: {
    apiBase() {
      if (this.externalRealtime) return;
      this.reloadData();
    },
    snapshot: {
      handler(value) {
        if (!value || typeof value !== "object" || !Object.keys(value).length) return;
        this.error = "";
        this.loading = false;
        this.applySnapshot(value);
      },
    },
    defaultProjection(value) {
      this.setProjection(value);
    },
    projectionMode() {
      this.resetMapView();
      this.syncProjectionAnimation();
    },
  },
  mounted() {
    this.$nextTick(() => {
      if (!this.canvasOnly || !this.$refs.infoDock) return;
      this.dockObserver = new ResizeObserver(([entry]) => {
        this.dockHeight = Math.ceil(entry.target.getBoundingClientRect().height);
      });
      this.dockObserver.observe(this.$refs.infoDock);
    });
    this.loadWorldGeometry();
    this.syncProjectionAnimation();
    this.stopMapSnapshotSubscription = this.store.subscribeMapSnapshot(this.handleRealtimeMapSnapshot);
    const initialSnapshot = this.snapshot && Object.keys(this.snapshot).length
      ? this.snapshot
      : this.store.getRealtimeMapSnapshot();
    if (initialSnapshot && typeof initialSnapshot === "object") {
      this.applySnapshot(initialSnapshot);
      this.loading = false;
      this.error = "";
    } else {
      if (this.externalRealtime) {
        this.loading = true;
        this.store.requestRealtimeMapSnapshot(500);
      } else {
        this.reloadData();
      }
    }
  },
  beforeUnmount() {
    this.dockObserver?.disconnect();
    this.stopGlobeRotation();
    if (typeof this.stopMapSnapshotSubscription === "function") {
      this.stopMapSnapshotSubscription();
      this.stopMapSnapshotSubscription = null;
    }
  },
  methods: {
    mapPointer(event) {
      const svg = this.$refs.mapSvg;
      const matrix = svg && svg.getScreenCTM();
      if (!matrix) return null;
      return new DOMPoint(event.clientX, event.clientY).matrixTransform(matrix.inverse());
    },
    zoomMap(value, anchor = { x: this.mapWidth / 2, y: this.mapHeight / 2 }) {
      const next = Math.max(1, Math.min(8, value));
      const ratio = next / this.mapZoom;
      this.mapPan = {
        x: anchor.x - (anchor.x - this.mapPan.x) * ratio,
        y: anchor.y - (anchor.y - this.mapPan.y) * ratio,
      };
      this.mapZoom = next;
      this.clampMapPan();
    },
    clampMapPan() {
      this.mapPan.x = Math.max(this.mapWidth * (1 - this.mapZoom), Math.min(0, this.mapPan.x));
      // Mercator extends beyond the initial viewport towards both poles.
      const extra = (this.mapWidth - this.mapPadding * 2 - this.mapHeight) / 2;
      this.mapPan.y = Math.max(this.mapHeight * (1 - this.mapZoom) - extra * this.mapZoom, Math.min(extra * this.mapZoom, this.mapPan.y));
    },
    resetMapView() {
      this.mapZoom = 1;
      this.mapPan = { x: 0, y: 0 };
    },
    onMapWheel(event) {
      if (this.isGlobeMode) return;
      event.preventDefault();
      const point = this.mapPointer(event);
      if (point) this.zoomMap(this.mapZoom * Math.exp(-Math.max(-100, Math.min(100, event.deltaY)) * .003), point);
    },
    startMapPan(event) {
      if (this.isGlobeMode || event.button !== 0) return;
      const point = this.mapPointer(event);
      if (!point) return;
      this.mapDragged = false;
      this.mapDrag = { id: event.pointerId, x: point.x, y: point.y, pan: { ...this.mapPan } };
    },
    moveMapPan(event) {
      if (!this.mapDrag || this.mapDrag.id !== event.pointerId) return;
      const point = this.mapPointer(event);
      if (!point) return;
      const dx = point.x - this.mapDrag.x;
      const dy = point.y - this.mapDrag.y;
      if (Math.hypot(dx, dy) > 3) {
        this.mapDragged = true;
        this.$refs.mapSvg.setPointerCapture(event.pointerId);
      }
      if (!this.mapDragged) return;
      this.mapPan = { x: this.mapDrag.pan.x + dx, y: this.mapDrag.pan.y + dy };
      this.clampMapPan();
    },
    endMapPan(event) {
      if (this.$refs.mapSvg.hasPointerCapture(event.pointerId)) this.$refs.mapSvg.releasePointerCapture(event.pointerId);
      this.mapDrag = null;
    },
    guardMapClick(event) {
      if (!this.mapDragged) return;
      event.stopPropagation();
      this.mapDragged = false;
    },
    buildMapUid() {
      if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
        return crypto.randomUUID().replace(/-/g, "").slice(0, 8);
      }
      if (typeof crypto !== "undefined" && typeof crypto.getRandomValues === "function") {
        const buffer = new Uint8Array(4);
        crypto.getRandomValues(buffer);
        return Array.from(buffer, (value) => value.toString(16).padStart(2, "0")).join("");
      }
      return `map-${Date.now().toString(36)}`;
    },
    assetBaseUrl() {
      return appBaseUrl();
    },
    worldGeoJsonUrlCandidates(kind) {
      const base = this.assetBaseUrl();
      if (kind === "globe") {
        return [`${base}geo/world.geojson`, `${base}geo/world-detailed.geojson`];
      }
      return [`${base}geo/world-detailed.geojson`, `${base}geo/world.geojson`];
    },
    loadGeoJson(candidates, assign) {
      const tryNext = (index = 0) => {
        if (index >= candidates.length) {
          return Promise.resolve(null);
        }
        return fetch(candidates[index])
          .then((res) => {
            if (!res.ok) {
              throw new Error(`HTTP ${res.status}`);
            }
            return res.json();
          })
          .then((payload) => {
            if (!payload || payload.type !== "FeatureCollection") {
              throw new Error("Invalid GeoJSON payload");
            }
            assign(payload);
            return payload;
          })
          .catch(() => tryNext(index + 1));
      };
      return tryNext();
    },
    loadWorldGeometry() {
      return Promise.all([
        this.loadGeoJson(this.worldGeoJsonUrlCandidates("detailed"), (payload) => {
          this.worldGeoJsonDetailed = payload;
        }),
        this.loadGeoJson(this.worldGeoJsonUrlCandidates("globe"), (payload) => {
          this.worldGeoJsonGlobe = payload;
        }),
      ]);
    },
    setProjection(mode) {
      this.projectionMode = String(mode || "flat").trim().toLowerCase() === "globe" ? "globe" : "flat";
    },
    syncProjectionAnimation() {
      if (this.isGlobeMode) {
        this.startGlobeRotation();
        return;
      }
      this.stopGlobeRotation();
    },
    startGlobeRotation() {
      this.stopGlobeRotation();
      this.globeLastFrameTs = 0;
      const tick = (timestamp) => {
        if (!this.isGlobeMode) {
          this.globeFrameId = null;
          return;
        }
        if (!this.globeLastFrameTs) {
          this.globeLastFrameTs = timestamp;
        }
        const elapsed = timestamp - this.globeLastFrameTs;
        // Capped at ~30 fps. Every rotation step re-projects the whole world
        // and re-renders every country path, so asking for 60 was asking for
        // twice that work to produce a difference of a third of a degree - and
        // when a frame overran its budget the next one was already due, which
        // is what made the globe stutter instead of just running slower.
        if (elapsed < GLOBE_FRAME_INTERVAL_MS) {
          this.globeFrameId = window.requestAnimationFrame(tick);
          return;
        }
        const delta = Math.min(64, elapsed);
        this.globeLastFrameTs = timestamp;
        const hasPublicFocus = Array.isArray(this.publicPoints) && this.publicPoints.length > 0;
        if (hasPublicFocus) {
          this.globeOscillationTime += (delta / 1000) * GLOBE_FOCUS_OSCILLATION_SPEED;
          this.globeRotation = this.normalizeLongitude(
            this.globeFocusLongitude + (Math.sin(this.globeOscillationTime) * GLOBE_FOCUS_OSCILLATION_DEG)
          );
        } else {
          this.globeRotation = this.normalizeLongitude(
            this.globeRotation + ((delta / 1000) * GLOBE_ROTATION_SPEED)
          );
        }
        this.globeFrameId = window.requestAnimationFrame(tick);
      };
      this.globeFrameId = window.requestAnimationFrame(tick);
    },
    stopGlobeRotation() {
      if (this.globeFrameId !== null) {
        window.cancelAnimationFrame(this.globeFrameId);
        this.globeFrameId = null;
      }
      this.globeLastFrameTs = 0;
      this.globeOscillationTime = 0;
    },
    latitudeToY(lat) {
      // Spherical Mercator uses the same scale on both axes.
      // Clamp at the Web Mercator latitude limit to keep the poles finite.
      const clipped = Math.max(-85.05112878, Math.min(85.05112878, Number(lat) || 0));
      const scale = (this.mapWidth - this.mapPadding * 2) / (2 * Math.PI);
      return this.mapHeight / 2 - scale * Math.log(Math.tan(Math.PI / 4 + clipped * Math.PI / 360));
    },
    longitudeToX(lon) {
      const clipped = Math.max(-180, Math.min(180, Number(lon) || 0));
      const usableWidth = this.mapWidth - (this.mapPadding * 2);
      return this.mapPadding + ((clipped + 180) / 360) * usableWidth;
    },
    normalizeLongitude(lon) {
      let value = Number(lon) || 0;
      while (value > 180) value -= 360;
      while (value < -180) value += 360;
      return value;
    },
    degToRad(value) {
      return (Number(value) || 0) * (Math.PI / 180);
    },
    projectPointFlat(lon, lat) {
      const x = this.longitudeToX(lon);
      const y = this.latitudeToY(lat);
      if (!Number.isFinite(x) || !Number.isFinite(y)) return null;
      return { x, y, depth: 1 };
    },
    projectPointGlobe(lon, lat, allowBackface = false) {
      const lambda = this.degToRad(this.normalizeLongitude((Number(lon) || 0) - this.globeRotation));
      const phi = this.degToRad(Math.max(-89.5, Math.min(89.5, Number(lat) || 0)));
      const phi0 = this.degToRad(this.globeTilt);
      const cosPhi = Math.cos(phi);
      const sinPhi = Math.sin(phi);
      const cosPhi0 = Math.cos(phi0);
      const sinPhi0 = Math.sin(phi0);
      const cosLambda = Math.cos(lambda);
      const sinLambda = Math.sin(lambda);
      const visibility = (sinPhi0 * sinPhi) + (cosPhi0 * cosPhi * cosLambda);
      if (!allowBackface && visibility <= 0) return null;
      const x = this.globeCenterX + (this.globeRadius * cosPhi * sinLambda);
      const y = this.globeCenterY - (this.globeRadius * ((cosPhi0 * sinPhi) - (sinPhi0 * cosPhi * cosLambda)));
      if (!Number.isFinite(x) || !Number.isFinite(y)) return null;
      return { x, y, depth: Math.max(0.08, visibility) };
    },
    projectPoint(lon, lat) {
      return this.isGlobeMode ? this.projectPointGlobe(lon, lat) : this.projectPointFlat(lon, lat);
    },
    clampToGlobeInterior(x, y, margin = 0) {
      const cx = this.globeCenterX;
      const cy = this.globeCenterY;
      const dx = x - cx;
      const dy = y - cy;
      const maxDistance = Math.max(0, this.globeRadius - margin);
      const distance = Math.hypot(dx, dy);
      if (!distance || distance <= maxDistance) {
        return { x, y };
      }
      const scale = maxDistance / distance;
      return {
        x: cx + (dx * scale),
        y: cy + (dy * scale),
      };
    },
    pointCoordinates(item) {
      if (!item || typeof item !== "object") return null;
      const lonRaw = item.lon;
      const latRaw = item.lat;
      if (
        lonRaw === null ||
        lonRaw === undefined ||
        latRaw === null ||
        latRaw === undefined ||
        lonRaw === "" ||
        latRaw === ""
      ) {
        return null;
      }
      const lon = Number(lonRaw);
      const lat = Number(latRaw);
      if (!Number.isFinite(lon) || !Number.isFinite(lat)) return null;
      return { lon, lat };
    },
    geometryToPathsFlat(geometry) {
      const geom = geometry && typeof geometry === "object" ? geometry : null;
      if (!geom || !Array.isArray(geom.coordinates)) return [];
      if (geom.type === "Polygon") {
        const path = this.polygonToPathFlat(geom.coordinates);
        return path ? [path] : [];
      }
      if (geom.type === "MultiPolygon") {
        return geom.coordinates.map((polygon) => this.polygonToPathFlat(polygon)).filter(Boolean);
      }
      return [];
    },
    polygonToPathFlat(polygon) {
      if (!Array.isArray(polygon)) return "";
      return polygon.map((ring) => this.ringToPathFlat(ring)).filter(Boolean).join(" ");
    },
    ringToPathFlat(ring) {
      if (!Array.isArray(ring) || ring.length < 2) return "";
      let path = "";
      let prevLon = null;
      let started = false;
      ring.forEach((pair, index) => {
        if (!Array.isArray(pair) || pair.length < 2) return;
        const lon = Number(pair[0]);
        const lat = Number(pair[1]);
        if (!Number.isFinite(lon) || !Number.isFinite(lat)) return;
        const projected = this.projectPointFlat(lon, lat);
        if (!projected) return;
        const command =
          !started || index === 0 || (prevLon !== null && Math.abs(lon - prevLon) > 180)
            ? "M"
            : "L";
        path += `${command}${projected.x.toFixed(2)},${projected.y.toFixed(2)} `;
        prevLon = lon;
        started = true;
      });
      return path ? `${path.trim()} Z` : "";
    },
    geometryToPathsGlobe(geometry) {
      const geom = geometry && typeof geometry === "object" ? geometry : null;
      if (!geom || !Array.isArray(geom.coordinates)) return [];
      if (geom.type === "Polygon") {
        return this.polygonToPathGlobe(geom.coordinates);
      }
      if (geom.type === "MultiPolygon") {
        return geom.coordinates.flatMap((polygon) => this.polygonToPathGlobe(polygon));
      }
      return [];
    },
    polygonToPathGlobe(polygon) {
      if (!Array.isArray(polygon)) return [];
      return polygon.flatMap((ring) => this.ringToPathsGlobe(ring));
    },
    ringToPathsGlobe(ring) {
      if (!Array.isArray(ring) || ring.length < 2) return [];
      const segments = [];
      let current = [];
      ring.forEach((pair) => {
        if (!Array.isArray(pair) || pair.length < 2) return;
        const projected = this.projectPointGlobe(Number(pair[0]), Number(pair[1]));
        if (projected) {
          current.push(projected);
          return;
        }
        if (current.length >= 2) {
          segments.push(current.slice());
        }
        current = [];
      });
      if (current.length >= 2) {
        segments.push(current.slice());
      }
      return segments
        .map((segment) => {
          if (segment.length < 2) return "";
          const commands = segment
            .map((point, index) => `${index === 0 ? "M" : "L"}${point.x.toFixed(2)},${point.y.toFixed(2)}`)
            .join(" ");
          return `${commands} Z`;
        })
        .filter(Boolean);
    },
    buildArcPath(sx, sy, tx, ty) {
      if (!this.isGlobeMode) {
        const cx = (sx + tx) / 2;
        const cy = (sy + ty) / 2 - Math.min(90, Math.abs(tx - sx) * 0.18 + 16);
        return `M${sx},${sy} Q${cx},${cy} ${tx},${ty}`;
      }
      const mx = (sx + tx) / 2;
      const my = (sy + ty) / 2;
      const vx = mx - this.globeCenterX;
      const vy = my - this.globeCenterY;
      const length = Math.hypot(vx, vy) || 1;
      const lift = Math.min(72, 22 + (Math.hypot(tx - sx, ty - sy) * 0.11));
      const control = this.clampToGlobeInterior(
        mx - ((vx / length) * lift),
        my - ((vy / length) * lift),
        14
      );
      const start = this.clampToGlobeInterior(sx, sy, 14);
      const end = this.clampToGlobeInterior(tx, ty, 10);
      return `M${start.x},${start.y} Q${control.x},${control.y} ${end.x},${end.y}`;
    },
    pointColor(item, depth = 1) {
      const weight = Number(item.open_port_count) || 0;
      const alphaBoost = this.isGlobeMode ? Math.min(1, 0.56 + (depth * 0.5)) : 0.95;
      if (weight >= 20) return `rgba(255, 84, 104, ${alphaBoost})`;
      if (weight >= 10) return `rgba(243, 177, 75, ${alphaBoost})`;
      return `rgba(53, 230, 177, ${Math.min(1, alphaBoost)})`;
    },
    pointGlowColor(item, depth = 1) {
      const weight = Number(item.open_port_count) || 0;
      const alpha = this.isGlobeMode ? (0.22 + (depth * 0.34)) : 0.52;
      if (weight >= 20) return `rgba(255, 84, 104, ${alpha.toFixed(3)})`;
      if (weight >= 10) return `rgba(243, 177, 75, ${Math.min(0.72, alpha + 0.08).toFixed(3)})`;
      return `rgba(53, 230, 177, ${Math.min(0.62, alpha).toFixed(3)})`;
    },
    pointRingColor(item, depth = 1) {
      const weight = Number(item.open_port_count) || 0;
      const alpha = this.isGlobeMode ? Math.min(0.94, 0.36 + (depth * 0.46)) : 0.84;
      if (weight >= 20) return `rgba(255, 155, 168, ${alpha.toFixed(3)})`;
      if (weight >= 10) return `rgba(255, 214, 145, ${Math.min(0.9, alpha).toFixed(3)})`;
      return `rgba(147, 255, 224, ${Math.min(0.88, alpha).toFixed(3)})`;
    },
    pointRadius(item, depth = 1) {
      const weight = Number(item.open_port_count) || 0;
      const base = weight >= 20 ? 4.2 : weight >= 10 ? 3.4 : 2.8;
      if (!this.isGlobeMode) return base;
      return base * (0.78 + (depth * 0.48));
    },
    deriveGlobeFocus(points) {
      const rows = Array.isArray(points) ? points : [];
      if (!rows.length) {
        return {
          longitude: this.globeFocusLongitude,
          tilt: 14,
        };
      }
      let sinSum = 0;
      let cosSum = 0;
      let latSum = 0;
      let totalWeight = 0;
      rows.forEach((item) => {
        const coords = this.pointCoordinates(item);
        if (!coords) return;
        const { lon, lat } = coords;
        const weight = Math.max(1, Number(item && item.open_port_count) || 0);
        const radians = this.degToRad(lon);
        sinSum += Math.sin(radians) * weight;
        cosSum += Math.cos(radians) * weight;
        latSum += lat * weight;
        totalWeight += weight;
      });
      if (!totalWeight || (!sinSum && !cosSum)) {
        return {
          longitude: this.globeFocusLongitude,
          tilt: 14,
        };
      }
      const longitude = this.normalizeLongitude(Math.atan2(sinSum, cosSum) * (180 / Math.PI));
      const avgLat = latSum / totalWeight;
      return {
        longitude,
        tilt: Math.max(-28, Math.min(32, avgLat * 0.58)),
      };
    },
    selectCountry(iso) {
      const code = String(iso || "").toUpperCase();
      if (!code || !this.countryByIso[code]) return;
      // Clicking the open country closes it, so the map can be cleared without
      // hunting for a dismiss control.
      this.selectedCountryIso = this.selectedCountryIso === code ? "" : code;
    },
    clearCountry() {
      this.selectedCountryIso = "";
    },
    formatBytes(value) {
      const bytes = Number(value) || 0;
      if (bytes < 1024) return `${bytes} B`;
      if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
      return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    },
    applySnapshot(snapshot) {
      const data = snapshot && snapshot.data ? snapshot.data : snapshot;
      const summary = (data && data.summary) || {};
      this.publicPoints = Array.isArray(data && data.public_points) ? data.public_points : [];
      this.countryStats = Array.isArray(data && data.countries) ? data.countries : [];
      // A country that dropped out of the window must not keep its panel open
      // describing traffic that is no longer in the slice.
      if (this.selectedCountryIso && !this.countryStats.some((c) => c.country_code === this.selectedCountryIso)) {
        this.selectedCountryIso = "";
      }
      this.originPoint = (data && data.origin) || null;
      this.localHostCount = Number((data && data.summary && data.summary.private_hosts) || 0);
      this.geoipStatus = (data && data.geoip) || {
        source: "empty",
        rows: 0,
        generated_at: "",
        partial: false,
      };
      const focus = this.deriveGlobeFocus(this.publicPoints);
      this.globeFocusLongitude = focus.longitude;
      this.globeTilt = focus.tilt;
      if (this.isGlobeMode && this.publicPoints.length) {
        this.globeRotation = focus.longitude;
        this.globeOscillationTime = 0;
      }
      this.summary = {
        total_hosts: Number(summary.total_hosts) || 0,
        public_hosts: Number(summary.public_hosts) || 0,
        unmapped_public_hosts: Number(summary.unmapped_public_hosts) || 0,
        total_ports: Number(summary.total_ports) || 0,
        total_open_ports: Number(summary.total_open_ports) || 0,
      };
      this.lastUpdated = new Date().toLocaleTimeString();
    },
    reloadData() {
      this.loading = true;
      this.error = "";
      return this.store
        .fetchJsonPromise("/api/map/scan?limit=500")
        .then((payload) => {
          this.applySnapshot(payload && payload.data ? payload.data : payload);
        })
        .catch((err) => {
          this.error = err.message || "Failed to load telemetry map data.";
          this.lastUpdated = "";
        })
        .finally(() => {
          this.loading = false;
        });
    },
    manualRefresh() {
      if (this.externalRealtime) {
        this.loading = true;
        if (this.store.requestRealtimeMapSnapshot(500)) {
          return Promise.resolve();
        }
      }
      return this.reloadData();
    },
    handleRealtimeMapSnapshot(event) {
      const snapshot = event && event.snapshot ? event.snapshot : null;
      if (!snapshot) return;
      if (!this.externalRealtime && this.showRefresh && this.lastUpdated && !this.liveRefreshEnabled) {
        return;
      }
      this.error = "";
      this.loading = false;
      this.applySnapshot(snapshot);
    },
  },
};
</script>

<style scoped>
.map-intro {
  position: relative;
  display: grid;
  gap: 8px;
}

.map-intro__eyebrow {
  color: rgba(108, 229, 255, 0.88);
  font-size: 0.72rem;
  font-weight: 700;
  letter-spacing: 0.18em;
  text-transform: uppercase;
}

.map-intro__title {
  color: rgba(240, 247, 255, 0.98);
  font-size: clamp(1.2rem, 2vw, 1.55rem);
  font-weight: 600;
  letter-spacing: 0.01em;
}

.map-intro__description {
  color: rgba(188, 208, 227, 0.82);
  font-size: 0.98rem;
  line-height: 1.6;
}

.map-intro__meta {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
  color: rgba(132, 173, 205, 0.86);
  font-size: 0.78rem;
  letter-spacing: 0.05em;
  text-transform: uppercase;
}

.map-intro__meta-divider {
  width: 4px;
  height: 4px;
  border-radius: 999px;
  background: rgba(91, 217, 255, 0.58);
  box-shadow: 0 0 14px rgba(91, 217, 255, 0.42);
}

.map-wrapper {
  position: relative;
  border-radius: 24px;
  overflow: hidden;
  border: 1px solid rgba(94, 176, 226, 0.24);
  /* Flat backdrop: the corner glows competed with the arcs and host points
     drawn on top, which are the part of this panel that carries data. */
  background: linear-gradient(175deg, rgba(4, 14, 28, 0.99), rgba(3, 9, 17, 0.98));
  box-shadow:
    inset 0 0 0 1px rgba(255, 255, 255, 0.03),
    inset 0 30px 80px rgba(47, 124, 196, 0.06),
    0 24px 60px rgba(4, 8, 15, 0.5);
}

.map-wrapper::before {
  content: "";
  position: absolute;
  inset: 0;
  pointer-events: none;
  background: linear-gradient(
    180deg,
    rgba(140, 218, 255, 0.06) 0%,
    rgba(140, 218, 255, 0) 26%,
    rgba(140, 218, 255, 0.08) 100%
  );
  z-index: 1;
}

.map-wrapper--globe {
  display: grid;
  justify-items: center;
  background: linear-gradient(180deg, rgba(4, 14, 28, 0.99), rgba(3, 9, 17, 0.98));
}

.map-overlay {
  position: absolute;
  top: 16px;
  left: 16px;
  right: 16px;
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 12px;
  flex-wrap: wrap;
  z-index: 3;
}

.map-overlay__group {
  display: grid;
  gap: 8px;
}

.map-overlay__label {
  color: rgba(162, 206, 229, 0.86);
  font-size: 0.7rem;
  font-weight: 700;
  letter-spacing: 0.14em;
  text-transform: uppercase;
}

.map-projection-toggle {
  padding: 4px;
  border-radius: 999px;
  background: rgba(6, 14, 28, 0.72);
  border: 1px solid rgba(102, 188, 229, 0.16);
  backdrop-filter: blur(10px);
}

.map-refresh-btn {
  min-height: 34px;
}

.map-wrapper svg {
  display: block;
  width: 100%;
  height: clamp(300px, 42vw, 520px);
  aspect-ratio: 2 / 1;
  position: relative;
  z-index: 0;
}

.map-wrapper--immersive svg {
  height: clamp(460px, 78vh, 920px);
}

.map-wrapper--globe svg {
  width: min(calc(100% - 32px), clamp(520px, 58vw, 760px));
  height: auto;
  aspect-ratio: 1 / 1;
  margin: 0 auto;
}

.map-wrapper--immersive.map-wrapper--globe svg {
  width: min(calc(100% - 32px), clamp(620px, 82vh, 840px));
  height: auto;
  aspect-ratio: 1 / 1;
}

.map-wrapper--immersive {
  border-radius: 28px;
  box-shadow:
    inset 0 0 0 1px rgba(255, 255, 255, 0.03),
    inset 0 40px 120px rgba(47, 124, 196, 0.08),
    0 30px 80px rgba(4, 8, 15, 0.58);
}

.map-origin__halo {
  fill: rgba(64, 224, 208, 0.18);
  stroke: rgba(64, 224, 208, 0.42);
  stroke-width: 1;
}

.map-origin__dot {
  fill: rgba(180, 255, 245, 0.98);
  stroke: rgba(10, 30, 34, 0.8);
  stroke-width: 1;
}

.map-origin__label {
  fill: rgba(180, 255, 245, 0.85);
  font-size: 7px;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}

.map-land {
  opacity: 0.94;
}

/* Only countries present in the current window react; the rest keep the
   default cursor so a click that would do nothing does not look clickable. */
.map-country--active {
  cursor: pointer;
  transition: fill 0.16s ease, stroke 0.16s ease;
}

.map-country--active:hover {
  fill: rgba(122, 210, 255, 0.26);
}

.map-country-popup {
  position: absolute;
  top: 14px;
  right: 14px;
  z-index: 3;
  width: min(300px, calc(100% - 28px));
  padding: 12px 14px;
  border-radius: 14px;
  background: rgba(9, 18, 32, 0.94);
  border: 1px solid rgba(122, 210, 255, 0.34);
  backdrop-filter: blur(6px);
}

.map-country-popup__head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 8px;
}

.map-country-popup__name {
  font-weight: 700;
  line-height: 1.2;
}

.map-country-popup__meta {
  font-size: 0.72rem;
  opacity: 0.72;
}

.map-country-popup__stats {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 6px;
  margin-top: 10px;
}

.map-country-popup__stats div {
  display: flex;
  flex-direction: column;
}

.map-country-popup__stats span {
  font-size: 0.68rem;
  opacity: 0.7;
}

.map-country-popup__stats strong {
  font-variant-numeric: tabular-nums;
}

.map-country-popup__protos {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
  margin-top: 10px;
}

.map-country-popup__ips {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin-top: 10px;
  font-size: 0.72rem;
  opacity: 0.82;
}

.map-country-popup__more {
  opacity: 0.6;
}

.map-ip-link {
  color: rgba(122, 210, 255, 0.96);
  text-decoration: none;
}

.map-ip-link:hover {
  text-decoration: underline;
}

.map-country-rail {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
  gap: 8px;
  margin-top: 14px;
}

.map-country-rail__item {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 7px 10px;
  border-radius: 10px;
  border: 1px solid rgba(143, 231, 202, 0.18);
  background: rgba(255, 255, 255, 0.03);
  text-align: left;
  cursor: pointer;
  min-width: 0;
}

.map-country-rail__item--on {
  border-color: rgba(122, 210, 255, 0.8);
  background: rgba(122, 210, 255, 0.14);
}

.map-country-rail__code {
  font-weight: 700;
  font-size: 0.74rem;
  flex: 0 0 auto;
}

.map-country-rail__name {
  flex: 1 1 auto;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-size: 0.78rem;
  opacity: 0.86;
}

.map-country-rail__count {
  flex: 0 0 auto;
  font-variant-numeric: tabular-nums;
  font-size: 0.74rem;
  opacity: 0.75;
}

.map-land--globe {
  opacity: 0.96;
}

.map-arc-flow {
  stroke-dasharray: 10 12;
  animation: arc-flow 3.2s linear infinite;
}

.map-arc-trace {
  opacity: 0.96;
}

@keyframes arc-flow {
  from {
    stroke-dashoffset: 48;
  }
  to {
    stroke-dashoffset: 0;
  }
}

@media (max-width: 960px) {
  .map-overlay {
    top: 12px;
    left: 12px;
    right: 12px;
  }

  .map-wrapper--immersive svg {
    height: clamp(460px, 74vh, 820px);
  }

  .map-wrapper--globe svg,
  .map-wrapper--immersive.map-wrapper--globe svg {
    width: min(calc(100% - 24px), clamp(360px, 92vw, 720px));
    height: auto;
  }
}

@media (max-width: 780px) {
  .map-intro__description {
    font-size: 0.92rem;
  }

  .map-overlay {
    gap: 10px;
  }

}

.map-canvas {
  position: relative;
  height: calc(100dvh - var(--v-layout-top, 0px) - var(--v-layout-bottom, 0px));
  overflow: hidden;
  background: #040a12;
}

.map-canvas .map-wrapper {
  width: 100%;
  height: 100%;
  margin: 0;
  border: 0;
  border-radius: 0;
  box-shadow: none;
  display: block;
}

.map-canvas .map-wrapper svg {
  width: 100%;
  height: 100%;
  margin: 0;
  aspect-ratio: auto;
}

.map-summary {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 8px;
  margin-top: 10px;
}
.map-summary__metric {
  padding: 8px 12px;
  border-radius: 10px;
  background: rgba(10, 24, 36, .72);
  border: 1px solid rgba(118, 201, 220, .16);
}
.map-info-dock {
  position: absolute;
  bottom: 12px;
  left: 16px;
  right: 16px;
  z-index: 4;
  max-height: min(50%, 400px);
  overflow: auto;
  padding: 0;
  border: 0;
  background: transparent;
  box-shadow: none;
  scrollbar-width: thin;
  pointer-events: none;
}
.map-info-dock > * { pointer-events: auto; }
.map-info-dock__heading {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}
.map-info-dock__heading > .v-btn {
  background: rgba(6, 15, 25, .8);
  border-radius: 10px;
}
.map-info-dock__status {
  display: flex;
  flex-wrap: wrap;
  gap: 4px 12px;
  color: #a0c1d7;
  font-size: 10px;
  padding: 4px 8px;
  border-radius: 8px;
  background: rgba(6, 15, 25, .72);
}
.map-info-dock .map-country-rail {
  display: flex;
  overflow-x: auto;
  flex-wrap: nowrap;
  gap: 6px;
  margin-top: 6px;
}
.map-info-dock .map-country-rail__item {
  flex: 0 0 auto;
  min-width: 0;
  padding: 5px 9px;
  font-size: 11px;
  gap: 8px;
  background: rgba(6, 15, 25, .72);
}
.map-info-dock .map-summary {
  width: min(720px, 100%);
  margin-top: 6px;
  gap: 6px;
}
.map-info-dock .map-summary__metric { padding: 5px 10px; }
.map-info-dock .map-summary .text-caption { font-size: 11px !important; line-height: 1.3; }
.map-info-dock .map-summary .text-h6 { font-size: 14px !important; line-height: 1.4; }
.map-info-dock .map-host-details { max-height: 220px; overflow: auto; background: rgba(6, 15, 25, .92); }
@media (max-width: 600px) {
  .map-info-dock { left: 8px; right: 8px; bottom: 8px; }
  .map-summary { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .map-info-dock__status { font-size: 9px; }
}
.map-interactive { touch-action: none; cursor: grab; }
.map-interactive:active { cursor: grabbing; }
.map-zoom-controls {
  display: flex;
  align-items: center;
  gap: 4px;
  border: 1px solid #69cad533;
  border-radius: 24px;
  background: #071321dd;
  backdrop-filter: blur(12px);
  font-size: 12px;
}

.map-canvas .map-wrapper--globe {
  padding-bottom: calc(var(--map-dock-height, 180px) + 32px);
  padding-top: 56px;
}
</style>
