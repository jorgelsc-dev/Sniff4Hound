<template>
  <div>
    <ViewHeader
      overline="Responses"
      title="Response Intelligence"
      description="Review captured service responses and HTTP favicons."
      :refresh-loading="loading"
      @refresh="load"
    />

    <v-tabs v-model="tab" color="primary" class="mb-4">
      <v-tab value="banners" :disabled="loading">Responses</v-tab>
      <v-tab value="favicons" :disabled="loading">Favicons</v-tab>
    </v-tabs>

    <v-row dense class="mb-3">
      <v-col cols="12" md="6">
        <v-text-field
          v-model.trim="tableFilters.query"
          label="Search"
          name="banner_table_search"
          placeholder="IP, port, response, URL..."
          prepend-inner-icon="mdi-magnify"
          clearable
          variant="outlined"
          density="comfortable"
        />
      </v-col>
      <v-col cols="12" md="3">
        <v-select
          v-model="tableFilters.proto"
          :items="protoFilterOptions"
          label="Proto"
          name="banner_table_proto_filter"
          item-title="label"
          item-value="value"
          clearable
          variant="outlined"
          density="comfortable"
        />
      </v-col>
      <v-col v-if="tab === 'favicons'" cols="12" md="3">
        <v-select
          v-model="tableFilters.mime"
          :items="mimeFilterOptions"
          label="MIME"
          name="banner_table_mime_filter"
          item-title="label"
          item-value="value"
          clearable
          variant="outlined"
          density="comfortable"
        />
      </v-col>
    </v-row>

    <EntityTablePanel
      v-if="tab === 'banners'"
      title="Captured Responses"
      subtitle="Service responses captured by listeners."
      v-model:live-enabled="liveRefreshEnabled"
      :rows="filteredBanners"
      :columns="bannerColumns"
      :expandable-rows="true"
      :loading="loading"
      :error="error"
      :last-updated="lastUpdated"
      :live-refresh="true"
      empty-text="No responses found"
      @refresh="load"
    >
      <template #cell-updated_at="{ value }">
        {{ formatTimestamp(value) }}
      </template>
      <template #cell-proto="{ value }">
        <v-chip size="x-small" color="primary" variant="tonal">
          {{ String(value || "unknown").toUpperCase() }}
        </v-chip>
      </template>
      <template #cell-src_ip="{ value }">
        <span class="mono">{{ value || "-" }}</span>
      </template>
      <template #cell-dst_ip="{ value }">
        <span class="mono">{{ value || "-" }}</span>
      </template>
      <template #cell-response_plain="{ item }">
        <span class="banner-text">{{ buildResponseSummary(item, 180) || "-" }}</span>
      </template>
      <template #cell-scan_state="{ value }">
        <v-chip size="x-small" :color="scanStatusColor(value)" variant="tonal">
          {{ scanStatusLabel(value) }}
        </v-chip>
      </template>
      <template #cell-response_size="{ value }">
        {{ formatBytes(value) || "-" }}
      </template>
      <template #cell-actions="{ item }">
        <div class="banner-actions">
          <v-btn
            size="x-small"
            color="success"
            variant="tonal"
            :disabled="loading || isBannerActionLoading(item.port_id, 'start') || !item.port_id || normalizePortScanState(item.scan_state) === 'active'"
            @click="runBannerAction(item, 'start')"
          >
            Start
          </v-btn>
          <v-btn
            size="x-small"
            color="warning"
            variant="tonal"
            :disabled="loading || isBannerActionLoading(item.port_id, 'stop') || !item.port_id || normalizePortScanState(item.scan_state) === 'stopped'"
            @click="runBannerAction(item, 'stop')"
          >
            Stop
          </v-btn>
          <v-btn
            size="x-small"
            color="info"
            variant="tonal"
            :disabled="loading || isBannerActionLoading(item.port_id, 'restart') || !item.port_id"
            @click="runBannerAction(item, 'restart')"
          >
            Restart
          </v-btn>
        </div>
      </template>
    </EntityTablePanel>

    <EntityTablePanel
      v-else
      title="Captured Favicons"
      subtitle="Favicons discovered on HTTP or HTTPS services."
      v-model:live-enabled="liveRefreshEnabled"
      :rows="filteredFavicons"
      :columns="faviconColumns"
      :expandable-rows="true"
      :loading="loading"
      :error="error"
      :last-updated="lastUpdated"
      :live-refresh="true"
      empty-text="No favicons found"
      @refresh="load"
    >
      <template #cell-preview="{ item }">
        <button
          type="button"
          class="favicon-button"
          :title="`Open favicon ${item.id}`"
          :aria-label="`Open favicon ${item.id}`"
          @click="openFavicon(item)"
        >
          <img :src="faviconSrc(item)" alt="favicon" class="favicon-thumb" />
        </button>
      </template>
      <template #cell-size="{ value }">
        {{ formatSize(value) }}
      </template>
    </EntityTablePanel>
  </div>
</template>

<script>
import store from "../state/appStore";
import ViewHeader from "../components/ui/ViewHeader.vue";
import EntityTablePanel from "../components/ui/EntityTablePanel.vue";
import {
  buildResponseSummary,
  formatBytes,
  formatTimestamp,
  hasOptionValue,
  matchesSearch,
  uniqueSorted,
} from "../utils/traffic";

// Cadence for the stream, in milliseconds.
const FEED_REFRESH_MS = 1000;
const FEED_LIMIT = 500;

export default {
  name: "BannersView",
  components: {
    ViewHeader,
    EntityTablePanel,
  },
  data() {
    return {
      store,
      tab: "banners",
      loading: false,
      error: "",
      lastUpdated: "",
      liveRefreshEnabled: true,
      banners: [],
      favicons: [],
      bannerColumns: [
        { key: "updated_at", label: "Seen" },
        { key: "proto", label: "Proto" },
        { key: "src_ip", label: "Src IP" },
        { key: "src_port", label: "Src Port" },
        { key: "dst_ip", label: "Dst IP" },
        { key: "dst_port", label: "Dst Port" },
        { key: "scan_state", label: "State" },
        { key: "response_size", label: "Size" },
        { key: "response_plain", label: "Response" },
        { key: "actions", label: "Actions" },
      ],
      faviconColumns: [
        { key: "id", label: "ID" },
        { key: "ip", label: "IP" },
        { key: "port", label: "Port" },
        { key: "proto", label: "Proto" },
        { key: "preview", label: "Preview" },
        { key: "icon_url", label: "Icon URL" },
        { key: "mime_type", label: "MIME" },
        { key: "size", label: "Size" },
      ],
      tableFilters: {
        query: "",
        proto: "",
        mime: "",
      },
      bannerActionLoading: {
        id: null,
        action: "",
      },
      feedHandle: null,
    };
  },
  computed: {
    apiBase() {
      return this.store.state.apiBase;
    },
    protoFilterOptions() {
      const source = this.tab === "favicons" ? this.favicons : this.banners;
      const values = uniqueSorted(source.map((item) => item.proto));
      return [{ label: "All", value: "" }, ...values.map((value) => ({ label: value.toUpperCase(), value }))];
    },
    mimeFilterOptions() {
      const values = uniqueSorted(this.favicons.map((item) => item.mime_type));
      return [{ label: "All", value: "" }, ...values.map((value) => ({ label: value, value }))];
    },
    filteredBanners() {
      const query = String(this.tableFilters.query || "").trim().toLowerCase();
      const proto = String(this.tableFilters.proto || "").trim().toLowerCase();
      return this.banners.filter((item) => {
        if (proto && String(item.proto || "").trim().toLowerCase() !== proto) return false;
        return matchesSearch(query, [
          item.proto,
          item.src_ip,
          item.dst_ip,
          item.src_port,
          item.dst_port,
          item.interface,
          item.response_size,
          item.summary,
          item.response_plain,
          item.tags || [],
        ]);
      });
    },
    filteredFavicons() {
      const query = String(this.tableFilters.query || "").trim().toLowerCase();
      const proto = String(this.tableFilters.proto || "").trim().toLowerCase();
      const mime = String(this.tableFilters.mime || "").trim().toLowerCase();
      return this.favicons.filter((item) => {
        if (proto && String(item.proto || "").trim().toLowerCase() !== proto) return false;
        if (mime && String(item.mime_type || "").trim().toLowerCase() !== mime) return false;
        return matchesSearch(query, [
          item.id,
          item.ip,
          item.port,
          item.proto,
          item.icon_url,
          item.mime_type,
          item.sha256,
          item.size,
        ]);
      });
    },
  },
  watch: {
    apiBase() {
      this.loadFavicons();
      this.openFeed();
    },
    liveRefreshEnabled(value) {
      if (value) this.openFeed();
      else this.closeFeed();
    },
    tab() {
      this.tableFilters.proto = "";
      this.tableFilters.mime = "";
      this.syncFilters();
    },
  },
  mounted() {
    // Favicons are read once: they are decoded artefacts of past captures, not
    // a live counter, so re-sending them on every tick would be bytes spent to
    // deliver the same list again.
    this.loadFavicons();
    this.openFeed();
  },
  beforeUnmount() {
    this.closeFeed();
  },
  methods: {
    buildResponseSummary,
    formatBytes,
    formatTimestamp,
    syncFilters() {
      if (!hasOptionValue(this.protoFilterOptions, this.tableFilters.proto)) this.tableFilters.proto = "";
      if (!hasOptionValue(this.mimeFilterOptions, this.tableFilters.mime)) this.tableFilters.mime = "";
    },
    normalizePortScanState(value) {
      const raw = String(value || "active").trim().toLowerCase();
      if (raw === "restarting") return "restarting";
      if (raw === "stopped") return "stopped";
      return "active";
    },
    scanStatusLabel(value) {
      const status = this.normalizePortScanState(value);
      if (status === "restarting") return "restarting";
      if (status === "stopped") return "stopped";
      return "active";
    },
    scanStatusColor(value) {
      const status = this.normalizePortScanState(value);
      if (status === "restarting") return "info";
      if (status === "stopped") return "warning";
      return "success";
    },
    formatProgress(value) {
      const numeric = Number(value);
      if (!Number.isFinite(numeric)) return "-";
      return `${numeric.toFixed(0)}%`;
    },
    isBannerActionLoading(id, action) {
      return this.bannerActionLoading.id === id && this.bannerActionLoading.action === action;
    },
    faviconSrc(item) {
      return this.store.apiUrl(`/favicons/raw/?id=${item.id}`);
    },
    openFavicon(item) {
      if (typeof window === "undefined") return;
      window.open(this.faviconSrc(item), "_blank", "noopener,noreferrer");
    },
    // /ws/banners carries the same rows /banners/ returned, pushed at the
    // interval in its URL, replacing the HTTP re-read this view used to issue
    // on every websocket change event.
    openFeed() {
      this.closeFeed();
      this.loading = true;
      this.feedHandle = this.store.openDataFeed(
        "banners",
        { limit: FEED_LIMIT, refresh: FEED_REFRESH_MS },
        (payload) => this.applyFeed(payload),
        () => {
          this.loadBannersOnce().catch(() => null);
        },
      );
    },
    closeFeed() {
      if (this.feedHandle) {
        this.feedHandle.close();
        this.feedHandle = null;
      }
    },
    applyFeed(payload) {
      if (payload && payload.type === "feed_error") {
        this.error = payload.message || "The responses stream stopped updating";
        this.loading = false;
        return;
      }
      if (!payload || payload.type !== "feed_data") return;
      this.banners = this.store.feedListResult(payload).rows;
      this.error = "";
      this.lastUpdated = new Date().toLocaleTimeString();
      this.syncFilters();
      this.loading = false;
    },
    loadFavicons() {
      return this.store
        .fetchJsonPromise("/favicons/")
        .then((data) => {
          this.favicons = this.store.extractArray(data);
        })
        .catch(() => {
          this.favicons = [];
        });
    },
    loadBannersOnce() {
      return this.store.fetchJsonPromise("/banners/").then((data) => {
        this.banners = this.store.extractArray(data);
        this.lastUpdated = new Date().toLocaleTimeString();
        this.syncFilters();
        this.loading = false;
      });
    },
  },
};
</script>

<style scoped>
.mono {
  font-family: var(--font-mono);
}

.banner-text {
  display: inline-block;
  max-width: 480px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.banner-actions {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
}

.favicon-button {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 30px;
  height: 30px;
  border: 1px solid rgba(130, 170, 200, 0.3);
  border-radius: 8px;
  background: rgba(6, 12, 22, 0.65);
  cursor: pointer;
}

.favicon-thumb {
  width: 18px;
  height: 18px;
  object-fit: contain;
}
</style>
