<template>
  <div class="soc-view">
    <ViewHeader
      overline="SOC"
      title="SOC Triage Loop"
      description="Run up to four passes over the same traffic slice and turn the evidence into actions, questions, and next-step validation."
      :refresh-loading="loading"
      :show-time-range="true"
      @refresh="load"
    >
      <template #actions>
        <v-btn to="/ai" prepend-icon="mdi-brain" variant="tonal">IA · Feedback</v-btn>
        <IocExportMenu />
        <v-btn
          icon="mdi-refresh"
          variant="outlined"
          color="primary"
          density="comfortable"
          :loading="loading"
          aria-label="Refresh"
          @click="load"
        >
          <v-icon icon="mdi-refresh" />
          <v-tooltip activator="parent" location="bottom">Refresh</v-tooltip>
        </v-btn>
      </template>
    </ViewHeader>

    <v-row dense>
      <v-col v-for="metric in metricCards" :key="metric.key" cols="12" sm="6" xl="2">
        <v-card variant="tonal" class="pa-5 metric-card">
          <div class="d-flex align-center justify-space-between ga-3">
            <div>
              <div class="text-caption text-medium-emphasis">{{ metric.label }}</div>
              <div class="text-h5 font-weight-bold" :class="metric.colorClass">
                {{ metric.value }}
              </div>
            </div>
            <v-icon :icon="metric.icon" class="metric-icon" :class="metric.colorClass" />
          </div>
          <div class="text-caption text-medium-emphasis mt-3">
            {{ metric.caption }}
          </div>
        </v-card>
      </v-col>
    </v-row>

    <v-card class="soc-hero pa-6 pa-md-7 mt-4" rounded="xl" variant="tonal" :style="heroStyle">
      <v-row dense class="align-center">
        <v-col cols="12" lg="8">
          <div class="text-overline">Current assessment</div>
          <h2 class="soc-hero__title">{{ verdictTitle }}</h2>
          <p class="soc-hero__copy">
            {{ verdictCopy }}
          </p>

          <div class="soc-hero__chips">
            <v-chip size="small" color="primary" variant="tonal">
              Risk: {{ formatNumber(riskScore) }}/100
            </v-chip>
            <v-chip size="small" :color="verdictColor" variant="tonal">
              Verdict: {{ verdictLabel }}
            </v-chip>
            <v-chip size="small" color="info" variant="tonal">
              Priority: {{ priorityLabel }}
            </v-chip>
            <v-chip size="small" color="success" variant="tonal">
              Cycles: {{ cycles.length }}
            </v-chip>
            <v-chip size="small" color="warning" variant="tonal">
              Questions: {{ questions.length }}
            </v-chip>
            <v-chip size="small" variant="outlined">
              Updated: {{ lastUpdated || "pending" }}
            </v-chip>
          </div>

          <div class="soc-hero__progress">
            <div class="soc-hero__progress-label">
              <span>Risk score</span>
              <strong>{{ formatNumber(riskScore) }}/100</strong>
            </div>
            <v-progress-linear
              :model-value="riskScore"
              height="10"
              rounded
              :color="verdictColor"
              bg-color="rgba(120, 138, 156, 0.25)"
            />
          </div>
        </v-col>

        <v-col cols="12" lg="4">
          <div class="soc-hero__panel">
            <div class="soc-hero__panel-kicker">Run depth</div>
            <v-btn-toggle
              v-model="cyclesRequested"
              class="soc-cycle-toggle mt-3"
              mandatory
              color="primary"
              variant="outlined"
            >
              <v-btn
                v-for="option in cycleOptions"
                :key="option.value"
                :value="option.value"
                size="small"
              >
                {{ option.label }}
              </v-btn>
            </v-btn-toggle>

            <div class="soc-hero__switch mt-4">
              <v-switch
                v-model="liveRefreshEnabled"
                color="primary"
                inset
                hide-details
                density="comfortable"
                label="Live refresh"
              />
            </div>

            <div class="soc-hero__stats">
              <div class="soc-hero__stat">
                <span>Sampled packets</span>
                <strong>{{ formatNumber(summary.sampled_packets) }}</strong>
              </div>
              <div class="soc-hero__stat">
                <span>Sampled payloads</span>
                <strong>{{ formatNumber(summary.sampled_payloads) }}</strong>
              </div>
              <div class="soc-hero__stat">
                <span>Sampled tags</span>
                <strong>{{ formatNumber(summary.sampled_tags) }}</strong>
              </div>
              <div class="soc-hero__stat">
                <span>Sampled flows</span>
                <strong>{{ formatNumber(summary.sampled_flows) }}</strong>
              </div>
            </div>
          </div>
        </v-col>
      </v-row>
    </v-card>

    <v-alert v-if="error" type="error" variant="tonal" class="mt-6">
      {{ error }}
    </v-alert>

    <v-alert v-if="!loading && !cycles.length" type="info" variant="tonal" class="mt-6">
      No SOC evidence is available yet. Capture traffic first, then rerun the triage loop.
    </v-alert>

    <v-tabs v-if="cycles.length" v-model="activeCycleId" color="primary" class="mt-6 soc-tabs">
      <v-tab v-for="cycle in cycles" :key="cycle.id" :value="cycle.id" :disabled="loading">
        <div class="soc-tab">
          <span class="soc-tab__kicker">Pass {{ cycle.id }}</span>
          <span class="soc-tab__title">{{ cycle.title }}</span>
          <v-chip size="x-small" variant="tonal" color="info">
            {{ cycleFindingCount(cycle) }} findings
          </v-chip>
        </div>
      </v-tab>
    </v-tabs>

    <v-window v-model="activeCycleId" class="mt-4">
      <v-window-item v-for="cycle in cycles" :key="cycle.id" :value="cycle.id">
        <v-row dense>
          <v-col cols="12" lg="4">
            <DataPanel
              title="What this pass needed"
              subtitle="The questions the current cycle was trying to answer."
              :loading="loading"
              :error="''"
              :last-updated="lastUpdated"
              :show-refresh="false"
            >
              <div class="d-flex flex-wrap ga-2">
                <v-chip
                  v-for="item in cycle.need || []"
                  :key="`${cycle.id}-need-${item}`"
                  size="small"
                  color="primary"
                  variant="tonal"
                >
                  {{ item }}
                </v-chip>
              </div>
            </DataPanel>
          </v-col>

          <v-col cols="12" lg="4">
            <DataPanel
              title="Observed signals"
              subtitle="What the pass surfaced before moving to the next one."
              :loading="loading"
              :error="''"
              :last-updated="lastUpdated"
              :show-refresh="false"
            >
              <div class="soc-bullet-list">
                <div
                  v-for="(item, index) in cycle.observations || []"
                  :key="`${cycle.id}-obs-${index}`"
                  class="soc-bullet-list__item"
                >
                  <v-icon size="16" icon="mdi-radiobox-marked" class="mr-2" />
                  <span>{{ item }}</span>
                </div>
              </div>
            </DataPanel>
          </v-col>

          <v-col cols="12" lg="4">
            <DataPanel
              title="Cycle findings"
              subtitle="Findings generated by this pass."
              :loading="loading"
              :error="''"
              :last-updated="lastUpdated"
              :show-refresh="false"
            >
              <div class="d-flex flex-wrap ga-2 mb-4">
                <v-chip size="small" color="info" variant="tonal">
                  Findings: {{ cycleFindingCount(cycle) }}
                </v-chip>
                <v-chip size="small" :color="cycleSeverityColor(cycle)" variant="tonal">
                  Highest: {{ cycleHighestSeverity(cycle) }}
                </v-chip>
              </div>

              <div v-if="cyclePreviewFindings(cycle).length" class="soc-finding-preview">
                <div
                  v-for="finding in cyclePreviewFindings(cycle)"
                  :key="finding.id"
                  class="soc-finding-preview__item"
                >
                  <div class="d-flex align-center justify-space-between ga-3">
                    <div class="text-subtitle-2">{{ finding.title }}</div>
                    <v-chip size="x-small" :color="severityColor(finding.severity)" variant="tonal">
                      {{ finding.severity }}
                    </v-chip>
                  </div>
                  <div class="text-body-2 text-medium-emphasis mt-1">
                    {{ finding.category }} · {{ formatConfidence(finding.confidence) }}
                  </div>
                </div>
              </div>
              <div v-else class="text-body-2 text-medium-emphasis">
                This pass did not surface an explicit finding.
              </div>
            </DataPanel>
          </v-col>
        </v-row>
      </v-window-item>
    </v-window>

    <v-row class="mt-4" dense>
      <v-col v-for="chart in chartPanels" :key="chart.key" cols="12" xl="6">
        <v-card variant="tonal" class="pa-5 chart-card">
          <div class="d-flex align-start justify-space-between ga-3">
            <div>
              <div class="text-subtitle-1">{{ chart.title }}</div>
              <div class="text-caption text-medium-emphasis">{{ chart.subtitle }}</div>
            </div>
            <v-chip size="small" variant="outlined" :color="chart.color">
              {{ formatNumber(chart.series.length) }}
            </v-chip>
          </div>

          <div v-if="chart.series.length" class="chart-stack mt-4">
            <div v-for="item in chart.series" :key="`${chart.key}-${item.label}`" class="chart-row">
              <div class="chart-row__label" :title="item.label">
                {{ item.label }}
              </div>
              <div class="chart-row__track" aria-hidden="true">
                <div class="chart-row__fill" :style="chartFillStyle(chart, item)" />
              </div>
              <div class="chart-row__value">
                {{ formatNumber(item.value) }}
              </div>
            </div>
          </div>

          <div v-else class="chart-empty text-medium-emphasis mt-4">
            No data available for this signal.
          </div>
        </v-card>
      </v-col>
    </v-row>

    <v-row class="mt-4" dense>
      <v-col cols="12" xl="8">
        <EntityTablePanel
          title="Findings"
          subtitle="Active findings from the selected cycle."
          :rows="activeCycleFindings"
          :columns="findingColumns"
          row-key="row_key"
          :search-enabled="true"
          search-label="Search findings"
          search-placeholder="Title, category, severity, evidence, or recommendation"
          :search-fields="findingSearchFields"
          :filter-definitions="findingFilterDefinitions"
          :expandable-rows="true"
          :loading="loading"
          :error="''"
          :last-updated="lastUpdated"
          :live-refresh="false"
          :page-size="20"
          empty-text="No findings for the active cycle"
        >
          <template #cell-cycle="{ value }">
            <v-chip size="x-small" color="info" variant="tonal">
              C{{ value }}
            </v-chip>
          </template>
          <template #cell-severity="{ value }">
            <v-chip size="x-small" :color="severityColor(value)" variant="tonal">
              {{ value }}
            </v-chip>
          </template>
          <template #cell-category="{ value }">
            <v-chip size="x-small" color="secondary" variant="tonal">
              {{ value }}
            </v-chip>
          </template>
          <template #cell-title="{ value }">
            <span class="summary-cell">{{ value || "-" }}</span>
          </template>
          <template #cell-confidence="{ value }">
            <v-chip size="x-small" color="primary" variant="tonal">
              {{ formatConfidence(value) }}
            </v-chip>
          </template>
          <template #cell-evidence_count="{ value }">
            <v-chip size="x-small" color="warning" variant="tonal">
              {{ formatNumber(value) }}
            </v-chip>
          </template>
          <template #cell-recommendation="{ value }">
            <span class="summary-cell">{{ value || "-" }}</span>
          </template>
          <template #row-expanded="{ item }">
            <div class="soc-expanded">
              <div class="soc-expanded__label">Evidence</div>
              <div class="d-flex flex-wrap ga-2 mt-2">
                <v-chip
                  v-for="(evidence, index) in item.evidence || []"
                  :key="`${item.id}-evidence-${index}`"
                  size="small"
                  variant="tonal"
                  color="info"
                >
                  {{ evidence }}
                </v-chip>
                <span v-if="!Array.isArray(item.evidence) || !item.evidence.length" class="text-body-2 text-medium-emphasis">
                  No evidence details were attached.
                </span>
              </div>

              <div class="soc-expanded__label mt-4">Recommendation</div>
              <div class="text-body-2 text-medium-emphasis mt-1">
                {{ item.recommendation || "-" }}
              </div>
            </div>
          </template>
        </EntityTablePanel>
      </v-col>

      <v-col cols="12" xl="4">
        <DataPanel
          title="Open questions"
          subtitle="The next validation pass should answer these items."
          :loading="loading"
          :error="''"
          :last-updated="lastUpdated"
          :show-refresh="false"
        >
          <div class="d-flex flex-wrap ga-2 mb-4">
            <v-chip size="small" color="info" variant="tonal">
              Questions: {{ questions.length }}
            </v-chip>
            <v-chip size="small" color="success" variant="tonal">
              Public rows: {{ formatNumber(summary.public_rows) }}
            </v-chip>
            <v-chip size="small" color="warning" variant="tonal">
              Cross-scope: {{ formatNumber(summary.cross_scope_rows) }}
            </v-chip>
          </div>

          <div v-if="questions.length" class="soc-question-list">
            <div
              v-for="(question, index) in questions"
              :key="`question-${index}`"
              class="soc-question-list__item"
            >
              <v-chip size="x-small" color="primary" variant="tonal">
                Q{{ index + 1 }}
              </v-chip>
              <span>{{ question }}</span>
            </div>
          </div>
          <div v-else class="text-body-2 text-medium-emphasis">
            The backend did not produce follow-up questions for this slice.
          </div>
        </DataPanel>
      </v-col>
    </v-row>

    <v-row class="mt-4" dense>
      <v-col cols="12" xl="6">
        <EntityTablePanel
          title="Top Hosts"
          subtitle="Hosts that need ownership and exposure validation."
          :rows="topHostRows"
          :columns="hostColumns"
          row-key="row_key"
          :search-enabled="true"
          search-label="Search hosts"
          search-placeholder="IP, scope, protocols, ports, or note"
          :search-fields="hostSearchFields"
          :filter-definitions="hostFilterDefinitions"
          :loading="loading"
          :error="''"
          :last-updated="lastUpdated"
          :live-refresh="false"
          :page-size="20"
          empty-text="No host evidence available"
        >
          <template #cell-ip="{ value }">
            <router-link class="soc-link" :to="{ path: '/investigate', query: { ip: value } }">
              {{ value }}
            </router-link>
          </template>
          <template #cell-scope="{ value }">
            <v-chip size="x-small" :color="scopeColor(value)" variant="tonal">
              {{ value }}
            </v-chip>
          </template>
          <template #cell-value="{ value }">
            <v-chip size="x-small" color="info" variant="tonal">
              {{ formatNumber(value) }}
            </v-chip>
          </template>
          <template #cell-note="{ value }">
            <span class="summary-cell">{{ value || "-" }}</span>
          </template>
        </EntityTablePanel>
      </v-col>

      <v-col cols="12" xl="6">
        <EntityTablePanel
          title="Top Conversations"
          subtitle="Directed flows and their peer scopes."
          :rows="topConversationRows"
          :columns="conversationColumns"
          row-key="row_key"
          :search-enabled="true"
          search-label="Search conversations"
          search-placeholder="Source, target, ports, scope, or note"
          :search-fields="conversationSearchFields"
          :filter-definitions="conversationFilterDefinitions"
          :loading="loading"
          :error="''"
          :last-updated="lastUpdated"
          :live-refresh="false"
          :page-size="20"
          empty-text="No conversation evidence available"
        >
          <template #cell-value="{ value }">
            <v-chip size="x-small" color="info" variant="tonal">
              {{ formatNumber(value) }}
            </v-chip>
          </template>
          <template #cell-proto="{ value }">
            <v-chip size="x-small" color="primary" variant="tonal">
              {{ String(value || "unknown").toUpperCase() }}
            </v-chip>
          </template>
          <template #cell-scope="{ value }">
            <v-chip size="x-small" :color="scopeColor(value)" variant="tonal">
              {{ value }}
            </v-chip>
          </template>
          <template #cell-note="{ value }">
            <span class="summary-cell">{{ value || "-" }}</span>
          </template>
        </EntityTablePanel>
      </v-col>
    </v-row>

    <v-row class="mt-4" dense>
      <v-col cols="12" xl="6">
        <EntityTablePanel
          title="Top Ports"
          subtitle="Ports that deserve service-owner validation."
          :rows="topPortRows"
          :columns="portColumns"
          row-key="row_key"
          :search-enabled="true"
          search-label="Search ports"
          search-placeholder="Port, protocols, scope, or note"
          :search-fields="portSearchFields"
          :filter-definitions="portFilterDefinitions"
          :loading="loading"
          :error="''"
          :last-updated="lastUpdated"
          :live-refresh="false"
          :page-size="20"
          empty-text="No port evidence available"
        >
          <template #cell-port="{ value }">
            <v-chip size="x-small" color="warning" variant="tonal">
              {{ value }}
            </v-chip>
          </template>
          <template #cell-scope="{ value }">
            <v-chip size="x-small" :color="scopeColor(value)" variant="tonal">
              {{ value }}
            </v-chip>
          </template>
          <template #cell-value="{ value }">
            <v-chip size="x-small" color="info" variant="tonal">
              {{ formatNumber(value) }}
            </v-chip>
          </template>
          <template #cell-note="{ value }">
            <span class="summary-cell">{{ value || "-" }}</span>
          </template>
        </EntityTablePanel>
      </v-col>

      <v-col cols="12" xl="6">
        <EntityTablePanel
          title="Payload Patterns"
          subtitle="What the sample looks like when you strip transport away."
          :rows="payloadPatternRows"
          :columns="payloadColumns"
          row-key="row_key"
          :search-enabled="true"
          search-label="Search payloads"
          search-placeholder="Label, note, or example"
          :search-fields="payloadSearchFields"
          :loading="loading"
          :error="''"
          :last-updated="lastUpdated"
          :live-refresh="false"
          :page-size="20"
          empty-text="No payload pattern evidence available"
        >
          <template #cell-value="{ value }">
            <v-chip size="x-small" color="secondary" variant="tonal">
              {{ formatNumber(value) }}
            </v-chip>
          </template>
          <template #cell-note="{ value }">
            <span class="summary-cell">{{ value || "-" }}</span>
          </template>
          <template #cell-example="{ value }">
            <span class="summary-cell">{{ value || "-" }}</span>
          </template>
        </EntityTablePanel>
      </v-col>
    </v-row>
  </div>
</template>

<script>
import store from "../state/appStore";
import ViewHeader from "../components/ui/ViewHeader.vue";
import IocExportMenu from "../components/ui/IocExportMenu.vue";
import DataPanel from "../components/ui/DataPanel.vue";
import EntityTablePanel from "../components/ui/EntityTablePanel.vue";
import { formatTimestamp } from "../utils/traffic";

// Cadence for the stream, in milliseconds.
const FEED_REFRESH_MS = 1000;
const FEED_LIMIT = 2000;
const SEVERITY_ORDER = new Map([
  ["high", 0],
  ["medium", 1],
  ["low", 2],
  ["info", 3],
]);

function normalizeSeverity(value) {
  const severity = String(value || "info").trim().toLowerCase();
  if (SEVERITY_ORDER.has(severity)) return severity;
  return "info";
}

function compareFindings(left, right) {
  const leftSeverity = normalizeSeverity(left && left.severity);
  const rightSeverity = normalizeSeverity(right && right.severity);
  const leftSeverityRank = SEVERITY_ORDER.has(leftSeverity) ? SEVERITY_ORDER.get(leftSeverity) : 3;
  const rightSeverityRank = SEVERITY_ORDER.has(rightSeverity) ? SEVERITY_ORDER.get(rightSeverity) : 3;
  const severityDiff = leftSeverityRank - rightSeverityRank;
  if (severityDiff !== 0) return severityDiff;
  const leftConfidence = Number(left && left.confidence ? left.confidence : 0);
  const rightConfidence = Number(right && right.confidence ? right.confidence : 0);
  if (rightConfidence !== leftConfidence) return rightConfidence - leftConfidence;
  return String(left && left.title ? left.title : "").localeCompare(String(right && right.title ? right.title : ""));
}

function seriesFrom(rows, limit = 6) {
  const series = (Array.isArray(rows) ? rows : [])
    .map((row) => ({
      label: String((row && (row.label ?? row.name ?? row.ip ?? row.port)) || "").trim(),
      value: Number(row && row.value ? row.value : 0),
    }))
    .filter((item) => item.label)
    .sort((left, right) => right.value - left.value || left.label.localeCompare(right.label))
    .slice(0, limit);
  const maxValue = series.length ? Math.max(...series.map((item) => item.value)) : 0;
  return series.map((item) => ({
    ...item,
    width: maxValue > 0 ? Math.max(10, Math.round((item.value / maxValue) * 100)) : 0,
  }));
}

export default {
  name: "SocView",
  components: {
    ViewHeader,
    IocExportMenu,
    DataPanel,
    EntityTablePanel,
  },
  data() {
    return {
      store,
      loading: false,
      error: "",
      lastUpdated: "",
      liveRefreshEnabled: true,
      cyclesRequested: 4,
      activeCycleId: 4,
      analysis: {},
      loadSequence: 0,
      feedHandle: null,
      cycleOptions: [
        { value: 1, label: "1 pass" },
        { value: 2, label: "2 passes" },
        { value: 3, label: "3 passes" },
        { value: 4, label: "4 passes" },
      ],
      findingColumns: [
        { key: "cycle", label: "Cycle" },
        { key: "severity", label: "Severity" },
        { key: "category", label: "Category" },
        { key: "title", label: "Title" },
        { key: "confidence", label: "Confidence" },
        { key: "evidence_count", label: "Evidence" },
        { key: "recommendation", label: "Recommendation", sortable: false },
      ],
      hostColumns: [
        { key: "ip", label: "IP" },
        { key: "scope", label: "Scope" },
        { key: "value", label: "Hits" },
        { key: "protocols", label: "Protocols" },
        { key: "ports", label: "Ports" },
        { key: "note", label: "Note", sortable: false },
      ],
      conversationColumns: [
        { key: "label", label: "Conversation" },
        { key: "proto", label: "Proto" },
        { key: "ports", label: "Ports" },
        { key: "scope", label: "Scope" },
        { key: "value", label: "Hits" },
        { key: "note", label: "Note", sortable: false },
      ],
      portColumns: [
        { key: "port", label: "Port" },
        { key: "scope", label: "Scope" },
        { key: "protocols", label: "Protocols" },
        { key: "value", label: "Hits" },
        { key: "note", label: "Note", sortable: false },
      ],
      payloadColumns: [
        { key: "label", label: "Pattern" },
        { key: "value", label: "Hits" },
        { key: "note", label: "Note" },
        { key: "example", label: "Example", sortable: false },
      ],
    };
  },
  computed: {
    summary() {
      return this.analysis.soc_summary || {};
    },
    cycles() {
      return Array.isArray(this.analysis.cycles) ? this.analysis.cycles : [];
    },
    findings() {
      return Array.isArray(this.analysis.findings)
        ? this.analysis.findings.map((finding) => ({
          ...finding,
          row_key: finding.id,
          evidence_count: Array.isArray(finding.evidence) ? finding.evidence.length : 0,
        }))
        : [];
    },
    questions() {
      return Array.isArray(this.analysis.questions) ? this.analysis.questions : [];
    },
    verdictLabel() {
      return String(this.summary.verdict || "observe").trim() || "observe";
    },
    priorityLabel() {
      return String(this.summary.priority || this.summary.verdict || "observe").trim() || "observe";
    },
    riskScore() {
      const numeric = Number(this.summary.risk_score || 0);
      if (!Number.isFinite(numeric) || numeric < 0) return 0;
      if (numeric > 100) return 100;
      return numeric;
    },
    verdictColor() {
      const verdict = this.verdictLabel.toLowerCase();
      if (verdict === "investigate") return "error";
      if (verdict === "review") return "warning";
      if (verdict === "monitor") return "info";
      return "secondary";
    },
    heroStyle() {
      return {
        "--soc-accent": this.verdictAccent,
        "--soc-accent-soft": this.verdictAccentSoft,
      };
    },
    verdictAccent() {
      const verdict = this.verdictLabel.toLowerCase();
      if (verdict === "investigate") return "rgba(255, 92, 92, 0.96)";
      if (verdict === "review") return "rgba(255, 159, 67, 0.94)";
      if (verdict === "monitor") return "rgba(52, 230, 255, 0.88)";
      return "rgba(140, 156, 176, 0.84)";
    },
    verdictAccentSoft() {
      const verdict = this.verdictLabel.toLowerCase();
      if (verdict === "investigate") return "rgba(255, 92, 92, 0.26)";
      if (verdict === "review") return "rgba(255, 159, 67, 0.22)";
      if (verdict === "monitor") return "rgba(52, 230, 255, 0.18)";
      return "rgba(140, 156, 176, 0.16)";
    },
    verdictTitle() {
      const verdict = this.verdictLabel.toLowerCase();
      if (verdict === "investigate") return "Immediate investigation recommended";
      if (verdict === "review") return "Review this slice before promoting it";
      if (verdict === "monitor") return "Monitor the slice and keep validating";
      return "Observation mode is sufficient for now";
    },
    verdictCopy() {
      const verdict = this.verdictLabel.toLowerCase();
      if (verdict === "investigate") {
        return "The pass surfaced public exposure, cross-scope traffic, and enough uncertainty to justify immediate follow-up on ownership and remote access paths.";
      }
      if (verdict === "review") {
        return "This slice is not clean enough to dismiss. Validate the public hosts, tunnel-like ports, and any loopback telemetry owners before moving on.";
      }
      if (verdict === "monitor") {
        return "The evidence points to expected traffic with a few items worth keeping on the radar. Recheck ownership and protocol drift on the next pass.";
      }
      return "The current slice is mostly local or low-risk evidence. Keep the loop available, but there is no strong escalation signal yet.";
    },
    metricCards() {
      return [
        {
          key: "packets",
          label: "Packets",
          value: this.formatNumber(this.summary.sampled_packets),
          caption: "Rows sampled by the SOC loop.",
          icon: "mdi-ethernet",
          colorClass: "text-primary",
        },
        {
          key: "findings",
          label: "Findings",
          value: this.formatNumber(this.summary.findings_total),
          caption: "Findings that survived the selected cycles.",
          icon: "mdi-clipboard-alert-outline",
          colorClass: "text-warning",
        },
        {
          key: "risk",
          label: "Risk",
          value: this.formatNumber(this.riskScore),
          caption: "Aggregate risk score for the selected cycle depth.",
          icon: "mdi-shield-alert-outline",
          colorClass: `text-${this.verdictColor}`,
        },
        {
          key: "cross-scope",
          label: "Cross-scope",
          value: this.formatNumber(this.summary.cross_scope_rows),
          caption: "Rows crossing public and private scope.",
          icon: "mdi-transit-connection-variant",
          colorClass: "text-secondary",
        },
        {
          key: "public",
          label: "Public",
          value: this.formatNumber(this.summary.public_rows),
          caption: "Public-side rows in the sample.",
          icon: "mdi-web",
          colorClass: "text-success",
        },
        {
          key: "gaps",
          label: "Direction gaps",
          value: this.formatNumber(this.summary.direction_unknown_rows),
          caption: "Rows that still need direction metadata.",
          icon: "mdi-swap-horizontal",
          colorClass: "text-info",
        },
      ];
    },
    activeCycle() {
      const cycleId = Number(this.activeCycleId || 0);
      return this.cycles.find((cycle) => Number(cycle.id || 0) === cycleId) || this.cycles[0] || null;
    },
    activeCycleFindings() {
      return this.findingsForCycle(this.activeCycle).map((finding) => ({
        ...finding,
        row_key: finding.id,
      }));
    },
    hostRows() {
      return this.decorateRows(this.analysis.top_hosts, (row, index) => row.ip || row.label || `host-${index}`);
    },
    conversationRows() {
      return this.decorateRows(
        this.analysis.top_conversations,
        (row, index) => `${row.label || "conversation"}|${row.proto || "unknown"}|${row.ports || "0"}|${row.scope || "unknown"}|${index}`
      );
    },
    portRows() {
      return this.decorateRows(this.analysis.top_ports, (row, index) => `${row.port || "port"}|${row.scope || "unknown"}|${index}`);
    },
    payloadPatternRows() {
      return this.decorateRows(this.analysis.payload_patterns, (row, index) => `${row.label || "payload"}|${index}`);
    },
    analysisSignals() {
      return this.analysis.signals || {};
    },
    chartPanels() {
      return [
        {
          key: "protocols",
          title: "Protocol mix",
          subtitle: "What the selected passes see by protocol family.",
          color: "primary",
          fill: "linear-gradient(90deg, rgba(52, 230, 255, 0.94), rgba(74, 136, 255, 0.86))",
          series: seriesFrom(this.analysisSignals.protocols, 6),
        },
        {
          key: "directions",
          title: "Direction mix",
          subtitle: "Inbound, outbound, and unknown direction labels.",
          color: "info",
          fill: "linear-gradient(90deg, rgba(74, 136, 255, 0.9), rgba(52, 230, 255, 0.7))",
          series: seriesFrom(this.analysisSignals.directions, 6),
        },
        {
          key: "scopes",
          title: "Row scopes",
          subtitle: "Local, private, public, and cross-scope rows.",
          color: "warning",
          fill: "linear-gradient(90deg, rgba(255, 159, 67, 0.92), rgba(243, 177, 75, 0.78))",
          series: seriesFrom(this.analysisSignals.row_scopes, 6),
        },
        {
          key: "payloads",
          title: "Payload patterns",
          subtitle: "How the payloads split between structured, text, and noisy evidence.",
          color: "secondary",
          fill: "linear-gradient(90deg, rgba(161, 138, 255, 0.9), rgba(255, 159, 67, 0.72))",
          series: seriesFrom(this.payloadPatternRows, 6),
        },
      ];
    },
    findingSearchFields() {
      return ["id", "cycle", "severity", "category", "title", "confidence", "recommendation", "evidence"];
    },
    findingFilterDefinitions() {
      return [
        { key: "severity", label: "Severity", field: "severity" },
        { key: "category", label: "Category", field: "category" },
      ];
    },
    hostSearchFields() {
      return ["ip", "scope", "value", "protocols", "ports", "note"];
    },
    hostFilterDefinitions() {
      return [{ key: "scope", label: "Scope", field: "scope" }];
    },
    conversationSearchFields() {
      return ["label", "proto", "ports", "scope", "value", "note"];
    },
    conversationFilterDefinitions() {
      return [
        { key: "scope", label: "Scope", field: "scope" },
        { key: "proto", label: "Proto", field: "proto" },
      ];
    },
    portSearchFields() {
      return ["port", "scope", "protocols", "value", "note"];
    },
    portFilterDefinitions() {
      return [{ key: "scope", label: "Scope", field: "scope" }];
    },
    payloadSearchFields() {
      return ["label", "value", "note", "example"];
    },
  },
  watch: {
    liveRefreshEnabled(value) {
      if (value) this.openFeed();
      else this.closeFeed();
    },
    cyclesRequested() {
      this.openFeed();
    },
    apiBase() {
      this.openFeed();
    },
  },
  mounted() {
    this.openFeed();
  },
  beforeUnmount() {
    this.closeFeed();
  },
  methods: {
    formatTimestamp,
    formatNumber(value) {
      const numeric = Number(value || 0);
      if (!Number.isFinite(numeric)) return "0";
      return numeric.toLocaleString();
    },
    formatConfidence(value) {
      const numeric = Number(value || 0);
      if (!Number.isFinite(numeric)) return "0%";
      const normalized = numeric <= 1 ? numeric * 100 : numeric;
      return `${Math.round(normalized)}%`;
    },
    severityColor(value) {
      const severity = normalizeSeverity(value);
      if (severity === "high") return "error";
      if (severity === "medium") return "warning";
      if (severity === "low") return "info";
      return "secondary";
    },
    scopeColor(value) {
      const scope = String(value || "").trim().toLowerCase();
      if (scope === "public") return "error";
      if (scope === "cross-scope") return "warning";
      if (scope === "private") return "info";
      if (scope === "local") return "success";
      return "secondary";
    },
    chartFillStyle(chart, item) {
      return {
        width: `${item.width}%`,
        background: chart.fill,
      };
    },
    decorateRows(rows, keyResolver) {
      return (Array.isArray(rows) ? rows : []).map((row, index) => ({
        ...(row && typeof row === "object" ? row : { value: row }),
        row_key: typeof keyResolver === "function" ? keyResolver(row || {}, index) : `row-${index}`,
      }));
    },
    findingsForCycle(cycle) {
      const cycleId = Number(cycle && cycle.id ? cycle.id : cycle);
      return this.findings
        .filter((finding) => Number(finding.cycle || 0) === cycleId)
        .slice()
        .sort(compareFindings);
    },
    cyclePreviewFindings(cycle) {
      return this.findingsForCycle(cycle).slice(0, 2);
    },
    cycleFindingCount(cycle) {
      if (!cycle) return 0;
      if (typeof cycle.finding_count === "number") return cycle.finding_count;
      if (Array.isArray(cycle.finding_ids)) return cycle.finding_ids.length;
      return this.findingsForCycle(cycle).length;
    },
    cycleHighestSeverity(cycle) {
      const rows = this.findingsForCycle(cycle);
      if (!rows.length) return "info";
      return normalizeSeverity(rows[0] && rows[0].severity);
    },
    cycleSeverityColor(cycle) {
      return this.severityColor(this.cycleHighestSeverity(cycle));
    },
    // /ws/soc carries the same analysis /api/soc/analysis/ returned, pushed at
    // the interval in its URL.
    openFeed() {
      this.closeFeed();
      this.loading = true;
      this.feedHandle = this.store.openDataFeed(
        "soc",
        {
          cycles: Number.parseInt(this.cyclesRequested, 10) || 4,
          limit: FEED_LIMIT,
          refresh: FEED_REFRESH_MS,
        },
        (payload) => this.applyFeed(payload),
        () => {
          this.load({ silent: true }).catch(() => null);
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
        this.error = payload.message || "The SOC stream stopped updating";
        this.loading = false;
        return;
      }
      if (!payload || payload.type !== "feed_data") return;
      this.analysis = payload.data || {};
      this.lastUpdated = this.analysis.generated_at
        ? formatTimestamp(this.analysis.generated_at)
        : new Date().toLocaleTimeString();
      if (!this.cycles.length) {
        this.activeCycleId = 1;
      } else if (!this.cycles.some((cycle) => Number(cycle.id || 0) === Number(this.activeCycleId || 0))) {
        this.activeCycleId = this.cycles[this.cycles.length - 1].id;
      }
      this.error = "";
      this.loading = false;
    },
    // Kept as the single-shot fallback for when the stream cannot serve.
    async load(options = {}) {
      const loadSeq = ++this.loadSequence;
      const requestedCycles = Number.parseInt(this.cyclesRequested, 10) || 4;
      if (!options.silent) this.loading = true;
      this.error = "";
      try {
        const payload = await this.store.fetchJsonPromise(
          `/api/soc/analysis/${this.store.buildListQuery({
            params: { cycles: requestedCycles },
            limit: 2000,
          })}`
        );
        if (loadSeq !== this.loadSequence) return;
        this.analysis = payload || {};
        this.lastUpdated = this.analysis.generated_at
          ? formatTimestamp(this.analysis.generated_at)
          : new Date().toLocaleTimeString();
        if (!this.cycles.length) {
          this.activeCycleId = 1;
        } else if (!this.cycles.some((cycle) => Number(cycle.id || 0) === Number(this.activeCycleId || 0))) {
          this.activeCycleId = this.cycles[this.cycles.length - 1].id;
        }
      } catch (err) {
        if (loadSeq !== this.loadSequence) return;
        this.analysis = {};
        this.lastUpdated = "";
        this.error = (err && err.message) || "Failed to load SOC analysis";
      } finally {
        if (loadSeq === this.loadSequence) {
          this.loading = false;
        }
      }
    },
  },
};
</script>

<style scoped>
.soc-view {
  position: relative;
}

.soc-hero {
  position: relative;
  overflow: hidden;
  border: 1px solid rgba(104, 184, 229, 0.22);
  background:
    linear-gradient(145deg, rgba(12, 21, 32, 0.96), rgba(9, 16, 25, 0.92));
}

.soc-hero__title {
  margin: 10px 0 0;
  font-size: clamp(2rem, 4vw, 3.25rem);
  line-height: 1;
}

.soc-hero__copy {
  max-width: 72ch;
  margin: 14px 0 0;
  color: rgba(217, 229, 243, 0.82);
  line-height: 1.65;
}

.soc-hero__chips {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-top: 18px;
}

.soc-hero__progress {
  margin-top: 22px;
}

.soc-hero__progress-label {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 8px;
  color: rgba(217, 229, 243, 0.82);
}

.soc-hero__progress-label strong {
  font-family: var(--font-mono);
  font-size: 0.88rem;
}

.soc-hero__panel {
  position: relative;
  padding: 18px 18px 16px;
  border: 1px solid rgba(104, 184, 229, 0.18);
  border-radius: 20px;
  background: linear-gradient(180deg, rgba(8, 15, 24, 0.76), rgba(7, 13, 21, 0.9));
  backdrop-filter: blur(10px);
}

.soc-hero__panel-kicker {
  color: rgba(120, 220, 255, 0.92);
  font-size: 0.72rem;
  font-weight: 700;
  letter-spacing: 0.16em;
  text-transform: uppercase;
}

.soc-hero__switch {
  display: flex;
  align-items: center;
}

.soc-hero__stats {
  display: grid;
  gap: 10px;
  margin-top: 10px;
}

.soc-hero__stat {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 10px 12px;
  border-radius: 14px;
  background: rgba(4, 10, 18, 0.42);
}

.soc-hero__stat span {
  color: rgba(171, 194, 216, 0.78);
  font-size: 0.8rem;
}

.soc-hero__stat strong {
  font-family: var(--font-mono);
  font-size: 0.88rem;
  font-weight: 700;
}

.soc-tabs {
  border-bottom: 1px solid rgba(104, 184, 229, 0.14);
  overflow-x: auto;
}

.soc-tabs :deep(.v-slide-group__content) {
  gap: 10px;
  padding-bottom: 2px;
}

.soc-tabs :deep(.v-tab) {
  min-height: 74px;
  padding-inline: 18px;
  border-radius: 18px 18px 0 0;
  background: rgba(8, 14, 22, 0.46);
  color: rgba(204, 223, 244, 0.88);
  transition: background-color 0.18s ease, color 0.18s ease, box-shadow 0.18s ease;
}

.soc-tabs :deep(.v-tab--selected) {
  color: rgba(243, 248, 255, 0.98);
  background: linear-gradient(180deg, rgba(19, 34, 52, 0.94), rgba(10, 18, 28, 0.98));
  box-shadow: inset 0 0 0 1px rgba(112, 188, 231, 0.2);
}

.soc-tabs :deep(.v-tab__slider) {
  opacity: 0;
}

.soc-tab {
  display: grid;
  gap: 4px;
  justify-items: start;
  text-align: left;
  padding: 8px 0;
}

.soc-tab__kicker {
  font-size: 0.72rem;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  color: rgba(140, 156, 176, 0.88);
}

.soc-tab__title {
  font-size: 0.9rem;
  font-weight: 700;
}

.soc-bullet-list {
  display: grid;
  gap: 10px;
}

.soc-bullet-list__item {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  line-height: 1.55;
  color: rgba(217, 229, 243, 0.82);
}

.soc-finding-preview {
  display: grid;
  gap: 12px;
}

.soc-finding-preview__item {
  padding: 12px;
  border-radius: 14px;
  background: rgba(4, 10, 18, 0.38);
  border: 1px solid rgba(104, 184, 229, 0.12);
}

.soc-expanded {
  padding: 8px 0 4px;
}

.soc-expanded__label {
  color: rgba(120, 220, 255, 0.9);
  font-size: 0.72rem;
  font-weight: 700;
  letter-spacing: 0.16em;
  text-transform: uppercase;
}

.soc-question-list {
  display: grid;
  gap: 12px;
}

.soc-question-list__item {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  line-height: 1.55;
  padding: 10px 12px;
  border-radius: 14px;
  background: rgba(4, 10, 18, 0.38);
  border: 1px solid rgba(104, 184, 229, 0.12);
}

.soc-link {
  color: rgba(103, 205, 248, 0.96);
  text-decoration: none;
}

.soc-link:hover {
  text-decoration: underline;
}

.chart-card {
  border-radius: 16px;
}

.chart-stack {
  display: grid;
  gap: 10px;
}

.chart-row {
  display: grid;
  grid-template-columns: minmax(84px, 1.1fr) minmax(0, 2.8fr) auto;
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
  height: 10px;
  border-radius: 999px;
  overflow: hidden;
  background: rgba(124, 145, 165, 0.18);
}

.chart-row__fill {
  height: 100%;
  border-radius: 999px;
}

.chart-row__value {
  min-width: 44px;
  text-align: right;
  font-family: var(--font-mono);
  font-size: 0.84rem;
  color: rgba(205, 221, 236, 0.86);
}

.chart-empty {
  min-height: 92px;
  display: grid;
  place-items: center;
  text-align: center;
}

.metric-card {
  border-radius: 16px;
}

.metric-icon {
  opacity: 0.92;
}

@media (max-width: 960px) {
  .chart-row {
    grid-template-columns: minmax(72px, 1fr) minmax(0, 2fr) auto;
  }
}
</style>
