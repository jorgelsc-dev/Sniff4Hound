#!/usr/bin/env node

// Fixture-only UI audit. Never run against an operator's live session.
const { chromium } = require('playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
const output = path.resolve(process.env.QA_STYLE_OUTPUT || 'QA/styles/states');
const port = Number(process.env.SNIFF4HOUND_DESKTOP_DEBUG_PORT);

async function main() {
  if (process.env.QA_STYLE_FIXTURE_STATES !== '1' || !Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error('Set QA_STYLE_FIXTURE_STATES=1 and SNIFF4HOUND_DESKTOP_DEBUG_PORT for a dedicated fixture session.');
  }
  const browser = await chromium.connectOverCDP('http://127.0.0.1:' + port);
  let page;
  for (let attempt = 0; attempt < 40 && !page; attempt++) {
    page = browser.contexts()[0].pages().find(page => page.url().startsWith('app://shell'));
    if (!page) await pause(250);
  }
  if (!page) { await browser.close(); throw new Error('Production frontend did not open'); }
  page.setDefaultTimeout(10000);
  const original = await page.evaluate(() => location.hash);
  await page.evaluate(() => {
    window.qaComponents = name => {
      const rows = [], seen = new Set();
      function walk(vnode) {
        if (!vnode || typeof vnode !== 'object' || seen.has(vnode)) return;
        seen.add(vnode);
        if (vnode.component) {
          const vm = vnode.component;
          if ((vm.type.name || vm.type.__name) === name) rows.push(vm);
          walk(vm.subTree);
        }
        for (const child of Array.isArray(vnode.children) ? vnode.children : []) walk(child);
        walk(vnode.ssContent); walk(vnode.ssFallback);
      }
      walk(document.querySelector('#app').__vue_app__._container._vnode);
      return rows;
    };
  });
  const reports = [];
  const errors = [];
  page.on('pageerror', err => errors.push(err.message));
  fs.mkdirSync(output, { recursive: true });
  async function route(value) {
    await page.evaluate(value => { location.hash = '#' + value; }, value);
    await pause(650);
    await page.waitForFunction(() => !document.querySelector('.view-fade-enter-active,.view-fade-leave-active,.panel-loader-shell'));
    await pause(700);
  }
  async function capture(name, selector) {
    await pause(250);
    const report = await page.locator(selector).first().evaluate(el => {
      const root = el.getBoundingClientRect();
      const outside = [...el.querySelectorAll('button,input,.v-slider,.device-cell,.cheat-row,.tournament-graph__progress')].filter(item => {
        const box = item.getBoundingClientRect();
        if (!box.width || !box.height) return false;
        const table = item.closest('.v-table__wrapper');
        if (table && (!table.closest('.entity-data-table') || innerWidth >= 600)) return false;
        return box.right > root.right + 1 || box.left < root.left - 1;
      }).map(item => ({ tag: item.tagName, class: String(item.className), text: item.textContent.slice(0,100) }));
      const clippedText = [...el.querySelectorAll('.v-alert__content,.tournament-panel__head .v-chip__content')].filter(item => item.scrollWidth > item.clientWidth + 1).map(item => ({ class: item.className, width: item.clientWidth, contentWidth: item.scrollWidth }));
      const charts = document.querySelector('.rnn-stage--tournament .rnn-charts');
      const chartBox = charts?.getBoundingClientRect();
      const graphBox = document.querySelector('.tournament-panel')?.getBoundingClientRect();
      const obscuredTournament = !!(chartBox && graphBox && chartBox.top < graphBox.bottom - 1);
      return { visible: root.width > 0 && root.height > 0, width: el.clientWidth, contentWidth: el.scrollWidth, outside, clippedText, obscuredTournament };
    });
    reports.push({ name, viewport: page.viewportSize(), ...report });
    await page.screenshot({ path: path.join(output, page.viewportSize().width + '-' + name + '.png') });
    console.log(page.viewportSize().width + ' ' + name + ': ' + (!report.visible || report.outside.length || report.clippedText.length || report.obscuredTournament ? 'ISSUES' : 'OK'));
  }
  try {
    for (const [width, height] of [[1360,860],[980,640],[390,844],[320,740],[844,390]]) {
      await page.setViewportSize({ width, height });
      await route('/ips');
      await page.locator('.entity-data-table').scrollIntoViewIfNeeded();
      await capture('ip-table', '.entity-data-table');

      for (const section of ['packetcache', 'packetjobs']) {
        await route('/settings?section=' + section);
        await page.evaluate(() => {
          const view = window.qaComponents('SettingsView')[0].proxy;
          const originalStore = view.store;
          // Fork this view's state; the actual runtime and backend stay unchanged.
          view.store = { ...originalStore, state: { ...originalStore.state, runtime: {
            ...originalStore.state.runtime,
            sniffer: { ...originalStore.state.runtime.sniffer, packet_pipeline: {
              since: '2026-10-03T15:00:00Z', cache_depth: 123456, cache_limit: 999999,
              cache_accepted: 123456789, cache_dropped: 99, cache_peak: 199999,
              processed: 123456789, persisted: 10000000, skipped: 12345, write_errors: 1,
            } },
          } } };
          window.qaRestorePipeline = () => { view.store = originalStore; };
        });
        await capture(section + '-counters', '.config-overlay__body');
        await page.evaluate(() => { window.qaRestorePipeline(); delete window.qaRestorePipeline; });
      }
      await route('/settings?section=storage');
      await page.getByRole('button', { name: 'Compactar', exact: true }).click();
      await capture('compact-confirmation', '.v-dialog .v-card');
      await page.getByRole('button', { name: 'Cancelar', exact: true }).click();
      await page.getByRole('button', { name: 'Historial de detección', exact: true }).click();
      await capture('purge-history-confirmation', '.v-dialog .v-card');
      await page.getByRole('button', { name: 'Cancelar', exact: true }).click();
      await page.locator('.config-overlay__body').getByRole('button', { name: 'Todo', exact: true }).click();
      await capture('purge-all-confirmation', '.v-dialog .v-card');
      await page.getByRole('button', { name: 'Cancelar', exact: true }).click();

      await route('/settings?section=exclusions');
      await capture('exclusions', '.config-overlay__body');
      await route('/settings?section=blacklist');
      await page.evaluate(() => {
        const components = window.qaComponents('BlacklistCategoryCard');
        components[0].proxy.draft.matchType = 'regex';
        components[0].proxy.draft.value = '^(?:[a-z0-9-]+\\.)+example\\.com$';
      });
      await capture('blacklist-regex-form', '.config-overlay__body');
      await page.getByRole('button', { name: 'Ayudante de regex', exact: true }).first().click();
      await capture('regex-dialog', '.regex-helper-card');
      await page.evaluate(() => {
        const helper = window.qaComponents('RegexHelperButton').find(vm => vm.proxy.dialogOpen);
        helper.proxy.working = '.*'; helper.proxy.sample = 'https://example.test/' + 'a'.repeat(200);
      });
      await capture('regex-long-result', '.regex-helper-card');
      await page.locator('.regex-helper-card').evaluate(el => { el.scrollTop = el.scrollHeight; });
      await capture('regex-dialog-bottom', '.regex-helper-card');
      await page.getByRole('button', { name: 'Cancelar', exact: true }).click();

      await route('/ai/overview');
      await page.getByRole('button', { name: 'Revisar / enseñar', exact: true }).first().click();
      await capture('ai-review', '.v-dialog .v-card');
      await page.getByRole('button', { name: 'Cancelar', exact: true }).click();
      await page.evaluate(() => {
        const store = document.querySelector('#app').__vue_app__._container._vnode.component.proxy.store;
        window.qaOriginalFetch = store.fetchJsonPromise;
        store.fetchJsonPromise = async (...args) => {
          const snapshot = await window.qaOriginalFetch(...args);
          if (!String(args[0]).includes('/api/ai/packets/')) return snapshot;
          // Reject the real fixture feed until this route is unmounted.
          return { ...snapshot, learning: { ...snapshot.learning, revision: 999999 }, ai_tournament: {
            active: false, round: 145, stop_reason: 'training_disabled',
            champion: { hidden_sizes: [16,32,64,32,16,8,4], accuracy: .995, evaluation_mode: 'holdout' },
            candidates: [
              { hidden_sizes: [16,32,64,32,16,8,4], status: 'champion', epoch: 1200, total_epochs: 1200, loss: .000123, accuracy: .995 },
              { hidden_sizes: [128,128,128,64,32], status: 'disqualified', epoch: 9999, total_epochs: 10000, loss: 12.3456, accuracy: .4 },
              { hidden_sizes: [8,4], status: 'done', epoch: 400, total_epochs: 400, loss: .123456, accuracy: .8 },
            ],
          }};
        };
      });
      await route('/ai/neural-network');
      await capture('tournament', '.tournament-panel');
      await page.locator('.tournament-panel').evaluate(el => { el.scrollTop = el.scrollHeight; });
      await capture('tournament-bottom', '.tournament-panel');
      await page.evaluate(() => {
        document.querySelector('#app').__vue_app__._container._vnode.component.proxy.store.fetchJsonPromise = window.qaOriginalFetch;
        delete window.qaOriginalFetch;
      });
      await route('/');
    }
    fs.writeFileSync(path.join(output, 'report.json'), JSON.stringify({ reports, errors }, null, 2));
    assert.equal(errors.length, 0, 'No runtime exceptions');
    assert(reports.every(report => report.visible && !report.outside.length && !report.clippedText.length && !report.obscuredTournament), 'All states are visible without clipped controls, text, or overlapping tournament panels');
    console.log('Checked ' + reports.length + ' fixture states. Report: ' + path.join(output, 'report.json'));
  } finally {
    await page.evaluate(() => {
      if (window.qaOriginalFetch) document.querySelector('#app').__vue_app__._container._vnode.component.proxy.store.fetchJsonPromise = window.qaOriginalFetch;
      window.qaRestorePipeline?.();
      delete window.qaRestorePipeline;
      delete window.qaOriginalFetch; delete window.qaComponents;
    });
    await route('/');
    await page.evaluate(hash => { location.hash = hash; }, original);
    const session = await page.context().newCDPSession(page);
    await session.send('Emulation.clearDeviceMetricsOverride');
    await session.detach();
    await browser.close();
  }
}
main().catch(error => { console.error(error); process.exit(1); });
