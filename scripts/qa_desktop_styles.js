#!/usr/bin/env node

// Run against a dedicated Electron QA session with the production bundle.
const fs = require('node:fs');
const path = require('node:path');

const port = Number(process.env.SNIFF4HOUND_DESKTOP_DEBUG_PORT);
const outputDir = path.resolve(process.env.QA_STYLE_OUTPUT || 'QA/styles');
const routes = (process.env.QA_STYLE_ROUTES || [
  '/', '/dashboard/overview', '/dashboard/node-map', '/dashboard/live-map',
  '/sniffer', '/honeypot', '/monitors', '/protocols', '/protocols/http',
  '/domains', '/paths', '/ips', '/investigate', '/soc', '/ai',
  '/ai/overview', '/ai/neural-network', '/settings', '/chat',
].join(',')).split(',');
const viewports = JSON.parse(process.env.QA_STYLE_VIEWPORTS || '[ [1360,860], [980,640], [768,1024], [390,844] ]');
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));

async function main() {
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error('Set SNIFF4HOUND_DESKTOP_DEBUG_PORT to the port of a dedicated Electron QA session.');
  }
  const targets = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
  const target = targets.find(item => item.type === 'page' && item.url.startsWith('app://shell/'));
  if (!target) throw new Error('Open the authenticated production frontend in Electron before running this audit.');
  const socket = new WebSocket(target.webSocketDebuggerUrl);
  const pending = new Map();
  const exceptions = [];
  let nextId = 0;
  let originalHash;
  await new Promise((resolve, reject) => {
    socket.addEventListener('open', resolve, { once: true });
    socket.addEventListener('error', reject, { once: true });
  });
  socket.addEventListener('message', event => {
    const message = JSON.parse(event.data);
    if (message.method === 'Runtime.exceptionThrown') {
      exceptions.push(message.params.exceptionDetails.text);
    }
    const request = pending.get(message.id);
    if (!request) return;
    pending.delete(message.id);
    clearTimeout(request.timer);
    if (message.error) request.reject(new Error(message.error.message));
    else request.resolve(message.result);
  });
  socket.addEventListener('close', () => {
    for (const request of pending.values()) {
      clearTimeout(request.timer);
      request.reject(new Error('The Electron debugging connection closed.'));
    }
    pending.clear();
  });
  function send(method, params = {}) {
    return new Promise((resolve, reject) => {
      const id = ++nextId;
      const timer = setTimeout(() => {
        pending.delete(id);
        reject(new Error(`CDP request timed out: ${method}`));
      }, method === 'Page.captureScreenshot' ? 30000 : 10000);
      pending.set(id, { resolve, reject, timer });
      socket.send(JSON.stringify({ id, method, params }));
    });
  }
  async function evaluate(expression) {
    const result = await send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
    if (result.exceptionDetails) throw new Error(result.exceptionDetails.text);
    return result.result.value;
  }
  async function screenshot(filename) {
    const result = await send('Page.captureScreenshot', { format: 'png' });
    fs.writeFileSync(path.join(outputDir, filename), Buffer.from(result.data, 'base64'));
  }
  try {
    await send('Runtime.enable');
    await send('Page.bringToFront');
    originalHash = await evaluate('location.hash');
    fs.mkdirSync(outputDir, { recursive: true });
    const reports = [];
    for (const [width, height] of viewports) {
      await send('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: 1, mobile: false });
      for (const route of routes) {
        await evaluate(`location.hash = ${JSON.stringify('#' + route)}`);
        await pause(600);
        for (let attempt = 0; attempt < 24; attempt++) {
          const busy = await evaluate(`document.querySelector('#app').__vue_app__?._container?._vnode?.component?.proxy?.store?.state?.tasks?.length || document.querySelectorAll('.panel-loader-shell,.view-fade-enter-active,.view-fade-leave-active').length`);
          if (!busy) break;
          await pause(250);
        }
        await evaluate('window.scrollTo(0, 0)');
        const report = await evaluate(`(() => {
          const rect = el => { const r = el.getBoundingClientRect(); return { top: r.top, bottom: r.bottom, width: r.width, height: r.height }; };
          const wrapper = document.querySelector('.v-application__wrap');
          const canvas = document.querySelector('.chat-view,.rnn-stage,.config-workspace,.ip-graph-card--canvas,.map-canvas');
          const headings = [...document.querySelectorAll('.text-h5')];
          const captions = [...document.querySelectorAll('.text-caption')];
          const inspector = document.querySelector('.config-overlay');
          const inspectorBody = inspector && getComputedStyle(inspector).display !== 'none' ? inspector.querySelector('.config-overlay__body') : null;
          const clippedInspectorControls = inspectorBody ? [...inspectorBody.querySelectorAll('button,input,.v-slider')].filter(el => {
            const bounds = el.getBoundingClientRect();
            const parent = inspectorBody.getBoundingClientRect();
            if (!bounds.width || !bounds.height || el.closest('.v-table__wrapper,.v-slide-group__content')) return false;
            return bounds.left < parent.left - 1 || bounds.right > parent.right + 1;
          }).length : 0;
          return {
            pageWidth: document.documentElement.scrollWidth,
            appWidth: wrapper?.clientWidth,
            headingSizes: [...new Set(headings.map(el => getComputedStyle(el).fontSize))],
            captionSizes: [...new Set(captions.map(el => getComputedStyle(el).fontSize))],
            canvas: canvas ? rect(canvas) : null,
            inspector: inspectorBody ? { width: inspectorBody.clientWidth, contentWidth: inspectorBody.scrollWidth, clippedControls: clippedInspectorControls } : null,
            loading: document.querySelectorAll('.panel-loader-shell').length,
            transitioning: document.querySelectorAll('.view-fade-enter-active,.view-fade-leave-active').length,
            currentRoute: document.querySelector('#app').__vue_app__.config.globalProperties.$router.currentRoute.value.fullPath,
            brokenImages: [...document.querySelectorAll('img')].filter(el => el.complete && !el.naturalWidth).length,
            tables: [...document.querySelectorAll('.v-table__wrapper')].map(el => ({ width: el.clientWidth, contentWidth: el.scrollWidth, overflow: getComputedStyle(el).overflowX, height: el.clientHeight })),
            entityTables: [...document.querySelectorAll('.entity-data-table')].map(el => ({
              rows: el.querySelectorAll('tbody .v-data-table__tr').length,
              mobileValues: el.querySelectorAll('.v-data-table__td-value').length,
              width: el.querySelector('.v-table__wrapper').clientWidth,
              contentWidth: el.querySelector('.v-table__wrapper').scrollWidth,
              clippedExpandButtons: [...el.querySelectorAll('.entity-data-table__expand-button')].filter(button => {
                const row = el.querySelector('.v-table__wrapper').getBoundingClientRect();
                const control = button.getBoundingClientRect();
                return control.left < row.left - 1 || control.right > row.right + 1;
              }).length,
            })),
          };
        })()`);
        const issues = [];
        if (report.currentRoute !== route || report.transitioning) issues.push('Route did not settle before inspection');
        if (report.pageWidth > width + 1) issues.push('Page overflows horizontally');
        if (report.appWidth < width - 20 || report.appWidth > width + 1) issues.push('Application does not fill the window');
        if (report.canvas && (report.canvas.bottom > height + 1 || report.canvas.height < height - 160)) issues.push('Canvas does not fit the viewport');
        if (report.inspector && report.inspector.contentWidth > report.inspector.width + 1) issues.push('Settings content overflows its inspector');
        if (report.inspector?.clippedControls) issues.push('Settings controls are clipped inside their inspector');
        if (report.headingSizes.includes('16px')) issues.push('Heading typography utility is missing');
        if (report.captionSizes.includes('16px')) issues.push('Caption typography utility is missing');
        if (report.brokenImages) issues.push('Image assets failed to load');
        if (report.tables.some(table => table.contentWidth > table.width + 1 && !['auto', 'scroll'].includes(table.overflow))) issues.push('Wide table has no horizontal scroll');
        if (width < 600 && report.entityTables.some(table => table.rows && !table.mobileValues)) issues.push('Entity table did not activate its mobile layout');
        if (width < 600 && report.entityTables.some(table => table.rows && table.contentWidth > table.width + 1)) issues.push('Mobile entity rows overflow horizontally');
        if (width < 600 && report.entityTables.some(table => table.clippedExpandButtons)) issues.push('Mobile expand buttons are clipped');
        const filename = `${width}x${height}-${route.replace(/[^a-zA-Z0-9]+/g, '_') || 'home'}`;
        await screenshot(`${filename}.png`);
        const tableVisible = await evaluate(`(() => { const el = document.querySelector('.entity-data-table,.packet-table'); if (!el || el.getBoundingClientRect().top < innerHeight / 2) return false; el.scrollIntoView({ block: 'start' }); return true; })()`);
        if (tableVisible) {
          await pause(100);
          await screenshot(`${filename}-table.png`);
        }
        reports.push({ route, width, height, ...report, issues });
        console.log(`${width}x${height} ${route}: ${issues.join('; ') || 'OK'}`);
      }
    }
    const reportPath = path.join(outputDir, 'report.json');
    fs.writeFileSync(reportPath, JSON.stringify({ reports, exceptions }, null, 2));
    console.log(`Checked ${reports.length} layouts. Report: ${reportPath}`);
    if (reports.some(report => report.issues.length) || exceptions.length) process.exitCode = 1;
  } finally {
    await send('Emulation.clearDeviceMetricsOverride').catch(() => {});
    if (originalHash !== undefined) await evaluate(`location.hash = ${JSON.stringify(originalHash)}`).catch(() => {});
    socket.close();
    setTimeout(() => process.exit(process.exitCode || 0), 100);
  }
}

main().catch(error => {
  console.error(error.message);
  process.exit(1);
});
