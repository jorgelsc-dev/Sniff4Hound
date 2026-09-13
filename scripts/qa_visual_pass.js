#!/usr/bin/env node
// Read-only visual/console-error pass over every current top-level Dashboard
// route (see frontend/src/router/index.js), driven directly over CDP.
// Unlike scripts/qa_ui_cdp.js (written for an older honeypot-config UI with
// routes - /ports, /banners, /catalog, /explorer, /agents - that no longer
// exist in this app), this walks the routes that are actually registered
// today. Does not seed or mutate any data; only observes.
const fs = require('fs');
const path = require('path');
const http = require('http');
const WebSocket = require('ws');

const BASE_URL = process.env.QA_BASE_URL || 'http://127.0.0.1:45678';
const CODE = process.env.QA_CODE || '';
const OUT_DIR = path.resolve(process.cwd(), 'QA');
const SHOT_DIR = path.join(OUT_DIR, 'visual-pass');

const ROUTES = [
  { label: 'Dashboard', path: '/' },
  { label: 'Sniffer', path: '/sniffer' },
  { label: 'Honeypot', path: '/honeypot' },
  { label: 'SOC', path: '/soc' },
  { label: 'AI', path: '/ai' },
  { label: 'Investigate', path: '/investigate' },
  { label: 'Protocols', path: '/protocols' },
  { label: 'Domains', path: '/domains' },
  { label: 'Paths', path: '/paths' },
  { label: 'IPs', path: '/ips' },
  { label: 'Monitors', path: '/monitors' },
  { label: 'Settings', path: '/settings' },
  { label: 'Chat', path: '/chat' },
  { label: 'Radar', path: '/radar' },
];

function fetchWsUrl() {
  return new Promise((resolve, reject) => {
    http
      .get('http://127.0.0.1:9222/json/version', (res) => {
        let data = '';
        res.on('data', (c) => (data += c));
        res.on('end', () => {
          try {
            resolve(JSON.parse(data).webSocketDebuggerUrl);
          } catch (err) {
            reject(err);
          }
        });
      })
      .on('error', reject);
  });
}

class CDPClient {
  constructor(url) {
    this.url = url;
    this.ws = null;
    this.nextId = 1;
    this.pending = new Map();
    this.listeners = new Map();
  }
  connect() {
    return new Promise((resolve, reject) => {
      this.ws = new WebSocket(this.url);
      this.ws.on('open', resolve);
      this.ws.on('error', reject);
      this.ws.on('message', (data) => this._onMessage(data));
    });
  }
  _onMessage(data) {
    let msg;
    try {
      msg = JSON.parse(data.toString());
    } catch {
      return;
    }
    if (msg.id) {
      const pending = this.pending.get(msg.id);
      if (!pending) return;
      this.pending.delete(msg.id);
      if (msg.error) pending.reject(new Error(msg.error.message || 'CDP error'));
      else pending.resolve(msg.result);
      return;
    }
    if (msg.method) {
      for (const handler of this.listeners.get(msg.method) || []) {
        try {
          handler(msg.params || {}, msg.sessionId);
        } catch {
          /* ignore */
        }
      }
    }
  }
  send(method, params = {}, sessionId) {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.ws.send(JSON.stringify({ id, method, params, sessionId }), (err) => {
        if (err) {
          this.pending.delete(id);
          reject(err);
        }
      });
    });
  }
  on(method, handler) {
    if (!this.listeners.has(method)) this.listeners.set(method, []);
    this.listeners.get(method).push(handler);
  }
  close() {
    if (this.ws) this.ws.close();
  }
}

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function main() {
  fs.mkdirSync(SHOT_DIR, { recursive: true });
  const wsUrl = await fetchWsUrl();
  const client = new CDPClient(wsUrl);
  await client.connect();

  const target = await client.send('Target.createTarget', { url: 'about:blank' });
  const { sessionId } = await client.send('Target.attachToTarget', {
    targetId: target.targetId,
    flatten: true,
  });

  await client.send('Page.enable', {}, sessionId);
  await client.send('Runtime.enable', {}, sessionId);
  await client.send('Log.enable', {}, sessionId);
  await client.send('Emulation.setDeviceMetricsOverride', {
    width: 1365,
    height: 768,
    deviceScaleFactor: 1,
    mobile: false,
  }, sessionId);

  const results = [];
  let current = null;

  client.on('Runtime.consoleAPICalled', (params, sid) => {
    if (sid !== sessionId || !current) return;
    const type = String(params.type || '').toLowerCase();
    if (type !== 'error' && type !== 'warning') return;
    const text = (params.args || []).map((a) => a.value ?? a.description ?? '').join(' ').trim();
    current[type === 'error' ? 'consoleErrors' : 'consoleWarnings'].push(text);
  });
  client.on('Runtime.exceptionThrown', (params, sid) => {
    if (sid !== sessionId || !current) return;
    const detail = params.exceptionDetails || {};
    current.exceptions.push(detail.text || (detail.exception && detail.exception.description) || 'exception');
  });

  for (const route of ROUTES) {
    current = { label: route.label, path: route.path, consoleErrors: [], consoleWarnings: [], exceptions: [] };
    const url = `${BASE_URL}${route.path}${CODE ? `?code=${encodeURIComponent(CODE)}` : ''}`;
    await client.send('Page.navigate', { url }, sessionId);
    await delay(1800);

    const evalResult = await client.send(
      'Runtime.evaluate',
      {
        expression: `(() => {
          const body = document.body ? document.body.innerText : '';
          return {
            title: document.title,
            hasVueApp: !!document.querySelector('#app, .v-application'),
            bodyLength: body.length,
            looksLikeAuthGate: /security code|enter.*code/i.test(body) && body.length < 2000,
            snippet: body.slice(0, 160).replace(/\\s+/g, ' '),
          };
        })()`,
        returnByValue: true,
      },
      sessionId
    );
    const info = (evalResult.result && evalResult.result.value) || {};

    const shotPath = path.join(SHOT_DIR, `${route.path.replace(/\W+/g, '_') || 'root'}.png`);
    try {
      const shot = await client.send(
        'Page.captureScreenshot',
        { format: 'png' },
        sessionId
      );
      fs.writeFileSync(shotPath, Buffer.from(shot.data, 'base64'));
    } catch {
      /* screenshot best-effort */
    }

    results.push({ ...current, ...info, shotPath });
    current = null;
  }

  await client.send('Target.closeTarget', { targetId: target.targetId });
  client.close();

  const lines = ['# Visual pass report', ''];
  let anyIssue = false;
  for (const r of results) {
    const issues = [];
    if (r.exceptions.length) issues.push(`${r.exceptions.length} JS exception(s)`);
    if (r.consoleErrors.length) issues.push(`${r.consoleErrors.length} console error(s)`);
    if (r.looksLikeAuthGate) issues.push('looks like it stayed on the auth gate (code not accepted?)');
    if (!r.hasVueApp) issues.push('no #app/.v-application root found');
    if (issues.length) anyIssue = true;
    lines.push(`## ${r.label} (${r.path})`);
    lines.push(`- title: ${r.title}`);
    lines.push(`- status: ${issues.length ? 'ISSUES: ' + issues.join('; ') : 'OK'}`);
    lines.push(`- snippet: ${r.snippet}`);
    if (r.exceptions.length) lines.push(`- exceptions: ${JSON.stringify(r.exceptions)}`);
    if (r.consoleErrors.length) lines.push(`- console errors: ${JSON.stringify(r.consoleErrors)}`);
    lines.push('');
  }
  lines.push(`Overall: ${anyIssue ? 'ISSUES FOUND' : 'ALL CLEAN'}`);
  fs.writeFileSync(path.join(OUT_DIR, 'visual-pass-report.md'), lines.join('\n'));
  console.log(lines.join('\n'));
  process.exit(anyIssue ? 1 : 0);
}

main().catch((err) => {
  console.error('QA visual pass failed:', err);
  process.exit(2);
});
