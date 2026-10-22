'use strict';
// Runs public/app.js against a minimal DOM stub and the real server, to catch runtime errors in every view.
const fs = require('fs'), os = require('os'), path = require('path');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'radar-ui-'));
process.env.DATA_DIR = tmp; process.env.ADMIN_PASSWORD = 'ui-test-pass'; process.env.RADAR_QUIET = '1'; process.env.ADMIN_PATH = 'ui-secret';

class El {
  constructor(tag) { this.tag = tag; this.children = []; this.attrs = {}; this.listeners = {}; this.nodeType = 1; this.className = ''; this.value = ''; this.style = {}; this.textContent_ = ''; }
  append(...k) { k.forEach(c => this.children.push(c && c.nodeType ? c : { nodeType: 3, data: String(c) })); }  // like the real DOM: non-nodes become text
  removeChild(c) { this.children = this.children.filter(x => x !== c); }
  get firstChild() { return this.children[0] || null; }
  setAttribute(k, v) { this.attrs[k] = v; } removeAttribute(k) { delete this.attrs[k]; }
  addEventListener(e, f) { (this.listeners[e] = this.listeners[e] || []).push(f); }
  querySelector(sel) { return findAll(this, sel)[0] || null; }
  querySelectorAll(sel) { return findAll(this, sel); }
  remove() {} close() {} showModal() {} select() {}
  get classList() { return { contains: c => this.className.split(' ').includes(c) }; }
  text() { return this.children.map(c => c.nodeType === 3 ? c.data : c.text()).join(' '); }
}
function findAll(root, sel) {
  const out = [];
  const cls = sel.startsWith('.') ? sel.slice(1).split(/[ .]/)[0] : null;
  (function walk(n) { for (const c of n.children || []) { if (c.nodeType === 1) { if (cls && c.className.split(' ').includes(cls)) out.push(c); walk(c); } } })(root);
  return out;
}
const byId = {};
['app', 'status', 'sheet', 'sheetBody'].forEach(i => { byId[i] = new El('div'); });
const navs = ['hosts', 'tools', 'admin'].map(n => { const e = new El('a'); e.attrs['data-nav'] = n; return e; });
global.document = {
  querySelector: s => s.startsWith('#') ? (byId[s.slice(1)] || (byId[s.slice(1)] = new El('x'))) : (s.includes('data-nav=') ? navs.find(n => n.attrs['data-nav'] === s.split('data-nav=')[1].replace(']', '')) : new El('x')),
  querySelectorAll: () => navs,
  createElement: t => new El(t), createTextNode: d => ({ nodeType: 3, data: String(d) }),
  body: new El('body'), execCommand() {}
};
const store = {}; global.localStorage = { getItem: k => store[k] || null, setItem: (k, v) => { store[k] = v; }, removeItem: k => { delete store[k]; } };
global.location = { hash: '#/', pathname: '/ui-secret' };
global.window = { addEventListener() {} };
Object.defineProperty(global, 'navigator', { value: { clipboard: { writeText: async () => {} } }, configurable: true });

(async () => {
  const { server } = require('../server');
  const store_ = require('../lib/store'), jobs = require('../lib/jobs'), probe = require('../lib/probe');
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + server.address().port;
  const realFetch = global.fetch;
  global.fetch = (u, o) => realFetch(base + u, o);

  const fake = { testedAt: Date.now(), working: true, error: null, info: { ip: '41.1.2.3', ips: ['41.1.2.3'], dnsMs: 12, cdn: 'Cloudflare', tls: { ok: true, ms: 120, version: 'TLSv1.3', cipher: 'TLS_AES_128_GCM_SHA256', alpn: 'h2', cert: { issuer: 'DigiCert', daysLeft: 80, nameMatch: true } }, http: { status: 200, server: 'cloudflare', ms: 90 }, port80: { ok: true, status: 301 }, ws: { tls: true, http: false } } };
  jobs.addHosts(['m.econet.co.zw', 'cdn.safaricom.co.ke'], { country: 'ZW', carriers: ['Econet'], source: 'test' });
  const db = store_.get();
  db.hosts['cdn.safaricom.co.ke'].country = 'KE'; db.hosts['cdn.safaricom.co.ke'].review = 'auto';
  for (const h of Object.values(db.hosts)) jobs.applyResult(h, fake);
  db.hosts['m.econet.co.zw'].review = 'approved';
  jobs.addHosts(['pending.econet.co.zw'], { country: 'ZW' }); jobs.applyResult(db.hosts['pending.econet.co.zw'], fake);

  let errors = 0;
  process.on('unhandledRejection', e => { errors++; console.log('UNHANDLED', e.stack || e); });
  const wait = ms => new Promise(r => setTimeout(r, ms));
  global.setInterval = () => 0; global.clearInterval = () => {};
  const src = fs.readFileSync(path.join(__dirname, '..', 'public', 'app.js'), 'utf8');
  const run = new Function('window', src + '\n;return {state, route, viewTools, viewAdmin, openHost};');
  const app = run(global.window);
  const dump = () => byId.app.text().replace(/\s+/g, ' ').trim();
  const check = (name, cond, extra = '') => { console.log((cond ? '  ok   ' : '  FAIL ') + name + (cond ? '' : '\n       ' + extra)); if (!cond) errors++; };

  await wait(400);
  let t = dump();
  check('hosts view renders published Zimbabwe host', t.includes('m.econet.co.zw') && !t.includes('pending.econet.co.zw'), t.slice(0, 300));
  check('shows carrier, latency and TLS facts', t.includes('Econet') && t.includes('120 ms') && t.includes('TLS 1.3'), t.slice(0, 400));
  check('country tabs include Kenya', t.includes('Kenya'), t.slice(0, 200));

  await app.openHost('m.econet.co.zw'); await wait(200);
  const sheet = byId.sheetBody.text().replace(/\s+/g, ' ');
  check('detail sheet has no stray "null"/"undefined" text', !/\bnull\b|undefined|\[object/.test(sheet), sheet);
  check('detail sheet lists facts and protocols', sheet.includes('DigiCert') && sheet.includes('SSL/TLS + SNI') && sheet.includes('WebSocket + TLS'), sheet.slice(0, 400));

  for (const tab of ['subdomains', 'check', 'payload']) { app.state.toolsTab = tab; app.viewTools(); await wait(50); check('tools tab renders: ' + tab, dump().length > 20 && !/\bnull\b|undefined|\[object/.test(dump()), dump()); }
  app.state.prefillHost = 'bug.econet.co.zw'; app.state.toolsTab = 'payload'; app.viewTools(); await wait(300);
  check('payload generator output appears', dump().includes('Upgrade: websocket') && dump().includes('vless://'), dump().slice(0, 300));

  location.hash = '#/admin'; await app.route(); await wait(100);
  check('admin shows login when signed out', dump().includes('Admin sign in'), dump());
  const login = await realFetch(base + '/api/admin/login', { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-admin-path': '/ui-secret' }, body: JSON.stringify({ password: 'ui-test-pass' }) });
  app.state.token = (await login.json()).token;
  for (const tab of ['review', 'hosts', 'sources', 'jobs', 'settings']) {
    app.state.adminTab = tab; app.viewAdmin(); await wait(300);
    const d = dump();
    check('no stray null/undefined in admin ' + tab, !/\bnull\b|undefined|\[object/.test(d), d.slice(0, 300));
    const want = { review: 'pending.econet.co.zw', hosts: 'cdn.safaricom.co.ke', sources: 'econet.co.zw', jobs: 'working', settings: 'Download backup' }[tab];
    check('admin tab renders: ' + tab, d.includes(want), d.slice(0, 300));
  }
  server.close();
  console.log(errors ? `\n${errors} problem(s)` : '\nUI smoke test passed');
  process.exit(errors ? 1 : 0);
})();
