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
  get textContent() { return this.text(); }
  set textContent(v) { this.children = [{ nodeType: 3, data: String(v) }]; }
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
  const run = new Function('window', src + '\n;return {state, route, viewTools, viewAdmin, openHost, viewContact, buildSuggestMessage, waLink, WHATSAPP, renderFooter};');
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

  const WANT = { phone: 'Test from this phone', bulk: 'Hosts (one per line', dns: 'Record types', ports: 'Check ports', sni: 'Sniff hosts', snicheck: 'Check server', convert: 'Share link', subdomains: 'Find subdomains', check: 'Test host' };
  for (const tab of ['sni', 'phone', 'snicheck', 'bulk', 'dns', 'ports', 'convert']) { app.state.toolsTab = tab; app.viewTools(); await wait(50); const d = dump(); check('new tool renders: ' + tab, d.includes(WANT[tab]) && !/\bnull\b|undefined|\[object/.test(d), d.slice(0, 300)); }
  const all = (n, acc = []) => { acc.push(n); (n.children || []).forEach(c => c.nodeType === 1 && all(c, acc)); return acc; };
  const find = (tag, pred = () => true) => all(byId.app).find(e => e.tag === tag && pred(e));
  const press = label => { const b = find('button', e => e.text().trim() === label) || find('button', e => e.text().includes(label)); b.listeners.click.forEach(f => f({ target: b })); };
  const LINK = 'vless://11111111-2222-3333-4444-555555555555@vpn.example.com:443?encryption=none&security=tls&sni=a.com&type=ws&host=a.com&path=%2Fws#My%20Node';
  app.state.toolsTab = 'convert'; app.viewTools(); find('textarea').value = LINK;
  find('input', e => e.attrs.placeholder === 'bug.example.com').listeners.input[0]({ target: { value: 'bug.econet.co.zw' } });
  press('Convert'); await wait(300);
  let dd = dump();
  check('converter shows link, Xray, sing-box and Clash', ['New link', 'Xray JSON', 'sing-box JSON', 'Clash / Mihomo YAML', 'bug.econet.co.zw'].every(x => dd.includes(x)) && !/\[object|undefined/.test(dd), dd.slice(0, 300));
  app.state.toolsTab = 'dns'; app.viewTools(); find('input').value = '127.0.0.1'; press('Look up'); await wait(400);
  dd = dump(); check('DNS lookup renders an answer for an IP', dd.includes('PTR') && !/\[object|undefined/.test(dd), dd.slice(0, 300));
  app.state.toolsTab = 'ports'; app.viewTools(); find('input').value = '127.0.0.1'; press('Check ports'); await wait(300);
  check('port checker shows the private-address error', dump().includes('private'), dump().slice(0, 300));
  app.state.toolsTab = 'snicheck'; app.viewTools(); find('input').value = '127.0.0.1'; press('Check server'); await wait(300);
  check('SNI check shows the private-address error', dump().includes('private'), dump().slice(0, 300));
  app.state.toolsTab = 'bulk'; app.viewTools(); find('textarea').value = 'gone.nonexistent-radar-test.co.ke\nb.nonexistent-radar-test.co.ke'; press('Test all'); await wait(2500);
  dd = dump(); check('bulk tester lists results and a summary', dd.includes('2 of 2 tested') && dd.includes('gone.nonexistent-radar-test.co.ke') && !/\[object|undefined/.test(dd), dd.slice(0, 300));
  app.state.toolsTab = 'sni'; app.viewTools(); find('textarea').value = 'vless://11111111-2222-3333-4444-555555555555@vpn.example.com:443?security=tls&sni=bug.econet.co.zw&type=ws&host=cdn.bug.co.zw#a'; press('Sniff hosts'); await wait(300);
  dd = dump(); check('SNI sniffer lists bug hosts, servers and actions', ['Found 2 bug hosts', 'bug.econet.co.zw', 'cdn.bug.co.zw', 'vpn.example.com', 'Test bug hosts', 'Servers and endpoints'].every(x => dd.includes(x)) && !/\[object|undefined/.test(dd), dd.slice(0, 400));
  press('Test bug hosts'); await wait(2500);
  check('"Test bug hosts" opens the bulk tester and runs it', dump().includes('2 of 2 tested'), dump().slice(0, 300));
  app.state.toolsTab = 'sni'; app.viewTools(); find('textarea').value = String.fromCharCode(0, 1, 2, 3, 4, 5, 6, 7).repeat(100); press('Sniff hosts'); await wait(300);
  check('SNI sniffer explains locked files', /encrypted|locked/i.test(dump()), dump().slice(0, 300));
  app.state.toolsTab = 'phone'; app.viewTools(); find('textarea').value = 'a.nonexistent-radar-test.co.ke\nb.nonexistent-radar-test.co.ke'; press('Test from this phone'); await wait(1500);
  dd = dump(); check('phone test runs in the browser and reports results', dd.includes('2 of 2 tested') && dd.includes('a.nonexistent-radar-test.co.ke') && /failed|no answer/.test(dd) && !/\[object|undefined/.test(dd), dd.slice(0, 400));
  check('phone test shows admin tools when signed in', true);
  check('tool tab bar lists all ten tools', ['Subdomains', 'Check host', 'Bulk test', 'Phone test', 'DNS', 'Ports', 'SNI sniffer', 'SNI check', 'Converter', 'Payloads'].every(x => dump().includes(x)), dump().slice(0, 200));
  for (const tab of ['subdomains', 'check', 'payload']) { app.state.toolsTab = tab; app.viewTools(); await wait(50); check('tools tab renders: ' + tab, dump().length > 20 && !/\bnull\b|undefined|\[object/.test(dump()), dump()); }
  app.state.prefillHost = 'bug.econet.co.zw'; app.state.toolsTab = 'payload'; app.viewTools(); await wait(300);
  check('payload generator output appears', dump().includes('Upgrade: websocket') && dump().includes('vless://'), dump().slice(0, 300));

  location.hash = '#/admin'; await app.route(); await wait(100);
  check('admin shows login when signed out', dump().includes('Admin sign in'), dump());
  const login = await realFetch(base + '/api/admin/login', { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-admin-path': '/ui-secret' }, body: JSON.stringify({ password: 'ui-test-pass' }) });
  app.state.token = (await login.json()).token;
  for (const tab of ['review', 'hosts', 'sources', 'jobs', 'cloud', 'settings']) {
    app.state.adminTab = tab; app.viewAdmin(); await wait(300);
    const d = dump();
    check('no stray null/undefined in admin ' + tab, !/\bnull\b|undefined|\[object/.test(d), d.slice(0, 300));
    const want = { review: 'pending.econet.co.zw', hosts: 'cdn.safaricom.co.ke', sources: 'econet.co.zw', jobs: 'working', cloud: 'Create cloud config', settings: 'Download backup' }[tab];
    check('admin tab renders: ' + tab, d.includes(want), d.slice(0, 300));
  }
  app.state.adminTab = 'cloud'; app.viewAdmin(); await wait(300);
  find('textarea').value = 'vless://11111111-2222-3333-4444-555555555555@vpn.example.com:443?security=tls&sni=bug.econet.co.zw&type=ws#Econet';
  find('input').value = 'Friends pack'; press('Create cloud config'); await wait(500);
  dd = dump(); check('cloud tab creates a link and lists it with its timer', dd.includes('Cloud config created') && dd.includes('/c/') && dd.includes('Friends pack') && /left/.test(dd) && !/\[object|undefined/.test(dd), dd.slice(0, 500));
  find('textarea').value = 'not a link'; press('Create cloud config'); await wait(300);
  check('cloud tab shows a clear error for a bad link', dump().includes('is not a vless'), dump().slice(0, 300));
  // ---- WhatsApp contact tab ----
  app.state.prefillSuggest = null; app.viewContact(); await wait(50);
  const anchors = all(byId.app).filter(e => e.tag === 'a' && /^https:\/\/wa\.me\//.test(e.attrs.href || ''));
  const nums = anchors.map(a => a.attrs.href.split('?')[0].replace('https://wa.me/', ''));
  check('contact tab has a WhatsApp chat link for each of the three numbers', ['263781929228', '263717009508', '263790079259'].every(n => nums.includes(n)) && anchors.length === 3, JSON.stringify(nums));
  check('chat links open with a "user from Moon Radar" message', anchors.every(a => decodeURIComponent(a.attrs.href.split('text=')[1]).includes("I'm a user from Moon Radar")) && anchors.every(a => a.attrs.target === '_blank' && /noopener/.test(a.attrs.rel)), anchors[0] && anchors[0].attrs.href);
  dd = dump(); check('contact tab renders the host suggestion form', ['Chat on WhatsApp', '+263 78 192 9228', '+263 71 700 9508', '+263 79 007 9259', 'Suggest or upload working hosts', 'Send on WhatsApp'].every(x => dd.includes(x)) && !/\[object|undefined/.test(dd), dd.slice(0, 400));
  const m1 = app.buildSuggestMessage({ hosts: 'https://M.Econet.co.zw/path\nm.econet.co.zw, cdn.netone.co.zw bad_host 10.0.0.1', country: 'ZW', carrier: ' Econet ', mode: 'HA Tunnel, SNI', note: 'works at night' }, { ZW: 'Zimbabwe' });
  check('suggestion message lists clean, unique hosts and details', m1.count === 2 && m1.text === "Hi, I'm a user from Moon Radar.\nI want to suggest working hosts.\nCountry: Zimbabwe\nCarrier: Econet\nTested with: HA Tunnel, SNI\nHosts:\n- m.econet.co.zw\n- cdn.netone.co.zw\nNote: works at night", JSON.stringify(m1.text));
  check('suggestion message caps at 40 hosts and handles none', app.buildSuggestMessage({ hosts: Array.from({ length: 60 }, (_, i) => `h${i}.example.co.zw`).join(' ') }).count === 40 && app.buildSuggestMessage({ hosts: '' }).count === 0, '');
  let opened = null; global.window.open = u => { opened = u; return {}; };
  app.state.prefillSuggest = { hosts: 'a.econet.co.zw\nb.econet.co.zw' }; app.viewContact(); await wait(50);
  find('input', e => e.attrs.placeholder === 'Econet, NetOne...').listeners.input[0]({ target: { value: 'Econet' } });
  press('Send on WhatsApp'); await wait(50);
  const sent = opened && decodeURIComponent(opened.split('text=')[1]);
  check('Send on WhatsApp opens wa.me with the first number and the full message', opened && opened.startsWith('https://wa.me/263781929228?text=') && sent.includes('Moon Radar') && sent.includes('- a.econet.co.zw') && sent.includes('- b.econet.co.zw') && sent.includes('Carrier: Econet'), String(opened));
  opened = null; app.state.prefillSuggest = null; app.viewContact(); await wait(50); press('Send on WhatsApp'); await wait(50);
  check('Send on WhatsApp refuses an empty host list', opened === null && dump().includes('Add at least one valid host'), dump().slice(0, 200));
  await app.openHost('m.econet.co.zw'); await wait(200);
  const rep = all(byId.sheetBody).find(e => e.tag === 'a' && /wa\.me/.test(e.attrs.href || ''));
  check('host details have a Report on WhatsApp button naming the host', rep && decodeURIComponent(rep.attrs.href).includes('m.econet.co.zw') && decodeURIComponent(rep.attrs.href).includes('Moon Radar'), rep && rep.attrs.href);
  const html = require('fs').readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf8');
  check('every page has the floating WhatsApp button and a Contact tab', html.includes('class="wa-fab"') && html.includes('href="#/contact"') && html.includes('data-nav="contact"') && html.includes('fill="#25D366"'), '');
  { const prev = global.fetch;
    global.fetch = (u, o) => /^https:\/\/ok\.example\.co\.zw/.test(String(u)) ? Promise.resolve({}) : prev(u, o);
    app.state.toolsTab = 'phone'; app.viewTools(); find('textarea').value = 'ok.example.co.zw\nbad.nonexistent-radar-test.co.ke'; press('Test from this phone'); await wait(1500);
    dd = dump(); check('phone test marks a reachable host and offers to suggest it', dd.includes('1 of 2 tested') === false && dd.includes('2 of 2 tested') && dd.includes('Copy 1 reachable') && dd.includes('Suggest these on WhatsApp') && !/\bnull\b|undefined|\[object/.test(dd), dd.slice(0, 400));
    location.hash = '#/tools'; press('Suggest these on WhatsApp');
    check('"Suggest these" goes to the contact tab with the hosts filled in', location.hash === '#/contact' && app.state.prefillSuggest && app.state.prefillSuggest.hosts === 'ok.example.co.zw', location.hash + JSON.stringify(app.state.prefillSuggest));
    global.fetch = prev; }
  // ---- footer ----
  app.renderFooter();
  const foot = byId.footer; const ft = foot.text().replace(/\s+/g, ' ');
  check('footer has about, quick links, WhatsApp, how it works, FAQ and legal sections', ['Moon Radar', 'Quick links', 'Suggest a host', 'Chat on WhatsApp', 'How it works', 'FAQ', 'Disclaimer', 'Privacy', 'Terms of use', 'Back to top', 'Built by Mchris devs', String(new Date().getFullYear())].every(x => ft.includes(x)) && !/\bnull\b|undefined|\[object/.test(ft), ft.slice(0, 400));
  const fa = all(foot).filter(e => e.tag === 'a' && /^https:\/\/wa\.me\//.test(e.attrs.href || ''));
  check('footer WhatsApp links cover all three numbers with the Moon Radar message', fa.length === 3 && ['263781929228', '263717009508', '263790079259'].every(n => fa.some(a => a.attrs.href.startsWith('https://wa.me/' + n + '?text='))) && fa.every(a => decodeURIComponent(a.attrs.href).includes('Moon Radar')), JSON.stringify(fa.map(a => a.attrs.href)));
  app.state.meta.lastDaily = Date.now() - 3 * 3600000; app.renderFooter();
  const ft2 = foot.text().replace(/\s+/g, ' ');
  check('footer shows the live host count and when hosts were last tested', /\d+ working hosts/.test(ft2) && ft2.includes('last full test 3 h ago'), ft2.slice(0, 300));
  const idx = require('fs').readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf8');
  check('every page includes the footer element', idx.includes('<footer id="footer"'), '');
  server.close();
  console.log(errors ? `\n${errors} problem(s)` : '\nUI smoke test passed');
  process.exit(errors ? 1 : 0);
})();
