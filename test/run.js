'use strict';
// Self-contained tests: local TLS/HTTP/WebSocket target, scoring, review workflow, auth, API.
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const http2 = require('http2');
const { execSync } = require('child_process');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'radar-'));
process.env.DATA_DIR = path.join(tmp, 'data');
process.env.ADMIN_PASSWORD = 'test-password-1';
process.env.RADAR_QUIET = '1';
process.env.ADMIN_PATH = 'secret-test-path';

let passed = 0, failed = 0;
async function t(name, fn) {
  try { await fn(); passed++; console.log('  ok   ' + name); }
  catch (e) { failed++; console.log('  FAIL ' + name + '\n       ' + (e.stack || e.message).split('\n').slice(0, 3).join('\n       ')); }
}

(async () => {
  const probe = require('../lib/probe');
  const gen = require('../lib/payloads');
  const disc = require('../lib/discover');

  console.log('probe engine');
  execSync(`openssl req -x509 -newkey rsa:2048 -nodes -keyout ${tmp}/k.pem -out ${tmp}/c.pem -days 30 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" 2>/dev/null`);
  const tlsSrv = http2.createSecureServer({ key: fs.readFileSync(tmp + '/k.pem'), cert: fs.readFileSync(tmp + '/c.pem'), allowHTTP1: true }, (req, res) => { res.setHeader('server', 'cloudflare'); res.end('hi'); });
  tlsSrv.on('upgrade', (req, sock) => { sock.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n'); sock.end(); });
  await new Promise(r => tlsSrv.listen(0, '127.0.0.1', r));
  const httpSrv = http.createServer((req, res) => res.end('ok'));
  httpSrv.on('upgrade', (req, sock) => { sock.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n'); sock.end(); });
  await new Promise(r => httpSrv.listen(0, '127.0.0.1', r));
  const ports = { tls: tlsSrv.address().port, http: httpSrv.address().port };

  let res;
  await t('probes a live TLS + HTTP target', async () => {
    res = await probe.probeHost('localhost', { allowPrivate: true, ports, deep: true, timeoutMs: 3000 });
    assert.ok(res.working);
    assert.strictEqual(res.info.tls.ok, true);
    assert.ok(/TLSv1\.[23]/.test(res.info.tls.version));
    assert.strictEqual(res.info.tls.alpn, 'h2');
    assert.strictEqual(res.info.tls.cert.nameMatch, true);
    assert.ok(res.info.http.status === 200);
    assert.strictEqual(res.info.cdn, 'Cloudflare');
    assert.strictEqual(res.info.port80.ok, true);
  });
  await t('detects WebSocket upgrade on 443 and 80', () => { assert.strictEqual(res.info.ws.tls, true); assert.strictEqual(res.info.ws.http, true); });
  await t('scores strong host highly and lists protocols', () => {
    const s = probe.scoreOf(res.info, []);
    assert.ok(s >= 75, 'score ' + s);
    const ids = probe.protocolsOf(res.info).map(p => p.id);
    for (const want of ['sni-ssl', 'xray-tls', 'ws-tls', 'grpc', 'http-payload', 'ws-http']) assert.ok(ids.includes(want), 'missing ' + want);
    assert.deepStrictEqual(probe.typesOf(res.info), ['sni', 'payload', 'ws']);
  });
  await t('closed ports report not working', async () => {
    const r = await probe.probeHost('localhost', { allowPrivate: true, ports: { tls: 1, http: 2 }, timeoutMs: 1500 });
    assert.strictEqual(r.working, false);
    assert.strictEqual(probe.scoreOf(r.info, []) < 25, true);
  });
  await t('blocks private IPs unless allowed (SSRF guard)', async () => {
    const r = await probe.probeHost('localhost', { timeoutMs: 1500 });
    assert.strictEqual(r.working, false);
    assert.strictEqual(r.error, 'private-ip');
  });
  await t('stability history changes the score', () => {
    const good = Array.from({ length: 10 }, () => ({ ok: true })), bad = Array.from({ length: 10 }, (_, i) => ({ ok: i < 2 }));
    assert.ok(probe.scoreOf(res.info, good) > probe.scoreOf(res.info, bad));
  });
  await t('host name cleaning', () => {
    assert.strictEqual(probe.cleanHost('https://WWW.Example.com:8443/x?y'), 'www.example.com');
    assert.strictEqual(probe.cleanHost('*.a.co.zw'), 'a.co.zw');
    assert.strictEqual(probe.cleanHost('not a host'), null);
    assert.strictEqual(probe.cleanHost('localhost'), null);
  });
  await t('CIDR expansion and limits', () => {
    assert.strictEqual(disc.expandCidr('41.57.0.0/24').length, 256);
    assert.throws(() => disc.expandCidr('10.0.0.0/8'));
    assert.throws(() => disc.expandCidr('nonsense'));
  });
  await t('payload generator builds configs', () => {
    const g = gen.generate({ host: 'bug.econet.co.zw', server: 'vpn.example.com', port: 443, uuid: '11111111-2222-3333-4444-555555555555' });
    assert.ok(g.payloads.every(p => p.text.includes('bug.econet.co.zw') || p.text.includes('[host_port]')));
    assert.ok(g.configs.find(c => c.name.startsWith('VLESS')).text.startsWith('vless://11111111-2222-3333-4444-555555555555@vpn.example.com:443'));
    const vm = g.configs.find(c => c.name.startsWith('VMess')).text.replace('vmess://', '');
    assert.strictEqual(JSON.parse(Buffer.from(vm, 'base64').toString()).sni, 'bug.econet.co.zw');
    assert.doesNotThrow(() => JSON.parse(g.configs.find(c => c.name.startsWith('Xray')).text));
  });
  await t('payload generator rejects header injection in fields', () => {
    const g = gen.generate({ host: 'a.example.com\r\nX: y', path: '/a b\r\nEvil: 1' });
    assert.ok(!g.payloads.some(p => /Evil/.test(p.text) && /\r\n/.test(p.text)));
  });

  console.log('server, auth and review workflow');
  const { server } = require('../server');
  const store = require('../lib/store');
  const jobs = require('../lib/jobs');
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + server.address().port;
  const call = async (p, o = {}) => { const r = await fetch(base + '/api' + p, { method: o.method || 'GET', headers: Object.assign({ 'Content-Type': 'application/json', 'x-admin-path': o.gate === false ? '/wrong' : '/secret-test-path' }, o.token ? { Authorization: 'Bearer ' + o.token } : {}), body: o.body ? JSON.stringify(o.body) : undefined }); const ct = r.headers.get('content-type') || ''; return { status: r.status, data: ct.includes('json') ? await r.json() : await r.text() }; };

  let token;
  await t('admin routes require login', async () => { assert.strictEqual((await call('/admin/status')).status, 401); });
  await t('login endpoint is invisible without the secret admin address', async () => {
    assert.strictEqual((await call('/admin/login', { method: 'POST', gate: false, body: { password: 'test-password-1' } })).status, 404);
  });
  await t('only the secret path serves the admin page marker', async () => {
    const pub = await (await fetch(base + '/')).text(); assert.ok(!pub.includes('radar-admin') && !/>Admin</.test(pub));
    const adm = await (await fetch(base + '/secret-test-path')).text(); assert.ok(adm.includes('name="radar-admin"') && adm.includes('noindex'));
    const other = await (await fetch(base + '/admin')).text(); assert.ok(!other.includes('name="radar-admin"'));
  });
  await t('wrong password is rejected, right one works', async () => {
    assert.strictEqual((await call('/admin/login', { method: 'POST', body: { password: 'nope' } })).status, 401);
    const r = await call('/admin/login', { method: 'POST', body: { password: 'test-password-1' } });
    assert.strictEqual(r.status, 200); token = r.data.token; assert.ok(token.length > 20);
  });
  await t('login is rate limited', async () => {
    let last;
    for (let i = 0; i < 8; i++) last = await call('/admin/login', { method: 'POST', body: { password: 'x' } });
    assert.strictEqual(last.status, 429);
  });

  const db = store.get();
  const mk = (host, country) => { jobs.addHosts([host], { country, source: 'test' }); return db.hosts[host]; };
  const up = h => jobs.applyResult(h, Object.assign({}, res, { testedAt: Date.now() }));
  const dn = h => jobs.applyResult(h, { host: h.host, testedAt: Date.now(), working: false, info: {}, error: 'timeout' });

  await t('non-Zimbabwe hosts publish automatically when working', async () => {
    const h = mk('cdn.example.co.ke', 'KE'); assert.strictEqual(h.review, 'auto');
    assert.strictEqual((await call('/hosts?country=KE')).data.total, 0);
    up(h);
    assert.strictEqual((await call('/hosts?country=KE')).data.total, 1);
  });
  await t('Zimbabwe hosts wait for admin approval', async () => {
    const h = mk('portal.econet.co.zw', 'ZW'); assert.strictEqual(h.review, 'new');
    up(h); assert.strictEqual(h.review, 'pending');
    assert.strictEqual((await call('/hosts?country=ZW')).data.total, 0);
    assert.strictEqual((await call('/hosts/portal.econet.co.zw')).status, 404);
    const q = await call('/admin/hosts?review=pending&working=1', { token });
    assert.strictEqual(q.data.total, 1);
  });
  await t('.zw names are forced into the review queue even if tagged global', () => {
    const h = mk('x.netone.co.zw', 'GLOBAL'); assert.strictEqual(h.country, 'ZW'); assert.strictEqual(h.review, 'new');
  });
  await t('approve publishes a Zimbabwe host', async () => {
    const r = await call('/admin/review', { method: 'POST', token, body: { action: 'approve', hosts: ['portal.econet.co.zw'] } });
    assert.strictEqual(r.data.changed, 1);
    const list = await call('/hosts?country=ZW');
    assert.strictEqual(list.data.total, 1); assert.strictEqual(list.data.hosts[0].host, 'portal.econet.co.zw');
    assert.strictEqual((await call('/hosts/portal.econet.co.zw')).status, 200);
  });
  await t('approved host disappears when down and returns when back up', async () => {
    const h = db.hosts['portal.econet.co.zw'];
    dn(h); assert.strictEqual((await call('/hosts?country=ZW')).data.total, 0);
    up(h); assert.strictEqual((await call('/hosts?country=ZW')).data.total, 1);
  });
  await t('reject keeps a working Zimbabwe host hidden', async () => {
    const h = db.hosts['x.netone.co.zw']; up(h);
    await call('/admin/review', { method: 'POST', token, body: { action: 'reject', hosts: [h.host] } });
    up(h); assert.strictEqual((await call('/hosts?country=ZW')).data.total, 1);
  });
  await t('unpublish moves host back to the queue', async () => {
    await call('/admin/review', { method: 'POST', token, body: { action: 'unpublish', hosts: ['portal.econet.co.zw'] } });
    assert.strictEqual((await call('/hosts?country=ZW')).data.total, 0);
    assert.strictEqual(db.hosts['portal.econet.co.zw'].review, 'pending');
  });
  await t('carrier verification stamp is recorded', () => {
    db.settings.carrier = 'Econet';
    const h = db.hosts['cdn.example.co.ke']; up(h);
    assert.strictEqual(h.verified.Econet.ok, true);
    db.settings.carrier = '';
  });
  await t('filters, sorting and export work', async () => {
    const r = await call('/hosts?type=sni&sort=latency'); assert.ok(r.data.total >= 1);
    const txt = await call('/export?format=txt'); assert.ok(txt.data.includes('cdn.example.co.ke'));
    const csv = await call('/export?format=csv'); assert.ok(csv.data.startsWith('host,country'));
  });
  await t('admin can add sources and hosts via API', async () => {
    const r = await call('/admin/sources', { method: 'POST', token, body: { domains: 'zero.example.co.zw\nbad host', country: 'ZW' } });
    assert.strictEqual(r.data.added, 1);
    assert.strictEqual((await call('/admin/sources', { method: 'POST', token, body: { domains: 'zero.example.co.zw' } })).data.added, 0);
  });
  await t('public tools: generate and input validation', async () => {
    const g = await call('/tools/generate', { method: 'POST', body: { host: 'a.example.com', server: 'v.example.com' } });
    assert.strictEqual(g.status, 200); assert.ok(g.data.uuid);
    assert.strictEqual((await call('/tools/check', { method: 'POST', body: { host: '###' } })).status, 400);
  });
  await t('offline guard: a dead connection does not mark working hosts as down', async () => {
    const h = db.hosts['cdn.example.co.ke'];
    assert.strictEqual(h.working, true);
    h.host = 'cdn.example.co.ke';
    const ghost = mk('gone.nonexistent-radar-test.co.ke', 'KE'); up(ghost);
    db.settings.zeroBalanceMode = false;
    process.env.RADAR_FORCE_OFFLINE = '1';
    const r = await jobs.testHost(ghost);
    delete process.env.RADAR_FORCE_OFFLINE;
    assert.strictEqual(r, 'offline');
    assert.strictEqual(ghost.working, true, 'host was wrongly marked down while offline');
  });
  await t('zero-balance mode: failures are real signals and mark hosts down', async () => {
    const ghost = db.hosts['gone.nonexistent-radar-test.co.ke'];
    db.settings.zeroBalanceMode = true;
    const r = await jobs.testHost(ghost);
    db.settings.zeroBalanceMode = false;
    assert.strictEqual(r, 'down');
    assert.strictEqual(ghost.working, false);
  });
  await t('settings are validated and password change works', async () => {
    await call('/admin/settings', { method: 'POST', token, body: { retestHour: 99, concurrency: 0 } });
    assert.strictEqual(db.settings.retestHour, 23); assert.strictEqual(db.settings.concurrency, 1);
    assert.strictEqual((await call('/admin/password', { method: 'POST', token, body: { current: 'bad', next: 'longenough1' } })).status, 401);
    assert.strictEqual((await call('/admin/password', { method: 'POST', token, body: { current: 'test-password-1', next: 'short' } })).status, 400);
  });
  await t('static files are served and traversal is blocked', async () => {
    const r = await fetch(base + '/'); assert.strictEqual(r.status, 200); assert.ok((await r.text()).includes('Radar'));
    const bad = await fetch(base + '/..%2f..%2fserver.js'); assert.strictEqual(bad.status, 403);
    assert.ok(!(await bad.text()).includes('createServer'));
  });
  await t('database persists to disk', () => {
    store.flush();
    const disk = JSON.parse(fs.readFileSync(path.join(process.env.DATA_DIR, 'db.json'), 'utf8'));
    assert.ok(disk.hosts['cdn.example.co.ke']); assert.ok(disk.settings.adminHash && !disk.settings.adminHash.includes('test-password'));
  });

  server.close(); tlsSrv.close(); httpSrv.close();
  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed ? 1 : 0);
})();
