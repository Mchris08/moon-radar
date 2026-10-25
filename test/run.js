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
  execSync(`openssl req -x509 -newkey rsa:2048 -nodes -keyout ${tmp}/k.pem -out ${tmp}/c.pem -days 30 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,DNS:test.example.com" 2>/dev/null`);
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

  console.log('new tools');
  const tools = require('../lib/tools');
  const convert = require('../lib/convert');
  const LINK = 'vless://11111111-2222-3333-4444-555555555555@vpn.example.com:443?encryption=none&security=tls&sni=a.com&fp=chrome&type=ws&host=a.com&path=%2Fws#My%20Node';
  await t('converter: link round-trips unchanged', () => { assert.strictEqual(convert.convert(LINK, {}).link, LINK); });
  await t('converter: bug host swaps SNI and Host and builds every format', () => {
    const r = convert.convert(LINK, { bug: 'bug.econet.co.zw' });
    assert.ok(r.link.includes('sni=bug.econet.co.zw') && r.link.includes('host=bug.econet.co.zw'));
    const x = JSON.parse(r.xray).outbounds[0];
    assert.strictEqual(x.streamSettings.tlsSettings.serverName, 'bug.econet.co.zw');
    assert.strictEqual(x.streamSettings.wsSettings.headers.Host, 'bug.econet.co.zw');
    const sb = JSON.parse(r.singbox).outbounds[0];
    assert.strictEqual(sb.tls.server_name, 'bug.econet.co.zw'); assert.strictEqual(sb.transport.type, 'ws');
    assert.ok(r.clash.includes('servername: "bug.econet.co.zw"') && r.clash.includes('type: vless'));
  });
  await t('converter: vmess and trojan parse and convert', () => {
    const vm = 'vmess://' + Buffer.from(JSON.stringify({ v: '2', ps: 'vm', add: '1.2.3.4', port: '443', id: '11111111-2222-3333-4444-555555555555', aid: '0', net: 'ws', host: 'h.com', path: '/', tls: 'tls', sni: 'h.com' })).toString('base64');
    const a = convert.convert(vm, { bug: 'new.example.com' });
    assert.strictEqual(JSON.parse(Buffer.from(a.link.slice(8), 'base64').toString()).sni, 'new.example.com');
    const b = convert.convert('trojan://pw@s.example.com:443?security=tls&sni=x.com&type=grpc&serviceName=svc#T', {});
    assert.strictEqual(JSON.parse(b.xray).outbounds[0].streamSettings.grpcSettings.serviceName, 'svc');
    assert.ok(b.clash.includes('password: "pw"'));
  });
  await t('converter: rejects bad input and warns about missing TLS', () => {
    assert.throws(() => convert.convert('http://x', {}), /vless/);
    assert.throws(() => convert.convert('vmess://@@@', {}), /base64/);
    assert.ok(convert.convert('vless://11111111-2222-3333-4444-555555555555@s.com:80?type=ws&security=none', {}).warnings.length >= 1);
  });
  await t('port parsing and limits', () => {
    assert.deepStrictEqual(tools.parsePorts('22,80,8000-8002'), [22, 80, 8000, 8001, 8002]);
    assert.throws(() => tools.parsePorts('0')); assert.throws(() => tools.parsePorts('1-100')); assert.throws(() => tools.parsePorts('abc'));
  });
  await t('port checker reports open, closed and blocks private hosts', async () => {
    const dead = await new Promise(r => { const s = require('net').createServer().listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => r(p)); }); });
    const r = await tools.portCheck('127.0.0.1', `${ports.tls},${ports.http},${dead}`, { allowPrivate: true });
    const by = Object.fromEntries(r.results.map(x => [x.port, x.status]));
    assert.strictEqual(by[ports.tls], 'open'); assert.strictEqual(by[ports.http], 'open'); assert.strictEqual(by[dead], 'closed');
    await assert.rejects(() => tools.portCheck('127.0.0.1', '80'), /private/);
  });
  await t('SNI probe reads the default certificate and tests names', async () => {
    const r = await tools.sniProbe('127.0.0.1', ['test.example.com', 'other.example.com'], ports.tls, { allowPrivate: true });
    assert.ok(r.defaultCert && r.defaultCert.names.includes('test.example.com'));
    const loc = r.results.find(x => x.sni === 'test.example.com'); assert.ok(loc.ok && loc.nameMatch && loc.sameCert);
    const oth = r.results.find(x => x.sni === 'other.example.com'); assert.ok(oth.ok && !oth.nameMatch);
    const auto = await tools.sniProbe('127.0.0.1', [], ports.tls, { allowPrivate: true });
    assert.ok(auto.usedCertNames && auto.results.length >= 1);
    await assert.rejects(() => tools.sniProbe('127.0.0.1', [], 443), /private/);
  });
  await t('DNS lookup: system resolver, IPs, validation', async () => {
    const r = await tools.dnsLookup('127.0.0.1', {}); assert.ok('PTR' in r.records || 'PTR' in r.errors);
    await assert.rejects(() => tools.dnsLookup('not a domain!', {}), /valid domain/);
    const q = await tools.dnsLookup('example.com', { types: ['A'], resolver: 'cloudflare' });
    assert.ok(Array.isArray(q.records.A) || q.errors.A, 'expected either records or a clear error');
  });

  await t('sniffer: pulls SNI, Host and servers from links, JSON, YAML, ovpn, payloads and subscriptions', () => {
    const sniffer = require('../lib/sniff');
    const names = r => Object.fromEntries(r.hosts.map(h => [h.host, h.roles]));
    let r = sniffer.sniff('vless://11111111-2222-3333-4444-555555555555@vpn.example.com:443?security=tls&sni=bug.econet.co.zw&type=ws&host=cdn.bug.co.zw#a');
    assert.deepStrictEqual(r.bugHosts.sort(), ['bug.econet.co.zw', 'cdn.bug.co.zw']); assert.deepStrictEqual(names(r)['vpn.example.com'], ['Server']);
    r = sniffer.sniff(JSON.stringify({ outbounds: [{ settings: { vnext: [{ address: 'srv.example.com' }] }, streamSettings: { tlsSettings: { serverName: 'm.econet.co.zw' }, wsSettings: { headers: { Host: 'cdn.econet.co.zw' } } } }] }));
    assert.deepStrictEqual(r.bugHosts.sort(), ['cdn.econet.co.zw', 'm.econet.co.zw']); assert.ok(r.formats.includes('JSON config'));
    r = sniffer.sniff('client\nremote vpn.example.com 443\nhttp-proxy-option CUSTOM-HEADER Host bug.telecel.co.zw\n# see config.json');
    assert.deepStrictEqual(r.bugHosts, ['bug.telecel.co.zw']); assert.ok(!names(r)['config.json']);
    r = sniffer.sniff('GET / HTTP/1.1[crlf]Host: bug.econet.co.zw[crlf]Upgrade: websocket[crlf][crlf]');
    assert.deepStrictEqual(r.bugHosts, ['bug.econet.co.zw']); assert.ok(!r.hosts.some(h => /host/.test(h.host)), 'placeholders must not become hosts');
    r = sniffer.sniff('CONNECT [host_port]@front.netone.co.zw [protocol][crlf]X-Online-Host: bug2.netone.co.zw[crlf][crlf]GET http://decoy.zol.co.zw/ HTTP/1.1[crlf]Referer: http://ref.zol.co.zw/');
    assert.deepStrictEqual(r.bugHosts.sort(), ['bug2.netone.co.zw', 'decoy.zol.co.zw', 'front.netone.co.zw', 'ref.zol.co.zw']);
    r = sniffer.sniff('proxies:\n  - server: "v.example.com"\n    servername: "sni.econet.co.zw"\n    ws-opts:\n      headers:\n        Host: "h.econet.co.zw"');
    assert.deepStrictEqual(r.bugHosts.sort(), ['h.econet.co.zw', 'sni.econet.co.zw']);
    r = sniffer.sniff('[Interface]\nAddress = 10.8.0.2/24\n[Peer]\nEndpoint = wg.example.com:51820');
    assert.deepStrictEqual(r.bugHosts, []); assert.ok(r.notes.some(n => /only has server/.test(n))); assert.ok(!r.ips.some(i => i.ip === '10.8.0.2'));
    const sub = Buffer.from('vless://11111111-2222-3333-4444-555555555555@vpn.example.com:443?security=tls&sni=bug.sub.co.zw&type=ws#a').toString('base64');
    r = sniffer.sniff(sub); assert.deepStrictEqual(r.bugHosts, ['bug.sub.co.zw']); assert.ok(r.notes[0].includes('base64'));
  });
  await t('sniffer: refuses locked binary files and bad input', () => {
    const sniffer = require('../lib/sniff');
    const r = sniffer.sniff(String.fromCharCode(0, 1, 2, 3, 4, 5, 6, 7).repeat(200));
    assert.strictEqual(r.binary, true); assert.ok(/encrypted|locked/i.test(r.notes[0]));
    assert.throws(() => sniffer.sniff('   '), /Paste/); assert.throws(() => sniffer.sniff('a'.repeat(600000)), /too big/);
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
  await t('tool endpoints validate input and are rate limited', async () => {
    assert.strictEqual((await call('/tools/convert', { method: 'POST', body: { link: 'nope' } })).status, 400);
    const ok = await call('/tools/convert', { method: 'POST', body: { link: LINK, bug: 'b.example.com' } });
    assert.strictEqual(ok.status, 200); assert.ok(ok.data.link.includes('b.example.com') && ok.data.xray && ok.data.singbox && ok.data.clash);
    assert.strictEqual((await call('/tools/sniff', { method: 'POST', body: { text: '' } })).status, 400);
    const sn = await call('/tools/sniff', { method: 'POST', body: { text: LINK } });
    assert.strictEqual(sn.status, 200); assert.ok(sn.data.bugHosts.includes('a.com'));
    assert.strictEqual((await call('/tools/dns', { method: 'POST', body: { name: '###' } })).status, 400);
    assert.strictEqual((await call('/tools/ports', { method: 'POST', body: { host: '127.0.0.1', ports: '80' } })).status, 400);
    assert.strictEqual((await call('/tools/sni', { method: 'POST', body: { target: '127.0.0.1' } })).status, 400);
    assert.strictEqual((await call('/tools/bulk', { method: 'POST', body: { hosts: '### !!!' } })).status, 400);
    const b = await call('/tools/bulk', { method: 'POST', body: { hosts: 'gone.nonexistent-radar-test.co.ke 127.0.0.1 a.invalid' } });
    assert.strictEqual(b.status, 200); assert.ok(b.data.results.length >= 1 && b.data.results.every(r => r.working === false));
    let last; for (let i = 0; i < 8; i++) last = await call('/tools/ports', { method: 'POST', body: { host: 'example.com', ports: '80' } });
    assert.strictEqual(last.status, 429);
  });
  await t('bulk tester caps public requests at 10 hosts', async () => {
    const many = Array.from({ length: 25 }, (_, i) => `h${i}.nonexistent-radar-test.co.ke`).join(' ');
    await new Promise(r => setTimeout(r, 100));
    const r = await call('/tools/bulk', { method: 'POST', body: { hosts: many } });
    assert.ok(r.status === 200 ? r.data.results.length <= 10 : r.status === 429);
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
  await t('backup excludes secrets and restore brings hosts and approvals back', async () => {
    assert.strictEqual((await call('/admin/backup')).status, 401);
    const b = await call('/admin/backup', { token });
    assert.strictEqual(b.status, 200);
    const raw = JSON.stringify(b.data);
    assert.ok(!raw.includes('adminHash') && !raw.includes('adminPath') && !raw.includes('secret-test-path'));
    assert.strictEqual(b.data.format, 'moon-radar-backup');
    const hostsBefore = Object.keys(db.hosts).length;
    const approvedBefore = db.hosts['x.netone.co.zw'].review;
    const hashBefore = db.settings.adminHash;
    for (const k of Object.keys(db.hosts)) delete db.hosts[k];                 // simulate a wipe
    assert.strictEqual((await call('/hosts')).data.total, 0);
    const r = await call('/admin/restore', { method: 'POST', token, body: b.data });
    assert.strictEqual(r.status, 200); assert.strictEqual(r.data.hosts, hostsBefore);
    assert.strictEqual(db.hosts['x.netone.co.zw'].review, approvedBefore);
    assert.strictEqual(db.settings.adminHash, hashBefore, 'restore must not touch the admin password');
    assert.ok((await call('/hosts')).data.total >= 1);
  });
  await t('restore rejects garbage and needs login', async () => {
    assert.strictEqual((await call('/admin/restore', { method: 'POST', body: {} })).status, 401);
    assert.strictEqual((await call('/admin/restore', { method: 'POST', token, body: { hello: 1 } })).status, 400);
    db.settings.carrier = ''; db.settings.zeroBalanceMode = false;
    const evil = { format: 'moon-radar-backup', hosts: { 'good.example.co.zw': { country: 'ZW', review: 'approved', working: true, score: 9999, history: 'x' }, '<script>': { country: 'ZW' } }, settings: { adminHash: 'hacked', retestHour: 99, carrier: 'Econet', zeroBalanceMode: true } };
    const hashBefore = db.settings.adminHash;
    const r = await call('/admin/restore', { method: 'POST', token, body: evil });
    assert.strictEqual(r.status, 200); assert.strictEqual(r.data.hosts, 1);
    assert.strictEqual(db.hosts['good.example.co.zw'].score, 100);
    assert.strictEqual(db.settings.carrier, '', 'restore must not copy the carrier label'); assert.strictEqual(db.settings.zeroBalanceMode, false, 'restore must not copy zero-balance mode');
    assert.strictEqual(db.settings.adminHash, hashBefore); assert.strictEqual(db.settings.retestHour, 23);
  });
  await t('whoami returns only the caller\'s own address', async () => { const r = await call('/whoami'); assert.strictEqual(r.status, 200); assert.ok(typeof r.data.ip === 'string' && r.data.ip.length > 0); });
  await t('admin can mark hosts as tested on a carrier from a phone test', async () => {
    assert.strictEqual((await call('/admin/verify', { method: 'POST', body: { carrier: 'Econet' } })).status, 401);
    assert.strictEqual((await call('/admin/verify', { method: 'POST', token, body: { working: ['good.example.co.zw'] } })).status, 400);
    const r = await call('/admin/verify', { method: 'POST', token, body: { carrier: 'Econet', working: ['good.example.co.zw', 'unknown.example.com'], failed: [] } });
    assert.strictEqual(r.status, 200); assert.strictEqual(r.data.marked, 1);
    assert.strictEqual(db.hosts['good.example.co.zw'].verified.Econet.ok, true);
    await call('/admin/verify', { method: 'POST', token, body: { carrier: 'Econet', failed: ['good.example.co.zw'] } });
    assert.strictEqual(db.hosts['good.example.co.zw'].verified.Econet.ok, false);
  });
  await t('cloud configs: create, serve with expiry header, hide behind login', async () => {
    const L1 = 'vless://11111111-2222-3333-4444-555555555555@vpn.example.com:443?encryption=none&security=tls&sni=bug.econet.co.zw&type=ws&host=bug.econet.co.zw&path=%2Fws#Econet';
    const L2 = 'trojan://pw@s.example.com:443?security=tls&sni=x.netone.co.zw&type=ws#Econet';
    assert.strictEqual((await call('/admin/clouds')).status, 401);
    assert.strictEqual((await call('/admin/clouds', { method: 'POST', body: { links: L1, duration: { value: 1, unit: 'days' } } })).status, 401);
    assert.strictEqual((await call('/admin/clouds', { method: 'POST', token, body: { links: '', duration: { value: 1, unit: 'days' } } })).status, 400);
    assert.strictEqual((await call('/admin/clouds', { method: 'POST', token, body: { links: L1, duration: { value: 1, unit: 'minutes' } } })).status, 400);
    const made = await call('/admin/clouds', { method: 'POST', token, body: { name: 'Friends', links: L1 + '\n' + L2, duration: { value: 2, unit: 'days' } } });
    assert.strictEqual(made.status, 200); assert.strictEqual(made.data.status, 'active');
    assert.ok(Math.abs((made.data.expiresAt - made.data.createdAt) - 2 * 86400000) < 1000);
    const tk = made.data.token;
    const r = await fetch(base + '/c/' + tk);
    assert.strictEqual(r.status, 200); assert.ok(r.headers.get('content-type').startsWith('text/plain'));
    assert.strictEqual(r.headers.get('cache-control'), 'no-store');
    assert.strictEqual(r.headers.get('subscription-userinfo'), `upload=0; download=0; total=0; expire=${Math.floor(made.data.expiresAt / 1000)}`);
    assert.deepStrictEqual(Buffer.from(await r.text(), 'base64').toString().split('\n'), [L1, L2]);
    assert.ok((await (await fetch(base + '/c/' + tk + '?f=clash')).text()).split('proxies:').length === 2);
    assert.strictEqual(JSON.parse(await (await fetch(base + '/c/' + tk + '?f=singbox')).text()).outbounds.length, 2);
    assert.strictEqual((await fetch(base + '/c/' + tk + '?f=nope')).status, 400);
    const list = await call('/admin/clouds', { token });
    assert.ok(list.data.find(x => x.token === tk).opens >= 3);
    assert.ok(!JSON.stringify(list.data).includes('vpn.example.com'), 'the admin list must not leak the config');
  });
  await t('cloud configs: expired, revoked and used-up links stop working', async () => {
    const L = 'vless://11111111-2222-3333-4444-555555555555@v.example.com:443?security=tls&sni=a.co.zw&type=ws#a';
    const mk = async extra => (await call('/admin/clouds', { method: 'POST', token, body: Object.assign({ links: L, duration: { value: 1, unit: 'hours' } }, extra) })).data.token;
    const a = await mk({});
    db.clouds[a].expiresAt = Date.now() - 1000;
    let r = await fetch(base + '/c/' + a); assert.strictEqual(r.status, 410); assert.ok((await r.text()).includes('expired'));
    const b = await mk({});
    assert.strictEqual((await call('/admin/clouds/' + b, { method: 'POST', token, body: { action: 'revoke' } })).data.status, 'revoked');
    assert.strictEqual((await fetch(base + '/c/' + b)).status, 410);
    await call('/admin/clouds/' + b, { method: 'POST', token, body: { action: 'restore' } });
    assert.strictEqual((await fetch(base + '/c/' + b)).status, 200);
    const c = await mk({ maxOpens: 2 });
    assert.strictEqual((await fetch(base + '/c/' + c)).status, 200); assert.strictEqual((await fetch(base + '/c/' + c)).status, 200);
    r = await fetch(base + '/c/' + c); assert.strictEqual(r.status, 410); assert.ok((await r.text()).includes('limit'));
    const ex = await call('/admin/clouds/' + a, { method: 'POST', token, body: { action: 'extend', minutes: 120 } });
    assert.strictEqual(ex.data.status, 'active'); assert.strictEqual((await fetch(base + '/c/' + a)).status, 200);
    assert.strictEqual((await call('/admin/clouds/' + a, { method: 'POST', token, body: { action: 'extend', minutes: 1 } })).status, 400);
    assert.strictEqual((await call('/admin/clouds/' + a, { method: 'DELETE', token })).status, 200);
    assert.strictEqual((await fetch(base + '/c/' + a)).status, 404);
    assert.strictEqual((await fetch(base + '/c/not-a-real-token-123456')).status, 404);
  });
  await t('cloud configs: timer can start on first use; browser preview does not start or use it', async () => {
    const created = await call('/admin/clouds', { method: 'POST', token, body: { ssh: { host: '1.2.3.4', port: 443, user: 'moon', password: 'pw1', sni: 'bug.econet.co.zw' }, duration: { value: 6, unit: 'hours' }, startOnFirstUse: true, maxOpens: 5 } });
    assert.strictEqual(created.data.status, 'waiting'); assert.strictEqual(created.data.expiresAt, null);
    const tk = created.data.token;
    const page = await fetch(base + '/c/' + tk, { headers: { Accept: 'text/html' } });
    assert.ok(page.headers.get('content-type').startsWith('text/html')); assert.ok((await page.text()).includes('SSH settings'));
    assert.strictEqual(db.clouds[tk].opens, 0); assert.strictEqual(db.clouds[tk].expiresAt, null);
    const txt = await (await fetch(base + '/c/' + tk)).text();
    assert.ok(txt.includes('Server: 1.2.3.4') && txt.includes('Username: moon') && txt.includes('SNI: bug.econet.co.zw'));
    assert.strictEqual(db.clouds[tk].opens, 1); assert.ok(Math.abs(db.clouds[tk].expiresAt - Date.now() - 6 * 3600000) < 5000);
    assert.strictEqual(JSON.parse(await (await fetch(base + '/c/' + tk + '?f=json')).text()).username, 'moon');
  });
  await t('cloud configs: the browser page escapes hostile names', async () => {
    const L = 'vless://11111111-2222-3333-4444-555555555555@v.example.com:443?security=tls&sni=a.co.zw&type=ws#a';
    const tk = (await call('/admin/clouds', { method: 'POST', token, body: { name: '<script>alert(1)</script>', links: L, duration: { value: 1, unit: 'days' } } })).data.token;
    const html = await (await fetch(base + '/c/' + tk, { headers: { Accept: 'text/html' } })).text();
    assert.ok(!html.includes('<script>alert(1)</script>') && html.includes('&lt;script&gt;'));
  });
  await t('cloud configs are left out of backups', async () => {
    const b = await call('/admin/backup', { token });
    assert.ok(!('clouds' in b.data) && !JSON.stringify(b.data).includes('vpn.example.com'));
  });
  await t('static files are served and traversal is blocked', async () => {
    const r = await fetch(base + '/'); assert.strictEqual(r.status, 200); assert.ok((await r.text()).includes('Radar'));
    const bad = await fetch(base + '/..%2f..%2fserver.js'); assert.strictEqual(bad.status, 403);
    assert.ok(!(await bad.text()).includes('createServer'));
  });
  await t('database persists to disk', () => {
    store.flush();
    const disk = JSON.parse(fs.readFileSync(path.join(process.env.DATA_DIR, 'db.json'), 'utf8'));
    assert.ok(disk.hosts['good.example.co.zw']); assert.ok(disk.settings.adminHash && !disk.settings.adminHash.includes('test-password'));
  });

  server.close(); tlsSrv.close(); httpSrv.close();
  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed ? 1 : 0);
})();
