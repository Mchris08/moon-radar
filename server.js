'use strict';
process.env.UV_THREADPOOL_SIZE = process.env.UV_THREADPOOL_SIZE || '64'; // lets DNS lookups run in parallel

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const store = require('./lib/store');
const probe = require('./lib/probe');
const disc = require('./lib/discover');
const jobs = require('./lib/jobs');
const gen = require('./lib/payloads');
const tools = require('./lib/tools');
const convert = require('./lib/convert');
const sniffer = require('./lib/sniff');
const cloud = require('./lib/cloud');
const { COUNTRIES, CARRIERS, inferCountry } = require('./lib/seeds');

const PORT = parseInt(process.env.PORT, 10) || 8080;
const HOST = process.env.BIND || '0.0.0.0';
const TRUST_PROXY = process.env.TRUST_PROXY === '1';
const PUBLIC_DIR = path.join(__dirname, 'public');
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.json': 'application/json', '.png': 'image/png', '.ico': 'image/x-icon', '.webmanifest': 'application/manifest+json' };

const db = store.load();

// ---------- hidden admin ----------
// The admin screen only exists at /<ADMIN_PATH>. Everywhere else the site shows no trace of it.
const cleanPath = s => String(s || '').replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 64);
if (process.env.ADMIN_PATH) db.settings.adminPath = cleanPath(process.env.ADMIN_PATH);
if (!db.settings.adminPath) { db.settings.adminPath = 'm-' + crypto.randomBytes(9).toString('base64url').replace(/[^a-zA-Z0-9]/g, 'x'); store.flush(); console.log('\n  Hidden admin address: /' + db.settings.adminPath); }
const adminUrl = () => '/' + db.settings.adminPath;

// ---------- auth ----------
const sessions = new Map();
const hashPw = (pw, salt = crypto.randomBytes(16).toString('hex')) => `${salt}:${crypto.scryptSync(pw, salt, 32).toString('hex')}`;
function checkPw(pw, stored) {
  if (!stored) return false;
  const [salt, h] = stored.split(':');
  const a = Buffer.from(h, 'hex');
  const b = crypto.scryptSync(String(pw), salt, 32);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
if (!db.settings.adminHash) {
  const pw = process.env.ADMIN_PASSWORD || crypto.randomBytes(6).toString('base64url');
  db.settings.adminHash = hashPw(pw);
  store.flush();
  console.log('\n  First run. Admin password: ' + pw + '\n  (change it in Admin > Settings)\n');
}
const isAdmin = req => {
  const t = (req.headers.authorization || '').replace(/^Bearer /, '');
  const exp = sessions.get(t);
  if (!exp || exp < Date.now()) { sessions.delete(t); return false; }
  return true;
};

// ---------- rate limiting ----------
const hits = new Map();
function limited(req, key, max, windowMs) {
  const ip = (TRUST_PROXY && req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
  const k = key + ':' + ip;
  const now = Date.now();
  const arr = (hits.get(k) || []).filter(t => now - t < windowMs);
  arr.push(now);
  hits.set(k, arr);
  return arr.length > max;
}
setInterval(() => { const now = Date.now(); for (const [k, v] of hits) if (!v.some(t => now - t < 120000)) hits.delete(k); }, 120000).unref();

// ---------- helpers ----------
const clientIp = req => (TRUST_PROXY && req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim().replace(/^::ffff:/, '');
const send = (res, code, data, headers = {}) => {
  const body = typeof data === 'string' ? data : JSON.stringify(data);
  res.writeHead(code, Object.assign({ 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }, headers));
  res.end(body);
};
const readBody = (req, limit = 1e6) => new Promise((resolve, reject) => {
  let b = '';
  req.on('data', c => { b += c; if (b.length > limit) { req.destroy(); reject(new Error('Body too large')); } });
  req.on('end', () => { try { resolve(b ? JSON.parse(b) : {}); } catch (_) { reject(new Error('Invalid JSON')); } });
  req.on('error', reject);
});

const isPublished = h => h.working && (h.review === 'auto' || h.review === 'approved');
const uptime = h => { const x = h.history.slice(-14); return x.length ? Math.round(100 * x.filter(i => i.ok).length / x.length) : null; };

function summary(h) {
  const t = (h.info && h.info.tls) || {};
  return {
    host: h.host, country: h.country, carriers: h.carriers, score: h.score, band: probe.bandOf(h.score),
    types: h.types || [], protocols: (h.protocols || []).map(p => p.id), latency: t.ok ? t.ms : null,
    tls: t.version || null, cdn: h.info && h.info.cdn || null, lastTested: h.lastTested, lastOk: h.lastOk,
    uptime: uptime(h), verified: h.verified || {}, working: h.working, review: h.review, source: h.source, note: h.note
  };
}
const detail = h => Object.assign(summary(h), { info: h.info, protocolDetail: h.protocols || [], history: h.history, firstSeen: h.firstSeen, parent: h.parent });

function filterHosts(list, q) {
  const text = (q.q || '').toLowerCase();
  const min = parseInt(q.minScore, 10) || 0;
  let out = list.filter(h => (!q.country || h.country === q.country) &&
    (!q.carrier || h.carriers.includes(q.carrier) || (h.verified[q.carrier] && h.verified[q.carrier].ok)) &&
    (!q.type || (h.types || []).includes(q.type)) &&
    (!q.protocol || (h.protocols || []).some(p => p.id === q.protocol)) &&
    (!text || h.host.includes(text)) && h.score >= min);
  const sorts = {
    score: (a, b) => b.score - a.score,
    latency: (a, b) => ((a.info.tls && a.info.tls.ms) || 1e9) - ((b.info.tls && b.info.tls.ms) || 1e9),
    new: (a, b) => b.firstSeen - a.firstSeen,
    name: (a, b) => a.host.localeCompare(b.host)
  };
  out.sort(sorts[q.sort] || sorts.score);
  return out;
}

function publicMeta() {
  const pub = Object.values(db.hosts).filter(isPublished);
  const counts = {};
  pub.forEach(h => { counts[h.country] = (counts[h.country] || 0) + 1; });
  const carriers = {};
  pub.forEach(h => h.carriers.forEach(c => { carriers[c] = (carriers[c] || 0) + 1; }));
  return { total: pub.length, counts, carriers, countries: COUNTRIES, carrierMap: CARRIERS, lastDaily: db.meta.lastDaily, scannerCarrier: db.settings.carrier, busy: jobs.status().running };
}

function applySettings(s, body) {
  const clamp = (v, lo, hi, d) => { const n = parseInt(v, 10); return Number.isFinite(n) ? Math.max(lo, Math.min(hi, n)) : d; };
  s.retestHour = clamp(body.retestHour, 0, 23, s.retestHour);
  s.concurrency = clamp(body.concurrency, 1, 100, s.concurrency);
  s.timeoutMs = clamp(body.timeoutMs, 1500, 20000, s.timeoutMs);
  s.pruneDays = clamp(body.pruneDays, 3, 180, s.pruneDays);
  s.maxNewPerRun = clamp(body.maxNewPerRun, 20, 5000, s.maxNewPerRun);
  s.deepWeekday = clamp(body.deepWeekday, 0, 6, s.deepWeekday);
  if (typeof body.carrier === 'string') s.carrier = body.carrier.slice(0, 30);
  if (typeof body.autoDaily === 'boolean') s.autoDaily = body.autoDaily;
  if (typeof body.zeroBalanceMode === 'boolean') s.zeroBalanceMode = body.zeroBalanceMode;
}

// ---------- backup / restore ----------
// Backups hold hosts, approvals, sources and settings. They never contain the admin password hash or the secret admin address.
function makeBackup() {
  const settings = Object.assign({}, db.settings);
  delete settings.adminHash; delete settings.adminPath;
  return { format: 'moon-radar-backup', version: 1, createdAt: Date.now(), hosts: db.hosts, sources: db.sources, settings, runs: db.runs, meta: db.meta };
}

function restoreBackup(data) {
  if (!data || data.format !== 'moon-radar-backup' || !data.hosts || typeof data.hosts !== 'object') throw new Error('This is not a Moon Radar backup file');
  const REVIEWS = ['new', 'pending', 'approved', 'rejected', 'auto'];
  const hosts = {};
  let n = 0;
  for (const [k, h] of Object.entries(data.hosts)) {
    const name = probe.cleanHost(k);
    if (!name || !h || typeof h !== 'object') continue;
    if (++n > 50000) break;
    const rec = jobs.newHostRecord(name, { country: typeof h.country === 'string' ? h.country : 'GLOBAL', carriers: Array.isArray(h.carriers) ? h.carriers.map(String).slice(0, 8) : [], source: String(h.source || 'restore').slice(0, 80), parent: h.parent ? String(h.parent) : null });
    Object.assign(rec, {
      firstSeen: +h.firstSeen || rec.firstSeen, lastTested: +h.lastTested || 0, lastOk: +h.lastOk || 0,
      working: !!h.working, failStreak: +h.failStreak || 0,
      review: REVIEWS.includes(h.review) ? h.review : rec.review,
      score: Math.max(0, Math.min(100, +h.score || 0)),
      info: h.info && typeof h.info === 'object' ? h.info : {},
      history: Array.isArray(h.history) ? h.history.slice(-30).map(x => ({ t: +x.t || 0, ok: !!x.ok, ms: x.ms == null ? null : +x.ms })) : [],
      verified: h.verified && typeof h.verified === 'object' ? h.verified : {},
      note: String(h.note || '').slice(0, 200),
      protocols: Array.isArray(h.protocols) ? h.protocols : [],
      types: Array.isArray(h.types) ? h.types.map(String) : [],
      error: h.error ? String(h.error) : null
    });
    if (rec.country !== 'ZW' && (rec.review === 'new' || rec.review === 'pending')) rec.review = 'auto';
    hosts[name] = rec;
  }
  const sources = [];
  const seen = new Set();
  for (const s of Array.isArray(data.sources) ? data.sources : []) {
    const d = s && probe.cleanHost(s.domain);
    if (!d || seen.has(d)) continue;
    seen.add(d);
    sources.push({ domain: d, country: String(s.country || 'GLOBAL').slice(0, 10), carriers: Array.isArray(s.carriers) ? s.carriers.map(String).slice(0, 8) : [], kind: s.kind === 'seed' ? 'seed' : 'zero-rated', deep: !!s.deep, enabled: s.enabled !== false, added: +s.added || Date.now() });
  }
  db.hosts = hosts;
  if (sources.length) db.sources = sources;
  if (data.settings && typeof data.settings === 'object') {
    // The carrier label and zero-balance mode describe the device that ran the scan, so they stay local.
    const s = Object.assign({}, data.settings);
    delete s.carrier; delete s.zeroBalanceMode;
    applySettings(db.settings, s);
  }
  if (Array.isArray(data.runs)) db.runs = data.runs.slice(-60);
  if (data.meta && +data.meta.lastDaily) db.meta.lastDaily = +data.meta.lastDaily;
  store.save();
  jobs.log(`Backup restored: ${Object.keys(hosts).length} hosts, ${db.sources.length} sources`);
  return { hosts: Object.keys(hosts).length, sources: db.sources.length };
}

// ---------- routes ----------
async function route(req, res, url, body) {
  const p = url.pathname;
  const m = req.method;
  const q = Object.fromEntries(url.searchParams);

  // ---- public ----
  if (p === '/api/meta' && m === 'GET') return send(res, 200, publicMeta());
  if (p === '/api/whoami' && m === 'GET') return send(res, 200, { ip: clientIp(req) || 'unknown' });

  if (p === '/api/hosts' && m === 'GET') {
    const list = filterHosts(Object.values(db.hosts).filter(isPublished), q);
    const limit = Math.min(parseInt(q.limit, 10) || 100, 500);
    const offset = parseInt(q.offset, 10) || 0;
    return send(res, 200, { total: list.length, hosts: list.slice(offset, offset + limit).map(summary) });
  }

  let mm = /^\/api\/hosts\/([^/]+)$/.exec(p);
  if (mm && m === 'GET') {
    const h = db.hosts[decodeURIComponent(mm[1])];
    if (!h || (!isPublished(h) && !isAdmin(req))) return send(res, 404, { error: 'Host not found' });
    return send(res, 200, detail(h));
  }

  if (p === '/api/export' && m === 'GET') {
    const list = filterHosts(Object.values(db.hosts).filter(isPublished), q);
    const fmt = q.format || 'txt';
    if (fmt === 'json') return send(res, 200, list.map(summary), { 'Content-Disposition': 'attachment; filename="hosts.json"' });
    if (fmt === 'csv') {
      const rows = ['host,country,carriers,score,types,latency_ms'].concat(list.map(h => [h.host, h.country, h.carriers.join('|'), h.score, (h.types || []).join('|'), (h.info.tls && h.info.tls.ms) || ''].join(',')));
      return send(res, 200, rows.join('\n'), { 'Content-Type': 'text/csv', 'Content-Disposition': 'attachment; filename="hosts.csv"' });
    }
    return send(res, 200, list.map(h => h.host).join('\n'), { 'Content-Type': 'text/plain; charset=utf-8', 'Content-Disposition': 'attachment; filename="hosts.txt"' });
  }

  if (p === '/api/tools/generate' && m === 'POST') return send(res, 200, Object.assign(gen.generate(body), { uuid: gen.newUuid() }));

  if (p === '/api/tools/check' && m === 'POST') {
    if (!isAdmin(req) && limited(req, 'check', 30, 60000)) return send(res, 429, { error: 'Too many checks. Wait a minute.' });
    const host = probe.cleanHost(body.host);
    if (!host) return send(res, 400, { error: 'Enter a valid hostname, for example example.com' });
    const r = await probe.probeHost(host, { timeoutMs: 6000, deep: true });
    const score = r.working ? probe.scoreOf(r.info, []) : 0;
    return send(res, 200, { host, working: r.working, error: r.error, score, band: probe.bandOf(score), info: r.info, protocols: r.working ? probe.protocolsOf(r.info) : [], types: probe.typesOf(r.info), testedAt: r.testedAt });
  }

  if (p === '/api/tools/convert' && m === 'POST') {
    try { return send(res, 200, convert.convert(body.link, body)); } catch (e) { return send(res, 400, { error: e.message }); }
  }

  if (p === '/api/tools/sniff' && m === 'POST') {
    if (!isAdmin(req) && limited(req, 'sniff', 30, 60000)) return send(res, 429, { error: 'Too many requests. Wait a minute.' });
    try { return send(res, 200, sniffer.sniff(body.text)); } catch (e) { return send(res, 400, { error: e.message }); }
  }

  if (p === '/api/tools/dns' && m === 'POST') {
    if (!isAdmin(req) && limited(req, 'dns', 30, 60000)) return send(res, 429, { error: 'Too many lookups. Wait a minute.' });
    try { return send(res, 200, await tools.dnsLookup(String(body.name || '').trim(), { types: Array.isArray(body.types) && body.types.length ? body.types : undefined, resolver: body.resolver })); } catch (e) { return send(res, 400, { error: e.message }); }
  }

  if (p === '/api/tools/ports' && m === 'POST') {
    if (!isAdmin(req) && limited(req, 'ports', 6, 60000)) return send(res, 429, { error: 'Too many port checks. Wait a minute.' });
    try { return send(res, 200, await tools.portCheck(String(body.host || '').trim(), body.ports)); } catch (e) { return send(res, 400, { error: e.message }); }
  }

  if (p === '/api/tools/sni' && m === 'POST') {
    if (!isAdmin(req) && limited(req, 'sni', 10, 60000)) return send(res, 429, { error: 'Too many SNI checks. Wait a minute.' });
    const snis = String(body.snis || '').split(/[\s,;]+/).filter(Boolean);
    try { return send(res, 200, await tools.sniProbe(String(body.target || '').trim(), snis, body.port)); } catch (e) { return send(res, 400, { error: e.message }); }
  }

  if (p === '/api/tools/bulk' && m === 'POST') {
    const admin = isAdmin(req);
    if (!admin && limited(req, 'bulk', 12, 60000)) return send(res, 429, { error: 'Too many requests. Wait a few seconds.' });
    const raw = Array.isArray(body.hosts) ? body.hosts : String(body.hosts || '').split(/[\s,;]+/);
    const names = [...new Set(raw.map(probe.cleanHost).filter(Boolean))].slice(0, admin ? 30 : 10);
    if (!names.length) return send(res, 400, { error: 'No valid host names found' });
    const results = [];
    await disc.pool(names, 6, async host => {
      const r = await probe.probeHost(host, { timeoutMs: 5000 });
      const score = r.working ? probe.scoreOf(r.info, []) : 0;
      const t = r.info.tls || {};
      results.push({ host, working: r.working, error: r.error, score, band: probe.bandOf(score), ms: t.ok ? t.ms : null, tls: t.version || null, cdn: r.info.cdn || null, types: probe.typesOf(r.info), ip: r.info.ip || null });
    });
    results.sort((a, b) => b.score - a.score || a.host.localeCompare(b.host));
    return send(res, 200, { results });
  }

  if (p === '/api/tools/subdomains' && m === 'POST') {
    if (!isAdmin(req) && limited(req, 'subs', 6, 60000)) return send(res, 429, { error: 'Too many searches. Wait a minute.' });
    const r = await disc.findSubdomains(body.domain, { deep: !!body.deep });
    const names = [...r.names].sort();
    const known = names.filter(n => db.hosts[n] && isPublished(db.hosts[n]));
    return send(res, 200, { domain: r.domain, count: names.length, stats: r.stats, names: names.slice(0, 1500), publishedHere: known });
  }

  if (p === '/api/admin/login' && m === 'POST') {
    if (req.headers['x-admin-path'] !== adminUrl()) return send(res, 404, { error: 'Not found' });
    if (limited(req, 'login', 6, 60000)) return send(res, 429, { error: 'Too many attempts. Wait a minute.' });
    if (!checkPw(body.password, db.settings.adminHash)) return send(res, 401, { error: 'Wrong password' });
    const token = crypto.randomBytes(32).toString('hex');
    sessions.set(token, Date.now() + 12 * 3600000);
    return send(res, 200, { token });
  }

  // ---- admin ----
  if (p.startsWith('/api/admin/')) {
    if (!isAdmin(req)) return send(res, 401, { error: 'Sign in required' });

    if (p === '/api/admin/status' && m === 'GET') {
      const all = Object.values(db.hosts);
      return send(res, 200, {
        job: jobs.status(), logs: db.logs.slice(-80), runs: db.runs.slice(-10), lastDaily: db.meta.lastDaily,
        counts: { total: all.length, working: all.filter(h => h.working).length, pending: all.filter(h => h.review === 'pending' && h.working).length, published: all.filter(isPublished).length, sources: db.sources.length }
      });
    }

    if (p === '/api/admin/hosts' && m === 'GET') {
      let list = Object.values(db.hosts);
      if (q.review) list = list.filter(h => h.review === q.review);
      if (q.working === '1') list = list.filter(h => h.working);
      if (q.working === '0') list = list.filter(h => !h.working);
      if (q.published === '1') list = list.filter(isPublished);
      list = filterHosts(list, q);
      const limit = Math.min(parseInt(q.limit, 10) || 100, 500);
      const offset = parseInt(q.offset, 10) || 0;
      return send(res, 200, { total: list.length, hosts: list.slice(offset, offset + limit).map(summary) });
    }

    if (p === '/api/admin/review' && m === 'POST') {
      const action = body.action;
      const map = { approve: 'approved', reject: 'rejected', pending: 'pending' };
      if (!map[action] && action !== 'unpublish') return send(res, 400, { error: 'Unknown action' });
      let n = 0;
      let targets = body.hosts || [];
      if (body.all === 'pending') targets = Object.values(db.hosts).filter(h => h.review === 'pending' && h.working).map(h => h.host);
      for (const name of targets) {
        const h = db.hosts[name];
        if (!h) continue;
        h.review = action === 'unpublish' ? 'pending' : map[action];
        n++;
      }
      store.save();
      jobs.log(`Admin ${action}: ${n} hosts`);
      return send(res, 200, { changed: n });
    }

    if (p === '/api/admin/hosts' && m === 'POST') {
      const names = String(body.hosts || '').split(/[\s,;]+/).map(probe.cleanHost).filter(Boolean);
      if (!names.length) return send(res, 400, { error: 'No valid hostnames found' });
      const created = jobs.addHosts(names, { country: body.country || 'GLOBAL', carriers: body.carriers || [], source: 'manual' });
      for (const n of names) { const h = db.hosts[n]; if (h && body.country) { h.country = inferCountry(n, body.country); if (h.country === 'ZW' && h.review === 'auto') h.review = h.working ? 'pending' : 'new'; } }
      const queue = created.slice(0, 300);
      setTimeout(async () => { for (const h of queue) { try { await jobs.testHost(h); } catch (_) { /* noop */ } } store.save(); }, 10);
      return send(res, 200, { added: created.length, skipped: names.length - created.length });
    }

    mm = /^\/api\/admin\/hosts\/([^/]+)$/.exec(p);
    if (mm) {
      const name = decodeURIComponent(mm[1]);
      const h = db.hosts[name];
      if (!h) return send(res, 404, { error: 'Host not found' });
      if (m === 'DELETE') { delete db.hosts[name]; store.save(); return send(res, 200, { ok: true }); }
      if (m === 'PATCH') {
        if (body.country) {
          h.country = body.country;
          if (h.country === 'ZW' && h.review === 'auto') h.review = h.working ? 'pending' : 'new';
          if (h.country !== 'ZW' && (h.review === 'new' || h.review === 'pending')) h.review = 'auto';
        }
        if (Array.isArray(body.carriers)) h.carriers = body.carriers.map(String).slice(0, 8);
        if (typeof body.note === 'string') h.note = body.note.slice(0, 200);
        store.save();
        return send(res, 200, summary(h));
      }
      if (m === 'POST') { await jobs.testHost(h); store.save(); return send(res, 200, detail(h)); }
    }

    if (p === '/api/admin/sources' && m === 'GET') return send(res, 200, db.sources);
    if (p === '/api/admin/sources' && m === 'POST') {
      const domains = String(body.domains || '').split(/[\s,;]+/).map(probe.cleanHost).filter(Boolean);
      let n = 0;
      for (const d of domains) {
        if (db.sources.some(s => s.domain === d)) continue;
        db.sources.push({ domain: d, country: body.country || 'GLOBAL', carriers: body.carriers || [], kind: 'zero-rated', deep: !!body.deep, enabled: true, added: Date.now() });
        n++;
      }
      store.save();
      return send(res, 200, { added: n });
    }
    mm = /^\/api\/admin\/sources\/([^/]+)$/.exec(p);
    if (mm) {
      const d = decodeURIComponent(mm[1]);
      const i = db.sources.findIndex(s => s.domain === d);
      if (i < 0) return send(res, 404, { error: 'Source not found' });
      if (m === 'DELETE') { db.sources.splice(i, 1); store.save(); return send(res, 200, { ok: true }); }
      if (m === 'PATCH') {
        if (typeof body.enabled === 'boolean') db.sources[i].enabled = body.enabled;
        if (typeof body.deep === 'boolean') db.sources[i].deep = body.deep;
        store.save();
        return send(res, 200, db.sources[i]);
      }
    }

    if (p === '/api/admin/run' && m === 'POST') {
      const kind = body.job;
      if (!['daily', 'retest', 'discover', 'deep'].includes(kind)) return send(res, 400, { error: 'Unknown job' });
      if (jobs.status().running) return send(res, 409, { error: 'A job is already running' });
      jobs.run(kind).catch(e => jobs.log(`${kind} failed: ${e.message}`));
      return send(res, 200, { started: kind });
    }
    if (p === '/api/admin/cidr' && m === 'POST') {
      if (jobs.status().running) return send(res, 409, { error: 'A job is already running' });
      try { disc.expandCidr(body.cidr); } catch (e) { return send(res, 400, { error: e.message }); }
      jobs.runCidr({ cidr: body.cidr, country: body.country || 'GLOBAL', carriers: body.carriers || [] }).catch(e => jobs.log('CIDR failed: ' + e.message));
      return send(res, 200, { started: 'cidr' });
    }
    if (p === '/api/admin/backup' && m === 'GET') {
      const day = new Date().toISOString().slice(0, 10);
      return send(res, 200, makeBackup(), { 'Content-Disposition': `attachment; filename="moon-radar-backup-${day}.json"` });
    }
    if (p === '/api/admin/restore' && m === 'POST') {
      if (jobs.status().running) return send(res, 409, { error: 'A scan is running. Stop it or wait, then restore.' });
      try { return send(res, 200, restoreBackup(body)); } catch (e) { return send(res, 400, { error: e.message }); }
    }
    if (p === '/api/admin/clouds' && m === 'GET') {
      const now = Date.now();
      return send(res, 200, Object.values(db.clouds).sort((a, b) => b.createdAt - a.createdAt).map(c => cloud.summary(c, now)));
    }
    if (p === '/api/admin/clouds' && m === 'POST') {
      if (Object.keys(db.clouds).length >= 500) return send(res, 400, { error: 'You have 500 cloud configs. Delete some old ones first.' });
      try {
        const c = cloud.create(body);
        db.clouds[c.token] = c;
        store.save();
        jobs.log(`Cloud config created: ${c.name}`);
        return send(res, 200, cloud.summary(c));
      } catch (e) { return send(res, 400, { error: e.message }); }
    }
    mm = /^\/api\/admin\/clouds\/([A-Za-z0-9_-]+)$/.exec(p);
    if (mm) {
      const c = db.clouds[mm[1]];
      if (!c) return send(res, 404, { error: 'Cloud config not found' });
      if (m === 'DELETE') { delete db.clouds[mm[1]]; store.save(); return send(res, 200, { ok: true }); }
      if (m === 'POST') {
        const now = Date.now();
        if (body.action === 'revoke') c.revoked = true;
        else if (body.action === 'restore') c.revoked = false;
        else if (body.action === 'extend') {
          let mins;
          try { mins = cloud.minutesFrom({ minutes: body.minutes }); } catch (e) { return send(res, 400, { error: e.message }); }
          if (c.expiresAt) c.expiresAt = Math.max(now, c.expiresAt) + mins * 60000; else c.durationMin += mins;
        } else return send(res, 400, { error: 'Unknown action' });
        store.save();
        return send(res, 200, cloud.summary(c, now));
      }
    }

    if (p === '/api/admin/verify' && m === 'POST') {
      const carrier = String(body.carrier || '').trim().slice(0, 30);
      if (!carrier) return send(res, 400, { error: 'Enter the carrier name, for example Econet' });
      const now = Date.now();
      let n = 0;
      const mark = (list, ok) => { for (const name of Array.isArray(list) ? list.slice(0, 2000) : []) { const h = db.hosts[probe.cleanHost(name)]; if (h) { h.verified[carrier] = { ok, t: now }; n++; } } };
      mark(body.working, true); mark(body.failed, false);
      store.save();
      jobs.log(`Phone test on ${carrier}: ${n} hosts marked`);
      return send(res, 200, { marked: n });
    }
    if (p === '/api/admin/stop' && m === 'POST') { jobs.stop(); return send(res, 200, { ok: true }); }

    if (p === '/api/admin/settings' && m === 'GET') { const s = Object.assign({}, db.settings); delete s.adminHash; delete s.adminPath; return send(res, 200, s); }
    if (p === '/api/admin/settings' && m === 'POST') {
      applySettings(db.settings, body);
      store.save();
      return send(res, 200, { ok: true });
    }
    if (p === '/api/admin/password' && m === 'POST') {
      if (!checkPw(body.current, db.settings.adminHash)) return send(res, 401, { error: 'Current password is wrong' });
      if (String(body.next || '').length < 8) return send(res, 400, { error: 'New password needs at least 8 characters' });
      db.settings.adminHash = hashPw(body.next);
      sessions.clear();
      store.save();
      return send(res, 200, { ok: true });
    }
    return send(res, 404, { error: 'Not found' });
  }

  return send(res, 404, { error: 'Not found' });
}

const plain = (res, code, text) => { res.writeHead(code, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(text + '\n'); };

function serveCloud(req, res, url) {
  if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405); return res.end(); }
  if (limited(req, 'cloud', 120, 60000)) return plain(res, 429, 'Too many requests. Try again in a minute.');
  const token = decodeURIComponent(url.pathname.slice(3)).replace(/\/+$/, '');
  const c = /^[A-Za-z0-9_-]{16,64}$/.test(token) ? db.clouds[token] : null;
  const now = Date.now();
  if (!c) return plain(res, 404, 'Config not found.');
  const st = cloud.status(c, now);
  if (st === 'revoked') return plain(res, 410, 'This config was withdrawn by its owner.');
  if (st === 'expired') return plain(res, 410, `This config expired on ${new Date(c.expiresAt).toUTCString()}.`);
  if (st === 'used up') return plain(res, 410, 'This config reached its open limit.');
  const fmt = (url.searchParams.get('f') || '').toLowerCase();
  if (!fmt && /text\/html/.test(req.headers.accept || '')) {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'X-Robots-Tag': 'noindex' });
    return res.end(req.method === 'HEAD' ? '' : cloud.card(c, now));
  }
  if (req.method === 'GET') { cloud.activate(c, now); c.opens++; store.save(); }
  const out = cloud.render(c, fmt);
  if (out.error) return plain(res, 400, out.error);
  res.writeHead(200, Object.assign({ 'Content-Type': out.type }, cloud.headers(c)));
  res.end(req.method === 'HEAD' ? '' : out.body);
}

function pruneClouds() {
  const cutoff = Date.now() - 30 * 86400000;
  let n = 0;
  for (const [k, c] of Object.entries(db.clouds)) {
    const st = cloud.status(c);
    if ((st === 'expired' && c.expiresAt < cutoff) || (st === 'revoked' && c.createdAt < cutoff) || (st === 'used up' && c.createdAt < cutoff)) { delete db.clouds[k]; n++; }
  }
  if (n) { store.save(); jobs.log(`Removed ${n} old cloud configs`); }
}

function serveStatic(req, res, url) {
  let f = decodeURIComponent(url.pathname);
  const isAdminPage = f.replace(/\/+$/, '') === adminUrl();
  if (f === '/' || !path.extname(f)) f = '/index.html';
  const full = path.normalize(path.join(PUBLIC_DIR, f));
  if (full !== PUBLIC_DIR && !full.startsWith(PUBLIC_DIR + path.sep)) { res.writeHead(403); return res.end(); }
  fs.readFile(full, (err, data) => {
    if (err) { res.writeHead(404); return res.end('Not found'); }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(full)] || 'application/octet-stream', 'Cache-Control': 'no-cache' });
    if (isAdminPage) return res.end(data.toString('utf8').replace('<head>', '<head><meta name="radar-admin" content="1"><meta name="robots" content="noindex,nofollow">'));
    res.end(data);
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  try {
    if (url.pathname.startsWith('/c/')) return serveCloud(req, res, url);
    if (url.pathname.startsWith('/api/')) {
      const big = url.pathname === '/api/admin/restore';
      if (big && !isAdmin(req)) return send(res, 401, { error: 'Sign in required' });
      const body = req.method === 'GET' || req.method === 'DELETE' ? {} : await readBody(req, big ? 40e6 : 1e6);
      return await route(req, res, url, body);
    }
    return serveStatic(req, res, url);
  } catch (e) {
    send(res, 500, { error: e.message || 'Server error' });
  }
});

if (require.main === module) {
  server.listen(PORT, HOST, () => {
    console.log(`Moon Radar running on http://localhost:${PORT}`);
    jobs.startScheduler();
    pruneClouds();
    setInterval(pruneClouds, 3600000).unref();
  });
  const bye = () => { store.flush(); process.exit(0); };
  process.on('SIGINT', bye);
  process.on('SIGTERM', bye);
}

module.exports = { server };
