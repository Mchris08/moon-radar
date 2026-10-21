'use strict';
const store = require('./store');
const probe = require('./probe');
const disc = require('./discover');
const { inferCountry } = require('./seeds');

const state = { running: null, phase: '', done: 0, total: 0, startedAt: 0, stop: false };
const HISTORY_MAX = 30;
let onlineCache = { t: 0, ok: true };

function log(msg) {
  const db = store.get();
  db.logs.push({ t: Date.now(), m: msg });
  if (db.logs.length > 300) db.logs.splice(0, db.logs.length - 300);
  store.save();
  if (process.env.RADAR_QUIET !== '1') console.log('[radar]', msg);
}

async function pool(items, n, fn) {
  let i = 0;
  const workers = Array.from({ length: Math.max(1, Math.min(n, items.length)) }, async () => {
    while (i < items.length && !state.stop) {
      const idx = i++;
      try { await fn(items[idx], idx); } catch (_) { /* noop */ }
      state.done++;
    }
  });
  await Promise.all(workers);
}

/** Is the device actually connected? Prevents a dead connection from marking every host as down. */
async function online(force) {
  const s = store.get().settings;
  if (s.zeroBalanceMode) return true;
  if (process.env.RADAR_FORCE_OFFLINE === '1') return false; // test hook
  if (!force && Date.now() - onlineCache.t < 30000) return onlineCache.ok;
  const checks = await Promise.all([
    probe.tlsConnect('1.1.1.1', 'cloudflare-dns.com', 443, 4000),
    probe.tlsConnect('8.8.8.8', 'dns.google', 443, 4000),
    probe.resolveIps('example.com', 4000).then(r => ({ ok: r.ips.length > 0 }))
  ]);
  onlineCache = { t: Date.now(), ok: checks.some(c => c.ok) };
  return onlineCache.ok;
}

function newHostRecord(host, { country, carriers, source, parent }) {
  const c = inferCountry(host, country);
  return {
    host, country: c, carriers: carriers || [], source: source || 'manual', parent: parent || null,
    firstSeen: Date.now(), lastTested: 0, lastOk: 0, working: false, failStreak: 0,
    review: c === 'ZW' ? 'new' : 'auto', // ZW hosts need admin approval
    score: 0, info: {}, history: [], verified: {}, note: ''
  };
}

/** Add hostnames that are not yet known. Returns the list of newly created records. */
function addHosts(names, meta) {
  const db = store.get();
  const created = [];
  for (const n of names) {
    const h = probe.cleanHost(n);
    if (!h || db.hosts[h]) continue;
    db.hosts[h] = newHostRecord(h, meta);
    created.push(db.hosts[h]);
  }
  store.save();
  return created;
}

function applyResult(h, res) {
  const db = store.get();
  const s = db.settings;
  h.lastTested = res.testedAt;
  h.history.push({ t: res.testedAt, ok: res.working, ms: res.info.tls && res.info.tls.ms || null });
  if (h.history.length > HISTORY_MAX) h.history.splice(0, h.history.length - HISTORY_MAX);
  if (res.working) {
    h.working = true;
    h.lastOk = res.testedAt;
    h.failStreak = 0;
    if (h.review === 'new') h.review = h.country === 'ZW' ? 'pending' : 'auto';
  } else {
    h.working = false;
    h.failStreak = (h.failStreak || 0) + 1;
  }
  h.info = res.info;
  h.error = res.error;
  h.score = res.working ? probe.scoreOf(res.info, h.history) : 0;
  h.protocols = res.working ? probe.protocolsOf(res.info) : [];
  h.types = probe.typesOf(res.info);
  if (s.carrier) h.verified[s.carrier] = { ok: res.working, t: res.testedAt };
}

/** Test one host. A failure is retried once with a longer timeout before the host is marked down. */
async function testHost(h) {
  const s = store.get().settings;
  const prevWs = h.info && h.info.ws;
  const opts = { timeoutMs: s.timeoutMs, deep: !prevWs, prevWs };
  let res = await probe.probeHost(h.host, opts);
  if (!res.working && res.error !== 'private-ip') {
    await new Promise(r => setTimeout(r, 1500));
    res = await probe.probeHost(h.host, Object.assign({}, opts, { timeoutMs: Math.round(s.timeoutMs * 1.5) }));
  }
  if (!res.working && !(await online())) return 'offline';
  applyResult(h, res);
  return res.working ? 'up' : 'down';
}

async function testMany(records, label) {
  const s = store.get().settings;
  state.phase = label; state.done = 0; state.total = records.length;
  let up = 0, down = 0, offline = 0;
  await pool(records, s.concurrency, async h => {
    const r = await testHost(h);
    if (r === 'up') up++; else if (r === 'down') down++; else offline++;
    if (state.done % 25 === 0) store.save();
  });
  store.save();
  return { up, down, offline };
}

async function discoverSources({ deep = false, onlyCountry = null } = {}) {
  const db = store.get();
  const s = db.settings;
  let sources = db.sources.filter(x => x.enabled !== false && (!onlyCountry || x.country === onlyCountry));
  sources.sort((a, b) => (b.country === 'ZW') - (a.country === 'ZW')); // Zimbabwe first
  state.phase = 'Discovering hosts'; state.done = 0; state.total = sources.length;
  const fresh = [];
  for (const src of sources) {
    if (state.stop) break;
    try {
      const r = await disc.findSubdomains(src.domain, { deep: deep || src.deep });
      const crawled = await disc.crawlHosts(src.domain);
      const names = new Set([...r.names, ...crawled]);
      const made = addHosts(names, { country: src.country, carriers: src.carriers, source: `source:${src.domain}`, parent: src.domain });
      made.forEach(m => fresh.push(m));
      log(`${src.domain}: ${names.size} names, ${made.length} new`);
    } catch (e) {
      log(`${src.domain}: discovery failed (${e.message})`);
    }
    state.done++;
    if (fresh.length >= s.maxNewPerRun) { log(`Reached max ${s.maxNewPerRun} new hosts for this run`); break; }
  }
  return fresh.slice(0, s.maxNewPerRun);
}

function prune() {
  const db = store.get();
  const cutoff = Date.now() - db.settings.pruneDays * 86400000;
  let n = 0;
  for (const [k, h] of Object.entries(db.hosts)) {
    if (h.working || h.source === 'manual' || h.review === 'approved') continue;
    const last = h.lastOk || h.firstSeen;
    if (last < cutoff && h.lastTested) { delete db.hosts[k]; n++; }
  }
  if (n) log(`Pruned ${n} hosts that stayed down for ${db.settings.pruneDays}+ days`);
  return n;
}

async function run(kind, params = {}) {
  if (state.running) throw new Error(`A job is already running (${state.running})`);
  state.running = kind; state.stop = false; state.startedAt = Date.now(); state.done = 0; state.total = 0;
  const db = store.get();
  const summary = { kind, t: Date.now(), tested: 0, up: 0, down: 0, fresh: 0, freshWorking: 0, skipped: false };
  try {
    if (!(await online(true))) {
      log(`${kind}: no internet connection, skipped. Will retry automatically.`);
      summary.skipped = true;
      return summary;
    }
    log(`${kind}: started`);
    if (kind === 'daily' || kind === 'discover' || kind === 'deep') {
      const deep = kind === 'deep' || (kind === 'daily' && new Date().getDay() === db.settings.deepWeekday);
      const fresh = await discoverSources({ deep });
      summary.fresh = fresh.length;
      if (fresh.length) {
        const r = await testMany(fresh, 'Testing new hosts');
        summary.tested += fresh.length; summary.up += r.up; summary.down += r.down;
        summary.freshWorking = r.up;
        log(`New hosts: ${fresh.length} found, ${r.up} working`);
      }
    }
    if (kind === 'daily' || kind === 'retest') {
      const all = Object.values(db.hosts).filter(h => (kind === 'retest' || Date.now() - h.lastTested > 3600000));
      all.sort((a, b) => (b.working - a.working) || (b.score - a.score));
      const r = await testMany(all, 'Re-testing known hosts');
      summary.tested += all.length; summary.up += r.up; summary.down += r.down;
      if (r.offline) log(`${r.offline} hosts left unchanged because the connection dropped`);
    }
    if (kind === 'daily') { prune(); db.meta.lastDaily = Date.now(); }
    summary.durationMs = Date.now() - state.startedAt;
    db.runs.push(summary);
    if (db.runs.length > 60) db.runs.splice(0, db.runs.length - 60);
    log(`${kind}: finished. ${summary.up} up, ${summary.down} down, ${summary.fresh} new`);
    return summary;
  } finally {
    state.running = null; state.phase = ''; state.stop = false;
    store.save();
  }
}

async function runCidr({ cidr, country, carriers }) {
  if (state.running) throw new Error(`A job is already running (${state.running})`);
  const ips = disc.expandCidr(cidr);
  state.running = 'cidr'; state.stop = false; state.startedAt = Date.now();
  state.phase = `Scanning ${cidr}`; state.done = 0; state.total = ips.length;
  try {
    const names = new Set();
    await pool(ips, Math.min(60, store.get().settings.concurrency * 3), async ip => {
      const r = await probe.grabCert(ip, 443, 2500);
      if (r.ok) r.names.forEach(n => { const h = probe.cleanHost(n); if (h) names.add(h); });
    });
    const made = addHosts(names, { country, carriers, source: `cidr:${cidr}` });
    log(`CIDR ${cidr}: ${names.size} certificate names, ${made.length} new`);
    if (made.length) await testMany(made, 'Testing CIDR hosts');
    return { names: names.size, fresh: made.length };
  } finally { state.running = null; state.phase = ''; store.save(); }
}

function status() {
  return Object.assign({}, state, { elapsed: state.running ? Date.now() - state.startedAt : 0 });
}
function stop() { state.stop = true; }

/** Called every minute: runs the daily pipeline once per day after retestHour, as soon as the device is online. */
function startScheduler() {
  const tick = async () => {
    const db = store.get();
    if (!db.settings.autoDaily || state.running) return;
    const now = new Date();
    const due = new Date(now); due.setHours(db.settings.retestHour, 0, 0, 0);
    if (now >= due && db.meta.lastDaily < due.getTime()) {
      try { await run('daily'); } catch (e) { log('daily failed: ' + e.message); }
    }
  };
  setInterval(tick, 60000);
  setTimeout(tick, 5000);
}

module.exports = { run, runCidr, status, stop, addHosts, testHost, applyResult, startScheduler, log, newHostRecord, online };
