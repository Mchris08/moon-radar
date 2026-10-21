'use strict';
const fs = require('fs');
const path = require('path');
const { seedSources } = require('./seeds');

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, '..', 'data');
const FILE = path.join(DATA_DIR, 'db.json');
let db = null;
let timer = null;

const defaults = () => ({
  version: 1,
  settings: {
    retestHour: 3,          // local hour for the daily run
    concurrency: 20,        // parallel probes (lower on weak phones)
    timeoutMs: 6000,
    carrier: '',            // carrier this scanner is running on, e.g. "Econet"
    zeroBalanceMode: false, // skip the "is the internet up?" check (for zero-balance carrier testing)
    pruneDays: 14,          // drop auto-discovered hosts that stay down this long
    maxNewPerRun: 500,      // cap on new hosts tested per discovery run
    autoDaily: true,
    deepWeekday: 0,         // 0 = Sunday: brute-force subdomains on this day
    adminHash: null
  },
  hosts: {},
  sources: [],
  runs: [],
  logs: [],
  meta: { lastDaily: 0 }
});

function load() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  try {
    db = JSON.parse(fs.readFileSync(FILE, 'utf8'));
    const d = defaults();
    db.settings = Object.assign(d.settings, db.settings);
    db.meta = Object.assign(d.meta, db.meta);
    db.hosts = db.hosts || {};
    db.sources = db.sources || [];
    db.runs = db.runs || [];
    db.logs = db.logs || [];
  } catch (_) {
    db = defaults();
  }
  if (!db.sources.length) {
    const now = Date.now();
    db.sources = seedSources().map(s => Object.assign({ added: now }, s));
  }
  flush();
  return db;
}

function flush() {
  clearTimeout(timer);
  timer = null;
  if (!db) return;
  const tmp = FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db));
  fs.renameSync(tmp, FILE);
}

function save() {
  if (timer) return;
  timer = setTimeout(flush, 800);
}

function get() { return db; }

module.exports = { load, save, flush, get, DATA_DIR };
