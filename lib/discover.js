'use strict';
const https = require('https');
const http = require('http');
const dns = require('dns').promises;
const crypto = require('crypto');
const net = require('net');
const { cleanHost, grabCert } = require('./probe');
const { WORDLIST } = require('./seeds');

function fetchText(url, { timeout = 20000, maxBytes = 2e6, insecure = false, redirects = 4 } = {}) {
  return new Promise((resolve, reject) => {
    let u;
    try { u = new URL(url); } catch (e) { return reject(e); }
    const lib = u.protocol === 'http:' ? http : https;
    const req = lib.get(u, {
      timeout,
      rejectUnauthorized: !insecure,
      headers: { 'User-Agent': 'Mozilla/5.0 (Linux; Android 12) MoonRadar/1.0', Accept: '*/*' }
    }, res => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location && redirects > 0) {
        res.resume();
        const next = new URL(res.headers.location, u).toString();
        return fetchText(next, { timeout, maxBytes, insecure, redirects: redirects - 1 }).then(resolve, reject);
      }
      let size = 0;
      const chunks = [];
      res.on('data', c => {
        size += c.length;
        if (size > maxBytes) { req.destroy(); return resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }); }
        chunks.push(c);
      });
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', reject);
  });
}

const inDomain = (name, domain) => name === domain || name.endsWith('.' + domain);

function collect(names, domain) {
  const out = new Set();
  for (const n of names) {
    const h = cleanHost(n);
    if (h && inDomain(h, domain)) out.add(h);
  }
  return out;
}

async function crtsh(domain) {
  const r = await fetchText(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`, { timeout: 30000, maxBytes: 25e6 });
  const rows = JSON.parse(r.body);
  const names = [];
  for (const row of rows) String(row.name_value || '').split('\n').forEach(n => names.push(n));
  return collect(names, domain);
}

async function certspotter(domain) {
  const r = await fetchText(`https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}&include_subdomains=true&expand=dns_names`, { timeout: 25000, maxBytes: 10e6 });
  const rows = JSON.parse(r.body);
  const names = [];
  for (const row of rows) (row.dns_names || []).forEach(n => names.push(n));
  return collect(names, domain);
}

async function hackertarget(domain) {
  const r = await fetchText(`https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`, { timeout: 20000 });
  if (/^error|api count exceeded/i.test(r.body)) throw new Error('hackertarget limit');
  return collect(r.body.split('\n').map(l => l.split(',')[0]), domain);
}

async function anubis(domain) {
  const r = await fetchText(`https://jldc.me/anubis/subdomains/${encodeURIComponent(domain)}`, { timeout: 20000 });
  return collect(JSON.parse(r.body), domain);
}

async function pool(items, n, fn) {
  let i = 0;
  const workers = Array.from({ length: Math.min(n, items.length) }, async () => {
    while (i < items.length) { const idx = i++; try { await fn(items[idx], idx); } catch (_) { /* noop */ } }
  });
  await Promise.all(workers);
}

async function lookupOk(name) {
  try { const r = await dns.lookup(name, { all: true }); return r.map(x => x.address); } catch (_) { return null; }
}

async function bruteforce(domain, concurrency = 40) {
  const wild = await lookupOk(`zz-${crypto.randomBytes(5).toString('hex')}.${domain}`);
  if (wild) return new Set(); // wildcard DNS: brute force would return noise
  const found = new Set();
  await pool(WORDLIST, concurrency, async w => {
    const name = `${w}.${domain}`;
    if (await lookupOk(name)) found.add(name);
  });
  return found;
}

/** Passive sources in parallel, optional DNS brute force. Returns { names:Set, errors:[] } */
async function findSubdomains(domain, { deep = false } = {}) {
  const d = cleanHost(domain);
  if (!d) throw new Error('Invalid domain');
  const sources = { 'crt.sh': crtsh, certspotter, hackertarget, anubis };
  const names = new Set([d]);
  const stats = {};
  await Promise.all(Object.entries(sources).map(async ([label, fn]) => {
    try { const s = await fn(d); s.forEach(x => names.add(x)); stats[label] = s.size; }
    catch (e) { stats[label] = 'failed'; }
  }));
  if (deep) {
    try { const s = await bruteforce(d); s.forEach(x => names.add(x)); stats.bruteforce = s.size; }
    catch (_) { stats.bruteforce = 'failed'; }
  }
  return { domain: d, names, stats };
}

const NOISE = /(^|\.)(w3\.org|schema\.org|purl\.org|xmlns\.com|gstatic\.com\.invalid|example\.com|localhost)$/;

/** Fetch a zero-rated site's homepage and pull out every hostname it loads assets from. */
async function crawlHosts(domain, limit = 80) {
  const found = new Set();
  const pages = [`https://${domain}/`, `https://www.${domain}/`];
  for (const url of pages) {
    try {
      const r = await fetchText(url, { timeout: 12000, maxBytes: 1.5e6, insecure: true });
      const re = /(?:https?:)?\/\/([a-z0-9][a-z0-9.-]*\.[a-z]{2,24})(?=[\/"'\s)?:])/gi;
      let m;
      while ((m = re.exec(r.body)) && found.size < limit * 3) {
        const h = cleanHost(m[1]);
        if (h && !NOISE.test(h) && !net.isIP(h)) found.add(h);
      }
    } catch (_) { /* site unreachable: skip */ }
  }
  return [...found].slice(0, limit);
}

function ipToInt(ip) { return ip.split('.').reduce((a, b) => ((a << 8) + (+b)) >>> 0, 0); }
function intToIp(n) { return [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.'); }

function expandCidr(cidr, maxIps = 4096) {
  const m = /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/.exec(String(cidr).trim());
  if (!m || !net.isIPv4(m[1])) throw new Error('Use IPv4 CIDR like 41.57.0.0/22');
  const bits = +m[2];
  if (bits < 12 || bits > 32) throw new Error('Prefix must be between /12 and /32');
  const size = Math.pow(2, 32 - bits);
  if (size > maxIps) throw new Error(`Range too large (${size} IPs). Max ${maxIps} per scan, use /${32 - Math.log2(maxIps)} or smaller.`);
  const base = (ipToInt(m[1]) >>> (32 - bits)) << (32 - bits) >>> 0;
  const out = [];
  for (let i = 0; i < size; i++) out.push(intToIp((base + i) >>> 0));
  return out;
}

module.exports = { fetchText, findSubdomains, crawlHosts, expandCidr, pool, lookupOk, grabCert };
