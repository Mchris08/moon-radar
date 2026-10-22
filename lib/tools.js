'use strict';
const dns = require('dns');
const dnsp = dns.promises;
const net = require('net');
const probe = require('./probe');

const RESOLVERS = { cloudflare: ['1.1.1.1', '1.0.0.1'], google: ['8.8.8.8', '8.8.4.4'], quad9: ['9.9.9.9', '149.112.112.112'] };
const TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'CAA'];
const NO_DATA = new Set(['ENODATA', 'ENOTFOUND', 'NODATA', 'NXDOMAIN']);

async function pool(items, n, fn) {
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => {
    while (i < items.length) { const k = i++; try { await fn(items[k], k); } catch (_) { /* noop */ } }
  }));
}

/** DNS records for a name, using the device's own resolver ("system") or a public one. */
async function dnsLookup(name, { types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT'], resolver = 'system' } = {}) {
  const out = { name: null, resolver, records: {}, errors: {}, note: null };
  const R = resolver !== 'system' && RESOLVERS[resolver] ? new dnsp.Resolver({ timeout: 4000, tries: 1 }) : dnsp;
  if (R !== dnsp) R.setServers(RESOLVERS[resolver]);
  else out.resolver = 'system';
  if (net.isIP(name)) {
    out.name = name;
    try { out.records.PTR = await R.reverse(name); } catch (e) { if (!NO_DATA.has(e.code)) out.errors.PTR = e.code || e.message; else out.records.PTR = []; }
    return out;
  }
  const host = probe.cleanHost(name);
  if (!host) throw new Error('Enter a valid domain name, for example example.com');
  out.name = host;
  const want = types.filter(t => TYPES.includes(t));
  await Promise.all(want.map(async t => {
    try {
      let r;
      if (t === 'A') r = R === dnsp ? (await dnsp.lookup(host, { all: true, family: 4 })).map(x => x.address) : (await R.resolve4(host, { ttl: true })).map(x => `${x.address}  (ttl ${x.ttl}s)`);
      else if (t === 'AAAA') r = R === dnsp ? (await dnsp.lookup(host, { all: true, family: 6 })).map(x => x.address) : (await R.resolve6(host, { ttl: true })).map(x => `${x.address}  (ttl ${x.ttl}s)`);
      else if (t === 'CNAME') r = await R.resolveCname(host);
      else if (t === 'MX') r = (await R.resolveMx(host)).sort((a, b) => a.priority - b.priority).map(x => `${x.priority} ${x.exchange}`);
      else if (t === 'NS') r = await R.resolveNs(host);
      else if (t === 'TXT') r = (await R.resolveTxt(host)).map(x => x.join(''));
      else if (t === 'SOA') { const s = await R.resolveSoa(host); r = [`${s.nsname} ${s.hostmaster} serial ${s.serial}`]; }
      else if (t === 'CAA') r = (await R.resolveCaa(host)).map(x => `${x.critical ? 1 : 0} ${x.issue ? 'issue ' + x.issue : x.iodef ? 'iodef ' + x.iodef : 'issuewild ' + (x.issuewild || '')}`);
      out.records[t] = r;
    } catch (e) {
      if (NO_DATA.has(e.code)) out.records[t] = [];
      else out.errors[t] = e.code || e.message;
    }
  }));
  const failedAll = want.length && want.every(t => out.errors[t]);
  if (failedAll && resolver === 'system') out.note = 'The device resolver did not answer. Try Cloudflare or Google from the resolver menu.';
  return out;
}

const SERVICES = { 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 465: 'SMTPS', 500: 'IKE', 587: 'SMTP', 993: 'IMAPS', 995: 'POP3S', 1194: 'OpenVPN', 1723: 'PPTP', 2053: 'Cloudflare HTTPS', 2083: 'Cloudflare HTTPS', 2087: 'Cloudflare HTTPS', 2096: 'Cloudflare HTTPS', 3128: 'Proxy', 3306: 'MySQL', 4500: 'IPsec NAT-T', 5432: 'PostgreSQL', 8080: 'HTTP alt', 8443: 'HTTPS alt', 8880: 'HTTP alt', 1080: 'SOCKS' };

function parsePorts(s, max = 30) {
  const out = new Set();
  for (const part of String(s || '').split(/[\s,;]+/).filter(Boolean)) {
    const m = /^(\d{1,5})(?:-(\d{1,5}))?$/.exec(part);
    if (!m) throw new Error(`"${part}" is not a port or range`);
    const a = +m[1], b = m[2] ? +m[2] : a;
    if (a < 1 || b > 65535 || b < a) throw new Error(`Port ${part} is out of range`);
    for (let p = a; p <= b; p++) { out.add(p); if (out.size > max) throw new Error(`Check at most ${max} ports at a time`); }
  }
  if (!out.size) throw new Error('Enter at least one port');
  return [...out];
}

function tcpCheck(ip, port, timeout) {
  return new Promise(resolve => {
    const t0 = Date.now();
    let done = false, banner = '';
    const sock = net.connect({ host: ip, port });
    const finish = (status, extra = {}) => { if (done) return; done = true; try { sock.destroy(); } catch (_) { /* noop */ } resolve(Object.assign({ port, status, ms: Date.now() - t0, banner: banner.replace(/[^\x20-\x7e]/g, '').slice(0, 80) }, extra)); };
    sock.setTimeout(timeout, () => finish('filtered'));
    sock.on('connect', () => { const ms = Date.now() - t0; sock.once('data', d => { banner = d.toString('latin1'); finish('open', { ms }); }); setTimeout(() => finish('open', { ms }), 700); });
    sock.on('error', e => finish(e.code === 'ECONNREFUSED' ? 'closed' : e.code === 'EHOSTUNREACH' || e.code === 'ENETUNREACH' ? 'unreachable' : 'filtered'));
  });
}

async function portCheck(target, portsText, { allowPrivate = false, timeoutMs = 3000 } = {}) {
  const host = net.isIP(target) ? target : probe.cleanHost(target);
  if (!host) throw new Error('Enter a valid host name or IP address');
  const ports = parsePorts(portsText);
  let ip = host;
  if (!net.isIP(host)) {
    const d = await probe.resolveIps(host, 5000);
    if (!d.ips.length) throw new Error('That name does not resolve');
    ip = d.ips[0];
  }
  if (!allowPrivate && probe.isPrivateIp(ip)) throw new Error('That address is private and cannot be checked');
  const results = [];
  await pool(ports, 8, async p => { const r = await tcpCheck(ip, p, timeoutMs); r.service = SERVICES[p] || null; results.push(r); });
  results.sort((a, b) => a.port - b.port);
  return { host, ip, results };
}

/** Which names does a server answer to? Handshake with each SNI and compare to the certificate it shows by default. */
async function sniProbe(target, snis, port = 443, { allowPrivate = false, timeoutMs = 5000 } = {}) {
  const host = net.isIP(target) ? target : probe.cleanHost(target);
  if (!host) throw new Error('Enter a valid host name or IP address');
  port = +port > 0 && +port < 65536 ? +port : 443;
  let ip = host;
  if (!net.isIP(host)) {
    const d = await probe.resolveIps(host, 5000);
    if (!d.ips.length) throw new Error('That name does not resolve');
    ip = d.ips[0];
  }
  if (!allowPrivate && probe.isPrivateIp(ip)) throw new Error('That address is private and cannot be checked');
  const def = await probe.tlsConnect(ip, '', port, timeoutMs, ['h2', 'http/1.1']);
  const out = { target: host, ip, port, defaultCert: def.ok ? { subject: def.cert.subject, issuer: def.cert.issuer, validTo: def.cert.validTo, names: def.cert.names, version: def.version, alpn: def.alpn, ms: def.ms } : null, defaultError: def.ok ? null : def.error, candidates: [], results: [] };
  let list = (snis || []).map(probe.cleanHost).filter(Boolean);
  if (!list.length && def.ok) { list = def.cert.names.filter(n => !n.startsWith('*')).map(probe.cleanHost).filter(Boolean); out.usedCertNames = true; }
  list = [...new Set(list)].slice(0, 25);
  await pool(list, 6, async s => {
    const r = await probe.tlsConnect(ip, s, port, timeoutMs, ['h2', 'http/1.1']);
    out.results.push(r.ok
      ? { sni: s, ok: true, ms: r.ms, version: r.version, alpn: r.alpn, subject: r.cert.subject, issuer: r.cert.issuer, nameMatch: r.cert.nameMatch, sameCert: !!(def.ok && r.cert.subject === def.cert.subject && r.cert.validTo === def.cert.validTo) }
      : { sni: s, ok: false, error: r.error });
  });
  out.results.sort((a, b) => (b.ok - a.ok) || a.sni.localeCompare(b.sni));
  return out;
}

module.exports = { dnsLookup, portCheck, sniProbe, parsePorts, RESOLVERS, TYPES };
