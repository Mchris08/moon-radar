'use strict';
const dns = require('dns').promises;
const net = require('net');
const tls = require('tls');

const HOST_RE = /^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z]{2,63}$/i;

function cleanHost(s) {
  s = String(s || '').trim().toLowerCase().replace(/^[a-z]+:\/\//, '').split(/[\/:?#\s,;]/)[0]
    .replace(/^\*\./, '').replace(/\.$/, '');
  return HOST_RE.test(s) ? s : null;
}

function isPrivateIp(ip) {
  if (!ip) return true;
  if (ip.startsWith('::ffff:')) ip = ip.slice(7);
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return a === 10 || a === 127 || a === 0 || a >= 224 ||
      (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127);
  }
  const v = ip.toLowerCase();
  return v === '::1' || v === '::' || v.startsWith('fc') || v.startsWith('fd') || v.startsWith('fe8') ||
    v.startsWith('fe9') || v.startsWith('fea') || v.startsWith('feb');
}

async function resolveIps(host, timeoutMs) {
  const t0 = Date.now();
  const run = async () => {
    try {
      const r = await dns.lookup(host, { all: true });
      if (r.length) return r.sort((a, b) => a.family - b.family).map(x => x.address);
    } catch (_) { /* fall through */ }
    try { const a = await dns.resolve4(host); if (a.length) return a; } catch (_) { /* noop */ }
    return [];
  };
  let timer;
  const ips = await Promise.race([run(), new Promise(r => { timer = setTimeout(() => r([]), timeoutMs); })]);
  clearTimeout(timer);
  return { ips, ms: Date.now() - t0 };
}

// Single TLS handshake with SNI = host, connecting straight to the resolved IP.
function tlsConnect(ip, host, port, timeout, alpn) {
  return new Promise(resolve => {
    const t0 = Date.now();
    let done = false;
    let sock;
    const finish = r => { if (done) return; done = true; try { sock && sock.destroy(); } catch (_) { /* noop */ } resolve(r); };
    try {
      sock = tls.connect({ host: ip, port, servername: host, rejectUnauthorized: false, ALPNProtocols: alpn || ['http/1.1'] }, () => {
        const ms = Date.now() - t0;
        const cert = sock.getPeerCertificate() || {};
        let nameMatch = false;
        try { nameMatch = !tls.checkServerIdentity(host, cert); } catch (_) { /* noop */ }
        const exp = cert.valid_to ? Date.parse(cert.valid_to) : 0;
        finish({
          ok: true, ms,
          version: sock.getProtocol(),
          cipher: (sock.getCipher() || {}).name || null,
          alpn: sock.alpnProtocol || null,
          cert: {
            subject: cert.subject && cert.subject.CN || null,
            issuer: cert.issuer && (cert.issuer.O || cert.issuer.CN) || null,
            validTo: cert.valid_to || null,
            daysLeft: exp ? Math.floor((exp - Date.now()) / 86400000) : null,
            nameMatch,
            names: (cert.subjectaltname || '').split(', ').map(s => s.replace(/^DNS:/, '')).filter(Boolean).slice(0, 12)
          }
        });
      });
      sock.setTimeout(timeout, () => finish({ ok: false, error: 'timeout' }));
      sock.on('error', e => finish({ ok: false, error: e.code || e.message }));
    } catch (e) { finish({ ok: false, error: e.code || e.message }); }
  });
}

// Send a raw request over plain TCP or TLS, return the response head.
function rawExchange({ ip, port, host, secure, request, timeout }) {
  return new Promise(resolve => {
    const t0 = Date.now();
    let buf = '';
    let done = false;
    let connected = false;
    let sock;
    const finish = () => {
      if (done) return; done = true;
      try { sock && sock.destroy(); } catch (_) { /* noop */ }
      resolve({ connected, head: buf, ms: Date.now() - t0 });
    };
    const onConnect = () => { connected = true; sock.write(request); };
    try {
      sock = secure
        ? tls.connect({ host: ip, port, servername: host, rejectUnauthorized: false, ALPNProtocols: ['http/1.1'] }, onConnect)
        : net.connect({ host: ip, port }, onConnect);
      sock.setTimeout(timeout, finish);
      sock.on('data', d => { buf += d.toString('latin1'); if (buf.includes('\r\n\r\n') || buf.length > 16384) finish(); });
      sock.on('error', finish);
      sock.on('end', finish);
    } catch (_) { finish(); }
  });
}

const UA = 'Mozilla/5.0 (Linux; Android 12; Mobile) MoonRadar/1.0';
const getReq = host => `GET / HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: ${UA}\r\nAccept: */*\r\nConnection: close\r\n\r\n`;
const headReq = host => `HEAD / HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: ${UA}\r\nAccept: */*\r\nConnection: close\r\n\r\n`;
const wsReq = host => `GET / HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: ${UA}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n`;

function detectCdn(h) {
  const server = (h.server || '').toLowerCase();
  const via = (h.via || '').toLowerCase();
  if (h['cf-ray'] || server.includes('cloudflare')) return 'Cloudflare';
  if (h['x-amz-cf-id'] || via.includes('cloudfront')) return 'CloudFront';
  if (server.includes('akamai') || h['x-akamai-transformed'] || h['akamai-grn']) return 'Akamai';
  if (h['x-served-by'] && /cache/i.test(h['x-served-by']) || server.includes('fastly')) return 'Fastly';
  if (server === 'gws' || server === 'esf' || server.includes('google') || h['x-goog-generation']) return 'Google';
  if (h['x-azure-ref'] || server.includes('azure')) return 'Azure';
  if (h['x-bunny'] || server.includes('bunny')) return 'Bunny';
  if (server.includes('sucuri') || h['x-sucuri-id']) return 'Sucuri';
  if (server.includes('imperva') || h['x-iinfo']) return 'Imperva';
  return null;
}

function parseHttp(head, ms) {
  if (!head) return null;
  const lines = head.split('\r\n');
  const m = /^HTTP\/[\d.]+\s+(\d{3})/.exec(lines[0] || '');
  if (!m) return null;
  const h = {};
  for (const l of lines.slice(1)) {
    const i = l.indexOf(':');
    if (i > 0) h[l.slice(0, i).trim().toLowerCase()] = l.slice(i + 1).trim();
  }
  return { status: +m[1], ms, server: h.server || null, cdn: detectCdn(h), location: h.location || null };
}

async function probeHost(host, opts = {}) {
  const timeout = opts.timeoutMs || 6000;
  const ports = Object.assign({ tls: 443, http: 80 }, opts.ports);
  const res = { host, testedAt: Date.now(), working: false, info: {}, error: null };
  const d = await resolveIps(host, timeout);
  res.info.dnsMs = d.ms;
  if (!d.ips.length) { res.error = 'dns'; return res; }
  const ip = d.ips[0];
  if (!opts.allowPrivate && isPrivateIp(ip)) { res.error = 'private-ip'; return res; }
  res.info.ip = ip;
  res.info.ips = d.ips.slice(0, 4);

  const [t, p80] = await Promise.all([
    tlsConnect(ip, host, ports.tls, timeout, ['h2', 'http/1.1']),
    rawExchange({ ip, port: ports.http, host, secure: false, request: headReq(host), timeout })
  ]);
  res.info.tls = t;
  const h80 = parseHttp(p80.head, p80.ms);
  res.info.port80 = { ok: p80.connected, status: h80 ? h80.status : null, ms: p80.connected ? p80.ms : null, location: h80 ? h80.location : null };
  if (h80 && !res.info.cdn) res.info.cdn = h80.cdn;

  if (t.ok) {
    const hx = await rawExchange({ ip, port: ports.tls, host, secure: true, request: getReq(host), timeout });
    const parsed = parseHttp(hx.head, hx.ms);
    if (parsed) {
      res.info.http = parsed;
      res.info.cdn = parsed.cdn || res.info.cdn || null;
    }
  }
  if (opts.deep) {
    const ws = { tls: null, http: null };
    const jobs = [];
    if (t.ok) jobs.push(rawExchange({ ip, port: ports.tls, host, secure: true, request: wsReq(host), timeout }).then(r => { const p = parseHttp(r.head, r.ms); ws.tls = !!(p && p.status === 101); }));
    if (p80.connected) jobs.push(rawExchange({ ip, port: ports.http, host, secure: false, request: wsReq(host), timeout }).then(r => { const p = parseHttp(r.head, r.ms); ws.http = !!(p && p.status === 101); }));
    await Promise.all(jobs);
    res.info.ws = ws;
  } else if (opts.prevWs) {
    res.info.ws = opts.prevWs;
  }
  res.working = !!(t.ok || p80.connected);
  if (!res.working) res.error = t.error || 'unreachable';
  return res;
}

function scoreOf(info, history) {
  const t = (info && info.tls) || {};
  let s = 0;
  if (t.ok) {
    s += 25;
    s += t.ms <= 150 ? 15 : t.ms <= 300 ? 11 : t.ms <= 600 ? 7 : t.ms <= 1200 ? 3 : 1;
    s += t.version === 'TLSv1.3' ? 10 : 4;
    if (t.alpn === 'h2') s += 5;
    if (t.cert && t.cert.nameMatch && t.cert.daysLeft > 14) s += 5;
  }
  if (info && info.http && info.http.status && info.http.status < 500) s += 10;
  if (info && info.port80 && info.port80.ok) s += 10;
  const h = (history || []).slice(-14);
  s += h.length >= 3 ? Math.round(20 * h.filter(x => x.ok).length / h.length) : 10;
  return Math.max(0, Math.min(100, s));
}

function bandOf(score) {
  return score >= 80 ? 'Excellent' : score >= 60 ? 'Good' : score >= 40 ? 'Fair' : 'Weak';
}

function typesOf(info) {
  const out = [];
  if (info && info.tls && info.tls.ok) out.push('sni');
  if (info && info.port80 && info.port80.ok) out.push('payload');
  if (info && info.ws && (info.ws.tls || info.ws.http)) out.push('ws');
  return out;
}

// Which tunnelling modes this host is suited to, and why.
function protocolsOf(info) {
  const out = [];
  const t = (info && info.tls) || {};
  if (t.ok) {
    out.push({ id: 'sni-ssl', label: 'SSL/TLS + SNI', apps: 'HTTP Injector (SSL), HA Tunnel, stunnel, Napster', why: 'TLS handshake succeeds with this name as SNI' });
    out.push({ id: 'xray-tls', label: 'VLESS / VMess / Trojan over TLS', apps: 'v2rayNG, Hiddify, NekoBox', why: `${t.version || 'TLS'} accepted on 443` });
    if (info.ws && info.ws.tls) out.push({ id: 'ws-tls', label: 'WebSocket + TLS', apps: 'v2rayNG, HTTP Injector, SSH-WS', why: 'WebSocket upgrade answered 101 on 443' });
    if (t.alpn === 'h2') out.push({ id: 'grpc', label: 'gRPC / HTTP2 transports', apps: 'v2rayNG, Xray', why: 'Server negotiated h2 via ALPN' });
    if (t.version === 'TLSv1.3' && t.alpn === 'h2' && t.cert && t.cert.nameMatch) out.push({ id: 'reality', label: 'XTLS-Reality target (dest/SNI)', apps: 'Xray, sing-box', why: 'TLS 1.3 + h2 + matching certificate' });
  }
  if (info && info.port80 && info.port80.ok) {
    out.push({ id: 'http-payload', label: 'HTTP payload (Host injection)', apps: 'HTTP Injector, HTTP Custom, KPN Tunnel', why: 'Port 80 accepts connections' });
    if (info.ws && info.ws.http) out.push({ id: 'ws-http', label: 'WebSocket over HTTP', apps: 'HTTP Injector, SSH-WS', why: 'WebSocket upgrade answered 101 on 80' });
  }
  return out;
}

// Grab certificate names from an IP without SNI (used by the CIDR scanner).
function grabCert(ip, port, timeout) {
  return new Promise(resolve => {
    let done = false;
    let sock;
    const finish = r => { if (done) return; done = true; try { sock && sock.destroy(); } catch (_) { /* noop */ } resolve(r); };
    try {
      sock = tls.connect({ host: ip, port, servername: '', rejectUnauthorized: false }, () => {
        const c = sock.getPeerCertificate() || {};
        const names = new Set();
        if (c.subject && c.subject.CN) names.add(c.subject.CN);
        (c.subjectaltname || '').split(', ').forEach(s => names.add(s.replace(/^DNS:/, '')));
        finish({ ok: true, names: [...names].filter(Boolean) });
      });
      sock.setTimeout(timeout, () => finish({ ok: false }));
      sock.on('error', () => finish({ ok: false }));
    } catch (_) { finish({ ok: false }); }
  });
}

module.exports = { cleanHost, isPrivateIp, resolveIps, tlsConnect, rawExchange, probeHost, scoreOf, bandOf, typesOf, protocolsOf, grabCert, parseHttp };
