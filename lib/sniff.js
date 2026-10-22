'use strict';
// Pulls SNI, Host header, server and payload host names out of VPN config text.
// Reads plain text only. Locked or encrypted config files are reported, not opened.
const net = require('net');
const probe = require('./probe');
const convert = require('./convert');

const R = { SNI: 'SNI', HOST: 'Host header', REQ: 'Request host', REF: 'Referer', AUTH: 'Authority host', SERVER: 'Server', PROXY: 'Proxy', ENDPOINT: 'Endpoint', CERT: 'Certificate name', URL: 'URL', MENTION: 'Mentioned' };
const BUG = new Set([R.SNI, R.HOST, R.REQ, R.REF, R.AUTH]);
const ORDER = [R.SNI, R.HOST, R.AUTH, R.REQ, R.REF, R.SERVER, R.ENDPOINT, R.PROXY, R.CERT, R.URL, R.MENTION];
const NOISE_TLD = new Set('json yaml yml conf txt ovpn js css html htm png jpg jpeg gif svg ico md xml log key crt pem cer pfx p12 ini cfg sh py exe apk zip gz tar bin dat db so dll ts map woff woff2 ttf'.split(' '));
const SNI_KEYS = new Set(['servername', 'server_name', 'sni', 'peer', 'tls-server-name']);
const HOST_KEYS = new Set(['host', 'authority']);
const SERVER_KEYS = new Set(['address', 'server', 'add', 'endpoint', 'remote']);

function looksBinary(text) {
  const s = String(text || '').slice(0, 4000);
  if (!s) return false;
  let bad = 0;
  for (let i = 0; i < s.length; i++) { const c = s.charCodeAt(i); if (c === 0xfffd || c < 9 || (c > 13 && c < 32)) bad++; }
  return bad / s.length > 0.05;
}

function extract(text, depth = 0) {
  const hosts = new Map();   // name -> Set(roles)
  const ips = new Map();     // ip -> Set(roles)
  const formats = new Set();
  const notes = [];

  const add = (raw, role, allowNoise = true) => {
    raw = String(raw || '').trim();
    if (!raw || /[\[\]{}$<>*]/.test(raw.replace(/^\[([0-9a-f:]+)\]/i, '$1'))) return;
    let h = raw.replace(/^https?:\/\//i, '').split(/[\/?#]/)[0];
    const v6 = /^\[([0-9a-f:]+)\](?::\d+)?$/i.exec(h);
    if (v6) h = v6[1]; else if (h.split(':').length === 2) h = h.split(':')[0];
    h = h.replace(/\.$/, '').toLowerCase();
    if (net.isIP(h)) { if (!ips.has(h)) ips.set(h, new Set()); ips.get(h).add(role); return; }
    const c = probe.cleanHost(h);
    if (!c) return;
    if (!allowNoise && NOISE_TLD.has(c.split('.').pop())) return;
    if (NOISE_TLD.has(c.split('.').pop()) && ![R.SNI, R.HOST, R.SERVER, R.AUTH].includes(role)) return;
    if (!hosts.has(c)) hosts.set(c, new Set());
    hosts.get(c).add(role);
  };
  const each = (re, fn) => { re.lastIndex = 0; let m; while ((m = re.exec(text))) { fn(m); if (m[0] === '') re.lastIndex++; } };

  // 1. share links
  const links = text.match(/(?:vless|vmess|trojan|ss):\/\/[^\s"'<>`]+/gi) || [];
  if (links.length) formats.add('Share links');
  for (const l of links) {
    try {
      if (/^ss:/i.test(l)) {
        const u = new URL(l);
        if (u.hostname) add(u.hostname, R.SERVER);
        const plugin = decodeURIComponent(u.searchParams.get('plugin') || '');
        const hm = /host=([^;]+)/.exec(plugin); if (hm) add(hm[1], R.HOST);
        const sm = /sni=([^;]+)/.exec(plugin); if (sm) add(sm[1], R.SNI);
      } else {
        const n = convert.parseLink(l);
        add(n.server, R.SERVER); if (n.sni) add(n.sni, R.SNI); if (n.host) n.host.split(',').forEach(x => add(x, R.HOST));
      }
    } catch (_) { /* skip unreadable link */ }
  }

  // 2. JSON (Xray, V2Ray, sing-box, vmess JSON)
  let json = null;
  try { const t = text.trim(); if (t.startsWith('{') || t.startsWith('[')) json = JSON.parse(t); } catch (_) { /* not json */ }
  if (json) {
    formats.add('JSON config');
    const walk = (o, key) => {
      if (Array.isArray(o)) return o.forEach(x => walk(x, key));
      if (o && typeof o === 'object') return Object.entries(o).forEach(([k, v]) => walk(v, k));
      if (typeof o !== 'string') return;
      const k = String(key || '').toLowerCase();
      if (SNI_KEYS.has(k)) add(o, R.SNI);
      else if (HOST_KEYS.has(k)) o.split(',').forEach(x => add(x, R.HOST));
      else if (SERVER_KEYS.has(k)) add(o, R.SERVER);
    };
    walk(json);
  }

  // 3. line and pattern passes (YAML, OpenVPN, WireGuard, stunnel, payload text)
  each(/(?:^|[\s,{"'])(?:sni|servername|server_name|peer|tls-server-name)["']?\s*[:=]\s*["']?([a-z0-9._-]+\.[a-z]{2,})/gim, m => add(m[1], R.SNI));
  each(/(?:^|[\s,{"'-])(?:server|endpoint|connect)["']?\s*[:=]\s*["']?(\[?[a-z0-9._:-]+\]?)/gim, m => add(m[1], /endpoint/i.test(m[0]) ? R.ENDPOINT : R.SERVER));
  each(/^\s*remote\s+([a-z0-9._-]+)\s+\d+/gim, m => { add(m[1], R.SERVER); formats.add('OpenVPN'); });
  each(/^\s*http-proxy\s+([a-z0-9._-]+)\s+\d+/gim, m => add(m[1], R.PROXY));
  each(/CUSTOM-HEADER\s+Host\s+([^\s"']+)/gi, m => add(m[1], R.HOST));
  each(/^\s*verify-x509-name\s+"?([a-z0-9._-]+)/gim, m => add(m[1], R.CERT));
  each(/(?:^|[\s\\\]"',{])(?:x-online-host|x-forward-host|host)["']?\s*:\s*["']?([^\s\[\]\\"',]+)/gi, m => add(m[1], R.HOST));
  each(/\b(?:GET|POST|HEAD|PUT|CONNECT|OPTIONS)\s+(?:https?:\/\/)?([a-z0-9.-]+\.[a-z]{2,})(?::\d+)?(?=[\/\s\[\\])/gi, m => add(m[1], R.REQ));
  each(/referer["']?\s*:\s*["']?https?:\/\/([a-z0-9.-]+)/gi, m => add(m[1], R.REF));
  each(/\[host_port\]@([a-z0-9.-]+\.[a-z]{2,})/gi, m => add(m[1], R.AUTH));
  each(/https?:\/\/([a-z0-9.-]+\.[a-z]{2,})/gi, m => add(m[1], R.URL, false));

  if (/^\s*\[Interface\]/im.test(text) || /^\s*Endpoint\s*=/im.test(text)) formats.add('WireGuard');
  if (/^\s*proxies\s*:/im.test(text)) formats.add('Clash YAML');
  if (/\[crlf\]|\[lf\]|\bHTTP\/1\.[01]\b/i.test(text)) formats.add('Payload text');
  if (/^\s*client\s*$/im.test(text) || /^\s*dev\s+tun/im.test(text)) formats.add('OpenVPN');
  if (/^\s*\[[a-z0-9_-]+\]\s*$/im.test(text) && /^\s*accept\s*=/im.test(text)) formats.add('stunnel');

  // 4. fallback: any other domain-looking name
  each(/\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})\b/gi, m => {
    const h = m[1].toLowerCase();
    if (!hosts.has(h)) add(h, R.MENTION, false);
  });

  // 5. base64 subscription (a list of links, base64 encoded)
  if (!links.length && !json && depth === 0 && /^[A-Za-z0-9+/=_-]{40,}$/.test(text.trim())) {
    try {
      const dec = Buffer.from(text.trim().replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
      if (/(vless|vmess|trojan|ss):\/\//i.test(dec)) { const r = extract(dec, 1); r.notes.unshift('Decoded a base64 subscription'); return r; }
    } catch (_) { /* not base64 */ }
  }

  const rank = roles => Math.min(...[...roles].map(r => ORDER.indexOf(r)));
  const list = [...hosts.entries()].map(([host, roles]) => ({ host, roles: ORDER.filter(r => roles.has(r)), bug: [...roles].some(r => BUG.has(r)) }))
    .sort((a, b) => (b.bug - a.bug) || (rank(new Set(a.roles)) - rank(new Set(b.roles))) || a.host.localeCompare(b.host)).slice(0, 300);
  const ipList = [...ips.entries()].map(([ip, roles]) => ({ ip, roles: ORDER.filter(r => roles.has(r)) }));
  if (list.length && !list.some(h => h.bug)) notes.push('This config only has server addresses. No SNI or Host names to test.');
  if (!list.length && !ipList.length) notes.push('No host names found. If this is an app export (.ehi, .hc, .npv and similar), it is probably locked.');
  return { formats: [...formats], hosts: list, ips: ipList, bugHosts: list.filter(h => h.bug).map(h => h.host), notes };
}

function sniff(text) {
  text = String(text || '');
  if (!text.trim()) throw new Error('Paste a config or choose a file');
  if (text.length > 500000) throw new Error('That is too big. The limit is 500 KB.');
  if (looksBinary(text)) return { binary: true, formats: [], hosts: [], ips: [], bugHosts: [], notes: ['This file looks encrypted or binary. Apps such as HTTP Injector, HTTP Custom and NapsternetV lock exported configs on purpose, and Moon Radar does not try to open them. Ask for an unlocked export, or copy the payload and SNI from the app screen and paste that.'] };
  return extract(text);
}

module.exports = { sniff, extract, looksBinary, ROLES: R };
