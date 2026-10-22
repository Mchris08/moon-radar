'use strict';
// Parse vless:// vmess:// trojan:// share links and convert them to other client formats.

const clean = o => {
  if (Array.isArray(o)) return o.map(clean);
  if (o && typeof o === 'object') {
    const r = {};
    for (const [k, v] of Object.entries(o)) {
      if (v === undefined || v === null || v === '' || (Array.isArray(v) && !v.length)) continue;
      const c = clean(v);
      if (c && typeof c === 'object' && !Array.isArray(c) && !Object.keys(c).length) continue;
      r[k] = c;
    }
    return r;
  }
  return o;
};
const list = s => String(s || '').split(',').map(x => x.trim()).filter(Boolean);
const b64decode = s => Buffer.from(String(s).replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');

function norm(o) {
  const n = Object.assign({ network: 'tcp', security: 'none', headerType: '', encryption: 'none' }, o);
  n.name = n.name || 'Moon-Radar';
  n.network = n.network === 'http' ? 'h2' : n.network;
  if (!n.server || !n.port) throw new Error('The link has no server or port');
  return n;
}

function parseLink(link) {
  link = String(link || '').trim();
  const m = /^(vless|vmess|trojan):\/\//i.exec(link);
  if (!m) throw new Error('Paste a vless://, vmess:// or trojan:// link');
  const protocol = m[1].toLowerCase();
  if (protocol === 'vmess') {
    let j;
    try { j = JSON.parse(b64decode(link.slice(8).trim())); } catch (_) { throw new Error('This vmess link is not valid base64 JSON'); }
    return norm({ protocol, name: j.ps, server: j.add, port: +j.port, id: j.id, aid: +j.aid || 0, scy: j.scy || 'auto', network: j.net || 'tcp', headerType: j.type === 'none' ? '' : j.type, host: j.host, path: j.path, security: j.tls === 'tls' ? 'tls' : 'none', sni: j.sni, alpn: j.alpn, fp: j.fp });
  }
  let u;
  try { u = new URL(link); } catch (_) { throw new Error('This link is not formatted correctly'); }
  const q = u.searchParams;
  const user = decodeURIComponent(u.username || '');
  if (!user) throw new Error(protocol === 'vless' ? 'The link has no UUID' : 'The link has no password');
  return norm({
    protocol, name: decodeURIComponent((u.hash || '').slice(1)), server: u.hostname.replace(/^\[|\]$/g, ''), port: +u.port || 443,
    id: protocol === 'vless' ? user : undefined, password: protocol === 'trojan' ? user : undefined,
    encryption: q.get('encryption') || 'none', flow: q.get('flow') || '', network: q.get('type') || 'tcp',
    security: q.get('security') || (protocol === 'trojan' ? 'tls' : 'none'), sni: q.get('sni') || q.get('peer') || '',
    host: q.get('host') || '', path: q.get('path') || '', alpn: q.get('alpn') || '', fp: q.get('fp') || '',
    serviceName: q.get('serviceName') || '', headerType: q.get('headerType') || '', pbk: q.get('pbk') || '', sid: q.get('sid') || '', spx: q.get('spx') || ''
  });
}

function applyOverrides(n, o = {}) {
  const r = Object.assign({}, n);
  const bug = String(o.bug || '').trim();
  if (bug) { r.sni = bug; r.host = bug; if (r.security === 'none' && r.protocol !== 'vmess') r.security = 'tls'; }
  if (o.sni) r.sni = String(o.sni).trim();
  if (o.host) r.host = String(o.host).trim();
  if (o.server) r.server = String(o.server).trim();
  if (+o.port > 0 && +o.port < 65536) r.port = +o.port;
  if (o.path) r.path = String(o.path).trim();
  if (o.name) r.name = String(o.name).trim();
  return r;
}

function toLink(n) {
  if (n.protocol === 'vmess') {
    const j = { v: '2', ps: n.name, add: n.server, port: String(n.port), id: n.id, aid: String(n.aid || 0), scy: n.scy || 'auto', net: n.network, type: n.headerType || 'none', host: n.host || '', path: n.path || '', tls: n.security === 'tls' ? 'tls' : '', sni: n.sni || '', alpn: n.alpn || '', fp: n.fp || '' };
    return 'vmess://' + Buffer.from(JSON.stringify(j)).toString('base64');
  }
  const p = new URLSearchParams();
  const add = (k, v) => { if (v) p.set(k, v); };
  if (n.protocol === 'vless') p.set('encryption', n.encryption || 'none');
  add('security', n.security);
  add('sni', n.sni); add('fp', n.fp); add('alpn', n.alpn);
  p.set('type', n.network);
  add('host', n.host); add('path', n.path); add('serviceName', n.serviceName);
  add('flow', n.flow); add('headerType', n.headerType);
  add('pbk', n.pbk); add('sid', n.sid); add('spx', n.spx);
  const server = n.server.includes(':') ? `[${n.server}]` : n.server;
  const cred = encodeURIComponent(n.protocol === 'vless' ? n.id : n.password);
  return `${n.protocol}://${cred}@${server}:${n.port}?${p.toString()}#${encodeURIComponent(n.name)}`;
}

function toXray(n) {
  const stream = { network: n.network, security: n.security === 'none' ? undefined : n.security };
  const h = n.host ? [n.host] : undefined;
  if (n.network === 'ws') stream.wsSettings = { path: n.path || '/', headers: n.host ? { Host: n.host } : undefined };
  else if (n.network === 'grpc') stream.grpcSettings = { serviceName: n.serviceName || n.path };
  else if (n.network === 'h2') stream.httpSettings = { path: n.path || '/', host: h };
  else if (n.network === 'httpupgrade') stream.httpupgradeSettings = { path: n.path || '/', host: n.host };
  else if (n.network === 'xhttp' || n.network === 'splithttp') stream.xhttpSettings = { path: n.path || '/', host: n.host };
  else if (n.network === 'tcp' && n.headerType === 'http') stream.tcpSettings = { header: { type: 'http', request: { path: [n.path || '/'], headers: n.host ? { Host: [n.host] } : undefined } } };
  if (n.security === 'tls') stream.tlsSettings = { serverName: n.sni || n.host || n.server, fingerprint: n.fp, alpn: list(n.alpn) };
  if (n.security === 'reality') stream.realitySettings = { serverName: n.sni, fingerprint: n.fp || 'chrome', publicKey: n.pbk, shortId: n.sid, spiderX: n.spx };
  let settings;
  if (n.protocol === 'vless') settings = { vnext: [{ address: n.server, port: n.port, users: [{ id: n.id, encryption: n.encryption || 'none', flow: n.flow }] }] };
  else if (n.protocol === 'vmess') settings = { vnext: [{ address: n.server, port: n.port, users: [{ id: n.id, alterId: n.aid || 0, security: n.scy || 'auto' }] }] };
  else settings = { servers: [{ address: n.server, port: n.port, password: n.password }] };
  return JSON.stringify({ outbounds: [clean({ tag: 'proxy', protocol: n.protocol, settings, streamSettings: stream })] }, null, 2);
}

function toSingbox(n) {
  const ob = { type: n.protocol, tag: 'proxy', server: n.server, server_port: n.port };
  if (n.protocol === 'vless') { ob.uuid = n.id; ob.flow = n.flow; }
  if (n.protocol === 'vmess') { ob.uuid = n.id; ob.security = n.scy || 'auto'; ob.alter_id = n.aid || 0; }
  if (n.protocol === 'trojan') ob.password = n.password;
  if (n.security !== 'none') {
    ob.tls = { enabled: true, server_name: n.sni || n.host || n.server, alpn: list(n.alpn), utls: n.fp ? { enabled: true, fingerprint: n.fp } : undefined };
    if (n.security === 'reality') { ob.tls.utls = { enabled: true, fingerprint: n.fp || 'chrome' }; ob.tls.reality = { enabled: true, public_key: n.pbk, short_id: n.sid }; }
  }
  if (n.network === 'ws') ob.transport = { type: 'ws', path: n.path || '/', headers: n.host ? { Host: n.host } : undefined };
  else if (n.network === 'grpc') ob.transport = { type: 'grpc', service_name: n.serviceName || n.path };
  else if (n.network === 'h2') ob.transport = { type: 'http', host: n.host ? [n.host] : undefined, path: n.path || '/' };
  else if (n.network === 'httpupgrade') ob.transport = { type: 'httpupgrade', host: n.host, path: n.path || '/' };
  return JSON.stringify({ outbounds: [clean(ob)] }, null, 2);
}

function toClash(n) {
  const q = v => JSON.stringify(String(v));
  const L = ['proxies:', `  - name: ${q(n.name)}`, `    type: ${n.protocol}`, `    server: ${q(n.server)}`, `    port: ${n.port}`];
  if (n.protocol === 'vless') { L.push(`    uuid: ${q(n.id)}`); if (n.flow) L.push(`    flow: ${q(n.flow)}`); }
  if (n.protocol === 'vmess') { L.push(`    uuid: ${q(n.id)}`, `    alterId: ${n.aid || 0}`, `    cipher: ${q(n.scy || 'auto')}`); }
  if (n.protocol === 'trojan') L.push(`    password: ${q(n.password)}`);
  L.push('    udp: true');
  if (n.protocol !== 'trojan') L.push(`    network: ${n.network === 'h2' ? 'h2' : n.network}`);
  else if (n.network !== 'tcp') L.push(`    network: ${n.network}`);
  if (n.security !== 'none') {
    L.push('    tls: true');
    L.push(`    ${n.protocol === 'trojan' ? 'sni' : 'servername'}: ${q(n.sni || n.host || n.server)}`);
    if (n.fp) L.push(`    client-fingerprint: ${q(n.fp)}`);
    if (n.alpn) L.push('    alpn:', ...list(n.alpn).map(a => `      - ${q(a)}`));
  }
  if (n.security === 'reality') L.push('    reality-opts:', `      public-key: ${q(n.pbk)}`, `      short-id: ${q(n.sid || '')}`);
  if (n.network === 'ws') { L.push('    ws-opts:', `      path: ${q(n.path || '/')}`); if (n.host) L.push('      headers:', `        Host: ${q(n.host)}`); }
  if (n.network === 'grpc') L.push('    grpc-opts:', `      grpc-service-name: ${q(n.serviceName || n.path || '')}`);
  if (n.network === 'h2') { L.push('    h2-opts:', `      path: ${q(n.path || '/')}`); if (n.host) L.push('      host:', `        - ${q(n.host)}`); }
  return L.join('\n');
}

function convert(link, overrides) {
  const parsed = parseLink(link);
  const n = applyOverrides(parsed, overrides);
  const warnings = [];
  if (n.security === 'none' && n.protocol !== 'trojan') warnings.push('This link has no TLS. An SNI bug host only works with TLS (security=tls).');
  if (n.network === 'tcp' && !n.headerType && n.host) warnings.push('A Host value is set but the transport is plain TCP, so it is ignored. Use ws, httpupgrade or h2 to send a Host header.');
  const summary = { protocol: n.protocol, name: n.name, server: n.server, port: n.port, network: n.network, security: n.security, sni: n.sni || null, host: n.host || null, path: n.path || null, fingerprint: n.fp || null, alpn: n.alpn || null };
  return { summary, warnings, link: toLink(n), xray: toXray(n), singbox: toSingbox(n), clash: toClash(n) };
}

module.exports = { parseLink, applyOverrides, toLink, toXray, toSingbox, toClash, convert };
