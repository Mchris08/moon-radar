'use strict';
// "Cloud configs": a share link that serves your VPN config until a timer runs out.
const crypto = require('crypto');
const convert = require('./convert');
const probe = require('./probe');

const MIN_MIN = 5;                 // 5 minutes
const MAX_MIN = 365 * 24 * 60;     // 365 days
const UNITS = { minute: 1, minutes: 1, hour: 60, hours: 60, day: 1440, days: 1440 };
const LINK_RE = /^(vless|vmess|trojan):\/\//i;

const cleanText = (s, max) => String(s == null ? '' : s).replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, max);

function minutesFrom(input) {
  const m = input.minutes != null ? Number(input.minutes) : Number(input.value) * (UNITS[String(input.unit || 'days').toLowerCase()] || NaN);
  if (!Number.isFinite(m) || m <= 0) throw new Error('Enter how long the config should last');
  const r = Math.round(m);
  if (r < MIN_MIN) throw new Error('The shortest duration is 5 minutes');
  if (r > MAX_MIN) throw new Error('The longest duration is 365 days');
  return r;
}

function parseSsh(s) {
  if (!s || typeof s !== 'object' || !(s.host || s.user || s.password)) return null;
  const host = /^[\d.]+$/.test(String(s.host || '').trim()) ? String(s.host).trim() : probe.cleanHost(s.host);
  if (!host) throw new Error('The SSH server must be a host name or IP address');
  const user = cleanText(s.user, 100);
  if (!user) throw new Error('The SSH profile needs a username');
  const port = parseInt(s.port, 10);
  if (s.port && !(port > 0 && port < 65536)) throw new Error('The SSH port must be 1 to 65535');
  const sni = s.sni ? probe.cleanHost(s.sni) : null;
  if (s.sni && !sni) throw new Error('The SNI must be a valid host name');
  return { host, port: port || 443, user, password: cleanText(s.password, 100), sni: sni || '', payload: cleanText(s.payload, 1000), note: cleanText(s.note, 200) };
}

function create(input, now = Date.now()) {
  const links = [...new Set(String(input.links || '').split(/\s+/).filter(Boolean))];
  if (links.length > 50) throw new Error('Use at most 50 links per cloud config');
  links.forEach((l, i) => {
    if (!LINK_RE.test(l)) throw new Error(`Item ${i + 1} is not a vless://, vmess:// or trojan:// link`);
    try { convert.parseLink(l); } catch (e) { throw new Error(`Link ${i + 1}: ${e.message}`); }
  });
  const ssh = parseSsh(input.ssh);
  if (!links.length && !ssh) throw new Error('Add at least one link or an SSH profile');
  const durationMin = minutesFrom(input.duration || {});
  let maxOpens = null;
  if (input.maxOpens !== undefined && input.maxOpens !== null && input.maxOpens !== '') {
    maxOpens = parseInt(input.maxOpens, 10);
    if (!(maxOpens >= 1 && maxOpens <= 100000)) throw new Error('The open limit must be 1 to 100000');
  }
  const startOnFirstUse = !!input.startOnFirstUse;
  return {
    token: crypto.randomBytes(18).toString('base64url'),
    name: cleanText(input.name, 60) || 'Moon Radar config',
    createdAt: now, durationMin, startOnFirstUse,
    expiresAt: startOnFirstUse ? null : now + durationMin * 60000,
    maxOpens, opens: 0, revoked: false, links, ssh
  };
}

function status(c, now = Date.now()) {
  if (c.revoked) return 'revoked';
  if (c.expiresAt && now >= c.expiresAt) return 'expired';
  if (c.maxOpens && c.opens >= c.maxOpens) return 'used up';
  if (!c.expiresAt) return 'waiting';
  return 'active';
}

function activate(c, now = Date.now()) { if (!c.expiresAt) c.expiresAt = now + c.durationMin * 60000; }

function summary(c, now = Date.now()) {
  return { token: c.token, name: c.name, status: status(c, now), createdAt: c.createdAt, expiresAt: c.expiresAt, durationMin: c.durationMin, startOnFirstUse: c.startOnFirstUse, opens: c.opens, maxOpens: c.maxOpens, links: c.links.length, ssh: !!c.ssh };
}

function sshText(c) {
  const s = c.ssh;
  const lines = [`Moon Radar config: ${c.name}`, 'Type: SSH', `Server: ${s.host}`, `Port: ${s.port}`, `Username: ${s.user}`];
  if (s.password) lines.push(`Password: ${s.password}`);
  if (s.sni) lines.push(`SNI: ${s.sni}`);
  if (s.payload) lines.push(`Payload: ${s.payload}`);
  if (s.note) lines.push(`Note: ${s.note}`);
  if (c.expiresAt) lines.push(`Expires: ${new Date(c.expiresAt).toISOString()}`);
  return lines.join('\n');
}

/** What an app gets when it fetches the link. Returns { type, body } or { error }. */
function render(c, fmt) {
  fmt = String(fmt || '').toLowerCase();
  const hasLinks = c.links.length > 0;
  if (hasLinks && ['', 'sub', 'raw', 'clash', 'singbox', 'xray'].includes(fmt)) {
    const b = convert.bundle(c.links);
    if (fmt === '' || fmt === 'sub') return { type: 'text/plain; charset=utf-8', body: b.sub };
    if (fmt === 'raw') return { type: 'text/plain; charset=utf-8', body: b.raw };
    if (fmt === 'clash') return { type: 'text/yaml; charset=utf-8', body: b.clash };
    if (fmt === 'singbox') return { type: 'application/json; charset=utf-8', body: b.singbox };
    return { type: 'application/json; charset=utf-8', body: b.xray };
  }
  if (c.ssh && (fmt === '' || fmt === 'ssh' || fmt === 'text')) return { type: 'text/plain; charset=utf-8', body: sshText(c) };
  if (c.ssh && fmt === 'json') return { type: 'application/json; charset=utf-8', body: JSON.stringify({ name: c.name, type: 'ssh', server: c.ssh.host, port: c.ssh.port, username: c.ssh.user, password: c.ssh.password, sni: c.ssh.sni, payload: c.ssh.payload, expires: c.expiresAt ? new Date(c.expiresAt).toISOString() : null }, null, 2) };
  return { error: 'That format is not available for this config' };
}

function headers(c) {
  const h = { 'Cache-Control': 'no-store', 'Profile-Update-Interval': '6' };
  if (c.expiresAt) h['Subscription-Userinfo'] = `upload=0; download=0; total=0; expire=${Math.floor(c.expiresAt / 1000)}`;
  return h;
}

const esc = s => String(s).replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));

/** A readable page for people who open the link in a browser. Opening it does not use up the config. */
function card(c, now = Date.now()) {
  const st = status(c, now);
  const blocks = [];
  if (c.links.length) {
    blocks.push(['Subscription link', 'Add this page address as a subscription URL in v2rayNG, NekoBox, Hiddify and similar apps.', '__URL__']);
    c.links.forEach((l, i) => blocks.push([`Link ${i + 1}`, '', l]));
  }
  if (c.ssh) blocks.push(['SSH settings', 'Enter these in your SSH tunnel app.', sshText(c)]);
  const when = c.expiresAt ? `<p>Expires <b id="when" data-t="${c.expiresAt}"></b></p>` : `<p>The timer (${Math.round(c.durationMin / 60 * 10) / 10} hours) starts when an app first opens this link.</p>`;
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>${esc(c.name)}</title>
<style>body{font:16px/1.5 system-ui,sans-serif;margin:0;background:#E9EEF0;color:#0C2A3B}main{max-width:680px;margin:0 auto;padding:18px}h1{font-size:22px;margin:0 0 6px}.box{background:#fff;border:1px solid #CBD6DB;border-radius:10px;padding:14px;margin:12px 0}pre{white-space:pre-wrap;word-break:break-all;background:#F3F6F7;border:1px solid #CBD6DB;border-radius:8px;padding:10px;font:13px/1.5 ui-monospace,monospace}button{font:inherit;font-weight:600;border:1px solid #CBD6DB;background:#fff;border-radius:8px;padding:6px 12px;cursor:pointer}small{color:#587080}.tag{display:inline-block;border:1px solid #12A150;color:#12A150;border-radius:6px;padding:0 8px;font-weight:600}</style></head><body><main>
<h1>${esc(c.name)}</h1><span class="tag">${esc(st)}</span>${when}
${blocks.map(([t, d, v], i) => `<div class="box"><b>${esc(t)}</b>${d ? `<br><small>${esc(d)}</small>` : ''}<pre id="b${i}" data-url="${v === '__URL__' ? 1 : 0}">${v === '__URL__' ? '' : esc(v)}</pre><button onclick="cp(${i})">Copy</button></div>`).join('')}
<small>Hosted by Moon Radar. Keep this link private.</small></main>
<script>var base=location.href.split('?')[0];document.querySelectorAll('pre[data-url="1"]').forEach(function(p){p.textContent=base});
function cp(i){var t=document.getElementById('b'+i).textContent;if(navigator.clipboard){navigator.clipboard.writeText(t)}else{var a=document.createElement('textarea');a.value=t;document.body.appendChild(a);a.select();document.execCommand('copy');a.remove()}}
var w=document.getElementById('when');if(w){var t=+w.dataset.t;(function tick(){var ms=t-Date.now();if(ms<=0){w.textContent='now (expired)';return}var d=Math.floor(ms/864e5),h=Math.floor(ms%864e5/36e5),m=Math.floor(ms%36e5/6e4);w.textContent=new Date(t).toLocaleString()+' ('+(d?d+'d ':'')+(h||d?h+'h ':'')+m+'m left)';setTimeout(tick,30000)})()}</script></body></html>`;
}

module.exports = { create, status, activate, summary, render, headers, card, minutesFrom, MAX_MIN };
