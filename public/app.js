'use strict';
/* Moon Radar front end. No build step, no dependencies. */
const $ = s => document.querySelector(s);
const app = $('#app');
const ADMIN = !!document.querySelector('meta[name=radar-admin]');
const state = { meta: null, filters: { country: null, carrier: '', type: '', sort: 'score', q: '' }, token: localStorage.getItem('radar_token') || '', toolsTab: 'sni', adminTab: 'review', jobTimer: null };

function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'value') el.value = v;
    else if (v === true) el.setAttribute(k, '');
    else el.setAttribute(k, v);
  }
  for (const kid of kids.flat(Infinity)) if (kid != null && kid !== false) el.append(kid.nodeType ? kid : document.createTextNode(kid));
  return el;
}
const clear = el => { while (el.firstChild) el.removeChild(el.firstChild); return el; };

async function api(path, opts = {}) {
  const headers = { 'Content-Type': 'application/json', 'x-admin-path': location.pathname.replace(/\/+$/, '') };
  if (state.token) headers.Authorization = 'Bearer ' + state.token;
  const r = await fetch('/api' + path, { method: opts.method || 'GET', headers, body: opts.body ? JSON.stringify(opts.body) : undefined });
  const ct = r.headers.get('content-type') || '';
  const data = ct.includes('json') ? await r.json() : await r.text();
  if (r.status === 401 && path.startsWith('/admin') && !path.endsWith('/login')) { state.token = ''; localStorage.removeItem('radar_token'); route(); }
  if (!r.ok) throw new Error(data.error || 'Request failed');
  return data;
}

function toast(msg) { const t = h('div', { class: 'toast' }, msg); document.body.append(t); setTimeout(() => t.remove(), 1800); }
async function copy(text) { try { await navigator.clipboard.writeText(text); } catch (_) { const t = h('textarea'); t.value = text; document.body.append(t); t.select(); document.execCommand('copy'); t.remove(); } toast('Copied'); }

const flag = c => c && c.length === 2 ? String.fromCodePoint(...[...c.toUpperCase()].map(x => 127397 + x.charCodeAt(0))) : '\u{1F310}';
function ago(t) {
  if (!t) return 'never';
  const s = Math.floor((Date.now() - t) / 1000);
  if (s < 90) return 'just now';
  if (s < 3600) return Math.floor(s / 60) + ' min ago';
  if (s < 86400) return Math.floor(s / 3600) + ' h ago';
  return Math.floor(s / 86400) + ' d ago';
}
// ---------- WhatsApp ----------
const WHATSAPP = [
  { number: '263781929228', label: '+263 78 192 9228' },
  { number: '263717009508', label: '+263 71 700 9508' },
  { number: '263790079259', label: '+263 79 007 9259' }
];
const WA_SVG = size => `<svg width="${size}" height="${size}" viewBox="0 0 32 32" aria-hidden="true"><path d="M16 3C8.8 3 3 8.8 3 16c0 2.5.7 4.8 1.9 6.8L3 29l6.4-1.9A12.9 12.9 0 0 0 16 29c7.2 0 13-5.8 13-13S23.2 3 16 3z" fill="#25D366"/><path d="M21.5 19.4c-.3-.2-1.8-.9-2.1-1s-.5-.1-.7.1-.8 1-1 1.2-.4.2-.7.1a8.5 8.5 0 0 1-4.2-3.7c-.3-.5.3-.5.9-1.6.1-.2.1-.4 0-.5l-1-2.3c-.2-.6-.5-.5-.7-.5h-.6a1.2 1.2 0 0 0-.9.4 3.7 3.7 0 0 0-1.1 2.7 6.4 6.4 0 0 0 1.3 3.4 14.6 14.6 0 0 0 5.6 4.9c2 .9 2.8.9 3.8.8a3.2 3.2 0 0 0 2.1-1.5 2.6 2.6 0 0 0 .2-1.5c-.1-.1-.3-.2-.6-.4z" fill="#fff"/></svg>`;

const waLink = (number, text) => `https://wa.me/${number}?text=${encodeURIComponent(text)}`;
function waIcon(size = 24) { const s = h('span', { 'aria-hidden': 'true', style: 'display:inline-flex' }); s.innerHTML = WA_SVG(size); return s; }
const HELLO = "Hi, I'm a user from Moon Radar. I need help with: ";

/** The WhatsApp message for "suggest or upload working hosts". */
function buildSuggestMessage(f, countries = {}) {
  const hosts = [...new Set(String(f.hosts || '').split(/[\s,;]+/).map(x => x.trim().toLowerCase().replace(/^https?:\/\//, '').split(/[\/:]/)[0]).filter(x => /^[a-z0-9]([a-z0-9._-]*[a-z0-9])?\.[a-z]{2,}$/.test(x)))].slice(0, 40);
  const lines = ["Hi, I'm a user from Moon Radar.", hosts.length > 1 ? 'I want to suggest working hosts.' : 'I want to suggest a working host.'];
  if (f.country) lines.push('Country: ' + (countries[f.country] || f.country));
  if (String(f.carrier || '').trim()) lines.push('Carrier: ' + String(f.carrier).trim().slice(0, 40));
  if (String(f.mode || '').trim()) lines.push('Tested with: ' + String(f.mode).trim().slice(0, 60));
  lines.push('Hosts:', ...hosts.map(x => '- ' + x));
  if (String(f.note || '').trim()) lines.push('Note: ' + String(f.note).trim().slice(0, 200));
  return { text: lines.join('\n'), count: hosts.length };
}

const typeLabel = { sni: 'SNI', payload: 'Payload', ws: 'WebSocket' };
const protoLabel = { 'sni-ssl': 'SSL/SNI', 'xray-tls': 'VLESS/VMess/Trojan', 'ws-tls': 'WS+TLS', grpc: 'gRPC', reality: 'Reality', 'http-payload': 'HTTP payload', 'ws-http': 'WS (HTTP)' };

function bars(score, working = true) {
  const n = working ? Math.max(1, Math.ceil(score / 20)) : 0;
  const cls = score >= 70 ? 's-good' : score >= 45 ? 's-mid' : 's-bad';
  return h('span', { class: 'bars ' + cls, role: 'img', 'aria-label': `Strength ${score} out of 100` }, [1, 2, 3, 4, 5].map(i => h('i', { class: i <= n ? 'on' : '' })));
}

// ---------- host list ----------
function hostItem(x, opts = {}) {
  const c = x.country;
  const meta = [flag(c) + ' ' + (state.meta.countries[c] || c)];
  if (x.carriers.length) meta.push(x.carriers.join(', '));
  if (x.cdn) meta.push(x.cdn);
  if (x.latency != null) meta.push(x.latency + ' ms');
  if (x.tls) meta.push(x.tls.replace('TLSv', 'TLS '));
  if (x.uptime != null) meta.push('up ' + x.uptime + '%');
  meta.push(ago(x.lastTested));
  const chips = [];
  x.types.forEach(t => chips.push(h('span', { class: 'chip' }, typeLabel[t] || t)));
  Object.entries(x.verified || {}).forEach(([k, v]) => v.ok && chips.push(h('span', { class: 'chip ok' }, 'Tested on ' + k)));
  const el = h('div', { class: 'item' + (opts.selected ? ' sel' : ''), tabindex: '0', role: 'button', onclick: e => { if (e.target.classList.contains('pick')) return; openHost(x.host); }, onkeydown: e => { if (e.key === 'Enter') openHost(x.host); } },
    opts.pick ? h('input', { type: 'checkbox', class: 'pick', 'aria-label': 'Select ' + x.host, checked: opts.selected, onchange: e => opts.pick(e.target.checked) }) : bars(x.score, x.working),
    h('div', { class: 'host' }, x.host),
    h('div', { class: 'score', title: x.band }, x.working ? String(x.score) : '0'),
    h('div', { class: 'meta' }, meta.map(m => h('span', null, m))),
    chips.length ? h('div', { class: 'chips' }, chips) : null);
  return el;
}

async function viewHosts() {
  const meta = state.meta;
  const f = state.filters;
  if (f.country === null) f.country = meta.counts.ZW ? 'ZW' : '';
  const wrap = h('div');
  const tabs = h('div', { class: 'tabs', role: 'group', 'aria-label': 'Country' });
  const mk = (code, label, n) => h('button', { class: 'tab', 'aria-pressed': String(f.country === code), onclick: () => { f.country = code; f.carrier = ''; viewHosts(); } }, code === 'ZW' ? h('span', { class: 'zw-stripe' }) : null, label, h('span', { class: 'n' }, String(n)));
  tabs.append(mk('', 'All', meta.total));
  const order = Object.keys(meta.counts).sort((a, b) => (b === 'ZW') - (a === 'ZW') || meta.counts[b] - meta.counts[a]);
  if (!meta.counts.ZW) tabs.append(mk('ZW', 'Zimbabwe', 0));
  order.forEach(c => tabs.append(mk(c, meta.countries[c] || c, meta.counts[c])));
  const carriers = f.country ? (meta.carrierMap[f.country] || []) : Object.keys(meta.carriers);
  const filters = h('div', { class: 'filters' },
    h('input', { class: 'wide', type: 'search', placeholder: 'Search host names', value: f.q, 'aria-label': 'Search', oninput: debounce(e => { f.q = e.target.value; load(); }, 300) }),
    h('select', { 'aria-label': 'Carrier', onchange: e => { f.carrier = e.target.value; load(); } }, h('option', { value: '' }, 'Any carrier'), carriers.map(c => h('option', { value: c, selected: f.carrier === c }, c))),
    h('select', { 'aria-label': 'Type', onchange: e => { f.type = e.target.value; load(); } }, [['', 'Any type'], ['sni', 'SNI (TLS)'], ['payload', 'HTTP payload'], ['ws', 'WebSocket']].map(([v, l]) => h('option', { value: v, selected: f.type === v }, l))),
    h('select', { class: 'wide', 'aria-label': 'Sort', onchange: e => { f.sort = e.target.value; load(); } }, [['score', 'Strongest first'], ['latency', 'Fastest first'], ['new', 'Newest first'], ['name', 'A to Z']].map(([v, l]) => h('option', { value: v, selected: f.sort === v }, l))));
  const list = h('div');
  const foot = h('div', { class: 'row-actions' });
  wrap.append(tabs, filters, list, foot);
  clear(app).append(wrap);
  async function load() {
    const qs = new URLSearchParams({ country: f.country, carrier: f.carrier, type: f.type, sort: f.sort, q: f.q, limit: 150 });
    const d = await api('/hosts?' + qs);
    clear(list);
    if (!d.hosts.length) list.append(h('div', { class: 'ledger' }, h('div', { class: 'empty' }, f.country === 'ZW' ? 'No Zimbabwe hosts are published yet. They appear here after an admin approves them.' : 'No working hosts match these filters yet.')));
    else list.append(h('div', { class: 'ledger' }, d.hosts.map(x => hostItem(x))));
    clear(foot).append(h('span', { class: 'muted small' }, `${d.total} hosts`));
    const q2 = new URLSearchParams({ country: f.country, carrier: f.carrier, type: f.type, q: f.q });
    ['txt', 'csv', 'json'].forEach(fmt => foot.append(h('a', { class: 'btn sm', href: `/api/export?format=${fmt}&${q2}`, download: '' }, 'Export ' + fmt.toUpperCase())));
  }
  load();
}

function debounce(fn, ms) { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; }

// ---------- host detail ----------
function infoBlock(d) {
  const i = d.info || {}, t = i.tls || {}, c = t.cert || {}, ht = i.http || {};
  const rows = [
    ['Strength', `${d.score}/100 (${d.band})`],
    ['IP address', i.ip ? i.ips.join(', ') : 'No DNS answer'],
    ['DNS time', i.dnsMs != null ? i.dnsMs + ' ms' : null],
    ['TLS on 443', t.ok ? `${t.version}, ${t.ms} ms, ${t.cipher || ''}` : 'Failed' + (t.error ? ` (${t.error})` : '')],
    ['HTTP/2 (ALPN)', t.ok ? (t.alpn === 'h2' ? 'Yes' : 'No') : null],
    ['Certificate', t.ok ? `${c.issuer || 'unknown issuer'}${c.daysLeft != null ? ', ' + c.daysLeft + ' days left' : ''}${c.nameMatch ? '' : ', name does not match'}` : null],
    ['HTTPS reply', ht.status ? `${ht.status}${ht.server ? ' from ' + ht.server : ''} in ${ht.ms} ms` : (t.ok ? 'No HTTP reply' : null)],
    ['Port 80', i.port80 ? (i.port80.ok ? 'Open' + (i.port80.status ? ' (' + i.port80.status + ')' : '') : 'Closed') : null],
    ['WebSocket', i.ws ? `443: ${i.ws.tls == null ? 'n/a' : i.ws.tls ? 'yes' : 'no'}, 80: ${i.ws.http == null ? 'n/a' : i.ws.http ? 'yes' : 'no'}` : null],
    ['CDN', i.cdn || 'None detected']
  ].filter(r => r[1] != null);
  return h('dl', { class: 'facts' }, rows.map(([k, v]) => [h('dt', null, k), h('dd', null, v)]));
}
function protoBlock(list) {
  if (!list.length) return h('p', { class: 'muted' }, 'No tunnelling mode is available for this host.');
  return h('div', null, list.map(p => h('div', { class: 'proto' }, h('b', null, p.label), h('span', { class: 'small' }, p.apps), h('div', { class: 'small muted' }, p.why))));
}

async function openHost(host) {
  const dlg = $('#sheet');
  const body = clear($('#sheetBody'));
  body.append(h('p', { class: 'muted' }, 'Loading'));
  dlg.showModal();
  try {
    const d = await api('/hosts/' + encodeURIComponent(host));
    clear(body);
    const phoneRes = h('div', { class: 'small' });
    const hist = h('div', { class: 'hist', 'aria-label': 'Test history' }, d.history.map(x => h('i', { class: x.ok ? 'up' : '', title: new Date(x.t).toLocaleString() })));
    body.append(h('div', null,
      h('div', { class: 'sheet-head' }, h('div', null, h('h3', { class: 'mono' }, d.host), h('div', { class: 'muted small' }, `${flag(d.country)} ${state.meta.countries[d.country] || d.country}${d.carriers.length ? ' · ' + d.carriers.join(', ') : ''}`)), bars(d.score, d.working)),
      d.working ? null : h('div', { class: 'notice' }, 'This host is not responding right now. It is hidden from the public list.'),
      Object.keys(d.verified || {}).length ? h('div', null, Object.entries(d.verified).map(([k, v]) => h('span', { class: 'chip ' + (v.ok ? 'ok' : 'no') }, `${v.ok ? 'Worked' : 'Failed'} on ${k}, ${ago(v.t)}`))) : null,
      infoBlock(d),
      h('h3', null, 'Use it for'), protoBlock(d.protocolDetail || []),
      h('h3', { style: 'margin-top:14px' }, `Last ${d.history.length} tests`), hist,
      d.uptime != null ? h('div', { class: 'small muted' }, `${d.uptime}% of recent tests passed. Last tested ${ago(d.lastTested)}.`) : null,
      h('div', { class: 'row-actions' },
        h('button', { class: 'btn', onclick: () => copy(d.host) }, 'Copy host'),
        h('a', { class: 'btn', href: waLink(WHATSAPP[0].number, `Hi, I'm a user from Moon Radar.\nAbout this host: ${d.host}\nOn my connection it is (working / not working).\nCarrier: `), target: '_blank', rel: 'noopener' }, 'Report on WhatsApp'),
        h('button', { class: 'btn', onclick: async e => { const b = e.target; b.disabled = true; b.textContent = 'Testing'; const r = await phoneTest(d.host); b.disabled = false; b.textContent = 'Test on my connection'; clear(phoneRes).append(h('span', { class: r.ok ? 'ok-msg' : 'err' }, r.ok ? `Reached from this phone in ${r.ms} ms` : r.timeout ? 'No answer from this phone. Likely blocked on this connection.' : 'Could not connect from this phone.')); } }, 'Test on my connection'),
        h('button', { class: 'btn primary', onclick: () => { dlg.close(); state.toolsTab = 'payload'; state.prefillHost = d.host; location.hash = '#/tools'; route(); } }, 'Payloads and configs'),
        state.token ? h('button', { class: 'btn', onclick: async e => { e.target.disabled = true; try { await api('/admin/hosts/' + encodeURIComponent(d.host), { method: 'POST' }); toast('Re-tested'); openHost(d.host); } catch (err) { toast(err.message); } } }, 'Re-test now') : null,
        h('button', { class: 'btn', onclick: () => dlg.close() }, 'Close')),
      phoneRes));
  } catch (e) { clear(body).append(h('div', { class: 'err' }, e.message), h('button', { class: 'btn', onclick: () => dlg.close() }, 'Close')); }
}
$('#sheet').addEventListener('click', e => { if (e.target === $('#sheet')) $('#sheet').close(); });

// ---------- tools ----------
function viewTools() {
  const TABS = [['sni', 'SNI sniffer'], ['phone', 'Phone test'], ['bulk', 'Bulk test'], ['check', 'Check host'], ['subdomains', 'Subdomains'], ['snicheck', 'SNI check'], ['dns', 'DNS'], ['ports', 'Ports'], ['convert', 'Converter'], ['payload', 'Payloads']];
  const wrap = h('div');
  const bar = h('div', { class: 'tabs', role: 'group', 'aria-label': 'Tool' }, TABS.map(([k, l]) => h('button', { class: 'tab', 'aria-pressed': String(state.toolsTab === k), onclick: () => { state.toolsTab = k; viewTools(); } }, l)));
  const body = h('div');
  wrap.append(bar, body);
  clear(app).append(wrap);
  ({ sni: toolSniff, phone: toolPhone, snicheck: toolSniCheck, subdomains: toolSubdomains, check: toolCheck, bulk: toolBulk, dns: toolDns, ports: toolPorts, convert: toolConvert, payload: toolPayload })[state.toolsTab](body);
}

function toolCheck(body) {
  const out = h('div');
  const input = h('input', { type: 'text', placeholder: 'example.com', autocapitalize: 'none', autocomplete: 'off', value: state.prefillCheck || '', 'aria-label': 'Host name' });
  const go = async () => {
    clear(out).append(h('p', { class: 'muted' }, 'Testing DNS, TLS, HTTP and WebSocket. This takes a few seconds.'));
    try {
      const d = await api('/tools/check', { method: 'POST', body: { host: input.value } });
      clear(out).append(h('div', { class: 'panel' },
        h('div', { class: 'sheet-head' }, h('h3', { class: 'mono' }, d.host), bars(d.score, d.working)),
        d.working ? null : h('div', { class: 'err' }, 'Not working: ' + (d.error || 'unreachable')),
        infoBlock(d), h('h3', null, 'Use it for'), protoBlock(d.protocols),
        h('div', { class: 'row-actions' }, h('button', { class: 'btn primary', onclick: () => { state.prefillHost = d.host; state.toolsTab = 'payload'; viewTools(); } }, 'Make payload'))));
    } catch (e) { clear(out).append(h('div', { class: 'err' }, e.message)); }
  };
  input.addEventListener('keydown', e => { if (e.key === 'Enter') go(); });
  body.append(h('div', { class: 'panel' }, h('label', { class: 'f' }, 'Host to test'), input,
    h('div', { class: 'row-actions' }, h('button', { class: 'btn primary', onclick: go }, 'Test host')),
    h('p', { class: 'small muted' }, 'Runs from the device where this app is running. For results that match your carrier, run Radar on that carrier\'s mobile data.')), out);
}

function toolSubdomains(body) {
  const out = h('div');
  const input = h('input', { type: 'text', placeholder: 'econet.co.zw', autocapitalize: 'none', 'aria-label': 'Domain' });
  const deep = h('input', { type: 'checkbox', id: 'deep' });
  let names = [];
  const go = async () => {
    clear(out).append(h('p', { class: 'muted' }, 'Searching certificate logs and DNS. Allow up to 40 seconds.'));
    try {
      const d = await api('/tools/subdomains', { method: 'POST', body: { domain: input.value, deep: deep.checked } });
      names = d.names;
      const st = Object.entries(d.stats).map(([k, v]) => `${k}: ${v}`).join(' · ');
      const results = h('div', { class: 'ledger' });
      const cap = names.slice(0, 300);
      cap.forEach(n => {
        const badge = h('span', { class: 'muted small' }, '');
        const row = h('div', { class: 'item', style: 'grid-template-columns:1fr auto' }, h('div', { class: 'host' }, n), h('div', null, badge, ' ', h('button', { class: 'btn sm', onclick: async e => { e.target.disabled = true; await testInline(n, badge); e.target.disabled = false; } }, 'Test')));
        results.append(row);
      });
      clear(out).append(h('div', { class: 'panel' }, h('b', null, `${d.count} names found for ${d.domain}`), h('div', { class: 'small muted' }, st), d.publishedHere.length ? h('div', { class: 'small' }, `${d.publishedHere.length} are already published as working hosts.`) : null,
        h('div', { class: 'row-actions' },
          h('button', { class: 'btn primary', onclick: async e => { e.target.disabled = true; e.target.textContent = 'Testing'; const rows = [...results.querySelectorAll('.item')]; let i = 0; await Promise.all(Array.from({ length: 4 }, async () => { while (i < Math.min(rows.length, 40)) { const k = i++; await testInline(cap[k], rows[k].querySelector('span')); } })); e.target.textContent = 'Test first 40'; e.target.disabled = false; } }, 'Test first 40'),
          h('button', { class: 'btn', onclick: () => copy(names.join('\n')) }, 'Copy all'),
          state.token ? h('button', { class: 'btn', onclick: async () => { try { const r = await api('/admin/hosts', { method: 'POST', body: { hosts: names.join('\n'), country: 'GLOBAL' } }); toast(`Added ${r.added} to scanner`); } catch (e) { toast(e.message); } } }, 'Add all to scanner') : null),
        d.count > 300 ? h('div', { class: 'small muted' }, 'Showing the first 300. Use Copy all for the rest.') : null), results);
    } catch (e) { clear(out).append(h('div', { class: 'err' }, e.message)); }
  };
  async function testInline(n, badge) {
    badge.textContent = 'testing';
    try { const r = await api('/tools/check', { method: 'POST', body: { host: n } }); badge.textContent = r.working ? `OK ${r.score}` : 'down'; badge.style.color = r.working ? 'var(--good)' : 'var(--bad)'; } catch (e) { badge.textContent = e.message.slice(0, 18); }
  }
  input.addEventListener('keydown', e => { if (e.key === 'Enter') go(); });
  body.append(h('div', { class: 'panel' }, h('label', { class: 'f' }, 'Domain'), input,
    h('label', { class: 'f' }, h('input', { type: 'checkbox', id: 'deepcb', onchange: e => { deep.checked = e.target.checked; } }), ' Also guess common names (slower, finds more)'),
    h('div', { class: 'row-actions' }, h('button', { class: 'btn primary', onclick: go }, 'Find subdomains')),
    h('p', { class: 'small muted' }, 'Sources: certificate transparency logs (crt.sh, Cert Spotter), Anubis, HackerTarget, plus optional DNS guessing.')), out);
}

function toolPayload(body) {
  const f = { host: state.prefillHost || '', server: '', port: '443', path: '/', uuid: '', password: '' };
  const out = h('div');
  const field = (label, key, ph) => h('div', null, h('label', { class: 'f' }, label), h('input', { type: 'text', value: f[key], placeholder: ph, autocapitalize: 'none', oninput: e => { f[key] = e.target.value; } }));
  const uuidInput = h('input', { type: 'text', value: f.uuid, placeholder: 'your VLESS/VMess id', oninput: e => { f.uuid = e.target.value; } });
  const go = async () => {
    try {
      const d = await api('/tools/generate', { method: 'POST', body: f });
      clear(out).append(h('div', null,
        h('h3', null, 'HTTP Injector style payloads'),
        d.payloads.map(p => h('div', { class: 'blk' }, h('div', { class: 'blk-h' }, h('b', null, p.name), h('button', { class: 'btn sm', onclick: () => copy(p.text) }, 'Copy')), h('pre', { class: 'code' }, p.text), h('div', { class: 'small muted' }, p.note))),
        h('h3', { style: 'margin-top:16px' }, 'Configs'),
        d.configs.map(c => h('div', { class: 'blk' }, h('div', { class: 'blk-h' }, h('b', null, c.name), h('button', { class: 'btn sm', onclick: () => copy(c.text) }, 'Copy')), h('pre', { class: 'code' }, c.text)))));
    } catch (e) { clear(out).append(h('div', { class: 'err' }, e.message)); }
  };
  body.append(h('div', { class: 'panel' },
    field('Bug host (SNI / Host header)', 'host', 'whitelisted.example.com'),
    field('Your tunnel server', 'server', 'server.yourdomain.com or IP'),
    h('div', { class: 'two' }, field('Port', 'port', '443'), field('WebSocket path', 'path', '/')),
    h('label', { class: 'f' }, 'UUID (VLESS / VMess)'), uuidInput,
    field('Password (Trojan)', 'password', 'optional'),
    h('div', { class: 'row-actions' }, h('button', { class: 'btn primary', onclick: go }, 'Generate'),
      h('button', { class: 'btn', onclick: () => { const u = crypto.randomUUID ? crypto.randomUUID() : ''; f.uuid = u; uuidInput.value = u; } }, 'New UUID')),
    h('p', { class: 'small muted' }, 'You bring the server (SSH, V2Ray or Xray). Radar builds the client side: the bug host goes into SNI and Host fields.')), out);
  if (f.host) go();
}

// ---------- more tools ----------
const sleep = ms => new Promise(r => setTimeout(r, ms));
const copyBlock = (title, text) => h('div', { class: 'blk' }, h('div', { class: 'blk-h' }, h('b', null, title), h('button', { class: 'btn sm', onclick: () => copy(text) }, 'Copy')), h('pre', { class: 'code' }, text));
const statusChip = st => h('span', { class: 'chip ' + (st === 'open' ? 'ok' : st === 'closed' ? 'no' : '') }, st);

function toolDns(body) {
  const out = h('div');
  const input = h('input', { type: 'text', placeholder: 'example.com or 8.8.8.8', autocapitalize: 'none', autocomplete: 'off', 'aria-label': 'Domain or IP address' });
  const resolver = h('select', { 'aria-label': 'Resolver' }, [['system', "This device's DNS"], ['cloudflare', 'Cloudflare 1.1.1.1'], ['google', 'Google 8.8.8.8'], ['quad9', 'Quad9 9.9.9.9']].map(([v, l]) => h('option', { value: v }, l)));
  const TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'CAA'];
  const on = new Set(['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT']);
  const boxes = h('div', null, TYPES.map(t => h('label', { class: 'chip', style: 'cursor:pointer' }, h('input', { type: 'checkbox', checked: on.has(t), onchange: e => { e.target.checked ? on.add(t) : on.delete(t); } }), ' ' + t)));
  const go = async () => {
    clear(out).append(h('p', { class: 'muted' }, 'Looking up records'));
    try {
      const d = await api('/tools/dns', { method: 'POST', body: { name: input.value, types: [...on], resolver: resolver.value } });
      const keys = [...new Set([...TYPES, 'PTR'])].filter(k => k in d.records || k in d.errors);
      clear(out).append(h('div', { class: 'panel' }, h('b', { class: 'mono' }, d.name), h('div', { class: 'small muted' }, d.resolver === 'system' ? "Answered by this device's DNS" : 'Answered by ' + d.resolver),
        d.note ? h('div', { class: 'notice' }, d.note) : null,
        keys.map(k => h('div', { class: 'proto' }, h('b', null, k), d.errors[k] ? h('span', { class: 'err' }, 'Error: ' + d.errors[k]) : (d.records[k].length ? d.records[k].map(r => h('div', { class: 'mono small' }, r)) : h('span', { class: 'muted small' }, 'No records'))))));
    } catch (e) { clear(out).append(h('div', { class: 'err' }, e.message)); }
  };
  input.addEventListener('keydown', e => { if (e.key === 'Enter') go(); });
  body.append(h('div', { class: 'panel' }, h('label', { class: 'f' }, 'Domain or IP address'), input, h('label', { class: 'f' }, 'Resolver'), resolver, h('label', { class: 'f' }, 'Record types'), boxes,
    h('div', { class: 'row-actions' }, h('button', { class: 'btn primary', onclick: go }, 'Look up')),
    h('p', { class: 'small muted' }, "\"This device's DNS\" shows what your own network answers. Compare it with Cloudflare or Google to spot a carrier redirecting names.")), out);
}

function toolPorts(body) {
  const out = h('div');
  const input = h('input', { type: 'text', placeholder: 'example.com or an IP', autocapitalize: 'none', 'aria-label': 'Host' });
  const ports = h('input', { type: 'text', value: '80,443', placeholder: '80,443,8000-8010', 'aria-label': 'Ports' });
  const presets = [['Web', '80,443,8080,8443'], ['SSH and VPN', '22,443,1194,500,4500,1723'], ['Cloudflare', '443,2053,2083,2087,2096,8443'], ['Common', '21,22,25,53,80,110,143,443,993,995,3306,8080,8443']];
  const go = async () => {
    clear(out).append(h('p', { class: 'muted' }, 'Checking ports. Closed ones answer fast, filtered ones take a few seconds.'));
    try {
      const d = await api('/tools/ports', { method: 'POST', body: { host: input.value, ports: ports.value } });
      clear(out).append(h('div', { class: 'panel' }, h('b', { class: 'mono' }, d.host), h('div', { class: 'small muted' }, 'IP ' + d.ip),
        h('table', { class: 't' }, d.results.map(r => h('tr', null, h('td', { class: 'mono' }, String(r.port)), h('td', null, r.service || ''), h('td', null, statusChip(r.status)), h('td', { class: 'muted small' }, r.status === 'open' ? r.ms + ' ms' : ''), h('td', { class: 'mono small' }, r.banner || ''))))));
    } catch (e) { clear(out).append(h('div', { class: 'err' }, e.message)); }
  };
  input.addEventListener('keydown', e => { if (e.key === 'Enter') go(); });
  body.append(h('div', { class: 'panel' }, h('label', { class: 'f' }, 'Host'), input, h('label', { class: 'f' }, 'Ports (up to 30)'), ports,
    h('div', null, presets.map(([l, v]) => h('button', { class: 'btn sm', style: 'margin:6px 6px 0 0', onclick: () => { ports.value = v; } }, l))),
    h('div', { class: 'row-actions' }, h('button', { class: 'btn primary', onclick: go }, 'Check ports')),
    h('p', { class: 'small muted' }, 'Open means something answered. Closed means the host refused. Filtered means no answer, usually a firewall. Private addresses are blocked.')), out);
}

function toolBulk(body) {
  const ta = h('textarea', { placeholder: 'host1.example.com\nhost2.example.com', 'aria-label': 'Hosts to test' });
  const out = h('div');
  let stop = false;
  const go = async () => {
    const names = [...new Set(ta.value.split(/[\s,;]+/).map(x => x.trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0]).filter(Boolean))].slice(0, 300);
    if (!names.length) { clear(out).append(h('div', { class: 'err' }, 'Paste at least one host')); return; }
    stop = false;
    const size = state.token ? 30 : 10;
    const results = [];
    const prog = h('i');
    const sumEl = h('div', { class: 'small muted' });
    const list = h('div', { class: 'ledger' });
    const stopBtn = h('button', { class: 'btn danger sm', onclick: () => { stop = true; } }, 'Stop');
    const actions = h('div', { class: 'row-actions' }, stopBtn);
    clear(out).append(h('div', null, h('div', { class: 'progress' }, prog), sumEl, actions, list));
    const paint = () => {
      const ok = results.filter(r => r.working).length;
      prog.style.width = Math.round(100 * results.length / names.length) + '%';
      sumEl.textContent = `${results.length} of ${names.length} tested, ${ok} working`;
      clear(list).append(...results.slice().sort((a, b) => b.score - a.score || a.host.localeCompare(b.host)).map(r =>
        h('div', { class: 'item', style: 'grid-template-columns:auto 1fr auto', onclick: () => r.working && openCheck(r.host) }, bars(r.score, r.working), h('div', { class: 'host' }, r.host), h('div', { class: 'score' }, r.working ? String(r.score) : 'down'),
          h('div', { class: 'meta' }, r.working ? [r.ms != null ? r.ms + ' ms' : null, r.tls ? r.tls.replace('TLSv', 'TLS ') : null, r.cdn, r.types.map(t => typeLabel[t] || t).join(', ')].filter(Boolean).map(x => h('span', null, x)) : h('span', null, r.error || 'not responding')))));
    };
    for (let i = 0; i < names.length && !stop; i += size) {
      let tries = 0;
      while (!stop) {
        try { const d = await api('/tools/bulk', { method: 'POST', body: { hosts: names.slice(i, i + size) } }); results.push(...d.results); paint(); break; }
        catch (e) { if (/Too many/.test(e.message) && ++tries <= 3) { sumEl.textContent = 'Slowing down to stay within the limit'; await sleep(8000); continue; } clear(actions).append(h('div', { class: 'err' }, e.message)); stop = true; }
      }
    }
    const working = results.filter(r => r.working).map(r => r.host);
    clear(actions).append(h('div', { class: 'row-actions', style: 'margin:0' }, h('button', { class: 'btn primary', disabled: !working.length, onclick: () => copy(working.join('\n')) }, `Copy ${working.length} working`),
      state.token && working.length ? h('button', { class: 'btn', onclick: async () => { try { const r = await api('/admin/hosts', { method: 'POST', body: { hosts: working.join('\n'), country: 'GLOBAL' } }); toast(`Added ${r.added} to scanner`); } catch (e) { toast(e.message); } } }, 'Add working to scanner') : null));
  };
  body.append(h('div', { class: 'panel' }, h('label', { class: 'f' }, 'Hosts (one per line, up to 300)'), ta,
    h('div', { class: 'row-actions' }, h('button', { class: 'btn primary', onclick: go }, 'Test all')),
    h('p', { class: 'small muted' }, 'Tests run in small batches so you see results as they arrive. Tap a working host to see its full details.')), out);
  if (state.prefillBulk) { ta.value = state.prefillBulk; state.prefillBulk = ''; setTimeout(go, 0); }
}
function openCheck(host) { state.prefillCheck = host; state.toolsTab = 'check'; viewTools(); }

function looksBinary(text) {
  const s = String(text || '').slice(0, 4000);
  let bad = 0;
  for (let i = 0; i < s.length; i++) { const c = s.charCodeAt(i); if (c === 0xfffd || c < 9 || (c > 13 && c < 32)) bad++; }
  return s.length > 0 && bad / s.length > 0.05;
}

function toolSniff(body) {
  const out = h('div');
  const ta = h('textarea', { placeholder: 'Paste a config here. Works with vless, vmess and trojan links, Xray, V2Ray and sing-box JSON, Clash YAML, .ovpn, WireGuard, stunnel and HTTP payloads.', 'aria-label': 'Config text', style: 'min-height:160px' });
  const lockedMsg = 'This file looks encrypted or binary. Apps such as HTTP Injector, HTTP Custom and NapsternetV lock exported configs on purpose, and Moon Radar does not try to open them. Ask for an unlocked export, or copy the payload and SNI from the app screen and paste that.';
  const go = async () => {
    if (!ta.value.trim()) { clear(out).append(h('div', { class: 'err' }, 'Paste a config or choose a file first')); return; }
    clear(out).append(h('p', { class: 'muted' }, 'Reading the config'));
    try {
      const d = await api('/tools/sniff', { method: 'POST', body: { text: ta.value } });
      if (d.binary) { clear(out).append(h('div', { class: 'notice' }, d.notes[0])); return; }
      const bug = d.hosts.filter(x => x.bug), other = d.hosts.filter(x => !x.bug);
      const servers = other.filter(x => x.roles.some(r => ['Server', 'Endpoint', 'Proxy'].includes(r)));
      const rest = other.filter(x => !servers.includes(x));
      const row = x => h('div', { class: 'item', style: 'grid-template-columns:1fr auto' }, h('div', { class: 'host' }, x.host), h('div', null, x.roles.map(r => h('span', { class: 'chip' + (['SNI', 'Host header'].includes(r) ? ' ok' : '') }, r))));
      const group = (title, list, hint) => list.length ? h('div', { class: 'panel' }, h('b', null, `${title} (${list.length})`), hint ? h('div', { class: 'small muted' }, hint) : null, h('div', { class: 'ledger', style: 'margin-top:8px' }, list.map(row))) : null;
      const allNames = d.hosts.map(x => x.host);
      clear(out).append(h('div', null,
        h('div', { class: 'panel' }, h('b', null, bug.length ? `Found ${bug.length} bug host${bug.length === 1 ? '' : 's'}` : 'No SNI or Host names found'),
          h('div', { class: 'small muted' }, (d.formats.length ? 'Looks like: ' + d.formats.join(', ') + '. ' : '') + `${d.hosts.length} names in total.`),
          d.notes.map(n => h('div', { class: 'notice' }, n)),
          h('div', { class: 'row-actions' },
            bug.length ? h('button', { class: 'btn primary', onclick: () => { state.prefillBulk = bug.map(x => x.host).join('\n'); state.toolsTab = 'bulk'; viewTools(); } }, 'Test bug hosts') : null,
            allNames.length ? h('button', { class: 'btn', onclick: () => { state.prefillBulk = allNames.join('\n'); state.toolsTab = 'bulk'; viewTools(); } }, 'Test all names') : null,
            allNames.length ? h('button', { class: 'btn', onclick: () => copy(allNames.join('\n')) }, 'Copy names') : null)),
        group('Bug host candidates', bug, 'Names in SNI and Host fields are what the carrier sees.'),
        group('Servers and endpoints', servers),
        d.ips.length ? h('div', { class: 'panel' }, h('b', null, `IP addresses (${d.ips.length})`), d.ips.map(i => h('div', { class: 'mono small' }, i.ip + '  ' + i.roles.join(', ')))) : null,
        group('Other names', rest),
        servers.length && bug.length ? h('div', { class: 'row-actions' }, h('button', { class: 'btn', onclick: () => { state.prefillSni = { target: servers[0].host, snis: bug.map(x => x.host).join('\n') }; state.toolsTab = 'snicheck'; viewTools(); } }, 'Check these names against ' + servers[0].host)) : null));
    } catch (e) { clear(out).append(h('div', { class: 'err' }, e.message)); }
  };
  const file = h('input', { type: 'file', 'aria-label': 'Config file', onchange: async e => {
    const f = e.target.files && e.target.files[0];
    if (!f) return;
    if (f.size > 500000) { clear(out).append(h('div', { class: 'err' }, 'That file is bigger than 500 KB')); return; }
    const txt = await f.text();
    if (looksBinary(txt)) { ta.value = ''; clear(out).append(h('div', { class: 'notice' }, lockedMsg)); return; }
    ta.value = txt; go();
  } });
  body.append(h('div', { class: 'panel' }, h('label', { class: 'f' }, 'Config text'), ta,
    h('label', { class: 'f' }, 'Or choose a file'), file,
    h('div', { class: 'row-actions' }, h('button', { class: 'btn primary', onclick: go }, 'Sniff hosts')),
    h('p', { class: 'small muted' }, 'Reads the file on the server and lists every SNI, Host header, payload host and server in it. Nothing is saved. Locked app exports (.ehi, .hc, .npv and similar) are encrypted and are not opened.')), out);
}

function toolSniCheck(body) {
  const out = h('div');
  const pre = state.prefillSni || {};
  state.prefillSni = null;
  const target = h('input', { type: 'text', placeholder: 'IP address or server name', autocapitalize: 'none', 'aria-label': 'Server', value: pre.target || '' });
  const port = h('input', { type: 'text', value: '443', inputmode: 'numeric', 'aria-label': 'Port' });
  const snis = h('textarea', { placeholder: 'Leave empty to test the names found in the certificate', 'aria-label': 'Names to test', value: pre.snis || '' });
  const go = async () => {
    clear(out).append(h('p', { class: 'muted' }, 'Connecting and trying each name'));
    try {
      const d = await api('/tools/sni', { method: 'POST', body: { target: target.value, port: port.value, snis: snis.value } });
      const dc = d.defaultCert;
      clear(out).append(h('div', null,
        h('div', { class: 'panel' }, h('b', { class: 'mono' }, `${d.target}:${d.port}`), h('div', { class: 'small muted' }, 'IP ' + d.ip),
          dc ? h('dl', { class: 'facts' }, [['Default certificate', dc.subject || 'unknown'], ['Issuer', dc.issuer || 'unknown'], ['Expires', dc.validTo || 'unknown'], ['TLS', `${dc.version || ''}${dc.alpn ? ', ' + dc.alpn : ''}, ${dc.ms} ms`], ['Names on it', (dc.names || []).join(', ') || 'none']].map(([k, v]) => [h('dt', null, k), h('dd', null, v)])) : h('div', { class: 'err' }, 'No TLS answer without a name' + (d.defaultError ? ' (' + d.defaultError + ')' : ''))),
        h('div', { class: 'panel' }, h('b', null, d.usedCertNames ? 'Names from the certificate' : 'Names you tested'), h('div', { class: 'small muted' }, 'Same certificate means the server treats the name like its default site. A different certificate means it hosts that name separately.'),
          d.results.length ? h('table', { class: 't' }, d.results.map(r => h('tr', null, h('td', { class: 'mono small' }, r.sni), h('td', null, r.ok ? h('span', { class: 'chip ok' }, 'handshake ok') : h('span', { class: 'chip no' }, r.error || 'failed')),
            h('td', { class: 'small muted' }, r.ok ? [r.version, r.ms + ' ms', r.nameMatch ? 'name matches' : 'name differs', r.sameCert ? 'same certificate' : 'different certificate'].filter(Boolean).join(', ') : '')))) : h('p', { class: 'muted' }, 'Nothing to test. Add names above.'))));
    } catch (e) { clear(out).append(h('div', { class: 'err' }, e.message)); }
  };
  target.addEventListener('keydown', e => { if (e.key === 'Enter') go(); });
  body.append(h('div', { class: 'panel' }, h('label', { class: 'f' }, 'Server'), target, h('label', { class: 'f' }, 'Port'), port, h('label', { class: 'f' }, 'Names (SNI) to test, optional'), snis,
    h('div', { class: 'row-actions' }, h('button', { class: 'btn primary', onclick: go }, 'Check server')),
    h('p', { class: 'small muted' }, 'Reads the certificate a server shows with no name, then tries names against it and compares the answers. To pull names out of a config file, use the SNI sniffer tab.')), out);
  if (pre.target) go();
}

function toolConvert(body) {
  const out = h('div');
  const link = h('textarea', { placeholder: 'vless://... or vmess://... or trojan://...', 'aria-label': 'Share link' });
  const f = {};
  const field = (label, key, ph) => h('div', null, h('label', { class: 'f' }, label), h('input', { type: 'text', placeholder: ph, autocapitalize: 'none', oninput: e => { f[key] = e.target.value; } }));
  const go = async () => {
    try {
      const d = await api('/tools/convert', { method: 'POST', body: Object.assign({ link: link.value }, f) });
      const sm = d.summary;
      clear(out).append(h('div', null,
        h('div', { class: 'panel' }, h('b', null, 'Link details'), h('dl', { class: 'facts' }, Object.entries(sm).filter(([, v]) => v).map(([k, v]) => [h('dt', null, k), h('dd', { class: 'mono small' }, String(v))])),
          d.warnings.map(w => h('div', { class: 'notice' }, w))),
        h('div', { class: 'panel' }, copyBlock('New link', d.link), copyBlock('Xray JSON', d.xray), copyBlock('sing-box JSON', d.singbox), copyBlock('Clash / Mihomo YAML', d.clash))));
    } catch (e) { clear(out).append(h('div', { class: 'err' }, e.message)); }
  };
  body.append(h('div', { class: 'panel' }, h('label', { class: 'f' }, 'Share link'), link,
    field('Bug host (sets SNI and Host together)', 'bug', 'bug.example.com'),
    h('div', { class: 'two' }, field('Server', 'server', 'keep as is'), field('Port', 'port', 'keep as is')),
    h('div', { class: 'two' }, field('Path', 'path', 'keep as is'), field('Name', 'name', 'keep as is')),
    h('div', { class: 'row-actions' }, h('button', { class: 'btn primary', onclick: go }, 'Convert')),
    h('p', { class: 'small muted' }, 'Turns a link into Xray, sing-box and Clash configs, and swaps the bug host if you set one. Nothing is saved.')), out);
}

// ---------- phone test (runs in this browser, on this device's connection) ----------
async function phoneProbe(host, timeoutMs) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  const t0 = performance.now();
  try {
    // no-cors: we cannot read the reply, but the promise only resolves if DNS, TCP and TLS all worked.
    await fetch('https://' + host + '/?mr=' + Math.random().toString(36).slice(2), { mode: 'no-cors', cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer', redirect: 'manual', signal: ctl.signal });
    return { ok: true, ms: Math.round(performance.now() - t0) };
  } catch (e) {
    return { ok: false, ms: Math.round(performance.now() - t0), timeout: ctl.signal.aborted };
  } finally { clearTimeout(timer); }
}
async function phoneTest(host) {
  let r = await phoneProbe(host, 7000);
  if (!r.ok && !r.timeout) r = await phoneProbe(host, 7000);   // a fast failure may be a one-off DNS hiccup
  return r;
}

function toolPhone(body) {
  const ipLine = h('span', null, 'Checking this connection');
  api('/whoami').then(d => { clear(ipLine).append(`This connection's public IP: ${d.ip}. Turn Wi-Fi off and reopen this tab: the IP changes when you are on mobile data.`); }).catch(() => { clear(ipLine).append(''); });
  const ta = h('textarea', { placeholder: 'host1.example.com\nhost2.example.com', 'aria-label': 'Hosts to test' });
  const out = h('div');
  let stop = false, pendingSet = null;
  const loader = (label, fn, pending) => h('button', { class: 'btn sm', style: 'margin:6px 6px 0 0', onclick: async () => { try { const list = await fn(); ta.value = list.join('\n'); pendingSet = pending ? new Set(list) : null; toast(list.length + ' hosts loaded'); } catch (e) { toast(e.message); } } }, label);
  const go = async () => {
    const names = [...new Set(ta.value.split(/[\s,;]+/).map(x => x.trim().toLowerCase().replace(/^https?:\/\//, '').split(/[\/:]/)[0]).filter(x => /^[a-z0-9]([a-z0-9._-]*[a-z0-9])?\.[a-z]{2,}$/.test(x)))].slice(0, 300);
    if (!names.length) { clear(out).append(h('div', { class: 'err' }, 'Paste or load at least one host')); return; }
    stop = false;
    const results = [];
    const prog = h('i'), sumEl = h('div', { class: 'small muted' }), list = h('div', { class: 'ledger' });
    const actions = h('div');
    const stopBtn = h('button', { class: 'btn danger sm', onclick: () => { stop = true; } }, 'Stop');
    const stopRow = h('div', { class: 'row-actions' }, stopBtn);
    clear(out).append(h('div', null, h('div', { class: 'progress' }, prog), sumEl, stopRow, actions, list));
    const paint = () => {
      const ok = results.filter(r => r.ok).length;
      prog.style.width = Math.round(100 * results.length / names.length) + '%';
      sumEl.textContent = `${results.length} of ${names.length} tested, ${ok} reachable from this phone`;
      clear(list).append(...results.slice().sort((a, b) => (b.ok - a.ok) || a.ms - b.ms).map(r =>
        h('div', { class: 'item', style: 'grid-template-columns:1fr auto;cursor:default' }, h('div', { class: 'host' }, r.host), h('div', null, h('span', { class: 'chip ' + (r.ok ? 'ok' : 'no') }, r.ok ? `reachable ${r.ms} ms` : r.timeout ? 'no answer' : 'failed')))));
    };
    let i = 0;
    await Promise.all(Array.from({ length: Math.min(6, names.length) }, async () => {
      while (i < names.length && !stop) { const host = names[i++]; const r = await phoneTest(host); results.push(Object.assign({ host }, r)); paint(); }
    }));
    const okList = results.filter(r => r.ok).map(r => r.host);
    const badList = results.filter(r => !r.ok).map(r => r.host);
    const carrier = h('input', { type: 'text', placeholder: 'Carrier you are on, e.g. Econet', 'aria-label': 'Carrier' });
    const approvable = pendingSet ? okList.filter(x => pendingSet.has(x)) : [];
    clear(stopRow).append(h('div', { class: 'row-actions', style: 'margin:0' }, h('button', { class: 'btn primary', disabled: !okList.length, onclick: () => copy(okList.join('\n')) }, `Copy ${okList.length} reachable`),
      okList.length ? h('button', { class: 'btn', onclick: () => { state.prefillSuggest = { hosts: okList.join('\n') }; location.hash = '#/contact'; } }, 'Suggest these on WhatsApp') : null));
    if (state.token && results.length) {
      clear(actions).append(h('div', { class: 'panel' }, h('b', null, 'Admin'), h('div', { class: 'small muted' }, 'Save these results on the hosts as tested from this carrier. Only do this while connected through that carrier.'), carrier,
        h('div', { class: 'row-actions' },
          h('button', { class: 'btn', onclick: async () => { try { const r = await api('/admin/verify', { method: 'POST', body: { carrier: carrier.value, working: okList, failed: badList } }); toast(`${r.marked} hosts marked`); } catch (e) { toast(e.message); } } }, 'Save as tested on this carrier'),
          approvable.length ? h('button', { class: 'btn primary', onclick: async () => { try { const r = await api('/admin/review', { method: 'POST', body: { action: 'approve', hosts: approvable } }); toast(`${r.changed} approved`); } catch (e) { toast(e.message); } } }, `Approve ${approvable.length} reachable`) : null)));
    }
  };
  body.append(h('div', { class: 'panel' }, h('label', { class: 'f' }, 'Hosts (one per line, up to 300)'), ta,
    h('div', null,
      loader('Load Zimbabwe hosts', async () => (await api('/hosts?country=ZW&limit=500')).hosts.map(x => x.host)),
      loader('Load all published', async () => (await api('/hosts?limit=500')).hosts.map(x => x.host)),
      state.token ? loader('Load waiting for review', async () => (await api('/admin/hosts?review=pending&working=1&country=ZW&limit=300')).hosts.map(x => x.host), true) : null),
    h('div', { class: 'row-actions' }, h('button', { class: 'btn primary', onclick: go }, 'Test from this phone')),
    h('div', { class: 'small muted' }, ipLine),
    h('div', { class: 'notice' }, 'This runs in your browser, on whatever connection this phone is using right now. To test a carrier, turn off Wi-Fi and use that carrier\'s mobile data.'),
    h('p', { class: 'small muted' }, 'Reachable means DNS, TCP and a valid TLS handshake all worked from this phone. A host with an invalid certificate shows as failed even though an SNI tunnel might still use it. Chrome\'s Secure DNS can bypass your carrier\'s DNS, and browsers may use HTTP/3 over UDP, so confirm a winner in your tunnel app before relying on it.')), out);
}

// ---------- contact (WhatsApp) ----------
function viewContact() {
  const countries = state.meta.countries;
  const f = Object.assign({ hosts: '', country: 'ZW', carrier: '', mode: '', note: '' }, state.prefillSuggest || {});
  state.prefillSuggest = null;
  let to = WHATSAPP[0].number;
  const preview = h('div', { class: 'msg-preview' });
  const fieldText = (label, key, ph) => h('div', null, h('label', { class: 'f' }, label), h('input', { type: 'text', placeholder: ph, value: f[key], oninput: e => { f[key] = e.target.value; update(); } }));
  const update = () => { const m = buildSuggestMessage(f, countries); clear(preview).append(m.count ? m.text : 'Add at least one host to see your message.'); return m; };
  const hosts = h('textarea', { placeholder: 'host1.example.com\nhost2.example.com', 'aria-label': 'Hosts', oninput: e => { f.hosts = e.target.value; update(); } });
  hosts.value = f.hosts;
  const country = h('select', { 'aria-label': 'Country', onchange: e => { f.country = e.target.value; update(); } }, Object.entries(countries).sort((a, b) => (b[0] === 'ZW') - (a[0] === 'ZW') || a[1].localeCompare(b[1])).map(([c, n]) => h('option', { value: c, selected: c === f.country }, n)));
  const toSel = h('select', { 'aria-label': 'Send to', onchange: e => { to = e.target.value; } }, WHATSAPP.map(w => h('option', { value: w.number }, w.label)));
  const msg = h('div');
  const send = () => {
    const m = update();
    if (!m.count) { clear(msg).append(h('div', { class: 'err' }, 'Add at least one valid host name first')); return; }
    clear(msg);
    const url = waLink(to, m.text);
    const w = window.open(url, '_blank', 'noopener');
    if (!w) location.href = url;
  };
  clear(app).append(h('div', null,
    h('div', { class: 'panel' }, h('div', { style: 'display:flex;align-items:center;gap:10px' }, waIcon(30), h('h2', null, 'Chat on WhatsApp')),
      h('p', { class: 'muted small' }, 'Tap a number. WhatsApp opens with a short message already written to say you are a Moon Radar user.'),
      h('div', { class: 'wa-list' }, WHATSAPP.map(w => h('a', { class: 'wa-btn', href: waLink(w.number, HELLO), target: '_blank', rel: 'noopener' }, waIcon(28), h('span', null, w.label, h('small', null, 'Tap to chat')), h('span', { class: 'go' }, 'Chat'))))),
    h('div', { class: 'panel' }, h('h2', null, 'Suggest or upload working hosts'),
      h('p', { class: 'muted small' }, 'Found hosts that work on your connection? Send them to us. We test them and add the good ones. Fill in the form and WhatsApp opens with the message ready to send.'),
      h('label', { class: 'f' }, 'Hosts (one per line, up to 40)'), hosts,
      h('div', { class: 'two' }, h('div', null, h('label', { class: 'f' }, 'Country'), country), fieldText('Carrier', 'carrier', 'Econet, NetOne...')),
      fieldText('App and mode', 'mode', 'HA Tunnel, SNI'), fieldText('Note (optional)', 'note', 'Works only at night, uses no data...'),
      h('label', { class: 'f' }, 'Send to'), toSel,
      h('div', { class: 'small muted', style: 'margin-top:10px' }, 'Your message:'), preview,
      msg, h('div', { class: 'row-actions' }, h('button', { class: 'btn primary', onclick: send }, 'Send on WhatsApp')),
      h('p', { class: 'small muted' }, 'Only share hosts you tested on your own connection. Say which carrier and app you used. The message goes through WhatsApp, not through this website.'))));
  update();
}

// ---------- footer ----------
function renderFooter() {
  const el = $('#footer');
  if (!el) return;
  const m = state.meta;
  const link = (href, text) => h('a', { href }, text);
  const acc = (title, ...kids) => h('details', null, h('summary', null, title), h('div', { class: 'body' }, kids));
  const qa = (q, a) => [h('div', { class: 'q' }, q), h('p', null, a)];
  clear(el).append(h('div', { class: 'in' },
    h('div', { class: 'cols' },
      h('div', null, h('h3', null, 'Moon Radar'),
        h('p', null, 'Finds and tests SNI and bug hosts for VPN tunnelling, with a focus on Zimbabwe. Hosts are rechecked about once a day, and Zimbabwe hosts are reviewed by an admin before they are published.'),
        m ? h('p', null, `${m.total} working hosts${m.lastDaily ? ' · last full test ' + ago(m.lastDaily) : ''}`) : null),
      h('div', null, h('h3', null, 'Quick links'),
        h('ul', null, h('li', null, link('#/', 'Hosts')), h('li', null, link('#/tools', 'Tools')), h('li', null, link('#/tools', 'Phone test')), h('li', null, link('#/contact', 'Suggest a host')), h('li', null, link('#/contact', 'Contact us')))),
      h('div', null, h('h3', null, 'Chat on WhatsApp'),
        h('ul', null, WHATSAPP.map(w => h('li', null, h('a', { class: 'fwa', href: waLink(w.number, HELLO), target: '_blank', rel: 'noopener' }, waIcon(22), w.label)))))),
    acc('How it works',
      h('ol', { style: 'margin:0;padding:0' }, [
        'Pick your country and carrier on the Hosts tab.',
        'Open a host to see its strength, speed and the tunnelling modes it suits.',
        'Test it from your own phone with "Test on my connection" or Tools, Phone test.',
        'Use it in your tunnel app. You still need your own SSH or V2Ray server.'
      ].map(t => h('li', null, t)))),
    acc('FAQ',
      qa('What is an SNI or bug host?', 'A website name your carrier treats specially, usually because it is zero-rated. A tunnel app puts that name in the SNI or Host field so the carrier sees it.'),
      qa('Why does a host work for someone else but not for me?', 'Zero-rating differs by carrier, region and package. Radar tests from a server, so confirm on your own phone and SIM.'),
      qa('How often are hosts tested?', 'About once a day. A host that stops answering is hidden until it comes back.'),
      qa('Why do Zimbabwe hosts take longer to appear?', 'An admin checks them first, so only reviewed hosts are published.'),
      qa('How do I suggest a host?', 'Open the Contact tab, fill in the form and send it on WhatsApp.'),
      qa('Do I need a server?', 'Yes. A bug host only gets you past the carrier. Your tunnel app still needs an SSH or V2Ray server to carry the traffic.')),
    acc('Disclaimer', h('p', null, 'Hosts are found automatically, from public sources and from user suggestions. A host can stop working at any time, and a working host is not a promise of free or unlimited data. Moon Radar is not affiliated with any mobile carrier. Use hosts in line with the law and your carrier\'s terms, and at your own risk.')),
    acc('Privacy', h('p', null, 'You do not need an account. Phone tests run in your browser, and results stay on your device unless you share them. Messages you send through the WhatsApp buttons go through WhatsApp, not through this site. The hosting provider may keep standard server logs.')),
    acc('Terms of use', h('p', null, 'Moon Radar is provided as is, with no guarantee that any host works. Hosts or features may be removed or changed at any time. Do not use it to break the law or to harm others.')),
    h('div', { class: 'bottom' }, h('span', null, `\u00a9 ${new Date().getFullYear()} Moon Radar. Built by Mchris devs.`), h('a', { href: '#top', onclick: e => { e.preventDefault(); window.scrollTo(0, 0); } }, 'Back to top'))));
}

// ---------- admin ----------
function viewAdmin() {
  if (!state.token) return adminLogin();
  const tabs = [['review', 'Review'], ['hosts', 'Hosts'], ['sources', 'Sources'], ['jobs', 'Scans'], ['cloud', 'Cloud'], ['settings', 'Settings']];
  const seg = h('div', { class: 'tabs', role: 'group' }, tabs.map(([k, l]) => h('button', { class: 'tab', 'aria-pressed': String(state.adminTab === k), onclick: () => { state.adminTab = k; viewAdmin(); } }, l)),
    h('button', { class: 'tab', onclick: () => { state.token = ''; localStorage.removeItem('radar_token'); route(); } }, 'Sign out'));
  const body = h('div');
  clear(app).append(seg, body);
  clearInterval(state.jobTimer);
  ({ review: adminReview, hosts: adminHosts, sources: adminSources, jobs: adminJobs, cloud: adminCloud, settings: adminSettings })[state.adminTab](body);
}

function adminLogin() {
  const pw = h('input', { type: 'password', placeholder: 'Admin password', autocomplete: 'current-password', 'aria-label': 'Admin password' });
  const msg = h('div');
  const go = async () => {
    try { const r = await api('/admin/login', { method: 'POST', body: { password: pw.value } }); state.token = r.token; localStorage.setItem('radar_token', r.token); viewAdmin(); }
    catch (e) { clear(msg).append(h('div', { class: 'err' }, e.message)); }
  };
  pw.addEventListener('keydown', e => { if (e.key === 'Enter') go(); });
  clear(app).append(h('div', { class: 'panel' }, h('h2', null, 'Admin sign in'), h('p', { class: 'muted' }, 'Approve Zimbabwe hosts, manage sources and run scans.'), pw, msg, h('div', { class: 'row-actions' }, h('button', { class: 'btn primary', onclick: go }, 'Sign in'))));
}

async function adminReview(body) {
  let mode = 'pending';
  const selected = new Set();
  const top = h('div'); const list = h('div');
  body.append(top, list);
  async function load() {
    const params = mode === 'pending' ? 'review=pending&working=1' : `review=${mode}`;
    const d = await api(`/admin/hosts?${params}&country=ZW&limit=300`);
    clear(top).append(
      h('div', { class: 'notice' }, 'Zimbabwe hosts stay hidden until you approve them. Hosts from other countries publish automatically once they pass testing.'),
      h('div', { class: 'seg' }, [['pending', 'Waiting'], ['approved', 'Approved'], ['rejected', 'Rejected']].map(([k, l]) => h('button', { 'aria-pressed': String(mode === k), onclick: () => { mode = k; selected.clear(); load(); } }, l))),
      h('div', { class: 'row-actions' },
        mode === 'pending' ? h('button', { class: 'btn primary', disabled: !selected.size, onclick: () => act('approve') }, `Approve selected (${selected.size})`) : null,
        mode === 'pending' ? h('button', { class: 'btn danger', disabled: !selected.size, onclick: () => act('reject') }, 'Reject selected') : null,
        mode === 'pending' && d.total ? h('button', { class: 'btn', onclick: async () => { if (!confirm(`Approve all ${d.total} waiting hosts?`)) return; await api('/admin/review', { method: 'POST', body: { action: 'approve', all: 'pending' } }); selected.clear(); load(); } }, 'Approve all') : null,
        mode === 'approved' ? h('button', { class: 'btn danger', disabled: !selected.size, onclick: () => act('unpublish') }, `Unpublish selected (${selected.size})`) : null,
        mode === 'rejected' ? h('button', { class: 'btn', disabled: !selected.size, onclick: () => act('pending') }, 'Move back to waiting') : null,
        h('button', { class: 'btn', onclick: () => { d.hosts.forEach(x => selected.add(x.host)); load(); } }, 'Select all')));
    clear(list);
    if (!d.hosts.length) list.append(h('div', { class: 'ledger' }, h('div', { class: 'empty' }, mode === 'pending' ? 'Nothing waiting. New working Zimbabwe hosts appear here after each scan.' : 'Nothing here.')));
    else list.append(h('div', { class: 'ledger' }, d.hosts.map(x => hostItem(x, { pick: on => { on ? selected.add(x.host) : selected.delete(x.host); load(); }, selected: selected.has(x.host) }))));
  }
  async function act(action) { try { const r = await api('/admin/review', { method: 'POST', body: { action, hosts: [...selected] } }); toast(`${r.changed} updated`); selected.clear(); load(); } catch (e) { toast(e.message); } }
  load();
}

async function adminHosts(body) {
  const f = { q: '', working: '', country: '', review: '' };
  const list = h('div');
  const bar = h('div', { class: 'filters' },
    h('input', { class: 'wide', type: 'search', placeholder: 'Search hosts', oninput: debounce(e => { f.q = e.target.value; load(); }, 300) }),
    h('select', { onchange: e => { f.working = e.target.value; load(); } }, [['', 'Up or down'], ['1', 'Working'], ['0', 'Down']].map(([v, l]) => h('option', { value: v }, l))),
    h('select', { onchange: e => { f.review = e.target.value; load(); } }, [['', 'Any review state'], ['pending', 'Waiting'], ['approved', 'Approved'], ['rejected', 'Rejected'], ['auto', 'Auto-published'], ['new', 'Not yet working']].map(([v, l]) => h('option', { value: v }, l))));
  const add = h('div', { class: 'panel' }, h('b', null, 'Add hosts manually'), h('label', { class: 'f' }, 'Hostnames (one per line)'), h('textarea', { id: 'addh', placeholder: 'host1.example.com\nhost2.example.com' }),
    h('label', { class: 'f' }, 'Country'), countrySelect('addc', 'ZW'),
    h('div', { class: 'row-actions' }, h('button', { class: 'btn primary', onclick: async () => { try { const r = await api('/admin/hosts', { method: 'POST', body: { hosts: $('#addh').value, country: $('#addc').value } }); toast(`${r.added} added, testing now`); setTimeout(load, 4000); } catch (e) { toast(e.message); } } }, 'Add and test')));
  body.append(bar, list, add);
  async function load() {
    const d = await api('/admin/hosts?' + new URLSearchParams({ q: f.q, working: f.working, review: f.review, limit: 200 }));
    clear(list).append(h('div', { class: 'small muted', style: 'margin-bottom:6px' }, `${d.total} hosts`), h('div', { class: 'ledger' }, d.hosts.length ? d.hosts.map(x => {
      const el = hostItem(x);
      const tag = h('span', { class: 'chip ' + (x.working ? 'ok' : 'no') }, x.working ? x.review : 'down');
      el.querySelector('.meta').append(tag);
      return el;
    }) : h('div', { class: 'empty' }, 'No hosts match.')));
  }
  load();
}

function countrySelect(id, val) {
  const m = state.meta;
  return h('select', { id }, Object.entries(m.countries).sort((a, b) => (b[0] === 'ZW') - (a[0] === 'ZW') || a[1].localeCompare(b[1])).map(([c, n]) => h('option', { value: c, selected: c === val }, n)));
}

async function adminSources(body) {
  const list = h('div');
  const addPanel = h('div', { class: 'panel' }, h('b', null, 'Add zero-rated websites'),
    h('p', { class: 'small muted' }, 'Radar expands each site into subdomains and asset hosts every day, then tests them.'),
    h('label', { class: 'f' }, 'Domains (one per line)'), h('textarea', { id: 'srcd', placeholder: 'example.co.zw' }),
    h('label', { class: 'f' }, 'Country'), countrySelect('srcc', 'ZW'),
    h('label', { class: 'f' }, 'Carrier it is zero-rated on (optional)'), h('input', { type: 'text', id: 'srcca', placeholder: 'Econet' }),
    h('label', { class: 'f' }, h('input', { type: 'checkbox', id: 'srcdeep' }), ' Always guess common subdomains too'),
    h('div', { class: 'row-actions' }, h('button', { class: 'btn primary', onclick: async () => { try { const ca = $('#srcca').value.trim(); const r = await api('/admin/sources', { method: 'POST', body: { domains: $('#srcd').value, country: $('#srcc').value, carriers: ca ? [ca] : [], deep: $('#srcdeep').checked } }); toast(`${r.added} added`); $('#srcd').value = ''; load(); } catch (e) { toast(e.message); } } }, 'Add sources')));
  const cidr = h('div', { class: 'panel' }, h('b', null, 'Scan an IP range'),
    h('p', { class: 'small muted' }, 'Reads TLS certificates on port 443 across a CIDR block (max 4096 addresses) and turns certificate names into hosts.'),
    h('input', { type: 'text', id: 'cidr', placeholder: '41.57.0.0/22' }), h('label', { class: 'f' }, 'Country'), countrySelect('cidrc', 'ZW'),
    h('div', { class: 'row-actions' }, h('button', { class: 'btn primary', onclick: async () => { try { await api('/admin/cidr', { method: 'POST', body: { cidr: $('#cidr').value, country: $('#cidrc').value } }); toast('Scan started, see Scans tab'); } catch (e) { toast(e.message); } } }, 'Scan range')));
  body.append(addPanel, list, cidr);
  async function load() {
    const s = await api('/admin/sources');
    s.sort((a, b) => (b.country === 'ZW') - (a.country === 'ZW') || a.domain.localeCompare(b.domain));
    clear(list).append(h('div', { class: 'panel' }, h('b', null, `${s.length} sources`), h('table', { class: 't' }, s.map(x => h('tr', null,
      h('td', { class: 'mono' }, x.domain), h('td', null, flag(x.country) + ' ' + x.country),
      h('td', null, h('button', { class: 'btn sm', onclick: async () => { await api('/admin/sources/' + encodeURIComponent(x.domain), { method: 'PATCH', body: { enabled: x.enabled === false } }); load(); } }, x.enabled === false ? 'Off' : 'On')),
      h('td', null, h('button', { class: 'btn sm danger', 'aria-label': 'Remove ' + x.domain, onclick: async () => { await api('/admin/sources/' + encodeURIComponent(x.domain), { method: 'DELETE' }); load(); } }, 'Remove')))))));
  }
  load();
}

async function adminJobs(body) {
  const box = h('div');
  body.append(box);
  const run = async job => { try { await api('/admin/run', { method: 'POST', body: { job } }); toast('Started'); refresh(); } catch (e) { toast(e.message); } };
  async function refresh() {
    let s;
    try { s = await api('/admin/status'); } catch (_) { return; }
    const j = s.job; const pct = j.total ? Math.round(100 * j.done / j.total) : 0;
    clear(box).append(
      h('div', { class: 'panel' },
        h('div', null, h('b', null, `${s.counts.working} working`), ` of ${s.counts.total} known · ${s.counts.published} published · ${s.counts.pending} waiting for review`),
        h('div', { class: 'small muted' }, `Last daily run: ${ago(s.lastDaily)}`),
        j.running ? h('div', null, h('div', { class: 'progress' }, h('i', { style: `width:${pct}%` })), h('div', { class: 'small' }, `${j.phase}: ${j.done}/${j.total}`), h('div', { class: 'row-actions' }, h('button', { class: 'btn danger', onclick: async () => { await api('/admin/stop', { method: 'POST' }); refresh(); } }, 'Stop scan'))) :
          h('div', { class: 'row-actions' },
            h('button', { class: 'btn primary', onclick: () => run('daily') }, 'Run full daily scan'),
            h('button', { class: 'btn', onclick: () => run('retest') }, 'Re-test all hosts'),
            h('button', { class: 'btn', onclick: () => run('discover') }, 'Find new hosts'),
            h('button', { class: 'btn', onclick: () => run('deep') }, 'Deep subdomain scan'))),
      h('div', { class: 'panel' }, h('b', null, 'Recent runs'), s.runs.length ? h('table', { class: 't' }, s.runs.slice().reverse().map(r => h('tr', null, h('td', null, ago(r.t)), h('td', null, r.kind), h('td', null, r.skipped ? 'skipped (offline)' : `${r.up} up, ${r.down} down, ${r.fresh} new`)))) : h('p', { class: 'muted small' }, 'No runs yet.')),
      h('div', { class: 'panel' }, h('b', null, 'Log'), h('div', { class: 'log' }, s.logs.slice().reverse().map(l => h('div', null, new Date(l.t).toLocaleTimeString() + '  ' + l.m)))));
  }
  await refresh();
  state.jobTimer = setInterval(refresh, 3000);
}

async function adminCloud(body) {
  const origin = location.origin || '';
  const fmtLeft = ms => { if (ms <= 0) return 'expired'; const d = Math.floor(ms / 864e5), hh = Math.floor(ms % 864e5 / 36e5), m = Math.floor(ms % 36e5 / 6e4); return d ? `${d}d ${hh}h` : hh ? `${hh}h ${m}m` : `${m} min`; };
  const f = { host: '', port: '443', user: '', password: '', sni: '', payload: '', note: '' };
  const sf = (label, key, ph) => h('div', null, h('label', { class: 'f' }, label), h('input', { type: 'text', placeholder: ph || '', autocapitalize: 'none', value: f[key], oninput: e => { f[key] = e.target.value; } }));
  const name = h('input', { type: 'text', placeholder: 'e.g. Friends pack', maxlength: '60', 'aria-label': 'Name' });
  const links = h('textarea', { placeholder: 'vless://...\nvmess://...\ntrojan://...', 'aria-label': 'VPN links' });
  const num = h('input', { type: 'number', value: '1', min: '1', 'aria-label': 'Duration' });
  const unit = h('select', { 'aria-label': 'Unit' }, [['minutes', 'minutes'], ['hours', 'hours'], ['days', 'days']].map(([v, l]) => h('option', { value: v, selected: v === 'days' }, l)));
  const quick = (label, n, u) => h('button', { class: 'btn sm', style: 'margin:6px 6px 0 0', onclick: () => { num.value = String(n); unit.value = u; } }, label);
  const first = h('input', { type: 'checkbox', id: 'cfirst' });
  const maxOpens = h('input', { type: 'number', min: '1', placeholder: 'no limit', 'aria-label': 'Open limit' });
  const result = h('div'), list = h('div');
  const ssh = h('details', { class: 'panel', style: 'margin:10px 0 0' }, h('summary', null, 'Add an SSH profile (HA Tunnel and similar)'),
    sf('Server', 'host', 'server.example.com or an IP'), h('div', { class: 'two' }, sf('Port', 'port', '443'), sf('Username', 'user')), sf('Password', 'password'), sf('SNI (bug host)', 'sni', 'bug.example.com'),
    h('label', { class: 'f' }, 'Payload (optional)'), h('textarea', { 'aria-label': 'Payload', style: 'min-height:60px', oninput: e => { f.payload = e.target.value; } }), sf('Note (optional)', 'note'));
  const create = async () => {
    try {
      const payload = { name: name.value, links: links.value, duration: { value: num.value, unit: unit.value }, startOnFirstUse: first.checked, maxOpens: maxOpens.value || null };
      if (f.host || f.user || f.password) payload.ssh = Object.assign({}, f);
      const c = await api('/admin/clouds', { method: 'POST', body: payload });
      const url = origin + '/c/' + c.token;
      clear(result).append(h('div', { class: 'panel' }, h('b', null, 'Cloud config created'), h('pre', { class: 'code' }, url),
        h('div', { class: 'small muted' }, c.expiresAt ? 'Expires ' + new Date(c.expiresAt).toLocaleString() : 'The timer starts when an app first opens the link.'),
        h('div', { class: 'row-actions' }, h('button', { class: 'btn primary', onclick: () => copy(url) }, 'Copy link'),
          c.links ? h('button', { class: 'btn', onclick: () => copy(url + '?f=clash') }, 'Copy Clash link') : null,
          c.links ? h('button', { class: 'btn', onclick: () => copy(url + '?f=singbox') }, 'Copy sing-box link') : null),
        h('p', { class: 'small muted' }, 'Paste the link as a subscription URL in v2rayNG, NekoBox, Hiddify and similar apps. People who open it in a browser see a readable page. Opening it there does not use it up.')));
      loadList();
    } catch (e) { clear(result).append(h('div', { class: 'err' }, e.message)); }
  };
  body.append(h('div', { class: 'panel' }, h('b', null, 'Create cloud config'),
    h('p', { class: 'small muted' }, 'Hosts your VPN config at a private link that stops working when the timer runs out.'),
    h('label', { class: 'f' }, 'Name'), name, h('label', { class: 'f' }, 'VPN links (vless, vmess, trojan), one per line'), links, ssh,
    h('label', { class: 'f' }, 'How long should it last?'), h('div', { class: 'two' }, num, unit),
    h('div', null, quick('1 hour', 1, 'hours'), quick('1 day', 1, 'days'), quick('7 days', 7, 'days'), quick('30 days', 30, 'days')),
    h('label', { class: 'f' }, first, ' Start the timer when an app first opens it'),
    h('label', { class: 'f' }, 'Limit how many times apps can open it (optional)'), maxOpens,
    h('div', { class: 'row-actions' }, h('button', { class: 'btn primary', onclick: create }, 'Create cloud config')),
    h('div', { class: 'notice' }, 'Cloud configs live on this server. On a free host that restarts, they disappear. They are not included in backups because they hold your server logins.')), result, list);
  async function loadList() {
    try {
      const rows = await api('/admin/clouds');
      const now = Date.now();
      const act = async (token, body2) => { try { await api('/admin/clouds/' + token, { method: 'POST', body: body2 }); loadList(); } catch (e) { toast(e.message); } };
      clear(list).append(h('div', { class: 'panel' }, h('b', null, `Your cloud configs (${rows.length})`),
        rows.length ? rows.map(c => h('div', { class: 'proto' },
          h('div', null, h('b', null, c.name + ' '), h('span', { class: 'chip ' + (c.status === 'active' ? 'ok' : c.status === 'waiting' ? '' : 'no') }, c.status)),
          h('div', { class: 'small muted' }, [c.status === 'active' ? fmtLeft(c.expiresAt - now) + ' left' : c.status === 'waiting' ? `starts on first use, then ${Math.round(c.durationMin / 60 * 10) / 10} h` : '', `${c.opens}${c.maxOpens ? ' of ' + c.maxOpens : ''} opens`, c.links ? c.links + ' link' + (c.links === 1 ? '' : 's') : '', c.ssh ? 'SSH profile' : ''].filter(Boolean).join(' · ')),
          h('div', { class: 'row-actions' },
            h('button', { class: 'btn sm', onclick: () => copy(origin + '/c/' + c.token) }, 'Copy link'),
            h('button', { class: 'btn sm', onclick: () => act(c.token, { action: 'extend', minutes: 1440 }) }, '+1 day'),
            h('button', { class: 'btn sm', onclick: () => act(c.token, { action: 'extend', minutes: 10080 }) }, '+7 days'),
            h('button', { class: 'btn sm', onclick: () => act(c.token, { action: c.status === 'revoked' ? 'restore' : 'revoke' }) }, c.status === 'revoked' ? 'Restore' : 'Revoke'),
            h('button', { class: 'btn sm danger', onclick: async () => { if (!confirm('Delete this cloud config? The link stops working.')) return; try { await api('/admin/clouds/' + c.token, { method: 'DELETE' }); loadList(); } catch (e) { toast(e.message); } } }, 'Delete')))) : h('p', { class: 'muted small' }, 'None yet.')));
    } catch (e) { clear(list).append(h('div', { class: 'err' }, e.message)); }
  }
  loadList();
}

async function adminSettings(body) {
  const s = await api('/admin/settings');
  const inputs = {};
  const num = (label, key, hint) => { inputs[key] = h('input', { type: 'number', value: String(s[key]) }); return h('div', null, h('label', { class: 'f' }, label), inputs[key], hint ? h('div', { class: 'small muted' }, hint) : null); };
  inputs.carrier = h('input', { type: 'text', value: s.carrier, placeholder: 'Econet' });
  inputs.autoDaily = h('input', { type: 'checkbox', checked: s.autoDaily });
  inputs.zero = h('input', { type: 'checkbox', checked: s.zeroBalanceMode });
  const msg = h('div');
  body.append(h('div', { class: 'panel' }, h('b', null, 'Scanner'),
    h('label', { class: 'f' }, 'Carrier this device is on'), inputs.carrier,
    h('div', { class: 'small muted' }, 'Every test is stamped "Tested on <carrier>". Run Radar on that SIM so approvals reflect real carrier behaviour.'),
    h('label', { class: 'f' }, inputs.zero, ' Zero-balance mode'),
    h('div', { class: 'small muted' }, 'Skips the internet check. Use it when testing on a SIM with no data, so only zero-rated hosts pass.'),
    h('label', { class: 'f' }, inputs.autoDaily, ' Run the daily scan automatically'),
    num('Daily scan hour (0 to 23, device time)', 'retestHour', 'If the device is off or offline at that hour, the scan runs as soon as it is online.'),
    num('Parallel tests', 'concurrency', 'Lower this on weak phones.'), num('Timeout per test (ms)', 'timeoutMs'),
    num('Forget auto-found hosts down for (days)', 'pruneDays'), num('Max new hosts per run', 'maxNewPerRun'), num('Deep scan weekday (0 = Sunday)', 'deepWeekday'),
    msg, h('div', { class: 'row-actions' }, h('button', { class: 'btn primary', onclick: async () => { try { await api('/admin/settings', { method: 'POST', body: { carrier: inputs.carrier.value, autoDaily: inputs.autoDaily.checked, zeroBalanceMode: inputs.zero.checked, retestHour: inputs.retestHour.value, concurrency: inputs.concurrency.value, timeoutMs: inputs.timeoutMs.value, pruneDays: inputs.pruneDays.value, maxNewPerRun: inputs.maxNewPerRun.value, deepWeekday: inputs.deepWeekday.value } }); clear(msg).append(h('div', { class: 'ok-msg' }, 'Saved')); } catch (e) { clear(msg).append(h('div', { class: 'err' }, e.message)); } } }, 'Save settings'))));
  const bmsg = h('div');
  const file = h('input', { type: 'file', accept: '.json,application/json', 'aria-label': 'Backup file' });
  body.append(h('div', { class: 'panel' }, h('b', null, 'Backup and restore'),
    h('p', { class: 'small muted' }, 'Free hosting can wipe your data when it restarts. Download a backup now and then. After a wipe, restore it to get all hosts and Zimbabwe approvals back. The file holds no passwords.'),
    h('div', { class: 'row-actions' }, h('button', { class: 'btn primary', onclick: async () => {
      try {
        const r = await fetch('/api/admin/backup', { headers: { Authorization: 'Bearer ' + state.token } });
        if (!r.ok) throw new Error('Backup failed');
        const blob = await r.blob();
        const a = h('a', { href: URL.createObjectURL(blob), download: 'moon-radar-backup-' + new Date().toISOString().slice(0, 10) + '.json' });
        document.body.append(a); a.click(); a.remove();
        clear(bmsg).append(h('div', { class: 'ok-msg' }, 'Backup downloaded'));
      } catch (e) { clear(bmsg).append(h('div', { class: 'err' }, e.message)); }
    } }, 'Download backup')),
    h('label', { class: 'f' }, 'Restore from a backup file'), file,
    h('div', { class: 'row-actions' }, h('button', { class: 'btn danger', onclick: async () => {
      if (!file.files || !file.files[0]) { clear(bmsg).append(h('div', { class: 'err' }, 'Choose a backup file first')); return; }
      if (!confirm('This replaces all current hosts, approvals and sources with the backup. Continue?')) return;
      try {
        const data = JSON.parse(await file.files[0].text());
        const r = await api('/admin/restore', { method: 'POST', body: data });
        clear(bmsg).append(h('div', { class: 'ok-msg' }, `Restored ${r.hosts} hosts and ${r.sources} sources`));
      } catch (e) { clear(bmsg).append(h('div', { class: 'err' }, e.message)); }
    } }, 'Restore backup')), bmsg));
  const cur = h('input', { type: 'password', autocomplete: 'current-password' }), nxt = h('input', { type: 'password', autocomplete: 'new-password' }), pm = h('div');
  body.append(h('div', { class: 'panel' }, h('b', null, 'Change password'), h('label', { class: 'f' }, 'Current password'), cur, h('label', { class: 'f' }, 'New password (8+ characters)'), nxt, pm,
    h('div', { class: 'row-actions' }, h('button', { class: 'btn', onclick: async () => { try { await api('/admin/password', { method: 'POST', body: { current: cur.value, next: nxt.value } }); state.token = ''; localStorage.removeItem('radar_token'); toast('Password changed. Sign in again.'); route(); } catch (e) { clear(pm).append(h('div', { class: 'err' }, e.message)); } } }, 'Change password'))));
}

// ---------- shell ----------
async function refreshStatus() {
  try {
    state.meta = await api('/meta');
    const m = state.meta;
    clear($('#status')).append(h('div', null, h('span', { class: 'dot' + (m.busy ? ' busy' : '') }), h('b', null, String(m.total)), ' working hosts'), h('div', null, m.lastDaily ? 'Daily test ' + ago(m.lastDaily) : 'Waiting for first scan'));
  } catch (_) { /* offline */ }
}

async function route() {
  clearInterval(state.jobTimer);
  if (ADMIN && !location.hash) { location.hash = '#/admin'; return; }
  const hash = location.hash || '#/';
  document.querySelectorAll('nav.main a').forEach(a => a.removeAttribute('aria-current'));
  const key = hash.startsWith('#/tools') ? 'tools' : hash.startsWith('#/contact') ? 'contact' : (ADMIN && hash.startsWith('#/admin')) ? 'admin' : 'hosts';
  const navEl = document.querySelector(`nav.main a[data-nav=${key}]`);
  if (navEl) navEl.setAttribute('aria-current', 'page');
  await refreshStatus();
  if (!state.meta) return clear(app).append(h('div', { class: 'empty' }, 'Cannot reach the Moon Radar server.'));
  if (key === 'tools') viewTools(); else if (key === 'contact') viewContact(); else if (key === 'admin') viewAdmin(); else viewHosts();
  renderFooter();
}
if (ADMIN && !document.querySelector('nav.main a[data-nav=admin]')) { const a = h('a', { href: '#/admin', 'data-nav': 'admin' }, 'Admin'); document.querySelector('nav.main').append(a); }
window.addEventListener('hashchange', route);
setInterval(refreshStatus, 60000);
route();
