'use strict';
/* Moon Radar front end. No build step, no dependencies. */
const $ = s => document.querySelector(s);
const app = $('#app');
const ADMIN = !!document.querySelector('meta[name=radar-admin]');
const state = { meta: null, filters: { country: null, carrier: '', type: '', sort: 'score', q: '' }, token: localStorage.getItem('radar_token') || '', toolsTab: 'subdomains', adminTab: 'review', jobTimer: null };

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
        h('button', { class: 'btn primary', onclick: () => { dlg.close(); state.toolsTab = 'payload'; state.prefillHost = d.host; location.hash = '#/tools'; route(); } }, 'Payloads and configs'),
        state.token ? h('button', { class: 'btn', onclick: async e => { e.target.disabled = true; try { await api('/admin/hosts/' + encodeURIComponent(d.host), { method: 'POST' }); toast('Re-tested'); openHost(d.host); } catch (err) { toast(err.message); } } }, 'Re-test now') : null,
        h('button', { class: 'btn', onclick: () => dlg.close() }, 'Close'))));
  } catch (e) { clear(body).append(h('div', { class: 'err' }, e.message), h('button', { class: 'btn', onclick: () => dlg.close() }, 'Close')); }
}
$('#sheet').addEventListener('click', e => { if (e.target === $('#sheet')) $('#sheet').close(); });

// ---------- tools ----------
function viewTools() {
  const wrap = h('div');
  const seg = h('div', { class: 'seg', role: 'group', 'aria-label': 'Tool' }, [['subdomains', 'Subdomains'], ['check', 'Check host'], ['payload', 'Payloads']].map(([k, l]) => h('button', { 'aria-pressed': String(state.toolsTab === k), onclick: () => { state.toolsTab = k; viewTools(); } }, l)));
  const body = h('div');
  wrap.append(seg, body);
  clear(app).append(wrap);
  ({ subdomains: toolSubdomains, check: toolCheck, payload: toolPayload })[state.toolsTab](body);
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

// ---------- admin ----------
function viewAdmin() {
  if (!state.token) return adminLogin();
  const tabs = [['review', 'Review'], ['hosts', 'Hosts'], ['sources', 'Sources'], ['jobs', 'Scans'], ['settings', 'Settings']];
  const seg = h('div', { class: 'tabs', role: 'group' }, tabs.map(([k, l]) => h('button', { class: 'tab', 'aria-pressed': String(state.adminTab === k), onclick: () => { state.adminTab = k; viewAdmin(); } }, l)),
    h('button', { class: 'tab', onclick: () => { state.token = ''; localStorage.removeItem('radar_token'); route(); } }, 'Sign out'));
  const body = h('div');
  clear(app).append(seg, body);
  clearInterval(state.jobTimer);
  ({ review: adminReview, hosts: adminHosts, sources: adminSources, jobs: adminJobs, settings: adminSettings })[state.adminTab](body);
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
  const key = hash.startsWith('#/tools') ? 'tools' : (ADMIN && hash.startsWith('#/admin')) ? 'admin' : 'hosts';
  const navEl = document.querySelector(`nav.main a[data-nav=${key}]`);
  if (navEl) navEl.setAttribute('aria-current', 'page');
  await refreshStatus();
  if (!state.meta) return clear(app).append(h('div', { class: 'empty' }, 'Cannot reach the Moon Radar server.'));
  if (key === 'tools') viewTools(); else if (key === 'admin') viewAdmin(); else viewHosts();
}
if (ADMIN && !document.querySelector('nav.main a[data-nav=admin]')) { const a = h('a', { href: '#/admin', 'data-nav': 'admin' }, 'Admin'); document.querySelector('nav.main').append(a); }
window.addEventListener('hashchange', route);
setInterval(refreshStatus, 60000);
route();
