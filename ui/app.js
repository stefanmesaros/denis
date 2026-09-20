'use strict';
// All network-derived strings (hostnames, vendors, mDNS names, alert summaries…)
// are attacker controlled. Never use innerHTML with them: build nodes and set
// textContent.

const $ = (id) => document.getElementById(id);
const state = {
  assets: [], events: [], alerts: [], agents: [], status: null,
  tab: 'assets', sort: 'last_seen', asc: false, selected: null,
};

function el(tag, props = {}, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === 'class') n.className = v; else if (k === 'text') n.textContent = v; else n[k] = v;
  }
  for (const k of kids) if (k != null) n.append(k);
  return n;
}

const now = () => (state.status ? state.status.now : Date.now() / 1000);
const fmtTime = (ts) => ts ? new Date(ts * 1000).toLocaleString() : '—';
function span(secs) {
  secs = Math.max(0, secs);
  if (secs < 60) return Math.floor(secs) + 's';
  if (secs < 3600) return Math.floor(secs / 60) + 'm';
  if (secs < 86400) return Math.floor(secs / 3600) + 'h';
  return Math.floor(secs / 86400) + 'd';
}
const ago = (ts) => (ts ? span(now() - ts) + ' ago' : '—');
const mb = (b) => (b / 1e6).toFixed(b >= 1e8 ? 0 : 1) + ' MB';

// ---------------------------------------------------------------- devices

function isOnline(a) {
  if (!state.status) return false;
  // Every alive host is refreshed by the ARP sweep; allow two missed sweeps.
  return a.last_seen >= state.status.now - (state.status.sweep_interval_secs * 2 + 60);
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
// Apple devices advertise <uuid>.local; prefer any human-readable name.
const name = (a) => [...a.hostnames, ...(a.fingerprint.mdns_names || [])].find((h) => !UUID.test(h)) || '';
const vendor = (a) => a.vendor || (a.randomized_mac ? '(private MAC)' : '');
const portsText = (a) => a.open_ports.map((p) => p.port + (p.service ? '/' + p.service : '')).join(', ');

function siteName(agentId) {
  if (!agentId) return 'local';
  const ag = state.agents.find((g) => g.id === agentId);
  return ag ? ag.name : agentId;
}
const assetById = (id) => state.assets.find((a) => a.id === id);
const deviceLabel = (a, fallback) => (a ? (name(a) || a.ip || a.mac) : fallback);

const sorters = {
  online: (a) => (isOnline(a) ? 1 : 0),
  site: (a) => siteName(a.agent_id).toLowerCase(),
  ip: (a) => (a.ip || '').split('.').map((x) => x.padStart(3, '0')).join('.'),
  mac: (a) => a.mac,
  vendor: (a) => vendor(a).toLowerCase(),
  name: (a) => name(a).toLowerCase(),
  device_type: (a) => a.device_type,
  os_guess: (a) => a.os_guess || '',
  ports: (a) => a.open_ports.length,
  last_seen: (a) => a.last_seen,
};

function matches(a, q) {
  if (!q) return true;
  const hay = [a.ip, a.mac, vendor(a), a.hostnames.join(' '), a.device_type, a.os_guess, portsText(a), siteName(a.agent_id)].join(' ').toLowerCase();
  return q.toLowerCase().split(/\s+/).every((t) => hay.includes(t));
}

const multiSite = () => state.agents.length > 0;

const inSite = (a, site) => !site || site === '__all' || (site === '__local' ? !a.agent_id : a.agent_id === site);

function renderAssets() {
  const q = $('search').value.trim();
  const onlyOnline = $('only-online').checked;
  const site = $('site').value;
  const key = sorters[state.sort];
  const rows = state.assets.filter((a) =>
    matches(a, q) && (!onlyOnline || isOnline(a)) && inSite(a, site));
  rows.sort((a, b) => {
    const x = key(a), y = key(b);
    return (x < y ? -1 : x > y ? 1 : 0) * (state.asc ? 1 : -1);
  });
  const showSite = multiSite();
  for (const c of document.querySelectorAll('.site-col')) c.hidden = !showSite;
  const body = $('assets-table').tBodies[0];
  body.replaceChildren(...rows.map((a) => el('tr', { onclick: () => showDetail(a.id) },
    el('td', {}, el('span', { class: 'dot' + (isOnline(a) ? ' on' : ''), title: isOnline(a) ? 'online' : 'not seen recently' })),
    showSite ? el('td', { text: siteName(a.agent_id) }) : null,
    el('td', { class: 'mono', text: a.ip || '—' }),
    el('td', { class: 'mono', text: a.mac }),
    el('td', { text: vendor(a) }),
    el('td', {}, el('span', { text: name(a) }), a.is_self ? el('span', { class: 'tag self', text: a.agent_id ? 'agent host' : 'this device' }) : null),
    el('td', {}, el('span', { class: 'tag', text: a.device_type })),
    el('td', { text: a.os_guess || '' }),
    el('td', { class: 'ports mono', text: portsText(a), title: portsText(a) }),
    el('td', { text: ago(a.last_seen), title: fmtTime(a.last_seen) }))));
  $('empty').hidden = state.assets.length > 0;
  $('count-assets').textContent = '(' + rows.length + (rows.length !== state.assets.length ? '/' + state.assets.length : '') + ')';
  for (const th of $('assets-table').tHead.rows[0].cells) {
    th.classList.toggle('sorted', th.dataset.sort === state.sort);
    th.classList.toggle('asc', th.dataset.sort === state.sort && state.asc);
  }
}

function renderSiteFilter() {
  const sel = $('site');
  sel.hidden = !multiSite() || state.tab !== 'assets';
  if (!multiSite()) return;
  const opts = [['__all', 'All sites'], ['__local', 'Local'], ...state.agents.map((g) => [g.id, g.name])];
  const sig = JSON.stringify(opts);
  if (sel.dataset.sig !== sig) {
    const cur = sel.value;
    sel.replaceChildren(...opts.map(([v, t]) => el('option', { value: v, text: t })));
    sel.value = opts.some(([v]) => v === cur) ? cur : '__all';
    sel.dataset.sig = sig;
  }
}

// ----------------------------------------------------------------- alerts

const sevTag = (e) => el('span', { class: 'sev ' + e.severity, text: e.severity });

function renderAlerts() {
  const showAcked = $('show-acked').checked;
  const rows = state.alerts.filter((e) => showAcked || !e.acked);
  const body = $('alerts-table').tBodies[0];
  body.replaceChildren(...rows.map((e) => {
    const a = assetById(e.asset_id);
    const d = e.raw_details || {};
    const site = e.agent_id ? ' · ' + siteName(e.agent_id) : '';
    return el('tr', { class: e.acked ? 'acked' : '', onclick: () => a && showDetail(a.id) },
      el('td', { text: ago(e.timestamp), title: fmtTime(e.timestamp) }),
      el('td', {}, sevTag(e), ' ' + e.score),
      el('td', {}, el('span', { class: 'tag', text: e.type })),
      el('td', { text: deviceLabel(a, '#' + e.asset_id) + site }),
      el('td', { class: 'wrap' }, el('div', { text: d.summary || '' }),
        (d.reasons || []).length ? el('div', { class: 'why', text: d.reasons.join(' · ') }) : null),
      el('td', {}, el('button', {
        type: 'button', text: e.acked ? 'Undo' : 'Acknowledge',
        onclick: (ev) => { ev.stopPropagation(); ack(e.id, !e.acked); },
      })));
  }));
  $('no-alerts').hidden = rows.length > 0;
  const n = state.status ? state.status.alerts_unacked : 0;
  $('count-alerts').hidden = !n;
  $('count-alerts').textContent = n;

  const s = state.status;
  const banner = $('learning');
  if (s && s.learning_ends_at && s.learning_ends_at > s.now) {
    banner.hidden = false;
    banner.textContent = 'Learning: new devices and destinations are learned, not alerted on, for another ' + span(s.learning_ends_at - s.now) + '. Unusually large transfers are only flagged once a device has enough history.';
  } else if (s && s.mode !== 'agent') {
    banner.hidden = false;
    banner.textContent = 'Detecting. Alerts score 0–100; anything under ' + s.min_score + ' is only logged. ' + (s.flows_enabled ? 'Traffic rules are active for devices whose traffic crosses this interface.' : 'Traffic rules (new destination, volume) are off: start with --flows.');
  } else {
    banner.hidden = true;
  }
}

async function ack(id, acked) {
  await fetch('/api/alerts/' + id + (acked ? '/ack' : '/unack'), { method: 'POST', headers: { 'X-Netscope': '1' } });
  refresh();
}

function renderEvents() {
  const body = $('events-table').tBodies[0];
  body.replaceChildren(...state.events.map((e) => {
    const a = assetById(e.asset_id);
    const d = e.raw_details || {};
    return el('tr', { onclick: () => a && showDetail(a.id) },
      el('td', { text: fmtTime(e.timestamp) }),
      el('td', {}, el('span', { class: 'tag', text: e.type })),
      el('td', {}, sevTag(e)),
      el('td', { text: e.score || '' }),
      el('td', { class: 'mono', text: a ? a.mac : '#' + e.asset_id }),
      el('td', { class: 'muted', text: d.summary || '' }));
  }));
}

// ----------------------------------------------------------------- sites

function renderAgents() {
  const local = state.assets.filter((a) => !a.agent_id).length;
  const s = state.status;
  const rows = [];
  if (s) {
    rows.push(el('tr', {},
      el('td', {}, el('span', { class: 'dot on' })),
      el('td', { text: 'local' }), el('td', { text: s.mode === 'master' ? 'master (embedded collector)' : 'this machine' }),
      el('td', { class: 'mono', text: s.interface }), el('td', { class: 'mono', text: s.subnet }),
      el('td', { text: local }), el('td', { text: s.version }), el('td', { text: 'now' })));
  }
  for (const g of state.agents) {
    const online = now() - g.last_report_at < 120;
    rows.push(el('tr', {},
      el('td', {}, el('span', { class: 'dot' + (online ? ' on' : ''), title: online ? 'reporting' : 'not reporting' })),
      el('td', { text: g.name }), el('td', { text: g.site || '' }), el('td', { class: 'mono', text: g.id }),
      el('td', { class: 'mono', text: g.subnet }),
      el('td', { text: state.assets.filter((a) => a.agent_id === g.id).length }),
      el('td', { text: g.version }), el('td', { text: ago(g.last_report_at), title: fmtTime(g.last_report_at) })));
  }
  $('agents-table').tBodies[0].replaceChildren(...rows);
  $('count-agents').textContent = '(' + rows.length + ')';
}

// ----------------------------------------------------------------- status

function renderStatus() {
  const s = state.status;
  const box = $('status');
  if (!s) { box.textContent = 'connecting…'; return; }
  const parts = [
    ['mode', s.mode],
    ['iface', s.interface + ' ' + s.subnet],
    ['devices', s.asset_count],
    ['sweep', s.sweeping ? 'running…' : s.passive_only ? 'passive only' : ago(s.last_sweep_finished)],
    ['frames', s.frames_matched],
  ];
  box.replaceChildren(...parts.flatMap(([k, v], i) => [i ? ' · ' : '', k + ' ', el('b', { text: String(v) })]));
  if (s.notes.length) box.append(el('div', { text: s.notes[0] }));
  $('scan').disabled = s.passive_only;
  $('scan').title = s.passive_only ? 'Disabled in passive-only mode' : 'Run an ARP sweep and port scan now';
}

// ----------------------------------------------------------------- detail

async function showDetail(id) {
  state.selected = id;
  const a = assetById(id);
  if (!a) return;
  const fp = a.fingerprint;
  const row = (k, v) => (v == null || v === '' || (Array.isArray(v) && !v.length)) ? [] : [el('dt', { text: k }), el('dd', { text: Array.isArray(v) ? v.join(', ') : String(v) })];
  const list = (items) => el('ul', {}, ...items.map((t) => el('li', { text: t })));
  const sig = fp.tcp_sig ? `ttl ${fp.tcp_sig.ttl}, window ${fp.tcp_sig.window}, options ${fp.tcp_sig.options}` : '';
  const dl = (rows) => el('dl', {}, ...rows.flat());

  let bl = null;
  try {
    const r = await fetch('/api/assets/' + id + '/baseline');
    if (r.ok) bl = await r.json();
  } catch (e) { /* offline: show without baseline */ }
  const mine = state.alerts.filter((e) => e.asset_id === id).slice(0, 8);

  const baselineNodes = bl ? [
    dl([
      row('Observed since', fmtTime(bl.observed_since)),
      row('Destinations', bl.destination_count),
      row('Outbound per bucket', bl.volume.n ? `${mb(bl.volume.mean)} ± ${mb(bl.volume.std)} (${bl.volume.n} samples)` : ''),
      row('Ports', Object.entries(bl.ports).sort((x, y) => y[1] - x[1]).slice(0, 8).map(([p]) => p)),
    ]),
    el('h3', { text: 'Recent destinations' }),
    list(bl.destinations.slice(0, 10).map((d) => `${d.ip}  ·  last ${ago(d.last_seen)}  ·  ${mb(d.bytes)}`)),
    el('h3', { text: 'Active hours (UTC)' }),
    hoursChart(bl.active_hours),
  ] : [el('div', { class: 'muted', text: 'No traffic baseline yet. It is built from flow accounting (--flows) for traffic that crosses the monitoring interface.' })];

  $('detail-body').replaceChildren(
    el('h2', { text: name(a) || a.ip || a.mac }),
    el('div', { class: 'muted', text: a.device_type + (a.os_guess ? ' · ' + a.os_guess : '') + (a.agent_id ? ' · site ' + siteName(a.agent_id) : '') }),
    ...(mine.length ? [el('h3', { text: 'Alerts' }), list(mine.map((e) => `[${e.severity} ${e.score}] ${e.type}: ${(e.raw_details || {}).summary || ''}`))] : []),
    el('h3', { text: 'Baseline' }),
    ...baselineNodes,
    el('h3', { text: 'Identity' }),
    dl([
      row('MAC', a.mac + (a.randomized_mac ? ' (private/randomised)' : '')),
      row('Vendor', a.vendor),
      row('Hostnames', a.hostnames),
      row('First seen', fmtTime(a.first_seen)),
      row('Last seen', fmtTime(a.last_seen)),
    ]),
    el('h3', { text: 'IP history' }),
    list(a.ip_history.slice().sort((x, y) => y.last_seen - x.last_seen).map((r) => `${r.ip}  (${fmtTime(r.first_seen)} → ${fmtTime(r.last_seen)})`)),
    el('h3', { text: 'Open ports' + (a.ports_scanned_at ? ' · scanned ' + ago(a.ports_scanned_at) : '') }),
    a.open_ports.length ? list(a.open_ports.map((p) => `${p.port}/${p.proto} ${p.service || ''}`)) : el('div', { class: 'muted', text: a.ports_scanned_at ? 'none of the scanned ports are open' : 'not scanned yet' }),
    el('h3', { text: 'Fingerprint evidence' }),
    dl([
      row('DHCP vendor class', fp.dhcp_vendor_class),
      row('DHCP options', fp.dhcp_param_list),
      row('mDNS services', fp.mdns_services),
      row('mDNS names', fp.mdns_names),
      row('mDNS models', fp.mdns_models),
      row('SSDP server', fp.ssdp_server),
      row('SSDP types', fp.ssdp_types),
      row('TCP SYN', sig),
      row('TTL seen', fp.ttl),
    ]),
    el('h3', { text: 'Why this guess' }),
    a.guess_reasons.length ? list(a.guess_reasons) : el('div', { class: 'muted', text: 'not enough evidence yet' }));
  $('detail').hidden = false;
}

function hoursChart(hours) {
  const max = Math.max(1, ...hours);
  return el('div', {},
    el('div', { class: 'hours' }, ...hours.map((n, h) => el('i', { title: `${h}:00 UTC: ${n} buckets`, style: `height:${Math.max(3, (n / max) * 100)}%` }))),
    el('div', { class: 'hours-axis' }, el('span', { text: '0' }), el('span', { text: '6' }), el('span', { text: '12' }), el('span', { text: '18' }), el('span', { text: '23' })));
}

// ------------------------------------------------------------------ shell

function setTab(t) {
  state.tab = t;
  for (const b of document.querySelectorAll('.tab')) b.classList.toggle('active', b.dataset.tab === t);
  for (const v of ['assets', 'alerts', 'events', 'agents']) $('view-' + v).hidden = t !== v;
  $('search').hidden = $('online-label').hidden = t !== 'assets';
  $('acked-label').hidden = t !== 'alerts';
  renderSiteFilter();
}

async function refresh() {
  try {
    const j = (u) => fetch(u).then((r) => r.json());
    const [status, assets, events, alerts, agents] = await Promise.all([
      j('/api/status'), j('/api/assets'), j('/api/events?limit=200'), j('/api/alerts?limit=200'), j('/api/agents'),
    ]);
    Object.assign(state, { status, assets, events, alerts, agents });
  } catch (e) {
    state.status = null;
  }
  renderStatus();
  renderSiteFilter();
  renderAssets();
  renderAlerts();
  renderEvents();
  renderAgents();
  if (state.selected != null && !$('detail').hidden) showDetail(state.selected);
}

for (const b of document.querySelectorAll('.tab')) b.onclick = () => setTab(b.dataset.tab);
for (const th of $('assets-table').tHead.rows[0].cells) {
  th.onclick = () => {
    const k = th.dataset.sort;
    state.asc = state.sort === k ? !state.asc : k === 'ip' || k === 'name' || k === 'vendor' || k === 'site';
    state.sort = k;
    renderAssets();
  };
}
$('search').oninput = renderAssets;
$('only-online').onchange = renderAssets;
$('site').onchange = renderAssets;
$('show-acked').onchange = renderAlerts;
$('close').onclick = () => { $('detail').hidden = true; state.selected = null; };
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') $('close').onclick(); });
$('scan').onclick = async () => {
  $('scan').disabled = true;
  await fetch('/api/scan', { method: 'POST', headers: { 'X-Netscope': '1' } });
  setTimeout(refresh, 1500);
  setTimeout(() => { $('scan').disabled = !!(state.status && state.status.passive_only); }, 5000);
};

setTab('assets');
refresh();
setInterval(refresh, 5000);
