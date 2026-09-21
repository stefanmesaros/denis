'use strict';
// All network-derived strings (hostnames, vendors, mDNS names, alert summaries…)
// are attacker controlled. Never use innerHTML with them: build nodes and set
// textContent.

const $ = (id) => document.getElementById(id);

// Every API call goes through here: it adds the CSRF header to state-changing
// requests and reacts centrally to "not signed in" / "password must change".
const rawFetch = window.fetch.bind(window);
window.fetch = async (input, init = {}) => {
  const url = typeof input === 'string' ? input : input.url;
  const method = (init.method || 'GET').toUpperCase();
  if (method !== 'GET') init = { ...init, headers: { 'X-Denis': '1', ...(init.headers || {}) } };
  const r = await rawFetch(input, { credentials: 'same-origin', ...init });
  // a wrong password or code typed into a form is a 401 too, but it is not the end of the session
  if (url.startsWith('/api/') && !/^\/api\/auth\/(login|mfa|password|totp)/.test(url)) {
    if (r.status === 401) onUnauthenticated();
    else if (r.status === 403) r.clone().json().then((j) => { if (j.code === 'must_change') onMustChange(); else if (j.code === 'mfa_required') onMustEnrol(); }).catch(() => {});
  }
  return r;
};

const RANK = { viewer: 1, editor: 2, admin: 3 };
/** Does the signed-in user have at least this role? (The server enforces it; this only hides buttons.) */
const can = (role) => !!(state.me && RANK[state.me.role] >= RANK[role]);
const state = {
  assets: [], events: [], alerts: [], agents: [], status: null, me: null, options: null,
  tab: 'assets', sort: 'last_seen', asc: false, selected: null,
};

function el(tag, props = {}, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === 'class') n.className = v; else if (k === 'text') n.textContent = v; else if (k.includes('-')) n.setAttribute(k, v); /* data-* and aria-* are attributes */ else n[k] = v;
  }
  for (const k of kids) if (k != null) n.append(k);
  return n;
}

const now = () => (state.status ? state.status.now : Date.now() / 1000);
const fmtTime = (ts) => ts ? new Date(ts * 1000).toLocaleString(locale()) : '—';
function span(secs) {
  secs = Math.max(0, secs);
  if (secs < 60) return Math.floor(secs) + 's';
  if (secs < 3600) return Math.floor(secs / 60) + 'm';
  if (secs < 86400) return Math.floor(secs / 3600) + 'h';
  return Math.floor(secs / 86400) + 'd';
}
const ago = (ts) => (ts ? tr('{t} ago', { t: span(now() - ts) }) : '—');
const mb = (b) => (b / 1e6).toFixed(b >= 1e8 ? 0 : 1) + ' MB';

// ---------------------------------------------------------------- devices

function isOnline(a) {
  if (!state.status) return false;
  // Every alive host is refreshed by the ARP sweep; allow two missed sweeps.
  return a.last_seen >= state.status.now - (state.status.sweep_interval_secs * 2 + 60);
}

// Machine-generated names (UUIDs, 32-hex ids) that a human would not recognise.
const UUID = /^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{32})$/i;
// Apple devices advertise <uuid>.local; prefer any human-readable name.
const name = (a) => a.display_name || [...a.hostnames, ...(a.fingerprint.mdns_names || [])].find((h) => !UUID.test(h)) || '';
const vendor = (a) => a.vendor || (a.randomized_mac ? tr('(private MAC)') : '');
const portsText = (a) => a.open_ports.map((p) => p.port + (p.service ? '/' + p.service : '')).join(', ');

function siteName(agentId) {
  if (!agentId) return tr('local');
  const ag = state.agents.find((g) => g.id === agentId);
  return ag ? ag.name : agentId;
}
const assetById = (id) => state.assets.find((a) => a.id === id);
const deviceLabel = (a, fallback) => (a ? (name(a) || a.ip || a.mac) : fallback);

/** A risk factor arrives as "+10 Remote Desktop (RDP) is open": keep the points, translate the words. */
function translateFactor(f) {
  const m = /^(\+\d+) (.*)$/.exec(f);
  if (!m) return tr(f);
  const [, pts, why] = m;
  let x = /^(iot|camera) devices are commonly left unpatched$/.exec(why);
  if (x) return pts + ' ' + tr('{type} devices are commonly left unpatched', { type: tr(x[1]) });
  x = /^(\d+) unacknowledged alerts in the last two weeks$/.exec(why);
  if (x) return pts + ' ' + tr('{n} unacknowledged alerts in the last two weeks', { n: x[1] });
  return pts + ' ' + tr(why);
}

/** Status notes from the collector are English sentences; one carries an error text. */
function translateNote(n) {
  const m = /^sweep failed: ([\s\S]*)$/.exec(n);
  return m ? tr('sweep failed: {error}', { error: m[1] }) : tr(n);
}

const riskTag = (a) => el('span', { class: 'sev ' + a.risk.level, text: a.risk.score, title: a.risk.factors.map(translateFactor).join('\n') || tr('no risk factors') });

/** The device icon in a small rounded badge. */
const iconBadge = (a, size = 18) => el('span', { class: 'iconbadge', title: tr(a.device_type) }, icon(iconFor(a), size));

const sorters = {
  risk: (a) => a.risk.score,
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
  const m = a.meta || {};
  const hay = [a.ip, a.mac, vendor(a), a.hostnames.join(' '), a.display_name, a.device_type, a.os_guess, portsText(a), siteName(a.agent_id), m.owner, m.serial_number, m.asset_tag, m.location, m.department, m.zone, m.status, (m.tags || []).join(' ')].join(' ').toLowerCase();
  return q.toLowerCase().split(/\s+/).every((t) => hay.includes(t));
}

const multiSite = () => state.agents.length > 0;

const inSite = (a, site) => !site || site === '__all' || (site === '__local' ? !a.agent_id : a.agent_id === site);

/** A device nobody has looked at yet (the review queue). Hand-entered devices count as reviewed. */
const needsReview = (a) => !(a.meta && (a.meta.reviewed || a.meta.manual)) && !a.is_self;

function renderAssets() {
  const q = $('search').value.trim();
  const onlyOnline = $('only-online').checked;
  const onlyReview = $('only-review').checked;
  const site = $('site').value;
  const key = sorters[state.sort];
  const rows = state.assets.filter((a) =>
    matches(a, q) && (!onlyOnline || isOnline(a)) && (!onlyReview || needsReview(a)) && inSite(a, site));
  const pending = state.assets.filter(needsReview).length;
  $('review-count').textContent = pending ? '(' + pending + ')' : '';
  $('review-all').hidden = !(onlyReview && rows.length && can('editor'));
  $('review-all').onclick = async () => {
    if (!confirm(tr('Mark the {n} devices shown as known?', { n: rows.length }))) return;
    const r = await api('POST', '/api/assets/review', { ids: rows.map((a) => a.id) });
    if (!r.ok) showMessage(tr('Could not save'), el('p', { text: apiError(r) }));
    refresh();
  };
  rows.sort((a, b) => {
    const x = key(a), y = key(b);
    return (x < y ? -1 : x > y ? 1 : 0) * (state.asc ? 1 : -1);
  });
  const showSite = multiSite();
  for (const c of document.querySelectorAll('.site-col')) c.hidden = !showSite;
  const body = $('assets-table').tBodies[0];
  body.replaceChildren(...rows.map((a) => el('tr', { onclick: () => showDetail(a.id) },
    el('td', {}, el('span', { class: 'dot' + (isOnline(a) ? ' on' : ''), title: isOnline(a) ? tr('online') : tr('not seen recently') })),
    showSite ? el('td', { text: siteName(a.agent_id) }) : null,
    el('td', {}, riskTag(a)),
    el('td', { class: 'mono', text: a.ip || '—' }),
    el('td', { class: 'mono', text: a.mac }),
    el('td', { text: vendor(a) }),
    el('td', { class: 'namecell' }, iconBadge(a), el('span', { text: name(a) }), a.meta && a.meta.manual ? el('span', { class: 'tag', text: tr('manual') }) : null, needsReview(a) && now() - a.first_seen < 14 * 86400 ? el('span', { class: 'tag new', title: tr('joined recently and nobody has reviewed it'), text: tr('new') }) : null, a.is_self ? el('span', { class: 'tag self', text: a.agent_id ? tr('agent host') : tr('this device') }) : null),
    el('td', {}, el('span', { class: 'tag', text: tr(a.device_type) })),
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
  sel.hidden = !multiSite() || !['assets', 'topology', 'trends'].includes(state.tab);
  if (!multiSite()) return;
  const opts = [['__all', tr('All sites')], ['__local', tr('Local')], ...state.agents.map((g) => [g.id, g.name])];
  const sig = JSON.stringify(opts);
  if (sel.dataset.sig !== sig) {
    const cur = sel.value;
    sel.replaceChildren(...opts.map(([v, t]) => el('option', { value: v, text: t })));
    sel.value = opts.some(([v]) => v === cur) ? cur : '__all';
    sel.dataset.sig = sig;
  }
}

// ----------------------------------------------------------------- alerts

const sevTag = (e) => el('span', { class: 'sev ' + e.severity, text: tr(e.severity) });

function renderAlerts() {
  const showAcked = $('show-acked').checked;
  const rows = state.alerts.filter((e) => showAcked || !e.acked);
  const body = $('alerts-table').tBodies[0];
  body.replaceChildren(...rows.map((e) => {
    const a = assetById(e.asset_id);
    const d = e.raw_details || {};
    const site = e.agent_id ? ' · ' + siteName(e.agent_id) : '';
    return el('tr', { class: e.acked ? 'acked' : '', onclick: () => showAlert(e, a) },
      el('td', { text: ago(e.timestamp), title: fmtTime(e.timestamp) }),
      el('td', {}, sevTag(e), ' ' + e.score),
      el('td', {}, el('span', { class: 'tag', text: e.type })),
      el('td', { text: deviceLabel(a, '#' + e.asset_id) + site }),
      el('td', { class: 'wrap' }, el('div', { text: d.summary || '' }),
        (d.reasons || []).length ? el('div', { class: 'why', text: d.reasons.join(' · ') }) : null),
      el('td', {}, el('button', {
        type: 'button', text: e.acked ? tr('Undo') : tr('Acknowledge'),
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
    banner.textContent = tr('Learning: new devices and destinations are learned, not alerted on, for another {time}. Unusually large transfers are only flagged once a device has enough history.', { time: span(s.learning_ends_at - s.now) });
  } else if (s && s.mode !== 'agent' && s.mode !== 'viewer') {
    banner.hidden = false;
    banner.textContent = tr('Detecting. Alerts score 0–100; anything under {min} is only logged.', { min: s.min_score }) + ' ' + (s.flows_enabled ? tr('Traffic rules are active for devices whose traffic crosses this interface.') : tr('Traffic rules (new destination, volume) are off: start with --flows.'));
  } else {
    banner.hidden = true;
  }
}

async function ack(id, acked) {
  await fetch('/api/alerts/' + id + (acked ? '/ack' : '/unack'), { method: 'POST', headers: { 'X-Denis': '1' } });
  refresh();
}

/** An alert in full: what happened, why it scored what it did, and what to do about it. */
function showAlert(e, a) {
  const d = e.raw_details || {};
  const advice = state.options && state.options.advice && state.options.advice[e.type];
  const nodes = [
    el('p', {}, sevTag(e), ' ' + tr('score {n}', { n: e.score }) + ' · ' + e.type + ' · ' + fmtTime(e.timestamp)),
    el('p', { text: d.summary || '' }),
    a ? el('p', { class: 'muted', text: tr('Device: {name}', { name: deviceLabel(a, '#' + e.asset_id) + ' (' + a.mac + ')' }) }) : null,
    (d.reasons || []).length ? el('div', {}, el('b', { text: tr('Why this score') }), el('ul', {}, ...d.reasons.map((r) => el('li', { text: translateFactor(r) })))) : null,
    advice ? el('div', {}, el('b', { text: tr('What to do') }), el('p', { text: tr(advice) })) : null,
    a ? el('button', { type: 'button', text: tr('Open device'), onclick: () => { $('msg-dialog').close(); showDetail(a.id); } }) : null,
  ];
  showMessage(tr('Alert'), ...nodes);
}

function renderEvents() {
  const body = $('events-table').tBodies[0];
  body.replaceChildren(...state.events.map((e) => {
    const a = assetById(e.asset_id);
    const d = e.raw_details || {};
    return el('tr', { onclick: () => showAlert(e, a) },
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
      el('td', { text: tr('local') }), el('td', { text: s.mode === 'master' ? tr('master (embedded collector)') : tr('this machine') }),
      el('td', { class: 'mono', text: s.interface }), el('td', { class: 'mono', text: s.subnet }),
      el('td', { text: local }), el('td', { text: s.version }), el('td', { text: tr('now') })));
  }
  for (const g of state.agents) {
    const online = now() - g.last_report_at < 120;
    rows.push(el('tr', {},
      el('td', {}, el('span', { class: 'dot' + (online ? ' on' : ''), title: online ? tr('reporting') : tr('not reporting') })),
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
  if (!s) { box.textContent = tr('connecting…'); return; }
  const parts = [
    [tr('mode'), s.mode === 'viewer' ? tr('viewer') : s.mode],
    [tr('iface'), s.interface + ' ' + s.subnet],
    [tr('devices'), s.asset_count],
    [tr('sweep'), s.sweeping ? tr('running…') : s.passive_only ? tr('passive only') : ago(s.last_sweep_finished)],
    [tr('frames'), s.frames_matched],
  ];
  // OpenObserve export health: a stalled export must be visible, not silent.
  for (const x of s.exports || []) parts.push([x.target.split(':')[0] === 'udp' || x.target.startsWith('tcp') ? 'syslog' : tr('export'), x.last_error ? tr('FAILING') : x.last_ok ? tr('ok {t}', { t: ago(x.last_ok) }) : tr('starting')]);
  box.replaceChildren(...parts.flatMap(([k, v], i) => [i ? ' · ' : '', k + ' ', el('b', { text: String(v) })]));
  if (s.notes.length) box.append(el('div', { text: translateNote(s.notes[0]) }));
  for (const x of s.exports || []) if (x.last_error) box.append(el('div', { class: 'form-error', text: tr('Export to {target}: {error}', { target: x.target, error: x.last_error }) }));
  $('scan').disabled = s.passive_only;
  $('scan').title = s.passive_only ? tr('Disabled in passive-only mode') : tr('Run an ARP sweep and port scan now');
}

// ----------------------------------------------------------------- detail

async function showDetail(id) {
  state.selected = id;
  const a = assetById(id);
  if (!a) return;
  const fp = a.fingerprint;
  const m = a.meta || {};
  const row = (k, v) => (v == null || v === '' || (Array.isArray(v) && !v.length)) ? [] : [el('dt', { text: k }), el('dd', { text: Array.isArray(v) ? v.join(', ') : String(v) })];
  const list = (items) => el('ul', {}, ...items.map((t) => el('li', { text: t })));
  const sig = fp.tcp_sig ? `ttl ${fp.tcp_sig.ttl}, window ${fp.tcp_sig.window}, options ${fp.tcp_sig.options}` : '';
  const dl = (rows) => el('dl', {}, ...rows.flat());

  let bl = null, hist = [];
  try {
    const r = await fetch('/api/assets/' + id + '/baseline');
    if (r.ok) bl = await r.json();
    const h = await fetch('/api/assets/' + id + '/history');
    if (h.ok) hist = await h.json();
  } catch (e) { /* offline: show without baseline/history */ }
  const plugged = await connectedTo(id); // which switch port it is plugged into, when a switch says
  const mine = state.alerts.filter((e) => e.asset_id === id).slice(0, 8);

  const baselineNodes = bl ? [
    dl([
      row(tr('Observed since'), fmtTime(bl.observed_since)),
      row(tr('Destinations'), bl.destination_count),
      row(tr('Outbound per bucket'), bl.volume.n ? `${mb(bl.volume.mean)} ± ${mb(bl.volume.std)} (${bl.volume.n} samples)` : ''),
      row(tr('Ports'), Object.entries(bl.ports).sort((x, y) => y[1] - x[1]).slice(0, 8).map(([p]) => p)),
    ]),
    el('h3', { text: tr('Recent destinations') }),
    list(bl.destinations.slice(0, 10).map((d) => `${d.ip}  ·  last ${ago(d.last_seen)}  ·  ${mb(d.bytes)}`)),
    el('h3', { text: tr('Active hours (local time)') }),
    hoursChart(bl.active_hours),
  ] : [el('div', { class: 'muted', text: tr('No traffic baseline yet. It is built from flow accounting (--flows) for traffic that crosses the monitoring interface.') })];

  const warranty = a.warranty ? ` (${a.warranty.state === 'expired' ? tr('expired {d} d ago', { d: -a.warranty.days }) : a.warranty.state === 'expiring' ? tr('expires in {d} d', { d: a.warranty.days }) : tr('ok')})` : '';
  const custom = Object.entries(m.custom || {}).map(([k, v]) => [k, v]);
  const infoRows = [
    row(tr('Status'), m.status && tr(m.status)), row(tr('Criticality'), m.criticality && tr(m.criticality)), row(tr('Owner'), m.owner), row(tr('Department'), m.department),
    row(tr('Location'), m.location), row(tr('Zone'), m.zone), row(tr('Purdue level'), m.purdue_level),
    row(tr('Asset tag'), m.asset_tag), row(tr('Serial number'), m.serial_number), row(tr('Model'), m.model), row(tr('Manufacturer'), m.manufacturer),
    row(tr('Supplier'), m.supplier), row(tr('Purchased'), [m.purchase_date, m.purchase_price].filter(Boolean).join(' · ')),
    row(tr('Warranty until'), m.warranty_expires ? m.warranty_expires + warranty : ''), row(tr('Tags'), m.tags),
    ...custom.map(([k, v]) => row(k, v)), row(tr('Notes'), m.notes),
  ];
  const detected = a.detected && (a.detected.device_type !== a.device_type || a.detected.os_guess !== a.os_guess);

  // (`replaceChildren(null)` would print the word "null", so absent sections are filtered out)
  $('detail-body').replaceChildren(...[
    el('div', { class: 'detail-head' }, iconBadge(a, 30),
      el('div', {}, el('h2', { text: name(a) || a.ip || a.mac }),
        el('div', { class: 'muted', text: tr(a.device_type) + (a.os_guess ? ' · ' + a.os_guess : '') + (a.agent_id ? ' · ' + tr('site {name}', { name: siteName(a.agent_id) }) : '') }))),
    can('editor') ? el('div', { class: 'detail-actions' },
      el('button', { type: 'button', class: 'primary', text: tr('Edit asset'), onclick: () => openAssetForm(a) }),
      needsReview(a) ? el('button', { type: 'button', text: tr('Mark as known'), onclick: async () => { await api('POST', '/api/assets/review', { ids: [a.id] }); await refresh(); showDetail(a.id); } }) : null,
      m.manual && can('admin') ? el('button', { type: 'button', text: tr('Delete'), onclick: () => deleteAsset(a) }) : null) : null,
    detected ? el('div', { class: 'muted small', text: tr('Discovery guessed: {what}', { what: tr(a.detected.device_type) + (a.detected.os_guess ? ' / ' + a.detected.os_guess : '') }) }) : null,
    el('h3', { text: tr('Asset information') }),
    infoRows.flat().length ? dl(infoRows) : el('div', { class: 'muted', text: can('editor') ? tr('Nothing entered yet. Use "Edit asset" to add an owner, serial number, location, warranty…') : tr('Nothing entered yet.') }),
    el('h3', { text: tr('Risk {score} ({level})', { score: a.risk.score, level: tr(a.risk.level) }) }),
    a.risk.factors.length ? list(a.risk.factors.map(translateFactor)) : el('div', { class: 'muted', text: tr('No risk factors.') }),
    ...(mine.length ? [el('h3', { text: tr('Alerts') }), list(mine.map((e) => `[${e.severity} ${e.score}] ${e.type}: ${(e.raw_details || {}).summary || ''}`))] : []),
    el('h3', { text: tr('Baseline') }),
    ...baselineNodes,
    el('h3', { text: tr('Identity') }),
    dl([
      row('MAC', a.mac + (a.randomized_mac ? ' ' + tr('(private/randomised)') : '')),
      row(tr('Vendor'), a.vendor),
      row(tr('Connected to'), plugged),
      row(tr('SSH banner'), fp.identity && fp.identity['banner.ssh']),
      row(tr('Web server banner'), fp.identity && fp.identity['banner.http']),
      row(tr('FTP banner'), fp.identity && fp.identity['banner.ftp']),
      row(tr('Mail server banner'), fp.identity && fp.identity['banner.smtp']),
      row(tr('Hostnames'), a.hostnames),
      row(tr('First seen'), fmtTime(a.first_seen)),
      row(tr('Last seen'), a.last_seen ? fmtTime(a.last_seen) : tr('never (entered by hand)')),
    ]),
    el('h3', { text: tr('IP history') }),
    a.ip_history.length ? list(a.ip_history.slice().sort((x, y) => y.last_seen - x.last_seen).map((r) => `${r.ip}  (${fmtTime(r.first_seen)} → ${fmtTime(r.last_seen)})`)) : el('div', { class: 'muted', text: tr('none') }),
    el('h3', { text: tr('Open ports') + (a.ports_scanned_at ? ' · ' + tr('scanned {t}', { t: ago(a.ports_scanned_at) }) : '') }),
    a.open_ports.length ? list(a.open_ports.map((p) => `${p.port}/${p.proto} ${p.service || ''}`)) : el('div', { class: 'muted', text: a.ports_scanned_at ? tr('none of the scanned ports are open') : tr('not scanned yet') }),
    el('h3', { text: tr('Fingerprint evidence') }),
    dl([
      row(tr('DHCP vendor class'), fp.dhcp_vendor_class),
      row(tr('DHCP options'), fp.dhcp_param_list),
      row(tr('mDNS services'), fp.mdns_services),
      row(tr('mDNS names'), fp.mdns_names),
      row(tr('mDNS models'), fp.mdns_models),
      row(tr('SSDP server'), fp.ssdp_server),
      row(tr('SSDP types'), fp.ssdp_types),
      row(tr('TCP SYN'), sig),
      row(tr('TTL seen'), fp.ttl),
    ]),
    el('h3', { text: tr('Why this guess') }),
    a.guess_reasons.length ? list(a.guess_reasons) : el('div', { class: 'muted', text: tr('not enough evidence yet') }),
    el('h3', { text: tr('Change history') }),
    hist.length ? list(hist.map(historyLine)) : el('div', { class: 'muted', text: tr('No manual changes yet.') }),
  ].filter(Boolean));
  $('detail').hidden = false;
}

/** One human-readable line per audit entry. */
function historyLine(h) {
  const when = fmtTime(h.ts);
  if (h.action === 'asset.create') return `${when} · ${h.user} created this asset`;
  const ch = (h.detail && h.detail.changes) || [];
  const txt = ch.map((c) => `${c.field}: ${c.old == null ? '∅' : c.old} → ${c.new == null ? '∅' : c.new}`).join('; ');
  return `${when} · ${h.user} changed ${txt || h.action}`;
}

function hoursChart(hours) {
  const max = Math.max(1, ...hours);
  return el('div', {},
    el('div', { class: 'hours' }, ...hours.map((n, h) => el('i', { title: `${h}:00: ${n} buckets`, style: `height:${Math.max(3, (n / max) * 100)}%` }))),
    el('div', { class: 'hours-axis' }, el('span', { text: '0' }), el('span', { text: '6' }), el('span', { text: '12' }), el('span', { text: '18' }), el('span', { text: '23' })));
}

// --------------------------------------------------------------- topology

const SVGNS = 'http://www.w3.org/2000/svg';
function svg(tag, attrs = {}, ...kids) {
  const n = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
  for (const k of kids) if (k != null) n.append(k);
  return n;
}

function renderTopology() {
  const site = $('site').value;
  const openAlerts = new Set(state.alerts.filter((e) => !e.acked).map((e) => e.asset_id));
  const groups = new Map();
  for (const a of state.assets.filter((x) => inSite(x, site))) {
    const k = siteName(a.agent_id);
    if (!groups.has(k)) groups.set(k, []);
    groups.get(k).push(a);
  }
  const colors = { none: 'var(--off)', low: 'var(--accent)', medium: 'var(--warn)', high: '#dc2626' };
  $('topo-legend').replaceChildren(...['none', 'low', 'medium', 'high'].map((l) =>
    el('span', {}, el('i', { style: 'background:' + colors[l] }), l === 'none' ? tr('no risk') : tr(l))));

  const panels = [...groups.entries()].map(([siteLabel, devices]) => {
    const gw = devices.filter((a) => a.is_gateway);
    const rest = devices.filter((a) => !a.is_gateway)
      .sort((x, y) => (x.device_type < y.device_type ? -1 : x.device_type > y.device_type ? 1 : (x.ip || '') < (y.ip || '') ? -1 : 1));
    const C = 280, S = 560;
    const kids = [];
    // rings, filled in order so devices of one type sit together
    const positions = [];
    let ring = 0, placed = 0;
    while (placed < rest.length) {
      const r = 95 + ring * 62;
      const cap = Math.max(6, Math.floor((2 * Math.PI * r) / 34));
      const n = Math.min(cap, rest.length - placed);
      for (let i = 0; i < n; i++) {
        const ang = (2 * Math.PI * i) / n - Math.PI / 2 + ring * 0.35;
        positions.push([C + r * Math.cos(ang), C + r * Math.sin(ang)]);
      }
      placed += n; ring++;
    }
    const centre = gw[0];
    for (const [x, y] of positions) kids.push(svg('line', { x1: C, y1: C, x2: x, y2: y }));
    const hub = svg('circle', { cx: C, cy: C, r: 17, class: 'node r-' + (centre ? centre.risk.level : 'none') },
      svg('title', {}, document.createTextNode(centre ? tr('{site} gateway {ip}', { site: siteLabel, ip: centre.ip || '' }) : tr('network (gateway not identified)'))));
    if (centre) hub.addEventListener('click', () => showDetail(centre.id));
    kids.push(hub);
    kids.push(svg('text', { x: C, y: C + 30 }, document.createTextNode(centre ? (centre.ip || tr('gateway')) : tr('network'))));
    rest.forEach((a, i) => {
      const [x, y] = positions[i];
      const c = svg('circle', { cx: x, cy: y, r: 10, class: 'node r-' + a.risk.level, opacity: isOnline(a) ? 1 : 0.4 },
        svg('title', {}, document.createTextNode(`${name(a) || tr('unnamed')} · ${a.ip || a.mac} · ${tr(a.device_type)} · ${tr('risk {n}', { n: a.risk.score })}`)));
      c.addEventListener('click', () => showDetail(a.id));
      kids.push(c);
      if (openAlerts.has(a.id)) kids.push(svg('circle', { cx: x + 8, cy: y - 8, r: 3.5, fill: '#dc2626' }));
      kids.push(svg('text', { x, y: y + 21 }, document.createTextNode((name(a) || (a.ip || '').split('.').pop() || '?').slice(0, 12))));
    });
    return el('div', { class: 'topo-site' }, el('h3', { text: siteLabel + ' · ' + tr('{n} devices', { n: devices.length }) }),
      svg('svg', { viewBox: `0 0 ${S} ${S}`, role: 'img', 'aria-label': tr('Topology of {site}', { site: siteLabel }) }, ...kids));
  });
  $('topo').replaceChildren(...panels);
}
// ---------------------------------------------------------------------- OT

// device types that belong to industrial networks; the server's list (options.ot_types) is authoritative
const OT_TYPES_FALLBACK = ['plc', 'hmi', 'rtu', 'scada server', 'industrial device'];
const otTypes = () => (state.options && state.options.ot_types) || OT_TYPES_FALLBACK;
const isOt = (a) => Object.keys((a.fingerprint && a.fingerprint.ot) || {}).length > 0 || otTypes().includes(a.device_type) || !!(a.meta && a.meta.purdue_level);

/** The most useful self-reported identity strings, in a readable order. */
function identityText(a) {
  const id = (a.fingerprint && a.fingerprint.identity) || {};
  const pick = ['enip.product_name', 'enip.vendor', 'enip.revision', 'enip.serial', 'bacnet.vendor', 'bacnet.device_instance',
    'profinet.station_name', 'profinet.vendor', 'lldp.system_name', 'lldp.system_description', 'cdp.platform'];
  return pick.filter((k) => id[k]).map((k) => id[k]).slice(0, 4).join(' · ');
}

async function loadOt() {
  const r = await fetch('/api/conversations');
  if (r.ok) state.convs = await r.json();
  renderOt();
}

function renderOt() {
  const convs = state.convs || [];
  const devices = state.assets.filter(isOt).sort((x, y) => (x.meta.purdue_level || '9').localeCompare(y.meta.purdue_level || '9') || (x.ip || '').localeCompare(y.ip || ''));
  const protos = [...new Set(convs.map((c) => c.protocol))].sort();
  const writers = new Set(convs.filter((c) => c.writes > 0 || c.controls > 0).map((c) => c.client.id));
  const otAlerts = state.alerts.filter((e) => !e.acked && e.type.startsWith('ot_')).length;
  const card = (n, label, cls) => el('div', { class: 'card' + (cls ? ' ' + cls : '') }, el('b', { text: String(n) }), label);
  $('ot-cards').replaceChildren(
    card(devices.length, tr('industrial devices')), card(protos.length, tr('industrial protocols seen')),
    card(convs.length, tr('communication paths')), card(writers.size, tr('devices that write / control')),
    card(otAlerts, tr('open OT alerts'), otAlerts ? 'bad' : ''));

  $('ot-devices').tBodies[0].replaceChildren(...devices.map((a) => el('tr', { onclick: () => showDetail(a.id) },
    el('td', { class: 'namecell' }, iconBadge(a), el('span', { text: name(a) || a.ip || a.mac })),
    el('td', { class: 'mono', text: a.ip || '—' }),
    el('td', { text: a.meta.purdue_level ? 'L' + a.meta.purdue_level : '—' }),
    el('td', { text: a.meta.zone || '' }),
    el('td', {}, el('span', { class: 'tag', text: tr(a.device_type) })),
    el('td', {}, ...Object.entries((a.fingerprint && a.fingerprint.ot) || {}).map(([p, r]) =>
      el('span', { class: 'tag', title: (r.server ? tr('answers requests') + ' ' : '') + (r.client ? tr('sends requests') : ''), text: p + (r.server && r.client ? ' S/C' : r.server ? ' S' : ' C') }))),
    el('td', { class: 'wrap', text: identityText(a) }),
    el('td', { text: ago(a.last_seen) }))));
  $('ot-empty').hidden = devices.length > 0;

  const sel = $('ot-proto');
  const sig = protos.join(',');
  if (sel.dataset.sig !== sig) {
    const cur = sel.value;
    sel.replaceChildren(el('option', { value: '', text: tr('All protocols') }), ...protos.map((p) => el('option', { value: p, text: p })));
    sel.value = protos.includes(cur) ? cur : '';
    sel.dataset.sig = sig;
  }
  const who = (p) => p.name || p.ip || p.mac;
  const rows = convs
    .filter((c) => (!sel.value || c.protocol === sel.value) && (!$('ot-risky').checked || c.writes > 0 || c.controls > 0))
    .sort((x, y) => (y.controls - x.controls) || (y.writes - x.writes) || (y.last_seen - x.last_seen));
  $('ot-matrix').tBodies[0].replaceChildren(...rows.map((c) => el('tr', { class: c.controls ? 'row-bad' : c.writes ? 'row-warn' : '' },
    el('td', { text: who(c.client) + (c.client.purdue_level ? ' (L' + c.client.purdue_level + ')' : '') }),
    el('td', { class: 'muted', text: '→' }),
    el('td', { text: who(c.server) + (c.server.purdue_level ? ' (L' + c.server.purdue_level + ')' : '') }),
    el('td', {}, el('span', { class: 'tag', text: c.protocol })),
    el('td', { text: c.reads }), el('td', { text: c.writes }),
    el('td', { text: c.controls ? c.controls + (c.note ? ' · ' + c.note : '') : '0' }),
    el('td', { class: 'wrap' }, ...Object.entries(c.commands || {}).sort((a, b) => b[1] - a[1]).slice(0, 6).map(([cmd, n]) => el('span', {
      class: 'chip' + (can('admin') ? ' clickable' : ''), title: can('admin') ? tr('Be told when this is sent: create a watch') : String(n), text: cmd + ' ×' + n,
      onclick: can('admin') ? (ev) => { ev.stopPropagation(); watchFor(c, cmd); } : null,
    }))),
    el('td', { text: ago(c.last_seen), title: fmtTime(c.last_seen) }))));
}
$('ot-proto').onchange = renderOt;
$('ot-risky').onchange = renderOt;

// ------------------------------------------------------------------ trends

function chart(title, big, points, key, kind, fmt) {
  const W = 360, H = 130, L = 34, B = 16, T = 6, R = 6;
  const vals = points.map((p) => p[key]);
  const max = Math.max(1, ...vals);
  const x = (i) => L + (points.length < 2 ? 0 : (i * (W - L - R)) / (points.length - 1));
  const y = (v) => T + (1 - v / max) * (H - T - B);
  const kids = [
    svg('line', { class: 'grid', x1: L, x2: W - R, y1: y(0), y2: y(0) }),
    svg('line', { class: 'grid', x1: L, x2: W - R, y1: y(max), y2: y(max) }),
    svg('text', { class: 'axis', x: L - 4, y: y(max) + 3, 'text-anchor': 'end' }, document.createTextNode(fmt(max))),
    svg('text', { class: 'axis', x: L - 4, y: y(0) + 3, 'text-anchor': 'end' }, document.createTextNode('0')),
  ];
  if (points.length) {
    const t0 = new Date(points[0].ts * 1000), t1 = new Date(points[points.length - 1].ts * 1000);
    const f = (d) => d.toLocaleString(locale(), { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
    kids.push(svg('text', { class: 'axis', x: L, y: H - 3 }, document.createTextNode(f(t0))));
    kids.push(svg('text', { class: 'axis', x: W - R, y: H - 3, 'text-anchor': 'end' }, document.createTextNode(f(t1))));
  }
  if (kind === 'bars') {
    const bw = Math.max(1.5, (W - L - R) / Math.max(points.length, 1) - 1);
    points.forEach((p, i) => { if (p[key] > 0) kids.push(svg('rect', { class: 'bar' + (key === 'alerts' ? ' alert' : ''), x: x(i) - bw / 2, y: y(p[key]), width: bw, height: y(0) - y(p[key]) })); });
  } else if (points.length > 1) {
    const pts = points.map((p, i) => `${x(i)},${y(p[key])}`).join(' ');
    kids.push(svg('polygon', { class: 'area', points: `${x(0)},${y(0)} ${pts} ${x(points.length - 1)},${y(0)}` }));
    kids.push(svg('polyline', { class: 'line', points: pts }));
  }
  return el('div', { class: 'chart' }, el('h3', { text: title }), el('div', { class: 'big', text: big }),
    points.length ? svg('svg', { viewBox: `0 0 ${W} ${H}`, role: 'img', 'aria-label': title }, ...kids) : el('div', { class: 'muted', text: tr('No samples yet. They are recorded every 5 minutes.') }));
}

const fmtBytes = (b) => (b >= 1e9 ? (b / 1e9).toFixed(1) + ' GB' : b >= 1e6 ? (b / 1e6).toFixed(1) + ' MB' : b >= 1e3 ? (b / 1e3).toFixed(0) + ' kB' : b + ' B');

async function loadTrends() {
  const site = $('site').value;
  const agent = !site || site === '__all' ? '' : '&agent=' + encodeURIComponent(site === '__local' ? 'local' : site);
  let data;
  try {
    data = await fetch('/api/trends?hours=' + $('range').value + agent).then((r) => r.json());
  } catch (e) { return; }
  const pts = data.points;
  const last = pts[pts.length - 1];
  const sum = (k) => pts.reduce((n, p) => n + p[k], 0);
  $('trends').replaceChildren(
    chart(tr('Devices online'), last ? tr('{n} of {total}', { n: last.devices_online, total: last.devices_total }) : '–', pts, 'devices_online', 'line', String),
    chart(tr('Sent outside the network'), fmtBytes(sum('bytes_out')), pts, 'bytes_out', 'bars', fmtBytes),
    chart(tr('Alerts raised'), String(sum('alerts')), pts, 'alerts', 'bars', String));
  $('trends-note').textContent = pts.length ? tr('{n} points, {step} each.', { n: pts.length, step: span(data.step_secs) }) + (state.status && !state.status.flows_enabled ? ' ' + tr('Traffic is only counted with --flows.') : '') : '';
}

// ------------------------------------------------------------------ shell

// --------------------------------------------------------------- findings

async function loadCompliance() {
  const r = await fetch('/api/compliance');
  if (!r.ok) return;
  const c = await r.json();
  $('compliance-note').textContent = tr(c.disclaimer);
  $('compliance-measures').replaceChildren(...c.measures.map((m) => el('div', { class: 'measure' },
    el('div', {}, el('b', { text: m.percent + '%' }), ' ' + tr(m.label)),
    el('div', { class: 'bar' }, el('i', { style: 'width:' + m.percent + '%' })),
    el('div', { class: 'muted small', text: tr(m.detail, m.vars) }))));
  const label = { in_place: [tr('in place'), 'ok'], partial: [tr('partly'), 'warn'], not_in_place: [tr('not in place'), 'bad'] };
  $('compliance-table').tBodies[0].replaceChildren(...c.controls.map((k) => el('tr', {},
    el('td', {}, el('b', { text: k.reference }), el('div', { text: tr(k.title) })),
    el('td', {}, el('div', { text: tr(k.evidence) }), el('div', { class: 'muted small', text: tr(k.note, k.vars) })),
    el('td', {}, el('span', { class: 'pill ' + label[k.status][1], text: label[k.status][0] })))));
}

function setTab(t) {
  state.tab = t;
  for (const b of document.querySelectorAll('.tab')) b.classList.toggle('active', b.dataset.tab === t);
  for (const v of ['assets', 'alerts', 'findings', 'rules', 'compliance', 'reports', 'health', 'alerting', 'topology', 'ot', 'trends', 'events', 'agents', 'users', 'settings', 'audit', 'account']) $('view-' + v).hidden = t !== v;
  $('search').hidden = $('online-label').hidden = $('review-label').hidden = t !== 'assets';
  if (t !== 'assets') $('review-all').hidden = true;
  // export and import links belong to the lists they export
  document.querySelector('.exports').hidden = !['assets', 'alerts', 'events'].includes(t);
  $('acked-label').hidden = t !== 'alerts';
  $('range').hidden = t !== 'trends';
  renderSiteFilter();
  if (t === 'topology') { if (topoMode === 'physical') renderPhysical(); else renderTopology(); }
  if (t === 'trends') loadTrends();
  if (t === 'ot') loadOt();
  if (t === 'findings') loadFindings();
  if (t === 'rules') loadRules();
  if (t === 'compliance') loadCompliance();
  if (t === 'reports') loadReports();
  if (t === 'health') loadHealth();
  if (t === 'alerting') loadAlerting();
  if (t === 'users') { renderUsers(); renderApiTokens(); }
  if (t === 'settings') { initBrandingForm(); loadUpdateBox(); loadTlsBox(); loadSecurityBox(); loadSwitchesBox(); loadVulnBox(); }
  if (t === 'audit') renderAudit();
  if (t === 'account') renderAccount();
  if (t === 'agents') renderTokens();
}

async function refresh() {
  if (!state.me) return;
  if (!state.options) loadOptions(); // in case the first request was refused
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
  if (state.tab === 'topology') renderTopology();
  if (state.tab === 'trends') loadTrends();
  if (state.tab === 'ot') loadOt();
  loadFindings();
  loadMaintenanceBanner();
  loadDemoBanner();
  loadUpdateBanner();
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
$('only-review').onchange = renderAssets;
$('site').onchange = () => { renderAssets(); if (state.tab === 'topology') renderTopology(); if (state.tab === 'trends') loadTrends(); };
$('range').onchange = loadTrends;
$('show-acked').onchange = renderAlerts;
$('close').onclick = () => { $('detail').hidden = true; state.selected = null; };
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') $('close').onclick(); });
document.addEventListener('visibilitychange', () => { if (!document.hidden) refresh(); });
$('scan').onclick = async () => {
  $('scan').disabled = true;
  await fetch('/api/scan', { method: 'POST', headers: { 'X-Denis': '1' } });
  setTimeout(refresh, 1500);
  setTimeout(() => { $('scan').disabled = !!(state.status && state.status.passive_only); }, 5000);
};

