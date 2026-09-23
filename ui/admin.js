'use strict';
// Sign-in, session handling, dialogs, asset editing, and the administration
// screens (users, agent tokens, audit log). Loaded after app.js, which owns
// `state`, `el`, `fetch` (wrapped) and the render functions used here.

// ------------------------------------------------------------------ helpers

/** JSON request helper: never throws on HTTP errors, returns {ok, status, json}. */
async function api(method, url, body) {
  const init = { method };
  if (body !== undefined) {
    init.headers = { 'Content-Type': typeof body === 'string' ? 'text/csv' : 'application/json' };
    init.body = typeof body === 'string' ? body : JSON.stringify(body);
  }
  try {
    const r = await fetch(url, init);
    let json = null;
    try { json = await r.json(); } catch (e) { /* 204 or non-JSON */ }
    return { ok: r.ok, status: r.status, json };
  } catch (e) {
    return { ok: false, status: 0, json: { error: tr('Cannot reach the server') } };
  }
}
/** Server messages are English; translate the fixed ones, and the two that carry a number. */
function translateError(msg) {
  let m = /^too many attempts; try again in (\d+) seconds$/.exec(msg);
  if (m) return tr('too many attempts; try again in {n} seconds', { n: m[1] });
  m = /^that finding does not apply to device #(\d+)$/.exec(msg);
  if (m) return tr('that finding does not apply to device #{n}', { n: m[1] });
  m = /^password must be at least (\d+) characters$/.exec(msg);
  if (m) return tr('password must be at least {n} characters', { n: m[1] });
  return tr(msg);
}
/** The outcome of an update is an English sentence with values in it: translate its known shapes. */
function translateResult(msg) {
  let m = /^Updated to (.+)\. DENIS is restarting\.$/.exec(msg);
  if (m) return tr('Updated to {version}. DENIS is restarting.', { version: m[1] });
  m = /^The update was not installed and nothing was changed: ([\s\S]*)$/.exec(msg);
  if (m) return tr('The update was not installed and nothing was changed: {error}', { error: m[1] });
  m = /^DENIS (\S+) did not start, so version (\S+) was put back\.(?: The database format had changed, so the backup taken before the update was restored \(the newer one is kept as (.+)\)\.)?$/.exec(msg);
  if (m) {
    return tr('DENIS {to} did not start, so version {from} was put back.', { to: m[1], from: m[2] })
      + (m[3] ? ' ' + tr('The database format had changed, so the backup taken before the update was restored (the newer one is kept as {path}).', { path: m[3] }) : '');
  }
  return tr(msg);
}
const apiError = (r) => (r.json && r.json.error && translateError(r.json.error)) || tr('Request failed ({status})', { status: r.status });

/** A message dialog. `nodes` are DOM nodes (never HTML strings). */
function showMessage(title, ...nodes) {
  // absent sections are passed as null: replaceChildren(null) would print the word "null"
  $('msg-body').replaceChildren(el('h3', { text: title }), ...nodes.filter(Boolean));
  const d = $('msg-dialog');
  if (!d.open) d.showModal();
}
$('msg-ok').onclick = () => $('msg-dialog').close();

/** A secret shown exactly once (temporary password, agent token). */
function showSecret(title, intro, secret, extra) {
  const box = el('code', { class: 'secret', text: secret });
  showMessage(title, el('p', { text: intro }), box,
    el('button', { type: 'button', text: tr('Copy'), onclick: () => navigator.clipboard && navigator.clipboard.writeText(secret) }),
    extra ? el('p', { class: 'muted', text: extra }) : null);
}

function openForm(title, fields, { submitLabel = tr('Save'), onSubmit, cancellable = true } = {}) {
  const form = $('dialog-form');
  const err = el('div', { class: 'form-error', role: 'alert', hidden: true });
  form.replaceChildren(el('h3', { text: title }), ...fields, err,
    el('div', { class: 'dialog-actions' },
      cancellable ? el('button', { type: 'button', text: tr('Cancel'), onclick: () => $('form-dialog').close() }) : null,
      el('button', { type: 'submit', class: 'primary', text: submitLabel })));
  form.onsubmit = async (ev) => {
    ev.preventDefault();
    err.hidden = true;
    const msg = await onSubmit(form);
    if (msg) { err.textContent = msg; err.hidden = false; } else if ($('form-dialog').open) $('form-dialog').close();
  };
  $('form-dialog').oncancel = (ev) => { if (!cancellable) ev.preventDefault(); };
  if (!$('form-dialog').open) $('form-dialog').showModal();
}

const field = (label, input) => el('label', {}, label, input);

// ------------------------------------------------------------------- theme

const THEMES = ['auto', 'light', 'dark'];
function applyTheme(t) {
  if (t === 'auto') document.documentElement.removeAttribute('data-theme');
  else document.documentElement.dataset.theme = t;
  $('theme').textContent = { auto: '◐', light: '☀', dark: '☾' }[t];
  $('theme').title = tr('Colour theme: {theme} (click to change)', { theme: tr(t) });
}
/** The theme this browser chose, else the operator's default (branding), else auto. */
function initTheme(fallback = 'auto') {
  let t = null;
  try { t = localStorage.getItem('denis-theme'); } catch (e) { /* storage blocked */ }
  if (!THEMES.includes(t)) t = THEMES.includes(fallback) ? fallback : 'auto';
  applyTheme(t);
  $('theme').onclick = () => {
    t = THEMES[(THEMES.indexOf(t) + 1) % THEMES.length];
    try { localStorage.setItem('denis-theme', t); } catch (e) { /* ignore */ }
    applyTheme(t);
  };
}

// ------------------------------------------------------------- branding

/**
 * White label: name, accent colour and logo the operator configured. Read from
 * the public /api/branding so it is in place before sign-in. Every value is put
 * in through textContent / style properties / img.src, never HTML.
 */
function applyBranding(b) {
  const name = b.product_name || 'DENIS';
  document.title = name;
  for (const id of ['brand-name']) $(id).textContent = name;
  document.querySelector('#login .brand-name').textContent = name;
  const root = document.documentElement.style;
  if (b.accent) { root.setProperty('--accent', b.accent); root.setProperty('--accent-text', b.accent_text || '#ffffff'); }
  else { root.removeProperty('--accent'); root.removeProperty('--accent-text'); }
  for (const id of ['brand-logo', 'login-logo']) {
    // an operator's own uploaded logo always wins; otherwise DENIS's own mark
    $(id).replaceChildren(el('img', { src: b.logo || 'denis-logo.svg', alt: '' }));
  }
  // the sign-in subtitle: the operator's own message replaces the product's tagline
  $('login-sub').textContent = b.login_message || tr('Device Enumeration & Network Inventory Security');
  state.branding = b;
  applyDefaultLanguage(b.default_language);
}

async function loadBranding() {
  const r = await api('GET', '/api/branding');
  if (r.ok) applyBranding(r.json);
  return r.ok ? r.json : {};
}

function initBrandingForm() {
  const b = state.branding || {};
  $('br-name').value = b.product_name || 'DENIS';
  $('br-accent').value = b.accent || '#2563eb';
  $('br-theme').value = b.theme_default || 'auto';
  $('br-lang').replaceChildren(...Object.entries(LANGS).map(([code, label]) => el('option', { value: code, text: label })));
  $('br-lang').value = b.default_language || 'en';
  $('br-msg').value = b.login_message || '';
  $('br-preview').replaceChildren(b.logo ? el('img', { src: b.logo, alt: tr('Current logo') }) : el('span', { class: 'muted', text: tr('no logo') }));
}

$('branding-form').onsubmit = async (ev) => {
  ev.preventDefault();
  const useDefault = $('br-accent').dataset.reset === '1';
  const r = await api('PUT', '/api/branding', {
    product_name: $('br-name').value, accent: useDefault ? null : $('br-accent').value,
    theme_default: $('br-theme').value, login_message: $('br-msg').value, default_language: $('br-lang').value,
  });
  $('br-status').textContent = r.ok ? tr('Saved.') : apiError(r);
  if (r.ok) { await loadBranding(); initBrandingForm(); }
};
$('br-accent').oninput = () => { $('br-accent').dataset.reset = '0'; };
$('br-accent-reset').onclick = () => { $('br-accent').dataset.reset = '1'; $('br-accent').value = '#2563eb'; $('br-status').textContent = tr('Press Save to use the default colour.'); };

$('br-file').onchange = async () => {
  const f = $('br-file').files[0];
  if (!f) return;
  const res = await fetch('/api/branding/logo', { method: 'PUT', headers: { 'Content-Type': f.type || 'application/octet-stream' }, body: f });
  $('br-file').value = '';
  if (res.ok) { await loadBranding(); initBrandingForm(); $('br-status').textContent = tr('Logo updated.'); }
  else { const j = await res.json().catch(() => ({})); $('br-status').textContent = j.error ? translateError(j.error) : tr('Upload failed ({status}).', { status: res.status }); }
};
$('br-remove').onclick = async () => {
  const res = await fetch('/api/branding/logo', { method: 'DELETE' });
  if (res.ok) { await loadBranding(); initBrandingForm(); $('br-status').textContent = tr('Logo removed.'); }
};

// --------------------------------------------------------------- session

let poller = null;
let healthPoller = null;

function showLogin(message) {
  if (poller) { clearInterval(poller); poller = null; }
  state.me = null;
  // Nothing from the previous session may linger in the DOM.
  Object.assign(state, { assets: [], events: [], alerts: [], agents: [], status: null });
  for (const tb of document.querySelectorAll('tbody')) tb.replaceChildren();
  $('detail').hidden = true;
  $('app').hidden = true;
  $('login').hidden = false;
  $('login-pass').value = '';
  resetLoginCodeStep();
  const e = $('login-error');
  e.hidden = !message;
  e.textContent = message || '';
  $('login-user').focus();
}

/** Called by the fetch wrapper on any 401. */
function onUnauthenticated() {
  if ($('login').hidden) showLogin(tr('Your session has ended. Please sign in again.'));
}

/** Called by the fetch wrapper on 403 {code: must_change}. */
function onMustChange() {
  if (!$('form-dialog').open) openPasswordForm(true);
}

/** Enter the application for the signed-in user in `state.me`. */
async function start() {
  $('login').hidden = true;
  $('app').hidden = false;
  $('whoami').textContent = state.me.username + ' (' + tr(state.me.role) + ')';
  $('tab-users').hidden = !can('admin');
  $('tab-settings').hidden = !can('admin');
  $('tab-audit').hidden = !can('admin');
  $('tab-alerting').hidden = !can('admin');
  $('data-box').hidden = !can('admin');
  $('update-box').hidden = !can('admin');
  $('overview-box').hidden = !can('admin');
  $('license-box').hidden = !can('admin');
  $('interfaces-box').hidden = !can('admin');
  $('tls-box').hidden = !can('admin');
  $('tokens-box').hidden = !can('admin');
  $('branding-box').hidden = !can('admin');
  $('setup-box').hidden = !can('admin');
  $('security-box').hidden = !can('admin');
  $('switches-box').hidden = !can('admin');
  $('vuln-box').hidden = !can('admin');
  for (const b of document.querySelectorAll('#topo-mode button')) b.onclick = () => setTopoMode(b.dataset.mode);
  $('setup-open').onclick = openSetupGuide;
  if (can('admin')) initBrandingForm();
  $('add-asset').hidden = !can('editor');
  $('import-assets').hidden = !can('editor');
  $('scan').hidden = !can('editor');
  await loadOptions();
  initReports();
  initHealth();
  loadHealthBadge();
  setTab('assets');
  await refresh();
  applyHash();
  maybeShowSetupGuide();
  if (poller) clearInterval(poller);
  poller = setInterval(refresh, 10000);
  if (healthPoller) clearInterval(healthPoller);
  healthPoller = setInterval(() => { if (state.tab === 'health') loadHealth(); else loadHealthBadge(); }, 60000);
}

async function boot() {
  initSidebar();
  const b = await loadBranding();
  loadSignInMethods();
  initTheme(b.theme_default);
  const me = await api('GET', '/api/auth/me');
  if (me.ok) {
    state.me = me.json.user;
    if (me.json.must_change) { await start(); onMustChange(); } else { await start(); if (me.json.must_enrol) onMustEnrol(); }
  } else {
    showLogin();
  }
}

$('login-form').onsubmit = async (ev) => {
  ev.preventDefault();
  // the second step, when the password was right and an authenticator app is on
  const r = loginTicket
    ? await api('POST', '/api/auth/mfa', { ticket: loginTicket, code: $('login-code').value })
    : await api('POST', '/api/auth/login', { username: $('login-user').value, password: $('login-pass').value });
  if (!r.ok) {
    const e = $('login-error');
    e.textContent = apiError(r);
    e.hidden = false;
    $('login-pass').value = '';
    $('login-code').value = '';
    return;
  }
  if (r.json.mfa_required) {
    $('login-error').hidden = true;
    showLoginCodeStep(r.json.ticket);
    return;
  }
  resetLoginCodeStep();
  state.me = r.json.user;
  await start();
  if (r.json.must_change) onMustChange();
  else if (r.json.must_enrol) onMustEnrol();
};
$('login-back').onclick = () => { resetLoginCodeStep(); $('login-error').hidden = true; $('login-user').focus(); };

$('logout').onclick = async () => {
  await api('POST', '/api/auth/logout');
  showLogin();
};

function openPasswordForm(forced) {
  const cur = el('input', { type: 'password', autocomplete: 'current-password', required: true });
  const n1 = el('input', { type: 'password', autocomplete: 'new-password', required: true, minLength: 12 });
  const n2 = el('input', { type: 'password', autocomplete: 'new-password', required: true, minLength: 12 });
  openForm(forced ? tr('Choose a new password') : tr('Change password'), [
    forced ? el('p', { class: 'muted', text: tr('Your password was set by an administrator. Choose your own before continuing.') }) : null,
    field(tr('Current password'), cur), field(tr('New password (at least 12 characters)'), n1), field(tr('Repeat new password'), n2),
  ], {
    submitLabel: tr('Change password'),
    cancellable: !forced,
    onSubmit: async () => {
      if (n1.value !== n2.value) return tr('The two new passwords do not match.');
      const r = await api('POST', '/api/auth/password', { current: cur.value, new: n1.value });
      if (!r.ok) return apiError(r);
      const me = await api('GET', '/api/auth/me');
      if (me.ok) state.me = me.json.user;
      await loadOptions(); // the first request after a forced change of password was refused
      await refresh();
      showMessage(tr('Password changed'), el('p', { text: tr('Your other sessions have been signed out.') }));
      return null;
    },
  });
}
$('change-pw').onclick = () => openPasswordForm(false);

// ------------------------------------------------------------ asset editor

const FIELD_DEFS = [
  ['display_name', tr('Name'), 'text'], ['icon', tr('Icon'), 'icon'], ['type_override', tr('Device type'), 'type'],
  ['status', tr('Status'), 'statuses'], ['criticality', tr('Criticality'), 'criticalities'],
  ['owner', tr('Owner'), 'text'], ['department', tr('Department'), 'text'], ['location', tr('Location'), 'text'],
  ['zone', tr('Zone / cell'), 'text'], ['purdue_level', tr('Purdue level (OT)'), 'purdue_levels'],
  ['asset_tag', tr('Asset tag'), 'text'], ['serial_number', tr('Serial number'), 'text'], ['model', tr('Model'), 'text'],
  ['manufacturer', tr('Manufacturer'), 'text'], ['os_override', tr('Operating system'), 'text'], ['supplier', tr('Supplier'), 'text'],
  ['purchase_date', tr('Purchase date'), 'date'], ['purchase_price', tr('Price'), 'text'], ['warranty_expires', tr('Warranty until'), 'date'],
  ['muted_until', tr('Silence notifications until'), 'date'],
  ['tags', tr('Tags (comma separated)'), 'tags'], ['notes', tr('Notes'), 'textarea'],
];

/** Load the lists the forms offer (statuses, criticalities, device types, icons…). Safe to call again. */
async function loadOptions() {
  const o = await api('GET', '/api/meta/options');
  if (o.ok) state.options = o.json;
  return state.options;
}

/** The words shown for an icon or type name: "smart_plug" -> "smart plug", in the chosen language. */
const nameOf = (n) => tr(String(n).replace(/_/g, ' '));

/**
 * The icon chooser: a searchable window with the icons grouped by kind. `onPick(name)` gets the chosen
 * icon name, or '' for "automatic" (the icon that fits the device type).
 */
function openIconModal({ value, autoName, onPick }) {
  const dlg = el('dialog', { class: 'icon-dialog', 'aria-label': tr('Choose an icon') });
  const search = el('input', { type: 'search', class: 'icon-search', placeholder: tr('Search icons…'), 'aria-label': tr('Search icons…') });
  const cats = el('div', { class: 'chips icon-cats' });
  const body = el('div', { class: 'icon-body' });
  let cat = '';
  const known = new Set((state.options && state.options.icons) || ICON_NAMES);
  const groups = ICON_CATEGORIES.map(([title, names]) => [title, names.filter((n) => known.has(n))]);
  const listed = new Set(groups.flatMap(([, names]) => names));
  const other = [...known].filter((n) => !listed.has(n));
  if (other.length) groups.push(['Other', other]);
  const choose = (name) => { dlg.close(); onPick(name); };
  const tile = (name) => el('button', { type: 'button', class: 'icon-tile' + (name === value ? ' selected' : ''), title: name ? nameOf(name) : tr('automatic'), onclick: () => choose(name) },
    icon(name || autoName(), 30), el('span', { text: name ? nameOf(name) : tr('Automatic') }));
  const draw = () => {
    const q = search.value.trim().toLowerCase();
    // an icon is found by its name, its translated name and the device type it stands for ("robot" finds the vacuum)
    const match = (n) => !q || n.replace(/_/g, ' ').includes(q) || nameOf(n).toLowerCase().includes(q)
      || (ICON_TYPES[n] || '').includes(q) || (ICON_TYPES[n] ? nameOf(ICON_TYPES[n]).toLowerCase().includes(q) : false);
    const sections = [];
    if (!q && !cat) sections.push(el('div', { class: 'icon-group' }, el('div', { class: 'group-title', text: tr('Automatic') }), el('div', { class: 'icon-grid' }, tile(''))));
    for (const [title, names] of groups) {
      if (cat && cat !== title) continue;
      const shown = names.filter(match);
      if (shown.length) sections.push(el('div', { class: 'icon-group' }, el('div', { class: 'group-title', text: tr(title) }), el('div', { class: 'icon-grid' }, ...shown.map(tile))));
    }
    body.replaceChildren(...(sections.length ? sections : [el('p', { class: 'muted', text: tr('No icon matches "{q}".', { q: search.value.trim() }) })]));
    cats.replaceChildren(...['', ...groups.map(([t]) => t)].map((t) => el('button', { type: 'button', class: 'chip clickable' + (t === cat ? ' active' : ''), text: t ? tr(t) : tr('All'), onclick: () => { cat = t; draw(); } })));
  };
  search.oninput = draw;
  dlg.append(el('div', { class: 'icon-head' }, el('h3', { text: tr('Choose an icon') }), el('button', { type: 'button', text: tr('Close'), onclick: () => dlg.close() })), search, cats, body);
  dlg.addEventListener('close', () => dlg.remove());
  document.body.append(dlg);
  draw();
  dlg.showModal();
  search.focus();
}

/**
 * The icon row of the asset form: the current icon, its name and a "Change…" button right beside them.
 * Choosing an icon calls `onPick(name)`; "Automatic" uses the icon that fits the device type.
 */
function iconPicker(current, autoIcon, onPick) {
  let value = current || '';
  const summary = el('span', { class: 'icon-current' });
  const draw = () => summary.replaceChildren(icon(value || autoIcon(), 28), el('span', { text: value ? nameOf(value) : tr('automatic ({icon})', { icon: nameOf(autoIcon()) }) }));
  const change = el('button', { type: 'button', text: tr('Change…'), onclick: () => openIconModal({ value, autoName: autoIcon, onPick: (n) => { value = n; draw(); onPick(n); } }) });
  draw();
  return { node: el('div', { class: 'icon-row' }, summary, change), get: () => value, refresh: draw, open: () => change.click() };
}

/** Device types sorted by the words the person reads, plus any custom one already stored on the device. */
function typeOptions(current) {
  const list = ((state.options && state.options.device_types) || []).slice();
  if (current && !list.includes(current)) list.push(current);
  return list.sort((x, y) => nameOf(x).localeCompare(nameOf(y), locale()));
}

/** Create/edit form. `a` is null when creating a new asset. */
async function openAssetForm(a) {
  // the lists may be missing if the first request was refused (a forced password change): fetch them now
  if (!state.options) await loadOptions();
  const meta = a ? (a.meta || {}) : {};
  const inputs = {};
  const rows = [];
  let macInput = null;
  if (!a) {
    macInput = el('input', { placeholder: tr('aa:bb:cc:dd:ee:ff (leave empty if unknown)'), autocomplete: 'off' });
    rows.push(field(tr('MAC address'), macInput));
  }
  const previewAsset = a || { device_type: 'unknown', hostnames: [], meta: {} };
  // what discovery found; "automatic" means: keep following it
  const detectedType = (a && ((a.detected && a.detected.device_type) || a.device_type)) || 'unknown';
  let typeSel = null;
  let iconPick = null;
  const shownType = () => (typeSel ? typeSel.value : meta.type_override) || detectedType;
  const typeNote = el('div', { class: 'muted small', hidden: true });
  for (const [key, label, kind] of FIELD_DEFS) {
    let input;
    const cur = meta[key] || '';
    if (kind === 'icon') {
      // the icon that fits the device type as it is set right now (the type field may change below)
      const autoIcon = () => iconFor({ ...previewAsset, device_type: shownType(), meta: { ...(previewAsset.meta || {}), icon: null } });
      // choosing an icon also sets the device type that goes with it
      const p = iconPicker(meta.icon, autoIcon, (name) => {
        const ty = name && ICON_TYPES[name];
        if (ty && typeSel && typeSel.value !== ty && [...typeSel.options].some((o) => o.value === ty)) {
          typeSel.value = ty;
          typeNote.textContent = tr('Device type set to "{type}" to match the icon. Change it above if that is wrong.', { type: nameOf(ty) });
          typeNote.hidden = false;
        }
        p.refresh();
      });
      iconPick = p;
      inputs[key] = { get: p.get };
      rows.push(el('div', { class: 'field-wide' }, el('span', { class: 'label', text: label }), p.node));
      continue;
    }
    if (kind === 'text') input = el('input', { value: cur, maxLength: 200 });
    else if (kind === 'date') input = el('input', { type: 'date', value: cur });
    else if (kind === 'textarea') input = el('textarea', { value: cur, maxLength: 4000, rows: 3 });
    else if (kind === 'tags') input = el('input', { value: (meta.tags || []).join(', ') });
    else if (kind === 'type') {
      // a list, filled in from discovery ("automatic"); the person can pick another, and the icon follows
      input = el('select', { id: 'asset-type' },
        el('option', { value: '', text: tr('Automatic (detected: {type})', { type: nameOf(detectedType) }) }),
        ...typeOptions(cur).map((t) => el('option', { value: t, text: nameOf(t) })));
      input.value = cur;
      typeSel = input;
      input.onchange = () => { typeNote.hidden = true; if (iconPick) iconPick.refresh(); };
    } else {
      const opts = (state.options && state.options[kind]) || [];
      input = el('select', {}, el('option', { value: '', text: '—' }), ...opts.map((o) => el('option', { value: o, text: tr(o) })));
      input.value = cur;
    }
    inputs[key] = { get: () => (kind === 'tags' ? input.value.split(',').map((t) => t.trim()).filter(Boolean) : input.value.trim()) };
    rows.push(el('div', { class: kind === 'textarea' || kind === 'tags' ? 'field-wide' : '' }, field(label, input), kind === 'type' ? typeNote : null));
  }

  // custom fields: free-form name/value pairs
  const custom = el('div', { class: 'custom-rows' });
  const customState = Object.entries(meta.custom || {}).map(([k, v]) => ({ k, v, orig: k }));
  const drawCustom = () => custom.replaceChildren(...customState.map((c, i) => el('div', { class: 'custom-row' },
    el('input', { value: c.k, placeholder: tr('field name'), maxLength: 40, oninput: (e) => { c.k = e.target.value; } }),
    el('input', { value: c.v, placeholder: tr('value'), maxLength: 500, oninput: (e) => { c.v = e.target.value; } }),
    el('button', { type: 'button', text: '×', title: tr('Remove'), onclick: () => { customState.splice(i, 1); c.removed = true; if (c.orig) removed.push(c.orig); drawCustom(); } }))));
  const removed = [];
  drawCustom();
  rows.push(el('div', { class: 'field-wide' }, el('span', { class: 'label', text: tr('Custom fields') }), custom,
    el('button', { type: 'button', text: tr('+ Add field'), onclick: () => { customState.push({ k: '', v: '', orig: null }); drawCustom(); } })));

  const grid = el('div', { class: 'form-grid' }, ...rows);
  openForm(a ? tr('Edit asset') : tr('Add asset'), [grid], {
    onSubmit: async () => {
      // Send only what changed.
      const patch = {};
      for (const [key, , kind] of FIELD_DEFS) {
        const val = inputs[key].get();
        if (kind === 'tags') {
          if (JSON.stringify(val) !== JSON.stringify(meta.tags || [])) patch.tags = val;
        } else if ((val || '') !== (meta[key] || '')) patch[key] = val === '' ? null : val;
      }
      const cust = {};
      for (const name of removed) if (!customState.some((c) => c.k.trim() === name)) cust[name] = null;
      for (const c of customState) {
        const k = c.k.trim();
        if (k && c.v.trim() !== ((meta.custom || {})[k] || '')) cust[k] = c.v.trim() === '' ? null : c.v.trim();
      }
      if (Object.keys(cust).length) patch.custom = cust;
      if (a) {
        // saving the form means somebody has looked at the device
        if (!meta.reviewed) patch.reviewed = true;
        if (!Object.keys(patch).length) return null;
        const r = await api('PATCH', '/api/assets/' + a.id + '/meta', patch);
        if (!r.ok) return apiError(r);
        await refresh();
        showDetail(a.id);
      } else {
        for (const k of Object.keys(patch)) if (patch[k] === null) delete patch[k];
        if (macInput.value.trim()) patch.mac = macInput.value.trim();
        const r = await api('POST', '/api/assets', patch);
        if (!r.ok) return apiError(r);
        await refresh();
        showDetail(r.json.id);
      }
      return null;
    },
  });
}

async function deleteAsset(a) {
  if (!confirm(tr('Delete "{name}"? This removes the record and its history.', { name: name(a) || a.mac }))) return;
  const r = await api('DELETE', '/api/assets/' + a.id);
  if (!r.ok) { showMessage(tr('Could not delete'), el('p', { text: apiError(r) })); return; }
  $('detail').hidden = true;
  await refresh();
}

$('add-asset').onclick = () => openAssetForm(null);

// ---------------------------------------------------------------- CSV import

$('import-assets').onclick = () => $('import-file').click();
$('import-file').onchange = async (ev) => {
  const f = ev.target.files[0];
  ev.target.value = '';
  if (!f) return;
  if (f.size > 5 * 1024 * 1024) { showMessage(tr('Import'), el('p', { text: tr('That file is larger than 5 MB.') })); return; }
  const r = await api('POST', '/api/assets/import', await f.text());
  if (!r.ok) { showMessage(tr('Import failed'), el('p', { text: apiError(r) })); return; }
  const j = r.json;
  showMessage(tr('Import finished'),
    el('p', { text: tr('{created} created, {updated} updated, {unchanged} unchanged, {problems} row(s) with problems.', { created: j.created, updated: j.updated, unchanged: j.unchanged, problems: j.errors.length }) }),
    j.errors.length ? el('ul', {}, ...j.errors.slice(0, 20).map((e) => el('li', { text: tr('line {line}: {error}', { line: e.line, error: translateError(e.error) }) }))) : null,
    el('p', { class: 'muted', text: tr('Columns: mac (required), plus any of the editable fields, tags (separated by ;), and custom.<name>. Empty cells leave a value unchanged. Tip: export the devices CSV, edit it in a spreadsheet, and import it back.') }));
  await refresh();
};

// ------------------------------------------------------------- users & audit

async function renderUsers() {
  if (!can('admin')) return;
  const r = await api('GET', '/api/users');
  if (r.ok) {
    $('users-table').tBodies[0].replaceChildren(...r.json.map((u) => el('tr', {},
      el('td', { text: u.username + (state.me && u.id === state.me.id ? ' ' + tr('(you)') : '') }),
      el('td', {}, (() => {
        const sel = el('select', {}, ...['viewer', 'editor', 'admin'].map((x) => el('option', { value: x, text: tr(x) })));
        sel.value = u.role;
        sel.onchange = async () => {
          const rr = await api('PATCH', '/api/users/' + u.id, { role: sel.value });
          if (!rr.ok) { showMessage(tr('Could not change role'), el('p', { text: apiError(rr) })); }
          renderUsers();
        };
        return sel;
      })()),
      el('td', { text: u.disabled ? tr('disabled') : u.must_change ? tr('must change password') : tr('active') }),
      el('td', {},
        el('span', { text: [u.totp ? tr('authenticator app') : null, u.passkeys ? tr('{n} passkeys', { n: u.passkeys }) : null].filter(Boolean).join(' · ') || tr('none') }),
        u.totp ? el('button', { type: 'button', class: 'reset-totp', title: tr('Remove the authenticator app (a lost phone). The person is signed out and can set it up again.'), text: tr('Reset'), onclick: async () => {
          if (!confirm(tr('Remove the authenticator app of {user}? They will be signed out.', { user: u.username }))) return;
          const rr = await api('DELETE', '/api/users/' + u.id + '/totp');
          if (!rr.ok) showMessage(tr('Could not reset'), el('p', { text: apiError(rr) }));
          renderUsers();
        } }) : null),
      el('td', { text: u.last_login ? fmtTime(u.last_login) : tr('never') }),
      el('td', {},
        el('button', { type: 'button', text: u.disabled ? tr('Enable') : tr('Disable'), onclick: async () => {
          const rr = await api('PATCH', '/api/users/' + u.id, { disabled: !u.disabled });
          if (!rr.ok) showMessage(tr('Could not update user'), el('p', { text: apiError(rr) }));
          renderUsers();
        } }),
        el('button', { type: 'button', text: tr('Reset password'), onclick: async () => {
          if (!confirm(tr('Reset the password of {user}? They will be signed out.', { user: u.username }))) return;
          const rr = await api('POST', '/api/users/' + u.id + '/reset-password');
          if (rr.ok) showSecret(tr('New temporary password for {user}', { user: u.username }), tr('Give this to the user. It works once and must be changed at sign-in.'), rr.json.temporary_password);
          else showMessage(tr('Could not reset'), el('p', { text: apiError(rr) }));
        } }),
        el('button', { type: 'button', text: tr('Sites'), title: tr('Which sites {user} may see or change', { user: u.username }), onclick: () => openSiteAccess(u) })))));
  }
}

/** Per-site read/write/none for one user (see access.rs). Default (no grant) = full access. */
async function openSiteAccess(u) {
  const r = await api('GET', '/api/users/' + u.id + '/site-access');
  if (!r.ok) { showMessage(tr('Could not load site access'), el('p', { text: apiError(r) })); return; }
  const bySite = Object.fromEntries(r.json.grants.map((g) => [g.site, g.permission]));
  const selects = r.json.sites.map(({ site, name }) => {
    const sel = el('select', { 'aria-label': name || tr('local') },
      el('option', { value: 'write', text: tr('Full access') }),
      el('option', { value: 'read', text: tr('Read only') }),
      el('option', { value: 'none', text: tr('No access') }));
    sel.value = bySite[site] || 'write';
    return [site, sel];
  });
  openForm(tr('Site access: {user}', { user: u.username }),
    [el('p', { class: 'muted small', text: tr('What {user} may see or change per site. "Full access" is the default until you change it here.', { user: u.username }) }),
      ...selects.map(([site, sel]) => field(r.json.sites.find((s) => s.site === site).name || tr('local'), sel))],
    { onSubmit: async () => {
      // only non-default rows are worth storing; "Full access" is already what no grant means
      const grants = selects.filter(([, sel]) => sel.value !== 'write').map(([site, sel]) => [site, sel.value]);
      const rr = await api('PUT', '/api/users/' + u.id + '/site-access', { grants });
      return rr.ok ? null : apiError(rr);
    } });
}

let auditRows = [];

/** The audit log page: the latest entries, filterable in the browser. */
async function renderAudit() {
  if (!can('admin')) return;
  const a = await api('GET', '/api/audit?limit=' + encodeURIComponent($('audit-limit').value));
  if (!a.ok) return;
  auditRows = a.json.map((e) => ({ e, text: [e.user, e.action, summarizeAudit(e)].join(' ').toLowerCase() }));
  drawAudit();
}

function drawAudit() {
  const q = $('audit-filter').value.trim().toLowerCase();
  const rows = auditRows.filter((r) => !q || r.text.includes(q));
  $('audit-table').tBodies[0].replaceChildren(...rows.map(({ e }) => el('tr', {},
    el('td', { text: fmtTime(e.ts) }), el('td', { text: e.user }), el('td', {}, el('span', { class: 'tag', text: e.action })),
    el('td', { class: 'muted', text: summarizeAudit(e) }))));
  $('audit-count').textContent = q ? tr('{n} of {total} entries', { n: rows.length, total: auditRows.length }) : tr('{n} entries', { n: rows.length });
}
$('audit-filter').oninput = drawAudit;
$('audit-limit').onchange = renderAudit;

function summarizeAudit(e) {
  const d = e.detail || {};
  if (d.changes) return d.changes.map((c) => `${c.field}: ${c.old == null ? '∅' : c.old} → ${c.new == null ? '∅' : c.new}`).join('; ') + (e.asset_id ? ` (asset #${e.asset_id})` : '');
  return Object.entries(d).map(([k, v]) => `${k}=${typeof v === 'object' ? JSON.stringify(v) : v}`).join(' ');
}

$('user-form').onsubmit = async (ev) => {
  ev.preventDefault();
  const r = await api('POST', '/api/users', { username: $('user-name').value.trim(), role: $('user-role').value });
  if (!r.ok) { showMessage(tr('Could not add user'), el('p', { text: apiError(r) })); return; }
  $('user-name').value = '';
  showSecret(tr('User created: {user}', { user: r.json.user.username }), tr('Give them this one-time password. They must change it at first sign-in.'), r.json.temporary_password);
  renderUsers();
};

// -------------------------------------------------------------- agent tokens

async function renderTokens() {
  if (!can('admin')) return;
  const r = await api('GET', '/api/agent-tokens');
  if (!r.ok) return;
  $('tokens-table').tBodies[0].replaceChildren(...r.json.map((t) => el('tr', {},
    el('td', { class: 'mono', text: t.agent_id }), el('td', { text: t.revoked ? tr('revoked') : tr('active') }), el('td', { text: t.label }),
    el('td', { text: fmtTime(t.created_at) }), el('td', { text: t.last_used ? ago(t.last_used) : tr('never') }),
    el('td', {}, t.revoked ? null : el('button', { type: 'button', text: tr('Revoke'), onclick: async () => {
      if (!confirm(tr('Revoke the token of {agent}? The agent will be disconnected.', { agent: t.agent_id }))) return;
      const rr = await api('DELETE', '/api/agent-tokens/' + encodeURIComponent(t.agent_id));
      if (!rr.ok) showMessage(tr('Could not revoke'), el('p', { text: apiError(rr) }));
      renderTokens();
    } })))));
}

$('token-form').onsubmit = async (ev) => {
  ev.preventDefault();
  const id = $('token-agent').value.trim();
  const r = await api('POST', '/api/agent-tokens', { agent_id: id, label: $('token-label').value.trim() });
  if (!r.ok) { showMessage(tr('Could not issue token'), el('p', { text: apiError(r) })); return; }
  $('token-agent').value = ''; $('token-label').value = '';
  showSecret(tr('Token for agent {agent}', { agent: id }), tr('Shown only once. Any earlier token for this agent has been revoked.'), r.json.token,
    tr('On the agent:') + '  DENIS_AGENT_TOKEN=<token> denis agent --master https://THIS-SERVER:8081 --master-ca ca.pem --id ' + id);
  renderTokens();
};

// ------------------------------------------------------------- API tokens

async function renderApiTokens() {
  if (!can('admin')) return;
  const r = await api('GET', '/api/api-tokens');
  if (!r.ok) return;
  $('apitokens-table').tBodies[0].replaceChildren(...r.json.map((t) => el('tr', {},
    el('td', { text: t.label }), el('td', { text: tr(t.role) }), el('td', { text: t.revoked ? tr('revoked') : tr('active') }),
    el('td', { text: t.created_by }), el('td', { text: fmtTime(t.created_at) }), el('td', { text: t.last_used ? ago(t.last_used) : tr('never') }),
    el('td', {}, t.revoked ? null : el('button', { type: 'button', text: tr('Revoke'), onclick: async () => {
      if (!confirm(tr('Revoke the token "{label}"? Whatever uses it will stop working.', { label: t.label }))) return;
      const rr = await api('DELETE', '/api/api-tokens/' + t.id);
      if (!rr.ok) showMessage(tr('Could not revoke'), el('p', { text: apiError(rr) }));
      renderApiTokens();
    } })))));
}

$('apitoken-form').onsubmit = async (ev) => {
  ev.preventDefault();
  const r = await api('POST', '/api/api-tokens', { label: $('apitoken-label').value.trim(), role: $('apitoken-role').value });
  if (!r.ok) { showMessage(tr('Could not create token'), el('p', { text: apiError(r) })); return; }
  $('apitoken-label').value = '';
  showSecret(tr('API token created'), tr('Shown only once; store it in your secret manager.'), r.json.token,
    tr('Example:') + '  curl -H "Authorization: Bearer <token>" https://THIS-SERVER/api/assets');
  renderApiTokens();
};

// ------------------------------------------------------------------ alerting

const CHANNEL_HELP = {
  slack: () => tr('In Slack: create an app with an Incoming Webhook (api.slack.com/messaging/webhooks) and paste its URL.'),
  teams: () => tr('In Teams: Workflows → "Send webhook alerts to a channel" (or a flow with the trigger "When a Teams webhook request is received") and paste its URL. The older Office 365 Connectors have been retired by Microsoft.'),
  discord: () => tr('In Discord: channel settings → Integrations → Webhooks → copy the webhook URL.'),
  pagerduty: () => tr('In PagerDuty: service → Integrations → add "Events API v2" and paste its Integration Key. Only serious alerts (score 70 and up by default) are sent, and repeats of the same alert about the same device fold into one incident.'),
  pushover: () => tr('In Pushover: create an application (pushover.net/apps/build) and paste its API token, then paste your user key (or a delivery group key) from your dashboard. Serious alerts arrive as high priority.'),
  ntfy: () => tr('Paste the address of your topic, like https://ntfy.sh/your-topic (or the topic on your own ntfy server). On the public ntfy.sh the topic name is the only secret, so make it long and hard to guess; for a protected topic add an access token.'),
  email: () => tr('Any SMTP server. Use STARTTLS or TLS whenever you use a password.'),
  webhook: () => tr('Your own system receives a JSON POST. If you set a signing secret (16+ characters) each request carries X-Denis-Signature: sha256=<HMAC of the body>, so the receiver can verify it came from DENIS.'),
};

function syncChannelForm() {
  const k = $('ch-kind').value;
  $('ch-url-row').hidden = !['slack', 'teams', 'discord', 'webhook', 'ntfy'].includes(k);
  $('ch-url-row').firstChild.textContent = k === 'ntfy' ? tr('Topic address') : tr('Webhook URL');
  $('ch-url').placeholder = k === 'ntfy' ? 'https://ntfy.sh/your-topic' : 'https://…';
  $('ch-secret-row').hidden = !['pagerduty', 'webhook', 'pushover', 'ntfy'].includes(k);
  $('ch-secret-row').firstChild.textContent = { webhook: tr('Signing secret (optional)'), pushover: tr('Application token'), ntfy: tr('Access token (optional)') }[k] || tr('Integration key');
  $('ch-user-row').hidden = k !== 'pushover';
  $('ch-smtp').hidden = k !== 'email';
  $('ch-min').value = k === 'pagerduty' ? 70 : 50;
  $('ch-help').textContent = CHANNEL_HELP[k]();
}
$('ch-kind').onchange = syncChannelForm;

async function loadAlerting() {
  if (!can('admin')) return;
  syncChannelForm();
  const [c, m] = await Promise.all([api('GET', '/api/channels'), api('GET', '/api/maintenance')]);
  if (m.ok) {
    $('maint-status').textContent = m.json.active
      ? tr('Silenced until {time}.', { time: fmtTime(m.json.until) }) + (m.json.note ? ' (' + m.json.note + ')' : '') + ' ' + tr('Alerts still appear in the console.')
      : tr('Notifications are on.');
    $('maint-end').hidden = !m.json.active;
  }
  if (!c.ok) return;
  $('no-channels').hidden = c.json.length > 0;
  const kindName = { slack: 'Slack', teams: 'Microsoft Teams', discord: 'Discord', pagerduty: 'PagerDuty', pushover: 'Pushover', ntfy: 'ntfy', email: 'E-mail', webhook: 'Webhook' };
  $('channels-table').tBodies[0].replaceChildren(...c.json.map((ch) => {
    const st = ch.status || {};
    const target = ch.kind === 'email' ? ch.smtp.to.join(', ') : (ch.url || (ch.kind === 'pagerduty' ? 'events.pagerduty.com' : ch.kind === 'pushover' ? 'api.pushover.net' : ''));
    const stateEl = !ch.enabled ? el('span', { class: 'pill', text: tr('disabled') })
      : st.last_error ? el('span', { class: 'pill bad', title: st.last_error, text: tr('failing') })
      : el('span', { class: 'pill ok', text: st.last_ok ? tr('ok {ago}', { ago: ago(st.last_ok) }) : tr('ready') });
    const min = el('input', { type: 'number', min: 0, max: 100, value: String(ch.min_score), style: 'width:70px' });
    min.onchange = async () => {
      const r = await api('PUT', '/api/channels/' + ch.id, { min_score: Number(min.value) });
      if (!r.ok) showMessage(tr('Could not save'), el('p', { text: apiError(r) }));
      loadAlerting();
    };
    return el('tr', {},
      el('td', { text: ch.name }), el('td', { text: kindName[ch.kind] || ch.kind }), el('td', { class: 'mono', text: target }),
      el('td', {}, min),
      el('td', {}, stateEl, st.last_error ? el('div', { class: 'form-error', text: st.last_error }) : null, st.sent ? el('div', { class: 'muted small', text: tr('{n} sent', { n: st.sent }) }) : null),
      el('td', {},
        el('button', { type: 'button', text: tr('Test'), onclick: async (ev) => {
          ev.target.disabled = true;
          const r = await api('POST', '/api/channels/' + ch.id + '/test');
          ev.target.disabled = false;
          showMessage(r.ok ? tr('Test sent') : tr('Test failed'), el('p', { text: r.ok ? tr('The test message was accepted. Check the channel.') : apiError(r) }));
        } }),
        ' ',
        el('button', { type: 'button', text: ch.enabled ? tr('Disable') : tr('Enable'), onclick: async () => {
          await api('PUT', '/api/channels/' + ch.id, { enabled: !ch.enabled });
          loadAlerting();
        } }),
        ' ',
        el('button', { type: 'button', text: tr('Delete'), onclick: async () => {
          if (!confirm(tr('Delete the channel "{name}"?', { name: ch.name }))) return;
          await api('DELETE', '/api/channels/' + ch.id);
          loadAlerting();
        } })));
  }));
}

$('channel-form').onsubmit = async (ev) => {
  ev.preventDefault();
  const k = $('ch-kind').value;
  const body = { kind: k, name: $('ch-name').value.trim(), min_score: Number($('ch-min').value) };
  if (['slack', 'teams', 'discord', 'webhook', 'ntfy'].includes(k)) body.url = $('ch-url').value.trim();
  if (['pagerduty', 'webhook', 'pushover', 'ntfy'].includes(k) && $('ch-secret').value) body.secret = $('ch-secret').value;
  if (k === 'pushover') body.user = $('ch-user').value;
  if (k === 'email') {
    body.smtp = {
      host: $('ch-smtp-host').value.trim(), port: Number($('ch-smtp-port').value), security: $('ch-smtp-sec').value,
      username: $('ch-smtp-user').value.trim() || null, password: $('ch-smtp-pass').value || null,
      from: $('ch-smtp-from').value.trim(), to: $('ch-smtp-to').value,
    };
  }
  const r = await api('POST', '/api/channels', body);
  $('ch-status').textContent = r.ok ? tr('Added. Use Test to check it.') : apiError(r);
  if (r.ok) {
    for (const id of ['ch-name', 'ch-url', 'ch-secret', 'ch-user', 'ch-smtp-pass']) $(id).value = '';
    loadAlerting();
  }
};

$('maint-form').onsubmit = async (ev) => {
  ev.preventDefault();
  const r = await api('PUT', '/api/maintenance', { minutes: Number($('maint-minutes').value), note: $('maint-note').value.trim() });
  if (!r.ok) showMessage(tr('Could not start'), el('p', { text: apiError(r) }));
  loadAlerting(); loadMaintenanceBanner();
};
$('maint-end').onclick = async () => {
  await api('PUT', '/api/maintenance', { minutes: null });
  loadAlerting(); loadMaintenanceBanner();
};

/** Everyone sees when notifications are silenced, so nobody assumes a quiet phone means a quiet network. */
async function loadMaintenanceBanner() {
  const r = await api('GET', '/api/maintenance');
  const b = $('maint-banner');
  if (r.ok && r.json.active) {
    b.hidden = false;
    b.textContent = tr('Maintenance mode: outgoing notifications are silenced until {time}.', { time: fmtTime(r.json.until) }) + (r.json.note ? ' (' + r.json.note + ')' : '') + ' ' + tr('Alerts still appear here.');
  } else b.hidden = true;
}

// ------------------------------------------------------------------ passkeys

const b64u = {
  enc: (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
  dec: (s) => {
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    return Uint8Array.from(atob(s), (c) => c.charCodeAt(0)).buffer;
  },
};

const passkeysSupported = () => !!(window.PublicKeyCredential && navigator.credentials);

/** Ask the server what the sign-in page may offer, and show the passkey button if it can work. */
async function loadSignInMethods() {
  const r = await api('GET', '/api/auth/methods');
  state.methods = r.ok ? r.json : { passkey: false };
  $('login-passkey').hidden = !(state.methods.passkey && passkeysSupported());
}

/** Turn the browser's error into a sentence a person can act on. */
function passkeyError(e) {
  if (e && e.name === 'NotAllowedError') return tr('Cancelled, or timed out.');
  if (e && e.name === 'InvalidStateError') return tr('This device already has a passkey for this account.');
  if (e && e.name === 'SecurityError') return tr('The browser refused: the address in the bar must match the configured public address (and use https).');
  return (e && e.message) || tr('The passkey could not be used.');
}

$('login-passkey').onclick = async () => {
  const showErr = (m) => { const e = $('login-error'); e.textContent = m; e.hidden = false; };
  $('login-error').hidden = true;
  const b = await api('POST', '/api/auth/passkey/login/begin', {});
  if (!b.ok) return showErr(apiError(b));
  const o = b.json.publicKey;
  let cred;
  try {
    cred = await navigator.credentials.get({ publicKey: { challenge: b64u.dec(o.challenge), rpId: o.rpId, timeout: o.timeout, userVerification: o.userVerification, allowCredentials: [] } });
  } catch (e) { return showErr(passkeyError(e)); }
  const r = cred.response;
  const f = await api('POST', '/api/auth/passkey/login/finish', {
    ceremony: b.json.ceremony,
    credential: { id: cred.id, response: {
      clientDataJSON: b64u.enc(r.clientDataJSON), authenticatorData: b64u.enc(r.authenticatorData), signature: b64u.enc(r.signature),
      userHandle: r.userHandle ? b64u.enc(r.userHandle) : '' } },
  });
  if (!f.ok) return showErr(apiError(f));
  state.me = f.json.user;
  await start();
};

/** Register a new passkey for the signed-in user. Returns an error message, or null. */
async function addPasskey(name) {
  const b = await api('POST', '/api/auth/passkey/register/begin', {});
  if (!b.ok) return apiError(b);
  const o = b.json.publicKey;
  let cred;
  try {
    cred = await navigator.credentials.create({ publicKey: {
      ...o, challenge: b64u.dec(o.challenge), user: { ...o.user, id: b64u.dec(o.user.id) },
      excludeCredentials: (o.excludeCredentials || []).map((c) => ({ ...c, id: b64u.dec(c.id) })),
    } });
  } catch (e) { return passkeyError(e); }
  const f = await api('POST', '/api/auth/passkey/register/finish', {
    ceremony: b.json.ceremony, name,
    credential: { id: cred.id, response: { clientDataJSON: b64u.enc(cred.response.clientDataJSON), attestationObject: b64u.enc(cred.response.attestationObject) } },
  });
  return f.ok ? null : apiError(f);
}

/** The passkeys of the signed-in user, inside the account page: list, add one, remove one. */
async function renderPasskeys(message) {
  const r = await api('GET', '/api/auth/passkeys');
  const list = r.ok ? r.json : [];
  const name = el('input', { placeholder: tr('name, e.g. "Work laptop" or "YubiKey"'), maxLength: 40 });
  const status = el('div', { class: message && message.ok ? 'muted' : 'form-error', text: message ? message.text : '' });
  const add = el('button', { type: 'button', class: 'primary', text: tr('Add a passkey'), onclick: async () => {
    add.disabled = true;
    const e = await addPasskey(name.value.trim());
    renderPasskeys(e ? { ok: false, text: e } : { ok: true, text: tr('Passkey added. You can now sign in with it.') });
  } });
  // absent parts are null: replaceChildren(null) would print the word "null"
  $('passkeys-body').replaceChildren(...[
    el('p', { class: 'muted', text: tr('A passkey lets you sign in with your fingerprint, face, device PIN or a security key instead of a password: nothing to type, and nothing an attacker can phish. Add one for each device you use.') }),
    !(state.methods && state.methods.passkey) ? el('p', { class: 'form-error', text: tr('Passkeys are not available on this setup: the administrator must start DENIS with --public-url https://your-address (or you can open the console as http://localhost).') }) : null,
    el('div', { class: 'passkey-list' }, ...list.map((p) => el('div', { class: 'passkey-row' },
      el('span', {}, el('b', { text: p.name }), el('span', { class: 'muted small', text: ' · ' + tr('added {time}', { time: fmtTime(p.created_at) }) + (p.last_used ? ' · ' + tr('last used {ago}', { ago: ago(p.last_used) }) : ' · ' + tr('never used')) })),
      el('button', { type: 'button', text: tr('Remove'), onclick: async () => {
        if (!confirm(tr('Remove the passkey "{name}"? You will not be able to sign in with it any more.', { name: p.name }))) return;
        await api('DELETE', '/api/auth/passkeys/' + p.id);
        renderPasskeys({ ok: true, text: tr('Removed.') });
      } }))),
      list.length ? null : el('div', { class: 'muted', text: tr('You have no passkeys yet.') })),
    passkeysSupported() ? el('div', { class: 'row' }, name, add) : el('p', { class: 'form-error', text: tr('This browser does not support passkeys.') }),
    status].filter(Boolean));
}

// ------------------------------------------------------------------- account

/** "My account": who you are, your password and passkeys, sign out. */
function renderAccount() {
  const me = state.me;
  if (!me) return;
  const roles = { viewer: tr('can read everything'), editor: tr('can also edit devices, acknowledge alerts and start scans'), admin: tr('can also manage users, settings and rules') };
  $('account-info').replaceChildren(el('div', {}, el('b', { text: me.username }), ' · ' + tr(me.role)), el('div', { text: roles[me.role] || '' }));
  renderPasskeys();
  renderTotp();
}
$('account').onclick = () => { location.hash = '#account'; setTab('account'); };
$('account-logout').onclick = () => $('logout').click();

// -------------------------------------------------------------- deep links

/**
 * Addresses you can bookmark or paste into a message: #rules, #findings, #alerting …
 * open that tab; #device/12 opens a device; #edit/12 its edit form; #alert/34 an alert.
 */
function applyHash() {
  const [what, arg] = location.hash.replace(/^#/, '').split('/');
  const tabs = ['overview', 'assets', 'alerts', 'findings', 'rules', 'compliance', 'reports', 'health', 'topology', 'ot', 'trends', 'events', 'agents', 'alerting', 'users', 'settings', 'audit'];
  if (tabs.includes(what) && !$('tab-' + what)?.hidden) setTab(what);
  if (what === 'account' && state.me) setTab('account');
  // #rules/watches: scroll to the OT command watches
  if (what === 'rules' && arg === 'watches') setTimeout(() => $('watches')?.scrollIntoView({ block: 'start' }), 700);
  // #settings/tls, #settings/updates ...: scroll to that section
  if (what === 'settings' && arg && !$('tab-settings').hidden) {
    const box = { branding: 'branding-box', overview: 'overview-box', license: 'license-box', interfaces: 'interfaces-box', tls: 'tls-box', updates: 'update-box', data: 'data-box', setup: 'setup-box', security: 'security-box', switches: 'switches-box', vulndata: 'vuln-box' }[arg];
    if (box) setTimeout(() => $(box).scrollIntoView({ block: 'start' }), 50);
  }
  if (what === 'passkeys') { location.hash = '#account'; return; }
  if (what === 'review') { setTab('assets'); $('only-review').checked = true; renderAssets(); }
  const id = Number(arg);
  if (!Number.isInteger(id) || !state.me) return;
  if (what === 'device') showDetail(id);
  else if (what === 'edit' && can('editor')) { const a = assetById(id); if (a) openAssetForm(a); }
  else if (what === 'icons' && can('editor')) {
    const a = assetById(id);
    if (a) { openAssetForm(a).then(() => setTimeout(() => document.querySelector('.icon-row button')?.click(), 50)); }
  }
  else if (what === 'alert') { const e = state.alerts.concat(state.events).find((x) => x.id === id); if (e) showAlert(e, assetById(e.asset_id)); }
}
window.addEventListener('hashchange', () => { if (state.me) applyHash(); });

// ---------------------------------------------------------- demo data, erase

/** Tell everyone when the data they are looking at is fictional. */
async function loadDemoBanner() {
  const r = await api('GET', '/api/demo');
  const b = $('demo-banner');
  b.hidden = !(r.ok && r.json.loaded);
  if (!b.hidden) b.textContent = tr('Demo data is loaded: the devices and alerts you see are fictional (a made-up company).') + ' ' + (can('admin') ? tr('Remove it under Settings → Demo data and reset when you are ready for your own network.') : tr('An administrator can remove it when the real deployment starts.'));
}

async function demoAction(method, url, doneText) {
  $('demo-status').textContent = '…';
  const r = await api(method, url);
  $('demo-status').textContent = r.ok ? doneText : apiError(r);
  await refresh();
  loadDemoBanner();
}
$('demo-load').onclick = () => demoAction('POST', '/api/demo', tr('Demo data loaded. Look around the Devices, Alerts, OT and Trends tabs.'));
$('demo-remove').onclick = () => demoAction('DELETE', '/api/demo', tr('Demo data removed.'));

$('erase-all').onclick = () => {
  const phrase = 'ERASE ALL DATA';
  const input = el('input', { placeholder: phrase, autocomplete: 'off' });
  openForm(tr('Erase all data'), [
    el('p', { text: tr('This deletes every device, edit, alert, baseline, communications record, trend sample and remote site, and starts a new learning period. Accounts, sign-in methods, notification channels, branding, rule settings and the audit log are kept.') }),
    el('p', { class: 'form-error', text: tr('It cannot be undone. Take a backup first (denis backup).') }),
    field(tr('Type {phrase} to confirm', { phrase }), input),
  ], {
    submitLabel: tr('Erase everything'),
    onSubmit: async () => {
      if (input.value.trim() !== phrase) return tr('Type the words exactly as shown.');
      const r = await api('POST', '/api/data/erase', { confirm: phrase });
      if (!r.ok) return apiError(r);
      await refresh();
      loadDemoBanner();
      $('demo-status').textContent = tr('Everything was erased. Learning starts again now.');
      return null;
    },
  });
};

// ------------------------------------------------------------------- updates

let updateInfo = null;

/** A new version is available: tell everyone, let administrators act. */
async function loadUpdateBanner() {
  const r = await api('GET', '/api/update');
  if (!r.ok) return;
  updateInfo = r.json;
  const b = $('update-banner');
  const u = updateInfo;
  b.hidden = !(u.notify || u.installing || u.result);
  if (b.hidden) return;
  b.replaceChildren();
  if (u.installing) b.append(el('span', { text: tr('Updating DENIS: {stage}', { stage: u.stage ? tr(u.stage) : '…' }) }));
  else if (u.notify) {
    b.append(el('span', { text: tr('DENIS {version} is available (you have {current}).', { version: u.latest.version, current: u.current }) + ' ' }),
      el('button', { type: 'button', text: tr('What\'s new'), onclick: () => openUpdateDialog() }));
  } else b.append(el('span', { text: translateResult(u.result) }));
}

function fmtWhen(ts) { return new Date(ts * 1000).toLocaleString(locale()); }

/** The update dialog: changelog, reassurance, and the choices. */
function openUpdateDialog() {
  const u = updateInfo;
  if (!u || !u.latest) return;
  const admin = can('admin');
  const close = () => $('msg-dialog').close();
  const post = async (path, body) => {
    const r = await api('POST', path, body);
    if (!r.ok) showMessage(tr('Update'), el('p', { class: 'form-error', text: apiError(r) }));
    return r;
  };
  const when = el('input', { type: 'datetime-local' });
  const nodes = [
    el('p', {}, el('b', { text: 'DENIS ' + u.latest.version }), el('span', { class: 'muted', text: '  (' + tr('you have {current}', { current: u.current }) + (u.latest.published_at ? ' · ' + tr('released {date}', { date: u.latest.published_at.slice(0, 10) }) : '') + ')' })),
    el('h4', { text: tr('What\'s new') }),
    el('div', { class: 'release-notes', text: u.latest.notes || tr('No release notes were published.') }),
    el('p', { class: 'muted', text: tr('Before installing, DENIS makes a verified backup of your database ({dir}) and keeps the previous version. Your data is not changed by updating. If the new version does not start, the previous version is put back automatically.', { dir: u.backup_dir }) }),
    !admin ? el('p', { class: 'muted', text: tr('An administrator can install this update.') }) : null,
    admin && u.file_capabilities ? el('p', { class: 'form-error', text: tr('This program gets its packet-capture permission from setcap, which an updated file would lose. Run it under systemd with AmbientCapabilities, or install the new version by hand and run setcap again') + (u.latest.page ? ': ' + u.latest.page : '.') }) : null,
    admin && !u.can_install && !u.file_capabilities ? el('p', { class: 'form-error', text: tr('This installation cannot update itself (this build has no release key, or the program folder is not writable for the user DENIS runs as). Install the new version by hand') + (u.latest.page ? ': ' + u.latest.page : '.') }) : null,
    admin && u.can_install ? el('div', { class: 'row' },
      el('button', { type: 'button', class: 'primary', text: tr('Install now'), onclick: async () => { if ((await post('/api/update/install', {})).ok) watchInstall(); } }),
      el('span', { class: 'muted', text: tr('or at') }), when,
      el('button', { type: 'button', text: tr('Schedule'), onclick: async () => {
        if (!when.value) return;
        const r = await post('/api/update/install', { when: Math.floor(new Date(when.value).getTime() / 1000) });
        if (r.ok) { close(); loadUpdateBanner(); loadUpdateBox(); }
      } })) : null,
    admin ? el('div', { class: 'row' },
      el('button', { type: 'button', text: tr('Remind me in 3 days'), onclick: async () => { await post('/api/update/snooze', { days: 3 }); close(); loadUpdateBanner(); } }),
      el('button', { type: 'button', text: tr('Skip this version'), onclick: async () => { await post('/api/update/skip', {}); close(); loadUpdateBanner(); } })) : null,
    u.scheduled_at ? el('p', {}, tr('Scheduled for {time}.', { time: fmtWhen(u.scheduled_at) }) + ' ', el('button', { type: 'button', text: tr('Cancel'), onclick: async () => { await api('DELETE', '/api/update/schedule'); close(); loadUpdateBanner(); loadUpdateBox(); } })) : null,
  ];
  showMessage(tr('Update available'), ...nodes);
}

/** Follow an install: show each stage, then wait for the new version to come back and reload. */
async function watchInstall() {
  const stages = ['Checking the release', 'Verifying the signature', 'Downloading', 'Testing the new program', 'Backing up the database', 'Installing', 'Restarting'];
  const list = el('div', { class: 'stage-list' });
  const note = el('p', { class: 'muted', text: tr('Please keep this page open.') });
  showMessage(tr('Updating DENIS'), list, note);
  let seen = -1;
  let down = false;
  for (let i = 0; i < 300; i++) {
    await new Promise((r) => setTimeout(r, 1000));
    let r;
    try { r = await api('GET', '/api/update'); } catch (e) { r = { ok: false }; }
    if (!r.ok || r.status === 0) {
      // the program is restarting: wait until it answers again, then load the new version
      down = true;
      list.replaceChildren(...stages.map((s) => el('div', { text: '✓ ' + tr(s) })), el('div', { text: tr('… starting the new version') }));
      continue;
    }
    // the new version answers: load it (the restart can be so quick that the page never saw the program down)
    if (r.json.current !== updateInfo.current) { location.reload(); return; }
    if (r.json.stage) {
      seen = Math.max(seen, stages.indexOf(r.json.stage));
      list.replaceChildren(...stages.map((s, idx) => el('div', { text: (idx < seen ? '✓ ' : idx === seen ? '▸ ' : '   ') + tr(s) })));
    } else if (r.json.result && !down) {
      // the update stopped before changing anything
      note.textContent = translateResult(r.json.result);
      note.className = 'form-error';
      return;
    }
  }
}

async function loadUpdateBox() {
  if (!can('admin')) return;
  const r = await api('GET', '/api/update');
  if (!r.ok) return;
  updateInfo = r.json;
  const u = r.json;
  let text = tr('Version {current}.', { current: u.current }) + ' ';
  if (!u.configured) text += u.checking_enabled ? tr('Update checks are not configured for this build.') : tr('Update checks are switched off (--no-update-check).');
  else if (u.last_error) text += tr('The last check failed: {error}', { error: u.last_error });
  else if (u.checked_at) text += u.available ? tr('Last checked {time}: version {version} is available.', { time: fmtWhen(u.checked_at), version: u.latest.version }) : tr('Last checked {time}: you are up to date.', { time: fmtWhen(u.checked_at) });
  else text += tr('Not checked yet (DENIS checks every few hours).');
  if (u.scheduled_at) text += ' ' + tr('Update scheduled for {time}.', { time: fmtWhen(u.scheduled_at) });
  if (u.result) text += ' ' + translateResult(u.result);
  $('update-status').textContent = text;
  $('update-check').disabled = !u.configured;
  $('update-open').hidden = !u.available;
}

$('update-check').onclick = async () => {
  $('update-msg').textContent = '…';
  const r = await api('POST', '/api/update/check');
  $('update-msg').textContent = r.ok ? '' : apiError(r);
  await loadUpdateBox();
  loadUpdateBanner();
};
$('update-open').onclick = () => openUpdateDialog();

// ------------------------------------------------------------------- sidebar

/** Menu icons, and the collapse/expand behaviour (remembered per browser). */
function initSidebar() {
  for (const b of document.querySelectorAll('#menu .tab')) {
    const label = b.querySelector('.label').textContent;
    b.prepend(el('span', { class: 'ni' }, icon(b.dataset.tab, 18)));
    b.title = label; // the tooltip is what a collapsed menu shows
  }
  const narrow = () => window.matchMedia('(max-width: 820px)').matches;
  let collapsed = narrow();
  try { const v = localStorage.getItem('denis-sidebar'); if (v && !narrow()) collapsed = v === 'collapsed'; } catch (e) { /* storage blocked */ }
  const apply = () => {
    document.body.classList.toggle('side-collapsed', collapsed);
    $('menu-toggle').setAttribute('aria-expanded', String(!collapsed));
  };
  $('menu-toggle').onclick = () => {
    collapsed = !collapsed;
    if (!narrow()) { try { localStorage.setItem('denis-sidebar', collapsed ? 'collapsed' : 'expanded'); } catch (e) { /* ignore */ } }
    apply();
  };
  // on a phone the menu covers the page: close it after choosing something
  for (const b of document.querySelectorAll('#menu .tab')) b.addEventListener('click', () => { if (narrow()) { collapsed = true; apply(); } });
  apply();
}

// -------------------------------------------------------------------- HTTPS certificate

function initOverviewBox() {
  if (!can('admin')) return;
  $('overview-enabled').checked = !!(state.status && state.status.msp_overview);
}
$('overview-enabled').onchange = async () => {
  const r = await api('PUT', '/api/msp-overview', { enabled: $('overview-enabled').checked });
  if (!r.ok) { showMessage(tr('Could not save'), el('p', { text: apiError(r) })); $('overview-enabled').checked = !$('overview-enabled').checked; return; }
  await refresh();
};

async function loadLicenseBox() {
  if (!can('admin')) return;
  const r = await api('GET', '/api/license');
  if (!r.ok) return;
  const l = r.json;
  const status = $('license-status');
  if (!l.installed) {
    status.textContent = tr('Community edition: personal, non-commercial use, up to {cap} devices.', { cap: l.device_cap });
  } else {
    const lines = [tr('Licensed to {customer} ({tier}).', { customer: l.customer, tier: l.tier })];
    lines.push(l.device_cap ? tr('Up to {cap} devices.', { cap: l.device_cap }) : tr('No device limit.'));
    if (l.activated_at) lines.push(tr('Activated {date}, valid {days} days from then.', { date: new Date(l.activated_at * 1000).toLocaleDateString(locale()), days: l.valid_days }));
    if (l.problem) lines.push(tr('Problem: {reason} — the Community edition is in force until this is fixed.', { reason: l.problem }));
    status.replaceChildren(...lines.flatMap((t, i) => [i ? el('div', {}) : null, el('div', { text: t, class: l.problem && i === lines.length - 1 ? 'form-error' : '' })]).filter(Boolean));
  }
  $('license-remove').hidden = !l.installed;
  $('license-text').value = '';
}
$('license-save').onclick = async () => {
  const text = $('license-text').value.trim();
  if (!text) return;
  const r = await api('PUT', '/api/license', text);
  $('license-msg').textContent = r.ok ? tr('Saved.') : apiError(r);
  if (r.ok) loadLicenseBox();
};
$('license-remove').onclick = async () => {
  if (!confirm(tr('Remove the installed license? The Community edition applies until another one is installed.'))) return;
  const r = await api('DELETE', '/api/license');
  $('license-msg').textContent = r.ok ? '' : apiError(r);
  if (r.ok) loadLicenseBox();
};

async function loadInterfacesBox() {
  if (!can('admin')) return;
  const r = await api('GET', '/api/interfaces');
  if (!r.ok) return;
  const d = r.json;
  const fill = (select, options, current) => {
    select.querySelectorAll('option:not(:first-child)').forEach((o) => o.remove());
    for (const name of options) select.append(el('option', { value: name, text: name }));
    select.value = current || '';
  };
  fill($('iface-select'), d.mains.map((m) => m.name), d.configured_iface);
  fill($('mirror-iface-select'), d.all, d.configured_mirror_iface);
  const lines = [tr('Running now: {iface}', { iface: d.running_iface + (d.running_mirror_iface ? ' + ' + d.running_mirror_iface : '') })];
  if ((d.configured_iface || '') !== (d.running_iface || '') || (d.configured_mirror_iface || '') !== (d.running_mirror_iface || '')) {
    lines.push(tr('Configured for next start: {iface} — restart DENIS to apply.', { iface: (d.configured_iface || tr('(auto)')) + (d.configured_mirror_iface ? ' + ' + d.configured_mirror_iface : '') }));
  }
  $('interfaces-status').replaceChildren(...lines.flatMap((t, i) => [i ? el('div', {}) : null, el('div', { text: t })]).filter(Boolean));
}
$('interfaces-save').onclick = async () => {
  const iface = $('iface-select').value || null;
  const mirror_iface = $('mirror-iface-select').value || null;
  const r = await api('PUT', '/api/interfaces', { iface, mirror_iface });
  $('interfaces-msg').textContent = r.ok ? tr('Saved. Restart DENIS to apply.') : apiError(r);
  if (r.ok) loadInterfacesBox();
};

async function loadTlsBox() {
  if (!can('admin')) return;
  const r = await api('GET', '/api/tls');
  if (!r.ok) return;
  const t = r.json;
  const status = $('tls-status');
  if (!t.enabled) {
    status.textContent = tr('This console is served over plain HTTP (--no-tls): put it behind HTTPS (a reverse proxy) or an SSH tunnel.');
    for (const id of ['tls-replace', 'tls-reset']) $(id).hidden = true;
    $('tls-ca').hidden = true;
    return;
  }
  if (!t.managed) {
    status.textContent = tr('HTTPS with certificate files you manage (--tls-cert/--tls-key). Replace those files to change the certificate.');
    for (const id of ['tls-replace', 'tls-reset']) $(id).hidden = true;
    $('tls-ca').hidden = true;
    return;
  }
  const i = t.info;
  const days = i ? Math.round((i.not_after - Date.now() / 1000) / 86400) : 0;
  status.replaceChildren(
    el('div', { text: i ? (i.source === 'custom' ? tr('Your own certificate for {names}', { names: i.names.join(', ') }) : tr('Certificate created by DENIS for {names}', { names: i.names.join(', ') })) : tr('Certificate unreadable') }),
    i ? el('div', { text: tr('Valid until {date} ({days} days)', { date: new Date(i.not_after * 1000).toLocaleDateString(locale()), days }) + (i.source === 'generated' ? tr('; renewed automatically.') : '.') }) : null,
    i ? el('div', { class: 'mono small', text: 'SHA-256 ' + i.fingerprint }) : null,
    i && i.source === 'generated' ? el('div', { class: 'muted', text: tr('Browsers warn about a certificate they do not know. Download the CA certificate and add it to your browser or operating system once, or give it to agents (--master-ca); or use your own certificate.') }) : null);
  $('tls-ca').hidden = !(t.has_ca && i && i.source === 'generated');
  $('tls-replace').hidden = false;
  $('tls-reset').hidden = !(i && i.source === 'custom');
}

$('tls-replace').onclick = () => {
  const cert = el('textarea', { rows: 6, placeholder: tr('-----BEGIN CERTIFICATE-----') });
  const key = el('textarea', { rows: 6, placeholder: tr('-----BEGIN PRIVATE KEY-----') });
  const fill = (target) => (ev) => { const f = ev.target.files[0]; if (f) f.text().then((t) => { target.value = t; }); };
  openForm(tr('Use your own certificate'), [
    el('p', { class: 'muted', text: tr('Paste (or load) the certificate chain and the matching private key, both as PEM text. The key must not have a passphrase. DENIS checks that they belong together and are valid now, then starts using them immediately; nothing restarts.') }),
    field(tr('Certificate (chain, PEM)'), cert), el('input', { type: 'file', accept: '.pem,.crt,.cer', onchange: fill(cert) }),
    field(tr('Private key (PEM)'), key), el('input', { type: 'file', accept: '.pem,.key', onchange: fill(key) }),
    el('p', { class: 'muted', text: tr('The private key is stored on the server, readable only by DENIS, and never shown again.') }),
  ], {
    submitLabel: tr('Install certificate'),
    onSubmit: async () => {
      const r = await api('POST', '/api/tls/certificate', { certificate: cert.value, key: key.value });
      if (!r.ok) return apiError(r);
      key.value = '';
      await loadTlsBox();
      $('tls-msg').textContent = tr('The new certificate is in use. Reload the page if your browser complains.');
      return null;
    },
  });
};

$('tls-reset').onclick = async () => {
  if (!confirm(tr('Go back to the certificate DENIS creates itself? Browsers that trusted your certificate will show a warning again.'))) return;
  const r = await api('DELETE', '/api/tls/certificate');
  $('tls-msg').textContent = r.ok ? tr('Back to the generated certificate.') : apiError(r);
  loadTlsBox();
};
