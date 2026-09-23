'use strict';
// The physical topology (switches, the cables between them and what is plugged in where, read over SNMP) and the
// list of switches under Settings. Loaded after totp.js.

let topoMode = 'logical';
let physical = null;

const sw = (topo, id) => topo.switches.find((s) => s.id === id);

/** "Switch · Gi1/0/12 (alias)" for one attachment. */
function attachmentText(topo, at) {
  const s = sw(topo, at.switch);
  return (s ? s.name : at.switch) + ' · ' + at.port + (at.port_alias ? ' (' + at.port_alias + ')' : '');
}

async function loadPhysical() {
  const r = await apiFetch('/api/topology');
  if (!r.ok) return null;
  physical = await r.json();
  return physical;
}

/** Where a device is plugged in, for its detail panel (nothing when no switch says). */
async function connectedTo(assetId) {
  try {
    const t = await loadPhysical();
    const at = t && t.attachments.find((a) => a.asset_id === assetId);
    return at ? attachmentText(t, at) + ' · ' + (at.via === 'lldp' ? tr('announced by the device') : tr('learned from the switch')) : '';
  } catch (e) { return ''; }
}

function setTopoMode(m) {
  topoMode = m;
  for (const b of document.querySelectorAll('#topo-mode button')) b.classList.toggle('active', b.dataset.mode === m);
  $('topo-logical').hidden = m !== 'logical';
  $('topo-physical').hidden = m !== 'physical';
  if (m === 'logical') renderTopology(); else renderPhysical();
}

async function renderPhysical() {
  const box = $('topo-physical-body');
  const topo = await loadPhysical();
  if (!topo) return;
  if (!topo.configured) {
    box.replaceChildren(el('p', { class: 'muted', text: tr('No switches are read yet. Add a switch (its address and a read-only SNMP community) and DENIS shows which port each device is plugged into and how the switches are cabled together.') }),
      can('admin') ? el('button', { type: 'button', class: 'primary', text: tr('Add a switch…'), onclick: () => { location.hash = '#settings/switches'; } }) : el('p', { class: 'muted', text: tr('An administrator can add switches under Settings.') }));
    return;
  }
  const colors = { none: 'var(--off)', low: 'var(--accent)', medium: 'var(--warn)', high: '#dc2626' };
  const cols = Math.max(1, Math.ceil(Math.sqrt(topo.switches.length)));
  // a switch with nothing plugged in (or not yet read) needs far less room than one ringed with
  // devices — without this, two mostly-empty switches end up looking lost, far apart on a mostly
  // blank canvas (exactly what a switch that gives back no forwarding table looks like today)
  const maxAttached = Math.max(0, ...topo.switches.map((s) => topo.attachments.filter((a) => a.switch === s.id).length));
  const CELL = maxAttached > 10 ? 380 : maxAttached > 0 ? 260 : 170;
  const rows = Math.ceil(topo.switches.length / cols);
  const kids = [];
  const centre = new Map();
  topo.switches.forEach((s, i) => centre.set(s.id, [(i % cols) * CELL + CELL / 2, Math.floor(i / cols) * CELL + CELL / 2]));
  // the cables between switches
  for (const l of topo.links.filter((x) => x.b_switch)) {
    const [x1, y1] = centre.get(l.a_switch) || [0, 0];
    const [x2, y2] = centre.get(l.b_switch) || [0, 0];
    kids.push(svg('line', { x1, y1, x2, y2, class: 'cable' }));
    kids.push(svg('text', { x: x1 + (x2 - x1) * 0.22, y: y1 + (y2 - y1) * 0.22 - 4 }, document.createTextNode(l.a_port)));
    kids.push(svg('text', { x: x1 + (x2 - x1) * 0.78, y: y1 + (y2 - y1) * 0.78 - 4 }, document.createTextNode(l.b_port)));
  }
  for (const s of topo.switches) {
    const [cx, cy] = centre.get(s.id);
    const mine = topo.attachments.filter((a) => a.switch === s.id);
    const n = mine.length;
    mine.forEach((at, i) => {
      const ang = (2 * Math.PI * i) / Math.max(n, 1) - Math.PI / 2;
      const r = 90 + (n > 14 ? (i % 2) * 34 : 0);
      const x = cx + r * Math.cos(ang), y = cy + r * Math.sin(ang);
      kids.push(svg('line', { x1: cx, y1: cy, x2: x, y2: y }));
      const a = at.asset_id != null ? assetById(at.asset_id) : null;
      const dot = svg('circle', { cx: x, cy: y, r: 9, class: 'node r-' + (a ? a.risk.level : 'none'), opacity: a ? (isOnline(a) ? 1 : 0.4) : 0.6 },
        svg('title', {}, document.createTextNode(`${a ? (name(a) || a.ip || a.mac) : (at.name || at.mac)} · ${attachmentText(topo, at)}`)));
      if (a) dot.addEventListener('click', () => showDetail(a.id));
      kids.push(dot);
      kids.push(svg('text', { x, y: y + 20 }, document.createTextNode(at.port)));
    });
    const hub = svg('rect', { x: cx - 26, y: cy - 13, width: 52, height: 26, rx: 5, class: 'switch-node' + (s.error && !s.last_ok ? ' down' : '') },
      svg('title', {}, document.createTextNode(`${s.name} · ${s.address}${s.error ? ' · ' + s.error : ''}`)));
    kids.push(hub);
    kids.push(svg('text', { x: cx, y: cy + 4, class: 'switch-label' }, document.createTextNode(s.name.slice(0, 9))));
  }
  // Even when the forwarding table is not offered at all (some cheap "smart" switches answer
  // IF-MIB fully but do not implement it), the port list itself — name, alias, up/down — is
  // still worth showing: it is the most a switch that limited will ever give.
  const portTable = (s) => {
    if (!s.ports || !s.ports.length) return null;
    const byPort = new Map(topo.attachments.filter((a) => a.switch === s.id).map((a) => [a.port, a]));
    return el('details', {},
      el('summary', { text: tr('Ports ({n})', { n: s.ports.length }) }),
      el('div', { class: 'table-wrap' }, el('table', {}, el('tbody', {},
        ...s.ports.map((p) => {
          const at = byPort.get(p.name);
          const dev = at && at.asset_id != null ? assetById(at.asset_id) : null;
          return el('tr', {},
            el('td', { text: p.name + (p.alias ? ' (' + p.alias + ')' : '') }),
            el('td', {}, el('span', { class: 'pill ' + (p.up ? 'ok' : p.up === false ? '' : 'warn'), text: p.up ? tr('up') : p.up === false ? tr('down') : tr('unknown') })),
            el('td', { class: 'muted small', text: dev ? deviceLabel(dev, '') : (at ? (at.name || at.mac || '') : '') }));
        })))));
  };
  const cards = topo.switches.map((s) => el('div', { class: 'rule-card' },
    el('div', { class: 'rule-head' }, el('b', { text: s.name }), el('code', { text: s.address }),
      s.error ? el('span', { class: 'changed', text: tr('cannot be read') }) : null),
    s.error ? el('p', { class: 'form-error', text: s.error }) : null,
    el('p', { class: 'muted small', text: s.last_ok ? tr('{ports} ports ({up} up), {macs} MACs learned; read {ago}.', { ports: s.ports_total, up: s.ports_up, macs: s.macs, ago: ago(s.last_ok) }) : tr('Not read yet.') }),
    s.last_ok && !s.error && s.macs === 0 && s.neighbors === 0
      ? el('p', { class: 'muted small', text: tr('The ports read fine, but this switch gave back no forwarding table (MAC-to-port) and no LLDP neighbours, so nothing can be drawn on it yet. Some inexpensive "smart" switches do not implement this over SNMP at all; others need a different SNMP community for it, or LLDP switched on in their own settings. The port list below (up/down, name) is still whatever this switch offers.') })
      : null,
    portTable(s)));
  $('topo-legend-physical').replaceChildren(...['none', 'low', 'medium', 'high'].map((l) => el('span', {}, el('i', { style: 'background:' + colors[l] }), l === 'none' ? tr('no risk') : tr(l))));
  box.replaceChildren(
    ...[
      el('div', { class: 'topo-site' },
        svg('svg', { viewBox: `0 0 ${cols * CELL} ${rows * CELL}`, role: 'img', 'aria-label': tr('Physical topology') }, ...kids)),
      topo.unknown_macs ? el('p', { class: 'muted small', text: tr('{n} more MAC addresses are plugged into access ports but are not in the register.', { n: topo.unknown_macs }) }) : null,
      ...cards,
    ].filter(Boolean));
}

// ------------------------------------------------------------------ settings: the switches

async function loadSwitchesBox() {
  const r = await api('GET', '/api/switches');
  if (!r.ok) return;
  const data = r.json;
  $('switches-body').replaceChildren(...[
    el('p', { class: 'muted', text: tr('DENIS reads your switches over SNMP (v2c, read only) to show which port each device is plugged into and how the switches are cabled. Use a read-only community, allow only this server to query it, and remember that v2c sends the community unencrypted. DENIS never changes anything on a switch.') }),
    ...data.targets.map((t) => el('div', { class: 'watch' + (t.enabled ? '' : ' off'), 'data-switch': t.id },
      el('div', { class: 'rule-head' }, el('b', { text: t.name }), el('code', { text: t.address }),
        el('span', { class: 'watch-actions' },
          el('button', { type: 'button', class: 'poll-switch', text: tr('Read now'), onclick: async (ev) => {
            ev.target.disabled = true;
            const p = await api('POST', '/api/switches/' + t.id + '/poll');
            ev.target.disabled = false;
            showMessage(t.name, el('p', { class: p.ok && p.json.ok ? 'ok-text' : 'form-error', text: p.ok && p.json.ok ? tr('Read: {ports} ports, {neighbors} neighbours, {macs} MAC addresses.', p.json) : (p.ok ? p.json.error : apiError(p)) }));
            loadSwitchesBox();
          } }),
          el('button', { type: 'button', text: tr('Edit'), onclick: () => openSwitchForm(t, data) }),
          el('button', { type: 'button', text: tr('Delete'), onclick: async () => {
            if (!confirm(tr('Delete the switch "{name}"?', { name: t.name }))) return;
            const d = await api('PUT', '/api/switches', { interval_secs: data.interval_secs, targets: data.targets.filter((x) => x.id !== t.id) });
            if (!d.ok) showMessage(tr('Could not delete'), el('p', { text: apiError(d) }));
            loadSwitchesBox();
          } }))),
      el('div', { class: 'muted small', text: t.error ? t.error : t.last_ok ? tr('{ports} ports, {neighbors} neighbours, {macs} MAC addresses; read {ago}.', { ports: t.ports, neighbors: t.neighbors, macs: t.macs, ago: ago(t.last_ok) }) : tr('Not read yet.') }))),
    data.targets.length ? null : el('p', { class: 'muted', text: tr('No switches yet.') }),
    el('div', { class: 'row' }, el('button', { type: 'button', class: 'primary', id: 'add-switch', text: tr('Add a switch…'), onclick: () => openSwitchForm(null, data) })),
  ].filter(Boolean));
}

function openSwitchForm(prefill, data) {
  const t = { name: '', address: '', enabled: true, ...(prefill || {}) };
  const isNew = !prefill;
  const name = el('input', { value: t.name, maxLength: 60, required: true, placeholder: tr('e.g. Core switch') });
  const address = el('input', { value: t.address, required: true, placeholder: '192.168.1.2', id: 'switch-address' });
  const community = el('input', { type: 'password', autocomplete: 'off', placeholder: isNew ? '' : tr('(unchanged)'), required: isNew, id: 'switch-community' });
  const enabled = el('input', { type: 'checkbox', checked: t.enabled });
  openForm(isNew ? tr('Add a switch') : tr('Edit the switch'), [el('div', { class: 'form-grid' },
    field(tr('Name'), name), field(tr('Address'), address),
    field(tr('SNMP community (read only)'), community),
    el('label', { class: 'check field-wide' }, enabled, ' ' + tr('Read this switch regularly')))], {
    onSubmit: async () => {
      const one = { id: t.id || Math.random().toString(36).slice(2, 10).replace(/[^a-z0-9]/g, 'x'), name: name.value.trim(), address: address.value.trim(), enabled: enabled.checked };
      if (community.value) one.community = community.value;
      const others = data.targets.filter((x) => x.id !== one.id).map(({ id, name: n, address: a, enabled: e }) => ({ id, name: n, address: a, enabled: e }));
      const r = await api('PUT', '/api/switches', { interval_secs: data.interval_secs, targets: isNew ? [...others, one] : data.targets.map((x) => (x.id === one.id ? one : { id: x.id, name: x.name, address: x.address, enabled: x.enabled })) });
      if (!r.ok) return apiError(r);
      loadSwitchesBox();
      return null;
    },
  });
}
