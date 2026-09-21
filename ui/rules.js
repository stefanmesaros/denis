'use strict';
// The Rules page: every detection, how it is set, exceptions per rule, and the administrator's own
// OT command watches. Loaded after admin.js (dialogs, api(), field(), openForm()).

let rulesData = null;

// --------------------------------------------------------------- scopes (exceptions, targets, senders)

const SCOPE_KINDS = () => [['device', tr('Device')], ['type', tr('Device type')], ['tag', tr('Tag')], ['cidr', tr('Network')]];

/** Human words for one scope: "Device: Reception printer", "Type: printer", "Network: 10.0.5.0/24". */
function scopeText(s) {
  const kind = Object.fromEntries(SCOPE_KINDS())[s.kind] || s.kind;
  if (s.kind === 'device') {
    const a = assetById(Number(s.value));
    return kind + ': ' + (a ? (name(a) || a.ip || a.mac) : '#' + s.value);
  }
  return kind + ': ' + (s.kind === 'type' ? tr(s.value) : s.value);
}

/**
 * A list of scopes with a small form to add one. `onChange(list)` is called with the new list;
 * read-only (`editable` false) it only shows the chips.
 */
function scopeEditor(list, onChange, editable) {
  const chips = el('div', { class: 'chips' }, ...list.map((s, i) => el('span', { class: 'chip' }, scopeText(s),
    editable ? el('button', { type: 'button', class: 'chip-x', title: tr('Remove'), text: '×', onclick: () => onChange(list.filter((_, j) => j !== i)) }) : null)));
  if (!editable) return list.length ? chips : el('span', { class: 'muted small', text: tr('none') });
  const kind = el('select', { 'aria-label': tr('What to match') }, ...SCOPE_KINDS().map(([v, t]) => el('option', { value: v, text: t })));
  const holder = el('span', {});
  let input;
  const draw = () => {
    if (kind.value === 'device') {
      const devices = state.assets.slice().sort((x, y) => (name(x) || x.ip || x.mac).localeCompare(name(y) || y.ip || y.mac));
      input = el('select', {}, ...devices.map((a) => el('option', { value: String(a.id), text: (name(a) || a.mac) + (a.ip ? ' · ' + a.ip : '') })));
    } else if (kind.value === 'type') {
      const types = ((state.options && state.options.device_types) || []).slice().sort((x, y) => nameOf(x).localeCompare(nameOf(y), locale()));
      input = el('select', {}, ...types.map((t) => el('option', { value: t, text: nameOf(t) })));
    } else {
      input = el('input', { placeholder: kind.value === 'cidr' ? '10.0.5.0/24' : tr('tag'), maxLength: 60 });
    }
    holder.replaceChildren(input);
  };
  kind.onchange = draw;
  draw();
  const add = el('button', { type: 'button', text: tr('Add'), onclick: () => {
    const value = input.value.trim();
    if (!value) return;
    if (list.some((s) => s.kind === kind.value && s.value === value)) return;
    onChange([...list, { kind: kind.value, value }]);
  } });
  return el('div', {}, chips, el('div', { class: 'row scope-add' }, kind, holder, add));
}

// -------------------------------------------------------------------------------------- rules page

/** Draw the rules. Everyone can read them; only administrators get editable fields. */
async function loadRules() {
  const r = await api('GET', '/api/rules');
  if (!r.ok) return;
  rulesData = r.json;
  const edit = can('admin');
  $('rules-actions').hidden = !edit;
  const numInput = (value, min, max, step, disabled, attrs = {}) =>
    el('input', { type: 'number', value: String(value), min: String(min), max: String(max), step: String(step), disabled, ...attrs });
  // exceptions and watches are saved as soon as they are changed
  const saveNow = async (patch) => {
    const res = await api('PUT', '/api/rules', patch);
    $('rules-status').textContent = res.ok ? tr('Saved. Applies within a few seconds.') : apiError(res);
    if (res.ok) loadRules();
    return res;
  };

  const g = rulesData.min_score;
  const minIn = numInput(g.value, 0, 100, 1, !edit, { id: 'rule-min-score' });
  $('rules-global').replaceChildren(
    el('div', { class: 'rule-head' }, el('b', { text: tr('Minimum score to raise an alert') }),
      g.overridden ? el('span', { class: 'changed', text: tr('changed (default {value})', { value: g.default }) }) : null),
    el('p', { class: 'muted', text: tr('Events scoring below this are recorded but not shown as alerts, and never sent out. Raise it to hear less, lower it to hear more.') }),
    el('div', { class: 'rule-controls' }, el('label', {}, tr('Score'), minIn)));

  const cards = [];
  for (const [group, title] of [['network', tr('Network rules')], ['ot', tr('Industrial (OT) rules')]]) {
    cards.push(el('div', { class: 'group-title', text: title }));
    if (group === 'ot') cards.push(watchesSection(edit, saveNow));
    if (group === 'network') cards.push(itWatchesSection(edit, saveNow));
    // the watches have their own cards (with their own exceptions); the rules behind them only carry the weight

    for (const rule of rulesData.rules.filter((x) => x.group === group)) {
      const on = el('input', { type: 'checkbox', checked: rule.enabled, disabled: !edit, id: 'rule-on-' + rule.id });
      const w = numInput(rule.weight, 0, 5, 0.05, !edit, { id: 'rule-w-' + rule.id });
      const own = numInput(rule.min_score == null ? '' : rule.min_score, 0, 100, 1, !edit, { id: 'rule-min-' + rule.id, placeholder: String(g.value) });
      const params = rule.params.map((p) => el('label', { title: tr(p.help) },
        tr(p.label) + ' (' + tr(p.unit) + ')' + (p.overridden ? ' • ' + tr('changed') : ''),
        numInput(p.value, p.min, p.max, p.step, !edit, { id: 'rule-p-' + p.key, 'data-key': p.key })));
      const exceptions = (rulesData.exceptions || {})[rule.id] || [];
      const card = el('div', { class: 'rule-card' + (rule.enabled ? '' : ' off'), id: 'rule-' + rule.id },
        el('div', { class: 'rule-head' }, on, el('b', { text: tr(rule.title) }), el('code', { text: rule.id }),
          rule.overridden ? el('span', { class: 'changed', text: tr('changed') }) : null),
        el('p', { text: tr(rule.summary) }),
        el('p', { class: 'muted', text: tr('Needs: {needs}', { needs: tr(rule.needs) }) }),
        el('div', { class: 'rule-controls' },
          el('label', { title: tr('1 = as designed, 0.5 = half as loud, 2 = twice as loud (scores are capped at 100)') }, tr('Weight (default {value})', { value: rule.default_weight }), w),
          el('label', { title: tr('Below this score this rule is only logged. Empty: use the minimum score above.') }, tr('Alert only from score'), own), ...params),
        rule.id === 'ot_command_watch' || rule.id === 'it_watch' ? null : el('details', { class: 'exceptions', open: exceptions.length > 0 },
          el('summary', { text: exceptions.length ? tr('Exceptions ({n})', { n: exceptions.length }) : tr('Exceptions') }),
          el('p', { class: 'muted small', text: tr('This rule stays quiet about these devices, device types, tags or networks. For industrial alerts the sending device counts too.') }),
          scopeEditor(exceptions, (list) => saveNow({ exceptions: { [rule.id]: list } }), edit)));
      on.onchange = () => { card.classList.toggle('off', !on.checked); if (on.checked && Number(w.value) === 0) w.value = String(rule.default_weight || 1); };
      cards.push(card);
    }
  }
  $('rules-list').replaceChildren(...cards);
}

$('rules-save').onclick = async () => {
  if (!rulesData) return;
  // send only what the person actually changed, so untouched settings keep following the
  // command-line defaults instead of being frozen as overrides
  const patch = { weights: {}, params: {}, min_scores: {} };
  const min = Number($('rule-min-score').value);
  if (min !== rulesData.min_score.value) patch.min_score = min;
  for (const rule of rulesData.rules) {
    // an unticked rule is a weight of 0; a ticked one keeps the weight typed
    const w = $('rule-on-' + rule.id).checked ? Number($('rule-w-' + rule.id).value) : 0;
    if (w !== rule.weight) patch.weights[rule.id] = w;
    const raw = $('rule-min-' + rule.id).value.trim();
    const own = raw === '' ? null : Number(raw);
    if (own !== (rule.min_score == null ? null : rule.min_score)) patch.min_scores[rule.id] = own;
    for (const p of rule.params) {
      const v = Number($('rule-p-' + p.key).value);
      if (v !== p.value) patch.params[p.key] = v;
    }
  }
  if (patch.min_score === undefined && !Object.keys(patch.weights).length && !Object.keys(patch.params).length && !Object.keys(patch.min_scores).length) {
    $('rules-status').textContent = tr('Nothing changed.');
    return;
  }
  const r = await api('PUT', '/api/rules', patch);
  $('rules-status').textContent = r.ok ? tr('Saved. Applies within a few seconds.') : apiError(r);
  if (r.ok) loadRules();
};

$('rules-reset').onclick = async () => {
  if (!confirm(tr('Reset every weight, threshold and minimum score to its default? Your exceptions and OT watches are kept.'))) return;
  // null removes an override: send one for everything that is set
  const patch = { min_score: null, weights: {}, params: {}, min_scores: {} };
  for (const rule of rulesData.rules) {
    if (rule.overridden) patch.weights[rule.id] = null;
    if (rule.min_score != null) patch.min_scores[rule.id] = null;
    for (const p of rule.params) if (p.overridden) patch.params[p.key] = null;
  }
  const r = await api('PUT', '/api/rules', patch);
  $('rules-status').textContent = r.ok ? tr('Back to defaults.') : apiError(r);
  if (r.ok) loadRules();
};

// ------------------------------------------------------------------------------- OT command watches

/** Ready-made watches: a click fills the form, the person adjusts it. */
const WATCH_PRESETS = () => [
  { label: tr('Only these devices may talk to it (any communication, also encrypted)'), proto: 'any', any_traffic: true },
  { label: tr('Any write command (registers, coils, tags)'), proto: 'any', writes: true },
  { label: tr('Any control command (stop, start, download, restart)'), proto: 'any', controls: true },
  { label: tr('Siemens S7: CPU stop'), proto: 's7', commands: ['PLC stop'] },
  { label: tr('Siemens S7: program download'), proto: 's7', commands: ['program download'] },
  { label: tr('Modbus: any write'), proto: 'modbus', writes: true },
  { label: tr('Modbus: diagnostics (restart, listen-only)'), proto: 'modbus', commands: ['diagnostics'] },
  { label: tr('EtherNet/IP: stop or reset'), proto: 'enip', commands: ['CIP stop', 'CIP reset'] },
  { label: tr('DNP3: restart'), proto: 'dnp3', commands: ['restart'] },
  { label: tr('DNP3: operate (switching)'), proto: 'dnp3', commands: ['operate'] },
  { label: tr('BACnet: reinitialize device'), proto: 'bacnet', commands: ['reinitialize'] },
  { label: tr('IEC 60870-5-104: any command'), proto: 'iec104', controls: true },
];

const PROTO_NAMES = () => ({ any: tr('any protocol'), modbus: 'Modbus', s7: 'Siemens S7', enip: 'EtherNet/IP', dnp3: 'DNP3', bacnet: 'BACnet', opcua: 'OPC UA', iec104: 'IEC 60870-5-104', tls: tr('any TLS (encrypted)'), 'modbus-tls': 'Modbus/TCP Security (TLS)', 'opcua-tls': 'OPC UA (TLS)', 'iec104-tls': 'IEC 104 (TLS)', 'dnp3-tls': 'DNP3 (TLS)', 'mqtt-tls': 'MQTT (TLS)' });

/** From the communications matrix: start a watch for one command on one path. */
function watchFor(conv, cmd) {
  const word = cmd.replace(/\s*\([^)]*\)\s*$/, '').trim() || cmd; // "write single register (6)" -> "write single register"
  const target = conv.server && conv.server.id != null ? [{ kind: 'device', value: String(conv.server.id) }] : [];
  openWatchForm({ name: word + ' → ' + (conv.server.name || conv.server.ip || conv.server.mac), proto: conv.protocol, commands: [word], targets: target },
    (nw) => api('PUT', '/api/rules', { ot_watches: [...((rulesData && rulesData.ot_watches) || []), nw] }).then((r) => { if (r.ok) setTab('rules'); return r; }));
}

/** What a watch looks for, in one line. */
function watchText(w) {
  const what = [];
  if (w.any_traffic) what.push(tr('any communication'));
  if (w.controls) what.push(tr('any control command'));
  if (w.writes) what.push(tr('any write'));
  what.push(...w.commands.map((c) => '"' + c + '"'));
  return (PROTO_NAMES()[w.proto] || w.proto) + ': ' + what.join(', ');
}

/** The "your own watches" block at the top of the OT rules. */
function watchesSection(edit, saveNow) {
  const list = rulesData.ot_watches || [];
  const put = (next) => saveNow({ ot_watches: next });
  const rows = list.map((w, i) => el('div', { class: 'watch' + (w.enabled ? '' : ' off') },
    el('div', { class: 'rule-head' },
      el('input', { type: 'checkbox', checked: w.enabled, disabled: !edit, title: tr('On or off'), onchange: (ev) => put(list.map((x, j) => (j === i ? { ...x, enabled: ev.target.checked } : x))) }),
      el('b', { text: w.name }), el('span', { class: 'muted small', text: tr('score {n}', { n: w.score }) }),
      edit ? el('span', { class: 'watch-actions' },
        el('button', { type: 'button', text: tr('Edit'), onclick: () => openWatchForm(w, (nw) => put(list.map((x, j) => (j === i ? nw : x)))) }),
        el('button', { type: 'button', text: tr('Delete'), onclick: () => { if (confirm(tr('Delete the watch "{name}"?', { name: w.name }))) put(list.filter((_, j) => j !== i)); } })) : null),
    el('div', { text: watchText(w) }),
    el('div', { class: 'muted small' },
      tr('Targets') + ': ' + (w.targets.length ? w.targets.map(scopeText).join(', ') : tr('any device')) + ' · ' +
      tr('Allowed senders') + ': ' + (w.allowed_senders.length ? w.allowed_senders.map(scopeText).join(', ') : tr('none')) + ' · ' +
      tr('at most one alert per {n} min', { n: w.cooldown_minutes }))));
  return el('div', { class: 'rule-card', id: 'watches' },
    el('div', { class: 'rule-head' }, el('b', { text: tr('Your OT command watches') }), el('code', { text: 'ot_command_watch' })),
    el('p', { class: 'muted', text: tr('Be told when a specific command reaches a specific industrial device: a CPU stop, a program download, any write to a pump station. Exclude your own engineering station with "allowed senders". Watches also fire during the learning period.') }),
    ...rows,
    list.length ? null : el('p', { class: 'muted', text: tr('No watches yet.') }),
    edit ? el('div', { class: 'row' }, el('button', { type: 'button', class: 'primary', text: tr('Add a watch'), onclick: () => openWatchForm(null, (nw) => put([...list, nw])) })) : null);
}

/**
 * The watch form. `prefill` may be a saved watch (edit) or the beginnings of one; `done(watch)` is
 * called with the finished watch when the person saves.
 */
async function openWatchForm(prefill, done) {
  const w = { name: '', enabled: true, proto: 'any', writes: false, controls: false, any_traffic: false, commands: [], targets: [], allowed_senders: [], score: 80, cooldown_minutes: 10, ...(prefill || {}) };
  const isNew = !prefill || !prefill.id;
  let targets = w.targets.slice();
  let senders = w.allowed_senders.slice();
  // functions really seen on this network: a click adds the word
  const seen = new Map();
  const cr = await api('GET', '/api/conversations');
  if (cr.ok) for (const c of cr.json) for (const [cmd, n] of Object.entries(c.commands || {})) seen.set(cmd, (seen.get(cmd) || 0) + n);

  const nameIn = el('input', { value: w.name, maxLength: 60, required: true, placeholder: tr('e.g. Stop commands to line 1') });
  const preset = el('select', {}, el('option', { value: '', text: tr('Start from a common watch…') }), ...WATCH_PRESETS().map((p, i) => el('option', { value: String(i), text: p.label })));
  const proto = el('select', {}, ...Object.entries(PROTO_NAMES()).map(([v, t]) => el('option', { value: v, text: t })));
  proto.value = w.proto;
  const writes = el('input', { type: 'checkbox', checked: w.writes });
  const controls = el('input', { type: 'checkbox', checked: w.controls });
  const anyTraffic = el('input', { type: 'checkbox', checked: w.any_traffic });
  const words = el('input', { value: w.commands.join(', '), placeholder: tr('e.g. write single register, 0x29, restart') });
  const seenBox = el('div', { class: 'chips' });
  const drawSeen = () => seenBox.replaceChildren(...[...seen.entries()].sort((a, b) => b[1] - a[1]).slice(0, 12).map(([cmd, n]) => el('button', {
    type: 'button', class: 'chip', title: tr('{n} seen', { n }), text: cmd,
    onclick: () => { const cur = words.value.split(',').map((x) => x.trim()).filter(Boolean); if (!cur.includes(cmd)) cur.push(cmd); words.value = cur.join(', '); },
  })));
  drawSeen();
  const score = el('input', { type: 'number', min: 1, max: 100, value: String(w.score) });
  const gap = el('input', { type: 'number', min: 1, max: 1440, value: String(w.cooldown_minutes) });
  const enabled = el('input', { type: 'checkbox', checked: w.enabled });
  preset.onchange = () => {
    const p = WATCH_PRESETS()[Number(preset.value)];
    if (!p) return;
    proto.value = p.proto;
    writes.checked = !!p.writes;
    controls.checked = !!p.controls;
    anyTraffic.checked = !!p.any_traffic;
    words.value = (p.commands || []).join(', ');
    if (!nameIn.value.trim()) nameIn.value = p.label;
  };
  const targetsBox = el('div', {});
  const sendersBox = el('div', {});
  const drawScopes = () => {
    targetsBox.replaceChildren(scopeEditor(targets, (l) => { targets = l; drawScopes(); }, true));
    sendersBox.replaceChildren(scopeEditor(senders, (l) => { senders = l; drawScopes(); }, true));
  };
  drawScopes();
  openForm(isNew ? tr('Add an OT command watch') : tr('Edit the OT command watch'), [el('div', { class: 'form-grid' },
    el('div', { class: 'field-wide' }, field(tr('Name'), nameIn)),
    field(tr('Start from'), preset),
    field(tr('Protocol'), proto),
    el('div', { class: 'field-wide' }, el('span', { class: 'label', text: tr('Alert when the command is') }),
      el('label', { class: 'check' }, anyTraffic, ' ' + tr('any communication at all, encrypted or not (use it with the targets and allowed senders below)')),
      el('label', { class: 'check' }, controls, ' ' + tr('any control command (stop, start, download, restart, operate)')),
      el('label', { class: 'check' }, writes, ' ' + tr('any write (registers, coils, tags, setpoints)')),
      el('label', {}, tr('or a function whose name contains (comma separated)'), words),
      seen.size ? el('div', { class: 'muted small' }, tr('Seen on your network (click to add):'), seenBox) : null),
    el('div', { class: 'field-wide' }, el('span', { class: 'label', text: tr('Only when the target is (empty: any device)') }), targetsBox),
    el('div', { class: 'field-wide' }, el('span', { class: 'label', text: tr('Never for these senders (for example your engineering station)') }), sendersBox),
    field(tr('Score of the alert (1–100)'), score),
    field(tr('At most one alert per sender and target in this many minutes'), gap),
    el('label', { class: 'check field-wide' }, enabled, ' ' + tr('On')))], {
    onSubmit: async () => {
      const commands = words.value.split(',').map((x) => x.trim()).filter(Boolean);
      const nw = {
        id: w.id || Math.random().toString(36).slice(2, 10).replace(/[^a-z0-9]/g, 'x'), name: nameIn.value.trim(), enabled: enabled.checked, proto: proto.value,
        writes: writes.checked, controls: controls.checked, any_traffic: anyTraffic.checked, commands, targets, allowed_senders: senders,
        score: Number(score.value), cooldown_minutes: Number(gap.value),
      };
      if (!nw.name) return tr('Give the watch a name.');
      if (!nw.writes && !nw.controls && !nw.any_traffic && !nw.commands.length) return tr('Choose what to watch for: any communication, a kind of command or a function name.');
      const res = await done(nw);
      return res && !res.ok ? apiError(res) : null;
    },
  });
}

// ------------------------------------------------------------------------------ network (IT) watches

const IT_PRESETS = () => [
  { label: tr('Devices talking to the internet'), remotes_mode: 'only', remotes: ['public'] },
  { label: tr('Remote access crossing the boundary (RDP, SSH, VNC, Telnet)'), ports_mode: 'only', ports: [3389, 22, 5900, 23], remotes_mode: 'only', remotes: ['public'] },
  { label: tr('Anything but DNS, web and time to the internet'), ports_mode: 'except', ports: [53, 80, 443, 123], remotes_mode: 'only', remotes: ['public'] },
  { label: tr('Mail sent straight from a device (SMTP)'), ports_mode: 'only', ports: [25, 465, 587], remotes_mode: 'only', remotes: ['public'] },
  { label: tr('Large transfer to the internet (5 MB or more in 10 seconds)'), remotes_mode: 'only', remotes: ['public'], min_kb: 5000 },
  { label: tr('Devices reaching the local network'), remotes_mode: 'only', remotes: ['private'] },
];

const IT_PROTO_NAMES = () => ({ any: tr('any protocol'), tcp: 'TCP', udp: 'UDP', icmp: 'ICMP' });
const LIST_MODE_NAMES = (what) => ({ any: what.any, only: what.only, except: what.except });

/** The words for one address entry: "the internet", "the local network", or the network itself. */
const remoteWord = (r) => (r === 'public' ? tr('the internet') : r === 'private' ? tr('the local network') : r.replace(/\/32$/, ''));

/** What a network watch looks for, in one line. */
function itWatchText(w) {
  const parts = [];
  parts.push(w.remotes_mode === 'any' ? tr('any address') : (w.remotes_mode === 'only' ? tr('to {list}', { list: w.remotes.map(remoteWord).join(', ') }) : tr('to anywhere except {list}', { list: w.remotes.map(remoteWord).join(', ') })));
  if (w.ports_mode !== 'any') parts.push(w.ports_mode === 'only' ? tr('on port {list}', { list: w.ports.join(', ') }) : tr('on any port except {list}', { list: w.ports.join(', ') }));
  if (w.proto !== 'any') parts.push(IT_PROTO_NAMES()[w.proto]);
  if (w.min_kb) parts.push(tr('at least {n} kB', { n: w.min_kb }));
  return parts.join(' · ');
}

/** The "your own network watches" block at the top of the network rules. */
function itWatchesSection(edit, saveNow) {
  const list = rulesData.it_watches || [];
  const put = (next) => saveNow({ it_watches: next });
  const rows = list.map((w, i) => el('div', { class: 'watch' + (w.enabled ? '' : ' off'), 'data-watch': w.id },
    el('div', { class: 'rule-head' },
      el('input', { type: 'checkbox', checked: w.enabled, disabled: !edit, title: tr('On or off'), onchange: (ev) => put(list.map((x, j) => (j === i ? { ...x, enabled: ev.target.checked } : x))) }),
      el('b', { text: w.name }), el('span', { class: 'muted small', text: tr('score {n}', { n: w.score }) }),
      edit ? el('span', { class: 'watch-actions' },
        el('button', { type: 'button', text: tr('Edit'), onclick: () => openItWatchForm(w, (nw) => put(list.map((x, j) => (j === i ? nw : x)))) }),
        el('button', { type: 'button', text: tr('Delete'), onclick: () => { if (confirm(tr('Delete the watch "{name}"?', { name: w.name }))) put(list.filter((_, j) => j !== i)); } })) : null),
    el('div', { text: itWatchText(w) }),
    el('div', { class: 'muted small' },
      tr('Devices') + ': ' + (w.sources.length ? w.sources.map(scopeText).join(', ') : tr('any device')) + ' · ' +
      tr('Never for') + ': ' + (w.except_sources.length ? w.except_sources.map(scopeText).join(', ') : tr('none')) + ' · ' +
      tr('at most one alert per {n} min', { n: w.cooldown_minutes }))));
  return el('div', { class: 'rule-card', id: 'it-watches' },
    el('div', { class: 'rule-head' }, el('b', { text: tr('Your network watches') }), el('code', { text: 'it_watch' })),
    el('p', { class: 'muted', text: tr('Be told when devices you choose talk to addresses or ports you did not allow: cameras reaching the internet, a server using an unusual port, the guest network reaching the office. Needs traffic analysis (--flows). Watches also fire during the learning period.') }),
    ...rows,
    list.length ? null : el('p', { class: 'muted', text: tr('No watches yet.') }),
    edit ? el('div', { class: 'row' }, el('button', { type: 'button', class: 'primary', id: 'add-it-watch', text: tr('Add a watch'), onclick: () => openItWatchForm(null, (nw) => put([...list, nw])) })) : null);
}

/** The network watch form. `prefill` may be a saved watch (edit) or the beginnings of one. */
function openItWatchForm(prefill, done) {
  const w = { name: '', enabled: true, sources: [], except_sources: [], proto: 'any', ports_mode: 'any', ports: [], remotes_mode: 'only', remotes: ['public'], min_kb: 0, score: 60, cooldown_minutes: 30, ...(prefill || {}) };
  const isNew = !prefill || !prefill.id;
  let sources = w.sources.slice();
  let except = w.except_sources.slice();
  const nameIn = el('input', { value: w.name, maxLength: 60, required: true, placeholder: tr('e.g. Cameras must not reach the internet') });
  const preset = el('select', {}, el('option', { value: '', text: tr('Start from a common watch…') }), ...IT_PRESETS().map((p, i) => el('option', { value: String(i), text: p.label })));
  const proto = el('select', {}, ...Object.entries(IT_PROTO_NAMES()).map(([v, t]) => el('option', { value: v, text: t })));
  proto.value = w.proto;
  const portsMode = el('select', {}, ...Object.entries(LIST_MODE_NAMES({ any: tr('any port'), only: tr('only these ports'), except: tr('any port except these') })).map(([v, t]) => el('option', { value: v, text: t })));
  portsMode.value = w.ports_mode;
  const ports = el('input', { value: w.ports.join(', '), placeholder: tr('e.g. 22, 3389') });
  const remotesMode = el('select', {}, ...Object.entries(LIST_MODE_NAMES({ any: tr('any address'), only: tr('only these addresses'), except: tr('any address except these') })).map(([v, t]) => el('option', { value: v, text: t })));
  remotesMode.value = w.remotes_mode;
  const remotes = el('input', { value: w.remotes.join(', '), placeholder: tr('e.g. public, 10.0.5.0/24, 192.168.1.10') });
  const addWord = (word) => () => { const cur = remotes.value.split(',').map((x) => x.trim()).filter(Boolean); if (!cur.includes(word)) cur.push(word); remotes.value = cur.join(', '); };
  const chips = el('div', { class: 'chips' },
    el('button', { type: 'button', class: 'chip', text: tr('the internet (public)'), onclick: addWord('public') }),
    el('button', { type: 'button', class: 'chip', text: tr('the local network (private)'), onclick: addWord('private') }));
  const minKb = el('input', { type: 'number', min: 0, max: 100000000, value: String(w.min_kb) });
  const score = el('input', { type: 'number', min: 1, max: 100, value: String(w.score) });
  const gap = el('input', { type: 'number', min: 1, max: 1440, value: String(w.cooldown_minutes) });
  const enabled = el('input', { type: 'checkbox', checked: w.enabled });
  preset.onchange = () => {
    const p = IT_PRESETS()[Number(preset.value)];
    if (!p) return;
    proto.value = p.proto || 'any';
    portsMode.value = p.ports_mode || 'any';
    ports.value = (p.ports || []).join(', ');
    remotesMode.value = p.remotes_mode || 'any';
    remotes.value = (p.remotes || []).join(', ');
    minKb.value = String(p.min_kb || 0);
    if (!nameIn.value.trim()) nameIn.value = p.label;
  };
  const sourcesBox = el('div', {});
  const exceptBox = el('div', {});
  const drawScopes = () => {
    sourcesBox.replaceChildren(scopeEditor(sources, (l) => { sources = l; drawScopes(); }, true));
    exceptBox.replaceChildren(scopeEditor(except, (l) => { except = l; drawScopes(); }, true));
  };
  drawScopes();
  openForm(isNew ? tr('Add a network watch') : tr('Edit the network watch'), [el('div', { class: 'form-grid' },
    el('div', { class: 'field-wide' }, field(tr('Name'), nameIn)),
    field(tr('Start from'), preset),
    field(tr('Protocol'), proto),
    el('div', { class: 'field-wide' }, el('span', { class: 'label', text: tr('For these devices (empty: any device)') }), sourcesBox),
    el('div', { class: 'field-wide' }, el('span', { class: 'label', text: tr('Never for these devices') }), exceptBox),
    field(tr('Talking on'), portsMode), field(tr('Ports (comma separated)'), ports),
    field(tr('Talking to'), remotesMode), field(tr('Addresses (comma separated)'), remotes),
    el('div', { class: 'field-wide muted small' }, tr('Use the words public (the internet) and private (the local network), single addresses, or networks like 10.0.5.0/24.'), chips),
    field(tr('Only when at least this many kB moved in 10 seconds (0: any amount)'), minKb),
    field(tr('Score of the alert (1–100)'), score),
    field(tr('At most one alert per device, address and port in this many minutes'), gap),
    el('label', { class: 'check field-wide' }, enabled, ' ' + tr('On')))], {
    onSubmit: async () => {
      const nw = {
        id: w.id || Math.random().toString(36).slice(2, 10).replace(/[^a-z0-9]/g, 'x'), name: nameIn.value.trim(), enabled: enabled.checked,
        sources, except_sources: except, proto: proto.value,
        ports_mode: portsMode.value, ports: ports.value.split(',').map((x) => x.trim()).filter(Boolean).map(Number),
        remotes_mode: remotesMode.value, remotes: remotes.value.split(',').map((x) => x.trim()).filter(Boolean),
        min_kb: Number(minKb.value) || 0, score: Number(score.value), cooldown_minutes: Number(gap.value),
      };
      if (!nw.name) return tr('Give the watch a name.');
      if (nw.ports.some((p) => !Number.isInteger(p) || p < 1 || p > 65535)) return tr('Ports are numbers from 1 to 65535, separated by commas.');
      const res = await done(nw);
      return res && !res.ok ? apiError(res) : null;
    },
  });
}
