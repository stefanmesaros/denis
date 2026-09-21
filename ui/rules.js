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
      input = el('input', { placeholder: tr('e.g. printer'), maxLength: 60 });
      input.setAttribute('list', 'type-list');
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
        rule.id === 'ot_command_watch' ? null : el('details', { class: 'exceptions', open: exceptions.length > 0 },
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

const PROTO_NAMES = () => ({ any: tr('any protocol'), modbus: 'Modbus', s7: 'Siemens S7', enip: 'EtherNet/IP', dnp3: 'DNP3', bacnet: 'BACnet', opcua: 'OPC UA', iec104: 'IEC 60870-5-104' });

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
  const w = { name: '', enabled: true, proto: 'any', writes: false, controls: false, commands: [], targets: [], allowed_senders: [], score: 80, cooldown_minutes: 10, ...(prefill || {}) };
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
        writes: writes.checked, controls: controls.checked, commands, targets, allowed_senders: senders,
        score: Number(score.value), cooldown_minutes: Number(gap.value),
      };
      if (!nw.name) return tr('Give the watch a name.');
      if (!nw.writes && !nw.controls && !nw.commands.length) return tr('Choose what to watch for: a kind of command or a function name.');
      const res = await done(nw);
      return res && !res.ok ? apiError(res) : null;
    },
  });
}
