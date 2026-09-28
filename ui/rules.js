'use strict';
// The Rules page: every detection, how it is set, exceptions per rule, and the administrator's own
// OT command watches. Loaded after admin.js (dialogs, api(), field(), openForm()).

let rulesData = null;

// --------------------------------------------------------------- scopes (exceptions, targets, senders)

/** What to actually do about traffic analysis being off: restart with --flows (a CLI flag, not
 * something the console can switch on), and make sure the traffic in question crosses the
 * interface DENIS captures on — add it as a mirror interface under Settings otherwise. */
const FLOWS_FIX = () => tr('Start DENIS with --flows, and if this traffic does not cross {iface}, add its interface as a mirror interface under Settings → Network interfaces.', { iface: (state.status && state.status.interface) || tr('the discovery interface') });

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

/** The "add one" mini-form shared by scopeEditor and exceptionsEditor: a labelled kind selector,
 * a labelled matching-value input (empty/unselected until you choose one — never a value picked
 * for you), and an Add button. Visually set apart (`scope-add-form`) from whatever list it is
 * adding to, so it reads as "add a new one", not as one more row in that list. */
function scopeAddForm(list, onChange) {
  const kind = el('select', {}, ...SCOPE_KINDS().map(([v, t]) => el('option', { value: v, text: t })));
  const holder = el('span', {});
  let input;
  const draw = () => {
    const valueLabel = SCOPE_KINDS().find(([v]) => v === kind.value)[1];
    if (kind.value === 'device') {
      const devices = state.assets.slice().sort((x, y) => (name(x) || x.ip || x.mac).localeCompare(name(y) || y.ip || y.mac));
      input = el('select', {}, el('option', { value: '', text: tr('Choose one…') }), ...devices.map((a) => el('option', { value: String(a.id), text: (name(a) || a.mac) + (a.ip ? ' · ' + a.ip : '') })));
    } else if (kind.value === 'type') {
      const types = ((state.options && state.options.device_types) || []).slice().sort((x, y) => nameOf(x).localeCompare(nameOf(y), locale()));
      input = el('select', {}, el('option', { value: '', text: tr('Choose one…') }), ...types.map((t) => el('option', { value: t, text: nameOf(t) })));
    } else {
      input = el('input', { placeholder: kind.value === 'cidr' ? '10.0.5.0/24' : tr('e.g. server-room'), maxLength: 60 });
    }
    holder.replaceChildren(field(valueLabel, input));
  };
  kind.onchange = draw;
  draw();
  const add = el('button', { type: 'button', text: tr('Add'), onclick: () => {
    const value = input.value.trim();
    if (!value) return;
    if (list.some((s) => s.kind === kind.value && s.value === value)) return;
    onChange([...list, { kind: kind.value, value }]);
  } });
  return el('div', { class: 'row scope-add-form' }, field(tr('Match by'), kind), holder, add);
}

/**
 * A list of scopes with a small form to add one. `onChange(list)` is called with the new list;
 * read-only (`editable` false) it only shows the chips.
 */
function scopeEditor(list, onChange, editable) {
  const chips = el('div', { class: 'chips' }, ...list.map((s, i) => el('span', { class: 'chip' }, scopeText(s),
    editable ? el('button', { type: 'button', class: 'chip-x', title: tr('Remove'), text: '×', onclick: () => onChange(list.filter((_, j) => j !== i)) }) : null)));
  if (!editable) return list.length ? chips : el('span', { class: 'muted small', text: tr('none') });
  return el('div', {}, chips, scopeAddForm(list, onChange));
}

/**
 * Exceptions specifically: a device-kind entry is shown as a row — who it actually is (name, MAC,
 * IP) and, when the console added it for you ("Add exception" on an alert), why — instead of
 * scopeEditor's plain "Device: <name>" chip, since an exception usually needs to be *recognised*
 * at a glance, not just named. Non-device kinds (type/tag/network) still render as chips: there is
 * no one device to describe. The remove button is a small square at the *start* of the row (a
 * consistent left-hand column to scan and click, instead of hunting for it after text of very
 * different lengths). Same `onChange`/`editable` contract as scopeEditor.
 */
function exceptionsEditor(list, onChange, editable) {
  const remove = (i) => onChange(list.filter((_, j) => j !== i));
  const rows = list.map((s, i) => {
    const removeBtn = editable ? el('button', { type: 'button', class: 'exception-remove', title: tr('Remove'), text: '×', onclick: () => remove(i) }) : null;
    if (s.kind !== 'device') {
      return el('div', { class: 'exception-row' }, removeBtn, el('div', { class: 'exception-row-body' }, el('div', {}, el('b', { text: scopeText(s) }))));
    }
    const a = assetById(Number(s.value));
    return el('div', { class: 'exception-row' },
      removeBtn,
      el('div', { class: 'exception-row-body' },
        el('div', {},
          el('b', { text: a ? deviceLabel(a, '#' + s.value) : tr('device #{id} (no longer known)', { id: s.value }) }),
          a ? el('span', { class: 'muted small', text: ' · ' + a.mac + (a.ip ? ' · ' + a.ip : '') }) : null),
        s.note ? el('div', { class: 'muted small', text: s.note }) : null));
  });
  const body = rows.length ? el('div', { class: 'exception-rows' }, ...rows) : el('span', { class: 'muted small', text: tr('none') });
  return editable ? el('div', {}, body, scopeAddForm(list, onChange)) : body;
}

// -------------------------------------------------------------------------------------- rules page

/** "Continue learning mode" (admin only): while it runs, nothing anywhere raises an alert —
 * every device is treated the way a brand new one already is — network-wide, for a chosen
 * 1-7 days. For after a change big enough that the existing baselines are not a fair
 * comparison any more (a new switch, a re-addressed subnet, a big batch of new devices). Named
 * "continue", not "restart": it only pauses alerting for the window - each device's baseline
 * keeps accumulating underneath it exactly as always, never reset. */
let learningExpiryTimer = null;

/** "Forget all learned baseline data" - a real reset, unlike learning mode itself. Lives right
 * here (not in Settings) because this is exactly where an admin is already thinking about
 * learning/baselines, and the two are easy to conflate otherwise - see the copy above/below this
 * button, which exists specifically to draw the distinction. */
function forgetAllBaselineButton() {
  return el('button', { type: 'button', class: 'danger', onclick: () => {
    const phrase = 'FORGET LEARNED BASELINE';
    const input = el('input', { placeholder: phrase, autocomplete: 'off' });
    openForm(tr('Forget all learned baseline data'), [
      el('p', { text: tr('This forgets every device\'s learned traffic baseline (destinations, ports, volume, active hours). Devices, alerts, the communications matrix and everything else are kept. The next traffic from any device is judged fresh, exactly like a device that was just discovered.') }),
      el('p', { class: 'form-error', text: tr('It cannot be undone.') }),
      field(tr('Type {phrase} to confirm', { phrase }), input),
    ], {
      submitLabel: tr('Forget it all'),
      onSubmit: async () => {
        if (input.value.trim() !== phrase) return tr('Type the words exactly as shown.');
        const r = await api('POST', '/api/baseline/forget-all', { confirm: phrase });
        if (!r.ok) return apiError(r);
        $('learning-msg').textContent = tr('Every learned baseline was forgotten.');
        return null;
      },
    });
  }, text: tr('Forget all learned baseline data…') });
}

function drawLearningBox(learning) {
  if (learningExpiryTimer) {
    clearTimeout(learningExpiryTimer);
    learningExpiryTimer = null;
  }
  const act = async (path, body) => {
    const r = await api('POST', '/api/learning/' + path, body);
    $('learning-msg').textContent = r.ok ? '' : apiError(r);
    if (r.ok) loadRules();
  };
  if (!learning) {
    const days = el('select', {}, ...[1, 2, 3, 4, 5, 6, 7].map((n) => el('option', { value: String(n), text: n === 1 ? tr('1 day') : tr('{n} days', { n }) })));
    days.value = '3';
    $('learning-box').replaceChildren(
      el('div', { class: 'rule-head' }, el('b', { text: tr('Continue learning mode') })),
      el('p', { class: 'muted', text: tr('After a change big enough that the existing baselines no longer make a fair comparison (a new switch, a re-addressed subnet, a batch of new devices), continue learning for every device at once: nothing anywhere alerts for the time you choose, the same treatment a brand new device already gets.') }),
      el('p', { class: 'muted small', text: tr('This only pauses alerting — it adds to what each device has already learned, it never throws that away. To make every baseline start over from nothing instead, use "Forget all learned baseline data" below.') }),
      el('div', { class: 'rule-controls' }, el('label', {}, tr('For'), days),
        el('button', { type: 'button', onclick: () => act('start', { days: Number(days.value) }), text: tr('Continue learning mode') }),
        forgetAllBaselineButton()),
      el('span', { id: 'learning-msg', class: 'muted' }));
    return;
  }
  // If it is still running (not paused), the countdown ends on its own without anyone clicking
  // anything - re-check right when that happens so this box does not keep showing Pause/End for
  // a learning period the server has already finished (loadRules() redraws from fresh data, which
  // then falls into the `!learning` branch above once the server reports it as over).
  if (!learning.paused) {
    learningExpiryTimer = setTimeout(loadRules, Math.max(1, learning.remaining_secs) * 1000 + 1000);
  }
  const remaining = span(learning.remaining_secs);
  $('learning-box').replaceChildren(
    el('div', { class: 'rule-head' }, el('b', { text: tr('Learning mode is running') }),
      el('span', { class: 'changed', text: learning.paused ? tr('paused') : tr('active') })),
    el('p', { class: 'muted', text: learning.paused
      ? tr('Paused with {remaining} left; nothing resumes counting down until you resume it. Nothing alerts anywhere while it is paused, either.', { remaining })
      : tr('{remaining} left. Nothing anywhere raises an alert until then, or until you end it early.', { remaining }) }),
    el('p', { class: 'muted small', text: tr('Each device keeps learning normally underneath this — nothing is reset, only alerting is paused.') }),
    el('div', { class: 'rule-controls' },
      el('button', { type: 'button', onclick: () => act(learning.paused ? 'resume' : 'pause', {}), text: learning.paused ? tr('Resume') : tr('Pause') }),
      el('button', { type: 'button', class: 'danger', onclick: async () => { if (confirm(tr('End learning mode now? Detection returns to normal immediately.'))) await act('end', {}); }, text: tr('End now') }),
      forgetAllBaselineButton()),
    el('span', { id: 'learning-msg', class: 'muted' }));
}

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

  $('learning-box').hidden = !edit;
  if (edit) drawLearningBox(rulesData.learning);

  const cards = [];
  cards.push(el('p', { class: 'muted small', text: '* ' + tr('needs traffic analysis (--flows), on the main interface or a mirror port') + (state.status && !state.status.flows_enabled ? ' — ' + tr('not currently running: {fix}', { fix: FLOWS_FIX() }) : '') }));
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
      const needsFlows = /--flows|mirror port/.test(rule.needs);
      const flowsMissing = needsFlows && state.status && !state.status.flows_enabled;
      const card = el('div', { class: 'rule-card' + (rule.enabled ? '' : ' off'), id: 'rule-' + rule.id },
        el('div', { class: 'rule-head' }, on, el('b', { text: tr(rule.title) }), el('code', { text: rule.id }),
          needsFlows ? el('span', { class: 'muted small', title: tr('Needs traffic analysis (--flows).') }, ' *') : null,
          rule.overridden ? el('span', { class: 'changed', text: tr('changed') }) : null),
        el('p', { text: tr(rule.summary) }),
        el('p', { class: flowsMissing ? 'form-error' : 'muted', text: (flowsMissing ? '⚠ ' : '') + tr('Needs: {needs}', { needs: tr(rule.needs) }) + (flowsMissing ? ' — ' + tr('not currently running: {fix}', { fix: FLOWS_FIX() }) : '') }),
        el('div', { class: 'rule-controls' },
          el('label', { title: tr('1 = as designed, 0.5 = half as loud, 2 = twice as loud (scores are capped at 100)') }, tr('Weight (default {value})', { value: rule.default_weight }), w),
          el('label', { title: tr('Below this score this rule is only logged. Empty: use the minimum score above.') }, tr('Alert only from score'), own), ...params),
        rule.id === 'ot_command_watch' || rule.id === 'it_watch' ? null : el('details', { class: 'exceptions', id: 'exceptions-' + rule.id, open: exceptions.length > 0 },
          el('summary', { text: exceptions.length ? tr('Exceptions ({n})', { n: exceptions.length }) : tr('Exceptions') }),
          el('p', { class: 'muted small', text: tr('This rule stays quiet about these devices, device types, tags or networks. For industrial alerts the sending device counts too.') }),
          exceptionsEditor(exceptions, (list) => saveNow({ exceptions: { [rule.id]: list } }), edit)));
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

// Export: the browser's normal download-a-link dance, so the file keeps its name and the
// person is never navigated away from the console. Import reads the chosen file and PUTs it
// as-is — it is already the exact shape /api/rules validates and applies (see rules_export).
$('rules-export').onclick = () => el('a', { href: '/api/rules/export', download: 'denis-rules.json' }).click();
$('rules-import').onclick = () => $('rules-import-file').click();
$('rules-import-file').onchange = async (ev) => {
  const file = ev.target.files[0];
  ev.target.value = ''; // so choosing the same file again still fires onchange
  if (!file) return;
  let patch;
  try {
    patch = JSON.parse(await file.text());
  } catch {
    $('rules-status').textContent = tr('Not a valid rules file.');
    return;
  }
  if (!confirm(tr('Import "{name}"? It replaces the settings it names (weights, thresholds, exceptions, watches) — anything not in the file is left as it is.', { name: file.name }))) return;
  const r = await api('PUT', '/api/rules', patch);
  $('rules-status').textContent = r.ok ? tr('Imported.') : apiError(r);
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

const PROTO_NAMES = () => ({ any: tr('any protocol'), modbus: 'Modbus', s7: 'Siemens S7', enip: 'EtherNet/IP', dnp3: 'DNP3', bacnet: 'BACnet', opcua: 'OPC UA', iec104: 'IEC 60870-5-104', fins: 'Omron FINS', 'hart-ip': 'HART-IP', 'knxnet-ip': 'KNXnet/IP', mqtt: 'MQTT', coap: 'CoAP', tls: tr('any TLS (encrypted)'), 'modbus-tls': 'Modbus/TCP Security (TLS)', 'opcua-tls': 'OPC UA (TLS)', 'iec104-tls': 'IEC 104 (TLS)', 'dnp3-tls': 'DNP3 (TLS)', 'mqtt-tls': 'MQTT (TLS)' });

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
    el('div', { class: 'rule-head' }, el('b', { text: tr('Your OT command watches') }), el('code', { text: 'ot_command_watch' }), el('span', { class: 'muted small', title: tr('Needs traffic analysis on a mirror port (--flows).') }, ' *')),
    el('p', { class: 'muted', text: tr('Be told when a specific command reaches a specific industrial device: a CPU stop, a program download, any write to a pump station. Exclude your own engineering station with "allowed senders". Watches also fire during the learning period.') }),
    state.status && !state.status.flows_enabled ? el('p', { class: 'form-error', text: '⚠ ' + tr('Not currently running: traffic analysis on a mirror port (--flows) is off. Watches are saved but will not fire until it is on.') + ' ' + FLOWS_FIX() }) : null,
    ...rows,
    list.length ? null : el('p', { class: 'muted', text: tr('No watches yet.') }),
    edit ? el('div', { class: 'row watch-add' }, el('button', { type: 'button', class: 'primary', text: tr('New Rule'), onclick: () => openWatchForm(null, (nw) => put([...list, nw])) })) : null);
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
    sendersBox.replaceChildren(exceptionsEditor(senders, (l) => { senders = l; drawScopes(); }, true));
  };
  drawScopes();
  const flowsWarning = state.status && !state.status.flows_enabled
    ? el('div', { class: 'field-wide form-error', text: '⚠ ' + tr('Traffic analysis on a mirror port is not currently running: this watch is saved but will not fire until it is.') + ' ' + FLOWS_FIX() })
    : null;
  openForm(isNew ? tr('Add an OT command watch') : tr('Edit the OT command watch'), [el('div', { class: 'form-grid' },
    el('label', { class: 'check field-wide' }, enabled, ' ' + tr('Watch enabled')),
    flowsWarning,
    el('div', { class: 'field-wide' }, field(tr('Name'), nameIn)),
    isNew ? field(tr('Start from a ready-made watch, then adjust it below (optional)'), preset) : null,
    field(tr('Protocol'), proto),
    el('div', { class: 'field-wide' }, el('span', { class: 'label', text: tr('Alert when the command is') }),
      el('label', { class: 'check' }, anyTraffic, ' ' + tr('any communication at all, encrypted or not (use it with the targets and allowed senders below)')),
      el('label', { class: 'check' }, controls, ' ' + tr('any control command (stop, start, download, restart, operate)')),
      el('label', { class: 'check' }, writes, ' ' + tr('any write (registers, coils, tags, setpoints)')),
      el('label', {}, tr('or a function whose name contains (comma separated)'), words),
      seen.size ? el('div', { class: 'muted small' }, tr('Seen on your network (click to add):'), seenBox) : null),
    el('div', { class: 'field-wide' }, el('span', { class: 'label', text: tr('Only when the target is (empty: any device)') }), targetsBox),
    el('details', { class: 'field-wide exceptions', open: senders.length > 0 },
      el('summary', { text: senders.length ? tr('Never for these senders ({n})', { n: senders.length }) : tr('Never for these senders') }),
      el('p', { class: 'muted small', text: tr('Optional: excludes senders that would otherwise match, for example your own engineering station.') }),
      sendersBox),
    field(tr('Score of the alert (1–100)'), score),
    field(tr('At most one alert per sender and target in this many minutes'), gap))], {
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
    el('div', { class: 'rule-head' }, el('b', { text: tr('Your network watches') }), el('code', { text: 'it_watch' }), el('span', { class: 'muted small', title: tr('Needs traffic analysis (--flows).') }, ' *')),
    el('p', { class: 'muted', text: tr('Be told when devices you choose talk to addresses or ports you did not allow: cameras reaching the internet, a server using an unusual port, the guest network reaching the office. Needs traffic analysis (--flows). Watches also fire during the learning period.') }),
    state.status && !state.status.flows_enabled ? el('p', { class: 'form-error', text: '⚠ ' + tr('Not currently running: traffic analysis (--flows) is off. Watches are saved but will not fire until it is on.') + ' ' + FLOWS_FIX() }) : null,
    ...rows,
    list.length ? null : el('p', { class: 'muted', text: tr('No watches yet.') }),
    edit ? el('div', { class: 'row watch-add' }, el('button', { type: 'button', class: 'primary', id: 'add-it-watch', text: tr('New Rule'), onclick: () => openItWatchForm(null, (nw) => put([...list, nw])) })) : null);
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
    exceptBox.replaceChildren(exceptionsEditor(except, (l) => { except = l; drawScopes(); }, true));
  };
  drawScopes();
  const flowsWarning = state.status && !state.status.flows_enabled
    ? el('div', { class: 'field-wide form-error', text: '⚠ ' + tr('Traffic analysis (--flows) is not currently running: this watch is saved but will not fire until it is.') + ' ' + FLOWS_FIX() })
    : null;
  openForm(isNew ? tr('Add a network watch') : tr('Edit the network watch'), [el('div', { class: 'form-grid' },
    el('label', { class: 'check field-wide' }, enabled, ' ' + tr('Watch enabled')),
    flowsWarning,
    el('div', { class: 'field-wide' }, field(tr('Name'), nameIn)),
    isNew ? field(tr('Start from a ready-made watch, then adjust it below (optional)'), preset) : null,
    field(tr('Protocol'), proto),
    el('div', { class: 'field-wide' }, el('span', { class: 'label', text: tr('For these devices (empty: any device)') }), sourcesBox),
    el('details', { class: 'field-wide exceptions', open: except.length > 0 },
      el('summary', { text: except.length ? tr('Never for these devices ({n})', { n: except.length }) : tr('Never for these devices') }),
      el('p', { class: 'muted small', text: tr('Optional: excludes devices that would otherwise match.') }),
      exceptBox),
    field(tr('Talking on'), portsMode), field(tr('Ports (comma separated)'), ports),
    field(tr('Talking to'), remotesMode), field(tr('Addresses (comma separated)'), remotes),
    el('div', { class: 'field-wide muted small' }, tr('Use the words public (the internet) and private (the local network), single addresses, or networks like 10.0.5.0/24.'), chips),
    field(tr('Only when at least this many kB moved in 10 seconds (0: any amount)'), minKb),
    field(tr('Score of the alert (1–100)'), score),
    field(tr('At most one alert per device, address and port in this many minutes'), gap))], {
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

// --------------------------------------------------------- Exceptions, accepted risks & baseline (Rules tab)
//
// Rule exceptions (rulesData.exceptions), OT/network watch allow-lists (ot_watches[].allowed_senders,
// it_watches[].except_sources), accepted risks (acceptedRisks, from findings.js) and learned baseline
// destinations (/api/baseline/destinations) each already have their own place to be *created* - this
// only aggregates them into one place to be *seen and removed*, grouped by the device they belong to,
// without changing where any of it is actually stored. Removing a row here calls the exact same
// endpoint removing it from its own place would. Exceptions scoped to a device type, tag or network
// (not one device) cannot be attributed to a device, so they get their own section above the table.

let rulesMode = 'rules';
let rexExpanded = new Set(); // asset ids currently expanded in the "by device" table

function setRulesMode(m) {
  rulesMode = m;
  for (const b of document.querySelectorAll('#rules-mode button')) b.classList.toggle('active', b.dataset.mode === m);
  for (const b of document.querySelectorAll('#rules-subtabs .subtab')) b.classList.toggle('active', b.dataset.rulesMode === m);
  $('rules-mode-rules').hidden = m !== 'rules';
  $('rules-mode-exceptions').hidden = m !== 'exceptions';
  if (m === 'exceptions') loadExceptionsView();
}
for (const b of document.querySelectorAll('#rules-mode button')) b.onclick = () => setRulesMode(b.dataset.mode);
for (const b of document.querySelectorAll('#rules-subtabs .subtab')) {
  b.onclick = () => { location.hash = '#rules/' + b.dataset.rulesMode; setTab('rules'); setRulesMode(b.dataset.rulesMode); };
}

/** "Exceptions & baseline" from a device's own panel: jump to the Rules page's Exceptions tab,
 * pre-filtered to and expanded on just this device (see `exceptionRow`'s `text` and the
 * server-side search behind `loadExceptionsView`, both of which already match on a device's own
 * name). */
function focusDeviceInExceptions(a) {
  $('detail').hidden = true;
  state.selected = null;
  setTab('rules');
  $('rex-search').value = deviceLabel(a, '#' + a.id);
  rexExpanded.add(a.id);
  setRulesMode('exceptions');
}

/** One row: a label, a detail line, and a remove button that does whatever removing this
 * particular kind of thing actually takes (a per-rule exceptions patch, a whole-watch-array PUT,
 * or a risk-acceptance DELETE) - the three real shapes behind one uniform list. Returns
 * `{node, text}` rather than just the node, so `loadExceptionsView` can filter by the search box
 * without a server round trip - each device's own exceptions/risks are few enough that this never
 * needs paging the way the (much larger) baseline-destinations list does. */
function exceptionRow(label, detail, onRemove) {
  const node = el('div', { class: 'exception-row' },
    can('admin') ? el('button', { type: 'button', class: 'exception-remove', title: tr('Remove'), text: '×', onclick: onRemove }) : null,
    el('div', { class: 'exception-row-body' }, el('div', {}, el('b', { text: label })), detail ? el('div', { class: 'muted small', text: detail }) : null));
  return { node, text: (label + ' ' + (detail || '')).toLowerCase() };
}

/** Same shape as exceptionRow, as a table row instead of a div - for the "Network-wide exceptions"
 * table, styled to match the "By device" table right below it rather than the (visually
 * different) exception-row list used inside each device's own expanded detail. */
function networkRow(label, detail, onRemove) {
  const node = el('tr', {},
    el('td', {}, can('admin') ? el('button', { type: 'button', class: 'exception-remove', title: tr('Remove'), text: '×', onclick: onRemove }) : null),
    el('td', {}, el('b', { text: label })),
    el('td', { class: 'muted small', text: detail || '' }));
  return { node, text: (label + ' ' + (detail || '')).toLowerCase() };
}

/** One learned baseline destination, as a removable row - shared between the per-device Asset
 * panel and this page. */
function baselineDestRow(assetId, d) {
  const trailing = el('span', { class: 'muted small' },
    tr('last {t}', { t: ago(d.last_seen) }) + ' · ' + mb(d.bytes),
    can('admin') ? el('button', {
      type: 'button', class: 'exception-remove', title: tr('Remove from baseline'), text: '×',
      onclick: async () => {
        if (!confirm(tr('Remove {ip} from this device\'s learned baseline? The next time it talks to that address, it is evaluated as new again.', { ip: d.ip }))) return;
        const del = await api('DELETE', '/api/assets/' + assetId + '/baseline/destinations/' + encodeURIComponent(d.ip));
        if (!del.ok) { showMessage(tr('Error'), el('p', { text: apiError(del) })); return; }
        loadExceptionsView();
      },
    }) : null);
  return el('div', { class: 'ip-context-row' }, ipInlineLazy(d.ip, trailing));
}

let rexSearchTimer = null;
$('rex-search').oninput = () => { clearTimeout(rexSearchTimer); rexSearchTimer = setTimeout(loadExceptionsView, 300); };

/** Draws the whole "Exceptions, accepted risks & baseline" tab: a network-wide exceptions list,
 * and a device table where each row expands into that device's own exceptions, accepted risks
 * and learned baseline destinations together. */
async function loadExceptionsView() {
  if (!rulesData) { const r = await api('GET', '/api/rules'); if (r.ok) rulesData = r.json; }
  if (!rulesData) return;
  const q = $('rex-search').value.trim().toLowerCase();

  const byDevice = new Map(); // asset id -> exceptionRow[]
  const network = []; // exceptionRow[], not attributable to one device
  const bucket = (id) => { if (!byDevice.has(id)) byDevice.set(id, []); return byDevice.get(id); };

  for (const [ruleId, scopes] of Object.entries(rulesData.exceptions || {})) {
    const rule = (rulesData.rules || []).find((r) => r.id === ruleId);
    scopes.forEach((s, i) => {
      const onRemove = async () => {
        if (!confirm(tr('Remove this exception from {rule}?', { rule: rule ? rule.title : ruleId }))) return;
        const list = scopes.filter((_, j) => j !== i);
        const r = await api('PUT', '/api/rules', { exceptions: { [ruleId]: list.length ? list : null } });
        if (!r.ok) return showMessage(tr('Error'), el('p', { text: apiError(r) }));
        rulesData = null;
        loadExceptionsView();
      };
      const detail = tr('Exception on rule: {rule}', { rule: rule ? rule.title : ruleId });
      if (s.kind === 'device') bucket(Number(s.value)).push(exceptionRow(scopeText(s), detail, onRemove));
      else network.push(networkRow(scopeText(s), detail, onRemove));
    });
  }

  for (const [group, field, kindLabel] of [['ot_watches', 'allowed_senders', tr('OT watch allow-list')], ['it_watches', 'except_sources', tr('Network watch exception')]]) {
    for (const w of rulesData[group] || []) {
      (w[field] || []).forEach((s, i) => {
        const onRemove = async () => {
          if (!confirm(tr('Remove this from the watch "{name}"?', { name: w.name }))) return;
          const updated = { ...w, [field]: w[field].filter((_, j) => j !== i) };
          const list = (rulesData[group] || []).map((x) => (x.id === w.id ? updated : x));
          const r = await api('PUT', '/api/rules', { [group]: list });
          if (!r.ok) return showMessage(tr('Error'), el('p', { text: apiError(r) }));
          rulesData = null;
          loadExceptionsView();
        };
        const detail = tr('{kind}: {name}', { kind: kindLabel, name: w.name });
        if (s.kind === 'device') bucket(Number(s.value)).push(exceptionRow(scopeText(s), detail, onRemove));
        else network.push(networkRow(scopeText(s), detail, onRemove));
      });
    }
  }

  // fetched fresh rather than read from the `acceptedRisks` global (findings.js): that global is
  // only populated once the Findings tab has been visited, so relying on it here would silently
  // drop accepted risks - and the devices only present because of one - until someone opened
  // Findings first.
  const rr = await api('GET', '/api/risk-acceptances');
  for (const a of (rr.ok ? rr.json : [])) {
    const row = exceptionRow(tr(a.title), tr('Accepted risk: {reason}', { reason: a.reason }), async () => {
      if (!confirm(tr('Withdraw the accepted risk "{title}"? It will count as a finding again.', { title: tr(a.title) }))) return;
      const r = await api('DELETE', '/api/risk-acceptances/' + a.id);
      if (!r.ok) return showMessage(tr('Error'), el('p', { text: apiError(r) }));
      if (typeof loadFindings === 'function') loadFindings();
      loadExceptionsView();
    });
    bucket(a.asset_id).push(row);
  }

  const shownNetwork = q ? network.filter((r) => r.text.includes(q)) : network;
  $('rex-network-table').tBodies[0].replaceChildren(...shownNetwork.map((r) => r.node));
  $('rex-network-empty').hidden = shownNetwork.length > 0;
  $('rex-network-empty').textContent = network.length ? tr('No matches.') : tr('None.');

  // baseline destinations: searched server-side (matches a device's name/MAC/IP or the
  // destination IP itself), so a device whose name matches already gets all its destinations back
  // - keeping the same "device matches -> show everything" rule used below for exceptions/risks.
  const br = await api('GET', '/api/baseline/destinations?q=' + encodeURIComponent(q) + '&limit=2000');
  const baselineByDevice = new Map();
  if (br.ok) {
    for (const d of br.json.destinations) {
      if (!baselineByDevice.has(d.asset_id)) baselineByDevice.set(d.asset_id, []);
      baselineByDevice.get(d.asset_id).push(d);
    }
    const { destinations, matched, limit } = br.json;
    $('rex-status').textContent = !q
      ? tr('{n} devices with a learned baseline shown below (search to find a specific device or address).', { n: baselineByDevice.size })
      : matched > limit
        ? tr('Showing {shown} of {matched} baseline matches — refine your search to narrow it further.', { shown: destinations.length, matched })
        : tr('{n} baseline match(es).', { n: matched });
  } else {
    $('rex-status').textContent = apiError(br);
  }

  const ids = new Set([...byDevice.keys(), ...baselineByDevice.keys()]);
  const results = [];
  for (const id of ids) {
    const a = assetById(id);
    const deviceHay = (a ? name(a) + ' ' + a.mac + ' ' + (a.ip || '') : '#' + id).toLowerCase();
    const deviceMatches = !q || deviceHay.includes(q);
    const excRows = byDevice.get(id) || [];
    const shownExc = deviceMatches ? excRows : excRows.filter((r) => r.text.includes(q));
    const baseRows = baselineByDevice.get(id) || [];
    if (!shownExc.length && !baseRows.length) continue;
    results.push({ id, asset: a, excRows: shownExc, baseRows });
  }
  results.sort((x, y) => (x.asset ? name(x.asset) || x.asset.ip || x.asset.mac : '#' + x.id).localeCompare(y.asset ? name(y.asset) || y.asset.ip || y.asset.mac : '#' + y.id));

  const rows = [];
  for (const { id, asset: a, excRows, baseRows } of results) {
    const open = rexExpanded.has(id);
    const toggle = () => { if (rexExpanded.has(id)) rexExpanded.delete(id); else rexExpanded.add(id); loadExceptionsView(); };
    const nameCell = a
      ? el('button', { type: 'button', class: 'namecell link-cell', title: tr('Open device panel'), onclick: (ev) => { ev.stopPropagation(); showDetail(id); } }, iconBadge(a), el('span', { text: name(a) }))
      : el('span', { text: tr('device #{id} (no longer known)', { id }) });
    rows.push(el('tr', { class: 'rex-row', onclick: toggle },
      el('td', { text: open ? '▾' : '▸' }),
      el('td', {}, nameCell),
      el('td', { class: 'mono', text: a ? (a.ip || '—') : '—' }),
      el('td', { class: 'mono', text: a ? a.mac : '' }),
      el('td', {}, a ? el('span', { class: 'tag', text: tr(a.device_type) }) : null),
      el('td', { text: tr('{n} item(s)', { n: excRows.length + baseRows.length }) })));
    if (open) {
      rows.push(el('tr', { class: 'rex-detail' }, el('td', { colSpan: 6 },
        excRows.length ? el('div', { class: 'exception-rows' }, ...excRows.map((r) => r.node)) : null,
        baseRows.length ? el('div', {}, el('div', { class: 'group-title', text: tr('Learned baseline destinations') }), ...baseRows.map((d) => baselineDestRow(id, d))) : null)));
    }
  }
  $('rex-table').tBodies[0].replaceChildren(...rows);
  $('rex-empty').hidden = results.length > 0;
  $('rex-bulk-actions').hidden = results.length < 2;
  $('rex-expand-all').onclick = () => { for (const { id } of results) rexExpanded.add(id); loadExceptionsView(); };
  $('rex-collapse-all').onclick = () => { for (const { id } of results) rexExpanded.delete(id); loadExceptionsView(); };
}
