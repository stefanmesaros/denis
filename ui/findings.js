'use strict';
// The Findings page: standing problems, with two actions per finding: "Verify fix" (look again, with a fresh scan
// where that is what proves it) and "Accept risk" (a person decides to live with it, with a reason and usually an
// end date), plus the list of accepted risks below. Loaded after rules.js.

let acceptedRisks = [];

/** When an accepted risk ends, in words: "in 78 days", "today", "until withdrawn". */
function untilText(a) {
  if (!a.expires_at) return tr('until withdrawn');
  const days = Math.ceil((a.expires_at - now()) / 86400);
  const date = new Date(a.expires_at * 1000).toLocaleDateString(locale());
  return days <= 0 ? date : tr('{date} (in {n} days)', { date, n: days });
}

async function loadFindings() {
  const [r, ar] = await Promise.all([apiFetch('/api/findings'), apiFetch('/api/risk-acceptances')]);
  if (!r.ok) return;
  const list = await r.json();
  acceptedRisks = ar.ok ? await ar.json() : [];
  const n = list.filter((f) => f.severity !== 'info').length;
  $('count-findings').hidden = !n;
  $('count-findings').textContent = n;
  if (state.tab !== 'findings') return; // the badge is kept fresh; the list is drawn only when shown
  const box = $('findings-list');
  $('no-findings').hidden = list.length > 0;
  const admin = can('admin');
  const editor = can('editor');
  box.replaceChildren(...list.map((f) => el('div', { class: 'finding', id: 'finding-' + f.id },
    el('div', { class: 'finding-head' }, el('span', { class: 'sev ' + (f.severity === 'info' ? 'info' : f.severity), text: tr(f.severity) }),
      el('b', { text: ' ' + tr(f.title) }), el('span', { class: 'muted', text: ' · ' + (f.assets.length === 1 ? tr('1 device') : tr('{n} devices', { n: f.assets.length })) }),
      el('span', { class: 'muted small', title: tr('When DENIS first saw this kind of finding'), text: ' · ' + tr('since {date}', { date: fmtExact(f.first_seen) }) })),
    el('p', { class: 'muted', text: tr(f.why) }),
    el('p', {}, el('b', { text: tr('What to do:') + ' ' }), tr(f.fix)),
    aiExplainButton('finding', f.id),
    (f.evidence || []).length ? el('ul', { class: 'evidence' }, ...f.evidence.map((e) => el('li', {}, el('b', { text: deviceLabel(assetById(e.asset_id) || {}, '#' + e.asset_id) + ': ' }), evidenceText(e)))) : null,
    el('div', { class: 'finding-devices' }, ...f.assets.map((id) => {
      const a = assetById(id);
      return el('button', { type: 'button', class: 'chip', text: a ? deviceLabel(a, '#' + id) : '#' + id, onclick: () => a && showDetail(a.id) });
    })),
    (editor || admin) ? el('div', { class: 'finding-actions' },
      editor ? el('button', { type: 'button', class: 'verify-fix', text: tr('Verify fix'), title: tr('Look again: scan these devices now and see whether the problem is gone'), onclick: (ev) => verifyFinding(f, f.assets, ev.target) }) : null,
      admin ? el('button', { type: 'button', class: 'accept-risk', text: tr('Accept risk…'), title: tr('Decide to live with this, with a reason and an end date'), onclick: () => openAcceptForm(f) }) : null) : null)));
  drawAcceptedRisks();
}

/** One sentence about software a device announced: what was read, and what that means. */
function evidenceText(e) {
  const v = { product: e.product, version: e.version, cycle: e.cycle, date: e.date, n: e.days_left, cve: e.cve, name: e.name, vendor: e.vendor, id: e.advisory_id };
  const parts = [];
  if (e.kind === 'eol') parts.push(e.date ? tr('{product} {version}: support for the {cycle} series ended on {date}.', v) : tr('{product} {version}: support for the {cycle} series has ended.', v));
  else if (e.kind === 'eol_soon') parts.push(tr('{product} {version}: support for the {cycle} series ends on {date} (in {n} days).', v));
  else if (e.kind === 'ics') parts.push(tr('{vendor} has an open ICS-CERT advisory, {id} ({name}), published {date}.', v));
  else parts.push(tr('{product} {version} is in the range affected by {cve} ({name}), which attackers are exploiting.', v));
  if (e.backport) parts.push(e.kind === 'kev' ? tr('The banner names a distribution, which may have fixed this without changing the version number: check.') : tr('A distribution may still patch it: check with yours.'));
  if (e.ransomware) parts.push(tr('Used in ransomware campaigns.'));
  if (e.kind === 'kev' && typeof e.epss === 'number') parts.push(tr('EPSS: {pct}% modelled probability of exploitation in the next 30 days.', { pct: Math.round(e.epss * 100) }));
  return parts.join(' ');
}

const STATUS_TEXT = () => ({
  fixed: [tr('Fixed'), 'ok'], still_present: [tr('Still present'), 'bad'], unreachable: [tr('Did not answer'), 'warn'],
  excluded: [tr('Excluded from scans'), 'warn'], not_probed: [tr('Not scanned'), 'warn'],
});

/** Ask the server to look again and show, device by device, what it found. */
async function verifyFinding(f, ids, button) {
  const label = button ? button.textContent : '';
  if (button) { button.disabled = true; button.textContent = tr('Checking…'); }
  const r = await api('POST', '/api/findings/' + encodeURIComponent(f.finding_id || f.id) + '/verify', { asset_ids: ids });
  if (button) { button.disabled = false; button.textContent = label; }
  if (!r.ok) { showMessage(tr('Verify fix'), el('p', { class: 'form-error', text: apiError(r) })); return; }
  const v = r.json;
  const words = STATUS_TEXT();
  const rows = v.results.map((x) => {
    const a = assetById(x.asset_id);
    const [text, cls] = words[x.status] || [x.status, ''];
    return el('div', { class: 'verify-row' }, el('span', { class: 'pill ' + cls, text }), ' ', el('b', { text: a ? deviceLabel(a, '#' + x.asset_id) : '#' + x.asset_id }), el('div', { class: 'muted small', text: translateError(x.detail) }));
  });
  const head = v.still_present === 0 && v.fixed > 0
    ? tr('Fixed: {n} of {total} devices no longer show it.', { n: v.fixed, total: v.results.length })
    : v.results.length === 0 ? tr('Nothing left to check: this finding no longer applies to any device.')
    : tr('{fixed} fixed, {still} still present.', { fixed: v.fixed, still: v.still_present });
  showMessage(tr('Verify fix') + ': ' + tr(f.title), el('p', {}, el('b', { text: head })),
    v.rescanned ? el('p', { class: 'muted small', text: tr('The devices were scanned again just now.') }) : null, ...rows);
  loadFindings();
  refresh();
}

/** "Accept risk": choose the devices, say why, say for how long. */
function openAcceptForm(f) {
  const checks = f.assets.map((id) => {
    const a = assetById(id);
    const box = el('input', { type: 'checkbox', checked: true, value: String(id) });
    return { id, box, node: el('label', { class: 'check' }, box, ' ' + (a ? deviceLabel(a, '#' + id) : '#' + id)) };
  });
  const reason = el('textarea', { rows: 3, maxLength: 500, required: true, placeholder: tr('Why is this acceptable? e.g. isolated VLAN, replaced in Q4, compensating control…') });
  const days = el('select', {}, ...[[30, tr('30 days')], [90, tr('90 days')], [180, tr('180 days')], [365, tr('1 year')], [0, tr('until I withdraw it')]].map(([v, t]) => el('option', { value: String(v), text: t })));
  days.value = '90';
  openForm(tr('Accept the risk: {title}', { title: tr(f.title) }), [
    el('p', { class: 'muted', text: tr('The finding disappears from the list below for the devices you choose, and shows up under Accepted risks with your name and reason. It comes back by itself when the time is up, or when you withdraw the decision.') }),
    el('div', { class: 'form-grid' },
      el('div', { class: 'field-wide' }, el('span', { class: 'label', text: tr('Devices') }), ...checks.map((c) => c.node)),
      el('div', { class: 'field-wide' }, field(tr('Reason (kept in the audit log and the report)'), reason)),
      el('div', { class: 'field-wide' }, field(tr('Accepted for'), days))),
  ], {
    submitLabel: tr('Accept risk'),
    onSubmit: async () => {
      const chosen = checks.filter((c) => c.box.checked).map((c) => c.id);
      if (!chosen.length) return tr('Choose at least one device.');
      if (reason.value.trim().length < 3) return tr('Give a reason: it is what an auditor will read.');
      const r = await api('POST', '/api/risk-acceptances', { finding_id: f.id, asset_ids: chosen, reason: reason.value.trim(), days: Number(days.value) || null });
      if (!r.ok) return apiError(r);
      await loadFindings();
      return null;
    },
  });
}

/** The accepted risks under the findings. */
function drawAcceptedRisks() {
  const admin = can('admin');
  const rows = acceptedRisks;
  $('accepted-box').hidden = rows.length === 0;
  $('accepted-table').tBodies[0].replaceChildren(...rows.map((a) => {
    const dev = assetById(a.asset_id);
    const soon = a.expires_at && a.expires_at - now() < 14 * 86400;
    return el('tr', { class: a.still_applies ? '' : 'row-ok' },
      el('td', {}, el('span', { class: 'sev ' + (a.severity === 'info' ? 'info' : a.severity), text: tr(a.severity) }), ' ', el('b', { text: tr(a.title) }),
        a.still_applies ? null : el('div', { class: 'muted small', text: tr('The problem is gone: you can withdraw this decision.') })),
      el('td', {}, dev ? el('button', { type: 'button', class: 'chip', text: deviceLabel(dev, '#' + a.asset_id), onclick: () => showDetail(dev.id) }) : '#' + a.asset_id),
      el('td', { class: 'wrap', text: a.reason }),
      el('td', {}, a.accepted_by, el('div', { class: 'muted small', text: fmtTime(a.accepted_at) })),
      el('td', { class: soon ? 'warn-text' : '', text: untilText(a) }),
      el('td', {},
        can('editor') && a.still_applies ? el('button', { type: 'button', text: tr('Verify'), title: tr('Look again: is it still true?'), onclick: (ev) => verifyFinding({ id: a.finding_id, finding_id: a.finding_id, title: a.title }, [a.asset_id], ev.target) }) : null,
        admin ? el('button', { type: 'button', text: tr('Withdraw'), title: tr('Stop accepting this risk: the finding counts again'), onclick: async () => {
          if (!confirm(tr('Withdraw the accepted risk "{title}" for {device}? It will count as a finding again.', { title: tr(a.title), device: dev ? deviceLabel(dev, '#' + a.asset_id) : '#' + a.asset_id }))) return;
          const r = await api('DELETE', '/api/risk-acceptances/' + a.id);
          if (!r.ok) showMessage(tr('Could not withdraw'), el('p', { text: apiError(r) }));
          loadFindings();
        } }) : null));
  }));
}
