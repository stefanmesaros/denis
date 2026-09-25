'use strict';
// The Reports page: saved snapshots of the network (made by hand or on a schedule) that can be opened,
// downloaded or printed, and the schedule that makes them. Loaded after findings.js.

const SCHEDULE_TEXT = () => [['off', tr('Never')], ['weekly', tr('Every week')], ['monthly', tr('Every month')]];
const PERIOD_TEXT = () => [[7, tr('7 days')], [30, tr('30 days')], [90, tr('90 days')], [180, tr('180 days')], [365, tr('1 year')]];

async function loadReports() {
  const r = await apiFetch('/api/reports');
  if (!r.ok) return;
  const data = await r.json();
  const rows = data.reports;
  $('no-reports').hidden = rows.length > 0;
  $('reports-table').hidden = rows.length === 0;
  $('reports-total').textContent = rows.length === 1 ? tr('1 report, {size}.', { size: fmtBytes(data.total_bytes) }) : rows.length ? tr('{n} reports, {size} in total.', { n: rows.length, size: fmtBytes(data.total_bytes) }) : '';
  const admin = can('admin');
  $('reports-table').tBodies[0].replaceChildren(...rows.map((x) => el('tr', {},
    el('td', { text: fmtTime(x.created_at) }),
    el('td', {}, el('b', { text: x.kind === 'scheduled' ? tr('On schedule') : tr('By hand') }), el('div', { class: 'muted small', text: x.created_by === 'schedule' ? '' : x.created_by })),
    el('td', { text: x.period_days === 1 ? tr('1 day') : tr('{n} days', { n: x.period_days }) }),
    el('td', { text: fmtBytes(x.size) }),
    el('td', {}, x.share_token
      ? el('span', { class: 'tag', title: tr('Anyone with the link can view this report, without signing in') }, tr('Shared'))
      : null),
    el('td', { class: 'row-actions' },
      el('a', { class: 'button', href: '/api/reports/' + x.id, target: '_blank', rel: 'noopener', text: tr('Open') }),
      el('a', { class: 'button', href: '/api/reports/' + x.id + '?download=1', text: tr('Download') }),
      admin ? el('button', { type: 'button', text: x.share_token ? tr('Sharing…') : tr('Share…'), onclick: () => openShareDialog(x) }) : null,
      admin ? el('button', { type: 'button', text: tr('Delete'), onclick: async () => {
        if (!confirm(tr('Delete the report from {date}? It cannot be recovered.', { date: fmtTime(x.created_at) }))) return;
        const d = await api('DELETE', '/api/reports/' + x.id);
        if (!d.ok) showMessage(tr('Could not delete'), el('p', { text: apiError(d) }));
        loadReports();
      } }) : null))));
  drawReportSchedule(data.settings);
}

/** The dialog for one report's "Share…" button: turn sharing on (or show the existing link),
 * copy it, or turn it off. The link works with no sign-in at all, so it is spelled out plainly
 * what that means before showing it. */
function openShareDialog(x) {
  const linkFor = (token) => location.origin + '/api/reports/shared/' + token;
  const draw = (token) => {
    const nodes = [el('p', { class: 'muted', text: tr('Anyone with this link can view this report — the full compliance overview and inventory it was made from — without signing in. Turn it off any time; the link stops working immediately.') })];
    if (token) {
      const link = el('input', { readOnly: true, value: linkFor(token), onclick: (ev) => ev.target.select() });
      nodes.push(
        el('div', { class: 'row' }, link, el('button', { type: 'button', text: tr('Copy'), onclick: async () => { await navigator.clipboard.writeText(linkFor(token)); } })),
        el('div', { class: 'row' }, el('button', { type: 'button', text: tr('Stop sharing'), onclick: async () => {
          const r = await api('DELETE', '/api/reports/' + x.id + '/share');
          if (!r.ok) { showMessage(tr('Could not save'), el('p', { text: apiError(r) })); return; }
          close(); loadReports();
        } })));
    } else {
      nodes.push(el('div', { class: 'row' }, el('button', { type: 'button', class: 'primary', text: tr('Turn on sharing'), onclick: async () => {
        const r = await api('PUT', '/api/reports/' + x.id + '/share', {});
        if (!r.ok) { showMessage(tr('Could not save'), el('p', { text: apiError(r) })); return; }
        openShareDialog({ ...x, share_token: r.json.share_token });
        loadReports();
      } })));
    }
    return nodes;
  };
  const close = () => $('msg-dialog').close();
  showMessage(tr('Share this report'), ...draw(x.share_token));
}

function drawReportSchedule(s) {
  const admin = can('admin');
  const sched = el('select', { id: 'rep-schedule' }, ...SCHEDULE_TEXT().map(([v, t]) => el('option', { value: v, text: t })));
  const days = el('select', { id: 'rep-days' }, ...PERIOD_TEXT().map(([v, t]) => el('option', { value: String(v), text: t })));
  const keep = el('input', { id: 'rep-keep', type: 'number', min: 1, max: 200, value: String(s.keep) });
  const emailTo = el('input', { id: 'rep-email-to', value: (s.email_to || []).join(', '), placeholder: tr('e.g. ops@example.com, ciso@example.com') });
  sched.value = s.schedule;
  days.value = String(s.days);
  for (const c of [sched, days, keep, emailTo]) c.disabled = !admin;
  const status = el('span', { class: 'muted', id: 'rep-status' });
  $('reports-schedule').replaceChildren(
    el('div', { class: 'form-grid' }, field(tr('Make a report automatically'), sched), field(tr('Each one covers'), days), field(tr('Keep the newest'), keep)),
    el('div', { class: 'form-grid' }, field(tr('E-mail a link when it is ready (optional)'), emailTo)),
    el('p', { class: 'muted small', text: tr('Sent through whichever e-mail channel is enabled under Alerting; needs a public URL configured (--public-url) for the link to work. Leave blank to only keep it in the console, as before.') }),
    el('p', { class: 'muted small', text: admin ? tr('Older scheduled reports are removed; reports you made by hand are never removed.') : tr('Only an administrator can change the schedule.') }),
    admin ? el('div', { class: 'row' }, el('button', { type: 'button', class: 'primary', id: 'rep-save', text: tr('Save schedule'), onclick: async () => {
      const email_to = emailTo.value.split(/[,;\s]+/).map((s) => s.trim()).filter(Boolean);
      const r = await api('PUT', '/api/reports/settings', { schedule: sched.value, days: Number(days.value), keep: Number(keep.value), email_to });
      status.textContent = r.ok ? tr('Saved.') : apiError(r);
    } }), status) : null);
}

async function makeReport() {
  const b = $('make-report');
  b.disabled = true;
  const label = b.textContent;
  b.textContent = tr('Making the report…');
  const r = await api('POST', '/api/reports', { days: Number($('report-days').value) });
  b.disabled = false;
  b.textContent = label;
  if (!r.ok) { showMessage(tr('Reports'), el('p', { class: 'form-error', text: apiError(r) })); return; }
  await loadReports();
  window.open('/api/reports/' + r.json.id, '_blank', 'noopener');
}

function initReports() {
  const sel = $('report-days');
  sel.replaceChildren(...PERIOD_TEXT().map(([v, t]) => el('option', { value: String(v), text: t })));
  sel.value = '7';
  $('make-report').onclick = makeReport;
  $('make-report').hidden = sel.hidden = !can('editor');
}
