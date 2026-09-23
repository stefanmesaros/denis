'use strict';
// The Health page: is DENIS itself in good shape (packet drops, database, disk, sweeps), and the backups of its
// database (administrators). Loaded after reports.js.

const BACKUP_SCHEDULE = () => [['off', tr('Never')], ['every8h', tr('Every 8 hours')], ['every12h', tr('Every 12 hours')], ['daily', tr('Every day')], ['weekly', tr('Every week')]];
const UPLOAD_SCHEDULE = () => [['manual', tr('Manually only')], ['every8h', tr('Every 8 hours')], ['every12h', tr('Every 12 hours')], ['daily', tr('Every day')], ['weekly', tr('Every week')]];
const BACKUP_KIND = () => ({ auto: tr('On schedule'), manual: tr('By hand'), update: tr('Before an update') });

/** The number of problems, in the menu (light request: no table counts). */
async function loadHealthBadge() {
  if (!state.me) return;
  const r = await apiFetch('/api/system?rows=0');
  if (!r.ok) return;
  const n = (await r.json()).warnings.length;
  $('count-health').hidden = !n;
  $('count-health').textContent = n;
}

async function loadHealth() {
  const r = await apiFetch('/api/system');
  if (!r.ok) return;
  const h = await r.json();
  $('count-health').hidden = !h.warnings.length;
  $('count-health').textContent = h.warnings.length;
  $('health-warnings').replaceChildren(...(h.warnings.length
    ? h.warnings.map((w) => el('div', { class: 'banner-warn', text: tr(w.text, w.vars) }))
    : [el('p', { class: 'ok-text', text: tr('Everything looks fine.') })]));
  const card = (title, big, small) => el('div', { class: 'measure' }, el('div', {}, el('b', { text: big }), ' ' + title), el('div', { class: 'muted small', text: small || '' }));
  const cards = [
    card(tr('Version'), h.version, tr('running for {span}', { span: span(h.uptime_secs) })),
    card(tr('Database'), fmtBytes(h.db.db_bytes), tr('{size} of it is free space', { size: fmtBytes(h.db.free_bytes) })),
  ];
  if (h.disk) cards.push(card(tr('Free disk'), fmtBytes(h.disk[0]), tr('of {size}', { size: fmtBytes(h.disk[1]) })));
  if (h.capture) {
    cards.push(card(tr('Packets dropped'), h.capture.drop_percent.toFixed(1) + '%',
      h.capture.running ? tr('{dropped} of {total} packets', { dropped: h.capture.dropped, total: h.capture.received + h.capture.dropped }) : tr('the capture is not running')));
  }
  if (h.sweep) {
    cards.push(card(tr('Last sweep'), h.sweep.last_finished ? ago(h.sweep.last_finished) : '—',
      h.sweep.sweeping ? tr('a sweep is running now') : tr('one is due every {span}', { span: span(h.sweep.interval_secs) })));
  }
  cards.push(card(tr('Backups'), String(h.backups.count), h.backups.latest_at ? tr('newest {ago}', { ago: ago(h.backups.latest_at) }) : tr('none yet')));
  $('health-cards').replaceChildren(...cards);
  $('health-rows').hidden = !h.db.rows.length;
  $('health-rows-table').tBodies[0].replaceChildren(...h.db.rows.map(([name, n]) => el('tr', {}, el('td', { text: name }), el('td', { class: 'num', text: n.toLocaleString(locale()) }))));
  $('backups-box').hidden = !can('admin');
  if (can('admin')) { loadBackups(); loadMspBackups(); }
}

/** Every customer's uploaded backups (--backup-upstream on their side), so an MSP can find and
 * download one without SSH access to this server. */
async function loadMspBackups() {
  const r = await api('GET', '/api/msp-backups');
  if (!r.ok) return;
  const sites = r.json;
  $('no-msp-backups').hidden = sites.length > 0;
  $('msp-backups-list').replaceChildren(...sites.map((site) => {
    const rows = site.backups.map((b) => el('tr', {},
      el('td', { text: fmtTime(b.modified) }),
      el('td', { text: fmtBytes(b.size) }),
      el('td', { class: 'row-actions' },
        el('a', { class: 'button', href: '/api/msp-backups/' + encodeURIComponent(site.agent_id) + '/' + encodeURIComponent(b.name), text: tr('Download') }),
        el('button', { type: 'button', text: tr('Delete'), onclick: async () => {
          if (!confirm(tr('Delete the backup from {date}? It cannot be recovered.', { date: fmtTime(b.modified) }))) return;
          const d = await api('DELETE', '/api/msp-backups/' + encodeURIComponent(site.agent_id) + '/' + encodeURIComponent(b.name));
          if (!d.ok) showMessage(tr('Could not delete'), el('p', { text: apiError(d) }));
          loadMspBackups();
        } }))));
    return el('div', { class: 'msp-backup-site' },
      el('h4', { text: site.name }),
      el('div', { class: 'table-wrap' }, el('table', {}, el('tbody', {}, ...rows))));
  }));
}

async function loadBackups() {
  const r = await apiFetch('/api/backups');
  if (!r.ok) return;
  const data = await r.json();
  const kinds = BACKUP_KIND();
  $('no-backups').hidden = data.backups.length > 0;
  $('backups-table').hidden = data.backups.length === 0;
  $('backups-table').tBodies[0].replaceChildren(...data.backups.map((b) => el('tr', {},
    el('td', { text: fmtTime(b.modified) }),
    el('td', { text: kinds[b.kind] || b.kind }),
    el('td', { text: fmtBytes(b.size) }),
    el('td', { class: 'row-actions' },
      el('a', { class: 'button', href: '/api/backups/' + encodeURIComponent(b.name), text: tr('Download') }),
      b.kind === 'update' ? null : el('button', { type: 'button', text: tr('Delete'), onclick: async () => {
        if (!confirm(tr('Delete the backup from {date}? It cannot be recovered.', { date: fmtTime(b.modified) }))) return;
        const d = await api('DELETE', '/api/backups/' + encodeURIComponent(b.name));
        if (!d.ok) showMessage(tr('Could not delete'), el('p', { text: apiError(d) }));
        loadHealth();
      } })))));
  const s = data.settings;
  const sched = el('select', { id: 'backup-schedule' }, ...BACKUP_SCHEDULE().map(([v, t]) => el('option', { value: v, text: t })));
  const keep = el('input', { id: 'backup-keep', type: 'number', min: 1, max: 60, value: String(s.keep) });
  sched.value = s.schedule;
  const status = el('span', { class: 'muted', id: 'backup-status' });
  $('backup-schedule-form').replaceChildren(
    el('div', { class: 'form-grid' }, field(tr('Back up the database automatically'), sched), field(tr('Keep the newest'), keep)),
    el('div', { class: 'row' },
      el('button', { type: 'button', class: 'primary', id: 'backup-save', text: tr('Save schedule'), onclick: async () => {
        const r2 = await api('PUT', '/api/backups/settings', { schedule: sched.value, keep: Number(keep.value) });
        status.textContent = r2.ok ? tr('Saved.') : apiError(r2);
        if (r2.ok) loadHealth();
      } }), status));

  $('backup-upload-box').hidden = !data.upload_configured;
  if (data.upload_configured) {
    const us = data.upload_settings;
    const usel = el('select', { id: 'backup-upload-schedule' }, ...UPLOAD_SCHEDULE().map(([v, t]) => el('option', { value: v, text: t })));
    usel.value = us.schedule;
    const ustatus = el('span', { class: 'muted', id: 'backup-upload-status' });
    $('backup-upload-form').replaceChildren(
      el('div', { class: 'form-grid' }, field(tr('Push the newest backup to your MSP'), usel)),
      el('div', { class: 'row' },
        el('button', { type: 'button', class: 'primary', text: tr('Save schedule'), onclick: async () => {
          const r2 = await api('PUT', '/api/backups/upload-schedule', { schedule: usel.value });
          ustatus.textContent = r2.ok ? tr('Saved.') : apiError(r2);
        } }), ustatus));
  }

  const agentKeep = el('input', { id: 'backup-agent-keep', type: 'number', min: 1, max: 60, value: String(data.agent_keep) });
  const akStatus = el('span', { class: 'muted', id: 'backup-agent-keep-status' });
  $('backup-agent-keep-form').replaceChildren(
    el('div', { class: 'form-grid' }, field(tr('Keep the newest'), agentKeep)),
    el('div', { class: 'row' },
      el('button', { type: 'button', class: 'primary', text: tr('Save'), onclick: async () => {
        const r2 = await api('PUT', '/api/backups/agent-keep', { keep: Number(agentKeep.value) });
        akStatus.textContent = r2.ok ? tr('Saved.') : apiError(r2);
      } }), akStatus));
}

async function backupNow() {
  const b = $('backup-now');
  b.disabled = true;
  const label = b.textContent;
  b.textContent = tr('Backing up…');
  const r = await api('POST', '/api/backups');
  b.disabled = false;
  b.textContent = label;
  if (!r.ok) showMessage(tr('Backups'), el('p', { class: 'form-error', text: apiError(r) }));
  loadHealth();
}

function initHealth() {
  $('backup-now').onclick = backupNow;
}
