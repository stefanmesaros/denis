'use strict';
// The setup guide: a checklist of what a new installation usually needs, each item green when it is really done
// (the server judges that). It opens by itself for an administrator until somebody marks it done, and can be
// opened again from Settings. Loaded after tables.js.

const SETUP_LATER = 'denis.setup.later';

/** What each step says, and where its button goes. `v` are the numbers the server sent. */
const SETUP_STEPS = () => ({
  network: {
    title: tr('Your network'), target: '#health', button: tr('Open Health'),
    text: (s) => (s.done
      ? tr('DENIS is watching {interface} ({subnet}) and knows {devices} devices. New devices and destinations are learned for a while (see the banner at the top); after that, anything unusual raises an alert.', s.vars)
      : tr('DENIS has not seen devices yet, or is not capturing. Look at the Health page, and press Scan now (top right) to look around at once.')),
  },
  security: {
    title: tr('Sign-in security'), target: '#account', button: tr('My account'),
    text: (s) => (s.done ? tr('Every administrator signs in with a passkey.') : tr('{a} of {b} administrators use a passkey. Add one in My account to sign in with a fingerprint, face or security key instead of a password.', s.vars)),
  },
  alerts: {
    title: tr('Be told about alerts'), target: '#alerting', button: tr('Open Alerting'),
    text: (s) => (s.done ? tr('{channels} notification channel(s) and {exports} export(s) are set up.', s.vars) : tr('Alerts are only visible in this console. Add Slack, Teams, e-mail or PagerDuty so that somebody is told.')),
  },
  people: {
    title: tr('Your colleagues'), target: '#users', button: tr('Open Users'),
    text: (s) => (s.done ? tr('{users} people can sign in.', s.vars) : tr('Only you can sign in. Add colleagues as viewers (read only), editors or administrators.')),
  },
  backups: {
    title: tr('Backups and reports'), target: '#health', button: tr('Open Health'),
    text: (s) => (s.done
      ? tr('Backup schedule: {schedule}. Scheduled reports: {reports}. Backups kept: {backups}.', { ...s.vars, schedule: Object.fromEntries(BACKUP_SCHEDULE())[s.vars.schedule] || s.vars.schedule, reports: Object.fromEntries(SCHEDULE_TEXT())[s.vars.reports] || s.vars.reports })
      : tr('There is no backup yet. Switch the backup schedule on, or make one now. Saved reports for an auditor are under Reports.')),
  },
  branding: {
    title: tr('Make it yours'), target: '#settings/branding', button: tr('Open Branding'),
    text: (s) => (s.done ? tr('Your name, colour or logo is set.') : tr('Optional: your product name, colour and logo (white label) for the console, the sign-in page and reports.')),
  },
});

async function openSetupGuide() {
  const r = await fetch('/api/setup');
  if (!r.ok) return;
  const data = await r.json();
  const words = SETUP_STEPS();
  const left = data.steps.filter((s) => !s.done).length;
  const cards = data.steps.map((s) => {
    const w = words[s.id];
    return el('div', { class: 'setup-step' + (s.done ? ' done' : ''), 'data-step': s.id },
      el('span', { class: 'setup-mark', 'aria-hidden': 'true', text: s.done ? '✓' : '○' }),
      el('div', { class: 'setup-body' },
        el('b', { text: w.title }),
        el('div', { class: 'muted', text: w.text(s) }),
        el('button', { type: 'button', text: w.button, onclick: () => { $('msg-dialog').close(); location.hash = w.target; } })));
  });
  const later = () => { try { sessionStorage.setItem(SETUP_LATER, '1'); } catch { /* the guide just reopens next time */ } $('msg-dialog').close(); };
  const done = async () => {
    const p = await api('PUT', '/api/setup', { completed: true });
    if (!p.ok) { showMessage(tr('Setup guide'), el('p', { class: 'form-error', text: apiError(p) })); return; }
    $('msg-dialog').close();
  };
  showMessage(tr('Setup guide'),
    el('p', { class: 'muted', text: tr('Welcome to DENIS. This checklist shows what a new installation usually needs. Each item turns green when it is really done, and you can open this guide again from Settings.') }),
    el('p', { text: left ? tr('{n} of {total} still to do.', { n: left, total: data.steps.length }) : tr('Everything is done.') }),
    ...cards,
    el('div', { class: 'row setup-actions' },
      data.completed ? null : el('button', { type: 'button', class: 'primary', id: 'setup-done', text: tr('Mark as done'), onclick: done }),
      data.completed ? null : el('button', { type: 'button', id: 'setup-later', text: tr('Remind me later'), onclick: later })));
}

/** After sign-in: open the guide by itself for an administrator who has not finished with it. */
async function maybeShowSetupGuide() {
  if (!can('admin') || !state.status || state.status.mode === 'viewer') return;
  if ($('form-dialog').open || $('msg-dialog').open) return; // a forced password change comes first
  try { if (sessionStorage.getItem(SETUP_LATER)) return; } catch { /* no storage: ask */ }
  const r = await fetch('/api/setup');
  if (!r.ok) return;
  if (!(await r.json()).completed) openSetupGuide();
}
