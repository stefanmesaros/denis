'use strict';
// The second sign-in step: an authenticator app (one-time codes). My account: set it up (QR code and recovery
// codes), turn it off, new recovery codes. The sign-in page's code step. Administrators: who must use one, and
// resetting somebody's after a lost phone. Loaded after setup.js.

let loginTicket = null;

// ------------------------------------------------------------------ the sign-in page

/** Ask for the code that goes with the password just typed. */
function showLoginCodeStep(ticket) {
  loginTicket = ticket;
  for (const id of ['login-user', 'login-pass']) $(id).closest('label').hidden = true;
  $('login-mfa').hidden = false;
  $('login-code').value = '';
  $('login-code').required = true;
  $('login-user').required = $('login-pass').required = false;
  $('login-passkey').hidden = true;
  $('login-code').focus();
}

/** Back to the user name and password (after a mistake, or a sign-out). */
function resetLoginCodeStep() {
  loginTicket = null;
  for (const id of ['login-user', 'login-pass']) $(id).closest('label').hidden = false;
  $('login-mfa').hidden = true;
  $('login-code').required = false;
  $('login-user').required = $('login-pass').required = true;
  $('login-code').value = '';
}

// ------------------------------------------------------------------ my account

/** Recovery codes, shown once, with ways to keep them. */
function showRecoveryCodes(codes) {
  const text = codes.join('\n');
  showMessage(tr('Your recovery codes'),
    el('p', { text: tr('Keep these somewhere safe, apart from your phone. Each one signs you in once if you lose the phone. They are shown only now.') }),
    el('pre', { class: 'recovery-codes', id: 'recovery-codes', text }),
    el('div', { class: 'row' },
      el('button', { type: 'button', text: tr('Copy'), onclick: () => navigator.clipboard && navigator.clipboard.writeText(text) }),
      el('a', { class: 'button', download: 'denis-recovery-codes.txt', href: 'data:text/plain;charset=utf-8,' + encodeURIComponent(text + '\n'), text: tr('Download') })));
}

async function renderTotp(message) {
  const box = $('totp-box');
  const authRequired = !state.status || state.status.auth_required !== false;
  box.hidden = !authRequired;
  if (!authRequired) return;
  const r = await api('GET', '/api/auth/totp');
  if (!r.ok) return;
  const s = r.json;
  const status = el('div', { class: message && message.ok ? 'muted' : 'form-error', text: message ? message.text : '' });
  $('totp-body').replaceChildren(...[
    el('p', { class: 'muted', text: tr('Ask for a 6-digit code from an authenticator app (Google Authenticator, Microsoft Authenticator, Authy, 1Password, Aegis…) as well as your password. Signing in with a passkey already counts as two steps and needs no code.') }),
    s.required ? el('p', { class: 'muted', text: tr('Your administrator requires a second sign-in step.') }) : null,
    s.enabled
      ? el('p', {}, el('b', { class: 'ok-text', text: tr('An authenticator app is set up.') }), ' ' + tr('{n} recovery codes left.', { n: s.recovery_left }))
      : el('p', { text: tr('No authenticator app is set up.') }),
    s.enabled
      ? el('div', { class: 'row' },
        el('button', { type: 'button', id: 'totp-recovery', text: tr('New recovery codes…'), onclick: openRecoveryForm }),
        el('button', { type: 'button', id: 'totp-off', text: tr('Turn off…'), onclick: openTotpOff }))
      : el('div', { class: 'row' }, el('button', { type: 'button', class: 'primary', id: 'totp-setup', text: tr('Set up an authenticator app…'), onclick: () => openTotpSetup() })),
    status].filter(Boolean));
}

/** Step 1: the password again. Step 2: scan the code, type the first one. */
function openTotpSetup(afterDone) {
  const pw = el('input', { type: 'password', autocomplete: 'current-password', required: true });
  openForm(tr('Set up an authenticator app'), [
    el('p', { class: 'muted', text: tr('First, your password once more.') }),
    field(tr('Current password'), pw),
  ], {
    submitLabel: tr('Continue'),
    onSubmit: async () => {
      const r = await api('POST', '/api/auth/totp/begin', { password: pw.value });
      if (!r.ok) return apiError(r);
      setTimeout(() => openTotpConfirm(r.json, afterDone), 50);
      return null;
    },
  });
}

function openTotpConfirm(begun, afterDone) {
  const code = el('input', { inputMode: 'numeric', autocomplete: 'one-time-code', maxLength: 8, required: true, placeholder: '123456', id: 'totp-code' });
  const secret = el('code', { class: 'secret', id: 'totp-secret', text: begun.secret.replace(/(.{4})/g, '$1 ').trim() });
  openForm(tr('Set up an authenticator app'), [
    el('ol', {},
      el('li', { text: tr('Open your authenticator app and add an account by scanning this code.') }),
      el('li', { text: tr('Then type the 6-digit code the app shows.') })),
    el('div', { class: 'qr-box' }, el('img', { id: 'totp-qr', class: 'qr', alt: tr('QR code for your authenticator app'), src: '/api/auth/totp/qr.svg?t=' + Date.now(), width: 200, height: 200 })),
    el('p', { class: 'muted small' }, tr('Cannot scan? Type this key into the app instead:') + ' ', secret),
    field(tr('Code from the app'), code),
  ], {
    submitLabel: tr('Turn on'),
    onSubmit: async () => {
      const r = await api('POST', '/api/auth/totp/confirm', { code: code.value });
      if (!r.ok) return apiError(r);
      setTimeout(() => { showRecoveryCodes(r.json.recovery_codes); $('msg-dialog').addEventListener('close', () => (afterDone ? afterDone() : renderTotp({ ok: true, text: tr('The authenticator app is on. From now on signing in with a password asks for a code.') })), { once: true }); }, 50);
      return null;
    },
  });
}

function openTotpOff() {
  const pw = el('input', { type: 'password', autocomplete: 'current-password', required: true });
  openForm(tr('Turn off the authenticator app'), [
    el('p', { class: 'muted', text: tr('Signing in will need only your password again. Your recovery codes stop working.') }),
    field(tr('Current password'), pw),
  ], {
    submitLabel: tr('Turn off'),
    onSubmit: async () => {
      const r = await api('POST', '/api/auth/totp/disable', { password: pw.value });
      if (!r.ok) return apiError(r);
      renderTotp({ ok: true, text: tr('The authenticator app is off.') });
      return null;
    },
  });
}

function openRecoveryForm() {
  const pw = el('input', { type: 'password', autocomplete: 'current-password', required: true });
  const code = el('input', { inputMode: 'numeric', autocomplete: 'one-time-code', maxLength: 8, required: true, placeholder: '123456' });
  openForm(tr('New recovery codes'), [
    el('p', { class: 'muted', text: tr('The codes you have now stop working. Your password and a current code from the app are needed.') }),
    field(tr('Current password'), pw), field(tr('Code from the app'), code),
  ], {
    submitLabel: tr('Make new codes'),
    onSubmit: async () => {
      const r = await api('POST', '/api/auth/totp/recovery', { password: pw.value, code: code.value });
      if (!r.ok) return apiError(r);
      setTimeout(() => { showRecoveryCodes(r.json.recovery_codes); $('msg-dialog').addEventListener('close', () => renderTotp(), { once: true }); }, 50);
      return null;
    },
  });
}

// ------------------------------------------------- a second step the administrator requires

/** Called when the server says a second step must be set up first (403 mfa_required, or must_enrol at sign-in). */
function onMustEnrol() {
  if ($('form-dialog').open) return;
  const passkeyName = el('input', { placeholder: tr('name, e.g. "Work laptop" or "YubiKey"'), maxLength: 40 });
  const passkeyError = el('div', { class: 'form-error', hidden: true });
  const canPasskey = state.methods && state.methods.passkey && passkeysSupported();
  openForm(tr('Set up a second sign-in step'), [
    el('p', { text: tr('Your administrator requires a second step for signing in. Set one up now: an authenticator app on your phone, or a passkey.') }),
    canPasskey ? el('div', { class: 'row' }, passkeyName, el('button', { type: 'button', id: 'enrol-passkey', text: tr('Add a passkey'), onclick: async () => {
      const e = await addPasskey(passkeyName.value.trim());
      if (e) { passkeyError.textContent = e; passkeyError.hidden = false; } else location.reload();
    } })) : null,
    passkeyError,
  ], {
    submitLabel: tr('Set up an authenticator app'),
    cancellable: false,
    onSubmit: async () => { setTimeout(() => openTotpSetup(() => location.reload()), 50); return null; },
  });
}

// ------------------------------------------------------------- administrators

const MFA_POLICY_TEXT = () => [['off', tr('Nobody')], ['admins', tr('Administrators')], ['all', tr('Everybody')]];

/** Settings → Sign-in security: who must use a second step. */
async function loadSecurityBox() {
  const r = await api('GET', '/api/security');
  if (!r.ok) return;
  const p = r.json;
  const sel = el('select', { id: 'mfa-policy' }, ...MFA_POLICY_TEXT().map(([v, t]) => el('option', { value: v, text: t })));
  sel.value = p.mfa_required;
  const status = el('span', { class: 'muted', id: 'mfa-status' });
  const count = (v) => (v === 'admins' ? p.admins_without : v === 'all' ? p.all_without : 0);
  const note = el('p', { class: 'muted small' });
  const drawNote = () => { note.textContent = sel.value === 'off' ? '' : tr('{n} people have no second step yet. At their next request they are asked to set one up before anything else works.', { n: count(sel.value) }); };
  sel.onchange = drawNote;
  drawNote();
  $('security-body').replaceChildren(
    el('p', { class: 'muted', text: tr('A second sign-in step is an authenticator app or a passkey. Signing in with a passkey already counts. Whoever is required to have one is asked to set it up at their next request.') }),
    el('label', { class: 'field-narrow' }, tr('Required for'), sel),
    note,
    el('div', { class: 'row' }, el('button', { type: 'button', class: 'primary', id: 'mfa-save', text: tr('Save'), onclick: async () => {
      const s = await api('PUT', '/api/security', { mfa_required: sel.value });
      status.textContent = s.ok ? tr('Saved.') : apiError(s);
    } }), status));
}
