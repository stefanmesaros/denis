'use strict';
// Settings → Software data: what DENIS knows about the end of support of the software versions devices announce, and
// which of them are known to be exploited; whether the support dates are refreshed. Loaded after switches.js.

async function loadVulnBox() {
  const r = await api('GET', '/api/vulndata');
  if (!r.ok) return;
  const d = r.json;
  const status = el('span', { class: 'muted', id: 'vuln-status' });
  const auto = el('input', { type: 'checkbox', id: 'vuln-auto', checked: d.refresh_eol, onchange: async () => {
    const s = await api('PUT', '/api/vulndata', { refresh_eol: auto.checked });
    status.textContent = s.ok ? tr('Saved.') : apiError(s);
  } });
  $('vuln-body').replaceChildren(
    el('p', { class: 'muted', text: tr('When a service tells DENIS its version (an SSH, FTP or mail banner, a web server header), DENIS can say whether that version is still supported and whether it is in the range of a vulnerability that attackers are exploiting now. Nothing is claimed without a version. A distribution may fix a flaw without changing the version number, so read a match as "check this", not as a verdict.') }),
    el('p', { text: tr('Support dates for {n} products and {k} known-exploited vulnerabilities, as of {date}.', { n: d.products.length, k: d.kev_entries, date: d.generated }) }),
    d.refreshed_at ? el('p', { class: 'muted', text: tr('The support dates were refreshed from endoflife.date {ago}.', { ago: ago(d.refreshed_at) }) }) : el('p', { class: 'muted', text: tr('The support dates are the ones that came with this version of DENIS.') }),
    el('p', { class: 'muted small', text: tr('The known-exploited list (CISA) and its affected versions (NVD) come with new versions of DENIS. Refreshing the support dates contacts endoflife.date and sends nothing about your network.') }),
    el('label', { class: 'check' }, auto, ' ' + tr('Refresh the support dates from endoflife.date every week')),
    el('div', { class: 'row' }, el('button', { type: 'button', id: 'vuln-refresh', text: tr('Refresh now'), onclick: async (ev) => {
      ev.target.disabled = true;
      status.textContent = '…';
      const p = await api('POST', '/api/vulndata/refresh');
      ev.target.disabled = false;
      status.textContent = p.ok && p.json.ok ? tr('Refreshed {n} products.', { n: p.json.refreshed }) + (p.json.failed.length ? ' ' + tr('{n} could not be fetched.', { n: p.json.failed.length }) : '') : (p.ok ? p.json.error : apiError(p));
      if (p.ok && p.json.ok) loadVulnBox();
    } }), status));
}
