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
    } }), status),
    el('h3', { class: 'section', text: tr('Custom CVEs') }),
    el('p', { class: 'muted', text: tr('Add a known-exploited vulnerability of your own — for software DENIS does not ship data for yet, or one you want flagged sooner. Matched against service banners exactly like the built-in list, above.') }),
    customKevTable(d.custom_kev, d.known_products),
    el('div', { class: 'row' }, el('button', { type: 'button', id: 'vuln-custom-add', text: tr('Add a custom CVE…'), onclick: () => openCustomKevForm(d.known_products, d.custom_kev) })));
}

function customKevTable(list, knownProducts) {
  if (!list.length) return el('p', { class: 'muted small', text: tr('No custom CVEs yet.') });
  return el('div', { class: 'table-wrap' }, el('table', {},
    el('thead', {}, el('tr', {}, el('th', { text: tr('CVE') }), el('th', { text: tr('Product') }), el('th', { text: tr('Name') }), el('th', { text: tr('Affected versions') }), el('th', {}))),
    el('tbody', {}, ...list.map((k, i) => el('tr', {},
      el('td', { class: 'mono', text: k.cve }),
      el('td', { text: k.product }),
      el('td', { text: k.name }),
      el('td', { class: 'muted small', text: k.ranges.map(rangeText).join('; ') }),
      el('td', {}, el('button', { type: 'button', text: tr('Delete'), onclick: async () => {
        if (!confirm(tr('Delete the custom entry for {cve}?', { cve: k.cve }))) return;
        const next = list.filter((_, j) => j !== i);
        const r = await api('PUT', '/api/vulndata/custom', next);
        if (!r.ok) { showMessage(tr('Could not delete'), el('p', { text: apiError(r) })); return; }
        loadVulnBox();
      } }))))),
  ));
}

function rangeText(r) {
  if (r.exact) return '= ' + r.exact;
  if (r.from && r.to) return r.from + ' – ' + r.to;
  if (r.from) return '≥ ' + r.from;
  if (r.to) return '≤ ' + r.to;
  return '?';
}

function openCustomKevForm(knownProducts, existing) {
  const cve = el('input', { placeholder: 'CVE-2026-12345', pattern: 'CVE-\\d{4}-\\d+', required: true, maxlength: 40 });
  const product = el('select', {}, el('option', { value: '', text: tr('Choose one…') }), ...knownProducts.map((p) => el('option', { value: p, text: p })));
  const name = el('input', { placeholder: tr('Short name'), required: true, maxlength: 200 });
  const added = el('input', { type: 'date', required: true });
  const kind = el('select', {}, el('option', { value: 'exact', text: tr('Exactly this version') }), el('option', { value: 'range', text: tr('A range of versions') }));
  const exact = el('input', { placeholder: '3.0.5' });
  const from = el('input', { placeholder: tr('from, e.g. 3.0.0') });
  const to = el('input', { placeholder: tr('to, e.g. 3.0.9') });
  const exactRow = field(tr('Version'), exact);
  const rangeRow = el('div', { class: 'row', hidden: true }, field(tr('From'), from), field(tr('To'), to));
  kind.onchange = () => { exactRow.hidden = kind.value !== 'exact'; rangeRow.hidden = kind.value !== 'range'; };
  openForm(tr('Add a custom CVE'), [el('div', { class: 'form-grid' },
    field(tr('CVE id'), cve), field(tr('Product'), product), field(tr('Name'), name), field(tr('Added/published'), added),
    field(tr('Match by'), kind), exactRow, rangeRow)], {
    onSubmit: async () => {
      if (!product.value) return tr('Choose a product.');
      const range = kind.value === 'exact'
        ? { exact: exact.value.trim() }
        : { from: from.value.trim() || null, from_incl: true, to: to.value.trim() || null, to_incl: true };
      const entry = { cve: cve.value.trim(), product: product.value, name: name.value.trim(), added: added.value, ranges: [range], ransomware: false };
      const r = await api('PUT', '/api/vulndata/custom', [...existing, entry]);
      if (!r.ok) return apiError(r);
      loadVulnBox();
      return null;
    },
  });
}
