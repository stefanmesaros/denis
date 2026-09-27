'use strict';
// IP enrichment: shared helpers for showing an IP address's country/city/ASN/ISP/reverse-DNS
// hostname wherever one appears (Alerts, Events, the asset panel's IP history). One small module
// so every call site is a one-line integration instead of five separate implementations — the
// same reasoning `aiExplainButton`/`sevTag` are already shared helpers rather than copy-pasted.
//
// `info` throughout is the `ip_info` shape the backend attaches next to any `"ip"` field
// (`ipenrich::decorate`) or returns from `GET /api/ip-enrichment/{ip}` directly: `{ip,
// classification, hostname, country, region, city, latitude, longitude, asn, as_org, isp,
// connection_type, geoip_source, geoip_db_version, dns_source}`. Every field but `ip`/
// `classification` may be absent — "Not available" in the UI, never a guess.

/** Flag emoji from an ISO 3166-1 alpha-2 country code (regional-indicator trick: 'US' -> 🇺🇸).
 * `null` for anything that is not exactly two ASCII letters, so a bad/unknown code degrades to no
 * flag rather than mojibake. */
function countryFlag(iso2) {
  if (!iso2 || !/^[A-Za-z]{2}$/.test(iso2)) return null;
  const cps = [...iso2.toUpperCase()].map((c) => 0x1f1e6 + (c.charCodeAt(0) - 65));
  return String.fromCodePoint(...cps);
}

/** The one-line "AS Org · ASnnnn · Country" (or as much of it as is known) shown right under an
 * IP address, per the brief's own example. `null` (render nothing) for a private/reserved/
 * loopback/etc. address — geolocation is only ever attempted for a public one. */
function ipContextLine(info) {
  if (!info || info.classification !== 'public') return null;
  const parts = [];
  if (info.as_org) parts.push(info.as_org);
  if (info.asn) parts.push('AS' + info.asn);
  if (info.country) parts.push((countryFlag(info.country) ? countryFlag(info.country) + ' ' : '') + info.country);
  if (!parts.length) return null;
  return parts.join(' · ');
}

/** A short word for a non-public address, shown in place of the geo context line. */
function classificationLabel(info) {
  if (!info || info.classification === 'public') return null;
  const words = { private: tr('private'), loopback: tr('loopback'), 'link-local': tr('link-local'), multicast: tr('multicast'), reserved: tr('reserved'), unspecified: tr('unspecified') };
  return words[info.classification] || null;
}

/** One IP address, inline: the address itself, clickable, with its context line right under it —
 * the exact `198.41.200.33` / `Cloudflare, Inc. · AS13335 · US` two-line pattern from the brief.
 * Clicking opens the full detail panel (`ipDetailDialog`). */
function ipInline(ip, info) {
  const context = ipContextLine(info) || classificationLabel(info);
  return el('div', { class: 'ip-inline' },
    el('button', { type: 'button', class: 'ip-link', text: ip, onclick: () => ipDetailDialog(ip, info) }),
    context ? el('div', { class: 'muted small', text: context }) : null);
}

/** The full click-through detail panel: every field, plus the data source and database version/
 * update date the brief asks for. Fetches a fresh answer on demand (the on-demand, directly-
 * awaited path — `IP_ENRICHMENT.md` §8/§14) rather than only showing whatever was already inline,
 * so opening it always has a real answer even if the inline copy was cached from before a GeoIP
 * database existed. */
async function ipDetailDialog(ip, info) {
  showMessage(ip, el('p', { class: 'muted', text: tr('Loading…') }));
  const r = await api('GET', '/api/ip-enrichment/' + encodeURIComponent(ip));
  const d = r.ok ? r.json : info || { ip, classification: 'public' };
  const row = (label, value) => (value == null || value === '') ? null : el('div', { class: 'ip-detail-row' }, el('span', { class: 'muted', text: label }), el('span', { text: value }));
  const flag = countryFlag(d.country);
  const rows = [
    row(tr('IP address'), d.ip),
    row(tr('Classification'), tr(d.classification)),
    row(tr('Reverse DNS'), d.hostname || (d.classification === 'public' ? tr('unavailable') : null)),
    row(tr('Country'), d.country ? (flag ? flag + ' ' : '') + d.country : null),
    row(tr('Region'), d.region),
    row(tr('City'), d.city),
    row(tr('Coordinates'), (d.latitude != null && d.longitude != null) ? `${d.latitude.toFixed(3)}, ${d.longitude.toFixed(3)}` : null),
    row(tr('ASN'), d.asn ? 'AS' + d.asn : null),
    row(tr('AS organization'), d.as_org),
    row(tr('ISP / network'), d.isp),
    row(tr('Connection type'), d.connection_type),
  ].filter(Boolean);
  const source = d.geoip_source
    ? tr('Data source: {source}{version}', { source: d.geoip_source, version: d.geoip_db_version ? ' (' + tr('database version {v}', { v: d.geoip_db_version }) + ')' : '' })
    : null;
  showMessage(ip,
    (d.latitude != null || d.country) ? el('p', { class: 'muted small', text: tr('Approximate location — never a precise physical address.') }) : null,
    rows.length ? el('div', { class: 'ip-detail' }, ...rows) : el('p', { class: 'muted', text: tr('Nothing is known about this address yet.') }),
    source ? el('p', { class: 'muted small', text: source }) : null);
}

/** Every `{ip, ip_info}` (or an array item shaped `{ip, ...}` with a sibling `ip_info`) found
 * anywhere in `raw_details`-like data, mirroring exactly what the backend's `ipenrich::decorate`
 * walk attaches server-side. A short, best-effort `label` is derived from the enclosing key when
 * one is recognised (`destinations[]`'s own proto/port, `client`/`server`), falling back to
 * nothing rather than a wrong guess. */
function findIpEntries(details) {
  const out = [];
  const visit = (node, label) => {
    if (Array.isArray(node)) { node.forEach((n) => visit(n, label)); return; }
    if (!node || typeof node !== 'object') return;
    // two address-field names in practice, not one — see decorate.rs's own module doc
    const addr = typeof node.ip === 'string' ? node.ip : (typeof node.remote === 'string' ? node.remote : null);
    if (addr && node.ip_info) {
      const bits = [label].filter(Boolean);
      if (node.proto && node.port) bits.push(node.proto + '/' + node.port);
      out.push({ ip: addr, info: node.ip_info, label: bits.join(' · ') });
    }
    for (const [k, v] of Object.entries(node)) {
      if (k === 'ip' || k === 'remote' || k === 'ip_info') continue;
      visit(v, ['destinations', 'client', 'server'].includes(k) ? k : label);
    }
  };
  visit(details, null);
  return out;
}

/** One IP address in a list that has no server-side `ip_info` at all yet (the asset panel's IP
 * history, built from the typed `Asset.ip_history` — never runs through `ipenrich::decorate`,
 * unlike an alert/event's `raw_details`). Renders immediately with just the address, then fetches
 * the real answer in the background and swaps the context line in — the panel never waits on a
 * lookup to open, and a device with ten historical addresses costs ten small, independent
 * requests rather than one slow one. */
function ipInlineLazy(ip) {
  const holder = ipInline(ip, null);
  api('GET', '/api/ip-enrichment/' + encodeURIComponent(ip)).then((r) => {
    if (r.ok) holder.replaceWith(ipInline(ip, r.json));
  });
  return holder;
}

/** The "Network context" section for an alert/event's detail dialog: every IP address its
 * `raw_details` mentions, each inline with its context line, clickable for the full panel. `null`
 * (render nothing) when there is nothing to show, so a rule with no IPs in it looks exactly as it
 * did before this existed.
 *
 * Always a fresh, on-demand lookup (`ipInlineLazy`), not the possibly-still-empty `ip_info` the
 * list endpoint already attached: a person opening one specific alert is exactly the "wait a
 * moment for one item" case `IP_ENRICHMENT.md` §8 describes, and a brand-new destination (the
 * most common reason to be looking at all) has usually not been resolved by the background
 * worker yet — showing nothing until a page reload would defeat the point of showing this here
 * at all. */
function ipContextSection(details) {
  const entries = findIpEntries(details);
  if (!entries.length) return null;
  return el('div', { class: 'ip-context-section' },
    el('b', { text: tr('Network context') }),
    ...entries.map((e) => el('div', { class: 'ip-context-row' }, e.label ? el('span', { class: 'tag', text: e.label }) : null, ipInlineLazy(e.ip))));
}
