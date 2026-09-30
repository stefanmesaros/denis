# Console UX review

A review of the console as it is built today, from reading `ui/index.html`, `ui/style.css` and every
`ui/*.js` file in this worktree (v2.51.0), not from a mood board. Same bar as [NAC.md](NAC.md) and
[MULTI_AGENT_DEDUP.md](MULTI_AGENT_DEDUP.md): every finding below names the file and the code it
comes from, and says whether the fix is a firm recommendation or a suggestion. Nothing in
`ui/` was changed for this review.

**What is already good, so it is not lost in a list of problems:** the DOM is built with
`textContent` only, there is one `apiFetch` wrapper, one `openForm`/`showMessage` dialog pair,
one `el()` helper, a real focus ring (`:focus-visible`, style.css line 29), a working three-way
theme toggle (`initTheme`, admin.js 87–105) and a runtime-brandable accent (`applyBranding`),
a collapsible sidebar that becomes an overlay on phones, virtualised rendering past 300 devices,
per-table column layouts, deep links for every tab and most objects (`applyHash`), and a
first-run setup guide whose steps are judged by the server. The poll-safe pattern in
`findings.js` (skip the rebuild when the JSON is byte-identical) is the right idea and should
spread. The review below is about the seams between all of that.

**How to read the "Proposed solution" blocks (added 2026-09-30).** Stefan asked for every finding
to go on the implementation queue with a fix an engineer can scope from, not a restatement of the
problem. Each block below names the files that change, the shape of the new code, and an effort on
the same 1–10 scale ROADMAP.md uses (1 = an hour, 3 = a day, 5 = a working week, 8+ = a release).
Where a solution depends on another finding's helper, it says so; the dependency order is at the
end of the prioritised list. Nothing here is implemented; `ui/` is unchanged by this pass. The
four-look theme picker Stefan decided on is a new section after the findings, because it is a
product decision about *where a control lives*, not a defect.

## Findings

### 1. Settings → Integrations is one page for seven credential forms, a scanner and a SIEM

`#cmdb-box` (index.html 635–727) stacks Entra ID/Intune, Active Directory, Jamf Pro, Azure, AWS
and GCP — each its own `Enabled` checkbox, three to five inputs, a "sync every" field, a
secret-status line, and a *Save* / *Sync now* / message row — followed by the shared "Imported
devices" list, then `#vulnscan-box` (Nessus) and `#siem-box`, all under one `settingsSelect`
category with no collapse, no per-source summary and no visual container per source beyond an
`h4`. `loadCmdbBox` (admin.js 1614) fires seven `GET`s every time Settings opens, whether or not
anyone is looking at Integrations.

Concrete problems: an administrator cannot tell at a glance which sources are on, which last
synced when, and which one is failing — that information is only in the per-source message
span after a manual *Sync now*. The page is roughly 2,000 px tall before any imported device is
listed. The eighth source (Qualys, ROADMAP item 10) makes it worse in the same shape.

**Firm recommendation.** Turn the Integrations category into a *list of sources* — one row per
source with name, on/off, last sync, imported count and last error (the data already exists in
each `*/settings` response plus `cmdb/devices`) — and open the credential form in the existing
`openForm` dialog on *Configure…*. The dialog is already how switches, watches, accepted risks
and TOTP set-up are edited, so this is consistency, not a new pattern. Load the seven settings
only when the Integrations category is selected.

**Proposed solution** *(effort: 5/10)* — the recommendation above, carried forward and scoped.

*HTML.* `#cmdb-box` (index.html 635–727) shrinks to: the intro `p`, an empty `#integrations-list`,
and `#cmdb-devices`. The six per-source blocks (Entra/Intune, AD, Jamf, Azure, AWS, GCP: every
`label`, `input`, `*-secret-status`, `*-save`, `*-sync`, `*-msg`) are deleted. `#vulnscan-box`
loses its form the same way and keeps `#vulnscan-findings`; `#siem-box` loses its form too. Three
boxes become one category page: a source list, then "Imported devices", then "Imported findings".

*JS: one registry instead of six copies.* In admin.js, replace the six `$('x-save').onclick` /
`$('x-sync').onclick` pairs and the six `if (s.ok) { … }` blocks in `loadCmdbBox` (1614–1804) with
a table:

```
INTEGRATIONS = [
  { key: 'cmdb', label: 'Microsoft Entra ID / Intune', api: '/api/cmdb', syncable: true,
    fields: [ ['tenant_id', 'Tenant ID', 'text'], ['client_id', 'Client (application) ID', 'text'],
              ['client_secret', 'Client secret', 'secret', 'client_secret_set'],
              ['include_intune', 'Also import Intune managed devices', 'check'],
              ['sync_interval_hours', 'Sync every (hours)', 'number'] ],
    help: 'Pulls device inventory from Microsoft Entra ID (…)' },
  { key: 'ad', … }, { key: 'jamf', … }, { key: 'azure', … }, { key: 'aws', … }, { key: 'gcp', … },
  { key: 'vulnscan', label: 'Nessus / Tenable.io', … },
  { key: 'siem', label: 'SIEM / log export', syncable: false, testable: true, fields: […] },
]
```

The `secret` field type carries the name of the `*_set` flag so the dialog can show the
"(unchanged)" placeholder exactly as today. `loadIntegrations()` does one `Promise.all` over
`INTEGRATIONS.map(i => api('GET', i.api + '/settings'))` plus `cmdb/devices` and
`vulnscan/findings`, caches the results in `state.integrations[key]`, and renders one row per
entry: a status dot (off / on and last sync ok / on and last sync failed), the label, a meta line
("last synced 2 h ago · 143 devices", or the last error verbatim, or "never synced"), and the
actions *Configure…*, *Sync now* (or *Send a test message* for SIEM). *Configure…* calls
`openIntegrationForm(i)`, which builds a `.form-grid` from `i.fields` inside `openForm`, with
`i.help` as the first paragraph and the *Enabled* checkbox as the first field, and on submit does
the same `PUT` the six handlers do today; on success it refreshes the one row, not the page.

*One server touch to check.* The row needs "last sync", "imported count" and "last error" per
source. `cmdb/devices` gives the count (group by `source`); whether each `*/settings` response
already carries `last_sync_at` and `last_error` must be checked in `src/` before scoping — if it
does not, each connector's settings struct gains those two read-only fields (one small Rust
change per connector, ~1/10 in total, and it is what makes the list worth having).

*Lazy loading.* `setTab('settings')` (app.js 1724) calls sixteen loaders at once. Replace that
line with a map `SETTINGS_LOADERS = { system: [loadLicenseBox, loadUpdateBox, …], security: […],
network: [loadInterfacesBox, loadSwitchesBox, loadIpenrichBox], data: […], integrations:
[loadIntegrations], ai: [loadAiBox], branding: [initBrandingForm, initOverviewBox] }` and have
`settingsSelect(cat)` run only its category's loaders, once per Settings visit (a `loadedCats`
`Set` cleared in `setTab` when leaving Settings). The seven GETs then happen only when someone
opens Integrations, and Settings → System opens with two requests instead of twenty.

*Also touched:* `tools/i18n` (the per-source help paragraphs move from HTML into `tr()` strings),
`tools/ui-smoke.mjs` if it clicks any of the deleted ids, `docs/` pages that say "under
Settings → Integrations, fill in…". Qualys (ROADMAP item 10) becomes one more registry entry.

### 2. There is no disclosure component, and NAC.md's first release needs one

NAC.md ("What the user is told") plans "a second, separate, clearly labelled field under a
disclosure: *Allow DENIS to disable ports on this switch*" inside the switch form. Today
`openSwitchForm` (switches.js 157–178) is a four-field `.form-grid`, and the console has no
disclosure primitive for forms: `<details>` is used three times, each styled ad hoc —
`.exceptions` (rules.js 275, 477, 638; style.css 416–417: a muted `summary`, no border, no
chevron), `.compliance-group` (app.js 1678; its own chevron and border), and the unstyled
per-switch port table on the Topology page (switches.js 95). Nothing marks a disclosure as
"opens something with consequences".

The same gap shows in the three existing "dangerous action" confirmations, which use three
different mechanics: *Erase all data* and *Forget all learned baseline data* type a phrase into
`openForm` (admin.js 1226, rules.js 112); *Delete site* uses the browser's `prompt()`
(admin.js 691); *Restart* / *Shut down* ask for the password in `openForm`
(`openSystemActionForm`, admin.js 1383). NAC.md's block dialog needs password **and** reason
**and** an acknowledgement checkbox that gates the submit button — a fourth variant if it is
built ad hoc.

**Firm recommendation.** Before NAC: (a) one `disclosure(summary, body, {tone})` helper with a
chevron, a border and a `tone: 'warning'` variant, used by the rules exceptions, the switch form
and the compliance groups alike; (b) one `openDangerForm({title, warning, requirePassword,
requireReason, acknowledge: 'text', typedPhrase})` built on `openForm`, and migrate erase-all,
forget-baseline, delete-site, restart and shutdown onto it. Both are needed anyway and neither
touches the server.

**Proposed solution** *(effort: 3/10 for both helpers; the five migrations are inside that)*

*(a) `disclosure()`* — in app.js next to `el()`, since rules.js, switches.js and admin.js all use
it: `disclosure({ summary, body, tone, open })` returns
`<details class="disclosure [disclosure-warn]" [open]>` with a `<summary>` made of the chevron
glyph from `icons.js`, the summary text, and — for `tone: 'warning'` — a small amber chip after
the text ("changes what DENIS may do"). `body` is an array of nodes placed in
`<div class="disclosure-body">`. CSS is one block: a `--line` border, 6 px radius, summary at
body size with the chevron rotating 90° on `[open]`, warn tone gets a `--warn` left rule and a
`--warn` chip. Migrate the three ad-hoc `<details>`: `.exceptions` (rules.js 275, 477, 638),
`.compliance-group` (app.js 1678), `portTable` (switches.js 95); delete their one-off CSS.

For NAC.md's switch form: `openSwitchForm` (switches.js 164) appends, after the read community
field, `disclosure({ tone: 'warning', open: !!t.write_community_set, summary: tr('Allow DENIS to
disable ports on this switch'), body: [field(tr('SNMP write community'), writeInput), el('p', {
class: 'muted', text: <what it permits / does not permit / v2c caveat> })] })`. The write field is
never `required` (a closed `<details>` cannot be focused for native validation), and the submit
handler sends `write_community` only when non-empty — the same "(unchanged)" convention the read
community uses. A "Remove port control" button inside the body clears it, and when the server
reports DENIS-disabled ports on that switch (NAC.md §6), that button goes through the danger form
in (b) with the warning "DENIS will no longer be able to re-enable {n} ports it disabled".

*(b) `openDangerForm()`* — in admin.js next to `openForm`, built on it. Signature:

```
openDangerForm({ title, intro, items, warnings, refusals, acknowledge, requirePassword,
                 requireReason, typedPhrase, submitLabel, onSubmit })
```

It renders, in this fixed order: `intro` (plain `p`); `items` (a `ul` of the things affected —
for NAC the devices behind the port and "and {n} devices DENIS cannot name"); `refusals` (a
`ul.refusals` in the danger colour; **when non-empty the submit button is not rendered at all**,
only *Close* — this is NAC.md's "refusals → no confirm button, only the reasons"); `warnings`
(each a `p.form-warn`); the `acknowledge` checkbox, rendered only when given, with its label
("I understand this also cuts off the devices listed above"); the reason `textarea` when
`requireReason` (`minlength 3`, `maxlength 200`, `required`); the password field when
`requirePassword` (`autocomplete="current-password"`); the typed-phrase input when `typedPhrase`;
then the actions with a danger-toned submit. One `syncSubmit()` bound to `input` on every gate
sets `submit.disabled = !(ackOk && reasonOk && pwOk && phraseOk)`; the button starts disabled
whenever any gate exists. `onSubmit({ password, reason, acknowledged })` returns an error string
or `null`, exactly like `openForm`. The dialog gets a `danger` class so the title carries a
`--danger` rule and the primary button uses the danger tone.

Migrations, each a mechanical swap of the body it already has: erase-all (admin.js 1226:
`typedPhrase: 'ERASE ALL DATA'`), forget-baseline (rules.js 112: `typedPhrase`), delete-site
(admin.js 690: `typedPhrase: agentId`, replacing `prompt()`), restart and shutdown
(`openSystemActionForm`, admin.js 1383: `requirePassword`, the warning as `warnings`). NAC's plan
dialog then needs no new code: `items` = `plan.affected`, `refusals` = `plan.refusals`, `warnings`
= `plan.warnings`, `acknowledge` when warnings exist, `requirePassword`, `requireReason`, and
`onSubmit` posts `/api/nac/apply`. NAC's *Enable* (one plain confirmation, no password) and every
destructive `confirm()` in finding 3 use the same function with only `intro` and `items`.

### 3. Thirty-three `confirm()` calls and one `prompt()`; feedback is inconsistent

`grep -c 'confirm('` over `ui/*.js` gives 33 (delete user, revoke/delete tokens, delete channel,
delete switch, delete report, delete backup, withdraw accepted risk, remove passkey, remove
baseline destination, reset password, "Also add an exception?", …). A native `confirm()` cannot
show the thing being deleted beyond a name, cannot be styled to match the theme, blocks the
poll, and on some browsers is suppressed after repeated use on one page. Success feedback is
equally mixed: twenty-one places write "Saved." into a `<span class="muted">` next to a button
(`$('…-msg').textContent = r.ok ? tr('Saved.') : apiError(r)` — sso, ai, cmdb, ad, jamf, azure,
aws, gcp, vulnscan, siem, retention, ipenrich, interfaces, license, branding, backup schedules,
reports schedule, the vulndata toggles, the MFA policy); others open a modal `showMessage` for
the same kind of result (import,
verify-fix, channel test, switch read); the Alerting channel table's inline min-score input
saves on `change` with **no** feedback at all except the row re-rendering (admin.js 945–950).

**Firm recommendation.** One non-modal `notice(text, {tone})` (a corner toast, auto-dismiss,
`aria-live="polite"`) for "Saved." and the like, and the danger form from finding 2 for every
destructive `confirm()`. Keep `showMessage` for results a person needs to read (import
summaries, verify-fix tables). Migrate destructive actions first: delete user, revoke agent
token (disconnects a site), delete switch, delete channel, withdraw accepted risk.

**Proposed solution** *(effort: 3/10; depends on finding 2's danger form)*

*`notice()`.* One `<div id="notices" aria-live="polite">` added to index.html after the dialogs,
fixed **bottom-left** (the Ask DENIS panel owns bottom-right), stacking upward, max three visible.
`notice(text, { tone = 'ok', ms })` in app.js appends a `.notice.<tone>` with the text and a
close button, removes it after 4 s (`danger`: 8 s, and it stays until closed when the tab is
hidden — `document.hidden`), and hover pauses the timer. Tones map to the status tokens. One
wrapper `saved(r, okText = tr('Saved.'))` does `r.ok ? notice(okText) : notice(apiError(r), {
tone: 'danger' })`, and the twenty-one `$('x-msg').textContent = r.ok ? tr('Saved.') :
apiError(r)` lines become `saved(r)`; the `span.muted` message elements are deleted from
index.html except where the text is a *result* someone reads (sync counts, "Restarting… reload
this page", update progress), which stay as they are. The channel table's min-score `change`
handler (admin.js 945) gets `saved(r, tr('Minimum score saved.'))` — or disappears into
finding 15's *Edit…* dialog, which is the better end state.

*The 33 `confirm()`s.* Classify by grep: destructive (delete/revoke/remove/withdraw/forget,
roughly 24) → `openDangerForm({ title, intro, items: [the named object], submitLabel })`, no
password, no phrase; questions that are not destructive ("Also add an exception?", "Mark the
{n} devices shown as known?", "Remove the IP address now?", ~9) → the same function with
`submitLabel` as the affirmative verb and no danger class (`tone: 'neutral'`). The one `prompt()`
is finding 2's delete-site. Nothing keeps a native dialog. Order: the five named above first
(they disconnect or destroy), then the rest file by file. Each migration is three lines; the
cost is `tools/i18n` (the confirm texts already exist as `tr()` strings and are reused as
`intro`) and one pass through `tools/ui-smoke.mjs` if it dismisses any native dialog.

### 4. Every polled table is rebuilt from scratch every 10 seconds, which keeps breaking in-row controls

`poller = setInterval(refresh, 10000)` (admin.js 253) and `refresh()` (app.js 1732) call
`renderAssets`, `renderAlerts`, `renderEvents` and `renderAgents` unconditionally, each doing
`tbody.replaceChildren(...)`. The consequences are already in the changelog and in code comments:
the Acknowledge reason dropdown had to become a "swap in for the click only" control because a
dropdown living in the row "could have its picked-but-not-yet-submitted value wiped under the
user" (app.js 492–501, CHANGELOG 2.43.1); the AI provider picker got the same treatment for the
same reason (admin.js 366–373, CHANGELOG 2.46.0); the Findings page lost in-flight AI answers
until it learned to skip identical rebuilds (findings.js 7–13, AI.md step 9). The open device
panel is re-rendered by the same poll (`if (state.selected != null && !$('detail').hidden)
showDetail(state.selected)`, app.js 1760), which re-issues four requests and rebuilds
`#detail-body`, so a person reading the bottom of a long panel is scrolled back up every ten
seconds while an AI answer they asked for in the alert dialog is unaffected only because that
dialog is modal.

**Firm recommendation.** Adopt the Findings rule everywhere: compute a cheap key per list (ids +
`last_seen`/`acked`/`score`) and skip the rebuild when it has not changed; for the device panel,
compare the four responses and only replace sections whose data changed, or at minimum preserve
`scrollTop`. Until then, every future in-row control (NAC's port-table *Disable…* button will
not be affected — `renderPhysical` runs only on tab change — but anything on Alerts, Devices or
Events will) inherits the same bug class.

**Proposed solution** *(effort: 5/10: the helper is a day, the four tables and the panel two to
three days, the smoke-test check half a day)*

The Findings rule (skip when the JSON is identical) is necessary but not sufficient: on Alerts
and Devices *something* changes almost every poll (`last_seen`, a new event), so a whole-list
skip rarely fires and the rebuild still wipes the row a person is using. The fix is **keyed row
reconciliation** — patch the rows that changed, keep the rows that did not, never destroy a row
that is in use — with the whole-list skip as its fast path.

*The helper.* `patchRows(tbody, items, { key, sig, build })` in tables.js (it is table plumbing,
and tables.js already loads on every page):

* `key(item)` is a stable id string (`'a:' + asset.id`, `'e:' + alert.id`, `'g:' + asset_id +
  '|' + type` for a repeated-alert group header); `sig(item)` is a string of every value the
  row *displays* (for a device row: ip, mac, vendor, display name, type, location, os, ports,
  risk score, the `isOnline` boolean, the manual/new/self flags, `agent_id`); `build(item)`
  is the existing row function.
* Fast path: join all sigs into one string, compare with `tbody.dataset.sig`; identical → return
  without touching the DOM (this is the Findings rule, and it is the common case on Events and
  Agents).
* Otherwise, index the existing rows by `tr.dataset.key`. Walk `items` in order with a cursor
  on `tbody.children`: if a row with that key exists and its `dataset.sig` equals the new sig,
  reuse it (move it with `insertBefore` if it is not already at the cursor); if the key exists
  but the sig differs, build a new row and `replaceWith` it; if the key is new, build and insert.
  Rows whose keys are no longer in `items` are removed. Set `dataset.key`/`dataset.sig` on every
  row `build` returns.
* **The in-use rule:** a row is *never replaced* — only moved — while it contains
  `document.activeElement`, or carries `data-busy` (set by `ackReasonPicker`, `resolveAiProvider`
  and any future in-row control while it is open, cleared when it closes). Its sig is re-checked
  on the next poll, so a stale row is at most ten seconds behind, and only while someone is
  inside it.

*Relative times.* `ago()` text changes every poll and must not be in the sig. Time cells become
`el('td', { class: 'rel', 'data-ts': e.timestamp })`, and one `tickRelativeTimes()` at the end
of `refresh()` does `querySelectorAll('[data-ts]')` → `textContent = ago(ts)`. Same for the
online dot (the boolean is in the sig; the tooltip is not).

*Where it goes.* `renderAssets` (non-virtual branch: the `body.replaceChildren(...)` at app.js
400 becomes `patchRows(body, items, …)`; group rows key on `'grp:' + label`; the virtual branch
`drawVirtualWindow` patches its window the same way — the spacer rows key on `'top'`/`'bottom'`
and their sig is their height), `renderAlerts` (624), `renderEvents` (833), `renderAgents`
(1128), `renderOverview`, the channels table, the accepted-risks table, the users and tokens
tables. `ackReasonPicker` can then stay as the swap-in it is (it now sets `data-busy`, so the
row survives), and the comment at app.js 492–501 shrinks to one line. Sorting and filtering
already produce `items` in display order, so the reconciliation handles a re-sort as a set of
moves — no rebuild on clicking a column header either.

*The device panel.* Split `showDetail(id)` into `loadDetail(id)` (the four requests →
`{ a, bl, hist, plugged, merged }`) and `renderDetail(d)`. `#detail-body` becomes fixed
containers, one per section (`section[data-sec="head"|"info"|"risk"|"alerts"|"baseline"|
"identity"|"ips"|"ports"|"evidence"|"why"|"history"]`), each rendered by a small function from
its slice of `d` and guarded by its own sig (`JSON.stringify` of that slice); only sections whose
sig changed get `replaceChildren`. Because the scroller's children keep their identity, the
scroll position survives; wrap the patch in a `scrollTop` save/restore anyway. The poll
(app.js 1760) calls `refreshDetail()`, which re-runs `renderDetail` from `state.assets` for the
sections that come from the asset itself, and re-issues the baseline/history/merged/topology
requests only when the asset's own sig (`last_seen`, `risk`, `meta`, ip history length) changed
or every sixth poll — four requests every 60 s instead of every 10 s while a panel is open.

*Proof it works.* `tools/ui-smoke.mjs` gains one scenario: open Alerts, click *Acknowledge* so
the reason `select` appears, wait 12 s (one poll), assert the `select` is still in the document
and still focused; open a device, scroll `#detail` to the bottom, wait 12 s, assert `scrollTop`
did not change. Those two assertions are the bug class this finding is about, and they are what
stops it coming back with the next in-row control (NAC's port table, finding 17).

### 5. The device panel is a 440 px column of fourteen headings with no structure

`showDetail` (app.js 1184–1320) renders, in fixed order: actions, *Asset information*, *Risk*,
*Alerts*, *Baseline* (with *Recent destinations* and *Active hours* under it), *Identity*, *IP
history*, *IPv6 addresses*, *Open ports*, *Fingerprint evidence*, *Why this guess*, *Change
history* — every section always expanded, `h3` at 12 px uppercase (style.css 121), inside a
fixed panel of `width: min(440px, 100vw)`. "Why this guess" — the product's signature
explainability — is the eleventh heading. The panel has no sticky header, so the device name and
the *Edit asset* button scroll away.

**Firm recommendation.** A sticky panel header (icon, name, type · OS · site, the action row) and
three in-panel tabs or anchor chips — *Overview* (asset information, risk, why this guess,
connected-to), *Activity* (alerts, baseline, IP history, active hours), *Evidence* (identity,
ports, fingerprint, change history). Same data, same requests; only the order and the
scroll change. **Suggestion:** widen to `min(520px, 100vw)` on screens ≥ 1280 px; the
two-column `dl` (110 px + 1fr) is cramped for a hostname plus a reverse-DNS line.

**Proposed solution** *(effort: 3/10; do it in the same change as finding 4's panel split, since
both restructure `#detail-body`)*

`#detail` (index.html 864) becomes a flex column with three children: `.detail-head` (sticky,
`top: 0`, panel background, bottom border: the 30 px icon, `h2` name, the "type · OS · site"
line, the close button, and the two `.detail-actions` rows), `.detail-tabs` (a `.segmented`
with `role="tablist"`, three buttons *Overview* / *Activity* / *Evidence*, sticky under the
head), and `.detail-scroll` (`overflow-y: auto`, the eleven `section[data-sec]` from finding 4).
Each section carries `data-tab="overview|activity|evidence"` and is hidden unless its tab is
active: Overview = info, risk, why-this-guess, connected-to (moved out of Identity, since it is
the first thing an operator wants); Activity = alerts, baseline (destinations, active hours), IP
history, IPv6; Evidence = identity (banners, JA3, hostnames, first/last seen), open ports,
fingerprint evidence, change history. `state.detailTab` persists across devices (someone
triaging ten devices wants the same tab each time) and in the deep link as `#device/12/evidence`
(`applyHash` reads the third segment). CSS: `@media (min-width: 1280px) { #detail { width:
min(520px, 100vw); } }` and `#detail dl { grid-template-columns: minmax(110px, 140px) 1fr; }`.
`Escape` and the close button unchanged. The section `h3`s stay but drop to one per section; the
uppercase 12 px treatment goes with DESIGN_LANGUAGE.md §2.

### 6. The asset editor is 22 unrelated fields in one auto-fit grid

`FIELD_DEFS` (admin.js 340–350) lays out name, icon, type, status, criticality, owner,
department, location, zone, Purdue level, asset tag, serial, model, manufacturer, OS, supplier,
purchase date, price, warranty, silence-until, tags, notes, then custom fields, into
`.form-grid` (`repeat(auto-fit, minmax(210px, 1fr))`, style.css 276), so the grouping a person
sees depends on the dialog width: at 720 px it is three columns and *Zone / cell* and *Purdue
level (OT)* land between *Location* and *Asset tag*; at phone width it is one column of 22 rows.
An office IT user sees OT fields every time.

**Firm recommendation.** Five `fieldset`s with legends — *Identity* (name, icon, type, OS,
manufacturer, model), *Ownership & place* (owner, department, location, tags), *Lifecycle*
(status, criticality, asset tag, serial, supplier, purchase date, price, warranty), *Industrial*
(zone, Purdue level; collapsed unless the device is OT or either is set), *Notes & custom
fields* (notes, silence-until, custom). `FIELD_DEFS` already carries the order, so this is one
extra column in that table plus one wrapper per group.

**Proposed solution** *(effort: 2/10; uses finding 2's `disclosure()`)*

Each `FIELD_DEFS` row (admin.js 340–350) gains a fourth element, the group key: `['zone',
tr('Zone / cell'), 'text', 'industrial']`. A `FIELD_GROUPS = [['identity', tr('Identity')],
['ownership', tr('Ownership & place')], ['lifecycle', tr('Lifecycle')], ['industrial',
tr('Industrial (OT)')], ['notes', tr('Notes & custom fields')]]` list gives the order and
legends. `openAssetForm` (admin.js 567) builds the inputs exactly as today, then groups them:
`fieldset` + `legend` + the same `.form-grid` inside, one per group that has at least one field.
The *Industrial* group is wrapped in `disclosure({ summary: legend, open: isOt(a) || !!(m.zone
|| m.purdue_level) })` instead of a `fieldset`, so an office IT user sees a one-line "Industrial
(OT)" row and nothing else. Custom fields append to the last group. CSS: `fieldset { border: 0;
padding: 0; margin: 0 0 var(--s-4); } legend { font-weight: 600; font-size: var(--fs-sm);
color: var(--text-2); margin-bottom: var(--s-2); }`. The submit handler is untouched: it reads
inputs by field key, not by position. The CSV import/export columns and the bulk-edit field
list are unaffected.

### 7. Five banners can stack under the header, in four colours

Three full-width bars sit under `<header>` (`#maint-banner` amber, `#demo-banner` blue,
`#update-banner` blue; index.html 46–48) and can all be visible at once; inside pages, `#learning`
(accent-left-bordered `.banner`, above the toolbar on Alerts only) and `#license-banner` (inside
Devices) add two more, and the Rules page has its own `#rule-suggestion-banner`. Only the rule
suggestion can be dismissed. On a demo install with a pending update in maintenance mode, the
first 120 px of every page is banners.

**Firm recommendation.** One banner stack under the header with a fixed priority (maintenance >
license problem > update > demo > learning), each dismissible for the session where the
information is not safety-relevant (update, demo), rendered by one `renderBanners()` from state
instead of five independent loaders. The learning banner belongs in the stack too: it is global
information shown only on one tab today (`renderAlerts`, app.js 684–694).

**Proposed solution** *(effort: 2/10)*

One `<div id="banner-stack">` replaces `#maint-banner`, `#demo-banner`, `#update-banner`
(index.html 46–48), `#learning` (91), `#license-banner` (171) and `#rule-suggestion-banner`
(414). In app.js: `state.banners = new Map()`, `setBanner(key, { text, tone, priority,
dismissible, action })`, `clearBanner(key)`, and `renderBanners()` which sorts by priority and
writes the stack with `patchRows`-style keys (finding 4) so a banner that did not change is not
re-rendered. Producers keep their loaders and just call `setBanner`/`clearBanner`:
`loadMaintenanceBanner` → `maintenance` (10, warn, not dismissible, action *End silence* for
admins), `renderLicenseBanner` → `license` (20, warn or danger, not dismissible),
`loadUpdateBanner` → `update` (30, info, dismissible, action *Update…*), `loadDemoBanner` →
`demo` (40, info, dismissible), the learning/detecting text from `renderAlerts` 684–694 →
`learning` (50, info, dismissible, shown on every tab), rules.js → `rule-suggestion` (60, info,
dismissible). NAC's "{n} ports disabled by DENIS" (finding 17) becomes `nac` at 15, warn, not
dismissible. Dismissal is `sessionStorage['denis-dismissed'] = { key: text }` — keyed with the
banner's *text*, so a new version number or a changed demo message reappears. The stack shows at
most two banners plus a "1 more" toggle; maintenance and license are never collapsed. The
`.banner`, `.banner-warn`, `.banner-info` classes collapse into `.banner.<tone>` on tokens.

### 8. The global toolbar strip is shown on every page, mostly empty

`#assets-toolbar` (index.html 92–124) sits above `<main>` and `setTab` (app.js 1697–1707) hides
its controls individually per tab. The `.toolbar` `div` itself is never hidden, so every non-Devices
page renders a 10 px-padded empty strip (plus the Trends range select or the site filter, floating
alone). The Alerts page has a second, local `.table-tools` row for its own controls, the Dashboard
has `#dash-toolbar`, OT has `#ot-devices-toolbar`: three toolbar patterns for one job. The
Columns-button placement contract in `tables.js` (175–195) and the two contradictory comments in
style.css (526–527) about where that button "sits" are symptoms of the same missing rule; the
changelog has three releases (2.13.0–2.13.2) fixing placements.

**Firm recommendation.** Every page owns its toolbar inside its `<section>`; the shared site
filter becomes a small control the three pages that use it (Devices, Topology, Trends) each
mount. One `pageToolbar(section, {left, right})` helper, and `tables.js` always mounts the
Columns button into the page's toolbar `right` slot.

**Proposed solution** *(effort: 3/10; the risk is selectors, not logic)*

*HTML.* `#assets-toolbar` (index.html 92–124) moves inside `#view-assets` as its first child
and keeps every id (the smoke test and `applyHash('review')` use `#only-review`, `#search`,
`#add-asset`). `#range` moves into `#view-trends`. `#alerts-tools` is already inside
`#view-alerts`; `#dash-toolbar`, `#ot-devices-toolbar`, `#channels-toolbar`,
`#reports-toolbar`, `#rex-table-tools` get the same class. Every toolbar becomes
`<div class="toolbar"><div class="left">…</div><div class="right">…</div></div>` — one CSS
rule, `justify-content: space-between`, replaces `.spacer`.

*The site filter.* `#site` is used by Devices, Topology and Trends. It becomes a factory
`siteFilter()` returning a `select.site-filter` bound to `state.site` (`onchange` sets
`state.site` and calls the current tab's renderer); each of the three sections mounts one in its
toolbar's `left` slot. `renderSiteFilter` fills every `.site-filter` from the same option list
(the `dataset.sig` skip it already has). `inSite(a, state.site)` replaces `$('site').value`.

*`setTab`.* Lines 1697–1705 (the eight per-control show/hide statements) are deleted; a
section's toolbar is hidden with its section. `$('learning')` handling goes with finding 7.

*`tables.js` contract.* `enhanceTable` stops looking for `data-cols-host` /
`.table-tools` / `.inline-form` (175–195): the Columns button and menu always go to
`table.closest('section').querySelector('.toolbar .right')`, appended last. Remove
`data-cols-host` and `data-cols-after` from index.html and the two contradictory comments at
style.css 526–527; the one rule is "Columns is the last item on the right of the page's
toolbar". `#assets-table-cols-btn` keeps its id.

### 9. Sidebar counts and badges do not mean the same thing

Devices shows `(shown/total)` in a grey `.count`; Sites shows `(n)`; Alerts, Findings **and
Health** show a red `.badge` (style.css 129, one colour, `#dc2626`). "3 unacknowledged alerts"
and "3 health problems" (one of which may be "no recent backup") look identical, and a viewer
who cannot act on either sees the same red. Nothing distinguishes *informational* counts from
*needs attention*.

**Firm recommendation.** Grey count for information (Devices, Sites, Findings-total), red badge
only for open alerts, amber for Health warnings; hide the Health badge when the only warning is
advisory. This is a one-line class change per badge once the amber token exists (see
DESIGN_LANGUAGE.md).

**Proposed solution** *(effort: 1/10, plus 1/10 if the server has to classify warnings)*

CSS: `.badge` (style.css 129) keeps the danger fill; add `.badge.warn` (`--warn` fill,
`--text` on it in light, or `--warn-text` on a 20 % tint in dark) and leave `.count` grey.
`#count-alerts` stays `.badge`. `#count-findings` becomes `.count` showing non-info findings
(`findings.js` 29–31 already computes `n`). `#count-health` becomes `.badge.warn`, and
`loadHealthBadge`/`loadHealth` (health.js 10–24) count only warnings whose `level !==
'advisory'`. Whether `/api/system` warnings carry a level must be checked in `src/`; if not,
each warning producer gains `level: "advisory" | "warning"` ("no recent backup" and "demo data
loaded" are advisory; disk, capture and export failures are warnings). The collapsed sidebar's
8 px dot (already implemented) follows the same class. No i18n change.

### 10. Row and header interactions are mouse-only

Every data row opens its object via `el('tr', { onclick })` (Devices, Alerts, Events, OT, the
MSP overview, the exceptions table) with no `tabindex`, no `role`, no key handler; sortable
headers (`th[data-sort]`) are clickable `th`s with `cursor: pointer` but are not focusable.
Keyboard users can reach the row checkbox (Devices, Alerts) and the action buttons, but not the
row itself. The donut segments got this right (`tabindex="0"`, `role="button"`, Enter/Space —
app.js 889–891), so the pattern exists.

**Firm recommendation.** Make the first text cell of each row a `button.link-cell` (the class
already exists, style.css 264) and the sort headers `<button>`s inside the `th`; add
`aria-sort` on the sorted header. Cost: a few lines in each renderer; benefit: the whole console
becomes keyboard-operable, which a security product sold to enterprises will be asked about.

**Proposed solution** *(effort: 2/10)*

*Rows.* A helper `rowLink(text, onOpen)` in app.js returns `el('button', { type: 'button',
class: 'link-cell', text, onclick: (ev) => { ev.stopPropagation(); onOpen(); } })`. In each
renderer the first text cell wraps its content in it: Devices → the name cell (app.js 380), or
the IP when there is no name; Alerts → the summary (562) and the group header summary (641);
Events → the summary (842); MSP overview → the site name; the exceptions table → the device
name. The row's own `onclick` stays for mouse users clicking anywhere in the row. `.link-cell`
(style.css 264) already exists; it gets `text-align: left; font: inherit` so a long summary
wraps like the cell did. Tab order then goes checkbox → link → actions, row by row.

*Sort headers.* `th[data-sort]` content becomes `<button type="button" class="sort-btn">Label
<span class="caret"></span></button>`; the `th.onclick` handlers at app.js 1769–1787 (and the
software table's) move onto the button. `renderAssets`/`renderAlerts` set `th.setAttribute(
'aria-sort', asc ? 'ascending' : 'descending')` on the sorted column and remove it from the
rest where they already toggle `.sorted`/`.asc`. `tables.js` `headText` (line 27) reads text
nodes only; it must read the button's text instead (one line), or the column menu shows blank
labels. `tools/ui-smoke.mjs` gains one tab-through: Devices, `Tab` ×3, `Enter`, assert
`#detail` is visible.

### 11. Terminology drifts between pages

*Room* (Devices column, group-by, filters, `room:` search key) vs *Location* (editor field
label, detail panel, CSV column `location`, and a second search key `location:`). *Sites* (menu,
page) vs *agent* (token form, deep links `#agents`, API). *New Rule* (the button that creates a
**watch**, rules.js 410 and 547) vs *watch* everywhere else on that page and in the docs. The
Health page calls itself "Is DENIS itself in good shape?", the menu groups it under *Manage*. The
Ask DENIS answer footer says "Based on {n} alert(s)" even for a destination hunt, whose matches
are baseline rows, not alerts (app.js 1041; AI.md step 10).

**Firm recommendation.** One word per concept, chosen once: *Location* (drop *Room*; keep the
`room:` search alias silently), *Site* in the UI with "agent" only in the token/CLI context,
*Watch* for the button. Fix the Ask DENIS footer to "Based on {n} match(es)". All are string
changes plus the `tools/i18n` table.

**Proposed solution** *(effort: 1/10)*

A grep-driven pass, no structure: index.html 102 ("Group by room" → "Group by location"), 184
(bulk edit "Room" → "Location"), 208 (column header "Room" → "Location"); `matches()` in app.js
keeps `room:` as an alias of `location:` with no mention in the search-help popover; rules.js
410 and 547 ("New Rule" → "New watch"); the Health intro sentence stays but the sidebar group
label question is answered by leaving Health under *Manage* (it is where an admin goes to fix
things). "Sites" stays as the page and menu word; the token form keeps "agent id" because it
is the value the CLI takes — add "(the site's agent id)" to its placeholder. Ask DENIS footer
(app.js 1041): `tr('Based on {n} match(es)')`. Then `tools/i18n` for the five languages and a
grep of `docs/` for "room". No server change: the CSV column and API field are `location`
already.

### 12. Empty and first-run states are uneven

Good: Devices (`#empty`), Alerts (`#no-alerts`), OT (`#ot-empty`), Software, Findings,
Reports, Channels, the physical topology's "Add a switch…" call to action. Missing: Events
(an empty `<tbody>` and nothing else), Audit log (same), Trends with no samples (eight chart
cards each saying "No samples yet" instead of one sentence), the logical Topology on an empty
install (an empty SVG), Compliance before the first sweep (percentages of zero). The Dashboard's
twelve KPI tiles all read "0" on a fresh install with no hint about the learning period.

**Suggestion.** One `emptyState(icon, sentence, action?)` helper and one sentence per page;
on the Dashboard, replace the tiles with the setup guide's remaining steps until the first
device exists.

**Proposed solution** *(effort: 2/10)*

`emptyState(iconName, sentence, action)` in app.js returns `<div class="empty">` with a 40 px
`icons.js` glyph in `--text-3`, the sentence in `--text-2`, and an optional secondary button.
The eight existing `p.muted[hidden]` empties (`#empty`, `#no-alerts`, `#ot-empty`,
`#software-empty`, `#no-findings`, `#no-reports`, `#no-channels`, `#no-backups`) keep their ids
and become `emptyState` output built once at load from their current text, so every existing
`hidden` toggle keeps working. New ones: Events (`renderEvents` when `state.events` is empty:
"Nothing has happened yet. Events appear as devices join, change or talk to something new."),
Audit (`drawAudit` with no rows: "No entries yet", or "No entries match" when filtered), Trends
(`loadTrends`: one `emptyState` in place of eight "No samples yet" cards when every series is
empty), logical Topology (`renderTopology` with no devices: the same sentence as Devices plus a
*Load demo data* action for admins), Compliance before the first sweep (`loadCompliance` when
the measures are all zero: "Compliance is measured after the first full sweep."). Dashboard:
`renderDashboard` when `state.assets.length === 0` renders the setup guide's remaining steps
(setup.js already fetches and judges them for `openSetupGuide`; expose that list) in place of
`#dash-cards`, with the learning-period sentence under it. Six new `tr()` strings.

### 13. The header status line is a 12 px sentence that wraps

`renderStatus` (app.js 1134–1156) writes "mode master · iface eth0 192.168.1.0/24 · devices 42
· sweep 3m ago · frames 12345 · syslog ok 12s ago" plus a note and any export error into a
muted 12 px `flex: 1` element; with a long interface name, two exports and a German label set it
wraps to two or three lines and pushes the header's buttons down (`flex-wrap: wrap`, style.css 21).
Almost all of it is on the Health page too.

**Suggestion.** Keep a single status dot + "sweep 3m ago" + one export health pill in the
header, with the full sentence as its tooltip and on Health. Move *Scan now* next to it.

**Proposed solution** *(effort: 1/10)*

`renderStatus` (app.js 1134–1156) renders into `#status` a single `.status-pill`: a dot
(`--ok` at rest; `--accent` with a 1.5 s breathing animation while `s.sweeping`; `--danger`
when any export has `last_error`; `--warn` when `passive_only`), then "sweep 3 m ago" (or
"sweeping…", "passive only"), then — only when an export is configured — one more pill
"syslog ok" / "export FAILING". The full sentence it builds today goes into the pill's `title`
and into a `#health-status-line` on the Health page (`loadHealth` already has the same data).
`s.notes[0]` and export errors, which are actionable, move to the banner stack (finding 7) as
`status-note` (priority 45, warn). `#scan` moves right after the pill in the header markup.
`.status` loses `flex: 1; min-width: 200px` (the cause of the wrap) and the header's
`flex-wrap` stays only for phone widths. Verify in German at 1024 px.

### 14. The Ask DENIS panel overlaps the device panel and the column menus

`.ask-denis-panel` is fixed bottom-right at `z-index: 40` (style.css 334); `#detail` is fixed
right with no z-index of its own (style.css 118), so an open device panel is covered by the Ask
DENIS box in its lower 520 px, including the *Change history* section. The `.cols-menu` (z 20)
and the sidebar (z 30) sit under it too.

**Suggestion.** Dock the panel to the left of `#detail` when the detail panel is open, or make
it a bottom sheet on narrow screens; give `#detail` an explicit z-index in the same scale.

**Proposed solution** *(effort: 1/10, CSS plus one class toggle)*

Tokens `--z-menu: 20; --z-sidebar: 30; --z-panel: 35; --z-ask: 40;` in `:root` (dialogs use
the top layer and need none). `#detail` gets `z-index: var(--z-panel)`. `showDetail` adds
`body.detail-open`; the close handler removes it. `.ask-denis-panel` gets `right: calc(min(440px,
100vw) + 16px)` under `body.detail-open` at widths ≥ 960 px (and `+ 520px` where finding 5
widens the panel), so it docks beside the device panel instead of over it. Below 960 px it
becomes a bottom sheet: `left: 0; right: 0; bottom: 0; width: auto; max-height: 50vh;
border-radius: 12px 12px 0 0`, and `#detail` stays full-width above it. `.cols-menu` moves to
`--z-menu`; nothing else changes.

### 15. Alerting: the "Add a channel" form is a permanent ten-kind form at the foot of the page

`#channel-form` (index.html 317–348) is always rendered, with `syncChannelForm` showing and
hiding rows for the selected kind; the SMTP block alone is seven fields. The channels table above
has *Test / Enable / Delete* per row, an inline min-score input, and no *Edit* — to change a URL
you delete and re-add (docs/alerting.md says so). The Slack help text lives in a `<p>` under the
form and changes with the kind, so it is often off-screen.

**Suggestion.** *Add a channel…* opens `openForm` with the kind-specific fields and the help
text at the top; the table gains *Edit…* for name/min-score/secret-rotation (the API already
accepts `PUT /api/channels/{id}` partials).

**Proposed solution** *(effort: 3/10; same shape as finding 1, smaller)*

A `CHANNEL_KINDS` table in admin.js — `{ slack: { label, help, fields: [['url', 'Webhook URL',
'url']] }, teams: …, email: { fields: [host, port, security, user, pass(secret), from, to] },
… }` — replaces `syncChannelForm` (admin.js 910) and the permanent `#channel-form` (index.html
317–348), which is deleted along with `#ch-help`. `openChannelForm(existing)` builds
`openForm` with: the kind `select` (disabled when editing), the help paragraph for that kind at
the top (re-rendered on kind change), *Name*, the kind's fields, *Send alerts scoring at least*.
For an existing channel the secret fields show "(unchanged)" and are sent only when filled —
`PUT /api/channels/{id}` already accepts partials. The channels table gains *Edit…* and loses
the inline min-score input (it moves into the dialog, which also removes an in-row control from
finding 4's scope). *Add a channel…* is a primary button in the Channels toolbar (finding 8).
`docs/alerting.md`'s "delete and re-add" sentence goes.

### 16. Small text carries meaningful information

`.small` is 12 px (style.css 269) and `.muted.small` is used for exact timestamps under relative
ones (alerts), exception notes ("why this exception exists"), CMDB match lines, the reverse-DNS
hostname under every IP, the EPSS sentence in findings evidence, and most settings hints. At the
console's 14 px base that is 86 % size in a muted colour: readable, but it is where the
explanations — the product's differentiator — end up.

**Suggestion.** Reserve 12 px for genuinely secondary metadata (timestamps, counts) and set
explanatory hints at 13 px in `--text-2` (see the type scale in DESIGN_LANGUAGE.md).

**Proposed solution** *(effort: 1/10, after DESIGN_LANGUAGE.md step 1 lands the tokens)*

Add one class, `.hint { font-size: var(--fs-sm); color: var(--text-2); }`, and reclassify by
hand: `grep -n 'muted small' ui/*.js ui/index.html` (about 60 hits). Explanations become `.hint`
— the `why` line under alert summaries (app.js 563), exception notes, CMDB match lines, the
EPSS sentence in findings evidence, every settings hint paragraph in index.html, the
"(unchanged)" secret-status lines. Metadata stays `.muted.small` — exact timestamps under
relative ones, `(you)`, counts, "read 4 m ago". Half a day of judgement calls, no logic.

### 17. What NAC.md will need from the UI that does not exist yet (checklist)

Collected here because NAC.md is the next large UI-affecting item and each of these is
cheaper before it than during it:

* A disclosure component (finding 2) for the switch form's write-community section.
* A chip/badge with tone variants — `.chip` (style.css 381, 411) has no colour variants; only
  `.pill.ok/.bad/.warn` do — for "Read only" / "Port control" / "Port control (off)" on switch rows.
* An action column and a state column in the per-switch port table (`portTable`, switches.js
  92–106: three cells, no actions) for *Disable…* / *Enable* and "Disabled by DENIS · who · when".
* The danger form (finding 2) with password + required reason + acknowledgement checkbox that
  gates submit, and a *refusals* rendering (a list of sentences, no submit button).
* A non-event notification surface in the header/health area for "n ports disabled by DENIS"
  (`#health-warnings` `.banner-warn` is the precedent, health.js 25–27).
* `summarizeAudit` (admin.js 815–819) turning `nac.*` entries into sentences; today unknown
  actions print `key=value` pairs.

**Proposed solution** — item by item, so NAC.md's "Where an action starts" and "Making it
louder" sections have a UI piece to land on. Checked against NAC.md §4–§7 and "What the user
is told", not only against the generic complaint.

* *Disclosure for the write community* — finding 2 (a), including the closed-`details` /
  `required` caveat and the "Remove port control" path that warns when ledger rows exist.
* *Chip tones* *(effort: 1/10)* — `.chip.ok`, `.chip.warn`, `.chip.danger`, `.chip.off` on the
  status tokens (`*-text` colour on a 14 % tint, as `.sev` will be after DESIGN_LANGUAGE.md),
  and a `chip(text, tone)` helper. Each switch row in `loadSwitchesBox` (switches.js 134) shows
  `chip('Read only', 'off')`, `chip('Port control', 'warn')` when `write_community_set &&
  nac.enabled`, `chip('Port control (off)', 'off')` when set but the global switch is off — the
  three states NAC.md names.
* *Port table with state and actions* *(effort: 2/10; depends on finding 4's `patchRows`)* —
  `portTable` (switches.js 92–106) becomes a real table with a `thead` (*Port*, *Link*,
  *Device*, *Admin state*, and an actions column for admins) and keyed rows (`'p:' + switch.id
  + ':' + p.ifindex`), rendered inside finding 2's `disclosure()`. *Admin state* shows "up",
  "down (on the switch)", or `chip('Disabled by DENIS', 'warn')` plus "· {who} · {when}" from the
  ledger data NAC.md says the topology response will carry. The actions cell shows *Disable…*
  under exactly NAC.md's four conditions (admin, switch has port control, global switch on, not
  an obvious uplink) and *Enable* on DENIS-disabled ports. Because the rows are keyed, a poll
  during the plan dialog does not rebuild the table under the person — the reason this finding
  said NAC "will not be affected" only by accident of `renderPhysical` running on tab change.
  The same *Disable this device's switch port…* button goes into the device panel's *Overview*
  section next to "Connected to" (finding 5).
* *The plan/confirm dialog* — finding 2 (b) as specified: `items` = affected devices plus the
  unknown-MAC count, `refusals` (no submit button when present), `warnings` with the mandatory
  acknowledgement, `requirePassword`, `requireReason` (3–200 chars), and the outcome shown with
  `showMessage` for "unconfirmed" (with its *Check now* button) since it is a result the person
  must read. *Enable* uses the same function with `intro` only, no password (NAC.md §6).
* *The non-event notification surface* — finding 7's banner stack, key `nac`, priority 15
  (under maintenance, above license), warn tone, not dismissible, text "{n} switch ports are
  disabled by DENIS", action *Show* → `#topology/physical`. It is fed from the same `/api/system`
  warnings list NAC.md proposes (so the Health badge — finding 9, amber — counts it too), and
  the "Disabled by DENIS" list at the top of the physical view is a `.card` (DESIGN_LANGUAGE.md
  §5.1) with keyed rows and *Enable* buttons.
* *Audit sentences* *(effort: 1/10)* — `summarizeAudit` (admin.js 815) gains an
  `AUDIT_SENTENCES` map keyed by action, tried before the `key=value` fallback: `'nac.disable':
  (d) => tr('disabled port {port} on {sw} — {outcome}; reason: {reason}', …)`, `'nac.restore'`,
  `'nac.plan.refused'` (lists the refusal codes as words), `'nac.disable.denied'`, `'nac.drift'`.
  The same map is where the existing `settings.*`, `user.*` and `token.*` actions can get
  sentences later, one line each.

## Where the console theme picker lives

Stefan's decision (2026-09-30): the current look and the three directions in
DESIGN_LANGUAGE_ALTERNATIVES.md — *Ink*, *Deep Field*, *Workbench* — all ship as user-selectable
looks, each with a light and a dark variant, eight palettes in all. He asked where that picker
belongs from a UX standpoint. This section answers it with one firm recommendation and says what
was rejected and why; the visual content of the four looks stays in the two design documents.

### First, what a "look" can and cannot be

A switchable look is **CSS only**: colour tokens, type scale (including a self-hosted font),
radii, elevation, control styling, motion budget. It is applied by one attribute on `<html>` and
the DOM is the same under every look. That rules some things *out* of the looks as
DESIGN_LANGUAGE_ALTERNATIVES.md drew them, and the queue has to be honest about it:

* Deep Field's 13 px body and 36 px rows fit (they are tokens). Its *Comfortable / Compact*
  density toggle, its starfield canvas and its actions-on-hover rows do not: they are separate
  features (the starfield already has its own flag and toggle in that document) and are not part
  of choosing Deep Field.
* Workbench's warm palette, Madefor font, 12 px card radius and resting shadows fit. Its
  pan/zoom topology canvas, card-shaped devices and alerts-as-cards do not: those change the DOM
  and would break `tables.js`, bulk selection and the smoke test under one look only. They stay
  where the alternatives document put them — "if the Topology page ever becomes the product".
* Ink's black primary button fits, *provided* the operator accent is decoupled from the button
  (see "Branding" below). Its orbit/pulse/skeleton motion module is CSS keyframes on existing
  elements and fits.

So a look is exactly: the token table from Part 2 of the alternatives document, the font, and
CSS-only motion. Everything structural is a feature with its own item.

### Recommendation

**The header's theme button (`#theme`, index.html 39, today a three-state cycle ◐ / ☀ / ☾)
becomes an *Appearance* popover with two controls: a segmented *Auto / Light / Dark* on top and
four radio cards for the look under it.** Nothing else moves; there is no new Settings section
for the personal choice, and no duplicate of the control on the account page.

Concretely:

* **Control.** Clicking `#theme` opens a `.cols-menu`-style popover anchored under it (the
  filters and search-help menus are the precedent: outside-click and `Escape` close it, it is
  `role="dialog"` with a label). Row one: a `.segmented` with `role="radiogroup"` — *Auto*,
  *Light*, *Dark* — the same three values `THEMES` has today. Under it, four
  `label.look-card` radio cards in one column: the look's name in bold, one line under it ("the
  console as it is today" / "monochrome, colour only where it means something" / "dark-first,
  dense, for a wall screen" / "warm, rounded, friendly"), and on the right a 5-swatch strip
  (canvas, surface, text, accent, danger) **drawn from that look's tokens in the scheme currently
  selected in row one** — pick *Dark* and all four strips redraw dark. The card for the active
  look is outlined in `--accent`. The button's own glyph shows the scheme (◐ / ☀ / ☾) as today,
  so the header does not change width.
* **Live preview is the console itself.** Choosing a card applies the look immediately (it is
  one attribute), the popover stays open so the person can click through all four while looking
  at the page behind it, and the choice is saved on each click — there is no *Apply*, nothing to
  cancel, and going back is one more click. This is the argument for the header over a page: the
  person compares looks against the data they were reading, not against a settings form.
* **Two axes, kept separate.** Look and scheme are independent. Picking *Deep Field* does **not**
  flip the scheme to dark; the person's *Auto* stays *Auto* and follows the OS, as it does today.
  The reasons: a silent flip overwrites a choice the person made; the person who does want dark
  is one click away in the same popover; and a look that forced a scheme would need a way back
  when switching looks again. Deep Field's card says "best in dark" in its one-line description,
  and that is all the steering it gets. The same rule the other way: no look is light-only.
* **Keyboard.** The popover opens on `Enter`/`Space` on `#theme`, focus moves to the active
  segment, arrow keys move within each radiogroup, `Tab` between the two, `Escape` closes and
  returns focus to the button. Cards are real radio inputs, so this costs nothing.

### Why not the two other places

* **Settings.** `#tab-settings` is hidden for anyone but an administrator (admin.js 213). A
  viewer or editor — the people who sit in front of the console most — could never pick a look.
  Settings is right for the *operator default*, not the personal choice.
* **My account** (`#view-account`, reached from the `#account` button). It is visible to every
  role and it is where language could also live, so it is defensible. It loses on two counts:
  the theme control already exists in the header and people have learned it is there, so a
  second place to look is a cost with no benefit; and a page cannot give the live preview — the
  person sees the look applied to the account page, the least representative screen in the
  console. If a second surface is ever wanted, it is one line on the account page ("Appearance:
  Deep Field · Dark — change") that opens the same popover; do not build a second control.

### Mechanics

* **DOM.** `data-theme` on `<html>` stays as it is (absent / `light` / `dark`, admin.js 88–93).
  A second attribute `data-look` (`classic` / `ink` / `deep-field` / `workbench`) is added by
  `applyLook(l)`. Stored in `localStorage['denis-look']` next to `denis-theme`, read in
  `initTheme` with the same fallback chain: browser choice → operator default → `classic`.
* **CSS.** After DESIGN_LANGUAGE.md step 1 (tokens with the shared names) lands, each look is
  two blocks: `:root[data-look="ink"] { …light tokens… }` and the dark tokens under the two
  selector shapes the file already uses (`@media (prefers-color-scheme: dark)
  :root[data-look="ink"]:not([data-theme="light"])` and `:root[data-look="ink"][data-theme=
  "dark"]`). `classic` is the default block and needs no selector. Eight blocks of ~20 lines,
  one file, no JS beyond the attribute. Any selector outside `:root` that still uses a hex
  colour is a bug under every look but classic — DESIGN_LANGUAGE.md §1 already lists the
  seventeen to fix, and the topology colour maps in app.js 1357/1397 and switches.js 49 are the
  three JS ones.
* **Fonts.** Ink, Deep Field and Workbench each name a self-hosted font in `@font-face` under
  `ui/fonts/` (OFL text into `THIRD-PARTY-LICENSES.md`). Browsers fetch a font only when a
  rendered element uses it, so declaring all three costs nothing at runtime until a look is
  chosen; the cost is binary size, roughly +0.7 MB for three families subsetted to the five
  languages, and the Slovak glyph check per family from the alternatives document. `font-display:
  swap` so no look ever blocks on its font. A *Use system font* checkbox at the foot of the
  popover (stored as `denis-font: system`) is the cheap escape hatch that document already asks
  for under Ink; it applies to every look.
* **Branding.** `applyBranding` (admin.js 119–121) writes `--accent`/`--accent-text` inline on
  `<html>`, which would override every look. Change it to write `--brand` and `--brand-text`
  instead, and let each look's block decide what the operator colour drives: classic, Deep
  Field and Workbench set `--accent: var(--brand, <look default>)`; Ink sets `--link: var(--brand,
  #0067d6)` and keeps `--accent` black/white. The `--accent-soft`/`--accent-line` tints derive
  as before. Settings → Branding gains a second row of the existing *Default theme* control:
  *Default look* (four options) beside *Default colour scheme* (the current select, renamed),
  stored as `look_default` next to `theme_default` in `src/branding.rs` (the same validation
  pattern, lines 94–99) and read by `initTheme` from `/api/branding` before sign-in. The
  contrast warning under 3 : 1 that DESIGN_LANGUAGE.md suggests for the accent picker becomes
  firm here, checked against the *default look's* surface in both schemes.
* **Sign-in page and reports.** The login card uses the same `style.css`, so it follows the
  operator default look; the printed report (`report.rs`) has its own CSS and is untouched by
  looks — say so in the release note rather than re-theming it four times.
* **Verification.** `tools/screenshots.py` takes Devices, Alerts and Settings → Switches under
  all eight palette combinations in one run, and the contrast table in each look's section of
  the alternatives document is re-measured with the operator accent substituted. `ui-smoke.mjs`
  opens the popover, picks each look, and asserts `data-look` and the `localStorage` value.

### Effort and order

**4/10** for the mechanism (popover with cards and swatches, `applyLook`, `data-look` blocks for
all four looks with the token tables already written, `--brand` split, branding default,
fonts and licences, screenshots) — *after* DESIGN_LANGUAGE.md step 1, which is the
prerequisite that makes "a look is a token block" true. Ship in two steps: Classic + Ink first
(Ink is the superset of the incremental path and needs the branding split, which is the only
JS risk), then Deep Field and Workbench as pure CSS additions. The structural extras those two
directions describe stay separate items on the queue with their own flags.

## Prioritised list

**P1 — do before the next UI-heavy feature (NAC):**

1. Disclosure component + danger-confirmation form; migrate the five existing dangerous actions
   and the destructive `confirm()`s (findings 2, 3, 17).
2. Poll-safe rendering for Alerts, Devices, Events and the device panel (finding 4).
3. Settings → Integrations as a source list with per-source status and a dialog form (finding 1).
4. Non-modal notice for "Saved." and inline results (finding 3).

**P2 — structural, each a contained change:**

5. Device panel: sticky header and three sections (finding 5).
6. Asset editor fieldsets (finding 6).
7. Banner stack with priority and dismissal (finding 7).
8. Per-page toolbars and a Columns-button contract (finding 8).
9. Keyboard-operable rows and sort headers (finding 10).
10. Badge semantics (finding 9) and terminology (finding 11).

**P3 — polish:**

11. Empty states (finding 12), header status line (13), Ask DENIS docking (14), Alerting form
    in a dialog with row edit (15), text sizes for explanations (16).

**Dependency order for the queue (added 2026-09-30).** The solutions above lean on four shared
pieces, so build those first and the rest become short changes: (1) DESIGN_LANGUAGE.md step 1
— tokens — is a prerequisite for findings 9, 16, the chip tones in 17 and the theme picker;
(2) `disclosure()` and `openDangerForm()` (finding 2) are used by 3, 6 and 17; (3) `patchRows`
(finding 4) is used by 5, 7, 17's port table and any table that gains an in-row control;
(4) the banner stack (finding 7) is used by 13 and 17. Finding 1 and finding 15 share the
"registry + `openForm` dialog" shape and should be done back to back. The theme picker sits
after (1) and is otherwise independent of everything on this list. Summed effort for all
seventeen plus the picker is about 45 points on the 1–10 scale, or roughly seven to nine
working weeks for one person; the P1 block alone (2, 3, 4, 1) is about 16 points.

## What this review did not do

It did not run the console in a browser or measure anything on a real screen; every finding is
from the source. It did not review the printed report (`report.rs` HTML) or the sign-in page
beyond its markup. It did not review translations. Where a fix is called "firm", that is a
judgement that the problem is real and the fix is cheap and contained; where it is a
"suggestion", the problem is real but the fix is a taste or priority call for Stefan.
