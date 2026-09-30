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

### 13. The header status line is a 12 px sentence that wraps

`renderStatus` (app.js 1134–1156) writes "mode master · iface eth0 192.168.1.0/24 · devices 42
· sweep 3m ago · frames 12345 · syslog ok 12s ago" plus a note and any export error into a
muted 12 px `flex: 1` element; with a long interface name, two exports and a German label set it
wraps to two or three lines and pushes the header's buttons down (`flex-wrap: wrap`, style.css 21).
Almost all of it is on the Health page too.

**Suggestion.** Keep a single status dot + "sweep 3m ago" + one export health pill in the
header, with the full sentence as its tooltip and on Health. Move *Scan now* next to it.

### 14. The Ask DENIS panel overlaps the device panel and the column menus

`.ask-denis-panel` is fixed bottom-right at `z-index: 40` (style.css 334); `#detail` is fixed
right with no z-index of its own (style.css 118), so an open device panel is covered by the Ask
DENIS box in its lower 520 px, including the *Change history* section. The `.cols-menu` (z 20)
and the sidebar (z 30) sit under it too.

**Suggestion.** Dock the panel to the left of `#detail` when the detail panel is open, or make
it a bottom sheet on narrow screens; give `#detail` an explicit z-index in the same scale.

### 15. Alerting: the "Add a channel" form is a permanent ten-kind form at the foot of the page

`#channel-form` (index.html 317–348) is always rendered, with `syncChannelForm` showing and
hiding rows for the selected kind; the SMTP block alone is seven fields. The channels table above
has *Test / Enable / Delete* per row, an inline min-score input, and no *Edit* — to change a URL
you delete and re-add (docs/alerting.md says so). The Slack help text lives in a `<p>` under the
form and changes with the kind, so it is often off-screen.

**Suggestion.** *Add a channel…* opens `openForm` with the kind-specific fields and the help
text at the top; the table gains *Edit…* for name/min-score/secret-rotation (the API already
accepts `PUT /api/channels/{id}` partials).

### 16. Small text carries meaningful information

`.small` is 12 px (style.css 269) and `.muted.small` is used for exact timestamps under relative
ones (alerts), exception notes ("why this exception exists"), CMDB match lines, the reverse-DNS
hostname under every IP, the EPSS sentence in findings evidence, and most settings hints. At the
console's 14 px base that is 86 % size in a muted colour: readable, but it is where the
explanations — the product's differentiator — end up.

**Suggestion.** Reserve 12 px for genuinely secondary metadata (timestamps, counts) and set
explanatory hints at 13 px in `--text-2` (see the type scale in DESIGN_LANGUAGE.md).

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

## What this review did not do

It did not run the console in a browser or measure anything on a real screen; every finding is
from the source. It did not review the printed report (`report.rs` HTML) or the sign-in page
beyond its markup. It did not review translations. Where a fix is called "firm", that is a
judgement that the problem is real and the fix is cheap and contained; where it is a
"suggestion", the problem is real but the fix is a taste or priority call for Stefan.
