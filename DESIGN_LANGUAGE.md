# A design language for the console: proposal

A proposal, not a re-skin. Nothing in `ui/` was changed for it. It is written against the CSS as
it is in this worktree (`ui/style.css`, 565 lines, v2.51.0) and with the same bar as
[NAC.md](NAC.md): what is a firm recommendation is marked as such, what is a taste call is marked
as a suggestion, and every number that can be checked (contrast ratios, sizes) was checked, not
guessed. "Expensive software" here means three concrete things: a consistent tonal scale instead
of ad-hoc greys, a visible hierarchy of surfaces and text, and controls that respond in the same
way everywhere. It does not mean gradients, glassmorphism or a new font.

## Where the console is today

`:root` defines ten custom properties — `--bg`, `--panel`, `--text`, `--muted`, `--line`,
`--accent`, `--accent-text`, `--ok`, `--off`, `--warn` — with a dark set under both
`@media (prefers-color-scheme: dark) :root:not([data-theme="light"])` and `:root[data-theme="dark"]`
(style.css 1–16). That structure is right and stays; everything below adds to it. The runtime
branding override sets only `--accent` and `--accent-text` (`applyBranding`, admin.js 119–121),
and every tint is derived with `color-mix(in srgb, var(--accent) N%, transparent)` (37 uses).
That, too, is right: an operator's accent keeps working with no further work.

What is *not* tokenised: red. `#dc2626` is hard-coded 17 times — 14 in style.css (badges,
`.sev.high`, `.form-error`, `.card.bad`, `.ring-high`, `.bar.alert`, `button.danger`,
`.pill.bad`, `.switch-node.down`, `.r-high`, `.legend-dot.high`, row tints) and 3 in JS
(topology risk colours, app.js 1357 and 1397; switches.js 49). Spacing uses a dozen distinct
values between 2 and 28 px with no scale. Radii come in ten sizes (1, 3, 4, 5, 6, 8, 9, 10, 12
px, 50 % and 999). Font sizes come in eleven (9, 10, 11, 12, 12.5, 13, 14, 15, 16, 20, 22 px).
Type is `system-ui` at 14 px / 1.4. Elevation is one of four hand-written `box-shadow`s.

Two measured accessibility defects (WCAG formula, sRGB):

| Today | Ratio | Used for | Verdict |
|---|---|---|---|
| `.ok-text` `#16a34a` on `#fff` | **3.30 : 1** | "Everything looks fine.", "An authenticator app is set up.", verify-fix *Fixed* pill | fails AA for text (4.5) |
| `#dc2626` on the dark panel `#171b21` | **3.58 : 1** | every `.form-error`, `.sev.high` text, `button.danger`, `.pill.bad` in dark mode | fails AA for text |

Everything else passes: `--muted` `#6a737d` on `#f7f8fa` is 4.53, `--accent` `#2563eb` on white
5.17, `--warn` `#b45309` on white 5.02, dark `--muted` 5.69, dark `--accent` 6.69. The proposal
keeps every passing pair at or above its current ratio and fixes the two failures.

## 1. Colour tokens

**Firm recommendation.** Add a two-level surface scale, a two-level text scale, an explicit
danger colour and *text* variants for the three status colours. Keep the old names as aliases
for one release so nothing breaks (`--panel: var(--surface)`, `--line: var(--border)`, etc.), then
migrate selectors and drop the aliases.

```css
:root {
  /* surfaces: canvas, raised, inset */
  --canvas:   #f5f6f8;
  --surface:  #ffffff;
  --surface-2:#f0f2f5;   /* inset areas: code, secrets, table-header strip, hover */
  --border:   #e5e7eb;
  --border-2: #d1d5db;   /* stronger: focused inputs' resting border, dividers in dialogs */
  /* text: primary, secondary, tertiary */
  --text:     #15181d;
  --text-2:   #4b5563;   /* explanations, hints — replaces most of today's .muted */
  --text-3:   #6b7280;   /* timestamps, counts, metadata (today's --muted) */
  /* brand */
  --accent:      #2563eb;   /* unchanged; overridden at runtime by branding */
  --accent-text: #ffffff;   /* unchanged */
  --accent-soft: color-mix(in srgb, var(--accent) 12%, transparent);
  --accent-line: color-mix(in srgb, var(--accent) 35%, transparent);
  /* status: fill + text pairs */
  --ok:          #16a34a;  --ok-text:     #15803d;
  --warn:        #d97706;  --warn-text:   #b45309;
  --danger:      #dc2626;  --danger-text: #b91c1c;
  --info:        var(--accent);
  --off:         #9aa3ad;
  /* focus */
  --focus: var(--accent);
}
```

Dark, under the same two selectors as today:

```css
  --canvas:   #0b0e12;
  --surface:  #12161c;
  --surface-2:#1a1f27;
  --border:   #232a33;
  --border-2: #303945;
  --text:     #e8ebef;
  --text-2:   #b3bac4;
  --text-3:   #8a93a0;
  --accent:      #7aa7ff;
  --accent-text: #0b1220;
  --ok:          #22c55e;  --ok-text:     #4ade80;
  --warn:        #f59e0b;  --warn-text:   #f0b429;
  --danger:      #ef4444;  --danger-text: #f87171;
  --off:         #5b6570;
```

Measured contrast for text pairs (must be ≥ 4.5 : 1 for body text, ≥ 3 : 1 for large/bold and
for non-text UI):

| Pair | Light | Dark |
|---|---|---|
| `--text` on `--surface` | 17.8 | 15.2 |
| `--text-2` on `--surface` | 7.6 | 9.3 |
| `--text-3` on `--surface` / on `--canvas` | 4.8 / 4.5 | 5.8 / 6.2 |
| `--accent` on `--surface` (links, active tab) | 5.2 | 7.6 |
| `--accent-text` on `--accent` (primary button) | 5.2 | 7.8 |
| `--ok-text` on `--surface` | 5.0 (was 3.3) | 10.4 |
| `--warn-text` on `--surface` | 5.0 | 9.7 |
| `--danger-text` on `--surface` | 6.5 | 6.6 (was 3.6) |
| white on `--danger` fill (badges) | 4.8 | — (dark badges use `--danger-text` on a 20 % tint) |

Rules that follow from the split:

* Text is always a `*-text` token; fills, rings, bars and dots are the plain token. `.sev.high`
  becomes `color: var(--danger-text); background: color-mix(in srgb, var(--danger) 14%,
  transparent)`, which is what `.sev.medium` already does with `--warn`.
* `.muted` splits: hints and explanations (`.rule-card p.muted`, settings intros, "why this
  exception exists") become `--text-2`; timestamps, counts and `(you)` stay `--text-3`. This is
  the single change that most affects how "premium" the console reads, because today every
  explanation is the same grey as a timestamp.
* The topology and donut colours in JS (`colors = { none: 'var(--off)', … high: '#dc2626' }`)
  read `var(--danger)`; `.r-high`, `.ring-high`, `.legend-dot.high`, `.bar.alert`,
  `.card.bad`, `.badge`, `.form-error`, `button.danger` use the tokens. After this, no hex
  colour remains outside `:root`.
* Branding: an operator accent that fails 4.5 : 1 against `--surface` already gets a black or
  white `--accent-text` from the server; `--accent-soft` and `--accent-line` derive from it, so a
  pale accent produces pale tints, which is acceptable. **Suggestion:** warn in Settings →
  Branding when the chosen accent is under 3 : 1 against `--surface` in either theme, since it is
  also used for links and the active menu item, where it is text.

## 2. Type scale

**Firm recommendation.** Keep the system font stack. The console has no build step, ships as an
embedded binary with `default-src 'self'`, and a self-hosted variable font is 100–300 KB per
family for a gain that is mostly taste. Change the scale, not the face.

```css
  --font:      system-ui, -apple-system, "Segoe UI", Roboto, Inter, sans-serif;
  --font-mono: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
  --fs-xs: 12px;  --lh-xs: 16px;   /* metadata, badges, table headers (uppercase +.04em) */
  --fs-sm: 13px;  --lh-sm: 18px;   /* hints, explanations, dense table cells */
  --fs-md: 14px;  --lh-md: 20px;   /* body, controls, table cells */
  --fs-lg: 16px;  --lh-lg: 22px;   /* dialog and panel titles, section titles */
  --fs-xl: 20px;  --lh-xl: 26px;   /* page-level numbers (chart .big) */
  --fs-2xl: 26px; --lh-2xl: 30px;  /* KPI tiles, donut totals */
  --fw-medium: 500; --fw-semibold: 600;
```

Six sizes replace eleven. `9px`/`10px`/`11px` (SVG axis labels, navgroup, badges) round up to
12 px except inside SVG, where `font-size` is in viewBox units and stays. `12.5px` (`.mono`,
`.cols-btn`, `.talker-label`) becomes 13. Numeric columns (`th.num, td.num`) keep
`font-variant-numeric: tabular-nums`; add it to the KPI tiles, the risk score chips and the
alert score cell so columns of numbers align.

Section headings (`h3.section`, today 14 px regular weight, `#detail h3` 12 px uppercase) become
one style: `--fs-lg`, `--fw-semibold`, `--text`, `margin: var(--s-6) 0 var(--s-2)`; the
uppercase 12 px treatment is reserved for `.navgroup` and table headers, where it labels a group
rather than titles a section. **Suggestion:** letter-spacing `-0.01em` on the two largest sizes;
it is the cheapest "designed" signal there is and is invisible on body text.

## 3. Spacing, radius, elevation

**Firm recommendation.** A 4 px base and three radii; all existing values snap to the nearest
step (2 → 4, 6 → 4 or 8 by context, 10 → 8 or 12, 14 → 16, 18 → 16, 20 → 20, 24 → 24, 26 → 24,
28 → 32).

```css
  --s-1: 4px; --s-2: 8px; --s-3: 12px; --s-4: 16px; --s-5: 20px; --s-6: 24px; --s-8: 32px;
  --r-1: 6px;    /* inputs, buttons, chips (rectangular), small menus */
  --r-2: 10px;   /* cards, table wraps, banners, rule cards, findings */
  --r-3: 14px;   /* dialogs, the device panel, the Ask DENIS panel, the login card */
  --r-pill: 999px;
  --shadow-1: 0 1px 2px rgba(15, 18, 22, .06);                          /* resting controls */
  --shadow-2: 0 4px 12px rgba(15, 18, 22, .10), 0 1px 3px rgba(15, 18, 22, .06); /* menus, hover cards */
  --shadow-3: 0 16px 40px rgba(15, 18, 22, .22), 0 2px 8px rgba(15, 18, 22, .10); /* dialogs, side panels */
```

In dark mode shadows barely read, so elevation is carried by the surface step instead: dialogs
and the side panel use `--surface-2` with a `--border-2` edge and `--shadow-3` at `.5` alpha.
Cards stay `--surface` on `--canvas` with a `--border`, never a shadow at rest — the current
design already does this and it is the right call for a data-dense tool; shadows are for things
that float (menus, dialogs, the Ask DENIS panel, a card on hover).

The `#view-settings > div > * + *` margin rules (style.css 368–370) go away once every settings
box is a card with its own internal `gap: var(--s-3)`.

## 4. Controls

**Firm recommendation.** One control height and four button tones.

* Height 32 px for every input, select, button and toolbar checkbox (`padding: 6px 12px` at
  20 px line-height, border included); 36 px for the primary action in dialogs and the login
  card; 28 px for row-action buttons in tables (`.row-actions button`, `.watch-actions button`).
* Tones: **primary** (`--accent` fill, `--accent-text`), **secondary** (`--surface` fill,
  `--border` edge — today's default), **quiet** (no border, no fill; hover shows `--accent-soft`;
  for `.link-cell`, `.chip-x`, `.exception-remove`, `.talker-x`, the theme/language/help header
  items), **danger** (`--danger-text` text, `--danger` border at 40 %; hover fills 12 %). `.primary`
  and `.danger` exist; *quiet* replaces five one-off "no border, no background" rules.
* Hover: border to `--accent-line`, no shadow change; active: `translateY(0)` and
  `--surface-2`; disabled: `opacity: .5` as today. The current hover shadow
  (`0 1px 3px color-mix(accent 22%)`) reads as jitter on a table of twenty buttons; drop it.
* Focus: keep `outline: 2px solid var(--focus); outline-offset: 2px` (today 1 px) and add
  `box-shadow: 0 0 0 4px color-mix(in srgb, var(--focus) 25%, transparent)` so the ring is
  visible on dark surfaces and over table row hover tints. Never remove the ring for mouse users
  via `:focus`; `:focus-visible` is already used correctly.
* Inputs: `background: var(--surface)` (today `--bg`, which makes fields look disabled on the
  canvas), `border: 1px solid var(--border-2)`, on focus the ring above and `border-color:
  var(--accent)`. Placeholder `--text-3`.
* Segmented control (`.segmented`): active segment `--surface` on a `--surface-2` track with
  `--shadow-1`, instead of a full accent fill — the accent fill competes with the primary button
  next to it on the Topology page.
* `prefers-reduced-motion: reduce` disables the 0.1–0.15 s transitions (sidebar width, card
  hover translate).

## 5. Three components, before and after

Each sketch is precise enough to implement from; the "after" uses only the tokens above.

### 5.1 A settings card (Settings → Network → Switches, or any `#…-box`)

**Today** (index.html 751–754, switches.js 128–155): an `h3.section` at 14 px, a `p.muted`
intro, a stack of `.watch` rows reusing the rules page's row style (a top border, a bold name,
a `code` address, right-aligned *Read now / Edit / Delete* buttons), a *Add a switch…* primary
button. No container: the box's edges are wherever the next `h3` starts. Save feedback is a
`span.muted` after the button.

**After:**

```
┌ card ─────────────────────────────────────────────────────────────────┐
│ Switches (SNMP)                                      [Add a switch…] │  header: fs-lg semibold, action right
│ DENIS reads your switches over SNMP (v2c, read only) to show which    │  intro: fs-sm text-2, max-width 68ch
│ port each device is plugged into… DENIS never changes anything on a   │
│ switch.                                                               │
├──────────────────────────────────────────────────────────────────────┤  divider: --border
│ ● Core switch     192.168.1.2    48 ports (41 up) · 112 MACs · 5m ago │  row: 44px, name fw-medium,
│                                            [Read now] [Edit] [Delete] │  meta fs-sm text-3, actions quiet
│ ○ Lab switch      10.0.9.4       cannot be read: no answer            │  status dot: --ok / --danger
│                                            [Read now] [Edit] [Delete] │
└──────────────────────────────────────────────────────────────────────┘
```

```css
.card { background: var(--surface); border: 1px solid var(--border); border-radius: var(--r-2); }
.card-head { display: flex; align-items: center; gap: var(--s-3); padding: var(--s-4) var(--s-5) 0; }
.card-head h3 { font: var(--fw-semibold) var(--fs-lg)/var(--lh-lg) var(--font); margin: 0; flex: 1; }
.card-intro { padding: var(--s-1) var(--s-5) var(--s-4); color: var(--text-2); font-size: var(--fs-sm); max-width: 68ch; }
.card-body { border-top: 1px solid var(--border); }
.card-row { display: grid; grid-template-columns: 12px 1fr auto; gap: var(--s-3); align-items: center;
            padding: var(--s-3) var(--s-5); min-height: 44px; }
.card-row + .card-row { border-top: 1px solid var(--border); }
.card-row .meta { color: var(--text-3); font-size: var(--fs-sm); }
```

Save feedback becomes the `notice()` toast from UX_REVIEW.md finding 3; the message span goes.
The same card wraps every other settings box (SSO, AI, each CMDB source once it is a list row,
SIEM, retention, license…), the rule cards, the findings, and the dashboard's three lists — one
component, one set of paddings.

### 5.2 A data table (Devices)

**Today** (style.css 93–110): `.table-wrap` with a 1 px border and 8 px radius; `th` 12 px
`--muted` semibold sticky; cells `8px 12px` with `white-space: nowrap`; row hover is a 7 %
accent tint; the sort caret is a Unicode ▾ appended in `::after`; a group row is bold muted text
with extra top padding.

**After:**

```
 ┌ table-wrap ───────────────────────────────────────────────────────────────────┐
 │ □  ●  RISK  IP            MAC                VENDOR   NAME              TYPE ▾ │  header strip: surface-2,
 ├───────────────────────────────────────────────────────────────────────────────┤  fs-xs uppercase text-3,
 │ □  ●  [72]  10.0.10.14    a4:5e:60:…  Apple    ⌂ Reception printer   printer │  sorted col: text + caret
 │ □  ○  [12]  10.0.10.22    b8:27:eb:…  Raspb…   ▣ sensor-hub          computer│  row: 40px, hover surface-2,
 │ ─ Office 11 · 6 devices ────────────────────────────────────────────────────  │  group row: fs-xs uppercase
 └───────────────────────────────────────────────────────────────────────────────┘  text-3 on surface-2
```

```css
.table-wrap { background: var(--surface); border: 1px solid var(--border); border-radius: var(--r-2); }
th { position: sticky; top: 0; background: var(--surface-2); color: var(--text-3);
     font: var(--fw-semibold) var(--fs-xs)/var(--lh-xs) var(--font); text-transform: uppercase; letter-spacing: .04em;
     padding: var(--s-2) var(--s-3); border-bottom: 1px solid var(--border); }
th.sorted { color: var(--text); }
td { padding: var(--s-2) var(--s-3); height: 40px; border-bottom: 1px solid var(--border); }
tbody tr:hover td { background: var(--surface-2); }
tr.group-row td { background: var(--surface-2); color: var(--text-3); font-size: var(--fs-xs);
                  text-transform: uppercase; letter-spacing: .04em; height: 32px; }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
.mono { font-family: var(--font-mono); font-size: var(--fs-sm); }
```

The risk chip (`.sev` reused for a number) becomes a 28 px-wide pill with tabular numerals and
the status *text* colour on a 14 % tint; the online dot gains a `--ok` ring on hover so it reads
as a state, not a decoration. The header strip on `--surface-2` is the one visible change that
makes a plain table look designed, and it costs one declaration. The acknowledged-row treatment
(`tr.acked td { opacity: .55 }`) becomes `color: var(--text-3)` on text only, so chips and
buttons in that row stay legible.

### 5.3 An alert row and its severity chip

**Today** (app.js 547–575; style.css 144–151): time cell with "7m ago" over an exact timestamp;
`SEV 80` as an uppercase chip plus the raw score; type as a `.tag` (accent tint); device; a
`td.wrap` with the summary and a 12 px muted "why" line joined with `·`; then *Acknowledge* and
*Add exception* as two full secondary buttons per row.

**After:**

```
│ □ │ ▍ 7 m ago          │ ● high  80 │ new_port │ Reception printer   │ Opened TCP/445 to 10.0.10.9       │ [Acknowledge ▾] [⋯] │
│   │   2026-09-30 15:01 │            │          │ · local             │ +40 new service port · +15 SMB    │                    │
```

* A 3 px left rule on the row in the severity fill (`--danger` / `--warn` / `--accent`) — the
  same device the expanded-group rows already use (`.alert-group-item td:first-child`,
  style.css 158), now meaning severity, so a column of alerts scans by colour before anyone reads
  a chip.
* The chip: dot + word + score in one pill, `--fs-xs`, `fw-semibold`, `*-text` colour on a 14 %
  tint, no uppercase (uppercase 12 px red text is the loudest element on the page today and it
  repeats forty times).
* The type as a `--surface-2` chip in `--font-mono` (it is an identifier, not a label).
* The reasons line in `--text-2` at `--fs-sm`, not `--text-3` at 12 px: it is the explanation.
* Actions: one secondary *Acknowledge* with the reason picker as a real menu (`▾`), and a quiet
  `⋯` overflow holding *Add exception* / *Open device* / *Explain with AI*. Two full buttons per
  row × 200 rows is where the page's visual noise comes from.

```css
tr.alert { border-left: 3px solid transparent; }
tr.alert.high { border-left-color: var(--danger); }
tr.alert.medium { border-left-color: var(--warn); }
tr.alert.low { border-left-color: var(--accent); }
.sev { display: inline-flex; align-items: center; gap: 6px; padding: 2px 8px; border-radius: var(--r-pill);
       font: var(--fw-semibold) var(--fs-xs)/var(--lh-xs) var(--font); font-variant-numeric: tabular-nums; }
.sev::before { content: ""; width: 6px; height: 6px; border-radius: 50%; background: currentColor; }
.sev.high { color: var(--danger-text); background: color-mix(in srgb, var(--danger) 14%, transparent); }
.sev.medium { color: var(--warn-text); background: color-mix(in srgb, var(--warn) 16%, transparent); }
.sev.low { color: var(--accent); background: var(--accent-soft); }
.sev.info { color: var(--text-3); background: var(--surface-2); }
```

### Also worth doing in the same pass (suggestions, sketched only)

* **KPI tiles** (`#dash-cards .card`): number at `--fs-2xl` semibold tabular, label `--fs-sm
  --text-2`, a 3 px top rule in the status colour for `.bad`/`.warn` instead of a coloured border
  all round, hover `--shadow-2`. Twelve identical white boxes with a 22 px number is the part of
  the dashboard that looks least finished today; the tiles are already `clickable`, so make
  them look it (a subtle `↗` in the corner on hover).
* **Sidebar**: active item gets a 3 px `--accent` bar on the left edge plus `--accent-soft`
  fill; icons `--text-3` at rest; `.navgroup` at `--fs-xs` `--text-3` with `--s-6` top margin.
  Collapsed rail: 56 px, icons centred, badges as 8 px dots (already done).
* **Header**: 56 px, brand left, a single status pill (`● watching eth0 · sweep 3 m ago`)
  centre-left, actions right as quiet buttons; the full status sentence moves to its tooltip
  (UX_REVIEW.md finding 13).
* **Dialogs**: `--r-3`, `--shadow-3`, a 1 px `--border-2` edge, header `--fs-lg` semibold with
  `--s-5` padding, body `--s-5`, footer actions right with a `--border` top rule; backdrop
  `rgba(11, 14, 18, .55)` with `backdrop-filter: blur(2px)` (this one *is* a taste call).
* **Empty states**: a 40 px icon in `--text-3`, one sentence in `--text-2`, one secondary
  button — the same box everywhere (UX_REVIEW.md finding 12).

## 6. An incremental path

Each step is one CSS diff, reviewable on its own, and leaves the console fully working:

1. **Tokens only.** Add the new custom properties to both `:root` blocks with the old names as
   aliases. Replace the seventeen hard-coded `#dc2626` and the JS colour maps with tokens. Change
   `.ok-text` and dark-mode danger to the `*-text` tokens. *Visible change: the two contrast
   fixes only.* Half a day.
2. **Type and spacing.** Apply the size scale and snap paddings/margins/radii to the steps.
   *Visible change: slightly larger hints, consistent gaps.* One day; the risk is a wrapped
   toolbar, so check Devices, Alerts and Rules at 1024 px and 375 px.
3. **Controls.** Heights, the four tones, focus ring, inputs on `--surface`, segmented control.
   One day.
4. **Cards and tables.** The `.card` component for settings boxes, rule cards, findings and
   dashboard lists; the table header strip and row heights. Best done together with
   UX_REVIEW.md finding 1 (Integrations as a source list) and finding 8 (per-page toolbars),
   since both touch the same markup. Two to three days including the JS.
5. **Alerts and the dashboard.** The severity rule, the chip, the overflow menu; KPI tiles.
   One to two days; the overflow menu is the only new JS.
6. **Dialogs, panel, header, sidebar.** Polish; one day.

Not in scope, deliberately: a webfont, an icon-set change (the inline SVG set in `icons.js` is
fine and brand-neutral), animation beyond hover/focus, a component library, or any build step.
Everything above is expressible in the current plain-CSS, no-build setup and stays inside the
`default-src 'self'` policy.

## 7. What to verify before calling it done

* Every text pair in the table in §1 re-measured after implementation, in both themes, with
  the operator's own accent substituted (a very light or very dark accent is the realistic
  failure).
* Keyboard walk-through of Devices → detail panel → Edit asset, and of Alerts → Acknowledge with
  a reason, with the focus ring visible at every stop, in both themes.
* The five languages at 1024 px: German and French labels are 20–30 % longer and are what wraps
  the header and the toolbar first.
* Print of the Compliance page and a saved report — they use their own CSS in `report.rs` and
  are unaffected, which should be confirmed rather than assumed.
* `prefers-reduced-motion` and forced-colours (`@media (forced-colors: active)`: the severity
  left rule and the chip dot need `forced-color-adjust: none` or an outline, or they vanish in
  Windows high-contrast mode — a case the current CSS does not handle either).
