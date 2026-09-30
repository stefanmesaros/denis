# Three design languages for a full redesign: proposal

A companion to [DESIGN_LANGUAGE.md](DESIGN_LANGUAGE.md), not a replacement for it. That document
proposes an incremental refinement of today's look (tokens, a type scale, three components) and
stays deliberately inside the current visual identity. This one answers a different question:
if the console were redesigned from the ground up, what would it look like, and would that be
worth doing? It proposes three genuinely different directions, each complete enough to build
from, and ends with a recommendation that is not simply "yes, redesign".

Nothing in `ui/` was changed for this document. It is written against the code as it is in
this worktree: `ui/style.css` (565 lines), `ui/app.js` (the logical topology in `renderTopology`,
lines 1338–1404), `ui/switches.js` (the physical topology), and `src/web/mod.rs` (the UI is
served with `Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; base-uri
'none'`, line 371, and the `ui/` folder is embedded in the binary with `rust_embed`). The same
bar as [NAC.md](NAC.md) applies: what was checked is marked as checked, what is a taste call is
marked as a suggestion, and every contrast ratio below was computed with the WCAG 2 formula in
sRGB, not guessed. Where this document describes what a reference product does, it says whether
that came from a source that could be read or from inference.

Constraints that every direction below must live inside, because they are facts about this
codebase and not preferences:

* **Plain CSS, no build step, no framework.** `README.md` line 438: "the web UI (plain JS, no
  build step, strict CSP)". Any direction has to be expressible as CSS custom properties, plain
  selectors and vanilla JS in the existing files.
* **`default-src 'self'`.** Nothing loads from a CDN — not a font, not a script, not a stylesheet.
  A webfont is possible, but only as a file embedded in the binary next to `style.css` and served
  from the same origin, and its licence goes into `THIRD-PARTY-LICENSES.md`.
* **Operator branding.** `applyBranding` (admin.js 119–121) overrides `--accent` and
  `--accent-text` at runtime with whatever colour the operator chose, and 37 tints are derived
  from it. A design language that makes the accent colour structurally important (as a brand
  colour, not just as "the colour of links and the primary button") has to survive an arbitrary
  operator accent. This constraint decides more below than any taste question.
* **Five languages**, including Slovak, German and French. German and French labels are 20–30 %
  longer than English; Slovak needs Latin Extended-A glyphs (č, š, ž, ď, ť, ľ, ô, ŕ). A webfont
  that lacks them falls back to the system face mid-word.
* **Two topology renderers**, both plain SVG built in JS: rings around a gateway (`renderTopology`)
  and switches-and-cables (`renderPhysical`). There is no canvas, no D3, no physics. Motion on the
  Topology page has to be added to, not instead of, this.
* **No `prefers-reduced-motion` handling today** (DESIGN_LANGUAGE.md §7 already notes this). Every
  motion idea below has to say what it does under that query.

## Part 1: the five references

### "Wiz" or "Wix"?

Stefan wrote *Wiz*. There are two candidates and they are very different products:

* **Wix** (wix.com) — the website builder. Its product UI is a light, friendly, blue-accented
  business dashboard; its own typeface is Wix Madefor.
* **Wiz** (wiz.io) — the cloud-security platform (acquired by Google in 2025). It is not a
  lesser-known product; in a security context it is the more obvious reference, and its console
  is exactly the kind of thing DENIS is: a findings/graph/inventory tool that has to show a lot
  and stay calm.

Both were researched. **Wiz (the security product) is treated as the primary reading of the
name below**, because it matches the brief ("minimalist, premium, very clean") *and* the domain,
and because its "security graph" page is the closest existing analogue to the DENIS Topology
page. Wix is kept as a secondary reference for direction C, where its friendliness and its
open-licensed typeface are useful. If Stefan meant Wix, nothing in Part 2 breaks; direction C
simply moves up a notch in relevance.

### Wiz (wiz.io) — cloud security console

* **Colour.** Confirmed from the public site: a dark-first brand (deep navy/charcoal backgrounds,
  white type, cyan-to-purple gradient accents used for illustration, not for controls). For the
  *product*, inferred from screenshots in Google Cloud's partner documentation and Wiz's own
  platform pages: the console itself is predominantly **light** (white cards on a pale grey
  canvas) with a dark navy sidebar, a single blue/indigo action colour, and severity colour used
  only in chips, dots and the graph nodes. The security graph draws typed nodes (icons in rounded
  squares) on a plain light canvas with thin grey edges; risk is shown by a coloured badge on the
  node, not by colouring the whole node.
* **Typography.** Not confirmed; the site's CSS could not be read. Inferred: a neutral grotesk
  (Inter or similar) at one weight for body and semibold for titles, tabular figures in counts.
* **Density.** Moderate-to-dense: findings tables with 8–10 columns, inline severity chips,
  expandable rows. Whitespace is spent on page margins and card padding, not between rows.
* **Libraries.** Not confirmed. Inferred from job postings ("React", "Figma") and from how the
  console behaves: React with an in-house component layer; nothing in what could be observed
  identifies Radix, MUI or Ant. Treat as unknown.

### Linear

* **Colour.** Confirmed from Linear's own write-up ("How we redesigned the Linear UI", part II):
  themes are generated in **LCH** from three inputs — base colour, accent colour, contrast — instead
  of ~98 hand-set variables, which is also how they get high-contrast themes for free. Neutrals are
  slightly tinted, never pure grey; the accent (their lavender, `#5e6ad2`, confirmed by third-party
  token extractions) is used sparingly: the active item, links, focus, one primary button.
* **Typography.** Confirmed: Inter for body and **Inter Display** for headings (same write-up),
  with the `cv01`/`ss03` alternates enabled (confirmed by token extractions, not by Linear
  directly). Weights are tuned rather than stepped: body around 400–450, "medium" at ~510,
  semibold ~590 on the variable axis.
* **Density.** Dense but calm: 13 px body in lists, 32 px rows, a lot of alignment work
  ("labels, icons and buttons aligned vertically and horizontally") and very little decoration.
  Borders are hairlines, surfaces differ by one or two lightness steps, shadows are reserved for
  popovers.
* **Libraries.** Confirmed by multiple secondary sources (LogRocket, Radix's own adopter list):
  **Radix UI primitives** underneath an in-house design system ("Orbiter"). The look is not
  produced by a library; the primitives give behaviour (menus, dialogs, tooltips) and Linear
  styles everything. For a plain-CSS project, the transferable idea is the *token structure*
  (one base, one accent, one contrast knob) and the alignment discipline, not a dependency.

### Vercel

* **Colour.** Confirmed from the public Geist documentation: ten scales — two backgrounds
  (`background-1` default, `background-2` subtle), a 10-step gray, and 10-step blue, red, amber,
  green, teal, purple, pink. Steps have fixed jobs: 100 background, 200 hover, 300 active,
  400–600 borders (default / hover / active), 700–800 high-contrast fills, 900–1000 secondary and
  primary text. P3 values where supported. Light and dark are the *same scale, inverted*, which
  is why Vercel's dark mode looks as finished as its light mode. Primary actions are **black on
  white / white on black**, with blue reserved for links.
* **Typography.** Confirmed: **Geist Sans** and **Geist Mono**, nine weights, variable, released
  under the **SIL Open Font License** with sources on GitHub (`vercel/geist-font`). That licence
  is what makes it the most practical premium face for this project: it can be embedded in the
  binary. Large, tight-tracked headings; 14 px body; mono everywhere an identifier appears.
* **Density.** Generous margins, dense content inside them: tables at 40 px rows, a lot of
  white, borders instead of shadows, a near-monochrome page where any colour means something.
* **Libraries.** Confirmed: Geist is Vercel's own system (React); Radix is used underneath
  according to secondary sources. There is a public Figma kit and an npm font package. The
  transferable part for DENIS is the **gray scale with jobs** and the font.

### Datadog

* **Colour.** Confirmed brand colour: purple `#632CA6` (press kit). Confirmed from
  third-party token extractions of the public site (not the app): purple is the single action
  colour; near-black `#212529` ink instead of pure black; flat tinted surfaces (`#f5f5f5`,
  `#eeeeee`), `#e1e5e9` hairlines, effectively **no box-shadows**. The app (inferred from
  screenshots and my own familiarity with it) is light by default with a full dark theme, and
  colour is spent almost entirely on **data**: graph series, status pills, host-map hexagons.
  Chrome is grey.
* **Typography.** Site: NationalWeb (confirmed by extraction). App: a neutral sans at 12–13 px
  with very heavy use of monospace for tags, hosts and values (inferred). Weight carries
  hierarchy (300/400/600/700), not size.
* **Density.** The highest of the five and the closest to what DENIS shows: dashboards with a
  dozen widgets, tables with a dozen columns, everything at 12–13 px. What keeps it organised
  (inferred from use): a fixed 2–4 px hairline grid, widget titles at one size everywhere,
  colour used only inside widgets, and consistent left alignment of every number column.
* **Libraries.** Confirmed: **DRUIDS**, an internal React/TypeScript system with 150+ (site says
  600+) components, documented publicly at druids.datadoghq.com but not open-sourced. Nothing
  reusable directly; the transferable lesson is "one widget frame, one title style, colour only
  for data".

### Tines

* **Colour.** Confirmed from the public site: light, white canvas, dark text, restrained accents.
  The storyboard (inferred from product screenshots and the marketing SVGs, since the app CSS
  could not be read): a **dotted-grid canvas**, actions as rounded rectangles with a coloured
  icon tile on the left, one pastel per action *type* (event transform, HTTP request, trigger,
  send to story…), bezier connectors, and "runs" visualised as dots travelling along connectors.
* **Typography.** Not confirmed. Inferred: a geometric humanist sans (Inter-like) with medium
  weights for node titles and a mono for payloads.
* **Density.** Low on the canvas (a node is 200 × 56 px or so with a lot of air), high in the
  side panels (JSON, logs). The canvas *is* the product, so it gets the space.
* **Libraries.** Not confirmed. Inferred: React; the canvas is custom (not React Flow — the
  interaction model predates it), rendered with SVG/HTML rather than `<canvas>`.

### What DENIS could reach for if it ever adopted a library

Stefan asked this directly. The honest answer for a no-build, plain-JS console is: the libraries
those five use (Radix, in-house React systems) are not adoptable without a build step and React,
which the project has explicitly decided against. Three realistic options, in order of fit:

1. **Nothing** — keep writing CSS, but adopt the *token discipline* of Vercel/Linear (a gray scale
   with jobs, one accent, one contrast knob). Every direction below is written this way.
2. **Open Props** (plain CSS custom properties, MIT, one file, no build) if a ready-made set of
   scales is wanted. It would replace §1–3 of DESIGN_LANGUAGE.md with imported tokens. Low value
   for the size; the project already has fewer than 30 tokens to name.
3. **Shoelace / Web Awesome** (web components, MIT, works without a build via one script and one
   stylesheet served from `'self'`) if behaviour-heavy components (menus, tabs, dialogs, tooltips)
   ever become the bottleneck. This is the only library route that keeps the "no build, strict
   CSP" promise; it costs ~150 KB and a second visual vocabulary to reconcile. Not recommended
   now; noted so the question has an answer.

shadcn/ui, Radix Themes, MUI, Ant, Mantine all require React and a bundler. Tailwind requires a
build (the CDN "play" script is explicitly not for production and needs `'unsafe-eval'`).

## Part 2: three directions

Each direction is complete: identity, both themes with measured contrast, type, spacing/radius/
elevation, motion, four before/after sketches, and cost. Token names are shared across all three
(`--canvas`, `--surface`, `--surface-2`, `--border`, `--border-2`, `--text`, `--text-2`,
`--text-3`, `--accent`, `--accent-text`, `--link`, `--ok`/`--ok-text`, `--warn`/`--warn-text`,
`--danger`/`--danger-text`, `--info`) so that the implementation of any one of them starts from
DESIGN_LANGUAGE.md step 1 and the three can be compared cell by cell.

"Before" in every sketch is today's console as read from `style.css`/`index.html`/`app.js`; it is
described once here to avoid repeating it three times:

* **Topology (before).** `#view-topology`: a segmented control (accent-filled active segment), a
  legend line of four dots, then one `.topo-site` white card per site (8 px padding, 8 px radius)
  containing a 560 × 560 SVG: straight `--line` spokes from a centre gateway circle (r 17) to
  device circles (r 10) on concentric rings 62 px apart, nodes filled with a 40–55 % mix of the
  risk colour into the panel colour, a red 3.5 px dot for open alerts, 9 px muted labels under
  each node (suppressed past 24 devices), a `muted` paragraph of explanation under the map. No
  motion, no hover state beyond a `--text` stroke.
* **Settings card (before).** An `h3.section` (14 px regular), a `p.muted` intro, rows
  (`.watch`: top border, bold name, `code` address, right-aligned *Read now / Edit / Delete*
  buttons), an *Add…* primary button, a `span.muted` for save feedback; no container.
* **Table row (before).** `th`/`td` at 8 px 12 px padding, 14 px, `nowrap`; hover a 7 % accent
  tint; the row is ~35 px tall; sort caret is a Unicode ▾.
* **Alert row (before).** Time cell ("7m ago" over an exact timestamp), `SEV 80` uppercase chip
  plus raw score, type as an accent-tinted `.tag`, device, `td.wrap` summary with a 12 px muted
  "why" line, and two full secondary buttons per row.

---

### Direction A — "Ink"

**Identity.** Leans on **Vercel** first and **Linear** second. A monochrome console: near-black
ink on near-white paper in light mode, the exact inversion in dark mode, one gray scale with
fixed jobs, and colour reserved for two things only — the operator's accent (links, focus, the
active item) and data (severity, status). The primary button is black (or white in dark), not
the accent, which is the single most "Vercel" decision and also the one that fits a security
console best: the button you press to acknowledge an alert should not compete with the red chip
that tells you why. Ink is the direction in which *colour always means something*, which is the
right property for a tool whose job is to make one red dot among two hundred grey ones
impossible to miss. It also fits the operator-branding constraint better than the other two: the
accent is decorative here, so a weak operator accent degrades gracefully.

**Colour.** Light:

| Token | Value | Job |
|---|---|---|
| `--canvas` | `#fafafa` | page |
| `--surface` | `#ffffff` | cards, tables, sidebar, header |
| `--surface-2` | `#f2f2f2` | table header strip, hover, inset code |
| `--border` | `#e6e6e6` | every resting hairline |
| `--border-2` | `#d4d4d4` | input resting border, dialog edge |
| `--text` | `#0a0a0a` | primary |
| `--text-2` | `#525252` | explanations |
| `--text-3` | `#6b6b6b` | metadata, timestamps |
| `--accent` | `#0a0a0a` | primary button fill (see note) |
| `--accent-text` | `#ffffff` | on the primary button |
| `--link` | operator accent, default `#0067d6` | links, active nav item, focus ring |
| `--ok` / `--ok-text` | `#16a34a` / `#15803d` | fills / text |
| `--warn` / `--warn-text` | `#f5a623` / `#a35a00` | fills / text |
| `--danger` / `--danger-text` | `#e5484d` / `#c4161c` | fills / text |
| `--info` | `var(--link)` | |

Dark:

| Token | Value |
|---|---|
| `--canvas` | `#0a0a0a` |
| `--surface` | `#111111` |
| `--surface-2` | `#1a1a1a` |
| `--border` | `#262626` |
| `--border-2` | `#333333` |
| `--text` | `#ededed` |
| `--text-2` | `#a1a1a1` |
| `--text-3` | `#8a8a8a` |
| `--accent` / `--accent-text` | `#ededed` / `#0a0a0a` |
| `--link` | operator accent, default `#52a8ff` |
| `--ok` / `--ok-text` | `#22c55e` / `#4ade80` |
| `--warn` / `--warn-text` | `#f5a623` / `#f5a623` |
| `--danger` / `--danger-text` | `#ff6166` / `#ff6166` |

Note on branding: in Ink the operator's colour becomes `--link`, and `--accent`/`--accent-text`
(the primary button) stay black/white. `applyBranding` writes to a different pair of variables;
a one-line change. **Firm recommendation** if this direction is chosen; making the black button
brandable would break the whole idea.

Measured contrast (body text must be ≥ 4.5 : 1; UI and large text ≥ 3 : 1):

| Pair | Light | Dark |
|---|---|---|
| `--text` on `--surface` | 19.8 | 16.1 |
| `--text-2` on `--surface` | 7.8 | 7.3 |
| `--text-3` on `--surface` / `--canvas` / `--surface-2` | 4.7 / 5.1 / 4.8 | 5.5 / 5.7 / 5.0 |
| `--link` (default) on `--surface` | 5.4 | 7.6 |
| `--accent-text` on `--accent` (primary button) | 19.8 | 16.9 |
| `--ok-text` on `--surface` | 5.0 | 10.8 |
| `--warn-text` on `--surface` | 5.2 | 9.3 |
| `--danger-text` on `--surface` | 6.0 | 6.4 |
| white on `--danger` fill (badge) | **3.9** — flagged | — |
| `--border` / `--border-2` on `--surface` | 1.25 / 1.48 | 1.25 / 1.49 |

Flags: white on the light-mode `--danger` fill is 3.9, under 4.5. Badges (`.badge`, the alert
count in the sidebar) are 11–12 px bold, which WCAG treats as body text. Either keep today's
`#dc2626` for *filled* badges (4.8 on white) and use `#e5484d` only for rings, rules and dots, or
render badges as `--danger-text` on a 14 % tint as DESIGN_LANGUAGE.md already proposes. The
proposal takes the second option. Borders at 1.25–1.5 are below the 3 : 1 non-text threshold
in every direction in this document and in the current console; hairlines are not required to
meet it, but focus rings and the checkbox border are, which is why the focus ring is 2 px of
`--link` and the checkbox border is `--border-2` plus a `--text-3` hover.

**Typography.** **Geist Sans** and **Geist Mono**, self-hosted as two variable WOFF2 files under
`ui/fonts/`, embedded by `rust_embed`, loaded by `@font-face` from `'self'`; OFL text appended to
`THIRD-PARTY-LICENSES.md`. Sizes as measured from the GitHub release should be verified before
committing — expect roughly 60–120 KB per variable file after subsetting to Latin + Latin
Extended-A. **Verify Slovak diacritics** (ď, ť, ľ, ŕ, ô) render from Geist and not from a
fallback; Geist's Latin coverage is broad but this was not checked glyph by glyph.
`font-display: swap` with the system stack as fallback so the console never blocks on the font.

| Step | Size / line | Weight | Used for |
|---|---|---|---|
| xs | 12 / 16 | 500, uppercase, +0.06 em | table headers, nav groups, chips |
| sm | 13 / 18 | 400 | hints, dense cells, metadata |
| md | 14 / 20 | 400 | body, controls |
| lg | 16 / 22 | 600, −0.01 em | card and dialog titles |
| xl | 20 / 26 | 600, −0.02 em | page title (one per page, new) |
| 2xl | 28 / 32 | 600, −0.02 em, tabular | KPI numbers, donut totals |
| mono | 13 / 18 | 400 | IPs, MACs, ports, rule types, communities |

Mono is used *more* than today: every identifier column (IP, MAC, port list, type key) is Geist
Mono at 13 px. That is the Vercel move that most changes how a data table reads.

**Spacing, radii, elevation.** 4 px base: 4, 8, 12, 16, 24, 32, 48. Page gutter 24 px (today 16).
Radii: 6 px controls, 8 px cards and tables, 12 px dialogs; no pill except chips (999). Shadows:
none at rest, anywhere. Popovers and menus: `0 4px 16px rgba(0,0,0,.08)` plus a `--border-2`
edge; dialogs: `0 24px 48px rgba(0,0,0,.16)` light, `.5` alpha dark; the detail panel: a
`--border-2` left edge and no shadow (today `-8px 0 24px`). Dark mode elevation is entirely
surface-step plus border, as in Vercel.

**Motion.** Ink's motion budget is small on purpose, and the Topology page gets the only
permanent movement:

* *Topology — one slow orbit.* Around the gateway node, a 1 px dashed circle at radius 60
  (`stroke-dasharray 2 6`, `--border-2`) rotates once every 90 s. It reads as "this thing is
  alive and watching" without moving anything a person is trying to read. Per-site, one element,
  CSS `@keyframes` on `transform: rotate` with `transform-origin` at the centre, compositor-only.
  On load, spokes draw in with `stroke-dashoffset` over 400 ms and nodes fade in staggered 12 ms
  each (capped at 300 ms total). Under `prefers-reduced-motion: reduce` the orbit is static and
  the draw-in is skipped. Hover on a node: its spoke goes from `--border` to `--text-3` and its
  label from `--text-3` to `--text` in 120 ms, so the eye finds the connection.
* *Live alerts.* A new unacknowledged alert's red dot on the Topology page and in the Alerts
  table pulses **three times** on arrival (a ring scaling 1 → 2.4 and fading 0.6 → 0 over 1.2 s,
  ease-out) and then stays static. Not a permanent pulse: an operator with forty open alerts does
  not want forty heartbeats. Reduced motion: no pulse, the dot simply appears.
* *Load states.* Skeleton rows (`--surface-2` bars, a 1.6 s left-to-right shimmer from
  `--surface-2` to `--border`) replace "Loading…" text in tables and KPI tiles. Reduced motion:
  static bars.
* *Numbers.* KPI tiles count from the previous value to the new one over 300 ms on refresh,
  tabular numerals so the tile does not jitter. Reduced motion: instant.
* *Everything else* is 120 ms ease-out on opacity/transform only: panel slide-in 8 px, menu
  drop 4 px, dialog scale .98 → 1. No hover translate on cards, no hover shadow on buttons.

**Sketches.**

*Topology, after.* One card per site on `--surface` with a 16 px inset, a header row (site name
`lg 600`, device count `sm --text-3`, the segmented control and legend moved into this row on
the right so the map starts at the same height in every card). The map on `--canvas` (not white),
with a 1 px `--border` frame at 8 px radius. Gateway: r 18, `--surface` fill, 2 px `--text`
stroke, IP in mono 11 px under it. Spokes: `--border`, 1 px. Devices: r 9, **`--surface` fill and
a 2 px stroke in the risk colour** (`--border-2` for none, `--link` low, `--warn` medium,
`--danger` high) — a hollow ring reads as data on a monochrome page where today's filled pastel
discs read as decoration; offline nodes at 0.4 opacity as today. Open alert: the 3.5 px
`--danger` dot with the three-pulse arrival. Labels `sm --text-3` in Geist Sans, `--text` on
hover. The dashed orbit at r 60 around the gateway. Legend as four ring-samples, not filled dots,
so it matches the nodes.

*Settings card, after.* A `--surface` card, `--border`, 8 px radius. Head: 16 px 24 px 0, title
`lg 600` left, one primary (black) *Add a switch* right. Intro: `sm --text-2`, max 68 ch,
24 px horizontal padding, 16 px bottom. Divider. Rows 44 px: a 8 px status ring (hollow, `--ok`
or `--danger` stroke) · name `md 500` · address in mono `sm` · meta `sm --text-3` · actions as
quiet text buttons (`--text-2`, `--text` on hover, no border) on the right; *Delete* becomes
`--danger-text` only on hover. Save feedback: the toast.

*Table row, after.* Header strip `--surface-2`, `xs 500` uppercase `--text-3`, the sorted column
`--text` with a 12 px chevron icon from `icons.js` instead of ▾. Rows 40 px, `md`, hover
`--surface-2`, identifier cells in Geist Mono `sm`. The online dot becomes a 8 px hollow ring
(`--ok` stroke) that fills on hover. Risk score: `xs 500` tabular in a 28 px pill, `*-text`
colour on a 12 % tint. Selected row (checkbox on): a 2 px `--link` inset rule on the left instead
of a tint, so a selected red row stays red.

*Alert row, after.* 3 px severity rule on the left in the *fill* colour. Time: `sm` "7 m ago"
with the timestamp in the tooltip (not a second line). Chip: `xs 500`, no uppercase, dot + word +
score. Type: mono `sm` on `--surface-2`. Summary `md --text`, reasons `sm --text-2`. Actions:
one secondary *Acknowledge ▾* and a quiet `⋯`. Acknowledged rows: text `--text-3`, rule
`--border-2`, chip on `--surface-2`.

**Cost and risk.** Ink is DESIGN_LANGUAGE.md plus four things: a webfont (half a day: files,
`@font-face`, licence, subsetting script under `tools/`), the black-button / link-accent split
(a day, mostly `applyBranding`, the 37 accent tints and the segmented control), mono in
identifier columns (half a day across `app.js`/`tables.js`), and the motion module (a day:
orbit, pulse, skeletons, reduced-motion query). **Roughly 1.5 × the incremental path: 8–10 days
versus 6–8.** Risk: low. Everything is CSS on the existing DOM plus one JS change; the Topology
motion is CSS keyframes on existing SVG elements. The one real risk is the font: binary size
(+150–250 KB), Slovak glyph coverage, and the small share of operators who will prefer the system
face (a *Use system font* toggle next to the theme toggle is cheap and worth adding).

---

### Direction B — "Deep Field"

**Identity.** Leans on **Wiz** first and **Datadog** second, with the Wiz *marketing* palette
(deep navy, cyan) brought into the product because it happens to be the right palette for a
monitoring console that is watched, not used: dark-first, high density, colour spent on data.
This is the direction Stefan's "stars in space on the Topology page" belongs to naturally — a
dark canvas is where a starfield is legible and where a red alert dot has the most contrast
(6.6 : 1 for the text variant on `--surface`, and the fill against the `#070b14` canvas is 5.2). Deep Field is the
direction for a console that lives on a wall screen or a second monitor in a NOC: the dark
canvas costs nothing at 3 a.m. and a bright cyan link on it is unmistakable. Light mode is a
full, equal theme (the Wiz console itself is light), but the design is *drawn* dark-first.

**Colour.** Dark (primary):

| Token | Value | Job |
|---|---|---|
| `--canvas` | `#070b14` | page; also the starfield sky |
| `--surface` | `#0e1523` | cards, tables, sidebar |
| `--surface-2` | `#16202f` | header strip, hover, inset |
| `--border` | `#1f2a3c` | hairlines |
| `--border-2` | `#2c3a4f` | input borders, dialog edge |
| `--text` | `#e6ecf5` | |
| `--text-2` | `#a9b6c8` | |
| `--text-3` | `#7f8da3` | |
| `--accent` / `--accent-text` | operator accent, default `#38bdf8` / `#06131f` | primary button, links, active nav |
| `--link` | `var(--accent)` | |
| `--ok` / `--ok-text` | `#22c55e` / `#4ade80` | |
| `--warn` / `--warn-text` | `#f59e0b` / `#fbbf24` | |
| `--danger` / `--danger-text` | `#ef4444` / `#f87171` | |
| `--info` | `var(--accent)` | |
| `--star-1` / `--star-2` | `#8fa3c4` / `#2a3447` | starfield (Topology only) |

Light:

| Token | Value |
|---|---|
| `--canvas` | `#f3f5f9` |
| `--surface` | `#ffffff` |
| `--surface-2` | `#e9edf3` |
| `--border` | `#d8dee8` |
| `--border-2` | `#c2cad6` |
| `--text` | `#0f172a` |
| `--text-2` | `#475569` |
| `--text-3` | `#5b6a80` |
| `--accent` / `--accent-text` | operator accent, default `#0369a1` / `#ffffff` |
| `--ok` / `--ok-text` | `#16a34a` / `#15803d` |
| `--warn` / `--warn-text` | `#d97706` / `#b45309` |
| `--danger` / `--danger-text` | `#dc2626` / `#b91c1c` |
| `--star-1` / `--star-2` | `#b8c4d6` / `#e3e8f0` (a faint dot field, not stars) |

Measured contrast:

| Pair | Dark | Light |
|---|---|---|
| `--text` on `--surface` | 15.4 | 17.9 |
| `--text-2` on `--surface` | 8.9 | 7.6 |
| `--text-3` on `--surface` / `--canvas` / `--surface-2` | 5.4 / 5.9 / 4.9 | 5.5 / 5.0 / 4.7 |
| `--accent` (default) on `--surface` | 8.5 | 5.9 |
| `--accent-text` on `--accent` (primary button) | 8.8 | 5.9 |
| `--ok-text` on `--surface` | 10.5 | 5.0 |
| `--warn-text` on `--surface` | 10.9 | 5.0 |
| `--danger-text` on `--surface` | 6.6 | 6.5 |
| `--danger-text` on a 14 % danger tint over `--surface` (chip) | 5.8 | — |
| `--text-2` node labels on `--canvas` (Topology) | 9.6 | — |
| `--star-1` on `--canvas` | 7.7 (deliberately visible) | — |
| `--star-2` on `--canvas` | 1.6 (deliberately faint) | — |

Flags: none for text. One design flag: the light-mode default accent was first set to sky-600
`#0284c7`, which gives white-on-fill 4.1 — under 4.5 for the 13–14 px button label. It was
darkened to `#0369a1` (5.9). An operator who brands with a bright cyan gets the server-computed
black `--accent-text`, which is fine (black on `#38bdf8` is 8.8). Note the general rule this
exposes: in Deep Field the accent *is* structural (primary button, links, active items, the
"low" risk colour), so a pale operator accent hurts more than in Ink; the Settings → Branding
warning under 3 : 1 that DESIGN_LANGUAGE.md suggests becomes a firm recommendation here.

**Typography.** **Inter** (variable, OFL, wide Latin coverage — Slovak confirmed by Inter's
published glyph set) for UI and **JetBrains Mono** (OFL) for identifiers. Both self-hosted as
above. Inter is the Datadog/Linear neutral; the console is dense enough that a face designed for
12–13 px matters more than character. Enable `tnum` globally (Inter's tabular figures) and `cv11`
(single-storey a) — a suggestion, not a requirement.

| Step | Size / line | Weight | Used for |
|---|---|---|---|
| 2xs | 11 / 14 | 500, uppercase, +0.08 em | widget titles, table headers, legend |
| xs | 12 / 16 | 400 | metadata, dense cells |
| sm | 13 / 18 | 400 | **body** (one size down from today) |
| md | 14 / 20 | 500 | controls, names, dialog body |
| lg | 16 / 22 | 600 | card titles |
| xl | 22 / 28 | 600, tabular | KPI numbers |
| mono | 12 / 16 | 400 | identifiers |

Body at 13 px is the Datadog density decision. It gains roughly one column on Devices at 1280 px
and one more row per 40 px. It is also the decision most likely to be reversed by users over 45;
a *Comfortable / Compact* density toggle (one class on `body` switching `--fs-body` and the row
height) is part of this direction, not an option.

**Spacing, radii, elevation.** 4 px base with a tighter default: 4, 8, 12, 16, 20, 32. Page
gutter 16 px (as today). Rows 36 px compact / 44 px comfortable. Radii: 4 px controls, 6 px
cards, 10 px dialogs — squarer than the other two, as in Datadog. No shadows at all in dark mode;
elevation is `--surface` → `--surface-2` → `--surface-2` with a `--border-2` edge (menus,
dialogs). Light mode: `0 1px 2px rgba(15,23,42,.06)` on cards, `0 8px 24px rgba(15,23,42,.14)`
on popovers and dialogs. A 1 px **inner top highlight** (`rgba(255,255,255,.04)`) on dark cards —
the one Wiz-marketing flourish that survives; it is what makes a dark card look machined rather
than flat. Suggestion only.

**Motion.** This is the direction where the starfield is designed properly, so it gets the most
space.

* *Topology — the starfield.* Behind each site's SVG map, a second layer: a `<canvas>` element
  (2D context, no library) the same size as the map, `position: absolute`, `z-index` below the
  SVG, `pointer-events: none`. It draws two populations: ~90 faint points (`--star-2`, 1 px,
  alpha .5–1) and ~14 brighter ones (`--star-1`, 1–1.5 px). Movement: the faint layer drifts
  at 0.6 px/s and the bright layer at 1.2 px/s in the same direction (a two-plane parallax), and
  a random 3–5 of the bright points breathe in alpha over 4–7 s each. That is all. No shooting
  stars, no twinkle on every point, no connection lines between stars (that would be indistinguishable
  from the topology's own spokes — the single most important "don't"). Frame rate capped at 24 fps
  with `requestAnimationFrame` skipping; the loop stops when the Topology tab is hidden, when the
  document is hidden (`visibilitychange`), and when the map is scrolled out of view
  (`IntersectionObserver`). Measured budget to hit: under 2 % CPU on a 2020 laptop with two sites
  visible; if it cannot, drop to 12 fps before dropping the feature.

  *Legibility rules.* (1) Stars never render inside a 26 px radius of any node or inside 14 px of
  any spoke — the canvas gets the node positions from `renderTopology` and skips them, so the
  data always sits on clean sky. (2) Star alpha is multiplied by 0.35 inside the outermost ring's
  bounding circle plus 20 px, so the field is brightest at the card edges and dimmest under the
  graph. (3) Labels get a 2 px `--canvas` text stroke (`paint-order: stroke`) so a star passing
  behind a label never touches its glyphs. (4) Light mode draws the same field as a static,
  motionless dot grid in `--star-2` (a faint paper texture) — there are no stars in daylight, and
  a moving light-grey speckle on white looks like a dirty screen.

  *Reduced motion.* `prefers-reduced-motion: reduce` → the canvas is drawn once (static field,
  same legibility rules) and the loop never starts. A per-user *Ambient motion* toggle in the
  header's theme menu (stored with the theme preference) does the same, because "reduce motion"
  is an OS setting many people never find.

  *What it is for.* An operator glancing at a wall screen can tell in half a second whether the
  page is live or frozen — a browser tab that lost its WebSocket looks identical to a live one
  today. The drift is the liveness indicator. That is the security-operator justification, and
  it is why the loop must also stop (freeze) when the server connection drops, not keep drifting
  over stale data. This last point is a firm recommendation: an animated stale page is worse than
  a static one.

* *Live data.* Unacknowledged alerts: the node's red dot gets a permanent, slow (3 s) halo at
  alpha .25 → 0, one ring, not a pulse — on a dark canvas it reads like a beacon. In the Alerts
  table the same three-pulse arrival as Ink. The header status pill (`● watching eth0`) gets a
  1.5 s breathing dot only while a sweep is in progress.
* *Traffic.* On the physical topology, cables whose switch port reported traffic in the last
  poll get a `stroke-dasharray 6 10` overlay in `--accent` at .5 alpha, flowing at 20 px/s
  toward the device. Cables with no traffic are plain. This turns the switch map into a live
  panel and it uses data DENIS already reads (port counters over SNMP). Reduced motion: the
  overlay is static.
* *Load / hover.* Skeleton shimmer as in Ink but on `--surface-2` → `--border-2`; hover on
  rows is a 100 ms background step; the detail panel slides 12 px.

**Sketches.**

*Topology, after (dark).* The whole `#view-topology` sits on `--canvas`. The segmented control
is a `--surface-2` track with a `--surface` active pill (not accent-filled). Per site, a card is
*not* drawn: the map floats directly on the canvas with the starfield behind it, and a `2xs`
uppercase title (`SITE HQ · 41 DEVICES · 2 OPEN`) at the top left with the legend on the right.
Gateway: r 18, `--surface` fill, 2 px `--accent` stroke, a 1 px `--accent` ring at r 26 at .3
alpha. Spokes: `--border-2` at full alpha (they must beat the faint stars: `--border-2` on the canvas
is 1.7, faint stars 1.6, and the bright ones are excluded from spoke corridors — a thin margin,
which is why spokes are not dimmed in this direction). Devices: r 9,
filled with the risk colour at 22 % over `--surface`, 1.5 px stroke in the full risk colour;
"none" nodes are `--surface` with a `--border-2` stroke. Labels `xs --text-2` (9.6 : 1 on canvas)
with the canvas-coloured stroke. Open alerts: the beacon. Offline: .35 alpha, dashed stroke.
Under the map, the explanation paragraph becomes a `?` icon-button tooltip; the paragraph is
noise on a dark wall screen.

*Settings card, after.* `--surface` card, `--border`, 6 px radius, a 1 px inner top highlight.
Head 12 px 16 px: title `lg 600`, a `2xs --text-3` count (`3 SWITCHES · LAST READ 4 M AGO`)
under it, the *Add* primary button (`--accent` fill) right. Intro `xs --text-2`, collapsible
behind a *What this does* disclosure after first read (density: the paragraph is shown once).
Rows 36 px compact: status as a 6 px filled dot (`--ok`/`--danger`) · name `md 500` · address
JetBrains Mono `mono` · meta `xs --text-3` right-aligned as columns (ports, MACs, age) · actions
appear on row hover only, as icon buttons (`icons.js` has read/edit/delete glyphs). Datadog's
"actions on hover" is the density trade: nothing is lost, the resting row is quiet.

*Table row, after.* Header `2xs` uppercase on `--surface-2` with a `--border` bottom rule; rows
36 px, body `sm`; zebra striping **off**, hover `--surface-2`; identifiers in JetBrains Mono
`mono`; numeric columns right-aligned tabular; the risk score as a 3-character mono number
coloured `*-text` with no pill (Datadog style: colour the number, not a box); online as a 6 px
dot. Group rows: `2xs` uppercase `--text-3` on `--canvas` (one step darker than the table), which
makes groups read as gaps in the table rather than as rows.

*Alert row, after.* The severity rule is the *whole first column*: a 4 px bar the row's height in
the fill colour, and the time cell next to it in `xs --text-3`. Chip: `2xs` uppercase word only
(`HIGH`), `*-text` on 14 % tint, 20 px tall; the score as a separate mono number column. Type in
mono on `--surface-2`. Summary `sm --text`, reasons `xs --text-2` on the same line separated by
` · ` when they fit, second line when they do not. Actions on hover only. New rows (arrived since
the last render) carry a 1 px `--accent` left edge for 10 s — Datadog's "new since you looked".

**Cost and risk.** A full re-theme, not an extension: every `--panel`/`--bg`/`--line` use
changes meaning, the accent-tinted hover model (37 `color-mix` uses) is replaced by surface
steps, body size drops to 13 px (every toolbar wraps differently in German and French), the
segmented control and the sidebar are redrawn, and the Topology page gains a canvas layer with
its own lifecycle (visibility, intersection, connection state) plus a density toggle and an
ambient-motion toggle with persistence. **Roughly 3 × the incremental path: 18–24 days.** Risks:
(1) the dark-first drawing makes light mode the second-class citizen unless every sketch is done
twice — budget it; (2) 13 px body will get pushback, hence the toggle; (3) the starfield has to
be measured for CPU and for legibility with a real 200-node site before it is kept — build it
behind a flag first; (4) the report CSS in `report.rs` and the login card are separate and will
look like a different product until they are re-themed too (add two days).

---

### Direction C — "Workbench"

**Identity.** Leans on **Tines** first and **Wix** second. Where Ink and Deep Field are
*consoles*, Workbench is a *tool*: a warm, light, rounded surface with a dotted-grid canvas for
the Topology page, devices drawn as small cards (icon tile + name + IP) rather than circles, and
cables as curves. The Tines idea that transfers is that the map is a place you *work in* — pan,
zoom, click, drag a device onto a site — not a picture you look at. Colour is spent per device
*type* (a pastel tile per type, as Tines does per action type), with risk as a badge on the tile,
which is closer to how Wiz's security graph draws nodes and which is the honest answer to the
problem today's map has: two hundred identical circles coloured only by risk tell you *where
the fire is* but not *what is burning*. The Wix contribution is temperature and typeface — a warm
grey canvas and Wix Madefor Text, which is OFL-licensed, humanist and friendly without being
soft. Workbench is the direction that most says "made by a person for people" and least says
"enterprise"; for a product sold to small IT teams and OT sites that is a feature.

**Colour.** Light (primary):

| Token | Value | Job |
|---|---|---|
| `--canvas` | `#f6f5f2` | page (warm) |
| `--surface` | `#ffffff` | cards |
| `--surface-2` | `#efede8` | inset, hover |
| `--border` | `#e4e1da` | |
| `--border-2` | `#cfcbc1` | |
| `--text` | `#1c1b19` | |
| `--text-2` | `#55524b` | |
| `--text-3` | `#6d6961` | |
| `--accent` / `--accent-text` | operator accent, default `#4f46e5` / `#ffffff` | |
| `--link` | `#4338ca` | |
| `--ok` / `--ok-text` | `#16a34a` / `#15803d` | |
| `--warn` / `--warn-text` | `#d97706` / `#a15c07` | |
| `--danger` / `--danger-text` | `#dc2626` / `#b91c1c` | |
| `--grid-dot` | `#d6d2c8` | canvas dots |
| type tiles | `#dbe4ff` computer · `#ffe4c7` printer/IoT · `#d9f5e3` server · `#fde2e2` OT/PLC · `#ede4ff` phone/tablet · `#e5e7eb` unknown | node tiles (text `--text` on all: 13.6–14.9 : 1) |

Dark:

| Token | Value |
|---|---|
| `--canvas` | `#1a1917` |
| `--surface` | `#232220` |
| `--surface-2` | `#2c2b28` |
| `--border` | `#3a3835` |
| `--border-2` | `#4a4743` |
| `--text` | `#f0ede8` |
| `--text-2` | `#b8b4ac` |
| `--text-3` | `#979289` |
| `--accent` / `--accent-text` | operator accent, default `#a5b4fc` / `#1e1b4b` |
| `--ok-text` / `--warn-text` / `--danger-text` | `#4ade80` / `#fbbf24` / `#f87171` (fills `#22c55e` / `#f59e0b` / `#ef4444`) |
| `--grid-dot` | `#33312d` |
| type tiles | the light tiles at 22 % over `--surface` (e.g. computer `#2f3a5e`; `--text` on it 9.5 : 1) |

Measured contrast:

| Pair | Light | Dark |
|---|---|---|
| `--text` on `--surface` | 17.2 | 13.6 |
| `--text-2` on `--surface` | 7.8 | 7.7 |
| `--text-3` on `--surface` / `--canvas` / `--surface-2` | 4.9 / 5.0 / 4.7 | 5.1 / 5.2 / 4.6 |
| `--link` on `--surface` | 7.9 | 8.0 |
| `--accent-text` on `--accent` (primary button) | 6.3 | 8.0 |
| `--ok-text` / `--warn-text` / `--danger-text` on `--surface` | 5.0 / 5.2 / 6.5 | 9.1 / 9.5 / 5.8 |
| `--text` on any type tile | ≥ 13.6 | ≥ 9.5 |

Flags: none for text. The warm neutrals are within 1–2 % of their cool equivalents, so nothing
inherited from DESIGN_LANGUAGE.md's measurements changes materially; `--text-3` in dark mode was
lifted from `#8f8b83` to `#979289` to clear 4.5 on `--surface-2` (4.17 → 4.6).

**Typography.** **Wix Madefor Text** (OFL 1.1, GitHub `wix-incubator/wixmadefor`, Latin +
Cyrillic + Vietnamese — Slovak is covered; four text weights with italics) for UI, and
**IBM Plex Mono** (OFL) for identifiers because its warmth matches Madefor better than Geist or
JetBrains Mono. Madefor Display is *not* used: the console has no display-size text.

| Step | Size / line | Weight | Used for |
|---|---|---|---|
| xs | 12 / 16 | 500 | badges, tile subtitles, table headers (sentence case, not uppercase) |
| sm | 13 / 18 | 400 | hints, metadata |
| md | 14 / 20 | 400 | body |
| lg | 17 / 24 | 600 | card titles |
| xl | 22 / 28 | 600 | page titles |
| 2xl | 30 / 34 | 700, tabular | KPI numbers |
| mono | 13 / 18 | 400 | identifiers |

Table headers are sentence case at `xs 500 --text-3`, not uppercase: the friendlier register of
this direction is carried more by dropping uppercase everywhere than by the font.

**Spacing, radii, elevation.** 4 px base, generous: 4, 8, 12, 16, 24, 32, 48. Page gutter 24 px.
Rows 44 px. Radii: 8 px controls, 12 px cards, 16 px dialogs and the detail panel, 10 px node
cards on the canvas; pills 999. Elevation is *used* here, softly: cards rest on
`0 1px 2px rgba(28,27,25,.05)`, hover lifts to `0 4px 12px rgba(28,27,25,.08)` with a 1 px
translate (the one place any direction keeps a hover translate), dialogs
`0 20px 48px rgba(28,27,25,.18)`. Dark: shadows at 2 × alpha plus the surface step.

**Motion.** Workbench's motion is *interaction* motion — the canvas responds to the hand — plus
one live-data idea.

* *Topology — the workbench canvas.* The map becomes a pannable, zoomable SVG (wheel to zoom
  0.5–2 ×, drag to pan, a *Fit* button; `viewBox` arithmetic, no library) on a dotted-grid
  background (`radial-gradient` dots at 20 px spacing in `--grid-dot`, moving with the pan via
  `background-position` so the grid feels attached to the world). Nodes are cards: 150 × 40 px,
  10 px radius, a 28 px type tile on the left in the type colour with the `icons.js` glyph,
  name `md 500` and IP in `mono xs --text-3`, a risk badge (`xs`, `*-text` on 14 % tint) at the
  top right when risk > none, and a `--danger` dot with the three-pulse arrival for open alerts.
  Cables are cubic beziers from the gateway card's right edge, 1.5 px `--border-2`, `--accent`
  on hover of either end. Layout is a radial tree as today but with card-sized slots
  (`positions` in `renderTopology` change from a 34 px arc step to a 170 px one), which means
  fewer nodes per ring and more rings; past ~60 devices the outer rings collapse to type groups
  ("14 printers ▸") that expand on click — this replaces today's "too many devices to label"
  message with something that works.
* *Live data — traffic along cables.* A device seen sending or receiving in the last sample
  window gets a 3 px `--accent` dot travelling along its cable toward the gateway once every
  4 s (`offset-path` on the bezier, `offset-distance` 0 → 100 % over 1.2 s, ease-in-out). The
  Tines "run" idea, grounded: DENIS already samples per-device activity every 5 minutes for
  Trends, and "what is talking right now" is exactly the question an operator asks on this page.
  Never more than one dot per cable; devices without recent traffic have still cables. Reduced
  motion: cables with recent traffic are drawn in `--accent` at .6 alpha, static.
* *Canvas motion.* Zoom and pan are direct (no easing) while the pointer is down and settle
  with a 200 ms ease-out on *Fit*. Nodes fade in on first render staggered 15 ms. Dragging a
  node is *not* in scope (positions are computed, not stored); it is the obvious next step and
  would need a stored layout per site.
* *Elsewhere.* Card hover lift (above), 150 ms; dialogs scale .96 → 1 with the backdrop
  fading; toasts slide up 8 px; KPI count-up as in Ink. Reduced motion: opacity only, no
  transforms, no lift.

**Sketches.**

*Topology, after.* The page is one full-height canvas panel (`--surface` with the dot grid),
12 px radius, with a floating toolbar top-left (`--surface` card, `--border`, 8 px shadow):
segmented *By gateway / Switches and cables* as a `--surface-2` track, the site select, a search
box that highlights matching cards (others drop to .3 alpha), a *Fit* button. A floating legend
bottom-left listing the *type* tiles (not risk) — risk is explained by the badges themselves. The
gateway card is 180 × 48 with a `--accent` tile and a 2 px `--accent` border. Type cards as
above. Hover on a card: shadow lift, its cable to `--accent`, and the tooltip (name · IP · type ·
risk) as a real `--surface` popover under it rather than an SVG `<title>`. Click opens the
detail panel as today. Explanation paragraph → a `?` popover.

*Settings card, after.* `--surface`, 12 px radius, resting shadow. Head 20 px 24 px: title
`lg 600`, intro `sm --text-2` directly under it (no divider), *Add a switch* primary right,
rounded 8 px. Rows 48 px on `--surface-2` **inset tiles** with 8 px radius and 8 px gaps (not
hairlines — this direction groups by tiles, Wix-style): a 28 px type tile with the switch glyph,
name `md 500`, address `mono sm`, a status pill (`● Read 4 m ago` `--ok-text` on 14 % tint, or
`○ No answer` `--danger-text`), and the three actions as a quiet `⋯` menu. Empty state: an
illustration-free box with one sentence `--text-2` and the primary button centred.

*Table row, after.* The table itself is a `--surface` card at 12 px radius with 16 px inner
padding on the wrap; header `xs 500 --text-3` sentence case on `--surface` (no strip); rows
44 px with 1 px `--border` rules; hover `--surface-2`; identifiers `mono sm`; the device's
name cell shows the 24 px type tile (today's `.iconbadge` at 28 px accent tint becomes the type
colour); risk badge as in the canvas; online as a `--ok` 8 px dot with a `--surface` 2 px ring
so it sits cleanly on the tile.

*Alert row, after.* Alerts are **cards, not rows** in this direction — a Tines-style list of
`--surface` cards at 12 px radius, 12 px gap, each with: the type tile of the device on the
left; line 1 `md 500` summary with the severity badge inline after it; line 2 `sm --text-2` the
reasons; line 3 `xs --text-3` device · site · 7 m ago; on the right *Acknowledge* secondary
(rounded 8 px) and `⋯`. High-severity cards get a 3 px `--danger` top rule (not left — cards
read top-down). Grouped alerts become one card with a `▸ 6 more like this` disclosure. The
table's column-tools (`tables.js`) do not apply to cards, so the *Columns* button goes away on
this page — a real functional loss for people who sort by score; a *Sort ▾* menu on the toolbar
replaces it.

**Cost and risk.** The largest of the three by a clear margin. The Topology page is a new
renderer (pan/zoom, bezier cables, card nodes, type grouping, popover tooltips, traffic dots with
data plumbing from the Trends sampler): 6–8 days on its own. The Alerts page changes DOM shape
(cards), which touches `tables.js`, bulk selection, the acknowledge flow and the smoke test
(`tools/ui-smoke.mjs`): 3–4 days. Re-theme, font, radius and elevation pass: 6–8 days. Per-type
tile colours need a type → colour map in one place and the `.iconbadge` change everywhere it is
used. **Roughly 4 × the incremental path: 24–32 days.** Risks: (1) it is the direction most
likely to be *wrong* for the audience — an OT site manager may find a friendly warm canvas less
trustworthy than a grey one, and there is no cheap way to test that before building it; (2) the
canvas interaction model (pan/zoom) is a new class of bug on touch devices and at 375 px; (3)
cards for alerts throw away column sorting and the acknowledged-row dimming that operators rely
on; (4) `offset-path` on SVG bezier paths has uneven browser support (fine in Chromium and
Firefox, verify Safari 17+); fall back to SMIL `animateMotion`.

## Part 3: comparison and recommendation

| | Incremental (DESIGN_LANGUAGE.md) | A Ink | B Deep Field | C Workbench |
|---|---|---|---|---|
| Effort | 6–8 days | 8–10 | 18–24 | 24–32 |
| New JS | overflow menu | orbit/pulse/skeleton module; `applyBranding` split | starfield lifecycle; density + motion toggles; traffic overlay | new topology renderer; alerts as cards; traffic dots |
| Webfont | none | Geist Sans + Mono (~200 KB) | Inter + JetBrains Mono (~250 KB) | Madefor Text + Plex Mono (~250 KB) |
| Binary growth | 0 | +0.2 MB | +0.25 MB | +0.25 MB |
| Light / dark parity | equal | equal by construction (inverted scale) | dark-first; light needs deliberate care | light-first; dark needs deliberate care |
| Survives a weak operator accent | yes | best (accent is only links) | worst (accent is structural) | middling |
| Density | today | today | higher (13 px, 36 px rows) | lower (44 px rows, cards) |
| Topology motion | none | orbit + draw-in + alert pulse | starfield + beacon + traffic flow | pan/zoom + traffic dots |
| Functional regressions | none | none | none | column tools on Alerts |
| Distance from today | small | medium | large | very large |

**What I would actually pick: Ink (A), and only the Topology motion from Deep Field (B), as a
second, separately-flagged step.**

Reasons, in order of weight:

1. **Ink is the only direction that is a superset of the incremental path.** Steps 1–6 of
   DESIGN_LANGUAGE.md are its first six days unchanged; the font, the black-button split, the
   mono columns and the motion module are four more. If the redesign stalls halfway, the console
   is in the incremental proposal's state, which is a good state. Deep Field and Workbench are
   not like this: half of either is worse than none.
2. **It is the direction that respects what DENIS is.** The console's value is that a red dot is
   visible among grey ones. Ink makes every colour a signal. Deep Field does too, but at the
   price of being dark-first for a product whose operators mostly sit in offices with windows;
   Workbench spends colour on device types, which is useful but dilutes the one signal that
   matters.
3. **It survives branding.** Operators set an accent; in Ink that accent colours links and the
   active item and nothing else, so nobody can brand their console into an illegible state. In
   Deep Field a pale accent is a primary button nobody can read.
4. **Its risk is a font file.** Everything else is CSS on the existing DOM.

On the starfield specifically: Stefan asked for it and the design in B is the version worth
building — the legibility rules (exclusion radius around nodes and spokes, alpha falloff under
the graph, label strokes, freeze on lost connection, stop when not visible, reduced-motion and a
user toggle) are what separate "stars in space" from a screensaver. It works on Ink's dark canvas
(`#0a0a0a`) as well as on Deep Field's navy — the sky is neutral either way — and on Ink's light
canvas it becomes the static dot grid. It is one CSS rule plus one ~120-line JS module with its
own lifecycle, and it should ship behind the *Ambient motion* toggle, off by default for the
first release, on by default once the CPU number has been measured on a real site. **That is the
concrete recommendation: A, then B's starfield as an opt-in module, and nothing from C for now.**

**The case for staying incremental,** stated plainly because it is real: the two measured
accessibility defects, the eleven font sizes and the ten radii are fixed by the incremental
proposal alone, and none of the three directions fixes a problem that proposal leaves open.
What a full direction adds is *identity* — the console looking like a product someone chose, not
a default — and identity is worth paying for only if the product is being shown to people who
have not bought it yet. If the next six months are about existing installations, the
incremental path is enough and the eight extra days are better spent on UX_REVIEW.md findings 1,
3 and 8. If the next six months include a public launch, screenshots on the website and
comparison against Wiz-class consoles, Ink's extra four days are the cheapest identity the
project will ever buy, and they should come after the incremental steps, not instead of them.

Workbench is the direction to come back to if the Topology page ever becomes the product (for
example if NAC.md's per-port actions land and operators start *doing* things on the map rather
than reading it). At that point a workbench canvas is justified by function, and its cost is
paid by the feature, not by the redesign.

## What to verify before choosing

* Render `Devices`, `Alerts` and `Settings → Switches` once per direction as static HTML
  mock-ups (a day for all three, no JS) and look at them on the actual monitor an operator would
  use, in both themes, in German. Every decision above that is a taste call becomes obvious in
  ten minutes with the three side by side and stays arguable forever on paper.
* Subset each candidate font to the five languages' character sets and record the WOFF2 sizes
  and the Slovak glyph check; the numbers above are estimates.
* Prototype the starfield alone on today's Topology page behind a query-string flag and
  measure CPU with two sites of 100+ nodes at 24 fps and 12 fps before designing anything else
  around it.
* Re-measure every contrast pair in Part 2 with the operator's own accent substituted, as
  DESIGN_LANGUAGE.md §7 already asks; the direction that fails is the one that made the accent
  structural.
