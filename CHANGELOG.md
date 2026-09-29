# Changelog

## 2.34.1: Fix ChatGPT explain/triage/recommend: wrong token-limit parameter

* **Every ChatGPT (OpenAI) call was failing** with a 400 from OpenAI, invisible until v2.33.0's own
  fix started surfacing provider error bodies: `gpt-5-mini` rejects the `max_tokens` request field
  outright ("Unsupported parameter: 'max_tokens' is not supported with this model. Use
  'max_completion_tokens' instead."). Found live, from a real account's own key, right after the
  error-surfacing fix made it visible for the first time. Fixed by sending `max_completion_tokens`
  for OpenAI specifically; Grok (x.ai), which uses the same request shape, keeps `max_tokens` — it
  is a different provider and does not have this restriction. Claude and Gemini were never
  affected (different request shape entirely).

## 2.34.0: Dashboard AI summary (step 5), and a real exceptions bug

* **A new "AI Security Summary" card on the dashboard**: a short, plain-language overview of the
  last day's alert activity, generated entirely by a background job — never by opening or
  refreshing the dashboard, which only ever reads what is already stored. The job wakes every 10
  minutes, checks whether the alert stream has moved on since the last summary, and if so (and
  only if the feature is on) generates exactly one new summary from severity counts plus the
  highest-scored individual alerts in the window — never the raw alert stream. A burst of alerts
  inside one 10-minute window still produces at most one AI call. The card always shows the last
  valid summary, with "Generated 8 minutes ago", even while a new one is being written or a
  generation attempt has failed — it is never left blank. Its own independent Settings → AI →
  Features toggle, off by default.
* **Fix: adding an exception for an "Agent offline" alert failed with `unknown rule "agent_offline"`.**
  `agent_offline` (and `arp_mismatch`) are real alertable event kinds — each borrows another
  rule's own scoring weight rather than having one of its own, so neither was ever added to the
  formal `RULES` list, but the actual exception-filtering logic (`notify.rs`) matches by the raw
  event kind regardless of `RULES` membership. The settings validation for `exceptions`
  specifically was checking `RULES` membership too strictly, rejecting a device-scoped exception
  on either kind even though it was already meaningful and already worked once saved.
  `weights`/`min_scores` are unaffected — those genuinely only apply to `RULES`.

## 2.33.0: AI recommended actions (step 4), and two real AI bugs found live

* **A new "Recommended actions" button on alerts**: a short, advisory list of 1–8 concrete next
  steps (e.g. check DNS history, compare with similar devices, consider isolating the device) —
  DENIS never acts on any of them itself. Distinct from triage's own single-sentence
  `recommended_action` (spec section 15 is its own capability). Its own independent toggle in
  Settings → AI → Features, off by default. `ai::parse_recommended_actions` validates the
  provider's JSON the same way `parse_triage` does (tolerant of markdown fencing or prose around
  it, rejects an empty or all-blank list as a hard error, caps an over-long one at 8 rather than
  failing outright).
* **Two real bugs found and fixed while diagnosing a live "Explain with AI" failure** (thank you
  for the live access to check):
  * **A non-2xx response from an AI provider silently lost its own error message.** ureq's default
    `http_status_as_error` turns any 4xx/5xx into a bare `StatusCode(code)` with the body already
    discarded, so a provider's actual reason (bad model name, over quota, a malformed request) never
    reached the administrator — only a generic "answered with an error", which then became an
    equally generic "Request failed (502)" once the console's error box couldn't parse anything more
    specific out of it. Fixed: the real status and the provider's own error body are now read and
    surfaced in full.
  * **The "Explain"/"Triage"/"Recommended actions" buttons rendered a literal "null" next to
    themselves** whenever only one provider was configured (so no provider picker was needed).
    `Element.append(null, button)` — unlike this codebase's own `el()` helper — stringifies a `null`
    argument into a real text node reading "null" instead of skipping it. Fixed in all three
    buttons.

## 2.32.0: AI alert triage (step 3 of the AI assistant)

* **A new "Triage with AI" button on alerts**, alongside the existing "Explain with AI": an
  assessment (**likely benign** / **suspicious** / **requires investigation**) with a confidence
  score, reasoning and a suggested next step — an *additional* signal shown next to DENIS's own
  severity, never a replacement for it. On click only, same bar as alert explanations, sending the
  same compact alert context (summary, scored reasons, device label) and nothing more.
* Its own independent toggle in Settings → AI → Features, off by default, alongside the (now also
  independent) alert-explanations toggle — enabling one never enables the other.
* **The provider's answer is validated, not trusted.** `ai::parse_triage` extracts a JSON object
  from the response (tolerant of markdown code fences or prose wrapped around it, since that's a
  common way a model fails to follow "reply with JSON only") and checks the assessment against a
  fixed set of three values — an assessment outside that set is a hard error, never guessed at,
  so nothing downstream can be driven by text a provider invented. Confidence is clamped to `[0,1]`.
* `GET /api/ai` now reports `alert_explanations`/`alert_triage` as independent flags rather than
  overloading the single `providers` list as the on/off signal for one feature — the design that
  worked for exactly one feature didn't scale to a second.

## 2.31.0: Settings → AI — a global switch and per-feature control (step 1 of the AI assistant)

* **A dedicated Settings → AI page**, replacing the AI provider configuration that used to live
  under Settings → Integrations. First of several planned steps for the "AI security assistant"
  roadmap item (see AI.md), shipped on its own so it's immediately usable rather than held back
  until the whole thing is done.
* **A global "Enable AI features" switch**: while off, DENIS never calls any AI provider for
  anything, no matter what is configured underneath — enforced server-side (`web_ai.rs`'s
  `explain` handler refuses directly, not just the button hiding), not only in the UI.
  **Alert explanations** — the existing "Explain with AI" feature — gets its own toggle
  underneath, independently switchable now that there's a place for it.
* **Existing installs keep working exactly as before, without a manual step.** An install that
  already had a provider key configured never had a separate toggle — the button just worked once
  a key was set. `ai::load` now recognizes that exact case (the stored config literally predates
  the new fields) and infers both switches on, so upgrading never silently disables something that
  already worked. A fresh install still defaults fully off — the administrator opts in explicitly,
  same as the spec asks.
* This is deliberately narrow: only the settings page and the one existing feature moved under it.
  Every other capability in the spec (triage, incident correlation, the dashboard summary, "Ask
  DENIS", threat hunting, recommended actions, security reports, a detection-rule assistant) is
  still unbuilt — see AI.md's own build order for what's next.

## 2.30.0: A documented public API — API-token rate limiting, and a stability commitment

* **API tokens now have real rate limits.** Found while scoping the "documented public API" roadmap
  item: `dnt_` console tokens had no throttling at all, unlike the separate agent protocol. Fixed —
  a valid token is capped at 300 requests/minute (a sliding window, generous enough for any
  reasonable polling interval, meant to catch a runaway loop or a compromised token); repeated
  *wrong* tokens from one address are throttled after 10 failures in 60 seconds, independent of any
  one token's own limit. Both answer `429 {"code": "rate_limited"}`.
* **`docs/api.md` is now genuinely complete and makes an explicit stability commitment.** Added the
  CMDB/Active Directory/Jamf Pro endpoints and site deletion, which were missing from it. A new
  "Stability" section makes a deliberate choice instead of leaving it unstated: the console UI's own
  API *is* the public one — no separate curated subset, no `/api/v1/` version prefix. Response
  shapes are additive-stable, not frozen (a new field can appear; an existing one keeps its name),
  and `Event.raw_details` is called out as intentionally free-form per alert kind. Chosen over
  inventing a parallel versioned surface because nothing about this product's real usage yet
  demands one.
* This closes the "documented public API" roadmap item: the auth (viewer/editor `dnt_` tokens),
  routing and docs scaffolding all already existed — real work here was closing the rate-limiting
  gap and making the stability question explicit, not building new infrastructure.

## 2.29.0: CMDB import: Jamf Pro (fourth source)

* **CMDB import now also pulls computer inventory from Jamf Pro** (Settings → Integrations → CMDB
  import), alongside the existing Entra ID, Intune and Active Directory sources — entirely
  independent: its own enable toggle, its own credentials (a Jamf Pro API client id/secret, the
  API-client/OAuth2-client-credentials model Jamf now recommends), its own sync schedule. Matched
  to DENIS's own discovered devices the same way as the other three sources — exact,
  case-insensitive hostname only, read-only, shown as extra context, never used to override a
  device's own fingerprinted identity.
* Reused almost the entire shape the last three sources already established: the same `ureq`-based
  HTTPS client and OAuth2 client-credentials token fetch as the Graph sources, the same
  hostname-matching/upsert logic and source-scoped pruning (a Jamf sync can never delete an Entra
  ID/Intune/AD-sourced row, or vice versa) as all three. The genuinely new work was Jamf's own
  pagination shape (`page`/`page-size`/`totalCount` rather than Graph's `@odata.nextLink`) and
  token endpoint.
* Like every CMDB source before it, this has been tested against hand-built fixtures matching
  Jamf's documented API shape, not yet against a real Jamf Pro instance — see CMDB.md for the full
  "what was verified, what wasn't" accounting this extends.
* Also: the roadmap now includes a new item, an "AI security assistant" (a configurable,
  event-driven layer on top of the existing AI alert explanation feature), with the full received
  specification recorded in a new AI.md — not built yet, scheduled after the public API per an
  explicit priority call.

## 2.28.0: IPv6 — remote-agent reporting, an active liveness check, and CSV/API exposure

* **Remote agents now report IPv6 flows to their master**, not just a local/embedded collector:
  `agent::Reporter` gained a second, parallel spool (`spool_v6`) with the same bounded,
  at-least-once, unacknowledged-until-acked delivery guarantee as the existing IPv4 one, and
  `Report.flows_v6` carries them over the wire (absent from an older agent's report, same
  convention as `signals`/`conversations`). The master feeds them into `new_destination_v6` exactly
  like the embedded collector's own path already did.
* **An active liveness check for IPv6** (`active::icmp_sweep_v6`): every scheduled sweep now also
  sends an ICMPv6 echo to every *already known* global IPv6 address (skips link-local addresses —
  routing one needs an interface scope id — and industrial devices, same rule as the IPv4 sweep).
  Deliberately narrower than full active discovery: this can only refresh staleness for an address
  already learned passively, never find a brand-new one (that needs joining solicited-node
  multicast groups, a materially bigger mechanism — see IPV6.md). Chosen over the fuller mechanism
  after asking directly: real packets on a real network is a meaningfully different risk than
  everything shipped so far, so the safer, smaller option was picked on purpose, not by default.
* **CSV export and the API already show IPv6 data.** The Devices CSV gained an `ipv6` column.
  The per-device baseline endpoint and its reverse-DNS/GeoIP/ASN enrichment needed **no code
  change at all** — both already work generically on `Baseline.typical_destinations`' plain string
  keys, so an IPv6 destination was already exposed correctly; added a regression test to lock that
  in rather than leave it merely assumed.
* Also: the roadmap's IPv6 item now reads 3/10 effort remaining (down from 7/10 at the start of
  this work) — what's left needs either real alert-noise/incident data to design well (rule parity
  with IPv4, an NDP-mismatch signal, conflict/gateway detection) or is a materially larger
  mechanism (full active discovery via multicast). See IPV6.md for the complete accounting.

## 2.27.0: IPv6 flow accounting and its first detection rule, opt-in

* **DENIS can now account IPv6 traffic and raise its first IPv6-aware alert**, behind the new
  `--ipv6-subnet` flag (repeatable, alongside `--ipv6` and `--flows` — the IPv6 analogue of
  `--mirror-subnet`, needed because an IPv6 interface can carry several global prefixes plus a
  permanent link-local one at once, with no single "the subnet" to infer automatically). A new
  rule, **New destination (IPv6)**, flags a device's first contact with an outside IPv6 address it
  has never used — the IPv6 counterpart of the existing "New destination" rule.
* Built as a **parallel** set of types (`FlowRecordV6`, `FlowSampleV6`, a second map inside
  `FlowAgg`) rather than widening the existing IPv4 ones — the same "parallel, not merged" choice
  already made for `ip_history`/`ipv6_history` — so the entire, heavily-tested IPv4 flow-accounting
  and detection path is untouched by this change. The new rule shares the *same*
  `Baseline.typical_destinations`/`typical_ports` maps as IPv4 (already generic, string-keyed), so
  one device's learning period and destination cap cover both address families together.
* Deliberately simpler than IPv4's `new_destination` for now, and documented as such (IPV6.md): no
  rotation-burst suppression yet (the IPv4 version exists because of real alert-noise data this
  project doesn't have for IPv6 yet — see v2.20.0), no `new_port` rule, no OT-over-IPv6 decoding,
  the threat list and network watches do not see IPv6 flows yet, and a remote agent does not yet
  report IPv6 flows to a master (only a local/embedded collector's own traffic is covered today).
* Also: the roadmap's remaining items are now explicitly reordered by priority (see ROADMAP.md),
  with rough effort estimates (1-10) on each, and the previously one-line "Policy enforcement
  (NAC)" item broken out into an actual ordered list of which network vendor to integrate with
  first (SNMP port shutdown, then RADIUS CoA, then pfSense/OPNsense/UniFi, then the major commercial
  firewall vendors roughly by fit for DENIS's own SMB/homelab-leaning audience).

## 2.26.0: IPv6 groundwork — passive device discovery, opt-in

* **DENIS can now passively discover IPv6 addresses**, behind a new `--ipv6` flag (off by
  default — every existing installation's capture is unchanged unless this is turned on).
  Neighbor Discovery (NDP), IPv6's replacement for ARP, is decoded the same way ARP already is:
  a Neighbor Advertisement whose Source Link-Layer option agrees with its own frame's Ethernet
  source is trusted as a real (MAC, address) binding, folded into a new "IPv6 addresses" section
  on the device panel (read-only for now). Unlike an IPv4 address, there is no single "current"
  IPv6 address — a device keeping both its permanent link-local address and one or more global
  ones at once is normal, not a conflict, so all of them are kept.
* Trusting a Neighbor Advertisement needed no subnet-membership check the way ARP's does: NDP
  requires an IP hop limit of exactly 255, and a conforming host discards anything with a lower
  one (a router would have decremented it) — so anything this reaches was necessarily sent by a
  device on the same physical link, by protocol guarantee, not a heuristic. This resolved one of
  the two open questions from IPV6.md's own scoping (its item 6) for the passive-discovery case,
  without needing to invent what IPv6 subnet membership means in general.
* This is deliberately a narrow, groundwork-only slice: no active IPv6 discovery yet (a /64's
  address space makes an ARP-sweep-style approach meaningless), no IPv6 in flows, detection rules
  or CIDR-based rule scopes, no NDP-mismatch signal analogous to `arp_mismatch`. See IPV6.md for
  the full "done vs. not done" accounting, and ROADMAP.md for what's next.
* Also: every remaining roadmap item has been consolidated into a single priority-ordered list
  (the old, separate "features competitors have" section drifted out of sync with "next up" more
  than once, so it's gone now) — three new items added on their own merit: vulnerability-scanner
  import (Qualys/Tenable/Nessus), cloud asset discovery (AWS/Azure/GCP), and a documented public
  API for third-party integrations.
* README's "Security and limitations" section refreshed: the master/agent-across-a-real-network
  item is now verified (done in v2.25.0's release testing), SSO and IPv6 moved from "does not
  exist" to "exists, here's exactly what's still unverified", stale module-map/schema-version
  entries fixed.

## 2.25.0: Delete a site from the console, configure the agent listener from Settings, and fix two real bugs from live testing

* **Sites can now be deleted from the console** (Settings/Sites page, admin-only): removes a whole
  remote site and every device it reported — findings, baselines, presence, the communications
  matrix, events — with the site id typed back to confirm, since this throws away real observed
  history (the agent's own token is untouched; revoke it separately if it should never report
  again). Found, while designing this, a real correctness risk worth building around rather than
  shipping past: the live collector's in-memory `Detector` holds its own copies of a device's
  baseline, presence and conversation-matrix rows, written back to the store on every periodic
  flush — deleting straight from the store while a collector runs would have had the deleted
  devices silently reappear a few ticks later. Fixed with a new `Detector::forget_assets` and a
  dedicated engine channel, the same pattern already used for live baseline edits.
* **The agent listener (`--ingest-listen`) can now be configured from Settings → Network
  interfaces**, not just the CLI flag — found missing during real cross-border master/agent
  testing this week (a paid VPS in a different country, reporting back to a home master over
  Tailscale): turning it on needed hand-editing the systemd unit and a restart, with no portal
  option at all. Same "never store a value that would crash-loop the next restart" validation as
  interface names already get: the address is actually bound (then released) before being saved.
* **Fixed a real gap in the `lan_scan` alert** (Internal network scan), reported directly from a
  live alert that only said "*device* contacted 4 different addresses" with no way to tell a
  security scanner from a legitimate discovery/backup tool without digging through raw flow logs:
  the alert now lists the actual addresses (or ports, for a single-address port scan) it saw,
  capped at 20 with a "+N more" tail, both in the human-readable reason text and as structured
  `contacted_addresses`/`contacted_ports` fields.
* Fixed a stale-URL-hash bug, also reported directly from real use: switching screens via the
  sidebar left the previous screen's hash (e.g. `#settings/system`) sitting in the address bar,
  so a page reload could land back on a screen the person had long since left. Clicking a tab now
  updates the address bar to match.
* Verified for real this cycle (see ROADMAP.md's "Verification still owed"): master/agent
  reporting across a real network, a genuine agent built from source and run on a remote VPS in a
  different country.

## 2.24.0: CMDB import — Active Directory (on-premises, LDAP/LDAPS)

* CMDB import (Settings → Integrations) can now also pull computer objects from an **on-premises
  Active Directory domain**, over LDAP/LDAPS, alongside the existing Entra ID and Intune sources —
  entirely independent of those two: its own enable toggle, its own credentials (a bind DN and
  password against a domain controller — a dedicated read-only service account is strongly
  recommended over a real administrator's own login), its own sync schedule. Matched to DENIS's
  own discovered devices the same way — exact, case-insensitive hostname only, preferring
  `dNSHostName` over the bare `name` attribute — read-only, one-directional, shown as extra
  context, never used to override a device's own fingerprinted identity.
* New dependency: the `ldap3` crate (its synchronous `LdapConn`, not the tokio-async client —
  matching how this codebase's other optional integrations already run their blocking I/O inside
  `spawn_blocking` rather than pulling in a second async runtime).
* Fixed a real bug uncovered while building this: `cmdb.rs`'s own Entra ID/Intune sync originally
  assumed it was the only writer to the shared imported-device table, and its "forget devices no
  longer present" pruning would have silently deleted Active Directory's rows on its very next
  run. Both sources' pruning is now scoped to their own rows only.
* Also fixed: `Settings::default()` for both the Entra ID/Intune and the new Active Directory
  settings reported `sync_interval_hours: 0` for a never-configured install rather than the
  intended 24 — `#[derive(Default)]` doesn't see a field's `#[serde(default = "...")]` attribute,
  they solve different problems that happen to look similar. The UI never showed this (it already
  had a `|| 24` display fallback), but the raw API response did.
* See [CMDB.md](CMDB.md) for the full "what was verified, what wasn't" honesty accounting, same
  bar as [SSO.md](SSO.md) — this was, until this release, entirely undocumented (see v2.23.0).

## 2.23.0: CMDB import — Intune managed devices

* CMDB import (Settings → Integrations) can now also pull **Intune managed devices**
  (`/deviceManagement/managedDevices`), alongside the existing Entra ID device import shipped in
  v2.18.0. A new checkbox, "Also import Intune managed devices", reuses the same app registration,
  tenant and client secret already configured — it just needs the additional
  `DeviceManagementManagedDevices.Read.All` application permission granted alongside
  `Device.Read.All`. Matched to DENIS's own discovered devices the same way as Entra ID devices —
  exact, case-insensitive hostname only, read-only, one-directional. Each imported device now
  shows which source it came from (Entra ID or Intune) in the device list.
* Entra ID and Intune device objects live in separate Graph GUID spaces for what may be the same
  physical device, so imported records are now keyed by `<source>:<id>` (`entra:...`,
  `intune:...`) to guarantee the two can never collide or overwrite each other in the store. A
  record saved before this existed (every Entra ID import through v2.22.0) still reads back
  correctly, defaulting to `entra`.

## 2.22.0: Enforcing passkey-only sign-in, and Settings now opens on System

* **Passkey-only sign-in** (Settings → Sign-in & security → "Passkey-only sign-in for"): a new,
  independent policy alongside the existing "who must use a second step" one. Once someone
  covered by it has actually added a passkey, their password stops opening a session at all —
  only the passkey does. Nobody is ever locked out by turning this on: the password keeps working
  right up until the person has set a passkey up, so bootstrapping a team onto it is always safe.
  A wrong password for a passkey-only account still gets the same generic "invalid username or
  password" as any other account — the stricter refusal only ever follows a *correct* password,
  so nothing new is guessable. The passkey sign-in flow itself needed no changes: it was already
  fully passwordless and username-less (a discoverable/resident-key WebAuthn flow, `allowCredentials: []`)
  since it was first built — this release is entirely the *policy* layer, plus fixing the
  settings storage underneath it to merge instead of silently overwriting sibling fields when two
  independent policies share one settings blob.
* Settings now opens on **System** by default, not Sign-in & security — the first thing an
  administrator sees when they click Settings is license/updates/restart/setup guide, not a
  security sub-page.

## 2.21.0: New rule — internal network scan (host sweep / port scan) detection

* A new built-in rule, **Internal network scan** (Rules → Network rules), flags a device that
  suddenly contacts many different addresses, or many different ports on one address, on your
  own local network in a short time: the actual signature of a host sweep or port scan, not
  ordinary traffic. Judged by breadth rather than connection success/failure (DENIS's flow
  records carry no TCP handshake state), consistent with the rest of the rule engine's "simple,
  explainable" style. Not subject to the learning period — a scan is abnormal on day one too.
  Needs traffic analysis on a mirror port, the same requirement as the OT rules, since seeing
  device-to-device LAN traffic (not just the collector's own uplink) needs a span/mirror port.
  Tunable like every other rule: the judging window, how many distinct addresses count as a
  sweep, how many distinct ports on one address count as a scan, and the cooldown between alerts.
* Closes a real gap found while answering "does DENIS tell me if a device on my network is
  scanning it?" — no. `new_device_burst` catches many *new devices* arriving quickly (an external
  scan/ARP-flood signature), but nothing previously flagged an already-known device suddenly
  probing many other local hosts or ports, the signature of a compromised device doing
  reconnaissance. See ROADMAP.md.

## 2.20.0: Alert noise — auto-detect rotating/pool-style destinations, and give custom watches the same protection

* `new_destination` no longer needs a port to be on a hardcoded list (previously just NTP/STUN,
  ports 123/3478) to recognise a rotating/pool-style service. It now watches each device's own
  behaviour: several distinct destinations on the same port in a short burst (a CDN edge, a
  relay, a broker handing out a fresh address per session) auto-promotes that port to "rotating"
  for that device, after which it stops repeating the alert — exactly like the built-in NTP/STUN
  case, just learned per device instead of declared up front. A device that instead picks up one
  genuinely new, unrelated destination every so often, spread out well beyond the burst window,
  is never promoted and keeps alerting normally: that spread-out pattern is the one actually worth
  an admin's attention.
* Your own network watches (`it_watch`) get the equivalent protection for the first time. Until
  now a watch's only anti-repeat mechanism was a flat cooldown per exact (device, address, port) —
  so a watch like "cameras talking to the internet" re-alerted for every single new CDN/cloud IP
  the camera's own service handed out. It now recognises the same rotating-burst pattern per
  (device, watch, port) and stops repeating for further new addresses once one is detected, while
  a device this watch already knows about still alerts normally once its own cooldown lapses.
* Diagnosed and grounded in a real 434-alert export from a 20-device home network (see
  ROADMAP.md): one camera alone produced 117 `new_port` alerts to 2 already-known relay servers,
  and 86 of 130 `new_destination` alerts were CDN (TCP/443) or NTP-pool (UDP/123) rotation, not
  new relationships. The `new_port`-to-a-known-destination cap and the NTP/STUN allowlist already
  existed since v2.0.1/v2.0.2; this release is the generalization past that hardcoded 2-port list,
  plus giving custom watches the protection the two built-in rules already had.

## 2.19.0: Unified "Exceptions, accepted risks & baseline" view, grouped by device

* The Rules page's "Exceptions & accepted risks" tab is renamed **"Exceptions, accepted risks &
  baseline"** and also reachable as its own sidebar sub-page under Rules (same pattern as the
  Settings categories), alongside the existing in-page tab.
* Its content is restructured: exceptions scoped to a device type, tag or network stay in their
  own "Network-wide exceptions" list (they cannot be attributed to one device), but everything
  else — rule exceptions on a specific device, OT/network watch allow-lists, accepted risks, and
  learned baseline destinations — is now grouped into a single "By device" table, styled like the
  Devices page. Clicking a device row expands it in place to show everything for that device
  together; clicking the device's name instead opens its own Asset panel directly. "Expand all" /
  "Collapse all" sit next to the table's own column controls.
* One search box now searches everything on the page at once — device name, MAC, IP, network,
  rule name, watch name or finding title — instead of the two separate search boxes this replaces.
* Fixed a real bug along the way: accepted risks were read from a global (`acceptedRisks`) that is
  only populated once the Findings tab has been visited in the current session, so a device
  present in this view only because of an accepted risk could silently disappear on a cold visit
  (e.g. following a bookmark straight to Rules). Now fetched fresh every time this view loads.

## 2.18.1: Fix — removed the manual IP lookup tool added in 2.18.0

* "Look up an address" (Settings → Network Intelligence) is removed again: on reflection it added
  a control surface without enough real use on its own — the console still cannot observe real
  IPv6 traffic (see ROADMAP.md), so a person typing an address in by hand was the only way it was
  ever reached. Nothing else about 2.18.0 changes.

## 2.18.0: CMDB import (Entra ID), an IPv6 address lookup tool, and a better exceptions/baseline workflow

* **CMDB import**: Settings → Integrations → CMDB import pulls device inventory from Microsoft
  Entra ID (an app registration with the `Device.Read.All` application permission, app-only
  auth) and cross-references it against DENIS's own discovered devices by hostname. Read-only and
  one-directional — nothing is ever written back to Entra ID, and a match is shown as extra
  context (OS, compliance state, when Entra last saw it), never used to override a device's own
  fingerprinted identity. Syncs on a schedule (default daily) or on demand. The first of the
  Active Directory/Entra ID/Intune/MDM family named in the roadmap — picked first because it needs
  no on-prem LDAP reachability and no separate Intune licence.
* **Look up an address** (Settings → Network Intelligence): check any IP address by hand, IPv4 or
  IPv6, the same full detail panel a click on an address anywhere else in the console opens. A
  first, safely-scoped piece of real IPv6 support: GeoIP, reverse DNS and classification already
  handle IPv6 addresses correctly (verified with a real IPv6 address) — this is simply the first
  place in the console a person can actually type one in, since capture/flow tracking itself is
  still IPv4-only (see ROADMAP.md for the full scope of what that still needs).
* Learning mode is now called **"Continue learning mode"**, not "Restart" — a plainer name for
  what it actually does (only pauses alerting for a window; a device's baseline keeps
  accumulating underneath it regardless, never reset). "Forget all learned baseline data" moved
  from Settings onto the Rules page, right next to it, since that is where an admin is already
  thinking about the distinction between the two.
* The Exceptions & accepted risks tab gets its own search box (by device, network, rule, watch or
  finding), and the learned-baseline search below it is now grouped by device — a device heading
  with its own destinations underneath, rather than one flat list repeating the device name on
  every row.
* A device's own panel gets an **"Exceptions & baseline"** button: jumps straight to the Rules
  page's Exceptions tab with both search boxes already filled in for that one device.

## 2.17.0: One place for every exception and accepted risk, and a searchable baseline across all devices

* Exceptions and allow-lists used to live in three separate places with no shared view: rule
  exceptions, OT/network watch allow-lists, and accepted risks from Findings. **Rules → Exceptions
  & accepted risks** now lists all three together — what it is, which rule/watch/finding it
  belongs to, and a "×" that removes it exactly the way removing it from its own place already
  did. Nothing about where any of it is stored changed; this is a view, not a migration.
* The same tab adds a **searchable, all-devices view of learned baseline destinations** — one
  search box (device name, MAC, device IP, or destination IP) instead of opening devices one at a
  time to find and remove something. New `GET /api/baseline/destinations` endpoint: searches
  server-side and caps what comes back (200 by default, 1000 at most, with a plain "N matched, N
  shown" count) rather than ever shipping a whole network's baseline in one response — a busy
  device alone can hold up to 2000 learned destinations.

## 2.16.0: Edit a device's learned baseline — remove one destination, or forget it all

* A device's traffic baseline can learn something wrong during a learning period, and the only fix
  used to be restarting learning for the *entire* network — far too blunt. A device's Asset panel
  now has a small "×" next to each entry under "Recent destinations": removing one means the next
  time that device talks to that address, it is judged fresh again, exactly like it never learned
  it. Admin-only, asks for confirmation first.
* New **Settings → Demo data and reset → "Forget all learned baseline data"**: wipes every
  device's learned traffic baseline network-wide (destinations, ports, volume, active hours) in
  one step, without touching devices, alerts, the communications matrix or anything else — for
  when a whole-network reset is genuinely what is needed, not just a grace period. Needs the exact
  confirmation phrase typed out first, same ceremony as "Erase all data".
* Cleared up a real point of confusion: "Restart learning mode" only pauses alerting for the
  window you choose — it does **not** reset or rebuild a device's baseline. New destinations and
  ports keep being learned underneath it exactly as always (verified directly against the
  detection code, not assumed). The Rules page now says so explicitly, and points at the new
  "Forget all learned baseline data" button for anyone who actually wants a clean slate.
* Fixed correctly for the case a collector is running live: baseline edits go through the same
  in-memory detector the capture pipeline uses, not just the stored row, so a live install's
  periodic baseline flush can never silently undo one of these edits a few seconds later.

## 2.15.5: The reverse-DNS hostname gets its own line, and the click-through panel's flag is fixed too

* The reverse-DNS hostname (usually the longest part of an IP's context by far) now sits on its
  own line under the flag/AS-organisation/ASN line, instead of crowded onto the same one — in
  Alerts, Events, a device's Recent destinations and its IP history alike, since they all share the
  one component this changes.
* The click-through detail panel (opened by clicking any IP) had the exact same "flag never
  renders" bug 2.15.3 fixed for the inline line — it was still reading the country's full name
  instead of its ISO code. Fixed the same way.

## 2.15.4: Fix — old cached IP lookups were stuck showing nothing (or no flag) for up to 30 days

* Found via a live report: some addresses in "Recent destinations"/"Network context" showed a
  full country/ASN line, others showed only a reverse-DNS hostname or nothing at all — for the
  same device, at the same time. Root cause: the GeoIP cache's 30-day TTL does not know a fresher
  answer might exist for a reason other than time passing. Two rollout-created shapes of old cache
  row were stuck this way until their TTL happened to expire: rows written back when there was no
  GeoIP database installed at all (2.15.1 and earlier, or an upgrade that never ran an update), and
  rows written after 2.15.2 but before 2.15.3 added the ISO country code the flag needs. Both are
  now recognised and refetched immediately instead of waited out — confirmed live against a
  database that had exactly this stale mix (previously-empty and previously-flagless rows both
  came back complete on the very next lookup, no cache flush or restart needed).

* **GeoIP database now auto-updates itself**, on by default (monthly) — turned on for the exact
  reason 2.15.2 needed a manual "Update now" click at all: nobody should have to find that button
  for the database to ever exist. Settings → Network → Network Intelligence gets an "Automatically
  update" switch and a Daily/Weekly/Monthly choice; turning it off goes back to on-demand only.
* The flag next to a country was never actually a flag — the field it read was the country's full
  name ("United States"), not the two-letter code the flag emoji needs, so it silently rendered
  nothing. GeoIP lookups now carry the real ISO country code too. The flag comes first in the IP
  context line, with the country's name as a hover tooltip rather than spelled out in text, then
  AS organisation, ASN and the reverse-DNS hostname — the hostname is now part of this inline line
  itself, not only the click-through detail panel.
* A destinations row's timestamp/byte count now sits on the same line as the IP address, instead
  of floating at an inconsistent height depending on whether a context line happened to be present
  underneath it.
* CISA/NVD known-exploited-vulnerability refresh (previously an opt-in "heavier" background job)
  is now on by default alongside the existing support-dates refresh, so a fresh install's Findings
  reflect real, current threat intelligence from day one rather than an empty page until someone
  finds the switch.
* Learning mode's box on the Rules page no longer keeps showing stale Pause/End controls once a
  learning period naturally finishes on its own — it now re-checks right when the countdown ends
  and redraws as "Restart learning mode", the same as it always did after an explicit "End now".

## 2.15.2: Fix — GeoIP data was never actually downloaded, and stale "Network context" in single-IP views

* Found the real cause of a live report of a completely blank "Network context" in production: the
  DB-IP Lite **download** itself had never been implemented — only the update mechanism (verify,
  atomic swap) existed, so a fresh install had a configured source but no data behind it. DENIS now
  really fetches `dbip-{city,asn}-lite-{month}.mmdb.gz` from DB-IP, decompresses and validates it
  (parses as a real MMDB file), and installs it the same zero-downtime way as any other update.
  Verified against DB-IP's real servers, not mocked.
* New **"Update now"** button next to Settings → Network → Network Intelligence's GeoIP source,
  for an admin to trigger that download on demand (hidden when the source is a custom file — there
  is nothing to fetch for that).
* Alerts, Events and a device's "Recent destinations" now always show a **fresh** lookup for the one
  IP address actually being looked at, instead of whatever happened to already be cached when the
  background enrichment worker got to it — the direct fix for addresses that were brand new and
  hadn't been resolved yet when someone opened that specific alert.

## 2.15.1: Hotfix — dependency security advisories, and a missed enrichment spot

* `cargo audit` caught two real advisories in 2.15.0's new dependencies right after release:
  `hickory-proto` (O(n²) name-compression DoS, RUSTSEC-2026-0119) and `maxminddb` (an unsound
  `open_mmap`, RUSTSEC-2025-0132, which DENIS never actually calls, but the fix is the right floor
  regardless). Bumped both past the fixed versions and adapted to their breaking API changes.
* A device's own traffic baseline ("Recent destinations") now gets the same country/ASN/ISP/
  reverse-DNS context as Alerts and Events — the one place IP enrichment was still missing where a
  customer would actually look for it (a device's own IP history, unlike this, is almost always
  private/LAN and was never a useful place for it).

## 2.15.0: IP Enrichment — GeoIP, ASN and reverse DNS for every public address DENIS shows

* Every public IP address the console mentions (Alerts, Events, a device's IP history) now gets a
  **"Network context"** line — country, AS organisation, ASN, reverse-DNS hostname — and a click
  opens a full detail panel with coordinates, connection type, data source and database version. A
  private/loopback/link-local/multicast/reserved address is classified as such and never
  geolocated. Geolocation is always labelled "Approximate location", never a precise claim.
* **Local-only by default**: GeoIP is read from a database file on disk (**DB-IP Lite**, free,
  CC BY 4.0), never a live API call per address — a customer's own traffic never leaves the box for
  this. A licensed MaxMind file works the same way if you point Settings at it instead.
  Provider-swappable by design: the same interface a future custom REST/internal-server provider
  would implement.
  New **Settings → Network → Network Intelligence**: reverse-DNS resolver/secondary/timeout/on-off
  (default `1.1.1.1`/`1.0.0.1`, 2000ms), the GeoIP source, and cache lifetimes (30 days GeoIP, 24
  hours reverse DNS by default) — every change takes effect immediately, no restart.
* **Never blocks anything.** Alerts, events and device discovery are built the instant they happen,
  regardless of whether enrichment for the addresses involved is ready yet; a background worker
  fills it in, deduplicated (the same address across 10,000 events costs one lookup, not 10,000)
  and rate-limited by a bounded queue that drops rather than ever stalls the caller. Reverse DNS has
  its own circuit breaker: five consecutive failures and it stops trying for a minute instead of
  queueing lookups behind a resolver that is already down.
  New Prometheus samples on `/metrics`: `ip_enrichment_total`, `_cache_hits`, `_cache_misses`,
  `_errors`, `_queue_dropped`, `dns_lookup_total`, `_cache_hits`, `_errors`,
  `ip_enrichment_geoip_up{provider=}`.
* Supports IPv4 and IPv6 throughout — classification, GeoIP lookup and reverse DNS.

## 2.14.0: A runZero-style Dashboard as the new home screen, plus five toolbar/layout fixes

* New **Dashboard** page, now the default landing screen (every other page is unchanged and still
  reachable from the sidebar): 12 clickable KPI tiles (devices, online/offline, needs review, open
  alerts, high-severity alerts, OT devices, high-risk devices, findings needing attention, accepted
  risks, sites, new devices in the chosen period), two trend charts (alerts raised, devices online)
  and four donut breakdowns (devices by risk, open alerts by severity, devices by type, findings by
  severity) over a period picker (24h/7d/30d), and three "what needs attention" lists (recent
  alerts, most at-risk devices, standing findings). Every tile, donut segment and list row is
  clickable and drills straight into Devices/Alerts/Findings pre-filtered to what it showed (a new
  `risk:` search key backs the risk-level drill-downs; Alerts gained a clearable severity filter
  chip for the same reason). Built entirely from state the app already loads each refresh — opening
  it costs no extra request beyond its own two trend-chart fetches.
* Software: the device count is now a button that lists which devices actually run that product and
  version, each opening its device panel (previously only a hover tooltip, easy to miss).
* OT: the communications-matrix "Columns" button now sits at the right edge of its row, matching
  every other Columns button, instead of crowding the "only writes / control commands" checkbox.
* Compliance: "Expand all"/"Collapse all" no longer read as glued to the first group below them.
* Reports: the same missing-gap fix for the period/"Make a report now" row and the Columns/"Open a
  live report…" row, both now separated from the table below.
* Settings: "Setup guide" moved from Network to System, where the rest of the first-run/maintenance
  items already live.

## 2.13.2: Fix the Update dialog's "Schedule" button doing nothing

* An empty `datetime-local` input still renders today's date as a greyed-out placeholder, which
  reads as already filled in — so "Schedule" was silently a no-op for anyone who clicked it
  without first opening the picker themselves (the code checked for a real value and returned
  early otherwise, with no message). The field now defaults to an hour from now, a real value,
  and a missing one is called out next to the button instead of failing silently.
* Also closed the matching gap server-side: `POST /api/update/install` with a `when` that isn't
  at least 30 seconds out now answers 400 ("choose a time at least 30 seconds from now") instead
  of silently installing immediately, as it used to when a chosen time didn't clear that margin.

## 2.13.1: Three toolbar placements corrected after a first look at 2.13.0

* Devices: "needs review" and Columns are now pinned to the right edge of the toolbar (they had
  landed on their own line, at the left, once the row wrapped).
* Alerts: a bigger gap between "show acknowledged" and Columns.
* Sites: Columns is flush right on the "Issue token" row, not sitting right next to the button
  (that placement is now Users' "Add user" only).

## 2.13.0: Consistent per-page toolbars — the Columns button always lands somewhere sensible

* Every page's own controls (an "add" form, an export link, a heading) and its **Columns** button
  now share one row, laid out on purpose instead of wherever the button happened to be auto-inserted:
  Devices has it right after "needs review"; Alerts reads Acknowledge all → Alerts CSV → show
  acknowledged → Columns; OT's "Industrial devices" and Alerting's "Channels" headings sit flush
  left with Columns flush right; Reports has "Open a live report without saving it" as a real
  button immediately left of a flush-right Columns; Sites and Users' "Add user" keep Columns right
  next to their own button, not pushed to the edge, while Users' "Create token" and the Audit log
  put it flush right like the rest. `ui/tables.js` gained `data-cols-host`/`data-cols-after` on a
  table to name that row explicitly, for the pages where it is not simply the row right before the
  table.
* The header's **Scan now** button moved from the far right to the front of that button group:
  Scan now, language, theme, account, Help, Sign out.

## 2.12.0: Settings navigation, take two — a sidebar sub-menu instead of page tabs

* 2.9.0 turned Settings' one long scroll into real sub-tabs, but grouped into 7 categories shown
  all at once on the page — which wrapped across 3 lines, the opposite of the fix. Replaced with a
  sidebar sub-menu (Sign-in & security, Network, Data, Integrations, Branding & MSP, System — 6
  entries, always one line, shown under "Settings" only while that page is open); picking one
  shows everything it covers directly on the page, with no further breakdown into per-item tabs.
  Every `#settings/...` deep link (the setup guide, the Switches page) keeps working unchanged,
  resolving to its category.

## 2.11.0: Windows groundwork — the last two `#[cfg(unix)]`-only gaps filled

* `src/certs.rs::private_file` (the TLS private key) and `src/health.rs::disk_space` now have
  `#[cfg(windows)]` implementations — an `icacls` call restricting the key to the account DENIS
  runs as, and `GetDiskFreeSpaceExW` for free/total disk space. Both compile and lint clean
  cross-compiled to `x86_64-pc-windows-gnu` (`cargo check`/`clippy`, the latter with `-D warnings`,
  matching CI's own Windows job). **Unverified beyond that** — nothing has run on a real Windows
  machine — see WINDOWS.md, which this closes out step 3 of. Capture (Npcap) and the actual
  service/installer are still separate, larger pieces of work, gated on machine access and a
  couple of licensing/privilege decisions that are not this repo's to make unilaterally.

## 2.10.0: Scheduled reports can now e-mail themselves

* **Scheduled reports → optional e-mail delivery** (Reports page, under the schedule): when a
  weekly/monthly report is made, DENIS can now e-mail a share link to a list of addresses instead
  of only keeping it in the console for someone to remember to check. Reuses whichever e-mail
  notification channel is already enabled (Settings → Alerting) — no separate SMTP setup — and
  needs `--public-url` configured so the link actually resolves. Leave the recipients blank to
  keep the previous behaviour exactly as it was.

## 2.9.0: Elasticsearch/OpenSearch export, a reorganised Settings page, and two UI fixes

* **Elasticsearch/OpenSearch export** (Settings → SIEM / Log export → Elasticsearch (Bulk API)):
  events, findings and the audit log as ECS-shaped documents, pushed straight to an index or data
  stream over the Bulk API — no Logstash/Filebeat in between. Same cursor-driven, at-least-once
  delivery every other SIEM target already has. The API key is a secret like any other in DENIS:
  never echoed back by the API, and an update that does not mention it keeps the one already
  stored instead of silently dropping it.
* **Settings, reorganised**: the page was one long scroll of 16 unrelated sections with a flat,
  un-grouped list of jump links — and three of those sections (System, Single sign-on, Explain
  with AI) had no link in that list at all, reachable only by typing the URL by hand. Replaced
  with real sub-tabs (only one section shown at a time), grouped into Get started / Network /
  Sign-in & security / Data / Integrations / System / Branding & MSP. Existing `#settings/...`
  links (the setup guide, the Switches page) keep working unchanged.
* **Fixed**: the search-syntax ⓘ button stayed visible on every page instead of only Devices — two
  unrelated toolbar elements shared the same CSS class, and only one had the `id` the page-switch
  code actually looked for.
* **Fixed**: dialogs with two stacked button rows (Settings → Updates is the one most people hit)
  had them touching — `.row` only spaces its own children, nothing above itself when two rows
  sit directly one after another.

## 2.8.0: ServiceNow ticketing

* **ServiceNow** joins the notification channels alongside Jira: files one real incident per
  alert against the Table API (`/api/now/table/incident`), Basic-auth authenticated. Severity
  maps to urgency/impact, and a `correlation_id` (ServiceNow's own convention, the same idea as
  PagerDuty's dedup key) means repeats of the same alert about the same device correlate in
  ServiceNow's UI instead of opening a new incident every time. Same dispatcher, digesting,
  backoff, mute and maintenance-mode machinery every other channel already has.

## 2.7.0: JA3 now also covers a device's outbound TLS (not just LAN-to-LAN)

* **JA3 for outbound TLS**: 2.5.0's JA3 fingerprinting only ever saw TLS between two local
  devices (the same path that decodes industrial protocols). A device that only ever *calls out*
  — phoning home, fetching updates, cloud telemetry — gave no such evidence at all. It now does:
  a ClientHello leaving the network is fingerprinted the same way, right where DENIS already
  counts that device's outbound traffic, with no measurable extra cost (the check is a handful of
  byte comparisons per packet; the real parse only ever runs on the one handshake packet of a
  connection, not its data).

## 2.6.0: Jira ticketing

* **Jira** joins the notification channels (Settings → Alerting → Add a channel): files one real
  Jira issue per alert, authenticated with an API token against the Cloud REST API (v3), under a
  project key you choose. Same delivery machinery every other channel already gets — per-channel
  cursor, storms fold into one digest issue, backoff on an outage, a device's mute and maintenance
  mode both apply. DENIS never updates or closes the issue afterwards; that happens in Jira like
  any other ticket.

## 2.5.0: TLS client/server fingerprinting (JA3/JA3S)

* **TLS fingerprinting**: DENIS now reads the cleartext ClientHello/ServerHello of any TLS
  handshake it sees (mirror port only, same as every other passive decoder — nothing is ever
  decrypted or intercepted) and computes the client's **JA3** and the server's **JA3S**
  fingerprint, shown on the device's Identity panel. This is the original 2017 method (public
  domain, no known patent, freely reimplemented by nmap/Zeek/Suricata/Wireshark and most other
  network tools) — deliberately not FoxIO's newer JA4+ family, which is patent-pending and
  license-restricted. Same idea, same value: a device whose TLS stack doesn't match what it
  claims to be, or an anonymous device that shares a fingerprint with a known client, is now
  visible without opening a single packet's payload.
* New `md-5` dependency (RustCrypto, MIT/Apache-2.0) for the JA3 hash itself.

## 2.4.0: bulk-edit owner/room/type/criticality/status, and a visible search-syntax guide

* **Bulk-edit** owner, room, department, device type, criticality or status across every selected
  device at once (Devices → select some → "Set for all selected") — the bulk-tag bar's other
  half, validated exactly the way a single-device edit already is.
* **The power-user search syntax** (`type:printer port:9100 vendor:hp …`) now has a small ⓘ
  button that opens a real, always-clickable panel listing every key with an example — not just
  a hover tooltip, which was easy to miss entirely.
* CI: hardened `tools/ui-smoke.mjs` against a shared runner occasionally failing to launch Chrome
  at all (unrelated to this project) — launch now retries up to 3 times with real diagnostics.

## 2.3.1: fixed the Devices "select all" checkbox silently breaking the whole page

* Clicking it set the sort state to something invalid (its column has no sort of its own, and the
  header-click handler had no guard against that), which broke every redraw of the Devices list
  afterwards — including the row checkboxes' own selection — until the page was reloaded. Found
  from a real report; a new automated check clicks the real checkbox so this fails loudly again
  if it recurs, instead of shipping unnoticed.

## 2.3.0: "Explain with AI" (bring-your-own-key), and a fix for a stuck alerts badge

* **"Explain with AI"** on any alert or finding (Settings → Explain with AI): an administrator
  gives their own API key for Claude, ChatGPT, Gemini or Grok, and anyone can then click one
  button for a short, plain-language summary. Never automatic, never sent anywhere unless someone
  clicks it — DENIS runs no shared AI backend and pays for none of this; every call is billed to
  the administrator's own account. Only what the console already shows for that one alert or
  finding is sent, nothing else about the network.
* **Alerts: "Acknowledge all"** clears an unacked backlog older than the page itself ever shows
  (it fetches only the most recent 200) — the unacked badge could otherwise stay stuck above zero
  forever with nothing left on screen to acknowledge, typically left over from before a noisy
  rule was tuned down.
* CI: fixed the dependency-audit job failing on a missing permission, and documented why one
  advisory (a timing side-channel in RSA private-key operations, reached transitively through
  SSO's OIDC library) does not apply to how DENIS actually uses it — a public-key-only verifier,
  never a private-key operation.

## 2.2.0: single sign-on (OpenID Connect)

* **Sign in through an identity provider** (Entra ID, Okta, Google Workspace, Keycloak, anything
  speaking OIDC) instead of a local password — Settings → Single sign-on. The first sign-in for
  an email creates a `viewer` account for it automatically; raise its role afterwards like any
  other account. Local accounts, including the initial admin password, keep working unchanged
  alongside it.
* Built on the `openidconnect` crate (authorization code + PKCE), not hand-rolled JWT
  verification. **What is and is not verified is written up plainly in
  [SSO.md](SSO.md)** — in short: configuration, account provisioning, permissions and secret
  handling all have real tests; the live exchange with an actual identity provider does not yet,
  and should be confirmed against one (a free Google or Keycloak client both work) before relying
  on it for anything that matters.

## 2.1.0: rules export/import, restart/shutdown, restartable learning mode, mirror-port and DNS checks

* **Export and import detection rules** as a JSON file (Rules → "Export as file" / "Import from
  file…") — the same shape the server already validates, so a large exceptions list, or a tuned
  set of thresholds, moves to another DENIS instance or comes back after a reinstall.
* **Restart, network-wide, one alert-free learning period, for 1 to 7 days** (Rules → "Restart
  learning mode"), for after a change big enough that the existing baselines are not a fair
  comparison any more — a new switch, a re-addressed subnet, a batch of new devices. Every
  device is treated the way a brand new one already is for the time you choose; pause and
  resume freeze and restore the remaining time, or end it early at any point.
* **Restart / Shut down DENIS from Settings**, admin-only, the administrator's own password
  asked again before either — a mistaken click here stops the service.
* **A mirror/SPAN interface with an IP address of its own is now flagged** on the Health page:
  one caused a real outage (an address conflict) on the network being watched, not just this
  machine. "Remove the address now" (Linux) offers an immediate fix.
* **DNS resolution is checked** and flagged on the Health page if this machine cannot resolve a
  domain name — pointing at either this machine's own DNS settings or its router's.
* Alerts and findings now show an exact date/time next to the relative one ("7m ago" alone does
  not say which day), and findings show "since" the date DENIS first saw that kind of problem.
* Alerts: a repeated alert's group can be acknowledged all at once instead of one occurrence at
  a time, and its expanded rows are set off more clearly from an ordinary row right below them.

## 2.0.2: `new_destination` no longer alerts forever on NTP/STUN's rotating server addresses

* NTP (time sync) and STUN both contact a *different* server address on purpose (an NTP pool
  rotates DNS answers; STUN server lists rotate too) — so `new_destination` alerted on "first
  contact" again and again, forever, for any device that simply keeps its clock in sync. Now,
  after a handful of these on the same service (tunable: Rules → New destination → "Stop
  repeating after"), DENIS stops repeating it — the same treatment 2.0.1 gave the analogous
  P2P/relay port problem, applied to the destination side.

## 2.0.1: `new_port` no longer alerts forever on a P2P/relay destination that hands out a new port every session

* Some devices (several IP cameras were the case that surfaced this) talk to a cloud relay/P2P
  service that allocates a different UDP port for every single session. Because that port never
  settles into "an established set of ports", `new_port` alerted on it again and again — for one
  busy camera, dozens of times a day, forever. `new_port` now stops repeating for a given
  destination after a handful of alerts (tunable: Rules → New service port → "Stop repeating
  after"), rather than raising it every time that destination hands out yet another new port.

## 2.0.0: Docker image, software inventory, bulk tagging, shared reports, alert grouping

* **Docker.** An official image (`docker compose up demo` for the no-install demo, or a `denis`
  service with `network_mode: host` for real capture) — see [docs/docker.md](docs/docker.md) for
  exactly what is and is not verified with it. Built with `cargo-chef` so a source-only change
  rebuilds in under two minutes instead of a full recompile.
* **Software inventory.** A fleet-wide page listing every product/version DENIS has read from a
  banner, and which devices run it — `GET /api/software`.
* **Power-user search.** The device search box now also takes `type:`, `port:`, `vendor:`,
  `owner:`, `tag:`, `room:`, `os:` and `status:`, combinable in one query separated by a space.
* **Bulk tagging.** Select devices on the register with a checkbox column and add or remove a tag
  from all of them at once.
* **Shareable reports.** A report can be given a public link (`PUT /api/reports/{id}/share`) that
  needs no sign-in to view, and revoked again at any time.
* **Alerts: repeated alerts for the same device now collapse into one row** ("×N, recurring since
  …") instead of cluttering the list with every repeat, with a caret to expand the individual
  occurrences.
* **IPv6 groundwork** (see [IPV6.md](IPV6.md)): an address model, storage, and a fuzz-tested
  header/NDP parser. Not yet wired into capture or the BPF filter — inert until that follow-up
  work lands, listed honestly as groundwork, not a feature.
* **Windows groundwork** (see [WINDOWS.md](WINDOWS.md)): `src/net.rs` now has a Windows
  implementation of interface discovery, local UTC offset and hostname lookup, verified by real
  cross-compilation (`cargo check`/`clippy --target x86_64-pc-windows-gnu`) — not yet by running an
  actual build on Windows, which still needs the Npcap SDK and a real machine to finish and test.

## 1.16.1: fixed the update dialog getting stuck on a successful update

* **The "Updating DENIS" dialog could get stuck** showing a half-finished checklist even though the
  update had already succeeded and the service had already restarted. A successful install clears
  the stage and reports `"Updated to X. DENIS is restarting."` — the same shape of message the
  console also uses for a *failed* install ("the update stopped before changing anything"), and the
  dialog treated both alike: showed the message and stopped watching, instead of waiting for the
  new version and reloading. It now tells the two apart and keeps waiting on success. Nothing on
  the server changed; installations that hit this only needed a manual page reload to see the new
  version, which is exactly what the dialog now does for you.
* **Top talkers** now says **since when** each figure runs: hover a bar for that device's own
  start, and a note under the three lists gives the oldest and newest start among what is shown —
  so a figure is never mistaken for a fixed daily or weekly total.
* Documentation: the README undersold what DENIS actually does — known-exploited CVE/end-of-support
  matching (a live CISA/NVD/EPSS feed) wasn't mentioned at all, and the compliance mapping list was
  missing half the standards DENIS already covers (DORA, PCI DSS, HIPAA, SOC 2, CMMC 2.0). Fixed,
  with more screenshots. All documentation screenshots regenerated against the current console
  (several were a few versions stale); the demo company now has traffic baselines for nine devices
  instead of one, so the Top talkers screenshot — and the demo itself — show a real leaderboard.

## 1.16.0: Top talkers leaderboards, and Alerts sorting/layout fixes

* **Trends → Top talkers**: three leaderboards ("Most received", "Most sent", "Total traffic")
  showing which devices have moved the most data, built from each device's existing traffic
  baseline (`--flows`) rather than a new time series — a live snapshot, not a chart over time. The
  gateway and this monitoring host are left out automatically, since they naturally funnel
  everyone else's traffic and would otherwise dominate every list; click **×** on any device to
  hide it from all three lists too (remembered server-side, not just in this browser).
* The **Alerts table can now be sorted** by clicking Time, Score, Type, Device or What happened —
  it was the one table on the console without this.
* The **"Detecting…"/"Learning…" banner now sits at the top of the Alerts page**, above the
  toolbar, and **Alerts CSV now sits next to the Columns button** instead of in a separate row —
  both were awkwardly placed below other controls.
* A rule's **Network/type/tag exceptions now render the same way as device exceptions** — one row
  with a **×** to remove it at the start — instead of a small inline chip that read differently
  from everything else in the same list.
* The generated **HTTPS certificate's "Download the CA certificate" link is now a button** like
  its neighbours, instead of a plain text link.

## 1.15.2: fixed a spacing regression that misaligned several button/label rows

1.14.1 added extra vertical spacing between the unrelated blocks Settings and Health stack (a
checkbox list touching the button below it, etc.). Its selector reached one level too far in some
cases and put a stray `margin-top` on individual children *inside* a `.row`/`.chips`/`.form-grid` —
containers that already lay out their own children with `gap`. The one-sided margin then broke
`align-items: center`, so the second item in a few flex rows sat a few pixels lower than the first:
**Save license** vs **Remove license**, the SIEM **Save** vs **Send a test message**, and the SIEM
**Transport/Host/Port/Format** labels. All fixed; nothing else changed.

## 1.15.1: the console can update itself under the hardened systemd service

* **Settings → Updates now actually works** for installations set up by `install.sh`. The program
  moves from `/usr/local/bin/denis` (owned by root — unwritable by the `denis` service user, and
  blocked again by `ProtectSystem=strict` even if it were not) to `/usr/local/lib/denis/denis`,
  owned by the `denis` user, with `/usr/local/bin/denis` kept as a convenience symlink for
  `denis backup`/`denis user reset`/etc. `ReadWritePaths=/usr/local/lib/denis` is the one exception
  to the otherwise still fully read-only system. An installation from before this existed migrates
  automatically the next time `sudo bash install.sh` is run (once, then every later update can be
  the one-click kind).
* An alert's **Acknowledge** and **Add exception** buttons no longer touch each other in the Alerts
  table.

## 1.15.0: Telnet, MySQL/MariaDB, SMB and MSSQL banners

Extends which services DENIS can read a product, version or build number from. Telnet and
RDP/SMB/database ports were already flagged as risky when open (`telnet_open`, `rdp_open`, `smb`,
…); this adds real evidence, where available, to four of them.

* **MySQL/MariaDB (3306)**: the server's own greeting packet, sent unauthenticated the instant the
  socket connects, gives a real product and version — told apart from each other by MariaDB's own
  version-string marker. Matched against known-exploited vulnerabilities and (once entered) custom
  CVEs exactly like every other product.
* **SMB (445)**: Windows' own build number (e.g. `10.0.19041`), read from the NTLMSSP challenge in
  an SMB2 Session Setup — the same technique `smbclient`/nmap's `smb-os-discovery` use. Two short,
  unauthenticated round trips (Negotiate, then Session Setup); Samba does not normally set the flag
  that makes this possible, so it correctly gives nothing there rather than a guess. Shown as
  evidence in the device panel; not matched against CVE data yet (Windows build numbers need a
  different kind of support-date/CVE mapping than the semantic-version products above).
* **MSSQL (1433)**: SQL Server's own build number, read from a TDS PRELOGIN exchange — always sent
  in the clear regardless of whether the connection later negotiates TLS. Shown as evidence, not yet
  matched against CVE data, for the same reason as SMB above.
* **Telnet (23)**: its login banner is now read and shown as evidence in the device panel (Telnet's
  banners vary too much between vendors to judge a version from reliably, so it is not matched
  against CVE data — the port itself already being open is what `telnet_open` flags).
* **`--no-extended-banners`**: turns all four off. Same cost as any other banner DENIS already
  reads — one extra connection (two for SMB), only for a port the scan already found open — but
  this exists for an administrator who would rather not connect to those specific ports at all.
* Not pursuing a version for **RDP**: without a full NLA/CredSSP negotiation (well beyond a single
  polite connection) RDP's own handshake does not reliably expose the Windows build behind it, so
  `rdp_open` (the open port itself) remains the finding there, without a version claim attached.
* The SMB and MSSQL parsers are new binary-protocol code: bounds-checked throughout (fuzz-tested
  against random and truncated input) and verified against hand-built packets matching each
  protocol's published specification, but **not yet verified against a real Windows Server or SQL
  Server instance** — be aware of that until it has been.

## 1.14.1: a live CISA/NVD known-exploited feed, Compliance as cards, more Trends charts

Follow-up to 1.14.0, from the same round of feedback.

* **Known-exploited vulnerabilities can now be refreshed live** (Settings → Software data): "Update
  now" fetches the current CISA Known Exploited Vulnerabilities catalog, looks up each recognised
  match's affected version range on NVD, and its exploitation-probability score from FIRST.org
  EPSS — only entries for the products DENIS can already read from a service banner, and only when
  NVD gives a clean single-product version range (nothing is ever guessed). An optional weekly
  auto-refresh sits beside it, off by default (heavier than the existing EOL refresh, so it is an
  administrator's own choice). Works alongside Custom CVEs, added in 1.14.0.
* **Compliance is no longer a wide table**: each requirement is its own card with the status always
  visible without scrolling sideways, and "Expand all" / "Collapse all" buttons for the
  now-grouped-by-standard list.
* **Trends**: three more charts — Devices offline, Devices in the register, and Total traffic —
  alongside 1.14.0's New devices and Received.
* **Rules**: the "traffic analysis is not running" warnings now name the actual capture interface
  and say concretely what to do (start with `--flows`, add a mirror interface under Settings if the
  traffic in question does not cross the main one).
* Settings fields that should not stretch full width (network interfaces, sign-in security) no
  longer do; a couple of remaining spacing gaps in Settings/Health were closed.

## 1.14.0: custom CVEs, simpler agent certificates, data retention, and a round of UX fixes

A larger release across several areas raised in feedback: vulnerability data, certificate
distribution for a fleet of agents, general housekeeping, and a pass of visual/UX polish on
Settings, Compliance, Topology, Trends, Sites and Users.

* **Custom CVEs** (Settings → Software data → Custom CVEs): add a known-exploited vulnerability of
  your own — for software DENIS does not ship data for yet, or one you want flagged sooner — with a
  CVE id, product, name, date and an exact version or a range. Matched against service banners
  exactly like the bundled/refreshed list, takes effect immediately, and is removable with one
  click. Validated on save (a bad entry never gets stored), capped at 200 entries.
* **Simpler certificate distribution for a fleet of agents**: `--master-ca-pem` (or
  `DENIS_MASTER_CA_PEM`) trusts the master's CA from its *text* instead of a file — nothing to copy
  to each agent's machine. *Settings → HTTPS certificate → Copy for --master-ca-pem* puts it on the
  clipboard, ready to push alongside each agent's token through a secrets manager, Ansible or
  cloud-init. The CA itself does not change when the master's own certificate renews, so an agent
  set up once (either way) keeps working across every later renewal without being touched again.
* **General data retention** (Settings → Data retention): one setting for how long events, alerts
  and trend samples are kept — 1 to 1095 days (3 years), 180 days by default — applied within the
  hour, no restart. The asset register itself is never affected.
* **A revoked agent key or API token can now be deleted**, not just revoked, from Sites and Users
  respectively — the row no longer lingers once you are done with it.
* **Compliance**: requirements are now grouped by standard (CIS Controls, NIST CSF, IEC 62443,
  ISO/IEC 27001, NIS2, NIST SP 800-82, DORA, PCI DSS, HIPAA Security Rule, SOC 2, CMMC), each
  collapsible with an "N of M in place" summary, instead of one long flat list; the status column no
  longer wraps its text ("in place" breaking across two lines).
* **Trends**: two more charts — "New devices" (derived from how the register grew between samples)
  and "Received" (inbound traffic, which was already recorded but never charted) — alongside the
  existing devices-online, sent-outside and alerts-raised charts.
* **Topology**: a site with many devices no longer draws a name label next to every node (which
  guaranteed overlapping text) — past 24 devices it relies on the tooltip and a click instead, with
  a note saying so. The physical (switches and cables) view explains plainly when a switch's ports
  read fine but it gave back no forwarding table or LLDP neighbours, and lays out switches with
  nothing plugged in more compactly instead of stranding them far apart on an empty canvas.
* **A round of spacing and layout fixes**: stacked checkboxes and rows in Settings and Health no
  longer touch each other or the control below (the "Back up now" button touching the backups
  table, SIEM's checkboxes crowding each other and the Save button); the network-interfaces form's
  mirror interfaces now sit below the discovery interface instead of squeezed beside it.

## 1.13.5: documentation refresh (SIEM export, Add exception, README)

* **`docs/export.md`'s SIEM section rewritten** for what ships since 1.13.0 — CEF/LEEF/JSON,
  UDP/TCP/TLS, independently-toggleable events/findings/audit streams, the Test button — instead
  of describing the old CLI-only, CEF-only, no-TLS behaviour. Same for the one-line mentions in
  `docs/index.md` and `docs/alerting.md`.
* **`docs/detection-rules.md`** now describes "Add exception" (1.13.2/1.13.3) next to the existing
  Exceptions section.
* **`README.md`** refreshed: the SIEM bullet, the `src/` file table (the Task-4 refactor split
  `src/web.rs` into `src/web/`; schema version v5 → v14; added `src/web_siem.rs`), and the unit
  test count.
* These `docs/*.md` files are the single source for both GitHub's own rendering and the console's
  built-in `/docs` pages (compiled in, rendered on request) — this release is what makes the
  in-product copy match.

## 1.13.4: fixed an exception-row rendering glitch; clearer Rules page forms

* **Fixed: an exception's name/MAC/IP could overlap its own note and wrap one character per
  line** in the narrower OT/network watch edit dialogs — a flex-sizing bug in the row added in
  1.13.3 (the note had no width limit of its own and starved its sibling to zero). Both lines now
  wrap normally at the row's real width, in any dialog.
* The exception/watch-exclusion remove button is now a small square at the **start** of the row,
  not the end.
* The "add one" mini-form under Exceptions (and a watch's "Never for..." lists) now labels both
  fields ("Match by" and the chosen kind's own name) and never pre-selects a real value for you —
  a device or type picker starts on an empty "Choose one…" — and is visually set apart from the
  list above it.
* "Add a watch" is now **"New Rule"** (both OT and network watch sections), set apart from the
  last watch above it with its own spacing, instead of reading as part of that row.

## 1.13.3: exceptions show who and why; "Add exception" also acknowledges the alert

Follow-up to 1.13.2's "create an exception from an alert", after trying it out:

* **The Rules page's Exceptions (and a watch's "Never for..." lists) now show a row per device** —
  name, MAC, IP, and, for one added from an alert, why ("contacted 47.254.143.217 (tcp port
  20001, 0 kB) — 23/09/2026, 15:24") — instead of a bare "Device: <name>" chip. Non-device
  exceptions (type/tag/network) are still shown as chips.
* **"Add exception" now also acknowledges the alert**, since it is covered by the new exception:
  it disappears from the default (unacknowledged) Alerts list immediately, the same as clicking
  Acknowledge would, in the one click.
* The button is labelled "Add exception" consistently (Alerts row and the alert's own detail
  dialog); what it will specifically do is its tooltip.

## 1.13.2: one-click "create an exception" from an alert

* **Alerts now have an "Except" action** (next to Acknowledge, and in the alert's own detail
  dialog), for administrators: one click stops that exact situation alerting again, without a
  trip to the Rules page.
  * An ordinary rule (`new_destination`, `volume_anomaly`, `arp_conflict`, ...): adds a
    device-scope exception on that rule for the alerting device — the same list the Rules page's
    own per-rule *Exceptions* section shows.
  * A network watch (`it_watch`): adds the alerting device to that watch's own exceptions.
  * An OT command watch (`ot_command_watch`): adds the *sender* (who sent the command) to that
    watch's allowed senders — looked up by MAC, since the alert only ever carried the sender's
    MAC/IP/name, not its id; an unrecognised sender says so plainly instead of doing nothing.

## 1.13.1: clearer watch forms, five worked rule examples, support dates refresh on by default

* **Rules page: clearer OT command watch / network watch forms.**
  * "Start from a common watch…" no longer appears when *editing* an existing watch — it has no
    saved value to reflect (a preset only ever pre-fills fields once), so showing it there just
    looked like a forgotten setting. Only shown when adding a new watch, and now labelled to say
    what it does.
  * "Enabled" moved to the top of the form (was the last field) and relabelled "Watch enabled".
  * "Never for these senders"/"Never for these devices" are now a collapsed section, opened
    automatically only when already in use — most watches never need it.
  * Every place that names a rule needing `--flows` now carries a `*` with a tooltip, and shows a
    highlighted warning specifically when traffic analysis is not currently running, instead of
    static prose that reads the same whether it applies right now or not.
* **Five worked examples for network watches** added to the docs, including the specific
  "does this device talk to others on the network it shouldn't" allow-list pattern.
* **Support dates (end-of-support software) now refresh from endoflife.date on their own by
  default** on a fresh install, instead of requiring an administrator to find the switch under
  Settings → Software data first. Still just the one public site, nothing about your network
  sent, and still a plain toggle to turn off. Existing installs keep whatever they already chose.

## 1.13.0: SIEM export (CEF/LEEF/JSON, GUI-configurable), a big internal refactor, six review fixes

* **New: SIEM / log export**, fully configurable from Settings, no restart needed. Send events
  and alerts, standing findings and/or the audit log — independently — as syslog, in **CEF**,
  **LEEF** or plain **JSON**, over **UDP**, **TCP** or **TLS** (encrypted; a self-signed
  collector's certificate can be trusted without verification, for setups with no public CA). A
  "Send a test message" button checks a target before saving it. The previous `--syslog` CLI flag
  (CEF, alerts only) still works — it now just seeds this setting the first time nothing has been
  saved yet, after which the console is authoritative.
* **Fixed: a mistyped network interface name could crash-loop the whole program.** `PUT
  /api/interfaces` validated everything about the request except whether the name actually exists
  on the machine; a typo saved cleanly and only failed on the next restart, which under
  `systemd`'s `Restart=always` is a crash-loop from one keystroke. It is now checked against the
  same interface list the page itself offers.
* **Fixed: a license-expiry alert could be silently lost.** The "already alerted for this stage"
  marker was written before the alert was actually sent; on the very first check after start-up
  (before the self-host device exists yet) that meant the marker was set with nothing sent, and
  since later checks only alert on a *change* of stage, the warning for that stage never went out
  for the life of the process.
* **Fixed: a down MSP backup upload wasted a whole schedule interval per failure**, even though
  the loop checks every 15 minutes regardless of the configured schedule. The upload slot is now
  only consumed once a send actually succeeds.
* **Fixed: an unmodified local backup was re-uploaded to the MSP on every due check** when the
  local backup schedule was slower than the upload one (e.g. weekly local, daily upload — the
  default). On the MSP side, uploads are named by arrival time and the retention count does not
  look at content, so this could fill an MSP's entire retention window with copies of one backup
  instead of real history. Re-sending is now skipped when the content has not changed.
* **Fixed: a mirror/SPAN interface on a different subnet or VLAN than the main one produced
  nothing at all** — no flows, no industrial-protocol decoding, no error — because every capture
  thread used the main interface's own subnet to decide what counted as "local", exactly the
  scenario `--mirror-iface`'s own documentation describes ("one per VLAN"). A new `--mirror-subnet
  <CIDR>` (repeatable) tells DENIS about a VLAN it cannot detect on its own; a mirror interface
  that does have its own address is now detected and added automatically, and one with neither
  logs a warning at start-up instead of failing silently.
* **Fixed: a device merged from one site into another could leak to a user restricted to the
  other site.** `GET /api/assets/{id}/merged` checked the canonical device's own site access but
  not each merged sibling's — a sibling that had since been re-observed on a site the caller
  cannot see would still hand over its MAC and timestamps.
* **Internal refactor** (no behaviour change other than the fixes above): the `Shared`
  collector-status struct and the `Store` trait (previously one 85-method trait) are now each
  split into narrow, independently-usable pieces; the `web` module's import cycle with its
  `web_*` handler modules is gone; per-site access grants moved out of a JSON blob under
  `settings` into their own database table with a real foreign key, replacing a fail-open default
  (an unreadable settings row used to mean full access for everyone) with fail-closed.

## 1.12.0: merge duplicate devices, a real SNMP port list, two live bugs fixed

* **"This is the same device as…"**: a device seen under more than one MAC address (an access
  point broadcasting several SSIDs, typically its most common cause) can now be merged into
  another one from its detail panel. The merged device disappears from the devices list and
  findings; its own history is kept, not deleted, and it comes straight back the moment you
  undo it (Settings is not involved: it is a per-device action, "Unmerge" shown right on the
  canonical device's panel under "Also known as").
* **Switches (SNMP): the port list is now shown even when the forwarding table is not**, for
  switches (some cheap "smart" models especially) that answer IF-MIB fully but do not implement
  a readable MAC table at all — you at least get port names, aliases and up/down status, which
  is the most such a switch will ever give.
* **Fixed: a mirror interface set from Settings → Network interfaces did not actually turn flow
  accounting on** (`flows_enabled` stayed `false` in `/api/status` even with a mirror interface
  configured and running) — the GUI override replaced the interface list *after* the CLI's own
  `--flows` implication had already run, so it was never re-derived. Detection was not affected
  (it never checked the flag), but the console's own status display was misleadingly wrong.
* **Fixed: Topology → "Switches and cables" could show a literal "null"** on the page — one
  render path passed `null` straight to the browser's `replaceChildren`, which stringifies it
  instead of skipping it. Caught after the fact by a real report; the smoke test that exercises
  this exact view now checks for it directly, not only after navigating away from the page.
* Removed the global `window.fetch` monkey-patch in favour of an explicit `apiFetch()` — every
  caller is now findable by name instead of the CSRF/401-handling behaviour being an invisible
  side effect of calling the browser's own `fetch`. No behaviour change.

## 1.11.0: more ports, ICS-CERT advisories, EPSS scores, and five more compliance standards

* **More ports scanned and risk-scored**: Kerberos, legacy r-services (rexec/rlogin/rsh), a SOCKS
  proxy, OpenVPN, container/orchestration (Docker already covered; now Kubernetes' API server and
  kubelet), message queues (RabbitMQ, Kafka), monitoring stacks (Prometheus, Kibana) and IRC (a
  common sign of a compromised device "phoning home").
* **CISA ICS-CERT advisories**: a new, separate finding for industrial devices — "the manufacturer
  has an open ICS-CERT advisory" — matched only by vendor name (Siemens, Schneider Electric,
  Rockwell Automation, …), never by firmware version, since that is not read passively. Explicitly
  conservative: it never claims a specific device is affected, only that its manufacturer has an
  open advisory worth checking against the exact model and firmware.
* **EPSS scores**: known-exploited-vulnerability findings now carry FIRST.org's EPSS score — a
  modelled probability of exploitation in the next 30 days — alongside the existing CVE and
  ransomware-use context, to help prioritise among several open findings.
* **Five more compliance standards**: DORA, PCI DSS v4.0, the HIPAA Security Rule, SOC 2 (Trust
  Services Criteria) and CMMC 2.0 (via NIST SP 800-171) join the existing CIS Controls v8, NIST
  CSF, IEC 62443-3-3, NIST SP 800-82, ISO/IEC 27001 Annex A and NIS2 mapping on the Compliance
  page — the same underlying evidence (inventory completeness, monitoring, MFA, audit log), shown
  in each standard's own words and control references.

## 1.10.0: security and reliability fixes from an architectural audit

* **Fixed: a device's own endpoints were not site-scoped** (IDOR). `/api/assets` already filtered
  by site access, but `/api/assets/{id}`, its `/baseline` and `/history` did not — a viewer
  restricted to "none" on a site could still read a device's full record, traffic baseline and
  edit history directly by id (sequential integers, trivially enumerable). Only matters for
  installs that use per-site access (MSP deployments). Also fixed the same gap in `POST
  /api/findings/{id}/verify`. Every case now answers 404 for both "does not exist" and "exists but
  you cannot see it", so existence itself is never leaked.
* **Fixed: a single panic could wedge every request until restart.** The whole database sat behind
  one lock; a panic anywhere while it was held "poisoned" it, and every request afterwards (from
  any user) panicked too, forever. A poisoned lock now recovers instead (the data behind it is
  still consistent either way), for the database connection and every simple status/cache lock.
  Left deliberately as-is, with a comment, wherever recovering could paper over real inconsistency
  (the in-memory device register and detector state).
* **Fixed: declared foreign keys were never enforced**, and deleting a disabled user left their
  per-site access grants behind forever (they live in a settings blob, not a table, so no FK ever
  caught them). Foreign keys are now actually on; `delete_user` cleans up its grants in the same
  transaction.

## 1.9.0: browse customers' uploaded backups from the console; several mirror interfaces at once

* **Settings → Health → "Customers' uploaded backups"**: an MSP can now find and download a given
  customer's uploaded backups right from the console (with a delete button for freeing space by
  hand) — no SSH access to this server needed, e.g. right after a customer reports being hit by
  ransomware. Admin-only, like local backups: these files hold other people's password hashes too.
* **`--mirror-iface` is now repeatable**: pass it more than once for more than one mirror/SPAN
  interface — one per VLAN, say, each fed from its own switch mirror port into its own NIC on the
  same server, all decoded into the same flow accounting and device register. Settings → Network
  interfaces gained a multi-select for it. This still does not run independent ARP discovery per
  VLAN (that remains `denis agent`, one per network) — it is for flow/traffic visibility across
  several networks from one box, not for separate device registers per network.
  See [Deployment](docs/deployment.md#one-or-more-mirror-port-interfaces-for-whole-network-flow-visibility).

## 1.8.0: independent backup upload schedule; retention for customers' backups at the MSP

* **Settings → Health → "Uploading to your MSP"**: how often the newest local backup is pushed to
  a configured `--backup-upstream` is now its own schedule (manually only / every 8 hours / every
  12 hours / every day / every week), independent of the local backup schedule above it. It never
  makes a new backup by itself — it just pushes whatever the newest one already is, when due.
  Shown only once `--backup-upstream` is actually configured. Upgrading changes nothing for a
  default install (daily local backups still upload daily, as before).
* **Local backup schedule** gains **every 8 hours** and **every 12 hours**, alongside the existing
  daily/weekly/off.
* **Settings → Health → "Customers' uploaded backups"**: an MSP's own setting for how many of each
  customer's uploaded backups to keep under `backups/from-agents/<id>/` (default 10; older ones
  are pruned automatically). Previously unbounded. This is purely local to the MSP's install — it
  never reaches back to the customer, who keeps full control of their own schedule and retention.

## 1.7.0: license expiry warnings and a grace period; a separate license-issuing tool

* **License expiry is no longer a cliff.** Settings → License always shows when the current
  license expires. **30 days out**, a banner and a one-off low-severity alert warn you, with
  everything still fully licensed. **Once it expires**, a **7-day grace period** keeps it fully
  working (a higher-severity alert marks this), so a renewal in progress never causes a surprise.
  Only after the grace period also passes does the install fall back to the Community edition. See
  [Licensing](docs/licensing.md#expiry-and-a-7-day-grace-period).
* **`license-issuer`, a new, separate, vendor-only tool** (`src/bin/license_issuer.rs`) replaces
  the `denis license-keygen`/`license-issue` subcommands, which are removed from `denis` itself —
  that tooling has no business shipping inside the binary every customer downloads. It keeps its
  own small database of every license it has issued (customer, tier, cap, validity, and the signed
  file itself), so a lost license file can always be recovered: `license-issuer issue "Acme
  s.r.o." --device-cap 500 --years 1`, `license-issuer list`, `license-issuer show <id>`.
* **Settings → Users**: an already-disabled user can now be permanently deleted (their sessions,
  passkeys and authenticator app are removed with them). Disabling remains the reversible first
  step; deleting is not, and is only offered once a user is already disabled.

## 1.6.0: a second, mirror-port interface — for whole-network flow visibility from one box

* **`denis run --mirror-iface eth1`**: a second, capture-only interface alongside the usual
  `--iface`. The main interface keeps doing exactly what it does today (ARP sweeps, port scans,
  discovery); the mirror interface is never probed and never used for discovery — it only decodes
  traffic into the same flow accounting (`new_destination`, `new_port`, `volume_anomaly`,
  `threat_list_match`), correlated to known devices by MAC. This is what a switch's mirror/SPAN
  destination port is for: plugged in there, one DENIS instance sees traffic between *other*
  devices that a normal switch port never forwards to it — no second `denis` process, no agent,
  no separate database needed just to test it. Implies `--flows`. See `denis interfaces`, which
  now also lists interfaces usable only as a mirror target (no IPv4 address needed for that role).
* **Settings → Network interfaces**: pick both interfaces from a dropdown instead of editing
  command-line flags or a systemd unit. A GUI-set choice takes priority over `--iface`/
  `--mirror-iface`, same as a pasted license already takes priority over `--license-file` — but
  unlike a license, a changed interface needs a restart to take effect (capture is opened once, at
  start-up), which the console says plainly.

## 1.5.0: renamed to MSP view; live devices and alerts can reach an MSP

* The tab and setting from 1.4.0 are renamed **Overview → MSP view**, to say plainly what it is for.
* **`denis run --report-to https://your-msp:8081`**: a customer's own master can now relay its
  devices and already-scored alerts to an MSP's master live, so they show up in **MSP view**
  alongside every other customer. Built deliberately to stay cheap at scale: devices are sent only
  when they actually changed (not the whole register every cycle — a customer with 1000 mostly-
  unchanging devices sends next to nothing most cycles), alerts only past a cursor, and findings/
  compliance are never sent at all (the MSP computes those itself once the register is mirrored,
  the same way it already does for its own local devices). Default cycle: 60 seconds, not the
  console's own on-screen refresh rate. See [Deployment](docs/deployment.md#msp-live-devices-and-alerts-from-a-customers-own-master).
* Independent of `--backup-upstream` (1.4.0): run either, both, or neither.

## 1.4.0: an Overview tab across sites, and backups reaching an MSP

* **Overview tab** (off by default; an administrator turns it on under Settings → Overview page):
  one row per site — the local network and every remote agent you can see, respecting your own
  site access — with online status, device count, open alerts by severity and last report time.
  Click a row to open that site's devices. Useful once you manage more than a couple of sites: an
  MSP with several customers, or one business with several branches.
* **Backups can reach an MSP** (`denis run --backup-upstream https://your-msp:8081`, with a token
  from `denis agent-token issue`): a customer's own scheduled backups are also pushed, outbound
  only, to the MSP's master, landing under `backups/from-agents/<id>/` there — so the MSP still
  has yesterday's device list if that customer is ever hit by ransomware, independent of whether
  the customer also reports live as an agent. See [Deployment](docs/deployment.md#msp-keeping-a-copy-of-a-customers-backups).

## 1.3.0: install a license from the console, no file needed

* **Settings → License**: paste a license's two lines directly into the console instead of
  passing `--license-file` — an administrator can install, see the status of, or remove a
  license without touching the command line or restarting. It takes effect immediately. A
  license given via `--license-file` still works and is used when nothing is pasted in the
  console. In an MSP/multi-customer setup the license belongs on the top-level install with a
  console (your own instance, or each customer's master) — agents reporting into a master never
  need their own.

## 1.2.0: many more critical ports scanned, identified and risk-scored

* **Scanning and risk-scoring now cover far more services**: RPC/NetBIOS (111, 135, 137, 138), SNMP
  (161), LDAP/LDAPS (389, 636), more databases (MSSQL, PostgreSQL, Oracle), Redis, MongoDB and
  Elasticsearch (all unauthenticated by default), Memcached (DDoS amplification), the Docker API
  without TLS (full host control if reachable), WinRM, Webmin, NFS, PPTP and more SMTP/IMAP/POP3
  variants — about 25 additional ports, each shown as its own named risk factor (e.g. "+20 Redis is
  reachable on the network (no password by default)") when found open, and counted by the
  "risky service reaching outside the LAN" rule the same way Telnet/RDP/SMB already were.

## 1.1.0: a proper logo, a unified look for controls, the site filter respects access control

* **A new logo**: a checkmark joining three device nodes (verified, connected devices), replacing
  the earlier radar-sweep mark. Used as the favicon and the default header/sign-in mark.
* **Every button, dropdown and checkbox now looks like one family**: consistent padding, a subtle
  shadow and hover state, and dropdowns/checkboxes are drawn the same way in every browser instead
  of falling back to the operating system's own look. Every table's **Columns** button now sits in
  a header strip attached to that table, not floating loose above it. Settings' section links
  (Branding, HTTPS certificate, Updates…) are now a row of buttons, not plain text links.
* **The site filter (Devices/Topology/Trends) respects per-site access control**: a user only sees
  the sites they can actually read, both in the dropdown itself and in what "Local" and each
  agent's name mean for them — matching what the Devices list already enforced server-side.

## 1.0.0: a commercial license, per-site access control, a logo

* **License**: DENIS is no longer MIT/Apache-2.0. It is now source-available under the **DENIS
  Community License**: free to read, build and run for personal, non-commercial use on up to 100
  devices. Any organisational use, or more than 100 devices, needs a commercial license — see
  [LICENSE](LICENSE) and [LICENSE-COMMERCIAL.md](LICENSE-COMMERCIAL.md). A license is a small
  signed file (`denis serve --license-file …` / `denis run --license-file …`); the Devices page
  shows a banner when you are over the Community cap or a license file has a problem, and the
  device list (and its CSV/report) is limited to the first 100 devices until one is installed.
  Detection and alerting are never limited by this — every device is still monitored.
* **Per-site access control**: an administrator can now grant each user **read**, **write** or
  **no access** to each site (the local network, or a remote agent) from the Users page (the
  **Sites** button on a user's row). Useful for an MSP whose technicians should only see their
  own customers, or to keep one site's devices out of a viewer's sight entirely. Nothing changes
  for an install that never opens this: with no grant set, everyone keeps seeing everything, same
  as before.
* **A logo**: DENIS has its own mark now (a device found by a radar sweep), used as the browser
  tab icon and as the default header/sign-in logo when no operator has uploaded their own
  white-label one.

## 0.7.0: grouping, multi-field filters and a room column for Devices; CSV export buttons

* **Devices**: a **Room** column (from the location field), **Group by** (type, room or owner, each with a count
  and an "unset" group for devices with nothing entered), and **Filters** — several conditions at once (type,
  room, vendor, owner, a substring of the OS guess) with a count badge and a **Clear filters** button. Both are
  per-browser and change only what is shown; CSV export is unaffected.
* **Devices CSV** is now a button next to **Import CSV** (it was a plain link). **Alerts CSV** is a button that
  only appears on the Alerts page (it used to sit in the same toolbar as the Devices export, on the Devices, Alerts
  *and* Events tabs, which never made sense on Events).
* **Scaling to a large network**: the console polls every **10 seconds** instead of 5 (the register does not change
  fast enough to need faster, and it halves the load on both sides). The Devices table now renders **lazily**: past
  a few hundred devices, filtering, sorting and grouping still run over every device, but only the rows near the
  current scroll position are ever put on the page, so a list of thousands scrolls as smoothly as a list of forty.
  Smaller networks (almost everyone) see no difference at all.

## 0.6.0: five more industrial and IIoT protocols, and an honest boundary between "decoded" and "port only"

* **Five more protocols, each verified against a real capture**: **Omron FINS** (now fully decoded: memory/parameter/
  program area reads and writes, and the **run/stop** command — the one that matters most), **MQTT** (PUBLISH as a
  write, SUBSCRIBE as a read), **CoAP** (GET reads, POST/PUT/DELETE write), **HART-IP** and **KNXnet/IP** (protocol
  and direction only: their command layout needs a capture to check exact byte offsets against, which DENIS did not
  have for either, so it names the protocol and stops there rather than guess at read vs write). Every decoder,
  including the seven already there, is checked in `tools/ot-samples.sh` against a real capture of that protocol.
* **A port number alone is never protocol identification any more.** The previous "known industrial port, content
  not decoded" fallback — which named a conversation from its port with no check of the payload at all — is gone.
  Ports with no public, checkable signature (Niagara Fox, GE SRTP, MELSEC, PCWorx, CODESYS) are used **only** for
  the *"industrial port crossing the boundary"* finding, whose wording now says "port X (normally Y)" instead of
  asserting the traffic is that protocol.
* Detection rules and watches gained the five new protocol names (`fins`, `hart-ip`, `knxnet-ip`, `mqtt`, `coap`).

## 0.5.0: encrypted OT traffic, allow-list watches, and a way to test without a plant

* **Encrypted industrial traffic is no longer invisible.** Between two local devices DENIS now records the *path* of traffic it
  cannot read: TLS on any port, secured industrial protocols by their port (OPC UA over TLS 4843, Modbus/TCP Security 802, IEC 104
  and DNP3 over TLS, MQTT over TLS), and industrial protocols it does not decode (Omron FINS, GE SRTP, MELSEC, PCWorx, CODESYS,
  Niagara Fox). Who talks to whom, in which direction, how much, and from the TLS handshake the **protocol version** and the **server
  name**. New paths raise `ot_new_conversation` ("the content is encrypted: DENIS sees who talks to whom, not what is said"). TLS
  between two ordinary machines is ignored, and a path never marks a device as industrial by itself.
* **Allow-list watches**: an OT command watch can now match **any communication at all** ("Only these devices may talk to it"): give
  the controller as target and the devices that may talk to it as allowed senders; any other device that talks to it, over any
  protocol, encrypted or not, raises an alert from the first minute.
* **`denis replay FILE.pcap`** runs any Ethernet capture through the decoders, inventory and rules and prints devices, conversations
  and alerts (nothing is stored). **`tools/ot-samples.sh`** uses it on real public captures (Modbus, Siemens S7 including a program
  download, IEC 104, BACnet, an EtherNet/IP firmware change) and on an encrypted capture made from real OpenSSL handshakes, and runs
  in `tools/pre-release.sh`. On those captures the decoders found what each is known to contain.

## 0.4.0: reports, health, two-step sign-in, real topology, software versions

*Built from 0.4.0-rc.1 and 0.4.0-rc.2.*

Reports
* **Reports** is its own page. A report (devices, findings, accepted risks, alerts, trends and the compliance overview)
  is **kept on the server** and can be opened, downloaded as one HTML file, printed or deleted at any time. Make one by hand
  (7 days to a year) or on a **schedule** (weekly or monthly, keeping the newest N; hand-made ones are never removed). The old
  "Printable report" link is gone (`/report` still gives a live one).
* **Compliance** now maps to **NIS2 Article 21**, **ISO/IEC 27001:2022 Annex A** and **NIST SP 800-82 Rev. 3** (through its
  SP 800-53 controls), next to CIS v8, NIST CSF 2.0 and IEC 62443-3-3.

Health and backups
* **Health** page: is DENIS itself in good shape? Packets dropped, database size (and free space in it), free disk, how late the
  sweeps are, rows per table, with a plain sentence for each problem and a count in the menu. New `/metrics`: `denis_database_bytes`,
  `denis_disk_free_bytes`, `denis_capture_dropped_packets`, `denis_backup_age_seconds`, `denis_health_warnings`.
* **Scheduled backups** of the database: **on by default, every day, keeping 7** (change or switch off under Health). List,
  download (administrators only: a backup holds password hashes and authenticator secrets), delete, *Back up now*. Refused when the
  disk could not hold a copy; a warning appears when the newest backup is too old.

Findings
* **Accepted risks are watched**: an event 14 and 3 days before a decision ends, one when it has ended, a daily rescan of the
  open-port ones, and a note (event and audit entry) when the problem has gone away. Nothing is withdrawn automatically.
* **Software versions from banners**: DENIS reads the SSH, FTP and SMTP banner and the web server headers of the ports its scan found
  open and takes a product and version from them. **End of support** (nginx, Apache HTTP Server, PHP, OpenSSL, Exim, ProFTPD, from
  endoflife.date) and **known exploited vulnerabilities** (CISA KEV, with NVD version ranges: nine today, for Apache HTTP Server, PHP
  and Exim) become findings that list, per device, what was read and what it means. No version, no claim. A banner that names a
  distribution is worded "may have been fixed", because distributions backport fixes. The data ships in the program
  (`data/vulndata.json`, built by `tools/build-vulndata.py`); the support dates can be refreshed from endoflife.date (off by default).
  *Verify fix* rescans and reads the banner again.

Alerting
* **Pushover** and **ntfy** notification channels (*Alerting* → *Add a channel*). Pushover: an application token and a user or
  group key; high alerts go as high priority. ntfy: the address of your topic on ntfy.sh or your own server, and an access token
  for a protected topic (never sent over plain `http://`); published as JSON, so device names with any characters are safe.
  Secrets are write-only, as for the other channels.

Detection
* **Network watches** (Rules → *Your network watches*): like the OT command watches, for ordinary traffic. Devices you choose
  (a device, type, tag or network) talking to addresses or ports you did not allow: *only these* / *except these* lists of ports and
  of addresses (`public`, `private`, networks), a protocol, a minimum amount of data, a score and a cooldown. Presets included. New
  rule `it_watch`; it also fires during the learning period.

Sign-in
* **Authenticator app (TOTP)** for everybody: *My account* → set up with a QR code, ten one-time recovery codes, a code after the
  password at sign-in. Each code works once, a wrong code never resets by re-entering the password, five wrong codes void the ticket
  and lock the account like wrong passwords. **Passkeys already count as two factors.** Administrators can **require** a second step for
  administrators or everybody (*Settings* → *Sign-in security*) and **reset** somebody's after a lost phone. The secret is stored in the
  database (a code cannot be checked against a hash): guard backups like the database. See [Security](docs/security.md).
* Fixed: typing a wrong current password when changing your password signed you out ("Your session has ended").

Topology
* **Switches and cables**: add switches (*Settings* → *Switches (SNMP)*, SNMP **v2c**, read only) and the Topology tab shows which port
  each device is plugged into (MAC learned on an access port, never an uplink) and how the switches are cabled (LLDP), and a device's
  panel says **Connected to**. Reads IF-MIB, LLDP-MIB and Q-BRIDGE/BRIDGE-MIB; never sets anything; the community is write-only in the API.
  **Not verified against real switches** (tested with two independent stand-in agents and byte-level checks); **SNMPv3 is not supported yet**.
  See [Switches (SNMP)](docs/switches.md).

Console
* **Table columns**: every table can hide and show columns, reorder them (arrows or drag a heading) and resize them (drag the edge),
  remembered per table in the browser. (In rc.1, moving a column a second time, or hiding one after moving, put headings over the
  wrong data; fixed, and the browser test now moves and hides columns repeatedly and checks every heading against its data.)
* **Setup guide** for a new installation: a checklist (network, sign-in security, notifications, colleagues, backups, branding) whose
  items turn green only when they are really done. It opens once for an administrator, and again from *Settings*.

Under the hood
* Database schema v13 (reports, authenticator secrets and recovery codes, switch snapshots). Updating from 0.3.0 migrates it; the
  automatic backup taken before the update is the way back.
* The browser test now also covers reports, health and backups, table columns, the setup guide, network watches, a real sign-in with
  the authenticator app (set-up, code step, recovery code, required set-up), a switch read over SNMP by an independent agent, and the
  software findings.

## 0.3.0: verify a fix, accept a risk

*Used for a while as 0.3.0-rc.1 on a real network before this release.*

Findings
* **Verify fix** on every finding: DENIS scans the devices again right now and says, per device, **fixed**, **still
  present**, **did not answer** (a silent device is never counted as fixed), **excluded** or **not scanned** (industrial
  devices are never probed; nor can a viewer-mode or passive-only console). Register findings (no owner, not reviewed,
  warranty…) are re-read from the register. The fresh port list is written to the register too.
* **Accept risk** (administrators): decide to live with a finding on chosen devices, with a required **reason** and
  an end date (30, 90, 180 days, a year, or until withdrawn). The device leaves the finding and appears under **Accepted
  risks** with who, when, why and how long is left; it comes back by itself when the time is up, and can be withdrawn
  at any time. Written to the audit log, listed in the printable report, counted in `/metrics`
  (`denis_accepted_risks`). API: `/api/risk-acceptances`, `/api/findings/{id}/verify`.
* Database schema v10 (accepted risks). Updating from 0.2.0 migrates it; the automatic backup taken before the update
  is the way back.

Releases
* The browser test of the console now also covers the Findings page (accepting needs a reason, withdrawing brings a
  finding back, Verify answers plainly).


## 0.2.0: everyday devices, a better asset editor, and release checks

Asset editor
* **Device type is a list**, sorted by name, with **Automatic (detected: …)** first; the icon follows the type, and
  **choosing an icon fills in the matching type**.
* **The icon chooser** opens from a **Change…** button right beside the icon: a searchable window with the icons grouped
  by kind. "robot" finds the vacuum, the lawn mower and the industrial robot.
* **40 new icons and device types** for what is common today: robot lawn mower, smart refrigerator, washing machine,
  dishwasher, oven, coffee machine, air purifier, air conditioner, heat pump, water heater, smart meter, battery storage,
  soundbar, AV receiver, smart display, VR headset, e-reader, baby monitor, pet feeder, smart scale, garage door opener,
  smart blinds, intercom, motion/door/leak sensors, weather station, drone, irrigation controller, NVR, digital signage,
  label printer, time clock, microcontroller, mini PC, management controller (BMC), wireless bridge, powerline adapter,
  vending machine, single-board computer. Discovery recognises many of them by name or manufacturer.
* **Fixed: the device type list could grow wider than its column and cover the field beside it** (Status). Fields now
  always stay inside their column, whatever the text.
* **Fixed: Status, Criticality and Purdue level showed no choices** (and the device type and icon lists were empty) after
  a first sign-in with a forced password change. The lists are now loaded again when missing.

Agents
* An agent **refuses a plain `http://` master address** (its token and data would cross the network readable) unless it
  is this machine or `--allow-plain-http` is given; the documentation explains how the agent channel is protected.

Releases
* **Stable and pre-release channels**: a tag with a hyphen (`v0.2.0-rc.1`) is published as a GitHub pre-release that the
  installer and the console's update check never offer. A candidate is used for a while, then re-tagged as stable.
* `tools/pre-release.sh` runs everything that must pass before a release, including a **browser test of the console**
  (`tools/ui-smoke.mjs`, also in CI and before every release build) and a check that a database from the newest
  published release opens with the new program.


## 0.1.3: installing as a service

* **`install.sh`**, attached to every release: on a Linux server it downloads the release for the machine, checks the
  Ed25519 signature and SHA-256, installs the program, the `denis` user and the systemd service, **picks a free port**
  (8443 or the next free one; 8080 is often taken), starts it and prints the address and the one-time admin password.
  Run it again to update (with a database backup first); `--uninstall` removes it; `--dry-run` only verifies.
* The installation guide starts from the GitHub release (no compiler), including a manual equivalent, port handling,
  changing settings in `/etc/denis/env`, updating, and what happens when a port is taken.
* The console's port is set with `DENIS_LISTEN` (like the other settings), so the unit no longer has to be edited. If
  the port is taken DENIS says so and exits; the unit stops retrying after five failed starts.
* The quick start and the README start from a downloaded release too.

## 0.1.2: OT command watches, rule exceptions, a tidier console

OT
* **OT command watches** (Rules page): alert when a specific command (an S7 CPU stop, a program download, any
  Modbus write, a DNP3 restart, a BACnet re-initialisation…) reaches specific devices, never from senders you allow
  (your engineering station). Ready-made watches for the common ones; works during the learning period.
* The communications matrix shows the **functions each path uses** ("Commands seen"); click one to watch for it.
* New rule `ot_write_escalation`: a path that only ever read starts writing.

Rules
* **Exceptions per rule**: devices, device types, tags or networks a rule stays quiet about (for industrial alerts the
  sender counts too).
* A **minimum score per rule**, and new settings: burst size and window, repeat gaps of the OT rules, how many Purdue
  levels apart count as skipping. *Reset* keeps your exceptions and watches.

Console
* New **Settings** page (branding, HTTPS certificate, updates, demo data and reset) and a separate **Audit log** page
  (filterable); **Users** now only holds users and API tokens.
* **My account** (click your name): password and passkeys moved out of the header.
* The console reloads as soon as an update has restarted it (it used to keep showing "Testing the new program").
* Database schema v9 (functions per path). Updating from 0.1.1 migrates it; the automatic backup taken before the
  update is the way back.

## 0.1.1: update test release

Nothing new in the program itself. This release exists to prove the self-update path end to end on a real
installation of 0.1.0: the update notice with these notes, the signature and checksum checks, the backup taken
before installing, the switch to the new program and the restart, with the data untouched.

Fixed
* The Linux build instructions now say that `libpcap-dev` is needed to build and that the pre-built program only needs
  the `libpcap0.8` runtime library; capturing needs `sudo setcap cap_net_raw,cap_net_admin=eip` on the program once.

## 0.1.0: first public release

Discovery and detection
* Passive discovery (ARP, DHCP, mDNS, SSDP, LLDP/CDP, PROFINET, TCP/IP stack) and polite active discovery.
* Explainable device typing and OS guessing, including DHCP option-list fingerprints.
* Rule-based, scored, tunable detections: new device, new destination, new port, volume, unusual hours, ARP
  conflict, silent device, rogue DHCP server, device bursts, threat-list match.
* Industrial (OT) support: passive decoding of Modbus, S7comm, EtherNet/IP-CIP, DNP3, BACnet, OPC UA and IEC
  60870-5-104; communications matrix; Purdue-level and unexpected-writer rules; never probes industrial devices.

Asset management
* Editable register (owner, location, serial number, warranty, criticality, tags, custom fields), 80+ icons,
  90+ device types, review queue, CSV import/export, change history, findings with fixes, coverage and
  standards mapping (CIS / NIST CSF / IEC 62443, as evidence).

Console and operations
* Web console with roles, passkey sign-in, API tokens, audit log, white-label branding, day/night/auto theme.
* Rules tab (view and tune every detection), built-in HTML documentation.
* Alerting to Slack, Microsoft Teams, Discord, PagerDuty, e-mail and a signed webhook; maintenance mode;
  syslog/CEF and OpenObserve export; Prometheus `/metrics`; `denis backup`.
* Optional built-in HTTPS, master/agent multi-site operation.

Also in this release
* **HTTPS by default** for the console and the agent port, with an automatically generated and renewed certificate
  (from a local DENIS authority) that can be replaced from the console. `--no-tls` for proxies and tunnels.
* Console in **English, German, French, Spanish and Slovak** (per-person choice, administrator default);
  collapsible **sidebar menu**; built-in **demo data**; **self-update** from signed GitHub releases with backup and
  automatic rollback; documentation with screenshots served inside the console.

Not yet verified or built: see the Status section of the README and ROADMAP.md.
