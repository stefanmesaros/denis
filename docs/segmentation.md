# Zones and policies

DENIS observes and alerts; it does not change your network. **Zones and policies describe how your
network is meant to be divided. DENIS checks the traffic it can see against them and tells you when
something crosses a line. It does not block that traffic** — see [Security](security.md) for what
DENIS can and cannot do to the network itself. "Policy" here means *what DENIS checks traffic
against*, never a rule DENIS imposes on the network.

This is the visibility and verification half of segmentation: what the zones are, which paths
between them exist, which paths are approved, and which observed traffic breaks the approval. The
console's **Zones** tab (administrators create and edit; anyone with console access can view) is
where this lives, between *Topology* and *OT*.

## Zones: every device and address resolves to exactly one

A **zone** is a named group of endpoints that should be treated alike at a network boundary — an
IEC 62443 zone, a VLAN's worth of cameras, "Office", "Servers", "Guest Wi-Fi", "Line 1 cell".
Membership is defined by **selectors**, not by a stored member list, so a new camera with the
`cctv` tag, or a new address in `10.0.20.0/24`, joins its zone without anyone editing the zone:

| selector | matches |
|---|---|
| `device` | one specific device |
| `tag` | a device whose register tags contain it |
| `meta_zone` | a device whose register "Zone / cell" field equals it |
| `purdue` | a device whose register Purdue level equals it |
| `site` | every device at that site |
| `type` | the device's effective type |
| `cidr` | a device whose current IPv4 address falls in the network, or a bare address peer in it; an IPv6 network (`2001:db8:5::/48`) places IPv6 address peers only |

A zone also has an **except** list, in the same selector shapes: "10.0.20.0/24 except the printer".

Every device and every address peer resolves to **exactly one** zone, so the picture stays a
partition rather than an overlapping mess: a device with an explicit `device` pin wins outright;
otherwise the first zone (in display order) with a matching selector and no matching exception
wins; a device matching nothing lands in the pseudo-zone **Unzoned**. An address that is not a
known device matches the first zone with a `cidr` selector containing it, else the pseudo-zone
**Internet** (public) or **Other private networks** (private) — IPv6 peers included, when IPv6 flows
are on: unique-local (`fc00::/7`) addresses are private, global ones public. DENIS's own host is resolved like
any device but is never judged (below). The zone editor shows overlaps rather than forbidding them
("14 devices match this zone and an earlier one; they are placed in *Servers*"), since forbidding
them would make a CIDR-based zone and a tag-based zone impossible to use side by side.

Each zone also carries:

* **trust** (`untrusted` / `internal` / `restricted`) — display and scoring context only;
* **inbound/outbound default** (`observe`, the default, or `deny`) — see "Judging traffic" below;
* a **level** (optional, for ordering, e.g. Purdue-style) — display only, never judged;
* **notes**, free text.

No zones are created automatically at upgrade — not from the register's existing free-text `zone`
values, not from Purdue levels; an administrator adds each zone. Starters that would build a
reviewed draft from those values are not built yet. The register's "Zone / cell" field is unaffected
and keeps its current label; the device panel shows the *resolved* segmentation zone separately
("Segmentation zone: *CCTV*, by tag `cctv`") so the two are never confused.

## Policies: zone policies, allow-lists, and your IT and OT rules

A **policy** is one of four kinds, all stored in the same table with optimistic-concurrency
revisions and an append-only history (so "policy 17 at revision 3" is a durable citation, and every
edit, delete or restore is one click to undo):

* **`zone_rule`** — "traffic from zone A to zone B is allowed / denied", optionally only for listed
  services (protocol and ports). `any` is allowed on one side. `bidirectional: true` covers both
  directions with one rule.
* **`allow_list`** — "these devices talk **only** to these peers and services": the cameras-to-
  recorder case, and what *freezing a device's behaviour* (a planned addition, see "What is not yet
  built" below) will eventually produce. Peers can be a device, type, tag, CIDR, zone (including a
  pseudo-zone), `public`, `private` or `any`; each entry can also require a **role** (the subject
  opened the connection, the peer did, or either), checked only when the edge's direction is
  confirmed.
* **`it_watch` / `ot_watch`** — your existing IT and OT rules, **moved in verbatim**
  with byte-for-byte the same matching, limits raised from 30 to 500 each. They still judge only
  what they always judged: a flow (local device to an address **outside** the networks DENIS
  monitors) for `it_watch`, a decoded industrial conversation for `ot_watch`. They are edited on the
  *Rules* page exactly as before. The Zones tab's **Policies** view lists them too, read-only, each
  with an "IT rule" or "OT rule" chip, what it looks for and who it is about, and an
  **Edit on Rules** button that opens the Rules page at that rule; the Rules page links back
  (**Zone policies**), so everything that can alert on traffic is in one list. See [Detection rules › your own IT rules](detection-rules.md#it_watch-your-it-rules-needs---flows)
  for why an IT rule is not the fix for "these two devices should only talk to each other" once both
  are on networks DENIS monitors — a `zone_rule` or `allow_list` is.

An IT or OT rule and a zone policy overlap only in a narrow case: "this kind of device must not talk to that
kind of place". An IT rule (cameras to the internet) and a `zone_rule` (CCTV to Internet: deny) can
both exist and both fire; they raise different alerts (`it_watch`, `segmentation_violation`) with their
own cooldowns. A rule of yours is "tell me when this happens" over one flow or one command; a zone policy is
"this path is (not) approved" over the paths DENIS has seen, can be tried in `record` mode, and is cited
by revision. Muting an alert for certain devices is a third thing, an **exception**, on the Rules
page. The picker for "which devices" is the same on both pages: a device, a type, a tag, a network, and
(for zones and your rules) a Purdue level, the register's "Zone / cell" field or a site.

<a id="a-zone-as-a-watchs-subject"></a>
### A zone as a rule's subject

A IT or OT rule may name a **zone** in its device lists (an IT rule's *for these devices* and *never for*,
an OT rule's *targets* and *allowed senders*; never an exception). It is stored as `{"kind": "zone", "value": "z:<id>"}`
and means exactly what the zone means: the devices that resolve into it (the first matching zone by position, a device
pin first). Things worth knowing before using it:

* **The rule follows the zone.** Editing the zone, editing another zone that takes devices from it (the first matching zone
  wins), or moving a device (tag, register field, Purdue level, address) changes which devices the rule covers, with no
  edit to the rule. The device's own
  attributes are read at match time, like every other rule subject; the zone definitions are the ones the segmentation
  engine compiled at its last reload (within seconds of a zone edit).
* **Observed placements count.** A device that is in a zone only by its address (`cidr`) or by a detected type is
  covered like any other; the preview reports how many are in the zone only that way, since a device can change those
  itself.
* **IT rules see outside traffic only.** A zone in an IT rule means these devices' traffic to addresses
  outside the networks DENIS monitors. The card, the form and the Policies list are labelled *outside traffic only*.
  OT rules see decoded industrial conversations between devices, east-west included.
* **A missing zone suspends the rule.** A rule that names a zone which does not exist (deleted, no zones compiled
  yet, or not found after an import) matches nothing and is shown as suspended on the Rules page; it is never
  widened. The console refuses to delete a zone a rule follows (`409`, naming the rules) and a *new* zone subject
  must name an existing zone when saved. Zones cannot be disabled; only built-in places (Unzoned, Internet, Other
  private networks) cannot be named.
* **The zone side says who follows it.** The zone list, the zone editor and its history name the rules that follow
  the zone, and after a zone is edited, deleted or restored the console reports how many devices each followed zone
  gained or lost (also noted in the audit log, `watches_following`), because moving a device out of one zone can move
  it into another.
* **Why it matched, later.** A rule alert has no policy revision, so one that matched through a zone records the zone
  id, name and revision, how the device was placed and the segmentation snapshot in its details (`zone_subject`); the
  revision's contents are in the zone's history.
* **Export and import.** `GET /api/rules/export` writes each zone subject with the zone's name in `note`. Importing a
  file whose zone id exists here under a different name is refused (zone ids differ between installs), as is one that
  names a zone that does not exist. An older DENIS refuses the new kind on import with "unknown subject kind". If DENIS is downgraded
  with such a rule saved, the older version treats a zone subject as matching no device: a rule whose *for these devices*
  or *targets* list names only zones then matches nothing, but a zone in a *never for* or *allowed senders* list excludes
  nobody, so that rule would alert on more. Remove zone subjects before downgrading.

A `zone_rule` or `allow_list` has a **mode**: `alert` (the default once saved by hand) or `record`.
In `record` mode, the very same violations are stored at `info` severity — visible in Events and in
the policy's own violation count — and never raised as an alert or sent anywhere. This is how a
policy is tried before it can page anyone.

Limits (raising the ones your rules had before, not removing them): 500 `it_watch`, 500 `ot_watch`,
1000 `zone_rule`, 500 `allow_list` (each up to 200 entries), 64 zones.

## Judging traffic: `segmentation_violation`

DENIS judges every **edge** it observes — east-west records (local ↔ local, off by default, needs
flow capture), flows (local ↔ outside) and decoded industrial conversations — against the current
zones and policies, live, in the detector, where each is already observed. This is a generalisation
of the existing `ot_purdue_skip` rule's shape (pair-based, no learning, a fixed cooldown), but it
reads *zones*, not only Purdue levels, and it reads every edge source, not only decoded industrial
traffic.

For an edge with client side C and server side S:

1. **Allow-list check.** For each enabled `allow_list` that names C or S as a subject: if nothing in
   its `allowed` list matches the traffic from that subject's point of view, that is a violation.
2. **Zone check** (only when C and S resolve to different zones):
   * an enabled **deny** `zone_rule` covering the pair and service wins outright (checked before any
     allow, so an explicit deny can never be overridden by a broader allow);
   * otherwise an enabled **allow** `zone_rule` covering it clears the traffic;
   * otherwise, if the destination zone's **inbound default** or the source zone's **outbound
     default** is `deny`, the crossing is a violation ("a zone boundary with nothing allowing it");
   * otherwise the crossing is simply *unreviewed* — described, not alerted on.
   * When the edge's direction is not confirmed (a flow, or a guessed port match), both orientations
     are checked and **a violation is only raised when both say so** — the benefit of the doubt goes
     to the traffic, so a guessed direction never turns an allowed path the other way round into
     "zone X reached zone Y".
3. Intra-zone traffic is never judged at the zone level (an `allow_list` can still cover it). DENIS's
   own traffic, and baseline-seeded edges with no real observation behind them, are never judged.

Each violation carries a fixed, documented score: **+70** for an explicit deny, **+(the policy's own
score, 60 by default)** for an allow-list miss, **+55** for a boundary default with nothing allowing
it; **+15** more for a decoded write/control command, **+10** when the far side's zone is rated
*restricted*, **+10** when the near side's zone is rated *untrusted*. The alert names the devices,
the zones (with each side's placement — asserted by tag/type/etc., or merely observed from an
address), the policy and its revision, and the direction's confidence, in the same *Segmentation*
section of the alert dialog.

Noise control: a cooldown of `segmentation_cooldown_hours` (default 6) per (client, peer, protocol,
port, cause); every fresh violation by the same client and cause in one ingest batch becomes **one**
alert ("and N more"); after six alerts for one client in an hour, further ones that hour are stored
at `info` only. `segmentation_violation` joins the existing `ot_intrusion` incident pattern, and
forms its own **`lateral_movement`** incident together with a network scan (`lan_scan`/`lan_sweep`)
on the same device — see [Incidents](incidents.md).

`ot_purdue_skip` is left exactly as it is. Once Purdue-level zones exist (the Purdue starter), an
out-of-level OT conversation can raise both rules — that is expected, not a bug, and `ot_purdue_skip`
can be switched off on the Rules page if it becomes redundant for a site.

## Safety model

* **Judging traffic, raising alerts, and resolving zone membership are automatic** — they are
  observation, the same bar DENIS applies everywhere else.
* **Creating, editing, reordering, deleting or restoring a zone or a policy is always an
  administrator**, through the console, with the change previewed before it is saved and versioned
  afterwards (`revision`, 409 on a stale edit, history and restore). No password re-confirmation —
  this changes what DENIS *says*, not the network, the same bar as `PUT /api/rules`.
* **DENIS never learns a policy by itself.** Nothing promotes observed traffic to "allowed" on its
  own; only a person's save creates or widens a policy.
* **By default nothing here blocks or changes anything on the network.** No zone, policy or violation
  causes a block by itself: blocks are made by an administrator, one at a time, through the enforcement
  connectors described under [Enforcement connectors](#enforcement-connectors) below. What the
  zones and policies feed into that is only a *suggestion* (the next bullet). The one exception is
  automatic enforcement by rules (level (b), experimental, off by default): once an administrator
  switches it on and marks a policy for it, that policy can block or quarantine a device that keeps
  breaking it (see [Enforcement, automation](enforcement.md#automation)).
* **"Offer to block devices that violate this" only makes suggestions, unless you also mark the
  policy for automatic enforcement.** A zone policy or an allow-list has an on/off setting for it (off by default,
  changed through the policy API for now; there is no checkbox in the console yet). It is an
  ordinary edit of the policy: administrators only, a new revision, in the history and the audit
  trail. When it is on, DENIS counts how often a device keeps breaking that policy and, once it has
  done so repeatedly (by default in 3 separate minutes at least 10 minutes apart, within a day) and
  the policy has stood unchanged for 24 hours, records a *suggestion* to block the device. A suggestion
  is shown to an administrator who may block devices as a card at the top of the Alerts page and in the device's own
  panel, with a **Review block...** button. The button only opens the plan dialog (what DENIS would block, for how long,
  what it would cut off); nothing is blocked until you confirm there with your password, exactly as for every other
  action, and the card is not shown while enforcement is switched off or when you lack the permission to block a
  device. A block made from a suggestion closes it. The stored ones are also listed at `GET /api/nac/prompts`. A
  suggestion itself notifies and blocks nothing. Suggestions
  are only recorded while Settings → Response policy is switched on and a connector or a switch could
  actually act on the device; they are never recorded for DENIS itself, the gateway or a device with
  an open address conflict, and they close by themselves after a week without a new violation. A
  policy that offers to block can also be marked for automatic enforcement (level (b), experimental,
  off by default); then DENIS acts on the suggestion itself, within the limits described in
  [Enforcement, automation](enforcement.md#automation).
  Only a policy that is enabled, in `alert` mode (not `record`) and opted in can produce one. The
  thresholds (3 separate minutes at least 10 minutes apart, a reminder every 24 hours, expiry after 7
  days) are stored under the setting `nac_prompts`; there is no way to change them from the console or
  the API yet, and `GET /api/nac/prompts` shows the values in force.

  *Verified vs. not verified:* the counting, the gates and the storage are covered by tests with
  hand-built violations and run on SQLite and PostgreSQL; nothing has been seen on a live network. The card
  is checked in a browser against a stand-in for the API.

## The zone matrix

The Zones tab's default view: a 5-minute background job scans `edges`, judges every row with the
same `segmentation::judge` the live detector uses, and groups the result by zone pair. A cell shows
*violation* (red), *unreviewed* (amber), *allowed* or *denied, nothing seen* (green — the second is
the compliance-evidence cell: a deny rule or boundary default covers the pair and nothing crossed in
the chosen window), *nothing seen* (empty — no rule, no traffic), or **not covered** (hatched grey).

**Not covered is the one state worth reading carefully.** Local ↔ local traffic other than decoded
industrial protocols is visible only where east-west accounting is switched on (Settings → Capture
interfaces; off by default). A same-site zone pair whose only possible evidence is east-west traffic,
and whose site does not have it on, shows *not covered* — never *nothing seen* and never *denied,
nothing seen* — because DENIS genuinely has no evidence either way. The matrix header says so in
plain words whenever any site is not covered. A cross-zone pair that could never be observed through
a same-site device pair at all (no site has members in both zones) is not subject to this gate: it
shows its ordinary state, since there was never anything to hide.

Clicking a cell opens a drawer with the device pairs and services behind it (newest first,
site-scoped the same way a viewer's other relationship queries are), and *Allow…*/*Deny…* buttons
that open the zone-rule form prefilled with that pair and decision — the same reviewed form every
other zone policy goes through, never applied automatically. A `segmentation_violation` alert's own
*Segmentation* section (zones, cause, policy, direction confidence) has the same *Allow this…*
button, prefilled from the alert's own stored evidence.

The window picker (1/7/30 days) and the coverage/compliance reasoning above apply the same way to
both the full matrix and one cell's drawer.

## Freezing a device's observed behaviour

The device panel's Segmentation section has *Freeze this device's behaviour…* (administrators). It
reads that device's own `edges` over the last 1-30 days (14 by default) and turns them into a
reviewable `allow_list` draft: one candidate entry per (peer, protocol, port, role), with its own
evidence (first/last seen, capture windows, direction confidence, which sources fed it). A candidate
seen in only one capture window is unticked by default ("seen once — often noise or a one-off"), and
more than five distinct public addresses sharing one protocol/port collapse into a single "any public
address" entry (a rotating service, so the list stays reviewable). **Nothing is written by computing
a draft.** It is shown for review — every entry can be ticked or unticked, the name, mode, score and
cooldown edited — and only becomes a real policy when an administrator sends it, via *Save*, to the
same `POST /api/policies` any hand-written policy goes through. It saves in `record` mode by default:
violations are stored and shown, never notified, until an administrator switches it to `alert`.

A site whose east-west accounting is off gets a warning in the draft: the frozen list holds only
traffic to outside addresses and decoded industrial conversations, and would start flagging
local-device traffic the moment east-west accounting is switched on.

"Freeze every {type} at this site" (the device list's own type filter, same dialog) resolves every
matching device — excluding the DENIS host itself and any retired/lost device — and names each one
explicitly as a `device` subject (today's selector vocabulary has no single "type AND site"
selector, so an explicit list is how a bounded group of specific devices is expressed). Refused,
not silently truncated, past 50 matching devices ("freeze a smaller group, or write a zone policy
instead") or past 200 distinct peers/services across the group.

## Enforcement connectors

*Settings → Response policy* is where an administrator lets DENIS block a device. It is separate from zones and policies:
no policy ever blocks anything by itself. Everything is off until someone turns it on, and every block is one
administrator's decision, made for one device at a time.

* **The switch.** *Allow administrators to block devices from DENIS* is off by default. Switching it off stops new blocks
  at once and does not undo any. The same page sets the most blocks per hour (10 by default, at most 100, all
  administrators together). The switch and the cap apply to switch ports and to every connector below.
* **Who and how.** Only a signed-in administrator (never an API token, never `--insecure-no-auth`). A block starts with a
  **dry run** that shows what would happen and every warning or refusal, then needs a **reason** (3 to 200 characters)
  and the administrator's **password** again. The password check counts against the account's [sign-in
  limits](security.md#sign-in-limits-and-lock-out). Each block is audited (`nac.<connector>.block…`), kept in a ledger and
  announced on the alerting channels.
* **Unblock** is always possible: it needs a reason and the password too, but it is **not** stopped by the switch or the
  hourly cap and is never refused by the guards below. Blocks that DENIS made and has not undone are listed under
  *Currently blocked by DENIS* (same page) with an **Unblock…** button, and on the device's panel. A block of a connector
  that has since been removed or paused stays listed, without the button.
* **The connectors.** All twenty kinds in the code are wired: switch ports by SNMP, FortiGate, Palo Alto, Check Point, Juniper SRX, Cisco ASA, Cisco FTD through FDM and through FMC,
  SonicWall, WatchGuard, OPNsense, MikroTik RouterOS (an address list and two forward drop rules over the REST API; simulator-tested
  only, see `docs/nac/mikrotik.md`), NSX-T, UniFi, Meraki, AWS, Azure, Hyper-V, Proxmox and RADIUS Disconnect. Each has a
  setup page in `docs/nac/` (named under the connector's *Setup notes*). Firewalls block an address by changing a group or list that you
  own; UniFi and Meraki block a MAC; AWS, Azure, Hyper-V and Proxmox move a VM into a quarantine group or firewall; RADIUS ends a
  session. Apart from SNMP port control, which has been tried on one real switch, each of them is labelled *Experimental* (simulator
  tested only) and needs the lab switch before it can block; see [Enforcement](enforcement.md).
* **Protected lists.** Each connector has its own *Never block these ...* list (addresses, MACs, VM names, instance ids,
  guests or targets). Put DENIS itself, the gateway and your management hosts on it; for Hyper-V and Proxmox it must name
  the VM or guest that DENIS runs in.
* **Guards that need no setup.** For every connector that takes an address or MAC, a block is refused before anything is
  sent for a loopback, unspecified, broadcast or multicast address, for DENIS itself and for the gateway, and when the
  address list DENIS checks against cannot be read. For an address or MAC named in an **open address-conflict
  (`arp_conflict`) alert from the last 24 hours** (two devices claim it, so the block may hit the wrong one), the dry run
  shows a warning and a box, **I understand that two devices claim this address and the block may hit the wrong one**, which the administrator must tick; if
  DENIS cannot read its alerts or devices, the block is refused with no box. Ticking is recorded in the audit log. VM and
  instance targets are not addresses, so only their protected list applies.

**Verified vs. not verified.** Every connector except SNMP has been tested only against a local simulation of the vendor's documented
interface, and the console says so next to each one: *Simulator only: not yet validated on real equipment*. None of those has been tried against real vendor hardware or a real
cloud account. **Lab switch:** while *Allow connectors that are not validated on real equipment (lab use)* (Settings →
Enforcement, administrators only, audited) is off, which is the default for a new install, DENIS refuses to block
through such a connector, in the preview and again in the apply; testing, reading and unblocking still work. An install
that already had a connector when it was upgraded gets the switch turned on once, with a notice in the console and an
audit entry (`nac.lab.auto_enabled`), so nothing silently stops working; an administrator can turn it off. The kinds
validated on real equipment are listed in one table, `VALIDATED_ON_HARDWARE` in `src/nac_registry.rs` (today: SNMP). Treat the first block on each as a trial on a device you can afford to lose, and unblock it to check the
way back. The SNMP port control has been tried on one real switch ([Switches](switches.md#what-is-verified-and-what-is-not)).

For the safety model, the five actions, quarantine, durations, permissions and the table of what each connector can do,
see [Enforcement](enforcement.md).

## How zones and policies feed blocking

Zones and policies do not block anything on their own. They feed blocking in two ways:

* **The reason shown to a person.** The device panel's segmentation section (`GET /api/assets/{id}/segmentation`)
  shows a device's zone placement, its open violations (each with the policy and its revision) and which policies
  depend on it as an approved peer, so you can see *why* a block would be policy-backed and whether blocking the
  device would also break an approved flow that depends on it ("Cameras → recorder", 15 devices).
* **Automatic enforcement by rules** (level (b), experimental, off by default). A policy takes part only when it is
  enabled, in `alert` mode, offers to block devices that violate it, and an administrator has marked it for
  automation with their password; any edit of the policy clears that mark. Saving a policy never by itself makes
  it enforceable. A device can never earn a block just by changing its own address: DENIS never acts on DENIS
  itself, the gateway, industrial (OT) devices or network infrastructure, and every automatic action is time
  limited and audited. See [Enforcement, automation](enforcement.md#automation).
