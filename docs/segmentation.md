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
| `cidr` | a device whose current IPv4 address falls in the network, or a bare address peer in it |

A zone also has an **except** list, in the same selector shapes: "10.0.20.0/24 except the printer".

Every device and every address peer resolves to **exactly one** zone, so the picture stays a
partition rather than an overlapping mess: a device with an explicit `device` pin wins outright;
otherwise the first zone (in display order) with a matching selector and no matching exception
wins; a device matching nothing lands in the pseudo-zone **Unzoned**. An address that is not a
known device matches the first zone with a `cidr` selector containing it, else the pseudo-zone
**Internet** (public) or **Other private networks** (private). DENIS's own host is resolved like
any device but is never judged (below). The zone editor shows overlaps rather than forbidding them
("14 devices match this zone and an earlier one; they are placed in *Servers*"), since forbidding
them would make a CIDR-based zone and a tag-based zone impossible to use side by side.

Each zone also carries:

* **trust** (`untrusted` / `internal` / `restricted`) — display and scoring context only;
* **inbound/outbound default** (`observe`, the default, or `deny`) — see "Judging traffic" below;
* a **level** (optional, for ordering, e.g. Purdue-style) — display only, never judged;
* **notes**, free text.

No zones are created automatically at upgrade — not from the register's existing free-text `zone`
values, not from Purdue levels. The Zones tab offers starters that build a *reviewed draft* instead
("Start from the zones already typed into the register", "Start from Purdue levels"); nothing is
saved until an administrator reviews and saves it. The register's "Zone / cell" field is unaffected
and keeps its current label; the device panel shows the *resolved* segmentation zone separately
("Segmentation zone: *CCTV*, by tag `cctv`") so the two are never confused.

## Policies: zone rules, allow-lists, and your existing watches

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
* **`it_watch` / `ot_watch`** — your existing network and command watches, **moved in verbatim**
  with byte-for-byte the same matching, limits raised from 30 to 500 each. They still judge only
  what they always judged: a flow (local device to an address **outside** the networks DENIS
  monitors) for `it_watch`, a decoded industrial conversation for `ot_watch`. They are edited on the
  *Rules* page exactly as before — the Zones tab only links there ("N network watches and M command
  watches are on the Rules page"). See [Detection rules › your own watches](detection-rules.md#it_watch-your-own-network-watches-needs---flows)
  for why a watch is not the fix for "these two devices should only talk to each other" once both
  are on networks DENIS monitors — a `zone_rule` or `allow_list` is.

A `zone_rule` or `allow_list` has a **mode**: `alert` (the default once saved by hand) or `record`.
In `record` mode, the very same violations are stored at `info` severity — visible in Events and in
the policy's own violation count — and never raised as an alert or sent anywhere. This is how a
policy is tried before it can page anyone.

Limits (raising the ones watches had before, not removing them): 500 `it_watch`, 500 `ot_watch`,
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
* **Nothing here blocks or changes anything on the network.** No zone, policy or violation is read
  by NAC port control in this release; a future NAC connector's use of this data is designed (not
  built) and summarised at the end of this document.

## The zone matrix

The Zones tab's default view: a 5-minute background job scans `edges`, judges every row with the
same `segmentation::judge` the live detector uses, and groups the result by zone pair. A cell shows
*violation* (red), *unreviewed* (amber), *allowed* or *denied, nothing seen* (green — the second is
the compliance-evidence cell: a deny rule or boundary default covers the pair and nothing crossed in
the chosen window), *nothing seen* (empty — no rule, no traffic), or **not covered** (hatched grey).

**Not covered is the one state worth reading carefully.** Local ↔ local traffic other than decoded
industrial protocols is visible only where east-west accounting is switched on (Settings → Network
interfaces; off by default). A same-site zone pair whose only possible evidence is east-west traffic,
and whose site does not have it on, shows *not covered* — never *nothing seen* and never *denied,
nothing seen* — because DENIS genuinely has no evidence either way. The matrix header says so in
plain words whenever any site is not covered. A cross-zone pair that could never be observed through
a same-site device pair at all (no site has members in both zones) is not subject to this gate: it
shows its ordinary state, since there was never anything to hide.

Clicking a cell opens a drawer with the device pairs and services behind it (newest first,
site-scoped the same way a viewer's other relationship queries are), and *Allow…*/*Deny…* buttons
that open the zone-rule form prefilled with that pair and decision — the same reviewed form every
other zone rule goes through, never applied automatically. A `segmentation_violation` alert's own
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
not silently truncated, past 50 matching devices ("freeze a smaller group, or write a zone rule
instead") or past 200 distinct peers/services across the group.

## For a future NAC connector (designed now, not built)

Nothing in this item changes `nac.rs`. The design for a later release is: a pure query,
`segmentation::basis_for(asset)`, returning a device's zone placement, its open violations (each
with a policy id and revision), and which policies depend on it as an approved peer — so a future
connector's plan can show, and its ledger can cite, *why* a quarantine would be policy-backed, and
can warn when blocking a device would also break an approved flow that depends on it ("Cameras →
recorder", 15 devices). A basis only counts as policy-backed once the violated policy is enabled,
in `alert` mode, at least 24 hours old, confirmed in direction, and the device's zone placement is
asserted rather than merely observed from its address — a device must never be able to earn a block
just by changing its own IP. Saving a policy never by itself makes it enforceable; that would need
an explicit, separately password-confirmed administrator action in a later release.
