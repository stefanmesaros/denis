# IPv6: what exists, what does not, and the plan

DENIS today is IPv4-only. This is not an oversight to patch in one pass — `Ipv4Addr` is the
address type of `Asset.ip_history`, `IpRecord`, `parse.rs`'s subnet/local-address logic, the ARP
sweep in `active.rs`, every detection rule's notion of "destination", the UI's address columns,
CSV export, and roughly 500 existing tests. Rewriting all of that in one change would be exactly
the kind of large, unverifiable, high-regression-risk work this project's own README warns against
elsewhere ("never claim something works when it hasn't been run for real"). This document is the
phased plan instead, and records what has actually been built so far against it.

## Status

**Done, tested, inert (changes no runtime behaviour today):**

* `model::Ipv6Record` — the IPv6 counterpart of `IpRecord`, with a `link_local` flag (a device
  normally has a permanent `fe80::/10` address *and* one or more global ones, so "the current
  address" is not a meaningful idea the way it is for a DHCP-leased IPv4 address).
* `Asset.ipv6_history: Vec<Ipv6Record>` — `#[serde(default)]`, empty for every device today.
  Schema v15 (`ALTER TABLE assets ADD COLUMN ipv6_history TEXT NOT NULL DEFAULT '[]'`); an existing
  database migrates in place, same as every schema step before it.
* `src/ipv6.rs` — a pure, fuzz-tested parser: the fixed IPv6 header plus its extension-header
  chain (Hop-by-Hop, Routing, Fragment, Destination Options — skipped to find the real upper-layer
  protocol without needing to understand any of them), and the three ICMPv6 message types
  discovery needs: Neighbor Solicitation/Advertisement (NDP, IPv6's replacement for ARP) and
  Router Advertisement (announces a gateway, the IPv6 equivalent of noticing a DHCP/ARP gateway).

**Done, tested, opt-in (`--ipv6`, off by default — real behaviour, but nobody gets it without
asking for it):**

* The kernel filter admits ICMPv6 (`bpf_filter`'s `ipv6: bool` parameter, appends `or icmp6`) —
  narrower than admitting all of `ip6`, since nothing downstream decodes IPv6 flows/OT traffic yet
  and there is no reason to hand the kernel filter more than what is actually used.
* `parse_frame` recognises `ETH_IPV6 = 0x86dd` and calls `parse_ndp`, which uses `ipv6::parse` +
  `ipv6::parse_icmpv6` to turn a Neighbor Advertisement into an `Observation::Ndp { mac, ip,
  link_local }` — the IPv6 analogue of `Observation::Arp`, trusted under the same bar: only when
  the Source Link-Layer option agrees with the frame's own Ethernet source (a disagreement is
  silently dropped rather than learned from — NDP has no `arp_mismatch`-style signal yet, see below).
  A Neighbor Solicitation claims no binding, the same asymmetry ARP requests/replies have.
* NDP messages are trusted *without* a subnet-membership check (unlike ARP's `ctx.is_local`):
  RFC 4861 requires a hop limit of 255 on every NDP message, and a conforming host discards any
  that arrived with a lower one (a router would have decremented it) — so anything `parse_ndp` sees
  with `hop_limit == 255` was necessarily sent by a device on this same link, by protocol
  guarantee, not a heuristic. This resolves the passive-discovery case of item 6 below without
  needing to define IPv6 subnet membership at all; the general question (CIDR scopes, flows) is
  still open.
* `inventory.rs` folds `Observation::Ndp` into `Asset.ipv6_history` (`note_ipv6`, mirroring
  `note_ip`) — except there is no "current address" concept to update, unlike IPv4: a device
  keeping both its permanent link-local address and one or more global ones live in the list at
  once is normal and expected, not a conflict.
* The device panel shows whatever `ipv6_history` has (read-only, no detection rule reasons about it
  in the IPv4-style, address-history sense — but see the next section, `new_destination_v6` does
  reason about IPv6 *flows* now).
* **IPv6 flow accounting and a first detection rule (2026-09-29), still opt-in.** `--ipv6-subnet`
  (repeatable, the IPv6 analogue of `--mirror-subnet`) tells `parse::Ctx::is_local_v6` what counts
  as local — resolving item 3's flow/CIDR-scope question below, deliberately as an explicit flag
  rather than autodetection, for the same reason `--mirror-subnet` already is: an IPv6 interface
  can carry several global prefixes plus a permanent link-local one at once, with no single
  "the subnet" to infer the way `net::select` does for one DHCP-leased IPv4 address. With it (and
  `--flows`), `parse_flow_v6` accounts IPv6 flows into a **parallel** set of types (`FlowSampleV6`,
  `FlowRecordV6`, `FlowAgg.map_v6`, `FlowBatch.flows_v6`) rather than widening the existing IPv4
  ones — the same "parallel, not merged" choice as `ip_history`/`ipv6_history` — so the entire,
  heavily-tested IPv4 flow path is untouched. `Detector::ingest_asset_v6` then reasons about them:
  a new rule, `new_destination_v6`, distinct from IPv4's `new_destination` because its scoring is
  deliberately simpler for now (see below), sharing the *same* `Baseline.typical_destinations`/
  `typical_ports` maps as IPv4 (already generic, string-keyed) so one device's learning period and
  destination cap cover both address families together.
* **Deliberately out of scope in this slice** (each a real, separate piece of work): no
  rotation-burst suppression or `new_port` rule for IPv6 yet (the IPv4 versions exist because of
  real alert-noise data this project doesn't have for IPv6 yet — a CDN/relay that hands out a
  fresh IPv6 address per session may currently repeat-alert more than its IPv4 counterpart would);
  no OT protocol decoding over IPv6 (no `parse_ot_v6`); the threat list and network watches
  (`it_watch`) are still IPv4-address-shaped and do not see IPv6 flows; `lan_scan`'s breadth-based
  logic has not been ported. Remote agents do not yet report IPv6 flows to a master (`Report` has
  no `flows_v6` field) — only a local/embedded collector's own IPv6 flows are detected today.

**Not done, and why each is its own step, not a detail of the others:**

1. **No active-discovery equivalent of the ARP sweep.** `active.rs` sweeps every address in a /24
   with ARP; IPv6's address space makes that approach meaningless (a /64 has 2^64 addresses). The
   real equivalent is joining the solicited-node multicast groups of addresses already learned
   passively and/or sending Neighbor Solicitations for specific targets — a materially different
   mechanism, not a drop-in replacement for `active::arp_sweep`.
2. **Rule parity with IPv4 flows.** `new_destination_v6` covers the single highest-value rule;
   rotation-burst suppression, `new_port`, OT-over-IPv6, the threat list and network watches seeing
   IPv6, and `lan_scan` for IPv6 are each their own scoping decision (see above), not a mechanical
   port — several need real alert-noise or incident data this project does not have yet for IPv6,
   the same bar the IPv4 rotation-burst fix itself was held to (see the v2.20.0 roadmap entry).
3. **Remote-agent IPv6 flow reporting.** `agent.rs`'s at-least-once spooling/re-send pipeline
   (`Reporter.spool`, `SPOOL_MAX`, `BATCH_FLOWS`) is IPv4-`FlowRecord`-shaped; extending it to also
   spool `FlowRecordV6` needs the same reliability guarantees, not just a wider `Report` struct —
   deliberately not rushed alongside the master/embedded-collector path above.
4. **CSV export and the API's read side are still IPv4-shaped for flows/destinations**
   (`report.rs`'s CSV writer, per-device baseline endpoint's destination list). Real, separate work
   once there is a reason an admin needs to see IPv6 flow data outside the device panel's raw
   `ipv6_history` list.
5. **No NDP equivalent of `arp_mismatch`.** A Source Link-Layer option that disagrees with the
   frame's own Ethernet source is currently just dropped (see above), the safe default, but ARP's
   `parse_arp` turns the IPv4 equivalent into a reported `Signal` instead of silence — worth adding
   once there is a real incident to design the alert's wording against, not invented speculatively.
6. **No IPv6 conflict/gateway-claim detection.** `Inventory::check_conflict` and `is_gateway` are
   IPv4-`by_ip`-keyed; an IPv6 analogue (a Router Advertisement is the gateway signal, not ARP/DHCP)
   is new mechanism, not a type-widen, and is meaningfully lower-value than IPv4's version since
   IPv6 address conflicts are rare by design (SLAAC/DAD already prevent most of what IPv4's
   `arp_conflict` catches).

## Suggested order

(1) and (2) are both substantial and can happen in either order; (2) specifically wants real
alert-noise/incident data to design against, the same bar the IPv4 rotation-burst fix was held to,
so it should not be rushed just to claim parity. (3) naturally follows once (2) has settled what a
remote agent would even need to spool. (4), (5) and (6) are smaller, worth doing once there is a
real need (an admin asking for IPv6 in CSV export, a real spoofing incident, a real gateway-claim
question) to shape them against.

## What this is not

This is not a claim that DENIS has full IPv6 support. Passive device discovery and IPv6 flow
accounting with one detection rule (`new_destination_v6`) work, opt-in, verified with hand-built
frames (unit tests, not yet a genuine dual-stack network — see ROADMAP.md's "Verification still
owed"). Rule parity with IPv4, remote-agent reporting, active discovery, CSV/API exposure and
conflict/gateway detection are all still IPv4-only or not started.
