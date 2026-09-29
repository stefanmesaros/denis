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
  yet) — the first slice item 5 below suggested starting with.

**Not done, and why each is its own step, not a detail of the others:**

1. **No active-discovery equivalent of the ARP sweep.** `active.rs` sweeps every address in a /24
   with ARP; IPv6's address space makes that approach meaningless (a /64 has 2^64 addresses). The
   real equivalent is joining the solicited-node multicast groups of addresses already learned
   passively and/or sending Neighbor Solicitations for specific targets — a materially different
   mechanism, not a drop-in replacement for `active::arp_sweep`.
2. **Detection, flows, CSV export and the API's write side are all still IPv4-shaped.**
   `detect.rs`'s baselines, every rule that reasons about "a destination", `report.rs`'s CSV
   writer, and `FlowRecord`/`Scope`'s CIDR matching all assume one current IPv4 address. Each of
   these is a real, separate piece of work once there is more IPv6 evidence than device addresses
   to reason about — deliberately not started before there is a rule that would need it.
3. **No IPv6 equivalent of `--iface`'s subnet-membership check for flows/CIDR scopes.**
   `parse::Ctx::is_local` decides "is this address ours to track" from `--subnet`/the interface's
   own IPv4 address, for the *flow-accounting* and *rule-scope* meaning of "local" — a different
   question from the one NDP's hop-limit check already answers above (which is specifically about
   trusting a discovery binding, not about scoping a flow or a CIDR rule). An IPv6 equivalent needs
   its own answer to what "local" means when an interface can carry several global prefixes and a
   permanent link-local one at once.
4. **No NDP equivalent of `arp_mismatch`.** A Source Link-Layer option that disagrees with the
   frame's own Ethernet source is currently just dropped (see above), the safe default, but ARP's
   `parse_arp` turns the IPv4 equivalent into a reported `Signal` instead of silence — worth adding
   once there is a real incident to design the alert's wording against, not invented speculatively.
5. **No IPv6 conflict/gateway-claim detection.** `Inventory::check_conflict` and `is_gateway` are
   IPv4-`by_ip`-keyed; an IPv6 analogue (a Router Advertisement is the gateway signal, not ARP/DHCP)
   is new mechanism, not a type-widen, and is meaningfully lower-value than IPv4's version since
   IPv6 address conflicts are rare by design (SLAAC/DAD already prevent most of what IPv4's
   `arp_conflict` catches).

## Suggested order

(1) and (2) are both substantial and can happen in either order; (2) likely wants a real detection
rule to design against rather than speculative CIDR/flow support. (3) is worth resolving before (2)
needs it. (4) and (5) are smaller, worth doing once there is a real incident/gateway-detection need
to shape them against, same reasoning as (4)'s own entry above.

## What this is not

This is not a claim that DENIS has full IPv6 support. Passive device discovery works, opt-in, and
is verified with hand-built frames (unit tests, not yet a genuine dual-stack network — see
ROADMAP.md's "Verification still owed"). Everything downstream of "what address does this device
have" (detection, flows, CIDR scopes, active discovery) is still IPv4-only.
