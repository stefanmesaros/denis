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

**Not done, and why each is its own step, not a detail of the others:**

1. **The kernel filter does not admit IPv6 at all.** `parse::BPF_FILTER`/`BPF_FILTER_FLOWS` only
   pass ARP, IPv4, and a short list of link-layer discovery protocols; every IPv6 frame is dropped
   by the kernel before `parse_frame` ever sees it. Widening this changes what *every* existing
   installation captures the moment it upgrades — more packets reaching userspace, more CPU, on
   machines this project cannot test in advance. This needs its own review and probably its own
   opt-in flag (`--ipv6`?), not a silent default-on change bundled with a parser.
2. **`parse_frame` does not call `ipv6::parse` yet.** Once (1) is decided, wiring it in is small:
   an `ETH_IPV6 = 0x86dd` arm parallel to `ETH_IPV4`'s, producing an `Observation` that
   `inventory.rs` folds into `Asset.ipv6_history` the way IPv4 observations become `ip_history`.
3. **No passive-discovery path populates `ipv6_history` yet.** `ipv6::parse_icmpv6` can already
   recognise a Neighbor Advertisement's target address and source MAC — the same shape of evidence
   ARP replies give `inventory.rs` today — but nothing calls it. This is the natural next step
   once (2) exists: observe NDP the way ARP is already observed, no active probing needed.
4. **No active-discovery equivalent of the ARP sweep.** `active.rs` sweeps every address in a /24
   with ARP; IPv6's address space makes that approach meaningless (a /64 has 2^64 addresses). The
   real equivalent is joining the solicited-node multicast groups of addresses already learned
   passively and/or sending Neighbor Solicitations for specific targets — a materially different
   mechanism, not a drop-in replacement for `active::arp_sweep`.
5. **Detection, the UI, CSV export and the API are all IPv4-shaped.** `detect.rs`'s baselines,
   every rule that reasons about "a destination", the Devices table's IP column, `report.rs`'s CSV
   writer, and the REST API's asset shape all assume one current IPv4 address. Each of these is a
   real, separate piece of work once there is IPv6 data to show — deliberately not started before
   there is.
6. **No IPv6 equivalent of `--iface`'s subnet-membership check.** `parse::Ctx::is_local` decides
   "is this address ours to track" from `--subnet`/the interface's own IPv4 address; an IPv6
   equivalent needs its own answer to what "local" means when an interface can carry several
   global prefixes and a permanent link-local one at once.

## Suggested order

(1) and (2) together, behind a flag, with real traffic on a real dual-stack network before it
defaults on for anyone — not simulated frames, the same bar the README already holds ARP-conflict
and OT detection to. Then (3), since passive NDP observation reuses (2)'s plumbing directly. (4)
and (5) are both substantial and can happen in either order after that; (5) probably wants to start
with just *showing* whatever `ipv6_history` already has (a read-only addition to the device panel)
before any detection rule is taught to reason about it.

## What this is not

This is not a claim that DENIS has IPv6 support. It has an address model and a parser that are
ready for it, tested in isolation, and change nothing about what a running collector does today.
