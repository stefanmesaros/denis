# Roadmap and known gaps

DENIS aims to be an honest, self-hostable alternative to the asset-visibility products that cost six figures a
year. This is what is still missing, in rough order. Pull requests welcome.

## Next up, in order

1. ~~**Alert noise: stop repeating for the same relationship.**~~ Done in v2.20.0 (2026-09-28).
   Diagnosed against a real 434-alert export from a 20-device home network: 86% of all alerts
   (374/434) were `new_port`, `new_destination` or `it_watch` — and most of those were not 374
   distinct events, just a handful of relationships re-alerting per session/IP: one camera alone
   produced 117 `new_port` alerts to 2 already-known relay servers, and 86 of 130 `new_destination`
   alerts were CDN (TCP/443) or NTP-pool (UDP/123) IP rotation, not new relationships. `new_port`
   and `new_destination` already capped repeats per destination since v2.0.1/v2.0.2, and
   `new_destination` already special-cased NTP/STUN (ports 123/3478) by a hardcoded allowlist, but
   nothing generalized past those 2 ports, and `it_watch` (custom watches) had no such logic at
   all. Considered ASN/org-based clustering (closer to how Cisco Stealthwatch's host-groups work)
   but rejected it — needs a new dependency threaded through the detector (enrichment is
   response-layer only today, not available during detection), the enrichment cache is
   best-effort and often empty for a destination's first contact, and it wouldn't even solve the
   NTP case (pool.ntp.org servers span unrelated ASNs by design). Shipped the same behavioral
   technique Zeek-style NIDS use instead: `new_destination` now auto-detects "rotating" per
   (device, port) from behavior — several distinct new destinations on the same port in a short
   burst — rather than only recognising a hardcoded list, and `it_watch` got the same
   already-known-destination/port suppression for the first time.
2. ~~**Internal reconnaissance / port-scan detection.**~~ Done in v2.21.0 (2026-09-28). Checked
   the rule list: DENIS had `new_device_burst` (many *new devices* joining quickly — an external
   scan/ARP-flood signature) but nothing that flagged an *already-known* device suddenly touching
   many different local hosts or ports in a short time — the actual signature of a compromised
   device scanning the LAN (raised while answering a direct question: "does DENIS tell me if a
   device on my network is scanning it?"). Shipped as a new rule, **Internal network scan**:
   breadth-based (distinct local addresses, or distinct ports on one local address, within a
   rolling window), not connection-state-based, consistent with the rest of the rule engine.
3. ~~**Enforcing passkey-only sign-in.**~~ Done in v2.22.0 (2026-09-28). The passkey
   infrastructure itself (registration, verification, storage) already existed and was mature
   (`passkey.rs`) — and, on inspection, the sign-in *flow* itself was already fully passwordless
   and username-less (a discoverable/resident-key WebAuthn ceremony, `allowCredentials: []`), so
   the actual missing piece was narrower than first scoped: an admin policy, independent of the
   existing "second step" one, that stops a covered account's password from opening a session at
   all once that account has actually added a passkey — never before, so nobody is locked out by
   turning it on. Along the way, fixed the settings storage the policy shares with the existing
   MFA policy: the old setter blindly overwrote the whole blob rather than merging into it, which
   would have silently erased whichever policy was set second.
4. ~~**CMDB import: Intune.**~~ Done in v2.23.0 (2026-09-28). Reused almost the entire Entra ID
   integration shipped in v2.18.0 — same Microsoft Graph OAuth2 app-only auth (the `.default`
   scope picks up whatever permissions are actually granted, so one token already covered both),
   same `ureq` client, same hostname-match/upsert/prune shape (`cmdb.rs`) — just a different Graph
   endpoint (`/deviceManagement/managedDevices`) and different fields (compliance state, OS, last
   check-in). Records from the two sources are now keyed by `<source>:<id>`, since Entra ID device
   objects and Intune managed devices live in separate GUID spaces for what may be the same
   physical machine.
5. ~~**CMDB import: Active Directory (on-prem).**~~ Done in v2.24.0 (2026-09-28). A different
   protocol from Entra ID/Intune, as scoped — LDAP/LDAPS via the new `ldap3` crate (its
   synchronous `LdapConn`, matching how every other optional integration in this codebase already
   runs its blocking I/O inside `spawn_blocking` rather than pulling in a second async runtime),
   its own independent settings/credentials/schedule rather than sharing Entra ID's app
   registration. The matching/store/UI shape from the Entra ID work carried over as expected; the
   real new work was the fetch side and — found only while building this, not anticipated in the
   original scoping — making `cmdb.rs`'s own pruning source-scoped, since it originally assumed it
   was the only writer to the imported-device table and would have deleted Active Directory's rows
   on its own next sync otherwise.
6. **IPv6 in capture and the asset model.** See below for the detailed scoping.
7. **Windows collectors.** Partial groundwork already exists (`WINDOWS.md`, Win32 calls in
   `net.rs`/`health.rs`, the `windows-sys` dependency), none of it verified on a real Windows
   machine. Picked ahead of SAML: it grows what DENIS can *observe* (a large share of real
   networks are Windows-centric and cannot run DENIS at all today), where SAML only changes how
   admins sign in — valuable for enterprise procurement, but it doesn't expand the product's
   actual capability. Do this first while the existing groundwork's context is still fresh.
8. **SAML.** OIDC SSO already exists; SAML is a separate protocol (XML signatures, metadata
   exchange, an ACS endpoint) with a real CVE history (signature-wrapping attacks) and
   meaningfully less mature Rust tooling than OIDC's. Ordered after Windows collectors per an
   explicit priority call, not because it is unimportant — revisit the order if a specific
   customer's procurement is blocked on it.

## Verification still owed
* Master/agent across a real network; TLS with a public CA or behind a reverse proxy.
* Passkeys with a physical security key or phone (verified with software authenticators only).
* OpenObserve, syslog, Elasticsearch/OpenSearch and the chat/e-mail/PagerDuty/Jira/ServiceNow integrations
  against the real services (each is tested against a local fake server, not the genuine article).
* Detections on real industrial traffic (verified with hand-built frames and replay).
* An independent penetration test.

## Features competitors have that DENIS does not (yet)
* **IPv6 in capture and the asset model.** Investigated in depth (2026-09-28): the IP-enrichment
  subsystem (GeoIP, reverse DNS, classification) already works on any `IpAddr` and needs nothing
  further. Everything upstream of it does not: `parse.rs` never recognises an IPv6 frame at all
  (no EtherType `0x86dd` handling), and `FlowRecord.remote`/`Asset.ip_history`/`Scope`'s CIDR
  matching are `Ipv4Addr` throughout — widening any one of them without the others would accept
  IPv6 syntax that can never actually match real traffic, which is worse than not offering it.
  A real implementation needs, at minimum: IPv6 header decode in `parse.rs`, an address type each
  of `Observation`, `FlowRecord`, `Ctx::is_local`, `Inventory` and `Scope::matches` can carry
  (`Asset.ipv6_history` already exists as an unused stub for exactly this), and an NDP-based
  equivalent of the ARP-based device-discovery/gateway-conflict logic. This is a multi-day
  capture-and-model change, not a UI or API addition — deliberately not started as a same-day
  slice alongside CMDB import and the UI redesign; a good first PR would be the address-type
  widening alone, with IPv6 frames still dropped, as a non-behaviour-changing groundwork step.
* Windows collectors, an alternative database (PostgreSQL) and high availability.
* **CMDB import** (Active Directory / Entra ID / Intune / MDM). Ticketing already exists: Jira and ServiceNow
  each file a real issue/incident per alert (Settings → Alerting → Add a channel), alongside the signed generic
  webhook for anything else.
* **SAML**, and forcing passkey-only sign-in. SSO via OIDC already exists (Settings → Single sign-on).
* **Multi-tenancy** for managed-service providers (white-label branding exists; tenant isolation does not).
* Policy enforcement (NAC): DENIS observes and alerts, it does not block.
