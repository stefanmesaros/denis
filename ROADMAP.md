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
6. **IPv6 in capture and the asset model.** *(effort: 7/10 remaining)* In progress (2026-09-29): the address-type-widening
   groundwork is done and shipping — see IPV6.md for exactly what is and is not wired up yet
   (currently: passive Neighbor Discovery, opt-in via `--ipv6`, off by default; no active discovery,
   no flows/detection/CIDR-scope awareness of IPv6 yet). Full detailed scoping lives in IPV6.md, not
   duplicated here, to avoid the two documents drifting out of sync with each other.
7. **CMDB import: Jamf (and similar MDM sources).** *(effort: 2/10)* Same shape as the Entra ID/Intune/Active
   Directory sources already built (own settings/credentials/schedule, upsert into the shared
   imported-device table, source-scoped pruning) — the smallest remaining item on this list, and a
   natural next step right after IPv6 while that CMDB pattern is fresh.
8. **A documented public API** *(effort: 5/10)* for third-party integrations (SOAR, ticketing systems beyond
   Jira/ServiceNow, custom dashboards). Today's API is internal-only (built for this product's own
   UI, not for third parties to depend on). Moved ahead of the newer integration sources per an
   explicit priority call: an admin-facing decision, not a technical dependency.
9. **Vulnerability-scanner import** (Qualys/Tenable/Nessus). *(effort: 4/10)* Same integration shape as CMDB import
   — pull findings for devices DENIS already tracks, merge into the register — and it plugs a real
   gap: DENIS's own vulnerability data today comes only from its own banner/version fingerprinting,
   not from a dedicated scanner's much deeper (and often authenticated/credentialed) checks.
   Complements, not replaces, DENIS's own detections.
10. **Windows collectors.** *(effort: 7/10)* Partial groundwork already exists (`WINDOWS.md`, Win32 calls in
    `net.rs`/`health.rs`, the `windows-sys` dependency), none of it verified on a real Windows
    machine. Grows what DENIS can *observe* (a large share of real networks are Windows-centric and
    cannot run DENIS at all today) rather than just how admins sign in, but needs a real Windows
    machine to verify against, so it is scheduled for whenever one is actually available to test on.
11. **SAML.** *(effort: 6/10)* OIDC SSO already exists (Settings → Single sign-on); SAML is a separate protocol
    (XML signatures, metadata exchange, an ACS endpoint) with a real CVE history
    (signature-wrapping attacks) and meaningfully less mature Rust tooling than OIDC's — valuable
    for enterprise procurement, but a materially bigger, riskier piece of work than the OIDC path
    already shipped. Revisit the order if a specific customer's procurement is blocked on it.
12. **Cloud asset discovery** (AWS/Azure/GCP inventory as another CMDB-like source). *(effort: 6/10)* On-prem and
    directory-based device inventory is now well covered (Entra ID, Intune, Active Directory, soon
    Jamf); most real networks these days are hybrid, so this is the natural next inventory source
    once the on-prem side is rounded out — but it is a new integration shape (cloud provider APIs,
    not LDAP/Graph), not a small extension of the CMDB work like Jamf is.
13. **Multi-tenancy** *(effort: 9/10)* for managed-service providers (white-label branding already exists; tenant
    isolation does not). A real architectural change (data isolation between tenants, not just
    cosmetic branding), ordered after the integration work above since it's a scaling concern for
    an MSP customer base DENIS does not have a lot of yet.
14. **An alternative database (PostgreSQL) and high availability.** *(effort: 9/10)* These two are grouped because
    they are related: SQLite (this project's only backend today) is a real ceiling for HA (no
    built-in replication) and for a multi-tenant MSP's scale, so PostgreSQL support is the
    prerequisite, not HA itself. Large, invasive changes (every `Store` implementation, every
    query) — ordered last among the concrete features because nothing above *needs* them yet.
15. **Policy enforcement (NAC): DENIS observes and alerts, it does not block.** *(effort: 10/10)* Kept last
    deliberately: this is a different product category (active network control, not passive
    visibility) with a much larger blast radius when it gets something wrong (a false positive
    blocks a real device, not just a false alert) — worth a deliberate product decision before any
    scoping work, not just the next item to pick up. No single blocking API is standard across every
    vendor, so this is really several connectors, not one feature — in the order worth building
    them (highest reach or best fit for DENIS's own audience per unit of effort, first):
    1. **SNMP `ifAdminStatus`** (standard MIB-II, vendor-agnostic) on the managed switches DENIS
       already polls for topology — `topology.rs` already knows exactly which switch port a
       suspicious device sits on, so this reuses existing credentials and data rather than a new
       enforcement surface from a standing start.
    2. **RADIUS CoA** (RFC 5176, Change of Authorization) — one implementation covers every switch,
       AP or NAC platform that already does 802.1X (Cisco ISE, Aruba ClearPass, FortiNAC included),
       the broadest reach for the effort, but needs a RADIUS server already in the customer's path.
    3. **pfSense / OPNsense** — open-source, real REST APIs (OPNsense's is clean and first-party;
       pfSense needs a package), and matches DENIS's own self-hosted/homelab audience.
    4. **Ubiquiti UniFi** — the same SMB/prosumer/homelab segment as pfSense/OPNsense, with a
       documented (if unofficial-ish) REST API for blocking a client, and a very common pairing
       with exactly the kind of network DENIS already targets.
    5. **Fortinet FortiGate** (FortiOS REST API) — the largest installed base in the SMB/mid-market
       segment DENIS is realistically selling into.
    6. **Cisco Meraki** — cloud-managed, with a modern, well-documented REST API (materially
       friendlier than classic Cisco gear below), and common in the same SMB/education space as
       Fortinet/UniFi.
    7. **Palo Alto Networks** (PAN-OS XML/REST API) — enterprise-grade but a heavier, older
       XML-first API, for a smaller share of DENIS's likely customers than the vendors above.
    8. **Cisco ASA/FTD** — a huge installed base overall, but an older, more complex management API
       surface than Meraki's, and enterprise-heavy like Palo Alto.
    9. **Check Point** — enterprise, its own proprietary management API; similar fit to Palo
       Alto/Cisco above.
    10. **SonicWall** — SMB-oriented but a smaller installed base than Fortinet/UniFi in DENIS's
        likely customer base.
    11. **WatchGuard** — SMB-oriented, smaller share still.
    12. **Juniper SRX** — enterprise-focused, the smallest overlap with DENIS's realistic customers
        of any vendor on this list; last for that reason, not technical difficulty.

## Verification still owed
* ~~Master/agent across a real network~~ Verified 2026-09-29: a real agent, built from source and
  run on a paid VPS in a different country, reported real devices back to a home master over
  Tailscale (self-signed CA, not a public one — that half is still owed), confirmed live in the
  console (a new site, its own subnet, device count, live "last report" ticking down). Found and
  fixed a real gap while doing this: the ingest listener (`--ingest-listen`) was CLI-flag-only, so
  turning it on needed hand-editing the systemd unit and a restart — no portal option existed
  (fixed in v2.25.0: Settings → Network interfaces). A remote agent scanning a shared/hosted
  network's subnet also risks tripping the host's own abuse detection or alarming other tenants —
  worth a `--passive-only` flag on future tests like this against anything not fully your own.
  Still owed: TLS with a public CA (this test used the built-in self-signed one), and behind a
  reverse proxy.
* Passkeys with a physical security key or phone (verified with software authenticators only).
* OpenObserve, syslog, Elasticsearch/OpenSearch and the chat/e-mail/PagerDuty/Jira/ServiceNow integrations
  against the real services (each is tested against a local fake server, not the genuine article).
* Detections on real industrial traffic (verified with hand-built frames and replay).
* IPv6 passive discovery (`--ipv6`) on a genuine dual-stack network — verified so far only with
  hand-built frames (see IPV6.md).
* An independent penetration test.

## Notes on items already covered above
Ticketing already exists: Jira and ServiceNow each file a real issue/incident per alert (Settings →
Alerting → Add a channel), alongside the signed generic webhook for anything else — not a gap.
Forcing passkey-only sign-in already exists too (Settings → Sign-in & security). These used to be
listed as gaps in a separate "features competitors have" section here; that section is gone now —
it drifted out of sync with "Next up, in order" more than once (the same feature ending up listed
as both done and missing), so there is now exactly one prioritised list of what remains, above.
