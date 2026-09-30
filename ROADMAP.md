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
6. **IPv6 in capture and the asset model.** *(effort: 1/10 remaining)* In progress (2026-09-29): passive
   discovery, flow accounting with a first detection rule, remote-agent reporting, an active
   liveness check for already-known addresses, CSV/API exposure, an `ndp_mismatch` signal (the NDP
   counterpart of `arp_mismatch`) and a `rogue_ra` signal (IPv6's rogue-gateway counterpart of
   `rogue_dhcp`) are all done and shipping, opt-in via `--ipv6`/`--ipv6-subnet` — the latter two
   built speculatively rather than waiting for real incident data, on explicit instruction (see
   IPV6.md). What remains is rule parity (needs real alert-noise/incident data to design well) and
   full active discovery of brand-new addresses (a materially larger, separate mechanism via
   multicast). Full detailed scoping lives in IPV6.md, not duplicated here, to avoid the two
   documents drifting out of sync with each other.
7. ~~**CMDB import: Jamf (and similar MDM sources).**~~ Done in v2.29.0 (2026-09-29). Same shape as
   the Entra ID/Intune/Active Directory sources already built (own settings/credentials/schedule,
   own Jamf Pro API client id/secret via OAuth2 client-credentials, upsert into the shared
   imported-device table, source-scoped pruning so a Jamf sync can never delete another source's
   rows).
8. ~~**A documented public API.**~~ Done 2026-09-29: scoped by reading the existing surface first
   rather than assuming — the routing, auth (`dnt_` viewer/editor tokens) and docs scaffolding
   (`docs/api.md`, already fairly complete) all already existed, so this was hardening and
   documenting what's there, not building new infrastructure. A real gap found while scoping this —
   API tokens had no rate limiting at all, unlike the separate agent protocol — is fixed: a valid
   token is capped at 300 requests/minute, repeated wrong tokens from one address are throttled,
   both `429`. `docs/api.md` now documents both limits, the CMDB/AD/Jamf endpoints and site deletion
   (missing from it), and a new "Stability" section makes an explicit, deliberate choice on
   versioning: the console UI's own API *is* the public one (no separate curated subset, no
   `/api/v1/` prefix) — response shapes are additive-stable, not frozen, and `Event.raw_details`
   is called out as intentionally free-form. Chosen over inventing a parallel versioned surface
   because nothing about this product's usage yet demands one, and a speculative version prefix
   with nothing on the other side of a "v2" is complexity without a customer to justify it.
9. ~~**AI security assistant**~~ — a configurable, event-driven layer on top of the existing AI
   alert explanation feature. Done (2026-09-29): shipped feature-by-feature per an explicit
   instruction, a minor release after each step, so partial progress always stayed usable — see
   AI.md's own "Status" section for exactly what shipped at each step (the Settings → AI page, a
   global on/off switch, and independent toggles for alert explanations, alert triage — an
   assessment alongside DENIS's own severity, never replacing it — recommended actions, a short
   advisory next-steps list DENIS never acts on itself, a dashboard AI summary generated entirely
   by a background job, never by opening the dashboard, "Ask DENIS", a free-text question box that
   only ever answers from a real structured search DENIS itself runs — never from facts the model
   invented — a Settings → AI usage overview, broken down per provider — an AI summary section on
   the existing periodic Reports, written once when a report is generated, never a dependency for
   the report itself to succeed — a fifth, self-hosted "Local model" provider (Ollama, LM Studio,
   llama.cpp's own server, ...), verified end-to-end against a real local Ollama instance, not just
   a fake-server test — Device behavioral analysis: an "Explain behavior change" button offered
   only on the alert kinds that already describe a change from a device's own stored baseline,
   never a fresh analysis of raw traffic — AI threat hunting: folded into "Ask DENIS" as a second
   query shape rather than a separate feature, so a question like "has anything talked to
   1.2.3.4?" searches every device's own already-tracked baseline instead of the event log, still
   only ever describing real rows DENIS itself found — and the AI detection-rule assistant:
   "Suggest a rule with AI" in the network watch form, a free-text description translated into one
   draft watch, the same shape the form's own built-in presets already fill it with — always still
   shown in the ordinary editable form before it is saved, never written or enabled on its own).
   Not part of the numbered spec but still discussed and approved alongside it: a proactive,
   dismissible "this kind of rule would suit your traffic" banner on the Rules page, computed
   cheaply from already-tracked baseline data with no AI call of its own.
   Full spec recorded in full in [AI.md](AI.md) (not duplicated here, same
   reasoning as IPV6.md/WINDOWS.md/SSO.md/CMDB.md each being their own document). Key architectural
   requirements: the detection engine stays fully AI-independent (no LLM in the
   hot path — flows, baselines, first-seen/new-destination/new-port detection, DNS/GeoIP/ASN, alert
   generation/correlation all stay deterministic and local); the AI layer only ever consumes
   compact, already-processed structured context, never raw packets; a dedicated Settings → AI page
   replaces today's scattered AI provider config, with a global on/off switch and a separate on/off
   toggle per capability (alert explanation — already exists, keep enabled if it already was;
   triage; incident correlation; device behavioral analysis; recommended actions; dashboard
   summary; natural-language "Ask DENIS"; threat hunting, read-only; a detection-rule assistant
   whose output always needs explicit admin activation, never auto-enabled; weekly reports) —
   new capabilities default off. The hard requirement most worth flagging up front: opening or
   refreshing the dashboard must never itself call the AI provider — a dashboard summary is marked
   "stale" by the detection engine on a meaningful state change (not every packet/flow), regenerated
   by a debounced background job (a burst of alerts becomes one AI call, not one per alert), cached
   with a state-version stamp, and the dashboard only ever reads the cached result. AI triage is an
   additional signal alongside DENIS's own deterministic severity, never a replacement for it. Needs
   real usage/cost data to tune the debounce window and what counts as "meaningful" well — the same
   bar already held elsewhere in this roadmap (IPv6's rotation-burst rule, NAC) — so the first cut
   should ship deliberately conservative (longer debounce, fewer auto-triggered capabilities) rather
   than guessed-generous.
10. ~~**Vulnerability-scanner import** (Qualys/Tenable/Nessus).~~ Nessus done (2026-09-29); Qualys
    and Tenable.io (a slightly different API, same shape) not yet started. Deliberately its own
    store table (`imported_vulns`, `vulnscan.rs`) rather than folding into `CmdbDevice`'s one-row-
    per-device shape or into `findings.rs`'s fixed, compile-time-known kinds: a scanner reports
    zero or more dynamic findings per host, each with its own severity and plugin id, which neither
    existing shape has room for. Matched to a device by IP first, then hostname, both exact —
    IP-first because a scanner speaks about hosts by address, not name. Complements, not replaces,
    DENIS's own banner/version-based EOL and known-exploited-vulnerability matching (`vulndata.rs`).
    Like every CMDB source, the exact API shape used has not been exercised against a real
    Nessus/Tenable.io instance — see CMDB.md's own honesty accounting.
11. **Windows collectors.** *(effort: 6/10)* In progress (2026-09-29): a real Windows 11 machine
    became available and moved this from groundwork to real verification — `denis.exe agent`
    (reporting over Tailscale to a real master, real token, real TLS) confirmed working end to end;
    `denis.exe run` (local capture) found and fixed a real bug (Windows interface discovery handed
    capture the localized display name instead of Npcap's own device-name convention, so it could
    never have opened a capture handle at all until now — see `WINDOWS.md`), not yet re-verified.
    Still needs: the fix confirmed live, the service wrapper, and the installer — each its own step,
    see `WINDOWS.md`'s own "Suggested order".
12. **SAML.** *(effort: 6/10)* OIDC SSO already exists (Settings → Single sign-on); SAML is a separate protocol
    (XML signatures, metadata exchange, an ACS endpoint) with a real CVE history
    (signature-wrapping attacks) and meaningfully less mature Rust tooling than OIDC's — valuable
    for enterprise procurement, but a materially bigger, riskier piece of work than the OIDC path
    already shipped. Revisit the order if a specific customer's procurement is blocked on it.
13. ~~**Cloud asset discovery** (AWS/Azure/GCP inventory as another CMDB-like source).~~ *(done
    2026-09-30)* All three providers shipped, each with a genuinely different authorization model:
    Azure (`azure_cloud.rs`, 2026-09-29) via Azure Resource Graph, an Azure RBAC role at the
    subscription, not a Graph application permission; AWS (`aws_cloud.rs`, 2026-09-29) via the EC2
    API, a long-lived IAM access key signed with AWS Signature Version 4, no bearer token or OAuth2
    exchange at all; GCP (`gcp_cloud.rs`, 2026-09-30) via Compute Engine's `aggregatedList`, a
    service account JSON key exchanged for an access token through a self-signed RFC 7523 JWT
    bearer assertion — a hybrid of the other two models. All three write into the same shared CMDB
    device list, matched by hostname the same way as the four directory/MDM sources. See CMDB.md
    for exactly what is verified against real fixtures/throwaway keys versus what still needs a
    real account of each provider to confirm.
14. **Multi-tenancy** *(effort: 9/10)* for managed-service providers (white-label branding already exists; tenant
    isolation does not). A real architectural change (data isolation between tenants, not just
    cosmetic branding), ordered after the integration work above since it's a scaling concern for
    an MSP customer base DENIS does not have a lot of yet.
15. **An alternative database (PostgreSQL) and high availability.** *(effort: 9/10)* These two are grouped because
    they are related: SQLite (this project's only backend today) is a real ceiling for HA (no
    built-in replication) and for a multi-tenant MSP's scale, so PostgreSQL support is the
    prerequisite, not HA itself. Large, invasive changes (every `Store` implementation, every
    query) — ordered last among the concrete features because nothing above *needs* them yet.
16. **Policy enforcement (NAC): DENIS observes and alerts, it does not block.** *(effort: 10/10)* Kept last
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
* IPv6 (`--ipv6`/`--ipv6-subnet`: passive discovery, flow accounting, the active liveness check)
  on a genuine dual-stack network — verified so far only with hand-built frames and integration
  tests against an in-process store, not real ICMPv6/NDP traffic or a real socket send (see
  IPV6.md).
* An independent penetration test.

## Notes on items already covered above
Ticketing already exists: Jira and ServiceNow each file a real issue/incident per alert (Settings →
Alerting → Add a channel), alongside the signed generic webhook for anything else — not a gap.
Forcing passkey-only sign-in already exists too (Settings → Sign-in & security). These used to be
listed as gaps in a separate "features competitors have" section here; that section is gone now —
it drifted out of sync with "Next up, in order" more than once (the same feature ending up listed
as both done and missing), so there is now exactly one prioritised list of what remains, above.
