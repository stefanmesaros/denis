# Roadmap and known gaps

DENIS aims to be an honest, self-hostable alternative to the asset-visibility products that cost six figures a
year. This is what is still missing, in rough order. Pull requests welcome.

## Next up, in order

1. **Alert noise: stop repeating for the same relationship, generalized beyond a hardcoded port
   list** (in progress, 2026-09-28). Diagnosed against a real 434-alert export from a 20-device
   home network: 86% of all alerts (374/434) were `new_port`, `new_destination` or `it_watch` —
   and most of those were not 374 distinct events, just a handful of relationships re-alerting
   per session/IP: one camera alone produced 117 `new_port` alerts to 2 already-known relay
   servers (a cloud relay that hands out a fresh ephemeral port per session), and 86 of 130
   `new_destination` alerts were TCP/443 or UDP/123 — CDN and NTP-pool IP rotation, not new
   relationships. On a network with hundreds of devices this doesn't scale linearly, it
   compounds, and the realistic admin response is disabling the rule — which defeats the point.
   `new_port`/`new_destination` already cap repeats per destination since v2.0.1/v2.0.2, and
   `new_destination` already special-cases NTP/STUN (ports 123/3478) by a hardcoded allowlist —
   but nothing generalizes past those 2 ports (port 443 legitimately carries both CDN rotation
   *and* the traffic that matters most to still catch, so it can't be blanket-exempted), and
   `it_watch` (custom watches) has no such logic at all — only a flat per-(device, watch, exact
   IP, exact port) cooldown, so any new IP or port re-fires immediately regardless of how
   established the relationship is. Considered ASN/org-based clustering for the generalization
   (closer to how Cisco Stealthwatch's host-groups work) but rejected it: it needs a new
   dependency threaded through the detector (enrichment is currently response-layer only, not
   available during detection — would touch ~77 call sites), the enrichment cache is best-effort
   and often empty for a destination's first contact (exactly when the decision matters most),
   and it wouldn't even solve the NTP case (pool.ntp.org servers span unrelated ASNs by design).
   Going with the same behavioral technique Zeek-style NIDS use instead: auto-detect "rotating"
   per (device, port) from behavior — several distinct new destinations on the same port in a
   short burst — rather than only recognising a hardcoded list, and extend the same
   already-known-destination/port suppression to `it_watch`. Reasoning for a genuinely slow,
   spread-out pattern (the actual signature of something worth an admin's attention) is
   preserved, since it never crosses the burst threshold.
2. **Internal reconnaissance / port-scan detection.** Checked the rule list (2026-09-28): DENIS
   has `new_device_burst` (many *new devices* joining quickly — an external scan/ARP-flood
   signature) but nothing that flags an *already-known* device suddenly touching many different
   local hosts or ports in a short time — the actual signature of a compromised device scanning
   the LAN. Not started yet; natural next step once the alert-noise work above lands, and likely
   shares mechanics with it (churn/burst detection over local rather than external destinations).
3. **IPv6 in capture and the asset model.** See below for the detailed scoping — unchanged, just
   reordered to come after the two items above per an explicit priority call.

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
