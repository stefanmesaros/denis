# Roadmap and known gaps

DENIS aims to be an honest, self-hostable alternative to the asset-visibility products that cost six figures a
year. This is what is still missing, in rough order. Pull requests welcome.

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
