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
* **SAML**, and forcing passkey-only sign-in. SSO via OIDC already exists (Settings → Single sign-on).
* **CMDB import** (Active Directory / Entra ID / Intune / MDM). Ticketing already exists: Jira and ServiceNow
  each file a real issue/incident per alert (Settings → Alerting → Add a channel), alongside the signed generic
  webhook for anything else.
* **Multi-tenancy** for managed-service providers (white-label branding exists; tenant isolation does not).
* IPv6 fully in capture, Windows collectors, an alternative database (PostgreSQL) and high availability.
* Deep packet inspection beyond the supported industrial protocols; Wi-Fi/wireless monitoring.
* Policy enforcement (NAC): DENIS observes and alerts, it does not block.
