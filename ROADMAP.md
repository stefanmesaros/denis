# Roadmap and known gaps

DENIS aims to be an honest, self-hostable alternative to the asset-visibility products that cost six figures a
year. This is what is still missing, in rough order. Pull requests welcome.

## Verification still owed
* Master/agent across a real network; TLS with a public CA or behind a reverse proxy.
* Passkeys with a physical security key or phone (verified with software authenticators only).
* OpenObserve, syslog and the chat/e-mail/PagerDuty integrations against the real services.
* Detections on real industrial traffic (verified with hand-built frames and replay).
* An independent penetration test.

## Features competitors have that DENIS does not (yet)
* **SSO** (OIDC / SAML), forcing passkey-only sign-in.
* **Ticketing and CMDB integrations** (ServiceNow, Jira, import from Active Directory / MDM / cloud). The signed
  generic webhook covers one-way notification today.
* **Multi-tenancy** for managed-service providers (white-label branding exists; tenant isolation does not).
* IPv6, Windows collectors, an alternative database (PostgreSQL) and high availability.
* Deep packet inspection beyond the supported industrial protocols; Wi-Fi/wireless monitoring.
* Policy enforcement (NAC): DENIS observes and alerts, it does not block.
