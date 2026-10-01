# Roadmap

What's planned next for DENIS, in plain terms — the detailed internal scoping and engineering
notes behind each item are kept privately alongside the source.

* **IPv6.** Passive discovery, baselines and alerting are largely in place for dual-stack networks
  already (opt-in); full parity with the IPv4 rule set is the remaining work.
* **A packaged Windows collector.** Capture already works when built from source on Windows; a
  signed, installable Windows release is in progress.
* **More vulnerability-scanner integrations.** Nessus/Tenable.io is in; Qualys is planned.
  SAML single sign-on, alongside the OIDC SSO already shipped.
* **Multi-tenancy** for managed service providers running many customer sites from one console.
* **An alternative database (PostgreSQL) and high availability**, for larger or more
  mission-critical deployments than the current single-SQLite-file model targets.
* **Policy enforcement (NAC).** DENIS today only observes and alerts — it never blocks anything.
  An opt-in, explicit enforcement mode (quarantining a device on a managed switch port) is
  designed but not yet built, and would always require administrator action, never run silently.

Shipped items move to [CHANGELOG.md](CHANGELOG.md) once released; this list only tracks what is
still ahead.
