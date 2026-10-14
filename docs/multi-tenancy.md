# Multi-tenancy: separate customers on one installation

An installation that never adds a tenant behaves exactly as before — nothing below changes anything
until you run `denis tenant add`. With a tenant, DENIS gives a second (or hundredth) customer their
own database, detector, background jobs and console, served from the same running process, with
nothing of one customer reachable from another.

## Adding a tenant

```bash
denis tenant add acme --name "Acme"
denis tenant set-hosts acme acme.msp.example
```

`add` only records the tenant; the next start of `denis run` creates its database
(`<data dir>/tenants/acme.db`), starts its runtime and console, and prints its first
administrator's one-time password — the same way an installation's own first start does.
`set-hosts` gives it the host name its console answers on (a request's `Host` header picks the
tenant); pass no hosts to clear them, and a host already claimed by another tenant is refused.
A tenant added while DENIS is running is served after the next restart.

Once added, a tenant has its own:

* database, detector and background jobs (capture, polling, alerting, backups);
* users, branding, settings, integrations, notification channels and audit log;
* agent tokens — issued in that tenant's console, or with
  `denis agent-token issue --tenant acme`, and reporting into that tenant only, through the same
  ingest port as every other tenant.

**Install-wide settings** (updates, restart, TLS, capture interfaces, the license, KEV/GeoIP data,
single sign-on) are refused in a tenant's console — they answer "managed by the operator of this
installation". Port control (NAC) is configured per tenant.

Other commands: `denis tenant list`, `denis tenant suspend <id>` / `resume <id>`, and
`denis tenant limit <id> [key] [value]` (below).

**Suspending a tenant stops everything, without a restart.** A running `denis run` notices the change
within a few seconds: the tenant's agents get `503`, its console refuses requests, and every one of
its background jobs (notification channels, SIEM export, port-control connectors, cloud and scanner
imports, backups, Autopilot and its phone subscribers) is stopped. Nothing is deleted, and the agents
keep their spool and send it after a resume. `resume` accepts the agents again at once and starts the
jobs that can be rebuilt; the few that own something that cannot be rebuilt (one-off tasks) stay
stopped until the next restart of DENIS.

### Limits and the outbound allow-list (set by the MSP, not by the tenant)

A tenant's own administrators cannot change these; they live in the control store:

```bash
denis tenant limit acme                                  # show all, with their defaults
denis tenant limit acme ingest.agent_backup_quota_mb 5000
denis tenant limit acme egress.allow "10.20.0.0/16, siem.acme.example"
denis tenant limit acme ingest.agent_backup_quota_mb     # no value: back to the default
```

| Key | Meaning | Default |
|---|---|---|
| `ingest.max_concurrent_applies` | Agent reports applied (or waiting for the tenant's apply lock) at once. More are answered `429` with `Retry-After`; agents retry. Read at start. | 4 (1-64) |
| `ingest.max_requests_per_minute` | Requests per minute for one agent token (`429` beyond it). `0` = no limit. | 120 |
| `ingest.agent_backup_quota_mb` | Total size of the backups this tenant's agents may upload (counting what pruning to the keep count frees). Past it an upload gets `507` and Health shows a warning to that tenant. `0` = no limit. A single upload is still capped at 500 MiB. | 20480 |
| `egress.allow` | Addresses, CIDR networks or host names the tenant's integrations may reach although they are private (see below). | empty |

The limits apply to a running DENIS within seconds. An upload is streamed to disk (never held whole in
memory) and refused as soon as it passes the cap or the quota, leaving no partial file.

### What a tenant's integrations may connect to

Every tenant except `default` is untrusted with the MSP host's network position. For a tenant's webhooks
and notification channels (including mail servers), SIEM export, port-control connectors (HTTP APIs and
SNMP switches), cloud, CMDB and scanner imports, directory (LDAP) servers and AI endpoints, DENIS refuses
to connect to: loopback, link-local (including the cloud metadata address 169.254.169.254), unspecified,
multicast and broadcast addresses, **the DENIS host's own addresses**, and private ranges (RFC 1918,
100.64.0.0/10, IPv6 unique-local fc00::/7), unless the MSP allow-lists them for that tenant with
`egress.allow`. A host name is resolved and **every** address it resolves to is checked, at connect time
and on the address actually used (a name that answers differently the second time cannot reach a denied
address); a name pointing partly at a denied address is refused whole. The `default` tenant is unchanged.

A tenant's switches and firewalls usually sit in the customer's private network: allow-list the
customer's range (and nothing wider) for the tenant, for example `10.20.0.0/16`. An unreachable target
shows the refusal in the connector's or channel's own error text.

## Moving a customer in or out

```bash
denis tenant export acme --to acme-2026-10-01.db
denis tenant import acme --from acme-2026-10-01.db --name "Acme"
```

`export` writes a tenant's database out as a standalone DENIS database — safe to run while DENIS
is up, openable with `denis serve --db`, runnable as its own installation, or imported elsewhere.
`default` exports the installation's own database. `import` brings a standalone database (an
installation's `denis.db`, a backup, another installation's export) in as a new tenant; the source
file is never changed. An imported customer's agents need their existing token rewritten with the
tenant's prefix (`dat_<id>_…` instead of `dat_…`) — tokens are stored hashed, so DENIS cannot do
this for you.

**Secrets from another installation are not carried over.** Sealed secrets (connector credentials,
channel webhooks and passwords, AI keys) can only be read with the key of the installation that
sealed them. On import, and at every later start of the tenant, a secret this installation cannot
read is removed and listed as "enter again" (Settings shows what is missing, the same notice as after
restoring a backup), and an audit entry `tenant.secrets.reentry_required` names them. It never stops
the import or the start-up. Secrets that do decrypt (an export from this same installation) are kept.

**A database knows which tenant it belongs to.** Each tenant database carries its tenant id (stamped when
the tenant is created or imported; older databases are stamped at their first open). A file placed in
another tenant's slot (for example restoring `acme.db` over `globex.db`) is refused with a clear error and
that tenant is left out, 503, instead of serving the wrong customer's data.

## MSP operator accounts

Separate from each tenant's own users, an **operator** is a technician who works across customers
without having a separate login in each one:

```bash
denis operator add alex                  # prints a random password, shown once
denis operator grant alex acme editor    # role: viewer, editor or admin
denis operator revoke alex acme
denis operator disable alex              # ends their sessions; enable reverses it
denis operator reset-password alex
denis operator delete alex
```

An operator signs in at `/operator.html` on the installation's own console, sees the tenants
they have been granted and each one's device count, open alerts, sites and last agent report, and
opens one to work inside it with the granted role. That tenant's own audit log records them as
`operator:<name>`, not as one of the tenant's own users; the tenant's own sign-in policy (SSO,
required 2FA) does not apply to them, and they cannot use the tenant's own account pages. Access
is re-checked on every request, so a revoke or disable takes effect immediately, not at next
sign-in.

**Second factor (4.1).** Every operator can enrol a second factor on the operator page: an
authenticator app (TOTP) or a passkey, enrolled and removed only with
the password (and a fresh proof once a factor exists). It is required, not optional, wherever an
operator reaches a customer remotely: opening an MSP customer and every request after it need an
enrolled factor and a proof in the current session, and dangerous requests need a proof from the last
10 minutes. Changing the MSP's customer list needs a factor, a fresh proof and the password.
`denis operator reset-factors <name>` removes an operator's factors. Proof times are kept in memory
only, so a restart or a failover asks for a new proof. See [MSP management](msp-management.md).

## What isolation means in practice

Every route is checked against the signed-in tenant: no response, export, backup, notification
channel or alert ever contains another tenant's data, and a request naming another tenant's ids
(a device, an agent, a user) is refused as if it did not exist. Install-wide enrichment data
(reverse DNS, GeoIP) is shared, by design, since it describes the public internet, not a customer.

## Known limits

Isolation of *data* is built into the structure (each tenant has its own database, users, detector,
alerts and console, and a request is checked against the tenant of its host name). Isolation of
*capacity* and of some operational controls is not complete. Plan for about ten trusted tenants per
installation; more works but these limits start to matter.

* **A tenant that fails to load does not stop the others.** If one tenant's database cannot be opened
  (for example it is corrupt, it was left on a newer schema, or it belongs to another tenant), DENIS
  logs it, starts everything else, and answers 503 on that tenant's host until the cause is fixed and
  DENIS is restarted. Check the log after every start and after every update. The automatic backup
  taken before an update covers **every** tenant's database, and an automatic rollback restores all
  of them (the newer files are kept next to them), so the old program never meets a database it
  refuses.
* **Shared limiters.** The password-check gate (Argon2) and the throttle on bad agent tokens (per
  source address) are shared, so one tenant's sign-in storm or token guessing can slow or lock out
  another's. Agent ingest itself has per-tenant apply locks, concurrency, request rate and backup
  quota (above).
* **One secrets key for the whole installation.** Sealed secrets (connector credentials, channel
  webhooks) of every tenant are encrypted with the one installation key, so anyone who can read that
  key can read every tenant's sealed secrets. A ciphertext copied from one tenant's database into
  another's would decrypt (the key is shared); the tenant stamp and the import rules above are what
  keep databases in their own slots.
* **Disk use is only partly bounded.** Agent backups have a per-tenant byte quota; a tenant's own data
  growth is limited by its retention settings, not by a size cap, so one tenant can still fill the
  disk for all.
* **A new tenant, and a resumed one that was suspended at start, need a restart** to start their
  jobs and console (tenants are loaded when DENIS starts). There is no tenant deletion.
* **Shared enrichment data.** Reverse DNS and GeoIP lookups are installation-wide, by design.
* **No link to a tenant's console in mails.** `--public-url` is the `default` tenant's address. A
  tenant's scheduled report emails and automatic enforcement notices carry no console link; the
  notice says where to find the action instead.
* **No high availability with tenants.** DENIS refuses to start with `--database-url` while tenants
  besides `default` exist: their data lives in SQLite files on one node, so the combination is refused
  at start rather than left to diverge. Start without `--database-url`, or move the tenants to their
  own installs.
* **One data key for all tenants** (planned for 4.4): see "One secrets key" above.
* **Reverse proxies must pass the host name through** (`proxy_set_header Host $host;`). A proxy that
  rewrites the host to `127.0.0.1` sends every tenant's traffic to the default console, where the
  credentials do not match (it fails closed, but nobody can sign in).

## Not yet built

* Single sign-on and passkeys inside a tenant's own console.
* The license's device cap is not yet counted across every tenant.
* A tenant's console shows install-wide controls as "managed by the operator of this
  installation" rather than hiding them outright.

* Tenants on PostgreSQL. PostgreSQL and an active-passive pair exist since 4.0.0 (see
  [High availability](high-availability.md)), but only for an installation without tenants: the tenants' data
  still lives in SQLite files on one node.

## Details from the console

Explanations that used to be printed on the console screens. The console shows them behind a small ? button.

* A row per site (device count, open alerts, last report). Useful once you manage more than a couple of sites — an MSP with several customers, or one business with several branches.
* How many of each customer's uploaded backups this install keeps (older ones are removed automatically). Only relevant once customers push backups here.
