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

Other commands: `denis tenant list`, `denis tenant suspend <id>` / `resume <id>` (pauses a tenant
without deleting anything).

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

## What isolation means in practice

Every route is checked against the signed-in tenant: no response, export, backup, notification
channel or alert ever contains another tenant's data, and a request naming another tenant's ids
(a device, an agent, a user) is refused as if it did not exist. Install-wide enrichment data
(reverse DNS, GeoIP) is shared, by design, since it describes the public internet, not a customer.

## Not yet built

* Single sign-on and passkeys inside a tenant's own console, and a second factor for operator
  accounts (operators have a password only, today).
* The license's device cap is not yet counted across every tenant.
* A tenant's console shows install-wide controls as "managed by the operator of this
  installation" rather than hiding them outright.

See `MULTI_TENANCY_HA.md` in the source repository for the full design and what a later phase
(PostgreSQL, active-passive failover) will add.
