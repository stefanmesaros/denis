# CMDB import (Microsoft Entra ID and Intune)

What DENIS supports, what was actually verified, and what still needs a real tenant to confirm —
written with the same honesty bar as [SSO.md](SSO.md) and [WINDOWS.md](WINDOWS.md): if something
below isn't marked verified, treat it as unverified, not as working.

## What it is

An administrator registers one app in Microsoft Entra ID (Azure AD) and points DENIS at it from
Settings → Integrations → CMDB import. DENIS then pulls device inventory from that tenant on a
schedule (or on demand) and cross-references it against what it has itself discovered, matched by
**exact, case-insensitive hostname only** — a fuzzy match risks pointing an admin at the wrong
device, which is worse than no match at all. A match is shown as extra context on the device (OS,
OS version, join/enrollment type, compliance state, when the source last saw it); it is never
merged into or treated as authoritative over a device's own fingerprinted identity, and nothing is
ever written back to Entra ID or Intune. Import is entirely read-only and one-directional.

Two sources, the same app registration:

* **Entra ID device objects** (`Device.Read.All` application permission) — always, once enabled.
* **Intune managed devices** (`DeviceManagementManagedDevices.Read.All` application permission,
  granted alongside the above) — optional, its own checkbox in Settings.

Both go through the Microsoft Graph API with app-only (client-credentials OAuth2) authentication;
the `.default` scope picks up whatever permissions are actually granted, so enabling Intune later
needs only the extra permission grant, not a new credential.

Active Directory (on-prem, via LDAP) and other MDM sources are on the roadmap but not built —
see [ROADMAP.md](ROADMAP.md).

## What was actually built and verified

* `src/cmdb.rs` implements the OAuth2 client-credentials token fetch, paginated Graph list calls
  (`@odata.nextLink`, capped at 50 pages so a misconfigured or unbounded tenant can never turn a
  sync into an unbounded loop) for both `/devices` and `/deviceManagement/managedDevices`, the
  hostname-matching and upsert/prune logic, and the periodic background job (checks hourly whether
  `sync_interval_hours` have actually passed, syncs if so, logs and retries on failure rather than
  crashing anything — the same posture every other optional integration in this codebase has).
* Every piece of logic that does **not** require talking to the real Graph API has a real, passing
  test: settings and the client secret round-trip and default to off; `sync_now` refuses cleanly
  when disabled or unconfigured (missing tenant/client id, missing secret); imported devices are
  stored and listed back, and a re-sync that no longer mentions a device forgets it; matching is
  exact, case-insensitive, hostname-only; the real Graph response shape for both endpoints
  deserializes correctly (`GraphDevice`, `GraphManagedDevice`, generic `GraphPage<T>` pagination);
  Intune's `complianceState` string maps to a plain `Option<bool>` correctly, including the "no
  compliance state at all" case staying genuinely unknown rather than defaulting to either compliant
  or not; Entra ID and Intune records are keyed `entra:<id>`/`intune:<id>` so the two Graph GUID
  spaces can never collide even for what is the same physical device, and a record saved before
  that prefix existed (every import through v2.22.0) still reads back correctly.
* The web layer's permissions and secret redaction are tested end to end: settings are admin-only
  to change, viewer-readable to see; the client secret is never echoed back in any response, only
  whether one is saved; a blank secret on save leaves the stored one untouched; enabling without a
  tenant/client id, or an out-of-range sync interval, is refused with a clear error; every setting
  change is written to the audit log.

## What is *not* yet verified

* **The actual exchange with a real Entra ID tenant, and a real Intune enrollment, have not been
  run.** Token fetch, Graph pagination against a tenant large enough to actually paginate, and the
  real JSON shape Graph returns for `/devices` and `/deviceManagement/managedDevices` have not been
  exercised end to end against the genuine service — only against hand-written JSON matching the
  documented shape. Everything above this point is verified; this specific path is not, and should
  not be treated as working until it is.
* No mock Graph server was built for this pass, for the same reason none was built for SSO: a
  correct one is itself real work, and doing it under time pressure risks a mock that "passes"
  without exercising the same code paths a real tenant would.
* Recommended before relying on this: register a real app (a free Azure AD tenant is enough),
  grant `Device.Read.All` (and, if using it, `DeviceManagementManagedDevices.Read.All`), admin-consent
  it, and confirm a full sync against real devices — including that a wrong tenant/client id or an
  expired/revoked secret is refused with a clear error rather than a confusing one.
* Large-tenant pagination (more than one Graph page, i.e. more devices than the default page size)
  has not been exercised against a real tenant, only against hand-built multi-page JSON fixtures.

## Configuration

Settings → Integrations → CMDB import (admin only): enable, tenant ID, client (application) ID,
client secret, sync interval (1 hour to 30 days), and the "Also import Intune managed devices"
checkbox. "Sync now" runs one immediately instead of waiting for the schedule. Nothing here needs
a restart.
