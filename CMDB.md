# CMDB import (Microsoft Entra ID, Intune, and Active Directory)

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

Three sources, two independent settings sections:

* **Entra ID device objects** (`Device.Read.All` application permission) — always, once enabled,
  via one app registration (client ID + secret).
* **Intune managed devices** (`DeviceManagementManagedDevices.Read.All` application permission,
  granted alongside the above) — optional, its own checkbox, the *same* app registration. Both go
  through the Microsoft Graph API with app-only (client-credentials OAuth2) authentication; the
  `.default` scope picks up whatever permissions are actually granted, so enabling Intune later
  needs only the extra permission grant, not a new credential.
* **Active Directory computer objects** (on-premises, over LDAP/LDAPS) — entirely independent of
  the two above: its own enable toggle, its own credentials (an LDAP bind DN and password against
  a domain controller, ideally a dedicated read-only service account rather than a real admin's
  own login), its own schedule. `src/ad.rs`, via the `ldap3` crate's synchronous client.

All three write into the same imported-device list, each row tagged with which source it came
from (`entra`/`intune`/`ad`) and keyed `<source>:<id>` so the different ID spaces — two different
Graph GUID spaces plus an LDAP distinguished name — can never collide even for what is the same
physical device. Each source's own sync only prunes its own source's rows: an Active Directory
sync can never delete a device Entra ID or Intune imported, and vice versa, even though a periodic
sync of one runs independently of the others.

Other MDM sources (Jamf and similar) are on the roadmap but not built — see [ROADMAP.md](ROADMAP.md).

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
* `src/ad.rs` implements the LDAP bind and subtree search (`ldap3`'s synchronous `LdapConn`, not
  the tokio-async one — this codebase's other optional integrations already run their blocking I/O
  inside `spawn_blocking`, so a second async runtime would be pure complexity for no benefit), the
  same hostname-matching/upsert logic, and its own periodic background job. Settings and the bind
  password round-trip and default to off; `sync_now` refuses cleanly when disabled or unconfigured
  (missing URL/bind DN/base DN, missing password); hostname matching prefers `dNSHostName` over
  the bare `name` attribute, same preference order a real DNS-registered computer object would
  resolve by; an Active Directory sync's own pruning is proven to leave Entra ID/Intune-sourced
  rows untouched, and `cmdb.rs`'s own pruning was fixed to do the same in the other direction (it
  did not originally know a third source could exist).
* `Settings::default()` for both `cmdb.rs` and `ad.rs` was found, while verifying this, to report
  `sync_interval_hours: 0` for a never-configured install rather than the intended 24 —
  `#[derive(Default)]` does not know about a `#[serde(default = "...")]` attribute on one field,
  they solve different problems that happen to look similar. Fixed with a manual `Default` impl on
  both; the UI never showed this (it already had `|| 24` as a display fallback), but the raw API
  response did.

## What is *not* yet verified

* **The actual exchange with a real Entra ID tenant, a real Intune enrollment, and a real Active
  Directory domain controller have not been run.** Token fetch, Graph pagination against a tenant
  large enough to actually paginate, the real JSON shape Graph returns for `/devices` and
  `/deviceManagement/managedDevices`, and the real LDAP bind/search/attribute shape a genuine
  domain controller returns, have not been exercised end to end against the genuine services —
  only against hand-written JSON/attribute fixtures matching the documented shape. Everything
  above this point is verified; this specific path is not, and should not be treated as working
  until it is.
* No mock Graph server or mock LDAP server was built for this pass, for the same reason none was
  built for SSO: a correct one is itself real work, and doing it under time pressure risks a mock
  that "passes" without exercising the same code paths a real server would.
* Recommended before relying on the Graph sources: register a real app (a free Azure AD tenant is
  enough), grant `Device.Read.All` (and, if using it, `DeviceManagementManagedDevices.Read.All`),
  admin-consent it, and confirm a full sync against real devices — including that a wrong
  tenant/client id or an expired/revoked secret is refused with a clear error rather than a
  confusing one. Large-tenant pagination (more than one Graph page) has not been exercised against
  a real tenant either, only against hand-built multi-page JSON fixtures.
* Recommended before relying on Active Directory: a dedicated read-only service account, LDAPS
  (not plain `ldap://`, which sends the bind password in the clear) against a real domain
  controller, and confirm a full sync — including that a wrong bind DN/password, an unreachable
  server, and a base DN with no read access are each refused with a clear, distinguishable error.
  TLS certificate validation for LDAPS has not been exercised against a real domain controller's
  certificate chain (self-signed AD CS roots are common and may need to be trusted explicitly).

## Configuration

Settings → Integrations → CMDB import (admin only), two independent sections:

* **Entra ID / Intune**: enable, tenant ID, client (application) ID, client secret, sync interval
  (1 hour to 30 days), and the "Also import Intune managed devices" checkbox.
* **Active Directory**: enable, server URL (`ldaps://dc.contoso.local:636`), bind DN, bind
  password, base DN, sync interval.

Both have their own "Sync now" to run one immediately instead of waiting for the schedule, and
both feed the one shared imported-device list below. Nothing here needs a restart.
