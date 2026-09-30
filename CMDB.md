# CMDB import (Microsoft Entra ID, Intune, Active Directory, Jamf Pro, Azure, AWS, and GCP)

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

Seven sources, seven independent settings sections:

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
* **Jamf Pro computer inventory** — also entirely independent: its own enable toggle, its own
  credentials (a Jamf Pro API client id/secret — Settings → System → API roles and clients in Jamf
  Pro — the API-client/OAuth2-client-credentials model Jamf now recommends over the older
  Basic-Auth-to-bearer-token exchange), its own schedule. `src/jamf.rs`, same `ureq`-based HTTPS
  client as the Graph sources, just a different token endpoint/scope and a different pagination
  shape (`page`/`page-size`/`totalCount` rather than Graph's `@odata.nextLink`). Covers computer
  inventory (`/api/v1/computers-inventory`) only, not mobile devices — the same "narrowest useful
  slice first" choice already made for Entra ID before Intune, and AD before this.
* **Azure virtual machines** (ROADMAP.md's "Cloud asset discovery", picked first of AWS/Azure/GCP)
  — a genuinely different integration shape from the four above: not Microsoft Graph or LDAP, but
  **Azure Resource Graph** (part of Azure Resource Manager), authorized by an **Azure RBAC role**
  ("Reader" is enough, assigned to the app registration at the subscription) rather than a Graph
  application permission — the app registration can be the very same one Entra ID/Intune already
  use, but the permission grant is unrelated and must be added separately, at the subscription, not
  in Graph's application-permissions blade. Scoped to one subscription id per sync, virtual
  machines only (not storage, databases or other resource types) — same "narrowest useful slice
  first" choice as every source above. `src/azure_cloud.rs`, same `ureq`-based HTTPS client as the
  Graph/Jamf sources.
* **AWS EC2 instances** (ROADMAP.md's "Cloud asset discovery", second of AWS/Azure/GCP) — a third
  distinct authorization model again: AWS has no OAuth2/bearer-token concept for its own APIs at
  all. Every request is signed with **AWS Signature Version 4** using a long-lived IAM access
  key id/secret access key pair — no token exchange, no expiry, no separate scope; the IAM policy
  attached to that access key (`ec2:DescribeInstances`, read-only, is enough) is what limits what
  it can see, the role Azure's RBAC role and Entra ID's application permission play for their own
  APIs. Scoped to one AWS region per sync, EC2 instances only (not RDS, S3 or other resource
  types) — same "narrowest useful slice first" choice as every source above. Matched by hostname
  using the instance's `Name` tag (EC2 has no dedicated hostname field of its own the way an Azure
  VM resource has a `name`), falling back to the instance id when no `Name` tag is set — that
  fallback device is still listed, it simply never matches anything by hostname.
  `src/aws_cloud.rs`, same `ureq`-based HTTPS client as the other sources, with a small hand-rolled
  SigV4 signer and XML-response reader (EC2's API is XML, not JSON, unlike every other source
  here) rather than pulling in the full AWS SDK for one read-only call.
* **GCP Compute Engine instances** (ROADMAP.md's "Cloud asset discovery", last of AWS/Azure/GCP) —
  a fourth authorization model, a genuine hybrid of the other two cloud sources: like Azure, the
  permission that matters is an IAM *role* (`roles/compute.viewer` is enough) granted at the
  project; like AWS, there is no interactive admin-consent step. But the credential is a **service
  account JSON key** (an RSA private key, not a client secret or an access key pair), and instead
  of a plain client-credentials exchange (Azure) or no exchange at all (AWS), GCP uses a **signed
  JWT bearer assertion** (RFC 7523) — a JWT whose claims are signed with the service account's own
  RSA private key (RS256), exchanged once for a short-lived OAuth2 access token, then used as a
  normal bearer token. Scoped to one GCP project per sync, Compute Engine VM instances only (not
  Cloud SQL, GKE or other resource types) — same "narrowest useful slice first" choice as every
  source above. Matched by hostname using the instance's own name (GCE instances have no separate
  hostname field the way an Azure VM resource has a `name` and EC2 relies on a `Name` tag — the
  instance name itself is the closest equivalent, and is genuinely the VM's own hostname inside its
  VPC in the overwhelming majority of real deployments). `src/gcp_cloud.rs`, same `ureq`-based
  HTTPS client as the other sources, with RSA-SHA256 JWT signing built on `ring`'s existing RSA
  support (already a dependency) rather than a JWT crate, and the same small nesting-free JSON
  parsing every source here already uses (`aggregatedList`'s response is JSON, unlike EC2's XML).

All seven write into the same imported-device list, each row tagged with which source it came
from (`entra`/`intune`/`ad`/`jamf`/`azure`/`aws`/`gcp`) and keyed `<source>:<id>` so the different
ID spaces — two different Graph GUID spaces, an LDAP distinguished name, a Jamf computer id, an
Azure resource id, an EC2 instance id, and a GCP project-scoped instance name — can never collide
even for what is the same physical device. Each source's own sync only prunes its own source's
rows: no source's sync can ever delete a device another source imported, even though each runs on
its own independent schedule.

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
  response did. `jamf::Settings` got the same manual `Default` impl from the start, this time
  learning from the other two rather than repeating the mistake.
* `src/jamf.rs` implements the OAuth2 client-credentials token fetch against Jamf Pro's own token
  endpoint, paginated `computers-inventory` list calls (`page`/`page-size`, stopping once
  `totalCount` is reached or a hard page cap is hit — the same "a misconfigured or unbounded
  instance can never turn a sync into an unbounded loop" reasoning as the Graph sources' own page
  cap), the same hostname-matching/upsert/prune logic, and its own periodic background job.
  Settings and the client secret round-trip and default to off; `sync_now` refuses cleanly when
  disabled or unconfigured (missing server URL/client id, missing secret); hostname matching is
  exact and case-insensitive; the pagination loop's stopping condition is proven not to loop
  forever against a `totalCount` a buggy server can never actually satisfy; a Jamf sync's own
  pruning is proven to leave the other three sources' rows untouched.

* `src/azure_cloud.rs` implements the OAuth2 client-credentials token fetch against Azure AD's
  token endpoint (the ARM scope, `https://management.azure.com/.default`, not Graph's), the
  Resource Graph query and its `$skipToken`-based pagination (capped at 50 pages, same reasoning as
  every other source's own page cap), the hostname-matching/upsert/prune logic, and its own
  periodic background job. Settings and the client secret round-trip and default to off; `sync_now`
  refuses cleanly when disabled or unconfigured (missing tenant/client id/subscription id, missing
  secret); hostname matching is exact and case-insensitive; the pagination loop's stopping
  condition is proven not to loop forever once a page returns no skip token or no rows; an Azure
  sync's own pruning is proven to leave the other four sources' rows untouched. The web layer's
  permissions and secret redaction are tested the same way as the other four sources.

* `src/aws_cloud.rs` implements AWS Signature Version 4 request signing from scratch (the
  canonical-request/string-to-sign/derived-signing-key chain AWS's own algorithm reference
  describes, using `ring`'s existing HMAC-SHA256 — already a dependency for TOTP in this codebase),
  a small nesting-aware XML tag extractor for `DescribeInstances`' response (no XML crate
  dependency was pulled in for one read-only, well-known-shape call), `NextToken`-based pagination
  (capped at 50 pages, same reasoning as every other source's own page cap), the
  hostname-matching/upsert/prune logic, and its own periodic background job. Settings and the
  secret access key round-trip and default to off; `sync_now` refuses cleanly when disabled or
  unconfigured (missing access key id/region, missing secret); the XML extractor is proven against
  a real `DescribeInstances`-shaped fixture including nested `reservationSet`/`instancesSet`/
  `tagSet` blocks that reuse the generic `item` tag at every nesting level (the case a naive,
  non-nesting-aware string scan would silently mis-split); an instance with no `Name` tag falls
  back to its instance id; `NextToken` is read when present; the SigV4 canonical-query-string
  encoder is proven against AWS's own reserved-character rules; an AWS sync's own pruning is proven
  to leave the other five sources' rows untouched. The web layer's permissions and secret
  redaction are tested the same way as the other five sources.

* `src/gcp_cloud.rs` implements the RFC 7523 JWT-bearer flow from scratch: PEM-to-DER decoding of
  the service account's private key (a small hand-rolled standard-base64 decoder, mirroring
  `report::base64`'s own encoder — this module cannot reuse that one directly, since it is
  `pub(crate)` to a different module's own concerns and only encodes), RSA-SHA256 signing of the
  JWT via `ring`'s existing `RsaKeyPair`/`RSA_PKCS1_SHA256` (already a dependency, used here for
  the first time in this codebase for RSA rather than ECDSA/Ed25519), the token exchange itself,
  `pageToken`-based pagination over `aggregatedList`'s per-zone response shape (capped at 50 pages,
  same reasoning as every other source's own page cap), the hostname-matching/upsert/prune logic,
  and its own periodic background job. Settings and the service account key round-trip and default
  to off; `sync_now` refuses cleanly when disabled or unconfigured (missing project id, missing
  key); a PEM key's wrapper is stripped and its body correctly decoded; `aggregatedList`'s
  per-zone `items` map is correctly flattened across zones, including zones that carry only a
  `warning` and no `instances` key at all (skipped rather than treated as an error); `nextPageToken`
  is read when present; a GCP sync's own pruning is proven to leave the other six sources' rows
  untouched. The web layer's permissions and secret redaction are tested the same way as the other
  six sources, plus an extra check the other cloud sources don't need: the service account field is
  a whole JSON document, not a single string, so an admin pasting something that is not valid JSON
  is refused with a clear error before it is ever saved.

## What is *not* yet verified

* **The actual exchange with a real Entra ID tenant, a real Intune enrollment, a real Active
  Directory domain controller, a real Jamf Pro instance, a real Azure subscription, a real AWS
  account, and a real GCP project have not been run.** Token fetch, Graph pagination against a
  tenant large enough to actually paginate, the real JSON shape Graph returns for `/devices` and
  `/deviceManagement/managedDevices`, the real LDAP bind/search/attribute shape a genuine domain
  controller returns, the real JSON shape (and exact field names) a genuine Jamf Pro instance's
  `computers-inventory` endpoint returns, the real Resource Graph response shape (and whether the
  RBAC-role-not-Graph-permission authorization model actually works the way Microsoft's docs
  describe) a genuine Azure subscription returns, the real `DescribeInstances` XML response shape
  (and whether the hand-rolled SigV4 signer is byte-for-byte correct against AWS's actual
  verification, not just against the algorithm reference) a genuine AWS account returns, and the
  real `aggregatedList` JSON response shape (and whether a real service account's RSA key, IAM role
  grant, and the JWT-bearer exchange all work the way Google's docs describe) a genuine GCP project
  returns, have not been exercised end to end against the genuine services — only against
  hand-written JSON/XML/attribute fixtures and one locally-generated, throwaway RSA key matching
  each provider's documented shape. Everything above this point is verified; this specific path is
  not, and should not be treated as working until it is.
* No mock Graph server, mock LDAP server or mock Jamf Pro server was built for this pass, for the
  same reason none was built for SSO: a correct one is itself real work, and doing it under time
  pressure risks a mock that "passes" without exercising the same code paths a real server would.
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
* Recommended before relying on Jamf Pro: a dedicated API client scoped to read-only computer
  inventory access (not an administrator's own credentials), and confirm a full sync against a
  real instance — including that a wrong server URL/client id, a revoked/expired secret, and an
  API client without the required privilege are each refused with a clear, distinguishable error.
  The exact JSON field names used (`general.name`, `general.lastEnrolledDate`,
  `general.lastContactTime`, `operatingSystem.name`/`version`) follow Jamf's published API
  reference but have not been confirmed against a real response body.
* Recommended before relying on Azure: an app registration with the Azure RBAC "Reader" role (not
  a Graph application permission) assigned at the subscription, and confirm a full sync against a
  real subscription — including that a wrong tenant/client id/subscription id, a revoked/expired
  secret, and an app registration without the role assignment are each refused with a clear,
  distinguishable error (the last of these in particular is a different failure shape than the
  other four sources' own permission errors, since it fails inside the Resource Graph call itself
  rather than at token issuance — the token still succeeds without the role, only the query does
  not). The exact KQL query and JSON field names (`osType`, `powerState`) follow Azure Resource
  Graph's published reference but have not been confirmed against a real response body.
* Recommended before relying on AWS: an IAM user or role with only `ec2:DescribeInstances`
  attached (not an administrator's own credentials), and confirm a full sync against a real
  account — including that a wrong/revoked access key, an access key without the required
  permission, and an empty or wrong region are each refused with a clear, distinguishable error.
  Signature errors from a genuinely incorrect SigV4 implementation and a merely-wrong credential
  both surface as an HTTP 401/403 from EC2 — this codebase has not yet confirmed which one a real
  mistake in the signer itself would actually produce, only that a deliberately wrong credential
  against the real endpoint produces the expected-shaped rejection.
* Recommended before relying on GCP: a service account with only `roles/compute.viewer` granted at
  the project (not an administrator's own credentials), and confirm a full sync against a real
  project — including that a wrong/revoked service account key, a service account without the
  required role, and an empty or wrong project id are each refused with a clear, distinguishable
  error. Verified so far: the JWT-bearer flow reaches Google's real token endpoint and is
  correctly rejected end to end using a locally-generated, throwaway RSA key that was never
  registered with any real GCP project (proving the PEM parsing, RS256 signing and HTTPS exchange
  all work) — but a real service account, a real IAM role grant, and a real
  `aggregatedList` response have not been exercised.

## Configuration

Settings → Integrations → CMDB import (admin only), seven independent sections:

* **Entra ID / Intune**: enable, tenant ID, client (application) ID, client secret, sync interval
  (1 hour to 30 days), and the "Also import Intune managed devices" checkbox.
* **Active Directory**: enable, server URL (`ldaps://dc.contoso.local:636`), bind DN, bind
  password, base DN, sync interval.
* **Jamf Pro**: enable, server URL (`https://yourinstance.jamfcloud.com`), client ID, client
  secret, sync interval.
* **Azure**: enable, tenant ID, client (application) ID, client secret, subscription ID, sync
  interval.
* **AWS**: enable, access key ID, secret access key, region, sync interval.
* **GCP**: enable, project ID, service account key (JSON), sync interval.

Each has its own "Sync now" to run one immediately instead of waiting for the schedule, and all
seven feed the one shared imported-device list below. Nothing here needs a restart.
