# API reference

The web UI is a client of this JSON API; everything it does you can script.

## Stability

This is the same API the console's own UI uses — there is no separate, narrower surface reserved
for third-party integrations. In practice that means:

* Endpoint paths and their meaning (`GET /api/assets` lists devices, `POST /api/alerts/{id}/ack`
  acknowledges an alert, and so on) are stable — the UI depends on them too, so a breaking rename
  would break DENIS's own console, not just an integration.
* Response bodies are today's internal data shapes serialized directly (an asset's JSON is close to
  its stored form). Fields are additive over time — a new field can appear, an existing one keeps
  its name and meaning — but treat an unfamiliar field as ignorable rather than assuming the shape
  is closed. `Event.raw_details` in particular is intentionally free-form and varies by alert kind;
  do not depend on its exact keys beyond what the alert you're handling documents.
* There is currently one version of this API — no `/api/v1/` prefix, no version header. If a
  genuinely breaking change is ever needed, it will get one then, rather than speculatively now.

## Authentication

* **Sign in**: `POST /api/auth/login` with `{"username": "...", "password": "..."}`. The response sets a
  `denis_session` cookie (HttpOnly, SameSite=Strict, `Secure` behind TLS). Send the cookie on later requests.
* **CSRF protection**: every request that is not `GET` must carry the header `X-Denis: 1`.
* A user whose password was set by an administrator must change it first (`POST /api/auth/password`); until
  then every other endpoint answers `403 {"code": "must_change"}`.
* Errors are JSON: `{"error": "…", "code": "unauthenticated | forbidden | must_change"}` where relevant.
  `401` = not signed in, `403` = role too low, `429` = too many attempts (see `Retry-After`).

```bash
curl --cacert tls/ca.pem -c jar -H 'X-Denis: 1' -H 'Content-Type: application/json' \
     -d '{"username":"admin","password":"…"}' https://localhost:8080/api/auth/login
curl --cacert tls/ca.pem -b jar https://localhost:8080/api/assets
```

### API tokens (for scripts and integrations)

An administrator creates a token on the **Users** tab (or `POST /api/api-tokens` `{"label": "Grafana", "role":
"viewer"}`); the value (`dnt_…`) is shown once. Send it as a bearer token:

```bash
curl -H 'Authorization: Bearer dnt_…' https://denis.example.com/api/assets
```

* Role is **viewer** (read) or **editor** (also change assets, acknowledge alerts, start scans); a token can
  **never** be an administrator, so a leaked token cannot manage users, tokens or read the audit log.
* No `X-Denis` header and no cookie are needed; when an `Authorization` header is present *only* the token is
  considered. Tokens cannot use `/api/auth/*` (they have no password or session).
* Only a hash is stored. Revoke with `DELETE /api/api-tokens/{id}`: it stops working immediately. The audit
  log records changes made by a token as `token:<label>`.
* Prefer a token per integration so one can be revoked without breaking the others.
* **Rate limits**: a valid token is capped at 300 requests/minute (a sliding window; comfortably above any
  reasonable polling interval, meant to catch a runaway loop or a compromised token, not to slow down normal
  use) — `429 {"code": "rate_limited"}` past that. Repeated *wrong* tokens from one address are throttled
  after 10 failures in 60 seconds, independent of any one token's own limit, so a guessed/brute-forced token
  cannot be tried indefinitely.

## Endpoints

Role = the lowest role allowed.

| Method & path | Role | Description |
|---|---|---|
| `GET /api/health` | public | `{"ok": true}` liveness probe |
| `GET /api/branding` · `GET /branding/logo` | public | white-label name, accent, default theme, sign-in message, logo (see [Branding](branding.md)) |
| `POST /api/auth/login` | public | sign in |
| `POST /api/auth/logout` · `GET /api/auth/me` · `POST /api/auth/password` | any | session / own password (`{"current","new"}`) |
| `GET /api/auth/methods` · `POST /api/auth/passkey/login/begin` · `…/login/finish` | public | sign-in methods on offer · passkey sign-in (WebAuthn) |
| `POST /api/auth/passkey/register/begin` · `…/register/finish` · `GET /api/auth/passkeys` · `DELETE /api/auth/passkeys/{id}` | any user | manage your own passkeys |
| `GET /api/status` | viewer | mode, interface, counts, learning period, unacknowledged alerts |
| `GET /api/meta/options` | viewer | allowed values (statuses, icons, device types, …) |
| `GET /api/assets` | viewer | all devices with `risk`, `meta` (entered data), `display_name`, `detected` (raw guess), `warranty` |
| `GET /api/assets/{id}` | viewer | one device |
| `GET /api/assets/{id}/baseline` | viewer | learned baseline (`null` if none) |
| `GET /api/assets/{id}/history` | viewer | change history of the entered data |
| `GET /api/alerts` · `GET /api/events` | viewer | `?limit=&asset_id=&unacked=1` (`alerts` = real alerts only) |
| `GET /api/agents` · `GET /api/conversations` | viewer | remote sites · industrial communications matrix (with the `commands` each path used) |
| `GET /api/trends` | viewer | `?hours=24&agent=<id\|local>` samples for charts |
| `GET /api/export/assets.csv` · `/alerts.csv` · `GET /report` | viewer | CSV exports · live printable report, not saved (`?days=7`) |
| `GET /api/reports` | viewer | saved reports (without content), the schedule and the total size |
| `GET /api/reports/{id}` | viewer | the saved report as a page; add `?download=1` to get it as a file |
| `POST /api/reports` | editor | make and save a report now: `{"days": 7}` |
| `POST /api/auth/mfa` | public | second step of a sign-in: `{ticket, code}` (a 6-digit code or a recovery code); `POST /api/auth/login` answers `{mfa_required: true, ticket}` instead of a session when an authenticator app is on |
| `GET /api/auth/totp` · `POST /api/auth/totp/begin` `/confirm` `/disable` `/recovery` · `GET /api/auth/totp/qr.svg` | any signed-in user | your authenticator app: status · set up (password, then the first code) · turn off · new recovery codes · the QR code of the pending secret |
| `DELETE /api/users/{id}/totp` | admin | remove somebody's authenticator app |
| `GET/PUT /api/security` | admin | who must use a second step: `{"mfa_required": "off\|admins\|all"}` (plus how many people that would catch) |
| `GET /api/vulndata` · `PUT /api/vulndata` · `POST /api/vulndata/refresh` | viewer / admin / admin | the software data (date, counts, whether refreshed) · `{"refresh_eol": true}` weekly refresh of support dates · refresh them now |
| `GET /api/topology` | viewer | the physical map: switches, links between them, where each known device is plugged in (`attachments[]`) |
| `GET/PUT /api/switches` · `POST /api/switches/{id}/poll` | viewer / admin | the switches read over SNMP (never the community): list · replace the list `{interval_secs, targets:[{id, name, address, community?, enabled}]}` (a blank community keeps the stored one) · read one now |
| `GET/PUT /api/setup` | admin | the setup guide: `{completed, steps[]}` judged from what is configured · `{"completed": true\|false}` |
| `GET/PUT /api/reports/settings` | viewer / admin | the schedule: `{"schedule": "off\|weekly\|monthly", "keep": 12, "days": 7}` |
| `DELETE /api/reports/{id}` | admin | delete a saved report |
| `GET /api/system` | viewer | health of DENIS itself: database size, disk, capture drops, sweep lag, backups, `warnings[]` (`?rows=0` skips the row counts) |
| `GET/POST /api/backups` · `GET/DELETE /api/backups/{name}` · `PUT /api/backups/settings` | admin | backups of the database: list (with the schedule, the upload-to-MSP schedule and its own retention) · make one now · download / delete · `{"schedule": "off\|every8h\|every12h\|daily\|weekly", "keep": 7}` |
| `PUT /api/backups/upload-schedule` · `PUT /api/backups/agent-keep` | admin | how often the newest backup is also pushed to `--backup-upstream` (`{"schedule": "manual\|every8h\|every12h\|daily\|weekly"}`), independent of the schedule above · how many of each customer's uploaded backups this MSP keeps (`{"keep": 10}`) |
| `POST /api/alerts/{id}/ack` · `/unack` | editor | acknowledge / undo |
| `POST /api/scan` | editor | run a sweep + port scan now |
| `POST /api/assets` | editor | create a manual asset: `{"mac"?, "display_name", …}` |
| `PATCH /api/assets/{id}/meta` | editor | partial update of entered data (see below) |
| `POST /api/assets/import` | editor | body = CSV text; returns `{created, updated, unchanged, errors[]}` |
| `DELETE /api/assets/{id}` | admin | delete a *manual* asset |
| `DELETE /api/users/{id}/passkeys` | admin | remove all of a user's passkeys |
| `GET/POST /api/users` · `PATCH /api/users/{id}` · `POST /api/users/{id}/reset-password` | admin | user management (`temporary_password` returned once) |
| `GET/POST /api/agent-tokens` · `DELETE /api/agent-tokens/{agent_id}` | admin | agent tokens (`token` returned once) |
| `GET /api/audit` | admin | audit log (`?limit=`) |
| `GET/POST /api/channels` · `PUT/DELETE /api/channels/{id}` · `POST /api/channels/{id}/test` | admin | notification channels (secrets are write-only) |
| `GET /api/maintenance` · `PUT /api/maintenance` | viewer · admin | maintenance mode `{"minutes": 60, "note": "…"}` (`null` ends it) |
| `GET/POST /api/api-tokens` · `DELETE /api/api-tokens/{id}` | admin | API tokens for scripts (`token` returned once) |
| `GET /api/findings` · `GET /api/risk-acceptances` | viewer | open findings (accepted risks already taken out) · the accepted risks in force, with reason, who, when and end date |
| `POST /api/risk-acceptances` · `DELETE /api/risk-acceptances/{id}` | admin | accept a risk `{"finding_id":"telnet_open","asset_ids":[12],"reason":"…","days":90}` (`days` omitted = until withdrawn; only a risk that exists can be accepted) · withdraw it |
| `POST /api/findings/{id}/verify` | editor | look again, optionally `{"asset_ids":[…]}`; returns `{rescanned, fixed, still_present, results:[{asset_id, status, detail}]}` with `status` one of `fixed`, `still_present`, `unreachable`, `excluded`, `not_probed` |
| `PUT /api/rules` · `DELETE /api/rules` | admin | change rule settings (`{"min_score":40,"weights":{"new_device":0},"params":{"silent_minutes":240},"min_scores":{"new_port":45},"exceptions":{"new_device":[{"kind":"type","value":"printer"}]},"ot_watches":[…]}`, `null` = back to default; `ot_watches` is the whole list) · reset all |
| `PUT /api/branding` · `PUT/DELETE /api/branding/logo` | admin | change branding (JSON) · upload/remove logo (raw PNG/JPEG/GIF/WebP, ≤256 KB) |
| `GET /api/ip-enrichment` | viewer | public-ish status: `{dns_enabled, geoip:{name,health,detail,db_version,updated_at}, attribution}` |
| `GET/PUT /api/ip-enrichment/settings` | viewer / admin | reverse-DNS resolver/secondary/timeout/on-off, GeoIP source (`{"source":"DbIpLite","auto_update":true,"update_frequency":"Monthly"}` or `{"source":{"CustomMmdb":{"city_path","asn_path"}},"auto_update":false}` — `update_frequency` is `Daily`/`Weekly`/`Monthly`), cache TTLs in seconds, whether a custom API secret is set (never the secret itself); a `PUT` takes effect immediately, no restart |
| `POST /api/ip-enrichment/geoip/update` | admin | download and install DB-IP Lite's current release now (refused when the source is a custom file — nothing to fetch); `{"ok":true,"version":"2026-09"}` or `{"ok":false,"error":"…"}`; runs automatically on the configured schedule regardless (`auto_update`) |
| `GET /api/ip-enrichment/{ip}` | viewer | on-demand, fresh lookup for one address: `{ip, classification, hostname, country, country_code, region, city, latitude, longitude, asn, as_org, isp, connection_type, geoip_source, geoip_db_version, dns_source}` — every field but `ip`/`classification` may be absent; `country_code` is the ISO 3166-1 alpha-2 code (for a flag), `country` is the display name |
| `DELETE /api/agents/{agent_id}` | admin | delete a whole remote site and every device it reported (findings, baselines, presence, the communications matrix, events); `{"confirm": "<agent_id>"}` — the site id typed back — is required. Returns `{"deleted": true, "devices_removed": N}`. The agent's own token is untouched; revoke it separately (see `DELETE /api/agent-tokens/{agent_id}`) |
| `GET/PUT /api/cmdb/settings` · `POST /api/cmdb/sync` | viewer / admin / admin | CMDB import, Entra ID + Intune: `{enabled, tenant_id, client_id, sync_interval_hours, include_intune, client_secret_set}` (`PUT` also takes `client_secret`, write-only) · sync now, `{ok, imported}` or `{ok:false, error}` |
| `GET/PUT /api/ad/settings` · `POST /api/ad/sync` | viewer / admin / admin | CMDB import, on-premises Active Directory: `{enabled, url, bind_dn, base_dn, sync_interval_hours, bind_password_set}` (`PUT` also takes `bind_password`) · sync now |
| `GET/PUT /api/jamf/settings` · `POST /api/jamf/sync` | viewer / admin / admin | CMDB import, Jamf Pro: `{enabled, server_url, client_id, sync_interval_hours, client_secret_set}` (`PUT` also takes `client_secret`) · sync now |
| `GET/PUT /api/azure/settings` · `POST /api/azure/sync` | viewer / admin / admin | Cloud import, Azure VMs: `{enabled, tenant_id, client_id, subscription_id, sync_interval_hours, client_secret_set}` (`PUT` also takes `client_secret`) · sync now |
| `GET/PUT /api/aws/settings` · `POST /api/aws/sync` | viewer / admin / admin | Cloud import, EC2: `{enabled, access_key_id, region, sync_interval_hours, secret_access_key_set}` (`PUT` also takes `secret_access_key`) · sync now |
| `GET/PUT /api/gcp/settings` · `POST /api/gcp/sync` | viewer / admin / admin | Cloud import, Compute Engine: `{enabled, project_id, sync_interval_hours, service_account_json_set}` (`PUT` also takes `service_account_json`, the whole key file; refused if not valid JSON) · sync now |
| `GET /api/cmdb/devices` | viewer | every device imported by any of the seven sources above, `source` one of `entra`/`intune`/`ad`/`jamf`/`azure`/`aws`/`gcp`, each with `matched_asset_id` (by hostname) when one was found |
| `GET/PUT /api/vulnscan/settings` · `POST /api/vulnscan/sync` · `GET /api/vulnscan/findings` | viewer / admin / admin / viewer | Nessus / Tenable.io import: `{enabled, server_url, sync_interval_hours, access_key_set, secret_key_set}` (`PUT` also takes `access_key`, `secret_key`) · sync now, `{ok, imported}` · the imported findings, each with `plugin_name`, `severity`, `host`, `matched_asset_id` (by IP, then hostname) |
| `GET /api/software` | viewer | the fleet-wide Software page: `{software:[{product, version, asset_ids[], cves[], eol}]}` |
| `GET /api/compliance` | viewer | the Compliance page: register measures and the per-standard control mapping |
| `GET /api/top-talkers` · `PUT /api/top-talkers/excluded` | viewer · editor | the Top talkers leaderboard (`{talkers[], excluded[]}`) · devices to hide from it (`{"excluded":[ids]}`, kept server-side) |
| `POST /api/alerts/ack-all` · `POST /api/alerts/ack-bulk` | editor | acknowledge every unacknowledged alert · `{"ids":[…], "reason"?}`; `POST /api/alerts/{id}/ack?reason=resolved\|false_positive\|expected_behavior` records a reason on a single one |
| `POST /api/assets/review` · `POST /api/assets/bulk-tags` · `POST /api/assets/bulk-edit` | editor | mark `{"ids":[…]}` as reviewed · `{"ids":[…], "add"\|"remove": "tag"}` · `{"ids":[…], "field", "value"}` (owner, location, department, type_override, criticality, status) |
| `GET /api/assets/{id}/merged` · `PATCH /api/assets/{id}/meta {"merged_into": id\|null}` | viewer · editor | devices hidden behind this one ("This is the same device as…", same site only) · merge / unmerge |
| `GET /api/baseline/destinations?q=&limit=` · `DELETE /api/assets/{id}/baseline/destinations/{ip}` · `POST /api/baseline/forget-all` | viewer · admin · admin | every learned destination across devices, searchable · forget one · forget every baseline (`{"confirm":"FORGET LEARNED BASELINE"}`) |
| `POST /api/learning/start` `/pause` `/resume` `/end` | admin | network-wide learning mode: `{"days": 1–7}` to start; its current state comes back as `learning` in `GET /api/rules` |
| `GET /api/rules/export` | viewer | the rule settings as a downloadable JSON file in the shape `PUT /api/rules` accepts |
| `PUT /api/reports/{id}/share` · `DELETE /api/reports/{id}/share` · `GET /api/reports/shared/{token}` | admin · admin · public | turn on a no-sign-in link for one saved report (`{share_token}`) · turn it off · the shared report itself |
| `GET /api/retention` · `PUT /api/retention` | admin | `{"days": 1–1095}`: how long events, alerts and trend samples are kept |
| `GET /api/license` · `PUT /api/license` (body = the license text) · `DELETE /api/license` | viewer · admin · admin | Community-edition cap and the installed license (see [Licensing](licensing.md)) |
| `GET/PUT /api/sso` | viewer / admin | single sign-on (OIDC): `{enabled, issuer_url, client_id, button_label, secret_set}` (`PUT` also takes `client_secret`); `GET /api/auth/sso` (public) says whether a button is on offer; `/api/auth/sso/login` and `/callback` are the browser flow |
| `GET/PUT /api/siem` · `POST /api/siem/test` | viewer / admin · admin | SIEM / log export settings (`{enabled, transport, host, port, format, insecure_tls, index, streams:{events,findings,audit}}`, `api_key` write-only) · send one test message with the posted settings |
| `GET /api/ai` · `GET/PUT /api/ai/settings` · `GET /api/ai/usage` | viewer · viewer / admin · viewer | which AI features are on for this user's buttons · provider keys (write-only), local model URL/name, the global switch and per-feature toggles · call/token counters per provider |
| `POST /api/ai/explain` · `/triage` · `/recommend` · `/behavior` · `/ask` · `/suggest-rule` · `GET /api/ai/summary` | editor · viewer | on-click AI calls (`{kind, id, provider}` / `{id, provider}` / `{question}` / `{description, provider}`); each is refused server-side when its feature is off · the cached dashboard summary, never generated by the request |
| `GET/PUT /api/interfaces` · `POST /api/interfaces/deconfigure-ip` | viewer / admin · admin | the discovery/mirror interfaces and the agent listener for the next start (`{iface, mirror_ifaces[], ingest_listen}`) · remove an address from a mirror interface now |
| `GET /api/tls` · `POST /api/tls/certificate` `{certificate, key}` · `DELETE /api/tls/certificate` | viewer · admin · admin | the HTTPS certificate in use · install your own (PEM) · back to the generated one |
| `GET /api/update` · `POST /api/update/check` `/install` `/snooze` `/skip` · `DELETE /api/update/schedule` | viewer · admin | self-update state · check now, install now or `{"when": ts}`, remind later, skip this version · cancel a scheduled install |
| `POST /api/system/restart` · `POST /api/system/shutdown` | admin | `{"password"}` — the current password is required again |
| `GET/PUT /api/users/{id}/site-access` | admin | per-site `{"grants":[[site, "read"\|"none"]]}`; no grant = full access |
| `DELETE /api/agent-tokens/{agent_id}/purge` · `DELETE /api/api-tokens/{id}/purge` | admin | delete an already-revoked token's record |
| `PUT /api/msp-overview` · `GET /api/msp-backups` · `GET/DELETE /api/msp-backups/{agent_id}/{name}` | admin | the MSP view switch (`{"enabled"}`; whether it is on comes back as `msp_overview` in `GET /api/status`) · customers' uploaded backups (see [Deployment](deployment.md#msp-keeping-a-copy-of-a-customers-backups)) |
| `GET /api/demo` · `POST /api/demo` · `DELETE /api/demo` · `POST /api/data/erase` | viewer · admin | whether demo data is loaded · load · remove · erase everything (`{"confirm":"ERASE ALL DATA"}`) |

### Editing an asset

`PATCH /api/assets/{id}/meta` takes any subset of these fields; `null` or `""` clears one; unknown fields and
invalid values are rejected with `400` and **nothing is applied**.

```json
{
  "display_name": "Reception printer", "icon": "printer", "type_override": "printer",
  "status": "active", "criticality": "high", "owner": "Jana", "department": "Office",
  "location": "Floor 1", "zone": "Office", "purdue_level": "4",
  "asset_tag": "A-1042", "serial_number": "SN-0042", "model": "LaserJet", "manufacturer": "HP",
  "os_override": null, "supplier": "…", "purchase_date": "2024-05-01", "purchase_price": "€450",
  "warranty_expires": "2027-05-01", "notes": "…",
  "tags": ["floor-1", "leased"],
  "custom": {"Cost centre": "CC-7", "VLAN": null}
}
```

## Agent ingest API (port 8081)

Used by `denis agent`; documented for completeness. `Authorization: Bearer <agent token>`.

* `GET /api/v1/ping` → `200` if the token is valid.
* `POST /api/v1/report` → `{agent, run_id, seq, sent_at, assets[], flows[], signals[], conversations[]}`, plus
  `flows_v6[]` and `signals_v6[]` from an agent running with `--ipv6` (absent from older agents' reports).
  Batches are idempotent per `(run_id, seq)`; the token is bound to `agent.id`.
* `POST /api/v1/msp-sync` is the separate path a customer's own master uses with `denis run --report-to`
  (devices and already-scored alerts, see [Deployment](deployment.md#msp-live-devices-and-alerts-from-a-customers-own-master));
  the same token kind, a different payload. Backups pushed with `--backup-upstream` use their own upload endpoint
  on this port too.
