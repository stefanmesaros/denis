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
* A token lives with the administrator who created it: it stops working while that account is disabled or
  once it is deleted, and it never acts above that account's current role (a token made by an admin who is
  later made a viewer is a viewer). A token is not limited by per-site access: it sees every site of the
  console it was issued in (on a multi-tenant install, only that tenant's console).
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
| `GET /api/assets/{id}/context` | viewer | everything matched to the device: `findings[]` (finding instances with `first_seen`/`opened_at`/`resolved_at`, resolved ones for 30 days, each with `related_incidents[]`: the incidents on this device that are not resolved or were active in the past 30 days, `{id, status, priority, pattern, first_ts, last_ts, status_reason}`, newest first), `scanner[]` (with `cve_intel`), `directory[]` (CMDB/MDM/cloud rows), `incidents[]`, `conversations[]` (`role`, `peer_id`), `sightings[]` (which collectors saw it), `exposure` (why the device is a top exposure, same shape as one `GET /api/exposures` row; `null` when it has no anchor fact) |
| `GET /api/assets/{id}/context` | viewer | everything matched to the device: `findings[]` (finding instances with `first_seen`/`opened_at`/`resolved_at`, resolved ones for 30 days), `scanner[]` (with `cve_intel`), `directory[]` (CMDB/MDM/cloud rows), `incidents[]`, `conversations[]` (`role`, `peer_id`), `sightings[]` (which collectors saw it), `exposure` (why the device is a top exposure, same shape as one `GET /api/exposures` row; `null` when it has no anchor fact), `coverage[]` (the four control cells, see below; empty for a device outside the matrix) |
| `GET /api/coverage?control=&state=&site=&criticality=&limit=&offset=` | viewer | control coverage: `sources[]` (enabled, `newest_sync`, `fresh`, `rows`, `unmatched_rows`, `verified`), `summary` (per control, the count of devices in each of the nine states), `percent` (per control: covered ÷ (covered + failing + not managed), `null` when nothing is checkable), `rows[]` (`asset_id`, `name`, `ip`, `device_type`, `criticality`, `site`, `cells[]` of `{control, state, evidence}`; critical devices with something not managed first), `total`, `unrestricted`, `settings`. States: `covered`, `failing`, `not_managed`, `no_match`, `ambiguous`, `unknown`, `off`, `exempt`, `na`. Only devices the caller may see are rows or are counted; for a caller with a closed site `rows` and `unmatched_rows` in `sources[]` are `null`. `site=` is `""` for the local collector or an agent id; `control` alone keeps the devices it applies to |
| `GET /api/coverage/unmatched?source=` | viewer without site restrictions (403 otherwise) | rows in a source that match no device (`outcome: "unmatched"`) or fit several (`"ambiguous"`, with `hint.key` and `hint.devices`); never coverage gaps |
| `GET /api/assets/{id}/coverage` | viewer (404 for a device the caller may not see) | the device's four cells with evidence; `in_matrix: false` and no cells for this host, a merged duplicate or a retired, lost or stolen device |
| `GET /api/posture?site=&days=30\|90\|365` | viewer, site-scoped (`*` only without a closed site; 404 otherwise) | `{version, metrics[] (the registry: key, label, unit, better, since_version), site, sites[], days, today, samples[] ({day, version, metrics}), goals[]}`; each goal carries `value`, `as_of`, `met`, `change_7d`, `change_30d` and, with a due date, `pace` (`reaches` with `day` and `after_due`, `moving_away`, `not_moving`, `met`, `not_enough_history`) |
| `POST /api/posture/goals` · `PUT /api/posture/goals/{id}` · `DELETE /api/posture/goals/{id}?revision=N` | admin | create `{metric, site?, target, due_date?, note?}` (one goal per metric and site; 409 with the existing one) · change `{target, due_date?, note?, revision}` · delete; a stale `revision` is a 409 with the current `goal`. Display only: no notification |
| `POST /api/posture/sample` | admin | take today's posture sample now, replacing today's rows; `{day, sites, version}`. The daily sample is taken by a background job after 00:15 console-local time |
| `GET /api/defender/settings` · `PUT /api/defender/settings` · `POST /api/defender/sync` | viewer · admin · admin | Microsoft Defender for Endpoint import: `{enabled, base_url, reuse_entra, tenant_id, client_id, sync_interval_hours}` plus `client_secret` on write (never returned: `client_secret_set`); the sync answers `{ok, imported}` or `{ok: false, error}`. The machines are in `GET /api/cmdb/devices` with `source: "defender"` |
| `GET /api/coverage/settings` · `PUT /api/coverage/settings` | viewer · admin | `{ot_scanning, scan_max_age_days}`: whether industrial devices count toward scanning (default off), and how many days old a scan may be (1-365, default 30) |
| `GET /api/alerts` · `GET /api/events` | viewer | `?limit=&asset_id=&unacked=1` (`alerts` = real alerts only); also `since=`/`until=` (Unix seconds), `kind=a,b`, `peer_ip=`, `peer_asset_id=`, `port=`, `proto=`, and `involving=<asset id>` (about that device or with it as the other party) |
| `GET /api/incidents` · `GET /api/incidents/{id}` | viewer | related alerts grouped into one incident with a priority verdict, plus `status` (`open`, `acknowledged`, `resolved`), `status_by`, `status_at`, `status_reason` (the disposition of a resolved one), `status_note`, `open_members` and `closed_members`. The detail also has `resolve_closes`/`resolve_keeps` (what *Resolve* would do right now) and `related_findings[]`: the finding instances on the incident's devices that are open or were fixed since it began (each the instance fields plus `title`, `accepted`, `work_item` `{id, status, owner, due_date, origin_incident_id}` or `null`, and `after_incident`), only for devices the caller may read. `acked` stays `true` for acknowledged and resolved — see [Incidents](incidents.md) |
| `POST /api/incidents/{id}/ack` | editor, site writable | `{"note"?}`: open → acknowledged; the incident's still-open alerts are acknowledged with it (no reason). Returns `{status, alerts_closed, alerts_kept}`. A body with a `reason` (what older consoles sent) is a resolve |
| `POST /api/incidents/{id}/resolve` | editor, site writable | `{"reason": "resolved" \| "false_positive" \| "expected_behavior", "note"?}`: the reason is required and goes to the still-open alerts and to those closed through this incident; alerts a person closed on their own keep their decision (`alerts_kept`). `409` when it is already resolved |
| `POST /api/incidents/{id}/reopen` | editor, site writable | `{"note"?}`: back to open; member alerts are not touched. A new alert joining an acknowledged or resolved incident re-opens it by itself |
| `GET /api/incidents/{id}/log` · `GET /api/events/{id}/log` | viewer, site readable | `{"log": [...]}`, oldest first: `ts`, `actor` (a user name, or `system` for the correlator), `change`, `from_state`, `to_state`, `reason`, `note`, `via` (`incident:<id>`, `bulk`, `correlator`, or null for a person acting directly) and `detail`. The log outlives the alert or incident it is about (it has its own retention, below), so an alert's rows carry what is needed to read them alone in `detail.alert` (`kind`, `severity`, `score`, `ts`, `asset_id`, `mac`, `label`, `site`: the device's MAC and label as they were when the decision was made; `site` is the agent id, `null` for the local collector), and an incident's rows carry `detail.site`. `object_exists` says whether the alert or incident is still there. For one that is gone, the same site rule applies using the site the log recorded; a log that records no site (written by an older build) is readable by administrators only; a log with no rows is a 404 |
| `GET/PUT /api/incidents/settings` | viewer / admin | whether DENIS groups alerts into incidents at all: `{"enabled": true}` |
| `GET /api/assets/{id}/edges` | viewer | the device's stored relationship edges, either side, most recent first (`?limit=`, max 2000): `src_asset_id`, `dst_asset_id` or `dst_ip`, `proto`, `port`, `initiator` (`syn`/`ports`/`decoded`/`unknown`), `source` (`east_west`/`flow`/`ot`/`baseline`), `first_seen`, `last_seen`, `windows`, `bytes`, `packets`. Raw rows; the relationship queries below name both sides |
| `GET /api/assets/{id}/talks-to` · `GET /api/assets/{id}/talked-to-by` | viewer | relationships with the device as the source · as the device peer (exact reverses of each other), most recent first (`?since=&limit=`, max 1000): `{asset_id, relations: [{edge_id, src, dst, proto, port, evidence, direction, initiator, source, first_seen, last_seen, windows, bytes, packets}]}`. `src`/`dst` are `{asset_id, label, ip, names?}` (`asset_id`/`label` null for an outside address; `names` — see [Passive DNS](passive-dns.md) — is up to 3 names the *other* side has looked up for that address, most recent first, present only when there is at least one). `evidence`: `observed` (DENIS saw the traffic), `inferred` (seeded from a baseline, no port), `configured` (reserved for communication policies; not produced yet). `direction`: `confirmed` (SYN seen or protocol-decoded), `guessed` (from port numbers), `unknown` (local device ↔ outside address). A row naming a device on a site you cannot read is left out |
| `GET /api/relationships/contacted` | viewer | who has contacted an address, or which devices looked up a name: `?address=<IP or CIDR>` (a domain name is still a 400 here) or `?asset=<id>`, plus `since=`/`limit=` — `{resolved, devices, relations}`: the local devices currently at that address, the contacts folded per device (`device`, `services` like `tcp/445`, strongest `evidence`, `first_seen`, `last_seen`, `bytes`), and the rows. Or `?name=<domain>` (see [Passive DNS](passive-dns.md) for the forms it accepts) — `{hits: [{device, name, ip, first_seen, last_seen, answers, contacted}]}`, one entry per (device, name), `contacted` an object when the device actually reached one of the resolved addresses afterwards and `null` when it only looked the name up |
| `GET /api/assets/{id}/dns-names` | viewer | this device's own passive-DNS rows (see [Passive DNS](passive-dns.md)), most recently seen first: `?limit=` (default 200, max 1,024) — `{asset_id, names: [{id, ip, name, cname, resolver, first_seen, last_seen, answers, contacted}]}`, `contacted` a plain boolean here (an edge from this device to that address exists) |
| `GET/PUT /api/interfaces/passive-dns` | viewer / admin | opt-in passive DNS for this console's own capture: `{"enabled": false, "retention_days": 30}` (default off, retention 1–90 days; takes effect at once). `GET` adds `saved`, `flows_enabled`, `capture`, `rows` (names recorded so far); the per-device/per-window caps are on `GET /api/health` instead |
| `DELETE /api/dns-names` | admin | delete every recorded name on this console (not the switch above, which deletes nothing); audited `passive_dns.purge` with the row count |
| `GET /api/events/{id}/investigate` | viewer | the alert dialog's Investigate panel: `{device, peer, window_secs, timeline, between, also_contacted_by, incident}` — the device's events within `?window=` seconds (default 3600, max 86400), the edges between the device and the alert's peer, the other devices with an edge to that peer, and the incident the alert belongs to (`{id, pattern, priority, acked}`). 404 like the alert |
| `GET/PUT /api/interfaces/east-west` | viewer / admin | opt-in east-west accounting for this console's own capture: `{"enabled": false}` (default off; takes effect at once). `GET` adds `saved` and `flows_enabled` |
| `GET /api/agents` · `GET /api/conversations` | viewer | remote sites · industrial communications matrix (with the `commands` each path used) |
| `GET /api/agents/{id}/join-preview?target=` · `PUT /api/agents/{id}/join` · `GET /api/agents/joins` | admin | what joining an agent into a site (`target`: `""` = local) does, with a `fingerprint` and a `refusal` · join `{"target": "", "preview": "<fingerprint>"}` (409 with the fresh preview if anything changed; `{}` un-joins) · existing joins with drift (`recent`, `introduced`, `drift`) and same-network `suggestions` |
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
| `GET /api/topology/changes` · `GET /api/assets/{id}/locations` | viewer | the change log (`since`, `switch`, `mac`, `asset`, `kind`, `limit` filters; newest first) · every switch port a device has been seen on, with first/last seen and VLAN. A change naming a device on a site the caller cannot read loses the device (id and MAC) but stays in the log |
| `PUT /api/switches/{id}/watched-ports` · `PUT /api/switches/watched-vlans` | admin | `{"ports": [ifIndex…]}` / `{"vlans": [id…]}`: replace what is watched (at most 64 each; ports only after the switch has been read once; audited). `PUT /api/switches` always carries these over, so editing the switch list never wipes them |
| `GET/PUT /api/switches` · `POST /api/switches/{id}/poll` | viewer / admin | the switches read over SNMP (never either community: `has_community`, `has_write_community`, `write_same_as_read`, `port_control` instead): list · replace the list `{interval_secs, targets:[{id, name, address, community?, write_community?, clear_write_community?, enabled}], confirm_orphan_blocks?}` (a blank community or write community keeps the stored one; a 409 `nac_active_blocks` asks for `confirm_orphan_blocks` when ports DENIS disabled would lose their undo) · read one now |
| `GET /api/nac` · `PUT /api/nac/settings` | viewer / admin | port control: `{enabled, max_actions_per_hour, active[], recent[]}` (the reason of a block for administrators only) · `{enabled, max_actions_per_hour}` (off by default) |
| `POST /api/nac/plan` | admin (a signed-in person: never an API token, never `--insecure-no-auth`) | preview a block from a fresh poll: `{"subject": {"port": {"switch", "ifindex"}}}` or `{"subject": {"device": asset_id}}` → `{plan_id?, expires_at, switch, port, affected[], unknown_macs, warnings[], refusals[], persistence}`; a plan with refusals has no id |
| `POST /api/nac/apply` | admin, with the password again | `{plan_id, password, reason, acknowledged_warnings}` → `{outcome: disabled\|unconfirmed\|refused\|denied, message, ledger_id}` |
| `POST /api/nac/actions/{id}/restore` · `POST /api/nac/actions/{id}/check` | admin | enable a port DENIS disabled (no password; works with port control off) · read it back now |
| `GET/PUT /api/setup` | admin | the setup guide: `{completed, steps[]}` judged from what is configured · `{"completed": true\|false}` |
| `GET/PUT /api/reports/settings` | viewer / admin | the schedule: `{"schedule": "off\|weekly\|monthly", "keep": 12, "days": 7}` |
| `DELETE /api/reports/{id}` | admin | delete a saved report |
| `GET /api/system` | viewer | health of DENIS itself: database size, disk, capture drops, sweep lag, backups, `east_west` (the switch, every cap between a packet and an edge and what each one cut), `warnings[]` (`?rows=0` skips the row counts) |
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
| `GET /api/exposures` | viewer | "Top exposures today", ranked: `{exposures: [{asset_id, score, impact, factors: [{points, anchor, kind, reason, what?, more?, source, incident_id?, text}]}]}`. `score` is the sum of the factors' points, an ordering key, not a 0-100 score; `impact` is `physical`/`critical`/`elevated`/`normal`/`low`; `kind` is `kev`/`incident`/`scanner`/`eol`/`high_finding`/`impact`/`no_owner`; `text` is the whole line in English (`+40 …`). Only devices with at least one anchor fact, on sites you can read. The table is in [Concepts](concepts.md#top-exposures-today) |
| `GET /api/findings` · `GET /api/risk-acceptances` | viewer | open findings (accepted risks already taken out; each with `related_incidents[]` as above plus `asset_ids`, which of the finding's devices the incident involves) · the accepted risks in force, with reason, who, when and end date |
| `GET /api/work-items` · `POST /api/work-items` | viewer · editor, site writable | remediation work items on devices you can read · `{"subject_kind":"finding"\|"exposure","subject_id","owner"?,"due_date"?,"notes"?,"origin_incident_id"?}`; `origin_incident_id` records the incident it was tracked from (stored once, never changed, audited) and is refused with `400` unless it is an incident you can read that involves the device |
| `POST /api/risk-acceptances` · `DELETE /api/risk-acceptances/{id}` | admin | accept a risk `{"finding_id":"telnet_open","asset_ids":[12],"reason":"…","days":90}` (`days` omitted = until withdrawn; only a risk that exists can be accepted) · withdraw it |
| `POST /api/findings/{id}/verify` | editor | look again, optionally `{"asset_ids":[…]}`; returns `{rescanned, fixed, still_present, results:[{asset_id, status, detail}]}` with `status` one of `fixed`, `still_present`, `unreachable`, `excluded`, `not_probed` |
| `PUT /api/rules` · `DELETE /api/rules` | admin | change rule settings (`{"min_score":40,"weights":{"new_device":0},"params":{"silent_minutes":240},"min_scores":{"new_port":45},"exceptions":{"new_device":[{"kind":"type","value":"printer"}]},"ot_watches":[…]}`, `null` = back to default; `ot_watches` is the whole list; a watch's `targets`/`allowed_senders`/`sources`/`except_sources` take `device`, `type`, `tag`, `cidr`, `meta_zone`, `purdue` or `site`, whereas an exception takes the first four only; a watch subject may also be `{"kind":"zone","value":"z:<id>"}`, a zone that must exist when added, and `GET`/`PUT` answer with `zone_status`: per watch that names a zone, its zones and whether the watch is `suspended` because one is gone) · reset all |
| `PUT /api/branding` · `PUT/DELETE /api/branding/logo` | admin | change branding (JSON) · upload/remove logo (raw PNG/JPEG/GIF/WebP, ≤256 KB) |
| `GET /api/ip-enrichment` | viewer | public-ish status: `{dns_enabled, geoip:{name,health,detail,db_version,updated_at}, attribution}` |
| `GET/PUT /api/ip-enrichment/settings` | viewer / admin | reverse-DNS resolver/secondary/timeout/on-off, GeoIP source (`{"source":"DbIpLite","auto_update":true,"update_frequency":"Monthly"}` or `{"source":{"CustomMmdb":{"city_path","asn_path"}},"auto_update":false}` — `update_frequency` is `Daily`/`Weekly`/`Monthly`), cache TTLs in seconds, whether a custom API secret is set (never the secret itself); a `PUT` takes effect immediately, no restart |
| `POST /api/ip-enrichment/geoip/update` | admin | download and install DB-IP Lite's current release now (refused when the source is a custom file — nothing to fetch); `{"ok":true,"version":"2026-09"}` or `{"ok":false,"error":"…"}`; runs automatically on the configured schedule regardless (`auto_update`) |
| `GET /api/ip-enrichment/{ip}` | viewer | on-demand, fresh lookup for one address: `{ip, classification, hostname, country, country_code, region, city, latitude, longitude, asn, as_org, isp, connection_type, geoip_source, geoip_db_version, dns_source}` — every field but `ip`/`classification` may be absent; `country_code` is the ISO 3166-1 alpha-2 code (for a flag), `country` is the display name |
| `DELETE /api/agents/{agent_id}` | admin | delete a whole remote site and every device it reported (findings, baselines, presence, the communications matrix, events); `{"confirm": "<agent_id>"}` — the site id typed back — is required. Returns `{"deleted": true, "devices_removed": N}`. The agent's own token is untouched; revoke it separately (see `DELETE /api/agent-tokens/{agent_id}`) |
| `GET/PUT /api/cmdb/settings` · `POST /api/cmdb/sync` | viewer / admin / admin | CMDB import, Entra ID + Intune (see `CMDB.md` in the repository): `{enabled, tenant_id, client_id, sync_interval_hours, include_intune, client_secret_set}` (`PUT` also takes `client_secret`, write-only) · sync now, `{ok, imported}` or `{ok:false, error}` |
| `GET/PUT /api/ad/settings` · `POST /api/ad/sync` | viewer / admin / admin | CMDB import, on-premises Active Directory: `{enabled, url, bind_dn, base_dn, sync_interval_hours, bind_password_set}` (`PUT` also takes `bind_password`) · sync now |
| `GET/PUT /api/jamf/settings` · `POST /api/jamf/sync` | viewer / admin / admin | CMDB import, Jamf Pro: `{enabled, server_url, client_id, sync_interval_hours, client_secret_set}` (`PUT` also takes `client_secret`) · sync now |
| `GET/PUT /api/azure/settings` · `POST /api/azure/sync` | viewer / admin / admin | Cloud import, Azure VMs: `{enabled, tenant_id, client_id, subscription_id, sync_interval_hours, client_secret_set}` (`PUT` also takes `client_secret`) · sync now |
| `GET/PUT /api/aws/settings` · `POST /api/aws/sync` | viewer / admin / admin | Cloud import, EC2: `{enabled, access_key_id, region, sync_interval_hours, secret_access_key_set}` (`PUT` also takes `secret_access_key`) · sync now |
| `GET/PUT /api/gcp/settings` · `POST /api/gcp/sync` | viewer / admin / admin | Cloud import, Compute Engine: `{enabled, project_id, sync_interval_hours, service_account_json_set}` (`PUT` also takes `service_account_json`, the whole key file; refused if not valid JSON) · sync now |
| `GET /api/cmdb/devices` | viewer | every device imported by any of the seven sources above, `source` one of `entra`/`intune`/`ad`/`jamf`/`azure`/`aws`/`gcp`, each with `matched_asset_id` (by hostname) when one was found |
| `GET/PUT /api/svcprobe/settings` | viewer / admin | the opt-in service probe (TLS certificates and web page titles on already-open ports): `{enabled, interval_hours}` (24 or 168; anything else becomes 24), plus `available` (this console scans at all), `last_run`, `hosts`, `ports`, `answered`, `tls_ports`, `http_ports` |
| `GET/PUT /api/vulnscan/settings` · `POST /api/vulnscan/sync` · `GET /api/vulnscan/findings` | viewer / admin / admin / viewer | Nessus / Tenable.io import: `{enabled, server_url, sync_interval_hours, access_key_set, secret_key_set}` (`PUT` also takes `access_key`, `secret_key`) · sync now, `{ok, imported}` · the imported findings, each with `plugin_name`, `severity`, `host`, `matched_asset_id` (by IP, then hostname) |
| `GET /api/software` | viewer | the fleet-wide Software page: `{software:[{product, version, asset_ids[], cves[], eol}]}` |
| `GET /api/compliance` | viewer | the Compliance page: register measures and the per-standard control mapping |
| `GET /api/top-talkers` · `PUT /api/top-talkers/excluded` | viewer · editor | the Top talkers leaderboard (`{talkers[], excluded[]}`) · devices to hide from it (`{"excluded":[ids]}`, kept server-side) |
| `POST /api/alerts/ack-all` · `POST /api/alerts/ack-bulk` | editor | acknowledge every unacknowledged alert · `{"ids":[…], "reason"?, "overwrite"?}` (ack-bulk leaves an alert that already has a decision alone and counts it in `skipped`; `"overwrite": true` is the explicit choice to change those too: it needs a `reason` (400 without), the same site-write rules apply, each alert whose reason actually changes gets its own log row naming the reason it replaces, and the `alerts.ack_bulk` audit row carries `"overwrite": true`; an alert that already carries exactly that reason is left alone); `POST /api/alerts/{id}/ack?reason=resolved\|false_positive\|expected_behavior` records a reason on a single one |
| `POST /api/assets/review` · `POST /api/assets/bulk-tags` · `POST /api/assets/bulk-edit` | editor | mark `{"ids":[…]}` as reviewed · `{"ids":[…], "add"\|"remove": "tag"}` · `{"ids":[…], "field", "value"}` (owner, location, department, type_override, criticality, status) |
| `GET /api/assets/{id}/merged` · `PATCH /api/assets/{id}/meta {"merged_into": id\|null}` | viewer · editor | devices hidden behind this one ("This is the same device as…", same site only) · merge / unmerge |
| `GET /api/baseline/destinations?q=&limit=` · `DELETE /api/assets/{id}/baseline/destinations/{ip}` · `POST /api/baseline/forget-all` | viewer · admin · admin | every learned destination across devices, searchable · forget one · forget every baseline (`{"confirm":"FORGET LEARNED BASELINE"}`) |
| `POST /api/learning/start` `/pause` `/resume` `/end` | admin | network-wide learning mode: `{"days": 1–7}` to start; its current state comes back as `learning` in `GET /api/rules` |
| `GET /api/rules/export` | viewer | the rule settings as a downloadable JSON file in the shape `PUT /api/rules` accepts |
| `POST /api/rules/preview` | admin | read-only "who does this watch cover now": `{"kind":"it_watch","sources":[…],"except_sources":[…]}` or `{"kind":"ot_watch","targets":[…],"allowed_senders":[…]}` (the subject lists as being edited; other fields are ignored). Answers with the zones named (found or missing, revision, devices held now), `suspended`, and per list `total`, `by_zone`, `by_other`, `by_zone_only`, `observed_only`, `excluded`, the first 30 `devices` (with `via` and site) and `truncated` |
| `POST /api/rules/draft` | admin | apply one Ask DENIS draft exactly as reviewed (`{"draft": …}`, the `draft` an Ask DENIS answer returned: an exception or a rule-settings change); validated like `PUT /api/rules`, all or nothing, `409` when a setting it was drafted against has changed since; the alerts an applied exception covers are acknowledged |
| `PUT /api/reports/{id}/share` · `DELETE /api/reports/{id}/share` · `GET /api/reports/shared/{token}` | admin · admin · public | make a no-sign-in link for one saved report (`{share_token, shared_until}`; the token is returned only here, it works for 30 days, and a second call makes a new link and ends the old one) · turn it off · the shared report itself |
| `GET /api/retention` · `PUT /api/retention` | admin | `{"days": 1–1095, "decision_log_days"?: 0 or 90–3650}`: how long events, alerts and trend samples are kept, and (separately) how long the decision log is kept; `0` keeps it for ever, default 1095 (3 years), and a `PUT` that leaves it out keeps the saved value. `GET` also returns `decision_log_default_days`. Audited as `retention.settings` with the old and new period |
| `GET /api/license` · `PUT /api/license` (body = the license text) · `DELETE /api/license` | viewer · admin · admin | Community-edition cap and the installed license (see [Licensing](licensing.md)) |
| `GET/PUT /api/sso` | viewer / admin | single sign-on (OIDC): `{enabled, issuer_url, client_id, button_label, secret_set}` (`PUT` also takes `client_secret`); `GET /api/auth/sso` (public) says whether a button is on offer; `/api/auth/sso/login` and `/callback` are the browser flow |
| `GET/PUT /api/siem` · `POST /api/siem/test` | viewer / admin · admin | SIEM / log export settings (`{enabled, transport, host, port, format, insecure_tls, index, streams:{events,findings,audit}}`, `api_key` write-only) · send one test message with the posted settings |
| `GET /api/ai` · `GET/PUT /api/ai/settings` · `GET /api/ai/usage` | viewer · viewer / admin · viewer | which AI features are on for this user's buttons · provider keys (write-only), local model URL/name, the global switch and per-feature toggles · call/token counters per provider |
| `POST /api/ai/explain` · `/triage` · `/recommend` · `/behavior` · `/ask` · `/incident` · `/suggest-rule` · `GET /api/ai/summary` | editor · viewer | on-click AI calls (`{kind, id, provider}` / `{id, provider}` / `{question, context_alert_ids}` — the previous answer's `alert_ids`, for a follow-up like "add an exception for that" / `{id, provider}` for one incident / `{description, provider}`); each is refused server-side when its feature is off · the cached dashboard summary, never generated by the request |
| `GET /api/threat` · `PUT /api/threat` · `POST /api/threat/{source}/refresh` | viewer / admin / admin | the auto-fetched blocklists that `threat_list_match` checks against, merged with your own `--threat-list` file: on/off (`refresh_<source>`) and refresh interval (`<source>_interval_hours`) per source · fetch one (`abusech`, `threatfox`, `urlhaus`, `spamhaus`, `asndrop` or `tor`) now |
| `GET/PUT /api/interfaces` · `POST /api/interfaces/deconfigure-ip` | viewer / admin · admin | the discovery/mirror interfaces and the agent listener for the next start (`{iface, mirror_ifaces[], ingest_listen}`) · remove an address from a mirror interface now |
| `GET /api/tls` · `POST /api/tls/certificate` `{certificate, key}` · `DELETE /api/tls/certificate` | viewer · admin · admin | the HTTPS certificate in use · install your own (PEM) · back to the generated one |
| `GET /api/update` · `POST /api/update/check` `/install` `/snooze` `/skip` · `DELETE /api/update/schedule` | viewer · admin | self-update state · check now, install now or `{"when": ts}`, remind later, skip this version · cancel a scheduled install |
| `POST /api/system/restart` · `POST /api/system/shutdown` | admin | `{"password"}` — the current password is required again |
| `GET/PUT /api/users/{id}/site-access` | admin | per-site `{"grants":[[site, "read"\|"none"]]}`; no grant = full access |
| `DELETE /api/agent-tokens/{agent_id}/purge` · `DELETE /api/api-tokens/{id}/purge` | admin | delete an already-revoked token's record |
| `PUT /api/msp-overview` · `GET /api/msp-backups` · `GET/DELETE /api/msp-backups/{agent_id}/{name}` | admin | the MSP view switch (`{"enabled"}`; whether it is on comes back as `msp_overview` in `GET /api/status`) · customers' uploaded backups (see [Deployment](deployment.md#msp-keeping-a-copy-of-a-customers-backups)) |
| `GET /api/demo` · `POST /api/demo` · `DELETE /api/demo` · `POST /api/data/erase` | viewer · admin | whether demo data is loaded · load · remove · erase everything (`{"confirm":"ERASE ALL DATA"}`) |
| `GET /api/zones` · `POST /api/zones` · `PUT /api/zones/{id}` · `DELETE /api/zones/{id}?revision=N` | viewer · admin | zones, each with member and reference counts · create · update (`revision` required, `409` with the current row when stale) · delete (refused with `409` while any policy or any watch still references it; each zone also lists the `watches` that follow it, and an update, delete or restore answers with `watches_following`: per followed zone, devices `joined` and `left`) — see [Zones and policies](segmentation.md) |
| `POST /api/zones/{id}/restore {"revision":N}` · `GET /api/zones/{id}/history` | admin · viewer | write a past revision back as a new one (also undoes a delete) · revisions, newest first (`404` when none exist) |
| `GET /api/policies?kind=` · `POST /api/policies` · `PUT /api/policies/{id}` · `DELETE /api/policies/{id}?revision=N` | viewer · admin | `zone_rule`/`allow_list` policies, filterable by kind (`it_watch`/`ot_watch` rows are listed here too, read-only, with the same `body` as in `GET /api/rules`; they are created, changed and deleted through `PUT /api/rules`, and `POST`/`PUT`/`DELETE` here refuse them) · create · update · delete, same `revision`/`409` rule as zones |
| `POST /api/policies/{id}/restore {"revision":N}` · `GET /api/policies/{id}/history` | admin · viewer | same as the zone endpoints above, for a policy Watches (`it_watch`, `ot_watch`) are refused with `400`, live or deleted: they are written through `PUT /api/rules` only, which validates them |
| `GET /api/segmentation/matrix?window=1d\|7d\|30d` | viewer | the zone matrix: zone headers, per-site coverage (whether east-west accounting is on/seen/off/unknown there), and every zone pair's state for the window, from the background job's last snapshot (an empty shape before it has ever run) — see [Zones and policies](segmentation.md) |
| `GET /api/segmentation/matrix/cell?src=&dst=&window=` | viewer | the drawer behind one cell: its computed state plus the sample rows (device pairs/services) behind it, newest first |
| `POST /api/policies/freeze {"subject":{"device":id}\|{"type":"...","site":"..."},"days":N}` | admin | writes nothing — a reviewable `allow_list` draft built from that subject's own observed `edges` over `days` (1-30, default 14); becomes a real policy only through the ordinary `POST /api/policies` above |

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
