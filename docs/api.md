# API reference

The web UI is a client of this JSON API; everything it does you can script.

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
| `GET /api/export/assets.csv` · `/alerts.csv` · `GET /report` | viewer | CSV exports · printable report (`?days=7`) |
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
| `PUT /api/rules` · `DELETE /api/rules` | admin | change rule settings (`{"min_score":40,"weights":{"new_device":0},"params":{"silent_minutes":240},"min_scores":{"new_port":45},"exceptions":{"new_device":[{"kind":"type","value":"printer"}]},"ot_watches":[…]}`, `null` = back to default; `ot_watches` is the whole list) · reset all |
| `PUT /api/branding` · `PUT/DELETE /api/branding/logo` | admin | change branding (JSON) · upload/remove logo (raw PNG/JPEG/GIF/WebP, ≤256 KB) |

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
* `POST /api/v1/report` → `{agent, run_id, seq, sent_at, assets[], flows[], signals[], conversations[]}`.
  Batches are idempotent per `(run_id, seq)`; the token is bound to `agent.id`.
