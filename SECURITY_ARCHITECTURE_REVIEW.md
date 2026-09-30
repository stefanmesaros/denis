# Security, code and architecture review (baseline, 2026-09-30)

A baseline review of what is on `main` today (v2.51.0, commit `c4bc925`), written before the
multi-tenancy, PostgreSQL, HA and NAC work in [MULTI_TENANCY_HA.md](MULTI_TENANCY_HA.md) and
[NAC.md](NAC.md) starts. It reviews shipped code only. It does not design any of that future work.

The same honesty bar as the other root-level documents applies. Every finding says how sure it
is:

* **Verified by reading**: I followed the code path end to end and the failure follows from what
  the code says. I did not run it.
* **Traced, not reproduced**: I followed the path across several modules and I am confident, but a
  test that shows it failing would be the real proof.
* **Suspected**: plausible from the code I read, but I did not trace every step.

Nothing in this document was confirmed by running an exploit or a failing test against a live
install. Known gaps that ROADMAP.md, CMDB.md, WINDOWS.md, IPV6.md, NAC.md, MULTI_AGENT_DEDUP.md
and MULTI_TENANCY_HA.md already name are not repeated here.

## How this review was done

* `cargo build`: clean.
* `cargo clippy --all-targets -- -D warnings`: clean.
* `cargo audit`: **not clean when run locally.** It reports RUSTSEC-2023-0071 (`rsa` 0.9.10, the
  "Marvin" timing side channel), pulled in only through `openidconnect`. CI passes because
  `.github/workflows/ci.yml` ignores that advisory, with a written justification. I checked the
  justification and it holds: `openidconnect` uses `rsa` only to verify ID-token signatures with a
  public key, and the one place DENIS signs with an RSA private key (`gcp_cloud.rs::fetch_token`)
  uses `ring`, not `rsa`. So the claim "clean in CI" is true, but a developer who runs
  `cargo audit` locally gets a failure. See L1.
* The test suite was not used as a review method.
* I read the security-critical modules in full or close to it: `web/mod.rs` (routing, `authn`,
  `guard`, `required_role`, the read handlers), `web/common.rs`, `web_admin.rs` (sessions, users,
  site access, interfaces, agents, finding verification), `auth.rs`, `access.rs`, `passkey.rs`,
  `web_passkey.rs`, `web_totp.rs`, `sso.rs`, `web_sso.rs`, `update.rs` (install path),
  `license.rs`, `certs.rs`, `ingest.rs`, and the SQL in `store/sqlite.rs`. I read `engine.rs`
  (task wiring, locks), large parts of `detect.rs` (asset resolution, flow ingestion, bounds,
  flush), `parse.rs` (the frame parser), `agent.rs` (batching) and `reverify.rs`. For the
  credential modules (`cmdb.rs`, `ad.rs`, `jamf.rs`, `azure_cloud.rs`, `aws_cloud.rs`,
  `gcp_cloud.rs`, `vulnscan.rs`, `channels.rs`, `switches.rs`, `sink.rs`, `syslog.rs`) I read
  every place a secret is loaded, saved, sent or logged. The rest got a lighter pass.

## Executive summary

At the level of individual primitives, the codebase is in good shape, better than most projects
its size. Every SQL statement is parameterised: I checked all of `store/sqlite.rs`, and the only
`format!`-built SQL splices compile-time constants (column lists, fixed table names, fixed pragma
names). Other strengths:

* Passwords use Argon2id with timing-equalised unknown-user handling.
* Session, API and agent tokens are stored as SHA-256 hashes.
* WebAuthn verification is careful: rpIdHash, UP and UV flags, origin, crossOrigin, and a counter
  check.
* TOTP rejects replay.
* Updates are Ed25519-signed, with a smoke test and rollback.
* The packet parser is defensively bounds-checked and fuzz-tested.
* The UI never uses `innerHTML`.
* Server-side HTML and CSV output is escaped and protected against formula injection.
* CSRF (a custom header plus `SameSite=Strict`) and DNS-rebinding protection are both in place.
* The "never round-trip a secret to the browser" convention is followed in every GET handler I
  checked.

The serious problems are not in those primitives. They are structural, and three themes account
for most of them:

1. **Per-site authorization is opt-in per handler, and several handlers never opted in** (H1). A
   user an admin restricted to "no access" on a site can still read that site's devices and alerts
   through the CSV exports, the printable report, stored reports, findings, and the AI
   explain/triage/recommend/behaviour endpoints, which take an arbitrary alert id. Multi-tenancy
   will be built on this same mechanism, so this is the most important finding to act on first.
2. **Single sign-on has three independent weaknesses** (H2). Turning SSO off in Settings does not
   actually turn it off. No allowed domain and no `email_verified` claim are checked. And accounts
   are linked by email address, which lets an identity provider that allows unverified emails take
   over an existing local account, skipping its TOTP and passkey-only policy.
3. **The engine's in-memory state and background tasks fail silently.** A panic in any detector
   task kills that task and poisons the shared detector lock. That then kills every other detection
   task, while the web console keeps reporting healthy (H3). Separately, deleting a site whose
   agent keeps reporting leaves stale ids in the detector's cache. From then on every baseline
   flush fails on a foreign-key violation, which silently stops presence and
   communications-matrix persistence **for the whole install** (H4).

H5 matters especially for NAC. "Verify fix" and the scheduled re-verification actively port-scan
a *remote site's* device IP from the *master's own* network. The wrong host gets scanned, and the
"never probe industrial devices" check is applied to the wrong device.

**Overall verdict**: the security primitives are sound. Before multi-tenancy, three structural
problems need fixing first:

* Authorization scoping lives in handlers instead of in the data-access layer.
* Detector and inventory caches duplicate database state and depend on manual invalidation.
* Background tasks have no supervision.

These are the same seams tenant isolation and HA will lean on hardest. Details are under "Overall
architecture health" at the end.

---

## Critical

None found. I did not find an unauthenticated remote code execution, an unauthenticated
authentication bypass, or SQL injection. The closest is H2 in a specific configuration: SSO set
up against a public identity provider and then "disabled".

## High

### H1. Site-access restrictions are bypassed by several read endpoints

**Where** (all verified by reading):

* `web/mod.rs:1073` `export_assets`, `:1077` `export_alerts` and `:1082` `report_page`. All three
  call `gather()` (`:1049`), which calls `report::gather(store, days, now)` with no user, then
  applies only the license cap.
* `web/mod.rs:546` `findings`: every device's findings, with device ids and names. It has no
  `AuthUser` at all.
* `web/mod.rs:1018` `top_talkers_get`: every device's traffic totals.
* `web_reports.rs:74` `view`: stored reports are generated across all sites (`reports.rs` uses
  the same global `report::gather`), and any viewer can open any report id.
* `web_ai.rs:187` `explain` (`kind: "alert"`), `:265` `triage`, `:323` `recommend` and `:643`
  `behavior`. Each calls `store.get_event(id)` for a caller-chosen id and never calls
  `site_readable`. The response is an AI-written description of that alert, its device label,
  and for `behavior` its baseline. A "no such alert" 404 versus a real answer also tells the
  caller which ids exist.
* Smaller leaks: `web/mod.rs:386` `status` (`alerts_unacked` counts every site), `:520`
  `compliance`, `:423` `/metrics` (lists every site id), and `web_ai.rs:381` `summary` (the
  fleet-wide AI summary).

**Concern.** `access.rs` and the `web_admin.rs` module doc say plainly that site scoping is each
handler's job ("A handler that takes `Path(id)` and skips this check is a bug"). The handlers
above never received that check. Handlers that take an id *in the JSON body* (the AI ones) are
exactly the kind the doc's rule of thumb misses.

**Failure scenario.** An admin gives contractor account `c1` (role viewer) the grant
`none` on site `branch-b`. `c1` opens `GET /api/export/assets.csv?days=365` and receives every
`branch-b` device: MAC, IP, hostname, vendor, open ports and risk factors. Next, `c1` loops over
`POST /api/ai/explain {"kind":"alert","id":"1".."N"}` and gets a readable description of every
`branch-b` alert. If AI is off, `alerts.csv` gives the same data.

**Direction.** Two layers, both needed before multi-tenancy:

1. Short term: add `me` to `gather()` and filter `devices`/`alerts` with `site_readable`. Add the
   check to the four AI handlers and to report viewing (either scope stored reports to a site or
   make them admin-only). Add a test that walks the route table: for every GET route, a user with
   `none` on a site must not see that site's MAC in the body.
2. Structural: move scoping into the query layer. For example, a `Scope` value passed into
   `list_events`/`load_assets`/`report::gather`, so a handler *cannot* load data without deciding
   whose it is. This is also the shape `tenant_id` will need. Also note: filtering after `LIMIT`
   (`events`/`alerts` at `web/mod.rs:614` and `:627`) returns short or empty pages to restricted
   users. Filtering in SQL fixes that too.

### H2. Single sign-on: "disabled" still works, any account at the IdP is accepted, and email linking can take over local accounts

**Status (2026-09-30): fixed.** `start` and `finish` both refuse outright when `enabled` is false.
Accounts now link on `(issuer, sub)` (a new `sso_identities` table), never on email; an unlinked
local account that merely shares an email is refused with a message asking an administrator to
link the two explicitly, rather than being auto-adopted. `email_verified == Some(false)` is
refused; `allowed_domains` is a required, admin-configured, non-empty list checked in `finish`
before provisioning. Nobody uses SSO yet in production, so this shipped as a straight behavior
change with no grandfathering.

**Where** (verified by reading): `sso.rs:146` `start`, `:170` `finish`, `:72` `validate`;
`web_sso.rs:94` `login`, `:116` `callback`; `auth.rs:578` `sso_login`.

**Concerns**, three independent ones:

1. **The on/off switch is only cosmetic.** `SsoConfig.enabled` is read only by `public()` (to hide
   the button) and by `validate()`, which *skips* its checks when disabled. Neither `login` nor
   `callback` nor `start`/`finish` checks `enabled`. When an admin configures SSO and later
   switches it off, the issuer, client id and secret stay stored (`web_sso.rs::put`). A direct
   `GET /api/auth/sso/login` (a public route, `web/mod.rs:247`) still runs the full flow and
   issues a session.
2. **No allow-list and no `email_verified` check.** `finish` accepts any ID token the configured
   client receives and keys the account on `claims.email()` (`sso.rs:182`). `sso_login` then
   provisions any new email as a `viewer`. With a public issuer, for example Google with an
   "External" OAuth client, any Google account holder in the world gets a viewer session. A
   viewer can read the whole inventory and every alert.
3. **Email-keyed linking to existing local accounts.** `sso_login` uses an existing local account
   "as-is" when its username equals the IdP email. Usernames may contain `@`
   (`auth.rs:188 validate_username`). `start_session_for` (`auth.rs:256`) then opens a session
   without TOTP and without the passkey-only policy (`passkey_only` is checked only in the
   password `login`). The authn middleware's `must_enrol` check does not help: an account that
   already has TOTP is "enrolled".

**Failure scenario.**

* Case 1: an admin tried Google SSO during evaluation, then turned it off. Months later anyone
  who knows the URL signs in via `/api/auth/sso/login`.
* Case 3: the IdP is a Keycloak realm with self-registration and no email verification, or an
  Auth0 database connection. An attacker registers there as `admin@company.com` and signs in to
  DENIS as the existing local `admin@company.com` administrator, skipping that account's TOTP.

**Direction.**

* Check `enabled` in `start` and `finish`, and refuse otherwise.
* Require `email_verified == true` whenever the claim is present, and add an admin-configured
  allowed-domains list (or allowed `hd`/`tid`), refusing when it is empty.
* Link on `(issuer, sub)` stored per user, not on email. Only link an existing *local* account
  after an explicit admin action.
* Decide deliberately whether an IdP login satisfies a local account's TOTP/passkey requirement,
  and write the decision down (e.g. require the `amr`/`acr` claim).

### H3. A panic in any engine task silently stops detection while the console looks healthy

**Status (2026-09-30): visibility half fixed (v2.58.0), architectural half deferred on purpose.**
The periodic detector tick now recovers from a poisoned lock (best effort) instead of also dying,
and `/api/health`/the Health page now show detector tick staleness and lock-poisoned state, so
this failure mode can never be silent again. The full fix this section asks for — a real
supervisor or dedicated detector thread, chosen "with M7 and Phase 2 in mind" per this session's
own follow-up review — is intentionally left for the multi-tenancy groundwork phase, where the
same ~25 `tokio::spawn` tasks get restructured anyway (see ROADMAP.md's confirmed order). Every
other lock site in `engine.rs`/`ingest.rs` still fails loudly (plain `.lock().unwrap()`), unchanged.

**Where** (verified by reading):

* `engine.rs:996-1174`: roughly 25 `tokio::spawn` tasks are pushed into `tasks`. Those handles
  are only `abort()`ed at shutdown (`:1258`) and are never awaited or polled.
* `engine.rs:1253`: the `select!` watches only Ctrl-C, the restart signal and the web `server`.
* `engine.rs:906-910`: a comment says the detector and inventory locks stay `.lock().unwrap()` so
  that "failing loudly and letting the process restart is safer than serving corrupted state".
* `Cargo.toml` has no `panic = "abort"`, and nothing installs a panic hook.

**Concern.** The comment describes behaviour the code does not have. A panic inside a Tokio task
is caught by Tokio, logged once, and does *not* end the process. If it happens while the detector
mutex is held (every detector call site holds it), the mutex is poisoned. From then on, every
other `d.lock().unwrap()` panics the next time it runs:

* the flow task (`:1080`)
* new-device and signals (`:1098`)
* the 5-second tick and baseline flush (`:1122`, `:1125`)
* presence and trends (`:1152`)
* ingest (`ingest.rs` `apply`, where it becomes a 500 per report)
* baseline edits and site delete (`:944`, `:983`)
* shutdown (`:1262`)

The same applies to the aggregator (`:589`/`:593`) and the inventory lock. Meanwhile the web
server, `/api/health` and systemd's `Restart=` all see a live process. For a monitoring product,
"up but not detecting" is the worst failure mode.

**Failure scenario.** Any single panic reachable from packet- or agent-derived data in
`Detector`/`Inventory` code, for example an arithmetic or indexing edge case in a rule, turns
into a permanent, silent end of all detection until someone restarts by hand. I did not find a
concrete panic in the parts of `detect.rs` I read. The parser has its own fuzz test; the detector
does not.

**Direction.** Pick one policy and make the code match it:

* either `panic = "abort"` in `[profile.release]`, so systemd restarts the process, or
* a supervisor that owns the `JoinHandle`s, `select!`s on them, and exits (or restarts the task
  with fresh state) when one ends.

Also add the detector and aggregator tasks' liveness (last tick time) to `/api/health` and the
Health page, so "up but not detecting" is visible.

### H4. Deleting a site whose agent keeps reporting breaks baseline, presence and conversation persistence for the whole install

**Where** (traced, not reproduced): the steps below span several files, listed in the trace.

**Trace.**

1. An admin deletes site `branch-b` (`web_admin.rs:1259 agents_delete`). By design, and as the
   doc comment says, the agent's token stays valid.
2. `delete_agent_and_its_devices` removes the assets. `Detector::forget_assets` (`detect.rs:484`)
   clears baselines, presence and conversations for those ids, **but not the `ids` cache**
   (`detect.rs:320`, filled at `:566-573`). The comment above it only discusses cooldown maps.
3. The agent's next report re-creates the assets with **new** ids (`AUTOINCREMENT`, so no reuse).
   The detector's `asset_id(Some("branch-b"), mac)` still returns the **old, deleted** id from its
   cache.
4. `ingest_asset(old_id)` creates `baselines[old_id]` and marks it dirty. Flow alerts for these
   devices are silently dropped, because `store.get_asset(old_id)` returns `None`.
5. Every 30 seconds `Detector::flush` (`detect.rs:1900`) calls `save_baseline(old_id)`. Since V13,
   `PRAGMA foreign_keys` is on (`store/sqlite.rs:385`) and `baselines.asset_id REFERENCES
   assets(id)`, so the insert fails. `flush` returns on the first `?` **before** removing that id
   from `dirty` and **before** it reaches the presence and conversation sections.
6. Result: from then on, presence and communications-matrix changes for *every* site are never
   persisted, and some baselines are persisted only when the hash-set iteration order happens to
   reach them first. The only symptom is a repeated "saving baselines failed" log line. A restart
   clears the cache, and silently loses everything that went unsaved in the meantime.

The same path applies to `delete_asset` (manual assets only) for a MAC that is also live on the
network.

**Direction.**

* `forget_assets` must also remove every `ids` entry whose value is in the set. More robustly,
  make `ids` validate on a miss (or key baselines by `(agent, mac)` instead of by row id).
* Make `flush` best-effort per item: log and drop an item that fails a constraint, and keep
  going.
* Add a test: delete a site, report again, flush, and assert that presence rows are written.

### H5. "Verify fix" and scheduled re-verification port-scan a remote site's device IP from the master's own network

**Status (2026-09-30): fixed (v2.59.0).** Both call sites (`web_admin.rs::finding_verify` and
`reverify.rs::evaluate`) now refuse any device with `agent_id.is_some()` before it ever reaches
the master's local rescanner — reported as `not_probed`, with a plain sentence explaining why,
rather than silently scanning whatever shares that IP on the master's own network. Routing the
request to the owning agent instead (so a remote device's fix really can be re-verified) is not
built — that needs the agent side to gain its own on-demand port-scan capability, which does not
exist yet.

**Where** (verified by reading): `web_admin.rs:1903 finding_verify`, `reverify.rs:152-155` and
`:210-214`, and `engine.rs:1367 rescanner`.

**Concern.** Both paths take `asset.current_ip()` for any device, including devices whose
`agent_id` is a remote site. They then hand the bare IPv4 address to the master's own local
`rescanner`. The rescanner has no idea of sites. It probes the address from the master's network,
honours only the master's own `--exclude`, and feeds the result back as `Observation::Ports` and
`Observation::Banners` into the **master's local inventory**, keyed by IP.

**Failure scenarios.**

* Branch and HQ both use `192.168.1.0/24`. An editor clicks "Verify fix" on a branch device
  `192.168.1.20`. HQ's own `192.168.1.20` gets scanned instead. The report then says the branch
  device is "fixed" or "still present" based on the wrong machine, and HQ's local device record
  gets the wrong port list.
* The `is_ot_device` guard in both paths is evaluated on the *remote* asset. If HQ's
  `192.168.1.20` is a PLC, it gets actively probed, which breaks the product's "industrial
  devices are never scanned" promise.
* `reverify::run` does this automatically, daily, for every accepted scan-type risk.
* A compromised agent can put any IP into a device's `ip_history` (it is taken as-is apart from
  truncation). An editor's "Verify fix", or the daily job, then points the master's active
  scanner at an arbitrary host.

**Direction.** Only rescan devices with `agent_id == None`. For remote devices, either say "not
probed: remote site" or route the request to that agent. NAC.md's SNMP connector will face the
same "which network does this address live on" question, so it is worth fixing this before that
code copies the pattern.

## Medium

### M1. Unauthenticated denial of service against passkey sign-in and registration

**Where** (verified by reading): `passkey.rs:156 Ceremonies::begin`, `web_passkey.rs:110
login_begin` (public).

`begin` refuses once 2,000 unexpired ceremonies exist, with a 5-minute TTL. Login and
registration share the one map. No per-address limit applies to `login/begin`. About 7 requests
per second from anywhere keeps it full, so no one can sign in or enrol with a passkey. Under the
`passkey_required` policy, password sign-in is also refused for covered accounts
(`auth.rs:292`). Those users, typically the administrators, are then completely locked out.

**Direction.** Rate-limit `login/begin` per client IP, as `ip_wait` already does for sign-in.
Keep registration ceremonies in a separate, per-user bounded map. Evict the oldest entry instead
of refusing new ones.

### M2. Any agent token can use the MSP-sync endpoint to inject forged alerts and unbounded data

**Where** (verified by reading): `ingest.rs:355 msp_sync` and `:112 apply_msp_sync`.

**Concern.**

* `/api/v1/msp-sync` accepts every `dat_` token. Nothing distinguishes an MSP customer's relay
  token from an ordinary remote-agent token.
* `apply_msp_sync` stores the sender's `Event`s as-is: kind, severity, score, `acked`,
  `timestamp` and arbitrary `raw_details` JSON. It also saves the sender's `AssetMeta` (name,
  owner, criticality, notes, `merged_into`...).
* It does none of what `apply`/`validate` do: no `clamp_asset`, no MAC validity check, no dedupe
  (every resend inserts the events again). The only bound is 5,000 items and 32 MB per request,
  with no request rate limit.

**Failure scenario.** A remote agent host is the least-trusted component: it sits on a remote
network. If it is compromised, it can:

* post forged high-severity alerts with any text into the master's console, SIEM export and AI
  prompts, since AI features read `raw_details`;
* edit any of its own site's device metadata;
* add 32 MB of events per request to the database, repeatedly.

**Direction.** Give tokens a kind (agent / msp-relay), set at issue time, and allow `msp-sync`
only for the relay kind. Also:

* Run the same validation and clamping as `apply`.
* Bound `raw_details` size.
* Dedupe on the sender's event id.
* Never accept `acked` or `ack_reason` from the sender.

### M3. The "never round-tripped" secrets can still be read back by an admin who changes the destination

**Where** (verified by reading for vulnscan, SMTP and switches; the other sources follow the same
"blank keeps the stored secret" rule and are suspected to share the problem):

* `web_vulnscan.rs:46 put`: a new `server_url` is saved while the stored API keys are kept. The
  keys go out in `X-ApiKeys` on the next `/api/vulnscan/sync`.
* `channels.rs:350-372`: a new SMTP `host` keeps the stored `password`.
* `switches.rs:92-97`: a new `address` for an existing switch id keeps the community.
  `/api/switches/{id}/poll` then sends it in cleartext SNMP to the new address.
* The same pattern exists for Jamf `server_url`, the SSO `issuer_url` (the client secret goes to
  whatever token endpoint the new issuer's discovery document names), and the SIEM/Elastic
  `api_key`.

**Concern.** Every GET correctly withholds these secrets, and that convention is followed in all
the handlers I checked. But any admin, or anyone holding an admin session, can recover each one:
point the destination at a host they control, press "Sync"/"Test"/"Poll", and read it off the
wire. Today admins are all-powerful, so this is Medium. Under multi-tenancy, where an MSP operator
and a customer admin are different people, it becomes a cross-tenant credential leak.

**Direction.** When a destination field (URL, host, address, issuer) changes, clear the stored
secret and require it to be entered again. Bind each secret to the destination it was entered
for.

### M4. A hijacked session can guess the password without limit and plant a lasting passkey

**Where** (verified by reading): `auth.rs:533 change_password` and `web_passkey.rs:32
register_begin` / `:66 register_finish`.

* `change_password` checks `current` with `verify_password` but never calls `record_failure` or
  `lock_remaining`, unlike `confirm_password` (`auth.rs:378`). A stolen session cookie therefore
  gives an unlimited password-guessing oracle, limited only by Argon2's cost.
* Passkey registration needs no re-authentication. TOTP set-up does: `web_totp.rs::begin` calls
  `confirm_password`. With a stolen session, an attacker can register a passkey. That passkey
  survives the victim changing their password and an admin's `reset-password`, which ends
  sessions (`auth.rs:553`) but leaves passkeys alone.

**Direction.** Route `change_password` through the same lock-out as `confirm_password`. Require
`confirm_password` (or an existing passkey assertion) before `register_begin`. Announce every new
passkey on the alerting channels. Consider having an admin password reset also revoke passkeys,
or at least list them.

### M5. The generated local CA can sign certificates for any domain

**Where** (verified by reading): `certs.rs:104 ca_params`.

The "DENIS local CA" is a real CA (`BasicConstraints::Constrained(0)`, `KeyCertSign`) with **no
name constraints**. The module doc and the console tell users to install it in their OS or
browser trust store. Anyone who later reads `tls/ca.key` on the DENIS host (0600, but it is the
host that faces a hostile LAN) can then issue a valid certificate for any site and intercept every
user who trusted it.

**Direction.** Add `NameConstraints` (`permitted_subtrees`) limited to the names and IPs from
`desired_names`. Existing CAs would need regenerating, and users re-trusting, so ship it with an
explicit notice. Alternatively, offer trust-on-first-use pinning of the server certificate
instead of a CA.

### M6. No cap on device count: spoofed MACs grow the inventory without limit

**Where** (verified by reading): `inventory.rs:178-204` (`entry(mac, now)` on every ARP, DHCP or
flow observation) and `parse.rs:258` (any outbound packet from a local IP yields an
`Observation::Arp`). No maximum exists anywhere in `inventory.rs`, `engine.rs` or `detect.rs`.

**Failure scenario.** Anyone on the monitored LAN sends frames with random, valid, locally
administered source MACs and local source IPs. Each one becomes an asset row, an `ids` entry and
a `new_device` evaluation. `new_device_burst` fires, but nothing stops the growth. Every
`/api/assets`, `/api/status`, `/metrics`, findings and report call does `load_assets()` on the
whole table. On top of that, `/api/assets` calls `site_readable` once per asset, and each call is
a `site_access_all()` query (`access.rs:78`). The console slows to a halt, and the database grows
by millions of rows.

**Direction.**

* Add a configurable hard cap on new-device creation per window (e.g. per minute), and on the
  total count, with a health warning when it is hit.
* Load the grants once per request in `site_readable`'s callers.
* Page `/api/assets`.

### M7. Blocking SQLite and `std::sync::Mutex` work runs on Tokio worker threads behind one global connection lock

**Where** (verified by reading; the size of the impact was not measured):

* `store/sqlite.rs:330`: one `Mutex<Connection>` for the whole process.
* `store/sqlite.rs:461`: `VACUUM INTO` (every backup and pre-update backup) holds that lock for
  the entire copy.
* `engine.rs:589/593` (aggregator `flush_now(&*store)`), `:1080-1082`, `:1098-1101`, `:1122-1125`
  and `:1152-1160`: these call detector and store methods that do synchronous SQLite I/O
  (`find_asset`, `get_asset`, `save_baseline`...) directly inside `tokio::spawn` async blocks,
  while holding the detector `std::sync::Mutex`.
* `ingest.rs` `apply` holds the same detector mutex inside `spawn_blocking` while processing up
  to 100,000 flows.

**Concern.** While a backup runs, or while a large agent report is applied, every engine task
blocks a Tokio worker thread on the SQLite lock or the detector lock. On a 1-2 vCPU host (the
VPS/homelab target) that is every worker, so the web server and the ingest listener stop
answering too. The web handlers do correctly use `spawn_blocking`; the engine does not.

**Direction.** Move engine-side detector and store work into `spawn_blocking` (or one dedicated
detector thread fed by a channel, which also makes H3's supervision simpler). Use SQLite's online
backup API in steps (`rusqlite::backup`) instead of `VACUUM INTO` under the global lock. A
read-connection pool (WAL allows concurrent readers) is the natural stepping stone toward the
PostgreSQL work anyway.

### M8. A remote site with more than 5,000 changed devices silently never reports its inventory

**Where** (verified by reading): `agent.rs:160 next_batch` sends
`inv.changed_since(self.last_rev)` with no size cap; `ingest.rs:269 validate` rejects more than
`MAX_ASSETS = 5_000` with a 400; and the agent's `on_rejected` (`agent.rs:206`) drops the batch
**and advances `last_rev`**.

**Failure scenario.** An agent's first run at a site with 6,000 devices, or after anything that
marks many devices changed, builds one batch with 6,000 assets. The master refuses it as "report
too large". The agent drops the batch, including the flows and signals in it, and marks all
6,000 devices as sent. Those devices appear on the master only if they change again.

**Direction.** Chunk assets in `next_batch` to at most `MAX_ASSETS` (as flows and convs already
are), keeping the remaining revision range pending. Make the master's limit an advertised
constant the agent reads, not a duplicated literal.

### M9. SSO sign-in can be forced onto the attacker's account (login CSRF)

**Where** (verified by reading): `sso.rs:104 stash_pending` and `:170 finish`. The `state`,
nonce and PKCE verifier are kept in a process-global map keyed by `state` alone, not bound to the
browser (no cookie). The error text says "does not belong to this browser", but nothing checks
that.

**Failure scenario.** The attacker starts `/api/auth/sso/login`, completes the IdP step with
their own account, captures the callback URL without opening it, and gets the victim to open
it. The victim is now signed in to DENIS as the attacker. The impact here is limited (a viewer
account), but it is the textbook OIDC login-CSRF.

**Direction.** Set a short-lived, `HttpOnly`, `SameSite=Lax` cookie holding a random value
at `login`. Key the pending map on it together with `state`, and compare in `callback`.

### M10. Credentials at rest are readable by other local users, and backups carry every one of them

**Where** (verified by reading):

* The SQLite database is created with default permissions (`Connection::open`) in systemd's
  `StateDirectory=denis`, which defaults to mode 0755 (`packaging/denis.service:43`; there is no
  `StateDirectoryMode=` or `UMask=`).
* Agent backups received by the master are written with `std::fs::write`
  (`ingest.rs:103`), so they get default permissions.
* `backup_to` creates the file first and `chmod`s it to 0600 afterwards (`store/sqlite.rs:461-466`).

**Concern.**

* The database holds TOTP secrets, every integration secret in plaintext settings rows (Entra,
  AD bind password, Jamf, AWS, the GCP private key, Nessus keys, SMTP and webhook secrets, the
  SSO client secret) and report share tokens (also plaintext, see L4).
* Any local account on the host can read the database and the received customer backups.
* `--backup-upstream` ships a customer's whole database, secrets included, to the MSP. A
  compromise of the MSP master therefore yields every customer's cloud and directory
  credentials.

**Direction.**

* Set `StateDirectoryMode=0700` and `UMask=0077` in both unit files.
* Create the database and agent backup files with mode 0600, before writing any data.
* Longer term, encrypt secret settings with a key kept outside the database, e.g. from
  `CREDENTIALS_DIRECTORY` or a key file.
* Strip or re-encrypt secrets in backups sent upstream.

## Low

**L1. The local `cargo audit` result disagrees with CI.** The only reason CI passes is an ignore
listed inline in `ci.yml`. Add a `.cargo/audit.toml` with the same ignore and its justification,
so that the local and CI results match and the exception lives in one place. (Verified.)

**L2. Anyone can keep any account locked out.** `auth.rs:240 record_failure` locks by username
after 5 failures, escalating to 15 minutes, from any IP. An attacker spreading guesses over
several IPs (each staying under the 20-per-IP window) can keep `admin` locked out indefinitely.
Passkey sign-in still works. This is a known trade-off; consider also keying the lock by
`(username, ip)` so that one attacker cannot lock out everyone else. (Verified.)

**L3. SSO `/login` is an unauthenticated amplifier.** Each `GET /api/auth/sso/login`
(`web_sso.rs:94`) fetches the IdP discovery document and adds an entry to the unbounded
`PENDING` map (`sso.rs:104`, TTL cleanup only). Cache the discovery document and cap the map.
(Verified by reading.)

**L4. Report share links are stored in plaintext and never expire.** `reports.rs:126 share`
stores the token itself in `settings["report_shares"]`, unlike every other token, which is
stored hashed. Store a hash and add an expiry. (Verified.)

**L5. Settings blobs fail open when they cannot be parsed.** Every settings `load` does
`serde_json::from_slice(..).ok().unwrap_or_default()`. For `auth.rs:408 read_security`, a
malformed blob means the MFA and passkey policies silently become `off`. For
`channels::load`, it means an empty list, and the next "add channel" then saves over and loses
all the old ones. `access.rs` already fails closed on a store error; the security policy should
too. (Verified by reading; I know of no current trigger.)

**L6. Settings updates can lose each other.** Channels, report shares, rules, the security
policy and findings first-seen are all read, changed and written back as separate store calls
with no transaction. Two admins editing at once can lose one change. This matters more under HA
with several writers. (Verified by reading.)

**L7. The IPv4 total-length field is trusted for byte counts.** `parse.rs:232` takes the
header's total length as the flow's byte count. A LAN attacker can send tiny packets that each
claim 65,535 bytes, to inflate a victim device's volume and trigger (or, over a learning period,
mask) `volume_anomaly`. Use `min(header length, captured length)` unless the packet is our own
TSO frame. (Verified.)

**L8. "Acknowledge all" costs two round trips per alert.** `web/mod.rs:701 ack_all` loads up to
100,000 events, then does one `site_writable` call (a full grants query) and one `spawn_blocking`
update per event. A single editor click can occupy the store lock for a long time. Use one
`UPDATE ... WHERE id IN (...)` after filtering by site in SQL. (Verified.)

**L9. API tokens bypass site restrictions and outlive their creator.** Tokens get user id `-1`
(`web/mod.rs:302`), which never has grants, so they have full access to every site. They also
remain valid after the admin who created them is disabled or deleted. Document this now, and
design tenant scoping for tokens as part of multi-tenancy. (Verified.)

**L10. Some settings changes are not audited.** `top_talkers_excluded_put` (`web/mod.rs:1037`)
changes a global setting at editor level without an audit entry, unlike every other setting.
(Verified.)

## Overall architecture health

**What is solid and should be kept.** The module split for the web layer (`web/` plus
`web_*`, with shared state in `web/common.rs`) is clean. The security conventions are real and
followed almost everywhere: hashed tokens, redacted GETs, audit calls, the X-Denis header,
strict CSP, escaped output. The ingest protocol has sensible idempotency (run id plus sequence
number) and bounds. The parser and the WebAuthn and TOTP code are among the best-written parts.
Detector state is bounded almost everywhere (the conversation, cooldown, LAN-scan and
rotation-burst maps all have caps or sweeps). That is unusually careful.

**What is structurally weak, in order of how much it matters for the next batch of work:**

1. **Authorization is enforced per handler, not by the data layer.** Site access (the only
   isolation mechanism that exists today) depends on every handler remembering to call
   `site_readable` or `scoped_asset`. H1 shows at least 10 routes that forgot, including every
   route that takes an id in the body. Multi-tenancy built the same way will have the same bug
   with worse consequences: one tenant reading another's data. **Recommendation: before
   multi-tenancy, change the `Store` read methods to take a scope (site set now, tenant later) as
   a required argument,** so an unscoped read is a compile error, not a code-review catch. Filter
   in SQL, not in Rust after `LIMIT`.
2. **The `Store` trait is too big.** It has 103 methods across 10 sub-traits, all combined into
   one `Store`, and every consumer gets all of it. On top of it sits an untyped key/value
   `settings` store with 186 call sites. That store holds real *data* (report shares, findings
   first-seen, license activations, channels, switches, site access until V14) as well as
   configuration. For PostgreSQL and multi-tenancy, each of these blobs needs a tenant key and
   concurrency control (L6). Consider moving data-like blobs into real tables before porting,
   rather than porting 186 call sites twice.
3. **The engine keeps database state in memory and relies on manual cache invalidation.** The
   detector's `ids`, baselines, presence and conversation maps, plus the inventory, are
   authoritative copies of database rows, kept consistent through bespoke channels (`erase_tx`,
   `baseline_edit_tx`, `agent_delete_tx`). H4 is a direct result: one forgotten map. With HA
   (two masters) this model cannot work as it stands, because each process's caches will
   disagree with the shared database. The HA design should decide explicitly which process owns
   detector state for which site.
4. **No supervision and a single connection.** There are about 25 unsupervised tasks (H3), sync
   I/O on async workers (M7), and one process-wide SQLite mutex. None of this hurts much at
   homelab scale. All of it will hurt with an MSP's device count and with HA failover, where
   "the process is up" must really mean "the process is working".
5. **Auth state lives in memory, which blocks HA.** Lock-out counters, MFA tickets, passkey
   ceremonies, SSO pending state (a process-global `static`) and the API rate limiter are all
   per-process. Behind a load balancer with two masters, sign-in ceremonies will fail at random,
   and lock-outs and rate limits will be per node. Plan to move these into the shared store (or
   use sticky sessions) as part of the HA work.

**Verdict.** The codebase is in good shape to *keep growing*, and its security primitives do not
need rework. It is **not yet in good shape to build multi-tenancy on**. Items 1 and 3 above, plus
H3's supervision, should be addressed first. The fixes for H1-H5 are each small, and should be
done now regardless. The structural change that matters most is making data scoping a property of
the store API rather than of each handler, because tenant isolation will depend on it more than on
anything else. For NAC specifically, fix H5 first: an enforcement action aimed at "the device with
this IP" has exactly the which-network ambiguity H5 shows, and a wrong target there cuts a real
device off instead of just scanning it.
