# Two collectors on one network: why every device shows up twice, and the fix

A real deployment (2026-09-30) put the master's own capture and a Windows agent
(`windows-test-laptop`) on the *same* L2 segment, `10.0.10.0/24`. Both see the same physical
devices — same MAC addresses, from two vantage points — and the console's "all sites" device list
now shows every one of them twice. Filtering the list to one site shows each device once. The
user has already reviewed and edited some of the `local` copies and does not want that work lost
or redone.

This document records what the code actually does today (read, not assumed), why, and a design
for the fix. It is a design only: nothing here is implemented yet. Same honesty bar as
[WINDOWS.md](WINDOWS.md) and [CMDB.md](CMDB.md): **verified** means read in the source in this
worktree; **inferred** means reasoned from that source but not run or observed.

## Short version

* **Not a keying typo — the duplicates are by design.** Every device row belongs to exactly one
  *site*, a site *is* a collector (`agent_id`, `NULL` = the master's own capture), and the unique
  key is `(site, mac)`. That model assumed each agent watches a *different* network ("run
  `denis agent` at each remote site", docs/concepts.md). Two collectors on one network were never
  modelled, so they become two sites with the same devices.
* **Do not switch to a global MAC key.** A site is also the access-control boundary
  (`access.rs`), the MSP customer boundary (`msp_relay.rs`), the unit that gets deleted with its
  devices, and the unit that gets its own learning period. Merging on MAC across *all* sites would
  merge devices across customers and across access grants.
* **The fix is narrower than a re-architecture:** let an administrator say "this agent watches
  the same network as site X" (a *join*). A joined agent's reports land in site X's rows, merged
  field by field instead of overwriting them. One transaction merges the duplicates that already
  exist. A small new table records which collectors have seen each device, so the console can show
  "seen by: local, windows-test-laptop". The console *suggests* the join when two sites share many
  globally unique MACs. It never joins them without a person confirming.
* **Your edits win.** The surviving row is always the target site's own row, which is where the
  user's edits are. Its human-set fields are never overwritten. The absorbed copy fills only what
  is empty. Every conflicting value that gets dropped goes to the audit log, and the confirmation
  dialog lists those values first.
* **Also a real bug, independent of the above** (inferred from code, not observed): after a master
  restart, local capture can start writing into the *agent's* rows instead of its own (see
  "A latent bug" below). Fix it first. It is small.

## What the code does today (verified)

### Device identity is `(site, mac)`, and has been since schema v1

`src/store/sqlite.rs`, V1:

```sql
agent_id TEXT,               -- NULL = the local collector
...
CREATE UNIQUE INDEX assets_agent_mac ON assets (COALESCE(agent_id, ''), mac);
```

Every lookup follows that key:

* `save_asset` adopts an existing row only by `COALESCE(agent_id,'') = COALESCE(?1,'') AND mac = ?2`.
* `find_asset(agent_id, mac)` uses the same predicate.
* `Detector::asset_id` caches `(agent, mac) -> id` (`detect.rs`), so flows, signals and
  conversations from a collector attach only to that collector's own row.

The `mac` column is **not** unique across the table. It is unique per site. For the local
capture, `agent_id` comes from `Inventory::entry`, which stamps the inventory's own `agent_id`
(`None` on the master) onto a new asset. For remote agents, `ingest.rs` overwrites it:
`a.agent_id = Some(id.clone())`, where `id` is the id the bearer token was issued for.

### Two ingestion paths, both site-keyed

* **`POST /api/v1/report`** (`denis agent`): `Ingest::apply` does `find_asset(Some(&id), &a.mac)`
  and then `save_asset(&mut a)` with the **agent's whole `Asset`**. That is a full-row replacement
  (`UPDATE assets SET ... every column ...`), not a merge. `first_seen` is the only field that gets
  reconciled (`min`).
* **`POST /api/v1/msp-sync`** (`denis run --report-to`, `msp_relay.rs`): `apply_msp_sync` uses the
  same `find_asset(Some(id), ..)` + full `save_asset`, **and also calls `save_meta` with the
  sender's own `AssetMeta`**. That overwrites the master-side edits for those rows on every sync
  where the device changed. This path mirrors *another install's* decisions and never re-scores
  them.

WINDOWS.md describes the Windows test as `denis.exe run` "reporting to the same production master".
That reads like `--report-to`, the msp-sync path, not `denis agent`. The brief for this document
says `denis.exe agent`.

**Now confirmed (2026-09-30): production uses `denis agent`, not `--report-to`.**
`apply_msp_sync` (`ingest.rs`) unconditionally calls `self.store.save_meta(a.id, &doc.meta, ...)`
for every device on every sync cycle — if this path were in use, every `windows-test-laptop`
device would have an `asset_meta` row by now, even an empty one. A read-only query against the
production database found **zero** `asset_meta` rows for any device with `agent_id =
'windows-test-laptop'`. That is only possible on the `/api/v1/report` (`denis agent`) path, which
never touches `asset_meta` at all. So the user's local edits are not at risk from this specific
overwrite path today — but the join design above still has to refuse msp-sync sites in general,
since a different install could use `--report-to` for this same scenario.

### The master's own capture is a separate writer

`engine.rs` runs one `Inventory` (an in-memory `HashMap<Mac, Asset>`) for the local capture. It
flushes whole rows through `save_asset`. Ingest never touches that `Inventory`. It writes straight
to the store. So today the two writers never write the same row, and that is the only reason the
whole-row overwrites don't clash. It is also why simply "sharing a row" is not enough (see the
fix).

### "Site" is `agent_id`, nothing more

* `access.rs`: `site_of(agent_id) = agent_id.unwrap_or("")`. Grants (`site_access` table) are
  per `(user, site)`. Every asset/event endpoint filters with `site_readable(&a.agent_id)`.
* UI: `inSite(a, site)` (`ui/app.js`) compares `a.agent_id`. `siteName(agentId)` shows the
  agent's name or `local`. This is why filtering to one site hides the duplicate: the duplicate
  lives in the other site.
* `AgentInfo.site` (`agents.site` column) is a free-text label that the agent **reports about
  itself** (`--site Branch`). It is only displayed. It is not a scope, and it must not become one
  automatically, because an agent could claim any label.
* Per-site behaviour keyed on `agent_id`: learning period (`Detector::learning_start(agent)`),
  agent-offline suppression (`tick_presence` skips devices of a silent agent), the agent-offline
  alert's host lookup (`a.agent_id == ag.id && a.is_self`), site deletion
  (`delete_agent_and_its_devices`: every row `WHERE agent_id = ?`), metrics (`metrics.agent_id`),
  and the report/CSV "site" column.

### A manual "same device as…" already exists, and it refuses exactly this case

`AssetMeta.merged_into` (`model.rs`) hides a device behind another one. It was built for one access
point broadcasting under several sibling MACs. The UI button is literally labelled *"This is the
same device as…"*. But:

* `ui/admin.js` `openMergeForm` offers only candidates with the same `agent_id`: "No other device
  on this site to merge with."
* `web_admin.rs` `patch_meta` refuses the merge server-side: "can only merge into a device on the
  same site".

So the user can't even fix this by hand today. That refusal is correct, too: `merged_into` is a
cosmetic hide. The hidden sibling keeps its own alerts, baselines and presence, and keeps
receiving the other collector's reports. Auto-setting it across sites (the obvious "automatic
pairing") would hide half the list while every duplicate alert, silence alert and edit split
continued underneath. **Rejected as the fix.** It is still the right tool for the case it was
built for, one box with several MACs on one site.

### Duplicates also cost licence slots (verified)

`/api/assets` applies `license::keep_within_cap` to the list after the site and `merged_into`
filters. Both copies count, so on a capped (community) install a second collector on the same
network roughly halves the useful device cap.

## A latent bug (inferred from code, not observed — fix first, it is small)

`Collector::start` loads the local `Inventory` from `store::real_assets(&*store)`, and that returns
**every** non-demo asset, including every remote agent's rows. `Inventory::new` keys them by MAC
into one `HashMap`. When two rows share a MAC, the one with the later `last_seen` wins
(`loaded.sort_by_key(last_seen)`, then insert).

After a master restart, for a MAC that both the master and the Windows agent have seen:

1. If the agent's row happened to win, local ARP/DHCP/mDNS observations of that MAC update the
   **agent's** row in memory. `entry()` finds it and never resets `agent_id`. `flush` then
   `UPDATE`s it by id, with `agent_id` still `'windows-test-laptop'`.
2. The next agent report overwrites that same row wholesale with the agent's own view. The local
   inventory's in-memory copy is now stale, and its next flush overwrites the agent's data back.
   `ip_history`, `open_ports`, `hostnames` and `fingerprint` flip-flop between the two views.
3. The master's own `local` row for that MAC stops getting discovery updates. Its `last_seen`
   freezes, so `tick_presence` can eventually raise `device_silent` on a device that is plainly
   online. Local flows still attach to the `local` row, because `find_asset(None, mac)` finds it.

So the number of duplicates, and which copy stays fresh, depends on restart timing. Anyone
inspecting the production database should expect a mixed picture, not a clean "one row per
collector".

**Fix:** the local `Inventory` loads only rows whose `agent_id` is `None`. That is one filter in
`Collector::start`, plus a test: a stored agent row with the same MAC is not touched by a local
observation after reload. This is correct whatever else is decided here, and it should ship before
(or with) the rest. After the join described below, a joined agent's devices *are* `local` rows,
so this filter loads them, which is what we want.

## Design

### 1. Root cause, plainly

This is an **architectural gap, not a bug**, apart from the latent bug above. The model is "a site
is one collector and owns its devices". A second collector on the same network is, by
construction, a second site with the same devices. Nothing mis-keys anything. The model has no way
to say "these two collectors look at one network".

### 2. What "same device" means: exact MAC, within one site

Exact MAC equality is sufficient here and nothing fuzzier is proposed:

* Two capture points on the **same L2 segment at the same time** see the *same* source MAC in the
  same frames. They see it via ARP broadcasts at minimum.
* **Randomised (locally administered) MACs match too.** A phone rotates its MAC per SSID or over
  time, not per observer, so both collectors see the same randomised MAC while it is in use. The
  separate problem, "same phone, new random MAC tomorrow", already exists with one collector. It is
  not made worse, and it stays out of scope (the manual `merged_into` covers the occasional case).
* Hostname, OUI+IP, port-set correlation: **not used for identity.** CMDB.md already records this
  project's position ("a fuzzy match risks pointing an admin at the wrong device, which is worse
  than no match at all"). IPs are history, not identity (`inventory.rs`'s module comment).

The **dedup boundary is the site, not the whole table.** Identity = `(site, mac)`, which is the
existing unique index, unchanged. What changes is that **a collector no longer always equals a
site.**

### 3. The fix: join an agent into an existing site

#### Schema (one new version, V20; illustrative)

```sql
-- Which site an agent's reports land in. NULL = its own site (today's behaviour, the default).
-- '' = the master's local site. 'x' = agent x's site (deferred, see below).
ALTER TABLE agents ADD COLUMN reports_into TEXT;

-- Which collectors have seen each device, and when. One row per (device, collector).
CREATE TABLE asset_sightings (
    asset_id   INTEGER NOT NULL REFERENCES assets(id),
    collector  TEXT    NOT NULL,          -- '' = the master's own capture, else an agent id
    first_seen INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL,
    is_self    INTEGER NOT NULL DEFAULT 0, -- this device is that collector's own host
    PRIMARY KEY (asset_id, collector)
) WITHOUT ROWID;
```

In the migration, backfill one sighting per existing asset: `collector = COALESCE(agent_id, '')`,
using the row's own `first_seen`, `last_seen` and `is_self`. `assets.agent_id` keeps its column
name but is documented from now on as "the site this device belongs to". Renaming the column
touches every query and test for no behavioural gain, so it is not proposed.

`reports_into` is set by an **administrator on the master**, never taken from the agent's report:
a token is bound to an agent id, and that agent must not be able to choose which site's rows it
writes into.

#### Ingest, once an agent is joined

Resolve `site = reports_into` for the agent, then:

* **Devices:** never `save_asset` the agent's whole `Asset`. Merge it into the site's row with one
  pure function (a sketch, not an implementation):

  ```text
  merge_observed(stored: &mut Asset, incoming: &Asset) // discovery fields only, never AssetMeta
    first_seen       = min
    last_seen        = max
    ip_history       = union by ip (min first_seen, max last_seen), newest 20
    ipv6_history     = same
    hostnames        = union, keep order, first 8
    open_ports       = whichever side has the newer ports_scanned_at (a scan is a snapshot:
                       a union would resurrect ports that one side has since seen closed)
    ports_scanned_at = max
    fingerprint      = per field: keep stored if set, else take incoming; list fields union+truncate
    is_gateway       = OR
    is_self          -> not merged here; goes to asset_sightings.is_self for that collector
    vendor, randomized_mac = identical by construction (same MAC)
    device_type, os_guess, guess_reasons = re-derived by fingerprint::guess afterwards
  ```

  Then upsert `asset_sightings(asset_id, agent_id)`.
* **Single writer.** For `reports_into = ''` (the local site), the merge runs **inside the local
  `Inventory`** (a new `Inventory::absorb(incoming, collector, now)` under its mutex), and the
  normal flush persists it. Otherwise the local inventory's in-memory copy and ingest would take
  turns overwriting each other: the same flip-flop as the latent bug, just on purpose. `Ingest`
  therefore needs an `Option<Arc<Mutex<Inventory>>>` of the local collector. If it is absent (a
  master without local capture), joining into `local` is not offered.
* **Flows, signals, conversations:** resolve devices with the *site* (`find_asset(site, mac)`,
  `Detector::asset_id(site, …)`). Keep the *agent id* only for per-collector bookkeeping (metrics
  and traffic totals). Today one `agent: Option<&str>` parameter means both; the implementer
  splits it into `site` and `collector`.
* **Events carry the site, not the collector.** `events.agent_id` is what `site_readable` filters
  alerts on. An alert about a `local` device stamped `windows-test-laptop` would be governed by the
  wrong grant. Put the collector into `raw_details.collector` instead, so it is still visible.
* **New-device alerts de-duplicate for free.** When the agent reports a MAC the site already has,
  `find_asset` finds it and nothing is "new". Inferred, likely but not verified: the per-device
  cooldowns (e.g. `conflict_cooldown_secs`, "per (device, address)") will also collapse the
  duplicate `arp_conflict` that both collectors raise, because both now resolve to one asset id.
  The implementer should confirm this with a test.
* **Learning period:** a joined agent's devices use the site's learning start. No second learning
  period for a network already learned.
* **Agent offline:** a joined agent going quiet raises its `agent_offline` event as before. For the
  host, look up the sighting with `collector = ag.id AND is_self`, since that device's `agent_id`
  is now `NULL`. Its devices are *not* suppressed as "site silent": the site's other collector may
  still see them. A device seen *only* by that agent will eventually go `device_silent`, and that
  is accurate.
* **Deleting the agent** now deletes its token, its `agents` row, its metrics and its sightings,
  **not the devices**. They belong to the site. This is the correct semantic, and the delete
  confirmation has to say so.
* **Access:** grants for the joined agent's id stop mattering, because its data is `local` data
  now. If any grant names that agent, the join dialog says so ("2 users have access set for
  windows-test-laptop; after joining, its devices follow the grants for local").

#### The join itself: one confirmed action, with a preview

Sites page: on an agent's row, *"Same network as…"* → pick a site (first slice: `local` only) →
preview → confirm. Admin only, audited.

**Suggestion, not automation.** The console shows a one-line hint on the Sites page when two sites
share at least 5 **globally unique** (non-randomised) MACs *and* the shared ones are at least 50%
of the smaller site. Example: "windows-test-laptop sees 38 of the same 42 devices as local — same
network? [Review]". The thresholds are illustrative. Why not auto-join:

* The same subnet string proves nothing. Two customers (or two branches) both on
  `192.168.1.0/24` is the *normal* case, and `agents.subnet` is self-reported anyway.
* A large overlap of *globally unique* MACs, on the other hand, is near-impossible across genuinely
  separate networks. That makes it a good *trigger for a question*, but the answer changes who can
  see what (access grants), so a person gives it.

**Preview** (read-only, computed before anything is written):

* N devices seen by both (will be merged), M seen only by the agent (will move to `local`).
* Every field where **both** copies carry a *different* human-set value, listed per device, with
  the value that will be kept (the `local` one). If the list is empty, it says so. This is the
  answer to "I don't want to redo my edits": the user sees in advance that nothing of theirs is
  lost.
* Access-grant note, if any grant names the agent.

### 4. Merge precedence, field by field

**Survivor = the target site's row** (here: the `local` copy). Its `id` stays, so every link,
bookmark, exception and audit entry that points at the `local` device keeps working. The absorbed
row is the agent's copy. It is only ever the side that *fills gaps*.

**Discovery data** (`assets` columns): `merge_observed` above. Neither side is "human", so
recency or union applies.

**Human data** (`asset_meta`, every field a person can set in *Edit asset*, the review queue,
merge or tags):

| Field(s) | Rule |
|---|---|
| `display_name`, `asset_tag`, `serial_number`, `model`, `manufacturer`, `type_override`, `os_override`, `owner`, `department`, `location`, `supplier`, `purchase_date`, `purchase_price`, `warranty_expires`, `status`, `criticality`, `notes`, `icon`, `zone`, `purdue_level`, `muted_until` | Survivor's value if set. Otherwise the absorbed value. If **both** are set and differ, keep the survivor's value and write the absorbed one to the audit log (`asset.merge`, field, dropped value). The preview lists these conflicts. |
| `tags` | Union (survivor's order first), capped as today. |
| `custom` (map) | Union. On a key conflict, the survivor's value wins and the loser is audited, as above. |
| `reviewed` | OR: reviewed on either copy means reviewed. |
| `manual` | Survivor's value (a hand-created local device stays "manual"). |
| `demo` | Unchanged. Demo rows are never agent rows. |
| `merged_into` | If the *absorbed* row was merged into X, re-point the survivor to X only if the survivor isn't itself merged. Otherwise audit and drop. Any *other* device's `merged_into = absorbed.id` → `survivor.id`. |

**Child rows**, re-pointed from `absorbed.id` to `survivor.id` in the same transaction:

| Table / store | Rule |
|---|---|
| `events` | `asset_id` → survivor. `agent_id` → the site (`NULL`). Original collector → `json_set(raw_details, '$.collector', <agent id>)`. History is kept, not deduplicated after the fact. |
| `risk_acceptances` | Re-point. An active acceptance for the same `finding_id` already on the survivor → keep the survivor's and revoke the absorbed one with an audit note. |
| `audit` | Re-point `asset_id`, so the absorbed copy's history shows up under the survivor. |
| `baselines` | Merge: union `typical_destinations`/`typical_ports`/`rotating_ports`, sum-or-max counters, min `observed_since`. Dropping the agent's learned destinations would trigger a wave of `new_destination` alerts. |
| `presence` | Union `hours`; `silent_alerted` = survivor's. |
| `conversations` | Re-point `client_id`/`server_id`. On a primary-key collision, sum packets/bytes/reads/writes/controls, min `first_seen`, max `last_seen`, union `commands`. |
| rule `Overrides` (settings JSON) | Every `Scope { kind: "device", value: <absorbed id> }`, in exceptions and in any OT/IT watch scopes, → survivor id. The implementer greps every `kind: "device"` consumer. |
| `asset_sightings` | Absorbed row's sighting → re-pointed to survivor with `collector = <agent id>`. |

**Devices only the agent saw** (no `local` copy): `UPDATE assets SET agent_id = NULL`. Id, meta,
events and all child rows are untouched. Their events' `agent_id` → `NULL` too (for access
consistency), with the collector recorded in `raw_details` as above.

**Live state has to follow**, or the next flush writes the old picture back. The engine already
solved exactly this for site deletion: `delete_agent_via_engine` sends the request through a
channel so that `Detector::forget_assets` runs after the store change. The join goes through the
same kind of channel:

1. store transaction;
2. `Detector::forget_assets(absorbed ids)`, clear the `(agent, mac) → id` cache, reload merged
   baselines/presence for survivors;
3. reload the affected rows into the local `Inventory`.

**Undo:** not offered in the first slice. The survivor keeps everything, and every dropped value is
in the audit log. "Un-join" only changes where *future* reports land. It does not split devices
apart again, and the dialog says so. Splitting merged history back out correctly is expensive and
has no demonstrated need.

### 5. UI

* **Device detail**, under the heading: *"Seen by: local · windows-test-laptop"*, one chip per
  sighting, each with its own "last seen" as a tooltip. A device seen by one collector shows
  nothing extra, so single-collector installs look exactly as they do today.
* **Devices list:** no new column. Optionally, a search key `seenby:<name>` (fits the existing
  `SEARCH_KEYS`), so "devices only the laptop sees" can be answered.
* **Site column:** unchanged. It is the site, which is now correct for both copies' data.
* **Sites page:** a joined agent shows *"reports into: local"* instead of its own device count, and
  the overlap hint + *Same network as…* action from §3.
* **"This is the same device as…"** stays exactly as is: same site only, for the one-box/several-MAC
  case. With joined sites, "same site" now covers what the user wanted.

### 6. What NOT to build (this slice)

* **Global MAC dedup across all sites.** It breaks site access, MSP customer separation and site
  deletion, and it would merge colliding MACs across unrelated networks (cloned VMs, vendor
  default MACs on lab gear). The site stays the boundary.
* **Cross-subnet correlation** (the same laptop seen at two different sites via routing, NAT or
  VPN; the same device under two MACs on two VLANs). This is a much harder problem: a router
  rewrites L2, so the MAC isn't even visible from the far side. It is also much rarer than "two
  capture points on one segment". Out of scope. A roaming laptop that shows up at two *separate*
  sites is two rows, as it is today.
* **Fuzzy identity** (hostname, OUI+IP, port-set similarity). See §2.
* **Automatic joins.** The console suggests; an admin confirms.
* **Agent-into-agent joins** (two agents on one branch network). The same `merge_observed` applies,
  but the single writer is then ingest under `apply_lock` (no local `Inventory` exists for a remote
  site). The mechanism is ready, but nobody has hit this case yet, so the UI offers only `local`
  as a target at first.
* **MSP relay sites** (`denis run --report-to`, the msp-sync path). A relay mirrors another
  install's *decisions*: it overwrites `asset_meta` on every sync. Joining one into `local` would
  overwrite the user's local edits, which is exactly what they don't want. The join refuses any
  site that has ever received an msp-sync. The implementer needs a marker, e.g. a flag set in
  `apply_msp_sync`. The operational answer for "a second capture point on the same network" is
  `denis agent`, not `denis run --report-to`. If production's Windows machine uses the latter (see
  the WINDOWS.md note above), switching it to `denis agent` comes first.
* **Undo / split** (see §4).
* **Renaming `assets.agent_id` → `site_id`.** Documentation only.

## Suggested order

1. ~~**Latent bug:** the local `Inventory` loads only `agent_id IS NULL` rows. Include the reload
   test. Ships alone.~~ Done (2026-09-30): `Collector::start` now filters through
   `local_only_assets`, with a regression test. Not yet independently re-verified against a real
   restart on production (see "What was not verified").
2. ~~**Schema V20** (`agents.reports_into`, `asset_sightings` + backfill), and sightings recorded
   on every save.~~ Done (v2.53.0, v2.55.0). No behaviour change from this step alone; the "seen
   by" chip still has no UI.
3. ~~**`merge_observed` + `Inventory::absorb`**, and ingest routing for `reports_into = ''` and for
   another agent's site, including the `site`/`collector` parameter split for
   `ingest_flows`/`ingest_signals`/`ingest_conversations`/`set_learning_start`.~~ Done (v2.56.0),
   with a minimal admin endpoint (`PUT /api/agents/{id}/join`) to actually set/clear
   `reports_into` — admin-only, audited (`agent.join`), refuses joining an agent into itself or
   into a target that doesn't exist. Tests: two collectors, one MAC, one row for both the
   join-into-local and join-into-another-site cases; unjoined behaviour unchanged (verified by the
   full existing suite, no regressions).
   **Not yet built, still exactly as designed below:** the preview step, the fresh re-poll before
   confirming, the "seen by" UI, the overlap hint, drift detection, and the MSP-relay-target
   refusal (needs a marker `apply_msp_sync` doesn't set yet — until it exists, an admin must not
   join an agent into a site that has ever received an MSP relay sync, and this endpoint does not
   check that itself). A per-collector sighting for a joined agent's own contribution to a local
   row is also not separately recorded yet — see `Inventory::absorb`'s own doc comment.
4. **The join transaction + preview + audit**, going through the engine channel — the endpoint
   above is a plain, immediate `set_reports_into` call, not yet the fuller preview/re-poll/lock
   flow this section originally specified. Test against a copy of a database with real duplicates
   **and** hand-edited `local` metas. The production database is the obvious fixture: back it up,
   then run the join against the copy and check that every edited field survived.
5. **Overlap hint** on the Sites page, and the actual UI button (Sites page / device panel) to
   call the join endpoint above — nothing in the console surfaces this yet.

## What was not verified

* No code in this document has been written or run.
* ~~Whether production's Windows machine reports via `denis agent` or `denis run
  --report-to`.~~ Confirmed 2026-09-30: `denis agent` (see above) — the user's local edits are
  not at risk from the msp-sync overwrite path in this specific deployment.
* The latent-bug scenario is reasoned from `Collector::start`, `Inventory::new`/`entry`/`flush` and
  `save_asset`. It has not been reproduced. Querying production for `local`-site rows with a frozen
  `last_seen` whose MAC also has a fresh `windows-test-laptop` row would confirm or refute it
  cheaply.
* How much *unicast* traffic both collectors see (a switched segment normally shows each host only
  its own traffic plus broadcast/multicast, so flow double-counting should be small). If both sat on
  mirror ports of the same switch, per-device volume baselines would double-count. That is a
  deployment question, and this slice doesn't change it.
* That the existing per-device alert cooldowns collapse the two collectors' duplicate alerts once
  both resolve to one asset id (§3). Likely, but check it with a test.
