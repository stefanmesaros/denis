# Policy enforcement (NAC): architecture

The design pass for ROADMAP.md item 16. It was written before any enforcement code beyond one SNMP
primitive (reviewed below), and it is written with the same honesty bar as [CMDB.md](CMDB.md),
[WINDOWS.md](WINDOWS.md) and [IPV6.md](IPV6.md). **Nothing here has been built or verified yet.**
Everything below is a plan. Wherever this document says a switch or vendor behaves a certain way,
read it as "expected, not yet verified against real hardware" unless it says otherwise.

## The product decision, stated plainly

Until now DENIS has made one promise everywhere: it *observes and alerts, it does not block*
(README.md, docs/index.md "Not an intrusion *prevention* system", docs/switches.md "DENIS never
sends a SET and never changes anything on a switch", the Settings → Switches intro sentence in all
five languages, and the `topology.rs` module comment "read-only, never SET"). Item 16 breaks that
promise on purpose, and the roadmap is right that it is a different product category. A false
positive in detection costs someone a minute of reading. A false positive in enforcement takes a
real device (or, if the wrong port is chosen, a whole floor) off the network.

Stefan approved building it anyway, one connector per release, in the roadmap's order, testing each
one on his own network before starting the next. This document takes that as settled and designs
for it. It keeps one principle in place of the old promise:

> **DENIS never blocks anything on its own.** A person with the administrator role asks for every
> block, for one target at a time. They see exactly what will be cut off before they confirm. They
> confirm with their password. Every block is logged, announced on every alerting channel, and
> listed until someone undoes it.

That sentence replaces "DENIS never changes anything" in the user-facing copy (see "What the user
is told" below). It stays true for every connector on the list, not only for SNMP. Automatic
enforcement is not ruled out forever, but it is explicitly **not** in scope for any release this
document plans (see "Deferred").

A note on the list: ROADMAP.md item 16 names **twelve** connectors (WatchGuard is 11th and Juniper
SRX 12th), not ten. The design below does not depend on the count.

## Review of what already exists: `snmp.rs`'s SET primitive

Before this review, `src/snmp.rs` in the main checkout gained `pub const SET: u8 = 0xa3`,
`encode_set_request(community, request_id, oid, value)`, a `send_and_wait` helper split out of
`ask`, and `Client::set_int(oid, value)`. The module comment now says the SET is used only by
`crate::nac` for `ifAdminStatus` (that module does not exist yet).

**Verdict: it is a sound foundation. Keep it, with three required fixes before anything calls it
and one recommended change.** The encoding is right: a v2c SetRequest-PDU with one varbind that
carries a real INTEGER value, reusing the tested `enc_oid`/`enc_int`/`tlv`. Putting it on the same
`Client`, with its hostile-input decoder and request-id matching, is also right. None of the
architecture below needs a different primitive. Credential separation happens *above* this layer.
`nac.rs` builds its own `Client` with the write community, and the polling path never does.

Required fixes:

1. **`set_int` can report success when the switch refused.** `send_and_wait` (inherited from `ask`)
   turns `error_status == 2` (v1-style `noSuchName`) into `Ok`, because a *walk* treats it as
   "nothing here". `set_int` then throws the response away and returns `Ok(())`. So a switch that
   answers a SET with `noSuchName` (some v1-minded agents answer a bad or read-only SET that way)
   would look as if the port had been disabled. Its doc comment says it "confirms the device
   accepted it (`error_status == 0`)". Today it does not. `set_int` must check
   `error_status == 0` itself. It must also check that the response echoes the same OID with
   `Value::Int(value)`. It should turn the common SET errors into plain sentences:
   `noAccess` (6) and `notWritable` (17) mean "this community cannot write, or this switch does not
   allow this object to be written"; `wrongValue` (10) and `inconsistentValue` (12) mean "the switch
   refused this value"; `authorizationError` (16) means "the community is not allowed to do this".
2. **"No answer" does not mean "not applied".** A SET that timed out may still have been applied,
   with only the answer lost. `send_and_wait` resends up to `retries` times. For `ifAdminStatus`
   that is harmless, because setting the same value twice is idempotent. But the doc comment should
   say that a timeout leaves the outcome unknown. Callers must not treat an `Err` as "nothing
   changed". `nac.rs` handles this with a read-back (see "Execution"). The primitive only has to
   state the rule.
3. **No test covers it.** The test agent (`snmp::agent`) answers GET, GETNEXT and GETBULK and
   silently ignores everything else (`_ => continue`), so a SET is never answered. The agent needs:
   a set of writable OIDs; a separate write community (so a test can prove that a SET with the
   *read* community is refused, not applied); and a way to answer with a chosen error status (so
   fix 1 can be tested with `noSuchName`, `notWritable` and a dropped reply). There should also be
   a byte-level test of `encode_set_request` against a hand-worked
   `snmpset -v2c -c private host 1.3.6.1.2.1.2.2.1.7.5 i 2`, like the existing
   `a_get_request_is_the_message_every_snmp_tool_sends`.

Recommended: make `set_int` and `encode_set_request` `pub(crate)`, not `pub`. The module comment
says only `nac.rs` uses them. The visibility should say the same, so that no other module can
start writing to switches without the change showing up in review. The intra-doc link to
`crate::nac` stays broken until that module exists. That is harmless unless `cargo doc` is run
with broken links denied.

## Safety model

The stated risk is that a false positive blocks a real device. Each safeguard below answers one way
that could happen. The safeguards are listed in the order a request meets them.

### 1. Nothing is enforceable until someone turns it on twice

* **A global switch, off by default:** "Port control" under Settings (a new `nac` settings key with
  `enabled: bool`). When it is off, no enforcement endpoint does anything and no enforcement button
  is drawn. It works as a kill switch: turning it off stops new blocks at once, without deleting
  any credentials. It does **not** re-enable ports that are already blocked. Undoing a block stays
  possible while the switch is off (see 6). That way, turning the feature off in a panic does not
  leave anyone stuck.
* **Per target, a separate write credential.** For SNMP that is a `write_community` on each switch
  that should be controllable, next to the existing read community. A switch without one stays
  exactly as read-only as today, even when the global switch is on. Every later connector follows
  the same rule: its enforcement credential is its own field, which is empty until someone fills
  it in.

Configuring a switch for topology must never quietly make it controllable. This is the concrete
answer to the "read-only, never SET" invariant: it stays true for every switch whose write
community is empty.

### 2. Only a person with the administrator role, with a fresh password, and never a script

* The endpoints are admin-only (add them to the admin branch of `web::required_role`). API tokens
  can only be viewer or editor (`auth::issue_api_token` refuses anything else), so this also means
  scripts cannot trigger enforcement. That is intended for now.
* Every block re-asks for the administrator's password (`Auth::confirm_password`). This is the
  precedent `system.restart` and `system.shutdown` already set for actions where "a mistaken click
  here … needs more than an open session". Wrong answers count against the account's lockout, as
  they already do there.
* Refused under `--insecure-no-auth`. There is no real user to confirm and no one to hold
  accountable, so the endpoints answer 403 with a sentence saying why. This matches how that mode
  is already treated as unsafe everywhere else.
* Refused for users limited to certain sites (see `access.rs`/`site_writable`). Switches are not
  scoped to a site today, so a user who may only change one site's devices has no defined right to
  change a switch's ports. Only an administrator with access to every site may act, until switches
  get a site.
* Open question, not decided here: users who sign in only with SSO or only with a passkey may have
  no local password to confirm. Whatever `system.restart` does for them should apply here too. If
  they cannot restart, they cannot block. The implementation should check this rather than assume
  it.

### 3. A fresh look before the plan, never the last poll

The table that joins a MAC address to a switch port (`topology::build`) comes from the last stored
poll. That poll may be up to `interval_secs` old (60 to 3600 s, 300 by default). Worse,
`switches::poll_and_store` **keeps the last good snapshot when a poll fails**, so a switch that has
not answered for a day still shows day-old attachments, with only an error line beside them. That
data is fine for drawing a map and not good enough for cutting a cable. So:

* **Planning a block always re-polls that one switch first**, using the existing `poll_and_store`,
  which also refreshes the map. If the re-poll fails, the answer is no, with the reason. The plan is
  built only from that fresh snapshot.
* **A plan is a server-side object with a short life**: an id, the user who asked for it, and a
  two-minute expiry, kept in memory in `AppState`. It names the exact target (switch id, `ifIndex`
  and the `ifName` seen for that index), plus everything the dialog shows about what will be cut
  off. Confirming sends back only the plan id, the password and a reason. The browser cannot change
  the target between preview and confirm, and a plan more than two minutes old cannot be used.
* **Confirming reads the port once more, cheaply, right before the SET.** It GETs `ifName`,
  `ifAdminStatus` and `ifType` for that `ifIndex`. If the name no longer matches the plan, the block
  is refused. `ifIndex` values can be renumbered after a reboot or a module change on some switches,
  and this check stops DENIS from disabling "index 5" when index 5 is now a different port. It does
  not walk the forwarding table again. Within the two-minute window, re-walking it costs more than
  the risk it removes.

This also answers whether there should be a dry-run mode: **the preview is the dry run, and there is
no path around it.** A separate "dry-run mode" setting would add nothing.

### 4. Refusals: what the server will not do, whatever the user confirms

These are hard checks in the shared layer (plus the connector-specific ones for SNMP). For this
first release they cannot be overridden. Each refusal is a sentence the dialog shows, and it is
audited.

Shared (every connector):

* The target would cut off **DENIS itself** (the `is_self` asset's MAC is behind it), **the gateway**
  (`is_gateway`), or **any switch DENIS polls** (its chassis MAC or an LLDP neighbour that is one of
  the polled switches).
* Undecided identity. The device has an open `arp_conflict` alert, or its MAC is seen on **more than
  one access port** in the fresh data. That is exactly what MAC cloning or a man-in-the-middle looks
  like, and in that case "the port where MAC X is learned" may be the victim's port. The dialog says
  so and tells the user to find the right one by hand.
* More than a set number of blocks in the last hour, across all users (suggested: 10). A human
  clicking through confirmation dialogs never gets close to that. A stolen administrator session
  replaying requests does.
* Another action is already in progress on the same target (one lock per switch).

SNMP `ifAdminStatus` only:

* **A trunk or uplink.** The port has an LLDP neighbour that is a polled switch, or it has more MACs
  behind it than `topology::UPLINK_MACS` (24). These are the same rules `topology::build` already
  uses to decide that a port only says "somewhere further down".
* **Not a physical port.** `ifType` is anything other than `ethernetCsmacd` (6). That excludes VLAN
  interfaces, port-channels (`ieee8023adLag`, 161), loopbacks and the CPU interface. It also means
  the port's own member interfaces are refused whenever `ifStackTable` shows them under a LAG. Note
  that DENIS reads `ifStackTable` nowhere today; see "Groundwork".
* **Nothing to judge by.** The switch gave back no forwarding table at all (the "cheap smart
  switch" case `ui/switches.js` already explains). DENIS cannot tell what is on a port there, so it
  will not guess.
* **The device is not seen there any more.** For a block that started from a *device*, its MAC must
  be learned on that port in the fresh poll. If it has aged out of the table or moved, the answer is
  "DENIS cannot see this device on any port right now".

### 5. Warnings: allowed, but the user has to tick an extra box

* More than one MAC is behind the port. That is common: a desk phone with a PC plugged into it, a
  small unmanaged switch under a desk. The dialog lists every device it can name and counts the
  MACs it cannot. The confirm button stays disabled until the user ticks "I understand this also
  cuts off the devices listed above".
* The port has an LLDP neighbour that is *not* a polled switch, such as an access point or an IP
  phone. Blocking an access point's port cuts off every wireless client behind it, and the dialog
  says that in so many words.
* The port has zero MACs learned (a block that started from the port table on an idle port): "DENIS
  cannot see anything on this port right now."

### 6. Undo is always easy, and always DENIS's own

* A port DENIS disabled can be re-enabled from DENIS by an administrator with one ordinary
  `confirm()`, **without** the password again. Reversing a mistake must be quicker than making one.
  Only turning something *off* needs the password.
* DENIS only re-enables ports **it** disabled, meaning ports in its own ledger (see "Data").
  It never turns on a port that someone shut down in the switch's own configuration.
* Re-enabling still needs the write community and still goes through audit and notification. It is
  allowed while the global kill switch is off. If someone removes a switch's write community, or
  deletes the switch, while DENIS-disabled ports remain on it, they are warned that DENIS will no
  longer be able to undo those blocks, and they must confirm.

### 7. After the SET: read back, never assume

After the SET, DENIS reads `ifAdminStatus` for that index back. The outcome is one of:

* **disabled (verified)**: it reads `down(2)`;
* **not confirmed**: the SET or the read-back got no answer. The port may or may not be down. The
  ledger records this as unknown. The UI says "check the switch" and offers the read-back again as
  a single "Check now" button;
* **refused**: the switch answered with an error, in the plain sentence from `set_int` fix 1.
  Nothing changed, and that is still audited.

### 8. Drift: DENIS notices, and does not fight back

Every regular poll also reads `ifAdminStatus` (see "Groundwork"). If a port the ledger says DENIS
disabled comes back `up(1)`, DENIS records it as **re-enabled outside DENIS**, adds a system entry
to the audit log, sends a notification and closes the ledger entry. It never disables the port
again on its own. Someone may have run `no shutdown` at the switch, or the switch may have
rebooted. Many switches treat an SNMP `ifAdminStatus` change as running-config only, so a reboot
turns the port back on unless someone saves the configuration. That is expected but **not yet
verified**, and it will differ between vendors. The user-facing docs have to say so plainly: a
block by DENIS is not guaranteed to survive the switch restarting.

### Not in the safety model, and why

* **No automatic re-enable timer (quarantine) in the first release.** A time limit is attractive,
  because it bounds the harm of a false positive. But it re-admits a device that really is
  compromised without anyone watching. It also needs a durable scheduler that survives DENIS
  restarts (and DENIS being *down* when the timer runs out). And it needs an answer to "what if the
  switch doesn't answer at re-enable time". The ledger, the health warning (below) and quick manual
  undo cover the false-positive case well enough for the first release. See "Deferred".
* **No cool-down before a port can be disabled again.** With a person, a password and a fresh plan
  on every block, a cool-down would only stop a legitimate second attempt. The hourly cap above
  covers the abusive case.
* **Never triggered by a detection rule, and never by AI.** The "Recommended actions" feature stays
  advisory ("Advisory only — DENIS does not act on any of these itself" in `ui/admin.js`). No AI
  output ever reaches enforcement, not even as a pre-filled suggestion in this first release.

## Credential and configuration model

### `switches::Target`

One new field:

* `write_community: String` (`#[serde(default)]`, so existing saved lists load unchanged). Empty
  means "DENIS may not change this switch", which is today's behaviour for every switch.

It is handled exactly like `community`, and more strictly where that differs:

* It is never returned by the API. `GET /api/switches` adds `has_write_community: bool`, next to
  the existing `has_community`.
* **A blank value on save keeps the stored one**, the same rule as `community`. Because blank means
  "keep", **clearing it needs an explicit flag** (`clear_write_community: true`). Today's
  `Config::update` has no way to *clear* a secret, and this one needs one.
* It follows the same validation as `community` (at most 64 characters, no control characters).
* It never appears in a log, the audit trail, an error message or a support bundle. The
  `switches.update` audit entry gains `port_control: bool` per switch, never the string. The
  existing test `switches_are_added_by_admins_…_without_ever_exposing_the_community` should grow a
  second secret and check that neither ever appears.
* It is **allowed to equal** `community`. Some inexpensive switches have only one community, and it
  can write. Refusing that would only push people to enter it anyway. Instead the API returns
  `write_same_as_read: true`, and the UI warns: "This switch is read with a community that can also
  write. Every regular poll sends it over the network." The docs recommend two communities.
* The write community is used **only** by `nac.rs`, only for the SET and read-back of one
  `ifAdminStatus` OID, and only while an action runs. Polls always use `community`. A code comment
  on `poll_and_store` should say so, and a test should check what the test agent receives: a poll
  never sends the write community.

The recommended switch-side setup goes into docs/switches.md as a checklist, **not yet verified per
vendor**:

* a separate write community, limited by an access list to the DENIS server's address;
* where the switch supports SNMP views, a view that allows writing only `ifAdminStatus`
  (`1.3.6.1.2.1.2.2.1.7`);
* ideally a management VLAN.

SNMPv2c sends the write community unencrypted each time an action runs. That is the same caveat the
page already gives for reading, but it now applies to a credential that can take ports down.
SNMPv3 is deferred (see below). The docs have to say that openly rather than bury it.

### The global `nac` setting

A new settings key, `nac`, stores `{ enabled: bool, max_actions_per_hour: u32 }`. It is edited by
administrators under Settings, on a new "Port control" box placed next to "Switches (SNMP)". Saving
it is audited as `nac.settings`. Later connectors add their own configuration in their own sections
(for example a `radius_coa` section), and they are all governed by this one global switch.

### What the user is told

Every place that makes the old promise changes. The changes are one-line edits, but they are
product copy, so here they are:

* **Settings → Switches intro** (`ui/switches.js` plus the 4 translation files). Replace "DENIS never
  changes anything on a switch." with: "DENIS only reads a switch unless you also give it a *write
  community*. Then an administrator can disable and re-enable single access ports on that switch
  from DENIS, and nothing else. DENIS never does this on its own."
* **Each switch's line** gets a badge: "Read only", or **"Port control"** (in the warning colour)
  when it has a write community *and* the global switch is on. When the switch has a write
  community but the global switch is off, the badge says "Port control (off)".
* **The switch form** gets a second, separate, clearly labelled field under a disclosure: "Allow
  DENIS to disable ports on this switch". Opening it shows the write community field and two
  sentences on what that permits, what it does not permit, and the v2c caveat.
* **docs/switches.md**: "DENIS never sends a SET…" becomes a precise statement. DENIS sends one kind
  of SET, `ifAdminStatus` on one port, only for a switch with a write community, only when an
  administrator asks and confirms. A new section, "Disabling a port", covers the flow, the
  refusals, undo, drift and the reboot caveat.
* **`topology.rs` module comment**: "(read-only, never SET)" becomes "(read-only; the only write to
  a switch anywhere is `nac.rs`'s `ifAdminStatus`, and only with that switch's separate write
  community)".
* **README.md line 13 and docs/index.md line 37** ("does not block anything", "it does not block
  traffic"). These now need a qualifier along the lines of "…it does not block anything on its own;
  an administrator can optionally disable a switch port from it". The wording is Stefan's decision,
  because it is positioning, not engineering. It must change in the same release. A README that
  says DENIS "does not block anything" while it can take ports down would be exactly the kind of
  unverified or false claim these documents exist to prevent.

## Where an action starts, and how it flows

### Entry points (first release)

1. **The Topology page's port table** (`ui/switches.js` `portTable`). A row gets a "Disable…" button
   when all of these hold: the viewer is an administrator, the switch has port control, the global
   switch is on, and the port is not obviously refused (an uplink by the existing rules). Refusal is
   still decided by the server; the UI only hides the button where it is clearly pointless. The row
   of a port DENIS disabled shows "Disabled by DENIS · {who} · {when}" and an "Enable" button.
2. **A device's detail panel**. It already shows "Connected to Switch · Gi1/0/12" through
   `connectedTo()`. The same button appears there: "Disable this device's switch port…". This is
   the entry point that matters in practice: an alert opens the device, the device shows its port.

Both call the same "plan" endpoint with a different *subject*, a port or a device. For a device
subject, the plan re-polls every switch whose last snapshot places that device, not just one, so
the "seen on more than one access port" refusal is checked against fresh data.

**No button on the alert or finding itself in this release.** An alert already leads to its
device. A button on the alert would suggest "this alert justifies a block", which is a link between
detection and enforcement this release deliberately avoids. It can be revisited once real use shows
whether the extra click matters.

### The flow

```
admin clicks "Disable…"
  → POST /api/nac/plan { subject: {port: {switch, ifindex}} | {device: asset_id} }
      server: kill switch on? role/site/auth mode ok? rate cap ok?
              re-poll the switch(es) now → locate target(s) → refusals / warnings / blast radius
      ← { plan_id, expires_at, target: {switch name, port name, alias}, affected: [devices…],
          unknown_macs, warnings: [...], refusals: [...] }
  dialog: shows all of it; refusals → no confirm button, only the reasons
          warnings → extra tick box; password field; reason field (required, 3–200 chars)
  → POST /api/nac/apply { plan_id, password, reason, acknowledged_warnings: bool }
      server: plan exists, is this user's, not expired → confirm_password
              → per-switch lock → GET ifName/ifAdminStatus/ifType → name matches plan?
              → SET ifAdminStatus=2 (write community) → GET read-back
              → ledger row, audit, notification
      ← { outcome: disabled | unconfirmed | refused, message }
```

Re-enable is a single `POST /api/nac/actions/{id}/restore` with no plan and no password. It is
checked against the ledger and does the same SET, read-back, ledger, audit and notification in the
other direction. There is also `POST /api/nac/actions/{id}/check`, the read-back alone, for
"unconfirmed" outcomes.

The dialog is a proper form (`openForm`, like the system restart and shutdown dialogs), not a
browser `confirm()`. It has too much to show, and the password has to be typed into it.

## Auditability

### Audit entries

All of these go through the existing `web_admin::audit`, with `asset_id` set to the targeted device
when there is one. None of them ever carries a community.

| action | when | detail |
|---|---|---|
| `nac.plan.refused` | a plan came back with refusals | subject, switch/port if resolved, the refusal codes |
| `nac.disable` | a SET was sent | connector, switch id/name/address, `ifIndex`, `ifName`, `ifAlias`, affected asset ids and MACs, unknown-MAC count, warnings acknowledged, reason, time of the fresh poll, previous admin status, outcome (`disabled`/`unconfirmed`/`refused` + message), ledger id |
| `nac.disable.denied` | a wrong password, an expired plan, or a port name that no longer matches at confirm time | why, plan target |
| `nac.restore` | a re-enable | the same shape as `nac.disable`, plus how long it was disabled |
| `nac.check` | a manual read-back | ledger id, what it read |
| `nac.drift` | a poll found a DENIS-disabled port up again | ledger id, switch/port; user `system` |
| `nac.settings` | the global setting changed | the new values |
| `switches.update` (existing) | as today, plus `port_control: bool` per switch | never the string |

A wrong password already counts against the lockout. Logging `nac.disable.denied` as well means an
administrator reading the audit log sees it, not only the lockout counter.

### A durable ledger, not just the audit log

The audit log answers "who did what, when". The ledger answers "which ports are cut off right now,
and by whom". Enforcement needs both. The audit log is also subject to retention, and the
authoritative record of a port that is still down must never be pruned by retention. The design
adds a small table, `nac_actions`, behind the `Store` trait like everything else. One row per block:

`id, connector, target (JSON: switch id, ifIndex, ifName), subject asset_id (nullable), state
(disabled | unconfirmed | restored | restored_elsewhere), reason, disabled_by, disabled_at,
restored_by, restored_at, last_checked_at, last_seen_admin_status`

While a row is not in a restored state, retention never deletes it.

### Making it louder than every other audited action

Every other audited action changes DENIS. This one changes the network. So:

* **Every alerting channel is notified**, on every block, every re-enable, every "unconfirmed"
  outcome and every drift. The `nac` module builds a `channels::Notification` itself (kind
  `nac_port_disabled` / `nac_port_enabled` / `nac_port_drift`, severity `high` for a disable), and
  it goes to every *enabled* channel **regardless of that channel's `min_score`** and regardless of
  maintenance windows. Those filters exist to tune how noisy *detections* are, not to hide *actions*.
  It is **not** stored as an `Event`, because it is not a detection. It would distort alert counts,
  risk scores and acknowledge flows, and `Event.asset_id` is not optional, while a port-table block
  may have no known device. The implementer needs one small addition in `channels.rs` to send one
  `Notification` to all enabled channels outside the event cursor.
* **A health warning** (the existing `/api/system` warnings list, so it shows up in the Health
  badge) appears while any ledger row is `disabled` or `unconfirmed`: "{n} switch ports are disabled
  by DENIS", with a link to the list. That keeps a forgotten block from turning into a mystery
  outage months later.
* **A "Disabled by DENIS" list** at the top of the Topology page's physical view, for everyone who
  can see Topology, with Enable buttons for administrators. Viewers see *that* a port is disabled
  and by whom, and cannot act on it.
* The audit page needs no separate view. `nac.` is a prefix the existing browser-side filter already
  handles. The `summarizeAudit` function in `ui/admin.js` should learn the `nac.*` shapes so each
  one reads as a sentence.

## Shape for the other eleven connectors

The shared layer is the part that must not know it is talking SNMP. Pseudocode only:

```
// One per connector: snmp_ifadmin, radius_coa, opnsense, unifi, fortigate, …
trait Enforcer {
    fn kind(&self) -> &'static str;                       // "snmp_ifadmin"
    fn is_configured(&self) -> bool;                      // has its write credential

    // Fresh, never cached: where can this subject be cut off *right now*?
    async fn locate(&self, subject: &Subject) -> Result<Vec<Located>>;

    // What cutting off `target` would also cut off, and connector-specific refusals/warnings.
    async fn assess(&self, target: &Located) -> Result<Assessment>;

    // Cheap re-check right before acting; Err or mismatch = refuse.
    async fn still_same(&self, target: &Located) -> Result<bool>;

    async fn isolate(&self, target: &Located) -> Outcome;  // must read back itself
    async fn restore(&self, target: &Located) -> Outcome;
    async fn current(&self, target: &Located) -> Result<TargetState>;   // for check + drift
}

Subject    = Device { asset_id, macs, ips } | Native(opaque connector key, e.g. switch+ifIndex)
Located    = { connector, key: JSON (opaque to the shared layer), label: "Core · Gi1/0/12" }
Assessment = { affected_assets, unknown_count, refusals: [code+sentence], warnings: [code+sentence],
               persistence: RunningOnly | Persistent | Transient }
Outcome    = Applied | Unconfirmed(why) | Refused(why)
```

**Shared** (one implementation, in `nac.rs`, used by every connector): the kill switch, role,
site, auth-mode and password checks, the rate cap, plans and their expiry, the shared refusals
(DENIS itself, the gateway, infrastructure, uncertain identity), the "warnings need a tick"
rule, the ledger, audit entries, notifications, the health warning, the undo rules, the drift
bookkeeping, and the dialog. The dialog renders `Assessment` generically: a label, a list of
affected devices, the refusals and warnings as sentences, and the persistence note. It has no
SNMP words in it.

**Connector-specific**, and the reason the key is opaque JSON rather than a port number:

* **What a target is.** For SNMP it is a switch plus `ifIndex`. For RADIUS CoA it is a NAS plus a
  session (Calling-Station-Id / Acct-Session-Id): there is no port, and no forwarding-table
  lookup. The session comes from the RADIUS server's accounting data, which DENIS does not have
  today. For pfSense/OPNsense/FortiGate/Palo Alto and the other firewalls it is an IP (or a MAC,
  where the product supports it) in an alias or address group. For UniFi and Meraki it is a
  client MAC.
* **What else gets cut off.** For SNMP, every MAC on the port. For CoA, normally only that session.
  For firewall IP blocks, whoever holds that IP address **next**. A DHCP lease can move, so an IP
  block can end up hitting a different device later. That connector has to say so in its
  assessment, and it probably has to refuse DHCP-assigned addresses or pin the block to a MAC.
  That decision belongs to that connector's release.
* **How long it lasts.** SNMP is probably `RunningOnly` (a reboot undoes it; not yet verified). A
  CoA Disconnect is `Transient`: the device just authenticates again unless the RADIUS policy also
  changes. The CoA release has to decide between Disconnect-Request and a CoA that assigns a
  quarantine VLAN or filter-id. Firewall rules are `Persistent`. The dialog shows this, so nobody
  thinks a disconnect is a ban.
* **Drift.** Each connector decides how to notice its own drift, if it can at all. For SNMP that
  is the regular poll. For firewalls it is checking whether the alias entry is still there.

The first release implements this trait only for SNMP. **Do not build the trait's full generality
before the second connector exists.** Write `nac.rs` so that the SNMP-specific parts sit behind
these seams (one `snmp_ifadmin` module or section), and pull out the real trait when RADIUS CoA
arrives. That is when the second implementation will show which parts of this sketch were wrong.

## Groundwork (read-only, and worth landing first)

This part changes nothing on any network and makes the rest safer. It can ship at the start of the
first connector's release, or just before it. Either way, Stefan can check it against his own
switches before any SET code exists:

* **Poll `ifAdminStatus`** (`1.3.6.1.2.1.2.2.1.7`) and **`ifType`** (`1.3.6.1.2.1.2.2.1.3`) as two
  more columns, and add `admin_up: Option<bool>` and `if_type: Option<u32>` to `topology::Port`
  (`serde(default)`, so stored snapshots still load). The port table can then say "disabled" (admin
  down) as distinct from "down" (no link). That is useful on its own, and it is what drift detection
  and the `ifType` refusal need.
* **Carry `ifIndex` through the forwarding table.** Today `FdbEntry.port` and `Attachment.port` are
  only port *names*, taken from `ifName`, or from the fallback `"port {n}"`. For LLDP attachments
  the name comes from `lldpLocPortDesc` instead, which may not match any `ifName` at all. A SET
  needs the index. Add `ifindex: Option<u32>` to both (`serde(default)`), filled in from the
  bridge-port map at poll time. Where it cannot be worked out, or two ports share a name, the
  answer is "refused: DENIS cannot tell which port this is". It must never guess.
* **Read `ifStackTable`** (`1.3.6.1.2.1.31.1.2.1.3`) only if the LAG-member refusal is built in the
  first release. Otherwise leave it and treat LAG membership as "not yet handled" in the docs.

## What the first release is, and what is deferred

**First release (connector 1, SNMP `ifAdminStatus`):** the groundwork above; the `snmp.rs` fixes;
`write_community` on switches; the global `nac` setting; plan → confirm → read-back for **one port
at a time**, from the port table or a device's panel; manual re-enable; the ledger; the audit
entries; notifications on every channel; the health warning; drift detection; and all the copy
changes. Tests should include, at minimum:

* a full plan/apply/restore run against the test agent;
* a SET with the wrong community, and a SET that gets no reply;
* an `ifIndex` whose name changed between plan and apply;
* every refusal and every warning;
* checks that neither community ever shows up in an API response or the audit log;
* a check that viewers, editors, API tokens and `--insecure-no-auth` are all refused.

**Explicitly deferred**, each with the reason:

* **Automatic enforcement of any kind** (from a rule, a score threshold or AI). That is the category
  jump the roadmap warned about. Revisit only after manual blocking has run on real networks long
  enough to know how often a plan is refused or a block is undone.
* **Automatic re-enable timers (quarantine).** See "Not in the safety model". It is the most likely
  next safety feature, and it needs a durable scheduler and a design for "the switch did not
  answer" first.
* **Quarantine VLAN instead of shutdown** (writing `dot1qPvid` to move the port into a quarantine
  VLAN). It is gentler, since the device can still reach a remediation portal, but it varies far
  more between vendors and needs a quarantine VLAN to exist. Disabling the port is the one
  behaviour that is the same across MIB-II.
* **Blocking several ports at once.** One target per plan. "Disable every port this device's MAC
  appears on" is exactly the uncertain-identity case, and that case is refused.
* **API or token access to enforcement.** Scripts would need a new token role and a confirmation
  story that has no human in it.
* **A button on alerts and findings.** Covered above: the device panel is one click away.
* **SNMPv3** (authPriv). It is the right long-term answer to the cleartext write community, but it
  is a separate project (USM, key localisation, engine discovery). The docs name it as a known
  limit.
* **Switches at remote sites.** Switches are polled by the master today, and the agent model has
  no switch polling of its own. Enforcement follows polling.
* **Users limited to certain sites.** Refused until switches get a site.
* **The generic trait.** It gets built with the second connector, as described above.

## Open questions for Stefan (product, not engineering)

* The README and docs/index.md positioning wording (see "What the user is told").
* Whether port control belongs to a particular license edition. `license.rs` gates other features,
  and this document does not assume either way.
* Whether the hourly cap (suggested 10) and the plan lifetime (suggested 2 minutes) are right for
  his network. Both are settings, so this is a question about defaults.
* What happens for SSO-only and passkey-only administrators, if `confirm_password` cannot serve
  them (see Safety model 2).

## Verification owed before calling connector 1 done

Same bar as ROADMAP.md's "Verification still owed": each item below counts as verified only once it
has been tried on a real switch and written down with the switch's make and model.

* A SET of `ifAdminStatus` to `down(2)` with a write community is accepted, and the read-back sees
  it.
* A SET with the read-only community is refused. Record *how*: an error status, or silence.
* The port comes back after `restore`.
* Whether the switch keeps the block across a reboot, and whether that changes after someone saves
  the configuration.
* The drift path: re-enable the port from the switch's own CLI or web UI, and watch DENIS notice at
  the next poll.
* The self-lockout refusal: try to disable the port DENIS's own server is on, and see it refused.
