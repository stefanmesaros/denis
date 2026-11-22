# Configuration changes (when a switch's configuration changed)

**Experimental** (4.6.0, off until you switch it on for a switch). For a Cisco switch that DENIS already reads over
SNMP, and in part for five firewalls and controllers (below), DENIS can tell you **that** the configuration changed,
**when**, and for a Cisco switch **whether the running configuration was saved**. It does **not** tell you what changed or
who changed it, and it stores no configuration. The Cisco part was tested only against a stand-in switch on 127.0.0.1:
**it has not been run against a real switch yet.** The firewall and controller parts rest on measurements in the
owner's lab (named in each section).

How sure each statement on this page is:

* **documented**: a MIB text or a vendor document says so (named);
* **verified**: read in DENIS's source code, checked by DENIS's own tests on 127.0.0.1, or seen on real equipment (then
  the date and device are named);
* **best guess**: neither; it still has to be checked on real equipment.

## What it does and what it does not do

* **Tier 1: that it changed, not what.** The console says, on every view, "DENIS can tell when the configuration changed,
  not what changed." (verified). Storing configurations and showing a difference between two of them (tier 2) is **not
  built** in 4.6.0.
* **No configuration text, no command, no user name.** Nothing the device sends beyond a few time stamps is stored. The
  Cisco history table, which also names the user of a change, is not read, because a user name is personal data
  (verified: an event holds only raw time-stamp numbers and one flag saying whether DENIS itself changed a port on that
  switch in that time).
* **Read only.** DENIS sends `GET` requests with the switch's read credential, as it does for port health. Nothing is
  written to the switch (verified).
* **Cisco only among switches in 4.6.0.** The time stamps are asked only of a switch DENIS recognises as Cisco. Another make shows "not
  supported" and nothing is claimed (verified). A FortiGate is watched **in part only**, see
  [FortiGate: a partial watch](#fortigate-a-partial-watch); a Palo Alto firewall by its commits, see
  [Palo Alto: commits and changes that wait for one](#palo-alto-commits-and-changes-that-wait-for-one); a MikroTik
  router by its own history, see [MikroTik: the router's history of changes](#mikrotik-the-routers-history-of-changes); a
  UniFi controller **in part**, by what it pushes to its devices, see
  [UniFi: the configuration pushed to a device](#unifi-the-configuration-pushed-to-a-device); an Omada controller by its
  site audit log, see [Omada: the site's audit log](#omada-the-sites-audit-log).
* **No alert, no incident, no action.** A change is a notice (the bell and your channels), never a security alert, and no
  rule, response or Autopilot starts from it (verified). Whether a change was legitimate is for a person to say.
* **Per switch, off by default.** A switch there before the update is "not decided" and is not asked until an
  administrator of the whole installation switches it on (verified).

## How it works

Every reading of a switch with the watch on (the normal schedule, or *Read now*) also asks the switch for four values
of CISCO-CONFIG-MAN-MIB and its own uptime in one request (documented: the MIB names them; that a given Catalyst model
answers them is best guess):

| Value | Meaning (documented) |
|---|---|
| `ccmHistoryRunningLastChanged` (`1.3.6.1.4.1.9.9.43.1.1.1.0`) | the switch's uptime when its running configuration last changed |
| `ccmHistoryRunningLastSaved` (`...43.1.1.2.0`) | when the running configuration was last copied anywhere (not only to start-up) |
| `ccmHistoryStartupLastChanged` (`...43.1.1.3.0`) | when the start-up configuration last changed |
| `sysUpTime` | the uptime at the reading, to turn those into times |

DENIS keeps one row per switch (the newest collection, and the raw numbers it is compared against) and one row per event.
It compares **raw numbers of one boot of the switch** only, never clock times, so a step of the DENIS server's clock or of
the switch's calendar clock can neither make a change nor hide one (verified in the tests).

The events:

| Event | Means | How sure the time is |
|---|---|---|
| `changed` | the running configuration changed since the reading before | the switch's own time stamp, or "seen between two readings" when it gave none |
| `saved` | the start-up configuration was written | the same |
| `restart_unsaved` | the switch restarted while changes were not saved | seen between two readings |

**Saved or not.** DENIS says the running configuration is *saved* when the start-up configuration was written at or after
the last change of the running one. It also counts it as saved when the running configuration last changed within five
minutes of the switch's start (that is the start-up configuration loading at boot; best guess, a constant in the
program). `ccmHistoryRunningLastSaved` is not used for this, because it also moves when the configuration is copied to a
file server (documented in the MIB). If a value needed for this was not read, the answer is *not known*, never "not
saved" (verified).

### What never becomes a change

* **A reading that failed.** A switch that did not answer, or answered only in part, gives a result of its own
  (`failed`, `partial`, `not_supported`, `ok`). A value that was not read is never compared with one that was, so a
  failed reading can never make a "change" and never hides the baseline (verified; a test per rule).
* **The first reading** after you switch the watch on makes no event: there is nothing to compare with (verified).
* **A restart of the switch.** The uptime goes back, so the old numbers mean nothing: DENIS starts a new baseline and
  does not call it a change (verified). From 4.6.1 an uptime shorter than the time since the reading before also counts
  as a restart (the switch started after that reading, even if it has since been up longer than at the baseline; best
  guess from the code, not yet seen on a real switch). The same test is used by the port readings. If changes were not saved at the restart, the event `restart_unsaved` says so,
  and an open "not saved" notice closes without a second message (it never says "saved now": the changes are lost).
  The 497-day wrap of the uptime is not a restart: a new baseline, no `restart_unsaved`, and changes that waited keep
  their time (verified in DENIS's tests).
* **A reading without the uptime.** Without it a restart cannot be ruled out, so nothing is compared and "saved" is
  "not known" in that reading (verified in DENIS's tests).
* **A device that cannot be read** never shows "changed" or "not saved" as a present fact. It shows "not known now" and
  what was last known, with its time (verified).

DENIS can only see that something changed **between two readings**, so several changes between two readings are one
event (best guess; the comparison is of the switch's time stamp, which should move with every change).

## Setting it up

1. Make sure the switch is in the list ([Switches](switches.md)) and that DENIS can read it (the read credential is
   enough; no write credential is needed).
2. Under *Network*, in the switch's row in *Equipment*, there is a "Configuration" line with the switch (as in the
   console); an administrator of the whole installation turns the watch on for one or several switches
   (`PUT /api/switches/config-watch`). Turning it off keeps the history and closes an open "not saved" notice without a
   message (nothing reads the switch any more, so nothing would close it); the same when a switch is removed or paused,
   or a connector's watch is switched off.
3. *Network → Configuration changes* (as in the console) opens with a status line ("Watching 2 of 3 switches and
   1 FortiGate (in part)", what could not be read, what is not saved) and its tab **Changes**: the devices whose
   changes are not saved, then the latest changes, newest first, of all watched devices or of one you choose. Its tab
   **Setup** (`#network/config-changes/setup`) lists every device in three columns: the device and what DENIS reads of
   it, the watch (the tick box of a switch; a firewall, router or controller is switched in its own form; a make that
   does not offer it says "Not supported for this make"), and the state with the last reading and the saved line.
4. On the Setup tab, choose after how many hours of unsaved changes the notice "not saved" opens: 1 to 168, 1 by default
   (`unsaved_after_hours`, `PUT /api/config-watch/settings`).

Who may do what: every signed-in person who may read a switch's site reads the list and the events, and an API token of
the area Network does. Only an administrator of the whole installation switches the watch on or off or changes the
setting (no token, no site administrator); both are audited (`switches.config_watch`, `config_watch.settings`).

## Notices

All in the category *infrastructure*, for editors and administrators (verified):

| Notice | When | Channels |
|---|---|---|
| `config_changed` | the configuration changed | bell and channels, folded (see below) |
| `config_saved` | the start-up configuration was written | bell only |
| `config_unsaved` / `config_unsaved_cleared` | changes have been unsaved for the chosen hours / were saved | bell and channels |
| `config_restart_unsaved` | the switch restarted with unsaved changes | bell and channels, high severity |

A notice says when, and how sure the time is ("the switch's own time stamp" or "seen between two readings"). When DENIS
itself changed a port on that switch in that time (from its own record of actions), the notice says so, so that you can
tell your own action from someone else's. An action DENIS recorded as failed with nothing done on the device does not
count, and the time looked at is never longer than the last 24 hours (verified in DENIS's tests). A notice is raised at
least once, even if DENIS stops between the write and the notice, and a repeat folds into the same row (verified). Only
the active node of a high-availability pair announces.

**Folding** (verified in DENIS's tests). A change folds into the notice of the change before it while they come less
than an hour apart, so a working session is one notice that counts up: each change moves the hour on. One notice never
covers more than a day: a new one starts at midnight UTC at the latest. The reason is that a folded change is not sent to
the channels again: without the limit, a device that changes in most readings would stay one notice for days and only
its first change would ever be sent. A change while DENIS itself acted is a notice of its own, so a person's change made
after one of DENIS's is never folded into it unseen. Saves (`config_saved`) fold the same way.

## Health warnings and states

A watched switch is one of the four states ([What the four states mean](operations.md#what-the-four-states-mean)):
*Degraded* (reason `config_unsaved`) while "not saved" is in force; *Not known* (reason `config_not_read`) when the
reading failed and the last reading that answered (in full or in part) is older than three intervals; *Not known* as "Not
monitored" when the watch is off. Health shows these warnings, each with a stable code:

| Code | Says |
|---|---|
| `config_not_supported` (advice) | The configuration watch is on, but this switch offers no configuration time stamps. |
| `config_partial` | Only part of the time stamps could be read; a value that was not read is never compared. |
| `config_read_failing` | The time stamps could not be read for more than 3 readings; changes made meanwhile are found at the next reading. |

`/metrics` carries `denis_config_events_total{kind}` and `denis_config_unsaved` (the number of watched devices whose "not
saved" is in force; a device removed or no longer watched is not counted) (verified in the code).

## Retention

Events are kept `config_history_days` (30 to 1,825, 400 by default; set under *Data retention* in the
console or through `PUT /api/retention`, see [Operations](operations.md#retention)), and at most 100,000 rows, the oldest going first. Removing a switch from the list
or a connector, or *Erase all data*, deletes its rows. The record holds no secret and no configuration.

## FortiGate: a partial watch

**Experimental**, off until you tick *Tell me when watched parts of its configuration change (Experimental)* in the
FortiGate connector's own form (Network → Equipment, the FortiGate, then Edit). DENIS then says "a change in one of the watched parts of the
configuration", **never** "the configuration changed": it reads a fixed list of parts, and a change anywhere else is not
seen.

**What was measured** (verified on real equipment: the owner's FortiGate 40F, 2026-11-18, with a read-only probe the owner
ran in the lab; the FortiOS version was not recorded with the measurement, the same unit ran 7.2.3 in
earlier tests, best guess that it still does):

* Every `cmdb` table answer of the REST API carries a `revision` token of its own (32 hex characters), and the token
  moves exactly with a change of that table: a policy comment changed the token of `firewall/policy` and not that of
  `system/global`; a host name changed `system/global` and not `firewall/policy`. Two reads without a change gave the
  same tokens.
* A read with a `format=` filter (`?format=policyid|name`) still carries the token, so DENIS asks for the key fields only.
* No single read covers the whole configuration: `monitor/system/ha-checksums` answers nothing on a standalone unit, and
  `monitor/system/config-revision` lists saved revisions and did not move after a policy or a host name change.
* After repeated refused calls (HTTP 403, the source address was not a trusted host) the FortiGate answers HTTP 429.

**How DENIS reads it.** Every 15 minutes, only on the node that may act, DENIS sends one `GET` per watched table with the
connector's own address, API token and TLS setting, with 2 seconds between two reads (verified in DENIS's tests against
a stand-in FortiGate on 127.0.0.1). Nothing is written to the FortiGate. It compares each token with the one of the last
reading and stores only the table names and a short hash of each token, never a token, an object name or any
configuration (verified in the same tests).

The watched parts (16 tables; the first two verified, the others best guess that they behave the same):

| Part | Tables |
|---|---|
| firewall policies | `firewall/policy` (verified) |
| system settings | `system/global` (verified) |
| addresses, address groups and virtual IPs | `firewall/address`, `firewall/addrgrp`, `firewall/vip` |
| services and service groups | `firewall.service/custom`, `firewall.service/group` |
| interfaces and zones | `system/interface`, `system/zone` |
| static routes | `router/static` |
| IPsec VPN tunnels | `vpn.ipsec/phase1-interface`, `vpn.ipsec/phase2-interface` |
| DHCP servers | `system.dhcp/server` |
| local users and user groups | `user/local`, `user/group` |
| administrators | `system/admin` |

**What it means, and its limits:**

* **Not saved does not apply.** FortiOS saves a change as it is made in its default mode (`cfg-save automatic`:
  documented), so the console shows "Saved as it is made" and there is no "not saved" notice.
* **When:** "between" two readings (seen by DENIS), never a time from the FortiGate.
* **Not covered:** everything outside the 16 tables (for example security profiles, SD-WAN, logging, certificates,
  other VDOMs). A change there is not seen.
* **VDOM:** the VDOM the connector names, else the FortiGate's default VDOM (root). Other VDOMs are not read (best guess
  that the global tables answer the same in every VDOM).
* **A table this model does not have** (HTTP 404 or 424) is "not offered" and is never a change.
* **A refused or failed read never becomes a change.** HTTP 401 or 403 stops the reading at once, without a retry.
  HTTP 429 is retried once after 2 seconds, then the reading waits for the next cycle. Whatever was not read keeps its
  last value and is compared the next time it is read, so a change made meanwhile is found then. A reading that read
  nothing is "could not be read"; one that read only some parts is "read in part" (verified in DENIS's tests).
* **The API token** needs read access to every listed table; a table it may not read stops that reading (HTTP 403), so
  the parts after it are read only in part. The administrator table is read last for that reason.
* **The first reading** only notes the tokens; a change is found from the second reading on.
* **DENIS's own changes.** Every block and release DENIS makes through this FortiGate writes to watched tables
  (addresses, address groups, policies, services). When DENIS applied or released an action through this connector
  between the two readings, the event and the notice say "DENIS itself made a change through this connector in that
  time"; the event is still shown, because a person may have changed something in the same minutes (verified in DENIS's
  tests). A reading read only in part keeps the time of the last complete one as the start of "between", so that start
  can lie far back; whether DENIS acted is still looked up in the last 24 hours only.
* **Each reading's time** is the time it began (a reading of 16 tables takes about a minute), so a change made while it
  ran is found by the next one with the right "between" (verified in DENIS's tests). The same holds for every
  connector below.

## Palo Alto: commits and changes that wait for one

**Experimental**, off until you tick *Tell me when a commit happens or changes wait for one (Experimental)* in the Palo
Alto connector's own form (Network → Equipment, the firewall, then Edit). DENIS then says **that a commit happened** and **whether changes wait
for a commit**. It does not say what changed or who committed.

**What was measured** (verified on real equipment: the owner's PA-220 with PAN-OS 10.1.14-h9, single vsys, standalone,
2026-11-18, with a read-only probe and an API key of a role with XML API access to operational requests and
configuration reads):

* The answer of `show system last-commit-info` (`type=op`, about 6 kB) was the same in every read without a commit,
  changed after a commit, and did **not** change with an uncommitted change.
* The answer of `show config list change-summary` was short and fixed (55 bytes) with no change waiting, different
  (95 bytes) while an uncommitted change existed, and back to the first one after the commit.
* `show system info` changes at every read (it holds the uptime): it is not used.

**How DENIS reads it.** Every 15 minutes, only on the node that may act, DENIS sends the two commands as `GET
/api/?type=op&cmd=…` with the connector's address, API key (in the `X-PAN-KEY` header, never in the address) and TLS
setting, 2 seconds apart (verified in DENIS's tests against a stand-in firewall on 127.0.0.1). Nothing is written to the
firewall and no commit is made.

* **A commit** is a change of the first answer since the last reading: event `changed`, "seen between two readings".
  DENIS keeps only a short fingerprint (16 hex characters of a SHA-256) of that answer, never its text. The answer
  names the administrator who committed and the time (best guess: its fields were not read), so DENIS learns only "a
  commit happened between these two readings".
* **Not committed** ("saved" in the switch's words): changes wait when the `<result>` of the second answer is not empty.
  That the empty answer is an empty `<result>` element is a best guess from its measured size; the test ignores white
  space, attribute order and `<result/>`. An answer that could not be read is "not known whether changes wait for a
  commit", never "committed" and never "not committed" (verified in DENIS's tests). When changes have waited for the
  hours you chose (`unsaved_after_hours`, 1 by default), the notice "has changes that are not committed" opens; it
  closes when nothing waits any more (a commit, or the changes were reverted).
* **DENIS's own commits.** A block through the static address group commits. When DENIS applied or released an action
  through this connector between the two readings (its own record of actions), the event and the notice say "DENIS
  itself made a change through this connector in that time". The event is still shown: a person may have committed in
  the same minutes (verified in DENIS's tests). A block through the dynamic group makes no commit.
* **Several commits between two readings** are one event.
* **A refused or failed read never becomes a change.** HTTP 401 or 403, or PAN-OS's own "Invalid Credential" answer,
  stops the reading at once, without a retry; HTTP 429 is retried once after 2 seconds, then the reading waits for the
  next cycle. What was not read keeps its last value (verified in DENIS's tests).
* **The first reading** only notes the fingerprint; a commit is found from the second reading on.

**Open (best guess, not measured):** whether the answer names the administrator (not looked at on purpose); whether the
commit PAN-OS makes by itself after a restart moves the first answer (if it does, a restart shows as one `changed`);
whether a partial commit or a commit pushed by Panorama looks the same (best guess: yes); a high-availability pair (each
firewall is its own connector and reports its own commits); multi-vsys (the commands are device wide, best guess);
other PAN-OS versions and models.

## MikroTik: the router's history of changes

**Experimental**, off until you tick *Tell me when its configuration changes (Experimental)* in the MikroTik connector's
own form (Network → Equipment, the router, then Edit). DENIS then says **that the configuration changed, at least once, between two
readings**. It does not say what changed or who changed it. **RouterOS 7 only**: RouterOS 6 has no REST API (only the
binary API) and is not supported.

**What was measured** (verified on real equipment: the owner's hEX E50UG with RouterOS 7.21.4, 2026-11-18, with a
read-only probe):

* `GET /rest/system/history` (also with `?.proplist=time`) answered the same in every read without a change; each
  configuration change made in a terminal (adding an address-list entry, removing it) added one entry (ids `*6`, `*7`,
  newest first) and changed the answer.
* `GET /rest/system/resource?.proplist=uptime` changes with time (it is read for the running time only).
* The router's log grew with each change too, but it is noisy and kept in memory: not used.

**How DENIS reads it.** Every 15 minutes, only on the node that may act, DENIS sends `GET
/rest/system/history?.proplist=.id,time` and, 2 seconds later, `GET /rest/system/resource?.proplist=uptime`, with the
connector's address, user, password, pinned certificate and TLS setting (verified in DENIS's tests against a stand-in
router on 127.0.0.1). Asking for `.id` and `time` only means the history's commands and user names are never sent to
DENIS (`.proplist` is documented REST syntax; that this version answers `.id,time` like `time` alone is best guess).
Nothing is written to the router.

* **A change** is a new newest entry or a different fingerprint of all the entries' ids: event `changed`, "seen between
  two readings". DENIS keeps the newest id and a 16-character fingerprint, never an entry's text. The entries' times are
  not in the fingerprint: whether RouterOS writes the time of an older entry relative to today (so that its text changes
  at midnight) is not measured, and the ids alone move with every new entry. A fingerprint written by an earlier test build
  is replaced by the first reading without an event (verified in DENIS's tests).
* **The history keeps at most 100 entries** (documented, MikroTik "Configuration Management"). When it is full, a new
  entry pushes the oldest out and the number of entries stays 100. DENIS therefore **never compares the number of
  entries**; it compares the newest id and the fingerprint, which both move (verified in DENIS's tests). Several changes
  between two readings are one event ("at least once").
* **Not saved does not apply.** RouterOS applies and keeps a change at once (documented), so the console shows "Saved as
  it is made" and there is no "not saved" notice.
* **A restart.** When the running time went back, or the start it gives lies more than 2 minutes after the one known,
  DENIS takes a new baseline and does not call it a change, whatever the history says (verified in DENIS's tests). The
  second test uses the DENIS server's clock: a step of that clock forward can look like a restart, which only makes a
  new baseline (a change may be missed, none is invented). The history is compared only in a reading that also read
  the running time.
* **DENIS's own changes.** When DENIS applied or released an action through this connector between the two readings,
  the event and the notice say so; the event is still shown.
* **A refused or failed read never becomes a change.** HTTP 401 or 403 stops the reading at once, without a retry; HTTP
  429 is retried once after 2 seconds, then the reading waits for the next cycle. What was not read keeps its last value
  (verified in DENIS's tests).
* **The first reading** only notes the history; a change is found from the second reading on.

**Open (best guess, not measured):** whether a change made through the REST API (as DENIS's own blocks are) appears in
the history; whether a restart clears the history (handled either way: a restart is a new baseline); whether changes in
safe mode that are rolled back leave an entry; other RouterOS 7 versions and models; whether the user's group needs more
than the `read`, `api` and `rest-api` policies to read the history (the connector's user has more, so it can).

## UniFi: the configuration pushed to a device

**Experimental**, off until you tick *Tell me when the configuration pushed to a device changes (Experimental)* in the
UniFi connector's form (Network → Equipment, the UniFi connector, then Edit). DENIS then says **that the configuration the controller pushed to a
device of the site changed**, and for how many devices. It does not say which device, what changed or who changed it.
This is a **partial** watch: it sees what the controller pushes to its devices, not every setting of the controller.

**What was measured** (verified on real equipment: the owner's UniFi Cloud Gateway Ultra with a nanoHD access point,
2026-11-18, with a read-only probe and a local read-only account (Network: View Only); the Network application version
was not recorded):

* Each row of `GET /proxy/network/api/s/default/stat/device` carries `cfgversion` (16 hex characters). It stayed the
  same in every read without a change (the rest of the answer changes at every read: counters).
* Renaming the access point moved `cfgversion` of **both** devices. Changing the DHCP lease time of the default network
  moved it for **one** device only (the gateway, best guess from the behaviour).
* An update of the controller moved it again (for one device during the update, for both after it): an update is seen
  as a pushed configuration. **A change can therefore also follow an update of the controller or a device.**
* Adding and renaming a client moved nothing: client names are not device configuration.
* Setting the lease time back did **not** bring the earlier value back. The value says "a configuration was pushed
  again", it is not a fingerprint of the settings: DENIS never says "changed back".

**How DENIS reads it.** Every 15 minutes, only on the node that may act, DENIS sends `GET {prefix}/api/s/<site>/stat/device`
with the connector's local account (the same sign-in and session as the connector's actions, so no extra sign-in while
the session lives), address, site and TLS setting, 2 seconds between two connectors (verified in DENIS's tests against a
stand-in console on 127.0.0.1). Of each row it takes only `_id` and `cfgversion`; the rest of the row (names, MAC and IP
addresses, ports, counters) is skipped and never kept. DENIS keeps per device a short fingerprint of its id and one over
that and its version, plus the number of devices (verified in DENIS's tests). It never reads the site settings
(`rest/setting`) or the Wi-Fi networks (`rest/wlanconf`): they hold secrets such as Wi-Fi keys. Nothing is written to the
controller.

* **A change** is a device present in both readings whose version moved: event `changed`, "seen between two readings",
  with the number of devices that changed and the number watched. Several changes between two readings are one event.
* **A device that appears or disappears** (adopted, removed, or its row is gone) is a change of what is on the site, not
  of a configuration: DENIS takes it into its record or lets it go **without** an event (verified in DENIS's tests). A
  change of another device in the same reading is still reported, counting only that device. The Network map shows the
  devices themselves.
* **A device whose row has no version** keeps its last value and is not compared (the reading shows as "read in part");
  a list in which no device gives one, or a connector that signs in with the API key only, shows "not offered": whether
  the Integration API gives the version is not measured.
* **Not saved does not apply.** The controller applies a change at once. The rows also carry `known_cfgversion` and
  `last_config_applied_*`; what they mean is a best guess, so DENIS does not read them and says nothing about "saved".
* **DENIS's own changes.** A port action of DENIS (port profile, disabled port) changes a switch's configuration. When
  DENIS applied or released an action through this connector between the two readings, the event and the notice say
  "DENIS itself made a change through this connector in that time"; the event is still shown.
* **A refused or failed read never becomes a change.** HTTP 401 (a forgotten session: one new sign-in, the session's
  own) or 403 stops the reading; HTTP 429 is retried once after 2 seconds, then the reading waits for the next cycle.
  What was not read keeps its last value (verified in DENIS's tests).
* **The first reading** only notes the versions; a change is found from the second reading on.

**Open (best guess, not measured):** a Wi-Fi, firewall or port profile change (best guess: the controller pushes them
and the version moves); a classic (not UniFi OS) controller; whether the Integration API with an API key gives the
version; other Network application versions; large sites (at most 2,000 devices are read; a longer list is not read).

## Omada: the site's audit log

**Experimental**, off until you tick *Tell me when a change is recorded in this site's audit log (Experimental)* in the
Omada connector's form (Network → Equipment, the Omada connector, then Edit). DENIS then says **that a change was recorded in the controller's
audit log for this site** between two readings. It does not say what changed or who changed it.

**What was measured** (verified on real equipment: the owner's Omada software controller with an ER605 router and an
EAP110 access point, 2026-11-18, with a read-only probe and an Open API app with the Viewer role; the controller version
was not recorded this time):

* `GET /openapi/v1/{omadacId}/sites/{siteId}/audit-logs?page=1&pageSize=1` answered with one row whose fields include
  `time` (milliseconds since 1970). The row also holds what changed, the old and new values, who did it and from where.
* The log was empty before any change. A new newest row appeared after renaming the access point, blocking a client,
  unblocking it, and renaming the access point back.
* A plain web sign-in and sign-out did **not** move the site log. The **global** audit log
  (`/openapi/v1/{omadacId}/audit-logs`) did move on web sign-ins, so it is not a sign of a configuration change and DENIS
  never reads it.
* The site's device list has no configuration version: it is not used.

**How DENIS reads it.** Every 15 minutes, only on the node that may act, DENIS asks the site list (to find the site's id,
as the connector does) and, 2 seconds later, the newest row of the site's audit log, with the connector's Open API app
(`Authorization: AccessToken=…`; the token is shared in memory with the connector's actions), address, Omada ID, site,
pinned certificate and TLS setting (verified in DENIS's tests against a stand-in controller on 127.0.0.1). Of the answer
it takes only the row's `time` and drops the rest unread: what the row says, its old and new values and the person's name
are never stored, logged or shown (verified in DENIS's tests, which plant a value in every other field and look for it in
everything DENIS stores and answers). Nothing is written to the controller.

* **A change** is a newest row later than the one known, or a first row in a log that was empty: event `changed`, "seen
  between two readings". Several rows between two readings are one event.
* **An empty log** is the starting point "no entry yet", not an error.
* **A log that was pruned or cleared.** When the newest time goes back, or the log becomes empty, DENIS takes a new
  starting point and does **not** call it a change (a change may be missed, none is invented; verified in DENIS's
  tests). **How long the controller keeps its audit log was not measured.**
* **DENIS's own blocks and unblocks** are written to the same log (verified). When DENIS applied or released an action
  through this connector between the two readings, the event and the notice say "DENIS itself made a change through
  this connector in that time"; the event is still shown, because a person may have changed something in the same
  minutes.
* **Not saved does not apply.** The controller applies a change at once (best guess), so there is no "not saved".
* **A refused or failed read never becomes a change.** A refused token is renewed once and the read retried once; HTTP
  403 stops the reading at once; HTTP 429 is retried once after 2 seconds, then the reading waits for the next cycle.
  What was not read keeps its last value (verified in DENIS's tests).
* **The first reading** only notes the newest time; a change is found from the second reading on.

**Open (best guess, not measured):** the retention of the audit log; whether the audit log can be switched off on a
controller (then nothing is ever seen); whether every kind of change is logged; whether the Viewer role may read the log
on every controller version (it could here); a cloud-based controller (best guess: the same shape, another address);
other controller versions.

## What is verified, and what is not

Verified (DENIS's own tests, against a stand-in switch on 127.0.0.1): each case of the comparison (a first reading, a
failed or partial reading, a restart, a time stamp going backwards, a change between two readings, clock steps), that
nothing but time-stamp numbers is stored, the notices and their folding, and the roles.

**Not verified:** any real switch. Which Catalyst or other Cisco models and IOS or IOS XE versions answer the three
objects, and with which numbers; whether `ccmHistoryRunningLastChanged` moves for every kind of change (including a
change made by a controller or a script); how a switch stack reports it; and whether the five-minute rule for the
start-up configuration at boot fits real models (best guess). Nothing was run against a real switch.

Not built: storing configurations, showing what changed, naming who changed it, other makes (a FortiGate is watched
in part only, a Palo Alto firewall by its commits, a MikroTik router with RouterOS 7 by its history, a UniFi controller in
part by what it pushes to its devices, an Omada controller by its site audit log, see above; RouterOS 6 is not
supported), and a detection rule "unexpected configuration change".
