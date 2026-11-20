# Operations: backup, demo data, monitoring, upgrades

## Backup and restore

**In the console** (*Health* → Backups, administrators): DENIS backs its own database up **every day** and keeps the
newest 7 (change or switch off the schedule there, keep up to 60). *Back up now* makes one by hand; each backup can be
**downloaded** or deleted. They are written to the `backups` folder beside the database (`/var/lib/denis/backups/`
for the installer's layout), named `denis-auto-…`, `denis-manual-…`; the copies made before an update
(`denis-before-…`) are listed too, but the updater looks after those. Only scheduled backups are ever removed
automatically. DENIS refuses to make a backup when the disk could not hold it, and the Health page warns when the
newest backup is too old. A backup on the same disk does not survive the disk: fetch some copies elsewhere. A backup is written under a temporary name
(`….db.partial`) and gets its real name only once it is complete and the integration secrets are taken out: if it fails
part-way (the disk fills up, say) the unfinished file is removed, and one left by a crash or a power loss is never
listed, never counted as the last scheduled backup, never uploaded to an MSP, and is removed by the backup job at its
next start (with the journal file SQLite may leave beside it). The list never offers a partial copy for restore. A database file that is damaged at start is reported with its path.

**A backup while DENIS keeps recording (SQLite, since 4.5.4).** The copy is read on a database connection of its own,
so capture, detection and the console keep writing while it runs; before 4.5.4 every write waited for the whole copy
(measured at 374 MiB: the longest write 2.7 to 8.5 s). What it costs instead: the database's write-ahead log (the
`denis.db-wal` file beside it) cannot be folded back into the database until the copy has ended, so it grows by what
is written meanwhile and needs that room on the disk; the writes after the copy fold it back in, and the file is
cut back to 32 MiB. The Health page
names a copy that took 10 minutes or more or left a log of 1 GiB or more, and a log that is 1 GiB or more right now.
A scheduled backup that fails (the disk fills up during the copy, say) removes nothing: the older backups are pruned
only after a new one is complete, so the last good backup stays however often the attempt fails.

From the command line:

```bash
denis backup /safe/place/denis-2026-09-21.db      # a verified copy, made while DENIS keeps running
```

* The copy is consistent (a snapshot), is **integrity-checked** before the command reports success, and is readable
  by its owner only. It contains password hashes and notification secrets: store it like a secret.
* The command refuses to overwrite an existing file.
* Schedule it, for example a nightly cron job or systemd timer:

```bash
0 2 * * *  denis backup /backups/denis-$(date +\%F).db --db /var/lib/denis/denis.db && find /backups -name 'denis-*.db' -mtime +14 -delete
```

**With several tenants** ([Multi-tenancy](multi-tenancy.md)): the console backup, `denis backup` and the update
backup each cover one database. The automatic backup before an update (and its automatic rollback) covers **every**
tenant database under `tenants/` as well, kept in `backups/tenants/<id>/`. To back up one tenant by hand use
`denis tenant export <id> --to <file>`. A tenant's database is stamped with its tenant id: restoring one tenant's file
into another tenant's slot is refused at start-up (that tenant answers 503 and the log says why), and importing a file
as a tenant re-stamps it. Secrets sealed under another installation's key are dropped on import and entered again.

**Restore:** stop DENIS (never copy over the database of a running DENIS), delete `denis.db-wal` and `denis.db-shm`
beside the database if they are there (they belong to the database being replaced, and SQLite would apply them to the
restored file), copy the backup over the database file (`denis.db`), start DENIS. A restore brings back the accounts
and tokens as they were when the backup was taken: check the users afterwards. API tokens, agent tokens and invitations that
were revoked after the copy was taken are revoked again at the start (see the revocation journal below).

What a restore cannot bring back, and what DENIS notices (4.5):

* **No sessions.** A backup holds no sign-in sessions (they are left out of the copy), so nobody is signed in by a
  restored file.
* **An older copy is recognised.** DENIS keeps a generation number in the database and in the file `db-generation` of
  the data directory, and moves it on at each start and each time a credential is taken away (an API or agent token
  revoked, a user disabled, demoted or deleted, a password reset or changed, a passkey or authenticator app removed).
  When a start finds the database behind the data directory (an older copy was put back), every session ends, the log
  says so with an error, the audit log has `store.restore_detected`, and the setting `store.restored_from_older_copy`
  records when; the Health page shows it for 30 days. Review then what the copy brought back: deleted users and removed passkeys or authenticator apps are back, used recovery codes work again. Revoke or
  remove them once more. A restore onto a fresh data directory (no `db-generation` file) is not recognised. A
  PostgreSQL dump made by DENIS leaves the sessions out too (the table is there, empty).
* **Revoked tokens and invitations stay revoked (4.5.2).** Every revocation of an API token, an agent token (also the one
  taken away by a rotation or a retried enrolment) or an invitation (revoked, claimed, all its uses taken) is also appended to
  `revoked.journal` in the data directory, **outside the database and so outside every backup**. It holds one line per
  revocation: the kind, the SHA-256 that the token table already keeps (or of the invitation id), the time and a closing
  `ok`; never a token. A line is read only when it is complete (all fields, the `ok`, the newline): a line cut off by a
  crash or a full disk is ignored. The line is written **before** the revocation is committed in the database, so a crash
  can leave a line without a revocation (harmless) but not a revocation without its line; if the journal cannot be written
  the revocation still goes through and the Health page says so.
  The file is private (mode 600), only appended to, and kept to the newest 10,000 revocations. Appending and the rewrite
  take a lock file (`revoked.journal.lock`) beside it, so the console and a command-line tool can run at once. At every
  start DENIS opens it only if it is a regular file of the DENIS user (or root) that nobody else can read or write (never
  through a link), reads it and revokes again whatever the database has open; the log says so with an error and the audit
  log has `tokens.revocations_reapplied` with the counts. A token that the database refused to revoke again is **refused**
  until a later start manages it, and Health and the audit log (`tokens.revocation_replay_incomplete`) say so; a journal that
  cannot be read or is invalid is shown in Health and the audit log the same way (the credentials it would have named are not
  known then: review the tokens). `denis serve` and `denis demo`, which open a copy for viewing, replay the journal too. So a
  token revoked after the backup is revoked again after you restore the backup. What it does **not** cover: a restore onto a
  data directory without the journal (a fresh machine; copy `revoked.journal` along with `secrets.key` if you move the data
  directory), revocations older than the newest 10,000, tokens whose validity was only shortened by a rotation, a multi-use
  enrolment code that was used some but not all of its times, and (in 4.5.2) the line of an invitation that is closed, which
  is written just after the invitation is saved. Deleted users, passkeys, authenticator apps and recovery codes are not in the
  journal either (see above).
  The journal is written by the console and by the command-line tools that revoke something (`denis agent-token`,
  `denis user`, `denis msp ...`; they find the data directory from `--data-dir` or the folder of `--db`; a process that
  does not know it says so once in the log), and it is applied to every tenant's database when that tenant is opened, not
  only to the default one. **On a PostgreSQL pair each node has its own `revoked.journal`**: a revocation made through
  node A is in A's file only, and a database restore followed by a start on B would not know it. Before you restore
  a PostgreSQL dump, merge the two files into both nodes. In a folder holding `a/revoked.journal` and `b/revoked.journal`
  (copies of the two nodes' files), run
  `cat a/revoked.journal b/revoked.journal | sort -k4,4nr | awk '!seen[$2 " " $3]++' | sort -k4,4n > merged`
  (newest time per revocation kept, oldest first), copy `merged` over `revoked.journal` on each node and set mode 600.
  DENIS does not do this by itself: any copy kept in the
  database would be rolled back by the very restore it is meant to survive. A line cut off by a full disk or a crash is
  closed with a newline before the next one is written (and stays ignored), a byte that is not text costs only its own line,
  and a journal that cannot be read is logged as an error at start.
  **What the journal guarantees, and what an operator sees (4.5.3).**
  * *Journal first, on purpose.* The line is written before the revocation commits. If the commit then fails (or the
    process dies between the two), the line stays valid, and the next start revokes that token, although the revocation
    never committed. This is the fail-closed choice: a revocation is never lost to a restore. You can see it: the token
    keeps working until that start, and the start's audit entry `tokens.revocations_reapplied` has
    `restore_detected: false` (it says `true` only when the start also recognised an older database copy). If you re-issued
    a token and the replacement was never delivered, repeat the re-issue after such a start.
  * *A revocation that could not be journaled* (full disk, wrong permissions, or another process holding the lock for
    more than 5 seconds) is still made, because a stolen token must always be revocable. It is never silent: the log has
    an error, the Health page warns until DENIS restarts, the audit entry of the token-revoking console call has
    `journaled: false`, and the answer carries the header `X-Denis-Journal: not-written`. That token is NOT protected
    against a restore until it is revoked once more with a writable journal.
  * *The lock is bounded.* `revoked.journal.lock` is opened without following a link (it must be a regular file of the
    DENIS user, mode 600, one name; anything else is refused with an error, never waited on) and is waited for at most 5
    seconds on every platform (`flock` on Unix, `LockFileEx` on Windows). A stopped or stuck process that holds it delays a
    revocation by those seconds at most; start-up never waits for it, because the replay only reads the journal and a
    line that is in the journal already is not written again.
  * *Repeating the replay is safe.* Starting twice changes nothing the second time: no second audit entry, no second
    journal line.
  * *Compaction* keeps the newest 10,000 distinct revocations **by time** (the later line wins a tie) and writes them oldest
    first, then flushes the folder; a journal merged from two nodes in any order keeps the right lines.
  * *A replay that cannot prove it was complete* is shown, never taken for clean: Health and the audit entry
    `tokens.revocation_replay_incomplete` say so when the journal cannot be read, when a credential could not be revoked
    again (it is refused until it can, per store; the bootstrap token of an invitation included), or when the invitation
    records could not be read completely (`invitations_unverified`). **What to do then:** fix the cause the log names (the
    file's owner and mode, the database), restart DENIS, and check that the warning is gone. While it is not gone, treat
    every token and enrolment/link code as possibly open after a restore: revoke and re-issue the API and agent tokens
    you rely on, and delete the open enrolment and link codes (Sites, Add agent) you do not recognise. If the journal is
    lost for good, there is nothing to replay: review the tokens by hand.
* **The secret key.** `secrets.key` is not in the database backups. When it is missing at start and the database holds
  values sealed with a key (integration credentials, authenticator-app secrets, the data key), DENIS refuses to start
  and says so, instead of making a new key that could open none of them (4.5; before, a new key was made silently).
  Put the installation's `secrets.key` back into the data directory (mode 0600) and start again. A database with nothing
  sealed still gets a new key at its first start, as before. Test a restore once
before you need it: `denis serve --db /backups/denis-2026-09-21.db` opens a backup in a console **without
capturing anything**, so you can check it safely (see below).

## Looking at a database without capturing: `denis serve`

```bash
denis serve --db copy.db --listen 127.0.0.1:8080
```

A console over an existing database with **no capture, no probing and no detection**: for checking a backup, for
reviewing data on another machine, for training and for demonstrations. Reading and editing the register works;
live discovery does not.

## Demo data, and starting clean (erase all data)

**Settings → Data → Demo data and reset** (administrators) has three buttons:

* **Load demo data**: a fictional company so you can explore every screen. Marked as demo; ignored by the
  collector and the detectors; a banner says it is loaded. (API: `POST /api/demo`; command line: `denis demo load`.)
* **Remove demo data**: deletes only the demo records. (`DELETE /api/demo`; `denis demo remove`.)

  Loading the demo on a console that already holds real data is safe, and removing it takes only what it added:

  * **Switches**: the three demo switches are added only when the switch list is empty. A console with switches keeps
    its list, its SNMP communities and its topology exactly as they were (it then has no demo switch topology). Removal
    takes out exactly the three demo switches and their topology; a switch added meanwhile stays.
  * **Posture history**: the demo's sixty days of history are written only for days that have no sample yet; a day
    with a real sample keeps it (only the demo sites' own rows are added). While the demo is loaded, the daily sample
    counts the demo devices only in the demo sites' rows; the "every site" row counts the real devices (on a console
    with nothing but the demo it counts the demo). Removal takes the demo's rows only, also those of the days the demo
    was loaded.
  * **Reports and the compliance overview**: demo devices, their sites and alerts are left out when real devices are
    present. On a console with nothing but the demo, a report shows the demo, says "Demo data." at the top, and its
    title ends with "(demo data)".
  * The demo's two sites are not counted by the Health page's "Agent reports" line.

  If a removal stops part-way (a database error), the demo still shows as loaded; press **Remove demo data** again
  to finish: every step takes only what is still there.
* **Erase all data**: for when you have finished exploring, or are moving from a trial to the real network. It deletes
  **every device, edit, alert, baseline, communications record, trend sample and remote site**, forgets what was
  learned (including the known DHCP, DHCPv6 and router-advertisement servers, sweepers, address pairs and the rules' own
  learning clocks), and starts a **new learning period**. It keeps user accounts and sign-in methods (passkeys, API tokens),
  notification channels, branding, rule settings, agent tokens and the **audit log** (which records that the erase
  happened and who did it). You must type `ERASE ALL DATA` to confirm. **It cannot be undone: take a backup first.**
  (`POST /api/data/erase` with `{"confirm": "ERASE ALL DATA"}`; with DENIS stopped, `denis erase --yes`, which also
  forgets what was learned.)

## Retention

*Settings → Data → Data retention* (administrators) sets how long events, alerts and trend samples are kept
(1 to 1095 days) before DENIS deletes them on its own, within the hour, no restart. Until a value is saved there
the `--retention-days` flag (default 90) applies. The asset register, baselines, accepted risks, saved reports
and the audit log are not affected by retention. The same page sets how long the **decision log** is kept (who
acknowledged, resolved or re-opened which alert or incident, when and why): 1095 days (3 years) by default, 90 to 3650
days, or 0 to keep it for ever. It is independent of the period above, so a decision can still be read after its alert
has been deleted. Nothing else removes decision-log rows: not deleting or merging a device, not *Erase all data*
(the rows hold no personal data beyond the user name and the note a person typed).

An alert that belongs to an incident nobody has resolved yet, and that incident, are kept up to a year beyond the
period, so a slow investigation does not lose its evidence; after that year they go like everything else. This holds on
SQLite and, from 4.5, on PostgreSQL too (before, PostgreSQL deleted them at the period). Each hourly prune is its own
step: one that fails (for example a statement timeout on a large first prune on PostgreSQL) is written to the log as
"pruning ... failed" and the others still run; it is tried again the next hour. On PostgreSQL the deletes run in chunks
of 2,000 rows, as on SQLite.

The ledger of received agent reports (4.5.4) keeps its own 7 days, whatever the period above is set to; per site at
most 2,000 rows of reports that were applied whole and at most 20,000 of the others (since 4.6.0: the applied rows no
longer push the gaps out) ([Gaps in what a remote site reported](#gaps-in-what-a-remote-site-reported)).

The port health history of the switches (4.6.0: the traffic and error samples of each port and the record of each
reading of a switch) has its own period: 8 days by default, 1 to 30, pruned every hour in chunks. It is set
under *Data retention* in the console or through `port_history_days` of `PUT /api/retention`. A value saved by hand outside 1 to 30 reads as 8. A settings row that cannot
be read prunes nothing that hour. The open conditions (a watched link that is down) are never pruned by age. With 50
switches of 48 ports read every 5 minutes, 8 days are about 200 to 400 MB (best guess, not measured yet); see
[Switches](switches.md#history-and-its-size).

Four more periods belong to the health features of 4.6.0. Each is a key of the stored retention setting, has its own
bounds and default, and is read on its own: a value that is out of range reads as that key's default and never makes
another fall back. The defaults are a best guess, not measured. A settings row that cannot be read prunes nothing in
that cycle. **All five can be set under *Data retention* in the console and through `PUT /api/retention` (administrators); a save keeps the keys it was not given.**

| Key | What it keeps | Range | Default |
|---|---|---|---|
| `port_history_days` | raw traffic and error samples of the switch ports | 1 to 30 days | 8 |
| `port_rollup_days` | the hourly figures of ports and switches (long history, up to a year) | 30 to 400 days | 90 |
| `check_history_days` | the raw runs of [service checks](service-checks.md) | 1 to 30 days | 8 |
| `check_rollup_days` | the hourly figures of service checks | 30 to 800 days | 400 |
| `config_history_days` | the events of [configuration changes](config-changes.md) | 30 to 1,825 days | 400 |

Raw samples of ports are deleted only for hours that were already rolled up (see [Switches](switches.md#history-and-its-size)).
The hourly port tables are capped at 5,000,000 rows and the configuration events at 100,000 rows, the oldest going
first.

Kept without a time limit (documented, not pruned by any period): the audit log, the results of connection tests run
by hand, the record of merged devices (it maps a merged device's old id to the one it became), the history of
segmentation changes, and revoked API tokens, agent tokens and push subscriptions. They grow with what people do, not
with traffic.

## The RADIUS accounting receiver (4.6.0, experimental)

DENIS's only inbound UDP port; off by default. What it accepts and why it is safe to leave off is in
[Security](security.md#the-radius-accounting-receiver-460-experimental). How to set it up, on DENIS and on the equipment, is in
[RADIUS accounting](radius-accounting.md).

* **Switching it on.** An administrator lists the sources (one IP address and one shared secret of at least 16
  characters each, at most 64 sources), chooses the listen address (for example this machine's address and port
  1813) and switches the receiver on; that asks for the password again and is audited. At once (well under a second) the
  service log says `RADIUS accounting: receiving on udp <address> from <n> source(s)`. Then point the equipment at
  that address as one more accounting server. Your firewall must let UDP from the listed sources reach that port.
* **When it cannot open the address** (in use, not an address of this machine, `0.0.0.0` without the explicit choice),
  the log says `RADIUS accounting: cannot listen on udp ...` once with the reason; DENIS runs on and tries again every
  few seconds.
* **Changing a source or a secret** takes effect at once (well under a second): the receiver stops receiving, stores
  and answers the records it has already received (for at most two seconds), and opens its port again with the new
  list. Records sent during that restart are sent again by the equipment.
* **Switching it off** needs no password; the port is closed at once (well under a second), after the records already
  received are stored and answered. Sessions already recorded stay,
  go stale when nothing is heard and end by themselves after seven days of silence.
* **Retention.** Ended sessions are kept for `history_days` (30 by default, 1 to 365) of the receiver's own settings,
  and beyond 200,000 rows the oldest ended ones go first; open sessions are never pruned. The hourly retention pass does
  this (at most 10,000 rows a pass); a settings row that cannot be read deletes nothing that hour.
* **After a restore** the shared secrets are not in the backup: enter each one again, or that source's records are not
  read (they are dropped and counted).
* **High availability:** only the node that leads runs jobs, so only it listens (best guess that nothing more is needed:
  the equipment must send to the address that follows the leader; not tested on a pair).
* **4.6.0: the main installation only.**

## Monitoring DENIS itself (Prometheus)

`GET /metrics` exposes counts and health in the Prometheus text format: devices (total, online, by type), open
alerts by severity, findings by severity, learning time left, remote sites and how long ago each reported,
failing exports and notification channels, maintenance mode, uptime. It contains **no device names, addresses or
alert text**.

It needs the same sign-in as the console. The counts are of every site, so only someone who may read every site gets
them: a person held off a site, or a token made by one, gets `403`. For Prometheus, create a **viewer API token**
(*Users* → API tokens) as an account that reads every site and give it as a bearer token:

```yaml
scrape_configs:
  - job_name: denis
    scheme: https
    authorization:
      credentials: dnt_…            # the token, ideally from a file: credentials_file
    static_configs:
      - targets: ["denis.example.com"]
```

Useful alerts: `denis_channel_failing == 1` (a notification channel is broken), `denis_export_failing == 1`,
`denis_site_last_report_age_seconds > 900` (a remote site went quiet), `denis_alerts_unacknowledged{severity="high"} > 0`,
`denis_health_warnings > 0` (the Health page has something to say), `denis_backup_age_seconds > 172800` (no backup for two days),
`denis_capture_dropped_packets` rising (the capture cannot keep up). Also exposed: `denis_database_bytes`, `denis_disk_free_bytes`.

Gauges and counters for the conditions in the next section: `denis_capture_parser_panics`,
`denis_panics_caught_total{stage="capture_parse|capture_thread|flow_detection|new_asset_detection|detector_tick|agent_ingest"}`
(every panic DENIS caught and survived; anything above 0 is a bug to report), `denis_signal_buffer_saturated`,
`denis_clock_skewed_agents`, `denis_snmp_incomplete_switches`, `denis_notifications_dropped`, and, for the
industrial layer-2 decoders, `denis_ot_sv_sampled_out_total` (Sampled Values frames skipped by the one-per-second
sampling) and `denis_ot_l2_appid_refused_total` (control blocks refused because a device already has the most it keeps),
and for IP fragments of industrial traffic `denis_ot_fragments_reassembled_total`,
`denis_ot_fragments_dropped_total{reason="timeout|limit|overlap|oversize|tiny|malformed"}`,
`denis_ot_fragments_duplicate_total` and `denis_ot_checksum_mismatch_total{reassembled="false|true"}` (industrial
messages with a wrong TCP/UDP checksum, still decoded; see the OT guide's limits).

For the switches DENIS reads (4.6.0, port health): `denis_switch_read_fail_streak{switch="<id>"}`, failed attempts in a
row to read a switch from this server (it says this server got no answer, not that the switch is down; one sample per
switch in the list), and `denis_switch_read_lag_seconds{switch="<id>"}`, how late the newest scheduled reading of a
switch started after it was due (no sample for a switch without a scheduled reading yet). The label is the switch's id,
never its address or community. Useful alerts: `denis_switch_read_fail_streak >= 3` (the point at which "cannot be read"
opens), `denis_switch_read_lag_seconds > 600` (with the default interval of 5 minutes: more than two intervals late, as
the Health warning). See [Reading switches](#reading-switches-port-health-460).

For service checks (4.6.0): `denis_checks_runs_total{outcome}` (runs since start by outcome: `ok`, `slow`, `wrong_answer`,
`warning`, `no_answer`, `not_run`), `denis_checks_state{state}` (how many checks are in each of the four states, no
sample per check), `denis_checks_skipped_total` (runs that waited because too many were in flight) and
`denis_checks_last_pass_seconds` (seconds since the job last finished a pass; no sample before the first one; a value
that keeps growing means the job has stopped). For configuration changes: `denis_config_events_total{kind}` (`changed`,
`saved`, `restart_unsaved`) and `denis_config_unsaved` (switches whose changes are not saved). Names and addresses are
never labels.

Per capture interface (label `iface`): `denis_capture_dropped_packets_by_iface` (dropped between the kernel and
DENIS) and `denis_capture_if_dropped_packets` (dropped by the network card or its driver before the capture saw
them; the unlabelled `denis_capture_dropped_packets` stays as the total), `denis_capture_unparsed_frames_total`
(IPv4, ARP or IPv6 frames whose header could not be read), `denis_capture_truncated_frames_total` (frames cut short
by the capture) and `denis_capture_oversize_frames_total` (frames longer than the network carries: the card merges
packets, see [Deployment, receive offload](deployment.md#receive-offload-grolro-on-the-capture-interface)), and,
while IPv6 is switched off, `denis_capture_ipv6_while_off_packets` (IPv6 packets in the last 10-second sample).
`denis_ot_unclassified_segments_total` counts TCP segments on an industrial port that no decoder recognised.

Duplicate packets per capture source (label `source`, the interface name; 4.3): a SPAN session that mirrors both
directions of two ports hands DENIS each packet between them twice. DENIS counts such copies and removes none
(Settings → Capture → Duplicate packets, on by default, applied at once). `denis_capture_dedup_checked_total`
(IPv4, IPv6 and layer-2 industrial frames looked at), `denis_capture_duplicates_total` (copies of an ordinary
packet within the window, 2 ms by default), `denis_capture_ot_duplicates_total` (copies of an industrial frame:
GOOSE, Sampled Values, PROFINET or an industrial port, counted apart and never to be removed) and
`denis_capture_dedup_evicted_total` (entries the fixed table of 65,536 per source gave up while still inside the
window); `denis_capture_dedup_observing` is 1 while counting. A copy is the same IP packet (TTL or hop limit,
DSCP/ECN, the header checksum and the VLAN tag may differ: the same packet seen on both sides of a router), with the
same L4 header and first 64 payload bytes. A TCP retransmission usually comes hundreds of milliseconds later and is
not a copy. With removal on, packets whose bytes cannot prove they are copies are counted but never removed: every
IPv6 packet, IPv4 with packet ID 0, TCP segments without payload and IP fragments. Health warns (`W_DUPLICATES`) when more than 5 % of the packets an interface received in the last minute were
copies, unless the interface removes them. Since 4.3.0 an administrator can switch removal on per interface
(`denis_capture_dedup_removed_total`: frames removed before parsing, never an industrial one) and merge copies across
the capture interfaces of one DENIS (`denis_capture_dedup_merged_total` and, per pair, `denis_capture_dedup_merged_pair_total{source,kept}`);
see [Duplicate packets from a mirror](deployment.md#duplicate-packets-from-a-mirror). A safety valve switches removal
back to counting (`W_DEDUP_AUTO_OFF`, audited `capture.dedup.auto_off`). The cost is measured by
`cargo run --release --example capture_dedup_bench`.

### When the database cannot keep up

DENIS writes what it has learned about devices to the database every two seconds. That write runs on its own
thread, so a slow disk or database does not stop DENIS reading packets: observations keep being taken in, and
the devices that changed are written on the next round (several changes to one device become one write). If the
write is still running when the next round is due, that round is skipped and counted. Only when the queue between
the capture and the rest of DENIS fills up does the capture have to wait, and then the network card may drop
packets.

These counters make that visible, separately from the packets the kernel drops (`denis_capture_dropped_packets`):

| Metric | Meaning |
|---|---|
| `denis_observation_queue_full_total` | Times the capture had to wait because the queue to the rest of DENIS was full. Rising: the database or disk is too slow for the traffic. |
| `denis_flow_windows_dropped_total` | Ten-second traffic windows thrown away because the part that stores traffic was behind. Each one is missing from the traffic views. |
| `denis_flow_detection_windows_total`, `denis_flow_detection_seconds_last`, `denis_flow_detection_seconds_max`, `denis_flow_detection_seconds_sum` | Traffic windows checked by the detection rules, and how long the last, the slowest and all of them took. Detection runs on its own thread, so a slow check delays alerts but never stops the capture. |
| `denis_flow_window_lag_seconds`, `denis_flow_window_queue_depth` | How late the last traffic window was checked (seconds after it closed) and how many windows were waiting. A lag that keeps growing means detection is slower than the traffic; at 256 waiting windows further ones are dropped. |
| `denis_ot_conversations_dropped_total`, `denis_ot_control_conversations_dropped_total` | Industrial messages not counted because a ten-second window's conversation table was full, and how many of those were control commands (kept first, so normally zero). The Health page warns while the first is above zero. |
| `denis_ot_stream_carried_total`, `_completed_total`, `_gaps_total`, `_oversize_total`, `_duplicates_total`, `_capped_total`, `_evicted_total` | What the industrial-protocol message tracking did: incomplete messages held for the next TCP segment and completed, continuations lost to missing or out-of-order packets, messages too long to be read, exact duplicate segments ignored, segments with more messages than are read, and connection states forgotten because too many were open. Health warns on any capped or evicted, and on a thousand gaps or over-long messages. |
| `denis_db_flush_total`, `denis_db_flush_failures_total`, `denis_db_flush_overruns_total` | Device writes done, failed (their rows are kept and retried), and rounds skipped because the previous write was still running. |
| `denis_db_flush_seconds_last`, `denis_db_flush_seconds_max`, `denis_db_flush_seconds_sum` | How long the last, the slowest and all device writes took. A write regularly near two seconds is the sign to look at the disk. |
| `denis_inventory_flush_snapshot_seconds_last`, `denis_inventory_flush_snapshot_seconds_max` | How long DENIS held the device list locked to copy the changed devices for a write (the last and the longest since start). While it holds it, no observations are taken off the queue; a copy regularly over a few tens of milliseconds on a busy mirror is worth reporting. |
| `denis_capture_busy_ratio{iface}` | The share of time each capture interface's worker spends on packets rather than waiting for the next one (0 to 1, estimated from one packet in 1,024; 0 after a quiet half second). Near 1 the worker cannot keep up with the interface and the kernel drops packets: compare with `denis_capture_dropped_packets_by_iface`. |

### What each detection rule costs

Every detection rule is measured, per run: one ten-second traffic window of one capture interface, one write of
the device list (every two seconds) or one report from an agent. The measurement is two clock readings per rule and
run (per device for the traffic rules), never per packet, and it is kept in plain counters; the capture threads do
not take part. The Health page shows it under **Detection rules** (time per run, the longest of the last five
minutes, the budget, the last alert and the state of each rule), and `/metrics` exports it with the label `rule`:

| Metric | Meaning |
|---|---|
| `denis_rule_evaluations_total{rule}` | Runs in which the rule was checked. |
| `denis_rule_records_total{rule}` | Records it examined (traffic, DNS, industrial or east-west records, signals, devices). |
| `denis_rule_eval_seconds_total{rule}` | The time it took, in total. |
| `denis_rule_window_seconds_last{rule}`, `denis_rule_window_seconds_max{rule}` | The time of its last run, and the longest run of the last five minutes. |
| `denis_rule_budget_seconds{rule}` | Its budget per run (see below). |
| `denis_rule_errors_total{rule}` | Failures caught in the rule's code. Its result for that data is lost; the other rules run on. |
| `denis_rule_skipped_total{rule}` | Runs in which it was skipped because it is paused. |
| `denis_rule_budget_trips_total{rule}` | Times it was paused, or warned about, for being too slow. |
| `denis_rule_paused{rule}` | 1 while it is paused (only for the rules that can be paused). |
| `denis_rule_alerts_total{rule}` | Alerts it raised since start (every rule, the periodic ones too). |
| `denis_detection_breaker_enabled` | 1 while a built-in IT rule that is too slow may be paused (setting for built-in IT rules `pause_rule`). |
| `denis_detection_breaker_own_enabled` | 1 while a rule of your own (IT) may be paused (setting for your own rules `pause_rule`). |
| `denis_detection_breaker_industrial_enabled` | 1 while an industrial rule that is not safety-critical may be paused (setting for industrial rules `pause_rule`). |

Some rules share one piece of code, which is then measured once, under the name of that shared part:
`flow_baselines` (new destination, new destination over IPv6, new port, volume, unusual hours, industrial protocol
to the internet), `passive_dns` (DNS resolver changed), `ot_conversations` (all industrial conversation rules, your
own OT rules included), `link_signals` (ARP, NDP, DHCP and router advertisement rules, host sweeps), `identity`
(fingerprint changed, GOOSE conflict) and `new_device` (new devices and the burst rule). The rules that run on a
schedule (device silent, agent offline, the switch rules) are counted when they raise an alert but are not timed.

**Budgets.** Each rule has a budget per run, set by its cost class in one table (`src/detect/meter.rs`,
`RULE_TABLE`), with the numbers of the performance analysis:

| Cost class | Budget per run | Used by |
|---|---|---|
| cheap | 1 ms | new rules with a fixed amount of work per record |
| moderate | 5 ms | new rules that keep state over time |
| customer | 50 ms | all of your own IT rules together (`it_watch`), all of your own OT rules together |
| built-in | 250 ms | the rules of DENIS 4.2 and earlier, and the shared parts above |

### When a rule is paused or detection is overloaded

A rule **trips** when a single run takes more than **4 times** its budget in **3 of its last 6 runs** (runs in
which it was not checked do not count). One slow run, after a burst of traffic for example, never trips it.

**What happens then is your choice** (Rules page, the **Performance protection** box at the top; administrators change
it and it is audited, everyone else reads it; Health, Detection rules, links to it with **Change protection
settings** and has no second copy of the controls). There are three settings, one per kind of rule, each with a plain
explanation and an (i) note:

| Row on the Rules page | Setting | Choices | Default |
|---|---|---|---|
| **Built-in IT rules** (the rules DENIS ships) | `detection.overload_policy` | **Pause the rule that overloads detection (recommended: protects packet capture)** (`pause_rule`), or **Keep every rule running and accept that packets may be dropped** (`accept_drops`) | `pause_rule` |
| **Your own IT rules** (the network rules you defined, `it_watch`) | `detection.overload_policy_own` | the same two choices | `pause_rule`, and until it is saved it follows the built-in setting |
| **Industrial (OT) rules** (advanced: every `ot_*` rule, the ones you defined yourself, `ot_command_watch`, too) | `detection.overload_policy_ot` | **Never pause an industrial rule, only warn** (`warn_only`), or **Pause an industrial rule that is not safety-critical** (`pause_rule`, with a strong warning and a question first) | `warn_only` |

Why pause: a rule that is much slower than its budget makes all detection late; when detection falls far enough
behind, traffic windows are dropped and the capture has to wait, so the kernel drops packets. Pausing the one slow
rule keeps the capture whole. Why keep it running: a paused rule finds nothing, and some sites would rather lose
packets than a rule. **A paused industrial rule stops protecting your industrial network**: that is why industrial
rules are only warned about unless you opt in, and the console asks again when you do.

**The pause scope.** Whatever the settings say, these rules are **never paused**, only warned about:

* every rule that is never quiet (`quiet::NEVER_QUIET`): threat list, rogue DHCP and router advertisements, DHCP
  options, DHCP starvation, DNS resolver changes, sweeps and fan-out, segmentation, new device on a watched port,
  fingerprint changes, listed names (`dns_threat_domain`), names, web addresses and addresses of the lists you added (`threat_list_domain`, `threat_list_url`, `threat_list_address`, 4.5), an exposed service followed by a fetch
  (`inbound_then_fetch`), and the industrial command, write, unexpected writer, your own OT rules and GOOSE conflicts;
* the safety-critical rules (`NEVER_PAUSED` in `src/detect/meter.rs`): `ot_program_upload`, `ot_concurrent_masters`,
  `ot_identity_changed`, `dns_threat_domain`, `inbound_then_fetch` and `lifecycle_device_seen`;
* the rules such a rule is built from (`FEEDS` in `src/detect/meter.rs`): pausing one would starve it while Health
  still showed it running. Today that keeps `inbound_bruteforce` and `anonymizer_contact` running (they feed
  `inbound_then_fetch`);
* every built-in rule of 4.2 and earlier and every shared pass (cost class `builtin`): `lan_scan`, `outbound_fanout`,
  `inbound_from_public`, `new_device` and the new-device burst, the flow baselines and the others are measured and
  warned about, never paused;
* a shared pass that measures one of those rules, because pausing it would silence that rule too: the industrial
  conversations (`ot_conversations`), passive DNS (`passive_dns`, it measures the resolver change), the link signals
  (`link_signals`, DHCP and router advertisements) and identity (`identity`, fingerprint and GOOSE);
* the rules that are not timed on their own (they are paused or not with their pass) and the periodic rules.

What may be paused, today: with the defaults, **your own IT rules** (`it_watch`, as a whole) and the IT rules of 4.3
that are not on the never-pause list (`iot_initiates_admin`, `admin_into_critical`, `remote_access_tool`,
`dns_nxdomain_burst`, `mining_pool`, `vpn_tunnel_start`, `admin_spread`, `new_admin_listener`,
`daily_upload_new_owner`). With the industrial setting `pause_rule` also every industrial rule of 4.3 that is not on
the never-pause list (`ot_new_function` and the rules of the second industrial pack). A pass that measures rules of more than one kind is paused only when every setting concerned allows it. Each
setting governs its own rules only: with `accept_drops` for your own IT rules the built-in IT rules can still be
paused, and the other way round; the industrial setting never changes what happens to an IT rule. Health shows each rule's verdict (`may_pause`, and `not_paused`: `never` or `policy`).

**The 4.3.0 switch.** Installs that switched the breaker off in 4.3.0 (`detection.breaker` = `off`) keep that
choice: without a saved `detection.overload_policy`, `off` reads as `accept_drops`, for the built-in and your own IT
rules. In the same way `detection.overload_policy` meant the built-in **and** your own IT rules in 4.3.0 and still
does until `detection.overload_policy_own` is saved (the first time an administrator chooses a value for your own
rules); after that the two are independent. Saving the settings keeps `detection.breaker` in step, and
`PUT /api/rules/breaker` still works (it sets both IT settings, the industrial one is kept).

**What counts.** A rule is judged on its own work: the processor time of the detection thread while it ran, without
the time spent waiting (for the database while another part of DENIS writes to it, for the disk) and without loading
device details that every later rule of the window uses too. Health shows the full time a run took. So a slow or busy
database never makes a rule look slow, and a rule that really computes too long still trips. As a second guard, a rule
also trips when the full time of one run is 20 times its budget and at least one second, in three of its last six
runs: a rule that holds up detection by waiting is caught too, while ordinary waits stay far below that limit.

A rule that trips is **paused** when the settings allow it: DENIS skips it from the next run on, so one slow rule
cannot make all detection late, and every other rule keeps running. A paused rule finds nothing. That
is why the pause is never silent: it is written to the log and the audit log (`rule.paused_performance`, by
`denis`), the Health page warns ("The detection rule ... was paused automatically ...", with the time it took and
its budget), the Rules page marks the rule **Paused: too slow** (it stays on in your settings) and offers **Run it again** in its details, and `denis_rule_paused{rule}` is 1. The pause is saved and
survives a restart. After 30 minutes a paused rule is **tried again**: it runs for a few units of work, and when three
in a row stay within the limit it runs again on its own (logged and audited as `rule.resumed_automatically`, by
`denis`). A trial run with far fewer records than the run that paused it (a quiet window) does not count either way.
One trial run over the limit pauses it again and doubles the wait before the next trial (1 hour, then 2 hours at
most); a rule paused again within two hours of running again on its own waits longer in the same way. So a rule that
is really too slow costs one run per trial and does not flap between paused and running. An administrator can re-enable it at any time with **Re-enable** in the rule's row under Health,
Detection rules, or **Run it again** in the details of the rule on the Rules page (both `POST /api/rules/paused/{rule}/resume`, audited as `rule.resumed`); the rule then starts again with
a clean history. Before re-enabling it, find out why it was slow: for your own IT rules that is usually a very large number
of rules or of listed networks and ports.

A rule that trips and may not be paused keeps running and is warned about on Health: "The detection rule ... is too
slow ..." (never paused), or "... It keeps running because of the overload setting ..." (a setting keeps it).

**Changing a setting** applies at once (`PUT /api/rules/overload-policy` with `detection_overload_policy`,
`detection_overload_policy_own` and/or `detection_overload_policy_ot`; an unknown value is refused and nothing is
changed; audited as `rule.overload_policy` with the values before and after, and a notice to the administrators). It
pauses nothing at once. A paused rule that the new settings no longer allow to be paused (for example an industrial
rule after `warn_only`, or a built-in IT rule after `accept_drops`) runs again with the next unit of work, audited as
`rule.resumed_automatically` with the reason `setting`; the same happens to a saved pause at start. The settings are
kept in the settings store (`detection.overload_policy`, `detection.overload_policy_own`,
`detection.overload_policy_ot`), the paused rules in `detection.paused_rules`.

**Notifications.** Besides Health, DENIS tells the administrators through the bell and every notification channel
you configured (Slack, Teams, e-mail, ...; each channel's minimum score, maintenance mode and cap apply as for every
notice). Three events:

| Event | When | Severity |
|---|---|---|
| `rule_paused` | the breaker paused a rule | warning (an industrial rule: high) |
| `rule_over_budget` | a rule tripped and was only warned about (never paused, or kept running by a setting) | warning |
| `overload_packet_loss` | traffic was lost while detection was far behind: for at least 5 minutes every sample (every 30 s) had a detection lag of 60 s or more, or 64 or more traffic windows waiting, and in at least two of those intervals packets were dropped (kernel or interface), traffic windows were dropped, or the capture had to wait | high |

Each message names the rule, the time of one run and its budget, the overload setting that decided (the one for
built-in IT rules, for your own IT rules or for industrial rules), and what to do (re-enable the rule under Health,
Detection rules; or change the setting on the Rules page, Performance protection). It holds no device, address or site
data. **At most one message per rule and event every 6 hours** (and one per 6 hours for the packet loss): a repeat
inside that time is only counted on the bell's entry of the message already sent, and the next message after the 6
hours says how often it happened in between. A rule that flaps (paused, re-enabled, paused again) therefore reaches
your channels at most four times a day. The packet-loss message is sent when the condition starts, not on every
sample while it lasts. The cooldown is kept in `detection.overload_notices` (a restart does not reset it).

The thresholds are constants in `src/detect/meter.rs`: `TRIP_FACTOR` = 4, `TRIP_WINDOWS` = 3, `TRIP_OF_LAST` = 6,
and the class budgets above. A failure (panic) inside one rule is caught and counted
(`denis_rule_errors_total`); the other rules of that run still run.

The Health page warns (for an hour after the last occurrence) when the capture had to wait ("Packet capture had to
wait N times ...") or when traffic windows were dropped ("N traffic windows ... were dropped ..."). Both clear when the cause
stops; a restart resets the counters.

Housekeeping deletes (the hourly removal of old events, trend samples, relationships, names and switch history)
run in chunks of 2,000 rows with a short pause between chunks, so they no longer hold the database for the whole
deletion.

**Optional separate read connection (SQLite).** By default the console's reads and DENIS's own writes share one
database connection. Setting the environment variable `DENIS_SQLITE_READ_CONNECTION=1` before starting DENIS gives
each database (the default site and every tenant, each its own) a second, read-only connection that the
console's list and detail reads use (alerts, incidents, relationships, trend samples, audit, switch history, names).
A long console query then no longer delays the writes, and the writes no longer delay it. It sees every committed
change. It is off by default; leave it unset unless a large installation's console feels slow while capture is busy.
It has no effect with PostgreSQL.

## What the four states mean

Since 4.6.0 every thing DENIS monitors from this server (a switch, a port, a [service check](service-checks.md), a
switch's [configuration](config-changes.md)) is shown in one of four states, from one place in the program, so that the
Dashboard, Health and the equipment pages never say different things. Each state is judged **from this server** and
travels with the time it was judged and since when it holds.

| State (code) | Shown as | Means |
|---|---|---|
| `healthy` | Healthy | this server judged it within the last expected interval and found nothing wrong |
| `degraded` | Degraded | it answered this server, and something about it is wrong: a condition in force, a wrong answer, a slow answer, a certificate about to end, unsaved configuration changes |
| `not_reachable` | Not reachable from this server | this server asked and got no answer from the thing itself. It is always said "from this server". It never says "down" or "offline", because another place may still reach it |
| `unknown` | Not known | it cannot be judged now: not asked yet, the last judgement is older than allowed, this server itself could not ask (no permission for ping, its own resolver failed, its main interface is failing; a switch the tenant's outbound policy does not allow, reason `not_allowed`), or a stored state this program does not know |

* **Why?** Beside a state that is not *Healthy*, in Health's tables, on Configuration changes and on Service checks,
  *Why?* opens a small panel: the reason the server gives, since when, where and when it was judged, and the ways to
  the readings in Health and to the setup of that monitor.
* **There is no fifth state.** "Offline" and "down" do not exist as states in the program (verified: no code path can
  produce them, and a test scans the wording).
* **No data is *Not known*, never "offline".** Something that nothing monitors (health switched off for a switch, a
  disabled check, a switch whose watch is off) is *Not known* and is shown in grey as "Not monitored"; that is never an
  item of *Needs attention*. Something switched on that has not been judged yet is *Not known* as well.
* **A judgement that is too old is *Not known*.** After three intervals (a check: three intervals plus its timeout) the
  last state is no longer shown as current, so a stopped job or a standby that took over never shows an old "Healthy".
  A judgement dated further ahead of this server's clock than that age (at least 10 minutes) is *Not known*
  too: the clock was stepped back after it was made (see "When the server's clock is stepped back" in
  [switches.md](switches.md)), and it says nothing about now.
* **When something is *Not reachable*, what hangs below it is not judged meanwhile.** The ports of a switch that cannot be
  read are folded into one item, "Loss of monitoring", not listed as faults of their own.
* **"This server cannot check" is not "Not reachable".** The first means no question left this server (for example it is
  not allowed to send a ping): *Not known*. The second means a question was sent and nothing came back.
* **The state is the same everywhere.** An unknown stored value reads as *Not known*, never as *Healthy*.

## The Health page

Health answers one question: can DENIS see, record and tell you? What is wrong on your network itself (an incident, a
link that went down, a check that fails) is under **Needs attention** on the Dashboard; each of the two pages carries
one line that points to the other. From 4.6.0 the page has five parts, always in this order:

1. **The verdict**: "Everything DENIS needs is working." or the number of problems and notes, and when Health was read.
2. **Problems** (`#health/problems`), only when there is one, in groups: *Network sign-ins*, *Service checks*,
   *Configuration changes*, *Switches* and *DENIS itself* (everything else, disk and backups included). A **Problem**
   needs a look; a **Note** is housekeeping and does not turn the menu badge red. Each one has its way there, for
   example *Open Sign-ins*, which opens Network → Sign-ins on its Setup tab.
3. **Monitoring** (`#health/monitoring`): one row per function, also for one that is off: *Capture*, *Switch readings*,
   *Service checks*, *Network sign-ins* and *Configuration changes*, each with its state in words and one line. A function
   that is off says **Off** in grey with **Set up**: off is a decision, not a fault. A row opens to that function's
   detailed table (`#health/capture`, `#health/switches`, `#health/checks`, `#health/sign-ins`, `#health/config`); a
   row whose function cannot work (a switch not reachable from this server, a receiver that cannot listen) opens by itself.
4. **This server** (`#health/server`): version, database, free disk, backups, packets dropped, the last network scan;
   the optional recording (east-west traffic, passive DNS, the internet connection watch, the shipped lists) with where
   each one is set; *What DENIS cannot see* (one line while there is nothing to report, open by itself when there is)
   and *Detection rules*.
5. **Background work** (`#health/jobs`): periodic jobs, services and supervised tasks (open by itself when one has an
   error), what is in the database, and this console's own status line.

The page is read again every minute while it is open. What you opened stays open and the page does not move.

## Health warnings that point at data you cannot see

The **Health** page lists problems first, in plain words, and `denis_health_warnings` counts them. These are the ones
that mean DENIS is working but part of what it should see is missing:

| Warning says | Meaning and what to do |
|---|---|
| The packet parser crashed on N packets | The parser caught a panic on a packet, skipped it and carried on, so that packet was not analysed. An unusual or deliberately malformed packet may be getting past detection. Keep the service log and report it; restarting does not remove the cause. |
| Remote agents are sending records with a time DENIS cannot trust | An agent's clock is more than 1 hour ahead of the master, or its records are more than 7 days old; those records are dropped. The warning names each agent, how many records were dropped and when. Set the time on that machine (switch NTP on); it is accepted again. Shown while a drop happened in the last hour. |
| Some switches gave back only part of their SNMP tables | A table was too large to read within the safety limits (rows, time or bytes). Ports, MAC addresses or neighbours may be missing from the topology, so a device can look unplugged. The switch card shows "Incomplete data" and names the tables. |
| The capture's signal buffer was full N times | More ARP and DHCP signals arrived between two checks than the buffer holds (for example a DHCP flood or a sweep). Address conflicts and forged ARP or DHCP servers are kept ahead of routine requests, so what was dropped was mostly routine. |
| Packet capture had to wait N times | The queue of observations waiting to be stored filled up, so the capture stopped reading packets for a moment and the network card may have dropped some. The database or disk is too slow: see [When the database cannot keep up](#when-the-database-cannot-keep-up). Shown for an hour. |
| N traffic windows were dropped | Ten-second traffic summaries were thrown away because the part that stores traffic was behind; those flows are missing from the traffic views. Same cause and same section. Shown for an hour. |
| N alert notifications were not sent | Only with `--webhook-volatile` (the old in-memory queue was full). The alerts are still stored and shown in the console; check Settings → Notifications. Shown for an hour after the last dropped notification. |
| N notifications could not be delivered in the last hour | The receiver refused them, or the alert was too old by the time it could be sent. They are given up on, listed under Settings → Notifications → Deliveries, and can be sent again from there. |
| Notifications for a channel have been waiting for N | A channel's oldest message has waited more than 15 minutes because the receiver cannot be reached or does not accept it. They are sent again automatically. |
| N notifications were not queued because too many were waiting | A channel that has been down for a long time reached 1,000 waiting messages (20,000 for all channels); the alerts are still in the console. |
| Agent reports (a service line) | Agents are enrolled but none has reported for 6 hours. Advisory. The demo's two sites do not count. |
| Saving devices and sightings (or east-west connections, or passive DNS names) to the database failed N times | A database write failed within the last 15 minutes: what was seen then is not saved. Check the free disk space and the database (on PostgreSQL: is the primary accepting writes?); the service log names the error. While writes fail, the **Database writes** service line is judged from the last flush that came with no new failure. |
| The last backup needed *time* to copy the database, and the database's write-ahead log … grew to *size* meanwhile (4.5.4) | Advisory, SQLite. The last backup since DENIS started took 10 minutes or more, or the `denis.db-wal` file reached 1 GiB while it ran. Recording went on during the copy; the log is folded back in after it. Check the free disk space: the log needs that room during every backup. Shown until DENIS restarts or the next backup is quick and small. |
| The database's write-ahead log … is *size* (4.5.4) | Advisory, SQLite. `denis.db-wal` is 1 GiB or more now. It is folded back in when nothing reads an older state of the database; if it stays this large, look for a program that keeps the database open (another `denis` command, a copy or backup tool) and check the free disk space. |
| Part of the database could not be read for this page | The Health page could not read the database statistics or the backup settings. It still shows everything else; the figures that need the database are empty. |
| *Job*: the last N attempts failed | A periodic job (Findings, Posture samples, Scheduled reports, Service probe, Tenant limits from the control store, Maintenance setting for notifications; advisory for Vulnerability data, the GeoIP database update, the Entra ID and Intune import, the vulnerability scanner import and, since 4.5, the Active Directory, Jamf Pro, Microsoft Defender, AWS, Azure and Google Cloud imports) failed three times in a row. What it keeps up to date is from its last completed run. The error is in the warning and under **Background work**. |
| The background job *X* failed N times in a row (4.5) | One of the jobs that reconcile work items or merge joined devices keeps failing. The error is in the warning; the service log has more. |
| Passkeys are off on this console / The stored passkeys were made for *old* (4.5) | Said at start and kept on the page: the sign-in policy asks for passkeys but passkeys cannot be used on this start (no `--public-url`, or a new public address). Accounts limited to passkeys sign in with their password until passkeys work again; `denis user reset-passkeys <name>` removes an account's old passkeys. |
| This database is older than the one this installation last ran (4.5) | A restore from an older copy was detected at start (see above). Shown for 30 days. |
| The standby *host* runs DENIS *version* … (4.5) | The standby of a PostgreSQL pair cannot open the database's schema and would not take over. Update it. |
| The export to *target* has not worked for *age* / The saved SIEM export settings do not pass this version's checks (4.5) | The SIEM or OpenObserve export has failed for 15 minutes, or its saved settings fail a check of this version (the export keeps running as configured). |
| The local TLS authority in *dir* cannot be read (4.5) | `ca.pem`/`ca.key` are there but do not open; they are not replaced on their own (agents pin them). Restore them, or delete both to make a new one. |
| N devices were deleted from the database while discovery still had them / N devices … were removed (4.5, advisory) | The live inventory dropped rows the database no longer had, or the aging pass of a nearly full site removed devices nothing referred to. Seen again, they come back as new devices. |
| Reports of these agents went missing / Remote agents dropped N flow records / Two collectors report as the same agent (4.5) | A gap in an agent's report sequence (from 4.5.4 read from the batch ledger, so a restart of the master does not clear it; shown for a day, with the number of reports and the age of the last gap), records its full buffers pushed out while the master could not take them, or two processes with one agent id (a cloned machine). |
| Reports of these sites were interrupted on this master / failed every time and were set aside / were refused by this master (4.5.4) | A part or all of a report a remote site sent is not in this database. Each warning names the sites with a count and the age of the newest case, for a day; **Sites** lists every case of the last 7 days with its time span and reason. See [Gaps in what a remote site reported](#gaps-in-what-a-remote-site-reported). |
| DENIS could not read these switches from this server for N readings in a row (4.6.0) | Three or more attempts in a row to read a switch that is switched on failed. This server gets no answer; that does not say the switch is down. Check the address, the SNMP credentials and the route from this server ([Troubleshooting](troubleshooting.md)). |
| Switch readings are late (4.6.0) | The newest scheduled reading of a switch started more than two intervals after it was due. The switches are read one after another, so a slow or silent switch delays the others. |
| The traffic counters of … were left out of some readings (4.6.0) | In at least 3 of the last 12 readings of a switch the counters took longer than their 5 seconds and were skipped. The port list and the topology were still read. |
| … offers no traffic counters DENIS can use (4.6.0) | Port health is on, and the newest reading of the switch found no byte counter at all (neither 64-bit nor 32-bit). A port whose only counters are 32-bit ones, too small for its speed at this interval, says "Not offered by this switch" in its own row without this warning. |
| … is not read: *reason* (4.6.0) | The newest attempt, from the last interval, was not allowed by a policy of this installation (the tenant's outbound policy). |
| Service checks (4.6.0, codes `checks_job_stalled`, `checks_late`, `checks_icmp_not_permitted`, `checks_store_failing`; advice: `checks_passive_only`, `checks_near_limit`) | The job has not finished a pass for minutes; checks are running late; this server may not send ping (give the service `CAP_NET_RAW` or set `net.ipv4.ping_group_range`); the checks cannot be read from the database; this server was started passive-only; 90 or more of at most 100 checks are listed. Each is explained in [Service checks](service-checks.md#health-warnings-of-service-checks). |
| Configuration changes (4.6.0, codes `config_partial`, `config_read_failing`; advice: `config_not_supported`) | Only part of a switch's configuration time stamps could be read; they could not be read for more than 3 readings; the switch offers none. Nothing is compared that was not read. See [Configuration changes](config-changes.md#health-warnings-and-states). |

These Health rows are produced by the checks and the configuration watch themselves and shown on the Health page as in
the console; their codes do not change. The other warnings new in 4.6.0 carry a stable `code` too (since the 4.6.0
review): `switch_unreadable`, `switch_reads_late`, `switch_counters_skipped`, `switch_counters_not_offered`,
`switch_not_allowed`, `db_migrated_without_copy`, `backup_copy_heavy`, `db_wal_large`, `east_west_capped`,
`passive_dns_capped`, `flows_unchecked`, `nac_unlisted_moves`, `nac_ports_disabled`, `nac_plain_credentials`,
`nac_invalid_config`, `agent_batch_interrupted`, `agent_batch_set_aside`, `agent_batch_refused`,
`agent_batches_dropped`, `agent_batches_lost`. A script matches the code, never the sentence.

A person who may read only some sites sees the warnings that name agents (reports that went missing, were interrupted,
set aside, refused or given up at the site, dropped flow records, two collectors as one agent) only for those sites;
the others are left out, not counted. The count of enforcement state changes outside DENIS's state table is shown on
the Health page, not counted for the menu badge.

**Background work** (at the bottom of the Health page, folded) lists each periodic job with its last completed run,
its last attempt and the last error; each service line with its status and last good time; and each supervised task
with its state, restarts and last error. The periodic jobs keep their record in the database (`jobrun.<job>` settings),
so it survives a restart. When the Health page itself cannot be read (`/api/system` fails), the page says "Health could
not be read" with the reason and the menu badge shows **!**, instead of keeping the last good page.

These warnings clear when the cause stops. A restart clears the counters (not the cause).

## Reading switches (port health, 4.6.0)

Port health is Experimental; what it reads and shows is in [Switches](switches.md#port-health-traffic-errors-and-restarts-experimental-460).
For the person who runs DENIS:

* **The Health table *Switch readings*** has one row per switch in the list: its port health (on, off, or not decided
  for a switch from before 4.6.0), the last reading and the last good one, how late the newest scheduled reading
  started, failures in a row, the time it took, what became of the counters (read, partly, skipped, not offered, not
  due yet, off), the ports sampled, and the last 24 hours (failed, skipped, not allowed). It is built from one row per
  attempt to read a switch (table `switch_polls`), written for every switch with port health on or off. It says how
  this server is doing at reading the switch, never whether the switch works.
* **The read budget.** The switches are read one after another, one lock per switch (a port action's re-read waits on
  the same lock). The counters are read inside the switch's reading, right after its port list, with a time limit of
  5 seconds for all of them and one retry per request; when it runs out the counters are "skipped" for that reading and
  the rest of the switch is read as always. They are read only when a port's last measurement is at least 4 minutes old,
  so a **Read now** right after a scheduled reading, or an interval of 60 seconds, adds no second measurement. The
  5 seconds and the 4 minutes are fixed in 4.6.0.
* **Backoff.** A switch that failed three scheduled readings in a row is read only every second interval until a
  reading succeeds; a successful **Read now** puts it back on the normal schedule at once. A reading that the tenant's
  outbound policy does not allow writes at most one "not allowed" row per interval.
* **High availability.** Only the active node reads switches; a node that loses its lease while a switch answers writes
  nothing of that reading.
* **Extra reads (4.6.0).** With port health on, a reading also asks for the processor, memory and PoE figures, and with
  a Cisco switch's configuration watch on, for three time stamps. They run in a phase of their own with a 3-second limit
  that lies inside the time the counters already had (so the per-switch lock is held no longer than before), one retry
  per request, and each table cut at 256 rows. When the counters used their whole time the extras are skipped for that
  reading ("not known", never 0 %). They never fail the reading. See [Switches](switches.md#device-figures-processor-memory-running-time-460).
* **The hourly roll-up** runs in the hourly retention cycle on the active node, at most 48 hours per switch per pass.
  A failure is written to the log and tried again the next hour; the raw samples it covers are kept until it succeeds.
* **Metrics**: `denis_switch_read_fail_streak` and `denis_switch_read_lag_seconds`, see
  [Monitoring DENIS itself](#monitoring-denis-itself-prometheus).
* **Backup and restore.** The tables of port health (`port_samples`, `port_last`, `switch_polls`,
  `infra_conditions`, and since 4.6.0 `port_link_changes`, `poe_ports`, `port_hourly`, `switch_hourly`) are part of the database and of every backup; they hold no credential (the error text of a
  reading is stored free of secrets). The SNMP communities and SNMPv3 passwords are left out of backups like the other
  integration secrets: after a restore, enter them again, or the readings of those switches fail and "cannot be read"
  opens after three of them (best guess of what an operator sees; not tried). The restored history ends at the time of
  the backup: when the hole is longer than three intervals (at least an hour), the first reading after the restore shows
  "Not known: too long since the reading before" instead of an average across it, and the reading after that is
  measured again. The conditions are as they were at the time of the backup and are judged again from the next reading.
* **Erase all data** deletes the four tables with the rest of the inventory; removing a switch from the list deletes its
  rows; the hourly prune keeps the [port history period](#retention).
* **Going back.** Schema V66 keeps the compatibility floor: on SQLite a build that knows the floor but stops at V65
  opens a database with the port health tables as it is and leaves them and their rows alone, so going back is a program swap and the
  history is still there for the next update ([Going back without a restore](updates.md#going-back-without-a-restore-from-460)).
  On PostgreSQL a build below the database's schema number refuses it in 4.6.0 whatever the floor says, and the way back
  is the dump taken before the update. To remove the tables by hand, see [Rolling back V66](#rolling-back-v66) and, for the later tables, [V68](#rolling-back-v68).

## Service checks and configuration changes (4.6.0, experimental)

Both are Experimental and off until an administrator adds a check or switches the watch on for a switch. What they do is in
[Service checks](service-checks.md) and [Configuration changes](config-changes.md). For the person who runs DENIS:

* **High availability.** Only the active node runs checks, reads the switches and raises their notices. A result that
  arrives after a node lost its lease is dropped, not written.
* **Passive-only.** A server started with `--passive-only` runs no checks (Health says so); it still reads a switch that
  an administrator configured, and that read carries the configuration time stamps when the watch is on.
* **What a check sends.** Only to the targets listed, from this server's own addresses, see
  [Security](security.md#service-checks-460-experimental). Plan a firewall rule for ICMP, the listed TCP ports and DNS
  from this server if you filter outbound traffic.
* **Backup and restore.** The tables of checks (`check_runs`, `check_state`, `check_hourly`) and of configuration changes
  (`config_state`, `config_events`) are part of the database and of every backup. The list of checks is a setting
  (`checks.list`) and is part of the settings; the industrial setting is `checks.ot_policy`. No password, secret or
  configuration is in any of them. After a restore the checks run again from their next due time, and the first reading
  of a switch's configuration after a restore is a first one again (it makes no event).
* **Erase all data** deletes the tables of both; removing a check or a switch deletes its rows.
* **Going back.** Schemas V68, V69, V70 and V71 keep the compatibility floor: a 4.6.0 build that does not know them uses
  such a database as it is and leaves the new tables, columns and indexes alone (see [Going back without a restore](updates.md#going-back-without-a-restore-from-460)).
  To remove them by hand: [V71](#rolling-back-v71), [V70](#rolling-back-v70), [V69](#rolling-back-v69), [V68](#rolling-back-v68).

## Is it your connection, or is it DENIS?

The icon button next to **Scan now**, in the header, opens a 10-20 second **connection stability
test** — not a speed test. It measures packet loss, jitter and latency over two legs at once: this
browser's own connection to DENIS, and DENIS's own connection to your gateway or a public resolver
(your choice, under the test's own settings — pick "gateway only" on a network with no internet
access). Because both legs are measured, the result can say *which side* was unstable, not just that
something was.

The result rates the connection separately for web browsing, a video call, and 1080p/4K streaming —
each has a different tolerance for loss and jitter, so one is often fine while another is borderline
or poor, each with the specific number that tripped it. It also says whether DENIS's own recent
network activity (a sweep or scan) overlapped the test and made things measurably worse, had no
effect, or was not running at all — the question this feature exists to answer. Every result is
saved and shown on the **Health** page with a short history, so a pattern across tests (a sweep
always correlating with trouble, say) becomes visible over time.

## Tracking a fix: work items

A finding or a Top-exposures item can be turned into a **work item** (*Track fix…*, from the
device panel or the Findings page): an owner, a status, a due date and notes, and optionally a
linked Jira or ServiceNow ticket (DENIS can create it, or you can link an existing one by hand).
DENIS confirms the fix itself, by one of three methods depending on what makes sense for that
finding: rescanning the device, checking that the underlying record is simply gone, or watching
that there has been no further contact matching the problem for a set number of hours (default 24,
an administrator can change it) while the device stays online. A confirmed fix is watched for 30
days and reopens automatically if the problem comes back.

A work item made from an [incident](incidents.md#related-findings)'s *Related findings* remembers which incident it was
tracked from ("From incident #12", a link) and keeps that when the incident is later resolved or ages out; a work item
made from the Findings page or a device panel has none.

## How big can one installation be?

Measured on one laptop (8 cores, SQLite, release build, a synthetic site), not on a server and without real browsers, so read it as an order of magnitude:

| Devices in one database | Console users at the same time | Result |
|---|---|---|
| up to 10,000 | up to 4 | comfortable: the 2-second write cycle finishes in under 0.2 s and console pages answer in well under a second |
| up to 1,000 | 16 | comfortable |
| 10,000 | 16 | the write cycle takes up to 1.9 s (the whole cycle) and pages take up to 1.3 s |
| 50,000 | 1 occasional user | the write cycle takes 1.1 s, 1.9 s at worst; with four users it falls behind. Not supported |

What limits it is that all work shares one database connection: one slow page (a device list at 50,000 devices takes
0.25 to 0.45 s, a report up to 1.5 s) holds up the writes behind it. The engine itself is not the limit. A pool of
read connections would fix that in testing (the write cycle stayed at 0.3 to 0.4 s with 16 users at 50,000 devices), but
**it is not built**: the figures for a pool are from a prototype in the test harness. Separate databases (one per
tenant) have separate connections; several sites in one database were not measured.

**With live capture (4.5.1).** A second set of measurements ran the whole pipeline at once on the same laptop: synthetic traffic of 35,000 frames per second, the detector, the 2-second write cycle and console readers (single runs of 60 seconds on a busy machine, so differences under about 30 % are noise):

| Devices | Console readers | Longest write cycle | Device list (95th percentile) | Memory peak |
|---|---|---|---|---|
| 20,000 | 0 / 4 / 16 | 0.6 / 1.1 / 1.9 s | - / 0.26 / 0.53 s | 0.6 / 1.2 / 1.4 GB |
| 30,000 | 0 / 4 / 16 | 0.9 / 1.2 / 2.3 s | - / 0.35 / 0.79 s | 0.8 / 1.9 / 2.0 GB |

No frame was lost in any of these runs. Before 4.5.1 the longest write cycle at these sizes was 3.3 to 3.9 s, because it waited behind long writes of connections and passive DNS names and behind the detector's periodic save; those now go to the database in small steps. At 149,000 frames per second and at 50,000 devices the same setup was not repeated with 4.5.1 and should be read from the 4.5.0 figures, which stalled there. **Verified up to 30,000 devices at 35,000 frames per second. Read it as the largest size one SQLite installation has been shown to handle on this laptop; beyond that it is not measured.** The readers of this test load the whole device list on every call, as an uncapped console does, and each decode is large: plan on 2 GB or more of memory for 30,000 devices with several people in the console. The console's status and exposure calls, which 4.5.1 reads without decoding every device, stay near 0.1 to 0.3 GB in a separate test of the server alone.

**What this table is, in plain words.** It comes from a synthetic test harness, not from a real network, and the numbers are an orientation, not a promise:

* The traffic is **generated frames handed to the capture worker**. No network card, driver or kernel was involved, so "no frame was lost" means no frame was lost *inside DENIS*. Loss in the kernel or the driver on a real interface is not counted: the harness only has DENIS's own software counters.
* The **DNS observations are injected in front of the detector**, not parsed from packets.
* The **console readers call the store directly, not over HTTP**. There is no web server, TLS, login or browser in their time, so real pages are slower than the figures.
* **"Longest write cycle" is the time of the database write itself** (`FlushPlan::write`, the step that stores the changed devices), not the whole cycle with the detector and the sampling around it.
* Every cell is a **single run of 60 seconds** on one laptop that was doing other things. Differences under about 30 % are noise; do not read one cell against another as a trend.

**PostgreSQL is not a speed-up for one site.** It stays the choice for high availability. Writing a changed device is a
round trip, and PostgreSQL commits once per block: the write cycle (`FlushPlan::write`) hands the changed devices to the store
in blocks of up to 500 (`save_assets_batch`), and PostgreSQL commits each block as one transaction (about 4 ms per
round trip against 0.1 ms on SQLite). The figures that were measured, however, are from **before** this: they were taken
when the write cycle still committed once per device, on the test setup (PostgreSQL in Docker on a laptop, so slower than a native
server): 1.5 s at 10,000 devices with no users, and over the 2-second cycle at 50,000. The block write has **not been
measured again**, so the estimate of about 5,000 devices per site on PostgreSQL is **the old measurement on the old write
path**; it is probably conservative now, and it is unverified on server hardware.

### Gaps in what a remote site reported

A remote agent sends its observations in numbered reports and sends a report again until the master acknowledges it.
From 4.5.4 the master writes one row per report into a ledger (table `agent_batches`): which site, which run and number,
the SHA-256 of the body, the time span its records cover, and **how far the master got with it**. The report itself is
not stored. The ledger is what makes these cases visible and bounded:

| What happened | What the master does | What you see |
|---|---|---|
| The master stopped or failed while it applied a report (a crash, a restart, a database error) | The agent sends the report again. The master carries on behind the last part it had started. The part that was started when it stopped is **not applied again** (it cannot tell whether it finished, and nothing is ever counted twice); everything after it is applied. | The report is listed as incomplete with the part that is missing (for example "flow records"). If it stopped before any counting part was started, the resend applies everything and nothing is listed. |
| The master stopped and the agent never sent the report again (it gave up, or it was reinstalled) | After 6 hours without a resend the report is closed. | Listed as "interrupted and not sent again" from the part it stopped at. Before that, from 10 minutes on, as "waiting for the site to send it again". |
| A report failed 10 times in a row with a program fault (a panic), also across restarts of the master | It is set aside: the agent is told to drop it, and nothing more of it is applied. A fault inside one counting part costs only that part: the resend leaves it out and applies the rest. | Listed as "set aside". Keep the service log and report it. |
| Reports never arrived (the agent dropped them: the master was away too long, a report was too large or was refused) | The next report that arrives shows the hole in the numbers. | Listed as "N reports never arrived", with the time span between the report before and the report after. |
| A second, different body arrived under a number that already has one | It is refused (one number, one body). If the first body was still unfinished, it is closed as incomplete. | Listed as "refused". Two collectors running with one agent's configuration (a cloned machine with its queue) are the usual cause. |

Where: **Sites** shows "Incomplete data: N" under a site's last report time, with one line per case (time span, reason,
report number) for 7 days; **Health** warns for a day; the bell gets a notice of category *agent* per site (at most
one an hour, repeats counted), which follows your notification channels like every notice. A site's "last report"
time alone does not tell you this: a site can report every few seconds and still have a gap.

What this does not do (documented): it does not bring the missing part back, and it does not make the detector's own
memory durable. Volume and baseline counts are kept in memory and saved on the detector's schedule, as for the local
capture, so a crash of the master can lose a few minutes of them for reports the ledger calls applied. A step whose
completion could not be written (the database went away at that moment) is treated as interrupted: the ledger errs
on the side of "incomplete", never on the side of counting twice.

Ledger rows are kept for 7 days after their last change, pruned every hour. Per site at most the newest 2,000 rows of
reports applied whole are kept (at a report every 15 seconds about 8 hours; they only serve to recognise a resend)
and at most the newest 20,000 of the others, so a gap stays listed for its 7 days (since 4.6.0; before, the applied
rows counted against the same 2,000 and pushed a gap out after about 8 hours). At about 150 bytes a row this is
about 3 MB per site at most (best guess, not measured). Deleting a site deletes its rows. **Sites** and **Health**
read at most 100 cases per site (Sites lists the newest 20), so one site with many refused reports does not hide
the others; when the ledger cannot be read, **Sites** still lists the sites and says that it cannot tell what is
missing.

## Upgrading

DENIS can update itself from GitHub releases (or, if GitHub cannot be reached, from the fallback host), with a backup
first, and can update its remote agents from the console ([Updates](updates.md)). To update by hand:

1. Take a backup (above).
2. Replace the `denis` binary and restart the service. On a Linux service installed with `install.sh`, just run the
   newest `install.sh` again: it does both steps ([Deployment](deployment.md#installing-on-a-linux-server-a-permanent-service)).

The database is upgraded in place, in one transaction per start on SQLite and on PostgreSQL alike (4.5; before, SQLite
committed each step on its own): a step that fails, or a crash mid-upgrade, leaves the database at the version it had
before the start, which the program you ran before can still open. A step can run twice: a column, table or index it
adds that is already there (a database set back to an older version by hand) is left out instead of failing the start.

**A database newer than the program** (4.6.0, SQLite): it depends on its compatibility floor, the oldest DENIS that can
still use it ([Updates](updates.md#going-back-without-a-restore-from-460)).

* The floor allows this program: the database is opened and used as it is. Nothing is migrated and the format number
  is not written; one warning in the log says so, and `GET /api/health` shows `ha.schema` (`version` above `build`).
* The floor is above this program, or the database has no readable floor: it is refused before anything in the file is
  changed (not even its journal mode), with a message that keeps the words tools look for and names the version needed:
  `database schema v70 is newer than this build (v66) and needs DENIS 4.8.0 or newer: a newer DENIS upgraded it in a way
  this version cannot read. Run that version or a newer one, or restore the backup taken before the update together with
  its secrets.key`. A program before 4.6.0 refuses every newer format number. On PostgreSQL a newer schema number is
  refused in 4.6.0 whatever the floor says.

**The copy before an upgrade** (4.6.0, SQLite). The program that upgrades a database first writes a verified copy of it,
exactly as it was, to `<data dir>/backups/` (tenants: `backups/tenants/<id>/`; a database opened by a command without a
data directory: a `backups` folder beside it), named `denis-before-<version>-<time>.db`, owner-only. The newest five per
folder are kept; `pre-migration.json` in the same folder records which copy belongs to which upgrade. It holds a lock
(`.pre-migration.lock`) while it upgrades: a second DENIS program that wants to upgrade the same database waits up to two
minutes and then stops with "another DENIS program is upgrading this database". If another program writes to the
database between the copy and the upgrade, the copy is taken again; after three rounds the start stops with "another
DENIS program is writing to this database" and nothing is changed (stop the other program first). If there is not twice
the database's size free in that folder, or the copy fails its check, **the database is not upgraded and the start
fails**; the program you ran before still opens it. `DENIS_MIGRATE_WITHOUT_COPY=1` (environment only) upgrades without
the copy, at your own risk: going back to the previous version then cannot restore that database, and Health and the
log say so. No copy is made of a new, an in-memory or an up-to-date database, of an import or a backup copy that is
being opened, or on PostgreSQL (take a `pg_dump` yourself before an update outside the built-in updater).

**Going back from 4.4.** Schema V57 (4.4, the counts of trial mode, which 4.4.1 removed: no rule can be put in a trial any more, the column stays) adds one column, `rule_outcomes_daily.trial`
(`INTEGER`/`BIGINT NOT NULL DEFAULT 0`, on SQLite and PostgreSQL alike), and nothing else; the trial records themselves
live in the saved rules (`rules` setting, field `rule_modes`), which needs no migration. Rolling back to 4.3 therefore means
restoring the backup taken before the update (the update does this by itself when it fails); a database already at V57 is
refused by 4.3 ("newer than this build") rather than opened. If you must run 4.3 on a V57 database without a backup, the
column is harmless to 4.3 and can stay; to bring the schema back by hand, stop DENIS and set it to 56: SQLite
`PRAGMA user_version = 56;`, PostgreSQL `UPDATE schema_version SET version = 56;`. Installing 4.4 or newer again
later upgrades that database as usual (from 4.5 on, SQLite leaves out the column that is already there; 4.4 itself
stopped with "duplicate column name: trial", so go straight to 4.5 or drop the column first). Nothing else changes, and the trial
records in the rules are ignored by 4.3 (it would reject a rules file that carries them, which is why a rules export never
does). Rules that were in a trial then simply raise their alerts as usual: nothing stays hidden.

**Back up before you update 4.4; two more changes cannot be read by 4.3.** Besides V57 and V59 (below), 4.4 adds V58 on
PostgreSQL (the write fence; `denis db undo-v58`) and changes the format of the stored secrets at the first start
(`enc1:` to `enc2:`, one way; `denis secrets downgrade-envelope` converts back). The order of the steps for a PostgreSQL
pair, the backup commands and how to stop both nodes are in
[High availability](high-availability.md#upgrading-a-pair-to-44); the secrets are in
[Security](security.md#upgrading-the-secret-format-44). The simplest way back stays the same: restore the copy taken
before the update, together with its `secrets.key`.

**Ways back from V65 on.** From the step after V65, a schema step that keeps the compatibility floor needs no hand
procedure: the previous version (4.6.0 or later) opens the database as it is, so going back is **starting the previous
version**. A "Rolling back Vnn" section is written only for a step that raises the floor; the release notes say which.
Before V65 (the steps below), every step has its own procedure.

### Rolling back V59

Schema V59 (4.4, durable delivery of alerts) adds two tables and nothing else: `deliveries` (one row per message to one
channel: its state, retries, and the text that is sent, never a URL, key or token) and `delivery_events` (which alerts a
row carries). It changes no existing table, so it can be taken back on its own. A build that does not know V59 refuses
the database ("newer than this build"); restoring the backup taken before the update is the simple way back. To go back
by hand, stop DENIS on every node first (on a database that is already at V60, take V60 back first, "Rolling back V60"
below), then:

```sql
-- PostgreSQL (one transaction)
BEGIN;
DROP TABLE delivery_events;
DROP TABLE deliveries;
UPDATE schema_version SET version = 58 WHERE version = 59;
COMMIT;
```

```sql
-- SQLite (sqlite3 denis.db)
PRAGMA foreign_keys = ON;
DROP TABLE delivery_events;
DROP TABLE deliveries;
PRAGMA user_version = 58;
```

What is lost: the messages that were still waiting to be sent (queued or being retried) and the history of what was
delivered, failed or given up. Alerts, incidents, devices and settings are not touched, and neither are the channel
cursors, so a build without the outbox resumes from them and sends what is newer than the cursor. A message that was
waiting for a receiver that was down is not sent after the rollback unless its alert is still newer than the cursor. The
next start of a 4.4 build with V59 creates the two tables again, empty. On PostgreSQL, `denis db undo-v58` refuses a
database that is at version 59: do the steps above first. The commands were run against a real SQLite file and a real
PostgreSQL 16 in the tests (`store/sqlite/tests_v59.rs`, `store/pg/tests/deliveries_tests.rs`).

### Rolling back V60

Schema V60 (4.4, the real split of one hardware address) adds one column, `assets.l2_domain` (every existing row gets
the empty value), and replaces the unique key of a device row, `(site, hardware address)`, by `(site, network, hardware
address)`. Nothing else changes. A build that does not know V60 refuses the database ("newer than this build");
restoring the backup taken before the update is the simple way back. To go back by hand, stop DENIS on every node first.
If an administrator split a hardware address, there are extra rows (`l2_domain` is not empty) and the old key would
refuse them: undo every split in the console first (device panel, *Undo the split*), or check that none is left:

```sql
SELECT COUNT(*) FROM assets WHERE l2_domain <> '';   -- must be 0
```

```sql
-- PostgreSQL (one transaction)
BEGIN;
DROP INDEX assets_agent_dom_mac;
ALTER TABLE assets DROP COLUMN l2_domain;
CREATE UNIQUE INDEX assets_agent_mac ON assets ((COALESCE(agent_id, '')), mac);
UPDATE schema_version SET version = 59 WHERE version = 60;
COMMIT;
```

```sql
-- SQLite (sqlite3 denis.db)
DROP INDEX assets_agent_dom_mac;
ALTER TABLE assets DROP COLUMN l2_domain;
CREATE UNIQUE INDEX assets_agent_mac ON assets (COALESCE(agent_id, ''), mac);
PRAGMA user_version = 59;
```

What is lost: nothing but the network of the rows (all of them are the original rows again). The setting
`identity.mac_split` stays in the settings table and is ignored by a build without V60. The next start of a 4.4 build
with V60 adds the column again, empty. On PostgreSQL, `denis db undo-v58` refuses a database that is at version 60: do
the steps above first, then undo V59 as described there. The steps were run against a real SQLite file in the tests
(`store/sqlite/tests_v60.rs`); the PostgreSQL migration is covered by the shared store conformance cases.

### Rolling back V61

Schema V61 (4.5, administrator threat lists) adds two tables and nothing else: `threat_lists` (one row per list: its
source, action, refresh and age settings, the name of its sealed credential and the status of its last fetch, never the
credential) and `threat_list_entries` (the entries of each list). It changes no existing table, so it can be taken back
on its own. A build that does not know V61 refuses the database ("newer than this build"); restoring the backup taken
before the update is the simple way back. To go back by hand, stop DENIS on every node first, then:

```sql
-- PostgreSQL (one transaction)
BEGIN;
DROP TABLE threat_list_entries;
DROP TABLE threat_lists;
UPDATE schema_version SET version = 60 WHERE version = 61;
COMMIT;
```

```sql
-- SQLite (sqlite3 denis.db)
PRAGMA foreign_keys = ON;
DROP TABLE threat_list_entries;
DROP TABLE threat_lists;
PRAGMA user_version = 60;
```

What is lost: every administrator list and its entries. The sealed credentials stay in the settings table
(`threat_list.credential.<id>`) and are ignored by an older build; delete them with
`DELETE FROM settings WHERE key LIKE 'threat_list.credential.%'` if you do not want them kept. The settings row
`threat_lists` (the global switches) is ignored too. The next start of a 4.5 build creates the tables again, empty. On
PostgreSQL, `denis db undo-v58` refuses a database that is at version 61 (at version 62, take back V62 first, below): do the steps above first. The SQLite steps are
run against a real file in `store/sqlite/tests_v61.rs`.

### Rolling back V62

Schema V62 (4.5, the threat list console) adds one column, `threat_lists.csv_column` (the column of a CSV list that holds
the indicator; empty means the first column). Nothing else changes. A build that does not know V62 refuses the database
("newer than this build"); restoring the backup taken before the update is the simple way back. To go back by hand, stop
DENIS on every node first, then:

```sql
-- PostgreSQL (one transaction)
BEGIN;
ALTER TABLE threat_lists DROP COLUMN csv_column;
UPDATE schema_version SET version = 61 WHERE version = 62;
COMMIT;
```

```sql
-- SQLite (sqlite3 denis.db, version 3.35 or later)
ALTER TABLE threat_lists DROP COLUMN csv_column;
PRAGMA user_version = 61;
```

What is lost: the column choice of each CSV list (those lists read their first column again). To go further back,
continue with "Rolling back V61". The SQLite steps are run against a real file in `store/sqlite/tests_v62.rs`.

### Rolling back V63

Schema V63 (4.5.4, the ledger of received agent reports) adds one table, `agent_batches`, with three indexes, and
nothing else: no existing table changes. A build that does not know V63 refuses the database ("newer than this
build"); restoring the backup taken before the update is the simple way back. To go back by hand, stop DENIS on every
node first, then:

```sql
-- PostgreSQL (one transaction)
BEGIN;
DROP TABLE agent_batches;
UPDATE schema_version SET version = 62 WHERE version = 63;
COMMIT;
```

```sql
-- SQLite (sqlite3 denis.db)
DROP TABLE agent_batches;
PRAGMA user_version = 62;
```

What is lost: the ledger (which reports were interrupted, refused or never arrived over the last 7 days). No device,
alert or setting is touched; the older build then acknowledges a resent report by its number alone, as it did before.
The next start of a 4.5.4 build creates the table again, empty. To go further back, continue with "Rolling back V62".
On PostgreSQL, `denis db undo-v58` refuses a database that is at version 63: do the steps above first. The SQLite
steps are run against a real file in `store/sqlite/tests_v63.rs`.

### Rolling back V64

Schema V64 (4.5.4) adds two tables, `agent_outbox` and `agent_outbox_dropped`: the disk queue in which a remote agent
keeps its reports until the master has acknowledged them (see
[A site keeps collecting while the master is away](deployment.md#a-site-keeps-collecting-while-the-master-is-away)).
They are created in every database and stay empty on a master. Nothing else changes. A build that does not know V64
refuses the database ("newer than this build"). To go back by hand, stop DENIS first, then:

```sql
-- PostgreSQL (one transaction)
BEGIN;
DROP TABLE agent_outbox_dropped;
DROP TABLE agent_outbox;
UPDATE schema_version SET version = 63 WHERE version = 64;
COMMIT;
```

```sql
-- SQLite (sqlite3 denis.db, or the agent's own database)
DROP TABLE agent_outbox_dropped;
DROP TABLE agent_outbox;
PRAGMA user_version = 63;
```

What is lost: on an agent, the reports that were still waiting for the
master, and the count of the ones the queue had already given up; send them first if you can (start the agent with
the master reachable and wait until the log stops saying that reports wait). On a master nothing is lost: the tables
are empty there. The next start of a 4.5.4 build creates the tables again, empty. To go further back, continue with
"Rolling back V63". The SQLite steps are run against a real file in `store/sqlite/tests_v64.rs`.

### Rolling back V65

Schema V65 (4.6.0) is a marker step: it changes no table. Its only effect is one settings row, `schema.min_reader`
(`{"schema": 65, "version": "4.6.0"}`, the compatibility floor), written in the same transaction on SQLite and
PostgreSQL (on PostgreSQL in the main schema and in each tenant's). V65 raises the floor: a build that does not know
V65 refuses the database ("newer than this build"). To go back by hand, stop DENIS first, then:

```sql
-- PostgreSQL (one transaction; in a tenant schema too, with its search_path)
BEGIN;
SET LOCAL denis.fence_exempt = 'maintenance';  -- the settings table is behind the write fence
DELETE FROM settings WHERE key = 'schema.min_reader';
UPDATE schema_version SET version = 64 WHERE version = 65;
COMMIT;
```

```sql
-- SQLite (sqlite3 denis.db, a tenant's or the agent's own database)
DELETE FROM settings WHERE key = 'schema.min_reader';
PRAGMA user_version = 64;
```

Nothing is lost. The next start of a 4.6.0 build writes the row again. To go further back, continue with
"Rolling back V64". The SQLite steps are run against a real file in `store/sqlite/tests_v65.rs`.

### Rolling back V66

Schema V66 (4.6.0) adds four tables for the health of the switches DENIS reads: `port_samples` (the traffic and error
history of each port), `port_last` (the last reading of each port), `switch_polls` (one row per attempt to read a
switch) and `infra_conditions` (the faults that are open, such as a watched link that is down), and one index on the
notifications (`notifications_open`). Nothing else changes, and V66 keeps the compatibility floor: a 4.6.0 build that
does not know V66 uses such a database as it is (SQLite; on PostgreSQL an older build refuses it; see [Going back without a restore](updates.md#going-back-without-a-restore-from-460)),
it just does not write or prune the four tables. To remove them by hand anyway, stop DENIS first (on a database at
V67 or newer, take those off first, the newest first, down to "Rolling back V67"), then:

```sql
-- PostgreSQL (one transaction; in a tenant schema too, with its search_path)
BEGIN;
DROP INDEX notifications_open;
DROP TABLE infra_conditions;
DROP TABLE switch_polls;
DROP TABLE port_last;
DROP TABLE port_samples;
UPDATE schema_version SET version = 65 WHERE version = 66;
COMMIT;
```

```sql
-- SQLite (sqlite3 denis.db, a tenant's or the agent's own database)
DROP INDEX notifications_open;
DROP TABLE infra_conditions;
DROP TABLE switch_polls;
DROP TABLE port_last;
DROP TABLE port_samples;
PRAGMA user_version = 65;
```

What is lost: the port history and the record of switch readings; an open link or switch fault is forgotten, and its notice
stays marked as open in the notification centre (nothing closes it any more). The next start of a build with V66
creates the tables again, empty. To go further back, continue with "Rolling back V65". The SQLite steps are run against
a real file in `store/sqlite/tests_v66.rs`.

### Rolling back V67

Schema V67 (4.6.0) adds one table for RADIUS accounting: `radius_sessions`, one row per network sign-in that the
listed switches, controllers or RADIUS servers reported (who signed in, from which hardware address, on which access
device and port, since when, and how it ended), with its indexes. Nothing else changes, and V67 keeps the compatibility
floor: a 4.6.0 build that does not know V67 uses such a database as it is (SQLite; on PostgreSQL an older build refuses it; see [Going back without a restore](updates.md#going-back-without-a-restore-from-460)),
it just does not write, prune or show the table. To remove it by hand anyway, stop DENIS first (on a database at V68 or
newer, take those off first: "Rolling back V71", "Rolling back V70", "Rolling back V69", "Rolling back V68"), then:

```sql
-- PostgreSQL (one transaction; in a tenant schema too, with its search_path)
BEGIN;
DROP TABLE radius_sessions;
UPDATE schema_version SET version = 66 WHERE version = 67;
COMMIT;
```

```sql
-- SQLite (sqlite3 denis.db, a tenant's or the agent's own database)
DROP TABLE radius_sessions;
PRAGMA user_version = 66;
```

Dropping the table drops its indexes with it. What is lost: the record of network sign-ins (the open ones and the
history of ended ones). Nothing on the network changes, and a Disconnect that was sent stays in the list of actions.
The next start of a build with V67 creates the table again, empty; the access devices fill it again with their next
accounting records. To go further back, continue with "Rolling back V66". The SQLite steps are run against a real file
in `store/sqlite/tests_v67.rs`.

### Rolling back V68

Schema V68 (4.6.0) extends the health of the switches DENIS reads: six columns on `switch_polls` (processor, memory,
Power over Ethernet supply, and which source answered), two on `port_last` (how often a link changed, and when it last
changed), and four tables: `port_link_changes` (one row per reading in which a port's link changed), `poe_ports` (the
newest state of each PoE port), `port_hourly` and `switch_hourly` (the hourly figures that keep a long history small).
Nothing else changes, and V68 keeps the compatibility floor: a 4.6.0 build that does not know V68 uses such a database
as it is (SQLite; on PostgreSQL an older build refuses it; see [Going back without a restore](updates.md#going-back-without-a-restore-from-460)); it leaves the new
columns empty and does not write or prune the four tables. To remove the tables by hand anyway, stop DENIS first (on a
database at V69 or newer, take those off first: "Rolling back V71", "Rolling back V70", "Rolling back V69"), then:

```sql
-- PostgreSQL (one transaction; in a tenant schema too, with its search_path)
BEGIN;
DROP TABLE switch_hourly;
DROP TABLE port_hourly;
DROP TABLE poe_ports;
DROP TABLE port_link_changes;
UPDATE schema_version SET version = 67 WHERE version = 68;
COMMIT;
```

```sql
-- SQLite (sqlite3 denis.db, a tenant's or the agent's own database)
DROP TABLE switch_hourly;
DROP TABLE port_hourly;
DROP TABLE poe_ports;
DROP TABLE port_link_changes;
PRAGMA user_version = 67;
```

The eight added columns stay: SQLite cannot remove a column on every version DENIS supports, and a build without V68
never names them. Dropping `port_hourly` drops its index. What is lost: the hourly history of ports and switches, the
record of link changes and the PoE port states. Nothing on the network changes. The next start of a build with V68
creates the tables again, empty, and finds the columns as they were. To go further back, continue with "Rolling back
V67". The SQLite steps are run against a real file in `store/sqlite/tests_v68.rs`.

### Rolling back V69

Schema V69 (4.6.0) adds three tables for service availability checks: `check_runs` (one row per run of a check: when,
the outcome, a reason code and numbers such as the answer time, never text the target sent), `check_state` (the state of
each check and when it is due) and `check_hourly` (the hourly figures). The checks themselves are a setting
(`checks.list`), not a table, and stay. Nothing else changes, and V69 keeps the compatibility floor (SQLite; on PostgreSQL an older build refuses a newer
database). To remove the
tables by hand anyway, stop DENIS first (on a database at V70 or V71, take those off first: "Rolling back V71",
"Rolling back V70"), then:

```sql
-- PostgreSQL (one transaction; in a tenant schema too, with its search_path)
BEGIN;
DROP TABLE check_hourly;
DROP TABLE check_state;
DROP TABLE check_runs;
UPDATE schema_version SET version = 68 WHERE version = 69;
COMMIT;
```

```sql
-- SQLite (sqlite3 denis.db, a tenant's or the agent's own database)
DROP TABLE check_hourly;
DROP TABLE check_state;
DROP TABLE check_runs;
PRAGMA user_version = 68;
```

What is lost: the results and the history of the checks; an open notice of a check stays marked as open in the
notification centre (nothing closes it any more). The list of checks stays. The next start of a build with V69 creates
the tables again, empty, and the checks run again from their next due time. To go further back, continue with "Rolling
back V68". The SQLite steps are run against a real file in `store/sqlite/tests_v69.rs`.

### Rolling back V70

Schema V70 (4.6.0) adds two tables for configuration change tracking: `config_state` (for each watched device, the
result of the newest collection and the device's own time stamps it is compared against) and `config_events` (one row
per change, save, or restart with unsaved changes), with two indexes. No configuration, command or user name is stored.
Nothing else changes, and V70 keeps the compatibility floor (SQLite; on PostgreSQL an older build refuses a newer
database). To remove the tables by hand anyway, stop DENIS first (on
a database at V71, take V71 off first: "Rolling back V71"), then:

```sql
-- PostgreSQL (one transaction; in a tenant schema too, with its search_path)
BEGIN;
DROP TABLE config_events;
DROP TABLE config_state;
UPDATE schema_version SET version = 69 WHERE version = 70;
COMMIT;
```

```sql
-- SQLite (sqlite3 denis.db, a tenant's or the agent's own database)
DROP TABLE config_events;
DROP TABLE config_state;
PRAGMA user_version = 69;
```

Dropping the tables drops their indexes with them. What is lost: the record of configuration changes and the state each
device was compared against; the next collection after the upgrade is then a first one again (it makes no event). Nothing on the network changes. To go further back, continue with "Rolling back V69". The SQLite steps are
run against a real file in `store/sqlite/tests_v70.rs`.

### Rolling back V71

Schema V71 (4.6.0) adds three indexes and nothing else: `radius_sessions_heard` (the session time job, which judges on
DENIS's own clock), `radius_sessions_last` (the order of the Sign-ins list) and `config_events_detected` (the removal
of old configuration events). No table, column or row changes, and V71 keeps the compatibility floor: a build that does
not know V71 uses such a database as it is (SQLite; on PostgreSQL an older build refuses it). To remove the indexes by hand anyway, stop DENIS first, then:

```sql
-- PostgreSQL (one transaction; in a tenant schema too, with its search_path)
BEGIN;
DROP INDEX radius_sessions_heard;
DROP INDEX radius_sessions_last;
DROP INDEX config_events_detected;
UPDATE schema_version SET version = 70 WHERE version = 71;
COMMIT;
```

```sql
-- SQLite (sqlite3 denis.db, a tenant's or the agent's own database)
DROP INDEX radius_sessions_heard;
DROP INDEX radius_sessions_last;
DROP INDEX config_events_detected;
PRAGMA user_version = 70;
```

Nothing is lost: only these reads get slower on a large table. The next start of a build with V71 creates the indexes
again. To go further back, continue with "Rolling back V70". The SQLite steps are run against a real file in
`store/sqlite/tests_v71.rs`.

### The delivery outbox has no switch

From 4.4 the channel messages (the alert stream, grouped incidents) are written to the outbox in the same database
step that moves the channel's cursor, and a sender sends them with retries; a receiver that is down, a restart or a
failover no longer loses a message, and a message is sent at least once, never exactly once (after a crash between the
send and the note that it was sent, the receiver may get it twice, with the same `Idempotency-Key` on a generic webhook).
There is no setting to turn the outbox off and no second, inline sending path: a switch that only stopped the sender
would leave messages piling up unsent. The way back is the rollback above (the cursors are not touched, so an older
build resumes from them). Notices (enforcement actions, MSP sessions, connector and capture problems) go through the
same outbox, one row per channel, so a channel that is down is retried on its own and the others are not held up.
Enforcement and MSP messages are sent in their own lane per channel, ahead of the alert stream: an alert that keeps
failing never delays them, and they are never folded into a summary. The figures are on
`/metrics` (`denis_delivery_queued`, `denis_delivery_oldest_seconds`, `denis_delivery_dead_total`,
`denis_delivery_dropped_total`, `denis_delivery_attempts_total`) and as Health warnings.

In the console, *Settings → Notifications* shows the same figures per channel (messages waiting and the age of the
oldest, delivered and given up on in 24 hours, the last success and error, from the database so they survive a
restart). **Send again those not delivered** on a channel, and **Send again** on a row of the *Deliveries* list, queue
a given-up message once more (alerts up to 7 days old); both are audited. The SIEM incidents stream and the command-line
webhook are channels of the same queue. A message is kept 30 days after it was delivered and 90 days after it was given
up on; waiting messages are never pruned by count.

## Refreshing the threat list

`--threat-list bad-ips.txt` is re-read whenever the file changes, so refreshing it is a cron job that replaces the
file (write to a temporary name and rename, so DENIS never reads a half-written file). If the new file is broken,
DENIS keeps the old list and logs a warning. For the public blocklists (abuse.ch Feodo Tracker, ThreatFox and URLhaus, Spamhaus DROP and
ASN-DROP, the Tor exit list) DENIS can fetch and
refresh itself, opt-in under *Settings* → **Data** → **Threat list sources**, see
[Detection rules › `threat_list_match`](detection-rules.md#threat_list_match-contact-with-a-known-bad-address-needs---flows-and-a-threat-list).

## Logs

DENIS logs to standard error (systemd: `journalctl -u denis`). `RUST_LOG=debug` adds detail. Secrets (webhook
URLs, keys, passwords, tokens) are never logged.

## Details from the console

Explanations that used to be printed on the console screens. The console shows a short version behind the small (i) button after the label it explains; "More in the docs" in it leads here.

* Health: problems come first, in groups. Then one row for each function, also for the ones that are off, then this server and its background work. See [The Health page](#the-health-page).
* How often the newest local backup is also pushed to your configured backup upstream, independent of the schedule above.
* 1 to 1095 days (3 years). 180 days (6 months) is a reasonable default; a busy network with flow accounting on can generate a large database over long periods, so keep this as short as your reporting needs allow.
