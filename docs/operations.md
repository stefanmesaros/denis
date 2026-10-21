# Operations: backup, demo data, monitoring, upgrades

## Backup and restore

**In the console** (*Health* → Backups, administrators): DENIS backs its own database up **every day** and keeps the
newest 7 (change or switch off the schedule there, keep up to 60). *Back up now* makes one by hand; each backup can be
**downloaded** or deleted. They are written to the `backups` folder beside the database (`/var/lib/denis/backups/`
for the installer's layout), named `denis-auto-…`, `denis-manual-…`; the copies made before an update
(`denis-before-…`) are listed too, but the updater looks after those. Only scheduled backups are ever removed
automatically. DENIS refuses to make a backup when the disk could not hold it, and the Health page warns when the
newest backup is too old. A backup on the same disk does not survive the disk: fetch some copies elsewhere. If a backup fails part-way (the disk fills up, say), the unfinished file is removed, so the list never offers a partial
copy for restore. A database file that is damaged at start is reported with its path.

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

**Restore:** stop DENIS, copy the backup over the database file (`denis.db`), start DENIS. Test a restore once
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
* **Erase all data**: for when you have finished exploring, or are moving from a trial to the real network. It deletes
  **every device, edit, alert, baseline, communications record, trend sample and remote site**, forgets what was
  learned, and starts a **new learning period**. It keeps user accounts and sign-in methods (passkeys, API tokens),
  notification channels, branding, rule settings, agent tokens and the **audit log** (which records that the erase
  happened and who did it). You must type `ERASE ALL DATA` to confirm. **It cannot be undone: take a backup first.**
  (`POST /api/data/erase` with `{"confirm": "ERASE ALL DATA"}`; with DENIS stopped, `denis erase --yes`.)

## Retention

*Settings → Data → Data retention* (administrators) sets how long events, alerts and trend samples are kept
(1 to 1095 days) before DENIS deletes them on its own, within the hour, no restart. Until a value is saved there
the `--retention-days` flag (default 90) applies. The asset register, baselines, accepted risks, saved reports
and the audit log are not affected by retention. The same page sets how long the **decision log** is kept (who
acknowledged, resolved or re-opened which alert or incident, when and why): 1095 days (3 years) by default, 90 to 3650
days, or 0 to keep it for ever. It is independent of the period above, so a decision can still be read after its alert
has been deleted. Nothing else removes decision-log rows: not deleting or merging a device, not *Erase all data*
(the rows hold no personal data beyond the user name and the note a person typed).

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

Gauges and counters for the conditions in the next section: `denis_capture_parser_panics`, `denis_signal_buffer_saturated`,
`denis_clock_skewed_agents`, `denis_snmp_incomplete_switches`, `denis_notifications_dropped`, and, for the
industrial layer-2 decoders, `denis_ot_sv_sampled_out_total` (Sampled Values frames skipped by the one-per-second
sampling) and `denis_ot_l2_appid_refused_total` (control blocks refused because a device already has the most it keeps),
and for IP fragments of industrial traffic `denis_ot_fragments_reassembled_total`,
`denis_ot_fragments_dropped_total{reason="timeout|limit|overlap|oversize|tiny|malformed"}`,
`denis_ot_fragments_duplicate_total` and `denis_ot_checksum_mismatch_total{reassembled="false|true"}` (industrial
messages with a wrong TCP/UDP checksum, still decoded; see the OT guide's limits).

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
| `denis_ot_conversations_dropped_total`, `denis_ot_control_conversations_dropped_total` | Industrial messages not counted because a ten-second window's conversation table was full, and how many of those were control commands (kept first, so normally zero). The Health page warns while the first is above zero. |
| `denis_ot_stream_carried_total`, `_completed_total`, `_gaps_total`, `_oversize_total`, `_duplicates_total`, `_capped_total`, `_evicted_total` | What the industrial-protocol message tracking did: incomplete messages held for the next TCP segment and completed, continuations lost to missing or out-of-order packets, messages too long to be read, exact duplicate segments ignored, segments with more messages than are read, and connection states forgotten because too many were open. Health warns on any capped or evicted, and on a thousand gaps or over-long messages. |
| `denis_db_flush_total`, `denis_db_flush_failures_total`, `denis_db_flush_overruns_total` | Device writes done, failed (their rows are kept and retried), and rounds skipped because the previous write was still running. |
| `denis_db_flush_seconds_last`, `denis_db_flush_seconds_max`, `denis_db_flush_seconds_sum` | How long the last, the slowest and all device writes took. A write regularly near two seconds is the sign to look at the disk. |

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
| N alert notifications were not sent | The delivery queue was full, usually because a webhook or channel is slow or down. The alerts are still stored and shown in the console; check Settings → Notifications. Shown for an hour after the last dropped notification. |
| Agent reports (a service line) | Agents are enrolled but none has reported for 6 hours. Advisory. |

These warnings clear when the cause stops. A restart clears the counters (not the cause).

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

**PostgreSQL is not a speed-up for one site.** It stays the choice for high availability. Writing a changed device is a
round trip and a durable commit each (about 4 ms against 0.1 ms on SQLite), and the write cycle is currently one commit
per device: on the test setup (PostgreSQL in Docker on a laptop, so slower than a native server) it took 1.5 s at
10,000 devices with no users and was over the 2-second cycle at 50,000. Plan on up to about 5,000 devices per site on
PostgreSQL until the write path is batched, and treat that as unverified on server hardware.

## Upgrading

DENIS can update itself from GitHub releases (or, if GitHub cannot be reached, from the fallback host), with a backup
first, and can update its remote agents from the console ([Updates](updates.md)). To update by hand:

1. Take a backup (above).
2. Replace the `denis` binary and restart the service. On a Linux service installed with `install.sh`, just run the
   newest `install.sh` again: it does both steps ([Deployment](deployment.md#installing-on-a-linux-server-a-permanent-service)).

The database is upgraded in place, in small transactional steps; a crash mid-upgrade leaves it at a consistent
older version. A database newer than the program is refused with a clear message (never silently downgraded).

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

* Is DENIS itself in good shape? Problems are listed first, in plain words; the rest is what to look at when something seems slow or the disk fills up.
* How often the newest local backup is also pushed to your configured backup upstream, independent of the schedule above.
* 1 to 1095 days (3 years). 180 days (6 months) is a reasonable default; a busy network with flow accounting on can generate a large database over long periods, so keep this as short as your reporting needs allow.
