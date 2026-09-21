# Operations: backup, demo data, monitoring, upgrades

## Backup and restore

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

**Settings → Demo data and reset** (administrators) has three buttons:

* **Load demo data**: a fictional company so you can explore every screen. Marked as demo; ignored by the
  collector and the detectors; a banner says it is loaded. (API: `POST /api/demo`; command line: `denis demo load`.)
* **Remove demo data**: deletes only the demo records. (`DELETE /api/demo`; `denis demo remove`.)
* **Erase all data**: for when you have finished exploring, or are moving from a trial to the real network. It deletes
  **every device, edit, alert, baseline, communications record, trend sample and remote site**, forgets what was
  learned, and starts a **new learning period**. It keeps user accounts and sign-in methods (passkeys, API tokens),
  notification channels, branding, rule settings, agent tokens and the **audit log** (which records that the erase
  happened and who did it). You must type `ERASE ALL DATA` to confirm. **It cannot be undone: take a backup first.**
  (`POST /api/data/erase` with `{"confirm": "ERASE ALL DATA"}`; with DENIS stopped, `denis erase --yes`.)

## Monitoring DENIS itself (Prometheus)

`GET /metrics` exposes counts and health in the Prometheus text format: devices (total, online, by type), open
alerts by severity, findings by severity, learning time left, remote sites and how long ago each reported,
failing exports and notification channels, maintenance mode, uptime. It contains **no device names, addresses or
alert text**.

It needs the same sign-in as the console. For Prometheus, create a **viewer API token** (*Users* → API tokens) and
give it as a bearer token:

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
`denis_site_last_report_age_seconds > 900` (a remote site went quiet), `denis_alerts_unacknowledged{severity="high"} > 0`.

## Upgrading

DENIS can update itself from GitHub releases, with a backup first ([Updates](updates.md)). To update by hand:

1. Take a backup (above).
2. Replace the `denis` binary and restart the service.

The database is upgraded in place, in small transactional steps; a crash mid-upgrade leaves it at a consistent
older version. A database newer than the program is refused with a clear message (never silently downgraded).

## Refreshing the threat list

`--threat-list bad-ips.txt` is re-read whenever the file changes, so refreshing it is a cron job that replaces the
file (write to a temporary name and rename, so DENIS never reads a half-written file). If the new file is broken,
DENIS keeps the old list and logs a warning.

## Logs

DENIS logs to standard error (systemd: `journalctl -u denis`). `RUST_LOG=debug` adds detail. Secrets (webhook
URLs, keys, passwords, tokens) are never logged.
