# Exporting data: OpenObserve and syslog/CEF

DENIS can push its data to [OpenObserve](https://openobserve.ai) so a customer who already runs it (for
logs, deep-packet-inspection output, etc.) can see network inventory, alerts and trends in the same console.

## Turn it on

```bash
export DENIS_OPENOBSERVE_USER='root@example.com'
export DENIS_OPENOBSERVE_PASSWORD='…'          # environment only, never a command-line flag
denis run --openobserve-url https://openobserve.example.com
```

| Option | Default | Meaning |
|---|---|---|
| `--openobserve-url` / `DENIS_OPENOBSERVE_URL` | off | server address only (no path, user name or query) |
| `--openobserve-org` / `DENIS_OPENOBSERVE_ORG` | `default` | organisation |
| `--openobserve-prefix` | `denis` | stream name prefix |
| `--openobserve-interval` | `15` | seconds between export cycles (5–3600) |

With systemd, put the two credentials in an `EnvironmentFile=` readable only by the service user.

## What is sent

| Stream | Contents | When |
|---|---|---|
| `denis_events` | every event and alert: kind, severity, score, summary, details, and the device's name/IP/MAC | as they happen |
| `denis_audit` | who changed what (sign-ins, edits, user and token administration) | as they happen |
| `denis_metrics` | 5-minute trend samples: devices, online, bytes in/out, alerts, per site | once a sample is 10 minutes old |
| `denis_assets` | the inventory, including the fields you maintain (owner, location, serial number, criticality, zone, Purdue level…) | when a device changes, and a full snapshot every 6 hours |

Timestamps are in `_timestamp` (microseconds), the field OpenObserve indexes on. History that already exists
is sent the first time you enable the export.

## Behaviour you can rely on

* **DENIS never waits for OpenObserve.** Detection and the UI are unaffected by a slow or dead server; the
  exporter simply catches up later from its saved position (kept in the database, so restarts resume).
* **At least once.** After a crash a batch may arrive twice. Events and audit entries carry their `id`;
  de-duplicate on it if that matters for your dashboards.
* **Health is visible**: the header shows `export ok 12s ago`, or `FAILING` with the reason underneath.
* Documents OpenObserve refuses (for example a field whose type clashes with an earlier schema) are logged
  and skipped rather than retried for ever.
* Trend samples that reach a master *late* from an agent (older than the newest sample already exported) are
  not exported.

## Security

* Credentials travel as HTTP Basic auth and are never logged or shown. Use **https://**; DENIS logs a
  warning if you use plain `http://` to another machine.
* Use a dedicated OpenObserve user that may only write to these streams.
* The audit log contains user names and the details of edits; treat the destination as sensitive.

## Not verified

The exporter is tested against a simulated OpenObserve endpoint (paths, authentication, batching, retry,
resume). It has **not yet been tried against a real OpenObserve server**: do that before promising it.

---

# Alerts to a SIEM (syslog / CEF)

```bash
denis run --syslog udp://siem.example.com:514        # or tcp://siem.example.com:6514
```

Every alert (not the low-level `info` events) is sent as an RFC 5424 syslog message whose body is an
ArcSight **CEF** record, which Splunk, QRadar, Wazuh, Microsoft Sentinel, Graylog and others parse natively:

```
<163>1 2026-09-20T21:42:48Z denis-host denis - arp_conflict - CEF:0|DENIS|DENIS|0.1.0|arp_conflict|192.0.2.10 claimed by two devices|8|rt=1789940568000 cs1Label=score cs1=85 cs2Label=eventId cs2=7 src=192.0.2.130 smac=02:00:5e:10:00:01 shost=Laptop-42 msg=+60 claims the gateway address; +25 first seen 2 min ago
```

* Facility `local4`; syslog severity error / warning / notice for high / medium / low; CEF severity 1–10.
* Fields: `src` (IP), `smac`, `shost` (the device's name), `cs1` score, `cs2` event id, `cs3` site (for agents),
  `msg` the reasons behind the score, `rt` event time in milliseconds.
* **UDP** sends one datagram per alert and cannot tell whether it arrived. **TCP** (newline-framed) is
  retried after a failure and the backlog is sent in order; use it when you can. There is no TLS syslog yet:
  keep it on a trusted network or a VPN.
* Like the OpenObserve export it runs from a saved position in the database, so a dead SIEM never affects
  detection, and delivery is at least once (de-duplicate on `cs2`).
* Text from the network (device names, hostnames) is escaped so it cannot forge CEF fields or extra records.
* Health shows in the header (`syslog ok …` / `FAILING`).
