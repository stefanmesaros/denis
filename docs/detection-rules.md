# Detection rules

**See and change them in the console:** the **Rules** tab lists every rule with what it does, what it needs, whether
it is on, its weight and its thresholds. Administrators can switch a rule off, turn its weight up or down
(`0` = off, `0.5` = half as loud, `2` = twice, scores are capped at 100), change the minimum score and tune the
thresholds (for example how many standard deviations count as an unusual transfer, or how long a device must be
silent). Changes apply within seconds, survive restarts, are limited to sane ranges on the server and are written to
the audit log; *Reset everything* returns to the defaults. Command-line options (`--min-score`, `--rule-weight`,
`--silent-minutes`, …) set the starting values; a value saved in the console wins over them. The console tunes the reviewed rules below and adds three things of your own, described in
[Making the rules fit your network](#making-the-rules-fit-your-network). API: `GET/PUT/DELETE /api/rules`.

All rules are **rule-based and explainable**: each alert shows the factors that produced its score. Scores are
0–100; below `--min-score` (default 30) an event is only logged. Each rule can be scaled or disabled:
`--rule-weight <rule>=<weight>` (`0` disables, `0.5` halves, up to `5`).

Rule names for `--rule-weight`: `new_device`, `new_destination`, `volume_anomaly`, `new_port`,
`unusual_hours`, `arp_conflict`, `device_silent`, `rogue_dhcp`, `new_device_burst`, `threat_list_match`,
`ot_new_conversation`, `ot_control_command`, `ot_internet_exposure`, `ot_purdue_skip`, `ot_unexpected_writer`,
`ot_command_watch`, `ot_write_escalation`.

Every alert carries **advice**: click an alert (Alerts or Events tab) to see its summary, *why* it scored what
it did, and *what to do next*. The same advice is in `GET /api/meta/options` (`advice`).

## Network rules

### `new_device`: a device joined
Fires when an asset first appears **after** the learning period (~60 seconds later, once fingerprinting had
time to work). Score 50, +15 if the type is unidentified, +10 if the manufacturer is unknown, −15 for a private
(randomised) MAC. Devices you registered by hand never trigger it.
*Typical false positive:* a visitor's phone. Tune: lower the weight, or use a guest VLAN.

### `new_destination`: first contact with an address *(needs `--flows`)*
A device that has been observed long enough contacts an IP it never used. Score 35, +15 if no other device
uses that address, −10 if it is in the same /24 as one the device already uses (CDN neighbours), +15 for an
unusual port, +10/+20 for ≥1 MB/≥50 MB sent in the first window, −10/−20 for devices that already talk to
≥100/≥500 hosts (laptops and phones naturally do). One alert per device per window.
*Best for:* NAS, cameras, printers, servers. *Noisy for:* laptops and phones; give it a lower weight.

### `new_port`: a service port never used before *(needs `--flows`)*
A device with an established set of ports uses a **new service port** (below 32768, not 53/80/123/443) towards a
known destination. Score 40, +15 for remote-administration/file-sharing/database ports (22, 23, 445, 3389,
3306, …), +10 for ≥1 MB, −10 for ICMP.

### `volume_anomaly`: unusual outbound volume *(needs `--flows`)*
Bytes sent outside in a 5-minute window exceed the device's own average by ≥3 standard deviations (the
deviation is floored so very regular devices do not alert on trivial changes; buckets under 5 MB are ignored).
Score 40 + 10 per extra deviation. An incident is not learned as the new normal. One alert per device per hour.

### `unusual_hours`: active when it never is *(needs `--flows`)*
After a week of history, activity (≥ 50 kB) in an hour of the day that holds less than 2% of the device's
history. Local time. Score 30–60. Six-hour cooldown.

### `arp_conflict` / `arp_mismatch`: address hijacking
Two devices claim one IP address within 5 minutes of each other, or an ARP message has an inconsistent sender
address. Score 70 (mismatch 45), +25 if the contested address is the **default gateway**, +15 if the claimant
takes ≥3 addresses in 10 minutes. Not subject to learning. At most 5 alerts per claimant per 10 minutes.
*Investigate:* the claimant MAC, which switch port it is on, whether a DHCP server hands out duplicates.

*Sibling interfaces:* one router or access point often answers for the same IP from several radios or
interfaces whose hardware addresses differ only in the last byte (seen on ASUS mesh gear). Such a pair scores 50
lower, so it is only logged, unless the contested address is the gateway. (A forger who picks a sibling
address is therefore only caught when the target is the gateway.)

### `device_silent` / `agent_offline`: a reliable device disappeared
A device that was online in ≥90% of hours over the last week (and observed ≥48 h) has not been seen for
`--silent-minutes` (default 120). Score 45, +15 for routers/NAS/servers/cameras, +10 if it was essentially
never offline, −10 for private-MAC devices. One alert per outage; an info event when it returns. If a remote
agent stops reporting, **one** `agent_offline` alert is raised instead of one per device.
*Needs active sweeps:* disabled under `--passive-only`.

### `rogue_dhcp`: a new DHCP server
A device that has not answered DHCP requests before starts handing out addresses (OFFER/ACK seen on the wire).
Servers seen during the learning period are the normal ones and are remembered across restarts. Score 70; 40 if it
is the default gateway (a router newly switching DHCP on). Reported once per device. A rogue DHCP server can give
every client a wrong gateway or DNS server, so this is worth knowing about on the first day.
*Investigate:* the MAC and switch port in the alert; enable DHCP snooping on managed switches.

### `new_device_burst`: many devices at once
Five or more new devices within ten minutes (after the learning period). Score 50, +4 per extra device, up to 80.
One alert per half hour; each device still gets its own `new_device` entry. Fits a scan, an ARP flood or a bridged
network, but also a meeting or a delivery of new equipment.

### `threat_list_match`: contact with a known-bad address *(needs `--flows` and `--threat-list`)*
```bash
denis run --flows --threat-list /var/lib/denis/bad-ips.txt
```
The file lists IPv4 addresses and networks, one per line (`203.0.113.9`, `198.51.100.0/24`; `#` comments allowed):
the format of the free lists from abuse.ch (Feodo Tracker), Spamhaus DROP and similar. DENIS ships no list and never
downloads one: refresh the file yourself (for example with cron); DENIS notices when it changes and reloads it, and
keeps the old list if the new file is broken. A device contacting a listed address scores 85 (+10 if it sent ≥100 kB),
from the first day (no learning period), once per device and address per six hours. Traffic is only seen when it
crosses the interface DENIS listens on (see [Concepts](concepts.md#visibility-what-can-be-seen-from-where)).

## Industrial (OT) rules
Details and examples are in the [OT guide](ot-guide.md). In short:

* `ot_new_conversation`: a communication path that did not exist during learning.
* `ot_control_command`: stop/start, program download, restart. Never suppressed by learning.
* `ot_internet_exposure`: an industrial protocol crossing the network boundary.
* `ot_purdue_skip`: two industrial devices talk across **more than one Purdue level** (a controller straight to an
  office PC; L1 ↔ L4, L2 ↔ L4, L3.5 ↔ L1…). Needs the Purdue level on both devices in the register. Score 50, +15 with
  write/control commands. Adjacent levels and the DMZ (3.5) next to 3 or 4 are fine. Once per pair per six hours.
* `ot_unexpected_writer`: a **phone, printer, camera, IoT gadget or similar** (by device type, including your
  correction) sends write or control commands to an industrial device. Score 65, +15 for control commands.
  Engineering laptops typed as *computer* are deliberately not judged by this rule.
* `ot_write_escalation`: a path that **only ever read** from an industrial device starts **writing** to it: how a
  monitoring connection turns into a controlling one. Score 60, +10 for an industrial target, +15 with control
  commands. Never during the learning period; once per pair per six hours (adjustable).
* `ot_command_watch`: **your own watches** for specific commands: see below and the [OT guide](ot-guide.md#command-watches).

## Findings: standing problems, with a fix

Alerts are events; **findings** (the *Findings* tab, `GET /api/findings`) are conditions that stay true until
you fix them, so they vanish by themselves once fixed. Devices with the same problem are grouped into one
finding, each with why it matters and what to do.

| Finding | Severity | Meaning |
|---|---|---|
| `lost_device_online` | high | a device you marked *lost* or *stolen* was seen in the last 7 days |
| `telnet_open` | high | Telnet open |
| `rdp_open`, `vnc_open`, `ftp_open`, `mysql_open`, `winbox_open` | medium | risky remote-access / data services reachable |
| `retired_device_online` | medium | a *retired* device is still on the network |
| `critical_no_owner` | medium | criticality high/critical but no owner entered |
| `smb_open`, `mqtt_open` | low | file sharing on a non-computer; open MQTT broker |
| `ot_no_purdue_level` | low | industrial device without a Purdue level |
| `unidentified` | low | type unknown and no name entered |
| `warranty_expired` / `warranty_expiring` | low / info | from the warranty date you entered |

Only devices seen in the last 7 days are considered, and devices whose status is *spare*, *retired*, *lost*
or *stolen* are not nagged about exposed services. Exposure findings come from the port scan, so they appear
only for devices that have been scanned (never industrial devices).

## Making the rules fit your network

On the **Rules** page (administrators):

* **Weight, minimum score and thresholds**, as before. Every rule also has **Alert only from score**: below it that
  rule is only logged, whatever the global minimum is. New settings include the burst size and window of
  `new_device_burst`, the repeat gaps of the OT rules and how many Purdue levels apart count as skipping.
* **Exceptions**, per rule: devices (by name), **device types**, **tags** and **networks** (`10.0.5.0/24`) that
  the rule stays quiet about. Typical uses: "never tell me about new destinations for the printers", "the lab VLAN
  may do anything", "this HMI is allowed to write". For industrial alerts the **sending** device counts too, so
  excepting the engineering station silences its control commands. An excepted alert is not stored at all; the
  audit log records who set the exception.
* **OT command watches** ([OT guide](ot-guide.md#command-watches)): tell DENIS which commands to alert on, for
  which targets, and from which senders never.

*Reset everything to defaults* returns weights, thresholds and minimum scores to their defaults and **keeps** your
exceptions and watches (they are your content, not tuning).

## Acknowledging and false positives

**Acknowledge** an alert once handled. It stops counting toward the device's risk (and you can *Undo*).
For a recurring harmless pattern, prefer lowering that rule's weight or raising `--min-score` over ignoring
alerts. Repeats are suppressed by cooldowns, so an alert is not a flood.
