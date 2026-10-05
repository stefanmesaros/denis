# Concepts

## How devices are found

| Technique | Kind | What it yields |
|---|---|---|
| ARP (requests, replies, sweep) | passive + active | the MAC ↔ IP pairing, the backbone of the inventory |
| DHCP | passive | the device's own hostname, vendor class ("MSFT 5.0", "android-dhcp"), and the list of options its DHCP client asks for, which identifies the client software (Windows, macOS, iOS, Android, Linux) even when the device has a private MAC and no name |
| mDNS / SSDP | passive | names, services (printer, AirPlay, Chromecast), model strings |
| LLDP / CDP / PROFINET DCP | passive | switches, access points and industrial devices announcing themselves |
| TCP handshakes, ping replies | passive + active | operating-system family (TTL, window size, option order) |
| Industrial protocols | passive | which devices are PLCs/HMIs and who talks to whom ([OT guide](ot-guide.md)) |
| Port scan (33 common ports) | active | open services |

The manufacturer comes from the IEEE registry compiled into the program (works offline). Phones and laptops
that use a **private/randomised MAC address** have no manufacturer; DENIS labels them *(private MAC)*.

Every guess of device type and OS is a set of weighted rules, and the device page lists the rules that fired
under **Why this guess**. If DENIS is wrong, correct it (Edit asset → Device type); your value wins everywhere.

## Visibility: what can be seen from where

A network switch sends each machine only the traffic addressed to it, plus broadcasts. Therefore:

* **Discovery** works from any machine on the network segment (broadcast/multicast is visible to all).
* **Traffic analysis** (`--flows`: who talks to the Internet, how much, on which ports; industrial
  conversations) only sees traffic that *crosses the interface DENIS listens on*. To see a whole network,
  place the collector where the traffic is:
  * on the **router/firewall** itself, or
  * on a **mirror/SPAN port** or network tap of a switch, or
  * one collector per segment.
* On an ordinary server on an ordinary port, `--flows` sees only that server's own traffic.
* **`--mirror-iface`** (repeatable) lets one instance do both at once: `--iface` keeps doing
  discovery exactly as above, and any number of extra, capture-only interfaces (each plugged into
  a mirror/SPAN port, one per VLAN say) are decoded into the same flow accounting — no separate
  `denis` process needed per VLAN. A mirror on a *different* subnet/VLAN than `--iface` also needs
  **`--mirror-subnet`** to name that range (a SPAN port usually has no address of its own to detect
  it from) — without it, that VLAN's traffic is invisible: not recognised as local, so nothing is
  decoded for it, with no error. See
  [Deployment](deployment.md#one-or-more-mirror-port-interfaces-for-whole-network-flow-visibility).
* **East-west traffic** (traffic between two of your own devices: a laptop and the file server, an
  HMI and a PLC) is **not recorded by default**, even with `--flows`: it shows internal behaviour
  that DENIS otherwise never sees. Switch it on per collector under Settings → Network interfaces
  (takes effect at once), or with `--east-west` on a remote agent. It is then kept as
  *relationship edges*: who talked to whom, over which protocol and port, first and last seen, and
  whether the client was seen opening the TCP connection (`initiator: syn`) or only guessed from the
  port numbers (`ports`). Bounded at every step (20,000 device pairs per 10-second capture window,
  256 edges per device for device peers and 256 for outside addresses, the general retention
  period); what each limit cut is on the Health page. Nothing alerts on east-west traffic yet. With it
  off, nothing between two of your own devices is recorded beyond the industrial conversations DENIS
  already decodes; see [Relationships](#relationships-and-the-investigate-section) below.
* **Passive DNS** (also opt-in, off by default) reads the DNS answers that cross the same interface and
  remembers which name each device looked up — but only the lookups that actually cross it: a mirror of the
  LAN side (or DENIS running on the resolver itself) sees every device's own lookups, a mirror of the WAN
  uplink only attributes every name to the router, an ordinary switch port sees nothing, and encrypted DNS
  (DoH, DoT) is never seen at all. See [Passive DNS](passive-dns.md).

Put **one collector per network segment**. Two collectors on the same segment (for example the master's own
capture plus an agent on the same LAN) report every device twice, once per site: a device's identity is
`(site, MAC)` by design, and the console has no way yet to say that two collectors watch one network. The fix is
designed (`MULTI_AGENT_DEDUP.md` in the repository) but not built.

## Learning period

A brand-new deployment knows nothing, so everything would look "new". For the first **24 hours** (adjustable
with `--learning-minutes`) DENIS only learns. Each remote site has its own learning period, and so does each
device's traffic baseline. Exceptions: ARP conflicts, industrial control commands and industrial protocols
crossing the network boundary alert immediately.

## Baselines

For each device with traffic, DENIS learns: the addresses it talks to, the ports it uses, how much it sends in a
5-minute window (mean and spread), and in which hours of the day it is active. Alerts are deviations from
*that device's own* normal, not from a global threshold.

## Scores, severity and tuning

Every alert has a **score from 0 to 100** and a list of the factors behind it (visible in the UI and in
notifications). Severity follows the score: below `--min-score` (30) it is only logged (*info*), 30–49 *low*,
50–69 *medium*, 70+ *high*.

Noisy? **Turn a rule down instead of off:** `--rule-weight new_destination=0.5` halves its scores; a weight of
`0` disables it. Raise `--min-score` to see fewer, more important alerts. See [Detection rules](detection-rules.md).

Related alerts about the same device (or the same recognisable attack pattern) are also grouped into one
**[incident](incidents.md)** with its own priority, so a multi-stage event is one thing to work rather than several
separate rows.

## Risk score

Each device also has a **risk score** (0–100) built from what it exposes and what it has done: open Telnet/RDP/
FTP…, an unidentified type, "unpatched-by-nature" categories (IoT, cameras), and its *unacknowledged* alerts
(recent and severe ones count more). The factors are listed on the device page. **Acknowledging** an alert
removes its contribution: the workflow is *investigate → acknowledge → risk drops*.
Criticality (Edit asset) makes alerts on an important device weigh more. It does not read that device's own
[Findings](detection-rules.md#findings-standing-problems-with-a-fix) or scanner results — a
known-exploited-vulnerability or end-of-life match does not raise this score on its own. Those standing facts are
what [Top exposures today](#top-exposures-today) ranks.

## Top exposures today

A short answer to "which devices should I look at first?". A device is on the list only if it has at least one
**anchor**, a standing fact serious enough on its own; every fact behind its place is listed as its own
`+N reason` line, with where it comes from (a banner, a scanner import, a finding, an incident, the asset
register). The points are fixed:

| Anchor (any one puts a device on the list) | Points |
|---|---|
| Known-exploited vulnerability (CISA KEV), from a software banner or a matched scanner CVE | 40 |
| Open incident at *Act now* or *Investigate today* | 35 |
| Critical scanner result (not already counted as known-exploited) | 30 |
| Open incident at *Review* or *Can wait* | 20 |
| High scanner result (only when there is no critical one) | 20 |
| Unsupported software (end of support) | 20 |
| Any other high-severity finding (Telnet open, a device marked lost seen online…) | 20 |

| Context (only added to a device that already has an anchor) | Points |
|---|---|
| An industrial device at Purdue level 0–2 | +25 |
| Rated *critical* | +20 |
| Rated *high*, or a server-class device / Purdue level 3 | +10 |
| Rated *low* | −10 |
| No owner recorded, on a device rated above normal | +5 |

The context is the same "what is at stake" assessment [incidents](incidents.md) are prioritised with, so the two
never disagree about how much a device matters. Each kind of fact counts once per device: twelve high scanner rows
are one line with "+11 more", not twelve. A finding whose risk has been accepted is not an anchor, and an
acknowledged incident is not open. The total is only an ordering key, not a 0–100 score. Nothing about
reachability ("can an attacker get to it?") is counted yet.

It appears on the Dashboard (the top five, with **Show all**) and, on a device that has an anchor, as **Why this is
a top exposure** on the device panel's Overview. You only ever see devices on sites you can read. API:
`GET /api/exposures` ([API](api.md)).

## Relationships and the Investigate section

DENIS keeps one **relationship** per device, peer (another device or an outside address), protocol and port, with
first and last seen, how much traffic and how many capture windows. Relationships come from traffic to outside
addresses (`--flows`), from the industrial conversations DENIS decodes, from east-west traffic when it is switched
on (above), and, once at upgrade to 3.2.0, from every device's learned baseline destinations (those have no port).
Each one says how DENIS knows it: **observed** (DENIS saw the traffic) or **inferred** (from a baseline only), and
whether the client side is **confirmed** (a TCP handshake was seen, or the protocol says so), **guessed** (from the
port numbers) or **unknown** (a device and an outside address).

An alert's dialog has a collapsible **Investigate** section, loaded the first time you open it: the device's other
events in the hour either side of the alert, what DENIS recorded between the device and the alert's other party
(with that address's network context), which other devices contacted the same party, and the incident the alert
belongs to. It only reads; it changes nothing. If east-west traffic is off, a contact between two of your own
devices will not be there, and the section says so.

Ask DENIS's "has anything ever talked to…?" also searches relationships, so it finds local destinations a baseline
never lists. It still takes an exact IP address or a CIDR range, not a domain name.

## Sites, agents and the master

A small network needs one process: `denis run`. For more sites, run `denis agent` at each remote site; it
collects locally and pushes summaries to the master (outbound connection only, so it works behind NAT).
See [Deployment](deployment.md#multiple-sites-agents).

## Timezones

Hour-of-day rules use the *server's local time zone*. Timestamps in the UI use the browser's; exports and the
report use UTC and say so.
