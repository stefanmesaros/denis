# Concepts

## How devices are found

| Technique | Kind | What it yields |
|---|---|---|
| ARP (requests, replies, sweep) | passive + active | the MAC ↔ IP pairing, the backbone of the inventory |
| DHCP | passive | the device's own hostname, vendor class ("MSFT 5.0", "android-dhcp"), and the list of options its DHCP client asks for, which identifies the client software (Windows, macOS, iOS, Android, Linux) even when the device has a private MAC and no name |
| mDNS / SSDP | passive | names, services (printer, AirPlay, Chromecast), model strings; also read over IPv6 when IPv6 is switched on |
| DHCPv6 (IPv6 only, opt-in) | passive | the device's name (client FQDN), vendor class, the options it asks for and its client identifier; DENIS only listens |
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
`(site, MAC)` by design. If it happens, an administrator can say that an agent watches the same network as the local
capture (*Sites* → *Same network as…*), and then merge the copies it already reported into the local devices; see
[Troubleshooting](troubleshooting.md).

## IPv6 (optional)

IPv6 is **off by default**; an IPv4-only install is unchanged by it. Switch it on with `--ipv6` on `denis run` or
`denis agent` (a command-line flag only: there is no console switch for it), and add `--ipv6-subnet <prefix>`
(repeatable) to say which IPv6 prefixes are yours. Unlike IPv4, an interface can carry several global prefixes and a
link-local address at once, so DENIS does not guess "the subnet". See [Deployment](deployment.md#flags-of-denis-run-and-denis-agent).

| You give | DENIS does |
|---|---|
| `--ipv6` only | reads IPv6 Neighbor Discovery and Router Advertisements (a device's IPv6 addresses appear on its panel, read-only, and in the Devices CSV `ipv6` column), reads mDNS, SSDP and DHCPv6 announcements for names and identity, and detects address conflicts, a forged neighbour and a new IPv6 router. Unless `--passive-only`, it also looks for IPv6 devices on its own link (below) |
| plus `--ipv6-subnet` | also accounts IPv6 traffic (needs `--flows` or a mirror interface): traffic leaving the network, traffic between your own devices (with `--east-west`), passive DNS and decoded industrial protocols over IPv6 |

What is covered:

* **Detection.** IPv6 traffic is judged by the same rules as IPv4: [`new_destination_v6`](detection-rules.md#new_destination_v6--ndp_mismatch-the-ipv6-counterparts)
  (the IPv6 form of `new_destination`), `new_port`, `lan_scan`, `outbound_fanout`, `threat_list_match`,
  `segmentation_violation`, `dns_resolver_changed`, IT rules, and the industrial rules. IPv6 gets its own
  learning period: with IPv6 flows newly switched on, nothing is alerted for the first learning period, and an install
  that already had IPv6 flows from 4.0.2 learns them once more after the update.
* **Address conflicts.** Two devices claiming one IPv6 address raise `arp_conflict` (the alert says `family: ipv6`).
  It is deliberately quiet: only a clear contest counts (a challenger to the IPv6 router's address at once; any other
  address only when two devices swap it back and forth within five minutes). Anycast and proxy advertisements,
  a handover after silence and an address that changes hands once are not conflicts, because IPv6 privacy addresses
  rotate constantly.
* **Finding devices.** Passive discovery learns an address only from Neighbor Discovery, never from a payload.
  In addition, once per sweep (not with `--passive-only`, and not in the OT profile unless `--active`) DENIS sends one
  all-nodes echo request (skipped while an industrial device is known: those are never pinged), and at most 1,024
  paced Neighbor Solicitations to the addresses a *known* device would have if it used its hardware address
  (link-local, and every /64 the network is known to use, at most four). It never scans an address range, and devices with randomised hardware
  addresses are not probed. Devices using only privacy addresses answer with their link-local address (so they are
  found); their global addresses are learned when they speak.
* **Identity.** IPv6 mDNS, SSDP and DHCPv6 *client* messages feed the same hostname, model and vendor fields as their
  IPv4 versions. DHCPv6 gives the client's name (FQDN), its vendor class and the options it asks for; relayed messages are
  read only when the relay is on your network and names the client's hardware address; server replies are never read.
  The sender's IPv6 address is not recorded from these messages.
* **NAT64.** A device on an IPv6-only network that contacts a listed IPv4 address through a NAT64 gateway
  (`64:ff9b::/96` or `64:ff9b:1::/48`) raises `threat_list_match`. A site-specific NAT64 prefix is not recognised.
* **Remote agents** report their IPv6 data to the master like IPv4 data; an older master ignores IPv6 records it
  cannot read instead of rejecting the whole report.

What is still IPv4-only: the ARP sweep, port scans and banner reads (so services and software versions are found
on IPv4 addresses only). LLMNR over IPv6 and duplicate-address-detection traffic are not read.

**Verified vs. not verified.** All of this is tested with hand-built frames and integration tests. It has not been run
on a real dual-stack network, and the active discovery's raw socket send has only been checked for its message layout and
its error handling, not on hardware. Alert scores for IPv6 reuse IPv4's and may need tuning on real IPv6 traffic.

A mirror can also reach DENIS in a VLAN (RSPAN) or as ERSPAN, VXLAN or Geneve packets: see [Tunnel mirroring](tunnel-mirroring.md).

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

### What a device is: site, VLAN, MAC

A device is its **MAC address at one site** (the local collector, or the agent that reports it). That key
has not changed in 4.1, and nothing about a VLAN is part of it:

- **Site.** Two sites may use the same private range (both 10.0.0.0/24). Their devices are separate
  devices, even with the same address or the same MAC. A switch or an enforcement connector can be
  **bound to a site** (Settings → Network → Switches, Settings → Enforcement; the choice appears once the tenant has
  two or more sites): DENIS then looks for a device only on the switches of its own site and never acts on a
  device of one site through the firewall of another ([Switches](switches.md), [Enforcement](enforcement.md)).
  A switch or connector that is **not bound** keeps working as before, and is marked "Not bound to a site"
  while the tenant has several sites.
- **VLAN.** The VLAN a frame travelled on is recorded as evidence on the device ("Seen on" in the device
  panel), when the capture can see the tag. The same MAC on two VLANs is **one device**, flagged (not merged,
  not split): a router or layer-3 switch legitimately is in many VLANs, and a host that moves VLAN (802.1X, a
  quarantine VLAN) must keep its baseline. The same address claimed from two VLANs is annotated in the
  conflict alert ("seen in different VLANs ... usually address reuse, not spoofing"), see
  [VLANs in 4.1](tunnel-mirroring.md#vlans-in-41-what-is-annotated-and-what-is-not-merged).
- **Virtual router addresses** (VRRP, HSRP, GLBP) are recognised by their reserved address ranges: they are
  never flagged as "several VLANs", count as forwarders, a port move of one is annotated as a likely failover,
  and DENIS never blocks one.
- **Capture source.** The main interface and each mirror interface are numbered capture sources. Two sources
  that see the same traffic count it twice; Health says so
  ([Do not overlap your mirrors](tunnel-mirroring.md#do-not-overlap-your-mirrors)).

## Timezones

Hour-of-day rules use the *server's local time zone*, or, for the devices of a remote site, that site's own
time zone when an administrator set one (Sites page, "Time zone"; an IANA name such as Europe/Bratislava,
daylight saving time included: a change of clock is picked up within a minute; a fixed offset such as UTC-05:00 is
still accepted but does not follow daylight saving; the server's own zone is the default; the zone database
comes from the operating system when it has one and from a copy inside DENIS otherwise). Timestamps in the UI use the browser's; exports and the
report use UTC and say so.

## Details from the console

Explanations that used to be printed on the console screens. The console shows them behind a small ? button.

* Devices with at least one serious standing fact (a known-exploited or critical vulnerability, unsupported software, an open incident, a high-severity finding), ranked by those facts and by what is at stake on the device. Every point is listed with where it comes from.
* Every product and version DENIS has read from a device's service banner (SSH, HTTP, FTP, SMTP, MySQL/MariaDB), grouped by software instead of by device — the same data the Findings page already checks against known-exploited vulnerabilities and end-of-support dates, seen fleet-wide.
* Standing weaknesses and housekeeping problems in your inventory: unlike alerts, these stay until you fix the cause, and disappear by themselves once you have.
* Findings someone decided to live with, and why. They count again when the time is up or when an administrator withdraws the decision.
* DENIS keeps watching them: it warns 14 days and 3 days before a decision ends, scans the open-port ones again once a day, and notes in the event log when a problem has gone away.
