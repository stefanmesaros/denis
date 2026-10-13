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
`lan_scan`, `lan_sweep`, `outbound_fanout`, `dhcp_options_changed`, `dhcp_starvation`, `new_destination_v6`, `ot_new_conversation`, `ot_control_command`, `ot_internet_exposure`,
`ot_purdue_skip`, `ot_unexpected_writer`, `ot_command_watch`, `ot_write_escalation`, `ot_goose_conflict`, `it_watch`, `segmentation_violation`, `inbound_from_public`.

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

*Rotation suppression:* three new destinations on the same port within an hour promote that port to
"rotating" for that device (a CDN edge handing out a fresh address per session, not several genuinely
separate services), and further contacts on it go quiet. The suppression only swallows low-signal contacts,
though: a new destination on a rotating port still alerts when nobody else on the network has contacted it
*and* at least 1 MB was sent, or the port is one of the remote-administration/file-sharing/database ports
`new_port` also flags (22, 23, 25, 445, 3389, …) — those are never auto-promoted to rotating at all, since a
burst of new destinations there is the signal itself (SSH/SMB/RDP worm propagation, spam fan-out), not noise.
A promoted port currently has no expiry (a follow-up, not yet built).

### `new_port`: a service port never used before *(needs `--flows`)*
A device with an established set of ports uses a **new service port** (below 32768, not 53/80/123/443) towards a
known destination. Score 40, +15 for remote-administration/file-sharing/database ports (22, 23, 445, 3389,
3306, …), +10 for ≥1 MB, −10 for ICMP.

*Owners, not addresses (what DENIS keeps quiet):* the unit of novelty for `new_destination` and `new_port` is the
**owner** of the remote address: its network operator (ASN) when the ASN database is installed, otherwise the
domain name the device resolved it from, otherwise the /24. Large cloud and hosting operators are narrowed to
the /16, because "this device already talks to a cloud" must not excuse every address in it. A new address of an
owner the device has used for at least six hours (or during its learning period) in the last 30 days is **not
news**; so is a random high UDP port (1024 and up, not a known service port: peer-to-peer and relay traffic
picks a fresh one per session) towards a destination the device already knows. DENIS does not drop these: they are
stored as `info` events with a reason code (`known_owner`, `p2p_udp`, `learning_digest`, `off_scope_private`),
counted, and shown under "Show quiet". An owner the device has never used still raises one alert per device and
day; further addresses of it that day are quiet. The `new_port` churn budget (3) is now per owner, not per
address. Nothing in these never-quiet kinds is ever quieted: threat-list hits, rogue DHCP/RA, DHCP option
changes and starvation, resolver changes, outbound fan-out, ARP sweeps, industrial control and write commands,
segmentation violations, watched-port arrivals, fingerprint changes, gateway ARP/NDP conflicts and a new device
(except a recognised private-MAC rejoin). A flow that uses a remote-administration/database port, hits the
threat list, or sends ≥10 MB in its first window to an owner the device never used stays raised whatever the
owner. One switch turns all of it off: "Quiet routine alerts" (setting `noise`, `enabled`, on by default).

*Noise profiles:* every device has a profile that says how much routine noise its role makes, suggested from its
type and changeable per device: **IoT cloud device** (cameras, TVs, speakers, gadgets: a low-scored new contact,
MQTT/CoAP and volumes under 25 MB are recorded quietly), **personal device** (phones, tablets, wearables, and a
laptop or computer with a private MAC: contacts scoring under 50, unusual hours, being away and volumes under
50 MB are recorded quietly), **infrastructure** (routers, NAS, servers, printers: nothing extra is quieted, a NAS
reaching a new provider is news), **industrial** (never quiets an industrial rule) and **standard**. A profile only
moves events into the recorded, counted quiet stream: the never-quiet kinds and the escape hatches do not depend on
it. A private-MAC newcomer whose hostname matches a device with a private MAC seen in the last 30 days is scored 25
as "probably <name> with a new private address", and is quiet for a personal device; a vendor-MAC newcomer is
never treated this way.

### `volume_anomaly`: unusual outbound volume *(needs `--flows`)*
Bytes sent outside in a 5-minute window exceed the device's own average by ≥3 standard deviations (the
deviation is floored so very regular devices do not alert on trivial changes; buckets under 5 MB are ignored).
Score 40 + 10 per extra deviation. An incident is not learned as the new normal. One alert per device per hour.

*Memory and floors:* the average only remembers about a day, so after a quiet day an ordinary upload looked
huge. DENIS therefore also keeps the device's own **peak per day for 14 days**: once it knows three days, a transfer
up to 1.5 times that peak is recorded quietly (`within_peak`, "within this device's own 14-day peak (119 MB)")
instead of raised. A device that moves almost nothing (fewer than 24 buckets of 100 kB in the last day, and a mean
under 1 MB) has no baseline to compare with: only the size counts, 40 at the floor and +10 per doubling. The
floor is 5 MB, 25 MB for an IoT cloud device towards a provider it uses (5 MB towards one it never used) and 50 MB
for a personal device; smaller transfers that would have alerted are recorded quietly (`profile_floor`). Never
quiet: most of the bytes going to a provider the device never used (+15), and 200 MB or more in one bucket from a
device that is not a server or NAS.

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

*Same device and known pairs:* when both claimants share a hostname or your register name, the two addresses
belong to one device (a second network interface, or a new private address): −40, and the event is kept quiet
(`same_device`). A (claimant, holder, address) pair that you acknowledged as expected behaviour or a false positive,
or that recurred at least three times over a day while both devices stayed in service (typical of a host with two
interfaces on one network), is quiet from then on (`known_pair`); the first occurrence is always raised. A device
using a private (locally administered) MAC that takes over an address once is a hand-over, not a conflict; it
only becomes one if the previous holder claims the address straight back. The gateway, and a claimant that
takes three or more addresses, are never quieted.

*Routed traffic and forged hand-overs (4.0.3):* a router, firewall or layer-3 switch carries other hosts' packets, so
its Ethernet address is seen next to many IP addresses that are not its own. A device that is the gateway, sent a
Router Advertisement, is typed router or firewall, or has been seen on three or more /24 networks is not blamed
for the addresses of the hosts behind it (its own known addresses still count), so two routers carrying one remote
host no longer raise a conflict. Only inferred sightings are excused this way: an ARP, DHCP, mDNS or LLDP claim, which
is what a poisoner has to make, is judged as before. The established gateway also keeps its address for an hour after it
was last seen, so an ARP spoofer who waits out the five-minute window can no longer take the address and turn the real
router into the blamed claimant. A DHCP lease for an address whose holder was seen on it in the last minute raises
`arp_conflict` and leaves the address with the holder, so a forged DHCP acknowledgement cannot move a busy device's
address silently. Switch management addresses announced by LLDP are not claimed by the per-port source address.

*IPv6 (opt-in, `--ipv6`):* two devices claiming one IPv6 address raise the very same `arp_conflict` alert (same
weight, cooldown, exceptions and gateway handling; the alert's details say `family: ipv6`). IPv6 is quieter by
design, because SLAAC's own duplicate-address detection already prevents most clashes, so only a clear
contest is reported: an exclusive Neighbor Advertisement (Override flag set; anycast and proxy advertisements are
never a claim) for an address another device was just using, and only when the two devices swap it back and forth
within 5 minutes. One hand-over is not a conflict, so a privacy-address device that changed its hardware address
and never returns stays quiet. A challenger to the **IPv6 router's** address (a device that sends Router
Advertisements with a non-zero lifetime; held for an hour, like the IPv4 gateway) is reported at once, with the
+25 gateway bonus, and never takes the address over. A router answering for a host (proxy ND) and the same
`fe80::1` reused on several VLANs of a mirrored trunk are not conflicts. An address built from a hardware
address (EUI-64) scores 20 lower for the device it was built from and 10 higher against any other claimant.

### `lan_scan`: internal network scan *(needs traffic analysis on a mirror port)*
An **already-known** device suddenly touches many different local hosts, or many different ports on one local
host, within a short rolling window — the signature of a compromised device scanning the LAN, which `new_device_burst`
(many *new* devices at once) does not cover. Breadth-based, not connection-state-based, like the rest of the rule
engine: by default 8 distinct local addresses, or 8 distinct ports on one local address, within 2 minutes. Score 55,
+3 per address or port beyond the threshold. One alert per device per hour (adjustable), then the window starts
fresh. Because it judges device-to-device traffic, it only sees what crosses a mirror/SPAN port; on an ordinary
port it sees only traffic to and from the collector itself. With IPv6 flows on (`--ipv6`), unique-local IPv6
addresses (`fc00::/7`) count as local hosts too, judged by the same thresholds in the same window — a sweep spread
over both address families is still one sweep. Once the count of addresses looks like a sweep, the addresses are
collapsed to devices first (the IPv4, link-local, unique-local and global addresses of one device are one host), so
a dual-stack device talking to its neighbours is not counted several times; the alert's details list the `addresses`.
Only addresses that are really local count towards those thresholds: the networks the site monitors (the
device's own /24 where none is known) and every address the register knows as a device of the site. Other private
addresses, including carrier-grade NAT (`100.64.0.0/10`, for example a mesh VPN's `100.100.100.100`) and the LAN
addresses a peer-to-peer partner exposes, are judged in a separate window with **doubled** thresholds, so a
real sweep of a routed network still fires and a stranger's network does not (the alert says so). On one host, the
Windows file-sharing set (ports 135, 137, 138, 139, 445) counts as one port, and UDP ports from 1024 up count only
when there are at least 20 of them. The two thresholds cannot be set below 5; a saved lower value is raised to 5
once, with an audit entry and a Health note.
*Typical false positive:* a vulnerability scanner or monitoring server that legitimately sweeps the LAN — add it
as an exception.

### `lan_sweep`: internal ARP sweep
One sender requests at least 20 distinct local addresses by ARP within two minutes: the signature of `nmap -sn`,
`arp-scan`, Metasploit or a worm mapping the subnet before it spreads. Unlike `lan_scan`, this needs no mirror
port — ARP requests are broadcast, so it is visible from any switch port. Score 70, +1 per address beyond the
threshold (capped at +20). The gateway is exempt outright (it routinely re-ARPs its whole client table); a
discovery tool (Fing, a router's own "network map" feature, Home Assistant, a UniFi controller) seen sweeping
during the learning period is remembered and never judged again.

### `outbound_fanout`: worm/spam fan-out *(needs `--flows`)*
An already-known device contacts at least 10 distinct **public** addresses on one remote-administration,
file-sharing, database or worm/spam-signature port (the same ports `new_port` flags, plus 2323/5555/7547 —
Mirai's alternate Telnet port, ADB, TR-069) within five minutes: the Mirai-family botnet propagation and
spam-bot signature. Unlike `lan_scan` (which ignores public addresses by design) and `new_destination` (whose
rotation-burst suppression actively hides a fan-out after the first few), this is judged fresh every time — the
port is never learned as normal and never promoted to "rotating". Score 75, +1 per address beyond the
threshold. Devices typed `server`, or whose type contains "mail", are exempt (a mail server legitimately fans
out on 25). Public IPv6 addresses count too when IPv6 flows are on, in the same per-port window as IPv4 ones.

### `new_destination_v6` / `ndp_mismatch`: the IPv6 counterparts
*Opt-in (`--ipv6`); see [IPv6](concepts.md#ipv6-optional).*
`new_destination_v6` is `new_destination`'s IPv6 twin *(needs `--flows`, `--ipv6-subnet`)*: a device contacts an
outside IPv6 address it has never used. It is scored exactly like `new_destination` (35 for a first contact,
+15 when no other device here has contacted the address, +15 for a port the device has never used, +10/+20 for
1 MB/50 MB sent, -10/-20 for a device that already talks to 100/500 IPv6 hosts), with one adaptation: an address
in the same /64 as one the device already uses is the "neighbour" (-10), where IPv4 uses the same /24. It has
its own weight, and the same rotation suppression: NTP/STUN, and any port
on which a burst of new IPv6 addresses shows a rotating service, stop repeating after a few alerts unless the
contact is a strong signal (a risky port, or 1 MB or more sent to an address nobody else uses). That state is
kept apart from IPv4's, so an IPv6 burst never quiets IPv4 alerts on the same port, and IPv6 destinations are
learned in their own list, so they never count towards IPv4's "already talks to many hosts" discount. With
IPv6 flows on, the threat list, `lan_scan`, `outbound_fanout`, `ot_internet_exposure` and
`segmentation_violation` judge IPv6 traffic exactly like IPv4 traffic, and every IPv6 conversation is recorded
as a relationship. IT rules (`it_watch`, which accept IPv6 networks), `new_port` (one learned set of
ports for both families) and `dns_resolver_changed` (an IPv6 resolver judged against the device's own IPv6
resolvers, learned on their own clock) cover IPv6 too. Industrial conversations between two IPv6 devices are
decoded like IPv4 ones (all the OT rules below apply), the threat list also matches an IPv4 entry reached through a
NAT64 address (`64:ff9b::/96`, `64:ff9b:1::/48`), and, when east-west accounting is on, IPv6 traffic between two
local devices becomes relationships and is judged by `segmentation_violation` like IPv4. `ndp_mismatch` is
`arp_mismatch`'s IPv6 twin: a Neighbor Advertisement (IPv6's ARP reply) carries a hardware address that disagrees
with its own Ethernet source. Score 45, folded into `arp_conflict`'s own weight — its IPv4 twin, not
`new_destination_v6` (no `--rule-weight` entry of its own, the same shortcut `arp_mismatch` takes with
`arp_conflict`'s weight, so turning down IPv6 rotation noise never silently disables this L2 spoofing signal too).
At most one alert per claimant/address pair per cooldown window. A hypervisor, a laptop docking a virtual machine
or a Wi-Fi repeater that translates its guests' addresses sends such advertisements for many addresses under its
own hardware address: from the **third** different address one hardware address mismatches for within an hour, it is
treated as a bridge, the score drops from 45 to 15 (the alert explains why) and there is one alert per hardware
address per cooldown instead of one per guest. The first two stay at full strength, and a mismatch on the IPv6
router's address is never lowered.

### `rogue_ra`: an unrecognised IPv6 router
*Opt-in (`--ipv6`); see [IPv6](concepts.md#ipv6-optional).*
`rogue_dhcp`'s IPv6 twin, same shape: a device that was not sending IPv6 Router Advertisements during the
learning period starts sending them — a rogue router can redirect every IPv6-capable device's traffic through
itself. Score 70, folded into `rogue_dhcp`'s own weight. Reported once per new router, remembered across
restarts (`router_advertisers_v6`). A challenger to the router's address is `arp_conflict`'s job, see above.

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

### `dhcp_options_changed`: a known server's router or DNS drifted
A DHCP server DENIS already knows starts handing out a different router (option 3) or DNS server (option 6) than
it did before — the DNSChanger/GhostDNS pattern, invisible to `rogue_dhcp` since the server's MAC never changes.
Score 60, or 75 when the new DNS server is a public address no device on the network already uses. Learned fresh
per server, learning period or not, and persisted across restarts; one alert per server every six hours.
*Typical false positive:* none really — an administrator switching DNS providers or replacing a router is exactly
what this is meant to surface, and it is a single acknowledgeable alert.

### `dns_resolver_changed`: a device started using a resolver it never has before *(needs passive DNS — see [Passive DNS](passive-dns.md))*
A device gets a DNS answer from a resolver address it has not received one from before, after its own resolver set
has had time to settle (learned silently for the usual learning period once passive DNS first sees the device, so
switching the feature on does not instantly judge every device's pre-existing resolver). This judges only the
*change*, never which resolver a device uses on its own — a Chromecast that always asks `8.8.8.8` learns `8.8.8.8`
once and never alerts for it again. Base score 40, +25 if the new resolver is a public address no other device on
this network uses, +15 if it is a local device that is neither the gateway nor a DNS server your DHCP hands out,
−10 for a well-known public resolver (Google, Cloudflare, Quad9, OpenDNS, …), −30 if it is the DNS server your own
DHCP server currently hands out (a lease renewal, most likely), −20 if at least 3 other devices here already use
it (an established resolver). One alert per device every six hours; three or more devices switching to the *same*
new resolver within an hour are recorded but only the first three raise an alert, with a note that this looks like
a deliberate network-wide change. Firing here suppresses the matching `new_destination` on port 53 for ten minutes,
so one resolver change is one alert, not two. *IPv6 prefix rotation:* a new global IPv6 resolver with the same
interface identifier (the last 64 bits, not zero) as one the device already has, under a different prefix, is the
same resolver after an internet provider changed the prefix: its history moves to the new address, no alert is
raised, and one informational note (score 0, `prefix_rotation`) is kept per site and identifier per day.
*Typical false positive:* you changed DNS provider, turned on a VPN client, or replaced the router — the alert
says so plainly, and no action is needed when that is what happened.
*Investigate:* the device's network settings and installed software; if many devices changed at once, check the
router and the DHCP server first. The looked-up names themselves are never included in this alert — only the
resolver address — since they would export browsing data for no detection value.

### `port_move`: a device moved to another switch port *(needs switches read over SNMP — see [Switches](switches.md))*
A registered device that had been plugged into one port for **at least 7 days** (and seen there on at least 3 polls)
turns up on another port, confirmed by two consecutive polls. Base score 30, +25 for a device that normally stays put
(industrial equipment, a server, printer, camera, access point, firewall, point of sale, …), +15 if you rated its
criticality high or critical, +15 if the new port or VLAN is one you watch, +10 if it moved to a different switch, −40
for a mobile device (laptop, phone, tablet or a randomised address), −10 if the new port's name is a guess because the
switch gave no bridge-port map. So a PLC that moves after months is **high**, an office PC **low**, and a laptop docking
at another desk **info**. Five or more devices moving together between the same two ports in one poll are one alert
(a desk switch or an uplink was re-cabled, not five devices). One alert per device every 24 hours. A move on its own
never opens an incident.
*Typical false positive:* someone moved a desk or re-patched a cable. *Investigate:* ask whoever works there; for a
stationary or critical device, check whether the machine now on the port is really the same one (a trusted address on a
new port with a different machine behind it is the classic MAC-clone pattern — `fingerprint_changed` below looks for
exactly that). DENIS only reports this; nothing on the switch is changed. Not judged until a switch has been tracked
for the learning period, and an unregistered MAC is never judged.

### `new_on_port`: a new device on a port or VLAN you watch *(needs switches read over SNMP)*
Fires only on ports and VLANs you chose to watch (the *Watch* toggle in the Topology port drawer and port table;
nothing watched means this rule never fires). A MAC that has not been on that port in the last 30 days appears there:
base 55, +20 if the address is not in the register (a minimal entry is created for it, the one place a switch rule does
that, so the alert has a device to be about), +10 if the device type is unknown, −20 if it was seen there before more
than 30 days ago, +5 if it moved here from another port within the hour. Its severity is the *watch* severity: watching
a port is an explicit request, so it is never downgraded below your minimum. It is exempt from the switch learning
period, so a port watched before any history exists reports every first MAC once. More than 10 new MACs on one watched
port in a single poll (a hub, an access point or a loop) are one alert. It joins the *arrival* step of the
`hostile_newcomer` incident, next to `new_device`.
*Investigate:* who or what this is. If it is not expected, treat it like a new device on a sensitive part of the network.

### `vlan_change`: a device changed VLAN *(needs switches read over SNMP)*
A registered device whose VLAN had been stable for at least 7 days shows up in another VLAN (confirmed by two polls).
Base 40, +20 if the new VLAN is watched, +15 for a stationary or critical device, −15 if the port's own access VLAN
changed in the same poll (the port was reconfigured), −10 if the VLAN number came from the switch's forwarding-table
numbering rather than a confirmed mapping, −25 for a mobile device. One alert per device every 24 hours; no incident
pattern. A port's own configuration change is logged and shown in the port drawer, but raises no alert in itself.
*Typical false positive:* you reconfigured a port on purpose. *Investigate:* the switch configuration; a device moved
into a more (or less) trusted VLAN without anyone planning it is a misconfiguration or an intrusion.

### `fingerprint_changed`: a device now looks like a different machine *(nothing extra needed)*
DENIS remembers, per device, what it passively learns about the operating system on three separate bases: the initial
TTL of its ICMP replies, the initial TTL of its TCP SYNs, and its DHCP vendor class (Windows, Android, Linux, Apple,
or the first word of anything else). The bases are never compared with each other: ICMP 255 and TCP 64 on one device
never count as a change. When a basis shows a different family on a device that has been in the register for at least 7
days, and the family it replaces had been stable for at least 7 days, that is a flip: base 55, +15 if a second basis
flipped in the same batch, +20 if the address also moved switch port within the hour (the MAC-clone pattern), −20 for
virtual machines, hypervisors and single-board computers, which get re-imaged often. A younger memory is just replaced,
silently. One alert per device every 24 hours, and it joins the *arrival* step of the `hostile_newcomer` incident: a
cloned identity that then probes is the same story as a stranger that probes. JA3 and the DHCP parameter list are
deliberately not used (too volatile).
*Typical false positive:* a re-installed machine, a dual-boot, a device behind a different NAT or VPN. *Investigate:*
what changed on that device, and whether it also moved port.

### `inbound_from_public`: a public address connected in *(needs `--flows`)*
A public (non-private, non-reserved) address opens a TCP connection to a local device, for example through a port
forward or a UPnP mapping to a solar inverter, a camera or a NAS, and the device accepts it. The capture follows the TCP
handshake (the source's SYN, the device's SYN+ACK, the source's ACK), so the direction is **confirmed**, never guessed
from port numbers, and a lone SYN, a connection the router refused with a reset, UDP and ICMP never count. The device's
own calls out to its vendor cloud are not inbound and never alert. IPv6 sources count when `--ipv6` is on.

*What is normal:* during its learning period a device learns the ports on which it accepts connections from the
internet. After it, a completed connection on a port it never served to the internet alerts; one on a learned port does
not. The rule has its own learning clock per site, started the first time it runs, so an update does not turn every
existing port forward into an alert (the first 24 hours only learn).

*Score:* 50 for a device that never served the internet (35 when it serves other ports), +20 for a remote-administration,
database or file-sharing port, +25 for an industrial port, +10 / +20 for a source network that reached 5 / 20 devices in
ten minutes. Use `--rule-weight inbound_from_public=<weight>`, or the weight and minimum score on the Rules page.

*The alert says who:* source address, the cached GeoIP country, network (ASN) and reverse-DNS name when the existing
address enrichment already has them (otherwise "unknown"; nothing is looked up for the alert), whether the address is on
your threat list, the destination device, protocol and port (with the service name for well-known ports), first and last
seen, connection attempts and handshakes completed, bytes in and out, and the other devices the same source network
reached (a scan indicator). The summary, which is also the notification text, names the source and the port. In the
alert dialog the same facts have their own **Connection from the internet** section (one block per source: address,
name, country, network, threat list, service and port, attempts, handshakes completed, first and last seen, bytes each
way, the devices it reached, plus the handshake evidence), not only the raw details.

*Who opened it:* the alert dialog's **Investigate** arrows and the device panel's **Recent destinations** carry an
**Initiated by** label: *this device*, *the other side* or *unknown*, each *confirmed* (a seen TCP handshake or a decoded
request) or *guessed* (from the port numbers), with a tooltip. An address that completed a handshake into the device is
*the other side (confirmed)* for the port it connected to; every other internet flow says *unknown*, because traffic
accounting keeps the bytes each way but not who started the connection, and its arrow points both ways instead of out.

*Noise control:* hits from one source network (IPv4 /24, IPv6 /48) are one alert per hour across all devices (a
scanner that hits 50 devices gives one alert listing them; further hits are counted in the quiet counters as
`grouped_source`), and one alert per device every 6 hours. A source the device already talks to, or one you marked with
**Allow this provider** in the alert dialog, is stored quietly (`known_owner`) unless the port is a risky or industrial
one. The quiet stream's kill switch, rule exceptions and the per-rule minimum score apply as for every rule.

*Marking things as expected:* a source with **Source <address> is expected for <device>** in the alert's own section
(administrators; it is the same action as **Allow this provider** with the source's own owner key, `POST /api/owners/allow`,
so it is scoped to the sites you may change, audited, and keeps that owner's later contacts quiet instead of silencing
them), the source network with **Allow this provider** (for this device or for all devices of a
noise profile); a port with **tcp/<port> on <device> is expected** in the alert's own section (administrators; it
records the port as one the device normally serves to the internet, `POST /api/assets/{id}/public-inbound/allow`, and is
written to the audit log). **Never alert on this again** still adds a permanent exception for the device. To judge one
device strictly, with no learning at all (every completed inbound connection alerts, whatever it did during learning),
switch on **Alert on every connection from the internet** in the device panel's Overview (it adds the tag
`alert-on-inbound`; editors).

*Health:* if a burst of scanning fills the capture's per-window limits (`flow::MAX_INBOUND_KEYS` sources per window,
`flow::MAX_INBOUND_TRACK` handshakes followed at once), the skipped packets are counted on the Health page
(**Internet connection watch**, and an advisory warning for an hour after a limit was hit). This counts this console's
own capture and, since 4.1.0, the skips a remote agent reports in its own reports (`inbound_dropped`, left out when 0, so
an older master or agent is unaffected): a second card, **Internet connection watch, remote sites**, names the busiest
sites. **UDP is out of scope:** the rule follows TCP handshakes only, so there is no UDP source to mark as expected.

*Where the capture sits matters:* the rule needs the LAN side of the router (a mirror port on the LAN switch, or a
collector in the LAN), where the public source address is still visible. On the WAN side the device is not visible at
all. Behind double NAT or a reverse proxy the source is the proxy's address.
*Typical false positive:* the vendor's cloud connecting in through a port forward you opened on purpose: mark its
network as expected. *Investigate:* the port forward or UPnP rule on the router, and the device's passwords.

### `dhcp_starvation`: DHCP pool exhaustion
One real sender floods DHCP DISCOVER/REQUEST messages claiming at least 20 distinct, almost certainly made-up
client hardware addresses within five minutes — the Yersinia/dhcpstarv class of attack, and the textbook first
half of "starve the real server, then answer as a rogue" (pairs naturally with `rogue_dhcp`). Not subject to
learning or the gateway exemption. Score 85, +1 per identity beyond the threshold. The claimed (fake) addresses
are never turned into assets — only the real sender is looked up and judged.
*Typical false positive:* a MAC-NAT Wi-Fi extender relaying DHCP for its own handful of clients never reaches the
20-identity threshold in five minutes.

### `new_device_burst`: many devices at once
Five or more new devices within ten minutes (after the learning period). Score 50, +4 per extra device, up to 80.
One alert per half hour; each device still gets its own `new_device` entry. Fits a scan, an ARP flood or a bridged
network, but also a meeting or a delivery of new equipment.

### `threat_list_match`: contact with a known-bad address *(needs `--flows` and a threat list)*
```bash
denis run --flows --threat-list /var/lib/denis/bad-ips.txt
```
Checks every outside address a device contacts against a list of known-bad IPv4 and IPv6 addresses and networks
(IPv6 destinations are checked when IPv6 flows are on, `--ipv6`). Two sources, unioned together — a hit on either
counts:

* **Your own file**, named with `--threat-list`: one entry per line (`203.0.113.9`, `198.51.100.0/24`,
  `2001:db8::9`, `2001:db8:bad::/48`; `#` comments allowed) — the format of the free lists from abuse.ch (Feodo
  Tracker), Spamhaus DROP and similar. DENIS never
  downloads this one itself: refresh the file yourself (for example with cron, writing to a temporary name and
  renaming it so DENIS never reads a half-written file); DENIS notices when it changes and reloads it, and keeps the
  old list if the new file is broken.
* **Auto-fetched sources**, under *Settings* → **Data** → **Threat list sources**, each off by default and
  switched on independently, each with its own refresh schedule (Daily / Weekly / Monthly):
  * **abuse.ch Feodo Tracker** — botnet command-and-control addresses.
  * **abuse.ch ThreatFox** — malware command-and-control addresses (`ip:port` indicators from the last 48 hours;
    the port is dropped). ThreatFox's domain and URL indicators are not used yet: DENIS has nothing to match a
    domain against until it records DNS answers.
  * **abuse.ch URLhaus** — addresses currently serving malware downloads; only URLs whose host is an IP address
    are used, for the same reason.
  * **Spamhaus DROP** — hijacked and spammer networks.
  * **Spamhaus ASN-DROP** — whole autonomous systems run by or for criminals. The list names AS numbers, not
    addresses, so DENIS turns it into networks with the GeoIP ASN database already used for IP enrichment (*Settings*
    → **IP enrichment**), offline — nothing is looked up online. Without an ASN database installed this source
    cannot be fetched (the refresh says so); the networks are as current as the older of the two downloads.
  * **The Tor Project's exit-node list** — current Tor exit relays. Not malware: a hit means a device talked to a Tor
    exit, which most networks treat as a policy question.

  Every hit names the list that flagged it, the most specific first (your own file, then the abuse.ch lists, then
  Spamhaus, then Tor). **Refresh now** fetches
  one immediately; the provider, entry count and last-fetched time are shown live. A response that does not parse as
  a real list (a captive portal, a broken download) is refused and the previous fetch, if any, stays in force —
  exactly like a broken local file.

Turning on a fetched source can only ever add coverage: it is unioned with your own file, never a replacement for it,
and a source you turn back off stops being used immediately even if its last fetch is still cached. A device
contacting a listed address scores 85 (+10 if it sent ≥100 kB), from the first day (no learning period), once per
device and address per six hours. Traffic is only seen when it crosses the interface DENIS listens on (see
[Concepts](concepts.md#visibility-what-can-be-seen-from-where)).

### Your own rules: IT rules and OT rules

Besides the built-in rules, administrators write **their own rules** on the Rules page, under **Your rules**. There
are two kinds. An **IT rule** (id `it_watch`) watches when a device talks to an address outside your networks. An
**OT rule** (id `ot_command_watch`) watches for industrial commands such as stop, start or write. (Before 4.1 they were
called network watches and OT command watches. Only the words changed: the ids, the settings, the API fields and
what is sent to other tools are the same, and an alert raised before the update keeps its old wording.)

**New IT rule** and **New OT rule** open one dialog, which also edits a saved rule. It reads as a sentence:

* **Templates first.** A new rule starts on a screen with the five most common templates (a link shows the rest),
  *Start from scratch* and, for IT rules when the AI rule assistant is on, *Describe it, let AI draft it*. A template
  only fills in the sentence; every part of it can be changed before saving.
* **A sentence that rewrites itself.** "Alert when every device talks to the internet on port 3389, 22 over any
  protocol, scored 60, at most once per device and address every 30 min." It stays in view while you scroll, and what is
  still missing is marked in red.
* **Three numbered sections:** which devices (or which target), what happens (or which command), then the score, how
  often to repeat and the name. The name is suggested from the sentence. Fields most rules do not need (devices the rule
  never applies to, an amount of data, starting paused) are behind *more*. On a phone one section is open at a time.
* **What this rule would have done.** The devices the rule covers right now, and what it would have raised over the
  last 7 days. For an IT rule that number is an **estimate**: DENIS keeps no history of every flow, only the destinations
  and ports each device has learned, so a destination the device talked to counts once. For an OT rule it is counted
  from the industrial paths DENIS has decoded, the commands as recorded. A rule saved today only counts from now on.
* **Mistakes next to the field.** A port that is not a number from 1 to 65535, an address that is not an address or a
  network, an empty name, a rule that would match every flow: each is marked where it is, and *Save rule* stays off
  (its tooltip says why) until they are fixed.
* **Undo.** After saving, a message with **Undo** stays for 20 seconds: a new rule is removed, an edited rule goes back
  to what it was.

The two kinds are described below, with their ids.

<a id="it_watch-your-own-network-watches-needs---flows"></a>
### `it_watch`: your IT rules *(needs `--flows`)*

*Rules* → **Your IT rules** (administrators): be told when devices you choose talk to addresses or ports
you did not allow. An IT rule is a set of conditions; traffic matches when it passes **all** the conditions that are set:

* **Devices**: for these devices (a device, a device type, a tag, a network, a Purdue level, a register "Zone / cell"
  value or a site; empty means any device), and **never for** the ones you list (a recorder that legitimately talks to
  everything). The same choices a zone's members offer, with the same meaning. A *network* here is the address the
  device has **now** (IPv4 only): if the device is re-addressed, the rule follows the device, not the old address.
  Exceptions ("mute") offer only a device, a type, a tag or a network.
  A device list may also name a **zone** (one you created on the Zones tab). That is a different kind of subject from
  the others: the rule **follows the zone**, so a device that joins the zone (its tag, register field, Purdue level,
  address or detected type changes) is covered from then on, and one that leaves it is no longer, with no edit to the
  rule. Devices that are in the zone only by their address or by a detected device type count too; the preview marks
  how many. Because an IT rule only sees a device's traffic to addresses **outside** your networks, a zone here
  means "these devices' traffic to the outside", never traffic inside the zone (use a zone policy for that). If the
  zone is deleted (the console refuses to delete one a rule follows, but a restored backup or an edited database can
  still do it) the rule is **suspended**: it matches nothing, not even the devices it names another way, and its card
  says so, until you remove the zone from it or restore the zone. An IT rule is never widened by a missing zone. See
  [Zones and policies](segmentation.md#a-zone-as-a-rules-subject).
* **Protocol**: any, TCP, UDP or ICMP.
* **Ports**: any, *only these*, or *any except these*.
* **Addresses**: any, *only these*, or *any except these*. An entry is a network like `10.0.5.0/24`, a single address,
  or one of two words: `public` (the internet) and `private` (the local network: 10/8, 172.16/12, 192.168/16, link-local
  and 100.64/10). Multicast and broadcast are neither.
* **Amount of data**: only when at least this many kB moved in one 10-second window.

*Only* makes a block-list ("alert on RDP or SSH to the internet"), *except* makes an allow-list for traffic to
addresses **outside** the networks DENIS monitors ("a device may only reach the internet on port 443, anything else
alerts"). An IT rule only ever sees a flow — a device talking to an address outside the monitored subnets — so "cameras
may talk to the recorder, nothing else" is **not** this; when the recorder is also one of DENIS's own devices, that
traffic is local-to-local and an IT rule never sees it at all. For that case use a **zone or policy** instead
(Zones tab → *allow-list policy*), which is judged over all observed traffic, including between your own devices. The
Zones tab's **Policies** view lists your IT and OT rules next to those policies (read-only, with a link back to this page).
Ready-made starting points are in the form (devices talking to the internet,
remote access crossing the boundary, anything but DNS/web/time to the internet, mail sent straight from a device,
large transfers, devices reaching the local network). The alert names the rule, the device, the destination, the port
and the amount, and carries the score you chose (1–100). One alert per device, address and port per cooldown (1–1440
minutes). Like OT rules, IT rules **also fire during the learning period** (you asked for them), and the
rule's **weight** scales or, at 0, switches off all of them. Only what leaves or enters through the monitored interface
is seen, so place the collector where the traffic is. Up to 500 IT rules.

**Who does this rule cover?** The rule form's **Show who this covers** button, and **Who does this cover?** on each
saved rule (administrators), list the devices the rule is about *right now*, split into those covered by a zone and
those covered by the other subjects, with the zones it names and how many devices each holds; nothing is written. It
uses the same matching as the alert path, so it cannot disagree with what will alert. It is a snapshot: look again
after changing a zone. The alert of a rule that matched through a zone records how the zone resolved at that moment
(zone, revision, how the device was placed, the segmentation snapshot), shown in the alert as **Zone at the time**.

#### Five worked examples

Each of these is one IT rule, added from *Rules* → **Your IT rules** → **New IT rule**. All of them need `--flows`
(traffic analysis) actually running — the page tells you plainly when it is not.

1. **"Does this device talk to other devices on the network when it shouldn't?"** — an IoT gadget, a smart TV, a badge
   reader: give it a device or tag, set **Addresses** to *any except these* and list `private` (the local network).
   Anything it says to the internet is ignored; any local device it reaches — a laptop, a server, another gadget it has
   no business with — alerts. To also flag it reaching the internet, add a second IT rule with **Addresses** set to
   *only these* → `public`.
2. **A printer or NAS that should only ever talk to one thing** — set **Devices** to the printer, **Addresses** to
   *any except these* and list the one server it legitimately talks to (`10.0.5.10`, say) plus `private` if it also
   needs the local network for discovery. Anything else it reaches alerts: exactly the "allow-list" pattern, tightened
   to a single address instead of the whole LAN.
3. **Cameras must never reach the internet** — **Devices**: the `camera` type (or a tag if you use one instead).
   **Addresses**: *only these* → `public`. This is one of the ready-made presets, unchanged.
4. **The guest network must not reach internal servers** — **Devices**: the guest subnet as a network
   (`10.30.0.0/24`). **Addresses**: *only these* → `private`. Pair it with a **Ports** *only these* of `139, 445, 3389`
   (SMB/RDP) if "reaching the internal network at all" is too broad and you only care about specific services.
5. **An admin workstation should not itself be doing remote administration outward** — **Devices**: that one
   workstation (or a tag like `no-outbound-admin`). **Ports**: *only these* → `22, 3389, 5900`. **Addresses**: leave as
   *any* (or restrict to `public` if internal RDP/SSH from it is expected and only outbound matters). Catches the
   workstation itself being used to reach out somewhere it normally wouldn't, not just being reached.

The **except**-style rules (1, 2) are the ones worth learning first: instead of listing every bad destination (which
you cannot know in advance), you list the *few good ones* and let the rule catch everything else.

### `segmentation_violation`: traffic your zones and policies do not allow

Full detail, including how a device is placed into a zone, is in [Zones and policies](segmentation.md); in short:

* Needs **zones and policies** set up on the *Zones* tab, and (for traffic between your own devices)
  **east-west accounting** on, since that is where most of this rule's traffic comes from. Judges every
  observed edge: east-west records, flows (local ↔ outside) and decoded industrial conversations alike —
  unlike `it_watch`, which only ever sees the last of those.
* Three causes, each its own score: an explicit **deny** zone policy matched (+70); an **allow-list** policy did
  not allow the traffic (+ the policy's own score, 60 by default); a zone's boundary default of **deny** was
  crossed with nothing approving it (+55). +15 more when the traffic was a decoded write or control command;
  +10 when the far side's zone is rated *restricted*; +10 when the near side's zone is rated *untrusted*.
* A policy or zone boundary in **record mode** produces the same event at `info` severity: stored, visible in
  Events and in the policy's own violation counts, never notified — how a newly frozen policy is tried out
  before it can page anyone.
* Not suppressed by learning (the judgement is about the pair's zones, not its history, the same reasoning as
  `ot_purdue_skip`). Cooldown six hours per (client, peer, protocol, port, cause); a burst against the same
  client and cause in one batch becomes one alert ("and N more"); after six in an hour for one client, further
  ones that hour are stored at `info`.
* Joins the `ot_intrusion` incident pattern, and starts its own `lateral_movement` pattern together with a
  network scan (`lan_scan`/`lan_sweep`) on the same device — see [Incidents](incidents.md).
* `ot_purdue_skip` is left exactly as it is: once Purdue-level zones exist, an out-of-level OT conversation can
  raise both rules. That is expected, not a duplicate bug.

## Industrial (OT) rules
Details and examples are in the [OT guide](ot-guide.md). In short:

* `ot_new_conversation`: a communication path that did not exist during learning.
* `ot_control_command`: stop/start, program download, restart. Never suppressed by learning.
* `ot_internet_exposure`: a **port normally used by an industrial protocol** crossing the network boundary. This is a
  port-number check (some of those ports have no way to confirm the payload from the outside), so the wording says
  "port X (normally Y)" rather than asserting the traffic is that protocol. "Crossing the boundary" means leaving the
  monitored subnets, not necessarily the public internet: a public remote scores 90 ("must never cross the network
  boundary"), another private network (a routed VLAN not covered by `--mirror-subnet`, say) scores 50 ("crosses into
  another internal network"). MQTT and CoAP are cloud IoT protocols by design and score 45 with their own wording
  ("a cloud IoT protocol, often unencrypted"), not treated as industrial control. A UDP flow on a TCP-only
  industrial port (Modbus, S7, OPC UA, IEC 104, MQTT) is ignored, since it is far more likely BitTorrent DHT/peer
  traffic landing on that port number by chance than the protocol itself. CoAP (UDP 5683) to a non-public IPv6
  address is ignored, since Matter and Thread devices talk it locally; a public peer is judged as before. IPv6 flows (`--ipv6`) are judged the
  same way — a public IPv6 remote scores 90, a unique-local one 50 — and share the same six-hour cooldown per
  device.
  *Confirmation tiers:* a UDP flow on an industrial port number is only a **coincidence** (a camera's random
  peer-to-peer port landing on 3671 or 5007) unless the device is an industrial one (PLC, HMI, RTU, an ICS vendor,
  or typed so by you) or the decoder has seen that protocol for it. Such a flow scores 35 (low) and is recorded as a
  quiet event (`port_coincidence`) for a random high port or a provider the device uses; a large first transfer, a
  threat-list hit or a risky port keeps it raised. TCP flows and industrial devices keep 90 / 50. Reserved
  addresses used by VPN and proxy software (`240.0.0.0/4`, `198.18.0.0/15`, `192.0.0.0/24`) are never "the internet":
  they are judged like another internal network (50). GE-SRTP (18245), PC Worx (1962) and Niagara Fox (1911) are
  TCP only, like Modbus and S7.
* `ot_purdue_skip`: two industrial devices talk across **more than one Purdue level** (a controller straight to an
  office PC; L1 ↔ L4, L2 ↔ L4, L3.5 ↔ L1…). Needs the Purdue level on both devices in the register. Score 50, +15 with
  write/control commands. Adjacent levels and the DMZ (3.5) next to 3 or 4 are fine. Once per pair per six hours.
* `ot_unexpected_writer`: a **phone, printer, camera, IoT gadget or similar** (by device type, including your
  correction) sends write or control commands to an industrial device. Score 65, +15 for control commands.
  Engineering laptops typed as *computer* are deliberately not judged by this rule.
* `ot_write_escalation`: a path that **only ever read** from an industrial device starts **writing** to it: how a
  monitoring connection turns into a controlling one. Score 60, +10 for an industrial target, +15 with control
  commands. Never during the learning period; once per pair per six hours (adjustable).
* `ot_goose_conflict`: the same IEC 61850 **GOOSE control block** (its `gocbRef` name) is published from **two
  different source MAC addresses** at the same time: a spoofed or injected publisher (GOOSE has no authentication
  without IEC 62351) or a duplicated device. Score 60, +15 when one address is a locally administered (made-up) one,
  +10 when the two belong to different manufacturers, +10 when the newer publisher appeared within the last hour. The
  alert is filed under the **newer** publisher and shows both addresses, their manufacturers, both APPIDs and the
  control block. The identity is the control block's *name*, not the APPID: APPIDs such as 0x0000 or 0x0001 are
  vendor defaults that many IEDs share. A **PRP duplicate** (the same frame over two LANs) carries one source address
  and is one publisher; HSR frames are not decoded. Both publishers must have been heard in the last ~50 minutes, so
  an IED replaced by new hardware does not conflict once the old one is off. A block that both addresses already
  published during the learning period (and the decoder's upgrade grace period) is the site's baseline and never
  alerts; a restart of DENIS forgets that baseline, so a standing duplicate can alert once more (an exception on the
  alert, or a lower weight, silences it). The configuration revision and the simulation flag are shown as evidence
  and are not scored. Once per newer publisher per six hours (adjustable, shared with `ot_write_escalation`). Needs
  GOOSE frames on the mirror (see the [OT guide](ot-guide.md#layer-2-traffic-goose-sampled-values-profinet)).
* `ot_command_watch`: **your own OT rules** for specific commands, or for **any communication** from a device that is not allowed to talk to a controller (also when it is encrypted): see the [OT guide](ot-guide.md#ot-rules) and [Encrypted traffic](ot-guide.md#encrypted-traffic-who-talks-to-whom-is-still-visible).

## Findings: standing problems, with a fix

Alerts are events; **findings** (the *Findings* tab, `GET /api/findings`) are conditions that stay true until
you fix them, so they vanish by themselves once fixed. Devices with the same problem are grouped into one
finding, each with why it matters and what to do.

| Finding | Severity | Meaning |
|---|---|---|
| `lost_device_online` | high | a device you marked *lost* or *stolen* was seen in the last 7 days |
| `kev_software` | high | a service announces a software version that is in the range of a vulnerability on CISA's known-exploited list ([below](#software-versions-end-of-support-and-known-exploits)) |
| `telnet_open` | high | Telnet open |
| `rdp_open`, `vnc_open`, `ftp_open`, `mysql_open`, `winbox_open` | medium | risky remote-access / data services reachable |
| `eol_software` | medium | a service announces a version whose support has ended |
| `retired_device_online` | medium | a *retired* device is still on the network |
| `critical_no_owner` | medium | criticality high/critical but no owner entered |
| `smb_open`, `mqtt_open` | low | file sharing on a non-computer; open MQTT broker |
| `eol_soon` | low | a service announces a version whose support ends within 90 days |
| `ot_no_purdue_level` | low | industrial device without a Purdue level |
| `unidentified` | low | type unknown and no name entered |
| `warranty_expired` / `warranty_expiring` | low / info | from the warranty date you entered |
| `cert_expired` / `cert_expiring` | medium / low | a TLS certificate has expired, or expires within 30 days ([service probe](#certificates-and-web-pages-opt-in), off by default) |
| `weak_tls` | medium | a TLS port still accepts TLS 1.0/1.1, or RC4, 3DES, NULL, export-grade or anonymous ciphers (service probe) |
| `cert_self_signed` | info | a TLS port presents a self-signed certificate (service probe) |
| `critical_unmanaged` | medium | a device rated high or critical is *not managed* or *failing* in your MDM or endpoint-protection tool (control coverage; never from *no match*, *ambiguous*, *unknown* or *off*) |
| `not_vulnerability_scanned` | low | the vulnerability scanner has no scan of the device, or its last scan is older than the limit (control coverage) |
| `coverage_unmatched` | info | DENIS cannot look the device up in your tools: no usable name, or a name shared with another device or record. Housekeeping, not a gap |

Only devices seen in the last 7 days are considered, and devices whose status is *spare*, *retired*, *lost*
or *stolen* are not nagged about exposed services. Exposure findings come from the port scan, so they appear
only for devices that have been scanned (never industrial devices).

## Certificates and web pages (opt-in)

Under *Settings* → **Network** → **Certificates and web pages** an administrator can switch on the **service probe**
(off by default; daily or weekly). It connects only to ports the port scan **already found open** — it never looks for
new ones — on local devices the scan is allowed to touch: never an industrial device, an excluded range, a device seen
only through a remote agent, or anything at all when DENIS runs `--passive-only`.

* **TLS ports** (443, 465, 636, 993, 995, 2376, 5001, 5986, 6443, 8006, 8443, 9443, 10250): one ordinary TLS 1.2/1.3
  handshake reads the certificate (subject, issuer, expiry, whether it signed itself) and the protocol and cipher; two
  short extra handshakes ask whether the service would still agree to TLS 1.0/1.1, or to RC4, 3DES, NULL, export-grade
  or anonymous ciphers, and are closed as soon as it answers. A device that only speaks TLS 1.0 still has its
  certificate read (it is sent unencrypted before TLS 1.3).
* **Web ports** (80, 3000, 8000, 8080, 8888, and 443, 5001, 8006, 8443, 9443 over TLS): one `GET /`, at most 64 kB
  read, and the page's `<title>` kept. Redirects are never followed.

Every connection has a short timeout, at most eight devices are probed at once with a pause between one device's
connections, and at most 1,024 devices per run. What comes back is kept as plain text in the device's panel
(*Certificates and web pages*) and feeds the four findings above. Switching the probe off removes what it found, and a
port that closes loses its result at the next run. The certificate is only read, never trusted: nothing is sent over
these connections except the `GET /`.

## Software versions: end of support and known exploits

When DENIS port-scans a device it also reads what the services say about themselves: the **banner** an SSH (22), FTP (21)
or SMTP (25) server sends when you connect, and the **`Server` / `X-Powered-By` headers** of a web server on 80, 8000,
8080 or 8888. That is one extra, ordinary connection per open port of those kinds (a `HEAD /` request for web servers); it
never happens for industrial devices or excluded ranges, which are not scanned at all. The banners are kept as plain text
(control characters removed, 200 characters at most) and shown in the device's panel.

**Extended banners** (Telnet 23, MySQL/MariaDB 3306, SMB 445, MSSQL 1433) read the same way, one or two more connections
each, only for a port the scan already found open — on by default, `--no-extended-banners` turns them off for an
administrator who would rather not connect to those specific ports at all. Telnet's banner and SMB's Windows build (read
from an SMB2 Session Setup's NTLMSSP challenge, same technique as `smbclient`/nmap's `smb-os-discovery`) and MSSQL's SQL
Server build (from a TDS PRELOGIN exchange) are kept as evidence in the device panel; MySQL/MariaDB's greeting gives a real
product and version like the others below. Windows/SQL Server build numbers are not (yet) matched against support-date or
CVE data — that needs a different kind of mapping than the semantic-version products below use.

From a banner DENIS takes a **product and a version** (OpenSSH, Dropbear, nginx, Apache HTTP Server, PHP, OpenSSL, lighttpd,
IIS, Exim, ProFTPD, vsftpd, MySQL, MariaDB) and asks two questions of it. **No version in the banner means no claim at all.**

* **Is this version still supported?** (`eol_software`, `eol_soon`.) From [endoflife.date](https://endoflife.date): support
  dates for nginx, Apache HTTP Server, PHP, OpenSSL, Exim and ProFTPD, refreshed weekly by default (Settings → Data →
  Software versions).
  A release whose date has passed is a finding; one that ends within 90 days is a low one. OpenSSH, lighttpd, vsftpd, Dropbear,
  MySQL and MariaDB have no published support dates built in, so they are never judged this way.
* **Is it in the range of a vulnerability that is being exploited?** (`kev_software`.) From the CISA *Known Exploited
  Vulnerabilities* catalog, with the affected version ranges from NVD and an exploitation-probability score from FIRST.org
  EPSS where known; only CVEs whose NVD ranges are clean and single-product are included. This ships as a **short,
  high-confidence** list, not a scanner's thousand CVEs, and can be extended two ways from Settings → Data → Software
  versions:
  * **Update now** fetches the current CISA catalog live, looks up ranges on NVD and scores on EPSS, for the same
    recognised products above; a weekly auto-refresh sits beside it, on by default like the support-date refresh
    (it can take a minute or two, since NVD is rate-limited per CVE; switch it off there if you would rather not
    contact those three sites).
  * **Custom CVEs**: add one by hand (CVE id, product, name, date, an exact version or a range) for software DENIS does not
    ship data for yet, or one you want flagged sooner than the next release. Matched exactly like the list above.

Each finding lists, per device, what was read and what it means (product, version, the release series and its end date, or the
CVE and its name; "used in ransomware campaigns" where CISA says so).

**Read a match as "check this", not as a verdict.** A distribution (Ubuntu, Debian, Red Hat…) often fixes a flaw without changing
the upstream version number, so a banner that names a distribution is worded accordingly ("may have been fixed"). A service can
also announce a version that is not what is really installed. *Verify fix* scans the device again, reads the banner again and
says whether it still announces that version; *Accept risk* works as for any finding.

**Where the data comes from and how it is kept.** `data/vulndata.json` ships inside DENIS (its date is shown under *Settings* →
*Data* → **Software versions**). It is built by `tools/build-vulndata.py` (needs `curl`), which you can run yourself: it fetches the three
sources, keeps a CVE only when its version ranges are unambiguous, and writes the file for you to read and commit. The support
dates can also be **refreshed by the console** from endoflife.date, weekly (on by default; an administrator can turn it
off) or on demand: that contacts one public site and sends nothing about your network. The known-exploited list arrives
with new DENIS releases.
DENIS never sends a version or a device name anywhere to look it up.

## Making the rules fit your network

On the **Rules** page (administrators):

* **Weight, minimum score and thresholds**, as before. Every rule also has **Alert only from score**: below it that
  rule is only logged, whatever the global minimum is. New settings include the burst size and window of
  `new_device_burst`, the repeat gaps of the OT rules and how many Purdue levels apart count as skipping.
* **Exceptions**, per rule: devices (by name), **device types**, **tags** and **networks** (`10.0.5.0/24`) that
  the rule stays quiet about. Typical uses: "never tell me about new destinations for the printers", "the lab VLAN
  may do anything", "this HMI is allowed to write". For industrial alerts the **sending** device counts too, so
  excepting the engineering station silences its control commands. An excepted alert is not stored at all; the
  audit log records who set the exception. A device-kind exception shows as a row — its name, MAC and IP, and,
  when it was added the quick way below, why.
* **Add exception**, on an alert itself (its row on the *Alerts* page, or its own detail dialog; administrators):
  one click adds the right exception for that exact alert, without a trip to the Rules page, and acknowledges the
  alert in the same step. What it adds depends on the rule: a device-scope exception for an ordinary rule; the
  alerting device added to that IT rule's own exceptions (`it_watch`); or the **sender** (who sent the
  command, found by MAC — not necessarily the device the alert is filed under) added to that OT rule's
  allowed senders (`ot_command_watch`).
* **OT rules** ([OT guide](ot-guide.md#ot-rules)): tell DENIS which commands to alert on, for
  which targets, and from which senders never.

*Reset everything to defaults* returns weights, thresholds and minimum scores to their defaults and **keeps** your
exceptions and rules (they are your content, not tuning).

## Verifying a fix and accepting a risk

Each finding on the **Findings** page has two buttons.

**Verify fix** (editors and administrators) looks again and answers per device:

| Answer | Meaning |
|---|---|
| **Fixed** | for an open port: DENIS just scanned the device and the port is closed. For a register finding (no owner, not reviewed, warranty…): the register no longer shows it. |
| **Still present** | scanned just now and the port is still open, or the register still shows it |
| **Did not answer** | the device did not respond to the scan (it may be off), so *nothing is confirmed*: a silent device is not treated as "fixed" |
| **Excluded from scans** | the address is inside an `--exclude` range: DENIS never probes it |
| **Not scanned** | industrial devices are **never** scanned (check the device and update its ports by hand); or this DENIS cannot probe (`denis serve` viewer mode, or `--passive-only`), in which case it says so |

The fresh port list is also written to the register. You can verify one device (the *Verify* button in the accepted
list) or every device of a finding.

A finding also shows **Seen in incident #12** for each [incident](incidents.md#related-findings) one of its devices
appeared in (still open, or active in the past 30 days). It is a link, not a state: resolving the incident does not close
the finding, and fixing the finding does not close the incident.

**Accept risk…** (administrators only, because it is a decision about risk) removes chosen devices from a finding and
records who accepted it, when, **why** (required: it is what an auditor reads) and for how long (30, 90, 180 days, a
year, or until withdrawn). Accepted risks are listed under the findings with their end date (highlighted when it is
within two weeks) and can be **withdrawn** at any time. When the time is up the finding counts again by itself. A
decision only exists while the problem exists: if the device is fixed the entry says *the problem is gone*.

**Accepted risks are watched** (once an hour, in the background):

* **Warnings before the end**: an event `risk_expiring` (severity low, so it can go to your notification channels) 14 days
  and again 3 days before a decision ends, and `risk_expired` when it has ended and counts again.
* **Rechecks**: once a day, DENIS scans the accepted *open-port* findings again (only those devices, never industrial
  ones, and only when the console can scan), so a fix is noticed without anyone pressing *Verify*.
* **Problem gone**: an `info` event `risk_gone` and an audit entry (`risk.gone`, by *system*) when the problem is no
  longer there. The decision is never withdrawn automatically: that stays a person's call. If the problem comes back
  and goes again, it is noted again.
Accepting is written to the [audit log](tour.md#audit-log-administrators) (`risk.accept` / `risk.revoke`, with the
reason) and accepted risks appear in the **saved reports** and as `denis_accepted_risks` in `/metrics`. API:
`GET/POST /api/risk-acceptances`, `DELETE /api/risk-acceptances/{id}`, `POST /api/findings/{id}/verify` (see the
[API reference](api.md)). Deleting a device, or *erase all data*, removes its accepted risks.

## Acknowledging and false positives

**Acknowledge** an alert once handled, optionally with a reason (*resolved*, *false positive*, *expected
behaviour*). It stops counting toward the device's risk (and you can *Undo*). Choosing *false positive* or
*expected behaviour* offers to add the matching exception in the same step. Several alerts can be ticked and
acknowledged together, and the same alert kind repeating for the same device is folded into one row you can expand.
For a recurring harmless pattern, prefer lowering that rule's weight or raising `--min-score` over ignoring
alerts. Repeats are suppressed by cooldowns, so an alert is not a flood.

## Learning mode, and forgetting a baseline

Besides the initial learning period, an administrator can **continue learning mode** for the whole network for 1
to 7 days (*Rules* → *Continue learning mode*), for after a change big enough that the existing baselines no
longer make a fair comparison (a new switch, a re-addressed subnet, a batch of new devices). It only pauses
alerting; each device keeps learning underneath. **Forget all learned baseline data** (same place, typed
confirmation) is the real reset: every device's destinations, ports, volume and active hours start from nothing.
One destination at a time can be removed from a device's baseline on its panel, or under *Rules* → *Exceptions,
accepted risks & baseline*.

**A lost alert does not teach DENIS the behaviour.** When an alert could not be saved (the database was briefly
unavailable), what the rule had learned for it (the destinations and ports of `new_destination` and `new_port`, a
DHCP or router-advertisement server, a DNS resolver, an industrial conversation) is taken back, so the next sighting
alerts again. Learned state that belongs to an alert is written to disk only after the alert itself is stored, so this
also holds across a restart. The delay is a few milliseconds; if the confirmation never arrives, saving resumes after
two minutes.

Rule settings can be **exported as a file and imported** on another install (*Rules* → *Export as file* /
*Import from file…*); the file is the same shape `PUT /api/rules` takes.

## Details from the console

Explanations that used to be printed on the console screens. The console shows them behind a small ? button.

* Off by default. When on, traffic between two of your own devices (a laptop and the file server, an HMI and a PLC) is recorded as relationships: who talks to whom, over which service, and since when. That is internal behaviour DENIS otherwise does not see, so switch it on only where that is acceptable. Takes effect at once, no restart. Needs traffic accounting (--flows) or a mirror interface; remote agents are switched with --east-west. The limits and what they cut are on the Health page.
