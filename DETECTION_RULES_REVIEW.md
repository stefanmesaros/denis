# Detection rules review (2026-09-30)

A review of the built-in detection rules (`src/detect.rs`), the administrator-configurable layer on
top of them (`src/rules.rs`), and how alerts feed the per-device risk score (`src/risk.rs`). The
questions were: is each rule correct as designed, which ones need adjusting, and which rules are
plainly missing given what DENIS already captures. This is a review only. No code, test or other
document was changed.

Same honesty labels as [MULTI_AGENT_DEDUP.md](MULTI_AGENT_DEDUP.md) and [CMDB.md](CMDB.md):

* **Verified** means read in the source in this worktree, including the parse and inventory code
  that feeds each rule, not only the rule itself.
* **Inferred** means reasoned from that source but not run. No test was run for this review, and no
  frame was replayed.
* **Judgment** means a claim about how real networks behave (consumer routers, IoT firmware,
  BitTorrent, Thread border routers). These claims are well known, but nobody has checked them
  against live traffic on a DENIS install. They should be tested against real traffic before
  anything is tuned on their strength alone.

## Short version

The rule engine is in good shape where it has been through real alert data (`new_port`,
`new_destination`'s noise handling, the ARP sibling-interface discount). The problems are mostly
**at the edges between parsing and detection**. In several places a rule is correct as unit-tested,
but the parse layer never delivers the input the rule was written for. The unit tests build
`FlowRecord`s and `Signal`s by hand, so they cannot catch this. The only full-pipeline test
(`tests/ot_pipeline.rs`, plus `replay.rs`'s single test) covers `ot_new_conversation`,
`ot_control_command` and `ot_internet_exposure`, and nothing else.

The five findings that matter most:

1. **`lan_scan` cannot see a scan of the local network** (verified). Flow records only exist for
   traffic between a local address and a *non-local* one (`parse.rs` `parse_flow`, lines 247/278).
   So the "many local addresses" that `lan_scan` counts are, by construction, private addresses
   *outside* the monitored subnets. A compromised device sweeping its own /24 produces no flow
   records at all. This holds even on a mirror port, and even with `--mirror-subnet` (which makes
   *more* traffic local, and so *less* of it visible to this rule).
2. **`rogue_dhcp` misses the most common real rogue DHCP server** (verified in code; the real-world
   part is judgment). Picture a consumer router plugged into the LAN by its LAN port, serving its own
   factory subnet. Its OFFERs come from an address outside the monitored subnet, so `parse_ipv4`
   never raises the signal (`parse.rs:448`, `ctx.is_local(&src)`). And when the rogue's address
   happens to equal the real gateway's (`192.168.1.1` is common to both), it gets the "it's the
   gateway" −30 discount, because that flag compares only the spoofable IP header source.
3. **`new_destination` goes permanently quiet on a port after one short burst** (verified). Three
   new destinations on the same port within an hour promote that port to "rotating" *forever*, for
   that device. Nothing requires the destinations to be related, and nothing ever decays the flag.
   On `tcp/443` this switches off the rule for most devices within days, on the port most
   command-and-control and exfiltration traffic uses. It also silences a spam bot on `tcp/25`
   after its third destination.
4. **MQTT and CoAP are treated as industrial protocols end to end** (verified that it happens; how
   often it fires is judgment). An MQTT `PUBLISH` counts as a *write*. So any smart plug, sensor or
   camera typed as IoT that publishes telemetry to a local broker raises `ot_unexpected_writer`
   (65, medium). It does so from day one, not subject to learning, about once an hour per device.
   The broker host also becomes an "industrial device" for every other purpose (never port-scanned,
   its TLS conversations enter the OT matrix). This hits the home/homelab audience hardest: a Home
   Assistant box running Mosquitto is exactly this setup.
5. **Your own watches are raised as *high* severity whenever the global minimum score is high**
   (verified). `it_watch` and `ot_command_watch` compute severity as
   `severity_for(score.max(min_score), min_score)`. Restarting learning mode sets `min_score` to
   101, and during that time every watch hit is filed as **high**, whatever score the
   administrator gave the watch. The same happens with any `--min-score` of 70 or more.

The most valuable missing rules, all buildable from frames DENIS already captures:

1. **Local reconnaissance visible from any switch port**: one device sending ARP requests for many
   different addresses, or SYNs to many ports on the collector's own address. These are the two
   things a LAN sweep produces that DENIS can see *without* a mirror port. It fills the gap in
   finding 1.
2. **Outbound fan-out on worm and spam ports**: an already-known device contacting many different
   *internet* addresses on Telnet, SSH, SMB, RDP or SMTP within minutes. This is the Mirai-family
   propagation and spam-bot signature. `lan_scan` deliberately ignores public addresses, and
   `new_destination`'s rotation logic actively suppresses it.
3. **DHCP option drift**: the DHCP server DENIS already knows starts handing out a different router
   or DNS server. This is the router-compromise pattern (DNSChanger/GhostDNS), and `rogue_dhcp`
   cannot see it because the server's MAC address did not change.

## A structural fact several findings depend on

Worth stating once, because it is easy to miss when reading `detect.rs` alone (verified,
`parse.rs:217-288`):

* A `FlowRecord` exists only when one side of an IPv4 packet is in `ctx.subnets` (the interface's
  own subnet plus any `--mirror-subnet`) and the other side is **not**, and is not multicast,
  broadcast, loopback or link-local. Traffic between two local addresses never becomes a flow. It
  is decoded only by `parse_ot`, and only when it is an industrial protocol or TLS.
* `FlowRecord.port` is `min(sport, dport)`, and a record carries no direction (who initiated) and
  no TCP state.
* ARP, DHCP-server, mDNS and SSDP observations are dropped when their source address is not in
  `ctx.subnets` (`parse.rs:334`, `448`, `462`).

So "local" in the rule descriptions and "local" in the parser mean different things. The parser's
meaning always wins.

## Per-rule audit

Rules not listed here were checked and found sound as designed: `device_silent`/`agent_offline`,
`threat_list_match`, `ot_control_command`, `ot_purdue_skip`, `new_port` (apart from one wording
nit below). Where this section suggests a change, a rough effort estimate follows in the same style
as ROADMAP.md.

### `lan_scan` (Internal network scan)

**What it claims:** an already-known device contacts many local addresses, or many ports on one
local address, in two minutes.

**What it actually sees (verified):** `lan_scan_hits` keeps only flows whose remote passes
`rules::is_private_addr` (`detect.rs:831`). As shown above, a flow's remote is never inside the
monitored subnets. What remains is private addresses on *other* subnets (other VLANs routed
through what DENIS watches, Docker/Kubernetes bridge ranges, `100.64.0.0/10` for CGNAT and
Tailscale). The unit tests (`many_distinct_local_addresses_…`, `…port_scan`) put `192.168.1.x`
straight into a `FlowRecord`, bypassing `parse_flow`. The real pipeline would never produce such a
record while `192.168.1.0/24` is the local subnet. The live alert that prompted the v2.x
"list the addresses" fix (CHANGELOG, "contacted 4 different addresses") must therefore have
involved addresses outside the configured subnets. Its `contacted_addresses` would show which kind,
and that is worth checking.

**What to do:**

* Scope the rule honestly for now. Rename the description to "a scan of *another* internal
  network", and change `RuleInfo.summary`, the ADVICE text and the documentation to match. The
  cross-subnet case is still worth catching: it is lateral movement between VLANs.
* Close the real gap with the reconnaissance rule in "Missing rules", item 1.
* Two false-positive fixes for the case it *does* see (inferred from code; the scenarios are
  judgment):
  * **Count only addresses and ports that are new for this device.** A Home Assistant box, a
    UniFi controller, a backup server or a Prometheus scraper in a server VLAN polls eight or more
    hosts in an IoT or client VLAN every couple of minutes. Today that is a medium alert every hour,
    forever. Filtering the log against `Baseline.typical_destinations` (for the host sweep) and
    against ports already seen to that host (for the port scan) keeps what a real scanner does,
    which is hit addresses it never used before, and drops routine polling.
  * **Ignore ephemeral "ports" in the port-scan branch** (`port >= EPHEMERAL_START`), as `new_port`
    already does. With `min(sport, dport)`, UDP between two high ports (RTP/VoIP, Steam Link or
    Moonlight streaming, WebRTC between VLANs) produces a random "service port" per flow, and eight
    of them to one host is a port scan by today's logic.
* Risk weighting: see `risk.rs` below. A scan currently counts as a "noisy" kind.

*(effort: 2/10 for the rescoping and both FP fixes)*

### `rogue_dhcp` (New DHCP server)

The brief asked whether this rule tells "the ISP router got replaced" from "a rogue DHCP server
appeared". Partly, and only in the easy case.

* **Router replaced, same LAN address (works, verified):** the new router's OFFERs come from the
  gateway IP, `sig.gateway` is true (`inventory.rs:282`), and it scores 40 (low) instead of 70.
  Expect it to arrive alongside `new_device` for the new router and, a couple of hours later,
  `device_silent` for the old one (45 + 15 gateway + 10 always-on = 70, high). That trio is
  correct, but it will read as an incident. A line in the rogue_dhcp advice, "if the gateway just
  changed MAC and the old router went silent, this is probably a replacement", would help.
* **Rogue server on a different subnet (missed, verified):** a consumer router or a travel router
  plugged into the LAN side serves its own default range (`192.168.0.1`, `192.168.50.1`,
  `10.0.0.1`, …; judgment: this is the typical real rogue DHCP incident in small offices). Its
  replies have an IP source outside `ctx.subnets`, so `parse_ipv4` never emits the `dhcp_server`
  signal (`parse.rs:448`). The rogue's ARP and mDNS are dropped by the same kind of gate, so it
  never even becomes an asset. And `Detector::dhcp_server` returns early for a MAC that is not a
  stored asset (`detect.rs:1617`, "Not stored yet: it will be seen again"). It will not be. The
  clients that take its lease then move into a subnet DENIS does not consider local. From then on
  their ARP and flows are dropped too (inferred), so the visible symptom is a cluster of
  `device_silent` alerts, not a `rogue_dhcp`.
* **Rogue server that spoofs, or happens to share, the gateway IP (under-scored, verified):** the
  gateway flag compares only the IP header source, which the sender chooses. A rogue router whose
  factory address equals the real gateway's (`192.168.1.1` on both is common, judgment) gets the
  −30 "routers normally serve DHCP" discount and lands at 40 (low).

**What to do:**

* In `parse_ipv4`, raise `dhcp_server` for any OFFER/ACK whose `giaddr` is `0.0.0.0` (not
  relayed: the sender is on this link by definition, whatever address it claims), not only for
  local source addresses. Keep the current gate for relayed replies, where the source is the relay
  router's own address. This is a parse change, not a capture change: the frame is already
  captured and already inspected.
* Let `dhcp_server` raise the alert without a stored asset (the alert can carry the MAC and the
  claimed IP), or create a minimal asset for it. Otherwise the fix above changes nothing.
* Base the gateway discount on the **MAC**, not the IP: apply it only if `s.mac` is the MAC that
  currently answers ARP for the gateway address (`by_ip[gateway]`). A same-address replacement
  router still qualifies once it has ARPed for the gateway IP, which it does at once. A rogue that
  only writes the gateway address into its IP header does not.

*(effort: 3/10)*

### `new_destination`: rotation promotion is sticky and indiscriminate

**Verified** (`detect.rs:975-1006`, and the test
`a_port_auto_detected_as_rotating_from_a_burst_stops_repeating_but_a_slow_trickle_does_not`):

* Three new-destination alerts on one `proto/port` in three different collection windows within an
  hour move that port into `Baseline.rotating_ports`, and set its churn to the maximum. From then
  on **no** new destination on that port raises an alert for that device.
* Nothing ever removes a port from `rotating_ports` or decays `destination_port_churn`. Only
  "forget baseline" does.
* Nothing requires the three destinations to be related. The test's own addresses are `10.0.0.1`,
  `20.0.0.1` and `30.0.0.1`: three unrelated /8s.

This fixed the real, measured noise it was built for (ROADMAP item 1). The cost is that for almost
any cloud-connected device, `tcp/443` (and probably `udp/443`) becomes permanently blind within
days of learning. That removes the rule's value for exactly the devices the documentation
recommends it for ("NAS, cameras, printers, servers"). **Two concrete false-negative scenarios**
(inferred):

* A camera is compromised in month three. Its new command server on `443` is never reported,
  because a firmware check-in burst in week one promoted 443.
* A device turned spam bot sends to dozens of mail servers on `tcp/25`. The first three raise
  alerts. The burst then promotes `tcp/25`, and every following destination is silent. The same
  applies to a device that starts brute-forcing SSH on the internet.

**What to do** (in order of how much each changes):

* Let the suppression swallow only low-signal contacts. A new destination on a rotating port should
  still alert when it carries one of the strong factors the scoring already computes: nobody else
  on the network has contacted it **and** at least 1 MB was sent, or the port is in `RISKY_PORTS`.
  That keeps the CDN and NTP noise out, because those destinations are shared with other devices
  and receive little data.
* Never auto-promote a port in `RISKY_PORTS`. A burst on 22, 23, 25, 445 or 3389 to new internet
  destinations is the signal itself, not noise (see "Missing rules", item 2).
* Give `rotating_ports` an expiry (for example 14 days after the last contact that counted towards
  it), so that one burst does not decide the rest of a device's life.

*(effort: 2/10)*

Small wording nit in `score_new_port` (verified): the RISKY_PORTS reason says "used towards the
outside". Since flows are always local↔non-local, that is true, but the "outside" may be another
internal VLAN. "towards another network" would be accurate.

### `ot_internet_exposure`

**Verified:** it fires on any TCP/UDP flow whose `min(sport, dport)` is in `OT_PORTS` or
`EXPOSURE_ONLY_PORTS`, scores 90, is not subject to learning, and holds for six hours per device.
Three problems:

1. **"Internet" here means "not the monitored subnet".** An OT site where DENIS watches the cell
   VLAN and the SCADA server sits in a routed VLAN not listed in `--mirror-subnet` gets a 90 (high)
   "an industrial control protocol … must never cross the network boundary" for ordinary Modbus
   polling. The fix is to split on `is_public_addr(remote)`: public remote, 90 as now; other
   private network, about 50, worded "crosses into another internal network". The
   public-internet case is the one the score was meant for.
2. **MQTT (1883) and CoAP (5683) are cloud IoT protocols by design** (judgment: plenty of consumer
   IoT, EV chargers and solar inverters talk plain MQTT to a vendor broker). Unencrypted MQTT to the
   internet is worth reporting, but as a hygiene finding, not as a 90 about "industrial control".
   Score these two at around 45, with their own wording.
3. **Port collisions from peer-to-peer traffic** (judgment, with a rough estimate). When both ends
   use high ports, `min(sport, dport)` is effectively random. The 17 flagged ports make up about
   1/3800 of the port space. A BitTorrent client's DHT and peer traffic reaches thousands of
   distinct peers per hour, most on random ports, so a torrenting machine can be expected to hit
   `44818`, `47808`, `20000`, `9600`, … several times an hour. That is one high alert every six
   hours, indefinitely. A detection-layer mitigation is to skip UDP flows for the TCP-only
   protocols, and to require the device to be industrial (`is_ot_device`) or the port to be one
   DENIS actually decoded. A cleaner fix, also in parse and not in capture, is to record whether the
   *other* port was ephemeral, and flag only when it was.

*(effort: 2/10 for all three)*

### MQTT/CoAP inside the OT rules (`ot_unexpected_writer`, `ot_write_escalation`, `ot_new_conversation`)

**Verified:** `ot.rs:599` classifies an MQTT `PUBLISH` as `OtClass::Write`. CoAP `POST`/`PUT` are
writes too. `flow.rs:114` counts those as writes on the (client, server) conversation. An MQTT
role also makes `fingerprint.ot` non-empty, which makes `is_ot_device` true for both the broker and
every client.

Consequences:

* `ot_unexpected_writer` (`detect.rs:1392`) fires whenever a client typed `iot`, `smart plug`,
  `camera`, `smart speaker`, … has `writes > 0`. It does not check that the server is industrial.
  It is also exempt from learning, and its default cooldown is one hour. **Every Tasmota, Shelly or
  ESPHome-style device that publishes to a local Mosquitto therefore raises a medium alert about
  once an hour, from the first day** (inferred from code; that such setups are common in the
  target audience is judgment). This needs DENIS to see that traffic. It does on a mirror port, and
  it also does when DENIS runs on the broker host itself, a likely homelab layout.
* A pure MQTT *subscriber* receives the broker's `PUBLISH` messages. With `server_is_src` those are
  counted as writes on the subscriber's own conversation (inferred), so display-only clients look
  like writers too.
* Once the broker host counts as industrial, local TLS to it (phones opening the Home Assistant app
  over HTTPS) passes the "TLS only when an OT device is involved" gate (`detect.rs:1193`). Each new
  phone then raises `ot_new_conversation` at 60, or 70 if the phone itself is new.
* The broker, now an "industrial device", is never port-scanned or pinged. So the `mqtt_open`
  finding, which exists precisely to flag an open broker, can never appear for a host that is
  actually seen serving MQTT (inferred from `findings.rs:268` and `inventory.rs:155`).

**What to do:** treat MQTT and CoAP as a separate class of IoT protocol. Keep them in the
communications matrix, but do not let them set `is_ot_device`, and do not let them feed
`ot_unexpected_writer` or `ot_write_escalation`, unless the other side is independently industrial
(by type or by vendor). Separately, `ot_unexpected_writer` should require `server_is_ot`, as its own
description ("…to an industrial device") already says. *(effort: 2/10)*

### `it_watch` and `ot_command_watch`: severity inflation

**Verified** (`detect.rs:810` and `1365`, `rules.rs:561`): both rules pass
`score.max(self.cfg.min_score)` into `severity_for`, so that a watch is "raised even if its score is
under the general minimum". The effect is that severity follows the global minimum, not the
watch's own score:

* **Restart learning mode** sets `min_score` to 101 so that "nothing anywhere can cross the alert
  threshold". Every watch hit during that time is filed with severity `high`, and goes to any
  channel that forwards high alerts.
* With `--min-score 75` (or 70), a watch the administrator scored at 35 is raised as `high`.

**What to do:** compute severity from the watch's own score, and treat "below the global minimum"
as a floor on *alert vs info* only. For example: `severity_for(score, 0)` when score > 0, and
`"info"` while a manual learning override is active. The last point is a product decision (the
documentation says watches fire during a device's learning period on purpose), but "high during a
period meant to silence everything" is plainly not intended. *(effort: 1/10)*

### `unusual_hours`

* **The histogram learns from any bucket, the alert only from buckets of 50 kB or more** (verified,
  `detect.rs:1749-1788`). `active_hours[hour] += 1` runs for every closed bucket, even one holding a
  single keep-alive. An always-on device (camera, NAS, IoT hub) therefore spreads its history evenly
  over all 24 hours, at about 4.2% each, and never drops below the 2% threshold. **The rule is
  effectively blind on exactly the always-on devices where 3 a.m. activity matters**, and works
  mostly on laptops and phones, the noisy ones. Fix: count a bucket toward `active_hours` only when
  it reaches `hours_min_bytes`, the same bar the alert uses. *(effort: 1/10)*
* **Fixed UTC offset** (verified, `main.rs:551`): `tz_offset_secs` is read once at startup. Across a
  daylight-saving change, a device on a wall-clock schedule moves by one hour in DENIS's frame, and a
  device with a sharp daily edge (a timer at 07:00) can alert for several days until the histogram
  catches up. It happens twice a year, restart or not. Fix: convert each timestamp with the tz rules
  (`localtime_r` per bucket), not a constant offset. Low priority. *(effort: 1/10)*

### `arp_conflict` / `arp_mismatch`

* **The per-claimant cap can swallow the gateway claim** (verified, `detect.rs:1458`). After five
  distinct addresses from one claimant within ten minutes, every further claim is skipped,
  including the one for the gateway. A full-duplex poisoner (bettercap-style, spoofing the gateway
  to each target and each target to the gateway) that happens to announce six client addresses
  before the gateway one loses the "+25 default gateway" alert. The five alerts it did get are
  already high, so the damage is context rather than detection. Fix: exempt `s.gateway` from the
  cap. *(effort: <1/10)*
* **`is_gateway` is sticky and set by IP alone** (verified, `inventory.rs:421`). A poisoner that
  wins the gateway address even once gets `is_gateway = true` permanently. Consequences today: it
  is typed as a router by the fingerprint guess (`fingerprint.rs:161`), it is automatically left
  out of Trends' top talkers (`trends.rs:134`), and it gains the +15 in `device_silent`. The same
  flag should mean "this MAC is our router", so set it only when the gateway address has been
  stable on one MAC for a while, or clear it when another MAC takes over the address.
  *(effort: 1/10)*
* **Attribution flips during a live conflict** (inferred). Once the poisoner holds `by_ip[gateway]`,
  the real router's next ARP makes the *router* the "claimant", and an alert is filed against the
  router's asset. The details show both MACs, so a careful reader will work it out, but the alert
  list shows the router as the offender. It would be better to keep blaming whichever MAC was
  *not* the long-standing holder.
* **Wi-Fi extenders in "universal repeater" mode** (judgment). These rewrite client MACs to their
  own (MAC-NAT). A client roaming between the main AP and the extender then appears as its IP
  moving between two MACs within seconds. That is 70 (high), plus 15 when several clients roam. The
  sibling-interface discount does not apply, because the MACs are from different vendors. A
  proportionate fix, in the same spirit as the sibling discount: a claimant that has held several
  addresses *steadily over hours* (not in a ten-minute burst) is a bridge or proxy, and its
  conflicts should score about 40 lower unless the gateway is involved. Worth confirming on real
  traffic before building, per the project's own bar.

### `new_device_burst`

**Verified** (`detect.rs:528-543`): `new_times` and `burst_until` are one global queue, not one per
collector. On a master with several agents, five new devices spread over five sites within ten
minutes count as a burst, filed under whichever site's device arrived fifth. This matters for the
MSP use case, and even more after multi-tenancy. Fix: key both by `agent_id`. The half-hour
reporting gap is also hardcoded (`now + 1800`) even though the window itself is configurable, which
is a minor inconsistency. *(effort: 1/10)*

### `volume_anomaly`

Sound. One adaptation behaviour to know about (inferred): the "an incident is not learned" clamp
(`learn_x = mean + z·floor`) also applies to a *legitimate* new routine, such as a nightly cloud
backup added last week. That routine raises alerts every night, at most one per hour, for days to
weeks while the mean slowly catches up. This is acceptable given how explainable it is; a
"recurring at the same hour for N nights" relearn could come later, if real alert exports show it
matters. Also note that "outside" means "outside the monitored subnet", so a backup to a NAS on
another VLAN counts.

### `rogue_ra`

* **Router Lifetime is ignored** (verified that `parse_ndp` does not read it; the scenario is
  judgment). Thread border routers (Apple TV, HomePod mini, Google Nest hubs: common in any Matter
  home) send Router Advertisements to announce the Thread network's route, with a Router Lifetime
  of 0, meaning "not a default router". Each new one raises `rogue_ra` at 70 (high). A zero-lifetime
  RA cannot take over the default route, although its route options can attract traffic for
  specific prefixes. Fix: read the Router Lifetime field (two bytes the parser already has in hand)
  and score zero-lifetime advertisers at about 35 ("announces routes, not a default gateway").
  *(effort: 1/10)*
* **No router-replacement discount.** `rogue_dhcp` scores a new DHCP server on the gateway address
  at 40, but `rogue_ra` scores the same replaced router at 70. Swapping one ISP router gives a low
  alert and a high alert for the same event. Applying the same MAC-based gateway check (see
  `rogue_dhcp` above) to RAs would make them consistent.

### `ndp_mismatch`: tied to the wrong knob

**Verified** (`detect.rs:1544`): `ndp_mismatch` uses `new_destination_v6`'s weight. That is the
IPv6 rule with no rotation suppression, and so the one an administrator is most likely to turn down
or off for noise. Turning it off silently disables an L2 spoofing signal as well. `arp_mismatch`
takes its weight from `arp_conflict`, its natural twin. `ndp_mismatch` should take its weight from
`RULE_ARP` in the same way. `rogue_ra` folding into `rogue_dhcp` is the right pairing and can stay.
The documentation's rule-weight paragraph would need the matching one-line change. *(effort: <1/10)*

### `new_destination_v6`

Noted without proposing new mechanism, given IPV6.md's explicit bar. The IPv4 rule's "−10 same /24
as a known destination" factor has no IPv6 counterpart, and IPv6 CDN addresses rotate within a
/48–/64 as a matter of course. A "same /64 as a known destination" factor would be a direct port of
an *existing* scoring factor, not the rotation-burst suppression IPV6.md defers. Even so, it
belongs under that document's "wait for real alert-noise data" rule, and is listed here only so
that the gap is written down.

### `new_device`

Sound. One grounded noise source (judgment): phones and laptops with private or rotating MACs
(iOS "rotating", Android per-connection randomisation) reappear under new MACs. Each time that
raises a `new_device` (35), and, if the old MAC was reliably present, a `device_silent` later. When
a new randomised-MAC device announces a DHCP hostname, DHCP parameter list and vendor class that
all match an existing randomised-MAC device that is no longer being seen, it is almost certainly
the same device rejoining. Scoring that case as info would remove a recurring alert without hiding
anything useful. *(effort: 2/10)*

### `risk.rs`: two security-relevant kinds count as "noisy"

**Verified** (`risk.rs:130-136`): kinds not listed explicitly fall into the "noisy" bucket (weight
0.25, capped at 30 points). That bucket currently includes `lan_scan` and `ot_write_escalation`,
which scores 60–85 and describes a monitoring path turning into a controlling one. So a device
seen scanning, or starting to write to a PLC, cannot become high-risk from its alerts alone, while
`new_port` (0.35, "serious") can. Suggested weights:

* `lan_scan`, `ot_write_escalation`: 0.4–0.6 in the serious bucket.
* `it_watch` / `ot_command_watch`: about 0.35, since the administrator explicitly asked for them.
* `new_device_burst`, `unusual_hours`: fine as noisy.

*(effort: <1/10)*

### Documentation discrepancies found along the way

These are in `docs/detection-rules.md`, verified against code:

* The `--rule-weight` name list omits `lan_scan` and `new_destination_v6`, and the page has no
  section for `lan_scan` at all.
* **Worked example 1 is inverted.** "Addresses: *any except these* → `private`" alerts on
  everything that is *not* private, which is internet traffic. That is the opposite of the stated
  goal ("any local device it reaches alerts"). The intended setting is *only these* → `private`,
  and even that setting only ever matches private addresses *outside* the monitored subnets (see
  the structural fact above).
* Examples 2 and 4 have the same limit. A guest subnet reaching internal servers is visible only if
  exactly one of the two subnets is local to DENIS. List both with `--mirror-subnet` and the
  traffic between them produces no flows at all.

## Missing rules, in priority order

Each item below is buildable from frames DENIS already captures. None needs a new protocol decoder,
a new BPF expression or an OS integration. Where a small `parse.rs` change is needed, it only keeps
a field of an already-parsed message that is currently thrown away. Each is tied to a specific,
documented attack pattern, and each is scoped to its narrowest useful slice. Candidates considered
and rejected are listed after these, with the reason.

### 1. Local reconnaissance visible from any switch port (`lan_sweep`) *(effort: 3/10)*

**Pattern:** a device on the LAN mapping its own subnet: `nmap -sn`, Metasploit or worm ARP
sweeps, `arp-scan`. This is the most common first step after an internal compromise, and exactly
what `lan_scan` cannot see (finding 1).

**Why it is buildable without a mirror port:** a host sweep of a local /24 *must* ARP for every
address, and ARP requests are broadcast. DENIS receives them on any switch port, whatever its
deployment. `BPF_FILTER` already admits `arp`. `parse_arp` already decodes every request and keeps
only the sender binding. The **target** address (`tpa`, bytes 24–27) is read past and discarded.
Separately, a port scan that includes the collector's own address sends SYNs to DENIS's own MAC.
`BPF_FILTER` already admits TCP SYNs, and `parse_tcp_sig` already parses them for fingerprinting,
but discards the destination port.

**Narrowest slice:**

* **ARP fan-out.** One sender MAC requesting at least N distinct target addresses (default around
  20, which is well above ordinary behaviour) within one to two minutes.
* **Collector as canary.** One local source sending SYNs to at least M distinct ports (default
  around 10) on `ctx.own_ip` within a minute. Nothing legitimate does this to a monitoring box
  except a scanner. Score it high.

**Known false positives** (judgment), handled with the learning period the codebase already uses:

* Routers that re-ARP their whole client table.
* Consumer routers with "network map" features (several ASUS models).
* Phone apps like Fing.
* A Home Assistant or UniFi controller doing discovery.

Exempt the gateway MAC, and learn "sweepers seen during the learning period" the way
`dhcp_known` learns DHCP servers. Unlike `lan_scan`, this one works without a mirror port, on an
ordinary LAN-attached collector.

### 2. Outbound fan-out on worm and spam ports (`outbound_fanout`) *(effort: 2/10)*

**Pattern:** Mirai and its many descendants propagate by scanning random internet addresses on
Telnet (23/2323), SSH (22), and a few service ports (5555 for ADB, 7547 for TR-069). Spam bots
fan out on `tcp/25`. SMB and RDP worms use 445 and 3389. For a home or SMB network full of cameras,
DVRs and routers, this is the single best-documented IoT compromise signature.

**Why it is missing today (verified):** `lan_scan` explicitly ignores public addresses.
`new_destination` alerts on the first few, then its rotation promotion *suppresses* the rest (see
the audit above). `new_port` needs a known destination.

**Narrowest slice:** within a few minutes, one already-known device contacts at least N (default
around 10) distinct *public* addresses on one port from `RISKY_PORTS ∪ {2323, 5555, 7547}`. It
never learns this as normal, and never promotes the port to "rotating". The data is entirely in
the existing `FlowRecord`s; this is detection-layer only, next to `lan_scan_hits`.

**False positives** (judgment):

* A mail server legitimately fans out on 25. Exclude devices typed `server` or `mail`, or better,
  anything whose baseline already shows that port to many destinations.
* An administrator's workstation running Ansible over SSH to cloud hosts fans out on 22. Handled
  the same way, through the baseline.

BitTorrent is not a concern, because it does not use these ports.

### 3. DHCP option drift (`dhcp_options_changed`) *(effort: 2/10)*

**Pattern:** the router that hands out addresses is itself compromised or misconfigured, and starts
handing out an attacker's DNS server (DNSChanger, GhostDNS, and the mass SOHO-router DNS hijacks
of recent years) or a different default gateway. `rogue_dhcp` cannot see this, because the
server's MAC does not change.

**Why it is buildable:** DHCP OFFER/ACK frames are already captured and already parsed by
`parse_dhcp`, which walks every option and keeps only 12/55/60/53. Options 3 (router) and 6 (DNS)
are in the same loop and are thrown away. Visibility is also unusually good for a switched
network: when the collector's own interface uses DHCP, it receives its own ACK at every renewal.

**Narrowest slice:** per known DHCP server, learn the router and DNS values during the learning
period, and alert when an OFFER or ACK carries a different value. Score about 60, or 75 if the new
DNS server is public and not one that any device already uses.

**False positives:** an administrator changing the router's DNS (to Pi-hole, NextDNS, …) is exactly
what this alerts on. That is intended: a single alert, and one click to acknowledge it.

### 4. DHCP starvation (`dhcp_starvation`) *(effort: 2/10)*

**Pattern:** flooding DISCOVERs with made-up client hardware addresses exhausts the real server's
pool (the Yersinia and dhcpstarv class of attack). It is the textbook first half of the "starve the
real server, then answer as a rogue" attack chain, so it pairs naturally with `rogue_dhcp`. Today
each made-up address becomes a *new asset* (inferred: `parse_dhcp` keys the observation on
`chaddr`), so the side effect is a polluted inventory plus a `new_device_burst` whose explanation
is wrong.

**Why it is buildable:** the frame's Ethernet source is in hand in `parse_ipv4`. `chaddr` is
already read. `giaddr` sits at a fixed offset in the same header.

**Narrowest slice:** one Ethernet source sending DHCP requests for at least 20 distinct `chaddr`
values within five minutes, with `giaddr` of 0 (not a relay).

**False positives** (judgment): MAC-NAT Wi-Fi extenders legitimately send DHCP on behalf of a
handful of clients, so key the rule on volume, not on the mismatch itself. A burst of 20 or more in
five minutes is not what an extender produces. As a hygiene follow-up, stop creating assets from
`chaddr` values that arrive in such a burst.

### 5. Identity flip on a known MAC (`fingerprint_changed`) *(effort: 3/10)*

**Pattern:** MAC cloning, meaning an attacker takes a trusted device's MAC to get past MAC
allow-lists, captive portals or ACL'd VLANs, or to inherit its DHCP reservation. From that point
DENIS attributes everything to the trusted device.

**Why it is buildable:** the inventory already records, per MAC, the initial-TTL family, the TCP
SYN signature, the DHCP parameter list and vendor class, and JA3. `inventory.rs` already knows when
one of them changes (`set_if_some` returns `changed`).

**Narrowest slice:** alert only when the *OS family* flips on a MAC with at least seven days of
stable history. That means the initial TTL family changing between 64 and 128, or the DHCP vendor
class changing family (for example `android-dhcp-*` to `MSFT 5.0`). Do not alert on
parameter-list or JA3 changes, because OS and browser updates change those routinely
(judgment). This is deliberately the least ambitious version. Widen it only if real incidents call
for it.

### 6. An industrial device talking to the internet at all *(effort: 1/10; a scoring change, not a new rule)*

`ot_internet_exposure` is port-based. A PLC calling any public address on 443 (a vendor cloud, or
a remote-access agent someone installed) only gets `new_destination`'s ordinary 35–50. The fix is a
factor, not a rule: "+20 the device is an industrial controller/device (`is_ot_device`, by type or
vendor, *not* by MQTT role — see above)". It is cheap, and it goes in the direction IEC 62443
already points.

### Considered and deliberately not proposed

* **Beaconing / periodic C2 detection.** It is well grounded in the literature, but on a home or
  IoT network nearly everything beacons legitimately (vendor keep-alives, NTP, telemetry). Without
  a destination allow-list it would be the noisiest rule in the product, and it would need
  per-destination timelines that the baseline does not keep. That is exactly the "speculative,
  invented for completeness" case IPV6.md warns about. Revisit only with a concrete incident that
  it would have caught.
* **LLMNR/NBT-NS/mDNS poisoning (Responder).** High value on Windows networks, but LLMNR (5355) and
  NBNS (137) are not decoded today, which would mean a new protocol parser. That is out of scope for
  this review, and belongs in ROADMAP.md if it is wanted.
* **DNS resolver bypass** (a device querying a public resolver directly). It is already
  expressible as an `it_watch` ("anything but DNS/web/time to the internet", a ready-made preset).
  It would also be noisy as a built-in rule (judgment: Chromecasts and many IoT devices hardcode
  8.8.8.8).
* **UPnP port-mapping requests.** These are SOAP over HTTP to the router, not SSDP, so this would
  mean new parsing. Not proposed.
* **"Internet-exposed device" (inbound connections from many public addresses).** `FlowRecord`
  carries no direction, and with `min(sport, dport)` an inbound connection to 443 looks the same as
  an outbound one. It needs an initiator bit in parse first. Not proposed until that exists.
* **IPv6 parity** (rotation suppression, `new_port`, threat list, watches, `lan_scan` for IPv6).
  IPV6.md already owns these, under its explicit "wait for real data" bar. Not re-proposed here.

## Suggested order

1. The one-line correctness fixes first, since they need no design: watch severity, gateway
   exemption from the ARP cap, `ndp_mismatch`'s weight, the `risk.rs` buckets, and the
   `unusual_hours` histogram bar. Together about a day of work, plus tests.
2. `rogue_dhcp`'s off-subnet and gateway-spoofing gaps, and `ot_internet_exposure`'s
   public/private split. Both are false-negative or false-positive problems with a clear fix.
3. `new_destination` rotation: bound the suppression. This is the most consequential design
   change. Try it against the same real alert export the v2.20.0 fix was diagnosed from, so the
   CDN noise that fix removed does not come back.
4. MQTT/CoAP out of the OT class.
5. Missing rules 1 and 2 (`lan_sweep`, `outbound_fanout`): the largest gains in actual coverage.
   Then 3 and 4 (the DHCP pair), then 5 and 6.
6. `lan_scan` rescoping and its false-positive fixes can go together with item 5 above: once
   `lan_sweep` exists, `lan_scan` honestly becomes the cross-VLAN rule.

Every item here should get at least one test that feeds **real frames through `parse_frame`**, not
hand-built `FlowRecord`s or `Signal`s. Findings 1, 2 and 4 in the short version all survived their
unit tests because the tests started one layer too late.

## What this review is not

It is not a claim that the findings marked *judgment* have happened on a real DENIS install. They
are well-known network behaviours (consumer routers' default subnets, MAC-NAT extenders, Thread
border routers, BitTorrent port distribution, MQTT telemetry) applied to logic that was verified by
reading. The fastest way to confirm or discard them is the same as the v2.20.0 noise fix: an alert
export from a real network, or a pcap replayed through `denis replay`.
