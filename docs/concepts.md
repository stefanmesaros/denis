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

Put **one collector per network segment**. Two collectors on the same segment report every device twice.

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

## Risk score

Each device also has a **risk score** (0–100) built from what it exposes and what it has done: open Telnet/RDP/
FTP…, an unidentified type, "unpatched-by-nature" categories (IoT, cameras), and its *unacknowledged* alerts
(recent and severe ones count more). The factors are listed on the device page. **Acknowledging** an alert
removes its contribution: the workflow is *investigate → acknowledge → risk drops*.
Criticality (Edit asset) makes alerts on an important device weigh more.

## Sites, agents and the master

A small network needs one process: `denis run`. For more sites, run `denis agent` at each remote site; it
collects locally and pushes summaries to the master (outbound connection only, so it works behind NAT).
See [Deployment](deployment.md#multiple-sites-agents).

## Timezones

Hour-of-day rules use the *server's local time zone*. Timestamps in the UI use the browser's; exports and the
report use UTC and say so.
