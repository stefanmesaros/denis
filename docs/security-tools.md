# Security tools that may flag DENIS

DENIS finds devices by listening and, unless you tell it not to, by asking. The asking looks, to an intrusion
detection or prevention system (IDS/IPS), an endpoint protection product (EDR/antivirus with a network module) or a
firewall with threat prevention, like the first step of an attack: one machine contacting many addresses and many
ports. If such a tool runs on the DENIS server, or sits between it and the devices, it may raise a "port scan" or an
"ARP" alert about DENIS. This page says exactly what DENIS sends, so you can recognise the alert, allow it
deliberately, or reduce it.

## What DENIS sends

Everything below is sent from the DENIS server only. The sweeps go to hosts on the **main interface's own subnet**
(devices seen on a mirror port or on another monitored network are never swept). The one exception is a single known
device that is scanned again on request (**Scan again**, a fix confirmation, a risk re-check, a work item's
verification): it is port-scanned, and pinged when it does not answer, wherever it is, as the port scan and ping
switches of its network allow, and never when it is industrial. Nothing is sent with `--passive-only`, and nothing
is sent in the OT profile unless `--active` is given.

| What | When | Detail |
|---|---|---|
| ARP sweep | every 300 s (`--sweep-interval`, at least 30 s) | an ARP "who-has" for every address of the subnet (a /24 at most), two passes, paced 2 ms apart (50 ms in the OT profile) |
| Ping (ICMP echo) | each sweep, unless the ping is switched off | one echo request to every host that answered the ARP sweep, 800 ms timeout |
| TCP port scan | per host, at most once per 1,800 s (`--rescan-interval`), and for every host when someone presses **Scan now** (`POST /api/scan`); never while the port scan is switched off | a plain TCP connect (full handshake, no half-open SYN scan) to each of 73 common ports (the list in `SCAN_PORTS`, `src/fingerprint.rs`), up to 64 connections at a time, 800 ms timeout each |
| Banner reads | after the port scan, on ports found open (so never while the port scan is off) | one connection to each of ports 21, 22, 25, 80, 8000, 8080 and 8888 found open (read the greeting or the HTTP header); ports 23, 445, 1433 and 3306 (Telnet, SMB, MSSQL, MySQL/MariaDB) as well, unless `--no-extended-banners`. SMB and MSSQL send a short fixed negotiation (nothing is authenticated) |
| Certificate and web page probe | **off by default**; when switched on, every 24 h or 7 days | TLS handshakes (plus two short checks whether the server still accepts old TLS versions or weak ciphers) and one `GET /` on ports the port scan already found open; at most 8 devices at a time |
| IPv6 discovery | only with `--ipv6` | one all-nodes echo request and at most 1,024 paced Neighbor Solicitations per sweep, link-local only |

There is no exploit, no password guessing and no vulnerability probing. "Vulnerabilities" in DENIS come from
comparing banners and ports it already read against its own data, or from importing a scanner's results;
neither sends anything additional to the devices.

Industrial devices (OT) are never pinged, port-scanned or banner-read, in any profile.

## Why a security tool may react

* **Port scan.** A scan-detection feature counts how many distinct ports (or hosts) one source touches within a
  short time. The DENIS server connecting to 73 ports on each of many hosts in one sweep crosses those thresholds
  by design. Because DENIS completes the handshake and then reads or closes the connection, it looks like a
  connect scan.
* **ARP.** An ARP request for every address of the subnet from one host looks like ARP reconnaissance to tools that
  watch for it.
* **Ping sweep.** Echo requests to many hosts in a row is the classic sweep pattern.
* **Banner and TLS probes.** A short connection that sends a fixed message and closes can match scanner signatures
  for SMB, MSSQL or TLS version checks.

Typical examples are endpoint products on the DENIS server itself (a "network threat blocked: port scanning
attack" message), IPS on a firewall between the DENIS server and a VLAN, network detection systems
that watch a mirror port, and cloud-managed endpoint detection. The product names differ; the cause is the same.

## What to do

1. **Confirm the source.** The alert names the DENIS server's address as the attacker. If it does, the alert is
   DENIS doing what it is configured to do. If the source is any other address, treat it as a real finding and do
   not dismiss it on the basis of this page.
2. **Allow the DENIS server for that detection only.** In the security tool, add the DENIS server's address to the
   exclusion or allow list of the port-scan, ARP-sweep and ping-sweep detections (names vary by product: trusted
   addresses, IDS exceptions, scan-detection exclusions). Prefer a rule that names the one address and the one
   detection. Do **not** switch the security tool off, and do not exclude the whole subnet.
3. **Tell the security team** that the DENIS server is an authorised scanner, so a later alert from another source
   is not waved through with it.
4. **Reduce what is sent** if allowing is not possible, see below.

## How to reduce the probing

The flags are options of `denis run` and `denis agent`
([Deployment](deployment.md#flags-of-denis-run-and-denis-agent)); the first two are the only ones that stop traffic
altogether. The port scan and the ping can also be switched off in the console, for every network or for one
(see [Port scan and ping switches](#port-scan-and-ping-switches) below).

| Goal | How |
|---|---|
| Send nothing at all | `--passive-only`. DENIS then only listens: ARP, DHCP, mDNS, SSDP, LLDP/CDP and the like. Devices that never announce themselves, port lists, banners and the certificate probe are then missing from the inventory |
| Listen only on an industrial or sensitive network | `--profile ot` (no sweep, no ping, no port scan, no banner reads). `--active` adds back a slow, paced ARP sweep |
| Stop the port scan, keep the ARP sweep and the ping | Settings → Capture → Active probing, **Port scan** off, or `--no-port-scan`. The banner reads stop with it. Port lists and banners are then no longer refreshed |
| Stop the ping, keep the ARP sweep | **Ping** off in the same place, or `--no-ping` |
| Stop either for one network only | Settings → Capture → Monitored networks, **Probing…** on that network: port scan and ping each *as the global setting*, *on* or *off* |
| Never probe some ranges | `--exclude 10.20.0.0/24` (repeatable). Hosts there are still observed passively |
| Probe less often | `--sweep-interval` (seconds between sweeps, minimum 30) and `--rescan-interval` (minimum seconds between port scans of one host). Raising them to, say, 3600 and 86400 lowers the number of alerts, not their nature |
| Skip Telnet, MySQL/MariaDB, SMB and MSSQL banner reads | `--no-extended-banners` |
| Keep the certificate and web page probe off | it is off unless an administrator switches it on (Settings → Network → Certificates and web pages) |
| Avoid IPv6 discovery traffic | leave `--ipv6` off (the default) |
| Avoid manual full scans | do not press **Scan now**; it forces a port scan of every host regardless of the rescan interval |

For the systemd service put the flags in the service's arguments or `/etc/denis/env` as described in
[Deployment](deployment.md). The flags set the starting values; they are applied when DENIS starts.

### Port scan and ping switches

Two switches, each on by default (an install that never changes them sends exactly what it sent before 4.2):

* **Port scan**: the TCP connect scan of the 73 ports, on schedule, on **Scan now**, and when a single device is
  scanned again (**Scan again**, a fix confirmation, a risk re-check, a work item's verification; a device whose port
  scan is off is reported as excluded from probing instead). The banner reads are part of it: they only connect to
  ports the scan has just found open.
* **Ping**: the ICMP echo request to every host that answered the ARP sweep, and the ping a single device gets when it
  does not answer its scan again. With `--ipv6` the IPv6 echo requests follow the switch too: they go out only while
  the global ping switch is on, never to a device whose IPv4 address has ping off for its network, and the IPv6
  all-nodes echo is not sent while any monitored network has ping off.

A single device is never scanned again while the live inventory holds an industrial device at its address, or while
two VLANs claim that address, whatever the request says (the same rule as the sweep).

Where the value for a host comes from, per switch:

1. **The network's own setting.** In Settings → Capture → Monitored networks every IPv4 network has **Probing…**:
   port scan and ping each *as the global setting* (the default), *on* or *off*. When networks overlap, the most
   specific one that has its own value decides. The sweeps cover only the main interface's own subnet (only its own
   /24 when it has more than 1022 addresses); the table says "not swept" or "partly swept" for the rest. A
   network's setting still applies there to a single device that is scanned again. A network's setting goes when the
   network is no longer monitored (removed in Settings, or gone from the interfaces and the command line), so it never
   comes back by itself when the network is monitored again later.
2. **The console setting** (Settings → Capture → Active probing), once an administrator has saved one.
3. **The start flag**, `--no-port-scan` or `--no-ping`, else on.

On `denis run` the flag is only the starting value: once the console saves a choice, the console wins (a later restart
with a different flag does not change it). **Use the start command's values** under Active probing clears the saved
choice, so the flag applies again (`PUT /api/interfaces/probing` with `"default"`). On `denis agent`, which has no console
of its own, the flag is the only switch: a choice or a network setting that an earlier `denis run` saved in the same data
directory is ignored. `--passive-only` (and the OT profile without `--active`) stops everything, whatever the switches
say. Changes apply from the next sweep (a sweep already running finishes as it started), without a restart, and are
recorded in the audit log with the old and the new value. Only administrators can change them; like the east-west
switch, they ask for no password (adding or removing a monitored network does).

A saved setting that cannot be read (a damaged value, a database error) never turns probing back on: port scan and ping
are then off wherever that setting would decide (a network setting whose network is still known counts as off for that
network; a global choice or a list that cannot be read at all switches both off everywhere, or, while DENIS runs, keeps
the values already in force). The log and the Health page say so until the setting is saved again.

### Other probes that follow the switches

The **certificate and web page probe** (own opt-in switch, Settings → Network → Certificates and web pages) obeys the
port scan switch: it does not connect to a host on a network whose port scan is off. The **connection stability
test** sends no pings when ping is off for the network of its target (the gateway or the public resolver), with
`--passive-only`, or on a console that does not capture itself (a viewer, or a tenant's console fed by agents); the
test then reports an empty WAN leg and rates the browser leg alone.

### What the switches do not cover

* **IPv6 Neighbor Solicitations** of IPv6 discovery (`--ipv6`) belong to the sweep, like the ARP sweep, and are
  still sent while ping is off; only the IPv6 all-nodes echo stops. See IPv6 discovery.

### What cannot be switched off separately

* The ARP sweep cannot be switched off while DENIS probes at all; only `--passive-only` (or the OT profile) stops it.
* The list of scanned ports and the connection limit (64 at a time) and timeout (800 ms) are fixed in the program.
* The ARP sweep pacing is fixed (2 ms, or 50 ms in the OT profile) and cannot be changed.
* Banner reads of the always-on kinds (SSH, FTP, SMTP and HTTP) cannot be disabled on their own while the port scan
  is on; only the four extended kinds can. Switching the port scan off stops all of them.
* `--passive-only`, `--exclude`, the intervals and `--no-extended-banners` are start options, not console settings.

## Devices with several MAC addresses

A second kind of alert has nothing to do with DENIS's own traffic. An access point, mesh node, router or switch
often has several hardware addresses: one for the wired port and one per radio, differing in the last digit or two.
When the device answers for the same IP address from one of them and then from another, a tool that watches ARP
sees an IP address changing owner, which is also what ARP cache poisoning or MAC spoofing looks like. Such an alert
about an access point is usually a false positive caused by the access point, not by DENIS or anything on the
network.

DENIS watches for the same thing (the `arp_conflict` rule), and it can show such a device as **one device** with
several interfaces: when the device reports its own addresses (for example through SNMP or a connector), or when an
administrator links the rows by hand. See "one device per physical box" in the [API](api.md) and
[Concepts](concepts.md). An open ARP conflict pauses automatic linking until it is resolved. To make another tool
quiet, use its own exception for that access point's addresses; check first that both hardware addresses really
belong to the same access point, for example on its label or admin page.

## See also

[Quick start](quickstart.md) · [Deployment](deployment.md) · [OT guide](ot-guide.md) · [Concepts](concepts.md) ·
[Troubleshooting](troubleshooting.md)
