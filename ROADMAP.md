# Roadmap

DENIS already discovers every device on your network passively, learns how each one normally
behaves, tells you when something changes with every alert explaining itself, and shows everything
it knows about a device (directory, MDM, cloud, scanner findings, incidents) in one place. As of
v3.4.0 it also lets you define zones and policies for what should be allowed to talk to what, flags
traffic that breaks those rules, and can show a name instead of a bare address once you switch on
passive DNS. As of v3.5.0 it also shows which devices lack management, scanning or endpoint protection, tracks that over time against goals you set, and gives incidents a clear lifecycle. As of
v4.0.0 it can also run on PostgreSQL with an active/standby failover pair, block through sixteen
kinds of firewall and controller in addition to the original SNMP switch connector, offers three
new console looks, and remembers your language choice per account. As of v4.1.0 every one of its
twenty connector kinds can carry out actions (experimental, simulator-tested only, apart from switching a
switch port off), and an MSP can manage a customer's installation remotely (experimental). Next comes
correctness under failure for high availability, and validating the connectors on real equipment.

The list is in rough order. Plans can change, and nothing here is a delivery promise. Ideas and
pull requests are welcome.

## 4.1.0: what is in, what is experimental, what is not built

**In 4.1.0:**

* **Connections from the internet.** A new alert when an address on the internet completes a connection to one of
  your devices (a port forward to a solar inverter, a camera, a NAS), with the source, its country and network when
  known, the port and whether other devices were reached. A port can be marked as expected per device.
* **A quieter alert stream** with a daily digest; what is never kept quiet is listed in the alerting guide.
* **Autopilot (experimental, off by default).** Triage of alerts with questions answered on a phone (Telegram, ntfy,
  web push), starting in shadow mode. It blocks nothing unless an administrator also switches on *Autopilot may
  block*, a separate and even more experimental option.
* **Enforcement actions (experimental, off by default).** All 20 connector kinds can block a device and, where the
  device can, block one flow, quarantine, switch a port off or end sessions, through one path with a kill switch, an
  hourly limit, a preview, per-action permissions and a record of every change. MikroTik, Cisco ASA and Cisco FTD
  (through FDM and through FMC) are new. Automation levels: by default a person decides every action; automatic
  enforcement by policies you mark, and Autopilot blocking on top of it, are separate experimental switches.
* **MSP remote management (experimental).** An MSP console opens a customer's own installation at the level the
  customer chooses, with a banner, an activity list and a one-click disconnect; every operator needs a second factor.
* **Network identity and industrial networks.** VLAN tags are read and shown; tunnelled mirrors (ERSPAN, GRE, VXLAN,
  Geneve) can be read; S7comm-plus, IEC 61850 MMS and ICCP, GOOSE, PROFINET and OPC UA are decoded, and messages split
  across TCP segments are followed.
* **SNMPv3** for reading switches and controlling ports; Cisco switches are read per VLAN.
* **Agents** install with one command and are updated from the console; usedenis.com is a signed fallback download
  host used only when GitHub cannot be reached.
* **IT rules and OT rules** with a new dialog for writing them, and a refreshed console look.

**Experimental, and not yet verified on real equipment:** every enforcement action apart from switching a switch port
off over SNMP (tried on one real switch), Autopilot's real-world use, MSP remote management, SNMPv3, Cisco switches and
tunnelled mirrors. Each untried connector needs two lab switches before it can act.

**Not built in 4.1.0:** fencing of database writes during a failover (planned next), a separate encryption key per
customer on one installation, IP fragment reassembly for industrial decoding, and, for MSP management, a one-click
upgrade for customers that already relay to an MSP, fleet templates and queued changes for offline customers.

## Coming next

**Correctness under failure.** Fencing of every database write to the active node of a high-availability pair, an
enforcement path that survives a failover in the middle of an action, a test suite across two real machines, and
validation of the enforcement connectors on real equipment, starting with SNMP switches, FortiGate and UniFi.

**Network identity.** Overlapping address spaces (VRFs), layer-2 domains and a registry of capture sources, so that
several mirrors and sites can be told apart cleanly.

## Built in earlier releases

**The switches and cables view, redrawn** — built, in v3.4.1. Chassis-style switch nodes with real
port sockets, speed-weighted cabling and a VLAN legend (the VLAN now comes from the switch's own
forwarding table, not guessed) replace the old grid-of-dots drawing — click a port to see what's
connected to it and its VLAN. History of which device was on which port and when is kept behind
the scenes; you can now mark ports and VLANs as sensitive, and DENIS alerts when a device moves to another
port or VLAN, when something new appears on a sensitive port, or when a device suddenly looks like a
different machine than it has for weeks. Built and tested so far against synthetic switch
data and a hand-built fixture from a real low-end switch's SNMP replies; a second, more capable
switch is still needed before the forwarding-table and VLAN side can be called verified on real
hardware.

**Control coverage, and one workflow for alerts, incidents and findings** — built, in v3.5.0. A Coverage
view shows which devices are managed, scanned, in your directory and protected by endpoint security,
with "DENIS checked and found nothing" always shown apart from "DENIS could not check", daily history
and goals you set. Incidents have a clear lifecycle (open, acknowledged, resolved) with a required
outcome, every decision is recorded with who, when and why, and incidents and findings link both ways.
Watches are listed with your policies and can follow a zone, with a preview of which devices they cover.
The integrations behind coverage (Intune, Entra ID, Active Directory, Jamf, the cloud accounts,
Nessus and Defender for Endpoint) are built and tested against stand-ins, not yet against live
tenants of every vendor.

**A database built for scale, and a standing-up partner for it** — built, in v4.0.0. PostgreSQL is
now a selectable alternative to the built-in SQLite file, and two servers sharing one PostgreSQL
database can run as an active/standby pair with automatic failover in under two seconds if the
active one goes down. Both are off by default, for installations that specifically need them; a
normal single-server SQLite install is unaffected. Not yet verified across two real machines with
a real network between them — tested so far on one machine against one shared database.

**Three new console looks, chosen by you** — built, in v4.0.0. An inbox-style view, a dark operator
console, and a warm paper worksheet style, each in light and dark, alongside the existing looks.
Every user picks their own under My account; new installs default to the inbox-style one.

## Later

**Per-customer keys and delivery records.** A separate data key for each customer on one installation, and
notifications that keep a record of what was delivered, retried at least once and never claimed exactly once.

**Ask DENIS keeps growing.** Each new view above also becomes a plain-language question you can
ask, answered only from data DENIS actually has.

## On request

These are planned, and we start them when a customer needs them:

* **Windows as a packaged collector**, installed as a regular Windows service. Capture on Windows
  already works.
* **SAML single sign-on**, alongside the OpenID Connect sign-on that already exists.
* **Qualys import**, alongside Nessus and Tenable, which are already supported.

## Not planned

DENIS will stay a passive, agentless network sensor. We do not plan to build a vulnerability
scanner, a SIEM, endpoint agents, a full CMDB, or a single opaque "security score". DENIS works
alongside those tools and feeds them.
