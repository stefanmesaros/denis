# Roadmap

DENIS already discovers every device on your network passively, learns how each one normally
behaves, tells you when something changes with every alert explaining itself, and shows everything
it knows about a device (directory, MDM, cloud, scanner findings, incidents) in one place. As of
v3.4.0 it also lets you define zones and policies for what should be allowed to talk to what, flags
traffic that breaks those rules, and can show a name instead of a bare address once you switch on
passive DNS. As of v3.5.0 it also shows which devices lack management, scanning or endpoint protection, tracks that over time against goals you set, and gives incidents a clear lifecycle. As of
v4.0.0 it can also run on PostgreSQL with an active/standby failover pair, block through sixteen
kinds of firewall and controller in addition to the original SNMP switch connector, offers three
new console looks, and remembers your language choice per account. Next comes wiring the rest of
those connectors to actually apply a block, not just be configured and tested.

The list is in rough order. Plans can change, and nothing here is a delivery promise. Ideas and
pull requests are welcome.

## Coming next

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

**Blocking a device — wiring the rest of the connectors.** Fifteen new connector kinds shipped in
v4.0.0 (RADIUS-based re-authentication, OPNsense, UniFi, FortiGate, Meraki, Palo Alto, Check Point,
SonicWall, WatchGuard, Juniper, Proxmox, Hyper-V, VMware NSX, and AWS/Azure's own security groups),
alongside the original SNMP-managed switches, all checked against the zones and policies above
before anything is confirmed. So far only FortiGate and UniFi are wired to actually apply a block;
the rest can be configured and tested today, with their enforcement wiring following one at a
time, each needing its own real-world testing against actual hardware before being relied on. Cisco
ASA/FTD remains planned but not yet started.

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
