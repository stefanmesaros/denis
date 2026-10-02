# Roadmap

DENIS already discovers every device on your network passively, learns how each one normally
behaves, tells you when something changes with every alert explaining itself, and shows everything
it knows about a device (directory, MDM, cloud, scanner findings, incidents) in one place. As of
v3.4.0 it also lets you define zones and policies for what should be allowed to talk to what, flags
traffic that breaks those rules, and can show a name instead of a bare address once you switch on
passive DNS. Next, DENIS uses that same picture to redraw what it knows about your switches and
cables, and to track coverage and progress over time.

The list is in rough order. Plans can change, and nothing here is a delivery promise. Ideas and
pull requests are welcome.

## Coming next

**The switches and cables view, redrawn** — in progress. Real switch ports, cabling and VLANs
(the VLAN now comes from the switch's own forwarding table, not guessed), with history of which
device was on which port and when, plus an alert when a device moves to another port or VLAN, or
something new appears on a port you have marked sensitive. Built and tested so far against
synthetic switch data and a hand-built fixture from a real low-end switch's SNMP replies; a second,
more capable switch is still needed before the forwarding-table and VLAN side can be called
verified on real hardware.

**Coverage and progress over time.** See which devices are missing management, scanning or an
owner — with "DENIS checked and found nothing" always shown separately from "DENIS could not check
this at all" — and track numbers like "unknown devices" or "unowned critical assets" falling week
by week, against a goal you set.

**A database built for scale, and a standing-up partner for it.** An alternative to the built-in
SQLite file for installations with heavy traffic history or many tenants, plus an active-passive
failover mode for sites that need it running even through a maintenance restart.

## Later

**A new look, chosen by you.** A cleaner, more modern console theme alongside today's look, each in
light and dark. Every user picks their own; an administrator sets the default. Validated with
mock-ups first, since half of a new visual identity can be worse than none.

**Blocking a device — more kinds of equipment.** Beyond the SNMP-managed switches already
supported: RADIUS-based re-authentication, then specific firewall brands one at a time
(pfSense/OPNsense, UniFi, FortiGate, Meraki, Palo Alto, Cisco, Check Point, SonicWall, WatchGuard,
Juniper), adjusted for what a given customer actually runs, now checked against the zones and
policies above before anything is confirmed. Each is its own release, each needs its own
real-world testing, and every rule above still applies: nothing blocks anything on its own.

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
