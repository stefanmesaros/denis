---

# Roadmap

DENIS already discovers every device on your network passively, learns how each one normally
behaves, tells you when something changes with every alert explaining itself, and shows everything
it knows about a device (directory, MDM, cloud, scanner findings, incidents) in one place. As of
v3.2.0 it also ranks the devices that most need attention today, with the reasons listed, and — if
you switch it on — records traffic between your own devices, so an alert can show who talked to
whom. Next, DENIS uses that picture to answer **what should be allowed to talk, and what do we do
when something does not follow the rules**.

The list is in rough order. Plans can change, and nothing here is a delivery promise. Ideas and
pull requests are welcome.

## Coming next

**Multiple customers on one installation, with real identity.** Each customer's data isolated by
design, for managed service providers and for organisations that need that separation internally.
This has been in active, incremental development for a while now.

**Blocking a device, starting with switches you already monitor.** An optional,
administrator-confirmed way to quarantine a device connected to a switch DENIS already talks to over
SNMP: one device at a time, with password confirmation and one-click undo. Nothing is blocked
automatically. Support for more kinds of network equipment (RADIUS re-authentication, specific
firewall brands) follows later — see "Later" below.

**Fix it, and know it is fixed.** Assign findings to a person, set a due date, and link a Jira or
ServiceNow ticket. DENIS confirms a fix either by rescanning or by checking that the unwanted
traffic really stopped while the device stayed online. This also finishes merging the device records
left behind when two collectors watching the same network are joined together.

**Smaller additions along the way.** Certificate and web-interface details for services already
found on your network, so you can see expired and self-signed certificates and weak TLS. More
free, well-known threat feeds.

**A database built for scale, and a standing-up partner for it.** An alternative to the built-in
SQLite file for installations with heavy traffic history or many tenants, plus an active-passive
failover mode for sites that need it running even through a maintenance restart.

**A more useful Ask DENIS.** Ask it to look at your recent alerts and it already finds real patterns
— a noisy device, scanning activity, an exposed port. The natural next step — "add an exception for
that", "turn down this rule's sensitivity for this device", or "write me a new rule for this" — will
draft the exact change for an administrator to review and apply with one click. It still never
changes anything by itself.

## Later

**Say what should happen, see what does.** Turn a device's observed behaviour into an approved
policy ("cameras talk only to the recorder"), define network zones, and get told when traffic
crosses a line it should not. This is also what the quarantine feature above checks against before
it is willing to act automatically on anything — right now it is strictly a manual, one-at-a-time
action.

**Names, not just addresses.** Optional passive DNS, so connections show `vendor.example` rather
than a cloud IP address, and a device that switches to an unexpected DNS server is flagged.

**The switches and cables view, redrawn.** Real switch ports, cabling and VLANs, plus an alert
when a device moves to another port or VLAN, or something new appears on a port you have marked
sensitive.

**Coverage and progress over time.** See which devices are missing management, scanning or an
owner, and track numbers like "unknown devices" or "unowned critical assets" falling week by week.

**A new look, chosen by you.** A cleaner, more modern console theme alongside today's look, each in
light and dark. Every user picks their own; an administrator sets the default. Validated with
mock-ups first, since half of a new visual identity can be worse than none.

**Blocking a device — more kinds of equipment.** Beyond the SNMP-managed switches above: RADIUS-based
re-authentication, then specific firewall brands one at a time (pfSense/OPNsense, UniFi, FortiGate,
Meraki, Palo Alto, Cisco, Check Point, SonicWall, WatchGuard, Juniper), adjusted for what a given
customer actually runs. Each is its own release, each needs its own real-world testing, and every
rule above still applies: nothing blocks anything on its own.

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
