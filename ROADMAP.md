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

**Multiple customers on one installation, with real identity** — built, coming in the next release.
Each customer gets their own database, detector and console on the same installation, with nothing
of one customer reachable from another; managed service providers get technician accounts that work
across customers without a separate login in each one, plus moving a customer's data in or out as a
standalone file.

**Blocking a device, starting with switches you already monitor** — built, coming in the next
release. An optional, administrator-confirmed way to disable a device's switch port, for switches
DENIS already talks to over SNMP: one port at a time, with a preview of what is behind it, a reason,
password confirmation and one-click undo. Nothing is blocked automatically. Support for more kinds
of network equipment (RADIUS re-authentication, specific firewall brands) follows later — see
"Later" below.

**Fix it, and know it is fixed.** Assign a finding or an exposure to a person, set a due date, and
link a Jira or ServiceNow ticket (DENIS can file it and keep the key itself). DENIS confirms a fix
either by rescanning or by checking that the unwanted traffic really stopped while the device
stayed online, and watches for 30 days in case the problem comes back. This also finishes merging
the device records left behind when two collectors watching the same network are joined together.

**Smaller additions along the way** — built, coming in the next release. Certificate and
web-interface details for services already found on your network, so you can see expired,
expiring and self-signed certificates and services that still accept outdated TLS — opt-in, and
only for ports DENIS already knows are open. Four more free, well-known threat feeds you can switch
on one by one: abuse.ch ThreatFox and URLhaus, Spamhaus ASN-DROP and the Tor exit-node list, each
named on the alert when it flags an address.

**Is it your connection, or is it DENIS?** — built, coming in the next release. A one-click,
10-20 second test of your connection's real stability — packet loss, jitter and latency, not just
upload/download speed — with a plain verdict for what you actually use it for (browsing, a video
call, 1080p or 4K streaming) and a note on whether DENIS itself was doing anything on the network
while you tested. A button next to "Scan now"; every result is saved on the Health page.

**A database built for scale, and a standing-up partner for it.** An alternative to the built-in
SQLite file for installations with heavy traffic history or many tenants, plus an active-passive
failover mode for sites that need it running even through a maintenance restart.

**A more useful Ask DENIS** — built, coming in the next release. Ask it to look at your recent
alerts and it finds real patterns — a noisy device, scanning activity, an exposed port. Now you can
follow up in the same conversation: "add an exception for that", "this rule is too sensitive", or
"write me a new rule for this". Ask DENIS drafts the exact change — which rule stays quiet about which
device, or which setting moves from what to what — and an administrator reviews it and applies it
with one click (a new rule opens in the ordinary rule form, filled in). It never changes anything by
itself, and when you ask for something it cannot do, it says so plainly instead of changing the
subject.

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

**A living network map** — approved, coming soon. The Topology page gets an optional, toggleable
ambient motion layer: your network drawn as a quiet field of connected points, with the gateway
giving a slow, steady pulse to show the map is live, and a brighter pulse on a fresh alert so your
eye finds it immediately. Off by default until it ships; a user setting either way.

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
