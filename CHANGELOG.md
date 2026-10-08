# Changelog

This is a customer-facing summary of what changed release to release — grouped by what it means
for you, not by internal implementation detail. Every release's full technical notes ship inside
the binary and the GitHub Release page for that version.

## 4.0.2: IPv6 detection now matches IPv4, per-site time zones, and the remaining 4.0.1 follow-ups

- IPv6 traffic is now checked against the threat list, zones and segmentation policies, the
  internal-scan and outbound-fan-out rules, and OT-exposure scoring, the same way IPv4 traffic
  already was. IPv6 conversations now also show up in the relationship view ("who talks to
  whom"), and an IPv6 destination no longer inflates or evicts an IPv4 device's own list of
  known destinations.
- Each site (remote collector) can now have its own time zone, so "unusual hours" is judged by
  the site's own clock instead of always the master's.
- Under a flood, the small buffer DENIS uses before writing security signals to disk now keeps
  spoofing/rogue-DHCP signals over routine ones instead of dropping either at random, and Health
  now shows when this buffer has been running full.
- API tokens are now tied to the account that created them by a permanent reference, not by that
  account's name, closing the last part of a 4.0.1 fix for a deleted-and-recreated username
  reviving an old token. The token list also shows plainly when a token's creator account no
  longer exists.

## 4.0.1: hardening against denial-of-service and spoofing, and a simpler choice of three console looks

- A security review found and fixed several ways the console or a remote collector could be made
  to use unlimited memory or CPU, including before anyone signs in: concurrent sign-in attempts
  are now limited, and a single malformed report from a remote site can no longer crash the server
  or be used to exhaust its memory.
- Account lockouts, for both passwords and two-factor codes, can no longer be bypassed by sending
  many requests at once, and a flood of failed sign-ins can no longer be used to reset another
  account's lockout count.
- Deleting a user now properly revokes any API tokens they created, so a token tied to a deleted
  account cannot start working again if the same username is used later.
- Several ways a forged network packet could mislabel a device as the network's gateway, plant
  false DNS records, or make the console actively contact attacker-chosen addresses are fixed.
- A compromised or leaked remote-site token could previously affect devices at other sites in the
  same installation; identity data a remote site reports now only ever applies to that site's own
  devices.
- IPv6 traffic now counts toward the same volume-anomaly detection IPv4 traffic already had.
- The console now offers three looks, Triage, Scope and Clipboard; the original look and Deep
  Field have been retired, and everyone now sees Triage by default.

## 4.0.0: PostgreSQL and high availability, 16 enforcement connectors, console skins and per-account language

- DENIS can now run on PostgreSQL instead of SQLite, as an alternative, selectable database for
  installations that need it. Nothing about a normal single-server install changes if you keep
  using SQLite, which stays the default. Backups on PostgreSQL leave integration secrets out, the
  same as on SQLite.
- On PostgreSQL, two DENIS servers can share one database and run as an active and a standby pair.
  If the active one goes down, the standby takes over within a few seconds, so the console keeps
  working without someone switching it by hand. This is for installations that need that kind of
  resilience; a single-server install does not need it and is unaffected.
- Sixteen enforcement connectors are now available under Settings, Enforcement, including
  FortiGate, Palo Alto, UniFi, Meraki, Check Point, SonicWall, WatchGuard, Juniper, Proxmox,
  Hyper-V, VMware NSX, OPNsense, RADIUS, and AWS and Azure. You can configure more than one of the
  same kind, for separate firewalls or sites, and block a device straight from its own page once a
  connector is set up. As before, every block is started by an administrator by hand and nothing
  is ever enforced automatically.
- The console now offers three looks you can choose from, alongside the existing default: an
  inbox-style view, a dark operator console, and a warm paper worksheet style. Each comes in a
  light and a dark variant. Pick one under My account; your choice follows you, and anyone who has
  not chosen yet sees the new inbox-style look by default.
- Your preferred language is now a personal account setting instead of a setting tied to one
  browser, so it follows you when you sign in on a different computer.
- The devices list now shows the actual risk number next to the priority word, so you can see at a
  glance how two devices with the same priority compare.
- A commercial license is now tied to the installation it was first used on, the same way its
  validity period already was. When an install has more devices than its license (or the
  Community edition's 100-device limit) allows, the console now shows exactly how many devices are
  listed out of the real total, with a plain explanation, instead of listing every device
  regardless of the license.
- After a backup restore, Settings now lists exactly which integrations (AI providers,
  notification channels, and others) lost their secret and still need it entered again.

## 3.6.0: Encrypted integration secrets, service health checks and console fixes

- Passwords and API keys for the directory, cloud, vulnerability scanner and IP enrichment
  integrations are now encrypted in the database. The key is kept in a file (secrets.key) in the
  data directory. Keep that file with the data: if it is lost, every integration secret has to be
  entered again. An existing installation converts its stored secrets once, at the first start.
- Backups and MSP uploads leave integration secrets out by default. After a restore, DENIS lists
  the integrations that need their secret entered again.
- Health shows five service checks: packet capture, database writes, background jobs, threat feeds
  and backups. A service that is stale or has never run is shown as a warning. The limits are
  listed in Health and can be changed by the developer.
- Background jobs that stop unexpectedly are reported and restarted where that is safe.
- A closed incident opens again when you click it from the list.
- The device page has one action bar; "Unmerge" appears when a device has merged addresses.
- Incidents have one AI button. A stored assessment is shown on request; "Ask again" runs a new one.
- Expanded alert groups can be collapsed from their footer.
- The sign-in screen appears at once, and the device list shows a loading state until the devices
  arrive.
- Switch and cable labels no longer overlap, and Software rows open the device list.
- The look (Default or Deep Field) is chosen under My account, not in the header.
- Zones and policies wrap long names instead of running off the page.
- A connection stability test can only be read and stopped by the user who started it.

## 3.5.1

* **Fixed:** an incident you closed opens again when you click it from the list.
* **Fixed:** the "Assign" and "Explain with AI" buttons in findings, events and alerts are where you
  expect them, and long names in Zones and Policies wrap instead of running off the page.
* **Changed:** the device page has one action bar. "Unmerge" is there when a device has merged
  addresses.
* **Changed:** incidents have one AI button. A saved assessment is shown on request, and "Ask
  again" runs a fresh one.
* **Changed:** an expanded alert group can be collapsed from its footer.
* **Changed:** the sign-in screen appears at once, and the device list shows a loading state until
  the devices arrive.
* **Changed:** switch and cable labels no longer overlap, and the Users page keeps its columns
  button next to "Add user".
* **Changed:** Software rows open the device list.
* **Changed:** the look (Default or Deep Field) is chosen under My account, not in the header.
* **Background jobs** that stop unexpectedly are reported in Health and restarted where that is
  safe. A connection stability test can only be read and stopped by the user who started it.
* **Health** warns about a legacy local certificate authority that has no name constraints.

## 3.5.0

* **Control coverage.** A new Coverage view shows, for every device, whether it is managed (MDM),
  in your directory, scanned for vulnerabilities and protected by endpoint security, with the
  evidence behind each answer ("no device called reception-pc in Intune, synced 3 hours ago").
  "DENIS checked and found nothing" is always shown apart from "DENIS could not check", so a gap
  in what DENIS can see never reads as a gap in your network. Missing controls become findings
  you can accept as a risk, track and re-check. A daily history lets you set a goal and watch the
  numbers move, and the Dashboard shows where you stand. Microsoft Defender for Endpoint is a new
  source. All eight integrations are built and tested against stand-ins, not yet against a live
  tenant of every vendor, and are marked that way in Settings.
* **One workflow for alerts, incidents and findings.** Incidents are open, acknowledged or
  resolved. Resolving needs an outcome (resolved, false positive or expected behavior) and applies
  to the incident's open alerts, but never overwrites a decision someone made on an alert
  themselves. Every decision is recorded with who, when and why, and that record is kept for
  three years by default (Settings, Data retention; you can shorten it or keep it forever).
  Incidents and findings link both ways: an incident lists its related findings and lets you
  track a fix, and a finding shows the incident it appeared in.
* **Watches and policies, closer together.** Your network and command watches are listed with
  your other policies, and every place that asks "who does this apply to" now uses the same
  picker, including Purdue level, register zone and site. A watch can now follow a zone, and
  before you save it you see which devices it covers today. If a zone a watch follows disappears,
  the watch stops matching instead of matching more, and says so.
* **A more reliable update window.** The window could stay on "Downloading" although the update
  had installed and DENIS had restarted. It now follows the update to the end and shows a clear
  result: updated (and the console reloads), rolled back, or a plain "still not back after N
  seconds" with a Reload button. This helps from the next update onward. Release notes in the
  window now keep their headings, lists and links.
* **Changed:** acknowledging selected alerts in bulk no longer overwrites alerts that already have
  a decision. Directory and scanner records are matched to devices the same way for every
  import, and a name shared by two devices is marked ambiguous instead of matching the wrong one.

## 3.4.1

* **The Switches and cables view, redrawn.** Chassis-style switches with real port sockets,
  cabling weighted by speed, a clickable VLAN legend and a drawer for each port. The VLAN now
  comes from the switch's own forwarding table, and DENIS remembers which device was on which
  port, and when.
* **Four new alerts about changes on your network:** a device moved to another port, a new device
  on a port or VLAN you chose to watch, a device changed VLAN, and a device that suddenly looks
  like a different machine. Tested against simulated switches, not yet across many real models.
* **Fixed:** the Track fix button did nothing, and the Findings page could show an error for a
  finding about a device that had not loaded yet.

## 3.4.0

* **Zones and segmentation policies.** Group devices into zones — by subnet, device type, tag, or
  pinning one in by hand — and write policies on top: explicit allow-lists, and a default for
  whether traffic may cross a zone's boundary at all. DENIS judges every flow it already sees
  against your policies and raises an alert when one is crossed without permission. A new **Zones**
  page shows a zone × zone matrix of what DENIS has actually verified — and says plainly when it
  can't verify a pair at all (traffic recording off for that site) rather than showing a false
  "all clear". A new policy starts in a quiet record-only mode, visible but never notified, until
  you switch it on; "Freeze this device's behaviour" turns a device's own observed traffic into a
  ready-to-review starting policy — nothing is saved until you confirm it.
* **Passive DNS, opt-in.** Settings → Network interfaces gains a Passive DNS section (off by
  default): DENIS remembers the name that resolved to each address your own devices contacted, with
  its own retention period and a "Delete all recorded names…" button. Names then show up wherever
  an address already did — the device panel, the Investigate section, alert evidence — always as
  "looked up as …", never "is …". Ask DENIS can now search by domain name, not just an IP. A new
  rule flags a device being pointed at an unexpected DNS resolver.
* **Deep Field: an optional animated look for the Topology map.** A new "Deep Field" console look
  (Settings, next to light/dark) gives the Topology map a quiet star-field background, a slow
  pulse on your gateway to show the page is live, and a brighter pulse on a fresh alert — off by
  default, and only changes the Topology page, not the rest of the console.

## 3.3.0

* **Multiple customers on one installation.** Separate databases, detectors and consoles per
  customer, with nothing reachable across them; MSP technician accounts that work across customers
  without a separate login in each one; export or import a customer as a standalone database.
* **Optionally disable a switch port, from DENIS.** For a switch DENIS already monitors over SNMP:
  one access port at a time, with a preview of what's behind it, a reason, your password, and
  one-click undo. DENIS never blocks anything on its own.
* **Track a fix until it's actually fixed.** Assign a finding to a person with a due date and a
  linked Jira/ServiceNow ticket; DENIS confirms the fix itself (a rescan, or no further contact
  while the device stays online) and watches for 30 days in case it comes back. Also closes the
  gap where two collectors watching the same network could leave a device listed twice after
  being joined.
* **Is it your connection, or is it DENIS?** A one-click, 10-20 second test of packet loss, jitter
  and latency — not a speed test — rated separately for browsing, a video call, and 1080p/4K
  streaming, with a note on whether DENIS's own network activity was the cause. A button next to
  "Scan now"; every result is saved on the Health page.
* **More threat intelligence, and certificate/TLS findings.** ThreatFox, URLhaus, Spamhaus
  ASN-DROP and the Tor exit list join the existing Feodo Tracker and Spamhaus DROP, each opt-in
  and named on a hit. An opt-in probe reads TLS certificates and protocol/cipher strength on your
  own devices' already-open ports, flagging an expired, soon-to-expire, self-signed or weak-TLS
  certificate.
* **Ask DENIS can now draft, not just answer.** A follow-up like "add an exception for that" or
  "this rule is too sensitive" drafts the exact change — a new rule, an exception, or a setting
  change — for an administrator to review and apply with one click. It never changes anything by
  itself.

## 3.2.0

* **"Top exposures today."** A short, ranked list of the devices that most need attention right
  now — a known-exploited vulnerability on a critical machine, an open Incident on something with
  no owner, a critical scanner finding — each with the reasons it's there, shown on the Dashboard
  and on the device's own panel. No black-box score.
* **See what talks to what inside your network** (optional, off by default). DENIS can now record
  traffic between devices on the same network, not just traffic to the internet, so you can ask
  "what talks to this server?" and get an answer with evidence. Turn it on under Settings →
  Network interfaces.
* **Investigate an alert without leaving it.** Alerts now have a collapsible "Investigate" section
  showing what else the device did around that time, which other devices contacted the same
  address, and the Incident it belongs to, if any.

## 3.1.0

* **Everything about a device, in one place.** The device panel now shows what your directory
  (Entra ID, Intune, Active Directory, Jamf, cloud accounts) and vulnerability scanner say about a
  device, alongside its open findings, related Incidents, and which collectors see it. You can
  also merge two collectors that watch the same network segment, directly from the console.
* **A refreshed Topology view.** Devices are grouped by type, and you can see which devices talk to
  each other over industrial protocols, with zoom and pan around the map.
* Findings now remember when they first appeared and when they were resolved, instead of only
  showing the current state.

## 3.0.0

* **Automatic Incidents.** Related alerts (the full chain of a compromised device's behaviour) are
  now grouped into one Incident with a priority verdict ("Act now" / "Investigate today" / …)
  instead of a flood of separate alerts you had to correlate yourself. An Incident can optionally
  get an AI-generated plain-language assessment of its likely consequences, and can be delivered
  as one grouped message to a notification channel or one event to a SIEM.
* **Auto-updating threat intelligence.** Known-bad IP/domain blocklists (abuse.ch, Spamhaus) now
  refresh automatically on a schedule you choose, merged with the existing CISA/NVD
  known-exploited-vulnerability and end-of-support feeds — all matched locally.
* **A much more capable "Ask DENIS" assistant** (optional, bring your own API key): search your
  alerts in plain language, check whether anything has ever talked to a specific address, jump
  straight to any screen or Settings page, or ask how to configure something — answered from
  DENIS's own real documentation. It will also tell you plainly what it can and can't do.
* **A redesigned Dashboard**: the standalone Trends page is gone — all of its charts and the "Top
  talkers" leaderboard now live directly on the Dashboard, alongside the optional AI summary.
* **Clearer Topology and alerts**: icon-based, risk-coloured device chips with click-to-select on
  the network map; the separate "Explain"/"Assess"/"Recommend" AI buttons on an alert are now one
  "Assess & Explain with AI" button.
* **More reliable Incidents.** Fixed a case where an alert could be grouped into the wrong open
  Incident; and deleting a device, a site, or your whole inventory now also cleans up the
  Incidents that referenced it, instead of leaving orphaned entries behind.
* Smaller fixes: the "Close" button on alert and incident dialogs is clearer about what it does
  and sits with the other action buttons instead of on its own row, clearer Devices CSV export
  naming, better Dashboard spacing, reordered Settings navigation, and more.

## 2.x series

Across the 2.x releases, DENIS grew from a single-site asset-discovery tool into its current
scope: OT/industrial protocol decoding (Modbus, S7comm, EtherNet/IP-CIP, DNP3, BACnet, OPC UA,
IEC 60870-5-104), SNMP switch topology, CMDB/cloud import (Entra ID, Intune, Active Directory,
Jamf Pro, Azure/AWS/GCP), vulnerability-scanner import (Nessus/Tenable.io), compliance mapping
(CIS Controls v8, NIST CSF 2.0, IEC 62443-3-3, NIST SP 800-82, ISO 27001 Annex A, NIS2, DORA,
PCI DSS v4.0, HIPAA, SOC 2, CMMC 2.0), the optional bring-your-own-key AI assistant, SIEM/log
export (CEF/LEEF/JSON, Elasticsearch/OpenSearch, OpenObserve), multi-site agents for MSPs, SSO
(OIDC), passkeys and authenticator apps, white-labelling, and one-click signed self-updates.

## 1.x series

Introduced multi-site/MSP capability (an Overview across sites, backups and live data reaching an
MSP master), commercial licensing, per-site access control, and the first round of OT protocol
support alongside the growing compliance and reporting features.

## 0.x series

The original release line: passive and active discovery, the explainable device-type/OS guesser,
the first detection rules (new device, rogue DHCP, ARP hijack, anomaly scoring), the asset
register, and the first OT protocol decoders.
