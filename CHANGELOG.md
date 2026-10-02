# Changelog

This is a customer-facing summary of what changed release to release — grouped by what it means
for you, not by internal implementation detail. Every release's full technical notes ship inside
the binary and the GitHub Release page for that version.

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
