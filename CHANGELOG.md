# Changelog

This is a customer-facing summary of what changed release to release — grouped by what it means
for you, not by internal implementation detail. Every release's full technical notes ship inside
the binary and the GitHub Release page for that version.

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
* Smaller fixes: clearer Devices CSV export naming, better Dashboard spacing, reordered Settings
  navigation, and more.

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
