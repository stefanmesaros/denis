# DENIS documentation

**DENIS** (*Device Enumeration & Network Inventory Security*) finds every device on your network, keeps an
inventory you can edit and export, learns what is normal for each device, and tells you when something is not.
It works on office and home networks (IT) and on industrial networks (OT).

| I want to… | Read |
|---|---|
| Install it and see my network in 10 minutes | [Quick start](quickstart.md) |
| Understand what the numbers and alerts mean | [Concepts](concepts.md) |
| Keep an asset register (owners, serial numbers, warranties, icons) | [Asset management](asset-management.md) |
| See what to fix first (exposed services, retired devices online, missing owners…) | [Detection rules › Findings](detection-rules.md#findings-standing-problems-with-a-fix) |
| Know exactly which detections exist and how to tune them | [Detection rules](detection-rules.md) |
| Use it on an industrial (OT/ICS) network | [OT guide](ot-guide.md) |
| Run it for a client: users, agents, TLS, backups | [Deployment & administration](deployment.md) |
| Send alerts to Slack, Teams, e-mail, PagerDuty, Pushover, ntfy or a webhook; maintenance mode | [Alerting](alerting.md) |
| Send events, audit log and inventory to OpenObserve, or events/findings/audit to a SIEM (syslog: CEF/LEEF/JSON) | [Export](export.md) |
| Put the customer's logo, colours and day/night mode on the portal | [Branding](branding.md) |
| Keep DENIS up to date (changelog, install now or later, automatic backup) | [Updates](updates.md) |
| Assess or harden its security | [Security](security.md) |
| Automate or integrate | [API reference](api.md) |
| Something does not work | [Troubleshooting](troubleshooting.md) |

## What DENIS does

1. **Discovers** devices passively (it listens: ARP, DHCP, mDNS, SSDP, LLDP/CDP, industrial protocols) and,
   optionally, actively (a polite ARP sweep, ping and a light port scan of ordinary devices).
2. **Fingerprints** each one: manufacturer, device type, operating system, open services, with an explanation
   of *why* it thinks so.
3. **Tracks** it: a name, owner, location, serial number, asset tag, warranty date, criticality and icon that
   *you* maintain, with a full change history.
4. **Learns** each device's normal behaviour and raises **scored alerts** (0–100) when it changes.
5. **Reports**: risk-ranked device list, alerts, trends, CSV exports and a printable report.

## What DENIS is not

* Not an intrusion *prevention* system: it observes and alerts, it does not block traffic.
* Not a vulnerability scanner: it does not test passwords or exploit anything. It flags exposed risky
  services (Telnet, RDP, …) and unusual behaviour.
* It sees only what reaches it. On a normal switched network a collector sees broadcast traffic and its own
  traffic. For whole-network traffic analysis put it on a **mirror/SPAN port** or on the gateway
  (see [Concepts › Visibility](concepts.md#visibility-what-can-be-seen-from-where)).
