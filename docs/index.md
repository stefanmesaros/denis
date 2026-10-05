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
| Work one grouped incident instead of a dozen separate alerts, with a priority to tell you what to do first | [Incidents](incidents.md) |
| Describe how your network is meant to be divided, and be told when traffic crosses a line it should not | [Zones and policies](segmentation.md) |
| See which devices your management, directory, scanning and endpoint-protection tools do not reach, and whether the numbers are improving | [Control coverage and posture history](coverage.md) |
| Use it on an industrial (OT/ICS) network | [OT guide](ot-guide.md) |
| Run it for a client: users, agents, TLS, backups | [Deployment & administration](deployment.md) |
| Run it for several customers on one installation, with MSP technician accounts | [Multi-tenancy](multi-tenancy.md) |
| Send alerts to Slack, Teams, e-mail, PagerDuty, Pushover, ntfy, Jira, ServiceNow or a webhook; maintenance mode | [Alerting](alerting.md) |
| Send events, audit log and inventory to OpenObserve, events/findings/audit to a SIEM (syslog: CEF/LEEF/JSON), or ECS documents to Elasticsearch/OpenSearch | [Export](export.md) |
| See which switch port each device is plugged into (SNMP) | [Switches](switches.md) |
| Run it in Docker | [Docker](docker.md) |
| Put the customer's logo, colours and day/night mode on the portal | [Branding](branding.md) |
| Keep DENIS up to date (changelog, install now or later, automatic backup) | [Updates](updates.md) |
| Assess or harden its security | [Security](security.md) |
| Know what the Community edition covers and how a commercial license works | [Licensing](licensing.md) |
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
5. **Reports**: risk-ranked device list, alerts, standing findings, compliance evidence, trends, CSV exports and
   saved or printable reports.

## What DENIS is not

* Not an intrusion *prevention* system: it observes and alerts, it does not block anything on its own; an
  administrator can optionally disable a switch port from it ([Disabling a port](switches.md#disabling-a-port)).
* Not a vulnerability scanner: it does not test passwords or exploit anything. It flags exposed risky
  services (Telnet, RDP, …) and unusual behaviour.
* It sees only what reaches it. On a normal switched network a collector sees broadcast traffic and its own
  traffic. For whole-network traffic analysis put it on a **mirror/SPAN port** or on the gateway
  (see [Concepts › Visibility](concepts.md#visibility-what-can-be-seen-from-where)).
