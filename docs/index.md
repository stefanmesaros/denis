# DENIS documentation

**DENIS** (*Device Enumeration & Network Inventory Security*) finds every device on your network, keeps an
inventory you can edit and export, learns what is normal for each device, and tells you when something is not.
It works on office and home networks (IT) and on industrial networks (OT).

**Finding things:** the search box at the top of every documentation page searches all pages, including the
setup pages for each port-control connector (listed in the menu under *Zones and policies*). Type one or more words
and press Enter; every word must appear in the same section. Capitals and accents do not matter, and a word also
matches longer words that contain it ("switch" finds "switches"). Each result shows the page, the section and the
matched words, and links straight to that section. Press `/` anywhere on a documentation page to jump to the
search box (it also works without JavaScript as an ordinary form: `/docs/search?q=your+words`).

| I want to… | Read |
|---|---|
| Install it and see my network in 10 minutes | [Quick start](quickstart.md) |
| Find my way around the console, tab by tab | [Console tour](tour.md) |
| Understand what the numbers and alerts mean | [Concepts](concepts.md) |
| Keep an asset register (owners, serial numbers, warranties, icons) | [Asset management](asset-management.md) |
| See which names each device looked up (passive DNS) | [Passive DNS](passive-dns.md) |
| See what to fix first (exposed services, retired devices online, missing owners…) | [Detection rules › Findings](detection-rules.md#findings-standing-problems-with-a-fix) |
| Know exactly which detections exist and how to tune them | [Detection rules](detection-rules.md) |
| Work one grouped incident instead of a dozen separate alerts, with a priority to tell you what to do first | [Incidents](incidents.md) |
| Describe how your network is meant to be divided, and be told when traffic crosses a line it should not | [Zones and policies](segmentation.md) |
| Block or quarantine a device, block a flow or switch a port off through a firewall, controller, cloud or switch connector; the experimental automation levels | [Enforcement](enforcement.md) |
| See which devices your management, directory, scanning and endpoint-protection tools do not reach, and whether the numbers are improving | [Control coverage and posture history](coverage.md) |
| Use it on an industrial (OT/ICS) network | [OT guide](ot-guide.md) |
| Run it for a client: users, agents, TLS, backups | [Deployment & administration](deployment.md) |
| Run two nodes on PostgreSQL with automatic failover | [High availability](high-availability.md) |
| Run it for several customers on one installation, with MSP technician accounts | [Multi-tenancy](multi-tenancy.md) |
| Manage customers' own DENIS installations remotely from an MSP console (experimental) | [MSP management](msp-management.md) |
| Send alerts to Slack, Teams, e-mail, PagerDuty, Pushover, ntfy, Jira, ServiceNow or a webhook; maintenance mode | [Alerting](alerting.md) |
| Let DENIS sort and explain alerts and ask you one question at a time (experimental); shadow mode, phone approval, AI options | [Autopilot](autopilot.md) |
| Send events, audit log and inventory to OpenObserve, events/findings/audit to a SIEM (syslog: CEF/LEEF/JSON), or ECS documents to Elasticsearch/OpenSearch | [Export](export.md) |
| See which switch port each device is plugged into (SNMP) | [Switches](switches.md) |
| Feed DENIS a mirror over RSPAN, ERSPAN, VXLAN or another tunnel | [Tunnel mirroring](tunnel-mirroring.md) |
| See what DENIS cannot see, and where to put the sensor | [What DENIS cannot see](visibility.md) |
| Understand why an IDS, IPS or endpoint product flags DENIS as a port scan, and what to do | [Security tools that may flag DENIS](security-tools.md) |
| Run it in Docker | [Docker](docker.md) |
| Back up and restore, load demo data, monitor DENIS itself, size an installation | [Operations](operations.md) |
| Put the customer's logo, colours and day/night mode on the portal | [Branding](branding.md) |
| Keep DENIS up to date (changelog, install now or later, automatic backup, remote agents, if GitHub is unreachable) | [Updates](updates.md) |
| Update to 4.3 (what changes for administrators, the abuse.ch key) and see what 4.3.0 does not do | [Upgrading to 4.3](updates.md#upgrading-to-43), [Known limits in 4.3.0](updates.md#known-limits-in-430) |
| See what was tested on real equipment and what only on a simulator | [Enforcement validation](nac/validation.md) |
| Assess or harden its security | [Security](security.md) |
| Get the software bill of materials, or see how DENIS is being prepared for the EU Cyber Resilience Act (not certified) | [SBOM](https://github.com/stefanmesaros/denis/blob/main/docs/compliance/SBOM.md), [CRA readiness](https://github.com/stefanmesaros/denis/blob/main/docs/compliance/CRA.md) |
| Help test DENIS and report what I find | [Testing DENIS](community-testing.md) |
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

* Not an intrusion *prevention* system: it does not sit inline, and by default it observes and alerts and does not
  block anything on its own. When an administrator switches enforcement on, DENIS can block or quarantine a device,
  block a flow, end its sessions or switch a port off through 20 kinds of connectors, each action confirmed by an
  administrator ([Enforcement](enforcement.md), [Disabling a port](switches.md#disabling-a-port)). Automatic
  enforcement by rules (level (b)) and letting Autopilot block (level (c)) are experimental and off by default.
* Not a vulnerability scanner: it does not test passwords or exploit anything. It flags exposed risky
  services (Telnet, RDP, …) and unusual behaviour.
* It sees only what reaches it. On a normal switched network a collector sees broadcast traffic and its own
  traffic. For whole-network traffic analysis put it on a **mirror/SPAN port** or on the gateway
  (see [Concepts › Visibility](concepts.md#visibility-what-can-be-seen-from-where)).
