# DENIS

**D**evice **E**numeration & **N**etwork **I**nventory **S**ecurity: find every device on an IT **or industrial (OT)**
network, keep an asset register you can edit, learn what is normal for each device, and get told (in Slack, Teams,
e-mail, PagerDuty…) when something is not. One Rust binary, no external services, documentation built in.

![The DENIS console](docs/img/devices.png)

**Install on a Linux server** (downloads a signed release, sets up a service, picks a free port, prints the address and
the one-time admin password; [details](docs/deployment.md#installing-on-a-linux-server-a-permanent-service)):

```bash
curl -fLO https://github.com/stefanmesaros/denis/releases/latest/download/install.sh
less install.sh && sudo bash install.sh
```

**Or just try it** (Mac or Linux; download `denis-<your platform>` from the [Releases](https://github.com/stefanmesaros/denis/releases)
page, or `cargo build --release`):

```bash
./denis run          # prints a one-time admin password; open https://localhost:8080 (self-signed by default, replaceable)
./denis demo --db demo.db load && ./denis serve --db demo.db --insecure-no-auth   # or look around a fictional company: no capture, no login (this machine only)
```

**Documentation** (also inside the console, with screenshots): [Quick start](docs/quickstart.md) ·
[Console tour](docs/tour.md) · [Concepts](docs/concepts.md) · [Asset management](docs/asset-management.md) ·
[Detection rules](docs/detection-rules.md) · [Alerting](docs/alerting.md) · [OT guide](docs/ot-guide.md) ·
[Branding](docs/branding.md) · [Export & SIEM](docs/export.md) · [Deployment](docs/deployment.md) ·
[Operations](docs/operations.md) · [Security](docs/security.md) · [API](docs/api.md) · [Troubleshooting](docs/troubleshooting.md)

## What it does, most important first

1. **Finds everything on the network.** Passive listening (ARP, DHCP, mDNS, SSDP, LLDP/CDP, PROFINET, TCP/IP
   stack) plus polite active discovery (ARP sweep, ping, port scan). Nothing hides from it; industrial devices are
   never probed.
2. **Says what each device is, and why.** Manufacturer from the IEEE registry, device type and operating system from
   weighted evidence (DHCP option lists, mDNS, SSDP, ports, names…). Every guess lists the rules behind it, and your
   correction always wins.
3. **Detects what changed, with explainable scores.** New device, rogue DHCP server, ARP hijack and gateway takeover,
   new destination or port, unusual volume or hour, silent device, burst of newcomers, contact with known-bad
   addresses: each scored 0–100 with the factors behind the score and **what to do about it**.
4. **Understands industrial networks.** Passive decoding of Modbus, S7comm, EtherNet/IP-CIP, DNP3, BACnet, OPC UA
   and IEC 60870-5-104; a communications matrix; alerts for control commands (PLC stop, program download), traffic
   crossing the network boundary, Purdue-level skipping and writes from devices that should never write.
5. **A real asset register.** Owner, location, serial number, asset tag, warranty, criticality, tags, custom
   fields, 80+ icons, 90+ device types, change history, a review queue for new devices, CSV import/export.
6. **Alerts reach you.** Slack, Microsoft Teams, Discord, PagerDuty, Pushover, ntfy, e-mail and a signed webhook, each with its own
   threshold, a Test button, digests during storms, maintenance mode and per-device silencing.
7. **Tells you what to fix.** *Findings* (Telnet/RDP exposed, lost devices still online, no owner, expiring
   warranty…), each with **Verify fix** (a fresh scan) and **Accept risk** (a reason, an end date, an audit trail) and a *Compliance* view mapping your coverage to CIS Controls v8, NIST CSF 2.0, IEC 62443-3-3, NIST SP 800-82, ISO/IEC 27001 Annex A and NIS2, and *Reports* that are kept on the server (made by hand or on a schedule) to view, download or print.
8. **A console you can trust, in your language.** English, German, French, Spanish and Slovak. Roles, passkey sign-in (WebAuthn), Argon2id, lock-outs, API tokens, an audit log,
   optional built-in HTTPS, strict headers. Every detection is visible and tunable (*Rules* tab).
9. **Plays well with the rest of your stack.** SIEM export in CEF, LEEF or JSON over UDP/TCP/TLS — pick the
   format, transport and which streams (events, findings, audit) from *Settings → SIEM / Log export*, no
   restart — OpenObserve export, Prometheus `/metrics`, REST API, `denis backup`.
10. **Many sites, your brand.** Agents on remote sites report to one master (outbound connections only), with
    **per-user, per-site access** (read/write/none, e.g. for an MSP whose technicians see only their own
    customers); white-label the console with your logo, colour and default day/night theme.
11. **Built to explain itself.** Documentation and a guided demo ship inside the binary; the code is commented for
    maintainers and fuzz-tested where it parses hostile input.

## Status: what is verified, what is not

Verified on macOS (Apple Silicon, Wi-Fi, a /24 with ~45 devices): 480+ unit tests and an end-to-end replay of a
simulated industrial network through the whole pipeline; fuzz tests of all parsers; `cargo audit` clean; a
master and agent talking over HTTP; the UI exercised in a browser (sign-in, forced password change, editing,
users, OT, topology, trends, report).

**Not yet verified**:

* **Agent ↔ master across a real network** (loopback only so far). **Built-in TLS** (`--tls-cert/--tls-key`,
  agent `--master-ca`) was verified on loopback with a private CA (TLS 1.3 + HTTP/2, old TLS refused, agent
  reporting over HTTPS) but not with a public certificate authority or a reverse proxy in front.
* ARP conflict and industrial detections on **real** wire traffic (tested with hand-built frames and replay;
  no forged or industrial traffic was generated on a live network).
* `unusual_hours` and `device_silent` on real elapsed time (tested with injected clocks).
* The **OpenObserve export** and **SIEM export** (syslog: CEF/LEEF/JSON) are tested against simulated
  endpoints, not a real OpenObserve or SIEM.
* The **German, French, Spanish and Slovak translations** are complete (a test fails if any string or placeholder is
  missing) but have not been reviewed by native-speaking security professionals: expect wording to improve. Alert
  texts already recorded stay in English.
* No multi-factor auth / SSO, no Postgres backend, no IPv6, no Windows.
* An independent **penetration test** and a disclosure policy: required before selling it.

## Development

```
src/parse.rs        Ethernet frame -> observations (pure, fuzzed)
src/ot.rs           industrial protocol + LLDP/CDP/PROFINET decoders (pure, tested from the specs)
src/flow.rs         per-window aggregation of flows and conversations (capture thread)
src/capture.rs      libpcap thread, kernel filter, throttling
src/active.rs       ARP sweep, ICMP, TCP scan (polite; never used on industrial devices)
src/inventory.rs    observations -> assets, ARP-conflict signals, deltas for agents
src/fingerprint.rs  vendor lookup and the explainable device-type/OS guesser
src/detect.rs       baselines, all rules, scoring, learning periods, communications matrix
src/risk.rs         per-device risk score
src/rules.rs        the rules as the console shows and tunes them
src/demo.rs         built-in demo data (a fictional company)
src/compliance.rs   coverage and standards mapping (CIS / NIST CSF / IEC 62443 / NIST 800-82 / ISO 27001 / NIS2)
src/reports.rs      saved reports and their schedule
src/snmp.rs         SNMP v2c client (BER, GET/GETBULK walks)
src/topology.rs     switches over SNMP: ports, LLDP neighbours, MAC-to-port; the physical map
src/banners.rs      service banners (SSH/FTP/SMTP/HTTP) and the product and version in them
src/vulndata.rs     end-of-support dates and known-exploited ranges (data/vulndata.json)
src/docs.rs         the documentation served inside the console
ui/i18n.js          language handling; texts in tools/i18n/*.tsv -> ui/i18n/*.json (python3 tools/i18n/build.py)
src/metrics.rs      Prometheus exposition
src/threat.rs       blocklist for the threat_list_match rule
src/findings.rs     standing weaknesses and housekeeping problems, with fixes
src/tracking.rs     validated asset edits, CSV import, warranty arithmetic, icons
src/passkey.rs      WebAuthn/passkey verification (ES256, strict)
src/auth.rs         users, sessions, per-agent tokens (Argon2id, hashed tokens, lock-out)
src/web/            API + embedded UI, auth middleware, security headers (mod.rs routes/reads, common.rs shared with web_*)
src/web_admin.rs    state-changing handlers (session, users, tokens, asset edits, import)
src/web_siem.rs     SIEM / log export settings (GET/PUT, a test-send endpoint)
src/ingest.rs       master side of the agent protocol (per-agent tokens, idempotent batches)
src/agent.rs        agent reporter
src/tls.rs          optional built-in HTTPS (rustls)
src/engine.rs       collector + detector + web wiring (`run`, `run_agent`)
src/store/          `Store` trait (split into focused sub-traits) + SQLite (schema v14, transactional migrations)
src/branding.rs     white-label settings and safe logo handling
src/channels.rs     notification channels (Slack/Teams/Discord/PagerDuty/Pushover/ntfy/e-mail/webhook)
src/syslog.rs       SIEM export: syslog in CEF, LEEF or JSON, over UDP/TCP/TLS
src/sink.rs         OpenObserve exporter (cursor-based, at-least-once)
src/report.rs       CSV / printable HTML (escaping, formula-injection guard)
ui/                 the web UI (plain JS, no build step, strict CSP)
docs/               user documentation
tests/              end-to-end replay tests
```

```bash
cargo test && cargo clippy --all-targets && cargo audit
```

Code is commented for maintainers: module headers state each module's purpose and invariants (what is trusted,
what is bounded), and non-obvious decisions say *why*.

## License, contributing, security

DENIS is source-available under the **DENIS Community License**: free to read, build and run for personal,
non-commercial use on up to 100 devices. Any organisational use, or more than 100 devices, needs a commercial
license — see [LICENSE](LICENSE) and [LICENSE-COMMERCIAL.md](LICENSE-COMMERCIAL.md). The full text is not an
OSI-approved open source license; it is source-available so you can read and audit it. List of
[third-party software](THIRD-PARTY-LICENSES.md) DENIS itself depends on (each under its own permissive license).

* Contributions are welcome: [CONTRIBUTING.md](CONTRIBUTING.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
* Found a vulnerability? Please report it privately: [SECURITY.md](SECURITY.md).
* What is missing and what is planned: [ROADMAP.md](ROADMAP.md); what changed: [CHANGELOG.md](CHANGELOG.md).

