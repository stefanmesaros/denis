# Roadmap and known gaps

DENIS aims to be an honest, self-hostable alternative to the asset-visibility products that cost six figures a
year. This is what is still missing, in order. Pull requests welcome.

## 4.1.0: delivered; what is in, what is experimental, what is not built

4.1.0 was released as stable after three release candidates and a full code review. What is in
the program, checked against the code, not against plans:

* **Connections from the internet.** The `inbound_from_public` rule: a public address that completes a TCP connection to
  one of your devices (a port forward to a solar inverter, a camera, a NAS) raises one alert with the source, its country
  and network when known, the port and whether other devices were reached. A port can be marked as expected per device.
  Needs `--flows`; IPv6 sources count with `--ipv6`.
* **Quieter alert stream, daily digest.** Routine events are kept quiet with a stored reason and listed in a daily
  digest; the list of what is never kept quiet is in [docs/alerting.md](docs/alerting.md).
* **Autopilot (experimental, off by default).** Triage with questions answered on a phone (Telegram, ntfy, web push),
  starting in shadow mode. It blocks nothing unless an administrator also switches on level (c), *Autopilot may block*
  (below). Not yet verified: a shadow week on a real network, real phone round trips, delivery to the real services, an
  external review ([docs/autopilot.md](docs/autopilot.md)).
* **Network identity.** VLAN tags and the ERSPAN header are read and shown, an address claimed from two VLANs is
  annotated, the same MAC on several VLANs is one flagged device. Tunnelled mirrors (ERSPAN, GRE, VXLAN, Geneve) can be
  read (opt-in), verified on hand-built frames and public captures only.
* **Industrial protocols.** S7comm-plus, IEC 61850 MMS and ICCP, GOOSE, PROFINET, OPC UA and CODESYS (identified only),
  decoded over IPv4 and, with `--ipv6`, IPv6; messages split across TCP segments are followed. Still not done in 4.1.0: IP
  fragment reassembly (added in 4.1.2), HSR frames, R-GOOSE/R-SV, TCP reassembly in general (see "Industrial protocol
  expansion" in [docs/ot-guide.md](docs/ot-guide.md)).
* **SNMPv3** for reading switches and for port control, Cisco switches read per VLAN, and the refusal of trunk,
  EtherChannel, management and CDP-neighbour ports. Tried on one real switch (D-Link); SNMPv3 and Cisco only
  against stand-ins.
* **Enforcement actions (experimental, off by default).** All 20 connector kinds are on one action path (plan, apply,
  list, release, extend, retry, orphans, per-action permissions, a ledger, timed actions that end by themselves and a
  read-back of the device state) with a kill switch, an hourly limit and a preview. The console has the plan dialog
  (the *Respond…* menu of a device, an incident or a flow), the list of active responses and block suggestions.
  MikroTik and Cisco ASA, FTD through FDM and through FMC are new connectors. Every connector not tried on real
  equipment is labelled *Experimental* and needs the lab switch; the actions new in 4.1 need a second lab switch. All of
  it is simulator-tested only, apart from switching a port off over SNMP on one switch.
* **Automation levels.** (a) nothing, the default; (b) automatic enforcement by policies an administrator marks
  (experimental, off by default); (c) *Autopilot may block*, a separate and even more experimental switch on top of (b)
  with its own gates and limits ([docs/enforcement.md](docs/enforcement.md#automation)).
* **MSP remote management (experimental).** An MSP console opens a customer's own master at the level the customer
  chooses, through a paired channel, with a banner, an activity list, co-approval and a one-click disconnect; every
  operator needs a second factor ([docs/msp-management.md](docs/msp-management.md)).
* **Agents.** One-command install (`install.sh --agent`, the Add agent dialog, Docker); updates from the console in three
  ways (by hand, automatic, through the master); a second download host, usedenis.com, used only when GitHub cannot be
  reached, with the same signature checks and a setting to switch it off.
* **Rules and console.** IT rules and OT rules (renamed from network watches and OT command watches) with a new dialog
  for writing them; a search box in the built-in docs, an Enforcement page, and the refreshed console look (palette,
  corner radius, bundled fonts).

**Not built in 4.1.0, or known limits** (do not read any of it as promised for a date):

* Verification on real equipment of any enforcement connector beyond switching a port off over SNMP on one switch
  (see 4.1.4 below).
* MSP management: the one-click "Allow management" for a customer that already relays with `--report-to`, fleet
  templates, queued changes for offline customers, several MSPs per customer.
* High-availability fencing, per-tenant encryption keys and tenants on PostgreSQL are planned (see "After 4.1" below; start-up
  refuses `--database-url` while tenants exist). IP fragments are reassembled for OT decoding since 4.1.2.
* Smaller findings of the internal code reviews, fixed in the next releases.

**Next:** 4.2 (below: connector safety and the exact scope of every action, tests on real equipment, resilient capture, monitored networks, one identity per device, notifications), then 4.3 *Correctness under failure*
(below).

## 4.1.1: delivered (tag `v4.1.1`)

* **Alpine, OpenRC and musl** (built, in this release). Reported by users: `install.sh` needed systemd and the Linux
  programs needed Debian's `libpcap.so.0.8`. Now: static musl programs for x86-64 and ARM64 with libpcap built in
  (`tools/build-musl.sh`, job `build-musl`), OpenRC and `--no-service` in `install.sh`, `install.sh` in the signed
  `SHA256SUMS`. Verified locally on ARM64 in Alpine containers; the x86-64 static program is first built and started
  by the release workflow, and OpenRC was exercised in a container, not on a booted Alpine machine.
* **Deferred review findings** (built: the quick and safe ones, listed in CHANGELOG.md 4.1.1; the rest is under
  4.1.2 below).
* **A local CI script** (built: `tools/ci-local.sh`) that runs the CI sequence in a Linux container as an unprivileged
  user (RELEASING.md, "What we learned from 4.1.0"); the Alpine check is `tools/build-musl.sh --smoke`.

## 4.1.2: delivered (tag `v4.1.2`)

4.1.1 took the quick and safe items of the 4.1.0 code review (A F8, F11, F12; E-8 UI, E-9; D-8, D-10 part, D-12;
FortiGate #6, #9, #10; ASA F10 to F12; FTD F15; C-8; T6-11). 4.1.2 took the items below; what stays open is tracked for the next releases.

* **Delivered in 4.1.2 (CHANGELOG.md 4.1.2):**
  * C-7: Proxmox and Hyper-V take what a guest reports as a hint only; the owner is decided by the configuration and
    DENIS's own IP-MAC pairing, and several claims on an address DENIS never saw are refused with a reason.
  * C-6: checked byte for byte against an independent Python reference (RFC 5176, RFC 2866, RFC 3579): the order was
    wrong and is fixed (Message-Authenticator first, over a zero authenticator; then the Request Authenticator).
  * D-6: the SNMPv3 engine ID is pinned per switch at the first authenticated poll; port control goes only to it, and
    an administrator confirms a new one.
  * PAN-OS #4: DENIS's own candidate edits are undone after a refused step or object delete, or a lost answer before
    any commit (known limit: not after a commit whose outcome is unknown).
  * FortiGate/PAN-OS #11 (one 600 s deadline per PAN-OS write path, under the 900 s claim age) and #14 (one write path
    at a time per firewall).
  * A F2: a "would you have blocked it?" judgement per record under the shadow report; only a "yes" counts as agreement.
  * OT-4 (audit): IP fragments are reassembled before OT decoding (bounded per flow and in total, with a timeout), so
    an industrial message split across IP fragments is decoded instead of skipped.
  * Fourteen of the 25 review items were left as larger design changes and are tracked for the next releases.
  * Dead code removed: the old enforcement run sequences of 14 vendor modules, `legacy_sync`, the `Legacy` adapter.
  * Split into modules without a change of behaviour: `src/ingest.rs`, `src/inventory.rs`, `src/detect/tests.rs`.
  * The 4.1.2 code review R-1, R-2, R-3, R-5, R-7, R-9, R-13, R-14 fixed, R-4 in part,
    R-12 already safe (test added).

## 4.1.3: delivered (tag `v4.1.3`)

Details in CHANGELOG.md 4.1.3. The hardware tests and the other plans first listed here moved to 4.1.4.

* **From the 4.1.2 code review:**
  * R-6: TCP/UDP checksum (IPv4 and IPv6 pseudo-header) checked before OT decoding: a reassembled datagram with a wrong
    one is still decoded and counted (and named in the Health warning), the same as an unfragmented one: a wrong sum never hides a command (checksum offload and GRO on the capturing host leave unfinished sums, and some embedded stacks do not check them).
  * R-8: a RADIUS reply's Message-Authenticator is verified when present.
  * R-10: the Autopilot agreement is shown per readable site to a site-limited person, and only a "yes" from a person
    who reads every site counts for the gate.
  * R-11: the C-12 checks run at use too (Hyper-V without TLS, Proxmox `http://`), with a Health warning.
  * R-15: a fragmented industrial command seen on both sides of a router is decoded once.
  * R-4 (rest): a byte cap per source in the fragment reassembly.
* **From the 4.1.3 code review:** R3-1 a reassembled UDP datagram is read up to its UDP
  length; R3-2 a reassembled datagram with a wrong checksum is decoded, counted and warned about
  instead of dropped; R3-3 an IPv6 UDP zero checksum always fails; R3-4 an exact repeat under the same MAC is decoded
  again; R3-6 optional `require_message_authenticator` for RADIUS replies, constant-time comparisons; R3-7 an
  Autopilot "yes" counts only from a current, enabled, unlimited administrator; R3-8 Health names every Hyper-V or
  Proxmox instance refused at use with its reason, Proxmox https guard at the request; R3-9; R3-10 to R3-16 for the
  lab selftest and the source scans.
* **The remaining large files split into modules** without a change of behaviour: `src/parse.rs`,
  `src/nac_registry.rs`, `src/engine.rs`, `src/web_admin.rs`, `src/web/tests.rs` and the store tests.

## 4.1.4: delivered (tag `v4.1.4`)

Details in CHANGELOG.md 4.1.4.

* **Network** replaces Topology: Map, Equipment (switches and connectors, with Read now and a write test), Response (what is
  blocked now, where it came from, devices DENIS never acts on) and Setup (a guided setup). Settings: Enforcement is now
  Response policy, Network is Capture, Setup guide is Getting started.
* **Gateway and hierarchy detection:** DENIS suggests which device is the gateway and which switch holds it, from DHCP,
  ARP, the internet traffic and its own route, says how sure it is and why, and asks the administrator to confirm.
* **Respond menu:** grouped by what you want, one reason per cause with a link to the setting that fixes it, your own
  reason before you apply. **Hands off:** a list of devices DENIS never acts on.
* **Experimental:** for a switch that gives no forwarding table, the administrator says which device is on which port.
* **Hardware results:** Cisco Catalyst 2960-X (SNMPv2c and SNMPv3): reading, switching a port off, the quarantine VLAN,
  release and extension tried on the switch, and the Cisco quarantine move is validated. D-Link DGS-1100-08V2: a model
  limit (no forwarding table or LLDP over SNMP). FortiGate 40F: first lab run passed; not yet called validated.
* Fixes from the internal code review of 4.1.3, and the TLS library update for new security advisories.

## Next: what customers asked for (planned, in this order)

From what people running network detection and access control say about their own deployments. These come before new connectors.

* **Seeing what DENIS cannot see.** Removing duplicate copies of the same packet when several mirror ports feed one sensor, and a coverage view that says which networks and links are seen, which are not, and what is missing (no mirror feed, drops, a link seen from one side only). Planned for 4.3.
* **Unknown devices without an agent.** Onboarding puts the unknown-device question first: what is on the network that nothing manages, with the evidence for each device and an owner to assign. Planned for 4.3.
* **One history per device.** A single timeline of a device: addresses, ports, alerts, connections and responses, to answer an incident question without opening five pages. Planned after 4.3.
* **Alerts people can trust.** Feedback on false alarms (this was normal, do not tell me again) and measurement of how many alerts are acted on, kept on the installation. Planned after 4.3.
* **More real-equipment checks of enforcement.** Kill switch, hourly limit, wrong credential, a connector that loses its connection, and release after a restart, on each verified device.
* **Simple, affordable use for small teams.** Quick first result, safe defaults, and licensing that does not price small organisations out; to be settled before the first commercial sale.

## 4.2: planned (4.1.5 was folded into it)

What was left out of 4.1.4 on purpose or not reached, and what the first lab runs on real equipment showed, in the order it is planned.

* **Safety and exactness of actions** (found in the first lab runs on real firewalls and switches):
  * The actions offered for a device follow where it really is: a switch-port action only when the device's own access port is
    known (never an uplink, trunk, infrastructure or mirror port), a firewall action first for the firewall that routes the
    device's network, others marked "path not verified".
  * An action says plainly what it covers: an address action names the address (and says that other addresses or interfaces of
    the device are not covered, IPv4 and IPv6 separately), a flow action names protocol and port or says "any".
  * A device that moved between networks is judged on its newest address; an older address inside a protected network
    becomes a warning you confirm, never a silent refusal and never a silent pass; gateways, infrastructure and DENIS itself
    stay protected.
  * Extending an action offers "add time" or "end N minutes from now" and shows the resulting end time; every change of a
    connector's safety options is written to the audit log; every connector option is enforced by the server.
  * Address-conflict alerts ignore routed traffic that only passes a mirror port.
* **UniFi with an API key:** the UniFi connector also works with a Network API key (no user name and password), reads clients
  through the official Network API and blocks through an ACL rule or firewall policy; the sign-in with a local account stays
  for the immediate disconnect of a client. Palo Alto keeps the XML API (it already uses an API key); the REST API of PAN-OS
  stays an option for objects and rules only, because it cannot commit or clear sessions.
* **Tests on real equipment** (each one is written down in `NAC_HARDWARE_VALIDATION.md` and decides the label of a connector):
  * FortiGate 40F: the first lab run passed (block, release, expiry of a host). Still to do: a wrong credential, the preview
    that no longer matches, the flow block, the kill switch, the hourly limit, the lab switch, twenty block and release
    cycles in a row, and one block held for a day.
  * Palo Alto PA-220, MikroTik and UniFi, then the other connectors that still say "simulator only".
  * The quarantine through a port VLAN setting on switches other than Cisco, and the port bounce, are not tried on a real
    switch yet.
* **Lab self-test:** `--cycles N` and `--soak-hours H` for the long runs above, a run on a PostgreSQL database, a sweep of
  anything an earlier run left behind after a crash, one shared check with the console's own permission check, and secrets
  hidden in the report by pattern as well as by value.
* **Network page, what 4.1.4 did not do yet:**
  * Double NAT is only seen as a disagreement between the route and what clients are told (no hop count yet); the default
    route of a layer-3 switch is not read; networks are shown as /24 groups.
  * An optional SNMP read of the firewall or router itself (interfaces, routes, forwarding), and topology read from the
    connectors (FortiGate interfaces and routes, OPNsense gateways, which UniFi or Meraki access point a client uses).
  * Manual port placement covers switching a port off only; a device behind a switch that gives no forwarding table gets a
    port picker on its panel instead of a link to the map; the Response page gets a setting for how long its history is
    kept; an optional search over the settings.
* **Capture that survives a missing interface:** DENIS starts even when a configured mirror port has no link, reports the
  interface as degraded (link down, missing, capture error, no traffic), recovers by itself when the switch or adapter
  returns, tells you once when monitoring is degraded and once when it is restored, and lets you add, disable, remove and
  re-check capture interfaces from Settings → Capture.
* **Monitored networks in the console:** the networks seen on mirror ports are listed, added and removed in Settings → Capture
  (saved, applied without a restart, never learned from traffic, never switching on active scanning); optionally mapped to the
  capture interface that sees them; Health says when an interface has no network coverage.
* **One device, several interfaces:** a firewall seen on its WAN and LAN addresses, as an SNMP device and as an enforcement
  connector is one device in the inventory; a Respond menu that stays open during background updates; the actions offered for
  a device follow where it really is (which firewall is on its path, which port it is really on).
* **A fuller network map:** switches, firewalls, routers and access points with the links between them as a best guess from what the devices report, each link marked as confirmed, guessed or set by hand; an administrator can correct a link by dragging a connection from one device to another, and the Equipment list can be ordered by this wiring.
* **Response from rules:** each detection rule gets an action setting: only notify, prepare the response for an administrator to approve with one click, or carry it out automatically (automatic stays experimental, off by default and behind the same safety checks and limits as every other action).
* **Palo Alto without waiting for a commit:** blocking and releasing a device through a dynamic address group and a tag registered over the API (seconds instead of a commit that can take minutes); the commit-based method stays as the fallback.
* **Supply chain and documentation:** a software bill of materials (CycloneDX and SPDX) with every release, a daily check of dependencies for known vulnerabilities, an updated architecture guide, a description at the top of every large module, a complete reference of the API endpoints added since 4.0, and a Cyber Resilience Act readiness document.
* **Equipment page:** one tidy, aligned list without sideways scrolling, one entry per physical device (a firewall that is both a connector and an SNMP device is shown once), real device names, details on demand, rows in a saved order you choose, and optionally ordered by how the devices are wired.
* **Notifications:** messages name the device (name, address, hostname), and for an outside address its reverse DNS name and
  country; a notification centre in the console for things you should know (released, extended, done automatically, failed,
  degraded).
* **Connectors:** FortiGate documentation for a customer to set it up alone (API permissions, trusted hosts, verification,
  troubleshooting) and its hardware results; MikroTik hardware results and follow-ups; every option of a connector is
  enforced by the server, not only shown in the console.
* **Smaller findings of the internal code reviews:** the stricter wording rule for the reason you type, texts that come from
  the server being shown as they are, and the Autopilot figures read in one query.
* **Smaller fixes and answers:** a missing value shown as the word "null" in the block dialog, and a short guide on when a network behind a router needs its own capture cable and when a mirror alone is enough.
* **Fresh screenshots** for the docs and the website, and the rest of the long-text reduction (the "?" tooltips outside
  `index.html`).

## Review findings still open

Smaller findings from the internal code reviews are tracked privately and fixed in the next releases.

## After 4.1: roadmap (from the independent architecture audit)

Added 2026-10-10. Design, reasons, data models, tests and open decisions are kept in the project's design notes
(section numbers in brackets). Effort in implementer-days, ±40 %; hardware lab time not included. Order inside a
release is the order listed. No marketing claim of "high availability", "validated with vendor X" or "MSP-ready"
before the evidence listed in §3.3 exists.

**Planned for 4.1** (identity pulled in where feasible). Status at the 4.1.0 release: the VLAN part of
network identity is built (see "4.1.0: delivered" above); the residual audit fixes were re-checked by the full code
review (fixed, or deferred to the items below); the stretch items remain open.

- Residual audit fixes, about 6 d: per-tenant ingest lock, `BAD_TIME` per tenant, one failing tenant no longer stops
  start-up, agent batch sequence saved with its events, isolation suite reads multi-line routes, NAC device writes and
  the switch poll ask the HA lease, standby waits out the lease before acting, `may_act` on enabling enforcement [§1].
- Network identity, minimal increment, about 12 d, no migration, unchanged default behaviour: VLAN read from tags and
  the ERSPAN header and carried on address claims; cross-VLAN conflicts annotated (setting, default alert); routed
  mirror no longer makes the router claim host addresses; per-device VLAN and source evidence; same MAC on several
  VLANs flagged, never merged; capture source id with an overlap warning; switches and NAC connectors bound to a
  site, site-aware topology and NAC targeting; stretch: VRRP/HSRP virtual MACs [§4 Part B].

**4.3 Correctness under failure** (45-60 d)

- An OpenAPI specification of the API and narrower API tokens (limited scopes and expiry).
- Removing code repeated across the connectors and splitting the largest source files, with no change of behaviour.

- A PostgreSQL-enabled release binary (`--features postgres`) next to the standard one, so high availability does not need a self-built program.

- Leader-epoch fencing of every PostgreSQL write, cursor and NAC intent row; DB-side fencing of the old leader [§5.3]
  (audit F2-1).
- Per-tenant data keys under the master key, tenant id in the associated data, tenant stamp, rotation, export with
  passphrase [§5.5] (audit F6-5 / T6-7).
- Enforcement orchestrator: snapshot and undo before the write, pending row and audit in one transaction; PAN-OS
  partial commit, SonicWall without override, Juniper commit confirmed, NSX revisions [§5.4]. (Already in 4.1:
  server-side plans stored in the database and spent once, device I/O on a thread of its own that a disconnecting
  client cannot cancel, and one central target guard, see `src/nac_orchestrator.rs`.)
- Real-equipment validation with a compatibility matrix (data file, API, UI, generated doc), live harness, fault
  proxy, recorded fixtures: SNMP (Cisco, HPE/Aruba), FortiGate, UniFi first [§5.1].
- Two-machine HA fault-injection suite, 24 h soak and load, tenant measurement at 10/50/100 [§5.3, §5.9, §6].
- OT visibility counters (fragments, undecodable segments, IPv6 when `--ipv6` is off), GRO guidance [§5.10].

**4.4 Network identity** (30-40 d)

- Address spaces (VRF), L2 domains, capture source registry, per-device L2 evidence table, admin-confirmed split of
  one MAC into two devices (the mirror of join) [§4 Part A].
- Mirror deduplication: aligned windows, max-merge per source role, optional packet digest; OT commands never lost
  to dedup [§5.6].
- Site-limited administrators may act on their site's switches and connectors; Palo Alto and Meraki validation;
  COTP fragment carry; CSV import site column [§5.1, §5.10].

**4.5 Delivery and tenancy hardening** (25-35 d)

- Delivery records with idempotency keys where receivers support them, `--webhook` made durable; stated plainly:
  at least once, never exactly once [§5.7].
- Suspend that stops ingest and jobs, tenant hot-add and delete, per-tenant quotas, egress policy for
  tenant-configured targets [§5.9].

**5.0 MSP scale** (30-45 d, only if an MSP customer needs it)

- Tenants in PostgreSQL, one schema per tenant; multi-tenant HA; 100+ tenants with measured limits [§5.8, §5.9].

**Not planned:** general TCP stream reassembly (4.1's bounded framing plus visibility counters instead) [§5.11];
validating all nineteen simulator-only connectors (on demand; the rest stay "simulator only") [§3.2].

## On request

These remain genuinely demand-driven — nothing moves them until the stated trigger happens.

* **Windows packaged collector** (carried over from an earlier roadmap item; M,
  verification-heavy). The service wrapper and installer are written (v2.62.0) but unverified.
  Still needed: run the wrapper for real, wire the privilege/service-account decision into
  `install`, a longer capture run, and CI that links the Windows binary. Do it whenever the
  Windows machine is to hand. See WINDOWS.md.
* **SAML** (carried over from item 3; L, 6/10). Start when a named customer is blocked in
  procurement. It must inherit H2's rules: link on IdP entity id/NameID, never email, and fail
  closed when no allowed domains are configured.
* **Qualys** (carried over from item 3; M). Start once API access on the target tier is confirmed
  and a customer is asking. `vulnscan.rs:24-38` has the scoping. Tenable.io already works through
  the Nessus code.
* ~~**Policy-triggered enforcement**~~ (deferred from 4.0.0). Built in 4.1.0 another way: a zone policy with
  `auto_enforce` drives automatic blocking at automation level (b) (`src/nac_auto.rs`), experimental and off by
  default; see [docs/enforcement.md](docs/enforcement.md). The original request, the 4.0.3 phase A and the design are
  in the project's design notes.

## Parked until real data exists

* Wireless (monitor-mode) intelligence. If a segment asks, start from controller APIs.
* See PRODUCT_GAP_ANALYSIS.md "What not to build" for what is deliberately out of scope.

## Verification still owed

*These stay on the list until they are done. An independent penetration test is planned for later, when the architecture, the code and the UX are in a good enough state.*
* ~~Master/agent across a real network~~ Verified 2026-09-29 over Tailscale with a self-signed
  CA. Still owed: TLS with a public CA, and running behind a reverse proxy. A `--passive-only`
  flag is worth adding for future tests against networks that are not entirely your own.
* Passkeys with a physical security key or phone (verified with software authenticators only).
* OpenObserve, syslog, Elasticsearch/OpenSearch and the chat/e-mail/PagerDuty/Jira/ServiceNow integrations
  against the real services (each is tested against a local fake server, not the genuine article).
* SSO (OIDC) against a real identity provider (SSO.md).
* The eight CMDB/cloud/EDR sources (Entra ID, Intune, Active Directory, Jamf Pro, Azure, AWS, GCP, Microsoft
  Defender for Endpoint) and the Nessus import against a real tenant/directory/instance/subscription/account/project (CMDB.md).
* The SNMP switch reader against real switches from any vendor (docs/switches.md). Item 15 depends
  on it.
* Detections on real industrial traffic (verified with hand-built frames and replay, and now also public recordings of
  S7comm-plus, MMS, GOOSE and PROFINET; see "Industrial protocol expansion" for what is still hand-built only).
* IPv6 on a genuine dual-stack network (IPV6.md).
* The Windows service wrapper and installer (see "On request" above).
* An independent penetration test.

## History and older item numbers

Items 1 to 36 (with 9a, 10a, 16a, 16b), the 4.0.2 follow-ups, the industrial protocol expansion of 4.1.0, the triage of
the external 3.5.0 review (A-01 to A-03, S-, C-, Q- IDs) and the 3.5.0 UX review are in
the project's roadmap history, under the same numbers that code comments cite. Items 21 to
36 (enforcement connectors) are done; the "known bug with a design" (two collectors on one segment) is resolved.
Still open from there:

* **A-02** (decision pending): a SQLite read pool (one writer, two to four readers) before 50,000 devices per
  database; measured in the project's design notes. Supported today: up to 10,000
  devices per database with up to four concurrent console users.
* **A-03** stays a release gate (`tools/check-pg-release-gate.sh`, run by `tools/pre-release.sh`).
* The open questions of the 3.5.0 UX review (primary customer, risk score, primary queue) wait for real customers.
