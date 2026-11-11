# Roadmap and known gaps

DENIS aims to be an honest, self-hostable alternative to the asset-visibility products that cost six figures a
year. This is what is still missing, in order. Pull requests welcome. The current release is 4.4.0.

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
* High-availability fencing, per-tenant encryption keys and tenants on PostgreSQL were planned here; they are built in 4.4.0
  (see "4.4.0: delivered"; up to 4.3 start-up refuses `--database-url` while tenants exist). IP fragments are reassembled for OT decoding since 4.1.2.
* Smaller findings of the internal code reviews, fixed in the next releases.

**Next:** 4.2 and 4.3.0 have shipped (below). What comes after 4.3.0 is under "Next after 4.3.0".

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

## 4.3.0: delivered (the release notes are in CHANGELOG.md)

4.3.0 took the first part of the "correctness under failure" plan and the customer asks below. What is in the program, checked
against the code:

* **More than 40 new detections.** Industrial: new control functions, program uploads, several masters at once, a changed device
  identity, scanning, cross-cell traffic, new protocols, remote-access paths, write bursts and commands outside working
  hours. Office networks: brute force from outside, known-bad domains, mining pools, VPN and anonymizer use, remote-access
  tools, administration spreading, a changed gateway, a rogue DHCPv6 server and a lost or stolen device on the network.
  One plain sentence for each is in [docs/detection-rules.md](docs/detection-rules.md#the-rules-added-in-43-at-a-glance).
* **Detection that measures itself.** Detection runs on its own threads, each rule is timed, and when one makes detection late
  DENIS can pause it (your choice, with industrial rules only warned about unless you opt in), tells you, and resumes it by
  itself; packet loss from overload is reported. Duplicate copies of a packet from SPAN or TAP ports are counted, and
  removed once an administrator switches it on.
* **Seeing what DENIS cannot see.** A page of Health shows, per capture interface, what arrived and what was lost, the
  networks and VLANs seen against the ones expected, and traffic seen in one direction only
  ([docs/visibility.md](docs/visibility.md)).
* **Alerts people can trust.** *This is normal* on any alert, and per-detection counters of what was acted on and what was
  dismissed, kept on the installation.
* **One history per device**, *Not managed by any tool* as a list and a Dashboard tile, and who had an address at a given time.
* **A new Network section.** Map (zoom, search, groups, drawn cables that save themselves), Equipment (one table, product-first
  *Add equipment*, controller rows that open), Response and Setup in seven steps.
* **Any managed switch with standard SNMP can be read.** Port off and the quarantine VLAN on such switches are Experimental,
  off by default and need a write test; tried only against simulated switches.
* **UniFi and Meraki clients** (read only): the clients a controller sees, on the map and on the device. UniFi checked on a real
  controller for the hardware address and the wired flag only; Meraki is Experimental and tested only against a simulator.
* **Site administrators.** An administrator limited to some sites manages only those sites; upgrade converts them
  automatically and an administrator of the whole installation always remains.
* **API tokens** with areas, expiry, rotation and an acts-as mode; site-limited accounts can no longer change other sites
  through imports or new devices.
* **Separate networks** for capture interfaces (the same VLAN number on two plants is not one VLAN) and a shared-hardware-address
  mark. Palo Alto extended support; Cisco VLAN reads that miss less.

**Not in 4.3.0, or known limits** (see [docs/updates.md](docs/updates.md#known-limits-in-430)): Catalyst 9800 and other
controllers, address spaces and VRF, the layer-2 card of a device, and a hardware-address split are not built. The PostgreSQL
code of 4.3 is compiled and reviewed, not yet run against a production database. Generic SNMP control and everything about
Meraki are Experimental.

## 4.4.0: delivered (the release notes are in CHANGELOG.md)

4.4.0 holds what was planned for 4.3.1 and 4.3.2 as well (there is no 4.3.1 or 4.3.2). What is in the program, checked against the
code and the release notes:

* **Where a device is plugged in.** One shared model of what a device hangs on (access points and switches under their controller,
  switch or gateway, virtual machines under their host) with an adapter per connector: UniFi, Cisco Meraki, FortiGate (FortiAP,
  FortiSwitch, Wi-Fi clients), Proxmox, Hyper-V and NSX (read only), TP-Link Omada and MikroTik.
* **New connectors, Experimental:** TP-Link Omada, MikroTik Wi-Fi (block by hardware address, disconnect, read the Wi-Fi clients) and the
  Cisco Catalyst 9800 wireless controller; none was tried on real equipment. Azure stays Experimental.
* **Verified in a lab:** UniFi Wi-Fi blocking (a client of an access point), the Cisco Secure Firewall Device Manager (FDM) and Management
  Center (FMC), both in the Cisco DevNet sandbox on virtual devices (29 October 2026), and AWS in a lab account (3 November 2026).
  They carry no label. Details: [docs/nac/validation.md](docs/nac/validation.md).
* **One Respond dialog.** It names the few responses that can work for this device and why one is recommended; equipment that is not on
  the device's path is kept in one closed group; a Wi-Fi client the controller shows gets the controller's client block.
* **Address spaces (VRF).** The same address in two routing domains is no longer taken for one network; an administrator can split a
  hardware address shared by two devices (schema V60). Alerts, baselines and flows per split device are not done yet.
* **Twelve new detections and Rules v2.** Three of the detections (name poisoning, a changed time source and writes outside the learned
  registers of an industrial device) are Experimental. New rules arrive switched off. Trial mode, exceptions with an expiry, what a change
  would have done over the last days, and why a rule alerted or did not. Your own rules with several conditions, an editor, export,
  import and templates; counts and sequences are Experimental and off by default.
* **MSP.** Rules an MSP sends (not allowed by default, ask me, or into a trial), single-use invitations for customers with a spoken phrase,
  one-line enrolment of agents. MSP management is no longer marked Experimental.
* **Shipped lists** can update themselves (off by default); the abuse.ch feeds use the current ThreatFox and URLhaus interfaces.
* **Durable delivery.** Alerts and notices go through a queue in the database (schema V59): at least once, never exactly once.
* **Keys.** A data key per customer under the master key, rotation of both while DENIS runs, a passphrase copy of the master key
  ([docs/key-management.md](docs/key-management.md)).
* **PostgreSQL (Experimental).** A write fence for the old leader (schema V58), two servers on one database, customers in PostgreSQL, a
  local fault lab with a Patroni cluster. The lab run of 2026-11-04 passed 13 of 15 scenarios; the two that did not (a half-open link
  to the database) are fixed but still to confirm in the lab.
* **Easier start and licensing.** A Start page, first-look numbers and a weekly summary mail. Licensing counts devices seen in the last
  30 days (tiers DENIS 500, DENIS 5000, DENIS 20000).
* **Review fixes and dependencies.** Fixes from the code review and patch updates of five libraries, among them certificate verification.

## Not done in 4.4.0, moves on (owner-approved list of 2026-11-04)

* **Managed-service high availability (step P13):** the run on a managed PostgreSQL service with a soak of many hours and the 10, 50 and
  100 tenant measurement (4.4.2, see below); a re-run of the two local lab scenarios s3b and s3c.
* **Azure, AWS and Omada tests** on real systems, then removing the Experimental labels that are verified (4.4.2).
* **Capacity measurement and the sizing table** (500, 5,000 and 20,000 devices, and the 50,000 check).
* **Full fuzz and Linux performance runs.**
* **Real-hardware checks:** MikroTik Wi-Fi access point, Omada with an EAP110, Cisco Catalyst 9800, Meraki.
* **Split of one hardware address, follow-ups:** detection per split device (alerts, baseline, flows), stamping the network on every
  observation, an engine channel for the undo.
* **Console database calls off the async workers.**
* **Command-line tools on PostgreSQL installs without stopping both nodes:** tenant suspend and resume live, `denis msp` and
  `msp-link` on PostgreSQL, moving the default tenant.
* **Rules follow-ups:** an advanced JSON drawer, what-if for a score change, server refusals translated through error codes, a
  persistent first_seen.
* **The quick-start time claim** ("about ten minutes") stays out until three outside testers have timed it; container timing.
* **Notifications:** `--webhook-volatile` and the warning `W_NOTIFY_DROPPED` are removed in 4.5.
* **AWS:** VPC Traffic Mirroring (VXLAN) was never verified on a real mirror, and there is no AWS inventory read mode.

## 4.4.1 (delivered)

*Evidence labels: documented / best guess / verified. A verified feature carries no label; only Experimental is labelled.*

* **The Rules page is one list with one model.** One row and one switch for every rule (built-in, IT, OT, several conditions and rules
  an MSP sent), *Processing impact* instead of *Cost*, new rules as a mark *New in 4.4.0* among the others, and no trial mode: a
  rule is on or off. A rule that was in a trial when 4.4.1 started is switched off, with one notice.
* **The Respond dialog:** equipment cards keep their width and the two information icons of "How long" are told apart.
* **Cisco Catalyst stacks.** Verified on a Catalyst 9200L stack (two members, IOS XE 26.02.1, physical) in the Cisco DevNet sandbox on
  5 November 2026, over SNMPv3: both members' ports, the write test, a port switched off and on, the quarantine VLAN on the
  second member, and the stack ports and the management port refused. IOS XE is named from `[IOSXE]` descriptions and a stack's
  model names every member. *Quarantine by VLAN* on Cisco carries no Experimental label any more; the move on other makes
  (`dot1qPvid`) stays Experimental.
* **TP-Link Omada on a real controller** (5.15.24.19, an ER605 gateway, an EAP110 access point): identity, sign-in, the site, the
  devices and the clients are verified. A controller without the v2 client list now checks a block by the client's own
  `blocked` flag. The controller's own block call disconnected a Wi-Fi client in about two seconds and the client could join again
  right after the release. Through DENIS, a wired client and the traffic effect are not yet verified: Omada stays Experimental.

## 4.4.2 (delivered)

* **TP-Link Omada** loses its Experimental label (owner decision, 5 November 2026): reading and the controller's own client block were tried on a real
  controller (5.15.24.19, an ER605, an EAP110). The 4.4.1 block through DENIS was refused because the client was asked in the wrong
  spelling of its hardware address; fixed. A block by DENIS on a wired client and its effect on traffic are not tried yet.
* **Respond path from controllers:** the address a controller reports for a device places it on the path of every connector kind,
  and the card says how and where the controller sees it.
* **Address-conflict alerts name their evidence:** the kind of packet, the capture interface, the VLAN and the Ethernet source, and the
  other holder's last claim when remembered.
* **MikroTik Wi-Fi:** no access-list entry is left behind when a step after it fails; a router without a Wi-Fi package no longer offers
  the Wi-Fi responses; the documentation names CAPsMAN for many access points.

## 4.4.3 (delivered)

* **TP-Link Omada:** the release of a block made for a device that has an address works (4.4.2 failed with "Give a plain MAC
  address"), and Respond recommends the controller of a device that the inventory holds in several rows.
* **MikroTik Wi-Fi:** a router that manages access points with CAPsMAN but has no separate Wi-Fi package (a hEX) is no longer reported as having none; the documentation tells how to set up the new CAPsMAN with one connector. A block of a client on a CAP through the manager is not tried yet.

## 4.5.0 (delivered; the release notes are in CHANGELOG.md)

There is no 4.4.4: what was planned for it is part of 4.5.0.

* **Alerts and blocks on visited domains and URLs: delivered.** Reading server names (TLS) and the host of a plain HTTP request is optional per collector and its cost is shown next to the switch. For an encrypted connection DENIS compares the address and the server name; the path of a URL is compared for plain HTTP only. A response can block a name on FortiGate, Palo Alto and MikroTik (Experimental: not yet tried on real equipment); UniFi and Omada do not offer it.
* **Threat lists: delivered.** Your own lists and lists from other sources (plain text, CSV, STIX 2.1, TAXII 2.1, MISP), each with its action (alert, alert and prepare a block, automatic block as Experimental), a refresh interval and an age limit; many lists per customer; an MSP can send the definition of a list to its customers. An alert says whether the match was an exact address, a range or a whole network provider.
* **Checks on real systems.** MikroTik Wi-Fi: the block by MAC, its release and the disconnect are verified with one access point under a CAPsMAN manager (the legacy `wireless` package and the legacy CAPsMAN are not supported; many access points under one manager are not tried). PostgreSQL was run in a container for the first time (two PostgreSQL defects found and fixed). Still open and done by the owner after the release: a block of a wired Omada client through DENIS, the Azure connector on a real subscription, AWS once more, Cisco Catalyst 9800.
* **A review of the whole code for state problems** (what happens when a step stops half way, a request arrives twice, or a restart comes in the middle) with about 380 findings, fixed in 4.5.0 with tests that pin the earlier behaviour.
* **Not in 4.5.0:** high availability on a managed PostgreSQL service (the run on a managed service, a long soak and the many-customer measurement; decided later), MikroTik access points at scale (one shared REST user for many standalone access points), and the evidence model below.

## Next after 4.4.0 (in this order; nothing here has a date)

* **A record of each connection as evidence** (source port, packets in each direction, first and last seen, how far the TCP handshake was seen, DNS answer lifetimes and name chains), kept with an alert so that an alert on a bare address can be investigated: a general model for DNS, server names and connection data that the detections and the investigation view share. 4.5.0 shows the names and the connection facts that are already collected, with their source.
* **Read what more endpoint tools know**: the device lists of further EDR and MDM products (Intune, Jamf, Entra ID and Defender are already read, see CMDB.md), next
  to what is seen on the network.
* **802.1X, RADIUS accounting and CoA.** Who is behind an address, durable quarantine through your own RADIUS server,
  session-exact disconnect; with the first customer who runs 802.1X.
* **Sandbox validations.** Done in the Cisco DevNet sandbox on 29 October 2026: Catalyst 9300 and 9200CX, Cisco Secure Firewall
  Device Manager (FDM) and Management Center (FMC). Still open: Meraki (when its sandbox is available), and a Cisco Modeling
  Labs run with a layer-2 switch image (IOSvL2) to verify client isolation (a quarantine VLAN move on a switch with real
  client traffic), started only when it is wanted.

## Next: what customers asked for (planned, in this order)

From what people running network detection and access control say about their own deployments. These come before new connectors.

* **Unknown devices without an agent (delivered in 4.3).** Onboarding puts the unknown-device question first: what is on the network that nothing manages, with the evidence for each device and an owner to assign. Delivered in 4.3: Devices → "Not managed by any tool", a Dashboard tile, an evidence card at the top of the device panel, owner assignment, CSV export, and the question as the first step of the setup guide. The answers come from the coverage tools you have connected (Intune, Entra, Active Directory, Jamf, Defender, Nessus), a hand entry, or a switch or connector DENIS reads; "cannot tell" is never shown as managed or as not managed. Tested against fixtures, not yet against a real tenant.
* **Which devices a security or management tool knows (read-only import; delivered for Microsoft Intune, Entra ID, Active Directory, Jamf Pro and Defender, further products on request).** DENIS reads the device list of the endpoint security and device management products you already run and sets it next to what it sees on the network. Each device then says either "managed by <tool>, last seen <time>, protection <status>" or "not managed by any tool", and the second group is a list an administrator can filter, assign an owner to, and export. How it works: a device is matched by hardware address, name or serial number; an unclear match is shown as a possible match for a person to confirm and is never guessed; a tool that cannot be reached or an old answer gives "unknown", a third state that never counts as healthy or as unhealthy. DENIS only reads: it changes nothing in those products, and it takes no action because of this data unless an administrator sets a rule for it. Not part of this item: admission by device health, or isolating a host through the endpoint product.
* **Who is behind an address (802.1X logs).** Reading the authentication and accounting records of your RADIUS server (user or certificate name, hardware address, access point, network name) to attach the identity to the device, including devices that use a random hardware address on Wi-Fi. For organisations that run 802.1X; planned later, together with the first customer who does.
* **RADIUS accounting and durable quarantine (for organisations that run 802.1X).** Planned to start with the first customer who does. DENIS reads the accounting records of your own RADIUS server and shows, per device, the user or certificate, how it signed in (802.1X or MAC), the port or access point and the session history. A quarantine can then be made lasting: DENIS gives your RADIUS server a restrict-only verdict to check at each sign-in, and with no answer from DENIS nothing is restricted. Session-exact disconnect, re-authenticate and port bounce go through the existing approval and audit path. DENIS also compares what it sees with what a MAC-authenticated port claims, to flag a spoofed hardware address. An integration with Cisco ISE (then Aruba ClearPass) comes on request. DENIS does not plan to be a RADIUS server itself.
* **More real-equipment checks of enforcement.** Kill switch, hourly limit, wrong credential, a connector that loses its connection, and release after a restart, on each verified device.
* **Simple, affordable use for small teams.** Quick first result, safe defaults, and licensing that does not price small organisations out; to be settled before the first commercial sale.

## 4.2: delivered as 4.2.0 to 4.2.4, with the plan it was built from

The plan below is kept as it was made. What shipped is in CHANGELOG.md under 4.2.0 to 4.2.4; an item of this list that is not
there is not built and moves to "Next after 4.3.0" or to the lists further down.

What was left out of 4.1.4 on purpose or not reached, and what the first lab runs on real equipment showed, in the order it was planned.

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

- A PostgreSQL-enabled release binary (`--features postgres`) next to the standard one, so high availability does not need a self-built program. (Shipped in 4.2.1.)

- Leader-epoch fencing of every PostgreSQL write, cursor and NAC intent row; DB-side fencing of the old leader [§5.3]
  (audit F2-1). *Moved to 4.4.0 and merged there (Experimental); see "4.4.0: delivered".*
- Per-tenant data keys under the master key, tenant id in the associated data, tenant stamp, rotation, export with
  passphrase [§5.5] (audit F6-5 / T6-7). *Moved to 4.4.0 and merged there.*
- Enforcement orchestrator: snapshot and undo before the write, pending row and audit in one transaction; PAN-OS
  partial commit, SonicWall without override, Juniper commit confirmed, NSX revisions [§5.4]. (Already in 4.1:
  server-side plans stored in the database and spent once, device I/O on a thread of its own that a disconnecting
  client cannot cancel, and one central target guard, see `src/nac_orchestrator.rs`.)
- Real-equipment validation with a compatibility matrix (data file, API, UI, generated doc), live harness, fault
  proxy, recorded fixtures: SNMP (Cisco, HPE/Aruba), FortiGate, UniFi first [§5.1].
- Two-machine HA fault-injection suite, 24 h soak and load, tenant measurement at 10/50/100 [§5.3, §5.9, §6]. *Moved: the
  local fault lab is merged in 4.4.0; the run on a managed service, the soak and the 10/50/100 measurement are still open.*
- OT visibility counters (fragments, undecodable segments, IPv6 when `--ipv6` is off), GRO guidance [§5.10].

**4.4 Network identity** (30-40 d)

- Address spaces (VRF), L2 domains, capture source registry, per-device L2 evidence table, admin-confirmed split of
  one MAC into two devices (the mirror of join) [§4 Part A].
- ~~Mirror deduplication~~ Shipped in 4.3 (`src/capture_dedup.rs`: modes off, observe and on per capture source, merging across
  interfaces, industrial frames never removed, a safety valve).
- Site-limited administrators may act on their site's switches and connectors; Palo Alto and Meraki validation;
  COTP fragment carry; CSV import site column [§5.1, §5.10].

**4.5 Delivery and tenancy hardening** (25-35 d)

- Delivery records with idempotency keys where receivers support them, `--webhook` made durable; stated plainly:
  at least once, never exactly once [§5.7]. *Moved to 4.4.0 and merged there.*
- Suspend that stops ingest and jobs, tenant hot-add and delete, per-tenant quotas, egress policy for
  tenant-configured targets [§5.9].

**5.0 MSP scale** (30-45 d, only if an MSP customer needs it)

- 100+ tenants with measured limits on PostgreSQL [§5.8, §5.9]. (Tenants in PostgreSQL, one schema per tenant, and
  multi-tenant HA are in 4.4.0 as Experimental; only the measurement at scale stays here.)

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
