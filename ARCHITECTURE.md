# DENIS architecture map

Orientation doc for an agent (or the owner) picking this codebase up cold. It exists because this
project has repeatedly hit the same failure mode: a session reads a stale `.md` file and acts on a
claim that code has already disproved, or re-derives something from scratch that was already
built. **This file's job is to be the one place that stays accurate about what exists and where.**
Everything stated as fact below was checked directly against source, by grep, read, or running a script, not
copied from another doc's claim. The parts written for 4.2 (marked **(4.2)**) and the numbers in §3, §4 and §6 were
checked on **2026-10-20** against `main` at the 4.2 review fixes (`Cargo.toml` still says `4.1.4`; 4.2.0 is the
unreleased top section of `CHANGELOG.md`). The older parts were last checked on 2026-10-13 at `v4.1.0` and were
corrected only where a statement was found to be wrong. Where a claim could not be directly confirmed, it says so.

A longer Slovak overview for software architects, written from the same code on the same day, is
[ARCHITEKTURA_DENIS_SK.md](ARCHITEKTURA_DENIS_SK.md). This file stays the short one.

This is an orientation doc, not a reference manual: it tells you which deeper `.md` or source file
to open next for a given task, rather than repeating that file's content. Keep it short enough to
read in one sitting; when you touch a subsystem and learn its status has changed, update the one
line here that's now wrong. That is the whole point of this file existing.

**If you are editing this file**: do not restate another doc's "done" claim as fact here without
checking source yourself. That is exactly the mistake that made this file necessary.

## Contents

1. [Subsystem map](#1-subsystem-map)
2. [Where to look](#2-where-to-look)
3. [Data model and the Store trait family](#3-data-model-and-the-store-trait-family)
4. [Build and release mechanics](#4-build-and-release-mechanics)
5. [Known stale or conflicting docs](#5-known-stale-or-conflicting-docs)
6. [Scale facts](#6-scale-facts)

---

## 1. Subsystem map

Status words below mean: **done** (built, exercised, no known missing piece for its stated scope),
**partial** (built but a named part is missing, unverified against the real thing, or only some of
several planned instances exist), **experimental** (built and tested, labelled experimental in the
product, off by default), **deferred** (explicitly named as "not yet" in its own doc or code comment).

### Packet capture
`src/capture.rs`, `src/capture_config.rs`, `src/tunnel.rs` (ERSPAN, GRE, VXLAN and Geneve mirror
tunnels, 4.1), `src/winservice.rs` (Windows service wrapper). Uses the `pcap` crate
(libpcap/Npcap), one OS thread per interface, BPF filter, promiscuous-with-fallback. **Done** on
macOS/Linux. **(4.2)** The interfaces are now owned by a supervisor, see "Capture supervisor and monitored
networks" below. The glibc release programs link against `libpcap.so.0.8`; from 4.1.1
there are also static musl programs with libpcap built in (`tools/build-musl.sh`, for Alpine and any Linux). Windows capture is verified on real hardware; the
Windows **service** wrapper/installer is **unverified on a real Windows machine**. Doc: **WINDOWS.md**.

### Capture supervisor and monitored networks (4.2)
`src/capture_supervisor.rs` (design D1 part A), `src/subnets.rs` (part B), `src/listen.rs`,
`src/web_admin/capture.rs`, `ui/capture.js`. `CaptureSupervisor` (created in `src/engine/collector.rs`) keeps one
**slot** per configured capture interface (the main one and each mirror), each with a state, its own worker
thread, counters and a bounded retry backoff (2, 4, 8, 16, 32, 60 s with jitter; 300 s for a missing permission;
a flapping interface waits at least 30 s). DENIS does not exit or wait because of a network card: a missing
interface, a mirror port without link or a failed open is a slot in a failure state, retried on its own. A slot
is the only owner of its worker, and a worker that does not stop keeps the slot blocked ("the previous capture
did not stop") instead of a second worker being started. Loss and recovery become notices (below) after a grace
period (`capture.alert_grace_secs`); a quiet interface (no packet for 15 minutes) is shown, never alerted. The
published state goes to a `Board` that Health, `/api/status` and the presence check read; only the main
interface pauses the presence check. `src/subnets.rs`: the **monitored networks** (the subnets treated as "your
own network") from the main interface, the command line and Settings, as a `LiveScope` that every capture thread
reads per packet, so a change applies at once. A monitored network never makes DENIS scan (sweeps and port scans
stay inside the main interface's own subnet), never widens what an enforcement action may touch and is never
learned from traffic. `src/listen.rs`: on Linux, a web address that is not on an interface yet at boot is bound
with `IP_FREEBIND`. Routes: `/api/interfaces/capture*`, `/api/interfaces/monitored-subnets*` (administrators;
changing monitored networks asks for the password again). Tests: `capture_supervisor_tests.rs`,
`web/tests/capture_tests.rs`, `tools/console-start-test.mjs`. Status: tested with a simulated opener and probe
and in the browser; **not** run against unplugged real hardware in every combination.

### Parsing / protocol decode
`src/parse.rs` (frame to `Observation`, VLAN tags; module root, the decoders are split by topic into `src/parse/`: dns, industrial, flows, discovery), `src/ja3.rs` (JA3/JA3S), `src/tls.rs` (the
console/agent-ingest TLS listener, not device-traffic fingerprinting), `src/flow.rs` (flow
aggregation, bounded key tables), `src/fingerprint.rs` (device/OS guessing, OUI lookup), `src/ot.rs`
plus `src/ot/` (industrial decoders, see OT below). **Done.**

### Detection / rules engine
`src/detect.rs` plus `src/detect/` (about 20,000 lines together, split by rule family: `arp`,
`inbound` (connections opened from the internet, 4.1), `exposure`, `identity`, `scan`, `volume`,
`ot`, `segmentation` and more; `facts` is the per-window cache of device attributes every rule reads
through; the detector's unit tests are split by rule topic into
`src/detect/tests/`), `src/rules.rs` (admin tuning), `src/rule_drafts.rs` (AI-assisted
tuning *drafts*, never auto-applied), `src/rule_dryrun.rs`, `src/rule_suggest.rs` (deterministic, **not
an AI feature**), `src/engine.rs` (orchestration: one `Collector` shared by `run` and `agent`; module root, the code is split by topic into `src/engine/`: shared, collector, tenants, run, agent_run).
Alert-noise reduction (4.1): `src/quiet.rs` (quiet stream), `src/digest.rs` (daily digest),
`src/autoclose.rs`, `src/noise.rs`. **Done.** Docs: **archive/DETECTION_RULES_REVIEW.md**,
**archive/ALERT_NOISE_REDUCTION.md**, **archive/INBOUND_FINDING.md**.

### Network-change / connection-stability tracking
`src/netchange.rs`, `src/connstab.rs`, `src/trends.rs`. **Done.**

### Agents / collectors
`src/agent.rs` (remote-agent push side), `src/ingest.rs` (module root; the code is split by topic into
`src/ingest/`: `apply`, `validate`, `msp`, `backup`, `http`) (master-side protocol, per-agent bearer
tokens stored as SHA-256 only, tenant-prefix token routing), `src/agent_update.rs` (4.1: three
admin-selectable agent update modes, manual by default, over the agent's existing report channel),
`src/agent_builds.rs`, `src/replay.rs`, `src/sink.rs` (OpenObserve), `src/syslog.rs` (CEF/LEEF/JSON,
Elasticsearch/OpenSearch). The agent is the same `denis` binary run as `denis agent`. **Done**;
agent install and update are tested in containers and against a test master, not across a real
remote site on every platform.

### Updates
`src/update.rs` (module root; the code is split by topic into `src/update/`), `src/update_key.rs` (the release public key compiled in), `src/update_mirror.rs`
(4.1: `usedenis.com` as a fallback host used only when GitHub cannot be reached, same signature
rules, no redirects). **Done.** Docs: **RELEASING.md**, `docs/updates.md`, `tools/mirror-hosting.md`.

### IPv6
`src/ipv6.rs`, `src/dhcpv6.rs`, opt-in via `--ipv6` (widens the BPF filter, `parse.rs`) and
`--ipv6-subnet`. **Partial by design**: real, tested, opt-in; `Asset.ip_history`, active-scan and CSV
export remain IPv4-only. The module comment of `ipv6.rs` is still partly stale (§5). Doc: **IPV6.md**.

### Passive DNS
`src/pdns.rs`, opt-in, own retention. **Done.** Use the module doc; archive/PASSIVE_DNS.md is background.

### IP enrichment
`src/ipenrich/` (GeoIP, reverse DNS, caching, classification, provider/owner lookup, settings).
**Done.** archive/IP_ENRICHMENT.md now carries a "built" status line.

### Multi-agent dedup
`src/device_merge.rs` + the stores' `merge_device`: the joined-collector merge job, after admin
confirmation. **Done** for local-site joins. archive/MULTI_AGENT_DEDUP.md now says so at its top.

### Enforcement (NAC connectors, orchestrator, actions, automation)
This is the largest subsystem (about 116,000 lines in `src/nac*.rs` and `src/nac_*/`, tests included).

* **Connectors.** `src/nac_registry.rs` (module root; the code is split by topic into `src/nac_registry/`: kinds, instances, guards, plan, virt) (`ConnectorKind::ALL`: **20 kinds**: SNMP, UniFi, Meraki,
  AWS, OPNsense, FortiGate, Palo Alto, Hyper-V, SonicWall, NSX, WatchGuard, Check Point, RADIUS CoA,
  Juniper, Azure, Proxmox, MikroTik, and new in 4.1 Cisco ASA, Cisco FTD through FDM and through FMC),
  one `src/nac_<kind>.rs` (+ `src/nac_<kind>/connector.rs`) per vendor, `src/nac.rs` for SNMP,
  `src/nac_ssh.rs` (the system `ssh`/`sshpass` for ASA and Juniper), `src/nac_connector.rs`.
  **(4.2)** Two connectors gained a second way to act: **Palo Alto** blocks and quarantines through a
  **dynamic address group** without a commit (`src/nac_paloalto/uid.rs`: DENIS registers its own tag for the
  address through the User-ID XML API and the group the administrator made once picks it up; ownership is proved
  by DENIS's own tag names per install, the ledger's undo data and a read before every write;
  `src/nac_paloalto/reconcile.rs`: the job `paloalto_reconcile` compares the ledger with the firewall every
  minute and after a restart, marks a row `unconfirmed` when the tag is gone and re-registers it only under the
  guards of a new apply), and **UniFi** signs in with an **API key** on the Integration API
  (`src/nac_unifi/integration.rs`) and blocks by **firewall policy** (`src/nac_unifi/fw_policy.rs`: methods
  `fw_policy` and `fw_flow`, one policy per zone pair, name and description carry DENIS's marker, the policy is
  put first in its pair's order under a lock per console and site, read back and compared whole). Both are
  **experimental**: they were run against simulators and read-only/one-off observations on one PA-220 and one UniFi
  gateway, not validated (NAC_HARDWARE_VALIDATION.md).
  `ConnectorKind::wired()` is true for every kind except SNMP, which keeps its own per-switch routes
  and serves the action path as instances `snmp:<switch id>`.
* **What was validated on real equipment**: exactly two capabilities, `nac_action::VALIDATED` in
  `src/nac_action/caps.rs`: SNMP disable a port (`if_admin_status`, one D-Link DGS-1100-08V2, NAC.md) and **(4.2)**
  SNMP quarantine by access VLAN (`access_vlan`, one Cisco Catalyst WS-C2960X-48TS-L, IOS 15.2(7)E4, SNMP v2c and
  v3). Everything else is tested against local simulations of the vendor's documented API only (some with a
  single observation on real equipment, in NAC_HARDWARE_VALIDATION.md) and labelled *simulator only* / experimental.
* **Orchestrator.** `src/nac_orchestrator.rs` (+ `action.rs`, `observe.rs`) is the one place a block or
  unblock is carried out: preview token, `Authorized` (only `web_nac::authorize`/`may_act` can make
  one), site gate, lab switch, egress policy, kill switch with an atomic hourly-cap reservation, target
  guard, intent row before the device is touched, the device call through a `Permit` only this module
  can mint, on a thread of its own, read-back, ledger finalization, audit, notification. Two connector
  shapes: *orchestrated* (every new connector and every connector on the action path) and *legacy*
  (the sixteen pre-orchestrator modules on the old routes, behind the same guards).
  `src/nac_guard.rs` holds the shared rules (preflight, instance scope, `WriteFail`, preview tokens,
  per-tenant keys).
* **Actions (4.1).** `src/nac_action.rs` (+ `caps.rs`, `spec.rs`): five action types (block a device,
  block a flow, quarantine, disable a port, end sessions) and per-kind capabilities.
  `src/nac_plan.rs`: plans are **stored** (`nac_plans`) and spent once, across restarts and HA nodes.
  `src/nac_flow.rs` (flow framework), `src/nac_perm.rs` (per-action permissions; release follows the
  action type), `src/nac_lab.rs` (two lab switches: `allow_unvalidated` and
  `allow_experimental_actions`, both off on a new install and never turned on by an upgrade),
  `src/nac_expiry.rs` (time-limited actions rolled back late, never early, leader only),
  `src/nac_reconcile.rs` (hourly read-back, drift marked `restored_elsewhere` and never re-applied,
  orphans listed but never deleted), `src/nac_reread.rs`, `src/nac_site.rs`, `src/nac_prompts.rs`
  (block suggestions), `src/nac_texts.rs`. Web: `src/web_nac.rs`, `src/web_nac_registry.rs`,
  `src/web_nac_actions.rs`, `src/web_nac_auto.rs`. **(4.2)** The old port-control route pair `POST
  /api/nac/plan` and `/api/nac/apply` is **retired** (it answers 410 and points to the action API); `nac::plan`,
  `nac::apply` and the in-memory plans are gone, so a port action goes through the same stored plan and
  orchestrator as every other action. Restore, check and drift of rows written before 4.2 stay.
* **Where a device is and which firewall is on its path (4.2).** `src/location.rs`: `resolve` is pure; from the
  polled switches, the port marks and the stored placement history of a MAC it says where the device is plugged
  in and how sure that is (`confirmed` when the device announces itself by LLDP as an end host on an access port that
  carries nothing else; `high` when its MAC is learned on exactly one access port of a fresh, complete forwarding
  table on two reads in a row; otherwise it names the shared port or says unknown, and the port is withheld
  with the reason). A switch-port action is offered only for `confirmed` or `high`. `src/nac_path.rs`: for every
  routing firewall connector and the device's current addresses, a status `verified`, `configured`, `off_path`,
  `not_verified` or `no_address` (`endpoint` for a connector that acts at the endpoint); `not_verified` and
  `off_path` are never recommended and never used by automation (the plan carries a warning a person must tick).
  `src/nac_scope.rs`: the plain-words sentences of what an action covers and what it does not (other addresses of the
  device, the flow's protocol and port), shown in the plan and written into the audit entry. `GET
  /api/nac/capabilities` (`src/web_nac_actions.rs`) returns every option of every connector for a target with its
  state and reason; the Respond menu in the console is built from it.
* **Automation** (`src/nac_auto.rs`), **experimental, off by default**: level (b), automatic
  enforcement by rules (policies opted in per revision, typed phrase, both lab switches, kill switch,
  at most 7 days per action, caps per hour, policy and device), and level (c), "let Autopilot block",
  only on top of (b), with stricter caps (24 h, 2 per hour, 6 per day), Autopilot active, and gates of
  7 days of would-have-blocked records, 10 judged and 95 % agreement. `grant_for_autopilot` re-checks
  everything on every use. Autopilot reaches enforcement only through `src/autopilot/enforce.rs`, which
  calls only `nac_auto` (a crate test pins it).

* **Rule actions (4.2, experimental)**: what a rule does when it matches, see "Rule actions" below.

Docs of record: **archive/ENFORCEMENT_ACTIONS_DESIGN.md** (the historical design; built),
**NAC.md** (safety model; current status at its top), `docs/enforcement.md`
(user guide, current), the generated capability matrix (`tools/gen-enforcement-matrix.py`),
**NAC_HARDWARE_VALIDATION.md** (the plan for real-equipment validation), the `archive/CODE_REVIEW_B_*.md` and
`archive/CODE_REVIEW_C_CONNECTORS.md` reviews with their Status sections.

### Switch topology / SNMP polling
`src/switches.rs`, `src/snmp.rs`, `src/snmp_v3.rs` + `src/snmp_v3/` (4.1: SNMPv3 USM for reads and the
`ifAdminStatus` write), `src/topology.rs` (Cisco per-VLAN reads, 4.1), `src/edges.rs`. **Done**; SNMPv3
and Cisco reads are tested against stand-ins, and (4.2) one Cisco Catalyst 2960X was read and written for the validated
quarantine capability above. **(4.2)** A Cisco switch with many VLANs is read in turns across polls (VLAN 1 every
poll, the others from where the last poll stopped; the VLANs not reached keep the previous snapshot's entries;
per-switch limit "VLANs read per poll", 2 to 512, default 64). Doc: **archive/SWITCH_TOPOLOGY.md**.

### Map, relations and the Equipment order (4.2)
`src/topology_relations.rs` (`build`, a pure builder computed per request, no stored snapshots), `src/web_relations.rs`
(`GET /api/topology/relations`, `POST /api/topology/links`, `DELETE /api/topology/links/{id}`), `src/web_gateway.rs`
(tiers, unmanaged marks, `PUT /api/network/equipment-order`), `src/gateway.rs` (`Confirmations`: the administrator's
statements, including the drawn cables and the order), `ui/wiring.js`, `ui/network.js`. Every link
says how DENIS knows it: `confirmed` (LLDP/CDP on a port with one neighbour), `inferred` with a confidence from the
forwarding tables (high, medium, low), or `manual` (drawn by an administrator; it always wins over a guess, and a
conflict with what the equipment said itself is shown). Where DENIS is not sure it asks (`questions`). At most 400
pieces of equipment and 200 drawn cables; the switches DENIS reads, the connectors and both ends of every cable are
always on the map; connectors that act at the endpoint, in a cloud or through a controller (UniFi, Meraki, FMC,
hypervisors, cloud groups, RADIUS) are not (`web_relations::on_the_map`). `order` turns the links into the "by wiring"
order (internet side first) that the Equipment page uses; the order is display only. Cable and tier writes check the
sites of both ends against the caller's grants. Tests: `topology_relations_tests.rs`, `web/tests/gateway_tests.rs`,
`tools/wiring-test.mjs`, `tools/equipment-order-test.mjs`. Status: built and tested against synthetic snapshots and
the lab's switches, not against many real networks.

### Device identity: one device, several interfaces (4.2)
`src/identity.rs` (the rules and `Groups`), `src/identity/evidence.rs` (what counts as evidence), `src/identity/job.rs`
(the job `identity`, every 5 minutes, leader only), `src/store/identity_repair.rs`, the `IdentityStore` trait with
`src/store/sqlite/identity.rs` and `src/store/pg/identity.rs`, `src/web_identity.rs`. An `Asset` row stays one MAC
endpoint at one site; it is an **interface** of a **device**, and the device is identified by its primary asset id, so
every API, rule, zone, exception, hands-off entry, event and incident that names an asset id keeps working. A row that is
not its own device is a **member**: `AssetMeta::merged_into` names the device (the compatibility mirror every consumer
reads) and the table `device_links` (schema V49) keeps why (source, evidence, who, when); both are written in one store
transaction. `identity_suggestions` holds what an administrator decides and `device_integrations` the switches and
connectors bound to a device by hand. Rules: never a chain, never across sites, a link only adds protection (a protected
address or hands-off entry of any member protects every interface), everything is reversible, a link never moves a row out
of another device. Evidence has two strengths: **authoritative** (the device lists its own hardware address and its
current address, or two integrations report the same real serial number) links automatically only over an
authenticated channel (SNMPv3 with authentication, a connector API over TLS with the certificate checked, a report
read successfully within 7 days) and is audited and undoable; otherwise it is a suggestion. **Supporting** evidence
(neighbouring hardware addresses of one vendor block, an equal host name) is a suggestion only, never for end-user
devices. A connector never acts on the device it manages (its address and every address of the device it is bound to
are refused as `protected_connector`). Routes: `/api/assets/{id}/interfaces`, `/api/identity/*` (administrators; over
the MSP channel a merged_into edit or an unbinding is an Admin-class change). Tests: `identity/evidence_tests.rs`,
`identity_tests.rs`, `store/sqlite/tests_v49.rs`, `tests/identity_*.rs`, `web/tests/device_identity_tests.rs`. Status:
tested with synthetic and fixture data; no automatic link has been run against a fleet of real routers.

### Segmentation policies
`src/segmentation.rs`, `src/segmentation_job.rs`, `src/segmentation_matrix.rs`,
`src/web_segmentation.rs`, `src/outbound_policy.rs`. **Done** for judging violations; segmentation
itself does not block: a policy may opt in to automatic enforcement (above), and (4.2) carries a response setting
(see "Rule actions"). Doc:
**archive/SEGMENTATION_POLICIES.md** (now carries a "built" status section).

### Control coverage / compliance
Three distinct things with similar names: `src/control.rs` is the **multi-tenancy control plane**;
`src/coverage.rs` + `src/watch_coverage.rs` is **control coverage** (**done**, archive/CONTROL_COVERAGE.md);
`src/compliance.rs` is **standards mapping** (**done**).

### CMDB, cloud and endpoint integrations
`src/cmdb.rs` (Entra ID, Intune), `src/ad.rs`, `src/jamf.rs`, `src/defender.rs`, `src/aws_cloud.rs`,
`src/azure_cloud.rs`, `src/gcp_cloud.rs`: one shared `cmdb_devices` table, exact hostname match.
**Built, none verified against a real tenant or account.** Doc: **CMDB.md**.

### Vulnerability scanning
`src/vulnscan.rs` (Nessus/Tenable.io; **Qualys deferred**), `src/vulndata.rs` (end-of-support, CISA
KEV, NVD ranges, `data/vulndata.json`). Nessus built, not verified against a real instance.

### OT (operational technology)
`src/ot.rs` + `src/ot/` (4.1 added S7comm-plus, IEC 61850 MMS/ICCP over ISO, GOOSE, PROFINET IO,
OPC UA, CODESYS, and `stream.rs` for messages split across TCP segments), `src/scl/` (IEC 61850 SCL
import), `src/detect/goose.rs`, `src/web_ot.rs`. Passive only. **Done**; exercised by
`tools/ot-samples.sh` (pre-release step 9). IP fragments are not reassembled for OT decoding. Docs:
`docs/ot-guide.md`, **archive/OT_PROTOCOL_EXPANSION.md**.

### Multi-tenancy
`src/control.rs` (`TenantId`, `TenantRegistry`, `ControlStore`, its own `control.db`),
`src/engine/tenants.rs` (`TenantRuntime`, bounded-concurrency tenant loading, `TENANT_LOAD_CONCURRENCY = 8`),
`src/tenant_lifecycle.rs` (4.1: suspend/resume and MSP limits applied to a running install without a
restart), `src/ingest.rs` (`route_token`/`wrap_token`), `src/operator.rs` + `src/web_operator.rs`
(operator accounts across tenants), `src/web/isolation.rs` (the isolation suite, which reads the live
route table). **Storage model: one `Store` per tenant, a separate SQLite file per tenant
(`<data_dir>/tenants/<id>.db`)**, the pre-existing install being the implicit `default` tenant.
**Tenants and PostgreSQL do not mix**: `engine.rs` refuses to start with `--database-url` while tenants
besides `default` exist (audit F2-5; `tests/ha_two_process.rs` checks it). One data key for all
tenants (audit F6-5, planned 4.4). **Done** for SQLite. Doc: **archive/MULTI_TENANCY_HA.md**,
`docs/multi-tenancy.md`.

### MSP management (4.1, experimental)
Two older, separate features: `src/msp_relay.rs` (`--report-to`: relay a site's devices and alerts to
an MSP master) and agent backups kept for customers. New in 4.1, **remote management** of a customer's
own master by its MSP:

* `src/msp_channel/` (wire format: signed Ed25519 envelope, canonical JSON, nonce replay set, link
  codes, key rotation; opens no socket), `client.rs`/`exec.rs` (the customer side: long-polls the MSP
  and executes requests through its own router).
* `src/msp_hub.rs` (MSP side: per-customer queues and long-poll waiters on the ingest listener,
  `/api/v1/msp-channel/{hello,poll,reply}`; never connects anywhere, never executes).
* `src/web/remote_proxy.rs` + `remote_resolve.rs` (MSP side: serves a customer's console on its own
  portal host after a 60 s single-use handoff), `src/web/remote_policy.rs` (customer side, the gate:
  every route has a remote class Read/Configure/Admin/Enforce/Never, a missing route is Never and a test
  fails the build), `src/msp_grant.rs` (the grant, read fresh from the `msp_link` row on every request),
  `src/msp_made.rs` (accounts and automation opt-ins an MSP made are disabled when the link ends),
  `src/msp_notify.rs`, `src/web_msp_link.rs` (the customer's own API), `src/web_msp_admin.rs`,
  `src/msp_cmd.rs` + `src/msp_cli.rs` (`denis msp ...`, `denis msp-link ...`).
* `src/operator_mfa.rs`: operators' second factor (TOTP or passkey). Required for opening a remote
  customer and for changing the MSP's customer list; Admin and Enforce class requests need a proof from
  the last 10 minutes. Proof times are not persisted (a restart asks again).

Tested in-process and with real `denis run` processes (`tests/msp_management.rs`), not across real
customer networks. Docs: **archive/MSP_HIERARCHY_DESIGN.md** (the historical design; built),
**archive/MSP_SECURITY_REVIEW.md**, `docs/msp-management.md`.

### HA / leader election
`src/ha.rs` (311 lines: role marker for `/api/health`, the process lease and `may_act()`, which every
external side effect asks first: notifications, exports, cursors, NAC jobs, the MSP hub),
`src/store/pg/`'s `LeaderElection` (`pg_try_advisory_lock`, epoch, migration lock),
`src/engine/run.rs`'s `ha_wait_for_leadership`, `tests/ha_two_process.rs` (real two-process `kill -9`
failover test, gated on a PostgreSQL URL). **Built and measured on one machine** (failover about 1.9 s);
not measured across two machines. **No epoch fencing of database writes** (audit F2-1, now planned for 4.3 in ROADMAP.md):
side effects ask the in-process lease (`may_act`), but writes are not fenced by the leader epoch in the
database. Requires `--features postgres` and
`--database-url`; SQLite is never HA. Docs: **archive/HA_DESIGN.md**, **HA_DEPLOYMENT.md**.

### PostgreSQL store
`src/store/pg/` (one file per sub-trait, about 16,600 lines with tests) + `src/store/pg_stubs.rs` (despite its name
the PostgreSQL `DeviceMergeStore`, pulled in with `include!`). `tools/check-pg-release-gate.sh`, run on 2026-10-20:
**stubs 0, production references outside its files 4, "PostgreSQL store is complete: gate passed"**. Feature
`postgres`, off by default. The baseline is V35 and `PG_MIGRATIONS` carries V36 to V52 with the same numbers as SQLite
(`PG_LATEST_VERSION = 52`). **Done.**

### SQLite store
`src/store/sqlite/` (one file per sub-trait, about 14,700 lines with tests), the default backend.
Schema **V52** (`src/store/sqlite/migrations.rs`; each step in its own transaction; a database newer than the build is
refused). The 4.1 migrations: V44/V45 block suggestions (`nac_prompts`), V46 Autopilot tables, V47 the enforcement
action columns, plans, steps and per-action permissions (with a data step granting existing
administrators all five), V48 `msp_link` (the customer side of the MSP link). An upgrade from 4.0.2
(V43) runs V44 to V48 in one start (`tests_v48.rs`). **(4.2)**, all additive: **V49** `device_links`,
`identity_suggestions`, `device_integrations` (data step: every existing `merged_into` becomes a `manual_legacy` link,
chains re-pointed to their root, dangling ones cleared); **V50** `notifications`, `notification_reads`,
`notification_cursor`; **V51** `policies.response`, `nac_prompts.prepared`/`snoozed_until`/`rule_kind` and the table
`nac_rule_trial` (data step: an existing automatic mark stays live, an existing "offer to block" becomes "prepare for
approval"); **V52** three indexes only. `repair_renumbered_v49` repairs a lab database from a build that numbered the
notification tables V49 (no released database is affected). **V53** one index; **V54** (4.3) the `api_tokens` columns `scopes`, `expires_at`, `rotated_from`, `last_used_from`, `acts_as_id` (all NULL for an existing token, so nothing changes yet). Upgrade tests: `tests_v49.rs`,
`tests_v51.rs`, and the PostgreSQL upgrade test in `store/pg/tests/upgrade_backup_tests.rs`. **Done.**

### Secrets / encryption
`src/secrets.rs`: every credential in `SECRET_KEYS` (and per-instance connector secrets
`"{name}.{instance}"`) as AES-256-GCM under a data key in `secrets.key` (outside the database), left
out of backups by default (the PostgreSQL backup leaves them out the same way). One data key for the whole install,
all tenants included (F6-5). **Not covered by it:** password hashes (hashed by `auth.rs`) and TOTP seeds, which are
stored in the database file as the code writes them; that file is created owner-only (mode 0600). **Done** for the
integration credentials. Doc: `archive/secret-storage-options.md` (option B, built).

### Backups
`src/backups.rs`: manual or scheduled, per tenant, secrets excluded by default. **Done.**

### Licensing
`src/license.rs`, `src/license_key.rs`, `src/license_alerts.rs`; `COMMUNITY_DEVICE_CAP = 100`;
vendor-only `src/bin/license_issuer.rs` and `src/bin/license_portal/`, never shipped. The cap is not
yet counted across tenants. **Done.**

### Web API
`src/web/mod.rs` (the middleware pipeline: `remote_resolve` -> `tenant_resolve` -> `guard` ->
`authn`, plus the MSP `remote_gate` for channel requests), `src/web/routes.rs` (`pub fn router`, about
390 `.route(` calls), `src/web/policy.rs` (`is_public`, `required_role`, the `hand_role_table` /
`required_role_table` tests), `src/web/common.rs` (`AppState`, tenancy context, `ApiError`, the 404
for "not yours"), 52 `src/web_*.rs` handler modules, and `src/web/tests/` (authorization matrix,
route policy, MSP remote tests read the router source so a new route cannot be forgotten). **Done.**

### Console UI
`ui/`: plain JS, **no bundler**, 44 `.js` files in `ui/` (41 `<script>` tags in `index.html`, loaded in order),
embedded via `RustEmbed`. New in 4.1: `enforcement-*.js`/`enforcement.css`, `autopilot*.js`, `protectme.js`,
`msp-customers.js`, `msp-manage.js`, `rule-dialog.js`, `inbound.js`, `quiet.js`, bundled fonts, a
service worker and manifest for the Autopilot phone page. New in 4.2: `capture.js` (Settings -> Capture),
`notifications.js` (the bell), `rule-response.js` (what a rule does), `wiring.js` (the map's cables). The
client-side `can(role)` check is UX only.
**Done.** Browser tests: `tools/ui-smoke*.mjs` and friends.

### Autopilot (4.1, experimental)
`src/autopilot/` (about 17,900 lines with tests): deterministic triage (`cluster`, `triage`, `options`,
`refuse`), the AI layer (`input`, `ai`, a closed answer schema), proposals with single-use approval
tokens (`token`), the executor (`execute`, imports no `nac*` module, a test pins it), delivery
(`deliver`, `push` for Web Push, `telegram`, `ntfy_reply`; started by `engine.rs` and tested against
local simulations of each service), phones and pairing, briefing and the shadow-mode report, the replay
tool (`denis autopilot-replay`). Off by default, shadow mode first. Blocking only through level (c)
above (`enforce.rs`). Web: `src/web_autopilot.rs`, `src/web_autopilot_phone.rs`. Docs:
**archive/AUTOPILOT_DESIGN.md** (the historical design; built; wording rules now in `tools/WORDING_RULES.md`), `docs/autopilot.md` (current).

### AI features
`src/ai.rs` (5 providers: Claude, OpenAI, Gemini, Grok, local OpenAI-compatible), `src/ai_summary.rs`,
`src/ai_usage.rs`, `src/incident_ai.rs`, `src/incident_text.rs`, `src/web_ai.rs`. Advisory only.
**Done.** Doc: **AI.md** (read its Status section).

### Notifications
`src/channels.rs` (`KINDS`: Slack, Teams, Discord, PagerDuty, Pushover, ntfy, Telegram, email, webhook,
Jira, ServiceNow: **11 kinds**), `src/notify.rs`, `src/notify_policy.rs`. **Done.**

### Notification centre (4.2)
`src/notice.rs`, `src/store/{sqlite,pg}/notices.rs` (the `NoticeStore` trait), `src/web_notifications.rs`,
`src/msp_notify.rs`, `src/channels/content.rs`, `ui/notifications.js`. Every operational message (an enforcement action
applied, released, extended, expired, failed or unconfirmed; something done automatically; a capture interface down and
back; an agent offline; an update; a rule's response demoted; an MSP session) is **one row** in `notifications` written
by `notice::raise`. The bell in the console reads those rows and the channel dispatcher (`channels::Dispatcher`, the job
`channels`) sends them, so both say the same thing and one dedup rule (a repeat of the same key inside its window only
counts up) applies. `notice::deliver` claims pending rows one at a time (`pending` -> `sending`; a row whose sender died
is claimed again after 5 minutes: at least once, rarely twice), sends each once per channel and records `sent`,
`partial`, `failed`, `skipped` (maintenance) or `none`. "Loud" notices (enforcement, MSP remote session) go to every
enabled channel whatever its filters and are not capped; the others respect the channel's minimum score, maintenance
mode, a device's mute date and a cap of 30 per channel per 10 minutes. On an HA standby nothing is sent. Read state and
muted categories are per person (`/api/notifications*`, filtered on the server by role, audience and site grants);
the `msp` category cannot be muted. Rows are kept 90 days (an open condition is kept), at most 50,000. Tests: `notice.rs`
(`mod tests`), `web/tests/notifications_tests.rs`, `tools/notifications-test.mjs`.

### Rule actions (4.2, experimental)
`src/rule_response.rs`, `src/nac_propose.rs`, `src/nac_prompts.rs`, `src/web_rule_response.rs`, `src/nac_auto.rs`,
`ui/rule-response.js`, schema V51. Every zone policy, allow list, IT rule and OT rule carries one setting,
`policies.response`: `notify` (default: an alert, nothing else), `propose` (a match prepares a response that waits for a
person in the normal plan dialog; `nac_propose` chooses the connector by the device's path and never prepares for
DENIS itself, infrastructure, industrial devices (except the sender of an OT rule) or hands-off devices) and `auto`
(experimental: a trial of at least 7 days, at least 3 "would have acted" records, at least 90 % agreement among the
judged ones and no "wrong device" judgement in the last 7 days, recorded in `nac_rule_trial`; then the password and the
typed phrase make it live, and it acts only through `nac_auto` behind every gate automation already has). No OT rule
ever acts by itself in 4.2. `auto_enforce` stays the single source of truth for automatic actions; every content edit of a
rule, a vanished connector, an ended MSP link or a lost permission demotes `auto` to `propose` with an audit entry and
a notice (`rule_response::reconcile`). Routes: `PUT /api/policies/{id}/response`, `POST /api/policies/response-preview`,
`POST /api/policies/{id}/response/go-live`, `GET /api/nac/rule-trials`, `POST /api/nac/rule-trials/{id}/judge`. Tests:
`rule_response.rs` (`mod tests`), `nac_auto_trial_tests.rs`, `web/tests/rule_response_tests.rs`,
`tools/rule-response-test.mjs`. Status: tested in simulation; no rule has gone live on a real network.

### i18n
`ui/i18n.js`, `ui/i18n/{de,fr,es,sk}.json` (generated), `tools/i18n/*.tsv` (185 source files, 5
columns), `tools/i18n/build.py`. Run on 2026-10-13: **6,382 strings x 4 languages, 0 untranslated**.

### Reporting
`src/report.rs`, `src/reports.rs`, `src/web_reports.rs`. **Done.**

### Auth / SSO / passkeys / TOTP
`src/auth.rs`, `src/sso.rs` + `src/web_sso.rs` (OIDC), `src/passkey.rs` + `src/web_passkey.rs`,
`src/totp.rs` + `src/web_totp.rs`, `src/access.rs` (per-site grants), `src/operator_mfa.rs` (operators,
above). **Done.** SSO and passkeys inside a non-default tenant's console are listed as not built in
`docs/multi-tenancy.md` (not re-checked in code for this pass).

### Supervision
`src/supervisor.rs`: every long-lived job is observed; a panic or unexpected return is recorded and
restartable jobs are restarted with backoff (Health page). **Done.**

## 2. Where to look

| Task | Start here |
|---|---|
| Add a NAC connector | a recent orchestrated module (`src/nac_mikrotik.rs`, `src/nac_asa.rs`) + `src/nac_registry.rs` (`ConnectorKind::ALL`, `wired()`) + its `CAPS` for `src/nac_action.rs::static_caps` + `src/nac_orchestrator.rs` (the `Connector` trait) + `docs/enforcement.md` and `tools/gen-enforcement-matrix.py` |
| Touch enforcement safety | `src/nac_orchestrator.rs`, `src/nac_guard.rs`, `src/nac_plan.rs`, `src/nac_lab.rs`, `src/nac_perm.rs`; the conformance tests in `src/nac_orchestrator_tests.rs` and `src/nac_orchestrator_action_tests.rs` |
| Touch automation / Autopilot blocking | `src/nac_auto.rs` (+ `nac_auto_tests.rs`, `nac_auto_ap_tests.rs`), `src/autopilot/enforce.rs`, `docs/enforcement.md#automation` |
| Add/modify a detection rule | `src/detect/` (the right family file) + `src/detect/kinds.rs` + `src/rules.rs` + archive/DETECTION_RULES_REVIEW.md; a rule reads device attributes (type, Purdue level, criticality, zone, site) only through `Detector::device_facts` and MACs only through `Detector::asset_id`, never a store query per window record (`src/detect/facts.rs`, "How a rule reads device attributes") |
| Add a web route | `src/web/routes.rs` (`router()`) + the handler module + `src/web/policy.rs` (`required_role`, and `hand_role_table` must agree) + a remote class in `src/web/remote_policy.rs`'s `TABLE` (the build fails without one) + `is_public()` if it must work pre-login |
| Add a store method | `src/store/mod.rs` (the right sub-trait) + `src/store/sqlite/<area>.rs` + `src/store/pg/<area>.rs` + a contract in `src/store/conformance.rs` (both backends call it) |
| Add a migration | `src/store/sqlite/migrations.rs` (next `V55`, and `SCHEMA_VERSION`) and the list in `SqliteStore::init` (`src/store/sqlite/mod.rs`) + `src/store/pg/migrations.rs` (a paired entry in `PG_MIGRATIONS`, and `PG_LATEST_VERSION`) + an upgrade test like `tests_v49.rs` / `tests_v51.rs` |
| Add a UI setting/string | the relevant `ui/*.js` + a line in the right `tools/i18n/*.tsv` + `python3 tools/i18n/build.py` + `--check` |
| Add a CMDB/cloud source | an existing one (`src/jamf.rs`, `src/aws_cloud.rs`) as the pattern + CMDB.md |
| Add a notification channel | `src/channels.rs` (`KINDS`) + `src/notify.rs` |
| Touch multi-tenancy routing | `src/control.rs`, `src/engine.rs`, `src/tenant_lifecycle.rs`, `src/ingest.rs`, `src/web/isolation.rs` |
| Touch MSP management | `src/msp_channel/`, `src/msp_hub.rs`, `src/web/remote_proxy.rs`, `src/web/remote_policy.rs`, `src/msp_grant.rs`, `src/operator_mfa.rs`, `tests/msp_management.rs`, archive/MSP_SECURITY_REVIEW.md |
| Touch device identity (which rows are one device) | `src/identity.rs`, `src/identity/evidence.rs`, `src/store/identity_repair.rs`, `src/web_identity.rs`; the guards read `identity::Groups` |
| Touch where a device is / which firewall is on its path | `src/location.rs`, `src/nac_path.rs`, `src/nac_scope.rs`, `src/web_nac_actions.rs` (`capabilities`) |
| Touch a notification or the bell | `src/notice.rs` (`raise`, `deliver`), `src/web_notifications.rs`, `src/channels.rs`, `ui/notifications.js` |
| Touch capture interfaces or monitored networks | `src/capture_supervisor.rs`, `src/subnets.rs`, `src/web_admin/capture.rs`, `src/engine/collector.rs` |
| Touch what a rule does when it matches | `src/rule_response.rs`, `src/nac_propose.rs`, `src/web_rule_response.rs`, `src/nac_auto.rs` |
| Touch the map, cables or the Equipment order | `src/topology_relations.rs`, `src/web_relations.rs`, `src/web_gateway.rs`, `ui/wiring.js` |
| Produce the SBOM / change the dependency policy | `tools/sbom.sh`, `tools/sbom-extra.json`, `deny.toml`, `.cargo/audit.toml`, `.github/workflows/dependency-audit.yml`, `docs/compliance/` |
| Touch HA/leader election | `src/ha.rs` (`may_act`), `src/store/pg/`'s `LeaderElection`, `src/engine/run.rs`'s `ha_wait_for_leadership`, `tests/ha_two_process.rs`, archive/HA_DESIGN.md / HA_DEPLOYMENT.md |
| Cut a release | `tools/pre-release.sh` (steps 0-9) + RELEASING.md (including "What we learned from 4.1.0") |
| Sync the public repo | `public-repo/README-FIRST.txt` (manual) |

## 3. Data model and the Store trait family

Core types live in `src/model.rs` (`Asset`, `Event`, `Policy`, `User`, ...).

The **Store trait family** (`src/store/mod.rs`, 2,796 lines) has 27 data sub-traits: `AssetStore`,
`EventStore`, `MetricStore`, `SettingsStore`, `IpCacheStore`, `CmdbStore`, `VulnScanStore`,
`FindingStore`, `EdgeStore`, `DnsStore`, `TopoStore`, `NacStore`, `ConnStabStore`, `PostureStore`,
`ReportStore`, `CaseStore`, `IncidentStore`, `AuthStore`, `WorkItemStore`, `DeviceMergeStore`,
`SegmentationStore`, `AdminStore`, `MspLinkStore` (4.1), `AutopilotStore` (4.1), `PromptStore`, `IdentityStore` (4.2),
`NoticeStore` (4.2), plus
`StoreIdentity` (a never-reused instance id, used by `nac_guard` to key per-tenant process state),
composed into the umbrella `Store` trait that handlers and jobs take as `Arc<dyn Store>`.

**Two implementations**: `src/store/sqlite/` and `src/store/pg/`, both split by area, both at schema
V52. Parity is kept by `src/store/conformance.rs` (4,108 lines; SQLite runs it always, PostgreSQL in
`src/store/pg/tests.rs` and `src/store/pg/tests/` when `DENIS_TEST_DATABASE_URL` is set) and by the release gate script.

**Multi-tenancy's storage model**: one `Store` instance per tenant, a SQLite file per tenant; no
`tenant_id` multiplexing. PostgreSQL serves one tenant (the HA case) and is refused at start with
other tenants present (F2-5).

**Enforcement state** lives in `nac_actions` (the ledger, one active action per physical target,
enforced by a unique index), `nac_plans`, the step records and `nac_prompts`; automation state in the
`nac.automation` setting; the MSP link in `msp_link` (`id = 1`, one link per customer in phase 1). **(4.2)**
Device identity in `device_links` / `identity_suggestions` / `device_integrations`; notices in `notifications`
(+ read state); a rule's response in `policies.response` and its trial in `nac_rule_trial`.

## 4. Build and release mechanics

`tools/pre-release.sh` runs 10 steps (0/9 to 9/9, checked 2026-10-20), stopping at the first failure: the commit to tag
(HEAD, clean, pushed, tag free) -> version consistent with CHANGELOG.md (and
`check-release-notes.sh`) -> unit and integration tests -> clippy `-D warnings` and
`check-pg-release-gate.sh` -> translations -> installer syntax and dry run -> release build -> console
in a real browser -> database of the newest published release opens -> OT decoders on real
captures. It prints the `git tag`/`git push` commands; **it does not run them**.

**CI and Release workflows** (`.github/workflows/ci.yml`, `release.yml`): the test build of `denis` is
given capture rights with `tools/ci-allow-capture.sh` between `cargo test --no-run` and `cargo test`
(`tests/msp_management.rs` starts a real `denis run`). Linux runners use `CARGO_BUILD_JOBS=2` and swap;
the ARM64 Linux build does **not** run the tests (the 8 GB runner was shut down while compiling them); in
`release.yml` only the Apple-silicon build runs them (how the others are covered: RELEASING.md).
`install.sh` is `packaging/install.sh` copied into the release and **is** in `SHA256SUMS` (the list that
`SHA256SUMS.sig` signs, with the programs), so it can be checked before it runs as root. Details and the local
container recipe: RELEASING.md, "What we learned from 4.1.0".

**(4.2) Supply chain.** `tools/sbom.sh` writes a CycloneDX 1.6 and an SPDX 2.3 JSON SBOM from `Cargo.lock`
(`cargo-sbom`, pinned) plus the libpcap and musl that the static builds embed (`tools/sbom-extra.json`); the job `sbom`
of `release.yml` runs it and the release job attaches the two files and `SBOM.sha256` (they are deliberately **not**
in `SHA256SUMS`: `update_mirror::release_from_dir` treats every `denis-*` entry of that list as a program). **That CI
job has not run yet**; only `tools/sbom.sh` was run by hand. `.github/workflows/dependency-audit.yml` runs `cargo
audit` and `cargo deny check` daily and on demand (also **not yet run on GitHub**) and `ci.yml` has a `deny` job; the
accepted advisory RUSTSEC-2023-0071 is listed in `.cargo/audit.toml`, `deny.toml` and the `ci.yml` audit input and
must be changed in all three. Customer-facing: `docs/compliance/SBOM.md`; the readiness document is
`docs/compliance/CRA.md`.

**Generated docs**: `python3 tools/gen-enforcement-matrix.py --check` keeps the capability matrix in
`docs/enforcement.md` in step with the code; `bash tools/check-wording.sh` checks wording rules;
`cargo test --lib docs` checks the in-app docs and their menu.

**Public-repo sync**: manual, `public-repo/README-FIRST.txt` (pinned to 4.1.3 at the time of writing, so
`public-repo/` is behind `docs/` until the 4.2 release pass).
No script or workflow pushes to the public repo.

**Versioning**: `Cargo.toml` `4.1.4` (tag `v4.1.4`); `CHANGELOG.md`'s top section is `4.2.0: Unreleased`, so the
version and the changelog differ on purpose until the release pass.

## 5. Known stale or conflicting docs

Checked on 2026-10-14 for 4.1.2. **The historical designs, reviews and plans are now in `archive/`**
(list and reasons in `archive/README.md`), each with a header that names the version it was written for, says
it is not maintained, and points to what is current. Their names are unchanged, so the hundreds of code comments
that cite them (for example "PASSIVE_DNS.md section 4") still find them with a search. That includes the files
this list used to call stale: ENFORCEMENT_ACTIONS_DESIGN.md, MSP_HIERARCHY_DESIGN.md, AUTOPILOT_DESIGN.md (its
wording rules moved to `tools/WORDING_RULES.md`), POLICY_TRIGGERED_ENFORCEMENT.md, DETECTION_RULES_REVIEW.md,
OT_PROTOCOL_EXPANSION.md, ALERT_NOISE_REDUCTION.md, MULTI_TENANCY_HA.md, the 4.1.0 code reviews
`CODE_REVIEW_A_*.md` to `CODE_REVIEW_F_*.md` (each with a Status section; the items still open are listed in
ROADMAP.md under 4.1.2) and `secret-storage-options.md`. ROADMAP.md was split: the current plan stays, the
history (items 1 to 36, the 3.5.0 review and UX review triage) is `archive/ROADMAP_HISTORY.md` under the same
item numbers and IDs. Five finished work files were deleted (DOCS_AUDIT, PUBLIC_REPO_SYNC_PLAN,
PUBLIC_ROADMAP_DRAFT, WEBSITE_UPDATE_FOR_4_1, UPDATE_WORDING_FOR_WEBSITE; git history has them).

Status headers corrected in the live internal docs: NAC.md (twenty connector kinds on one action path),
POST_4_1_ARCHITECTURE.md (what 4.1 built, the rest is the 4.2 to 5.0 plan), NAC_HARDWARE_VALIDATION.md (still a plan
for 4.2).

Fixed on 2026-10-20: the module comment of `src/ipv6.rs` (it said no IPv6 traffic reaches userspace); the comment
above `SqliteStore::open_writer` (it said integration credentials are plaintext rows; they are sealed, `secrets.rs`);
`store/pg/mod.rs` (it said PostgreSQL was not wired in) and the "not yet built" notes on `DeviceMergeStore`.

Still stale:

1. **`NAC_HARDWARE_VALIDATION.md`'s status header** was last rewritten for 4.1.2 and says "nothing here has been run";
   later bench notes are in the same file (a MikroTik, a FortiGate, a Cisco Catalyst, a PA-220) and the matrix row
   wording says what was and was not tested. Read the notes, not the header.
2. **Comments in code** that cite an archived design by section describe the design, not necessarily the code
   as it is now; the code wins.
3. **`public-repo/`** is a copy synced by hand at a release; it differs from `docs/` and `README.md` now.
4. **The user docs under `docs/` and `public-repo/`** are being reconciled for 4.1.2 separately (the overview
   texts in `README.md`, `docs/index.md` and `docs/segmentation.md`, and the pages that name internal files
   "in the repository"); see DOCS_INVENTORY_4_1_2.md.

**Living, trustworthy as current status**: ROADMAP.md, NAC.md (status at the top and the safety model),
POST_4_1_ARCHITECTURE.md (as the 4.2+ plan), NAC_HARDWARE_VALIDATION.md (as the plan), WINDOWS.md, IPV6.md,
CMDB.md, SSO.md, AI.md, HA_DEPLOYMENT.md, TUNNEL_VERIFICATION_PLAN.md, `tools/WORDING_RULES.md`, and the user docs
under `docs/` (security.md, multi-tenancy.md, autopilot.md, enforcement.md and deployment.md were re-checked against
code on 2026-10-13).

## 6. Scale facts

Measured on 2026-10-20 on `main` (4.2.0 in development) with `find`, `wc -l` and `grep -c`; earlier figures are in
the git history of this file.

- Rust: **about 474,000 lines across 731 files** in `src/` (tests included)
- Console UI (plain JS, no bundler): **about 24,200 lines across 44 `.js` files** in `ui/`
- Tests: **4,748** `#[test]`/`#[tokio::test]` annotations across `src/` + `tests/` (counted, not run here)
- Root-level `.md` files: **25**
- `docs/` (in-app help, embedded): **52** `.md` files including `docs/nac/` and, new, `docs/compliance/` (not pages of the
  help menu)
- Current version: **4.1.4** (`Cargo.toml`); 4.2.0 is unreleased
- Schema: **V52** on SQLite and PostgreSQL (V49 to V52 are 4.2)
- NAC connector kinds: **20**; capabilities validated on real equipment: **2** (SNMP port disable, SNMP quarantine by VLAN)
- Enforcement action types: **5**; automation levels: (a) manual, (b) rules, (c) Autopilot, (b) and (c)
  experimental and off by default
- CMDB/cloud/endpoint sources sharing `cmdb_devices`: **8**, none verified against a real tenant
- AI providers: **5**; notification channel kinds: **11**
- Languages: **4 translated** + English, **6,382 strings** per language
- Store sub-traits: **27** data traits plus `StoreIdentity`; **2 backends**, PostgreSQL at 0 stubs
