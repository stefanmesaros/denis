# Enforcement

<!-- enforcement-experimental -->
**Most of enforcement is experimental.** Apart from switching one switch port off over SNMP, which has been tried on one
real switch, every action DENIS can take on your network has been tested only against a local simulation of the vendor's
documented interface. None of it has been tried against real firewalls, cloud accounts or hypervisors. An action can cut a
device off from your network, and a mistake in your own quarantine setup can cut off more than you meant. Try each
connector first on a device you can afford to lose, and release it to check the way back.
<!-- /enforcement-experimental -->

Enforcement is the part of DENIS that changes something on your network: it blocks a device, quarantines it, switches a
switch port off or ends its sessions. Everything else in DENIS only looks. Enforcement is **off by default**, it works only
through equipment you have connected on purpose, and every action is one signed-in administrator's decision, shown to them
in full before it happens and recorded afterwards.

This page explains how enforcement works, what each action does and does not do, what you must prepare on your side, and
what is available today. The setup of each device type is on its own page, listed at the end.

*Checked against the code on 2026-10-13, after the last vendor package was merged.*

## What is available today

* **Switch ports over SNMP.** Disabling a port is validated on one real switch. See [Switches](switches.md#disabling-a-port).
* **Blocking, quarantine and ending sessions through the connectors** (firewalls, UniFi, Meraki, AWS, Azure, NSX-T,
  Hyper-V, Proxmox, RADIUS Disconnect), each with the connector's own **Block** button under *Settings → Enforcement*. All
  of these are simulator only.
* **The general path** with plans, durations, expiry, per-action permissions, a ledger and an API
  (`/api/nac/actions/...`) is built on the server, and **all twenty connectors are on it now** (flow blocks, quarantine,
  ending sessions and, where the device has them, port actions; simulator only, except the SNMP port disable). In the
  console it is reached through the **Respond...** menu of a device, an incident or a flow, which opens the plan dialog
  (see [The plan dialog](#the-plan-dialog)), and through the API.

## Capability matrix

*Written from the capability tables in the code (`CAPS` in each `src/nac_*.rs`) by `tools/gen-enforcement-matrix.py`; a test fails when the table below differs from what the generator writes.* The states:

* **Built**: the code exists and has been validated on real equipment.
* **Experimental**: the code exists and has been tested only against a simulation. It needs the lab switch.
* **Not built**: the connector does not do this yet in this version.
* **Unsupported**: the device or its interface cannot do this honestly, so DENIS does not offer it. It is shown as
  unavailable and never faked.

Each cell also names the method, DENIS's name for how the action is done. Where a connector has two methods for one action
(MikroTik and Meraki quarantine), both are listed with their own state. "Built" and "Experimental" mean the code exists. A
connector that has been moved onto the plan and apply path (see *What is available today*) offers its Experimental actions
through that path; for the others, a vendor's existing action is reached through the connector's own Block button.

<!-- matrix:begin -->

| Connector | Block device | Block flow | Quarantine | Disable port | End sessions |
|---|---|---|---|---|---|
| [SNMP switch ports](nac/snmp.md) | Unsupported | Unsupported | Experimental: `access_vlan` | Built: `if_admin_status` | Unsupported |
| [Fortinet FortiGate](nac/fortigate.md) | Experimental: `address_group` | Experimental: `deny_rule` | Experimental: `quarantine_group` | Unsupported | Experimental: `session_clear` |
| [Palo Alto PAN-OS](nac/paloalto.md) | Experimental: `address_group` | Experimental: `deny_rule` | Experimental: `quarantine_group` | Unsupported | Experimental: `session_clear` |
| [OPNsense](nac/opnsense.md) | Experimental: `alias` | Experimental: `deny_rule` | Experimental: `quarantine_alias` | Unsupported | Experimental: `state_kill` |
| [SonicWall](nac/sonicwall.md) | Experimental: `address_group` | Unsupported | Experimental: `quarantine_group` | Unsupported | Unsupported |
| [Check Point](nac/checkpoint.md) | Experimental: `group` | Experimental: `deny_rule` | Experimental: `quarantine_group` | Unsupported | Unsupported |
| [Juniper SRX](nac/juniper.md) | Experimental: `address_set` | Experimental: `deny_rule` | Experimental: `quarantine_set` | Unsupported | Experimental: `session_clear` |
| [WatchGuard Firebox](nac/watchguard.md) | Experimental: `blocked_sites` | Unsupported | Unsupported | Unsupported | Unsupported |
| [MikroTik RouterOS](nac/mikrotik.md) | Experimental: `address_list` | Experimental: `deny_rule` | Experimental: `quarantine_list`; Not built: `access_vlan` | Experimental: `ethernet_disable` | Experimental: `conntrack_remove` |
| [Ubiquiti UniFi](nac/unifi.md) | Experimental: `block_sta` | Unsupported | Experimental: `port_profile` | Experimental: `port_disable` | Experimental: `kick_sta` |
| [Cisco Meraki](nac/meraki.md) | Experimental: `client_policy_blocked` | Unsupported | Experimental: `group_policy`; Not built: `access_vlan` | Experimental: `port_disable` | Unsupported |
| [Cisco ASA](nac/asa.md) | Experimental: `object_group` | Experimental: `deny_rule` | Experimental: `quarantine_group` | Unsupported | Experimental: `clear_conn` |
| [Cisco FTD via FDM](nac/ftd_fdm.md) | Experimental: `network_group` | Experimental: `deny_rule` | Experimental: `quarantine_group` | Unsupported | Unsupported |
| [Cisco FTD via FMC](nac/ftd_fmc.md) | Experimental: `dynamic_object`, `network_group` | Experimental: `deny_rule` | Experimental: `quarantine_dynamic_object`, `quarantine_network_group` | Unsupported | Unsupported |
| [VMware NSX-T](nac/nsx.md) | Experimental: `dfw_group` | Experimental: `deny_rule` | Experimental: `quarantine_group` | Unsupported | Unsupported |
| [AWS Security Groups](nac/aws.md) | Experimental: `isolation_sg` | Unsupported | Experimental: `security_group_swap` | Unsupported | Unsupported |
| [Azure NSGs](nac/azure.md) | Experimental: `isolation_nsg` | Experimental: `deny_rule` | Experimental: `nsg_swap` | Unsupported | Unsupported |
| [Microsoft Hyper-V](nac/hyperv.md) | Experimental: `port_acl_deny_all` | Experimental: `deny_rule` | Experimental: `access_vlan` | Experimental: `vnic_disconnect` | Unsupported |
| [Proxmox VE](nac/proxmox.md) | Experimental: `vm_firewall_drop` | Experimental: `deny_rule` | Experimental: `quarantine_ipset` | Experimental: `link_down` | Unsupported |
| [RADIUS CoA](nac/radius_coa.md) | Unsupported | Unsupported | Unsupported | Unsupported | Experimental: `radius_disconnect` |

Of the 100 cells (20 connectors, 5 actions; a cell with two methods counts by its best one): 1 is Built, 62 Experimental, 0 Not built and 37 Unsupported.
20 of the 20 connectors have code for at least one action.

<!-- matrix:end -->

Why a cell says Unsupported, in short:

* **A firewall, SRX, NSX-T or a cloud service has no access port**, so *Disable port* is not offered. A cloud instance has no
  switch port either.
* **A switch** cannot block one device on a port and exposes no traffic filtering through the standard tables DENIS uses;
  switching a port off and on does not end one device's sessions.
* **AWS** security groups only allow traffic, so they cannot hold a deny rule.
* **Meraki** replaces the whole MX firewall rule list in one call, and DENIS does not rewrite rules it does not own. Meraki
  documents no way to end a session.
* **WatchGuard** Blocked Sites works per address only, and offers no group an administrator can reference through the
  interface DENIS uses.
* **RADIUS** Disconnect ends a session and is not a block, RADIUS cannot filter traffic, and a CoA quarantine is applied
  again by the RADIUS server at the next sign-in, so real quarantine belongs in your policy server.
* Where the interface offers no session end (SonicWall, Check Point, FDM, FMC, NSX-T, Hyper-V, Proxmox, AWS, Azure), *End
  sessions* is not offered.

## Settings for flow blocks on a connector

A connector that can block one flow with a deny rule has two more settings in its form (under Safety):

* **At most this many DENIS deny rules** (`max_managed_rules`, default 50, from 1 to 1000). DENIS refuses a new flow block (code `max_rules`) when it already manages that many rules on this connector. Releasing a block frees a place.
* **Networks this firewall routes between** (`routed_networks`, a list of networks such as `10.0.0.0/24`; only on firewalls that sit in the path of the traffic: MikroTik, FortiGate, PAN-OS, OPNsense, Check Point, Juniper SRX, ASA, FDM and FMC). When it is set, and a device of the flow is in none of the listed networks, the plan shows a warning that the rule may never see this traffic. Empty means DENIS says nothing about the path. Hyper-V, Proxmox, Azure and NSX-T do not have it: their rule is enforced at the device or the group itself, whichever way the traffic is routed.

Where the rule goes is not a setting: every connector puts its rule first (at the top of the policy, the layer or the access list you name in its form, or with the highest priority the device allows), because a deny rule below an allow rule does nothing.

## Troubleshooting

When DENIS refuses, the plan lists each refusal with a code. The common ones:

| Code | What it means and what to do |
|---|---|
| `enforcement_off` | The kill switch is off. An administrator switches it on under *Settings → Enforcement*. |
| `needs_lab` | A lab switch is missing. The text names which one. |
| `needs_config` | The connector needs a setting first, for example the quarantine group or VLAN. Set it in the connector's settings. |
| `needs_rule_opt_in` | Flow blocks need *Allow DENIS to create deny rules* on this connector. |
| `paused`, `not_wired` | The connector is paused (resume it under *Settings → Enforcement*) or cannot act yet in this version. |
| `not_built`, `unsupported` | See the matrix. The text of `unsupported` says why. |
| `not_orchestrated` | The connector is not on the plan and apply path. No connector in this version answers it any more; it stays for a connector added later. |
| `nac_permission` (HTTP 403) | Your account lacks the permission of this action. An administrator grants it under *Users*. |
| `unknown_capability` | The connector has no such method for this action. |
| `reason`, `duration` | The reason must be 3 to 200 characters. The duration must be 5 minutes to 365 days, in whole minutes, or permanent. |
| `target_kind`, `target` | The action does not fit the target (a device, a flow or a port), or the request names no usable address. |
| `own_session`, `protected` | The target is your own address, or DENIS, the gateway, a DNS or directory server, a protected address or a virtual router address. This never changes. |
| `site`, `egress` | The target belongs to another site than the connector, or the tenant is not allowed to reach this address. |
| `port_class` | DENIS acts only on an access port. It refuses a trunk, an uplink, a port-channel member, a management port, or a port whose kind it cannot tell. |
| `conflict` | Another DENIS action is already active on this target. Release it or extend it. |
| `max_rules` | The connector already holds the most DENIS rules allowed (50 by default). |
| `cap_reached` | The hourly limit is used up. Wait, or raise it under *Settings → Enforcement*. |
| `same_subnet`, `no_endpoint_here` | Flow refusals, explained under *Block a flow*. |
| `no_effect`, `effect`, `observe` | The connector could not say what it would change or undo with, so DENIS will not act. |

Other situations:

* **`unconfirmed`.** DENIS did not get a clear answer. Use the action's *check* (or *Check now* on a switch port) to read the
  device back. A confirmed change stays active; one that is gone becomes `restored_elsewhere`.
* **`rollback_failed`.** DENIS could not undo it, and it is still in force. DENIS retries on its own; you can retry now or,
  if you removed it on the device yourself, mark it resolved by hand (the password is needed). Look at the device and at the
  action's steps before doing either.
* **An orphan is listed.** An object named `denis-...` on a device is not accounted for. Check that it really is DENIS's,
  then remove it through the API.
* **Drift (`restored_elsewhere`).** Someone changed the device by hand, or it restarted. DENIS does not reapply. Start a new
  action if you still want it.
* **A repeated request.** A request sent twice returns the first answer with `"replayed": true` and does not touch the device
  a second time.

More general help is on the [Troubleshooting](troubleshooting.md) page.

## Automation

**Highly experimental. Off by default.** Automation means DENIS blocks or quarantines a device without asking anyone.
There are three levels:

* **Level (a), nothing.** This is how DENIS works until you change it. A person plans, confirms and applies every action.
* **Level (b), automatic enforcement by rules.** A policy that you mark for it can block or quarantine a device by itself
  when the device keeps breaking that policy. No AI is involved: the rule is the one you wrote.
* **Level (c), Autopilot may block.** Even more experimental, and a separate switch under level (b): it needs level (b) on,
  its own warning, the typed phrase **LET AUTOPILOT BLOCK**, your password, Autopilot active after its shadow period, at
  least 7 days of "would have blocked" records of which at least 10 were judged by a person and 95 % agree. Autopilot then
  may quarantine (or block) one ordinary device for at most 24 hours when a rule or detector reports a high severity
  finding. It never acts on the model's opinion alone, never on OT or infrastructure devices, and everything goes through
  the same path, limits, kill switch and audit as any action. See [Autopilot may block](autopilot.md#autopilot-may-block-experimental).

### Switching level (b) on

*Settings → Enforcement → Automation (Experimental)* has one switch. Switching it on needs, all together:

* a signed-in administrator who may act on the network (not an API token, not `--insecure-no-auth`, not an account limited to
  some sites) and who holds the permissions to block a device **and** to quarantine;
* the administrator's password again;
* the typed phrase **AUTOMATIC ENFORCEMENT** (capitals do not matter, spaces around it do not matter, anything else is refused);
* both lab switches (connectors not validated on real equipment, and new actions of 4.1) and the enforcement switch on.

Switching it **off** is one click for any administrator, without a password. It also switches level (c) off. Actions that are
already running keep their end time and can be released at any time.

### Marking a policy

Switching automation on does nothing by itself. A policy takes part only when an administrator marks it: the action (block
the device or quarantine it), the connector and its method, and the longest time the action may last. Marking needs the
password and the permission of the action. The policy must also offer to block devices that violate it (see
[Zones and policies](segmentation.md)). **Every edit of the policy clears the mark.** After an edit the policy needs a new,
deliberate mark, because what you approved was the policy as it was.

### What DENIS does by itself, and what it never does

When a marked policy produces a block suggestion, DENIS builds the same plan a person would see and applies it through the
same path, with the rule as the actor:

* **Time-limited, always.** The action lasts the shortest of the policy's time, the longest automatic time you set and
  7 days. The default is 1 hour. An automatic action is never permanent.
* **No warnings.** If the plan has any refusal or any warning, nothing is done and the suggestion stays open for a person.
  DENIS tells you "Automatic enforcement skipped" and why.
* **Limits.** Automatic actions count against the hourly limit of all enforcement, and against their own limit (1 to 10 per
  hour, default 3). One policy can cause at most 2 per hour. A device gets at most one automatic action in 24 hours, even if
  you undid the first one. A flood of alerts cannot go beyond these limits.
* **Fresh and after the mark.** Only a violation seen in the last 15 minutes, and after the policy was marked, can trigger it.
* **Never on** DENIS itself, the gateway, industrial (OT) devices, or network and server infrastructure (routers, switches,
  firewalls, access points, servers). The guards that apply to everyone also apply here: uplinks, trunks, management ports
  and the addresses on your "never block" lists.
* **Checked again every time.** The administrator who switched automation on must still exist, still be an enabled
  administrator without a site limit and still hold the permission. If not, automation stops itself, says so on every
  notification channel and writes `nac.automation.suspended` to the audit log. A lab switch switched off does the same. The
  enforcement switch off stops it without suspending it.
* **Leader only.** On a cluster only the leader acts. DENIS cannot yet fence a leader that lost its lease, so treat
  automation on a cluster with extra care.

### Undo

Every automatic action is announced on every notification channel (high severity, never filtered) with the device, the
policy, the end time and an **Undo** link: `<public address>/#/enforcement/action/<id>?undo=1`. The link only opens the
console. Nothing changes until you press **Undo** there, signed in, so a mail or chat link preview cannot undo anything. Undo
is an ordinary release through the same path (it works with enforcement switched off, and needs the permission of the action).
A link names one action, and works once.

### Level (c): letting Autopilot block

Under "Let Autopilot block" in the same box. The switch is greyed out until every line above it says *Yes*. It is audited as
`nac.automation.autopilot` (on, off, who, the typed phrase, the agreement figures), `nac.automation.autopilot.run` for each
block, `nac.automation.autopilot.refused` for each refusal (including a refused suggestion of the model), and
`nac.automation.suspended` when it stops itself. Autopilot blocks are in the ledger as actor `autopilot`, with the decision as
the origin. They count against the hourly limit of all enforcement and against the automatic limit of level (b); on top,
Autopilot may do 2 an hour, 6 a day and one per device in 3 days, and never for more than 24 hours. Switching level (b) off
switches level (c) off in the same write.

### Audit

Switching on or off, every limit change, every skipped suggestion and every automatic action is in the audit log:
`nac.automation.rules`, `nac.automation.rules.run` (with the policy id and revision), `nac.automation.rules.skipped`,
`nac.automation.suspended`, `policies.auto_enforce`, and the action itself as `nac.<connector>.<action>` by `rule:<policy id>`.

## The plan dialog

Every action starts as a plan. The dialog says in one sentence what DENIS would do, lets you choose the connector and the
duration, lists what it would cut off, shows every refusal and warning, and asks for your reason and your password.
Nothing changes on a device until you press Apply.

![The plan dialog for blocking one flow](img/enforcement-plan.png)

## Active responses

*Settings -> Enforcement* lists what is in force, a failed removal first. Each row has **Release** (no password), **Extend**
(password) and, when DENIS could not confirm a change, **Check now**. A device's panel shows the same for that device.

![The list of active responses](img/enforcement-active.png)

## Block suggestions

When a device keeps breaking a segmentation policy, DENIS suggests blocking it: a card at the top of the Alerts page and in
the device's panel, with **Review block...**. The button only opens the plan dialog above; nothing is blocked until you
confirm there with your password. The card is not shown while enforcement is switched off or when you may not block devices.

![A block suggestion on the Alerts page](img/enforcement-prompts.png)

## Not available yet

* **Enforcement from an MSP console** on a customer's local master is not built for actions on devices beyond what the level
  and the boxes of [MSP management](msp-management.md) allow.

## Where to find it in the console

* *Settings → Enforcement*: the kill switch and the hourly limit, the first lab switch, the connectors with their settings
  and *Never block these* lists, and *Currently blocked by DENIS* with **Unblock…**.
* *Topology → Switches and cables*, and a device's panel: **Disable…** for a switch port.
* *Users*: each administrator's enforcement permissions, and the one-time notice after the upgrade.

## The connector pages

[SNMP switch ports](nac/snmp.md), [Fortinet FortiGate](nac/fortigate.md), [Palo Alto PAN-OS](nac/paloalto.md),
[OPNsense](nac/opnsense.md), [SonicWall](nac/sonicwall.md), [Check Point](nac/checkpoint.md),
[Juniper SRX](nac/juniper.md), [WatchGuard Firebox](nac/watchguard.md), [MikroTik RouterOS](nac/mikrotik.md),
[Ubiquiti UniFi](nac/unifi.md), [Cisco Meraki](nac/meraki.md), [VMware NSX-T](nac/nsx.md),
[AWS Security Groups](nac/aws.md), [Azure NSGs](nac/azure.md), [Microsoft Hyper-V](nac/hyperv.md),
[Proxmox VE](nac/proxmox.md) and [RADIUS CoA](nac/radius_coa.md). The overview of the connectors is in
[Zones and policies](segmentation.md#enforcement-connectors); the actions API is in [API](api.md).
