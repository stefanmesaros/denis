# Enforcement: Check Point Management API

Status: **Experimental. Simulator only: not yet validated on real equipment.** Everything below was built from Check Point's published Management API reference and checked against a fake Management Server in DENIS's own tests. It has never been run against a real Security Management Server. The vendor behaviours that are still unproven are listed under *Verified and not verified* below.

Lab use: the old block (*Block device*, the address group) is allowed only while an administrator has switched on *Allow connectors that are not validated on real equipment (lab use)* under *Settings → Response policy*. Quarantine and flow blocks are new in 4.1 and need that switch and also *Allow experimental enforcement actions*. A flow block also needs *Allow DENIS to create deny rules on this firewall* ticked on this connector. Testing, reading and releasing always work.

Besides the connector's own refusals, every action through it is refused for a loopback, unspecified, broadcast or multicast address, for DENIS itself and for the gateway, for DNS and directory servers, for anything in *Never block these IP addresses*, and for the address you are using to reach the console. Release is never refused for these reasons.

## What DENIS can do on a Check Point

| Action | What DENIS writes | What it does not do |
|---|---|---|
| **Block device** (group) | One host object (`denis-<tag>-<id>` on the new path, `denis-block-<ip>` on the old routes), added to the group you created for blocks, then a publish and an install of the policy package. | It does not create the rule that makes the group block anything: **your own deny rule** that refers to the group does that. It does not end open connections. |
| **Quarantine** (group) | The same host object, added to a second group that you created for quarantine, then publish and install. | It creates **no rule at all** and never an allow rule. What a quarantined device may reach is decided by your own rules. |
| **Block flow** (deny rule) | Two host objects (`denis-<tag>-<id>-src` and `-dst`), a TCP or UDP service object `denis-<tag>-<id>-svc` for a protocol and port, and one access rule `denis-<tag>-<id>` with action **Drop**, placed at the top of the access layer, then publish and install. With both directions: a second rule `denis-<tag>-<id>-r`. | It never writes an Accept or other allow rule, never a network, `Any` source or destination, or a rule for the gateway's own addresses. ICMP is refused (DENIS does not build ICMP service objects). Only with *Allow DENIS to create deny rules on this firewall* ticked. |
| End sessions | **Not possible through the Management API.** | The Management API documents no call that ends an open connection. The gateway's own SAM commands are a different product surface DENIS does not use. |
| Disable port | Not possible on a firewall. | |

Every object DENIS makes carries the marker in its comment (`DENIS managed; owner <tag>; action <id>; by <login>; expires <time or never>`), so removal is exact: DENIS removes only what carries its own marker, by name, and an object with another install's tag is never touched. Text you typed (the reason) is never written to the Check Point.

## Publish and install are part of the action

A Management session's edits are private to that session until it is **published**, and a gateway enforces only what a policy **install** has pushed. DENIS therefore does, and records each as a step you can read in the action's detail:

1. **Log in** (one session per action).
2. **Read first.** The group (it must exist and must already have a member, so put a placeholder in it), and for a rule the access layer. **DENIS refuses when another administrator has unpublished changes**: it reads the open sessions, and if one of someone else's holds changes, the plan says who and nothing is written. If your version cannot give DENIS that list, DENIS refuses too, unless you tick *Do not check for other administrators' unpublished changes* (off by default; read its warning).
3. **Make the edits** in the session.
4. **For a rule: read the rule base back inside the session and check the rule is at the top, before anything is published.** If it is not, the session is discarded and nothing is ever published.
5. **Publish** and wait for its task.
6. **Install the policy package on the gateways** you named and wait for its task. The task number is kept in the step, so a later check can ask Check Point again.
7. **Log out.**

* **If anything fails before the publish, DENIS discards the session** (`discard`), so nothing half-made is published and no other administrator sees it.
* **If the publish's answer is lost,** nothing is discarded (it may have been published): the action is *unconfirmed* and DENIS asks again.
* **A change that is published but not installed is not enforced.** DENIS says *unconfirmed* until a read-back shows the change and the install task has succeeded. A later *Check now* asks Check Point whether the install task finished.
* **An install pushes everything already published in the package**, including other administrators' published changes that have not been installed yet. DENIS shows that in every plan (and the existing warning, that the install also publishes any other pending policy change in the package, stays).
* A publish and an install can each take minutes. The time limit of an action starts when the install has finished.

A release removes the member (and the host object), publishes and installs. A release whose earlier attempt published but did not install only installs. If Check Point refuses, or another administrator's unpublished changes are in the way, the action stays active and DENIS tries again, with growing waits, and tells you.

## Setup on the Check Point

Check these against Check Point's documentation for your version before relying on them.

1. **The block group and your own rule.** Create a **group** dedicated to DENIS's blocks (with a placeholder member, for example a host object for `192.0.2.255`) and a **Drop rule** that refers to it at the top of the rule base. DENIS never creates or edits this rule.
2. **Quarantine (optional).** A second group (with a placeholder member) and **your own rules** that use it: allow what a quarantined device needs (DHCP, DNS, NTP, the remediation server) and drop the rest. DENIS never creates, checks or edits these rules. Traffic inside the device's own subnet does not pass the gateway and is not affected.
3. **Flow blocks (optional).** Tick *Allow DENIS to create deny rules on this firewall* only if you accept that DENIS writes access rules here. It is off by default; turning it on needs your password again, like turning on enforcement. Name the **access layer** (default `Network`) where DENIS puts its rules at the top. A rule in a layer above, or an inherited rule from a higher policy, can still pass traffic before DENIS's rule is looked at, and DENIS cannot see it.
4. **An administrator for DENIS** (or an **API key**, R81.20 and later), with a permission profile that may read and edit the objects and the access layer, publish, install the policy on the gateways, and **read other administrators' sessions** (for the check above; whether a profile may read sessions is **[verify]**). Use an account of its own, and turn on the Management API (*Manage & Settings → Blades → Management API*).
5. **The policy package and the gateways.** Name the policy package and the gateway or cluster objects the install targets (at least one).
6. **In DENIS** (*Network → Equipment → Add a connector → Check Point*): **base URL**, **authentication mode**, **username** (password mode), the **secret** (stored sealed as `nac.checkpoint.password` or `nac.checkpoint.api_key`), the **domain** (Multi-Domain only), the **policy package**, the **gateways**, the **block group**, the optional **quarantine group** and **access layer**, and the addresses never to block.

## What DENIS records

The ledger row is written before anything changes (`unconfirmed`), the audit entry before the connector is touched, and each request that changes something is a step (host created, member added, rule created and its position checked, publish and install with their task numbers and times, discard). A release or an automatic end removes by name and marker.

Objects and rules that carry your DENIS install's marker but belong to no active action (for example after a database restore) are listed as orphans, with a button to remove them. Removing one takes it out of the groups, deletes it, publishes and installs, so it is held back by the same check for other administrators' unpublished changes. Objects with another install's tag, and anything without the marker, are never listed as DENIS's and never removed.

## The old routes

The old block and unblock buttons behave as before: host object `denis-block-<ip>`, member of the block group, publish, install (an unblock also deletes the host object, with a second publish and install). They write the same ledger rows (no action type) and an unblock through them closes only those rows. They do not check for other administrators' unpublished changes (they never did).

## Removing everything by hand

In SmartConsole, remove the member from your group first, delete the host and service objects named `denis-...` and the rules named `denis-...`, then publish and install the policy.

## Verified and not verified

* **Verified (against a local fake Management Server over TLS, in the test suite):** the request sequence and that it is the same for the old routes, the refusal while another administrator has unpublished changes (and when the sessions cannot be read, and with the check off), the discard after any refusal before the publish, no discard after a lost publish answer, that a rule is checked at the top inside the session and a rule that did not land there is discarded and never published, that only Drop rules are ever built, that quarantine sends only membership calls, an install that never finishes (unconfirmed, then settled by asking its task again), a failed install, a release that only installs, orphan listing and removal by marker only, a foreign object under a DENIS name left alone, and that refusals send nothing.
* **Not verified: everything on a real Security Management Server.** In particular, behaviours that are unproven vendor facts (marked **[verify]** in the code):
  * `login` answers `sid` and the session `uid`; `X-chkp-sid` is accepted on every other call; the API-key login form works on R81.20 and later.
  * **`show-sessions` (with `view-published-sessions` false) lists the open sessions with `user-name`, `uid` and a `changes` count**, and a session of another administrator with changes is unpublished work. If your version answers differently, DENIS refuses until you tick the option above.
  * `add-host`, `add-service-tcp` and `add-service-udp` take a `comments` text and `set-group` takes `members.add` and `members.remove`; `delete-host` is refused while a group still refers to the object; an **empty group is accepted** (DENIS never makes one: it refuses to add to an empty group).
  * `add-access-rule` with `position` `top` and `action` `Drop` puts the rule first in the layer; **`show-access-rulebase` shows the session's own unpublished edits** and nests rules in `access-section` entries (DENIS walks them). DENIS checks the position by reading the rule base itself, so a version that places the rule elsewhere makes the action fail instead of publishing it.
  * `publish` and `install-policy` answer a `task-id`, and `show-task` reports `succeeded`, `failed`, `partially succeeded` or `in progress`. Check Point's API has no call that reads what a gateway currently enforces, so *enforced* means the install task succeeded and the database shows the change, not that DENIS saw a gateway drop traffic.
  * Whether `discard` leaves nothing behind in every case; whether a session that is never logged out keeps holding locks (DENIS always logs out).

## Limits

* IPv4 only.
* A change is in force only after the install, minutes later. Choose a time limit of at least several minutes.
* Block device and quarantine do nothing until **your own** rule refers to the group.
* A block stops new connections; open connections stay open. It does not stop traffic inside one subnet.
* Layers above DENIS's layer, inherited rules and rules in other policy packages are not visible to DENIS.

## Details from the console

The console shows a short line under each field and a short note behind its (i). The full explanation of each field is here.

- **Quarantine group name (optional)**: The group you created for quarantine. DENIS moves a device into it and back, and nothing else: what the group may reach is decided by your own rules on the Check Point. DENIS never creates an allow rule. Leave empty to switch quarantine off for this Check Point.
- **Access layer for deny rules (default Network)**: The access layer of your policy package where DENIS puts a deny rule at the top when you block one flow. Leave empty to use Network.
- **Allow DENIS to create deny rules on this firewall**: Off by default. When on, DENIS can create one Drop rule per flow block at the top of the access layer, named denis-... and tagged DENIS managed, and delete it again when the action ends. It never creates an allow rule and never uses any address but the two hosts of the flow. A wrong deny rule can cut off traffic: switch this on only if you accept that.
- **Do not check for other administrators' unpublished changes**: Off by default. Installing a policy pushes everything already published in the package, and DENIS refuses to publish and install while another administrator has unpublished changes in an open session, or when it cannot read the open sessions. Tick this only if your version cannot give DENIS that list and you accept that DENIS may act while someone else is editing.
