# Enforcement: SonicWall SonicOS

Status: **Experimental. Simulator only: not yet validated on real equipment.** Everything below was built from SonicWall's published SonicOS 7 API documentation and knowledge-base articles, and checked against a fake SonicWall in DENIS's own tests. It has never been run against a real SonicWall. The vendor behaviours that are still unproven are listed under *Verified and not verified* below.

**SonicOS Gen7 / SonicOSX 7.x only.** Every working address-object and address-group example SonicWall publishes is marked for 7.X firmware. Gen6 is not implemented and not assumed to work.

Lab use: the old block (*Block device*, the address group) is allowed only while an administrator has switched on *Allow connectors that are not validated on real equipment (lab use)* under *Settings → Response policy*. The quarantine is new in 4.1 and needs that switch and also *Allow experimental enforcement actions*. Testing, reading and releasing always work.

Besides the connector's own refusals, every action through it is refused for a loopback, unspecified, broadcast or multicast address, for DENIS itself and for the gateway, for DNS and directory servers, for anything in *Never block these IP addresses*, and for the address you are using to reach the console. Release is never refused for these reasons.

## What DENIS can do on a SonicWall

| Action | What DENIS writes | What it does not do |
|---|---|---|
| **Block device** (address group) | One host address object (`denis-<tag>-<id>` on the new path, `denis-block-<ip>` on the old routes) in the zone you set, added to the address group you created for blocks, then one commit. | It does not create the access rule that makes the group block anything: **your own deny rule** that refers to the group does that. It does not end open connections. |
| **Quarantine** (address group) | The same address object, added to a second address group that you created for quarantine, then one commit. | It creates **no access rule at all** and never an allow rule. What a quarantined device may reach is decided by your own access rules. |
| Block one flow with a deny rule | **Not possible, and shown as unavailable.** | SonicOS access rules belong to a pair of zones, and the REST API does not document a way to put a new rule first in that pair's list. DENIS could not be sure a deny rule would be checked before an allow rule, so it does not write rules on a SonicWall. |
| End sessions | **Not possible.** | SonicWall's documentation shows no REST call that ends the open connections of one address, and DENIS does not guess one. |
| Disable port | Not possible on a firewall. | |

On the new path the address object is named from the action number, so removal is exact: DENIS removes only an address object whose name carries its own install's tag (`denis-<tag>-`), by name. An object with another install's tag, and the old `denis-block-<ip>` objects, are never touched by the new path. SonicOS address objects are not given a description by DENIS (the unverified `comment` field is not sent), so the name is the marker. Text you typed (the reason) is never written to the SonicWall.

## The configuration session and the commit are part of the action

SonicOS keeps **one** configuration session at a time, and a change made through the API is only *pending* until it is committed. So the new path does this, and records each as a step you can read in the action's detail:

1. **Reads first, nothing taken over yet.** DENIS reads the group (it must exist and must already have a member: DENIS does not add to an empty group, so put a placeholder address object in it) and the firewall's pending changes.
2. **It refuses while changes are pending.** A commit applies **every** pending change, and DENIS taking over the session signs out an administrator who is editing. If the firewall shows pending changes, or DENIS cannot read them, the plan says so and nothing is written. Ask the administrator to commit or discard them first. If your SonicOS version cannot give DENIS that list, tick *Do not check for pending changes before changing the configuration* (off by default; read its warning).
3. **It takes over the session** (`POST auth` with `override`). **This signs out an administrator who is signed in to the configuration at that moment.** That warning is shown in every plan and is unchanged from the old routes.
4. **It makes every edit, then commits once.** The whole member list of the group is written back (see below), then there is one commit after the last edit.
5. **If an edit or the commit is refused, DENIS discards the pending changes** (`DELETE config/pending`) before it ends the session, so nothing half-made stays pending for the next administrator's commit. If the commit's answer was lost (it may have been applied), nothing is discarded: the action is *unconfirmed* and DENIS reads the firewall back.
6. **It ends the session.**
7. **Confirmation.** The action is *enforced* only when the group read back shows the object **and nothing is still pending**. A change that is made but not committed is not in force, and DENIS says *unconfirmed*.

An accepted write that answers with an empty body is treated as *unknown*, not as success.

A release removes the object from the group, deletes the object, and commits once. If the delete is refused (SonicOS refuses while something else still refers to the object), the release still succeeds, because leaving the group is what ends the block; the leftover object is listed as an orphan. A group that DENIS's object is the only member of is never emptied: the release is held back, the action stays active, and DENIS tells you (add a placeholder member and release again).

## Setup on the SonicWall

Check these against SonicWall's documentation for your firmware version before relying on them.

1. **The block group and your own rule.** Create an **address group** dedicated to DENIS's blocks (with a placeholder member, for example an address object for `192.0.2.255`) and a **deny access rule** that refers to it at the top of the policy. DENIS never creates or edits this rule. Reserve the group for DENIS's IPv4 blocks: DENIS reads and rewrites only the IPv4 member list, and it is unproven whether a group that also holds MAC or FQDN members would keep them.
2. **Quarantine (optional).** A second address group (with a placeholder member) and **your own access rules** that use it: allow what a quarantined device needs (DHCP, DNS, NTP, the remediation server) and deny the rest. DENIS never creates, checks or edits these rules. Traffic inside the device's own subnet does not pass the firewall and is not affected.
3. **An administrator account for DENIS** in the *SonicWall Administrators* group, with the SonicOS API and RFC-2617 HTTP Basic authentication turned on (*Device | Settings | Administration*). It needs to read and change address objects and groups and to commit. Use an account of its own.
4. **A zone.** SonicOS requires every host address object to carry a zone. Use an existing zone name; it has no effect on which traffic your deny rule matches.
5. **In DENIS** (*Network → Equipment → Add a connector → SonicWall*): **Base URL**, **username**, **password** (stored sealed as `nac.sonicwall.password`), the **block address group name**, the **zone**, the optional **quarantine address group name**, and the addresses never to block.

## What DENIS records

The ledger row is written before anything changes (`unconfirmed`), the audit entry before the connector is touched, and each request that changes something is a step (session taken over, object created, group written, commit, discard, session ended). A release or an automatic end removes by name and commits; if SonicOS refuses, or pending changes are in the way, the action stays active and DENIS tries again, with growing waits, and tells you. A release of an action whose commit answer was lost does not refuse because of pending changes, since they may be its own.

Address objects that carry your DENIS install's tag but belong to no active action (for example after a database restore) are listed as orphans, with a button to remove them. Removing one takes it out of the block and quarantine groups, deletes it and commits. Objects with another install's tag, objects without a tag, and the old `denis-block-<ip>` objects are never listed as DENIS's and never removed by this.

## The old routes

The old block and unblock buttons behave as before: address object `denis-block-<ip>`, member of the block group, one commit, the session taken over and ended. They write the same ledger rows (no action type) and an unblock through them closes only those rows. They do not check for pending changes (they never did). One difference: an unblock whose group read fails is now refused instead of rewriting the group from an empty list.

## Removing everything by hand

In SonicOS, *Object | Match Objects | Addresses*: remove the member from your group first, then delete the address objects named `denis-...`, then commit.

## Verified and not verified

* **Verified (against a local fake SonicWall over TLS, in the test suite):** the request sequence and that it is the same for the old routes, one commit after every edit, the refusal while another administrator's changes are pending (and when the list cannot be read, and with the check switched off), the discard after a refused edit or commit so nothing stays pending, no discard after a lost commit answer, an empty answer read as unknown, a read-back that needs the change to be committed, release after a lost answer, a leftover object after a refused delete, that the last member is never removed, that an administrator's own members and objects are untouched, orphan listing and removal by tag only, that quarantine sends only membership calls, that no access rule is ever sent, and that refusals send nothing.
* **Not verified: everything on a real SonicWall.** In particular, behaviours that are unproven vendor facts (marked **[verify]** in the code):
  * `POST auth` with `{"override": true}` starts the single configuration session and answers `success: true` somewhere in the body (DENIS scans the whole body); `DELETE auth` ends it.
  * **`GET config/pending` answers the pending changes in the same shape as the configuration, and nothing but `status` when nothing is pending.** DENIS treats any other content as pending changes and refuses (the safe direction). If your version answers differently, DENIS refuses every action until you tick the option above.
  * **`DELETE config/pending` discards the pending changes** of the session.
  * `PUT address-groups/ipv4/name/<group>` replaces the member list (DENIS always sends the whole list), and a group that also holds MAC or FQDN members keeps them.
  * `POST address-objects/ipv4` needs a zone; `DELETE address-objects/ipv4/name/<name>` succeeds in the same session once the group no longer refers to the object; `GET address-objects/ipv4` lists every object with its `name` and `host.ip`.
  * An empty address group is accepted by SonicOS (DENIS never makes one: it refuses to add to an empty group and never removes the last member).
  * A commit saves the configuration, so the change survives a restart.
  * **Rules and sessions:** whether SonicOS has a way to place an access rule first in a zone pair's list, and whether a REST call ends the open connections of one address. DENIS found neither and shows both as unavailable.

## Limits

* IPv4 only. SonicOS keeps IPv6 address objects and groups on separate endpoints that are not implemented.
* Block device and quarantine do nothing until **your own** access rule refers to the group.
* A block stops new connections; open connections stay open.
* The commit applies every pending change on the firewall, which is why DENIS refuses to start while it can see any.

## Details from the console

The console shows a short line under each field and a short note behind its (i). The full explanation of each field is here.

- **Quarantine address group name (optional)**: The address group you created for quarantine. DENIS moves a device into it and back, and nothing else: what the group may reach is decided by your own access rules on the SonicWall. DENIS never creates an allow rule. Leave empty to switch quarantine off for this SonicWall.
- **Do not check for pending changes before changing the configuration**: Off by default. DENIS takes over the firewall's configuration session and commits, which applies every pending change and signs out an administrator who is editing, so it refuses to start while it can see pending changes, or when it cannot read them. Tick this only if your SonicOS version cannot give DENIS that list and you accept that a commit may apply other people's pending changes.
