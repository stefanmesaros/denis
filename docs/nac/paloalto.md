# Enforcement: Palo Alto Networks PAN-OS

Status: **Experimental. Simulator only: not yet validated on real equipment.** Everything below was built from PAN-OS's published XML API documentation and checked against a fake firewall in DENIS's own tests. It has never been run against a real PAN-OS firewall. Nothing here is listed as validated on hardware.

Lab use: the host block (address group) is allowed only while an administrator has switched on *Allow connectors that are not validated on real equipment (lab use)* under *Settings → Enforcement*. The actions new in 4.1 (flow block, quarantine, ending sessions) additionally need *Allow experimental actions (lab use)*. Releasing an action and removing what DENIS made always work.

## What DENIS can do on PAN-OS

| Action | What DENIS writes | What it does not do |
|---|---|---|
| **Block device** (address group) | One address object for the device, added to the static address group you created for blocks, then a commit. Ends the device's open sessions. | It never creates or edits the deny rule that uses the group. |
| **Quarantine** (quarantine group) | The same, into a second static address group you created for quarantine. | It never creates an allow rule, and never edits your rules. What a quarantined device may reach is decided by your own security rules for that group (DHCP, DNS, NTP, a remediation server). DENIS does not check them. |
| **Block flow** (deny rule) | One deny security rule `denis-<tag>-<id>` for exactly one source host, destination host, protocol and port, placed at the top of the security rulebase and checked there, plus single host address objects (and one service object when a protocol or port is given) named from it, then a commit. | Only with the per-instance switch *Allow DENIS to create deny rules on this firewall*, and only with the commit scoped to one administrator. Deny only: no code path builds an allow rule. Never a network, a name or an address other than the two hosts. |
| **End sessions** (session clear) | `clear session all filter source <ip>` and `... filter destination <ip>`: at most two calls, never a call without a filter. | It cannot be undone. The device can open new sessions at once. It changes no configuration and needs no commit. |
| Disable port | Not available: a firewall has no access port DENIS can switch off. | |

Every object DENIS makes carries `DENIS managed; owner <tag>; action <id>; by <login>; expires <time or never>` in its description. Text you typed as a reason is never sent to the firewall. DENIS deletes only objects that carry its own owner tag. An object with a DENIS-style name that does not carry the tag is never touched, and the action is refused.

## The commit model, and why it matters here

A change made through the XML API lands in the *candidate* configuration and does nothing until a commit publishes it. A plain commit publishes **everything that is pending, including other administrators' unfinished edits.** DENIS therefore treats the commit as the most important part of every action:

* **Scope the commit.** Under *Scope commits to this administrator only* enter the PAN-OS account that DENIS's API key belongs to. Every commit DENIS makes is then a partial commit of that account's own changes. A flow block (it writes a rule) **refuses to run without it**.
* **Without the scope**, block device and quarantine still work, the plan says that a full commit publishes everything pending, and DENIS **refuses** when it can see that another administrator has changes waiting (`show config list changes`, **[verify]**). Your own earlier unfinished DENIS edits would show up the same way.
* **DENIS waits for the commit job** (up to three minutes, polling every two seconds) and records in the action's steps how long it took. A commit takes from seconds to several minutes on a real firewall.
* **A commit is never assumed.** The action is *enforced* only when DENIS has read the **running** configuration back and found the change in it. A commit that is still running when the wait ends, or whose answer was lost, leaves the action *unconfirmed* (the row stays active, and a later check or release settles it).
* **A commit the firewall refuses, or whose job finishes with anything but OK, publishes nothing.** DENIS then withdraws its own candidate objects, so nothing of it is left to be published by somebody else's commit. The action ends *failed*; if even the withdrawal is refused it ends *partial* and stays releasable.
* **Releasing** commits only when the running configuration still holds something of DENIS's (or when an earlier commit of the action ended without a usable answer, because that job may still land). A candidate edit that never reached the running configuration is simply deleted.

## Setup

1. **Block group.** In PAN-OS create a **static address group** for DENIS's blocks (*Objects → Address Groups*) and a **deny rule** that uses it as source (or destination), at the top of the Security Policy. A static group needs at least one member, so put one placeholder address in the group (for example an address object for `192.0.2.255/32`, a documentation address that is never routed). DENIS refuses to use a group that has no static member or that is a dynamic group, and says so. DENIS never creates or edits this rule.
2. **Quarantine group (optional).** Create a second static address group, again with a placeholder member, and **your own security rules** for it: allow what a quarantined device needs (DHCP, DNS, NTP, the remediation server) and deny the rest. DENIS never creates these. Enter the group's name in *Quarantine address group name*. Leave it empty to switch quarantine off.
3. **API account.** Create an administrator for DENIS (a role-based or custom admin role) and generate its **API key**. The role needs the XML API for *Configuration* (read and write the objects and, for flow blocks, the security rulebase), *Commit* (and *Commit for other admins* is **not** needed), and *Operational Requests* (job status, clear sessions, `show config list changes`). Restrict the account's management access to the DENIS machine.
4. **vsys.** Name the vsys that holds the groups (PAN-OS always has at least `vsys1`).
5. *Settings → Enforcement* → **Palo Alto Networks PAN-OS** → **Add…**: base URL, vsys, block group name, API key, *Never block these IP addresses* (DENIS itself, the gateway, the firewall), *Scope commits to this administrator only* (the account of the API key), and optionally the quarantine group.
6. **Flow blocks:** tick *Allow DENIS to create deny rules on this firewall* only if you accept that DENIS writes security rules on this firewall. It is off by default, and DENIS will not create or delete any rule while it is off. Turning it on needs your password again and is written to the audit log. A wrong deny rule can cut off traffic.

## How a flow block is shaped

The rule is `from any to any`, source `denis-<tag>-<id>-src` (a single `/32` address object), destination `denis-<tag>-<id>-dst`, application `any`, service `any` or the service object `denis-<tag>-<id>-svc` (TCP or UDP with the given port or range, or the whole port range when only a protocol is given), action **deny**, log at session end. The two host addresses alone make the rule exact, so DENIS does not look up zones or interfaces. In both directions, a second rule `denis-<tag>-<id>-r` swaps the two. ICMP is not built (PAN-OS matches it through an application); DENIS refuses a flow with ICMP and says why.

After creating the rule DENIS moves it to the top of the rulebase and reads the rulebase back: only DENIS's own rules (same owner tag) may stand before it. If it did not land at the top, DENIS removes it and the action ends *failed*. After the commit it checks the same thing in the running configuration.

## What is verified

Only against the fake firewall in `src/nac_paloalto/tests.rs` and `src/nac_paloalto/tests/orch_tests.rs`: creating, finding by name, moving and deleting the rule, address objects and service; the quarantine move and restore; ending sessions; the partial and full commit and what each publishes; a slow commit, a commit that fails, a commit the firewall refuses, a commit that is still running or whose answer is lost (the action is *unconfirmed* and can still be released); a refused step after earlier steps (compensated, nothing left behind, or *partial* and still releasable); the opt-in, commit-scope and lab-switch refusals; orphans found by owner tag and removed only when they carry it. **Not verified on any real PAN-OS firewall.**

Behaviours that are unproven vendor facts (marked **[verify]** in the code):

* `type=config&action=move&where=top` places a security rule first, and `type=config&action=get` on the rulebase lists the rules in evaluation order. DENIS checks the position after the move and removes the rule if it did not land at the top.
* A security rule with `any` as source and destination zone is accepted and matches the flow whatever zones the two hosts are in.
* `get` and `show` on an object that does not exist answer with success and an empty result, or with an error that says the object does not exist. DENIS reads both as "not there" and any other error as "cannot tell" (never as "absent").
* A static address group needs at least one member, and `set` at the group's `static` node merges one member without replacing the others. DENIS does not remove its own entry if it is the only member and tells you to add a placeholder.
* `show config list changes` lists the pending changes with the administrator who made each one. If its answer cannot be read, DENIS only carries the note about the full commit.
* A commit job ends with the result `OK`; any other result means nothing was published.
* A partial commit of one administrator publishes only that administrator's changes, including when those are objects that the rule refers to.
* `clear session all filter source <ip>` and `... filter destination <ip>` end the sessions of that address. PAN-OS may answer with an error when no session matches. DENIS then reports the action as failed (nothing changed) rather than completed.
* Whether sessions that are already open are cut by a new deny rule depends on the firewall's session rematch setting ("rematch all sessions on config policy change"). DENIS does not change it.
* Security rules match the addresses before NAT and the zones after NAT. A destination behind a destination NAT is matched by its public (original) address.
* **Panorama.** Pre-rules that Panorama pushes to this firewall are evaluated before the firewall's own rulebase, so they can still allow a flow that DENIS's rule denies. DENIS talks to the firewall, not to Panorama, and cannot see them. The plan says so for every flow block. Placing DENIS's rule in a Panorama device group is not built.
* The rule, address and service `description` fields accept the marker (well under their 1023 character limit).

## Limits

* IPv4 only.
* Traffic between two devices in the same subnet does not pass the firewall, and no rule on it stops it.
* Rule placement is the top of the local security rulebase only. No other anchor is offered, and shared or Panorama rulebases are not written.
* A deny rule for a flow in both directions is two rules (`denis-<tag>-<id>` and `denis-<tag>-<id>-r`).
* PAN-OS tags are not used; the marker in the description is what identifies DENIS's objects.

## Credentials

The API key is stored only in the encrypted secret store (`nac.panos.api_key`) and sent as the `X-PAN-KEY` header. It is never written to the ledger, the audit log or a notification. DENIS uses the XML API only, not the REST API: only the XML API has a commit and the operational commands DENIS needs.

## Existing instances

Instances from earlier versions keep working and nothing changes for them: the same block group, the same address objects (`denis-block-<ip>`), the same ledger rows, the same one commit per block. The old *Block…* and *Unblock…* buttons act as before. Records the old routes made are released through the old *Unblock…*; records of the new actions are released through the new action list.
