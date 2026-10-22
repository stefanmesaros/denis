# Enforcement: OPNsense

Status: **Experimental. Simulator only: not yet validated on real equipment.** Everything below was built from OPNsense's published REST API documentation and controller sources and checked against a fake OPNsense in DENIS's own tests. It has never been run against a real OPNsense. Nothing here is listed as validated on hardware.

Lab use: the host block (alias) is allowed only while an administrator has switched on *Allow connectors that are not validated on real equipment (lab use)* under *Settings → Response policy*. The actions new in 4.1 (flow block, quarantine, ending sessions) additionally need *Allow experimental actions (lab use)*. Releasing an action and removing what DENIS made always work.

Besides the connector's own refusals, every action through it is refused for a loopback, unspecified, broadcast or multicast address, for DENIS itself and for the gateway, for the addresses on this connector's protected list, for an address in an open `arp_conflict` alert (unless the administrator ticks a box to accept that) and for any address that belongs to the OPNsense itself, before anything is sent. Releasing is never refused for these reasons.

## What DENIS can do on an OPNsense

| Action | What DENIS writes | What it does not do |
|---|---|---|
| **Block device** (alias) | One address, added to the alias you created for blocks, then **apply** of the firewall filter, then it ends the device's open states (best effort). | It never creates or edits the rule that uses the alias. An address that is already in the alias is refused: an alias entry has no name, so DENIS could not tell its own from yours, and it never takes yours over. |
| **Quarantine** (quarantine alias) | The same, into a second alias you created for quarantine. | It never creates an allow rule, and never edits your rules. What a quarantined device may reach is decided by your own rules for that alias (DHCP, DNS, NTP, a remediation server). DENIS does not check them. |
| **Block flow** (deny rule) | One **floating** deny rule per direction, `denis-<tag>-<id>` (and `-r`), for exactly one source, destination, protocol and port: action `block`, `quick`, inbound, logged, sequence 1, created through the filter API, checked to be ahead of every other floating rule DENIS can read, then **applied**. | Only with the per-instance switch *Allow DENIS to create deny rules on this firewall*. Deny only: no code path builds a pass rule. Never `any` for a source or destination, never a network or a name. A new rule does not cut connections that are already open (pf keeps its states): it stops new ones. |
| **End sessions** (state kill) | The open states of one address: read first, ended only when every state read holds exactly that address, at most 2000. | It cannot be undone. The device can open new sessions at once. If the state list also holds states of other addresses (a free-text match such as `10.1.1.5` also matches `10.1.1.50`), DENIS ends none and says so. |
| Disable port | Not available: a firewall has no access port DENIS can switch off. | |

Every rule DENIS makes carries `denis-<tag>-<id>; DENIS managed; owner <tag>; action <id>; by <login>; expires <time or never>` in its description (OPNsense rules have no name field, so the description starts with the name). Text you typed as a reason is never sent to the OPNsense. DENIS deletes only rules that carry its own owner marker. A rule with a DENIS-style name that does not carry the marker is never touched, and the action is refused. Entries of an alias have no name and cannot carry a marker: they are never listed as orphans. If a record of one is lost, remove the address from the alias by hand.

## The apply step is part of the action

`addRule`, `delRule` and the alias calls only change what OPNsense has saved. DENIS therefore records **apply filter** as a step of its own:

* a refused apply is a refused action: the rule DENIS saved is removed again (and the filter applied again), the action ends *failed*, and nothing of DENIS's is left; if that clean-up cannot be applied either, the action is *partly applied* and stays active until it is released;
* an apply whose answer is lost leaves the action *not confirmed*;
* the read-back reads the rule table again and counts the rule as in force only when the action's own apply did not fail;
* every removal applies too, also when the rule is already gone from the saved configuration, so a removal whose apply failed earlier is published by the next try.

OPNsense applies **every** saved change to its rules at once. A change someone else saved in the web interface and did not apply yet is applied too. The plan says so.

## Setup

1. **Block alias.** In OPNsense create a firewall alias of type *Host(s)* (*Firewall → Aliases*) dedicated to DENIS's blocks, and a **block rule** that uses it (as source or destination, as you need), high up in the rules. DENIS never creates or edits this rule. The alias may be empty; it has to exist.
2. **Quarantine alias (optional).** Create a second alias of type *Host(s)* and **your own rules** for it: allow what a quarantined device needs (DHCP, DNS, NTP, the remediation server) and deny the rest. DENIS never creates these. Enter the alias name in *Quarantine alias name*. Leave it empty to switch quarantine off.
3. **API user.** Create a user for DENIS (*System → Access → Users*) and give it only the privileges it needs, then create its API key and secret. Read and write: *Firewall: Alias: Edit* (alias entries) and, for flow blocks, *Firewall: Rules: Edit* and *Firewall: Automation: Filter*. Read: *Diagnostics: Interfaces* (to read the firewall's own addresses) and *Diagnostics: Firewall* (states). Applying the filter needs the *Firewall: Rules* privilege. Allow the API user only from DENIS's address if your OPNsense can restrict that.
4. *Network → Equipment* → **OPNsense** → **Add…**: base URL, API key, API secret, block alias name, *Never block these IP addresses* (DENIS itself, the gateway, the OPNsense), and optionally the quarantine alias.
5. **Flow blocks:** tick *Allow DENIS to create deny rules on this firewall* only if you accept that DENIS writes rules on this OPNsense. It is off by default, and DENIS will not create or delete any rule while it is off. Changing it needs your password. A wrong deny rule can cut off traffic.

## How a flow block is placed

OPNsense evaluates floating rules before the rules of the interfaces, and a `quick` rule ends the evaluation at the first match. DENIS creates its rule floating (no interface), `quick`, inbound, with sequence 1, the lowest value, and then reads the rules back: if another enabled floating rule it can read has a sequence of 1 or lower (or a sequence DENIS cannot read), DENIS refuses at the plan and, if the check fails after the rule was made, removes it again. Give your own floating rules a sequence above 1. A rule in the classic *Firewall → Rules* pages, or one the filter API does not list, cannot be seen by DENIS.

## What is verified

Only against the fake OPNsense server in `src/nac_opnsense/tests.rs`: the alias add and delete with the apply, the quarantine alias, creating, finding by name, checking the position of and deleting the rule (both directions, TCP, UDP and ICMP for IPv4 and IPv6, port ranges), the apply as a step with its refusal, its lost answer and its compensation, lost answers on every write (the action is *not confirmed* and can still be released), a refused step (compensated, nothing left behind, or *partly applied* and still releasable), the opt-in and lab-switch refusals, a missing or empty alias, the firewall's own addresses, orphans found by owner marker and removed only when they carry it, and the bounded end of sessions (unbounded match, unreadable table, more than 2000 states, nothing open). **Not verified on any real OPNsense.**

Behaviours that are unproven vendor facts (marked **[verify]** in the code):

* `POST /api/firewall/filter/addRule` with `{"rule": {...}}`, `GET searchRule`, `POST delRule/<uuid>` and `POST apply` exist and behave as documented. They belong to OPNsense 24.1 and later; older releases have no filter REST API, and DENIS then refuses a flow block and says so.
* A rule with **no interface** is a floating rule, and a floating `quick` rule is evaluated before the interface rules.
* `searchRule` returns `sequence`, `interface`, `enabled`, `description` and the match fields of every rule, and a lower `sequence` is evaluated first with 1 as the lowest value.
* `filter/apply` answers `{"status": "OK"}` on success.
* `alias/getAliasUUID/<name>` answers a `uuid` for an alias that exists (DENIS uses it only to tell a missing alias from an empty one; when it cannot answer, an empty alias is refused).
* `alias_util/add` and `delete` change the live table, and whether the entry is also saved in the alias's configuration and survives a reboot is not verified. The read-back after the apply shows whether the apply dropped it.
* `diagnostics/interface/getInterfaceConfig` lists the firewall's own addresses in `ipv4[].ipaddr` and `ipv6[].ipaddr`. When it cannot be read, a flow block is refused; a host action goes ahead (only the protected list guards the firewall's own address then).
* `diagnostics/firewall/query_states` takes `{"filter": ...}` and answers rows with `src_addr` and `dst_addr`, and `kill_states` with the same filter ends exactly the states the first call showed.
* `description` accepts the 255 character marker.
* pf keeps established states: a new block rule does not end open connections. **End sessions** is the way to cut those, for all sessions of the address.
* OPNsense does not offer a safe "apply and roll back unless confirmed" that DENIS relies on. (Newer releases have a savepoint call for the filter; DENIS does not use it.)

## Limits

* Both IPv4 and IPv6 for flows and host actions (an alias holds either).
* Traffic between two devices in the same subnet does not pass the firewall, and no rule on it stops it.
* A flow rule is floating and inbound: it is placed first among the floating rules only. No other position is offered.
* A deny rule for a flow in both directions is two rules (`denis-<tag>-<id>` and `denis-<tag>-<id>-r`).
* NAT: OPNsense filters on the original source, before outbound NAT, and after a port forward has translated the destination.

## Credentials

The API secret is stored only in the encrypted secret store (`nac.opnsense.api_secret`) and sent as HTTP Basic authentication with the API key. It is never written to the ledger, the audit log or a notification.

## Existing instances

Instances from earlier versions keep working and nothing changes for them: the same block alias, the same raw address entry, the same apply and the same loose `kill_states` call, the same ledger rows. The old *Block…* and *Unblock…* buttons act as before. Records the old routes made are released through the old *Unblock…*; records of the new actions are released through the new action list.

## Details from the console

The console shows a short line under each field and a short note behind its (i). The full explanation of each field is here.

- **Quarantine alias name (optional)**: The alias you created for quarantine. DENIS moves one address into it and back, and nothing else: what the alias may reach is decided by your own rules on the OPNsense. DENIS never creates an allow rule. Leave empty to switch quarantine off.
- **Allow DENIS to create deny rules on this firewall**: Off by default. When on, DENIS can create one floating deny rule per flow block on this OPNsense, first in the rule order, named denis-... and tagged DENIS managed, apply the rules, and delete the rule again when the action ends. It never creates an allow rule. A wrong deny rule can cut off traffic.
