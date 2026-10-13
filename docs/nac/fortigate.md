# Enforcement: Fortinet FortiGate

Status: **Experimental. Simulator only: not yet validated on real equipment.** Everything below was built from FortiOS's published REST API documentation and checked against a fake FortiGate in DENIS's own tests. It has never been run against a real FortiGate. Nothing here is listed as validated on hardware.

Lab use: the host block (address group) is allowed only while an administrator has switched on *Allow connectors that are not validated on real equipment (lab use)* under *Settings → Enforcement*. The actions new in 4.1 (flow block, quarantine, ending sessions) additionally need *Allow experimental actions (lab use)*. Releasing an action and removing what DENIS made always work.

## What DENIS can do on a FortiGate

| Action | What DENIS writes | What it does not do |
|---|---|---|
| **Block device** (address group) | One address object for the device, added to the address group you created for blocks. Ends the device's open sessions. | It never creates or edits the deny policy that uses the group. |
| **Quarantine** (quarantine group) | The same, into a second address group you created for quarantine. | It never creates an allow rule, and never edits your policies. What a quarantined device may reach is decided by your own policies for that group (DHCP, DNS, NTP, a remediation server). DENIS does not check them. |
| **Block flow** (deny rule) | One deny policy `denis-<tag>-<id>` for exactly one source, destination, protocol and port, placed at the top of the policy table, plus single host address objects (and one custom service when a port is given) named from it. | Only with the per-instance switch *Allow DENIS to create deny rules on this firewall*. Deny only: no code path builds an allow, accept or permit rule. Never `any` for an interface or an address, never a network or a name. |
| **End sessions** (session clear) | `firewall/session/close-multiple` for the device's address, once as source and once as destination: at most two calls, never a call without a filter. | It cannot be undone. The device can open new sessions at once. |
| Disable port | Not available: a firewall has no access port DENIS can switch off. | |

Every object DENIS makes carries `DENIS managed; owner <tag>; action <id>; by <login>; expires <time or never>` in its comment. Text you typed as a reason is never sent to the FortiGate. DENIS deletes only objects that carry its own owner tag. An object with a DENIS-style name that does not carry the tag is never touched, and the action is refused.

## Setup

1. **Block group.** In FortiOS create an address group for DENIS's blocks (*Policy & Objects → Addresses*) and a **deny policy** that uses it as source, at the top of the policy table. FortiOS does not keep an address group with no member, so put one placeholder address in the group (for example an address object for `192.0.2.255/32`, a documentation address that is never routed). DENIS refuses to use a group that has no member and says so.
2. **Quarantine group (optional).** Create a second address group, again with a placeholder member, and **your own policies** for it: allow what a quarantined device needs (DHCP, DNS, NTP, the remediation server) and deny the rest. DENIS never creates these. Enter the group's name in *Quarantine address group name*. Leave it empty to switch quarantine off.
3. **API user.** Create a REST API administrator (*System → Administrators → REST API Admin*) and give it an administrator profile with these permissions. Read-write: *Firewall* (address and address group objects, and for flow blocks also policies and custom services). Read: *Network* (routing table lookup) and *System* (interfaces and zones). To end sessions the profile also needs the *Firewall* monitor permission that lets it clear sessions. Restrict the trusted hosts of the API user to the DENIS machine. Generate its token.
4. **VDOM.** If VDOMs are enabled, name the one that holds the groups; leave empty otherwise.
5. *Settings → Enforcement* → **Fortinet FortiGate** → **Add…**: base URL, VDOM, block group name, API token, *Never block these IP addresses* (DENIS itself, the gateway, the FortiGate), and optionally the quarantine group.
6. **Flow blocks:** tick *Allow DENIS to create deny rules on this firewall* only if you accept that DENIS writes policies on this FortiGate. It is off by default, and DENIS will not create or delete any policy while it is off. A wrong deny rule can cut off traffic.

## How a flow block finds its interfaces

A FortiOS policy needs a source and a destination interface. DENIS never uses `any`: whether your FortiOS build accepts `any` there is not verified, so DENIS looks up the interface of each address instead. It first looks for the directly connected network (the most specific one) among the FortiGate's interfaces, then asks the routing table (`monitor/router/lookup`). If an interface is a member of a zone, the policy names the zone. If DENIS cannot tell, or both addresses are behind the same interface, it refuses and says why. A refusal is a normal answer, not an error.

## What is verified

Only against the fake FortiGate server in `src/nac_fortigate/tests.rs`: creating, finding by name, moving and deleting the policy, address objects and service; the quarantine move and restore; ending sessions; lost answers (the action is *unconfirmed* and can still be released); a refused step after earlier steps (compensated, nothing left behind, or *partial* and still releasable); the opt-in and lab-switch refusals; orphans found by owner tag and removed only when they carry it. **Not verified on any real FortiGate.**

Behaviours that are unproven vendor facts (marked **[verify]** in the code):

* `PUT cmdb/firewall/policy/<id>?action=move&before=<id>` places a policy at the top, and a new policy gets the next free id. DENIS checks the position after the move and removes the policy if it did not land at the top.
* `GET monitor/router/lookup?destination=<ip>` answers with the interface in `results.interface`.
* Zone members are listed in `cmdb/system/zone` as `interface[].interface-name`, and a zone member must be referenced through its zone.
* The predefined services `ALL`, `ALL_TCP`, `ALL_UDP` and `ALL_ICMP` exist.
* FortiOS does not keep an address group with no member (so a placeholder is needed). DENIS does not remove its own entry if it is the only member and tells you to add a placeholder.
* `firewall/session/close-multiple` with `srcaddr` or `dstaddr` closes the sessions of that address. FortiOS may answer with an error when no session matches. DENIS then reports the action as failed (nothing changed) rather than completed.
* Whether sessions that are already open are cut by a new deny policy depends on the global setting `firewall-session-dirty` (default `check-all`). DENIS does not change it.
* FortiOS matches the original source address (before source NAT). A destination behind a virtual IP is matched by the virtual IP.
* The policy `comments` and address `comment` fields accept the 255 character marker.

## Limits

* IPv4 only. FortiOS keeps IPv6 objects on separate endpoints that DENIS does not use.
* Traffic between two devices in the same subnet does not pass the firewall, and no rule on it stops it.
* Policy placement is the top of the table only. No other anchor is offered.
* A deny policy for a flow in both directions is two policies (`denis-<tag>-<id>` and `denis-<tag>-<id>-r`).

## Credentials

The API token is stored only in the encrypted secret store (`nac.fortigate.api_token`) and sent as `Authorization: Bearer <token>`. It is never written to the ledger, the audit log or a notification.

## Existing instances

Instances from earlier versions keep working and nothing changes for them: the same block group, the same address objects (`denis-block-<ip>`), the same ledger rows. The old *Block…* and *Unblock…* buttons act as before. Records the old routes made are released through the old *Unblock…*; records of the new actions are released through the new action list.
