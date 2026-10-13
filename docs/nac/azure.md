# Enforcement: Azure network security groups

Status: **Experimental. Simulator only: not yet validated on real equipment.** Everything below was built from Microsoft's published Azure Resource Manager (ARM) REST reference and checked against a fake ARM in DENIS's own tests. It has never been run against a real subscription. Nothing here is listed as validated on hardware.

Lab use: the quarantine (the swap that was called "block" before 4.1) is allowed only while an administrator has switched on *Allow connectors that are not validated on real equipment (lab use)* under *Settings → Enforcement*. The actions new in 4.1 (host block through the isolation group, flow block) additionally need *Allow experimental actions (lab use)*. Releasing an action and removing what DENIS made always work.

Besides the connector's own refusals, every action through it is refused for a loopback, unspecified, broadcast or multicast address, for DENIS itself and for the gateway, for a machine on this connector's protected list, for an address in an open `arp_conflict` alert (unless the administrator ticks a box to accept that), before anything is sent. Releasing is never refused for these reasons.

## What the old "block" really is

Before 4.1 this connector's block moved every network interface of one VM into one network security group (NSG) you made for quarantine. That was always a **quarantine of the machine**, not a block of one address, and DENIS now calls it that (*Quarantine*, method `nsg_swap`). The old *Block…* and *Unblock…* buttons still do exactly this, by VM name, and old records keep working. Nothing about the old routes changed.

## What DENIS can do on Azure

| Action | What DENIS writes | What it does not do |
|---|---|---|
| **Quarantine** (`nsg_swap`) | Every network interface of the machine is pointed at the NSG you made for quarantine. DENIS remembers the NSG each interface had (or none) and tags each interface (see below). | It never creates or edits a rule. What a quarantined machine may reach is decided by the rules in your NSG (DHCP, DNS, a remediation server). DENIS does not check them. |
| **Block device** (`isolation_nsg`) | The same swap, into a second NSG you made with **no allow rules at all**, so the machine can neither send nor receive. | Same: DENIS never creates or checks a rule in it. A rule in it that allows traffic lets that traffic through. |
| **Block flow** (`deny_rule`) | An **inbound** and an **outbound** deny rule for one source, destination, protocol and port, in the NSG you named for DENIS's rules: `denis-<tag>-<id>` (inbound) and `denis-<tag>-<id>-o` (outbound), and `-r` and `-ro` for the way back when both directions are asked for. | Only with the per-instance switch *Allow DENIS to create deny rules on this firewall*. `access: Deny` only: no code path builds an allow rule. Never `*` or a network for a source or destination. It does not attach the NSG anywhere. Open connections may continue for a short time. |
| End sessions | Not available: Azure has no call DENIS uses to end sessions. | |
| Disable port | Not available: a cloud instance has no switch port. | |

Why an inbound and an outbound rule: DENIS cannot know whether your NSG is attached to the interface or subnet of the source or of the destination. An outbound rule covers the first, an inbound rule the second. A flow in both directions is four rules.

## Setup

1. **App registration.** In Entra ID (Azure AD), register an app (service principal) for DENIS and make a client secret.
2. **Role.** Give the service principal a role in the **one resource group** DENIS works in. The minimal permissions are listed below. The built-in *Network Contributor* role covers them (and more); a custom role is better.
3. **Quarantine NSG** and, if you want the host block, an **isolation NSG**: create them and give DENIS their full resource ids. DENIS never creates or edits their rules.
4. **NSG for DENIS's deny rules (only for flow blocks).** Create an NSG that is meant for DENIS's rules, **attach it** to the network interfaces or subnets of the machines it should protect, and give DENIS its full resource id. DENIS uses a band of 100 priority numbers in it (default from 100, configurable from 100 to 3997 as *First priority number for DENIS rules* in the connector settings): the lowest free numbers of the band. **DENIS refuses when a rule of yours that allows traffic has a lower number** than the number it would use, because that rule could still let the traffic through. Put your own allow rules at higher numbers (a default of 300 and up is fine).
5. Fill in the connector: *tenant id*, *client id*, *client secret* (secret), *subscription id*, *resource group*, *quarantine NSG*, optionally *isolation NSG* and *NSG for DENIS deny rules*, and the VM names never to block.
6. **Flow blocks:** tick *Allow DENIS to create deny rules on this firewall* only if you accept that DENIS writes rules in that NSG. It is off by default, and DENIS will not create or delete any rule while it is off. It needs the NSG id above. Changing it needs your password. A wrong deny rule can cut off traffic.

## Minimal permissions

| Needed for | The service principal must be allowed to (in the resource group) |
|---|---|
| All swaps and finding a machine by its address | `Microsoft.Compute/virtualMachines/read`, `Microsoft.Network/networkInterfaces/read`, `Microsoft.Network/networkInterfaces/write` (the write also covers the tags) |
| Block flow | `Microsoft.Network/networkSecurityGroups/read`, `Microsoft.Network/networkSecurityGroups/securityRules/read`, `.../write`, `.../delete` on the one NSG for DENIS's rules |
| Asynchronous writes | `Microsoft.Network/locations/operations/read` (to follow a `202` answer) |

**[verify]** the exact action names against your Azure RBAC version. DENIS never creates or edits an NSG itself, and never writes to a resource it does not list here.

## How a machine is found

The old routes take a VM name. The new actions take the machine's **private IP address**: DENIS lists the network interfaces of the resource group, finds the ones with that address, and takes the VM they are attached to. If no machine, or more than one machine, has the address, DENIS refuses and says so. It then runs the generic address guard on **every** private address of that VM (a second interface may carry DENIS itself or the gateway), and applies the protected list to the VM's name.

## Marks on the network interfaces

Each interface DENIS changes through the new actions gets four tags: `denis-owner` (this install's owner tag), `denis-action` (the action id), `denis-prior-nsg` (the NSG it had, or `none`) and `denis-nsg` (the NSG DENIS put there). Your own tags are kept. They remove themselves when the action ends. The tags make a swap visible in the portal and let DENIS find a swap whose record was lost (an orphan, listed under *Health* and removed there): an orphan is put back to its prior group only while it still carries the group DENIS swapped in. NSG rules cannot carry tags, so a rule carries `DENIS managed; owner <tag>; action <id>; by <login>; expires <time or never>` in its description (at most 140 characters) and the name `denis-<tag>-<id>`. Text you typed as a reason is never sent to Azure. DENIS deletes only rules that carry its own owner mark. A rule with a DENIS-style name that does not is never touched, and the action is refused.

**A restore never overwrites someone else's change.** When an action ends, DENIS puts an interface back only while it still carries the NSG DENIS swapped in. If an administrator pointed it somewhere else meanwhile, DENIS leaves it alone, takes off only its own tags, and notes it in the action's steps.

## Cloud behaviour

* **Eventual consistency.** Azure answers a write while the resource is still `Updating`. DENIS reads the interface or the rules again, at most four times with a pause, until `provisioningState` is `Succeeded` and the content is what it wrote. An `Updating` that does not end leaves the action *not confirmed*, never "enforced". An accepted (`202`) write is polled for up to 30 seconds.
* **Concurrent changes.** Every interface write carries the `etag` read before it (`If-Match`). If someone else changed the interface in between, Azure answers `412`, the change is not made, and a restore is repeated from a fresh read (at most three times).
* **Throttling.** Azure answers `429` (and `503` with `Retry-After`) when a subscription asks too fast. DENIS waits, at most 10 seconds each time, and repeats the request up to three times. A request that is still refused changed nothing.
* **Priority collisions.** Another writer taking the number DENIS chose is answered by Azure with a refusal that names the priority. DENIS reads the rules again and chooses again, at most three times, and refuses after that.
* **Rule limit.** An NSG holds at most 1000 rules. DENIS refuses to create rules in one that is nearly full.
* **Region and subscription.** One connector works in one subscription and one resource group. A VM outside it is not found.

## Refusals that cannot be turned off

* A flow that has an Azure platform address (168.63.129.16, the wire server, and 169.254.169.254, the metadata service) as one end: a deny rule for them would break the VM.
* An ICMP flow between IPv6 addresses: DENIS cannot verify that an Azure rule matches it.
* A machine with an interface that already carries the quarantine or the isolation group, or a tag that starts with `denis-owner`: DENIS never takes over.

## What is verified

Only against the fake ARM in `src/nac_azure/tests.rs`: the swap of every interface with its marks and `etag`, a restore of exactly what was there (a group, or none; your own tags kept), finding the machine by address (none, two, a listing in pages), the protected list on the name and on every address of the VM, a swap already in place, a refused write, a lost race (`412`), throttling (bounded), `Updating` reads (bounded), asynchronous writes (polled, failing, left *partly applied*), the flow rules (both directions, TCP, UDP, ICMP, IPv6, in the band, collisions, allow rules in front, a full band, a nearly full NSG, a rule stored with another number, a refused rule, a lost answer, the second of two refused) and their removal, orphans found by mark and removed only when they carry it, rules of another DENIS install left alone, the old routes (same calls, same effect, rows from earlier versions), the opt-in and lab-switch refusals, and expiry. **Not verified on any real subscription.**

Behaviours that are unproven vendor facts (marked **[verify]** in the code):

* `PUT` of a network interface accepts `If-Match` with the `etag` of the `GET` and answers `412` on a mismatch, and it accepts the `tags` object echoed back with DENIS's four added.
* `GET .../networkInterfaces` in a resource group lists `properties.ipConfigurations[].properties.privateIPAddress` and `properties.virtualMachine.id`.
* `PUT .../networkSecurityGroups/{nsg}/securityRules/{name}` creates a rule and answers `201`, or `202` with `Azure-AsyncOperation`, and `GET` of the NSG lists its rules with their `provisioningState`.
* Rule priorities are unique per direction (DENIS keeps them unique across both directions to be safe).
* A priority collision is answered with a `4xx` whose text names the priority.
* The rule protocol `Icmp` covers ICMPv4 only.
* A deny rule in an NSG attached to a network interface also stops traffic inside one subnet.
* The Azure RBAC action names in the table above.

## Limits

* Both IPv4 and IPv6 for flows; the quarantine and the host block find a machine by one private address of either kind.
* NSGs are **stateful**: new connections are stopped at once, but a connection that was already open may continue for a short time. DENIS cannot end it.
* A flow rule works only where the NSG is attached. DENIS does not check where.
* An NSG on a subnet and an NSG on a network interface are both evaluated, in series: a deny in either denies. The swap changes only the interface's group.
* NAT: an NSG sees the private addresses of the interface.

## Credentials

Azure AD app-only OAuth2, client-credentials grant: `tenant_id` and `client_id` are plain configuration, the client secret is stored only in the encrypted secret store (`nac.azure.client_secret`). A token is fetched fresh for every call and never cached. The secret is never written to the ledger, the audit log or a notification.

## Existing instances

Instances from earlier versions keep working and nothing changes for them: the same swap of every interface by VM name, the same calls (no tags, no `If-Match`), the same restore of each interface's original group. One difference in the record: the original groups of an interface are now written to the record's undo data, before the first change, and no longer into its target; a record made by an earlier version keeps them in its target and is still released. The old *Block…* and *Unblock…* buttons act as before. Records the old routes made are released through the old *Unblock…*; records of the new actions are released through the new action list.
