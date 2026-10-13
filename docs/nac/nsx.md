# Enforcement: VMware NSX-T

Status: **Experimental. Simulator only: not yet validated on real equipment.** Everything below was built from VMware's published NSX-T Policy API reference and checked against a fake NSX Manager in DENIS's own tests. It has never been run against a real NSX Manager. Nothing here is listed as validated on hardware.

Lab use: the host block (group) is allowed only while an administrator has switched on *Allow connectors that are not validated on real equipment (lab use)* under *Settings → Enforcement*. The actions new in 4.1 (quarantine, flow block) additionally need *Allow experimental actions (lab use)*. Releasing an action and removing what DENIS made always work.

Besides the connector's own refusals, every action through it is refused for a loopback, unspecified, broadcast or multicast address, for DENIS itself and for the gateway, for the addresses on this connector's protected list, for an address in an open `arp_conflict` alert (unless the administrator ticks a box to accept that) and for the address of NSX Manager itself, before anything is sent. Releasing is never refused for these reasons.

Targets **NSX-T 3.x and 4.x** through the Policy API of a single, non-Federation NSX Manager (a "Local Manager"), not a Global Manager that fronts several sites.

## What DENIS can do on NSX-T

| Action | What DENIS writes | What it does not do |
|---|---|---|
| **Block device** (group) | One IPv4 address, added to the static `IPAddressExpression` of the group you created for blocks. The write carries the group's `_revision` and then waits for NSX to report the change as realized. | It never creates or edits the rule that uses the group, the policy or the domain. Open connections are not cut: the distributed firewall keeps its state table, so the block stops new connections. |
| **Quarantine** (quarantine group) | The same, into a second group you created for quarantine. **Membership only.** | It never creates an allow rule and never edits your rules. What a quarantined device may reach is decided by your own distributed firewall rules for that group (DHCP, DNS, NTP, a remediation server). DENIS does not check them. |
| **Block flow** (deny rule) | One distributed firewall rule per direction in the security policy you name, `denis-<tag>-<id>` (and `-r`): action `DROP`, both ways, logged, for exactly one source, destination, protocol and port, with the lowest free sequence numbers of that policy. Then DENIS reads the rules back and checks that the rule is in place and ahead of every rule that is not DENIS's. | Only with the per-instance switch *Allow DENIS to create deny rules on this firewall*. Deny only: no code path builds an allow rule. Never `ANY` for a source or destination, never a group or a network. A new rule does not cut connections that are already open. |
| End sessions | Not available. | NSX Manager has no call that ends the open connections of an address. That can be done only on the ESXi host's own command line, which DENIS does not reach. |
| Disable port | Not available: NSX has no switch port DENIS can switch off. | |

Every rule DENIS makes has the id and display name `denis-<tag>-<id>`, two NSX tags (`denis-owner` with this install's owner tag, and `denis-action` with the action id) and the description `denis-<tag>-<id>; DENIS managed; owner <tag>; action <id>; by <login>; expires <time or never>`. Text you typed as a reason is never sent to NSX. DENIS deletes only rules that carry its own `denis-owner` tag. A rule with a DENIS-style name that does not carry the tag is never touched, and the action is refused. An entry in a group cannot carry a tag, so a group entry is never listed as an orphan: if a record of one is lost, remove the address from the group by hand.

## Setup

1. **Block group.** In NSX Manager create a **group** (*Inventory, Groups*) dedicated to DENIS, with a static IP address expression (it can start empty), and a distributed firewall **deny rule** that uses the group, near the top of a security policy. **DENIS owns this group's whole `IPAddressExpression`.** Do not add other IP addresses to it by hand: DENIS's next read-modify-write replaces the list it read. An expression of another kind (a tag or name condition) in the same group is written back untouched.
2. **Quarantine group (optional).** Create a second group of the same kind and your own rules for it (allow DHCP, DNS, NTP and the remediation server, deny the rest). Give DENIS its id. Leave the setting empty to switch quarantine off.
3. **Security policy for deny rules (only for flow blocks).** Create a security policy (*Security, Distributed Firewall*) that is meant for DENIS's rules, in the same domain, and give DENIS its id:
   * its **applied to** must be the whole distributed firewall (`DFW`). DENIS refuses a policy with a restricted scope, because a rule in it would not cover every workload;
   * it must be the **first policy of its category**. DENIS refuses a policy that has another policy of the same category before it. The **Emergency** category is evaluated before all others and is the right place. A policy of an earlier category (Ethernet, Emergency, Infrastructure, Environment come before Application) is evaluated first and can still decide first: DENIS can only warn about that;
   * DENIS puts its rules at the lowest free sequence numbers below every rule that is not DENIS's. If your own rules in that policy start at number 0, or leave no number free before them, DENIS refuses. The simplest policy is one that holds nothing but DENIS's rules.
4. **NSX Manager account.** Create an account for DENIS and give it a role that can read and write groups and security policies of the domain. **[verify]** The built-in *Security Engineer* role does this; it is broader than DENIS needs, and NSX-T has no way to build a narrower role by hand. For a connector that only blocks and quarantines through groups (no rules) the same role is needed for the group write. Reading, testing and releasing need the same account.
5. **Domain id.** NSX-T's single-site default is `default`.
6. Fill in the connector: *Base URL*, *username*, *password* (secret), *domain id*, *block group id*, optionally *quarantine group id* and *security policy for DENIS deny rules*, and the IP addresses never to block.
7. **Flow blocks:** tick *Allow DENIS to create deny rules on this firewall* only if you accept that DENIS writes rules on this NSX Manager. It is off by default, and DENIS will not create or delete any rule while it is off. It needs the security policy id above. Changing it needs your password. A wrong deny rule can cut off traffic.

## Realization, and what "done" means

NSX stores what DENIS writes as *intent* and then realizes it on the hosts, a moment later. DENIS therefore records **wait for realization** as a step of its own after every write, asks for the realized state of the group or the policy, one second apart, at most 30 times:

* `success` or `partial_success` is done;
* `failed` is a refused action: the change DENIS saved is taken back again, the action ends *failed*, and if that clean-up cannot be realized either, the action is *partly applied* and stays active until it is released;
* a poll that runs out without an answer leaves the action *not confirmed*: the change is saved in NSX and may well be in force, but DENIS does not say so. It can still be released, and the reconcile job looks again.

The read-back after a write reads the group or the rule list again, a few times with a short pause (a manager that answers from a replica may lag a moment behind), and counts the change as in force only when it sees it and the action's own realization step finished.

## Concurrent edits and rate limits

* **A group write carries the `_revision` that was read.** If someone else changed the group in between, NSX refuses the write (`409` or `412`), and DENIS reads the group again and repeats the change, at most three times, instead of overwriting the other edit. After the third attempt it refuses and says so; the group is unchanged. The old routes (below) keep their earlier behaviour and do not send a revision.
* **Rate limits.** NSX Manager answers `429` with a `Retry-After` when a client asks too fast. DENIS waits (at most 10 seconds each time) and repeats the request, at most three times. A `429` that does not go away is a refusal that changed nothing.

## Minimal permissions

| Needed for | What the NSX Manager account must be allowed |
|---|---|
| Block device, Quarantine | Read and write on the two groups (`GET` and `PATCH /policy/api/v1/infra/domains/{domain}/groups/{group}`) and read the realized state (`GET /policy/api/v1/infra/realized-state/status`) |
| Block flow | Additionally: read the security policy and list the policies of the domain; list, create and delete rules of the one policy (`GET`, `PUT`, `DELETE .../security-policies/{policy}/rules/{rule}`) |

**[verify]** the role names and whether a scope limited to one domain is possible in your NSX-T version. DENIS never creates a group or a policy, and never changes the policy's own settings.

## What is verified

Only against the fake NSX Manager in `src/nac_nsx/tests.rs`: the group write with the revision, a lost race (retried, then refused), `429` waits (bounded), a lagging read-back (bounded), the realized-state step with its failure, its poll running out and its compensation, the quarantine group (only `PATCH` of the group, nothing else is ever sent), creating, finding by name, checking the position of and deleting the rule (both directions, TCP, UDP and ICMP for IPv4 and IPv6, port ranges, a listing in several pages), a refused rule (nothing left behind), a lost answer on the rule (the action is *not confirmed* and can still be released), the second rule of a flow refused (the first is taken back), a manager that renumbers the rule behind yours, the policy checks (missing, restricted scope, not first of its category, no free sequence number), the opt-in and lab-switch refusals, orphans found by tag and removed only when they carry it, rules of another DENIS install left alone, and expiry. **Not verified on any real NSX Manager.**

Behaviours that are unproven vendor facts (marked **[verify]** in the code):

* `PUT /infra/domains/{d}/security-policies/{p}/rules/{id}` creates a rule with that id, and `GET .../rules` lists the rules of one policy (with a `cursor` for the next page).
* `source_groups` and `destination_groups` accept a single IP address (IPv4 and IPv6), `service_entries` accept an `L4PortSetServiceEntry` (`l4_protocol`, `destination_ports`) and an `ICMPTypeServiceEntry` (`protocol` `ICMPv4` or `ICMPv6`), and `services: ["ANY"]` means every service.
* A lower `sequence_number` is evaluated first inside a policy, and the policy's `category` and `sequence_number` order the policies as DENIS reads them.
* `PATCH` of a group with the `_revision` read before answers `409` or `412` when the group changed meanwhile.
* The realized-state query answers for a security policy path and for a group path, with `state` `success`, `partial_success`, `failed` or another value while it is in progress.
* A new rule does not end connections that are already open (the distributed firewall keeps its state table).
* `PATCH` of a group's `expression` replaces the list (JSON merge patch) and leaves the other fields alone.

## Limits

* The block group and the quarantine group hold **IPv4** addresses only (a group action refuses an IPv6 address). A flow can be IPv4 or IPv6.
* The distributed firewall filters traffic between two machines of one subnet too (it is enforced on the host's virtual network card), so a flow rule here can stop east-west traffic that a gateway firewall never sees.
* A flow rule is first within its policy, not first of all policies. See the setup above.
* A deny rule for a flow in both directions is two rules (`denis-<tag>-<id>` and `denis-<tag>-<id>-r`).
* NAT: the distributed firewall sees the addresses of the virtual machine's own interface, before any NAT of an edge gateway.
* IPv4 hosts are blocked and quarantined by their address, not by the virtual machine: a machine whose address changes escapes until the next action.

## Credentials

The user name is plain configuration. The password is stored only in the encrypted secret store (`nac.nsx.password`) and sent as HTTP Basic authentication on every request. It is never written to the ledger, the audit log or a notification.

## Existing instances

Instances from earlier versions keep working and nothing changes for them: the same block group, the same read and `PATCH` of its `expression`, the same realization poll that is only a note, the same ledger rows. The old *Block…* and *Unblock…* buttons act as before. Records the old routes made are released through the old *Unblock…*; records of the new actions are released through the new action list.
