# Enforcement: Proxmox VE

Status: **Experimental. Simulator only: not yet validated on real equipment.** Everything below was built from Proxmox VE's published API reference and checked against a fake Proxmox cluster in DENIS's own tests. It has never been run against a real cluster. Nothing here is listed as validated on hardware.

Lab use: the guest isolation (the block that existed before 4.1) is allowed only while an administrator has switched on *Allow connectors that are not validated on real equipment (lab use)* under *Settings → Response policy*. The actions new in 4.1 (flow block, quarantine, link down) additionally need *Allow experimental actions (lab use)*. Releasing an action and removing what DENIS made always work.

Besides the connector's own refusals, every action through it is refused for a loopback, unspecified, broadcast or multicast address, for DENIS itself and for the gateway, for the addresses on this connector's protected list, for a guest that holds such an address, for a guest on the **Never quarantine these guests** list and for an address in an open `arp_conflict` alert (unless the administrator ticks a box to accept that), before anything is sent. Releasing is never refused for these reasons.

## What DENIS can do on a Proxmox cluster

A guest is a virtual machine (`qemu`) or a container (`lxc`). The old route names it as `node/qemu/ID` or `node/lxc/ID`. The new actions name a device by its **address**, and DENIS finds the guest that owns it (see *How a guest is found*).

| Action | What DENIS writes | What it does not do |
|---|---|---|
| **Block device** (isolate the guest) | The guest's own firewall options: `enable=1`, `policy_in=DROP`, `policy_out=DROP`. The options as they were are recorded first and put back exactly when the action ends. | It does not cut a connection that is already open (see the limits below). It never writes a rule. |
| **Quarantine** (cluster IP set) | One address of the guest, added to a **cluster IP set you made** (Datacenter, Firewall, IPSet), with a comment that marks it as DENIS's. Removed again when the action ends. | It never creates or edits the set, and **never writes an allow rule**. What a quarantined guest may reach is decided by your own firewall rules that use the set (a security group, or rules at the datacenter level). DENIS does not check them. |
| **Block flow** (deny rule) | One `DROP` rule per direction in the firewall of the guest that owns an end of the flow, inserted at position 0, for exactly one source, destination, protocol and port, named `denis-<tag>-<id>` in its comment. Read back. | Only with the per-instance switch *Allow DENIS to create deny rules on this Proxmox*. Deny only: no code path builds an accept rule. Never `any`, never a network, never a name. It never switches a firewall on. A rule does not cut connections that are already open. |
| **Disable port** (link down) | The guest's network device `netN` gets `link_down=1`, like pulling the plug. Put back from the device's current value when the action ends, so a change somebody else made to another property is kept. | Only a network device of a guest: never a node or its management interface. It does not touch the device's other properties. |
| End sessions | Not available: Proxmox has no call DENIS can use to end the sessions of a guest. | |

Every rule and every IP set entry DENIS makes carries `denis-<tag>-<id>; DENIS managed; owner <tag>; action <id>; by <login>; expires <time or never>` in its comment. Text you typed as a reason is never sent to the Proxmox. DENIS deletes only objects that carry its own owner marker. A rule or entry with a DENIS-style name that does not carry the marker is never touched, and the action is refused.

## How a guest is found

The action path names a device by its IP address (and hardware address when the request has one). DENIS reads `GET /cluster/resources?type=vm`, then the configuration of every guest that is not a template (the hardware address and fixed address of each `netN`, the cloud-init `ipconfigN`), and for a running guest with the agent on what the guest agent reports (and for a container its interface list). It acts only when **exactly one** guest owns the address:

* no guest has it: refused;
* more than one guest has it: refused, DENIS acts on none;
* the address and the hardware address belong to different guests: refused;
* a guest whose configuration DENIS cannot read: refused (it could be the owner);
* more than 400 guests: refused (too many to search by address).

A template is never acted on. A guest on the protected list is never acted on. A guest that holds an address of DENIS itself, the gateway, a DNS or directory server or a protected network is never acted on, whichever of its addresses was named.

**Live migration.** A guest moves between nodes and the API path contains the node. DENIS therefore looks the guest up by its id every time and uses the node it is on **now**, for the change and for the release. Before a release it checks that the machine behind the id still has the hardware addresses it had when the action was planned: if the id was reused by another machine, DENIS does not touch it and the release stays open and loud. A guest that no longer exists has nothing left to restore, and the release says so.

## Setup

1. **API token.** In Proxmox VE create a user for DENIS and an **API token** for it (Datacenter, Permissions). Give the token a role with only what DENIS needs, on the path `/vms` (or on single guests):
   * `VM.Audit` to read guests, their configuration and their firewall,
   * `VM.Config.Network` to change a guest's firewall options and rules and the link of a network device (the old isolation needs it too),
   * `VM.Monitor` (Proxmox 7) or `VM.GuestAgent.Audit` (Proxmox 8) so that DENIS can ask the guest agent for addresses (optional; without it a guest is found only by the addresses in its configuration) **[verify]**.
   For the quarantine IP set and for the checks that the firewall is on, the token also needs `Sys.Audit` on `/` (to read the cluster firewall options and the IP sets) and `Sys.Modify` on `/` (to change an IP set). Proxmox has no narrower privilege for the cluster firewall **[verify]**. If you do not use the quarantine, `Sys.Audit` alone is enough. Untick *Privilege Separation* or give the token the role itself.
2. **Connector settings** under *Network → Equipment* → **Proxmox VE** → **Add…**: the **base URL** (`https://<host>:8006`), the **token user** (`user@realm`, for example `denis@pve`), the **token id**, the **token secret**, whether to **verify the TLS certificate** (Proxmox ships a self-signed certificate on every node, so leave it off only if you have not replaced it), and *Never quarantine these guests*: `100`, `qemu/100`, `pve1/100` or `pve1/lxc/100`. **Put the guest DENIS itself runs in on this list.**
3. **Quarantine IP set (optional).** Create a cluster IP set (Datacenter, Firewall, IPSet) and **your own rules** that use it: for example a security group that allows what a quarantined guest needs (DHCP, DNS, NTP, a remediation server) and drops the rest, included in the firewall of the guests, or datacenter rules. DENIS never creates these. Enter the set's name in *Quarantine IP set name*. Leave it empty to switch quarantine off.
4. **The firewall must be on.** Proxmox applies a guest's firewall settings only when the firewall is switched on for the datacenter (Datacenter, Firewall, Options), for the node and for the guest, and a network device is filtered only when *Firewall* is ticked on that device. For the new actions DENIS checks this and refuses if it is not so (a flow block also needs the guest's own firewall on; DENIS never switches a firewall on for it). The old isolation does not check, as before: it sets the guest's own options and nothing else.
5. **Flow blocks:** tick *Allow DENIS to create deny rules on this Proxmox* only if you accept that DENIS writes rules in your guests' firewalls. It is off by default, and DENIS will not create or delete any rule while it is off. Changing it needs your password. A wrong deny rule can cut off traffic.

## How a flow block is placed

A rule is created with `pos=0`, so it is the first rule of the guest. DENIS then reads the guest's rules back: if the rule is not there, is not what was planned, or an enabled rule that is not DENIS's own comes before it, DENIS refuses and removes it again. The rule goes on the guest that owns an end of the flow: an `out` rule on the source's guest and an `in` rule on the destination's guest (both when both are guests, on different nodes if need be). For both directions the same is done for the reverse flow. A flow of which neither end is a guest of this Proxmox is refused. Rules of one action are named `denis-<tag>-<id>`, `-2`, `-3`, `-4`.

## What is verified

Only against the fake Proxmox server in `src/nac_proxmox/connector/tests.rs`: finding the guest (a fixed address, the agent, a container, the hardware address, ambiguity, a mismatch, a guest that cannot be read, a vanished guest, too many guests), the old isolation with the same calls as before, creating, finding, positioning and deleting a rule with the digest (TCP, UDP and ICMP, ranges, both directions, two guests on two nodes), the IP set (add, a foreign entry, a missing set, an entry taken over by an administrator), the link (a qemu device and a container device, a change kept on release, a pending change that does not count), the opt-in and lab refusals, the firewall checks, lost and dropped answers on every write (the action is *not confirmed* and can still be released), a refused step (compensated, nothing left behind, or *partly applied* and still releasable), a guest that migrates, an id that now belongs to another machine, a deleted guest, orphans, expiry, and the secrets never appearing in the ledger or the audit log.

Behaviours that are unproven vendor facts (marked **[verify]** in the code):

* `GET /cluster/resources?type=vm` lists every guest the token may see, with `node`, `vmid`, `type`, `status` and `template`.
* The configuration lists `netN` as `model=MAC,bridge=...,firewall=1,link_down=1` (qemu) or `name=eth0,hwaddr=MAC,ip=A.B.C.D/N,...` (lxc), the cloud-init addresses as `ipconfigN`, and carries a `digest` that `PUT .../config` accepts as a guard.
* `GET .../agent/network-get-interfaces` (qemu) and `GET .../lxc/{id}/interfaces` list the addresses of a running guest.
* `POST .../firewall/rules` accepts `pos=0`; `GET .../firewall/rules` lists `pos`, `type`, `action`, `source`, `dest`, `proto`, `dport`, `enable` and `comment`; `DELETE .../firewall/rules/{pos}` takes `digest`. A comment of up to 255 characters is accepted.
* The firewall rule `proto` accepts `tcp`, `udp`, `icmp` and, for IPv6, `ipv6-icmp`; `dport` accepts `80` and `5000:5010`.
* `GET /cluster/firewall/options` and `/nodes/{node}/firewall/options` tell whether the firewall is on; the node setting defaults to on.
* `POST /cluster/firewall/ipset/{name}` with `cidr` and `comment`, and `DELETE .../ipset/{name}/{cidr}`; an entry keeps the comment.
* `link_down` is a property of `netN` for both kinds of guest, a running qemu guest applies it at once, and `GET .../config?current=1` shows what is applied (DENIS counts a change as done only when both views show it; when Proxmox refuses the question it trusts the configuration).
* A cluster IP set only filters guest traffic through rules that use it, and which rules reach a guest's traffic depends on your Proxmox version and firewall (iptables or nftables).
* A new rule or policy stops new connections. The packet filter accepts packets in the connection tracking states `ESTABLISHED` and `RELATED` ahead of the policy, so a connection that is already open may stay up. The API has no call that flushes the tracking table of a guest. The read-back confirms the stored configuration; `pve-firewall` recompiles the rule set on its own schedule and no call confirms that it has caught up.
* Changing the firewall options or a rule needs only `VM.Config.Network` on the guest.

## Limits

* One address per request: IPv4 and IPv6 are both accepted for host actions and flows.
* Traffic between two guests on the same bridge is filtered only when the firewall is on for both, and a rule on one does not cover the other.
* The old isolation sets the guest's options for all its network devices; whether a device with no *Firewall* tick is filtered is Proxmox's decision, and DENIS does not check it on the old route.
* A flow block is a guest firewall rule: it does not change what the node or the datacenter firewall does.
* End sessions is not available.

## Credentials

A Proxmox API token: *token user* and *token id* (plain) and the *token secret*, stored only in the encrypted secret store (`nac.proxmox.token_secret`) and sent as `Authorization: PVEAPIToken=user@realm!tokenid=secret`. It is never written to the ledger, the audit log or a notification.

## Existing instances

Instances from earlier versions keep working and nothing changes for them: the same guest address (`node/qemu/ID`), the same API calls in the same order (read the options, write them, read them back), the same ledger row with the options as they were, and the old *Block…* and *Unblock…* buttons act as before. The connection test only checks that the configuration is complete: there is no harmless request that does not name a guest, so the cluster is first contacted when you plan a block. Records the old routes made are released through the old *Unblock…*; records of the new actions are released through the new action list. What changed is only who writes the record: the ledger row is now written by the enforcement orchestrator, which also applies the hourly cap and the kill switch and stamps the row with the connector instance.
