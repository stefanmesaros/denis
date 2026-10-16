# Enforcement: Cisco Meraki

Status: **Experimental. Simulator only: not yet validated on real equipment.** Everything below was built from Meraki's published Dashboard API documentation and checked against a fake Dashboard in DENIS's own tests. It has never been run against a real organization. Nothing here is listed as validated on hardware.

Lab use: the client block (the pre-4.1 action) is allowed only while an administrator has switched on *Allow connectors that are not validated on real equipment (lab use)* under *Settings → Response policy*. The actions new in 4.1 (quarantine by group policy, switching off a switch port) additionally need *Allow experimental actions (lab use)*. Releasing an action always works.

Besides this connector's own refusals, every action through it goes through DENIS's common guards before anything is sent: loopback, unspecified, broadcast and multicast addresses, DENIS itself, the gateway, and an address or MAC in an open `arp_conflict` alert are refused, and a list DENIS cannot read refuses the action.

## The three Meraki options

Meraki gives DENIS three different ways to act, and they are not equal. DENIS uses the first two and deliberately does not use the third.

| Option | Used for | What DENIS writes | What it does not do |
|---|---|---|---|
| **1. Client policy** `Blocked` | **Block device** | `PUT /networks/{id}/clients/{mac}/policy` with `devicePolicy = "Blocked"`. The policy the client had (including a group policy id) is recorded and put back when the action ends. | It blocks by MAC address, not by IP address. It does not cut a connection that is already open on every product line (see below). |
| **2. Group policy** | **Quarantine** | The same endpoint with `devicePolicy = "Group policy"` and the `groupPolicyId` of the group policy **you** made for quarantine. The prior policy is put back when the action ends. | It never creates or edits a group policy. What the group policy allows is your own definition, and DENIS does not check it. A client that is blocked is refused (moving it to quarantine would loosen the block). |
| **3. MX layer 3 firewall rules** | nothing | nothing | **Not built, neither for a flow block nor for a host block.** `PUT .../appliance/firewall/l3FirewallRules` replaces the whole rule list in one call with no revision number. Two writers lose each other's rules, and a list that comes out wrong can lock the network out. DENIS would have to read the whole list, add one tagged rule and write the whole list back, and nothing in the API lets it refuse when the list changed in between. A host block through a `/32` deny rule was weighed and left out for the same reason. |

Two more things, both on **MS switches**:

| Action | What DENIS writes | What it does not do |
|---|---|---|
| **Disable port** | `PUT /devices/{serial}/switch/ports/{portId}` with `enabled = false` on one port of an MS switch in the configured network, then reads the port back. Released with `enabled = true`, only when the port is still down. | Never an uplink (the port the Dashboard reaches the switch through), a trunk, a member of a link aggregation, a port with an LLDP or CDP neighbour, or a port DENIS cannot show to be a plain access port. It is also refused when the port is already off. |
| Quarantine by VLAN (`access_vlan`) | Not built in this release. | |
| End sessions | Not available: Meraki documents no way to end a session on an MX or MS. | |

A flow block (a deny rule for two hosts) is **unsupported** on Meraki, for the reason in option 3. It is shown greyed out with that reason.

## Setup

1. **API key.** In the Dashboard create an API key for a **dedicated administrator account** (Organization → Settings → Dashboard API access, then the user's own profile → API access). The role is *Network admin* (read and write) on the one network DENIS manages. *Read-only* is enough for testing and reading but cannot block. Do not use an organization administrator. Keep the key out of anything but DENIS: the key is sent as the `X-Cisco-Meraki-API-Key` header on every call and stored only in the encrypted secret store (`nac.meraki.api_key`).
2. **Organization and network.** Note the **organization id** and **network id** (both are in the Dashboard's URLs; a network id looks like `L_646829496481099333`). DENIS checks that the network belongs to the organization (`GET /networks/{id}` returns `organizationId`) and refuses the new actions when it does not, and a port action needs a network that has switches.
3. **Quarantine group policy (optional).** In the Dashboard create a group policy (Network-wide → Group policies) and set what a quarantined client may do: DHCP, DNS, a remediation server, nothing else. DENIS never creates or edits it. Enter its **name or id** in *Quarantine group policy*. Leave it empty to switch quarantine off for this network.
4. *Network → Equipment* → **Cisco Meraki** → **Add…**: the Dashboard API address (`https://api.meraki.com`; a regional shard such as `api.meraki.cn` or `api.gov-meraki.com` only if your organization lives there), organization id, network id, the API key, the MACs never to block (DENIS itself, the gateway, your access points and switches), and the quarantine group policy.
5. **For a port action:** the target is the switch's **serial number** and the **port id** as the Dashboard shows it (for example `7`). Only an MS switch of the configured network is accepted.

## Rate limits

The Dashboard API allows about ten requests a second per organization and answers `429` with a `Retry-After` (seconds) when that is exceeded. A `429` means the request was **not processed**, so DENIS waits for the time given (at most 10 seconds, at most three times) and sends it again. When the waiting runs out the action is refused with nothing changed, never recorded as "unknown". The old routes use the same waiting. A port action makes four to six read calls before the write; a client action two.

## Unblock and release

* **Client block:** the prior policy is read **before** the block and written into the ledger row **before** the Dashboard is touched, so a lost answer cannot leave a client blocked with its old policy forgotten. Releasing puts that policy back exactly (a group policy id included). If the client is no longer blocked (someone changed it), DENIS leaves it alone and says so in the steps. With no ledger record DENIS falls back to `Normal` only on the old route, and refuses to remove a block it has no record of.
* **Quarantine:** the same, only while the client is still in DENIS's group policy.
* **Port:** only while the port is still switched off.
* The old routes (the *Block…* and *Unblock…* buttons of earlier versions) make **the same Dashboard calls and write the same ledger row** as before: a read, a write, a read back; the row records `mac`, `network_id`, `organization_id`, `prior_policy` and `prior_group_policy_id`.

## Orphans, and why a client policy cannot be listed

A client policy has no name and cannot carry a marker, so DENIS cannot find, from the Dashboard alone, a client that it left blocked. The record is the ledger: the row's target and undo data hold the MAC, the prior policy and the prior group policy, and a client DENIS blocked stays visible in *Active responses* until it is released or expires. The only Meraki object with a name is a group policy, and DENIS makes none. The orphan check therefore lists group policies named `denis-<tag>-...` (a name that claims to be made by this installation) and never deletes one: remove it in the Dashboard if it is not in use.

## What is verified

Only against the fake Dashboard in `src/nac_meraki/orch_tests.rs` (and the earlier tests in `src/nac_meraki.rs`): the old routes make the same calls and ledger row as the pre-4.1 code; block and release with the prior policy (normal, whitelisted, group policy); refusal of an unknown, already blocked or protected client and of an IP address; quarantine by group policy name and id, restoring a prior group policy, refusal of a blocked client, a client already there and a missing group policy; a release that leaves a client alone that someone else changed; lost answers, refused writes and server errors; a network in the wrong organization; disabling a port (read back, released, left alone when someone switched it on), every hard refusal (uplink, trunk, LLDP, CDP, link aggregation, already off, not a switch, another network's switch, unknown port, bad port id, statuses unreadable); a port that changes between the plan and the apply; `429` waits and an endless `429`; lab refusals sending zero requests. **Not verified on any real Meraki organization.**

Behaviours that are unproven vendor facts (marked **[verify]** in the code):

* `GET /networks/{id}` returns `organizationId` and `productTypes`; `GET /networks/{id}/groupPolicies` lists `groupPolicyId` and `name`.
* `GET /devices/{serial}` returns `networkId` and `model` (`MS...` for a switch).
* `GET` and `PUT /devices/{serial}/switch/ports/{portId}` read and change `enabled` and `type` (`access` or `trunk`), and a `PUT` answers the port as it is now. DENIS treats a `PUT` that answers without the port as unknown, not as done.
* `GET /devices/{serial}/switch/ports/statuses` reports `isUplink`, `lldp` and `cdp` per port. A port with no `isUplink` is unknown and refused.
* `GET /networks/{id}/switch/linkAggregations` lists each aggregation's member `serial` and `portId`.
* Whether a client policy `Blocked` ends a connection that is already open depends on the product line: an access point removes a blocked client from the SSID, a switch or an appliance applies a traffic policy that stops new traffic but is not documented as tearing down an open session.
* The rate limit of about ten requests a second and the `Retry-After` header in seconds.

## Limits

* One network per connector instance.
* A client is named by its **MAC address**. A target with only an IP address is refused. Traffic inside the client's own subnet does not pass an MX and is not affected by a policy enforced there.
* MR access points are blocked through the client policy; their ports are not ports.
* Switch ports only on MS switches of the configured network. A stacked or modular port id is accepted as the Dashboard shows it.

## Credentials

A single Dashboard API key (`nac.meraki.api_key`), sent as the `X-Cisco-Meraki-API-Key` header on every call: there is no session and nothing is kept between calls. It is never written to the ledger, the audit log or a notification.
