# Enforcement: Cisco Secure Firewall Management Center (FMC)

Controls Cisco Secure Firewall Threat Defense (FTD) firewalls that are managed centrally (formerly Firepower Management Center).

Status: **Block device through the dynamic object is verified in the Cisco DevNet sandbox, on a virtual FMC 7.7.12, 29 October 2026. Everything else of this connector is Experimental.** "Verified" means exactly what was run: *Test connection*; the plan; the apply, which ended `enforced` (the address mapping was added to the dynamic object, confirmed by DENIS's read-back and by an independent, fresh sign-in to the FMC); the release, which ended `restored` (the mapping was gone again, confirmed the same way); and the test object was deleted afterwards. It was a virtual FMC, not a physical device, and DENIS does not call it real equipment. Still Experimental, checked only against a fake FMC in DENIS's own tests: the block through a network group (with deployment), the quarantine (dynamic object and network group) and the flow block with a deny rule. End sessions is not possible through FMC's REST API.

Lab use: block device through the dynamic object needs neither lab switch. Every other action of this connector needs both switches under *Settings → Response policy*: *Allow Experimental connectors (lab use)* and *Allow experimental actions (lab use)*, and carries the Experimental mark. Releasing an action and removing what DENIS made always work.

This page is for an FTD device that is managed by an FMC. An FTD device managed on the box itself (FDM) is a different connector.

## Two ways to act, and which to choose

| | Dynamic objects | Network groups and deployments |
|---|---|---|
| Used for | Block device, Quarantine | Block device, Quarantine, **Block flow** |
| What DENIS writes | One address added to (and later removed from) the *mappings* of a dynamic object you created | A host object, added to a network group you created (or, for a flow, a deny access rule at the top of the access policy), then a **deployment** |
| Deployment | **None.** FMC pushes the change to the devices (needs FMC 7.0 or later, **[verify]**) | **Yes.** A job that takes seconds to about ten minutes |
| Pending changes of other people | Not touched | A deployment carries every pending change on the listed devices, so DENIS **refuses** while another administrator has any |
| Speed | Seconds | Minutes |

Use dynamic objects when you can. Use network groups when your FMC version has no dynamic object API, or when you want to block a single flow. On an FMC that other people also work on, prefer dynamic objects: a deployment publishes everyone's pending changes on the listed devices, and DENIS refuses to deploy while there are any.

## What DENIS can do

| Action | Method | What DENIS writes | What it does not do |
|---|---|---|---|
| **Block device** | `dynamic_object` | The device's address, as a mapping of the dynamic object you named for blocks. | It never creates or edits the access rule that uses the object. It removes only an address it put in itself, and refuses an address that is already in the object. |
| **Block device** | `network_group` | One host object `denis-<tag>-<id>`, added to the network group you named for blocks, then a deployment to the devices you listed. | It never creates or edits the rule that uses the group. It refuses an empty group, and never takes the last member out of a group. |
| **Quarantine** | `quarantine_dynamic_object`, `quarantine_network_group` | The same, into a second dynamic object or network group you created for quarantine. | It never creates an allow rule and never edits your rules. What a quarantined device may reach is decided by your own access rules for that object or group (DHCP, DNS, a remediation server). DENIS does not check them. |
| **Block flow** | `deny_rule` | One **block** access rule `denis-<tag>-<id>` for exactly one source host, destination host, and optionally one protocol and port or port range, placed at the top of the access policy you named and checked there, plus a host object for each address, then a deployment. In both directions: a second rule `denis-<tag>-<id>-r`. | Only with the per-instance switch *Allow DENIS to create deny rules on this firewall*. Deny only: no code path builds an allow, trust or monitor rule. Never a network, a name or an address other than the two hosts. ICMP is not built. |
| Disable port | Not available | | A firewall has no access port DENIS can switch off. |
| End sessions | Not available | | FMC has no REST call that ends the connections of one address. |

Every object DENIS makes carries `DENIS managed; owner <tag>; action <id>; by <login>; expires <time or never>` in its description (a host object) or comment (an access rule). The text you typed as a reason is never sent to the FMC. DENIS deletes only objects that carry its own owner tag. An object with a DENIS-style name that does not carry the tag is never touched, and the action is refused.

A dynamic object mapping is only an address: it has no name and no description, so it carries no marker. DENIS records in the action's undo data that the address was not in the object before, and takes it out again only because of that record. Mappings are therefore not listed as orphans.

## The deployment

A change in the FMC's configuration does nothing on a device until a deployment job pushes it, and **a deployment carries every pending change on the devices it names, whoever made it, and affects every device in it.** That is the most important fact about network groups and rules on an FMC, and DENIS treats the deployment as part of the action, not as a footnote:

* **DENIS refuses to deploy while someone else has pending changes.** Before the first write it reads the pending changes of the devices you listed (`deployabledevices` and `pendingchanges`, who made each one) and refuses when any belongs to another account. If it cannot read who made them, it refuses too. It reads them again right before it deploys. Your own earlier unfinished DENIS work, made with the same FMC account, does not count.
* **The deployment is waited for.** DENIS starts the job and polls its status for up to ten minutes. The action stays *pending* while it waits, and the steps record how long it took.
* **A deployment is never assumed.** The action is *enforced* only when the job reported success, the listed devices show nothing pending, and the configuration reads back as DENIS wrote it. A job that is still running when the wait ends, or whose answer is lost, leaves the action *unconfirmed*: it stays active, expires like any other, and a later check or release settles it.
* **A deployment that fails publishes nothing.** DENIS deletes its own pending objects (no deployment is needed for that, because nothing was deployed). The action ends *failed*. If even that removal is refused, it ends *partial* and stays releasable.
* **Releasing** deploys the withdrawal again when something of the action may have reached the devices (a deployment that ended without a usable answer counts). A release that needs a deployment while another administrator has pending changes **changes nothing and stays active**, loud, and is tried again later.
* **Which devices.** The deployment goes to the devices listed in the connector's settings, by name or ID, and only to them. An access policy that is assigned to other devices as well leaves those devices with a pending change that nobody deploys; assign it to the listed devices only.
* **Interruption.** Depending on what else is pending, a deployment can briefly interrupt traffic inspection on a device (FMC restarts the inspection process for some changes, **[verify]**). The plan says so for every action that deploys.

Dynamic object changes need none of this and are not held back by other people's pending changes.

## Setup

1. **A dedicated FMC account** for DENIS, with REST API access. Its role needs to read and write objects (network objects, network groups and, for dynamic objects, dynamic objects), to read and write the access policy (only for flow blocks), to read devices, and to deploy configuration (only for network groups and flow blocks). A custom role with exactly those rights is better than Administrator (**[verify]** the exact permission names of your FMC version). Restrict the account's login to the DENIS machine if your FMC allows it. Use a different account from the ones people use in the web interface: pending changes are told apart by account name, and DENIS's own are the ones it does not mind. A new sign-in with the same account can also end the earlier session's token (seen on FMC 7.7.12: "Access token invalid" while a person was signed in with DENIS's account).
2. **Block object (dynamic object mode).** In FMC create a dynamic object of type IP (*Objects → Object Management → Dynamic Objects*) and **your own access rule** that blocks traffic from or to it, high in the policy. Enter its name in *Block dynamic object name*.
3. **Block group (network group mode, optional).** Create a network group with **at least one member** (a placeholder host such as 192.0.2.255, a documentation address that is never routed), and your own rule that blocks it. FMC does not keep an empty group, and DENIS refuses to use an empty one. Enter its name in *Block network group name*.
4. **Quarantine object or group (optional).** The same, for quarantine, and **your own access rules** that allow what a quarantined device needs (DHCP, DNS, NTP, the remediation server) and block the rest. Leave empty to switch quarantine off.
5. **Devices to deploy to** (network group and flow modes): the FTD devices by name or ID, as FMC shows them.
6. **Access policy** (flow blocks only): the name of the access policy DENIS writes its deny rules into.
7. *Network → Equipment* → **Cisco Secure Firewall Management Center (FMC)** → **Add…**: base URL, user name, password, optionally the domain, the objects and groups above, the devices, the policy, *Never block these IP addresses* (DENIS itself, the gateway, the FMC, the FTD management addresses). With a self-signed FMC certificate paste the certificate into *Pinned FMC certificate* instead of switching verification off.
8. **Flow blocks:** tick *Allow DENIS to create deny rules on this firewall* only if you accept that DENIS writes access rules on this firewall. It is off by default, and DENIS will not create or delete any rule while it is off. Turning it on needs your password again and is written to the audit log. A wrong deny rule can cut off traffic.

## How a flow block is shaped

The rule is `denis-<tag>-<id>`, action **BLOCK** (not block-with-reset), source one host object `denis-<tag>-<id>-src`, destination `denis-<tag>-<id>-dst`, and for a protocol the destination port literal (TCP is protocol 6, UDP 17, a single port or a range, or the whole protocol when no port is given), logged at the start of the connection. It is created in the mandatory section with *insert before rule 1*, so it stands first. DENIS then reads the rules back: only DENIS's own rules (same owner tag) may stand before it. If it did not land at the top, DENIS removes it and the action ends *failed*. After the deployment it checks the same thing again. An empty policy takes no position.

Rules that the policy inherits from a parent access policy, and prefilter rules, are evaluated before the rules of this policy and can still allow the flow. DENIS cannot see them; the plan says so. FTD access rules match the addresses before translation, so a destination behind a destination NAT is matched by its public address. Connections that are already open may continue until the device re-evaluates them.

## Tokens, domains and limits of the API

* **Sign-in.** DENIS signs in with the account's name and password (Basic authentication, one token request) at the start of each action and keeps no token afterwards. Use an account for DENIS alone: another sign-in with the same account can end DENIS's token in the middle of an action. A token lasts 30 minutes; when one expires in the middle of an action DENIS refreshes it (up to three refreshes), then signs in again. The password goes only into the `Authorization` header of the token request, is read from the encrypted secret store, and is never logged or written to the ledger.
* **Domains.** Without a domain name the account's default domain is used. A domain given by name or UUID is looked up in the list the FMC returns at sign-in, and DENIS refuses to run when the account has no access to it.
* **Rate limit.** The FMC API accepts about 120 requests a minute from one address (**[verify]**). DENIS paces itself under it. When the FMC answers 429 it waits for the `Retry-After` it is given (at most 30 seconds, at most three times) and repeats the request, which was not processed. When the waiting runs out the action is refused with nothing changed, never marked "unknown".
* **Lists** are read page by page, at most 40 pages of 200.
* **Lost answers.** A write that the FMC accepted but whose answer was lost is *unknown*: DENIS reads the result back, and the object names are deterministic, so a retry finds what is already there instead of making a second one.
* **One at a time.** For a network group (replaced as a whole) and for rules, DENIS holds a lock per connector while it works, reads the group again right before writing, and checks afterwards that nothing that was in the group is missing. If someone else changed the group in that moment and an entry was lost, DENIS puts it back and stops.

## Orphans

DENIS lists host objects and access rules that carry its owner tag but belong to no active action, and removes one only when you ask, and only when it carries the tag. A removed host object is first taken out of your block and quarantine groups (never leaving a group empty). Removing an orphan deploys when devices are listed, with the same refusal while another administrator has pending changes. Objects with another owner tag belong to another DENIS installation and are ignored.

## What is verified

**Against a live FMC, 29 October 2026.** Secure Firewall Management Center 7.7.12 in the Cisco DevNet sandbox (a shared FMC with one managed virtual FTD 7.2.9), with the released DENIS 4.3.0. This was a test of the REST API: nothing was deployed there, and it is not a test on hardware.

* `POST /api/fmc_platform/v1/auth/generatetoken` with Basic authentication answers 204 with the access token, the refresh token and `DOMAIN_UUID` in headers whose names come in another case than documented (DENIS reads header names case-insensitively).
* Listings of the server version, devices, network groups, hosts, networks, dynamic objects and access policies; creating and deleting a dynamic object.
* The mapping calls. DENIS 4.3.0 sent `POST .../object/dynamicobjects/{id}/mappings?action=add` (and `?action=remove`), which FMC 7.7.12 refuses with HTTP 400 ("Invalid query parameter for the POST operation"): FMC has no `action` parameter, and every `DELETE` on the mappings is refused too. The forms that work, and that DENIS now uses:
  * add: `POST .../object/dynamicobjects/{id}/mappings` with `{"mappings": ["192.0.2.77"]}` (201);
  * remove: `POST .../object/dynamicobjectmappings` with `{"remove": [{"mappings": ["192.0.2.77"], "dynamicObject": {"id": "...", "name": "...", "type": "DynamicObject"}}]}` (201); the same endpoint takes `{"add": [...]}`;
  * read back: `GET .../object/dynamicobjects/{id}/mappings` (DENIS reads `items[]` as plain addresses or objects with `mapping`, and `mappings[]`).
* A plan for a block through a dynamic object.

**Against the fake FMC** in `src/nac_ftd_fmc/tests.rs` and `src/nac_ftd_fmc/tests/orch_tests.rs` (the fake refuses the `action` parameter like the real one): sign-in, the domain lookup, token refresh and renewal, paging, pacing, 429 handling and the pinned certificate; the console's *Test connection* (read only); dynamic object mappings (add, remove through the bulk endpoint, the read-back of presence and absence, an address that is already there, a missing object or one of the wrong type, lost answers); network group blocks and quarantine with a deployment (host object, group write, deployment, release with a second deployment); another administrator's pending changes (at plan time, between plan and apply, unreadable, and on release); a deployment that is slow, fails, is refused or never ends; an empty group and the last member; a group that loses a member during the write; foreign objects with DENIS-style names; flow rules (position, both directions, port, empty policy, a rule that does not land at the top, refused creation, lost answer); orphans by marker.

**Not verified:** whether the managed devices then enforce the dynamic object's mapping; quarantine; network group mode and flow rules (they need a deployment, which was not made on the shared sandbox FMC); orphans; high availability.

Behaviours that are still unproven vendor facts (marked **[verify]** in the code):

* The devices receive a dynamic object mapping change **without a deployment** (FMC 7.0 or later).
* A network group `PUT` replaces the `objects` list and accepts the body it was read as, without `links` and `metadata`. FMC does not keep an empty group.
* `POST .../policy/accesspolicies/{id}/accessrules?section=mandatory&insertBefore=1` puts the rule first; listing the rules returns them in evaluation order; `newComments` come back as `commentHistoryList`. A rule name may be 50 characters (DENIS's are at most 40).
* `GET .../deployment/deployabledevices` lists the devices that have pending changes; `GET .../deployabledevices/{id}/pendingchanges` names who made them (`lastUser`); `POST .../deployment/deploymentrequests` answers with a task whose status `GET .../job/taskstatuses/{id}` reports (success, in progress, failed).
* Creating or deleting a host object that no policy uses does not make a device show pending changes.
* The number of requests the API allows (120 a minute), the token lifetime (30 minutes) and the three refreshes.
* Whether a deployment restarts the inspection process, and what happens to traffic meanwhile, depends on the changes it carries and on your FTD settings.

## Limits

* Network objects and groups, access rules and dynamic objects only. No NAT, prefilter, intrusion or file policy is read or written.
* Rule placement is the top of the mandatory section of one access policy. No other anchor is offered.
* IPv4 and IPv6 hosts, never a network, a range or a name.
* Traffic between two devices in the same subnet does not pass the firewall, and no rule on it stops it.
* A dynamic object mapping has no marker, so DENIS can neither list nor clean up mappings it lost track of.
* No Multi-Domain child-domain inheritance logic: objects are read and written in the one domain you name.

## Details from the console

The console shows a short line under each field and a short note behind its (i). The full explanation of each field is here.

- **Multi-Domain domain name (optional)**: The FMC domain DENIS works in, by name or UUID. Leave empty to use the default domain of this account. The account must be allowed to read and write objects in this domain.
- **Block dynamic object name**: The dynamic object you created for blocks. DENIS adds a blocked address to its mappings and takes it out again. FMC pushes the change to the devices without a deployment (needs FMC 7.0 or later). You write the access rule that blocks traffic from or to this object; DENIS never creates or edits it. Leave empty to switch this way of blocking off.
- **Quarantine dynamic object name (optional)**: The dynamic object you created for quarantine. DENIS moves a device into it and back, and nothing else: what it may reach is decided by your own access rules. DENIS never creates an allow rule. Leave empty to switch this way of quarantine off.
- **Block network group name (optional)**: A network group you created for blocks, used with a deployment instead of a dynamic object. DENIS adds one host object to it, then deploys to the devices listed below. The group must have at least one member already. A deployment carries every pending change on those devices, so DENIS refuses to write while another administrator has pending changes there.
- **Quarantine network group name (optional)**: A network group you created for quarantine, used with a deployment. DENIS adds one host object to it and takes it out again, and deploys each time. What the group may reach is decided by your own access rules. The group must have at least one member already.
- **Devices to deploy to (names or IDs)**: The FTD devices that receive a deployment after a change in network group or access rule mode. A deployment changes every pending item on these devices, not only DENIS's, and can take about ten minutes. Not used with dynamic objects.
- **Access policy for deny rules (optional)**: The access policy DENIS writes its flow deny rules into, at the top. Needed only for flow blocks. It must be assigned to the devices listed above, or those devices keep a pending change that nobody deploys.
- **Allow DENIS to create deny rules on this firewall**: Off by default. When on, DENIS can create one deny access rule per flow block (two for both directions) at the top of the access policy named above, marked denis-... and DENIS managed, deploy it, and delete it again when the action ends. It never creates an allow rule and never uses any address but the two hosts of the flow. A deployment affects every device in it and can take about ten minutes. A wrong deny rule can cut off traffic: switch this on only if you accept that.

## 4.5.0: checks, deployments and the token

* **Set up but not deployed yet.** For the network group and the flow block, the hourly check keeps an action that
  is on the FMC as planned but not deployed active and unconfirmed instead of closing it; pending changes about the
  group or the access policy count as this action's only when no deployment of it finished. A flow rule that is no
  longer first or no longer as planned keeps the action active with a notice.
* **A stop during the deployment wait**: "deploy started" is recorded before the wait, so the release deploys its
  removal.
* **A failed deployment to several devices** may have gone through on some of them: the action stays open
  (unconfirmed) and its release deploys the removal ("The FMC reported that the deployment failed, on at least one
  of the devices ..."). With one device a failed deployment is still "nothing was deployed".
* **One token per FMC and user.** The clients of DENIS share one token in the process (best guess from the
  documented behaviour that a new sign-in of the same user can end the earlier token), so a read-back no longer ends
  the token of an action that waits for its deployment. The pacing window is still per client.
