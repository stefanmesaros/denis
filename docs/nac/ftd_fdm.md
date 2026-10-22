# Enforcement: Cisco FTD (managed with FDM)

Status: **Experimental. Simulator only: not yet validated on real equipment.** Everything below was built from Cisco's published Firewall Device Manager (FDM) REST API documentation and checked against a fake FDM in DENIS's own tests. It has never been run against a real Secure Firewall Threat Defense (FTD). The vendor behaviours that are still unproven are listed under *Verified and not verified* below.

This page is for an FTD that you manage **locally with FDM** (the on-box manager). An FTD managed by a Firewall Management Center (FMC) is a different connector.

Lab use: every action of this connector is allowed only while an administrator has switched on both *Allow connectors that are not validated on real equipment (lab use)* and *Allow experimental enforcement actions* under *Settings → Response policy*. This connector is new in 4.1 and has no older block button. Everything goes through the Respond menu: a plan you read, a confirmation, a time limit (one hour by default), and a release that DENIS also makes on its own when the time is up.

Besides the connector's own refusals, every action through it is refused for a loopback, unspecified, broadcast or multicast address, for DENIS itself and for the gateway, for DNS and directory servers, for anything in the connector's *protected networks* and in *Never block these IP addresses*, for the address you are using to reach the console, for the address in the connector's Base URL, and for every address of the FTD itself (its interfaces and the standby address of a high availability pair, which DENIS reads from FDM each time).

## What DENIS can do on an FTD

| Action | What DENIS writes | What it does not do |
|---|---|---|
| **Block device** (network group) | One network object `denis-<tag>-<id>` (`HOST`, its description led by the marker `DENIS managed; owner <tag>; action <id>; ...`), added to the network group you created for blocks, then a deployment. | It does not create the access rule that makes the group block anything: **your own access rule** that refers to the group does that. It does not end open connections. |
| **Quarantine** (network group) | The same network object, added to a second network group that you created for quarantine, then a deployment. | It creates **no access rule at all** and never an allow rule. What a quarantined device may reach is decided by your own access rules. |
| **Block flow** (deny rule) | Two network objects (`denis-<tag>-<id>-src` and `-dst`), a port object `denis-<tag>-<id>-svc` for a protocol and port, and one access rule `denis-<tag>-<id>` with action DENY, placed at the top of the access policy, then a deployment. With both directions: a second rule `denis-<tag>-<id>-r`. | It never writes an allow or trust rule, a network or `any`, or a rule for the FTD's own addresses. ICMP is refused (FDM matches it through protocol objects DENIS does not build). Only with *Allow DENIS to create deny rules on this firewall* ticked. |
| End sessions | **Not possible through FDM's REST API.** | DENIS does not run the command line to do it. |
| Disable port | Not possible on a firewall. | |

Every object DENIS makes carries the marker in its description, so removal is exact: DENIS removes only what carries its own marker, by name, and an object with another install's tag is never touched. An access rule has no description in FDM, so a flow rule is recognised by its name `denis-<tag>-...` together with the fact that it refers only to DENIS's own objects. Text you typed (the reason) is never written to the FTD: the marker holds only DENIS's own tag, the action number, your login name and the planned end time.

## The deployment is part of the action

FDM keeps every change as a **pending change** until a deployment has run, and a deployment publishes **every** pending change of every administrator. It takes from about a minute to several minutes. So:

* **A change is not in force until the deployment has finished.** DENIS starts the deployment job, waits for it (up to about ten minutes) and records the job number and the time as a step. Until it has read the result back, the action is **unconfirmed**. Only a read-back that shows the change deployed makes it *enforced*.
* **DENIS refuses to make a change while another administrator has pending changes.** It reads the list of pending changes; if it shows a change that someone else made (or one with no author shown), the plan says so and nothing is written, because a deployment from DENIS would publish it. Ask that person to deploy or discard it first. A release that has to deploy is held back the same way: the action stays active, DENIS tells you, and tries again later. If your FDM version cannot give DENIS the list, DENIS refuses too, unless you tick *Deploy without checking for other administrators' pending changes* (off by default; read its warning).
* **A failed deployment publishes nothing.** DENIS withdraws its own pending objects and rules, does not deploy again, and the action fails.
* **A deployment that is still running when DENIS stops waiting, or whose answer is lost,** leaves the action *unconfirmed*. A release (or the next automatic try) then deploys the removal.
* **Tokens.** DENIS signs in once per call with the user's password (`POST /fdm/token`), uses the bearer token, refreshes it with the refresh token before it runs out and whenever FDM answers 401, so a long deployment does not fail on an expired token.
* A deployment can briefly interrupt traffic inspection on the FTD, depending on what else changed (the plan says so).
* A change that was **never deployed** (the deployment failed or was never started) is withdrawn from the pending changes without a deployment. A change that was deployed, or may have been, is removed and deployed.

## Setup on the FTD

Check these against Cisco's documentation for your software version before relying on them.

1. **A user for DENIS.** In FDM, *System Settings → Management Access → AAA* (or *Device → System Settings → Local users*), create a local user with a role that may change objects and policies and deploy (an **Administrator**; whether a read-write role may deploy is **[verify]**). Use an account of its own: DENIS decides "this pending change is not mine" by the user name, so a person who also signs in with this account would look like DENIS.
2. **The REST API.** The FDM REST API is served by the FDM web interface on its HTTPS port (443 by default). Allow DENIS's address in *System Settings → Management Access → Management Interface* / data interface access lists for HTTPS.
3. **The block group and your own rule.** Create a network group (for example `DENIS-BLOCK`) with at least one member (FDM does not keep an empty group; DENIS refuses to add to an empty one, so put a placeholder object, for example `192.0.2.255`, in it), and **your own** access rule that denies the group, high in the access policy.
4. **Quarantine (optional).** A second network group (with a placeholder member) and **your own access rules** that use it: allow what a quarantined device needs (DHCP, DNS, NTP, the remediation server) and deny the rest. DENIS never creates, checks or edits these rules.
5. **Flow blocks (optional).** Tick *Allow DENIS to create deny rules on this firewall* only if you accept that DENIS writes access rules on this FTD. It is off by default, and DENIS will not create a flow rule while it is off. Turning it on needs your password again, like turning on enforcement. A prefilter fastpath rule or a trust rule above can still pass traffic before the access policy is looked at, and DENIS cannot see the prefilter policy.
6. **In DENIS** (*Network → Equipment → Add a connector → Cisco FTD (FDM)*): **Base URL** (`https://<FTD address>`, add `:port` if you changed it), **Username** and **Password** (stored sealed as `nac.ftd_fdm.password`), the **block network group name**, the optional quarantine group and access policy name (empty = the device's one access policy), and the TLS settings below.

## TLS

* **Pinned certificate (recommended).** Leave *Verify TLS certificate* ticked and paste the FTD's certificate (PEM) into *Pinned device certificate*. A self-signed certificate is trusted only if it is the one pinned.
* **Verification off.** Untick *Verify TLS certificate* for a lab. The connection is encrypted but not authenticated.

Changing the Base URL, the TLS settings or the pinned certificate while the saved password is kept needs your DENIS password (the same rule as for every connector).

## What DENIS records

The ledger row is written before anything changes (`unconfirmed`), the audit entry before the connector is touched, and each request that changes something is a step (object created, added to the group, rule created, deployment with its job number and time). A release or an automatic end removes by name and marker and deploys; if FDM refuses, or a pending change by someone else is in the way, the action stays active and DENIS tries again, with growing waits, and tells you.

Objects, port objects and rules that carry your DENIS install's marker (or name and objects) but belong to no active action (for example after a database restore) are listed as orphans, with a button to remove them. Removing one deploys, so it is held back by the same check for other administrators' pending changes. Objects with another install's tag, and anything without the marker, are never listed as DENIS's and never removed.

## Removing everything by hand

In FDM, *Objects → Networks* (filter on `denis-`), remove the member from your group first, then delete the objects; delete the rules named `denis-...` under *Policies → Access Control*; delete port objects named `denis-...` under *Objects → Ports*; then deploy.

## Verified and not verified

* **Verified (against a local fake FDM over TLS, in the test suite):** the request sequence, the marker, that no allow rule is ever written and a flow rule goes first, the position check and the removal of a rule that did not land at the top, the deployment (many polls, a failed job, a job that never ends, "nothing to deploy"), the refusal while another administrator has pending changes (and when the list cannot be read), withdrawing an undeployed change without a deployment, a release held back by another administrator's pending change and finished when it is gone, token refresh before expiry and after a 401, paging past 100 objects with a device that ignores the filter, lost answers, orphan listing and removal, and that refusals send nothing.
* **Not verified: everything on a real FTD.** In particular, behaviours that are unproven vendor facts (marked **[verify]** in the code):
  * `POST /fdm/token` with `grant_type` `password` and `refresh_token` answers `access_token`, `refresh_token`, `expires_in` and `refresh_expires_in`; a bearer token is accepted on every other call.
  * A list answers `{"items": [...], "paging": {...}}` and honours `limit`, `offset` and `filter=name:<name>` (DENIS also compares names itself and follows `paging.next`).
  * `POST /object/networks` with `subType` `HOST`, `PUT /object/networkgroups/{id}` with the whole object and the group's `version`, `DELETE`, and `POST /object/tcpports` and `/object/udpports` with `port` as a number or `from-to`.
  * `POST /policy/accesspolicies/{id}/accessrules?at=0` puts the rule first, and the rule list comes back in evaluation order.
  * `GET /operational/pendingchanges` lists the pending changes with the user who made each one (the field names DENIS reads are `userName`, `username`, `user`, `modifiedBy`, `lastModifiedBy` and `createdBy`). **The endpoint itself is unproven.** If it does not exist on your version, DENIS refuses to deploy unless the option above is ticked.
  * `POST /operational/deploy` starts a deployment job and `GET /operational/deploy/{id}` answers its `state` (`QUEUED`, `DEPLOYING`, `DEPLOYED`, `FAILED`); a deployment with nothing pending answers an error that says so.
  * `GET /devices/default/interfaces` shows each interface's address and the standby address of a high availability pair (DENIS reads every IPv4 address in the answer except netmasks; an address an interface learns by DHCP is not in the configuration and is not seen), and `GET /devices/default/subinterfaces` may not exist.
  * Access rules match real (untranslated) addresses.
  * An FTD in a high availability pair may need a deployment on both units; DENIS only talks to the unit it is pointed at.
  * Whether FDM has a REST call that ends open connections: DENIS found none, so the capability is unsupported, never faked.

## Limits

* IPv4 only.
* A change is in force only after the deployment, minutes later. The time limit of an action starts when the deployment has finished, so a short limit is still a real one, but choose at least several minutes.
* Block device and quarantine do nothing until **your own** access rule refers to the group.
* A flow rule stops new connections; open connections stay open. It does not stop traffic inside one subnet.

## Details from the console

The console shows a short line under each field and a short note behind its (i). The full explanation of each field is here.

- **Block network group name**: The network group you created for blocks. DENIS adds a network object for the device to it and takes it out again, and nothing else: whether the group blocks anything is decided by your own access rule that refers to it. A change is in force only after the deployment, which takes minutes.
- **Quarantine network group name (optional)**: The network group you created for quarantine. DENIS moves a device into it and back, and nothing else: what the group may reach is decided by your own access rules on the FTD. DENIS never creates an allow rule. Leave empty to switch quarantine off for this FTD.
- **Access policy name (optional)**: The access policy DENIS puts deny rules at the top of when you block one flow. Leave empty to use the device's one access policy.
- **Allow DENIS to create deny rules on this firewall**: Off by default. When on, DENIS can create one deny rule per flow block at the top of the access policy, named denis-... , and delete it again when the action ends. It never creates an allow rule and never uses any address but the two hosts of the flow. A wrong deny rule can cut off traffic: switch this on only if you accept that.
- **Deploy without checking for other administrators' pending changes**: Off by default. A deployment publishes every pending change on the FTD, including changes another administrator has not finished, so DENIS refuses to deploy while it can see changes that are not its own, or when it cannot read the list. Tick this only if your FDM version cannot give DENIS that list and you accept that a deployment may publish other people's pending changes.
