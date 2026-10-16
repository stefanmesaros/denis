# Enforcement: Ubiquiti UniFi

Status: **Experimental. Simulator only: not yet validated on real equipment.** Everything below was built from the controller's behaviour as publicly known (the UniFi Network API is not officially documented, and it changes between Network versions) and checked against a fake controller in DENIS's own tests. It has never been run against a real controller. Nothing here is listed as validated on hardware.

Lab use: the client block (the pre-4.1 action) is allowed only while an administrator has switched on *Allow connectors that are not validated on real equipment (lab use)* under *Settings → Response policy*. The actions new in 4.1 (disconnect a wireless client, disable a switch port, quarantine a switch port) additionally need *Allow experimental actions (lab use)*. Releasing an action always works.

Besides this connector's own refusals, every action through it goes through DENIS's common guards before anything is sent: loopback, unspecified, broadcast and multicast addresses, DENIS itself, the gateway, and an address or MAC in an open `arp_conflict` alert are refused, and a list DENIS cannot read refuses the action.

## What each action does, and what it does not do

| Action | What DENIS sends | What it does not do |
|---|---|---|
| **Block device** (`block_sta`) | `POST cmd/stamgr` `block-sta` for the client's MAC address, then reads the client back (`stat/user/{mac}`, `blocked`). Released with `unblock-sta`, only while the client is still blocked. | It blocks by **MAC address**: a target with only an IP address is refused. A wireless client is disconnected at once. **What it does to a wired client has not been tested** (see below). A client the controller has no record of is refused. |
| **Disconnect a wireless client** (`kick_sta`, "end sessions") | `POST cmd/stamgr` `kick-sta`, after checking that `stat/sta` shows the client connected and wireless. | **Wireless clients only.** A wired client, a client that is not connected, and a client whose row does not say whether it is wired are refused. The client may reconnect at once: this ends a session, it does not keep the client off. Releasing it only closes the record: an ended session cannot be undone, nothing is sent. |
| **Disable port** (`port_disable`) | `PUT rest/device/{id}` with the device's port override list, in which the one port's entry uses the controller's built in **Disabled** port profile. The port is read back from the controller. | It never changes any other port, any other field, or any profile or network. A controller with no profile named Disabled refuses. |
| **Quarantine** (`port_profile`) | The same write, with the one port's entry on the **port profile you made** for quarantine. | DENIS never creates or edits a port profile or a network, and never writes a firewall rule: what the quarantine network allows is your own definition. The profile must carry its native network only (no tagged networks), or DENIS refuses. |
| **Block a flow** | Not available. | **Unsupported.** UniFi has no published interface for firewall rules, and its rule model differs between Network versions (classic rules, traffic rules, zone based policies). DENIS writes no UniFi firewall rule. It is shown greyed out with that reason. |

### What the two port actions refuse (and cannot be told otherwise)

Only a port that the controller shows to be a plain port of a UniFi **switch** (device type `usw`) is changed. The port is read again right before the write, and a port that changed since the plan is refused. Refused:

* an **uplink** (`is_uplink`), a member or master of a **link aggregation**, a **mirror** port;
* a port with an **LLDP neighbour**, a port with **another UniFi device** of the site behind it (its MAC in the port's MAC table or as the LLDP chassis: access points, other switches, the gateway), and a port with a **MAC address of your protected list** behind it. The controller knows nothing about devices it does not manage, so **list DENIS itself, your gateway and the controller in *Never block these MAC addresses*** (these are also the devices DENIS is reached through). A port that one of them is behind is then refused;
* a **trunk**: a port whose profile carries a custom list of tagged networks (`forward: customize`);
* a port DENIS cannot read, a port that is already switched off, an unknown switch, a device that is not a switch, a port number that is not a number from 1 to 256.

A quarantine is also refused for a port with **more than one device** behind it, with a **voice network** (a phone is probably behind it), or under **802.1X port control**. A port that passes tagged networks of its own (profile "All", the factory default) asks for a tick: DENIS replaces the whole profile of the port, so afterwards it carries the quarantine profile only.

DENIS keeps one active action per port: a disable and a quarantine of the same port cannot both be active.

### How the override list is written

A device's `port_overrides` are replaced as a whole by one `PUT`. DENIS therefore reads the device immediately before the write, changes **only the one entry of the one port** (only its `portconf_id`), keeps every other entry exactly as the controller reported it, and writes under a lock per controller instance. Release changes back **only that one field**, and only while the entry still shows DENIS's profile: if someone put the port on another profile in the meantime, DENIS leaves it alone and says so in the steps. If the entry did not exist before, it is removed again; if it did, everything else in it (a name, PoE mode) stays as it is at that moment.

## The controller kinds

* **UniFi OS console** (Dream Machine, Cloud Gateway, Cloud Key Gen2+): sign-in at `/api/auth/login`, API under `/proxy/network`, and every call carries the `X-Csrf-Token` of the sign-in. When an answer carries a newer token (`X-Updated-Csrf-Token`), DENIS uses that one from then on.
* **Classic controller** (software or self-hosted): sign-in at `/api/login`, no prefix, no CSRF header.
* The configuration says which one it is (**no default**). A wrong choice fails at sign-in and changes nothing.
* **Site:** the site short name (`default` unless it was renamed). The actions new in 4.1 check that the controller has a site of that name (`GET /api/self/sites`) before anything else.
* **Account and session:** a **local** controller account with a user name and a password, signed in for each action and dropped when it ends. A cloud (`unifi.ui.com`) account with two step sign-in cannot sign in through the local API. **API keys are not used**: the calls DENIS makes (`cmd/stamgr`, `rest/device`) belong to the classic API, which the official key based API does not cover **[verify]**.
* Cloud-hosted UniFi (`unifi.ui.com`) is out of scope: DENIS must reach the controller directly.

## Setup

1. Create (or reuse) a controller **local account** for DENIS. A *Site Admin* for the one site is enough to block clients; changing a switch's port settings needs the right to edit devices of the site **[verify]**. Do not use the owner account.
2. Note whether the controller is a **UniFi OS console** or a **classic** controller, and the **site short name**.
3. **Quarantine port profile (optional).** In the controller make a *Switch Ports* profile (Settings → Profiles): its **native network** is your quarantine VLAN, with DHCP and the rules you want there, and it carries **no tagged networks**. Enter its **name or id** in *Quarantine port profile*. Leave it empty to switch the port quarantine off.
4. *Network → Equipment* → **Ubiquiti UniFi** → **Add…**: the controller address (`https://host[:port]`, no path), site, user name, password, the console checkbox, the quarantine port profile, and **the MAC addresses never to block**: DENIS's own adapter, the gateway, the controller and any access point or switch you rely on.
5. **For a port action** the target is the switch's **MAC address** and the **port number** as the controller numbers it (1 to 256).

## Unblock, release and expiry

* **Client block:** released with `unblock-sta` only while the client is still blocked. A client someone else already unblocked is left alone. With no ledger record, the old *Unblock* route refuses to remove a block it has no record of.
* **Port actions:** see above. A release the controller refuses leaves the action active, flagged, and retried; it is never closed.
* **Expiry** rolls an action back after its duration, whatever the kill switch, the hourly cap and both lab switches say.
* The old routes (the *Block…* and *Unblock…* buttons of earlier versions) make **the same controller calls and write the same ledger row** as before: sign in, read the client, `cmd/stamgr`, read the client back, on one session; the row records `mac`, `site` and `controller`.

## Orphans

DENIS creates **no named object** on a UniFi controller, so there is nothing to list or remove by name. The record is the ledger: the undo data of a port action holds the switch, the port, whether an override existed and the profile to give back.

## What is verified

Only against the fake controller in `src/nac_unifi/orch_tests.rs` (and the earlier tests in `src/nac_unifi.rs`): the old routes make the same calls and ledger row as the pre-4.1 code on a console and on a classic controller; block and release; refusal of an unknown, already blocked or protected client and of an IP address; the CSRF token rotation; a site the controller does not have; lost answers, refused writes and server errors; disabling and quarantining a port with every override left as it was, every hard refusal of the table above, a port that changes between the plan and the apply, a release that leaves a changed port alone, a release the controller refuses; the wireless disconnect and its refusals; expiry ignoring the kill switch, the cap and both lab switches; lab refusals sending zero requests; the flow block refused with zero requests. **Not verified on any real UniFi controller.** The owner's console is a Cloud Gateway Ultra, which has no radio and no switch ports: a real test of the disconnect needs an access point, and of the port actions a UniFi switch.

Behaviours that are unproven vendor facts (marked **[verify]** in the code):

* `GET stat/device/{mac}` returns the device `_id`, `type` (`usw` for a switch), `port_table` (per port `port_idx`, `is_uplink`, `aggregated_by`, `op_mode`, `portconf_id`, `enable`, `lldp_table`, `mac_table`) and `port_overrides`. A port with no `is_uplink` is unknown and refused.
* `PUT rest/device/{id}` with `{"port_overrides": [...]}` replaces the list, takes effect on the switch without further steps, and a port whose entry uses the Disabled profile goes down.
* `GET rest/portconf` lists profiles with `_id`, `name`, `forward` (`all`, `native`, `customize`, `disabled`), `native_networkconf_id`, `voice_networkconf_id` and `dot1x_ctrl`; the built in profile named `Disabled` has `forward: disabled`.
* `GET stat/sta` lists the connected clients with `is_wired`; `kick-sta` ends a wireless session.
* **What `block-sta` does to a wired client.** UniFi documents the block as a disconnect for wireless clients. Whether it stops a client on a wired switch port is not known and has to be tried on real equipment before the block is relied on for wired devices.
* That the Network application keeps a client block across a restart of the console.
* The role a limited account needs for the port writes.

## Limits

* One site per connector instance.
* Traffic inside a VLAN that is switched, not routed, never passes the gateway: a client block at the controller is the only control that covers it, and its wired behaviour is the unknown above.
* A switch port action is not a firewall rule: it cuts or moves a port, with everything behind it.
* The controller session lasts for one action; there is no keep-alive.

## Credentials

Username (plain configuration) and password (`nac.unifi.password`, encrypted secret store). The password is never written to the ledger, the audit log or a notification.
