# Enforcement: Ubiquiti UniFi

Status: **Verified on UniFi Network 10.6.106 / UniFi OS 5.1.33, UCG Ultra: block device through the firewall policy, block a flow and their release (also automatic expiry); not verified: block by client MAC (did not hold for a wired client behind another switch), Wi-Fi client disconnect, port actions (no Wi-Fi device or UniFi switch in the lab).** The verified actions are the two firewall policy actions of the API key path (*Block device: firewall policy on the gateway* and *Block a flow*), with their release by hand, early and at expiry: they carry no *Experimental* mark and need neither lab setting (4.2). Everything else below was built from the controller's behaviour as publicly known (the UniFi Network API for these calls is not officially documented, and it changes between Network versions), checked against a simulated controller in DENIS's own tests, and stays *Experimental*. Sign-in is either a **local account with a user name and a password** (the controller's session cookie) or, new in 4.2, an **API key**; see *The controller kinds* and *With an API key (4.2)* below.

DENIS signs in to UniFi in one of two ways, chosen per connector under *How DENIS signs in*: a **local account** (user name and password, the way every version before 4.2 worked) or an **API key** of the Network application (new in 4.2), or **both**. What each one can do is in the table below. The API key path was built from the official Integration API documents and read-only answers of a Cloud Gateway Ultra (Network 10.6.106), and checked against a fake console in DENIS's own tests; it has not blocked anything on a real console yet.

Lab use: the two firewall policy actions (API key) are validated on real equipment and need no lab setting. The client block by MAC (the pre-4.1 action) did not hold for a wired client behind another switch on the real console, so it stays *Experimental* and is allowed only while an administrator has switched on *Allow connectors that are not validated on real equipment (lab use)* under *Settings → Response policy*. The actions new in 4.1 (disconnect a wireless client, disable a switch port, quarantine a switch port) additionally need *Allow experimental actions (lab use)*. Releasing an action always works.

Besides this connector's own refusals, every action through it goes through DENIS's common guards before anything is sent: loopback, unspecified, broadcast and multicast addresses, DENIS itself, the gateway, and an address or MAC in an open `arp_conflict` alert are refused, and a list DENIS cannot read refuses the action.

## Quick setup (about 10 minutes)

**What must be in the path.** *Block device* acts at the controller, on a client's **MAC address**: the controller must already
know the client (it has connected once). A **wired** client is the open question (see below). The two port actions need a **UniFi switch** (device type
`usw`); a gateway such as the Cloud Gateway Ultra has no switch ports of that kind, and disconnecting a wireless client needs
an adopted access point. DENIS must reach the controller's address directly over HTTPS (not through `unifi.ui.com`).
Since 4.2 a UniFi connector is a firewall on the path like the others: fill in **Networks this firewall routes
between** with the networks of the gateway (for example `192.168.14.0/24`). Only a device with a current address in
one of them gets the UniFi responses in the main part of the Respond menu; for any other device they are listed under
*Other firewalls* or *Path not verified*, and automation never uses them. The port actions act only on a port of a
UniFi switch: the Respond menu never offers them for a port of a switch DENIS reads over SNMP (a Cisco, for example).

1. **A local account for DENIS.** In UniFi OS: *Admins & Users → Create New Admin*, tick *Restrict to Local Access Only*, give it a
   user name (for example `denis`) and a long random password, and the Network application role *Site Admin* for the one site
   (or the least role that can block clients; the exact role names differ between releases). It must not be the owner
   account, and it must not be a cloud (`ui.com`) account with two-step sign-in: such an account cannot sign in through the
   local API.
2. **Find out two facts:** whether the controller is a **UniFi OS console** (Dream Machine, Cloud Gateway, Cloud Key Gen2+) or a
   classic software controller, and the **site short name** (`default` unless renamed; it is in the Network application's
   address, `/network/<site>/`).
3. **In DENIS:** *Network → Equipment → + Add a connector…* → *Ubiquiti UniFi (local controller)*: **Controller address**
   (`https://192.0.2.10`, no path; add `:port` if it is not 443), **Site short name**, **Username**, **Password**, tick **This
   is a UniFi OS console (Dream Machine, Cloud Key Gen2+, …)** for a console (leave it clear for a classic controller; a wrong
   choice fails at sign-in and changes nothing), **Quarantine port profile (name or id, optional)** only if you built one (see
   *Setup*), and **Never block these MAC addresses**: DENIS's own adapter, the gateway, the controller and any access point or
   switch you rely on. **Verify TLS certificate** stays ticked if the console's certificate is trusted; the console's own
   certificate is self-signed, so in a lab you may untick it. Press **Test connection**.
4. **Settings → Response policy:** tick *Allow administrators to block devices from DENIS*, *Allow connectors that are not
   validated on real equipment (lab use)* and, for the actions new in 4.1, *Allow experimental actions (lab use)*.
5. **First test, on a harmless device:** *Respond → Block device* on a test client for **5 minutes**. A target with only an IP
   address is refused; the plan needs the client's MAC. Expect: a wireless client is disconnected at once;
   the controller shows the client as *Blocked*; at the end of the time (or on **Release**) DENIS unblocks it. **On a real
   console the block did not hold for a wired client behind another switch** (the controller showed it as *Blocked*, but
   its traffic came back before the time was up): use the firewall policy method for wired devices. The plan warns when
   the controller does not say the client is wireless, and the firewall policy method is the one DENIS preselects when
   both are set up.

**If something fails:** a sign-in failure means the account is a cloud account, has two-step sign-in, is not a local
account, or the console checkbox does not match the controller kind; "the controller has no site of that name" means the site
short name is wrong; a client "the controller has no record of" has never connected to this site; a port is refused as an
uplink, a link aggregation member, a trunk, or because another UniFi device or a listed MAC is behind it.

**What each action does and how it is verified:** *Block device* sends `block-sta` for the MAC and reads the client back
(`blocked`); **Release** sends `unblock-sta` only while the client is still blocked. **Extend** sets the new end from now, not
added to the old end, and needs your password. The port actions change **one field of one port entry** and are read back.
Nothing is created on the controller that has a name, so there is nothing to clean up by hand.

## What each action does, and what it does not do

| Action | What DENIS sends | What it does not do |
|---|---|---|
| **Block device** (`block_sta`) | `POST cmd/stamgr` `block-sta` for the client's MAC address, then reads the client back (`stat/user/{mac}`, `blocked`). Released with `unblock-sta`, only while the client is still blocked. | It blocks by **MAC address**: a target with only an IP address is refused. A wireless client is disconnected at once. **Not reliable for a wired client behind another switch** (see below): the plan warns, and the read-back says only that the controller shows the client as blocked. A client the controller has no record of is refused. |
| **Disconnect a wireless client** (`kick_sta`, "end sessions") | `POST cmd/stamgr` `kick-sta`, after checking that `stat/sta` shows the client connected and wireless. | **Wireless clients only.** A wired client, a client that is not connected, and a client whose row does not say whether it is wired are refused. The client may reconnect at once: this ends a session, it does not keep the client off. Releasing it only closes the record: an ended session cannot be undone, nothing is sent. |
| **Disable port** (`port_disable`) | `PUT rest/device/{id}` with the device's port override list, in which the one port's entry uses the controller's built in **Disabled** port profile. The port is read back from the controller. | It never changes any other port, any other field, or any profile or network. A controller with no profile named Disabled refuses. |
| **Quarantine** (`port_profile`) | The same write, with the one port's entry on the **port profile you made** for quarantine. | DENIS never creates or edits a port profile or a network, and never writes a firewall rule: what the quarantine network allows is your own definition. The profile must carry its native network only (no tagged networks), or DENIS refuses. |
| **Block device: firewall policy on the gateway** (`fw_policy`, API key) | One zone-based **firewall policy** per pair of zones: from the zone of the device's network to every zone of the site, the device's own zone included, except the **Gateway** zone (unless you tick that). Each policy has action **BLOCK** (dropped silently, never REJECT), a source filter of exactly one item, the device's address as `a.b.c.d/32` (IPv4 only: DENIS cannot tell the network of an IPv6 address yet, and refuses it), and is put **first** in the order of its zone pair; the order is read back. A later block puts its own policy first, so an earlier one of DENIS stands behind DENIS's own policies only, which still counts as in force; a policy of anyone else ahead of it does not. The read-back compares the whole policy with what DENIS wrote (action, zones, the one address, the address family, `matchOpposite`, and for a flow the protocol and the port): a policy changed in the console is *not confirmed*. Released by deleting the policies. | It matches the device's **IP address**, not its MAC address: another address of the device (IPv6, another network) is not blocked, and the plan says so. **Traffic inside the device's own network is switched and never reaches the gateway: it is not blocked.** The device can still reach the gateway itself (DHCP, DNS), so it keeps its address and stays visible. **Whether connections already open are cut has not been tested.** A device on the protected list, the gateway's own address, and an address in no network of the site are refused. |
| **Block a flow** (`fw_flow`, API key) | One firewall policy from the source's zone to the destination's zone (`External` for an address on the internet), with the destination address as one `/32` item, and the port and protocol of the flow when it has them **[verify the port and protocol filter shape on the console]**. Placed first in its pair, read back, deleted on release. | Only traffic that passes the gateway. With the local account only, it is not offered. |

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
* **Local account and session:** a **local** controller account with a user name and a password, signed in for each action and dropped when it ends. A cloud (`unifi.ui.com`) account with two step sign-in cannot sign in through the local API. The client block, the wireless disconnect and the two port actions use it (`cmd/stamgr`, `rest/device`), unchanged.
* **API key:** sent as the `X-API-KEY` header to the Integration API under `/proxy/network/integration/v1` (the console's own self-signed certificate: switch off *Verify TLS certificate* only on a trusted network, or give the console a certificate DENIS trusts). The client list, the networks, the firewall zones and the firewall policies are read through it, and DENIS's own firewall policies are added, ordered and deleted through it. Lists are read page by page, at most 4000 items; a longer list is refused rather than read in part, and so is an answer that is not a list (a proxy page, an empty body) or a list that ends before the count the console gave: a release never concludes "none left" from a list it could not read. A site with more than 64 networks is refused the same way. When several networks hold an address, the one with the longest prefix decides its zone. *Test connection* reads the Network version (9.4 or newer is needed for firewall policies with a key), the site, the zones (none means the site does not use the zone-based firewall), one policy and one client, and writes nothing. A version too old or a site without zones fails the test, with the API key alone and with both sign-ins (the firewall policy methods would not work). With the API key alone, the methods of the local account (block a client, disconnect, the port actions) are refused already in the plan, and the firewall policies with the local account alone, before anything is sent.
* Cloud-hosted UniFi (`unifi.ui.com`) is out of scope: DENIS must reach the controller directly.

## Setup

1. Create (or reuse) a controller **local account** for DENIS. A *Site Admin* for the one site is enough to block clients; changing a switch's port settings needs the right to edit devices of the site **[verify]**. Do not use the owner account.
2. Note whether the controller is a **UniFi OS console** or a **classic** controller, and the **site short name**.
3. **Quarantine port profile (optional).** In the controller make a *Switch Ports* profile (Settings → Profiles): its **native network** is your quarantine VLAN, with DHCP and the rules you want there, and it carries **no tagged networks**. Enter its **name or id** in *Quarantine port profile*. Leave it empty to switch the port quarantine off.
4. *Network → Equipment* → **Ubiquiti UniFi** → **Add…**: the controller address (`https://host[:port]`, no path), site, user name, password, the console checkbox, the quarantine port profile, and **the MAC addresses never to block**: DENIS's own adapter, the gateway, the controller and any access point or switch you rely on.
5. **For a port action** the target is the switch's **MAC address** and the **port number** as the controller numbers it (1 to 256).

### With an API key (4.2)

1. In UniFi OS make a local admin for DENIS (for example `denis`) with access to the **Network** application only, remote access off. A key carries **all the rights of the admin who made it**, and there is no narrower scope per key: the key can change any Network setting that admin can. A role that lets the admin add firewall policies is needed (*Site Admin* is enough **[verify the smallest role; a View Only admin's key must be refused when it writes]**).
2. Signed in as that admin, open the Network application, *Settings → Control Plane → Integrations*, and create an **API key**. It is shown once.
3. In the connector choose *How DENIS signs in*: **API key** (or **Both**, to keep the client block and the port actions of the local account too), paste the key, and tick **Allow DENIS to create firewall policies on this console**. With the key only, the user name may stay empty.
4. Optional: *Firewall policies also block the device's access to the gateway* (off by default), and *Most firewall policies DENIS keeps on this site* (50 by default: DENIS refuses a block that would pass it).
5. The site must use the **zone-based firewall** (Network 9 and later migrate to it). *Test connection* says when it does not.

## Unblock, release and expiry

* **Client block:** released with `unblock-sta` only while the client is still blocked. A client someone else already unblocked is left alone. With no ledger record, the old *Unblock* route refuses to remove a block it has no record of.
* **Port actions:** see above. A release the controller refuses leaves the action active, flagged, and retried; it is never closed.
* **Expiry** rolls an action back after its duration, whatever the kill switch, the hourly cap and both lab switches say.
* The old routes (the *Block…* and *Unblock…* buttons of earlier versions) make **the same controller calls and write the same ledger row** as before: sign in, read the client, `cmd/stamgr`, read the client back, on one session; the row records `mac`, `site` and `controller`.

## Orphans

The local-account actions create **no named object** on the controller: the record is the ledger (the undo data of a port action holds the switch, the port, whether an override existed and the profile to give back).

The firewall policies of the API key path are named `denis-<install tag>-<action>-<n>` and carry a description `DENIS managed; owner <tag>; action <id>; by <login>; expires <time>` (never your reason). A policy is DENIS's only when its name, its description and the console's own `USER_DEFINED` origin all say so: a policy of yours with a similar name is never listed, changed or removed. The reconciliation lists such policies that no active action accounts for as orphans, which you can remove from *Network → Response*. A policy you delete or switch off in the console is reported as *changed outside DENIS*; DENIS does not put it back. If someone reorders a zone pair while DENIS places its policy, the action is marked not confirmed and the policy stays in force. Placing a policy reads and writes the order of its zone pair under one lock per console address and site, so two connectors of the same site never interleave. While the ledger has firewall policy actions of a connector, an orphan list that cannot be read (no API key any more) is an error, and the last list stays shown.

## What is verified

**On a real UniFi console** (UniFi Cloud Gateway Ultra, UniFi Network 10.6.106, UniFi OS 5.1.33, API key, zone-based firewall, 2026-10): *Block device* with the firewall policy, *Block a flow*, and their release by hand, early and at expiry. Not tested on real equipment: the Wi-Fi client disconnect (needs an access point), the port actions (need a UniFi switch); they stay *Experimental*. The client block by MAC (sign-in *Both*) was tried on a wired client behind another switch and **did not hold**: the controller showed the client as blocked and DENIS read that back, but the traffic came back before the time was up; it stays *Experimental*. In DENIS's own tests, against a simulated controller: the old routes make the same calls and ledger row as the pre-4.1 code on a console and on a classic controller; block and release; refusal of an unknown, already blocked or protected client and of an IP address; the CSRF token rotation; a site the controller does not have; lost answers, refused writes and server errors; disabling and quarantining a port with every override left as it was, every hard refusal of the table above, a port that changes between the plan and the apply, a release that leaves a changed port alone, a release the controller refuses; the wireless disconnect and its refusals; expiry ignoring the kill switch, the cap and both lab switches; lab refusals sending zero requests; the flow block refused with zero requests. A Cloud Gateway Ultra has no radio and no UniFi switch ports: a real test of the disconnect needs an access point, and of the port actions a UniFi switch. The API key path (one firewall policy per zone pair) was built against a fake console made from synthetic data of the same shape as a real Cloud Gateway Ultra answers; nothing of it has been run on the real console yet.

Behaviours that are unproven vendor facts (marked **[verify]** in the code):

* `GET stat/device/{mac}` returns the device `_id`, `type` (`usw` for a switch), `port_table` (per port `port_idx`, `is_uplink`, `aggregated_by`, `op_mode`, `portconf_id`, `enable`, `lldp_table`, `mac_table`) and `port_overrides`. A port with no `is_uplink` is unknown and refused.
* `PUT rest/device/{id}` with `{"port_overrides": [...]}` replaces the list, takes effect on the switch without further steps, and a port whose entry uses the Disabled profile goes down.
* `GET rest/portconf` lists profiles with `_id`, `name`, `forward` (`all`, `native`, `customize`, `disabled`), `native_networkconf_id`, `voice_networkconf_id` and `dot1x_ctrl`; the built in profile named `Disabled` has `forward: disabled`.
* `GET stat/sta` lists the connected clients with `is_wired`; `kick-sta` ends a wireless session.
* **What `block-sta` does to a wired client.** UniFi documents the block as a disconnect for wireless clients. On a UCG Ultra (Network 10.6.106) it did not stop a wired client behind another switch although the controller showed it as blocked (2026-10-21). Use the firewall policy method for wired devices.
* That the Network application keeps a client block across a restart of the console.
* The role a limited account needs for the port writes.

## Limits

* One site per connector instance.
* Firewall policies (API key): only traffic through the gateway; no ACL rule on a UniFi switch is written in this version (the console used for testing offers no switch ACLs); quarantine and the port actions stay on the local account.
* Traffic inside a VLAN that is switched, not routed, never passes the gateway: a client block at the controller is the only control that covers it, and its wired behaviour is the unknown above.
* A switch port action is not a firewall rule: it cuts or moves a port, with everything behind it.
* The local sign-in session is kept in memory (see *Sign-in limits* below); there is no keep-alive.

## Sign-in limits

A UniFi controller limits how often one account may sign in (HTTP 429). With *How DENIS signs in = Both*, DENIS signs in with the local account for the client block, the wireless session end and the port actions. Since 4.2.1 it signs in **once** and reuses that session for plan checks, *Check again*, *Test connection* and the actions, for up to 10 minutes without use and 30 minutes in all. The session lives in memory only (never on disk, in a log or in the ledger) and is dropped as soon as the address, the user name or the password changes, or when the controller answers that it expired (DENIS then signs in once more). The API key path needs no sign-in.

When the controller does answer 429, DENIS waits as long as the controller asks (`Retry-After`, at most 2 minutes; 1 minute if it does not say) before it tries to sign in again, and shows "UniFi limits how often DENIS can sign in. Wait a few minutes and check again." That is a temporary answer, not a refusal by DENIS: nothing was changed, and checking again later works.

Use a **dedicated local account** for DENIS (a role limited to what DENIS needs, not your own administrator account), so that DENIS's sign-ins and yours never count against each other.

## Credentials

Username (plain configuration), password (`nac.unifi.password`) and API key (`nac.unifi.api_key`), both in the encrypted secret store, write-only in the form. Neither is ever written to the ledger, the plan, the steps, the audit log, a notification, a log line or a support bundle; an error from the console is reduced to its status and code before DENIS keeps it.

## Details from the console

The console shows a short line under each field and a short note behind its (i). The full explanation of each field is here.

- **Quarantine port profile (name or id, optional)**: The switch port profile you made in the controller for quarantine: its native network is your quarantine VLAN and it carries no tagged networks. DENIS puts one port on it and puts the old profile back, and nothing else: what the VLAN allows is decided by your own rules. DENIS never creates or edits a port profile or a network. Leave empty to switch the port quarantine off for this controller.
- **Never block these MAC addresses**: Addresses DENIS never blocks and never moves a switch port away from. List DENIS itself, your gateway and the controller here, as well as any other device DENIS must never cut off: a switch port with one of these behind it is refused.
- **Allow DENIS to create firewall policies on this console**: Off by default. When on, and DENIS signs in with an API key, DENIS can add its own firewall policies (block only, named denis-... and marked DENIS managed), put them first in the order of their zone pair, and delete them again when the action ends. It never creates an allow policy and never changes a policy, zone or network it did not make. A wrong block can cut off traffic.
