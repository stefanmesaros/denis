# Enforcement: Cisco Catalyst 9800 wireless controller (WLC)

Reads the clients and access points of a Cisco Catalyst 9800 wireless controller (IOS XE) for the map, and can end one wireless client's session. It does **not** block a client for good: for that, use the [RADIUS CoA connector](../nac/radius_coa.md) or a firewall.

Status: **Experimental.** Nothing here is listed as validated on hardware (see [Enforcement validation](../nac/validation.md)).

Lab use: ending a session is allowed only while an administrator has switched on both *Allow connectors that are not validated on real equipment (lab use)* and *Allow experimental enforcement actions* under *Settings → Response policy*. This connector is new in 4.4 and has no older block button. Everything goes through the Respond dialog: a plan you read, a confirmation and a record in the ledger. Ending a session leaves nothing to give back, so releasing it writes nothing.

Besides the connector's own refusals, every action through it is refused for a loopback, unspecified, broadcast or multicast address, for DENIS itself and for the gateway, for anything on the hands-off list and in *Never act on these MAC addresses*, and for an address in an open `arp_conflict` alert (unless the administrator ticks a box to accept that), before anything is sent. The connector adds: an access point of the controller is refused, so is a client that is not shown as a wireless client (wired and guest-LAN clients), a client the controller does not list, and a client that has the controller's own address or one of DENIS's own addresses.

## Evidence labels

Every claim about Cisco's interface or equipment on this page carries one of three labels:

* **documented**: checked in a page or file Cisco publishes (read 2 November 2026): the public YANG files `vendor/cisco/xe/17151` of the YangModels repository, and the RESTCONF chapter of the *Programmability Configuration Guide, Cisco IOS XE 17.18.x*.
* **best guess**: from memory, field reports or other people's code; not checked in anything Cisco publishes.
* **verified**: checked on real equipment, with the date. **Nothing in this connector is verified yet.**

## What DENIS can do on a Catalyst 9800

| Action | What DENIS writes | What it does not do |
|---|---|---|
| **End sessions** (`client_delete`) | One RESTCONF call, `POST /restconf/operations/Cisco-IOS-XE-wireless-client-rpc:apf-ms-delete-all` with the client's MAC (the call is documented, its URL form and body are best guess). Then it looks at the client table once. | It is not a block. The client can join again at once, and many do. It does not touch the controller's configuration. |
| Block device, block a flow, quarantine, disable a port | **Not offered.** | See *What is not offered and why*. |

DENIS names a client by its **MAC address**; an IP address is refused. Text you typed (the reason) is never sent to the controller.

After the call DENIS reads the client's entry in the client table once (after about 3 seconds) and records one of three notes: the controller no longer lists the client, the client is connected again (said plainly as normal for many devices), or the table could not be read. None of the three changes the result: the call was accepted.

## What is not offered and why

* **A block for good.** On a Catalyst 9800 a lasting per-MAC block is a change of the controller's configuration (an exclusion or deny entry saved with the running configuration); the only per-client call Cisco publishes in the models DENIS checked is the delete above. DENIS does not write controller configuration. **To keep a client out, use the [RADIUS CoA connector](../nac/radius_coa.md)** (the 9800 accepts RFC 5176 Disconnect and CoA from a configured dynamic-author client: best guess) together with a RADIUS policy that rejects the client, or block it on a firewall.
* **The CLI.** `clear wireless client mac-address <mac>` exists as a command, but DENIS never builds a command line or sends text to a shell: with no call in the models, a feature is not built. On IOS XE older than 17.14 the RPC is not in the public models (documented: the module revision 2024-03-01, version 1.3.0, "Added RPC for client deauthentication", first appears in the 17.14.1 files), so those controllers are read but not disconnected, and *Test connection* says so.
* **Quarantine, flows, ports.** DENIS does not change a client's VLAN or policy on the controller, writes no rules on it, and a wireless controller has no switch port to switch off through it.

## Setup on the controller

Enable RESTCONF over HTTPS with local authentication and make a dedicated user:

```
aaa new-model
aaa authentication login default local
aaa authorization exec default local
username denis-wlc privilege 15 secret <a long password>
restconf
ip http secure-server
ip http authentication local
```

* `restconf` and `ip http secure-server` are **documented**. AAA is **documented** as required for RESTCONF (the guide shows `aaa new-model`, `aaa authentication login default ... local` and `aaa authorization exec default ... local`). `ip http authentication local` is **best guess** (it appears in field configurations, not on the guide's page).
* **Privilege level.** The guide mentions users "defined with privilege level 15 access" (documented) and shows no way to read wireless data with less. Whether a **read-only user** (for example `privilege 1`, or privilege 15 limited by command authorisation or a role) may read the wireless operational data over RESTCONF is **best guess**: try `privilege 1` first, and if *Test connection* answers HTTP 401 or 403, the user needs more. DENIS itself only reads (`GET`) and sends the one `POST` described above, but the account you make can do whatever its privilege allows, so give it a long password, use it for nothing else and limit who may reach the HTTPS server, for example with an access list on the HTTP server (`ip http access-class`, best guess for the exact syntax of your release).
* The address is `https://<controller>` (port 443). RESTCONF is served at `/restconf` (documented).
* A new connector reads the clients by default; see *Reading the clients* below.

In DENIS (*Network → Equipment → Add a connector → Cisco Catalyst 9800 wireless controller (WLC)*): **Controller address**, **Username**, **Password** (stored sealed as `nac.cisco_wlc.password`), the MACs that must never be touched, and the TLS settings below.

## TLS

* **Pinned certificate (recommended).** The controller's certificate is often self-signed. Leave *Verify TLS certificate* ticked and paste the controller's certificate (PEM) into *Pinned controller certificate*; it is then trusted only if it is that one.
* **Verification off.** Untick *Verify TLS certificate* for a lab. The connection is encrypted but not authenticated.

Redirects are never followed: the password travels only to the address in the settings. Changing the address, the TLS settings or the pinned certificate while the saved password is kept needs your DENIS password (the same rule as for every connector).

## How DENIS signs in

HTTP Basic on every request (`Authorization: Basic base64(user:password)`), nothing kept between calls, JSON in both directions (`Accept` and `Content-Type: application/yang-data+json`, documented). The password is never written to the store, the ledger or the audit.

## What DENIS asks the controller

All reads are `GET /restconf/data/<module>:<container>/<list>` (documented root and media type). The module and leaf names are **documented** (the public YANG files); that the controller serves them to the configured user in the usual RESTCONF JSON shape is **best guess**.

| Data | Why | Label |
|---|---|---|
| `Cisco-IOS-XE-wireless-access-point-oper`: `ap-name-mac-map` (`wtp-name`, `wtp-mac`, `eth-mac`) | The access points, their radio and Ethernet MACs; DENIS never acts on one. | documented |
| same module: `capwap-data` (`wtp-mac`, `name`, `wtp-ip`, `ap-state`, `device-detail/static-info/ap-models/model`) | Name, address, model of each access point. | documented |
| same module: `lldp-neigh` (`wtp-mac`, `neigh-mac`, `port-id`) | The switch and port an access point hangs on. | documented (`neigh-mac` meaning: best guess) |
| `Cisco-IOS-XE-wireless-client-oper`: `common-oper-data` (`client-mac`, `ap-name`, `client-type`, `co-state`, `username`) | The clients, their access point and state. | documented |
| same module: `dot11-oper-data` (`vap-ssid`, `ap-mac-address`), `traffic-stats` (`most-recent-rssi`), `policy-data` (`res-vlan-id`), `sisf-db-mac` (`ipv4-binding/ip-key/ip-addr`) | SSID, signal, VLAN and address of a client. | documented |
| `Cisco-IOS-XE-native:native/version`, `/hostname` | The release and the host name for *Test connection* and the version shown. Optional: a user that may not read them still works. | best guess |
| `POST /restconf/operations/Cisco-IOS-XE-wireless-client-rpc:apf-ms-delete-all` | The only change (see above). | RPC and inputs documented, URL form and 204 answer best guess |

A list is read with the documented `fields` selector where the answer would be large; a controller that answers HTTP 400 is asked again without it. The query parameters `offset` and `limit` are **not documented** for IOS XE and are not used: a list is read in one request, limited to 16 MB and to 6000 rows, and a list cut by a limit is a partial read, never a guess.

## Test connection

*Test connection* reads the access point list, the client list and, if the user may, the release and host name. It **writes nothing** (it sends only `GET`). It says if the release is older than 17.14.

## Reading the clients (optional)

With *Read the clients and devices this controller sees (read only, experimental)* ticked, DENIS lists the controller's clients (MAC, address, Wi-Fi or wired, SSID, signal, VLAN, access point) and access points (name, model, address) on the map and the device pages, every two minutes, with growing waits after a failure. It never changes anything on the controller. Lists are bounded (5000 clients, 1000 access points) and a list cut by a bound or refused is marked partial. A detail list that the user may not read (signal, VLAN, address) leaves that detail out.

* **Uplink of an access point.** DENIS draws an access point under the switch only when the access point reports it in its **LLDP** neighbour table (`lldp-neigh`): the neighbour's MAC and its port. The CDP table (`cdp-cache-data`) names a neighbour by device id and address, not by MAC, so it is not used. An access point needs LLDP switched on (best guess: in its AP join profile) and a switch that sends it. An access point that reports no neighbour has no uplink; DENIS does not guess one. The parent of every access point is the controller itself.
* The access point's MAC is its **Ethernet** MAC from `ap-name-mac-map` where the controller gives it (the address the access point shows on the wire), otherwise its radio MAC.

## What DENIS records

The ledger row is written before anything changes (`unconfirmed`), the audit entry before the connector is touched, and the call is a step with the later note about the client table. The row holds the MAC and the controller address. DENIS creates no object on the controller, so there is nothing to find or clean up as an orphan.

## Removing everything by hand

Nothing is created on the controller by DENIS. Remove the user you made and, if you no longer need RESTCONF, `no restconf`.

## Verified and not verified

* **documented**: the RESTCONF root and JSON media type; `restconf` and `ip http secure-server`; AAA as a requirement; the `fields` and `depth` parameters; the models, lists and leaves in the table above; the RPC `apf-ms-delete-all` with its inputs (`mac-addr`, `ip-addr` or `user-name`, and `zone-id`), and that it is in the models from the 17.14.1 files.
* **best guess**: `ip http authentication local`; that a privilege-1 (read-only) user can read the wireless data; the exact URL, body and answer of the RPC call; that `native/version` and `native/hostname` are readable; that the `fields` selector with those paths is honoured; the meaning of `neigh-mac`; that CDP and LLDP neighbours are present when the access points have them switched on; the behaviour of `ip http access-class`.
* **verified**: nothing. No real Catalyst 9800 has been used.
* **Checked against a local fake controller over TLS, in the test suite**: Basic sign-in on every request, a wrong password, a redirect that is not followed, a refused `fields` selector, a missing, empty, forbidden, hostile or too long list, the read of clients, access points and the LLDP uplink, the refusals that must send nothing (an access point, a wired client, an unknown client, the controller's own address, a protected MAC, an IP address), the disconnect with its note about the client table, a controller without the call, a controller that says no, a lost answer, and that the password is in no path, row or step.

## What hardware would verify it

A Catalyst 9800 (a 9800-CL virtual machine is enough for the models and the sign-in; **clients and access point neighbours need a real access point and a client**, for example a Catalyst 9100 series access point and a phone) on IOS XE 17.14 or later. Then: *Test connection* with a read-only user and with a privilege-15 user; read the clients and access points and compare with the controller's own view; check the LLDP uplink with LLDP on and off; end a Wi-Fi client's session and watch whether it rejoins; try it on an IOS XE release before 17.14; check the RADIUS CoA connector against the same controller for the lasting block.

## Limits

* Ending a session only; no block for good, no IP address, no flow, no quarantine.
* A client that rejoins at once is normal; ending its session is not a way to keep it out.
* Wireless clients only. Wired and guest-LAN clients are refused.
* A controller on IOS XE older than 17.14 is read but not disconnected.
* One controller per connector. A high-availability pair is reached through its management address; what happens at a switchover during a read is not known.

## Details from the console

The console shows a short line under each field and a short note behind its (i). The full explanation of each field is here.

- **Username**: A local user of the controller; give it only the rights this needs.
- **Never act on these MAC addresses**: List DENIS itself, your gateway, the controller and any device that must never be cut off. An access point of the controller is refused anyway.
- **Read the clients and devices this controller sees**: Read only. On by default for a new connector. A connector made before 4.3 reads clients only after an administrator ticks this.
