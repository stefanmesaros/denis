# Enforcement: MikroTik RouterOS

Status: **Experimental. Simulator only: not yet validated on real equipment.** Everything below was built from MikroTik's published RouterOS 7 REST API documentation and checked against a fake router in DENIS's own tests. It has never been run against a real MikroTik. Nothing here is listed as validated on hardware.

Lab use: the host block (address list) is allowed only while an administrator has switched on *Allow connectors that are not validated on real equipment (lab use)* under *Settings → Response policy*. The actions new in 4.1 (flow block, quarantine, disabling a port, removing connections) additionally need *Allow experimental actions (lab use)*. Releasing an action and removing what DENIS made always work.

Besides the connector's own refusals, every block through it is refused for a loopback, unspecified, broadcast or multicast address, for DENIS itself and for the gateway, for DNS and directory servers, for anything in the connector's *protected networks*, and for an address in an open `arp_conflict` alert unless the administrator ticks a box to accept that, before anything is sent. Unblock is never refused for any of these reasons.

## What DENIS can do on a MikroTik

| Action | What DENIS writes | What it does not do |
|---|---|---|
| **Block device** (address list) | One entry in the address list you name (default `denis-blocked`), its comment led by `denis-<tag>-<id>`; DENIS's two drop rules (`chain=forward`, `src-address-list` and `dst-address-list`) if they do not exist yet, at the top of the forward chain; removes the device's open connections. | It never edits, moves, enables or deletes any other rule. The two drop rules stay after a release (they match nothing while the list is empty). |
| **Quarantine** (quarantine list) | The same kind of entry in a second address list you created for quarantine. Removes the device's open connections. | It creates **no rule at all** and never an allow rule. What a quarantined device may reach is decided by your own firewall rules that use that list (DHCP, DNS, NTP, a remediation server). DENIS does not check them. |
| **Block flow** (drop rule) | One filter rule `chain=forward action=drop` for exactly one source host, destination host, protocol and port, placed at the top of the filter table (above any fast-track rule), its comment `denis-<tag>-<id> DENIS managed; owner <tag>; ...`; the flow's open connections are removed. | Only with the per-instance switch *Allow DENIS to create deny rules on this firewall*. Drop only: no code path builds an accept, fast-track or other rule. Never a network, a list or a name. Never the `input` or `output` chain, so the router's own management cannot be cut. |
| **Disable port** (Ethernet) | `PATCH interface/ethernet/<id>` with `disabled=true` for one Ethernet port, after the typed confirmation of its name; released with `disabled=false`. | Never an uplink, a trunk, a link aggregation member, a routed port, the port DENIS is reached through, the gateway's port, or a link to other network equipment (see below). When DENIS cannot tell, it refuses. |
| **End sessions** (connection removal) | Removes the connection-table entries of one address, at most 2000. | It cannot be undone. The device can open new connections at once. Never the router's own addresses. |
| Move to quarantine VLAN | Not built in this version. | |

Every object DENIS makes on the new path carries `denis-<tag>-<id> DENIS managed; owner <tag>; action <id>; by <login>; expires <time or never>` in its comment (RouterOS has no name field on a rule or a list entry, so the comment is the name). Text you typed as a reason is never sent to the router. DENIS deletes only objects whose comment starts with its own name and owner tag. An object with a DENIS-style name that does not carry the marker is never touched, and the action is refused.

## How a host block works (the old method, still the same)

A block of one IPv4 or IPv6 address, through the router's RouterOS **7.1+ REST API** (`https://<router>/rest/...`):

1. **Makes sure DENIS's two drop rules exist**, per address family, and creates them when they do not: `chain=forward action=drop src-address-list=<list>` and `chain=forward action=drop dst-address-list=<list>`, each with the comment `DENIS managed (...)`, placed **before the first existing rule** (the top of the forward chain).
2. **Adds the address** to the list. For the old buttons the comment is `DENIS <ledger id> <timestamp>`, for the new actions `denis-<tag>-<id> DENIS managed; ...`.
3. **Removes the target's connections** from the connection-tracking table (`/ip/firewall/connection`, or `/ipv6/firewall/connection`): a tracked or fast-tracked connection is not looked at again by a new rule.
4. **Reads back** the list entry and the two rules. Only then is the block "Blocked"; otherwise it is "Unconfirmed".

An unblock removes DENIS's entries of that address from the list and reads the list back. If DENIS's own drop rule has been disabled on the router, the block is refused with a sentence saying so, rather than silently changed.

## The flow rule and where it goes

A flow block writes one rule (two when both directions are blocked: the second is `denis-<tag>-<id>-r`) with `chain=forward action=drop src-address=<src> dst-address=<dst>`, plus `protocol` and `dst-port` when the flow has them. DENIS asks RouterOS to put it before the first rule of the filter table (`place-before`), reads the table back and checks that nothing but DENIS's own rules stands before it. A router that ignores `place-before` is asked once to move the rule; if the rule is still not at the top, DENIS removes it and the action ends *failed*. Rules at the top are above the default `fasttrack-connection` rule, which is what lets the drop rule see packets of connections that were fast-tracked before. DENIS also removes the flow's open connections from the connection table (only entries between the two addresses, and of that protocol and port), because an established or fast-tracked connection is not re-evaluated by a new rule.

RouterOS checks the forward chain **after destination NAT and before source NAT**: a destination behind a port forward is matched by its internal address, and a source behind masquerade by its address before translation.

## Disabling a port: what DENIS refuses

DENIS acts only on a port listed under *Interfaces, Ethernet*, and only after reading the router. It refuses, and sends nothing, when the port:

* is a member of a bonding (link aggregation) interface;
* holds an IP address, or is the interface of a DHCP client or a PPPoE client (a routed or uplink port);
* has a neighbour seen on it (LLDP, MNDP or CDP: a link to other network equipment);
* is tagged on a bridge VLAN, carries a VLAN interface, or is a bridge port that admits tagged frames (a trunk);
* is the port DENIS is reached through: DENIS finds the interface of the connected network DENIS's address is in, or the route to it, and when that is a bridge it looks the DENIS host up in the ARP table and the bridge host table to find the exact port; if it cannot find it, every port of that bridge is refused;
* is the port of the default gateway, found the same way (IPv4 and, where the router has the IPv6 package, IPv6);
* is already disabled, or does not exist, or whose name has anything but letters, digits, dots, dashes and underscores.

When any of these reads fails, DENIS refuses ("could not tell"); it never assumes a port is a plain access port. The check is made when you ask for the plan and again just before the write. The port name must be typed in the confirmation. The port stays disabled in the router's configuration, after a restart too, until it is enabled again.

## What it does not do

* **No MAC blocking.** A MAC-only target is refused. Blocking by MAC at layer 2 (`/interface/bridge/filter`, bridge hosts, wireless access lists) is not part of this connector.
* **Only traffic that passes through the router's `forward` chain is stopped.** Two devices talking inside one bridge or switch without bridge-firewall (`use-ip-firewall`) never reach it, and traffic that the router's switch chip forwards in hardware (hardware offload) never reaches the CPU firewall at all. The block follows the address: a DHCP lease can move the address to another device later, so confirm the address is still the right one just before blocking.
* **It does not manage the router's other firewall rules, NAT, DHCP or users.**
* **It does not create the user, group or certificate** (below), and does not enable the `www-ssl` service.

## Setup on the router

Commands are RouterOS CLI (Terminal in WinBox or SSH); the same can be done in WinBox. Check them against MikroTik's documentation for your RouterOS version before relying on them.

1. **A certificate for `www-ssl`.** RouterOS has no certificate on `www-ssl` by default. Create a self-signed one that names the address DENIS connects to:
   `/certificate add name=denis-rest common-name=192.168.88.1 subject-alt-name=IP:192.168.88.1 days-valid=3650 key-usage=key-cert-sign,crl-sign,digital-signature,key-encipherment,tls-server`, then `/certificate sign denis-rest`.
2. **Enable the service**, with that certificate, reachable only from DENIS:
   `/ip service set www-ssl certificate=denis-rest disabled=no address=<DENIS address>/32`
   (the REST API is served on the `www-ssl` port, 443 by default; plain `www` also serves it, but DENIS only speaks HTTPS).
3. **A least-privilege group and user.** The policies DENIS is expected to need are **`read`, `write` and `rest-api`**: `read` for the reads, `write` for the address list, the filter rules, the connection table and the Ethernet ports, `rest-api` to use the REST API at all. `policy` (user and group management) and `test`, `ssh`, `winbox` and the others are not needed. This minimal set is what the documentation suggests but **has not been tried on a real router**: if the router answers HTTP 403, add `api` and then `web` one at a time and report back; verify against MikroTik's documentation for your version.
   `/user group add name=denis-api policy=read,write,rest-api`
   `/user add name=denis group=denis-api password=<a long random password> address=<DENIS address>/32`
4. **Quarantine (optional).** Create a second address list for quarantine (it can be empty) and **your own firewall rules** that use it: allow what a quarantined device needs (DHCP, DNS, NTP, the remediation server) and drop the rest, above the rules that would otherwise let it through. DENIS never creates these. Enter the list's name in *Quarantine address list name*. Leave it empty to switch quarantine off.
5. **In DENIS** (*Network → Equipment → Add a connector → MikroTik*): **Base URL** `https://<router address>` (add `:port` if you changed it), **REST API user** and **Password** (stored sealed as `nac.mikrotik.password`), the **address list name** (default `denis-blocked`), addresses never to block, and the TLS settings below. Use **Test connection**: it reads the router's identity, version and own addresses and the DENIS rules, and writes nothing.
6. **Flow blocks:** tick *Allow DENIS to create deny rules on this firewall* only if you accept that DENIS writes filter rules on this router. It is off by default, and DENIS will not create a flow rule while it is off. Turning it on needs your password again and is written to the audit log. A wrong drop rule can cut off traffic.
7. **Disabling a port:** for the device name of a port, use this connector's name (or the router's identity) and the port's name, for example `ether3`.

## TLS

RouterOS ships self-signed certificates, so DENIS offers two ways:

* **Pinned certificate (recommended).** Leave *Verify TLS certificate* ticked and paste the router's certificate (PEM) into *Pinned router certificate*. Export it on the router with `/certificate export-certificate denis-rest type=pem` (it creates `cert_export_denis-rest.crt` under *Files*) and open that file as text. With a pin, DENIS trusts **only** that certificate. The certificate must name the address in the Base URL (`subject-alt-name=IP:...` above), or the connection is refused.
* **Verification off.** Untick *Verify TLS certificate* for a lab. The connection is encrypted but not authenticated.

Changing the Base URL, the TLS settings or the pinned certificate while the saved password is kept needs your DENIS password (the same rule as for every connector).

## Credentials

A user name (plain configuration) and a password (`nac.mikrotik.password`), sent as HTTP Basic auth on every request. The password is never logged, audited or returned.

## What DENIS records

The ledger row is written before anything changes (`unconfirmed`), the audit entry before the connector is touched, and the audit entry of the result carries the router's identity and RouterOS version. Each step of an action (rule created, rule moved, check at the top, connections removed, port disabled) is recorded with its outcome. A write whose answer was lost (a timeout, a reset, a 5xx) is read back and recorded as `unconfirmed` if the read-back disagrees; a definite refusal (a 4xx) after an earlier step is compensated (the earlier steps are undone) and the action ends *failed*, or *partial* and still releasable if the undo is refused too.

## Refusals specific to this connector

The router's **own addresses** (IPv4 from `/ip/address`, IPv6 from `/ipv6/address`; if they cannot be read the block is refused), for a flow block, an end of the flow and for ending sessions as well; the address in the Base URL when it is a literal IP, the address DENIS itself sends from toward the router, the *Never block these IP addresses* list, a RouterOS older than 7.1 (no REST API), a disabled or invalid DENIS drop rule, and a list entry for the address that DENIS did not make.

## Removing everything by hand

* Entries: `/ip firewall address-list remove [find comment~"^DENIS"]` and `... [find comment~"^denis-"]` (and `/ipv6 firewall address-list ...`).
* Rules: `/ip firewall filter remove [find comment~"^DENIS managed"]` and `... [find comment~"^denis-"]` (and `/ipv6 firewall filter ...`).
* A port: `/interface ethernet enable ether3`.

## Verified and not verified

* **Verified (against a local fake RouterOS REST server over TLS, in the test suite):** the request sequence, the rules' shape (forward only, drop only, top of the chain, created once), the entry and rule comments, idempotent second block, connection removal for all four address fields and for a flow's own connections only, unblock leaving the host block's rules, quarantine writing no rule, the position check and the move fallback, a rule that cannot be put at the top being removed, a foreign object under a DENIS name being refused and never touched, a refused write after earlier steps (compensated, or partial), a lost answer (read back, releasable), the port refusals one by one, the typed port name, disabling and enabling a port, refusal of the router's own addresses, the pinned certificate, authentication and permission failures, 4xx, 5xx and timeouts, IPv6 paths, orphans found by marker and removed only when they carry it. **Not verified on any real MikroTik.**

Behaviours that are unproven vendor facts (marked **[verify]** in the code):

* **`place-before` in a REST `PUT`** to `ip/firewall/filter` puts the rule before the given rule. If it does not, DENIS tries `POST ip/firewall/filter/move` with `numbers` and `destination` and checks again.
* **Hardware offload and fast-track.** Traffic that a switch chip forwards in hardware, and connections that are fast-tracked, can bypass the CPU firewall; DENIS removes tracked connections but cannot stop a hardware-forwarded flow between two ports of one bridge.
* `PATCH interface/ethernet/<id>` with `disabled=true` (and `false`) disables and enables the port, and `disabled` reads back as `true` or `false`.
* A `GET` with `name=`, `interface=`, `address=` or `mac-address=` filters the rows.
* `ip/neighbor` lists LLDP, MNDP and CDP neighbours with the interface they were seen on, and a neighbour of an ordinary host (not network equipment) can make a port look like infrastructure; DENIS then refuses, never the other way.
* `ip/route` rows carry `immediate-gw` (`<address>%<interface>` or an interface name) and `dst-address`, and `active=true` selects the active ones.
* `interface/bridge/host` lists the port a MAC address was learned on in `on-interface`, and the IPv6 neighbour table is `ipv6/neighbor`.
* RouterOS accepts the `.proplist` query and the string-valued JSON the code reads, and a 404 on a delete means the object is already gone.
* The comment field accepts the 255 character marker.

## Limits

* Port classification reads IPv4 routes and addresses always, IPv6 only where the router has the IPv6 package. A router whose only way out is something DENIS cannot resolve is refused for every port that might be on the path.
* The access VLAN move is not built.
* IPv4 and IPv6 are supported for host blocks, quarantine, flow blocks and ending sessions.

## Existing instances

Instances from earlier versions keep working and nothing changes for them: the same block list, the same two drop rules, the same entries (comment `DENIS <ledger id> <timestamp>`), the same ledger rows. The old *Block…* and *Unblock…* buttons act as before. Records the old routes made are released through the old *Unblock…*; records of the new actions are released through the new action list.
