# Enforcement: MikroTik RouterOS

Status: **Verified on MikroTik E50UG, RouterOS 7.21.4: block device (address list), block a flow, quarantine by address, End sessions (needs loose TCP tracking off and drop-invalid rules, see the setup notes) and their release; on the new `wifi` stack with one access point under a CAPsMAN manager (4.5): block Wi-Fi client by MAC, its release, and disconnect Wi-Fi client; not tested: disabling a port.** Tested on a real MikroTik E50UG (hEX family, RouterOS 7.21.4) with a laptop behind it: block flow (rule created, traffic stopped, the router's counters confirm the drops, expiry removed the rule); block device (pings stopped within 3 s, DENIS read the entry back and confirmed it, manual release within 3 s, and the automatic expiry released it too; the 4.2 read-back fix works); quarantine by address (in force within 3 s, release within 3 s, extending the time, a repeated quarantine refused as a conflict, expiry); End sessions (an established SSH session was cut, but only with loose TCP tracking switched off and a drop-invalid rule in the input and forward chains; the plan warns when they are missing); and the refusal of flow blocks while *Allow DENIS to create deny rules* is off. Not tested: disabling a port, removing connections of an IPv6 address, lost answers, a reboot, a concurrent edit by another administrator, a 24 hour hold, repeated cycles, other RouterOS versions or models. The verified actions carry no *Experimental* mark and need neither lab setting; disabling a port stays *Experimental* and needs the lab switches below.

Lab use: *Block device*, *Block a connection*, the quarantine by address and *End sessions* are validated on real equipment and need no lab setting. Disabling a port is allowed only while an administrator has switched on both *Allow Experimental connectors (lab use)* and *Allow experimental actions (lab use)* under *Settings → Response policy*. Releasing an action and removing what DENIS made always work. Reading the Wi-Fi clients and access points is *Experimental*. *Block Wi-Fi client by MAC* and *Disconnect Wi-Fi client* are verified on the new `wifi` stack (one access point under a CAPsMAN manager) and need no lab setting; a client on the legacy stack (not supported) is refused unless both lab settings are on (see *Wi-Fi* below).

Besides the connector's own refusals, every block through it is refused for a loopback, unspecified, broadcast or multicast address, for DENIS itself and for the gateway, for DNS and directory servers, for anything in the connector's *protected networks*, and for an address in an open `arp_conflict` alert unless the administrator ticks a box to accept that, before anything is sent. Unblock is never refused for any of these reasons.

## Quick setup (about 10 minutes)

Tested on a MikroTik E50UG with RouterOS 7.21.4 (block device, flow block, quarantine by address, End sessions, release, expiry and
extension). Other RouterOS 7 versions share the same REST API and are expected to work; they have not been tried.
RouterOS 6 has no REST API and is not supported.

**What must be in the traffic path.** The devices you want to stop must **be routed by this MikroTik**: the block works in the
`forward` chain of the firewall, so traffic that stays inside one bridge or switch (two devices in the same subnet on bridge
ports) never reaches it, and neither does traffic that the switch chip forwards in hardware. DENIS reaches the router's HTTPS
address (`www-ssl`) from the DENIS server.

**Before you start:** be connected to the router by WinBox (also over MAC address) or SSH, preferably in *Safe Mode* (Ctrl-X) so
that a mistake reverts itself; know the DENIS server's IP address; make a backup first
(`/system backup save name=pre-denis` and `/export file=pre-denis`).

1. **HTTPS and the API user.** In the RouterOS terminal (replace `<router address>` and `<DENIS address>`). **The certificate
   is not optional**: RouterOS has no certificate on `www-ssl` by default, and without one the router accepts the TCP
   connection but the TLS handshake fails, so DENIS cannot connect. The `address=` restriction keeps the service and the user
   reachable from DENIS only. (If DENIS reaches the router through another interface, the router's firewall `input` chain
   must also allow TCP 443 from the DENIS server.)
   ```
   /certificate add name=denis-rest common-name=<router address> subject-alt-name=IP:<router address> days-valid=3650 key-usage=key-cert-sign,crl-sign,digital-signature,key-encipherment,tls-server
   /certificate sign denis-rest
   /ip service set www-ssl certificate=denis-rest disabled=no address=<DENIS address>/32
   /user group add name=denis-api policy=read,write,rest-api
   /user add name=denis group=denis-api password=<a long random password> address=<DENIS address>/32
   ```
2. **Quarantine rule (only if you want *Quarantine*; do it once, by hand).** The rule must sit in `forward` **before the
   fasttrack rule**, otherwise connections that are already open are not cut:
   ```
   /ip firewall filter add chain=forward action=drop src-address-list=denis-quarantine place-before=[find where action=fasttrack-connection] comment="DENIS quarantine"
   ```
   *Block device* needs no rule of your own (DENIS creates its two drop rules at the top of the filter table).
3. **In DENIS:** *Network → Equipment → + Add a connector…* → *MikroTik RouterOS (address list)*: **Base URL (www-ssl service)**
   `https://<router address>`, **REST API user** `denis` and its **Password**, **Block address list name** `denis-blocked`,
   **Quarantine address list name (optional)** `denis-quarantine` (only if you made the rule in step 2), and under **Never block
   these IP addresses** the router's own addresses, the gateway and DENIS. For the certificate either paste it into **Pinned
   router certificate** (export: `/certificate export-certificate denis-rest type=pem`, then open the file
   `cert_export_denis-rest.crt` under *Files* as text) or, in a lab, untick **Verify TLS certificate**. Press **Test
   connection**: it reads the identity, the version and the router's own addresses, and writes nothing.
   Then under *Settings → Response policy* tick *Allow administrators to block devices from DENIS*. Block device,
   block flow, the quarantine by address and End sessions are validated and need no lab setting; disabling a port needs
   both lab switches (*Allow Experimental connectors (lab use)* and *Allow experimental
   actions (lab use)*). For End sessions to cut running TCP sessions, set up the router as in *End sessions: what the
   router must have* below (loose TCP tracking off, drop-invalid rules in input and forward).
4. **Try it on a harmless device:** *Respond → Block device* for 5 minutes on a test client behind the MikroTik. The client must
   lose its connection and regain it at the end (or at **Release**). **Block flow** (one flow) needs *Allow DENIS to create deny
   rules on this firewall* ticked (it asks for your password again); the plan shows the protocol and port, and "any" when none
   were given. In WinBox, *IP → Firewall → Filter Rules* shows DENIS's rules with their packet counters, and *Address Lists*
   shows the entry.

If something fails: HTTP 403 means the group lacks `rest-api` or the user's *address* does not include the DENIS server;
the connection fails at the TLS step when `www-ssl` has no certificate assigned or the certificate
does not name the address in the Base URL; "accepted but still reachable" means the traffic does not pass the forward chain,
or the quarantine rule is not before `fasttrack`.

### What happens on the router, in order

* **Block device:** DENIS makes sure its two drop rules exist (`chain=forward`, one for `src-address-list`, one for
  `dst-address-list`, placed before the first rule, so before fasttrack), adds the device to `denis-blocked`, removes the
  device's open connections, and reads the list and the rules back. **Release** (or the end of the time) removes the list
  entry. The two drop rules stay (they match nothing while the list is empty).
* **Quarantine by address:** the same kind of entry in `denis-quarantine`; the drop is **your** rule (step 2), which must
  stand before the fasttrack rule or connections that were already open are not cut. DENIS creates no rule for it.
* **Block flow:** one drop rule for exactly one source, destination, protocol and port at the top of the filter table, read
  back to check its position, removed at the end.
* **Extend** adds the time you choose to what is left by default (an action with 4 minutes left, extended by 15, ends in
  19); the other choice, *from now*, sets the new end that long from the moment you confirm. The dialog shows the new end
  as a clock time before you give your password. The expiry job releases about 30 seconds after the end. (On the tested
  build, before 4.2, Extend always counted from now.)
* **A repeated action** on the same address is refused as a conflict (no duplicate entry).
* **Persistence:** RouterOS applies REST changes to its configuration at once. DENIS removes what it made at the end; the
  commands under *Removing everything by hand* below do it manually.

### Known issues in the tested build, and what 4.2 changes

These were seen on the E50UG with a build before 4.2. 4.2 changes the code for each of them; the block device read-back fix was confirmed on the router itself (2026-10-21), the others are tested against answers built from the RouterOS documentation.

* **Block device read-back.** On the E50UG the block device was enforced (traffic stopped, packets counted, expiry restored
  the client) but DENIS reported the read-back of the entry as failed: the read-back counted the default input-chain rules
  above DENIS's drop rules. 4.2 counts only forward-chain rules that can let the traffic through. The fix was confirmed on the E50UG (RouterOS 7.21.4): DENIS read the entry back and reported the block as confirmed. If you still see a failed
  read-back, check the router (*Address Lists* and the packet counters of the rules) and the action's steps before you
  repeat it.
* **Quarantine by hardware address** from the Respond dialog was refused when an old address of the device lies in a network
  listed under *Never block addresses in these networks*. In 4.2 an address the device left more than a day ago, with a
  fresh address outside those networks since, is a warning you tick (the plan names the old address); a recent one still
  refuses.
* A flow entered without protocol and port is blocked for **all** protocols and ports between the two addresses. In 4.2
  the plan says so ("Covers traffic of any protocol and to any port ...").

## What DENIS can do on a MikroTik

| Action | What DENIS writes | What it does not do |
|---|---|---|
| **Block device** (address list) | One entry in the address list you name (default `denis-blocked`), its comment led by `denis-<tag>-<id>`; DENIS's two drop rules (`chain=forward`, `src-address-list` and `dst-address-list`) if they do not exist yet, at the top of the forward chain; removes the device's open connections. | It never edits, moves, enables or deletes any other rule. The two drop rules stay after a release (they match nothing while the list is empty). |
| **Quarantine** (quarantine list) | The same kind of entry in a second address list you created for quarantine. Removes the device's open connections. | It creates **no rule at all** and never an allow rule. What a quarantined device may reach is decided by your own firewall rules that use that list (DHCP, DNS, NTP, a remediation server). DENIS does not check them. |
| **Block flow** (drop rule) | One filter rule `chain=forward action=drop` for exactly one source host, destination host, protocol and port, placed at the top of the filter table (above any fast-track rule), its comment `denis-<tag>-<id> DENIS managed; owner <tag>; ...`; the flow's open connections are removed. | Only with the per-instance switch *Allow DENIS to create deny rules on this firewall*. Drop only: no code path builds an accept, fast-track or other rule. Never a network, a list or a name. Never the `input` or `output` chain, so the router's own management cannot be cut. |
| **Disable port** (Ethernet) | `PATCH interface/ethernet/<id>` with `disabled=true` for one Ethernet port, after the typed confirmation of its name; released with `disabled=false`. | Never an uplink, a trunk, a link aggregation member, a routed port, the port DENIS is reached through, the gateway's port, or a link to other network equipment (see below). When DENIS cannot tell, it refuses. |
| **End sessions** (connection removal) | Removes the connection-table entries of one address, at most 2000. | It cannot be undone. The device can open new connections at once. Never the router's own addresses. |
| **Block Wi-Fi client by MAC** (`block_client_mac`) | One entry in the router's Wi-Fi access list that refuses the client's MAC address, first in the list, its comment led by `denis-<tag>-<id>`; then the client's row is removed from the registration table so it is disconnected. | It never edits another entry. Wi-Fi clients only; a wired device, a CAPsMAN access point, a neighbour and the router itself are refused. See *Wi-Fi* below. |
| **Disconnect Wi-Fi client** (`disconnect_client`) | Removes the client's row from the Wi-Fi registration table. | Blocks nothing: the client can join again at once. |
| Move to quarantine VLAN | Not built in this version. | |

Every object DENIS makes on the new path carries `denis-<tag>-<id> DENIS managed; owner <tag>; action <id>; by <login>; expires <time or never>` in its comment (RouterOS has no name field on a rule or a list entry, so the comment is the name). Text you typed as a reason is never sent to the router. DENIS deletes only objects whose comment starts with its own name and owner tag. An object with a DENIS-style name that does not carry the marker is never touched, and the action is refused.

## Block domain (4.5, Experimental)

Evidence labels for this section: **documented** (in the vendor's published pages), **best guess** (from the product or other people's code, not checked in a published page), **verified** (tried on real equipment, with the date). **Nothing in this section is verified**; it was built and tried against DENIS's simulated device only, so the action is Experimental and needs both lab switches.

**What DENIS writes** (method `dns_static`): a static DNS entry (`ip/dns/static`) for the name with `type=FWD`, `forward-to` = the first DNS server the router uses, `match-subdomain=yes` for *and below*, `address-list` = **DENIS's own name list** `<block list>-names` (never the host-block list, whose two rules drop both directions), its comment `denis-<tag>-<id> DENIS managed; owner <tag>; ...`. The first name block also creates DENIS's chain of the same name: a jump at the top of the forward chain for traffic **to** an address in the name list (`dst-address-list`), then in the chain one `return` rule per address that is never dropped (private, shared, loopback, link-local, multicast and reserved IPv4 ranges, the connector's *protected addresses* and *protected networks*, the router's own DNS servers and the well-known public resolvers), then one `drop` rule. A `return` goes back to the forward chain below the jump, so your own rules and DENIS's other rules still apply to that traffic. Release deletes the entry, and the release of the last name block removes the jump and the chain. Needs *Allow DENIS to create deny rules*. A static entry for the same name that DENIS did not make, or a rule in DENIS's chain that DENIS did not make, is never touched and the action is refused.

**The addresses the name resolves to.** Because the router turns the name into addresses, the plan resolves the name now and refuses the block when any answer is an address DENIS never blocks (private, internal or special, a protected address, the address of DENIS, of the administrator's session or of the router, or a DNS resolver), listing the addresses. The plan also says that the addresses can change after the block is applied: the return rules above are what keeps a later answer of that kind from being dropped. The hourly read-back judges a name block by what DENIS owns: the marked static DNS entry gone (or disabled, or feeding another list) means the block is gone. When today's keep set has grown (a protected address or network added, the router's DNS servers changed, for example a new resolver from the provider, or a resolver added to DENIS's list), the read-back adds the missing `return` rules to DENIS's chain (a `return` rule only lets more through, so no person is needed) and the block stays confirmed. A chain that someone changed (a rule DENIS did not make, a disabled rule, a missing jump or drop rule) is reported as a deviation: the action stays in effect, a notice says what differs, DENIS does not change it, and the release still removes the entry.

**What it does:** every device behind this router that uses the router as its DNS server.

**What it does not do:** it works only for names the router itself resolves (*IP, DNS, allow remote requests* on, and devices pointed at the router). A device with another resolver, encrypted DNS or a direct connection by address is not stopped (the router cannot know the name). The addresses already learned stay in the list until their DNS lifetime ends, **also after the release**. IPv4 only. **Best guess, not checked in a published page or on a router:** that `address-list` works on a `FWD` static entry on the RouterOS version in use, and that `match-subdomain` applies to it.

**What we tried:** the fake router in DENIS's tests (entry and chain created and read back, a second name sharing the chain, release and removal of the chain with the last name, orphan removal, a foreign entry or chain rule refused, no DNS server refused, a name resolving to a private, protected or resolver address refused). Nothing on a real RouterOS. **Documented, not verified:** that a `return` rule in a jumped-to chain resumes the forward chain below the jump (the RouterOS firewall filter actions `jump` and `return`); not tried on a router.

## How a host block works (the old method, still the same)

A block of one IPv4 or IPv6 address, through the router's RouterOS **7.1+ REST API** (`https://<router>/rest/...`):

1. **Makes sure DENIS's two drop rules exist**, per address family, and creates them when they do not: `chain=forward action=drop src-address-list=<list>` and `chain=forward action=drop dst-address-list=<list>`, each with the comment `DENIS managed (...)`, placed **before the first existing rule** (the top of the forward chain).
2. **Adds the address** to the list. For the old buttons the comment is `DENIS <ledger id> <timestamp>`, for the new actions `denis-<tag>-<id> DENIS managed; ...`.
3. **Removes the target's connections** from the connection-tracking table (`/ip/firewall/connection`, or `/ipv6/firewall/connection`): a tracked or fast-tracked connection is not looked at again by a new rule.
4. **Reads back** the list entry and the two rules. Only then is the block "Blocked"; otherwise it is "Unconfirmed".
   The read-back also checks that nothing above DENIS's two rules can let the address's traffic through: an
   `accept`, `fasttrack-connection`, `jump` or `return` rule of the **forward** chain. Rules of the `input` and
   `output` chains do not count (they never see traffic that passes through the router), nor do disabled rules,
   RouterOS's own dynamic counter rule, or rules that drop or only log. The default rules `accept in ipsec policy`
   and `accept out ipsec policy` count only when the router has an IPsec policy in force. When such a rule is above
   DENIS's rules, the block stays "Unconfirmed" and the action's steps name the rule.

An unblock removes DENIS's entries of that address from the list and reads the list back. If DENIS's own drop rule has been disabled on the router, the block is refused with a sentence saying so, rather than silently changed.

### What a host block covers, and what it does not

The two drop rules sit in the `forward` chain, so the block stops everything that **passes through the router** from or to the address: the internet and the other networks the router routes (documented: the chain's purpose; the internet was verified, other networks were not tried). It does not stop:

* **Traffic that does not pass the router.** A device on the same switch or access point, in the same network, talks to its neighbours directly, so a block through the router does not isolate it from them. To cut a device off from its neighbours, quarantine its switch port (a wired device) or use a quarantine VLAN, or block it on its access point (a Wi-Fi client: an access point that has its own connector, or the CAPsMAN manager).
* **Traffic to the router itself** (DHCP, DNS asked of the router, ping of its address). Those packets belong to the `input` chain, which DENIS's rules never touch: the device keeps its address and can still ask the router for names, but cannot reach what the answers name.
* **The Wi-Fi association.** An access point behind the router does not know about the block; the device stays connected to the Wi-Fi.

Tried on 6 November 2026 on the owner's E50UG (RouterOS 7.21.4) with a client connected through a standalone MikroTik access point (a cAP lite): its traffic stopped within about two to three seconds, the counters of the `drop from list` rule rose, and the release restored the traffic within about two to three seconds and left the list empty.

## The flow rule and where it goes

A flow block writes one rule (two when both directions are blocked: the second is `denis-<tag>-<id>-r`) with `chain=forward action=drop src-address=<src> dst-address=<dst>`, plus `protocol` and `dst-port` when the flow has them. DENIS asks RouterOS to put it before the first rule of the filter table (`place-before`), reads the table back and checks that no rule before it can let the flow through (the same check as for the host block's rules above). A router that ignores `place-before` is asked once to move the rule; if the rule is still not at the top, DENIS removes it and the action ends *failed*. Rules at the top are above the default `fasttrack-connection` rule, which is what lets the drop rule see packets of connections that were fast-tracked before. DENIS also removes the flow's open connections from the connection table (only entries between the two addresses, and of that protocol and port), because an established or fast-tracked connection is not re-evaluated by a new rule.

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

## End sessions: what the router must have

*End sessions* removes the address's records from the router's connection table. A running TCP stream is not ended by that alone: while **loose TCP tracking** is on, RouterOS creates a new record when the next packet of the stream arrives, and a stream the router no longer tracks only stops if a **drop invalid** rule drops its packets. On a router set up like this, the removal of the records was confirmed to end an established SSH session (RouterOS 7.21.4, E50UG):

`/ip firewall connection tracking set loose-tcp-tracking=no`
`/ip firewall filter add chain=input action=drop connection-state=invalid place-before=0`
`/ip firewall filter add chain=forward action=drop connection-state=invalid place-before=0`

The default RouterOS configuration already has the two drop-invalid rules (*defconf: drop invalid*); a router that was reset or built without it does not. Since 4.2.1 the plan of *End sessions* reads both settings and shows a warning you tick when loose tracking is on or an enabled drop-invalid rule is missing in the input or the forward chain (the warning names which); when the router cannot be read, the warning says so and the plan still works. *Test connection* shows the same warning. Automatic actions never accept a warning.

DENIS reports what it did: "removed N of M connection records" in the steps, and "no connection records for this address" only when there were none. Even with the settings above, **Block device is the reliable way to cut sessions**: it also blocks the address from opening new ones.

## What it does not do

* **No MAC blocking of wired devices.** The address-list actions refuse a MAC-only target. Blocking by MAC at layer 2 (`/interface/bridge/filter`, bridge hosts) is not part of this connector. The Wi-Fi actions below use the MAC address, for Wi-Fi clients only.
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
3. **A least-privilege group and user.** The policies DENIS needs are **`read`, `write` and `rest-api`**: `read` for the reads, `write` for the address list, the filter rules, the connection table and the Ethernet ports, `rest-api` to use the REST API at all. `policy` (user and group management) and `test`, `ssh`, `winbox` and the others are not needed. This is the set used on the E50UG test. If the router answers HTTP 403, check the user's `address=` first; only then add `api` and then `web` one at a time and tell us which one was needed.
   `/user group add name=denis-api policy=read,write,rest-api`
   `/user add name=denis group=denis-api password=<a long random password> address=<DENIS address>/32`
4. **Quarantine (optional).** Create a second address list for quarantine (it can be empty) and **your own firewall rules** that use it: allow what a quarantined device needs (DHCP, DNS, NTP, the remediation server) and drop the rest, above the rules that would otherwise let it through. DENIS never creates these. Enter the list's name in *Quarantine address list name*. Leave it empty to switch quarantine off.
5. **In DENIS** (*Network → Equipment → + Add a connector… → MikroTik RouterOS (address list)*): **Base URL** `https://<router address>` (add `:port` if you changed it), **REST API user** and **Password** (stored sealed as `nac.mikrotik.password`), the **address list name** (default `denis-blocked`), addresses never to block, and the TLS settings below. Use **Test connection**: it reads the router's identity, version and own addresses and the DENIS rules, and writes nothing.
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

## When a block on the router changes (4.5)

The hourly check and **Check** tell a block that is gone from one that is only weakened. *Gone* (closed as removed
outside DENIS) only when DENIS's own object is no longer there: the marked address-list entry, the drop rule(s) of a
flow block, the marked Wi-Fi access-list entry. When the object is still there but no longer in force, the action stays
in effect with a notice, and its release still removes the object:

* a host block whose entry is in the list while one of DENIS's two drop rules is missing or disabled;
* a flow block whose rule is no longer first in the forward chain, was changed or disabled, or only one of its two
  directions is left;
* a Wi-Fi block whose client is connected again (an entry above DENIS's, or another Wi-Fi stack, lets it in) or whose
  entry was disabled.
* a name block whose static DNS entry was disabled, moved to another address list or had its subdomain setting
  changed (the entry is still there, so the release still removes it).

Before DENIS makes its two drop rules again (because someone deleted them), it removes the entries in the list that
carry its marker and whose ledger row is read and has ended (an entry whose row is missing, cannot be read or whose name
carries no action id is left in place): a rule made again would block them once more with no action to end
them. Every write to a router holds that router, so two actions never interleave on the shared chain, rules or access
list order; a second copy of DENIS's drop rule in the name chain is its own, and the next name block removes it. A
released port is found by the interface id recorded at the block, so a renamed router, connector or port is still
enabled. An old-route unblock also looks in the list the block was made in, when the list was renamed since. The release
of a Wi-Fi block reads the access list recorded at the block too, and an access list it cannot read stops the release
with nothing changed (only a menu the router no longer has counts as gone). A flow rule under DENIS's name whose comment
lost DENIS's marker is not removed: the release says so; remove it by hand and mark the action as resolved.

## Removing everything by hand

* Entries: `/ip firewall address-list remove [find comment~"^DENIS"]` and `... [find comment~"^denis-"]` (and `/ipv6 firewall address-list ...`).
* Rules: `/ip firewall filter remove [find comment~"^DENIS managed"]` and `... [find comment~"^denis-"]` (and `/ipv6 firewall filter ...`).
* A port: `/interface ethernet enable ether3`.
* Wi-Fi entries: `/interface wifi access-list remove [find comment~"^denis-"]`, `/interface wireless access-list remove [find comment~"^denis-"]` and `/caps-man access-list remove [find comment~"^denis-"]`.

## Verified and not verified

* **On a real E50UG (RouterOS 7.21.4), 6 November 2026, for a client behind an access point:** block device through the address list stopped the traffic of an iPhone connected to a standalone MikroTik access point (cAP lite) cabled into the router's LAN within about two to three seconds, the counters of the drop rule rose, and the release restored the traffic within about two to three seconds and left the list empty (see *What a host block covers*).
* **On a real E50UG (RouterOS 7.21.4):** block flow (drop rule at the top, traffic blocked, counters confirm the drops,
  expiry removed the rule and restored traffic); block device (enforced, rules before fasttrack, thousands of packets
  dropped, expiry restored the client and left the list empty; the read-back was reported as failed, see above);
  quarantine by address with a hand-made rule before fasttrack (enforced with read-back, manual release restored at once,
  extend worked and counts from now, a repeated quarantine refused as a conflict, expiry); the switch *Allow DENIS to create
  deny rules* enforced by the server. **Not yet done:** disabling a port, ending sessions with an independent proof, lost
  answers, a reboot, a concurrent edit, a 24 hour hold, repeated cycles. Result: the flow block and the quarantine by
  address validated per action (owner decision, 4.2); block device (read-back) and the other actions are not.
* **In DENIS's own tests, against a simulated RouterOS REST server over TLS:** the request sequence, the rules' shape (forward only, drop only, top of the chain, created once), the entry and rule comments, idempotent second block, connection removal for all four address fields and for a flow's own connections only, unblock leaving the host block's rules, quarantine writing no rule, the position check and the move fallback, a rule that cannot be put at the top being removed, a foreign object under a DENIS name being refused and never touched, a refused write after earlier steps (compensated, or partial), a lost answer (read back, releasable), the port refusals one by one, the typed port name, disabling and enabling a port, refusal of the router's own addresses, the pinned certificate, authentication and permission failures, 4xx, 5xx and timeouts, IPv6 paths, orphans found by marker and removed only when they carry it.

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

## Wi-Fi: clients, access points, block and disconnect

Since 4.4 the connector can read the Wi-Fi clients and access points of a RouterOS router, and block or disconnect a Wi-Fi client. The block by MAC, its release and the disconnect are **verified** on the new `wifi` stack with one access point under a CAPsMAN manager (4.5) and need no lab switch. On the legacy stack they are refused unless both lab switches (*Allow Experimental connectors (lab use)* and *Allow experimental actions (lab use)* under *Settings → Response policy*) are on. The read is *Experimental* and behind its own tick. Where this page says "documented" the source is MikroTik's help pages (RouterOS WiFi, REST API and CAPsMAN pages); where it says "assumed" the point comes from the console commands or from forum answers and has to be checked on a router.

### The two Wi-Fi stacks

RouterOS 7 has two Wi-Fi stacks. DENIS supports the new `wifi` package (the one that ships on current MikroTik access points and is the only one tried on real equipment). The legacy `wireless` package and the legacy CAPsMAN are **not supported**: the code for them exists and was tested against a simulated router only, it may work or not, and it is not offered as a supported way to run DENIS. Since 4.5 the plan refuses a block or a disconnect of a client that DENIS finds on the legacy stack, unless both lab switches are on. The table lists what each stack uses:

| | New `wifi` package | Legacy `wireless` package |
|---|---|---|
| Interfaces | `/interface/wifi` | `/interface/wireless` |
| Registered clients | `/interface/wifi/registration-table` (documented: `mac-address`, `interface`, `ssid`, `signal`, `uptime`, `tx-rate`, `rx-rate`) | `/interface/wireless/registration-table` (assumed to carry the same fields; the signal may be written `-62dBm@5GHz`) |
| Access list | `/interface/wifi/access-list`, `action=reject` (documented: `accept`, `reject`, `query-radius`; the first matching rule wins; there is no implicit reject) | `/interface/wireless/access-list`, `authentication=no` and `forwarding=no` (from forum answers, valid while the interface has `default-authentication=yes`) |
| CAPsMAN | In the same package: `/interface/wifi/capsman/remote-cap` (documented: `identity`, `base-mac`, `address`, `board-name`) | Legacy CAPsMAN: `/caps-man/remote-cap`, `/caps-man/registration-table`, `/caps-man/access-list` (documented: `accept`, `reject`, `query-radius`) |
| Package names DENIS looks for | `wifi-qcom`, `wifi-qcom-ac`, `wifiwave2` (assumed) | `wireless` |

DENIS finds out which stack the router has from `/system/package` (a disabled package does not count). A router can have both. When the package list cannot be read, the read tries both and ignores the one that is absent; the actions refuse, because they must know where the client is.

### Many access points: use CAPsMAN, one connector

If you run many MikroTik access points, the way to cover them with **one** connector is CAPsMAN: the access points (CAPs) are managed by one router (the manager), and DENIS reads and acts through that manager's connector. A CAP needs no connector of its own.

* **Legacy CAPsMAN** (`/caps-man`) manages access points that run the `wireless` package. **New CAPsMAN** (`/interface/wifi/capsman`) manages access points that run the `wifi` package (`wifi-qcom`, `wifi-qcom-ac`; `wifiwave2` before RouterOS 7.13). Documented: MikroTik's manual for the new CAPsMAN covers the `wifi-qcom` and `wifi-qcom-ac` packages, and the `wireless` package cannot run together with `wifi-qcom` on one router (help.mikrotik.com, WiFi and Packages pages).
* **Which package the manager router itself needs**: tried in the lab on a hEX (E50UG, RouterOS 7.21.4) whose only package is `routeros`: the menu `/interface/wifi/capsman` is there and a hAP ax lite (RouterOS 7.20.8) joined it as a CAP, was provisioned, and a phone connected through it and got an address from the manager's network. Since 4.4.3 DENIS also looks for the `/interface/wifi` menu when no Wi-Fi package is named, so such a manager is not reported as "no Wi-Fi package". The block by MAC, its release and the disconnect of a client that is on a CAP of the new package work through the manager's access list and registration table: verified with one access point under the manager (4.5); a setup with several access points was not tried.
* **Setting up the new CAPsMAN** (steps that worked in the lab, RouterOS 7.21.4 manager, hAP ax lite CAP): on the manager `/interface/wifi/capsman set enabled=yes interfaces=bridge`, a `security` profile, a `configuration` with the SSID, `security` and `datapath.bridge=bridge`, and a `provisioning` rule with `action=create-dynamic-enabled`; on the CAP `/interface/wifi/cap set enabled=yes discovery-interfaces=bridge` and `/interface/wifi set wifi1 configuration.manager=capsman` (a CAP that still has the local configuration of *Quick Set > Home AP* keeps its SSID and is not taken over); if the radio shows on the manager (`/interface/wifi/radio print`) but no SSID is sent, `/interface/wifi/radio provision 0`. In the lab the CAP's Wi-Fi interface was not put into its bridge by `datapath.bridge`, and clients got no address until `/interface/bridge/port add bridge=bridge interface=wifi1` was added on the CAP; check `/interface/bridge/port print` there.
* A **standalone** access point (RouterOS with its own radio, not under CAPsMAN) needs its own connector for now. Each one is a normal connector with the same REST user. A bulk way to add them from the neighbours a router sees is planned (ROADMAP 4.4.4), not available yet.
* A router with **no Wi-Fi package** (a hEX, for example) has no Wi-Fi client of its own. Once DENIS has read it and found that, *Respond* lists *Block Wi-Fi client by MAC* and *Disconnect Wi-Fi client* of that connector under "not available" with the reason "no Wi-Fi package", and never preselects them. Before the first read nothing is known and the options appear as usual; the plan still refuses with the same sentence.

### Reading the clients and access points

Tick *Read the Wi-Fi clients and access points of this router (read only, Experimental)* in the connector's form (it is off for a connector made before 4.4 and on for a new one). DENIS then reads every 120 seconds, with `GET` requests only, with the same user and password as the other actions. It lists:

* **Clients:** MAC address, IP address (from the router's ARP table and DHCP leases when it has them), host name (the lease), SSID, signal, the Wi-Fi interface and the access point (the router itself, or the CAP). Wired clients are not listed, and nothing is invented: a field the router did not give stays empty.
* **Access points:** the CAPsMAN's CAPs (identity, base MAC, address, board) hanging under the router that manages them; and, when the router has radios and no CAPs, the router itself as an access point. A standalone access point hangs on the neighbour from `/ip/neighbor` (a switch or router with a MAC address) when exactly one such neighbour is seen on a port that is not a Wi-Fi interface; with none or several, no parent is drawn.
* Which CAP a client of the new CAPsMAN is on is assumed from the row's `radio-name` or from the radio MAC of its interface against the CAP's base MAC (the first five octets); a client DENIS cannot place is shown on the router.

The read needs the `read` policy for the user. The data uses the same connection settings (certificate pin or *Verify TLS*) as the actions. The read is bounded: at most 5000 clients and 1000 access points, a time limit per read, a size limit per answer, and a partial read never concludes a client has gone.

### Block a Wi-Fi client by MAC

1. DENIS finds the client in the registration tables (the router's own radios and, through CAPsMAN, its CAPs). An IP-only request is resolved to a MAC through the ARP table and the DHCP leases only when exactly one MAC is found; otherwise it is refused.
2. It adds one entry to the access list that governs the client, as the first entry (`place-before` the first entry; this is documented for firewall rules and assumed for access lists): new stack and legacy CAPsMAN `action=reject`, legacy local radios `authentication=no forwarding=no`. The comment starts `denis-<tag>-<id> DENIS managed; owner <tag>; ...`, as for the address-list entries. DENIS checks that the entry is first; if the router ignored `place-before`, one move is tried (`POST .../move`, assumed); if the entry is still not first it is removed and the action fails.
3. It removes the client's row from the registration table, so the client is disconnected (documented). A new entry alone does not drop a station that is already associated, which is why this step is part of the block.
4. **Read-back:** the entry is in the list and the MAC is no longer in the registration tables. **Release** (or the end of the time) removes only the entries that carry DENIS's marker for that action; any other entry, even one with a DENIS-like name, is left alone.

The reject entry always takes effect: the new stack has no implicit reject rule and the first matching rule wins, and DENIS puts its entry first. If the access list already has any entry for that MAC that DENIS did not make, the plan is refused. A phone with a private (randomised) MAC address gets a warning that you tick: it can join again with another address.

**Refused** (the plan says why, and nothing is written): a MAC on the connector's *Never block these MAC addresses (Wi-Fi clients)* list, one of the router's own interfaces, a CAPsMAN access point or a neighbour the router sees, a client with an address of DENIS or of the router, a MAC that is not a connected Wi-Fi client (a wired client, or one that is not there), an IP address with no single MAC, and anything DENIS could not read.

### Disconnect a Wi-Fi client

Removes the client's row from the registration table (`DELETE /rest/interface/wifi/registration-table/<id>`, the REST form of the documented `remove`). It blocks nothing. A look afterwards is written in the steps: the client is gone, or it has joined again at once (normal for many devices; not a failure). If the router found none of the client's rows to remove and still lists the client, nothing was disconnected and the action fails.

### Setting up the router user

The Wi-Fi read and actions use the same REST user as the rest of this page: group policies `read,write,rest-api`. `read` reads the tables, `write` adds and removes the access-list entries and the registration rows, `rest-api` is needed for any REST call. Nothing else is needed (assumed; if the router answers HTTP 403, check the user's *address* first, as above, then tell us which further policy was needed). For a read-only account the read works and every action is refused by the router.

### Limits

* Only traffic that the router's own radios or its CAPsMAN access points carry. An access point that is not managed by CAPsMAN is not seen from the router (add it as its own connector if it runs RouterOS).
* A client that is on a CAP of the *new* package appears in the manager's `/interface/wifi/registration-table`, and the manager's access list applies to it: verified with one access point under the manager (4.5), not with several.
* A block by MAC does not stop a device that joins with another MAC address, and a wired connection of the same device is not affected.
* DENIS's entry is first, so no earlier rule (a `query-radius` or `ssid-regexp` rule, say) can let the client in; rules below it are not read or changed.

## Existing instances

Instances from earlier versions keep working and nothing changes for them: the same block list, the same two drop rules, the same entries (comment `DENIS <ledger id> <timestamp>`), the same ledger rows. The old *Block…* and *Unblock…* buttons act as before. Records the old routes made are released through the old *Unblock…*; records of the new actions are released through the new action list.

## Details from the console

The console shows a short line under each field and a short note behind its (i). The full explanation of each field is here.

- **Quarantine address list name (optional)**: The address list you created for quarantine. DENIS adds a device to it and takes it out again, and nothing else: what the list may reach is decided by your own firewall rules on the router. DENIS never creates a rule for it. Leave empty to switch quarantine off for this router.
- **Allow DENIS to create deny rules on this firewall**: Off by default. When on, DENIS can create one drop rule per flow block in the forward chain of this router, at the top of the filter table, marked denis-... and DENIS managed, and delete it again when the action ends. It never creates an allow rule and never uses any address but the two hosts of the flow. A wrong drop rule can cut off traffic: switch this on only if you accept that.
