# Switches and the physical topology (SNMP)

The **Topology** tab has three maps. *By gateway* is the logical one every install has. **Switches and cables** is the
physical one: which **port** each device is plugged into and how the **switches are cabled together**. **Equipment links**
shows the cables between switches, firewalls, routers and access points, each marked confirmed, best guess or set by hand
(see below). They need your switches to answer SNMP, so you tell DENIS which ones to read.

## What DENIS reads

For every switch you add (*Settings* → **Switches (SNMP)**), DENIS reads, and only reads, every few minutes:

| MIB | What for |
|---|---|
| system (`sysDescr`, `sysName`) | the switch's name and description |
| IF-MIB (`ifName`, else `ifDescr`; `ifAlias`, `ifOperStatus`, `ifAdminStatus`, `ifType`, `ifHighSpeed`) | the ports: name, the label somebody typed, up or down (link), switched on or off (administratively), physical or not, speed |
| LLDP-MIB (`lldpRemTable`, `lldpLocChassisId`) | what each port sees on the other end of the cable: another switch, an access point, a phone: as that device announces itself |
| Q-BRIDGE-MIB (`dot1qTpFdbPort`), else BRIDGE-MIB (`dot1dTpFdbPort`) | the forwarding table: which MAC address was learned on which port |

Where the switch has them, a poll also reads what the port is for: link aggregation (IEEE8023-LAG-MIB
`dot3adAggPortAttachedAggID`, IF-MIB `ifStackStatus`) and CDP neighbours (CISCO-CDP-MIB `cdpCacheTable`), and on **Cisco
IOS** the 802.1Q trunk mode of each port (CISCO-VTP-MIB `vlanTrunkPortDynamicStatus`) and the VLAN list (CISCO-VTP-MIB
`vtpVlanTable`, else the ports' access VLANs). Port control uses these to warn about trunks, aggregation members and
infrastructure (by hand only, with warnings to tick); nothing else draws on them.

A poll only ever reads, always with the read community (SNMPv2c) or the read user (SNMPv3). DENIS sends **one kind of
SET**: `ifAdminStatus` of **one port**, only for a switch you gave a separate **write community** or **write user**, only when an **administrator asks and confirms** with
their password (see [Disabling a port](#disabling-a-port)). A switch without a write community is never written to.
A table a switch does not implement is simply left out; only a switch that does not answer at all is an error, shown on
the switch's line with the reason.

## Setting it up

For the two switches tested on real equipment there is a step-by-step quick setup, with the switch commands, the DENIS fields, a first test and the common problems: [Cisco Catalyst 2960-X](nac/snmp.md#quick-setup-cisco-catalyst-2960-x) and [D-Link DGS-1100](nac/snmp.md#quick-setup-d-link-dgs-1100). The general steps follow.

1. On the switch, create a **read-only SNMPv3 user** (recommended, see [SNMPv3](#snmpv3)) or a **read-only SNMP v2c
   community**, and allow **only the DENIS server's address** to use it (an access list on the switch). In v2c the
   community travels unencrypted, so give it a long random name and treat it as a password that anybody who can watch
   that link could learn.
2. *Network* → *Equipment* → **+ Add a switch…**: a name, the switch's address (`192.168.1.2`, or `192.168.1.2:1161`
   for another port), the **SNMP version** and the community, or for SNMPv3 the user and its passwords. The community
   and the passwords are stored encrypted, are never shown again (leave them blank when editing to keep them) and never
   appear in the audit log.
3. Press **Read now**. It says how many ports, neighbours and MAC addresses were read, or why not ("no answer from the
   device": check that SNMP is on, the community, and that UDP 161 is reachable from the DENIS server).
4. Open **Network** → *Map* (formerly *Topology*) → *Switches and cables*. A device's own panel has a **Place & response** block that says which port it is plugged into. *Network* → *Setup* walks through these steps for several switches and a firewall.

Polling runs from the DENIS collector (not in a `denis serve` viewer). The interval is 5 minutes by default (60 to 3600 seconds).

## Disabling a port

This is one of the actions described on the [Enforcement](enforcement.md) page, which also covers durations, permissions
and the other connectors.

**By default DENIS never blocks anything on its own** (automatic enforcement is a separate, experimental, off-by-default
switch, see [Enforcement](enforcement.md)). A person with the administrator role asks for every block, for one port at a
time. They see exactly what will be cut off before they confirm. They confirm with their password. Every block is
logged, announced on every alerting channel, and listed until someone undoes it.

### Turning it on (twice)

1. *Settings* → **Enforcement**: *Allow administrators to block devices from DENIS* (off by default; this one switch also covers
   the firewall and cloud connectors, see [Zones and policies](segmentation.md#enforcement-connectors)), and the most blocks
   per hour across all administrators (10 by default). Switching it off stops new blocks at once; it does not enable
   ports that are already off, and enabling them from DENIS keeps working.
2. Per switch: *Settings* → *Switches (SNMP)* → *Edit* → **Allow DENIS to disable ports on this switch**, and enter a
   **write community**. Each switch's line then says *Port control* (or *Port control (off)* while step 1 is off)
   instead of *Read only*. Like the read community it is never shown again, never logged or audited (the audit log
   only says `port_control: true`); leave it blank to keep it, or tick *Remove the write community* to clear it. It
   may be the same as the read community (some inexpensive switches have only one), but then every regular poll sends a
   community that can write, and the form says so.

Recommended on the switch, **not yet verified per vendor**:

* a **separate write community**, limited by an access list to the DENIS server's address;
* where the switch supports SNMP views, a view that allows writing **only `ifAdminStatus`** (`1.3.6.1.2.1.2.2.1.7`);
* ideally, SNMP on a management VLAN.

SNMP v2c sends the write community **unencrypted** each time a port is disabled or enabled: the same caveat as for
reading, but for a credential that can take ports down. SNMPv3 (below) does not have this problem.

### Who can, and how

Only a signed-in **administrator** with the permission to disable ports: never a viewer or editor, never an API token,
never under `--insecure-no-auth`. A port is switched off from the **Respond** menu (a device's panel, or a port of a
switch's port table), through the response dialog and the action API (`POST /api/nac/actions/plan`, then
`/api/nac/actions/apply`). The routes before 4.2 (`POST /api/nac/plan` and `/api/nac/apply`) are retired: they answer
HTTP 410 and point to the action API (one tick there acknowledged every warning, and the apply did not judge the port
again). A port DENIS disabled before 4.2 is still switched on again, and checked, from *Active responses*.

DENIS first **reads the switch again, right now** and shows a plan built from that read: the switch and port, every
device it can name behind the port, how many MAC addresses it cannot name, and every warning and refusal. The plan is
valid for **two minutes** and can be confirmed once, only by whoever asked for it. Confirming needs a **reason** (3 to 200 characters) and your **password** (wrong
answers count against the account's lockout, like restarting DENIS). Right before acting, DENIS reads the port once more
and refuses if that index now carries another port's name (some switches renumber ports after a reboot or a module
change). Then it sends the SET and **reads the port back**:

* **disabled**: the switch reads it as switched off;
* **not confirmed**: the SET or the read-back got no clear answer; the port may or may not be off. Check the switch, or
  use **Check now**;
* **refused**: the switch answered with an error (for example "this community cannot write"); nothing changed.

### What DENIS refuses, whatever you confirm

* cutting yourself off (the self-lockout): the port **DENIS itself** is behind (its own connection, and so the way it
  reaches the switch), the port the **gateway** is behind, the port behind which the **switch being changed** is itself
  reached (its own management address is learned there), the switch's **management port** (`Fa0`/`FastEthernet0`,
  `Gi0/0`, `mgmt0`) by name, and a port marked as a **mirror (SPAN) destination**: switching that off blinds DENIS, it
  would see nothing of the network any more, not even what the action itself does;
* a port that **leads to another switch DENIS reads** (an LLDP neighbour, or that switch's chassis or management address
  learned behind it) or is the port **toward the spanning-tree root**, unless DENIS can show that its own way to the switch
  goes through another port: its own hardware address is learned on another port of this switch, or, when DENIS is in
  another network and the switch does not learn it at all, the gateway's is (and not on this port). Code `denis_path`
  (4.2). DENIS does not read the switch's ARP table, so the gateway DENIS knows stands in for the address the switch
  routes DENIS's traffic through; when DENIS is in the register as itself and is learned on another port, an uplink stays
  possible by hand with its warnings (the D-Link behind the Catalyst, when DENIS is plugged into the Catalyst);
* the port of the **device you are using** for this very request (your session's address belongs to a device behind the
  port: `own_session`);
* a **forwarding table read only in part** (`snapshot_truncated`): a Q-BRIDGE or BRIDGE walk that stopped at a limit, or
  a Cisco switch's per-VLAN tables cut off (the row limit, VLAN contexts that did not answer, or a VLAN not reached that
  no poll has read yet). VLANs not reached that are carried over from the poll that last read them are complete. The
  read right before a port action pages a Cisco switch's
  VLANs like the regular poll (its own *VLANs per poll*, continuing where the last poll stopped);
* a list DENIS cannot read (the register, the address-conflict alerts, the active actions, the confirmed gateways, the
  port marks and the interfaces of a device: `unreadable`): it is never read as empty;
* a device whose identity is in doubt: an open **address-conflict** alert, or its MAC learned on **more than one access
  port** right now (MAC cloning, a man in the middle: the port may be the victim's). Find the right port by hand;
* a device or address on the **hands-off** list, or a protected device behind the port;
* anything but a **physical Ethernet port** (`ifType` 6): no VLAN interfaces, port-channels (`ifType` 161), loopbacks or
  the CPU;
* a device that **changed between the preview and the confirmation**: right before the SET DENIS reads the switch's
  forwarding table once more and stops, with nothing changed and nothing written, if a planned device is no longer on
  the port (unplugged, replaced), is learned somewhere else, or if another device is on the port;
* a switch that gave back **no forwarding table**, or forwarding entries without a bridge-port map: DENIS cannot tell
  what is on the port and will not guess. **Many inexpensive "smart" switches are like this** (the D-Link DGS-1100-08V2
  is one): DENIS reads their ports, but cannot disable any of them;
* a device DENIS **cannot see** on any access port right now;
* a port that is **already switched off** at the switch (so that undoing a block can never switch on a port someone
  shut on purpose), or whose state the switch does not report;
* more than the hourly limit, another action on the same switch in progress, a switch without a write community, or one
  that is not read regularly (DENIS could not notice the port coming back).

Allowed, but only after ticking *I understand this also cuts off the devices listed above*: **several MACs** behind the
port (a desk phone with a PC behind it, a small switch under a desk), an **LLDP neighbour that is not a switch** (an
access point: every wireless client behind it), or **nothing seen** on the port right now.

### Ports that are not plain access ports: by hand only, with warnings to tick

Until 4.2 these were refused. Now an administrator decides, and DENIS warns strongly (owner decision of 19 October
2026). Each one is a **warning of its own that must be ticked in the plan and again when you apply it**, next to the
mandatory reason, your password and the port name typed to confirm. Each warning names the port, says how many MAC
addresses are learned on it and which switches, access points or other equipment are behind it, and what switching it
off cuts:

| Warning (code) | When |
| --- | --- |
| `uplink` | an LLDP neighbour on the port is another switch DENIS reads (only when DENIS is shown to reach the switch through another port; otherwise `denis_path` refuses) |
| `switch_behind` | the chassis MAC or the management address of another switch DENIS reads is learned on the port (the same condition) |
| `trunk` | more MACs behind the port than an access port has (24 by default; an administrator can lower it, 1 to 24, with `trunk_mac_threshold`, never raise it) |
| `trunk_port` | the switch says the port is an **802.1Q trunk** (Cisco IOS), even with one MAC behind it |
| `lag_member` | the port is a member of an **EtherChannel/LAG** (on any switch that reports it) |
| `cdp_neighbour` | a Cisco device announces itself on the port over **CDP** (a switch, an access point, a router, a Cisco IP phone) |
| `class_unknown` | a Cisco IOS port whose trunk mode the switch did not report, unless exactly one device and no neighbour is behind it |
| `behind_port` | any port the one port rule does not call a plain access port (an uplink, a trunk, network equipment learned there, spanning tree, a port marked as unmanaged equipment), with the count and the names of what is behind it |

These ports are **never proposed** by DENIS (the Respond menu lists them under *Only by hand*, with the warning, never as
the recommended choice) and **never acted on by automation or Autopilot**: they never accept a plan that has a warning.
Right before the write DENIS reads the port once more; if it then finds a kind of port the plan you confirmed did not warn
about, it changes nothing and asks you to plan again. The VLAN move stays refused on a trunk and on an aggregation member
(they have no single access VLAN to change), and on any port with more than one device behind it.

LAG membership is read from `dot3adAggPortAttachedAggID` and `ifStackStatus` when the switch has them; a switch that
has neither cannot show that a port is an aggregation member.

### Cisco IOS: one forwarding table per VLAN

Cisco IOS serves the BRIDGE-MIB per VLAN: the community `public@20` shows the table of VLAN 20, a plain `public` only
that of VLAN 1 (and IOS does not serve the Q-BRIDGE tables). When a switch says it is Cisco IOS (`sysObjectID` under
1.3.6.1.4.1.9 and `sysDescr` naming IOS, not NX-OS or an ASA), DENIS lists the VLANs (CISCO-VTP-MIB, else the access
VLANs of the ports) and reads the bridge-port map and the forwarding table once for each, with `<community>@<vlan>`.
It reads at most 64 VLANs per poll (set per switch under *VLANs read per poll*, 2 to 512) and for at most 30 seconds,
stops after two VLANs in a row without an answer (the device does not index by community), and records what it left
out on the switch card as an incomplete read; the plain table stays in use whenever the per-VLAN read gives nothing.
**A switch with more VLANs is read across polls:** VLAN 1 is read every time (last, after the others: its plain table
is read anyway, so it never uses up a poll's time before them), and the others in turn, each poll continuing where the
last one stopped (the limit, or the 30 seconds), so every VLAN is read within a few polls. The VLANs a poll does not
reach keep the entries of the poll that last read them, except for a device this poll saw elsewhere (it is shown only
where it is now), and the switch card says which VLANs those are. Once every VLAN has been read by some poll, such a
switch's table counts as complete (a note on the card, not an incomplete read): port actions and a VLAN quarantine are
not refused for it. Until then (the first polls after adding the switch or upgrading) it is an incomplete read. The
per-switch setting in the switch form (`cisco_per_vlan`):
*Automatic* (default), *Always* or *Never*. Other switches are never read this way. Tested on a
Catalyst WS-C2960X-48TS-L (IOS 15.2(7)E4) with SNMPv2c and SNMPv3.

### Undo, drift, and what is announced

* **Enable** (Topology → *Disabled by DENIS*, or the port's row) takes one ordinary confirmation and no password, and
  works while port control is switched off. DENIS only enables ports **it** disabled (its own ledger), after checking the
  index still carries the same port name.
* Removing a switch, or its write community, while ports DENIS disabled are still off asks for confirmation first:
  DENIS can no longer enable them after that; it would have to be done at the switch.
* **Drift**: every regular poll reads `ifAdminStatus`. A port DENIS disabled that is switched on again (`no shutdown` at
  the switch, or the switch restarted) is recorded as *switched on outside DENIS*, logged by `system`, and announced.
  DENIS never disables it again on its own.
* **Restarts**: on many switches a port disabled over SNMP is only off in the running configuration and comes back
  on when the switch restarts, unless someone saves the configuration. **A block by DENIS is not guaranteed to survive a
  switch restart.** Not yet verified per vendor.
* Every block, enable, *not confirmed* outcome and drift goes to **every enabled alerting channel**, regardless of its
  minimum score and of maintenance mode. While any port is disabled by DENIS, **Health** shows a warning. Everyone who
  can see Topology sees the *Disabled by DENIS* list (who, when); only administrators see the reason and can enable.
* The audit log records `nac.plan.refused`, `nac.disable`, `nac.disable.denied` (wrong password, expired plan, renamed
  port), `nac.restore`, `nac.check`, `nac.drift` and `nac.settings`. Neither community ever appears in them.

### The response dialog and quarantine by VLAN (4.1)

Each switch is also offered in the response dialog (the Respond button), with two actions. The buttons above keep working
as before.

* **Disable port** with a **duration** (the default is one hour; permanent needs an extra tick). When the time is up
  DENIS enables the port again, and a release does the same. It is one action per physical port, you type the port's
  name to confirm, the port is read again right before the change, and a port that someone enabled in the meantime is
  recorded as *removed elsewhere* and not disabled again.
* **Move the port to the quarantine VLAN** (experimental). In the switch form, under *Quarantine by VLAN*, enter the
  VLAN you built for quarantine (2 to 4094, not 1002 to 1005) and tick *I tested this VLAN*. Without the tick the switch
  offers no quarantine. DENIS moves **one access port** into it and back (Cisco IOS: `vmVlan`; other switches:
  `dot1qPvid`); it never creates the VLAN, its DHCP, its gateway or any rule. A device with a static address, and any
  OT device, is simply cut off until the port is restored. Refused, whatever you confirm: a trunk or an EtherChannel
  member (no single access VLAN to change: switch it off by hand instead), the management port, a mirror port, the port of
  the gateway or of DENIS itself, a port with more than one device or a neighbour (a phone, an access point; this covers
  an uplink), a voice VLAN, 802.1X or MAC authentication, a VLAN that does not exist on the switch, and a port that is
  already in it. The optional *bounce* switches the port off and on once so that the device
  asks for an address again; it is off by default. The details, the OIDs and what was not verified are in
  [SNMP port control](nac/snmp.md#the-response-dialog-41-disable-a-port-or-move-it-to-the-quarantine-vlan).

## Switches at several sites

When the tenant has two or more sites (the local capture and one or more agents), the switch form offers
**Site**. A switch bound to a site places only the devices of that site: the same MAC address at two
sites is two devices, each placed on its own site's switch, and a topology change (a moved device, a VLAN
change, a new device on a watched port) is raised on the device of the switch's own site. A new device
found on a watched port is created at the switch's site.

A switch that is **not bound** keeps working as before (it is tenant-wide), but it cannot tell which site's
device a MAC belongs to when devices of two sites share it: nothing is attached to such a MAC (counted in
`denis_topology_ambiguous_mac_total`) instead of guessing. Once any switch is bound, port control (NAC)
asks only the switches bound to the device's own site where it is, and never acts on a device of one site
through a switch of another. When you save the list, the
console keeps each switch's binding (the form sends it back): an API client that saves the list must send
`site` too, or it unbinds the switches.

## How a device is placed

* A device is drawn on the port where its **MAC address was learned**. If it is learned in several places, the port with the
  **fewest** other MACs behind it wins: an access port beats an uplink.
* A port that leads to **another switch you poll** (LLDP says so), or that has **more than 24 MACs** behind it, is a
  trunk: what it learns is only "somewhere further down", so no device is claimed to be plugged into it. The device shows up
  on its real port once the switch it hangs off is added as well.
* A neighbour that **announces itself by LLDP** (an access point, a phone) is drawn with what it says and matched to the
  register by its chassis MAC.
* MACs on access ports that are **not in the register** are only counted (the map says how many).

### Testing the write credential

A wrong write community or write user is otherwise found out in the middle of an incident. `POST /api/switches/{id}/test-write` (administrators who may act, and only while enforcement is switched on) tests it without changing anything: DENIS picks a physical port that is switched off, or has no link, with no device learned on it, no neighbour and no link to another switch it reads, and that is a plain access port by the same rules as a real action. It reads the port again, sets `ifAdminStatus` to **the value the port already has** and reads it back. If the switch has no such port, DENIS says so and writes nothing; unplug or switch off an unused port, read the switch again and test again. The test is audited (`nac.write_test`), takes the switch's one-at-a-time lock, and follows the same lab-switch rule as a real action for SNMPv3.

### Port roles

Every port in `GET /api/topology` (`switches[].ports[]`) carries `role` and `role_reason`: `uplink` (leads to another switch DENIS reads), `lag`, `trunk`, `management`, `infrastructure` (CDP or LLDP says network equipment is there), `unknown` (a Cisco port whose trunk mode DENIS cannot tell) or `access`. The words come from one function (`topology::port_role`), which reads the same facts port control refuses on, so a port never has one word on the map and another in a refusal. The same answer carries `gateway` (`{asset_id, ip, mac, switch, port, confidence: "likely", evidence[]}`, or `null`): the device DENIS treats as the gateway today (from its own route), and where a switch says it is plugged in.

### The gateway, and how sure DENIS is

DENIS looks for the device that connects your network to the internet from several witnesses, and says how sure it is. It no longer
trusts only the address its own host routes through (wrong on a management VLAN, behind a second router, or on a collector that is not on
your network).

* **What clients are told.** The router that DHCP servers hand to devices (option 3), counted over time. Three sightings and a device
  that holds that address make the gateway **confident**.
* **Who carries the internet traffic.** The device on the other end of the frames to and from public addresses.
* **DENIS's own route.** The 4.1 signal, kept as **likely**.
* **A switch that routes.** A switch DENIS reads that says it routes (`ipForwarding`, `sysServices`) and holds the gateway address is
  shown as the gateway itself, and as the core.
* **A virtual address.** A VRRP, HSRP or GLBP address is one gateway, whatever routers stand behind it.
* **Look-alike.** A device the fingerprint calls a router, when nothing else is known, is **possible**.

When the route and what clients are told point to different devices (a collector on a management VLAN, a provider's box in front of your
own firewall), the sure one is shown first and the other is marked **not sure**, with the reason in words. Two gateways that each serve
their own networks are both shown. Each card has **Why DENIS thinks so**.

An administrator can **Confirm** the gateway, **Change…** it, say **There is more than one…**, or **Re-detect** (forget what was
confirmed by hand). What a person confirmed outranks every inference, is audited, and makes the device hands-off like the gateway the
route names; it only ever adds a refusal. The core switch (the switch the gateway is plugged into, or a layer-3 switch itself) is the
top of the map; an administrator can name another one. Switches seen over LLDP that DENIS does not read are shown as grey boxes with
**Add…** (the form opens with their management address) and **Mark unmanaged** (a hub, a dumb switch).

What DENIS does not do: it does not learn the mask or the VLAN of each DHCP lease (networks are shown as /24 groups), it does not probe
the number of hops, so a second router in front of yours shows only as a disagreement between the route and what clients are told, and
it does not read the default route of a layer-3 switch.

Spanning tree helps with uplinks: the port toward the root bridge and the ports held in blocking are treated as uplinks, so they are
never switched off or moved. A neighbour's management address (LLDP) is kept for the "add it" step.

### Equipment links: the cabling between your equipment (4.2)

*Network* → *Map* → **Equipment links** draws your switches, firewalls, routers and access points with the cables between them, the
internet side on top (the gateway, then what is behind it). It is where you check the cabling: DENIS shows its best estimate first, you
correct it once at setup, and later it just shows. Every cable says how DENIS knows it, in words and by the line pattern (never by
colour alone):

* **confirmed** (solid): the equipment announces it itself, over LLDP or CDP, on a port with one neighbour.
* **best guess** (dashed, with how sure: high, medium, low): from the forwarding tables. A port that carries only one device's own
  addresses is that device's cable (high). A switch DENIS reads whose own address is learned on a shared port is guessed to be behind it
  (medium); other equipment seen only there is guessed to be behind that switch, port not known (low). A switch that reads no forwarding
  table of its own (the D-Link DGS-1100) is placed from the other switches' view. Two or more neighbours announcing on one port are
  relayed by equipment in between, so they are not called cabled there.
* **set by hand** (dotted): a cable an administrator drew, or a port marked as leading to unmanaged equipment.

A firewall that DENIS also reads as a switch, or whose interfaces are one device in the register, is one box. Where DENIS is not sure it
says so under **Where DENIS is not sure** and offers the choices (*Yes, that is right*, *Choose the cable myself…*, *A switch or
access point DENIS does not read*, *A shared desk switch or hub*); it never presents a guess as fact.

**Correcting a cable** (administrators): drag a thread from the small circle of one box and drop it on the other box (on the map and in
the setup wizard's *Uplinks* step); a short form then asks for the ports (from the switch's list) and a note, and you confirm. Without a
mouse: press Enter on one box, then Enter on the other, then confirm; or **Choose a cable…** picks both ends from lists. A cable drawn by
hand always wins over every guess between the same equipment or on the same port, is saved for every administrator, survives a restart,
is written to the audit log with the old and the new value, and is undone with **Remove cable**. When the equipment itself announces
something else, the cable you drew is used and the map shows the conflict. A switch port with a cable drawn by hand is never treated as a
plain access port for port actions (more warnings, never fewer).

The same links give the order **by wiring** that *Network* → *Equipment* can use (internet side first, firewalls and routers on one
level), and the setup wizard asks its *Uplinks* questions from them and lists *Networks and firewalls* (which firewall routes which
network, and whether DENIS also sees it is that network's gateway). The API is `GET /api/topology/relations`, `POST /api/topology/links`
and `DELETE /api/topology/links/{id}` (see the API reference).

### Manual port placement (Experimental)

Some switches cannot say which MAC address is on which port. The **D-Link DGS-1100-08V2** (firmware 1.00.015) is one: over SNMP it exposes only the system group and `ifTable`/`ifXTable`. It answers neither BRIDGE-MIB, Q-BRIDGE-MIB (no forwarding table, no VLAN objects) nor LLDP, although writing `ifAdminStatus` works. That is a limit of the model, not of DENIS. DENIS then refuses every port action on it ("no forwarding table"), which is correct and used to leave the administrator stuck.

An administrator can say "this device is on port N" instead:

* **Where.** On the device's panel, in *Place & response*, **Place it manually…** (a switch, a port from the list of plain access ports that have a link, shown with their role, and a note). The panel then shows **placed by hand** with who made it and when it ends, and **Change**, **Confirm again** and **Clear**. *Network → Equipment* shows **Placed by hand…** (in the row's **⋯** menu and its detail) on a switch without a forwarding table, with the list of its placements (confirm again, clear). The API is `GET/PUT /api/switches/{id}/manual-ports` and `DELETE …/{entry}`; setting one needs an administrator who may act, and every change is audited (`nac.manual_port.set`, `nac.manual_port.clear`).
* **Only where DENIS has no better word.** A placement is refused when the switch reports a forwarding table (it is never overridden; if one appears later the placement is ignored), when the switch was not read lately, when the port is not a plain access port with a link and nothing announcing itself (not an uplink, trunk, link aggregation, management port, or a port with an LLDP or CDP neighbour), when the device is DENIS itself, the gateway, a DNS or directory server or hands-off, or when a switch that knows better says the device is elsewhere. Two devices on one port need the administrator to say that sharing it is meant.
* **What it allows.** Only switching the port **off**. A VLAN move is refused for such a port (it needs what the switch says about the port's VLAN). In the plan the refusal "no forwarding table" becomes **one warning that must be ticked** ("{who} placed a device on this port by hand on {date}. DENIS cannot verify what is on this port."), the typed port name stays, and the placed device counts in "what this cuts off", so DENIS itself, the gateway and hands-off devices are refused as for any port.
* **How long it holds.** 30 days (the end is shown; one click confirms it again), and not past a change of the port's link: DENIS reads `ifLastChange` and refuses a placement made before the link last changed, or when the switch does not say. It is refused when the port has no link, and when DENIS itself is behind the switch (another switch learns DENIS on a port that leads to it), because then any port could be the way to DENIS. It is **Experimental**: it needs the second lab switch like every new action, and the kill switch, the hourly limit and the password as always.
* **Right before the write.** The switch is read again; the link, the neighbours, the age and the link change are judged again, and `ifAdminStatus` is read and read back as for every port action. There is no forwarding table to compare, so the usual "the same devices are still behind the port" comparison is replaced by those checks.

What DENIS cannot know here: that the device is really on that port. The warning says so, and so does the audit row. "The only known path to DENIS" is judged only from what other switches report.

## Watching ports and VLANs, and what DENIS notices

DENIS keeps a bounded history of where each MAC has been seen (per switch, port and VLAN) and a change log, and a
change is only believed when **two consecutive polls agree**, so one flaky read never raises anything. A port or VLAN can
be **watched** (*Watch* in the port drawer or port table; administrators only, up to 64 of each, ports by ifIndex so it is
offered only for switches that answered a bridge-port map). Four detection rules read this, see
[Detection rules](detection-rules.md): `port_move`, `new_on_port` (watched ports and VLANs only), `vlan_change` and
`fingerprint_changed` (which needs no switch at all). Port-level configuration changes (PVID, admin state changed by
someone else, neighbours coming and going) are logged and shown in the drawer but do not alert.
The history can be browsed: `GET /api/topology/changes` and `GET /api/assets/{id}/locations` ([API](api.md)).

## What is verified, and what is not

The SNMP client (BER encoding and decoding, GET, GETBULK and GETNEXT walks) is tested against byte sequences worked out
from the specifications, against hostile and corrupted answers (it never panics; every length is bounded), and against
two independent stand-in switches (one written in Rust for the tests, one in JavaScript for the browser test).
It has been tried against **two real switches: a Cisco Catalyst WS-C2960X-48TS-L** (IOS 15.2(7)E4, SNMPv2c and SNMPv3 with SHA-1 and AES-128; reading, port control, the quarantine VLAN move, LLDP placement; see [SNMP port control](nac/snmp.md#quick-setup-cisco-catalyst-2960-x)) **and a D-Link DGS-1100-08V2** (2026-10-01). The D-Link answers IF-MIB (names only
in `ifDescr`, "port1" to "port8"; `ifType`, `ifAdminStatus`, `ifOperStatus`), but **no forwarding table, no bridge-port
map and no LLDP**, so DENIS lists its ports and cannot place any device on them. It answers larger GETBULK requests with
`tooBig` (DENIS now asks for fewer rows per answer), and a GET for several variables, one of which it lacks, with only
that one (DENIS now matches answers by OID and asks again for the rest). Vendors differ (VLAN-specific communities on
some Cisco models, LLDP local port numbering, bridge-port to interface maps), so read the map critically at first and
please report a switch that shows something wrong.

Port control on the D-Link (one empty port, by hand, with DENIS's own connector code): a SET of `ifAdminStatus` with
the write community was accepted and read back as off; the port came back on with a SET back to on; a SET with the
**read** community got **no answer** (silence, not an error status) and changed nothing; a port switched on from outside
DENIS (`snmpset`) was noticed by the next poll as drift. A plan through the console is refused on every port of this
switch ("no forwarding table"), as it should be. The uplink refusal was seen on the Catalyst 2960-X, which has a forwarding table (since 4.2 an uplink is a warning to tick by hand instead; that was not tried on the switch yet). **Not verified yet:** whether a block
survives a switch restart (with and without saving the configuration), and the self-lockout refusal on real hardware;
those are tested only against the stand-in switches.

The 4.1 response dialog for switches (expiry, one action per port, drift read back by the reconcile job) and **quarantine
by VLAN** were tested on the **Catalyst 2960-X** (`vmVlan`, the VLAN checks, extend, release, the uplink refusal) with SNMPv2c
and SNMPv3, and otherwise against the stand-in switch. Not tried on any real switch: a Q-BRIDGE `dot1qPvid` write alone
moving a port on a switch that is not Cisco, and what the bounce does to a real device. That is why quarantine by VLAN on
a switch that is not Cisco is labelled experimental.

## SNMPv3

A switch can be read, and its ports controlled, with **SNMPv3** instead of SNMPv2c. Choose the **SNMP version** in the
switch form. A switch set to SNMPv3 is **never** queried with SNMPv2c: there is no fallback, and an answer with a weaker
security level than the request is dropped.

**What is supported** (the User-based Security Model, RFC 3414):

| | Supported |
|---|---|
| Security levels | `authPriv` (signed and encrypted, **recommended**), `authNoPriv` (signed only), `noAuthNoPriv` (nothing, for an isolated lab only) |
| Authentication | HMAC-SHA-1 (RFC 3414) and HMAC-SHA-2: SHA-224, **SHA-256**, SHA-384, **SHA-512** (RFC 7860) |
| Privacy | **AES-128** (RFC 3826); AES-192 and AES-256 are offered but **experimental** (vendors derive these keys in different ways, DENIS uses the method of net-snmp) |
| Not supported | **DES** privacy and **MD5** authentication (both retired), traps and informs (DENIS only polls) |
| Requests | GET, GETNEXT, GETBULK and the one SET of port control, with bounded retries, timeouts and message sizes |

**Recommended:** `authPriv`, SHA-256 or SHA-512, AES-128, passwords of 8 to 128 characters (use long ones). Use the
strongest protocols the switch offers: the **Catalyst 2960-X on IOS 15.2 offers only SHA-1 and AES-128**, so pick
SHA-1 and AES-128 for it; that is still far better than SNMPv2c.

**Two users, as with the two communities.** The **read user** is used for every poll and needs read access only. The
**write user** is used only when an administrator disables or enables a port (see [Disabling a port](#disabling-a-port));
give it write access to `ifAdminStatus` only, and keep it a different user, so that polling never carries write rights.
Leave the write user's name empty and DENIS stays read-only on that switch. Port control over SNMPv3 is validated on the
Catalyst 2960-X (SHA-1, AES-128) and, since 4.2, needs no *Allow experimental actions (lab use)*, like SNMPv2c; other
switch models stay untested. The same rules as for the communities apply
to the passwords: they are stored encrypted with the installation's secret key, never returned by the API or shown
again, never logged or audited, left out of backups (the restore asks for them again), and a blank password on save
keeps the stored one **only while the switch's address and the user name stay the same**. After a change of address or
user, enter the passwords again.

**How it works.** DENIS first asks the switch for its **engine ID** (an unauthenticated request every SNMPv3 agent
answers), turns each password into a key for that engine (RFC 3414 appendix A.2: the password is hashed over 1 MiB, the
result is kept in memory so a poll does not repeat it), and then signs and encrypts each request. The switch checks
the message against its own clock: a message more than 150 seconds off, or from before a reboot, is refused with a
`notInTimeWindows` report, which is signed, so DENIS takes the switch's boot count and time from it and asks again
(at most twice). A wrong password, an unknown user or a level the user is not allowed shows up as a plain sentence in the
switch's line ("The switch rejected the authentication. The authentication protocol is the most likely cause ..."; a plain
"SHA" on a switch means SHA-1, not SHA-256, so check the protocol first and the password second). A switch
that does not answer at all says "no answer from the device". A wrong **privacy** password is often silence, because
many agents simply drop what they cannot decrypt.

**The engine ID is pinned (4.1.2).** Since the first request is unauthenticated, someone on the path could answer it
for another switch. So the first poll whose answer is authenticated pins the switch's engine ID, and port control is
sent only to that engine (a switch added before 4.1.2 is pinned at its next poll). If the switch later answers with
another engine ID (it was replaced or its SNMP configuration reset, or someone answers for it), polls go on, the
switch's line on *Network → Equipment* is marked *engine ID changed* and its detail shows both IDs, and disabling or enabling a port is refused until an
administrator presses **Confirm the new engine ID**. Changing the switch's address drops the pin. Give each switch its
own write user password: a key localised for one switch then never works on another.

**Cisco per-VLAN reading.** With SNMPv2c a Cisco IOS switch gives each VLAN's forwarding table through
`community@vlan`. With SNMPv3 DENIS reads the SNMP **context** `vlan-<n>` instead, with the same user and keys. The
group on the switch must be allowed to use these contexts (see the Cisco steps below).

### Setting up SNMPv3 on a Cisco IOS switch (Catalyst 2960-X)

Example for a DENIS server at `192.0.2.10`. Replace the group, user and password names. Do the read user first and
press **Read now** before adding the write user.

```
ip access-list standard DENIS-SNMP
 permit 192.0.2.10
!
snmp-server view DENIS-READ iso included
snmp-server view DENIS-IFADMIN 1.3.6.1.2.1.2.2.1.7 included
!
! read group: read-only, authentication and encryption required, also for the per-VLAN contexts
snmp-server group DENIS-RO v3 priv read DENIS-READ access DENIS-SNMP
snmp-server group DENIS-RO v3 priv context vlan- match prefix read DENIS-READ access DENIS-SNMP
! write group: may write only ifAdminStatus (ifAdminStatus is also what the read view shows)
snmp-server group DENIS-RW v3 priv read DENIS-READ write DENIS-IFADMIN access DENIS-SNMP
!
snmp-server user denis-ro DENIS-RO v3 auth sha <auth password> priv aes 128 <privacy password> access DENIS-SNMP
snmp-server user denis-rw DENIS-RW v3 auth sha <auth password> priv aes 128 <privacy password> access DENIS-SNMP
```

Then in DENIS: *Settings* → *Switches (SNMP)* → add or edit the switch → **SNMP version: SNMPv3** → user `denis-ro`,
level `authPriv`, authentication **SHA-1**, privacy **AES-128**, and the two passwords. For port control, open *Allow
DENIS to disable ports on this switch* and enter `denis-rw` and its passwords.

Notes: the user lines are not shown in `show running-config` (the keys are kept in a form tied to the switch's SNMP
engine ID, so changing `snmp-server engineID` invalidates them: create the users again). `show snmp user` lists them.
The per-VLAN context lines are the part to check on your IOS version; if the forwarding table of VLANs other than 1 stays
empty, that is the first thing to look at. DENIS never saves the switch's configuration. This was set up and read on a
Catalyst WS-C2960X-48TS-L with IOS 15.2(7)E4; the full quick setup, with the write view for the quarantine VLAN, is in
[SNMP port control](nac/snmp.md#quick-setup-cisco-catalyst-2960-x).

### Setting up SNMPv3 on another switch

The names differ, the pieces are the same:

1. Create a **read-only SNMPv3 user** with security level **authPriv**, authentication SHA-256 or SHA-512 (SHA-1 if
   that is all there is), privacy AES-128, and passwords of at least 8 characters.
2. Give it a read view of at least the system, interfaces (IF-MIB), LLDP, BRIDGE-MIB and Q-BRIDGE-MIB trees (or the whole
   `iso` tree).
3. Allow only the DENIS server's address to use it (an access list or management ACL, where the switch has one).
4. For port control, create a **second user** mapped to a group with **write** access to `ifAdminStatus`
   (`1.3.6.1.2.1.2.2.1.7`) only.
5. Enter both in DENIS as above, press **Read now**, and check that the ports and MAC addresses show up.

If the switch offers only DES or MD5, DENIS cannot use SNMPv3 with it: use SNMPv2c on a management network.

**Verification.** SNMPv3 was checked against RFC test vectors, against a second, independent SNMP implementation
(net-snmp, with SHA-1 and AES-128) and against stand-in switches (every level and protocol, wrong passwords, a skewed
clock, a replayed message, a downgrade attempt), and then on a real **Catalyst 2960-X** (IOS 15.2(7)E4, SHA-1 and
AES-128, `authPriv`). It has not been tried on another make, so treat the first reads from another switch as a test.

**Not supported yet (SNMPv2c only):** none of this changes for SNMPv2c switches; they work exactly as before.

## Details from the console

Explanations that used to be printed on the console screens. The console shows a short version behind the small (i) button after the label it explains; "More in the docs" in it leads here.

* Curved lines show which gateway a device sits behind, not who talks to whom: a single collector cannot see ordinary device-to-device traffic. Dashed arrows are real conversations DENIS decoded for industrial (OT) protocols, shown on sites of up to 60 devices. Dotted arcs group devices of one type. Colour is the risk level; faded nodes were not seen recently; a red dot marks unacknowledged alerts. Drag to pan; Ctrl or ⌘ + scroll (or pinch) to zoom.
