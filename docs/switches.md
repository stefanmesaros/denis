# Switches and the physical topology (SNMP)

The **Topology** tab has two maps. *By gateway* is the logical one every install has. **Switches and cables** is the
physical one: which **port** each device is plugged into and how the **switches are cabled together**. It needs your
switches to answer SNMP, so you tell DENIS which ones to read.

## What DENIS reads

For every switch you add (*Settings* → **Switches (SNMP)**), DENIS reads, and only reads, every few minutes:

| MIB | What for |
|---|---|
| system (`sysDescr`, `sysName`) | the switch's name and description |
| IF-MIB (`ifName`, else `ifDescr`; `ifAlias`, `ifOperStatus`, `ifAdminStatus`, `ifType`, `ifHighSpeed`) | the ports: name, the label somebody typed, up or down (link), switched on or off (administratively), physical or not, speed |
| LLDP-MIB (`lldpRemTable`, `lldpLocChassisId`) | what each port sees on the other end of the cable: another switch, an access point, a phone: as that device announces itself |
| Q-BRIDGE-MIB (`dot1qTpFdbPort`), else BRIDGE-MIB (`dot1dTpFdbPort`) | the forwarding table: which MAC address was learned on which port |

A poll only ever reads, always with the read community. DENIS sends **one kind of SET**: `ifAdminStatus` of **one
port**, only for a switch you gave a separate **write community**, only when an **administrator asks and confirms** with
their password (see [Disabling a port](#disabling-a-port)). A switch without a write community is never written to.
A table a switch does not implement is simply left out; only a switch that does not answer at all is an error, shown on
the switch's line with the reason.

## Setting it up

1. On the switch, create a **read-only SNMP v2c community** and allow **only the DENIS server's address** to use it (an
   access list on the switch). Give it a long random name: **in v2c the community travels unencrypted**, so treat it as a
   password that anybody who can watch that link could learn.
2. *Settings* → *Switches (SNMP)* → **Add a switch**: a name, the switch's address (`192.168.1.2`, or `192.168.1.2:1161`
   for another port) and the community. The community is stored with the list, is never shown again (leave it blank when
   editing to keep it) and never appears in the audit log.
3. Press **Read now**. It says how many ports, neighbours and MAC addresses were read, or why not ("no answer from the
   device": check that SNMP is on, the community, and that UDP 161 is reachable from the DENIS server).
4. Open **Topology** → *Switches and cables*. A device's own panel also gets a **Connected to** line.

Polling runs from the DENIS collector (not in a `denis serve` viewer). The interval is 5 minutes by default (60 to 3600 seconds).

## Disabling a port

**DENIS never blocks anything on its own.** A person with the administrator role asks for every block, for one port at a
time. They see exactly what will be cut off before they confirm. They confirm with their password. Every block is
logged, announced on every alerting channel, and listed until someone undoes it.

### Turning it on (twice)

1. *Settings* → **Port control**: *Allow administrators to disable switch ports* (off by default), and the most blocks
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
reading, but for a credential that can take ports down. SNMPv3 is not supported yet.

### Who can, and how

Only a signed-in **administrator** with access to every site (switches do not belong to a site yet): never a viewer
or editor, never an API token, never under `--insecure-no-auth`. Two places offer it, when port control is on and the
switch has a write community:

* **Topology** → *Switches and cables* → a switch's **Ports** table: **Disable…** on a port;
* a device's panel, under *Connected to*: **Disable this device's switch port…**

Either way DENIS first **reads the switch again, right now** (for a device: every switch that last placed it) and shows
a preview built only from that fresh read: the switch and port, every device it can name behind the port, how many MAC
addresses it cannot name, and every warning and refusal. The preview is valid for **two minutes** and can be confirmed
once, only by whoever asked for it. Confirming needs a **reason** (3 to 200 characters) and your **password** (wrong
answers count against the account's lockout, like restarting DENIS). Right before acting, DENIS reads the port once more
and refuses if that index now carries another port's name (some switches renumber ports after a reboot or a module
change). Then it sends the SET and **reads the port back**:

* **disabled**: the switch reads it as switched off;
* **not confirmed**: the SET or the read-back got no clear answer; the port may or may not be off. Check the switch, or
  use **Check now**;
* **refused**: the switch answered with an error (for example "this community cannot write"); nothing changed.

### What DENIS refuses, whatever you confirm

* cutting off **DENIS itself**, the **gateway**, or a **switch DENIS reads**;
* a device whose identity is in doubt: an open **address-conflict** alert, or its MAC learned on **more than one access
  port** right now (MAC cloning, a man in the middle: the port may be the victim's). Find the right port by hand;
* an **uplink** (an LLDP neighbour that is a switch DENIS reads) or a **trunk** (more than 24 MACs behind it);
* anything but a **physical Ethernet port** (`ifType` 6): no VLAN interfaces, port-channels, loopbacks or the CPU;
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

LAG (port-channel) membership is not read yet (`ifStackTable`): a member port of a LAG is not recognised as such.

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

## How a device is placed

* A device is drawn on the port where its **MAC address was learned**. If it is learned in several places, the port with the
  **fewest** other MACs behind it wins: an access port beats an uplink.
* A port that leads to **another switch you poll** (LLDP says so), or that has **more than 24 MACs** behind it, is a
  trunk: what it learns is only "somewhere further down", so no device is claimed to be plugged into it. The device shows up
  on its real port once the switch it hangs off is added as well.
* A neighbour that **announces itself by LLDP** (an access point, a phone) is drawn with what it says and matched to the
  register by its chassis MAC.
* MACs on access ports that are **not in the register** are only counted (the map says how many).

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
It has been tried against **one real switch so far, a D-Link DGS-1100-08V2** (2026-10-01): it answers IF-MIB (names only
in `ifDescr`, "port1" to "port8"; `ifType`, `ifAdminStatus`, `ifOperStatus`), but **no forwarding table, no bridge-port
map and no LLDP**, so DENIS lists its ports and cannot place any device on them. It answers larger GETBULK requests with
`tooBig` (DENIS now asks for fewer rows per answer), and a GET for several variables, one of which it lacks, with only
that one (DENIS now matches answers by OID and asks again for the rest). Vendors differ (VLAN-specific communities on
some Cisco models, LLDP local port numbering, bridge-port to interface maps), so read the map critically at first and
please report a switch that shows something wrong.

Port control on that switch (one empty port, by hand, with DENIS's own connector code): a SET of `ifAdminStatus` with
the write community was accepted and read back as off; the port came back on with a SET back to on; a SET with the
**read** community got **no answer** (silence, not an error status) and changed nothing; a port switched on from outside
DENIS (`snmpset`) was noticed by the next poll as drift. A plan through the console is refused on every port of this
switch ("no forwarding table"), as it should be. **Not verified yet:** whether a block survives a switch restart (with
and without saving the configuration), and the self-lockout and uplink refusals on real hardware (they need a switch
that has a forwarding table). Those are tested only against the stand-in switches.

**Not supported yet:** SNMPv3 (authentication and encryption). Until it is, restrict the v2c community as described above.
