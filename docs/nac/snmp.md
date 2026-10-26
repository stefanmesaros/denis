# Port control: SNMP switches (Cisco Catalyst, D-Link and others)

Status, by switch:

| Switch | Status |
|---|---|
| **Cisco Catalyst 2960-X** (tested: WS-C2960X-48TS-L, IOS 15.2(7)E4) | **Validated on real equipment**, with SNMPv2c and with SNMPv3 (SHA-1, AES-128, `authPriv`): reading, disabling a port, moving a port to a quarantine VLAN, release, extending the time, the Release button, the uplink refusal, and placing a device that announces itself over LLDP. |
| **D-Link DGS-1100** (tested: DGS-1100-08V2, firmware 1.00.015) | **Partly tested.** Reading the ports and switching a port off and on by `ifAdminStatus` work. This model answers SNMP only for the system group and the interface table: no forwarding table and no LLDP, so DENIS cannot place devices behind it by itself (you place them by hand), and it has no VLAN objects, so there is no quarantine VLAN. This is a limit of the model. |
| Any other managed switch | SNMPv2c and SNMPv3 reading and `ifAdminStatus` follow the same standard tables and are expected to work. **Not tested** on other makes. The VLAN move on a switch that is not Cisco (`dot1qPvid`) has not been tried at all. |

Configured per switch, not through the generic *Add a connector* list (it predates it): *Network → Equipment → + Add a
switch…*. The two actions that change a switch are **Disable port** and **Move the port to the quarantine VLAN**. The
page has a quick setup for each tested switch, then the details that apply to every switch.

* [Quick setup: Cisco Catalyst 2960-X](#quick-setup-cisco-catalyst-2960-x)
* [Quick setup: D-Link DGS-1100](#quick-setup-d-link-dgs-1100)
* [What each action does on a switch](#what-each-action-does-on-a-switch)

## What it blocks

A single physical switch access port, by switching off `ifAdminStatus` (MIB-II, OID `1.3.6.1.2.1.2.2.1.7`) for the
`ifIndex` the device's MAC was learned on in the most recent poll. Everything else plugged into the same port is cut
off too: the dialog lists what DENIS knows about it before you confirm.

## Quick setup: Cisco Catalyst 2960-X

**Verified with:** Cisco Catalyst 2960-X, IOS 15.2, SNMPv3 `authPriv` (SHA-1, AES-128) and SNMPv2c with a write
community; switching a port off and moving it to the quarantine VLAN were verified in the owner's lab.

Tested on a Catalyst WS-C2960X-48TS-L with IOS 15.2(7)E4, SNMPv2c and SNMPv3 (SHA-1, AES-128, `authPriv`). Other
Catalyst models and IOS 15.x releases use the same MIBs and are expected to work; they have not been tried.

**What must be in the path.** A switch port action acts on the port the device is plugged into, so the device must be
connected to an **access port of this switch** (directly, or through an unmanaged mini-switch, which DENIS warns about).
DENIS reaches the switch's management address over UDP 161 from the DENIS server. A device that reaches the network only
through another switch needs that switch added too. Traffic does not have to pass a firewall.

1. **On the switch** (example DENIS server `192.0.2.10`; replace the names, passwords and the address). Use SNMPv3 where you
   can; the v2c lines are for a switch you cannot change to v3.

   SNMPv3 (IOS 15.x offers only SHA-1 and AES-128):
   ```
   lldp run
   ip access-list standard DENIS-SNMP
    permit 192.0.2.10
    deny any log
   snmp-server view DENIS-READ iso included
   snmp-server view DENIS-WRITE 1.3.6.1.2.1.2.2.1.7 included
   snmp-server view DENIS-WRITE 1.3.6.1.4.1.9.9.68.1.2.2.1.2 included
   snmp-server group DENIS-RO v3 priv read DENIS-READ access DENIS-SNMP
   snmp-server group DENIS-RO v3 priv context vlan- match prefix read DENIS-READ access DENIS-SNMP
   snmp-server group DENIS-RW v3 priv read DENIS-READ write DENIS-WRITE access DENIS-SNMP
   snmp-server user denis-ro DENIS-RO v3 auth sha <auth password> priv aes 128 <privacy password> access DENIS-SNMP
   snmp-server user denis-rw DENIS-RW v3 auth sha <auth password> priv aes 128 <privacy password> access DENIS-SNMP
   ```
   SNMPv2c:
   ```
   lldp run
   ip access-list standard DENIS-SNMP
    permit 192.0.2.10
    deny any log
   snmp-server view DENIS-WRITE 1.3.6.1.2.1.2.2.1.7 included
   snmp-server view DENIS-WRITE 1.3.6.1.4.1.9.9.68.1.2.2.1.2 included
   snmp-server community <long random read community> RO DENIS-SNMP
   snmp-server community <long random write community> view DENIS-WRITE RW DENIS-SNMP
   ```
   What these do: the read user or community reads everything DENIS polls (ports, MAC table per VLAN, LLDP, CDP, trunk
   mode, VLAN list); the write user or community may write **only** `ifAdminStatus` (switch a port off) and `vmVlan`
   (`1.3.6.1.4.1.9.9.68.1.2.2.1.2`, move an access port to another VLAN). **The `vmVlan` line is needed for the quarantine
   VLAN**: without it the move is refused. Both are restricted to the DENIS server's address by the access list. Leave out
   the `vmVlan` line if you will never use the quarantine VLAN. `lldp run` lets DENIS place a device that announces itself
   over LLDP (a phone, an access point, a laptop with LLDP) by name; leave CDP on (the default), because DENIS uses it only to
   refuse a port that has network equipment behind it. `snmp-server ifindex persist` keeps port numbers the same across a
   reboot and is a sensible addition.

   The `snmp-server user` lines do not show in `show running-config`; `show snmp user` lists them. Changing
   `snmp-server engineID` invalidates them: create the users again.
2. **Quarantine VLAN (only if you want it).** Create the VLAN, give it a DHCP scope and the services a quarantined device
   needs (DNS, NTP, your remediation server), plus the rules you want there. DENIS never creates any of it.
   ```
   vlan 99
    name denis-quarantine
   ```
   Put a test device on a port in that VLAN by hand and check that it gets an address and reaches those services.
3. **In DENIS:** *Network → Equipment → + Add a switch…*: **Name**, **Address** (`192.0.2.2`, or `192.0.2.2:1161` for another
   port), **SNMP version**.
   * *SNMPv3:* under **Read user**: **User name** `denis-ro`, **Security level** `authPriv`, **Authentication protocol**
     *SHA-1* (a plain `sha` on the switch means SHA-1, not SHA-256), **Authentication password**, **Privacy protocol**
     *AES-128*, **Privacy password**. Open **Allow DENIS to disable ports on this switch** and enter the **Write user**
     `denis-rw` with the same level and protocols and its passwords.
   * *SNMPv2c:* **SNMP community (read only)**; open **Allow DENIS to disable ports on this switch** and enter the
     **SNMP write community**.
   * Leave **Cisco: forwarding table per VLAN** on *Automatic*. Keep **Read this switch regularly** ticked (port control
     needs the switch to be read; DENIS could not notice a port coming back otherwise).
   * For the quarantine: open **Quarantine by VLAN (experimental)**, enter the **Quarantine VLAN** (`99`) and tick **I tested
     this VLAN** only after step 2 worked. Without the tick the switch offers no quarantine.
   * Save, then press **Read now**. It must report ports, neighbours and MAC addresses. If a VLAN other than 1 is missing,
     see *If something fails* below.
4. **Settings → Response policy:** tick *Allow administrators to block devices from DENIS* (and look at the limit of
   blocks per hour). Disabling a port and the VLAN move are validated on this switch, with SNMPv2c and with SNMPv3 (SHA-1,
   AES-128), and need no lab switch.
5. **Try it on a harmless device.** Open a test client's panel, *Respond…* → *Disable port*, duration **5 minutes**, type
   the port's name (for example `Gi1/0/5`), your reason and your password. Expect: the client loses its link;
   `show interfaces Gi1/0/5 status` says *disabled*; `show running-config interface Gi1/0/5` shows `shutdown`. After the five
   minutes (plus about 30 seconds) the port comes back by itself. Then try **Release** before the end, and **Extend…** (the
   new duration counts **from now**). For the quarantine: *Respond…* → move the port to the quarantine VLAN;
   `show vlan id 99` lists the port; release puts it back in its VLAN exactly as it was.

**If something fails**

* *The quarantine move is refused by the switch, or a Read now error says the write was refused:* the write view must
  include `1.3.6.1.4.1.9.9.68.1.2.2.1.2` (`vmVlan`, `vmMembershipEntry.2`) as well as `ifAdminStatus`
  (`1.3.6.1.2.1.2.2.1.7`). A write view with only `ifAdminStatus` switches ports off but fails every quarantine move.
  Check `show snmp group` (which view the write group uses) and `show snmp view | include DENIS`.
* *Disable port and the quarantine move are missing from the Respond menu:* the switch has no write credential in DENIS.
  With SNMPv2c the port actions need the **SNMP write community**; without it they simply do not appear, with no error.
* *"The switch rejected the authentication":* the authentication protocol on the switch and in DENIS must be the same. IOS
  15.x: SHA-1 and AES-128 only. A wrong **privacy** password usually gives no answer at all rather than an error.
* *"No answer from the device":* UDP 161 from the DENIS server, the access list, the user name or community.
* *Devices in VLAN 20 are not placed:* with SNMPv3 the read group needs the
  `snmp-server group DENIS-RO v3 priv context vlan- match prefix read DENIS-READ ...` line above; with v2c the per-VLAN
  read uses `<community>@<vlan>`. Press **Read now** and look at the switch card.
* *The switch card names VLANs that did not answer:* a VLAN with no port up has no forwarding table on IOS and stays
  silent (`show spanning-tree vlan 20` says the instance does not exist); that is normal. DENIS reads the other VLANs, and
  in 4.2.4 refuses a port action only on a port that carries a VLAN it could not read.
* The full table (text on the switch card, cause, check, fix) with the `show` commands and an `snmpwalk` test is in
  [Switches: troubleshooting a Cisco switch](../switches.md#troubleshooting-a-cisco-switch).
* *A port is refused:* the port DENIS or the gateway is behind, the way to the switch itself, `Fa0`, a mirror port; for the
  VLAN move also a trunk, an EtherChannel member, more than one device, a voice VLAN, 802.1X or MAC authentication. The
  plan names the reason. An uplink, a trunk, an EtherChannel member or a port with a CDP neighbour can be switched off
  **by hand only**, with a warning to tick for each (see [Switches](../switches.md#ports-that-are-not-plain-access-ports-by-hand-only-with-warnings-to-tick)).
* *A port is back after a switch restart:* DENIS changes the running configuration only and never saves; a reload returns
  the port to its saved state.
* *"Confirm the new engine ID" on the switch line:* the switch's SNMP engine ID changed (replaced, reset, or someone
  answers for it). Check, then confirm it on *Network → Equipment*.

## Quick setup: D-Link DGS-1100

Tested on a DGS-1100-08V2, firmware 1.00.015, SNMPv2c. Other DGS-1100 models and firmware are expected to behave alike
but have not been tried. This series has no SNMPv3.

**What this switch can and cannot do for DENIS.** Over SNMP it serves only the system group and the interface table. So:

* DENIS reads its **ports** (names `port1` to `port8`, link, on or off) and can switch a port **off and on** by
  `ifAdminStatus`. This was tried with the write community: the SET was accepted and read back, and the port came back with
  a SET back to on. A SET with the **read** community gets no answer at all (silence, not an error) and changes nothing.
* It gives **no forwarding table, no LLDP and no VLAN objects**, so DENIS **cannot see which device is on which port**. A
  plan from a device's panel is refused with "no forwarding table" until you place the device on a port by hand
  (below). There is **no quarantine VLAN** on this switch.

**What must be in the path.** The device must be plugged into this switch, and DENIS must reach the switch's address over
UDP 161.

1. **On the switch:** in the web interface turn SNMP on and create two communities: one **read-only** and a **separate
   read-write** one, long and random; if the switch can limit them to the DENIS server's address, do it. (The menu names
   differ between firmware versions; use the SNMP section of the web interface, or the manual of your firmware.) Use a
   management VLAN if you can: SNMPv2c sends the communities unencrypted.
2. **In DENIS:** *Network → Equipment → + Add a switch…*: **Name**, **Address**, **SNMP version** *SNMPv2c*, **SNMP community
   (read only)**. Leave **Cisco: forwarding table per VLAN** as it is (it does not apply). Open **Allow DENIS to disable
   ports on this switch** and enter the **SNMP write community**. Save and press **Read now**: it reports the ports and no
   MAC addresses.
3. **Settings → Response policy:** tick *Allow administrators to block devices from DENIS*. The old port control (Topology)
   is validated on this switch. Placing a device by hand is **experimental** and needs *Allow experimental actions (lab use)*.
4. **Place the device by hand.** Open the device's panel, *Place & response* → **Place it manually…**: choose the switch and
   the port (the list shows plain access ports that have a link), add a note, save. The panel then says *placed by hand*.
   The placement holds for **30 days**, or until the port's link changes (DENIS reads `ifLastChange`), and can be changed,
   confirmed again or cleared.
5. **First test.** *Respond…* → *Disable port* for **5 minutes** on a test client. The plan shows a warning that must be
   ticked ("DENIS cannot verify what is on this port"); type the port's name (`port3`), your reason and password. The
   client loses its link and gets it back at the end, or at **Release**.

**If something fails:** "no forwarding table" means the device is not placed; "learned on more than one port" and the like
do not apply here. A placement is refused when the port has no link, when it is an uplink or has a neighbour, or when
another switch DENIS reads says the device is elsewhere. If a switch answers a larger request with `tooBig`, DENIS asks for
fewer rows (this switch does).

## What each action does on a switch

| Action | What DENIS writes | Undo | Verified how |
|---|---|---|---|
| **Disable port** | `ifAdminStatus` of **one** port to *down*, after the typed port name, the password and a fresh read of the switch. | The port is set back to *up* at the end of the time, on **Release**, or on **Enable**. Only a port DENIS switched off is ever switched on. | DENIS reads the port back after the write; the hourly job reads it again. |
| **Move to the quarantine VLAN** (Cisco) | `vmVlan` of **one** access port to your quarantine VLAN. On a switch that is not Cisco: `dot1qPvid` (not tried). | The port's previous VLAN is recorded and written back **only if the port is still in the quarantine VLAN**. | Same read-back and hourly check. |
| Block a device, block a flow, end sessions | Not offered: a switch cannot do them. | | |

* **A duration** (minutes, hours, days or permanent; the default is one hour). A permanent action needs a tick. When
  the time is up DENIS puts the port back, even while port control is switched off; the expiry job waits 30 seconds longer
  than the time set and only runs on the active HA node.
* **Extend** sets the new end **from now** (not added to the old end) and needs your password. **Release** needs no password.
* **Drift:** a port that someone changed in the meantime (`no shutdown`, another VLAN) is recorded as *removed elsewhere* and
  never changed back by DENIS. An answer that did not arrive leaves the action *not confirmed*: use **Check now**.
* **Persistence:** the change is in the running configuration only; DENIS never saves it. A switch restart returns the port to
  its saved state.

## Setup, in general

1. On the switch, create a **separate write credential**: preferably an **SNMPv3 write user** (see
   [switches.md](../switches.md#snmpv3) and the Cisco IOS steps above), otherwise a separate **write community** (do not
   reuse the read-only polling one). Restrict it to an access list that allows only the DENIS server's address, and, if
   the switch supports SNMP views, to writing only `ifAdminStatus` (on a Cisco switch also `vmVlan`,
   `1.3.6.1.4.1.9.9.68.1.2.2.1.2`, for the quarantine VLAN move).
2. *Network → Equipment* → edit the switch → open "Allow DENIS to disable ports on this switch" →
   enter the write user and its passwords (SNMPv3) or the write community (SNMPv2c).
3. *Settings → Response policy*: turn on "Allow administrators to block devices from DENIS".

## Credentials

Per switch, one of two kinds, stored next to that switch's read credential:

* **SNMPv3 (recommended):** a **write user** with its own security level, protocols and passwords, separate from the
  read user. The message is signed (and at `authPriv` encrypted), so nothing useful travels in clear text when a port is
  disabled or enabled. The passwords are stored encrypted, never returned and never logged. A switch set to SNMPv3 is
  never written to with a community.
* **SNMPv2c:** one write community string. It travels **unencrypted** every time a port is disabled or enabled, exactly
  as the read community does for polling; the switch form says so.

Port control over SNMPv3 is validated on the Catalyst 2960-X (SHA-1, AES-128, `authPriv`) and is no longer experimental:
since 4.2 it needs no *Allow experimental actions (lab use)*, like SNMPv2c. Other switch models stay as described above
(expected to work, not tested).

If the switch refuses the credential before looking at the request (wrong user, password or level), DENIS reports a
refusal and nothing was changed; if no answer comes back, the outcome is "not confirmed" and the port is read again.

### SNMPv3 on another switch

Create a second SNMPv3 user at `authPriv` (SHA-256 or SHA-512 and AES-128 where offered), put it in a group whose write
view contains only `ifAdminStatus` (`1.3.6.1.2.1.2.2.1.7`) and, for the quarantine VLAN move on a Cisco switch, `vmVlan` (`1.3.6.1.4.1.9.9.68.1.2.2.1.2`), allow only the DENIS server's address to use it, and enter
it in the switch form. DES and MD5 are not supported.

## Cisco IOS (Catalyst 2960-X and family)

* **Location in every VLAN.** The forwarding table is read once per VLAN through `<community>@<vlan>` (SNMPv3: the
  context `vlan-<n>` with the same user; setting *Cisco: forwarding table per VLAN*, automatic by default), so a device in VLAN 20 is found, not only one in VLAN 1.
* **Refused, whatever is confirmed:** the Port-channel itself (not a physical port); the management port `Fa0`.
* **By hand only, with a warning to tick at the plan and again at the apply** (4.2; never proposed, never automated): an
  802.1Q trunk (CISCO-VTP-MIB `vlanTrunkPortDynamicStatus`), even with one MAC; a port whose trunk mode the switch did not
  report unless exactly one device and no neighbour is behind it (an end host that announces itself, such as a laptop, is
  the device, not a neighbour); an EtherChannel member; a port with a CDP neighbour (a Cisco IP phone's port too); more
  than 24 MACs (can be lowered, `trunk_mac_threshold`).
* **Re-read at confirmation.** Right before the SET the switch's forwarding table is read again; a device that was
  unplugged, replaced or moved, or a second device that joined, stops the block with nothing changed.
* **Write view.** `snmp-server community <rw> view <view> RW <acl>` (SNMPv2c) or the write group above (SNMPv3), with a
  view that includes only `ifAdminStatus` (`1.3.6.1.2.1.2.2.1.7`) and, for the quarantine VLAN move, `vmVlan` (`1.3.6.1.4.1.9.9.68.1.2.2.1.2`); the SET changes the running configuration only and DENIS never saves it.
* The MIB objects for the VLAN list, trunk mode, link aggregation and CDP answered on the 2960-X as expected; on another
  model or IOS release, a table that does not answer makes DENIS warn about the port (`class_unknown`) rather than guess.

## The response dialog (4.1): disable a port, or move it to the quarantine VLAN

Each switch also appears in the response dialog (Respond, from a device, a port or an incident) as the
connector `snmp:<switch id>`. Two actions are built; the old buttons on the Topology page keep working exactly as
before and share the same refusals. The dialog adds what every response has (see [Enforcement](../enforcement.md)):

* **A duration**: minutes, hours, days or permanent. The default is **one hour**. A permanent action carries an extra
  warning and a box to tick. When the time is up DENIS puts the port back **exactly as it was**, even while port control
  is switched off; the expiry job waits 30 seconds longer than the time set and only runs on the active HA node. Someone
  can also release it by hand at any time (Active responses).
* **A stored plan** that can be used once, within two minutes, only by the person it was made for.
* **One action per physical port.** A second plan on a port that has an active action is refused, whichever action it
  is, and so is a port the old routes disabled.
* **The port's name typed** to confirm (this is a high risk action).
* **Steps and undo data**: what DENIS read before it wrote (the port's previous admin status or VLAN) is kept with the
  action and is what a release restores. DENIS reads the port again right before the write.
* **Read-back and drift**: after the write DENIS reads the port; the hourly reconcile job reads it again. A port that
  someone changed in the meantime is recorded as *removed elsewhere* and **never changed back by DENIS**.

Both actions need the switch's write credential (SNMPv3 write user or v2c write community, as above) and the switch must be
read regularly.

### Disable port (`if_admin_status`)

The same refusals, the same re-read of the forwarding table and the same warnings to tick (several devices, a neighbour
that is not a switch, nothing seen) as the old button. It is validated on the Catalyst 2960-X and was validated earlier
for the SET and the read-back on the D-Link switch (2026-10-01). Undo data: the port was **on** (DENIS never disables a
port that is already off).

### Quarantine by VLAN (`access_vlan`)

DENIS moves **one access port** into a quarantine VLAN **you** built, and moves it back. It never creates the VLAN, its
DHCP scope, its gateway or any rule, and it never edits a VLAN list.

Set up, per switch (*Network → Equipment* → edit the switch → *Quarantine by VLAN (experimental)*):

1. On the switch, create the VLAN (for example 99) and give it DHCP and the services a quarantined device needs (DNS,
   NTP, your remediation server), plus the rules you want on it. Nothing here is DENIS's business.
2. Put a test device on a port in that VLAN and check that it gets an address and reaches those services.
3. Enter the VLAN number (2 to 4094, not 1002 to 1005) and tick *I tested this VLAN*. **Without the tick the switch
   offers no quarantine.** Changing the number clears the tick.

What DENIS writes: on a **Cisco IOS** switch `vmVlan` (CISCO-VLAN-MEMBERSHIP-MIB, `1.3.6.1.4.1.9.9.68.1.2.2.1.2.<ifIndex>`,
INTEGER); on **every other switch** `dot1qPvid` (Q-BRIDGE-MIB, `1.3.6.1.2.1.17.7.1.4.5.1.1.<bridge port>`, Gauge32), the
bridge port found through `dot1dBasePortIfIndex`. On a switch that is not Cisco only the port's VLAN changes. Some switches
also need the port to be an untagged member of the new VLAN, which DENIS does not do (see the list below). The move on a
Cisco switch is validated on the 2960-X; the `dot1qPvid` write is **not** tried on any switch.

**Refused, whatever is ticked** (the same hard list as for disabling a port, plus these):

* a trunk port or a member of an EtherChannel or link aggregation (no single access VLAN to change: switch it off by hand
  instead), the management port, a mirror port, the port where DENIS itself or the gateway sits;
* an uplink, a port with a CDP neighbour or a port whose kind the switch did not say carries the same warnings to tick as
  for switching a port off, and is refused anyway when more than one device is behind it (below);
* a port with **more than one device** behind it (a hub, a phone with a PC), or any LLDP neighbour on it (a phone or an
  access point), or traffic from more than one VLAN learned on it, or tables that were read only in part;
* a **voice VLAN** on the port (Cisco `vmVoiceVlanId`); a Cisco switch that does not answer is refused too;
* a port whose VLAN is not one fixed access VLAN (Cisco `vmVlanType` other than static, so VMPS or several VLANs), or
  whose VLAN the switch did not say;
* **802.1X or MAC authentication** active on the port (IEEE8021-PAE-MIB `dot1xAuthAuthControlledPortControl` reads *auto*
  while `dot1xPaeSystemAuthControl` is on). A Cisco switch that does not answer is refused; on another vendor's switch DENIS
  cannot tell, and it is a warning you must tick instead;
* a quarantine VLAN that **does not exist on the switch** (read from the switch's VLAN list, Cisco `vtpVlanState`), or
  that DENIS could not look up;
* a port **already in the quarantine VLAN**;
* no quarantine VLAN set for the switch, or the *tested* tick missing.

A warning you must tick: an **OT** device behind the port (noise profile OT), and the cases above marked as warnings.

**Bounce** (off by default). The dialog can switch the port off and on once after the move (`ifAdminStatus` down, then up)
so that the device asks for an address again, and does the same after the move back. Leave it off for a device with a
static address or an OT device: it is simply cut off until the port is restored. If 802.1X or MAC authentication is
active on the port the switch can undo the change by itself; DENIS then records the change as removed elsewhere and does
not repeat it. If the port cannot be switched on again after the bounce, DENIS undoes the move and tries to switch it on.
The bounce has not been tried on a real device.

**Undo.** The port's previous VLAN is recorded. On release or at the end of the time DENIS moves the port back **only if it
is still in the quarantine VLAN**; a port someone else moved is left where it is. The change is in the running
configuration only (DENIS never saves it), so a switch restart returns the port to its saved VLAN.

### What is verified, and what is not

Tested on a real Catalyst WS-C2960X-48TS-L (IOS 15.2(7)E4), SNMPv2c and SNMPv3 (SHA-1, AES-128): the port moved to
the quarantine VLAN (`show vlan id` confirmed it), came back on release, the time could be extended, the Release button
worked, an uplink was refused, and a device announcing itself over LLDP was placed by name. The rest was tested against a
stand-in switch in DENIS's own tests (plan, apply, expiry, drift, each refusal, a lost answer or request, the re-read
before the write, the one action per port rule). On the 2960-X:

* `vmVlan` is writable with a read-write community or SNMPv3 write user, the write needs the view to include
  `1.3.6.1.4.1.9.9.68.1.2.2.1.2`, and the new VLAN takes effect in the running configuration.
* `vmVlanType` reads static(1) on an access port; `vmVoiceVlanId` answers and reads "none" (DENIS treats 4095 and 4096
  and anything outside 1 to 4094 as none) without a voice VLAN.
* `dot1xPaeSystemAuthControl` and `dot1xAuthAuthControlledPortControl` answer, and a MAB or 802.1X port reads *auto*. (On IOS,
  MAB needs `dot1x system-auth-control`.) If they do not answer, a quarantine on a Cisco switch is refused: that is the
  safe outcome, not a fault.
* `vtpVlanState` for management domain 1 tells operational(1) for an existing VLAN (a VTP transparent switch too).

**Not tried:** `dot1qPvid` on a switch that is not Cisco (some switches need the egress membership too); the bounce on a
real device; whether a block survives a switch restart on any switch.

## Caveats

See [Switches](../switches.md#disabling-a-port) for the safety model (re-poll before plan, blast radius, the self-lockout
refusals, the uplink and LAG warnings to tick, drift detection).
