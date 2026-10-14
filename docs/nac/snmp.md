# Port control: SNMP (switch port, `ifAdminStatus`)

Status: **wired and validated on real equipment** (one real switch, supervised pilot use; it is not subject to the lab switch) (connector 1). Configured per switch, not through the generic
"Enforcement connectors" list (it predates it): *Settings → Network → Switches (SNMP)*.

## What it blocks

A single physical switch access port, by switching off `ifAdminStatus` (MIB-II, OID `1.3.6.1.2.1.2.2.1.7`) for the
`ifIndex` the device's MAC was learned on in the most recent poll. Everything else plugged into the same port is cut
off too — the dialog lists what DENIS knows about it before you confirm.

## Setup

1. On the switch, create a **separate write credential**: preferably an **SNMPv3 write user** (see
   [switches.md](../switches.md#snmpv3) and the Cisco IOS steps below), otherwise a separate **write community** (do not
   reuse the read-only polling one). Restrict it to an access list that allows only the DENIS server's address, and, if
   the switch supports SNMP views, to writing only `ifAdminStatus`.
2. *Settings → Network → Switches (SNMP)* → edit the switch → open "Allow DENIS to disable ports on this switch" →
   enter the write user and its passwords (SNMPv3) or the write community (SNMPv2c).
3. *Settings → Enforcement*: turn on "Allow administrators to block devices from DENIS".

## Credentials

Per switch, one of two kinds, stored next to that switch's read credential:

* **SNMPv3 (recommended):** a **write user** with its own security level, protocols and passwords, separate from the
  read user. The message is signed (and at `authPriv` encrypted), so nothing useful travels in clear text when a port is
  disabled or enabled. The passwords are stored encrypted, never returned and never logged. A switch set to SNMPv3 is
  never written to with a community.
* **SNMPv2c:** one write community string. It travels **unencrypted** every time a port is disabled or enabled, exactly
  as the read community does for polling; the switch form says so.

**SNMPv3 port control is new and not yet tried on real equipment**, so it is treated like the other new actions:
DENIS refuses to plan a block on a SNMPv3 switch until an administrator allows experimental actions (lab use) under
*Settings → Enforcement*. Reading with SNMPv3, and enabling a port again, never need that. SNMPv2c port control is
unchanged.

If the switch refuses the credential before looking at the request (wrong user, password or level), DENIS reports a
refusal and nothing was changed; if no answer comes back, the outcome is "not confirmed" and the port is read again, as
before. The SET itself and the read-back are the same in both versions.

### SNMPv3 on a Cisco IOS switch

```
ip access-list standard DENIS-SNMP
 permit 192.0.2.10
snmp-server view DENIS-READ iso included
snmp-server view DENIS-IFADMIN 1.3.6.1.2.1.2.2.1.7 included
snmp-server group DENIS-RO v3 priv read DENIS-READ access DENIS-SNMP
snmp-server group DENIS-RO v3 priv context vlan- match prefix read DENIS-READ access DENIS-SNMP
snmp-server group DENIS-RW v3 priv read DENIS-READ write DENIS-IFADMIN access DENIS-SNMP
snmp-server user denis-ro DENIS-RO v3 auth sha <auth password> priv aes 128 <privacy password> access DENIS-SNMP
snmp-server user denis-rw DENIS-RW v3 auth sha <auth password> priv aes 128 <privacy password> access DENIS-SNMP
```

IOS 15.2 on the Catalyst 2960-X offers SHA-1 and AES-128: choose those in the switch form (security level `authPriv`).
The write group can write only `ifAdminStatus`; the SET changes the running configuration only and DENIS never saves it.
Not yet tried on real hardware.

### SNMPv3 on another switch

Create a second SNMPv3 user at `authPriv` (SHA-256 or SHA-512 and AES-128 where offered), put it in a group whose write
view contains only `ifAdminStatus` (`1.3.6.1.2.1.2.2.1.7`), allow only the DENIS server's address to use it, and enter
it in the switch form. DES and MD5 are not supported.

## Cisco IOS (Catalyst 2960-X and family)

* **Location in every VLAN.** The forwarding table is read once per VLAN through `<community>@<vlan>` (SNMPv3: the
  context `vlan-<n>` with the same user; setting *Cisco: forwarding table per VLAN*, automatic by default), so a device in VLAN 20 is found, not only one in VLAN 1.
* **Refused, whatever is confirmed:** an 802.1Q trunk (CISCO-VTP-MIB `vlanTrunkPortDynamicStatus`), even with one MAC;
  a port whose trunk mode the switch did not report unless exactly one device and no neighbour is behind it; an
  EtherChannel member or the Port-channel itself; the management port `Fa0`; a port with a CDP neighbour (a Cisco IP
  phone's port too); more than 24 MACs (can be lowered, `trunk_mac_threshold`).
* **Re-read at confirmation.** Right before the SET the switch's forwarding table is read again; a device that was
  unplugged, replaced or moved, or a second device that joined, stops the block with nothing changed.
* **Write view.** `snmp-server community <rw> view <view> RW <acl>` (SNMPv2c) or the write group above (SNMPv3), with a
  view that includes only `ifAdminStatus` (`1.3.6.1.2.1.2.2.1.7`); the SET changes the running configuration only and DENIS never saves it.
* The OIDs for the VLAN list, trunk mode, LAG membership and CDP are marked "verify on hardware": see the hardware
  validation plan for what to record.

## The response dialog (4.1): disable a port, or move it to the quarantine VLAN

Since 4.1 each switch also appears in the response dialog (Respond, from a device, a port or an incident) as the
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
read regularly. A SNMPv3 switch still needs *experimental actions* under *Settings → Enforcement*, as for the old button.

### Disable port (`if_admin_status`)

Unchanged in what it writes and refuses (see above and the Cisco IOS section): the same refusals, the same
re-read of the forwarding table, the same warnings to tick (several devices, a neighbour that is not a switch, nothing
seen). It is the capability validated on the D-Link switch (2026-10-01) for the SET and the read-back; the new plan,
expiry and drift handling around it was tried against the stand-in switch only. Undo data: the port was **on**
(DENIS never disables a port that is already off).

### Quarantine by VLAN (`access_vlan`, experimental)

DENIS moves **one access port** into a quarantine VLAN **you** built, and moves it back. It never creates the VLAN, its
DHCP scope, its gateway or any rule, and it never edits a VLAN list.

Set up, per switch (*Settings → Network → Switches (SNMP)* → edit the switch → *Quarantine by VLAN*):

1. On the switch, create the VLAN (for example 99) and give it DHCP and the services a quarantined device needs (DNS,
   NTP, your remediation server), plus the rules you want on it. Nothing here is DENIS's business.
2. Put a test device on a port in that VLAN and check that it gets an address and reaches those services.
3. Enter the VLAN number (2 to 4094, not 1002 to 1005) and tick *I tested this VLAN*. **Without the tick the switch
   offers no quarantine.** Changing the number clears the tick.
4. Allow *experimental actions* and *connectors that are not validated* under *Settings → Enforcement*: this action has
   not been tried on real equipment.

What DENIS writes: on a **Cisco IOS** switch `vmVlan` (CISCO-VLAN-MEMBERSHIP-MIB, `1.3.6.1.4.1.9.9.68.1.2.2.1.2.<ifIndex>`,
INTEGER); on **every other switch** `dot1qPvid` (Q-BRIDGE-MIB, `1.3.6.1.2.1.17.7.1.4.5.1.1.<bridge port>`, Gauge32), the
bridge port found through `dot1dBasePortIfIndex`. On a switch that is not Cisco only the port's VLAN changes. Some switches
also need the port to be an untagged member of the new VLAN, which DENIS does not do (see the list below).

**Refused, whatever is ticked** (the same hard list as for disabling a port, plus these):

* a trunk port, a member of an EtherChannel or link aggregation, the management port, an uplink to another switch DENIS
  reads, a port with a CDP neighbour, the port where DENIS itself or the gateway sits, a port whose kind the switch did
  not say;
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

**Undo.** The port's previous VLAN is recorded. On release or at the end of the time DENIS moves the port back **only if it
is still in the quarantine VLAN**; a port someone else moved is left where it is. The change is in the running
configuration only (DENIS never saves it), so a switch restart returns the port to its saved VLAN.

### What is verified, and what is not (V4)

Everything in this section was exercised against the stand-in switch of the tests, with SNMPv2c and with SNMPv3
(plan, apply, expiry, release, drift, each refusal, a lost answer, a lost request, the re-read before the write, the one
action per port rule, tenants). **Nothing in it was tried on a real switch.** The unproven points, to be checked on a
real Catalyst 2960-X:

* **[verify]** `vmVlan` is writable with a read-write community or SNMPv3 write user on the 2960-X, the write needs the
  view to include `1.3.6.1.4.1.9.9.68.1.2.2.1.2`, and the new VLAN takes effect in the running configuration.
* **[verify]** `vmVlanType` reads static(1) on an access port; `vmVoiceVlanId` answers on the 2960-X and reads "none"
  (DENIS treats 4095 and 4096 and anything outside 1 to 4094 as none) without a voice VLAN.
* **[verify]** `dot1xPaeSystemAuthControl` and `dot1xAuthAuthControlledPortControl` answer on the 2960-X, and a MAB or 802.1X
  port reads *auto*. (On IOS, MAB needs `dot1x system-auth-control`.) If they do not answer, a quarantine on a Cisco
  switch is refused: that is the safe outcome, not a fault.
* **[verify]** `vtpVlanState` for management domain 1 tells operational(1) for an existing VLAN (a VTP transparent switch
  too).
* **[verify]** `dot1qPvid` is writable on a switch that is not Cisco, and changing it alone moves the port; some switches
  need the egress membership too. This is the least certain row: try your own switch before you tick *tested*.
* **[verify]** the write works in SNMPv3 in the default context, and a write view that covers the VLAN object.
* The bounce is not tried on a real device either (does the link drop long enough, does a DHCP client renew).

## Caveats

See [Switches](../switches.md#disabling-a-port) — this connector has the most thorough safety model (re-poll before plan, blast
radius, uplink/LAG refusals, drift detection) because it was built first and is the one verified against a real
switch (D-Link DGS-1100-08V2).
