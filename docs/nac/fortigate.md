# Enforcement: Fortinet FortiGate

Status: **Verified on FortiGate 40F, FortiOS 7.2.3: block device (address group), release, expiry, extend, block a flow, End sessions (an open SSH session was cut in 1-2 s) and quarantine through the quarantine address group (blocks web access; what a quarantined device may reach is decided by your own policies); not tested: IPv6, HA, VDOM mode.** Tested on that FortiGate (2026-10-15 to 2026-10-21): block device and its release (by hand in 3 s), expiry after 5 minutes, extending the time, a flow block with read-back and real traffic stopped (effect and release at once), End sessions (an active SSH channel was cut within 1 to 2 s), quarantine through the quarantine address group (the device was in the group at once, read back OK, web access was blocked, and after 5 minutes it was released automatically and traffic was back within 1 s), and cleanup of everything DENIS made. Not yet tested on the device: IPv6, HA, VDOM mode, a lost answer or a reboot during an action, a concurrent edit by another administrator, a 24 hour hold, repeated block and release cycles, and other FortiOS versions or models. All four actions carry no *Experimental* mark and need neither lab setting.

Lab use: none of the FortiGate actions (*Block device*, *Block a connection*, *Quarantine*, *End sessions*) needs a lab setting: all four are validated on real equipment. Releasing an action and removing what DENIS made always work.

## Quick setup (about 10 minutes)

Tested on a FortiGate 40F with FortiOS 7.2.3 (block, release, expiry, extension, flow block, ending sessions and quarantine). Other
FortiOS 7.x versions use the same REST API and are expected to work; they have not been tried.

**Before you start:**

* The FortiGate must be **in the path of the traffic** (see below), and its HTTPS management address must be reachable from
  the DENIS server (for example the `wan` or a management interface with `https` in *Administrative access*).
* You need a FortiOS administrator who can change the firewall configuration, and the DENIS server's IP address.
* Plan the first test: one harmless client behind the FortiGate and a free 5 minutes.

**What you need:** the FortiGate must be **in the path of the traffic** you want to stop (the device behind it, routed through
it). DENIS reaches the FortiGate's HTTPS management address from the DENIS server; the REST API alone cannot stop traffic that
does not pass the firewall.

1. **Objects and the deny policy** (once; DENIS never creates these). In the FortiGate CLI (*>_* in the web console), adapt the
   interface names `lan` and `wan`:
   ```
   config firewall address
       edit "denis-placeholder"
           set subnet 192.0.2.255 255.255.255.255
       next
   end
   config firewall addrgrp
       edit "DENIS-BLOCK"
           set member "denis-placeholder"
       next
   end
   config firewall policy
       edit 0
           set name "DENIS-BLOCK-deny"
           set srcintf "lan"
           set dstintf "wan"
           set srcaddr "DENIS-BLOCK"
           set dstaddr "all"
           set action deny
           set schedule "always"
           set service "ALL"
           set logtraffic all
       next
   end
   ```
   Move `DENIS-BLOCK-deny` to the **top** of the policy table (*Policy & Objects → Firewall Policy*, drag it, or
   `config firewall policy` then `move <id> before <first id>`).
2. **The API user** (least privilege, restricted to the DENIS server). Replace `<DENIS address>`:
   ```
   config system accprofile
       edit "denis-api"
           set sysgrp read-write
           set netgrp read
           set fwgrp custom
           config fwgrp-permission
               set policy read-write
               set address read-write
               set service read-write
           end
       next
   end
   config system api-user
       edit "denis"
           set accprofile "denis-api"
           config trusthost
               edit 1
                   set ipv4-trusthost <DENIS address> 255.255.255.255
               next
           end
       next
   end
   execute api-user generate-key denis
   ```
   The last command shows the **token once**: copy it straight into DENIS (step 3), do not paste it anywhere else. If you lose
   it, run the command again; the old token stops working.
   * **Why System read-write?** Ending sessions (the *End sessions* part of a block and the action of the same name) needs
     `System: Read/Write` on FortiOS 7.2.3; with *Read* only, FortiOS answers 401/403 to that call. **System read-write is a
     strong permission**: restrict the REST API administrator to the DENIS server with *Trusted Hosts* (done above) and keep the
     token private. All other permissions stay *None*; never use `super_admin`.
   * *Block device* and *Quarantine* need the *Firewall* address permission (read-write); *Block flow* adds policy and service
     (read-write); *Network* read is needed for the routing lookup of a flow block.
   * **Trusted hosts are not optional in practice.** Because the profile is broad, the REST API administrator should be
     usable from the DENIS server's address only (`trusthost` above). If DENIS reports 401 or 403 on every call, the address
     DENIS connects *from* is probably not the one you entered.
3. **In DENIS:** *Network → Equipment → + Add a connector…* → *Fortinet FortiGate (address group)*: **Base URL**
   `https://<FortiGate address>`, **VDOM (leave blank for global mode)** (empty if VDOMs are off), **Block address group name**
   `DENIS-BLOCK`, **API token**, **Quarantine address group name (optional)** (leave empty unless you built that group), and under
   **Never block these IP addresses** the FortiGate's own addresses, the gateway and DENIS. Keep **Verify TLS certificate**
   ticked and make the FortiGate's certificate trusted if you can (the default certificate is self-signed: untick it only in a
   lab). Press **Test connection**: it must succeed and writes nothing.
   Then under *Settings → Response policy* tick *Allow administrators to block devices from DENIS*. All four actions
   (block device, flow block, quarantine, ending sessions) are validated and need no lab setting.
4. **Try it on a harmless device:** *Respond → Block device* for a test client behind the FortiGate for 5 minutes. The client must
   lose its connection, then regain it at the end (DENIS removes everything it created). Tick *Allow DENIS to create deny rules*
   only if you want *Block flow*.

If something fails: HTTP 401/403 on ending sessions means *System* is not read-write or the Trusted Host does not include the
DENIS server; "no effect" with an accepted block means the deny policy is not first or the traffic does not pass this
FortiGate (check the interfaces, NAT and the policy order); a block that is refused with "the group has no member" means
the placeholder is missing from `DENIS-BLOCK` (FortiOS does not keep an empty address group).

### What happens on the FortiGate, in order

* **Block device** for a duration: DENIS creates one address object for the device (`denis-<tag>-<id>`, with the DENIS
  marker in its comment), adds it to `DENIS-BLOCK`, ends the device's open sessions, and reads the group back. The deny
  policy you made then drops the traffic. **Release** (or the end of the time) removes the object from the group and deletes
  it, and reads the group back. Nothing else on the FortiGate is touched.
* **Extend** sets the new end **from now**, not on top of the old end; it needs your password. The expiry job waits about 30
  seconds past the end, then releases.
* **Block flow** (needs *Allow DENIS to create deny rules on this firewall*) creates a deny policy `denis-<tag>-<id>` for one
  source, destination, protocol and port at the top of the table, reads the table back to check its position, and removes it
  at the end. A flow entered without protocol and port is blocked for **all** protocols and ports between the two addresses;
  the plan says so.
* **Persistence:** REST API changes are written to the FortiGate's configuration immediately; DENIS removes what it made at
  the end. An object that someone removed in the meantime is recorded as removed elsewhere (use **Check now**).

### Known behaviour to expect

* **Ending sessions** is accepted by the FortiGate with *System: Read/Write*; it is not undone and the device can reconnect at
  once. A new deny policy or a new group member may not cut sessions that are already open, depending on the global
  `firewall-session-dirty` setting (default `check-all`, which does); DENIS does not change it.
* One change at a time on one FortiGate: a second action waits up to two minutes and is then refused with nothing changed.

## What DENIS can do on a FortiGate

| Action | What DENIS writes | What it does not do |
|---|---|---|
| **Block device** (address group) | One address object for the device, added to the address group you created for blocks. Ends the device's open sessions. | It never creates or edits the deny policy that uses the group. |
| **Quarantine** (quarantine group) | The same, into a second address group you created for quarantine. | It never creates an allow rule, and never edits your policies. What a quarantined device may reach is decided by your own policies for that group (DHCP, DNS, NTP, a remediation server). DENIS does not check them. |
| **Block flow** (deny rule) | One deny policy `denis-<tag>-<id>` for exactly one source, destination, protocol and port, placed at the top of the policy table, plus single host address objects (and one custom service when a port is given) named from it. | Only with the per-instance switch *Allow DENIS to create deny rules on this firewall*. Deny only: no code path builds an allow, accept or permit rule. Never `any` for an interface or an address, never a network or a name. |
| **End sessions** (session clear) | `firewall/session/close-multiple` for the device's address, once as source and once as destination: at most two calls, never a call without a filter. | It cannot be undone. The device can open new sessions at once. IPv4 only. |
| Disable port | Not available: a firewall has no access port DENIS can switch off. | |

Every object DENIS makes carries `DENIS managed; owner <tag>; action <id>; by <login>; expires <time or never>` in its comment. Text you typed as a reason is never sent to the FortiGate. DENIS deletes only objects that carry its own owner tag. An object with a DENIS-style name that does not carry the tag is never touched, and the action is refused.

## Block domain (4.5, Experimental)

Evidence labels for this section: **documented** (in the vendor's published pages), **best guess** (from the product or other people's code, not checked in a published page), **verified** (tried on real equipment, with the date). **Nothing in this section is verified**; it was built and tried against DENIS's simulated device only, so the action is Experimental and needs both lab switches.

**What DENIS writes** (method `fqdn_group`): an address object `denis-<tag>-<id>` of type `fqdn` with the name (documented: FortiOS firewall address type "FQDN"), and with *and below* a second object `denis-<tag>-<id>-w` of type `wildcard-fqdn` with `*.name` (documented: the wildcard FQDN type; best guess that a wildcard object does not match the bare name, so both are made). Both are added to the **domain block address group** you create yourself and name in the connector's settings (*Domain block address group*). Release removes them from the group and deletes the objects. Every object carries `DENIS managed; owner <tag>; ...` in its comment; an object with the same name that does not carry it is never touched and the action is refused.

**What you set up first:** the group (with one placeholder member, FortiOS keeps no empty group) and a **deny policy of your own that uses the group as the destination**, above your allow policies. A block "does nothing" if that policy is missing or below an allow: that is outside DENIS, as for the other groups. The group must differ from the block group and the quarantine group (they are used as the source).

**The addresses the name resolves to.** FortiOS turns an FQDN object into the addresses the name resolves to, and the deny policy then blocks those addresses for everything behind the firewall. The plan resolves the name now and **refuses** the block when any answer is an address DENIS never blocks (private, internal or special, a protected address or network, the address of DENIS, of the administrator's session or of the firewall, or a DNS resolver), listing the addresses. **Warning:** the addresses can change after the block is applied, and FortiOS follows the name, not DENIS's check: a name that later resolves to an internal address would block that address. Use the name block only for names you expect to stay on public addresses, and release it when that changes.

**What it does:** all devices behind this FortiGate are stopped from reaching the name, not only the device that visited it. The plan says so.

**What it does not do:** FortiOS resolves the name itself, so a device that resolves it elsewhere (DoH/DoT) or connects by address may get through (best guess). It ends no open sessions. IPv4 and IPv6 resolution is FortiOS's own (not tried). A web address with a path is not offered here (no URL object).

**What we tried:** the fake FortiGate in DENIS's tests: create/reuse the objects, add to the group, read back, release, expiry, a foreign object under the name (refused), the last member (refused), orphan removal, a missing group and an empty group (refused). Nothing on a real FortiGate.

## Setup

1. **Block group.** In FortiOS create an address group for DENIS's blocks (*Policy & Objects → Addresses*) and a **deny policy** that uses it as source, at the top of the policy table. FortiOS does not keep an address group with no member, so put one placeholder address in the group (for example an address object for `192.0.2.255/32`, a documentation address that is never routed). DENIS refuses to use a group that has no member and says so.
2. **Quarantine group (optional).** Create a second address group, again with a placeholder member, and **your own policies** for it: allow what a quarantined device needs (DHCP, DNS, NTP, the remediation server) and deny the rest. DENIS never creates these. Enter the group's name in *Quarantine address group name*. Leave it empty to switch quarantine off.
3. **API user.** Create it as in the quick setup above (*System → Administrators → REST API Admin*, or the CLI commands there): an administrator profile with *System* read-write (needed for ending sessions on FortiOS 7.2.3), *Firewall* policy, address and service read-write, *Network* read, everything else *None*, and trusted hosts limited to the DENIS machine. Generate its token.
4. **VDOM.** If VDOMs are enabled, name the one that holds the groups; leave empty otherwise.
5. *Network → Equipment* → **+ Add a connector…** → **Fortinet FortiGate (address group)**: Base URL, VDOM, Block address group name, API token, *Never block these IP addresses* (DENIS itself, the gateway, the FortiGate), and optionally the Quarantine address group name.
6. **Flow blocks:** tick *Allow DENIS to create deny rules on this firewall* only if you accept that DENIS writes policies on this FortiGate. It is off by default, and DENIS will not create or delete any policy while it is off. A wrong deny rule can cut off traffic.

## Quarantine policies example

DENIS only moves a device into the quarantine address group; the policies for that group are yours. This is what worked on
the FortiGate 40F (adapt the interface names `lan` and `wan` and the member address; the member is a placeholder that keeps
the group non-empty, the same as for the block group):

```
config firewall address
    edit "denis-q-placeholder"
        set subnet 192.0.2.254 255.255.255.255
    next
end
config firewall addrgrp
    edit "DENIS-QUARANTINE"
        set member "denis-q-placeholder"
    next
end
config firewall policy
    edit 0
        set name "DENIS-Q-allow"
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "DENIS-QUARANTINE"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "DNS" "NTP" "PING"
        set nat enable
    next
    edit 0
        set name "DENIS-Q-deny"
        set srcintf "lan"
        set dstintf "any"
        set srcaddr "DENIS-QUARANTINE"
        set dstaddr "all"
        set action deny
        set schedule "always"
        set service "ALL"
    next
end
```

Both policies must sit **above** your normal allow policies (use *move* in the CLI or drag them in *Policy & Objects →
Firewall Policy*), with `DENIS-Q-allow` first and `DENIS-Q-deny` right after it. If the DNS server is on another network
that the quarantined device reaches through the FortiGate (for example a lab server), it may need its own allow policy
without NAT. Enter `DENIS-QUARANTINE` as *Quarantine address group name*.

## How a flow block finds its interfaces

A FortiOS policy needs a source and a destination interface. DENIS never uses `any`: whether your FortiOS build accepts `any` there is not verified, so DENIS looks up the interface of each address instead. It first looks for the directly connected network (the most specific one) among the FortiGate's interfaces, then asks the routing table (`monitor/router/lookup`). If an interface is a member of a zone, the policy names the zone. If DENIS cannot tell, or both addresses are behind the same interface, it refuses and says why. A refusal is a normal answer, not an error.

## What is verified

**On a real FortiGate 40F (FortiOS 7.2.3):** block device with read-back, release (by hand in 3 s), expiry after 5 minutes, extending the time, a flow block with read-back and real traffic stopped (a client to a public address on port 443; effect and release at once), ending sessions (accepted with *System: Read/Write*; an active SSH channel was cut within 1 to 2 s), quarantine through the quarantine address group (in at once and read back, web access blocked, released automatically after 5 minutes with traffic back within 1 s), and cleanup that left nothing on the device. The first lab run also passed the protected-target refusals. **Not shown:** IPv6, HA, VDOM mode, lost answers, reboot and concurrent-edit behaviour, a 24 hour hold and repeated cycles. Result: all four actions validated per action (owner decision, 4.2 and 2026-10-21).

**In DENIS's own tests, against a simulated FortiGate:** creating, finding by name, moving and deleting the policy, address objects and service; the quarantine move and restore; ending sessions; lost answers (the action is *unconfirmed* and can still be released); a refused step after earlier steps (compensated, nothing left behind, or *partial* and still releasable); the opt-in and lab-switch refusals; orphans found by owner tag and removed only when they carry it.

Behaviours that are unproven vendor facts (marked **[verify]** in the code):

* `PUT cmdb/firewall/policy/<id>?action=move&before=<id>` places a policy at the top, and a new policy gets the next free id. DENIS checks the position after the move and removes the policy if it did not land at the top.
* `GET monitor/router/lookup?destination=<ip>` answers with the interface in `results.interface`.
* Zone members are listed in `cmdb/system/zone` as `interface[].interface-name`, and a zone member must be referenced through its zone.
* The predefined services `ALL`, `ALL_TCP`, `ALL_UDP` and `ALL_ICMP` exist.
* FortiOS does not keep an address group with no member (so a placeholder is needed). DENIS does not remove its own entry if it is the only member and tells you to add a placeholder.
* `firewall/session/close-multiple` with the query parameters `saddr` or `daddr` closes the sessions of that address.
* Whether sessions that are already open are cut by a new deny policy depends on the global setting `firewall-session-dirty` (default `check-all`). DENIS does not change it.
* FortiOS matches the original source address (before source NAT). A destination behind a virtual IP is matched by the virtual IP.
* The policy `comments` and address `comment` fields accept the 255 character marker.

**What End sessions reports.** DENIS says what FortiOS answered, and only that:

* **Completed** means FortiOS *accepted* the request (`status: success`) for at least one direction and refused
  neither (the other direction may have had nothing to close). It is not an independent check that every open
  session ended; DENIS does not read the session table afterwards.
* **Completed, nothing open**: FortiOS answered for both directions that no session matched (only an answer that says so
  is read this way). Nothing was closed because nothing was open; the message says so, and since 4.2 it does not count
  toward the hourly limit (before 4.2 it was reported as failed and counted).
* **Failed** with "HTTP 401 or 403": the API token is wrong or expired, the Trusted Host does not include the DENIS
  server, or the administrator profile lacks *System* read-write. "HTTP 424": the session filter was missing or not
  accepted. Nothing was closed in either case.
* **Unconfirmed** when FortiOS accepted one direction but not the other (the message names both), or gave no usable
  answer (no connection, a timeout, an unexplained server error, or a success code without a confirmation): sessions
  may or may not have been closed. Check on the FortiGate (*Dashboard → FortiView Sessions*, or
  `diagnose sys session filter src <ip>` and `diagnose sys session list`).

The same request is sent when a *Block device* is applied; there, its answer is recorded as a note in the action's
steps and never changes the result of the block itself.

## Limits

* IPv4 only. FortiOS keeps IPv6 objects on separate endpoints that DENIS does not use.
* Traffic between two devices in the same subnet does not pass the firewall, and no rule on it stops it.
* Policy placement is the top of the table only. No other anchor is offered.
* A deny policy for a flow in both directions is two policies (`denis-<tag>-<id>` and `denis-<tag>-<id>-r`).
* One change at a time on one FortiGate (4.1.2): a block, a release or an orphan removal holds the firewall for its
  whole run; another one waits up to two minutes and is then refused with nothing changed. Ending sessions does not
  hold it.

## Where is it plugged in (4.4)

With **Read what this firewall manages (read only)** ticked (it is ticked for a new connector; a connector made before 4.4 stays off until you tick it), DENIS reads which FortiAP and FortiSwitch units this FortiGate manages and the Wi-Fi clients on its FortiAPs. The map then draws a managed unit under the FortiGate, with the interface the FortiGate names, instead of leaving it floating, and a Wi-Fi client's device page says which FortiAP it is on, the SSID and the signal. DENIS only sends `GET` requests, with the same API token, address, VDOM and certificate setting as the rest of this connector. A read-only administrator profile (read access to Wireless, Switch controller and System) is enough. Every statement about FortiOS below carries a label:

* `documented` (checked 2026-11-02): the switch configuration object `GET /api/v2/cmdb/switch-controller/managed-switch` and its fields `switch-id`, `name`, `sn` and `fsw-wan1-peer` (the FortiGate interface the switch is attached through), and the answer envelope with `results`. Fortinet's own answer reference for the monitor calls sits behind a Fortinet developer login that was not available.
* `best guess` (from field reports, **not checked**): the monitor calls `GET /api/v2/monitor/wifi/managed_ap` (`wtp_id`, `name`, `connecting_from`, `connecting_interface`, `mesh_uplink`), `GET /api/v2/monitor/switch-controller/managed-switch/status` (`serial`, `name`, `connecting_from`, `fgt_peer_port_name`, `peer_device_name`, `peer_port_name`) and `GET /api/v2/monitor/wifi/client` (`mac`, `ip`, `ssid`, `wtp_id`, `wtp_name`, `signal`, `vlan`), and that a FortiAP's interface is named by `connecting_interface`.
* `verified`: nothing yet. No FortiGate has answered these calls for DENIS.

What the map shows, and what it does not:

* A unit is drawn under the FortiGate only when the answer names an interface for it. A FortiSwitch whose answer names another managed switch as its peer is drawn under that switch, with the peer's port. A FortiAP that says it is on a mesh link is not drawn under anything (its parent access point is not named).
* The answer names the interface a unit connects through, not the cable behind it: a FortiAP plugged into a FortiSwitch is still drawn under the FortiGate until DENIS learns the port from the switch itself: when that FortiSwitch is also one of the switches DENIS reads over SNMP, the port is filled in by the [port join](../switches.md#port-join-the-port-of-an-access-point-or-switch-a-controller-did-not-name) (the line then says *port learned from ... by LLDP* or *by the MAC table*); otherwise the line says *reported by the controller*.
* Wired clients behind a FortiSwitch are not read in this version. If one of the three lists is not answered, what was answered is shown and the read counts as partial.
* The FortiGate's own hardware address is not known, so it is the connector's box on the map that the units hang under.

## Credentials

The API token is stored only in the encrypted secret store (`nac.fortigate.api_token`) and sent as `Authorization: Bearer <token>`. It is never written to the ledger, the audit log or a notification.

## Existing instances

Instances from earlier versions keep working and nothing changes for them: the same block group, the same address objects (`denis-block-<ip>`), the same ledger rows. The old *Block…* and *Unblock…* buttons act as before. Records the old routes made are released through the old *Unblock…*; records of the new actions are released through the new action list.

## Details from the console

The console shows a short line under each field and a short note behind its (i). The full explanation of each field is here.

- **Quarantine address group name (optional)**: The address group you created for quarantine. DENIS moves a device into it and back, and nothing else: what the group may reach is decided by your own policies on the FortiGate. DENIS never creates an allow rule. Leave empty to switch quarantine off for this FortiGate.
- **Allow DENIS to create deny rules on this firewall**: Off by default. When on, DENIS can create one deny policy per flow block on this FortiGate, at the top of the policy table, named denis-... and tagged DENIS managed, and delete it again when the action ends. It never creates an allow rule and never uses any interface or any address. A wrong deny rule can cut off traffic: switch this on only if you accept that.

## 4.5.0: checks and releases

* **The VDOM is recorded** in the action's record (`vdom`); its release and read-back go to that VDOM even after the
  connector's VDOM setting changed. An action made before 4.5.0 uses today's setting, as before.
* **A deny policy someone moved** below an allow policy, disabled or edited keeps the action active with a notice
  ("DENIS's policy ... is still on the FortiGate, but no longer on top ..."); the release removes it. Only a policy that
  is gone closes the action.
* A flow release that cannot delete or read its service or address objects lists them as left behind at once.
