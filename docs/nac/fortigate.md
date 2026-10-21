# Enforcement: Fortinet FortiGate

Status: **Verified on FortiGate 40F, FortiOS 7.2.3: block device (address group), block a flow, and their release; not tested: quarantine, ending sessions.** Tested on that FortiGate: block device, release, expiry after 5 minutes, extending the time, a flow block with read-back and real traffic stopped, ending sessions (the call is accepted; closing an open session was not shown independently), and cleanup of everything DENIS made. Not yet tested on the device: the quarantine group, a lost answer or a reboot during an action, a concurrent edit by another administrator, a 24 hour hold, repeated block and release cycles, and other FortiOS versions or models. The two verified actions carry no *Experimental* mark and need neither lab setting (4.2); ending sessions stays *Experimental* until closing an open session has been shown, and so does the quarantine group.

Lab use: *Block device* (address group) and *Block a flow* are validated on real equipment and need no lab setting. The quarantine and ending sessions need both *Allow connectors that are not validated on real equipment (lab use)* and *Allow experimental actions (lab use)* under *Settings → Response policy*. Releasing an action and removing what DENIS made always work.

## Quick setup (about 10 minutes)

Tested on a FortiGate 40F with FortiOS 7.2.3 (block, release, expiry, extension, flow block and ending sessions). Other
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
   Then under *Settings → Response policy* tick *Allow administrators to block devices from DENIS*. Block device and flow
   block are validated and need no lab setting; for quarantine and ending sessions also tick *Allow connectors that are not
   validated on real equipment (lab use)* and *Allow experimental actions (lab use)*.
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

## Setup

1. **Block group.** In FortiOS create an address group for DENIS's blocks (*Policy & Objects → Addresses*) and a **deny policy** that uses it as source, at the top of the policy table. FortiOS does not keep an address group with no member, so put one placeholder address in the group (for example an address object for `192.0.2.255/32`, a documentation address that is never routed). DENIS refuses to use a group that has no member and says so.
2. **Quarantine group (optional).** Create a second address group, again with a placeholder member, and **your own policies** for it: allow what a quarantined device needs (DHCP, DNS, NTP, the remediation server) and deny the rest. DENIS never creates these. Enter the group's name in *Quarantine address group name*. Leave it empty to switch quarantine off.
3. **API user.** Create it as in the quick setup above (*System → Administrators → REST API Admin*, or the CLI commands there): an administrator profile with *System* read-write (needed for ending sessions on FortiOS 7.2.3), *Firewall* policy, address and service read-write, *Network* read, everything else *None*, and trusted hosts limited to the DENIS machine. Generate its token.
4. **VDOM.** If VDOMs are enabled, name the one that holds the groups; leave empty otherwise.
5. *Network → Equipment* → **+ Add a connector…** → **Fortinet FortiGate (address group)**: Base URL, VDOM, Block address group name, API token, *Never block these IP addresses* (DENIS itself, the gateway, the FortiGate), and optionally the Quarantine address group name.
6. **Flow blocks:** tick *Allow DENIS to create deny rules on this firewall* only if you accept that DENIS writes policies on this FortiGate. It is off by default, and DENIS will not create or delete any policy while it is off. A wrong deny rule can cut off traffic.

## How a flow block finds its interfaces

A FortiOS policy needs a source and a destination interface. DENIS never uses `any`: whether your FortiOS build accepts `any` there is not verified, so DENIS looks up the interface of each address instead. It first looks for the directly connected network (the most specific one) among the FortiGate's interfaces, then asks the routing table (`monitor/router/lookup`). If an interface is a member of a zone, the policy names the zone. If DENIS cannot tell, or both addresses are behind the same interface, it refuses and says why. A refusal is a normal answer, not an error.

## What is verified

**On a real FortiGate 40F (FortiOS 7.2.3):** block device with read-back, release, expiry after 5 minutes, extending the time, a flow block with read-back and real traffic stopped (a client to a public address on port 443), ending sessions (accepted with *System: Read/Write*), and cleanup that left nothing on the device. The first lab run also passed the protected-target refusals. **Not shown:** that ending sessions closed an open session (independent proof), the quarantine group, lost answers, reboot and concurrent-edit behaviour, a 24 hour hold and repeated cycles. Result: block device and the flow block validated per action (owner decision, 4.2); the quarantine group and ending sessions are not.

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

## Credentials

The API token is stored only in the encrypted secret store (`nac.fortigate.api_token`) and sent as `Authorization: Bearer <token>`. It is never written to the ledger, the audit log or a notification.

## Existing instances

Instances from earlier versions keep working and nothing changes for them: the same block group, the same address objects (`denis-block-<ip>`), the same ledger rows. The old *Block…* and *Unblock…* buttons act as before. Records the old routes made are released through the old *Unblock…*; records of the new actions are released through the new action list.
