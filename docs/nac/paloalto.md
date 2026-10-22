# Enforcement: Palo Alto Networks PAN-OS

Status: **Verified on Palo Alto PA-220, PAN-OS 10.1.14-h9: block device through the dynamic group, release, automatic expiry, extend, End sessions, quarantine through the dynamic group (in and out in about 10 s), the tag surviving a firewall restart with an active block, block a flow through the static rule and a commit (slow: minutes); not tested: re-registering a lost tag on the hardware, HA, IPv6, the static address group block and the static quarantine group.** A block through the dynamic group counts as in force only when the group on the firewall lists the address (`show object dynamic-address-group`); DENIS waits for that for up to 20 seconds in all, ends the open sessions after it, and shows the action as not confirmed if the group never lists the address (the tag stays). A firewall that refuses this read is not asked again: the action is not confirmed, with the text "DENIS could not read the group membership from this firewall", and the hourly check leaves only the rows of that group as they are. The XML API answer of this read was captured on the PA-220 (empty without a block, the blocked address listed during one) and DENIS's tests use those answers; the block with the 4.2.1 wait has not yet been run end to end on the hardware. End sessions was tested: an open SSH session was dropped and DENIS reported Done in 3 seconds. Measured on the bench (2026-10-20): *Test connection* found the dynamic group's match, the deny rule first and the User-ID API allowed; *Block device* through the dynamic group took effect within 10 seconds (an API tag, no commit) and its release took 8 seconds; *Block a flow* through the static deny rule with a commit worked, and its early release took about 2.5 minutes (the commit). The verified actions carry no *Experimental* mark and need neither lab setting (4.2). Everything else below was built from PAN-OS's published XML API documentation and checked against a simulated firewall in DENIS's own tests, and stays *Experimental*. The answers of the User-ID API that the simulated firewall gives were taken from the same PA-220. The menu names below may differ slightly between PAN-OS versions; your first test, as described, will show it.

Lab use: *Block device* through the dynamic address group and *Block a flow* are validated on real equipment and need no lab setting. The host block through the static address group is allowed only while an administrator has switched on *Allow connectors that are not validated on real equipment (lab use)* under *Settings → Response policy*. The other actions (quarantine through the static group) additionally need *Allow experimental actions (lab use)*. Releasing an action and removing what DENIS made always work.

## Quick setup without commits (recommended, 4.2)

DENIS blocks a device by registering **its own tag** for the device's address through the PAN-OS **User-ID XML API**
(`type=user-id`). A **dynamic address group** that you create once, whose only match is that tag, picks the address up at
once, and **your deny rule** that uses the group does the blocking. Nothing goes into the candidate configuration, so there
is **no commit** for a block or a release: the time to block is seconds, not the minutes a commit takes on a PA-220. This is
the default method for *Block device* and *Quarantine* wherever it is set up; the static address group (below) stays as the
fallback you choose explicitly.

**DENIS's tags are its own.** Each DENIS installation uses `denis-blocked-<id>` and `denis-quarantine-<id>`, where `<id>` is
the installation's six-character owner tag; the connector form fills the names in when you save, and *Test connection*
shows them. DENIS keeps in each action's record exactly which address and tag it registered, reads the firewall's list of
registered addresses before every register and every removal, and **never registers or removes a tag it has no record of**:
if an address already carries DENIS's tag without a DENIS action, the block is refused with the command to look at it on the
firewall, and DENIS never takes it over.

1. *Objects → Tags → Add*: `denis-blocked-<id>` (and `denis-quarantine-<id>` if you use quarantine). Use the exact names the
   DENIS connector form shows after you saved it once (step 7). Whether the dynamic group needs the tag object or accepts a
   typed name has not been checked yet; the tag object costs nothing and makes it selectable.
2. *Objects → Address Groups → Add*: name `DENIS-DYN-BLOCK`, *Type* **Dynamic**, *Add Match Criteria* `denis-blocked-<id>`:
   the match reads `'denis-blocked-<id>'`, and nothing else is in it. DENIS refuses a group whose match is anything more
   (for example `'denis-blocked-<id>' or 'x'`), because then its deny rule would block other addresses too.
3. *Policies → Security → Add*, then move it **to the top**: `DENIS-DYN-BLOCK-deny`, source zone your inside zone (or any),
   source address `DENIS-DYN-BLOCK`, destination any, application any, service any, action **Drop**, log at session end.
   Optionally a second rule with `DENIS-DYN-BLOCK` as the destination. DENIS checks before every block, and every minute
   while a block is active, that an enabled deny rule drops **everything** from the group and that **no enabled allow rule
   stands above it**. Only a rule with the group as a source counts, with destination, application and service `any`,
   source and destination zone `any`, no negated source or destination, no schedule, and no source user, URL category or
   HIP profile other than `any`: a rule that drops only some traffic (one zone, `application-default`, one application,
   nights only) or only traffic *to* the group does not prove the block, and DENIS refuses with "No enabled deny rule
   uses ...".
4. Quarantine (optional): a dynamic group `DENIS-DYN-QUARANTINE` with the match `'denis-quarantine-<id>'`, and **your own**
   rules for it (allow DHCP, DNS, NTP and the remediation server above a deny for the rest). DENIS never creates an allow
   rule; it checks only that an enabled rule uses the group.
5. *Device → Admin Roles → Add* `denis-api-dag`: XML API **User-ID Agent** (register and remove tags), **Operational
   Requests** (the list of registered addresses, ending sessions, the firewall's model and uptime) and **Configuration**
   (DENIS reads the group and the security rules; it writes no configuration for these methods). Add **Commit** only if you
   also use the static group or flow blocks. Web UI and REST API off, Command Line None. *Device → Administrators*: the DENIS
   account with that role. Whether *User-ID Agent* alone is enough for the tag writes has not been checked yet.
6. **Commit once.** This is the only commit the method needs.
7. In DENIS (*Network → Equipment → + Add a connector… → Palo Alto Networks PAN-OS*): **Block dynamic address group name**
   `DENIS-DYN-BLOCK`; leave **Block tag** empty and save: DENIS fills in `denis-blocked-<id>`. Use that name in steps 1 and 2.
   Optionally the quarantine pair. The static **Block address group name** is optional now. Press **Test connection**: it
   must say that the dynamic group was found with the right match, that the deny rule is first, and that the User-ID API is
   allowed. To prove the last one it registers DENIS's own probe tag `denis-probe-<id>` for `192.0.2.255` (a documentation
   address that is never routed, matched by no group) and removes it again; nothing else is written.
8. CLI check afterwards: `show object registered-ip all` lists nothing of DENIS. After a block it lists the address with
   `denis-blocked-<id>`, and `debug object registered-ip show tag-source ip <address> tag all` shows the XML API as the source.

CLI equivalent of steps 2 and 3 (configure mode; check the syntax on your version):
```
set tag denis-blocked-<id>
set address-group DENIS-DYN-BLOCK dynamic filter "'denis-blocked-<id>'"
set rulebase security rules DENIS-DYN-BLOCK-deny from any to any source DENIS-DYN-BLOCK destination any application any service any action drop log-end yes
move rulebase security rules DENIS-DYN-BLOCK-deny top
commit
```

**What a block through the dynamic group does.** DENIS reads the setup and the address's tags, registers its tag for the
address (one call, no commit), waits until the dynamic group lists the address (`show object dynamic-address-group`,
every second for up to 20 seconds) and only then ends the device's open sessions (`clear session`), because a change of
a dynamic group may not end sessions that are already open, and a session opened before the group has the address would
stay allowed. The action counts as *enforced* only when DENIS has read the tag back from the firewall, the group lists
the address and the setup still holds. If the group does not list the address in time, the action is *unconfirmed* (the
tag stays, the sessions are ended once, and the next check confirms it when the group has caught up). A release removes exactly the tags of the action's record that the firewall
still lists, then reads back. A lost answer leaves the action *unconfirmed*; **Check now** or a release settles it (both
calls can be repeated safely). A release, a check and a re-registration read and write in the vsys the block was made in
(its record says which), and every read of the registered addresses names that vsys.

**Restarts.** Tags registered through the User-ID API are runtime data, not configuration. On one PA-220 with PAN-OS
10.1.14-h9 a registered tag was still there after a commit and after a full restart; other models and versions, an HA
failover and a dataplane restart are not tested. DENIS therefore checks the firewall regularly and after every restart it
sees. If a block's tag is missing, DENIS shows the action as unconfirmed and registers the tag again when your settings
allow it.

**Limits.** The registered addresses of a firewall are shared by every source (VM monitoring, Panorama, other
integrations). A PA-220 and a PA-820 hold 1,000, a PA-850 2,500, a PA-3200 200,000 (Palo Alto's figures). DENIS refuses a
new block when the firewall is at 95 percent of its model's limit, and when DENIS itself already holds *At most this many
registered addresses* (default 200). Both are checked at the plan and again right before the register, while DENIS holds
the firewall's tag lock, and DENIS's share is also counted in the same database transaction that records the action, so
two blocks applied at the same moment cannot pass the limits together. Every DENIS connector of the same firewall address
and vsys counts as one: their blocks are DENIS's to each other, never foreign, never orphans. IPv4 only. A flow block (one source, one destination, one port) still needs a rule and
a commit: a dynamic group is a set of addresses and cannot express a single flow. **Block a flow, and every method that
commits (the static block and quarantine groups), says on its Respond menu row and in the plan dialog that it needs a
commit and takes minutes on a PA-220, and points to *Block device* with the dynamic group (no commit, seconds) for fast
containment (4.2).**

**Residual risk.** A tag is a name: anyone with the API can register or remove `denis-blocked-<id>`. DENIS notices it on its
next check and never removes a tag it did not register. When DENIS finds its lost tag there again from someone else, the
action says so: it stays *unconfirmed*, is never confirmed by that tag, and its release removes nothing. A registration is
offered as DENIS's leftover (an orphan) only when an ended action's register went through and no release of that action
removed the tag afterwards; a tag that appears after DENIS's own release, or for an action that failed, is not DENIS's.
Two connectors of one HA pair under different addresses are not recognised as one firewall.

**The default method.** When the dynamic group is set, *Block device* and *Quarantine* preselect it in the Respond menu,
Autopilot and Protect Me use it, and `denis nac selftest` tests it. The static group is offered second, labelled "(commit,
can take minutes)", and is used automatically only on an instance that has no dynamic group. It is never a silent fallback:
a failed block through the dynamic group is reported, and you choose the static path yourself. A release always uses the
method the action was made with.

**DENIS checks every minute (and after a restart).** An active action in DENIS's database is not proof of a block. Every
minute, and at once when the firewall's uptime shows a restart, DENIS reads the firewall's registered addresses for its
tags and checks the setup of the group again. All there: the action shows when it was last verified. A tag missing, or the
group or its deny rule changed: the action is shown as *unconfirmed* at once, written to the audit log and notified. With
*Register a tag again when the firewall lost it* (on by default) DENIS then registers a missing tag again, at most three
times per action per hour, only while every safety check of a new block still allows the device (kill switch, lab
switches, protected addresses, Hands off), and only a read-back that shows the tag makes the action enforced again. A
changed setup is never "repaired" by DENIS: fix the group or the rule, and the next check confirms the action. When the
firewall cannot be read (also its security rules, for example without the Configuration permission), or DENIS cannot use
the connector (a deleted connector, an address the outbound policy refuses, no API key), nothing changes and the action
shows that DENIS could not verify, with the time of its last proof. Right before a re-registration DENIS reads the action
again: one released, expired or changed meanwhile is not registered again. An unchanged result is written to the action at
most every ten minutes, and a skipped re-registration is written to the audit log when its reason is new, at most hourly
otherwise.

**Measuring the real time to block.** The time that counts is from the click on *Apply* until the device's traffic stops,
not the API's answer. DENIS records the moment the apply request arrived as the action's first step ("apply received", in
server milliseconds). Run `denis nac probe-listen --listen 0.0.0.0:8099 --log probe.tsv` on the DENIS server while the test
client calls `http://<denis>:8099/probe?seq=<n>` a few times a second (`tools/nac-hwtest-probe.sh --interval 0.2`, or a
`curl.exe` loop on Windows): each line of `probe.tsv` is `server_ms`, the source address and the sequence number, on the
same clock. The time to block is the last probe request minus "apply received"; the time to flow after a release is the
first probe request after the release's start. `denis nac selftest` measures the same from the start of its own apply
(`--method address_group` runs the static path on the same instance for comparison).

## Quick setup with the static address group (fallback, about 20 minutes, plus the commits)

**What must be in the traffic path.** The firewall must **route or switch the traffic you want to stop** (the device sits
behind one of its interfaces and talks through it). The XML API cannot stop traffic that does not pass the firewall, and
two devices in the same subnet on one side of it never meet it. DENIS reaches the firewall's management address over HTTPS
from the DENIS server.

**Two things to know first.** Every change goes into the *candidate* configuration and counts only after a **commit**, which
takes seconds to several minutes on a PA-220; a block therefore takes noticeably longer than on other devices. And a normal
commit publishes *everybody's* pending changes, so DENIS commits only the changes of its own administrator account (the
*commit scope*, step 3).

1. **Hand-made objects and the deny rule** (once; DENIS never creates these). In the web interface:
   * *Objects → Addresses*: `denis-placeholder`, type IP Netmask, `192.0.2.255/32` (a documentation address that is never
     routed). A static group needs at least one member.
   * *Objects → Address Groups*: `DENIS-BLOCK`, type **Static**, member `denis-placeholder`. DENIS refuses a dynamic group
     or a group with no static member.
   * *Policies → Security*, at the **top**: `DENIS-BLOCK-deny`, source zone your inside zone, source address `DENIS-BLOCK`,
     destination zone any, destination address any, application any, service any, action **Drop** (or Deny), log at session
     end. Below your own rules that allow traffic this rule would do nothing, so it must be first.
   * Commit.
2. **The API account.** *Device → Admin Roles → Add* `denis-api-role`: in *XML API* enable **Configuration**, **Operational
   Requests** and **Commit**; leave **Commit for other admins**, Report, Log, Import and Export off; *Web UI* all off; *Command
   Line* None; *REST API* all off. *Device → Administrators → Add* `denis-api`: *Role Based*, profile `denis-api-role`, a long
   random password. In *Device → Setup → Interfaces → Management* (or the interface you use) add the DENIS server to
   *Permitted IP Addresses*; the list applies to every administrator, so keep your own addresses in it. Commit.
3. **The API key.** Create it with a POST, so the password is not in a URL or in your shell history:
   ```
   read -rs PW
   curl -sk -X POST 'https://<firewall address>/api/?type=keygen' \
        --data-urlencode 'user=denis-api' --data-urlencode "password=$PW"
   unset PW
   ```
   The answer carries `<key>...</key>`. Paste it straight into DENIS (step 4); do not keep it anywhere else. DENIS sends it in
   the `X-PAN-KEY` header and uses the XML API only. (`-k` skips certificate checking for this one call; use the firewall's
   certificate if you have one.)
4. **In DENIS:** *Network → Equipment → + Add a connector…* → *Palo Alto Networks PAN-OS*: **Base URL**
   `https://<firewall address>`, **vsys** (`vsys1` unless you use another), **Block address group name** `DENIS-BLOCK`, **API
   key**, **Never block these IP addresses** (the firewall's own addresses, the gateway and DENIS), **Scope commits to this
   administrator only (optional)** `denis-api` (always set it; a flow block refuses to run without it), **Quarantine address
   group name (optional)** (empty unless you built that group), and **Verify TLS certificate** (make the certificate
   trusted; untick it only in a lab). Press **Test connection**: it reads and writes nothing, and *Commit → Preview Changes*
   must stay empty.
5. **Settings → Response policy:** tick *Allow administrators to block devices from DENIS*. The block through the static
   address group (this step's first test) also needs *Allow connectors that are not validated on real equipment (lab use)*;
   quarantine through the static group additionally needs *Allow experimental actions (lab use)*. The flow block, ending
   sessions, the quarantine through the dynamic group and the block through the dynamic group are validated and need
   neither.
6. **First test, on a harmless device:** *Respond → Block device* for **5 minutes** on a test client behind the firewall.
   Expect a wait of up to a few minutes while the commit job runs (DENIS shows how long it took in the action's steps; *Monitor →
   Tasks* shows the job). Then the client loses its connection, `DENIS-BLOCK` holds an object `denis-<tag>-<id>` whose
   description starts with `DENIS managed; owner`, and at the end of the time (or on **Release**) the object is removed,
   committed and read back. Afterwards *Commit → Preview Changes* must be empty.

**What each action does and how it is verified.** *Block device* and *Quarantine* add and remove one address object in the
group, each with a commit; the action counts as enforced only when DENIS has read the **running** configuration back and found
the change. *Block flow* writes one deny security rule at the top of the rulebase (and its address and service objects) with
a partial commit of `denis-api`. *End sessions* runs `clear session` for the address and changes no configuration. **Extend**
sets the new end from now, not added to the old end, and needs your password. A commit that is still running when DENIS stops
waiting leaves the action *unconfirmed*; **Check now** or a release settles it.

**If something fails**

* *A refusal that another administrator has changes waiting:* without the commit scope DENIS refuses a full commit that would
  publish someone else's work. Set the scope, or commit or revert the pending changes first.
* *Authentication or permission errors:* the API key belongs to the account in *Scope commits to this administrator only*; the
  role needs XML API Configuration, Operational Requests and Commit; the DENIS server must be in the permitted IP addresses.
* *"The group has no static member":* the placeholder is missing, or the group is dynamic.
* *The block is enforced in DENIS but traffic still flows:* `DENIS-BLOCK-deny` is not first in the rulebase, or a Panorama
  pre-rule allows the traffic (DENIS cannot see Panorama's rules), or "rematch all sessions on config policy change" is off
  so that open sessions continue until they end (use **End sessions**).
* *A stuck or failed commit:* *Monitor → Tasks* shows the job. DENIS withdraws its own candidate edits when a commit fails.

## What DENIS can do on PAN-OS

| Action | What DENIS writes | What it does not do |
|---|---|---|
| **Block device** (dynamic group, the default when set) | DENIS's tag `denis-blocked-<id>` for the device's address, through the User-ID API. No commit. Ends the device's open sessions. | It never creates or edits the dynamic group or the deny rule, never registers or removes another tag, and never takes over a tag that was there before. |
| **Quarantine** (quarantine dynamic group, the default when set) | DENIS's tag `denis-quarantine-<id>` for the device's address. No commit. | It never creates an allow rule. What a quarantined device may reach is decided by your own rules for that group. |
| **Block device** (address group) | One address object for the device, added to the static address group you created for blocks, then a commit. Ends the device's open sessions. | It never creates or edits the deny rule that uses the group. |
| **Quarantine** (quarantine group) | The same, into a second static address group you created for quarantine. | It never creates an allow rule, and never edits your rules. What a quarantined device may reach is decided by your own security rules for that group (DHCP, DNS, NTP, a remediation server). DENIS does not check them. |
| **Block flow** (deny rule) | One deny security rule `denis-<tag>-<id>` for exactly one source host, destination host, protocol and port, placed at the top of the security rulebase and checked there, plus single host address objects (and one service object when a protocol or port is given) named from it, then a commit. | Only with the per-instance switch *Allow DENIS to create deny rules on this firewall*, and only with the commit scoped to one administrator. Deny only: no code path builds an allow rule. Never a network, a name or an address other than the two hosts. |
| **End sessions** (session clear) | `clear session all filter source <ip>` and `... filter destination <ip>`: at most two calls, never a call without a filter. | It cannot be undone. The device can open new sessions at once. It changes no configuration and needs no commit. **Completed** when PAN-OS accepted at least one of the two calls (not an independent check that every session ended). **Failed** when it refused both: nothing was closed, and DENIS does not read a refusal as "no open session". **Unconfirmed** when no usable answer came back. |
| Disable port | Not available: a firewall has no access port DENIS can switch off. | |

Every object DENIS makes carries `DENIS managed; owner <tag>; action <id>; by <login>; expires <time or never>` in its description. Text you typed as a reason is never sent to the firewall. DENIS deletes only objects that carry its own owner tag. An object with a DENIS-style name that does not carry the tag is never touched, and the action is refused.

## The commit model, and why it matters here

A change made through the XML API lands in the *candidate* configuration and does nothing until a commit publishes it. A plain commit publishes **everything that is pending, including other administrators' unfinished edits.** DENIS therefore treats the commit as the most important part of every action:

* **Scope the commit.** Under *Scope commits to this administrator only* enter the PAN-OS account that DENIS's API key belongs to. Every commit DENIS makes is then a partial commit of that account's own changes. A flow block (it writes a rule) **refuses to run without it**.
* **Without the scope**, block device and quarantine still work, the plan says that a full commit publishes everything pending, and DENIS **refuses** when it can see that another administrator has changes waiting (`show config list changes`, **[verify]**). Your own earlier unfinished DENIS edits would show up the same way.
* **DENIS waits for the commit job** (up to three minutes, polling every two seconds, and never past ten minutes from the start of the action's run, whatever the firewall's answer times are) and records in the action's steps how long it took. A commit takes from seconds to several minutes on a real firewall.
* **A commit is never assumed.** The action is *enforced* only when DENIS has read the **running** configuration back and found the change in it. A commit that is still running when the wait ends, or whose answer was lost, leaves the action *unconfirmed* (the row stays active, and a later check or release settles it).
* **A commit the firewall refuses, or whose job finishes with anything but OK, publishes nothing.** DENIS then withdraws its own candidate objects, so nothing of it is left to be published by somebody else's commit. The action ends *failed*; if even the withdrawal is refused it ends *partial* and stays releasable.
* **One change at a time on one firewall (4.1.2).** A block, a release or an orphan removal holds the firewall for its whole run, commit included; another one waits up to two minutes and is then refused with nothing changed. So a commit never publishes another DENIS action's half-made edits. Ending sessions and reading do not hold it.
* **Half an action is never left in the candidate (4.1.2).** DENIS keeps a list of its own candidate edits while an action or a release runs. When a step is refused (a write, a delete of one of its objects, the commit) or an answer is lost before any commit was sent, it undoes exactly those edits, newest first: it deletes what it created and sets back what it deleted (a deleted rule goes back to the top). It never touches anything it did not change itself in that run. A commit whose outcome is unknown keeps the edits, because that commit job may still publish them; the action is then *unconfirmed* and the read-back of the running configuration decides.
* **Releasing** commits only when the running configuration still holds something of DENIS's (or when an earlier commit of the action ended without a usable answer, because that job may still land). A candidate edit that never reached the running configuration is simply deleted.

## Setup

1. **Block group.** In PAN-OS create a **static address group** for DENIS's blocks (*Objects → Address Groups*) and a **deny rule** that uses it as source (or destination), at the top of the Security Policy. A static group needs at least one member, so put one placeholder address in the group (for example an address object for `192.0.2.255/32`, a documentation address that is never routed). DENIS refuses to use a group that has no static member or that is a dynamic group, and says so. DENIS never creates or edits this rule.
2. **Quarantine group (optional).** Create a second static address group, again with a placeholder member, and **your own security rules** for it: allow what a quarantined device needs (DHCP, DNS, NTP, the remediation server) and deny the rest. DENIS never creates these. Enter the group's name in *Quarantine address group name*. Leave it empty to switch quarantine off.
3. **API account.** Create an administrator for DENIS (a role-based or custom admin role) and generate its **API key**. The role needs the XML API for *Configuration* (read and write the objects and, for flow blocks, the security rulebase), *Commit* (and *Commit for other admins* is **not** needed), and *Operational Requests* (job status, clear sessions, `show config list changes`). Restrict the account's management access to the DENIS machine.
4. **vsys.** Name the vsys that holds the groups (PAN-OS always has at least `vsys1`).
5. *Network → Equipment* → **Palo Alto Networks PAN-OS** → **Add…**: base URL, vsys, block group name, API key, *Never block these IP addresses* (DENIS itself, the gateway, the firewall), *Scope commits to this administrator only* (the account of the API key), and optionally the quarantine group.
6. **Flow blocks:** tick *Allow DENIS to create deny rules on this firewall* only if you accept that DENIS writes security rules on this firewall. It is off by default, and DENIS will not create or delete any rule while it is off. Turning it on needs your password again and is written to the audit log. A wrong deny rule can cut off traffic.

## How a flow block is shaped

The rule is `from any to any`, source `denis-<tag>-<id>-src` (a single `/32` address object), destination `denis-<tag>-<id>-dst`, application `any`, service `any` or the service object `denis-<tag>-<id>-svc` (TCP or UDP with the given port or range, or the whole port range when only a protocol is given), action **deny**, log at session end. The two host addresses alone make the rule exact, so DENIS does not look up zones or interfaces. In both directions, a second rule `denis-<tag>-<id>-r` swaps the two. ICMP is not built (PAN-OS matches it through an application); DENIS refuses a flow with ICMP and says why.

After creating the rule DENIS moves it to the top of the rulebase and reads the rulebase back: only DENIS's own rules (same owner tag) may stand before it. If it did not land at the top, DENIS removes it and the action ends *failed*. After the commit it checks the same thing in the running configuration.

## What is verified

**On a real PA-220 (PAN-OS 10.1.14-h9), 2026-10-20:** *Test connection* (the dynamic group's match, the deny rule first,
the User-ID API allowed); *Block device* through the dynamic group in effect within 10 seconds, without a commit, released
in 8 seconds; *Block a flow* through the static deny rule with a commit, released early after about 2.5 minutes (the
commit). **Not tested on the firewall:** the block through the static address group, quarantine through the static group,
re-registering a lost tag on the hardware, HA, IPv6. In DENIS's own tests, against a simulated firewall: creating, finding by name, moving and deleting the rule, address objects and service; the quarantine move and restore; ending sessions; the partial and full commit and what each publishes; a slow commit, a commit that fails, a commit the firewall refuses, a commit that is still running or whose answer is lost (the action is *unconfirmed* and can still be released); a refused step after earlier steps (compensated, nothing left behind, or *partial* and still releasable); the opt-in, commit-scope and lab-switch refusals; orphans found by owner tag and removed only when they carry it.

**The blocks through a dynamic group (4.2).** Observed on one PA-220 with PAN-OS 10.1.14-h9, with a test tag that no group
matched (the simulated firewall answers in these shapes): a register answers success; a second register of the same tag
answers `status="error"` with the entry message `... already exists, ignore` (DENIS reads it as "the tag was already
there", never as its own); an unregister answers success whether or not the tag was there (so DENIS reads back before and
after); the list of registered addresses has the address, `from_agent`, `persistent` and the tags, and no remaining time;
the `X-PAN-KEY` header works for `type=user-id`; a member timeout works and a second register replaces it (DENIS sets no
timeout in this version); the tag was still there after a commit and after a full restart. In DENIS's own tests, against
the simulated firewall: register and release of exactly DENIS's tag, a tag already there refused and never removed, a tag
that appears between the plan and the write not taken over, another DENIS tag and foreign addresses as warnings, lost
answers on register and unregister, the setup check (missing group, static group, a match with more than the tag, no or a
disabled deny rule, an allow rule above it), the firewall's limit and DENIS's share, a firewall that does not page the list,
the connection test with its probe tag, orphans from ended actions.

Still **[verify]** for the dynamic group: the end-to-end time from the click to the blocked traffic, whether open sessions
are cut without `clear session`, the paging of `show object registered-ip` (`limit`, `start-point`; DENIS falls back to one
unpaged read), the XML form of `show object registered-ip all option count` (DENIS falls back to counting the list), the
least-privilege role (*User-ID Agent* alone for the tag writes), whether the group's match needs the tag object, IPv6
addresses, a dataplane restart, an HA failover, other models and versions.

Behaviours that are unproven vendor facts (marked **[verify]** in the code):

* `type=config&action=move&where=top` places a security rule first, and `type=config&action=get` on the rulebase lists the rules in evaluation order. DENIS checks the position after the move and removes the rule if it did not land at the top.
* A security rule with `any` as source and destination zone is accepted and matches the flow whatever zones the two hosts are in.
* `get` and `show` on an object that does not exist answer with success and an empty result, or with an error that says the object does not exist. DENIS reads both as "not there" and any other error as "cannot tell" (never as "absent").
* A static address group needs at least one member, and `set` at the group's `static` node merges one member without replacing the others. DENIS does not remove its own entry if it is the only member and tells you to add a placeholder.
* `show config list changes` lists the pending changes with the administrator who made each one. If its answer cannot be read, DENIS only carries the note about the full commit.
* A commit job ends with the result `OK`; any other result means nothing was published.
* A partial commit of one administrator publishes only that administrator's changes, including when those are objects that the rule refers to.
* `clear session all filter source <ip>` and `... filter destination <ip>` end the sessions of that address. PAN-OS may answer with an error when no session matches. DENIS then reports the action as failed (nothing changed) rather than completed.
* Whether sessions that are already open are cut by a new deny rule depends on the firewall's session rematch setting ("rematch all sessions on config policy change"). DENIS does not change it.
* Security rules match the addresses before NAT and the zones after NAT. A destination behind a destination NAT is matched by its public (original) address.
* **Panorama.** Pre-rules that Panorama pushes to this firewall are evaluated before the firewall's own rulebase, so they can still allow a flow that DENIS's rule denies. DENIS talks to the firewall, not to Panorama, and cannot see them. The plan says so for every flow block. Placing DENIS's rule in a Panorama device group is not built.
* The rule, address and service `description` fields accept the marker (well under their 1023 character limit).

## Limits

* IPv4 only.
* Traffic between two devices in the same subnet does not pass the firewall, and no rule on it stops it.
* Rule placement is the top of the local security rulebase only. No other anchor is offered, and shared or Panorama rulebases are not written.
* A deny rule for a flow in both directions is two rules (`denis-<tag>-<id>` and `denis-<tag>-<id>-r`).
* For the static group, the flow block and its objects, the marker in the description is what identifies DENIS's objects. A
  registered address has no description: there DENIS's own tag names and the action's record are what identify DENIS's
  registrations.

## Credentials

The API key is stored only in the encrypted secret store (`nac.panos.api_key`) and sent as the `X-PAN-KEY` header. It is never written to the ledger, the audit log or a notification. DENIS uses the XML API only, not the REST API: only the XML API has a commit and the operational commands DENIS needs.

## Existing instances

Instances from earlier versions keep working and nothing changes for them: the same block group, the same address objects (`denis-block-<ip>`), the same ledger rows, the same one commit per block. The old *Block…* and *Unblock…* buttons act as before. Records the old routes made are released through the old *Unblock…*; records of the new actions are released through the new action list. An old-route block is released from the static group its record names, also after the static group was cleared in the connector's form (4.2 makes it optional).

## Details from the console

The console shows a short line under each field and a short note behind its (i). The full explanation of each field is here.

- **Scope commits to this administrator only (optional)**: The PAN-OS administrator account that DENIS's API key belongs to. When set, every commit DENIS makes is a partial commit of that administrator's own changes, so other administrators' pending changes are not published. Without it DENIS makes a full commit, which publishes everything that is pending. A flow block (deny rule) needs it.
- **Quarantine address group name (optional)**: The static address group you created for quarantine. DENIS moves a device into it and back, and nothing else: what the group may reach is decided by your own security rules. DENIS never creates an allow rule. Leave empty to switch quarantine off for this firewall.
- **Allow DENIS to create deny rules on this firewall**: Off by default. When on, DENIS can create one deny security rule per flow block on this firewall, at the top of the security rulebase, named denis-... and marked DENIS managed, and delete it again when the action ends. It never creates an allow rule and never uses any address but the two hosts of the flow. It needs the commit scoped to one administrator. A wrong deny rule can cut off traffic: switch this on only if you accept that.
- **Block dynamic address group name (no commit, recommended)**: The dynamic address group you created for blocks, with exactly one match: DENIS's block tag below. DENIS registers that tag for a blocked device through the User-ID API, so the group picks the device up in seconds without a commit; your deny rule that uses the group, at the top of the security rules, does the blocking. DENIS never creates or edits the group or the rule, and checks both before every block.
- **Block tag (DENIS's own)**: Leave it empty: DENIS fills in denis-blocked- and this installation's six-character tag when you save. Type the saved name, in single quotes, as the match of the dynamic group in PAN-OS. A name of your own must start with denis- (lower-case letters, digits and hyphens). DENIS never registers or removes any other tag.
- **Block address group name (static, with commit)**: Optional when the dynamic group is set. The static address group DENIS adds a device to, followed by a commit, which can take minutes. It is the fallback you choose explicitly, and the old Block and Unblock buttons use it.
- **Quarantine dynamic address group name (optional, no commit)**: The dynamic address group you created for quarantine, with exactly one match: DENIS's quarantine tag below. DENIS registers the tag for a quarantined device and removes it when the action ends, without a commit. What the group may reach is decided by your own security rules. DENIS never creates an allow rule. Leave empty to switch this off.
- **Quarantine tag (DENIS's own)**: Leave it empty: DENIS fills in denis-quarantine- and this installation's six-character tag when you save. Type the saved name, in single quotes, as the match of the quarantine dynamic group in PAN-OS.
- **Register a tag again when the firewall lost it**: On by default. DENIS reads the firewall's registered addresses every minute and right after it sees a restart. When the tag of an active block or quarantine is missing, the action is shown as unconfirmed at once, and with this on DENIS registers the tag again, at most three times per action per hour, only while every safety check still allows the device, and writes it to the audit log. Off: DENIS only shows the action as unconfirmed and notifies you.
- **At most this many registered addresses**: DENIS refuses a new block or quarantine through a dynamic group when it already holds this many registered addresses on this firewall (default 200, from 1 to 1000). The firewall's own limit is shared with every other source (a PA-220 holds 1000); DENIS also refuses when the firewall is at 95 percent of it.
