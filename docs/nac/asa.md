# Enforcement: Cisco ASA

Status: **Experimental. Simulator only: not yet validated on real equipment.** Everything below was built from Cisco's published ASA command reference and checked against a scripted fake ASA in DENIS's own tests. It has never been run against a real ASA. The vendor behaviours that are still unproven are listed under *Verified and not verified* below.

Lab use: every action of this connector is allowed only while an administrator has switched on both *Allow connectors that are not validated on real equipment (lab use)* and *Allow experimental enforcement actions* under *Settings → Enforcement*. This connector is new in 4.1 and has no older block button. Everything goes through the Respond menu: a plan you read, a confirmation, a time limit (one hour by default), and a release that DENIS also makes on its own when the time is up.

Besides the connector's own refusals, every action through it is refused for a loopback, unspecified, broadcast or multicast address, for DENIS itself and for the gateway, for DNS and directory servers, for anything in the connector's *protected networks* and in *Never block these IP addresses*, for the address you are using to reach the console, and for every address of the ASA itself (its interfaces, the management interface and the standby address of a failover pair, which DENIS reads from the ASA each time).

## What DENIS can do on an ASA

| Action | What DENIS writes | What it does not do |
|---|---|---|
| **Block device** (object group) | One network object `denis-<tag>-<id>` (`host <address>`, its description led by the marker `DENIS managed; owner <tag>; action <id>; ...`), added to the `object-group network` you created for blocks, with `network-object object`. | It does not create the access rule that makes the group block anything: **your own access rule** that refers to the group does that. It does not end open connections (use *End sessions*). |
| **Quarantine** (object group) | The same network object, added to a second `object-group network` that you created for quarantine. | It creates **no access line at all** and never a permit line. What a quarantined device may reach is decided by your own access rules. |
| **Block flow** (deny line) | Two network objects (`denis-<tag>-<id>-src` and `-dst`) and, at the top of the access list you name, one remark `DENIS managed denis-<tag>-<id>` and one `extended deny` line that refers to the two objects, for one source host, one destination host, a protocol and a port. With both directions: a second remark and line `denis-<tag>-<id>-r`. | It never writes a permit line, a network or `any`, or a line for the ASA's own addresses. Only with *Allow DENIS to create deny rules on this firewall* ticked. |
| **End sessions** (clear conn) | `clear conn address <address>` for one IPv4 address, after counting that no more than 2000 connections are open for it. | It cannot be undone and the device can open new connections at once. Never `clear conn all`, never an address of the ASA itself. |
| Disable port | Not possible on a firewall. | |

Every object DENIS makes carries the marker in its description (and in the remark of a line), so removal is exact: DENIS removes only what carries its own marker, by name, and an object with another install's tag is never touched. Text you typed (the reason) is never written to the ASA: the marker holds only DENIS's own tag, the action number, your login name and the planned end time.

## No commit, no rollback timer: what that means

An ASA has no candidate configuration. **Every command takes effect in the running configuration the moment the ASA accepts it**, and there is no lock and no timer that undoes it. DENIS therefore:

* records **every command** as a step of the action (you can read them in the action's detail);
* writes the **marker first** (an object's description before its address), so an object that was only half made is still recognisably DENIS's and is removed again;
* undoes the steps that were accepted when a later step is refused, and if that cannot be done, leaves the action active and marked partial, so that a release (or the next automatic try) finishes it;
* reads the configuration back afterwards: the group member and the object for a membership action, and for a flow block the **position of the lines in the access list** (the first lines of the list must be DENIS's own remark and line, with nothing but other DENIS lines above them). A line that did not land at the top is removed again and the action fails. **Hit counts are never used as proof.**

### `write memory`

DENIS does **not** run `write memory` by default. Its changes live in the running configuration only, so a reload of the ASA removes them, which suits an action that ends on its own. `write memory` saves every unsaved change on the ASA, including changes other administrators have not finished, so DENIS does not do it for you unless you ask.

If you tick *Save the configuration after each change (write memory)*, DENIS runs `write memory` after a change and after its removal, and the plan says that this also saves everything else that is unsaved. A save that fails does not undo the change: the action stays in force, and the failed save is a step in its detail. In multiple context mode the save is the context's own.

## Contexts, failover and privilege

* **Multiple context mode.** Name the context under *Security context*. DENIS reads `show mode`, switches with `changeto context <name>`, and checks that the prompt shows `hostname/<name>`, which is the default prompt in multiple mode. It never writes in the system context and refuses if the prompt does not show the context. On an ASA in single mode the context must be empty.
* **Failover.** DENIS changes the **active** unit only; when it reaches the standby unit it refuses. Point the connector at the address of the active unit. The active unit replicates configuration changes to its peer.
* **Privilege.** The account needs privilege level 15 so that it lands at `hostname#` after signing in (with `aaa authorization exec ... auto-enable`, or a local user with privilege 15 where your ASA version does that), or you store the account's enable password (*Enable password*, sealed as `nac.asa.enable_password`). Without either, DENIS refuses.

## Setup on the ASA

Commands are the ASA CLI; check them against Cisco's documentation for your software version before relying on them.

1. **SSH from the DENIS host.** `ssh <DENIS address> 255.255.255.255 <interface name>` (for example `ssh 192.0.2.5 255.255.255.255 inside`), and `aaa authentication ssh console LOCAL`. The DENIS host needs an OpenSSH client (`ssh`) and `sshpass` on its path, as for the Juniper connector. An ASA that offers only old SSH algorithms (for example `diffie-hellman-group1-sha1`) is refused by current OpenSSH clients: allow a current key exchange on the ASA (`ssh key-exchange group dh-group14-sha256`).
2. **A user.** `username denis password <a long random password> privilege 15`. Cisco has no read-write role below 15 that covers the commands DENIS sends without command authorization; if you use command authorization (TACACS+ or local), allow at least: `terminal`, `show mode`, `show failover`, `show version`, `show running-config` (object, object-group, access-list, access-group, interface), `show interface ip brief`, `show conn`, `changeto context`, `configure terminal` and, inside it, `object network`, `object-group network`, `network-object`, `host`, `description`, `access-list`, `no`, `exit`, `end`, `clear conn`, and `write memory` if you tick the save option.
3. **The block group and your own rule.** `object-group network DENIS-BLOCK` (it must have at least one member before DENIS uses it: DENIS refuses to add to an empty group; add a placeholder, for example a network object for `192.0.2.255`), and **your own** access rule that denies the group, high in the list your interface uses: `access-list OUTSIDE_IN extended deny ip object-group DENIS-BLOCK any` (and the same with the group as destination, if you want to stop traffic to it).
4. **Quarantine (optional).** A second `object-group network` (with a placeholder member) and **your own access rules** that use it: allow what a quarantined device needs (DHCP, DNS, NTP, the remediation server) and deny the rest. DENIS never creates, checks or edits these rules.
5. **Flow blocks (optional).** Name the extended access list DENIS may put deny lines at the top of. It must be bound to an interface with `access-group <list> in interface <name>` (or `global`). DENIS refuses a list that is not bound that way, and a list that is also bound with `control-plane`. A line only stops traffic that enters the interface the list is bound to, and only **new** connections: open ones stay open (use *End sessions* too). Tick *Allow DENIS to create deny rules on this firewall* only if you accept that DENIS writes access list lines on this ASA. It is off by default, and DENIS will not create a flow rule while it is off. Turning it on needs your password again, like turning on enforcement.
6. **In DENIS** (*Settings → Enforcement → Add a connector → Cisco ASA*): **Device address**, **SSH port**, **SSH username** and **SSH password** (sealed as `nac.asa.password`), the **block object group**, the optional quarantine group, access list and context, and the host key settings below.

## Host keys

Verification is **on** by default: DENIS runs `ssh` with `StrictHostKeyChecking=yes` against the `known_hosts` file you name, so a connection to a device whose key is not in that file is refused. DENIS never accepts a key on first use. Put the ASA's key there yourself, for example with `ssh-keyscan -t ecdsa <address>` checked against the fingerprint the ASA shows (`show ssh fingerprint` where your version has it). Unticking *Verify SSH host key* is for a lab only: every connection then accepts whatever key answers.

## How DENIS talks to the ASA

Each call opens one SSH session with the host's own `ssh` (`-tt`, one password attempt, no agent, no user configuration file, `TERM=dumb`), signs in, sets `terminal pager 0` and `terminal width 511`, does its work and closes. The password is passed to the child process only through its environment (`sshpass -e`), never on a command line. Every wait has a deadline (25 seconds a command, 60 seconds for `write memory`, 4 minutes for a whole session), a command's answer is cut off at 2 MB, and a session that stops at a question (`[confirm]`, a password, `--More--`) is ended, never answered. A line DENIS sends contains only letters, digits and the punctuation of a name or an address, never a question mark (which asks an ASA for help). Names that reach a command line (the groups, the list, the context) are limited to letters, digits, dots, dashes and underscores when you save the settings.

DENIS runs one session at a time per ASA connector, so two of its own actions do not interleave their reads and writes.

## Credentials

A user name (plain configuration), a password (`nac.asa.password`) and optionally an enable password (`nac.asa.enable_password`). Both are stored sealed, never logged, audited or returned.

## What DENIS records

The ledger row is written before anything changes (`unconfirmed`), the audit entry before the connector is touched, and each command is a step. A release or an automatic end removes by name and marker and reads the configuration back; if the ASA refuses, the action stays active and DENIS tries again, with growing waits, and tells you.

Objects and lines that carry your DENIS install's marker but belong to no active action (for example after a database restore) are listed as orphans, with a button to remove them. Objects with another install's tag, and anything without the marker, are never listed as DENIS's and never removed.

## Removing everything by hand

* Objects: `show running-config object network | include denis-` and `no object network denis-<tag>-<id>` (remove it from your group first: `object-group network DENIS-BLOCK`, `no network-object object denis-<tag>-<id>`).
* Lines: `show running-config access-list <list>`, then `no access-list <list> ...` with the text of each line that carries `DENIS managed` or refers to a `denis-` object.
* Sessions cannot be restored.

## Verified and not verified

* **Verified (against a scripted fake ASA, and the SSH layer against a stand-in `ssh` script, in the test suite):** the command sequence of every action, the marker, the order (marker before address), the group membership, that no permit line is ever written, the position check and the removal of a line that did not land at the top, compensation of a failed step and the partial state when it cannot be undone, a lost answer settled by reading back, refusals (own addresses, empty or missing group, an access list that is not bound, the control plane, a foreign object or line under DENIS's name, another install's objects), contexts, the standby unit, the enable password, the save policy, orphan listing and removal, and that refusals send nothing.
* **Not verified: everything on a real ASA.** In particular, behaviours that are unproven vendor facts (marked **[verify]** in the code):
  * The prompts after signing in (`hostname#`, `hostname(config)#`, `hostname(config-network-object)#`, `hostname(config-network-object-group)#`, `hostname/context#`), and that `terminal pager 0`, `terminal width 511` and `show mode` are accepted.
  * `show running-config object-group id <name>` and `show running-config object network <name>` print nothing (or an error that says so) for an object that does not exist.
  * `show running-config access-list <name>` lists remarks and extended lines in evaluation order, prints a TCP or UDP port by its keyword (`eq https` for 443; DENIS knows about 80 keywords and reads anything else as "cannot tell"), and prints an object reference as `object <name>`.
  * `access-list <name> line 1 extended deny ... object A object B` and `access-list <name> line 1 remark ...` insert at the top, a remark counts as a line of its own, and `no access-list <name> <the line as shown>` deletes it.
  * `no object network <name>` is refused while an access list or group still refers to it (DENIS removes the references first).
  * `clear conn address <address>` ends the connections whose source or destination is that address and answers `N connection(s) deleted.`.
  * Access lists match real (untranslated) addresses on ASA 8.3 and later: a flow whose destination sits behind a static NAT is matched by its real address.
  * `show failover | include This host` contains the word Standby on the standby unit.
  * Whether an object group that has just been emptied is handled the way you expect by the access rules that use it (the reason DENIS never leaves a group empty).
  * Whether a remark's text is accepted with the characters DENIS uses, and the maximum lengths of object names (64), descriptions (200) and remarks (100); DENIS's marker and names stay under them.

## Limits

* IPv4 only.
* A flow rule stops new connections that enter the interface the list is bound to. It does not stop traffic inside one subnet, and does not cut open connections.
* Block device and quarantine do nothing until **your own** access rule refers to the group.
* One ASA at a time per connector; a failover pair is one connector pointed at the active unit.
