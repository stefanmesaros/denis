# Enforcement: Juniper SRX

Status: **Experimental. Simulator only: not yet validated on real equipment.** Everything below was built from Juniper's NETCONF and Junos XML API documentation and checked against a fake SRX in DENIS's own tests. It has never been run against a real SRX. Nothing here is listed as validated on hardware.

Lab use: the host block (address set) is allowed only while an administrator has switched on *Allow connectors that are not validated on real equipment (lab use)* under *Settings → Enforcement*. The actions new in 4.1 (flow block, quarantine, ending sessions) additionally need *Allow experimental actions (lab use)*. Releasing an action and removing what DENIS made always work.

Besides the connector's own refusals, every action through it is refused for a loopback, unspecified, broadcast or multicast address, for DENIS itself and for the gateway, for the addresses on this connector's protected list, for an address in an open `arp_conflict` alert (unless the administrator ticks a box to accept that) and for any address that belongs to the SRX itself, before anything is sent. Releasing is never refused for these reasons.

DENIS talks to the SRX over **NETCONF through SSH**, with the host's own `ssh` program (and `sshpass` for a password or a protected key): it does not implement SSH itself. There is no REST API on Junos that is as universal.

## What DENIS can do on an SRX

| Action | What DENIS writes | What it does not do |
|---|---|---|
| **Block device** (address set) | One address object `denis-<tag>-<id>` (the device's address, `/32`) in the global address book, added to the address-set you created for blocks. Then it ends the device's open sessions (best effort). | It never creates or edits the policy that uses the set. An address that is already in the set under another name is refused: DENIS never takes over an entry it did not make. |
| **Quarantine** (quarantine address set) | The same, into a second address-set you created for quarantine. | It never creates an allow policy, and never edits your policies. What a quarantined device may reach is decided by your own policies for that set (DHCP, DNS, NTP, a remediation server). DENIS does not check them. |
| **Block flow** (deny rule) | One security policy `denis-<tag>-<id>` (`then deny`, logged) for exactly one source, destination, protocol and port, **first in the policy list of the zone pair** the two addresses are reached through, plus two single host address objects and, with a port, one custom application, all named from it. A flow in both directions is two policies, in the two zone pairs. | Only with the per-instance switch *Allow DENIS to create deny rules on this firewall*. Deny only: no code path builds a permit or reject policy. Never `any` for an address. Never a global policy (see below). Sessions that are already open continue until they end or are cleared: the policy stops new ones. |
| **End sessions** (session clear) | `clear security flow session source-prefix <ip>/32` and `destination-prefix <ip>/32`, after the sessions of the address were counted (at most 2000). | It cannot be undone. The device can open new sessions at once. If the count cannot be read, or is above 2000, DENIS ends none. |
| Disable port | Not available: an SRX has no access port DENIS can switch off. (EX switches are another connector.) | |

Every object DENIS makes carries `DENIS managed; owner <tag>; action <id>; by <login>; expires <time or never>` in its `description`. Text you typed as a reason is never sent to the SRX. DENIS deletes only objects that carry its own owner tag. An object with a DENIS-style name that does not carry the tag is never touched, and the action is refused.

## The commit is part of the action

Junos keeps a **candidate** configuration next to the running one, and a **commit** publishes the whole candidate. DENIS treats this as part of the action and records each step:

1. It **locks** the candidate and **compares** it with the running configuration. If someone else has uncommitted changes in it, DENIS refuses and changes nothing: a commit would publish their unfinished work. It does not touch or discard those changes.
2. It **edits** the candidate and **checks** the result (`commit check`), so a change the SRX would refuse is refused with nothing committed. A failure after the edit leaves the candidate as it was (`discard-changes`, also from a second session when the first one was lost, and only when the difference mentions DENIS's own names).
3. A change that **adds** something (a set member, a policy) is committed with **`commit confirmed 2`**: unless DENIS confirms it, the SRX takes the change back by itself after two minutes. So if DENIS crashes, loses the session or finds the running configuration not as planned, a bad policy does not stay.
4. DENIS reads the **running** configuration back (the policy is there, first in its pair, as planned) and only then sends the **confirming commit**, recorded as the step *confirm the commit*. The read-back of the action counts the change as in force only when that step finished. A refused or lost confirmation leaves the action *not confirmed* (or *partly applied* when the clean-up cannot be committed either), active and visible, and the SRX takes the change back.
5. A change that **removes** something is a plain commit: taking a block away cannot lock anyone out.
6. The lock is always released.

DENIS does not use the commit confirmation as an undo of its own: it removes what it made by name and owner tag.

## How a flow block finds its zones

A security policy belongs to a zone pair. DENIS never writes a policy it cannot tie to one. It looks for the **directly connected network** (the most specific one) of each address among the SRX's interface addresses and takes the **zone** of that interface. If the address is not on a connected network it asks the routing table (`get-route-information`) for the interface the route leaves through. If it cannot tell, or the interface is in no zone, or both addresses are behind the same interface, it refuses and says why. A refusal is a normal answer, not an error.

**Why never a global policy.** Junos evaluates the policies of a zone pair first and **global** policies only after them. A deny in a global policy would not stop traffic that a policy of the zone pair permits, so it would look like a block and stop nothing. DENIS refuses a flow whose zones it cannot determine instead.

## Setup

1. **Block set.** In `security address-book global` create an **address-set** for DENIS's blocks and a **deny policy** (or a reject) that uses it, high up in the policy list. DENIS never creates or edits this policy. Junos does not keep an address-set with no member, so put one placeholder address in the set (for example `192.0.2.255/32`, a documentation address that is never routed). DENIS refuses a set that has no member, and never takes out the last member of a set.
2. **Quarantine set (optional).** Create a second address-set the same way, again with a placeholder, and **your own policies** for it: allow what a quarantined device needs (DHCP, DNS, NTP, the remediation server) and deny the rest. DENIS never creates these. Enter its name in *Quarantine address-set name*. Leave it empty to switch quarantine off.
3. **Account.** Create a user for DENIS with a login class that may use NETCONF over SSH (`set system services netconf ssh`; DENIS uses the NETCONF subsystem on port 830, or on the SSH port if NETCONF is served there). Give it only what it needs: configure access to `security address-book`, `security policies` and `applications` (flow blocks), the `commit` permission, `view` for interfaces, zones and routes, and the operational commands `show security flow session` and `clear security flow session`. A key or a password (*SSH password*; for a protected key, the passphrase). The host DENIS runs on needs `ssh` and, for a password or a protected key, `sshpass`.
4. **Host key.** Put the SRX's host key in a `known_hosts` file the DENIS process can read and give its path. DENIS never trusts an unknown key on first use. Turn verification off only for a lab device.
5. *Settings → Enforcement* → **Juniper SRX** → **Add…**: address, port, user, authentication, secrets, block address-set name, *Never block these IPv4 addresses* (DENIS itself, the gateway, the SRX), and optionally the quarantine set.
6. **Flow blocks:** tick *Allow DENIS to create deny rules on this firewall* only if you accept that DENIS writes policies on this SRX. It is off by default, and DENIS will not create or delete any policy while it is off. Changing it needs your password. A wrong deny policy can cut off traffic; the commit confirmation takes it back if DENIS cannot confirm it.

## What is verified

Only against the fake SRX server in `src/nac_juniper/tests.rs` (a candidate and a running configuration as XML trees, edited by the same requests DENIS sends; a confirmed commit that is taken back unless it is confirmed; the CLI passthrough): creating, finding by name, placing first, and deleting the policy, addresses and application, in both directions; the quarantine move and restore; the member refusals (missing set, empty set, last member, an address already in the set); ending sessions by prefix; the whole commit model (a dirty candidate, a refused lock, a refused check, a refused commit, a refused or lost confirmation, a lost answer on the edit or on the commit, a device that does not answer in time); the opt-in and lab-switch refusals; orphans found by owner tag and removed only when they carry it; and that the old routes still make the same calls. **Not verified on any real SRX.**

Behaviours that are unproven vendor facts (marked **[verify]** in the code):

* `<commit-configuration>` with `<confirmed/>` and `<confirm-timeout>` (minutes), `<check/>` and `<log>` work over NETCONF, and an unconfirmed `commit confirmed` is taken back by the device by itself.
* `<get-configuration compare="rollback" rollback="0" format="text"/>` answers an empty output when the candidate equals the running configuration. When it cannot be asked, DENIS refuses.
* The global address book is `<address-book><name>global</name>...` (one level). The code that was in DENIS before 4.1 writes the element twice, and was never run on a real SRX: the old routes still do, DENIS reads either form, and the new actions write the single level. **If your SRX answers the old routes with an error, this is the first place to look.**
* An address accepts `description` and `ip-prefix`; a custom `application` accepts `protocol` and `destination-port` (a range such as `5000-5010` too); the predefined applications `junos-tcp-any`, `junos-udp-any` and `junos-icmp-all` exist.
* `<policy insert="first">` places a policy first in the zone pair's list, and `then { deny; log { session-init; } }` is accepted.
* A set with no member is refused by Junos at commit.
* `<get-route-information><destination>` answers the interface in `via`.
* `clear security flow session source-prefix <ip>/32` (and `destination-prefix`) ends the sessions of that address only, `show security flow session ... summary` prints `Total sessions: N`, and the `<command format="text">` passthrough runs both. The old routes use a different command (`destination-address`) that was never confirmed either and are left as they were.
* Policies take effect for new sessions only; open sessions continue unless cleared (unless `policy-rematch` is on).
* The commit time of an SRX can be long: DENIS waits up to 180 seconds for a commit and then leaves the action *not confirmed*.

## Limits

* IPv4 only (IPv6 flow-based forwarding is a separate setting on an SRX).
* Only the **global** address book is edited.
* Traffic between two devices in the same subnet does not pass the firewall, and no policy on it stops it.
* Policy placement is the first position of the zone pair only. No other anchor is offered.
* The candidate is shared: while DENIS holds the lock nobody else can commit, and it holds it for the length of the change (seconds to a minute or two on a slow commit).
* In a chassis cluster, the commit goes to the whole cluster; DENIS does not look at the nodes.
* NAT: Junos matches policies after static and destination NAT and before source NAT.

## Credentials

The SSH password (`nac.juniper.password`) and the key passphrase (`nac.juniper.key_passphrase`) are stored only in the encrypted secret store and given to the `ssh` child process in its environment, never in its arguments, the ledger, the audit log or a notification. The private key is a file path DENIS must be able to read.

## Existing instances

Instances from earlier versions keep working and nothing changes for them: the same block address-set, the same address objects (`denis-block-<ip>`), the same plain commit, the same ledger rows. The old *Block…* and *Unblock…* buttons act as before. Records the old routes made are released through the old *Unblock…*; records of the new actions are released through the new action list.
