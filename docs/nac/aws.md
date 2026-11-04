# Enforcement: Amazon Web Services security groups (AWS)

Status: **Verified in a lab AWS account (eu-central-1), 3 November 2026: the host block through the isolation security group and the quarantine, found by private IP address, with the `denis-owner`, `denis-action`, `denis-prior-groups` and `denis-sg` tags, release at expiry, the refusal for an address no instance has, and the refusals for protected instance ids and protected networks.** The rest was built from the EC2 API reference and checked against a fake EC2 in DENIS's own tests.

Lab use: both actions are verified and need no lab setting. Releasing an action and removing what DENIS made always work.

Besides the connector's own refusals, every action through it is refused for a loopback, unspecified, broadcast or multicast address, for DENIS itself and for the gateway, for an instance on this connector's protected list, for an address in an open `arp_conflict` alert (unless the administrator ticks a box to accept that), before anything is sent. Releasing is never refused for these reasons.

## What the old "block" really is

Before 4.1 this connector's block moved every network interface of one EC2 instance into one security group you made for quarantine. That was always a **quarantine of the instance**, not a block of one address, and DENIS now calls it that (*Quarantine*, method `security_group_swap`). The old *Block…* and *Unblock…* buttons still do exactly this, by instance id, and old records keep working. Nothing about the old routes changed.

## What DENIS can do on AWS

| Action | What DENIS writes | What it does not do |
|---|---|---|
| **Quarantine** (`security_group_swap`) | Every network interface of the instance gets exactly one security group: the one you made for quarantine. DENIS remembers the groups each interface had and tags each interface (see below). | It never creates or edits a security group or a rule. What a quarantined instance may reach is decided by the rules in your group (DHCP, DNS, a remediation server). DENIS does not check them. |
| **Block device** (`isolation_sg`) | The same swap, into a second group you made with **no rules at all**, inbound and outbound, so the instance can neither send nor receive new connections. | Same: DENIS never creates or checks a rule in it. A rule in it lets that traffic through. |
| Block flow | **Not available, and it will not be.** | A security group only allows traffic: it has no deny rule, so it cannot block one flow. A network ACL can deny, but it is subnet-wide and yours: DENIS does not touch it. |
| End sessions | Not available: AWS has no call DENIS uses to end sessions. | |
| Disable port | Not available: a cloud instance has no switch port. | |

## Setup

1. **IAM user or role.** Create a dedicated IAM user for DENIS with an access key and the minimal policy below.
2. **Quarantine security group** and, if you want the host block, an **isolation security group**: create them in the VPC of the instances and give DENIS their ids. For the isolation group, **remove the default allow-all outbound rule as well**, or the instance can still open connections. DENIS never creates or edits their rules.
3. Fill in the connector: *IAM access key id*, *secret access key* (secret), *region*, *quarantine security group id*, optionally *isolation security group id*, and the instance ids never to block.

## Minimal IAM permissions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow",
      "Action": ["ec2:DescribeNetworkInterfaces"],
      "Resource": "*" },
    { "Effect": "Allow",
      "Action": ["ec2:ModifyNetworkInterfaceAttribute", "ec2:CreateTags", "ec2:DeleteTags"],
      "Resource": "arn:aws:ec2:<region>:<account>:network-interface/*" },
    { "Effect": "Allow",
      "Action": ["ec2:ModifyNetworkInterfaceAttribute"],
      "Resource": "arn:aws:ec2:<region>:<account>:security-group/*" }
  ]
}
```

**Why every security group of the account and region, not only the two you made.** AWS checks `ModifyNetworkInterfaceAttribute` against
each security group an interface is *given*. Putting the interface into the quarantine or isolation group needs those two, but **putting it
back needs the group it had before**, and that is any group an instance of yours uses. A policy that names only the two DENIS groups moves the
instance away and then cannot bring it back (AWS answers `UnauthorizedOperation` on the old group; found on the first run against a real AWS
account, 3 November 2026, region eu-central-1). If you do not want `security-group/*`, list every group your instances may carry. Never limit this
statement to the two DENIS groups.

**DENIS checks this before it isolates anything.** For every network interface of the instance it sends a *dry run* of the change (`ModifyNetworkInterfaceAttribute` with `DryRun`: AWS answers `DryRunOperation` when the call would be allowed and changes nothing), once for putting the interface back into the groups it has now and once for giving it the quarantine or isolation group. If AWS would refuse either, DENIS says so in plain words and does not touch the instance: it never isolates an instance it could not release. The dry runs are two extra requests per interface, only when an action is applied, and they count against the account's request rate like any other call (a throttled one is waited out as described below).

`DescribeNetworkInterfaces` cannot be limited to resources in EC2. **[verify]** the exact resource ARNs `ModifyNetworkInterfaceAttribute` is checked against (the interface, and each security group it is given) in your account. `ec2:CreateTags` and `ec2:DeleteTags` are needed by the new actions only (the old routes write no tags): without `CreateTags` a new action is refused and takes its swap back, so there is never a swap without a mark. DENIS never needs `AuthorizeSecurityGroup*`, `RevokeSecurityGroup*`, `CreateSecurityGroup`, `DeleteSecurityGroup` or any network ACL permission, and a test pins that the code never calls them. A condition on the tag `denis-owner` can narrow `DeleteTags` further.

## How an instance is found

The old routes take an instance id. The new actions take the instance's **private IP address**: DENIS asks EC2 for the network interfaces with that address in the connector's region, finds the instance they are attached to, and refuses when no instance, or more than one (two networks that use one range), has it. It then runs the generic address guard on **every** address of every interface of that instance (a second interface may carry DENIS itself or the gateway), and applies the protected list to the instance id.

## Marks on the network interfaces

Each interface DENIS changes through the new actions gets four tags: `denis-owner` (this install's owner tag), `denis-action` (the action id), `denis-prior-groups` (the groups it had, comma separated, or `unknown` when they do not fit the 256 characters a tag value may have) and `denis-sg` (the group DENIS put there). Your own tags are kept. DENIS removes its own when the action ends. The tags make a swap visible in the console and let DENIS find a swap whose record was lost (an orphan, listed under *Health* and removed there): an orphan is put back to its prior groups only while it still carries only the group DENIS swapped in, and never guessed when the prior groups are `unknown`: then its tags stay for a person to read, and the groups are fixed by hand.

**A restore never overwrites someone else's change.** When an action ends, DENIS puts an interface back only while it still carries only the group DENIS swapped in. If an administrator gave it other groups meanwhile, DENIS leaves it alone, takes off only its own tags, and says so in the result of the release: which interface, which groups it carried instead of the group DENIS had set (the `denis-sg` tag), and that DENIS did not change them back. Such a release is never reported as a plain "removed": the person is told to look at that interface in AWS.

## While an action is active

* **Isolation holds only while no other administrator changes the groups.** A security group change by hand (for example adding an open group to the isolated interface) takes the isolation away, and AWS has no way to forbid it. DENIS does not fight it.
* **The sweep.** The reconcile job reads every active action back from AWS at least once an hour and once after every start. If an interface of an isolated instance carries the DENIS group **and** another one, DENIS keeps the action active (so it still ends at its time), writes the finding into the action's verification, records `nac.drift_partial` in the audit log and raises one high-severity notice that names the interface and the groups. The same finding is not announced again at the next sweep. If the DENIS group is gone altogether, the action is recorded as removed by someone else, as for every connector. **DENIS does not fix it by itself:** putting the groups back would overwrite a change a person made, possibly on purpose, and which of the two is right is theirs to say. The *Check now* button of the action runs the same read at once.
* **Release can lag.** The expiry job runs every 10 seconds and starts a release 30 seconds after the end time (late, never early), then reads AWS back until it sees the old groups, so the groups come back about 30 to 45 seconds after the time shown (45 seconds were seen in the lab account). A press on *Release* does not wait for the 30 seconds.

## Connections that were already open

A security group decides about **new** connections. AWS keeps the connections it already tracks alive after the groups of an interface change, so a `ping` or an SSH session that was running before the action can keep working for a while, and a new connection is refused straight away. This was seen on the first run against a real AWS account (3 November 2026, eu-central-1): a running `ping` went on after the swap; stopping it and starting a new one showed the block. If a running connection must end at once, end it on the instance as well, or use the isolation group, which also has no outbound rule, and start the action before the session you care about.

## Cloud behaviour

* **Eventual consistency.** EC2 is eventually consistent: a read right after a write may still show the old groups. DENIS reads again, at most four times with a pause, until it sees what it wrote and DENIS's marks. A read that still disagrees leaves the action *not confirmed*, never "enforced".
* **Throttling.** EC2 answers `RequestLimitExceeded` (HTTP 503) or `Throttling` when an account asks too fast. DENIS waits with a backoff of 0.5, 1 and 2 seconds and repeats the request, at most three times. A request that is still refused changed nothing.
* **No compare and swap.** `ModifyNetworkInterfaceAttribute` replaces the list of groups with no revision. A change an administrator makes in the moment between DENIS's read and its write is overwritten; DENIS checks right before the first write that the interfaces still have what it read, and refuses if they do not.
* **Region.** One connector works in one region. An instance in another region is not found.

## What is verified

**In a lab AWS account (eu-central-1), 3 November 2026:** the host block through the isolation group and the quarantine by private IP address, the four tags, release at expiry, the refusal for an address no instance has, the refusal for protected instance ids and protected networks, and (see *Connections that were already open* above) that a running connection survives the swap while a new one is refused. Not tried there: IPv6, an instance with several network interfaces, an instance behind a load balancer, a second region, throttling.

**Against the fake EC2 in `src/nac_aws/tests.rs`:** the swap of every interface with its marks, a restore of exactly what was there (your own tags kept), the host block with its isolation group, finding the instance by address (none, two, a listing in pages), the protected list on the id and on every address of the instance, a swap already in place, a refused write, a refused tag (the swap is taken back), a lost answer, the second interface refused (the action is left partly applied until released), throttling (bounded), a lagging read (bounded), a restore that leaves a changed interface alone, prior groups too long for a tag, the old routes (same calls, same effect, rows from earlier versions), orphans found by mark and put back only when they carry it, the dry-run refusals (an old group DENIS may not give back, a swap group it may not give), a group added by hand during the block (the release says so and changes nothing, the sweep notices it once and keeps the action), and expiry.

Behaviours that were not tried in the lab account and are still unproven vendor facts (marked **[verify]** in the code):

* The IPv6 filter `ipv6-addresses.ipv6-address` of `DescribeNetworkInterfaces` and the `tag:<key>` filter DENIS uses to find an orphan by its mark.
* A throttled call is answered with the error code `RequestLimitExceeded` or `Throttling`.
* The IAM resource ARNs in the policy above, other than `security-group/*`.

## Limits

* Security groups are **stateful**: a connection that is already tracked may continue until it goes idle, and DENIS cannot end it.
* An instance with more than the interfaces the region reports in one listing is read in pages, up to 20 of them.
* An instance with a security group per interface keeps one group per interface after the swap (the swapped-in group, on every interface).
* Instances behind a load balancer or a NAT gateway are found by their own private address, not by the address a client sees.

## Credentials

A long-lived IAM access key id (plain configuration) and secret access key (`nac.aws.secret_access_key`), signed with AWS Signature Version 4. An assumed role was considered and rejected: it only moves the long-lived secret one hop away. The secret is never written to the ledger, the audit log or a notification.

## Existing instances

Instances from earlier versions keep working and nothing changes for them: the same swap of every interface by instance id, the same calls (no tags, no address search), the same restore of each interface's original groups. One difference in the record: the original groups of an interface are now written to the record's undo data, before the first change, and no longer into its target; a record made by an earlier version keeps them in its target and is still released. The old *Block…* and *Unblock…* buttons act as before. Records the old routes made are released through the old *Unblock…*; records of the new actions are released through the new action list.

## Details from the console

The console shows a short line under each field and a short note behind its (i). The full explanation of each field is here.

- **Isolation security group id (optional)**: The security group you made for the host block: no rules at all, inbound and outbound (remove the default allow-all outbound rule too), so an instance whose interfaces carry only this group can neither send nor receive new connections. DENIS only swaps the interfaces' groups and puts the old ones back, and never creates or edits a rule in it. Leave empty to switch the host block off.
