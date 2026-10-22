# Enforcement: AWS security groups

Status: **Experimental. Simulator only: not yet validated on real equipment.** Everything below was built from the EC2 API reference and checked against a fake EC2 in DENIS's own tests. It has never been run against a real AWS account. Nothing here is listed as validated on hardware.

Lab use: the quarantine (the swap that was called "block" before 4.1) is allowed only while an administrator has switched on *Allow connectors that are not validated on real equipment (lab use)* under *Settings → Response policy*. The host block through the isolation group, new in 4.1, additionally needs *Allow experimental actions (lab use)*. Releasing an action and removing what DENIS made always work.

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
      "Resource": ["arn:aws:ec2:<region>:<account>:security-group/<quarantine sg>",
                   "arn:aws:ec2:<region>:<account>:security-group/<isolation sg>"] }
  ]
}
```

`DescribeNetworkInterfaces` cannot be limited to resources in EC2. **[verify]** the exact resource ARNs `ModifyNetworkInterfaceAttribute` is checked against (the interface, and each security group it is given) in your account. `ec2:CreateTags` and `ec2:DeleteTags` are needed by the new actions only (the old routes write no tags): without `CreateTags` a new action is refused and takes its swap back, so there is never a swap without a mark. DENIS never needs `AuthorizeSecurityGroup*`, `RevokeSecurityGroup*`, `CreateSecurityGroup`, `DeleteSecurityGroup` or any network ACL permission, and a test pins that the code never calls them. A condition on the tag `denis-owner` can narrow `DeleteTags` further.

## How an instance is found

The old routes take an instance id. The new actions take the instance's **private IP address**: DENIS asks EC2 for the network interfaces with that address in the connector's region, finds the instance they are attached to, and refuses when no instance, or more than one (two networks that use one range), has it. It then runs the generic address guard on **every** address of every interface of that instance (a second interface may carry DENIS itself or the gateway), and applies the protected list to the instance id.

## Marks on the network interfaces

Each interface DENIS changes through the new actions gets four tags: `denis-owner` (this install's owner tag), `denis-action` (the action id), `denis-prior-groups` (the groups it had, comma separated, or `unknown` when they do not fit the 256 characters a tag value may have) and `denis-sg` (the group DENIS put there). Your own tags are kept. DENIS removes its own when the action ends. The tags make a swap visible in the console and let DENIS find a swap whose record was lost (an orphan, listed under *Health* and removed there): an orphan is put back to its prior groups only while it still carries only the group DENIS swapped in, and never guessed when the prior groups are `unknown`: then its tags stay for a person to read, and the groups are fixed by hand.

**A restore never overwrites someone else's change.** When an action ends, DENIS puts an interface back only while it still carries only the group DENIS swapped in. If an administrator gave it other groups meanwhile, DENIS leaves it alone, takes off only its own tags, and notes it in the action's steps.

## Cloud behaviour

* **Eventual consistency.** EC2 is eventually consistent: a read right after a write may still show the old groups. DENIS reads again, at most four times with a pause, until it sees what it wrote and DENIS's marks. A read that still disagrees leaves the action *not confirmed*, never "enforced".
* **Throttling.** EC2 answers `RequestLimitExceeded` (HTTP 503) or `Throttling` when an account asks too fast. DENIS waits with a backoff of 0.5, 1 and 2 seconds and repeats the request, at most three times. A request that is still refused changed nothing.
* **No compare and swap.** `ModifyNetworkInterfaceAttribute` replaces the list of groups with no revision. A change an administrator makes in the moment between DENIS's read and its write is overwritten; DENIS checks right before the first write that the interfaces still have what it read, and refuses if they do not.
* **Region.** One connector works in one region. An instance in another region is not found.

## What is verified

Only against the fake EC2 in `src/nac_aws/tests.rs`: the swap of every interface with its marks, a restore of exactly what was there (your own tags kept), the host block with its isolation group, finding the instance by address (none, two, a listing in pages), the protected list on the id and on every address of the instance, a swap already in place, a refused write, a refused tag (the swap is taken back), a lost answer, the second interface refused (the action is left partly applied until released), throttling (bounded), a lagging read (bounded), a restore that leaves a changed interface alone, prior groups too long for a tag, the old routes (same calls, same effect, rows from earlier versions), orphans found by mark and put back only when they carry it, the lab-switch refusals, and expiry. **Not verified on any real AWS account.**

Behaviours that are unproven vendor facts (marked **[verify]** in the code):

* `DescribeNetworkInterfaces` takes the filters `addresses.private-ip-address`, `ipv6-addresses.ipv6-address`, `attachment.instance-id`, `network-interface-id` and `tag:<key>`, and returns `tagSet`, `groupSet`, `attachment` and `privateIpAddressesSet`.
* `CreateTags` and `DeleteTags` work on a network interface id, and `DeleteTags` with a key and no value deletes the tag whatever its value.
* A throttled call is answered with the error code `RequestLimitExceeded` or `Throttling`.
* A security group change does not cut a connection that is already tracked, and a new connection is refused at once.
* The IAM resource ARNs in the policy above.

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
