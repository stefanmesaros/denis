# Enforcement: WatchGuard Firebox

Status: **Experimental.** Everything below was built from WatchGuard's published API documentation and checked against a fake WatchGuard Cloud endpoint in DENIS's own tests. It has never been run against a real account or Firebox. Nothing here is listed as validated on hardware. Needs **Fireware v12.5.3 or higher** on the Firebox.

Lab use: the block (the pre-4.1 action, and the only action of this connector) is allowed only while an administrator has switched on *Allow Experimental connectors (lab use)* under *Settings → Response policy*. Because it is an action of the pre-4.1 kind, the second switch for new actions is not needed. Releasing it always works.

Besides this connector's own refusals, every action through it goes through DENIS's common guards before anything is sent: loopback, unspecified, broadcast and multicast addresses, DENIS itself, the gateway, and an address in an open `arp_conflict` alert are refused, and a list DENIS cannot read refuses the action.

## What each action does, and what it does not do

| Action | What DENIS does | What it does not do |
|---|---|---|
| **Block device** (`blocked_sites`) | Adds one IPv4 address to the Firebox's native **Blocked Sites** list through WatchGuard Cloud (`POST .../exceptions/blockedsite`, address type `ipv4_host`, action `block`, for the one configured device), reads the list back, and removes the entry (`DELETE`) when the action ends. | **IPv4 only**: WatchGuard documents no IPv6 address type for a blocked site, and a MAC address or a host name is refused. It never creates a range or a network. It does not close a connection that is already open: WatchGuard documents no call for that. |
| Block a connection | **Unsupported.** Blocked Sites works per address only, and DENIS uses no rule interface on this device. Shown greyed out with that reason. | |
| Quarantine | **Unsupported.** WatchGuard offers no group an administrator can reference through the interface DENIS uses. | |
| Disable port | **Unsupported.** A firewall has no access port DENIS can switch off. | |
| End sessions | **Unsupported.** This connector has no way to end sessions that DENIS uses. | |

Blocked Sites is dropped by the Firebox directly: unlike the other firewall connectors, no policy and no address group has to be made first.

## The WatchGuard Policy Manager model, and what "saved" means here

A Firebox can be managed from **WatchGuard Cloud**, locally with **WatchGuard System Manager's Policy Manager** (the configuration is edited as a copy and **saved to the Firebox**), or from its own Web UI. **DENIS talks only to WatchGuard Cloud's Firebox Management API, never to the Firebox.** That has two consequences, and the plan says both:

* **A block is "requested" until WatchGuard Cloud shows it reached the Firebox (4.6.1, read of the deployments since 4.6.2).** WatchGuard documents that a change saved in WatchGuard Cloud reaches the Firebox through a **deployment**, and that each deployment leaves a transaction record per device with its status (**documented**, not checked on a device). After the write DENIS reads the Blocked Sites list back and then the deployment records of this Firebox (`GET /v1/commands/<account>/transactions/?device=<device>&tx_type=deployment`, read only). The action is `enforced` only when the entry is on the list **and** a deployment of this Firebox with status `complete`, a confirmation date and not staged started after the entry was made (WatchGuard's own `created` time of the entry; when the answer has none, DENIS's time of the write plus two minutes for the difference between the clocks). Until then it is `unconfirmed` (*Not confirmed*) with "Requested: … WatchGuard Cloud shows no completed deployment to the Firebox since the entry was made …", or, when the deployment records cannot be read, "… DENIS could not read the deployments …". **Check now** and the hourly check confirm it once the deployment is there. **DENIS never deploys by itself**: a deployment sends every saved change of the Firebox, other people's too. Deploy the configuration to the Firebox in WatchGuard Cloud yourself.
* **A release is never held back, and says "released" only when it can.** The release takes the entry off the list at once (kill switch, cap and lab switches do not hold it). It is confirmed only when the entry is off the list **and** a completed deployment to this Firebox started at least two minutes (by DENIS's clock) after DENIS took it off. Until then the release ends as `rollback_failed` (still active; DENIS tries it again on its own) with the reason ("… WatchGuard Cloud shows no completed deployment to this Firebox since, so DENIS cannot tell whether the Firebox still blocks the address …"); the action stays open, and a later release (after you deployed) closes it without a second removal.
* **An entry that is no longer on the list is "cannot tell", never "gone" (4.6.2).** A check that finds the entry missing from WatchGuard Cloud's list does not close the action as removed elsewhere: the Firebox may keep it until the next deployment. The action stays as it was with "The entry is no longer on WatchGuard Cloud's Blocked Sites list …"; release it to end it.
* **To be confirmed on a device:** whether an entry on WatchGuard Cloud's list reaches the Firebox without a deployment, and whether a locally managed Firebox (one that needs *global exceptions* switched on for this API) leaves the same deployment records. If an entry is applied without a deployment, DENIS still says "requested" until a deployment record appears: the cautious side. The old *Block…* route of earlier versions keeps its earlier answer.
* **A save from an older copy removes the entry.** A Blocked Sites entry is part of the Firebox configuration. If an administrator opened the configuration in Policy Manager before DENIS wrote, and later saves it to the Firebox from that older copy, the entry is gone again (and an entry DENIS removed comes back). When the entry is gone from WatchGuard Cloud's list too, DENIS's periodic check says so ("cannot tell", see above); it does **not** write the entry again by itself. (WatchGuard documents that entries made through this API do not appear in Policy Manager for a locally managed Firebox; whether such a save removes them is to be confirmed on a device.) Agree with whoever uses Policy Manager that they refresh the configuration from the Firebox before they edit.
* A Firebox that is managed locally and merely **reports** to WatchGuard Cloud: WatchGuard lists the Blocked Sites API as supported for it, but DENIS has not seen it work **[verify]**. Test with a harmless address first.

## Setup

1. Make sure the Firebox is connected and reporting to a **WatchGuard Cloud** account (locally managed Fireboxes can be added for visibility without handing over configuration control).
2. In WatchGuard Cloud create API credentials: an **AccessID** and **access password** pair and an **API key** (Account → API Access, or as your WatchGuard Cloud plan documents it). Give the credential pair the least role that can manage the Blocked Sites exceptions of that one device **[verify role names]**.
3. Note the **account id** (shown in the account's own URL, such as `WGC-1-123abc456`) and the **device id or serial** of the one Firebox (such as `FBCL-12345`). A block always names one device: DENIS never creates an account-wide exception.
4. *Network → Equipment* → **WatchGuard** → **Add…**: the **base URL** (the regional cloud endpoint, such as `https://api.us.cloud.watchguard.com`), the Access ID, the access password, the API key, the account id, the device id, and the IP addresses never to block (DENIS itself, the gateway, your management addresses).

## Unblock, release and expiry

* A release lists the Blocked Sites entries, removes the entry of this address on this device, and reads the list again. On the **action path** it removes only an entry that carries DENIS's mark (see below): an entry that an administrator made by hand for the same address is never removed, and DENIS says so in the steps. The old *Unblock…* route removes the entry its own ledger row records, as before.
* A release the cloud refuses leaves the action active, flagged, and retried; it is never closed.
* **Expiry** rolls an action back after its duration, whatever the kill switch, the hourly cap and both lab switches say.
* The old routes (the *Block…* and *Unblock…* buttons of earlier versions) make **the same calls and write the same ledger row** as before: sign in, list, create (description `DENIS: <reason>`), list; the row records `ip`, `account_id`, `device_id` and `base_url`.

## Orphans, and the mark on the entry

An entry made on the action path has the description `DENIS managed; owner <tag>; action <id>`. It never contains the reason you typed: free text is not written to a device. The `<tag>` is this installation's own tag, so DENIS can tell its entries from another DENIS installation's and from yours. The hourly check lists entries with this installation's mark that no active action accounts for (*orphans*): they are shown, never removed automatically, and removing one needs your confirmation. Entries of the old routes carry `DENIS: <reason>` and are accounted for by their ledger row.

## Paging

The list answer carries a `more` flag. DENIS reads the first 500 entries. On the action path a list that says there is more is **refused**, because an entry past the first page would be invisible to the check for an existing block. The old routes keep their earlier behaviour.

## What is verified

Only against the fake endpoint in `src/nac_watchguard/orch_tests.rs` (and the earlier tests in `src/nac_watchguard.rs`): the old routes make the same calls, the same description and the same ledger row as the pre-4.1 code; refusal of IPv6, a MAC, a protected address and an unblock of an entry DENIS did not make; the action path's mark and the reason never reaching the device; an address already on the list; a list with more pages; an entry that is not DENIS's left alone on release; an entry that vanished from the list seen as "cannot tell" and not written again; a block confirmed only by a completed deployment after the entry, a release confirmed only by one after the removal, and both saying so when the deployments cannot be read; a lost answer on the create settled by the read-back; a refused create, a server error with and without the change applied; a release the cloud refuses and its retry; expiry ignoring the kill switch, the cap and both lab switches; orphans listed and removed by tag only; lab refusals sending zero requests; every unsupported action refused with zero requests. **Not verified on any real WatchGuard Cloud account or Firebox.**

Behaviours that are unproven vendor facts (marked **[verify]** in the code):

* Whether a Firebox that only reports to WatchGuard Cloud (locally managed) accepts this API against its account.
* Whether an entry created through the API is applied by the Firebox at once, or only through a deployment (WatchGuard documents the deployment; to be confirmed on a device), and how long that takes.
* The deployment records (`commands/<account>/transactions`, `tx_type=deployment`): their fields, which device id they carry, and that `complete` with a confirmation date means the Firebox applied the change. Whether the records come in pages and in which order, and that `inception_time` is in seconds: DENIS reads one answer; when it says there are more (`more`) and none of the records on it started late enough, DENIS says it could not read the deployments (never "no deployment"), and a start time more than 30 days after DENIS's own clock (a time in milliseconds, or a broken record) makes the whole answer unreadable (4.6.2, best guess for what WatchGuard Cloud answers).
* Whether `/oauth/token` also needs the `WatchGuard-API-Key` header (DENIS sends it there too).
* Paging past the first page, and the exact error answers (DENIS reads the HTTP status and the documented fields, never the wording of an error).
* Whether the API stores and returns the `description` of an exception as written (DENIS's mark relies on it).

## Limits

* One Firebox per connector instance.
* Traffic that never passes the Firebox (inside one switched network) is not affected.
* An open connection is not closed.

## Credentials

AccessID (plain configuration), access password (`nac.watchguard.access_password`) and API key (`nac.watchguard.api_key`), both in the encrypted secret store. They obtain an OAuth token from `/oauth/token`; a token is requested for each action and dropped when it ends. None of them is written to the ledger, the audit log or a notification.

## 4.5.0: releases and leftovers

* **The entry id is recorded** with the step that made the entry; the release removes exactly that entry, however long
  the account's list is (a 404 is "already gone"). Actions made before 4.5.0 are found by address as before.
* **Ownership is exact**: only an entry whose description is this action's own mark counts as DENIS's on the action
  path (another install's entry, another action's or an old route's does not).
* **Leftovers can be removed**: they are listed as `denis-<tag>-<action>-blockedsite-<address>`, which the shared
  removal on the Health page accepts.
