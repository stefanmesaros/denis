# Enforcement: WatchGuard Firebox

Status: **Experimental. Simulator only: not yet validated on real equipment.** Everything below was built from WatchGuard's published API documentation and checked against a fake WatchGuard Cloud endpoint in DENIS's own tests. It has never been run against a real account or Firebox. Nothing here is listed as validated on hardware. Needs **Fireware v12.5.3 or higher** on the Firebox.

Lab use: the block (the pre-4.1 action, and the only action of this connector) is allowed only while an administrator has switched on *Allow connectors that are not validated on real equipment (lab use)* under *Settings → Enforcement*. Because it is an action of the pre-4.1 kind, the second switch for new actions is not needed. Releasing it always works.

Besides this connector's own refusals, every action through it goes through DENIS's common guards before anything is sent: loopback, unspecified, broadcast and multicast addresses, DENIS itself, the gateway, and an address in an open `arp_conflict` alert are refused, and a list DENIS cannot read refuses the action.

## What each action does, and what it does not do

| Action | What DENIS does | What it does not do |
|---|---|---|
| **Block device** (`blocked_sites`) | Adds one IPv4 address to the Firebox's native **Blocked Sites** list through WatchGuard Cloud (`POST .../exceptions/blockedsite`, address type `ipv4_host`, action `block`, for the one configured device), reads the list back, and removes the entry (`DELETE`) when the action ends. | **IPv4 only**: WatchGuard documents no IPv6 address type for a blocked site, and a MAC address or a host name is refused. It never creates a range or a network. It does not close a connection that is already open: WatchGuard documents no call for that. |
| Block a flow | **Unsupported.** Blocked Sites works per address only, and DENIS uses no rule interface on this device. Shown greyed out with that reason. | |
| Quarantine | **Unsupported.** WatchGuard offers no group an administrator can reference through the interface DENIS uses. | |
| Disable port | **Unsupported.** A firewall has no access port DENIS can switch off. | |
| End sessions | **Unsupported.** This connector has no way to end sessions that DENIS uses. | |

Blocked Sites is dropped by the Firebox directly: unlike the other firewall connectors, no policy and no address group has to be made first.

## The WatchGuard Policy Manager model, and what "saved" means here

A Firebox can be managed from **WatchGuard Cloud**, locally with **WatchGuard System Manager's Policy Manager** (the configuration is edited as a copy and **saved to the Firebox**), or from its own Web UI. **DENIS talks only to WatchGuard Cloud's Firebox Management API, never to the Firebox.** That has two consequences, and the plan says both:

* **DENIS confirms the entry on WatchGuard Cloud's list, not on the Firebox.** After the write DENIS reads the list back; when the entry is there, the action is `enforced`. DENIS cannot see, through this API, whether and when the Firebox itself has applied the entry. When the read-back does not show the entry, the action is recorded as `unconfirmed`, never as enforced. After the first real use, check the Blocked Sites list on the Firebox itself.
* **A save from an older copy removes the entry.** A Blocked Sites entry is part of the Firebox configuration. If an administrator opened the configuration in Policy Manager before DENIS wrote, and later saves it to the Firebox from that older copy, the entry is gone again (and an entry DENIS removed comes back). DENIS's periodic check notices that the entry is missing, records the action as `restored_elsewhere` and says so; it does **not** write the entry again by itself. Agree with whoever uses Policy Manager that they refresh the configuration from the Firebox before they edit.
* A Firebox that is managed locally and merely **reports** to WatchGuard Cloud: WatchGuard lists the Blocked Sites API as supported for it, but DENIS has not seen it work **[verify]**. Test with a harmless address first.

## Setup

1. Make sure the Firebox is connected and reporting to a **WatchGuard Cloud** account (locally managed Fireboxes can be added for visibility without handing over configuration control).
2. In WatchGuard Cloud create API credentials: an **AccessID** and **access password** pair and an **API key** (Account → API Access, or as your WatchGuard Cloud plan documents it). Give the credential pair the least role that can manage the Blocked Sites exceptions of that one device **[verify role names]**.
3. Note the **account id** (shown in the account's own URL, such as `WGC-1-123abc456`) and the **device id or serial** of the one Firebox (such as `FBCL-12345`). A block always names one device: DENIS never creates an account-wide exception.
4. *Settings → Enforcement* → **WatchGuard** → **Add…**: the **base URL** (the regional cloud endpoint, such as `https://api.us.cloud.watchguard.com`), the Access ID, the access password, the API key, the account id, the device id, and the IP addresses never to block (DENIS itself, the gateway, your management addresses).

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

Only against the fake endpoint in `src/nac_watchguard/orch_tests.rs` (and the earlier tests in `src/nac_watchguard.rs`): the old routes make the same calls, the same description and the same ledger row as the pre-4.1 code; refusal of IPv6, a MAC, a protected address and an unblock of an entry DENIS did not make; the action path's mark and the reason never reaching the device; an address already on the list; a list with more pages; an entry that is not DENIS's left alone on release; an entry that vanished (a save from an older copy) seen as gone and not written again; a lost answer on the create settled by the read-back; a refused create, a server error with and without the change applied; a release the cloud refuses and its retry; expiry ignoring the kill switch, the cap and both lab switches; orphans listed and removed by tag only; lab refusals sending zero requests; every unsupported action refused with zero requests. **Not verified on any real WatchGuard Cloud account or Firebox.**

Behaviours that are unproven vendor facts (marked **[verify]** in the code):

* Whether a Firebox that only reports to WatchGuard Cloud (locally managed) accepts this API against its account.
* Whether an entry created through the API is applied by the Firebox at once, or needs a push or a save, and how long that takes.
* Whether `/oauth/token` also needs the `WatchGuard-API-Key` header (DENIS sends it there too).
* Paging past the first page, and the exact error answers (DENIS reads the HTTP status and the documented fields, never the wording of an error).
* Whether the API stores and returns the `description` of an exception as written (DENIS's mark relies on it).

## Limits

* One Firebox per connector instance.
* Traffic that never passes the Firebox (inside one switched network) is not affected.
* An open connection is not closed.

## Credentials

AccessID (plain configuration), access password (`nac.watchguard.access_password`) and API key (`nac.watchguard.api_key`), both in the encrypted secret store. They obtain an OAuth token from `/oauth/token`; a token is requested for each action and dropped when it ends. None of them is written to the ledger, the audit log or a notification.
