# Asset management

DENIS keeps two kinds of information about a device, deliberately apart:

* **Discovered**: what the network shows (MAC, IPs, hostnames, ports, fingerprints). It updates itself.
* **Entered**: what you know (name, owner, serial number…). DENIS **never overwrites it**, however often the
  device is rescanned.

Where they disagree, *your value wins*: a corrected device type or OS is used in the list, the risk score,
exports and reports (the original guess stays visible as "Discovery guessed…").

## Editing a device

Open a device (click its row) → **Edit asset** (needs the *editor* role).

| Field | Purpose |
|---|---|
| Name | shown everywhere instead of the discovered hostname |
| Icon | 120+ icons in ten groups (computers, network, office, video and audio, smart home, appliances and robots, energy, industrial…). The **Change…** button sits right beside the icon and opens a window you can search ("robot" finds the vacuum, the lawn mower and the industrial robot); *Automatic* picks the icon that fits the device type. Choosing an icon also sets the matching device type |
| Device type | a list of 120+ types, sorted by name. The first entry, **Automatic (detected: …)**, keeps following what discovery finds; pick another to correct a wrong guess (the icon follows, unless you chose one by hand). Choosing an icon fills in the type that goes with it |
| Operating system, Manufacturer | correct a wrong guess (free text) |
| Status | `active`, `spare`, `retired`, `lost`, `stolen` |
| Criticality | `low`, `normal`, `high`, `critical`: how much this device's alerts weigh in its risk |
| Owner, Department, Location | who is responsible and where it is |
| Zone / cell, Purdue level | network zone; Purdue level (0–5, 3.5 = DMZ) for industrial assets |
| Asset tag, Serial number, Model, Supplier | inventory identifiers |
| Purchase date, Price, Warranty until | lifecycle |
| Silence notifications until | no chat/e-mail/PagerDuty alerts about this device until the end of that date (alerts still show in the console) |
| Tags | free labels (stored lower-case) |
| Notes | free text |
| Custom fields | any name/value pairs you need ("Cost centre", "VLAN"…) |

Clear a field by emptying it. Every change is recorded with **who, when, old value → new value** and shown on the
**History** tab of the device page (admins also see the global **Audit log** page).

## The review queue

Discovery finds devices; only a person can say *"yes, that belongs here"*. Every device starts as **not reviewed**.
On the Devices tab tick **needs review** to see them (the number in brackets is how many). New arrivals also carry a
small **new** tag for their first two weeks.

* Open a device and press **Mark as known**, or **Edit asset** and save (saving marks it reviewed).
* Accepted a whole list? Filter, then **Mark all shown as known**.
* Devices you add by hand count as reviewed.

The **Findings** tab lists devices still waiting, and the **Compliance** tab measures how much of the register a
person has looked at, which is what an auditor asks for ("how do you address unauthorized assets?").

## Devices that are not on the network (yet)

**+ Add asset** registers a device by hand, for a spare laptop in a cupboard, a rack switch that is off, or
a device you know is coming. MAC address is optional:

* With a MAC, DENIS will *adopt* the record when the device shows up, and it is **not** reported as a "new device".
* Without one, DENIS gives it a private placeholder address (`02:54:42:…`); you can create a new record with
  the real MAC later.

Manually created assets are marked **manual**; an *admin* can delete them (discovered devices cannot be deleted,
they would simply reappear: set their status to `retired` instead).

## Lifecycle and status

* Devices with a **warranty** that expired or expires within 60 days are listed in the report under
  *Lifecycle: needs attention*, and the device page shows a countdown.
* A device with status **lost** or **stolen** is listed in the same section.
* Retired/spare devices are expected to be offline and never raise "went silent" alerts.

## Grouping and filtering the list

**Group by** (top of the Devices tab) splits the list into sections by **type**, **location** or **owner**,
each with a count; devices with nothing entered for that field land in an "unset" group at the end. **Filters**
combines several conditions at the same time — type, location, vendor and owner (pick from what is actually in your
register) plus a substring of the OS guess — so "type is computer, location is Office 11, OS contains Unix" narrows to
exactly that. Both are per-browser and only change what is *shown*; **Devices CSV** always exports everything.

On a large network the list is rendered lazily: past a few hundred devices, filtering, sorting and grouping still
run over every device, but only the rows near where you are scrolled are actually drawn, so the table stays smooth
with thousands of devices. Smaller networks look and behave exactly the same as before.

## CSV export and import

**Devices CSV** (a button on the Devices tab, next to **Import CSV**) exports every device, discovered and entered
columns together, regardless of any group-by or filter currently applied.
The `ipv6` column lists the device's IPv6 addresses (most recent first, separated by semicolons); it is empty unless DENIS runs with `--ipv6`, and the import ignores it.

To **edit in a spreadsheet and import back**:

1. Export, open in Excel/LibreOffice/Google Sheets, edit the editable columns (`display_name`, `asset_tag`,
   `serial_number`, `owner`, `location`, `warranty_expires`, `tags`, `custom.<name>`…).
2. Save as CSV and click **Import CSV** (*editor* role).

Rules:

* The **`mac`** column identifies the device; it is required. Unknown MACs create manual assets.
* **Empty cells change nothing.** To clear a value use the edit form.
* Columns that describe discovery (`ip`, `vendor`, `risk_score`, …) may stay in the file; they are ignored.
* **`site`** is optional: `local`, a site name or a site id (an export writes the name). It picks the device when
  the same MAC is known at several sites (without it such a row is refused), and sets the site of a new manual
  record (without it, the local site). An unknown site, or a name two sites share, is a row error. Every row is
  checked against your access to its site: a row for a site you may only read is refused with its own error and
  the other rows are still applied.
* `tags` are separated by `;`. Custom fields use a `custom.` prefix and keep their capitalisation.
* Dates are `YYYY-MM-DD`. `status`, `criticality`, `icon`, `purdue_level` must be valid values.
* The file must be ≤ 5 MB and ≤ 5000 rows. A summary shows how many rows were created, updated, unchanged
  and which lines had problems (with the reason). Good rows are still applied.
* Importing the same file twice changes nothing.

**Safety:** names come from the network and can contain formulas. In exports, cells that start with `=`, `+`,
`-` or `@` are prefixed with an apostrophe so a spreadsheet will not execute them; the import removes it again.

## Searching

The filter box on the Devices tab searches IP, MAC, name, vendor, type, OS, ports, site **and** owner, serial
number, asset tag, location, department, zone, status and tags.

To find out **which device had an address at a given time**, type the address, an `@` and the time into the same box:
`10.0.20.15 @ 2026-10-21 14:02` (your local time). DENIS lists every device that used the address within five minutes
of that time, with the window each had it, the switch port it was seen on then, and the devices that used it
afterwards. When more than one device is listed (a DHCP lease that moved), compare the windows: DENIS never picks one
for you. A device that forwards traffic for others (a router, a firewall) is marked, because the address may belong to
a machine behind it.

## The History tab

The **History** tab of a device puts everything DENIS knows about the device in one list, newest first, 200 entries a
page ("Show older entries" reads the next page). It reads the tables DENIS already keeps and stores nothing new:

![The History tab of a device](img/device-timeline.png)

| Group | What it shows | Where it comes from |
|---|---|---|
| Addresses | an address started being used, was last seen | the device's IPv4 and IPv6 history |
| Port and VLAN | the switch port it was seen on, moves, VLAN changes | the switch port tables and the change log |
| Contacts | first contact with a peer (once per day and per peer device), first contacted by | the traffic relationships |
| Alerts and events | alerts, quiet alerts, other events, fingerprint changes | events |
| Incidents | an incident opened for the device | incidents |
| Responses | what DENIS or a person did to the device and each step | the enforcement ledger |
| Identity | interfaces linked, copies merged, suggestions and what was decided | device links, merges, suggestions |
| Changes | edits, acknowledgements and other state changes | the audit log and the decision log |

Each entry says where it comes from (a sensor, a switch, a connector, a person, DENIS) and how DENIS knows it
(observed, reported by another system, inferred, entered or decided). A device made of several interfaces shows the
history of all of them. A device on a site you may not read is not found, and a peer or a suggested partner on such a
site is left out of the entries, as it is everywhere else. The filter buttons and the period select narrow the list.

Events, alerts and port movements older than the retention period (Settings → Data → Data retention, 90 days unless you
changed it) are deleted, and the tab says so at the end of the list. Addresses, "first seen" and "last seen" are never deleted.
Not in the list: hostname changes and changes of the "is anything managing this device" answer, which DENIS does not
store.

## Details from the console

Explanations that used to be printed on the console screens. The console shows a short version behind the small (i) button after the label it explains; "More in the docs" in it leads here.

* Who has sent and received the most since their traffic baseline started — a live leaderboard, not a chart over time. The gateway and this monitoring host are left out automatically; click × on a device to hide it from these three lists too.
* Cross-references DENIS's own discovery against inventory pulled from these sources — matched by hostname, shown as extra context, never written back and never used to override a device's own fingerprinted identity.
