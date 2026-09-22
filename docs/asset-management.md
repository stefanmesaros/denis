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

Clear a field by emptying it. Every change is recorded with **who, when, old value → new value** and shown under
**Change history** on the device page (admins also see the global **Audit log** page).

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

**Group by** (top of the Devices tab) splits the list into sections by **type**, **room** (location) or **owner**,
each with a count; devices with nothing entered for that field land in an "unset" group at the end. **Filters**
combines several conditions at the same time — type, room, vendor and owner (pick from what is actually in your
register) plus a substring of the OS guess — so "type is computer, room is Office 11, OS contains Unix" narrows to
exactly that. Both are per-browser and only change what is *shown*; **Devices CSV** always exports everything.

## CSV export and import

**Devices CSV** (a button on the Devices tab, next to **Import CSV**) exports every device, discovered and entered
columns together, regardless of any group-by or filter currently applied.

To **edit in a spreadsheet and import back**:

1. Export, open in Excel/LibreOffice/Google Sheets, edit the editable columns (`display_name`, `asset_tag`,
   `serial_number`, `owner`, `location`, `warranty_expires`, `tags`, `custom.<name>`…).
2. Save as CSV and click **Import CSV** (*editor* role).

Rules:

* The **`mac`** column identifies the device; it is required. Unknown MACs create manual assets.
* **Empty cells change nothing.** To clear a value use the edit form.
* Columns that describe discovery (`ip`, `vendor`, `risk_score`, …) may stay in the file; they are ignored.
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
