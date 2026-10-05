# Control coverage and posture history

**Findings → Coverage** shows which of your devices your management, directory, scanning and
endpoint-protection tools know about, matched by name or address. **Findings → Posture** keeps the
numbers DENIS already shows elsewhere once a day, so you can see whether things are getting better,
and lets an administrator set a target for any of them.

DENIS does not install agents, does not check whether an endpoint-protection product actually works,
and does not decide your policy. It shows where the tools you already pay for do not reach, and it
is explicit about the cases where it cannot tell. That distinction is the point of the whole page:

* **Not managed** means DENIS looked for this device in that tool and did not find it. The cell
  always says what was looked up: "No device called reception-pc in Intune (synced 3 hours ago)".
* **No match** means DENIS had nothing to look the device up by (no usable name, no address). It is
  *not* a gap and never raises a finding about a missing control; it is something to fix in your
  records.

Every integration this page rests on is **unverified**: each has been tested against recorded
samples of the tool's answers, not against a real installation (see the *unverified integration*
tag on every source card).

## Controls and sources

| Control | Answered by | Covered when the matched record… | Failing when… | Applies to |
|---|---|---|---|---|
| **MDM** | Intune, Jamf Pro | exists and is fresh | Intune reports it as not compliant | computers, laptops, mini PCs, thin clients, phones, tablets |
| **Directory** | Entra ID, Active Directory | exists and is fresh | the Entra record is only *registered*, not joined | computers, laptops, mini PCs, thin clients, servers, virtual machines, database servers, hypervisors |
| **Vulnerability scanning** | Nessus / Tenable.io | the scanner has a recent scan of the device's address | the newest scan is older than the limit (30 days by default) | every device with an address, except industrial devices (below) |
| **Endpoint protection (EDR)** | Microsoft Defender for Endpoint | exists, fresh and onboarded | the sensor is not active | computers, laptops, mini PCs, thin clients, servers, virtual machines, database servers |

Cloud inventory (Azure, AWS, GCP) is shown as context on a device but is not a control. A device's
owner and review state stay findings (`critical_no_owner`, `unreviewed`), not matrix columns.

A source manages only some platforms: Jamf, Apple; Active Directory, Windows; Defender, everything but
Android. DENIS reads the platform from its guess of the operating system (or the one you entered).
When the platform is known and no tool switched on for the control manages it, the cell reads
**Off**, not Not managed. When the platform is unknown, every tool counts.

The out-of-matrix devices are DENIS's own host, merged duplicates, and devices whose status is
*retired*, *lost* or *stolen*.

## The nine states of a cell

Judged in this order; the first that applies wins.

| State | Meaning |
|---|---|
| **n/a** | the control does not apply to this kind of device (a camera has no MDM) |
| **Off** | no tool for this control is switched on, or none of them manages this device's platform |
| **Unknown** | every switched-on tool for the control is out of date (nothing synced for twice its interval plus an hour) or has never synced. The cell says since when |
| **Covered** | a fresh tool has a record that matches the device |
| **Failing** | covered, but the tool says something is wrong (see the table above). Where several tools match (Intune and Jamf), any Covered wins |
| **Exempt** | an administrator accepted the risk of the finding this cell would raise, so the cell is shown as such and counted on its own |
| **Ambiguous** | the name the device is known by fits more than one device or record in at least one fresh tool, so it was matched to none of them |
| **No match** | the device has no usable name (only an automatic one, a UUID, `localhost`, a vendor default) and no address to look it up by |
| **Not managed** | DENIS could look the device up, and no record matched |

The **coverage percentage** of a control is covered ÷ (covered + failing + not managed). No match,
ambiguous, unknown, exempt and n/a are outside it and shown next to it, never hidden: the number is
about what could be checked.

Industrial (OT) devices read **n/a** for scanning unless an administrator ticks *Count industrial
(OT) devices toward vulnerability scanning* under *Coverage settings* on the Coverage page: active
scanning can upset fragile controllers. The same box sets how old a scan may be (1 to 365 days).

## How a device is matched to a record

One matcher serves the coverage view and every import, so the CMDB page, the device panel and the
matrix agree. The first rule that decides wins:

1. **Address** (for records that carry one, such as a scanner host): exactly one device currently has it.
2. **Full name**, exactly (case and a trailing dot ignored): exactly one device and exactly one record in that tool.
3. **Short name**: the first label of a name (`reception-pc` of `reception-pc.contoso.local`), when it
   is held by exactly one device and one record. A match this way is labelled "matched by short name".
   Active Directory stores fully qualified names while DHCP usually announces the short one, so
   without this rule an AD source would almost never match.
4. A name held by several devices or records is **ambiguous**, and the record matches none of them.
5. Otherwise, no match.

Nothing is fuzzy: no edit distance, no substring, no prefix beyond the first label. A device's names
are what it announces (DHCP, mDNS) and, last of all, the name entered in the register. A name typed
into the register is never the only basis for "Not managed": a device that announces no name of its
own reads No match. Records that match no device are listed under **In your tools, not seen by DENIS**
(for users who may see every site); they are often legitimate (a laptop that is away, a network DENIS
does not watch) and are never counted as gaps.

## Findings

| Finding | Severity | Raised for |
|---|---|---|
| `critical_unmanaged` | medium | a device rated high or critical that is *not managed* or *failing* in MDM or EDR |
| `not_vulnerability_scanned` | low | a device that is *not managed* or *failing* in scanning |
| `coverage_unmatched` | info | a device with *no match* or *ambiguous* anywhere: names to fix |

None is raised from Unknown, Off or n/a, and a missing name never creates a gap. Like every finding,
they get an instance per device, can carry a work item, and can have their risk accepted: the matrix
cell then reads **Exempt**. They create no exposure.

## Posture history

Once a day, shortly after midnight (after 00:15 console-local time), DENIS writes one row per site
that has devices, plus one for all sites together, each computed from its own devices (a median or a
percentage is not a sum). If the console was down at midnight it samples at its first opportunity
that day; a day it was down for entirely has no row and the chart shows a gap. History starts when
the feature does and is never reconstructed. Rows are kept for 1,100 days. Administrators can press
*Take a sample now* to replace today's rows, for example after a big clean-up.

A number that does not apply on a day is **absent**, never 0: no verified fix in 30 days, or a
control that nothing is switched on for. There is no composite score and no number is weighted
against another.

| Metric | Meaning | Better |
|---|---|---|
| Devices | devices in the register (not this host, not merged, not retired) | – |
| Devices that could not be identified / nobody has reviewed / critical with no owner | open findings of that kind, risk not accepted | lower |
| Devices with a high-severity finding | devices with an open high or critical finding | lower |
| Devices with a known-exploited vulnerability | devices on the exposure list for a known-exploited vulnerability | lower |
| Devices running unsupported software | open `eol_software` findings | lower |
| Devices on the exposure list | see the Dashboard | lower |
| Open incidents | not yet acknowledged | lower |
| Segmentation violations in the last 7 days | alerts above info | lower |
| Open / overdue work items | everything but verified / past the due date | lower |
| Median days to a verified fix | over items verified in the last 30 days | lower |
| Coverage per control (MDM, directory, scanning, EDR) | the coverage percentage | higher |
| Not managed / could not be looked up, per control | the cells in those states (no match and ambiguous together) | lower |

When the definition of a number changes (or one is added) DENIS raises its metrics version, and the
charts mark the first day counted the new way, so a change of definition is never mistaken for a trend.

## Goals

An administrator can set a target for one metric at one site (or all sites), optionally by a date.
A goal is **met** when the value is at or below the target (for a lower-is-better number) or at or
above it (higher-is-better). Beside every goal DENIS shows today's value, whether it is met, the
change over 7 and 30 days, and, when there is a due date, a plain pace sentence from the straight line
fitted to the last 30 samples (at least 7 are needed): "At the current pace (−0.4 a day) this reaches 5
around 12 November, after the due date of 1 November.", or "Moving away from the target.", or "Not
enough history yet". There are no probabilities. Goals are display only: nothing is notified when
one stops being met. A number that measures a size (the device count) cannot have a goal.

Goals and the all-sites row are visible only to people who may see every site; everyone else sees the
sites they may read.

## API

The endpoints are listed in [the API reference](api.md): `GET /api/coverage`,
`GET /api/coverage/unmatched`, `GET /api/assets/{id}/coverage`, `GET`/`PUT /api/coverage/settings`,
`GET /api/posture`, `POST /api/posture/sample` and the goal endpoints under `/api/posture/goals`.
The detection findings are listed in [Detection rules](detection-rules.md).
