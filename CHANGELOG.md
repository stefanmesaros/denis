# Changelog

## 0.3.0-rc.1: verify a fix, accept a risk

*Release candidate: used for a while before it becomes 0.3.0.*

Findings
* **Verify fix** on every finding: DENIS scans the devices again right now and says, per device, **fixed**, **still
  present**, **did not answer** (a silent device is never counted as fixed), **excluded** or **not scanned** (industrial
  devices are never probed; nor can a viewer-mode or passive-only console). Register findings (no owner, not reviewed,
  warranty…) are re-read from the register. The fresh port list is written to the register too.
* **Accept risk** (administrators): decide to live with a finding on chosen devices, with a required **reason** and
  an end date (30, 90, 180 days, a year, or until withdrawn). The device leaves the finding and appears under **Accepted
  risks** with who, when, why and how long is left; it comes back by itself when the time is up, and can be withdrawn
  at any time. Written to the audit log, listed in the printable report, counted in `/metrics`
  (`denis_accepted_risks`). API: `/api/risk-acceptances`, `/api/findings/{id}/verify`.
* Database schema v10 (accepted risks). Updating from 0.2.0 migrates it; the automatic backup taken before the update
  is the way back.

Releases
* The browser test of the console now also covers the Findings page (accepting needs a reason, withdrawing brings a
  finding back, Verify answers plainly).


## 0.2.0: everyday devices, a better asset editor, and release checks

Asset editor
* **Device type is a list**, sorted by name, with **Automatic (detected: …)** first; the icon follows the type, and
  **choosing an icon fills in the matching type**.
* **The icon chooser** opens from a **Change…** button right beside the icon: a searchable window with the icons grouped
  by kind. "robot" finds the vacuum, the lawn mower and the industrial robot.
* **40 new icons and device types** for what is common today: robot lawn mower, smart refrigerator, washing machine,
  dishwasher, oven, coffee machine, air purifier, air conditioner, heat pump, water heater, smart meter, battery storage,
  soundbar, AV receiver, smart display, VR headset, e-reader, baby monitor, pet feeder, smart scale, garage door opener,
  smart blinds, intercom, motion/door/leak sensors, weather station, drone, irrigation controller, NVR, digital signage,
  label printer, time clock, microcontroller, mini PC, management controller (BMC), wireless bridge, powerline adapter,
  vending machine, single-board computer. Discovery recognises many of them by name or manufacturer.
* **Fixed: the device type list could grow wider than its column and cover the field beside it** (Status). Fields now
  always stay inside their column, whatever the text.
* **Fixed: Status, Criticality and Purdue level showed no choices** (and the device type and icon lists were empty) after
  a first sign-in with a forced password change. The lists are now loaded again when missing.

Agents
* An agent **refuses a plain `http://` master address** (its token and data would cross the network readable) unless it
  is this machine or `--allow-plain-http` is given; the documentation explains how the agent channel is protected.

Releases
* **Stable and pre-release channels**: a tag with a hyphen (`v0.2.0-rc.1`) is published as a GitHub pre-release that the
  installer and the console's update check never offer. A candidate is used for a while, then re-tagged as stable.
* `tools/pre-release.sh` runs everything that must pass before a release, including a **browser test of the console**
  (`tools/ui-smoke.mjs`, also in CI and before every release build) and a check that a database from the newest
  published release opens with the new program.


## 0.1.3: installing as a service

* **`install.sh`**, attached to every release: on a Linux server it downloads the release for the machine, checks the
  Ed25519 signature and SHA-256, installs the program, the `denis` user and the systemd service, **picks a free port**
  (8443 or the next free one; 8080 is often taken), starts it and prints the address and the one-time admin password.
  Run it again to update (with a database backup first); `--uninstall` removes it; `--dry-run` only verifies.
* The installation guide starts from the GitHub release (no compiler), including a manual equivalent, port handling,
  changing settings in `/etc/denis/env`, updating, and what happens when a port is taken.
* The console's port is set with `DENIS_LISTEN` (like the other settings), so the unit no longer has to be edited. If
  the port is taken DENIS says so and exits; the unit stops retrying after five failed starts.
* The quick start and the README start from a downloaded release too.

## 0.1.2: OT command watches, rule exceptions, a tidier console

OT
* **OT command watches** (Rules page): alert when a specific command (an S7 CPU stop, a program download, any
  Modbus write, a DNP3 restart, a BACnet re-initialisation…) reaches specific devices, never from senders you allow
  (your engineering station). Ready-made watches for the common ones; works during the learning period.
* The communications matrix shows the **functions each path uses** ("Commands seen"); click one to watch for it.
* New rule `ot_write_escalation`: a path that only ever read starts writing.

Rules
* **Exceptions per rule**: devices, device types, tags or networks a rule stays quiet about (for industrial alerts the
  sender counts too).
* A **minimum score per rule**, and new settings: burst size and window, repeat gaps of the OT rules, how many Purdue
  levels apart count as skipping. *Reset* keeps your exceptions and watches.

Console
* New **Settings** page (branding, HTTPS certificate, updates, demo data and reset) and a separate **Audit log** page
  (filterable); **Users** now only holds users and API tokens.
* **My account** (click your name): password and passkeys moved out of the header.
* The console reloads as soon as an update has restarted it (it used to keep showing "Testing the new program").
* Database schema v9 (functions per path). Updating from 0.1.1 migrates it; the automatic backup taken before the
  update is the way back.

## 0.1.1: update test release

Nothing new in the program itself. This release exists to prove the self-update path end to end on a real
installation of 0.1.0: the update notice with these notes, the signature and checksum checks, the backup taken
before installing, the switch to the new program and the restart, with the data untouched.

Fixed
* The Linux build instructions now say that `libpcap-dev` is needed to build and that the pre-built program only needs
  the `libpcap0.8` runtime library; capturing needs `sudo setcap cap_net_raw,cap_net_admin=eip` on the program once.

## 0.1.0: first public release

Discovery and detection
* Passive discovery (ARP, DHCP, mDNS, SSDP, LLDP/CDP, PROFINET, TCP/IP stack) and polite active discovery.
* Explainable device typing and OS guessing, including DHCP option-list fingerprints.
* Rule-based, scored, tunable detections: new device, new destination, new port, volume, unusual hours, ARP
  conflict, silent device, rogue DHCP server, device bursts, threat-list match.
* Industrial (OT) support: passive decoding of Modbus, S7comm, EtherNet/IP-CIP, DNP3, BACnet, OPC UA and IEC
  60870-5-104; communications matrix; Purdue-level and unexpected-writer rules; never probes industrial devices.

Asset management
* Editable register (owner, location, serial number, warranty, criticality, tags, custom fields), 80+ icons,
  90+ device types, review queue, CSV import/export, change history, findings with fixes, coverage and
  standards mapping (CIS / NIST CSF / IEC 62443, as evidence).

Console and operations
* Web console with roles, passkey sign-in, API tokens, audit log, white-label branding, day/night/auto theme.
* Rules tab (view and tune every detection), built-in HTML documentation.
* Alerting to Slack, Microsoft Teams, Discord, PagerDuty, e-mail and a signed webhook; maintenance mode;
  syslog/CEF and OpenObserve export; Prometheus `/metrics`; `denis backup`.
* Optional built-in HTTPS, master/agent multi-site operation.

Also in this release
* **HTTPS by default** for the console and the agent port, with an automatically generated and renewed certificate
  (from a local DENIS authority) that can be replaced from the console. `--no-tls` for proxies and tunnels.
* Console in **English, German, French, Spanish and Slovak** (per-person choice, administrator default);
  collapsible **sidebar menu**; built-in **demo data**; **self-update** from signed GitHub releases with backup and
  automatic rollback; documentation with screenshots served inside the console.

Not yet verified or built: see the Status section of the README and ROADMAP.md.
