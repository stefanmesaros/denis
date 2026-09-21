# Changelog

## 0.4.0-rc.2: Pushover and ntfy, and a fix for moving table columns

*A release candidate on top of 0.4.0-rc.1.*

* **Pushover** and **ntfy** notification channels (*Alerting* → *Add a channel*). Pushover: an application token and a user or
  group key; high alerts go as high priority. ntfy: the address of your topic on ntfy.sh or your own server, and an access token
  for a protected topic (never sent over plain `http://`); published as JSON, so device names with any characters are safe.
  Secrets are write-only, as for the other channels.
* Fixed: **moving a table column a second time put the headings over the wrong data.** The first move worked, later ones did not.
  The browser test now moves columns several times and checks every heading against its data.
* Fixed a test that assumed the machine running it has no SSH server (the CI runners do).

## 0.4.0-rc.1: reports, health, two-step sign-in, real topology, software versions

*A release candidate: use it for a while on a real network before it becomes 0.4.0.*

Reports
* **Reports** is its own page. A report (devices, findings, accepted risks, alerts, trends and the compliance overview)
  is **kept on the server** and can be opened, downloaded as one HTML file, printed or deleted at any time. Make one by hand
  (7 days to a year) or on a **schedule** (weekly or monthly, keeping the newest N; hand-made ones are never removed). The old
  "Printable report" link is gone (`/report` still gives a live one).
* **Compliance** now maps to **NIS2 Article 21**, **ISO/IEC 27001:2022 Annex A** and **NIST SP 800-82 Rev. 3** (through its
  SP 800-53 controls), next to CIS v8, NIST CSF 2.0 and IEC 62443-3-3.

Health and backups
* **Health** page: is DENIS itself in good shape? Packets dropped, database size (and free space in it), free disk, how late the
  sweeps are, rows per table, with a plain sentence for each problem and a count in the menu. New `/metrics`: `denis_database_bytes`,
  `denis_disk_free_bytes`, `denis_capture_dropped_packets`, `denis_backup_age_seconds`, `denis_health_warnings`.
* **Scheduled backups** of the database: **on by default, every day, keeping 7** (change or switch off under Health). List,
  download (administrators only: a backup holds password hashes and authenticator secrets), delete, *Back up now*. Refused when the
  disk could not hold a copy; a warning appears when the newest backup is too old.

Findings
* **Accepted risks are watched**: an event 14 and 3 days before a decision ends, one when it has ended, a daily rescan of the
  open-port ones, and a note (event and audit entry) when the problem has gone away. Nothing is withdrawn automatically.
* **Software versions from banners**: DENIS reads the SSH, FTP and SMTP banner and the web server headers of the ports its scan found
  open and takes a product and version from them. **End of support** (nginx, Apache HTTP Server, PHP, OpenSSL, Exim, ProFTPD, from
  endoflife.date) and **known exploited vulnerabilities** (CISA KEV, with NVD version ranges: nine today, for Apache HTTP Server, PHP
  and Exim) become findings that list, per device, what was read and what it means. No version, no claim. A banner that names a
  distribution is worded "may have been fixed", because distributions backport fixes. The data ships in the program
  (`data/vulndata.json`, built by `tools/build-vulndata.py`); the support dates can be refreshed from endoflife.date (off by default).
  *Verify fix* rescans and reads the banner again.

Detection
* **Network watches** (Rules → *Your network watches*): like the OT command watches, for ordinary traffic. Devices you choose
  (a device, type, tag or network) talking to addresses or ports you did not allow: *only these* / *except these* lists of ports and
  of addresses (`public`, `private`, networks), a protocol, a minimum amount of data, a score and a cooldown. Presets included. New
  rule `it_watch`; it also fires during the learning period.

Sign-in
* **Authenticator app (TOTP)** for everybody: *My account* → set up with a QR code, ten one-time recovery codes, a code after the
  password at sign-in. Each code works once, a wrong code never resets by re-entering the password, five wrong codes void the ticket
  and lock the account like wrong passwords. **Passkeys already count as two factors.** Administrators can **require** a second step for
  administrators or everybody (*Settings* → *Sign-in security*) and **reset** somebody's after a lost phone. The secret is stored in the
  database (a code cannot be checked against a hash): guard backups like the database. See [Security](docs/security.md).
* Fixed: typing a wrong current password when changing your password signed you out ("Your session has ended").

Topology
* **Switches and cables**: add switches (*Settings* → *Switches (SNMP)*, SNMP **v2c**, read only) and the Topology tab shows which port
  each device is plugged into (MAC learned on an access port, never an uplink) and how the switches are cabled (LLDP), and a device's
  panel says **Connected to**. Reads IF-MIB, LLDP-MIB and Q-BRIDGE/BRIDGE-MIB; never sets anything; the community is write-only in the API.
  **Not verified against real switches** (tested with two independent stand-in agents and byte-level checks); **SNMPv3 is not supported yet**.
  See [Switches (SNMP)](docs/switches.md).

Console
* **Table columns**: every table can hide and show columns, reorder them (arrows or drag a heading) and resize them (drag the edge),
  remembered per table in the browser.
* **Setup guide** for a new installation: a checklist (network, sign-in security, notifications, colleagues, backups, branding) whose
  items turn green only when they are really done. It opens once for an administrator, and again from *Settings*.

Under the hood
* Database schema v13 (reports, authenticator secrets and recovery codes, switch snapshots). Updating from 0.3.0 migrates it; the
  automatic backup taken before the update is the way back.
* The browser test now also covers reports, health and backups, table columns, the setup guide, network watches, a real sign-in with
  the authenticator app (set-up, code step, recovery code, required set-up), a switch read over SNMP by an independent agent, and the
  software findings.

## 0.3.0: verify a fix, accept a risk

*Used for a while as 0.3.0-rc.1 on a real network before this release.*

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
