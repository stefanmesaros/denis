# Changelog

## 1.13.2: one-click "create an exception" from an alert

* **Alerts now have an "Except" action** (next to Acknowledge, and in the alert's own detail
  dialog), for administrators: one click stops that exact situation alerting again, without a
  trip to the Rules page.
  * An ordinary rule (`new_destination`, `volume_anomaly`, `arp_conflict`, ...): adds a
    device-scope exception on that rule for the alerting device — the same list the Rules page's
    own per-rule *Exceptions* section shows.
  * A network watch (`it_watch`): adds the alerting device to that watch's own exceptions.
  * An OT command watch (`ot_command_watch`): adds the *sender* (who sent the command) to that
    watch's allowed senders — looked up by MAC, since the alert only ever carried the sender's
    MAC/IP/name, not its id; an unrecognised sender says so plainly instead of doing nothing.

## 1.13.1: clearer watch forms, five worked rule examples, support dates refresh on by default

* **Rules page: clearer OT command watch / network watch forms.**
  * "Start from a common watch…" no longer appears when *editing* an existing watch — it has no
    saved value to reflect (a preset only ever pre-fills fields once), so showing it there just
    looked like a forgotten setting. Only shown when adding a new watch, and now labelled to say
    what it does.
  * "Enabled" moved to the top of the form (was the last field) and relabelled "Watch enabled".
  * "Never for these senders"/"Never for these devices" are now a collapsed section, opened
    automatically only when already in use — most watches never need it.
  * Every place that names a rule needing `--flows` now carries a `*` with a tooltip, and shows a
    highlighted warning specifically when traffic analysis is not currently running, instead of
    static prose that reads the same whether it applies right now or not.
* **Five worked examples for network watches** added to the docs, including the specific
  "does this device talk to others on the network it shouldn't" allow-list pattern.
* **Support dates (end-of-support software) now refresh from endoflife.date on their own by
  default** on a fresh install, instead of requiring an administrator to find the switch under
  Settings → Software data first. Still just the one public site, nothing about your network
  sent, and still a plain toggle to turn off. Existing installs keep whatever they already chose.

## 1.13.0: SIEM export (CEF/LEEF/JSON, GUI-configurable), a big internal refactor, six review fixes

* **New: SIEM / log export**, fully configurable from Settings, no restart needed. Send events
  and alerts, standing findings and/or the audit log — independently — as syslog, in **CEF**,
  **LEEF** or plain **JSON**, over **UDP**, **TCP** or **TLS** (encrypted; a self-signed
  collector's certificate can be trusted without verification, for setups with no public CA). A
  "Send a test message" button checks a target before saving it. The previous `--syslog` CLI flag
  (CEF, alerts only) still works — it now just seeds this setting the first time nothing has been
  saved yet, after which the console is authoritative.
* **Fixed: a mistyped network interface name could crash-loop the whole program.** `PUT
  /api/interfaces` validated everything about the request except whether the name actually exists
  on the machine; a typo saved cleanly and only failed on the next restart, which under
  `systemd`'s `Restart=always` is a crash-loop from one keystroke. It is now checked against the
  same interface list the page itself offers.
* **Fixed: a license-expiry alert could be silently lost.** The "already alerted for this stage"
  marker was written before the alert was actually sent; on the very first check after start-up
  (before the self-host device exists yet) that meant the marker was set with nothing sent, and
  since later checks only alert on a *change* of stage, the warning for that stage never went out
  for the life of the process.
* **Fixed: a down MSP backup upload wasted a whole schedule interval per failure**, even though
  the loop checks every 15 minutes regardless of the configured schedule. The upload slot is now
  only consumed once a send actually succeeds.
* **Fixed: an unmodified local backup was re-uploaded to the MSP on every due check** when the
  local backup schedule was slower than the upload one (e.g. weekly local, daily upload — the
  default). On the MSP side, uploads are named by arrival time and the retention count does not
  look at content, so this could fill an MSP's entire retention window with copies of one backup
  instead of real history. Re-sending is now skipped when the content has not changed.
* **Fixed: a mirror/SPAN interface on a different subnet or VLAN than the main one produced
  nothing at all** — no flows, no industrial-protocol decoding, no error — because every capture
  thread used the main interface's own subnet to decide what counted as "local", exactly the
  scenario `--mirror-iface`'s own documentation describes ("one per VLAN"). A new `--mirror-subnet
  <CIDR>` (repeatable) tells DENIS about a VLAN it cannot detect on its own; a mirror interface
  that does have its own address is now detected and added automatically, and one with neither
  logs a warning at start-up instead of failing silently.
* **Fixed: a device merged from one site into another could leak to a user restricted to the
  other site.** `GET /api/assets/{id}/merged` checked the canonical device's own site access but
  not each merged sibling's — a sibling that had since been re-observed on a site the caller
  cannot see would still hand over its MAC and timestamps.
* **Internal refactor** (no behaviour change other than the fixes above): the `Shared`
  collector-status struct and the `Store` trait (previously one 85-method trait) are now each
  split into narrow, independently-usable pieces; the `web` module's import cycle with its
  `web_*` handler modules is gone; per-site access grants moved out of a JSON blob under
  `settings` into their own database table with a real foreign key, replacing a fail-open default
  (an unreadable settings row used to mean full access for everyone) with fail-closed.

## 1.12.0: merge duplicate devices, a real SNMP port list, two live bugs fixed

* **"This is the same device as…"**: a device seen under more than one MAC address (an access
  point broadcasting several SSIDs, typically its most common cause) can now be merged into
  another one from its detail panel. The merged device disappears from the devices list and
  findings; its own history is kept, not deleted, and it comes straight back the moment you
  undo it (Settings is not involved: it is a per-device action, "Unmerge" shown right on the
  canonical device's panel under "Also known as").
* **Switches (SNMP): the port list is now shown even when the forwarding table is not**, for
  switches (some cheap "smart" models especially) that answer IF-MIB fully but do not implement
  a readable MAC table at all — you at least get port names, aliases and up/down status, which
  is the most such a switch will ever give.
* **Fixed: a mirror interface set from Settings → Network interfaces did not actually turn flow
  accounting on** (`flows_enabled` stayed `false` in `/api/status` even with a mirror interface
  configured and running) — the GUI override replaced the interface list *after* the CLI's own
  `--flows` implication had already run, so it was never re-derived. Detection was not affected
  (it never checked the flag), but the console's own status display was misleadingly wrong.
* **Fixed: Topology → "Switches and cables" could show a literal "null"** on the page — one
  render path passed `null` straight to the browser's `replaceChildren`, which stringifies it
  instead of skipping it. Caught after the fact by a real report; the smoke test that exercises
  this exact view now checks for it directly, not only after navigating away from the page.
* Removed the global `window.fetch` monkey-patch in favour of an explicit `apiFetch()` — every
  caller is now findable by name instead of the CSRF/401-handling behaviour being an invisible
  side effect of calling the browser's own `fetch`. No behaviour change.

## 1.11.0: more ports, ICS-CERT advisories, EPSS scores, and five more compliance standards

* **More ports scanned and risk-scored**: Kerberos, legacy r-services (rexec/rlogin/rsh), a SOCKS
  proxy, OpenVPN, container/orchestration (Docker already covered; now Kubernetes' API server and
  kubelet), message queues (RabbitMQ, Kafka), monitoring stacks (Prometheus, Kibana) and IRC (a
  common sign of a compromised device "phoning home").
* **CISA ICS-CERT advisories**: a new, separate finding for industrial devices — "the manufacturer
  has an open ICS-CERT advisory" — matched only by vendor name (Siemens, Schneider Electric,
  Rockwell Automation, …), never by firmware version, since that is not read passively. Explicitly
  conservative: it never claims a specific device is affected, only that its manufacturer has an
  open advisory worth checking against the exact model and firmware.
* **EPSS scores**: known-exploited-vulnerability findings now carry FIRST.org's EPSS score — a
  modelled probability of exploitation in the next 30 days — alongside the existing CVE and
  ransomware-use context, to help prioritise among several open findings.
* **Five more compliance standards**: DORA, PCI DSS v4.0, the HIPAA Security Rule, SOC 2 (Trust
  Services Criteria) and CMMC 2.0 (via NIST SP 800-171) join the existing CIS Controls v8, NIST
  CSF, IEC 62443-3-3, NIST SP 800-82, ISO/IEC 27001 Annex A and NIS2 mapping on the Compliance
  page — the same underlying evidence (inventory completeness, monitoring, MFA, audit log), shown
  in each standard's own words and control references.

## 1.10.0: security and reliability fixes from an architectural audit

* **Fixed: a device's own endpoints were not site-scoped** (IDOR). `/api/assets` already filtered
  by site access, but `/api/assets/{id}`, its `/baseline` and `/history` did not — a viewer
  restricted to "none" on a site could still read a device's full record, traffic baseline and
  edit history directly by id (sequential integers, trivially enumerable). Only matters for
  installs that use per-site access (MSP deployments). Also fixed the same gap in `POST
  /api/findings/{id}/verify`. Every case now answers 404 for both "does not exist" and "exists but
  you cannot see it", so existence itself is never leaked.
* **Fixed: a single panic could wedge every request until restart.** The whole database sat behind
  one lock; a panic anywhere while it was held "poisoned" it, and every request afterwards (from
  any user) panicked too, forever. A poisoned lock now recovers instead (the data behind it is
  still consistent either way), for the database connection and every simple status/cache lock.
  Left deliberately as-is, with a comment, wherever recovering could paper over real inconsistency
  (the in-memory device register and detector state).
* **Fixed: declared foreign keys were never enforced**, and deleting a disabled user left their
  per-site access grants behind forever (they live in a settings blob, not a table, so no FK ever
  caught them). Foreign keys are now actually on; `delete_user` cleans up its grants in the same
  transaction.

## 1.9.0: browse customers' uploaded backups from the console; several mirror interfaces at once

* **Settings → Health → "Customers' uploaded backups"**: an MSP can now find and download a given
  customer's uploaded backups right from the console (with a delete button for freeing space by
  hand) — no SSH access to this server needed, e.g. right after a customer reports being hit by
  ransomware. Admin-only, like local backups: these files hold other people's password hashes too.
* **`--mirror-iface` is now repeatable**: pass it more than once for more than one mirror/SPAN
  interface — one per VLAN, say, each fed from its own switch mirror port into its own NIC on the
  same server, all decoded into the same flow accounting and device register. Settings → Network
  interfaces gained a multi-select for it. This still does not run independent ARP discovery per
  VLAN (that remains `denis agent`, one per network) — it is for flow/traffic visibility across
  several networks from one box, not for separate device registers per network.
  See [Deployment](docs/deployment.md#one-or-more-mirror-port-interfaces-for-whole-network-flow-visibility).

## 1.8.0: independent backup upload schedule; retention for customers' backups at the MSP

* **Settings → Health → "Uploading to your MSP"**: how often the newest local backup is pushed to
  a configured `--backup-upstream` is now its own schedule (manually only / every 8 hours / every
  12 hours / every day / every week), independent of the local backup schedule above it. It never
  makes a new backup by itself — it just pushes whatever the newest one already is, when due.
  Shown only once `--backup-upstream` is actually configured. Upgrading changes nothing for a
  default install (daily local backups still upload daily, as before).
* **Local backup schedule** gains **every 8 hours** and **every 12 hours**, alongside the existing
  daily/weekly/off.
* **Settings → Health → "Customers' uploaded backups"**: an MSP's own setting for how many of each
  customer's uploaded backups to keep under `backups/from-agents/<id>/` (default 10; older ones
  are pruned automatically). Previously unbounded. This is purely local to the MSP's install — it
  never reaches back to the customer, who keeps full control of their own schedule and retention.

## 1.7.0: license expiry warnings and a grace period; a separate license-issuing tool

* **License expiry is no longer a cliff.** Settings → License always shows when the current
  license expires. **30 days out**, a banner and a one-off low-severity alert warn you, with
  everything still fully licensed. **Once it expires**, a **7-day grace period** keeps it fully
  working (a higher-severity alert marks this), so a renewal in progress never causes a surprise.
  Only after the grace period also passes does the install fall back to the Community edition. See
  [Licensing](docs/licensing.md#expiry-and-a-7-day-grace-period).
* **`license-issuer`, a new, separate, vendor-only tool** (`src/bin/license_issuer.rs`) replaces
  the `denis license-keygen`/`license-issue` subcommands, which are removed from `denis` itself —
  that tooling has no business shipping inside the binary every customer downloads. It keeps its
  own small database of every license it has issued (customer, tier, cap, validity, and the signed
  file itself), so a lost license file can always be recovered: `license-issuer issue "Acme
  s.r.o." --device-cap 500 --years 1`, `license-issuer list`, `license-issuer show <id>`.
* **Settings → Users**: an already-disabled user can now be permanently deleted (their sessions,
  passkeys and authenticator app are removed with them). Disabling remains the reversible first
  step; deleting is not, and is only offered once a user is already disabled.

## 1.6.0: a second, mirror-port interface — for whole-network flow visibility from one box

* **`denis run --mirror-iface eth1`**: a second, capture-only interface alongside the usual
  `--iface`. The main interface keeps doing exactly what it does today (ARP sweeps, port scans,
  discovery); the mirror interface is never probed and never used for discovery — it only decodes
  traffic into the same flow accounting (`new_destination`, `new_port`, `volume_anomaly`,
  `threat_list_match`), correlated to known devices by MAC. This is what a switch's mirror/SPAN
  destination port is for: plugged in there, one DENIS instance sees traffic between *other*
  devices that a normal switch port never forwards to it — no second `denis` process, no agent,
  no separate database needed just to test it. Implies `--flows`. See `denis interfaces`, which
  now also lists interfaces usable only as a mirror target (no IPv4 address needed for that role).
* **Settings → Network interfaces**: pick both interfaces from a dropdown instead of editing
  command-line flags or a systemd unit. A GUI-set choice takes priority over `--iface`/
  `--mirror-iface`, same as a pasted license already takes priority over `--license-file` — but
  unlike a license, a changed interface needs a restart to take effect (capture is opened once, at
  start-up), which the console says plainly.

## 1.5.0: renamed to MSP view; live devices and alerts can reach an MSP

* The tab and setting from 1.4.0 are renamed **Overview → MSP view**, to say plainly what it is for.
* **`denis run --report-to https://your-msp:8081`**: a customer's own master can now relay its
  devices and already-scored alerts to an MSP's master live, so they show up in **MSP view**
  alongside every other customer. Built deliberately to stay cheap at scale: devices are sent only
  when they actually changed (not the whole register every cycle — a customer with 1000 mostly-
  unchanging devices sends next to nothing most cycles), alerts only past a cursor, and findings/
  compliance are never sent at all (the MSP computes those itself once the register is mirrored,
  the same way it already does for its own local devices). Default cycle: 60 seconds, not the
  console's own on-screen refresh rate. See [Deployment](docs/deployment.md#msp-live-devices-and-alerts-from-a-customers-own-master).
* Independent of `--backup-upstream` (1.4.0): run either, both, or neither.

## 1.4.0: an Overview tab across sites, and backups reaching an MSP

* **Overview tab** (off by default; an administrator turns it on under Settings → Overview page):
  one row per site — the local network and every remote agent you can see, respecting your own
  site access — with online status, device count, open alerts by severity and last report time.
  Click a row to open that site's devices. Useful once you manage more than a couple of sites: an
  MSP with several customers, or one business with several branches.
* **Backups can reach an MSP** (`denis run --backup-upstream https://your-msp:8081`, with a token
  from `denis agent-token issue`): a customer's own scheduled backups are also pushed, outbound
  only, to the MSP's master, landing under `backups/from-agents/<id>/` there — so the MSP still
  has yesterday's device list if that customer is ever hit by ransomware, independent of whether
  the customer also reports live as an agent. See [Deployment](docs/deployment.md#msp-keeping-a-copy-of-a-customers-backups).

## 1.3.0: install a license from the console, no file needed

* **Settings → License**: paste a license's two lines directly into the console instead of
  passing `--license-file` — an administrator can install, see the status of, or remove a
  license without touching the command line or restarting. It takes effect immediately. A
  license given via `--license-file` still works and is used when nothing is pasted in the
  console. In an MSP/multi-customer setup the license belongs on the top-level install with a
  console (your own instance, or each customer's master) — agents reporting into a master never
  need their own.

## 1.2.0: many more critical ports scanned, identified and risk-scored

* **Scanning and risk-scoring now cover far more services**: RPC/NetBIOS (111, 135, 137, 138), SNMP
  (161), LDAP/LDAPS (389, 636), more databases (MSSQL, PostgreSQL, Oracle), Redis, MongoDB and
  Elasticsearch (all unauthenticated by default), Memcached (DDoS amplification), the Docker API
  without TLS (full host control if reachable), WinRM, Webmin, NFS, PPTP and more SMTP/IMAP/POP3
  variants — about 25 additional ports, each shown as its own named risk factor (e.g. "+20 Redis is
  reachable on the network (no password by default)") when found open, and counted by the
  "risky service reaching outside the LAN" rule the same way Telnet/RDP/SMB already were.

## 1.1.0: a proper logo, a unified look for controls, the site filter respects access control

* **A new logo**: a checkmark joining three device nodes (verified, connected devices), replacing
  the earlier radar-sweep mark. Used as the favicon and the default header/sign-in mark.
* **Every button, dropdown and checkbox now looks like one family**: consistent padding, a subtle
  shadow and hover state, and dropdowns/checkboxes are drawn the same way in every browser instead
  of falling back to the operating system's own look. Every table's **Columns** button now sits in
  a header strip attached to that table, not floating loose above it. Settings' section links
  (Branding, HTTPS certificate, Updates…) are now a row of buttons, not plain text links.
* **The site filter (Devices/Topology/Trends) respects per-site access control**: a user only sees
  the sites they can actually read, both in the dropdown itself and in what "Local" and each
  agent's name mean for them — matching what the Devices list already enforced server-side.

## 1.0.0: a commercial license, per-site access control, a logo

* **License**: DENIS is no longer MIT/Apache-2.0. It is now source-available under the **DENIS
  Community License**: free to read, build and run for personal, non-commercial use on up to 100
  devices. Any organisational use, or more than 100 devices, needs a commercial license — see
  [LICENSE](LICENSE) and [LICENSE-COMMERCIAL.md](LICENSE-COMMERCIAL.md). A license is a small
  signed file (`denis serve --license-file …` / `denis run --license-file …`); the Devices page
  shows a banner when you are over the Community cap or a license file has a problem, and the
  device list (and its CSV/report) is limited to the first 100 devices until one is installed.
  Detection and alerting are never limited by this — every device is still monitored.
* **Per-site access control**: an administrator can now grant each user **read**, **write** or
  **no access** to each site (the local network, or a remote agent) from the Users page (the
  **Sites** button on a user's row). Useful for an MSP whose technicians should only see their
  own customers, or to keep one site's devices out of a viewer's sight entirely. Nothing changes
  for an install that never opens this: with no grant set, everyone keeps seeing everything, same
  as before.
* **A logo**: DENIS has its own mark now (a device found by a radar sweep), used as the browser
  tab icon and as the default header/sign-in logo when no operator has uploaded their own
  white-label one.

## 0.7.0: grouping, multi-field filters and a room column for Devices; CSV export buttons

* **Devices**: a **Room** column (from the location field), **Group by** (type, room or owner, each with a count
  and an "unset" group for devices with nothing entered), and **Filters** — several conditions at once (type,
  room, vendor, owner, a substring of the OS guess) with a count badge and a **Clear filters** button. Both are
  per-browser and change only what is shown; CSV export is unaffected.
* **Devices CSV** is now a button next to **Import CSV** (it was a plain link). **Alerts CSV** is a button that
  only appears on the Alerts page (it used to sit in the same toolbar as the Devices export, on the Devices, Alerts
  *and* Events tabs, which never made sense on Events).
* **Scaling to a large network**: the console polls every **10 seconds** instead of 5 (the register does not change
  fast enough to need faster, and it halves the load on both sides). The Devices table now renders **lazily**: past
  a few hundred devices, filtering, sorting and grouping still run over every device, but only the rows near the
  current scroll position are ever put on the page, so a list of thousands scrolls as smoothly as a list of forty.
  Smaller networks (almost everyone) see no difference at all.

## 0.6.0: five more industrial and IIoT protocols, and an honest boundary between "decoded" and "port only"

* **Five more protocols, each verified against a real capture**: **Omron FINS** (now fully decoded: memory/parameter/
  program area reads and writes, and the **run/stop** command — the one that matters most), **MQTT** (PUBLISH as a
  write, SUBSCRIBE as a read), **CoAP** (GET reads, POST/PUT/DELETE write), **HART-IP** and **KNXnet/IP** (protocol
  and direction only: their command layout needs a capture to check exact byte offsets against, which DENIS did not
  have for either, so it names the protocol and stops there rather than guess at read vs write). Every decoder,
  including the seven already there, is checked in `tools/ot-samples.sh` against a real capture of that protocol.
* **A port number alone is never protocol identification any more.** The previous "known industrial port, content
  not decoded" fallback — which named a conversation from its port with no check of the payload at all — is gone.
  Ports with no public, checkable signature (Niagara Fox, GE SRTP, MELSEC, PCWorx, CODESYS) are used **only** for
  the *"industrial port crossing the boundary"* finding, whose wording now says "port X (normally Y)" instead of
  asserting the traffic is that protocol.
* Detection rules and watches gained the five new protocol names (`fins`, `hart-ip`, `knxnet-ip`, `mqtt`, `coap`).

## 0.5.0: encrypted OT traffic, allow-list watches, and a way to test without a plant

* **Encrypted industrial traffic is no longer invisible.** Between two local devices DENIS now records the *path* of traffic it
  cannot read: TLS on any port, secured industrial protocols by their port (OPC UA over TLS 4843, Modbus/TCP Security 802, IEC 104
  and DNP3 over TLS, MQTT over TLS), and industrial protocols it does not decode (Omron FINS, GE SRTP, MELSEC, PCWorx, CODESYS,
  Niagara Fox). Who talks to whom, in which direction, how much, and from the TLS handshake the **protocol version** and the **server
  name**. New paths raise `ot_new_conversation` ("the content is encrypted: DENIS sees who talks to whom, not what is said"). TLS
  between two ordinary machines is ignored, and a path never marks a device as industrial by itself.
* **Allow-list watches**: an OT command watch can now match **any communication at all** ("Only these devices may talk to it"): give
  the controller as target and the devices that may talk to it as allowed senders; any other device that talks to it, over any
  protocol, encrypted or not, raises an alert from the first minute.
* **`denis replay FILE.pcap`** runs any Ethernet capture through the decoders, inventory and rules and prints devices, conversations
  and alerts (nothing is stored). **`tools/ot-samples.sh`** uses it on real public captures (Modbus, Siemens S7 including a program
  download, IEC 104, BACnet, an EtherNet/IP firmware change) and on an encrypted capture made from real OpenSSL handshakes, and runs
  in `tools/pre-release.sh`. On those captures the decoders found what each is known to contain.

## 0.4.0: reports, health, two-step sign-in, real topology, software versions

*Built from 0.4.0-rc.1 and 0.4.0-rc.2.*

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

Alerting
* **Pushover** and **ntfy** notification channels (*Alerting* → *Add a channel*). Pushover: an application token and a user or
  group key; high alerts go as high priority. ntfy: the address of your topic on ntfy.sh or your own server, and an access token
  for a protected topic (never sent over plain `http://`); published as JSON, so device names with any characters are safe.
  Secrets are write-only, as for the other channels.

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
  remembered per table in the browser. (In rc.1, moving a column a second time, or hiding one after moving, put headings over the
  wrong data; fixed, and the browser test now moves and hides columns repeatedly and checks every heading against its data.)
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
