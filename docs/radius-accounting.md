# RADIUS accounting (network sign-ins)

**Experimental** (4.6.0, off by default). DENIS can receive the RADIUS accounting records (RFC 2866) that your
switches, wireless controllers or RADIUS server already produce, and show who is signed in on which device, through
which access device and port, and since when. It was tested only against records written by DENIS's own tests on
127.0.0.1, and once on real equipment (see *Lab result 2026-11-18* below). **Only that one run on a Cisco Catalyst
2960-X is verified; everything else has not been run against real equipment yet.**

How sure each statement on this page is:

* **documented**: an RFC or a vendor document says so (named);
* **verified**: read in DENIS's source code, checked by DENIS's own tests on 127.0.0.1, or seen on real equipment (then
  the date, device and version are named);
* **best guess**: neither; it still has to be checked on the bench.

## What it does and what it does not do

* **DENIS is not a RADIUS server.** It opens one UDP port that only receives Accounting-Request packets. It never
  answers a sign-in request (Access-Request): nobody can authenticate against DENIS, and a device whose sign-in depends
  on DENIS would never get in. An Access-Request that arrives anyway is counted, and Health says that some equipment
  was told to use DENIS as a sign-in server (verified).
* **One more accounting server.** You add DENIS to your equipment *beside* the accounting server you already have. Your
  RADIUS server keeps deciding who may sign in. DENIS stays out of the sign-in path (best guess that a switch's sign-ins
  are not affected when DENIS is down; to be checked on the bench).
* **Answered only after it is stored** (documented: RFC 2866 section 2). If the database cannot take a record, DENIS
  does not answer and the equipment sends it again (verified).
* **Read only in 4.6.0.** DENIS shows sessions; it does not end them from this page. Ending a session through the
  RADIUS Disconnect connector is described in [RADIUS Change of Authorization (CoA)](nac/radius_coa.md) and is a
  separate, Experimental connector with its own settings (verified: the session-exact Disconnect is not built in this
  version).
* **No block, no VLAN change, no automation.** Nothing in this feature changes equipment, and no rule or Autopilot uses
  it to act (verified).
* **The main installation only.** Hosted tenants have no receiver in 4.6.0; their console says so (verified).
* **No receiver on a remote agent.** The equipment must reach the master's UDP port, through a route or a VPN
  (verified).
* **No RadSec** (RADIUS over TLS) and no RADIUS over TCP (verified).
* **It also runs under `--passive-only`.** `--passive-only` stops DENIS from sending probes onto the network; the
  receiver sends nothing on its own, it only listens and answers the records it was sent, so a configured receiver
  keeps running (verified, from the code). For a rehearsal on a copy of a database, switch the receiver off in that
  copy first, or start it on a loopback address that the equipment cannot reach.

## Two ways to send records to DENIS

| | The access device sends to DENIS itself (source kind *Access device*) | The RADIUS server forwards (source kind *RADIUS server*) |
|---|---|---|
| How | Each switch or controller gets DENIS as one more accounting server. | Your RADIUS server copies each accounting record to DENIS. |
| What DENIS sees | The access device's own address, one secret per device. | One address (the RADIUS server) and one secret; the access device is known only from NAS-IP-Address or NAS-Identifier inside the record. |
| When DENIS is down | The device repeats a record a few times, then gives up: those records are lost, sessions go stale and come back with the next interim record (documented: RFC 2866 retransmission; how often a Catalyst retries: best guess). | Nothing is lost when the RADIUS server keeps its copies and retries (documented for FreeRADIUS `copy-acct-to-home-server`, v3.2.x). |
| Works with | Any equipment that sends RFC 2866 accounting. | FreeRADIUS (documented); Microsoft NPS and Cisco ISE have their own forwarding, not looked at. |

For a RADIUS server that forwards, you can list the access devices it may speak for (*Access devices it may speak
for*); a record that names another access device is answered but not stored (verified). Empty means any access device
the server forwards.

## Setting it up in DENIS

*Network → Sign-ins → Setup* (an administrator of the whole installation; a site administrator, an
editor, a viewer and an API token cannot open it, verified):

1. **Sources.** Add one source per sending address: a name, the kind (*Access device* or *RADIUS server*), the one IP
   address it sends from (no host name, no prefix; IPv4 or IPv6), the site its sessions belong to, the interim interval
   it is set to (0 when it sends none, else 60 to 86,400 seconds; 900 by default) and its **shared secret**. At most 64
   sources; two sources with the same address are refused (verified).
2. **The shared secret, per source.** At least 16 characters (documented: RFC 2865 section 3 asks for at least 16
   octets), at most 128. It is stored sealed, never shown again, also not to administrators, never written to a log
   line or an audit entry, and left out of backups: enter it again after a restore (verified). Use a long random value
   and a different one for each source.
3. **The listen address.** An address of this server and a port, for example `192.0.2.20:1813` (1813 is the accounting
   port, documented: RFC 2866 section 3). There is no default that listens everywhere; `0.0.0.0` or `::` is accepted
   only when you tick *Listen on every address of this server* (verified). Prefer the address on your management
   network. Your firewall must let UDP from the listed sources reach it. With *every address*, the operating system
   picks the sender address of each answer by its route: on a server with a second address on the same network, or
   with asymmetric routing, an answer can leave from another address than the one the equipment sent to, and the
   equipment then ignores it and sends the record again (documented: Linux and BSD behaviour for a socket bound to
   every address; not seen in a test). A listen address of its own avoids this.
4. **Who may see user names**, and **how long ended sessions are kept** (see *Privacy* and *Retention* below).
5. Tick *Receive RADIUS accounting* and **Save**. Saving asks for your password again, as does any change to the
   address, the sources, a secret or who may see user names; every change is audited as `radius.accounting.updated`
   with the names and addresses of the sources, never a secret (verified). Saving wakes the receiver at once: the port
   is open well under a second after the save (verified by a test on loopback; before 4.6.0's fix it took up to five
   seconds), and meanwhile *Health* says *starting*. The service log then says
   `RADIUS accounting: receiving on udp <address> from <n> source(s)` (verified). A record sent before the port is open
   reaches no listener and is not answered; the equipment sends it again after its timeout (5 seconds on a Catalyst)
   and that copy is stored (documented: RFC 2866 retransmission). Configure the equipment after the line appears. A
   Catalyst counts such a record as a timeout and a retransmission in `show aaa servers`; nothing is lost. A change saved while records arrive restarts the receiver: records already received are still
   stored and answered first (verified by a test, at most two seconds), records sent during the restart are sent
   again by the equipment.

*Switch the receiver off now* needs no password; the port is closed at once, well under a second (verified by a test
on loopback). Sessions already recorded stay, go stale and end by themselves after seven days of silence.

**Switched off is no work.** While the receiver is off and no source is listed (a new installation), nothing of it
runs: no port, no timer of its own, no secret opened, no database read except the settings row once every ten minutes
as a safety net, and *Health* and `/metrics` show nothing and read nothing (verified by a test that counts every
database access). While it is off but sessions are still open, the session time job runs once a minute until the last
one has ended, then stops (verified by a test).

The **Message-Authenticator** of a record, when present, is checked as RFC 5176 section 3.4 describes it for Disconnect
packets (documented for Disconnect and CoA; best guess that accounting senders compute it the same way). If a source's
records are all dropped as *bad Message-Authenticator* while the secret is right, tick *Ignore the Message-Authenticator
of this source* for that source only.

## Setting it up on a Cisco switch (IOS 15.2, Catalyst 2960-X)

Written for a Catalyst 2960-X with IOS 15.2(7)E4 (the owner's lab switch). Addresses are examples: the switch
`192.0.2.5` (its management VLAN 10), your RADIUS server `192.0.2.10`, DENIS `192.0.2.20`. The secrets are
placeholders: choose your own.

**Read this before you type anything.** These lines change the switch's AAA configuration, which decides who may sign
in on the switch itself and on its ports. Two mistakes lock people out:

* On a switch without `aaa new-model` (logins with line passwords), `aaa new-model` switches remote login to the AAA
  methods: without a local user and `aaa authentication login default local` first, nobody can log in remotely any
  more (documented: Cisco IOS AAA configuration guide; that a switch without a local user then refuses vty logins is a
  best guess from IOS behaviour).
* On a switch that already does 802.1X, its `aaa ... default` lines already name your RADIUS group (for example
  `group ISE`). The accounting line below **replaces** your current `aaa accounting dot1x default` line: name the
  group(s) it names today, then `G-DENIS`. Do not type the `aaa authentication dot1x` or `aaa authorization network`
  lines of the lab block on such a switch: they would replace your sign-in method lists.

So work inside a safety net (`reload in 15`: unless cancelled, the switch goes back to its saved configuration in 15
minutes), keep your own login working first, and save only when a second login works.

```
! --- 0. Look first; change nothing yet
show version
show running-config | include aaa|radius|dot1x|username|login
!     Note the group your "aaa accounting dot1x default" line names today (below: G-RADIUS).
!
! --- 1. Safety net: unless cancelled, the switch reloads its SAVED configuration in 15 minutes.
!     Answer "no" if it asks to save. Never "write memory" until step 5.
reload in 15
configure terminal
!
! --- 2. ONLY on a switch that does not have "aaa new-model" yet: keep your own login working first.
!     Skip the username line if a local administrator already exists.
username <local admin> privilege 15 secret <a password of your own>
aaa new-model
aaa authentication login default local
aaa authorization exec default local
!
! --- 3. DENIS as one more ACCOUNTING server. Nothing here changes who may sign in.
radius server DENIS
 address ipv4 192.0.2.20 auth-port 1812 acct-port 1813
 key <secret of the DENIS source, 16 characters or more>
 exit
ip radius source-interface Vlan10
aaa group server radius G-DENIS
 server name DENIS
 exit
!     This line REPLACES your current "aaa accounting dot1x default" line: name the group(s) it names today, then G-DENIS.
aaa accounting dot1x default start-stop broadcast group G-RADIUS group G-DENIS
aaa accounting update newinfo periodic 15
end
!
! --- 4. Check, from a SECOND session (a new SSH login) before closing this one:
!     you can still log in; "show aaa servers" lists DENIS; DENIS Health shows accepted records.
!
! --- 5. Only when all of step 4 is fine:
reload cancel
write memory
```

**Only for a lab switch that does not do 802.1X yet** (this is what the owner's lab run used; never on a switch whose
ports already sign people in): inside the same `reload in 15` window, after step 2 and before step 3, add your RADIUS
server and turn 802.1X on, with the test port in open mode so traffic flows even if a sign-in fails:

```
radius server MY-RADIUS
 address ipv4 192.0.2.10 auth-port 1812 acct-port 1813
 key <secret of your RADIUS server>
 exit
aaa group server radius G-RADIUS
 server name MY-RADIUS
 exit
aaa authentication dot1x default group G-RADIUS
aaa authorization network default group G-RADIUS
radius-server vsa send accounting
dot1x system-auth-control
interface GigabitEthernet1/0/10
 authentication open
 authentication port-control auto
 mab
 exit
```

| Line | What it does | How sure |
|---|---|---|
| `reload in 15` / `reload cancel` | The safety net: unless cancelled, the switch reloads its saved configuration after 15 minutes, which undoes every unsaved line. | documented (Cisco IOS command reference); used in the owner's lab on 2026-11-18 (verified) |
| `aaa authentication login default local` (with a local `username`) | Keeps remote login working with a local user once `aaa new-model` is on. | documented (Cisco IOS AAA configuration guide); used in the owner's lab on 2026-11-18; that the switch kept remote login is a best guess (not recorded) |
| `aaa authorization exec default local` | A local user of privilege 15 lands in privileged mode after login. | best guess (documented command, not used in the lab run) |
| `aaa accounting dot1x default start-stop broadcast group G-RADIUS group G-DENIS` | Sends each Start, Interim and Stop to the first server of **each** group, so your RADIUS server and DENIS both get it. | documented (Catalyst 2960-X 15.2(2)E command reference: `broadcast`); accepted and kept on 15.2(7)E4, and Start and Stop reached DENIS, 2026-11-18 (verified); that the RADIUS server got them too in that run: best guess |
| DENIS only in `G-DENIS`, never in the `aaa authentication` or `aaa authorization` lines | DENIS is never asked about a sign-in. | best guess that a switch with DENIS down signs clients in as before; bench item |
| `aaa accounting update newinfo periodic 15` | An interim record every 15 minutes: this is what tells DENIS a session is still going on. Set the source's interim interval in DENIS to 900 seconds to match. | documented (IOS command reference, minutes, off by default); verified on 2960-X, IOS 15.2(7)E4 (2026-11-18): with 1 minute a record about every minute reached DENIS; that a new interval applies only to a session opened after the change: best guess from that run |
| `radius-server vsa send accounting` | Lets the switch put Cisco attributes (the audit session id) into accounting records. | documented (Cisco 802.1X deployment guide); not retained on 2960-X, IOS 15.2(7)E4 (absent from the running configuration afterwards; best guess: on by default) |
| `ip radius source-interface Vlan10` | Makes the switch send from the address of that interface. It must be the address you listed as the source in DENIS, or every record is dropped as *not listed*. Write it **before** the `aaa group server radius` blocks (or leave the group with `exit` first): written directly after a group's lines, the switch takes it as a command of that group. | verified on 2960-X, IOS 15.2(7)E4, 2026-11-18 (accepted; the order matters as described) |
| `radius server …` / `address ipv4 … acct-port 1813` / `key`, `aaa group server radius`, `aaa new-model`, `dot1x system-auth-control` | The usual RADIUS and 802.1X configuration. | verified on 2960-X, IOS 15.2(7)E4, 2026-11-18 (accepted and kept in the running configuration) |
| The port lines (`authentication port-control auto`, `dot1x pae authenticator`, `mab`) | 802.1X on a port. Already in place on a switch that uses 802.1X. | `authentication port-control auto` and `mab` (with `authentication open`) verified on 2960-X, IOS 15.2(7)E4, 2026-11-18; `dot1x pae authenticator` best guess (not used in that run) |

Check first with `show version` that the image is LAN Base or higher (802.1X is not in LAN Lite: best guess). The verified
switch is a WS-C2960X-48TS-L (the suffix L meaning LAN Base is a best guess).

## Lab result 2026-11-18

First run on real equipment, in the owner's lab: Cisco Catalyst WS-C2960X-48TS-L, IOS 15.2(7)E4; FreeRADIUS 3.2.6
(Docker) accepting MAC authentication bypass from the switch; DENIS 4.6.0 receiving on UDP 1813 from one source of kind
*Access device*. Verified: the switch sent Accounting Start and Stop for a MAB sign-in (2 Starts, 1 Stop after the
cable was replugged) and DENIS stored them; *Network, Sign-ins* showed the active MAB sign-in with the access device
named; *Health* showed 5 accepted, 0 dropped, 1 active and 1 ended session; `show aaa servers` showed 4 accounting
transactions succeeded, 0 failed. The switch counted one timeout and one retransmission towards DENIS (longest answer
about 6.2 seconds); no record was lost. The slow first answer was most likely a record sent in the gap of up to five
seconds between *Save* and the open port, answered from its retransmission (best guess; the gap itself was measured on
loopback, 4.8 seconds); 4.6.0 opens the port at once after the save.
Interim records, verified the same day: with `aaa accounting update newinfo periodic 1` (one minute, set for the test) and a new
session (the cable replugged), the switch sent a record about every minute; *Health* counted them (8, then 10 accepted),
the number of sessions did not change (1 active, 2 ended) and the session stayed active. A changed interval applies to a
new session, not to one that is already open (best guess from this run: the first minutes after the change showed nothing).
Not exercised: 802.1X with a supplicant (EAP), the FreeRADIUS forwarding topology, binding a
session to a known device (the lab DENIS had no devices). Disconnect/CoA is not built.

**The Disconnect port is not needed for accounting.** `aaa server radius dynamic-author` (UDP 1700 by default on Cisco
IOS, 3799 on most other equipment and in RFC 5176) is what the separate [RADIUS CoA](nac/radius_coa.md) connector uses
to end a session. Accounting to DENIS needs only that the switch can send UDP to the listen address (documented for
the ports: RFC 5176 section 3, Cisco IOS XE AAA guide; best guess that the 2960-X uses the same default).

## Setting it up on FreeRADIUS (forwarding)

FreeRADIUS 3.2 can copy accounting to DENIS with its shipped virtual server `copy-acct-to-home-server`, which reads
the `detail` file and retries a record until it is answered (documented: `raddb/sites-available/copy-acct-to-home-server`,
v3.2.x). A ready-to-read example is in the repository under `tools/radius-lab/freeradius/` (`proxy.conf` and the
virtual server). In DENIS, add the FreeRADIUS server's address as a source of kind *RADIUS server*, and list your
switches under *Access devices it may speak for*. That the `detail` module must write to exactly the file the virtual
server reads is a best guess, to be checked in the rehearsal.

## What you see in the console

* **Network → Sign-ins → Setup**: the switch, the listen address, the sources with *Secret set* or
  *No secret set yet*, the receiver's state (*listening on … since …*, *could not open …*) and how many sign-ins are
  kept (verified).
* **The device panel, block "Network sign-ins"**: the current sign-in and the earlier ones: user or certificate name as
  the access device reported it (or *Hidden*), how it signed in (802.1X or MAC address bypass, with *derived* when DENIS
  worked it out from the user name), the access device, the port or Wi-Fi network, the VLAN when reported, since when,
  when it was last heard, why it ended, and *How sure* (*Sure*, *Likely*, *Unclear* with the reason). A value the
  record did not carry says *Not reported*, never a guess (verified). The block is not shown on an installation where
  the receiver was never set up.
* **The alert dialog**: one line *Signed in at the time of the alert: …* when a session of the alert's device covers
  the alert's time; it opens the device's block (verified).
* **Network → Sign-ins**: every recorded sign-in, newest heard first, with filters for state, site, source, hardware
  address, access device and text, and *Not matched to a device* (verified).
* **Health**, *Monitoring*, row *Network sign-ins* (`#health/sign-ins`): the receiver, each source, the last record
  heard and the counts of accepted and dropped records for the last hour (verified).

**How a session is matched to a device**: only by the exact hardware address in Calling-Station-Id, against the
devices of the source's own site; never by user name, host name or IP address. An address that is split over more
than one device is shown as *May belong to this device*; a record without a hardware address is *Not matched*.
Accounting never creates a device and writes nothing into the inventory (verified).

**Fresh or stale.** A session is *Active* while records keep arriving within twice its interim interval plus two
minutes (24 hours for a source that sends no interim records). After that it is *Stale*, shown as *last observed
at …*, never as confirmed active; a stale session with nothing heard for seven days is ended as *not heard for 7 days*
(verified). An Accounting-On from an access device (it restarted) ends that device's open sessions (verified).

**Two clocks (4.6.0).** "Arriving" is measured on this server's clock: when the newest record arrived, not the
time the equipment wrote into it. The equipment's own time (Event-Timestamp) only puts the records of one session in
order. A record whose time is more than 5 minutes from this server's clock, with no Acct-Delay-Time that explains it
(a switch without NTP, or one that restarted before its clock was set), is applied with this server's arrival time
instead, and the session says *Likely: the times come from DENIS’s clock, not from the access device*. Why: with the equipment's clock a switch
two hours behind made every session stale and ended it after a week while it was still in use, a switch a year ahead
kept sessions *Active* for a year, and the restart record of a switch whose clock was not set yet ended nothing. With
this rule the restart, the start and end times, *who was signed in at the time of an alert*, the order of the list
and the retention all use one clock (verified by tests with a clock two hours behind, a year ahead, and one set right
in the middle of a session).

**An interim record from another device (4.6.0).** When an interim record arrives for an open session but names
another hardware address than the session has, the session keeps its user, address and port, is shown as *Unclear:
records of another hardware address arrived with this session number*, and the record is counted
(`interim_mismatch`); no new session is made. Why: a switch that restarts numbers its sessions from 1 again; if its
restart record and the new session's start were lost, the next device's interim records carry the old number, and
taking their user name would show the wrong person on a device as *Sure*. The same is done for an end record that
does not fit (verified by tests).

## Health warnings

Each warning links to the settings page. The code is the stable name in `GET /api/system` (verified: `src/health.rs`).
A source that is only listed while the receiver is off gets a row and no warning.

| Code | When |
|---|---|
| `radius_listen_failed` | The receiver cannot open its address (in use, not an address of this server, `0.0.0.0` without the tick). It tries again every few seconds. |
| `radius_bad_secret` | A source sent 5 or more records in the last hour that failed the shared-secret check, and none that passed: the secrets most likely differ. |
| `radius_bad_authenticator` | As above, while other records from the same address passed: a second device with another secret, or forged records. |
| `radius_queue_full` | Records were dropped in the last hour because the queue to the database was full. |
| `radius_rate_limited` | Records were dropped in the last hour because a source sent more than 2,000 a second. |
| `radius_store_failing` | Records in the last 10 minutes could not be stored, so they were not answered. |
| `radius_no_secret` | A listed source has no stored secret (for example after a restore): nothing it sends is read. |
| `radius_unknown_source` | 3 or more packets arrived in the last hour from addresses that are not listed (the addresses are shown), sign-in requests from such addresses included. |
| `radius_access_request` | 3 or more sign-in requests arrived in the last hour from a listed source: remove DENIS from that equipment's authentication servers. |
| `radius_source_silent` | A source with open sessions has sent nothing for longer than its window: its sessions go stale. |
| `radius_clock` | 10 or more records of a source in the last hour carried a time more than 5 minutes from this server's clock: check NTP. Those records are applied with this server's clock (see *Two clocks*). |
| `radius_near_cap` | The kept sessions reach 90 % of the limit of 200,000. |
| `radius_tick_stalled` | The session time job has not finished a pass for 5 minutes, so sessions are not marked stale or ended on time. |

`/metrics` adds `denis_radius_listening`, `denis_radius_listen_failed`, `denis_radius_packets_total`,
`denis_radius_unlisted_packets_total`, `denis_radius_queue_depth`, `denis_radius_queue_high` and
`denis_radius_source_heard_age_seconds` (verified: `src/web/system.rs`).

Why `radius_source_silent` needs open sessions (4.6.0): a source that has nothing to report sends nothing (a quiet
switch at night after its last end record). That is not a fault, and a warning every night from half an hour after
the last sign-out would teach people to ignore it; the *Silent* line in the table still shows it. A source with open
sessions that goes quiet is a fault: its sessions go stale. One packet anyone can send without a secret does not
raise `radius_unknown_source` or `radius_access_request`; equipment that is set up wrongly retries at once, so a real
mistake reaches 3 within seconds (verified by tests).

## Privacy

The records name people (user or certificate names) and their devices: that is personal data.

* **Who sees user names**: editors and administrators by default. An administrator can choose *Administrators only*
  or *Everyone who can sign in (viewers too)*. Everyone else sees *Hidden*, and the text filter does not match names
  they may not see (verified).
* **API tokens and an MSP technician never see user names**, whatever is chosen (verified).
* **Where they go**: only the RADIUS accounting pages and API read the session table; notifications, channel
  messages, syslog and SIEM exports, reports and the Autopilot and AI inputs do not (verified by a search of the source
  for every reader of the table; no automatic test keeps it so).
* A device's sessions are deleted with the device and with its site, and erased with the inventory (verified). They
  are in a database backup like the rest of the database (best guess).
* Tell your users or your data-protection officer before you switch it on.

## Retention

Ended sessions are kept for 30 days by default (1 to 365, under *Keep ended sign-ins for this many days*), and beyond
200,000 rows the oldest ended ones go first whatever their age. Open sessions are never pruned; they end by themselves
after seven days of silence. The hourly retention pass deletes at most 10,000 rows by age at a time; the rows over
the limit of 200,000 have a budget of their own, so the table is back at its limit after each pass however many
sessions end in an hour (4.6.0); a settings row that cannot be read deletes nothing that hour (verified). Size: about 90 MB at the cap (best guess: about 450 bytes a row
with its indexes).

## Limits

* **UDP and MD5.** RFC 2866 has no protection against a copied record being sent again, and its authenticator is an
  MD5 hash with the shared secret (documented). Someone on the path can replay a record and make an ended session look
  open until it goes stale; they cannot make DENIS change anything. Someone who spoofs a listed address can use up that
  source's budget, so genuine records are dropped and resent. A weak secret can be guessed offline from one captured
  record. Keep accounting on the management network, and use a long random secret.
* **Bounds.** 2,000 records a second per source (bursts of 4,000), a queue of 4,096 records, packets of at most 4,096
  bytes (documented: RFC 2865 section 3). Above that, records are dropped and counted, and the equipment sends them
  again (verified).
* **What a real switch sends is not known yet.** Which attributes a Catalyst puts into its Start, Interim and Stop
  records, how it writes the hardware address, whether it sends Event-Timestamp, Framed-IP-Address, the VLAN or the
  sign-in method: all best guess until the bench. Every attribute is optional in DENIS, and the console says what was
  not reported.
* **High availability**: only the leading node runs the receiver; the equipment must send to the address that follows
  the leader (best guess that nothing more is needed; not tested on a pair).
* Unknown attributes and vendors are skipped and counted, never refused (verified).

More on the receiver's safety in [Security](security.md#the-radius-accounting-receiver-460-experimental), and its
operation (logs, restore, retention) in [Operations](operations.md#the-radius-accounting-receiver-460-experimental).
The routes are in the [API reference](api.md#radius-accounting).
