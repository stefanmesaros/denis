# High availability: two nodes on PostgreSQL

This page is for the administrator who runs two DENIS servers against one shared PostgreSQL database, with one of them
leading and the other on standby. It covers what must be the same on both machines, what must not, how to put a load
balancer in front of them, how to test the pair yourself, and what is and is not guaranteed after a failover. The short
version is in [Deployment › PostgreSQL and a second node](deployment.md#postgresql-and-a-second-node-optional).

**Before you start:**

* High availability needs PostgreSQL. A SQLite install is never a pair.
* **High availability is Experimental in 4.4.** It is tested with a database container, with two processes on one
  machine and in a local fault lab (a Patroni cluster in Docker), not on managed or clustered PostgreSQL. The table
  [Where things stand](#where-things-stand-in-44) says what is covered and what is not.
* It needs the PostgreSQL build of DENIS. A build without it refuses `--database-url`. No self-build is needed: a ready-made PostgreSQL build is attached to every release from 4.2.1 (`denis-pg-x86_64-unknown-linux-musl`, `denis-pg-aarch64-unknown-linux-musl`): static, signed like the others, so nothing needs to be built. `sudo bash install.sh --postgres` installs it, and it updates itself to the PostgreSQL build of each new release. `denis --version` ends with `(postgresql)` when it is that build.
  Building it yourself (`cargo build --release --features postgres`) still works; a build from 4.2.1 source cannot update itself on a platform that has no PostgreSQL release file. **If you built the PostgreSQL program by hand from 4.2.0 or earlier, do not use the console Update button** (the old program does not know the flavour and would take the standard build, which refuses `--database-url`): run `sudo bash install.sh --postgres` once instead. Running the installer again without `--postgres` stops with a message when it finds a PostgreSQL installation: one it installed with `--postgres`, a program that says `(postgresql)`, or a database address in `/etc/denis/env` or in the service (unit, drop-in, OpenRC script or `/etc/conf.d/denis`). `--standard` is the explicit way back to the standard build. Keep the database address in `/etc/denis/env` (`DENIS_DATABASE_URL`, the password in `DENIS_DATABASE_PASSWORD`): the installer rewrites the service file, and stops while that file names the database itself. The PostgreSQL build backs the database up with `pg_dump` before every update: install the PostgreSQL client of your server's version (Alpine: `apk add postgresql-client`; Debian/Ubuntu: `apt install postgresql-client`).
* Both nodes' `--database-url` point at the same database. The password goes only in `DENIS_DATABASE_PASSWORD`, never in
  the URL or on the command line.
* **Tenants together with a pair are Experimental (4.4).** With `--database-url` the tenants and the MSP's operators
  live in the database too (one schema and one database role per tenant), so both nodes run the same tenants. An
  install whose tenants are still in SQLite files refuses to start with `--database-url` until
  `denis tenant move-to-postgres` has copied them
  ([the control schema and tenant schemas](#the-control-schema-and-tenant-schemas-on-postgresql-44),
  [Multi-tenancy](multi-tenancy.md)).
* The availability of PostgreSQL itself (a managed or clustered service) is up to your database platform. When the
  database is unreachable, both nodes stay on standby, because neither can become leader.
* This has been tried with PostgreSQL 16 in a test container, with two processes on one machine and in the local fault
  lab. It has not been tried on managed or clustered PostgreSQL, and not in production. Run the
  [failover test](#testing-a-failover) on your own pair before you rely on it.
* **Update a test pair first.** The newer PostgreSQL code (the tables for API token scopes, rule outcomes, capture
  samples and the delivery queue, the write fence, the control schema) has run on PostgreSQL 16 in containers and in the
  lab, but not against a production database. Update a test pair, run the failover test again, and only then the
  production pair, following [Upgrading a pair to 4.4](#upgrading-a-pair-to-44). Known limits of 4.3.0:
  [Known limits in 4.3.0](updates.md#known-limits-in-430).

## Where things stand in 4.4

| Part | State | Evidence and what is missing |
|---|---|---|
| One node on PostgreSQL | Optional; standard database stays SQLite | Complete store, tested on PostgreSQL 16. For one site SQLite is faster; PostgreSQL is chosen for a pair |
| Pair with leader and standby | **Experimental** | `kill -9`, a stopped lock session, a database switchover and a promotion tested on one machine and in the lab. Not run on a managed service; no soak of many hours |
| Write fence (schema V58) | **Experimental** | Tested in containers and in the lab (scenarios `s5_fence`, `s5b_paused_leader`). Not run on a managed service or after a real power loss |
| Old leader gives up on a half-open link | Fixed, **to confirm in the lab** | Fixed after the lab run and checked by a two-process test; the lab scenarios `s3b_half_open` and `s3c_cut_after_takeover` have not been re-run |
| Delivery queue (schema V59) | At least once, never exactly once | Tested on PostgreSQL 16 including failover and flood tests; see [Delivery](#delivery-is-at-least-once-not-exactly-once) |
| Data key per tenant, key changes | Tested on SQLite and PostgreSQL 16 | [Key management](key-management.md); the pair runbook has not been run on two real machines |
| Control schema and tenants on PostgreSQL | **Experimental** until measured | Tested in containers and with two processes. Nothing measured with 10, 50 or 100 tenants, and no number is promised |
| Managed PostgreSQL service (for example a cloud Multi-AZ instance) | **Not covered yet** | The run on a managed service is still to do; it happens after the 4.4.0 release, not before. Its DNS switch, proxies, TLS chain, maintenance events and latency between zones are untested |
| Connection poolers in transaction mode | **Not supported** | Session locks and session settings need session pooling or a direct connection |

Going back after an upgrade (the backup, the one-way change of the secret format, the commands that undo it) is on one
page section: [Upgrading a pair to 4.4](#upgrading-a-pair-to-44).

## How the pair works

Both nodes start and try to take one install-wide lock in the database. The one that gets it becomes the **leader**: it
captures, detects, sends notifications and serves the console and the agent port. The other one is on **standby**: it
serves only `/api/health`, which answers HTTP `503` with `{"ok":false,"role":"standby"}`, and does not open the agent port
(`--ingest-listen`) at all. The leader's `/api/health` answers `{"ok":true,"role":"leader"}`.

When the leader stops, the standby takes the lock and becomes leader, in tests within about 2 seconds of the database
noticing the old session is gone. When the old leader comes back, it starts as standby; leadership does not move back by
itself, and there is nothing to fail back by hand.

## What both nodes must share

**The database.** Both `--database-url` values point at the same PostgreSQL database.

**The same `secrets.key`, always.** Every integration credential (CMDB client secrets, connector passwords, scanner keys
and so on) and, since 4.2, every authenticator-app secret is stored in the shared database, encrypted with a key that
lives in the file `secrets.key` in each node's data directory, never in the database. Each node creates its own key on
its first start, so the two differ until you copy one.

Copy `secrets.key` from the first node to the second **before the second node's first start** (stop it, copy the file
with mode `0600` and the service user as owner, start it), and keep it identical from then on. This is needed whether or
not any credential is stored. Nothing renews the key automatically, so one copy is enough, as long as a reinstall or a
wiped disk does not make a new one on one node.

DENIS checks it. The first node that starts as leader records a check value of its key in the shared database (an HMAC
of a fixed text under the key; it cannot be turned back into the key). A node whose key differs refuses to start when it
becomes leader, before it seals or opens anything, with an error that says so; the other node keeps or takes the
leadership, and its Health page names the node that refused until that node starts with the right key. Without this
check, a node with another key would seal new authenticator secrets under its own key, and after the next failover the
other node could not read them: those people's codes would be refused.

A node that is still waiting for leadership makes the same comparison once when it starts (it only reads the recorded
value; it runs no migration): with another key it stops with the same error at once, and leaves a note for the Health
page of the node that runs, instead of finding out when it takes over.

Before upgrading a pair to 4.2, compare `secrets.key` on both nodes (`sha256sum secrets.key`) and copy it if it differs.
If the pair's key is lost for good (for example after a restore to new nodes), the start is refused too:
`denis user reset-mfa --unreadable` with that node's `--database-url` and `--data-dir` (with DENIS stopped on both nodes:
since 4.4 the command takes the leader lock, see [the write fence](#the-write-fence-44)) removes the authenticator apps the
new key cannot open (those people set them up again) and records the new key for the pair; integration credentials are
entered again as after any restore without the key.

**The secret format change (4.4) runs on the leader.** The first start of 4.4 moves the stored secrets of the shared
database to a data key of the tenant (one transaction, all or nothing; see [Upgrading the secret
format](security.md#upgrading-the-secret-format-44)). Only the node that holds leadership does it, after the key
check above; the standby never writes to the database before it is leader. If the move cannot be made, the leader
starts anyway in the old format and the Health page says why. During a rolling upgrade, do not run 4.3 on the
second node once the first node on 4.4 has moved the database: 4.3 cannot read the new format. Upgrade both nodes, or
restore the pre-update copy to go back. `denis secrets migrate --dry-run --database-url ...` shows the counts first.

**Changing `secrets.key` on a pair.** Stop the standby and the leader, run `denis secrets rotate-master
--confirm-stopped` on the leader, copy the new `secrets.key` to the standby, start the leader and then the standby. The
rotation updates the check value recorded in the shared database, so a node that still has the old file refuses to
start. The steps, what is checked first and how an interrupted run is finished are in [Key
management](key-management.md#change-the-master-key). Changing the data key of a tenant (`denis secrets rotate`) needs
no stop and no copy; it runs against the shared database.

Keep a copy of `secrets.key` safely and separately from the database backups (not in the same place or the same
archive): `denis secrets key-export` writes it under a passphrase you type, and a restore needs it, and a database restored without the matching key asks you to enter every integration
credential again and refuses the authenticator codes until those apps are reset.

**The same certificate.** Clients reach the pair through one address, so both nodes must present a certificate that
clients trust for that address.

* **Recommended:** your own certificate from a real authority (public or your internal one) for the shared address,
  given to both nodes with `--tls-cert` and `--tls-key` (or uploaded in the console), and kept identical on both with your
  own tooling. DENIS re-reads it every hour without a restart.
* Out of the box, each node makes its **own** certificate authority on its first start, in `tls/` beside its data.
  Browsers and agents (`--master-ca`) that trust the first node's authority will not trust the second one after a
  failover. If you want DENIS's own certificate anyway, start the first node, copy its whole `tls/` directory (`ca.pem`,
  `ca.key`, `server.pem`, `server.key`) to the second node's `--tls-dir` before the second node's first start, and give
  both the same `--tls-name <shared host name>`.
* DENIS's own certificate renews itself 30 days before it expires (about every two years), on whichever node is leader
  at the time, and only in that node's `tls/`. A one-time copy therefore drifts apart. Either put `--tls-dir` on a file
  system both nodes share, or copy `tls/` from the current leader (see `role` in `/api/health`) to the other node on a
  schedule. Your own certificate avoids this.

## What does not need to be shared

* **The GeoIP database** (`geoip/` in the data directory). Each node downloads and refreshes its own copy.
* **Backup files.** Only the leader runs the scheduled backup, and it writes to its own disk. A backup taken while one node
  was leader exists only on that node; if that machine is lost for good, the backup goes with it. Send backups off the
  machine with `--backup-upstream` instead of sharing the backup folder; the backup job needs the folder to itself.
* Each node's own log files and anything else about that process only.

## Load balancer or virtual address

Point agents, browsers and anything else at **one virtual address or host name** that checks both nodes and sends
traffic only to the one whose `/api/health` says `"role":"leader"`. Never point anything at one node's own address:

* the standby is by definition not the node that should serve you, and which node leads changes without any
  configuration change;
* the standby does not open the agent port at all, so an agent sent to it gets "connection refused", not a slow answer.

Example with HAProxy (its open-source version can check the body of the health answer; open-source nginx has no active
health check):

```
global
    maxconn 4096

defaults
    log     global
    retries 3
    timeout connect 5s
    timeout client  60s
    timeout server  60s

# TCP passthrough: DENIS keeps serving its own TLS end to end, so the
# certificate is managed in one place (see "The same certificate").
frontend denis_console
    mode tcp
    bind *:8443
    default_backend denis_console_nodes

backend denis_console_nodes
    mode tcp
    option httpchk GET /api/health
    http-check expect string "\"role\":\"leader\""
    server node-a 192.0.2.11:8443 check check-ssl verify none
    server node-b 192.0.2.12:8443 check check-ssl verify none

# The same for --ingest-listen if agents report to a separate port. The health
# check still goes to the console port: /api/health is only served there.
frontend denis_ingest
    mode tcp
    bind *:8444
    default_backend denis_ingest_nodes

backend denis_ingest_nodes
    mode tcp
    option httpchk GET /api/health
    http-check expect string "\"role\":\"leader\""
    server node-a 192.0.2.11:8444 check port 8443 check-ssl verify none
    server node-b 192.0.2.12:8444 check port 8443 check-ssl verify none
```

* `verify none` on the health check is for DENIS's own certificate authority, which HAProxy does not trust. With your own
  certificate, give HAProxy its authority (`ca-file`) and drop `verify none`.
* HAProxy checks every 2 seconds by default, about as often as the standby looks for the lock; checking much more often
  gains little.

## Testing a failover

Run this once after you set the pair up, and again after any change to either node's configuration.

1. **Check that exactly one node is leader:**
   ```
   curl -sk https://node-a:8443/api/health
   curl -sk https://node-b:8443/api/health
   ```
   One must answer `{"ok":true,"role":"leader"}`, the other `{"ok":false,"role":"standby"}` with HTTP 503. If both or
   neither say `leader`, stop: something is already wrong (two nodes on different databases, a database problem, or a
   node still starting).
2. **Note the time and stop the leader hard**, not gracefully, because a failover is meant for a leader that cannot clean
   up after itself:
   ```
   # on the leader's own machine
   sudo kill -9 $(pgrep -f 'denis run')
   ```
   At least once, also try pulling the network cable or switching the machine off: that tests how fast the database
   notices a connection that died without a word.
3. **Poll the standby until it says leader** and note how long it took:
   ```
   while true; do
     curl -sk https://node-b:8443/api/health && break
     sleep 0.5
   done
   ```
   Expect a few seconds plus your network and database round trip. If it takes tens of seconds, look first at the
   connection to PostgreSQL (long TCP keepalive, or a firewall or NAT that drops idle connections silently); see the
   [connection settings](#postgresql-connection-settings).
4. **Check through the shared address**, not the node directly: open the console through the virtual address. This tests
   your load balancer, not only the election.
5. **Check that the stopped node comes back as standby.** DENIS does not restart itself: a node that loses leadership
   exits, and your service manager must start it again. Put the database address in `/etc/denis/env`, the settings
   file the service reads (this is the supported place: the installer rewrites the service file on every run and refuses
   to run while that file names the database itself):
   ```
   DENIS_DATABASE_URL=postgres://denis@db.example/denis
   DENIS_DATABASE_PASSWORD=...
   ```
   and let systemd restart the node (`sudo systemctl edit denis`):
   ```ini
   [Service]
   Restart=always
   RestartSec=2
   ```
   The restarted node logs `standby: waiting for the install-wide HA leader lock` and stays standby.
6. When both nodes are up with one leader and one standby, you are done.

## The local fault lab (4.4)

**Status: Experimental.** `tools/ha-lab/` is a test setup for the people who build and review DENIS, not something to run
in production. It starts, in Docker on one machine, a three-node Patroni PostgreSQL 16 cluster (with etcd), HAProxy that
always points at the primary, Toxiproxy (one listener per DENIS node, to cut, stall and slow the link to the database)
and two DENIS nodes, and then injects faults and checks what the pair does. It shows how **our code** behaves under leader
loss, network faults and a database failover. It says nothing about a managed database service (its DNS switch, its
proxies and poolers, its TLS chain, its maintenance events, its latency between zones); that needs a run on the service
itself.

What you need: Docker (on a Mac: `colima start --vm-type vz --vz-rosetta --cpu 4 --memory 6`), about 6 GB of memory for
the Docker machine, and the PostgreSQL build of DENIS for Linux, which the lab builds itself.

```
tools/ha-lab/lab.sh build      # static Linux build of DENIS (PostgreSQL flavour) for the containers; slow once
tools/ha-lab/lab.sh up         # throw-away passwords are made now; starts the cluster, HAProxy, Toxiproxy and the pair
tools/ha-lab/lab.sh run        # all scenarios, about 16 minutes; or: lab.sh run s1_kill s5_fence
tools/ha-lab/lab.sh down       # removes containers, volumes and the passwords
```

The passwords are generated when `up` runs (into `tools/ha-lab/.env`, which git ignores) and are gone after `down`. The
results of a run are written to `tools/ha-lab/state/results-<time>.log` and `.json`. A sampler asks both nodes for
`/api/health` about five times a second during the whole run and counts every sample in which both answered `leader`.

| Scenario | Fault | What must hold |
|---|---|---|
| `s0_steady` | none, 60 s (`SOAK_SECONDS`) | one leader, one standby, election number unchanged |
| `s1_kill` | leader process killed with `kill -9` | the other node leads, the number moved once, the killed node returns as standby |
| `s1b_cable` | leader machine vanishes: frozen, network gone, no reset | the other node leads, the number moved once, the old one leaves when it returns |
| `s2_lock_session` | `pg_terminate_backend` on the leader's lock session | the old leader exits, a single leader again, number moved once |
| `s3_partition` | the leader's link to the database is cut with a reset | the other node takes over, the old one does not keep leading |
| `s3b_half_open` | packets swallowed, nothing reset | the old leader gives up by itself within about 9 s, the other node takes over |
| `s3c_cut_after_takeover` | the same, in the first second after a node won the election | the new leader leaves within 100 s |
| `s4a_switchover_async`, `s4b_switchover_sync` | planned switchover of the database, asynchronous and with a synchronous standby | both nodes recover alone within 120 s, one leader |
| `s4c_primary_dies` | the database primary is killed, a replica is promoted, the old primary rejoins | the same |
| `s5_fence` | a session without a leader mark, and one with the deposed leader's mark, try to write | both refused with `DN001`; the current mark is accepted |
| `s5b_paused_leader` | the leader is frozen, its lock session cut, the other node leads, the old one resumes | the new leader answers `leader` on every sample, the old one leaves |
| `s6_split_brain` | a third node with a copy of the leader's data directory; a node with another `secrets.key`; a write without a mark | the third node stays standby; the stranger never leads; the write is refused |
| `s7_slow_link` | 200 ms added delay and 5 % loss on the path to the database for 120 s | nothing flaps: same leader, number unchanged, no node exits |
| `s8_backup_restore` | `pg_dump`, two takeovers, restore of the old dump, start of the pair | the pair starts, the first takeover after the restore works, the election number moves forward |

**Result of the run of 2026-11-04** (Apple silicon, Docker through colima, PostgreSQL 16.15, Patroni 3.3.2; 3,486 health
samples in 16 minutes, none with two leaders): 13 of 15 scenarios passed. Measured: `kill -9` of the leader to the other
node answering as leader 0.8 s; lock session dropped 0.3 s until the old leader left; database switchover (asynchronous
and synchronous) and promotion after killing the primary: both nodes were a working pair again within 1 s, 1 s and 8 s
(the primary moved in about 22 s after the kill); a slow link (200 ms, 5 % loss) for 120 s changed nothing. The pair
restored from an old dump started and took over again. Two scenarios failed, see the next list.

**Findings of this run (one fixed and to confirm in the lab, two open).**

* *A link that goes half-open delayed the old leader's exit far beyond the documented 8 seconds* (`s3b_half_open`,
  `s3c_cut_after_takeover`; **fixed after the run, to confirm in the lab**: not yet re-run there). In a node that had been leading for a
  while and was cut off, the log said "did not answer within 8 s" but only about 60 seconds after the cut in all four
  scenario runs, and a node cut off in its first second as leader had not left after 100 s. The database fence still
  refused every write of that node and the lease ran out after 3 s, so nothing was stored by it; the health answer,
  however, said `leader` until the process exited. Cause: the check's 8 s deadline was an asynchronous timer, and the node's
  console and jobs call the database from asynchronous code, so while the link was silent those calls held every worker
  thread of the runtime and the timer could not fire until one was free. A two-process test (a proxy that swallows the
  traffic, with console requests running meanwhile) reproduced it: the old program had not left after 40 s. Fix: the check (lease renewal, the deadline, the exit) now runs
  on its own operating-system thread with plain thread waits, and asks the database through one small thread of its own;
  it does not use the runtime's workers or the connection pool. `/api/health` also stops saying `leader` the moment the
  lease has run out (a node that only waits after a takeover still says `leader`). With the fix the same test sees the node leave after about 9 s. The lab scenarios have not been re-run
  (the program for the lab does not build in a Docker machine of 6 GB); run `lab.sh run s3b_half_open
  s3c_cut_after_takeover` to confirm, with a larger Docker machine for `lab.sh build`. While the link is silent the
  node's console itself may not answer either (its workers wait on the dead connection); for a load balancer that also
  counts as not leader.
* *Silent loss of the leader machine takes about 2.5 minutes to be noticed in this lab* (`s1b_cable`: 153 s), because the
  database server's peer is HAProxy and Toxiproxy, which keep the session until their own keepalive gives up. The 4.4
  server-side keepalive settings (about 25 s) cannot be tested here; a managed run can.
* *Not done yet:* the run on a rented managed PostgreSQL service (step P13 of the plan), which happens after the 4.4.0 release (planned for 4.4.1), with a soak and the 10, 50 and 100
  tenant measurement. Until then the lab results above are the limit of what is verified.
* The setup checks the election mark the pair writes; it does not send agent data, so the "no lost agent data" rule is not
  covered, and a soak of many hours is a separate run (`SOAK_SECONDS` lengthens the baseline).

What the lab leaves out on purpose: a per-tenant `pg_dump -n` and a restore into the standalone SQLite path (the tenant
steps have their own tests), a provider point-in-time restore, and everything that belongs to a managed service.

## PostgreSQL connection settings

A PostgreSQL connection silenced by a network split, a firewall or a dead peer reports no error by itself. Without limits
a leader cut off from the database would wait for the operating system's TCP give-up time, often many minutes, and the
standby could not take over meanwhile. Every DENIS connection therefore carries these limits. Change one with its
environment variable (seconds; `0` switches the limit off), or by naming the same libpq parameter in `--database-url`,
which always wins (`keepalives_idle`, `keepalives_interval`, `keepalives_retries`, `connect_timeout`, `tcp_user_timeout`,
and `options=-c statement_timeout=...`).

| Setting | Variable | Default | What it limits |
|---|---|---|---|
| Connect timeout | `DENIS_PG_CONNECT_TIMEOUT_SECS` | 10 | Opening a connection to a server that does not answer |
| TCP keepalive idle / interval / retries | `DENIS_PG_KEEPALIVE_IDLE_SECS`, `DENIS_PG_KEEPALIVE_INTERVAL_SECS`, `DENIS_PG_KEEPALIVE_RETRIES` | 10 / 5 / 3 | A silent peer on an idle connection is noticed after about 25 s |
| TCP user timeout (Linux) | `DENIS_PG_TCP_USER_TIMEOUT_SECS` | 20 | Data written but never acknowledged |
| Statement timeout | `DENIS_PG_STATEMENT_TIMEOUT_SECS` | 120 | A query that runs or stalls on the server; DENIS also stops waiting 30 s later |
| Lock wait timeout | `DENIS_PG_LOCK_TIMEOUT_SECS` | 30 | Waiting for a lock another session holds |
| Idle-in-transaction timeout | `DENIS_PG_IDLE_IN_TRANSACTION_TIMEOUT_SECS` | 60 | A transaction left open |
| Leader-lock session statement timeout | `DENIS_PG_LOCK_SESSION_STATEMENT_TIMEOUT_SECS` | 5 | The leader lock's own statements (idle-in-transaction there is twice this; DENIS stops waiting 3 s later) |

Database migrations at start-up lift the statement and lock limits for their own transaction, because a migration can be
long and can wait for the other node.

Since 4.4 each connection also asks the **database server** to drop it quickly when the DENIS machine disappears (the
server-side keepalive and `tcp_user_timeout` settings, from the same variables). Without this, a leader machine that
lost power would keep the leader lock for as long as the server waits on the dead connection, up to about two hours with
Linux defaults, and the standby could not take over. DENIS also accepts only a connection to a server that takes writes
(`target_session_attrs=read-write`), and opens again a pool connection that the server closed. A server that refuses one
of these settings still works; the log then names the setting that was skipped. Details: `HA_DEPLOYMENT.md`, "Dead peers".

## What happens to the old leader

The leader checks once a second that it still holds leadership. Each good answer renews a local lease of three seconds.
If the answer says another node leads, is an error, or does not arrive within about 8 seconds, the node gives the lease up
and exits; your service manager starts it again as standby. This check runs on its own thread, apart from the
console's and the jobs' work, so a database link that has gone silent cannot delay it. Once the lease has run out,
`/api/health` no longer answers `leader`, even before the process has exited.

Everything that has an effect outside the database checks the lease immediately before it acts: sending a notification
(every channel and the webhook), grouping an alert into an incident and notifying about it, exporting to OpenObserve,
relaying to an MSP, and moving the position each of these keeps. A node whose lease has run out does none of them. So a
node that lost leadership can still send something for at most about three seconds after its last good check, even when
its connection to the database died silently. A node that has just taken over waits four seconds before it sends or moves
anything itself (the console and the agents' ingest work at once), so the old leader has stopped by then. Since 4.4 the database also refuses that node's writes once another node has
taken over ([the write fence](#the-write-fence-44)).

## Delivery is at least once, not exactly once

Notifications and exports are delivered **at least once**:

* **Channel messages go through a queue in the database (4.4).** A message is written there in the same step that moves the
  channel's position, and only the leader sends. Each send is noted after the receiver accepted it. If the leader stops
  in between (a crash, a lost lease), the next leader finds the message still marked as being sent, waits for the
  claim to go stale (two minutes), and sends it again **with the same key** (the
  `Idempotency-Key` header of a webhook, a fixed e-mail `Message-ID`, the Jira label or ServiceNow line that lets a
  retry find the ticket). The old leader's late note that it delivered is refused by the database fence.
  Exports (syslog, Elasticsearch, OpenObserve) keep their own position in the database and move it only after the
  target accepted the batch.
* A node can pass the lease check, lose leadership a moment later and still finish the one send it had started, while the
  new leader sends the same alert.
* **Database writes are fenced since 4.4** (see [The write fence](#the-write-fence-44) below): a write from a node that
  is no longer the leader is refused by the database itself and stores nothing. What stays at least once is everything
  that leaves the database (a message already on its way, an export already sent), because a database cannot take
  back a message.

Where a duplicate matters, make the receiver tolerate it: the generic webhook carries the alert's id, and every exported
document has a stable id. Alerts older than 24 hours are never sent, which limits how old a repeated message can be.
Automatic enforcement on a pair runs only on the leader. The fence closes the database side of a leader that lost its
lease in the middle of a write, but an action already sent to a switch, firewall or other device cannot be recalled, so
treat [automation](enforcement.md#automation) on a pair with care while high availability is Experimental.

## The write fence (4.4)

**Status: Experimental.** It ran against PostgreSQL 16 in a test container, with two processes on one machine. It has not
been tried on managed or clustered PostgreSQL.

Before 4.4 only the code that sends things asked "am I still the leader" (the lease above); the database accepted a
write from any connection. A leader whose lock session alone was dropped, or that was paused for a while, could still
finish a write after the other node had taken over, and a moved cursor or an overwritten row could follow. Now:

* Every DENIS table (a fixed list of about eighty, the same in the main schema, a tenant schema and the control schema) has a trigger that runs once per write statement and compares the **leader mark** the
  connection carries with the one in the database. The mark is the election number plus a random token chosen at each
  takeover. The token matters when the database itself went back in time (a replica that lost its last commit was
  promoted): the number can then repeat, the token cannot.
* A node puts its mark on each of its database connections when it opens them, and again when it opens one anew. A
  connection without a mark cannot write. Reading is never refused.
* A node that takes over waits until the previous leader's open write transactions have finished (at most about two
  and a half minutes; the previous leader's own statement limit is two minutes), then records its mark. From that
  moment every write with the old mark is refused: nothing the old leader writes after the takeover is stored, and a
  write that was already running has finished before the new leader reads anything.
* A refused write comes back as `this node is not the HA leader`. The old leader's lease is revoked at once and the
  process exits without waiting for its next check. A web request or an agent report that meets the refusal gets HTTP
  `503` with `Retry-After`, not an internal error: an agent keeps the batch and sends it again to the node that leads
  now, and a repeated batch is not applied twice.

What you may see and what to do:

* `denis user ...`, `denis secrets ...` and the other command-line tools that change a PostgreSQL installation now take
  the leader lock first. While a DENIS node leads they stop with "a DENIS node is running as the HA leader": stop DENIS
  on both nodes first. Their writes bypass the fence on purpose, and the next start of the leader logs that the
  database was changed with the fence switched off.
* An operator who must change data by hand in `psql` types `SET denis.fence_exempt = 'maintenance';` first (any other
  value is no exemption), and should do so only with DENIS stopped. Without it the write is refused with SQLSTATE
  `DN001` and a message that names this setting.
* **Give DENIS a schema or a database of its own.** The fence is attached to the DENIS tables only, never to a table of
  another application, but DENIS still assumes it owns its schema (it changes the tables in it at every upgrade). Do not
  share the schema with another application. A tenant's database role has no right at all on the election table or on
  the node notes: the trigger function runs as the role that migrates the main schema.
* The standby's note about a refused start (a different `secrets.key`) is kept in the table `ha_node_notes`, which the
  fence does not cover, because a standby must not write the other tables.
* The cost is one trigger call per write statement. Measured on PostgreSQL 16.15 in a container on a busy laptop: a
  single-row insert took 663 µs without the trigger and 670 µs with it (+1.0 %); a stored call that inserts and updates
  and commits took 2,988 µs and 2,969 µs (the difference is below the noise of the disk flush); a 50-row insert took
  1,236 µs and 1,233 µs. On a real server the numbers differ; the trigger itself adds a few microseconds per statement.

## Upgrading a pair to 4.4

4.4 changes three things that an older program cannot read. Read this before you update, and update a test pair first.

* **The database schema** goes to version 60 (58: the write fence; 59: the delivery queue; 60: the split of a hardware address). An older program refuses it
  ("newer than this build").
* **The format of stored secrets** changes from `enc1:` to `enc2:` at the first start of the leader. This is one way:
  an older program cannot read `enc2:` (details and the two ways back: [Security](security.md#upgrading-the-secret-format-44)).
* **The tenants** stay in their SQLite files until you move them. Nothing moves by itself.

**1. Back up first. This is yours to do; DENIS does not replace it.** The update also keeps its own copy, but take yours
before you start:

```
PGPASSWORD="$DENIS_DATABASE_PASSWORD" pg_dump --format=custom --file=denis-before-4.4.dump "$DENIS_DATABASE_URL"
sha256sum <data directory>/secrets.key     # the same value must come out on both nodes
denis secrets key-export --to /safe/place/denis-master-key.json   # a copy of the key under a passphrase, kept apart from the dump
```

A dump without the matching `secrets.key` cannot give back the stored credentials, and the key belongs apart from the
dump. If tenants live in the database, the dump covers all schemas; one tenant alone is `pg_dump --schema=t_<id>`.

**2. Update both nodes** (or follow your own rolling order, but never run 4.3 on the second node once the first node on
4.4 has moved the secrets). The first start of 4.4 on the leader applies the schema and, as the leader, moves the secrets
in one transaction (all or none; if it cannot, it starts in the old format and the Health page says why).
`denis secrets migrate --dry-run --database-url ...` shows the counts beforehand.

**3. Going back.** Stop DENIS on **both** nodes first (below). Then either:

* **Restore the dump** together with the `secrets.key` it belongs to, and start the older version. This is the simple way
  and covers the schema and the secrets together. Or
* **Undo the changes in place**, in this order, then start the older version:

  ```
  denis secrets downgrade-envelope --database-url postgres://denis@db.example/denis   # enc2: back to enc1:, deletes the data key
  # schema 59 -> 58: the two statements of "Rolling back V59" in Operations
  denis db undo-v58 --database-url postgres://denis@db.example/denis                  # schema 58 -> 57
  ```

  (the password in `DENIS_DATABASE_PASSWORD`; add `--dry-run` to `downgrade-envelope` to see the counts first). Rolling
  back V59 by hand is described in [Operations](operations.md#rolling-back-v59): it removes the waiting delivery
  messages and nothing else. `denis db undo-v58` is refused while a node leads and while the database is at version 59.

`denis db undo-v58` drops the trigger from every table, the functions `denis_fence()` and `denis_fence_attach()`, the
table `ha_node_notes` and the column `ha_leader_epoch.token`, and sets the schema version back to 57, in one transaction;
no data is touched. The same steps by hand:

```sql
DO $$ DECLARE t record; BEGIN
  FOR t IN SELECT tgrelid::regclass AS r FROM pg_trigger WHERE tgname = 'denis_fence' AND NOT tgisinternal
  LOOP EXECUTE format('DROP TRIGGER denis_fence ON %s', t.r); END LOOP; END $$;
DROP FUNCTION IF EXISTS public.denis_fence_attach();
DROP FUNCTION IF EXISTS public.denis_fence();
DROP TABLE IF EXISTS public.ha_node_notes;
ALTER TABLE public.ha_leader_epoch DROP COLUMN IF EXISTS token;
UPDATE schema_version SET version = 57 WHERE version = 58;
```

The next start of 4.4 applies the versions again. Tenants moved to PostgreSQL: the SQLite files were never changed, so
going back to SQLite is "start without `--database-url`" (what was done on PostgreSQL since is not in them; see below).

### Stopping both nodes for a command-line tool

The tools that change a PostgreSQL installation (`denis user ...`, `denis secrets ...`, `denis db undo-v58`,
`denis tenant ...`, `denis operator ...`) take the leader lock and are refused while a node leads. Stop the standby first,
then the leader, check that neither answers, run the tool, then start the first node again and then the second:

```
# on each node (systemd; OpenRC: rc-service denis stop; Docker: docker stop <container>)
sudo systemctl stop denis
# check from anywhere: both must refuse the connection or time out
curl -sk --max-time 3 https://node-a:8443/api/health; curl -sk --max-time 3 https://node-b:8443/api/health
# run the tool on one node with its own --database-url and --data-dir, then:
sudo systemctl start denis     # on the node that was leader first, then on the other
```

Behind a load balancer the shared address is down for the time between the two stops and the first start; plan it for a
quiet moment. Agents keep their batches and send them again.

## The control schema and tenant schemas on PostgreSQL (4.4)

**Status: Experimental.** Tenants on PostgreSQL stay Experimental until they have been measured with 10, 50 and 100
tenants on a managed cluster; none of those numbers exist yet. Everything here is tested against PostgreSQL 16 in a
container, with two DENIS processes on one machine.

**What changes for an installation.** Nothing, unless it runs with `--database-url`. With it, `denis run` keeps the
control store (tenants, console host names, the MSP's operators and remote customers, link keys) in the schema
`denis_control` and every tenant in its own schema, all on the one pool of connections (`--pg-pool-size`, default 8,
1 to 64; it does not grow with the number of tenants), and `control.db` and `tenants/<id>.db` are not read. Both nodes of
a pair then run the same tenants: the leader loads each tenant, the node that takes over loads them from the same
schemas. A tenant whose schema is missing or whose tables cannot be brought up to date does not load and answers 503;
every other tenant starts, and the log names the reason.

**Getting there from SQLite tenants.** Stop DENIS, then run `denis tenant move-to-postgres --database-url ...` (add
`--dry-run` first: it reads, reports tables, rows and problems, and changes nothing). It copies `control.db` into the
control schema and each `tenants/<id>.db` into the tenant's schema (made and migrated first, then filled), one
transaction per table, and then checks every table again: row count and a checksum over all its values on both sides.
Secrets stay sealed exactly as stored and no value is printed. The SQLite files are only read. The command can be run
again after an interruption and continues with the tables not finished; a tenant that already holds data of its own on
PostgreSQL is not overwritten unless you add `--replace-target` (which destroys that data). `default` is not moved: it
is the installation's own database (`public`) and is not touched by this command.

* **`control.db` stays the source until the copy is verified.** `denis run --database-url` refuses to start while a
  `control.db` in the data directory holds tenants, operator accounts, remote customers or MSP keys that are not in the
  database yet, with the command to run. After the move, keep the files for a while; once you rely on PostgreSQL, rename
  `control.db` (for example `control.db.moved`) so it cannot be mistaken for the live one.
* **Rollback.** The SQLite files were never changed: stop DENIS, start it without `--database-url` and it runs from them
  as before (anything done on PostgreSQL since is not in them). To remove what was copied: `denis tenant delete <id>
  --yes --database-url ...` drops one tenant's schema and role; `DROP SCHEMA denis_control CASCADE` drops the control
  schema. `denis tenant move-to-postgres --replace-target` copies again from scratch.
* **The command-line tools need DENIS stopped on both nodes** when `--database-url` is given (`denis tenant add | delete
  | list | suspend | resume | limit | set-hosts`, `denis operator ...`, `denis secrets ...`): they take the leader lock
  and write with the leader fence off, as `denis user` does, and are refused while a node leads. On an SQLite installation `denis tenant suspend` reaches a running DENIS within
  seconds; on a PostgreSQL installation it needs the stop in this version. `denis msp` and `denis msp-link`
  do not work on a PostgreSQL installation yet and say so. `denis tenant export` and `import` work on SQLite tenants; for
  a PostgreSQL tenant use `pg_dump -n t_<id>`.
* **What stays on each node's disk.** The tenants' background files (their agents' uploaded backups, under
  `<data dir>/tenants/<id>/`) are files, not rows: after a failover the new leader does not have the old leader's. Use
  `--backup-upstream` as for `default`.
* **Creating a tenant** (`denis tenant add <id> --name ... --database-url ...`) makes its schema and role and creates its
  tables at once. A login role without `CREATEROLE` is refused before anything is registered, with the exact
  `ALTER ROLE ... CREATEROLE` to run once as a superuser. A superuser login role works, and the command warns that the
  tenants are then kept apart by the program's schema switch alone.

**The control schema `denis_control`.** The same data as `control.db` (tenants and their console host names, the MSP's
operators with memberships, sessions, second factors, handoff codes, remote customers, link signing keys and MSP
settings), kept in the schema `denis_control` of the installation's database, so that both nodes of a pair see the same
tenants and operators. It has its own small version series (`C1`, `C2`, ...), apart from the schema version of the data
tables. Every table has the write fence of the previous section: a node that is no longer the leader cannot write it.

* Taking it away again: `DROP SCHEMA denis_control CASCADE;` removes the schema completely and touches nothing else.
  The local `control.db` stays the source of truth until a copy to PostgreSQL has been made and checked; keep it.
* Sealed values in it (the operators' authenticator secrets, the MSP link keys) stay sealed under the installation's
  secret key, never in plain text. After a key change the two tables are rewritten so the replaced values do not stay
  in the table files.
* Before you upgrade, take the backup the previous section asks for; the new schema is created at the next start.

**A schema and a role per tenant.** A tenant `acme` lives in the schema `t_acme`, which belongs to the database role
`denis_t_acme`. `default` stays in `public` (nothing is moved). The program reaches every tenant through the same small
set of database connections (8 by default, shared by all tenants, so the number of connections does not grow with the
number of tenants). Before each piece of work the connection switches to the tenant's schema and role; the search path
of a tenant connection lists only its own schema, so a missing table is an error and never falls back to another
tenant's table, and the cached statements of a connection are dropped at each switch.

* The database user in `--database-url` must be an **ordinary role with `CREATEROLE`** (not a superuser). It owns
  nothing in the tenant schemas and is a member of the tenant roles without using their rights unless it switches
  (PostgreSQL 16: `WITH INHERIT FALSE`). A session that forgets to switch, or switches to another tenant, is then
  refused by the database ("permission denied"). On PostgreSQL before 16 the user must be `NOINHERIT`
  (`ALTER ROLE denis NOINHERIT`); creating a tenant is refused with that exact command if it is not. A superuser
  ignores all of this: it works, but the tenants are kept apart only by the program's switch, and the program says so.
* If the database user may not create roles (some managed services), creating a tenant is refused with a clear message.
  There is no weaker mode that does it anyway.
* Each tenant schema has its own copy of the data tables and its own `schema_version`, and the write fence on every
  table. The main schema (`public`) must be at schema version 58 or newer first: the fence function, the election
  table and the standby's notes exist once, there.
* Backups: the backup of a tenant is a `pg_dump --schema=t_acme`; the backup of `default` is a dump of `public` only.
  Removing a tenant drops its schema and role for good (backups taken earlier still hold its data).
* PgBouncer in transaction mode does not work with DENIS (session locks and session settings); use session pooling or a
  direct connection.
* Numbers for many tenants (10, 50, 100) have not been measured and none are promised.
