# High availability: two nodes on PostgreSQL

This page is for the administrator who runs two DENIS servers against one shared PostgreSQL database, with one of them
leading and the other on standby. It covers what must be the same on both machines, what must not, how to put a load
balancer in front of them, how to test the pair yourself, and what is and is not guaranteed after a failover. The short
version is in [Deployment › PostgreSQL and a second node](deployment.md#postgresql-and-a-second-node-optional).

**Before you start:**

* High availability needs PostgreSQL. A SQLite install is never a pair.
* It needs the PostgreSQL build of DENIS. A build without it refuses `--database-url`. No self-build is needed: a ready-made PostgreSQL build is attached to every release from 4.2.1 (`denis-pg-x86_64-unknown-linux-musl`, `denis-pg-aarch64-unknown-linux-musl`): static, signed like the others, so nothing needs to be built. `sudo bash install.sh --postgres` installs it, and it updates itself to the PostgreSQL build of each new release. `denis --version` ends with `(postgresql)` when it is that build.
  Building it yourself (`cargo build --release --features postgres`) still works; a build from 4.2.1 source cannot update itself on a platform that has no PostgreSQL release file. **If you built the PostgreSQL program by hand from 4.2.0 or earlier, do not use the console Update button** (the old program does not know the flavour and would take the standard build, which refuses `--database-url`): run `sudo bash install.sh --postgres` once instead. Running the installer again on a PostgreSQL installation without `--postgres` stops with a message; `--standard` is the explicit way back to the standard build.
* Both nodes' `--database-url` point at the same database. The password goes only in `DENIS_DATABASE_PASSWORD`, never in
  the URL or on the command line.
* **Not together with tenants.** An install with tenants besides `default` refuses to start with `--database-url`
  ([Multi-tenancy](multi-tenancy.md)).
* The availability of PostgreSQL itself (a managed or clustered service) is up to your database platform. When the
  database is unreachable, both nodes stay on standby, because neither can become leader.
* This has been tried with PostgreSQL 16 in a test container and with two processes on one machine. It has not been tried
  on managed or clustered PostgreSQL in production. Run the [failover test](#testing-a-failover) on your own pair before
  you rely on it.

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
`denis user reset-mfa --unreadable` with that node's `--database-url` and `--data-dir` removes the authenticator apps the
new key cannot open (those people set them up again) and records the new key for the pair; integration credentials are
entered again as after any restore without the key.

Keep a copy of `secrets.key` safely and separately from the database backups (not in the same place or the same
archive): a restore needs it, and a database restored without the matching key asks you to enter every integration
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
    server node-a 10.0.10.11:8443 check check-ssl verify none
    server node-b 10.0.10.12:8443 check check-ssl verify none

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
    server node-a 10.0.10.11:8444 check port 8443 check-ssl verify none
    server node-b 10.0.10.12:8444 check port 8443 check-ssl verify none
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
   exits, and your service manager must start it again. With systemd:
   ```ini
   [Service]
   ExecStart=/usr/local/bin/denis run --database-url postgres://... --listen 0.0.0.0:8443 ...
   Restart=always
   RestartSec=2
   ```
   The restarted node logs `standby: waiting for the install-wide HA leader lock` and stays standby.
6. When both nodes are up with one leader and one standby, you are done.

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

## What happens to the old leader

The leader checks once a second that it still holds leadership. Each good answer renews a local lease of three seconds.
If the answer says another node leads, is an error, or does not arrive within about 8 seconds, the node gives the lease up
and exits; your service manager starts it again as standby.

Everything that has an effect outside the database checks the lease immediately before it acts: sending a notification
(every channel and the webhook), grouping an alert into an incident and notifying about it, exporting to OpenObserve,
relaying to an MSP, and moving the position each of these keeps. A node whose lease has run out does none of them. So a
node that lost leadership can still send something for at most about three seconds after its last good check, even when
its connection to the database died silently.

## Delivery is at least once, not exactly once

Notifications and exports are delivered **at least once**:

* Each sender keeps its position in the database and moves it only after the target accepted the message. If the process
  stops between the two, the next leader sends that message again.
* A node can pass the lease check, lose leadership a moment later and still finish the one send it had started, while the
  new leader sends the same alert.
* **Known limit (until 4.1.4):** database writes carry no leader mark. In the few seconds after a failover the old leader
  can still write a row that the new one also writes.

Where a duplicate matters, make the receiver tolerate it: the generic webhook carries the alert's id, and every exported
document has a stable id. Alerts older than 24 hours are never sent, which limits how old a repeated message can be.
Automatic enforcement on a pair runs only on the leader, but DENIS cannot yet fence a leader that lost its lease in the
middle of a database write, so treat [automation](enforcement.md#automation) on a pair with extra care.
