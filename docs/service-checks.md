# Service checks (availability from this server)

**Experimental** (4.6.0). An administrator lists services, and DENIS asks each of them again and again from the
DENIS server: a ping, a TCP port, a DNS question or a web page. Each answer becomes one of four plain states, and a
service that stops answering raises one notice. It was tested only against stand-in services on 127.0.0.1 and with
DENIS's own tests. **It has not been run on a customer network yet.**

How sure each statement on this page is:

* **documented**: an RFC or a vendor document says so (named);
* **verified**: read in DENIS's source code or checked by DENIS's own tests on 127.0.0.1, never on real equipment;
* **best guess**: neither; it still has to be checked on a real network.

## What it does and what it does not do

* **Only what an administrator types.** DENIS asks the host, port or DNS server written in a check, and nothing else.
  It never sweeps a network, never takes a target from the inventory, from a web page, from a redirect or from a DNS
  answer other than the resolution of the typed name (verified).
* **From this server only.** Every state is "as seen from the DENIS server". A check does not say what a user at another
  place sees (verified). A reading by a remote agent is not part of 4.6.0.
* **Read only, no credentials.** A web check sends one `GET`, no body, no extra headers and no sign-in; a URL with a
  user name or password is refused. A check that needs a sign-in is not possible in 4.6.0 (verified).
* **No alert, no incident, no action.** A failing check is a notice (the bell and your notification channels), never a
  security alert, and no rule, response or Autopilot starts from it (verified).
* **The main installation only.** A hosted tenant gets `404 not_available_here` (verified).
* **Not run under `--passive-only`.** A server started passive-only does not run checks, and Health says so (verified).
  Only the active node of a high-availability pair runs them; the standby asks nothing (verified).

## The four states, and "this server cannot check"

A check is always in one of the four states described in [What the four states mean](operations.md#what-the-four-states-mean):
*Healthy*, *Degraded*, *Not reachable from this server* and *Not known*. Two cases need care.

| What happened | State | Why |
|---|---|---|
| The service answered as expected | Healthy | |
| It answered, but slower than "slow above", with a status you did not expect, without the text you asked for, with a certificate that ended, is about to end or is not trusted, or with a DNS answer that lacks the value you expected | Degraded | it answered this server, and something about the answer is wrong |
| Nothing answered: no echo reply, the connection timed out or was refused, no HTTP status line, no DNS answer, or the name does not exist | Not reachable from this server | a question left this server and nothing came back. It never says "down" or "offline" |
| This server could not ask: no permission to send a ping, its own resolver failed, the main network interface is in a failure state, the local network stack refused to send, or the target address is not allowed | Not known | no question left, or DENIS knows its own side is at fault, so it says nothing about the service |

**"Not reachable from this server" and "This server cannot check right now" are two different things** (verified).
The first means a question was sent and nothing came back. The second means no question was sent, or this server knows
its own side is at fault; the state is then *Not known* and DENIS raises **one** notice, "This server cannot run its
checks right now", instead of one per check. DENIS decides this only from positive evidence of a local fault (an error
of this server's network stack, the state of its main interface, its own resolver). It does not guess "everything
failed at once, so it must be this server": that is exactly what a real outage of the target network looks like.
Only a fault of this server as a whole (its main interface in a failure state, its own resolver failing) raises that
one notice. A fault of the way to one target (no route to that address, for example an IPv6 target on a server without
IPv6, or a send the network stack refused) makes only that check *Not known*, with its reason, so that one such check
does not open and close the notice for every other one.

A check that is disabled, or has not run yet, is *Not known*, shown as "Not monitored" or "Not known" in grey, never as
a fault and never as offline (verified). A check whose last judgement is older than three intervals plus its timeout
reads as *Not known* too, so a stopped job never shows an old "Healthy" (verified).

A state needs **two bad runs in a row** to open and **two good runs in a row** to close, the same rule as port health
(verified). A certificate about to expire opens after one run, because a date does not flap.

## The four kinds of check

| Kind | What one run does | Settings |
|---|---|---|
| Ping (ICMP) | up to 3 echo requests, 1 second apart, 16 bytes of data | "slow above" (milliseconds) |
| TCP port | opens a connection to the port and closes it | the port; "slow above" |
| DNS question | asks one DNS server (typed as an IP address, port 53 by default) one question of the type A, AAAA, CNAME, MX, TXT or NS; optionally expects a value in the answer | the server, the name, the type, "expect" |
| Web page (HTTP or HTTPS) | one `GET` of one path on the typed host and port, with the `User-Agent` `DENIS-check`; no redirect is followed (a redirect is a status like any other); no proxy | the path (at most 1,024 bytes, may carry a query: do not put a token in it, everyone who may read the check's site sees the path), expected status (for example `200-399`, `200` or `200,204`), a text to find, "verify certificate", "warn this many days before the certificate ends", "slow above" |

For a web page over HTTPS DENIS reads the server's certificate from the same connection that carries the request, and
shows its end date, subject and issuer (cleaned and cut to 200 characters). Without "verify certificate" any
certificate is accepted and only its end date is judged; with it, the public root certificates DENIS carries decide
whether it is trusted and whether the name matches. A private certificate authority is therefore "not trusted" in 4.6.0
(verified in the code; how this behaves with a real internal authority is best guess).

DENIS keeps nothing a target wrote except that certificate text. A run stores numbers and one reason code.

## Limits

All of these are constants in the program, shown to the console by `GET /api/checks` (`limits`) (verified):

| Limit | Value |
|---|---|
| Checks in an installation | 100 (best guess for one server, not measured) |
| Interval | 30 seconds to 24 hours; 5 minutes by default |
| Waiting time (timeout) | 1 to 10 seconds, never more than a third of the interval; 5 seconds by default. It counts from the start of the run, the look-up of a name included, and bounds every step of it (a TLS handshake and an answer that arrive a byte at a time too); a ping waits that long for each echo |
| Runs in flight | 8 in all, 1 per check, 2 per target as typed (a name and its address count as two targets) |
| Web answer read | status line and headers at most 16 KiB; body at most 64 KiB, and only when a text is to be found |
| Text to find or value to expect | at most 200 bytes; a text to find is compared as bytes, a DNS value as DNS writes it (an address in any of its forms, a name in any case and with or without its final dot, a TXT value as bytes) |
| DNS answer | at most 4 KiB |
| Name of a check | 1 to 80 characters |
| "Run now" | refused for 30 seconds after the last run (`409 too_soon`), and for a check that is switched off (`409 check_disabled`) |
| A dependency chain | at most 4 levels |

At the shortest interval, 100 checks are about 3 runs a second (arithmetic, verified). Checks saved together do not all
run together: each check's schedule gets a small offset of up to 10 % of its interval, and a new check first runs within
10 seconds (verified).

## Which addresses a check may ask

Private addresses are the point of the feature, so they are allowed. The rules are applied when a check is saved and
again **on every run, on every address the name resolves to** (a name can change) (verified):

* Never, whatever is ticked: this computer's own addresses, loopback, link-local (with the cloud metadata address),
  the other cloud metadata addresses, unspecified, multicast, broadcast, `0.0.0.0/8` and `240.0.0.0/4`. The same holds
  for such an IPv4 address written inside an IPv6 one (NAT64 `64:ff9b::/96` and `64:ff9b:1::/48`, 6to4 `2002::/16`,
  the old IPv4-compatible `::a.b.c.d`). The refusal is `target_denied`.
* A **public address** needs the tick *outside my networks* on that check, and asking for it needs your password again
  (`target_outside`, `reauth_required`, `bad_password`).
* A name is resolved once per run, every answer must pass, and the connection goes to the checked address, never to
  the name again, so a name that changes between the check and the connection cannot reach a refused address. The name
  is still sent in the `Host` header and for TLS.
* A DNS check is guarded on its **server** (which must be an IP address); the name it asks is data, not a target.
* The tenant's outbound policy is asked as well.

A run the guard refuses is *Not known* (reason `target_denied` or `target_outside`): DENIS did not ask, so it says
nothing about the target.

## Industrial networks: off until you switch them on

A check is an active probe, and DENIS keeps active traffic away from industrial equipment. A check is treated as
industrial, and **held**, when (verified):

* its target address belongs to a device DENIS identified as industrial, or
* the device's own Purdue level, or the level of its zone, is 3 or below (level 3.5 is not industrial by this rule), or
* the installation was started with `--profile ot --active` (every check is then industrial; under
  `--profile ot` without `--active` no check runs at all).

A held check sends nothing. It shows "Not run: the target is industrial equipment, and checks are not switched on for
its site or zone", with the state *Not known*. The setting that lets checks reach industrial equipment is empty on every
installation and is never filled by an update. An administrator of the whole installation lists the sites and zones in
*Checks to industrial equipment* in the console (`PUT /api/checks/ot-policy`), with the password again; the change is
audited. A ping check to an address in a network where ping is switched off is held as well. If DENIS cannot read the
inventory, the zones or the setting, the run is held (`ot_unknown`): it never falls back to "allowed".

The inventory of **every** site is asked, not only the inventory of the check's own site: when any device that has the
target's address now is industrial, the check is held, so that a controller seen by an agent of another site is never
probed. The check's site only decides which entry of *Checks to industrial equipment* lets it through. Where two sites
use the same private addresses, a check may therefore be held for a device of the other site; list the site or zone
to let it run.

A target that is not in the inventory is not industrial by this rule, because DENIS cannot know. Do not list the address
of a controller that DENIS has not seen yet.

## Dependencies and "affected"

Without help, a DNS server that stops answering would raise one notice for itself and one for each of thirty checks
that need it. A check may therefore name **one** parent: another check of the same site, or a switch DENIS reads
(verified: no loop, at most four levels; a deleted parent clears the field of its dependants).

* A dependant that fails **while its parent is failing** raises no notice of its own. It still moves through its own
  states, so its history is true, and the console shows "Affected by *parent*" beside it.
* The parent's notice and its item in the console say how many checks are affected.
* A dependant that keeps failing **after** its parent recovered raises its own notice then.
* DENIS never discovers dependencies: only what you declared is used. Two checks that fail for a shared cause nobody
  declared raise two notices. To avoid that, declare the dependency on the check that tests the shared cause.

## Setting it up

*Network → Service checks* in the console, as in the console (administrators of the whole installation add, change,
remove and run checks; every signed-in person who may read the site sees them, and an API token of the area Network
reads them). The page opens with a status line: whether the checks job runs on this server, how many checks need a
look, when the last one ran, *Read again* and *Details in Health*. Its tab **Checks** holds *Add a check* and the list,
worst first; its tab **Setup** (`#network/checks/setup`) holds *Checks to industrial equipment* and where a failing
check is reported. The empty list explains what a check is and that DENIS asks only where you point it; an
administrator can start from an example (*Ping a device*, *A DNS question to my DNS server*, *A web page*), which opens
the form with that kind. The form refuses values outside the limits before it sends them.

1. Add a check: a name, the kind, the target, the interval and the waiting time. Leave the rest at its default at first.
2. Choose the site whose people may see the check. A check without a site belongs to the whole installation and is read
   only by someone who may read every site.
3. Press *Run now* to see the first answer (not more often than every 30 seconds).
4. For a service behind another one (for example behind the DNS server), choose the parent.

## What you see

* **The table**: name, kind, target, site, the state as a word (with "from this server" spelled out for *Not reachable*),
  since when, the last answer time and, for HTTPS, the days left on the certificate.
* **A history chart** per check: 24 hours, 7, 30 and 90 days, and a year, at most 300 buckets. Colour and word both
  carry the state. Short ranges are drawn from the raw runs and longer ones from hourly figures; the answer says which
  (`source`) and from when data exists (`kept_from`).
* **Notices** (category *services*): `check_not_reachable` (high), `check_degraded` (warn), `check_cert_expiring` (warn,
  for editors and administrators), `check_recovered` (info, to the same readers as the notice it closes; none when no
  notice was open), `checks_vantage_cannot_check` and `checks_vantage_can_check`.
  Each carries the name of the check and says "from this server". The notice is deduplicated by the check's id and the
  kind of problem, never by a name or an address. A notice is raised at least once, even if DENIS stops between the write
  and the notice (verified).
* **Health** (as in the console): one section for service checks, with the warnings below.

### Health warnings of service checks

Each warning has a stable code. The first four are faults; the last two are advice.

| Code | Says | What to do |
|---|---|---|
| `checks_job_stalled` | The service checks job has not finished a pass for N minutes (more than 2 minutes while it should run). | Look at the service log; restart DENIS if it does not recover. |
| `checks_late` | N service checks are running late (due more than 2 minutes ago). | Too many checks for the runs in flight, or a slow network: raise intervals or remove checks. |
| `checks_icmp_not_permitted` | This server may not send echo requests, so ping checks cannot run. Shown for an hour after it was seen. | On Linux give the service the `CAP_NET_RAW` capability, or allow unprivileged ping (`net.ipv4.ping_group_range`). |
| `checks_store_failing` | The service checks cannot be read from the database since a time; no check runs meanwhile. | Check the database and the free disk space. |
| `checks_passive_only` (advice) | Checks do not run: this server was started passive-only. | Start without `--passive-only` if you want checks. |
| `checks_near_limit` (advice) | N of at most 100 checks are listed (shown from 90). | Remove checks you do not need. |

### Metrics

`/metrics` carries `denis_checks_runs_total{outcome}`, `denis_checks_state{state}` (counts of checks, no per-check label),
`denis_checks_skipped_total` and `denis_checks_last_pass_seconds` (verified in the code; see
[Operations](operations.md#monitoring-denis-itself-prometheus)).

## History and retention

Each run stores one small row: the time, the outcome, one reason code and numbers such as the answer time. Raw runs are
kept `check_history_days` (1 to 30, 8 by default) and the hourly figures built from them `check_rollup_days`
(30 to 800, 400 by default). Both are set under *Data retention* in the console or through `PUT /api/retention`
([Operations](operations.md#retention)). A check you
remove has its rows deleted with it. *Erase all data* deletes them too.

## Privacy and security

A check holds no secret, so the whole check is audited (`checks.created`, `checks.updated`, `checks.deleted`,
`checks.run_now`, and `checks.ot_policy` with the sites and zones before and after). The password asked for a public
address or the industrial setting is never stored, logged or audited. What DENIS sends and where is in
[Security](security.md#service-checks-460-experimental).

## What is verified, and what is not

Verified (DENIS's own tests, against stand-in services on 127.0.0.1): the guard on every resolved address and the
refusal of a name that changes between check and connection; the industrial hold; the two-and-two rule; one notice for a
parent and its dependants; that a failing local side opens one notice and no per-check ones; the bounds above.

**Not verified:** any run against a customer network; a ping check on a server without the right to send echo requests
(the warning is built, the behaviour on each operating system is best guess); a certificate chain from a private
authority; an IPv6-only network; how 100 checks at the 30-second floor load a small server (best guess, not measured);
how a firewall or an intrusion prevention system reacts to the ping, TCP connection and `DENIS-check` request (see
[Security tools that may flag DENIS](security-tools.md)).
