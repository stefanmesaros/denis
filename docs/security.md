# Security

DENIS is security software, so its own security matters. This page states what it protects, how, and, just as
important, what it does **not** do, so you can assess it honestly.

## Threat model

| Asset | Threat | Controls |
|---|---|---|
| Inventory and alerts | unauthorised reading/changing | sign-in, roles, audit log, loopback-only by default |
| User accounts | password guessing, theft of the database, sign-in floods | Argon2id hashes, lock-out with back-off per account and address, per-address limits, a cap on simultaneous password checks ([details](#sign-in-limits-and-lock-out)), no default credentials, forced first-login change |
| Sessions | theft, fixation, cross-site request forgery | 256-bit random tokens (only their SHA-256 is stored), HttpOnly + SameSite=Strict cookie, idle/absolute expiry, custom-header CSRF check on state changes, `Host` validation against DNS rebinding |
| Agent channel | impersonation, injection | one token per agent bound to its id, revocable, hashed at rest, throttled on failures, size limits, input validation, time and count limits per report ([details](#what-a-master-accepts-from-an-agent)) |
| The collector process | malicious network frames | every parser bounds-checks and is fuzz-tested (the targets are listed under [Verification performed](#verification-performed)), protocol decoders verify signatures, strings from the network are sanitised, memory bounds everywhere; a crash inside the packet parser is contained to that packet, counted and shown on the Health page |
| Users' browsers | stored XSS via device names | the UI builds DOM with `textContent` only (never HTML strings), strict Content-Security-Policy (`default-src 'self'`), HTML/CSV output escaped, CSV formula injection neutralised |
| The host | privilege | runs unprivileged with only `CAP_NET_RAW`/`CAP_NET_ADMIN`; never executes anything received from the network |

**No backdoors by design:** there is no hard-coded credential, no maintenance account and no telemetry. The first
administrator password is random and shown once.

**Outbound connections.** Besides the ones you configure yourself (notification channels, exports, a master URL,
CMDB/cloud imports, an AI provider), a default install makes four kinds of outbound request on its own, none of
which carries anything about your network, and each of which can be switched off:

| What | Where to | How often | Off with |
|---|---|---|---|
| update check | `api.github.com`; `usedenis.com` only if GitHub cannot be reached | every 6 hours | `--no-update-check` / `DENIS_NO_UPDATE_CHECK=1` (the fallback alone: *Settings → System → Updates*) |
| GeoIP database (DB-IP Lite) | `db-ip.com` | monthly | *Settings → Network → Network Intelligence* (auto-update off, or your own MMDB file) |
| end-of-support dates | `endoflife.date` | weekly | *Settings → Data → Software versions* |
| known-exploited vulnerabilities | CISA, NVD, FIRST.org (EPSS) | weekly | *Settings → Data → Software versions* |

Six more are **opt-in**, off by default rather than on-by-default like the four above: the blocklists that
`threat_list_match` checks contacted addresses against — **abuse.ch Feodo Tracker**, **ThreatFox** and **URLhaus**,
**Spamhaus DROP** and **ASN-DROP**, and **the Tor Project's exit-node list** — each switched on and
scheduled (Daily/Weekly/Monthly) independently under *Settings → Data → Threat list sources*
([details](detection-rules.md#threat_list_match-contact-with-a-known-bad-address-needs---flows-and-a-threat-list)).
Each download is a plain GET of the publisher's public file; nothing about your network is sent (ASN-DROP's AS numbers
are resolved to networks offline, with the local GeoIP database). Turning any of them on is the one deliberate exception to "nothing fetched unless you asked for it" — not a silent
default.

Reverse-DNS lookups of public addresses go to the resolver you set (`1.1.1.1` by default) and do carry the
address being looked up; switch them off or point them at your own resolver under *Network Intelligence*.

## What DENIS does not protect (be aware)

* **HTTPS is on by default**, for the console and the agent port: a certificate DENIS generates (from its own local
  authority; renewed automatically) or your own, replaceable in the console without a restart. Browsers warn about the
  generated one until the CA is trusted (see [Deployment](deployment.md#reaching-the-ui-securely-https-is-on-by-default)).
  `--no-tls` (plain HTTP) exists for a reverse proxy or SSH tunnel and should never face a network. The generated CA
  key and the server key are stored beside the database, readable by the DENIS user only: protect the folder and its
  backups. Agents pin the master's CA with `--master-ca`; there is no option to skip certificate checks.
* **The agent-to-master channel is encrypted** (TLS 1.2/1.3) and authenticated in both directions by default: the agent
  checks the master's certificate against the CA you give it (`--master-ca`; there is no way to skip the check), and the
  master accepts only the agent's own bearer token. An agent **refuses a plain `http://` master address** unless it is
  this machine, or you pass `--allow-plain-http` for a VPN or tunnel you trust: otherwise the token and everything the
  agent saw would cross the network readable. If the master runs with `--no-tls` (behind a TLS proxy) point the agent at
  the proxy's `https://` address. What is not protected: the agent's token is a shared secret rather than a client
  certificate, so keep it as safe as a password (revocable per agent under *Sites*).
* **Passkeys** (WebAuthn) and **one-time codes from an authenticator app** (TOTP) are supported for sign-in (below).
  **Single sign-on** over OpenID Connect exists (*Settings → Sign-in & security → Single sign-on*) but has not yet
  been exercised against a real identity provider — ID-token signature verification end to end is the specific
  gap. Before relying on it, configure it against one real provider (for example a Keycloak container or a free
  Google Cloud OAuth client) and confirm a full sign-in end to end. SAML is not
  supported.
* Login lock-out is counted **per account and per source address**, with an account-wide limit behind it: see
  [Sign-in limits and lock-out](#sign-in-limits-and-lock-out) for the exact numbers and for what an attacker can and
  cannot do to the real owner. Behind a reverse proxy **on the same machine** the client address is taken from the
  last `X-Forwarded-For` entry (make sure your proxy sets/appends it); from any other peer that header is
  ignored. A proxy on a *different* machine makes all users look like one address: keep the proxy local.
* **No encryption at rest.** The SQLite file holds the inventory and password hashes; protect it with file
  permissions and disk encryption.
* API tokens are long-lived bearer credentials (viewer/editor only, hashed at rest, revocable, audited). Treat
  them like passwords; they are not bound to an address and have no expiry. A token is tied to the account that
  created it, by the account's permanent id (not its name): it works only while that account exists and is enabled,
  never above that account's current role, and only on the sites that account may access (a token made by an
  administrator who later becomes a site-restricted editor is restricted with them). A token that could not be
  attributed to an account (made before 4.0.2 and not matched to an account at the upgrade) works for nobody; the token list shows
  it as "creator unknown", and a token whose creator was deleted as "account deleted". Bad tokens are throttled
  (10 per minute per address) and each valid token may make 300 requests a minute.
* Anyone who can read the database file or run `denis user …` on the host is effectively an administrator.
* Agents are trusted for the id their token was issued for: a stolen agent token lets an attacker submit
  false devices/flows *for that agent* until it is revoked.
* The passive parsers see whatever is on the wire; an attacker on the network can *influence what is
  displayed* (names, counts) though not execute anything; and can try to evade detection like against any
  monitoring tool.
* Anything DENIS reads from the network is only as trustworthy as the network. Device-type guesses can be
  spoofed (a device can claim to be a printer).

## Sign-in limits and lock-out

All of this is in memory, so a restart clears the counters (the *known addresses* below included).

| Limit | Value |
|---|---|
| Wrong passwords or codes from one address for one account before that account is locked **for that address** | 5. The lock is 30 seconds, doubling with every further 5 wrong guesses, to at most 15 minutes |
| Wrong passwords or codes for one account from **all** addresses together before the account is locked for addresses that have never signed in to it | 25 |
| Failed sign-ins from one address (any accounts) | 20 per 10 minutes, then HTTP 429 until the window passes |
| Failed sign-ins from one IPv6 /64 network | 400 per 10 minutes. The 20 above count each IPv6 address on its own, so rotating through addresses of one network is still bounded |
| Passkey sign-in start requests from one address | 30 per minute (600 per minute for a /64) |
| Password checks running at the same time | twice the number of processor cores, at least 2 and at most 16. Up to 256 more wait for up to 10 seconds; past that the answer is HTTP 503 with `Retry-After` |
| Distinct unknown session cookies from one address (IPv6: one /64) | 60 per minute, then HTTP 429 `rate_limited`. A cookie found invalid is remembered for 30 seconds and answered 401 without a database read, so a real user with an expired session is not affected |

* **A stranger cannot lock the owner out.** The lock for 25 guesses from many addresses refuses only addresses that
  have never signed in to that account. An address that completed a full sign-in (password, and the second step where
  it is on) in the last 30 days is *known* for that account (up to 8 addresses per account), and is not refused by
  the account-wide lock; it is still held to its own limit of 5, and its wrong guesses still count towards the 25, so
  the total number of guesses an unknown attacker gets per account does not grow. An attacker cannot become known
  without the password. Not covered: a passkey sign-in does not mark an address known, and the owner signing in for
  the first time from a new address during an attack has to wait for the lock to end.
* IPv4-mapped IPv6 addresses count as the IPv4 address. Account names are limited to letters, digits and `. _ - @`, so
  spelling variants of one name share one lock-out count.
* Changing a password and confirming a password for a sensitive action (setting up an authenticator app, enforcement
  changes) take their place in the same lock-out count before the password is checked, so a burst of simultaneous
  guesses cannot all pass the check before the first failure is recorded. Operator and single-sign-on first sign-ins
  use the same cap on simultaneous password checks.
* A right password for an account that may sign in only with a passkey is answered exactly like a wrong one (and
  counts the same).

## What a master accepts from an agent

A report from a remote agent (or from a customer's master that relays to an MSP) is checked before it is used, so a
broken or hostile agent cannot fill the master or poison its detection:

* **Size and count.** A report is at most 32 MB, and holds at most 5,000 devices, 100,000 traffic windows, 10,000
  security signals, 20,000 industrial conversations, 50,000 east-west records and 50,000 DNS records. Records over a
  limit, with an invalid MAC address or with an invalid field are skipped and the rest is applied; the master logs
  how many.
* **Time.** A record's timestamp may be at most **7 days old** and at most **1 hour ahead** of the master's clock;
  other records are dropped. An agent whose records are dropped for this reason is named on the Health page (with how
  many records and how long ago): set its time (switch NTP on) and its data is accepted again.
* **Quarantine.** If applying the same batch crashes the master's detection 10 times in a row, the batch is refused as
  malformed so the agent drops it instead of retrying for ever. An ordinary store error (the database busy or briefly
  unavailable) is not counted towards this: such a batch is retried, and nothing is lost in a short database outage.
* **Bad tokens** from one address: more than 10 a minute are refused.

**Relays to an MSP (`--report-to`).** A customer's master sends its devices and alerts to the MSP's master as one
site, and the MSP's master keeps every customer machine reached that way in its own sub-site (at most 256 per
relay). Access to sub-sites only ever **narrows**: on every sync, a user who has a grant on the relay site gets at
least that restriction on each of its sub-sites; a restriction an administrator set on a sub-site stays (an explicit
"none" is never replaced), a later widening of the relay site's grant does not widen existing sub-sites, and no grant
is deleted. Devices a customer sent before 4.0.2 are adopted into the sub-site (the same record, so alerts and notes
move with it), events with the same time but different details are both kept, and the event cursor overlaps by 200
events so one stored late on PostgreSQL is still relayed. See
[Deployment](deployment.md#msp-live-devices-and-alerts-from-a-customers-own-master).
`--report-to` accepts an `https://` address; `http://` is refused unless the address is this machine or
`--report-to-allow-plain-http` is given for a VPN or tunnel you trust. An address that is not acceptable is logged
and the relay is skipped; DENIS still starts. `--report-to-ca` pins the MSP's certificate authority, as `--master-ca`
does for an agent.

## Enforcement (mostly experimental)

Enforcement is the part of DENIS that can change your network ([Enforcement](enforcement.md)). It is **off by default**. A
manual action is a signed-in administrator's click, with the password again, after a preview. Two automatic levels exist,
both **experimental and off by default**: **automatic enforcement by rules** (a policy you mark for it may block or
quarantine a device by itself) and, on top of it, **letting Autopilot block**. Neither can act unless an administrator
switches it on with a typed phrase and the password, and both need the two lab switches below to stay on; switching a lab
switch off stops them. Automatic actions are always time limited (at most 7 days, 24 hours for Autopilot), capped per hour
and per device, and announced with an undo link. See [Automation](enforcement.md#automation). Every action, manual or
automatic, goes through one path with a **kill switch**, an **hourly limit**, a ledger of what DENIS changed, and an undo
that removes only what DENIS made. Apart from switching one switch port off over SNMP, which has been
tried on one real switch, every connector is labelled *Experimental* (tested only against a simulation of the vendor's
interface) and cannot act until an administrator switches on a **lab** setting; the actions new in 4.1 sit behind a second
lab switch that an upgrade never turns on. Which account may do which action is a separate per-account permission. Treat a
block as something you try first on a device you can afford to lose.

## Updates and agents

An update is installed only if the release's checksum list carries a valid signature from the project's release key, built
into the program. That holds for every source: GitHub, the fallback host `usedenis.com` (used only when GitHub cannot be
reached; it sees your address and nothing else, and can be switched off) and, for an agent, the master that hands it a
release. A master cannot make an agent run unsigned code: the agent verifies the release itself with its own copy of the key,
refuses anything not strictly newer than its own version, and refuses everything when started with `--no-self-update`. By
default nothing is sent to an agent; an administrator presses Update, or chooses the automatic mode. Pre-release versions
are offered only if an administrator opts in. See [Updates](updates.md).

## Autopilot (experimental)

[Autopilot](autopilot.md) is built so that the worst thing it can do is bounded, and so that nothing it
does is hidden.

* **No enforcement by default.** The list of things it can propose is closed and has no block, quarantine, port,
  VLAN, firewall or connector action; its executor imports no enforcement code. A block suggestion is
  forwarded with a link to the console's block review, where a block needs your password or passkey. The one
  exception is the separate, experimental and off-by-default option **Let Autopilot block**: it sits on top of
  automatic enforcement by rules, needs the typed phrase, your password, both lab switches, Autopilot active after
  its shadow period and the agreement gates, may only quarantine or block one device for at most 24 hours, and goes
  through the same orchestrator, limits and audit as any action. Only one file of Autopilot reaches enforcement, and
  only through that gate (a test pins it).
* **Approvals from a phone** are a single-use token per question and per answer: an HMAC over the
  question, the answer, the exact action (a hash of its parameters), the key epoch and an expiry, with
  a random nonce of which only a hash is stored. A token cannot be replayed, used for another answer,
  used after the action changed, or used after the phone was revoked (which changes the key). A
  link only ever shows the question; the answer is a separate request. Anything doubtful is refused with one generic message and a
  sampled audit row; a refusal never changes state. The higher classes also need your password or a
  passkey on the phone, the passkey assertion being bound to that one question.
* **Who can decide.** Administrators who may act, never an API token, never a site-limited
  administrator for tenant-wide settings, never `--insecure-no-auth`.
* **The approval key** is a sealed setting (encrypted with the data key), left out of backups and made
  again after a restore, which ends every outstanding approval.
* **An AI model** sees only what you allowed, names are fenced and cleaned and never part of an
  instruction, a name that looks like an instruction is kept away from the model, and its answer is
  checked against bounds it does not control and discarded whole when anything in it is invented. See
  [Autopilot](autopilot.md) for the data classes (all off for a cloud model by default) and for what is
  and is not verified.
* **Everything is recorded:** each question and answer is a decision-log row, and the audit log has
  `autopilot.settings`, `autopilot.mode`, `autopilot.experimental_ack`, `autopilot.proposal.*`,
  `autopilot.apply`, `autopilot.pause`, `autopilot.phone.*` and `autopilot.quiet_exception.remove`
  entries, none of which holds a token or a key.

## MSP management (experimental)

[MSP management](msp-management.md) lets a company that looks after your network open your console remotely. It is off
until one of your administrators pairs with it, and the properties that matter:

* **You stay the authority.** The MSP's requests run through your own console, under your own checks, as the user
  `msp:<MSP>:<technician>`. The level you choose (Off, Read only, Read and write, Full) is read from your database for
  every request, so lowering it or pressing Disconnect acts on the next one. The technician's role at the MSP can only narrow it.
* **Signed, bound, not replayable.** Every request is signed with the Ed25519 key you pinned when you compared its
  fingerprint, carries your link id, a timestamp (two minutes), a nonce and a hash of its body. Anything that fails is
  never executed.
* **A fixed list of things an MSP can never do**, enforced by a class on every route (a route without a class is refused,
  and a test fails the build): the link itself, the audit log, your administrators, sign-in policy, TLS, backups,
  secrets and where this master sends its data. Dangerous operations (users, tokens, restart, update, enforcement) need a
  second factor proven at the MSP in the last 10 minutes, and optionally your administrators' approval (co-approval).
* **Nothing the MSP makes outlives it.** An account it creates or resets is switched off, and an automatic-enforcement
  opt-in it set is removed, when you disconnect, unlink or lower the level below Full. Moving an integration to another
  address never keeps its saved key, and the MSP cannot lower how many backups are kept.
* **Loud.** A new account, a changed level, a request waiting for approval and an enforcement by the MSP are sent to
  your notification channels. The approval screen shows the request as it will run (path, query, body with secrets
  masked), and the approval is bound to what was shown.
* **Everything is in your audit log**, with the technician's name and the request id; reads are summarised every five
  minutes. A banner on every page says who manages you.
* **What it cannot prove.** A signature shows that the MSP's master asserted a technician's identity, not that a particular
  person acted. An attacker who takes over the MSP's master can do, to each customer, what that customer allowed,
  while it is online. Keep the level low, leave the enforcement boxes empty unless you need them, and switch on approval.
* **For MSPs**, the customer's own console runs pages in your technician's browser: serve customers on a separate portal
  domain (see the page), and give every technician, viewers included, a second factor. Opening a customer shows a page
  that says who is opening what and needs a click, so a link cannot be pushed into somebody else's browser.

## Text from the network

Names, banners, page titles and SNMP strings sent by devices are cleaned before they are stored or shown: control
characters, text-direction overrides and zero-width characters (which can make a name look like another one) are
removed. Text in Persian, Indic scripts and emoji that needs joining characters keeps them.

## Passkeys

Anyone can add passkeys to their own account (click your name in the header → **My account**) and then sign in with a fingerprint,
face, device PIN or security key, with no password to type or phish.

* **Verified, not just present.** A passkey is only accepted if the authenticator verified the person (biometric or
  PIN), so a passkey sign-in is effectively two factors in one.
* **Bound to your address.** A passkey works only on the address given by `--public-url https://denis.example.com`
  (the browser refuses it anywhere else, and DENIS checks the origin too). Without `--public-url` passkeys work only
  when you browse to `http://localhost`. The address is configured, never taken from request headers.
* **What is stored:** the credential id and the *public* key. A database leak reveals nothing that can sign in.
* Accepted: ES256 (ECDSA P-256), which every platform authenticator and security key supports; attestation is not
  requested and not accepted, so there is no device certificate to trust. A counter that goes backwards (cloned key)
  is refused; authenticators that do not count (synced passkeys) are fine.
* A passkey cannot skip a pending password change, cannot sign in a disabled account, is rate limited like passwords,
  and every registration, removal and sign-in is in the audit log.
* **Lost device:** the person removes it under *Passkeys*; an administrator can remove *all* of a user's passkeys
  (`DELETE /api/users/{id}/passkeys`). Passwords keep working unless an administrator turns on **passkey-only
  sign-in** (*Settings → Sign-in & security*, for administrators or everybody). The console enforces it, not only the
  sign-in page: once a covered account has added a passkey, its password stops opening a session; until it has added
  one, the password still signs in but every other request is refused with `passkey_required` (HTTP 403) and the
  console asks the person to add a passkey first (API tokens are not affected). The requirement is applied only where
  passkeys are switched on (`--public-url`, or the console opened as `http://localhost`), because it could not be met
  otherwise. If an administrator reset the account's password, the person can still sign in with the passkey, and the
  reset password is replaced by a random one nobody knows.
* Verified with a software authenticator against the full protocol (forged, replayed, unverified, cloned and
  wrong-origin responses are all refused) and in a browser with a simulated authenticator. Not yet verified with a
  physical security key or a phone.

## Authenticator app (TOTP)

Anyone can add a second step to their own account: *My account* → **Authenticator app** → *Set up*. DENIS asks for the
password again, shows a QR code (and the key, to type by hand) for any authenticator app (Google Authenticator, Microsoft
Authenticator, Authy, 1Password, Aegis…: standard RFC 6238, 6 digits, 30 seconds), and turns it on only after the person
types a correct first code. Ten **recovery codes** are shown once.

* **At sign-in** a right password earns only a short-lived (5 minutes), single-use *ticket*; the session comes when the
  code is right. Each code works **once** (a code seen over a shoulder cannot be replayed), a clock a little fast or
  slow is tolerated (one 30-second step either way), and a recovery code works once.
* **Guessing is throttled.** Wrong codes count against the account with the same growing lock-out as wrong passwords, five
  wrong codes void the ticket, and a right password does **not** reset that count, so re-entering the password cannot
  restart the guessing. Wrong attempts are also counted per client address. They appear in the audit log (`auth.mfa_failed`),
  as do turning it on or off, new recovery codes and the use of a recovery code.
* **Passkeys** already are two factors (the device plus a fingerprint or PIN), so a passkey sign-in asks for no code.
* **Sensitive actions ask for the password again**: setting up, turning off and new recovery codes (the last also
  needs a current code).
* **Requiring it.** *Settings* → **Sign-in & security**: require a second step (an authenticator app *or* a passkey) for
  nobody, administrators, or everybody. Whoever is required and has none is asked to set one up at their next request,
  and nothing else works until they have (API tokens are not affected). While it is required, a person cannot turn their
  only second step off.
* **Lost phone:** an administrator resets the person's authenticator app (*Users* → *Reset*, or
  `DELETE /api/users/{id}/totp`); the person is signed out, signs in with the password (or a passkey) and sets it up again.
* **What is stored.** A code cannot be checked against a hash, so the secret is stored in the database, beside the password
  hashes: a copy or **backup of the database** can produce codes for everyone, so guard backups like the database itself.
  The secret is shown once, at set-up, and never returned again. Recovery codes are stored only as hashes.

## Hardening checklist

- [ ] HTTPS on (the default), with the CA trusted or your own certificate installed; never `--no-tls` on a network.
- [ ] Ingest port firewalled to the agents' addresses, and TLS/VPN in front if it crosses untrusted networks.
- [ ] Run as an unprivileged user with capabilities (the systemd unit does); database directory `0700`.
- [ ] Set `--public-url` and have people add a passkey or an authenticator app; require a second step (*Settings* → *Sign-in & security*), or passkey-only sign-in for administrators.
- [ ] Decide which of the default outbound connections above you want, and turn off the rest.
- [ ] Individual named accounts; *viewer* by default; only a few admins; review the audit log.
- [ ] Rotate agent tokens when staff or hardware change; revoke tokens of retired agents.
- [ ] Back up the database; test a restore.
- [ ] Keep the binary updated; run `cargo audit` in your build pipeline.
- [ ] On OT networks: mirror-port only, `--profile ot`, exclusions for anything fragile.

## Verification performed

* Unit and integration tests (780+ across the crate) including negative tests: unauthenticated access to every
  route, every role on every kind of route, session/cookie flags, lock-out, CSRF header, rebinding, token binding
  and revocation, API-token rate limits, hostile CSV/HTML, secrets never echoed back by any settings endpoint.
* Coverage-guided fuzzing (libFuzzer) with 18 targets over the untrusted-input parsers: captured frames, mirror tunnels
  (ERSPAN, GRE, VXLAN, Geneve), DNS answers, the agent report, the SNMP raw dump, the industrial-protocol decoders
  (including the layer-2 and BER readers and IP fragment reassembly), uploaded SCL files, IPv6 extension headers and
  identity messages, SNMP and SNMPv3 replies, device banners, the enforcement connectors' reply parsers, the MSP
  management channel and the asset CSV import. Fourteen of them ran for about five
  minutes each in 2026 (no such run is recorded for the newer ones, such as mirror tunnels, IP fragment reassembly and
  the MSP channel) and found two real crashes in the first eight targets (a banner and
  an SNMP hex string cut inside a multibyte character), both fixed; no crash is recorded for the others.
  Five minutes is a smoke test, not assurance: longer runs have not been done. Hostile-frame and recovery tests
  (about 150 malformed frames, 150,000 mutations, damaged or oversized capture and database files) run with the
  ordinary tests.
* `cargo audit` against the RustSec advisory database, on every CI run, against the ~430 crates in `Cargo.lock`.
* A coordinated-disclosure policy exists (`SECURITY.md` in the repository: GitHub private vulnerability reporting).
* Not yet done (do before selling): an independent penetration test, and a review of the TLS-proxy deployment
  you intend to ship.

## Notes for penetration testers

* Scope: the UI/API on port 8080, the agent ingest on 8081 (if enabled), the CLI and the database file on the
  host, and the packet parsers (send crafted frames to the capture interface).
* Suggested accounts: one per role (`denis user add …`). `--insecure-no-auth` must be *absent*; it is refused on
  non-loopback addresses.
* Things to try: authorisation bypass by method/path/case, session fixation and reuse after logout/password
  change, CSRF without the `X-Denis` header, `Host` header games, oversize/deeply nested JSON, CSV import
  payloads, stored XSS through hostnames/mDNS/SSDP/LLDP strings, token guessing on ingest, ARP/DHCP/mDNS
  malformed frames, DNS name-compression loops, resource exhaustion (many hosts/flows/conversations).
  Expected behaviour is a clean rejection with no crash; bounds exist for hosts, flows, conversations, request
  size, CSV rows and stored history.

## Details from the console

Explanations that used to be printed on the console screens. The console shows them behind a small ? button.

* Let people sign in through an identity provider (Entra ID, Okta, Google Workspace, Keycloak, anything speaking OpenID Connect) instead of a local password. The first sign-in for an identity creates a viewer account for it automatically, keyed on its email; raise its role afterwards like any other account. If an email already belongs to a different local account, sign-in is refused until an administrator links the two explicitly. Local accounts, including the initial admin password, keep working alongside this.
* Optional, bring-your-own-key: DENIS can use an AI provider you configure for a growing set of individually-switchable features below. Each call is billed to your own account with the provider you choose — DENIS runs and hosts none of this itself. Only compact, already-processed context (an alert's own summary and reasons, a device's label) is ever sent — never raw traffic, never more than what the feature you enable actually needs.
* The decision log records who acknowledged, resolved or re-opened which alert or incident, when and why. It has its own period, independent of the setting above: it stays after the alerts and incidents themselves have been deleted. 90 to 3650 days; 1095 (3 years) is the default. Enter 0 to keep it for ever. It holds user names and the notes people typed, and no other personal data.
* A rough sense of how much these features have actually been used — a call count and, when the provider's own response reported one, its token count. Not exact billing information; check your provider's own dashboard for that.
* Adds an "Explain with AI" button to alerts and findings: one plain-language summary per click. Never automatic — only called when you click the button, sending only that one alert or finding's own summary, reasons and device label.
* Adds an "Assess & Explain with AI" button to alerts (shared with Device behavioral analysis below) and contributes the assessment section: what it means, a triage read (likely benign / suspicious / requires investigation), what could happen if ignored, and concrete next steps — plus the AI's own plain-language risk estimate, shown alongside (never in place of) DENIS's own severity. Advisory only; DENIS never acts on any of it itself. Only called when you click the button, sending the same alert data as the explanation feature above.
* Adds an "AI Security Summary" card to the dashboard: a short overview of the last day's alert activity. Never generated by opening or refreshing the dashboard — a background job regenerates it on its own, only when there has been meaningful new alert activity since the last one, at most every few minutes.
* Adds an "Ask DENIS" button next to "Scan now": a panel that stays open while you move between screens, for five kinds of request — ask about recent alert activity ("What changed in the last 24 hours?"), hunt for a destination across every device's own traffic history ("Has anything talked to 1.2.3.4?"), jump straight to a screen or Settings page ("Take me to Topology", "Open the SSO settings"), ask a how-to question answered from the real documentation ("How do I add a switch?"), or ask what it can do. The AI never answers from facts it invented, acts on a setting, or takes any action itself — for a search it only ever chooses how to search, and DENIS runs that search itself; for a how-to question it only ever describes one real documentation page. Only called when you ask a question.
* Adds an "AI Security Summary" section to your periodic reports (Settings → AI → Security reports): devices, new devices, alert activity, standing findings and accepted risks over the report's period, in plain language. Written once, when a report is generated and saved — on its existing schedule, or "Generate now" — never on a separate timer of its own, and never for "Open a live report without saving it" (that link stays instant and free). If the AI call fails, the report is still generated without a summary.
* Contributes a "Behavior change" section to the same "Assess & Explain with AI" button, for alerts that describe a change from one device's own established pattern (new destination, new port, unusual hours, unusual traffic volume): what the device normally does, compared with what just changed. Only offered on those alert kinds — DENIS already decided the change was meaningful before this button ever appears. Only called when you click it.
* Adds an "Assess consequences with AI" button to the incident detail dialog (Incidents page): what could realistically happen if this specific incident is ignored, plus innocent explanations and the one fact that would settle it. On click, per incident. DENIS's own rule-based priority and consequence text stay exactly as they are either way — this is an additional opinion shown alongside them, never a replacement. May consume API credits.
* Only meaningful with Incident consequences above also on. Writes that same assessment in the background, without anyone clicking the button, for open incidents already at priority Act now or Investigate today. At most once per incident per change, and only after it has stopped absorbing new alerts for 5 minutes; at most 50 calls a day across every incident. May consume API credits.
* The master switch: while off, DENIS never calls any AI provider for any feature below, no matter what is configured or enabled underneath.
* Each is off by default and only ever calls the provider above for what it says below — nothing runs in the background unless its own description says so.
