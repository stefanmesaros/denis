# Security

DENIS is security software, so its own security matters. This page states what it protects, how, and, just as
important, what it does **not** do, so you can assess it honestly.

## Threat model

| Asset | Threat | Controls |
|---|---|---|
| Inventory and alerts | unauthorised reading/changing | sign-in, roles, audit log, loopback-only by default |
| User accounts | password guessing, theft of the database | Argon2id hashes, lock-out with back-off, no default credentials, forced first-login change |
| Sessions | theft, fixation, cross-site request forgery | 256-bit random tokens (only their SHA-256 is stored), HttpOnly + SameSite=Strict cookie, idle/absolute expiry, custom-header CSRF check on state changes, `Host` validation against DNS rebinding |
| Agent channel | impersonation, injection | one token per agent bound to its id, revocable, hashed at rest, throttled on failures, size limits, input validation |
| The collector process | malicious network frames | every parser bounds-checks and is fuzz-tested (hundreds of thousands of hostile inputs), protocol decoders verify signatures, strings from the network are sanitised, memory bounds everywhere |
| Users' browsers | stored XSS via device names | the UI builds DOM with `textContent` only (never HTML strings), strict Content-Security-Policy (`default-src 'self'`), HTML/CSV output escaped, CSV formula injection neutralised |
| The host | privilege | runs unprivileged with only `CAP_NET_RAW`/`CAP_NET_ADMIN`; never executes anything received from the network |

**No backdoors by design:** there is no hard-coded credential, no maintenance account, no telemetry and no
outbound connection except those *you* configure (webhook, master URL). The first administrator password is
random and shown once.

## What DENIS does not protect (be aware)

* **HTTPS is on by default**, for the console and the agent port: a certificate DENIS generates (from its own local
  authority; renewed automatically) or your own, replaceable in the console without a restart. Browsers warn about the
  generated one until the CA is trusted (see [Deployment](deployment.md#reaching-the-ui-securely-https-is-on-by-default)).
  `--no-tls` (plain HTTP) exists for a reverse proxy or SSH tunnel and should never face a network. The generated CA
  key and the server key are stored beside the database, readable by the DENIS user only: protect the folder and its
  backups. Agents pin the master's CA with `--master-ca`; there is no option to skip certificate checks.
* **Passkeys** (WebAuthn) are supported for sign-in (below). There is no separate TOTP code and no single sign-on (SAML/OIDC) yet.
* Login lock-out is **per account name**: an attacker can lock a known account for short periods (denial of
  service), but cannot guess passwords faster. On top of that each **source address** may make 20 failed
  sign-ins per 10 minutes, then is refused (HTTP 429) for the rest of the window, which stops one address
  trying many accounts. Behind a reverse proxy **on the same machine** the client address is taken from the
  last `X-Forwarded-For` entry (make sure your proxy sets/appends it); from any other peer that header is
  ignored. A proxy on a *different* machine makes all users look like one address: keep the proxy local.
* **No encryption at rest.** The SQLite file holds the inventory and password hashes; protect it with file
  permissions and disk encryption.
* API tokens are long-lived bearer credentials (viewer/editor only, hashed at rest, revocable, audited). Treat
  them like passwords; they are not bound to an address and have no expiry.
* Anyone who can read the database file or run `denis user …` on the host is effectively an administrator.
* Agents are trusted for the id their token was issued for: a stolen agent token lets an attacker submit
  false devices/flows *for that agent* until it is revoked.
* The passive parsers see whatever is on the wire; an attacker on the network can *influence what is
  displayed* (names, counts) though not execute anything; and can try to evade detection like against any
  monitoring tool.
* Anything DENIS reads from the network is only as trustworthy as the network. Device-type guesses can be
  spoofed (a device can claim to be a printer).

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
  (`DELETE /api/users/{id}/passkeys`). Passwords keep working; there is no way to force passkey-only sign-in yet.
* Verified with a software authenticator against the full protocol (forged, replayed, unverified, cloned and
  wrong-origin responses are all refused) and in a browser with a simulated authenticator. Not yet verified with a
  physical security key or a phone.

## Hardening checklist

- [ ] HTTPS on (the default), with the CA trusted or your own certificate installed; never `--no-tls` on a network.
- [ ] Ingest port firewalled to the agents' addresses, and TLS/VPN in front if it crosses untrusted networks.
- [ ] Run as an unprivileged user with capabilities (the systemd unit does); database directory `0700`.
- [ ] Set `--public-url` and have people add a passkey.
- [ ] Individual named accounts; *viewer* by default; only a few admins; review the audit log.
- [ ] Rotate agent tokens when staff or hardware change; revoke tokens of retired agents.
- [ ] Back up the database; test a restore.
- [ ] Keep the binary updated; run `cargo audit` in your build pipeline.
- [ ] On OT networks: mirror-port only, `--profile ot`, exclusions for anything fragile.

## Verification performed

* Unit and integration tests (≈200) including negative tests: unauthenticated access to every route, every
  role on every kind of route, session/cookie flags, lock-out, CSRF header, rebinding, token binding and
  revocation, hostile CSV/HTML.
* Fuzz tests of every wire parser and of CSV/JSON input.
* `cargo audit` against the RustSec advisory database: 0 known vulnerabilities in 250 dependencies.
* Not yet done (do before selling): an independent penetration test, review of the TLS-proxy deployment
  you intend to ship, and a coordinated-disclosure process (define a security contact and policy).

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
