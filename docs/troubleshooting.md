# Troubleshooting

**"cannot open en0 for capture … Permission denied"**
Packet capture needs privileges. Linux: `sudo setcap cap_net_raw,cap_net_admin=eip ./denis` (or run as root /
via the systemd unit). macOS: install Wireshark's ChmodBPF or run with `sudo`.

**"binding web UI on 127.0.0.1:8080 … Address already in use"**
Another DENIS (or another program) holds the port; port 8080 in particular is popular. Nothing is taken over and
nothing is sent to the network when this happens. Start DENIS on a free port: `--listen 127.0.0.1:9000` (or `0.0.0.0:9443`
to reach it from the network). `ss -ltnp` (Linux) or `lsof -nP -iTCP -sTCP:LISTEN` (macOS) shows who holds a port.
For the systemd service set `DENIS_LISTEN` in `/etc/denis/env` and restart it ([Deployment](deployment.md#installing-on-a-linux-server-a-permanent-service)).

**No devices appear**
Check `denis interfaces` and pass `--iface`. On Wi-Fi some access points isolate clients (no broadcast between
them). Passive discovery only finds devices that announce themselves; without `--passive-only`, an ARP sweep
finds the rest within seconds. Virtual/VPN interfaces (`utun`, `docker0`) are not monitored by default.

**I forgot the admin password**
On the server: `denis user reset admin`. It prints a new one-time password.

**The UI keeps showing the sign-in page**
The session expired (12 h idle / 7 days), you were signed out by a password change elsewhere, or the cookie is
marked `Secure` but you are on plain HTTP (`--secure-cookies` requires HTTPS in front).

**403 "unexpected Host header"**
DENIS only answers requests whose `Host` is `localhost`, `127.0.0.1` or `[::1]` when bound to loopback (defence
against DNS rebinding). Behind a reverse proxy, pass the original `Host` (`proxy_set_header Host $host;`).

**"No traffic baseline yet" / the Dashboard's traffic charts and the OT tab are empty**
Traffic analysis needs `--flows` (or `--profile ot`) and traffic that reaches the collector. See
[Concepts › Visibility](concepts.md#visibility-what-can-be-seen-from-where).

**Too many alerts**
Normal during the first days on a busy network. Use `--rule-weight new_destination=0.5`, raise `--min-score`,
prefer the rules on quiet devices, and acknowledge what you have handled. During the first 24 hours new
things are learned, not alerted on.

**A device has the wrong type or OS**
Edit asset → Device type / Operating system. Your value is used everywhere. The device page's *Why this guess*
shows what DENIS saw.

**Two of every device in Sites (or in the "All sites" device list)**
Two collectors on the same network segment, each reporting the same devices under its own site. Sites →
*Same network as…* on the agent's row (an administrator; the Sites page also suggests it when an agent sees
most of the same devices as the local capture) previews what a join does, then sends that agent's future
reports into the local site. The copies it already listed stay under its own site and stop updating until you merge them: tick *also merge…* in the
join dialog, or, for a join made earlier, use *Merge the copies left behind…* on the Sites page (it previews first,
runs in the background, and the copies' own edits are not carried over). A site that has
received an MSP relay sync cannot be joined.

**An agent is not connecting**
Check `denis agent-token list` (revoked?), the master's `--ingest-listen` address and firewall, that the agent
id matches the token, and that the agent can reach `https://MASTER:8081/api/v1/ping` with the token (and has the master's CA: `--master-ca`).

**Database problems**
Stop DENIS, restore the latest backup (`.backup` file) over the database file. Never edit it while running.

**Sign-in says "too many attempts", or the account is locked**
Five wrong passwords or codes from one address lock that account for that address: 30 seconds, doubling with every
five more wrong guesses, up to 15 minutes. An address that signed in successfully within the last 30 days is not
locked out by other people's wrong guesses, but one that never has is, after 25 wrong guesses from anywhere (it waits
for the lock to end). 20 failures from one address
in 10 minutes answer HTTP 429 until the window passes. A burst of sign-ins at the same moment can answer HTTP 503 with
`Retry-After`: wait and try again. Details: [Security](security.md#sign-in-limits-and-lock-out). A restart clears all of it.

**"passkey required" after signing in**
An administrator made a passkey mandatory (*Settings → Sign-in & security*) and your account has none. DENIS now enforces
this itself on every request: add a passkey under *My account*, then continue. If passkeys are switched off on this
console, the requirement is not applied, because it could not be met. A passkey-only account whose password an
administrator reset can still sign in with the passkey.

**An API token suddenly sees fewer sites, or stopped working**
A token follows the account that created it: it stops while that account is disabled or deleted, never exceeds its
role, and takes that account's per-site access settings ([API](api.md#api-tokens-for-scripts-and-integrations)).

**The Health page says the packet parser crashed, or a signal buffer overflowed**
Both mean some packets were skipped and not analysed. Keep the service log (the parser logs one rate-limited line per
crash) and report it with the time. A full signal buffer usually means something on the network is sweeping it or
flooding it with DHCP requests. See [Operations](operations.md#health-warnings-that-point-at-data-you-cannot-see).

**A remote site's events or traffic are missing, and Health names its agent**
The agent's clock is wrong: records more than 1 hour ahead of the master or more than 7 days old are dropped. Switch NTP on
there. Data from before the fix stays missing.

**A switch looks incomplete, or a device looks unplugged**
Health says the switch gave back only part of its SNMP tables. A table was too big to read within the safety limits
(rows, time or bytes), and the switch card names it. The topology of that switch is not complete.

**IPv6 devices do not appear**
IPv6 is off unless `--ipv6` is given. Active discovery of new IPv6 addresses does not run with `--passive-only` or in the
OT profile (unless `--active`), and finds only devices that answer from an address built from their hardware address.
IPv6 flows and decoded industrial traffic also need `--ipv6-subnet` for your prefixes. See
[Concepts](concepts.md#ipv6-optional).

**An industrial protocol shows no GOOSE, Sampled Values or PROFINET devices**
Layer-2 traffic stays inside its switch or VLAN: mirror the station bus (GOOSE), the process bus (Sampled Values) or the
cell switch (PROFINET). Sampled Values are off until switched on under *Settings → Capture → Network interface* (a restart is
needed). See [OT guide](ot-guide.md#layer-2-traffic-goose-sampled-values-profinet).

**A Siemens S7-1200/1500 stop or program download raised no control-command alert**
Not reported for S7comm-plus, deliberately (see [OT guide](ot-guide.md#limits-to-know-about)). Classic S7comm still is.

**A block is refused**
The dry run says why. Common reasons: the target is DENIS itself or the gateway, it is on that connector's *Never
block these ...* list, enforcement is switched off or the hourly limit is reached, or the address is named in an open
`arp_conflict` alert (tick the acknowledgement if you accept that the wrong device may be hit). Unblocking is never
refused for these reasons. See [Zones and policies](segmentation.md#enforcement-connectors).

**`--report-to` does nothing**
Look for "--report-to ignored" in the log: an `http://` address (without `--report-to-allow-plain-http`) or another
unacceptable address turns the relay off, and DENIS carries on without it.

## The browser says the connection is not private / certificate warning

DENIS uses HTTPS with a certificate it created itself, which browsers do not know. Either trust the DENIS CA once (*Settings → Sign-in & security → HTTPS certificate → Download the CA certificate*, or `tls/ca.pem` beside the database) or install your own certificate there. Open the console by a name or address the certificate covers (`localhost`, this machine's name, its IP addresses, or a `--tls-name`); otherwise the browser reports a name mismatch. A `curl` needs `--cacert tls/ca.pem`.
