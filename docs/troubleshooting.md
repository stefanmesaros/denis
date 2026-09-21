# Troubleshooting

**"cannot open en0 for capture … Permission denied"**
Packet capture needs privileges. Linux: `sudo setcap cap_net_raw,cap_net_admin=eip ./denis` (or run as root /
via the systemd unit). macOS: install Wireshark's ChmodBPF or run with `sudo`.

**"binding web UI on 127.0.0.1:8080 … Address already in use"**
Another DENIS (or program) holds the port. Stop it, or use `--listen 127.0.0.1:9000`. Nothing is sent to the
network when this happens.

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

**"No traffic baseline yet" / Trends and OT tabs are empty**
Traffic analysis needs `--flows` (or `--profile ot`) and traffic that reaches the collector. See
[Concepts › Visibility](concepts.md#visibility-what-can-be-seen-from-where).

**Too many alerts**
Normal during the first days on a busy network. Use `--rule-weight new_destination=0.5`, raise `--min-score`,
prefer the rules on quiet devices, and acknowledge what you have handled. During the first 24 hours new
things are learned, not alerted on.

**A device has the wrong type or OS**
Edit asset → Device type / Operating system. Your value is used everywhere. The device page's *Why this guess*
shows what DENIS saw.

**Two of every device in Sites**
Two collectors on the same network segment. Keep one collector per segment.

**An agent is not connecting**
Check `denis agent-token list` (revoked?), the master's `--ingest-listen` address and firewall, that the agent
id matches the token, and that the agent can reach `http://MASTER:8081/api/v1/ping` with the token.

**Database problems**
Stop DENIS, restore the latest backup (`.backup` file) over the database file. Never edit it while running.

## The browser says the connection is not private / certificate warning

DENIS uses HTTPS with a certificate it created itself, which browsers do not know. Either trust the DENIS CA once (*Settings → HTTPS certificate → Download the CA certificate*, or `tls/ca.pem` beside the database) or install your own certificate there. Open the console by a name or address the certificate covers (`localhost`, this machine's name, its IP addresses, or a `--tls-name`); otherwise the browser reports a name mismatch. A `curl` needs `--cacert tls/ca.pem`.
