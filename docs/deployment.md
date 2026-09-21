# Deployment and administration

## Ports and processes

| Purpose | Default | Notes |
|---|---|---|
| Web UI + API | `127.0.0.1:8080` | HTTPS (certificate created by DENIS), sign-in required; this machine only. `--listen` / `DENIS_LISTEN` changes it |
| Agent ingest | *off* | enable with `--ingest-listen 0.0.0.0:8081`; per-agent bearer tokens |

DENIS is one binary. `denis run` is the whole system for one network (collector, detection, UI). Add
`denis agent` processes for extra sites.

## Installing on a Linux server (a permanent service)

You do not need a compiler. The installer downloads the program from the GitHub release, **checks its signature
and checksum**, sets it up as a systemd service and tells you where to open it. It works on Ubuntu, Debian,
Raspberry Pi OS and RHEL-family systems, on x86-64 and ARM64.

```bash
curl -fLO https://github.com/stefanmesaros/denis/releases/latest/download/install.sh
less install.sh            # it runs as root: read it first (it is short and commented)
sudo bash install.sh
```

What you see at the end (example):

```
==> Signature OK (signed with the DENIS release key)
==> Checksum OK
==> DENIS 0.1.3 is running
    Open   https://192.168.1.20:8443
    Sign in as   admin   with the one-time password below (you must change it at first sign-in):
      xxxxxxxxxxxxxxxxxxxx
```

Open the address in a browser. It warns once about the certificate (DENIS made its own; see
[HTTPS](#reaching-the-ui-securely-https-is-on-by-default) to trust or replace it), then sign in as `admin` with the
one-time password and choose your own. Lost it? `sudo -u denis denis user reset admin --db /var/lib/denis/denis.db`.

**What the installer changes**, and nothing else: `/usr/local/bin/denis`, the `denis` system user, the service
`/etc/systemd/system/denis.service`, `/etc/denis/env` (your settings) and `/var/lib/denis` (the data). It does not
touch firewalls or other services, and it never takes over a port that is in use.

**Ports.** The console listens on **8443** on every address, or the next free port if that is taken (8080, the
"usual" port, is often used by something else, so DENIS does not start there on a server). Choose yourself with
`--port 9000`. `--local-only` listens on `127.0.0.1` only (from 8080 upward), for use through an SSH tunnel:
`ssh -L 8443:localhost:8443 you@server` then `https://localhost:8443`. If you pick a port that is already in use the
installer stops before changing anything and says so. If a firewall is on (`ufw`), the installer tells you the one
command that opens the port; it does not run it.

| Option | Meaning |
|---|---|
| `--version v0.1.3` | install that release instead of the newest |
| `--port N` | console port |
| `--local-only` | listen on this machine only |
| `--name NAME` | another name or address the certificate must cover (repeatable); the machine's address and name are added automatically |
| `--dry-run` | download and verify, change nothing (no root needed): a safe way to try it |
| `--no-signature-check` | check the SHA-256 only, for a system whose `openssl` is too old for Ed25519 |
| `--uninstall` | stop and remove the program and service, **keep the data** |
| `--uninstall --purge` | also delete the data, the settings and the `denis` user |

**Change a setting later** (port, extra certificate names, alert webhook…): edit `/etc/denis/env` and
`sudo systemctl restart denis`. Any `denis run` option that has an environment name can go there, for example
`DENIS_LISTEN=0.0.0.0:9443`, `DENIS_TLS_NAMES=denis.example.lan`, `DENIS_WEBHOOK=…`, `DENIS_NO_UPDATE_CHECK=1`.
The file is only readable by root.

**Update.** Run the installer again (`sudo bash install.sh`, after downloading the newest one). It backs the
database up to `/var/lib/denis/backups/`, replaces the program (keeping the old one as `/usr/local/bin/denis.previous`),
keeps your settings and restarts. The console also tells administrators when a new version exists. It cannot install
it itself under this service (the program folder is not writable by the service user; that is a safety choice), so
the installer is the way.

**If something is wrong.** `systemctl status denis` and `journalctl -u denis -n 30` say what happened. The usual one:

* *`Address already in use`* means the port in `/etc/denis/env` was taken after the installer chose it (another program
  started, or you moved it). DENIS exits, changes nothing else, and systemd tries five times in two minutes and then
  leaves the service *failed*. Set a free `DENIS_LISTEN` in `/etc/denis/env`, then
  `sudo systemctl reset-failed denis && sudo systemctl restart denis`. `ss -ltnp` shows who holds a port.
* *No devices*: see [Troubleshooting](troubleshooting.md).

### Without the installer

The same thing by hand (x86-64 shown; the ARM64 file is `denis-aarch64-unknown-linux-gnu`):

```bash
sudo apt install libpcap0.8t64            # Ubuntu 22.04 and Debian: libpcap0.8
V=v0.1.3                                   # the version you want, see the Releases page
cd /tmp
curl -fLO https://github.com/stefanmesaros/denis/releases/download/$V/denis-x86_64-unknown-linux-gnu
curl -fLO https://github.com/stefanmesaros/denis/releases/download/$V/SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS   # must say: denis-x86_64-unknown-linux-gnu: OK
sudo install -m755 denis-x86_64-unknown-linux-gnu /usr/local/bin/denis
sudo useradd --system --no-create-home --shell /usr/sbin/nologin denis
sudo curl -fL -o /etc/systemd/system/denis.service https://raw.githubusercontent.com/stefanmesaros/denis/$V/packaging/denis.service
sudo mkdir -p /etc/denis && sudo tee /etc/denis/env >/dev/null <<'EOF'
DENIS_LISTEN=0.0.0.0:8443
DENIS_TLS_NAMES=192.168.1.20
EOF
sudo chmod 600 /etc/denis/env
sudo systemctl daemon-reload && sudo systemctl enable --now denis
sudo journalctl -u denis | grep -A4 "FIRST START"
```

(`SHA256SUMS.sig` is an Ed25519 signature of `SHA256SUMS`; the installer checks it with the project's release key.
To check it yourself: the key is in `src/update_key.rs`, and `openssl pkeyutl -verify -rawin` verifies it.)

Or **build from source** (needs [Rust](https://rustup.rs)): `sudo apt install build-essential libpcap-dev`,
`cargo build --release`, `sudo install -m755 target/release/denis /usr/local/bin/denis`, then the service steps above.

The service runs as the unprivileged `denis` user with only the capabilities packet capture needs
(`CAP_NET_RAW`, `CAP_NET_ADMIN`; no `setcap` is needed) and keeps its data in `/var/lib/denis`. The unit's syntax is
checked with `systemd-analyze verify`; read the comments at the top of `packaging/denis.service`.

The first-start administrator password is printed to the service's standard error: read it with
`sudo journalctl -u denis | grep -A3 "FIRST START"`, or simply run `sudo -u denis denis user reset admin
--db /var/lib/denis/denis.db`.

## Reaching the UI securely: HTTPS is on by default

DENIS serves the console **and the agent port over HTTPS out of the box**. On first start it creates a small
certificate authority ("DENIS local CA") and a server certificate for `localhost`, this machine's name and addresses
(and any `--tls-name`). The certificate lasts about two years and is **renewed automatically** before it ends, or
when the machine gets a new address. TLS 1.2/1.3 only, HTTP/2 offered, session cookie marked `Secure`.

Browse to **https://localhost:8080** (or the address and port you set in `DENIS_LISTEN`). Browsers do not know the DENIS authority, so they warn once. Two ways to make the
warning go away:

* **Trust the DENIS CA once**: *Settings → HTTPS certificate → Download the CA certificate* (or copy
  `tls/ca.pem` from beside the database) and add it to your browser or operating system's trust store. From then on
  the generated certificate is trusted, including after every automatic renewal.
* **Use your own certificate** (Let's Encrypt, your company CA, a purchased one): *Settings → HTTPS certificate → Use my
  own certificate…*, paste the chain and the private key. DENIS checks that they belong together and are valid, and starts
  using them **immediately, without a restart**. *Go back to the generated certificate* undoes it.

Prefer files? `denis run --tls-cert fullchain.pem --tls-key privkey.pem` uses your files instead (re-read every hour,
so a renewed certificate needs no restart), and the console's upload is then disabled. Certificates and keys live in
`tls/` beside the database (`--tls-dir` to move it); keys are readable by the DENIS user only.

Agents on other machines trust the master's certificate with `--master-ca`: give them the CA file
(`tls/ca.pem`, downloadable from the console).

Because a listener that is not on loopback accepts any `Host` name, put a firewall in front of it if it is reachable
from a network you do not fully trust.

**Plain HTTP (only when something else provides TLS):** `--no-tls` serves plain HTTP. Use it behind a reverse proxy
on the same machine, or with an SSH tunnel (`ssh -L 8080:localhost:8080 you@server`). **Do not** expose plain HTTP on a
network: sign-in credentials and the session cookie would cross it in clear text.

**TLS reverse proxy on the same machine** (for a shared console). Example with Caddy (automatic certificates):

```
denis.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

Start DENIS with `--no-tls --secure-cookies --public-url https://denis.example.com`. While the UI listens on loopback
DENIS refuses any `Host` name it does not know (protection against DNS rebinding); `--public-url` tells it the public
name is fine and it is also what [passkeys](security.md#passkeys) are bound to. Caddy passes the original `Host` on by
default; with nginx use `proxy_set_header Host $host;` and `proxy_set_header X-Forwarded-For $remote_addr;` (DENIS uses
the last `X-Forwarded-For` entry, from a proxy on this machine only, to rate-limit sign-in attempts per client). Keep
the proxy on the same machine.

## Users and roles

Manage users on the **Users** tab (admins) or with the CLI on the server:

```bash
denis user list
denis user add jana --role editor        # prints a one-time password
denis user reset jana                    # new one-time password, signs her out everywhere
denis user disable jana                  # and: denis user enable jana
```

| Role | Can |
|---|---|
| **viewer** | see everything, export CSV, open the report |
| **editor** | + edit assets, add/import assets, acknowledge alerts, start scans |
| **admin** | + manage users, agent tokens, view the audit log, delete manual assets |

Rules: new and reset passwords are one-time and **must be changed at first sign-in**; passwords need ≥ 12
characters; five wrong passwords lock that account out for 30 seconds (doubling for repeated failures, up to
15 minutes); sessions end after 12 h idle or 7 days; changing a password signs out the user's other sessions;
**the last enabled administrator cannot be removed or demoted**. Everything security-relevant is in the audit log.

## Multiple sites (agents)

On the master:

```bash
denis run --ingest-listen 0.0.0.0:8081
denis agent-token issue --id branch-1 --label "Branch office"     # prints a token once
```

At the remote site:

```bash
DENIS_AGENT_TOKEN=dat_… denis agent --master https://MASTER:8081 --master-ca /etc/denis/ca.pem --id branch-1 --name "Branch office" --site Branch --flows
```

* Each agent has **its own token, bound to its id**; a token cannot speak for another agent. Revoke it with
  `denis agent-token revoke --id branch-1` (or in the **Sites** tab): the agent is cut off immediately.
* Agents only make *outbound* connections. They send changes every 15 s and keep unsent data (in memory, up to
  200 000 traffic windows) while the master is unreachable.
* **No TLS is built into the ingest port.** Across the Internet, put it behind a TLS proxy or a VPN
  (WireGuard/SSH tunnel). Repeated bad tokens from one address are throttled.
* Give each site its own learning period; the master handles it automatically.

## Alert notifications

Configure **Slack, Teams, Discord, PagerDuty, Pushover, ntfy, e-mail and signed webhooks** in the console (*Alerting* tab, see [Alerting](alerting.md)); no restart, per-channel thresholds, a Test button. The simple command-line webhook below is the older way and still works:

```bash
denis run --webhook https://hooks.slack.com/services/… --webhook-min-score 60
# or: DENIS_WEBHOOK=… denis run
```

The payload is JSON with `text` (Slack) and `content` (Discord) plus the full event, so standard incoming-webhook
URLs work. Delivery is retried three times and never blocks detection. Only alerts at or above
`--webhook-min-score` are sent. (Keep the URL in the environment variable; command-line arguments are visible
to other local users.)

## Data, backup and retention

Everything is in one SQLite file (`denis.db` in the working directory by default, or `--db`).
**Back it up** while running with `denis backup` (a verified, owner-only copy; see [Operations](operations.md#backup-and-restore)):

```bash
denis backup /backups/denis-$(date +%F).db --db /var/lib/denis/denis.db
```

Restore by stopping DENIS and copying the backup over the database file. Trend samples are kept for
`--retention-days` (90); events, baselines and audit entries are small and kept indefinitely.

The database contains your network inventory and password hashes: protect it like the service itself
(owner-only permissions).

## Upgrading

Stop DENIS, replace the binary, start it. The database migrates itself on start (**one-way**: older builds refuse
a newer database): back it up first.

## Resource use

Sized for one /24 up to ~1000 hosts per collector. Flow accounting captures every IPv4 frame on the interface;
on a busy gigabit link use a fast machine or a dedicated capture interface.

## Command reference

`denis run --help`, `denis agent --help`. Other commands:

| Command | Purpose |
|---|---|
| `denis interfaces` | list usable interfaces (`*` = default) |
| `denis list` / `denis alerts` | inventory / alerts as a table, straight from the database |
| `denis report --days 7 -o report.html` | printable report (`--format assets-csv|alerts-csv`) |
| `denis user …`, `denis agent-token …` | access management (see above) |
| `denis backup FILE` | verified copy of the database, while running |
| `denis replay FILE.pcap` | run a packet capture through the decoders and rules and print what was found (nothing is stored) |
| `denis serve` | console over a database, no capture (backups, demos) |
| `denis demo load\|remove` | built-in demo data (a fictional company) |
| `denis erase --yes` | empty the database of devices and history (DENIS stopped; take a backup first) |
