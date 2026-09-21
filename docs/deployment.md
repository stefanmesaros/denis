# Deployment and administration

## Ports and processes

| Purpose | Default | Notes |
|---|---|---|
| Web UI + API | `127.0.0.1:8080` | HTTPS (certificate created by DENIS), sign-in required; this machine only. `--listen` / `DENIS_LISTEN` changes it |
| Agent ingest | *off* | enable with `--ingest-listen 0.0.0.0:8081`; per-agent bearer tokens |

DENIS is one binary. `denis run` is the whole system for one network (collector, detection, UI). Add
`denis agent` processes for extra sites.

## Installing on Ubuntu / Debian (a permanent service)

**1. The program.** Either download a release (no compiler needed) or build it.

*From a release* (x86-64 shown; the ARM64 file is `denis-aarch64-unknown-linux-gnu`):

```bash
sudo apt install libpcap0.8t64            # Ubuntu 22.04: libpcap0.8
V=v0.1.3                                   # the version you want, see the Releases page
cd /tmp
curl -fLO https://github.com/stefanmesaros/denis/releases/download/$V/denis-x86_64-unknown-linux-gnu
curl -fLO https://github.com/stefanmesaros/denis/releases/download/$V/SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS   # must say: denis-x86_64-unknown-linux-gnu: OK
sudo install -m755 denis-x86_64-unknown-linux-gnu /usr/local/bin/denis
```

*Or build it* (needs [Rust](https://rustup.rs)):

```bash
sudo apt install build-essential libpcap-dev
cargo build --release
sudo install -m755 target/release/denis /usr/local/bin/denis
```

**2. The service.**

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin denis
sudo cp packaging/denis.service /etc/systemd/system/     # from the repository, or the same file at
                                                         # https://github.com/stefanmesaros/denis/blob/main/packaging/denis.service
```

**3. Choose where the console listens (do this before starting).** The unit listens on `127.0.0.1:8080`, reachable
only from the server itself. To open it from your laptop, and/or to avoid a port that something else already uses,
create `/etc/denis/env` (root-owned, mode 0600):

```bash
sudo mkdir -p /etc/denis
sudo tee /etc/denis/env >/dev/null <<'EOF'
DENIS_LISTEN=0.0.0.0:8443
DENIS_TLS_NAMES=192.168.1.20
EOF
sudo chmod 600 /etc/denis/env
```

Use a free port (`ss -ltn` lists the taken ones) and put the server's own address or name in `DENIS_TLS_NAMES`, so the
generated certificate covers it. Then browse to `https://192.168.1.20:8443`.

**4. Start it.**

```bash
sudo systemctl daemon-reload && sudo systemctl enable --now denis
sudo systemctl status denis        # active (running)
```

**If the port is already taken** (another program on 8080, say) DENIS cannot open the console and exits with
`Error: binding web UI on 127.0.0.1:8080 … Address already in use`. Nothing else is disturbed and nothing is taken
over. systemd retries five times within two minutes and then leaves the service *failed* (`systemctl status denis`,
`journalctl -u denis -n 20`). Set another `DENIS_LISTEN` in `/etc/denis/env`, then
`sudo systemctl reset-failed denis && sudo systemctl restart denis`.

The service runs as the unprivileged `denis` user with only the capabilities packet capture needs
(`CAP_NET_RAW`, `CAP_NET_ADMIN`) and stores data in `/var/lib/denis`. The unit's syntax is checked with
`systemd-analyze verify`; read the comments at the top of `packaging/denis.service` and test it before relying on it.

**Updating** a service installed like this is by hand (the console announces the update, but the program folder is not
writable by the service, so it cannot replace itself): download the new file as in step 1 (`sudo install` over
`/usr/local/bin/denis`) and `sudo systemctl restart denis`. Back up first:
`sudo -u denis denis backup /var/lib/denis/backup-before-update.db`.

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

Configure **Slack, Teams, Discord, PagerDuty, e-mail and signed webhooks** in the console (*Alerting* tab, see [Alerting](alerting.md)); no restart, per-channel thresholds, a Test button. The simple command-line webhook below is the older way and still works:

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
| `denis serve` | console over a database, no capture (backups, demos) |
| `denis demo load\|remove` | built-in demo data (a fictional company) |
| `denis erase --yes` | empty the database of devices and history (DENIS stopped; take a backup first) |
