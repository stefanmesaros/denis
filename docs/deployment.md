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
and checksum**, sets it up as a service (systemd, or OpenRC on Alpine) and tells you where to open it.

**Supported systems:** Linux on x86-64 and ARM64, with **systemd** (Ubuntu, Debian, Raspberry Pi OS, RHEL-family,
Fedora, Arch, ...) or **OpenRC** (Alpine). Two builds of the program exist, and the installer picks one:

* Debian, Ubuntu and Raspberry Pi OS get the usual build (`denis-*-unknown-linux-gnu`). It uses the system's libpcap
  (`libpcap.so.0.8`), which the installer adds with `apt-get` when it is missing.
* Alpine and every other Linux get the **static build** (`denis-*-unknown-linux-musl`, from 4.1.1): libpcap and the C
  library are built in, so nothing else is installed and it runs regardless of which libpcap the system has (or none).
  `--static` takes it on Debian or Ubuntu too.
* **High availability** (a second node on a shared PostgreSQL database) needs the PostgreSQL build: a ready-made PostgreSQL build is attached to every release from 4.2.1 (`denis-pg-x86_64-unknown-linux-musl`, `denis-pg-aarch64-unknown-linux-musl`): static, signed like the others, so nothing needs to be built. `sudo bash install.sh --postgres` installs it, and it updates itself to the PostgreSQL build of each new release. `denis --version` ends with `(postgresql)` when it is that build. See [High availability](high-availability.md).

On a system with neither systemd nor OpenRC the installer stops and suggests `--no-service` (below).

```bash
curl -fLO https://github.com/stefanmesaros/denis/releases/latest/download/install.sh
less install.sh            # it runs as root: read it first (it is short and commented)
sudo bash install.sh
```

**Alpine:** the installer is a bash script and downloads with curl, so add those first, then run it as root:

```sh
apk add bash curl openssl
bash install.sh            # as root (or: doas bash install.sh)
```

It writes `/etc/init.d/denis` (supervised by OpenRC's `supervise-daemon`, started at boot in the `default` runlevel),
logs to `/var/log/denis/denis.log`, and gives the `denis` user's process the two capture capabilities through OpenRC
(`capabilities=`, OpenRC 0.45 or newer, so the console can still update the program). On an older OpenRC it gives the
program file the capabilities with `setcap` instead (installing `libcap-setcap` if needed); updates then go through
the installer, because the console does not replace a file that carries capabilities. Manage it with
`rc-service denis status|restart|stop`.

**Check the installer before running it** (releases from 4.1.1 on list `install.sh` in the signed `SHA256SUMS`). In bash,
with the release key from `src/update_key.rs` (the same key the installer carries):

```bash
V=v4.1.3; B=https://github.com/stefanmesaros/denis/releases/download/$V
curl -fLO $B/install.sh -O $B/SHA256SUMS -O $B/SHA256SUMS.sig
hex2bin() { printf '%b' "$(printf '%s' "$1" | sed 's/../\\x&/g')"; }
hex2bin 302a300506032b6570032100abe75462c8adfb1d4c5aa39d25e44377d00c77442f423c2f01cd51fec40e938e > denis-release.der
hex2bin "$(tr -d ' \n\r' < SHA256SUMS.sig)" > SHA256SUMS.bin
openssl pkeyutl -verify -pubin -inkey denis-release.der -keyform DER -rawin -in SHA256SUMS -sigfile SHA256SUMS.bin
sha256sum -c --ignore-missing SHA256SUMS   # must say: install.sh: OK
```

What you see at the end (example):

```
==> Signature OK (signed with the DENIS release key)
==> Checksum OK
==> DENIS 2.51.0 is running
    Open   https://192.168.1.20:8443
    Sign in as   admin   with the one-time password below (you must change it at first sign-in):
      xxxxxxxxxxxxxxxxxxxx
```

Open the address in a browser. It warns once about the certificate (DENIS made its own; see
[HTTPS](#reaching-the-ui-securely-https-is-on-by-default) to trust or replace it), then sign in as `admin` with the
one-time password and choose your own. Lost it? `sudo -u denis denis user reset admin --db /var/lib/denis/denis.db`.

**What the installer changes**, and nothing else: the program at `/usr/local/lib/denis/denis` (owned by the `denis`
user, so it can update itself later — see *Update* below) with a convenience symlink at `/usr/local/bin/denis`, the
`denis` system user, the service `/etc/systemd/system/denis.service`, `/etc/denis/env` (your settings) and
`/var/lib/denis` (the data). It does not touch firewalls or other services, and it never takes over a port that is
in use.

**Ports.** The console listens on **8443** on every address, or the next free port if that is taken (8080, the
"usual" port, is often used by something else, so DENIS does not start there on a server). Choose yourself with
`--port 9000`. `--local-only` listens on `127.0.0.1` only (from 8080 upward), for use through an SSH tunnel:
`ssh -L 8443:localhost:8443 you@server` then `https://localhost:8443`. If you pick a port that is already in use the
installer stops before changing anything and says so. If a firewall is on (`ufw`), the installer tells you the one
command that opens the port; it does not run it.

| Option | Meaning |
|---|---|
| `--version v2.51.0` | install that release instead of the newest |
| `--port N` | console port |
| `--local-only` | listen on this machine only |
| `--name NAME` | another name or address the certificate must cover (repeatable); the machine's address and name are added automatically |
| `--dry-run` | download and verify, change nothing (no root needed): a safe way to try it |
| `--no-service` | install the program, the `denis` user, `/etc/denis/env` and the data folder, but no service (see below) |
| `--static` | take the static build even on Debian or Ubuntu |
| `--postgres` | take the PostgreSQL build (`denis-pg-*`, static; release 4.2.1 or newer; master only), for [high availability](high-availability.md). Required when running the installer again on a PostgreSQL installation (also to move one built by hand from 4.2.0 or earlier: do not use the console Update button for that) |
| `--standard` | take the standard build although a PostgreSQL build is installed (it refuses `--database-url`) |
| `--no-signature-check` | check the SHA-256 only, for a system whose `openssl` is too old for Ed25519 |
| `--uninstall` | stop and remove the program and service, **keep the data** |
| `--uninstall --purge` | also delete the data, the settings and the `denis` user |

**Without a service (`--no-service`).** For a system with neither systemd nor OpenRC, or to run DENIS under your own
supervisor (runit, s6, supervisord, a container). The installer verifies and installs the program as usual, creates
the `denis` user, `/etc/denis/env` (readable by the `denis` group, since the program reads it itself) and
`/var/lib/denis`, gives the program file the capture capabilities with `setcap`, and prints the command to start it:

```sh
su -s /bin/sh denis -c 'set -a; . /etc/denis/env; exec /usr/local/lib/denis/denis run --db /var/lib/denis/denis.db'
```

The first start prints the one-time `admin` password. The console cannot update a program file that carries
capabilities, so update by running `bash install.sh --no-service` again (stop DENIS first, start it afterwards).
`--agent --no-service` does the same for a remote agent (`denis agent --db /var/lib/denis-agent/agent.db`).

**Change a setting later** (port, extra certificate names, alert webhook…): edit `/etc/denis/env` and
`sudo systemctl restart denis` (OpenRC: `rc-service denis restart`). Any `denis run` option that has an environment name can go there, for example
`DENIS_LISTEN=0.0.0.0:9443`, `DENIS_TLS_NAMES=denis.example.lan`, `DENIS_WEBHOOK=…`, `DENIS_NO_UPDATE_CHECK=1`.
The file is only readable by root. When `DENIS_LISTEN` names the machine's own address (not `0.0.0.0`) and that address
is not on an interface yet when DENIS starts (a late link or DHCP), Linux binds it anyway (`IP_FREEBIND`) and the log
says so; the console answers as soon as the address appears. DENIS looks for the address every 30 seconds: when it has not
appeared after 5 minutes (usually a typo in `DENIS_LISTEN`), the log says so as an error and the Health page warns until it
appears. On other systems DENIS stops with "address not available".

**Update.** The console tells administrators when a new version exists (Settings → System → Updates, or the banner under the
header) and **installs it itself** with one click — no root needed, because `/usr/local/lib/denis` is owned by the
`denis` user (`ReadWritePaths` is the one exception `ProtectSystem=strict` allows). It backs the database up to
`/var/lib/denis/backups/` first and keeps the old program as `/usr/local/lib/denis/denis.previous`. Prefer to control
it yourself, or air-gapped: run the installer again (`sudo bash install.sh`, after downloading the newest one; on a PostgreSQL installation add `--postgres`, without it the installer stops instead of replacing the build) instead —
same backup, same result. An installation from before this existed (the program straight at `/usr/local/bin/denis`,
owned by root, not writable by the service user) needs `sudo bash install.sh` run **once** to move it into the new
layout (it also updates the systemd unit's `ExecStart`/`ReadWritePaths`, which only root can do); every update after
that can be the one-click kind. Only stable releases are offered unless an administrator opts in to pre-releases
(release candidates, for testers; see [Updates](updates.md#pre-release-versions-for-testers)). If GitHub cannot be reached, the
same signed files are fetched from `usedenis.com`, which can be switched off. Remote agents are updated from the **Sites**
page, by hand by default: see [Updating remote agents](updates.md#updating-remote-agents).

**If something is wrong.** `systemctl status denis` and `journalctl -u denis -n 30` say what happened (OpenRC:
`rc-service denis status` and `tail -n 30 /var/log/denis/denis.log`). The usual one:

* *`Address already in use`* means the port in `/etc/denis/env` was taken after the installer chose it (another program
  started, or you moved it). DENIS exits, changes nothing else, and systemd tries five times in two minutes and then
  leaves the service *failed*. Set a free `DENIS_LISTEN` in `/etc/denis/env`, then
  `sudo systemctl reset-failed denis && sudo systemctl restart denis`. `ss -ltnp` shows who holds a port.
* *No devices*: see [Troubleshooting](troubleshooting.md).

### Without the installer

The same thing by hand (x86-64 shown; the ARM64 file is `denis-aarch64-unknown-linux-gnu`; for the static build
take `denis-x86_64-unknown-linux-musl` and skip the libpcap package):

```bash
sudo apt install libpcap0.8t64            # Ubuntu 22.04 and Debian: libpcap0.8
V=v2.51.0                                  # the version you want, see the Releases page
cd /tmp
curl -fLO https://github.com/stefanmesaros/denis/releases/download/$V/denis-x86_64-unknown-linux-gnu
curl -fLO https://github.com/stefanmesaros/denis/releases/download/$V/SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS   # must say: denis-x86_64-unknown-linux-gnu: OK
sudo useradd --system --no-create-home --shell /usr/sbin/nologin denis
sudo install -d -o denis -g denis /usr/local/lib/denis
sudo install -m755 -o denis -g denis denis-x86_64-unknown-linux-gnu /usr/local/lib/denis/denis
sudo ln -sf /usr/local/lib/denis/denis /usr/local/bin/denis   # convenience: denis backup, denis user reset, ...
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
`cargo build --release` (the static build: [below](#building-the-static-program-yourself)), `sudo install -m755 -o denis -g denis target/release/denis /usr/local/lib/denis/denis`
(after the `useradd`/`install -d` steps above), then the service steps above.

The service runs as the unprivileged `denis` user with only the capabilities packet capture needs
(`CAP_NET_RAW`, `CAP_NET_ADMIN`; no `setcap` is needed) and keeps its data in `/var/lib/denis`. The unit's syntax is
checked with `systemd-analyze verify`; read the comments at the top of `packaging/denis.service`.

The first-start administrator password is printed to the service's standard error: read it with
`sudo journalctl -u denis | grep -A3 "FIRST START"`, or simply run `sudo -u denis denis user reset admin
--db /var/lib/denis/denis.db`.

### Building the static program yourself

The release files `denis-x86_64-unknown-linux-musl` and `denis-aarch64-unknown-linux-musl` are built with the musl C
library and libpcap linked in. They need nothing installed and run on Alpine, Debian, RHEL, Arch, systems with
`libpcap.so.1` or with no libpcap at all. They are built in an Alpine container, so only Docker is needed:

```bash
tools/build-musl.sh                              # -> ./denis-<arch>-unknown-linux-musl (this machine's CPU type)
tools/build-musl.sh --smoke ./denis-aarch64-unknown-linux-musl   # run it in a clean alpine container
FEATURES=postgres tools/build-musl.sh            # the PostgreSQL flavour -> ./denis-pg-<arch>-unknown-linux-musl
```

What the script does in the `rust:1-alpine` container (the release workflow runs the same script):

```sh
apk add musl-dev libpcap-dev pkgconf linux-headers file   # libpcap-dev includes the static libpcap.a
export RUSTFLAGS="-C target-feature=+crt-static"           # link the C library in
export PKG_CONFIG_ALL_STATIC=1                             # make the pcap crate link libpcap.a, not libpcap.so
cargo build --release --locked --target "$(uname -m)-unknown-linux-musl"
file target/.../denis                                      # must say "static-pie linked" (or "statically linked")
```

`--smoke` starts the result in a plain `alpine:latest` container with no package added: `denis --version`,
`denis interfaces`, then `denis run --passive-only` until `/api/health` answers.

The build is for the CPU of the machine (or Docker VM) it runs on: an Apple silicon Mac makes the ARM64 file. The
x86-64 file is made by the release workflow on an x86-64 runner (or locally with `docker run --platform linux/amd64`,
emulated and slow). The release build of the `denis` crate needs about 3 GB of memory; give Docker that much, or swap.

## Reaching the UI securely: HTTPS is on by default

DENIS serves the console **and the agent port over HTTPS out of the box**. On first start it creates a small
certificate authority ("DENIS local CA") and a server certificate for `localhost`, this machine's name and addresses
(and any `--tls-name`). The certificate lasts about two years and is **renewed automatically** before it ends, or
when the machine gets a new address. TLS 1.2/1.3 only, HTTP/2 offered, session cookie marked `Secure`.

The authority can only vouch for this console: it is created with X.509 name constraints that limit it to the
console's own host names (and their subdomains) and to private, loopback, link-local and carrier-grade-NAT
addresses (plus any public address the machine has or is named with). Even someone who later copies `tls/ca.key`
cannot use it to impersonate another website to a browser that trusts the CA. A new `--tls-name` (or a new public
address) outside those names makes DENIS create a new authority, which then has to be trusted again (the log says
so). An authority made by an earlier version has no constraints: it keeps working, and the log and the Health page
warn until you replace it (delete `tls/ca.pem` and `tls/ca.key`, restart, trust the new CA, and give agents the
new file with `--master-ca`).

Browse to **https://localhost:8080** (or the address and port you set in `DENIS_LISTEN`). Browsers do not know the DENIS authority, so they warn once. Two ways to make the
warning go away:

* **Trust the DENIS CA once**: *Settings → Sign-in & security → HTTPS certificate → Download the CA certificate* (or copy
  `tls/ca.pem` from beside the database) and add it to your browser or operating system's trust store. From then on
  the generated certificate is trusted, including after every automatic renewal.
* **Use your own certificate** (Let's Encrypt, your company CA, a purchased one): *Settings → Sign-in & security → HTTPS certificate → Use my
  own certificate…*, paste the chain and the private key. DENIS checks that they belong together and are valid, and starts
  using them **immediately, without a restart**. *Go back to the generated certificate* undoes it.

Prefer files? `denis run --tls-cert fullchain.pem --tls-key privkey.pem` uses your files instead (re-read every hour,
so a renewed certificate needs no restart), and the console's upload is then disabled. Certificates and keys live in
`tls/` beside the database (`--tls-dir` to move it); keys are readable by the DENIS user only.

Agents on other machines trust the master's certificate with `--master-ca`: give them the CA file
(`tls/ca.pem`, downloadable from the console). For more than a couple of agents, copying a file to
every machine is the tedious part — not renewal: the CA itself is long-lived and does not change
when the master's own certificate renews, so an agent set up once keeps working across every later
renewal without touching it again. To skip the file copy itself, use `--master-ca-pem`
(or `DENIS_MASTER_CA_PEM`) with the certificate's *text* instead of a path — *Settings → Sign-in & security → HTTPS
certificate → Copy for --master-ca-pem* puts it on the clipboard, ready to push through whatever
already deploys each agent's token (a secrets manager, Ansible, cloud-init), with nothing extra to
transfer per machine. Give either `--master-ca` or `--master-ca-pem`, never both.

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
denis user reset-mfa jana                # removes her authenticator app and signs her out; she sets it up again
denis user reset-mfa --unreadable        # every account whose authenticator app secrets.key cannot open
denis user scrub-backups               # seals authenticator secrets left readable in scheduled and manual backups
```

`denis user` works on the SQLite file (`--db`, `--data-dir` for where `secrets.key` is) or, on a PostgreSQL
installation, on the database of `--database-url` (the same value as `denis run`, the password in
`DENIS_DATABASE_PASSWORD`), so a locked-out installation can always be recovered from the host's shell.

| Role | Can |
|---|---|
| **viewer** | see everything, export CSV, open the report |
| **editor** | + edit assets, add/import assets, acknowledge alerts, start scans |
| **admin** | + manage users, agent tokens, view the audit log, delete manual assets |

Rules: new and reset passwords are one-time and **must be changed at first sign-in**; passwords need ≥ 12
characters; five wrong passwords from one address lock that account out *for that address* for 30 seconds (doubling for
repeated failures, up to 15 minutes; the exact limits, and why a stranger cannot lock the owner out, are in
[Security](security.md#sign-in-limits-and-lock-out)); sessions end after 12 h idle or 7 days; changing a password signs out the user's other sessions;
**the last enabled administrator cannot be removed or demoted**. Everything security-relevant is in the audit log.

## Multiple sites (agents)

### The easy way

1. On the master, make sure it accepts agents: *Settings → Capture → Network interface → Accept remote agents at*
   (for example `0.0.0.0:8081`), then restart. Or start it with `denis run --ingest-listen 0.0.0.0:8081`.
2. Open the **Sites** tab and press **Add agent**. Give the agent an id (and, if you like, a name and a site),
   and DENIS creates its token and shows the exact commands, with this master's address and CA certificate filled
   in, ready to copy: one for Linux, one for Docker and one for running `denis agent` by hand. The token is shown
   once.
3. Run the Linux command on the remote machine. It looks like this (the dialog fills in the values; the CA
   certificate follows as the text after `<<'PEM_…'`, a random delimiter). The installer then asks for the token:
   paste it from the dialog. Since 4.1.1 the token is not on the command line, where other users of the machine could
   read it in the process list, and not in the shell history (`DENIS_AGENT_TOKEN` in the environment or
   `--token-file FILE` work too; `--token` still works).

```bash
curl -fLO https://github.com/stefanmesaros/denis/releases/download/v4.1.3/install.sh
sudo bash install.sh --version v4.1.3 --agent --master https://MASTER:8081 \
  --id branch-1 --name "Branch office" --site Branch --flows --master-ca-pem - <<'PEM_7Q2K9XWA'
-----BEGIN CERTIFICATE-----
…
-----END CERTIFICATE-----
PEM_7Q2K9XWA
```

`install.sh --agent` downloads the same signed release as the master install and checks its signature and
checksum before changing anything. It then installs the program the same way, writes `/etc/denis/agent.env` (mode
600, because the token is in it), puts the CA at `/etc/denis/ca.pem`, installs the `denis-agent` service and starts
it. Within a minute or so the agent appears under **Sites** on the master. Details:

* `--dry-run` downloads and verifies and says what it would write, without changing anything or needing root.
* It refuses to run on a machine that already runs the master (the same network would be watched twice); add
  `--allow-master-here` if you really mean it.
* `--master-ca-pem FILE` takes a file instead; leave the option out when the master uses a publicly trusted
  certificate. `--master-ca-pem -` reads the text from standard input, which is why the installer is downloaded
  first instead of piped from `curl`.
* A plain `http://` master address is refused unless you add `--allow-plain-http` (a VPN or tunnel you trust). The
  dialog never adds it for you: it warns, and you add the option yourself.
* Agent mode needs release 4.1.0 or newer (a 4.1.0 release candidate counts too). Without `--version` the installer
  takes the latest stable release; a release candidate must be named with `--version`, because "latest" skips
  pre-releases.
* On Alpine the agent is an OpenRC service too (`/etc/init.d/denis-agent`, log `/var/log/denis/denis-agent.log`), and
  the static build (agent mode on Alpine therefore needs 4.1.1 or newer).
* To change settings later, edit `/etc/denis/agent.env` and `sudo systemctl restart denis-agent` (OpenRC:
  `rc-service denis-agent restart`), or run the
  installer again with the new token. Running it with `--agent` alone updates the program and keeps the settings.
  `--agent --uninstall` removes the service (`--purge` also deletes its data and settings).
* Docker: see [Docker, Run a remote agent](docker.md#run-a-remote-agent).

### By hand

On the master:

```bash
denis run --ingest-listen 0.0.0.0:8081
denis agent-token issue --id branch-1 --label "Branch office"     # prints a token once
```

At the remote site:

```bash
DENIS_AGENT_TOKEN=dat_… denis agent --master https://MASTER:8081 --master-ca /etc/denis/ca.pem --id branch-1 --name "Branch office" --site Branch --flows
```

The agent's settings can also come from the environment (`DENIS_MASTER`, `DENIS_AGENT_TOKEN`, `DENIS_AGENT_ID`,
`DENIS_AGENT_NAME`, `DENIS_AGENT_SITE`, `DENIS_FLOWS`, `DENIS_MASTER_CA` or `DENIS_MASTER_CA_PEM`); that is how the
installed service and the Docker image are configured. `packaging/denis-agent.service` is the service file the
installer uses; it needs no editing.

### Windows and macOS

There is no agent installer for Windows or macOS yet. `packaging/install.sh` is Linux only (systemd, OpenRC, or `--no-service`). The
Windows script `packaging/install.ps1` has not been verified, and there is no signed Windows release, so an agent
on Windows is not something we can support today. On macOS (or anywhere else) you can download the program and
run `denis agent ...` by hand as above, but there is no service setup and capture needs administrator rights;
these paths have not been tested for agents. For a site without a Linux machine, run the agent on a small Linux
box or in Docker on the site's network.

* Each agent has **its own token, bound to its id**; a token cannot speak for another agent. Revoke it with
  `denis agent-token revoke --id branch-1` (or in the **Sites** tab): the agent is cut off immediately.
* Agents only make *outbound* connections. They send changes every 15 s and keep unsent data (in memory, up to
  200 000 traffic windows) while the master is unreachable.
* **The ingest port speaks the same HTTPS as the console** (the DENIS local CA or your own certificate; see
  [HTTPS](#reaching-the-ui-securely-https-is-on-by-default)), and the agent pins the master's CA with
  `--master-ca` / `--master-ca-pem`. Across the Internet, a firewall rule limiting the port to the agents'
  addresses, or a VPN (WireGuard/Tailscale/SSH tunnel), is still worth adding. Repeated bad tokens from one
  address are throttled.
* The listener can also be switched on from the console (*Settings → Capture → Network interface*, "Accept
  remote agents at"); like the interface choice, it needs a restart to take effect.
* Give each site its own learning period; the master handles it automatically.
* **Set the agent's clock** (NTP). The master drops records dated more than 1 hour ahead of its own clock or more than 7
  days old, and the Health page names an agent whose records are dropped for that reason. Give the site its **time
  zone** on the Sites page so hour-of-day rules (`unusual_hours`) use the site's local time, not the master's.
* A report is size-checked on arrival (at most 32 MB, and a fixed number of devices, traffic windows and so on); see
  [Security](security.md#what-a-master-accepts-from-an-agent).
* **Overlapping private ranges.** Two sites may both use 10.0.0.0/24: a device is `(site, MAC)`, so their
  devices never mix. Bind each switch and each enforcement connector to its site (Network → Equipment and
  Settings → Response policy show **Site** once there are two or more sites), so that DENIS never acts on a
  device of one site through the firewall of the other. Unbound ones keep working but are marked "Not
  bound to a site" and need a ticked warning to block. See [Concepts](concepts.md#what-a-device-is-site-vlan-mac).
* Do not point a second collector at a network the master already captures itself: every device would be
  listed twice ([Concepts](concepts.md#visibility-what-can-be-seen-from-where)).

## MSP: keeping a copy of a customer's backups

If you run one DENIS install per customer and manage them, you can have each customer's install
push its own scheduled backups to your own master too — so you still have yesterday's device list
(and everything else in the database) if a customer is ever hit by ransomware, without needing any
inbound access to their network.

On your (the MSP's) master, issue the customer a token the same way as for an agent — this only
grants backup uploads, nothing else, unless you also set them up as a reporting agent:

```bash
denis run --ingest-listen 0.0.0.0:8081   # if not already running for agents
denis agent-token issue --id customer-a --label "Customer A"
```

On the customer's own install:

```bash
DENIS_BACKUP_TOKEN=dat_… denis run --backup-upstream https://YOUR-MSP:8081
```

* Their local scheduled backups (the Health page → Backups) are unaffected. **How often the
  newest one is also pushed to you** is a separate schedule the customer sets themselves, right
  below it (Health → "Uploading to your MSP"): manually only, every 8/12/24 hours, or
  every 7 days — independent of their own local backup schedule, and only shown once
  `--backup-upstream` is configured. It never triggers a new backup by itself; it just pushes
  whatever the newest one already is when it is due.
* On your side they land under `backups/from-agents/customer-a/` next to your own database's
  backups, named the same way, but with their own retention: **how many of a given customer's
  uploads you keep** is your own setting (Health → "Customers' uploaded backups",
  default 10), unrelated to that customer's local `keep`.
* A customer with `--backup-upstream` set but no reachable MSP just logs a warning and keeps its
  local backup; nothing about their own install depends on you being reachable.
* This is independent of whether that customer also reports live as an agent (`denis agent`) —
  backups can flow to you even if their master runs entirely standalone otherwise.

## MSP: live devices and alerts from a customer's own master

Beyond backups, a customer's own master (not just a lightweight agent) can relay its devices and
already-scored alerts to your master too, live — so it shows up in your **MSP view** (Settings →
MSP view) alongside every other customer, each kept apart by [site access](tour.md#msp-view-optional).

```bash
denis run --ingest-listen 0.0.0.0:8081   # on your (the MSP's) master, if not already running
denis agent-token issue --id customer-a --label "Customer A"
```

On the customer's own master:

```bash
DENIS_REPORT_TOKEN=dat_… denis run --report-to https://YOUR-MSP:8081
```

**Bandwidth-conscious by design** — this was built specifically so a large customer never means a
large, constant stream of traffic:

* **Devices are sent only when they actually changed** (compared by content, ignoring volatile
  fields like "last seen"), not the whole register every cycle — a customer with 1000 devices that
  are not currently changing sends next to nothing most cycles. A full resync happens every 6
  hours regardless, so nothing silently drifts.
* **Alerts are sent only past a cursor** (the ones you have not already received) — inherently a
  small number, however many devices a customer has.
* **Findings and compliance are never sent at all.** Once a customer's register is mirrored, your
  master computes those itself the same way it already does for your own local devices — sending
  them separately would just be redundant traffic.
* The default cycle is **60 seconds**, deliberately not as frequent as the console's own on-screen
  refresh (that never leaves the browser-to-local-master link anyway). Change it with
  `--report-to-interval` if you want it less frequent still.
* **`--report-to` must be `https://`.** A plain `http://` address is refused unless it is this machine or you also give
  `--report-to-allow-plain-http` (for a VPN or tunnel you trust); `--report-to-ca` trusts your MSP's own certificate
  authority. A refused address is logged and the relay stays off; the customer's DENIS still starts normally.
* **Each customer machine is a site of its own on your master.** A customer master that relays several of its own
  agents appears as one sub-site per agent (at most 256 per customer). Access restrictions you set on the customer's
  site are copied onto its sub-sites and are only ever tightened, never widened and never deleted by a later sync. Devices
  the customer sent before 4.0.2 are adopted into the new sub-site, not counted twice. See
  [Security](security.md#what-a-master-accepts-from-an-agent) for what your master accepts from a relay.
* This does **not** replace `--backup-upstream` above — run both if you want live visibility *and*
  a backup copy; they are independent and one does not require the other.

## MSP: remote management of a customer's own master

The relay above only mirrors. With [MSP management](msp-management.md) (experimental), your technicians can also
**open the customer's console from yours and work in it**, at the level the customer allows. A summary of what you have to
provide; the page linked has the steps and the limits.

* **On your master**: `--ingest-listen` reachable by customers over HTTPS (they dial out to it, nothing listens at the
  customer), `--public-url` for your own console, and one operator per technician with a second factor (an authenticator
  app, or a passkey with `--public-url`).
* **A portal domain**, separate from your console's, for the customers' consoles: one address per customer
  (`acme.portal.example`). Needed: a **wildcard certificate** for `*.portal.example` that the listener (or the reverse proxy
  in front of it) presents, a **wildcard DNS record** for it, and `denis msp portal --domain portal.example` (or the operator
  page). DENIS does not request certificates. With a reverse proxy, forward the original `Host` header. With DENIS's own
  listener, use `--tls-cert`/`--tls-key` (or the console's upload) with a certificate whose names include your console's
  address and `*.portal.example`; the generated local CA vouches only for the console's own names. Serving customers
  on your console's own domain is possible after an explicit acknowledgement and is less safe: see the page.
* **On the customer's master**: nothing but a version with 4.1, an outbound HTTPS connection to your ingest address and an
  administrator who pairs it (Settings, MSP management, or `denis msp-link connect`). `--no-msp-management` switches
  the feature off for a process. A customer behind a private CA gives its master the CA with `--report-to-ca`.
* **High availability**: only the active node of a pair connects (customer side) or serves the channel (MSP side).

```bash
denis msp portal --domain portal.example
denis msp customer add acme --name "Acme" --host acme.portal.example --url https://msp.example:8081
denis operator grant alex default editor && denis msp customer grant alex acme editor
```

## One or more mirror-port interfaces for whole-network flow visibility

`--flows` only sees traffic that crosses the interface DENIS listens on (see
[Concepts](concepts.md#visibility-what-can-be-seen-from-where)). Normally that means a separate
`denis` instance on the router itself, or on a mirror/SPAN port. `--mirror-iface` lets one
instance do that too, on one machine, alongside its usual discovery:

```bash
denis run --iface eth0 --mirror-iface eth1
```

* `--iface` (`eth0` above) is unchanged from today: ARP sweeps, port scans, everything discovery
  does. There is always exactly one of these — it is where "the subnet" comes from.
* `--mirror-iface` (`eth1` above) is capture-only — never probed, never used for discovery, never
  needs an IPv4 address of its own (a mirror/SPAN destination port usually has none; `denis
  interfaces` lists it separately for that reason). It is decoded into the same flow accounting as
  `--iface`, correlated to already-known devices by MAC address; traffic from a device DENIS has
  not discovered yet is dropped until discovery (on `--iface`) finds it. Implies `--flows`.
* **Repeatable**: pass `--mirror-iface` more than once for more than one mirror interface — one
  per VLAN, say, each on its own switch mirror/SPAN port fed into its own NIC on the same server.
  All of them feed the same flow accounting and the same device register; no separate agent
  process is needed just to see several VLANs from one box. (What this does **not** do is run
  independent discovery per VLAN — that still needs `denis agent`, one per network, if each VLAN
  needs its own ARP sweep and subnet of known devices.)
* **`--mirror-subnet <CIDR>`** (repeatable) tells DENIS about a subnet it cannot see on its own. A
  mirror on the *same* subnet/VLAN as `--iface` needs nothing extra — that range is already known.
  But a mirror carrying a **different** VLAN (the common reason to add one) usually has no IPv4
  address of its own to auto-detect its range from, and without being told, DENIS cannot tell that
  VLAN's traffic apart from "random internet noise": neither device-to-device traffic on it nor its
  traffic to the internet is recognised as belonging to a local device, so flow accounting and
  industrial-protocol decoding produce nothing for it — silently, no error. If a mirror interface
  *does* have its own address, its subnet is added automatically; `--mirror-subnet` is only needed
  when it does not. DENIS logs a warning at start-up when a mirror interface has neither.

```bash
denis run --iface eth0 --mirror-iface eth1 --mirror-subnet 10.20.0.0/24
```

Typical wiring: the switch's uplink to the router/firewall is mirrored to a spare switch port, fed
into a second NIC (or a USB-Ethernet adapter) on the same server that already runs DENIS.

**DENIS does not stop for a network card.** A mirror port without link while the switch boots, an
unplugged USB adapter, a typo in `--mirror-iface` or a missing capture permission (`CAP_NET_RAW`)
never keeps DENIS from starting: the console, the database, alerts and every other interface keep
working, and DENIS retries the interface on its own (every few seconds, a little longer when it
keeps failing; every five minutes for a missing permission). Each interface has its own state on
the Health page: *capturing*, *no traffic* (a quiet mirror is not broken), *no link*, *missing*,
*capture error* or *switched off*, with its counters, last packet and last error, and a **Re-check**
button. When the main interface is not ready, network sweeps and port scans wait for it, and so does
the "device went silent" check (an unplugged mirror does not pause it). A capture thread that waits
because the database side is behind is not reported as broken. The capture totals on the Health page
(and `denis_capture_dropped_packets`) count since start, including interfaces removed meanwhile. One
notification is sent when an interface has not worked for its grace period (60 seconds for the main
interface, 120 seconds for a mirror, set from 30 seconds to 60 minutes under Settings → Capture) and
one when it works again.

**Settings → Capture → Network interface** picks the discovery interface (applied after a restart). It
cannot be one of the mirror interfaces, and DENIS never picks a mirror interface itself when it chooses
the main interface automatically. Saving it never changes the mirror interfaces.
Under **Capture interfaces** an administrator adds, switches off, switches on and removes mirror
interfaces; this applies at once, without a restart, and the own subnet of a mirror that has an address
follows at once. The first change there saves the list, and from
then on the saved list replaces `--mirror-iface` (an interface removed there does not come back from
the service's start command). The main interface cannot be removed there. An interface whose capture
did not stop when it was removed cannot be added again until that capture has ended.

**Settings → Capture → Monitored networks** lists every subnet DENIS treats as your own: the
interfaces' own subnets (cannot be removed), the `--mirror-subnet` values ("command line") and the
ones added there. Adding or removing one needs the administrator password, applies at once and is
audited. A `--mirror-subnet` value removed there stays off although the start command still names it,
and can be switched back on (also a command-line value that would not be accepted if typed there). A
monitored network is never swept (sweeps, pings and port scans reach only hosts inside the main
interface's own subnet, and for IPv6 its own prefixes; a single known device scanned again on request is the
exception, as its network's probing switches allow), never widens what an enforcement action may touch,
and is never learned from traffic: the "seen but not monitored" lines are hints only. Ranges that only
stand for other addresses (IPv4-mapped, NAT64, discard-only, site-local IPv6) and IPv4 ranges covering
169.254.0.0/16 are refused. Under Advanced, an IPv4 network can be assigned to the capture interface
that sees it; address claims for it seen on another interface are then not accepted. A network that is,
or covers, the own subnet of another capture interface cannot be assigned (that interface would no
longer accept claims from its own network).

**Do I need a second cable on every segment behind a router?** No for passive visibility: a mirror of
a VLAN or segment (and that segment's subnet under Monitored networks) is enough to see its devices
and traffic. Active discovery (ARP sweeps, port scans) only runs on the main interface's own subnet,
so a routed segment is seen only through its mirror; scanning it actively needs an interface (or an
agent) in that subnet.

A mirror delivered over the network (RSPAN VLAN, ERSPAN, AWS or Azure VXLAN) is covered in [Tunnel mirroring](tunnel-mirroring.md).

**Never mirror the same traffic to two interfaces.** The flow counts of the interfaces are added, so
overlapping mirrors count every byte twice. Health warns when two sources look identical; see
[Do not overlap your mirrors](tunnel-mirroring.md#do-not-overlap-your-mirrors). To see the VLAN of a
mirrored frame (recorded on the device as evidence, and used to annotate address conflicts across VLANs),
the capture interface must receive the 802.1Q tag in the frame: on a Linux network card that strips it,
`ethtool -K <iface> rxvlan off`.

## Alert notifications

Configure **Slack, Teams, Discord, PagerDuty, Pushover, ntfy, e-mail, Jira, ServiceNow and signed webhooks** in the console (*Settings → Notifications*, see [Alerting](alerting.md)); no restart, per-channel thresholds, a Test button. The simple command-line webhook below is the older way and still works:

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

Restore by stopping DENIS and copying the backup over the database file. Events, alerts and trend samples are
pruned after the retention period: `--retention-days` (default 90) until an administrator saves a value under
*Settings → Data → Data retention* (1 to 1095 days; the console proposes 180), which then wins. The register,
baselines, accepted risks, saved reports and the audit log are never pruned by retention. The **decision log** (who
acknowledged, resolved or re-opened which alert or incident, when and why) has its own period under the same heading:
1095 days (3 years) unless an administrator changes it (90 to 3650 days, or 0 to keep it for ever). It outlives the
alerts and incidents it is about, and only its own age prunes it: deleting or merging a device and *Erase all data*
leave it in place, because it holds no personal data beyond the user names and the notes people typed.

The database contains your network inventory and password hashes: protect it like the service itself
(owner-only permissions).

## Upgrading

Stop DENIS, replace the binary, start it. The database migrates itself on start (**one-way**: older builds refuse
a newer database): back it up first.

## Resource use

Sized for one /24 up to ~1000 hosts per collector. Flow accounting captures every IPv4 frame on the interface;
on a busy gigabit link use a fast machine or a dedicated capture interface. How many devices and console users one database carries is in [Operations](operations.md#how-big-can-one-installation-be).

## PostgreSQL and a second node (optional)

By default DENIS keeps everything in one SQLite file. `--database-url postgres://user@host/denis` (the password only in
`DENIS_DATABASE_PASSWORD`, never in the URL or on the command line) uses PostgreSQL instead, and lets two DENIS
nodes share that database with one of them as leader and the other on standby. It needs a DENIS built with the
`postgres` feature: a build without it refuses the option. A ready-made PostgreSQL build is attached to every release (from 4.2.1, `denis-pg-<arch>-unknown-linux-musl`; `install.sh --postgres` installs it). A SQLite install is never a pair.

* Only the leader captures, detects and serves the console and agent port; the standby answers `/api/health` with `503`
  and `role: standby` until it wins leadership. Point agents and browsers at one virtual address that routes to the
  node whose health check says leader.
* Both nodes must have the **same `secrets.key`**, always: copy it to the second node before its first start. A node
  whose key differs refuses to start when it becomes leader, and the other node's Health page names it
  ([High availability](high-availability.md#what-both-nodes-must-share)). Give both the same certificate, ideally your own (`--tls-cert`), because
  each node otherwise makes its own authority.
* Backups made while a node was leader exist only on that node's disk: use `--backup-upstream`.
* Every PostgreSQL connection carries keepalive, connect, statement, lock-wait and idle-in-transaction limits, and the
  leader proves its leadership once a second, so a database link that fails silently ends the old leader's side effects
  within about three seconds and the process within about ten. The defaults and the `DENIS_PG_*` variables that change them
  are in [High availability](high-availability.md#postgresql-connection-settings). Delivery of notifications and exports across a failover is **at least once**: after a
  failover a message can arrive twice; the design does not promise exactly once.
* **Known limit (until 4.1.4):** only side effects are tied to the leader's lease. Database writes carry no leader epoch,
  so in the few seconds after a failover the old leader can still write a row the new one also writes.
* **Not together with tenants.** An install with tenants besides `default` refuses to start with `--database-url`:
  tenants keep their data in SQLite files on one node.
* Speed is not a reason to choose it: for one site SQLite is faster ([Operations](operations.md#how-big-can-one-installation-be)).

The full guide, with a load-balancer example and a failover test, is [High availability](high-availability.md). It has
been tried with PostgreSQL 16 in a test container, not on managed or clustered PostgreSQL in production.

## Command reference

`denis run --help` and `denis agent --help` print the same flags with their full explanation. Other commands:

| Command | Purpose |
|---|---|
| `denis interfaces` | list usable interfaces (`*` = default) |
| `denis list` / `denis alerts` | inventory / alerts as a table, straight from the database (`alerts --all` also shows info-level events) |
| `denis report --days 7 -o report.html` | printable report (`--format assets-csv|alerts-csv`) |
| `denis user …`, `denis agent-token …` | access management (see above) |
| `denis backup FILE` | verified copy of the database, while running |
| `denis replay FILE.pcap` | run a packet capture through the decoders and rules and print what was found (nothing is stored) |
| `denis serve` | console over a database, no capture (backups, demos) |
| `denis demo load\|remove` | built-in demo data (a fictional company) |
| `denis erase --yes` | empty the database of devices and history (DENIS stopped; take a backup first) |
| `denis tenant …`, `denis operator …` | tenants and MSP operator accounts, see [Multi-tenancy](multi-tenancy.md) |
| `denis msp …`, `denis msp-link …` | experimental: an MSP's remote customers and key, a customer's link to its MSP; see [MSP management](msp-management.md) |

### Flags of `denis run` and `denis agent`

The **Both** column says whether `denis agent` takes the flag too. Where a setting can also be changed in the console,
the flag only sets the starting value. Flags marked *env* can be given as an environment variable instead (so a secret
stays out of the process list).

| Flag | Both | Default | What it does |
|---|---|---|---|
| `-i`, `--iface` | yes | the default-route interface | interface to monitor |
| `--mirror-iface` | yes | none | capture-only interface (switch mirror/SPAN port); repeatable; implies `--flows` |
| `--mirror-subnet` | yes | none | extra subnet to treat as local for a mirror port; repeatable |
| `--sweep-interval` | yes | 300 | seconds between ARP sweeps |
| `--rescan-interval` | yes | 1800 | minimum seconds between port scans of one host |
| `--passive-only` | yes | off | never transmit ARP, ICMP, TCP probes (nor the IPv6 discovery below) |
| `--flows` | yes | off | account traffic to and from outside the subnet and decode industrial protocols |
| `--profile it\|ot` | yes | `it` | `ot` listens only and turns on traffic analysis; see the [OT guide](ot-guide.md) |
| `--active` | yes | off | with `--profile ot`, allow a gentle, slow ARP sweep |
| `--exclude` | yes | none | never probe this range (repeatable); still observed passively |
| `--no-extended-banners` | yes | off | do not read Telnet, MySQL/MariaDB, SMB and MSSQL banners |
| `--no-port-scan` | yes | off | do not port-scan (and so no banner reads); console setting overrides on `run` ([Security tools](security-tools.md#port-scan-and-ping-switches)) |
| `--no-ping` | yes | off | do not ping the hosts that answered the ARP sweep; console setting overrides on `run` |
| `--ipv6` | yes | off | IPv6 Neighbor Discovery, mDNS, SSDP and DHCPv6 identity, and active IPv6 discovery; see [Concepts](concepts.md#ipv6-optional) |
| `--ipv6-subnet` | yes | none | IPv6 prefix to treat as local (repeatable); needed for IPv6 flows and industrial decoding |
| `--east-west` | yes | off | record traffic between two local devices as relationship edges (console setting overrides on `run`) |
| `--passive-dns` | yes | off | remember the names each device looked up (console setting overrides on `run`) |
| `--ot-sv` | yes | off | decode IEC 61850 Sampled Values, sampled to one frame per stream per second (console setting overrides on `run`, after a restart) |
| `-l`, `--listen` | run | `127.0.0.1:8080` | web console address (*env* `DENIS_LISTEN`) |
| `--db` | yes | `denis.db` / `denis-agent.db` | database file |
| `--data-dir` | run | the database's folder | backups, uploaded agent backups, GeoIP database (*env* `DENIS_DATA_DIR`) |
| `--database-url` | run | none (SQLite) | PostgreSQL URL; the password only through `DENIS_DATABASE_PASSWORD`; needs a build with PostgreSQL (*env* `DENIS_DATABASE_URL`) |
| `--ingest-listen` | run | off | accept remote agents on this address |
| `--insecure-no-auth` | run | off | no sign-in; development only, refused unless the console is on loopback |
| `--public-url` | run | none | the address people type; passkeys are bound to it (*env* `DENIS_PUBLIC_URL`) |
| `--allowed-host` | run | none | public host name a local reverse proxy forwards (repeatable) (*env* `DENIS_ALLOWED_HOSTS`) |
| `--no-tls` | run | off | plain HTTP, for a TLS-terminating proxy or an SSH tunnel (*env* `DENIS_NO_TLS`) |
| `--tls-name`, `--tls-dir`, `--tls-cert`, `--tls-key` | run | | names in the generated certificate, its folder, or your own certificate and key (*env* `DENIS_TLS_*`) |
| `--secure-cookies` | run | off | mark the session cookie `Secure` behind a TLS proxy |
| `--learning-minutes` | run | 1440 | how long a device or site is observed before new things count as anomalies |
| `--min-score` | run | 30 | scores below this are logged as info, not raised |
| `--rule-weight RULE=WEIGHT` | run | none | scale a rule's score (0 disables); repeatable |
| `--bucket-secs`, `--min-volume-mb`, `--min-samples` | run | 300, 5, 12 | volume rule: bucket length, smallest bucket considered, buckets needed before a baseline is trusted |
| `--hours-learning-days` | run | 7 | unusual-hours rule: days observed before a daily pattern is judged |
| `--silent-minutes` | run | 120 | silent-device rule; needs active sweeps |
| `--retention-days` | run | 90 | delete trend samples older than this |
| `--threat-list` | run | none | text file of known-bad IPv4 addresses and networks; needs `--flows` (*env* `DENIS_THREAT_LIST`) |
| `--webhook`, `--webhook-min-score` | run | none, 60 | post alerts as JSON (*env* `DENIS_WEBHOOK`) |
| `--syslog` | run | none | send alerts as syslog/CEF; only seeds the console setting (*env* `DENIS_SYSLOG`) |
| `--openobserve-url`, `-org`, `-prefix`, `-interval` | run | none, `default`, `denis`, 15 | export to OpenObserve; credentials from `DENIS_OPENOBSERVE_USER` and `DENIS_OPENOBSERVE_PASSWORD` |
| `--license-file` | run | none | signed commercial license (*env* `DENIS_LICENSE_FILE`) |
| `--no-update-check` | run | off | never contact GitHub for a new version (*env* `DENIS_NO_UPDATE_CHECK`) |
| `--update-channel stable\|prerelease` | run | `stable` | also offer pre-release versions (beta / release candidates) to testers; a choice saved in Settings wins (*env* `DENIS_UPDATE_CHANNEL`); see [Updates](updates.md#pre-release-versions-for-testers) |
| `--auto-security-updates on\|off` | run | none | install security updates (stable releases of the running minor line) automatically; used while no administrator has chosen in the console, a choice saved there wins (*env* `DENIS_AUTO_SECURITY_UPDATES`); without it a new installation starts with them on and an existing one is asked; see [Updates](updates.md#automatic-security-updates) |
| `--update-repo` | run | the project's | `owner/repo` whose releases DENIS updates from (*env* `DENIS_UPDATE_REPO`) |
| `--update-mirror` | run | `https://usedenis.com` | the fallback host tried only when GitHub cannot be reached; an empty value removes the fallback (*env* `DENIS_UPDATE_MIRROR`); see [Updates](updates.md#if-github-cannot-be-reached) |
| `--backup-upstream`, `--backup-upstream-token-env` | run | none, `DENIS_BACKUP_TOKEN` | push this install's backups to an MSP; see above |
| `--report-to`, `--report-to-token-env`, `--report-to-interval`, `--report-to-ca`, `--report-to-allow-plain-http` | run | none, `DENIS_REPORT_TOKEN`, 60, none, off | relay devices and alerts to an MSP; see above. A refused address is logged and the relay skipped |
| `--no-msp-management` | run | off (`DENIS_NO_MSP_MANAGEMENT`) | experimental: no remote management by an MSP in this process, whatever the console says; see [MSP management](msp-management.md) |
| `--master`, `--token`, `--master-ca`, `--master-ca-pem`, `--allow-plain-http`, `--id`, `--name`, `--site`, `--report-interval` | agent | `--report-interval` 15 | where and how an agent reports; see [Multiple sites](#multiple-sites-agents). `--token` can come from `DENIS_AGENT_TOKEN` |
| `--no-self-update` | agent | off | never take an update from the master's command; the agent still reports its version (*env* `DENIS_AGENT_NO_SELF_UPDATE`); see [Updating remote agents](updates.md#updating-remote-agents) |

One more flag is hidden from `--help`: `--ot-l2=false` stops decoding layer-2 industrial protocols (GOOSE, PROFINET
DCP Set). It is on by default and only exists as an escape hatch.

## Details from the console

Explanations that used to be printed on the console screens. The console shows a short version behind the small (i) button after the label it explains; "More in the docs" in it leads here.

* One row per site — the local network and every remote agent you can see. Click a row to open its devices.
* For more than a couple of agents, this is usually simpler than copying the CA file to every machine: paste it as one value, e.g. DENIS_MASTER_CA_PEM, wherever you already push each agent's token.
* Lets other DENIS agents on other networks report to this instance over the internet or a VPN. Leave blank for a standalone install (the normal case). Saved with the Save button above.
* With (auto), DENIS picks the interface on its own: the one that holds the default route. Choose one yourself only when DENIS is watching the wrong network.
