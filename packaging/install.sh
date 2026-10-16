#!/usr/bin/env bash
# DENIS installer for Linux: systemd (Ubuntu, Debian, Raspberry Pi OS, RHEL-family, ...) or OpenRC (Alpine).
#
#   curl -fLO https://github.com/stefanmesaros/denis/releases/latest/download/install.sh
#   less install.sh                      # read it first: it runs as root
#   sudo bash install.sh
#
# On Alpine first:  apk add bash curl openssl   (then run it as root:  bash install.sh)
#
# What it does, in order:
#   1. finds the newest release (or the one you name with --version),
#   2. downloads the program for this machine (x86-64 or ARM64) and SHA256SUMS + SHA256SUMS.sig. Debian and
#      Ubuntu get the usual build (it uses the system's libpcap); Alpine and every other Linux get the static
#      build (*-unknown-linux-musl, libpcap built in, nothing else to install; release 4.1.1 or newer),
#   3. checks the Ed25519 signature on SHA256SUMS against the project's release key (built in below) and
#      the program's SHA-256 against that signed list. Anything wrong: it stops before changing anything,
#   4. installs the libpcap runtime library if the program needs it and it is missing,
#   5. installs the program at /usr/local/lib/denis/denis (owned by the "denis" service user, so the
#      console's own Settings -> Updates can update it later without root), a convenience symlink at
#      /usr/local/bin/denis, the "denis" service user, the service (a systemd unit, or /etc/init.d/denis
#      on OpenRC) and /etc/denis/env,
#   6. picks a free port for the web console (8443, or the next free one; --port to choose),
#   7. starts the service and tells you the address and the one-time administrator password.
#
# With neither systemd nor OpenRC (or with --no-service) it stops after step 5 without a service: the
# program, the user, /etc/denis/env and the data folder are in place, and it prints how to start it.
#
# A remote agent (a second site or network segment that reports to a master) installs the same way, from
# the same signed files, with --agent. Issue the token on the master first (console: Sites -> Add agent, which
# also shows this exact command; or:  denis agent-token issue --id ID):
#
#   sudo bash install.sh --agent --master https://MASTER:8081 --id branch-1 \
#        --name "Branch office" --site Branch --flows --master-ca-pem ca.pem
#
# It asks for the token (dat_...) at the terminal, so the token is never on a command line.
#
# It then writes /etc/denis/agent.env (mode 600: the token is in it) and the denis-agent service, puts the CA
# at /etc/denis/ca.pem and starts it. Agent mode needs release 4.1.0 or newer. It refuses to run on a machine
# that already runs the master (service "denis"), because one machine should not watch the same network twice;
# --allow-master-here overrides that. No port is opened: the agent only connects out to the master.
#
# Run it again to update (your data in /var/lib/denis is backed up first and never touched) or with
# --uninstall to remove the program. Nothing else on the machine is changed: no firewall rules, no other
# services, nothing takes over a port that is already in use.
#
# Options:
#   --version vX.Y.Z    install that release instead of the newest
#   --port N            web console port (default: first free from 8443, or from 8080 with --local-only)
#   --local-only        listen on 127.0.0.1 only (reach it with an SSH tunnel); default is every address
#   --name NAME         extra name or address the console's certificate must cover (repeatable)
#   --dry-run           download and verify, change nothing (needs no root)
#   --no-service        install the program, user, settings and data folder only; no service is set up or
#                       started (for systems without systemd or OpenRC, or to run it under your own supervisor)
#   --static            take the static build (*-unknown-linux-musl) even on Debian or Ubuntu
#   --no-signature-check  verify the SHA-256 only (for systems whose openssl cannot check Ed25519)
#   --uninstall         stop and remove the program and service, keep the data
#   --purge             with --uninstall: also delete the data (/var/lib/denis), /etc/denis and the user
#   --agent             install a remote agent instead of the master (the options below belong to it)
#   --master URL        the master's agent address, e.g. https://192.168.1.10:8081 (its "ingest" listener)
#   --token TOKEN       the agent's token (dat_...), from Sites -> Add agent or "denis agent-token issue".
#                       Without it the installer asks for it at the terminal (not shown, not in ps or the
#                       shell history); DENIS_AGENT_TOKEN in the environment or --token-file FILE work too.
#   --token-file FILE   read the token from the first line of FILE
#   --id ID             this agent's id: letters, digits . _ - (up to 64)
#   --name NAME         display name (default: the id)
#   --site SITE         site or location label
#   --flows             also account traffic to/from outside the subnet (needs the agent to see it: gateway or mirror port)
#   --master-ca-pem F   the master's CA certificate, as a file, or "-" to read it from standard input
#                       (Settings -> HTTPS certificate -> Copy for --master-ca-pem). Needed when the master
#                       uses the certificate DENIS made itself; not for a publicly trusted one.
#   --allow-master-here install the agent even though this machine also runs the master
#   -h, --help          this text
# --- end of help ---
[ -n "${BASH_VERSION:-}" ] || { echo "error: run this with bash (on Alpine first: apk add bash curl openssl)" >&2; exit 1; }
set -euo pipefail

REPO="stefanmesaros/denis"
# The Ed25519 public key release files are signed with (the same key is built into the program).
RELEASE_PUBLIC_KEY_HEX="abe75462c8adfb1d4c5aa39d25e44377d00c77442f423c2f01cd51fec40e938e"
MIN_VERSION="0.1.3"          # the first release this installer's service layout fits
LIBDIR=/usr/local/lib/denis  # owned by the service user, so it can update itself here (see below)
BIN="$LIBDIR/denis"
LINK=/usr/local/bin/denis    # a symlink to $BIN, for convenience (denis backup, denis user reset, ...)
UNIT=/etc/systemd/system/denis.service
ENVFILE=/etc/denis/env
DATA=/var/lib/denis
SERVICE_USER=denis

# Remote-agent mode (--agent). Same program, same user, same signed download as the master install.
AGENT_UNIT=/etc/systemd/system/denis-agent.service
AGENT_ENVFILE=/etc/denis/agent.env
AGENT_CA=/etc/denis/ca.pem
AGENT_DATA=/var/lib/denis-agent
AGENT_MIN_VERSION="4.1.0"   # the first release whose agent reads its settings from the environment file
ROOT=""                     # a prefix for the agent's own files; only the tests (tools/install-agent-test.sh) set it

# OpenRC (Alpine): init scripts instead of systemd units, logs in files
OPENRC_INIT=/etc/init.d/denis
OPENRC_AGENT_INIT=/etc/init.d/denis-agent
LOGDIR=/var/log/denis
STATIC_MIN_VERSION="4.1.1"  # the first release with the static builds (denis-*-unknown-linux-musl)
INIT=systemd                # systemd, openrc or none; decided by detect_init below (the tests keep systemd)

VERSION="" PORT="" LOCAL_ONLY=0 DRY=0 NOSIG=0 UNINSTALL=0 PURGE=0 NOSERVICE=0 STATIC=0
AGENT=0 MASTER_URL="" AGENT_TOKEN="" AGENT_ID="" AGENT_NAME="" AGENT_SITE="" AGENT_FLOWS=0 CA_SRC="" ALLOW_MASTER=0
CA_PEM="" ALLOW_HTTP=0 AGENT_KEEP_ENV=0 TOKEN_FILE="" TOKEN_PROMPT=1
NAMES=()

say()  { printf '\033[1m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }
usage() { sed -n '2,/^# --- end of help ---$/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0; }

# ------------------------------------------------------------------------------ remote agent helpers
# (kept as functions so tools/install-agent-test.sh can source this file and exercise them without root)

agent_unit() {  # the service file; identical to packaging/denis-agent.service below its header (the tests check)
# --- agent unit begin ---
cat <<'AGENT_UNIT_EOF'
[Unit]
Description=denis remote agent
After=network-online.target
Wants=network-online.target
# a start that keeps failing (a wrong token or address) is not retried forever
StartLimitIntervalSec=120
StartLimitBurst=5

[Service]
User=denis
# DENIS_MASTER, DENIS_AGENT_TOKEN, DENIS_AGENT_ID, DENIS_AGENT_NAME, DENIS_AGENT_SITE, DENIS_FLOWS and
# DENIS_MASTER_CA come from here: nothing to edit in this file.
EnvironmentFile=/etc/denis/agent.env
ExecStart=/usr/local/lib/denis/denis agent --db /var/lib/denis-agent/agent.db
Restart=on-failure
RestartSec=5
# Readable/writable by no one else (SECURITY_ARCHITECTURE_REVIEW.md M10).
StateDirectory=denis-agent
StateDirectoryMode=0700
UMask=0077

AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=true
ProtectSystem=strict
# owned by the service user: the one exception, so an update commanded by the master can replace the program
ReadWritePaths=/usr/local/lib/denis
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_PACKET AF_UNIX AF_NETLINK

[Install]
WantedBy=multi-user.target
AGENT_UNIT_EOF
# --- agent unit end ---
}

openrc_script() {  # /etc/init.d/denis; identical to packaging/denis.openrc (the tests check)
# --- openrc begin ---
cat <<'OPENRC_EOF'
#!/sbin/openrc-run
# The DENIS service for OpenRC (Alpine Linux). packaging/install.sh writes it to /etc/init.d/denis.
# Settings: /etc/denis/env (DENIS_LISTEN=..., any `denis run` option's environment name).
# After editing:  rc-service denis restart      Logs: /var/log/denis/denis.log
description="denis network asset discovery"
command=/usr/local/lib/denis/denis
command_args="run --db /var/lib/denis/denis.db"
command_user="denis:denis"
supervisor=supervise-daemon
# a start that keeps failing (for instance a taken port) is not retried forever
respawn_delay=5
respawn_max=5
respawn_period=120
output_log=/var/log/denis/denis.log
error_log=/var/log/denis/denis.log
# the database holds TOTP secrets and integration credentials: readable by the service user only
umask=077
# Only what capture/injection needs, as ambient capabilities of the service user (no capability on
# the file, so the console's own Settings -> Updates can still replace the program). install.sh
# removes this line on an OpenRC too old for it and gives the file the capabilities instead.
capabilities="^cap_net_raw,^cap_net_admin"

depend() {
	need net
	after firewall
}

# KEY=value lines, read the way systemd reads an EnvironmentFile: no shell code in the file runs as root
denis_env() {
	[ -r "$1" ] || return 0
	while IFS= read -r line || [ -n "$line" ]; do
		case "$line" in DENIS_*=*) ;; *) continue ;; esac
		key=${line%%=*}
		val=${line#*=}
		case "$key" in *[!A-Za-z0-9_]*) continue ;; esac
		case "$val" in \"*\") val=${val#\"}; val=${val%\"} ;; esac
		export "$key=$val"
	done < "$1"
}

start_pre() {
	checkpath -d -o denis:denis -m 0700 /var/lib/denis
	checkpath -d -o denis:denis -m 0750 /var/log/denis
	export DENIS_LISTEN=127.0.0.1:8080
	denis_env /etc/denis/env
}
OPENRC_EOF
# --- openrc end ---
}

openrc_agent_script() {  # /etc/init.d/denis-agent; identical to packaging/denis-agent.openrc (the tests check)
# --- openrc agent begin ---
cat <<'OPENRC_AGENT_EOF'
#!/sbin/openrc-run
# The DENIS remote agent for OpenRC (Alpine Linux). packaging/install.sh --agent writes it to /etc/init.d/denis-agent.
# DENIS_MASTER, DENIS_AGENT_TOKEN, DENIS_AGENT_ID, ... come from /etc/denis/agent.env: nothing to edit here.
# After editing that file:  rc-service denis-agent restart      Logs: /var/log/denis/denis-agent.log
description="denis remote agent"
command=/usr/local/lib/denis/denis
command_args="agent --db /var/lib/denis-agent/agent.db"
command_user="denis:denis"
supervisor=supervise-daemon
# a start that keeps failing (a wrong token or address) is not retried forever
respawn_delay=5
respawn_max=5
respawn_period=120
output_log=/var/log/denis/denis-agent.log
error_log=/var/log/denis/denis-agent.log
umask=077
# see /etc/init.d/denis: ambient capabilities, so an update commanded by the master can replace the program
capabilities="^cap_net_raw,^cap_net_admin"

depend() {
	need net
	after firewall
}

# KEY=value lines, read the way systemd reads an EnvironmentFile: no shell code in the file runs as root
denis_env() {
	[ -r "$1" ] || return 0
	while IFS= read -r line || [ -n "$line" ]; do
		case "$line" in DENIS_*=*) ;; *) continue ;; esac
		key=${line%%=*}
		val=${line#*=}
		case "$key" in *[!A-Za-z0-9_]*) continue ;; esac
		case "$val" in \"*\") val=${val#\"}; val=${val%\"} ;; esac
		export "$key=$val"
	done < "$1"
}

start_pre() {
	checkpath -d -o denis:denis -m 0700 /var/lib/denis-agent
	checkpath -d -o denis:denis -m 0750 /var/log/denis
	denis_env /etc/denis/agent.env
}
OPENRC_AGENT_EOF
# --- openrc agent end ---
}

# ------------------------------------------------------------------------------ which system, which program

detect_init() {  # sets INIT: systemd, openrc or none
  if command -v systemctl >/dev/null && [ -d /run/systemd/system ]; then INIT=systemd
  elif command -v openrc-run >/dev/null || command -v rc-service >/dev/null || [ -x /sbin/openrc ]; then INIT=openrc
  else INIT=none; fi
}

is_musl_system() {  # Alpine, or another Linux built on the musl C library
  [ -f /etc/alpine-release ] && return 0
  local out
  out=$(ldd --version 2>&1 || true)   # (captured first: musl's ldd exits 1, and pipefail would hide the match)
  case "$out" in *musl*|*MUSL*|*Musl*) return 0 ;; esac
  return 1
}

has_pcap08() {  # Debian's libpcap SONAME, the one the glibc build is linked against
  local out
  out=$(ldconfig -p 2>/dev/null || true)
  case "$out" in *libpcap.so.0.8*) return 0 ;; esac
  return 1
}

ver_lt() {  # is version $1 older than $2? (numbers only: 4.1.1-rc.1 counts as 4.1.1; no sort -V needed)
  local a b i x y
  a="${1#v}"; a="${a%%-*}"; b="${2#v}"; b="${b%%-*}"
  IFS=. read -r -a x <<< "$a"; IFS=. read -r -a y <<< "$b"
  for i in 0 1 2; do
    [ "$((10#${x[i]:-0}))" -lt "$((10#${y[i]:-0}))" ] && return 0
    [ "$((10#${x[i]:-0}))" -gt "$((10#${y[i]:-0}))" ] && return 1
  done
  return 1
}

choose_libc() {  # sets LIBC (gnu or musl) and LIBC_WHY; $1 = the release, for the fallback of older ones
  LIBC=gnu LIBC_WHY=""
  if [ "$STATIC" = 1 ]; then LIBC=musl LIBC_WHY="--static was given"
  elif is_musl_system; then LIBC=musl LIBC_WHY="this system uses the musl C library (Alpine)"
  elif ! has_pcap08 && ! command -v apt-get >/dev/null; then LIBC=musl LIBC_WHY="no Debian-style libpcap here"
  fi
  if [ "$LIBC" = musl ] && ver_lt "$1" "$STATIC_MIN_VERSION"; then
    case "$LIBC_WHY" in
      "no Debian-style libpcap here")
        warn "$1 has no static build (the first is v$STATIC_MIN_VERSION): taking the usual one, which needs libpcap.so.0.8"
        LIBC=gnu LIBC_WHY="" ;;
      *) die "$1 has no static build, which this system needs ($LIBC_WHY): the first is v$STATIC_MIN_VERSION. Leave out --version, or name a newer one." ;;
    esac
  fi
}

restart_hint() {  # how to restart service $1 after editing its settings
  case "$INIT" in
    systemd) echo "sudo systemctl restart $1" ;;
    openrc) echo "rc-service $1 restart" ;;
    *) echo "restart the program" ;;
  esac
}

master_present() {  # is this machine already running the master (service "denis")?
  [ -f "$ROOT$UNIT" ] && return 0
  [ -f "$ROOT$OPENRC_INIT" ] && return 0
  [ -z "$ROOT" ] && command -v systemctl >/dev/null && systemctl list-unit-files denis.service 2>/dev/null | grep -q '^denis\.service' && return 0
  return 1
}

agent_read_token() {  # the token without putting it on a command line, where other users see it in ps (review D-8):
  # from --token-file, from DENIS_AGENT_TOKEN in the environment, or typed at the terminal (not echoed)
  if [ -z "$AGENT_TOKEN" ] && [ -n "$TOKEN_FILE" ]; then
    [ -r "$TOKEN_FILE" ] || die "--token-file $TOKEN_FILE cannot be read"
    IFS= read -r AGENT_TOKEN < "$TOKEN_FILE" || true
    AGENT_TOKEN="${AGENT_TOKEN%$'\r'}"
  fi
  if [ -z "$AGENT_TOKEN" ] && [ -n "${DENIS_AGENT_TOKEN:-}" ]; then AGENT_TOKEN="$DENIS_AGENT_TOKEN"; fi
  # standard input may carry the CA (--master-ca-pem -), so the question goes to the terminal itself
  if [ -z "$AGENT_TOKEN" ] && [ -n "$MASTER_URL" ] && [ "$TOKEN_PROMPT" = 1 ] && { : < /dev/tty; } 2>/dev/null; then
    printf 'Paste the agent token (dat_..., it is not shown) and press Enter: ' > /dev/tty
    IFS= read -rs AGENT_TOKEN < /dev/tty || true
    printf '\n' > /dev/tty
  fi
  return 0
}

agent_check_args() {  # validate everything given on the command line (and the CA text); changes nothing
  agent_read_token
  if [ "${#NAMES[@]}" -gt 1 ]; then die "--name was given more than once"; fi
  [ "${#NAMES[@]}" -eq 1 ] && AGENT_NAME="${NAMES[0]}"
  if [ -z "$MASTER_URL" ] && [ -z "$AGENT_TOKEN" ] && [ -f "$ROOT$AGENT_ENVFILE" ]; then
    # an update: the settings already on this machine stay as they are
    if [ -n "$AGENT_ID$AGENT_NAME$AGENT_SITE$CA_SRC" ] || [ "$AGENT_FLOWS" = 1 ]; then
      die "$AGENT_ENVFILE already exists. To change the agent's settings give --master and --token again (a new token from Sites -> Add agent), or edit the file and run: $(restart_hint denis-agent)"
    fi
    AGENT_KEEP_ENV=1
    return 0
  fi
  [ -n "$MASTER_URL" ] || die "--agent needs --master URL: the master's agent address, for example https://192.168.1.10:8081 (Sites -> Add agent shows the whole command)"
  [ -n "$AGENT_TOKEN" ] || die "--agent needs the agent token (dat_...): type it when asked, or give --token-file FILE or DENIS_AGENT_TOKEN. Issue one on the master (Sites -> Add agent, or: denis agent-token issue --id ID)"
  [ -n "$AGENT_ID" ] || die "--agent needs --id: a short name for this agent, for example branch-1"
  MASTER_URL="${MASTER_URL%/}"
  printf '%s' "$MASTER_URL" | grep -Eq '^https?://[][A-Za-z0-9._:-]+$' || die "--master must look like https://host:8081 (no path, no spaces)"
  case "$MASTER_URL" in
    http://*) [ "$ALLOW_HTTP" = 1 ] || die "--master $MASTER_URL is plain http: the token and the inventory would cross the network unencrypted. Use the https:// address, or add --allow-plain-http on a network you trust (a VPN or tunnel)." ;;
  esac
  printf '%s' "$AGENT_TOKEN" | grep -Eq '^dat_[A-Za-z0-9_-]{16,}$' || die "--token is not an agent token (it starts with dat_ and has no spaces)"
  printf '%s' "$AGENT_ID" | grep -Eq '^[A-Za-z0-9._-]{1,64}$' || die "--id may use letters, digits, dot, underscore and dash only (up to 64)"
  local label v
  for label in AGENT_NAME AGENT_SITE; do
    v="${!label}"
    [ "${#v}" -le 100 ] || die "--${label#AGENT_} is longer than 100 characters"
    case "$v" in *'"'*|*'\'*) die "--$(printf '%s' "${label#AGENT_}" | tr 'A-Z' 'a-z') must not contain double quotes or backslashes" ;; esac
    case "$v" in *$'\n'*|*$'\r'*|*$'\t'*) die "--$(printf '%s' "${label#AGENT_}" | tr 'A-Z' 'a-z') has a control character in it" ;; esac
    if [ "$(printf '%s' "$v" | LC_ALL=C tr -d '[:cntrl:]')" != "$v" ]; then die "--$(printf '%s' "${label#AGENT_}" | tr 'A-Z' 'a-z') has a control character in it"; fi
  done
  if [ -n "$CA_SRC" ]; then
    if [ "$CA_SRC" = "-" ]; then CA_PEM=$(cat)
    else [ -r "$CA_SRC" ] || die "cannot read the CA file $CA_SRC"; CA_PEM=$(cat "$CA_SRC"); fi
    [ "${#CA_PEM}" -le 100000 ] || die "the CA text is far too long to be a certificate"
    case "$CA_PEM" in *"PRIVATE KEY"*) die "that is a private key, not a certificate. Use Settings -> HTTPS certificate -> Copy for --master-ca-pem on the master." ;; esac
    case "$CA_PEM" in *"-----BEGIN CERTIFICATE-----"*"-----END CERTIFICATE-----"*) ;; *) die "--master-ca-pem: no PEM certificate found (it should start with -----BEGIN CERTIFICATE-----)" ;; esac
    if command -v openssl >/dev/null && ! printf '%s\n' "$CA_PEM" | openssl x509 -noout >/dev/null 2>&1; then
      die "--master-ca-pem: openssl cannot read that certificate; copy it again from the master"
    fi
  elif [ "${MASTER_URL#https://}" != "$MASTER_URL" ]; then
    warn "no --master-ca-pem: the master's certificate must be one that this machine already trusts (a public one). A master that made its own certificate needs it: Settings -> HTTPS certificate -> Copy for --master-ca-pem."
  fi
}

write_agent_files() {  # $1 = "keep" leaves an existing agent.env alone; the service file follows $INIT
  mkdir -p "$ROOT/etc/denis"
  if [ "${1:-}" != keep ]; then
    if [ -n "$CA_PEM" ]; then
      printf '%s\n' "$CA_PEM" > "$ROOT$AGENT_CA"
      chmod 644 "$ROOT$AGENT_CA"
    fi
    if [ -f "$ROOT$AGENT_ENVFILE" ]; then
      install -m 600 "$ROOT$AGENT_ENVFILE" "$ROOT$AGENT_ENVFILE.previous"
    fi
    install -m 600 /dev/null "$ROOT$AGENT_ENVFILE"   # created private first, filled afterwards: the token is never world-readable
    {
      echo "# Settings for the DENIS remote agent. After editing:  $(restart_hint denis-agent)"
      echo "# Written by install.sh --agent. The token is a secret: keep this file readable by root only."
      echo "DENIS_MASTER=$MASTER_URL"
      echo "DENIS_AGENT_TOKEN=$AGENT_TOKEN"
      echo "DENIS_AGENT_ID=$AGENT_ID"
      [ -z "$AGENT_NAME" ] || echo "DENIS_AGENT_NAME=\"$AGENT_NAME\""
      [ -z "$AGENT_SITE" ] || echo "DENIS_AGENT_SITE=\"$AGENT_SITE\""
      [ "$AGENT_FLOWS" = 0 ] || echo "DENIS_FLOWS=true"
      [ -z "$CA_PEM" ] || echo "DENIS_MASTER_CA=$AGENT_CA"
      [ "$ALLOW_HTTP" = 0 ] || echo "DENIS_ALLOW_PLAIN_HTTP=true"
    } > "$ROOT$AGENT_ENVFILE"
  fi
  case "$INIT" in
    systemd)
      mkdir -p "$ROOT$(dirname "$AGENT_UNIT")"
      agent_unit > "$ROOT$AGENT_UNIT"
      chmod 644 "$ROOT$AGENT_UNIT" ;;
    openrc)
      mkdir -p "$ROOT$(dirname "$OPENRC_AGENT_INIT")"
      openrc_agent_script > "$ROOT$OPENRC_AGENT_INIT"
      chmod 755 "$ROOT$OPENRC_AGENT_INIT" ;;
  esac
}

# Tests source this file to reach the functions above; running it that way stops here.
if [ "${DENIS_INSTALLER_LIB:-}" = 1 ]; then return 0 2>/dev/null || exit 0; fi

while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="${2:?--version needs a value}"; shift 2 ;;
    --port) PORT="${2:?--port needs a value}"; shift 2 ;;
    --local-only) LOCAL_ONLY=1; shift ;;
    --name) NAMES+=("${2:?--name needs a value}"); shift 2 ;;
    --agent) AGENT=1; shift ;;
    --master) MASTER_URL="${2:?--master needs a value}"; shift 2 ;;
    --token) AGENT_TOKEN="${2:?--token needs a value}"; shift 2 ;;
    --token-file) TOKEN_FILE="${2:?--token-file needs a file name}"; shift 2 ;;
    --id) AGENT_ID="${2:?--id needs a value}"; shift 2 ;;
    --site) AGENT_SITE="${2:?--site needs a value}"; shift 2 ;;
    --flows) AGENT_FLOWS=1; shift ;;
    --master-ca-pem) CA_SRC="${2:?--master-ca-pem needs a file name, or - for standard input}"; shift 2 ;;
    --allow-plain-http) ALLOW_HTTP=1; shift ;;
    --allow-master-here) ALLOW_MASTER=1; shift ;;
    --dry-run) DRY=1; shift ;;
    --no-service) NOSERVICE=1; shift ;;
    --static) STATIC=1; shift ;;
    --no-signature-check) NOSIG=1; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    --purge) PURGE=1; shift ;;
    -h|--help) usage ;;
    *) die "unknown option $1 (see --help)" ;;
  esac
done

[ "$(uname -s)" = Linux ] || die "this installer is for Linux. On macOS download the program from the Releases page and run it (see the quick start)."
[ "$DRY" = 1 ] || [ "$(id -u)" = 0 ] || die "run it as root:  sudo bash $0   (Alpine: run it in a root shell, or with doas)"
detect_init
if [ "$NOSERVICE" = 1 ]; then
  INIT=none
elif [ "$INIT" = none ] && [ "$DRY" = 0 ] && [ "$UNINSTALL" = 0 ]; then
  die "neither systemd nor OpenRC was found, so no service can be set up. Run it again with --no-service: it installs the program, the \"denis\" user, $ENVFILE and the data folder, and prints the command to start DENIS (put that under your own supervisor). See docs/deployment.md."
fi
for c in curl sha256sum; do command -v "$c" >/dev/null || die "$c is required (Alpine: apk add curl)"; done
if [ -n "$VERSION" ]; then
  printf '%s' "$VERSION" | grep -Eq '^v?[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?$' || die "--version must look like v4.1.1"
fi

if [ "$AGENT" = 1 ]; then
  [ -z "$PORT" ] && [ "$LOCAL_ONLY" = 0 ] || die "--port and --local-only belong to the master: an agent opens no port"
  if [ "$UNINSTALL" = 0 ]; then
    agent_check_args
    if master_present && [ "$ALLOW_MASTER" = 0 ]; then
      die "this machine already runs the DENIS master (service \"denis\"). An agent here would watch the same network a second time and list every device twice. Install the agent on a different machine; if you really mean it, add --allow-master-here."
    fi
  fi
else
  [ -z "$MASTER_URL$AGENT_TOKEN$TOKEN_FILE$AGENT_ID$AGENT_SITE$CA_SRC" ] && [ "$AGENT_FLOWS" = 0 ] && [ "$ALLOW_MASTER" = 0 ] && [ "$ALLOW_HTTP" = 0 ] \
    || die "--master, --token, --id, --site, --flows and --master-ca-pem are for a remote agent: add --agent"
fi

port_in_use() {  # is something listening on TCP port $1?
  if command -v ss >/dev/null; then ss -ltnH 2>/dev/null | awk '{print $4}' | grep -Eq "[:.]$1\$"
  elif command -v netstat >/dev/null; then netstat -ltn 2>/dev/null | awk 'NR > 2 {print $4}' | grep -Eq "[:.]$1\$"
  else (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; fi
}

# ------------------------------------------------------------------------------ the service, for systemd or OpenRC
svc_stop() {
  case "$INIT" in
    systemd) systemctl stop "$1" 2>/dev/null || true ;;
    openrc) rc-service "$1" stop >/dev/null 2>&1 || true ;;
  esac
}
svc_start() {  # start at boot, and (re)start now
  case "$INIT" in
    systemd) systemctl daemon-reload; systemctl enable "$1" >/dev/null 2>&1; systemctl restart "$1" ;;
    openrc) rc-update add "$1" default >/dev/null 2>&1 || true; rc-service "$1" restart ;;
  esac
}
svc_running() {
  case "$INIT" in
    systemd) systemctl is-active --quiet "$1" ;;
    openrc) rc-service "$1" status >/dev/null 2>&1 ;;
    *) return 1 ;;
  esac
}
svc_failed() {
  case "$INIT" in
    systemd) systemctl is-failed --quiet "$1" ;;
    openrc) ! rc-service "$1" status >/dev/null 2>&1 ;;
    *) return 1 ;;
  esac
}
svc_log() {  # the last $2 lines the service $1 wrote
  case "$INIT" in
    systemd) journalctl -u "$1" --no-pager -n "$2" -o cat 2>/dev/null ;;
    openrc) tail -n "$2" "$LOGDIR/$1.log" 2>/dev/null ;;
  esac
}
svc_remove() {  # stop, disable and delete service $1, whichever kind is on this machine
  if command -v systemctl >/dev/null && [ -d /run/systemd/system ]; then systemctl disable --now "$1" 2>/dev/null || true; fi
  if [ -f "/etc/systemd/system/$1.service" ]; then
    rm -f "/etc/systemd/system/$1.service"
    command -v systemctl >/dev/null && systemctl daemon-reload 2>/dev/null || true
  fi
  if [ -f "/etc/init.d/$1" ] && head -1 "/etc/init.d/$1" | grep -q openrc-run; then
    rc-service "$1" stop >/dev/null 2>&1 || true
    rc-update del "$1" default >/dev/null 2>&1 || true
    rm -f "/etc/init.d/$1"
  fi
}
svc_status_line() {  # the "Service / Logs" hint for service $1
  case "$INIT" in
    systemd) echo "Service:  systemctl status $1     Logs:  journalctl -u $1 -f" ;;
    openrc) echo "Service:  rc-service $1 status     Logs:  tail -f $LOGDIR/$1.log" ;;
    *) echo "No service was set up (--no-service)" ;;
  esac
}
as_user() {  # run a command as the service user (runuser is missing on Alpine)
  if command -v runuser >/dev/null; then runuser -u "$SERVICE_USER" -- "$@"
  else su -s /bin/sh "$SERVICE_USER" -c "$(printf '%q ' "$@")"; fi
}
create_user() {
  if command -v useradd >/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
  elif command -v adduser >/dev/null; then  # Alpine (busybox)
    addgroup -S "$SERVICE_USER" 2>/dev/null || true
    adduser -S -D -H -h "$DATA" -s /sbin/nologin -G "$SERVICE_USER" "$SERVICE_USER"
  else
    die "neither useradd nor adduser is here: create a system user \"$SERVICE_USER\" yourself and run this again"
  fi
}
delete_user() {
  if command -v userdel >/dev/null; then userdel "$SERVICE_USER"
  elif command -v deluser >/dev/null; then deluser "$SERVICE_USER"; fi
}
ensure_setcap() {
  command -v setcap >/dev/null && return 0
  say "Installing setcap (to give the program its two capture capabilities)"
  if command -v apk >/dev/null; then apk add -q libcap-setcap 2>/dev/null || apk add -q libcap-utils 2>/dev/null || apk add -q libcap
  elif command -v apt-get >/dev/null; then apt-get install -y -qq libcap2-bin
  elif command -v dnf >/dev/null; then dnf install -y -q libcap
  elif command -v yum >/dev/null; then yum install -y -q libcap
  fi
  command -v setcap >/dev/null || die "setcap is needed to let the service user capture: install it (Alpine: apk add libcap-setcap) and run this again"
}

# ------------------------------------------------------------------------------ uninstall
if [ "$UNINSTALL" = 1 ] && [ "$AGENT" = 1 ]; then
  say "Stopping and removing the DENIS agent (its data is kept unless --purge)"
  svc_remove denis-agent
  if [ -f "$UNIT" ] || [ -f "$OPENRC_INIT" ]; then
    say "The master is still installed here, so the program and the service user stay."
  else
    rm -f "$LINK" "$LINK.previous"; rm -rf "$LIBDIR"
  fi
  rm -f "$AGENT_CA"
  if [ "$PURGE" = 1 ]; then
    rm -rf "$AGENT_DATA" "$AGENT_ENVFILE" "$AGENT_ENVFILE.previous" "$LOGDIR/denis-agent.log"
    say "The agent and its data are removed. Delete its token on the master too (Sites)."
  else
    say "Removed. Its settings stay in $AGENT_ENVFILE and its data in $AGENT_DATA (add --purge to delete them). The token still works until you revoke it on the master."
  fi
  exit 0
fi
if [ "$UNINSTALL" = 1 ]; then
  say "Stopping and removing DENIS (data kept unless --purge)"
  svc_remove denis
  rm -f "$LINK" "$LINK.previous"
  rm -rf "$LIBDIR"
  if [ "$PURGE" = 1 ]; then
    rm -rf "$DATA" /etc/denis "$LOGDIR"
    id "$SERVICE_USER" >/dev/null 2>&1 && delete_user || true
    say "Everything removed, including the data."
  else
    say "Removed. Your data is still in $DATA and settings in /etc/denis (add --purge to delete them)."
  fi
  exit 0
fi

# ------------------------------------------------------------------------------ what to install
case "$(uname -m)" in
  x86_64|amd64) ARCH=x86_64 ;;
  aarch64|arm64) ARCH=aarch64 ;;
  *) die "no pre-built program for $(uname -m): build from source (docs/deployment.md)" ;;
esac
if [ -z "$VERSION" ]; then
  say "Looking for the newest release"
  VERSION=$(curl -fsSL -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest" | sed 's|.*/||') \
    || die "could not reach GitHub"
  case "$VERSION" in v[0-9]*) ;; *) die "could not find a release (got \"$VERSION\")" ;; esac
fi
case "$VERSION" in v*) ;; *) VERSION="v$VERSION" ;; esac
if [ "$AGENT" = 1 ]; then
  # compare the number part only, so that 4.1.0-rc.1 counts as 4.1.0
  BASEV="${VERSION#v}"; BASEV="${BASEV%%-*}"
  if [ "$(printf '%s\n%s\n' "$BASEV" "$AGENT_MIN_VERSION" | sort -V | head -1)" != "$AGENT_MIN_VERSION" ]; then
    die "$VERSION is older than $AGENT_MIN_VERSION: agent mode needs 4.1.0 or newer (earlier agents were set up by hand, see docs/deployment.md). Name a newer one with --version, for example --version v$AGENT_MIN_VERSION"
  fi
elif [ "$(printf '%s\n%s\n' "${VERSION#v}" "$MIN_VERSION" | sort -V | head -1)" != "$MIN_VERSION" ]; then
  if [ "$DRY" = 1 ]; then warn "$VERSION is older than $MIN_VERSION: this installer's service would not fit it (dry run only)"
  else die "$VERSION is older than $MIN_VERSION, the first release this installer supports"; fi
fi
choose_libc "$VERSION"
TARGET="$ARCH-unknown-linux-$LIBC"
say "Release $VERSION for $TARGET${LIBC_WHY:+ (the static build: $LIBC_WHY)}"

if [ -t 2 ]; then PROGRESS="--progress-bar"; else PROGRESS="-s"; fi
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
BASE="https://github.com/$REPO/releases/download/$VERSION"
for f in "denis-$TARGET" SHA256SUMS SHA256SUMS.sig; do
  say "Downloading $f"
  curl -fSL --retry 3 $PROGRESS -o "$TMP/$f" "$BASE/$f" || die "could not download $BASE/$f"
done

# ------------------------------------------------------------------------------ verify
if [ "$NOSIG" = 1 ]; then
  warn "skipping the signature check: only the checksum is verified (it comes from the same place as the program)"
else
  command -v openssl >/dev/null || die "openssl is needed to check the signature (or use --no-signature-check)"
  hex2bin() { printf '%b' "$(printf '%s' "$1" | sed 's/../\\x&/g')"; }
  hex2bin "302a300506032b6570032100$RELEASE_PUBLIC_KEY_HEX" > "$TMP/key.der"
  hex2bin "$(tr -d ' \n\r' < "$TMP/SHA256SUMS.sig")" > "$TMP/sig.bin"
  if ! out=$(openssl pkeyutl -verify -pubin -inkey "$TMP/key.der" -keyform DER -rawin -in "$TMP/SHA256SUMS" -sigfile "$TMP/sig.bin" 2>&1); then
    case "$out" in
      *"Signature Verification Failure"*) die "THE SIGNATURE DOES NOT MATCH: the download is not from the DENIS project. Nothing was installed." ;;
      *) die "this openssl cannot check Ed25519 signatures ($out). Update openssl, or use --no-signature-check" ;;
    esac
  fi
  say "Signature OK (signed with the DENIS release key)"
fi
( cd "$TMP" && grep " denis-$TARGET\$" SHA256SUMS | sha256sum -c - >/dev/null ) \
  || die "THE CHECKSUM DOES NOT MATCH: the download is damaged or altered. Nothing was installed."
say "Checksum OK"
chmod 755 "$TMP/denis-$TARGET"
"$TMP/denis-$TARGET" --version >/dev/null 2>&1 || warn "the program does not start on this machine (missing library?); the install continues so you can see why"

# ------------------------------------------------------------------------------ choose the address
if [ "$AGENT" = 1 ]; then
  KEEP_ENV=1  # not used by the agent; it has no port to choose
elif [ -f "$ENVFILE" ]; then
  LISTEN=$(sed -n 's/^DENIS_LISTEN=//p' "$ENVFILE" | tail -1)
  say "Keeping your settings in $ENVFILE (listening on ${LISTEN:-127.0.0.1:8080})"
  KEEP_ENV=1
else
  KEEP_ENV=0
  if [ "$LOCAL_ONLY" = 1 ]; then HOST=127.0.0.1 START=8080; else HOST=0.0.0.0 START=8443; fi
  if [ -n "$PORT" ]; then
    port_in_use "$PORT" && die "port $PORT is already in use (see: ss -ltnp). Choose another with --port."
    P=$PORT
  else
    P=$START
    while port_in_use "$P"; do
      say "Port $P is in use, trying the next one"
      P=$((P + 1))
      [ "$P" -lt $((START + 50)) ] || die "no free port found near $START: choose one with --port"
    done
  fi
  LISTEN="$HOST:$P"
fi

if [ "$DRY" = 1 ] && [ "$AGENT" = 1 ]; then
  say "Dry run: everything downloaded and verified. Would install $VERSION to $BIN and set up the agent \"${AGENT_ID:-as before}\" (service denis-agent). Nothing was changed."
  if [ "$AGENT_KEEP_ENV" = 1 ]; then echo "    It would keep your settings in $AGENT_ENVFILE."
  else
    echo "    It would write:"
    echo "      $AGENT_ENVFILE (mode 600):  DENIS_MASTER=$MASTER_URL  DENIS_AGENT_ID=$AGENT_ID  DENIS_AGENT_TOKEN=(hidden)${AGENT_NAME:+  DENIS_AGENT_NAME=\"$AGENT_NAME\"}${AGENT_SITE:+  DENIS_AGENT_SITE=\"$AGENT_SITE\"}$([ "$AGENT_FLOWS" = 1 ] && echo '  DENIS_FLOWS=true')"
    [ -z "$CA_PEM" ] || echo "      $AGENT_CA (the master's CA certificate, $(printf '%s\n' "$CA_PEM" | grep -c 'BEGIN CERTIFICATE') certificate(s))"
  fi
  case "$INIT" in
    systemd) echo "      $AGENT_UNIT (generated; it reads the settings above)" ;;
    openrc) echo "      $OPENRC_AGENT_INIT (generated; it reads the settings above)" ;;
    *) echo "      no service (--no-service, or neither systemd nor OpenRC here)" ;;
  esac
  master_present && echo "    This machine also runs the master (--allow-master-here was given)."
  exit 0
fi
if [ "$DRY" = 1 ]; then
  say "Dry run: everything downloaded and verified. Would install $VERSION to $BIN and listen on ${LISTEN} (service: $INIT). Nothing was changed."
  exit 0
fi

# ------------------------------------------------------------------------------ install
# the static build (musl) has libpcap inside; only the usual build needs the system's
if [ "$LIBC" = gnu ] && ! has_pcap08; then
  say "Installing the libpcap runtime library"
  if command -v apt-get >/dev/null; then
    apt-get update -qq && { apt-get install -y -qq libpcap0.8t64 2>/dev/null || apt-get install -y -qq libpcap0.8; }
  elif command -v dnf >/dev/null; then dnf install -y -q libpcap
  elif command -v yum >/dev/null; then yum install -y -q libpcap
  else die "please install the libpcap runtime library (libpcap0.8) and run this again"; fi
fi

id "$SERVICE_USER" >/dev/null 2>&1 || { say "Creating the service user \"$SERVICE_USER\""; create_user; }

UPGRADE=0
SVC=denis; [ "$AGENT" = 1 ] && SVC=denis-agent
# An install from before this layout existed put the real binary straight at $LINK: a plain file
# there (not a symlink) means this is one of those, and it is moved into $LIBDIR below so that, from
# now on, the console's own Settings -> Updates can update it without root (ProtectSystem=strict
# only allows writes under $LIBDIR, which is owned by the service user).
OLD_LAYOUT=0
[ -e "$LINK" ] && [ ! -L "$LINK" ] && OLD_LAYOUT=1
CURRENT_BIN="$BIN"
[ "$OLD_LAYOUT" = 1 ] && CURRENT_BIN="$LINK"
if [ -x "$CURRENT_BIN" ]; then
  UPGRADE=1
  if [ "$AGENT" = 1 ]; then say "A DENIS program is already installed here: replacing it with $VERSION"
  else say "Existing installation found: updating (your data is backed up first)"; fi
  svc_stop "$SVC"
  [ "$INIT" = none ] && warn "--no-service: if DENIS is running, stop it now and start it again after this (the files are replaced underneath it)"
  if [ "$AGENT" = 0 ] && [ -f "$DATA/denis.db" ]; then
    mkdir -p "$DATA/backups" && chown "$SERVICE_USER" "$DATA/backups"
    B="$DATA/backups/denis-before-${VERSION#v}-$(date +%Y%m%d-%H%M%S).db"
    as_user "$CURRENT_BIN" backup --db "$DATA/denis.db" "$B" >/dev/null 2>&1 \
      && say "Backup written to $B" || warn "could not back up the database with the old program; copy $DATA/denis.db yourself if it matters"
  fi
  mkdir -p "$LIBDIR"
  if [ "$OLD_LAYOUT" = 1 ]; then
    say "Moving the program to $LIBDIR so it can update itself from the console from now on"
    mv "$CURRENT_BIN" "$BIN.previous"
  else
    cp -p "$BIN" "$BIN.previous"
  fi
fi
mkdir -p "$LIBDIR"  # a fresh install: $UPGRADE is 0, so the block above never ran
install -m 755 "$TMP/denis-$TARGET" "$BIN"
chown -R "$SERVICE_USER":"$SERVICE_USER" "$LIBDIR"
ln -sf "$BIN" "$LINK"

# Capture needs CAP_NET_RAW and CAP_NET_ADMIN. systemd and OpenRC 0.45+ give them to the service user's
# process (ambient), which leaves the file plain so the console can still update it. Without a service, or
# with an older OpenRC, the file itself gets them; the console then refuses to replace such a file
# (it would lose them), so updates go through this installer.
OPENRC_CAPS=1
if [ "$INIT" = openrc ]; then
  # (it wants the service name first even for --help, and exits non-zero after printing it)
  SD_HELP=$(RC_SVCNAME=denis supervise-daemon denis --help 2>&1 || true)
  case "$SD_HELP" in *--capabilities*) ;; *) OPENRC_CAPS=0 ;; esac
fi
if [ "$INIT" = none ] || [ "$OPENRC_CAPS" = 0 ]; then
  ensure_setcap
  setcap cap_net_raw,cap_net_admin+ep "$BIN"
  say "Gave $BIN the capture capabilities (cap_net_raw, cap_net_admin); update it later by running this installer again"
fi
if [ "$INIT" = none ]; then  # what systemd's StateDirectory and the OpenRC script's checkpath do otherwise
  D="$DATA"; [ "$AGENT" = 1 ] && D="$AGENT_DATA"
  mkdir -p "$D"; chown "$SERVICE_USER":"$SERVICE_USER" "$D"; chmod 700 "$D"
fi

# ------------------------------------------------------------------------------ the agent: its own files, then done
if [ "$AGENT" = 1 ]; then
  case "$INIT" in systemd) SVCFILE="$AGENT_UNIT" ;; openrc) SVCFILE="$OPENRC_AGENT_INIT" ;; *) SVCFILE="" ;; esac
  UPGRADE=0; [ -n "$SVCFILE" ] && [ -f "$SVCFILE" ] && UPGRADE=1
  say "Writing the agent's settings${SVCFILE:+ and service} ($AGENT_ENVFILE${SVCFILE:+, $SVCFILE})"
  if [ "$AGENT_KEEP_ENV" = 1 ]; then write_agent_files keep; else write_agent_files; fi
  if [ "$INIT" = none ]; then
    # the command below runs as the service user, which must be able to read its settings
    chgrp "$SERVICE_USER" "$AGENT_ENVFILE" && chmod 640 "$AGENT_ENVFILE"
    echo
    say "The DENIS agent ${VERSION#v} is installed (no service: --no-service)"
    echo "    Start it, as the service user, with its settings (put this under your own supervisor so it starts at boot):"
    echo "      su -s /bin/sh $SERVICE_USER -c 'set -a; . $AGENT_ENVFILE; exec $BIN agent --db $AGENT_DATA/agent.db'"
    echo "    Settings:  $AGENT_ENVFILE     Update:  bash $(basename "$0") --agent --no-service     Remove:  bash $(basename "$0") --agent --uninstall"
    exit 0
  fi
  say "Starting the DENIS agent"
  svc_start denis-agent
  ok=0
  for _ in $(seq 1 15); do
    sleep 1
    if svc_running denis-agent; then ok=1; else ok=0; fi
    svc_failed denis-agent && break
  done
  if [ "$ok" = 0 ]; then
    svc_log denis-agent 25 | sed 's/\x1b\[[0-9;]*m//g' | grep -v 'dat_' >&2 || true
    die "The agent did not stay running. The lines above say why (a wrong token or address is the usual reason). Fix $AGENT_ENVFILE, then:  $(restart_hint denis-agent)"
  fi
  echo
  say "The DENIS agent ${VERSION#v} is running"
  [ "$AGENT_KEEP_ENV" = 1 ] && echo "    Updated. Its settings in $AGENT_ENVFILE are as they were." \
    || echo "    It reports to ${MASTER_URL} as \"$AGENT_ID\"."
  echo "    On the master, open the Sites tab: within a minute or so this agent should appear there with its name, site and device count."
  if [ "$INIT" = openrc ]; then LOGCMD="tail -f $LOGDIR/denis-agent.log"; else LOGCMD="journalctl -u denis-agent -f"; fi
  echo "    If it does not: on this machine  $LOGCMD  (a refused token or an untrusted certificate is said plainly there),"
  echo "    and check that this machine can reach the master's agent address (outbound only; nothing is opened here)."
  master_present && echo "    This machine also runs the master: restart it ($(restart_hint denis)) to use the program just installed."
  echo
  echo "    $(svc_status_line denis-agent)     Settings:  $AGENT_ENVFILE"
  echo "    Update:   from the master (Sites -> Update), or $([ "$INIT" = systemd ] && echo 'sudo ')bash $(basename "$0") --agent     Remove:  $([ "$INIT" = systemd ] && echo 'sudo ')bash $(basename "$0") --agent --uninstall"
  exit 0
fi

if [ "$INIT" = systemd ]; then
say "Writing the service ($UNIT)"
# --- unit begin ---
cat > "$UNIT" <<'UNIT_EOF'
[Unit]
Description=denis network asset discovery
After=network-online.target
Wants=network-online.target
# a start that keeps failing (for instance a taken port) is not retried forever
StartLimitIntervalSec=120
StartLimitBurst=5

[Service]
User=denis
Environment=DENIS_LISTEN=127.0.0.1:8080
EnvironmentFile=-/etc/denis/env
ExecStart=/usr/local/lib/denis/denis run --db /var/lib/denis/denis.db
Restart=on-failure
RestartSec=5

# /var/lib/denis, owned by the service user, and readable/writable by no one else: the database
# holds TOTP secrets and every integration credential in plaintext settings rows
# (SECURITY_ARCHITECTURE_REVIEW.md M10).
StateDirectory=denis
StateDirectoryMode=0700
UMask=0077

# Only what capture/injection needs: CAP_NET_RAW (packet sockets, raw ICMP),
# CAP_NET_ADMIN (promiscuous mode via PACKET_ADD_MEMBERSHIP).
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=true
ProtectSystem=strict
# owned by the service user (see above): the one exception, so the program can update itself
ReadWritePaths=/usr/local/lib/denis
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_PACKET AF_UNIX AF_NETLINK

[Install]
WantedBy=multi-user.target
UNIT_EOF
# --- unit end ---
chmod 644 "$UNIT"
elif [ "$INIT" = openrc ]; then
  say "Writing the service ($OPENRC_INIT)"
  openrc_script > "$OPENRC_INIT"
  # an OpenRC older than 0.45 cannot hand capabilities to the process: the file has them instead (above)
  [ "$OPENRC_CAPS" = 1 ] || sed -i '/^capabilities=/d' "$OPENRC_INIT"
  chmod 755 "$OPENRC_INIT"
fi

if [ "$KEEP_ENV" = 0 ]; then
  ADDR=$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.*src \([0-9.]*\).*/\1/p' | head -1)
  TLS_NAMES=$(printf '%s\n' "$ADDR" "$(hostname)" ${NAMES[@]+"${NAMES[@]}"} | grep -v '^$' | paste -sd, -)
  mkdir -p /etc/denis
  {
    echo "# Settings for the DENIS service. After editing:  $(restart_hint denis)"
    echo "# All options are listed in docs/deployment.md; any 'denis run' option with an environment name works here."
    echo "DENIS_LISTEN=$LISTEN"
    [ "$LOCAL_ONLY" = 1 ] || [ -z "$TLS_NAMES" ] || echo "DENIS_TLS_NAMES=$TLS_NAMES"
  } > "$ENVFILE"
  chmod 600 "$ENVFILE"
fi
PORT_NOW="${LISTEN##*:}"

if [ "$INIT" = none ]; then
  # the command below runs as the service user, which must be able to read its settings (no secret is in them)
  chgrp "$SERVICE_USER" "$ENVFILE" && chmod 640 "$ENVFILE"
  echo
  say "DENIS ${VERSION#v} is installed (no service: --no-service)"
  echo "    Start it, as the service user, with its settings (put this under your own supervisor so it starts at boot):"
  echo "      su -s /bin/sh $SERVICE_USER -c 'set -a; . $ENVFILE; exec $BIN run --db $DATA/denis.db'"
  if [ "$UPGRADE" = 0 ]; then
    echo "    At its first start it prints the one-time password for   admin   (you must change it at first sign-in)."
  else
    echo "    Updated. Your data and settings are as they were; the previous program is $BIN.previous."
  fi
  echo "    The console will be at https://$(hostname):$PORT_NOW (it listens on ${LISTEN})."
  echo "    Settings:  $ENVFILE     Update:  bash $(basename "$0") --no-service     Remove:  bash $(basename "$0") --uninstall"
  exit 0
fi

say "Starting DENIS"
SINCE=$(date '+%Y-%m-%d %H:%M:%S')
LOG_BEFORE=0
[ "$INIT" = openrc ] && [ -f "$LOGDIR/denis.log" ] && LOG_BEFORE=$(wc -c < "$LOGDIR/denis.log")
svc_start denis
ok=0
for _ in $(seq 1 40); do
  if port_in_use "$PORT_NOW"; then ok=1; break; fi
  svc_failed denis && break
  sleep 1
done
if [ "$ok" = 0 ]; then
  svc_log denis 25 | sed 's/\x1b\[[0-9;]*m//g' | grep -vi 'password' >&2 || true
  die "DENIS did not start. The lines above say why. Fix it, then:  $(restart_hint denis)   (settings: $ENVFILE)"
fi

# ------------------------------------------------------------------------------ what now
HOSTS=$(sed -n 's/^DENIS_TLS_NAMES=//p' "$ENVFILE" | tail -1 | tr ',' ' ')
echo
say "DENIS ${VERSION#v} is running"
if [ "${LISTEN%%:*}" = 127.0.0.1 ]; then
  echo "    The console listens on this machine only. From your computer:"
  echo "      ssh -L $PORT_NOW:localhost:$PORT_NOW ${SUDO_USER:-you}@$(hostname)    then open   https://localhost:$PORT_NOW"
else
  for h in ${HOSTS:-$(hostname)}; do echo "    Open   https://$h:$PORT_NOW"; done
  echo "    (your browser will warn once: DENIS made its own certificate. Settings -> HTTPS certificate explains how to trust or replace it.)"
  if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q 'Status: active'; then
    echo "    The firewall (ufw) is on. To allow the console:  sudo ufw allow $PORT_NOW/tcp"
  fi
fi
if [ "$UPGRADE" = 0 ]; then
  echo "    Sign in as   admin   with the one-time password below (you must change it at first sign-in):"
  if [ "$INIT" = openrc ]; then
    # the password line can come a moment after the port opens
    for _ in 1 2 3 4 5; do grep -qi 'password:' "$LOGDIR/denis.log" 2>/dev/null && break; sleep 1; done
    NEWLOG=$(tail -c +"$((LOG_BEFORE + 1))" "$LOGDIR/denis.log" 2>/dev/null) || NEWLOG=""
  else
    NEWLOG=$(journalctl -u denis --since "$SINCE" --no-pager -o cat 2>/dev/null) || NEWLOG=""
  fi
  PW=$(printf '%s\n' "$NEWLOG" | sed 's/\x1b\[[0-9;]*m//g' | grep -m1 -i 'password:' | sed 's/.*password: *//; s/ *[│|].*//; s/ *$//') || true
  if [ -n "${PW:-}" ]; then echo "      $PW"
  elif [ "$INIT" = systemd ]; then echo "      (not found: run   sudo -u $SERVICE_USER $BIN user reset admin --db $DATA/denis.db   for a new one)"
  else echo "      (not found: run   su -s /bin/sh $SERVICE_USER -c '$BIN user reset admin --db $DATA/denis.db'   for a new one)"; fi
else
  echo "    Updated. Your data and settings are as they were; the previous program is $BIN.previous."
fi
echo
echo "    $(svc_status_line denis)     Settings:  $ENVFILE"
echo "    Update:   $([ "$INIT" = systemd ] && echo 'sudo ')bash $(basename "$0")     Remove:  $([ "$INIT" = systemd ] && echo 'sudo ')bash $(basename "$0") --uninstall"
