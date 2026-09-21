#!/usr/bin/env bash
# DENIS installer for Linux with systemd (Ubuntu, Debian, Raspberry Pi OS, RHEL-family).
#
#   curl -fLO https://github.com/stefanmesaros/denis/releases/latest/download/install.sh
#   less install.sh                      # read it first: it runs as root
#   sudo bash install.sh
#
# What it does, in order:
#   1. finds the newest release (or the one you name with --version),
#   2. downloads the program for this machine (x86-64 or ARM64) and SHA256SUMS + SHA256SUMS.sig,
#   3. checks the Ed25519 signature on SHA256SUMS against the project's release key (built in below) and
#      the program's SHA-256 against that signed list. Anything wrong: it stops before changing anything,
#   4. installs the libpcap runtime library if it is missing,
#   5. installs /usr/local/bin/denis, the "denis" service user, the systemd unit and /etc/denis/env,
#   6. picks a free port for the web console (8443, or the next free one; --port to choose),
#   7. starts the service and tells you the address and the one-time administrator password.
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
#   --no-signature-check  verify the SHA-256 only (for systems whose openssl cannot check Ed25519)
#   --uninstall         stop and remove the program and service, keep the data
#   --purge             with --uninstall: also delete the data (/var/lib/denis), /etc/denis and the user
#   -h, --help          this text
set -euo pipefail

REPO="stefanmesaros/denis"
# The Ed25519 public key release files are signed with (the same key is built into the program).
RELEASE_PUBLIC_KEY_HEX="abe75462c8adfb1d4c5aa39d25e44377d00c77442f423c2f01cd51fec40e938e"
MIN_VERSION="0.1.3"          # the first release this installer's service layout fits
BIN=/usr/local/bin/denis
UNIT=/etc/systemd/system/denis.service
ENVFILE=/etc/denis/env
DATA=/var/lib/denis
SERVICE_USER=denis

VERSION="" PORT="" LOCAL_ONLY=0 DRY=0 NOSIG=0 UNINSTALL=0 PURGE=0
NAMES=()

say()  { printf '\033[1m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }
usage() { sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0; }

while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="${2:?--version needs a value}"; shift 2 ;;
    --port) PORT="${2:?--port needs a value}"; shift 2 ;;
    --local-only) LOCAL_ONLY=1; shift ;;
    --name) NAMES+=("${2:?--name needs a value}"); shift 2 ;;
    --dry-run) DRY=1; shift ;;
    --no-signature-check) NOSIG=1; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    --purge) PURGE=1; shift ;;
    -h|--help) usage ;;
    *) die "unknown option $1 (see --help)" ;;
  esac
done

[ "$(uname -s)" = Linux ] || die "this installer is for Linux. On macOS download the program from the Releases page and run it (see the quick start)."
if [ "$DRY" = 0 ]; then
  [ "$(id -u)" = 0 ] || die "run it with sudo:  sudo bash $0"
  command -v systemctl >/dev/null && [ -d /run/systemd/system ] || die "systemd was not found: install by hand (docs/deployment.md)"
fi
for c in curl sha256sum; do command -v "$c" >/dev/null || die "$c is required"; done

port_in_use() {  # is something listening on TCP port $1?
  if command -v ss >/dev/null; then ss -ltnH 2>/dev/null | awk '{print $4}' | grep -Eq "[:.]$1\$"
  else (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; fi
}

# ------------------------------------------------------------------------------ uninstall
if [ "$UNINSTALL" = 1 ]; then
  say "Stopping and removing DENIS (data kept unless --purge)"
  systemctl disable --now denis 2>/dev/null || true
  rm -f "$UNIT" "$BIN" "$BIN.previous"
  systemctl daemon-reload
  if [ "$PURGE" = 1 ]; then
    rm -rf "$DATA" /etc/denis
    id "$SERVICE_USER" >/dev/null 2>&1 && userdel "$SERVICE_USER" || true
    say "Everything removed, including the data."
  else
    say "Removed. Your data is still in $DATA and settings in /etc/denis (add --purge to delete them)."
  fi
  exit 0
fi

# ------------------------------------------------------------------------------ what to install
case "$(uname -m)" in
  x86_64|amd64) TARGET=x86_64-unknown-linux-gnu ;;
  aarch64|arm64) TARGET=aarch64-unknown-linux-gnu ;;
  *) die "no pre-built program for $(uname -m): build from source (docs/deployment.md)" ;;
esac
if [ -z "$VERSION" ]; then
  say "Looking for the newest release"
  VERSION=$(curl -fsSL -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest" | sed 's|.*/||') \
    || die "could not reach GitHub"
  case "$VERSION" in v[0-9]*) ;; *) die "could not find a release (got \"$VERSION\")" ;; esac
fi
case "$VERSION" in v*) ;; *) VERSION="v$VERSION" ;; esac
if [ "$(printf '%s\n%s\n' "${VERSION#v}" "$MIN_VERSION" | sort -V | head -1)" != "$MIN_VERSION" ]; then
  if [ "$DRY" = 1 ]; then warn "$VERSION is older than $MIN_VERSION: this installer's service would not fit it (dry run only)"
  else die "$VERSION is older than $MIN_VERSION, the first release this installer supports"; fi
fi
say "Release $VERSION for $TARGET"

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
if [ -f "$ENVFILE" ]; then
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

if [ "$DRY" = 1 ]; then
  say "Dry run: everything downloaded and verified. Would install $VERSION to $BIN and listen on ${LISTEN}. Nothing was changed."
  exit 0
fi

# ------------------------------------------------------------------------------ install
if ! ldconfig -p 2>/dev/null | grep -q 'libpcap\.so\.0\.8'; then
  say "Installing the libpcap runtime library"
  if command -v apt-get >/dev/null; then
    apt-get update -qq && { apt-get install -y -qq libpcap0.8t64 2>/dev/null || apt-get install -y -qq libpcap0.8; }
  elif command -v dnf >/dev/null; then dnf install -y -q libpcap
  elif command -v yum >/dev/null; then yum install -y -q libpcap
  else die "please install the libpcap runtime library (libpcap0.8) and run this again"; fi
fi

id "$SERVICE_USER" >/dev/null 2>&1 || { say "Creating the service user \"$SERVICE_USER\""; useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"; }

UPGRADE=0
if [ -x "$BIN" ]; then
  UPGRADE=1
  say "Existing installation found: updating (your data is backed up first)"
  systemctl stop denis 2>/dev/null || true
  if [ -f "$DATA/denis.db" ]; then
    mkdir -p "$DATA/backups" && chown "$SERVICE_USER" "$DATA/backups"
    B="$DATA/backups/denis-before-${VERSION#v}-$(date +%Y%m%d-%H%M%S).db"
    runuser -u "$SERVICE_USER" -- "$BIN" backup --db "$DATA/denis.db" "$B" >/dev/null 2>&1 \
      && say "Backup written to $B" || warn "could not back up the database with the old program; copy $DATA/denis.db yourself if it matters"
  fi
  cp -p "$BIN" "$BIN.previous"
fi
install -m 755 "$TMP/denis-$TARGET" "$BIN"

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
ExecStart=/usr/local/bin/denis run --db /var/lib/denis/denis.db
Restart=on-failure
RestartSec=5

# /var/lib/denis, owned by the service user
StateDirectory=denis

# Only what capture/injection needs: CAP_NET_RAW (packet sockets, raw ICMP),
# CAP_NET_ADMIN (promiscuous mode via PACKET_ADD_MEMBERSHIP).
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=true
ProtectSystem=strict
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

if [ "$KEEP_ENV" = 0 ]; then
  ADDR=$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.*src \([0-9.]*\).*/\1/p' | head -1)
  TLS_NAMES=$(printf '%s\n' "$ADDR" "$(hostname)" ${NAMES[@]+"${NAMES[@]}"} | grep -v '^$' | paste -sd, -)
  mkdir -p /etc/denis
  {
    echo "# Settings for the DENIS service. After editing:  sudo systemctl restart denis"
    echo "# All options are listed in docs/deployment.md; any 'denis run' option with an environment name works here."
    echo "DENIS_LISTEN=$LISTEN"
    [ "$LOCAL_ONLY" = 1 ] || [ -z "$TLS_NAMES" ] || echo "DENIS_TLS_NAMES=$TLS_NAMES"
  } > "$ENVFILE"
  chmod 600 "$ENVFILE"
fi

say "Starting DENIS"
SINCE=$(date '+%Y-%m-%d %H:%M:%S')
systemctl daemon-reload
systemctl enable denis >/dev/null 2>&1
systemctl restart denis
PORT_NOW="${LISTEN##*:}"
ok=0
for _ in $(seq 1 40); do
  if port_in_use "$PORT_NOW"; then ok=1; break; fi
  systemctl is-failed --quiet denis && break
  sleep 1
done
if [ "$ok" = 0 ]; then
  journalctl -u denis --no-pager -n 25 -o cat 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g' | grep -vi 'password' >&2 || true
  die "DENIS did not start. The lines above say why. Fix it, then:  sudo systemctl restart denis   (settings: $ENVFILE)"
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
  PW=$(journalctl -u denis --since "$SINCE" --no-pager -o cat 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g' | grep -m1 -i 'password:' | sed 's/.*password: *//; s/ *[│|].*//; s/ *$//') || true
  if [ -n "${PW:-}" ]; then echo "      $PW"; else echo "      (not found: run   sudo -u $SERVICE_USER $BIN user reset admin --db $DATA/denis.db   for a new one)"; fi
else
  echo "    Updated. Your data and settings are as they were; the previous program is $BIN.previous."
fi
echo
echo "    Service:  systemctl status denis     Logs:  journalctl -u denis -f     Settings:  $ENVFILE"
echo "    Update:   sudo bash $(basename "$0")     Remove:  sudo bash $(basename "$0") --uninstall"
