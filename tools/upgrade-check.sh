#!/usr/bin/env bash
# Upgrade check: a database made by the newest PUBLISHED release must open, intact, with the program being
# released (schema migration, no data lost), and the console must answer. Needs network (GitHub) and curl.
#
#   tools/upgrade-check.sh [path/to/new/denis]        (default: target/release/denis, else target/debug/denis)
set -euo pipefail
cd "$(dirname "$0")/.."
NEW="${1:-}"
[ -n "$NEW" ] || { [ -x target/release/denis ] && NEW=target/release/denis || NEW=target/debug/denis; }
[ -x "$NEW" ] || { echo "no program at $NEW: build first"; exit 2; }
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) T=aarch64-apple-darwin ;; Darwin-x86_64) T=x86_64-apple-darwin ;;
  Linux-x86_64) T=x86_64-unknown-linux-gnu ;; Linux-aarch64) T=aarch64-unknown-linux-gnu ;;
  *) echo "unsupported platform"; exit 2 ;;
esac
TMP=$(mktemp -d); trap 'kill $SRV 2>/dev/null || true; rm -rf "$TMP"' EXIT
SRV=""
V=$(curl -fsSL -o /dev/null -w '%{url_effective}' https://github.com/stefanmesaros/denis/releases/latest | sed 's|.*/||')
echo "newest published release: $V"
curl -fsSL -o "$TMP/old" "https://github.com/stefanmesaros/denis/releases/download/$V/denis-$T"
curl -fsSL -o "$TMP/SUMS" "https://github.com/stefanmesaros/denis/releases/download/$V/SHA256SUMS"
( cd "$TMP" && grep " denis-$T\$" SUMS | sed "s/denis-$T/old/" | shasum -a 256 -c - >/dev/null ) || { echo "checksum of the old release does not match"; exit 1; }
chmod +x "$TMP/old"
"$TMP/old" demo --db "$TMP/d.db" load >/dev/null
BEFORE=$("$TMP/old" --version)
# open the old release's database with the new program
PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
"$NEW" serve --db "$TMP/d.db" --insecure-no-auth --listen "127.0.0.1:$PORT" >"$TMP/new.log" 2>&1 & SRV=$!
for _ in $(seq 1 40); do curl -fs "http://127.0.0.1:$PORT/api/status" >/dev/null 2>&1 && break; sleep 0.25; done
N=$(curl -fs "http://127.0.0.1:$PORT/api/assets" | python3 -c 'import sys,json; print(len(json.load(sys.stdin)))') || { cat "$TMP/new.log"; echo "the new program could not serve the old database"; exit 1; }
E=$(curl -fs "http://127.0.0.1:$PORT/api/alerts" | python3 -c 'import sys,json; print(len(json.load(sys.stdin)))')
kill $SRV; wait $SRV 2>/dev/null || true; SRV=""
[ "$N" = 42 ] || { echo "expected the 42 demo devices, the new program shows $N"; exit 1; }
[ "$E" -gt 0 ] || { echo "the demo alerts are gone"; exit 1; }
"$NEW" backup --db "$TMP/d.db" "$TMP/backup.db" >/dev/null || { echo "the new program cannot back up the migrated database"; exit 1; }
# and the old release must refuse the migrated database rather than misread it (only if the schema changed)
if "$TMP/old" serve --db "$TMP/d.db" --insecure-no-auth --listen "127.0.0.1:$PORT" >"$TMP/old.log" 2>&1 & OLD=$!; sleep 2; kill -0 $OLD 2>/dev/null; then kill $OLD 2>/dev/null; wait $OLD 2>/dev/null || true; echo "note: the old release still opens the migrated database (the schema did not change)"; else grep -q "newer than this build" "$TMP/old.log" && echo "the old release refuses the migrated database, as it should" || echo "note: the old release could not open it: $(tail -1 "$TMP/old.log")"; fi
echo "upgrade check OK: $BEFORE database -> $($NEW --version): $N devices, $E alerts, backup works"
