#!/usr/bin/env bash
# Everything that must pass before a release tag is pushed (about 5 minutes). See RELEASING.md.
#
#   tools/pre-release.sh          all steps (needs network for the last two)
#   OFFLINE=1 tools/pre-release.sh   skip the steps that contact GitHub
#
# It stops at the first failure. Passing does not replace looking at the console yourself, but it catches the
# kind of break that is easy to miss by hand: an empty dropdown, a page that throws, a translation that is missing.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:/opt/homebrew/opt/rustup/bin:$PATH"
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

step "1/8 the version is consistent (Cargo.toml, CHANGELOG.md)"
V=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
grep -q "^## $V\b" CHANGELOG.md || { echo "CHANGELOG.md has no '## $V' section (it becomes the release notes)"; exit 1; }
echo "version $V"

step "2/8 unit and integration tests"
if ! OUT=$(cargo test --locked 2>&1); then echo "$OUT" | tail -40; echo "cargo test failed (if it says the lock file needs an update: run cargo build once and commit Cargo.lock)"; exit 1; fi
echo "$OUT" | grep -E "^test result" | sort | uniq -c

step "3/8 lint (warnings are errors)"
cargo clippy --locked --all-targets -- -D warnings

step "4/8 translations are complete and the generated catalogs are current"
BEFORE=$(cat ui/i18n/*.json | shasum)
python3 tools/i18n/build.py --check
[ "$BEFORE" = "$(cat ui/i18n/*.json | shasum)" ] || { echo "ui/i18n/*.json were out of date and have been regenerated: review and commit them, then run this again"; exit 1; }

step "5/8 the installer (syntax, and a dry run that downloads and verifies the newest release)"
bash -n packaging/install.sh
if [ "${OFFLINE:-0}" != 0 ]; then echo "(offline: skipped the download)"
elif [ "$(uname -s)" != Linux ]; then echo "(the installer is for Linux: the dry run is skipped on $(uname -s); CI and the Linux server cover it)"
else bash packaging/install.sh --dry-run --local-only 2>&1 | tail -3; fi

step "6/8 build the release program"
cargo build --release --locked

step "7/8 the console in a real browser (every page, the asset editor, icons, rules, all languages, phone layout)"
DENIS_BIN=target/release/denis node tools/ui-smoke.mjs

step "8/8 a database from the newest published release opens with this program"
if [ "${OFFLINE:-0}" = 0 ]; then tools/upgrade-check.sh target/release/denis; else echo "(offline: skipped)"; fi

printf '\n\033[1;32mall pre-release checks passed for %s\033[0m\n' "$V"
echo "Now: commit, tag v$V, push. Then read RELEASING.md for the stable/pre-release steps and check the release page."
