# Releasing DENIS

DENIS installs updates from this repository's GitHub releases, and only accepts files signed with the project's
**release key**. This page is for maintainers.

## One-time setup

1. Generate the key pair (on a trusted machine):

   ```bash
   denis release-keygen
   ```

2. Store the **private key** as a repository secret named `DENIS_RELEASE_KEY`
   (Settings → Secrets and variables → Actions). Never commit it. Anyone holding it can publish updates that every
   installation will trust, so guard it like a signing certificate (a hardware token or an offline machine is
   better still: sign `SHA256SUMS` yourself with `denis release-sign` and upload it by hand).
3. Paste the **public key** into `src/update_key.rs` (`RELEASE_PUBLIC_KEY`) and set `UPDATE_REPO` to
   `owner/repo`. Commit. Programs built without these two values cannot update themselves.

Lost or leaked private key? Generate a new pair, ship a release built with the new public key **installed by hand**
(installations still trust the old key), and revoke the old secret. That is the price of a trust anchor compiled into
the program.

## Stable and pre-release: how a version earns "stable"

Two kinds of release, told apart by the tag:

| Tag | GitHub marks it | Who gets it |
|---|---|---|
| `v0.2.0-rc.1`, `v0.2.0-rc.2`… (anything with a `-`) | **pre-release** | only people who ask for it (`install.sh --version v0.2.0-rc.1`, or the Releases page). The installer's "newest release", `releases/latest` and the console's update check **never** offer it. |
| `v0.2.0` | **stable** ("Latest") | everyone: new installs with `install.sh`, and every console that checks for updates |

So a new version is first published as a release candidate, **used for a while** (a week or two on a real network, by
you or a friendly user), and only when it has behaved is the same code re-tagged as the stable version. The
soak period is what finds what tests cannot: a device type nobody has, a switch that behaves differently, a habit.

**Making it stable:** when the candidate has run without problems, set `version` in `Cargo.toml` to `0.2.0`, retitle
the `## 0.2.0-rc.N` section of `CHANGELOG.md` to `## 0.2.0` (keep the notes), run `tools/pre-release.sh`, commit, tag
`v0.2.0` and push. Nothing else changes between the candidate and the stable release, so what was tested is what ships.
If a candidate has a problem, fix it and publish `-rc.2`; the stable channel stays as it was.

## Every release

1. Update `CHANGELOG.md` with a `## <version>` section (it becomes the release notes shown in every console) and the
   `version` in `Cargo.toml` (`0.2.0-rc.1` for a candidate). Commit.
2. Run **`tools/pre-release.sh`**. It refuses to pass unless all of this holds: version and changelog agree; all unit
   tests pass; clippy is clean; every translation is present and the generated catalogs are current; the installer is
   valid and a dry run against the newest published release verifies; the release program builds; **the console works
   in a real browser** (`tools/ui-smoke.mjs`: every page opens without errors, no page shows `null`/`undefined`, lists
   have their rows, the asset editor's dropdowns and the icon chooser work, also when the first request for the option
   lists was refused, an OT watch can be added and removed, every language loads, the phone layout does not
   overflow); and a database made by the newest published release opens with the new program (`tools/upgrade-check.sh`).
   GitHub's CI runs the same browser test on every push, and the release workflow repeats it before building.
3. Tag and push: `git tag v0.2.0-rc.1 && git push origin main v0.2.0-rc.1`.
4. The **Release** workflow tests, builds Linux (x86-64, ARM64) and macOS (Apple silicon, Intel), writes `SHA256SUMS`,
   signs it, attaches `install.sh` and publishes the release (a **pre-release** if the tag has a `-`) with the files
   `denis-<target>`, `SHA256SUMS`, `SHA256SUMS.sig`, `install.sh`.
5. Look at the release page, then install it somewhere real (`sudo bash install.sh --version v0.2.0-rc.1`) and use it.
6. Installed consoles notice a *stable* release within a few hours, show the changelog and ask the administrator.

When something in the pre-release checks fails, **fix it and add a check** so the same kind of break is caught next
time (`tools/ui-smoke.mjs` is the place for anything visible in the console).

## What an installation does with an update

Verify the signature, verify the file's checksum against the signed list, test that the new program runs, back up the
database, keep the old program as `denis.previous`, switch, restart in place, and confirm after a minute (or go back
after two failed starts). See [docs/updates.md](docs/updates.md).
