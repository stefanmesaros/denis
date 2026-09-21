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

## Every release

1. Update `CHANGELOG.md` with a `## <version>` section (it becomes the release notes shown in every console) and the
   `version` in `Cargo.toml`. Commit.
2. Tag and push: `git tag v0.2.0 && git push origin v0.2.0`.
3. The **Release** workflow builds Linux (x86-64, ARM64) and macOS (Apple silicon, Intel), writes `SHA256SUMS`, signs it
   and publishes the release with the files `denis-<target>`, `SHA256SUMS`, `SHA256SUMS.sig`.
4. Installed consoles notice within a few hours, show the changelog and ask the administrator.

## What an installation does with an update

Verify the signature, verify the file's checksum against the signed list, test that the new program runs, back up the
database, keep the old program as `denis.previous`, switch, restart in place, and confirm after a minute (or go back
after two failed starts). See [docs/updates.md](docs/updates.md).
