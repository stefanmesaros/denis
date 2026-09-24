# Updates

DENIS can tell you when a new version is out, show you what changed, and install it for you: **now or at a time you
choose**, with a backup first and without touching your data.

## How it works for you

1. Every few hours DENIS asks GitHub whether a newer **release** exists. If so, a bar appears under the header:
   *"DENIS 0.2.0 is available. What's new"* (everyone sees it; only administrators can install).
2. **What's new** opens the changelog and your choices:
   * **Install now**: a progress list shows each step; the page reloads on the new version.
   * **Schedule**: pick a time (for example tonight at 03:00); DENIS installs then.
   * **Remind me in 3 days**, or **Skip this version**.
3. **Settings → Updates** shows the current version, when DENIS last checked, and **Check for updates now**.

## What happens during an install, and why it is safe

| Step | Detail |
|---|---|
| Verify | The release's checksum list must carry a valid **signature** from the project's release key (the public key is built into your DENIS). A file that does not match the signed checksum is refused. A compromised GitHub account alone cannot push code to you. |
| Test | The new program is asked for its version before anything is replaced; if it cannot run on this machine the update stops with nothing changed. |
| Back up | A verified copy of your database is written to a `backups` folder beside the database (`denis-before-<version>-<time>.db`, owner-only; the newest five are kept). |
| Switch | The old program is kept as `denis.previous`, the new one takes its place, and DENIS restarts **in place** (same process, same arguments). |
| Confirm | After one minute of healthy running the update counts as done. If the new version fails to start twice, the **previous version comes back automatically**, together with the pre-update database if its format had changed; the console tells you what happened. |

Your data is not changed by updating: the database is migrated forward by the new version exactly as in any manual
upgrade, after the backup exists. Only newer versions are offered; a downgrade is never installed.

## Requirements and limits

* The program must be in a folder the DENIS user can write to. `install.sh` sets this up for you: the program lives
  at `/usr/local/lib/denis/denis` (owned by the `denis` user, with a convenience symlink at `/usr/local/bin/denis`),
  and the systemd unit's `ReadWritePaths` allows writes there and nowhere else. That is what makes the one-click
  update above possible under `ProtectSystem=strict`. An installation from before this layout existed (the program
  straight at `/usr/local/bin/denis`, owned by root) cannot update itself yet: the console says so and links the
  release for a manual update — run `sudo bash install.sh` **once** to move it into the new layout (see
  [Deployment](deployment.md#installing-on-a-linux-server-a-permanent-service)); every update after that is one click.
* A build without a release key (a build you compiled yourself before setting one) can *see* new versions but not
  install them.
* Agents on remote sites are separate programs: update them the same way you installed them (or run
  `denis` from the same release). The master shows each agent's version under **Sites**.
* Updates come from `https://github.com/<owner>/<repo>/releases` only.

## Privacy and switching it off

Checking sends one anonymous HTTPS request to `api.github.com` every six hours; GitHub sees your address, nothing
about your network or data. To never contact GitHub (air-gapped, or you prefer to update by hand):

```bash
denis run --no-update-check      # or DENIS_NO_UPDATE_CHECK=1
```

## By hand

Download `denis-<platform>` and `SHA256SUMS` from the release, compare `sha256sum`, take a backup
(`denis backup FILE`), stop DENIS, replace the binary, start it. See [Operations](operations.md#upgrading).
