# Updates

DENIS can tell you when a new version is out, show you what changed, and install it for you: **now or at a time you
choose**, with a backup first and without touching your data.

## How it works for you

1. Every few hours DENIS asks GitHub whether a newer **release** exists. If so, a bar appears under the header:
   *"DENIS 2.52.0 is available. What's new"* (everyone sees it; only administrators can install).
2. **What's new** opens the changelog and your choices:
   * **Install now**: a progress list shows each step; the page reloads on the new version.
   * **Schedule**: pick a time (for example tonight at 03:00); DENIS installs then.
   * **Remind me in 3 days**, or **Skip this version**.
3. **Settings → System → Updates** shows the current version, when DENIS last checked, and **Check for updates now**.

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
* Agents on remote sites are separate programs. By default nothing happens to them: you update them from the
  master when you choose to, or by hand ([Updating remote agents](#updating-remote-agents)). The master shows each
  agent's version under **Sites**.
* Updates come from `https://github.com/<owner>/<repo>/releases`. Only if GitHub cannot be reached, DENIS tries
  `https://usedenis.com` instead ([below](#if-github-cannot-be-reached)); nowhere else.

## Pre-release versions (for testers)

DENIS is published in two kinds of release. A **stable** release is what everyone gets. Before a version becomes
stable it is published as a **pre-release** (a *release candidate*, tagged like `v4.1.0-rc.1`, or a *beta*): the same
code that will become stable if it behaves, for people who want to try it first. **By default your installation only
ever offers stable releases**, and nothing below changes that.

Testers can opt in: **Settings → System → Updates → Include pre-release versions (beta/release candidates)**
(administrators only, off by default, one setting for the whole installation; the console records who changed it and
when, in the audit log as `update.channel`). It applies at the next check (or press **Check for updates now**).
While it is on, or while a pre-release is installed, the box shows **Beta channel**, and a pre-release in the update
window is marked **pre-release** next to its version, with its release notes from GitHub and a warning.

**Who should enable it:** people who test DENIS and are prepared to report what they find (see the
[community testing guide](community-testing.md)); not a production network you cannot afford to have a problem on.

**The warning, in full:**

* a pre-release is for testing and may contain bugs;
* a database that a pre-release has upgraded **may not open with an older program**;
* the automatic backup that DENIS makes before every update is the way back (below);
* please report problems on GitHub.

**Everything else is identical to a stable update:** the same release key signs it, the same checks run (signature,
checksum, the new program is asked for its version, a verified database backup, automatic rollback if it does not
start), and snooze, skip and schedule work per version.

**How the newest version is chosen.** With the setting off, DENIS asks GitHub for the *latest* release, exactly as
before, and a pre-release is never offered. With it on, DENIS reads the list of releases, ignores drafts, and offers
the newest one by version order: `4.1.0` is newer than `4.1.0-rc.2`, which is newer than `4.1.0-rc.1` (and `rc.10`
is newer than `rc.2`). A version only counts when its signed checksum list has been published. A downgrade is never
offered.

**When the final stable version arrives.** If you run `4.1.0-rc.2` and `4.1.0` is released, `4.1.0` is offered as a
normal update, **whether or not the setting is on**: a stable release is always newer than its own candidates. Install
it and you are back on the stable channel. After that, with the setting off, no further pre-releases are offered.

**Going back to stable without a newer stable release.** Switch the setting off (an offered pre-release is withdrawn at
once and an install scheduled for it is cancelled). A program that is already installed stays until you replace it:
stop DENIS, restore the automatic backup from the `backups` folder (`denis-before-<version>-<time>.db`, made just
before the pre-release was installed; see [Operations](operations.md#backup-and-restore)), put the previous program
back (the update kept it as `denis.previous`, or reinstall the stable release with `install.sh`), and start DENIS.
Data collected while the pre-release ran is not in that backup.

**Command line:** `denis run --update-channel prerelease` (or `DENIS_UPDATE_CHANNEL=prerelease`; the default is
`stable`) turns the setting on at start-up for a new installation. Once an administrator has saved the setting in the
console, **the saved choice wins**, like the other settings that are kept in the database.

**Agents.** The channel does not apply to agents on its own: an agent is brought to the version of its master, never
past it, so a master on a pre-release brings its agents to that pre-release only when you ask (or when the automatic mode
is on). See [Updating remote agents](#updating-remote-agents).

## If GitHub cannot be reached

Some networks block GitHub, and a shared address can be rate limited by it. If the normal version check or the
download fails, DENIS tries a second host, `https://usedenis.com`. It is used **only when GitHub fails**, for the
version check and for the download alike, and never while GitHub answers.

The second host is held to exactly the same rules as GitHub:

* **The release key decides.** The host publishes a list of what it holds (`latest.json`) signed with the same
  release key, and the same signed `SHA256SUMS` for each version. DENIS verifies both with the key built into the
  program. A file that does not verify, or whose checksum is not the signed one, is refused; a host that is
  compromised cannot push code any more than a compromised GitHub account can.
* **Only newer versions**, **HTTPS only**, a size limit on everything, and **no redirects**: an answer that redirects
  to another host is refused, not followed.
* **The outbound rules of a customer are respected.** On an MSP installation the connection is made under the
  tenant's own outbound policy (`egress.allow`, see [Multi-tenancy](multi-tenancy.md)), like any other connection DENIS
  makes on a customer's behalf.

If the host's newest version is older than the one GitHub has offered, DENIS does not install it: the console shows
"usedenis.com is behind GitHub", so a stale mirror is noticed instead of silently doing nothing. (The host is asked for
its version only after GitHub failed, so this is shown when GitHub answered once and failed afterwards, for example
at the download.)

**The setting:** *Settings → System → Updates → If GitHub is unreachable, try usedenis.com*, administrators only,
**on by default**, one setting for the whole installation (audited as `update.mirror`). Upgrading to 4.1 shows a
one-time notice about it; reading the notice or making the choice dismisses it. `--update-mirror ""` (or
`DENIS_UPDATE_MIRROR=`) removes the fallback entirely; `--no-update-check` still means nothing is contacted.

When the fallback answered, the console says so ("GitHub could not be reached, so usedenis.com answered") and the
update window shows where the version came from.

## Updating remote agents

An agent is a separate program on another network, with its own copy of the release key. It **never changes itself
unless the master's administrator allows it**, and it verifies every release itself, whatever the master says. The
master's answer to the agent's report is the only place a command is read from: the same connection the agent already
uses, to the master address it was started with, with the CA and token it already has. Nothing is opened on the agent.

**Settings → System → Updates for remote agents** (administrators; one choice per customer on an MSP installation):

| Mode | What happens |
|---|---|
| **Manually** (default) | Under **Sites** an agent that is older than the master shows **outdated**, its last update result and, for an administrator, an **Update** button (and **Update all outdated** above the table). The master remembers the request and answers the agent's next report (within about a minute) with "update to version X". |
| **Automatically** | The master gives the same command to every agent that is older than the master, with no click. Switch back to *Manually* to stop. A failed attempt is left alone for a day before it is tried again. |

Agents are always brought to **the version of the master**, never past it: update the master first, then its agents.

**Where the agent gets the new version** (same page):

| Source | What happens |
|---|---|
| **From the internet** (default) | The agent downloads the signed release itself: from GitHub, and, if the fallback setting above is on, from usedenis.com when GitHub cannot be reached. |
| **From this master** | For sites without internet access. The master downloads the release itself, verifies it exactly as for its own update, keeps it, and hands it only to the agents you asked to update, authenticated by their own token, over the same connection. Nothing is served to an agent that was not asked, to an agent of another customer, or for another platform than the one the agent reported. The agent checks the signature again before installing. Each agent may fetch a few builds per hour, and the master keeps only its own version per customer (at most 1.5 GB). |

**What the agent does**, with the same code as the master's update: it downloads the files, checks the signature on
`SHA256SUMS` against the release key built into the agent, checks the program's SHA-256 against that list, asks the new
program for its version, keeps a copy of the old program and of its own database, switches, restarts in place, and puts
the old version back by itself if the new one does not start. It **refuses**:

* any version that is not strictly newer than its own (a command can never downgrade);
* anything whose signature or checksum does not verify, or that is built for another platform;
* everything, if it was started with `--no-self-update` (the site's own switch, also `DENIS_AGENT_NO_SELF_UPDATE=1`).

If an update fails, the agent keeps running its old version and reports the error; the master shows it under **Sites**
and does not push the same version again.

**Manual update needed.** Where an agent cannot replace its own program, it says so instead of trying, and the console
shows **Manual update needed** with the reason:

* the program's folder is not writable by the agent's user, for example a systemd unit with `ProtectSystem=strict`
  and no `ReadWritePaths=` entry for that folder (the layout `install.sh` sets up for the master allows it; an agent
  installed some other way may not);
* the program carries file capabilities (`setcap`), which an updated file would lose (use systemd's
  `AmbientCapabilities` instead);
* no signed release is published for the platform (Windows, for example) or the build has no release key.

An agent older than 4.1 does not report this state and cannot take a command: the master shows "older than 4.1" and
you update it by hand once; every later update can be done from the console.

## Privacy and switching it off

Checking sends one anonymous HTTPS request to `api.github.com` every six hours (the release list instead of the latest release when pre-releases are on); GitHub sees your address, nothing
about your network or data. **Only if GitHub cannot be reached** the same check, or the download, goes to
`usedenis.com`, which then sees your address likewise and nothing else. An agent that is told to update contacts the
same hosts once for that update (or only its own master, when the source is the master). To never contact GitHub or the
fallback host (air-gapped, or you prefer to update by hand):

```bash
denis run --no-update-check      # or DENIS_NO_UPDATE_CHECK=1
```

## By hand

Download `denis-<platform>` and `SHA256SUMS` from the release, compare `sha256sum`, take a backup
(`denis backup FILE`), stop DENIS, replace the binary, start it. See [Operations](operations.md#upgrading).

## Details from the console

Explanations that used to be printed on the console screens. The console shows them behind a small ? button.

* Agents on other networks are separate programs. By default nothing happens to them: you press Update for an agent under Sites. An agent is always brought to the version of this master, never past it, and it checks the signature of every release itself before installing anything.
