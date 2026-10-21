# Updates

DENIS can tell you when a new version is out, show you what changed, and install it for you: **now or at a time you
choose**, with a backup first and without touching your data. **Security updates install by themselves** (on by
default for a new installation since 4.2, one switch to turn off): see
[Automatic security updates](#automatic-security-updates).

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
| Back up | A verified copy of your database is written to a `backups` folder beside the database (`denis-before-<version>-<time>.db`, owner-only; the newest five are kept). An attempt that stops before the switch removes its own copies again, and older copies are pruned only after a switch, so attempts that did not happen never push out the backups of updates that did. |
| Switch | The old program is kept as `denis.previous`, the new one takes its place, and DENIS restarts **in place** (same process, same arguments). |
| Confirm | After one minute of healthy running the update counts as done. If the new version fails to start twice, the **previous version comes back automatically**, together with the pre-update database if its format had changed; the console tells you what happened. |

Your data is not changed by updating: the database is migrated forward by the new version exactly as in any manual
upgrade, after the backup exists. Only newer versions are offered; a downgrade is never installed.

## Automatic security updates

**Automatic security updates are on by default, and you can switch them off:** *Settings → System → Updates →
Install security updates automatically* (administrators only, one setting for the whole installation, audited as
`update.auto` with the value before and after).

Security updates are always free of charge.

**What is installed by itself.** A stable release **of the version line that runs**: on 4.2.1, the releases 4.2.2,
4.2.3 and so on; on 4.1.6, 4.1.7. These are the releases that carry fixes for the line, security fixes included.
**Never by itself:** a new minor or major version (4.3.0, 5.0.0), a pre-release (even with pre-releases switched on;
a release counts as one when its tag has a `-` or GitHub marks it as a pre-release), a version you skipped, or a
version that had to be rolled back after it was installed (automatically or by hand). Those are offered in the update
bar as before and wait for you.

**Exactly the version it chose.** The automatic install puts in place the release it picked and nothing else. If
GitHub cannot deliver that release's files, usedenis.com is used only when it offers exactly that version; otherwise
the attempt fails with nothing changed and is tried again later. It never takes another version from the fallback
host instead.

**Skipping a patch.** *Skip this version* in the update window applies to the release offered there. When the update
bar offers a newer line (4.3.0) and a patch of the running line (4.2.4) is the one that would install by itself, that
patch cannot be skipped on its own: switch automatic security updates off, or choose a daily window, to hold it back.

**How.** Exactly the steps of a manual install, nothing skipped or weakened: the signature on `SHA256SUMS` must
verify with the release key built into the program, the file must match the signed checksum, the new program must
report its version, the database is backed up, the old program is kept, and the previous version comes back by
itself if the new one does not start. DENIS looks for a release with its regular check (every six hours, and at once
when you switch the setting on); when GitHub's newest release is a new minor version, it reads GitHub's release list
to find the newest release of the line that runs (from usedenis.com only the newest stable release is available, so
when GitHub cannot be reached a patch of an older line is found at the next check that reaches GitHub).

**When.** By default an eligible release is installed **as soon as it is found**. Under *When* you can choose
**Only inside a daily window** instead and give the hours (from, to; this server's local time, for example 2 to 5; a
window may run over midnight, 22 to 4): a release found outside the window waits for its next opening. The window
counts for the automatic security updates only. (The *Schedule* button in the update window, which existed before,
installs one offered version once at a time you pick; it is kept as it is and is the way to time a new minor version.)
Changing *When* is audited as `update.auto_timing` with the value before and after. A change of the switch and of
*When* in one save is checked as a whole and saved together, or not at all. On the night summer time starts, a window
whose hour is skipped by the clock change (2 to 3 in central Europe) opens in the hour after the jump instead; on the
night it ends, the repeated hour is just one more hour.

**Never in the middle of an enforcement action.** An install does not start while an enforcement action (a block, a
quarantine, a port change, or its removal, including *Enable port* and the switch write test) is being applied or
rolled back. At the moment the program is replaced,
DENIS waits up to a minute for running actions to end and lets no new one start until it has restarted (an action
asked for in those seconds is refused with "DENIS is installing an update"; try again a minute later). If an action
is still running after that minute, the update stops with nothing changed and is tried again shortly after.

**What you are told** (the bell, and your notification channels by their minimum level):

| What happened | Notice |
|---|---|
| Installed | *Update X was installed* (info), with the version before and "installed automatically" |
| Failed before anything was replaced (download, signature, test of the new program) | *Automatic update to X failed* (high), with the reason. Nothing changed; tried again after a day |
| The new version did not start and the previous one came back | *Update X did not start and was rolled back* (high). That version is not tried automatically again; install it by hand once the cause is known |
| A release marked as a security fix that is not installed by itself (automatic updates off, or it starts a new line) | *Security update X is available* (high). Also for a security release of the running line while the update bar offers a newer line |

**A new installation and an existing one.** A database created by DENIS 4.2 or newer starts with automatic security
updates **on**. An installation that existed before keeps its behaviour: they stay **off** until an administrator
chooses, and DENIS asks once (a notice in the bell, a banner, and the question with *Turn on* and *Keep off* in
*Settings → System → Updates*). Nothing is switched on without that choice. The default is decided at the first start
that checks for updates: a program started with `--no-update-check` decides and saves nothing (unless
`--auto-security-updates` is given), shows automatic security updates as off, and does not tell its agents to update
because of them. If the saved choice cannot be read at a start (a database error), nothing is decided or saved and
nothing is installed until it can be read; a saved value that cannot be understood counts as off until an
administrator chooses again.

**While they are off,** the Health page shows an advisory, "Security updates are not applied automatically", with a
link to the setting; *Dismiss for 30 days* hides it for 30 days. It also says so when they are on but this
installation cannot replace its own program (see the requirements below). `--no-update-check` still means nothing is
contacted, and then nothing is installed either; the advisory is not shown for such a build.

**Security releases.** The maintainer marks a release that fixes a security problem (see RELEASING.md): it then
carries a file `SECURITY-RELEASE`, and the console shows it as a security update. On usedenis.com the mark is part of
the signed list of what the host holds; on GitHub it is the presence of that file among the release's files, which is
not checked against a signature. Either way the mark is only a label: it makes the notice louder and never decides
what is installed; whether a release installs by itself depends on its version line alone, and every install is
verified with the release key as always.

**Remote agents** follow the master's choice through their own update modes (see
[Updating remote agents](#updating-remote-agents)): as long as no mode was saved for them, they follow the master
within its version line while automatic security updates are on, and wait for you while they are off.

**For scripted installations:** `denis run --auto-security-updates on|off` (or `DENIS_AUTO_SECURITY_UPDATES`) sets the
choice at start-up as long as no administrator has chosen in the console: an existing installation started with it is
not asked, and a later start with the other value changes it. **Once an administrator saves the choice in the
console, the saved choice wins**, like the other settings that are kept in the database (`--update-channel` works the
same way). Without the flag a new installation starts with them on and an existing one is asked.

**A pair of nodes (PostgreSQL).** The leader installs. The standby installs a version only after the leader has run
it for six hours (the shared record says the leader installed it and started on it), or once it becomes the leader
itself; until then it keeps running the old version. At most one automatic install starts within six hours on the
pair, whatever its version, and the start is recorded with a compare-and-set in the shared database, so the two nodes
can never both start one. If the leader installed a version by hand, the standby is not updated automatically: update
it by hand too. This order is covered by tests; it has not been tried on a real pair.

**Customers of an MSP.** The setting belongs to the installation, like the other update settings (a customer's
console cannot change it). A customer's agents follow it the same way as the installation's own agents until the
customer's administrator saves a mode in their console; their saved mode always wins, and the console shows which
mode they inherit while none is saved.

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
* Agents on remote sites are separate programs. They are updated from the master, in the mode you choose (until you
  choose, they follow the master's automatic security updates), or by hand
  ([Updating remote agents](#updating-remote-agents)). The master shows each agent's version under **Sites**.
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
| **Manually** | Under **Sites** an agent that is older than the master shows **outdated**, its last update result and, for an administrator, an **Update** button (and **Update all outdated** above the table). The master remembers the request and answers the agent's next report (within about a minute) with "update to version X". |
| **Automatically** | The master gives the same command to every agent that is older than the master, with no click. Switch back to *Manually* to stop. A failed attempt is left alone for a day before it is tried again. |
| **Security updates only** (4.2) | The same command, but only to an agent in the master's own version line (an agent on 4.2.1 when the master runs 4.2.3; not one on 4.1.x), and only while the master runs a stable release. A failed attempt waits a day, as above. |

**Until you save a mode,** the installation's own agents follow the master's [automatic security
updates](#automatic-security-updates): *Security updates only* while those are on, *Manually* while they are off (so an
installation that existed before 4.2 and has not switched them on behaves exactly as before). Once you save a mode it
stays as saved, and the console says which mode is inherited while none is saved. This holds for a customer's console
on an MSP installation too: its agents follow the installation's choice until the customer's administrator saves a
mode of their own, which always wins. The command
an agent receives is the same in every mode, so agents of 4.1 understand it.

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
fallback host (air-gapped, or you prefer to update by hand; nothing is then installed automatically either):

```bash
denis run --no-update-check      # or DENIS_NO_UPDATE_CHECK=1
```

## By hand

Download `denis-<platform>` and `SHA256SUMS` from the release, compare `sha256sum`, take a backup
(`denis backup FILE`), stop DENIS, replace the binary, start it. See [Operations](operations.md#upgrading).

## Details from the console

Explanations that used to be printed on the console screens. The console shows a short version behind the small (i) button after the label it explains; "More in the docs" in it leads here.

* Agents on other networks are separate programs. Until you choose a mode here they follow this master's automatic security updates: on, an agent in this master's version line is brought to its version; off, nothing happens to them until you press Update for an agent under Sites. An agent is always brought to the version of this master, never past it, and it checks the signature of every release itself before installing anything.
