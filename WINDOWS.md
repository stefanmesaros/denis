# A Windows build: what exists, what does not, and the plan

DENIS has no finished Windows build today (see README's Status section and ROADMAP.md), but as of
2026-09-30 real progress exists: a real Windows 11 machine (via `--target x86_64-pc-windows-gnu`
cross-compilation for everything checked from this side, and a genuine `cargo build --release` run
on the Windows machine itself for everything in the next section) has actually built and run parts
of it, **including local packet capture with real traffic** (see "Verified on a real Windows
machine" below). This document tracks the groundwork: an honest audit of what already works, what
is missing, and a phased plan, updated only with what was actually run, not what "should" work.
Writing untested platform-specific code and calling it a "Windows agent" would be exactly the kind
of unverified claim this project's own README explicitly refuses to make elsewhere (self-update,
ARP-conflict detection, the SMB/MSSQL banner readers all carry a stated verification bar before
they are called done — a Windows build deserves the same bar, not a lower one because it's harder
to check).

## Verified on a real Windows machine (2026-09-30): local capture works

The interface-naming fix below (shipped in v2.48.0, "cross-compile-clean but not yet re-verified
live" at the time) has now actually been run: `denis.exe run` (agent name `windows-test-laptop`,
DENIS v2.50.0) opened a real adapter on the Windows 11 machine's own network and captured real
traffic, reporting to the same production master over Tailscale used for the earlier `agent`-mode
test. Observed directly from the master's own database (read-only inspection, not the console UI):

* **42 devices discovered** on the machine's `10.0.10.0/24` segment within about two minutes of the
  agent's first report, with real vendor OUIs (Apple, TP-Link, Ubiquiti, ASUS, Western Digital,
  Espressif, D-Link and others) — this is genuine ARP/traffic-based discovery, not a static list.
* **Port scanning and OS fingerprinting both work** through this path: banners and open ports
  (SSH, HTTP/HTTPS, SMB, NFS, AFP, OpenVPN, AirPlay, Webmin, rpcbind) were read back correctly, and
  `os_guess` correctly distinguished Linux, "Unix-like", iOS, and "Embedded firmware (lwIP/RTOS)"
  across different devices on the same segment.
* **The detection engine correctly consumes this agent's data**: `new_device` events and an
  `arp_conflict` alert (two ASUS Wi-Fi radios claiming the same IP moments apart, a real and
  correctly-scored finding, not a Windows-specific artifact) were generated directly from packets
  this Windows agent captured, flowing through the same pipeline as every Linux/macOS agent.
* The agent kept reporting continuously (`last_report_at` within 1–2 seconds of "now" on repeated
  checks), with no capture errors observed in this window.

This confirms the `net.rs` `FriendlyName`/`AdapterName` fix (below) genuinely resolved the original
`libpcap error: Error opening adapter: ...(123)` failure, not just cross-compiled clean. **Not yet
observed in this pass**: behavior over a longer run (hours/days), the Windows Service wrapper (this
was `denis.exe run`, interactive, not a service), and elevated-privilege/service-account behavior
(item 1 under "What is genuinely missing" below) — those remain open.

## Verified on a real Windows machine (2026-09-29)

* **The Npcap SDK's linking blocker (below) is resolved in practice**: pointing the `LIB`
  environment variable at the Npcap SDK's `Lib\x64` folder (`set LIB=%LIB%;C:\npcap-sdk\Lib\x64`)
  before `cargo build --release` is enough — a real `denis.exe` linked successfully, once Visual
  Studio Build Tools' "Desktop development with C++" workload was also installed (the other half
  of that same blocker: `link.exe`/`wpcap.lib` are two separate missing pieces, not one). No code
  change was needed for this part; it was a build-environment gap, not a source gap.
* **`denis.exe agent` reached a real master over Tailscale and authenticated successfully**: built
  from source on the Windows machine, run against a master's `--ingest-listen` address bound to a
  Tailscale-only interface, with a real agent token and `--master-ca`. This is the agent-forwarding
  path (`denis.exe agent`, not local capture) — confirms the reporting/HTTP/TLS/auth side of the
  Windows binary genuinely works end to end against a real DENIS master, independent of capture.
* **`denis.exe run` (local capture) failed, and the fix is now identified and cross-compile-clean,
  but not yet re-verified live**: opening the discovered interface failed with `libpcap error:
  Error opening adapter: The filename, directory name, or volume label syntax is incorrect. (123)`.
  Root cause: `net.rs`'s Windows interface discovery (written and cross-compile-checked, but never
  run for real, in the previous pass below) used `GetAdaptersAddresses`' `FriendlyName` (the
  localized, human-readable name Explorer shows — "Pripojenie bezdrôtovej siete" in this case) as
  the identifier handed to `pcap::Capture::from_device`. Npcap's capture API never accepts that —
  only its own device-name convention, `\Device\NPF_{GUID}`, built from the same call's
  `AdapterName` field. Fixed: `Iface` now carries both `name` (the Npcap device string, what
  capture actually opens) and `display_name` (`FriendlyName`, for the Settings interface picker,
  which showed only `name` before and would otherwise show the same illegible GUID string a person
  cannot recognise as "their Wi-Fi"). This exact class of gap — code that only ever compiled
  clean, never ran — is precisely why this document does not call anything "done" from a
  cross-compile alone; the next real Windows run is what confirms the fix, not this one.

## Verified by actually cross-compiling (`--target x86_64-pc-windows-gnu`)

* `cargo check --all-targets` (lib, both binaries, and every test) **passes cleanly**, as does
  `cargo clippy --all-targets` — zero warnings. This covers everything in the previous version of
  this document's "already fine" list, plus the interface-discovery and local-time/hostname code
  below that turned out **not** to be fine (see next section): the whole non-capture codebase now
  actually type-checks and lints for Windows, not just "looks like it probably would."
* `cargo build` (which additionally *links* a real `.exe`) **fails** from this cross-compile
  environment specifically, because it has no Npcap SDK on its own `LIB` path — the linker cannot
  find `wpcap.lib`/`libwpcap.a`, confirming `pcap`'s Windows backend needs the **Npcap SDK's import
  library at link time**, not just at runtime. Resolved in practice on a real Windows machine (see
  the section above) simply by pointing `LIB` at the SDK's `Lib\x64` folder — no code change, no
  Cargo feature needed after all; the earlier "make capture optional" idea in "Suggested order"
  below was a hedge against this being harder than it turned out to be.

## Fixed this pass (previously Unix-only, now has a real `#[cfg(windows)]` implementation)

`src/net.rs` used `nix`/`libc` APIs with **no Windows equivalent at all** — this was not "probably
fine," it flatly failed to compile until fixed:

* `list_interfaces` / `list_all_up` (`nix::ifaddrs::getifaddrs`, POSIX-only) now have a Windows
  implementation via `GetAdaptersAddresses` (the Win32 API Npcap's own examples use for this).
  **Unverified beyond compiling and linting clean**: the linked-list/buffer-retry handling follows
  Microsoft's documented pattern, but nothing has run it against a real adapter list.
* `local_utc_offset_secs` (`libc::localtime_r`/`tm_gmtoff`, which does not exist on Windows' CRT)
  now uses `GetTimeZoneInformation` instead. Same caveat: written against documented behaviour
  (including its inverted sign convention versus the Unix version), not run for real.
* `local_hostname` (`nix::unistd::gethostname`) now reads the `COMPUTERNAME` environment variable
  on Windows, which needs no unsafe FFI at all.

New dependency: `windows-sys`, scoped to `[target.'cfg(windows)'.dependencies]` so it affects
nothing on macOS/Linux.

## What is already fine (unchanged from before, still true)

* `src/update.rs::has_file_capabilities` / `make_executable` — both already compile to a no-op
  outside their relevant platform. Self-update's actual logic (download, verify signature, atomic
  rename, roll back on failure) is not Unix-specific; only these two small checks are.
* `src/certs.rs::private_file` (chmod 0600 on the TLS private key) and `src/health.rs::disk_space`
  now have `#[cfg(windows)]` siblings (an `icacls` call restricting the key to the running user's
  account — the documented, scriptable way to do it, not a raw Win32 ACL rewrite; `GetDiskFreeSpaceExW`
  for free/total bytes). **Unverified beyond compiling and linting clean** on the cross-compile
  target, exactly like `net.rs`'s pieces above: nothing has actually run on a Windows machine.
* The core pipeline (`parse.rs`, `detect.rs`, `inventory.rs`, `fingerprint.rs`, the web/API layer,
  the SQLite store) has no OS-specific code at all.

## What is genuinely missing, and why each is its own step

1. **Packet capture.** DENIS captures via the `pcap` crate, which links libpcap on macOS/Linux and
   needs **Npcap** (WinPcap's actively maintained successor) on Windows — a separate driver the
   user must install first (confirmed: build-time needs the Npcap *SDK*, runtime needs the Npcap
   *driver* itself — two different downloads from npcap.com), with its own licensing to check
   (Npcap's free tier restricts redistribution; bundling it into an installer is a licensing
   decision, not a code change). The interface-naming bug that was the actual immediate blocker is
   now confirmed fixed on real hardware (see "Verified on a real Windows machine (2026-09-30)"
   above): capture opens and reports real traffic. Still open: this ran interactively, as the
   signed-in user (not yet as a service or as a different, more restricted account).
   **Correction (2026-09-30), researched rather than assumed: this document previously said
   raw-socket capture "requires Administrator... so the service itself likely needs to run as
   `LocalSystem`". That was wrong.** Npcap is an NDIS filter driver, not raw sockets, and its
   default install (`/admin_only=no`, the out-of-the-box setting) makes the capture devices
   readable by *any* local user, including an unprivileged service account — no group membership
   or registry change needed. There is no separate "Npcap users" group (a real per-group ACL is an
   open, unassigned upstream feature request). The *other* installer setting, "Restrict Npcap
   driver's access to Administrators only" (`/admin_only=yes`, off by default), is what actually
   forces `LocalSystem`/Administrator — an administrator choosing that setting is choosing the
   restriction, not something DENIS's own service account model should assume by default.
   **Recommendation: a dedicated low-privilege Windows service account (a virtual account, `NT
   SERVICE\denis`), not `LocalSystem`**, mirroring Linux's own unprivileged `denis` user as closely
   as Windows allows — the same reasoning as Linux's dedicated account: this process parses hostile
   network traffic, exactly where a parsing bug becomes worse if the process is SYSTEM. This is
   not a novel or risky choice: Microsoft's own Defender for Identity sensor, also Npcap-based,
   ships exactly this way (its service runs as `LocalService`, installing Npcap with
   `/admin_only=no`). `LocalSystem` should remain a documented fallback only for administrators who
   deliberately set `admin_only=yes` on their own network. **Not yet verified: whether `NT
   SERVICE\denis` can actually list adapters and open a capture on the real Windows 11 test
   machine** — everything above is Npcap's own documented behavior, not something run here yet.
2. **The service.** ~~Written (2026-09-30), unverified~~: `src/winservice.rs` (`#[cfg(windows)]`)
   plus `denis service install|uninstall|start|stop`/the hidden `denis service run` the Service
   Control Manager itself invokes, using the `windows-service` crate. Deliberately a thin wrapper
   rather than hosting the engine's own async runtime inside the SCM's callback: the service
   supervises an ordinary `denis.exe run <args>` **child process** (the same pattern NSSM and
   similar wrappers use), so the well-tested `run` code path is untouched by any of this — nothing
   here can regress it. A control handler responds to Stop/Shutdown; output that would have gone to
   systemd's journal goes to a plain `service.log` next to the executable instead (no Windows Event
   Log integration yet). Checked only by `cargo check`/`clippy --target x86_64-pc-windows-gnu`
   (clean, and covered by CI's `windows-check` job going forward) — **not run on a real Windows
   machine**: whether the SCM actually accepts this service, starts the child correctly, and
   delivers Stop control in time is all still open. The service account is still whatever an
   administrator sets in the Services console after `install` (defaults to `LocalSystem`) — wiring
   up `NT SERVICE\denis` programmatically at install time is not done (bullet 1's own recommendation
   is unaffected by this; it is just not automated yet).
3. **The installer.** ~~Written (2026-09-30), unverified, and necessarily partial~~:
   `packaging/install.ps1` installs an already-built `denis.exe` (there is no signed Windows
   release to download yet — CI cannot even link one without the Npcap SDK, bullet 1), copies it to
   `%ProgramFiles%\DENIS`, creates `%ProgramData%\DENIS` restricted to Administrators/SYSTEM via
   `icacls` (the ACL equivalent of the systemd units' `StateDirectoryMode=0700`,
   SECURITY_ARCHITECTURE_REVIEW.md M10), registers and starts the service, and optionally opens the
   listen port in Windows Firewall (`New-NetFirewallRule`, only for a non-loopback address, never
   silently). What `install.sh` does that this deliberately does **not** yet: download a release,
   or verify an Ed25519 signature/SHA-256 checksum against it — both need a real signed Windows
   artifact to exist first. CI's `windows-installer-syntax` job parses this script on a real
   `windows-latest` runner (so it is at least known to be syntactically valid PowerShell), but
   nothing has actually executed it — the install steps, the ACL restriction, and the firewall rule
   are all unverified against a real Windows machine.
4. **File permissions throughout.** Anywhere the code assumes POSIX mode bits (the TLS private key,
   the SQLite database file, the one-time admin password file) needs a Windows ACL equivalent so a
   secret is not left world-readable there either.
5. **CI.** ~~Done~~: `.github/workflows/ci.yml`'s `windows-check` job runs `cargo check`/`clippy
   --target x86_64-pc-windows-gnu --all-targets` on every push and PR, so a future change that
   breaks Windows portability is caught the way `net.rs`'s original gap should have been. A real
   `cargo build`/`cargo test` job (one that actually links and runs) still needs the Npcap SDK
   available in CI first (bullet 1) - that part is still missing. A second job,
   `windows-installer-syntax`, parses `packaging/install.ps1` on a real `windows-latest` runner
   (there is no Windows binary yet for it to actually install - see item 2 below).

## What this deliberately does not attempt yet

Claiming any of the above - the service wrapper, the installer, or a signed Windows release - as
*done*. All three now exist as code (see items 2, 3 and 5), written and cross-compile/lint or
parse checked exactly like every other Windows-only piece here before it was run for real, but
none of them have been. A real Windows machine to build and run the service wrapper against, and a
licensing/trust-model decision (Npcap bundling, whether to automate the `NT SERVICE\denis` account
at install time) that is a product decision, not an engineering one this document can make
unilaterally, are both still needed before any of this is genuinely usable.

## Suggested order

1. ~~A Windows CI job that just builds the existing code~~ — done for `cargo check`/`clippy` (see
   above); a real `cargo build` needs step 2 first.
2. ~~Get the Npcap SDK's import library into the build~~ — resolved in practice on a real machine:
   point `LIB` at the SDK's `Lib\x64` folder, no code or CI change needed. A real Windows *CI* job
   would still need the SDK fetched into the runner first (a licensing question for redistributing
   it in CI, not for a person building locally themselves), so CI itself is still `check`/`clippy`
   only — this step is done for a local/manual build, not yet for CI.
3. ~~Fill in the remaining small `#[cfg(windows)]` gaps (certs.rs, health.rs)~~ — done, checked the
   same way net.rs's were (`cargo check`/`clippy --target x86_64-pc-windows-gnu`, both clean).
4. ~~Decide the capture/privilege story (which account the service runs as)~~ — researched
   2026-09-30 (see "Verified on a real Windows machine" above for the correction and
   recommendation): a dedicated low-privilege virtual service account (`NT SERVICE\denis`), not
   `LocalSystem`, matching Microsoft Defender for Identity's own precedent. Not yet verified live.
   Npcap *runtime* redistribution licensing for end users is still an open product decision.
5. ~~A minimal `denis.exe` that can `run` interactively (no service yet) against Npcap, verified on
   a real Windows machine with real traffic~~ — done (2026-09-30): both `denis.exe agent` (the
   reporting path) and `denis.exe run` (local capture, the interface-naming fix) are confirmed
   working end to end against a real master, with real traffic, real port scans, real OS
   fingerprints and real detection events. See "Verified on a real Windows machine (2026-09-30)"
   above for specifics.
6. ~~The service wrapper and installer~~ — written (2026-09-30): `src/winservice.rs` (`denis
   service install|uninstall|start|stop`, using the `windows-service` crate) and
   `packaging/install.ps1`. Both are cross-compile/lint or parse checked only (see items 2 and 3
   above) - **running either for real on a Windows machine is the next actual step**, not a
   further round of writing more unverified code.

## For IPv6

This is unrelated in code but related in spirit: see [IPV6.md](IPV6.md) for the same kind of
honest "what exists, what does not, why each step is separate" plan for IPv6 support. Both were
deliberately scoped as groundwork/design work rather than a rushed, unverifiable implementation.
