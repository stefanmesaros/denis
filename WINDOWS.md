# A Windows build: what exists, what does not, and the plan

DENIS has no Windows build today (see README's Status section and ROADMAP.md). This document
tracks the groundwork for one: an honest audit of what already works, what is missing, and a
phased plan. There is still no Windows machine in this environment, so nothing here has been *run*
on Windows — but as of the second pass below, the parts that can be checked by actually
cross-compiling (installed a real `x86_64-w64-mingw32` toolchain via Homebrew rather than guessing)
have been, and this document only claims what that real compiler output actually showed. Writing
untested platform-specific code and calling it a "Windows agent" would be exactly the kind of
unverified claim this project's own README explicitly refuses to make elsewhere (self-update,
ARP-conflict detection, the SMB/MSSQL banner readers all carry a stated verification bar before
they are called done — a Windows build deserves the same bar, not a lower one because it's harder
to check).

## Verified by actually cross-compiling (`--target x86_64-pc-windows-gnu`)

* `cargo check --all-targets` (lib, both binaries, and every test) **passes cleanly**, as does
  `cargo clippy --all-targets` — zero warnings. This covers everything in the previous version of
  this document's "already fine" list, plus the interface-discovery and local-time/hostname code
  below that turned out **not** to be fine (see next section): the whole non-capture codebase now
  actually type-checks and lints for Windows, not just "looks like it probably would."
* `cargo build` (which additionally *links* a real `.exe`) **fails**: the linker cannot find
  `wpcap.lib`/`libwpcap.a` — `pcap`'s Windows backend needs the **Npcap SDK's import library at
  link time**, not just at runtime. This confirms bullet 1 below is a real, immediate blocker, not
  a theoretical one: even a Windows build of DENIS that never opens a capture handle still needs
  the Npcap SDK present just to produce a binary, unless capture is made an optional Cargo feature
  (not done — see "Suggested order").

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
   would need **Npcap** (WinPcap's actively maintained successor) on Windows — a separate driver
   the user must install first, with its own licensing to check (Npcap's free tier restricts
   redistribution; bundling it into an installer is a licensing decision, not a code change).
   Capture also needs elevated privileges on Windows (raw sockets require Administrator, or Npcap's
   "WinPcap API-compatible Mode" with specific driver options) — there is no Windows equivalent of
   Linux's `setcap`/`AmbientCapabilities` that lets an unprivileged service open a capture handle,
   so the service itself likely needs to run as `LocalSystem` or a privileged account, a materially
   different trust model than the dedicated unprivileged `denis` user Linux installs use today.
2. **The service.** `packaging/install.sh` and `packaging/denis.service` set up a `systemd` unit;
   Windows needs a Windows Service (via `sc.exe`, or a Rust service wrapper such as the `windows-
   service` crate) with its own install/uninstall, start/stop, and log destination (systemd's
   journal has no Windows equivalent; Windows Event Log or a plain file would replace it).
3. **The installer.** `install.sh` is a POSIX shell script: detecting the OS/architecture,
   downloading and verifying the signed release, and registering the service are each written in
   Bash today and would need a genuine PowerShell (or a small Rust) equivalent, not a translation
   line-by-line — Windows path conventions (`%ProgramData%`, `%ProgramFiles%`), permission model
   (ACLs, not `chmod`/`setcap`), and firewall rules (`netsh advfirewall` vs `ufw`) all differ.
4. **File permissions throughout.** Anywhere the code assumes POSIX mode bits (the TLS private key,
   the SQLite database file, the one-time admin password file) needs a Windows ACL equivalent so a
   secret is not left world-readable there either.
5. **CI.** `.github/workflows/ci.yml` builds and tests on `ubuntu-latest`/`macos-latest` only. A
   `cargo check`/`clippy` job for `x86_64-pc-windows-gnu` can be added today (it already passes —
   see above) and would catch a future change that breaks Windows portability again. A real
   `cargo build`/`cargo test` job needs the Npcap SDK available in CI first (bullet 1).

## What this deliberately does not attempt yet

An actual Windows binary, service wrapper, or installer script. Every item above needs either a
real Windows machine to build and test against, or a licensing/trust-model decision (Npcap
bundling, the service account's privilege level) that is a product decision, not an engineering
one this document can make unilaterally. Writing any of it without both would produce exactly the
kind of "should work" code this project's own testing standard exists to prevent.

## Suggested order

1. ~~A Windows CI job that just builds the existing code~~ — done for `cargo check`/`clippy` (see
   above); a real `cargo build` needs step 2 first.
2. Get the Npcap SDK's import library into the build, one way or another: either check in a
   pre-converted `.a` (mingw-compatible) copy for CI/cross-builds, or make `pcap`/capture an
   optional Cargo feature so a Windows build can at least link *without* capture until this is
   resolved for real. Either is a real decision (licensing of redistributing a converted SDK
   artifact; whether a capture-less Windows build is worth shipping as an interim step) that this
   document flags rather than picks unilaterally.
3. ~~Fill in the remaining small `#[cfg(windows)]` gaps (certs.rs, health.rs)~~ — done, checked the
   same way net.rs's were (`cargo check`/`clippy --target x86_64-pc-windows-gnu`, both clean).
4. Decide the capture/privilege story (Npcap *runtime* licensing for end users, which account the
   service runs as) — a product decision, not code.
5. A minimal `denis.exe` that can `run` interactively (no service yet) against Npcap, verified on a
   real Windows machine with real traffic — the same bar `docs/security.md`'s "not yet verified"
   list already holds every other platform-sensitive capability to.
6. The service wrapper and installer, once (5) has actually been run for real.

## For IPv6

This is unrelated in code but related in spirit: see [IPV6.md](IPV6.md) for the same kind of
honest "what exists, what does not, why each step is separate" plan for IPv6 support. Both were
deliberately scoped as groundwork/design work rather than a rushed, unverifiable implementation.
