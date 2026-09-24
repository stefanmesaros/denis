# A Windows build: what exists, what does not, and the plan

DENIS has no Windows build today (see README's Status section and ROADMAP.md). This document is
the groundwork for one: an honest audit of what already works, what is missing, and a phased plan
— written without touching any code, because there is no Windows machine in this environment to
build or run anything on. Writing untested platform-specific code and calling it a "Windows agent"
would be exactly the kind of unverified claim this project's own README explicitly refuses to make
elsewhere (self-update, ARP-conflict detection, the SMB/MSSQL banner readers all carry a stated
verification bar before they are called done — a Windows build deserves the same bar).

## What is already fine

Several of the small platform-specific helpers already have a Windows-safe fallback, because they
were written defensively rather than Unix-only from the start:

* `src/net.rs::default_gateway` — macOS and Linux each have a real implementation; anything else
  (including Windows) returns `None` today, which is a correct, honest "not detected" rather than
  a wrong answer. A Windows implementation (`GetIpForwardTable`/`route print`, or the `windows`
  crate) is additive, not a rewrite.
* `src/update.rs::has_file_capabilities` / `make_executable` — both already compile to a no-op
  outside their relevant platform (`#[cfg(not(target_os = "linux"))]` / `#[cfg(not(unix))]`).
  Self-update's actual logic (download, verify signature, atomic rename, roll back on failure) is
  not Unix-specific; only these two small checks are.
* `src/certs.rs::private_file` (chmod 0600 on the TLS private key) and `src/health.rs::disk_space`
  are `#[cfg(unix)]`-gated but narrow: a `#[cfg(windows)]` sibling for each (an ACL restricting the
  key to the running user; `GetDiskFreeSpaceExW`) is a bounded, separate piece of work each.
* The core pipeline (`parse.rs`, `detect.rs`, `inventory.rs`, `fingerprint.rs`, the web/API layer,
  the SQLite store) has no OS-specific code at all — it is why the collector already builds and
  runs on both macOS and Linux without a fork.

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
5. **CI.** `.github/workflows/ci.yml` builds and tests on `ubuntu-latest`/`macos-latest` only; a
   Windows build target needs its own CI job before "it compiles on Windows" can be trusted at all,
   let alone "it captures and detects correctly on Windows."

## What this deliberately does not attempt yet

An actual Windows binary, service wrapper, or installer script. Every item above needs either a
real Windows machine to build and test against, or a licensing/trust-model decision (Npcap
bundling, the service account's privilege level) that is a product decision, not an engineering
one this document can make unilaterally. Writing any of it without both would produce exactly the
kind of "should work" code this project's own testing standard exists to prevent.

## Suggested order

1. A Windows CI job that just builds the existing code (no capture yet) — cheap, and it converts
   "probably fine" for the OS-agnostic core into a real, continuously-checked fact rather than an
   assumption.
2. Fill in the small `#[cfg(windows)]` gaps this document lists (net.rs, certs.rs, health.rs,
   update.rs) — narrow, additive, each independently testable once (1) exists.
3. Decide the capture/privilege story (Npcap licensing, which account the service runs as) — a
   decision, not code, and probably worth external advice given the licensing question.
4. A minimal `denis.exe` that can `run` interactively (no service yet) against Npcap, verified on a
   real Windows machine with real traffic — the same bar `docs/security.md`'s "not yet verified"
   list already holds every other platform-sensitive capability to.
5. The service wrapper and installer, once (4) has actually been run for real.

## For IPv6

This is unrelated in code but related in spirit: see [IPV6.md](IPV6.md) for the same kind of
honest "what exists, what does not, why each step is separate" plan for IPv6 support. Both were
deliberately scoped as groundwork/design work rather than a rushed, unverifiable implementation.
