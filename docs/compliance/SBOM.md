# Software bill of materials (SBOM)

An SBOM lists every software component that is part of a DENIS release, with its version and licence, so that you
can check it against vulnerability databases and licence rules without taking our word for it. This page says
where to find the DENIS SBOM, what is in it, how to scan it and what it does not cover.

**Availability:** the SBOM files are produced by the release workflow from the first release made after
2026-10-20. Releases before that have none; for those you can generate the same files from the source tree
yourself (see [Generate it yourself](#generate-it-yourself)). Until the first release with SBOM files has run, the
release workflow step is untested in production (it was run by hand on the source tree only).

## Where to find it

Every release carries two SBOM files and one checksum file next to the programs:

| File | Format |
|---|---|
| `denis-<version>.cdx.json` | CycloneDX 1.6, JSON |
| `denis-<version>.spdx.json` | SPDX 2.3, JSON |
| `SBOM.sha256` | SHA-256 of the two files above (`sha256sum -c SBOM.sha256`) |

* On GitHub: the release page of the version at <https://github.com/stefanmesaros/denis/releases>, under *Assets*.
* On the fallback download host: `https://usedenis.com/releases/<version>/` (the same files, copied when the
  mirror is configured; the mirror is only a fallback, GitHub is the primary place).

**Integrity.** The two programs lists are signed (`SHA256SUMS` and `SHA256SUMS.sig`, see [Updates](../updates.md)).
The SBOM files are **not** part of that signed list: the update mechanism treats every `denis-*` entry of the signed
list as a program for a platform, so the SBOM files are checked with the separate `SBOM.sha256` instead, which is
not signed with the release key. Download them from the release page over HTTPS, and compare with the checksum.

## What is in it

* **Every Rust crate** in `Cargo.lock`: name, exact version, licence expression, package URL (`pkg:cargo/...`),
  project and repository URLs where the crate declares them, and the dependency edges between crates. About 450
  crates, for all supported platforms and all optional features together (so it can list a Windows-only or
  macOS-only crate that the Linux program does not contain: it describes the source release, not one binary).
* **Components that are not Rust crates** and that the two static Linux programs
  (`denis-x86_64-unknown-linux-musl`, `denis-aarch64-unknown-linux-musl`) embed: the **libpcap** packet capture
  library and the **musl** C library, as listed in `tools/sbom-extra.json`. Their versions are those of the Alpine
  packages in the `rust:1-alpine` build image on the build day; this repository does not pin them, so the SBOM
  says so and gives no version. The glibc Linux and macOS programs do not embed libpcap: they load the libpcap of
  the system they run on, which is therefore not in the SBOM and is yours to patch.
* The product itself as the main component (`denis`, the version of the release, licence: see `LICENSE`).

## What is not in it

* The operating system, Docker base image layers, your database server (PostgreSQL in the high-availability
  setup) and the JavaScript/CSS in the console: the console is plain files written for DENIS and loads no
  third-party script from the internet.
* Hashes of the individual crates: they are in `Cargo.lock`, which is part of the source. The SBOM tool does not
  copy them.
* The CycloneDX/SPDX `licenseConcluded` fields are `NOASSERTION` for crates: the licence shown is the one the
  crate declares, not a legal review. The reviewed summary is in `THIRD-PARTY-LICENSES.md`.

## Scan it

Any scanner that reads CycloneDX or SPDX works. Examples (install the scanner from its own project):

```sh
# Grype
grype sbom:./denis-4.2.0.cdx.json

# Trivy
trivy sbom ./denis-4.2.0.cdx.json

# OSV-Scanner
osv-scanner --sbom=denis-4.2.0.cdx.json
```

(Replace the version with the one you downloaded.) A hit is a crate version that matches an advisory. It is not
by itself proof that DENIS is affected: the advisory may concern a function DENIS does not call, or a platform it
does not run on. DENIS checks its own dependencies against the RustSec advisory database every day
(`cargo audit` and `cargo deny`, the workflow `dependency-audit.yml`); the one advisory accepted today,
RUSTSEC-2023-0071, is justified in `.cargo/audit.toml`. If a scanner reports something that you think matters,
report it as described in [SECURITY.md](../../SECURITY.md).

## Generate it yourself

From a checkout of the source of a release (Rust toolchain and `python3` needed):

```sh
sh tools/sbom.sh            # writes target/sbom/denis-<version>.cdx.json and .spdx.json
```

The script installs `cargo-sbom` at a pinned version if it is missing, reads `Cargo.lock`, merges
`tools/sbom-extra.json` and checks that both outputs are valid JSON with the expected number of entries. The
output has a fresh random serial number and timestamp each time, so two runs differ in those fields only.
