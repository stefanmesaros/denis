# Cyber Resilience Act readiness

This page describes how DENIS is being prepared for the **Cyber Resilience Act** (Regulation (EU) 2024/2847, the
"CRA"). It is written for customers, their security reviewers and auditors. It says what exists today, where the
evidence is, and what is still open. Nothing on this page is a declaration of conformity.

**DENIS is not CRA-compliant, not certified and not CE-marked.** It is designed to align with the requirements of the
CRA and is being prepared for conformity assessment. Where this page says "evidence", it points to a file or a
document a reader can open and check.

## Purpose and scope

* **Product.** DENIS (Device Enumeration & Network Inventory Security) is network detection and response software with
  an optional network access control (enforcement) function: it discovers devices passively and actively, raises
  alerts, and, when an administrator allows it, blocks or quarantines devices through firewalls, switches and
  controllers. It is a product with digital elements in the sense of the CRA: software with a data connection that
  runs on the customer's own hardware or in a container. A remote agent is the same program run in another mode.
* **Developed in the European Union (Slovakia).**
* **Manufacturer:** Štefan Mesároš, a natural person for now. DENIS is not sold yet and no legal entity exists; a legal
  entity will be established before the first sale and this page will then name it. Security contact:
  mail@usedenis.com. The postal address for the EU declaration of conformity is **to be stated by the manufacturer**
  when the declaration is prepared.
* **What this page covers:** the Community edition and the commercial licence, which are the same program, in all
  its modes (standalone, master, agent), the installer, the update mechanism and the container image.
* **What it does not cover:** the vendor-only licence tools (`license_issuer`, `license_portal`, never shipped),
  third-party services DENIS talks to, and your own deployment (network, host hardening, backups).

## Status today

* DENIS is **not currently sold.** Licences are issued manually on request. The Community edition is published on
  GitHub under the DENIS Community License.
* The CRA entered into force on **10 December 2024.** The reporting obligations for manufacturers (actively exploited
  vulnerabilities and severe incidents, Article 14) apply from **11 September 2026**, and the regulation applies in
  full from **11 December 2027.**
* The reporting date has already passed. Whether it applies to a product that is not sold but is distributed as a free
  edition is a question for a legal adviser; **this page assumes it does** and the process below is built so that it
  can be followed from the first day (see [Vulnerability handling](#vulnerability-handling-and-reporting)).
* Dates and article numbers on this page are from the regulation as the maintainer reads it. They are a reading aid,
  not legal advice. Check them against the official text before relying on them.

## Product classification (assumption)

The CRA sorts products into a default class, **Class I** and **Class II** (Annex III). Among others, Annex III lists
firewalls and intrusion detection and prevention systems in Class II, and network management systems and security
information and event management (SIEM) systems in Class I.

DENIS does network detection and response, and its enforcement function acts on firewalls, switches and
controllers. It is therefore **conservatively assumed to fall into Class II**, which needs a **third-party conformity
assessment** (by a notified body) instead of the manufacturer's own assessment.

The **final classification and the conformity assessment route are to be confirmed with a notified body or a legal
adviser.** Until then DENIS makes no claim of compliance, certification, CE marking or conformity.

## How DENIS maps to the essential requirements (Annex I)

Annex I, Part I lists the security properties a product must have; Part II lists how vulnerabilities must be handled.
The table groups them by theme. "Evidence" is where the mechanism is described or can be checked. "Status" is the
maintainer's honest reading; "partial" means a named part is missing.

### Part I: properties of the product

| Requirement (theme) | DENIS mechanism | Evidence | Status |
|---|---|---|---|
| Secure by design, risk-based | Threat model with an asset-by-asset table of controls; design reviews and code reviews before releases; the safety model for enforcement is written down | [docs/security.md](../security.md) (Threat model), [NAC.md](../../NAC.md), review records in the source repository (`archive/CODE_REVIEW_*.md`, not in the public repository) | partial: no independent assessment yet |
| Secure by default | Console listens on loopback by default; HTTPS on by default with a generated certificate; no default credentials, the first administrator password is random and shown once and must be changed; enforcement is off until an administrator switches it on; experimental connectors and actions are behind lab switches that are off on a new install and never turned on by an upgrade; Autopilot and rule actions off by default | [docs/security.md](../security.md), [docs/deployment.md](../deployment.md), [docs/enforcement.md](../enforcement.md), `src/nac_lab.rs` | done for the points listed |
| No known exploitable vulnerabilities when placed on the market | Daily `cargo audit` and `cargo deny` against the RustSec database; CI audit job; one advisory accepted with a written justification | `.github/workflows/dependency-audit.yml`, `.github/workflows/ci.yml`, `.cargo/audit.toml`, `deny.toml` | partial: the workflows are new and have not yet run on GitHub; the accepted advisory RUSTSEC-2023-0071 is documented |
| Access control and authentication | Roles (viewer, editor, administrator), per-site grants, Argon2id password hashes, lock-out and rate limits, passkeys, authenticator-app codes, optional single sign-on (OpenID Connect), session tokens stored only as SHA-256, API tokens bound to the creating account and revocable; enforcement actions need a separate permission and the person's password | [docs/security.md](../security.md) (Sign-in limits, Passkeys, TOTP), `src/auth.rs`, `src/access.rs`, `src/nac_perm.rs` | done; single sign-on has not been exercised against a real identity provider (stated in docs/security.md) |
| Confidentiality of data | HTTPS for the console and the agent channel (TLS 1.2/1.3; agents pin the master's CA, no option to skip the check); integration credentials and authenticator-app secrets stored as AES-256-GCM ciphertext under a key outside the database; secrets left out of backups by default | [docs/security.md](../security.md), `src/secrets.rs` | partial: **no encryption at rest** for the inventory database (use disk encryption); the database file is protected by owner-only file permissions (mode 0600) |
| Integrity of data and programs | Releases are checked with an Ed25519 signature over `SHA256SUMS` (key built into the program); the installer verifies the signature before it installs; the update mechanism verifies it before it replaces the program; stored enforcement plans are spent once; every enforcement action is written to a ledger before the device is touched | [docs/updates.md](../updates.md), [RELEASING.md](../../RELEASING.md), `packaging/install.sh`, `src/update.rs`, `src/nac_plan.rs` | done |
| Data minimisation | Passive observation; no telemetry; the outbound requests a default install makes on its own are listed and each can be switched off | [docs/security.md](../security.md) (Outbound connections) | done |
| Availability and resilience | Capture supervisor retries missing or failed capture interfaces on its own; long-running jobs are supervised and restarted; bounded tables and per-request limits; sign-in and token rate limits; two-node high availability on PostgreSQL | `src/capture_supervisor.rs`, `src/supervisor.rs`, [docs/high-availability.md](../high-availability.md) | partial: high availability is measured on one machine; no epoch fencing of database writes yet (planned) |
| Limited attack surface | Runs as an unprivileged user with only `CAP_NET_RAW` and `CAP_NET_ADMIN`, `NoNewPrivileges`, `ProtectSystem=strict` in the service file; every packet parser bounds-checks and is fuzz-tested; strict Content-Security-Policy; every route has a role and a remote class and a test fails the build if one is missing | `packaging/install.sh`, [docs/security.md](../security.md) (Verification performed), `src/web/policy.rs`, `src/web/remote_policy.rs`, `fuzz/` | done; fuzzing runs were short (stated in docs/security.md) |
| Reducing the impact of an incident | Enforcement kill switch and hourly limit; protected networks and hands-off list; time-limited actions rolled back; a connector never acts on its own device; automatic actions only through gated, experimental paths with a trial period; tenant isolation (one database per customer) | [docs/enforcement.md](../enforcement.md), [NAC.md](../../NAC.md), [docs/multi-tenancy.md](../multi-tenancy.md) | done in simulation; **only two enforcement capabilities have been validated on real equipment** (see below) |
| Logging and monitoring | Audit log of sign-ins, configuration and every enforcement action with old and new values; notification centre; export of events, findings and the audit log to a SIEM (syslog CEF/LEEF/JSON) | [docs/export.md](../export.md), [docs/alerting.md](../alerting.md), `src/notice.rs` | done; the audit log is not signed or write-once |
| Secure removal of data and settings | `denis erase`, *Erase all data* in the console, installer `--uninstall --purge` | [docs/deployment.md](../deployment.md), [docs/operations.md](../operations.md) | done |
| Security updates | **Automatic security updates are on by default, opt-out** (4.2): a signed, stable release of the minor line that runs is installed by itself, through the same signature, checksum, backup and rollback steps as a manual install, never while an enforcement action runs; new minor or major versions wait for the administrator. One setting switches it off (administrators, audited with the old and new value); while off, Health shows a standing advisory. An installation that existed before 4.2 keeps its behaviour and is asked once. The console checks every 6 hours and installs anything else on an administrator's action or at a chosen time; remote agents follow the master's choice within its version line unless a mode is saved for them | [docs/updates.md](../updates.md#automatic-security-updates), `src/update/auto.rs`, `src/update.rs`, `src/agent_update.rs` | done in code and tests (4.2); existing installations are on only after the administrator agrees |

### Part II: vulnerability handling

| Requirement (theme) | DENIS mechanism | Evidence | Status |
|---|---|---|---|
| Identify and document components (SBOM) | CycloneDX and SPDX bills of materials from `Cargo.lock` plus the static libpcap and musl, attached to each release | [SBOM.md](SBOM.md), `tools/sbom.sh`, `tools/sbom-extra.json` | partial: written by hand on the source tree; the release job has not run yet |
| Fix without delay; security updates | Fixes are released as patch releases of the affected minor line through the signed update path, and install automatically where automatic security updates are on; a release that fixes a security problem is marked (`SECURITY-RELEASE`, listed in its signed checksum list; on usedenis.com in the signed manifest; a label for the console only, [RELEASING.md](../../RELEASING.md)) and announced with a high notice where it is not installed by itself | `CHANGELOG.md`, [docs/updates.md](../updates.md#automatic-security-updates), [RELEASING.md](../../RELEASING.md) | done; no separate security-only release stream |
| Regular tests and reviews | About 4,700 automated tests, fuzz targets for the untrusted-input parsers, clippy with warnings as errors, a pre-release script that stops at the first failure, code reviews before releases | `tools/pre-release.sh`, `.github/workflows/ci.yml`, `fuzz/`, [RELEASING.md](../../RELEASING.md) | partial: **no independent penetration test yet** |
| Disclose fixed vulnerabilities publicly | GitHub security advisories for confirmed problems; reporters credited unless they prefer not | [SECURITY.md](../../SECURITY.md) | process exists; no advisory has been published yet from this process |
| Coordinated vulnerability disclosure policy | Private reporting through GitHub; acknowledgement within 3 working days; assessment and a fix or mitigation plan within 30 days for serious issues; up to 90 days before publication | [SECURITY.md](../../SECURITY.md) | done |
| Contact address for reports | GitHub private vulnerability reporting on the repository's Security tab, or mail@usedenis.com | [SECURITY.md](../../SECURITY.md) | done: GitHub private vulnerability reporting, or e-mail to mail@usedenis.com for reporters without a GitHub account |
| Secure distribution of updates | Signed checksum list, HTTPS, a second download host used only when GitHub cannot be reached (same signature rules, no redirects) | [docs/updates.md](../updates.md), `tools/mirror-hosting.md` | done |
| Security patches with advisory notices | Fixes ship in normal releases; the update bar and changelog tell the administrator what changed | [docs/updates.md](../updates.md), `CHANGELOG.md` | done as a commitment: security fixes are always free of charge (see support period); there is no separate security-only release stream |

## Vulnerability handling and reporting

**Receiving reports (today).** Reports come in through GitHub private vulnerability reporting or by e-mail to
mail@usedenis.com ([SECURITY.md](../../SECURITY.md)). The maintainer acknowledges within 3 working days and gives an assessment and a
fix or mitigation plan within 30 days for serious problems.

**Finding them ourselves.** A dependency check runs daily (`cargo audit`, `cargo deny`); a failed run is reported by
GitHub to the repository owner (according to the owner's notification settings). The bill of materials lets customers run their own scanners (see [SBOM.md](SBOM.md)).

**Reporting to the authorities (Article 14).** The CRA asks manufacturers to notify actively exploited vulnerabilities
and severe incidents through a single reporting platform operated by ENISA and the national CSIRT: an early warning
within 24 hours of becoming aware, a notification within 72 hours and a final report afterwards (14 days after a fix
is available for a vulnerability, one month after the notification for an incident; confirm the exact periods against
the official text). **Decided:** the manufacturer (Štefan Mesároš) files these reports and decides whether a
vulnerability is actively exploited. The process:

1. A report or a finding (own check, dependency audit, outside report) is assessed on the day it arrives.
2. The manufacturer decides whether there is evidence that the vulnerability is being exploited in the wild. If yes,
   that moment starts the 24-hour clock; the decision and its time are written down.
3. The early warning, the 72-hour notification and the final report are filed on the ENISA reporting platform.
4. Affected users are informed by the update bar and `CHANGELOG.md`, and by a GitHub security advisory.

**Still open, to be decided by the manufacturer:**

* a named deputy for when the manufacturer is not available;
* the coordinating national CSIRT and the registration on the ENISA reporting platform when it is available;
* whether a mailing list for security notices will be offered (none exists).

**Informing users.** A fixed vulnerability is described in `CHANGELOG.md` and, when it is confirmed and serious, in a
GitHub security advisory. The update bar in the console tells administrators that a new version is available.

## Support period

**Decided support period:**

* Every major version (for example 4.x) receives security fixes for **at least five years** from its first release.
* New features go only into the newest version.
* The current and the previous minor line always receive security fixes.
* Security fixes are **always free of charge**.

Until [SECURITY.md](../../SECURITY.md) and the download page are updated to say the same, they still describe the
earlier, narrower wording ("only the latest release and the `main` branch" while the project is young); this page
states the intended commitment. **Still to do:** state the end-of-support date of each release on the download page
and in the console, and decide what "supported" covers beyond security fixes.

## Known gaps and next steps

1. **Conformity assessment.** Confirm the class and choose a notified body for the third-party assessment; none has
   been approached. Harmonised standards for the CRA are not yet available, so the assessment will be against the
   essential requirements directly (or against a common specification, if one is published).
2. **Independent penetration test.** Planned with an independent party in about one to two months; not done yet. A summary without technical details will be published afterwards ([SECURITY.md](../../SECURITY.md), [docs/security.md](../security.md)).
3. **Hardware validation of enforcement.** Of the 20 connector kinds, only two capabilities (SNMP port disable and SNMP
   quarantine by VLAN) have been validated on real equipment; everything else is tested against simulations of the
   vendor's documented interface and labelled experimental ([NAC_HARDWARE_VALIDATION.md](../../NAC_HARDWARE_VALIDATION.md)).
4. **Support period:** decided (see above); publish the end-of-support dates and align SECURITY.md.
5. **Automatic security updates by default**: provided since 4.2 for new installations (opt-out); an installation
   that existed before is asked once and stays as it was until the administrator chooses (see the table).
6. **Technical documentation package** (Annex VII): design and development description, risk assessment, test
   evidence, the list of standards applied. The pieces exist across the repository; they are not yet assembled into one
   controlled package.
7. **EU declaration of conformity and CE marking:** not issued; they follow a successful assessment.
8. **Single reporting platform:** registration and internal process (see above).
9. **Encryption at rest** for the inventory database is not provided by DENIS; disk encryption is recommended.
   (Integration credentials and, since 4.2, authenticator-app secrets are stored sealed with a key kept outside the
   database.)
10. **Signed audit log:** the audit log can be exported to a SIEM but is not tamper-evident by itself.
11. **First SBOM release and daily audit run:** the CI jobs that attach the SBOM files and run the daily dependency
    check are new and untested until the next release.
12. **Manufacturer details** for the declaration: name and contact are fixed (see Scope); the legal entity to be established before the first sale and the postal address are open.

## Information for auditors

| What | Where |
|---|---|
| Product description, features, edition limits | [README.md](../../README.md), [docs/index.md](../index.md), [docs/licensing.md](../licensing.md) |
| Architecture, where each subsystem lives, what is verified | [ARCHITECTURE.md](../../ARCHITECTURE.md) |
| Threat model, controls, known limitations, verification performed | [docs/security.md](../security.md) |
| Enforcement safety model | [NAC.md](../../NAC.md), [docs/enforcement.md](../enforcement.md) |
| Hardware validation status | [NAC_HARDWARE_VALIDATION.md](../../NAC_HARDWARE_VALIDATION.md), the generated matrix in [docs/enforcement.md](../enforcement.md) |
| Multi-tenancy and isolation | [docs/multi-tenancy.md](../multi-tenancy.md) |
| High availability | [docs/high-availability.md](../high-availability.md), [HA_DEPLOYMENT.md](../../HA_DEPLOYMENT.md) |
| Vulnerability reporting policy | [SECURITY.md](../../SECURITY.md) |
| Update mechanism and signing | [docs/updates.md](../updates.md), [RELEASING.md](../../RELEASING.md), `SHA256SUMS` and `SHA256SUMS.sig` on each release |
| Software bill of materials | [SBOM.md](SBOM.md); the files are attached to each release from the first release that includes the SBOM job |
| Third-party licences | [THIRD-PARTY-LICENSES.md](../../THIRD-PARTY-LICENSES.md), `deny.toml` |
| Dependency checks | `.github/workflows/dependency-audit.yml`, `.github/workflows/ci.yml`, `.cargo/audit.toml` |
| Release process and pre-release checks | [RELEASING.md](../../RELEASING.md), `tools/pre-release.sh`, `.github/workflows/release.yml` |
| Tests | `src/` (unit tests next to the code), `tests/` (integration tests), `fuzz/` (fuzz targets) |
| Change history | `CHANGELOG.md` |
| Open work | [ROADMAP.md](../../ROADMAP.md) |

Internal code reviews are not published. Files that live only in the source repository (internal reviews and
designs in `archive/`) are given to auditors on request under a non-disclosure agreement. A public summary of the
review practice is in the next section.

## Review practice

* **Automated tests:** about 4,750 test functions in the source tree (unit tests in `src/`, integration tests in
  `tests/`), plus 18 fuzz targets for the parsers of untrusted input. Clippy runs with warnings as errors and
  `tools/pre-release.sh` stops at the first failure.
* **Code reviews before releases.** The 4.2 release had a maximum-effort review of the 4.2 changes by several
  independent reviewers. Each finding was verified and fixed with a regression test.
* **Dependencies:** checked daily against the RustSec database; a bill of materials accompanies each release.
* **Not published:** the full review reports. They are given to auditors on request under a non-disclosure agreement.
* **Independent penetration test:** planned in about one to two months; a summary without technical details will be
  published afterwards.

## Decisions summary

Decided by the manufacturer: manufacturer and place of development (above); security contact mail@usedenis.com and
GitHub private reporting; Article 14 reports filed by the manufacturer; five-year security support per major version,
security fixes always free; internal reviews not published, summary here; penetration test planned. Automatic security
updates are on by default for new installations and can be switched off (the update mechanism section describes the
implementation). Still open: deputy for reporting, CSIRT registration, legal entity and postal address, final
classification and notified body.
