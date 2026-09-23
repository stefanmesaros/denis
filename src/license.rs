//! Commercial licensing: verifies a signed license file that raises the Community edition's
//! 100-device cap and permits organisational use. See `LICENSE` and `LICENSE-COMMERCIAL.md`.
//!
//! A license file is exactly two lines: the JSON payload, then its Ed25519 signature (hex) over
//! the exact UTF-8 bytes of that first line. It is issued with `license-issuer` (a separate,
//! vendor-only tool — see src/bin/license_issuer.rs — run by whoever sells licenses; the matching
//! private key never goes in this repository) and verified
//! here against `LICENSE_PUBLIC_KEY`, the same Ed25519 scheme already used for release signing
//! (see `update::sign` / `update::verify_signature`, and `denis release-keygen`).
//!
//! Validity runs from **first use, not from issuing**: the first time a given license file
//! verifies on an install, its content hash is recorded in that install's database
//! (`settings` key `license_activation:<hash>`) with the current time. It then stays valid for
//! `valid_days` from that moment, on that install — moving the same file to another install
//! starts its own year there. This needs no clock synchronised with the issuer, and a license
//! only ever starts counting down once someone actually uses it.

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::license_key::LICENSE_PUBLIC_KEY;
use crate::store::Store;
use crate::tracking::valid_date;
use crate::update::{sha256_hex, sign, verify_signature};

/// The cap in force with no license, an unreadable one, or one that failed to verify or has
/// expired: personal, non-commercial use only (see `LICENSE`, clause 1).
pub const COMMUNITY_DEVICE_CAP: u32 = 100;

/// The `settings` key a license pasted into Settings → License is stored under
/// (`web_admin::license_put`); it always takes priority over `--license-file`.
pub const SETTING_KEY: &str = "license_content";

/// How long a license is valid for once first used, unless the license itself says otherwise.
pub const DEFAULT_VALID_DAYS: u32 = 365;

/// After expiry, a license keeps working for this many more days (a higher-severity alert fires,
/// but nothing is hidden yet) before the install actually falls back to the Community edition.
pub const GRACE_DAYS: i64 = 7;

/// How many days before expiry the console starts warning (a lower-severity alert, everything
/// still fully in force).
pub const WARNING_DAYS: i64 = 30;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct License {
    pub customer: String,
    /// A label shown in the console (e.g. "business", "enterprise"); not itself checked.
    pub tier: String,
    /// `None` = unlimited devices.
    pub device_cap: Option<u32>,
    /// Always true today (clause 2 covers any organisational use); kept explicit in case a
    /// future non-commercial-but-over-cap grant is ever issued.
    pub commercial: bool,
    /// `YYYY-MM-DD` this file was generated. Informational only — validity is counted from
    /// first use, not from this date (see the module docs).
    pub issued: String,
    /// Days of validity from the moment this license file first verifies on an install.
    pub valid_days: u32,
}

/// What is actually in force right now, after trying to load and verify a license file.
#[derive(Debug, Clone)]
pub struct Effective {
    /// Present only if a license file was found, verified and parsed (even if since expired).
    pub license: Option<License>,
    /// The device cap in force right now. `None` = unlimited.
    pub device_cap: Option<u32>,
    pub commercial: bool,
    /// When this install first activated the license (first successful verification), if any.
    pub activated_at: Option<i64>,
    /// When it expires (`activated_at + valid_days`), if a license is loaded. Still set during
    /// the grace period — see `stage()`.
    pub expires_at: Option<i64>,
    /// Why the license file (if any) is not in force: unreadable, bad signature, expired (and its
    /// grace period also passed)... `None` means either there is no license file (plain Community
    /// edition), it is fully valid, or it is within its grace period (still in force).
    pub problem: Option<String>,
}

impl Effective {
    fn community(problem: Option<String>) -> Effective {
        Effective { license: None, device_cap: Some(COMMUNITY_DEVICE_CAP), commercial: false, activated_at: None, expires_at: None, problem }
    }

    pub fn over_cap(&self, device_count: u32) -> bool {
        self.device_cap.is_some_and(|cap| device_count > cap)
    }
}

/// Where a license stands relative to its expiry and grace period.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// No license, an unlimited one, or more than `WARNING_DAYS` from expiry.
    Fine,
    /// Still fully in force, within `WARNING_DAYS` of expiring.
    ExpiringSoon { days_left: i64 },
    /// Past expiry but within the `GRACE_DAYS` grace period: still fully in force.
    Grace { days_left: i64 },
    /// Past the grace period too: downgraded to the Community edition (`problem` is set).
    Expired,
}

/// Classify `eff` as of `now`. Cheap and pure — call it as often as you like (e.g. once per
/// sweep) to decide whether a warning banner or alert is due.
pub fn stage(eff: &Effective, now: i64) -> Stage {
    let Some(expires_at) = eff.expires_at else { return Stage::Fine };
    let grace_until = expires_at + GRACE_DAYS * 86_400;
    // A partial day left still counts as a whole day (round up), so "0 days left" never shows
    // while anything is still in force.
    let days_ceil = |secs: i64| (secs.max(0) + 86_399) / 86_400;
    if now >= grace_until {
        Stage::Expired
    } else if now >= expires_at {
        Stage::Grace { days_left: days_ceil(grace_until - now) }
    } else if expires_at - now <= WARNING_DAYS * 86_400 {
        Stage::ExpiringSoon { days_left: days_ceil(expires_at - now) }
    } else {
        Stage::Fine
    }
}

/// The stable subset of `ids` kept under `cap`: the numerically lowest ids (oldest-registered
/// devices) are kept, so which devices are visible does not change as they go on- or offline —
/// only newly-registered devices past the cap change what is hidden. `None` cap = keep everything.
pub fn keep_within_cap(ids: &[i64], cap: Option<u32>) -> std::collections::HashSet<i64> {
    match cap {
        None => ids.iter().copied().collect(),
        Some(cap) => {
            let mut v = ids.to_vec();
            v.sort_unstable();
            v.truncate(cap as usize);
            v.into_iter().collect()
        }
    }
}

/// Load and verify a license file, falling back to the Community edition if there is none, it
/// cannot be read, its signature does not verify, or its activation window has passed. Never
/// fails: an install always ends up with *some* effective license (Community at worst).
pub fn load(path: Option<&Path>, store: &dyn Store) -> Effective {
    let Some(path) = path else { return Effective::community(None) };
    match std::fs::read_to_string(path) {
        Ok(raw) => verify_and_activate(&raw, store, LICENSE_PUBLIC_KEY),
        Err(e) => Effective::community(Some(format!("could not read {}: {e}", path.display()))),
    }
}

/// Same as `load`, but the license text is already in hand (e.g. pasted into the console's
/// Settings → License page) rather than read from a file. See `web_admin::license_put`.
pub fn load_from_text(text: &str, store: &dyn Store) -> Effective {
    verify_and_activate(text, store, LICENSE_PUBLIC_KEY)
}

/// The license actually in force right now, freshly recomputed: a pasted one (Settings →
/// License) always takes priority over `license_file`, exactly as `web::effective_license` also
/// resolves it. Cheap enough to call periodically (e.g. once per sweep) rather than caching.
pub fn effective(store: &dyn Store, license_file: Option<&Path>) -> Effective {
    if let Ok(Some(bytes)) = store.get_setting(SETTING_KEY) {
        if let Ok(text) = String::from_utf8(bytes) {
            return load_from_text(&text, store);
        }
    }
    load(license_file, store)
}

/// Only used by tests, to check verification against a throwaway key instead of the real
/// (embedded) `LICENSE_PUBLIC_KEY`.
#[cfg(test)]
fn load_with_key(path: Option<&Path>, store: &dyn Store, key: Option<[u8; 32]>) -> Effective {
    let Some(path) = path else { return Effective::community(None) };
    match std::fs::read_to_string(path) {
        Ok(raw) => verify_and_activate(&raw, store, key),
        Err(e) => Effective::community(Some(format!("could not read {}: {e}", path.display()))),
    }
}

fn verify_and_activate(raw: &str, store: &dyn Store, key: Option<[u8; 32]>) -> Effective {
    let (payload, license) = match verify_and_parse(raw, key) {
        Ok(pair) => pair,
        Err(e) => return Effective::community(Some(e.to_string())),
    };
    let now = crate::model::now_ts();
    let activated = activation_time(store, &payload, now);
    let expires_at = activated + i64::from(license.valid_days.max(1)) * 86_400;
    let grace_until = expires_at + GRACE_DAYS * 86_400;
    if now >= grace_until {
        Effective {
            device_cap: Some(COMMUNITY_DEVICE_CAP),
            commercial: false,
            activated_at: Some(activated),
            expires_at: Some(expires_at),
            problem: Some(format!(
                "the license expired {} days after it was first used here, and the {GRACE_DAYS}-day grace period has also passed",
                license.valid_days
            )),
            license: Some(license),
        }
    } else {
        // Still fully in force, including during the grace period (expired but not yet past
        // grace): `stage()` is what tells the console/alerts to start warning.
        Effective { device_cap: license.device_cap, commercial: license.commercial, activated_at: Some(activated), expires_at: Some(expires_at), license: Some(license), problem: None }
    }
}

/// The setting key a license's activation time is stored under: content-addressed, so the same
/// file always maps to the same record, and re-issuing an unrelated license never collides.
fn activation_key(payload: &str) -> String {
    format!("license_activation:{}", sha256_hex(payload.as_bytes()))
}

/// The first time `payload` verifies on this install, `now` is recorded and returned. Every
/// later call returns that same recorded moment. If the store cannot be read or written, `now`
/// is used without being persisted — the license still works this run, just re-activates next
/// time (fails safe: never refuses to start DENIS over a settings-table hiccup).
fn activation_time(store: &dyn Store, payload: &str, now: i64) -> i64 {
    let key = activation_key(payload);
    if let Ok(Some(bytes)) = store.get_setting(&key) {
        if let Ok(ts) = std::str::from_utf8(&bytes).unwrap_or_default().parse::<i64>() {
            return ts;
        }
    }
    let _ = store.set_setting(&key, now.to_string().as_bytes(), now);
    now
}

fn verify_and_parse(raw: &str, key: Option<[u8; 32]>) -> Result<(String, License)> {
    let mut lines = raw.lines();
    let payload = lines.next().filter(|s| !s.is_empty()).context("not a license file (empty)")?;
    let sig = lines.next().context("not a license file (missing signature line)")?;
    let key = key.ok_or_else(|| anyhow!("this build has no licensing key: contact support"))?;
    if !verify_signature(&key, payload.as_bytes(), sig) {
        bail!("the license signature does not match: it was not issued for this program, or the file was edited");
    }
    let license = serde_json::from_str(payload).context("could not parse the license")?;
    Ok((payload.to_string(), license))
}

/// Build and sign a license file's contents (see `license-issuer`, src/bin/license_issuer.rs).
/// `seed_hex` is the private
/// key's hex seed (never printed or stored by this program; the caller reads it from wherever
/// they keep it, e.g. an environment variable).
pub fn issue(seed_hex: &str, license: &License) -> Result<String> {
    if !valid_date(&license.issued) {
        bail!("issued must be a date like 2026-09-22");
    }
    if license.valid_days == 0 {
        bail!("valid_days must be at least 1");
    }
    let payload = serde_json::to_string(license).context("could not serialise the license")?;
    let sig = sign(seed_hex, payload.as_bytes())?;
    Ok(format!("{payload}\n{sig}\n"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::sqlite::SqliteStore;
    use crate::update::generate_keypair;

    fn sample(device_cap: Option<u32>, valid_days: u32) -> License {
        License { customer: "Acme s.r.o.".into(), tier: "business".into(), device_cap, commercial: true, issued: "2026-01-01".into(), valid_days }
    }

    fn hex32(h: &str) -> [u8; 32] {
        let b: Vec<u8> = (0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect();
        b.try_into().unwrap()
    }

    #[test]
    fn no_license_file_is_the_community_edition() {
        let store = SqliteStore::open_in_memory().unwrap();
        let eff = load(None, &store);
        assert_eq!(eff.device_cap, Some(COMMUNITY_DEVICE_CAP));
        assert!(!eff.commercial);
        assert!(eff.license.is_none());
        assert!(!eff.over_cap(100));
        assert!(eff.over_cap(101));
    }

    #[test]
    fn a_missing_file_falls_back_to_community_with_a_reason() {
        let store = SqliteStore::open_in_memory().unwrap();
        let eff = load(Some(std::path::Path::new("/does/not/exist/license.key")), &store);
        assert_eq!(eff.device_cap, Some(COMMUNITY_DEVICE_CAP));
        assert!(eff.problem.is_some());
    }

    #[test]
    fn a_valid_license_raises_the_cap_and_activates_on_first_use() {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteStore::open_in_memory().unwrap();
        let (seed, public) = generate_keypair().unwrap();
        let text = issue(&seed, &sample(Some(1000), 365)).unwrap();
        let path = dir.path().join("license.key");
        std::fs::write(&path, &text).unwrap();

        let eff = load_with_key(Some(&path), &store, Some(hex32(&public)));
        assert_eq!(eff.device_cap, Some(1000));
        assert!(eff.commercial);
        assert!(eff.problem.is_none());
        let activated = eff.activated_at.expect("activated");

        // loading again (e.g. next start-up) keeps the same activation time, not a fresh one
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let eff2 = load_with_key(Some(&path), &store, Some(hex32(&public)));
        assert_eq!(eff2.activated_at, Some(activated));
    }

    #[test]
    fn a_license_expires_valid_days_after_first_activation_not_after_issuing() {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteStore::open_in_memory().unwrap();
        let (seed, public) = generate_keypair().unwrap();
        let text = issue(&seed, &sample(Some(1000), 1)).unwrap(); // valid for 1 day from first use
        let path = dir.path().join("license.key");
        std::fs::write(&path, &text).unwrap();

        let eff = load_with_key(Some(&path), &store, Some(hex32(&public)));
        assert!(eff.problem.is_none(), "should be valid right after activating");
        // a 1-day license is, by definition, always within the 30-day warning window
        assert!(matches!(stage(&eff, crate::model::now_ts()), Stage::ExpiringSoon { .. }));

        // back-date the recorded activation to simulate 2 days having passed since first use:
        // the 1-day license expired a day ago, but the 7-day grace period has not passed yet
        let key = activation_key(text.lines().next().unwrap());
        let two_days_ago = crate::model::now_ts() - 2 * 86_400;
        store.set_setting(&key, two_days_ago.to_string().as_bytes(), two_days_ago).unwrap();

        let eff2 = load_with_key(Some(&path), &store, Some(hex32(&public)));
        assert_eq!(eff2.device_cap, Some(1000), "still in force during the grace period");
        assert!(eff2.problem.is_none());
        assert!(matches!(stage(&eff2, crate::model::now_ts()), Stage::Grace { days_left } if days_left == 6));

        // once the grace period has *also* passed, it falls back to the Community edition
        let long_ago = crate::model::now_ts() - (1 + GRACE_DAYS + 1) * 86_400;
        store.set_setting(&key, long_ago.to_string().as_bytes(), long_ago).unwrap();
        let eff3 = load_with_key(Some(&path), &store, Some(hex32(&public)));
        assert_eq!(eff3.device_cap, Some(COMMUNITY_DEVICE_CAP));
        assert_eq!(stage(&eff3, crate::model::now_ts()), Stage::Expired);
        assert!(eff3.problem.unwrap().contains("grace period"));
    }

    #[test]
    fn expiring_soon_is_flagged_thirty_days_out_while_still_fully_in_force() {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteStore::open_in_memory().unwrap();
        let (seed, public) = generate_keypair().unwrap();
        let text = issue(&seed, &sample(Some(1000), 365)).unwrap();
        let path = dir.path().join("license.key");
        std::fs::write(&path, &text).unwrap();
        let key = activation_key(text.lines().next().unwrap());

        // activated 340 days ago: 25 days left on a 365-day license
        let activated = crate::model::now_ts() - 340 * 86_400;
        store.set_setting(&key, activated.to_string().as_bytes(), activated).unwrap();
        let eff = load_with_key(Some(&path), &store, Some(hex32(&public)));
        assert_eq!(eff.device_cap, Some(1000), "still fully in force");
        assert!(eff.problem.is_none());
        assert!(matches!(stage(&eff, crate::model::now_ts()), Stage::ExpiringSoon { days_left } if days_left == 25));
    }

    #[test]
    fn a_tampered_payload_fails_verification() {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteStore::open_in_memory().unwrap();
        let (seed, public) = generate_keypair().unwrap();
        let text = issue(&seed, &sample(Some(100), 365)).unwrap();
        let tampered = format!("{}\n{}\n", serde_json::to_string(&sample(Some(999_999), 365)).unwrap(), text.lines().nth(1).unwrap());
        let path = dir.path().join("license.key");
        std::fs::write(&path, &tampered).unwrap();

        let eff = load_with_key(Some(&path), &store, Some(hex32(&public)));
        assert_eq!(eff.device_cap, Some(COMMUNITY_DEVICE_CAP));
        assert!(eff.problem.unwrap().contains("signature"));
    }

    #[test]
    fn a_missing_or_wrong_embedded_key_falls_back_to_community() {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteStore::open_in_memory().unwrap();
        let (seed, _public) = generate_keypair().unwrap();
        let text = issue(&seed, &sample(Some(100), 365)).unwrap();
        let path = dir.path().join("license.key");
        std::fs::write(&path, &text).unwrap();

        // this build has no key at all (the real LICENSE_PUBLIC_KEY, until a licensing program exists)
        let eff = load_with_key(Some(&path), &store, None);
        assert_eq!(eff.device_cap, Some(COMMUNITY_DEVICE_CAP));
        assert!(eff.problem.unwrap().contains("no licensing key"));

        // and a key that does not match the one it was signed with
        let (_, other_public) = generate_keypair().unwrap();
        let eff2 = load_with_key(Some(&path), &store, Some(hex32(&other_public)));
        assert_eq!(eff2.device_cap, Some(COMMUNITY_DEVICE_CAP));
    }

    #[test]
    fn load_from_text_works_without_a_file_on_disk() {
        let store = SqliteStore::open_in_memory().unwrap();
        let (seed, _) = generate_keypair().unwrap();
        let text = issue(&seed, &sample(Some(250), 365)).unwrap();
        // this build's real LICENSE_PUBLIC_KEY is set, but won't match a throwaway test key,
        // so this only exercises that the text-based path reaches verification (not I/O)
        let eff = load_from_text(&text, &store);
        assert!(eff.problem.is_some());
        assert_eq!(eff.device_cap, Some(COMMUNITY_DEVICE_CAP));
    }

    #[test]
    fn bad_issued_dates_or_zero_validity_are_rejected_at_issue_time() {
        let (seed, _) = generate_keypair().unwrap();
        let mut bad_date = sample(Some(100), 365);
        bad_date.issued = "not-a-date".into();
        assert!(issue(&seed, &bad_date).is_err());
        assert!(issue(&seed, &sample(Some(100), 0)).is_err());
    }
}
