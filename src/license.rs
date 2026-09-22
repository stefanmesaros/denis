//! Commercial licensing: verifies a signed license file that raises the Community edition's
//! 100-device cap and permits organisational use. See `LICENSE` and `LICENSE-COMMERCIAL.md`.
//!
//! A license file is exactly two lines: the JSON payload, then its Ed25519 signature (hex) over
//! the exact UTF-8 bytes of that first line. It is issued with `denis license-issue` (run by
//! whoever sells licenses; the matching private key never goes in this repository) and verified
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

/// How long a license is valid for once first used, unless the license itself says otherwise.
pub const DEFAULT_VALID_DAYS: u32 = 365;

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
    /// Why the license file (if any) is not in force: unreadable, bad signature, expired...
    /// `None` means either there is no license file (plain Community edition) or it is valid.
    pub problem: Option<String>,
}

impl Effective {
    fn community(problem: Option<String>) -> Effective {
        Effective { license: None, device_cap: Some(COMMUNITY_DEVICE_CAP), commercial: false, activated_at: None, problem }
    }

    pub fn over_cap(&self, device_count: u32) -> bool {
        self.device_cap.is_some_and(|cap| device_count > cap)
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
    load_with_key(path, store, LICENSE_PUBLIC_KEY)
}

fn load_with_key(path: Option<&Path>, store: &dyn Store, key: Option<[u8; 32]>) -> Effective {
    let Some(path) = path else { return Effective::community(None) };
    let raw = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => return Effective::community(Some(format!("could not read {}: {e}", path.display()))),
    };
    let (payload, license) = match verify_and_parse(&raw, key) {
        Ok(pair) => pair,
        Err(e) => return Effective::community(Some(e.to_string())),
    };
    let now = crate::model::now_ts();
    let activated = activation_time(store, &payload, now);
    let expires_at = activated + i64::from(license.valid_days.max(1)) * 86_400;
    if now > expires_at {
        Effective {
            device_cap: Some(COMMUNITY_DEVICE_CAP),
            commercial: false,
            activated_at: Some(activated),
            problem: Some(format!("the license expired {} days after it was first used here", license.valid_days)),
            license: Some(license),
        }
    } else {
        Effective { device_cap: license.device_cap, commercial: license.commercial, activated_at: Some(activated), license: Some(license), problem: None }
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

/// Build and sign a license file's contents (`denis license-issue`). `seed_hex` is the private
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

        // back-date the recorded activation to simulate 2 days having passed since first use
        let key = activation_key(text.lines().next().unwrap());
        let two_days_ago = crate::model::now_ts() - 2 * 86_400;
        store.set_setting(&key, two_days_ago.to_string().as_bytes(), two_days_ago).unwrap();

        let eff2 = load_with_key(Some(&path), &store, Some(hex32(&public)));
        assert_eq!(eff2.device_cap, Some(COMMUNITY_DEVICE_CAP));
        assert!(eff2.problem.unwrap().contains("expired"));
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
    fn bad_issued_dates_or_zero_validity_are_rejected_at_issue_time() {
        let (seed, _) = generate_keypair().unwrap();
        let mut bad_date = sample(Some(100), 365);
        bad_date.issued = "not-a-date".into();
        assert!(issue(&seed, &bad_date).is_err());
        assert!(issue(&seed, &sample(Some(100), 0)).is_err());
    }
}
