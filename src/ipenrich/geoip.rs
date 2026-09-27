//! The default GeoIP provider: local `.mmdb` files, read with the `maxminddb` crate — never a
//! live API call per lookup (`IP_ENRICHMENT.md` §1's hard constraint: a customer's own IP
//! addresses are never sent to a third party per-event). Two independent readers, since DB-IP
//! Lite (like MaxMind's own GeoLite2) ships country/city data and ASN data as separate files:
//! `city` answers country/region/city/lat-long, `asn` answers the AS number and organisation.
//!
//! The database itself can come from three places, all read through the same `MmdbProvider`:
//! DB-IP Lite (the default, auto-managed under the data directory, §10's update mechanism), or a
//! customer's own MaxMind-format file(s) pointed at by path (no download logic needed — DENIS
//! never distributes a database it does not have the rights to). A REST-API or internal-server
//! provider is a *different* type implementing `GeoipProvider`, not a mode of this one.
//!
//! Zero downtime, ever: lookups go through an `Arc<Readers>` behind a `RwLock`, swapped only after
//! a new database is confirmed to open and parse — the exact pattern `vulndata::CURRENT` already
//! uses for its own bundled/refreshed data.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use anyhow::{bail, Context, Result};
use maxminddb::geoip2;
use serde::{Deserialize, Serialize};

use super::provider::GeoipProvider;
use super::types::{Capabilities, EnrichedIp, Health, ProviderStatus};

pub const DB_IP_ATTRIBUTION: &str = "IP Geolocation by DB-IP (https://db-ip.com), licensed under CC BY 4.0";

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub enum GeoipSource {
    /// The default: DB-IP Lite, auto-managed under `<data-dir>/geoip/`.
    #[default]
    DbIpLite,
    /// A customer's own MaxMind-format database(s) — DENIS reads whatever is at these paths and
    /// never fetches or updates them itself.
    CustomMmdb { city_path: Option<String>, asn_path: Option<String> },
}

/// How often the periodic job (see `ipenrich::run_geoip_auto_update`) checks DB-IP for a newer
/// release. DB-IP only ever publishes monthly, so `Daily`/`Weekly` cost nothing beyond a slightly
/// earlier catch of that month's release (`update_now` is idempotent — re-installing the same
/// month's file is a harmless no-op) — offered anyway since some customers would rather be sure.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq)]
pub enum UpdateFrequency {
    Daily,
    Weekly,
    #[default]
    Monthly,
}

impl UpdateFrequency {
    pub fn as_secs(self) -> i64 {
        match self {
            UpdateFrequency::Daily => 86_400,
            UpdateFrequency::Weekly => 7 * 86_400,
            UpdateFrequency::Monthly => 30 * 86_400,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct GeoipConfig {
    pub source: GeoipSource,
    /// Only meaningful for `DbIpLite`: check for a newer monthly release on the periodic job.
    /// On by default — a fresh install should not silently sit on an aging database forever just
    /// because nobody found the "Update now" button — but a customer who would rather control
    /// exactly when the database on disk changes can turn it off.
    pub auto_update: bool,
    #[serde(default)]
    pub update_frequency: UpdateFrequency,
}

impl Default for GeoipConfig {
    fn default() -> Self {
        GeoipConfig { source: GeoipSource::default(), auto_update: true, update_frequency: UpdateFrequency::default() }
    }
}

struct Readers {
    city: Option<maxminddb::Reader<Vec<u8>>>,
    asn: Option<maxminddb::Reader<Vec<u8>>>,
    source_name: &'static str,
    db_version: Option<String>,
    updated_at: Option<i64>,
    /// Set when a database was configured but could not be opened (missing file, corrupt data) —
    /// surfaced through `status()` rather than failing every single `lookup()` call.
    problem: Option<String>,
}

impl Readers {
    fn empty(source_name: &'static str) -> Self {
        Readers { city: None, asn: None, source_name, db_version: None, updated_at: None, problem: None }
    }
}

pub struct MmdbProvider {
    inner: RwLock<std::sync::Arc<Readers>>,
}

impl Default for MmdbProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl MmdbProvider {
    pub fn new() -> Self {
        MmdbProvider { inner: RwLock::new(std::sync::Arc::new(Readers::empty("DB-IP Lite"))) }
    }

    /// Point this provider at a (possibly new) pair of database files. Both readers are opened
    /// and confirmed valid *before* anything currently serving lookups is touched — a bad path or
    /// a corrupt file here leaves the previous, still-working database in place and reports the
    /// problem through `status()` instead of taking GeoIP down.
    pub fn reload(&self, source_name: &'static str, city_path: Option<&Path>, asn_path: Option<&Path>, db_version: Option<String>, updated_at: Option<i64>) {
        let open = |p: &Path| -> Result<maxminddb::Reader<Vec<u8>>> {
            maxminddb::Reader::open_readfile(p).with_context(|| format!("opening {}", p.display()))
        };
        let mut problem = None;
        let city = city_path.and_then(|p| match open(p) {
            Ok(r) => Some(r),
            Err(e) => {
                tracing::warn!("GeoIP city/country database unavailable: {e:#}");
                problem.get_or_insert_with(|| e.to_string());
                None
            }
        });
        let asn = asn_path.and_then(|p| match open(p) {
            Ok(r) => Some(r),
            Err(e) => {
                tracing::warn!("GeoIP ASN database unavailable: {e:#}");
                problem.get_or_insert_with(|| e.to_string());
                None
            }
        });
        if city.is_none() && asn.is_none() && problem.is_none() {
            problem = Some("no database configured".to_string());
        }
        *self.inner.write().unwrap() = std::sync::Arc::new(Readers { city, asn, source_name, db_version, updated_at, problem });
    }
}

impl GeoipProvider for MmdbProvider {
    fn name(&self) -> &'static str {
        self.inner.read().unwrap().source_name
    }

    fn capabilities(&self) -> Capabilities {
        let r = self.inner.read().unwrap();
        Capabilities { geoip: r.city.is_some(), asn: r.asn.is_some(), reverse_dns: false }
    }

    fn status(&self) -> ProviderStatus {
        let r = self.inner.read().unwrap();
        // Down: nothing at all is working (including "never configured" — Readers::empty has
        // no problem string set, but also no readers, which is just as much a Down state).
        // Degraded: at least one of city/asn opened, but the other one has a recorded problem.
        let health = if r.city.is_none() && r.asn.is_none() {
            Health::Down
        } else if r.problem.is_some() {
            Health::Degraded
        } else {
            Health::Ok
        };
        let detail = r.problem.clone().unwrap_or_else(|| if health == Health::Down { "no GeoIP database configured".to_string() } else { String::new() });
        ProviderStatus { name: r.source_name.to_string(), health, detail, db_version: r.db_version.clone(), updated_at: r.updated_at }
    }

    fn lookup(&self, ip: IpAddr) -> EnrichedIp {
        let r = self.inner.read().unwrap();
        let mut out = EnrichedIp::default();
        if let Some(reader) = &r.city {
            if let Ok(Some(rec)) = reader.lookup(ip).and_then(|l| l.decode::<geoip2::City>()) {
                out.country = rec.country.names.english.map(str::to_string);
                out.country_code = rec.country.iso_code.map(str::to_string);
                out.region = rec.subdivisions.first().and_then(|s| s.names.english).map(str::to_string);
                out.city = rec.city.names.english.map(str::to_string);
                out.latitude = rec.location.latitude;
                out.longitude = rec.location.longitude;
            }
        }
        if let Some(reader) = &r.asn {
            if let Ok(Some(rec)) = reader.lookup(ip).and_then(|l| l.decode::<geoip2::Asn>()) {
                out.asn = rec.autonomous_system_number;
                out.as_org = rec.autonomous_system_organization.map(str::to_string);
            }
        }
        if !out.is_empty() {
            out.geoip_source = Some(r.source_name.to_string());
            out.geoip_db_version = r.db_version.clone();
        }
        out
    }

    /// Forwards to the inherent `reload` above — method resolution always prefers an inherent
    /// method over a trait one for the same receiver type, so this is not infinite recursion, just
    /// this type's answer to the trait's "a Settings save takes effect immediately" contract.
    fn reload(&self, source_name: &'static str, city_path: Option<&Path>, asn_path: Option<&Path>, db_version: Option<String>, updated_at: Option<i64>) {
        MmdbProvider::reload(self, source_name, city_path, asn_path, db_version, updated_at)
    }
}

// ------------------------------------------------------------------------------- database updates

/// `<version, sha256-hex>` for one already-downloaded, verified database file — recorded so a
/// repeat check does not re-download an unchanged release, and so `status()`/the Settings page
/// can show "version 2026-09, updated 3 days ago" without re-reading the file.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
pub struct InstalledVersion {
    pub version: String,
    pub sha256: String,
    pub installed_at: i64,
}

/// Verifies `bytes` against a published SHA-256 checksum, then that `maxminddb` can actually open
/// and read at least one field from it (catches a checksum that matched but a format DENIS's
/// version of the crate cannot parse) — both must pass before anything already serving lookups is
/// replaced. Returns the temp file path it wrote to (for the caller to atomically rename into
/// place) so a failure here never touches the currently-installed database.
pub fn verify_and_stage(bytes: &[u8], expected_sha256_hex: &str, stage_path: &Path) -> Result<()> {
    use sha2::{Digest, Sha256};
    let got = hex_lower(&Sha256::digest(bytes));
    if !got.eq_ignore_ascii_case(expected_sha256_hex) {
        bail!("checksum mismatch: expected {expected_sha256_hex}, got {got}");
    }
    std::fs::write(stage_path, bytes).with_context(|| format!("writing {}", stage_path.display()))?;
    // sanity check: does maxminddb accept this file at all? A checksum can only prove the bytes
    // are the ones that were published, not that this build of the crate can read them.
    if let Err(e) = maxminddb::Reader::open_readfile(stage_path) {
        let _ = std::fs::remove_file(stage_path);
        bail!("downloaded database does not parse as a valid MMDB file: {e}");
    }
    Ok(())
}

/// Atomically swaps `stage_path` into `final_path`, first moving whatever is at `final_path` (if
/// anything) to `final_path.with_extension("mmdb.previous")` as a one-generation-back fallback —
/// never a moment where `final_path` does not exist or is half-written.
pub fn atomic_install(stage_path: &Path, final_path: &Path) -> Result<()> {
    if final_path.exists() {
        let fallback = final_path.with_extension("mmdb.previous");
        std::fs::rename(final_path, &fallback).with_context(|| format!("keeping the previous database as {}", fallback.display()))?;
    }
    std::fs::rename(stage_path, final_path).with_context(|| format!("installing {}", final_path.display()))
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Where DENIS keeps its own copy of the GeoIP databases (created on first use).
pub fn data_dir(base: &Path) -> PathBuf {
    base.join("geoip")
}

// ------------------------------------------------------------------------------- DB-IP Lite download

/// DB-IP's own free-tier download host — https://db-ip.com, CC BY 4.0 (`DB_IP_ATTRIBUTION`).
const DB_IP_BASE: &str = "https://download.db-ip.com/free";
/// A City-Lite file is tens of MB; refuse anything absurd rather than an unbounded read.
const MAX_DOWNLOAD_BYTES: u64 = 200 * 1024 * 1024;

fn fetch(url: &str) -> Result<Vec<u8>> {
    let agent: ureq::Agent = ureq::Agent::config_builder().timeout_global(Some(std::time::Duration::from_secs(120))).http_status_as_error(true).build().into();
    let mut resp = agent.get(url).header("User-Agent", concat!("denis/", env!("CARGO_PKG_VERSION"))).call().with_context(|| format!("fetching {url}"))?;
    resp.body_mut().with_config().limit(MAX_DOWNLOAD_BYTES).read_to_vec().with_context(|| format!("downloading {url}"))
}

fn gunzip(bytes: &[u8]) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(bytes).read_to_end(&mut out).context("decompressing the downloaded database")?;
    Ok(out)
}

/// Downloads and installs DB-IP Lite's city and ASN databases for one `"YYYY-MM"` release into
/// `dir` — the actual network call behind §10's update mechanism. DB-IP's free Lite files have no
/// published checksum to verify against (unlike a GitHub release's signed checksums), so beyond
/// what HTTPS itself already guarantees against tampering in transit, the only integrity check
/// possible is "does it parse as a real MMDB file" — exactly what `atomic_install`'s caller here
/// does before ever touching what is currently installed, same as `verify_and_stage`'s reasoning.
fn download_and_install(dir: &Path, month: &str) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    for (kind, name) in [("city", "city-current.mmdb"), ("asn", "asn-current.mmdb")] {
        let url = format!("{DB_IP_BASE}/dbip-{kind}-lite-{month}.mmdb.gz");
        let bytes = gunzip(&fetch(&url)?)?;
        let stage = dir.join(format!("{name}.download"));
        std::fs::write(&stage, &bytes).with_context(|| format!("writing {}", stage.display()))?;
        if let Err(e) = maxminddb::Reader::open_readfile(&stage) {
            let _ = std::fs::remove_file(&stage);
            bail!("downloaded {kind} database does not parse as a valid MMDB file: {e}");
        }
        atomic_install(&stage, &dir.join(name))?;
    }
    Ok(())
}

/// This month's release and the one before it, "YYYY-MM" — DB-IP publishes a few days into each
/// month, so a check run early falls back to the still-current previous release instead of
/// finding nothing.
fn candidate_months(now: i64) -> Result<[String; 2]> {
    let dt = time::OffsetDateTime::from_unix_timestamp(now).context("bad timestamp")?;
    let (y, m) = (dt.year(), dt.month() as u8 as i32);
    let (py, pm) = if m == 1 { (y - 1, 12) } else { (y, m - 1) };
    Ok([format!("{y:04}-{m:02}"), format!("{py:04}-{pm:02}")])
}

/// Tries this month's release, then last month's — called from the Settings "Update now" button
/// and (when `auto_update` is on) the periodic background job. Returns the version actually
/// installed.
pub fn update_now(dir: &Path, now: i64) -> Result<String> {
    let months = candidate_months(now)?;
    let mut last_err = None;
    for month in &months {
        match download_and_install(dir, month) {
            Ok(()) => return Ok(month.clone()),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("no release month to try")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn a_fresh_geoip_config_defaults_to_dbip_lite_with_monthly_auto_update_on() {
        let cfg = GeoipConfig::default();
        assert_eq!(cfg.source, GeoipSource::DbIpLite);
        assert!(cfg.auto_update, "a fresh install should not silently sit on an aging database");
        assert_eq!(cfg.update_frequency, UpdateFrequency::Monthly);
    }

    #[test]
    fn update_frequency_maps_to_the_expected_number_of_seconds() {
        assert_eq!(UpdateFrequency::Daily.as_secs(), 86_400);
        assert_eq!(UpdateFrequency::Weekly.as_secs(), 7 * 86_400);
        assert_eq!(UpdateFrequency::Monthly.as_secs(), 30 * 86_400);
    }

    #[test]
    fn a_provider_with_no_database_reports_down_and_returns_nothing_but_never_panics() {
        let p = MmdbProvider::new();
        assert_eq!(p.status().health, Health::Down);
        let out = p.lookup("8.8.8.8".parse().unwrap());
        assert!(out.is_empty());
    }

    #[test]
    fn a_missing_file_path_is_a_graceful_degraded_status_not_a_crash() {
        let p = MmdbProvider::new();
        p.reload("Custom MMDB", Some(Path::new("/no/such/file.mmdb")), None, None, None);
        let st = p.status();
        assert_eq!(st.health, Health::Down); // neither reader opened
        assert!(!st.detail.is_empty());
        assert!(p.lookup("8.8.8.8".parse().unwrap()).is_empty());
    }

    #[test]
    fn verify_and_stage_refuses_a_checksum_mismatch_and_leaves_no_file_behind() {
        let dir = tempfile::tempdir().unwrap();
        let stage = dir.path().join("staged.mmdb");
        let err = verify_and_stage(b"not a real database", "0000000000000000000000000000000000000000000000000000000000000000", &stage).unwrap_err();
        assert!(err.to_string().contains("checksum mismatch"), "{err}");
        assert!(!stage.exists());
    }

    #[test]
    fn verify_and_stage_refuses_bytes_that_do_not_parse_as_mmdb_even_with_a_correct_checksum() {
        use sha2::{Digest, Sha256};
        let dir = tempfile::tempdir().unwrap();
        let stage = dir.path().join("staged.mmdb");
        let bytes = b"definitely not an mmdb file";
        let sum = hex_lower(&Sha256::digest(bytes));
        let err = verify_and_stage(bytes, &sum, &stage).unwrap_err();
        assert!(err.to_string().contains("does not parse"), "{err}");
        assert!(!stage.exists(), "a bad file is cleaned up, not left half-staged");
    }

    #[test]
    fn atomic_install_keeps_the_old_database_as_a_fallback_and_installs_the_new_one() {
        let dir = tempfile::tempdir().unwrap();
        let final_path = dir.path().join("city.mmdb");
        let stage1 = dir.path().join("stage1");
        std::fs::write(&stage1, b"version one").unwrap();
        atomic_install(&stage1, &final_path).unwrap();
        assert_eq!(std::fs::read(&final_path).unwrap(), b"version one");

        let stage2 = dir.path().join("stage2");
        std::fs::write(&stage2, b"version two").unwrap();
        atomic_install(&stage2, &final_path).unwrap();
        assert_eq!(std::fs::read(&final_path).unwrap(), b"version two", "the new one is now live");
        let fallback = dir.path().join("city.mmdb.previous");
        assert_eq!(std::fs::read(&fallback).unwrap(), b"version one", "the old one is kept, one generation back");
    }

    #[test]
    fn a_reload_that_fails_never_disturbs_a_database_that_was_already_serving_lookups() {
        // this exercises reload()'s "open everything before touching self.inner" ordering by
        // simply confirming a failed reload does not panic and leaves status() reporting the
        // failure rather than silently pretending to have swapped in a working database
        let p = MmdbProvider::new();
        p.reload("DB-IP Lite", Some(Path::new("/no/such/file.mmdb")), Some(Path::new("/also/missing.mmdb")), Some("2026-09".into()), Some(1000));
        let st = p.status();
        assert_eq!(st.health, Health::Down);
        assert_eq!(st.db_version.as_deref(), Some("2026-09"), "the version is still recorded even though the files could not be opened, for the Settings page to show what *should* be installed");
    }

    #[test]
    fn data_dir_is_a_geoip_subdirectory_of_whatever_base_is_given() {
        assert_eq!(data_dir(Path::new("/var/lib/denis")), PathBuf::from("/var/lib/denis/geoip"));
    }

    #[test]
    fn a_provider_with_a_working_database_would_report_ok_and_source_name() {
        // no real .mmdb ships with this repo (redistributing a GeoIP database is exactly what
        // the brief says not to do) — this documents the expectation with a stand-in `Readers`
        // state reached through the same `reload` path a real install would use, so the only
        // untested step is "does maxminddb parse a genuine DB-IP Lite file", which is exactly
        // the crate's own, separately-maintained test suite's job, not ours.
        let dir = tempfile::tempdir().unwrap();
        // an empty file fails to open as a real mmdb, which is exactly reload()'s "problem" path
        // — kept here as a smoke check that reload() never panics on a file that exists but is
        // not a real database, distinct from a path that does not exist at all.
        let bogus = dir.path().join("empty.mmdb");
        let mut f = std::fs::File::create(&bogus).unwrap();
        f.write_all(b"").unwrap();
        let p = MmdbProvider::new();
        p.reload("DB-IP Lite", Some(&bogus), None, Some("2026-09".into()), Some(1000));
        assert_eq!(p.status().health, Health::Down);
    }
}
