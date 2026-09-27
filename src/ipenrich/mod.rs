//! IP enrichment: reverse DNS, GeoIP/ASN and public/private classification for every IP address
//! DENIS shows, from a provider-swappable, cached, never-blocking-ingestion pipeline. See
//! `IP_ENRICHMENT.md` for the full architecture and the reasoning behind it.

pub mod cache;
pub mod classify;
pub mod decorate;
pub mod dns;
pub mod geoip;
pub mod provider;
pub mod service;
pub mod settings;
pub mod types;

pub use cache::Cache;
pub use classify::Classification;
pub use decorate::{decorate, decorate_all};
pub use dns::{DnsConfig, Resolver as DnsResolver};
pub use geoip::{GeoipConfig, GeoipSource, MmdbProvider, UpdateFrequency};
pub use provider::GeoipProvider;
pub use service::{CacheTtls, Metrics, Service};
pub use types::{Capabilities, EnrichedIp, Health, IpInfo, ProviderStatus};

use std::path::Path;
use std::sync::Arc;

use crate::store::Store;

/// The two on-disk paths DB-IP Lite's currently-installed database would be at, if it has ever
/// been installed — `None`/`None` (not an error) when it has not, which is a perfectly normal
/// "GeoIP not set up yet" state for a fresh install (`MmdbProvider::status()` then reports Down,
/// exactly as it should).
fn db_ip_lite_paths(db_path: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let dir = geoip::data_dir(db_path.parent().unwrap_or_else(|| Path::new(".")));
    (dir.join("city-current.mmdb"), dir.join("asn-current.mmdb"))
}

/// Resolves a `GeoipConfig` to what a provider actually needs to open: the two file paths (if
/// any), the name to show, and the version already on record — shared by `build_service` (start-
/// up) and `reconfigure_geoip` (an admin saving new Settings), so both ways of pointing the
/// running service at a database agree on exactly where DB-IP Lite's files live.
fn resolve_geoip_paths(store: &dyn Store, geoip_cfg: &GeoipConfig, db_path: &Path) -> (Option<std::path::PathBuf>, Option<std::path::PathBuf>, &'static str, Option<String>) {
    match &geoip_cfg.source {
        GeoipSource::DbIpLite => {
            let (city, asn) = db_ip_lite_paths(db_path);
            let version = crate::store::SettingsStore::get_setting(store, "ipenrich.geoip_db_version").ok().flatten().and_then(|b| String::from_utf8(b).ok());
            (Some(city), Some(asn), "DB-IP Lite", version)
        }
        GeoipSource::CustomMmdb { city_path, asn_path } => (city_path.as_ref().map(std::path::PathBuf::from), asn_path.as_ref().map(std::path::PathBuf::from), "Custom MMDB", None),
    }
}

/// Builds the enrichment service from whatever is already in `SettingsStore` and on disk, and
/// spawns its background worker — called once at start-up from both of `engine.rs`'s server
/// modes (capture and viewer-only), right next to where every other background job is spawned.
/// A missing/not-yet-configured GeoIP database is not an error here: the service comes up with
/// GeoIP simply unavailable (`MmdbProvider::status()` reports it), reverse DNS still works on its
/// own, and nothing about start-up depends on a database existing yet.
pub fn build_service(store: Arc<dyn Store>, db_path: &Path) -> Arc<Service> {
    let dns_cfg = settings::dns_config(&*store);
    let geoip_cfg = settings::geoip_config(&*store);
    let ttls = settings::cache_ttls(&*store);

    let provider = MmdbProvider::new();
    let (city, asn, source_name, db_version) = resolve_geoip_paths(&*store, &geoip_cfg, db_path);
    // reload() only actually opens a file when one exists (open_readfile fails, and is logged,
    // for a path that is not there yet); DB-IP Lite's paths not existing on a fresh install is
    // exactly this, expected, case, not a startup error — but still worth telling the provider
    // about (it then reports Down with a clear reason) rather than leaving it never configured.
    provider.reload(source_name, city.as_deref(), asn.as_deref(), db_version, None);

    let dns = Arc::new(DnsResolver::new(dns_cfg));
    Service::spawn(store, dns, Arc::new(provider), ttls)
}

/// Re-points the running service's GeoIP provider at whatever `SettingsStore` now says (an admin
/// just saved a new source) — the "Settings take effect within seconds, no restart" promise every
/// other config box in this console already makes, extended to GeoIP. `db_path` is `Shared`'s own
/// `db_path` field (`AppState.shared.db_path`), the same value `build_service` was given at start.
pub fn reconfigure_geoip(service: &Service, store: &dyn Store, db_path: &Path) {
    let geoip_cfg = settings::geoip_config(store);
    let (city, asn, source_name, db_version) = resolve_geoip_paths(store, &geoip_cfg, db_path);
    service.reload_geoip(source_name, city.as_deref(), asn.as_deref(), db_version);
}

const GEOIP_LAST_AUTO_CHECK_KEY: &str = "ipenrich.geoip_last_auto_check";

/// Whether the periodic job should actually attempt a download this tick — split out from
/// `run_geoip_auto_update` purely so this decision (the part with real branches worth testing) is
/// testable without spawning the loop itself and waiting on real time.
fn geoip_auto_update_due(cfg: &GeoipConfig, last_check: i64, now: i64) -> bool {
    cfg.auto_update && matches!(cfg.source, GeoipSource::DbIpLite) && now - last_check >= cfg.update_frequency.as_secs()
}

/// Periodic background job, spawned once at start-up right alongside `vulndata::run` and the
/// others: when Settings has GeoIP auto-update on (the default) and the configured source is
/// DB-IP Lite, checks on the chosen schedule (`GeoipConfig::update_frequency`) for a newer monthly
/// release and installs it exactly the way the Settings "Update now" button does. A persisted
/// "when did this last actually happen" timestamp means a restart does not re-trigger a download
/// that simply isn't due yet. On failure the timestamp is left alone, so the next 6-hourly tick
/// retries rather than waiting out the full period (a `Daily`/`Weekly`/`Monthly` DB-IP outage
/// should not turn into a much longer outage of DENIS's own data).
pub async fn run_geoip_auto_update(service: Arc<Service>, store: Arc<dyn Store>, db_path: std::path::PathBuf) {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(6 * 3600));
    tokio::time::sleep(std::time::Duration::from_secs(300)).await;
    loop {
        tick.tick().await;
        let cfg = settings::geoip_config(&*store);
        let now = crate::model::now_ts();
        let last: i64 = store.get_setting(GEOIP_LAST_AUTO_CHECK_KEY).ok().flatten().and_then(|b| String::from_utf8(b).ok()).and_then(|s| s.parse().ok()).unwrap_or(0);
        if !geoip_auto_update_due(&cfg, last, now) {
            continue;
        }
        let dir = geoip::data_dir(db_path.parent().unwrap_or_else(|| Path::new(".")));
        let result = tokio::task::spawn_blocking(move || geoip::update_now(&dir, now)).await;
        match result {
            Ok(Ok(version)) => {
                let _ = store.set_setting("ipenrich.geoip_db_version", version.as_bytes(), now);
                let _ = store.set_setting(GEOIP_LAST_AUTO_CHECK_KEY, now.to_string().as_bytes(), now);
                reconfigure_geoip(&service, &*store, &db_path);
                tracing::info!("GeoIP database auto-updated to {version}");
            }
            Ok(Err(e)) => tracing::warn!("GeoIP auto-update failed, will retry at the next check: {e:#}"),
            Err(e) => tracing::warn!("GeoIP auto-update failed, will retry at the next check: {e}"),
        }
    }
}

/// A `Service` with its worker running but nothing configured (DNS off, no GeoIP database) — for
/// every test elsewhere in the crate (`web/mod.rs`'s own test helpers) that needs a valid
/// `AppState` but is not itself testing enrichment.
#[cfg(test)]
pub fn test_service(store: Arc<dyn Store>) -> Arc<Service> {
    let dns = Arc::new(DnsResolver::new(DnsConfig { enabled: false, ..Default::default() }));
    Service::spawn(store, dns, Arc::new(MmdbProvider::new()), CacheTtls::default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn db_ip_lite_paths_live_under_a_geoip_folder_next_to_the_database_file() {
        let (city, asn) = db_ip_lite_paths(Path::new("/var/lib/denis/denis.db"));
        assert_eq!(city, Path::new("/var/lib/denis/geoip/city-current.mmdb"));
        assert_eq!(asn, Path::new("/var/lib/denis/geoip/asn-current.mmdb"));
    }

    #[tokio::test]
    async fn build_service_never_fails_on_a_fresh_install_with_no_geoip_database_yet() {
        let store: Arc<dyn Store> = Arc::new(crate::store::sqlite::SqliteStore::open_in_memory().unwrap());
        let svc = build_service(store, Path::new("/tmp/denis-test-nonexistent/denis.db"));
        let info = svc.best_effort(&["8.8.8.8".parse().unwrap()], crate::model::now_ts());
        assert!(info[&"8.8.8.8".parse().unwrap()].enriched.is_empty(), "no database yet: nothing cached, no panic");
    }

    #[test]
    fn geoip_auto_update_is_never_due_when_turned_off_or_on_a_custom_file() {
        let mut cfg = GeoipConfig { auto_update: false, ..GeoipConfig::default() };
        assert!(!geoip_auto_update_due(&cfg, 0, 100_000_000), "auto_update is off");
        cfg.auto_update = true;
        cfg.source = GeoipSource::CustomMmdb { city_path: None, asn_path: None };
        assert!(!geoip_auto_update_due(&cfg, 0, 100_000_000), "nothing for DENIS to fetch for a customer's own file");
    }

    #[test]
    fn geoip_auto_update_is_due_only_once_the_chosen_period_has_actually_elapsed() {
        let cfg = GeoipConfig { auto_update: true, source: GeoipSource::DbIpLite, update_frequency: geoip::UpdateFrequency::Weekly };
        let last_check = 1_000_000;
        assert!(!geoip_auto_update_due(&cfg, last_check, last_check + 3600), "an hour in is nowhere near a week");
        assert!(!geoip_auto_update_due(&cfg, last_check, last_check + 7 * 86_400 - 1));
        assert!(geoip_auto_update_due(&cfg, last_check, last_check + 7 * 86_400));
        assert!(geoip_auto_update_due(&cfg, last_check, last_check + 30 * 86_400), "well overdue is still due");
    }

    #[test]
    fn geoip_auto_update_is_due_immediately_on_a_fresh_install_with_no_prior_check() {
        // last_check defaults to 0 (no setting ever written) on a brand new install - it should
        // not have to wait out a full period before its very first automatic check.
        let cfg = GeoipConfig::default();
        assert!(geoip_auto_update_due(&cfg, 0, crate::model::now_ts()));
    }
}
