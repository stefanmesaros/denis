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
pub use geoip::{GeoipConfig, GeoipSource, MmdbProvider};
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
}
