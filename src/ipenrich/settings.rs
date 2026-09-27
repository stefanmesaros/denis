//! `SettingsStore` persistence for the enrichment config — one key per concern, exactly the
//! `ai.rs`/`sso.rs` pattern (a JSON blob per `SettingsStore` key, loaded once at start-up and
//! after every admin edit).

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::store::SettingsStore;

use super::dns::DnsConfig;
use super::geoip::GeoipConfig;
use super::service::CacheTtls;

const DNS_KEY: &str = "ipenrich.dns";
const GEOIP_KEY: &str = "ipenrich.geoip";
const CACHE_KEY: &str = "ipenrich.cache";

/// A customer's own REST API credential (bearer token/API key), when `GeoipSource` is a REST
/// provider — kept in its own key, like a notification channel's webhook secret, so it is never
/// bundled into a settings blob that might get logged or exported whole.
const CUSTOM_API_SECRET_KEY: &str = "ipenrich.custom_api_secret";

fn load<T: Default + for<'de> Deserialize<'de>>(store: &dyn SettingsStore, key: &str) -> T {
    store.get_setting(key).ok().flatten().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}
fn save<T: Serialize>(store: &dyn SettingsStore, key: &str, value: &T, now: i64) -> Result<()> {
    store.set_setting(key, &serde_json::to_vec(value)?, now)
}

pub fn dns_config(store: &dyn SettingsStore) -> DnsConfig {
    load(store, DNS_KEY)
}
pub fn save_dns_config(store: &dyn SettingsStore, cfg: &DnsConfig, now: i64) -> Result<()> {
    save(store, DNS_KEY, cfg, now)
}

pub fn geoip_config(store: &dyn SettingsStore) -> GeoipConfig {
    load(store, GEOIP_KEY)
}
pub fn save_geoip_config(store: &dyn SettingsStore, cfg: &GeoipConfig, now: i64) -> Result<()> {
    save(store, GEOIP_KEY, cfg, now)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
struct CacheTtlsRepr {
    geoip_ttl_secs: i64,
    dns_ttl_secs: i64,
}
impl Default for CacheTtlsRepr {
    fn default() -> Self {
        let d = CacheTtls::default();
        CacheTtlsRepr { geoip_ttl_secs: d.geoip_secs, dns_ttl_secs: d.dns_secs }
    }
}

pub fn cache_ttls(store: &dyn SettingsStore) -> CacheTtls {
    let r: CacheTtlsRepr = load(store, CACHE_KEY);
    CacheTtls { geoip_secs: r.geoip_ttl_secs, dns_secs: r.dns_ttl_secs }
}
pub fn save_cache_ttls(store: &dyn SettingsStore, ttls: CacheTtls, now: i64) -> Result<()> {
    save(store, CACHE_KEY, &CacheTtlsRepr { geoip_ttl_secs: ttls.geoip_secs, dns_ttl_secs: ttls.dns_secs }, now)
}

pub fn custom_api_secret(store: &dyn SettingsStore) -> Option<String> {
    store.get_setting(CUSTOM_API_SECRET_KEY).ok().flatten().and_then(|b| String::from_utf8(b).ok()).filter(|s| !s.is_empty())
}
pub fn save_custom_api_secret(store: &dyn SettingsStore, secret: &str, now: i64) -> Result<()> {
    store.set_setting(CUSTOM_API_SECRET_KEY, secret.as_bytes(), now)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::sqlite::SqliteStore;

    #[test]
    fn every_setting_round_trips_and_defaults_match_the_brief() {
        let store = SqliteStore::open_in_memory().unwrap();

        // defaults, before anything is ever saved
        assert_eq!(dns_config(&store), DnsConfig::default());
        assert_eq!(geoip_config(&store), GeoipConfig::default());
        assert_eq!(cache_ttls(&store), CacheTtls::default());
        assert_eq!(custom_api_secret(&store), None);

        let dns = DnsConfig { enabled: false, primary: "9.9.9.9".into(), secondary: None, timeout_ms: 500 };
        save_dns_config(&store, &dns, 1000).unwrap();
        assert_eq!(dns_config(&store), dns);

        let geo = GeoipConfig { source: super::super::geoip::GeoipSource::CustomMmdb { city_path: Some("/x/city.mmdb".into()), asn_path: None }, auto_update: false };
        save_geoip_config(&store, &geo, 1000).unwrap();
        assert_eq!(geoip_config(&store), geo);

        let ttls = CacheTtls { geoip_secs: 1, dns_secs: 2 };
        save_cache_ttls(&store, ttls, 1000).unwrap();
        assert_eq!(cache_ttls(&store), ttls);

        save_custom_api_secret(&store, "sk_live_abc123", 1000).unwrap();
        assert_eq!(custom_api_secret(&store).as_deref(), Some("sk_live_abc123"));
    }

    #[test]
    fn an_empty_saved_secret_reads_back_as_none_same_as_never_having_been_set() {
        let store = SqliteStore::open_in_memory().unwrap();
        save_custom_api_secret(&store, "", 1000).unwrap();
        assert_eq!(custom_api_secret(&store), None);
    }
}
