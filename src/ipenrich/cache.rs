//! The shared IP-enrichment cache: an in-process memory tier (checked first, sub-microsecond) in
//! front of the `IpCacheStore` SQLite tier (survives a restart) — the "both" combination decided
//! in `IP_ENRICHMENT.md` §7. GeoIP and reverse-DNS are cached independently, each with its own
//! TTL, so a stale hostname can be re-resolved without discarding still-fresh GeoIP data for the
//! same address, and vice versa.
//!
//! This module only knows about storage and freshness; it never calls a provider itself (that is
//! `mod.rs`'s `IpEnrichmentService`, which decides *whether* to call one based on what `Cache`
//! reports is still missing or stale).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;

use anyhow::Result;

use crate::store::IpCacheStore;

use super::types::EnrichedIp;

#[derive(Clone, Debug, Default)]
struct Row {
    enriched: EnrichedIp,
    geoip_expires_at: Option<i64>,
    dns_expires_at: Option<i64>,
}

/// What a lookup needs to tell the caller: the best data on hand right now (possibly empty, or
/// possibly stale-but-still-returned so the UI has *something* while a refresh happens in the
/// background), plus whether each sub-part is still within its TTL.
#[derive(Debug, Clone, PartialEq)]
pub struct Lookup {
    pub enriched: EnrichedIp,
    pub geoip_fresh: bool,
    pub dns_fresh: bool,
}

pub struct Cache {
    mem: Mutex<HashMap<IpAddr, Row>>,
}

impl Default for Cache {
    fn default() -> Self {
        Self::new()
    }
}

impl Cache {
    pub fn new() -> Self {
        Cache { mem: Mutex::new(HashMap::new()) }
    }

    /// Best data on hand for `ip` right now, and whether each sub-part is still fresh. Checks
    /// memory first; on a miss there, falls through to `store` and populates memory so the next
    /// call for the same IP never touches SQLite again.
    pub fn get(&self, store: &dyn IpCacheStore, ip: IpAddr, now: i64) -> Result<Lookup> {
        if let Some(row) = self.mem.lock().unwrap().get(&ip) {
            return Ok(Lookup { enriched: row.enriched.clone(), geoip_fresh: is_fresh(row.geoip_expires_at, now), dns_fresh: is_fresh(row.dns_expires_at, now) });
        }
        let Some((json, geoip_expires_at, dns_expires_at)) = store.get_ip_cache(&ip.to_string())? else {
            return Ok(Lookup { enriched: EnrichedIp::default(), geoip_fresh: false, dns_fresh: false });
        };
        let enriched: EnrichedIp = serde_json::from_slice(&json).unwrap_or_default();
        let row = Row { enriched: enriched.clone(), geoip_expires_at, dns_expires_at };
        let lookup = Lookup { enriched, geoip_fresh: is_fresh(row.geoip_expires_at, now), dns_fresh: is_fresh(row.dns_expires_at, now) };
        self.mem.lock().unwrap().insert(ip, row);
        Ok(lookup)
    }

    /// Merge freshly-fetched GeoIP fields in and write through both tiers, with a new expiry
    /// `ttl_secs` out. Never touches the DNS expiry of the same row (see `EnrichedIp::merge_from`
    /// and the `V16` schema note on why each sub-part is independent).
    pub fn put_geoip(&self, store: &dyn IpCacheStore, ip: IpAddr, data: &EnrichedIp, ttl_secs: i64, now: i64) -> Result<()> {
        self.merge_and_store(store, ip, data, Some(now + ttl_secs), None)
    }

    /// Merge a freshly-resolved (or freshly-failed, i.e. `hostname: None`) reverse-DNS answer in.
    /// A failed lookup still sets the expiry (so a broken resolver is not retried on every single
    /// event until its own TTL passes) but never overwrites `hostname` with `None` if a still-live
    /// answer from the same window would clobber a real one — `merge_from` already never touches
    /// a field the new side has as `None`, so this is naturally safe as long as callers pass
    /// exactly one field (`hostname`/`dns_source`) here, which `dns.rs` does.
    pub fn put_dns(&self, store: &dyn IpCacheStore, ip: IpAddr, data: &EnrichedIp, ttl_secs: i64, now: i64) -> Result<()> {
        self.merge_and_store(store, ip, data, None, Some(now + ttl_secs))
    }

    fn merge_and_store(&self, store: &dyn IpCacheStore, ip: IpAddr, data: &EnrichedIp, geoip_expires_at: Option<i64>, dns_expires_at: Option<i64>) -> Result<()> {
        let merged = {
            let mut mem = self.mem.lock().unwrap();
            let row = mem.entry(ip).or_default();
            row.enriched.merge_from(data);
            if geoip_expires_at.is_some() {
                row.geoip_expires_at = geoip_expires_at;
            }
            if dns_expires_at.is_some() {
                row.dns_expires_at = dns_expires_at;
            }
            row.enriched.clone()
        };
        store.set_ip_cache(&ip.to_string(), &serde_json::to_vec(&merged)?, geoip_expires_at, dns_expires_at)
    }

    /// Drop everything from the memory tier (not SQLite) — used only by tests that need a clean
    /// slate without spinning up a second `Cache`.
    #[cfg(test)]
    fn clear_memory(&self) {
        self.mem.lock().unwrap().clear();
    }
}

fn is_fresh(expires_at: Option<i64>, now: i64) -> bool {
    expires_at.is_some_and(|t| t > now)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::sqlite::SqliteStore;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn a_miss_reports_nothing_fresh_and_an_empty_answer() {
        let store = SqliteStore::open_in_memory().unwrap();
        let cache = Cache::new();
        let l = cache.get(&store, ip("8.8.8.8"), 1000).unwrap();
        assert!(l.enriched.is_empty());
        assert!(!l.geoip_fresh && !l.dns_fresh);
    }

    #[test]
    fn a_geoip_write_is_read_back_fresh_immediately_and_after_a_memory_clear() {
        let store = SqliteStore::open_in_memory().unwrap();
        let cache = Cache::new();
        let geo = EnrichedIp { country: Some("US".into()), asn: Some(15169), geoip_source: Some("DB-IP Lite".into()), ..Default::default() };
        cache.put_geoip(&store, ip("8.8.8.8"), &geo, 3600, 1000).unwrap();

        let l = cache.get(&store, ip("8.8.8.8"), 1000).unwrap();
        assert_eq!(l.enriched.country.as_deref(), Some("US"));
        assert!(l.geoip_fresh);
        assert!(!l.dns_fresh); // never set

        // simulate a restart: the memory tier is gone, only SQLite remains
        cache.clear_memory();
        let l2 = cache.get(&store, ip("8.8.8.8"), 1000).unwrap();
        assert_eq!(l2.enriched.country.as_deref(), Some("US"));
        assert!(l2.geoip_fresh);
    }

    #[test]
    fn geoip_and_dns_ttls_are_independent_of_each_other() {
        let store = SqliteStore::open_in_memory().unwrap();
        let cache = Cache::new();
        let geo = EnrichedIp { country: Some("DE".into()), ..Default::default() };
        cache.put_geoip(&store, ip("1.1.1.1"), &geo, 30 * 86_400, 1000).unwrap(); // 30 days
        let dns = EnrichedIp { hostname: Some("one.one.one.one".into()), ..Default::default() };
        cache.put_dns(&store, ip("1.1.1.1"), &dns, 86_400, 1000).unwrap(); // 24 hours

        // just past the DNS TTL but well within the GeoIP one
        let l = cache.get(&store, ip("1.1.1.1"), 1000 + 86_400 + 1).unwrap();
        assert!(l.geoip_fresh, "geoip still has 29 days left");
        assert!(!l.dns_fresh, "dns just expired");
        // both fields are still present even though one is stale — a caller can still show it
        assert_eq!(l.enriched.country.as_deref(), Some("DE"));
        assert_eq!(l.enriched.hostname.as_deref(), Some("one.one.one.one"));
    }

    #[test]
    fn an_expired_entry_still_returns_its_data_but_reports_itself_stale() {
        let store = SqliteStore::open_in_memory().unwrap();
        let cache = Cache::new();
        let geo = EnrichedIp { country: Some("US".into()), ..Default::default() };
        cache.put_geoip(&store, ip("8.8.4.4"), &geo, 100, 1000).unwrap();
        let l = cache.get(&store, ip("8.8.4.4"), 1000 + 200).unwrap();
        assert!(!l.geoip_fresh);
        assert_eq!(l.enriched.country.as_deref(), Some("US"), "still readable while a refresh is pending");
    }

    #[test]
    fn a_second_geoip_write_never_clobbers_a_dns_field_from_the_first() {
        let store = SqliteStore::open_in_memory().unwrap();
        let cache = Cache::new();
        cache.put_dns(&store, ip("9.9.9.9"), &EnrichedIp { hostname: Some("dns.quad9.net".into()), ..Default::default() }, 86_400, 1000).unwrap();
        cache.put_geoip(&store, ip("9.9.9.9"), &EnrichedIp { country: Some("US".into()), ..Default::default() }, 30 * 86_400, 1000).unwrap();
        let l = cache.get(&store, ip("9.9.9.9"), 1000).unwrap();
        assert_eq!(l.enriched.hostname.as_deref(), Some("dns.quad9.net"));
        assert_eq!(l.enriched.country.as_deref(), Some("US"));
    }

    #[test]
    fn concurrent_lookups_of_the_same_ip_never_panic_and_converge_on_the_merged_result() {
        use std::sync::Arc;
        let store = Arc::new(SqliteStore::open_in_memory().unwrap());
        let cache = Arc::new(Cache::new());
        let mut handles = Vec::new();
        for i in 0..8u8 {
            let (store, cache) = (store.clone(), cache.clone());
            handles.push(std::thread::spawn(move || {
                let data = EnrichedIp { country: Some("US".into()), asn: Some(100 + i as u32), ..Default::default() };
                cache.put_geoip(&*store, ip("203.0.113.9"), &data, 3600, 1000).unwrap();
                cache.get(&*store, ip("203.0.113.9"), 1000).unwrap()
            }));
        }
        for h in handles {
            let l = h.join().unwrap();
            assert!(l.geoip_fresh);
            assert_eq!(l.enriched.country.as_deref(), Some("US"));
        }
    }
}
