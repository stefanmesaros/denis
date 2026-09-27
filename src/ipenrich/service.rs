//! `IpEnrichmentService`: the piece that actually ties `cache`, `dns` and a `GeoipProvider`
//! together, and the one hard rule every method here is written around — **enrichment must never
//! block event/alert processing** (`IP_ENRICHMENT.md` §9). Concretely:
//!
//! - Whatever builds an event/alert's JSON calls [`Service::best_effort`]: classify + a read-only
//!   cache lookup, nothing else. No provider is ever called from this path, so it is exactly as
//!   fast as a `HashMap` read, always.
//! - The same caller then calls [`Service::enqueue`] with the same IPs, a non-blocking
//!   `try_send` onto a bounded channel a background task drains. A full queue (a provider stuck
//!   or a burst far bigger than usual) means some IPs are enriched a little later, never that
//!   ingestion waits.
//! - A person clicking an IP to see its full detail panel gets [`Service::enrich_now`], which
//!   *does* await a real answer (including reverse DNS) — a directly-awaited, single-IP path is
//!   fine to wait a moment for, unlike bulk ingestion.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use tokio::sync::mpsc;

use crate::store::Store;

use super::cache::Cache;
use super::classify::classify;
#[cfg(test)]
use super::classify::Classification;
use super::dns::Resolver as DnsResolver;
use super::provider::GeoipProvider;
use super::types::{EnrichedIp, IpInfo};

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CacheTtls {
    pub geoip_secs: i64,
    pub dns_secs: i64,
}

impl Default for CacheTtls {
    fn default() -> Self {
        // Exactly the brief's own defaults: GeoIP 30 days, reverse DNS 24 hours.
        CacheTtls { geoip_secs: 30 * 86_400, dns_secs: 86_400 }
    }
}

/// Plain counters for `/metrics` (wired up separately, in `web/mod.rs`, alongside the other
/// Prometheus samples) — see `IP_ENRICHMENT.md` §15 for the exact names.
#[derive(Default)]
pub struct Metrics {
    pub enrichment_total: AtomicU64,
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,
    pub errors: AtomicU64,
    pub dns_total: AtomicU64,
    pub dns_cache_hits: AtomicU64,
    pub dns_errors: AtomicU64,
    /// IPs dropped from the enrichment queue because it was full — never blocks the caller, but
    /// worth knowing about if it happens often (the queue is sized generously for exactly this
    /// reason; see `Service::spawn`).
    pub queue_dropped: AtomicU64,
}

impl Metrics {
    fn inc(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

const QUEUE_CAPACITY: usize = 10_000;

pub struct Service {
    cache: Arc<Cache>,
    dns: Arc<DnsResolver>,
    geoip: Arc<dyn GeoipProvider>,
    store: Arc<dyn Store>,
    ttls: RwLock<CacheTtls>,
    tx: mpsc::Sender<IpAddr>,
    /// IPs already queued for the background worker — checked before every `try_send` so a burst
    /// of events for the same address (the common case: one noisy destination, many packets)
    /// enqueues one lookup, not one per event, without waiting on the worker at all.
    pending: Mutex<HashSet<IpAddr>>,
    pub metrics: Arc<Metrics>,
}

impl Service {
    /// Spawns the background worker and returns the shared handle every caller uses. `store` is
    /// the same `Arc<dyn Store>` the rest of the program already has (the SQLite cache tier).
    pub fn spawn(store: Arc<dyn Store>, dns: Arc<DnsResolver>, geoip: Arc<dyn GeoipProvider>, ttls: CacheTtls) -> Arc<Service> {
        let (tx, rx) = mpsc::channel(QUEUE_CAPACITY);
        let svc = Arc::new(Service { cache: Arc::new(Cache::new()), dns, geoip, store, ttls: RwLock::new(ttls), tx, pending: Mutex::new(HashSet::new()), metrics: Arc::new(Metrics::default()) });
        tokio::spawn(worker(svc.clone(), rx));
        svc
    }

    /// A handle with no background worker running — for tests and for the on-demand path when a
    /// caller wants `enrich_now` without also standing up the queue/worker.
    #[cfg(test)]
    fn new_inert(store: Arc<dyn Store>, dns: Arc<DnsResolver>, geoip: Arc<dyn GeoipProvider>, ttls: CacheTtls) -> Service {
        let (tx, rx) = mpsc::channel(1);
        // Nothing ever drains this in "inert" mode (no worker spawned) — deliberately leaked
        // rather than dropped, or every `try_send` would fail with "channel closed" instead of
        // the "queue full" behaviour these tests actually mean to exercise.
        std::mem::forget(rx);
        Service { cache: Arc::new(Cache::new()), dns, geoip, store, ttls: RwLock::new(ttls), tx, pending: Mutex::new(HashSet::new()), metrics: Arc::new(Metrics::default()) }
    }

    pub fn set_ttls(&self, ttls: CacheTtls) {
        *self.ttls.write().unwrap() = ttls;
    }

    /// The three small accessors `web_ipenrich.rs`'s status/settings handlers need — reading the
    /// live, already-running provider/resolver rather than re-reading `SettingsStore` (which
    /// would not reflect a change made through `set_dns_config` until the next restart).
    pub fn dns_enabled(&self) -> bool {
        self.dns.config().enabled
    }
    pub fn geoip_status(&self) -> super::types::ProviderStatus {
        self.geoip.status()
    }
    pub fn set_dns_config(&self, cfg: super::dns::DnsConfig) {
        self.dns.set_config(cfg);
    }

    /// Classify + read-only cache lookup for every one of `ips` — never calls a provider, never
    /// blocks. Exactly what `detect.rs` calls while building an event's `destinations`/`ip`
    /// fields: whatever is already known is included, and nothing here ever waits for more.
    pub fn best_effort(&self, ips: &[IpAddr], now: i64) -> HashMap<IpAddr, IpInfo> {
        let mut out = HashMap::with_capacity(ips.len());
        for &ip in dedup(ips).iter() {
            let classification = classify(ip);
            let enriched = if classification.is_public() {
                match self.cache.get(&*self.store, ip, now) {
                    Ok(l) => {
                        if l.geoip_fresh || l.dns_fresh {
                            Metrics::inc(&self.metrics.cache_hits);
                        } else {
                            Metrics::inc(&self.metrics.cache_misses);
                        }
                        l.enriched
                    }
                    Err(e) => {
                        tracing::debug!("ip enrichment cache read failed for {ip}: {e:#}");
                        EnrichedIp::default()
                    }
                }
            } else {
                EnrichedIp::default()
            };
            out.insert(ip, IpInfo { ip, classification, enriched });
        }
        out
    }

    /// Enqueue `ips` for background enrichment (dedup'd against what is already pending). Always
    /// returns immediately: a full queue drops the excess (counted in `metrics.queue_dropped`)
    /// rather than ever blocking the caller — see the module doc for why that trade is correct
    /// here (an occasional delayed enrichment, never a delayed event).
    pub fn enqueue(&self, ips: &[IpAddr]) {
        let mut pending = self.pending.lock().unwrap();
        for &ip in dedup(ips).iter() {
            if !classify(ip).is_public() || pending.contains(&ip) {
                continue;
            }
            match self.tx.try_send(ip) {
                Ok(()) => {
                    pending.insert(ip);
                }
                Err(_) => Metrics::inc(&self.metrics.queue_dropped),
            }
        }
    }

    /// On-demand: a real, fresh-as-possible answer for one IP, awaited directly (reverse DNS
    /// included) — for the click-through detail panel, where a person expects to wait a moment
    /// for one item, unlike bulk ingestion. Still respects the cache (does not re-fetch GeoIP or
    /// re-resolve DNS that is still within its TTL).
    pub async fn enrich_now(&self, ip: IpAddr, now: i64) -> IpInfo {
        let classification = classify(ip);
        if !classification.is_public() {
            return IpInfo { ip, classification, enriched: EnrichedIp::default() };
        }
        Metrics::inc(&self.metrics.enrichment_total);
        let lookup = self.cache.get(&*self.store, ip, now).unwrap_or(super::cache::Lookup { enriched: EnrichedIp::default(), geoip_fresh: false, dns_fresh: false });
        if !lookup.geoip_fresh {
            let geoip = self.geoip.clone();
            let ttl = self.ttls.read().unwrap().geoip_secs;
            let data = tokio::task::spawn_blocking(move || geoip.lookup(ip)).await.unwrap_or_default();
            if let Err(e) = self.cache.put_geoip(&*self.store, ip, &data, ttl, now) {
                tracing::debug!("caching geoip data for {ip} failed: {e:#}");
                Metrics::inc(&self.metrics.errors);
            }
        }
        if !lookup.dns_fresh {
            Metrics::inc(&self.metrics.dns_total);
            let res = self.dns.reverse_lookup(ip, now).await;
            if res.hostname.is_none() {
                if let Some(reason) = res.reason {
                    tracing::debug!("reverse dns unavailable for {ip}: {reason}");
                    if reason != "disabled" {
                        Metrics::inc(&self.metrics.dns_errors);
                    }
                }
            }
            let data = EnrichedIp { hostname: res.hostname, dns_source: Some(self.dns.config().primary), ..Default::default() };
            let ttl = self.ttls.read().unwrap().dns_secs;
            if let Err(e) = self.cache.put_dns(&*self.store, ip, &data, ttl, now) {
                tracing::debug!("caching dns data for {ip} failed: {e:#}");
                Metrics::inc(&self.metrics.errors);
            }
        }
        let enriched = self.cache.get(&*self.store, ip, now).map(|l| l.enriched).unwrap_or_default();
        IpInfo { ip, classification, enriched }
    }
}

fn dedup(ips: &[IpAddr]) -> Vec<IpAddr> {
    let mut seen = HashSet::with_capacity(ips.len());
    ips.iter().copied().filter(|ip| seen.insert(*ip)).collect()
}

async fn worker(svc: Arc<Service>, mut rx: mpsc::Receiver<IpAddr>) {
    while let Some(ip) = rx.recv().await {
        let now = crate::model::now_ts();
        let lookup = svc.cache.get(&*svc.store, ip, now).unwrap_or(super::cache::Lookup { enriched: EnrichedIp::default(), geoip_fresh: false, dns_fresh: false });
        Metrics::inc(&svc.metrics.enrichment_total);
        if !lookup.geoip_fresh {
            let geoip = svc.geoip.clone();
            let data = tokio::task::spawn_blocking(move || geoip.lookup(ip)).await.unwrap_or_default();
            let ttl = svc.ttls.read().unwrap().geoip_secs;
            if let Err(e) = svc.cache.put_geoip(&*svc.store, ip, &data, ttl, now) {
                tracing::debug!("caching geoip data for {ip} failed: {e:#}");
                Metrics::inc(&svc.metrics.errors);
            }
        }
        if !lookup.dns_fresh {
            Metrics::inc(&svc.metrics.dns_total);
            let res = svc.dns.reverse_lookup(ip, now).await;
            if res.hostname.is_none() {
                if let Some(reason) = res.reason {
                    if reason != "disabled" {
                        Metrics::inc(&svc.metrics.dns_errors);
                    }
                }
            }
            let data = EnrichedIp { hostname: res.hostname, dns_source: Some(svc.dns.config().primary), ..Default::default() };
            let ttl = svc.ttls.read().unwrap().dns_secs;
            if let Err(e) = svc.cache.put_dns(&*svc.store, ip, &data, ttl, now) {
                tracing::debug!("caching dns data for {ip} failed: {e:#}");
                Metrics::inc(&svc.metrics.errors);
            }
        }
        svc.pending.lock().unwrap().remove(&ip);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipenrich::dns::DnsConfig;
    use crate::ipenrich::provider::test_support::FixedProvider;
    use crate::store::sqlite::SqliteStore;

    fn svc_with(answer: EnrichedIp) -> Service {
        let store: Arc<dyn Store> = Arc::new(SqliteStore::open_in_memory().unwrap());
        let dns = Arc::new(DnsResolver::new(DnsConfig { enabled: false, ..Default::default() }));
        let geoip: Arc<dyn GeoipProvider> = Arc::new(FixedProvider { answer });
        Service::new_inert(store, dns, geoip, CacheTtls::default())
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn best_effort_never_calls_a_provider_and_answers_from_cache_alone() {
        let svc = svc_with(EnrichedIp { country: Some("US".into()), ..Default::default() });
        // nothing cached yet: best_effort must not itself call the (fixed, would-answer) provider
        let out = svc.best_effort(&[ip("8.8.8.8")], 1000);
        assert!(out[&ip("8.8.8.8")].enriched.is_empty(), "best_effort never enriches on its own");
        assert_eq!(out[&ip("8.8.8.8")].classification, Classification::Public);
    }

    #[test]
    fn best_effort_classifies_private_addresses_without_any_cache_lookup() {
        let svc = svc_with(EnrichedIp::default());
        let out = svc.best_effort(&[ip("10.0.0.5")], 1000);
        assert_eq!(out[&ip("10.0.0.5")].classification, Classification::Private);
        assert!(out[&ip("10.0.0.5")].enriched.is_empty());
    }

    #[tokio::test]
    async fn enrich_now_calls_the_provider_populates_the_cache_and_best_effort_then_sees_it() {
        let svc = svc_with(EnrichedIp { country: Some("DE".into()), asn: Some(3320), ..Default::default() });
        let info = svc.enrich_now(ip("1.2.3.4"), 1000).await;
        assert_eq!(info.enriched.country.as_deref(), Some("DE"));
        assert_eq!(info.enriched.asn, Some(3320));
        // and now the non-blocking read-only path sees it too, without calling anything
        let out = svc.best_effort(&[ip("1.2.3.4")], 1000);
        assert_eq!(out[&ip("1.2.3.4")].enriched.country.as_deref(), Some("DE"));
    }

    #[tokio::test]
    async fn enrich_now_on_a_private_address_never_calls_the_provider_at_all() {
        let svc = svc_with(EnrichedIp { country: Some("should never appear".into()), ..Default::default() });
        let info = svc.enrich_now(ip("192.168.1.1"), 1000).await;
        assert_eq!(info.classification, Classification::Private);
        assert!(info.enriched.is_empty(), "a private address is never sent to a geoip provider");
    }

    #[test]
    fn a_duplicate_ip_across_many_events_is_deduped_before_ever_reaching_the_queue() {
        // 10,000 events, 1 unique IP: enqueue should only ever try_send once, the rest are
        // recognised as already-pending and skipped — mirrors the brief's own dedup example.
        let svc = svc_with(EnrichedIp::default());
        let many = vec![ip("8.8.8.8"); 10_000];
        svc.enqueue(&many);
        assert_eq!(svc.pending.lock().unwrap().len(), 1);
    }

    #[test]
    fn enqueue_never_blocks_even_when_the_queue_is_saturated() {
        // new_inert's channel has capacity 1 and nothing ever drains it (no worker spawned) —
        // the second distinct IP must be dropped, counted, and return immediately, not block.
        let svc = svc_with(EnrichedIp::default());
        svc.enqueue(&[ip("1.1.1.1")]);
        svc.enqueue(&[ip("2.2.2.2")]); // queue capacity 1, already holds 1.1.1.1: this one drops
        assert_eq!(svc.metrics.queue_dropped.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn private_and_reserved_addresses_are_never_enqueued() {
        let svc = svc_with(EnrichedIp::default());
        svc.enqueue(&[ip("10.0.0.1"), ip("127.0.0.1"), ip("224.0.0.1")]);
        assert!(svc.pending.lock().unwrap().is_empty());
    }
}
