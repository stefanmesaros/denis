//! Reverse DNS: a provider fully separate from GeoIP (`IP_ENRICHMENT.md` §11), with its own
//! configurable resolver(s), timeout, on/off switch, and a circuit breaker so a resolver that has
//! gone down does not queue up slow, doomed lookups behind it. Supports both IPv4 and IPv6
//! addresses and resolvers.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::Duration;

use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use serde::{Deserialize, Serialize};

/// After this many consecutive failures (timeouts, unreachable resolver, …), stop trying for
/// `COOLDOWN_SECS`: a resolver that is genuinely down should not have every single enrichment
/// attempt wait out its own timeout one at a time.
const TRIP_AFTER: u32 = 5;
const COOLDOWN_SECS: i64 = 60;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct DnsConfig {
    pub enabled: bool,
    pub primary: String,
    pub secondary: Option<String>,
    pub timeout_ms: u32,
}

impl Default for DnsConfig {
    fn default() -> Self {
        DnsConfig { enabled: true, primary: "1.1.1.1".into(), secondary: Some("1.0.0.1".into()), timeout_ms: 2000 }
    }
}

/// One resolved (or refused) reverse-DNS answer.
#[derive(Debug, Clone, PartialEq)]
pub struct DnsResult {
    pub hostname: Option<String>,
    /// Why `hostname` is `None`: `"disabled"`, `"circuit open"`, `"timeout"`, `"no PTR record"`,
    /// `"resolver unreachable: {e}"`, … — logged, never shown raw to a viewer (the UI just says
    /// "Reverse DNS: unavailable").
    pub reason: Option<&'static str>,
}

/// Consecutive-failure counter + trip time, shared across every lookup so the circuit breaker is
/// meaningful process-wide, not per-call.
#[derive(Default)]
struct Breaker {
    consecutive_failures: AtomicU32,
    tripped_until: AtomicU64, // unix seconds; 0 = not tripped
}

impl Breaker {
    fn is_open(&self, now: i64) -> bool {
        let until = self.tripped_until.load(Ordering::Relaxed) as i64;
        until > now
    }
    fn record_success(&self) {
        self.consecutive_failures.store(0, Ordering::Relaxed);
        self.tripped_until.store(0, Ordering::Relaxed);
    }
    fn record_failure(&self, now: i64) {
        let n = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
        if n >= TRIP_AFTER {
            self.tripped_until.store((now + COOLDOWN_SECS) as u64, Ordering::Relaxed);
        }
    }
}

pub struct Resolver {
    cfg: std::sync::RwLock<DnsConfig>,
    breaker: Breaker,
}

impl Resolver {
    pub fn new(cfg: DnsConfig) -> Self {
        Resolver { cfg: std::sync::RwLock::new(cfg), breaker: Breaker::default() }
    }

    pub fn set_config(&self, cfg: DnsConfig) {
        *self.cfg.write().unwrap() = cfg;
    }

    pub fn config(&self) -> DnsConfig {
        self.cfg.read().unwrap().clone()
    }

    /// Is the circuit currently open (i.e. lookups are being skipped without even trying)?
    pub fn circuit_open(&self, now: i64) -> bool {
        self.breaker.is_open(now)
    }

    fn build(&self) -> Option<TokioAsyncResolver> {
        let cfg = self.config();
        if !cfg.enabled {
            return None;
        }
        let mut ips: Vec<IpAddr> = Vec::new();
        if let Ok(ip) = cfg.primary.parse() {
            ips.push(ip);
        }
        if let Some(s) = &cfg.secondary {
            if let Ok(ip) = s.parse() {
                ips.push(ip);
            }
        }
        if ips.is_empty() {
            return None;
        }
        let group = NameServerConfigGroup::from_ips_clear(&ips, 53, true);
        let resolver_config = ResolverConfig::from_parts(None, vec![], group);
        let mut opts = ResolverOpts::default();
        opts.timeout = Duration::from_millis(cfg.timeout_ms as u64);
        opts.attempts = 1; // our own circuit breaker handles repeated failure, not hickory's own retry
        Some(TokioAsyncResolver::tokio(resolver_config, opts))
    }

    /// Reverse-resolve one address. Never panics, never blocks past the configured timeout, and
    /// never touches the network at all when disabled or while the circuit is open.
    pub async fn reverse_lookup(&self, ip: IpAddr, now: i64) -> DnsResult {
        if !self.config().enabled {
            return DnsResult { hostname: None, reason: Some("disabled") };
        }
        if self.breaker.is_open(now) {
            return DnsResult { hostname: None, reason: Some("circuit open") };
        }
        let Some(resolver) = self.build() else {
            return DnsResult { hostname: None, reason: Some("no resolver configured") };
        };
        match resolver.reverse_lookup(ip).await {
            Ok(answer) => {
                self.breaker.record_success();
                match answer.iter().next() {
                    Some(name) => DnsResult { hostname: Some(name.to_string().trim_end_matches('.').to_string()), reason: None },
                    None => DnsResult { hostname: None, reason: Some("no PTR record") },
                }
            }
            Err(e) => {
                self.breaker.record_failure(now);
                let reason = if matches!(e.kind(), hickory_resolver::error::ResolveErrorKind::Timeout) { "timeout" } else { "resolver unreachable" };
                DnsResult { hostname: None, reason: Some(reason) }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_the_brief_exactly() {
        let cfg = DnsConfig::default();
        assert!(cfg.enabled);
        assert_eq!(cfg.primary, "1.1.1.1");
        assert_eq!(cfg.secondary.as_deref(), Some("1.0.0.1"));
        assert_eq!(cfg.timeout_ms, 2000);
    }

    #[tokio::test]
    async fn disabled_never_touches_the_network_and_says_so() {
        let r = Resolver::new(DnsConfig { enabled: false, ..Default::default() });
        let res = r.reverse_lookup("8.8.8.8".parse().unwrap(), 1000).await;
        assert_eq!(res, DnsResult { hostname: None, reason: Some("disabled") });
    }

    #[tokio::test]
    async fn a_resolver_with_no_servers_configured_fails_closed_without_panicking() {
        let r = Resolver::new(DnsConfig { enabled: true, primary: "not an ip".into(), secondary: None, timeout_ms: 2000 });
        let res = r.reverse_lookup("8.8.8.8".parse().unwrap(), 1000).await;
        assert_eq!(res.hostname, None);
        assert_eq!(res.reason, Some("no resolver configured"));
    }

    #[tokio::test]
    async fn repeated_failures_trip_the_circuit_breaker_and_it_reports_open() {
        // 203.0.113.0/24 is TEST-NET-3 (RFC 5737): guaranteed to never answer, so every one of
        // these lookups fails the same way a genuinely dead resolver would, without depending on
        // any real network condition beyond "this address is never reachable".
        let r = Resolver::new(DnsConfig { enabled: true, primary: "203.0.113.1".into(), secondary: None, timeout_ms: 200 });
        let mut now = 1000i64;
        for _ in 0..TRIP_AFTER {
            let res = r.reverse_lookup("8.8.8.8".parse().unwrap(), now).await;
            assert_eq!(res.hostname, None);
            now += 1;
        }
        assert!(r.circuit_open(now), "should have tripped after {TRIP_AFTER} consecutive failures");
        // and it reports "circuit open" immediately, without waiting out another timeout
        let res = r.reverse_lookup("8.8.8.8".parse().unwrap(), now).await;
        assert_eq!(res.reason, Some("circuit open"));
        // the cooldown eventually lifts
        assert!(!r.circuit_open(now + COOLDOWN_SECS + 1));
    }

    #[test]
    fn config_can_be_read_back_exactly_after_being_set() {
        let r = Resolver::new(DnsConfig::default());
        let custom = DnsConfig { enabled: false, primary: "9.9.9.9".into(), secondary: Some("8.8.4.4".into()), timeout_ms: 500 };
        r.set_config(custom.clone());
        assert_eq!(r.config(), custom);
    }
}
