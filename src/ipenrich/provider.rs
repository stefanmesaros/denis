//! The provider abstraction (`IP_ENRICHMENT.md` §4): DENIS never hard-codes a single GeoIP
//! source. A `GeoipProvider` is anything that can turn a public IP into whatever GeoIP/ASN fields
//! it knows; `geoip.rs`'s `MmdbProvider` (DB-IP Lite by default, or a customer's own MaxMind-format
//! file) is the only one built in today, but a `CustomApiProvider` (configurable JSON field-path
//! mapping) or an `InternalServerProvider` (an enterprise's own GeoIP service) are additions of a
//! new file implementing this same trait — no change to the trait, the cache, or any caller.
//!
//! Plain synchronous methods, not `async fn`: a local MMDB read never blocks meaningfully, and a
//! future network-calling provider (custom REST API, internal server) is expected to do what
//! `ai::explain` already does elsewhere in this codebase — a blocking `ureq` call with its own
//! timeout, run through `tokio::task::spawn_blocking` by whoever calls it (the orchestration in
//! `mod.rs`), rather than the trait itself being async.

use std::net::IpAddr;

use super::types::{Capabilities, EnrichedIp, ProviderStatus};

pub trait GeoipProvider: Send + Sync {
    /// A short, stable identifier written into `EnrichedIp::geoip_source` and shown in the UI's
    /// "Data source" line, e.g. `"DB-IP Lite"`, `"Custom MMDB"`, `"Custom API"`.
    fn name(&self) -> &'static str;
    fn capabilities(&self) -> Capabilities;
    /// The provider's own view of its health, for the Health page and `/metrics` — never panics,
    /// never blocks on the network to answer this (a local file check at most).
    fn status(&self) -> ProviderStatus;
    /// Best-effort: an address this provider has nothing for returns `EnrichedIp::default()`, not
    /// an error — a missing/corrupt database is a `status()` concern, not a per-call one, so a
    /// caller never has to handle a `Result` just to enrich one more IP.
    fn lookup(&self, ip: IpAddr) -> EnrichedIp;
}

// A `test_support::FixedProvider` (a fixed-answer stand-in for tests that exercise the
// orchestration around a provider without needing a real MMDB file) lands here once `geoip.rs`
// or `mod.rs`'s own tests actually need one — left out for now so nothing sits unused.
