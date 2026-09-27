//! IP enrichment: reverse DNS, GeoIP/ASN and public/private classification for every IP address
//! DENIS shows, from a provider-swappable, cached, never-blocking-ingestion pipeline. See
//! `docs/ip-enrichment-design.md` for the full architecture and the reasoning behind it.
//!
//! Built bottom-up, one committed layer at a time: this module currently only re-exports
//! `classify` (public/private/loopback/… detection). The rest (`cache`, `dns`, `geoip`,
//! `provider`) land in following commits.

pub mod cache;
pub mod classify;
pub mod dns;
pub mod geoip;
pub mod provider;
pub mod service;
pub mod types;

pub use cache::Cache;
pub use classify::Classification;
pub use dns::{DnsConfig, Resolver as DnsResolver};
pub use geoip::{GeoipConfig, GeoipSource, MmdbProvider};
pub use provider::GeoipProvider;
pub use service::{CacheTtls, Metrics, Service};
pub use types::{Capabilities, EnrichedIp, Health, IpInfo, ProviderStatus};
