//! IP enrichment: reverse DNS, GeoIP/ASN and public/private classification for every IP address
//! DENIS shows, from a provider-swappable, cached, never-blocking-ingestion pipeline. See
//! `docs/ip-enrichment-design.md` for the full architecture and the reasoning behind it.
//!
//! Built bottom-up, one committed layer at a time: this module currently only re-exports
//! `classify` (public/private/loopback/… detection). The rest (`cache`, `dns`, `geoip`,
//! `provider`) land in following commits.

pub mod classify;

pub use classify::Classification;
