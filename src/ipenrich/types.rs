//! Shared data types: what one enriched IP looks like, and the small status/capability types a
//! provider reports about itself. Kept separate from `provider.rs` (the trait) and `cache.rs`
//! (storage) so every other file can depend on the types alone.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use super::classify::Classification;

/// Everything DENIS might know about one IP address. Every field beyond `ip`/`classification` is
/// `Option`: absent means "Not available" in the UI, never a guessed or fabricated value (the
/// brief's own, explicit requirement — see `docs/ip-enrichment-design.md` §5).
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct EnrichedIp {
    pub hostname: Option<String>,
    pub country: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub asn: Option<u32>,
    pub as_org: Option<String>,
    pub isp: Option<String>,
    /// e.g. "hosting"/"business"/"residential", only when the GeoIP source actually says so.
    pub connection_type: Option<String>,
    /// Which provider answered ("DB-IP Lite", "Custom MMDB", "Custom API", …); `None` means
    /// nothing has enriched this IP yet (as opposed to a provider having tried and found nothing,
    /// which is `Some(name)` with every other field still `None`).
    pub geoip_source: Option<String>,
    pub geoip_db_version: Option<String>,
    /// Which reverse-DNS resolver answered, when `hostname` came from one.
    pub dns_source: Option<String>,
}

impl EnrichedIp {
    /// Nothing at all has been filled in yet (the zero value, for a brand-new cache row).
    pub fn is_empty(&self) -> bool {
        *self == EnrichedIp::default()
    }

    /// Merge `other`'s fields over `self`, but only where `other` actually has an answer — used
    /// when GeoIP and reverse-DNS fill in the same row independently and on their own schedules
    /// (see `cache.rs`), so a fresher DNS answer never clobbers still-valid GeoIP data or vice
    /// versa.
    pub fn merge_from(&mut self, other: &EnrichedIp) {
        macro_rules! take { ($($f:ident),*) => { $( if other.$f.is_some() { self.$f = other.$f.clone(); } )* }; }
        take!(hostname, country, region, city, asn, as_org, isp, connection_type, geoip_source, geoip_db_version, dns_source);
        if other.latitude.is_some() {
            self.latitude = other.latitude;
        }
        if other.longitude.is_some() {
            self.longitude = other.longitude;
        }
    }
}

/// The full answer for one IP: its classification (always known, never a lookup) plus whatever
/// enrichment could be filled in (only ever attempted for `Classification::Public`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct IpInfo {
    pub ip: IpAddr,
    pub classification: Classification,
    #[serde(flatten)]
    pub enriched: EnrichedIp,
}

/// What a provider can, in principle, supply — shown in Settings so an administrator can tell,
/// e.g., a reverse-DNS-only custom API apart from a full GeoIP+ASN one.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Capabilities {
    pub geoip: bool,
    pub asn: bool,
    pub reverse_dns: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Health {
    Ok,
    Degraded,
    Down,
}

/// A provider's own view of itself, for the Health page and `/metrics` (see design doc §15).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ProviderStatus {
    pub name: String,
    pub health: Health,
    /// A short, plain-language reason when `health` is not `Ok` ("database file missing",
    /// "5 consecutive timeouts, retrying in 42s", …). Empty when `health` is `Ok`.
    pub detail: String,
    pub db_version: Option<String>,
    pub updated_at: Option<i64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_from_only_overwrites_fields_the_other_side_actually_has() {
        let mut a = EnrichedIp { country: Some("US".into()), city: Some("Ashburn".into()), ..Default::default() };
        let dns_only = EnrichedIp { hostname: Some("one.one.one.one".into()), dns_source: Some("1.1.1.1".into()), ..Default::default() };
        a.merge_from(&dns_only);
        assert_eq!(a.hostname.as_deref(), Some("one.one.one.one"));
        assert_eq!(a.country.as_deref(), Some("US")); // untouched
        assert_eq!(a.city.as_deref(), Some("Ashburn")); // untouched

        let newer_geoip = EnrichedIp { country: Some("DE".into()), asn: Some(3320), ..Default::default() };
        a.merge_from(&newer_geoip);
        assert_eq!(a.country.as_deref(), Some("DE")); // updated
        assert_eq!(a.hostname.as_deref(), Some("one.one.one.one")); // still untouched by the geoip merge
        assert_eq!(a.asn, Some(3320));
    }

    #[test]
    fn a_default_enriched_ip_is_empty_and_merging_nothing_changes_nothing() {
        let mut a = EnrichedIp::default();
        assert!(a.is_empty());
        a.merge_from(&EnrichedIp::default());
        assert!(a.is_empty());
    }
}
