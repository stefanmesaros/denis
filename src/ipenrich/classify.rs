//! Public/private/loopback/link-local/multicast/reserved classification of an IP address — pure,
//! no I/O, no state. Runs before anything else in the enrichment pipeline: a non-`Public` address
//! is never looked up in GeoIP or reverse-resolved (see `mod.rs`), so getting this right is the
//! one thing standing between "customer's own LAN addresses" and "sent to a GeoIP database".
//!
//! Deliberately hand-rolled against the octets/segments rather than relying on `std`'s own
//! `Ipv6Addr::is_unique_local`/`is_unicast_link_local` (unstable for a long time across Rust
//! versions) or pulling in `ipnet` just for this — the ranges below are fixed by RFC and are not
//! going to change, so a small, fully-tested table here is both simpler and more portable than
//! depending on exactly which nightly features happen to be stable on the build's toolchain.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Classification {
    Public,
    Private,
    Loopback,
    LinkLocal,
    Multicast,
    Reserved,
    Unspecified,
}

impl Classification {
    /// Only a `Public` address is ever worth an external GeoIP/rDNS lookup.
    pub fn is_public(self) -> bool {
        matches!(self, Classification::Public)
    }

    /// The word the UI shows (`tr()` catalog key on the JS side; kept a short, fixed vocabulary
    /// there rather than duplicating these sentences server-side).
    pub fn as_str(self) -> &'static str {
        match self {
            Classification::Public => "public",
            Classification::Private => "private",
            Classification::Loopback => "loopback",
            Classification::LinkLocal => "link-local",
            Classification::Multicast => "multicast",
            Classification::Reserved => "reserved",
            Classification::Unspecified => "unspecified",
        }
    }
}

fn classify_v4(ip: Ipv4Addr) -> Classification {
    let o = ip.octets();
    if ip.is_unspecified() {
        Classification::Unspecified
    } else if o[0] == 127 {
        Classification::Loopback
    } else if o[0] == 10 || (o[0] == 172 && (16..=31).contains(&o[1])) || (o[0] == 192 && o[1] == 168) {
        Classification::Private
    } else if o[0] == 169 && o[1] == 254 {
        Classification::LinkLocal
    } else if o[0] >= 224 && o[0] <= 239 {
        Classification::Multicast
    } else if o[0] == 0
        || o[0] >= 240
        || (o[0] == 100 && (64..=127).contains(&o[1])) // 100.64.0.0/10: carrier-grade NAT
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24: IETF protocol assignments
        || (o[0] == 192 && o[1] == 0 && o[2] == 2) // 192.0.2.0/24: TEST-NET-1
        || (o[0] == 198 && (o[1] == 18 || o[1] == 19)) // 198.18.0.0/15: benchmarking
        || (o[0] == 198 && o[1] == 51 && o[2] == 100) // 198.51.100.0/24: TEST-NET-2
        || (o[0] == 203 && o[1] == 0 && o[2] == 113) // 203.0.113.0/24: TEST-NET-3
        || o == [255, 255, 255, 255]
    {
        Classification::Reserved
    } else {
        Classification::Public
    }
}

fn classify_v6(ip: Ipv6Addr) -> Classification {
    // An IPv4-mapped (`::ffff:a.b.c.d`) or IPv4-compatible address is classified as its embedded
    // IPv4 address — the same host either way, and the brief's IPv4 ranges already cover it.
    if let Some(v4) = ip.to_ipv4_mapped() {
        return classify_v4(v4);
    }
    let s = ip.segments();
    if ip.is_unspecified() {
        Classification::Unspecified
    } else if ip.is_loopback() {
        Classification::Loopback
    } else if (s[0] & 0xfe00) == 0xfc00 {
        // fc00::/7 — unique local addresses (RFC 4193): this network's own private space
        Classification::Private
    } else if (s[0] & 0xffc0) == 0xfe80 {
        // fe80::/10 — link-local
        Classification::LinkLocal
    } else if (s[0] & 0xff00) == 0xff00 {
        // ff00::/8 — multicast
        Classification::Multicast
    } else if s[0] == 0x2001 && s[1] == 0x0db8 {
        // 2001:db8::/32 — documentation range
        Classification::Reserved
    } else {
        Classification::Public
    }
}

pub fn classify(ip: IpAddr) -> Classification {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => classify_v6(v6),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> IpAddr {
        s.parse().unwrap()
    }
    fn v6(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn a_real_public_ipv4_and_ipv6_address_classify_as_public() {
        assert_eq!(classify(v4("8.8.8.8")), Classification::Public);
        assert_eq!(classify(v4("1.1.1.1")), Classification::Public);
        assert_eq!(classify(v6("2606:4700:4700::1111")), Classification::Public); // Cloudflare DNS
    }

    #[test]
    fn every_rfc1918_ipv4_private_range_is_private() {
        assert_eq!(classify(v4("10.0.0.1")), Classification::Private);
        assert_eq!(classify(v4("10.255.255.255")), Classification::Private);
        assert_eq!(classify(v4("172.16.0.1")), Classification::Private);
        assert_eq!(classify(v4("172.31.255.255")), Classification::Private);
        assert_eq!(classify(v4("192.168.0.1")), Classification::Private);
        assert_eq!(classify(v4("192.168.255.255")), Classification::Private);
        // just outside the 172.16.0.0/12 range: public, not private
        assert_eq!(classify(v4("172.32.0.1")), Classification::Public);
        assert_eq!(classify(v4("172.15.255.255")), Classification::Public);
    }

    #[test]
    fn ipv6_unique_local_is_private() {
        assert_eq!(classify(v6("fc00::1")), Classification::Private);
        assert_eq!(classify(v6("fd12:3456:789a::1")), Classification::Private);
    }

    #[test]
    fn loopback_v4_and_v6() {
        assert_eq!(classify(v4("127.0.0.1")), Classification::Loopback);
        assert_eq!(classify(v4("127.255.255.255")), Classification::Loopback);
        assert_eq!(classify(v6("::1")), Classification::Loopback);
    }

    #[test]
    fn link_local_v4_and_v6() {
        assert_eq!(classify(v4("169.254.1.1")), Classification::LinkLocal);
        assert_eq!(classify(v6("fe80::1")), Classification::LinkLocal);
    }

    #[test]
    fn multicast_v4_and_v6() {
        assert_eq!(classify(v4("224.0.0.1")), Classification::Multicast);
        assert_eq!(classify(v4("239.255.255.255")), Classification::Multicast);
        assert_eq!(classify(v6("ff02::1")), Classification::Multicast);
    }

    #[test]
    fn reserved_ranges_are_neither_public_nor_private() {
        assert_eq!(classify(v4("0.0.0.1")), Classification::Reserved);
        assert_eq!(classify(v4("240.0.0.1")), Classification::Reserved);
        assert_eq!(classify(v4("255.255.255.255")), Classification::Reserved);
        assert_eq!(classify(v4("192.0.2.1")), Classification::Reserved); // TEST-NET-1
        assert_eq!(classify(v4("198.51.100.1")), Classification::Reserved); // TEST-NET-2
        assert_eq!(classify(v4("203.0.113.1")), Classification::Reserved); // TEST-NET-3
        assert_eq!(classify(v6("2001:db8::1")), Classification::Reserved);
    }

    #[test]
    fn unspecified_addresses_are_their_own_classification() {
        assert_eq!(classify(v4("0.0.0.0")), Classification::Unspecified);
        assert_eq!(classify(v6("::")), Classification::Unspecified);
    }

    #[test]
    fn an_ipv4_mapped_ipv6_address_classifies_as_its_embedded_ipv4() {
        assert_eq!(classify(v6("::ffff:10.0.0.5")), Classification::Private);
        assert_eq!(classify(v6("::ffff:8.8.8.8")), Classification::Public);
    }

    #[test]
    fn only_public_is_ever_worth_an_external_lookup() {
        assert!(Classification::Public.is_public());
        for c in [Classification::Private, Classification::Loopback, Classification::LinkLocal, Classification::Multicast, Classification::Reserved, Classification::Unspecified] {
            assert!(!c.is_public());
        }
    }
}
