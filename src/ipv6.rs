//! IPv6 groundwork: a pure, fuzz-friendly parser for the IPv6 header and the handful of ICMPv6
//! message types that matter for discovery (Neighbor Solicitation/Advertisement — IPv6's
//! replacement for ARP — and Router Advertisement, which announces a gateway).
//!
//! **Nothing in the running collector calls this yet.** `BPF_FILTER`/`BPF_FILTER_FLOWS` in
//! `parse.rs` do not admit EtherType 0x86DD frames at all, so no IPv6 traffic reaches userspace
//! today regardless of what this module can decode — that is a deliberate, separate decision
//! (widening the kernel filter changes what every existing installation captures, which needs its
//! own review, not something to fold into a parser addition). This module exists so the address
//! model (`model::Ipv6Record`) and the parsing logic are already written, reviewed and tested
//! before that wiring happens, per the phased plan in `IPV6.md`.
//!
//! Every length here is bounds-checked: like the rest of `src/parse.rs`, this reads bytes from an
//! untrusted network and must never panic or read out of bounds on a truncated or hostile packet.

use std::net::Ipv6Addr;

/// Extension headers RFC 8200 defines, in the order they may legally chain: skipped to find the
/// real payload without needing to understand what each one does.
const HOP_BY_HOP: u8 = 0;
const ROUTING: u8 = 43;
const FRAGMENT: u8 = 44;
const DEST_OPTS: u8 = 60;
pub const NO_NEXT_HEADER: u8 = 59;
pub const ICMPV6: u8 = 58;

/// The fixed 40-byte header, plus where its actual upper-layer payload starts once any extension
/// headers are skipped (`payload_offset`, relative to the slice `parse` was given) and what
/// protocol it is (`upper_protocol`; `NO_NEXT_HEADER` if the chain says there is none).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ipv6Header {
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
    pub hop_limit: u8,
    pub upper_protocol: u8,
    pub payload_offset: usize,
}

/// Parses the fixed IPv6 header from `data` (an IPv6 packet, as it would sit right after the
/// Ethernet header) and walks any extension header chain to find where the real payload starts.
/// `None` on anything too short or with a header chain that runs past the end of `data` — the
/// same "give up, do not guess" behaviour `parse_ipv4`/`parse_arp` already have for hostile input.
pub fn parse(data: &[u8]) -> Option<Ipv6Header> {
    if data.len() < 40 || data[0] >> 4 != 6 {
        return None; // not IPv6, or too short to be a header at all
    }
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(&data[8..24]).ok()?);
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&data[24..40]).ok()?);
    let hop_limit = data[7];
    let mut next_header = data[6];
    let mut offset = 40;
    // walk the extension header chain: each one starts with (next header, header length in 8-byte
    // units *not counting the first 8 bytes*) except Fragment, which is a fixed 8 bytes with no
    // length field of its own. A chain longer than the packet, or one that never resolves to a
    // real protocol, is exactly the kind of input this must not loop forever or panic on.
    for _ in 0..8 {
        match next_header {
            HOP_BY_HOP | ROUTING | DEST_OPTS => {
                let hdr = data.get(offset..offset + 2)?;
                let len = (hdr[1] as usize + 1) * 8;
                next_header = hdr[0];
                offset = offset.checked_add(len)?;
            }
            FRAGMENT => {
                let hdr = data.get(offset..offset + 8)?;
                next_header = hdr[0];
                offset = offset.checked_add(8)?;
            }
            _ => break, // a real protocol, or NO_NEXT_HEADER ("nothing follows")
        }
        if offset > data.len() {
            return None;
        }
    }
    Some(Ipv6Header { src, dst, hop_limit, upper_protocol: next_header, payload_offset: offset })
}

/// One ICMPv6 message this module cares about (RFC 4861): the rest (echo request/reply,
/// destination unreachable, …) are not discovery-relevant and are left as `None`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Icmpv6 {
    /// "Who has this address?" — sent to the solicited-node multicast address of `target`, the
    /// IPv6 analogue of an ARP request. The sender's own address is `Ipv6Header::src` (this
    /// message carries no address of its own beyond the target it is asking about).
    NeighborSolicitation { target: Ipv6Addr },
    /// "I have this address" — a reply to a solicitation, or sent unprompted when an address is
    /// (re)configured. `source_link_layer` is the answering interface's MAC, when the option
    /// carrying it is present (it usually is).
    NeighborAdvertisement { target: Ipv6Addr, source_link_layer: Option<[u8; 6]> },
    /// A router announcing itself: the IPv6 equivalent of noticing something answer as a DHCP/ARP
    /// gateway would on IPv4. Sent from the router's own link-local address (`Ipv6Header::src`).
    RouterAdvertisement,
}

/// Parses an ICMPv6 message body (i.e. `data[header.payload_offset..]` when
/// `header.upper_protocol == ICMPV6`). `None` for a type this module does not need, or on
/// anything too short to hold the fixed part of a message it claims to be.
pub fn parse_icmpv6(data: &[u8]) -> Option<Icmpv6> {
    let ty = *data.first()?;
    match ty {
        133 => Some(Icmpv6::RouterAdvertisement), // Router Solicitation is not itself interesting
        134 => Some(Icmpv6::RouterAdvertisement),
        135 => {
            // type(1) code(1) checksum(2) reserved(4) target(16) [options...]
            let target = Ipv6Addr::from(<[u8; 16]>::try_from(data.get(8..24)?).ok()?);
            Some(Icmpv6::NeighborSolicitation { target })
        }
        136 => {
            let target = Ipv6Addr::from(<[u8; 16]>::try_from(data.get(8..24)?).ok()?);
            Some(Icmpv6::NeighborAdvertisement { target, source_link_layer: find_source_link_layer_option(data.get(24..)?) })
        }
        _ => None,
    }
}

/// Walks NDP's TLV options (type(1) octets(1, in 8-byte units) value) looking for a Source
/// Link-Layer Address option (type 1, the common Ethernet case: 6-byte MAC). Malformed or
/// truncated options just end the search rather than erroring: an advertisement without a usable
/// option is simply address-only evidence, not a parse failure.
fn find_source_link_layer_option(mut opts: &[u8]) -> Option<[u8; 6]> {
    for _ in 0..16 {
        let &[ty, len_units, ..] = opts else { return None };
        if len_units == 0 {
            return None; // a zero-length option would loop forever
        }
        let len = len_units as usize * 8;
        let body = opts.get(2..len)?;
        if ty == 1 && body.len() >= 6 {
            return <[u8; 6]>::try_from(&body[..6]).ok();
        }
        opts = opts.get(len..)?;
    }
    None
}

/// Is this a link-local address (`fe80::/10`)? Kept here (rather than relying only on the
/// standard library's own `is_unicast_link_local`) so `model::Ipv6Record::link_local` and this
/// module agree on the definition without either depending on the other.
pub fn is_link_local(ip: &Ipv6Addr) -> bool {
    ip.segments()[0] & 0xffc0 == 0xfe80
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal, valid IPv6 header (no extension headers) carrying `next_header` with `payload`
    /// appended right after it.
    fn packet(next_header: u8, src: Ipv6Addr, dst: Ipv6Addr, payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; 40];
        p[0] = 0x60; // version 6, no traffic class/flow label needed for these tests
        p[6] = next_header;
        p[7] = 64; // hop limit
        p[8..24].copy_from_slice(&src.octets());
        p[24..40].copy_from_slice(&dst.octets());
        p.extend_from_slice(payload);
        p
    }

    #[test]
    fn a_plain_header_is_read_correctly() {
        let src: Ipv6Addr = "fe80::1".parse().unwrap();
        let dst: Ipv6Addr = "ff02::1".parse().unwrap();
        let p = packet(ICMPV6, src, dst, &[1, 2, 3]);
        let h = parse(&p).unwrap();
        assert_eq!((h.src, h.dst, h.hop_limit, h.upper_protocol, h.payload_offset), (src, dst, 64, ICMPV6, 40));
    }

    #[test]
    fn extension_headers_are_skipped_to_find_the_real_protocol() {
        let src: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst: Ipv6Addr = "2001:db8::2".parse().unwrap();
        // Hop-by-Hop (8 bytes: next=Fragment, len=0) -> Fragment (8 bytes, fixed, next=ICMPv6) -> ICMPv6
        let mut ext = vec![FRAGMENT, 0, 0, 0, 0, 0, 0, 0]; // hop-by-hop header, 8 bytes total
        ext.extend_from_slice(&[ICMPV6, 0, 0, 0, 0, 0, 0, 0]); // fragment header, 8 bytes total
        ext.extend_from_slice(&[9, 9]); // the "real" payload
        let p = packet(HOP_BY_HOP, src, dst, &ext);
        let h = parse(&p).unwrap();
        assert_eq!((h.upper_protocol, h.payload_offset), (ICMPV6, 40 + 16));
        assert_eq!(&p[h.payload_offset..], [9, 9]);
    }

    #[test]
    fn a_chain_that_runs_past_the_end_of_the_packet_is_rejected_not_panicked_on() {
        // claims a Hop-by-Hop header far longer than what actually follows
        let p = packet(HOP_BY_HOP, Ipv6Addr::UNSPECIFIED, Ipv6Addr::UNSPECIFIED, &[ICMPV6, 200]);
        assert_eq!(parse(&p), None);
    }

    #[test]
    fn too_short_or_the_wrong_version_is_rejected() {
        assert_eq!(parse(&[0x60; 39]), None); // one byte short of a full header
        let mut p = packet(ICMPV6, Ipv6Addr::UNSPECIFIED, Ipv6Addr::UNSPECIFIED, &[]);
        p[0] = 0x45; // IPv4's version nibble
        assert_eq!(parse(&p), None);
    }

    #[test]
    fn no_next_header_is_reported_as_such_not_treated_as_an_error() {
        let p = packet(NO_NEXT_HEADER, Ipv6Addr::LOCALHOST, Ipv6Addr::LOCALHOST, &[]);
        assert_eq!(parse(&p).unwrap().upper_protocol, NO_NEXT_HEADER);
    }

    #[test]
    fn neighbor_solicitation_gives_the_target_address() {
        let target: Ipv6Addr = "fe80::42".parse().unwrap();
        let mut body = vec![135, 0, 0, 0, 0, 0, 0, 0];
        body.extend_from_slice(&target.octets());
        assert_eq!(parse_icmpv6(&body), Some(Icmpv6::NeighborSolicitation { target }));
    }

    #[test]
    fn neighbor_advertisement_gives_the_target_and_the_link_layer_option_when_present() {
        let target: Ipv6Addr = "2001:db8::abcd".parse().unwrap();
        let mut body = vec![136, 0, 0, 0, 0, 0, 0, 0];
        body.extend_from_slice(&target.octets());
        // Source Link-Layer Address option: type 1, length 1 (8-byte unit), then the MAC
        body.extend_from_slice(&[1, 1, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(parse_icmpv6(&body), Some(Icmpv6::NeighborAdvertisement { target, source_link_layer: Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]) }));
    }

    #[test]
    fn neighbor_advertisement_without_a_recognised_option_still_gives_the_target() {
        let target: Ipv6Addr = "::1".parse().unwrap();
        let mut body = vec![136, 0, 0, 0, 0, 0, 0, 0];
        body.extend_from_slice(&target.octets());
        assert_eq!(parse_icmpv6(&body), Some(Icmpv6::NeighborAdvertisement { target, source_link_layer: None }));
    }

    #[test]
    fn router_advertisement_and_solicitation_are_recognised() {
        assert_eq!(parse_icmpv6(&[134, 0, 0, 0]), Some(Icmpv6::RouterAdvertisement));
        assert_eq!(parse_icmpv6(&[133, 0, 0, 0]), Some(Icmpv6::RouterAdvertisement));
    }

    #[test]
    fn an_uninteresting_or_empty_message_is_none_not_an_error() {
        assert_eq!(parse_icmpv6(&[128, 0, 0, 0]), None); // echo request
        assert_eq!(parse_icmpv6(&[]), None);
    }

    #[test]
    fn truncated_neighbor_messages_never_panic() {
        assert_eq!(parse_icmpv6(&[135]), None);
        assert_eq!(parse_icmpv6(&[136, 0, 0, 0, 0, 0, 0, 0]), None); // no target at all
    }

    #[test]
    fn a_malformed_option_chain_never_panics_or_loops_forever() {
        let target = Ipv6Addr::UNSPECIFIED;
        let mut body = vec![136, 0, 0, 0, 0, 0, 0, 0];
        body.extend_from_slice(&target.octets());
        body.extend_from_slice(&[1, 0]); // a zero-length option: would loop forever if not guarded
        assert_eq!(parse_icmpv6(&body), Some(Icmpv6::NeighborAdvertisement { target, source_link_layer: None }));
    }

    /// Small deterministic PRNG (xorshift64*) so a fuzz failure is reproducible.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next() % n.max(1) as u64) as usize
        }
    }

    #[test]
    fn parsing_never_panics_on_truncated_or_random_input() {
        let good = packet(ICMPV6, "fe80::1".parse().unwrap(), "ff02::1".parse().unwrap(), &[1, 2, 3, 4, 5]);
        for cut in 0..good.len() {
            let _ = parse(&good[..cut]); // truncated at every point: must not panic
        }
        let mut rng = Rng(0xf00d_1ce6);
        for _ in 0..3000 {
            let n = rng.below(200);
            let junk: Vec<u8> = (0..n).map(|_| rng.next() as u8).collect();
            let _ = parse(&junk);
            let _ = parse_icmpv6(&junk);
        }
    }

    #[test]
    fn link_local_addresses_are_recognised_by_prefix() {
        assert!(is_link_local(&"fe80::1".parse().unwrap()));
        assert!(is_link_local(&"febf:ffff::1".parse().unwrap())); // top of fe80::/10
        assert!(!is_link_local(&"fec0::1".parse().unwrap())); // just past it
        assert!(!is_link_local(&"2001:db8::1".parse().unwrap()));
        assert!(!is_link_local(&Ipv6Addr::LOCALHOST));
    }
}
