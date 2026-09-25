//! JA3 / JA3S TLS client and server fingerprinting.
//!
//! This is the original 2017 method (Salesforce, public domain, no known patent on it and
//! reimplemented freely by nmap, Zeek, Suricata, Wireshark and most other network tools) —
//! deliberately *not* FoxIO's newer JA4+ family, which is patent-pending and license-restricted.
//! The idea is the same either way and the value to DENIS is the same: a TLS client (or server)
//! is characterised by the *values and order* of what its ClientHello (or ServerHello) presents,
//! hashed to a short id that is stable for one piece of software and differs between them —
//! useful for spotting "this device's TLS stack doesn't match what it claims to be" or grouping
//! otherwise-anonymous devices that share a client.
//!
//! Bounds-checked throughout: these are attacker/network-controlled bytes, and a mirror-port
//! capture can also just cut a hello short (see `capture.rs`'s snaplen).

use std::collections::BTreeMap;

use md5::{Digest, Md5};

/// Is `v` one of the 16 GREASE values (RFC 8701) a TLS-1.3-aware client/server inserts into
/// cipher suites, extensions or supported groups specifically so naive fingerprinting breaks on
/// them? Filtered out before hashing, exactly as the reference implementation does.
fn is_grease(v: u16) -> bool {
    let (hi, lo) = ((v >> 8) as u8, (v & 0xff) as u8);
    hi == lo && hi & 0x0f == 0x0a
}

fn rd16(p: &[u8], i: usize) -> Option<u16> {
    p.get(i..i + 2).map(|b| u16::from_be_bytes([b[0], b[1]]))
}

struct Hello {
    version: u16,
    ciphers: Vec<u16>,
    extensions: Vec<u16>,
    curves: Vec<u16>,
    point_formats: Vec<u8>,
}

/// Parse the fields of a ClientHello (`client = true`) or ServerHello, from the start of the TLS
/// record (the content-type byte) through its extensions.
fn parse_hello(p: &[u8], client: bool) -> Option<Hello> {
    let version = rd16(p, 9)?;
    let mut i = 43usize; // record header 5 + handshake header 4 + version 2 + random 32
    i += 1 + *p.get(i)? as usize; // session id
    let mut ciphers = Vec::new();
    if client {
        let len = rd16(p, i)? as usize;
        i += 2;
        let end = (i + len).min(p.len());
        while i + 2 <= end {
            let c = rd16(p, i)?;
            if !is_grease(c) {
                ciphers.push(c);
            }
            i += 2;
        }
        i = i.max(end);
        i += 1 + *p.get(i)? as usize; // compression methods
    } else {
        ciphers.push(rd16(p, i)?); // the one cipher the server chose
        i += 2;
        i += 1; // compression method
    }
    let mut extensions = Vec::new();
    let mut curves = Vec::new();
    let mut point_formats = Vec::new();
    if let Some(ext_len) = rd16(p, i) {
        i += 2;
        let end = (i + ext_len as usize).min(p.len());
        while i + 4 <= end {
            let (t, l) = (rd16(p, i)?, rd16(p, i + 2)? as usize);
            let body = p.get(i + 4..(i + 4 + l).min(end))?;
            if !is_grease(t) {
                extensions.push(t);
            }
            if client {
                match t {
                    // supported_groups (elliptic curves)
                    10 if body.len() >= 2 => {
                        let n = (u16::from_be_bytes([body[0], body[1]]) as usize).min(body.len().saturating_sub(2));
                        for c in body[2..2 + n].chunks_exact(2) {
                            let g = u16::from_be_bytes([c[0], c[1]]);
                            if !is_grease(g) {
                                curves.push(g);
                            }
                        }
                    }
                    // ec_point_formats
                    11 if !body.is_empty() => {
                        let n = (body[0] as usize).min(body.len().saturating_sub(1));
                        point_formats.extend_from_slice(&body[1..1 + n]);
                    }
                    _ => {}
                }
            }
            i += 4 + l;
        }
    }
    Some(Hello { version, ciphers, extensions, curves, point_formats })
}

fn md5_hex(s: &str) -> String {
    let mut h = Md5::new();
    h.update(s.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn join<T: ToString>(v: &[T]) -> String {
    v.iter().map(T::to_string).collect::<Vec<_>>().join("-")
}

/// JA3 fingerprint of a captured ClientHello: the raw "version,ciphers,extensions,curves,point
/// formats" string and its MD5 hash (the id used everywhere else, including public JA3 lookup
/// lists). `None` if `record` is not a (complete enough) ClientHello.
pub fn client_ja3(record: &[u8]) -> Option<(String, String)> {
    let h = parse_hello(record, true)?;
    let s = format!("{},{},{},{},{}", h.version, join(&h.ciphers), join(&h.extensions), join(&h.curves), join(&h.point_formats));
    let digest = md5_hex(&s);
    Some((s, digest))
}

/// JA3S fingerprint of a captured ServerHello: "version,cipher,extensions". Identifies the TLS
/// stack a server runs, independent of which certificate it presents.
pub fn server_ja3s(record: &[u8]) -> Option<(String, String)> {
    let h = parse_hello(record, false)?;
    let s = format!("{},{},{}", h.version, join(&h.ciphers), join(&h.extensions));
    let digest = md5_hex(&s);
    Some((s, digest))
}

/// Convenience for callers that already branched on message type: fold whichever of
/// [`client_ja3`] / [`server_ja3s`] applies into an identity map keyed the way
/// `Fingerprint::identity` expects (`ja3`/`ja3_raw` or `ja3s`/`ja3s_raw`).
pub fn identity(record: &[u8], client: bool) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    let fp = if client { client_ja3(record) } else { server_ja3s(record) };
    if let Some((raw, hash)) = fp {
        m.insert(if client { "ja3" } else { "ja3s" }.into(), hash);
        m.insert(if client { "ja3_raw" } else { "ja3s_raw" }.into(), raw);
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal, hand-built ClientHello: TLS 1.2 legacy version, two cipher suites (one GREASE),
    /// no session id, one GREASE extension plus supported_groups (one curve) and ec_point_formats.
    fn client_hello() -> Vec<u8> {
        let mut hs = Vec::new();
        hs.push(1); // handshake type: ClientHello
        hs.extend([0, 0, 0]); // handshake length placeholder
        hs.extend([3, 3]); // legacy_version = TLS1.2 (771)
        hs.extend([0u8; 32]); // random
        hs.push(0); // session id length 0
        // cipher suites: GREASE, then TLS_AES_128_GCM_SHA256 (0x1301 = 4865)
        hs.extend([0, 4]);
        hs.extend([0x0a, 0x0a]);
        hs.extend([0x13, 0x01]);
        hs.push(1); // compression methods length
        hs.push(0); // null
        // extensions
        let ext_start = hs.len();
        hs.extend([0, 0]); // extensions length placeholder
        hs.extend([0x1a, 0x1a, 0, 0]); // GREASE extension, empty body
        hs.extend([0, 10, 0, 4, 0, 2, 0x00, 0x1d]); // supported_groups: x25519 (0x001d = 29)
        hs.extend([0, 11, 0, 2, 1, 0]); // ec_point_formats: uncompressed (0)
        let ext_len = (hs.len() - ext_start - 2) as u16;
        hs[ext_start..ext_start + 2].copy_from_slice(&ext_len.to_be_bytes());
        let hs_len = (hs.len() - 4) as u32;
        hs[1..4].copy_from_slice(&hs_len.to_be_bytes()[1..]);

        let mut b = vec![0x16, 3, 1]; // content type, record version (ignored by JA3)
        b.extend((hs.len() as u16).to_be_bytes());
        b.extend(hs);
        b
    }

    #[test]
    fn client_ja3_strips_grease_and_orders_fields() {
        let (raw, hash) = client_ja3(&client_hello()).unwrap();
        assert_eq!(raw, "771,4865,10-11,29,0");
        assert_eq!(hash.len(), 32);
        assert_eq!(hash, md5_hex(&raw));
    }

    #[test]
    fn truncated_hello_is_none() {
        let full = client_hello();
        assert!(client_ja3(&full[..20]).is_none());
    }

    #[test]
    fn server_hello_uses_three_fields() {
        let mut b = Vec::new();
        b.extend([0x16, 3, 3, 0, 0]);
        b.push(2); // ServerHello
        b.extend([0, 0, 0]);
        b.extend([3, 3]); // legacy_version
        b.extend([0u8; 32]);
        b.push(0); // session id
        b.extend([0x13, 0x01]); // chosen cipher
        b.push(0); // compression
        b.extend([0, 4]); // extensions length
        b.extend([0, 43, 0, 0]); // supported_versions, empty body
        let (raw, hash) = server_ja3s(&b).unwrap();
        assert_eq!(raw, "771,4865,43");
        assert_eq!(hash, md5_hex(&raw));
    }

    #[test]
    fn no_grease_false_positive_on_mismatched_bytes() {
        // 0x1a2a: low nibble of both bytes is 0xa, but the bytes themselves differ, so this is
        // NOT a GREASE value and must survive filtering.
        assert!(!is_grease(0x1a2a));
        assert!(is_grease(0xcaca));
    }
}
