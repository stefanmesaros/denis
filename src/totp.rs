//! One-time codes from an authenticator app (RFC 6238 TOTP, the kind Google Authenticator, Microsoft
//! Authenticator, Authy, 1Password and Aegis all read): 6 digits, a new one every 30 seconds, HMAC-SHA1
//! (the variant every app supports), plus the recovery codes that stand in when the phone is lost.
//!
//! What is verified here: a code is accepted for the current 30-second step and one step either side (clock
//! drift), and each step can be used **once** (the caller passes the last step it accepted, so a code that
//! was watched over a shoulder cannot be replayed). Recovery codes are random and long enough that a
//! plain SHA-256 is a sound way to store them; each works once.

use anyhow::{anyhow, Result};
use ring::hmac;

pub const STEP_SECS: i64 = 30;
pub const DIGITS: u32 = 6;
pub const SECRET_BYTES: usize = 20;
pub const RECOVERY_CODES: usize = 10;

/// A fresh random secret (160 bits, what the RFC recommends for SHA-1).
pub fn generate_secret() -> Result<[u8; SECRET_BYTES]> {
    let mut b = [0u8; SECRET_BYTES];
    getrandom::fill(&mut b).map_err(|e| anyhow!("no secure randomness available: {e}"))?;
    Ok(b)
}

/// RFC 4648 base32 without padding: how authenticator apps take a secret typed by hand.
pub fn base32(bytes: &[u8]) -> String {
    const A: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let (mut buf, mut bits) = (0u32, 0);
    for &b in bytes {
        buf = (buf << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            out.push(A[((buf >> (bits - 5)) & 31) as usize] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        out.push(A[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// The code for one 30-second step (RFC 4226 dynamic truncation).
pub fn code_at(secret: &[u8], step: i64) -> u32 {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);
    let tag = hmac::sign(&key, &(step as u64).to_be_bytes());
    let h = tag.as_ref();
    let off = (h[19] & 0x0f) as usize;
    let bin = u32::from_be_bytes([h[off] & 0x7f, h[off + 1], h[off + 2], h[off + 3]]);
    bin % 10u32.pow(DIGITS)
}

/// The step a moment falls in.
pub fn step_of(now: i64) -> i64 {
    now.div_euclid(STEP_SECS)
}

/// Check what the person typed. Returns the step it belongs to when it is right **and** newer than
/// `last_used_step` (so each code works once); the caller must then store that step.
pub fn verify(secret: &[u8], typed: &str, now: i64, last_used_step: i64) -> Option<i64> {
    let digits: String = typed.chars().filter(|c| !c.is_whitespace() && *c != '-').collect();
    if digits.len() != DIGITS as usize || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let typed: u32 = digits.parse().ok()?;
    let now_step = step_of(now);
    // one step either side covers a clock that is a little off; check them all (no early exit on the first hit's position)
    let mut found = None;
    for step in [now_step - 1, now_step, now_step + 1] {
        if code_at(secret, step) == typed && step > last_used_step && found.is_none_or(|f| step > f) {
            found = Some(step);
        }
    }
    found
}

fn pct(s: &str) -> String {
    s.bytes().map(|b| if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') { (b as char).to_string() } else { format!("%{b:02X}") }).collect()
}

/// The address an authenticator app reads from the QR code (the "Key URI format").
pub fn otpauth_uri(issuer: &str, account: &str, secret: &[u8]) -> String {
    format!("otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits={DIGITS}&period={STEP_SECS}", pct(issuer), pct(account), base32(secret), pct(issuer))
}

/// A QR code as a small self-contained SVG (black modules on a white square, with the quiet zone).
pub fn qr_svg(text: &str) -> Result<String> {
    use qrcode::{Color, EcLevel, QrCode};
    let code = QrCode::with_error_correction_level(text.as_bytes(), EcLevel::M).map_err(|e| anyhow!("QR code: {e}"))?;
    let n = code.width();
    let quiet = 4;
    let size = n + 2 * quiet;
    let mut path = String::new();
    for (i, c) in code.to_colors().iter().enumerate() {
        if *c == Color::Dark {
            let (x, y) = (i % n + quiet, i / n + quiet);
            path.push_str(&format!("M{x} {y}h1v1h-1z"));
        }
    }
    Ok(format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {size} {size}\" shape-rendering=\"crispEdges\" role=\"img\"><rect width=\"{size}\" height=\"{size}\" fill=\"#fff\"/><path d=\"{path}\" fill=\"#000\"/></svg>"
    ))
}

/// Ten recovery codes like `k7m2p-9qx4d`: 50 random bits each, from an alphabet without look-alikes.
pub fn new_recovery_codes() -> Result<Vec<String>> {
    const A: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789"; // 31 characters
    let limit = 256 - (256 % A.len()); // rejection sampling: no modulo bias
    let mut out = Vec::new();
    while out.len() < RECOVERY_CODES {
        let mut raw = [0u8; 64];
        getrandom::fill(&mut raw).map_err(|e| anyhow!("no secure randomness available: {e}"))?;
        let mut chars = raw.iter().filter(|b| (**b as usize) < limit).map(|b| A[*b as usize % A.len()] as char);
        while out.len() < RECOVERY_CODES {
            let code: String = chars.by_ref().take(10).collect();
            if code.len() < 10 {
                break;
            }
            out.push(format!("{}-{}", &code[..5], &code[5..]));
        }
    }
    Ok(out)
}

/// What a person typed as a recovery code, reduced to what is compared: lower case, letters and digits only.
pub fn normalize_recovery(typed: &str) -> String {
    typed.chars().filter(|c| c.is_ascii_alphanumeric()).map(|c| c.to_ascii_lowercase()).collect()
}

/// Does this look like a recovery code (10 letters/digits) rather than a 6-digit code?
pub fn looks_like_recovery(typed: &str) -> bool {
    normalize_recovery(typed).len() == 10
}

pub fn hash_recovery(typed: &str) -> String {
    crate::auth::sha256_hex(&format!("denis-recovery:{}", normalize_recovery(typed)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 appendix B, SHA-1, secret "12345678901234567890" (the RFC lists 8 digits; these are the last 6).
    #[test]
    fn matches_the_rfc_6238_test_vectors() {
        let secret = b"12345678901234567890";
        for (time, code) in [(59, 287_082), (1_111_111_109, 81_804), (1_111_111_111, 50_471), (1_234_567_890, 5_924), (2_000_000_000, 279_037), (20_000_000_000i64, 353_130)] {
            assert_eq!(code_at(secret, step_of(time)), code, "t={time}");
        }
    }

    #[test]
    fn base32_matches_the_rfc_4648_vectors_and_the_rfc_secret() {
        assert_eq!(base32(b""), "");
        assert_eq!(base32(b"f"), "MY");
        assert_eq!(base32(b"fo"), "MZXQ");
        assert_eq!(base32(b"foobar"), "MZXW6YTBOI");
        assert_eq!(base32(b"12345678901234567890"), "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    }

    #[test]
    fn a_code_is_accepted_for_its_step_and_one_either_side_but_only_once() {
        let s = b"12345678901234567890";
        let t = 1_111_111_111;
        let now_code = format!("{:06}", code_at(s, step_of(t)));
        assert_eq!(verify(s, &now_code, t, 0), Some(step_of(t)));
        assert_eq!(verify(s, &format!("{} {}", &now_code[..3], &now_code[3..]), t, 0), Some(step_of(t)), "spaces are fine");
        // a clock that is a step off still works
        assert_eq!(verify(s, &now_code, t + 30, 0), Some(step_of(t)));
        assert_eq!(verify(s, &now_code, t - 30, 0), Some(step_of(t)));
        assert_eq!(verify(s, &now_code, t + 90, 0), None, "two steps off is too far");
        // replay: the same step cannot be used twice, an older one neither
        assert_eq!(verify(s, &now_code, t, step_of(t)), None);
        assert_eq!(verify(s, &now_code, t, step_of(t) + 1), None);
        // not codes at all
        for bad in ["", "12345", "1234567", "abcdef", "000000", "12 34 5x"] {
            assert_eq!(verify(s, bad, t, 0), if bad == "000000" && code_at(s, step_of(t)) == 0 { Some(step_of(t)) } else { None }, "{bad:?}");
        }
    }

    #[test]
    fn the_key_uri_carries_the_secret_and_escapes_names() {
        let u = otpauth_uri("My DENIS", "ana@example.com", b"12345678901234567890");
        assert_eq!(u, "otpauth://totp/My%20DENIS:ana%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=My%20DENIS&algorithm=SHA1&digits=6&period=30");
        assert!(!otpauth_uri("a&b=c", "x y", b"k").contains("a&b"), "an ampersand in a name must not start a new parameter");
    }

    #[test]
    fn the_qr_code_is_a_self_contained_svg() {
        let svg = qr_svg(&otpauth_uri("DENIS", "ana", b"12345678901234567890")).unwrap();
        assert!(svg.starts_with("<svg ") && svg.ends_with("</svg>") && svg.contains("<path d=\"M"));
        assert!(!svg.contains("<script") && !svg.contains("href"));
    }

    #[test]
    fn recovery_codes_are_random_readable_unique_and_compared_loosely() {
        let a = new_recovery_codes().unwrap();
        assert_eq!(a.len(), RECOVERY_CODES);
        for c in &a {
            assert_eq!(c.len(), 11);
            assert_eq!(c.as_bytes()[5], b'-');
            assert!(looks_like_recovery(c));
            assert!(c.chars().all(|ch| ch == '-' || "abcdefghjkmnpqrstuvwxyz23456789".contains(ch)), "{c}");
        }
        let mut sorted = a.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), RECOVERY_CODES);
        assert_ne!(a, new_recovery_codes().unwrap());
        // typed in capitals, with spaces or without the dash: the same code
        let c = &a[0];
        assert_eq!(hash_recovery(c), hash_recovery(&c.to_uppercase().replace('-', " ")));
        assert_ne!(hash_recovery(c), hash_recovery(&a[1]));
        assert!(!looks_like_recovery("123456"));
    }
}
