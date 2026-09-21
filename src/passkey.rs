//! Passkeys (WebAuthn): sign in with a fingerprint, face, device PIN or a security
//! key instead of a password. Phishing-resistant and nothing secret is ever typed.
//!
//! This module holds the *protocol*: building the options a browser needs, and
//! verifying what the browser (the "authenticator") sends back. It is deliberately
//! small and strict, and every check WebAuthn requires of a relying party is here:
//!
//! **Registration** (`verify_registration`): the client data says `webauthn.create`,
//! carries exactly the challenge we issued and an origin we expect; the attestation is
//! format `none` (we ask for no attestation and accept no other, so there is no
//! certificate chain to trust); the authenticator data proves the right relying party
//! (`rpIdHash`), that a person was present *and verified* (flags UP and UV), and carries
//! a credential with an ES256 (ECDSA P-256) public key.
//!
//! **Sign-in** (`verify_assertion`): `webauthn.get`, our challenge, our origin, the same
//! `rpIdHash` and UP+UV flags, and an ECDSA signature over `authData ‖ SHA-256(clientData)`
//! that verifies under the public key stored at registration. A signature counter that
//! goes backwards (when the authenticator uses one) means a cloned key and is refused.
//!
//! Only ES256 is offered: every platform authenticator and security key supports it and
//! it keeps the verifier to one algorithm. Cryptography is `ring`; parsing is `ciborium`.
//!
//! Where a passkey may be used is pinned by configuration ([`Config`]): the relying-party
//! id and the exact origins. They come from `--public-url` (or `localhost` when the console
//! listens on loopback), never from request headers, so a spoofed `Host` cannot move them.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use ciborium::value::Value;
use ring::digest;
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1};
use serde_json::{json, Value as Json};

/// How long a challenge stays valid.
const CEREMONY_TTL: Duration = Duration::from_secs(300);
/// Unfinished ceremonies kept at once (a flood of `begin` calls cannot exhaust memory).
const MAX_CEREMONIES: usize = 2000;
const MAX_CRED_ID: usize = 1023;

const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_AT: u8 = 0x40;

// ------------------------------------------------------------------ base64url

const URL_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

pub fn b64url(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for c in bytes.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        out.push(URL_ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(URL_ALPHABET[(n >> 12) as usize & 63] as char);
        if c.len() > 1 {
            out.push(URL_ALPHABET[(n >> 6) as usize & 63] as char);
        }
        if c.len() > 2 {
            out.push(URL_ALPHABET[n as usize & 63] as char);
        }
    }
    out
}

/// Decode unpadded (or padded) base64url; `None` for anything else.
pub fn unb64url(s: &str) -> Option<Vec<u8>> {
    let s = s.trim_end_matches('=');
    if s.len() % 4 == 1 || s.len() > 200_000 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0);
    for ch in s.bytes() {
        let v = URL_ALPHABET.iter().position(|c| *c == ch)? as u32;
        acc = acc << 6 | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

// -------------------------------------------------------------------- config

/// Where passkeys are valid.
#[derive(Clone, Debug, PartialEq)]
pub struct Config {
    /// The relying-party id: a host name, or `localhost`.
    pub rp_id: String,
    /// Exact origins (`https://host[:port]`) a browser may report.
    pub origins: Vec<String>,
}

impl Config {
    /// From `--public-url` (an `https://` address users type), or `localhost` when the
    /// console listens on loopback. `None` = passkeys are not available on this setup.
    pub fn from_settings(public_url: Option<&str>, listen: SocketAddr, https: bool) -> Result<Option<Config>, String> {
        if let Some(u) = public_url {
            let (scheme, rest) = u.split_once("://").ok_or("--public-url must look like https://denis.example.com")?;
            let authority = rest.trim_end_matches('/');
            if authority.is_empty() || authority.contains(['/', '?', '#', '@']) || !matches!(scheme, "https" | "http") {
                return Err("--public-url must be just a scheme and host, like https://denis.example.com".into());
            }
            let host = authority.rsplit_once(':').filter(|(_, p)| p.chars().all(|c| c.is_ascii_digit())).map_or(authority, |(h, _)| h);
            // browsers only allow WebAuthn in a secure context: https, or localhost
            if scheme == "http" && host != "localhost" {
                return Err("passkeys need https:// (only localhost may use http://)".into());
            }
            if host.starts_with('[') || host.parse::<std::net::Ipv4Addr>().is_ok() {
                return Err("passkeys need a host name, not an IP address".into());
            }
            return Ok(Some(Config { rp_id: host.to_ascii_lowercase(), origins: vec![format!("{scheme}://{}", authority.to_ascii_lowercase())] }));
        }
        if listen.ip().is_loopback() {
            return Ok(Some(Config { rp_id: "localhost".into(), origins: vec![format!("{}://localhost:{}", if https { "https" } else { "http" }, listen.port())] }));
        }
        Ok(None)
    }
}

// ----------------------------------------------------------------- ceremonies

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Kind {
    Register,
    Login,
}

struct Pending {
    challenge: Vec<u8>,
    kind: Kind,
    /// Who is registering (login ceremonies have no user yet: the credential says who).
    user_id: Option<i64>,
    expires: Instant,
}

/// Outstanding challenges: single use, short lived, bounded.
#[derive(Default)]
pub struct Ceremonies {
    map: HashMap<String, Pending>,
}

fn random(n: usize) -> Result<Vec<u8>, String> {
    let mut b = vec![0u8; n];
    SystemRandom::new().fill(&mut b).map_err(|_| "no secure randomness available".to_string())?;
    Ok(b)
}

impl Ceremonies {
    /// Issue a challenge. Returns `(ceremony id, challenge bytes)`.
    pub fn begin(&mut self, kind: Kind, user_id: Option<i64>) -> Result<(String, Vec<u8>), String> {
        let now = Instant::now();
        self.map.retain(|_, p| p.expires > now);
        if self.map.len() >= MAX_CEREMONIES {
            return Err("too many sign-ins in progress; try again in a minute".into());
        }
        let id = b64url(&random(24)?);
        let challenge = random(32)?;
        self.map.insert(id.clone(), Pending { challenge: challenge.clone(), kind, user_id, expires: now + CEREMONY_TTL });
        Ok((id, challenge))
    }

    /// Take a ceremony (it can never be used twice, even if verification then fails).
    pub fn take(&mut self, id: &str, kind: Kind) -> Option<(Vec<u8>, Option<i64>)> {
        let p = self.map.remove(id)?;
        (p.kind == kind && p.expires > Instant::now()).then_some((p.challenge, p.user_id))
    }
}

// ------------------------------------------------------------------- options

/// What the browser needs to create a passkey (`navigator.credentials.create`).
/// Binary fields are base64url; the page converts them.
pub fn creation_options(cfg: &Config, challenge: &[u8], user_id: i64, username: &str, existing: &[Vec<u8>], product: &str) -> Json {
    json!({
        "challenge": b64url(challenge),
        "rp": { "id": cfg.rp_id, "name": product },
        "user": { "id": b64url(&user_id.to_be_bytes()), "name": username, "displayName": username },
        "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }],
        "timeout": 120_000,
        // a discoverable credential, so signing in needs no user name; a person must be verified
        "authenticatorSelection": { "residentKey": "required", "requireResidentKey": true, "userVerification": "required" },
        "attestation": "none",
        "excludeCredentials": existing.iter().map(|id| json!({ "type": "public-key", "id": b64url(id) })).collect::<Vec<_>>(),
    })
}

/// What the browser needs to sign in (`navigator.credentials.get`).
pub fn request_options(cfg: &Config, challenge: &[u8]) -> Json {
    json!({
        "challenge": b64url(challenge),
        "rpId": cfg.rp_id,
        "timeout": 120_000,
        "userVerification": "required",
        "allowCredentials": [], // usernameless: the passkey names its owner
    })
}

// -------------------------------------------------------------- verification

/// Why a ceremony was refused. Messages are safe to show to the person signing in.
#[derive(Debug, PartialEq)]
pub enum PasskeyError {
    /// The request was malformed or failed a check.
    Invalid(&'static str),
}

impl std::fmt::Display for PasskeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let PasskeyError::Invalid(m) = self;
        f.write_str(m)
    }
}

type R<T> = Result<T, PasskeyError>;

fn bad<T>(m: &'static str) -> R<T> {
    Err(PasskeyError::Invalid(m))
}

/// Check the client data JSON: right ceremony type, our challenge, an origin we expect.
fn check_client_data(cfg: &Config, want_type: &str, challenge: &[u8], raw: &[u8]) -> R<()> {
    let v: Json = serde_json::from_slice(raw).or_else(|_| bad("the passkey response is not valid"))?;
    if v["type"] != want_type {
        return bad("the passkey response is for a different operation");
    }
    if v["challenge"].as_str() != Some(&b64url(challenge)) {
        return bad("the passkey response does not match this sign-in (challenge)");
    }
    let origin = v["origin"].as_str().unwrap_or("");
    if !cfg.origins.iter().any(|o| o == origin) {
        return bad("the passkey was created for a different web address than the one configured (--public-url)");
    }
    // a page embedded in another site must not be able to use our passkeys
    if v["crossOrigin"].as_bool() == Some(true) || v.get("topOrigin").is_some() {
        return bad("passkeys cannot be used from an embedded page");
    }
    Ok(())
}

/// The fixed part of authenticator data.
struct AuthData<'a> {
    flags: u8,
    sign_count: u32,
    rest: &'a [u8],
}

fn parse_auth_data<'a>(cfg: &Config, d: &'a [u8]) -> R<AuthData<'a>> {
    if d.len() < 37 {
        return bad("the passkey response is too short");
    }
    let rp_hash = digest::digest(&digest::SHA256, cfg.rp_id.as_bytes());
    if d[..32] != *rp_hash.as_ref() {
        return bad("the passkey belongs to a different site (relying party)");
    }
    let flags = d[32];
    // a person must have been present AND verified (fingerprint, face, PIN): that is what makes a passkey "two factors in one"
    if flags & FLAG_UP == 0 || flags & FLAG_UV == 0 {
        return bad("the passkey did not verify you (fingerprint, face or PIN is required)");
    }
    Ok(AuthData { flags, sign_count: u32::from_be_bytes([d[33], d[34], d[35], d[36]]), rest: &d[37..] })
}

/// A passkey accepted at registration.
#[derive(Debug, PartialEq)]
pub struct NewCredential {
    pub credential_id: Vec<u8>,
    /// Uncompressed P-256 point: `04 ‖ x ‖ y` (65 bytes).
    pub public_key: Vec<u8>,
    pub sign_count: u32,
}

fn cbor_get(map: &[(Value, Value)], key: i128) -> Option<&Value> {
    map.iter().find(|(k, _)| matches!(k, Value::Integer(i) if i128::from(*i) == key)).map(|(_, v)| v)
}

fn cbor_int(v: Option<&Value>) -> Option<i128> {
    match v? {
        Value::Integer(i) => Some(i128::from(*i)),
        _ => None,
    }
}

pub fn verify_registration(cfg: &Config, challenge: &[u8], client_data_json: &[u8], attestation_object: &[u8]) -> R<NewCredential> {
    check_client_data(cfg, "webauthn.create", challenge, client_data_json)?;
    let att: Value = ciborium::de::from_reader(attestation_object).or_else(|_| bad("the passkey response is not valid"))?;
    let Value::Map(att) = att else { return bad("the passkey response is not valid") };
    let field = |name: &str| att.iter().find(|(k, _)| matches!(k, Value::Text(t) if t == name)).map(|(_, v)| v);
    // we asked for no attestation: anything else is refused, so there is no attestation to trust
    if !matches!(field("fmt"), Some(Value::Text(f)) if f == "none") {
        return bad("only passkeys without attestation are accepted");
    }
    let Some(Value::Bytes(auth_data)) = field("authData") else { return bad("the passkey response is not valid") };
    let ad = parse_auth_data(cfg, auth_data)?;
    if ad.flags & FLAG_AT == 0 || ad.rest.len() < 18 {
        return bad("the passkey response carries no credential");
    }
    let id_len = u16::from_be_bytes([ad.rest[16], ad.rest[17]]) as usize;
    if id_len == 0 || id_len > MAX_CRED_ID || ad.rest.len() < 18 + id_len {
        return bad("the passkey response is not valid");
    }
    let credential_id = ad.rest[18..18 + id_len].to_vec();
    // The COSE public key follows; anything after it (extensions) is ignored.
    let mut key_bytes = &ad.rest[18 + id_len..];
    let key: Value = ciborium::de::from_reader(&mut key_bytes).or_else(|_| bad("the passkey's public key is not valid"))?;
    let Value::Map(key) = key else { return bad("the passkey's public key is not valid") };
    // kty 2 = EC2, alg -7 = ES256, crv 1 = P-256
    if cbor_int(cbor_get(&key, 1)) != Some(2) || cbor_int(cbor_get(&key, 3)) != Some(-7) || cbor_int(cbor_get(&key, -1)) != Some(1) {
        return bad("only ES256 (P-256) passkeys are supported");
    }
    let (Some(Value::Bytes(x)), Some(Value::Bytes(y))) = (cbor_get(&key, -2), cbor_get(&key, -3)) else { return bad("the passkey's public key is not valid") };
    if x.len() != 32 || y.len() != 32 {
        return bad("the passkey's public key is not valid");
    }
    let mut public_key = Vec::with_capacity(65);
    public_key.push(0x04);
    public_key.extend_from_slice(x);
    public_key.extend_from_slice(y);
    Ok(NewCredential { credential_id, public_key, sign_count: ad.sign_count })
}

/// Verify a sign-in. `stored_count` is the last counter we saw. Returns the new counter.
pub fn verify_assertion(
    cfg: &Config, challenge: &[u8], public_key: &[u8], stored_count: u32,
    client_data_json: &[u8], authenticator_data: &[u8], signature: &[u8],
) -> R<u32> {
    check_client_data(cfg, "webauthn.get", challenge, client_data_json)?;
    let ad = parse_auth_data(cfg, authenticator_data)?;
    let mut msg = authenticator_data.to_vec();
    msg.extend_from_slice(digest::digest(&digest::SHA256, client_data_json).as_ref());
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, public_key)
        .verify(&msg, signature)
        .or_else(|_| bad("the passkey signature is not valid"))?;
    // Many authenticators (and synced passkeys) always report 0. When a counter is in use it
    // must only ever go up: a repeat or a step back means the key has been copied.
    if (ad.sign_count != 0 || stored_count != 0) && ad.sign_count <= stored_count {
        return bad("this passkey looks cloned (its counter went backwards) and was refused");
    }
    Ok(ad.sign_count)
}

// ---------------------------------------------------------------------- tests

#[cfg(test)]
pub(crate) mod soft {
    //! A software authenticator: enough of a real one to run both ceremonies against the verifier.
    use super::*;
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

    pub struct Authenticator {
        key: EcdsaKeyPair,
        pub credential_id: Vec<u8>,
        pub counter: u32,
    }

    pub fn cbor(v: &Value) -> Vec<u8> {
        let mut out = Vec::new();
        ciborium::ser::into_writer(v, &mut out).unwrap();
        out
    }

    impl Authenticator {
        pub fn new() -> Self {
            let rng = SystemRandom::new();
            let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
            let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap();
            Authenticator { key, credential_id: random(32).unwrap(), counter: 0 }
        }

        pub fn public_key(&self) -> Vec<u8> {
            self.key.public_key().as_ref().to_vec()
        }

        pub fn client_data(kind: &str, challenge: &[u8], origin: &str) -> Vec<u8> {
            json!({ "type": kind, "challenge": b64url(challenge), "origin": origin, "crossOrigin": false }).to_string().into_bytes()
        }

        fn auth_data(&self, rp_id: &str, flags: u8, with_credential: bool) -> Vec<u8> {
            let mut d = digest::digest(&digest::SHA256, rp_id.as_bytes()).as_ref().to_vec();
            d.push(flags);
            d.extend_from_slice(&self.counter.to_be_bytes());
            if with_credential {
                d.extend_from_slice(&[0u8; 16]); // aaguid
                d.extend_from_slice(&(self.credential_id.len() as u16).to_be_bytes());
                d.extend_from_slice(&self.credential_id);
                let pk = self.public_key();
                d.extend(cbor(&Value::Map(vec![
                    (Value::Integer(1.into()), Value::Integer(2.into())),
                    (Value::Integer(3.into()), Value::Integer((-7).into())),
                    (Value::Integer((-1).into()), Value::Integer(1.into())),
                    (Value::Integer((-2).into()), Value::Bytes(pk[1..33].to_vec())),
                    (Value::Integer((-3).into()), Value::Bytes(pk[33..65].to_vec())),
                ])));
            }
            d
        }

        /// `(clientDataJSON, attestationObject)` as a browser would return them.
        pub fn register(&self, cfg: &Config, challenge: &[u8]) -> (Vec<u8>, Vec<u8>) {
            self.register_with(cfg, challenge, FLAG_UP | FLAG_UV | FLAG_AT, "none")
        }

        pub fn register_with(&self, cfg: &Config, challenge: &[u8], flags: u8, fmt: &str) -> (Vec<u8>, Vec<u8>) {
            let att = Value::Map(vec![
                (Value::Text("fmt".into()), Value::Text(fmt.into())),
                (Value::Text("attStmt".into()), Value::Map(vec![])),
                (Value::Text("authData".into()), Value::Bytes(self.auth_data(&cfg.rp_id, flags, true))),
            ]);
            (Self::client_data("webauthn.create", challenge, &cfg.origins[0]), cbor(&att))
        }

        /// `(clientDataJSON, authenticatorData, signature)`.
        pub fn assert(&mut self, cfg: &Config, challenge: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
            self.assert_with(cfg, challenge, FLAG_UP | FLAG_UV, &cfg.origins[0].clone())
        }

        pub fn assert_with(&mut self, cfg: &Config, challenge: &[u8], flags: u8, origin: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
            self.counter += 1;
            let cd = Self::client_data("webauthn.get", challenge, origin);
            let ad = self.auth_data(&cfg.rp_id, flags, false);
            let mut msg = ad.clone();
            msg.extend_from_slice(digest::digest(&digest::SHA256, &cd).as_ref());
            let sig = self.key.sign(&SystemRandom::new(), &msg).unwrap().as_ref().to_vec();
            (cd, ad, sig)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::soft::*;
    use super::*;

    fn cfg() -> Config {
        Config { rp_id: "denis.example.com".into(), origins: vec!["https://denis.example.com".into()] }
    }

    #[test]
    fn base64url_round_trips_and_rejects_garbage() {
        for n in 0..70usize {
            let data: Vec<u8> = (0..n).map(|i| (i * 37 + 11) as u8).collect();
            let e = b64url(&data);
            assert!(!e.contains(['+', '/', '=']));
            assert_eq!(unb64url(&e).unwrap(), data, "{n}");
        }
        assert_eq!(b64url(&[0xfb, 0xff]), "-_8");
        assert_eq!(unb64url("-_8").unwrap(), [0xfb, 0xff]);
        assert_eq!(unb64url("AQ==").unwrap(), [1], "padding is tolerated");
        for bad in ["A", "AAAAA", "a+b/", "ab cd", "é"] {
            assert!(unb64url(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn the_address_passkeys_belong_to_is_configured_never_taken_from_the_request() {
        let l: SocketAddr = "0.0.0.0:8443".parse().unwrap();
        let lo: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let c = Config::from_settings(Some("https://Denis.Example.com/"), l, true).unwrap().unwrap();
        assert_eq!((c.rp_id.as_str(), c.origins.as_slice()), ("denis.example.com", &["https://denis.example.com".to_string()][..]));
        let c = Config::from_settings(Some("https://denis.example.com:8443"), l, true).unwrap().unwrap();
        assert_eq!(c.origins[0], "https://denis.example.com:8443");
        assert_eq!(Config::from_settings(None, lo, false).unwrap().unwrap(), Config { rp_id: "localhost".into(), origins: vec!["http://localhost:8080".into()] });
        assert_eq!(Config::from_settings(None, lo, true).unwrap().unwrap().origins, vec!["https://localhost:8080".to_string()], "with TLS on, the origin is https");
        assert!(Config::from_settings(None, l, true).unwrap().is_none(), "reachable from the network but no public address: off");
        for bad in ["denis.example.com", "http://denis.example.com", "https://10.0.0.5", "https://[::1]", "https://a.example/x", "https://u@a.example", "ftp://a.example", "https://"] {
            assert!(Config::from_settings(Some(bad), l, true).is_err(), "{bad}");
        }
        assert!(Config::from_settings(Some("http://localhost:8080"), l, false).is_ok());
    }

    #[test]
    fn ceremonies_are_single_use_typed_and_bounded() {
        let mut c = Ceremonies::default();
        let (id, ch) = c.begin(Kind::Login, None).unwrap();
        assert_eq!(ch.len(), 32);
        assert!(c.take(&id, Kind::Register).is_none(), "a login challenge cannot finish a registration");
        assert!(c.take(&id, Kind::Login).is_none(), "and the wrong attempt consumed it");
        let (id, ch) = c.begin(Kind::Register, Some(7)).unwrap();
        assert_eq!(c.take(&id, Kind::Register), Some((ch, Some(7))));
        assert!(c.take(&id, Kind::Register).is_none(), "never twice");
        assert!(c.take("nope", Kind::Login).is_none());
        for _ in 0..MAX_CEREMONIES {
            let _ = c.begin(Kind::Login, None);
        }
        assert!(c.begin(Kind::Login, None).is_err(), "bounded");
    }

    #[test]
    fn a_genuine_registration_and_sign_in_verify() {
        let cfg = cfg();
        let mut a = Authenticator::new();
        let ch = random(32).unwrap();
        let (cd, att) = a.register(&cfg, &ch);
        let cred = verify_registration(&cfg, &ch, &cd, &att).unwrap();
        assert_eq!((cred.credential_id.as_slice(), cred.public_key.as_slice(), cred.sign_count), (a.credential_id.as_slice(), a.public_key().as_slice(), 0));
        // sign in twice; the counter must rise
        let ch2 = random(32).unwrap();
        let (cd, ad, sig) = a.assert(&cfg, &ch2);
        assert_eq!(verify_assertion(&cfg, &ch2, &cred.public_key, 0, &cd, &ad, &sig).unwrap(), 1);
        let ch3 = random(32).unwrap();
        let (cd, ad, sig) = a.assert(&cfg, &ch3);
        assert_eq!(verify_assertion(&cfg, &ch3, &cred.public_key, 1, &cd, &ad, &sig).unwrap(), 2);
    }

    #[test]
    fn registration_refuses_every_departure_from_the_protocol() {
        let cfg = cfg();
        let a = Authenticator::new();
        let ch = random(32).unwrap();
        let (cd, att) = a.register(&cfg, &ch);
        assert!(verify_registration(&cfg, &ch, &cd, &att).is_ok());
        // a different challenge (replay of an old ceremony)
        assert!(verify_registration(&cfg, &random(32).unwrap(), &cd, &att).is_err());
        // another site's origin, and another site's relying party
        let evil_cd = Authenticator::client_data("webauthn.create", &ch, "https://evil.example.com");
        assert!(verify_registration(&cfg, &ch, &evil_cd, &att).is_err());
        let other_rp = Config { rp_id: "other.example.com".into(), origins: vec!["https://denis.example.com".into()] };
        let (cd2, att2) = a.register(&other_rp, &ch);
        assert!(verify_registration(&cfg, &ch, &cd2, &att2).is_err(), "rpIdHash mismatch");
        // the wrong ceremony type
        let get_cd = Authenticator::client_data("webauthn.get", &ch, &cfg.origins[0]);
        assert!(verify_registration(&cfg, &ch, &get_cd, &att).is_err());
        // no user verification, no user presence, no credential data
        for flags in [FLAG_UP | FLAG_AT, FLAG_UV | FLAG_AT, FLAG_UP | FLAG_UV] {
            let (cd, att) = a.register_with(&cfg, &ch, flags, "none");
            assert!(verify_registration(&cfg, &ch, &cd, &att).is_err(), "flags {flags:#x}");
        }
        // an attestation format we do not accept
        let (cd, att) = a.register_with(&cfg, &ch, FLAG_UP | FLAG_UV | FLAG_AT, "packed");
        assert!(verify_registration(&cfg, &ch, &cd, &att).is_err());
        // embedded in another page
        let embedded = json!({"type": "webauthn.create", "challenge": b64url(&ch), "origin": cfg.origins[0], "crossOrigin": true}).to_string();
        assert!(verify_registration(&cfg, &ch, embedded.as_bytes(), &att).is_err());
        // garbage and truncation never panic
        for junk in [&b""[..], b"\xff\xff", b"{}", &att[..att.len() / 2], &att[..10]] {
            assert!(verify_registration(&cfg, &ch, &cd, junk).is_err());
            assert!(verify_registration(&cfg, &ch, junk, &att).is_err());
        }
    }

    #[test]
    fn sign_in_refuses_forged_replayed_unverified_and_cloned_responses() {
        let cfg = cfg();
        let mut a = Authenticator::new();
        let pk = a.public_key();
        let ch = random(32).unwrap();
        let (cd, ad, sig) = a.assert(&cfg, &ch);
        assert!(verify_assertion(&cfg, &ch, &pk, 0, &cd, &ad, &sig).is_ok());
        // someone else's key
        let stranger = Authenticator::new();
        assert!(verify_assertion(&cfg, &ch, &stranger.public_key(), 0, &cd, &ad, &sig).is_err());
        // the signature over different data (tampered authenticator data or client data)
        let mut ad2 = ad.clone();
        ad2[36] ^= 1;
        assert!(verify_assertion(&cfg, &ch, &pk, 0, &cd, &ad2, &sig).is_err());
        let cd2 = Authenticator::client_data("webauthn.get", &ch, &cfg.origins[0]).into_iter().chain(b" ".iter().copied()).collect::<Vec<_>>();
        assert!(verify_assertion(&cfg, &ch, &pk, 0, &cd2, &ad, &sig).is_err());
        assert!(verify_assertion(&cfg, &ch, &pk, 0, &cd, &ad, &sig[..sig.len() - 1]).is_err());
        // wrong challenge / origin / type
        assert!(verify_assertion(&cfg, &random(32).unwrap(), &pk, 0, &cd, &ad, &sig).is_err());
        let (cd_o, ad_o, sig_o) = a.assert_with(&cfg, &ch, FLAG_UP | FLAG_UV, "https://evil.example.com");
        assert!(verify_assertion(&cfg, &ch, &pk, 0, &cd_o, &ad_o, &sig_o).is_err());
        // no user verification (someone just touched a stolen key)
        let (cd_n, ad_n, sig_n) = a.assert_with(&cfg, &ch, FLAG_UP, &cfg.origins[0].clone());
        assert!(verify_assertion(&cfg, &ch, &pk, 0, &cd_n, &ad_n, &sig_n).is_err());
        // replay: the same counter, or a lower one, than the last we saw
        let (cd_r, ad_r, sig_r) = a.assert(&cfg, &ch); // counter is now 4
        assert!(verify_assertion(&cfg, &ch, &pk, 4, &cd_r, &ad_r, &sig_r).is_err(), "counter not increased");
        assert!(verify_assertion(&cfg, &ch, &pk, 9, &cd_r, &ad_r, &sig_r).is_err(), "counter went back");
        assert!(verify_assertion(&cfg, &ch, &pk, 3, &cd_r, &ad_r, &sig_r).is_ok());
        // authenticators that never count (synced passkeys) are fine
        let mut z = Authenticator::new();
        z.counter = 0;
        let ch = random(32).unwrap();
        let cd = Authenticator::client_data("webauthn.get", &ch, &cfg.origins[0]);
        let mut zero_ad = z.assert(&cfg, &ch).1;
        zero_ad[33..37].copy_from_slice(&[0, 0, 0, 0]);
        let mut msg = zero_ad.clone();
        msg.extend_from_slice(digest::digest(&digest::SHA256, &cd).as_ref());
        use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let k = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap();
        let sig = k.sign(&rng, &msg).unwrap();
        use ring::signature::KeyPair;
        assert_eq!(verify_assertion(&cfg, &ch, k.public_key().as_ref(), 0, &cd, &zero_ad, sig.as_ref()).unwrap(), 0);
        // garbage never panics
        for junk in [&b""[..], &[0u8; 5], &[0u8; 37], &[0xffu8; 200]] {
            assert!(verify_assertion(&cfg, &ch, &pk, 0, junk, junk, junk).is_err());
        }
    }

    #[test]
    fn options_ask_for_verified_discoverable_es256_credentials_with_no_attestation() {
        let cfg = cfg();
        let o = creation_options(&cfg, &[1; 32], 7, "vera", &[vec![9, 9]], "DENIS");
        assert_eq!(o["rp"]["id"], "denis.example.com");
        assert_eq!(o["pubKeyCredParams"][0]["alg"], -7);
        assert_eq!((o["attestation"].as_str(), o["authenticatorSelection"]["userVerification"].as_str(), o["authenticatorSelection"]["residentKey"].as_str()), (Some("none"), Some("required"), Some("required")));
        assert_eq!(o["excludeCredentials"][0]["id"], b64url(&[9, 9]));
        let r = request_options(&cfg, &[2; 32]);
        assert_eq!((r["userVerification"].as_str(), r["rpId"].as_str()), (Some("required"), Some("denis.example.com")));
        assert_eq!(r["allowCredentials"], json!([]));
    }
}
