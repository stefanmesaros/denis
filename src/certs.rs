//! The console's TLS certificate: created automatically, replaceable by the administrator.
//!
//! **Out of the box** DENIS makes its own small certificate authority ("DENIS local CA") the
//! first time it starts and signs a server certificate with it. The server certificate names
//! everything the console can be reached as (`localhost`, this machine's name and addresses,
//! plus any `--tls-name`), lasts about two years and is renewed automatically before it runs
//! out, or when the machine gets a new address. Browsers do not know that authority, so they
//! warn once; install the CA certificate (downloadable from the console) to make the warning
//! go away, or give agents the same file with `--master-ca`.
//!
//! **Your own certificate** (from Let's Encrypt, your company CA…) replaces it: upload it in the
//! console (or pass `--tls-cert/--tls-key`). Uploads are checked (the key must match the
//! certificate, it must be valid now) and take effect immediately, without a restart. Removing
//! it brings the generated one back.
//!
//! Files live in one folder (default: `tls/` beside the database), keys readable by their
//! owner only:
//!
//! * `ca.pem`, `ca.key`: the local authority (valid 10 years)
//! * `server.pem`, `server.key`: what the console serves
//! * `custom`: exists only while `server.*` is an uploaded certificate

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use rcgen::{BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType};
use serde::Serialize;
use x509_parser::prelude::*;

/// Server certificates last this long (and are renewed [`RENEW_BEFORE_DAYS`] before the end).
const SERVER_DAYS: i64 = 825;
const CA_DAYS: i64 = 3650;
pub const RENEW_BEFORE_DAYS: i64 = 30;
const CA_NAME: &str = "DENIS local CA";
const MAX_PEM: usize = 256 * 1024;

pub const CA_CERT: &str = "ca.pem";
const CA_KEY: &str = "ca.key";
pub const SERVER_CERT: &str = "server.pem";
pub const SERVER_KEY: &str = "server.key";
const CUSTOM_MARKER: &str = "custom";

/// What the console shows about the certificate in use.
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct CertInfo {
    pub subject: String,
    pub issuer: String,
    /// Unix seconds.
    pub not_before: i64,
    pub not_after: i64,
    pub names: Vec<String>,
    /// SHA-256 of the certificate, `AA:BB:…`: compare it with what the browser shows.
    pub fingerprint: String,
    /// `generated` (by DENIS) or `custom` (uploaded)
    pub source: &'static str,
}

fn key_pair_path(dir: &Path, name: &str) -> PathBuf {
    dir.join(name)
}

#[cfg(unix)]
fn private_file(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path).with_context(|| format!("writing {}", path.display()))?;
    f.write_all(data)?;
    Ok(())
}

/// Unverified beyond compiling (see WINDOWS.md): restricts the file to the account DENIS runs
/// as, the ACL equivalent of Unix's `mode 0o600` above. `icacls` (not a raw Win32 ACL rewrite) is
/// the documented, scriptable way to do this, the same reasoning `net.rs` uses for shelling out
/// to `route` on macOS rather than reimplementing routing-table access over FFI.
#[cfg(windows)]
fn private_file(path: &Path, data: &[u8]) -> Result<()> {
    std::fs::write(path, data).with_context(|| format!("writing {}", path.display()))?;
    let user = std::env::var("USERNAME").unwrap_or_default();
    if user.is_empty() {
        return Ok(());
    }
    let grant = format!("{user}:F");
    let out = std::process::Command::new("icacls")
        .arg(path)
        .args(["/inheritance:r", "/grant:r", &grant])
        .output()
        .with_context(|| "running icacls")?;
    if !out.status.success() {
        bail!("icacls could not restrict permissions on {}: {}", path.display(), String::from_utf8_lossy(&out.stderr));
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn private_file(path: &Path, data: &[u8]) -> Result<()> {
    std::fs::write(path, data).with_context(|| format!("writing {}", path.display()))
}

fn utc(unix: i64) -> Result<::time::OffsetDateTime> {
    ::time::OffsetDateTime::from_unix_timestamp(unix).map_err(|e| anyhow!("bad time: {e}"))
}

fn ca_params(now: i64, days: i64) -> Result<CertificateParams> {
    let mut p = CertificateParams::default();
    p.distinguished_name.push(DnType::CommonName, CA_NAME);
    p.distinguished_name.push(DnType::OrganizationName, "DENIS");
    p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];
    p.not_before = utc(now - 3600)?;
    p.not_after = utc(now + days * 86_400)?;
    Ok(p)
}

/// Every name the console should be reachable as.
pub fn desired_names(extra: &[String]) -> Vec<String> {
    let mut names: Vec<String> = vec!["localhost".into(), "127.0.0.1".into(), "::1".into()];
    if let Some(h) = crate::net::local_hostname() {
        names.push(h.clone());
        names.push(format!("{h}.local"));
    }
    for i in crate::net::list_interfaces().unwrap_or_default() {
        names.push(i.ip.to_string());
    }
    names.extend(extra.iter().cloned());
    names.retain(|n| !n.is_empty() && n.len() <= 253 && n.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '_')));
    names.sort();
    names.dedup();
    names
}

fn san_types(names: &[String]) -> Vec<SanType> {
    names
        .iter()
        .filter_map(|n| match n.parse::<IpAddr>() {
            Ok(ip) => Some(SanType::IpAddress(ip)),
            Err(_) => n.clone().try_into().ok().map(SanType::DnsName),
        })
        .collect()
}

fn generate_ca(dir: &Path, now: i64) -> Result<()> {
    let key = KeyPair::generate().map_err(|e| anyhow!("{e}"))?;
    let cert = ca_params(now, CA_DAYS)?.self_signed(&key).map_err(|e| anyhow!("{e}"))?;
    private_file(&key_pair_path(dir, CA_KEY), key.serialize_pem().as_bytes())?;
    std::fs::write(dir.join(CA_CERT), cert.pem())?;
    Ok(())
}

fn generate_server(dir: &Path, names: &[String], now: i64, days: i64) -> Result<()> {
    let ca_key = KeyPair::from_pem(&std::fs::read_to_string(dir.join(CA_KEY))?).map_err(|e| anyhow!("the CA key is unreadable: {e}"))?;
    // the issuer is rebuilt from the same fixed name, so it matches the stored CA certificate
    let issuer = Issuer::new(ca_params(now, CA_DAYS)?, ca_key);
    let key = KeyPair::generate().map_err(|e| anyhow!("{e}"))?;
    let mut p = CertificateParams::default();
    let cn = names.iter().find(|n| n.parse::<IpAddr>().is_err()).cloned().unwrap_or_else(|| "localhost".into());
    p.distinguished_name.push(DnType::CommonName, cn);
    p.subject_alt_names = san_types(names);
    p.is_ca = IsCa::NoCa;
    p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    p.not_before = utc(now - 3600)?;
    p.not_after = utc(now + days * 86_400)?;
    let cert = p.signed_by(&key, &issuer).map_err(|e| anyhow!("{e}"))?;
    private_file(&dir.join(SERVER_KEY), key.serialize_pem().as_bytes())?;
    std::fs::write(dir.join(SERVER_CERT), cert.pem())?;
    Ok(())
}

fn parse_pem_cert(pem: &str) -> Result<Vec<u8>> {
    let (_, p) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).map_err(|_| anyhow!("that is not a PEM certificate"))?;
    if p.label != "CERTIFICATE" {
        bail!("that is not a certificate");
    }
    Ok(p.contents)
}

fn describe(der: &[u8], source: &'static str) -> Result<CertInfo> {
    let (_, c) = X509Certificate::from_der(der).map_err(|_| anyhow!("the certificate could not be read"))?;
    let mut names = Vec::new();
    if let Ok(Some(san)) = c.subject_alternative_name() {
        for n in &san.value.general_names {
            match n {
                GeneralName::DNSName(d) => names.push(d.to_string()),
                GeneralName::IPAddress(b) if b.len() == 4 => names.push(IpAddr::from([b[0], b[1], b[2], b[3]]).to_string()),
                GeneralName::IPAddress(b) if b.len() == 16 => names.push(IpAddr::from(<[u8; 16]>::try_from(*b).unwrap()).to_string()),
                _ => {}
            }
        }
    }
    let fp = ring::digest::digest(&ring::digest::SHA256, der).as_ref().iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":");
    Ok(CertInfo {
        subject: c.subject().to_string(),
        issuer: c.issuer().to_string(),
        not_before: c.validity().not_before.timestamp(),
        not_after: c.validity().not_after.timestamp(),
        names,
        fingerprint: fp,
        source,
    })
}

/// The certificate currently in `dir` (after [`ensure`]).
pub fn info(dir: &Path) -> Result<CertInfo> {
    let der = parse_pem_cert(&std::fs::read_to_string(dir.join(SERVER_CERT))?)?;
    describe(&der, if dir.join(CUSTOM_MARKER).exists() { "custom" } else { "generated" })
}

/// The local CA certificate (PEM), for browsers and agents to trust.
pub fn ca_pem(dir: &Path) -> Option<String> {
    std::fs::read_to_string(dir.join(CA_CERT)).ok()
}

pub fn is_custom(dir: &Path) -> bool {
    dir.join(CUSTOM_MARKER).exists()
}

/// Make sure `dir` holds a usable certificate for the console. Generates the authority and the
/// server certificate when missing, and renews the server certificate when it is close to its end
/// or does not cover a name it should. An uploaded certificate is left alone. Returns `true` if
/// anything was (re)generated.
pub fn ensure(dir: &Path, extra_names: &[String], now: i64) -> Result<bool> {
    ensure_with(dir, extra_names, now, SERVER_DAYS)
}

fn ensure_with(dir: &Path, extra_names: &[String], now: i64, server_days: i64) -> Result<bool> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    if is_custom(dir) && dir.join(SERVER_CERT).exists() && dir.join(SERVER_KEY).exists() {
        return Ok(false);
    }
    let mut changed = false;
    let ca_ok = (|| -> Result<bool> {
        let der = parse_pem_cert(&std::fs::read_to_string(dir.join(CA_CERT))?)?;
        std::fs::metadata(dir.join(CA_KEY))?;
        Ok(describe(&der, "generated")?.not_after > now + 365 * 86_400)
    })()
    .unwrap_or(false);
    if !ca_ok {
        generate_ca(dir, now)?;
        changed = true;
    }
    let names = desired_names(extra_names);
    let leaf_ok = !changed
        && (|| -> Result<bool> {
            let i = info(dir)?;
            let covers = names.iter().all(|n| i.names.contains(n));
            Ok(covers && i.not_after > now + RENEW_BEFORE_DAYS * 86_400 && i.not_before <= now + 60)
        })()
        .unwrap_or(false);
    if !leaf_ok {
        generate_server(dir, &names, now, server_days)?;
        changed = true;
    }
    Ok(changed)
}

/// Check and install an uploaded certificate chain and key. On success the console serves it from
/// the next reload; on any problem nothing is changed.
pub fn install_custom(dir: &Path, cert_pem: &str, key_pem: &str, now: i64) -> Result<CertInfo> {
    if cert_pem.len() > MAX_PEM || key_pem.len() > MAX_PEM {
        bail!("that file is too large to be a certificate");
    }
    // the chain: the first certificate is the server's; at least one is required
    let certs: Vec<Vec<u8>> = x509_parser::pem::Pem::iter_from_buffer(cert_pem.as_bytes())
        .filter_map(|p| p.ok())
        .filter(|p| p.label == "CERTIFICATE")
        .map(|p| p.contents)
        .collect();
    let leaf = certs.first().ok_or_else(|| anyhow!("no certificate found: paste the PEM text starting with -----BEGIN CERTIFICATE-----"))?;
    let info = describe(leaf, "custom")?;
    if info.not_after <= now {
        bail!("that certificate has expired");
    }
    if info.not_before > now + 86_400 {
        bail!("that certificate is not valid yet");
    }
    // the private key must be the one this certificate was issued for
    let key_der = {
        use rustls::pki_types::{pem::PemObject, PrivateKeyDer};
        PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).map_err(|_| anyhow!("no private key found: paste the PEM text starting with -----BEGIN PRIVATE KEY-----, and remove any passphrase first"))?
    };
    let signer = rustls::crypto::ring::sign::any_supported_type(&key_der).map_err(|_| anyhow!("that private key type is not supported (use RSA or ECDSA)"))?;
    let spki_of_key = signer.public_key().ok_or_else(|| anyhow!("that private key type is not supported"))?;
    let (_, c) = X509Certificate::from_der(leaf).map_err(|_| anyhow!("the certificate could not be read"))?;
    if spki_of_key.as_ref() != c.tbs_certificate.subject_pki.raw {
        bail!("that private key does not belong to that certificate");
    }
    std::fs::create_dir_all(dir)?;
    // write the new pair beside the old one, then swap, so a failure leaves the console working
    let (tmp_cert, tmp_key) = (dir.join("server.pem.new"), dir.join("server.key.new"));
    std::fs::write(&tmp_cert, cert_pem)?;
    private_file(&tmp_key, key_pem.as_bytes())?;
    std::fs::rename(&tmp_key, dir.join(SERVER_KEY))?;
    std::fs::rename(&tmp_cert, dir.join(SERVER_CERT))?;
    std::fs::write(dir.join(CUSTOM_MARKER), b"uploaded")?;
    Ok(info)
}

/// Go back to the certificate DENIS generates.
pub fn reset_to_generated(dir: &Path, extra_names: &[String], now: i64) -> Result<CertInfo> {
    let _ = std::fs::remove_file(dir.join(CUSTOM_MARKER));
    let _ = std::fs::remove_file(dir.join(SERVER_CERT));
    let _ = std::fs::remove_file(dir.join(SERVER_KEY));
    ensure(dir, extra_names, now)?;
    info(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000;

    fn names(i: &CertInfo) -> Vec<&str> {
        i.names.iter().map(String::as_str).collect()
    }

    #[test]
    fn the_first_start_creates_an_authority_and_a_server_certificate_that_chain_and_cover_the_local_names() {
        let dir = tempfile::tempdir().unwrap();
        assert!(ensure(dir.path(), &["denis.example.com".into()], NOW).unwrap());
        let i = info(dir.path()).unwrap();
        assert_eq!(i.source, "generated");
        for want in ["localhost", "127.0.0.1", "::1", "denis.example.com"] {
            assert!(names(&i).contains(&want), "{want} in {:?}", i.names);
        }
        assert!(i.not_after > NOW + 800 * 86_400 && i.not_after < NOW + 830 * 86_400, "about {SERVER_DAYS} days");
        assert!(i.issuer.contains(CA_NAME) && !i.subject.contains(CA_NAME));
        assert_eq!(i.fingerprint.split(':').count(), 32);
        // the leaf really is signed by the CA, and the CA really is a CA
        let ca = parse_pem_cert(&ca_pem(dir.path()).unwrap()).unwrap();
        let leaf = parse_pem_cert(&std::fs::read_to_string(dir.path().join(SERVER_CERT)).unwrap()).unwrap();
        let (_, ca_c) = X509Certificate::from_der(&ca).unwrap();
        let (_, leaf_c) = X509Certificate::from_der(&leaf).unwrap();
        assert!(ca_c.is_ca() && !leaf_c.is_ca());
        leaf_c.verify_signature(Some(ca_c.public_key())).expect("signed by the local CA");
        assert_eq!(leaf_c.issuer().to_string(), ca_c.subject().to_string());
        // keys are private to the owner
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for k in [CA_KEY, SERVER_KEY] {
                assert_eq!(std::fs::metadata(dir.path().join(k)).unwrap().permissions().mode() & 0o777, 0o600, "{k}");
            }
        }
        // a second start changes nothing (the same certificate keeps being served)
        let before = std::fs::read(dir.path().join(SERVER_CERT)).unwrap();
        assert!(!ensure(dir.path(), &["denis.example.com".into()], NOW + 86_400).unwrap());
        assert_eq!(std::fs::read(dir.path().join(SERVER_CERT)).unwrap(), before);
    }

    #[test]
    fn a_certificate_near_its_end_or_missing_a_name_is_renewed_under_the_same_authority() {
        let dir = tempfile::tempdir().unwrap();
        // a short-lived server certificate
        ensure_with(dir.path(), &[], NOW, 40).unwrap();
        let ca_before = std::fs::read(dir.path().join(CA_CERT)).unwrap();
        assert!(!ensure_with(dir.path(), &[], NOW + 5 * 86_400, 40).unwrap(), "35 days left: fine");
        assert!(ensure_with(dir.path(), &[], NOW + 20 * 86_400, 40).unwrap(), "20 days left: renewed");
        assert_eq!(std::fs::read(dir.path().join(CA_CERT)).unwrap(), ca_before, "the authority is not replaced, so trusted CAs stay trusted");
        assert!(info(dir.path()).unwrap().not_after > NOW + 20 * 86_400 + 30 * 86_400);
        // a new name (an extra address the machine now has) triggers a new certificate
        let n = info(dir.path()).unwrap().names.len();
        assert!(ensure(dir.path(), &["new-name.example".into()], NOW + 21 * 86_400).unwrap());
        assert!(info(dir.path()).unwrap().names.len() > n);
        // damaged files are replaced instead of crashing start-up
        std::fs::write(dir.path().join(SERVER_CERT), "garbage").unwrap();
        assert!(ensure(dir.path(), &[], NOW + 22 * 86_400).unwrap());
        assert!(info(dir.path()).is_ok());
        std::fs::write(dir.path().join(CA_CERT), "garbage").unwrap();
        assert!(ensure(dir.path(), &[], NOW + 23 * 86_400).unwrap());
    }

    /// A certificate and key made by "somebody else" (a company CA, Let's Encrypt…).
    fn foreign(names: &[&str], days_from_now: i64, valid_from: i64) -> (String, String) {
        let key = KeyPair::generate().unwrap();
        let mut p = CertificateParams::new(names.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
        p.not_before = utc(valid_from).unwrap();
        p.not_after = utc(NOW + days_from_now * 86_400).unwrap();
        (p.self_signed(&key).unwrap().pem(), key.serialize_pem())
    }

    #[test]
    fn an_uploaded_certificate_is_checked_replaces_the_generated_one_and_can_be_removed() {
        let dir = tempfile::tempdir().unwrap();
        ensure(dir.path(), &[], NOW).unwrap();
        let generated = std::fs::read(dir.path().join(SERVER_CERT)).unwrap();
        let (cert, key) = foreign(&["denis.corp.example"], 90, NOW - 86_400);
        // the wrong key, garbage, expired and not-yet-valid uploads all fail and change nothing
        let (_, other_key) = foreign(&["x.example"], 90, NOW - 86_400);
        for (c, k, why) in [
            (cert.as_str(), other_key.as_str(), "does not belong"),
            ("nonsense", key.as_str(), "no certificate"),
            (cert.as_str(), "nonsense", "no private key"),
            ("", "", "no certificate"),
        ] {
            let e = install_custom(dir.path(), c, k, NOW).unwrap_err().to_string();
            assert!(e.contains(why), "{e}");
        }
        let (old_cert, old_key) = foreign(&["old.example"], -1, NOW - 100 * 86_400);
        assert!(install_custom(dir.path(), &old_cert, &old_key, NOW).unwrap_err().to_string().contains("expired"));
        let (future_cert, future_key) = foreign(&["future.example"], 90, NOW + 30 * 86_400);
        assert!(install_custom(dir.path(), &future_cert, &future_key, NOW).unwrap_err().to_string().contains("not valid yet"));
        assert!(install_custom(dir.path(), &"a".repeat(MAX_PEM + 1), &key, NOW).is_err());
        assert_eq!(std::fs::read(dir.path().join(SERVER_CERT)).unwrap(), generated, "every refusal left the console's certificate alone");
        assert!(!is_custom(dir.path()));

        let i = install_custom(dir.path(), &cert, &key, NOW).unwrap();
        assert_eq!((i.source, names(&i)), ("custom", vec!["denis.corp.example"]));
        assert!(is_custom(dir.path()) && info(dir.path()).unwrap().source == "custom");
        // start-up leaves an uploaded certificate alone, even one that lacks the local names
        assert!(!ensure(dir.path(), &[], NOW + 86_400).unwrap());
        assert_eq!(names(&info(dir.path()).unwrap()), vec!["denis.corp.example"]);
        // removing it brings back a generated one that covers the local names again
        let back = reset_to_generated(dir.path(), &[], NOW + 2 * 86_400).unwrap();
        assert_eq!(back.source, "generated");
        assert!(names(&back).contains(&"localhost"));
        assert!(!is_custom(dir.path()));
    }

    #[test]
    fn the_names_in_a_certificate_are_limited_to_safe_characters() {
        let n = desired_names(&["ok.example.com".into(), "bad name".into(), "x/y".into(), "".into(), "é.example".into(), "a".repeat(300)]);
        assert!(n.contains(&"ok.example.com".to_string()) && n.contains(&"localhost".to_string()));
        assert!(!n.iter().any(|x| x.contains(' ') || x.contains('/') || x.is_empty() || x.len() > 253 || !x.is_ascii()));
    }
}
