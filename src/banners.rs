//! What a service says about itself: the banner an SSH, FTP or SMTP server sends on connect, and the `Server`
//! header of a web server. The one piece of *version evidence* the end-of-life and known-exploited checks rest
//! on: no banner, no claim.
//!
//! Collecting is a single, polite connection per open port (SSH 22, FTP 21, SMTP 25, HTTP 80/8000/8080/8888), read
//! at most 2 kB, with a short timeout, and only for the ports the port scan already found open on a device it
//! was allowed to scan (industrial devices and excluded ranges are never touched). Everything that comes back is
//! written by the other party: it is stripped of control characters and cut to 200 characters before it is kept,
//! and it is only ever shown as plain text.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::model::OpenPort;

/// The ports a banner is read from and the key it is kept under (`banner.ssh` in the device's identity).
pub const BANNER_PORTS: &[(u16, &str)] = &[(22, "ssh"), (21, "ftp"), (25, "smtp"), (80, "http"), (8000, "http"), (8080, "http"), (8888, "http")];

/// Text from another machine, made safe to keep and show.
pub fn clean(raw: &[u8]) -> String {
    String::from_utf8_lossy(raw).chars().map(|c| if c.is_control() { ' ' } else { c }).collect::<String>().split_whitespace().collect::<Vec<_>>().join(" ").chars().take(200).collect()
}

/// Read what one service says. `None` if it says nothing usable within the timeout.
async fn grab_one(ip: Ipv4Addr, port: u16, kind: &str, timeout: Duration) -> Option<String> {
    let mut s = tokio::time::timeout(timeout, TcpStream::connect(SocketAddr::new(IpAddr::V4(ip), port))).await.ok()?.ok()?;
    if kind == "http" {
        // an ordinary, harmless request: the answer's headers name the server
        let req = format!("HEAD / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: DENIS-inventory\r\nConnection: close\r\n\r\n");
        tokio::time::timeout(timeout, s.write_all(req.as_bytes())).await.ok()?.ok()?;
    }
    let mut buf = vec![0u8; 2048];
    let mut got = 0;
    // banners arrive in one or two segments; stop at the end of the first line (or headers) or when the buffer is full
    let deadline = tokio::time::Instant::now() + timeout;
    while got < buf.len() {
        match tokio::time::timeout_at(deadline, s.read(&mut buf[got..])).await {
            Ok(Ok(0)) | Err(_) | Ok(Err(_)) => break,
            Ok(Ok(n)) => {
                got += n;
                if kind != "http" && buf[..got].contains(&b'\n') {
                    break;
                }
                if kind == "http" && buf[..got].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
        }
    }
    if got == 0 {
        return None;
    }
    let text = &buf[..got];
    let picked = match kind {
        "http" => {
            // the headers worth keeping: who serves it, and what runs behind it
            let mut keep = Vec::new();
            for line in String::from_utf8_lossy(text).lines() {
                let l = line.trim();
                let lower = l.to_ascii_lowercase();
                if lower.starts_with("server:") || lower.starts_with("x-powered-by:") {
                    keep.push(clean(l.as_bytes()));
                }
            }
            keep.join(" | ")
        }
        _ => clean(text.split(|b| *b == b'\n').next().unwrap_or(text)),
    };
    (!picked.is_empty()).then_some(picked)
}

/// Read the banners of the open ports of one device: `banner.ssh`, `banner.http` … The first port of a kind that answers wins.
pub async fn grab(ip: Ipv4Addr, open: &[OpenPort], timeout: Duration) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (port, kind) in BANNER_PORTS {
        let key = format!("banner.{kind}");
        if out.contains_key(&key) || !open.iter().any(|p| p.port == *port && p.proto == "tcp") {
            continue;
        }
        if let Some(text) = grab_one(ip, *port, kind, timeout).await {
            out.insert(key, text);
        }
    }
    out
}

// -------------------------------------------------------------------------------------------- parsing

/// A product and version found in a banner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Software {
    /// A stable key: `openssh`, `nginx`, `apache-http-server`, `php`, `openssl`, `proftpd`, `vsftpd`, `exim`, …
    pub product: &'static str,
    pub version: String,
    /// Where it was read: `ssh`, `http`, `ftp` or `smtp`.
    pub source: &'static str,
    /// The banner names a distribution (Ubuntu, Debian, el7…): fixes are often backported without a new version number.
    pub distro: bool,
}

const DISTROS: &[&str] = &["ubuntu", "debian", "raspbian", "centos", "red hat", "rhel", "fedora", "suse", "alpine", "freebsd", "amazon", "rocky", "almalinux", "oracle", "el6", "el7", "el8", "el9"];

fn has_distro(banner: &str) -> bool {
    let l = banner.to_ascii_lowercase();
    DISTROS.iter().any(|d| l.contains(d))
}

/// `1.0.2k-fips` -> `1.0.2k`; `7.4p1` stays; anything that does not start like a version is refused.
fn version_token(s: &str) -> Option<String> {
    let t: String = s.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '.').collect();
    let t = t.trim_end_matches('.');
    (t.chars().next().is_some_and(|c| c.is_ascii_digit()) && t.len() <= 24).then(|| t.to_string())
}

/// After `prefix` (case-insensitive), the version token that follows a `/`, `_`, space or `-`.
fn after<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    let lower = text.to_ascii_lowercase();
    let i = lower.find(&prefix.to_ascii_lowercase())? + prefix.len();
    text.get(i..).map(|r| r.trim_start_matches(['/', '_', ' ', '-']))
}

/// Products and versions a banner gives away. Never guesses a version the banner does not contain.
pub fn parse(source: &'static str, banner: &str) -> Vec<Software> {
    let distro = has_distro(banner);
    let mut out = Vec::new();
    let mut add = |product: &'static str, version: Option<String>| {
        if let Some(version) = version {
            if !out.iter().any(|s: &Software| s.product == product && s.version == version) {
                out.push(Software { product, version, source, distro });
            }
        }
    };
    match source {
        "ssh" => {
            // SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5 / SSH-2.0-dropbear_2022.83
            let text = banner.trim();
            if let Some(r) = after(text, "OpenSSH_") {
                add("openssh", version_token(r));
            } else if let Some(r) = after(text, "dropbear_") {
                add("dropbear", version_token(r));
            }
        }
        "ftp" => {
            // 220 ProFTPD 1.3.5e Server (Debian) [...] / 220 (vsFTPd 3.0.3)
            if let Some(r) = after(banner, "ProFTPD") {
                add("proftpd", version_token(r));
            }
            if let Some(r) = after(banner, "vsFTPd") {
                add("vsftpd", version_token(r));
            }
        }
        "smtp" => {
            // 220 mail.example.com ESMTP Exim 4.94.2 Mon, 21 Sep 2026 ... (Postfix and Sendmail do not print a version)
            if let Some(r) = after(banner, "Exim") {
                add("exim", version_token(r));
            }
        }
        "http" => {
            // Server: Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1f PHP/7.4.3 | X-Powered-By: PHP/7.4.3
            for (marker, product) in [("Apache/", "apache-http-server"), ("nginx/", "nginx"), ("OpenSSL/", "openssl"), ("PHP/", "php"), ("lighttpd/", "lighttpd"), ("Microsoft-IIS/", "iis"), ("Exim/", "exim")] {
                for chunk in banner.split(['|', ' ']).filter(|c| c.len() > marker.len()) {
                    if chunk.len() >= marker.len() && chunk[..marker.len()].eq_ignore_ascii_case(marker) && chunk.is_char_boundary(marker.len()) {
                        // `Apache-Coyote/1.1` and similar do not start with `Apache/`: only the exact marker counts
                        add(product, version_token(&chunk[marker.len()..]));
                    }
                }
            }
        }
        _ => {}
    }
    out
}

/// Every product and version a device's kept banners give away.
pub fn software_of(identity: &BTreeMap<String, String>) -> Vec<Software> {
    let mut out: Vec<Software> = Vec::new();
    for (key, source) in [("banner.ssh", "ssh"), ("banner.http", "http"), ("banner.ftp", "ftp"), ("banner.smtp", "smtp")] {
        if let Some(b) = identity.get(key) {
            for s in parse(source, b) {
                if !out.iter().any(|o| o.product == s.product && o.version == s.version) {
                    out.push(s);
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(source: &'static str, banner: &str) -> Vec<(&'static str, String, bool)> {
        parse(source, banner).into_iter().map(|s| (s.product, s.version, s.distro)).collect()
    }

    #[test]
    fn ssh_banners_give_the_product_and_version_and_say_when_a_distribution_built_it() {
        assert_eq!(one("ssh", "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5"), vec![("openssh", "9.6p1".into(), true)]);
        assert_eq!(one("ssh", "SSH-2.0-OpenSSH_7.4"), vec![("openssh", "7.4".into(), false)]);
        assert_eq!(one("ssh", "SSH-2.0-dropbear_2022.83"), vec![("dropbear", "2022.83".into(), false)]);
        assert_eq!(one("ssh", "SSH-2.0-OpenSSH_for_Windows_8.1"), vec![], "no version in it, so nothing is claimed");
        assert_eq!(one("ssh", "SSH-2.0-Cisco-1.25"), vec![]);
        assert_eq!(one("ssh", ""), vec![]);
    }

    #[test]
    fn ftp_and_smtp_banners_are_read_only_when_they_print_a_version() {
        assert_eq!(one("ftp", "220 ProFTPD 1.3.5e Server (Debian) [::ffff:10.0.0.5]"), vec![("proftpd", "1.3.5e".into(), true)]);
        assert_eq!(one("ftp", "220 (vsFTPd 3.0.3)"), vec![("vsftpd", "3.0.3".into(), false)]);
        assert_eq!(one("ftp", "220 FTP server ready"), vec![]);
        assert_eq!(one("smtp", "220 mail.example.com ESMTP Exim 4.94.2 Mon, 21 Sep 2026 10:00:00 +0000"), vec![("exim", "4.94.2".into(), false)]);
        assert_eq!(one("smtp", "220 mx.example.com ESMTP Postfix (Ubuntu)"), vec![], "Postfix prints no version: nothing to judge");
    }

    #[test]
    fn a_web_server_header_names_the_server_and_what_runs_behind_it() {
        assert_eq!(
            one("http", "Server: Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1f PHP/7.4.3"),
            vec![("apache-http-server", "2.4.41".into(), true), ("openssl", "1.1.1f".into(), true), ("php", "7.4.3".into(), true)]
        );
        assert_eq!(one("http", "Server: nginx/1.18.0 (Ubuntu) | X-Powered-By: PHP/8.1.2"), vec![("nginx", "1.18.0".into(), true), ("php", "8.1.2".into(), true)]);
        assert_eq!(one("http", "Server: lighttpd/1.4.55"), vec![("lighttpd", "1.4.55".into(), false)]);
        assert_eq!(one("http", "Server: Microsoft-IIS/10.0 | X-Powered-By: ASP.NET"), vec![("iis", "10.0".into(), false)]);
        assert_eq!(one("http", "Server: nginx"), vec![], "no version");
        assert_eq!(one("http", "Server: Apache-Coyote/1.1"), vec![], "another product with a similar name");
        assert_eq!(one("http", "Server: Apache/2.4.41 Apache/2.4.41"), vec![("apache-http-server", "2.4.41".into(), false)], "named once");
        // hostile text: nothing panics, nothing is invented
        for junk in ["Server: nginx/", "Server: Apache/x", "Server: PHP/\u{0}", "\u{feff}Server: ☃/1", "Server: nginx/99999999999999999999999999"] {
            let _ = parse("http", junk);
        }
        assert_eq!(one("http", "Server: nginx/99999999999999999999999999"), vec![], "an absurdly long token is refused");
    }

    #[test]
    fn what_is_kept_is_cleaned_and_bounded() {
        assert_eq!(clean(b"SSH-2.0-OpenSSH_9.6\r\n\x00\x1b[31m red"), "SSH-2.0-OpenSSH_9.6 [31m red");
        assert_eq!(clean(&[b'a'; 500]).len(), 200);
        assert_eq!(clean(b"  a \t b  "), "a b");
    }

    #[test]
    fn software_is_collected_from_the_kept_banners_of_a_device() {
        let mut id = BTreeMap::new();
        id.insert("banner.ssh".to_string(), "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6".to_string());
        id.insert("banner.http".to_string(), "Server: nginx/1.18.0".to_string());
        id.insert("lldp.system_name".to_string(), "not a banner".to_string());
        let s = software_of(&id);
        assert_eq!(s.iter().map(|x| (x.product, x.version.as_str(), x.source)).collect::<Vec<_>>(), vec![("openssh", "8.9p1", "ssh"), ("nginx", "1.18.0", "http")]);
    }

    /// A stand-in service on this machine: says `banner` on connect (or after a request, for HTTP).
    async fn serve(banner: &'static [u8], wait_for_request: bool) -> u16 {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                tokio::spawn(async move {
                    if wait_for_request {
                        let mut b = [0u8; 512];
                        let _ = s.read(&mut b).await;
                    }
                    let _ = s.write_all(banner).await;
                    let _ = s.shutdown().await;
                });
            }
        });
        port
    }

    #[tokio::test]
    async fn a_banner_is_read_from_the_open_port_and_only_from_the_ports_named() {
        let ssh = serve(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\nignored second line\r\n", false).await;
        let http = serve(b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nX-Powered-By: PHP/7.4.3\r\nContent-Type: text/html\r\n\r\n", true).await;
        // the real ports 22 and 80 cannot be used in a test, so drive grab_one directly for the kinds
        let ip = Ipv4Addr::LOCALHOST;
        assert_eq!(grab_one(ip, ssh, "ssh", Duration::from_millis(800)).await.as_deref(), Some("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5"), "only the first line");
        assert_eq!(grab_one(ip, http, "http", Duration::from_millis(800)).await.as_deref(), Some("Server: nginx/1.18.0 | X-Powered-By: PHP/7.4.3"));
        // silence and a closed port are "nothing", not an error
        let quiet = serve(b"", false).await;
        assert_eq!(grab_one(ip, quiet, "ssh", Duration::from_millis(300)).await, None);
        assert_eq!(grab_one(ip, 1, "ssh", Duration::from_millis(300)).await, None);
        // a port that was not found open by the scan is not touched at all
        assert!(grab(ip, &[], Duration::from_millis(200)).await.is_empty());
    }
}
