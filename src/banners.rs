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

/// The same, but only read when `extended` is on (`--no-extended-banners` to disable): legacy
/// text (Telnet) or a binary greeting (MySQL/MariaDB) rather than the simple one-line text banners
/// above. Same cost as any other entry here: one extra connection, only for a port the scan
/// already found open, no different from probing SSH or FTP.
pub const EXTENDED_BANNER_PORTS: &[(u16, &str)] = &[(23, "telnet"), (3306, "mysql"), (445, "smb"), (1433, "mssql")];

/// The ports `grab` tries, in order: the always-on ones, plus the extended ones when asked for.
fn ports_for(extended: bool) -> impl Iterator<Item = &'static (u16, &'static str)> {
    BANNER_PORTS.iter().chain(extended.then_some(EXTENDED_BANNER_PORTS).into_iter().flatten())
}

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
        "telnet" => {
            // strip Telnet's IAC (0xFF) option-negotiation sequences (RFC 854) first, or they show
            // up as junk in what is otherwise a plain login banner; IAC IAC is a literal 0xFF byte
            let mut stripped = Vec::with_capacity(text.len());
            let mut i = 0;
            while i < text.len() {
                if text[i] == 0xFF {
                    i += if text.get(i + 1) == Some(&0xFF) { 2 } else { 3.min(text.len() - i) };
                } else {
                    stripped.push(text[i]);
                    i += 1;
                }
            }
            clean(stripped.split(|b| *b == b'\n').next().unwrap_or(&stripped))
        }
        "mysql" => {
            // MySQL/MariaDB's initial handshake packet, sent unauthenticated the moment the socket
            // connects: a 3-byte length, a 1-byte sequence number, a protocol-version byte (10),
            // then a NUL-terminated ASCII server-version string.
            match text.get(4) {
                Some(10) => match text.get(5..).and_then(|rest| rest.iter().position(|b| *b == 0).map(|end| &rest[..end])) {
                    Some(version) => clean(version),
                    None => String::new(),
                },
                _ => String::new(),
            }
        }
        _ => clean(text.split(|b| *b == b'\n').next().unwrap_or(text)),
    };
    (!picked.is_empty()).then_some(picked)
}

/// Read the banners of the open ports of one device: `banner.ssh`, `banner.http` … The first port of a kind that answers wins.
/// `extended`: also read `EXTENDED_BANNER_PORTS` (Telnet, MySQL/MariaDB, SMB, MSSQL) — the same one-connection
/// cost as any other entry, but off the fast path by default so an administrator who would rather
/// not connect to those specific ports at all can say so (`--no-extended-banners`).
pub async fn grab(ip: Ipv4Addr, open: &[OpenPort], timeout: Duration, extended: bool) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (port, kind) in ports_for(extended) {
        let key = format!("banner.{kind}");
        if out.contains_key(&key) || !open.iter().any(|p| p.port == *port && p.proto == "tcp") {
            continue;
        }
        // SMB and MSSQL need a short exchange (negotiate, then a follow-up message), not a single
        // connect-and-read like every other kind here, so they have their own functions.
        let got = match *kind {
            "smb" => smb_version(ip, *port, timeout).await,
            "mssql" => mssql_version(ip, *port, timeout).await,
            _ => grab_one(ip, *port, kind, timeout).await,
        };
        if let Some(text) = got {
            out.insert(key, text);
        }
    }
    out
}

// -------------------------------------------------------------------------------------- SMB (445)

/// Windows' own build number, read from an SMB2 Session Setup's NTLMSSP challenge — the same
/// technique `smbclient`/nmap's `smb-os-discovery` use. Two short, fixed-format, unauthenticated
/// round trips: a Negotiate (dialect 2.0.2 only, to avoid SMB 3.1.1's negotiate-context complexity)
/// confirms the server speaks SMB2 at all, then a Session Setup carrying an NTLMSSP
/// NEGOTIATE_MESSAGE; Windows answers with a CHALLENGE_MESSAGE that includes its own OS version
/// unless asked not to. Samba does not normally set the version flag, so this correctly gives
/// nothing there rather than a guess. Kept as evidence only (`banner.smb`): a kernel build number
/// is not compared against any support-date or CVE data here.
async fn smb_version(ip: Ipv4Addr, port: u16, timeout: Duration) -> Option<String> {
    let mut s = tokio::time::timeout(timeout, TcpStream::connect(SocketAddr::new(IpAddr::V4(ip), port))).await.ok()?.ok()?;
    let deadline = tokio::time::Instant::now() + timeout;

    tokio::time::timeout_at(deadline, s.write_all(&smb2_negotiate_request())).await.ok()?.ok()?;
    let negotiate = read_direct_tcp_message(&mut s, deadline).await?;
    // a real SMB2 Negotiate response is at least a 64-byte header; anything shorter is not this protocol
    if negotiate.len() < 64 {
        return None;
    }

    tokio::time::timeout_at(deadline, s.write_all(&smb2_session_setup_request())).await.ok()?.ok()?;
    let setup = read_direct_tcp_message(&mut s, deadline).await?;
    smb_ntlm_version(&setup)
}

/// Direct TCP transport (MS-SMB2 2.1, port 445): each message is preceded by a 4-byte header whose
/// last 3 bytes (big-endian) are the length of what follows. No NetBIOS session semantics on 445,
/// just this length prefix.
async fn read_direct_tcp_message(s: &mut TcpStream, deadline: tokio::time::Instant) -> Option<Vec<u8>> {
    let mut hdr = [0u8; 4];
    tokio::time::timeout_at(deadline, s.read_exact(&mut hdr)).await.ok()?.ok()?;
    let len = ((hdr[1] as usize) << 16) | ((hdr[2] as usize) << 8) | hdr[3] as usize;
    if len == 0 || len > 1_000_000 {
        return None;
    }
    let mut body = vec![0u8; len];
    tokio::time::timeout_at(deadline, s.read_exact(&mut body)).await.ok()?.ok()?;
    Some(body)
}

fn direct_tcp_wrap(msg: &[u8]) -> Vec<u8> {
    let len = msg.len() as u32;
    let mut out = vec![0, (len >> 16) as u8, (len >> 8) as u8, len as u8];
    out.extend_from_slice(msg);
    out
}

/// A 64-byte SMB2 header (MS-SMB2 2.2.1) with everything a request needs zeroed (no signing, no
/// session yet on the first two messages).
fn smb2_header(command: u16, message_id: u64) -> Vec<u8> {
    let mut h = vec![0xFE, b'S', b'M', b'B']; // ProtocolId
    h.extend([0x40, 0x00]); // StructureSize = 64
    h.extend([0, 0]); // CreditCharge
    h.extend([0, 0, 0, 0]); // Status
    h.extend(command.to_le_bytes());
    h.extend([0, 0]); // CreditRequest
    h.extend([0u8; 4]); // Flags
    h.extend([0u8; 4]); // NextCommand
    h.extend(message_id.to_le_bytes());
    h.extend([0u8; 4]); // Reserved
    h.extend([0u8; 4]); // TreeId
    h.extend([0u8; 8]); // SessionId
    h.extend([0u8; 16]); // Signature
    h
}

/// SMB2 NEGOTIATE (command 0x0000) offering only dialect 2.0.02 — every SMB2-capable server
/// (Windows Vista/2008 onward, Samba) accepts it, and it needs none of 3.1.1's extra negotiate
/// contexts.
fn smb2_negotiate_request() -> Vec<u8> {
    let mut msg = smb2_header(0x0000, 0);
    msg.extend([0x24, 0x00]); // StructureSize = 36
    msg.extend([1, 0]); // DialectCount = 1
    msg.extend([1, 0]); // SecurityMode = SIGNING_ENABLED
    msg.extend([0, 0]); // Reserved
    msg.extend([0u8; 4]); // Capabilities
    msg.extend([0u8; 16]); // ClientGuid
    msg.extend([0u8; 8]); // ClientStartTime
    msg.extend([0x02, 0x02]); // Dialects[0] = 0x0202
    direct_tcp_wrap(&msg)
}

/// SMB2 SESSION_SETUP (command 0x0001) carrying an NTLMSSP NEGOTIATE_MESSAGE as its security buffer.
fn smb2_session_setup_request() -> Vec<u8> {
    let ntlm = ntlm_negotiate_message();
    let mut msg = smb2_header(0x0001, 1);
    let header_len = msg.len() as u16; // 64
    msg.extend([0x19, 0x00]); // StructureSize = 25 (MS-SMB2's documented value for this message)
    msg.push(0); // Flags
    msg.push(1); // SecurityMode = NEGOTIATE_SIGNING_ENABLED
    msg.extend([0u8; 4]); // Capabilities
    msg.extend([0u8; 4]); // Channel
    let offset = header_len + 24; // 24 = the fixed part of this body, after which the buffer starts
    msg.extend(offset.to_le_bytes());
    msg.extend((ntlm.len() as u16).to_le_bytes());
    msg.extend([0u8; 8]); // PreviousSessionId
    msg.extend(ntlm);
    direct_tcp_wrap(&msg)
}

/// A minimal NTLMSSP NEGOTIATE_MESSAGE (MS-NLMP 2.2.1.1): no domain/workstation name, but the
/// NTLMSSP_NEGOTIATE_VERSION flag set, which is what makes a Windows server echo its own build
/// number back in the CHALLENGE_MESSAGE.
fn ntlm_negotiate_message() -> Vec<u8> {
    let mut m = b"NTLMSSP\0".to_vec();
    m.extend(1u32.to_le_bytes()); // MessageType = 1
    // UNICODE | REQUEST_TARGET | NTLM | ALWAYS_SIGN | EXTENDED_SESSIONSECURITY | VERSION | 128 | 56
    m.extend(0xA208_8205u32.to_le_bytes());
    m.extend([0u8; 8]); // DomainNameFields (len=0, maxlen=0, offset=0: none supplied)
    m.extend([0u8; 8]); // WorkstationFields
    m.extend([0u8; 8]); // Version (placeholder: this end's own version is never asked about)
    m
}

/// The CHALLENGE_MESSAGE's Version field (MS-NLMP 2.2.2.10), if the server included one, from a raw
/// SMB2 SESSION_SETUP response body. Every offset and length is bounds-checked against what was
/// actually received; a short, truncated or unrelated reply is "no version", never a panic.
fn smb_ntlm_version(setup_response: &[u8]) -> Option<String> {
    let body = setup_response.get(64..)?; // past the SMB2 header
    // SESSION_SETUP Response (MS-SMB2 2.2.6): StructureSize(2), SessionFlags(2),
    // SecurityBufferOffset(2), SecurityBufferLength(2), Buffer.
    let sec_buf_offset = u16::from_le_bytes(body.get(4..6)?.try_into().ok()?) as usize;
    let sec_buf_len = u16::from_le_bytes(body.get(6..8)?.try_into().ok()?) as usize;
    let ntlm = setup_response.get(sec_buf_offset..sec_buf_offset.checked_add(sec_buf_len)?)?;
    if ntlm.get(0..8)? != b"NTLMSSP\0" || u32::from_le_bytes(ntlm.get(8..12)?.try_into().ok()?) != 2 {
        return None; // not an NTLMSSP CHALLENGE_MESSAGE
    }
    let flags = u32::from_le_bytes(ntlm.get(20..24)?.try_into().ok()?);
    if flags & 0x0200_0000 == 0 {
        return None; // NTLMSSP_NEGOTIATE_VERSION not set: this server did not send one
    }
    let version = ntlm.get(48..56)?;
    let build = u16::from_le_bytes([version[2], version[3]]);
    Some(format!("{}.{}.{}", version[0], version[1], build))
}

// ------------------------------------------------------------------------------------ MSSQL (1433)

/// SQL Server's own build number, read from a TDS PRELOGIN exchange (MS-TDS 2.2.6.4): one
/// unauthenticated request, always answered in the clear (the PRELOGIN response is what negotiates
/// whether everything *after* it is wrapped in TLS, so it cannot itself require TLS to read).
async fn mssql_version(ip: Ipv4Addr, port: u16, timeout: Duration) -> Option<String> {
    let mut s = tokio::time::timeout(timeout, TcpStream::connect(SocketAddr::new(IpAddr::V4(ip), port))).await.ok()?.ok()?;
    let deadline = tokio::time::Instant::now() + timeout;
    tokio::time::timeout_at(deadline, s.write_all(&tds_prelogin_request())).await.ok()?.ok()?;
    let mut hdr = [0u8; 8];
    tokio::time::timeout_at(deadline, s.read_exact(&mut hdr)).await.ok()?.ok()?;
    if hdr[0] != 0x04 {
        return None; // not TDS's TABULAR_RESULT type: not a PRELOGIN response
    }
    let len = u16::from_be_bytes([hdr[2], hdr[3]]) as usize;
    if !(8..=4096).contains(&len) {
        return None;
    }
    let mut body = vec![0u8; len - 8];
    tokio::time::timeout_at(deadline, s.read_exact(&mut body)).await.ok()?.ok()?;
    tds_prelogin_version(&body)
}

/// A TDS packet (MS-TDS 2.2.3) of type PRELOGIN (0x12), carrying VERSION, ENCRYPTION, INSTOPT and
/// MARS options — the minimal set most servers expect — ending in the mandatory terminator (0xFF).
/// `ENCRYPT_NOT_SUP` is offered: DENIS reads only the PRELOGIN response itself, never a login, so
/// there is nothing to encrypt and nothing gained from negotiating TLS here.
fn tds_prelogin_request() -> Vec<u8> {
    let opts: [(u8, u16); 4] = [(0x00, 6), (0x01, 1), (0x02, 1), (0x04, 1)];
    let mut body = Vec::new();
    let mut offset = 5 * opts.len() as u16 + 1;
    for (token, len) in opts {
        body.push(token);
        body.extend(offset.to_be_bytes());
        body.extend(len.to_be_bytes());
        offset += len;
    }
    body.push(0xFF); // terminator
    body.extend([0, 0, 0, 0, 0, 0]); // VERSION: this end's own version/subbuild, unused by the server
    body.push(0x02); // ENCRYPTION: ENCRYPT_NOT_SUP
    body.push(0x00); // INSTOPT: default instance (a single NUL: empty instance name)
    body.push(0x00); // MARS: off
    let mut packet = vec![0x12, 0x01, 0, 0, 0, 0, 1, 0]; // Type=PRELOGIN, Status=EOM (End Of Message), SPID=0, PacketID=1
    packet.extend(&body);
    let len = packet.len() as u16;
    packet[2..4].copy_from_slice(&len.to_be_bytes());
    packet
}

/// The VERSION option's data in a PRELOGIN response body (the bytes after the 8-byte TDS packet
/// header): SQL Server's own build, unauthenticated, always in the clear. Every offset is
/// bounds-checked; a malformed or foreign reply is "no version", never a panic.
fn tds_prelogin_version(body: &[u8]) -> Option<String> {
    let mut i = 0;
    loop {
        let token = *body.get(i)?;
        if token == 0xFF {
            return None; // terminator reached: no VERSION option in this reply
        }
        let offset = u16::from_be_bytes(body.get(i + 1..i + 3)?.try_into().ok()?) as usize;
        let length = u16::from_be_bytes(body.get(i + 3..i + 5)?.try_into().ok()?) as usize;
        if token == 0x00 {
            let v = body.get(offset..offset.checked_add(length)?)?;
            return (v.len() >= 4).then(|| format!("{}.{}.{}", v[0], v[1], u16::from_be_bytes([v[2], v[3]])));
        }
        i += 5;
    }
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
        "mysql" => {
            // the version string DENIS already isolated in `grab_one` starts with the version
            // itself: "8.0.35" (MySQL) or "10.6.12-MariaDB-1:10.6.12+maria~ubu2004" (MariaDB
            // rewrites its own version first, so it is told apart by that marker, not the port)
            if banner.to_ascii_lowercase().contains("mariadb") {
                add("mariadb", version_token(banner));
            } else {
                add("mysql", version_token(banner));
            }
        }
        _ => {}
    }
    out
}

/// Every product and version a device's kept banners give away.
pub fn software_of(identity: &BTreeMap<String, String>) -> Vec<Software> {
    let mut out: Vec<Software> = Vec::new();
    for (key, source) in [("banner.ssh", "ssh"), ("banner.http", "http"), ("banner.ftp", "ftp"), ("banner.smtp", "smtp"), ("banner.mysql", "mysql")] {
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
    fn a_mysql_greeting_names_the_product_and_tells_mariadb_apart() {
        assert_eq!(one("mysql", "8.0.35"), vec![("mysql", "8.0.35".into(), false)]);
        assert_eq!(one("mysql", "10.6.12-MariaDB-1:10.6.12+maria~ubu2004"), vec![("mariadb", "10.6.12".into(), false)]);
        assert_eq!(one("mysql", "5.7.44-log"), vec![("mysql", "5.7.44".into(), false)]);
        assert_eq!(one("mysql", ""), vec![]);
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
        assert!(grab(ip, &[], Duration::from_millis(200), true).await.is_empty());
    }

    #[tokio::test]
    async fn telnet_and_mysql_banners_are_parsed_correctly() {
        let ip = Ipv4Addr::LOCALHOST;
        // Telnet: a login banner preceded by IAC option-negotiation noise (RFC 854), stripped
        let telnet = serve(b"\xff\xfb\x01\xff\xfb\x03\xff\xfd\x1fUbuntu 22.04 LTS\r\nlogin: ", false).await;
        assert_eq!(grab_one(ip, telnet, "telnet", Duration::from_millis(800)).await.as_deref(), Some("Ubuntu 22.04 LTS"));
        // MySQL: length(3) + seq(1) + protocol version 10 + NUL-terminated version + more binary junk
        let mut greeting = vec![0, 0, 0, 0, 10];
        greeting.extend(b"8.0.35\0");
        greeting.extend([1, 2, 3, 4]); // connection id and beyond: not part of the version string
        let mysql = serve(Box::leak(greeting.into_boxed_slice()), false).await;
        assert_eq!(grab_one(ip, mysql, "mysql", Duration::from_millis(800)).await.as_deref(), Some("8.0.35"));
        // a server that answers but is not actually MySQL (no protocol-version-10 byte) says nothing
        let not_mysql = serve(b"hello there", false).await;
        assert_eq!(grab_one(ip, not_mysql, "mysql", Duration::from_millis(300)).await, None);
    }

    #[test]
    fn extended_banner_ports_are_only_tried_when_asked_for() {
        // real ports 23/3306/445/1433 cannot be bound in a test the way ssh(22)/http(80) already
        // cannot be, so the on/off switch is checked at the port-list level instead
        let off: Vec<_> = ports_for(false).collect();
        let on: Vec<_> = ports_for(true).collect();
        assert_eq!(off.len(), BANNER_PORTS.len(), "nothing extra without --extended-banners");
        assert_eq!(on.len(), BANNER_PORTS.len() + EXTENDED_BANNER_PORTS.len());
        for entry in [(23, "telnet"), (3306, "mysql"), (445, "smb"), (1433, "mssql")] {
            assert!(on.contains(&&entry), "{entry:?}");
            assert!(!off.contains(&&entry), "{entry:?}");
        }
    }

    // -------------------------------------------------------------------------------------- SMB

    /// A well-formed SMB2 SESSION_SETUP response body carrying an NTLMSSP CHALLENGE_MESSAGE whose
    /// Version field says `major.minor.build`.
    fn smb_setup_response(major: u8, minor: u8, build: u16, version_flag: bool) -> Vec<u8> {
        let mut ntlm = b"NTLMSSP\0".to_vec();
        ntlm.extend(2u32.to_le_bytes()); // MessageType = 2 (CHALLENGE)
        ntlm.extend([0u8; 8]); // TargetNameFields
        ntlm.extend(if version_flag { 0x0200_0000u32 } else { 0u32 }.to_le_bytes());
        ntlm.extend([0u8; 8]); // ServerChallenge
        ntlm.extend([0u8; 8]); // Reserved
        ntlm.extend([0u8; 8]); // TargetInfoFields
        ntlm.extend([major, minor, build as u8, (build >> 8) as u8, 0, 0, 0, 0]); // Version (offset 48..56), ProductBuild little-endian

        let mut msg = smb2_header(0x0001, 1);
        msg.extend([0x09, 0x00]); // StructureSize
        msg.extend([0, 0]); // SessionFlags
        let offset = (msg.len() + 4) as u16; // + 2 more fields before the buffer
        msg.extend(offset.to_le_bytes());
        msg.extend((ntlm.len() as u16).to_le_bytes());
        msg.extend(&ntlm);
        msg
    }

    #[test]
    fn the_windows_build_is_read_from_the_ntlm_challenge_when_offered() {
        let with_version = smb_setup_response(10, 0, 19041, true);
        assert_eq!(smb_ntlm_version(&with_version).as_deref(), Some("10.0.19041"));
        // Samba and older Windows commonly do not set the VERSION flag at all: correctly nothing
        let without_version = smb_setup_response(10, 0, 19041, false);
        assert_eq!(smb_ntlm_version(&without_version), None);
    }

    #[test]
    fn smb_parsing_never_panics_on_hostile_or_truncated_input() {
        assert_eq!(smb_ntlm_version(&[]), None);
        assert_eq!(smb_ntlm_version(&[0u8; 63]), None, "shorter than one SMB2 header");
        let full = smb_setup_response(6, 1, 7601, true);
        for cut in 0..full.len() {
            let _ = smb_ntlm_version(&full[..cut]); // truncated at every possible point: must not panic
        }
        let mut rng = Rng(0x5eed_1234);
        for _ in 0..2000 {
            let n = 1 + rng.below(200);
            let junk: Vec<u8> = (0..n).map(|_| rng.next() as u8).collect();
            let _ = smb_ntlm_version(&junk);
        }
    }

    #[test]
    fn the_smb_request_builders_are_internally_consistent() {
        // the 4-byte direct-TCP length prefix matches what actually follows
        let neg = smb2_negotiate_request();
        let len = ((neg[1] as usize) << 16) | ((neg[2] as usize) << 8) | neg[3] as usize;
        assert_eq!(len, neg.len() - 4);
        assert_eq!(&neg[4..8], b"\xfeSMB");

        let setup = smb2_session_setup_request();
        let len = ((setup[1] as usize) << 16) | ((setup[2] as usize) << 8) | setup[3] as usize;
        assert_eq!(len, setup.len() - 4);
        // the security-buffer offset/length the request itself claims must point at the NTLM blob
        // it actually appended, both counted from the start of the SMB2 message (i.e. past the
        // 4-byte direct-TCP prefix)
        let msg = &setup[4..];
        let sec_offset = u16::from_le_bytes(msg[76..78].try_into().unwrap()) as usize;
        let sec_len = u16::from_le_bytes(msg[78..80].try_into().unwrap()) as usize;
        assert_eq!(sec_offset, 64 + 24, "header (64) + this message's fixed body (24)");
        assert_eq!(&msg[sec_offset..sec_offset + 8], b"NTLMSSP\0");
        assert_eq!(sec_len, msg.len() - sec_offset);
    }

    async fn smb_mock(negotiate_reply: Vec<u8>, setup_reply: Vec<u8>) -> u16 {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = l.accept().await {
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf).await; // the Negotiate request: ignored, a fixed reply is sent
                let _ = s.write_all(&direct_tcp_wrap(&negotiate_reply)).await;
                let _ = s.read(&mut buf).await; // the Session Setup request
                let _ = s.write_all(&direct_tcp_wrap(&setup_reply)).await;
            }
        });
        port
    }

    #[tokio::test]
    async fn smb_version_reads_the_build_over_two_real_round_trips() {
        let port = smb_mock(vec![0u8; 64], smb_setup_response(10, 0, 22621, true)).await;
        assert_eq!(smb_version(Ipv4Addr::LOCALHOST, port, Duration::from_millis(800)).await.as_deref(), Some("10.0.22621"));
        // a server that answers but is not SMB2 at all (too short to be a header)
        let not_smb = smb_mock(vec![0u8; 4], vec![]).await;
        assert_eq!(smb_version(Ipv4Addr::LOCALHOST, not_smb, Duration::from_millis(300)).await, None);
    }

    // ------------------------------------------------------------------------------------ MSSQL

    /// A well-formed TDS PRELOGIN response body (after the 8-byte packet header) with a single
    /// VERSION option.
    fn prelogin_response(major: u8, minor: u8, build: u16) -> Vec<u8> {
        let mut body = vec![0x00u8, 0, 6, 0, 6, 0xFF]; // one VERSION option (offset 6, length 6), then terminator
        body.extend([major, minor, (build >> 8) as u8, build as u8, 0, 0]);
        body
    }

    #[test]
    fn the_sql_server_build_is_read_from_the_prelogin_response() {
        assert_eq!(tds_prelogin_version(&prelogin_response(15, 0, 4295)), Some("15.0.4295".to_string()));
        assert_eq!(tds_prelogin_version(&[0xFF]), None, "no options at all, just the terminator");
        assert_eq!(tds_prelogin_version(&[0x01, 0, 3, 0, 1, 0xFF, 0x02]), None, "an ENCRYPTION option only: no VERSION");
    }

    #[test]
    fn prelogin_parsing_never_panics_on_hostile_or_truncated_input() {
        assert_eq!(tds_prelogin_version(&[]), None);
        let full = prelogin_response(12, 0, 2000);
        for cut in 0..full.len() {
            let _ = tds_prelogin_version(&full[..cut]);
        }
        let mut rng = Rng(0x7ace_9001);
        for _ in 0..2000 {
            let n = rng.below(100);
            let junk: Vec<u8> = (0..n).map(|_| rng.next() as u8).collect();
            let _ = tds_prelogin_version(&junk);
        }
    }

    #[test]
    fn the_prelogin_request_is_a_well_formed_tds_packet() {
        let p = tds_prelogin_request();
        assert_eq!(p[0], 0x12, "PRELOGIN packet type");
        assert_eq!(p[1], 0x01, "End Of Message");
        let len = u16::from_be_bytes([p[2], p[3]]) as usize;
        assert_eq!(len, p.len());
        assert_eq!(*p.last().unwrap(), 0x00, "MARS option data (the last byte written)");
    }

    #[tokio::test]
    async fn mssql_version_reads_the_build_over_one_real_round_trip() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = l.accept().await {
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf).await;
                let body = prelogin_response(15, 0, 2000);
                let mut packet = vec![0x04, 0x01, 0, 0, 0, 0, 1, 0];
                packet.extend(&body);
                let total = packet.len() as u16;
                packet[2..4].copy_from_slice(&total.to_be_bytes());
                let _ = s.write_all(&packet).await;
            }
        });
        assert_eq!(mssql_version(Ipv4Addr::LOCALHOST, port, Duration::from_millis(800)).await.as_deref(), Some("15.0.2000"));
        // a server that answers but with the wrong TDS packet type is not a PRELOGIN response
        let l2 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port2 = l2.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = l2.accept().await {
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf).await;
                let _ = s.write_all(&[0x01, 0x01, 0, 8, 0, 0, 1, 0]).await;
            }
        });
        assert_eq!(mssql_version(Ipv4Addr::LOCALHOST, port2, Duration::from_millis(300)).await, None);
    }
}
