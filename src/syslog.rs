//! Syslog / CEF export of events for SIEMs (Splunk, QRadar, Wazuh, Sentinel, …).
//!
//! Each event becomes one RFC 5424 syslog message whose body is an ArcSight
//! **CEF** record, the format nearly every SIEM parses out of the box:
//!
//! ```text
//! <164>1 2026-09-20T21:00:00Z denis-host denis - new_port - CEF:0|DENIS|DENIS|0.1.0|new_port|Port 23 first used|8|rt=... src=10.0.0.5 ...
//! ```
//!
//! Like the OpenObserve exporter this is a *puller* driven by a cursor kept in the
//! database (see `sink.rs`): a dead syslog server never affects detection, and after
//! an outage the backlog is sent in order. Delivery is at-least-once.
//!
//! Transports: `udp://host:port` (one datagram per message; fire and forget) and
//! `tcp://host:port` (newline-framed, RFC 6587 "non-transparent framing"; a
//! connection per cycle, so a failure leaves the cursor where it was and is retried).
//!
//! # Injection
//!
//! Hostnames, device names and other text in an event come from the network or
//! from users. In a CEF record an unescaped `|` (header) or `=` (extension) lets
//! the sender forge fields, and a newline would forge a whole extra record. All
//! such characters are escaped or replaced below, and the tests attack exactly this.

use std::io::Write;
use std::net::{ToSocketAddrs, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context, Result};

use crate::model::Event;
use crate::sink::ExportStatus;
use crate::store::{Store};

const BATCH: usize = 500;
const MAX_BATCHES_PER_CYCLE: usize = 40;
/// Syslog facility `local4`.
const FACILITY: u8 = 20;
/// Bound on one message so a hostile summary cannot produce a huge datagram.
const MAX_FIELD: usize = 1024;

#[derive(Clone, Debug, PartialEq)]
pub enum Transport {
    Udp,
    Tcp,
}

#[derive(Clone, Debug)]
pub struct SyslogConfig {
    pub transport: Transport,
    /// `host:port`
    pub addr: String,
    pub interval: Duration,
}

impl SyslogConfig {
    /// Parse `udp://host:port` or `tcp://host:port`.
    pub fn parse(url: &str, interval: Duration) -> Result<Self> {
        let (transport, rest) = if let Some(r) = url.strip_prefix("udp://") {
            (Transport::Udp, r)
        } else if let Some(r) = url.strip_prefix("tcp://") {
            (Transport::Tcp, r)
        } else {
            bail!("the syslog target must look like udp://host:514 or tcp://host:514");
        };
        let (host, port) = rest.rsplit_once(':').context("the syslog target needs a port, e.g. udp://siem.example.com:514")?;
        if host.is_empty() || port.parse::<u16>().is_err() || rest.contains('/') {
            bail!("the syslog target must look like udp://host:514 or tcp://host:514");
        }
        Ok(SyslogConfig { transport, addr: rest.to_string(), interval })
    }
}

/// Escape a CEF *header* field: `\` and `|` are special.
fn cef_header(s: &str) -> String {
    clean(s).replace('\\', "\\\\").replace('|', "\\|")
}

/// Escape a CEF *extension value*: `\` and `=` are special.
fn cef_value(s: &str) -> String {
    clean(s).replace('\\', "\\\\").replace('=', "\\=")
}

/// Control characters (newlines above all) become spaces; length is bounded.
fn clean(s: &str) -> String {
    s.chars().map(|c| if c.is_control() { ' ' } else { c }).take(MAX_FIELD).collect()
}

/// CEF severity 0–10 from our severity name and score.
fn cef_severity(e: &Event) -> u8 {
    match e.severity.as_str() {
        "high" => 8 + (e.score >= 90) as u8,
        "medium" => 5 + (e.score >= 50) as u8,
        "low" => 3,
        _ => 1,
    }
}

/// Syslog severity (RFC 5424 §6.2.1) from ours.
fn syslog_severity(e: &Event) -> u8 {
    match e.severity.as_str() {
        "high" => 3,   // error
        "medium" => 4, // warning
        "low" => 5,    // notice
        _ => 6,        // informational
    }
}

/// Names and addresses of the device an event is about.
#[derive(Default, Clone)]
pub struct Subject {
    pub name: Option<String>,
    pub ip: Option<String>,
    pub mac: Option<String>,
}

/// One RFC 5424 message carrying a CEF record. `host` is this machine's name.
pub fn format_event(e: &Event, subject: &Subject, host: &str, version: &str) -> String {
    let pri = FACILITY * 8 + syslog_severity(e);
    let summary = e.raw_details["summary"].as_str().unwrap_or("");
    let mut ext = format!("rt={} cs1Label=score cs1={} cs2Label=eventId cs2={}", e.timestamp * 1000, e.score, e.id);
    if let Some(v) = &subject.ip {
        ext.push_str(&format!(" src={}", cef_value(v)));
    }
    if let Some(v) = &subject.mac {
        ext.push_str(&format!(" smac={}", cef_value(v)));
    }
    if let Some(v) = &subject.name {
        ext.push_str(&format!(" shost={}", cef_value(v)));
    }
    if let Some(a) = &e.agent_id {
        ext.push_str(&format!(" cs3Label=site cs3={}", cef_value(a)));
    }
    if let Some(r) = e.raw_details["reasons"].as_array() {
        let joined: Vec<&str> = r.iter().filter_map(|x| x.as_str()).collect();
        ext.push_str(&format!(" msg={}", cef_value(&joined.join("; "))));
    }
    // syslog header fields may not contain spaces; the host comes from the OS but is still sanitised
    let host: String = host.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-')).take(64).collect();
    format!(
        "<{pri}>1 {} {} denis - {} - CEF:0|DENIS|DENIS|{}|{}|{}|{}|{ext}",
        crate::report::iso(e.timestamp),
        if host.is_empty() { "-" } else { &host },
        e.kind.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '_').collect::<String>(),
        cef_header(version),
        cef_header(&e.kind),
        cef_header(summary),
        cef_severity(e),
    )
}

pub struct Syslog {
    cfg: SyslogConfig,
    host: String,
    pub status: Arc<Mutex<ExportStatus>>,
}

impl Syslog {
    pub fn new(cfg: SyslogConfig) -> Self {
        let target = format!("{}://{}", if cfg.transport == Transport::Udp { "udp" } else { "tcp" }, cfg.addr);
        Syslog {
            cfg,
            host: crate::net::local_hostname().unwrap_or_default(),
            status: Arc::new(Mutex::new(ExportStatus { target, ..Default::default() })),
        }
    }

    pub fn interval(&self) -> Duration {
        self.cfg.interval
    }

    fn cursor(store: &dyn Store) -> Result<i64> {
        Ok(store
            .get_setting("syslog.cursor.events")?
            .and_then(|b| String::from_utf8(b).ok()?.parse().ok())
            .unwrap_or(0))
    }

    fn send(&self, msgs: &[String]) -> Result<()> {
        let addr = self.cfg.addr.to_socket_addrs().with_context(|| format!("resolving {}", self.cfg.addr))?.next().context("no address")?;
        match self.cfg.transport {
            Transport::Udp => {
                let sock = UdpSocket::bind(if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" })?;
                for m in msgs {
                    sock.send_to(m.as_bytes(), addr)?;
                }
            }
            Transport::Tcp => {
                let mut s = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(10))?;
                s.set_write_timeout(Some(Duration::from_secs(10)))?;
                let mut buf = Vec::new();
                for m in msgs {
                    buf.extend_from_slice(m.as_bytes());
                    buf.push(b'\n');
                }
                s.write_all(&buf)?;
                s.flush()?;
            }
        }
        Ok(())
    }

    /// One cycle: send events after the cursor, advance it after each accepted batch.
    /// Only events that are alerts or worse are sent (`info` is noise for a SIEM).
    pub fn sync_once(&self, store: &dyn Store, now: i64) -> Result<u64> {
        let r = self.sync_inner(store, now);
        let mut st = self.status.lock().unwrap();
        match &r {
            Ok(n) => {
                st.sent += n;
                st.last_ok = Some(now);
                st.last_error = None;
            }
            Err(e) => st.last_error = Some(format!("{e:#}")),
        }
        r
    }

    fn sync_inner(&self, store: &dyn Store, now: i64) -> Result<u64> {
        let mut sent = 0;
        for _ in 0..MAX_BATCHES_PER_CYCLE {
            let after = Self::cursor(store)?;
            let batch = store.events_after(after, BATCH)?;
            let Some(last) = batch.last().map(|e| e.id) else { break };
            let assets = store.load_assets()?;
            let metas = store.load_all_meta()?;
            let msgs: Vec<String> = batch
                .iter()
                .filter(|e| e.severity != "info")
                .map(|e| {
                    let a = assets.iter().find(|a| a.id == e.asset_id);
                    let subject = Subject {
                        name: metas.get(&e.asset_id).and_then(|m| m.display_name.clone()).or_else(|| a.and_then(|a| a.hostnames.first().cloned())),
                        ip: a.and_then(|a| a.current_ip()).map(|i| i.to_string()),
                        mac: a.map(|a| a.mac.to_string()),
                    };
                    format_event(e, &subject, &self.host, env!("CARGO_PKG_VERSION"))
                })
                .collect();
            if !msgs.is_empty() {
                self.send(&msgs)?;
            }
            store.set_setting("syslog.cursor.events", last.to_string().as_bytes(), now)?;
            sent += msgs.len() as u64;
            if batch.len() < BATCH {
                break;
            }
        }
        Ok(sent)
    }
}

/// Run until aborted; log each distinct failure once.
pub async fn run(sink: Arc<Syslog>, store: Arc<dyn Store>) {
    let mut last_err = String::new();
    loop {
        let (s, st) = (sink.clone(), store.clone());
        let now = crate::model::now_ts();
        match tokio::task::spawn_blocking(move || s.sync_once(&*st, now)).await {
            Ok(Ok(_)) => {
                if !last_err.is_empty() {
                    tracing::info!("syslog export recovered");
                    last_err.clear();
                }
            }
            Ok(Err(e)) => {
                let msg = format!("{e:#}");
                if msg != last_err {
                    tracing::warn!("syslog export failed (will retry): {msg}");
                    last_err = msg;
                }
            }
            Err(_) => return,
        }
        tokio::time::sleep(sink.interval()).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::AssetStore;
    use crate::store::EventStore;
    use crate::model::{Asset, Mac};
    use crate::store::sqlite::SqliteStore;
    use serde_json::json;

    fn event(kind: &str, sev: &str, score: i32, summary: &str) -> Event {
        Event { id: 7, agent_id: None, asset_id: 1, kind: kind.into(), timestamp: 1_789_933_092, severity: sev.into(), score, acked: false, raw_details: json!({"summary": summary, "reasons": ["+40 a", "+20 b"]}) }
    }

    #[test]
    fn a_message_is_rfc5424_with_a_cef_body_and_correct_priorities() {
        let s = Subject { name: Some("Reception printer".into()), ip: Some("10.0.0.5".into()), mac: Some("00:11:22:33:44:55".into()) };
        let m = format_event(&event("new_port", "high", 91, "Port 23 first used"), &s, "denis-host", "0.1.0");
        assert!(m.starts_with("<163>1 2026-09-20T"), "{m}"); // local4 (20*8) + error (3)
        assert!(m.contains(" denis-host denis - new_port - CEF:0|DENIS|DENIS|0.1.0|new_port|Port 23 first used|9|"), "{m}");
        for want in ["src=10.0.0.5", "smac=00:11:22:33:44:55", "shost=Reception printer", "cs1=91", "cs2=7", "msg=+40 a; +20 b", "rt=1789933092000"] {
            assert!(m.contains(want), "{want} in {m}");
        }
        assert!(format_event(&event("x", "medium", 40, ""), &s, "h", "1").starts_with("<164>1"));
        assert!(format_event(&event("x", "low", 30, ""), &s, "h", "1").starts_with("<165>1"));
    }

    #[test]
    fn hostile_text_cannot_forge_cef_fields_or_extra_records() {
        let evil = "printer|9|forged\nCEF:0|X|Y|1|fake|fake|10| cs1=999\r<0>1 injected";
        let s = Subject { name: Some(evil.into()), ip: None, mac: None };
        let m = format_event(&event("new_device", "high", 80, evil), &s, "bad host\n", "1");
        assert!(!m.contains('\n') && !m.contains('\r'), "one line only: {m:?}");
        // header: every | inside the summary is escaped, so only the five separators after
        // vendor, product, version, kind and summary remain before "|severity|rt=..."
        let header = m.split("CEF:0|").nth(1).unwrap().split("|rt=").next().unwrap();
        let unescaped = header.match_indices('|').filter(|(i, _)| !header[..*i].ends_with('\\')).count();
        assert_eq!(unescaped, 5, "{header}");
        // extension: '=' inside a value is escaped, so no extra field can be forged
        assert!(m.contains("shost=printer|9|forged"), "{m}");
        assert!(m.contains("cs1\\=999"), "{m}");
        let ext = m.split("|rt=").nth(1).unwrap();
        assert_eq!(ext.matches(" cs1=").count(), 1, "only our own score field in the extension: {m}");
        assert!(m.contains(" badhost denis - "), "host sanitised: {m}");
        // absurd lengths are cut
        let long = "a".repeat(10_000);
        assert!(format_event(&event("x", "high", 80, &long), &Subject::default(), "h", "1").len() < 4_000);
    }

    #[test]
    fn targets_are_parsed_strictly() {
        let i = Duration::from_secs(5);
        assert!(SyslogConfig::parse("udp://siem.example.com:514", i).is_ok());
        assert_eq!(SyslogConfig::parse("tcp://10.0.0.1:6514", i).unwrap().transport, Transport::Tcp);
        for bad in ["siem:514", "http://x:514", "udp://host", "udp://:514", "udp://host:notaport", "udp://host:514/extra"] {
            assert!(SyslogConfig::parse(bad, i).is_err(), "{bad}");
        }
    }

    #[test]
    fn udp_delivery_skips_info_events_advances_the_cursor_and_does_not_resend() {
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        rx.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
        let cfg = SyslogConfig::parse(&format!("udp://{}", rx.local_addr().unwrap()), Duration::from_secs(5)).unwrap();
        let sl = Syslog::new(cfg);
        let s = SqliteStore::open_in_memory().unwrap();
        let mut a = Asset::new(Mac([2, 0, 0, 0, 0, 1]), 1);
        s.save_asset(&mut a).unwrap();
        for (sev, score) in [("info", 0), ("high", 85)] {
            let mut e = Event { asset_id: a.id, ..event("arp_conflict", sev, score, "conflict") };
            s.insert_event(&mut e).unwrap();
        }
        assert_eq!(sl.sync_once(&s, 100).unwrap(), 1);
        let mut buf = [0u8; 4096];
        let n = rx.recv(&mut buf).unwrap();
        let m = String::from_utf8_lossy(&buf[..n]);
        assert!(m.contains("arp_conflict") && m.contains("smac=02:00:00:00:00:01"), "{m}");
        assert!(rx.recv(&mut buf).is_err(), "the info event was not sent");
        assert_eq!(sl.sync_once(&s, 110).unwrap(), 0);
        assert!(rx.recv(&mut buf).is_err(), "nothing is sent twice");
    }

    #[test]
    fn a_tcp_outage_leaves_the_cursor_so_the_backlog_arrives_later() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        drop(l); // nothing listening: connection refused
        let sl = Syslog::new(SyslogConfig::parse(&format!("tcp://{addr}"), Duration::from_secs(5)).unwrap());
        let s = SqliteStore::open_in_memory().unwrap();
        let mut a = Asset::new(Mac([2, 0, 0, 0, 0, 1]), 1);
        s.save_asset(&mut a).unwrap();
        let mut e = Event { asset_id: a.id, ..event("new_port", "high", 80, "x") };
        s.insert_event(&mut e).unwrap();
        assert!(sl.sync_once(&s, 100).is_err());
        assert!(sl.status.lock().unwrap().last_error.is_some());
        // the collector comes back
        let l = std::net::TcpListener::bind(addr).unwrap();
        let h = std::thread::spawn(move || {
            let (mut c, _) = l.accept().unwrap();
            let mut v = String::new();
            std::io::Read::read_to_string(&mut c, &mut v).unwrap();
            v
        });
        assert_eq!(sl.sync_once(&s, 110).unwrap(), 1);
        let got = h.join().unwrap();
        assert!(got.ends_with('\n') && got.contains("new_port"), "{got:?}");
    }
}
