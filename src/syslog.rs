//! Syslog export of events, findings and the audit log to a SIEM (Splunk, QRadar, Wazuh,
//! Sentinel, ...), in **CEF**, **LEEF** or plain **JSON**, over **UDP**, **TCP** or **TLS**.
//!
//! Fully configurable from the console (Settings → SIEM / Log export, see `Settings` below):
//! pick a format, a transport, a target, and which streams to send, independently:
//!
//! * **events** — everything the detector raised (`info` is skipped: noise for a SIEM), the
//!   original and still the most common use of this exporter.
//! * **findings** — standing weaknesses (`findings.rs`: EOL software, KEV matches, open risky
//!   ports, ...). These have no natural sequence number (they are recomputed from current state,
//!   not logged as they happen), so a small persisted set of "already sent" keys is used instead
//!   of a cursor: a finding is sent once, the first time it is seen, and again if it ever clears
//!   and comes back.
//! * **audit** — who changed what in the console.
//!
//! Like the OpenObserve exporter this is a *puller* driven by a cursor kept in the database (see
//! `sink.rs`): a dead SIEM never affects detection, and after an outage the backlog is sent in
//! order. Delivery is at-least-once.
//!
//! ```text
//! <164>1 2026-09-20T21:00:00Z denis-host denis - new_port - CEF:0|DENIS|DENIS|0.1.0|new_port|Port 23 first used|8|rt=... src=10.0.0.5 ...
//! ```
//!
//! # Injection
//!
//! Hostnames, device names and other text in a record come from the network or from users. In a
//! CEF/LEEF record an unescaped delimiter lets the sender forge fields, and a newline would forge
//! a whole extra record. All such characters are escaped or replaced in `render`, and the tests
//! attack exactly this.
//!
//! # Configuration
//!
//! `Settings` (this module) is the one source of truth, editable any time from the console with
//! no restart. The legacy `--syslog udp://host:514` CLI flag (CEF, events only, still supported
//! for headless installs) only *seeds* it, once, the first time DENIS starts with nothing saved
//! yet (`seed_from_cli`) — after that the console is authoritative.

use std::io::Write as _;
use std::net::{TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::model::{AuditEntry, Event};
use crate::sink::ExportStatus;
use crate::store::Store;

pub const SETTINGS_KEY: &str = "siem";
const BATCH: usize = 500;
const MAX_BATCHES_PER_CYCLE: usize = 40;
/// Syslog facility `local4`.
const FACILITY: u8 = 20;
/// Bound on one field so a hostile summary cannot produce a huge message.
const MAX_FIELD: usize = 1024;
/// How many "already sent" finding keys to remember (oldest dropped first): enough for any
/// realistic number of standing findings without the settings row growing without bound.
const MAX_SENT_FINDINGS: usize = 5000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    Udp,
    Tcp,
    /// TCP wrapped in TLS (RFC 5425): plaintext syslog crosses more networks than it should, so
    /// this is offered as a first-class transport, not an afterthought.
    Tls,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    Cef,
    Leef,
    Json,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Streams {
    pub events: bool,
    pub findings: bool,
    pub audit: bool,
}

impl Streams {
    fn any(self) -> bool {
        self.events || self.findings || self.audit
    }
}

#[derive(Clone, Debug)]
pub struct SyslogConfig {
    pub transport: Transport,
    /// `host:port`
    pub addr: String,
    pub format: Format,
    pub streams: Streams,
    /// Only meaningful for `Transport::Tls`: skip certificate verification. A self-signed SIEM
    /// collector is common in this world, and there is no certificate-pinning UI (yet) to do
    /// better than the system's own trust roots or "trust nothing".
    pub insecure_tls: bool,
    pub interval: Duration,
}

impl SyslogConfig {
    /// Parse the legacy CLI form: `udp://host:514`, `tcp://host:514` or `tls://host:6514`.
    /// Always means CEF and the events stream only; see `Settings` for the fuller form.
    pub fn parse(url: &str, interval: Duration) -> Result<Self> {
        let (transport, rest) = if let Some(r) = url.strip_prefix("udp://") {
            (Transport::Udp, r)
        } else if let Some(r) = url.strip_prefix("tcp://") {
            (Transport::Tcp, r)
        } else if let Some(r) = url.strip_prefix("tls://") {
            (Transport::Tls, r)
        } else {
            bail!("the syslog target must look like udp://host:514, tcp://host:514 or tls://host:6514");
        };
        let (host, port) = rest.rsplit_once(':').context("the syslog target needs a port, e.g. udp://siem.example.com:514")?;
        if host.is_empty() || port.parse::<u16>().is_err() || rest.contains('/') {
            bail!("the syslog target must look like udp://host:514, tcp://host:514 or tls://host:6514");
        }
        Ok(SyslogConfig { transport, addr: rest.to_string(), format: Format::Cef, streams: Streams { events: true, findings: false, audit: false }, insecure_tls: false, interval })
    }
}

/// The console's SIEM / Log export settings: the one source of truth once anything has been
/// saved (see the module doc comment).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Settings {
    pub enabled: bool,
    /// `"udp"`, `"tcp"` or `"tls"`.
    pub transport: String,
    pub host: String,
    pub port: u16,
    /// `"cef"`, `"leef"` or `"json"`.
    pub format: String,
    pub streams: Streams,
    pub insecure_tls: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings { enabled: false, transport: "udp".into(), host: String::new(), port: 514, format: "cef".into(), streams: Streams { events: true, findings: false, audit: false }, insecure_tls: false }
    }
}

impl Settings {
    pub fn validate(&self) -> Result<(), &'static str> {
        if !matches!(self.transport.as_str(), "udp" | "tcp" | "tls") {
            return Err("transport must be udp, tcp or tls");
        }
        if !matches!(self.format.as_str(), "cef" | "leef" | "json") {
            return Err("format must be cef, leef or json");
        }
        if self.enabled {
            if self.host.trim().is_empty() {
                return Err("a host is required");
            }
            if self.port == 0 {
                return Err("a port is required");
            }
            if !self.streams.any() {
                return Err("choose at least one stream to send: events, findings or the audit log");
            }
        }
        Ok(())
    }

    fn transport(&self) -> Transport {
        match self.transport.as_str() {
            "tcp" => Transport::Tcp,
            "tls" => Transport::Tls,
            _ => Transport::Udp,
        }
    }

    fn format(&self) -> Format {
        match self.format.as_str() {
            "leef" => Format::Leef,
            "json" => Format::Json,
            _ => Format::Cef,
        }
    }

    pub fn config(&self) -> SyslogConfig {
        SyslogConfig { transport: self.transport(), addr: format!("{}:{}", self.host, self.port), format: self.format(), streams: self.streams, insecure_tls: self.insecure_tls, interval: Duration::from_secs(15) }
    }
}

pub fn load(store: &dyn Store) -> Result<Settings> {
    Ok(match store.get_setting(SETTINGS_KEY)? {
        Some(b) => serde_json::from_slice(&b).ok().filter(|s: &Settings| s.validate().is_ok()).unwrap_or_default(),
        None => Settings::default(),
    })
}

pub fn save(store: &dyn Store, s: &Settings, now: i64) -> Result<()> {
    store.set_setting(SETTINGS_KEY, &serde_json::to_vec(s)?, now)
}

/// Turn the legacy `--syslog` CLI flag into the first saved `Settings`, only when nothing has
/// been saved from the console yet — a headless install keeps working exactly as it did, and the
/// console becomes authoritative the moment anyone opens it (even without changing anything).
pub fn seed_from_cli(store: &dyn Store, cli: &SyslogConfig, now: i64) -> Result<()> {
    if store.get_setting(SETTINGS_KEY)?.is_some() {
        return Ok(());
    }
    let (host, port) = cli.addr.rsplit_once(':').unwrap_or((cli.addr.as_str(), "514"));
    let s = Settings {
        enabled: true,
        transport: match cli.transport {
            Transport::Udp => "udp",
            Transport::Tcp => "tcp",
            Transport::Tls => "tls",
        }
        .into(),
        host: host.to_string(),
        port: port.parse().unwrap_or(514),
        format: "cef".into(),
        streams: Streams { events: true, findings: false, audit: false },
        insecure_tls: false,
    };
    save(store, &s, now)
}

// ------------------------------------------------------------------------------------ rendering

/// A generic exportable record, built once per event/finding/audit entry and then rendered into
/// whichever format the SIEM was configured for — keeps the escaping and structure logic (CEF,
/// LEEF, JSON) in one place instead of once per content type.
struct Rec {
    /// A short, code-like identifier: the event kind, the finding id, or `"audit"`.
    kind: String,
    summary: String,
    /// `"high"`, `"medium"`, `"low"` or `"info"`.
    severity: String,
    score: Option<i32>,
    timestamp: i64,
    /// Extra key/value pairs, in a stable order.
    fields: Vec<(&'static str, String)>,
}

/// Control characters (newlines above all) become spaces; length is bounded.
fn clean(s: &str) -> String {
    s.chars().map(|c| if c.is_control() { ' ' } else { c }).take(MAX_FIELD).collect()
}

/// Escape a CEF/LEEF *header* field: `\` and `|` are special.
fn header_escape(s: &str) -> String {
    clean(s).replace('\\', "\\\\").replace('|', "\\|")
}

/// Escape a CEF *extension value*: `\` and `=` are special.
fn cef_value(s: &str) -> String {
    clean(s).replace('\\', "\\\\").replace('=', "\\=")
}

/// Escape a LEEF *attribute value*: `\` and the tab delimiter are special.
fn leef_value(s: &str) -> String {
    clean(s).replace('\\', "\\\\").replace('\t', " ")
}

/// CEF severity 0-10 from our severity name and score.
fn cef_severity(severity: &str, score: Option<i32>) -> u8 {
    let score = score.unwrap_or(0);
    match severity {
        "high" => 8 + (score >= 90) as u8,
        "medium" => 5 + (score >= 50) as u8,
        "low" => 3,
        _ => 1,
    }
}

/// Syslog severity (RFC 5424 §6.2.1) from ours.
fn syslog_severity(severity: &str) -> u8 {
    match severity {
        "high" => 3,   // error
        "medium" => 4, // warning
        "low" => 5,    // notice
        _ => 6,        // informational
    }
}

fn render_cef(r: &Rec, version: &str) -> String {
    let mut ext = format!("rt={}", r.timestamp * 1000);
    if let Some(sc) = r.score {
        ext.push_str(&format!(" cs1Label=score cs1={sc}"));
    }
    for (k, v) in &r.fields {
        ext.push_str(&format!(" {k}={}", cef_value(v)));
    }
    format!("CEF:0|DENIS|DENIS|{}|{}|{}|{}|{ext}", header_escape(version), header_escape(&r.kind), header_escape(&r.summary), cef_severity(&r.severity, r.score))
}

fn render_leef(r: &Rec, version: &str) -> String {
    let mut ext = format!("devTime={}\tsev={}", crate::report::iso(r.timestamp), cef_severity(&r.severity, r.score));
    if let Some(sc) = r.score {
        ext.push_str(&format!("\tscore={sc}"));
    }
    for (k, v) in &r.fields {
        ext.push_str(&format!("\t{k}={}", leef_value(v)));
    }
    format!("LEEF:2.0|DENIS|DENIS|{}|{}|{ext}", header_escape(version), header_escape(&r.kind))
}

fn render_json(r: &Rec) -> String {
    let mut obj = serde_json::Map::new();
    obj.insert("kind".into(), json!(clean(&r.kind)));
    obj.insert("summary".into(), json!(clean(&r.summary)));
    obj.insert("severity".into(), json!(r.severity));
    obj.insert("timestamp".into(), json!(r.timestamp));
    if let Some(sc) = r.score {
        obj.insert("score".into(), json!(sc));
    }
    for (k, v) in &r.fields {
        obj.insert((*k).to_string(), json!(clean(v)));
    }
    serde_json::to_string(&serde_json::Value::Object(obj)).unwrap_or_default()
}

fn render(r: &Rec, format: Format, version: &str) -> String {
    match format {
        Format::Cef => render_cef(r, version),
        Format::Leef => render_leef(r, version),
        Format::Json => render_json(r),
    }
}

/// One RFC 5424 message wrapping `body` (a CEF/LEEF/JSON record, already rendered).
fn envelope(body: &str, timestamp: i64, host: &str, msgid: &str, severity: &str) -> String {
    let pri = FACILITY * 8 + syslog_severity(severity);
    let host: String = host.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-')).take(64).collect();
    let msgid: String = msgid.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '_').take(32).collect();
    format!(
        "<{pri}>1 {} {} denis - {} - {body}",
        crate::report::iso(timestamp),
        if host.is_empty() { "-" } else { &host },
        if msgid.is_empty() { "-" } else { &msgid },
    )
}

/// Names and addresses of the device an event/finding is about.
#[derive(Default, Clone)]
pub struct Subject {
    pub name: Option<String>,
    pub ip: Option<String>,
    pub mac: Option<String>,
}

impl Subject {
    fn fields(&self) -> Vec<(&'static str, String)> {
        let mut f = Vec::new();
        if let Some(v) = &self.ip {
            f.push(("src", v.clone()));
        }
        if let Some(v) = &self.mac {
            f.push(("smac", v.clone()));
        }
        if let Some(v) = &self.name {
            f.push(("shost", v.clone()));
        }
        f
    }
}

fn event_rec(e: &Event, subject: &Subject) -> Rec {
    let mut fields = subject.fields();
    if let Some(a) = &e.agent_id {
        fields.push(("site", a.clone()));
    }
    if let Some(r) = e.raw_details["reasons"].as_array() {
        let joined: Vec<&str> = r.iter().filter_map(|x| x.as_str()).collect();
        if !joined.is_empty() {
            fields.push(("msg", joined.join("; ")));
        }
    }
    fields.push(("eventId", e.id.to_string()));
    Rec { kind: e.kind.clone(), summary: e.raw_details["summary"].as_str().unwrap_or("").to_string(), severity: e.severity.clone(), score: Some(e.score), timestamp: e.timestamp, fields }
}

/// One finding, about one device (`findings::Finding.assets` is flattened to one `Rec` per id).
fn finding_rec(id: &str, title: &str, why: &str, severity: &str, asset_id: i64, subject: &Subject, now: i64) -> Rec {
    let mut fields = subject.fields();
    fields.push(("assetId", asset_id.to_string()));
    fields.push(("msg", why.to_string()));
    Rec { kind: id.to_string(), summary: title.to_string(), severity: severity.to_string(), score: None, timestamp: now, fields }
}

fn audit_rec(a: &AuditEntry) -> Rec {
    let mut fields = vec![("user", a.user.clone()), ("action", a.action.clone())];
    if let Some(id) = a.asset_id {
        fields.push(("assetId", id.to_string()));
    }
    Rec { kind: "audit".into(), summary: a.action.clone(), severity: "info".into(), score: None, timestamp: a.ts, fields }
}

// -------------------------------------------------------------------------------------- sending

/// Accepts any server certificate: only used when the console is explicitly told to trust one
/// (`Settings.insecure_tls`), for a self-signed SIEM collector with no certificate-pinning UI.
#[derive(Debug)]
struct AcceptAny;

impl rustls::client::danger::ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, _msg: &[u8], _cert: &rustls::pki_types::CertificateDer<'_>, _dss: &rustls::DigitallySignedStruct) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(&self, _msg: &[u8], _cert: &rustls::pki_types::CertificateDer<'_>, _dss: &rustls::DigitallySignedStruct) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()
    }
}

fn tls_client_config(insecure: bool) -> Arc<rustls::ClientConfig> {
    let _ = rustls::crypto::ring::default_provider().install_default(); // idempotent
    let builder = rustls::ClientConfig::builder();
    let cfg = if insecure {
        builder.dangerous().with_custom_certificate_verifier(Arc::new(AcceptAny)).with_no_client_auth()
    } else {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    Arc::new(cfg)
}

pub struct Syslog {
    cfg: SyslogConfig,
    host: String,
    pub status: Arc<Mutex<ExportStatus>>,
}

impl Syslog {
    pub fn new(cfg: SyslogConfig) -> Self {
        let scheme = match cfg.transport {
            Transport::Udp => "udp",
            Transport::Tcp => "tcp",
            Transport::Tls => "tls",
        };
        let target = format!("{scheme}://{}", cfg.addr);
        Syslog { cfg, host: crate::net::local_hostname().unwrap_or_default(), status: Arc::new(Mutex::new(ExportStatus { target, ..Default::default() })) }
    }

    pub fn interval(&self) -> Duration {
        self.cfg.interval
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
                let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(10))?;
                s.set_write_timeout(Some(Duration::from_secs(10)))?;
                s.write_all(&framed(msgs))?;
                s.flush()?;
            }
            Transport::Tls => {
                let host_only = self.cfg.addr.rsplit_once(':').map(|(h, _)| h).unwrap_or(&self.cfg.addr);
                let server_name = rustls::pki_types::ServerName::try_from(host_only.to_string()).map_err(|_| anyhow::anyhow!("{host_only:?} is not a usable TLS server name"))?;
                let mut conn = rustls::ClientConnection::new(tls_client_config(self.cfg.insecure_tls), server_name)?;
                let mut tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(10))?;
                tcp.set_write_timeout(Some(Duration::from_secs(10)))?;
                let mut tls = rustls::Stream::new(&mut conn, &mut tcp);
                tls.write_all(&framed(msgs))?;
                tls.flush()?;
            }
        }
        Ok(())
    }

    /// One cycle: send everything new on every enabled stream, advancing each stream's own
    /// cursor only after its batch is accepted (a send failure part-way leaves the others'
    /// cursors alone, so nothing already-delivered is lost or resent on the next try).
    pub fn sync_once(&self, store: &dyn Store, now: i64) -> Result<u64> {
        let r = self.sync_inner(store, now);
        let mut st = self.status.lock().unwrap_or_else(|e| e.into_inner());
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
        if self.cfg.streams.events {
            sent += self.sync_events(store, now)?;
        }
        if self.cfg.streams.audit {
            sent += self.sync_audit(store, now)?;
        }
        if self.cfg.streams.findings {
            sent += self.sync_findings(store, now)?;
        }
        Ok(sent)
    }

    fn sync_events(&self, store: &dyn Store, now: i64) -> Result<u64> {
        let mut sent = 0;
        for _ in 0..MAX_BATCHES_PER_CYCLE {
            let after = cursor(store, "syslog.cursor.events")?;
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
                    let r = event_rec(e, &subject);
                    envelope(&render(&r, self.cfg.format, env!("CARGO_PKG_VERSION")), r.timestamp, &self.host, &e.kind, &r.severity)
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

    fn sync_audit(&self, store: &dyn Store, now: i64) -> Result<u64> {
        let mut sent = 0;
        for _ in 0..MAX_BATCHES_PER_CYCLE {
            let after = cursor(store, "syslog.cursor.audit")?;
            let batch = store.audit_after(after, BATCH)?;
            let Some(last) = batch.last().map(|a| a.id) else { break };
            let msgs: Vec<String> = batch.iter().map(|a| { let r = audit_rec(a); envelope(&render(&r, self.cfg.format, env!("CARGO_PKG_VERSION")), r.timestamp, &self.host, "audit", &r.severity) }).collect();
            if !msgs.is_empty() {
                self.send(&msgs)?;
            }
            store.set_setting("syslog.cursor.audit", last.to_string().as_bytes(), now)?;
            sent += msgs.len() as u64;
            if batch.len() < BATCH {
                break;
            }
        }
        Ok(sent)
    }

    /// Findings have no sequence number (recomputed from current state, not logged as they
    /// happen): a small persisted set of "already sent" `finding_id:asset_id` keys stands in for
    /// a cursor, so each one is sent once, and again if it clears and comes back later.
    fn sync_findings(&self, store: &dyn Store, now: i64) -> Result<u64> {
        let assets = crate::store::real_assets(store)?;
        let metas = store.load_all_meta()?;
        let findings = crate::findings::compute(&assets, &metas, now);
        let mut sent_keys: Vec<String> = store.get_setting("syslog.sent_findings")?.and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
        let mut msgs = Vec::new();
        let mut new_keys = Vec::new();
        for f in &findings {
            for &asset_id in &f.assets {
                let key = format!("{}:{asset_id}", f.id);
                if sent_keys.contains(&key) {
                    continue;
                }
                let a = assets.iter().find(|a| a.id == asset_id);
                let subject = Subject {
                    name: metas.get(&asset_id).and_then(|m| m.display_name.clone()).or_else(|| a.and_then(|a| a.hostnames.first().cloned())),
                    ip: a.and_then(|a| a.current_ip()).map(|i| i.to_string()),
                    mac: a.map(|a| a.mac.to_string()),
                };
                let r = finding_rec(f.id, f.title, f.why, f.severity, asset_id, &subject, now);
                msgs.push(envelope(&render(&r, self.cfg.format, env!("CARGO_PKG_VERSION")), r.timestamp, &self.host, f.id, &r.severity));
                new_keys.push(key);
            }
        }
        if !msgs.is_empty() {
            self.send(&msgs)?;
            sent_keys.extend(new_keys);
            // Only what is currently open needs remembering; a finding that cleared can be
            // forgotten, keeping this from growing without bound on a large, changing inventory.
            let open: std::collections::HashSet<String> = findings.iter().flat_map(|f| f.assets.iter().map(move |a| format!("{}:{a}", f.id))).collect();
            sent_keys.retain(|k| open.contains(k));
            if sent_keys.len() > MAX_SENT_FINDINGS {
                let cut = sent_keys.len() - MAX_SENT_FINDINGS;
                sent_keys.drain(0..cut);
            }
            store.set_setting("syslog.sent_findings", &serde_json::to_vec(&sent_keys)?, now)?;
        }
        Ok(msgs.len() as u64)
    }
}

fn framed(msgs: &[String]) -> Vec<u8> {
    let mut buf = Vec::new();
    for m in msgs {
        buf.extend_from_slice(m.as_bytes());
        buf.push(b'\n');
    }
    buf
}

fn cursor(store: &dyn Store, key: &str) -> Result<i64> {
    Ok(store.get_setting(key)?.and_then(|b| String::from_utf8(b).ok()?.parse().ok()).unwrap_or(0))
}

/// Send one small message right now, bypassing cursors and settings — for the console's "Test"
/// button, so an administrator can check a target before saving or waiting for the next cycle.
pub fn send_test(cfg: &SyslogConfig, host: &str) -> Result<()> {
    let sl = Syslog::new(cfg.clone());
    let r = Rec { kind: "test".into(), summary: "DENIS SIEM export test message".into(), severity: "info".into(), score: None, timestamp: crate::model::now_ts(), fields: vec![("host", host.to_string())] };
    sl.send(&[envelope(&render(&r, cfg.format, env!("CARGO_PKG_VERSION")), r.timestamp, &sl.host, "test", &r.severity)])
}

/// Run until aborted; log each distinct failure once. Reads `Settings` fresh every cycle, so a
/// change from the console (including turning it off) takes effect on the next tick, no restart.
pub async fn run(store: Arc<dyn Store>, status: Arc<Mutex<ExportStatus>>) {
    let mut last_err = String::new();
    loop {
        let (s, st) = (store.clone(), status.clone());
        let now = crate::model::now_ts();
        let outcome = tokio::task::spawn_blocking(move || -> Result<()> {
            let settings = load(&*s)?;
            if !settings.enabled {
                return Ok(());
            }
            let sl = Syslog::new(settings.config());
            sl.sync_once(&*s, now)?;
            *st.lock().unwrap_or_else(|e| e.into_inner()) = sl.status.lock().unwrap_or_else(|e| e.into_inner()).clone();
            Ok(())
        })
        .await;
        match outcome {
            Ok(Ok(())) => {
                if !last_err.is_empty() {
                    tracing::info!("SIEM export recovered");
                    last_err.clear();
                }
            }
            Ok(Err(e)) => {
                let msg = format!("{e:#}");
                if msg != last_err {
                    tracing::warn!("SIEM export failed (will retry): {msg}");
                    last_err = msg;
                }
            }
            Err(_) => return,
        }
        tokio::time::sleep(Duration::from_secs(15)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Asset, Mac};
    use crate::store::sqlite::SqliteStore;
    use crate::store::{AdminStore, AssetStore, EventStore};
    use serde_json::json;

    fn event(kind: &str, sev: &str, score: i32, summary: &str) -> Event {
        Event { id: 7, agent_id: None, asset_id: 1, kind: kind.into(), timestamp: 1_789_933_092, severity: sev.into(), score, acked: false, raw_details: json!({"summary": summary, "reasons": ["+40 a", "+20 b"]}) }
    }

    #[test]
    fn a_cef_message_is_rfc5424_with_correct_priorities() {
        let s = Subject { name: Some("Reception printer".into()), ip: Some("10.0.0.5".into()), mac: Some("00:11:22:33:44:55".into()) };
        let r = event_rec(&event("new_port", "high", 91, "Port 23 first used"), &s);
        let m = envelope(&render_cef(&r, "0.1.0"), r.timestamp, "denis-host", &r.kind, &r.severity);
        assert!(m.starts_with("<163>1 2026-09-20T"), "{m}"); // local4 (20*8) + error (3)
        assert!(m.contains(" denis-host denis - new_port - CEF:0|DENIS|DENIS|0.1.0|new_port|Port 23 first used|9|"), "{m}");
        for want in ["src=10.0.0.5", "smac=00:11:22:33:44:55", "shost=Reception printer", "cs1=91", "eventId=7", "msg=+40 a; +20 b", "rt=1789933092000"] {
            assert!(m.contains(want), "{want} in {m}");
        }
    }

    #[test]
    fn a_leef_message_carries_the_same_fields_tab_separated() {
        let s = Subject { name: Some("Reception printer".into()), ip: Some("10.0.0.5".into()), mac: None };
        let r = event_rec(&event("new_port", "medium", 40, "Port 23 first used"), &s);
        let m = render_leef(&r, "0.1.0");
        assert!(m.starts_with("LEEF:2.0|DENIS|DENIS|0.1.0|new_port|"), "{m}");
        assert!(m.contains("src=10.0.0.5") && m.contains("shost=Reception printer") && m.contains("sev=5"), "{m}");
    }

    #[test]
    fn a_json_message_is_valid_json_with_our_fields() {
        let s = Subject { name: None, ip: Some("10.0.0.5".into()), mac: None };
        let r = event_rec(&event("new_port", "low", 30, "Port 23 first used"), &s);
        let v: serde_json::Value = serde_json::from_str(&render_json(&r)).unwrap();
        assert_eq!(v["kind"], "new_port");
        assert_eq!(v["src"], "10.0.0.5");
        assert_eq!(v["severity"], "low");
    }

    #[test]
    fn hostile_text_cannot_forge_cef_fields_or_extra_records_in_any_format() {
        let evil = "printer|9|forged\nCEF:0|X|Y|1|fake|fake|10| cs1=999\r<0>1 injected\ttabbed";
        let s = Subject { name: Some(evil.into()), ip: None, mac: None };
        let r = event_rec(&event("new_device", "high", 80, evil), &s);
        for m in [envelope(&render_cef(&r, "1"), r.timestamp, "bad host\n", &r.kind, &r.severity), envelope(&render_leef(&r, "1"), r.timestamp, "bad host\n", &r.kind, &r.severity), envelope(&render_json(&r), r.timestamp, "bad host\n", &r.kind, &r.severity)] {
            assert!(!m.contains('\n') && !m.contains('\r'), "one line only: {m:?}");
            assert!(m.contains(" badhost denis - "), "host sanitised: {m}");
        }
        let cef = render_cef(&r, "1");
        let header = cef.split("CEF:0|").nth(1).unwrap().split("|rt=").next().unwrap();
        let unescaped = header.match_indices('|').filter(|(i, _)| !header[..*i].ends_with('\\')).count();
        assert_eq!(unescaped, 5, "{header}");
        assert!(cef.contains("cs1\\=999"), "{cef}");
        // absurd lengths are cut
        let long = "a".repeat(10_000);
        let r2 = event_rec(&event("x", "high", 80, &long), &Subject::default());
        assert!(render_cef(&r2, "1").len() < 4_000);
    }

    #[test]
    fn targets_are_parsed_strictly_including_tls() {
        let i = Duration::from_secs(5);
        assert!(SyslogConfig::parse("udp://siem.example.com:514", i).is_ok());
        assert_eq!(SyslogConfig::parse("tcp://10.0.0.1:6514", i).unwrap().transport, Transport::Tcp);
        assert_eq!(SyslogConfig::parse("tls://10.0.0.1:6514", i).unwrap().transport, Transport::Tls);
        for bad in ["siem:514", "http://x:514", "udp://host", "udp://:514", "udp://host:notaport", "udp://host:514/extra"] {
            assert!(SyslogConfig::parse(bad, i).is_err(), "{bad}");
        }
    }

    #[test]
    fn settings_are_validated_and_default_to_disabled() {
        let d = Settings::default();
        assert!(!d.enabled);
        assert!(d.validate().is_ok());
        assert!(Settings { transport: "quic".into(), ..d.clone() }.validate().is_err());
        assert!(Settings { format: "syslog-ng".into(), ..d.clone() }.validate().is_err());
        assert!(Settings { enabled: true, host: "".into(), ..d.clone() }.validate().is_err());
        assert!(Settings { enabled: true, host: "siem".into(), port: 0, ..d.clone() }.validate().is_err());
        assert!(Settings { enabled: true, host: "siem".into(), streams: Streams::default(), ..d.clone() }.validate().is_err(), "at least one stream");
        assert!(Settings { enabled: true, host: "siem".into(), ..d }.validate().is_ok());
    }

    #[test]
    fn the_cli_flag_seeds_settings_only_once_the_console_then_wins() {
        let store = SqliteStore::open_in_memory().unwrap();
        let cli = SyslogConfig::parse("tcp://10.0.0.9:514", Duration::from_secs(5)).unwrap();
        seed_from_cli(&store, &cli, 100).unwrap();
        let s = load(&store).unwrap();
        assert!(s.enabled && s.transport == "tcp" && s.host == "10.0.0.9" && s.port == 514 && s.format == "cef");

        // the console changes it; seeding again (as if restarted with the same --syslog flag) is a no-op
        save(&store, &Settings { host: "changed".into(), ..s }, 200).unwrap();
        seed_from_cli(&store, &cli, 300).unwrap();
        assert_eq!(load(&store).unwrap().host, "changed");
    }

    #[test]
    fn udp_delivery_skips_info_events_advances_the_cursor_and_does_not_resend() {
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        rx.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
        let mut cfg = SyslogConfig::parse(&format!("udp://{}", rx.local_addr().unwrap()), Duration::from_secs(5)).unwrap();
        cfg.streams = Streams { events: true, findings: false, audit: false };
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
        let mut cfg = SyslogConfig::parse(&format!("tcp://{addr}"), Duration::from_secs(5)).unwrap();
        cfg.streams = Streams { events: true, findings: false, audit: false };
        let sl = Syslog::new(cfg);
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

    #[test]
    fn audit_and_findings_streams_are_independently_toggled_and_findings_are_sent_once() {
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        rx.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
        let mut cfg = SyslogConfig::parse(&format!("udp://{}", rx.local_addr().unwrap()), Duration::from_secs(5)).unwrap();
        cfg.streams = Streams { events: false, findings: true, audit: true };
        let sl = Syslog::new(cfg);
        let s = SqliteStore::open_in_memory().unwrap();
        s.add_audit(1, "admin", "user.create", None, &json!({})).unwrap();
        let mut a = Asset::new(Mac([0x3c, 0x22, 0xfb, 1, 2, 3]), 1); // a real vendor OUI so findings can fire
        a.open_ports = vec![crate::model::OpenPort { port: 23, proto: "tcp".into(), service: None }];
        s.save_asset(&mut a).unwrap();

        let n = sl.sync_once(&s, 100).unwrap();
        assert!(n >= 2, "at least the audit entry and one finding: {n}");
        let mut seen = Vec::new();
        let mut buf = [0u8; 4096];
        while let Ok(len) = rx.recv(&mut buf) {
            seen.push(String::from_utf8_lossy(&buf[..len]).to_string());
        }
        assert!(seen.iter().any(|m| m.contains("user.create")), "{seen:?}");
        assert!(seen.iter().any(|m| m.contains("telnet")), "{seen:?}");

        // a second cycle with nothing new resends neither
        assert_eq!(sl.sync_once(&s, 110).unwrap(), 0);
    }
}
