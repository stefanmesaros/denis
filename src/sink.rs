//! Export to OpenObserve: DENIS's events, audit log, trend samples and asset
//! inventory, pushed to an OpenObserve (or compatible) server so a customer can
//! see everything in one console.
//!
//! # Design
//!
//! The exporter is a *puller*, not a hook in the detection path. Every
//! `interval` it asks the database "what is new since my cursor?", posts that,
//! and only after the server has accepted it moves the cursor forward:
//!
//! * a slow or unreachable OpenObserve can never slow detection down or lose an
//!   alert (the data is already in SQLite; the exporter just catches up later);
//! * delivery is **at least once**: if DENIS stops between "accepted" and "cursor
//!   saved", one batch is sent twice. Every event/audit document carries its
//!   database `id`, so a dashboard can de-duplicate on it;
//! * cursors live in the `settings` table, so a restart resumes where it stopped.
//!
//! Streams (`<prefix>` defaults to `denis`): `<prefix>_events`, `<prefix>_audit`,
//! `<prefix>_metrics` and `<prefix>_assets`.
//!
//! # Trust and secrets
//!
//! The user name and password come from the environment only (never a flag, which
//! would show in `ps`) and are sent as HTTP Basic auth. They are never logged and
//! never appear in error text. Plain `http://` to a non-local host sends them in
//! the clear, so a warning is logged at start-up. The audit log is exported as it
//! is stored; it holds no passwords or tokens (see `web_admin::audit` callers).

use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::Serialize;
use serde_json::{json, Value};

use crate::model::{Asset, AssetMeta};
use crate::store::Store;

/// Documents per HTTP request.
const BATCH: usize = 500;
/// Requests per stream per cycle, so one cycle stays bounded after a long outage.
const MAX_BATCHES_PER_CYCLE: usize = 40;
/// Assets are re-sent in full at least this often even if nothing changed, so a
/// dashboard's "last seen" never goes stale.
const FULL_SNAPSHOT_EVERY: i64 = 6 * 3600;
/// Trend samples are only exported once they are this old: the collector may
/// still be rewriting the newest one.
const METRIC_LAG: i64 = 600;

#[derive(Clone, Debug)]
pub struct SinkConfig {
    /// Base URL of OpenObserve, e.g. `https://openobserve.example.com` (no path).
    pub url: String,
    pub org: String,
    pub prefix: String,
    pub user: String,
    pub password: String,
    pub interval: Duration,
}

/// What the UI shows about the export.
#[derive(Clone, Debug, Default, Serialize)]
pub struct ExportStatus {
    pub target: String,
    pub last_ok: Option<i64>,
    pub last_error: Option<String>,
    /// Documents accepted since start.
    pub sent: u64,
}

pub struct Sink {
    cfg: SinkConfig,
    agent: ureq::Agent,
    auth: String,
    /// asset id -> hash of what was last exported for it.
    asset_hashes: Mutex<HashMap<i64, u64>>,
    last_full_snapshot: Mutex<i64>,
    pub status: Arc<Mutex<ExportStatus>>,
}

impl SinkConfig {
    /// Refuse nonsense early, with a message that says what to fix.
    pub fn validate(&self) -> Result<()> {
        let u = &self.url;
        if !(u.starts_with("http://") || u.starts_with("https://")) {
            bail!("the OpenObserve URL must start with http:// or https://");
        }
        if u.contains('?') || u.contains('#') || u.contains('@') {
            bail!("the OpenObserve URL must be just the server address (no user name, query or fragment)");
        }
        let ok = |s: &str| !s.is_empty() && s.len() <= 64 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
        if !ok(&self.org) {
            bail!("the OpenObserve organisation may contain only letters, digits, - and _");
        }
        if !ok(&self.prefix) {
            bail!("the stream prefix may contain only letters, digits, - and _");
        }
        if self.user.is_empty() || self.password.is_empty() {
            bail!("set DENIS_OPENOBSERVE_USER and DENIS_OPENOBSERVE_PASSWORD (credentials are read from the environment only)");
        }
        Ok(())
    }

    /// Is this an unencrypted connection to somewhere other than this machine?
    pub fn cleartext_remote(&self) -> bool {
        let Some(rest) = self.url.strip_prefix("http://") else { return false };
        let host = rest.split(['/', ':']).next().unwrap_or("");
        !(host == "localhost" || host == "127.0.0.1" || host == "[::1]")
    }
}

impl Sink {
    pub fn new(cfg: SinkConfig) -> Result<Self> {
        cfg.validate()?;
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(30)))
            .build()
            .into();
        let auth = format!("Basic {}", crate::report::base64(format!("{}:{}", cfg.user, cfg.password).as_bytes()));
        let target = format!("{} (org {})", cfg.url.trim_end_matches('/'), cfg.org);
        Ok(Sink {
            cfg,
            agent,
            auth,
            asset_hashes: Mutex::new(HashMap::new()),
            last_full_snapshot: Mutex::new(0),
            status: Arc::new(Mutex::new(ExportStatus { target, ..Default::default() })),
        })
    }

    pub fn interval(&self) -> Duration {
        self.cfg.interval
    }

    fn stream(&self, name: &str) -> String {
        format!("{}_{name}", self.cfg.prefix)
    }

    /// POST one batch. Returns the number of documents the server refused.
    fn post(&self, stream: &str, docs: &[Value]) -> Result<u64> {
        let url = format!("{}/api/{}/{}/_json", self.cfg.url.trim_end_matches('/'), self.cfg.org, stream);
        let mut resp = self
            .agent
            .post(&url)
            .header("Authorization", &self.auth)
            .send_json(docs)
            // The error text never contains the Authorization header.
            .with_context(|| format!("posting {} document(s) to stream {stream}", docs.len()))?;
        // OpenObserve answers 200 with per-stream counts; a non-zero `failed` means
        // some documents were refused (schema clash, too old…). Retrying would
        // refuse them forever, so count them, warn and move on.
        let body: Value = resp.body_mut().read_json().unwrap_or(Value::Null);
        let failed = body["status"]
            .as_array()
            .map(|a| a.iter().map(|s| s["failed"].as_u64().unwrap_or(0)).sum())
            .unwrap_or(0);
        if failed > 0 {
            tracing::warn!("OpenObserve refused {failed} of {} document(s) for {stream}", docs.len());
        }
        Ok(failed)
    }

    fn cursor(store: &dyn Store, key: &str) -> Result<i64> {
        Ok(store
            .get_setting(&format!("sink.cursor.{key}"))?
            .and_then(|b| String::from_utf8(b).ok()?.parse().ok())
            .unwrap_or(0))
    }

    fn set_cursor(store: &dyn Store, key: &str, v: i64, now: i64) -> Result<()> {
        store.set_setting(&format!("sink.cursor.{key}"), v.to_string().as_bytes(), now)
    }

    /// One export cycle. Streams already sent before an error keep their progress.
    /// Returns how many documents were accepted.
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
        let names = AssetNames::load(store)?;
        let mut sent = 0u64;

        // ---- events
        let stream = self.stream("events");
        for _ in 0..MAX_BATCHES_PER_CYCLE {
            let after = Self::cursor(store, "events")?;
            let batch = store.events_after(after, BATCH)?;
            let Some(last) = batch.last().map(|e| e.id) else { break };
            let docs: Vec<Value> = batch.iter().map(|e| event_doc(e, &names)).collect();
            self.post(&stream, &docs)?;
            Self::set_cursor(store, "events", last, now)?;
            sent += docs.len() as u64;
            if batch.len() < BATCH {
                break;
            }
        }

        // ---- audit
        let stream = self.stream("audit");
        for _ in 0..MAX_BATCHES_PER_CYCLE {
            let after = Self::cursor(store, "audit")?;
            let batch = store.audit_after(after, BATCH)?;
            let Some(last) = batch.last().map(|e| e.id) else { break };
            let docs: Vec<Value> = batch.iter().map(|a| audit_doc(a, &names)).collect();
            self.post(&stream, &docs)?;
            Self::set_cursor(store, "audit", last, now)?;
            sent += docs.len() as u64;
            if batch.len() < BATCH {
                break;
            }
        }

        // ---- trend samples (by time, complete samples only)
        let stream = self.stream("metrics");
        let after = Self::cursor(store, "metrics")?;
        let samples = store.list_metrics(after + 1, now - METRIC_LAG, None)?;
        for chunk in samples.chunks(BATCH).take(MAX_BATCHES_PER_CYCLE) {
            let docs: Vec<Value> = chunk
                .iter()
                .map(|m| {
                    json!({
                        "_timestamp": m.ts * 1_000_000, "ts": m.ts,
                        "agent_id": if m.agent_id.is_empty() { "local" } else { m.agent_id.as_str() },
                        "devices_total": m.devices_total, "devices_online": m.devices_online,
                        "bytes_out": m.bytes_out, "bytes_in": m.bytes_in, "alerts": m.alerts,
                    })
                })
                .collect();
            self.post(&stream, &docs)?;
            if let Some(m) = chunk.last() {
                Self::set_cursor(store, "metrics", m.ts, now)?;
            }
            sent += docs.len() as u64;
        }

        // ---- asset inventory: what changed, plus a full snapshot now and then
        let stream = self.stream("assets");
        let full = now - *self.last_full_snapshot.lock().unwrap_or_else(|e| e.into_inner()) >= FULL_SNAPSHOT_EVERY;
        let mut docs = Vec::new();
        let mut hashes = Vec::new();
        for a in &names.assets {
            let meta = names.metas.get(&a.id);
            let doc = asset_doc(a, meta, now);
            let h = fingerprint_of(&doc);
            if full || self.asset_hashes.lock().unwrap_or_else(|e| e.into_inner()).get(&a.id) != Some(&h) {
                docs.push(doc);
                hashes.push((a.id, h));
            }
        }
        for (chunk, hs) in docs.chunks(BATCH).zip(hashes.chunks(BATCH)) {
            self.post(&stream, chunk)?;
            let mut map = self.asset_hashes.lock().unwrap_or_else(|e| e.into_inner());
            for (id, h) in hs {
                map.insert(*id, *h);
            }
            sent += chunk.len() as u64;
        }
        if full && !docs.is_empty() {
            *self.last_full_snapshot.lock().unwrap_or_else(|e| e.into_inner()) = now;
        }
        Ok(sent)
    }
}

/// Hash of an asset document ignoring the volatile fields, so "changed" means
/// a real change and not merely "seen again".
fn fingerprint_of(doc: &Value) -> u64 {
    let mut d = doc.clone();
    if let Some(o) = d.as_object_mut() {
        for k in ["_timestamp", "last_seen"] {
            o.remove(k);
        }
    }
    let mut h = DefaultHasher::new();
    d.to_string().hash(&mut h);
    h.finish()
}

/// Names for asset ids, so an alert in the dashboard says which device it is
/// about without a join.
struct AssetNames {
    assets: Vec<Asset>,
    metas: HashMap<i64, AssetMeta>,
}

impl AssetNames {
    fn load(store: &dyn Store) -> Result<Self> {
        Ok(AssetNames { assets: store.load_assets()?, metas: store.load_all_meta()? })
    }

    fn describe(&self, id: i64) -> (Option<String>, Option<String>, Option<String>) {
        let Some(a) = self.assets.iter().find(|a| a.id == id) else { return (None, None, None) };
        let name = self
            .metas
            .get(&id)
            .and_then(|m| m.display_name.clone())
            .or_else(|| a.hostnames.first().cloned());
        (name, a.current_ip().map(|i| i.to_string()), Some(a.mac.to_string()))
    }
}

fn event_doc(e: &crate::model::Event, names: &AssetNames) -> Value {
    let (name, ip, mac) = names.describe(e.asset_id);
    json!({
        "_timestamp": e.timestamp * 1_000_000, "ts": e.timestamp,
        "id": e.id, "kind": e.kind, "severity": e.severity, "score": e.score, "acked": e.acked,
        "agent_id": e.agent_id, "asset_id": e.asset_id,
        "asset_name": name, "asset_ip": ip, "asset_mac": mac,
        "summary": e.raw_details["summary"], "details": e.raw_details,
    })
}

fn audit_doc(a: &crate::model::AuditEntry, names: &AssetNames) -> Value {
    let (name, ..) = a.asset_id.map(|i| names.describe(i)).unwrap_or((None, None, None));
    json!({
        "_timestamp": a.ts * 1_000_000, "ts": a.ts,
        "id": a.id, "user": a.user, "action": a.action, "asset_id": a.asset_id, "asset_name": name, "details": a.detail,
    })
}

fn asset_doc(a: &Asset, meta: Option<&AssetMeta>, now: i64) -> Value {
    let m = meta.cloned().unwrap_or_default();
    json!({
        "_timestamp": now * 1_000_000,
        "id": a.id, "agent_id": a.agent_id, "mac": a.mac.to_string(),
        "ip": a.current_ip().map(|i| i.to_string()),
        "name": m.display_name.clone().or_else(|| a.hostnames.first().cloned()),
        "hostnames": a.hostnames,
        "vendor": m.manufacturer.clone().or_else(|| a.vendor.clone()),
        "device_type": m.type_override.clone().unwrap_or_else(|| a.device_type.clone()),
        "os": m.os_override.clone().or_else(|| a.os_guess.clone()),
        "open_ports": a.open_ports.iter().map(|p| p.port).collect::<Vec<_>>(),
        "is_gateway": a.is_gateway, "randomized_mac": a.randomized_mac,
        "first_seen": a.first_seen, "last_seen": a.last_seen,
        "serial_number": m.serial_number, "asset_tag": m.asset_tag, "model": m.model,
        "owner": m.owner, "department": m.department, "location": m.location,
        "status": m.status, "criticality": m.criticality, "zone": m.zone, "purdue_level": m.purdue_level,
        "warranty_expires": m.warranty_expires, "tags": m.tags,
    })
}

/// Run the exporter until the task is aborted. Errors are logged (once per
/// distinct message, so an outage does not fill the log) and retried next cycle.
pub async fn run(sink: Arc<Sink>, store: Arc<dyn Store>) {
    let mut last_err = String::new();
    loop {
        let (s, st) = (sink.clone(), store.clone());
        let now = crate::model::now_ts();
        match tokio::task::spawn_blocking(move || s.sync_once(&*st, now)).await {
            Ok(Ok(n)) => {
                if !last_err.is_empty() {
                    tracing::info!("OpenObserve export recovered");
                    last_err.clear();
                }
                if n > 0 {
                    tracing::debug!("exported {n} document(s) to OpenObserve");
                }
            }
            Ok(Err(e)) => {
                let msg = format!("{e:#}");
                if msg != last_err {
                    tracing::warn!("OpenObserve export failed (will retry): {msg}");
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
    use crate::model::{Event, Mac};
    use crate::store::sqlite::SqliteStore;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicU16, Ordering};

    /// A tiny fake OpenObserve: records `(path, authorization, body)` and answers
    /// with whatever status `status` currently holds.
    struct Fake {
        url: String,
        seen: Arc<Mutex<Vec<(String, String, Value)>>>,
        status: Arc<AtomicU16>,
    }

    fn fake() -> Fake {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let status = Arc::new(AtomicU16::new(200));
        let (s2, st2) = (seen.clone(), status.clone());
        std::thread::spawn(move || {
            for conn in l.incoming() {
                let Ok(mut c) = conn else { return };
                let mut buf = Vec::new();
                let mut chunk = [0u8; 8192];
                let (head_end, len) = loop {
                    let n = c.read(&mut chunk).unwrap_or(0);
                    if n == 0 {
                        break (0, 0);
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..p]).to_lowercase();
                        let len = head.lines().find_map(|l| l.strip_prefix("content-length:")).and_then(|v| v.trim().parse().ok()).unwrap_or(0usize);
                        break (p + 4, len);
                    }
                };
                while buf.len() < head_end + len {
                    let n = c.read(&mut chunk).unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
                let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
                let path = head.split_whitespace().nth(1).unwrap_or("").to_string();
                let auth = head.lines().find_map(|l| l.strip_prefix("authorization: ").or_else(|| l.strip_prefix("Authorization: "))).unwrap_or("").trim().to_string();
                let body: Value = serde_json::from_slice(&buf[head_end..]).unwrap_or(Value::Null);
                let code = st2.load(Ordering::SeqCst);
                if code == 200 {
                    s2.lock().unwrap_or_else(|e| e.into_inner()).push((path, auth, body));
                }
                let payload = if code == 200 { r#"{"code":200,"status":[{"name":"x","successful":1,"failed":0}]}"# } else { "{}" };
                let _ = write!(c, "HTTP/1.1 {code} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}", payload.len());
            }
        });
        Fake { url, seen, status }
    }

    fn cfg(url: &str) -> SinkConfig {
        SinkConfig { url: url.into(), org: "default".into(), prefix: "denis".into(), user: "root@example.com".into(), password: "s3cret-pw".into(), interval: Duration::from_secs(10) }
    }

    fn store_with_event() -> (SqliteStore, i64) {
        let s = SqliteStore::open_in_memory().unwrap();
        let mut a = Asset::new(Mac([2, 0, 0, 0, 0, 1]), 100);
        s.save_asset(&mut a).unwrap();
        let mut e = Event {
            id: 0, agent_id: None, asset_id: a.id, kind: "new_port".into(), timestamp: 1_000, severity: "high".into(), score: 70,
            acked: false, raw_details: json!({"summary": "port 23 opened"}),
        };
        s.insert_event(&mut e).unwrap();
        (s, a.id)
    }

    #[test]
    fn events_go_to_the_right_stream_with_basic_auth_and_microsecond_timestamps() {
        let f = fake();
        let sink = Sink::new(cfg(&f.url)).unwrap();
        let (s, _) = store_with_event();
        let n = sink.sync_once(&s, 5_000).unwrap();
        assert!(n >= 2, "the event and the asset inventory");
        let seen = f.seen.lock().unwrap_or_else(|e| e.into_inner());
        let (path, auth, body) = seen.iter().find(|(p, ..)| p.ends_with("denis_events/_json")).expect("events posted");
        assert_eq!(path, "/api/default/denis_events/_json");
        assert_eq!(auth, &format!("Basic {}", crate::report::base64(b"root@example.com:s3cret-pw")));
        let d = &body[0];
        assert_eq!(d["_timestamp"], 1_000_000_000i64);
        assert_eq!(d["kind"], "new_port");
        assert_eq!(d["summary"], "port 23 opened");
        assert_eq!(d["asset_mac"], "02:00:00:00:00:01");
        assert!(seen.iter().any(|(p, ..)| p.ends_with("denis_assets/_json")));
    }

    #[test]
    fn a_failed_post_keeps_the_cursor_and_the_next_cycle_resends_then_stops_resending() {
        let f = fake();
        let sink = Sink::new(cfg(&f.url)).unwrap();
        let (s, _) = store_with_event();
        f.status.store(500, Ordering::SeqCst);
        assert!(sink.sync_once(&s, 5_000).is_err());
        assert!(sink.status.lock().unwrap_or_else(|e| e.into_inner()).last_error.is_some());
        assert!(f.seen.lock().unwrap_or_else(|e| e.into_inner()).is_empty());
        f.status.store(200, Ordering::SeqCst);
        sink.sync_once(&s, 5_010).unwrap();
        let count = |f: &Fake| f.seen.lock().unwrap_or_else(|e| e.into_inner()).iter().filter(|(p, ..)| p.contains("denis_events")).count();
        assert_eq!(count(&f), 1, "the event arrived after the outage");
        assert!(sink.status.lock().unwrap_or_else(|e| e.into_inner()).last_error.is_none());
        sink.sync_once(&s, 5_020).unwrap();
        assert_eq!(count(&f), 1, "nothing new -> nothing resent");
        // a new event is the only thing that goes out next
        let mut e = Event { id: 0, agent_id: None, asset_id: 1, kind: "volume".into(), timestamp: 2_000, severity: "medium".into(), score: 40, acked: false, raw_details: json!({}) };
        s.insert_event(&mut e).unwrap();
        sink.sync_once(&s, 5_030).unwrap();
        assert_eq!(count(&f), 2);
        let seen = f.seen.lock().unwrap_or_else(|e| e.into_inner());
        let last = seen.iter().rev().find(|(p, ..)| p.contains("denis_events")).unwrap();
        assert_eq!(last.2.as_array().unwrap().len(), 1);
        assert_eq!(last.2[0]["kind"], "volume");
    }

    #[test]
    fn a_restart_resumes_from_the_stored_cursor() {
        let f = fake();
        let (s, _) = store_with_event();
        Sink::new(cfg(&f.url)).unwrap().sync_once(&s, 5_000).unwrap();
        let before = f.seen.lock().unwrap_or_else(|e| e.into_inner()).iter().filter(|(p, ..)| p.contains("denis_events")).count();
        Sink::new(cfg(&f.url)).unwrap().sync_once(&s, 5_010).unwrap(); // a fresh process
        let after = f.seen.lock().unwrap_or_else(|e| e.into_inner()).iter().filter(|(p, ..)| p.contains("denis_events")).count();
        assert_eq!(before, after, "events are not sent again after a restart");
    }

    #[test]
    fn unchanged_assets_are_not_resent_until_the_periodic_snapshot() {
        let f = fake();
        let sink = Sink::new(cfg(&f.url)).unwrap();
        let (s, _) = store_with_event();
        let assets = |f: &Fake| f.seen.lock().unwrap_or_else(|e| e.into_inner()).iter().filter(|(p, ..)| p.contains("denis_assets")).count();
        sink.sync_once(&s, 5_000).unwrap();
        assert_eq!(assets(&f), 1);
        sink.sync_once(&s, 5_060).unwrap();
        assert_eq!(assets(&f), 1, "nothing changed");
        let m = AssetMeta { owner: Some("Ann".into()), ..Default::default() };
        s.save_meta(1, &m, "t", 5_070).unwrap();
        sink.sync_once(&s, 5_080).unwrap();
        assert_eq!(assets(&f), 2, "an edit is exported at once");
        sink.sync_once(&s, 5_080 + FULL_SNAPSHOT_EVERY).unwrap();
        assert_eq!(assets(&f), 3, "and a full snapshot follows later");
    }

    #[test]
    fn the_configuration_is_validated_and_secrets_never_reach_the_status_or_errors() {
        for bad in [
            SinkConfig { url: "ftp://x".into(), ..cfg("") },
            SinkConfig { url: "http://u:p@host".into(), ..cfg("") },
            SinkConfig { url: "http://host/?x=1".into(), ..cfg("") },
            SinkConfig { org: "../x".into(), ..cfg("http://h") },
            SinkConfig { prefix: "a b".into(), ..cfg("http://h") },
            SinkConfig { password: String::new(), ..cfg("http://h") },
        ] {
            assert!(bad.validate().is_err(), "{bad:?}");
        }
        assert!(cfg("https://o.example.com").validate().is_ok());
        assert!(cfg("http://10.0.0.5:5080").cleartext_remote());
        assert!(!cfg("http://127.0.0.1:5080").cleartext_remote());
        assert!(!cfg("https://o.example.com").cleartext_remote());
        // an unreachable server: the recorded error must not contain the password
        let sink = Sink::new(cfg("http://127.0.0.1:1")).unwrap();
        let (s, _) = store_with_event();
        let e = format!("{:#}", sink.sync_once(&s, 5_000).unwrap_err());
        assert!(!e.contains("s3cret-pw") && !e.contains("Basic "), "{e}");
    }
}
