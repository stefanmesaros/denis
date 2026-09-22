//! Master side of the agent protocol: validate a `Report`, upsert its assets
//! under the agent's id, feed its flows to the detector.
//!
//! This listener is separate from the operator UI on purpose: it is the only
//! thing meant to be reachable from other machines. Every request needs a
//! bearer token issued *for one specific agent id* (`auth::issue_agent_token`):
//! a stolen token can neither impersonate another agent nor be recovered from
//! the database (only its SHA-256 is stored), and can be revoked individually.
//! Repeated bad tokens from one address are throttled.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::Context;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Extension, Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};

use crate::auth::Auth;
use crate::detect::Detector;
use crate::model::{now_ts, AgentInfo, Asset, Report, ReportAck};
use crate::notify::Alerts;
use crate::store::Store;

pub const MAX_ASSETS: usize = 5_000;
pub const MAX_FLOWS: usize = 100_000;
pub const MAX_SIGNALS: usize = 10_000;
pub const MAX_CONVS: usize = 20_000;
const MAX_BODY: usize = 32 * 1024 * 1024;

#[derive(Debug)]
pub enum IngestError {
    BadRequest(String),
    Internal(anyhow::Error),
}

impl From<anyhow::Error> for IngestError {
    fn from(e: anyhow::Error) -> Self {
        IngestError::Internal(e)
    }
}

pub struct Ingest {
    store: Arc<dyn Store>,
    detector: Arc<Mutex<Detector>>,
    alerts: Arc<Alerts>,
    auth: Arc<Auth>,
    /// address -> (bad tokens in the current window, window start)
    failures: Mutex<HashMap<IpAddr, (u32, i64)>>,
    /// Reports are applied one at a time: simple, and plenty for this scale.
    apply_lock: Mutex<()>,
    /// Where an agent's own backups (see `--backup-upstream` on their side) are kept: one
    /// subfolder per agent id, under the master's own `backups` folder. `None` disables receiving
    /// them at all (the route still exists, but every upload is refused).
    agent_backups_dir: Option<PathBuf>,
}

/// The agent id a request's token was issued for.
#[derive(Clone)]
pub struct AgentIdentity(pub String);

/// More than this many bad tokens per window from one address are refused.
const MAX_FAILURES: u32 = 10;
const FAILURE_WINDOW_SECS: i64 = 60;

impl Ingest {
    pub fn new(
        store: Arc<dyn Store>,
        detector: Arc<Mutex<Detector>>,
        alerts: Arc<Alerts>,
        auth: Arc<Auth>,
        agent_backups_dir: Option<PathBuf>,
    ) -> Self {
        Ingest {
            store,
            detector,
            alerts,
            auth,
            failures: Mutex::new(HashMap::new()),
            apply_lock: Mutex::new(()),
            agent_backups_dir,
        }
    }

    /// Write one agent's uploaded backup under its own subfolder, named the way `backups::create`
    /// names local ones so the Health page can list and prune them the same way. Refuses an id
    /// with anything that could escape the folder (already validated by `validate()` for reports,
    /// but this path is reached before that, so it is re-checked here too).
    fn store_agent_backup(&self, agent_id: &str, bytes: &[u8]) -> anyhow::Result<String> {
        let dir = self.agent_backups_dir.as_deref().context("no --backup-upstream-dir configured on this master")?;
        let id_ok = !agent_id.is_empty() && agent_id.len() <= 64 && agent_id.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
        anyhow::ensure!(id_ok, "bad agent id");
        let site_dir = dir.join(agent_id);
        std::fs::create_dir_all(&site_dir)?;
        let stamp = crate::report::iso(now_ts()).replace(['-', ':'], "");
        let name = format!("denis-auto-{stamp}.db");
        let tmp = site_dir.join(format!(".{name}.part"));
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(&tmp, site_dir.join(&name))?;
        Ok(name)
    }

    /// Seconds an address must wait, or 0 if it may try.
    fn throttled(&self, ip: IpAddr, now: i64) -> i64 {
        let m = self.failures.lock().unwrap();
        m.get(&ip)
            .filter(|(n, start)| *n >= MAX_FAILURES && now - start < FAILURE_WINDOW_SECS)
            .map_or(0, |(_, start)| FAILURE_WINDOW_SECS - (now - start))
    }

    fn note_failure(&self, ip: IpAddr, now: i64) {
        let mut m = self.failures.lock().unwrap();
        if m.len() > 10_000 {
            m.retain(|_, (_, start)| now - *start < FAILURE_WINDOW_SECS);
        }
        let e = m.entry(ip).or_insert((0, now));
        if now - e.1 >= FAILURE_WINDOW_SECS {
            *e = (0, now);
        }
        e.0 += 1;
    }

    pub fn apply(&self, report: Report, now: i64) -> Result<ReportAck, IngestError> {
        validate(&report)?;
        let _guard = self.apply_lock.lock().unwrap();
        let id = report.agent.id.clone();
        let prev = self.store.get_agent(&id)?;

        // An exact replay of a batch we already applied (the agent retried after
        // a lost response): acknowledge, don't double-count its flows.
        if let Some(p) = &prev {
            if p.last_run_id == report.run_id && report.seq <= p.last_seq {
                let mut touched = p.clone();
                touched.last_report_at = now;
                self.store.upsert_agent(&touched)?;
                return Ok(ReportAck {
                    seq: report.seq,
                    assets: 0,
                    flows: 0,
                    duplicate: true,
                });
            }
        }
        let first_seen = prev.as_ref().map_or(now, |p| p.first_seen);
        self.detector
            .lock()
            .unwrap()
            .set_learning_start(Some(&id), first_seen);

        let mut new_assets: Vec<Asset> = Vec::new();
        let n_assets = report.assets.len();
        for mut a in report.assets {
            clamp_asset(&mut a);
            a.agent_id = Some(id.clone());
            match self.store.find_asset(Some(&id), &a.mac)? {
                Some(existing) => {
                    a.id = existing.id;
                    a.first_seen = a.first_seen.min(existing.first_seen);
                    self.store.save_asset(&mut a)?;
                }
                None => {
                    a.id = 0;
                    self.store.save_asset(&mut a)?;
                    // A device somebody registered by hand is known, not "new".
                    let registered = self.store.get_meta(a.id)?.is_some_and(|m| m.manual);
                    if !registered {
                        new_assets.push(a);
                    }
                }
            }
        }

        let n_flows = report.flows.len();
        let mut events = Vec::new();
        {
            let mut det = self.detector.lock().unwrap();
            for a in &new_assets {
                events.extend(det.on_new_asset(a, now));
            }
            events.extend(det.ingest_flows(Some(&id), &report.flows, &*self.store, now));
            events.extend(det.ingest_signals(Some(&id), &report.signals, &*self.store, now));
            events.extend(det.ingest_conversations(Some(&id), &report.conversations, &*self.store, now));
        }
        self.alerts.emit(events);

        // Recorded last: if we crashed above, the agent's retry re-applies the
        // batch (assets are idempotent; at worst one window of flows repeats).
        self.store.upsert_agent(&AgentInfo {
            id,
            name: report.agent.name,
            site: report.agent.site,
            version: report.agent.version,
            subnet: report.agent.subnet,
            first_seen,
            last_report_at: now,
            last_run_id: report.run_id,
            last_seq: report.seq,
        })?;
        Ok(ReportAck {
            seq: report.seq,
            assets: n_assets,
            flows: n_flows,
            duplicate: false,
        })
    }
}

fn validate(r: &Report) -> Result<(), IngestError> {
    let bad = |m: &str| Err(IngestError::BadRequest(m.to_string()));
    let id_ok = !r.agent.id.is_empty()
        && r.agent.id.len() <= 64
        && r.agent.id.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if !id_ok {
        return bad("agent id must be 1-64 characters of [A-Za-z0-9._-]");
    }
    if r.agent.name.len() > 128 || r.agent.site.as_ref().is_some_and(|s| s.len() > 128) || r.run_id.len() > 64 {
        return bad("name/site/run_id too long");
    }
    if r.assets.len() > MAX_ASSETS || r.flows.len() > MAX_FLOWS || r.signals.len() > MAX_SIGNALS || r.conversations.len() > MAX_CONVS {
        return bad("report too large");
    }
    if r.assets.iter().any(|a| !a.mac.is_valid())
        || r.flows.iter().any(|f| !f.mac.is_valid())
        || r.signals.iter().any(|s| !s.mac.is_valid())
        || r.conversations.iter().any(|c| !c.client_mac.is_valid() || !c.server_mac.is_valid()) {
        return bad("invalid MAC address in report");
    }
    Ok(())
}

/// Bound list sizes so one misbehaving agent can't bloat the database.
fn clamp_asset(a: &mut Asset) {
    a.ip_history.sort_by_key(|r| std::cmp::Reverse(r.last_seen));
    a.ip_history.truncate(20);
    a.hostnames.truncate(8);
    a.open_ports.truncate(128);
    a.guess_reasons.truncate(64);
    let f = &mut a.fingerprint;
    f.mdns_services.truncate(16);
    f.mdns_names.truncate(16);
    f.mdns_models.truncate(16);
    f.ssdp_types.truncate(12);
}

// ---------------------------------------------------------------- HTTP

/// Generous: a whole SQLite database, not a report. Still bounded so one agent cannot fill the disk.
const MAX_BACKUP_BYTES: usize = 500 * 1024 * 1024;

pub fn router(ingest: Arc<Ingest>) -> Router {
    let reports = Router::new().route("/api/v1/ping", get(ping)).route("/api/v1/report", post(report)).layer(DefaultBodyLimit::max(MAX_BODY));
    let backups = Router::new().route("/api/v1/backup", post(backup_upload)).layer(DefaultBodyLimit::max(MAX_BACKUP_BYTES));
    reports.merge(backups).layer(middleware::from_fn_with_state(ingest.clone(), auth)).with_state(ingest)
}

/// Bearer token -> agent identity, with per-address throttling of bad tokens.
async fn auth(State(ing): State<Arc<Ingest>>, mut req: Request, next: Next) -> Response {
    let now = now_ts();
    let ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map_or(IpAddr::from([0, 0, 0, 0]), |c| c.0.ip());
    let wait = ing.throttled(ip, now);
    if wait > 0 {
        let mut r = (StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!({"error": "too many failed attempts"}))).into_response();
        if let Ok(v) = axum::http::HeaderValue::from_str(&wait.to_string()) {
            r.headers_mut().insert(header::RETRY_AFTER, v);
        }
        return r;
    }
    let identity = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .and_then(|t| ing.auth.verify_agent_token(t, now));
    let Some(id) = identity else {
        ing.note_failure(ip, now);
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "unauthorized"}))).into_response();
    };
    req.extensions_mut().insert(AgentIdentity(id.agent_id));
    next.run(req).await
}

async fn ping() -> Json<serde_json::Value> {
    Json(serde_json::json!({"ok": true, "version": env!("CARGO_PKG_VERSION")}))
}

/// A customer's own scheduled backup, pushed here by their `--backup-upstream` (see
/// `backups::run`). Kept so this master's operator still has yesterday's device list if that
/// customer is hit by ransomware — outbound push only, same trust model as reporting itself.
async fn backup_upload(State(ing): State<Arc<Ingest>>, Extension(who): Extension<AgentIdentity>, body: axum::body::Bytes) -> Response {
    if body.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "empty body"}))).into_response();
    }
    let ok_header = &body[..body.len().min(16)];
    if !ok_header.starts_with(b"SQLite format 3\0") {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "not a SQLite database"}))).into_response();
    }
    match ing.store_agent_backup(&who.0, &body) {
        Ok(name) => {
            tracing::info!("received a backup from agent {}: {name} ({})", who.0, crate::health::human_bytes(body.len() as u64));
            (StatusCode::CREATED, Json(serde_json::json!({"ok": true, "name": name}))).into_response()
        }
        Err(e) => {
            tracing::warn!("could not store backup from agent {}: {e:#}", who.0);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "internal error"}))).into_response()
        }
    }
}

async fn report(State(ing): State<Arc<Ingest>>, Extension(who): Extension<AgentIdentity>, Json(report): Json<Report>) -> Response {
    // The token was issued for one agent id; it cannot speak for another.
    if report.agent.id != who.0 {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error": "this token is not valid for that agent id"}))).into_response();
    }
    let res = tokio::task::spawn_blocking(move || ing.apply(report, now_ts()))
        .await
        .context("ingest task panicked")
        .map_err(IngestError::from)
        .and_then(|r| r);
    match res {
        Ok(ack) => Json(ack).into_response(),
        Err(IngestError::BadRequest(m)) => {
            (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": m}))).into_response()
        }
        Err(IngestError::Internal(e)) => {
            tracing::error!("ingest failed: {e:#}");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "internal error"}))).into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::DetectConfig;
    use crate::model::{AgentMeta, FlowRecord, IpRecord, Mac};
    use crate::store::sqlite::SqliteStore;
    use crate::store::EventQuery;
    use axum::body::Body;
    use std::net::Ipv4Addr;
    use tower::ServiceExt;

    const M: Mac = Mac([0x3c, 0x22, 0xfb, 1, 2, 3]);

    fn setup(learning: i64) -> (Arc<Ingest>, Arc<dyn Store>) {
        setup_with(learning, None)
    }

    fn setup_with(learning: i64, agent_backups_dir: Option<PathBuf>) -> (Arc<Ingest>, Arc<dyn Store>) {
        let store: Arc<dyn Store> = Arc::new(SqliteStore::open_in_memory().unwrap());
        let cfg = DetectConfig { learning_secs: learning, settle_secs: 0, ..Default::default() };
        let det = Arc::new(Mutex::new(Detector::new(cfg, vec![], 0)));
        let alerts = Arc::new(Alerts::new(store.clone(), None));
        let auth = Arc::new(Auth::new(store.clone()));
        (Arc::new(Ingest::new(store.clone(), det, alerts, auth, agent_backups_dir)), store)
    }

    fn report(seq: u64, assets: Vec<Asset>, flows: Vec<FlowRecord>) -> Report {
        Report {
            agent: AgentMeta { id: "site-b".into(), name: "Office".into(), site: Some("HQ".into()), version: "0.2.0".into(), subnet: "10.1.0.0/24".into() },
            run_id: "run1".into(),
            seq,
            sent_at: 0,
            assets,
            flows,
            signals: vec![],
            conversations: vec![],
        }
    }

    fn asset(mac: Mac, ip: [u8; 4]) -> Asset {
        let mut a = Asset::new(mac, 100);
        a.id = 777; // agent-local ids must never leak into the master's table
        a.ip_history.push(IpRecord { ip: Ipv4Addr::from(ip), first_seen: 100, last_seen: 100 });
        a
    }

    fn flow(ts: i64, remote: [u8; 4]) -> FlowRecord {
        FlowRecord { mac: M, remote: Ipv4Addr::from(remote), proto: 6, port: 443, bytes_out: 1000, bytes_in: 1000, packets: 2, window_start: ts, window_secs: 10 }
    }

    #[test]
    fn report_upserts_assets_under_the_agent_and_registers_it() {
        let (ing, store) = setup(1000);
        let ack = ing.apply(report(1, vec![asset(M, [10, 1, 0, 5])], vec![]), 500).unwrap();
        assert_eq!((ack.assets, ack.duplicate), (1, false));
        let a = store.find_asset(Some("site-b"), &M).unwrap().unwrap();
        assert_ne!(a.id, 777);
        assert_eq!(a.agent_id.as_deref(), Some("site-b"));
        assert!(store.find_asset(None, &M).unwrap().is_none(), "not confused with the local collector");
        let ag = store.get_agent("site-b").unwrap().unwrap();
        assert_eq!((ag.first_seen, ag.last_report_at, ag.last_seq, ag.subnet.as_str()), (500, 500, 1, "10.1.0.0/24"));

        // A later report updates the same row and keeps the earliest first_seen.
        let mut again = asset(M, [10, 1, 0, 6]);
        again.first_seen = 300;
        ing.apply(report(2, vec![again], vec![]), 600).unwrap();
        let b = store.find_asset(Some("site-b"), &M).unwrap().unwrap();
        assert_eq!((b.id, b.first_seen, b.current_ip()), (a.id, 100, Some(Ipv4Addr::new(10, 1, 0, 6))));
        assert_eq!(store.load_assets().unwrap().len(), 1);
        assert_eq!(store.get_agent("site-b").unwrap().unwrap().first_seen, 500);
    }

    #[test]
    fn a_replayed_batch_is_acknowledged_but_not_double_counted() {
        let (ing, store) = setup(0);
        // learning 0 -> destinations are judged immediately; make baselines observable
        ing.apply(report(1, vec![asset(M, [10, 1, 0, 5])], vec![flow(0, [1, 1, 1, 1])]), 20).unwrap();
        let id = store.find_asset(Some("site-b"), &M).unwrap().unwrap().id;
        let bytes = |_: &Arc<dyn Store>| ing.detector.lock().unwrap().baseline(id).unwrap().typical_destinations["1.1.1.1"].bytes;
        assert_eq!(bytes(&store), 2000);
        let dup = ing.apply(report(1, vec![], vec![flow(0, [1, 1, 1, 1])]), 30).unwrap();
        assert!(dup.duplicate);
        assert_eq!(bytes(&store), 2000, "replay must not add bytes");
        // a new run resets the sequence
        let mut r = report(1, vec![], vec![flow(10, [1, 1, 1, 1])]);
        r.run_id = "run2".into();
        assert!(!ing.apply(r, 40).unwrap().duplicate);
        assert_eq!(bytes(&store), 4000);
        // and the replay of run2/seq1 is again ignored
        let mut r = report(1, vec![], vec![flow(10, [1, 1, 1, 1])]);
        r.run_id = "run2".into();
        assert!(ing.apply(r, 50).unwrap().duplicate);
    }

    #[test]
    fn remote_flows_drive_the_same_rules_and_alerts_carry_the_agent_id() {
        let (ing, store) = setup(1000);
        ing.apply(report(1, vec![asset(M, [10, 1, 0, 5])], vec![flow(0, [1, 1, 1, 1])]), 10).unwrap();
        ing.apply(report(2, vec![], vec![flow(2000, [8, 8, 4, 4])]), 2010).unwrap();
        let alerts = store.list_events(&EventQuery { alerts_only: true, ..Default::default() }).unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].kind, "new_destination");
        assert_eq!(alerts[0].agent_id.as_deref(), Some("site-b"));
    }

    #[test]
    fn signals_from_agents_become_scored_alerts_and_old_agents_without_them_still_parse() {
        use crate::model::Signal;
        let (ing, store) = setup(1000);
        let other = Mac([0x00, 0x11, 0x22, 3, 3, 3]);
        let mut a = asset(M, [10, 1, 0, 5]);
        a.first_seen = 50;
        let mut victim = asset(other, [10, 1, 0, 1]);
        victim.first_seen = 50;
        ing.apply(report(1, vec![a, victim], vec![]), 60).unwrap();
        let mut r = report(2, vec![], vec![]);
        r.signals = vec![Signal { kind: "arp_conflict".into(), ts: 70, mac: M, ip: Ipv4Addr::new(10, 1, 0, 1), other_mac: Some(other), gateway: true }];
        ing.apply(r, 70).unwrap();
        let alerts = store.list_events(&EventQuery { alerts_only: true, ..Default::default() }).unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!((alerts[0].kind.as_str(), alerts[0].score, alerts[0].severity.as_str()), ("arp_conflict", 95, "high"));
        assert_eq!(alerts[0].agent_id.as_deref(), Some("site-b"));
        // a Phase 2 agent's report has no "signals" key at all
        let old = serde_json::json!({
            "agent": {"id": "old", "name": "old", "site": null, "version": "0.1", "subnet": "10.0.0.0/24"},
            "run_id": "r", "seq": 1, "sent_at": 0, "assets": [], "flows": []
        });
        let parsed: Report = serde_json::from_value(old).unwrap();
        assert!(parsed.signals.is_empty());
    }

    #[test]
    fn a_newly_enrolled_agent_gets_its_own_learning_period() {
        let (ing, store) = setup(1000);
        // The local collector's learning began at t=0, long ago, but this agent
        // enrolls at t=50_000 and its device is first seen then too.
        let mut a = asset(M, [10, 1, 0, 5]);
        a.first_seen = 50_000;
        ing.apply(report(1, vec![a], vec![]), 50_000).unwrap();
        let ev = store.list_events(&EventQuery::default()).unwrap();
        assert_eq!((ev.len(), ev[0].kind.as_str(), ev[0].severity.as_str()), (1, "new_device", "info"));
        assert!(store.list_events(&EventQuery { alerts_only: true, ..Default::default() }).unwrap().is_empty());
    }

    #[test]
    fn hostile_reports_are_rejected() {
        let (ing, _) = setup(0);
        let bad = |f: &dyn Fn(&mut Report)| {
            let mut r = report(1, vec![asset(M, [10, 1, 0, 5])], vec![]);
            f(&mut r);
            matches!(ing.apply(r, 1), Err(IngestError::BadRequest(_)))
        };
        assert!(bad(&|r| r.agent.id = "../etc".into()));
        assert!(bad(&|r| r.agent.id = "".into()));
        assert!(bad(&|r| r.agent.id = "x".repeat(65)));
        assert!(bad(&|r| r.assets[0].mac = Mac([0xff; 6])));
        assert!(bad(&|r| r.flows = vec![FlowRecord { mac: Mac([1, 0, 0, 0, 0, 1]), ..flow(0, [1, 1, 1, 1]) }]));
        assert!(bad(&|r| r.assets = (0..=MAX_ASSETS).map(|_| asset(M, [1, 1, 1, 1])).collect()));
    }

    async fn call(app: &Router, req: axum::http::Request<Body>) -> (StatusCode, serde_json::Value) {
        let resp = app.clone().oneshot(req).await.unwrap();
        let st = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        (st, serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null))
    }

    fn post_report(token: Option<&str>, body: &[u8]) -> axum::http::Request<Body> {
        let mut b = axum::http::Request::post("/api/v1/report").header("content-type", "application/json");
        if let Some(t) = token {
            b = b.header("authorization", t);
        }
        b.body(Body::from(body.to_vec())).unwrap()
    }

    #[tokio::test]
    async fn http_requires_a_token_issued_for_that_agent() {
        let (ing, store) = setup(1000);
        let token = ing.auth.issue_agent_token("site-b", "Branch", 1).unwrap();
        let other = ing.auth.issue_agent_token("site-c", "Other", 1).unwrap();
        let app = router(ing);
        let body = serde_json::to_vec(&report(1, vec![asset(M, [10, 1, 0, 5])], vec![])).unwrap();
        assert_eq!(call(&app, post_report(None, &body)).await.0, StatusCode::UNAUTHORIZED);
        assert_eq!(call(&app, post_report(Some("Bearer wrong"), &body)).await.0, StatusCode::UNAUTHORIZED);
        assert_eq!(call(&app, post_report(Some(&token), &body)).await.0, StatusCode::UNAUTHORIZED, "scheme required");
        assert!(store.list_agents().unwrap().is_empty(), "nothing applied when unauthorised");
        // a valid token for a DIFFERENT agent must not be able to speak for site-b
        let (st, v) = call(&app, post_report(Some(&format!("Bearer {other}")), &body)).await;
        assert_eq!(st, StatusCode::FORBIDDEN, "{v}");
        assert!(store.list_agents().unwrap().is_empty());
        let (st, v) = call(&app, post_report(Some(&format!("Bearer {token}")), &body)).await;
        assert_eq!((st, v["assets"].as_u64()), (StatusCode::OK, Some(1)));
        let ping = axum::http::Request::get("/api/v1/ping").header("authorization", format!("Bearer {token}")).body(Body::empty()).unwrap();
        assert_eq!(call(&app, ping).await.0, StatusCode::OK);
        let bad = axum::http::Request::post("/api/v1/report").header("authorization", format!("Bearer {token}")).header("content-type", "application/json").body(Body::from("{nope")).unwrap();
        assert!(call(&app, bad).await.0.is_client_error());
        // revoking the token cuts the agent off immediately
        store.revoke_agent_token("site-b").unwrap();
        assert_eq!(call(&app, post_report(Some(&format!("Bearer {token}")), &body)).await.0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a_customers_backup_is_stored_under_its_own_agent_id_only_with_a_valid_sqlite_header() {
        let dir = tempfile::tempdir().unwrap();
        let backups_dir = dir.path().join("from-agents");
        let (ing, _store) = setup_with(1000, Some(backups_dir.clone()));
        let token = ing.auth.issue_agent_token("site-b", "Branch", 1).unwrap();
        let other = ing.auth.issue_agent_token("site-c", "Other", 1).unwrap();
        let app = router(ing);
        let post = |token: &str, body: &'static [u8]| {
            axum::http::Request::post("/api/v1/backup").header("authorization", format!("Bearer {token}")).body(Body::from(body)).unwrap()
        };

        // not a SQLite file: refused, nothing written
        assert_eq!(call(&app, post(&token, b"not a database")).await.0, StatusCode::BAD_REQUEST);
        assert!(!backups_dir.join("site-b").exists());

        // a real (if tiny) SQLite header is accepted and lands under this agent's own folder
        let mut sqlite_bytes = b"SQLite format 3\0".to_vec();
        sqlite_bytes.extend([0u8; 100]);
        let (st, v) = call(&app, post(&token, Box::leak(sqlite_bytes.clone().into_boxed_slice()))).await;
        assert_eq!(st, StatusCode::CREATED, "{v}");
        let files: Vec<_> = std::fs::read_dir(backups_dir.join("site-b")).unwrap().collect();
        assert_eq!(files.len(), 1);
        assert_eq!(std::fs::read(files[0].as_ref().unwrap().path()).unwrap(), sqlite_bytes);

        // site-c's token cannot write into site-b's folder or vice versa: each writes its own
        let (st, _) = call(&app, post(&other, Box::leak(sqlite_bytes.clone().into_boxed_slice()))).await;
        assert_eq!(st, StatusCode::CREATED);
        assert!(backups_dir.join("site-c").exists());
        assert!(!backups_dir.join("site-c").join("does-not-leak-into-site-b").exists());
    }

    #[tokio::test]
    async fn repeated_bad_tokens_from_one_address_are_throttled() {
        let (ing, _) = setup(1000);
        let good = ing.auth.issue_agent_token("site-b", "Branch", 1).unwrap();
        let app = router(ing);
        let from = |t: &str| {
            let mut r = axum::http::Request::get("/api/v1/ping").header("authorization", format!("Bearer {t}")).body(Body::empty()).unwrap();
            r.extensions_mut().insert(ConnectInfo::<SocketAddr>("203.0.113.9:5000".parse().unwrap()));
            r
        };
        for _ in 0..MAX_FAILURES {
            assert_eq!(call(&app, from("bad")).await.0, StatusCode::UNAUTHORIZED);
        }
        // the address is now locked out, even with a correct token
        assert_eq!(call(&app, from(&good)).await.0, StatusCode::TOO_MANY_REQUESTS);
        // another address is unaffected
        let mut other = axum::http::Request::get("/api/v1/ping").header("authorization", format!("Bearer {good}")).body(Body::empty()).unwrap();
        other.extensions_mut().insert(ConnectInfo::<SocketAddr>("198.51.100.7:5000".parse().unwrap()));
        assert_eq!(call(&app, other).await.0, StatusCode::OK);
    }

}
