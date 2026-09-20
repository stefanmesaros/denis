//! Master side of the agent protocol: validate a `Report`, upsert its assets
//! under the agent's id, feed its flows to the detector.
//!
//! This listener is separate from the (unauthenticated, loopback) UI on purpose:
//! it is the only thing that is meant to be reachable from other machines, and
//! every request needs the shared bearer token.

use std::sync::{Arc, Mutex};

use anyhow::Context;
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};

use crate::detect::Detector;
use crate::model::{now_ts, AgentInfo, Asset, Report, ReportAck};
use crate::notify::Alerts;
use crate::store::Store;

pub const MAX_ASSETS: usize = 5_000;
pub const MAX_FLOWS: usize = 100_000;
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
    token: String,
    /// Reports are applied one at a time: simple, and plenty for this scale.
    apply_lock: Mutex<()>,
}

impl Ingest {
    pub fn new(
        store: Arc<dyn Store>,
        detector: Arc<Mutex<Detector>>,
        alerts: Arc<Alerts>,
        token: String,
    ) -> Self {
        Ingest {
            store,
            detector,
            alerts,
            token,
            apply_lock: Mutex::new(()),
        }
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
                    new_assets.push(a);
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
    if r.assets.len() > MAX_ASSETS || r.flows.len() > MAX_FLOWS {
        return bad("report too large");
    }
    if r.assets.iter().any(|a| !a.mac.is_valid()) || r.flows.iter().any(|f| !f.mac.is_valid()) {
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

pub fn router(ingest: Arc<Ingest>) -> Router {
    Router::new()
        .route("/api/v1/ping", get(ping))
        .route("/api/v1/report", post(report))
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .layer(middleware::from_fn_with_state(ingest.clone(), auth))
        .with_state(ingest)
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

async fn auth(State(ing): State<Arc<Ingest>>, req: Request, next: Next) -> Response {
    let ok = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .is_some_and(|t| ct_eq(t.as_bytes(), ing.token.as_bytes()));
    if !ok {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "unauthorized"}))).into_response();
    }
    next.run(req).await
}

async fn ping() -> Json<serde_json::Value> {
    Json(serde_json::json!({"ok": true, "version": env!("CARGO_PKG_VERSION")}))
}

async fn report(State(ing): State<Arc<Ingest>>, Json(report): Json<Report>) -> Response {
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
        let store: Arc<dyn Store> = Arc::new(SqliteStore::open_in_memory().unwrap());
        let cfg = DetectConfig { learning_secs: learning, settle_secs: 0, ..Default::default() };
        let det = Arc::new(Mutex::new(Detector::new(cfg, vec![], 0)));
        let alerts = Arc::new(Alerts::new(store.clone(), None));
        (Arc::new(Ingest::new(store.clone(), det, alerts, "s3cret".into())), store)
    }

    fn report(seq: u64, assets: Vec<Asset>, flows: Vec<FlowRecord>) -> Report {
        Report {
            agent: AgentMeta { id: "site-b".into(), name: "Office".into(), site: Some("HQ".into()), version: "0.2.0".into(), subnet: "10.1.0.0/24".into() },
            run_id: "run1".into(),
            seq,
            sent_at: 0,
            assets,
            flows,
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

    #[tokio::test]
    async fn http_requires_the_bearer_token() {
        let (ing, store) = setup(1000);
        let app = router(ing);
        let body = serde_json::to_vec(&report(1, vec![asset(M, [10, 1, 0, 5])], vec![])).unwrap();
        let post = |auth: Option<&str>| {
            let mut b = axum::http::Request::post("/api/v1/report").header("content-type", "application/json");
            if let Some(a) = auth {
                b = b.header("authorization", a);
            }
            b.body(Body::from(body.clone())).unwrap()
        };
        assert_eq!(call(&app, post(None)).await.0, StatusCode::UNAUTHORIZED);
        assert_eq!(call(&app, post(Some("Bearer wrong"))).await.0, StatusCode::UNAUTHORIZED);
        assert_eq!(call(&app, post(Some("s3cret"))).await.0, StatusCode::UNAUTHORIZED, "scheme required");
        assert!(store.list_agents().unwrap().is_empty(), "nothing applied when unauthorised");
        let (st, v) = call(&app, post(Some("Bearer s3cret"))).await;
        assert_eq!((st, v["assets"].as_u64()), (StatusCode::OK, Some(1)));
        let ping = axum::http::Request::get("/api/v1/ping").header("authorization", "Bearer s3cret").body(Body::empty()).unwrap();
        assert_eq!(call(&app, ping).await.0, StatusCode::OK);
        let bad = axum::http::Request::post("/api/v1/report").header("authorization", "Bearer s3cret").header("content-type", "application/json").body(Body::from("{nope")).unwrap();
        assert!(call(&app, bad).await.0.is_client_error());
    }

    #[test]
    fn constant_time_compare() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"abcd"));
        assert!(ct_eq(b"", b""));
    }
}
