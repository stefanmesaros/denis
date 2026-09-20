//! JSON API + embedded static UI.
//!
//! Phase 1 has no authentication (local-only use), so the defences here are the
//! ones that protect a localhost service from *the browser*: Host-header
//! validation (DNS rebinding), a custom header on state-changing requests (CSRF),
//! and a strict CSP (hostnames come from the network and are attacker-controlled).

use std::net::Ipv4Addr;
use std::sync::Arc;

use axum::extract::{Path, Query, Request, State};
use axum::http::{header, HeaderValue, StatusCode, Uri};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize};

use crate::engine::Shared;
use crate::model::Asset;
use crate::store::{EventQuery, Store};

#[derive(RustEmbed)]
#[folder = "ui/"]
struct Ui;

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<dyn Store>,
    pub shared: Arc<Shared>,
    /// Bound to a loopback address: enforce Host-header checking.
    pub loopback_only: bool,
}

pub async fn serve(listener: tokio::net::TcpListener, state: AppState) -> std::io::Result<()> {
    axum::serve(listener, router(state)).await
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/status", get(status))
        .route("/api/assets", get(assets))
        .route("/api/assets/{id}", get(asset))
        .route("/api/assets/{id}/baseline", get(baseline))
        .route("/api/events", get(events))
        .route("/api/alerts", get(alerts))
        .route("/api/alerts/{id}/ack", post(ack))
        .route("/api/alerts/{id}/unack", post(unack))
        .route("/api/agents", get(agents))
        .route("/api/scan", post(scan))
        .fallback(static_file)
        .layer(middleware::from_fn_with_state(state.clone(), guard))
        .with_state(state)
}

/// Host check (loopback binds only), CSRF header on POST, and response hardening.
async fn guard(State(st): State<AppState>, req: Request, next: Next) -> Response {
    if st.loopback_only {
        let host = req
            .headers()
            .get(header::HOST)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");
        let name = host
            .rsplit_once(':')
            .filter(|(_, port)| port.chars().all(|c| c.is_ascii_digit()))
            .map_or(host, |(n, _)| n);
        if !matches!(name, "localhost" | "127.0.0.1" | "[::1]") {
            return (StatusCode::FORBIDDEN, "unexpected Host header").into_response();
        }
    }
    if req.method() != axum::http::Method::GET && !req.headers().contains_key("x-netscope") {
        return (StatusCode::FORBIDDEN, "missing X-Netscope header").into_response();
    }
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'self'; frame-ancestors 'none'; base-uri 'none'"),
    );
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    resp
}

struct ApiError(anyhow::Error);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        tracing::error!("api error: {:#}", self.0);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "internal error"})),
        )
            .into_response()
    }
}

impl<E: Into<anyhow::Error>> From<E> for ApiError {
    fn from(e: E) -> Self {
        ApiError(e.into())
    }
}

/// Run a blocking store call off the async executor.
async fn blocking<T: Send + 'static>(
    store: &Arc<dyn Store>,
    f: impl FnOnce(&dyn Store) -> anyhow::Result<T> + Send + 'static,
) -> Result<T, ApiError> {
    let store = store.clone();
    Ok(tokio::task::spawn_blocking(move || f(&*store)).await??)
}

#[derive(Serialize)]
struct AssetView {
    #[serde(flatten)]
    asset: Asset,
    /// Convenience: the most recently seen IP.
    ip: Option<Ipv4Addr>,
}

impl From<Asset> for AssetView {
    fn from(asset: Asset) -> Self {
        let ip = asset.current_ip();
        AssetView { asset, ip }
    }
}

async fn status(State(st): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    let (count, unacked) = blocking(&st.store, |s| {
        let q = EventQuery { limit: 1000, alerts_only: true, unacked_only: true, ..Default::default() };
        Ok((s.load_assets()?.len(), s.list_events(&q)?.len()))
    })
    .await?;
    let mut v = serde_json::to_value(st.shared.snapshot())?;
    v["asset_count"] = count.into();
    v["alerts_unacked"] = unacked.into();
    v["now"] = crate::model::now_ts().into();
    Ok(Json(v))
}

async fn assets(State(st): State<AppState>) -> Result<Json<Vec<AssetView>>, ApiError> {
    let mut list = blocking(&st.store, |s| s.load_assets()).await?;
    list.sort_by(|a, b| b.last_seen.cmp(&a.last_seen).then(a.id.cmp(&b.id)));
    Ok(Json(list.into_iter().map(AssetView::from).collect()))
}

async fn asset(State(st): State<AppState>, Path(id): Path<i64>) -> Result<Response, ApiError> {
    Ok(match blocking(&st.store, move |s| s.get_asset(id)).await? {
        Some(a) => Json(AssetView::from(a)).into_response(),
        None => (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "not found"}))).into_response(),
    })
}

#[derive(Deserialize)]
struct EventsQuery {
    limit: Option<usize>,
    asset_id: Option<i64>,
    /// `1` = only alerts (severity above info).
    alerts: Option<u8>,
    /// `1` = only alerts nobody has acknowledged.
    unacked: Option<u8>,
}

impl From<EventsQuery> for EventQuery {
    fn from(q: EventsQuery) -> Self {
        EventQuery {
            limit: q.limit.unwrap_or(100).min(1000),
            asset_id: q.asset_id,
            alerts_only: q.alerts == Some(1),
            unacked_only: q.unacked == Some(1),
        }
    }
}

async fn events(
    State(st): State<AppState>,
    Query(q): Query<EventsQuery>,
) -> Result<Json<Vec<crate::model::Event>>, ApiError> {
    let q: EventQuery = q.into();
    Ok(Json(blocking(&st.store, move |s| s.list_events(&q)).await?))
}

/// Alerts only, newest first.
async fn alerts(
    State(st): State<AppState>,
    Query(q): Query<EventsQuery>,
) -> Result<Json<Vec<crate::model::Event>>, ApiError> {
    let q = EventQuery { alerts_only: true, ..q.into() };
    Ok(Json(blocking(&st.store, move |s| s.list_events(&q)).await?))
}

async fn set_ack(st: AppState, id: i64, acked: bool) -> Result<Response, ApiError> {
    let found = blocking(&st.store, move |s| s.set_event_acked(id, acked)).await?;
    Ok(if found {
        StatusCode::NO_CONTENT.into_response()
    } else {
        (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "not found"}))).into_response()
    })
}

async fn ack(State(st): State<AppState>, Path(id): Path<i64>) -> Result<Response, ApiError> {
    set_ack(st, id, true).await
}

async fn unack(State(st): State<AppState>, Path(id): Path<i64>) -> Result<Response, ApiError> {
    set_ack(st, id, false).await
}

async fn agents(State(st): State<AppState>) -> Result<Json<Vec<crate::model::AgentInfo>>, ApiError> {
    Ok(Json(blocking(&st.store, |s| s.list_agents()).await?))
}

/// The device's learned baseline, with destinations most-recent-first and capped.
async fn baseline(State(st): State<AppState>, Path(id): Path<i64>) -> Result<Response, ApiError> {
    Ok(match blocking(&st.store, move |s| s.get_baseline(id)).await? {
        Some(b) => {
            let mut dests: Vec<_> = b.typical_destinations.iter().collect();
            dests.sort_by_key(|(_, d)| std::cmp::Reverse(d.last_seen));
            let top: Vec<_> = dests
                .into_iter()
                .take(50)
                .map(|(ip, d)| serde_json::json!({"ip": ip, "first_seen": d.first_seen, "last_seen": d.last_seen, "bytes": d.bytes}))
                .collect();
            Json(serde_json::json!({
                "asset_id": b.asset_id,
                "observed_since": b.observed_since,
                "buckets": b.buckets,
                "destination_count": b.typical_destinations.len(),
                "destinations": top,
                "ports": b.typical_ports,
                "volume": {"n": b.volume.n, "mean": b.volume.mean, "std": b.volume.var.sqrt()},
                "active_hours": b.active_hours,
                "updated_at": b.updated_at,
            }))
            .into_response()
        }
        None => (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "no baseline yet"}))).into_response(),
    })
}

async fn scan(State(st): State<AppState>) -> StatusCode {
    st.shared.scan_now.notify_one();
    StatusCode::ACCEPTED
}

async fn static_file(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };
    match Ui::get(path) {
        Some(file) => {
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            (
                [(header::CONTENT_TYPE, mime.as_ref().to_string())],
                file.data.into_owned(),
            )
                .into_response()
        }
        None => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Mac;
    use crate::store::sqlite::SqliteStore;
    use axum::body::Body;
    use tower::ServiceExt;

    fn app(loopback_only: bool) -> (Router, Arc<dyn Store>) {
        let store: Arc<dyn Store> = Arc::new(SqliteStore::open_in_memory().unwrap());
        let shared = crate::engine::test_shared();
        (
            router(AppState { store: store.clone(), shared, loopback_only }),
            store,
        )
    }

    async fn get_json(app: &Router, uri: &str, host: &str) -> (StatusCode, serde_json::Value) {
        let req = axum::http::Request::get(uri).header("host", host).body(Body::empty()).unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null))
    }

    #[tokio::test]
    async fn assets_api_serves_stored_assets_with_current_ip() {
        let (app, store) = app(true);
        let mut a = Asset::new(Mac([0x3c, 0x22, 0xfb, 1, 2, 3]), 10);
        a.ip_history.push(crate::model::IpRecord { ip: Ipv4Addr::new(192, 168, 1, 9), first_seen: 10, last_seen: 10 });
        store.save_asset(&mut a).unwrap();

        let (code, v) = get_json(&app, "/api/assets", "localhost:8080").await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(v[0]["mac"], "3c:22:fb:01:02:03");
        assert_eq!(v[0]["ip"], "192.168.1.9");
        assert!(v[0]["agent_id"].is_null());

        let (code, _) = get_json(&app, &format!("/api/assets/{}", a.id), "127.0.0.1:8080").await;
        assert_eq!(code, StatusCode::OK);
        let (code, _) = get_json(&app, "/api/assets/999", "127.0.0.1:8080").await;
        assert_eq!(code, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn rebinding_host_header_is_rejected_on_loopback_bind() {
        let (app, _) = app(true);
        let (code, _) = get_json(&app, "/api/assets", "evil.example.com").await;
        assert_eq!(code, StatusCode::FORBIDDEN);
        // ...but not when deliberately bound to a LAN address.
        let (app, _) = self::app(false);
        let (code, _) = get_json(&app, "/api/assets", "192.168.1.10:8080").await;
        assert_eq!(code, StatusCode::OK);
    }

    #[tokio::test]
    async fn post_requires_custom_header_and_ui_has_csp() {
        let (app, _) = app(true);
        let bare = axum::http::Request::post("/api/scan").header("host", "localhost").body(Body::empty()).unwrap();
        assert_eq!(app.clone().oneshot(bare).await.unwrap().status(), StatusCode::FORBIDDEN);
        let ok = axum::http::Request::post("/api/scan")
            .header("host", "localhost")
            .header("x-netscope", "1")
            .body(Body::empty())
            .unwrap();
        assert_eq!(app.clone().oneshot(ok).await.unwrap().status(), StatusCode::ACCEPTED);

        let idx = axum::http::Request::get("/").header("host", "localhost").body(Body::empty()).unwrap();
        let resp = app.oneshot(idx).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers()[header::CONTENT_SECURITY_POLICY].to_str().unwrap().contains("default-src 'self'"));
    }

    #[tokio::test]
    async fn alerts_can_be_listed_acked_and_unacked_and_baselines_read() {
        use crate::model::{AgentInfo, Baseline, DestStat, Event};
        let (app, store) = app(true);
        let mut a = Asset::new(Mac([0x3c, 0x22, 0xfb, 1, 2, 3]), 10);
        store.save_asset(&mut a).unwrap();
        for (sev, score) in [("info", 0), ("high", 85)] {
            let mut e = Event {
                id: 0, agent_id: None, asset_id: a.id, kind: "new_destination".into(), timestamp: 5,
                severity: sev.into(), score, acked: false, raw_details: serde_json::json!({"summary": "x"}),
            };
            store.insert_event(&mut e).unwrap();
        }
        let (code, v) = get_json(&app, "/api/alerts", "localhost").await;
        assert_eq!((code, v.as_array().unwrap().len(), v[0]["score"].as_i64()), (StatusCode::OK, 1, Some(85)));
        assert_eq!(get_json(&app, "/api/events", "localhost").await.1.as_array().unwrap().len(), 2);
        let id = v[0]["id"].as_i64().unwrap();

        let post = |path: String| axum::http::Request::post(path).header("host", "localhost").header("x-netscope", "1").body(Body::empty()).unwrap();
        assert_eq!(app.clone().oneshot(post(format!("/api/alerts/{id}/ack"))).await.unwrap().status(), StatusCode::NO_CONTENT);
        assert!(get_json(&app, "/api/alerts?unacked=1", "localhost").await.1.as_array().unwrap().is_empty());
        assert_eq!(get_json(&app, "/api/alerts", "localhost").await.1[0]["acked"], true);
        assert_eq!(get_json(&app, "/api/status", "localhost").await.1["alerts_unacked"], 0);
        assert_eq!(app.clone().oneshot(post(format!("/api/alerts/{id}/unack"))).await.unwrap().status(), StatusCode::NO_CONTENT);
        assert_eq!(get_json(&app, "/api/status", "localhost").await.1["alerts_unacked"], 1);
        assert_eq!(app.clone().oneshot(post("/api/alerts/999/ack".into())).await.unwrap().status(), StatusCode::NOT_FOUND);
        // acking without the CSRF header is refused
        let bare = axum::http::Request::post(format!("/api/alerts/{id}/ack")).header("host", "localhost").body(Body::empty()).unwrap();
        assert_eq!(app.clone().oneshot(bare).await.unwrap().status(), StatusCode::FORBIDDEN);

        // baseline: 404 until one exists, then destinations come back recent-first
        assert_eq!(get_json(&app, &format!("/api/assets/{}/baseline", a.id), "localhost").await.0, StatusCode::NOT_FOUND);
        let mut b = Baseline::new(a.id, 1);
        b.typical_destinations.insert("1.1.1.1".into(), DestStat { first_seen: 1, last_seen: 5, bytes: 9 });
        b.typical_destinations.insert("2.2.2.2".into(), DestStat { first_seen: 1, last_seen: 50, bytes: 9 });
        store.save_baseline(&b).unwrap();
        let (code, v) = get_json(&app, &format!("/api/assets/{}/baseline", a.id), "localhost").await;
        assert_eq!((code, v["destinations"][0]["ip"].as_str(), v["destination_count"].as_i64()), (StatusCode::OK, Some("2.2.2.2"), Some(2)));

        // agents
        assert!(get_json(&app, "/api/agents", "localhost").await.1.as_array().unwrap().is_empty());
        store.upsert_agent(&AgentInfo { id: "site-b".into(), name: "Office".into(), site: None, version: "t".into(), subnet: "10.0.0.0/24".into(), first_seen: 1, last_report_at: 2, last_run_id: "r".into(), last_seq: 1 }).unwrap();
        assert_eq!(get_json(&app, "/api/agents", "localhost").await.1[0]["id"], "site-b");
    }
}
