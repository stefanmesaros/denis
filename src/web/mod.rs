//! JSON API + embedded static UI.
//!
//! Request pipeline (outermost first):
//! 1. `guard`: Host-header validation (DNS rebinding), the custom
//!    `X-Denis` header on state-changing requests (CSRF), security headers.
//! 2. `authn`: session cookie -> user, role check by method/path, forced
//!    password change. Static UI files and `/api/auth/login` are public;
//!    everything else needs a session.
//! 3. the handler (reads in this file, state changes in `web_admin`).
//!
//! Defence in depth for a UI that shows attacker-influenced strings (hostnames
//! arrive from the network): strict CSP, DOM built with `textContent`, cookies
//! that are HttpOnly + SameSite=Strict.

use std::collections::HashMap;

use axum::extract::{Extension, Path, Query, Request, State};
use axum::http::{header, HeaderValue, StatusCode, Uri};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::extract::DefaultBodyLimit;
use axum::routing::{delete, get, patch, post, put};
use axum::{Json, Router};
use rust_embed::RustEmbed;
use serde::Deserialize;

use crate::auth::role_rank;
use crate::model::{now_ts, Asset, User};
pub(crate) mod common;
pub(crate) use common::{asset_view, blocking, effective_license, open_alerts, scoped_asset, site_readable, site_writable, view, ApiError, AssetView};
pub use common::{AppState, AuthUser, SESSION_COOKIE};
use crate::web_admin as admin;
use crate::web_health as health_page;
use crate::web_reports as reports_page;
use crate::web_setup as setup_page;
use crate::web_topology as topology_page;
use crate::web_totp as totp_page;
use crate::web_retention as retention_page;
use crate::web_siem as siem_page;
use crate::web_vuln as vuln_page;
use crate::web_passkey as passkey;
use crate::{report, trends};
use crate::store::EventQuery;

#[derive(RustEmbed)]
#[folder = "ui/"]
struct Ui;

pub async fn serve(listener: tokio::net::TcpListener, state: AppState) -> std::io::Result<()> {
    // ConnectInfo gives handlers the peer address (used to rate-limit sign-in attempts).
    axum::serve(listener, router(state).into_make_service_with_connect_info::<std::net::SocketAddr>()).await
}

/// Like `serve`, but over TLS.
pub async fn serve_tls(listener: tokio::net::TcpListener, state: AppState, cfg: axum_server::tls_rustls::RustlsConfig) -> std::io::Result<()> {
    crate::tls::serve(listener, router(state), cfg).await
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/docs", get(|| async { axum::response::Redirect::to("/docs/index") }))
        .route("/docs/", get(|| async { axum::response::Redirect::to("/docs/index") }))
        .route("/docs/img/{file}", get(docs_image))
        .route("/docs/{page}", get(docs_page))
        .route("/api/health", get(|| async { Json(serde_json::json!({ "ok": true })) }))
        // session
        .route("/api/auth/login", post(admin::login))
        .route("/api/auth/logout", post(admin::logout))
        .route("/api/auth/methods", get(passkey::methods))
        .route("/api/auth/passkey/login/begin", post(passkey::login_begin))
        .route("/api/auth/passkey/login/finish", post(passkey::login_finish))
        .route("/api/auth/passkey/register/begin", post(passkey::register_begin))
        .route("/api/auth/passkey/register/finish", post(passkey::register_finish))
        .route("/api/auth/mfa", post(totp_page::mfa_login))
        .route("/api/auth/totp", get(totp_page::status))
        .route("/api/auth/totp/begin", post(totp_page::begin))
        .route("/api/auth/totp/qr.svg", get(totp_page::qr))
        .route("/api/auth/totp/confirm", post(totp_page::confirm))
        .route("/api/auth/totp/disable", post(totp_page::disable))
        .route("/api/auth/totp/recovery", post(totp_page::new_recovery_codes))
        .route("/api/users/{id}/totp", delete(totp_page::admin_reset))
        .route("/api/security", get(totp_page::policy_get).put(totp_page::policy_put))
        .route("/api/auth/passkeys", get(passkey::list))
        .route("/api/auth/passkeys/{id}", delete(passkey::delete))
        .route("/api/users/{id}/passkeys", delete(passkey::admin_revoke_all))
        .route("/api/auth/me", get(admin::me))
        .route("/api/auth/password", post(admin::change_password))
        // read
        .route("/api/status", get(status))
        .route("/api/meta/options", get(admin::options))
        .route("/api/channels", get(admin::channels_list).post(admin::channels_create))
        .route("/api/channels/{id}", axum::routing::put(admin::channels_update).delete(admin::channels_delete))
        .route("/api/channels/{id}/test", post(admin::channels_test))
        .route("/api/maintenance", get(admin::maintenance_get).put(admin::maintenance_put))
        .route("/metrics", get(metrics))
        .route("/api/compliance", get(compliance))
        .route("/api/tls", get(admin::tls_get))
        .route("/api/tls/certificate", post(admin::tls_upload).delete(admin::tls_reset))
        .route("/tls/ca.pem", get(admin::tls_ca))
        .route("/api/update", get(admin::update_get))
        .route("/api/update/check", post(admin::update_check))
        .route("/api/update/install", post(admin::update_install))
        .route("/api/update/snooze", post(admin::update_snooze))
        .route("/api/update/skip", post(admin::update_skip))
        .route("/api/update/schedule", delete(admin::update_unschedule))
        .route("/api/demo", get(admin::demo_get).post(admin::demo_load).delete(admin::demo_remove))
        .route("/api/data/erase", post(admin::data_erase))
        .route("/api/findings", get(findings))
        .route("/api/findings/{id}/verify", post(admin::finding_verify))
        .route("/api/siem", get(siem_page::get).put(siem_page::put))
        .route("/api/siem/test", post(siem_page::test))
        .route("/api/retention", get(retention_page::get).put(retention_page::put))
        .route("/api/vulndata", get(vuln_page::status).put(vuln_page::put))
        .route("/api/vulndata/refresh", post(vuln_page::refresh))
        .route("/api/vulndata/custom", put(vuln_page::custom_put))
        .route("/api/vulndata/kev/refresh", post(vuln_page::kev_refresh))
        .route("/api/topology", get(topology_page::topology))
        .route("/api/switches", get(topology_page::list).put(topology_page::put))
        .route("/api/switches/{id}/poll", post(topology_page::poll_now))
        .route("/api/system", get(health_page::health))
        .route("/api/setup", get(setup_page::get).put(setup_page::put))
        .route("/api/backups", get(health_page::list).post(health_page::make))
        .route("/api/backups/settings", put(health_page::settings_put))
        .route("/api/backups/upload-schedule", put(health_page::upload_settings_put))
        .route("/api/backups/agent-keep", put(health_page::agent_keep_put))
        .route("/api/msp-backups", get(health_page::msp_backups_list))
        .route("/api/msp-backups/{agent_id}/{name}", get(health_page::msp_backup_download).delete(health_page::msp_backup_remove))
        .route("/api/backups/{name}", get(health_page::download).delete(health_page::remove))
        .route("/api/reports", get(reports_page::list).post(reports_page::make))
        .route("/api/reports/settings", get(reports_page::settings_get).put(reports_page::settings_put))
        .route("/api/reports/{id}", get(reports_page::view).delete(reports_page::remove))
        .route("/api/reports/{id}/share", put(reports_page::share_put).delete(reports_page::share_delete))
        .route("/api/reports/shared/{token}", get(reports_page::shared_view))
        .route("/api/risk-acceptances", get(admin::risk_list).post(admin::risk_accept))
        .route("/api/risk-acceptances/{id}", delete(admin::risk_revoke))
        .route("/api/rules", get(admin::rules_get).put(admin::rules_put).delete(admin::rules_reset))
        .route("/api/assets", get(assets).post(admin::create_asset))
        .route("/api/assets/import", post(admin::import_assets))
        .route("/api/assets/review", post(admin::review_assets))
        .route("/api/assets/bulk-tags", post(admin::bulk_tags))
        .route("/api/assets/{id}", get(asset).delete(admin::delete_asset))
        .route("/api/assets/{id}/meta", patch(admin::patch_meta))
        .route("/api/assets/{id}/history", get(admin::history))
        .route("/api/assets/{id}/baseline", get(baseline))
        .route("/api/assets/{id}/merged", get(merged_into_this))
        .route("/api/events", get(events))
        .route("/api/alerts", get(alerts))
        .route("/api/alerts/{id}/ack", post(ack))
        .route("/api/alerts/{id}/unack", post(unack))
        .route("/api/agents", get(agents))
        .route("/api/conversations", get(conversations))
        .route("/api/trends", get(trend_points))
        .route("/api/top-talkers", get(top_talkers_get))
        .route("/api/software", get(software_get))
        .route("/api/top-talkers/excluded", put(top_talkers_excluded_put))
        .route("/api/export/assets.csv", get(export_assets))
        .route("/api/export/alerts.csv", get(export_alerts))
        .route("/report", get(report_page))
        .route("/api/scan", post(scan))
        // administration
        .route("/api/users", get(admin::users_list).post(admin::users_create))
        .route("/api/users/{id}", patch(admin::users_update).delete(admin::users_delete))
        .route("/api/users/{id}/reset-password", post(admin::users_reset))
        .route("/api/users/{id}/site-access", get(admin::site_access_get).put(admin::site_access_put))
        .route("/api/api-tokens", get(admin::api_tokens_list).post(admin::api_tokens_create))
        .route("/api/api-tokens/{id}", delete(admin::api_tokens_revoke))
        .route("/api/api-tokens/{id}/purge", delete(admin::api_tokens_delete))
        .route("/api/agent-tokens", get(admin::tokens_list).post(admin::tokens_issue))
        .route("/api/agent-tokens/{agent_id}", delete(admin::tokens_revoke))
        .route("/api/agent-tokens/{agent_id}/purge", delete(admin::tokens_delete))
        .route("/api/audit", get(admin::audit_list))
        .route("/api/branding", get(admin::branding_get).put(admin::branding_put))
        .route("/api/license", get(admin::license_get).put(admin::license_put).delete(admin::license_delete))
        .route("/api/msp-overview", put(admin::msp_overview_put))
        .route("/api/interfaces", get(admin::interfaces_get).put(admin::interfaces_put))
        .route("/api/branding/logo", axum::routing::put(admin::logo_put).delete(admin::logo_delete).layer(DefaultBodyLimit::max(crate::branding::MAX_LOGO_BYTES + 1024)))
        .route("/branding/logo", get(admin::logo_get))
        .fallback(static_file)
        .layer(middleware::from_fn_with_state(state.clone(), authn))
        .layer(middleware::from_fn_with_state(state.clone(), guard))
        .with_state(state)
}

/// Paths reachable without a session: the static UI shell (it contains no
/// data), the login call and the liveness probe.
fn is_public(method: &axum::http::Method, path: &str) -> bool {
    !(path.starts_with("/api/") || path.starts_with("/report") || path.starts_with("/docs") || path == "/metrics")
        || matches!(path, "/api/auth/login" | "/api/health" | "/api/auth/methods" | "/api/auth/passkey/login/begin" | "/api/auth/passkey/login/finish" | "/api/auth/mfa")
        // branding is read before anybody can sign in; changing it is admin-only
        || (path == "/api/branding" && method == axum::http::Method::GET)
        // a shared report link is the point of sharing it: no session, by a long random token
        || (path.starts_with("/api/reports/shared/") && method == axum::http::Method::GET)
}

/// Lowest role that may call `method path`. Reads need `viewer`; changing
/// anything needs `editor`; managing users, tokens and the audit log, or
/// deleting assets, needs `admin`.
pub(crate) fn required_role(method: &axum::http::Method, path: &str) -> &'static str {
    if path.starts_with("/api/users") || path.starts_with("/api/tls") || path.starts_with("/api/data") || path.starts_with("/api/channels") || path.starts_with("/api/agent-tokens") || path.starts_with("/api/api-tokens") || path.starts_with("/api/audit") || path.starts_with("/api/backups") || path.starts_with("/api/msp-backups") || path.starts_with("/api/setup") || path.starts_with("/api/security") || path.starts_with("/api/retention") {
        return "admin";
    }
    if path.starts_with("/api/auth/") {
        return "viewer"; // any signed-in user may log out / change own password
    }
    if (path.starts_with("/api/branding") || path.starts_with("/api/rules") || path.starts_with("/api/maintenance") || path.starts_with("/api/demo") || path.starts_with("/api/update") || path.starts_with("/api/risk-acceptances") || path.starts_with("/api/switches") || path.starts_with("/api/vulndata") || path.starts_with("/api/license") || path.starts_with("/api/msp-overview") || path.starts_with("/api/interfaces") || path.starts_with("/api/siem") || path == "/api/reports/settings" || path.ends_with("/share")) && method != axum::http::Method::GET {
        return "admin";
    }
    if method == axum::http::Method::DELETE {
        return "admin";
    }
    if method == axum::http::Method::GET || method == axum::http::Method::HEAD {
        return "viewer";
    }
    "editor"
}

/// Session -> user, then role enforcement. See the module docs.
async fn authn(State(st): State<AppState>, mut req: Request, next: Next) -> Response {
    let path = req.uri().path().to_string();
    // An Authorization header means "this is a script": only the bearer token is
    // considered, never a cookie that might ride along. (A cross-site page cannot
    // set this header, which is also why such requests need no CSRF header.)
    let bearer = req.headers().get(header::AUTHORIZATION).and_then(|h| h.to_str().ok()).map(|h| h.strip_prefix("Bearer ").unwrap_or("").to_string());
    let via_token = bearer.is_some();
    let user = if st.no_auth {
        Some(User { id: 0, username: "local".into(), role: "admin".into(), created_at: 0, disabled: false, must_change: false, last_login: None })
    } else if let Some(t) = bearer {
        st.auth.verify_api_token(&t, now_ts()).map(|t| User {
            id: -1, username: format!("token:{}", t.label), role: t.role, created_at: t.created_at, disabled: false, must_change: false, last_login: t.last_used,
        })
    } else {
        admin::session_token(req.headers()).and_then(|t| st.auth.session_user(&t, now_ts()))
    };
    if let Some(u) = &user {
        req.extensions_mut().insert(AuthUser(u.clone()));
    }
    if is_public(req.method(), &path) {
        return next.run(req).await;
    }
    let deny = |code: StatusCode, msg: &str, extra: &str| {
        (code, Json(serde_json::json!({ "error": msg, "code": extra }))).into_response()
    };
    let Some(u) = user else {
        return deny(StatusCode::UNAUTHORIZED, "authentication required", "unauthenticated");
    };
    // Tokens have no password or session to manage.
    if via_token && !st.no_auth && path.starts_with("/api/auth/") && path != "/api/auth/me" {
        return deny(StatusCode::FORBIDDEN, "not available to API tokens", "forbidden");
    }
    // A password set by someone else must be changed before anything else works.
    if u.must_change && !path.starts_with("/api/auth/") {
        return deny(StatusCode::FORBIDDEN, "password change required", "must_change");
    }
    // A second step the administrator requires must be set up before anything else works (setting it up is allowed).
    if !via_token && !st.no_auth && !path.starts_with("/api/auth/") && st.auth.must_enrol(&u, now_ts()) {
        return deny(StatusCode::FORBIDDEN, "set up a second sign-in step first", "mfa_required");
    }
    if role_rank(&u.role) < role_rank(required_role(req.method(), &path)) {
        return deny(StatusCode::FORBIDDEN, "your role does not allow this", "forbidden");
    }
    next.run(req).await
}

/// Host check (loopback binds only), CSRF header on POST, and response hardening.
async fn guard(State(st): State<AppState>, req: Request, next: Next) -> Response {
    let path = req.uri().path().to_string();
    if st.loopback_only {
        // HTTP/1 sends a Host header; HTTP/2 (TLS with ALPN) puts the name in the
        // URI's :authority instead.
        let host = req
            .headers()
            .get(header::HOST)
            .and_then(|h| h.to_str().ok())
            .or_else(|| req.uri().authority().map(|a| a.as_str()))
            .unwrap_or("");
        let name = host
            .rsplit_once(':')
            .filter(|(_, port)| port.chars().all(|c| c.is_ascii_digit()))
            .map_or(host, |(n, _)| n);
        if !(matches!(name, "localhost" | "127.0.0.1" | "[::1]") || st.allowed_hosts.iter().any(|h| h.eq_ignore_ascii_case(name))) {
            return (StatusCode::FORBIDDEN, "unexpected Host header").into_response();
        }
    }
    let scripted = req.headers().get(header::AUTHORIZATION).and_then(|h| h.to_str().ok()).is_some_and(|h| h.starts_with("Bearer dnt_"));
    if req.method() != axum::http::Method::GET && !scripted && !req.headers().contains_key("x-denis") {
        return (StatusCode::FORBIDDEN, "missing X-Denis header").into_response();
    }
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    if !h.contains_key(header::CONTENT_SECURITY_POLICY) {
        h.insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static("default-src 'self'; frame-ancestors 'none'; base-uri 'none'"),
        );
    }
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h.insert("cross-origin-opener-policy", HeaderValue::from_static("same-origin"));
    h.insert("cross-origin-resource-policy", HeaderValue::from_static("same-origin"));
    h.insert("permissions-policy", HeaderValue::from_static("camera=(), microphone=(), geolocation=(), payment=()"));
    // API answers hold inventory data: never let a browser or proxy keep them.
    let cache = if path.starts_with("/api/") || path.starts_with("/report") { "no-store" } else { "no-cache" };
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
    resp
}

async fn status(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>) -> Result<Json<serde_json::Value>, ApiError> {
    let (count, unacked) = blocking(&st.store, |s| {
        let q = EventQuery { limit: 1000, alerts_only: true, unacked_only: true, ..Default::default() };
        Ok((s.load_assets()?.len(), s.list_events(&q)?.len()))
    })
    .await?;
    let now = crate::model::now_ts();
    let mut v = serde_json::to_value(st.shared.snapshot())?;
    v["asset_count"] = count.into();
    v["alerts_unacked"] = unacked.into();
    v["auth_required"] = (!st.no_auth).into();
    v["now"] = now.into();
    // whether the local site (no agent) shows in the site filter at all (see access.rs)
    v["local_readable"] = site_readable(&st, &me, &None).into();
    v["msp_overview"] = matches!(st.store.get_setting(crate::web_admin::MSP_OVERVIEW_KEY), Ok(Some(b)) if b == b"1").into();
    let lic = effective_license(&st);
    let (stage, grace_days_left) = match crate::license::stage(&lic, now) {
        crate::license::Stage::Fine => ("fine", None),
        crate::license::Stage::ExpiringSoon { days_left } => ("expiring_soon", Some(days_left)),
        crate::license::Stage::Grace { days_left } => ("grace", Some(days_left)),
        crate::license::Stage::Expired => ("expired", None),
    };
    v["license"] = serde_json::json!({
        "tier": lic.license.as_ref().map(|l| l.tier.as_str()),
        "customer": lic.license.as_ref().map(|l| l.customer.as_str()),
        "device_cap": lic.device_cap,
        "commercial": lic.commercial,
        "problem": lic.problem,
        "over_cap": lic.over_cap(count as u32),
        "expires_at": lic.expires_at,
        "stage": stage,
        "days_left": grace_days_left,
    });
    Ok(Json(v))
}

/// Prometheus exposition: counts and health, never names or alert text.
async fn metrics(State(st): State<AppState>) -> Result<Response, ApiError> {
    use crate::metrics::Exposition;
    let now = now_ts();
    let (mut assets, metas, alerts, agents) = blocking(&st.store, |s| {
        let q = EventQuery { limit: 5000, alerts_only: true, unacked_only: true, ..Default::default() };
        Ok((s.load_assets()?, s.load_all_meta()?, s.list_events(&q)?, s.list_agents()?))
    })
    .await?;
    for a in &mut assets {
        if let Some(m) = metas.get(&a.id) {
            crate::tracking::apply_overrides(a, m);
        }
    }
    let info = st.shared.snapshot();
    let online_window = (info.sweep_interval_secs as i64) * 2 + 60;
    let mut e = Exposition::new();
    e.gauge("denis_up", "1 while the console is running.", 1.0);
    e.family("denis_build_info", "gauge", "Version of the running program.");
    e.sample("denis_build_info", &[("version", info.version), ("mode", info.mode)], 1.0);
    e.gauge("denis_uptime_seconds", "Seconds since start.", (now - info.started_at).max(0) as f64);
    e.family("denis_frames_matched_total", "counter", "Network frames the collector has matched.");
    e.sample("denis_frames_matched_total", &[], info.frames_matched as f64);
    e.gauge("denis_devices", "Devices in the inventory.", assets.len() as f64);
    e.gauge("denis_devices_online", "Devices seen recently.", assets.iter().filter(|a| now - a.last_seen <= online_window).count() as f64);
    e.family("denis_devices_by_type", "gauge", "Devices per device type.");
    let mut by_type: std::collections::BTreeMap<&str, u64> = Default::default();
    for a in &assets {
        *by_type.entry(a.device_type.as_str()).or_default() += 1;
    }
    for (t, n) in by_type {
        e.sample("denis_devices_by_type", &[("type", t)], n as f64);
    }
    e.family("denis_alerts_unacknowledged", "gauge", "Alerts nobody has acknowledged yet, by severity.");
    for sev in ["high", "medium", "low"] {
        e.sample("denis_alerts_unacknowledged", &[("severity", sev)], alerts.iter().filter(|a| a.severity == sev).count() as f64);
    }
    let accepted_all = blocking(&st.store, |s| s.list_risk_acceptances()).await?;
    let (findings, accepted) = crate::findings::apply_acceptances(crate::findings::compute(&assets, &metas, now), &accepted_all, now);
    e.gauge("denis_accepted_risks", "Risks people decided to accept (in force now).", accepted.len() as f64);
    e.family("denis_findings", "gauge", "Standing problems to fix, by severity.");
    for sev in ["high", "medium", "low", "info"] {
        e.sample("denis_findings", &[("severity", sev)], findings.iter().filter(|f| f.severity == sev).count() as f64);
    }
    e.gauge("denis_learning_seconds_remaining", "Seconds until the learning period ends (0 = detecting).", info.learning_ends_at.map_or(0, |t| (t - now).max(0)) as f64);
    e.gauge("denis_sites", "Remote sites (agents) that ever reported.", agents.len() as f64);
    e.family("denis_site_last_report_age_seconds", "gauge", "Seconds since each remote site last reported.");
    for a in &agents {
        e.sample("denis_site_last_report_age_seconds", &[("site", &a.id)], (now - a.last_report_at).max(0) as f64);
    }
    e.family("denis_export_failing", "gauge", "1 if an export (OpenObserve, syslog) is failing.");
    for x in &info.exports {
        e.sample("denis_export_failing", &[("target", x.target.split("://").next().unwrap_or("export"))], x.last_error.is_some() as u8 as f64);
    }
    let channels = blocking(&st.store, |s| crate::channels::load(s)).await?;
    let cstat = st.shared.channel_status.lock().unwrap().clone();
    e.family("denis_channel_failing", "gauge", "1 if a notification channel could not deliver its last message.");
    for c in &channels {
        e.sample("denis_channel_failing", &[("channel", &c.name), ("kind", &c.kind)], cstat.get(&c.id).is_some_and(|s| s.last_error.is_some()) as u8 as f64);
    }
    let maint = blocking(&st.store, |s| crate::channels::load_maintenance(s)).await?;
    let shared = st.shared.clone();
    let health = blocking(&st.store, move |s| crate::health::gather(s, &shared, now, false)).await?;
    e.gauge("denis_database_bytes", "Size of the database.", health.db.db_bytes as f64);
    e.gauge("denis_health_warnings", "Problems the Health page lists right now.", health.warnings.len() as f64);
    if let Some((free, _)) = health.disk {
        e.gauge("denis_disk_free_bytes", "Free space on the disk that holds the database.", free as f64);
    }
    if let Some(c) = &health.capture {
        e.gauge("denis_capture_dropped_packets", "Packets the capture dropped since it started.", c.dropped as f64);
    }
    if let Some(t) = health.backups.latest_at {
        e.gauge("denis_backup_age_seconds", "Age of the newest backup.", (now - t).max(0) as f64);
    }
    e.gauge("denis_maintenance_mode", "1 while outgoing notifications are silenced.", maint.active(now) as u8 as f64);
    Ok((
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8".to_string())],
        e.finish(),
    )
        .into_response())
}

/// Coverage of the register and a mapping onto CIS / NIST CSF / IEC 62443 controls.
async fn compliance(State(st): State<AppState>) -> Result<Json<crate::compliance::Report>, ApiError> {
    let shared = st.shared.clone();
    Ok(Json(blocking(&st.store, move |s| crate::reports::compliance_now(s, &shared, now_ts())).await?))
}

async fn assets(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>) -> Result<Json<Vec<AssetView>>, ApiError> {
    let now = now_ts();
    let (mut list, alerts, mut metas) = blocking(&st.store, |s| Ok((s.load_assets()?, open_alerts(s)?, s.load_all_meta()?))).await?;
    list.retain(|a| site_readable(&st, &me, &a.agent_id));
    // A device merged into another (the same physical box seen under a second MAC, typically) is
    // hidden here — its own history is kept, not deleted, and it comes straight back the moment
    // the merge is undone.
    list.retain(|a| metas.get(&a.id).is_none_or(|m| m.merged_into.is_none()));
    // Community edition (or an expired/invalid license): only the first `cap` devices are
    // returned. Detection and alerting are unaffected — every device is still monitored, just
    // not listed here past the cap (see license::keep_within_cap and LICENSE, clause 1).
    let cap = effective_license(&st).device_cap;
    if cap.is_some() {
        let keep = crate::license::keep_within_cap(&list.iter().map(|a| a.id).collect::<Vec<_>>(), cap);
        list.retain(|a| keep.contains(&a.id));
    }
    list.sort_by(|a, b| b.last_seen.cmp(&a.last_seen).then(a.id.cmp(&b.id)));
    Ok(Json(list.into_iter().map(|a| { let m = metas.remove(&a.id).unwrap_or_default(); view(a, &alerts, m, now) }).collect()))
}

/// Standing weaknesses and housekeeping problems, with what to do about each.
async fn findings(State(st): State<AppState>) -> Result<Json<Vec<crate::findings::Finding>>, ApiError> {
    let now = now_ts();
    let (mut list, metas) = blocking(&st.store, |s| Ok((s.load_assets()?, s.load_all_meta()?))).await?;
    // the same corrections the asset list applies, so both views agree
    for a in &mut list {
        if let Some(m) = metas.get(&a.id) {
            crate::tracking::apply_overrides(a, m);
        }
    }
    let acceptances = blocking(&st.store, |s| s.list_risk_acceptances()).await?;
    // what is still open: a decision to live with a risk takes that device out of the finding
    Ok(Json(crate::findings::apply_acceptances(crate::findings::compute(&list, &metas, now), &acceptances, now).0))
}

async fn asset(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Path(id): Path<i64>) -> Result<Response, ApiError> {
    Ok(match asset_view(&st, &me, id).await? {
        Some(v) => Json(v).into_response(),
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
    Extension(AuthUser(me)): Extension<AuthUser>,
    Query(q): Query<EventsQuery>,
) -> Result<Json<Vec<crate::model::Event>>, ApiError> {
    let q: EventQuery = q.into();
    let mut list = blocking(&st.store, move |s| s.list_events(&q)).await?;
    list.retain(|e| site_readable(&st, &me, &e.agent_id));
    Ok(Json(list))
}

/// Alerts only, newest first.
async fn alerts(
    State(st): State<AppState>,
    Extension(AuthUser(me)): Extension<AuthUser>,
    Query(q): Query<EventsQuery>,
) -> Result<Json<Vec<crate::model::Event>>, ApiError> {
    let q = EventQuery { alerts_only: true, ..q.into() };
    let mut list = blocking(&st.store, move |s| s.list_events(&q)).await?;
    list.retain(|e| site_readable(&st, &me, &e.agent_id));
    Ok(Json(list))
}

async fn set_ack(st: AppState, me: &User, id: i64, acked: bool) -> Result<Response, ApiError> {
    if let Some(e) = blocking(&st.store, move |s| s.get_event(id)).await? {
        if !site_readable(&st, me, &e.agent_id) {
            return Ok((StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "not found"}))).into_response());
        }
        if !site_writable(&st, me, &e.agent_id) {
            return Ok((StatusCode::FORBIDDEN, Json(serde_json::json!({"error": "read-only access to this site"}))).into_response());
        }
    }
    let found = blocking(&st.store, move |s| s.set_event_acked(id, acked)).await?;
    Ok(if found {
        StatusCode::NO_CONTENT.into_response()
    } else {
        (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "not found"}))).into_response()
    })
}

async fn ack(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Path(id): Path<i64>) -> Result<Response, ApiError> {
    set_ack(st, &me, id, true).await
}

async fn unack(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Path(id): Path<i64>) -> Result<Response, ApiError> {
    set_ack(st, &me, id, false).await
}

/// The industrial communications matrix, joined with device names so the UI
/// can show "HMI-3 → PLC-line2 (s7): 1,204 reads, 3 writes, 1 control".
async fn conversations(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>) -> Result<Json<serde_json::Value>, ApiError> {
    let (convs, mut assets, metas) = blocking(&st.store, |s| Ok((s.list_conversations()?, s.load_assets()?, s.load_all_meta()?))).await?;
    // a path is shown only when both ends are on a site this user can read
    assets.retain(|a| site_readable(&st, &me, &a.agent_id));
    let by_id: std::collections::HashMap<i64, &Asset> = assets.iter().map(|a| (a.id, a)).collect();
    let party = |id: i64| {
        by_id.get(&id).map(|a| {
            let m = metas.get(&id);
            serde_json::json!({
                "id": id, "mac": a.mac, "ip": a.current_ip(),
                "name": m.and_then(|m| m.display_name.clone()).or_else(|| a.hostnames.first().cloned()),
                "device_type": m.and_then(|m| m.type_override.clone()).unwrap_or_else(|| a.device_type.clone()),
                "purdue_level": m.and_then(|m| m.purdue_level.clone()),
                "zone": m.and_then(|m| m.zone.clone()),
            })
        })
    };
    let rows: Vec<_> = convs
        .into_iter()
        .filter_map(|c| {
            let (cl, sv) = (party(c.client_id)?, party(c.server_id)?);
            Some(serde_json::json!({
                "client": cl, "server": sv, "protocol": c.proto, "port": c.port,
                "first_seen": c.first_seen, "last_seen": c.last_seen, "packets": c.packets, "bytes": c.bytes,
                "reads": c.reads, "writes": c.writes, "controls": c.controls, "note": c.note, "commands": c.commands,
            }))
        })
        .collect();
    Ok(Json(serde_json::json!(rows)))
}

async fn agents(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>) -> Result<Json<Vec<crate::model::AgentInfo>>, ApiError> {
    let mut list = blocking(&st.store, |s| s.list_agents()).await?;
    list.retain(|a| site_readable(&st, &me, &Some(a.id.clone())));
    Ok(Json(list))
}

/// The device's learned baseline, with destinations most-recent-first and capped.
async fn baseline(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Path(id): Path<i64>) -> Result<Response, ApiError> {
    if scoped_asset(&st, &me, id).await?.is_none() {
        return Ok((StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "not found"}))).into_response());
    }
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
        // `null`, not 404: most devices have no traffic baseline (no flow
        // accounting), and the browser logs every 404 as a console error.
        None => Json(serde_json::Value::Null).into_response(),
    })
}

/// Fleet-wide software inventory: every distinct product+version read from a device's service
/// banners, with which devices have it and, where `vulndata::Intel` knows about it, whether it is
/// end-of-support or has a known-exploited vulnerability. The same access rules as `/api/assets`
/// (site visibility, the Community edition's device cap) apply to which devices can contribute a
/// row here, so this never reveals a device outside what the caller could already see there.
async fn software_get(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>) -> Result<Json<serde_json::Value>, ApiError> {
    let now = now_ts();
    let (mut list, intel) = blocking(&st.store, |s| Ok((s.load_assets()?, crate::vulndata::Intel::load(s)))).await?;
    list.retain(|a| site_readable(&st, &me, &a.agent_id));
    let cap = effective_license(&st).device_cap;
    if cap.is_some() {
        let keep = crate::license::keep_within_cap(&list.iter().map(|a| a.id).collect::<Vec<_>>(), cap);
        list.retain(|a| keep.contains(&a.id));
    }
    let today = now / 86_400;
    let groups = crate::banners::software_inventory(list.iter().map(|a| (a.id, &a.fingerprint.identity)));
    let rows: Vec<_> = groups
        .into_iter()
        .map(|g| {
            let eol = intel.eol(g.product, &g.version, today);
            let kev = intel.kev(g.product, &g.version);
            serde_json::json!({
                "product": crate::vulndata::product_name(g.product),
                "version": g.version,
                "source": g.source,
                "asset_ids": g.asset_ids,
                "eol": eol.map(|e| serde_json::json!({ "state": e.state, "cycle": e.cycle, "days_left": e.days_left })),
                "cves": kev.iter().map(|k| serde_json::json!({ "cve": k.cve, "name": k.name, "ransomware": k.ransomware, "epss": intel.epss(&k.cve) })).collect::<Vec<_>>(),
            })
        })
        .collect();
    Ok(Json(serde_json::json!({ "software": rows })))
}

/// Devices merged into this one (see `AssetMeta::merged_into`) — hidden from `/api/assets`, so
/// the canonical device's own panel needs its own way to list them, to offer "Unmerge".
async fn merged_into_this(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Path(id): Path<i64>) -> Result<Response, ApiError> {
    if scoped_asset(&st, &me, id).await?.is_none() {
        return Ok((StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "not found"}))).into_response());
    }
    let (user_id, role) = (me.id, me.role.clone());
    let siblings = blocking(&st.store, move |s| {
        let metas = s.load_all_meta()?;
        let ids: Vec<i64> = metas.iter().filter(|(_, m)| m.merged_into == Some(id)).map(|(id, _)| *id).collect();
        let mut out = Vec::new();
        for sid in ids {
            if let Some(a) = s.get_asset(sid)? {
                // A sibling merged in from a different site than the canonical device's own must
                // stay invisible to someone who can only see the canonical device's site — the
                // same rule scoped_asset already enforces for the canonical device itself.
                if !crate::access::readable(s, user_id, &role, &a.agent_id) {
                    continue;
                }
                out.push(serde_json::json!({ "id": a.id, "mac": a.mac.to_string(), "first_seen": a.first_seen, "last_seen": a.last_seen }));
            }
        }
        Ok(out)
    })
    .await?;
    Ok(Json(serde_json::json!(siblings)).into_response())
}

#[derive(Deserialize)]
struct TrendQuery {
    hours: Option<i64>,
    /// `local`, an agent id, or absent for everything combined.
    agent: Option<String>,
}

async fn trend_points(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Query(q): Query<TrendQuery>) -> Result<Response, ApiError> {
    let hours = q.hours.unwrap_or(24).clamp(1, 24 * 365);
    let now = crate::model::now_ts();
    let agent = q.agent.map(|a| if a == "local" { String::new() } else { a });
    // a specific site's trend is refused outright when it is not readable; the all-sites
    // total (no `agent`) is not filtered — a small aggregate byte/device count is low-sensitivity
    if let Some(a) = &agent {
        if !site_readable(&st, &me, &Some(a.clone()).filter(|s| !s.is_empty())) {
            return Ok((StatusCode::FORBIDDEN, Json(serde_json::json!({"error": "read-only or no access to this site"}))).into_response());
        }
    }
    let samples = blocking(&st.store, move |s| s.list_metrics(now - hours * 3600, now + 1, agent.as_deref())).await?;
    let (points, step) = trends::downsample(&samples, 240);
    Ok(Json(serde_json::json!({ "hours": hours, "step_secs": step, "points": points })).into_response())
}

/// Who talked the most since their traffic baseline started (`--flows` only — `talkers` is empty
/// without it): a live snapshot for "Most received / most sent / total" leaderboards, not a time
/// series. `excluded` lists the asset ids an administrator picked by hand, on top of the automatic
/// gateway/self exclusion, so the settings UI can show which devices are already hidden.
async fn top_talkers_get(State(st): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    let (talkers, excluded) = blocking(&st.store, |s| {
        let baselines = s.load_baselines()?;
        let assets = s.load_assets()?;
        let excluded = trends::load_excluded(s)?;
        let talkers = trends::top_talkers(&baselines, &assets, &excluded);
        Ok((talkers, excluded))
    })
    .await?;
    let mut excluded: Vec<i64> = excluded.into_iter().collect();
    excluded.sort_unstable();
    Ok(Json(serde_json::json!({ "talkers": talkers, "excluded": excluded })))
}

#[derive(Deserialize)]
struct TopTalkersExcludedPut {
    excluded: Vec<i64>,
}

async fn top_talkers_excluded_put(State(st): State<AppState>, Json(b): Json<TopTalkersExcludedPut>) -> Result<Response, ApiError> {
    let now = now_ts();
    let excluded: std::collections::HashSet<i64> = b.excluded.into_iter().collect();
    blocking(&st.store, move |s| trends::save_excluded(s, &excluded, now)).await?;
    Ok(Json(serde_json::json!({"ok": true})).into_response())
}

#[derive(Deserialize)]
struct DaysQuery {
    days: Option<i64>,
}

async fn gather(st: &AppState, days: Option<i64>) -> Result<report::ReportData, ApiError> {
    let (days, now) = (days.unwrap_or(7), crate::model::now_ts());
    let mut data = blocking(&st.store, move |s| report::gather(s, days, now)).await?;
    // Same device cap as the Devices page and its CSV; alerts, findings and compliance are not
    // capped (this is a browsing limit, not a monitoring one — see the `assets` handler).
    let cap = effective_license(st).device_cap;
    if cap.is_some() {
        let keep = crate::license::keep_within_cap(&data.devices.iter().map(|d| d.asset.id).collect::<Vec<_>>(), cap);
        data.devices.retain(|d| keep.contains(&d.asset.id));
    }
    Ok(data)
}

fn csv_response(name: &str, body: String) -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/csv; charset=utf-8".to_string()),
            (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{name}\"")),
        ],
        body,
    )
        .into_response()
}

async fn export_assets(State(st): State<AppState>, Query(q): Query<DaysQuery>) -> Result<Response, ApiError> {
    Ok(csv_response("denis-devices.csv", report::assets_csv(&gather(&st, q.days).await?)))
}

async fn export_alerts(State(st): State<AppState>, Query(q): Query<DaysQuery>) -> Result<Response, ApiError> {
    Ok(csv_response("denis-alerts.csv", report::alerts_csv(&gather(&st, q.days).await?)))
}

/// Self-contained, printable report. Inline styles only, so it gets its own CSP.
async fn report_page(State(st): State<AppState>, Query(q): Query<DaysQuery>) -> Result<Response, ApiError> {
    let html = report::html(&gather(&st, q.days).await?);
    Ok((
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8".to_string()),
            (
                header::CONTENT_SECURITY_POLICY,
                "default-src 'none'; style-src 'unsafe-inline'; img-src data:; frame-ancestors 'none'; base-uri 'none'".to_string(),
            ),
        ],
        html,
    )
        .into_response())
}

/// A documentation screenshot.
async fn docs_image(Path(file): Path<String>) -> Response {
    match crate::docs::image(&file) {
        Some(bytes) => ([(header::CONTENT_TYPE, "image/png".to_string()), (header::CACHE_CONTROL, "private, max-age=3600".to_string())], bytes).into_response(),
        None => (StatusCode::NOT_FOUND, "no such image").into_response(),
    }
}

/// One page of the built-in documentation (sign-in required, like the console).
async fn docs_page(State(st): State<AppState>, Path(page): Path<String>, Query(q): Query<HashMap<String, String>>) -> Result<Response, ApiError> {
    let brand = blocking(&st.store, |s| crate::branding::load(s)).await?;
    Ok(match crate::docs::page(&page, &brand, q.get("lang").map(String::as_str)) {
        Some(html) => (
            [
                (header::CONTENT_TYPE, "text/html; charset=utf-8".to_string()),
                (header::CONTENT_SECURITY_POLICY, "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'".to_string()),
            ],
            html,
        )
            .into_response(),
        None => (StatusCode::NOT_FOUND, "no such page").into_response(),
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
    use crate::engine::Shared;
    use crate::model::{AssetMeta, Mac};
    use crate::store::sqlite::SqliteStore;
    use crate::store::Store;
    use axum::body::Body;
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use tower::ServiceExt;

    /// App with login disabled: the pre-existing API tests exercise handlers, not auth.
    fn app(loopback_only: bool) -> (Router, Arc<dyn Store>) {
        app_with(loopback_only, true)
    }

    fn app_with(loopback_only: bool, no_auth: bool) -> (Router, Arc<dyn Store>) {
        app_with_shared(loopback_only, no_auth, crate::engine::test_shared())
    }

    fn app_with_shared(loopback_only: bool, no_auth: bool, shared: Arc<Shared>) -> (Router, Arc<dyn Store>) {
        let store: Arc<dyn Store> = Arc::new(SqliteStore::open_in_memory().unwrap());
        let auth = Arc::new(crate::auth::Auth::new(store.clone()));
        (
            router(AppState { store: store.clone(), shared, loopback_only, allowed_hosts: vec![], auth, no_auth, secure_cookie: false, license: crate::license::load(None, &*store) }),
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
    async fn per_site_access_restricts_a_viewer_but_never_an_admin_and_an_admin_can_set_it() {
        let (app, store, [viewer, _editor, admin]) = secured().await;
        let mut local_asset = Asset::new(Mac([0x02, 0, 0, 0, 0, 1]), 10);
        store.save_asset(&mut local_asset).unwrap();
        let mut site_a_asset = Asset { agent_id: Some("site-a".into()), ..Asset::new(Mac([0x02, 0, 0, 0, 0, 2]), 10) };
        store.save_asset(&mut site_a_asset).unwrap();
        store.upsert_agent(&crate::model::AgentInfo {
            id: "site-a".into(), name: "Site A".into(), site: None, version: "0.7.0".into(), subnet: "10.0.0.0/24".into(),
            first_seen: 10, last_report_at: 10, last_run_id: String::new(), last_seq: 0,
        }).unwrap();
        let vera_id = store.find_user("vera").unwrap().unwrap().user.id;

        // before any grant: a viewer sees both sites, same as always
        let (_, _, v) = send(&app, req("GET", "/api/assets", Some(&viewer), None)).await;
        assert_eq!(v.as_array().unwrap().len(), 2);

        // an admin restricts the viewer to no access on site-a
        let (st, _, _) = send(&app, req("PUT", &format!("/api/users/{vera_id}/site-access"), Some(&admin), Some(serde_json::json!({"grants": [["site-a", "none"]]})))).await;
        assert_eq!(st, StatusCode::NO_CONTENT);

        // the viewer no longer sees site-a's device, but still sees the local one
        let (_, _, v) = send(&app, req("GET", "/api/assets", Some(&viewer), None)).await;
        let macs: Vec<_> = v.as_array().unwrap().iter().map(|a| a["mac"].as_str().unwrap().to_string()).collect();
        assert_eq!(macs, vec![local_asset.mac.to_string()]);

        // ...and an admin is never restricted, regardless of grants
        let (_, _, v) = send(&app, req("GET", "/api/assets", Some(&admin), None)).await;
        assert_eq!(v.as_array().unwrap().len(), 2);

        // the site filter's own data sources agree: /api/agents drops site-a for the viewer...
        let (_, _, v) = send(&app, req("GET", "/api/agents", Some(&viewer), None)).await;
        assert!(v.as_array().unwrap().is_empty(), "{v}");
        let (_, _, v) = send(&app, req("GET", "/api/agents", Some(&admin), None)).await;
        assert_eq!(v.as_array().unwrap().len(), 1, "{v}");
        // ...and /api/status says whether "Local" itself belongs in the site filter
        let (_, _, v) = send(&app, req("GET", "/api/status", Some(&viewer), None)).await;
        assert_eq!(v["local_readable"], true);
        let (st, _, _) = send(&app, req("PUT", &format!("/api/users/{vera_id}/site-access"), Some(&admin), Some(serde_json::json!({"grants": [["", "none"]]})))).await;
        assert_eq!(st, StatusCode::NO_CONTENT);
        let (_, _, v) = send(&app, req("GET", "/api/status", Some(&viewer), None)).await;
        assert_eq!(v["local_readable"], false);
        let (_, _, v) = send(&app, req("GET", "/api/status", Some(&admin), None)).await;
        assert_eq!(v["local_readable"], true);
        send(&app, req("PUT", &format!("/api/users/{vera_id}/site-access"), Some(&admin), Some(serde_json::json!({"grants": [["site-a", "none"]]})))).await; // restore for the assertions below

        // reading back the grants shows what was set, plus every known site
        let (_, _, v) = send(&app, req("GET", &format!("/api/users/{vera_id}/site-access"), Some(&admin), None)).await;
        assert_eq!(v["grants"][0]["site"], "site-a");
        assert_eq!(v["grants"][0]["permission"], "none");
        assert!(v["sites"].as_array().unwrap().iter().any(|s| s["site"] == "site-a"));

        // a non-admin cannot change anyone's grants
        let (st, _, _) = send(&app, req("PUT", &format!("/api/users/{vera_id}/site-access"), Some(&viewer), Some(serde_json::json!({"grants": []})))).await;
        assert_eq!(st, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn a_devices_own_endpoints_are_site_scoped_too_not_just_the_list() {
        // regression test for an IDOR: /api/assets already filtered by site, but
        // /api/assets/{id}, its /baseline and /history did not — a restricted viewer who knew
        // (or guessed, ids are sequential) another site's device id could read it directly.
        let (app, store, [viewer, editor, admin]) = secured().await;
        let mut site_a_asset = Asset { agent_id: Some("site-a".into()), ..Asset::new(Mac([0x02, 0, 0, 0, 0, 2]), 10) };
        store.save_asset(&mut site_a_asset).unwrap();
        let id = site_a_asset.id;
        store
            .upsert_agent(&crate::model::AgentInfo {
                id: "site-a".into(), name: "Site A".into(), site: None, version: "0.7.0".into(), subnet: "10.0.0.0/24".into(),
                first_seen: 10, last_report_at: 10, last_run_id: String::new(), last_seq: 0,
            })
            .unwrap();
        let vera_id = store.find_user("vera").unwrap().unwrap().user.id;
        send(&app, req("PUT", &format!("/api/users/{vera_id}/site-access"), Some(&admin), Some(serde_json::json!({"grants": [["site-a", "none"]]})))).await;

        // before restriction: reachable, same as any other device
        assert_eq!(send(&app, req("GET", &format!("/api/assets/{id}"), Some(&admin), None)).await.0, StatusCode::OK);

        // the restricted viewer gets 404, not 403: existence itself must not leak
        for uri in [format!("/api/assets/{id}"), format!("/api/assets/{id}/baseline"), format!("/api/assets/{id}/history")] {
            let (st, _, v) = send(&app, req("GET", &uri, Some(&viewer), None)).await;
            assert_eq!(st, StatusCode::NOT_FOUND, "{uri}: {v}");
        }
        // an unrestricted role (editor has no grant here) and the admin still see it
        for cookie in [&editor, &admin] {
            assert_eq!(send(&app, req("GET", &format!("/api/assets/{id}"), Some(cookie), None)).await.0, StatusCode::OK);
            assert_eq!(send(&app, req("GET", &format!("/api/assets/{id}/history"), Some(cookie), None)).await.0, StatusCode::OK);
        }
        // a nonexistent id answers exactly the same way (404) — no distinguishing signal
        assert_eq!(send(&app, req("GET", "/api/assets/999999", Some(&viewer), None)).await.0, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn merging_a_device_hides_it_from_the_list_and_its_own_findings_but_keeps_its_history() {
        let (app, store, [_viewer, editor, admin]) = secured().await;
        let mut canonical = Asset::new(Mac([0x02, 0, 0, 0, 0, 1]), 10);
        store.save_asset(&mut canonical).unwrap();
        let mut sibling = Asset::new(Mac([0x02, 0, 0, 0, 0, 2]), 10);
        store.save_asset(&mut sibling).unwrap();
        let (cid, sid) = (canonical.id, sibling.id);

        // cannot merge into itself, into a nonexistent device, or into one on another site
        assert_eq!(send(&app, req("PATCH", &format!("/api/assets/{sid}/meta"), Some(&editor), Some(serde_json::json!({"merged_into": sid})))).await.0, StatusCode::BAD_REQUEST);
        assert_eq!(send(&app, req("PATCH", &format!("/api/assets/{sid}/meta"), Some(&editor), Some(serde_json::json!({"merged_into": 999999})))).await.0, StatusCode::BAD_REQUEST);

        // merge sibling into canonical
        let (st, _, _) = send(&app, req("PATCH", &format!("/api/assets/{sid}/meta"), Some(&editor), Some(serde_json::json!({"merged_into": cid})))).await;
        assert_eq!(st, StatusCode::OK);

        // no chains: cannot merge a third device into the now-merged sibling
        let mut third = Asset::new(Mac([0x02, 0, 0, 0, 0, 3]), 10);
        store.save_asset(&mut third).unwrap();
        assert_eq!(send(&app, req("PATCH", &format!("/api/assets/{}/meta", third.id), Some(&editor), Some(serde_json::json!({"merged_into": sid})))).await.0, StatusCode::BAD_REQUEST);

        // hidden from the list...
        let (_, _, list) = send(&app, req("GET", "/api/assets", Some(&admin), None)).await;
        let ids: Vec<i64> = list.as_array().unwrap().iter().map(|a| a["id"].as_i64().unwrap()).collect();
        assert!(ids.contains(&cid) && !ids.contains(&sid), "{ids:?}");
        // ...but its own endpoint and history still work (nothing was deleted)
        assert_eq!(send(&app, req("GET", &format!("/api/assets/{sid}"), Some(&admin), None)).await.0, StatusCode::OK);

        // the canonical device's own /merged endpoint lists it, for the "unmerge" button
        let (st, _, siblings) = send(&app, req("GET", &format!("/api/assets/{cid}/merged"), Some(&admin), None)).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(siblings.as_array().unwrap().len(), 1);
        assert_eq!(siblings[0]["id"], sid);
        assert_eq!(send(&app, req("GET", &format!("/api/assets/{sid}/merged"), Some(&admin), None)).await.2.as_array().unwrap().len(), 0, "not itself a canonical device for anything");

        // unmerging brings it straight back
        send(&app, req("PATCH", &format!("/api/assets/{sid}/meta"), Some(&editor), Some(serde_json::json!({"merged_into": null})))).await;
        let (_, _, list) = send(&app, req("GET", "/api/assets", Some(&admin), None)).await;
        let ids: Vec<i64> = list.as_array().unwrap().iter().map(|a| a["id"].as_i64().unwrap()).collect();
        assert!(ids.contains(&sid), "{ids:?}");
        assert_eq!(send(&app, req("GET", &format!("/api/assets/{cid}/merged"), Some(&admin), None)).await.2.as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn a_sibling_merged_from_another_site_stays_invisible_to_someone_who_cannot_see_that_site() {
        // Same-site is enforced when a merge is *created* (see patch_meta), but a device's own
        // agent_id is not immutable afterwards (it can be re-observed on a different site later),
        // so /merged must re-check site access itself rather than trust the merge was safe.
        let (app, store, [_viewer, editor, admin]) = secured().await;
        let mut canonical = Asset::new(Mac([0x02, 0, 0, 0, 0, 1]), 10);
        store.save_asset(&mut canonical).unwrap();
        let mut sibling = Asset::new(Mac([0x02, 0, 0, 0, 0, 2]), 10);
        store.save_asset(&mut sibling).unwrap();
        let (cid, sid) = (canonical.id, sibling.id);
        let (st, _, _) = send(&app, req("PATCH", &format!("/api/assets/{sid}/meta"), Some(&editor), Some(serde_json::json!({"merged_into": cid})))).await;
        assert_eq!(st, StatusCode::OK);

        // the sibling drifts to "site-a", which eda is explicitly denied (no grant at all would
        // mean full access by default: see access.rs's "opt-in" doc comment)
        sibling.agent_id = Some("site-a".into());
        store.save_asset(&mut sibling).unwrap();
        let eda_id = store.find_user("eda").unwrap().unwrap().user.id;
        send(&app, req("PUT", &format!("/api/users/{eda_id}/site-access"), Some(&admin), Some(serde_json::json!({"grants": [["site-a", "none"]]})))).await;

        // an admin still sees it (not site-restricted)...
        let (_, _, v) = send(&app, req("GET", &format!("/api/assets/{cid}/merged"), Some(&admin), None)).await;
        assert_eq!(v.as_array().unwrap().len(), 1);
        // ...but eda, who has no grant for site-a, gets nothing back for the same canonical device
        let (st, _, v) = send(&app, req("GET", &format!("/api/assets/{cid}/merged"), Some(&editor), None)).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(v.as_array().unwrap().len(), 0, "the site-a sibling must not leak its MAC/timestamps to a caller restricted to other sites");
    }

    #[tokio::test]
    async fn a_read_only_site_grant_blocks_writes_but_not_reads() {
        let (app, store, [viewer, editor, admin]) = secured().await;
        let mut a = Asset { agent_id: Some("site-a".into()), ..Asset::new(Mac([0x02, 0, 0, 0, 0, 9]), 10) };
        store.save_asset(&mut a).unwrap();
        let mut e = crate::model::Event { agent_id: Some("site-a".into()), asset_id: a.id, kind: "new_device".into(), timestamp: now_ts(), severity: "high".into(), score: 80, acked: false, raw_details: serde_json::json!({}), id: 0 };
        store.insert_event(&mut e).unwrap();
        let eda_id = store.find_user("eda").unwrap().unwrap().user.id;

        let (st, _, _) = send(&app, req("PUT", &format!("/api/users/{eda_id}/site-access"), Some(&admin), Some(serde_json::json!({"grants": [["site-a", "read"]]})))).await;
        assert_eq!(st, StatusCode::NO_CONTENT);

        // eda (editor) can still see the alert on site-a (read is granted)...
        let (_, _, v) = send(&app, req("GET", "/api/alerts", Some(&editor), None)).await;
        assert_eq!(v.as_array().unwrap().len(), 1);
        // ...but cannot acknowledge it (read, not write)
        let (st, _, _) = send(&app, req("POST", &format!("/api/alerts/{}/ack", e.id), Some(&editor), None)).await;
        assert_eq!(st, StatusCode::FORBIDDEN);
        assert!(!store.get_event(e.id).unwrap().unwrap().acked);
        let _ = viewer;
    }

    #[tokio::test]
    async fn the_overview_tab_toggle_is_admin_only_and_reflected_in_status() {
        let (app, _store, [viewer, editor, admin]) = secured().await;

        // off by default
        let (_, _, v) = send(&app, req("GET", "/api/status", Some(&viewer), None)).await;
        assert_eq!(v["msp_overview"], false);

        // only an admin may turn it on
        assert_eq!(send(&app, req("PUT", "/api/msp-overview", Some(&viewer), Some(serde_json::json!({"enabled": true})))).await.0, StatusCode::FORBIDDEN);
        assert_eq!(send(&app, req("PUT", "/api/msp-overview", Some(&editor), Some(serde_json::json!({"enabled": true})))).await.0, StatusCode::FORBIDDEN);
        let (st, _, _) = send(&app, req("PUT", "/api/msp-overview", Some(&admin), Some(serde_json::json!({"enabled": true})))).await;
        assert_eq!(st, StatusCode::NO_CONTENT);

        // ...and everyone (any signed-in role) now sees it is on
        for cookie in [&viewer, &editor, &admin] {
            let (_, _, v) = send(&app, req("GET", "/api/status", Some(cookie), None)).await;
            assert_eq!(v["msp_overview"], true, "{cookie}");
        }

        let (st, _, _) = send(&app, req("PUT", "/api/msp-overview", Some(&admin), Some(serde_json::json!({"enabled": false})))).await;
        assert_eq!(st, StatusCode::NO_CONTENT);
        let (_, _, v) = send(&app, req("GET", "/api/status", Some(&viewer), None)).await;
        assert_eq!(v["msp_overview"], false);
    }

    #[tokio::test]
    async fn a_license_can_be_pasted_into_settings_by_an_admin_only_and_removed_again() {
        let (app, _store, [viewer, editor, admin]) = secured().await;
        let put = |cookie: &str, body: &str| {
            axum::http::Request::put("/api/license").header("host", "localhost").header("x-denis", "1")
                .header("cookie", format!("{SESSION_COOKIE}={cookie}")).header("content-type", "text/plain")
                .body(Body::from(body.to_string())).unwrap()
        };

        // before anything is installed: Community, readable by any signed-in role
        let (st, _, v) = send(&app, req("GET", "/api/license", Some(&viewer), None)).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(v["installed"], false);
        assert_eq!(v["device_cap"], 100);

        // garbage is refused, with a reason, and nothing is stored
        let (st, _, v) = send(&app, put(&admin, "not a license file")).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        assert!(!v["error"].as_str().unwrap().is_empty());
        let (_, _, v) = send(&app, req("GET", "/api/license", Some(&viewer), None)).await;
        assert_eq!(v["installed"], false);

        // only an admin may install or remove one
        assert_eq!(send(&app, put(&viewer, "x")).await.0, StatusCode::FORBIDDEN);
        assert_eq!(send(&app, put(&editor, "x")).await.0, StatusCode::FORBIDDEN);
        assert_eq!(send(&app, req("DELETE", "/api/license", Some(&editor), None)).await.0, StatusCode::FORBIDDEN);

        // removing one that was never installed is a harmless no-op, still Community afterwards
        let (st, _, v) = send(&app, req("DELETE", "/api/license", Some(&admin), None)).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(v["installed"], false);
    }

    #[tokio::test]
    async fn several_mirror_interfaces_can_be_configured_from_settings_by_an_admin_only_and_cleared_again() {
        let (app, store, [viewer, editor, admin]) = secured().await;

        // any signed-in role can see the candidates and the (empty) configuration
        let (st, _, v) = send(&app, req("GET", "/api/interfaces", Some(&viewer), None)).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(v["configured_iface"], serde_json::Value::Null);
        assert_eq!(v["configured_mirror_ifaces"], serde_json::Value::Null);
        assert!(v["mains"].is_array() && v["all"].is_array());

        // a name that does not exist on this machine is refused (it would otherwise crash-loop
        // the capture engine on the next restart) and never saved
        let up = crate::net::list_all_up().unwrap();
        let fake = serde_json::json!({"iface": "definitely-not-a-real-nic-xyz"});
        assert_eq!(send(&app, req("PUT", "/api/interfaces", Some(&admin), Some(fake))).await.0, StatusCode::BAD_REQUEST);
        let (_, _, v) = send(&app, req("GET", "/api/interfaces", Some(&viewer), None)).await;
        assert_eq!(v["configured_iface"], serde_json::Value::Null, "the rejected name must not have been saved");

        assert!(up.len() >= 2, "this test needs at least two up network interfaces on the host to exercise real names: {up:?}");
        let (iface, m1, m2) = (up[0].clone(), up[1].clone(), up.get(2).cloned().unwrap_or_else(|| up[1].clone()));

        // only an admin may set it; more than one mirror interface is fine (one per VLAN, say)
        let body = serde_json::json!({"iface": iface, "mirror_ifaces": [m1, m2]});
        assert_eq!(send(&app, req("PUT", "/api/interfaces", Some(&viewer), Some(body.clone()))).await.0, StatusCode::FORBIDDEN);
        assert_eq!(send(&app, req("PUT", "/api/interfaces", Some(&editor), Some(body.clone()))).await.0, StatusCode::FORBIDDEN);
        assert_eq!(send(&app, req("PUT", "/api/interfaces", Some(&admin), Some(body))).await.0, StatusCode::NO_CONTENT);

        // the choice is now reflected, for everyone, and it is persisted (not just cached)
        let (_, _, v) = send(&app, req("GET", "/api/interfaces", Some(&viewer), None)).await;
        assert_eq!(v["configured_iface"].as_str(), Some(iface.as_str()));
        assert_eq!(crate::capture_config::load(&*store).iface.as_deref(), Some(iface.as_str()));

        // a mirror interface cannot be the same as the discovery one
        let same = serde_json::json!({"iface": iface, "mirror_ifaces": [iface]});
        assert_eq!(send(&app, req("PUT", "/api/interfaces", Some(&admin), Some(same))).await.0, StatusCode::BAD_REQUEST);

        // clearing the mirror interfaces (an explicit empty list) leaves the main one alone
        let clear_mirrors = serde_json::json!({"iface": iface, "mirror_ifaces": []});
        assert_eq!(send(&app, req("PUT", "/api/interfaces", Some(&admin), Some(clear_mirrors))).await.0, StatusCode::NO_CONTENT);
        let (_, _, v) = send(&app, req("GET", "/api/interfaces", Some(&viewer), None)).await;
        assert_eq!(v["configured_iface"].as_str(), Some(iface.as_str()));
        assert_eq!(v["configured_mirror_ifaces"].as_array().unwrap().len(), 0);

        let audit = send(&app, req("GET", "/api/audit", Some(&admin), None)).await.2.to_string();
        assert!(audit.contains("interfaces.set"), "{audit}");
    }

    #[tokio::test]
    async fn siem_settings_are_admin_only_validated_and_a_bad_test_target_reports_its_own_error() {
        let (app, _store, [viewer, editor, admin]) = secured().await;

        // any signed-in role can see the (disabled by default) settings
        let (st, _, v) = send(&app, req("GET", "/api/siem", Some(&viewer), None)).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(v["enabled"], false);

        // only an admin may change it
        let body = serde_json::json!({"enabled": true, "transport": "udp", "host": "siem.example.com", "port": 514, "format": "leef", "streams": {"events": true, "findings": true, "audit": false}, "insecure_tls": false});
        assert_eq!(send(&app, req("PUT", "/api/siem", Some(&viewer), Some(body.clone()))).await.0, StatusCode::FORBIDDEN);
        assert_eq!(send(&app, req("PUT", "/api/siem", Some(&editor), Some(body.clone()))).await.0, StatusCode::FORBIDDEN);
        assert_eq!(send(&app, req("PUT", "/api/siem", Some(&admin), Some(body))).await.0, StatusCode::NO_CONTENT);

        let (_, _, v) = send(&app, req("GET", "/api/siem", Some(&viewer), None)).await;
        assert_eq!((v["enabled"].as_bool(), v["format"].as_str(), v["streams"]["findings"].as_bool()), (Some(true), Some("leef"), Some(true)));

        // enabling it with no stream chosen at all is rejected, and nothing is changed
        let no_streams = serde_json::json!({"enabled": true, "transport": "udp", "host": "siem.example.com", "port": 514, "format": "cef", "streams": {"events": false, "findings": false, "audit": false}, "insecure_tls": false});
        assert_eq!(send(&app, req("PUT", "/api/siem", Some(&admin), Some(no_streams))).await.0, StatusCode::BAD_REQUEST);
        assert_eq!(send(&app, req("GET", "/api/siem", Some(&viewer), None)).await.2["format"], "leef", "the bad request must not have been saved");

        // the Test button uses whatever is in the form, not what was saved, and reports failure plainly
        let unreachable = serde_json::json!({"transport": "tcp", "host": "127.0.0.1", "port": 1, "format": "json"});
        let (st, _, v) = send(&app, req("POST", "/api/siem/test", Some(&admin), Some(unreachable))).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(v["ok"], false);
        assert!(v["error"].as_str().is_some());
        assert_eq!(send(&app, req("POST", "/api/siem/test", Some(&editor), Some(serde_json::json!({"transport": "udp", "host": "x", "port": 514, "format": "cef"})))).await.0, StatusCode::FORBIDDEN);

        let audit = send(&app, req("GET", "/api/audit", Some(&admin), None)).await.2.to_string();
        assert!(audit.contains("siem.settings") && audit.contains("siem.test"), "{audit}");
    }

    #[tokio::test]
    async fn data_retention_is_admin_only_defaults_sensibly_and_is_validated() {
        let (app, _store, [viewer, editor, admin]) = secured().await;
        for u in [&viewer, &editor] {
            assert_eq!(send(&app, req("GET", "/api/retention", Some(u), None)).await.0, StatusCode::FORBIDDEN);
        }
        let (st, _, v) = send(&app, req("GET", "/api/retention", Some(&admin), None)).await;
        assert_eq!(st, StatusCode::OK);
        assert!(v["days"].as_i64().unwrap() > 0, "a sensible default before anything is saved");

        assert_eq!(send(&app, req("PUT", "/api/retention", Some(&editor), Some(serde_json::json!({"days": 30})))).await.0, StatusCode::FORBIDDEN);
        assert_eq!(send(&app, req("PUT", "/api/retention", Some(&admin), Some(serde_json::json!({"days": 0})))).await.0, StatusCode::BAD_REQUEST);
        assert_eq!(send(&app, req("PUT", "/api/retention", Some(&admin), Some(serde_json::json!({"days": 4000})))).await.0, StatusCode::BAD_REQUEST);
        assert_eq!(send(&app, req("PUT", "/api/retention", Some(&admin), Some(serde_json::json!({"days": 30})))).await.0, StatusCode::NO_CONTENT);
        assert_eq!(send(&app, req("GET", "/api/retention", Some(&admin), None)).await.2["days"], 30);

        let audit = send(&app, req("GET", "/api/audit", Some(&admin), None)).await.2.to_string();
        assert!(audit.contains("retention.settings"), "{audit}");
    }

    #[tokio::test]
    async fn the_community_edition_caps_the_devices_list_and_its_csv_but_not_alerts() {
        let (app, store) = app(true);
        for i in 0..105u8 {
            let mut a = Asset::new(Mac([0x02, 0, 0, 0, 0, i]), 10 + i as i64);
            store.save_asset(&mut a).unwrap();
        }
        let (code, v) = get_json(&app, "/api/assets", "localhost:8080").await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(v.as_array().unwrap().len(), crate::license::COMMUNITY_DEVICE_CAP as usize);

        // the real total is still reported, so the console can show "105 devices, 100 shown"
        let (_, status) = get_json(&app, "/api/status", "localhost:8080").await;
        assert_eq!(status["asset_count"], 105);
        assert_eq!(status["license"]["device_cap"], crate::license::COMMUNITY_DEVICE_CAP);
        assert_eq!(status["license"]["over_cap"], true);

        // the CSV export respects the same cap (one header line + up to the cap data lines)
        let req = axum::http::Request::get("/api/export/assets.csv").header("host", "localhost").body(Body::empty()).unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = String::from_utf8(axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap().to_vec()).unwrap();
        assert_eq!(body.lines().count() - 1, crate::license::COMMUNITY_DEVICE_CAP as usize);

        // which 100 are shown is stable across calls (the lowest ids, not whichever 100 happen to sort first)
        let (_, v2) = get_json(&app, "/api/assets", "localhost:8080").await;
        let ids: std::collections::HashSet<_> = v.as_array().unwrap().iter().map(|a| a["id"].clone()).collect();
        let ids2: std::collections::HashSet<_> = v2.as_array().unwrap().iter().map(|a| a["id"].clone()).collect();
        assert_eq!(ids, ids2);
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
            .header("x-denis", "1")
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

        let post = |path: String| axum::http::Request::post(path).header("host", "localhost").header("x-denis", "1").body(Body::empty()).unwrap();
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

        // baseline: null until one exists, then destinations come back recent-first
        let (code, v) = get_json(&app, &format!("/api/assets/{}/baseline", a.id), "localhost").await;
        assert_eq!((code, v.is_null()), (StatusCode::OK, true));
        let mut b = Baseline::new(a.id, 1);
        b.typical_destinations.insert("1.1.1.1".into(), DestStat { first_seen: 1, last_seen: 5, bytes: 9, bytes_out: 9, bytes_in: 0 });
        b.typical_destinations.insert("2.2.2.2".into(), DestStat { first_seen: 1, last_seen: 50, bytes: 9, bytes_out: 9, bytes_in: 0 });
        store.save_baseline(&b).unwrap();
        let (code, v) = get_json(&app, &format!("/api/assets/{}/baseline", a.id), "localhost").await;
        assert_eq!((code, v["destinations"][0]["ip"].as_str(), v["destination_count"].as_i64()), (StatusCode::OK, Some("2.2.2.2"), Some(2)));

        // agents
        assert!(get_json(&app, "/api/agents", "localhost").await.1.as_array().unwrap().is_empty());
        store.upsert_agent(&AgentInfo { id: "site-b".into(), name: "Office".into(), site: None, version: "t".into(), subnet: "10.0.0.0/24".into(), first_seen: 1, last_report_at: 2, last_run_id: "r".into(), last_seq: 1 }).unwrap();
        assert_eq!(get_json(&app, "/api/agents", "localhost").await.1[0]["id"], "site-b");
    }

    #[tokio::test]
    async fn assets_carry_a_risk_score_and_open_alerts_raise_it() {
        use crate::model::{Event, OpenPort};
        let (app, store) = app(true);
        let mut a = Asset::new(Mac([0x00, 0x1b, 0x63, 1, 2, 3]), 10);
        a.vendor = Some("Acme".into());
        a.device_type = "iot".into();
        a.open_ports = vec![OpenPort { port: 23, proto: "tcp".into(), service: None }];
        store.save_asset(&mut a).unwrap();
        let (_, v) = get_json(&app, "/api/assets", "localhost").await;
        assert_eq!(v[0]["risk"]["score"], 40);
        assert_eq!(v[0]["risk"]["level"], "medium");
        assert!(v[0]["risk"]["factors"][0].as_str().unwrap().contains("Telnet"));
        let mut e = Event {
            id: 0, agent_id: None, asset_id: a.id, kind: "arp_conflict".into(), timestamp: crate::model::now_ts(),
            severity: "high".into(), score: 95, acked: false, raw_details: serde_json::json!({}),
        };
        store.insert_event(&mut e).unwrap();
        let (_, v) = get_json(&app, &format!("/api/assets/{}", a.id), "localhost").await;
        assert_eq!(v["risk"]["level"], "high");
        // acknowledging removes the alert's contribution
        store.set_event_acked(e.id, true).unwrap();
        assert_eq!(get_json(&app, &format!("/api/assets/{}", a.id), "localhost").await.1["risk"]["score"], 40);
    }

    #[tokio::test]
    async fn trends_exports_and_report_are_served_safely() {
        use crate::model::Metric;
        let (app, store) = app(true);
        let mut a = Asset::new(Mac([0x00, 0x1b, 0x63, 1, 2, 3]), 10);
        a.hostnames = vec!["=HYPERLINK(\"http://evil\")".into()];
        store.save_asset(&mut a).unwrap();
        let now = crate::model::now_ts();
        store.insert_metrics(&[
            Metric { ts: now - 600, agent_id: "".into(), devices_total: 3, devices_online: 2, bytes_out: 10, bytes_in: 1, alerts: 0 },
            Metric { ts: now - 300, agent_id: "b".into(), devices_total: 1, devices_online: 1, bytes_out: 5, bytes_in: 1, alerts: 1 },
        ]).unwrap();

        let (code, v) = get_json(&app, "/api/trends?hours=1", "localhost").await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(v["points"].as_array().unwrap().len(), 2);
        assert_eq!(get_json(&app, "/api/trends?hours=1&agent=b", "localhost").await.1["points"].as_array().unwrap().len(), 1);
        assert_eq!(get_json(&app, "/api/trends?hours=1&agent=local", "localhost").await.1["points"][0]["devices_total"], 3);

        let req = |p: &str| axum::http::Request::get(p).header("host", "localhost").body(Body::empty()).unwrap();
        let resp = app.clone().oneshot(req("/api/export/assets.csv")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers()[header::CONTENT_TYPE].to_str().unwrap().starts_with("text/csv"));
        assert!(resp.headers()[header::CONTENT_DISPOSITION].to_str().unwrap().contains("denis-devices.csv"));
        let body = String::from_utf8(axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap().to_vec()).unwrap();
        assert!(body.contains("\"'=HYPERLINK("), "formula neutralised: {body}");

        let resp = app.clone().oneshot(req("/report?days=3")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let csp = resp.headers()[header::CONTENT_SECURITY_POLICY].to_str().unwrap().to_string();
        assert!(csp.contains("default-src 'none'") && csp.contains("style-src 'unsafe-inline'") && !csp.contains("script-src"));
        let html = String::from_utf8(axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap().to_vec()).unwrap();
        assert!(html.contains("Network report") && html.contains("Last 3 day(s)"));
        assert!(!html.contains("<script"));
        // the normal UI keeps the strict default policy
        let idx = app.oneshot(req("/")).await.unwrap();
        assert!(idx.headers()[header::CONTENT_SECURITY_POLICY].to_str().unwrap().contains("default-src 'self'"));
    }

    #[tokio::test]
    async fn top_talkers_leaves_out_the_gateway_and_a_hand_picked_device() {
        use crate::model::{Baseline, DestStat};
        let (app, store) = app(true);
        let mut gw = Asset::new(Mac([0, 0, 0, 0, 0, 1]), 0);
        gw.is_gateway = true;
        store.save_asset(&mut gw).unwrap();
        let mut noisy = Asset::new(Mac([0, 0, 0, 0, 0, 2]), 0);
        store.save_asset(&mut noisy).unwrap();
        let mut quiet = Asset::new(Mac([0, 0, 0, 0, 0, 3]), 0);
        store.save_asset(&mut quiet).unwrap();
        for (id, out) in [(gw.id, 900), (noisy.id, 500), (quiet.id, 10)] {
            let mut b = Baseline::new(id, 1);
            b.typical_destinations.insert("1.1.1.1".into(), DestStat { first_seen: 1, last_seen: 1, bytes: out, bytes_out: out, bytes_in: 0 });
            store.save_baseline(&b).unwrap();
        }

        // before any manual exclusion: the gateway is already left out automatically
        let (code, v) = get_json(&app, "/api/top-talkers", "localhost").await;
        assert_eq!(code, StatusCode::OK);
        let ids: Vec<i64> = v["talkers"].as_array().unwrap().iter().map(|t| t["asset_id"].as_i64().unwrap()).collect();
        assert!(ids.contains(&noisy.id) && ids.contains(&quiet.id) && !ids.contains(&gw.id));
        assert_eq!(v["excluded"], serde_json::json!([]));

        // excluding "noisy" by hand removes it too, and the list is remembered
        let put = axum::http::Request::put("/api/top-talkers/excluded")
            .header("host", "localhost")
            .header(header::CONTENT_TYPE, "application/json")
            .header("x-denis", "1")
            .body(Body::from(serde_json::json!({ "excluded": [noisy.id] }).to_string()))
            .unwrap();
        assert_eq!(app.clone().oneshot(put).await.unwrap().status(), StatusCode::OK);
        let (_, v) = get_json(&app, "/api/top-talkers", "localhost").await;
        let ids: Vec<i64> = v["talkers"].as_array().unwrap().iter().map(|t| t["asset_id"].as_i64().unwrap()).collect();
        assert!(!ids.contains(&noisy.id) && ids.contains(&quiet.id));
        assert_eq!(v["excluded"], serde_json::json!([noisy.id]));
    }

    #[tokio::test]
    async fn software_groups_the_fleet_by_product_and_version_and_respects_site_access() {
        let (app, store) = app(true);
        let mut a = Asset::new(Mac([0, 0, 0, 0, 0, 1]), 0);
        a.fingerprint.identity.insert("banner.ssh".into(), "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6".into());
        store.save_asset(&mut a).unwrap();
        let mut b = Asset::new(Mac([0, 0, 0, 0, 0, 2]), 0);
        b.fingerprint.identity.insert("banner.ssh".into(), "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6".into());
        store.save_asset(&mut b).unwrap();
        let mut c = Asset::new(Mac([0, 0, 0, 0, 0, 3]), 0);
        c.fingerprint.identity.insert("banner.ssh".into(), "SSH-2.0-OpenSSH_9.6p1".into());
        store.save_asset(&mut c).unwrap();
        let mut none = Asset::new(Mac([0, 0, 0, 0, 0, 4]), 0);
        store.save_asset(&mut none).unwrap();

        let (code, v) = get_json(&app, "/api/software", "localhost").await;
        assert_eq!(code, StatusCode::OK);
        let rows = v["software"].as_array().unwrap();
        assert_eq!(rows.len(), 2, "one row per distinct product+version: {rows:?}");
        let old = rows.iter().find(|r| r["version"] == "8.9p1").unwrap();
        assert_eq!(old["product"], "OpenSSH");
        let mut ids: Vec<i64> = old["asset_ids"].as_array().unwrap().iter().map(|x| x.as_i64().unwrap()).collect();
        ids.sort_unstable();
        assert_eq!(ids, vec![a.id, b.id]);
        let newer = rows.iter().find(|r| r["version"] == "9.6p1").unwrap();
        assert_eq!(newer["asset_ids"].as_array().unwrap(), &vec![serde_json::json!(c.id)]);
        // a device with no readable banner contributes no row at all -- not a null/empty one
        assert!(rows.iter().all(|r| r["asset_ids"].as_array().unwrap().iter().all(|x| x.as_i64().unwrap() != none.id)));
    }

    // ------------------------------------------------------------ auth / RBAC

    /// A request as a browser would send it: Host, session cookie, CSRF header.
    fn req(method: &str, uri: &str, cookie: Option<&str>, body: Option<serde_json::Value>) -> axum::http::Request<Body> {
        let mut b = axum::http::Request::builder().method(method).uri(uri).header("host", "localhost");
        if let Some(c) = cookie {
            b = b.header("cookie", format!("{SESSION_COOKIE}={c}"));
        }
        if method != "GET" {
            b = b.header("x-denis", "1");
        }
        match body {
            Some(v) => b.header("content-type", "application/json").body(Body::from(v.to_string())).unwrap(),
            None => b.body(Body::empty()).unwrap(),
        }
    }

    async fn send(app: &Router, r: axum::http::Request<Body>) -> (StatusCode, axum::http::HeaderMap, serde_json::Value) {
        let resp = app.clone().oneshot(r).await.unwrap();
        let (st, h) = (resp.status(), resp.headers().clone());
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        (st, h, serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null))
    }

    fn cookie_of(h: &axum::http::HeaderMap) -> String {
        h[header::SET_COOKIE].to_str().unwrap().split(';').next().unwrap().split_once('=').unwrap().1.to_string()
    }

    /// An app with real login and one user per role; returns each user's session cookie.
    async fn secured() -> (Router, Arc<dyn Store>, [String; 3]) {
        secured_with(crate::engine::test_shared()).await
    }

    async fn secured_with(shared: Arc<Shared>) -> (Router, Arc<dyn Store>, [String; 3]) {
        let (app, store) = app_with_shared(true, false, shared);
        let auth = crate::auth::Auth::new(store.clone());
        let mut cookies = Vec::new();
        for (name, role) in [("vera", "viewer"), ("eda", "editor"), ("adam", "admin")] {
            store.create_user(name, &crate::auth::hash_password("a-long-passphrase-1").unwrap(), role, false, 0).unwrap();
            let (st, h, _) = send(&app, req("POST", "/api/auth/login", None, Some(serde_json::json!({"username": name, "password": "a-long-passphrase-1"})))).await;
            assert_eq!(st, StatusCode::OK, "{name}");
            cookies.push(cookie_of(&h));
        }
        let _ = auth;
        (app, store, [cookies.remove(0), cookies.remove(0), cookies.remove(0)])
    }

    #[test]
    fn required_role_table() {
        use axum::http::Method as M;
        for (m, p, want) in [
            (M::GET, "/api/assets", "viewer"), (M::GET, "/report", "viewer"), (M::GET, "/api/export/assets.csv", "viewer"),
            (M::POST, "/api/alerts/1/ack", "editor"), (M::PATCH, "/api/assets/1/meta", "editor"), (M::POST, "/api/assets", "editor"),
            (M::POST, "/api/assets/import", "editor"), (M::POST, "/api/scan", "editor"), (M::DELETE, "/api/assets/1", "admin"),
            (M::GET, "/api/users", "admin"), (M::POST, "/api/users", "admin"), (M::GET, "/api/audit", "admin"),
            (M::GET, "/api/agent-tokens", "admin"), (M::GET, "/api/api-tokens", "admin"), (M::DELETE, "/api/api-tokens/1", "admin"), (M::DELETE, "/api/agent-tokens/x", "admin"),
            (M::PUT, "/api/branding", "admin"), (M::PUT, "/api/branding/logo", "admin"), (M::DELETE, "/api/branding/logo", "admin"),
            (M::GET, "/api/branding", "viewer"), (M::GET, "/api/backups", "admin"), (M::GET, "/api/backups/denis-auto-x.db", "admin"), (M::POST, "/api/backups", "admin"), (M::GET, "/api/system", "viewer"), (M::POST, "/api/reports", "editor"), (M::GET, "/api/reports/3", "viewer"), (M::PUT, "/api/reports/settings", "admin"), (M::DELETE, "/api/reports/3", "admin"), (M::GET, "/api/rules", "viewer"), (M::PUT, "/api/rules", "admin"), (M::DELETE, "/api/rules", "admin"),
            (M::POST, "/api/auth/password", "viewer"), (M::POST, "/api/auth/logout", "viewer"),
            (M::GET, "/api/retention", "admin"), (M::PUT, "/api/retention", "admin"),
        ] {
            assert_eq!(required_role(&m, p), want, "{m} {p}");
        }
    }

    #[tokio::test]
    async fn everything_but_the_shell_and_login_needs_a_session() {
        let (app, _store, _) = secured().await;
        for uri in ["/api/assets", "/api/status", "/api/alerts", "/api/users", "/api/audit", "/api/export/assets.csv", "/report", "/docs/index", "/docs/", "/api/meta/options", "/api/findings", "/api/compliance", "/api/update", "/api/rules", "/api/channels", "/api/maintenance", "/api/trends?hours=1", "/api/auth/me"] {
            let (st, _, v) = send(&app, req("GET", uri, None, None)).await;
            assert_eq!(st, StatusCode::UNAUTHORIZED, "{uri}");
            assert_eq!(v["code"], "unauthenticated");
        }
        for (m, uri) in [("POST", "/api/scan"), ("POST", "/api/alerts/1/ack"), ("PATCH", "/api/assets/1/meta"), ("POST", "/api/assets")] {
            assert_eq!(send(&app, req(m, uri, None, Some(serde_json::json!({})))).await.0, StatusCode::UNAUTHORIZED, "{m} {uri}");
        }
        // public: the UI shell (it carries no data), liveness, and the login call itself
        for uri in ["/", "/app.js", "/style.css", "/api/health"] {
            assert_eq!(send(&app, req("GET", uri, None, None)).await.0, StatusCode::OK, "{uri}");
        }
        // garbage or forged cookies are just "not logged in"
        for c in ["", "x", &"0".repeat(64), &"g".repeat(64)] {
            assert_eq!(send(&app, req("GET", "/api/assets", Some(c), None)).await.0, StatusCode::UNAUTHORIZED, "{c:?}");
        }
    }

    #[tokio::test]
    async fn login_sets_a_hardened_cookie_and_gives_no_hints() {
        let (app, store) = app_with(true, false);
        store.create_user("vera", &crate::auth::hash_password("a-long-passphrase-1").unwrap(), "viewer", false, 0).unwrap();
        let login = |u: &str, p: &str| req("POST", "/api/auth/login", None, Some(serde_json::json!({"username": u, "password": p})));
        let (st, h, v) = send(&app, login("vera", "a-long-passphrase-1")).await;
        assert_eq!(st, StatusCode::OK);
        let c = h[header::SET_COOKIE].to_str().unwrap().to_string();
        assert!(c.starts_with("denis_session=") && c.contains("HttpOnly") && c.contains("SameSite=Strict") && c.contains("Path=/"), "{c}");
        assert!(!c.contains("Secure"), "Secure only behind TLS");
        assert_eq!(v["user"]["username"], "vera");
        assert!(v["user"].get("password_hash").is_none(), "hashes never leave the server: {v}");
        // wrong password and unknown user are indistinguishable
        let (s1, _, e1) = send(&app, login("vera", "nope")).await;
        let (s2, _, e2) = send(&app, login("nobody", "nope")).await;
        assert_eq!((s1, s2), (StatusCode::UNAUTHORIZED, StatusCode::UNAUTHORIZED));
        assert_eq!(e1, e2);
        // login is a state change: the CSRF header is required
        let no_csrf = axum::http::Request::post("/api/auth/login").header("host", "localhost").header("content-type", "application/json")
            .body(Body::from(r#"{"username":"vera","password":"a-long-passphrase-1"}"#)).unwrap();
        assert_eq!(send(&app, no_csrf).await.0, StatusCode::FORBIDDEN);
        // absurdly long input is refused cheaply
        assert_eq!(send(&app, login(&"u".repeat(500), "x")).await.0, StatusCode::UNAUTHORIZED);
        // lockout after repeated failures, with Retry-After
        for _ in 0..6 {
            let _ = send(&app, login("vera", "bad")).await;
        }
        let (st, h, _) = send(&app, login("vera", "a-long-passphrase-1")).await;
        assert_eq!(st, StatusCode::TOO_MANY_REQUESTS);
        assert!(h.contains_key(header::RETRY_AFTER));
    }

    #[tokio::test]
    async fn secure_flag_is_added_behind_tls_and_logout_revokes_the_session() {
        let store: Arc<dyn Store> = Arc::new(SqliteStore::open_in_memory().unwrap());
        store.create_user("vera", &crate::auth::hash_password("a-long-passphrase-1").unwrap(), "viewer", false, 0).unwrap();
        let app = router(AppState { store: store.clone(), shared: crate::engine::test_shared(), loopback_only: true, allowed_hosts: vec![],
            auth: Arc::new(crate::auth::Auth::new(store.clone())), no_auth: false, secure_cookie: true, license: crate::license::load(None, &*store) });
        let (_, h, _) = send(&app, req("POST", "/api/auth/login", None, Some(serde_json::json!({"username": "vera", "password": "a-long-passphrase-1"})))).await;
        assert!(h[header::SET_COOKIE].to_str().unwrap().contains("Secure"));
        let c = cookie_of(&h);
        assert_eq!(send(&app, req("GET", "/api/auth/me", Some(&c), None)).await.0, StatusCode::OK);
        let (st, h, _) = send(&app, req("POST", "/api/auth/logout", Some(&c), None)).await;
        assert_eq!(st, StatusCode::NO_CONTENT);
        assert!(h[header::SET_COOKIE].to_str().unwrap().contains("Max-Age=0"));
        // the old cookie is dead server-side, not just deleted in the browser
        assert_eq!(send(&app, req("GET", "/api/auth/me", Some(&c), None)).await.0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn roles_are_enforced_on_every_kind_of_route() {
        let (app, store, [viewer, editor, admin]) = secured().await;
        let mut a = Asset::new(Mac([0x00, 0x1b, 0x63, 1, 2, 3]), 10);
        store.save_asset(&mut a).unwrap();
        let meta = format!("/api/assets/{}/meta", a.id);
        let patch = serde_json::json!({"owner": "Jana"});
        // (method, uri, body, viewer, editor, admin) -> expected status is "allowed?" (anything but 401/403)
        let cases: Vec<(&str, String, Option<serde_json::Value>, [bool; 3])> = vec![
            ("GET", "/api/assets".into(), None, [true, true, true]),
            ("GET", "/report".into(), None, [true, true, true]),
            ("PATCH", meta.clone(), Some(patch.clone()), [false, true, true]),
            ("POST", "/api/assets".into(), Some(serde_json::json!({"display_name": "x"})), [false, true, true]),
            ("POST", "/api/scan".into(), None, [false, true, true]),
            ("GET", "/api/users".into(), None, [false, false, true]),
            ("POST", "/api/users".into(), Some(serde_json::json!({"username": "newbie", "role": "viewer"})), [false, false, true]),
            ("GET", "/api/audit".into(), None, [false, false, true]),
            ("GET", "/api/agent-tokens".into(), None, [false, false, true]),
            ("POST", "/api/agent-tokens".into(), Some(serde_json::json!({"agent_id": "b1"})), [false, false, true]),
            ("DELETE", format!("/api/assets/{}", a.id), None, [false, false, true]),
        ];
        for (m, uri, body, allowed) in cases {
            for (who, cookie, ok) in [("viewer", &viewer, allowed[0]), ("editor", &editor, allowed[1]), ("admin", &admin, allowed[2])] {
                let (st, _, _) = send(&app, req(m, &uri, Some(cookie), body.clone())).await;
                let denied = st == StatusCode::FORBIDDEN || st == StatusCode::UNAUTHORIZED;
                assert_eq!(!denied, ok, "{who} {m} {uri} -> {st}");
            }
        }
        // the state-changing calls really did nothing for the denied roles
        assert!(store.get_meta(a.id).unwrap().is_some(), "editor's PATCH applied");
    }

    #[tokio::test]
    async fn an_admin_set_password_must_be_changed_before_anything_else() {
        let (app, store) = app_with(true, false);
        let auth = crate::auth::Auth::new(store.clone());
        store.create_user("root", &crate::auth::hash_password("a-long-passphrase-1").unwrap(), "admin", false, 0).unwrap();
        let (_, h, _) = send(&app, req("POST", "/api/auth/login", None, Some(serde_json::json!({"username": "root", "password": "a-long-passphrase-1"})))).await;
        let admin = cookie_of(&h);
        let (st, _, v) = send(&app, req("POST", "/api/users", Some(&admin), Some(serde_json::json!({"username": "jana", "role": "editor"})))).await;
        assert_eq!(st, StatusCode::CREATED);
        let temp = v["temporary_password"].as_str().unwrap().to_string();
        assert!(v["user"].get("password_hash").is_none());
        let (_, h, v) = send(&app, req("POST", "/api/auth/login", None, Some(serde_json::json!({"username": "jana", "password": temp})))).await;
        assert_eq!(v["must_change"], true);
        let jana = cookie_of(&h);
        // everything except the self-service endpoints is blocked
        for uri in ["/api/assets", "/api/status", "/report"] {
            let (st, _, v) = send(&app, req("GET", uri, Some(&jana), None)).await;
            assert_eq!((st, v["code"].as_str()), (StatusCode::FORBIDDEN, Some("must_change")), "{uri}");
        }
        assert_eq!(send(&app, req("GET", "/api/auth/me", Some(&jana), None)).await.0, StatusCode::OK);
        // a weak replacement is refused, a good one unlocks the account
        let bad = send(&app, req("POST", "/api/auth/password", Some(&jana), Some(serde_json::json!({"current": temp, "new": "short"})))).await;
        assert_eq!(bad.0, StatusCode::BAD_REQUEST);
        assert_eq!(send(&app, req("POST", "/api/auth/password", Some(&jana), Some(serde_json::json!({"current": "wrong", "new": "a-brand-new-passphrase"})))).await.0, StatusCode::UNAUTHORIZED);
        assert_eq!(send(&app, req("POST", "/api/auth/password", Some(&jana), Some(serde_json::json!({"current": temp, "new": "a-brand-new-passphrase"})))).await.0, StatusCode::NO_CONTENT);
        assert_eq!(send(&app, req("GET", "/api/assets", Some(&jana), None)).await.0, StatusCode::OK);
        let _ = auth;
    }

    #[tokio::test]
    async fn user_admin_protects_the_last_admin_and_hides_secrets() {
        let (app, store, [_, _, admin]) = secured().await;
        let users = send(&app, req("GET", "/api/users", Some(&admin), None)).await.2;
        assert_eq!(users.as_array().unwrap().len(), 3);
        assert!(users.to_string().find("argon2").is_none() && users.to_string().find("password").is_none());
        let adam = users.as_array().unwrap().iter().find(|u| u["username"] == "adam").unwrap()["id"].as_i64().unwrap();
        for body in [serde_json::json!({"disabled": true}), serde_json::json!({"role": "viewer"})] {
            assert_eq!(send(&app, req("PATCH", &format!("/api/users/{adam}"), Some(&admin), Some(body))).await.0, StatusCode::BAD_REQUEST, "the only admin cannot be removed");
        }
        // agent tokens: issued once, listed without the secret, revocable
        let (st, _, v) = send(&app, req("POST", "/api/agent-tokens", Some(&admin), Some(serde_json::json!({"agent_id": "branch-1", "label": "HQ"})))).await;
        assert_eq!(st, StatusCode::CREATED);
        let tok = v["token"].as_str().unwrap().to_string();
        assert!(tok.starts_with("dat_"));
        let listed = send(&app, req("GET", "/api/agent-tokens", Some(&admin), None)).await.2.to_string();
        assert!(listed.contains("branch-1") && !listed.contains(&tok) && !listed.contains(&crate::auth::sha256_hex(&tok)));
        assert_eq!(send(&app, req("DELETE", "/api/agent-tokens/branch-1", Some(&admin), None)).await.0, StatusCode::NO_CONTENT);
        assert_eq!(send(&app, req("DELETE", "/api/agent-tokens/branch-1", Some(&admin), None)).await.0, StatusCode::NOT_FOUND);
        assert_eq!(send(&app, req("POST", "/api/agent-tokens", Some(&admin), Some(serde_json::json!({"agent_id": "../x"})))).await.0, StatusCode::BAD_REQUEST);
        // a revoked token can be purged from the list; an active one cannot
        assert_eq!(send(&app, req("POST", "/api/agent-tokens", Some(&admin), Some(serde_json::json!({"agent_id": "branch-2", "label": "HQ"})))).await.0, StatusCode::CREATED);
        assert_eq!(send(&app, req("DELETE", "/api/agent-tokens/branch-2/purge", Some(&admin), None)).await.0, StatusCode::NOT_FOUND, "still active");
        assert_eq!(send(&app, req("DELETE", "/api/agent-tokens/branch-2", Some(&admin), None)).await.0, StatusCode::NO_CONTENT, "revoke");
        assert_eq!(send(&app, req("DELETE", "/api/agent-tokens/branch-2/purge", Some(&admin), None)).await.0, StatusCode::NO_CONTENT);
        assert!(!send(&app, req("GET", "/api/agent-tokens", Some(&admin), None)).await.2.to_string().contains("branch-2"));
        // all of it is in the audit trail, attributed
        let audit = store.list_audit(None, 50).unwrap();
        let actions: Vec<&str> = audit.iter().map(|a| a.action.as_str()).collect();
        assert!(actions.contains(&"agent_token.issue") && actions.contains(&"agent_token.revoke") && actions.contains(&"agent_token.delete") && actions.contains(&"auth.login"), "{actions:?}");
        assert!(audit.iter().any(|a| a.action == "agent_token.issue" && a.user == "adam"));
    }

    #[tokio::test]
    async fn a_user_can_only_be_deleted_once_already_disabled_and_it_is_permanent() {
        let (app, store, [viewer, editor, admin]) = secured().await;
        // a separate user, so disabling them (which signs them out) does not affect the role
        // cookies (vera/eda/adam themselves) used to check who may call delete
        let (st, _, v) = send(&app, req("POST", "/api/users", Some(&admin), Some(serde_json::json!({"username": "temp-hire", "role": "viewer"})))).await;
        assert_eq!(st, StatusCode::CREATED);
        let id = v["user"]["id"].as_i64().unwrap();

        // refused while still active
        let (st, _, v) = send(&app, req("DELETE", &format!("/api/users/{id}"), Some(&admin), None)).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        assert!(v["error"].as_str().unwrap().contains("disable"));
        assert!(store.get_user_record(id).unwrap().is_some());

        // only an admin may delete, even once disabled
        assert_eq!(send(&app, req("PATCH", &format!("/api/users/{id}"), Some(&admin), Some(serde_json::json!({"disabled": true})))).await.0, StatusCode::NO_CONTENT);
        assert_eq!(send(&app, req("DELETE", &format!("/api/users/{id}"), Some(&viewer), None)).await.0, StatusCode::FORBIDDEN);
        assert_eq!(send(&app, req("DELETE", &format!("/api/users/{id}"), Some(&editor), None)).await.0, StatusCode::FORBIDDEN);

        let (st, _, _) = send(&app, req("DELETE", &format!("/api/users/{id}"), Some(&admin), None)).await;
        assert_eq!(st, StatusCode::NO_CONTENT);
        assert!(store.get_user_record(id).unwrap().is_none(), "gone for good");

        // deleting again (already gone) is a clean rejection, not a crash
        assert_eq!(send(&app, req("DELETE", &format!("/api/users/{id}"), Some(&admin), None)).await.0, StatusCode::BAD_REQUEST);

        let audit = send(&app, req("GET", "/api/audit", Some(&admin), None)).await.2.to_string();
        assert!(audit.contains("user.delete"), "{audit}");
    }

    #[tokio::test]
    async fn responses_carry_security_headers_and_api_answers_are_not_cacheable() {
        let (app, _, [viewer, ..]) = secured().await;
        let (_, h, _) = send(&app, req("GET", "/api/assets", Some(&viewer), None)).await;
        for (k, v) in [("x-content-type-options", "nosniff"), ("x-frame-options", "DENY"), ("referrer-policy", "no-referrer"),
                       ("cache-control", "no-store"), ("cross-origin-opener-policy", "same-origin")] {
            assert_eq!(h[k], v, "{k}");
        }
        assert!(h["content-security-policy"].to_str().unwrap().contains("frame-ancestors 'none'"));
        let (_, h, _) = send(&app, req("GET", "/", None, None)).await;
        assert_eq!(h["x-frame-options"], "DENY");
    }

    // ------------------------------------------------------- asset tracking

    #[tokio::test]
    async fn asset_tracking_edit_create_history_and_delete() {
        let (app, store, [viewer, editor, admin]) = secured().await;
        let mut found = Asset::new(Mac([0x00, 0x1b, 0x63, 1, 2, 3]), 100);
        found.hostnames = vec!["hp-laser".into()];
        found.device_type = "unknown".into();
        found.ip_history.push(crate::model::IpRecord { ip: Ipv4Addr::new(10, 0, 0, 9), first_seen: 100, last_seen: 100 });
        store.save_asset(&mut found).unwrap();
        let uri = format!("/api/assets/{}", found.id);

        // edit: the manual values are returned, overrides win, raw guess preserved
        let (st, _, v) = send(&app, req("PATCH", &format!("{uri}/meta"), Some(&editor), Some(serde_json::json!({
            "display_name": "Reception printer", "serial_number": "SN-42", "owner": "Jana", "type_override": "printer",
            "icon": "printer", "criticality": "high", "warranty_expires": "2020-01-01", "tags": ["Floor 1"],
            "custom": {"Cost centre": "CC-7"}, "zone": "Office", "purdue_level": "4"})))).await;
        assert_eq!(st, StatusCode::OK, "{v}");
        assert_eq!((v["display_name"].as_str(), v["device_type"].as_str(), v["detected"]["device_type"].as_str()), (Some("Reception printer"), Some("printer"), Some("unknown")));
        assert_eq!((v["meta"]["serial_number"].as_str(), v["meta"]["icon"].as_str(), v["meta"]["tags"][0].as_str()), (Some("SN-42"), Some("printer"), Some("floor 1")));
        assert_eq!(v["warranty"]["state"], "expired");
        // validation errors are 400 and change nothing
        for bad in [serde_json::json!({"icon": "bomb"}), serde_json::json!({"status": "borrowed"}), serde_json::json!({"warranty_expires": "soon"}), serde_json::json!({"nope": 1})] {
            assert_eq!(send(&app, req("PATCH", &format!("{uri}/meta"), Some(&editor), Some(bad))).await.0, StatusCode::BAD_REQUEST);
        }
        assert_eq!(send(&app, req("PATCH", "/api/assets/9999/meta", Some(&editor), Some(serde_json::json!({"owner": "x"})))).await.0, StatusCode::NOT_FOUND);
        // the edit shows in the list too, and the history names who did it
        let list = send(&app, req("GET", "/api/assets", Some(&viewer), None)).await.2;
        assert_eq!(list[0]["meta"]["owner"], "Jana");
        let hist = send(&app, req("GET", &format!("{uri}/history"), Some(&viewer), None)).await.2;
        assert_eq!(hist.as_array().unwrap().len(), 1);
        assert_eq!((hist[0]["user"].as_str(), hist[0]["action"].as_str()), (Some("eda"), Some("asset.edit")));
        assert!(hist[0]["detail"]["changes"].to_string().contains("SN-42"));
        // a second identical edit is a no-op and adds no history
        send(&app, req("PATCH", &format!("{uri}/meta"), Some(&editor), Some(serde_json::json!({"owner": "Jana"})))).await;
        assert_eq!(send(&app, req("GET", &format!("{uri}/history"), Some(&viewer), None)).await.2.as_array().unwrap().len(), 1);

        // discovered assets cannot be deleted
        let (st, _, v) = send(&app, req("DELETE", &uri, Some(&admin), None)).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        assert!(v["error"].as_str().unwrap().contains("retired"));

        // a manual asset with no MAC gets a private placeholder and is a record, not a sighting
        let (st, _, v) = send(&app, req("POST", "/api/assets", Some(&editor), Some(serde_json::json!({"display_name": "Spare laptop", "type_override": "laptop", "status": "spare"})))).await;
        assert_eq!(st, StatusCode::CREATED, "{v}");
        let (mid, mac) = (v["id"].as_i64().unwrap(), v["mac"].as_str().unwrap().to_string());
        assert!(mac.starts_with("02:54:42:"));
        assert_eq!((v["meta"]["manual"].as_bool(), v["last_seen"].as_i64(), v["device_type"].as_str()), (Some(true), Some(0), Some("laptop")));
        // with a MAC; a duplicate MAC is a conflict; a bad one a 400
        let (st, _, _) = send(&app, req("POST", "/api/assets", Some(&editor), Some(serde_json::json!({"mac": "3C:22:FB:AA:00:01", "display_name": "Switch"})))).await;
        assert_eq!(st, StatusCode::CREATED);
        assert_eq!(send(&app, req("POST", "/api/assets", Some(&editor), Some(serde_json::json!({"mac": "3c:22:fb:aa:00:01"})))).await.0, StatusCode::CONFLICT);
        for bad in ["nonsense", "ff:ff:ff:ff:ff:ff", "01:00:5e:00:00:01"] {
            assert_eq!(send(&app, req("POST", "/api/assets", Some(&editor), Some(serde_json::json!({"mac": bad})))).await.0, StatusCode::BAD_REQUEST, "{bad}");
        }
        // discovery of that MAC later adopts the same row instead of duplicating it
        let mut seen = Asset::new(mac.parse().unwrap(), 500);
        store.save_asset(&mut seen).unwrap();
        assert_eq!(seen.id, mid);
        // manual assets can be deleted, by an admin only
        assert_eq!(send(&app, req("DELETE", &format!("/api/assets/{mid}"), Some(&editor), None)).await.0, StatusCode::FORBIDDEN);
        assert_eq!(send(&app, req("DELETE", &format!("/api/assets/{mid}"), Some(&admin), None)).await.0, StatusCode::NO_CONTENT);
        assert!(store.get_asset(mid).unwrap().is_none() && store.get_meta(mid).unwrap().is_none());
    }

    #[tokio::test]
    async fn csv_import_creates_updates_and_reports_bad_rows() {
        let (app, store, [_, editor, _]) = secured().await;
        let mut existing = Asset::new(Mac([0x00, 0x1b, 0x63, 1, 2, 3]), 100);
        store.save_asset(&mut existing).unwrap();
        let csv = "mac,display_name,serial_number,owner,tags,status,custom.VLAN\n\
                   00:1B:63:01:02:03,Old printer,SN-1,Jana,\"a; b\",active,10\n\
                   3c:22:fb:00:00:09,New NAS,SN-2,,storage,,20\n\
                   bogus,X,,,,,\n\
                   3c:22:fb:00:00:0a,Bad status,,,,borrowed,\n";
        let post = |body: &str| {
            let mut r = axum::http::Request::post("/api/assets/import").header("host", "localhost").header("x-denis", "1")
                .header("cookie", format!("{SESSION_COOKIE}={editor}")).body(Body::from(body.to_string())).unwrap();
            r.headers_mut().insert("content-type", "text/csv".parse().unwrap());
            r
        };
        let (st, _, v) = send(&app, post(csv)).await;
        assert_eq!(st, StatusCode::OK, "{v}");
        assert_eq!((v["created"].as_i64(), v["updated"].as_i64(), v["unchanged"].as_i64()), (Some(1), Some(1), Some(0)));
        let errs: Vec<(i64, String)> = v["errors"].as_array().unwrap().iter().map(|e| (e["line"].as_i64().unwrap(), e["error"].as_str().unwrap().to_string())).collect();
        assert_eq!(errs.iter().map(|e| e.0).collect::<Vec<_>>(), [4, 5]);
        assert!(errs[1].1.contains("status"));
        let m = store.get_meta(existing.id).unwrap().unwrap();
        assert_eq!((m.display_name.as_deref(), m.tags.clone(), m.custom["VLAN"].as_str()), (Some("Old printer"), vec!["a".to_string(), "b".to_string()], "10"));
        let created = store.find_asset(None, &"3c:22:fb:00:00:09".parse().unwrap()).unwrap().unwrap();
        assert!(store.get_meta(created.id).unwrap().unwrap().manual);
        // importing the same file again changes nothing
        let (_, _, v) = send(&app, post(csv)).await;
        assert_eq!((v["created"].as_i64(), v["updated"].as_i64(), v["unchanged"].as_i64()), (Some(0), Some(0), Some(2)));
        // structural problems reject the whole file
        assert_eq!(send(&app, post("serial_number\nx")).await.0, StatusCode::BAD_REQUEST);
        assert_eq!(send(&app, post("mac,colour\n3c:22:fb:00:00:0b,red")).await.0, StatusCode::BAD_REQUEST);
        // the audit trail records the import and per-asset changes
        let actions: Vec<String> = store.list_audit(None, 50).unwrap().into_iter().map(|a| a.action).collect();
        assert!(actions.contains(&"asset.import".to_string()) && actions.contains(&"asset.create".to_string()));
    }

    #[tokio::test]
    async fn the_conversation_matrix_is_served_with_names_and_purdue_levels() {
        use crate::model::Conversation;
        let (app, store, [viewer, ..]) = secured().await;
        let (mut hmi, mut plc) = (Asset::new(Mac([0x3c, 0x22, 0xfb, 1, 1, 1]), 10), Asset::new(Mac([0x00, 0x1b, 0x1b, 2, 2, 2]), 10));
        hmi.hostnames = vec!["hmi-line2".into()];
        store.save_asset(&mut hmi).unwrap();
        store.save_asset(&mut plc).unwrap();
        store.save_meta(plc.id, &AssetMeta { display_name: Some("PLC line 2".into()), purdue_level: Some("1".into()), type_override: Some("plc".into()), ..Default::default() }, "eda", 1).unwrap();
        store.save_conversations(&[Conversation { client_id: hmi.id, server_id: plc.id, proto: "s7".into(), port: 102, first_seen: 1, last_seen: 9, packets: 50, bytes: 4000, reads: 40, writes: 5, controls: 1, note: Some("PLC stop (0x29)".into()), commands: [("write variable (0x05)".to_string(), 5)].into() },
            Conversation { client_id: hmi.id, server_id: 9999, proto: "modbus".into(), port: 502, first_seen: 1, last_seen: 9, packets: 1, bytes: 1, reads: 1, writes: 0, controls: 0, note: None, commands: Default::default() }]).unwrap();
        let (st, _, v) = send(&app, req("GET", "/api/conversations", Some(&viewer), None)).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(v.as_array().unwrap().len(), 1, "a row whose asset no longer exists is not shown");
        assert_eq!((v[0]["client"]["name"].as_str(), v[0]["server"]["name"].as_str()), (Some("hmi-line2"), Some("PLC line 2")));
        assert_eq!((v[0]["server"]["purdue_level"].as_str(), v[0]["server"]["device_type"].as_str()), (Some("1"), Some("plc")));
        assert_eq!((v[0]["protocol"].as_str(), v[0]["writes"].as_i64(), v[0]["controls"].as_i64(), v[0]["note"].as_str()), (Some("s7"), Some(5), Some(1), Some("PLC stop (0x29)")));
        assert_eq!(v[0]["commands"]["write variable (0x05)"], 5, "the functions seen on a path are part of the matrix");
        // needs a session like everything else
        assert_eq!(send(&app, req("GET", "/api/conversations", None, None)).await.0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a_proxys_public_name_is_accepted_only_when_allowed_and_http2_authority_counts_as_host() {
        let store: Arc<dyn Store> = Arc::new(SqliteStore::open_in_memory().unwrap());
        let mk = |hosts: Vec<String>| router(AppState {
            store: store.clone(), shared: crate::engine::test_shared(), loopback_only: true, allowed_hosts: hosts,
            auth: Arc::new(crate::auth::Auth::new(store.clone())), no_auth: true, secure_cookie: false, license: crate::license::load(None, &*store),
        });
        let health = |host: &str| axum::http::Request::get("/api/health").header("host", host).body(Body::empty()).unwrap();
        let strict = mk(vec![]);
        assert_eq!(strict.clone().oneshot(health("denis.example.com")).await.unwrap().status(), StatusCode::FORBIDDEN);
        let open = mk(vec!["denis.example.com".into()]);
        assert_eq!(open.clone().oneshot(health("denis.example.com")).await.unwrap().status(), StatusCode::OK);
        assert_eq!(open.clone().oneshot(health("DENIS.example.com:8443")).await.unwrap().status(), StatusCode::OK, "case and port");
        assert_eq!(open.clone().oneshot(health("evil.example.net")).await.unwrap().status(), StatusCode::FORBIDDEN, "others stay out");
        assert_eq!(open.clone().oneshot(health("denis.example.com.evil.net")).await.unwrap().status(), StatusCode::FORBIDDEN, "no suffix tricks");
        // HTTP/2 has no Host header: the name is in the request URI
        let h2 = axum::http::Request::get("https://localhost:8093/api/health").body(Body::empty()).unwrap();
        assert_eq!(strict.clone().oneshot(h2).await.unwrap().status(), StatusCode::OK);
        let h2_evil = axum::http::Request::get("https://evil.example.net/api/health").body(Body::empty()).unwrap();
        assert_eq!(strict.oneshot(h2_evil).await.unwrap().status(), StatusCode::FORBIDDEN);
    }

    fn bearer(method: &str, uri: &str, token: &str, body: Option<serde_json::Value>) -> axum::http::Request<Body> {
        // deliberately no X-Denis header: scripts do not send one
        let b = axum::http::Request::builder().method(method).uri(uri).header("host", "localhost").header("authorization", format!("Bearer {token}"));
        match body {
            Some(v) => b.header("content-type", "application/json").body(Body::from(v.to_string())).unwrap(),
            None => b.body(Body::empty()).unwrap(),
        }
    }

    #[tokio::test]
    async fn api_tokens_are_admin_managed_role_limited_revocable_and_never_stored_in_clear() {
        let (app, store, [viewer, editor, admin]) = secured().await;
        let make = |label: &str, role: &str| req("POST", "/api/api-tokens", Some(&admin), Some(serde_json::json!({"label": label, "role": role})));
        // only admins manage tokens; a token can never be admin
        assert_eq!(send(&app, req("POST", "/api/api-tokens", Some(&editor), Some(serde_json::json!({"label": "x", "role": "viewer"})))).await.0, StatusCode::FORBIDDEN);
        assert_eq!(send(&app, req("GET", "/api/api-tokens", Some(&viewer), None)).await.0, StatusCode::FORBIDDEN);
        for bad in [("x", "admin"), ("", "viewer"), ("   ", "viewer"), ("a\nb", "viewer")] {
            assert_eq!(send(&app, make(bad.0, bad.1)).await.0, StatusCode::BAD_REQUEST, "{bad:?}");
        }
        let (st, _, v) = send(&app, make("grafana", "viewer")).await;
        assert_eq!(st, StatusCode::CREATED);
        let ro = v["token"].as_str().unwrap().to_string();
        let ro_id = v["id"].as_i64().unwrap();
        assert!(ro.starts_with("dnt_") && ro.len() == 68);
        let rw = send(&app, make("automation", "editor")).await.2["token"].as_str().unwrap().to_string();
        // the database holds only a hash, and the list never shows the token
        assert!(store.find_api_token(&ro).unwrap().is_none(), "raw token is not a key");
        assert!(store.find_api_token(&crate::auth::sha256_hex(&ro)).unwrap().is_some());
        let (_, _, list) = send(&app, req("GET", "/api/api-tokens", Some(&admin), None)).await;
        assert_eq!(list.as_array().unwrap().len(), 2);
        assert!(!list.to_string().contains(&ro) && !list.to_string().contains("token_hash"));

        // a viewer token reads without any cookie, but cannot change things
        assert_eq!(send(&app, bearer("GET", "/api/assets", &ro, None)).await.0, StatusCode::OK);
        assert_eq!(send(&app, bearer("POST", "/api/scan", &ro, None)).await.0, StatusCode::FORBIDDEN);
        // an editor token may write, without the CSRF header (it is not cookie based)
        let (st, ..) = send(&app, bearer("POST", "/api/assets", &rw, Some(serde_json::json!({"display_name": "Made by script"})))).await;
        assert_eq!(st, StatusCode::CREATED);
        // ...but never reaches administration, and has no password or session to manage
        for (m, u) in [("GET", "/api/users"), ("GET", "/api/api-tokens"), ("POST", "/api/api-tokens"), ("GET", "/api/audit"), ("GET", "/api/agent-tokens")] {
            assert_eq!(send(&app, bearer(m, u, &rw, Some(serde_json::json!({"label": "x", "role": "viewer"})))).await.0, StatusCode::FORBIDDEN, "{m} {u}");
        }
        assert_eq!(send(&app, bearer("POST", "/api/auth/password", &rw, Some(serde_json::json!({"current": "a", "new": "b"})))).await.0, StatusCode::FORBIDDEN);
        assert_eq!(send(&app, bearer("GET", "/api/auth/me", &rw, None)).await.2["user"]["username"], "token:automation");
        // the audit log names the token, not a person
        let audit = send(&app, req("GET", "/api/audit", Some(&admin), None)).await.2.to_string();
        assert!(audit.contains("token:automation"), "{audit}");

        // an Authorization header means bearer only: a valid cookie does not rescue a bad token
        for bad in ["dnt_".to_string() + &"0".repeat(64), "garbage".into(), String::new()] {
            let mut r = bearer("GET", "/api/assets", &bad, None);
            r.headers_mut().insert("cookie", format!("{SESSION_COOKIE}={admin}").parse().unwrap());
            assert_eq!(send(&app, r).await.0, StatusCode::UNAUTHORIZED, "{bad:?}");
        }
        // revoked tokens stop working at once
        assert_eq!(send(&app, req("DELETE", &format!("/api/api-tokens/{ro_id}"), Some(&admin), None)).await.0, StatusCode::NO_CONTENT);
        assert_eq!(send(&app, bearer("GET", "/api/assets", &ro, None)).await.0, StatusCode::UNAUTHORIZED);
        assert_eq!(send(&app, req("DELETE", &format!("/api/api-tokens/{ro_id}"), Some(&admin), None)).await.0, StatusCode::NOT_FOUND);
        // a revoked API token can be purged from the list
        assert_eq!(send(&app, req("DELETE", &format!("/api/api-tokens/{ro_id}/purge"), Some(&admin), None)).await.0, StatusCode::NO_CONTENT);
        let list = send(&app, req("GET", "/api/api-tokens", Some(&admin), None)).await.2;
        assert!(!list.as_array().unwrap().iter().any(|t| t["id"].as_i64() == Some(ro_id)));
        // and a cookie session still needs the CSRF header
        let mut no_csrf = req("POST", "/api/scan", Some(&editor), None);
        no_csrf.headers_mut().remove("x-denis");
        assert_eq!(send(&app, no_csrf).await.0, StatusCode::FORBIDDEN);
    }

    // ------------------------------------------------- per-address sign-in limit

    /// A sign-in request as if it came from `peer` (optionally through a proxy header).
    fn login_from(peer: &str, xff: Option<&str>, user: &str, pw: &str) -> axum::http::Request<Body> {
        let mut r = req("POST", "/api/auth/login", None, Some(serde_json::json!({"username": user, "password": pw})));
        r.extensions_mut().insert(axum::extract::ConnectInfo(format!("{peer}:5555").parse::<std::net::SocketAddr>().unwrap()));
        if let Some(x) = xff {
            r.headers_mut().insert("x-forwarded-for", x.parse().unwrap());
        }
        r
    }

    #[tokio::test]
    async fn one_address_cannot_guess_across_many_accounts_and_the_proxy_header_is_only_trusted_from_loopback() {
        let (app, ..) = secured().await;
        // 20 wrong guesses, each for a different account name: the per-account lock never triggers
        for i in 0..20 {
            let (st, ..) = send(&app, login_from("203.0.113.9", None, &format!("nobody{i}"), "wrong-password-1")).await;
            assert_eq!(st, StatusCode::UNAUTHORIZED);
        }
        // the address is now refused, even with correct credentials
        let (st, h, _) = send(&app, login_from("203.0.113.9", None, "vera", "a-long-passphrase-1")).await;
        assert_eq!(st, StatusCode::TOO_MANY_REQUESTS);
        assert!(h.contains_key(header::RETRY_AFTER));
        // other addresses are unaffected
        assert_eq!(send(&app, login_from("203.0.113.10", None, "vera", "a-long-passphrase-1")).await.0, StatusCode::OK);
        // a remote peer cannot pick its own identity with X-Forwarded-For
        assert_eq!(send(&app, login_from("203.0.113.9", Some("198.51.100.1"), "vera", "a-long-passphrase-1")).await.0, StatusCode::TOO_MANY_REQUESTS);
        // a local reverse proxy is believed: the client it names (last entry) is judged, not the proxy
        assert_eq!(send(&app, login_from("127.0.0.1", Some("1.2.3.4, 198.51.100.7"), "vera", "a-long-passphrase-1")).await.0, StatusCode::OK);
        for i in 0..20 {
            send(&app, login_from("127.0.0.1", Some("198.51.100.66"), &format!("ghost{i}"), "wrong-password-1")).await;
        }
        assert_eq!(send(&app, login_from("127.0.0.1", Some("198.51.100.66"), "vera", "a-long-passphrase-1")).await.0, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(send(&app, login_from("127.0.0.1", Some("198.51.100.67"), "vera", "a-long-passphrase-1")).await.0, StatusCode::OK, "one client behind the proxy does not lock out the others");
    }

    #[tokio::test]
    async fn rules_are_visible_to_everyone_editable_by_admins_only_and_validated_on_the_server() {
        let (app, store, [viewer, editor, admin]) = secured().await;
        let (st, _, v) = send(&app, req("GET", "/api/rules", Some(&viewer), None)).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(v["rules"].as_array().unwrap().len(), crate::detect::RULES.len());
        assert_eq!(v["min_score"]["value"], 30);
        let patch = serde_json::json!({"min_score": 55, "weights": {"new_device": 0}, "params": {"silent_minutes": 240}});
        for c in [&viewer, &editor] {
            assert_eq!(send(&app, req("PUT", "/api/rules", Some(c), Some(patch.clone()))).await.0, StatusCode::FORBIDDEN);
            assert_eq!(send(&app, req("DELETE", "/api/rules", Some(c), None)).await.0, StatusCode::FORBIDDEN);
        }
        let (st, _, v) = send(&app, req("PUT", "/api/rules", Some(&admin), Some(patch))).await;
        assert_eq!(st, StatusCode::OK, "{v}");
        assert_eq!(v["min_score"]["value"], 55);
        let nd = v["rules"].as_array().unwrap().iter().find(|r| r["id"] == "new_device").unwrap().clone();
        assert_eq!((nd["enabled"].as_bool(), nd["weight"].as_f64()), (Some(false), Some(0.0)));
        // stored, so the running detector (and a restart) will pick it up
        assert_eq!(crate::rules::load(&*store).unwrap().min_score, Some(55));
        // bad values are refused and change nothing
        for bad in [serde_json::json!({"min_score": 500}), serde_json::json!({"weights": {"bogus": 1}}), serde_json::json!({"params": {"volume_z_threshold": 0}})] {
            assert_eq!(send(&app, req("PUT", "/api/rules", Some(&admin), Some(bad))).await.0, StatusCode::BAD_REQUEST);
        }
        assert_eq!(crate::rules::load(&*store).unwrap().min_score, Some(55));
        assert!(send(&app, req("GET", "/api/audit", Some(&admin), None)).await.2.to_string().contains("rules.update"));
        let (st, _, v) = send(&app, req("DELETE", "/api/rules", Some(&admin), None)).await;
        assert_eq!((st, v["any_override"].as_bool()), (StatusCode::OK, Some(false)));
        assert_eq!(v["min_score"]["value"], 30);
    }

    #[tokio::test]
    async fn watches_exceptions_and_per_rule_minimums_round_trip_and_reach_the_detector_settings() {
        let (app, store, [viewer, _editor, admin]) = secured().await;
        let watch = serde_json::json!({"id": "w1", "name": "S7 stop", "enabled": true, "proto": "s7", "controls": true, "commands": ["PLC stop"],
            "targets": [{"kind": "type", "value": "plc"}], "allowed_senders": [{"kind": "cidr", "value": "10.0.9.0/24"}], "score": 90, "cooldown_minutes": 5});
        let patch = serde_json::json!({"ot_watches": [watch], "exceptions": {"new_device": [{"kind": "tag", "value": "lab"}]}, "min_scores": {"new_port": 45}});
        assert_eq!(send(&app, req("PUT", "/api/rules", Some(&viewer), Some(patch.clone()))).await.0, StatusCode::FORBIDDEN);
        let (st, _, v) = send(&app, req("PUT", "/api/rules", Some(&admin), Some(patch))).await;
        assert_eq!(st, StatusCode::OK, "{v}");
        // everyone can read what is watched (so nobody assumes silence means nothing is being watched)
        let (_, _, v) = send(&app, req("GET", "/api/rules", Some(&viewer), None)).await;
        assert_eq!(v["ot_watches"][0]["name"], "S7 stop");
        assert_eq!(v["exceptions"]["new_device"][0]["value"], "lab");
        let np = v["rules"].as_array().unwrap().iter().find(|r| r["id"] == "new_port").unwrap().clone();
        assert_eq!(np["min_score"], 45);
        // the detector's settings carry the watch and the per-rule minimum
        let cfg = crate::rules::load(&*store).unwrap().apply(&crate::detect::DetectConfig::default());
        assert_eq!((cfg.ot_watches.len(), cfg.rule_min_scores["new_port"]), (1, 45));
        // a bad watch is refused and nothing changes
        let bad = serde_json::json!({"ot_watches": [{"id": "x", "name": "n", "enabled": true, "proto": "s7", "score": 50, "cooldown_minutes": 5}]});
        assert_eq!(send(&app, req("PUT", "/api/rules", Some(&admin), Some(bad))).await.0, StatusCode::BAD_REQUEST);
        assert_eq!(crate::rules::load(&*store).unwrap().ot_watches.len(), 1);
        // editing the weights keeps the watches and exceptions (they are content, not settings)
        let (st, _, v) = send(&app, req("PUT", "/api/rules", Some(&admin), Some(serde_json::json!({"weights": {"new_device": null}, "min_scores": {"new_port": null}})))).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!((v["ot_watches"].as_array().unwrap().len(), v["exceptions"]["new_device"].as_array().unwrap().len()), (1, 1));
        let audit = send(&app, req("GET", "/api/audit", Some(&admin), None)).await.2.to_string();
        assert!(audit.contains("rules.update"), "changes to watches are audited");
    }

    #[tokio::test]
    async fn an_authenticator_app_is_a_second_step_with_one_use_codes_recovery_codes_lockout_and_an_admin_reset() {
        let (app, store, [viewer, _editor, _admin]) = secured().await;
        let uid = store.find_user("vera").unwrap().unwrap().user.id;
        let pw = "a-long-passphrase-1";
        let login = || async { send(&app, req("POST", "/api/auth/login", None, Some(serde_json::json!({"username": "vera", "password": pw})))).await };
        let mfa = |ticket: String, code: String| {
            let app = app.clone();
            async move { send(&app, req("POST", "/api/auth/mfa", None, Some(serde_json::json!({"ticket": ticket, "code": code})))).await }
        };
        let now_code = |offset: i64| { let t = store.get_totp(uid).unwrap().unwrap(); format!("{:06}", crate::totp::code_at(&t.secret, crate::totp::step_of(now_ts()) + offset)) };
        // nothing is set up: the status says so, and the password alone signs in
        let (_, _, v) = send(&app, req("GET", "/api/auth/totp", Some(&viewer), None)).await;
        assert_eq!((v["enabled"].as_bool(), v["pending"].as_bool(), v["recovery_left"].as_u64()), (Some(false), Some(false), Some(0)));
        // set-up: the password again first
        assert_eq!(send(&app, req("POST", "/api/auth/totp/begin", Some(&viewer), Some(serde_json::json!({"password": "wrong-password-1"})))).await.0, StatusCode::UNAUTHORIZED);
        assert_eq!(send(&app, req("GET", "/api/auth/totp/qr.svg", Some(&viewer), None)).await.0, StatusCode::NOT_FOUND, "no QR code before it is started");
        let (st, _, v) = send(&app, req("POST", "/api/auth/totp/begin", Some(&viewer), Some(serde_json::json!({"password": pw})))).await;
        assert_eq!(st, StatusCode::OK, "{v}");
        assert!(v["uri"].as_str().unwrap().starts_with("otpauth://totp/DENIS:vera?secret=") && v["secret"].as_str().unwrap().len() == 32);
        let resp = app.clone().oneshot(req("GET", "/api/auth/totp/qr.svg", Some(&viewer), None)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers()[header::CONTENT_TYPE], "image/svg+xml");
        assert!(String::from_utf8_lossy(&axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap()).starts_with("<svg "));
        // pending: still only the password is needed
        assert!(login().await.2["user"]["username"] == "vera", "a set-up that was never confirmed changes nothing");
        // confirming needs a right code
        assert_eq!(send(&app, req("POST", "/api/auth/totp/confirm", Some(&viewer), Some(serde_json::json!({"code": "000000"})))).await.0, StatusCode::BAD_REQUEST);
        let (st, _, v) = send(&app, req("POST", "/api/auth/totp/confirm", Some(&viewer), Some(serde_json::json!({"code": now_code(0)})))).await;
        assert_eq!(st, StatusCode::OK, "{v}");
        let recovery: Vec<String> = v["recovery_codes"].as_array().unwrap().iter().map(|c| c.as_str().unwrap().to_string()).collect();
        assert_eq!(recovery.len(), 10);
        assert_eq!(send(&app, req("POST", "/api/auth/totp/begin", Some(&viewer), Some(serde_json::json!({"password": pw})))).await.0, StatusCode::CONFLICT, "starting again does not replace a working one");
        // the password now earns only a ticket, and no session
        let (st, h, v) = login().await;
        assert_eq!((st, v["mfa_required"].as_bool()), (StatusCode::OK, Some(true)), "{v}");
        assert!(h.get(header::SET_COOKIE).is_none() && v.get("user").is_none(), "no session before the code");
        let ticket = v["ticket"].as_str().unwrap().to_string();
        // wrong codes are refused; the confirming code cannot be replayed; the next one works
        assert_eq!(mfa(ticket.clone(), "123456".into()).await.0, StatusCode::UNAUTHORIZED);
        assert_eq!(mfa(ticket.clone(), now_code(0)).await.0, StatusCode::UNAUTHORIZED, "the code that confirmed the set-up was used already");
        assert_eq!(mfa("f".repeat(64), now_code(1)).await.0, StatusCode::UNAUTHORIZED, "an invented ticket is nothing");
        let (st, h, v) = mfa(ticket.clone(), now_code(1)).await;
        assert_eq!((st, v["user"]["username"].as_str()), (StatusCode::OK, Some("vera")), "{v}");
        let cookie = cookie_of(&h);
        assert_eq!(send(&app, req("GET", "/api/assets", Some(&cookie), None)).await.0, StatusCode::OK);
        assert_eq!(mfa(ticket, now_code(1)).await.0, StatusCode::UNAUTHORIZED, "a ticket works once");
        // the same code cannot be used twice, also for a fresh ticket
        let t2 = login().await.2["ticket"].as_str().unwrap().to_string();
        assert_eq!(mfa(t2, now_code(1)).await.0, StatusCode::UNAUTHORIZED, "each code works once");
        // a ticket is void after five wrong codes, even if the sixth is right
        let t3 = login().await.2["ticket"].as_str().unwrap().to_string();
        for _ in 0..5 {
            mfa(t3.clone(), "111111".into()).await;
        }
        assert_ne!(mfa(t3, now_code(-1)).await.0, StatusCode::OK, "the ticket is void (or the account is locked)");
        // the account is locked for a moment after five wrong codes, and the right password does not lift that
        let (st, _, _) = login().await;
        assert_eq!(st, StatusCode::TOO_MANY_REQUESTS);
        let (_, _, v) = send(&app, req("GET", "/api/auth/totp", Some(&cookie), None)).await;
        assert_eq!((v["enabled"].as_bool(), v["recovery_left"].as_u64()), (Some(true), Some(recovery.len() as u64)));
    }

    #[tokio::test]
    async fn recovery_codes_the_admin_reset_and_the_policy_that_makes_a_second_step_compulsory() {
        let (app, store, [viewer, _editor, admin]) = secured().await;
        let uid = store.find_user("vera").unwrap().unwrap().user.id;
        let pw = "a-long-passphrase-1";
        // vera turns the app on
        send(&app, req("POST", "/api/auth/totp/begin", Some(&viewer), Some(serde_json::json!({"password": pw})))).await;
        let secret = store.get_totp(uid).unwrap().unwrap().secret;
        let code = |offset: i64| format!("{:06}", crate::totp::code_at(&secret, crate::totp::step_of(now_ts()) + offset));
        let (_, _, v) = send(&app, req("POST", "/api/auth/totp/confirm", Some(&viewer), Some(serde_json::json!({"code": code(0)})))).await;
        let recovery: Vec<String> = v["recovery_codes"].as_array().unwrap().iter().map(|c| c.as_str().unwrap().to_string()).collect();
        let ticket = |app: Router| async move { send(&app, req("POST", "/api/auth/login", None, Some(serde_json::json!({"username": "vera", "password": pw})))).await.2["ticket"].as_str().unwrap().to_string() };
        // a recovery code (typed loosely) signs in, once
        let t = ticket(app.clone()).await;
        let typed = recovery[0].to_uppercase().replace('-', " ");
        let (st, _, v) = send(&app, req("POST", "/api/auth/mfa", None, Some(serde_json::json!({"ticket": t, "code": typed})))).await;
        assert_eq!((st, v["user"]["username"].as_str()), (StatusCode::OK, Some("vera")), "{v}");
        let t = ticket(app.clone()).await;
        assert_eq!(send(&app, req("POST", "/api/auth/mfa", None, Some(serde_json::json!({"ticket": t, "code": recovery[0]})))).await.0, StatusCode::UNAUTHORIZED, "a recovery code works once");
        // new recovery codes need the password and a current code; the old ones stop working
        assert_eq!(send(&app, req("POST", "/api/auth/totp/recovery", Some(&viewer), Some(serde_json::json!({"password": pw, "code": "000000"})))).await.0, StatusCode::UNAUTHORIZED);
        let (st, _, v) = send(&app, req("POST", "/api/auth/totp/recovery", Some(&viewer), Some(serde_json::json!({"password": pw, "code": code(1)})))).await;
        assert_eq!(st, StatusCode::OK, "{v}");
        assert_ne!(v["recovery_codes"][0], recovery[1].as_str());
        let t = ticket(app.clone()).await;
        assert_eq!(send(&app, req("POST", "/api/auth/mfa", None, Some(serde_json::json!({"ticket": t, "code": recovery[1]})))).await.0, StatusCode::UNAUTHORIZED, "the old codes are gone");
        // the users list shows how each person signs in, never a secret
        let (_, _, users) = send(&app, req("GET", "/api/users", Some(&admin), None)).await;
        let vera = users.as_array().unwrap().iter().find(|u| u["username"] == "vera").unwrap();
        assert_eq!((vera["totp"].as_bool(), vera["passkeys"].as_u64()), (Some(true), Some(0)));
        assert!(!users.to_string().contains("secret"));
        // the policy: admin only; "all" catches everybody without a second step
        assert_eq!(send(&app, req("PUT", "/api/security", Some(&viewer), Some(serde_json::json!({"mfa_required": "all"})))).await.0, StatusCode::FORBIDDEN);
        assert_eq!(send(&app, req("PUT", "/api/security", Some(&admin), Some(serde_json::json!({"mfa_required": "sometimes"})))).await.0, StatusCode::BAD_REQUEST);
        let (_, _, p) = send(&app, req("GET", "/api/security", Some(&admin), None)).await;
        assert_eq!((p["mfa_required"].as_str(), p["all_without"].as_u64(), p["admins_without"].as_u64()), (Some("off"), Some(2), Some(1)), "{p}");
        assert_eq!(send(&app, req("PUT", "/api/security", Some(&admin), Some(serde_json::json!({"mfa_required": "all"})))).await.0, StatusCode::OK);
        // adam has no second step: everything but signing in and setting one up is refused, with a code the console understands
        let (st, _, v) = send(&app, req("GET", "/api/assets", Some(&admin), None)).await;
        assert_eq!((st, v["code"].as_str()), (StatusCode::FORBIDDEN, Some("mfa_required")), "{v}");
        assert_eq!(send(&app, req("GET", "/api/auth/totp", Some(&admin), None)).await.0, StatusCode::OK, "setting one up is allowed");
        assert_eq!(send(&app, req("GET", "/api/auth/me", Some(&admin), None)).await.2["must_enrol"], true);
        // vera has one, so nothing changes for her; she cannot turn it off while it is required
        assert_eq!(send(&app, req("GET", "/api/assets", Some(&viewer), None)).await.0, StatusCode::OK);
        assert_eq!(send(&app, req("POST", "/api/auth/totp/disable", Some(&viewer), Some(serde_json::json!({"password": pw})))).await.0, StatusCode::CONFLICT);
        // adam sets one up and is let in
        send(&app, req("POST", "/api/auth/totp/begin", Some(&admin), Some(serde_json::json!({"password": pw})))).await;
        let aid = store.find_user("adam").unwrap().unwrap().user.id;
        let asecret = store.get_totp(aid).unwrap().unwrap().secret;
        let acode = format!("{:06}", crate::totp::code_at(&asecret, crate::totp::step_of(now_ts())));
        assert_eq!(send(&app, req("POST", "/api/auth/totp/confirm", Some(&admin), Some(serde_json::json!({"code": acode})))).await.0, StatusCode::OK);
        assert_eq!(send(&app, req("GET", "/api/assets", Some(&admin), None)).await.0, StatusCode::OK);
        // the administrator resets vera's app (a lost phone): her sessions end and the password alone works again
        assert_eq!(send(&app, req("DELETE", &format!("/api/users/{uid}/totp"), Some(&viewer), None)).await.0, StatusCode::FORBIDDEN);
        let (st, _, v) = send(&app, req("DELETE", &format!("/api/users/{uid}/totp"), Some(&admin), None)).await;
        assert_eq!((st, v["removed"].as_bool()), (StatusCode::OK, Some(true)));
        assert_eq!(send(&app, req("GET", "/api/assets", Some(&viewer), None)).await.0, StatusCode::UNAUTHORIZED, "her sessions ended");
        let (_, _, v) = send(&app, req("POST", "/api/auth/login", None, Some(serde_json::json!({"username": "vera", "password": pw})))).await;
        assert!(v["user"]["username"] == "vera" && v.get("ticket").is_none());
        let audit = send(&app, req("GET", "/api/audit", Some(&admin), None)).await.2.to_string();
        for a in ["totp.enable", "totp.recovery_code_used", "totp.recovery_codes", "totp.reset", "security.mfa_policy", "auth.mfa_failed"] {
            assert!(audit.contains(a), "{a}");
        }
        assert!(!audit.contains(&recovery[2]), "no code is ever written to the audit log");
    }

    #[tokio::test]
    async fn switches_are_added_by_admins_polled_over_snmp_and_place_known_devices_on_their_ports_without_ever_exposing_the_community() {
        use crate::snmp::{agent, oid, Value};
        let (app, store, [viewer, editor, admin]) = secured().await;
        let mut cam = Asset::new(Mac([0xaa, 0, 0, 0, 0, 9]), 10);
        cam.device_type = "camera".into();
        cam.last_seen = now_ts();
        store.save_asset(&mut cam).unwrap();
        // a small switch: two ports, one MAC learned on port 2
        let mut mib = std::collections::BTreeMap::new();
        mib.insert(oid("1.3.6.1.2.1.1.1.0"), Value::Str(b"Acme switch".to_vec()));
        mib.insert(oid("1.3.6.1.2.1.1.5.0"), Value::Str(b"sw-lab".to_vec()));
        for i in 1..=2u32 {
            mib.insert(oid(&format!("1.3.6.1.2.1.31.1.1.1.1.{i}")), Value::Str(format!("Gi1/0/{i}").into_bytes()));
            mib.insert(oid(&format!("1.3.6.1.2.1.17.1.4.1.2.{i}")), Value::Int(i as i64));
        }
        mib.insert(oid("1.3.6.1.2.1.17.7.1.2.2.1.2.1.170.0.0.0.0.9"), Value::Int(2));
        let a = agent::start("SUPERSECRETCOMMUNITY", mib, false);
        let put = |targets: serde_json::Value| serde_json::json!({"interval_secs": 300, "targets": targets});
        let target = serde_json::json!({"id": "lab1", "name": "Lab switch", "address": a.addr.to_string(), "community": "SUPERSECRETCOMMUNITY", "enabled": true});
        for c in [&viewer, &editor] {
            assert_eq!(send(&app, req("PUT", "/api/switches", Some(c), Some(put(serde_json::json!([target.clone()]))))).await.0, StatusCode::FORBIDDEN);
            assert_eq!(send(&app, req("POST", "/api/switches/lab1/poll", Some(c), None)).await.0, StatusCode::FORBIDDEN);
        }
        // refused: no community for a new switch, a name for an address
        let no_comm = serde_json::json!({"id": "x1", "name": "n", "address": "192.0.2.1", "enabled": true});
        assert_eq!(send(&app, req("PUT", "/api/switches", Some(&admin), Some(put(serde_json::json!([no_comm]))))).await.0, StatusCode::BAD_REQUEST);
        let named = serde_json::json!({"id": "x2", "name": "n", "address": "sw.example.com", "community": "c", "enabled": true});
        assert_eq!(send(&app, req("PUT", "/api/switches", Some(&admin), Some(put(serde_json::json!([named]))))).await.0, StatusCode::BAD_REQUEST);
        assert_eq!(send(&app, req("PUT", "/api/switches", Some(&admin), Some(put(serde_json::json!([target.clone()]))))).await.0, StatusCode::NO_CONTENT);
        // read it now
        let (st, _, v) = send(&app, req("POST", "/api/switches/lab1/poll", Some(&admin), None)).await;
        assert_eq!((st, v["ok"].as_bool(), v["ports"].as_u64(), v["macs"].as_u64()), (StatusCode::OK, Some(true), Some(2), Some(1)), "{v}");
        assert_eq!(send(&app, req("POST", "/api/switches/nope/poll", Some(&admin), None)).await.0, StatusCode::NOT_FOUND);
        // the topology names the port the camera is plugged into; everyone signed in can read it
        let (_, _, t) = send(&app, req("GET", "/api/topology", Some(&viewer), None)).await;
        assert_eq!(t["configured"], true);
        assert_eq!((t["switches"][0]["sys_name"].as_str(), t["switches"][0]["ports_total"].as_u64()), (Some("sw-lab"), Some(2)));
        let at = &t["attachments"][0];
        assert_eq!((at["asset_id"].as_i64(), at["port"].as_str(), at["switch"].as_str(), at["via"].as_str()), (Some(cam.id), Some("Gi1/0/2"), Some("lab1"), Some("fdb")), "{t}");
        // the community is never sent back, nor written to the audit log; leaving it blank on the next save keeps it
        let (_, _, list) = send(&app, req("GET", "/api/switches", Some(&viewer), None)).await;
        assert_eq!((list["targets"][0]["has_community"].as_bool(), list["targets"][0]["macs"].as_u64()), (Some(true), Some(1)));
        assert!(!list.to_string().contains("SUPERSECRET") && !t.to_string().contains("SUPERSECRET"));
        let renamed = serde_json::json!({"id": "lab1", "name": "Lab core", "address": a.addr.to_string(), "enabled": true});
        assert_eq!(send(&app, req("PUT", "/api/switches", Some(&admin), Some(put(serde_json::json!([renamed]))))).await.0, StatusCode::NO_CONTENT);
        assert_eq!(send(&app, req("POST", "/api/switches/lab1/poll", Some(&admin), None)).await.2["ok"], true, "the stored community was kept");
        let audit = send(&app, req("GET", "/api/audit", Some(&admin), None)).await.2.to_string();
        assert!(audit.contains("switches.update") && audit.contains("switches.poll") && !audit.contains("SUPERSECRET"));
        // removing the switch from the list removes it from the topology
        assert_eq!(send(&app, req("PUT", "/api/switches", Some(&admin), Some(put(serde_json::json!([]))))).await.0, StatusCode::NO_CONTENT);
        assert_eq!(send(&app, req("GET", "/api/topology", Some(&viewer), None)).await.2["configured"], false);
    }

    #[tokio::test]
    async fn software_data_is_readable_by_everyone_switched_and_refreshed_by_admins_and_findings_carry_their_evidence() {
        let (app, store, [viewer, editor, admin]) = secured().await;
        let (st, _, v) = send(&app, req("GET", "/api/vulndata", Some(&viewer), None)).await;
        assert_eq!(st, StatusCode::OK);
        assert!(v["kev_entries"].as_u64().unwrap() >= 5 && v["products"].as_array().unwrap().iter().any(|p| p == "nginx") && v["refresh_eol"] == true && v["refresh_kev"] == false && v["refreshed_at"].is_null(), "on by default; {v}");
        for c in [&viewer, &editor] {
            assert_eq!(send(&app, req("PUT", "/api/vulndata", Some(c), Some(serde_json::json!({"refresh_eol": false})))).await.0, StatusCode::FORBIDDEN);
            assert_eq!(send(&app, req("POST", "/api/vulndata/refresh", Some(c), None)).await.0, StatusCode::FORBIDDEN);
            // the live CISA/NVD refresh needs an admin too (never called here: it would reach the real internet)
            assert_eq!(send(&app, req("POST", "/api/vulndata/kev/refresh", Some(c), None)).await.0, StatusCode::FORBIDDEN);
        }
        assert_eq!(send(&app, req("PUT", "/api/vulndata", Some(&admin), Some(serde_json::json!({"refresh_eol": false})))).await.0, StatusCode::NO_CONTENT);
        assert_eq!(send(&app, req("GET", "/api/vulndata", Some(&viewer), None)).await.2["refresh_eol"], false);
        // a web server announcing a version in a known-exploited range shows up in the findings, with what was read
        let mut web = Asset::new(Mac([2, 0, 0, 0, 0, 5]), 10);
        web.device_type = "server".into();
        web.last_seen = now_ts();
        web.fingerprint.identity.insert("banner.http".into(), "Server: Apache/2.4.49 (Unix)".into());
        store.save_asset(&mut web).unwrap();
        let (_, _, f) = send(&app, req("GET", "/api/findings", Some(&viewer), None)).await;
        let kev = f.as_array().unwrap().iter().find(|x| x["id"] == "kev_software").unwrap_or_else(|| panic!("{f}"));
        assert_eq!((kev["severity"].as_str(), kev["assets"][0].as_i64(), kev["evidence"][0]["product"].as_str(), kev["evidence"][0]["version"].as_str()), (Some("high"), Some(web.id), Some("Apache HTTP Server"), Some("2.4.49")));
        assert!(kev["evidence"][0]["cve"].as_str().unwrap().starts_with("CVE-2021-"), "{kev}");
        let audit = send(&app, req("GET", "/api/audit", Some(&admin), None)).await.2.to_string();
        assert!(audit.contains("vulndata.settings"));
    }

    #[tokio::test]
    async fn custom_cves_are_admin_only_validated_and_matched_like_bundled_ones() {
        let (app, store, [viewer, editor, admin]) = secured().await;
        let good = serde_json::json!([{"cve": "CVE-2026-9999", "name": "made up for the test", "added": "2026-01-01", "product": "vsftpd", "ranges": [{"exact": "3.0.5"}]}]);
        for c in [&viewer, &editor] {
            assert_eq!(send(&app, req("PUT", "/api/vulndata/custom", Some(c), Some(good.clone()))).await.0, StatusCode::FORBIDDEN);
        }
        let bad = serde_json::json!([{"cve": "not-a-cve", "name": "x", "added": "2026-01-01", "product": "vsftpd", "ranges": [{"exact": "3.0.5"}]}]);
        assert_eq!(send(&app, req("PUT", "/api/vulndata/custom", Some(&admin), Some(bad))).await.0, StatusCode::BAD_REQUEST);
        assert_eq!(send(&app, req("PUT", "/api/vulndata/custom", Some(&admin), Some(good))).await.0, StatusCode::NO_CONTENT);
        let (_, _, v) = send(&app, req("GET", "/api/vulndata", Some(&viewer), None)).await;
        assert_eq!(v["custom_kev"].as_array().unwrap().len(), 1);
        assert!(v["known_products"].as_array().unwrap().iter().any(|p| p == "vsftpd"));

        let mut ftp = Asset::new(Mac([2, 0, 0, 0, 0, 6]), 10);
        ftp.last_seen = now_ts();
        ftp.fingerprint.identity.insert("banner.ftp".into(), "220 (vsFTPd 3.0.5)".into());
        store.save_asset(&mut ftp).unwrap();
        let (_, _, f) = send(&app, req("GET", "/api/findings", Some(&viewer), None)).await;
        let kev = f.as_array().unwrap().iter().find(|x| x["id"] == "kev_software" && x["evidence"][0]["cve"] == "CVE-2026-9999");
        assert!(kev.is_some(), "{f}");

        assert_eq!(send(&app, req("PUT", "/api/vulndata/custom", Some(&admin), Some(serde_json::json!([])))).await.0, StatusCode::NO_CONTENT, "an empty list clears it");
        let audit = send(&app, req("GET", "/api/audit", Some(&admin), None)).await.2.to_string();
        assert!(audit.contains("vulndata.custom"));
    }

    #[tokio::test]
    async fn the_setup_guide_reports_what_is_really_configured_and_is_for_administrators() {
        let (app, _store, [viewer, editor, admin]) = secured().await;
        for c in [&viewer, &editor] {
            assert_eq!(send(&app, req("GET", "/api/setup", Some(c), None)).await.0, StatusCode::FORBIDDEN);
            assert_eq!(send(&app, req("PUT", "/api/setup", Some(c), Some(serde_json::json!({"completed": true})))).await.0, StatusCode::FORBIDDEN);
        }
        let (st, _, v) = send(&app, req("GET", "/api/setup", Some(&admin), None)).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(v["completed"], false);
        let ids: Vec<&str> = v["steps"].as_array().unwrap().iter().map(|s| s["id"].as_str().unwrap()).collect();
        assert_eq!(ids, ["network", "security", "alerts", "people", "backups", "branding"]);
        let step = |v: &serde_json::Value, id: &str| v["steps"].as_array().unwrap().iter().find(|s| s["id"] == id).unwrap().clone();
        assert_eq!(step(&v, "people")["done"], true, "three users can sign in");
        assert_eq!(step(&v, "security")["done"], false, "no passkeys yet");
        assert_eq!(step(&v, "alerts")["done"], false);
        // changing something makes the step true by itself
        let ch = serde_json::json!({"name": "Ops", "kind": "slack", "enabled": true, "min_score": 30, "url": "https://hooks.slack.com/services/T1/B2/x"});
        let made = send(&app, req("POST", "/api/channels", Some(&admin), Some(ch))).await;
        assert!(made.0.is_success(), "{:?}", made.2);
        assert_eq!(step(&send(&app, req("GET", "/api/setup", Some(&admin), None)).await.2, "alerts")["done"], true);
        // marking it done is remembered, with who did it, and can be undone
        let (st, _, p) = send(&app, req("PUT", "/api/setup", Some(&admin), Some(serde_json::json!({"completed": true})))).await;
        assert_eq!((st, p["completed_by"].as_str()), (StatusCode::OK, Some("adam")));
        assert_eq!(send(&app, req("GET", "/api/setup", Some(&admin), None)).await.2["completed"], true);
        send(&app, req("PUT", "/api/setup", Some(&admin), Some(serde_json::json!({"completed": false})))).await;
        assert_eq!(send(&app, req("GET", "/api/setup", Some(&admin), None)).await.2["completed"], false);
        assert!(send(&app, req("GET", "/api/audit", Some(&admin), None)).await.2.to_string().contains("setup.guide"));
    }

    #[tokio::test]
    async fn network_watches_round_trip_survive_other_edits_and_are_refused_when_nonsense() {
        let (app, store, [viewer, _editor, admin]) = secured().await;
        let watch = serde_json::json!({"id": "cam1", "name": "Cameras stay home", "enabled": true, "sources": [{"kind": "type", "value": "camera"}], "except_sources": [],
            "proto": "any", "ports_mode": "any", "ports": [], "remotes_mode": "only", "remotes": ["public"], "min_kb": 0, "score": 70, "cooldown_minutes": 30});
        assert_eq!(send(&app, req("PUT", "/api/rules", Some(&viewer), Some(serde_json::json!({"it_watches": [watch]})))).await.0, StatusCode::FORBIDDEN);
        let (st, _, v) = send(&app, req("PUT", "/api/rules", Some(&admin), Some(serde_json::json!({"it_watches": [watch]})))).await;
        assert_eq!(st, StatusCode::OK, "{v}");
        let (_, _, v) = send(&app, req("GET", "/api/rules", Some(&viewer), None)).await;
        assert_eq!((v["it_watches"][0]["name"].as_str(), v["it_watches"][0]["remotes"][0].as_str()), (Some("Cameras stay home"), Some("public")));
        assert!(v["rules"].as_array().unwrap().iter().any(|r| r["id"] == "it_watch" && r["group"] == "network"), "the rule behind the watches is listed, so its weight can be turned down");
        let cfg = crate::rules::load(&*store).unwrap().apply(&crate::detect::DetectConfig::default());
        assert_eq!(cfg.it_watches.len(), 1);
        // nonsense is refused and nothing changes
        for bad in [
            serde_json::json!({"id": "x", "name": "n", "enabled": true, "sources": [], "proto": "any", "ports_mode": "any", "remotes_mode": "any", "score": 50, "cooldown_minutes": 5}),
            serde_json::json!({"id": "y", "name": "n", "enabled": true, "sources": [], "proto": "tcp", "ports_mode": "only", "ports": [], "remotes_mode": "any", "score": 50, "cooldown_minutes": 5}),
            serde_json::json!({"id": "z", "name": "n", "enabled": true, "sources": [], "proto": "tcp", "ports_mode": "any", "remotes_mode": "only", "remotes": ["nowhere"], "score": 50, "cooldown_minutes": 5}),
        ] {
            assert_eq!(send(&app, req("PUT", "/api/rules", Some(&admin), Some(serde_json::json!({"it_watches": [bad]})))).await.0, StatusCode::BAD_REQUEST);
        }
        assert_eq!(crate::rules::load(&*store).unwrap().it_watches.len(), 1);
        // other edits keep the watches; the rule's weight can silence them all
        let (st, _, v) = send(&app, req("PUT", "/api/rules", Some(&admin), Some(serde_json::json!({"weights": {"it_watch": 0}})))).await;
        assert_eq!((st, v["it_watches"].as_array().unwrap().len()), (StatusCode::OK, 1));
    }

    #[tokio::test]
    async fn notification_channels_are_admin_only_never_reveal_secrets_and_can_be_tested() {
        use std::io::{Read, Write};
        // a stand-in for Slack: answers 200 to anything and remembers the last body
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/services/T1/B2/SUPERSECRETTOKEN", l.local_addr().unwrap());
        let got = Arc::new(std::sync::Mutex::new(String::new()));
        let g2 = got.clone();
        std::thread::spawn(move || {
            for c in l.incoming() {
                let Ok(mut c) = c else { return };
                // the headers and the body can arrive in separate reads: keep reading until the body is complete
                let mut req = Vec::new();
                let mut buf = [0u8; 4096];
                loop {
                    let n = c.read(&mut buf).unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    req.extend_from_slice(&buf[..n]);
                    let text = String::from_utf8_lossy(&req).to_string();
                    let Some((head, body)) = text.split_once("\r\n\r\n") else { continue };
                    let want = head.lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").and_then(|v| v.trim().parse::<usize>().ok())).unwrap_or(0);
                    if body.len() >= want {
                        break;
                    }
                }
                *g2.lock().unwrap() = String::from_utf8_lossy(&req).to_string();
                let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
            }
        });
        let (app, _store, [viewer, editor, admin]) = secured().await;
        let body = serde_json::json!({"name": "ops-slack", "kind": "slack", "url": url, "min_score": 40});
        for c in [&viewer, &editor] {
            assert_eq!(send(&app, req("GET", "/api/channels", Some(c), None)).await.0, StatusCode::FORBIDDEN);
            assert_eq!(send(&app, req("POST", "/api/channels", Some(c), Some(body.clone()))).await.0, StatusCode::FORBIDDEN);
        }
        let (st, _, v) = send(&app, req("POST", "/api/channels", Some(&admin), Some(body))).await;
        assert_eq!(st, StatusCode::CREATED, "{v}");
        let id = v["id"].as_str().unwrap().to_string();
        let (_, _, list) = send(&app, req("GET", "/api/channels", Some(&admin), None)).await;
        assert!(!list.to_string().contains("SUPERSECRET") && list[0]["has_url"] == true, "{list}");
        assert_eq!(send(&app, req("POST", "/api/channels", Some(&admin), Some(serde_json::json!({"name": "x", "kind": "slack", "url": "javascript:alert(1)"})))).await.0, StatusCode::BAD_REQUEST);
        // the test button really sends, and reports success
        let (st, _, v) = send(&app, req("POST", &format!("/api/channels/{id}/test"), Some(&admin), None)).await;
        assert_eq!((st, v["ok"].as_bool()), (StatusCode::OK, Some(true)), "{v}");
        assert!(got.lock().unwrap().contains("DENIS test notification"));
        // disable, then edit without re-sending the secret: the URL is kept
        let (st, _, v) = send(&app, req("PUT", &format!("/api/channels/{id}"), Some(&admin), Some(serde_json::json!({"enabled": false, "min_score": 70})))).await;
        assert_eq!((st, v["enabled"].as_bool(), v["min_score"].as_i64(), v["has_url"].as_bool()), (StatusCode::OK, Some(false), Some(70), Some(true)));
        assert_eq!(send(&app, req("PUT", "/api/channels/nope", Some(&admin), Some(serde_json::json!({})))).await.0, StatusCode::NOT_FOUND);
        // the audit log records the changes but not the URL
        let audit = send(&app, req("GET", "/api/audit", Some(&admin), None)).await.2.to_string();
        assert!(audit.contains("channel.create") && audit.contains("channel.test") && !audit.contains("SUPERSECRET"), "{audit}");
        // a channel that fails to deliver reports why, without leaking the token
        assert_eq!(send(&app, req("DELETE", &format!("/api/channels/{id}"), Some(&admin), None)).await.0, StatusCode::NO_CONTENT);
        let dead = serde_json::json!({"name": "dead", "kind": "webhook", "url": "http://127.0.0.1:1/hook/PRIVATETOKEN123"});
        let did = send(&app, req("POST", "/api/channels", Some(&admin), Some(dead))).await.2["id"].as_str().unwrap().to_string();
        let (st, _, v) = send(&app, req("POST", &format!("/api/channels/{did}/test"), Some(&admin), None)).await;
        assert_eq!(st, StatusCode::BAD_GATEWAY);
        assert!(!v.to_string().contains("PRIVATETOKEN"), "{v}");
    }

    #[tokio::test]
    async fn maintenance_mode_is_readable_by_all_and_settable_by_admins() {
        let (app, _, [viewer, editor, admin]) = secured().await;
        assert_eq!(send(&app, req("GET", "/api/maintenance", Some(&viewer), None)).await.2["active"], false);
        let on = serde_json::json!({"minutes": 60, "note": "patch night"});
        assert_eq!(send(&app, req("PUT", "/api/maintenance", Some(&editor), Some(on.clone()))).await.0, StatusCode::FORBIDDEN);
        assert_eq!(send(&app, req("PUT", "/api/maintenance", Some(&admin), Some(serde_json::json!({"minutes": 999999})))).await.0, StatusCode::BAD_REQUEST);
        let (st, _, v) = send(&app, req("PUT", "/api/maintenance", Some(&admin), Some(on))).await;
        assert_eq!((st, v["active"].as_bool(), v["note"].as_str()), (StatusCode::OK, Some(true), Some("patch night")));
        assert_eq!(send(&app, req("GET", "/api/maintenance", Some(&viewer), None)).await.2["active"], true);
        let (_, _, v) = send(&app, req("PUT", "/api/maintenance", Some(&admin), Some(serde_json::json!({"minutes": null})))).await;
        assert_eq!(v["active"], false);
    }

    #[tokio::test]
    async fn metrics_need_a_sign_in_or_token_and_expose_counts_but_no_names() {
        let (app, store, [viewer, _, admin]) = secured().await;
        let mut a = Asset::new(Mac([2, 0, 0, 0, 0, 9]), 1);
        a.hostnames = vec!["secret-host-name".into()];
        a.device_type = "camera".into();
        a.last_seen = now_ts();
        store.save_asset(&mut a).unwrap();
        assert_eq!(send(&app, req("GET", "/metrics", None, None)).await.0, StatusCode::UNAUTHORIZED);
        let scrape = |r: axum::http::Request<Body>| { let app = app.clone(); async move {
            let resp = app.oneshot(r).await.unwrap();
            (resp.status(), String::from_utf8(axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap().to_vec()).unwrap())
        } };
        let (st, body) = scrape(req("GET", "/metrics", Some(&viewer), None)).await;
        assert_eq!(st, StatusCode::OK);
        for want in ["denis_up 1", "denis_devices 1", "denis_devices_online 1", "denis_devices_by_type{type=\"camera\"} 1", "denis_alerts_unacknowledged{severity=\"high\"} 0", "denis_maintenance_mode 0", "denis_build_info{version="] {
            assert!(body.contains(want), "{want}\n{body}");
        }
        assert!(!body.contains("secret-host-name") && !body.contains("02:00:00"), "no names or addresses");
        // a Prometheus server uses an API token
        let (_, _, v) = send(&app, req("POST", "/api/api-tokens", Some(&admin), Some(serde_json::json!({"label": "prometheus", "role": "viewer"})))).await;
        let token = v["token"].as_str().unwrap().to_string();
        assert_eq!(scrape(bearer("GET", "/metrics", &token, None)).await.0, StatusCode::OK);
    }

    #[tokio::test]
    async fn the_review_queue_marks_devices_as_known_by_id_or_all_at_once_for_editors() {
        let (app, store, [viewer, editor, _]) = secured().await;
        let mut ids = Vec::new();
        for n in 1..=3u8 {
            let mut a = Asset::new(Mac([2, 0, 0, 0, 0, n]), 1);
            a.last_seen = now_ts();
            store.save_asset(&mut a).unwrap();
            ids.push(a.id);
        }
        let reviewed = |id: i64| store.get_meta(id).unwrap().is_some_and(|m| m.reviewed);
        assert_eq!(send(&app, req("POST", "/api/assets/review", Some(&viewer), Some(serde_json::json!({"ids": [ids[0]]})))).await.0, StatusCode::FORBIDDEN);
        assert_eq!(send(&app, req("POST", "/api/assets/review", Some(&editor), Some(serde_json::json!({})))).await.0, StatusCode::BAD_REQUEST);
        let (st, _, v) = send(&app, req("POST", "/api/assets/review", Some(&editor), Some(serde_json::json!({"ids": [ids[0], 99999]})))).await;
        assert_eq!((st, v["reviewed"].as_i64()), (StatusCode::OK, Some(1)));
        assert!(reviewed(ids[0]) && !reviewed(ids[1]));
        let f = send(&app, req("GET", "/api/findings", Some(&editor), None)).await.2;
        assert_eq!(f.as_array().unwrap().iter().find(|x| x["id"] == "unreviewed").unwrap()["assets"].as_array().unwrap().len(), 2);
        let (_, _, v) = send(&app, req("POST", "/api/assets/review", Some(&editor), Some(serde_json::json!({"all": true})))).await;
        assert_eq!(v["reviewed"].as_i64(), Some(2), "only the ones not yet reviewed change");
        assert!(ids.iter().all(|i| reviewed(*i)));
        assert!(send(&app, req("GET", "/api/findings", Some(&editor), None)).await.2.as_array().unwrap().iter().all(|x| x["id"] != "unreviewed"));
        // it survives a normal edit, and reviewed can be undone through the ordinary patch
        let (st, ..) = send(&app, req("PATCH", &format!("/api/assets/{}/meta", ids[0]), Some(&editor), Some(serde_json::json!({"owner": "Ann"})))).await;
        assert_eq!(st, StatusCode::OK);
        assert!(reviewed(ids[0]));
    }

    #[tokio::test]
    async fn bulk_tags_add_and_remove_one_tag_across_many_devices_for_editors() {
        let (app, store, [viewer, editor, _]) = secured().await;
        let mut ids = Vec::new();
        for n in 1..=3u8 {
            let mut a = Asset::new(Mac([3, 0, 0, 0, 0, n]), 1);
            store.save_asset(&mut a).unwrap();
            ids.push(a.id);
        }
        // device 0 already has the tag; adding it in bulk should not double it or count as changed
        let mut m = crate::model::AssetMeta { tags: vec!["rack-2".into()], ..Default::default() };
        store.save_meta(ids[0], &m, "setup", 1).unwrap();
        m.tags = vec![];

        assert_eq!(send(&app, req("POST", "/api/assets/bulk-tags", Some(&viewer), Some(serde_json::json!({"ids": ids, "add": "rack-2"})))).await.0, StatusCode::FORBIDDEN);
        assert_eq!(send(&app, req("POST", "/api/assets/bulk-tags", Some(&editor), Some(serde_json::json!({"ids": ids})))).await.0, StatusCode::BAD_REQUEST, "neither add nor remove given");
        assert_eq!(send(&app, req("POST", "/api/assets/bulk-tags", Some(&editor), Some(serde_json::json!({"ids": ids, "add": "rack-2", "remove": "x"})))).await.0, StatusCode::BAD_REQUEST, "both given");

        let tags_of = |id: i64| store.get_meta(id).unwrap().unwrap_or_default().tags;
        let (st, _, v) = send(&app, req("POST", "/api/assets/bulk-tags", Some(&editor), Some(serde_json::json!({"ids": ids, "add": "Rack-2"})))).await;
        assert_eq!((st, v["changed"].as_i64()), (StatusCode::OK, Some(2)), "only the two devices that did not already have it change");
        assert!(ids.iter().all(|&id| tags_of(id) == vec!["rack-2".to_string()]), "the tag is normalised the same way a single-device edit would");

        let (st, _, v) = send(&app, req("POST", "/api/assets/bulk-tags", Some(&editor), Some(serde_json::json!({"ids": ids, "remove": "rack-2"})))).await;
        assert_eq!((st, v["changed"].as_i64()), (StatusCode::OK, Some(3)));
        assert!(ids.iter().all(|&id| tags_of(id).is_empty()));

        // {"all": true} reaches every device, same as the review queue
        store.save_meta(ids[0], &crate::model::AssetMeta::default(), "setup", 1).unwrap();
        let (_, _, v) = send(&app, req("POST", "/api/assets/bulk-tags", Some(&editor), Some(serde_json::json!({"all": true, "add": "fleet"})))).await;
        assert_eq!(v["changed"].as_i64(), Some(3));
        assert!(ids.iter().all(|&id| tags_of(id) == vec!["fleet".to_string()]));
    }

    /// A console with passkeys on for `http://localhost:8080`, and one signed-in viewer "vera".
    async fn with_passkeys() -> (Router, Arc<dyn Store>, String, crate::passkey::Config) {
        let store: Arc<dyn Store> = Arc::new(SqliteStore::open_in_memory().unwrap());
        let auth = Arc::new(crate::auth::Auth::new(store.clone()));
        let cfg = crate::passkey::Config { rp_id: "localhost".into(), origins: vec!["http://localhost:8080".into()] };
        *auth.passkey_cfg.lock().unwrap() = Some(cfg.clone());
        store.create_user("vera", &crate::auth::hash_password("a-long-passphrase-1").unwrap(), "viewer", false, 0).unwrap();
        let app = router(AppState { store: store.clone(), shared: crate::engine::test_shared(), loopback_only: true, allowed_hosts: vec![], auth, no_auth: false, secure_cookie: false, license: crate::license::load(None, &*store) });
        let (st, h, _) = send(&app, req("POST", "/api/auth/login", None, Some(serde_json::json!({"username": "vera", "password": "a-long-passphrase-1"})))).await;
        assert_eq!(st, StatusCode::OK);
        (app, store, cookie_of(&h), cfg)
    }

    fn b64(b: &[u8]) -> String {
        crate::passkey::b64url(b)
    }

    /// Register `auth` for the signed-in user; returns the HTTP status.
    async fn register(app: &Router, cookie: &str, cfg: &crate::passkey::Config, auth: &crate::passkey::soft::Authenticator, name: &str) -> StatusCode {
        let (_, _, v) = send(app, req("POST", "/api/auth/passkey/register/begin", Some(cookie), Some(serde_json::json!({})))).await;
        let challenge = crate::passkey::unb64url(v["publicKey"]["challenge"].as_str().unwrap()).unwrap();
        let (cd, att) = auth.register(cfg, &challenge);
        let body = serde_json::json!({"ceremony": v["ceremony"], "name": name, "credential": {"id": b64(&auth.credential_id), "response": {"clientDataJSON": b64(&cd), "attestationObject": b64(&att)}}});
        send(app, req("POST", "/api/auth/passkey/register/finish", Some(cookie), Some(body))).await.0
    }

    /// Sign in with `auth`; returns the status and the cookie, if any.
    async fn passkey_login(app: &Router, cfg: &crate::passkey::Config, auth: &mut crate::passkey::soft::Authenticator) -> (StatusCode, Option<String>) {
        let (_, _, v) = send(app, req("POST", "/api/auth/passkey/login/begin", None, Some(serde_json::json!({})))).await;
        let challenge = crate::passkey::unb64url(v["publicKey"]["challenge"].as_str().unwrap()).unwrap();
        let (cd, ad, sig) = auth.assert(cfg, &challenge);
        let body = serde_json::json!({"ceremony": v["ceremony"], "credential": {"id": b64(&auth.credential_id), "response": {"clientDataJSON": b64(&cd), "authenticatorData": b64(&ad), "signature": b64(&sig), "userHandle": ""}}});
        let (st, h, _) = send(app, req("POST", "/api/auth/passkey/login/finish", None, Some(body))).await;
        (st, h.get(header::SET_COOKIE).map(|_| cookie_of(&h)))
    }

    #[tokio::test]
    async fn a_user_can_register_a_passkey_and_sign_in_with_it_and_only_with_it() {
        use crate::passkey::soft::Authenticator;
        let (app, store, cookie, cfg) = with_passkeys().await;
        // the sign-in page can ask what is offered, before anybody is signed in
        let (_, _, m) = send(&app, req("GET", "/api/auth/methods", None, None)).await;
        assert_eq!((m["passkey"].as_bool(), m["rp_id"].as_str()), (Some(true), Some("localhost")));
        // registering needs a session
        assert_eq!(send(&app, req("POST", "/api/auth/passkey/register/begin", None, Some(serde_json::json!({})))).await.0, StatusCode::UNAUTHORIZED);
        let mut mine = Authenticator::new();
        assert_eq!(register(&app, &cookie, &cfg, &mine, "Work laptop").await, StatusCode::CREATED);
        let (_, _, list) = send(&app, req("GET", "/api/auth/passkeys", Some(&cookie), None)).await;
        assert_eq!(list[0]["name"], "Work laptop");
        assert!(!list.to_string().contains("public_key") && !list.to_string().contains(&b64(&mine.credential_id)), "no key material is ever listed");
        // registering the same credential twice is refused
        assert_eq!(register(&app, &cookie, &cfg, &mine, "again").await, StatusCode::BAD_REQUEST);

        // sign in: a fresh session that works
        let (st, fresh) = passkey_login(&app, &cfg, &mut mine).await;
        assert_eq!(st, StatusCode::OK);
        let fresh = fresh.expect("session cookie");
        assert_eq!(send(&app, req("GET", "/api/auth/me", Some(&fresh), None)).await.2["user"]["username"], "vera");
        // the audit trail and last-used time record it
        assert!(store.list_audit(None, 50).unwrap().iter().any(|a| a.action == "auth.passkey_login"));
        assert!(store.list_passkeys(1).unwrap()[0].last_used.is_some());

        // a stranger's passkey (never registered) gets nowhere
        let mut stranger = Authenticator::new();
        assert_eq!(passkey_login(&app, &cfg, &mut stranger).await, (StatusCode::UNAUTHORIZED, None));
        // a cloned key: its counter goes back to 1 after the real one reached 2
        mine.counter = 0;
        assert_eq!(passkey_login(&app, &cfg, &mut mine).await.0, StatusCode::UNAUTHORIZED);
        // a finished (or made-up) ceremony cannot be replayed
        let replay = serde_json::json!({"ceremony": "abc", "credential": {"id": b64(&mine.credential_id), "response": {"clientDataJSON": "e30", "authenticatorData": "AA", "signature": "AA"}}});
        assert_eq!(send(&app, req("POST", "/api/auth/passkey/login/finish", None, Some(replay))).await.0, StatusCode::UNAUTHORIZED);
        // another person cannot remove it, its owner can, and then it no longer signs in
        store.create_user("eda", &crate::auth::hash_password("a-long-passphrase-1").unwrap(), "editor", false, 0).unwrap();
        let (_, h, _) = send(&app, req("POST", "/api/auth/login", None, Some(serde_json::json!({"username": "eda", "password": "a-long-passphrase-1"})))).await;
        let eda = cookie_of(&h);
        let pid = list[0]["id"].as_i64().unwrap();
        assert_eq!(send(&app, req("DELETE", &format!("/api/auth/passkeys/{pid}"), Some(&eda), None)).await.0, StatusCode::NOT_FOUND);
        mine.counter = 10;
        assert_eq!(passkey_login(&app, &cfg, &mut mine).await.0, StatusCode::OK);
        assert_eq!(send(&app, req("DELETE", &format!("/api/auth/passkeys/{pid}"), Some(&cookie), None)).await.0, StatusCode::NO_CONTENT);
        mine.counter = 20;
        assert_eq!(passkey_login(&app, &cfg, &mut mine).await.0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn passkeys_respect_disabled_accounts_pending_password_changes_and_the_off_switch() {
        use crate::passkey::soft::Authenticator;
        let (app, store, cookie, cfg) = with_passkeys().await;
        let mut mine = Authenticator::new();
        assert_eq!(register(&app, &cookie, &cfg, &mine, "phone").await, StatusCode::CREATED);
        // an account that owes a password change cannot skip it with a passkey
        store.update_user(1, None, None, None, Some(true)).unwrap();
        assert_eq!(passkey_login(&app, &cfg, &mut mine).await.0, StatusCode::FORBIDDEN);
        store.update_user(1, None, None, None, Some(false)).unwrap();
        // a disabled account cannot sign in at all
        store.update_user(1, None, Some(true), None, None).unwrap();
        assert_eq!(passkey_login(&app, &cfg, &mut mine).await.0, StatusCode::UNAUTHORIZED);
        store.update_user(1, None, Some(false), None, None).unwrap();
        assert_eq!(passkey_login(&app, &cfg, &mut mine).await.0, StatusCode::OK);
        // an administrator can revoke everything a user has (lost device)
        store.create_user("adam", &crate::auth::hash_password("a-long-passphrase-1").unwrap(), "admin", false, 0).unwrap();
        let (_, h, _) = send(&app, req("POST", "/api/auth/login", None, Some(serde_json::json!({"username": "adam", "password": "a-long-passphrase-1"})))).await;
        let adam = cookie_of(&h);
        assert_eq!(send(&app, req("DELETE", "/api/users/1/passkeys", Some(&cookie), None)).await.0, StatusCode::FORBIDDEN);
        let (st, _, v) = send(&app, req("DELETE", "/api/users/1/passkeys", Some(&adam), None)).await;
        assert_eq!((st, v["removed"].as_i64()), (StatusCode::OK, Some(1)));
        assert_eq!(passkey_login(&app, &cfg, &mut mine).await.0, StatusCode::UNAUTHORIZED);
        // where passkeys are off, everything says so
        let (app2, ..) = secured().await;
        assert_eq!(send(&app2, req("GET", "/api/auth/methods", None, None)).await.2["passkey"], false);
        assert_eq!(send(&app2, req("POST", "/api/auth/passkey/login/begin", None, Some(serde_json::json!({})))).await.0, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn the_compliance_view_reflects_the_register_and_is_readable_by_viewers() {
        let (app, store, [viewer, ..]) = secured().await;
        let mut a = Asset::new(Mac([2, 0, 0, 0, 0, 5]), 1);
        a.last_seen = now_ts();
        a.device_type = "computer".into();
        store.save_asset(&mut a).unwrap();
        let (st, _, v) = send(&app, req("GET", "/api/compliance", Some(&viewer), None)).await;
        assert_eq!(st, StatusCode::OK);
        let reviewed = v["measures"].as_array().unwrap().iter().find(|m| m["label"].as_str().unwrap().contains("reviewed")).unwrap();
        assert_eq!(reviewed["percent"], 0);
        store.save_meta(a.id, &AssetMeta { reviewed: true, owner: Some("Ops".into()), ..Default::default() }, "t", 1).unwrap();
        let (_, _, v) = send(&app, req("GET", "/api/compliance", Some(&viewer), None)).await;
        let r = v["measures"].as_array().unwrap().iter().find(|m| m["label"].as_str().unwrap().contains("reviewed")).unwrap();
        assert_eq!(r["percent"], 100);
        assert!(v["controls"].as_array().unwrap().len() >= 10 && v["disclaimer"].as_str().unwrap().contains("not a certification"));
    }

    #[tokio::test]
    async fn demo_data_can_be_loaded_and_removed_by_admins_and_everything_can_be_erased_only_with_the_exact_words() {
        let (app, store, [viewer, editor, admin]) = secured().await;
        let mut real = Asset::new(Mac([2, 0, 0, 0, 0, 77]), 1);
        store.save_asset(&mut real).unwrap();
        assert_eq!(send(&app, req("GET", "/api/demo", Some(&viewer), None)).await.2["loaded"], false);
        for c in [&viewer, &editor] {
            assert_eq!(send(&app, req("POST", "/api/demo", Some(c), None)).await.0, StatusCode::FORBIDDEN);
            assert_eq!(send(&app, req("DELETE", "/api/demo", Some(c), None)).await.0, StatusCode::FORBIDDEN);
            assert_eq!(send(&app, req("POST", "/api/data/erase", Some(c), Some(serde_json::json!({"confirm": "ERASE ALL DATA"})))).await.0, StatusCode::FORBIDDEN);
        }
        let (st, _, v) = send(&app, req("POST", "/api/demo", Some(&admin), None)).await;
        assert_eq!((st, v["assets"].as_i64()), (StatusCode::CREATED, Some(42)));
        assert_eq!(send(&app, req("POST", "/api/demo", Some(&admin), None)).await.0, StatusCode::CONFLICT);
        assert_eq!(send(&app, req("GET", "/api/demo", Some(&viewer), None)).await.2["loaded"], true);
        let assets = send(&app, req("GET", "/api/assets", Some(&viewer), None)).await.2;
        assert_eq!(assets.as_array().unwrap().len(), 43, "demo devices show like any other");
        let (_, _, v) = send(&app, req("DELETE", "/api/demo", Some(&admin), None)).await;
        assert_eq!(v["removed"], 42);
        assert_eq!(send(&app, req("GET", "/api/assets", Some(&viewer), None)).await.2.as_array().unwrap().len(), 1, "the real device stayed");
        // erase: wrong or missing words change nothing
        for bad in [serde_json::json!({}), serde_json::json!({"confirm": "erase all data"}), serde_json::json!({"confirm": "yes"})] {
            let (st, ..) = send(&app, req("POST", "/api/data/erase", Some(&admin), Some(bad))).await;
            assert!(st == StatusCode::BAD_REQUEST || st == StatusCode::UNPROCESSABLE_ENTITY, "{st}");
        }
        assert_eq!(store.load_assets().unwrap().len(), 1);
        let (st, ..) = send(&app, req("POST", "/api/data/erase", Some(&admin), Some(serde_json::json!({"confirm": "ERASE ALL DATA"})))).await;
        assert_eq!(st, StatusCode::OK);
        assert!(store.load_assets().unwrap().is_empty());
        assert_eq!(store.list_users().unwrap().len(), 3, "accounts survive");
        let audit = send(&app, req("GET", "/api/audit", Some(&admin), None)).await.2.to_string();
        assert!(audit.contains("demo.load") && audit.contains("demo.remove") && audit.contains("data.erase"), "{audit}");
    }

    #[tokio::test]
    async fn update_status_is_readable_by_everyone_and_every_action_needs_an_administrator() {
        let (app, _, [viewer, editor, admin]) = secured().await;
        let (st, _, v) = send(&app, req("GET", "/api/update", Some(&viewer), None)).await;
        assert_eq!((st, v["available"].as_bool(), v["current"].as_str()), (StatusCode::OK, Some(false), Some(env!("CARGO_PKG_VERSION"))));
        for c in [&viewer, &editor] {
            for (m, u, body) in [("POST", "/api/update/check", None), ("POST", "/api/update/install", Some(serde_json::json!({}))), ("POST", "/api/update/snooze", Some(serde_json::json!({"days": 3}))), ("POST", "/api/update/skip", None), ("DELETE", "/api/update/schedule", None)] {
                assert_eq!(send(&app, req(m, u, Some(c), body)).await.0, StatusCode::FORBIDDEN, "{m} {u}");
            }
        }
        // this test console has no updater: an administrator is told so, not crashed on
        let (st, ..) = send(&app, req("POST", "/api/update/install", Some(&admin), Some(serde_json::json!({})))).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn the_certificate_can_be_inspected_replaced_and_reset_only_by_admins_and_the_ca_is_public() {
        let dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn Store> = Arc::new(SqliteStore::open_in_memory().unwrap());
        let shared = crate::engine::test_shared();
        // without TLS the API says so
        let auth = Arc::new(crate::auth::Auth::new(store.clone()));
        let app_off = router(AppState { store: store.clone(), shared: shared.clone(), loopback_only: true, allowed_hosts: vec![], auth: auth.clone(), no_auth: true, secure_cookie: false, license: crate::license::load(None, &*store) });
        assert_eq!(send(&app_off, req("GET", "/api/tls", None, None)).await.2["enabled"], false);
        assert_eq!(send(&app_off, req("POST", "/api/tls/certificate", None, Some(serde_json::json!({"certificate": "x", "key": "y"})))).await.0, StatusCode::BAD_REQUEST);
        assert_eq!(app_off.clone().oneshot(req("GET", "/tls/ca.pem", None, None)).await.unwrap().status(), StatusCode::NOT_FOUND);

        // with a managed certificate
        crate::certs::ensure(dir.path(), &[], now_ts()).unwrap();
        let config = crate::tls::load(&dir.path().join(crate::certs::SERVER_CERT), &dir.path().join(crate::certs::SERVER_KEY)).await.unwrap();
        shared.set_tls_for_test(Arc::new(crate::tls::TlsHandle { config, dir: Some(dir.path().to_path_buf()), names: vec![] }));
        for u in ["viewer", "editor", "adam"] {
            let role = match u { "viewer" => "viewer", "editor" => "editor", _ => "admin" };
            store.create_user(u, &crate::auth::hash_password("a-long-passphrase-1").unwrap(), role, false, 0).unwrap();
        }
        let app = router(AppState { store: store.clone(), shared, loopback_only: true, allowed_hosts: vec![], auth, no_auth: false, secure_cookie: false, license: crate::license::load(None, &*store) });
        let login = |u: &'static str| { let app = app.clone(); async move {
            let (_, h, _) = send(&app, req("POST", "/api/auth/login", None, Some(serde_json::json!({"username": u, "password": "a-long-passphrase-1"})))).await;
            cookie_of(&h)
        } };
        let (viewer, editor, admin) = (login("viewer").await, login("editor").await, login("adam").await);
        for c in [&viewer, &editor] {
            assert_eq!(send(&app, req("GET", "/api/tls", Some(c), None)).await.0, StatusCode::FORBIDDEN);
            assert_eq!(send(&app, req("POST", "/api/tls/certificate", Some(c), Some(serde_json::json!({"certificate": "x", "key": "y"})))).await.0, StatusCode::FORBIDDEN);
            assert_eq!(send(&app, req("DELETE", "/api/tls/certificate", Some(c), None)).await.0, StatusCode::FORBIDDEN);
        }
        let (_, _, v) = send(&app, req("GET", "/api/tls", Some(&admin), None)).await;
        assert_eq!((v["enabled"].as_bool(), v["info"]["source"].as_str(), v["has_ca"].as_bool()), (Some(true), Some("generated"), Some(true)));
        // the authority's certificate is downloadable before anyone signs in, and it is only the certificate
        let resp = app.clone().oneshot(req("GET", "/tls/ca.pem", None, None)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = String::from_utf8(axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap().to_vec()).unwrap();
        assert!(body.contains("BEGIN CERTIFICATE") && !body.contains("PRIVATE"), "never the key");
        // uploads are validated
        let bad = serde_json::json!({"certificate": "nonsense", "key": "nonsense"});
        assert_eq!(send(&app, req("POST", "/api/tls/certificate", Some(&admin), Some(bad))).await.0, StatusCode::BAD_REQUEST);
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["denis.corp.example".to_string()]).unwrap().self_signed(&key).unwrap();
        let good = serde_json::json!({"certificate": cert.pem(), "key": key.serialize_pem()});
        let (st, _, v) = send(&app, req("POST", "/api/tls/certificate", Some(&admin), Some(good))).await;
        assert_eq!((st, v["source"].as_str(), v["names"][0].as_str()), (StatusCode::OK, Some("custom"), Some("denis.corp.example")), "{v}");
        assert_eq!(send(&app, req("GET", "/api/tls", Some(&admin), None)).await.2["info"]["source"], "custom");
        // the audit log knows, without the key
        let audit = send(&app, req("GET", "/api/audit", Some(&admin), None)).await.2.to_string();
        assert!(audit.contains("tls.replace") && !audit.contains("PRIVATE"), "{audit}");
        // and the generated certificate can be brought back
        let (st, _, v) = send(&app, req("DELETE", "/api/tls/certificate", Some(&admin), None)).await;
        assert_eq!((st, v["source"].as_str()), (StatusCode::OK, Some("generated")));
    }

    #[tokio::test]
    async fn the_documentation_needs_sign_in_serves_known_pages_only_and_never_allows_script() {
        let (app, _, [viewer, ..]) = secured().await;
        let (st, ..) = send(&app, req("GET", "/docs/index", None, None)).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
        let resp = app.clone().oneshot(req("GET", "/docs/detection-rules", Some(&viewer), None)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let csp = resp.headers()[header::CONTENT_SECURITY_POLICY].to_str().unwrap().to_string();
        assert!(csp.contains("default-src 'none'") && !csp.contains("script-src"), "{csp}");
        let body = String::from_utf8(axum::body::to_bytes(resp.into_body(), 1 << 22).await.unwrap().to_vec()).unwrap();
        assert!(body.contains("Detection rules") && body.contains("<nav>") && !body.contains("<script"));
        for bad in ["/docs/nope", "/docs/..%2Fsecret", "/docs/index.md"] {
            assert_eq!(send(&app, req("GET", bad, Some(&viewer), None)).await.0, StatusCode::NOT_FOUND, "{bad}");
        }
        assert_eq!(app.clone().oneshot(req("GET", "/docs/", Some(&viewer), None)).await.unwrap().status(), StatusCode::SEE_OTHER);
    }

    #[tokio::test]
    async fn findings_list_what_is_wrong_with_the_stored_inventory_and_respect_corrections() {
        let (app, store) = app(true);
        let mut cam = Asset::new(Mac([2, 0, 0, 0, 0, 1]), 10);
        cam.device_type = "camera".into();
        cam.vendor = Some("Acme".into());
        cam.last_seen = now_ts();
        cam.open_ports = vec![crate::model::OpenPort { port: 23, proto: "tcp".into(), service: None }];
        store.save_asset(&mut cam).unwrap();
        let (code, v) = get_json(&app, "/api/findings", "localhost").await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(v[0]["id"], "telnet_open");
        assert_eq!(v[0]["assets"], serde_json::json!([cam.id]));
        assert!(v[0]["fix"].as_str().unwrap().contains("SSH"));
        // marking the device as spare takes it out of the list
        store.save_meta(cam.id, &crate::model::AssetMeta { status: Some("spare".into()), ..Default::default() }, "t", 1).unwrap();
        assert!(get_json(&app, "/api/findings", "localhost").await.1.as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_risk_can_be_accepted_by_admins_only_with_a_reason_leaves_the_open_list_and_can_be_withdrawn() {
        let (app, store, [viewer, editor, admin]) = secured().await;
        let mut cam = Asset::new(Mac([2, 0, 0, 0, 0, 1]), 10);
        cam.device_type = "camera".into();
        cam.vendor = Some("Acme".into());
        cam.last_seen = now_ts();
        cam.open_ports = vec![crate::model::OpenPort { port: 23, proto: "tcp".into(), service: None }];
        store.save_asset(&mut cam).unwrap();
        let mut cam2 = Asset::new(Mac([2, 0, 0, 0, 0, 2]), 10);
        cam2.device_type = "camera".into();
        cam2.vendor = Some("Acme".into());
        cam2.last_seen = now_ts();
        cam2.open_ports = cam.open_ports.clone();
        store.save_asset(&mut cam2).unwrap();
        let body = serde_json::json!({"finding_id": "telnet_open", "asset_ids": [cam.id], "reason": "isolated VLAN, replaced in Q4", "days": 90});
        for c in [&viewer, &editor] {
            assert_eq!(send(&app, req("POST", "/api/risk-acceptances", Some(c), Some(body.clone()))).await.0, StatusCode::FORBIDDEN, "only an administrator decides what risk to live with");
        }
        // refused: no reason, an unknown finding, a finding the device does not have, too long a time
        for bad in [
            serde_json::json!({"finding_id": "telnet_open", "asset_ids": [cam.id], "reason": " "}),
            serde_json::json!({"finding_id": "nope", "asset_ids": [cam.id], "reason": "because"}),
            serde_json::json!({"finding_id": "telnet_open", "asset_ids": [], "reason": "because"}),
            serde_json::json!({"finding_id": "telnet_open", "asset_ids": [cam.id], "reason": "because", "days": 100000}),
        ] {
            assert_eq!(send(&app, req("POST", "/api/risk-acceptances", Some(&admin), Some(bad.clone()))).await.0, StatusCode::BAD_REQUEST, "{bad}");
        }
        for bad in [serde_json::json!({"finding_id": "ftp_open", "asset_ids": [cam.id], "reason": "because"}), serde_json::json!({"finding_id": "telnet_open", "asset_ids": [9999], "reason": "because"})] {
            assert_eq!(send(&app, req("POST", "/api/risk-acceptances", Some(&admin), Some(bad.clone()))).await.0, StatusCode::CONFLICT, "only a risk that exists can be accepted: {bad}");
        }
        assert_eq!(send(&app, req("GET", "/api/findings", Some(&viewer), None)).await.2[0]["assets"], serde_json::json!([cam.id, cam2.id]));
        let (st, _, v) = send(&app, req("POST", "/api/risk-acceptances", Some(&admin), Some(body))).await;
        assert_eq!(st, StatusCode::CREATED, "{v}");
        let id = v["ids"][0].as_i64().unwrap();
        // one device drops out of the finding, the other stays; the decision is listed with who and why
        assert_eq!(send(&app, req("GET", "/api/findings", Some(&viewer), None)).await.2[0]["assets"], serde_json::json!([cam2.id]));
        let (_, _, list) = send(&app, req("GET", "/api/risk-acceptances", Some(&viewer), None)).await;
        assert_eq!((list[0]["asset_id"].as_i64(), list[0]["reason"].as_str(), list[0]["accepted_by"].as_str(), list[0]["still_applies"].as_bool()), (Some(cam.id), Some("isolated VLAN, replaced in Q4"), Some("adam"), Some(true)), "{list}");
        assert!(list[0]["expires_at"].as_i64().unwrap() > now_ts() + 89 * 86_400);
        // the report an auditor reads carries it, and the metrics count it
        let text = |resp: Response| async move { String::from_utf8_lossy(&axum::body::to_bytes(resp.into_body(), 10_000_000).await.unwrap()).to_string() };
        let report = text(app.clone().oneshot(req("GET", "/report", Some(&viewer), None)).await.unwrap()).await;
        assert!(report.contains("Accepted risks") && report.contains("isolated VLAN"), "the printable report lists accepted risks");
        let metrics = text(app.clone().oneshot(req("GET", "/metrics", Some(&viewer), None)).await.unwrap()).await;
        assert!(metrics.contains("denis_accepted_risks 1"), "{metrics}");
        // withdraw it: the device is back in the finding; a second withdrawal finds nothing
        assert_eq!(send(&app, req("DELETE", &format!("/api/risk-acceptances/{id}"), Some(&editor), None)).await.0, StatusCode::FORBIDDEN);
        assert_eq!(send(&app, req("DELETE", &format!("/api/risk-acceptances/{id}"), Some(&admin), None)).await.0, StatusCode::OK);
        assert_eq!(send(&app, req("DELETE", &format!("/api/risk-acceptances/{id}"), Some(&admin), None)).await.0, StatusCode::NOT_FOUND);
        assert_eq!(send(&app, req("GET", "/api/findings", Some(&viewer), None)).await.2[0]["assets"], serde_json::json!([cam.id, cam2.id]));
        let audit = send(&app, req("GET", "/api/audit", Some(&admin), None)).await.2.to_string();
        assert!(audit.contains("risk.accept") && audit.contains("risk.revoke") && audit.contains("isolated VLAN"), "who decided what, and why, is in the audit log");
    }

    #[tokio::test]
    async fn reports_are_saved_viewed_downloaded_scheduled_and_deleted_with_the_right_roles() {
        let (app, store, [viewer, editor, admin]) = secured().await;
        let mut cam = Asset::new(Mac([2, 0, 0, 0, 0, 1]), 10);
        cam.device_type = "camera".into();
        cam.last_seen = now_ts();
        store.save_asset(&mut cam).unwrap();
        let text = |resp: Response| async move { (resp.status(), resp.headers().clone(), String::from_utf8_lossy(&axum::body::to_bytes(resp.into_body(), 10_000_000).await.unwrap()).to_string()) };
        // a viewer reads reports but cannot make them; an editor can
        assert_eq!(send(&app, req("POST", "/api/reports", Some(&viewer), Some(serde_json::json!({"days": 7})))).await.0, StatusCode::FORBIDDEN);
        assert_eq!(send(&app, req("POST", "/api/reports", Some(&editor), Some(serde_json::json!({"days": 0})))).await.0, StatusCode::BAD_REQUEST);
        let (st, _, meta) = send(&app, req("POST", "/api/reports", Some(&editor), Some(serde_json::json!({"days": 30})))).await;
        assert_eq!(st, StatusCode::CREATED, "{meta}");
        let id = meta["id"].as_i64().unwrap();
        assert_eq!((meta["kind"].as_str(), meta["created_by"].as_str(), meta["period_days"].as_i64()), (Some("manual"), Some("eda"), Some(30)));
        let (_, _, list) = send(&app, req("GET", "/api/reports", Some(&viewer), None)).await;
        assert_eq!(list["reports"][0]["id"], id);
        assert_eq!(list["settings"]["schedule"], "off");
        // viewing: inline, with a strict CSP, and it carries the compliance overview with all the frameworks
        let (st, h, body) = text(app.clone().oneshot(req("GET", &format!("/api/reports/{id}"), Some(&viewer), None)).await.unwrap()).await;
        assert_eq!(st, StatusCode::OK);
        assert!(h[header::CONTENT_SECURITY_POLICY].to_str().unwrap().contains("default-src 'none'"));
        assert_eq!(h[header::CONTENT_DISPOSITION], "inline");
        for want in ["Compliance overview", "CIS Controls", "NIS2", "ISO/IEC 27001:2022", "Devices by risk"] {
            assert!(body.contains(want), "{want}");
        }
        let (_, h, _) = text(app.clone().oneshot(req("GET", &format!("/api/reports/{id}?download=1"), Some(&viewer), None)).await.unwrap()).await;
        assert!(h[header::CONTENT_DISPOSITION].to_str().unwrap().starts_with("attachment; filename=\"denis-report-"));
        assert_eq!(send(&app, req("GET", "/api/reports/9999", Some(&viewer), None)).await.0, StatusCode::NOT_FOUND);
        // sharing: admin-only, idempotent, reachable with no session at all by its token, and the
        // list shows the current token so the console can offer the link again
        assert_eq!(send(&app, req("PUT", &format!("/api/reports/{id}/share"), Some(&editor), None)).await.0, StatusCode::FORBIDDEN);
        let (st, _, v) = send(&app, req("PUT", &format!("/api/reports/{id}/share"), Some(&admin), None)).await;
        assert_eq!(st, StatusCode::OK);
        let token = v["share_token"].as_str().unwrap().to_string();
        assert_eq!(send(&app, req("PUT", &format!("/api/reports/{id}/share"), Some(&admin), None)).await.2["share_token"], token, "a second share reuses the same link");
        let (_, _, list) = send(&app, req("GET", "/api/reports", Some(&viewer), None)).await;
        assert_eq!(list["reports"][0]["share_token"], token);
        let (st, h, body) = text(app.clone().oneshot(req("GET", &format!("/api/reports/shared/{token}"), None, None)).await.unwrap()).await;
        assert_eq!(st, StatusCode::OK, "no cookie, no bearer token -- just the shared link");
        assert!(h[header::CONTENT_SECURITY_POLICY].to_str().unwrap().contains("default-src 'none'"));
        assert!(body.contains("Compliance overview"));
        assert_eq!(send(&app, req("GET", "/api/reports/shared/not-a-real-token", None, None)).await.0, StatusCode::NOT_FOUND);
        assert_eq!(send(&app, req("DELETE", &format!("/api/reports/{id}/share"), Some(&editor), None)).await.0, StatusCode::FORBIDDEN);
        assert_eq!(send(&app, req("DELETE", &format!("/api/reports/{id}/share"), Some(&admin), None)).await.0, StatusCode::NO_CONTENT);
        assert_eq!(send(&app, req("GET", &format!("/api/reports/shared/{token}"), None, None)).await.0, StatusCode::NOT_FOUND, "the old link stops working");
        // the schedule: administrators only, validated
        let sched = serde_json::json!({"schedule": "weekly", "keep": 4, "days": 14});
        assert_eq!(send(&app, req("PUT", "/api/reports/settings", Some(&editor), Some(sched.clone()))).await.0, StatusCode::FORBIDDEN);
        assert_eq!(send(&app, req("PUT", "/api/reports/settings", Some(&admin), Some(serde_json::json!({"schedule": "hourly", "keep": 4, "days": 14})))).await.0, StatusCode::BAD_REQUEST);
        assert_eq!(send(&app, req("PUT", "/api/reports/settings", Some(&admin), Some(sched))).await.0, StatusCode::OK);
        assert_eq!(send(&app, req("GET", "/api/reports/settings", Some(&viewer), None)).await.2["keep"], 4);
        // deleting: administrators only
        // deleting a report also revokes its share, if it had one
        let token2 = send(&app, req("PUT", &format!("/api/reports/{id}/share"), Some(&admin), None)).await.2["share_token"].as_str().unwrap().to_string();
        assert_eq!(send(&app, req("DELETE", &format!("/api/reports/{id}"), Some(&editor), None)).await.0, StatusCode::FORBIDDEN);
        assert_eq!(send(&app, req("DELETE", &format!("/api/reports/{id}"), Some(&admin), None)).await.0, StatusCode::NO_CONTENT);
        assert_eq!(send(&app, req("DELETE", &format!("/api/reports/{id}"), Some(&admin), None)).await.0, StatusCode::NOT_FOUND);
        assert_eq!(send(&app, req("GET", &format!("/api/reports/shared/{token2}"), None, None)).await.0, StatusCode::NOT_FOUND, "deleting the report revoked its share too");
        let audit = send(&app, req("GET", "/api/audit", Some(&admin), None)).await.2.to_string();
        assert!(audit.contains("report.create") && audit.contains("report.schedule") && audit.contains("report.delete"));
    }

    #[tokio::test]
    async fn health_and_backups_work_for_the_right_roles_and_never_leave_the_backup_folder() {
        let tmp = tempfile::tempdir().unwrap();
        let (app, _store, [viewer, editor, admin]) = secured_with(crate::engine::test_shared_at(tmp.path().join("denis.db"))).await;
        // anyone signed in sees the health summary; the sentences are ones the console translates
        let (st, _, h) = send(&app, req("GET", "/api/system", Some(&viewer), None)).await;
        assert_eq!(st, StatusCode::OK);
        assert!(h["db"]["db_bytes"].as_i64().unwrap() > 0 && h["db"]["schema_version"].as_i64().unwrap() >= 11, "{h}");
        assert!(h["disk"][1].as_u64().unwrap() > 0);
        assert_eq!(h["backups"]["schedule"], "daily");
        assert!(h["db"]["rows"].as_array().unwrap().iter().any(|r| r[0] == "events"));
        // backups: administrators only, for every method
        for c in [&viewer, &editor] {
            assert_eq!(send(&app, req("GET", "/api/backups", Some(c), None)).await.0, StatusCode::FORBIDDEN);
            assert_eq!(send(&app, req("POST", "/api/backups", Some(c), None)).await.0, StatusCode::FORBIDDEN);
        }
        let (st, _, made) = send(&app, req("POST", "/api/backups", Some(&admin), None)).await;
        assert_eq!(st, StatusCode::CREATED, "{made}");
        let name = made["name"].as_str().unwrap().to_string();
        assert!(name.starts_with("denis-manual-") && made["size"].as_u64().unwrap() > 0);
        let (_, _, list) = send(&app, req("GET", "/api/backups", Some(&admin), None)).await;
        assert_eq!(list["backups"][0]["name"], name.as_str());
        // the file is a real SQLite database
        let resp = app.clone().oneshot(req("GET", &format!("/api/backups/{name}"), Some(&admin), None)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers()[header::CONTENT_DISPOSITION].to_str().unwrap().contains(&name));
        let bytes = axum::body::to_bytes(resp.into_body(), 100_000_000).await.unwrap();
        assert!(bytes.starts_with(b"SQLite format 3"));
        // names that are not backups are not found, whatever they look like
        for bad in ["denis.db", "..%2Fdenis.db", "denis-auto-nothing.db", "passwd"] {
            assert_eq!(send(&app, req("GET", &format!("/api/backups/{bad}"), Some(&admin), None)).await.0, StatusCode::NOT_FOUND, "{bad}");
        }
        // the schedule is validated, saved, and shows up in the health summary
        assert_eq!(send(&app, req("PUT", "/api/backups/settings", Some(&admin), Some(serde_json::json!({"schedule": "hourly", "keep": 3})))).await.0, StatusCode::BAD_REQUEST);
        assert_eq!(send(&app, req("PUT", "/api/backups/settings", Some(&admin), Some(serde_json::json!({"schedule": "weekly", "keep": 3})))).await.0, StatusCode::OK);
        assert_eq!(send(&app, req("GET", "/api/system", Some(&viewer), None)).await.2["backups"]["schedule"], "weekly");
        assert_eq!(send(&app, req("DELETE", &format!("/api/backups/{name}"), Some(&admin), None)).await.0, StatusCode::NO_CONTENT);
        assert_eq!(send(&app, req("DELETE", &format!("/api/backups/{name}"), Some(&admin), None)).await.0, StatusCode::NOT_FOUND);
        let audit = send(&app, req("GET", "/api/audit", Some(&admin), None)).await.2.to_string();
        assert!(audit.contains("backup.create") && audit.contains("backup.download") && audit.contains("backup.schedule") && audit.contains("backup.delete"));
    }

    #[tokio::test]
    async fn the_upload_schedule_is_hidden_without_an_upstream_and_agent_retention_is_independent() {
        let tmp = tempfile::tempdir().unwrap();
        let (app, store, [viewer, _editor, admin]) = secured_with(crate::engine::test_shared_at(tmp.path().join("denis.db"))).await;

        // no --backup-upstream configured on this test install: nothing to show or set
        let (_, _, list) = send(&app, req("GET", "/api/backups", Some(&admin), None)).await;
        assert_eq!(list["upload_configured"], false);
        assert_eq!(list["upload_settings"]["schedule"], "daily");
        assert_eq!(list["agent_keep"], crate::backups::DEFAULT_AGENT_KEEP);

        // the upload schedule is validated and saved regardless (a console viewing it before
        // --backup-upstream is added later is not an error)
        assert_eq!(send(&app, req("PUT", "/api/backups/upload-schedule", Some(&viewer), Some(serde_json::json!({"schedule": "every8h"})))).await.0, StatusCode::FORBIDDEN);
        assert_eq!(send(&app, req("PUT", "/api/backups/upload-schedule", Some(&admin), Some(serde_json::json!({"schedule": "hourly"})))).await.0, StatusCode::BAD_REQUEST);
        assert_eq!(send(&app, req("PUT", "/api/backups/upload-schedule", Some(&admin), Some(serde_json::json!({"schedule": "every8h"})))).await.0, StatusCode::OK);
        assert_eq!(send(&app, req("GET", "/api/backups", Some(&admin), None)).await.2["upload_settings"]["schedule"], "every8h");

        // the per-agent retention is a separate, always-available local setting
        assert_eq!(send(&app, req("PUT", "/api/backups/agent-keep", Some(&viewer), Some(serde_json::json!({"keep": 5})))).await.0, StatusCode::FORBIDDEN);
        assert_eq!(send(&app, req("PUT", "/api/backups/agent-keep", Some(&admin), Some(serde_json::json!({"keep": 0})))).await.0, StatusCode::BAD_REQUEST);
        assert_eq!(send(&app, req("PUT", "/api/backups/agent-keep", Some(&admin), Some(serde_json::json!({"keep": 5})))).await.0, StatusCode::NO_CONTENT);
        assert_eq!(send(&app, req("GET", "/api/backups", Some(&admin), None)).await.2["agent_keep"], 5);

        let audit = send(&app, req("GET", "/api/audit", Some(&admin), None)).await.2.to_string();
        assert!(audit.contains("backup.upload_schedule") && audit.contains("backup.agent_keep"), "{audit}");
        let _ = store;
    }

    #[tokio::test]
    async fn an_admin_can_browse_download_and_delete_customers_uploaded_backups() {
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("denis.db");
        let (app, store, [viewer, editor, admin]) = secured_with(crate::engine::test_shared_at(db_path.clone())).await;
        store.upsert_agent(&crate::model::AgentInfo { id: "customer-a".into(), name: "Customer A".into(), site: None, version: "1.0".into(), subnet: "10.0.0.0/24".into(), first_seen: 1, last_report_at: 1, last_run_id: String::new(), last_seq: 0 }).unwrap();

        // nothing uploaded yet
        let (_, _, list) = send(&app, req("GET", "/api/msp-backups", Some(&admin), None)).await;
        assert_eq!(list.as_array().unwrap().len(), 0);

        // seed an uploaded backup by hand (the HTTP upload path itself is covered in ingest.rs)
        let dir = crate::backups::agents_dir(&db_path).join("customer-a");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("denis-auto-20260101T000000Z.db"), b"SQLite format 3\0fake").unwrap();

        // viewer/editor cannot see it at all: these hold other customers' secrets too
        for c in [&viewer, &editor] {
            assert_eq!(send(&app, req("GET", "/api/msp-backups", Some(c), None)).await.0, StatusCode::FORBIDDEN);
        }
        let (st, _, list) = send(&app, req("GET", "/api/msp-backups", Some(&admin), None)).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!((list[0]["agent_id"].as_str(), list[0]["name"].as_str(), list[0]["backups"].as_array().unwrap().len()), (Some("customer-a"), Some("Customer A"), 1));

        // path traversal in either the agent id or the file name is refused, not just ignored
        for bad in ["../customer-a", "customer-a/../../etc"] {
            assert_eq!(send(&app, req("GET", &format!("/api/msp-backups/{}/denis-auto-20260101T000000Z.db", bad.replace('/', "%2F")), Some(&admin), None)).await.0, StatusCode::NOT_FOUND, "{bad}");
        }
        assert_eq!(send(&app, req("GET", "/api/msp-backups/customer-a/..%2F..%2Fdenis.db", Some(&admin), None)).await.0, StatusCode::NOT_FOUND);

        // the real file downloads
        let resp = app.clone().oneshot(req("GET", "/api/msp-backups/customer-a/denis-auto-20260101T000000Z.db", Some(&admin), None)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        assert!(bytes.starts_with(b"SQLite format 3"));

        // only an admin may delete it
        assert_eq!(send(&app, req("DELETE", "/api/msp-backups/customer-a/denis-auto-20260101T000000Z.db", Some(&viewer), None)).await.0, StatusCode::FORBIDDEN);
        assert_eq!(send(&app, req("DELETE", "/api/msp-backups/customer-a/denis-auto-20260101T000000Z.db", Some(&admin), None)).await.0, StatusCode::NO_CONTENT);
        assert_eq!(send(&app, req("GET", "/api/msp-backups", Some(&admin), None)).await.2[0]["backups"].as_array().unwrap().len(), 0);

        let audit = send(&app, req("GET", "/api/audit", Some(&admin), None)).await.2.to_string();
        assert!(audit.contains("msp_backup.download") && audit.contains("msp_backup.delete"), "{audit}");
    }

    #[tokio::test]
    async fn verify_fix_rereads_the_register_and_says_plainly_when_it_cannot_scan() {
        let (app, store, [viewer, editor, _admin]) = secured().await;
        let mut cam = Asset::new(Mac([2, 0, 0, 0, 0, 1]), 10);
        cam.device_type = "camera".into();
        cam.vendor = Some("Acme".into());
        cam.last_seen = now_ts();
        cam.open_ports = vec![crate::model::OpenPort { port: 23, proto: "tcp".into(), service: None }];
        cam.ip_history.push(crate::model::IpRecord { ip: std::net::Ipv4Addr::new(10, 0, 0, 7), first_seen: 1, last_seen: 1 });
        store.save_asset(&mut cam).unwrap();
        // a finding about the register (no owner on a critical device) is confirmed by reading the register again
        store.save_meta(cam.id, &crate::model::AssetMeta { criticality: Some("critical".into()), reviewed: true, ..Default::default() }, "t", 1).unwrap();
        let path = "/api/findings/critical_no_owner/verify";
        assert_eq!(send(&app, req("POST", path, Some(&viewer), None)).await.0, StatusCode::FORBIDDEN, "viewers do not start checks");
        let (st, _, v) = send(&app, req("POST", path, Some(&editor), None)).await;
        assert_eq!((st, v["results"][0]["status"].as_str(), v["still_present"].as_i64(), v["rescanned"].as_bool()), (StatusCode::OK, Some("still_present"), Some(1), Some(false)), "{v}");
        store.save_meta(cam.id, &crate::model::AssetMeta { criticality: Some("critical".into()), owner: Some("Ops".into()), reviewed: true, ..Default::default() }, "t", 2).unwrap();
        let (_, _, v) = send(&app, req("POST", path, Some(&editor), None)).await;
        assert_eq!((v["results"].as_array().map(Vec::len), v["fixed"].as_i64()), (Some(0), Some(0)), "nothing is left to check once the finding is gone: {v}");
        let (_, _, v) = send(&app, req("POST", path, Some(&editor), Some(serde_json::json!({"asset_ids": [cam.id]})))).await;
        assert_eq!((v["results"][0]["status"].as_str(), v["fixed"].as_i64()), (Some("fixed"), Some(1)), "{v}");
        // an open port needs a scan; this console cannot scan (no collector), and says so instead of guessing
        let (st, _, v) = send(&app, req("POST", "/api/findings/telnet_open/verify", Some(&editor), None)).await;
        assert_eq!((st, v["results"][0]["status"].as_str(), v["rescanned"].as_bool()), (StatusCode::OK, Some("not_probed"), Some(false)), "{v}");
        assert!(v["results"][0]["detail"].as_str().unwrap().contains("cannot scan"));
        assert_eq!(send(&app, req("POST", "/api/findings/nope/verify", Some(&editor), None)).await.0, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn verify_fix_silently_drops_asset_ids_outside_the_callers_site_access() {
        // regression test: an editor restricted to no access on site-a could still ask
        // /api/findings/{id}/verify to check a site-a device's asset_id directly (that endpoint
        // never looked at site access at all, unlike /api/assets).
        let (app, store, [_viewer, editor, admin]) = secured().await;
        let mut cam = Asset { agent_id: Some("site-a".into()), ..Asset::new(Mac([0x02, 0, 0, 0, 0, 9]), 1) };
        cam.device_type = "camera".into();
        cam.last_seen = now_ts();
        cam.open_ports = vec![crate::model::OpenPort { port: 23, proto: "tcp".into(), service: None }];
        store.save_asset(&mut cam).unwrap();
        store
            .upsert_agent(&crate::model::AgentInfo {
                id: "site-a".into(), name: "Site A".into(), site: None, version: "0.7.0".into(), subnet: "10.0.0.0/24".into(),
                first_seen: 10, last_report_at: 10, last_run_id: String::new(), last_seq: 0,
            })
            .unwrap();
        let eda_id = store.find_user("eda").unwrap().unwrap().user.id;
        send(&app, req("PUT", &format!("/api/users/{eda_id}/site-access"), Some(&admin), Some(serde_json::json!({"grants": [["site-a", "none"]]})))).await;

        let path = "/api/findings/telnet_open/verify";
        let (st, _, v) = send(&app, req("POST", path, Some(&editor), Some(serde_json::json!({"asset_ids": [cam.id]})))).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(v["results"].as_array().map(Vec::len), Some(0), "the site-a device was asked for by id but must not appear: {v}");

        // an admin (or anyone with access to site-a) still gets it
        let (_, _, v) = send(&app, req("POST", path, Some(&admin), Some(serde_json::json!({"asset_ids": [cam.id]})))).await;
        assert_eq!(v["results"].as_array().map(Vec::len), Some(1), "{v}");
    }

    #[tokio::test]
    async fn verify_fix_scans_the_devices_again_and_reports_fixed_still_open_silent_and_never_touches_industrial_ones() {
        use crate::engine::{RescanOutcome, RescanRequest};
        let store: Arc<dyn Store> = Arc::new(SqliteStore::open_in_memory().unwrap());
        let shared = crate::engine::test_shared();
        let (tx, mut rx) = tokio::sync::mpsc::channel::<RescanRequest>(4);
        shared.set_rescanner_for_test(tx);
        // the "collector": .7 still has Telnet open, .8 closed it, .9 does not answer, .10 is excluded
        let asked = Arc::new(std::sync::Mutex::new(Vec::new()));
        let asked2 = asked.clone();
        tokio::spawn(async move {
            while let Some(req) = rx.recv().await {
                asked2.lock().unwrap().extend(req.ips.iter().copied());
                let out = req.ips.iter().map(|ip| (*ip, match ip.octets()[3] {
                    7 => RescanOutcome::Scanned(vec![crate::model::OpenPort { port: 23, proto: "tcp".into(), service: None }], Default::default()),
                    8 => RescanOutcome::Scanned(vec![], Default::default()),
                    10 => RescanOutcome::Excluded,
                    _ => RescanOutcome::Unreachable,
                })).collect();
                let _ = req.reply.send(out);
            }
        });
        let auth = Arc::new(crate::auth::Auth::new(store.clone()));
        let app = router(AppState { store: store.clone(), shared, loopback_only: true, allowed_hosts: vec![], auth, no_auth: true, secure_cookie: false, license: crate::license::load(None, &*store) });
        let mk = |n: u8, ty: &str, vendor: &str| {
            let mut a = Asset::new(Mac([2, 0, 0, 0, 0, n]), 10);
            a.device_type = ty.into();
            a.vendor = Some(vendor.into());
            a.last_seen = now_ts();
            a.open_ports = vec![crate::model::OpenPort { port: 23, proto: "tcp".into(), service: None }];
            a.ip_history.push(crate::model::IpRecord { ip: std::net::Ipv4Addr::new(10, 0, 0, n), first_seen: 1, last_seen: 1 });
            store.save_asset(&mut a).unwrap();
            a
        };
        let (still, gone, silent, excluded) = (mk(7, "camera", "Acme"), mk(8, "camera", "Acme"), mk(9, "camera", "Acme"), mk(10, "camera", "Acme"));
        let plc = mk(11, "plc", "Siemens AG");
        let (st, v) = {
            let (st, _, v) = send(&app, req("POST", "/api/findings/telnet_open/verify", None, None)).await;
            (st, v)
        };
        assert_eq!(st, StatusCode::OK, "{v}");
        let status = |a: &Asset| v["results"].as_array().unwrap().iter().find(|r| r["asset_id"] == a.id).unwrap()["status"].as_str().unwrap().to_string();
        assert_eq!((status(&still), status(&gone), status(&silent), status(&excluded), status(&plc)), ("still_present".into(), "fixed".into(), "unreachable".into(), "excluded".into(), "not_probed".into()), "{v}");
        assert_eq!((v["rescanned"].as_bool(), v["fixed"].as_i64(), v["still_present"].as_i64()), (Some(true), Some(1), Some(1)));
        assert!(!asked.lock().unwrap().contains(&std::net::Ipv4Addr::new(10, 0, 0, 11)), "an industrial device is never sent to the scanner");
        // asking about one device only scans that one
        asked.lock().unwrap().clear();
        let (_, _, v) = send(&app, req("POST", "/api/findings/telnet_open/verify", None, Some(serde_json::json!({"asset_ids": [gone.id]})))).await;
        assert_eq!((v["results"].as_array().unwrap().len(), v["results"][0]["status"].as_str()), (1, Some("fixed")));
        assert_eq!(*asked.lock().unwrap(), vec![std::net::Ipv4Addr::new(10, 0, 0, 8)]);
    }

    // -------------------------------------------------------------- branding

    fn png() -> Vec<u8> {
        [&[0x89u8, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a][..], &[7; 32]].concat()
    }

    fn put_raw(uri: &str, cookie: &str, ctype: &str, body: Vec<u8>) -> axum::http::Request<Body> {
        axum::http::Request::put(uri).header("host", "localhost").header("x-denis", "1").header("content-type", ctype)
            .header("cookie", format!("{SESSION_COOKIE}={cookie}")).body(Body::from(body)).unwrap()
    }

    #[tokio::test]
    async fn branding_is_public_to_read_admin_only_to_change_and_the_logo_is_safe() {
        let (app, _store, [viewer, editor, admin]) = secured().await;
        // readable before sign-in (the login page needs it)
        let (st, _, v) = send(&app, req("GET", "/api/branding", None, None)).await;
        assert_eq!((st, v["product_name"].as_str(), v["logo"].is_null()), (StatusCode::OK, Some("DENIS"), true));
        // only admins change it
        let patch = serde_json::json!({"product_name": "Acme Guard", "accent": "#dc2626", "theme_default": "dark", "login_message": "Authorised use only"});
        for c in [None, Some(&viewer), Some(&editor)] {
            let (st, ..) = send(&app, req("PUT", "/api/branding", c.map(String::as_str), Some(patch.clone()))).await;
            assert!(st == StatusCode::UNAUTHORIZED || st == StatusCode::FORBIDDEN, "{st}");
        }
        assert_eq!(send(&app, req("PUT", "/api/branding", Some(&admin), Some(patch))).await.0, StatusCode::OK);
        let v = send(&app, req("GET", "/api/branding", None, None)).await.2;
        assert_eq!((v["product_name"].as_str(), v["accent"].as_str(), v["accent_text"].as_str(), v["theme_default"].as_str()), (Some("Acme Guard"), Some("#dc2626"), Some("#ffffff"), Some("dark")));
        // invalid values are refused and change nothing
        for bad in [serde_json::json!({"accent": "red;}</style><script>"}), serde_json::json!({"product_name": "<script>"}), serde_json::json!({"theme_default": "x"}), serde_json::json!({"default_language": "xx"})] {
            let (st, ..) = send(&app, req("PUT", "/api/branding", Some(&admin), Some(bad.clone()))).await;
            // a name with markup is *stored as text* (the UI never renders HTML), so only the other two are refused
            if bad.get("product_name").is_none() {
                assert_eq!(st, StatusCode::BAD_REQUEST, "{bad}");
            }
        }
        assert_eq!(send(&app, req("GET", "/api/branding", None, None)).await.2["accent"], "#dc2626");
        // the default language is one of the translated ones, English until an administrator says otherwise
        assert_eq!(send(&app, req("GET", "/api/branding", None, None)).await.2["default_language"], "en");
        assert_eq!(send(&app, req("PUT", "/api/branding", Some(&admin), Some(serde_json::json!({"default_language": "sk"})))).await.0, StatusCode::OK);
        assert_eq!(send(&app, req("GET", "/api/branding", None, None)).await.2["default_language"], "sk");

        // logo: real images only, admin only, size-limited; served locked-down
        assert_eq!(send(&app, put_raw("/api/branding/logo", &editor, "image/png", png())).await.0, StatusCode::FORBIDDEN);
        for (body, why) in [(b"<svg onload=alert(1)/>".to_vec(), "svg"), (b"GIF89".to_vec(), "truncated"), (vec![], "empty")] {
            assert_eq!(send(&app, put_raw("/api/branding/logo", &admin, "image/png", body)).await.0, StatusCode::BAD_REQUEST, "{why}");
        }
        // the client-declared type is irrelevant: an SVG labelled image/png is still refused
        assert_eq!(send(&app, put_raw("/api/branding/logo", &admin, "image/png", b"<svg/>".to_vec())).await.0, StatusCode::BAD_REQUEST);
        assert_eq!(send(&app, put_raw("/api/branding/logo", &admin, "image/png", [png(), vec![0u8; 300_000]].concat())).await.0, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(send(&app, put_raw("/api/branding/logo", &admin, "text/html", png())).await.0, StatusCode::NO_CONTENT);
        let v = send(&app, req("GET", "/api/branding", None, None)).await.2;
        assert!(v["logo"].as_str().unwrap().starts_with("/branding/logo?v="));
        let resp = app.clone().oneshot(req("GET", "/branding/logo", None, None)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers()[header::CONTENT_TYPE], "image/png");
        assert_eq!(resp.headers()[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
        assert!(resp.headers()[header::CONTENT_SECURITY_POLICY].to_str().unwrap().contains("sandbox"));
        assert_eq!(axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap().to_vec(), png());
        // remove it
        assert_eq!(send(&app, req("DELETE", "/api/branding/logo", Some(&admin), None)).await.0, StatusCode::NO_CONTENT);
        assert_eq!(send(&app, req("GET", "/branding/logo", None, None)).await.0, StatusCode::NOT_FOUND);
        assert!(send(&app, req("GET", "/api/branding", None, None)).await.2["logo"].is_null());
    }
}
