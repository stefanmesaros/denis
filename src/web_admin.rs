//! Handlers for everything that changes state or manages access: login and
//! sessions, users, agent tokens, asset editing/creation/import, audit trail.
//!
//! Authorisation is decided in `web::authn` (by method and path) *before* these
//! run; the handlers only need to know *who* is acting, for the audit trail.

use std::sync::Arc;

use axum::extract::{Extension, Path, Query, Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::auth::{self, AuthError};
use crate::branding;
use crate::model::{now_ts, Asset, AssetMeta, RiskAcceptance};
use crate::tracking;
use crate::web::{asset_view, blocking, site_writable, ApiError, AppState, AuthUser, SESSION_COOKIE};

pub(crate) fn err(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(json!({ "error": msg.into() }))).into_response()
}

/// Best-effort audit entry: a failure to log must not fail the action itself
/// (but is logged loudly).
pub(crate) fn audit(st: &AppState, user: &str, action: &str, asset_id: Option<i64>, detail: Value) {
    if let Err(e) = st.store.add_audit(now_ts(), user, action, asset_id, &detail) {
        tracing::error!("audit write failed for {action}: {e:#}");
    }
}

fn map_auth_err(e: AuthError) -> Response {
    match e {
        AuthError::Invalid => err(StatusCode::UNAUTHORIZED, "invalid username or password"),
        AuthError::Locked(secs) => {
            let mut r = err(StatusCode::TOO_MANY_REQUESTS, format!("too many attempts; try again in {secs} seconds"));
            if let Ok(v) = HeaderValue::from_str(&secs.to_string()) {
                r.headers_mut().insert(header::RETRY_AFTER, v);
            }
            r
        }
        AuthError::Rejected(m) => err(StatusCode::BAD_REQUEST, m),
        AuthError::MfaRequired(_) => err(StatusCode::UNAUTHORIZED, "a one-time code is required"),
        AuthError::Internal(e) => {
            tracing::error!("auth error: {e:#}");
            err(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
        }
    }
}

/// `Set-Cookie` value. HttpOnly (no script access), SameSite=Strict (no
/// cross-site sends), and `Secure` when running behind TLS.
pub(crate) fn cookie(token: &str, secure: bool, max_age: Option<i64>) -> HeaderValue {
    let mut c = format!("{SESSION_COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/");
    if let Some(m) = max_age {
        c.push_str(&format!("; Max-Age={m}"));
    }
    if secure {
        c.push_str("; Secure");
    }
    HeaderValue::from_str(&c).expect("cookie is ASCII")
}

// ------------------------------------------------------------------ session

#[derive(Deserialize)]
pub struct LoginReq {
    username: String,
    password: String,
}

/// The address a request really came from. A reverse proxy on this same machine
/// (the peer is loopback) puts the real client last in `X-Forwarded-For`; from any
/// other peer that header is client-controlled and therefore ignored.
pub(crate) fn client_ip(peer: Option<std::net::SocketAddr>, headers: &axum::http::HeaderMap) -> std::net::IpAddr {
    let peer_ip = peer.map_or(std::net::IpAddr::from([0, 0, 0, 0]), |p| p.ip());
    if peer_ip.is_loopback() {
        if let Some(ip) = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.rsplit(',').next())
            .and_then(|v| v.trim().parse().ok())
        {
            return ip;
        }
    }
    peer_ip
}

pub(crate) async fn login(
    State(st): State<AppState>,
    peer: Option<Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<LoginReq>,
) -> Response {
    let ip = client_ip(peer.map(|Extension(c)| c.0), &headers);
    let wait = st.auth.ip_wait(ip, now_ts());
    if wait > 0 {
        audit(&st, "-", "auth.login_throttled", None, json!({ "ip": ip.to_string() }));
        return map_auth_err(AuthError::Locked(wait));
    }
    // Bound the input before spending an Argon2 verification on it.
    if body.username.len() > 64 || body.password.len() > 256 {
        st.auth.ip_failure(ip, now_ts());
        return map_auth_err(AuthError::Invalid);
    }
    let auth = st.auth.clone();
    let (u, p) = (body.username.clone(), body.password);
    let res = tokio::task::spawn_blocking(move || auth.login(&u, &p, now_ts())).await;
    let res = match res {
        Ok(r) => r,
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    };
    match res {
        Ok((token, user)) => {
            audit(&st, &user.username, "auth.login", None, json!({}));
            let mut r = Json(json!({ "user": user, "must_change": user.must_change })).into_response();
            r.headers_mut().insert(header::SET_COOKIE, cookie(&token, st.secure_cookie, None));
            r
        }
        Err(AuthError::MfaRequired(ticket)) => {
            // the password was right; the session comes with the code (POST /api/auth/mfa)
            Json(json!({ "mfa_required": true, "ticket": ticket })).into_response()
        }
        Err(e) => {
            // The attempted name is logged as typed (trimmed, bounded): useful
            // for spotting guessing without revealing whether it exists.
            let name: String = body.username.trim().chars().take(64).collect();
            if matches!(e, AuthError::Invalid) {
                st.auth.ip_failure(ip, now_ts());
            }
            audit(&st, &name, "auth.login_failed", None, json!({ "locked": matches!(e, AuthError::Locked(_)), "ip": ip.to_string() }));
            map_auth_err(e)
        }
    }
}

fn token_from(req_headers: &axum::http::HeaderMap) -> Option<String> {
    req_headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .filter_map(|p| p.trim().split_once('='))
        .find(|(k, _)| *k == SESSION_COOKIE)
        .map(|(_, v)| v.to_string())
}

pub(crate) fn session_token(headers: &axum::http::HeaderMap) -> Option<String> {
    token_from(headers)
}

pub(crate) async fn logout(State(st): State<AppState>, Extension(AuthUser(user)): Extension<AuthUser>, req: Request) -> Response {
    if let Some(t) = token_from(req.headers()) {
        st.auth.logout(&t);
    }
    audit(&st, &user.username, "auth.logout", None, json!({}));
    let mut r = StatusCode::NO_CONTENT.into_response();
    r.headers_mut().insert(header::SET_COOKIE, cookie("", st.secure_cookie, Some(0)));
    r
}

pub(crate) async fn me(State(st): State<AppState>, Extension(AuthUser(user)): Extension<AuthUser>) -> Json<Value> {
    // a person who must set up a second step before anything else works (an API token or a no-login console never must)
    let must_enrol = user.id > 0 && !st.no_auth && st.auth.must_enrol(&user, now_ts());
    Json(json!({ "user": user, "must_change": user.must_change, "must_enrol": must_enrol }))
}

#[derive(Deserialize)]
pub struct PasswordReq {
    current: String,
    new: String,
}

pub(crate) async fn change_password(
    State(st): State<AppState>,
    Extension(AuthUser(user)): Extension<AuthUser>,
    req_headers: axum::http::HeaderMap,
    Json(body): Json<PasswordReq>,
) -> Response {
    if body.current.len() > 256 || body.new.len() > 256 {
        return err(StatusCode::BAD_REQUEST, "password too long");
    }
    let keep = token_from(&req_headers);
    let auth = st.auth.clone();
    let id = user.id;
    let res = tokio::task::spawn_blocking(move || auth.change_password(id, &body.current, &body.new, keep.as_deref())).await;
    match res {
        Ok(Ok(())) => {
            audit(&st, &user.username, "auth.password_changed", None, json!({}));
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(Err(e)) => {
            audit(&st, &user.username, "auth.password_change_failed", None, json!({}));
            map_auth_err(e)
        }
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    }
}

// -------------------------------------------------------------------- users

/// The users with how each signs in: passkeys and whether an authenticator app is on (never any secret).
pub(crate) async fn users_list(State(st): State<AppState>) -> Result<Json<Vec<Value>>, ApiError> {
    let rows = blocking(&st.store, |s| {
        let totp = s.totp_enabled_users()?;
        let mut out = Vec::new();
        for u in s.list_users()? {
            let passkeys = s.list_passkeys(u.id)?.len();
            let mut v = serde_json::to_value(&u)?;
            v["passkeys"] = passkeys.into();
            v["totp"] = totp.contains(&u.id).into();
            out.push(v);
        }
        Ok(out)
    })
    .await?;
    Ok(Json(rows))
}

#[derive(Deserialize)]
pub struct NewUser {
    username: String,
    role: String,
}

/// The one-time password is returned once and never stored in clear.
pub(crate) async fn users_create(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Json(b): Json<NewUser>) -> Response {
    let auth = st.auth.clone();
    let (name, role) = (b.username.trim().to_string(), b.role);
    let res = tokio::task::spawn_blocking(move || auth.create_user(&name, &role, now_ts())).await;
    match res {
        Ok(Ok((user, password))) => {
            audit(&st, &me.username, "user.create", None, json!({ "user": user.username, "role": user.role }));
            (StatusCode::CREATED, Json(json!({ "user": user, "temporary_password": password }))).into_response()
        }
        Ok(Err(e)) => map_auth_err(e),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    }
}

#[derive(Deserialize)]
pub struct UserPatch {
    role: Option<String>,
    disabled: Option<bool>,
}

pub(crate) async fn users_update(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Path(id): Path<i64>, Json(b): Json<UserPatch>) -> Response {
    let res = st.auth.update_user(id, b.role.as_deref(), b.disabled);
    match res {
        Ok(()) => {
            audit(&st, &me.username, "user.update", None, json!({ "user_id": id, "role": b.role, "disabled": b.disabled }));
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => map_auth_err(e),
    }
}

/// Permanently remove a user — only once they are already disabled (see `Auth::delete_user`).
pub(crate) async fn users_delete(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    let auth = st.auth.clone();
    match tokio::task::spawn_blocking(move || auth.delete_user(id)).await {
        Ok(Ok(())) => {
            audit(&st, &me.username, "user.delete", None, json!({ "user_id": id }));
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(Err(e)) => map_auth_err(e),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    }
}

pub(crate) async fn users_reset(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Path(id): Path<i64>) -> Response {
    let auth = st.auth.clone();
    match tokio::task::spawn_blocking(move || auth.reset_password(id)).await {
        Ok(Ok(pw)) => {
            audit(&st, &me.username, "user.reset_password", None, json!({ "user_id": id }));
            Json(json!({ "temporary_password": pw })).into_response()
        }
        Ok(Err(e)) => map_auth_err(e),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    }
}

// -------------------------------------------------------------------- per-site access

/// This user's site grants, plus every known site (local + every agent that ever reported) so
/// the console can offer one row per site even where nothing has been set yet.
pub(crate) async fn site_access_get(State(st): State<AppState>, Path(id): Path<i64>) -> Result<Json<Value>, ApiError> {
    let (grants, agents) = blocking(&st.store, move |s| {
        let all = crate::access::load_all(s);
        Ok((all.into_iter().filter(|g| g.user_id == id).collect::<Vec<_>>(), s.list_agents()?))
    })
    .await?;
    let mut sites = vec![json!({ "site": crate::access::LOCAL_SITE, "name": "local" })];
    sites.extend(agents.iter().map(|a| json!({ "site": a.id, "name": a.name })));
    Ok(Json(json!({ "sites": sites, "grants": grants })))
}

#[derive(Deserialize)]
pub struct SiteAccessPut {
    /// `(site, permission)` pairs; replaces this user's whole set. An empty list means "no
    /// restriction on any site" (full access everywhere, the default before this is ever used).
    grants: Vec<(String, String)>,
}

pub(crate) async fn site_access_put(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Path(id): Path<i64>, Json(b): Json<SiteAccessPut>) -> Result<Response, ApiError> {
    if b.grants.len() > 500 {
        return Ok(err(StatusCode::BAD_REQUEST, "too many grants"));
    }
    if st.store.get_user_record(id)?.is_none() {
        return Ok(err(StatusCode::NOT_FOUND, "no such user"));
    }
    let now = now_ts();
    let store = st.store.clone();
    let grants = b.grants.clone();
    let res = tokio::task::spawn_blocking(move || crate::access::set_for_user(&*store, id, &grants, now)).await.map_err(|e| anyhow::anyhow!(e))?;
    match res {
        Ok(()) => {
            audit(&st, &me.username, "user.site_access", None, json!({ "user_id": id, "grants": b.grants }));
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        Err(e) => Ok(err(StatusCode::BAD_REQUEST, e)),
    }
}

// -------------------------------------------------------------------- MSP overview toggle

/// Off by default: most installs are one site and never need a second menu item for it.
pub(crate) const MSP_OVERVIEW_KEY: &str = "msp_overview_enabled";

#[derive(Deserialize)]
pub struct MspOverviewReq {
    enabled: bool,
}

/// Show or hide the "Overview" tab (a row per site, for anyone managing more than a couple —
/// an MSP with several customers, or one business with several branches). Reading whether it is
/// on is part of `/api/status` (polled already); this only changes it, admin-only.
pub(crate) async fn msp_overview_put(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Json(b): Json<MspOverviewReq>) -> Result<Response, ApiError> {
    let now = now_ts();
    let v: &[u8] = if b.enabled { b"1" } else { b"0" };
    st.store.set_setting(MSP_OVERVIEW_KEY, v, now)?;
    audit(&st, &me.username, "msp_overview.set", None, json!({ "enabled": b.enabled }));
    Ok(StatusCode::NO_CONTENT.into_response())
}

// -------------------------------------------------------------------- license

fn license_json(eff: &crate::license::Effective) -> Value {
    let (stage, days_left) = match crate::license::stage(eff, now_ts()) {
        crate::license::Stage::Fine => ("fine", None),
        crate::license::Stage::ExpiringSoon { days_left } => ("expiring_soon", Some(days_left)),
        crate::license::Stage::Grace { days_left } => ("grace", Some(days_left)),
        crate::license::Stage::Expired => ("expired", None),
    };
    json!({
        "tier": eff.license.as_ref().map(|l| &l.tier),
        "customer": eff.license.as_ref().map(|l| &l.customer),
        "device_cap": eff.device_cap,
        "commercial": eff.commercial,
        "problem": eff.problem,
        "activated_at": eff.activated_at,
        "expires_at": eff.expires_at,
        "valid_days": eff.license.as_ref().map(|l| l.valid_days),
        "installed": eff.license.is_some(),
        "stage": stage,
        "days_left": days_left,
    })
}

/// The license in force right now (see `web::effective_license`): a GUI-pasted one always wins
/// over `--license-file`. Anyone signed in may see it (it says which edition they are on).
pub(crate) async fn license_get(State(st): State<AppState>) -> Result<Json<Value>, ApiError> {
    Ok(Json(license_json(&crate::web::effective_license(&st))))
}

/// Paste a license file's two lines into the console instead of using `--license-file`. Verified
/// before it is stored; a bad one is refused with why, and nothing changes.
pub(crate) async fn license_put(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, body: String) -> Result<Response, ApiError> {
    let text = body.trim();
    if text.is_empty() || text.len() > 4096 {
        return Ok(err(StatusCode::BAD_REQUEST, "paste the license file's contents (two lines)"));
    }
    let eff = crate::license::load_from_text(text, &*st.store);
    let Some(license) = &eff.license else {
        return Ok(err(StatusCode::BAD_REQUEST, eff.problem.unwrap_or_else(|| "could not verify this license".into())));
    };
    let customer = license.customer.clone();
    st.store.set_setting(crate::license::SETTING_KEY, format!("{text}\n").as_bytes(), now_ts())?;
    audit(&st, &me.username, "license.install", None, json!({ "customer": customer, "problem": eff.problem }));
    Ok(Json(license_json(&eff)).into_response())
}

/// Remove a pasted license: falls back to `--license-file` if one was given at start-up, else
/// the Community edition. Does not touch a license given via `--license-file` (there is nothing
/// stored to remove in that case).
pub(crate) async fn license_delete(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>) -> Result<Response, ApiError> {
    st.store.delete_setting(crate::license::SETTING_KEY)?;
    audit(&st, &me.username, "license.remove", None, json!({}));
    Ok(Json(license_json(&crate::web::effective_license(&st))).into_response())
}

// -------------------------------------------------------------------- capture interfaces

/// Candidates for `--iface` (need an IPv4 address) and for `--mirror-iface`
/// (any up interface: a mirror/SPAN port usually has none), plus the
/// GUI-configured choice (if any) and what is actually running right now.
/// Changing this needs a restart, since capture is opened once at start-up —
/// the console says so; this only lets you queue the change.
pub(crate) async fn interfaces_get(State(st): State<AppState>) -> Result<Json<Value>, ApiError> {
    let (mains, all) = tokio::task::spawn_blocking(|| {
        let mains: Vec<Value> = crate::net::list_interfaces().unwrap_or_default().iter().map(|i| json!({ "name": i.name, "ip": i.ip.to_string() })).collect();
        let all: Vec<String> = crate::net::list_all_up().unwrap_or_default();
        (mains, all)
    })
    .await
    .map_err(|e| anyhow::anyhow!(e))?;
    let configured = crate::capture_config::load(&*st.store);
    let running = st.shared.snapshot();
    Ok(Json(json!({
        "mains": mains,
        "all": all,
        "configured_iface": configured.iface,
        "configured_mirror_ifaces": configured.mirror_ifaces,
        "running_iface": running.interface,
        "running_mirror_ifaces": running.mirror_interfaces,
    })))
}

#[derive(Deserialize)]
pub struct InterfacesPut {
    /// `None`/omitted clears the override (falls back to `--iface`/auto-detect).
    #[serde(default)]
    iface: Option<String>,
    /// `None`/omitted clears the override (falls back to `--mirror-iface`); `Some(vec![])` is a
    /// deliberate override to "no mirror interfaces".
    #[serde(default)]
    mirror_ifaces: Option<Vec<String>>,
}

pub(crate) async fn interfaces_put(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Json(b): Json<InterfacesPut>) -> Result<Response, ApiError> {
    if b.iface.as_deref() == Some("") {
        return Ok(err(StatusCode::BAD_REQUEST, "pass null, not an empty string, to clear the discovery interface"));
    }
    if let Some(mirrors) = &b.mirror_ifaces {
        if mirrors.iter().any(|m| m.is_empty()) {
            return Ok(err(StatusCode::BAD_REQUEST, "a mirror interface name cannot be empty"));
        }
        if let Some(iface) = &b.iface {
            if mirrors.contains(iface) {
                return Ok(err(StatusCode::BAD_REQUEST, "the discovery and mirror interfaces must be different"));
            }
        }
        if mirrors.len() > 16 {
            return Ok(err(StatusCode::BAD_REQUEST, "too many mirror interfaces"));
        }
    }
    let now = now_ts();
    let store = st.store.clone();
    let (iface, mirrors) = (b.iface.clone(), b.mirror_ifaces.clone());
    tokio::task::spawn_blocking(move || crate::capture_config::save(&*store, iface.as_deref(), mirrors.as_deref(), now))
        .await
        .map_err(|e| anyhow::anyhow!(e))??;
    audit(&st, &me.username, "interfaces.set", None, json!({ "iface": b.iface, "mirror_ifaces": b.mirror_ifaces }));
    Ok(StatusCode::NO_CONTENT.into_response())
}

// -------------------------------------------------------------------- TLS

/// The certificate the console is served with.
pub(crate) async fn tls_get(State(st): State<AppState>) -> Result<Json<Value>, ApiError> {
    let Some(h) = st.shared.tls() else {
        return Ok(Json(json!({ "enabled": false })));
    };
    let Some(dir) = h.dir.clone() else {
        return Ok(Json(json!({ "enabled": true, "managed": false, "source": "files" })));
    };
    let d2 = dir.clone();
    let info = tokio::task::spawn_blocking(move || crate::certs::info(&d2)).await.ok().and_then(|r| r.ok());
    Ok(Json(json!({ "enabled": true, "managed": true, "info": info, "has_ca": crate::certs::ca_pem(&dir).is_some() })))
}

/// The local authority's certificate (public information): install it in a browser or give it to
/// agents (`--master-ca`) to make the generated certificate trusted.
pub(crate) async fn tls_ca(State(st): State<AppState>) -> Response {
    let pem = st.shared.tls().and_then(|h| h.dir.clone()).and_then(|d| crate::certs::ca_pem(&d));
    match pem {
        Some(p) => ([(header::CONTENT_TYPE, "application/x-pem-file".to_string()), (header::CONTENT_DISPOSITION, "attachment; filename=\"denis-local-ca.pem\"".to_string())], p).into_response(),
        None => (StatusCode::NOT_FOUND, "no local certificate authority").into_response(),
    }
}

#[derive(Deserialize)]
pub struct CertUpload {
    certificate: String,
    key: String,
}

/// Replace the console's certificate with your own. Takes effect at once.
pub(crate) async fn tls_upload(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Json(b): Json<CertUpload>) -> Result<Response, ApiError> {
    let Some(h) = st.shared.tls() else { return Ok(err(StatusCode::BAD_REQUEST, "the console is not served over TLS (--no-tls)")) };
    let Some(dir) = h.dir.clone() else { return Ok(err(StatusCode::CONFLICT, "the certificate is managed with --tls-cert/--tls-key: replace those files instead")) };
    let d2 = dir.clone();
    let res = tokio::task::spawn_blocking(move || crate::certs::install_custom(&d2, &b.certificate, &b.key, now_ts())).await;
    let info = match res {
        Ok(Ok(i)) => i,
        Ok(Err(e)) => return Ok(err(StatusCode::BAD_REQUEST, format!("{e:#}"))),
        Err(_) => return Ok(err(StatusCode::INTERNAL_SERVER_ERROR, "internal error")),
    };
    if let Err(e) = h.config.reload_from_pem_file(dir.join(crate::certs::SERVER_CERT), dir.join(crate::certs::SERVER_KEY)).await {
        return Ok(err(StatusCode::INTERNAL_SERVER_ERROR, format!("the certificate was stored but could not be loaded: {e}")));
    }
    audit(&st, &me.username, "tls.replace", None, json!({ "fingerprint": info.fingerprint, "subject": info.subject }));
    Ok(Json(info).into_response())
}

/// Go back to the certificate DENIS generates.
pub(crate) async fn tls_reset(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>) -> Result<Response, ApiError> {
    let Some(h) = st.shared.tls() else { return Ok(err(StatusCode::BAD_REQUEST, "the console is not served over TLS (--no-tls)")) };
    let Some(dir) = h.dir.clone() else { return Ok(err(StatusCode::CONFLICT, "the certificate is managed with --tls-cert/--tls-key")) };
    let (d2, names) = (dir.clone(), h.names.clone());
    let info = match tokio::task::spawn_blocking(move || crate::certs::reset_to_generated(&d2, &names, now_ts())).await {
        Ok(Ok(i)) => i,
        Ok(Err(e)) => return Ok(err(StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}"))),
        Err(_) => return Ok(err(StatusCode::INTERNAL_SERVER_ERROR, "internal error")),
    };
    if let Err(e) = h.config.reload_from_pem_file(dir.join(crate::certs::SERVER_CERT), dir.join(crate::certs::SERVER_KEY)).await {
        return Ok(err(StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")));
    }
    audit(&st, &me.username, "tls.reset", None, json!({ "fingerprint": info.fingerprint }));
    Ok(Json(info).into_response())
}

// ------------------------------------------------------------------ updates

/// What the console needs to show about updates (also when this process has no updater).
pub(crate) async fn update_get(State(st): State<AppState>) -> Json<Value> {
    Json(match st.shared.updater() {
        Some(u) => u.snapshot(now_ts()),
        None => json!({ "configured": false, "checking_enabled": false, "available": false, "notify": false, "current": crate::update::current_version().text() }),
    })
}

fn updater(st: &AppState) -> Result<Arc<crate::update::Updater>, Box<Response>> {
    st.shared.updater().ok_or_else(|| Box::new(err(StatusCode::BAD_REQUEST, "updates are not available in this mode")))
}

/// Look for a new release right now.
pub(crate) async fn update_check(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>) -> Result<Response, ApiError> {
    let u = match updater(&st) { Ok(u) => u, Err(r) => return Ok(*r) };
    let u2 = u.clone();
    let r = tokio::task::spawn_blocking(move || u2.check(now_ts())).await;
    audit(&st, &me.username, "update.check", None, json!({}));
    Ok(match r {
        Ok(Ok(_)) => Json(u.snapshot(now_ts())).into_response(),
        Ok(Err(e)) => err(StatusCode::BAD_GATEWAY, format!("{e:#}")),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    })
}

#[derive(Deserialize)]
pub struct InstallReq {
    /// Unix time to install at; absent or null = now.
    #[serde(default)]
    when: Option<i64>,
}

/// Install the new version now, or at a chosen time. A verified database backup is made first.
pub(crate) async fn update_install(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Json(b): Json<InstallReq>) -> Result<Response, ApiError> {
    let u = match updater(&st) { Ok(u) => u, Err(r) => return Ok(*r) };
    let snap = u.snapshot(now_ts());
    if snap["file_capabilities"] == true {
        return Ok(err(StatusCode::CONFLICT, "this program gets its packet-capture permission from setcap, which an updated file would lose: run it under systemd with AmbientCapabilities, or update by hand and run setcap again"));
    }
    if snap["can_install"] != true {
        return Ok(err(StatusCode::CONFLICT, "this installation cannot update itself (no release key in this build, or the program folder is not writable): update by hand"));
    }
    let now = now_ts();
    let res = match b.when.filter(|t| *t > now + 30) {
        Some(t) => u.schedule(Some(t), now).map(|_| "scheduled"),
        None => u.install_in_background().map(|_| "started"),
    };
    Ok(match res {
        Ok(what) => {
            audit(&st, &me.username, "update.install", None, json!({ "what": what, "when": b.when, "version": snap["latest"]["version"] }));
            (StatusCode::ACCEPTED, Json(json!({ "status": what }))).into_response()
        }
        Err(e) => err(StatusCode::BAD_REQUEST, format!("{e:#}")),
    })
}

#[derive(Deserialize)]
pub struct SnoozeReq {
    days: i64,
}

pub(crate) async fn update_snooze(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Json(b): Json<SnoozeReq>) -> Result<Response, ApiError> {
    let u = match updater(&st) { Ok(u) => u, Err(r) => return Ok(*r) };
    let res = blocking(&st.store, move |_| Ok(u.snooze(b.days, now_ts()).map_err(|e| e.to_string()))).await?;
    Ok(match res {
        Ok(()) => { audit(&st, &me.username, "update.snooze", None, json!({ "days": b.days })); StatusCode::NO_CONTENT.into_response() }
        Err(e) => err(StatusCode::BAD_REQUEST, e),
    })
}

pub(crate) async fn update_skip(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>) -> Result<Response, ApiError> {
    let u = match updater(&st) { Ok(u) => u, Err(r) => return Ok(*r) };
    let res = blocking(&st.store, move |_| Ok(u.skip(now_ts()).map_err(|e| e.to_string()))).await?;
    Ok(match res {
        Ok(()) => { audit(&st, &me.username, "update.skip", None, json!({})); StatusCode::NO_CONTENT.into_response() }
        Err(e) => err(StatusCode::BAD_REQUEST, e),
    })
}

pub(crate) async fn update_unschedule(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>) -> Result<Response, ApiError> {
    let u = match updater(&st) { Ok(u) => u, Err(r) => return Ok(*r) };
    let res = blocking(&st.store, move |_| Ok(u.schedule(None, now_ts()).map_err(|e| e.to_string()))).await?;
    Ok(match res {
        Ok(()) => { audit(&st, &me.username, "update.unschedule", None, json!({})); StatusCode::NO_CONTENT.into_response() }
        Err(e) => err(StatusCode::BAD_REQUEST, e),
    })
}

// ------------------------------------------------------- demo data and reset

pub(crate) async fn demo_get(State(st): State<AppState>) -> Result<Json<Value>, ApiError> {
    Ok(Json(json!({ "loaded": blocking(&st.store, |s| crate::demo::is_loaded(s)).await? })))
}

/// Fill the console with the fictional demo company.
pub(crate) async fn demo_load(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>) -> Result<Response, ApiError> {
    let r = blocking(&st.store, |s| Ok(crate::demo::load(s, now_ts()).map_err(|e| e.to_string()))).await?;
    Ok(match r {
        Ok(l) => {
            audit(&st, &me.username, "demo.load", None, json!({ "assets": l.assets, "events": l.events }));
            (StatusCode::CREATED, Json(l)).into_response()
        }
        Err(e) => err(StatusCode::CONFLICT, e),
    })
}

/// Remove the demo data (and only that).
pub(crate) async fn demo_remove(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>) -> Result<Response, ApiError> {
    let n = blocking(&st.store, |s| crate::demo::remove(s)).await?;
    audit(&st, &me.username, "demo.remove", None, json!({ "assets": n }));
    Ok(Json(json!({ "removed": n })).into_response())
}

/// The exact words that must be typed to erase everything.
pub const ERASE_PHRASE: &str = "ERASE ALL DATA";

#[derive(Deserialize)]
pub struct EraseReq {
    confirm: String,
}

/// Erase every device, edit, alert, baseline, communication record and trend sample, and start
/// learning again from scratch. Users, sign-in methods, channels, branding, rule settings, API
/// and agent tokens and the audit log are kept. This cannot be undone: take a backup first.
pub(crate) async fn data_erase(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Json(b): Json<EraseReq>) -> Result<Response, ApiError> {
    if b.confirm != ERASE_PHRASE {
        return Ok(err(StatusCode::BAD_REQUEST, format!("type {ERASE_PHRASE} to confirm")));
    }
    let done = match st.shared.erase_via_engine().await {
        Some(r) => r,
        None => blocking(&st.store, |s| Ok(s.erase_inventory().map_err(|e| e.to_string()))).await?,
    };
    if let Err(e) = done {
        return Ok(err(StatusCode::INTERNAL_SERVER_ERROR, e));
    }
    audit(&st, &me.username, "data.erase", None, json!({}));
    Ok(Json(json!({ "erased": true })).into_response())
}

// ------------------------------------------------------ notification channels

fn maintenance_json(m: &crate::channels::Maintenance, now: i64) -> Value {
    json!({ "active": m.active(now), "until": if m.active(now) { Some(m.until) } else { None }, "note": if m.active(now) { m.note.as_str() } else { "" } })
}

/// Channels (secrets masked) with their delivery health.
pub(crate) async fn channels_list(State(st): State<AppState>) -> Result<Json<Value>, ApiError> {
    let list = blocking(&st.store, |s| crate::channels::load(s)).await?;
    let status = st.shared.channel_status.lock().unwrap().clone();
    let out: Vec<Value> = list
        .iter()
        .map(|c| {
            let mut v = c.masked();
            v["status"] = json!(status.get(&c.id));
            v
        })
        .collect();
    Ok(Json(json!(out)))
}

pub(crate) async fn channels_create(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Json(body): Json<Value>) -> Result<Response, ApiError> {
    let res = blocking(&st.store, move |s| {
        let mut list = crate::channels::load(s)?;
        let made = crate::channels::from_body(&body, None).and_then(|c| crate::channels::add(&mut list, c));
        if made.is_ok() {
            crate::channels::save(s, &list, now_ts())?;
        }
        Ok(made)
    })
    .await?;
    Ok(match res {
        Err(e) => err(StatusCode::BAD_REQUEST, e),
        Ok(c) => {
            audit(&st, &me.username, "channel.create", None, json!({ "id": c.id, "name": c.name, "kind": c.kind }));
            (StatusCode::CREATED, Json(c.masked())).into_response()
        }
    })
}

pub(crate) async fn channels_update(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Path(id): Path<String>, Json(body): Json<Value>) -> Result<Response, ApiError> {
    let id2 = id.clone();
    let res = blocking(&st.store, move |s| {
        let mut list = crate::channels::load(s)?;
        let Some(i) = list.iter().position(|c| c.id == id2) else { return Ok(Err((StatusCode::NOT_FOUND, "no such channel".to_string()))) };
        Ok(match crate::channels::from_body(&body, Some(&list[i])) {
            Err(e) => Err((StatusCode::BAD_REQUEST, e)),
            Ok(mut c) => {
                c.id = id2;
                list[i] = c.clone();
                crate::channels::save(s, &list, now_ts())?;
                Ok(c)
            }
        })
    })
    .await?;
    Ok(match res {
        Err((code, e)) => err(code, e),
        Ok(c) => {
            audit(&st, &me.username, "channel.update", None, json!({ "id": c.id, "name": c.name, "enabled": c.enabled, "min_score": c.min_score }));
            Json(c.masked()).into_response()
        }
    })
}

pub(crate) async fn channels_delete(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Path(id): Path<String>) -> Result<Response, ApiError> {
    let id2 = id.clone();
    let found = blocking(&st.store, move |s| {
        let mut list = crate::channels::load(s)?;
        let before = list.len();
        list.retain(|c| c.id != id2);
        if list.len() == before {
            return Ok(false);
        }
        crate::channels::save(s, &list, now_ts())?;
        s.delete_setting(&format!("channel.{id2}.cursor"))?;
        Ok(true)
    })
    .await?;
    if !found {
        return Ok(err(StatusCode::NOT_FOUND, "no such channel"));
    }
    st.shared.channel_status.lock().unwrap().remove(&id);
    audit(&st, &me.username, "channel.delete", None, json!({ "id": id }));
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Send a test message through one channel right now and report what happened.
pub(crate) async fn channels_test(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Path(id): Path<String>) -> Result<Response, ApiError> {
    let id2 = id.clone();
    let ch = blocking(&st.store, move |s| Ok(crate::channels::load(s)?.into_iter().find(|c| c.id == id2))).await?;
    let Some(ch) = ch else { return Ok(err(StatusCode::NOT_FOUND, "no such channel")) };
    let host = crate::net::local_hostname().unwrap_or_default();
    let sent = tokio::task::spawn_blocking(move || crate::channels::send(&ch, &crate::channels::Notification::test(), &host, now_ts())).await;
    audit(&st, &me.username, "channel.test", None, json!({ "id": id, "ok": matches!(sent, Ok(Ok(()))) }));
    Ok(match sent {
        Ok(Ok(())) => Json(json!({ "ok": true })).into_response(),
        Ok(Err(e)) => err(StatusCode::BAD_GATEWAY, format!("{e:#}")),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    })
}

pub(crate) async fn maintenance_get(State(st): State<AppState>) -> Result<Json<Value>, ApiError> {
    let m = blocking(&st.store, |s| crate::channels::load_maintenance(s)).await?;
    Ok(Json(maintenance_json(&m, now_ts())))
}

#[derive(Deserialize)]
pub struct MaintenanceReq {
    /// Minutes from now (1 to 30 days), or null/0 to end maintenance mode.
    minutes: Option<i64>,
    #[serde(default)]
    note: String,
}

/// Silence all outgoing notifications for a while (planned work), or end that.
pub(crate) async fn maintenance_put(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Json(b): Json<MaintenanceReq>) -> Result<Response, ApiError> {
    let now = now_ts();
    let minutes = b.minutes.unwrap_or(0);
    if !(0..=30 * 24 * 60).contains(&minutes) || b.note.chars().count() > 200 || b.note.chars().any(char::is_control) {
        return Ok(err(StatusCode::BAD_REQUEST, "minutes must be between 0 and 43200 and the note at most 200 characters"));
    }
    let m = crate::channels::Maintenance { until: if minutes == 0 { 0 } else { now + minutes * 60 }, note: b.note.trim().to_string() };
    let m2 = m.clone();
    blocking(&st.store, move |s| s.set_setting(crate::channels::MAINTENANCE_KEY, &serde_json::to_vec(&m2)?, now)).await?;
    audit(&st, &me.username, if minutes == 0 { "maintenance.end" } else { "maintenance.start" }, None, json!({ "minutes": minutes, "note": m.note }));
    Ok(Json(maintenance_json(&m, now)).into_response())
}

// ------------------------------------------------------------------- rules

/// The detection rules with their effective and default settings.
pub(crate) async fn rules_get(State(st): State<AppState>) -> Result<Json<Value>, ApiError> {
    let base = st.shared.detect_base().unwrap_or_default();
    let o = blocking(&st.store, |s| crate::rules::load(s)).await?;
    Ok(Json(crate::rules::describe(&base, &o)))
}

/// Change rule settings (admin). Takes effect within seconds, no restart.
pub(crate) async fn rules_put(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Json(patch): Json<Value>) -> Result<Response, ApiError> {
    let base = st.shared.detect_base().unwrap_or_default();
    let p2 = patch.clone();
    let res = blocking(&st.store, move |s| {
        let mut o = crate::rules::load(s)?;
        Ok(match o.patch(&p2) {
            Err(e) => Err(e),
            Ok(()) => {
                crate::rules::save(s, &o, now_ts())?;
                Ok(o)
            }
        })
    })
    .await?;
    Ok(match res {
        Err(e) => err(StatusCode::BAD_REQUEST, e),
        Ok(o) => {
            audit(&st, &me.username, "rules.update", None, patch);
            Json(crate::rules::describe(&base, &o)).into_response()
        }
    })
}

/// Drop every portal override: back to the command-line / built-in settings.
pub(crate) async fn rules_reset(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>) -> Result<Response, ApiError> {
    let base = st.shared.detect_base().unwrap_or_default();
    blocking(&st.store, |s| crate::rules::save(s, &crate::rules::Overrides::default(), now_ts())).await?;
    audit(&st, &me.username, "rules.reset", None, json!({}));
    Ok(Json(crate::rules::describe(&base, &crate::rules::Overrides::default())).into_response())
}

// ---------------------------------------------------------------- API tokens

pub(crate) async fn api_tokens_list(State(st): State<AppState>) -> Result<Json<Value>, ApiError> {
    Ok(Json(json!(blocking(&st.store, |s| s.list_api_tokens()).await?)))
}

#[derive(Deserialize)]
pub struct NewApiToken {
    label: String,
    role: String,
}

/// Create an API token. The value is in the response once and never again.
pub(crate) async fn api_tokens_create(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Json(b): Json<NewApiToken>) -> Response {
    match st.auth.issue_api_token(&b.label, &b.role, &me.username, now_ts()) {
        Ok((id, token)) => {
            audit(&st, &me.username, "api_token.create", None, json!({ "id": id, "label": b.label.trim(), "role": b.role }));
            (StatusCode::CREATED, Json(json!({ "id": id, "token": token, "role": b.role }))).into_response()
        }
        Err(e) => map_auth_err(e),
    }
}

pub(crate) async fn api_tokens_revoke(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Path(id): Path<i64>) -> Result<Response, ApiError> {
    let found = blocking(&st.store, move |s| s.revoke_api_token(id)).await?;
    if found {
        audit(&st, &me.username, "api_token.revoke", None, json!({ "id": id }));
        Ok(StatusCode::NO_CONTENT.into_response())
    } else {
        Ok(err(StatusCode::NOT_FOUND, "no active API token with that id"))
    }
}

// ------------------------------------------------------------- agent tokens

pub(crate) async fn tokens_list(State(st): State<AppState>) -> Result<Json<Value>, ApiError> {
    let t = blocking(&st.store, |s| s.list_agent_tokens()).await?;
    Ok(Json(json!(t
        .into_iter()
        .map(|t| json!({ "agent_id": t.agent_id, "label": t.label, "created_at": t.created_at, "last_used": t.last_used, "revoked": t.revoked }))
        .collect::<Vec<_>>())))
}

#[derive(Deserialize)]
pub struct NewToken {
    agent_id: String,
    #[serde(default)]
    label: String,
}

/// Issue (or rotate) an agent's token; the value is shown exactly once.
pub(crate) async fn tokens_issue(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Json(b): Json<NewToken>) -> Response {
    if b.label.len() > 100 {
        return err(StatusCode::BAD_REQUEST, "label too long");
    }
    match st.auth.issue_agent_token(&b.agent_id, b.label.trim(), now_ts()) {
        Ok(token) => {
            audit(&st, &me.username, "agent_token.issue", None, json!({ "agent_id": b.agent_id }));
            (StatusCode::CREATED, Json(json!({ "agent_id": b.agent_id, "token": token }))).into_response()
        }
        Err(e) => map_auth_err(e),
    }
}

pub(crate) async fn tokens_revoke(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Path(agent_id): Path<String>) -> Result<Response, ApiError> {
    let id = agent_id.clone();
    let found = blocking(&st.store, move |s| s.revoke_agent_token(&id)).await?;
    if found {
        audit(&st, &me.username, "agent_token.revoke", None, json!({ "agent_id": agent_id }));
        Ok(StatusCode::NO_CONTENT.into_response())
    } else {
        Ok(err(StatusCode::NOT_FOUND, "no active token for that agent"))
    }
}

// ----------------------------------------------------------------- branding

/// Public: the sign-in page needs the product name, colour and logo before
/// anybody is signed in. Nothing sensitive is in here by design.
pub(crate) async fn branding_get(State(st): State<AppState>) -> Result<Json<Value>, ApiError> {
    let (b, ver) = blocking(&st.store, |s| {
        let ver = if s.get_setting(branding::LOGO_KEY)?.is_some() {
            s.get_setting("branding.logo_v")?.map(|v| String::from_utf8_lossy(&v).to_string())
        } else {
            None
        };
        Ok((branding::load(s)?, ver))
    })
    .await?;
    Ok(Json(json!({
        "product_name": b.product_name,
        "accent": b.accent,
        "accent_text": b.accent.as_deref().map(branding::text_on),
        "theme_default": b.theme_default,
        "login_message": b.login_message,
        "default_language": b.default_language,
        "logo": ver.map(|v| format!("/branding/logo?v={v}")),
    })))
}

pub(crate) async fn branding_put(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Json(patch): Json<Value>) -> Result<Response, ApiError> {
    let out = blocking(&st.store, move |s| {
        let mut b = branding::load(s)?;
        Ok(match b.apply(&patch) {
            Err(e) => Err(e),
            Ok(()) => {
                branding::save(s, &b, now_ts())?;
                Ok((b, patch))
            }
        })
    })
    .await?;
    Ok(match out {
        Err(e) => err(StatusCode::BAD_REQUEST, e),
        Ok((b, patch)) => {
            audit(&st, &me.username, "branding.update", None, json!({ "fields": patch.as_object().map(|o| o.keys().cloned().collect::<Vec<_>>()) }));
            Json(json!({ "product_name": b.product_name, "accent": b.accent, "theme_default": b.theme_default, "login_message": b.login_message, "default_language": b.default_language })).into_response()
        }
    })
}

/// Upload the logo (raw image bytes). Only real PNG/JPEG/GIF/WebP files are
/// accepted, judged by content; SVG and anything else is refused.
pub(crate) async fn logo_put(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, body: axum::body::Bytes) -> Result<Response, ApiError> {
    if body.len() > branding::MAX_LOGO_BYTES {
        return Ok(err(StatusCode::PAYLOAD_TOO_LARGE, format!("the logo must be at most {} KB", branding::MAX_LOGO_BYTES / 1024)));
    }
    let Some(kind) = branding::sniff_image(&body) else {
        return Ok(err(StatusCode::BAD_REQUEST, "the logo must be a PNG, JPEG, GIF or WebP image (SVG is not accepted)"));
    };
    let n = body.len();
    blocking(&st.store, move |s| {
        let now = now_ts();
        s.set_setting(branding::LOGO_KEY, &body, now)?;
        s.set_setting(branding::LOGO_TYPE_KEY, kind.as_bytes(), now)?;
        s.set_setting("branding.logo_v", now.to_string().as_bytes(), now)
    })
    .await?;
    audit(&st, &me.username, "branding.logo_set", None, json!({ "type": kind, "bytes": n }));
    Ok(StatusCode::NO_CONTENT.into_response())
}

pub(crate) async fn logo_delete(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>) -> Result<Response, ApiError> {
    blocking(&st.store, |s| {
        for k in [branding::LOGO_KEY, branding::LOGO_TYPE_KEY, "branding.logo_v"] {
            s.delete_setting(k)?;
        }
        Ok(())
    })
    .await?;
    audit(&st, &me.username, "branding.logo_removed", None, json!({}));
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Public: the logo image. The content type comes from the bytes themselves,
/// and the response is locked down so it can only ever be displayed as an image.
pub(crate) async fn logo_get(State(st): State<AppState>) -> Result<Response, ApiError> {
    Ok(match blocking(&st.store, |s| branding::load_logo(s)).await? {
        Some((kind, bytes)) => (
            [
                (header::CONTENT_TYPE, kind.to_string()),
                (header::CONTENT_SECURITY_POLICY, "default-src 'none'; sandbox".to_string()),
            ],
            bytes,
        )
            .into_response(),
        None => err(StatusCode::NOT_FOUND, "no logo"),
    })
}

// ------------------------------------------------------------ asset editing

/// Everything the edit form needs to render its pickers.
pub(crate) async fn options() -> Json<Value> {
    Json(json!({
        "statuses": tracking::STATUSES,
        "criticalities": tracking::CRITICALITIES,
        "icons": tracking::ICONS,
        "purdue_levels": tracking::PURDUE_LEVELS,
        "device_types": crate::fingerprint::DEVICE_TYPES,
        "ot_types": crate::fingerprint::OT_TYPES,
        "roles": auth::ROLES,
        // what to do about each kind of alert
        "advice": crate::detect::ADVICE.iter().cloned().collect::<std::collections::BTreeMap<_, _>>(),
    }))
}

pub(crate) async fn patch_meta(
    State(st): State<AppState>,
    Extension(AuthUser(me)): Extension<AuthUser>,
    Path(id): Path<i64>,
    Json(patch): Json<Value>,
) -> Result<Response, ApiError> {
    let Some(existing) = blocking(&st.store, move |s| s.get_asset(id)).await? else {
        return Ok(err(StatusCode::NOT_FOUND, "no such asset"));
    };
    if !site_writable(&st, &me, &existing.agent_id) {
        return Ok(err(StatusCode::FORBIDDEN, "read-only access to this site"));
    }
    let by = me.username.clone();
    let outcome = blocking(&st.store, move |s| {
        if s.get_asset(id)?.is_none() {
            return Ok(Err((StatusCode::NOT_FOUND, "no such asset".to_string())));
        }
        let mut meta = s.get_meta(id)?.unwrap_or_default();
        match tracking::apply_patch(&mut meta, &patch) {
            Err(e) => Ok(Err((StatusCode::BAD_REQUEST, e))),
            Ok(changes) => {
                if !changes.is_empty() {
                    s.save_meta(id, &meta, &by, now_ts())?;
                }
                Ok(Ok(changes))
            }
        }
    })
    .await?;
    match outcome {
        Err((code, msg)) => Ok(err(code, msg)),
        Ok(changes) => {
            if !changes.is_empty() {
                audit(&st, &me.username, "asset.edit", Some(id), json!({ "changes": changes }));
            }
            Ok(match asset_view(&st, id).await? {
                Some(v) => Json(v).into_response(),
                None => err(StatusCode::NOT_FOUND, "no such asset"),
            })
        }
    }
}

#[derive(Deserialize)]
pub struct ReviewReq {
    /// Mark exactly these devices as known...
    #[serde(default)]
    ids: Vec<i64>,
    /// ...or every device that is not yet.
    #[serde(default)]
    all: bool,
}

/// Review queue: mark devices as known. Returns how many changed.
pub(crate) async fn review_assets(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Json(b): Json<ReviewReq>) -> Result<Response, ApiError> {
    if !b.all && (b.ids.is_empty() || b.ids.len() > 5000) {
        return Ok(err(StatusCode::BAD_REQUEST, "give 1-5000 device ids, or {\"all\": true}"));
    }
    let by = me.username.clone();
    let (user_id, role) = (me.id, me.role.clone());
    let n = blocking(&st.store, move |s| {
        let now = now_ts();
        let ids: Vec<i64> = if b.all { s.load_assets()?.into_iter().map(|a| a.id).collect() } else { b.ids };
        let mut changed = 0usize;
        for id in ids {
            let Some(a) = s.get_asset(id)? else { continue };
            if !crate::access::writable(s, user_id, &role, &a.agent_id) {
                continue; // this user cannot change devices on this site: silently skipped, not an error
            }
            let mut meta = s.get_meta(id)?.unwrap_or_default();
            if !meta.reviewed {
                meta.reviewed = true;
                s.save_meta(id, &meta, &by, now)?;
                changed += 1;
            }
        }
        Ok(changed)
    })
    .await?;
    audit(&st, &me.username, "assets.review", None, json!({ "count": n }));
    Ok(Json(json!({ "reviewed": n })).into_response())
}

/// Outcome of creating a manual asset: `(id, changes)` or an HTTP-ready error.
type Created = Result<(i64, Vec<crate::model::Change>), (StatusCode, String)>;

/// Create the asset row (and its meta) for a manually entered device.
fn create_manual(s: &dyn crate::store::Store, mac: crate::model::Mac, patch: &Value, by: &str, now: i64) -> anyhow::Result<Created> {
    let mut meta = AssetMeta { manual: true, ..Default::default() };
    let changes = match tracking::apply_patch(&mut meta, patch) {
        Ok(c) => c,
        Err(e) => return Ok(Err((StatusCode::BAD_REQUEST, e))),
    };
    let mut a = Asset::new(mac, now);
    a.last_seen = 0; // never observed: it is a record, not a sighting
    a.vendor = crate::fingerprint::vendor_for(&mac);
    a.device_type = meta.type_override.clone().unwrap_or_else(|| "unknown".into());
    s.save_asset(&mut a)?;
    s.save_meta(a.id, &meta, by, now)?;
    Ok(Ok((a.id, changes)))
}

pub(crate) async fn create_asset(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Json(mut body): Json<Value>) -> Result<Response, ApiError> {
    // `mac` is optional: assets that are not on the network yet get a private
    // placeholder that a real MAC can later replace (see README).
    let mac = match body.as_object_mut().and_then(|o| o.remove("mac")) {
        None | Some(Value::Null) => tracking::synthetic_mac(),
        Some(Value::String(s)) if s.trim().is_empty() => tracking::synthetic_mac(),
        Some(Value::String(s)) => match s.trim().to_lowercase().parse::<crate::model::Mac>() {
            Ok(m) if m.is_valid() => m,
            _ => return Ok(err(StatusCode::BAD_REQUEST, "mac: not a valid unicast MAC address")),
        },
        Some(_) => return Ok(err(StatusCode::BAD_REQUEST, "mac must be a string")),
    };
    let by = me.username.clone();
    let out = blocking(&st.store, move |s| {
        if s.find_asset(None, &mac)?.is_some() {
            return Ok(Err((StatusCode::CONFLICT, "an asset with that MAC address already exists".to_string())));
        }
        create_manual(s, mac, &body, &by, now_ts())
    })
    .await?;
    Ok(match out {
        Err((c, m)) => err(c, m),
        Ok((id, changes)) => {
            audit(&st, &me.username, "asset.create", Some(id), json!({ "changes": changes }));
            match asset_view(&st, id).await? {
                Some(v) => (StatusCode::CREATED, Json(v)).into_response(),
                None => err(StatusCode::INTERNAL_SERVER_ERROR, "created asset vanished"),
            }
        }
    })
}

/// Only manually created assets can be deleted; a discovered one would just
/// reappear, so it is retired via `status` instead.
pub(crate) async fn delete_asset(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Path(id): Path<i64>) -> Result<Response, ApiError> {
    let out = blocking(&st.store, move |s| {
        let Some(a) = s.get_asset(id)? else { return Ok(Err((StatusCode::NOT_FOUND, "no such asset"))) };
        let meta = s.get_meta(id)?.unwrap_or_default();
        if !meta.manual {
            return Ok(Err((StatusCode::BAD_REQUEST, "discovered assets cannot be deleted; set their status to \"retired\" instead")));
        }
        s.delete_asset(id)?;
        Ok(Ok(a.mac.to_string()))
    })
    .await?;
    Ok(match out {
        Err((c, m)) => err(c, m),
        Ok(mac) => {
            audit(&st, &me.username, "asset.delete", Some(id), json!({ "mac": mac }));
            StatusCode::NO_CONTENT.into_response()
        }
    })
}

pub(crate) async fn history(State(st): State<AppState>, Path(id): Path<i64>) -> Result<Json<Value>, ApiError> {
    let h = blocking(&st.store, move |s| s.list_audit(Some(id), 100)).await?;
    Ok(Json(json!(h)))
}

#[derive(Deserialize)]
pub struct AuditQuery {
    limit: Option<usize>,
}

pub(crate) async fn audit_list(State(st): State<AppState>, Query(q): Query<AuditQuery>) -> Result<Json<Value>, ApiError> {
    let limit = q.limit.unwrap_or(200).min(2000);
    let h = blocking(&st.store, move |s| s.list_audit(None, limit)).await?;
    Ok(Json(json!(h)))
}

/// Bulk create/update from CSV (see `tracking::parse_import`).
pub(crate) async fn import_assets(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, body: String) -> Result<Response, ApiError> {
    let (rows, mut errors) = match tracking::parse_import(&body) {
        Ok(v) => v,
        Err(e) => return Ok(err(StatusCode::BAD_REQUEST, e)),
    };
    let by = me.username.clone();
    let (created, updated, unchanged, row_errors, audits) = blocking(&st.store, move |s| {
        let (mut created, mut updated, mut unchanged) = (0, 0, 0);
        let (mut errs, mut audits) = (Vec::new(), Vec::new());
        for r in rows {
            match s.find_asset(None, &r.mac)? {
                None => match create_manual(s, r.mac, &r.patch, &by, now_ts())? {
                    Ok((id, changes)) => {
                        created += 1;
                        audits.push(("asset.create", id, changes));
                    }
                    Err((_, m)) => errs.push((r.line, m)),
                },
                Some(a) => {
                    let mut meta = s.get_meta(a.id)?.unwrap_or_default();
                    match tracking::apply_patch(&mut meta, &r.patch) {
                        Err(m) => errs.push((r.line, m)),
                        Ok(ch) if ch.is_empty() => unchanged += 1,
                        Ok(ch) => {
                            s.save_meta(a.id, &meta, &by, now_ts())?;
                            updated += 1;
                            audits.push(("asset.edit", a.id, ch));
                        }
                    }
                }
            }
        }
        Ok((created, updated, unchanged, errs, audits))
    })
    .await?;
    errors.extend(row_errors);
    errors.sort_by_key(|e| e.0);
    for (action, id, changes) in audits {
        audit(&st, &me.username, action, Some(id), json!({ "changes": changes, "via": "csv-import" }));
    }
    audit(&st, &me.username, "asset.import", None, json!({ "created": created, "updated": updated, "unchanged": unchanged, "errors": errors.len() }));
    Ok(Json(json!({
        "created": created, "updated": updated, "unchanged": unchanged,
        "errors": errors.iter().map(|(l, m)| json!({ "line": l, "error": m })).collect::<Vec<_>>(),
    }))
    .into_response())
}

// -------------------------------------------------------------------- findings: accepted risks and verifying a fix

// The sentences the risk and verify endpoints send back (translated by the console; `i18n.rs` checks they are).
const D_GONE: &str = "the device is no longer in the register";
const D_REG_STILL: &str = "the register still shows it";
const D_REG_FIXED: &str = "the register no longer shows it";
const D_OT: &str = "industrial devices are never scanned: check the device itself and update its ports by hand";
const D_NO_ADDR: &str = "no address is known for this device";
const D_CANNOT_SCAN: &str = "this DENIS cannot scan (viewer mode or passive-only): run a scan yourself, then verify again";
const D_PORT_OPEN: &str = "scanned just now: the port is still open";
const D_PORT_CLOSED: &str = "scanned just now: the port is closed";
const D_BANNER_STILL: &str = "scanned just now: the service still announces this version";
const D_BANNER_GONE: &str = "scanned just now: the service no longer announces this version";
const D_EXCLUDED: &str = "this address is excluded from probing (--exclude)";
const D_SILENT: &str = "the device did not answer: it may be off, so nothing is confirmed";
const E_REASON: &str = "give a reason of 3 to 500 characters: it is what an auditor will read";
const E_UNKNOWN: &str = "unknown finding";
const E_DEVICES: &str = "choose 1 to 500 devices";
const E_DAYS: &str = "the decision can last 1 to 3650 days (or leave it open-ended)";
const E_NOT_APPLY: &str = "that finding does not apply to any device right now";
const E_NO_RISK: &str = "no such accepted risk";

/// Every fixed sentence of the risk and verify endpoints, so the translation test can check them.
pub fn risk_texts() -> [&'static str; 18] {
    [D_BANNER_STILL, D_BANNER_GONE, D_GONE, D_REG_STILL, D_REG_FIXED, D_OT, D_NO_ADDR, D_CANNOT_SCAN, D_PORT_OPEN, D_PORT_CLOSED, D_EXCLUDED, D_SILENT, E_REASON, E_UNKNOWN, E_DEVICES, E_DAYS, E_NOT_APPLY, E_NO_RISK]
}

/// The decisions in force with the words of the finding each is about.
pub(crate) async fn risk_list(State(st): State<AppState>) -> Result<Json<Value>, ApiError> {
    let now = now_ts();
    let (mut assets, metas, acceptances) = blocking(&st.store, |s| Ok((s.load_assets()?, s.load_all_meta()?, s.list_risk_acceptances()?))).await?;
    for a in &mut assets {
        if let Some(m) = metas.get(&a.id) {
            tracking::apply_overrides(a, m);
        }
    }
    let (_, accepted) = crate::findings::apply_acceptances(crate::findings::compute(&assets, &metas, now), &acceptances, now);
    Ok(Json(json!(accepted)))
}

#[derive(Deserialize)]
pub(crate) struct AcceptReq {
    finding_id: String,
    asset_ids: Vec<i64>,
    reason: String,
    /// How many days the decision lasts; absent = until someone withdraws it.
    days: Option<u32>,
}

/// "Accept the risk": a person decides to live with a finding on some devices, with the reason and (usually) an end date.
pub(crate) async fn risk_accept(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Json(b): Json<AcceptReq>) -> Result<Response, ApiError> {
    let reason = b.reason.trim().to_string();
    if reason.chars().count() < 3 || reason.chars().count() > 500 || reason.chars().any(|c| c.is_control() && c != '\n') {
        return Ok(err(StatusCode::BAD_REQUEST, E_REASON));
    }
    if !crate::findings::is_known(&b.finding_id) {
        return Ok(err(StatusCode::BAD_REQUEST, E_UNKNOWN));
    }
    if b.asset_ids.is_empty() || b.asset_ids.len() > 500 {
        return Ok(err(StatusCode::BAD_REQUEST, E_DEVICES));
    }
    if b.days.is_some_and(|d| !(1..=3650).contains(&d)) {
        return Ok(err(StatusCode::BAD_REQUEST, E_DAYS));
    }
    let now = now_ts();
    let (mut assets, metas) = blocking(&st.store, |s| Ok((s.load_assets()?, s.load_all_meta()?))).await?;
    for a in &mut assets {
        if let Some(m) = metas.get(&a.id) {
            tracking::apply_overrides(a, m);
        }
    }
    // only a risk that exists can be accepted
    let current = crate::findings::compute(&assets, &metas, now);
    let Some(finding) = current.iter().find(|f| f.id == b.finding_id) else {
        return Ok(err(StatusCode::CONFLICT, E_NOT_APPLY));
    };
    if let Some(bad) = b.asset_ids.iter().find(|id| !finding.assets.contains(id)) {
        return Ok(err(StatusCode::CONFLICT, format!("that finding does not apply to device #{bad}")));
    }
    let expires_at = b.days.map(|d| now + d as i64 * 86_400);
    let (finding_id, ids, by, why) = (b.finding_id.clone(), b.asset_ids.clone(), me.username.clone(), reason.clone());
    let created = blocking(&st.store, move |s| {
        let mut made = Vec::new();
        for asset_id in ids {
            made.push(s.add_risk_acceptance(&RiskAcceptance { id: 0, finding_id: finding_id.clone(), asset_id, reason: why.clone(), accepted_by: by.clone(), accepted_at: now, expires_at, revoked_at: None, revoked_by: None })?);
        }
        Ok(made)
    })
    .await?;
    audit(&st, &me.username, "risk.accept", None, json!({ "finding": b.finding_id, "assets": b.asset_ids, "reason": reason, "expires_at": expires_at }));
    Ok((StatusCode::CREATED, Json(json!({ "ids": created, "expires_at": expires_at }))).into_response())
}

/// Withdraw a decision: the finding counts again.
pub(crate) async fn risk_revoke(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Path(id): Path<i64>) -> Result<Response, ApiError> {
    let (by, now) = (me.username.clone(), now_ts());
    let done = blocking(&st.store, move |s| s.revoke_risk_acceptance(id, &by, now)).await?;
    if !done {
        return Ok(err(StatusCode::NOT_FOUND, E_NO_RISK));
    }
    audit(&st, &me.username, "risk.revoke", None, json!({ "id": id }));
    Ok(Json(json!({ "ok": true })).into_response())
}

#[derive(Deserialize, Default)]
pub(crate) struct VerifyReq {
    #[serde(default)]
    asset_ids: Vec<i64>,
}

/// "Verify fix": look again. A finding about an open port makes DENIS scan the devices again right now; the others
/// are re-read from the register. Each device is reported as `fixed`, `still_present`, `unreachable` (a scan proves
/// nothing about a device that does not answer), `excluded` (the operator keeps probes away from it) or `not_probed`
/// (industrial devices are never scanned; or this program cannot probe).
pub(crate) async fn finding_verify(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Path(finding_id): Path<String>, body: Option<Json<VerifyReq>>) -> Result<Response, ApiError> {
    if !crate::findings::is_known(&finding_id) {
        return Ok(err(StatusCode::NOT_FOUND, E_UNKNOWN));
    }
    let wanted = body.map(|Json(b)| b.asset_ids).unwrap_or_default();
    let now = now_ts();
    let (mut assets, metas) = blocking(&st.store, |s| Ok((s.load_assets()?, s.load_all_meta()?))).await?;
    for a in &mut assets {
        if let Some(m) = metas.get(&a.id) {
            tracking::apply_overrides(a, m);
        }
    }
    let before = crate::findings::compute(&assets, &metas, now);
    // the devices to look at: the ones asked for, else every device that has the finding (accepted ones too: a fix is a fix)
    let mut ids: Vec<i64> = before.iter().find(|f| f.id == finding_id).map(|f| f.assets.clone()).unwrap_or_default();
    if !wanted.is_empty() {
        ids = wanted.into_iter().collect();
    }
    ids.sort_unstable();
    ids.dedup();
    ids.truncate(200);

    let port_finding = crate::findings::is_scan_finding(&finding_id);
    let banner_finding = crate::findings::is_banner_finding(&finding_id);
    let mut results: Vec<Value> = Vec::new();
    let mut rescanned = false;
    let mut to_scan: Vec<(i64, std::net::Ipv4Addr)> = Vec::new();
    for id in &ids {
        let Some(a) = assets.iter().find(|a| a.id == *id) else {
            results.push(json!({ "asset_id": id, "status": "fixed", "detail": D_GONE }));
            continue;
        };
        let meta = metas.get(id);
        if !port_finding {
            let still = crate::findings::applies(a, meta, now, &finding_id);
            results.push(json!({ "asset_id": id, "status": if still { "still_present" } else { "fixed" }, "detail": if still { D_REG_STILL } else { D_REG_FIXED } }));
        } else if crate::fingerprint::is_ot_device(a) {
            results.push(json!({ "asset_id": id, "status": "not_probed", "detail": D_OT }));
        } else if let Some(ip) = a.current_ip() {
            to_scan.push((*id, ip));
        } else {
            results.push(json!({ "asset_id": id, "status": "unreachable", "detail": D_NO_ADDR }));
        }
    }
    if !to_scan.is_empty() {
        match st.shared.rescan(to_scan.iter().map(|(_, ip)| *ip).collect()).await {
            None => {
                for (id, _) in &to_scan {
                    results.push(json!({ "asset_id": id, "status": "not_probed", "detail": D_CANNOT_SCAN }));
                }
            }
            Some(outcomes) => {
                rescanned = true;
                for (id, ip) in &to_scan {
                    let outcome = outcomes.iter().find(|(o, _)| o == ip).map(|(_, o)| o.clone());
                    let a = assets.iter().find(|a| a.id == *id).expect("asset").clone();
                    results.push(match outcome {
                        Some(crate::engine::RescanOutcome::Scanned(open, banners)) => {
                            let mut fresh = a.clone();
                            fresh.open_ports = open;
                            // what the services say now replaces what was read before
                            fresh.fingerprint.identity.retain(|k, _| !k.starts_with("banner."));
                            fresh.fingerprint.identity.extend(banners);
                            let still = crate::findings::applies(&fresh, metas.get(id), now, &finding_id);
                            let detail = match (banner_finding, still) {
                                (true, true) => D_BANNER_STILL,
                                (true, false) => D_BANNER_GONE,
                                (false, true) => D_PORT_OPEN,
                                (false, false) => D_PORT_CLOSED,
                            };
                            json!({ "asset_id": id, "status": if still { "still_present" } else { "fixed" }, "detail": detail })
                        }
                        Some(crate::engine::RescanOutcome::Excluded) => json!({ "asset_id": id, "status": "excluded", "detail": D_EXCLUDED }),
                        _ => json!({ "asset_id": id, "status": "unreachable", "detail": D_SILENT }),
                    });
                }
            }
        }
    }
    let fixed = results.iter().filter(|r| r["status"] == "fixed").count();
    let still = results.iter().filter(|r| r["status"] == "still_present").count();
    audit(&st, &me.username, "finding.verify", None, json!({ "finding": finding_id, "devices": ids.len(), "fixed": fixed, "still_present": still, "rescanned": rescanned }));
    results.sort_by_key(|r| r["asset_id"].as_i64());
    Ok(Json(json!({ "finding_id": finding_id, "rescanned": rescanned, "fixed": fixed, "still_present": still, "results": results })).into_response())
}
