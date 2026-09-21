//! HTTP handlers for the authenticator-app second step (TOTP): signing in with a code, setting it up
//! (with a QR code), turning it off, new recovery codes, an administrator's reset, and the policy that
//! makes a second step compulsory. The arithmetic is in `totp.rs`, the one-time tickets and lock-out in `auth.rs`.
//!
//! The secret is stored in the database (a code cannot be checked against a hash), so a backup or a copy of the
//! database holds everything needed to make codes: guard it like the password hashes it sits beside. The secret is
//! shown once, at set-up, and never returned again.

use axum::extract::{Extension, Path, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use crate::auth::AuthError;
use crate::model::now_ts;
use crate::web::{blocking, ApiError, AppState, AuthUser};
use crate::web_admin::{audit, client_ip, cookie, err};

const E_CODE: &str = "the code was not accepted";
const E_PASSWORD: &str = "that password is not right";
const E_NOT_STARTED: &str = "start again: there is no pending set-up";
const E_ALREADY: &str = "an authenticator app is already set up: turn it off first";
const E_OFF: &str = "no authenticator app is set up";
const E_REQUIRED: &str = "your administrator requires a second sign-in step: add a passkey first, then you can turn this off";
const E_BAD_CODE_SETUP: &str = "that code is not right: check the time on your phone, then type the next code";
const E_POLICY: &str = "the policy must be off, admins or all";

/// Every fixed sentence of these endpoints, so the translation test can check them.
pub fn texts() -> [&'static str; 8] {
    [E_CODE, E_PASSWORD, E_NOT_STARTED, E_ALREADY, E_OFF, E_REQUIRED, E_BAD_CODE_SETUP, E_POLICY]
}

fn wrong_password(e: AuthError) -> Response {
    match e {
        AuthError::Locked(secs) => err(StatusCode::TOO_MANY_REQUESTS, format!("too many attempts; try again in {secs} seconds")),
        AuthError::Invalid => err(StatusCode::UNAUTHORIZED, E_PASSWORD),
        _ => err(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    }
}

// ---------------------------------------------------------------- signing in

#[derive(Deserialize)]
pub struct MfaReq {
    ticket: String,
    code: String,
}

/// Public: the second step of a sign-in. The ticket came with the right password.
pub(crate) async fn mfa_login(
    State(st): State<AppState>,
    peer: Option<Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    headers: axum::http::HeaderMap,
    Json(b): Json<MfaReq>,
) -> Response {
    let ip = client_ip(peer.map(|Extension(c)| c.0), &headers);
    let now = now_ts();
    let wait = st.auth.ip_wait(ip, now);
    if wait > 0 {
        return err(StatusCode::TOO_MANY_REQUESTS, format!("too many attempts; try again in {wait} seconds"));
    }
    if b.ticket.len() != 64 || b.code.len() > 32 {
        st.auth.ip_failure(ip, now);
        return err(StatusCode::UNAUTHORIZED, E_CODE);
    }
    let auth = st.auth.clone();
    let (ticket, code) = (b.ticket, b.code);
    let res = tokio::task::spawn_blocking(move || auth.complete_mfa(&ticket, &code, now_ts())).await;
    match res {
        Ok(Ok((token, user, method))) => {
            audit(&st, &user.username, "auth.login", None, json!({ "second_step": method }));
            if method == "recovery" {
                audit(&st, &user.username, "totp.recovery_code_used", None, json!({}));
            }
            let must_enrol = st.auth.must_enrol(&user, now_ts());
            let mut r = Json(json!({ "user": user, "must_change": user.must_change, "must_enrol": must_enrol })).into_response();
            r.headers_mut().insert(header::SET_COOKIE, cookie(&token, st.secure_cookie, None));
            r
        }
        Ok(Err(AuthError::Locked(secs))) => err(StatusCode::TOO_MANY_REQUESTS, format!("too many attempts; try again in {secs} seconds")),
        Ok(Err(_)) => {
            st.auth.ip_failure(ip, now);
            audit(&st, "-", "auth.mfa_failed", None, json!({ "ip": ip.to_string() }));
            err(StatusCode::UNAUTHORIZED, E_CODE)
        }
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    }
}

// ------------------------------------------------------------------ set-up

pub(crate) async fn status(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>) -> Result<Json<serde_json::Value>, ApiError> {
    let uid = me.id;
    let (totp, left, passkeys) = blocking(&st.store, move |s| Ok((s.get_totp(uid)?, s.recovery_codes_left(uid)?, s.list_passkeys(uid)?.len()))).await?;
    let policy = st.auth.mfa_policy(now_ts());
    let required = match policy.as_str() { "all" => true, "admins" => me.role == "admin", _ => false };
    Ok(Json(json!({
        "enabled": totp.as_ref().is_some_and(|t| t.enabled),
        "pending": totp.as_ref().is_some_and(|t| !t.enabled),
        "recovery_left": left, "passkeys": passkeys, "policy": policy, "required": required,
    })))
}

#[derive(Deserialize)]
pub struct PasswordReq {
    password: String,
}

/// Start: check the password again, make a secret and keep it pending until its first code is confirmed.
pub(crate) async fn begin(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Json(b): Json<PasswordReq>) -> Response {
    if b.password.len() > 256 {
        return err(StatusCode::BAD_REQUEST, E_PASSWORD);
    }
    let auth = st.auth.clone();
    let (u, pw) = (me.clone(), b.password);
    match tokio::task::spawn_blocking(move || auth.confirm_password(&u, &pw, now_ts())).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return wrong_password(e),
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    }
    let Ok(secret) = crate::totp::generate_secret() else { return err(StatusCode::INTERNAL_SERVER_ERROR, "internal error") };
    let uid = me.id;
    let stored = blocking(&st.store, move |s| s.set_totp_pending(uid, &secret, now_ts())).await;
    match stored {
        Ok(true) => {}
        Ok(false) => return err(StatusCode::CONFLICT, E_ALREADY),
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    }
    let issuer = crate::branding::load(&*st.store).map(|b| b.product_name).unwrap_or_else(|_| "DENIS".into());
    Json(json!({ "secret": crate::totp::base32(&secret), "uri": crate::totp::otpauth_uri(&issuer, &me.username, &secret) })).into_response()
}

/// The QR code of the pending secret, as an image the console shows (so the secret never sits in a `data:` address).
pub(crate) async fn qr(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>) -> Response {
    let uid = me.id;
    let rec = match blocking(&st.store, move |s| s.get_totp(uid)).await {
        Ok(r) => r,
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    };
    let Some(rec) = rec.filter(|r| !r.enabled) else { return err(StatusCode::NOT_FOUND, E_NOT_STARTED) };
    let issuer = crate::branding::load(&*st.store).map(|b| b.product_name).unwrap_or_else(|_| "DENIS".into());
    match crate::totp::qr_svg(&crate::totp::otpauth_uri(&issuer, &me.username, &rec.secret)) {
        Ok(svg) => (
            [
                (header::CONTENT_TYPE, "image/svg+xml".to_string()),
                (header::CONTENT_SECURITY_POLICY, "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'".to_string()),
                (header::CACHE_CONTROL, "no-store".to_string()),
            ],
            svg,
        )
            .into_response(),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    }
}

#[derive(Deserialize)]
pub struct CodeReq {
    code: String,
}

/// Confirm with the first code: the app is now on, and the recovery codes are shown (once).
pub(crate) async fn confirm(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Json(b): Json<CodeReq>) -> Response {
    let now = now_ts();
    if let Err(e) = st.auth.code_check(&me, now) {
        return wrong_password(e);
    }
    let uid = me.id;
    let rec = match blocking(&st.store, move |s| s.get_totp(uid)).await {
        Ok(r) => r,
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    };
    let Some(rec) = rec.filter(|r| !r.enabled) else { return err(StatusCode::BAD_REQUEST, E_NOT_STARTED) };
    let Some(step) = crate::totp::verify(&rec.secret, &b.code, now, 0) else {
        st.auth.code_failed(&me, now);
        return err(StatusCode::BAD_REQUEST, E_BAD_CODE_SETUP);
    };
    let Ok(codes) = crate::totp::new_recovery_codes() else { return err(StatusCode::INTERNAL_SERVER_ERROR, "internal error") };
    let hashes: Vec<String> = codes.iter().map(|c| crate::totp::hash_recovery(c)).collect();
    match blocking(&st.store, move |s| s.enable_totp(uid, step, &hashes)).await {
        Ok(true) => {
            audit(&st, &me.username, "totp.enable", None, json!({}));
            Json(json!({ "recovery_codes": codes })).into_response()
        }
        Ok(false) => err(StatusCode::CONFLICT, E_ALREADY),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    }
}

/// Turn it off (own account; the password again). Refused when the policy requires a second step and this is the only one.
pub(crate) async fn disable(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Json(b): Json<PasswordReq>) -> Response {
    if b.password.len() > 256 {
        return err(StatusCode::BAD_REQUEST, E_PASSWORD);
    }
    let auth = st.auth.clone();
    let (u, pw) = (me.clone(), b.password);
    match tokio::task::spawn_blocking(move || auth.confirm_password(&u, &pw, now_ts())).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return wrong_password(e),
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    }
    let uid = me.id;
    let (has_passkey, on) = match blocking(&st.store, move |s| Ok((!s.list_passkeys(uid)?.is_empty(), s.get_totp(uid)?.is_some()))).await {
        Ok(v) => v,
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    };
    if !on {
        return err(StatusCode::NOT_FOUND, E_OFF);
    }
    let required = match st.auth.mfa_policy(now_ts()).as_str() { "all" => true, "admins" => me.role == "admin", _ => false };
    if required && !has_passkey {
        return err(StatusCode::CONFLICT, E_REQUIRED);
    }
    let _ = blocking(&st.store, move |s| s.delete_totp(uid)).await;
    audit(&st, &me.username, "totp.disable", None, json!({}));
    StatusCode::NO_CONTENT.into_response()
}

#[derive(Deserialize)]
pub struct RecoveryReq {
    password: String,
    code: String,
}

/// New recovery codes (the old ones stop working): needs the password and a current code.
pub(crate) async fn new_recovery_codes(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Json(b): Json<RecoveryReq>) -> Response {
    let now = now_ts();
    if b.password.len() > 256 || b.code.len() > 32 {
        return err(StatusCode::BAD_REQUEST, E_CODE);
    }
    let auth = st.auth.clone();
    let (u, pw) = (me.clone(), b.password);
    match tokio::task::spawn_blocking(move || auth.confirm_password(&u, &pw, now_ts())).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return wrong_password(e),
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    }
    if let Err(e) = st.auth.code_check(&me, now) {
        return wrong_password(e);
    }
    let uid = me.id;
    let rec = match blocking(&st.store, move |s| s.get_totp(uid)).await {
        Ok(r) => r,
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    };
    let Some(rec) = rec.filter(|r| r.enabled) else { return err(StatusCode::NOT_FOUND, E_OFF) };
    let step = match crate::totp::verify(&rec.secret, &b.code, now, rec.last_step) {
        Some(s) => s,
        None => {
            st.auth.code_failed(&me, now);
            return err(StatusCode::UNAUTHORIZED, E_CODE);
        }
    };
    let Ok(codes) = crate::totp::new_recovery_codes() else { return err(StatusCode::INTERNAL_SERVER_ERROR, "internal error") };
    let hashes: Vec<String> = codes.iter().map(|c| crate::totp::hash_recovery(c)).collect();
    let saved = blocking(&st.store, move |s| {
        if !s.advance_totp_step(uid, step)? {
            return Ok(false); // the same code was used a moment ago
        }
        s.replace_recovery_codes(uid, &hashes)?;
        Ok(true)
    })
    .await;
    match saved {
        Ok(true) => {
            audit(&st, &me.username, "totp.recovery_codes", None, json!({}));
            Json(json!({ "recovery_codes": codes })).into_response()
        }
        Ok(false) => err(StatusCode::UNAUTHORIZED, E_CODE),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    }
}

// --------------------------------------------------------------- administrators

/// An administrator removes somebody's authenticator app (a lost phone): they can then sign in with their password
/// (or a passkey) and set it up again. Their sessions are ended.
pub(crate) async fn admin_reset(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Path(id): Path<i64>) -> Result<Response, ApiError> {
    let removed = blocking(&st.store, move |s| {
        let had = s.delete_totp(id)?;
        if had {
            s.delete_user_sessions(id, None)?;
        }
        Ok(had)
    })
    .await?;
    if removed {
        audit(&st, &me.username, "totp.reset", None, json!({ "user_id": id }));
    }
    Ok(Json(json!({ "removed": removed })).into_response())
}

/// Who must use a second step, and how many people that would catch right now.
pub(crate) async fn policy_get(State(st): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    let policy = st.auth.mfa_policy(now_ts());
    let (admins_without, all_without) = blocking(&st.store, |s| {
        let totp = s.totp_enabled_users()?;
        let (mut a, mut n) = (0, 0);
        for u in s.list_users()?.into_iter().filter(|u| !u.disabled) {
            if !totp.contains(&u.id) && s.list_passkeys(u.id)?.is_empty() {
                n += 1;
                if u.role == "admin" {
                    a += 1;
                }
            }
        }
        Ok((a, n))
    })
    .await?;
    Ok(Json(json!({ "mfa_required": policy, "admins_without": admins_without, "all_without": all_without })))
}

#[derive(Deserialize)]
pub struct PolicyReq {
    mfa_required: String,
}

pub(crate) async fn policy_put(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Json(b): Json<PolicyReq>) -> Response {
    if !crate::auth::MFA_POLICIES.contains(&b.mfa_required.as_str()) {
        return err(StatusCode::BAD_REQUEST, E_POLICY);
    }
    if let Err(e) = st.auth.set_mfa_policy(&b.mfa_required, now_ts()) {
        return match e {
            AuthError::Rejected(m) => err(StatusCode::BAD_REQUEST, m),
            _ => err(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
        };
    }
    audit(&st, &me.username, "security.mfa_policy", None, json!({ "mfa_required": b.mfa_required }));
    Json(json!({ "mfa_required": b.mfa_required })).into_response()
}
