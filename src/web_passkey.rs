//! HTTP handlers for passkeys. The cryptography and every WebAuthn check live in
//! `passkey.rs`; this file only moves JSON in and out, enforces who may call what, and
//! turns a verified passkey into an ordinary session cookie.

use axum::extract::{Extension, Path, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::model::now_ts;
use crate::passkey::{self, Kind};
use crate::web::{blocking, ApiError, AppState, AuthUser};
use crate::web_admin::{audit, client_ip, cookie, err};

/// Passkeys one person may register.
const MAX_PER_USER: usize = 10;

const NOT_AVAILABLE: &str = "Passkeys are not available on this setup. Start DENIS with --public-url https://your-address (or open the console as http://localhost).";

fn cfg(st: &AppState) -> Option<passkey::Config> {
    st.auth.passkey_cfg.lock().unwrap().clone()
}

/// Public: which sign-in methods this console offers (the sign-in page asks before anybody is signed in).
pub(crate) async fn methods(State(st): State<AppState>) -> Json<Value> {
    let c = cfg(&st);
    Json(json!({ "password": true, "passkey": c.is_some(), "rp_id": c.map(|c| c.rp_id) }))
}

pub(crate) async fn register_begin(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>) -> Result<Response, ApiError> {
    let Some(cfg) = cfg(&st) else { return Ok(err(StatusCode::BAD_REQUEST, NOT_AVAILABLE)) };
    let (uid, uname) = (me.id, me.username.clone());
    let (existing, brand) = blocking(&st.store, move |s| Ok((s.list_passkeys(uid)?, crate::branding::load(s)?))).await?;
    if existing.len() >= MAX_PER_USER {
        return Ok(err(StatusCode::BAD_REQUEST, format!("at most {MAX_PER_USER} passkeys per person: remove one first")));
    }
    let begun = st.auth.ceremonies.lock().unwrap().begin(Kind::Register, Some(me.id));
    let (ceremony, challenge) = match begun {
        Ok(v) => v,
        Err(e) => return Ok(err(StatusCode::TOO_MANY_REQUESTS, e)),
    };
    let ids: Vec<Vec<u8>> = existing.into_iter().map(|p| p.credential_id).collect();
    Ok(Json(json!({ "ceremony": ceremony, "publicKey": passkey::creation_options(&cfg, &challenge, uid, &uname, &ids, &brand.product_name) })).into_response())
}

#[derive(Deserialize)]
pub struct Credential {
    id: String,
    response: Value,
}

#[derive(Deserialize)]
pub struct FinishReq {
    ceremony: String,
    #[serde(default)]
    name: String,
    credential: Credential,
}

/// Read a base64url field of the browser's response.
fn field(v: &Value, key: &str) -> Option<Vec<u8>> {
    passkey::unb64url(v.get(key)?.as_str()?)
}

pub(crate) async fn register_finish(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Json(b): Json<FinishReq>) -> Result<Response, ApiError> {
    let Some(cfg) = cfg(&st) else { return Ok(err(StatusCode::BAD_REQUEST, NOT_AVAILABLE)) };
    let name: String = b.name.trim().chars().filter(|c| !c.is_control()).take(40).collect();
    let taken = st.auth.ceremonies.lock().unwrap().take(&b.ceremony, Kind::Register);
    let Some((challenge, Some(owner))) = taken else { return Ok(err(StatusCode::BAD_REQUEST, "this registration expired; start again")) };
    if owner != me.id {
        return Ok(err(StatusCode::BAD_REQUEST, "this registration belongs to another sign-in"));
    }
    let (Some(cd), Some(att)) = (field(&b.credential.response, "clientDataJSON"), field(&b.credential.response, "attestationObject")) else {
        return Ok(err(StatusCode::BAD_REQUEST, "the passkey response is not valid"));
    };
    let cred = match passkey::verify_registration(&cfg, &challenge, &cd, &att) {
        Ok(c) => c,
        Err(e) => {
            audit(&st, &me.username, "passkey.register_failed", None, json!({ "reason": e.to_string() }));
            return Ok(err(StatusCode::BAD_REQUEST, e.to_string()));
        }
    };
    if passkey::unb64url(&b.credential.id).as_deref() != Some(cred.credential_id.as_slice()) {
        return Ok(err(StatusCode::BAD_REQUEST, "the passkey response is not valid"));
    }
    let name = if name.is_empty() { format!("Passkey {}", now_ts() % 10_000) } else { name };
    let (uid, n2) = (me.id, name.clone());
    let saved = blocking(&st.store, move |s| {
        if s.list_passkeys(uid)?.len() >= MAX_PER_USER {
            return Ok(Err("too many passkeys".to_string()));
        }
        Ok(match s.add_passkey(uid, &cred.credential_id, &cred.public_key, cred.sign_count, &n2, now_ts()) {
            Ok(id) => Ok(id),
            Err(_) => Err("this passkey is already registered".to_string()), // unique credential id
        })
    })
    .await?;
    Ok(match saved {
        Ok(id) => {
            audit(&st, &me.username, "passkey.register", None, json!({ "id": id, "name": name }));
            (StatusCode::CREATED, Json(json!({ "id": id, "name": name }))).into_response()
        }
        Err(m) => err(StatusCode::BAD_REQUEST, m),
    })
}

/// Public: start a sign-in with a passkey (no user name needed).
pub(crate) async fn login_begin(State(st): State<AppState>) -> Response {
    let Some(cfg) = cfg(&st) else { return err(StatusCode::BAD_REQUEST, NOT_AVAILABLE) };
    match st.auth.ceremonies.lock().unwrap().begin(Kind::Login, None) {
        Ok((ceremony, challenge)) => Json(json!({ "ceremony": ceremony, "publicKey": passkey::request_options(&cfg, &challenge) })).into_response(),
        Err(e) => err(StatusCode::TOO_MANY_REQUESTS, e),
    }
}

/// Public: finish a passkey sign-in and open a session.
pub(crate) async fn login_finish(
    State(st): State<AppState>,
    peer: Option<Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    headers: axum::http::HeaderMap,
    Json(b): Json<FinishReq>,
) -> Result<Response, ApiError> {
    let ip = client_ip(peer.map(|Extension(c)| c.0), &headers);
    let now = now_ts();
    let wait = st.auth.ip_wait(ip, now);
    if wait > 0 {
        let mut r = err(StatusCode::TOO_MANY_REQUESTS, format!("too many attempts; try again in {wait} seconds"));
        if let Ok(v) = header::HeaderValue::from_str(&wait.to_string()) {
            r.headers_mut().insert(header::RETRY_AFTER, v);
        }
        return Ok(r);
    }
    let fail = |st: &AppState, why: &str| {
        st.auth.ip_failure(ip, now_ts());
        audit(st, "-", "auth.passkey_failed", None, json!({ "ip": ip.to_string(), "reason": why }));
        err(StatusCode::UNAUTHORIZED, "the passkey was not accepted")
    };
    let Some(cfg) = cfg(&st) else { return Ok(err(StatusCode::BAD_REQUEST, NOT_AVAILABLE)) };
    let Some((challenge, _)) = st.auth.ceremonies.lock().unwrap().take(&b.ceremony, Kind::Login) else {
        return Ok(fail(&st, "expired or unknown ceremony"));
    };
    let r = &b.credential.response;
    let (Some(cd), Some(ad), Some(sig), Some(cred_id)) = (
        field(r, "clientDataJSON"), field(r, "authenticatorData"), field(r, "signature"), passkey::unb64url(&b.credential.id),
    ) else {
        return Ok(fail(&st, "malformed response"));
    };
    let cid = cred_id.clone();
    let found = blocking(&st.store, move |s| s.find_passkey(&cid)).await?;
    let Some(pk) = found else { return Ok(fail(&st, "unknown passkey")) };
    // the passkey names its owner; if it also says who, they must agree
    if let Some(h) = field(r, "userHandle").filter(|h| !h.is_empty()) {
        if h != pk.user_id.to_be_bytes() {
            return Ok(fail(&st, "user handle mismatch"));
        }
    }
    let new_count = match passkey::verify_assertion(&cfg, &challenge, &pk.public_key, pk.sign_count, &cd, &ad, &sig) {
        Ok(c) => c,
        Err(e) => return Ok(fail(&st, &e.to_string())),
    };
    let auth = st.auth.clone();
    let uid = pk.user_id;
    let started = tokio::task::spawn_blocking(move || auth.start_session_for(uid, now_ts())).await;
    let (token, user) = match started {
        Ok(Ok(v)) => v,
        Ok(Err(crate::auth::AuthError::Rejected(m))) => return Ok(err(StatusCode::FORBIDDEN, m)),
        Ok(Err(_)) => return Ok(fail(&st, "account unavailable")),
        Err(_) => return Ok(err(StatusCode::INTERNAL_SERVER_ERROR, "internal error")),
    };
    let pid = pk.id;
    blocking(&st.store, move |s| s.update_passkey_use(pid, new_count, now_ts())).await?;
    audit(&st, &user.username, "auth.passkey_login", None, json!({ "passkey": pk.name }));
    let mut resp = Json(json!({ "user": user, "must_change": false })).into_response();
    resp.headers_mut().insert(header::SET_COOKIE, cookie(&token, st.secure_cookie, None));
    Ok(resp)
}

/// The signed-in user's own passkeys (never key material).
pub(crate) async fn list(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>) -> Result<Json<Value>, ApiError> {
    let uid = me.id;
    let v = blocking(&st.store, move |s| s.list_passkeys(uid)).await?;
    Ok(Json(json!(v.into_iter().map(|p| json!({ "id": p.id, "name": p.name, "created_at": p.created_at, "last_used": p.last_used })).collect::<Vec<_>>())))
}

pub(crate) async fn delete(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Path(id): Path<i64>) -> Result<Response, ApiError> {
    let uid = me.id;
    let found = blocking(&st.store, move |s| s.delete_passkey(id, uid)).await?;
    if !found {
        return Ok(err(StatusCode::NOT_FOUND, "no such passkey"));
    }
    audit(&st, &me.username, "passkey.remove", None, json!({ "id": id }));
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Administrators: remove every passkey of a user (a lost or stolen device).
pub(crate) async fn admin_revoke_all(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Path(user_id): Path<i64>) -> Result<Response, ApiError> {
    let n = blocking(&st.store, move |s| s.delete_user_passkeys(user_id)).await?;
    audit(&st, &me.username, "passkey.revoke_all", None, json!({ "user_id": user_id, "removed": n }));
    Ok(Json(json!({ "removed": n })).into_response())
}
