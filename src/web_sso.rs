//! Single sign-on (OpenID Connect) HTTP handlers: the login page's public status, an
//! administrator's configuration, and the redirect/callback that does the actual sign-in.
//! The protocol itself is in `sso.rs`; this is just the web plumbing around it.

use axum::extract::{Query, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::model::now_ts;
use crate::sso::SsoConfig;
use crate::web::common::{blocking, ApiError, AppState, AuthUser};
use crate::web_admin::{audit, cookie, err};

/// Where the identity provider is asked to send the browser back to: this request's own
/// Host header (already checked against `--allowed-host` by the time a handler sees it) and
/// the scheme this console is actually reachable on.
fn redirect_url(st: &AppState, headers: &axum::http::HeaderMap) -> String {
    let host = headers.get(header::HOST).and_then(|h| h.to_str().ok()).unwrap_or("localhost");
    let scheme = if st.secure_cookie { "https" } else { "http" };
    format!("{scheme}://{host}/api/auth/sso/callback")
}

/// Whether to show a "Sign in with ..." button, and its label. Public: shown on the sign-in
/// page before anyone is authenticated.
pub(crate) async fn status(State(st): State<AppState>) -> Result<Json<crate::sso::PublicStatus>, ApiError> {
    let cfg = blocking(&st.store, |s| crate::sso::load(s)).await?;
    Ok(Json(cfg.public()))
}

/// The administrator's configuration, secret withheld (see `Redacted`).
#[derive(Serialize)]
pub struct Redacted {
    #[serde(flatten)]
    cfg: SsoConfig,
    /// So the form can show "unchanged" instead of a blank field without ever sending the
    /// actual secret back to the browser.
    secret_set: bool,
}

pub(crate) async fn get(State(st): State<AppState>) -> Result<Json<Redacted>, ApiError> {
    let mut cfg = blocking(&st.store, |s| crate::sso::load(s)).await?;
    let secret_set = !cfg.client_secret.is_empty();
    cfg.client_secret.clear();
    Ok(Json(Redacted { cfg, secret_set }))
}

#[derive(Deserialize)]
pub struct PutReq {
    enabled: bool,
    issuer_url: String,
    client_id: String,
    /// Blank keeps the secret already stored (see `get`'s `secret_set`); anything else replaces it.
    #[serde(default)]
    client_secret: String,
    #[serde(default)]
    button_label: String,
    /// Email domains allowed to sign in - required non-empty to enable (see `SsoConfig::validate`).
    #[serde(default)]
    allowed_domains: Vec<String>,
}

pub(crate) async fn put(State(st): State<AppState>, axum::extract::Extension(AuthUser(me)): axum::extract::Extension<AuthUser>, Json(b): Json<PutReq>) -> Result<Response, ApiError> {
    let res = blocking(&st.store, move |s| {
        let existing = crate::sso::load(s)?;
        let issuer_url = b.issuer_url.trim().to_string();
        // M3: the client secret is only ever safe to keep for the issuer it was entered for - it
        // goes to whatever token endpoint that issuer's discovery document names, so a changed
        // issuer must not silently carry the old secret to it.
        let issuer_changed = existing.issuer_url != issuer_url;
        let cfg = SsoConfig {
            enabled: b.enabled,
            issuer_url,
            client_id: b.client_id.trim().to_string(),
            client_secret: if b.client_secret.is_empty() { if issuer_changed { String::new() } else { existing.client_secret } } else { b.client_secret },
            button_label: b.button_label.trim().to_string(),
            allowed_domains: b.allowed_domains.iter().map(|d| d.trim().trim_start_matches('@').to_lowercase()).filter(|d| !d.is_empty()).collect(),
        };
        Ok(match cfg.validate() {
            Ok(()) => {
                crate::sso::save(s, &cfg, now_ts())?;
                Ok(cfg)
            }
            Err(e) => Err(e),
        })
    })
    .await?;
    Ok(match res {
        Ok(cfg) => {
            audit(&st, &me.username, "sso.update", None, json!({"enabled": cfg.enabled, "issuer_url": cfg.issuer_url}));
            let secret_set = !cfg.client_secret.is_empty();
            let mut cfg = cfg;
            cfg.client_secret.clear();
            Json(Redacted { cfg, secret_set }).into_response()
        }
        Err(e) => err(StatusCode::BAD_REQUEST, e),
    })
}

/// The short-lived cookie binding a sign-in attempt to the browser that started it (M9: login
/// CSRF - see `sso.rs`'s module docs). `SameSite=Lax`, not `Strict`: it must still be sent on the
/// top-level, cross-site GET the identity provider issues to bring the browser back to `callback`.
const SSO_COOKIE: &str = "denis_sso";

fn sso_cookie(value: &str, secure: bool, clear: bool) -> HeaderValue {
    let mut c = format!("{SSO_COOKIE}={value}; HttpOnly; SameSite=Lax; Path=/api/auth/sso");
    c.push_str(if clear { "; Max-Age=0" } else { "; Max-Age=600" });
    if secure {
        c.push_str("; Secure");
    }
    HeaderValue::from_str(&c).expect("cookie is ASCII")
}

/// Start a sign-in: redirect to the identity provider.
pub(crate) async fn login(State(st): State<AppState>, headers: axum::http::HeaderMap) -> Result<Response, ApiError> {
    let redirect = redirect_url(&st, &headers);
    let res = blocking(&st.store, move |s| {
        let cfg = crate::sso::load(s)?;
        Ok(crate::sso::start(&cfg, &redirect))
    })
    .await?;
    Ok(match res {
        Ok((url, browser_token)) => {
            let mut r = Redirect::to(&url).into_response();
            r.headers_mut().insert(header::SET_COOKIE, sso_cookie(&browser_token, st.secure_cookie, false));
            r
        }
        Err(e) => err(StatusCode::BAD_REQUEST, format!("{e:#}")),
    })
}

#[derive(Deserialize)]
pub struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

/// The identity provider sending the browser back with (usually) a code to exchange, or an error.
pub(crate) async fn callback(State(st): State<AppState>, Query(q): Query<CallbackQuery>, headers: axum::http::HeaderMap) -> Result<Response, ApiError> {
    // Single-use regardless of outcome: whatever happens below, this browser's sign-in attempt is
    // over, so the cookie that bound it is cleared on every response this handler returns.
    let clear_sso_cookie = sso_cookie("", st.secure_cookie, true);
    let with_cleared_cookie = |mut r: Response| {
        // `append`, not `insert`: the success path already sets the session cookie, and Set-Cookie
        // is one of the few headers a browser expects to see repeated, not replaced.
        r.headers_mut().append(header::SET_COOKIE, clear_sso_cookie.clone());
        r
    };
    if let Some(e) = q.error {
        return Ok(with_cleared_cookie(sso_failed(&format!("{e}: {}", q.error_description.unwrap_or_default()))));
    }
    let (Some(code), Some(state)) = (q.code, q.state) else {
        return Ok(with_cleared_cookie(sso_failed("the identity provider did not send back a code")));
    };
    let browser_token = headers
        .get(header::COOKIE)
        .and_then(|h| h.to_str().ok())
        .and_then(|c| c.split(';').map(str::trim).find_map(|kv| kv.strip_prefix(&format!("{SSO_COOKIE}="))))
        .unwrap_or("")
        .to_string();
    let redirect = redirect_url(&st, &headers);
    let identity = blocking(&st.store, move |s| {
        let cfg = crate::sso::load(s)?;
        Ok(crate::sso::finish(&cfg, &redirect, &code, &state, &browser_token))
    })
    .await?;
    let identity = match identity {
        Ok(i) => i,
        Err(e) => return Ok(with_cleared_cookie(sso_failed(&format!("{e:#}")))),
    };
    let auth = st.auth.clone();
    let (issuer, sub, email) = (identity.issuer.clone(), identity.sub.clone(), identity.email.clone());
    let login = tokio::task::spawn_blocking(move || auth.sso_login(&issuer, &sub, &email, now_ts())).await;
    match login {
        Ok(Ok((token, user, created))) => {
            audit(&st, &user.username, if created { "sso.provisioned" } else { "sso.login" }, None, json!({}));
            let mut r = Redirect::to("/").into_response();
            r.headers_mut().insert(header::SET_COOKIE, cookie(&token, st.secure_cookie, None));
            Ok(with_cleared_cookie(r))
        }
        Ok(Err(crate::auth::AuthError::Invalid)) => Ok(sso_failed(&format!("the account for {} is disabled", identity.email))),
        Ok(Err(crate::auth::AuthError::Rejected(m))) => Ok(sso_failed(&format!("signed in as {}, but: {m}", identity.email))),
        Ok(Err(_)) => Ok(err(StatusCode::INTERNAL_SERVER_ERROR, "internal error")),
        Err(_) => Ok(err(StatusCode::INTERNAL_SERVER_ERROR, "internal error")),
    }
}

/// A plain page rather than a JSON error: this is a top-level browser navigation, not a script's
/// `fetch`, so there is no console page open yet to show a toast in.
fn sso_failed(reason: &str) -> Response {
    let body = format!(
        "<!doctype html><html><body style=\"font:14px system-ui;max-width:32em;margin:3em auto\">\
         <h3>Sign-in did not complete</h3><p>{}</p><p><a href=\"/\">Back to DENIS</a></p></body></html>",
        html_escape(reason)
    );
    (StatusCode::BAD_REQUEST, [(header::CONTENT_TYPE, "text/html; charset=utf-8")], body).into_response()
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}
