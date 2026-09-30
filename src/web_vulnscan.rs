//! Vulnerability-scanner import HTTP handlers: an administrator's Nessus/Tenable API keys,
//! on-demand sync, and the imported findings list. See `vulnscan.rs` for the actual API calls and
//! matching logic — this file is only the HTTP surface over it, same split as `web_jamf.rs` is to
//! `jamf.rs`.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Extension;
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::model::now_ts;
use crate::vulnscan::Settings;
use crate::web::common::{blocking, ApiError, AppState, AuthUser};
use crate::web_admin::{audit, err};

#[derive(Serialize)]
pub struct SettingsResp {
    #[serde(flatten)]
    pub settings: Settings,
    /// Never the keys themselves — only whether each is already saved, same convention as every
    /// other stored credential in this codebase.
    pub access_key_set: bool,
    pub secret_key_set: bool,
}

pub(crate) async fn get(State(st): State<AppState>) -> Result<Json<SettingsResp>, ApiError> {
    let (settings, access, secret) = blocking(&st.store, |s| Ok((crate::vulnscan::settings(s), crate::vulnscan::access_key(s), crate::vulnscan::secret_key(s)))).await?;
    Ok(Json(SettingsResp { settings, access_key_set: access.is_some(), secret_key_set: secret.is_some() }))
}

#[derive(Deserialize)]
pub struct PutReq {
    #[serde(flatten)]
    settings: Settings,
    /// Blank/absent: leave the stored key as it is — never sent back to the browser to round-trip,
    /// so the form always submits these blank unless the admin actually typed a new one.
    #[serde(default)]
    access_key: String,
    #[serde(default)]
    secret_key: String,
}

pub(crate) async fn put(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Json(b): Json<PutReq>) -> Result<Response, ApiError> {
    if b.settings.enabled && b.settings.server_url.trim().is_empty() {
        return Ok(err(StatusCode::BAD_REQUEST, "the scanner's server URL is required to enable this"));
    }
    if !(1..=24 * 30).contains(&b.settings.sync_interval_hours) {
        return Ok(err(StatusCode::BAD_REQUEST, "sync interval must be between 1 hour and 30 days"));
    }
    let now = now_ts();
    blocking(&st.store, move |s| {
        // M3: a stored key is only ever safe to keep for the destination it was entered for - an
        // admin who changes server_url and leaves the key field blank must re-enter it, rather
        // than have it silently sent to whatever host now sits at server_url.
        let destination_changed = crate::vulnscan::settings(s).server_url.trim() != b.settings.server_url.trim();
        crate::vulnscan::save_settings(s, &b.settings, now)?;
        if !b.access_key.is_empty() {
            crate::vulnscan::save_access_key(s, &b.access_key, now)?;
        } else if destination_changed {
            crate::vulnscan::save_access_key(s, "", now)?;
        }
        if !b.secret_key.is_empty() {
            crate::vulnscan::save_secret_key(s, &b.secret_key, now)?;
        } else if destination_changed {
            crate::vulnscan::save_secret_key(s, "", now)?;
        }
        Ok(())
    })
    .await?;
    audit(&st, &me.username, "vulnscan.settings.update", None, json!({}));
    let (settings, access, secret) = blocking(&st.store, |s| Ok((crate::vulnscan::settings(s), crate::vulnscan::access_key(s), crate::vulnscan::secret_key(s)))).await?;
    Ok(Json(SettingsResp { settings, access_key_set: access.is_some(), secret_key_set: secret.is_some() }).into_response())
}

#[derive(Serialize)]
pub struct SyncResp {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    imported: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// Sync now: an administrator clicked the button rather than waiting for the periodic job.
pub(crate) async fn sync(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>) -> Result<Response, ApiError> {
    let now = now_ts();
    let store = st.store.clone();
    let result = tokio::task::spawn_blocking(move || crate::vulnscan::sync_now(&*store, now)).await;
    let resp = match result {
        Ok(Ok(n)) => {
            audit(&st, &me.username, "vulnscan.sync", None, json!({"ok": true, "imported": n}));
            SyncResp { ok: true, imported: Some(n), error: None }
        }
        Ok(Err(e)) => {
            audit(&st, &me.username, "vulnscan.sync", None, json!({"ok": false, "error": e.to_string()}));
            SyncResp { ok: false, imported: None, error: Some(format!("{e:#}")) }
        }
        Err(_) => SyncResp { ok: false, imported: None, error: Some("internal error".to_string()) },
    };
    Ok(Json(resp).into_response())
}

/// Every imported finding — read-only, any signed-in viewer, same access level as the CMDB
/// devices list (`GET /api/cmdb/devices`) it sits alongside.
pub(crate) async fn findings(State(st): State<AppState>) -> Result<Response, ApiError> {
    let findings = blocking(&st.store, |s| crate::vulnscan::list_vulns(s)).await?;
    Ok(Json(findings).into_response())
}
