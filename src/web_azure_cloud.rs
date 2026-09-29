//! Azure cloud asset discovery HTTP handlers: an administrator's Azure app registration
//! credentials and subscription, on-demand sync. See `azure_cloud.rs` for the actual API calls and
//! matching logic — this file is only the HTTP surface over it, same split as `web_jamf.rs` is to
//! `jamf.rs`. The imported device list itself is shared with the other CMDB sources and stays at
//! `GET /api/cmdb/devices` — there is no separate `/api/azure/devices`.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Extension;
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::azure_cloud::Settings;
use crate::model::now_ts;
use crate::web::common::{blocking, ApiError, AppState, AuthUser};
use crate::web_admin::{audit, err};

#[derive(Serialize)]
pub struct SettingsResp {
    #[serde(flatten)]
    pub settings: Settings,
    /// Never the secret itself — only whether one is already saved, same convention as every
    /// other stored credential in this codebase.
    pub client_secret_set: bool,
}

pub(crate) async fn get(State(st): State<AppState>) -> Result<Json<SettingsResp>, ApiError> {
    let (settings, secret) = blocking(&st.store, |s| Ok((crate::azure_cloud::settings(s), crate::azure_cloud::client_secret(s)))).await?;
    Ok(Json(SettingsResp { settings, client_secret_set: secret.is_some() }))
}

#[derive(Deserialize)]
pub struct PutReq {
    #[serde(flatten)]
    settings: Settings,
    /// Blank/absent: leave the stored secret as it is (it is never sent back to the browser to
    /// round-trip, so the form always submits this blank unless the admin actually typed a new one).
    #[serde(default)]
    client_secret: String,
}

pub(crate) async fn put(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Json(b): Json<PutReq>) -> Result<Response, ApiError> {
    if b.settings.enabled && (b.settings.tenant_id.trim().is_empty() || b.settings.client_id.trim().is_empty() || b.settings.subscription_id.trim().is_empty()) {
        return Ok(err(StatusCode::BAD_REQUEST, "tenant id, client id and subscription id are required to enable this"));
    }
    if !(1..=24 * 30).contains(&b.settings.sync_interval_hours) {
        return Ok(err(StatusCode::BAD_REQUEST, "sync interval must be between 1 hour and 30 days"));
    }
    let now = now_ts();
    blocking(&st.store, move |s| {
        crate::azure_cloud::save_settings(s, &b.settings, now)?;
        if !b.client_secret.is_empty() {
            crate::azure_cloud::save_client_secret(s, &b.client_secret, now)?;
        }
        Ok(())
    })
    .await?;
    audit(&st, &me.username, "azure.settings.update", None, json!({}));
    let (settings, secret) = blocking(&st.store, |s| Ok((crate::azure_cloud::settings(s), crate::azure_cloud::client_secret(s)))).await?;
    Ok(Json(SettingsResp { settings, client_secret_set: secret.is_some() }).into_response())
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
    let result = tokio::task::spawn_blocking(move || crate::azure_cloud::sync_now(&*store, now)).await;
    let resp = match result {
        Ok(Ok(n)) => {
            audit(&st, &me.username, "azure.sync", None, json!({"ok": true, "imported": n}));
            SyncResp { ok: true, imported: Some(n), error: None }
        }
        Ok(Err(e)) => {
            audit(&st, &me.username, "azure.sync", None, json!({"ok": false, "error": e.to_string()}));
            SyncResp { ok: false, imported: None, error: Some(format!("{e:#}")) }
        }
        Err(_) => SyncResp { ok: false, imported: None, error: Some("internal error".to_string()) },
    };
    Ok(Json(resp).into_response())
}
