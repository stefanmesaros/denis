//! SIEM / log export settings (Settings → SIEM / Log export): syslog in CEF, LEEF or JSON, over
//! UDP, TCP or TLS, with events/findings/audit sent independently. See `syslog.rs`.

use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use crate::model::now_ts;
use crate::syslog::{self, Settings, Streams};
use crate::web::common::{blocking, ApiError, AppState, AuthUser};
use crate::web_admin::{audit, err};

pub(crate) async fn get(State(st): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    Ok(Json(blocking(&st.store, |s| syslog::load(s)).await?.masked()))
}

pub(crate) async fn put(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Json(body): Json<serde_json::Value>) -> Result<Response, ApiError> {
    let existing = blocking(&st.store, |s| syslog::load(s)).await?;
    let b = match syslog::from_body(&body, &existing) {
        Ok(b) => b,
        Err(e) => return Ok(err(StatusCode::BAD_REQUEST, e)),
    };
    if let Err(e) = b.validate() {
        return Ok(err(StatusCode::BAD_REQUEST, e));
    }
    let audit_body = json!({ "enabled": b.enabled, "transport": b.transport, "format": b.format, "streams": b.streams });
    blocking(&st.store, move |s| syslog::save(s, &b, now_ts())).await?;
    audit(&st, &me.username, "siem.settings", None, audit_body);
    Ok(StatusCode::NO_CONTENT.into_response())
}

#[derive(Deserialize)]
pub(crate) struct TestReq {
    transport: String,
    host: String,
    port: u16,
    format: String,
    #[serde(default)]
    insecure_tls: bool,
    #[serde(default)]
    api_key: Option<String>,
    #[serde(default)]
    index: String,
}

/// Send one message right now with whatever is in the form, bypassing settings entirely — so an
/// administrator can check a target before saving it (or without ever saving it).
pub(crate) async fn test(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Json(b): Json<TestReq>) -> Result<Response, ApiError> {
    let probe = Settings {
        enabled: true, transport: b.transport, host: b.host, port: b.port, format: b.format,
        streams: Streams { events: true, findings: false, audit: false }, insecure_tls: b.insecure_tls,
        api_key: b.api_key, index: b.index,
    };
    if let Err(e) = probe.validate() {
        return Ok(err(StatusCode::BAD_REQUEST, e));
    }
    let hostname = crate::net::local_hostname().unwrap_or_default();
    let out = tokio::task::spawn_blocking(move || syslog::send_test(&probe.config(), &hostname)).await.map_err(|e| anyhow::anyhow!(e))?;
    audit(&st, &me.username, "siem.test", None, json!({ "ok": out.is_ok() }));
    Ok(match out {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => Json(json!({ "ok": false, "error": format!("{e:#}") })).into_response(),
    })
}
