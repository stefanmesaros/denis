//! The Health page and the backups it manages.

use axum::body::Body;
use axum::extract::{Extension, Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

use crate::backups::{self, Settings};
use crate::model::now_ts;
use crate::web::{blocking, ApiError, AppState, AuthUser};
use crate::web_admin::{audit, err};

const E_NO_BACKUP: &str = "no such backup";
const E_KEEP_UPDATE: &str = "backups made before an update are managed by the updater and cannot be deleted here";

/// Every fixed sentence of these endpoints and of the page, so the translation test can check them.
pub fn texts() -> Vec<&'static str> {
    let mut v = vec![E_NO_BACKUP, E_KEEP_UPDATE];
    v.extend(crate::health::texts());
    v
}

#[derive(serde::Deserialize)]
pub(crate) struct HealthQuery {
    /// `0` = skip the table row counts (the badge in the menu asks like this).
    rows: Option<u8>,
}

pub(crate) async fn health(State(st): State<AppState>, Query(q): Query<HealthQuery>) -> Result<Json<crate::health::Health>, ApiError> {
    let shared = st.shared.clone();
    let rows = q.rows != Some(0);
    Ok(Json(blocking(&st.store, move |s| crate::health::gather(s, &shared, now_ts(), rows)).await?))
}

pub(crate) async fn list(State(st): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    let path = st.shared.db_path.clone();
    let settings = blocking(&st.store, |s| backups::load(s)).await?;
    let upload_settings = blocking(&st.store, |s| backups::load_upload_settings(s)).await?;
    let agent_keep = blocking(&st.store, |s| Ok(backups::load_agent_keep(s))).await?;
    Ok(Json(json!({
        "backups": backups::list(&path),
        "settings": settings,
        // shown only when --backup-upstream is actually configured: the schedule otherwise
        // decides nothing
        "upload_configured": st.shared.snapshot().backup_upstream_configured,
        "upload_settings": upload_settings,
        // an MSP's own setting: how many of each customer's uploaded backups to keep
        "agent_keep": agent_keep,
    })))
}

#[derive(serde::Deserialize)]
pub struct AgentKeepReq {
    keep: u32,
}

/// How many of a given customer's uploaded backups this MSP keeps under
/// `backups/from-agents/<agent-id>/` (see `backups::AGENT_KEEP_KEY`) — purely local to this
/// install, never reaches back to any customer.
pub(crate) async fn agent_keep_put(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Json(b): Json<AgentKeepReq>) -> Result<Response, ApiError> {
    if !(1..=backups::MAX_KEEP).contains(&b.keep) {
        return Ok(err(StatusCode::BAD_REQUEST, "keep must be between 1 and 60"));
    }
    blocking(&st.store, move |s| backups::save_agent_keep(s, b.keep, now_ts())).await?;
    audit(&st, &me.username, "backup.agent_keep", None, json!({ "keep": b.keep }));
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// How often this install's own scheduled backups are also pushed to its configured
/// `--backup-upstream` (independent of the local schedule above; see `backups::UploadSettings`).
pub(crate) async fn upload_settings_put(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Json(b): Json<backups::UploadSettings>) -> Result<Response, ApiError> {
    if let Err(e) = b.validate() {
        return Ok(err(StatusCode::BAD_REQUEST, e));
    }
    let b2 = b.clone();
    blocking(&st.store, move |s| backups::save_upload_settings(s, &b2, now_ts())).await?;
    audit(&st, &me.username, "backup.upload_schedule", None, json!({ "schedule": b.schedule }));
    Ok(Json(b).into_response())
}

pub(crate) async fn make(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>) -> Result<Response, ApiError> {
    let path = st.shared.db_path.clone();
    let made = blocking(&st.store, move |s| backups::create(s, &path, "manual", now_ts())).await?;
    audit(&st, &me.username, "backup.create", None, json!({ "name": made.name, "size": made.size }));
    Ok((StatusCode::CREATED, Json(made)).into_response())
}

/// The file itself, streamed (a backup can be large).
pub(crate) async fn download(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Path(name): Path<String>) -> Result<Response, ApiError> {
    let Some(p) = backups::path_of(&st.shared.db_path, &name) else { return Ok(err(StatusCode::NOT_FOUND, E_NO_BACKUP)) };
    let file = tokio::fs::File::open(&p).await.map_err(|e| ApiError::from(anyhow::Error::new(e)))?;
    let len = file.metadata().await.map(|m| m.len()).unwrap_or(0);
    audit(&st, &me.username, "backup.download", None, json!({ "name": name }));
    Ok((
        [
            (header::CONTENT_TYPE, "application/vnd.sqlite3".to_string()),
            (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{name}\"")),
            (header::CONTENT_LENGTH, len.to_string()),
            (header::CACHE_CONTROL, "private, no-store".to_string()),
        ],
        Body::from_stream(tokio_util::io::ReaderStream::new(file)),
    )
        .into_response())
}

pub(crate) async fn remove(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Path(name): Path<String>) -> Result<Response, ApiError> {
    let Some(p) = backups::path_of(&st.shared.db_path, &name) else { return Ok(err(StatusCode::NOT_FOUND, E_NO_BACKUP)) };
    if name.starts_with("denis-before-") {
        return Ok(err(StatusCode::CONFLICT, E_KEEP_UPDATE));
    }
    tokio::fs::remove_file(&p).await.map_err(|e| ApiError::from(anyhow::Error::new(e)))?;
    audit(&st, &me.username, "backup.delete", None, json!({ "name": name }));
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Every customer's uploaded backups (`--backup-upstream` on their side), grouped by site — so an
/// MSP can find and download one without SSH access to this server, e.g. right after a customer
/// reports being hit by ransomware. Admin-only, like the local backups above: these files hold
/// other people's password hashes too.
pub(crate) async fn msp_backups_list(State(st): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    let path = st.shared.db_path.clone();
    let out = blocking(&st.store, move |s| {
        let names: std::collections::HashMap<String, String> = s.list_agents()?.into_iter().map(|a| (a.id, a.name)).collect();
        let sites: Vec<serde_json::Value> = backups::agent_ids_with_backups(&path)
            .into_iter()
            .map(|id| {
                let files = backups::list_agent_backups(&path, &id);
                json!({ "agent_id": id, "name": names.get(&id).cloned().unwrap_or_else(|| id.clone()), "backups": files })
            })
            .collect();
        Ok(sites)
    })
    .await?;
    Ok(Json(json!(out)))
}

/// One customer's backup file, streamed the same way a local one is.
pub(crate) async fn msp_backup_download(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Path((agent_id, name)): Path<(String, String)>) -> Result<Response, ApiError> {
    let Some(p) = backups::path_of_agent(&st.shared.db_path, &agent_id, &name) else { return Ok(err(StatusCode::NOT_FOUND, E_NO_BACKUP)) };
    let file = tokio::fs::File::open(&p).await.map_err(|e| ApiError::from(anyhow::Error::new(e)))?;
    let len = file.metadata().await.map(|m| m.len()).unwrap_or(0);
    audit(&st, &me.username, "msp_backup.download", None, json!({ "agent_id": agent_id, "name": name }));
    Ok((
        [
            (header::CONTENT_TYPE, "application/vnd.sqlite3".to_string()),
            (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{agent_id}-{name}\"")),
            (header::CONTENT_LENGTH, len.to_string()),
            (header::CACHE_CONTROL, "private, no-store".to_string()),
        ],
        Body::from_stream(tokio_util::io::ReaderStream::new(file)),
    )
        .into_response())
}

/// Removing one by hand — the automatic retention (`--backups/agent-keep`) usually does this, but
/// an administrator may want space back sooner.
pub(crate) async fn msp_backup_remove(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Path((agent_id, name)): Path<(String, String)>) -> Result<Response, ApiError> {
    let Some(p) = backups::path_of_agent(&st.shared.db_path, &agent_id, &name) else { return Ok(err(StatusCode::NOT_FOUND, E_NO_BACKUP)) };
    tokio::fs::remove_file(&p).await.map_err(|e| ApiError::from(anyhow::Error::new(e)))?;
    audit(&st, &me.username, "msp_backup.delete", None, json!({ "agent_id": agent_id, "name": name }));
    Ok(StatusCode::NO_CONTENT.into_response())
}

pub(crate) async fn settings_put(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Json(b): Json<Settings>) -> Result<Response, ApiError> {
    if let Err(e) = b.validate() {
        return Ok(err(StatusCode::BAD_REQUEST, e));
    }
    let b2 = b.clone();
    blocking(&st.store, move |s| backups::save(s, &b2, now_ts())).await?;
    // a shorter list of scheduled backups takes effect at once
    backups::prune_auto(&st.shared.db_path, b.keep as usize);
    audit(&st, &me.username, "backup.schedule", None, json!({ "schedule": b.schedule, "keep": b.keep }));
    Ok(Json(b).into_response())
}
