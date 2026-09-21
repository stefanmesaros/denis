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
    Ok(Json(json!({ "backups": backups::list(&path), "settings": settings })))
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
