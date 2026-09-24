//! The Reports page: list, make, view, download, delete, and the schedule.

use axum::extract::{Extension, Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use crate::model::now_ts;
use crate::reports::{self, Settings};
use crate::web::common::{blocking, ApiError, AppState, AuthUser};
use crate::web_admin::{audit, err};

const E_DAYS: &str = "a report covers 1 to 365 days";
const E_NO_REPORT: &str = "no such report";

/// Every fixed sentence of these endpoints, so the translation test can check them.
pub fn texts() -> [&'static str; 2] {
    [E_DAYS, E_NO_REPORT]
}

pub(crate) async fn list(State(st): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    let (items, settings, shares) = blocking(&st.store, |s| Ok((s.list_reports()?, reports::load(s)?, reports::load_shares(s)?))).await?;
    let total: i64 = items.iter().map(|r| r.size).sum();
    let items: Vec<_> = items.into_iter().map(|m| { let t = shares.get(&m.id).cloned(); let mut v = serde_json::to_value(&m).unwrap(); v["share_token"] = json!(t); v }).collect();
    Ok(Json(json!({ "reports": items, "settings": settings, "total_bytes": total })))
}

#[derive(Deserialize)]
pub(crate) struct MakeReq {
    days: Option<i64>,
}

pub(crate) async fn make(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Json(b): Json<MakeReq>) -> Result<Response, ApiError> {
    let days = b.days.unwrap_or(7);
    if !(1..=365).contains(&days) {
        return Ok(err(StatusCode::BAD_REQUEST, E_DAYS));
    }
    let shared = st.shared.clone();
    let by = me.username.clone();
    let meta = blocking(&st.store, move |s| reports::generate(s, &shared, "manual", days, &by, now_ts())).await?;
    audit(&st, &me.username, "report.create", None, json!({ "id": meta.id, "days": days }));
    Ok((StatusCode::CREATED, Json(meta)).into_response())
}

#[derive(Deserialize)]
pub(crate) struct ViewQuery {
    download: Option<u8>,
}

/// The rendered page and its headers, shared by the signed-in view and the public shared-link
/// view: identical content and CSP either way, since a report is a frozen, self-contained page
/// that carries no script and cannot be edited from here regardless of who is looking at it.
fn report_response(meta: &crate::model::ReportMeta, body: Vec<u8>, download: bool) -> Response {
    let disposition = if download {
        format!("attachment; filename=\"denis-report-{}-{}.html\"", crate::report::day(meta.created_at), meta.id)
    } else {
        "inline".to_string()
    };
    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8".to_string()),
            (header::CONTENT_DISPOSITION, disposition),
            (header::CONTENT_SECURITY_POLICY, "default-src 'none'; style-src 'unsafe-inline'; img-src data:; frame-ancestors 'self'; base-uri 'none'".to_string()),
            (header::CACHE_CONTROL, "private, no-store".to_string()),
        ],
        body,
    )
        .into_response()
}

/// The saved page itself. It carries its own styles, so it gets its own strict CSP (no script, ever).
pub(crate) async fn view(State(st): State<AppState>, Path(id): Path<i64>, Query(q): Query<ViewQuery>) -> Result<Response, ApiError> {
    let Some((meta, body)) = blocking(&st.store, move |s| s.get_report(id)).await? else {
        return Ok(err(StatusCode::NOT_FOUND, E_NO_REPORT));
    };
    Ok(report_response(&meta, body, q.download == Some(1)))
}

/// The same report, reached with a share token instead of a session: no `Extension<AuthUser>`,
/// so this is only ever wired up as a public route (see `is_public`). A token that does not
/// currently name a shared report -- wrong, revoked, or the report itself was deleted -- gets the
/// same 404 either way, so a guess cannot tell those apart.
pub(crate) async fn shared_view(State(st): State<AppState>, Path(token): Path<String>, Query(q): Query<ViewQuery>) -> Result<Response, ApiError> {
    let t = token.clone();
    let Some(id) = blocking(&st.store, move |s| reports::report_id_for_token(s, &t)).await? else {
        return Ok(err(StatusCode::NOT_FOUND, E_NO_REPORT));
    };
    let Some((meta, body)) = blocking(&st.store, move |s| s.get_report(id)).await? else {
        return Ok(err(StatusCode::NOT_FOUND, E_NO_REPORT));
    };
    Ok(report_response(&meta, body, q.download == Some(1)))
}

pub(crate) async fn remove(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Path(id): Path<i64>) -> Result<Response, ApiError> {
    if !blocking(&st.store, move |s| s.delete_report(id)).await? {
        return Ok(err(StatusCode::NOT_FOUND, E_NO_REPORT));
    }
    let now = now_ts();
    let _ = blocking(&st.store, move |s| reports::unshare(s, id, now)).await;
    audit(&st, &me.username, "report.delete", None, json!({ "id": id }));
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Turn sharing on for a report (idempotent: a second call returns the same link) or off.
/// Admin-only (see `required_role`): this is the one thing on the Reports page that makes data
/// reachable by someone who cannot sign in at all.
pub(crate) async fn share_put(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Path(id): Path<i64>) -> Result<Response, ApiError> {
    if blocking(&st.store, move |s| s.get_report(id)).await?.is_none() {
        return Ok(err(StatusCode::NOT_FOUND, E_NO_REPORT));
    }
    let now = now_ts();
    let token = blocking(&st.store, move |s| reports::share(s, id, now)).await?;
    audit(&st, &me.username, "report.share", None, json!({ "id": id }));
    Ok(Json(json!({ "share_token": token })).into_response())
}

pub(crate) async fn share_delete(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Path(id): Path<i64>) -> Result<Response, ApiError> {
    let now = now_ts();
    blocking(&st.store, move |s| reports::unshare(s, id, now)).await?;
    audit(&st, &me.username, "report.unshare", None, json!({ "id": id }));
    Ok(StatusCode::NO_CONTENT.into_response())
}

pub(crate) async fn settings_get(State(st): State<AppState>) -> Result<Json<Settings>, ApiError> {
    Ok(Json(blocking(&st.store, |s| reports::load(s)).await?))
}

pub(crate) async fn settings_put(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Json(b): Json<Settings>) -> Result<Response, ApiError> {
    if let Err(e) = b.validate() {
        return Ok(err(StatusCode::BAD_REQUEST, e));
    }
    let s2 = b.clone();
    blocking(&st.store, move |s| reports::save(s, &s2, now_ts())).await?;
    audit(&st, &me.username, "report.schedule", None, json!({ "schedule": b.schedule, "keep": b.keep, "days": b.days }));
    Ok(Json(b).into_response())
}
