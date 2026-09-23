//! What DENIS knows about end-of-support dates and known-exploited vulnerabilities, and the switch for refreshing the dates.

use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use crate::model::now_ts;
use crate::vulndata::{self, Settings};
use crate::web::common::{blocking, ApiError, AppState, AuthUser};
use crate::web_admin::audit;

pub(crate) async fn status(State(st): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    let s = blocking(&st.store, |s| Ok(vulndata::settings(s))).await?;
    let i = vulndata::current();
    Ok(Json(json!({
        "generated": i.data.generated,
        "kev_catalog_version": i.data.kev_catalog_version,
        "kev_entries": i.data.kev.len(),
        "products": i.products(),
        "refreshed_at": i.refreshed_at,
        "refresh_eol": s.refresh_eol,
    })))
}

#[derive(Deserialize)]
pub(crate) struct PutReq {
    refresh_eol: bool,
}

pub(crate) async fn put(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Json(b): Json<PutReq>) -> Result<Response, ApiError> {
    let s = Settings { refresh_eol: b.refresh_eol };
    blocking(&st.store, move |st| vulndata::save_settings(st, &s, now_ts())).await?;
    audit(&st, &me.username, "vulndata.settings", None, json!({ "refresh_eol": b.refresh_eol }));
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Fetch fresh support dates from endoflife.date now (administrators). Says which products could not be fetched.
pub(crate) async fn refresh(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>) -> Result<Response, ApiError> {
    let out = blocking(&st.store, |s| Ok(vulndata::refresh_now(s, vulndata::EOL_URL, now_ts()).map_err(|e| format!("{e:#}")))).await?;
    audit(&st, &me.username, "vulndata.refresh", None, json!({ "ok": out.is_ok() }));
    Ok(match out {
        Ok((n, failed)) => Json(json!({ "ok": true, "refreshed": n, "failed": failed })).into_response(),
        Err(e) => Json(json!({ "ok": false, "error": e })).into_response(),
    })

}
