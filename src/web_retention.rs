//! General data-retention setting (Settings → Data retention). See `retention.rs`.

use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

use crate::model::now_ts;
use crate::retention::{self, Settings};
use crate::web::common::{blocking, ApiError, AppState, AuthUser};
use crate::web_admin::{audit, err};

pub(crate) async fn get(State(st): State<AppState>) -> Result<Json<Settings>, ApiError> {
    let cli_default = st.shared.cli_retention_days;
    let days = blocking(&st.store, move |s| Ok(retention::effective_days(s, cli_default))).await?;
    Ok(Json(Settings { days }))
}

pub(crate) async fn put(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Json(b): Json<Settings>) -> Result<Response, ApiError> {
    if let Err(e) = b.validate() {
        return Ok(err(StatusCode::BAD_REQUEST, e.to_string()));
    }
    let days = b.days;
    blocking(&st.store, move |s| retention::save(s, &b, now_ts())).await?;
    audit(&st, &me.username, "retention.settings", None, json!({ "days": days }));
    Ok(StatusCode::NO_CONTENT.into_response())
}
