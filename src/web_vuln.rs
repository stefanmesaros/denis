//! What DENIS knows about end-of-support dates and known-exploited vulnerabilities, and the switch for refreshing the dates.

use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use crate::model::now_ts;
use crate::vulndata::{self, Kev, Settings};
use crate::web::common::{blocking, ApiError, AppState, AuthUser};
use crate::web_admin::{audit, err};

pub(crate) async fn status(State(st): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    let (s, custom, live) = blocking(&st.store, |s| Ok((vulndata::settings(s), vulndata::custom_kev(s), vulndata::kev_live(s)))).await?;
    let i = vulndata::current();
    Ok(Json(json!({
        "generated": i.data.generated,
        "kev_catalog_version": i.data.kev_catalog_version,
        "kev_entries": i.data.kev.len(),
        "products": i.products(),
        "refreshed_at": i.refreshed_at,
        "refresh_eol": s.refresh_eol,
        "refresh_kev": s.refresh_kev,
        "custom_kev": custom,
        "known_products": vulndata::KNOWN_PRODUCTS,
        "kev_live_count": live.kev.len(),
        "kev_live_fetched_at": if live.fetched_at > 0 { Some(live.fetched_at) } else { None },
        "kev_live_catalog_version": live.catalog_version,
    })))
}

#[derive(Deserialize)]
pub(crate) struct PutReq {
    refresh_eol: bool,
    #[serde(default)]
    refresh_kev: bool,
}

pub(crate) async fn put(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Json(b): Json<PutReq>) -> Result<Response, ApiError> {
    let s = Settings { refresh_eol: b.refresh_eol, refresh_kev: b.refresh_kev };
    blocking(&st.store, move |st| vulndata::save_settings(st, &s, now_ts())).await?;
    audit(&st, &me.username, "vulndata.settings", None, json!({ "refresh_eol": b.refresh_eol, "refresh_kev": b.refresh_kev }));
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

/// Fetch known-exploited vulnerabilities from CISA's KEV catalog now, look up their affected
/// version ranges on NVD, and their EPSS score (administrators). Takes a while — NVD is fetched
/// once per matched CVE, paced to its rate limit — so this runs to completion before answering.
pub(crate) async fn kev_refresh(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>) -> Result<Response, ApiError> {
    let now = now_ts();
    let out = tokio::task::spawn_blocking(move || vulndata::fetch_kev_live(vulndata::KEV_URL, vulndata::NVD_URL, vulndata::EPSS_URL, vulndata::NVD_PACE, now))
        .await
        .map_err(|e| anyhow::anyhow!(e))?;
    let out = match out {
        Ok((live, failed)) => {
            let n = live.kev.len();
            blocking(&st.store, move |s| vulndata::save_kev_live(s, &live, now)).await?;
            Ok((n, failed))
        }
        Err(e) => Err(format!("{e:#}")),
    };
    audit(&st, &me.username, "vulndata.kev_refresh", None, json!({ "ok": out.is_ok() }));
    Ok(match out {
        Ok((n, failed)) => Json(json!({ "ok": true, "matched": n, "skipped": failed })).into_response(),
        Err(e) => Json(json!({ "ok": false, "error": e })).into_response(),
    })
}

/// Replace the whole list of administrator-entered CVEs (Settings → Software data → Custom
/// CVEs). Matched against service banners exactly like the bundled/refreshed data.
pub(crate) async fn custom_put(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Json(list): Json<Vec<Kev>>) -> Result<Response, ApiError> {
    let n = list.len();
    match blocking(&st.store, move |s| Ok(vulndata::save_custom_kev(s, &list, now_ts()).map_err(|e| format!("{e:#}")))).await? {
        Ok(()) => {
            audit(&st, &me.username, "vulndata.custom", None, json!({ "count": n }));
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        Err(e) => Ok(err(StatusCode::BAD_REQUEST, e)),
    }
}
