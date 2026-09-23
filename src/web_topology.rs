//! The physical topology and the list of switches it is read from.

use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use crate::model::now_ts;
use crate::switches::{self, Target};
use crate::web::common::{blocking, ApiError, AppState, AuthUser};
use crate::web_admin::{audit, err};

const E_NO_SWITCH: &str = "no such switch";

/// Every fixed sentence of these endpoints, so the translation test can check them.
pub fn texts() -> [&'static str; 1] {
    [E_NO_SWITCH]
}

/// Switches, links between them and where each known device is plugged in.
pub(crate) async fn topology(State(st): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    let (topo, cfg) = blocking(&st.store, |s| {
        let cfg = switches::load(s)?;
        let polled = switches::polled(s, &cfg)?;
        Ok((crate::topology::build(&polled, &s.load_assets()?), cfg))
    })
    .await?;
    let mut v = serde_json::to_value(topo)?;
    v["configured"] = (!cfg.targets.is_empty()).into();
    Ok(Json(v))
}

/// The list, without any community; what the last poll of each said.
pub(crate) async fn list(State(st): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    let (cfg, polled) = blocking(&st.store, |s| {
        let cfg = switches::load(s)?;
        let polled = switches::polled(s, &cfg)?;
        Ok((cfg, polled))
    })
    .await?;
    let targets: Vec<serde_json::Value> = cfg
        .targets
        .iter()
        .zip(polled.iter())
        .map(|(t, p)| {
            json!({
                "id": t.id, "name": t.name, "address": t.address, "enabled": t.enabled, "has_community": !t.community.is_empty(),
                "last_ok": p.last_ok, "error": p.error,
                "ports": p.snapshot.as_ref().map(|s| s.ports.len()), "neighbors": p.snapshot.as_ref().map(|s| s.lldp.len()), "macs": p.snapshot.as_ref().map(|s| s.fdb.len()),
            })
        })
        .collect();
    Ok(Json(json!({ "interval_secs": cfg.interval_secs, "targets": targets })))
}

#[derive(Deserialize)]
pub(crate) struct PutReq {
    interval_secs: Option<u64>,
    targets: Vec<Target>,
}

pub(crate) async fn put(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Json(b): Json<PutReq>) -> Result<Response, ApiError> {
    let (interval, targets) = (b.interval_secs, b.targets);
    let outcome = blocking(&st.store, move |s| {
        let mut cfg = switches::load(s)?;
        Ok(match cfg.update(interval, &targets) {
            Ok(()) => {
                switches::save(s, &cfg, now_ts())?;
                Ok(cfg)
            }
            Err(e) => Err(e),
        })
    })
    .await?;
    match outcome {
        Ok(cfg) => {
            // the communities are secrets: only names and addresses go in the audit log
            let names: Vec<serde_json::Value> = cfg.targets.iter().map(|t| json!({ "name": t.name, "address": t.address, "enabled": t.enabled })).collect();
            audit(&st, &me.username, "switches.update", None, json!({ "interval_secs": cfg.interval_secs, "switches": names }));
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        Err(e) => Ok(err(StatusCode::BAD_REQUEST, e)),
    }
}

/// Read one switch now (administrators): the answer says what was found, or why not.
pub(crate) async fn poll_now(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Path(id): Path<String>) -> Result<Response, ApiError> {
    let target = blocking(&st.store, move |s| Ok(switches::load(s)?.targets.into_iter().find(|t| t.id == id))).await?;
    let Some(target) = target else { return Ok(err(StatusCode::NOT_FOUND, E_NO_SWITCH)) };
    let out = switches::poll_and_store(&st.store, &target, now_ts()).await;
    audit(&st, &me.username, "switches.poll", None, json!({ "name": target.name, "ok": out.is_ok() }));
    Ok(Json(match out {
        Ok(s) => json!({ "ok": true, "ports": s.ports.len(), "neighbors": s.lldp.len(), "macs": s.fdb.len(), "sys_name": s.sys_name }),
        Err(e) => json!({ "ok": false, "error": e }),
    })
    .into_response())
}
