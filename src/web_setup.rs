//! The setup guide: what a new installation still needs, worked out from what is really configured
//! (so the checklist is always true), and whether an administrator has finished with it.
//!
//! The guide opens by itself for an administrator until somebody marks it done; it can be opened again
//! from Settings at any time.

use std::collections::BTreeMap;

use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::model::now_ts;
use crate::store::Store;
use crate::web::common::{blocking, ApiError, AppState, AuthUser};
use crate::web_admin::audit;

const KEY: &str = "setup_guide";

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Progress {
    /// When an administrator marked the guide done (`None`: not yet).
    pub completed_at: Option<i64>,
    pub completed_by: Option<String>,
}

pub fn load(store: &dyn Store) -> anyhow::Result<Progress> {
    Ok(store.get_setting(KEY)?.and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default())
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Step {
    pub id: &'static str,
    pub done: bool,
    /// Numbers and names the console puts into the step's sentence.
    pub vars: BTreeMap<&'static str, String>,
}

/// What the steps are judged by.
pub struct Facts {
    pub devices: usize,
    pub sweep_done: bool,
    pub passive_only: bool,
    pub capture_running: bool,
    pub viewer: bool,
    pub interface: String,
    pub subnet: String,
    pub admins: usize,
    pub admins_with_mfa: usize,
    pub channels: usize,
    pub exports: usize,
    pub users: usize,
    pub backup_schedule: String,
    pub backups: usize,
    pub report_schedule: String,
    pub branded: bool,
}

fn v<const N: usize>(pairs: [(&'static str, String); N]) -> BTreeMap<&'static str, String> {
    pairs.into_iter().collect()
}

pub fn steps(f: &Facts) -> Vec<Step> {
    vec![
        Step {
            id: "network",
            // a passive-only collector never sweeps: seeing devices is what tells it works
            done: f.devices > 0 && (f.sweep_done || f.passive_only) && (f.capture_running || f.viewer),
            vars: v([("interface", f.interface.clone()), ("subnet", f.subnet.clone()), ("devices", f.devices.to_string())]),
        },
        Step { id: "security", done: f.admins > 0 && f.admins_with_mfa >= f.admins, vars: v([("a", f.admins_with_mfa.to_string()), ("b", f.admins.to_string())]) },
        Step { id: "alerts", done: f.channels + f.exports > 0, vars: v([("channels", f.channels.to_string()), ("exports", f.exports.to_string())]) },
        Step { id: "people", done: f.users > 1, vars: v([("users", f.users.to_string())]) },
        Step {
            id: "backups",
            done: f.backup_schedule != "off" || f.backups > 0,
            vars: v([("schedule", f.backup_schedule.clone()), ("reports", f.report_schedule.clone()), ("backups", f.backups.to_string())]),
        },
        Step { id: "branding", done: f.branded, vars: BTreeMap::new() },
    ]
}

fn gather(store: &dyn Store, st: &AppState) -> anyhow::Result<serde_json::Value> {
    let info = st.shared.snapshot();
    let users = store.list_users()?;
    let admins: Vec<_> = users.iter().filter(|u| u.role == "admin" && !u.disabled).collect();
    // a second step: a passkey or an authenticator app
    let totp = store.totp_enabled_users()?;
    let mut with_passkey = 0;
    for a in &admins {
        if totp.contains(&a.id) || !store.list_passkeys(a.id)?.is_empty() {
            with_passkey += 1;
        }
    }
    let brand = crate::branding::load(store)?;
    let bs = crate::backups::load(store)?;
    let facts = Facts {
        devices: crate::store::real_assets(store)?.len(),
        sweep_done: info.last_sweep_finished.is_some(),
        passive_only: info.passive_only,
        capture_running: st.shared.capture_stats.running.load(std::sync::atomic::Ordering::Relaxed),
        viewer: info.mode == "viewer",
        interface: info.interface.clone(),
        subnet: info.subnet.clone(),
        admins: admins.len(),
        admins_with_mfa: with_passkey,
        channels: crate::channels::load(store)?.iter().filter(|c| c.enabled).count(),
        exports: info.exports.len(),
        users: users.iter().filter(|u| !u.disabled).count(),
        backup_schedule: bs.schedule.clone(),
        backups: crate::backups::list(&st.shared.db_path).len(),
        report_schedule: crate::reports::load(store)?.schedule,
        branded: brand != crate::branding::Branding::default() || crate::branding::load_logo(store)?.is_some(),
    };
    let progress = load(store)?;
    Ok(json!({ "completed": progress.completed_at.is_some(), "completed_at": progress.completed_at, "completed_by": progress.completed_by, "steps": steps(&facts) }))
}

pub(crate) async fn get(State(st): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    let st2 = st.clone();
    Ok(Json(blocking(&st.store, move |s| gather(s, &st2)).await?))
}

#[derive(Deserialize)]
pub(crate) struct Put {
    completed: bool,
}

/// Mark the guide done (it stops opening by itself) or not done (it opens again at the next sign-in).
pub(crate) async fn put(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Json(b): Json<Put>) -> Result<Response, ApiError> {
    let now = now_ts();
    let progress = if b.completed { Progress { completed_at: Some(now), completed_by: Some(me.username.clone()) } } else { Progress::default() };
    let p2 = progress.clone();
    blocking(&st.store, move |s| s.set_setting(KEY, &serde_json::to_vec(&p2)?, now)).await?;
    audit(&st, &me.username, "setup.guide", None, json!({ "completed": b.completed }));
    Ok((StatusCode::OK, Json(progress)).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts() -> Facts {
        Facts {
            devices: 0, sweep_done: false, passive_only: false, capture_running: false, viewer: false, interface: "eth0".into(), subnet: "192.168.1.0/24".into(),
            admins: 1, admins_with_mfa: 0, channels: 0, exports: 0, users: 1, backup_schedule: "off".into(), backups: 0, report_schedule: "off".into(), branded: false,
        }
    }

    fn done(f: &Facts) -> Vec<(&'static str, bool)> {
        steps(f).into_iter().map(|s| (s.id, s.done)).collect()
    }

    #[test]
    fn a_fresh_install_has_everything_still_to_do() {
        assert!(done(&facts()).iter().all(|(_, d)| !d));
        assert_eq!(steps(&facts()).len(), 6);
    }

    #[test]
    fn each_step_is_judged_by_what_is_really_configured() {
        let mut f = facts();
        f.devices = 12;
        f.sweep_done = true;
        assert!(!done(&f)[0].1, "devices but the capture is not running");
        f.capture_running = true;
        assert!(done(&f)[0].1);
        f.sweep_done = false;
        assert!(!done(&f)[0].1, "no sweep yet");
        f.passive_only = true;
        assert!(done(&f)[0].1, "passive only never sweeps");
        f.admins_with_mfa = 1;
        f.channels = 1;
        f.users = 2;
        f.backup_schedule = "daily".into();
        f.branded = true;
        assert!(done(&f).iter().all(|(_, d)| *d));
        // an export counts as a way to be told; an admin without a passkey among two is not "secure"
        let mut g = facts();
        g.exports = 1;
        g.admins = 2;
        g.admins_with_mfa = 1;
        assert_eq!((done(&g)[1].1, done(&g)[2].1), (false, true));
        // a backup on disk counts even if the schedule was switched off afterwards
        let mut h = facts();
        h.backups = 1;
        assert!(done(&h)[4].1);
    }
}
