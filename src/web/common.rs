//! What `web` (routing/handlers) and every `web_*` module (more handlers, grouped by
//! area) both need: request state, the auth extractor, error plumbing, and site-scoped
//! asset loading. Kept apart from `web.rs` so neither side of that split has to import
//! from the other — `web_*` modules depend on this file, `web.rs` depends on this file
//! and on them, and this file depends on neither.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

use axum::response::{IntoResponse, Response};
use axum::http::StatusCode;
use axum::Json;
use serde::Serialize;

use crate::auth::Auth;
use crate::engine::Shared;
use crate::model::{now_ts, Asset, AssetMeta, User};
use crate::risk::{self, Risk};
use crate::store::{EventQuery, Store};

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<dyn Store>,
    pub shared: Arc<Shared>,
    /// Bound to a loopback address: enforce Host-header checking.
    pub loopback_only: bool,
    /// Extra `Host` names accepted on a loopback bind (the public name a reverse
    /// proxy on this machine forwards). Anything else is refused: DNS rebinding.
    pub allowed_hosts: Vec<String>,
    pub auth: Arc<Auth>,
    /// Skip login entirely. Development and tests only; the engine refuses it
    /// on a non-loopback address.
    pub no_auth: bool,
    /// Mark the session cookie `Secure` (set when a TLS-terminating proxy is in front).
    pub secure_cookie: bool,
    /// What edition/cap is in force (see `license`). Defaults to the Community edition.
    pub license: crate::license::Effective,
}

/// Name of the session cookie.
pub const SESSION_COOKIE: &str = "denis_session";

/// Inserted into request extensions by `authn` for handlers that audit.
#[derive(Clone)]
pub struct AuthUser(pub User);

pub(crate) struct ApiError(anyhow::Error);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        tracing::error!("api error: {:#}", self.0);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "internal error"})),
        )
            .into_response()
    }
}

impl<E: Into<anyhow::Error>> From<E> for ApiError {
    fn from(e: E) -> Self {
        ApiError(e.into())
    }
}

/// Run a blocking store call off the async executor.
pub(crate) async fn blocking<T: Send + 'static>(
    store: &Arc<dyn Store>,
    f: impl FnOnce(&dyn Store) -> anyhow::Result<T> + Send + 'static,
) -> Result<T, ApiError> {
    let store = store.clone();
    Ok(tokio::task::spawn_blocking(move || f(&*store)).await??)
}

/// What the discovery engine concluded, before any manual override.
#[derive(Serialize)]
struct Detected {
    device_type: String,
    os_guess: Option<String>,
    vendor: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct AssetView {
    /// The asset with manual overrides applied to `device_type`, `os_guess`
    /// and `vendor`; the raw values are in `detected`.
    #[serde(flatten)]
    asset: Asset,
    /// Convenience: the most recently seen IP.
    ip: Option<Ipv4Addr>,
    risk: Risk,
    /// Everything entered by hand (owner, serial number, icon, ...).
    meta: AssetMeta,
    /// The name to show: manual name, else discovered hostname.
    display_name: Option<String>,
    detected: Detected,
    /// `{state: expired|expiring|ok, days}` when a warranty date is set.
    warranty: Option<serde_json::Value>,
}

/// Unacknowledged alerts grouped by device, for risk scoring.
pub(crate) fn open_alerts(store: &dyn Store) -> anyhow::Result<HashMap<i64, Vec<crate::model::Event>>> {
    let q = EventQuery { limit: 5000, alerts_only: true, unacked_only: true, ..Default::default() };
    let mut m: HashMap<i64, Vec<crate::model::Event>> = Default::default();
    for e in store.list_events(&q)? {
        m.entry(e.asset_id).or_default().push(e);
    }
    Ok(m)
}

pub(crate) fn view(
    mut asset: Asset,
    alerts: &HashMap<i64, Vec<crate::model::Event>>,
    meta: AssetMeta,
    now: i64,
) -> AssetView {
    let detected = Detected { device_type: asset.device_type.clone(), os_guess: asset.os_guess.clone(), vendor: asset.vendor.clone() };
    // Manual values win over guesses everywhere: display, risk, exports.
    crate::tracking::apply_overrides(&mut asset, &meta);
    let refs: Vec<&crate::model::Event> = alerts.get(&asset.id).map(|v| v.iter().collect()).unwrap_or_default();
    let risk = risk::assess_with(&asset, &refs, now, meta.criticality.as_deref());
    let ip = asset.current_ip();
    let warranty = crate::tracking::warranty_state(&meta, now).map(|(s, d)| serde_json::json!({ "state": s, "days": d }));
    AssetView { display_name: meta.display_name.clone(), asset, ip, risk, meta, detected, warranty }
}

/// May `me` see this site's devices/alerts at all (site access, see `access.rs`)?
pub(crate) fn site_readable(st: &AppState, me: &User, agent_id: &Option<String>) -> bool {
    crate::access::readable(&*st.store, me.id, &me.role, agent_id)
}

/// May `me` change this site's devices/alerts (acknowledge, edit, delete)?
pub(crate) fn site_writable(st: &AppState, me: &User, agent_id: &Option<String>) -> bool {
    crate::access::writable(&*st.store, me.id, &me.role, agent_id)
}

/// The license actually in force right now: one pasted into Settings → License always takes
/// priority (checked fresh on every call — cheap, and it lets an admin see the effect
/// immediately without restarting), otherwise the one this process started with (`--license-file`
/// / `DENIS_LICENSE_FILE`, or the Community edition if neither is set).
pub(crate) fn effective_license(st: &AppState) -> crate::license::Effective {
    if let Ok(Some(bytes)) = st.store.get_setting(crate::license::SETTING_KEY) {
        if let Ok(text) = String::from_utf8(bytes) {
            return crate::license::load_from_text(&text, &*st.store);
        }
    }
    st.license.clone()
}

/// Loads a device only if `me` may see it (site access; see `access.rs`). `None` means "does not
/// exist, or you may not see it" — every caller must answer both cases the same way (404), so an
/// out-of-scope id can never be told apart from a nonexistent one by an attacker probing ids.
pub(crate) async fn scoped_asset(st: &AppState, me: &User, id: i64) -> Result<Option<Asset>, ApiError> {
    let a = blocking(&st.store, move |s| s.get_asset(id)).await?;
    let me = me.clone();
    Ok(a.filter(move |a| site_readable(st, &me, &a.agent_id)))
}

/// One asset's full view (used after edits).
pub(crate) async fn asset_view(st: &AppState, me: &User, id: i64) -> Result<Option<AssetView>, ApiError> {
    let now = now_ts();
    let Some(a) = scoped_asset(st, me, id).await? else { return Ok(None) };
    let (alerts, meta) = blocking(&st.store, move |s| Ok((open_alerts(s)?, s.get_meta(id)?))).await?;
    Ok(Some(view(a, &alerts, meta.unwrap_or_default(), now)))
}
