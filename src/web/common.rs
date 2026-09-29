//! What `web` (routing/handlers) and every `web_*` module (more handlers, grouped by
//! area) both need: request state, the auth extractor, error plumbing, and site-scoped
//! asset loading. Kept apart from `web.rs` so neither side of that split has to import
//! from the other — `web_*` modules depend on this file, `web.rs` depends on this file
//! and on them, and this file depends on neither.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

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
    /// IP enrichment (`crate::ipenrich`): reverse DNS + GeoIP/ASN, cached, provider-swappable.
    pub ipenrich: Arc<crate::ipenrich::Service>,
    /// Throttles `Bearer dnt_` API-token traffic (brute-forced tokens per source IP, and a request
    /// quota per valid token) — see `ApiRateLimiter`'s own doc for why this exists.
    pub api_limiter: Arc<ApiRateLimiter>,
    /// Set by `ai_summary::run` while it is actually calling a provider, so the summary endpoint
    /// can tell a reader "Updating…" instead of just "stale" — never set from a request handler.
    pub ai_summary_generating: Arc<std::sync::atomic::AtomicBool>,
}

/// Rate-limits Bearer `dnt_` API-token traffic on the console/admin API. Mirrors `ingest.rs`'s own
/// per-IP throttle for the separate agent protocol, plus something the agent protocol does not
/// need: a per-token request quota, since a console API token is meant to be handed to a
/// third-party integration (a SOAR, a ticketing sync) that DENIS itself cannot audit the behaviour
/// of — a misconfigured or compromised one should not be able to hammer the API unbounded just
/// because its token is genuinely valid. Both windows are deliberately generous defaults, not
/// (yet) admin-configurable — see ROADMAP.md's public-API item.
pub struct ApiRateLimiter {
    /// source IP -> (bad token attempts in the current window, window start)
    bad_token: Mutex<HashMap<IpAddr, (u32, i64)>>,
    /// token id -> recent request timestamps within the current window
    requests: Mutex<HashMap<i64, VecDeque<i64>>>,
}

const MAX_BAD_TOKEN_ATTEMPTS: u32 = 10;
const BAD_TOKEN_WINDOW_SECS: i64 = 60;
/// Generous on purpose: this guards against a runaway loop or a compromised token, not against
/// legitimate polling (even a naive integration polling every few seconds stays well under this).
pub const MAX_REQUESTS_PER_TOKEN: usize = 300;
const REQUEST_WINDOW_SECS: i64 = 60;

impl Default for ApiRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiRateLimiter {
    pub fn new() -> Self {
        ApiRateLimiter { bad_token: Mutex::new(HashMap::new()), requests: Mutex::new(HashMap::new()) }
    }

    /// Seconds a source IP must wait before another bearer-token attempt is even checked, or 0.
    pub fn bad_token_throttled(&self, ip: IpAddr, now: i64) -> i64 {
        let m = self.bad_token.lock().unwrap();
        m.get(&ip)
            .filter(|(n, start)| *n >= MAX_BAD_TOKEN_ATTEMPTS && now - start < BAD_TOKEN_WINDOW_SECS)
            .map_or(0, |(_, start)| BAD_TOKEN_WINDOW_SECS - (now - start))
    }

    pub fn note_bad_token(&self, ip: IpAddr, now: i64) {
        let mut m = self.bad_token.lock().unwrap();
        if m.len() > 10_000 {
            m.retain(|_, (_, start)| now - *start < BAD_TOKEN_WINDOW_SECS);
        }
        let e = m.entry(ip).or_insert((0, now));
        if now - e.1 >= BAD_TOKEN_WINDOW_SECS {
            *e = (0, now);
        }
        e.0 += 1;
    }

    /// `true` if this (already-verified) token may proceed; records the attempt either way. A
    /// sliding window: old timestamps are dropped before counting, so a burst right at a window
    /// boundary can never double the effective limit the way a fixed-bucket reset could.
    pub fn allow_request(&self, token_id: i64, now: i64) -> bool {
        let mut m = self.requests.lock().unwrap();
        if m.len() > 10_000 {
            m.retain(|_, times| times.back().is_some_and(|t| now - *t < REQUEST_WINDOW_SECS));
        }
        let times = m.entry(token_id).or_default();
        while times.front().is_some_and(|t| now - *t >= REQUEST_WINDOW_SECS) {
            times.pop_front();
        }
        if times.len() >= MAX_REQUESTS_PER_TOKEN {
            return false;
        }
        times.push_back(now);
        true
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_valid_token_is_capped_at_the_request_quota_then_recovers_once_the_window_slides() {
        let lim = ApiRateLimiter::new();
        for i in 0..MAX_REQUESTS_PER_TOKEN {
            assert!(lim.allow_request(1, 1000), "request {i} should still be inside the quota");
        }
        assert!(!lim.allow_request(1, 1000), "the quota-th-plus-one request in the same second is refused");
        // a different token has its own, independent quota
        assert!(lim.allow_request(2, 1000));
        // once the oldest requests fall out of the window, the token can proceed again
        assert!(lim.allow_request(1, 1000 + REQUEST_WINDOW_SECS));
    }

    #[test]
    fn bad_tokens_are_throttled_per_source_ip_and_recover_after_the_window() {
        let lim = ApiRateLimiter::new();
        let ip: IpAddr = "10.0.0.5".parse().unwrap();
        for _ in 0..MAX_BAD_TOKEN_ATTEMPTS {
            assert_eq!(lim.bad_token_throttled(ip, 1000), 0, "not throttled until the threshold is reached");
            lim.note_bad_token(ip, 1000);
        }
        assert!(lim.bad_token_throttled(ip, 1000) > 0, "throttled once the threshold is reached");
        // a different address is never affected by another one's failures
        let other: IpAddr = "10.0.0.6".parse().unwrap();
        assert_eq!(lim.bad_token_throttled(other, 1000), 0);
        // the window rolls forward: old failures do not throttle forever
        assert_eq!(lim.bad_token_throttled(ip, 1000 + BAD_TOKEN_WINDOW_SECS), 0);
    }
}
