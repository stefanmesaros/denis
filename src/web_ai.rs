//! "Explain with AI" HTTP handlers: an administrator's provider keys, and the on-demand,
//! opt-in explanation of one alert or finding. See `ai.rs` for the actual provider calls and
//! why this exists only as a bring-your-own-key, click-to-run feature.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Extension;
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::model::now_ts;
use crate::web::common::{blocking, ApiError, AppState, AuthUser};
use crate::web_admin::{audit, err};

/// What the "Explain" button needs: which providers it may offer, without ever seeing a key.
#[derive(Serialize)]
pub struct PublicStatus {
    pub providers: Vec<ProviderStatus>,
    pub default_provider: String,
}

#[derive(Serialize)]
pub struct ProviderStatus {
    pub id: &'static str,
    pub name: &'static str,
}

pub(crate) async fn status(State(st): State<AppState>) -> Result<Json<PublicStatus>, ApiError> {
    let cfg = blocking(&st.store, |s| crate::ai::load(s)).await?;
    Ok(Json(PublicStatus {
        providers: cfg.configured().into_iter().map(|id| ProviderStatus { id, name: crate::ai::provider_name(id) }).collect(),
        default_provider: cfg.default_provider,
    }))
}

/// The administrator's configuration: which providers have a key (never the key itself).
#[derive(Serialize)]
pub struct Redacted {
    pub keys_set: Vec<&'static str>,
    pub default_provider: String,
}

pub(crate) async fn get(State(st): State<AppState>) -> Result<Json<Redacted>, ApiError> {
    let cfg = blocking(&st.store, |s| crate::ai::load(s)).await?;
    Ok(Json(Redacted { keys_set: cfg.configured(), default_provider: cfg.default_provider }))
}

#[derive(Deserialize)]
pub struct PutReq {
    /// One entry per provider that should change; a blank value clears that provider's key, an
    /// absent one leaves it as it is (so the form never has to know or resend the others).
    #[serde(default)]
    keys: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    default_provider: String,
}

pub(crate) async fn put(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Json(b): Json<PutReq>) -> Result<Response, ApiError> {
    let res = blocking(&st.store, move |s| {
        let mut cfg = crate::ai::load(s)?;
        for (k, v) in &b.keys {
            if !crate::ai::PROVIDERS.contains(&k.as_str()) {
                return Ok(Err(format!("unknown provider {k:?}")));
            }
            if v.is_empty() {
                cfg.keys.remove(k);
            } else {
                cfg.keys.insert(k.clone(), v.clone());
            }
        }
        if !b.default_provider.is_empty() && !crate::ai::PROVIDERS.contains(&b.default_provider.as_str()) {
            return Ok(Err(format!("unknown provider {:?}", b.default_provider)));
        }
        cfg.default_provider = b.default_provider;
        crate::ai::save(s, &cfg, now_ts())?;
        Ok(Ok(cfg))
    })
    .await?;
    Ok(match res {
        Ok(cfg) => {
            audit(&st, &me.username, "ai.update", None, json!({"providers": cfg.configured()}));
            Json(Redacted { keys_set: cfg.configured(), default_provider: cfg.default_provider }).into_response()
        }
        Err(e) => err(StatusCode::BAD_REQUEST, e),
    })
}

#[derive(Deserialize)]
pub struct ExplainReq {
    kind: String,
    /// An alert's numeric event id, or a finding's string id, as text either way.
    id: String,
    #[serde(default)]
    provider: Option<String>,
}

#[derive(Serialize)]
struct ExplainResp {
    provider: &'static str,
    text: String,
}

/// Explain one alert or finding the caller can already see — never more than that, and only
/// when they click the button (see `ai.rs`'s module docs for why this is never automatic).
pub(crate) async fn explain(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Json(b): Json<ExplainReq>) -> Result<Response, ApiError> {
    let store = st.store.clone();
    let now = now_ts();
    let prompt = match b.kind.as_str() {
        "alert" => {
            let id: i64 = match b.id.parse() {
                Ok(id) => id,
                Err(_) => return Ok(err(StatusCode::BAD_REQUEST, "bad alert id")),
            };
            let ev = blocking(&store, move |s| s.get_event(id)).await?;
            let Some(ev) = ev else { return Ok(err(StatusCode::NOT_FOUND, "no such alert")) };
            let asset = blocking(&store, move |s| s.get_asset(ev.asset_id)).await?;
            let label = asset.map(|a| device_label(&a)).unwrap_or_else(|| format!("device #{}", ev.asset_id));
            let d = &ev.raw_details;
            let summary = d["summary"].as_str().unwrap_or_default();
            let reasons: Vec<String> = d["reasons"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect()).unwrap_or_default();
            crate::ai::alert_prompt(&ev.kind, ev.score, &ev.severity, summary, &reasons, &label)
        }
        "finding" => {
            let (list, metas) = blocking(&store, |s| Ok((s.load_assets()?, s.load_all_meta()?))).await?;
            let list = list.into_iter().map(|mut a| { if let Some(m) = metas.get(&a.id) { crate::tracking::apply_overrides(&mut a, m); } a }).collect::<Vec<_>>();
            let findings = crate::findings::compute(&list, &metas, now);
            let Some(f) = findings.into_iter().find(|f| f.id == b.id) else { return Ok(err(StatusCode::NOT_FOUND, "no such finding, or it no longer applies")) };
            crate::ai::finding_prompt(f.title, f.why, f.fix, f.assets.len())
        }
        _ => return Ok(err(StatusCode::BAD_REQUEST, "kind must be \"alert\" or \"finding\"")),
    };
    let cfg = blocking(&store, |s| crate::ai::load(s)).await?;
    let provider = b.provider.filter(|p| !p.is_empty()).unwrap_or(cfg.default_provider.clone());
    let provider: &'static str = match crate::ai::PROVIDERS.iter().find(|p| **p == provider) {
        Some(p) => p,
        None => return Ok(err(StatusCode::BAD_REQUEST, "choose a configured provider")),
    };
    let cfg2 = cfg.clone();
    let text = tokio::task::spawn_blocking(move || crate::ai::explain(&cfg2, provider, &prompt)).await;
    match text {
        Ok(Ok(text)) => {
            audit(&st, &me.username, "ai.explain", None, json!({"kind": b.kind, "provider": provider}));
            Ok(Json(ExplainResp { provider, text }).into_response())
        }
        Ok(Err(e)) => Ok(err(StatusCode::BAD_GATEWAY, format!("{e:#}"))),
        Err(_) => Ok(err(StatusCode::INTERNAL_SERVER_ERROR, "internal error")),
    }
}

fn device_label(a: &crate::model::Asset) -> String {
    let name = a.hostnames.iter().chain(a.fingerprint.mdns_names.iter()).find(|h| h.len() != 36 && h.len() != 32).cloned();
    let ip = a.current_ip().map(|ip| ip.to_string()).unwrap_or_default();
    match name {
        Some(n) => format!("{n} ({ip})"),
        None => format!("{} {ip}", a.device_type),
    }
}
