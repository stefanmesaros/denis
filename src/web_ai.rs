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
use crate::web::common::{blocking, site_readable, ApiError, AppState, AuthUser};
use crate::web_admin::{audit, err};

/// Best-effort, same tolerance as `audit`: a failure to record usage must never fail the AI call
/// that already succeeded, only be logged.
fn record_usage(st: &AppState, now: i64, provider: &str, tokens: Option<i64>) {
    if let Err(e) = crate::ai_usage::record(&*st.store, now, provider, tokens) {
        tracing::error!("AI usage record failed: {e:#}");
    }
}

/// Combines two calls' own token counts (`ask`'s "Ask DENIS" needs two) into one: `None` only when
/// *neither* reported a count, since one real count is still real usage worth keeping.
fn sum_tokens(a: Option<i64>, b: Option<i64>) -> Option<i64> {
    match (a, b) {
        (None, None) => None,
        (a, b) => Some(a.unwrap_or(0) + b.unwrap_or(0)),
    }
}

/// What a per-feature button needs: which providers it may offer, without ever seeing a key, and
/// which capabilities are actually switched on right now — `providers` is empty whenever AI is
/// globally off (nothing works regardless of a per-feature flag), so a caller can check either
/// `providers.length` alone (any feature) or a specific flag (`alert_explanations`/`alert_triage`)
/// together with it, and never needs to duplicate the enabled/feature logic client-side.
#[derive(Serialize)]
pub struct PublicStatus {
    pub providers: Vec<ProviderStatus>,
    pub default_provider: String,
    pub alert_explanations: bool,
    pub alert_triage: bool,
    pub recommended_actions: bool,
    pub dashboard_summary: bool,
    pub ask_denis: bool,
    pub device_behavior: bool,
    pub rule_assistant: bool,
    pub ask_model_per_action: bool,
}

#[derive(Serialize)]
pub struct ProviderStatus {
    pub id: &'static str,
    pub name: &'static str,
}

pub(crate) async fn status(State(st): State<AppState>) -> Result<Json<PublicStatus>, ApiError> {
    let cfg = blocking(&st.store, |s| crate::ai::load(s)).await?;
    let providers = if cfg.enabled {
        cfg.configured().into_iter().map(|id| ProviderStatus { id, name: crate::ai::provider_name(id) }).collect()
    } else {
        Vec::new()
    };
    Ok(Json(PublicStatus {
        providers,
        default_provider: cfg.default_provider,
        alert_explanations: cfg.enabled && cfg.features.alert_explanations,
        alert_triage: cfg.enabled && cfg.features.alert_triage,
        recommended_actions: cfg.enabled && cfg.features.recommended_actions,
        dashboard_summary: cfg.enabled && cfg.features.dashboard_summary,
        ask_denis: cfg.enabled && cfg.features.ask_denis,
        device_behavior: cfg.enabled && cfg.features.device_behavior,
        rule_assistant: cfg.enabled && cfg.features.rule_assistant,
        ask_model_per_action: cfg.ask_model_per_action,
    }))
}

/// The administrator's configuration: which providers are ready to use — a key for a cloud
/// provider, or a URL and model name for `local` — never the key itself.
#[derive(Serialize)]
pub struct Redacted {
    pub keys_set: Vec<&'static str>,
    /// Providers that literally have a key value stored, regardless of whether they are otherwise
    /// ready — distinct from `keys_set` specifically because `local` can be "ready" (url and model
    /// both set) with no key at all, and the "(unchanged)" placeholder on its own key field must
    /// not claim one is saved when none is.
    pub keys_present: Vec<&'static str>,
    pub default_provider: String,
    pub enabled: bool,
    pub features: crate::ai::AiFeatures,
    pub anthropic_workspace_id: String,
    pub local_url: String,
    pub local_model: String,
    pub ask_model_per_action: bool,
}

fn redacted(cfg: crate::ai::AiConfig) -> Redacted {
    let keys_present = crate::ai::PROVIDERS.iter().copied().filter(|p| cfg.key_for(p).is_some()).collect();
    Redacted {
        keys_set: cfg.configured(), keys_present, default_provider: cfg.default_provider, enabled: cfg.enabled, features: cfg.features,
        anthropic_workspace_id: cfg.anthropic_workspace_id, local_url: cfg.local_url, local_model: cfg.local_model, ask_model_per_action: cfg.ask_model_per_action,
    }
}

pub(crate) async fn get(State(st): State<AppState>) -> Result<Json<Redacted>, ApiError> {
    let cfg = blocking(&st.store, |s| crate::ai::load(s)).await?;
    Ok(Json(redacted(cfg)))
}

#[derive(Deserialize)]
pub struct PutReq {
    /// One entry per provider that should change; a blank value clears that provider's key, an
    /// absent one leaves it as it is (so the form never has to know or resend the others).
    #[serde(default)]
    keys: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    default_provider: String,
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    features: crate::ai::AiFeatures,
    #[serde(default)]
    anthropic_workspace_id: String,
    #[serde(default)]
    local_url: String,
    #[serde(default)]
    local_model: String,
    #[serde(default)]
    ask_model_per_action: bool,
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
        cfg.enabled = b.enabled;
        cfg.features = b.features;
        cfg.anthropic_workspace_id = b.anthropic_workspace_id.trim().to_string();
        cfg.local_url = b.local_url.trim().trim_end_matches('/').to_string();
        cfg.local_model = b.local_model.trim().to_string();
        cfg.ask_model_per_action = b.ask_model_per_action;
        crate::ai::save(s, &cfg, now_ts())?;
        Ok(Ok(cfg))
    })
    .await?;
    Ok(match res {
        Ok(cfg) => {
            audit(&st, &me.username, "ai.update", None, json!({"providers": cfg.configured(), "enabled": cfg.enabled, "features": cfg.features}));
            Json(redacted(cfg)).into_response()
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
    // Defense in depth: the button is already hidden when either is off (see `status` above), but
    // this is the actual boundary that must refuse a direct call, not just the UI hiding a button.
    let cfg = blocking(&store, |s| crate::ai::load(s)).await?;
    if !cfg.enabled {
        return Ok(err(StatusCode::FORBIDDEN, "AI is turned off in Settings → AI"));
    }
    if !cfg.features.alert_explanations {
        return Ok(err(StatusCode::FORBIDDEN, "the alert-explanations AI feature is turned off in Settings → AI"));
    }
    let prompt = match b.kind.as_str() {
        "alert" => {
            let id: i64 = match b.id.parse() {
                Ok(id) => id,
                Err(_) => return Ok(err(StatusCode::BAD_REQUEST, "bad alert id")),
            };
            let ev = blocking(&store, move |s| s.get_event(id)).await?;
            let Some(ev) = ev else { return Ok(err(StatusCode::NOT_FOUND, "no such alert")) };
            // Same site scoping as every other view of an alert, and the same "no such alert"
            // wording either way - a distinguishable 403 would tell an unauthorized caller which
            // ids exist (SECURITY_ARCHITECTURE_REVIEW.md H1).
            if !site_readable(&st, &me, &ev.agent_id) {
                return Ok(err(StatusCode::NOT_FOUND, "no such alert"));
            }
            let asset = blocking(&store, move |s| s.get_asset(ev.asset_id)).await?;
            let label = asset.map(|a| a.label()).unwrap_or_else(|| format!("device #{}", ev.asset_id));
            let d = &ev.raw_details;
            let summary = d["summary"].as_str().unwrap_or_default();
            let reasons: Vec<String> = d["reasons"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect()).unwrap_or_default();
            crate::ai::alert_prompt(&ev.kind, ev.score, &ev.severity, summary, &reasons, &label)
        }
        "finding" => {
            let (mut list, metas) = blocking(&store, |s| Ok((s.load_assets()?, s.load_all_meta()?))).await?;
            // Same site scoping as the `findings` list endpoint (SECURITY_ARCHITECTURE_REVIEW.md
            // H1): a finding computed over devices the caller cannot see would leak their
            // existence and state through this prompt.
            list.retain(|a| site_readable(&st, &me, &a.agent_id));
            let list = list.into_iter().map(|mut a| { if let Some(m) = metas.get(&a.id) { crate::tracking::apply_overrides(&mut a, m); } a }).collect::<Vec<_>>();
            let findings = crate::findings::compute(&list, &metas, now);
            let Some(f) = findings.into_iter().find(|f| f.id == b.id) else { return Ok(err(StatusCode::NOT_FOUND, "no such finding, or it no longer applies")) };
            crate::ai::finding_prompt(f.title, f.why, f.fix, f.assets.len())
        }
        _ => return Ok(err(StatusCode::BAD_REQUEST, "kind must be \"alert\" or \"finding\"")),
    };
    let provider = b.provider.filter(|p| !p.is_empty()).unwrap_or(cfg.default_provider.clone());
    let provider: &'static str = match crate::ai::PROVIDERS.iter().find(|p| **p == provider) {
        Some(p) => p,
        None => return Ok(err(StatusCode::BAD_REQUEST, "choose a configured provider")),
    };
    let cfg2 = cfg.clone();
    let text = tokio::task::spawn_blocking(move || crate::ai::explain(&cfg2, provider, &prompt)).await;
    match text {
        Ok(Ok((text, tokens))) => {
            audit(&st, &me.username, "ai.explain", None, json!({"kind": b.kind, "provider": provider}));
            record_usage(&st, now, provider, tokens);
            Ok(Json(ExplainResp { provider, text }).into_response())
        }
        Ok(Err(e)) => Ok(err(StatusCode::BAD_GATEWAY, format!("{e:#}"))),
        Err(_) => Ok(err(StatusCode::INTERNAL_SERVER_ERROR, "internal error")),
    }
}

#[derive(Deserialize)]
pub struct TriageReq {
    /// An alert's numeric event id, as text. Triage is alert-only (spec section 12) — findings
    /// have no severity of their own for a triage assessment to sit alongside.
    id: String,
    #[serde(default)]
    provider: Option<String>,
}

#[derive(Serialize)]
struct TriageResp {
    provider: &'static str,
    /// DENIS's own severity/score, unchanged, shown alongside the AI assessment below so a caller
    /// never has to separately re-fetch the alert to see both at once (spec: "both should remain
    /// visible").
    severity: String,
    score: i32,
    #[serde(flatten)]
    result: crate::ai::TriageResult,
}

/// AI triage of one alert the caller can already see: a structured, *additional* assessment next
/// to DENIS's own deterministic severity — never written back over it (see `ai::TriageResult`'s own
/// doc). On click only, same bar as `explain`.
pub(crate) async fn triage(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Json(b): Json<TriageReq>) -> Result<Response, ApiError> {
    let store = st.store.clone();
    let now = now_ts();
    let cfg = blocking(&store, |s| crate::ai::load(s)).await?;
    if !cfg.enabled {
        return Ok(err(StatusCode::FORBIDDEN, "AI is turned off in Settings → AI"));
    }
    if !cfg.features.alert_triage {
        return Ok(err(StatusCode::FORBIDDEN, "the alert-triage AI feature is turned off in Settings → AI"));
    }
    let id: i64 = match b.id.parse() {
        Ok(id) => id,
        Err(_) => return Ok(err(StatusCode::BAD_REQUEST, "bad alert id")),
    };
    let ev = blocking(&store, move |s| s.get_event(id)).await?;
    let Some(ev) = ev else { return Ok(err(StatusCode::NOT_FOUND, "no such alert")) };
    // Same site scoping as `explain`, and the same "no such alert" wording either way
    // (SECURITY_ARCHITECTURE_REVIEW.md H1).
    if !site_readable(&st, &me, &ev.agent_id) {
        return Ok(err(StatusCode::NOT_FOUND, "no such alert"));
    }
    let asset = blocking(&store, move |s| s.get_asset(ev.asset_id)).await?;
    let label = asset.map(|a| a.label()).unwrap_or_else(|| format!("device #{}", ev.asset_id));
    let d = &ev.raw_details;
    let summary = d["summary"].as_str().unwrap_or_default();
    let reasons: Vec<String> = d["reasons"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect()).unwrap_or_default();
    let prompt = crate::ai::alert_prompt(&ev.kind, ev.score, &ev.severity, summary, &reasons, &label);
    let provider = b.provider.filter(|p| !p.is_empty()).unwrap_or(cfg.default_provider.clone());
    let provider: &'static str = match crate::ai::PROVIDERS.iter().find(|p| **p == provider) {
        Some(p) => p,
        None => return Ok(err(StatusCode::BAD_REQUEST, "choose a configured provider")),
    };
    let cfg2 = cfg.clone();
    let result = tokio::task::spawn_blocking(move || crate::ai::triage(&cfg2, provider, &prompt, now)).await;
    match result {
        Ok(Ok((result, tokens))) => {
            audit(&st, &me.username, "ai.triage", None, json!({"alert_id": id, "provider": provider, "assessment": result.assessment}));
            record_usage(&st, now, provider, tokens);
            Ok(Json(TriageResp { provider, severity: ev.severity, score: ev.score, result }).into_response())
        }
        Ok(Err(e)) => Ok(err(StatusCode::BAD_GATEWAY, format!("{e:#}"))),
        Err(_) => Ok(err(StatusCode::INTERNAL_SERVER_ERROR, "internal error")),
    }
}

#[derive(Deserialize)]
pub struct RecommendReq {
    /// An alert's numeric event id, as text. Advisory next steps, alert-only, same as triage —
    /// findings already carry their own fixed `fix` text (see `finding_prompt`).
    id: String,
    #[serde(default)]
    provider: Option<String>,
}

#[derive(Serialize)]
struct RecommendResp {
    provider: &'static str,
    #[serde(flatten)]
    result: crate::ai::RecommendedActions,
}

/// Advisory next steps for one alert the caller can already see (spec section 15) — never anything
/// DENIS itself acts on. On click only, same bar as `explain`/`triage`.
pub(crate) async fn recommend(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Json(b): Json<RecommendReq>) -> Result<Response, ApiError> {
    let store = st.store.clone();
    let now = now_ts();
    let cfg = blocking(&store, |s| crate::ai::load(s)).await?;
    if !cfg.enabled {
        return Ok(err(StatusCode::FORBIDDEN, "AI is turned off in Settings → AI"));
    }
    if !cfg.features.recommended_actions {
        return Ok(err(StatusCode::FORBIDDEN, "the recommended-actions AI feature is turned off in Settings → AI"));
    }
    let id: i64 = match b.id.parse() {
        Ok(id) => id,
        Err(_) => return Ok(err(StatusCode::BAD_REQUEST, "bad alert id")),
    };
    let ev = blocking(&store, move |s| s.get_event(id)).await?;
    let Some(ev) = ev else { return Ok(err(StatusCode::NOT_FOUND, "no such alert")) };
    // Same site scoping as `explain`/`triage`, and the same "no such alert" wording either way
    // (SECURITY_ARCHITECTURE_REVIEW.md H1).
    if !site_readable(&st, &me, &ev.agent_id) {
        return Ok(err(StatusCode::NOT_FOUND, "no such alert"));
    }
    let asset = blocking(&store, move |s| s.get_asset(ev.asset_id)).await?;
    let label = asset.map(|a| a.label()).unwrap_or_else(|| format!("device #{}", ev.asset_id));
    let d = &ev.raw_details;
    let summary = d["summary"].as_str().unwrap_or_default();
    let reasons: Vec<String> = d["reasons"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect()).unwrap_or_default();
    let prompt = crate::ai::alert_prompt(&ev.kind, ev.score, &ev.severity, summary, &reasons, &label);
    let provider = b.provider.filter(|p| !p.is_empty()).unwrap_or(cfg.default_provider.clone());
    let provider: &'static str = match crate::ai::PROVIDERS.iter().find(|p| **p == provider) {
        Some(p) => p,
        None => return Ok(err(StatusCode::BAD_REQUEST, "choose a configured provider")),
    };
    let cfg2 = cfg.clone();
    let result = tokio::task::spawn_blocking(move || crate::ai::recommend_actions(&cfg2, provider, &prompt, now)).await;
    match result {
        Ok(Ok((result, tokens))) => {
            audit(&st, &me.username, "ai.recommend", None, json!({"alert_id": id, "provider": provider}));
            record_usage(&st, now, provider, tokens);
            Ok(Json(RecommendResp { provider, result }).into_response())
        }
        Ok(Err(e)) => Ok(err(StatusCode::BAD_GATEWAY, format!("{e:#}"))),
        Err(_) => Ok(err(StatusCode::INTERNAL_SERVER_ERROR, "internal error")),
    }
}

#[derive(Serialize)]
pub struct SummaryResp {
    text: String,
    generated_at: i64,
    /// Whether `text` was generated from an older alert stream than the one that exists right
    /// now — the dashboard still shows `text` either way (AI.md section 10: never blank just
    /// because generation is pending), this only changes whether it also says "Updating…".
    stale: bool,
    /// The background job (`ai_summary::run`) is actively calling a provider right now.
    generating: bool,
    /// Whether the feature is even on — mirrors `PublicStatus.dashboard_summary`, repeated here so
    /// the dashboard can render from this one response alone.
    available: bool,
}

/// Read-only: the dashboard's own AI summary, exactly as `ai_summary::run` last stored it. This
/// handler never calls a provider itself — see that module's own doc for why (AI.md section 6 is
/// explicit that opening or refreshing the dashboard must never trigger AI generation).
pub(crate) async fn summary(State(st): State<AppState>) -> Result<Json<SummaryResp>, ApiError> {
    let store = st.store.clone();
    let (cfg, record, version) = blocking(&store, |s| {
        Ok((crate::ai::load(s)?, crate::ai_summary::load(s)?, crate::ai_summary::current_version(s)?))
    })
    .await?;
    let available = cfg.enabled && cfg.features.dashboard_summary;
    Ok(Json(SummaryResp {
        text: record.text,
        generated_at: record.generated_at,
        stale: record.source_state_version != version,
        generating: st.ai_summary_generating.load(std::sync::atomic::Ordering::SeqCst),
        available,
    }))
}

/// How many of the recent alerts matching an "Ask DENIS" query are actually shown to the answer
/// call — kept small so the second prompt stays compact and cheap (AI.md section 11), and because
/// past this many individually-named rows an answer stops being readable anyway.
const ASK_MAX_ROWS: usize = 20;
/// How many of the most recent alerts are scanned to find matches — generous enough to almost
/// always cover a 720-hour (30-day) window without scanning the whole alert history, same
/// reasoning as `ai_summary::CONTEXT_SCAN_LIMIT`.
const ASK_SCAN_LIMIT: usize = 1000;

#[derive(Deserialize)]
pub struct AskReq {
    question: String,
    #[serde(default)]
    provider: Option<String>,
}

#[derive(Serialize)]
struct AskResp {
    provider: &'static str,
    answer: String,
    /// How many alerts DENIS's own search actually found — lets the UI show e.g. "based on 3
    /// alerts" without the caller having to parse that back out of the prose answer.
    matched: usize,
}

/// A free-text question about the network (AI.md section 16), on click only. Two AI calls, never
/// one: the first only ever chooses *how* DENIS should search its own alerts (`ai::AskQuery`,
/// validated the same way `parse_triage` is — an invented severity or alert kind is a hard error,
/// never guessed); DENIS itself runs that exact search; the second call only ever describes what
/// DENIS actually found. The model is never in a position to answer from facts it invented.
pub(crate) async fn ask(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Json(b): Json<AskReq>) -> Result<Response, ApiError> {
    let store = st.store.clone();
    let now = now_ts();
    let cfg = blocking(&store, |s| crate::ai::load(s)).await?;
    if !cfg.enabled {
        return Ok(err(StatusCode::FORBIDDEN, "AI is turned off in Settings → AI"));
    }
    if !cfg.features.ask_denis {
        return Ok(err(StatusCode::FORBIDDEN, "the Ask DENIS AI feature is turned off in Settings → AI"));
    }
    if b.question.trim().is_empty() {
        return Ok(err(StatusCode::BAD_REQUEST, "ask a question first"));
    }
    let provider = b.provider.filter(|p| !p.is_empty()).unwrap_or(cfg.default_provider.clone());
    let provider: &'static str = match crate::ai::PROVIDERS.iter().find(|p| **p == provider) {
        Some(p) => p,
        None => return Ok(err(StatusCode::BAD_REQUEST, "choose a configured provider")),
    };
    let cfg2 = cfg.clone();
    let question = b.question.clone();
    let query = tokio::task::spawn_blocking(move || crate::ai::interpret_question(&cfg2, provider, &question)).await;
    // Both calls' own token counts are summed into one usage record: from the administrator's
    // point of view this is one "Ask DENIS" use, not two, even though it costs two calls.
    let (query, total_tokens) = match query {
        Ok(Ok((q, t))) => (q, t),
        Ok(Err(e)) => return Ok(err(StatusCode::BAD_GATEWAY, format!("{e:#}"))),
        Err(_) => return Ok(err(StatusCode::INTERNAL_SERVER_ERROR, "internal error")),
    };
    if let Some(destination) = query.destination {
        return ask_destination(st, &me, now, cfg, provider, b.question, destination, total_tokens).await;
    }
    let q2 = crate::store::EventQuery { alerts_only: true, limit: ASK_SCAN_LIMIT, ..Default::default() };
    let hours = query.hours;
    let severity = query.severity.clone();
    let kind = query.kind.clone();
    let device = query.device.clone();
    let rows = blocking(&store, move |s| {
        let cutoff = now - hours * 3600;
        let mut matched: Vec<crate::ai::AskResultRow> = Vec::new();
        for e in s.list_events(&q2)? {
            if e.timestamp < cutoff {
                continue;
            }
            if severity.as_deref().is_some_and(|sev| sev != e.severity) {
                continue;
            }
            if kind.as_deref().is_some_and(|k| k != e.kind) {
                continue;
            }
            let label = s.get_asset(e.asset_id)?.map(|a| a.label()).unwrap_or_else(|| format!("device #{}", e.asset_id));
            if let Some(d) = &device {
                if !label.to_lowercase().contains(&d.to_lowercase()) {
                    continue;
                }
            }
            let summary = e.raw_details["summary"].as_str().unwrap_or_default().to_string();
            matched.push(crate::ai::AskResultRow { kind: e.kind, severity: e.severity, score: e.score, device_label: label, summary, age_secs: now - e.timestamp });
            if matched.len() >= ASK_MAX_ROWS {
                break;
            }
        }
        Ok(matched)
    })
    .await?;
    let matched = rows.len();
    let results_prompt = crate::ai::ask_results_prompt(&b.question, &rows);
    let cfg3 = cfg.clone();
    let answer = tokio::task::spawn_blocking(move || crate::ai::answer_question(&cfg3, provider, &results_prompt)).await;
    match answer {
        Ok(Ok((answer, t2))) => {
            audit(&st, &me.username, "ai.ask", None, json!({"provider": provider, "matched": matched}));
            record_usage(&st, now, provider, sum_tokens(total_tokens, t2));
            Ok(Json(AskResp { provider, answer, matched }).into_response())
        }
        Ok(Err(e)) => Ok(err(StatusCode::BAD_GATEWAY, format!("{e:#}"))),
        Err(_) => Ok(err(StatusCode::INTERNAL_SERVER_ERROR, "internal error")),
    }
}

/// How many devices' traffic history a destination hunt reports back to the answer call — same
/// reasoning as `ASK_MAX_ROWS`: capped so the second call's own prompt stays bounded.
const ASK_DEST_MAX_ROWS: usize = 20;

/// Step 10, AI threat hunting: `ask`'s other branch, taken when the interpretation call decided
/// this question is a destination search rather than an alert search. Scans every device's own
/// baseline (already-tracked data, nothing new collected) for a destination matching `hunted`
/// (case-insensitive substring, same matching style as `/api/baseline/destinations`), scoped by
/// the caller's own site access exactly like that endpoint.
#[allow(clippy::too_many_arguments)]
async fn ask_destination(
    st: AppState, me: &crate::model::User, now: i64, cfg: crate::ai::AiConfig, provider: &'static str,
    question: String, hunted: String, total_tokens: Option<i64>,
) -> Result<Response, ApiError> {
    let store = st.store.clone();
    let st2 = st.clone();
    let me2 = me.clone();
    let needle = hunted.to_lowercase();
    let rows = blocking(&store, move |s| {
        let assets = s.load_assets()?;
        let by_id: std::collections::HashMap<i64, &crate::model::Asset> = assets.iter().map(|a| (a.id, a)).collect();
        let mut out: Vec<crate::ai::AskDestinationRow> = Vec::new();
        for b in s.load_baselines()? {
            let Some(a) = by_id.get(&b.asset_id) else { continue };
            if !site_readable(&st2, &me2, &a.agent_id) {
                continue;
            }
            for (ip, d) in &b.typical_destinations {
                if !ip.to_lowercase().contains(&needle) {
                    continue;
                }
                out.push(crate::ai::AskDestinationRow {
                    device_label: a.label(), destination: ip.clone(),
                    first_seen_secs_ago: now - d.first_seen, last_seen_secs_ago: now - d.last_seen, bytes: d.bytes,
                });
                if out.len() >= ASK_DEST_MAX_ROWS {
                    return Ok(out);
                }
            }
        }
        Ok(out)
    })
    .await?;
    let matched = rows.len();
    let results_prompt = crate::ai::ask_destination_prompt(&question, &hunted, &rows);
    let answer = tokio::task::spawn_blocking(move || crate::ai::answer_destination_question(&cfg, provider, &results_prompt)).await;
    match answer {
        Ok(Ok((answer, t2))) => {
            audit(&st, &me.username, "ai.ask", None, json!({"provider": provider, "matched": matched, "destination": hunted}));
            record_usage(&st, now, provider, sum_tokens(total_tokens, t2));
            Ok(Json(AskResp { provider, answer, matched }).into_response())
        }
        Ok(Err(e)) => Ok(err(StatusCode::BAD_GATEWAY, format!("{e:#}"))),
        Err(_) => Ok(err(StatusCode::INTERNAL_SERVER_ERROR, "internal error")),
    }
}

#[derive(Deserialize)]
pub struct SuggestRuleReq {
    description: String,
    #[serde(default)]
    provider: Option<String>,
}

#[derive(Serialize)]
struct SuggestRuleResp {
    provider: &'static str,
    name: String,
    proto: String,
    ports_mode: String,
    ports: Vec<u16>,
    remotes_mode: String,
    remotes: Vec<String>,
    min_kb: i64,
    score: i32,
    cooldown_minutes: i32,
}

/// Step 11, the AI detection-rule assistant: turn a plain-language description into one draft
/// network watch, the same shape the form's own built-in presets already fill it with — a dynamic
/// preset, never a rule written on its own. On click only, one call (unlike Ask DENIS's two: there
/// is no DENIS-side fact to fetch first, only a shape for the administrator to review, edit and
/// submit themselves in the ordinary form).
pub(crate) async fn suggest_rule(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Json(b): Json<SuggestRuleReq>) -> Result<Response, ApiError> {
    let now = now_ts();
    let cfg = blocking(&st.store, |s| crate::ai::load(s)).await?;
    if !cfg.enabled {
        return Ok(err(StatusCode::FORBIDDEN, "AI is turned off in Settings → AI"));
    }
    if !cfg.features.rule_assistant {
        return Ok(err(StatusCode::FORBIDDEN, "the AI detection-rule assistant is turned off in Settings → AI"));
    }
    if b.description.trim().is_empty() {
        return Ok(err(StatusCode::BAD_REQUEST, "describe what to watch for first"));
    }
    let provider = b.provider.filter(|p| !p.is_empty()).unwrap_or(cfg.default_provider.clone());
    let provider: &'static str = match crate::ai::PROVIDERS.iter().find(|p| **p == provider) {
        Some(p) => p,
        None => return Ok(err(StatusCode::BAD_REQUEST, "choose a configured provider")),
    };
    let description = b.description.clone();
    let result = tokio::task::spawn_blocking(move || crate::ai::suggest_rule(&cfg, provider, &description)).await;
    match result {
        Ok(Ok((s, tokens))) => {
            audit(&st, &me.username, "ai.suggest_rule", None, json!({"provider": provider}));
            record_usage(&st, now, provider, tokens);
            Ok(Json(SuggestRuleResp {
                provider, name: s.name, proto: s.proto, ports_mode: s.ports_mode, ports: s.ports,
                remotes_mode: s.remotes_mode, remotes: s.remotes, min_kb: s.min_kb, score: s.score, cooldown_minutes: s.cooldown_minutes,
            })
            .into_response())
        }
        Ok(Err(e)) => Ok(err(StatusCode::BAD_GATEWAY, format!("{e:#}"))),
        Err(_) => Ok(err(StatusCode::INTERNAL_SERVER_ERROR, "internal error")),
    }
}

#[derive(Deserialize)]
pub struct BehaviorReq {
    /// An alert's numeric event id, as text. Alert-only, and only one of the specific kinds
    /// `detect::is_behavioral_kind` names — a finding has no baseline of its own to compare
    /// against, and most alert kinds are not "this device usually does X" in the first place.
    id: String,
    #[serde(default)]
    provider: Option<String>,
}

#[derive(Serialize)]
struct BehaviorResp {
    provider: &'static str,
    text: String,
}

/// "Device behavioral analysis" (AI.md section 14): explain one behavioral-change alert the
/// caller can already see against the device's own stored `Baseline`. On click only, same bar as
/// `explain`/`triage` — and only ever offered at all on an alert kind DENIS already decided
/// represents a change from that device's own normal pattern.
pub(crate) async fn behavior(State(st): State<AppState>, Extension(AuthUser(me)): Extension<AuthUser>, Json(b): Json<BehaviorReq>) -> Result<Response, ApiError> {
    let store = st.store.clone();
    let now = now_ts();
    let cfg = blocking(&store, |s| crate::ai::load(s)).await?;
    if !cfg.enabled {
        return Ok(err(StatusCode::FORBIDDEN, "AI is turned off in Settings → AI"));
    }
    if !cfg.features.device_behavior {
        return Ok(err(StatusCode::FORBIDDEN, "the device-behavioral-analysis AI feature is turned off in Settings → AI"));
    }
    let id: i64 = match b.id.parse() {
        Ok(id) => id,
        Err(_) => return Ok(err(StatusCode::BAD_REQUEST, "bad alert id")),
    };
    let ev = blocking(&store, move |s| s.get_event(id)).await?;
    let Some(ev) = ev else { return Ok(err(StatusCode::NOT_FOUND, "no such alert")) };
    // Same site scoping as `explain`/`triage`/`recommend`, and the same "no such alert" wording
    // either way (SECURITY_ARCHITECTURE_REVIEW.md H1).
    if !site_readable(&st, &me, &ev.agent_id) {
        return Ok(err(StatusCode::NOT_FOUND, "no such alert"));
    }
    if !crate::detect::is_behavioral_kind(&ev.kind) {
        return Ok(err(StatusCode::BAD_REQUEST, "this alert kind has no established baseline to compare against"));
    }
    let asset = blocking(&store, move |s| s.get_asset(ev.asset_id)).await?;
    let label = asset.map(|a| a.label()).unwrap_or_else(|| format!("device #{}", ev.asset_id));
    let baseline = blocking(&store, move |s| s.get_baseline(ev.asset_id)).await?;
    let summary = ev.raw_details["summary"].as_str().unwrap_or_default();
    let baseline_summary = match &baseline {
        Some(b) => crate::ai::BaselineSummary {
            known_destination_count: b.typical_destinations.len(),
            known_port_count: b.typical_ports.len(),
            typical_volume: format!("~{} per 5-minute window", crate::health::human_bytes(b.volume.mean.max(0.0) as u64)),
            active_hours: (0..24).filter(|h| b.active_hours[*h as usize] > 0).collect(),
            observed_days: (now - b.observed_since) / 86_400,
        },
        None => crate::ai::BaselineSummary { known_destination_count: 0, known_port_count: 0, typical_volume: "not enough data yet".into(), active_hours: Vec::new(), observed_days: 0 },
    };
    let prompt = crate::ai::behavior_change_prompt(&ev.kind, &ev.severity, ev.score, summary, &label, &baseline_summary);
    let provider = b.provider.filter(|p| !p.is_empty()).unwrap_or(cfg.default_provider.clone());
    let provider: &'static str = match crate::ai::PROVIDERS.iter().find(|p| **p == provider) {
        Some(p) => p,
        None => return Ok(err(StatusCode::BAD_REQUEST, "choose a configured provider")),
    };
    let cfg2 = cfg.clone();
    let result = tokio::task::spawn_blocking(move || crate::ai::explain_behavior_change(&cfg2, provider, &prompt)).await;
    match result {
        Ok(Ok((text, tokens))) => {
            audit(&st, &me.username, "ai.behavior", None, json!({"alert_id": id, "provider": provider}));
            record_usage(&st, now, provider, tokens);
            Ok(Json(BehaviorResp { provider, text }).into_response())
        }
        Ok(Err(e)) => Ok(err(StatusCode::BAD_GATEWAY, format!("{e:#}"))),
        Err(_) => Ok(err(StatusCode::INTERNAL_SERVER_ERROR, "internal error")),
    }
}

/// AI usage visibility (AI.md section 23): read-only, admin-only (registered under the same
/// `/api/ai/settings` admin-only path prefix in `web/mod.rs`). Never itself a reason a feature
/// stops working — see `ai_usage.rs`'s own doc for why recording is always best-effort.
pub(crate) async fn usage(State(st): State<AppState>) -> Result<Json<crate::ai_usage::UsageRecord>, ApiError> {
    Ok(Json(blocking(&st.store, |s| crate::ai_usage::load(s)).await?))
}
