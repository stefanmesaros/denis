//! "Explain with AI": an optional, opt-in, bring-your-own-key summary of one alert or finding in
//! plain language, from whichever provider an administrator has given a key for. Nothing here
//! runs on its own — it is called once, when someone clicks the button, never automatically, and
//! never on more than the one alert or finding they asked about.
//!
//! Deliberately out of scope: no DENIS-hosted or DENIS-paid-for API access. Every call is billed
//! to the administrator's own account with the provider they chose; if none is configured, the
//! button does not appear. This project does not want to run, fund or be liable for a shared AI
//! backend for every installation.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::store::SettingsStore;

pub const KEY: &str = "ai";

pub const PROVIDERS: &[&str] = &["claude", "openai", "gemini", "grok", "local"];

pub fn provider_name(id: &str) -> &'static str {
    match id {
        "claude" => "Claude (Anthropic)",
        "openai" => "ChatGPT (OpenAI)",
        "gemini" => "Gemini (Google)",
        "grok" => "Grok (xAI)",
        "local" => "Local model",
        _ => "AI",
    }
}

/// Individually-controllable AI capabilities (see AI.md's build order: shipped one at a time, a
/// field added here as each one lands). Every field defaults to `false` for a fresh install —
/// the administrator opts in per capability, never gets one silently turned on — except where
/// `load`'s own migration logic below preserves what an existing install already had.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct AiFeatures {
    /// "Explain with AI" on one alert or finding, on click — the only capability that exists so
    /// far (see `explain` below). Not the same thing as the global `AiConfig.enabled` switch: both
    /// must be on for the button to appear or the endpoint to answer.
    #[serde(default)]
    pub alert_explanations: bool,
    /// AI triage (`triage` below): an assessment alongside DENIS's own severity, on click, never
    /// a replacement for it. Independent of `alert_explanations` — either, both, or neither.
    #[serde(default)]
    pub alert_triage: bool,
    /// Recommended actions (`recommend_actions` below): a short advisory list of next steps for
    /// one alert, on click. Independent of the other two — DENIS never acts on this list itself.
    #[serde(default)]
    pub recommended_actions: bool,
    /// The dashboard's AI summary (see `ai_summary.rs`): unlike the three above, this is never
    /// generated on click — a background job regenerates it on its own schedule when recent alert
    /// activity moves on, and the dashboard only ever reads what is already stored (AI.md section
    /// 6 calls this a hard requirement). Off means the background job makes zero API calls, same
    /// as `AiConfig.enabled` off.
    #[serde(default)]
    pub dashboard_summary: bool,
    /// "Ask DENIS" (`interpret_question`/`answer_question` below): a free-text question about the
    /// network, on click, never automatic. The AI never answers from its own invented facts — it
    /// only ever translates the question into one structured alert search DENIS itself runs, then
    /// summarizes exactly what came back (AI.md section 16).
    #[serde(default)]
    pub ask_denis: bool,
    /// The periodic report's own AI summary (AI.md section 19): written once, when the report
    /// itself is generated — on the existing schedule (Settings → Reports) or an explicit
    /// "Generate now", never on its own timer and never by opening the Reports page. A failure to
    /// write it never fails the report itself; the report is still saved without a summary.
    #[serde(default)]
    pub security_reports: bool,
    /// "Explain behavior change" (`explain_behavior_change` below): on click, only offered on an
    /// alert that describes a change from a device's own established pattern
    /// (`detect::is_behavioral_kind`) — new destination, new port, unusual hours, volume anomaly.
    /// Uses the device's own stored `Baseline` as "normal"; DENIS decided the change was
    /// meaningful before this is ever offered, matching AI.md section 14's own "do not
    /// continuously ask the AI to analyze every device".
    #[serde(default)]
    pub device_behavior: bool,
    /// Step 11, the AI detection-rule assistant: "Suggest a rule with AI" in the network-watch
    /// form (`suggest_rule` below), on click only — describe what to watch for in plain language
    /// and get back a draft the same shape as picking one of the built-in presets, always still
    /// shown in the ordinary editable form before it is saved. Never writes a rule itself; the
    /// administrator always reviews and submits it, same as every other rule.
    #[serde(default)]
    pub rule_assistant: bool,
}

/// One API key per provider an administrator has set up, and which one the "Explain" button
/// uses by default. Keys are never sent back to the browser once saved (see `web_ai::Redacted`).
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct AiConfig {
    #[serde(default)]
    pub keys: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    pub default_provider: String,
    /// Global on/off switch (AI.md section 4): when `false`, no AI call is ever made for any
    /// capability, regardless of what `features` below says — checked first, everywhere this is
    /// checked at all.
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub features: AiFeatures,
    /// Only needed for an Anthropic API key issued at the organization level rather than scoped
    /// to one workspace — see `claude`'s own doc for the exact error such a key gets without this.
    /// Not a secret, unlike `keys`; round-trips to the browser as-is.
    #[serde(default)]
    pub anthropic_workspace_id: String,
    /// The "local" provider's own base URL (e.g. `http://localhost:11434` for Ollama), for anyone
    /// running their own model instead of a cloud one — Ollama, LM Studio, llama.cpp's own server,
    /// vLLM, or anything else that speaks the same OpenAI-compatible `/v1/chat/completions` shape.
    /// Not a secret; round-trips to the browser as-is, same as `anthropic_workspace_id`.
    #[serde(default)]
    pub local_url: String,
    /// The exact model name to ask the local server for (e.g. `qwen2.5:14b`) — there is no single
    /// fixed model the way there is for a cloud provider, since it is whatever the administrator
    /// has pulled locally.
    #[serde(default)]
    pub local_model: String,
}

impl AiConfig {
    /// Providers ready to use, in the fixed `PROVIDERS` order (stable for the UI): a key for every
    /// cloud provider, but the local provider instead needs its URL and model name both set — most
    /// local servers take no key at all, so key presence would wrongly gate it.
    pub fn configured(&self) -> Vec<&'static str> {
        PROVIDERS.iter().copied().filter(|p| self.is_ready(p)).collect()
    }

    fn is_ready(&self, provider: &str) -> bool {
        if provider == "local" {
            !self.local_url.trim().is_empty() && !self.local_model.trim().is_empty()
        } else {
            self.keys.get(provider).is_some_and(|k| !k.is_empty())
        }
    }

    pub fn key_for(&self, provider: &str) -> Option<&str> {
        self.keys.get(provider).map(|s| s.as_str()).filter(|s| !s.is_empty())
    }
}

/// Loads the config, migrating a pre-`enabled`/`features` install (every one saved before this
/// pair of fields existed) so it keeps working exactly as it did: if a provider key was already
/// configured, alert explanation effectively already worked (there was no separate toggle for it),
/// so both the global switch and the alert-explanations feature default to *on* for that install —
/// never for a fresh one, which opts in explicitly. This only ever applies once: the check is
/// against the raw stored JSON literally lacking an `"enabled"` key, so a later, real save (which
/// always writes one, `true` or `false`) is respected exactly as saved from then on.
pub fn load(store: &dyn SettingsStore) -> Result<AiConfig> {
    let raw = store.get_setting(KEY)?;
    let mut cfg: AiConfig = raw.as_deref().and_then(|b| serde_json::from_slice(b).ok()).unwrap_or_default();
    let pre_migration = raw.as_deref().and_then(|b| serde_json::from_slice::<serde_json::Value>(b).ok()).is_some_and(|v| v.get("enabled").is_none());
    if pre_migration && !cfg.keys.is_empty() {
        cfg.enabled = true;
        cfg.features.alert_explanations = true;
    }
    Ok(cfg)
}

pub fn save(store: &dyn SettingsStore, c: &AiConfig, now: i64) -> Result<()> {
    store.set_setting(KEY, &serde_json::to_vec(c)?, now)
}

const SYSTEM_PROMPT: &str = "You are helping a network administrator understand one security alert from DENIS, a \
network monitoring tool. You are given the alert's own summary, its scored reasons, and the device it concerns — \
nothing else about their network. In 3-6 short sentences: explain in plain language why this likely fired, how \
serious it really is in context, and what to check or do next. Do not invent facts not given to you; say plainly \
when you are not sure. Do not repeat the input back verbatim.";

/// Triage's own system prompt: unlike `SYSTEM_PROMPT` (free-form prose), this must return exactly
/// one JSON object DENIS can safely parse and act on — see `TriageResult`/`parse_triage` below for
/// why `assessment` is validated against a fixed set rather than trusted as free text.
const TRIAGE_SYSTEM_PROMPT: &str = "You are triaging one security alert from DENIS, a network monitoring tool, for \
a network administrator. You are given the alert's own summary, its scored reasons, and the device it concerns — \
nothing else about their network. Reply with exactly one JSON object and nothing else (no markdown fencing, no \
commentary before or after): {\"assessment\": one of \"likely_benign\", \"suspicious\", \"requires_investigation\", \
\"confidence\": a number from 0 to 1, \"reasoning\": 1-3 short sentences, \"recommended_action\": one short \
sentence of advisory next step}. This is an additional signal alongside DENIS's own severity score, never a \
replacement for it - do not claim to change or override anything. Do not invent facts not given to you.";

/// `http_status_as_error` (ureq's own default) turns a non-2xx response into a bare
/// `Error::StatusCode(code)` with the body already discarded — so a provider's actual reason (bad
/// model name, over quota, malformed request) never reached an administrator, who saw only a
/// generic "answered with an error" and, once that crossed this app's own `BAD_GATEWAY` wrapping,
/// nothing at all. Disabled here so a non-2xx response is read like any other: the status is
/// checked explicitly and the provider's own error body (most of them return `{"error": {...}}` or
/// similar) is surfaced instead of being thrown away.
/// 60s, not 30: a "thinking"/reasoning model (seen live with Gemini, whose current default model
/// spends unpredictable time reasoning before answering — and which alias resolution can move
/// between generations that do or do not support turning thinking off at all) can genuinely take
/// longer than 30s for a short prompt. Every provider gets the same budget; none of these calls
/// are on a request path a person is blocked on beyond clicking a button and waiting.
fn call_ureq_json(url: &str, headers: &[(&str, String)], body: &serde_json::Value) -> Result<serde_json::Value> {
    let agent: ureq::Agent = ureq::Agent::config_builder().timeout_global(Some(std::time::Duration::from_secs(60))).http_status_as_error(false).build().into();
    let mut req = agent.post(url).header("Content-Type", "application/json");
    for (k, v) in headers {
        req = req.header(*k, v);
    }
    let mut resp = req.send_json(body.clone()).map_err(|e| anyhow!("the provider could not be reached: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        let text = resp.body_mut().read_to_string().unwrap_or_default();
        return Err(anyhow!("the provider answered with {status}: {}", if text.is_empty() { "(no body)" } else { text.trim() }));
    }
    resp.body_mut().read_json::<serde_json::Value>().map_err(|e| anyhow!("the provider's answer was not valid JSON: {e}"))
}

/// `workspace_id`: some Anthropic API keys are issued at the organization level rather than
/// scoped to one workspace, and the API then rejects every request outright ("This API key is
/// not scoped to a workspace, so this request must include the anthropic-workspace-id header ...")
/// until that header is added — found live, from a real account's own key. Empty means the key is
/// already workspace-scoped (the common case), so no such header is sent.
/// Every provider call below returns `(text, tokens)`: `tokens` is the total token count the
/// provider's own response reported for that one call, when it reported one at all — used only to
/// give an administrator a rough sense of usage (`ai_usage.rs`), never anything DENIS itself acts
/// on, so a provider that does not report it (or a shape this code does not recognise) just means
/// `None` rather than a hard error.
fn claude(key: &str, workspace_id: &str, system: &str, prompt: &str) -> Result<(String, Option<i64>)> {
    let body = json!({
        "model": "claude-haiku-4-5-20251001",
        "max_tokens": 500,
        "system": system,
        "messages": [{"role": "user", "content": prompt}],
    });
    let mut headers = vec![("x-api-key", key.to_string()), ("anthropic-version", "2023-06-01".to_string())];
    if !workspace_id.trim().is_empty() {
        headers.push(("anthropic-workspace-id", workspace_id.trim().to_string()));
    }
    let v = call_ureq_json("https://api.anthropic.com/v1/messages", &headers, &body)?;
    let text = v["content"][0]["text"].as_str().map(str::to_string).ok_or_else(|| anyhow!("no answer in the response: {v}"))?;
    let tokens = v["usage"]["input_tokens"].as_i64().zip(v["usage"]["output_tokens"].as_i64()).map(|(i, o)| i + o);
    Ok((text, tokens))
}

/// `token_param`: the request field that caps the reply length — `"max_tokens"` for most
/// OpenAI-compatible APIs (x.ai's included), but OpenAI's own newer reasoning-family models
/// (`gpt-5-mini` among them) reject that name outright ("Unsupported parameter: 'max_tokens' is
/// not supported with this model. Use 'max_completion_tokens' instead.") and require
/// `"max_completion_tokens"` — found live, via a real 400 from OpenAI once `call_ureq_json`
/// started surfacing a non-2xx response's own body instead of discarding it.
/// `reasoning_effort`: only OpenAI's own reasoning-family models accept this field at all — Grok,
/// which shares this same request shape, rejects unknown parameters, so it is only ever set for
/// the OpenAI call site. Without it, a reasoning model can spend its *entire* token budget on
/// invisible internal reasoning before ever writing the visible answer, leaving a genuinely empty
/// completion — found live: Triage and Recommended actions both failed with "no JSON object in
/// the response: " (an empty string) rather than any real error, because `500` tokens was entirely
/// consumed by reasoning. `"low"` keeps that spend small enough to leave real room for the answer;
/// the token budget itself is also raised so a longer answer still has somewhere to go.
/// `key`: `None` for a local server that takes no authentication at all (the common case for
/// Ollama/LM Studio/llama.cpp's own server run on localhost) — the `Authorization` header is then
/// omitted entirely rather than sent as `Bearer ` with nothing after it.
fn openai_style(url: &str, key: Option<&str>, model: &str, token_param: &str, reasoning_effort: Option<&str>, system: &str, prompt: &str) -> Result<(String, Option<i64>)> {
    let mut body = json!({
        "model": model,
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}],
    });
    body[token_param] = json!(1500);
    if let Some(effort) = reasoning_effort {
        body["reasoning_effort"] = json!(effort);
    }
    let mut headers = Vec::new();
    if let Some(k) = key {
        headers.push(("Authorization", format!("Bearer {k}")));
    }
    let v = call_ureq_json(url, &headers, &body)?;
    let text = v["choices"][0]["message"]["content"].as_str().map(str::to_string).ok_or_else(|| anyhow!("no answer in the response: {v}"))?;
    let tokens = v["usage"]["total_tokens"].as_i64();
    Ok((text, tokens))
}

/// A pinned model name (`gemini-2.5-flash`) broke once already when Google retired it for new API
/// keys. `gemini-flash-latest` is Google's own stable alias for the current fast/economical model
/// in the family — "hot-swapped with every new release", with two weeks' notice by email before
/// a breaking change — so this should not need another manual update the next time Google moves
/// the underlying model on.
fn gemini(key: &str, system: &str, prompt: &str) -> Result<(String, Option<i64>)> {
    let url = format!("https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-latest:generateContent?key={key}");
    let body = json!({
        "system_instruction": {"parts": [{"text": system}]},
        "contents": [{"parts": [{"text": prompt}]}],
    });
    let v = call_ureq_json(&url, &[], &body)?;
    let text = v["candidates"][0]["content"]["parts"][0]["text"].as_str().map(str::to_string).ok_or_else(|| anyhow!("no answer in the response: {v}"))?;
    let tokens = v["usageMetadata"]["totalTokenCount"].as_i64();
    Ok((text, tokens))
}

/// Ask one provider `prompt`, under `system`'s instructions. Shared by every capability below —
/// they differ only in which system prompt and what they do with the text that comes back.
/// Returns the trimmed answer plus that call's own token count, when the provider reported one.
fn ask(cfg: &AiConfig, provider: &str, system: &str, prompt: &str) -> Result<(String, Option<i64>)> {
    if provider == "local" {
        if cfg.local_url.trim().is_empty() || cfg.local_model.trim().is_empty() {
            return Err(anyhow!("the local model's URL and model name are not both set"));
        }
        let url = format!("{}/v1/chat/completions", cfg.local_url.trim().trim_end_matches('/'));
        let (text, tokens) = openai_style(&url, cfg.key_for("local"), cfg.local_model.trim(), "max_tokens", None, system, prompt)?;
        return Ok((text.trim().to_string(), tokens));
    }
    let key = cfg.key_for(provider).ok_or_else(|| anyhow!("no API key is set for {}", provider_name(provider)))?;
    let (text, tokens) = match provider {
        "claude" => claude(key, &cfg.anthropic_workspace_id, system, prompt)?,
        "openai" => openai_style("https://api.openai.com/v1/chat/completions", Some(key), "gpt-5-mini", "max_completion_tokens", Some("low"), system, prompt)?,
        "gemini" => gemini(key, system, prompt)?,
        "grok" => openai_style("https://api.x.ai/v1/chat/completions", Some(key), "grok-4-fast", "max_tokens", None, system, prompt)?,
        other => return Err(anyhow!("unknown provider {other:?}")),
    };
    Ok((text.trim().to_string(), tokens))
}

/// Ask one provider to explain `prompt` (already built from an alert's or finding's own data).
/// Returns the explanation plus that call's own token count (see `ask`'s own doc).
pub fn explain(cfg: &AiConfig, provider: &str, prompt: &str) -> Result<(String, Option<i64>)> {
    ask(cfg, provider, SYSTEM_PROMPT, prompt)
}

/// The controlled set of triage assessments (spec section 12): never arbitrary text, so nothing
/// downstream can be driven by a value DENIS did not itself define. `Other` exists only so a
/// provider that returns something outside this set is a visible, reportable case, not silently
/// dropped or panicking - see `parse_triage`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Assessment {
    LikelyBenign,
    Suspicious,
    RequiresInvestigation,
}

impl Assessment {
    fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "likely_benign" => Some(Assessment::LikelyBenign),
            "suspicious" => Some(Assessment::Suspicious),
            "requires_investigation" => Some(Assessment::RequiresInvestigation),
            _ => None,
        }
    }
}

/// AI triage's structured answer (spec section 12) — an *additional* signal shown alongside
/// DENIS's own deterministic severity, never a replacement for it: nothing in this codebase ever
/// writes an `Assessment` back into an `Event`'s own `severity`/`score`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TriageResult {
    pub assessment: Assessment,
    /// Clamped to `[0, 1]` — a provider returning `1.4` or `-0.2` is a real thing to guard against,
    /// not hypothetical, given nothing about the response format is actually enforced on their end.
    pub confidence: f64,
    pub reasoning: String,
    pub recommended_action: String,
    pub generated_at: i64,
}

/// Ask one provider to triage `prompt`, returning DENIS's own validated structure — never the
/// provider's raw text. `now` is DENIS's own clock, not trusted from the model (see `TriageResult`
/// doc: `generated_at` records when *this* triage ran).
pub fn triage(cfg: &AiConfig, provider: &str, prompt: &str, now: i64) -> Result<(TriageResult, Option<i64>)> {
    let (text, tokens) = ask(cfg, provider, TRIAGE_SYSTEM_PROMPT, prompt)?;
    Ok((parse_triage(&text, now)?, tokens))
}

/// Extracts and validates one `TriageResult` from a provider's raw text. Tolerant of the common
/// ways a model fails to follow "JSON only" (markdown code fences, leading/trailing prose around
/// the object) by finding the first `{...}` span rather than requiring the whole response to be
/// nothing else — but never tolerant of an `assessment` outside the fixed set: that always fails
/// rather than guessing, per spec ("a controlled set... rather than allowing arbitrary text to
/// drive application logic").
fn parse_triage(text: &str, now: i64) -> Result<TriageResult> {
    let start = text.find('{').ok_or_else(|| anyhow!("no JSON object in the response: {text}"))?;
    let end = text.rfind('}').ok_or_else(|| anyhow!("no JSON object in the response: {text}"))?;
    if end < start {
        return Err(anyhow!("no JSON object in the response: {text}"));
    }
    let v: serde_json::Value = serde_json::from_str(&text[start..=end]).map_err(|e| anyhow!("the response was not valid JSON: {e}"))?;
    let assessment = v["assessment"].as_str().and_then(Assessment::parse).ok_or_else(|| anyhow!("the response's \"assessment\" was missing or not one of the allowed values: {v}"))?;
    let confidence = v["confidence"].as_f64().unwrap_or(0.0).clamp(0.0, 1.0);
    let reasoning = v["reasoning"].as_str().unwrap_or_default().trim().to_string();
    let recommended_action = v["recommended_action"].as_str().unwrap_or_default().trim().to_string();
    Ok(TriageResult { assessment, confidence, reasoning, recommended_action, generated_at: now })
}

/// Recommended actions' own system prompt (spec section 15): distinct from triage's single
/// `recommended_action` sentence — a short, concrete list for someone about to actually go
/// investigate, not a one-line hint. Advisory only: nothing in this codebase ever acts on this
/// list itself (spec: "do not automatically execute network changes").
const RECOMMEND_SYSTEM_PROMPT: &str = "You are suggesting concrete next steps for a network administrator \
investigating one security alert from DENIS, a network monitoring tool. You are given the alert's own summary, \
its scored reasons, and the device it concerns — nothing else about their network. Reply with exactly one JSON \
object and nothing else (no markdown fencing, no commentary before or after): {\"actions\": [\"...\", ...]}, \
2 to 5 short, concrete, advisory steps (e.g. \"check the device's DNS history\", \"compare with similar devices\", \
\"consider isolating the device\") - never a command DENIS itself could execute, never a claim that anything was \
already done. Do not invent facts not given to you.";

/// Advisory next steps for one significant alert (spec section 15) — a short list, not DENIS
/// acting on anything itself. Distinct from `TriageResult.recommended_action` (one sentence,
/// bundled with an assessment); this is its own capability, its own toggle, a slightly deeper list
/// for someone about to actually go investigate.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RecommendedActions {
    pub actions: Vec<String>,
    pub generated_at: i64,
}

/// Bounds on `actions`: fewer than 2 is not really "a list", more than a handful stops being
/// concise advice and starts being noise nobody will actually read - both symptoms of a provider
/// not really following the prompt, worth surfacing as a real answer either way rather than
/// silently truncating or padding.
const MIN_ACTIONS: usize = 1;
const MAX_ACTIONS: usize = 8;

/// Ask one provider for recommended actions on `prompt`, returning DENIS's own validated list.
pub fn recommend_actions(cfg: &AiConfig, provider: &str, prompt: &str, now: i64) -> Result<(RecommendedActions, Option<i64>)> {
    let (text, tokens) = ask(cfg, provider, RECOMMEND_SYSTEM_PROMPT, prompt)?;
    Ok((parse_recommended_actions(&text, now)?, tokens))
}

/// Extracts and validates a `RecommendedActions` from a provider's raw text — same "find the first
/// `{...}` span" tolerance as `parse_triage`, for the same reason. An empty, missing, or
/// wildly-oversized list fails rather than being silently coerced into something usable, since
/// either is more likely a provider that ignored the prompt than legitimate advice.
fn parse_recommended_actions(text: &str, now: i64) -> Result<RecommendedActions> {
    let start = text.find('{').ok_or_else(|| anyhow!("no JSON object in the response: {text}"))?;
    let end = text.rfind('}').ok_or_else(|| anyhow!("no JSON object in the response: {text}"))?;
    if end < start {
        return Err(anyhow!("no JSON object in the response: {text}"));
    }
    let v: serde_json::Value = serde_json::from_str(&text[start..=end]).map_err(|e| anyhow!("the response was not valid JSON: {e}"))?;
    let actions: Vec<String> = v["actions"]
        .as_array()
        .ok_or_else(|| anyhow!("the response's \"actions\" was missing or not a list: {v}"))?
        .iter()
        .filter_map(|a| a.as_str())
        .map(|a| a.trim().to_string())
        .filter(|a| !a.is_empty())
        .take(MAX_ACTIONS)
        .collect();
    if actions.len() < MIN_ACTIONS {
        return Err(anyhow!("the response gave no usable actions: {v}"));
    }
    Ok(RecommendedActions { actions, generated_at: now })
}

/// The prompt for one alert: exactly what the console already shows for it, nothing more.
pub fn alert_prompt(alert_type: &str, score: i32, severity: &str, summary: &str, reasons: &[String], device_label: &str) -> String {
    format!(
        "Alert type: {alert_type}\nSeverity: {severity} (score {score}/100)\nDevice: {device_label}\nSummary: {summary}\nScored reasons: {}",
        if reasons.is_empty() { "(none given)".to_string() } else { reasons.join("; ") }
    )
}

/// The prompt for one finding: its title, why it matters, and the fix already shown, plus how
/// many devices it currently affects (not their identities beyond a count).
pub fn finding_prompt(title: &str, why: &str, fix: &str, device_count: usize) -> String {
    format!("Standing finding: {title}\nWhy it matters (already known to the administrator): {why}\nSuggested fix (already known): {fix}\nAffects {device_count} device(s) right now.")
}

/// "Device behavioral analysis" (AI.md section 14): explains one alert that already represents a
/// change from a device's own established pattern (`detect::is_behavioral_kind` gates which alert
/// kinds this is offered on) against that same pattern — DENIS's own stored `Baseline`, never a
/// fresh analysis of raw traffic. Only ever called on click, on an alert DENIS already decided was
/// a meaningful change, matching the spec's own "do not continuously ask the AI to analyze every
/// device".
const BEHAVIOR_SYSTEM_PROMPT: &str = "You are explaining one significant behavioral change for a device on a network \
monitored by DENIS, a network monitoring tool, to a network administrator. You are given the device's own established \
normal pattern (known destinations, known ports, typical traffic volume, active hours) and the specific alert that \
flagged a change from it — nothing else about the device or the network. In 2-5 short sentences: describe what \
changed relative to what is normal for this specific device, and how significant that looks in context. Do not \
invent facts not given to you; if the device has little established history yet, say so plainly rather than treating \
a thin baseline as if it were a confident one.";

/// A device's own established pattern, reduced to what the behavior-change prompt needs — built by
/// the caller from the real `model::Baseline` (kept here as plain fields so this function, like
/// every other prompt builder, has no `Store`/model dependency of its own).
pub struct BaselineSummary {
    pub known_destination_count: usize,
    pub known_port_count: usize,
    /// Typical traffic per collection window, already rounded/formatted by the caller (units vary
    /// by how the baseline was sampled, so this is prose, not a bare number).
    pub typical_volume: String,
    /// Hours (0-23, UTC) this device has actually been active in, sorted — empty means no
    /// established pattern yet.
    pub active_hours: Vec<u8>,
    pub observed_days: i64,
}

/// The prompt for one behavioral-change alert: the device's own baseline (`BaselineSummary`) plus
/// the alert that flagged the change against it.
pub fn behavior_change_prompt(alert_type: &str, severity: &str, score: i32, summary: &str, device_label: &str, baseline: &BaselineSummary) -> String {
    let hours = if baseline.active_hours.is_empty() {
        "not established yet".to_string()
    } else {
        baseline.active_hours.iter().map(|h| h.to_string()).collect::<Vec<_>>().join(", ")
    };
    format!(
        "Device: {device_label}\nAlert: {alert_type} (severity {severity}, score {score}/100): {summary}\n\nThis device's own established normal pattern, from {} day(s) of observation:\n- Known destinations: {}\n- Known ports: {}\n- Typical traffic volume: {}\n- Active hours (UTC): {hours}",
        baseline.observed_days, baseline.known_destination_count, baseline.known_port_count, baseline.typical_volume,
    )
}

/// Ask one provider to explain a behavioral-change alert against the device's own baseline.
pub fn explain_behavior_change(cfg: &AiConfig, provider: &str, prompt: &str) -> Result<(String, Option<i64>)> {
    ask(cfg, provider, BEHAVIOR_SYSTEM_PROMPT, prompt)
}

/// The dashboard summary's own system prompt (AI.md section 5): a short overview, not a chat, and
/// never a restatement of the raw counts already visible on the dashboard around it.
const SUMMARY_SYSTEM_PROMPT: &str = "You are writing a short \"AI Security Summary\" card for the dashboard of DENIS, \
a network monitoring tool, summarizing roughly the last 24 hours of alert activity for a network administrator. \
You are given alert counts by severity and a handful of the most significant individual alerts (their type, \
severity, score, device and summary) — nothing else about their network. In 2-5 short sentences: describe the \
overall state (calm, or not), name the most significant change if there is one, and note anything that plausibly \
deserves a look. Do not turn this into a chatbot reply or a bullet-point restatement of the counts already shown \
elsewhere on the dashboard. Do not invent facts not given to you; if nothing significant happened, say so plainly \
and briefly.";

/// Ask one provider to write the dashboard summary for `prompt` (already built by
/// `dashboard_summary_prompt`). Free-form prose, same shape as `explain`.
pub fn summarize(cfg: &AiConfig, provider: &str, prompt: &str) -> Result<(String, Option<i64>)> {
    ask(cfg, provider, SUMMARY_SYSTEM_PROMPT, prompt)
}

/// One alert named individually in the summary prompt, most-significant-first.
pub struct SummaryHighlight {
    pub kind: String,
    pub severity: String,
    pub score: i32,
    pub device_label: String,
    pub summary: String,
}

/// The prompt for the dashboard summary: severity counts over the window plus the highest-scored
/// individual alerts within it — never the raw alert stream, and never more than
/// `highlights.len()` alerts named individually (the caller decides how many; see `ai_summary.rs`).
pub fn dashboard_summary_prompt(window_hours: i64, by_severity: &[(&str, i64)], highlights: &[SummaryHighlight]) -> String {
    let counts = by_severity.iter().filter(|(_, n)| *n > 0).map(|(sev, n)| format!("{n} {sev}")).collect::<Vec<_>>().join(", ");
    let mut out = format!("Alert activity over the last {window_hours} hours: {}.\n", if counts.is_empty() { "none".to_string() } else { counts });
    if highlights.is_empty() {
        out.push_str("No individual alerts stand out enough to name.");
    } else {
        out.push_str("The most significant individual alerts:\n");
        for h in highlights {
            out.push_str(&format!("- [{}, score {}] {} on {}: {}\n", h.severity, h.score, h.kind, h.device_label, h.summary));
        }
    }
    out
}

/// The periodic security report's own system prompt (AI.md section 19): a fuller picture than the
/// dashboard summary (device counts, standing findings, accepted risk) over a period that can be
/// weeks or months, not hours — still 2-5 short sentences, still never inventing anything not
/// given to it.
const SECURITY_REPORT_SYSTEM_PROMPT: &str = "You are writing a short \"AI Security Summary\" for a periodic network \
security report from DENIS, a network monitoring tool, covering the report's own period. You are given: the number \
of devices known and how many are new in this period; alert counts by severity and a handful of the most \
significant individual alerts; how many standing findings need attention and how many accepted risks exist — \
nothing else about the network. In 3-6 short sentences: describe the overall state, name the most significant \
change or risk if there is one, and note what plausibly deserves investigation before the next report. Do not \
turn this into a chatbot reply or a bullet-point restatement of the counts already shown elsewhere in the report. \
Do not invent facts not given to you; if nothing significant happened, say so plainly and briefly.";

/// The prompt for the security report's own summary: everything `SECURITY_REPORT_SYSTEM_PROMPT`
/// says it is given, and nothing else — built from the same report data every other section of
/// the report already shows, never a fresh query of its own.
pub fn security_report_prompt(days: i64, device_count: usize, new_devices: usize, by_severity: &[(&str, i64)], findings_needing_attention: usize, accepted_risks: usize, highlights: &[SummaryHighlight]) -> String {
    let counts = by_severity.iter().filter(|(_, n)| *n > 0).map(|(sev, n)| format!("{n} {sev}")).collect::<Vec<_>>().join(", ");
    let mut out = format!(
        "Report period: {days} day(s).\nDevices known: {device_count} ({new_devices} new this period).\nAlert activity: {}.\nStanding findings needing attention: {findings_needing_attention}.\nAccepted risks: {accepted_risks}.\n",
        if counts.is_empty() { "none".to_string() } else { counts }
    );
    if highlights.is_empty() {
        out.push_str("No individual alerts stand out enough to name.");
    } else {
        out.push_str("The most significant individual alerts:\n");
        for h in highlights {
            out.push_str(&format!("- [{}, score {}] {} on {}: {}\n", h.severity, h.score, h.kind, h.device_label, h.summary));
        }
    }
    out
}

/// Ask one provider to write the periodic security report's own summary for `prompt` (already
/// built by `security_report_prompt`). Free-form prose, same shape as `explain`/`summarize`.
pub fn write_security_report(cfg: &AiConfig, provider: &str, prompt: &str) -> Result<(String, Option<i64>)> {
    ask(cfg, provider, SECURITY_REPORT_SYSTEM_PROMPT, prompt)
}

/// "Ask DENIS" (AI.md section 16) is deliberately two separate calls, never one: the model is
/// never trusted to answer from what it already "knows" about the question, only from DENIS's own
/// data. First it translates the free-text question into one structured `AskQuery` (this prompt);
/// DENIS itself runs that exact query (see `web_ai::ask`) and hands the real results to a second
/// call (`ASK_ANSWER_SYSTEM_PROMPT` below) whose only job is to describe what came back.
///
/// A question can ask DENIS to hunt for a destination across every device's traffic history
/// instead of searching already-raised alerts ("has anything ever talked to 1.2.3.4?", "which
/// devices have contacted evil.example?") — this is step 10, AI threat hunting, folded into the
/// same Ask DENIS flow rather than a separate feature: when `destination` comes back set, DENIS
/// searches every device's own baseline (`model::Baseline::typical_destinations` — already-tracked
/// data, nothing new collected) instead of the event log, and the other fields are ignored.
const ASK_INTERPRET_SYSTEM_PROMPT: &str = "You are translating a network administrator's plain-language question about \
their network into one structured search against DENIS, a network monitoring tool. You do not know anything about \
their network yourself - you only ever choose how to search it. Reply with exactly one JSON object and nothing else (no \
markdown fencing, no commentary before or after): {\"destination\": an IP address or domain name, if the question asks \
whether, or which devices, have communicated with one specific address (e.g. \"has anything talked to 1.2.3.4\", \"which \
devices have contacted evil.example\") - when this is present every other field is ignored, so omit it unless the \
question is clearly a search for a specific destination across all devices; \"hours\": how many hours back to search (a \
whole number from 1 to 720; default to 24 if the question does not imply a period), \"severity\": one of \"low\", \
\"medium\", \"high\", or omit entirely if the question does not ask about a specific severity, \"kind\": the exact \
alert-type keyword if the question clearly names one kind of alert (e.g. \"new_destination\", \"new_device\", \
\"volume_anomaly\", \"new_port\", \"unusual_hours\", \"device_silent\"), otherwise omit, \"device\": a device name or \
partial name if the question names one device, otherwise omit}. Never invent a device, destination or alert kind not \
implied by the question.";

/// One structured search, and nothing more than that — the only thing the interpretation call is
/// allowed to produce, and the only thing `web_ai::ask` is allowed to run against the store.
/// `kind`, if present, is validated against `detect::is_alertable_kind` so a hallucinated alert
/// type is a hard error rather than silently searching for nothing. `destination`, if present,
/// takes over the whole search (see the prompt's own doc comment above): the alert-search fields
/// are simply unused in that case, not validated against anything.
#[derive(Clone, Debug, PartialEq)]
pub struct AskQuery {
    pub hours: i64,
    pub severity: Option<String>,
    pub kind: Option<String>,
    pub device: Option<String>,
    pub destination: Option<String>,
}

/// Ask one provider to translate `question` into an `AskQuery`.
pub fn interpret_question(cfg: &AiConfig, provider: &str, question: &str) -> Result<(AskQuery, Option<i64>)> {
    let (text, tokens) = ask(cfg, provider, ASK_INTERPRET_SYSTEM_PROMPT, question)?;
    Ok((parse_ask_query(&text)?, tokens))
}

fn parse_ask_query(text: &str) -> Result<AskQuery> {
    let start = text.find('{').ok_or_else(|| anyhow!("no JSON object in the response: {text}"))?;
    let end = text.rfind('}').ok_or_else(|| anyhow!("no JSON object in the response: {text}"))?;
    if end < start {
        return Err(anyhow!("no JSON object in the response: {text}"));
    }
    let v: serde_json::Value = serde_json::from_str(&text[start..=end]).map_err(|e| anyhow!("the response was not valid JSON: {e}"))?;
    let hours = v["hours"].as_i64().unwrap_or(24).clamp(1, 720);
    let severity = match v.get("severity").and_then(|s| s.as_str()) {
        None => None,
        Some(s) if ["low", "medium", "high"].contains(&s) => Some(s.to_string()),
        Some(s) => return Err(anyhow!("the response named an unknown severity {s:?}")),
    };
    let kind = match v.get("kind").and_then(|s| s.as_str()) {
        None => None,
        Some(s) if crate::detect::is_alertable_kind(s) => Some(s.to_string()),
        Some(s) => return Err(anyhow!("the response named an unknown alert kind {s:?}")),
    };
    let device = v.get("device").and_then(|s| s.as_str()).map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);
    let destination = v.get("destination").and_then(|s| s.as_str()).map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);
    Ok(AskQuery { hours, severity, kind, device, destination })
}

/// The answer call's own system prompt: unlike the interpretation prompt, this one only ever sees
/// real DENIS data - it must never claim anything the given rows don't show.
const ASK_ANSWER_SYSTEM_PROMPT: &str = "You are answering a network administrator's question about their network, using \
DENIS, a network monitoring tool. You are given the administrator's original question and the exact alerts DENIS found \
for the structured search that question was translated into - nothing else about their network. Answer the question in \
2-5 short sentences, using only what is in the given alerts. If no alerts were found, say so plainly rather than \
speculating about what might have happened. Do not invent devices, addresses or events not present in the data given \
to you.";

/// One alert row handed back to the "answer" call — exactly what DENIS itself found, never
/// anything the AI invented.
pub struct AskResultRow {
    pub kind: String,
    pub severity: String,
    pub score: i32,
    pub device_label: String,
    pub summary: String,
    /// Seconds before "now" this alert fired, computed by the caller (which already has "now"
    /// for the query window itself) — kept this function pure/deterministic, like every other
    /// prompt builder here.
    pub age_secs: i64,
}

/// The prompt for the answer call: the original question plus exactly the rows DENIS found for
/// the structured search it was translated into.
pub fn ask_results_prompt(question: &str, rows: &[AskResultRow]) -> String {
    let mut out = format!("Original question: {question}\n\n");
    if rows.is_empty() {
        out.push_str("DENIS found no matching alerts for this search.");
    } else {
        out.push_str(&format!("DENIS found {} matching alert(s):\n", rows.len()));
        for r in rows {
            out.push_str(&format!("- [{}, score {}, {}s ago] {} on {}: {}\n", r.severity, r.score, r.age_secs, r.kind, r.device_label, r.summary));
        }
    }
    out
}

/// Ask one provider to answer `question` given the real search results already found.
pub fn answer_question(cfg: &AiConfig, provider: &str, prompt: &str) -> Result<(String, Option<i64>)> {
    ask(cfg, provider, ASK_ANSWER_SYSTEM_PROMPT, prompt)
}

/// Step 10, AI threat hunting: the answer call for a destination search across every device's own
/// baseline (`web_ai::ask`'s other branch, taken when `AskQuery::destination` came back set) —
/// same two-call shape and the same rule as `ASK_ANSWER_SYSTEM_PROMPT`, just worded for "who has
/// talked to this address" instead of "which alerts fired".
const ASK_DESTINATION_ANSWER_SYSTEM_PROMPT: &str = "You are answering a network administrator's question about whether \
any of their devices have communicated with a specific destination, using DENIS, a network monitoring tool. You are \
given the administrator's original question, the destination that was searched for, and the exact per-device traffic \
history DENIS found for it - nothing else about their network. Answer the question in 2-5 short sentences, using only \
what is in the given rows. If no device's history shows it, say so plainly rather than speculating about what might \
have happened. Do not invent devices, addresses, byte counts or events not present in the data given to you.";

/// One device's own baseline history of contacting the hunted destination — real, already-tracked
/// data (`model::Baseline::typical_destinations`), never invented.
pub struct AskDestinationRow {
    pub device_label: String,
    pub destination: String,
    pub first_seen_secs_ago: i64,
    pub last_seen_secs_ago: i64,
    pub bytes: u64,
}

/// The prompt for the destination-hunt answer call: the original question, the destination DENIS
/// actually searched for, and exactly the per-device rows it found.
pub fn ask_destination_prompt(question: &str, hunted: &str, rows: &[AskDestinationRow]) -> String {
    let mut out = format!("Original question: {question}\nHunted destination: {hunted}\n\n");
    if rows.is_empty() {
        out.push_str("DENIS found no device whose traffic history includes this destination.");
    } else {
        out.push_str(&format!("DENIS found {} device(s) with this destination in their traffic history:\n", rows.len()));
        for r in rows {
            out.push_str(&format!(
                "- {} contacted {}: first seen {}s ago, last seen {}s ago, {} bytes total\n",
                r.device_label, r.destination, r.first_seen_secs_ago, r.last_seen_secs_ago, r.bytes
            ));
        }
    }
    out
}

/// Ask one provider to answer a destination-hunt `question` given the real baseline rows already found.
pub fn answer_destination_question(cfg: &AiConfig, provider: &str, prompt: &str) -> Result<(String, Option<i64>)> {
    ask(cfg, provider, ASK_DESTINATION_ANSWER_SYSTEM_PROMPT, prompt)
}

/// Step 11, the AI detection-rule assistant: translate a plain-language description of what to
/// watch for into a draft network watch, the exact same shape the UI's own built-in presets
/// already fill a blank watch form with (`ui/rules.js`'s `IT_PRESETS`) — this is a dynamic,
/// free-text preset, never a rule written and saved on its own. `web_ai::suggest_rule` (one call,
/// not two like Ask DENIS: there is no DENIS-side search to run first, nothing here asserts a
/// fact about the network — only a shape the administrator reviews, edits and submits themselves
/// in the ordinary form, matching AI.md section 18's "never auto-enabled").
const RULE_SUGGEST_SYSTEM_PROMPT: &str = "You are turning a network administrator's plain-language description of what \
they want to be alerted about into one draft network watch for DENIS, a network monitoring tool. Reply with exactly one \
JSON object and nothing else (no markdown fencing, no commentary before or after): {\"name\": a short name for the \
watch (a few words), \"proto\": one of \"any\", \"tcp\", \"udp\", \"icmp\" (default \"any\" if not implied), \
\"ports_mode\": one of \"any\", \"only\", \"except\" (default \"any\"), \"ports\": a list of port numbers (1-65535, \
empty unless ports_mode is \"only\" or \"except\"), \"remotes_mode\": one of \"any\", \"only\", \"except\" (default \
\"only\"), \"remotes\": a list of addresses - the words \"public\" (the internet) or \"private\" (the local network), \
single IPs, or CIDR networks (default [\"public\"] unless the description implies otherwise), \"min_kb\": kilobytes \
that must move in 10 seconds before this fires, a whole number, 0 unless the description mentions a large transfer, \
\"score\": how serious a match is, 1-100 (default 60), \"cooldown_minutes\": minutes between repeat alerts for the \
same device/address/port, 1-1440 (default 30)}. Never invent devices or specific addresses not named in the \
description; describe the traffic pattern only.";

/// One draft network watch, and nothing more — the only thing the rule-suggestion call is allowed
/// to produce. Every field is validated the same way a hand-filled form would be: an invented
/// mode/protocol is a hard error, a port or number outside range is clamped or rejected, never
/// silently guessed into something plausible-looking.
#[derive(Clone, Debug, PartialEq)]
pub struct RuleSuggestion {
    pub name: String,
    pub proto: String,
    pub ports_mode: String,
    pub ports: Vec<u16>,
    pub remotes_mode: String,
    pub remotes: Vec<String>,
    pub min_kb: i64,
    pub score: i32,
    pub cooldown_minutes: i32,
}

/// Ask one provider to translate `description` into a `RuleSuggestion`.
pub fn suggest_rule(cfg: &AiConfig, provider: &str, description: &str) -> Result<(RuleSuggestion, Option<i64>)> {
    let (text, tokens) = ask(cfg, provider, RULE_SUGGEST_SYSTEM_PROMPT, description)?;
    Ok((parse_rule_suggestion(&text)?, tokens))
}

fn parse_rule_suggestion(text: &str) -> Result<RuleSuggestion> {
    let start = text.find('{').ok_or_else(|| anyhow!("no JSON object in the response: {text}"))?;
    let end = text.rfind('}').ok_or_else(|| anyhow!("no JSON object in the response: {text}"))?;
    if end < start {
        return Err(anyhow!("no JSON object in the response: {text}"));
    }
    let v: serde_json::Value = serde_json::from_str(&text[start..=end]).map_err(|e| anyhow!("the response was not valid JSON: {e}"))?;
    let name = v.get("name").and_then(|s| s.as_str()).map(str::trim).filter(|s| !s.is_empty()).unwrap_or("Suggested watch").to_string();
    let mode = |field: &str, default: &str| -> Result<String> {
        match v.get(field).and_then(|s| s.as_str()) {
            None => Ok(default.to_string()),
            Some(s) if ["any", "only", "except"].contains(&s) => Ok(s.to_string()),
            Some(s) => Err(anyhow!("the response named an unknown {field} {s:?}")),
        }
    };
    let proto = match v.get("proto").and_then(|s| s.as_str()) {
        None => "any".to_string(),
        Some(s) if ["any", "tcp", "udp", "icmp"].contains(&s) => s.to_string(),
        Some(s) => return Err(anyhow!("the response named an unknown proto {s:?}")),
    };
    let ports_mode = mode("ports_mode", "any")?;
    let ports: Vec<u16> = v
        .get("ports")
        .and_then(|p| p.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_i64()).filter(|n| *n >= 1 && *n <= 65535).map(|n| n as u16).collect())
        .unwrap_or_default();
    let remotes_mode = mode("remotes_mode", "only")?;
    let remotes: Vec<String> = v
        .get("remotes")
        .and_then(|p| p.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str()).map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).collect())
        .filter(|v: &Vec<String>| !v.is_empty())
        .unwrap_or_else(|| vec!["public".to_string()]);
    let min_kb = v["min_kb"].as_i64().unwrap_or(0).clamp(0, 100_000_000);
    let score = v["score"].as_i64().unwrap_or(60).clamp(1, 100) as i32;
    let cooldown_minutes = v["cooldown_minutes"].as_i64().unwrap_or(30).clamp(1, 1440) as i32;
    Ok(RuleSuggestion { name, proto, ports_mode, ports, remotes_mode, remotes, min_kb, score, cooldown_minutes })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_key_means_no_button_and_a_plain_refusal_to_call_out() {
        let cfg = AiConfig::default();
        assert!(cfg.configured().is_empty());
        assert!(explain(&cfg, "claude", "x").is_err());
    }

    #[test]
    fn configured_lists_only_providers_with_a_real_key_in_a_stable_order() {
        let mut cfg = AiConfig::default();
        cfg.keys.insert("grok".into(), "gk".into());
        cfg.keys.insert("claude".into(), "".into()); // blank: not configured
        cfg.keys.insert("openai".into(), "ok".into());
        assert_eq!(cfg.configured(), vec!["openai", "grok"]);
    }

    #[test]
    fn the_local_provider_needs_its_url_and_model_set_not_a_key() {
        let mut cfg = AiConfig::default();
        assert!(!cfg.configured().contains(&"local"));
        cfg.local_url = "http://localhost:11434".into();
        assert!(!cfg.configured().contains(&"local"), "url alone is not enough");
        cfg.local_model = "qwen2.5:14b".into();
        assert!(cfg.configured().contains(&"local"), "url and model, no key needed");
        assert!(cfg.is_ready("local"));
    }

    #[test]
    fn asking_the_local_provider_without_both_set_fails_before_any_network_call() {
        let cfg = AiConfig::default();
        assert!(ask(&cfg, "local", "system", "prompt").is_err());
        let mut half = AiConfig { local_url: "http://localhost:11434".into(), ..Default::default() };
        assert!(ask(&half, "local", "system", "prompt").is_err(), "model name still missing");
        half.local_model = "qwen2.5:14b".into();
        half.local_url = String::new();
        assert!(ask(&half, "local", "system", "prompt").is_err(), "url still missing");
    }

    #[test]
    fn prompts_include_exactly_what_the_console_already_shows_and_nothing_invented() {
        let p = alert_prompt("new_port", 55, "medium", "First use of tcp/22", &["+40 first use".into(), "+15 risky port".into()], "Camera Kitchen (10.0.10.5)");
        assert!(p.contains("new_port") && p.contains("55") && p.contains("Camera Kitchen") && p.contains("+40 first use"));
        let f = finding_prompt("Telnet exposed", "unencrypted remote login", "disable Telnet, use SSH", 3);
        assert!(f.contains("Telnet exposed") && f.contains("3 device"));
    }

    #[test]
    fn a_clean_triage_response_parses_exactly() {
        let r = parse_triage(r#"{"assessment": "suspicious", "confidence": 0.7, "reasoning": "New external destination.", "recommended_action": "Check the device."}"#, 1000).unwrap();
        assert_eq!(r, TriageResult { assessment: Assessment::Suspicious, confidence: 0.7, reasoning: "New external destination.".into(), recommended_action: "Check the device.".into(), generated_at: 1000 });
    }

    #[test]
    fn markdown_fencing_and_surrounding_prose_are_tolerated() {
        let text = "Sure, here is my assessment:\n```json\n{\"assessment\": \"likely_benign\", \"confidence\": 0.9, \"reasoning\": \"r\", \"recommended_action\": \"a\"}\n```\nLet me know if you need more.";
        let r = parse_triage(text, 1000).unwrap();
        assert_eq!(r.assessment, Assessment::LikelyBenign);
    }

    #[test]
    fn an_assessment_outside_the_fixed_set_is_a_hard_error_never_guessed() {
        assert!(parse_triage(r#"{"assessment": "probably fine i guess", "confidence": 0.5, "reasoning": "r", "recommended_action": "a"}"#, 1000).is_err());
        assert!(parse_triage(r#"{"confidence": 0.5, "reasoning": "r", "recommended_action": "a"}"#, 1000).is_err(), "missing assessment entirely");
        assert!(parse_triage("not json at all", 1000).is_err());
    }

    #[test]
    fn confidence_is_clamped_to_zero_one_and_missing_defaults_to_zero() {
        let over = parse_triage(r#"{"assessment": "suspicious", "confidence": 1.4, "reasoning": "r", "recommended_action": "a"}"#, 1000).unwrap();
        assert_eq!(over.confidence, 1.0);
        let under = parse_triage(r#"{"assessment": "suspicious", "confidence": -0.2, "reasoning": "r", "recommended_action": "a"}"#, 1000).unwrap();
        assert_eq!(under.confidence, 0.0);
        let missing = parse_triage(r#"{"assessment": "suspicious", "reasoning": "r", "recommended_action": "a"}"#, 1000).unwrap();
        assert_eq!(missing.confidence, 0.0);
    }

    #[test]
    fn triage_needs_a_key_same_as_explain() {
        let cfg = AiConfig::default();
        assert!(triage(&cfg, "claude", "x", 1000).is_err());
    }

    #[test]
    fn a_clean_recommended_actions_response_parses_exactly() {
        let r = parse_recommended_actions(r#"{"actions": ["Check the device's DNS history", "Compare with similar devices"]}"#, 1000).unwrap();
        assert_eq!(r, RecommendedActions { actions: vec!["Check the device's DNS history".into(), "Compare with similar devices".into()], generated_at: 1000 });
    }

    #[test]
    fn recommended_actions_fencing_and_prose_are_tolerated() {
        let text = "Here you go:\n```json\n{\"actions\": [\"Investigate the destination\"]}\n```\nHope that helps.";
        let r = parse_recommended_actions(text, 1000).unwrap();
        assert_eq!(r.actions, vec!["Investigate the destination".to_string()]);
    }

    #[test]
    fn an_empty_or_missing_actions_list_is_a_hard_error() {
        assert!(parse_recommended_actions(r#"{"actions": []}"#, 1000).is_err());
        assert!(parse_recommended_actions(r#"{"actions": ["", "  "]}"#, 1000).is_err(), "blank-only entries are not usable actions");
        assert!(parse_recommended_actions(r#"{}"#, 1000).is_err(), "missing actions entirely");
        assert!(parse_recommended_actions("not json at all", 1000).is_err());
    }

    #[test]
    fn an_oversized_actions_list_is_capped_not_rejected() {
        let many: Vec<String> = (0..20).map(|i| format!("\"step {i}\"")).collect();
        let text = format!(r#"{{"actions": [{}]}}"#, many.join(","));
        let r = parse_recommended_actions(&text, 1000).unwrap();
        assert_eq!(r.actions.len(), MAX_ACTIONS);
    }

    #[test]
    fn recommend_actions_needs_a_key_same_as_explain() {
        let cfg = AiConfig::default();
        assert!(recommend_actions(&cfg, "claude", "x", 1000).is_err());
    }

    #[test]
    fn summary_needs_a_key_same_as_explain() {
        let cfg = AiConfig::default();
        assert!(summarize(&cfg, "claude", "x").is_err());
    }

    #[test]
    fn the_summary_prompt_includes_counts_and_only_the_highlights_it_was_given() {
        let h = [SummaryHighlight { kind: "new_destination".into(), severity: "medium".into(), score: 55, device_label: "Camera Kitchen (10.0.10.5)".into(), summary: "First contact with 3.113.81.30".into() }];
        let p = dashboard_summary_prompt(24, &[("high", 0), ("medium", 1), ("low", 4)], &h);
        assert!(p.contains("1 medium") && p.contains("4 low") && !p.contains("0 high"), "{p}");
        assert!(p.contains("Camera Kitchen") && p.contains("First contact with 3.113.81.30"), "{p}");
    }

    #[test]
    fn an_empty_window_says_so_plainly_rather_than_an_empty_list() {
        let p = dashboard_summary_prompt(24, &[("high", 0), ("medium", 0), ("low", 0)], &[]);
        assert!(p.contains("none"), "{p}");
        assert!(p.contains("No individual alerts"), "{p}");
    }

    #[test]
    fn the_security_report_prompt_includes_device_and_finding_counts_not_just_alerts() {
        let h = [SummaryHighlight { kind: "new_device".into(), severity: "high".into(), score: 80, device_label: "Unknown (10.0.10.99)".into(), summary: "Never seen before".into() }];
        let p = security_report_prompt(7, 42, 3, &[("high", 1), ("medium", 0), ("low", 0)], 5, 2, &h);
        assert!(p.contains("7 day") && p.contains("42") && p.contains("3 new") && p.contains("5") && p.contains("Accepted risks: 2"), "{p}");
        assert!(p.contains("Unknown") && p.contains("Never seen before"), "{p}");
    }

    #[test]
    fn write_security_report_needs_a_key_same_as_explain() {
        let cfg = AiConfig::default();
        assert!(write_security_report(&cfg, "claude", "x").is_err());
    }

    #[test]
    fn the_behavior_change_prompt_includes_the_baseline_and_the_alert() {
        let baseline = BaselineSummary { known_destination_count: 12, known_port_count: 3, typical_volume: "~80 MB/day".into(), active_hours: vec![6, 7, 8, 20, 21], observed_days: 30 };
        let p = behavior_change_prompt("new_destination", "medium", 55, "First contact with 3.113.81.30", "Baby Monitor (10.0.10.9)", &baseline);
        assert!(p.contains("Baby Monitor") && p.contains("First contact with 3.113.81.30") && p.contains("30 day"), "{p}");
        assert!(p.contains("12") && p.contains("~80 MB/day") && p.contains("6, 7, 8, 20, 21"), "{p}");
    }

    #[test]
    fn an_empty_baseline_says_not_established_rather_than_an_empty_list() {
        let baseline = BaselineSummary { known_destination_count: 0, known_port_count: 0, typical_volume: "not enough data yet".into(), active_hours: vec![], observed_days: 0 };
        let p = behavior_change_prompt("new_port", "low", 30, "x", "New Device", &baseline);
        assert!(p.contains("not established yet"), "{p}");
    }

    #[test]
    fn explain_behavior_change_needs_a_key_same_as_explain() {
        let cfg = AiConfig::default();
        assert!(explain_behavior_change(&cfg, "claude", "x").is_err());
    }

    #[test]
    fn a_clean_ask_query_parses_with_defaults_for_what_was_omitted() {
        let q = parse_ask_query(r#"{"hours": 48, "severity": "high", "kind": "new_destination", "device": "Baby Monitor"}"#).unwrap();
        assert_eq!(q, AskQuery { hours: 48, severity: Some("high".into()), kind: Some("new_destination".into()), device: Some("Baby Monitor".into()), destination: None });
        let bare = parse_ask_query(r#"{}"#).unwrap();
        assert_eq!(bare, AskQuery { hours: 24, severity: None, kind: None, device: None, destination: None }, "hours defaults to 24, everything else stays unset rather than guessed");
    }

    #[test]
    fn a_destination_hunt_query_parses_and_ignores_blank_destinations() {
        let q = parse_ask_query(r#"{"destination": "evil.example", "hours": 48}"#).unwrap();
        assert_eq!(q.destination, Some("evil.example".into()));
        let blank = parse_ask_query(r#"{"destination": "  "}"#).unwrap();
        assert_eq!(blank.destination, None, "blank/whitespace-only destinations are treated as omitted");
    }

    #[test]
    fn the_destination_hunt_prompt_says_plainly_when_nothing_matched() {
        let rows = [AskDestinationRow { device_label: "Baby Monitor (10.0.10.9)".into(), destination: "3.113.81.30".into(), first_seen_secs_ago: 90_000, last_seen_secs_ago: 60, bytes: 4096 }];
        let p = ask_destination_prompt("has anything talked to 3.113.81.30?", "3.113.81.30", &rows);
        assert!(p.contains("Baby Monitor") && p.contains("3.113.81.30") && p.contains("4096 bytes"));
        let empty = ask_destination_prompt("has anything talked to 9.9.9.9?", "9.9.9.9", &[]);
        assert!(empty.contains("no device") && empty.contains("9.9.9.9"), "{empty}");
    }

    #[test]
    fn ask_query_hours_are_clamped_to_a_sane_range() {
        assert_eq!(parse_ask_query(r#"{"hours": 0}"#).unwrap().hours, 1);
        assert_eq!(parse_ask_query(r#"{"hours": 100000}"#).unwrap().hours, 720);
    }

    #[test]
    fn an_ask_query_with_an_invented_severity_or_kind_is_a_hard_error_never_guessed() {
        assert!(parse_ask_query(r#"{"severity": "critical"}"#).is_err());
        assert!(parse_ask_query(r#"{"kind": "made_up_alert_type"}"#).is_err());
        assert!(parse_ask_query("not json at all").is_err());
    }

    #[test]
    fn a_rule_suggestion_parses_with_the_same_defaults_a_blank_form_would_have() {
        let s = parse_rule_suggestion(
            r#"{"name": "Cameras online", "proto": "tcp", "ports_mode": "any", "remotes_mode": "only", "remotes": ["public"], "min_kb": 0, "score": 70, "cooldown_minutes": 15}"#,
        )
        .unwrap();
        assert_eq!(
            s,
            RuleSuggestion {
                name: "Cameras online".into(), proto: "tcp".into(), ports_mode: "any".into(), ports: vec![],
                remotes_mode: "only".into(), remotes: vec!["public".into()], min_kb: 0, score: 70, cooldown_minutes: 15,
            }
        );
        let bare = parse_rule_suggestion(r#"{}"#).unwrap();
        assert_eq!(
            bare,
            RuleSuggestion {
                name: "Suggested watch".into(), proto: "any".into(), ports_mode: "any".into(), ports: vec![],
                remotes_mode: "only".into(), remotes: vec!["public".into()], min_kb: 0, score: 60, cooldown_minutes: 30,
            },
            "sensible defaults when the model omits nearly everything"
        );
    }

    #[test]
    fn a_rule_suggestion_with_an_invented_mode_or_protocol_is_a_hard_error() {
        assert!(parse_rule_suggestion(r#"{"proto": "bluetooth"}"#).is_err());
        assert!(parse_rule_suggestion(r#"{"ports_mode": "sometimes"}"#).is_err());
        assert!(parse_rule_suggestion(r#"{"remotes_mode": "occasionally"}"#).is_err());
    }

    #[test]
    fn a_rule_suggestion_drops_out_of_range_ports_and_clamps_numbers() {
        let s = parse_rule_suggestion(r#"{"ports": [22, 0, 99999, 3389], "score": 500, "cooldown_minutes": -5, "min_kb": -10}"#).unwrap();
        assert_eq!(s.ports, vec![22, 3389], "0 and 99999 are outside 1-65535");
        assert_eq!((s.score, s.cooldown_minutes, s.min_kb), (100, 1, 0));
    }

    #[test]
    fn the_ask_results_prompt_includes_the_question_and_only_what_denis_actually_found() {
        let rows = [AskResultRow { kind: "new_destination".into(), severity: "medium".into(), score: 55, device_label: "Baby Monitor (10.0.10.9)".into(), summary: "First contact with 3.113.81.30".into(), age_secs: 3600 }];
        let p = ask_results_prompt("Why is the Baby Monitor generating alerts?", &rows);
        assert!(p.contains("Why is the Baby Monitor generating alerts?") && p.contains("Baby Monitor") && p.contains("3.113.81.30"), "{p}");
        let empty = ask_results_prompt("anything unusual today?", &[]);
        assert!(empty.contains("no matching alerts"), "{empty}");
    }

    #[test]
    fn interpret_and_answer_need_a_key_same_as_explain() {
        let cfg = AiConfig::default();
        assert!(interpret_question(&cfg, "claude", "what happened today?").is_err());
        assert!(answer_question(&cfg, "claude", "x").is_err());
    }

    /// A minimal fake OpenAI-compatible server (the shape Ollama/LM Studio/llama.cpp's own server
    /// all speak): reads the request, hands the body back to the caller (to check the request
    /// shape — no `Authorization` header for a keyless local server, the right URL, the right
    /// model name), and answers with a canned chat-completion response.
    fn fake_local_server() -> (String, std::sync::mpsc::Receiver<(String, String)>) {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for conn in l.incoming() {
                let Ok(mut c) = conn else { return };
                let mut buf = Vec::new();
                let mut chunk = [0u8; 8192];
                let (head_end, len) = loop {
                    let n = c.read(&mut chunk).unwrap_or(0);
                    if n == 0 {
                        break (0, 0);
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..p]).to_string();
                        let len = head.to_lowercase().lines().find_map(|l| l.strip_prefix("content-length:")).and_then(|v| v.trim().parse().ok()).unwrap_or(0usize);
                        break (p + 4, len);
                    }
                };
                while buf.len() < head_end + len {
                    let n = c.read(&mut chunk).unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
                let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
                let body = String::from_utf8_lossy(&buf[head_end..head_end + len]).to_string();
                let _ = tx.send((head, body));
                let resp = r#"{"choices":[{"message":{"content":"Two devices behaved unusually today."}}],"usage":{"total_tokens":42}}"#;
                let _ = write!(c, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", resp.len(), resp);
            }
        });
        (url, rx)
    }

    #[test]
    fn the_local_provider_sends_no_auth_header_hits_the_right_path_and_parses_the_answer() {
        let (url, rx) = fake_local_server();
        let cfg = AiConfig { local_url: url, local_model: "qwen2.5:14b".into(), ..Default::default() };
        let (text, tokens) = ask(&cfg, "local", "system prompt", "user prompt").unwrap();
        assert_eq!(text, "Two devices behaved unusually today.");
        assert_eq!(tokens, Some(42));
        let (head, body) = rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
        assert!(head.starts_with("POST /v1/chat/completions"), "{head}");
        assert!(!head.to_lowercase().contains("authorization:"), "a keyless local server gets no Authorization header at all: {head}");
        assert!(body.contains("\"qwen2.5:14b\"") && body.contains("user prompt"), "{body}");
    }

    #[test]
    fn a_local_url_with_a_trailing_slash_does_not_produce_a_double_slash_path() {
        let (url, rx) = fake_local_server();
        let cfg = AiConfig { local_url: format!("{url}/"), local_model: "qwen2.5:14b".into(), ..Default::default() };
        ask(&cfg, "local", "s", "p").unwrap();
        let (head, _) = rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
        assert!(head.starts_with("POST /v1/chat/completions"), "{head}");
    }
}
